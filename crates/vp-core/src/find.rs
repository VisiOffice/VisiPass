//! `find`: many queries, one listing, one detail fetch. Returns references, never values.
//!
//! A query that matches nothing returns close titles as suggestions instead,
//! fetched in the same batch, so a typo never costs another approval.

use crate::model::{ItemDetail, Listed, kind};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

const SUGGESTION_THRESHOLD: f64 = 0.6;
const SUGGESTIONS_PER_MISS: usize = 3;

pub struct Search {
    pub query: String,
    pub items: Vec<usize>,
    pub suggested: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SecretMatch {
    #[serde(rename = "ref")]
    pub reference: String,
    pub title: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Suggestion {
    pub query: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub title: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct FindResult {
    pub matches: Vec<SecretMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<Suggestion>,
}

fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut current = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            current[j] = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + cost);
        }
        previous = current;
    }
    previous[b.len()]
}

/// How close a title comes to a query that matched nothing (0..1). Each term
/// scores its best title word, so typos like "databse" still find "Database".
fn closeness(terms: &[String], title: &str) -> f64 {
    let candidates = words(title);
    let score = |term: &String| {
        candidates
            .iter()
            .map(|word| {
                if word.contains(term.as_str())
                    || (word.chars().count() >= 3 && term.contains(word.as_str()))
                {
                    1.0
                } else {
                    let longest = term.chars().count().max(word.chars().count()).max(1);
                    1.0 - distance(term, word) as f64 / longest as f64
                }
            })
            .fold(0.0, f64::max)
    };
    if terms.is_empty() {
        0.0
    } else {
        terms.iter().map(score).sum::<f64>() / terms.len() as f64
    }
}

fn matches(terms: &[String], listed: &Listed) -> bool {
    let title = listed.summary.title.to_lowercase();
    let tags: Vec<String> = listed
        .summary
        .tags
        .iter()
        .map(|t| t.to_lowercase())
        .collect();
    terms.iter().all(|term| {
        title.contains(term.as_str()) || tags.iter().any(|tag| tag.contains(term.as_str()))
    })
}

/// Decides which listed items each query wants, before any details are fetched.
pub fn plan(queries: &[String], listed: &[Listed]) -> Vec<Search> {
    let mut unique: Vec<&String> = Vec::new();
    for q in queries {
        if !unique.contains(&q) {
            unique.push(q);
        }
    }
    unique
        .into_iter()
        .map(|query| {
            let terms: Vec<String> = query
                .to_lowercase()
                .split_whitespace()
                .map(String::from)
                .collect();
            let items: Vec<usize> = (0..listed.len())
                .filter(|&i| matches(&terms, &listed[i]))
                .collect();
            let suggested = if items.is_empty() {
                let mut scored: Vec<(usize, f64)> = (0..listed.len())
                    .map(|i| (i, closeness(&terms, &listed[i].summary.title)))
                    .filter(|(_, score)| *score >= SUGGESTION_THRESHOLD)
                    .collect();
                scored.sort_by(|a, b| {
                    b.1.total_cmp(&a.1)
                        .then_with(|| listed[a.0].summary.title.cmp(&listed[b.0].summary.title))
                });
                scored
                    .into_iter()
                    .take(SUGGESTIONS_PER_MISS)
                    .map(|(i, _)| i)
                    .collect()
            } else {
                Vec::new()
            };
            Search {
                query: query.clone(),
                items,
                suggested,
            }
        })
        .collect()
}

/// Indices of every listed item any search needs details for.
pub fn wanted(searches: &[Search], len: usize) -> Vec<usize> {
    (0..len)
        .filter(|i| {
            searches
                .iter()
                .any(|s| s.items.contains(i) || s.suggested.contains(i))
        })
        .collect()
}

/// Secret-bearing fields of an item: concealed fields and passwords that have a reference.
pub fn secrets(item: &ItemDetail) -> Vec<SecretMatch> {
    item.fields
        .iter()
        .filter(|f| f.kind == "CONCEALED" || f.purpose.as_deref() == Some("PASSWORD"))
        .filter_map(|f| {
            f.reference.as_ref().map(|r| SecretMatch {
                reference: r.clone(),
                title: item.title.clone(),
                kind: kind(&item.category),
                queries: None,
            })
        })
        .collect()
}

pub fn assemble(searches: &[Search], listed: &[Listed], details: &[ItemDetail]) -> FindResult {
    let by_id: HashMap<&str, Vec<SecretMatch>> = details
        .iter()
        .map(|d| (d.id.as_str(), secrets(d)))
        .collect();
    let secrets_of = |indices: &[usize]| -> Vec<SecretMatch> {
        indices
            .iter()
            .flat_map(|&i| {
                by_id
                    .get(listed[i].summary.id.as_str())
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    };
    let mut found: BTreeMap<String, SecretMatch> = BTreeMap::new();
    for search in searches {
        for m in secrets_of(&search.items) {
            found
                .entry(m.reference.clone())
                .or_insert_with(|| SecretMatch {
                    queries: Some(Vec::new()),
                    ..m
                })
                .queries
                .get_or_insert_with(Vec::new)
                .push(search.query.clone());
        }
    }
    let single = searches.len() == 1;
    let matches = found
        .into_values()
        .map(|m| {
            if single {
                SecretMatch { queries: None, ..m }
            } else {
                m
            }
        })
        .collect();
    let suggestions = searches
        .iter()
        .flat_map(|s| {
            secrets_of(&s.suggested).into_iter().map(|m| Suggestion {
                query: s.query.clone(),
                reference: m.reference,
                title: m.title,
                kind: m.kind,
            })
        })
        .collect();
    FindResult {
        matches,
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldMeta, ItemSummary, VaultRef};

    fn item(id: &str, title: &str) -> (Listed, ItemDetail) {
        let vault = VaultRef {
            id: "v".into(),
            name: "Dev".into(),
        };
        let summary = ItemSummary {
            id: id.into(),
            title: title.into(),
            category: "API_CREDENTIAL".into(),
            vault: vault.clone(),
            tags: vec![],
        };
        let detail = ItemDetail {
            id: id.into(),
            title: title.into(),
            category: "API_CREDENTIAL".into(),
            vault,
            tags: vec![],
            urls: vec![],
            created_at: None,
            updated_at: None,
            fields: vec![
                FieldMeta {
                    id: "credential".into(),
                    label: Some("credential".into()),
                    kind: "CONCEALED".into(),
                    purpose: None,
                    reference: Some(format!("op://Dev/{title}/credential")),
                    section: None,
                },
                FieldMeta {
                    id: "username".into(),
                    label: None,
                    kind: "STRING".into(),
                    purpose: None,
                    reference: Some(format!("op://Dev/{title}/username")),
                    section: None,
                },
            ],
        };
        (
            Listed {
                summary,
                raw: serde_json::Value::Null,
            },
            detail,
        )
    }

    fn fixture() -> (Vec<Listed>, Vec<ItemDetail>) {
        ["OpenAI API Key", "Stripe API Key", "Database Password"]
            .iter()
            .enumerate()
            .map(|(i, t)| item(&i.to_string(), t))
            .unzip()
    }

    #[test]
    fn finds_across_queries_once() {
        let (listed, details) = fixture();
        let queries = vec!["openai".to_string(), "api key".to_string()];
        let searches = plan(&queries, &listed);
        let result = assemble(&searches, &listed, &details);
        assert_eq!(result.matches.len(), 2);
        let openai = &result.matches[0];
        assert_eq!(openai.reference, "op://Dev/OpenAI API Key/credential");
        assert_eq!(
            openai.queries.as_deref(),
            Some(&["openai".to_string(), "api key".to_string()][..])
        );
        assert!(result.suggestions.is_empty());
    }

    #[test]
    fn suggests_on_typo() {
        let (listed, details) = fixture();
        let queries = vec!["databse".to_string()];
        let searches = plan(&queries, &listed);
        assert_eq!(wanted(&searches, listed.len()), vec![2]);
        let result = assemble(&searches, &listed, &details);
        assert!(result.matches.is_empty());
        assert_eq!(result.suggestions[0].title, "Database Password");
        assert_eq!(result.matches.first().and_then(|m| m.queries.clone()), None);
    }

    #[test]
    fn single_query_omits_queries() {
        let (listed, details) = fixture();
        let result = assemble(&plan(&["stripe".into()], &listed), &listed, &details);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].queries, None);
    }
}
