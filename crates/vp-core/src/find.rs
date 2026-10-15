//! `find`: many queries, one listing, one detail fetch. Returns references, never values.
//!
//! A query that matches nothing returns close titles as suggestions instead,
//! fetched in the same batch, so a typo never costs another approval.

use crate::model::{ItemDetail, ItemSummary, Listed, kind};
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
            urls: vec![],
            favorite: false,
            updated_at: None,
            additional_information: None,
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

/// The site name of a URL: `https://app.payvy.com/login` -> `payvy`.
fn site_name(href: &str) -> Option<String> {
    let rest = href.split_once("://").map(|(_, r)| r).unwrap_or(href);
    let host = rest.split(['/', '?', '#', ':']).next()?.to_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    // Second-level labels like co.uk or com.au: take the label before them.
    let short_tld = |l: &&str| matches!(*l, "co" | "com" | "org" | "net" | "gov" | "ac" | "edu");
    match labels.as_slice() {
        [] => None,
        [one] => Some(one.to_string()),
        [.., name, second, tld] if short_tld(second) && tld.len() == 2 => Some(name.to_string()),
        [.., name, _tld] => Some(name.to_string()),
    }
}

fn host_of(href: &str) -> String {
    let rest = href.split_once("://").map(|(_, r)| r).unwrap_or(href);
    let host = rest
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or(rest)
        .to_lowercase();
    host.strip_prefix("www.").map(String::from).unwrap_or(host)
}

/// Where a login may be filled: a page's scheme, host and port, parsed as the
/// browser parses it. `https://bank.com:x@evil.com/` is evil.com, so a page URL
/// carrying a user name or password is refused rather than split by hand.
struct Origin {
    https: bool,
    host: String,
    /// `None` for the scheme's default port.
    port: Option<u16>,
}

fn origin(url: &url::Url) -> Option<Origin> {
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let host = url.host_str()?.trim_end_matches('.').to_lowercase();
    let host = host.strip_prefix("www.").map(String::from).unwrap_or(host);
    (!host.is_empty()).then_some(Origin {
        https,
        host,
        port: url.port(),
    })
}

/// A page the extension reports. Strict: http(s), no credentials in the URL.
fn page_origin(page_url: &str) -> Option<Origin> {
    let url = url::Url::parse(page_url).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    origin(&url)
}

/// A website saved on an item, which may be written without a scheme
/// (`payvy.com/login`); those count as https.
fn saved_origin(href: &str) -> Option<Origin> {
    let href = href.trim();
    let url = if href.contains("://") {
        url::Url::parse(href)
    } else {
        url::Url::parse(&format!("https://{href}"))
    }
    .ok()?;
    origin(&url)
}

/// The registrable domain by the Public Suffix List, private section included,
/// so `myapp.vercel.app` and `evil.vercel.app` are different sites.
fn registrable(host: &str) -> Option<&str> {
    psl::domain_str(host)
}

/// How well an item's websites match a page, for filling: 3 for the exact
/// host, 2 for the same site (another subdomain), None otherwise. The exact
/// host wins, so a login saved for admin.payvy.com is offered before one for
/// payvy.com on admin.payvy.com. Ports must agree, and a login saved for an
/// https site never fills on plain http (the reverse is an upgrade, and fine).
pub fn page_match(page_url: &str, item: &ItemSummary) -> Option<u32> {
    let page = page_origin(page_url)?;
    item.urls
        .iter()
        .filter_map(|u| {
            let saved = saved_origin(&u.href)?;
            if (saved.https && !page.https) || saved.port != page.port {
                return None;
            }
            if saved.host == page.host {
                Some(3)
            } else {
                registrable(&page.host)
                    .filter(|site| registrable(&saved.host) == Some(*site))
                    .map(|_| 2)
            }
        })
        .max()
}

fn label(origin: &Origin) -> String {
    match (origin.https, origin.port) {
        (true, None) => origin.host.clone(),
        (true, Some(port)) => format!("{}:{port}", origin.host),
        (false, None) => format!("http://{}", origin.host),
        (false, Some(port)) => format!("http://{}:{port}", origin.host),
    }
}

/// The page a fill belongs to, for grants and prompts: `dashboard.stripe.com`,
/// or `http://localhost:3000` off https. Empty when the URL is not a page
/// VisiPass fills (not http(s), or credentials in the URL).
pub fn page_host(url: &str) -> String {
    page_origin(url).map(|o| label(&o)).unwrap_or_default()
}

/// A saved website, for display: `payvy.com`.
pub fn saved_host(href: &str) -> String {
    saved_origin(href).map(|o| label(&o)).unwrap_or_default()
}

/// A parsed search: free words, `"quoted phrases"`, and field filters
/// (`url:`, `user:`, `tag:`, `vault:`, `type:`). Values may be quoted:
/// `vault:"Work Stuff"`. Everything is case-insensitive.
#[derive(Debug, Default, PartialEq)]
pub struct Query {
    pub words: Vec<String>,
    pub phrases: Vec<String>,
    pub filters: Vec<(String, String)>,
}

const FILTERS: [&str; 5] = ["url", "user", "tag", "vault", "type"];

impl Query {
    pub fn parse(input: &str) -> Self {
        let mut query = Query::default();
        let mut chars = input.chars().peekable();
        while chars.peek().is_some() {
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            let mut token = String::new();
            let mut quoted = false;
            while let Some(&c) = chars.peek() {
                if c == '"' {
                    quoted = true;
                    chars.next();
                    for q in chars.by_ref() {
                        if q == '"' {
                            break;
                        }
                        token.push(q);
                    }
                } else if c.is_whitespace() {
                    break;
                } else {
                    token.push(c);
                    chars.next();
                }
            }
            let token = token.to_lowercase();
            if token.is_empty() {
                continue;
            }
            match token
                .split_once(':')
                .filter(|(key, _)| FILTERS.contains(key))
            {
                Some((key, value)) if !value.is_empty() => {
                    query.filters.push((key.into(), value.into()))
                }
                _ if quoted => query.phrases.push(token),
                _ => query.words.push(token),
            }
        }
        query
    }

    /// The free text used for ranking: words and phrases together.
    fn text(&self) -> String {
        self.words
            .iter()
            .chain(&self.phrases)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// How well an item answers a search, or None if it does not match. Higher is
/// better. The item for the site you typed comes first: a search for "payvy"
/// puts payvy.com above "Amazon - Payvy". Usernames match, but rank last, so a
/// domain that is also in your email address does not bury the site itself.
pub fn rank(query: &str, item: &ItemSummary) -> Option<u32> {
    let parsed = Query::parse(query);
    let title = item.title.to_lowercase();
    let tags: Vec<String> = item.tags.iter().map(|t| t.to_lowercase()).collect();
    let hosts: Vec<String> = item.urls.iter().map(|u| host_of(&u.href)).collect();
    let sites: Vec<String> = item
        .urls
        .iter()
        .filter_map(|u| site_name(&u.href))
        .collect();
    let user = item
        .additional_information
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    let vault = item.vault.name.to_lowercase();
    let kind = crate::model::kind(&item.category);

    for (key, value) in &parsed.filters {
        let ok = match key.as_str() {
            "url" => hosts.iter().any(|h| h.contains(value.as_str())),
            "user" => user.contains(value.as_str()),
            "tag" => tags.iter().any(|t| t.contains(value.as_str())),
            "vault" => vault.contains(value.as_str()),
            "type" => {
                kind.contains(value.as_str())
                    || crate::model::kind(value).replace('-', "") == kind.replace('-', "")
            }
            _ => true,
        };
        if !ok {
            return None;
        }
    }
    let anywhere = |term: &str| {
        title.contains(term)
            || tags.iter().any(|t| t.contains(term))
            || hosts.iter().any(|h| h.contains(term))
            || user.contains(term)
    };
    if !parsed
        .words
        .iter()
        .chain(&parsed.phrases)
        .all(|term| anywhere(term))
    {
        return None;
    }
    let text = parsed.text();
    if text.is_empty() {
        return Some(0);
    }
    let query = text;
    let title_words: Vec<&str> = title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let root = |h: &String| h.matches('.').count() <= 1 && site_name(h).is_some_and(|s| s == query);
    let in_title_tags_or_sites = parsed.words.iter().chain(&parsed.phrases).all(|term| {
        title.contains(term.as_str())
            || tags.iter().any(|t| t.contains(term.as_str()))
            || hosts.iter().any(|h| h.contains(term.as_str()))
    });
    let score = if hosts.iter().any(|h| *h == query || root(h)) {
        100 // the site itself: payvy.com
    } else if sites.contains(&query) {
        95 // a subdomain of it: admin.payvy.com
    } else if title == query {
        90
    } else if title.starts_with(&query) {
        80
    } else if sites.iter().any(|s| s.starts_with(&query)) {
        70
    } else if title_words.first().is_some_and(|w| *w == query) {
        65
    } else if title_words.contains(&query.as_str()) {
        60
    } else if title.contains(&query) {
        50
    } else if tags.contains(&query) {
        40
    } else if in_title_tags_or_sites {
        30
    } else {
        20 // only the username matched
    };
    // Shorter titles win ties: "Payvy" before "Payvy - Staging Admin".
    Some(score * 1000 + 999u32.saturating_sub(title.len() as u32))
}

#[cfg(test)]
mod rank_tests {
    use super::*;
    use crate::model::{Url, VaultRef};

    fn item(title: &str, url: Option<&str>, tags: &[&str]) -> ItemSummary {
        ItemSummary {
            id: title.into(),
            title: title.into(),
            category: "LOGIN".into(),
            vault: VaultRef {
                id: "v".into(),
                name: "V".into(),
            },
            tags: tags.iter().map(|t| t.to_string()).collect(),
            urls: url
                .map(|u| vec![Url { href: u.into() }])
                .unwrap_or_default(),
            favorite: false,
            updated_at: None,
            additional_information: None,
        }
    }

    #[test]
    fn own_site_ranks_first() {
        let items = [
            item("Amazon - Payvy", Some("https://www.amazon.com"), &[]),
            item("Bill - Payvy", Some("https://app.bill.com"), &[]),
            item("Payvy Admin", Some("https://admin.payvy.com/login"), &[]),
            item("Company site", Some("https://payvy.com"), &[]),
            item("Amazon", Some("https://amazon.com"), &["payvy"]),
            item("Stripe", Some("https://stripe.com"), &[]),
        ];
        let mut ranked: Vec<(u32, &str)> = items
            .iter()
            .filter_map(|i| rank("payvy", i).map(|r| (r, i.title.as_str())))
            .collect();
        ranked.sort_by_key(|r| std::cmp::Reverse(r.0));
        let order: Vec<&str> = ranked.iter().map(|(_, t)| *t).collect();
        assert_eq!(order[..2], ["Company site", "Payvy Admin"]);
        assert!(!order.contains(&"Stripe"));
        assert_eq!(order.last(), Some(&"Amazon"), "tag-only match is last");
    }

    #[test]
    fn site_names() {
        assert_eq!(
            site_name("https://app.payvy.com/x").as_deref(),
            Some("payvy")
        );
        assert_eq!(
            site_name("https://shop.example.co.uk").as_deref(),
            Some("example")
        );
        assert_eq!(site_name("localhost:3000").as_deref(), Some("localhost"));
    }

    fn with_user(mut i: ItemSummary, user: &str) -> ItemSummary {
        i.additional_information = Some(user.into());
        i
    }

    #[test]
    fn usernames_match_but_rank_last() {
        let site = item("Payvy", Some("https://payvy.com"), &[]);
        let other = with_user(
            item("Stripe", Some("https://stripe.com"), &[]),
            "robert@payvy.com",
        );
        assert!(rank("payvy", &site).unwrap() > rank("payvy", &other).unwrap());
        assert!(rank("stripe", &other).is_some());
    }

    #[test]
    fn parses_phrases_and_filters() {
        let q = Query::parse(r#"stripe "live key" url:dashboard vault:"work stuff" nope:x"#);
        assert_eq!(q.words, ["stripe", "nope:x"]);
        assert_eq!(q.phrases, ["live key"]);
        assert_eq!(
            q.filters,
            [
                ("url".into(), "dashboard".into()),
                ("vault".into(), "work stuff".into())
            ]
        );
    }

    #[test]
    fn filters_narrow_and_phrases_are_exact() {
        let a = with_user(
            item("CCC Bank", Some("https://ccc.au"), &["bank"]),
            "me@example.org",
        );
        let b = item("CCC Com Bank", Some("https://ccc.com.au"), &[]);
        assert!(rank("url:ccc.au", &a).is_some());
        assert!(
            rank("url:ccc.au", &b).is_none(),
            "ccc.au is not inside ccc.com.au"
        );
        assert!(rank("\"ccc bank\"", &a).is_some());
        assert!(rank("\"ccc bank\"", &b).is_none());
        assert!(rank("user:example.org", &a).is_some());
        assert!(rank("tag:bank type:login", &a).is_some());
        assert!(rank("type:api", &a).is_none());
        assert!(rank("vault:v", &a).is_some());
    }

    #[test]
    fn page_matching_prefers_the_exact_host() {
        let root = item("Payvy", Some("https://payvy.com/login"), &[]);
        let admin = item("Payvy Admin", Some("https://admin.payvy.com"), &[]);
        let other = item("Payvy Net", Some("https://payvy.net"), &[]);
        assert_eq!(
            page_match("https://admin.payvy.com/signin", &admin),
            Some(3)
        );
        assert_eq!(page_match("https://admin.payvy.com/signin", &root), Some(2));
        assert_eq!(
            page_match("https://admin.payvy.com/signin", &other),
            None,
            "different domain"
        );
        assert_eq!(
            page_match("https://payvy.com.evil.example/login", &root),
            None,
            "lookalike host"
        );
        assert_eq!(page_match("chrome://newtab", &root), None);
    }

    #[test]
    fn page_matching_parses_urls_as_the_browser_does() {
        let bank = item("Bank", Some("https://bank.com/login"), &[]);
        for phish in [
            "https://bank.com:x@evil.com/login",
            "https://bank.com@evil.com/",
        ] {
            assert_eq!(page_match(phish, &bank), None, "{phish}");
            assert_eq!(page_host(phish), "", "credentials in the URL: {phish}");
        }
        // A backslash is a path separator for http(s): the host is evil.com.
        assert_eq!(page_match(r"https://evil.com\@bank.com/", &bank), None);
        assert_eq!(page_host(r"https://evil.com\@bank.com/"), "evil.com");
        assert_eq!(
            page_match("http://bank.com/login", &bank),
            None,
            "https login on http"
        );
        assert_eq!(
            page_match("https://bank.com:8443/", &bank),
            None,
            "other port"
        );
        assert_eq!(page_match("https://WWW.Bank.com./x", &bank), Some(3));
        let old = item("Old", Some("http://bank.com"), &[]);
        assert_eq!(
            page_match("https://bank.com/", &old),
            Some(3),
            "upgrade to https"
        );
        let bare = item("Bare", Some("bank.com"), &[]);
        assert_eq!(page_match("https://bank.com/", &bare), Some(3));
        let dev = item("Dev", Some("http://localhost:3000"), &[]);
        assert_eq!(page_match("http://localhost:3000/login", &dev), Some(3));
        assert_eq!(page_match("http://localhost:4000/login", &dev), None);
        assert_eq!(
            page_host("http://localhost:3000/x"),
            "http://localhost:3000"
        );
        assert_eq!(
            page_host("https://dashboard.stripe.com/x"),
            "dashboard.stripe.com"
        );
    }

    #[test]
    fn shared_hosting_suffixes_are_separate_sites() {
        let app = item("App", Some("https://myapp.vercel.app"), &[]);
        assert_eq!(page_match("https://evil.vercel.app/", &app), None);
        let pages = item("Pages", Some("https://me.github.io"), &[]);
        assert_eq!(page_match("https://them.github.io/", &pages), None);
        let uk = item("Shop", Some("https://shop.example.co.uk"), &[]);
        assert_eq!(page_match("https://www.example.co.uk/", &uk), Some(2));
        assert_eq!(page_match("https://other.co.uk/", &uk), None);
    }
}
