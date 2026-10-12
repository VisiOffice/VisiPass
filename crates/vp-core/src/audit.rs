//! `inventory` and `audit`: metadata only. URLs lose query strings and fragments.

use crate::model::{ItemDetail, kind};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct InventoryField {
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryItem {
    pub id: String,
    pub title: String,
    pub vault: String,
    pub kind: String,
    pub tags: Vec<String>,
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub fields: Vec<InventoryField>,
}

/// Origin and path only: query strings and fragments often carry tokens.
pub fn safe_url(input: &str) -> String {
    let cut = input.find(['?', '#']).unwrap_or(input.len());
    let base = &input[..cut];
    // Drop userinfo (`https://user:pass@host`).
    match base.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(authority);
            format!("{scheme}://{host}{path}")
        }
        None => base.to_string(),
    }
}

pub fn inventory(details: &[ItemDetail]) -> Vec<InventoryItem> {
    let mut items: Vec<InventoryItem> = details
        .iter()
        .map(|item| {
            let mut tags = item.tags.clone();
            tags.sort();
            InventoryItem {
                id: item.id.clone(),
                title: item.title.clone(),
                vault: item.vault.name.clone(),
                kind: kind(&item.category),
                tags,
                urls: item.urls.iter().map(|u| safe_url(&u.href)).collect(),
                created_at: item.created_at.clone(),
                updated_at: item.updated_at.clone(),
                fields: item
                    .fields
                    .iter()
                    .map(|f| InventoryField {
                        label: f.label.clone().unwrap_or_else(|| f.id.clone()),
                        kind: f.kind.to_lowercase(),
                        purpose: f.purpose.as_ref().map(|p| p.to_lowercase()),
                        section: f.section.as_ref().and_then(|s| s.label.clone()),
                        reference: f.reference.clone(),
                    })
                    .collect(),
            }
        })
        .collect();
    items.sort_by(|a, b| a.vault.cmp(&b.vault).then_with(|| a.title.cmp(&b.title)));
    items
}

#[derive(Clone, Debug, Serialize)]
pub struct Brief {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub items: usize,
    pub tagged: usize,
    pub untagged: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DuplicateTitle {
    pub title: String,
    pub items: Vec<Brief>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KindBrief {
    pub id: String,
    pub title: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OldLogin {
    pub id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UrlReview {
    pub id: String,
    pub title: String,
    pub urls: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Audit {
    pub summary: Summary,
    pub duplicate_titles: Vec<DuplicateTitle>,
    pub untagged_machine_credentials: Vec<KindBrief>,
    pub old_logins: Vec<OldLogin>,
    pub urls_to_review: Vec<UrlReview>,
}

const MACHINE_KINDS: [&str; 6] = [
    "api-credential",
    "database",
    "document",
    "password",
    "secure-note",
    "ssh-key",
];
const TRANSIENT: [&str; 10] = [
    "callback", "oauth", "invite", "signup", "register", "activate", "accept", "forgot", "reset",
    "checkout",
];

/// `now` is RFC 3339; logins not updated in five years are flagged.
pub fn audit(items: &[InventoryItem], now: &str) -> Audit {
    let cutoff = crate::time::years_before(now, 5);
    let mut groups: BTreeMap<String, Vec<&InventoryItem>> = BTreeMap::new();
    for item in items {
        groups
            .entry(item.title.to_lowercase())
            .or_default()
            .push(item);
    }
    Audit {
        summary: Summary {
            items: items.len(),
            tagged: items.iter().filter(|i| !i.tags.is_empty()).count(),
            untagged: items.iter().filter(|i| i.tags.is_empty()).count(),
        },
        duplicate_titles: groups
            .into_values()
            .filter(|g| g.len() > 1)
            .map(|g| DuplicateTitle {
                title: g[0].title.clone(),
                items: g
                    .iter()
                    .map(|i| Brief {
                        id: i.id.clone(),
                        title: i.title.clone(),
                    })
                    .collect(),
            })
            .collect(),
        untagged_machine_credentials: items
            .iter()
            .filter(|i| i.tags.is_empty() && MACHINE_KINDS.contains(&i.kind.as_str()))
            .map(|i| KindBrief {
                id: i.id.clone(),
                title: i.title.clone(),
                kind: i.kind.clone(),
            })
            .collect(),
        old_logins: items
            .iter()
            .filter_map(|i| match &i.updated_at {
                Some(updated) if i.kind == "login" && *updated < cutoff => Some(OldLogin {
                    id: i.id.clone(),
                    title: i.title.clone(),
                    updated_at: updated.clone(),
                }),
                _ => None,
            })
            .collect(),
        urls_to_review: items
            .iter()
            .filter_map(|i| {
                let urls: Vec<String> = i
                    .urls
                    .iter()
                    .filter(|u| {
                        let lower = u.to_lowercase();
                        TRANSIENT.iter().any(|t| lower.contains(t))
                    })
                    .cloned()
                    .collect();
                (!urls.is_empty()).then(|| UrlReview {
                    id: i.id.clone(),
                    title: i.title.clone(),
                    urls,
                })
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_query_fragment_and_userinfo() {
        assert_eq!(
            safe_url("https://a.com/reset?token=sentinel#x"),
            "https://a.com/reset"
        );
        assert_eq!(safe_url("https://user:sentinel@a.com/p"), "https://a.com/p");
        assert_eq!(safe_url("a.com/x?y"), "a.com/x");
    }

    fn inv(
        id: &str,
        title: &str,
        kind: &str,
        tags: &[&str],
        updated: &str,
        urls: &[&str],
    ) -> InventoryItem {
        InventoryItem {
            id: id.into(),
            title: title.into(),
            vault: "V".into(),
            kind: kind.into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            created_at: None,
            updated_at: Some(updated.into()),
            fields: vec![],
        }
    }

    #[test]
    fn audits() {
        let items = vec![
            inv(
                "1",
                "GitHub",
                "login",
                &[],
                "2019-01-01T00:00:00Z",
                &["https://github.com/login/oauth"],
            ),
            inv("2", "github", "login", &["x"], "2026-01-01T00:00:00Z", &[]),
            inv(
                "3",
                "Stripe API Key",
                "api-credential",
                &[],
                "2026-01-01T00:00:00Z",
                &[],
            ),
        ];
        let a = audit(&items, "2026-10-12T00:00:00Z");
        assert_eq!(a.summary.untagged, 2);
        assert_eq!(a.duplicate_titles.len(), 1);
        assert_eq!(a.untagged_machine_credentials.len(), 1);
        assert_eq!(a.old_logins.len(), 1);
        assert_eq!(a.urls_to_review.len(), 1);
    }
}
