//! Duplicate logins: the same site and username saved more than once, as two
//! imports from different password managers leave behind. Pure: the daemon
//! fetches the items and compares their passwords; what leaves it says only
//! whether they agree ("A", "B"), never what they are.

use crate::find;
use crate::model::{Field, Item, ItemSummary, UrlEntry, VaultRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Logins that share a site and username, as indexes into `items`. A login is
/// placed by its first website; one without a website is not grouped.
pub fn candidates(items: &[ItemSummary]) -> Vec<(String, String, Vec<usize>)> {
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        if item.category != "LOGIN" {
            continue;
        }
        let Some(site) = item.urls.first().and_then(|u| find::site_of(&u.href)) else {
            continue;
        };
        let username = item
            .additional_information
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        groups.entry((site, username)).or_default().push(i);
    }
    groups
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|((site, username), members)| (site, username, members))
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: String,
    pub title: String,
    pub vault: VaultRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub urls: Vec<String>,
    /// Which password this login has: "A", "B", ... by first appearance in
    /// the group, or none when it has no password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Two-factor codes saved on it.
    pub codes: usize,
    pub notes: bool,
    /// Fields besides username, password, codes and notes.
    pub fields: usize,
    /// The one to keep if the human does not choose.
    pub suggested: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub site: String,
    pub username: String,
    /// Every login in the group has the same password: keeping one loses nothing.
    pub same_password: bool,
    pub items: Vec<Member>,
}

fn has_purpose(field: &Field, purpose: &str) -> bool {
    field.purpose.as_deref() == Some(purpose)
}

fn value(field: &Field) -> Option<&str> {
    field
        .value
        .as_ref()
        .map(|v| v.expose())
        .filter(|v| !v.trim().is_empty())
}

fn is_extra(field: &Field) -> bool {
    !["USERNAME", "PASSWORD", "NOTES"]
        .iter()
        .any(|p| has_purpose(field, p))
        && field.kind != "OTP"
}

/// Describes a group of fetched logins without their values.
pub fn group(site: String, username: String, items: &[Item]) -> Group {
    let mut passwords: Vec<&str> = Vec::new();
    let mut members: Vec<Member> = items
        .iter()
        .map(|item| {
            let password = item
                .fields
                .iter()
                .find(|f| has_purpose(f, "PASSWORD"))
                .and_then(value)
                .map(|p| {
                    let n = passwords.iter().position(|q| *q == p).unwrap_or_else(|| {
                        passwords.push(p);
                        passwords.len() - 1
                    });
                    char::from(b'A' + (n % 26) as u8).to_string()
                });
            let filled = |f: &&Field| value(f).is_some();
            Member {
                id: item.id.clone(),
                title: item.title.clone(),
                vault: item.vault.clone(),
                updated_at: item.updated_at.clone(),
                urls: item.urls.iter().map(|u| u.href.clone()).collect(),
                password,
                codes: item
                    .fields
                    .iter()
                    .filter(filled)
                    .filter(|f| f.kind == "OTP")
                    .count(),
                notes: item
                    .fields
                    .iter()
                    .filter(filled)
                    .any(|f| has_purpose(f, "NOTES")),
                fields: item
                    .fields
                    .iter()
                    .filter(filled)
                    .filter(|f| is_extra(f))
                    .count(),
                suggested: false,
            }
        })
        .collect();
    let same_password = passwords.len() <= 1;
    // With one password, keep the fullest; with several, the most recently
    // changed, whose password is likeliest to be the current one.
    let best = (0..members.len()).max_by(|&a, &b| {
        let (a, b) = (&members[a], &members[b]);
        let fullness = |m: &Member| m.codes * 4 + m.fields * 2 + m.urls.len() + m.notes as usize;
        let newer = a.updated_at.cmp(&b.updated_at);
        if same_password {
            fullness(a).cmp(&fullness(b)).then(newer)
        } else {
            newer.then(fullness(a).cmp(&fullness(b)))
        }
    });
    if let Some(best) = best {
        members[best].suggested = true;
    }
    Group {
        site,
        username,
        same_password,
        items: members,
    }
}

/// What a merge copied onto the login that is kept.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Added {
    /// Passwords that differed from the kept one.
    pub passwords: usize,
    pub urls: usize,
    pub codes: usize,
    pub notes: usize,
    pub fields: usize,
}

fn same_href(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_lowercase();
    norm(a) == norm(b)
}

/// Copies onto `keep` what only the others have: websites, two-factor codes,
/// notes, tags and other fields, and any password that differs from the kept
/// one, as a concealed "other password" field. So nothing is lost when the
/// others are archived, even if the wrong login was kept.
pub fn merge(mut keep: Item, others: &[Item]) -> (Item, Added) {
    let mut added = Added::default();
    let next_id = |fields: &[Field]| {
        (1..)
            .map(|n| format!("merged{n}"))
            .find(|id| !fields.iter().any(|f| &f.id == id))
            .unwrap_or_default()
    };
    for other in others {
        keep.favorite |= other.favorite;
        for tag in &other.tags {
            if !keep.tags.contains(tag) {
                keep.tags.push(tag.clone());
            }
        }
        for url in &other.urls {
            if !keep.urls.iter().any(|u| same_href(&u.href, &url.href)) {
                keep.urls.push(UrlEntry {
                    href: url.href.clone(),
                    label: url.label.clone(),
                    primary: keep.urls.is_empty(),
                });
                added.urls += 1;
            }
        }
        for field in &other.fields {
            let Some(text) = value(field) else { continue };
            if has_purpose(field, "USERNAME") {
                continue;
            }
            if has_purpose(field, "PASSWORD") {
                if keep.fields.iter().any(|f| value(f) == Some(text)) {
                    continue;
                }
                let id = next_id(&keep.fields);
                keep.fields.push(Field {
                    id,
                    label: Some(format!("other password ({})", other.title)),
                    kind: "CONCEALED".into(),
                    purpose: None,
                    section: None,
                    value: field.value.clone(),
                    reference: None,
                });
                added.passwords += 1;
                continue;
            }
            if has_purpose(field, "NOTES") {
                match keep.fields.iter_mut().find(|f| has_purpose(f, "NOTES")) {
                    Some(notes) => {
                        let current = notes.value.as_ref().map(|v| v.expose()).unwrap_or("");
                        if current.contains(text.trim()) {
                            continue;
                        }
                        let joined = if current.trim().is_empty() {
                            text.to_string()
                        } else {
                            format!("{current}\n\n{text}")
                        };
                        notes.value = Some(crate::secret::Secret::new(joined));
                    }
                    None => {
                        let mut notes = field.clone();
                        notes.id = "notesPlain".into();
                        notes.section = None;
                        notes.reference = None;
                        keep.fields.push(notes);
                    }
                }
                added.notes += 1;
                continue;
            }
            let duplicate = keep.fields.iter().any(|f| {
                value(f) == Some(text)
                    && (field.kind == "OTP" && f.kind == "OTP"
                        || f.display_label() == field.display_label())
            });
            if duplicate {
                continue;
            }
            let mut copy = field.clone();
            copy.id = if keep.fields.iter().any(|f| f.id == field.id) {
                next_id(&keep.fields)
            } else {
                field.id.clone()
            };
            copy.section = None;
            copy.reference = None;
            keep.fields.push(copy);
            if field.kind == "OTP" {
                added.codes += 1;
            } else {
                added.fields += 1;
            }
        }
    }
    (keep, added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Url;
    use crate::secret::Secret;

    fn summary(id: &str, url: &str, user: &str) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            title: id.into(),
            category: "LOGIN".into(),
            vault: VaultRef {
                id: "v".into(),
                name: "Personal".into(),
            },
            tags: vec![],
            urls: vec![Url { href: url.into() }],
            favorite: false,
            updated_at: None,
            additional_information: Some(user.into()),
        }
    }

    fn field(id: &str, kind: &str, purpose: Option<&str>, value: &str) -> Field {
        Field {
            id: id.into(),
            label: Some(id.into()),
            kind: kind.into(),
            purpose: purpose.map(String::from),
            section: None,
            value: Some(Secret::new(value.into())),
            reference: None,
        }
    }

    fn login(id: &str, updated: &str, password: &str, extra: Vec<Field>) -> Item {
        let mut fields = vec![
            field("username", "STRING", Some("USERNAME"), "robert"),
            field("password", "CONCEALED", Some("PASSWORD"), password),
        ];
        fields.extend(extra);
        Item {
            id: id.into(),
            title: "Chase".into(),
            category: "LOGIN".into(),
            vault: VaultRef {
                id: "v".into(),
                name: "Personal".into(),
            },
            tags: vec![],
            urls: vec![UrlEntry {
                href: "https://chase.com".into(),
                label: None,
                primary: true,
            }],
            favorite: false,
            created_at: None,
            updated_at: Some(updated.into()),
            sections: vec![],
            fields,
        }
    }

    #[test]
    fn logins_group_by_site_and_username_across_subdomains_and_case() {
        let items = vec![
            summary("a", "https://chase.com", "Robert"),
            summary("b", "https://secure.chase.com/login", "robert "),
            summary("c", "https://chase.com", "someone-else"),
            summary("d", "https://example.com", "robert"),
        ];
        let groups = candidates(&items);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "chase.com");
        assert_eq!(groups[0].2, vec![0, 1]);
    }

    #[test]
    fn same_passwords_keep_the_fullest_and_say_so_without_values() {
        let plain = login("a", "2026-01-01T00:00:00Z", "sentinel-pw", vec![]);
        let full = login(
            "b",
            "2020-01-01T00:00:00Z",
            "sentinel-pw",
            vec![field("TOTP_1", "OTP", None, "otpauth://totp/x?secret=A")],
        );
        let group = group("chase.com".into(), "robert".into(), &[plain, full]);
        assert!(group.same_password);
        assert!(group.items[1].suggested && !group.items[0].suggested);
        assert_eq!(group.items[0].password.as_deref(), Some("A"));
        let json = serde_json::to_string(&group).unwrap();
        assert!(!json.contains("sentinel-pw"));
        assert!(!json.contains("secret=A"));
    }

    #[test]
    fn different_passwords_suggest_the_newest() {
        let old = login("a", "2020-01-01T00:00:00Z", "one", vec![]);
        let new = login("b", "2026-01-01T00:00:00Z", "two", vec![]);
        let group = group("chase.com".into(), "robert".into(), &[old, new]);
        assert!(!group.same_password);
        assert_eq!(group.items[1].password.as_deref(), Some("B"));
        assert!(group.items[1].suggested);
    }

    #[test]
    fn merge_brings_what_only_the_others_have() {
        let keep = login(
            "a",
            "2026-01-01T00:00:00Z",
            "one",
            vec![field("notesPlain", "STRING", Some("NOTES"), "first")],
        );
        let mut other = login(
            "b",
            "2020-01-01T00:00:00Z",
            "two",
            vec![
                field("notesPlain", "STRING", Some("NOTES"), "second"),
                field("TOTP_1", "OTP", None, "otpauth://totp/x?secret=A"),
                field("PIN", "CONCEALED", None, "1234"),
            ],
        );
        other.urls.push(UrlEntry {
            href: "https://chase.com/".into(),
            label: None,
            primary: false,
        });
        other.urls.push(UrlEntry {
            href: "https://secure.chase.com".into(),
            label: None,
            primary: false,
        });
        other.tags.push("bank".into());
        let (merged, added) = merge(keep, std::slice::from_ref(&other));
        assert_eq!(
            added,
            Added {
                passwords: 1,
                urls: 1,
                codes: 1,
                notes: 1,
                fields: 1
            }
        );
        let get = |purpose: &str| {
            merged
                .fields
                .iter()
                .find(|f| f.purpose.as_deref() == Some(purpose))
                .and_then(|f| f.value.as_ref())
                .map(|v| v.expose().to_string())
        };
        assert_eq!(
            get("PASSWORD").as_deref(),
            Some("one"),
            "the kept password stays"
        );
        let older = merged
            .fields
            .iter()
            .find(|f| f.label.as_deref() == Some("other password (Chase)"))
            .unwrap();
        assert_eq!(older.kind, "CONCEALED");
        assert_eq!(older.value.as_ref().map(|v| v.expose()), Some("two"));
        assert_eq!(get("NOTES").as_deref(), Some("first\n\nsecond"));
        assert_eq!(merged.tags, vec!["bank".to_string()]);
        // Merging again adds nothing.
        let (_, again) = merge(merged, &[other]);
        assert_eq!(again, Added::default());
    }
}
