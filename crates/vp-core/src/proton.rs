//! Reads a Proton Pass export (Settings → Export, as an unencrypted ZIP or a
//! CSV) into VisiPass items. Pure: the daemon reads the file and unzips it.
//!
//! IDs are derived from Proton's share and item IDs (a CSV has none, so from
//! the vault, type, name and creation time), so importing the same export
//! twice skips what is already there instead of making duplicates.

use crate::Failure;
use crate::model::{Field, Item, SectionRef, UrlEntry, VaultRef};
use crate::secret::Secret;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// One Proton vault and the items it holds.
#[derive(Debug)]
pub struct ProtonVault {
    /// A VisiPass vault ID derived from Proton's share ID.
    pub id: String,
    pub name: String,
    pub items: Vec<Item>,
}

/// What the export held that does not become an item.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Left {
    /// In Proton's trash.
    pub trashed: usize,
    /// Hide-my-email aliases: they live in Proton, there is no secret to keep.
    pub aliases: usize,
    /// Item types VisiPass does not know.
    pub unknown: usize,
    /// Logins that had passkeys; the login comes over, the passkey cannot.
    pub passkeys: usize,
    /// Cards, identities and SSH keys in a CSV export, which holds only their
    /// name and note.
    pub incomplete: usize,
}

#[derive(Debug)]
pub struct Export {
    pub vaults: Vec<ProtonVault>,
    pub left: Left,
}

/// A 26-character ID in the alphabet VisiPass uses, from a hash of `parts`.
fn derived_id(parts: &[&str]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    hash.finalize()[..26]
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect()
}

const ENCRYPTED: &str =
    "This Proton Pass export is encrypted. Export again and choose ZIP (or CSV)";

pub fn parse(bytes: &[u8]) -> Result<Export, Failure> {
    let text = String::from_utf8_lossy(bytes);
    let start = text.trim_start_matches('\u{feff}').trim_start();
    if start.starts_with("-----BEGIN PGP") {
        return Err(Failure::new(ENCRYPTED));
    }
    if start.starts_with("type,name,") {
        return parse_csv(start);
    }
    let root: Value = serde_json::from_str(start).map_err(|_| {
        Failure::new(
            "This is not a Proton Pass export. In Proton Pass: Settings → Export, choose ZIP",
        )
    })?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(Failure::new(ENCRYPTED));
    }
    let Some(shares) = root.get("vaults").and_then(Value::as_object) else {
        return Err(Failure::new(
            "This is not a Proton Pass JSON export (no vaults in it)",
        ));
    };
    let mut left = Left::default();
    let mut vaults = Vec::new();
    for (share_id, share) in shares {
        let name = text_of(share, "name").unwrap_or_else(|| "Proton Pass".into());
        let id = derived_id(&["proton-pass-vault", share_id]);
        let vault = VaultRef {
            id: id.clone(),
            name: name.clone(),
        };
        let mut items = Vec::new();
        for raw in share
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // 1 is active, 2 is in the trash.
            if raw.get("state").and_then(Value::as_i64) == Some(2) {
                left.trashed += 1;
                continue;
            }
            let item_id = text_of(raw, "itemId").unwrap_or_default();
            if let Some(mut item) = item(raw, &vault, &mut left) {
                item.id = derived_id(&["proton-pass-item", share_id, &item_id]);
                items.push(item);
            }
        }
        vaults.push(ProtonVault { id, name, items });
    }
    Ok(Export { vaults, left })
}

/// Proton's CSV: type,name,url,autofillUrls,email,username,password,note,totp,
/// createTime,modifyTime,vault. `autofillUrls` is a JSON list of {url, mode};
/// `url` is the same URLs joined with commas. Trash is not exported.
fn parse_csv(text: &str) -> Result<Export, Failure> {
    let mut rows = csv_rows(text).into_iter();
    let header = rows.next().unwrap_or_default();
    let column = |name: &str| header.iter().position(|h| h == name);
    let (Some(kind), Some(name)) = (column("type"), column("name")) else {
        return Err(Failure::new("This CSV is not a Proton Pass export"));
    };
    let [
        url,
        autofill,
        email,
        username,
        password,
        note,
        totp,
        created,
        modified,
        vault_name,
    ] = [
        "url",
        "autofillUrls",
        "email",
        "username",
        "password",
        "note",
        "totp",
        "createTime",
        "modifyTime",
        "vault",
    ]
    .map(column);
    let mut left = Left::default();
    let mut vaults: Vec<ProtonVault> = Vec::new();
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for row in rows {
        if row.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let cell = |i: Option<usize>| {
            i.and_then(|i| row.get(i))
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(String::from)
        };
        let vault_name = cell(vault_name).unwrap_or_else(|| "Proton Pass".into());
        let kind = cell(Some(kind)).unwrap_or_default();
        let title = cell(Some(name)).unwrap_or_else(|| "Untitled".into());
        let created = cell(created);
        let mut f = Fields {
            fields: Vec::new(),
            sections: Vec::new(),
        };
        let mut urls = Vec::new();
        let category = match kind.as_str() {
            "login" => {
                let email = cell(email);
                let username = cell(username).or_else(|| email.clone());
                let separate_email = email.filter(|e| Some(e) != username.as_ref());
                f.add(
                    Some("username"),
                    "username",
                    "STRING",
                    Some("USERNAME"),
                    username,
                    None,
                );
                f.add(
                    Some("password"),
                    "password",
                    "CONCEALED",
                    Some("PASSWORD"),
                    cell(password),
                    None,
                );
                f.add(Some("email"), "email", "STRING", None, separate_email, None);
                f.otp(cell(totp), None);
                let listed: Vec<String> = cell(autofill)
                    .and_then(|a| serde_json::from_str::<Vec<Value>>(&a).ok())
                    .map(|a| a.iter().filter_map(|e| text_of(e, "url")).collect())
                    .filter(|a: &Vec<String>| !a.is_empty())
                    .or_else(|| cell(url).map(|u| vec![u]))
                    .unwrap_or_default();
                for (i, href) in listed.into_iter().enumerate() {
                    urls.push(UrlEntry {
                        href,
                        label: None,
                        primary: i == 0,
                    });
                }
                "LOGIN"
            }
            "note" => "SECURE_NOTE",
            "alias" => {
                left.aliases += 1;
                continue;
            }
            "creditCard" | "identity" | "sshKey" | "wifi" | "custom" => {
                left.incomplete += 1;
                continue;
            }
            _ => {
                left.unknown += 1;
                continue;
            }
        };
        f.add(
            Some("notesPlain"),
            "notesPlain",
            "STRING",
            Some("NOTES"),
            cell(note),
            None,
        );
        let vault_id = derived_id(&["proton-pass-vault-name", &vault_name]);
        let base = [
            "proton-pass-csv-item",
            &vault_name,
            &kind,
            &title,
            created.as_deref().unwrap_or(""),
        ]
        .join("\u{0}");
        // Same vault, type, name and creation second: tell them apart by order.
        let n = seen.entry(base.clone()).or_default();
        *n += 1;
        let id = derived_id(&[&base, &n.to_string()]);
        let time = |s: Option<String>| s.and_then(|s| s.parse().ok()).map(crate::time::rfc3339);
        let vault = VaultRef {
            id: vault_id.clone(),
            name: vault_name.clone(),
        };
        let item = Item {
            id,
            title,
            category: category.into(),
            vault: vault.clone(),
            tags: vec![],
            urls,
            favorite: false,
            created_at: time(created),
            updated_at: time(cell(modified)),
            sections: f.sections,
            fields: f.fields,
        };
        match vaults.iter_mut().find(|v| v.id == vault_id) {
            Some(v) => v.items.push(item),
            None => vaults.push(ProtonVault {
                id: vault_id,
                name: vault_name,
                items: vec![item],
            }),
        }
    }
    Ok(Export { vaults, left })
}

/// RFC 4180: quoted cells may hold commas, newlines and doubled quotes.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            '"' if quoted => quoted = false,
            '"' if cell.is_empty() => quoted = true,
            ',' if !quoted => row.push(std::mem::take(&mut cell)),
            '\r' if !quoted && chars.peek() == Some(&'\n') => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            c => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}

fn text_of(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Builds fields with IDs unique within the item.
struct Fields {
    fields: Vec<Field>,
    sections: Vec<SectionRef>,
}

impl Fields {
    fn add(
        &mut self,
        id: Option<&str>,
        label: &str,
        kind: &str,
        purpose: Option<&str>,
        value: Option<String>,
        section: Option<&SectionRef>,
    ) {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            return;
        };
        let id = match id {
            Some(id) if !self.fields.iter().any(|f| f.id == id) => id.to_string(),
            _ => format!("field{}", self.fields.len() + 1),
        };
        self.fields.push(Field {
            id,
            label: Some(label.into()),
            kind: kind.into(),
            purpose: purpose.map(String::from),
            section: section.cloned(),
            value: Some(Secret::new(value)),
            reference: None,
        });
    }

    fn otp(&mut self, uri: Option<String>, section: Option<&SectionRef>) {
        let n = self.fields.len() + 1;
        self.add(
            Some(&format!("TOTP_{n}")),
            "one-time password",
            "OTP",
            None,
            uri,
            section,
        );
    }

    /// Proton's custom fields: text, hidden, totp and timestamp.
    fn extra(&mut self, list: Option<&Value>, section: Option<&SectionRef>) {
        for extra in list.and_then(Value::as_array).into_iter().flatten() {
            let label = text_of(extra, "fieldName").unwrap_or_else(|| "field".into());
            let data = extra.get("data").cloned().unwrap_or(Value::Null);
            match extra.get("type").and_then(Value::as_str) {
                Some("totp") => self.otp(
                    text_of(&data, "totpUri").or_else(|| text_of(&data, "content")),
                    section,
                ),
                Some("hidden") => self.add(
                    None,
                    &label,
                    "CONCEALED",
                    None,
                    text_of(&data, "content"),
                    section,
                ),
                Some("timestamp") => {
                    let when = data
                        .get("timestamp")
                        .and_then(Value::as_u64)
                        .map(crate::time::rfc3339)
                        .or_else(|| text_of(&data, "content"));
                    self.add(None, &label, "STRING", None, when, section)
                }
                _ => self.add(
                    None,
                    &label,
                    "STRING",
                    None,
                    text_of(&data, "content"),
                    section,
                ),
            }
        }
    }

    fn section(&mut self, label: Option<String>) -> SectionRef {
        let section = SectionRef {
            id: Some(format!("section{}", self.sections.len() + 1)),
            label,
        };
        self.sections.push(section.clone());
        section
    }
}

/// "socialSecurityNumber" -> "social security number".
fn words(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if c.is_uppercase() && !out.is_empty() {
            out.push(' ');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn item(raw: &Value, vault: &VaultRef, left: &mut Left) -> Option<Item> {
    let data = raw.get("data")?;
    let metadata = data.get("metadata").cloned().unwrap_or(Value::Null);
    let content = data.get("content").cloned().unwrap_or(Value::Null);
    let mut f = Fields {
        fields: Vec::new(),
        sections: Vec::new(),
    };
    let mut urls = Vec::new();
    let category = match data.get("type").and_then(Value::as_str) {
        Some("login") => {
            let email = text_of(&content, "itemEmail");
            let username = text_of(&content, "itemUsername")
                .or_else(|| text_of(&content, "username"))
                .or_else(|| email.clone());
            let separate_email = email.filter(|e| Some(e) != username.as_ref());
            f.add(
                Some("username"),
                "username",
                "STRING",
                Some("USERNAME"),
                username,
                None,
            );
            f.add(
                Some("password"),
                "password",
                "CONCEALED",
                Some("PASSWORD"),
                text_of(&content, "password"),
                None,
            );
            f.add(Some("email"), "email", "STRING", None, separate_email, None);
            f.otp(text_of(&content, "totpUri"), None);
            for (i, href) in content
                .get("urls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .enumerate()
            {
                urls.push(UrlEntry {
                    href: href.into(),
                    label: None,
                    primary: i == 0,
                });
            }
            if content
                .get("passkeys")
                .and_then(Value::as_array)
                .is_some_and(|p| !p.is_empty())
            {
                left.passkeys += 1;
            }
            "LOGIN"
        }
        Some("note") => "SECURE_NOTE",
        Some("creditCard") => {
            for (key, id, label, kind) in [
                ("cardholderName", "cardholder", "cardholder name", "STRING"),
                ("number", "ccnum", "number", "CONCEALED"),
                (
                    "verificationCode",
                    "cvv",
                    "verification number",
                    "CONCEALED",
                ),
                ("expirationDate", "expiry", "expiry date", "STRING"),
                ("pin", "pin", "PIN", "CONCEALED"),
            ] {
                f.add(Some(id), label, kind, None, text_of(&content, key), None);
            }
            "CREDIT_CARD"
        }
        Some("identity") => {
            const CONCEALED: [&str; 3] =
                ["socialSecurityNumber", "passportNumber", "licenseNumber"];
            if let Some(object) = content.as_object() {
                for (key, value) in object {
                    match value {
                        Value::String(_) => {
                            let kind = if CONCEALED.contains(&key.as_str()) {
                                "CONCEALED"
                            } else {
                                "STRING"
                            };
                            f.add(
                                Some(key),
                                &words(key),
                                kind,
                                None,
                                text_of(&content, key),
                                None,
                            )
                        }
                        // extraPersonalDetails, extraAddressDetails, ...: custom fields.
                        Value::Array(_) if key != "extraSections" => f.extra(Some(value), None),
                        _ => {}
                    }
                }
            }
            for extra in content
                .get("extraSections")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let section = f.section(text_of(extra, "sectionName"));
                f.extra(extra.get("sectionFields"), Some(&section));
            }
            "IDENTITY"
        }
        Some("sshKey") => {
            f.add(
                Some("private_key"),
                "private key",
                "CONCEALED",
                None,
                text_of(&content, "privateKey"),
                None,
            );
            f.add(
                Some("public_key"),
                "public key",
                "STRING",
                None,
                text_of(&content, "publicKey"),
                None,
            );
            "SSH_KEY"
        }
        Some("wifi") => {
            f.add(
                Some("network_name"),
                "network name",
                "STRING",
                None,
                text_of(&content, "ssid"),
                None,
            );
            f.add(
                Some("wireless_password"),
                "wireless network password",
                "CONCEALED",
                None,
                text_of(&content, "password"),
                None,
            );
            "WIRELESS_ROUTER"
        }
        Some("custom") => "SECURE_NOTE",
        Some("alias") => {
            left.aliases += 1;
            return None;
        }
        _ => {
            left.unknown += 1;
            return None;
        }
    };
    // Custom items and SSH keys keep their own sections.
    for extra in content
        .get("sections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let section = f.section(text_of(extra, "sectionName"));
        f.extra(extra.get("sectionFields"), Some(&section));
    }
    f.extra(data.get("extraFields"), None);
    f.add(
        Some("notesPlain"),
        "notesPlain",
        "STRING",
        Some("NOTES"),
        metadata
            .get("note")
            .and_then(Value::as_str)
            .map(String::from),
        None,
    );
    let time = |key: &str| {
        raw.get(key)
            .and_then(Value::as_u64)
            .map(crate::time::rfc3339)
    };
    Some(Item {
        id: String::new(),
        title: text_of(&metadata, "name").unwrap_or_else(|| "Untitled".into()),
        category: category.into(),
        vault: vault.clone(),
        tags: vec![],
        urls,
        favorite: raw.get("pinned").and_then(Value::as_bool).unwrap_or(false),
        created_at: time("createTime"),
        updated_at: time("modifyTime"),
        sections: f.sections,
        fields: f.fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = r#"{
      "version": "1.22.0", "userId": "u", "encrypted": false,
      "vaults": {
        "shareA": {
          "name": "Personal", "description": "",
          "items": [
            {"itemId": "i1", "shareId": "shareA", "state": 1, "pinned": true,
             "createTime": 1700000000, "modifyTime": 1700000100,
             "data": {"metadata": {"name": "Chase", "note": "business", "itemUuid": "x"},
                      "extraFields": [{"fieldName": "PIN", "type": "hidden", "data": {"content": "sentinel-pin-1"}},
                                      {"fieldName": "2FA", "type": "totp", "data": {"totpUri": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}}],
                      "type": "login",
                      "content": {"itemEmail": "me@example.com", "itemUsername": "robert",
                                  "password": "sentinel-pass-1", "urls": ["https://chase.com", "https://secure.chase.com"],
                                  "totpUri": "", "passkeys": [{"keyId": "k"}]}}},
            {"itemId": "i2", "shareId": "shareA", "state": 2,
             "data": {"metadata": {"name": "Old"}, "type": "login", "content": {"password": "x"}}},
            {"itemId": "i3", "shareId": "shareA", "state": 1, "aliasEmail": "a@passmail.net",
             "data": {"metadata": {"name": "alias"}, "type": "alias", "content": {}}},
            {"itemId": "i4", "shareId": "shareA", "state": 1,
             "data": {"metadata": {"name": "Visa", "note": ""}, "type": "creditCard",
                      "content": {"cardholderName": "R", "number": "4111111111111111", "verificationCode": "123",
                                  "expirationDate": "2030-01", "pin": ""}}}
          ]
        },
        "shareB": {"name": "Work", "items": [
            {"itemId": "i5", "shareId": "shareB", "state": 1,
             "data": {"metadata": {"name": "Old site", "note": ""}, "type": "login",
                      "content": {"username": "legacy", "password": "pw", "urls": []}}}
        ]}
      }
    }"#;

    fn value<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
        item.fields
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose())
    }

    #[test]
    fn a_login_keeps_its_username_password_sites_codes_and_notes() {
        let export = parse(EXPORT.as_bytes()).unwrap();
        let personal = export.vaults.iter().find(|v| v.name == "Personal").unwrap();
        let chase = &personal.items[0];
        assert_eq!(chase.title, "Chase");
        assert_eq!(chase.category, "LOGIN");
        assert!(chase.favorite);
        assert_eq!(value(chase, "username"), Some("robert"));
        assert_eq!(value(chase, "password"), Some("sentinel-pass-1"));
        assert_eq!(value(chase, "email"), Some("me@example.com"));
        assert_eq!(value(chase, "notesPlain"), Some("business"));
        assert_eq!(chase.urls.len(), 2);
        assert!(chase.urls[0].primary && !chase.urls[1].primary);
        let pin = chase
            .fields
            .iter()
            .find(|f| f.label.as_deref() == Some("PIN"))
            .unwrap();
        assert_eq!(pin.kind, "CONCEALED");
        assert_eq!(chase.fields.iter().filter(|f| f.kind == "OTP").count(), 1);
        assert_eq!(chase.created_at.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert_eq!(chase.vault.id, personal.id);
    }

    #[test]
    fn trash_and_aliases_are_left_out_and_counted() {
        let export = parse(EXPORT.as_bytes()).unwrap();
        assert_eq!(
            export.left,
            Left {
                trashed: 1,
                aliases: 1,
                unknown: 0,
                passkeys: 1,
                incomplete: 0,
            }
        );
        let personal = export.vaults.iter().find(|v| v.name == "Personal").unwrap();
        assert_eq!(personal.items.len(), 2);
        let card = &personal.items[1];
        assert_eq!(card.category, "CREDIT_CARD");
        assert_eq!(value(card, "ccnum"), Some("4111111111111111"));
        assert_eq!(value(card, "pin"), None, "empty fields are not kept");
    }

    #[test]
    fn ids_are_stable_so_importing_again_skips() {
        let a = parse(EXPORT.as_bytes()).unwrap();
        let b = parse(EXPORT.as_bytes()).unwrap();
        let ids = |e: &Export| {
            e.vaults
                .iter()
                .flat_map(|v| v.items.iter().map(|i| i.id.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&a), ids(&b));
        assert!(ids(&a).iter().all(|id| id.len() == 26));
        let mut unique = ids(&a);
        unique.dedup();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn older_exports_with_a_plain_username_still_work() {
        let export = parse(EXPORT.as_bytes()).unwrap();
        let work = export.vaults.iter().find(|v| v.name == "Work").unwrap();
        assert_eq!(value(&work.items[0], "username"), Some("legacy"));
    }

    #[test]
    fn encrypted_and_foreign_files_say_what_to_do() {
        let pgp = parse(b"-----BEGIN PGP MESSAGE-----\n...").unwrap_err();
        assert!(pgp.0.contains("choose ZIP"));
        let encrypted = parse(br#"{"encrypted": true, "vaults": {}}"#).unwrap_err();
        assert!(encrypted.0.contains("choose ZIP"));
        let foreign = parse(b"name,url,email,username,password").unwrap_err();
        assert!(foreign.0.contains("Settings"));
    }

    const CSV: &str = "\u{feff}type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault\r\n\
login,Chase,\"https://chase.com,https://secure.chase.com\",\"[{\"\"url\"\":\"\"https://chase.com\"\",\"\"mode\"\":0},{\"\"url\"\":\"\"https://secure.chase.com\"\",\"\"mode\"\":0}]\",me@example.com,,sentinel-pass-1,\"two\r\nlines, \"\"quoted\"\"\",otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,1700000000,1700000100,Personal\r\n\
login,Chase,https://chase.com,\"[{\"\"url\"\":\"\"https://chase.com\"\",\"\"mode\"\":0}]\",,robert,sentinel-pass-2,,,1700000000,1700000000,Personal\r\n\
note,Wifi,,,,,,the note,,1700000000,1700000000,Work\r\n\
alias,a@passmail.net,,,a@passmail.net,,,,,1700000000,1700000000,Personal\r\n\
creditCard,Visa,,,,,,,,1700000000,1700000000,Personal\r\n";

    #[test]
    fn a_csv_export_brings_logins_and_notes_and_counts_the_rest() {
        let export = parse(CSV.as_bytes()).unwrap();
        assert_eq!(
            export.left,
            Left {
                aliases: 1,
                incomplete: 1,
                ..Left::default()
            }
        );
        let personal = export.vaults.iter().find(|v| v.name == "Personal").unwrap();
        assert_eq!(personal.items.len(), 2);
        let chase = &personal.items[0];
        assert_eq!(value(chase, "username"), Some("me@example.com"));
        assert_eq!(value(chase, "email"), None);
        assert_eq!(value(chase, "password"), Some("sentinel-pass-1"));
        assert_eq!(value(chase, "notesPlain"), Some("two\r\nlines, \"quoted\""));
        assert_eq!(chase.urls.len(), 2);
        assert_eq!(chase.urls[1].href, "https://secure.chase.com");
        assert_eq!(chase.fields.iter().filter(|f| f.kind == "OTP").count(), 1);
        assert_eq!(chase.created_at.as_deref(), Some("2023-11-14T22:13:20Z"));
        let other = &personal.items[1];
        assert_eq!(value(other, "username"), Some("robert"));
        assert_ne!(
            chase.id, other.id,
            "same name and time still get their own IDs"
        );
        let again = parse(CSV.as_bytes()).unwrap();
        assert_eq!(again.vaults[0].items[1].id, other.id);
        let work = export.vaults.iter().find(|v| v.name == "Work").unwrap();
        assert_eq!(work.items[0].category, "SECURE_NOTE");
    }
}
