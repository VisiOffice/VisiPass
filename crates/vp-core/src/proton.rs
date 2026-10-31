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
    /// Passkeys that could not come over (a key type VisiPass does not use,
    /// or content it could not read); their logins still do.
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
            imported_passkeys: Vec::new(),
            passkeys: Vec::new(),
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

/// One passkey from a login's `passkeys`, private key included. Proton keeps
/// it in `content`: base64 of MessagePack `{c, v: 1}` whose `c` is MessagePack
/// of a `ProtonPassKey` (proton-pass-common, `passkey/protonpasskey.rs`): a COSE
/// key in `key`, credential ID `cid`, RP ID `rid`, user handle `uhd`. Only an
/// EC2 P-256 key comes over, the only kind VisiPass signs with; anything else,
/// or anything unreadable, is None and counted as left behind.
fn passkey(p: &Value) -> Option<crate::passkey::Imported> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use rmpv::Value as Mp;
    use zeroize::Zeroizing;

    let decode64 = |text: &str| {
        let text = text.trim();
        STANDARD
            .decode(text)
            .or_else(|_| STANDARD_NO_PAD.decode(text.trim_end_matches('=')))
            .ok()
    };
    fn get<'a>(map: &'a Mp, key: &str) -> Option<&'a Mp> {
        map.as_map()?
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }
    // rmp_serde writes a Vec<u8> as an array of integers; accept bin too.
    fn bytes(v: &Mp) -> Option<Vec<u8>> {
        match v {
            Mp::Binary(b) => Some(b.clone()),
            Mp::Array(items) => items
                .iter()
                .map(|i| i.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect(),
            _ => None,
        }
    }
    // An adjacently tagged label, {t: "assign" | "int" | "txt", c: ...}: its
    // content as a name (unit variants are written by name) or a number.
    fn tagged(v: &Mp) -> Option<&Mp> {
        get(v, "c")
    }
    fn read(bytes: &[u8]) -> Option<Mp> {
        let mut slice = bytes;
        let value = rmpv::decode::read_value(&mut slice).ok()?;
        slice.is_empty().then_some(value)
    }

    let outer = read(&Zeroizing::new(decode64(p.get("content")?.as_str()?)?))?;
    if get(&outer, "v")?.as_u64()? != 1 {
        return None;
    }
    let inner = read(&Zeroizing::new(bytes(get(&outer, "c")?)?))?;
    let key = get(&inner, "key")?;
    let kty = tagged(get(key, "kty")?)?;
    if !(kty.as_str() == Some("EC2") || kty.as_i64() == Some(2)) {
        return None;
    }
    if let Some(alg) = get(key, "alg").filter(|a| !a.is_nil()) {
        let alg = tagged(alg)?;
        if !(alg.as_str() == Some("ES256") || alg.as_i64() == Some(crate::passkey::ES256)) {
            return None;
        }
    }
    let mut curve = None;
    let mut scalar = None;
    for pair in get(key, "par")?.as_array()? {
        let [label, value] = pair.as_array()?.as_slice() else {
            return None;
        };
        let label = tagged(label)?.as_i64();
        let value_tag = get(value, "t")?.as_str()?;
        let value = tagged(value)?;
        match (label, value_tag) {
            // crv: a COSE integer, little-endian bytes of an i128.
            (Some(-1), "int") => {
                let inner = bytes(get(value, "inner")?)?;
                curve = Some(
                    inner
                        .iter()
                        .rev()
                        .fold(0i128, |n, b| n << 8 | i128::from(*b)),
                );
            }
            (Some(-4), "bytes") => scalar = Some(Zeroizing::new(bytes(value)?)),
            _ => {}
        }
    }
    if curve != Some(1) {
        return None;
    }
    let scalar = scalar?;
    let encoded = Zeroizing::new(crate::passkey::b64(&scalar));
    // Check the scalar is a usable P-256 key before it is saved.
    crate::passkey::Key::import(&encoded).ok()?;

    let text = |v: Option<&Mp>| v.and_then(Mp::as_str).map(String::from);
    let json_text = |key: &str| text_of(p, key);
    let rp_id = text(get(&inner, "rid")).or_else(|| json_text("rpId"))?;
    let credential_id = bytes(get(&inner, "cid")?)?;
    let user_handle = get(&inner, "uhd")
        .and_then(bytes)
        .or_else(|| json_text("userHandle").and_then(|t| decode64(&t)))
        .unwrap_or_default();
    if credential_id.is_empty() || rp_id.is_empty() {
        return None;
    }
    Some(crate::passkey::Imported {
        info: crate::model::PasskeyInfo {
            credential_id: crate::passkey::b64(&credential_id),
            rp_id,
            user_name: text(get(&inner, "un"))
                .or_else(|| json_text("userName"))
                .unwrap_or_default(),
            created_at: p
                .get("createTime")
                .and_then(Value::as_u64)
                .filter(|t| *t > 0)
                .map(crate::time::rfc3339),
        },
        user_handle: crate::passkey::b64(&user_handle),
        user_display_name: text(get(&inner, "udn"))
            .or_else(|| json_text("userDisplayName"))
            .unwrap_or_default(),
        key: Secret::new(encoded.to_string()),
    })
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
    let mut imported = Vec::new();
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
            for p in content
                .get("passkeys")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                match passkey(p) {
                    Some(p) => imported.push(p),
                    None => left.passkeys += 1,
                }
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
        passkeys: imported.iter().map(|p| p.info.clone()).collect(),
        imported_passkeys: imported,
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

    /// Proton's own types (proton-pass-common, passkey/protonpasskey.rs and
    /// passkey_handling.rs), with the serde attributes they carry, so the
    /// test's content is exactly what Proton writes (names included, as
    /// serde writes unit variants by name).
    #[allow(clippy::upper_case_acronyms)]
    mod proton_types {
        use serde::Serialize;

        #[derive(Serialize)]
        pub struct SerializedPassKey {
            #[serde(rename = "c")]
            pub content: Vec<u8>,
            #[serde(rename = "v")]
            pub format_version: u8,
        }
        #[derive(Serialize)]
        pub struct ProtonPassKey {
            pub key: ProtonKey,
            #[serde(rename = "cid")]
            pub credential_id: Vec<u8>,
            #[serde(rename = "rid")]
            pub rp_id: String,
            #[serde(rename = "uhd")]
            pub user_handle: Option<Vec<u8>>,
            #[serde(rename = "cnt")]
            pub counter: Option<u32>,
            #[serde(rename = "ext")]
            pub extensions: Extensions,
            #[serde(rename = "udn")]
            pub user_display_name: Option<String>,
            #[serde(rename = "un")]
            pub username: Option<String>,
        }
        #[derive(Serialize)]
        pub struct Extensions {
            pub hmac_secret: Option<()>,
        }
        #[derive(Serialize)]
        pub struct ProtonKey {
            pub kty: KeyTypeLabel,
            #[serde(rename = "kid")]
            pub key_id: Vec<u8>,
            pub alg: Option<AlgorithmLabel>,
            #[serde(rename = "kops")]
            pub key_ops: Vec<()>,
            #[serde(rename = "biv")]
            pub base_iv: Vec<u8>,
            #[serde(rename = "par")]
            pub params: Vec<(Label, ProtonValue)>,
        }
        #[derive(Serialize)]
        pub enum KeyType {
            OKP = 1,
            EC2 = 2,
        }
        #[derive(Serialize)]
        #[serde(tag = "t", content = "c")]
        pub enum KeyTypeLabel {
            #[serde(rename = "assign")]
            Assigned(KeyType),
        }
        #[derive(Serialize)]
        pub enum Algorithm {
            EdDSA = -8,
            ES256 = -7,
        }
        #[derive(Serialize)]
        #[serde(tag = "t", content = "c")]
        pub enum AlgorithmLabel {
            #[serde(rename = "assign")]
            Assigned(Algorithm),
        }
        #[derive(Serialize)]
        #[serde(tag = "t", content = "c")]
        pub enum Label {
            #[serde(rename = "int")]
            Int(i64),
        }
        #[derive(Serialize)]
        #[serde(tag = "t", content = "c")]
        pub enum ProtonValue {
            #[serde(rename = "int")]
            Integer(ProtonInteger),
            #[serde(rename = "bytes")]
            Bytes(Vec<u8>),
        }
        #[derive(Serialize)]
        pub struct ProtonInteger {
            pub inner: Vec<u8>,
        }
    }

    /// A passkey entry as Proton's export holds it, for a P-256 key with
    /// scalar `d` (or an Ed25519 one when `ed25519`).
    fn proton_passkey(d: &[u8; 32], ed25519: bool) -> Value {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use proton_types::*;
        let int = |n: i128| {
            ProtonValue::Integer(ProtonInteger {
                inner: n.to_le_bytes().to_vec(),
            })
        };
        let (kty, alg, params) = if ed25519 {
            (
                KeyType::OKP,
                Algorithm::EdDSA,
                vec![
                    (Label::Int(-1), int(6)),
                    (Label::Int(-4), ProtonValue::Bytes(d.to_vec())),
                ],
            )
        } else {
            let key = p256::ecdsa::SigningKey::from_slice(d).unwrap();
            let point = key.verifying_key().to_encoded_point(false);
            (
                KeyType::EC2,
                Algorithm::ES256,
                vec![
                    (Label::Int(-1), int(1)),
                    (
                        Label::Int(-2),
                        ProtonValue::Bytes(point.x().unwrap().to_vec()),
                    ),
                    (
                        Label::Int(-3),
                        ProtonValue::Bytes(point.y().unwrap().to_vec()),
                    ),
                    (Label::Int(-4), ProtonValue::Bytes(d.to_vec())),
                ],
            )
        };
        let inner = ProtonPassKey {
            key: ProtonKey {
                kty: KeyTypeLabel::Assigned(kty),
                key_id: vec![],
                alg: Some(AlgorithmLabel::Assigned(alg)),
                key_ops: vec![],
                base_iv: vec![],
                params,
            },
            credential_id: vec![1, 2, 3, 250],
            rp_id: "github.com".into(),
            user_handle: Some(vec![9, 8, 7]),
            counter: None,
            extensions: Extensions { hmac_secret: None },
            user_display_name: Some("Robert".into()),
            username: Some("robert@example.com".into()),
        };
        let content = rmp_serde::to_vec_named(&SerializedPassKey {
            content: rmp_serde::to_vec_named(&inner).unwrap(),
            format_version: 1,
        })
        .unwrap();
        serde_json::json!({
            "keyId": "k", "content": STANDARD.encode(content), "domain": "github.com",
            "rpId": "github.com", "rpName": "GitHub", "userName": "robert@example.com",
            "userDisplayName": "Robert", "userId": "", "createTime": 1700000000, "note": "",
            "credentialId": STANDARD.encode([1, 2, 3, 250]), "userHandle": STANDARD.encode([9, 8, 7]),
        })
    }

    #[test]
    fn a_p256_passkey_comes_over_with_its_key_and_others_are_counted() {
        let d = [7u8; 32];
        let export = serde_json::json!({
            "version": "1.0", "userId": "u", "encrypted": false,
            "vaults": {"shareA": {"name": "Personal", "description": "", "items": [
                {"itemId": "i1", "shareId": "shareA", "state": 1, "createTime": 1700000000,
                 "data": {"metadata": {"name": "GitHub", "note": ""}, "extraFields": [], "type": "login",
                          "content": {"itemUsername": "robert", "password": "sentinel-pass-2",
                                      "urls": ["https://github.com"], "totpUri": "",
                                      "passkeys": [proton_passkey(&d, false), proton_passkey(&d, true)]}}}
            ]}}
        });
        let parsed = parse(export.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.left.passkeys, 1, "the Ed25519 one stays behind");
        let item = &parsed.vaults[0].items[0];
        assert_eq!(item.imported_passkeys.len(), 1);
        let p = &item.imported_passkeys[0];
        assert_eq!(p.info.rp_id, "github.com");
        assert_eq!(p.info.credential_id, crate::passkey::b64(&[1, 2, 3, 250]));
        assert_eq!(p.info.user_name, "robert@example.com");
        assert_eq!(p.user_handle, crate::passkey::b64(&[9, 8, 7]));
        assert_eq!(p.user_display_name, "Robert");
        assert_eq!(p.key.expose(), crate::passkey::b64(&d));
        assert_eq!(item.passkeys, vec![p.info.clone()]);
        // The key never reaches the item's JSON.
        let json = serde_json::to_string(item).unwrap();
        assert!(!json.contains(&crate::passkey::b64(&d)));
    }

    #[test]
    fn unreadable_passkey_content_is_counted_not_imported() {
        for content in ["", "not base64!", "AAAA", "gqFjkKF2Ag=="] {
            let p = serde_json::json!({"keyId": "k", "content": content, "rpId": "github.com"});
            assert!(passkey(&p).is_none(), "{content}");
        }
    }
}
