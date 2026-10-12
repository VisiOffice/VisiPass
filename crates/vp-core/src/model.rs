//! Item metadata. None of these types has a `value` field: decoding a backend's
//! JSON into them drops every secret before the rest of VisiPass sees it.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRef {
    #[serde(default)]
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub category: String,
    pub vault: VaultRef,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub urls: Vec<Url>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
    /// What the backend shows under the title: the username for a login.
    #[serde(default)]
    pub additional_information: Option<String>,
}

/// A listed item plus the backend's own entry for it, kept verbatim so the
/// backend can fetch details for many items in one call.
#[derive(Clone, Debug)]
pub struct Listed {
    pub summary: ItemSummary,
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Url {
    pub href: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionMeta {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldMeta {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub section: Option<SectionMeta>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemDetail {
    pub id: String,
    pub title: String,
    pub category: String,
    pub vault: VaultRef,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub urls: Vec<Url>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldMeta>,
}

// ---- Human surfaces only ------------------------------------------------
//
// The types below carry values. They travel only on the desktop app's private
// channel, never on the public socket agents use.

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<SectionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<crate::secret::Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Field {
    pub fn concealed(&self) -> bool {
        self.kind == "CONCEALED" || self.purpose.as_deref() == Some("PASSWORD")
    }

    pub fn display_label(&self) -> String {
        match (self.label.as_deref(), self.purpose.as_deref()) {
            (_, Some("USERNAME")) => "username".into(),
            (_, Some("PASSWORD")) => "password".into(),
            (_, Some("NOTES")) => "notes".into(),
            (Some(label), _) if !label.is_empty() => label.into(),
            _ => self.id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlEntry {
    pub href: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// An item with its values, as the app shows and edits it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// Empty for an item not yet created.
    #[serde(default)]
    pub id: String,
    pub title: String,
    pub category: String,
    pub vault: VaultRef,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub urls: Vec<UrlEntry>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub sections: Vec<SectionRef>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

/// The categories the app can create in M1, with their built-in fields.
pub fn template(category: &str) -> Vec<Field> {
    let field = |id: &str, kind: &str, purpose: Option<&str>| Field {
        id: id.into(),
        label: Some(id.into()),
        kind: kind.into(),
        purpose: purpose.map(String::from),
        section: None,
        value: Some(crate::secret::Secret::new(String::new())),
        reference: None,
    };
    let notes = field("notesPlain", "STRING", Some("NOTES"));
    match category {
        "LOGIN" => vec![
            field("username", "STRING", Some("USERNAME")),
            field("password", "CONCEALED", Some("PASSWORD")),
            notes,
        ],
        "PASSWORD" => vec![field("password", "CONCEALED", Some("PASSWORD")), notes],
        "API_CREDENTIAL" => vec![
            field("username", "STRING", None),
            field("credential", "CONCEALED", None),
            notes,
        ],
        _ => vec![notes],
    }
}

/// `API_CREDENTIAL` -> `api-credential`.
pub fn kind(category: &str) -> String {
    category.to_lowercase().replace('_', "-")
}

/// Where a new credential goes. Every field is non-secret metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Destination {
    pub title: String,
    pub vault: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// What a verified write returns. Deliberately excludes values, notes and URLs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub title: String,
    pub vault: String,
    pub kind: String,
    pub field: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordRequest {
    pub item: String,
    pub vault: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub apply: bool,
    pub repair_imported_fields: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordOutcome {
    pub id: String,
    pub title: String,
    pub vault: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_drops_values() {
        let json = r#"{"id":"a","title":"T","category":"LOGIN","vault":{"id":"v","name":"V"},
            "fields":[{"id":"password","type":"CONCEALED","purpose":"PASSWORD","value":"sentinel-secret-123"}]}"#;
        let item: ItemDetail = serde_json::from_str(json).unwrap();
        let back = serde_json::to_string(&item).unwrap();
        assert!(!back.contains("sentinel-secret-123"));
    }
}
