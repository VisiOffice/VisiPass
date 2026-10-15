//! Item reads and writes for the desktop app. Every write is followed by a
//! read-back that must match, and is never retried.

use crate::{Call, OpBackend, edit, is_id};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use vp_core::Failure;
use vp_core::model::{Field, Item, VaultRef};
use vp_core::secret::Secret;

const UNVERIFIED: &str = "The save could not be verified. Do not save again; reopen the item to check it (1Password details suppressed)";

fn field_json(field: &Field) -> Value {
    let mut value = json!({
        "id": field.id,
        "type": field.kind,
        "label": field.label.clone().unwrap_or_else(|| field.id.clone()),
        "value": field.value.as_ref().map(|v| v.expose().to_string()).unwrap_or_default(),
    });
    if let Some(purpose) = &field.purpose {
        value["purpose"] = json!(purpose);
    }
    if let Some(section) = &field.section {
        value["section"] = json!({ "id": section.id, "label": section.label });
    }
    value
}

fn urls_json(item: &Item) -> Value {
    Value::Array(
        item.urls
            .iter()
            .enumerate()
            .map(|(i, u)| json!({ "href": u.href, "primary": u.primary || i == 0, "label": u.label }))
            .collect(),
    )
}

/// The fields a human edited must read back exactly as saved.
fn matches(saved: &Item, wanted: &Item) -> bool {
    let tags = |i: &Item| i.tags.iter().cloned().collect::<BTreeSet<_>>();
    let urls = |i: &Item| {
        i.urls
            .iter()
            .map(|u| u.href.clone())
            .collect::<BTreeSet<_>>()
    };
    saved.title == wanted.title
        && saved.category == wanted.category
        && tags(saved) == tags(wanted)
        && urls(saved) == urls(wanted)
        && wanted.fields.iter().all(|w| {
            let value = |f: &Field| {
                f.value
                    .as_ref()
                    .map(|v| v.expose().to_string())
                    .unwrap_or_default()
            };
            // 1Password may drop empty fields, and may re-ID new custom fields,
            // so a field also matches by label and value.
            saved.fields.iter().any(|s| {
                value(s) == value(w) && (s.id == w.id || (w.label.is_some() && s.label == w.label))
            }) || (value(w).is_empty() && !saved.fields.iter().any(|s| s.id == w.id))
        })
}

impl OpBackend {
    pub(crate) async fn vault_list(&self, account: Option<&str>) -> Result<Vec<VaultRef>, Failure> {
        self.json(
            &["vault", "list", "--format", "json"],
            Call {
                account,
                ..Call::default()
            },
        )
        .await
    }

    /// `op vault create`, once, then reads the vault list back.
    pub(crate) async fn new_vault(&self, name: &str) -> Result<VaultRef, Failure> {
        let named = |vaults: &[VaultRef]| {
            vaults
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .cloned()
        };
        if named(&self.vault_list(None).await?).is_some() {
            return Err(Failure::new(format!(
                "A vault named \"{name}\" already exists"
            )));
        }
        let unverified = "The vault may have been created, but could not be verified. Do not create it again; check the vault list first (1Password details suppressed)";
        let created: VaultRef = self
            .json(
                &["vault", "create", name, "--format", "json"],
                Call {
                    failure: Some(unverified),
                    ..Call::default()
                },
            )
            .await?;
        match named(&self.vault_list(None).await?) {
            Some(vault) if vault.id == created.id => Ok(vault),
            _ => Err(Failure::new(unverified)),
        }
    }

    async fn raw_item(&self, id: &str, vault: &str, failure: &str) -> Result<Secret, Failure> {
        Ok(Secret::new(
            self.op(
                &[
                    "item", "get", id, "--vault", vault, "--format", "json", "--reveal",
                ],
                Call {
                    failure: Some(failure),
                    ..Call::default()
                },
            )
            .await?,
        ))
    }

    pub(crate) async fn get_item(&self, id: &str, vault: &str) -> Result<Item, Failure> {
        let failure = "Could not open this item (1Password details suppressed)";
        let raw = self.raw_item(id, vault, failure).await?;
        serde_json::from_str(raw.expose()).map_err(|_| Failure::new(failure))
    }

    /// Many items with their values, in one `op` call, for importing into the
    /// native vault. The output never reaches an error message.
    pub async fn items_with_values(
        &self,
        entries: &[vp_core::model::Listed],
    ) -> Result<Vec<Item>, Failure> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let failure = "Could not read items from 1Password (1Password details suppressed)";
        let input = format!(
            "{}\n",
            serde_json::Value::Array(entries.iter().map(|e| e.raw.clone()).collect())
        );
        let output = Secret::new(
            self.op(
                &["item", "get", "-", "--format", "json", "--reveal"],
                Call {
                    input: Some(&input),
                    failure: Some(failure),
                    ..Call::default()
                },
            )
            .await?,
        );
        crate::json_documents(output.expose())
            .map_err(|_| Failure::new(failure))?
            .into_iter()
            .map(|v| serde_json::from_value(v).map_err(|_| Failure::new(failure)))
            .collect()
    }

    pub(crate) async fn put_item(&self, item: &Item) -> Result<Item, Failure> {
        if item.title.trim().is_empty()
            || item.vault.name.trim().is_empty() && item.vault.id.is_empty()
        {
            return Err(Failure::new("An item needs a title and a vault"));
        }
        let vault = if item.vault.id.is_empty() {
            item.vault.name.clone()
        } else {
            item.vault.id.clone()
        };
        let saved_id = if item.id.is_empty() {
            let template = Secret::new(
                json!({
                    "title": item.title,
                    "category": item.category,
                    "tags": item.tags,
                    "urls": urls_json(item),
                    "sections": item.sections,
                    "fields": item.fields.iter().map(field_json).collect::<Vec<_>>(),
                })
                .to_string(),
            );
            #[derive(serde::Deserialize)]
            struct Created {
                id: String,
            }
            let created: Created = self
                .json(
                    &["item", "create", "-", "--vault", &vault, "--format", "json"],
                    Call {
                        input: Some(template.expose()),
                        failure: Some("Creation may have succeeded, but could not be verified. Do not create it again; search for it first (1Password details suppressed)"),
                        ..Call::default()
                    },
                )
                .await?;
            created.id
        } else {
            let raw = self
                .raw_item(
                    &item.id,
                    &vault,
                    "Could not open this item to edit it; nothing was changed",
                )
                .await?;
            let template = merge(raw.expose(), item)?;
            self.op(
                &[
                    "item", "edit", &item.id, "--vault", &vault, "--format", "json",
                ],
                Call {
                    input: Some(template.expose()),
                    failure: Some(UNVERIFIED),
                    ..Call::default()
                },
            )
            .await?;
            item.id.clone()
        };
        if !is_id(&saved_id) {
            return Err(Failure::new(UNVERIFIED));
        }
        let saved = self
            .get_item(&saved_id, &vault)
            .await
            .map_err(|_| Failure::new(UNVERIFIED))?;
        if !matches(&saved, item) {
            return Err(Failure::new(UNVERIFIED));
        }
        Ok(saved)
    }

    pub(crate) async fn favorite_item(
        &self,
        id: &str,
        vault: &str,
        favorite: bool,
    ) -> Result<(), Failure> {
        #[derive(serde::Deserialize)]
        struct Edited {
            #[serde(default)]
            favorite: bool,
        }
        let flag = if favorite { "true" } else { "false" };
        let edited: Edited = self
            .json(
                &[
                    "item",
                    "edit",
                    id,
                    "--vault",
                    vault,
                    "--favorite",
                    flag,
                    "--format",
                    "json",
                ],
                Call::default(),
            )
            .await?;
        if edited.favorite != favorite {
            return Err(Failure::new(
                "1Password did not confirm the favourite change",
            ));
        }
        Ok(())
    }

    pub(crate) async fn archive_item(&self, id: &str, vault: &str) -> Result<(), Failure> {
        self.op(
            &["item", "delete", id, "--vault", vault, "--archive"],
            Call::default(),
        )
        .await
        .map(|_| ())
    }
}

/// Applies the app's edits to 1Password's own template, keeping everything the
/// app does not model (section metadata, field ordering, unknown keys).
fn merge(raw: &str, item: &Item) -> Result<Secret, Failure> {
    let refuse = || {
        Failure::new(
            "This item has passkeys or unnamed imported fields; edit it in 1Password. Nothing was changed",
        )
    };
    // Reuse the password editor's safety checks: refuse passkeys and unnamed fields.
    edit::with_password(raw, "", false).map_err(|_| refuse())?;
    let mut template: Value = serde_json::from_str(raw).map_err(|_| refuse())?;
    let existing: Vec<Value> = template
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fields: Vec<Value> = item
        .fields
        .iter()
        .map(|field| {
            match existing
                .iter()
                .find(|f| f.get("id").and_then(Value::as_str) == Some(field.id.as_str()))
            {
                Some(original) => {
                    let mut updated = original.clone();
                    updated["value"] = json!(
                        field
                            .value
                            .as_ref()
                            .map(|v| v.expose().to_string())
                            .unwrap_or_default()
                    );
                    if let Some(label) = &field.label {
                        updated["label"] = json!(label);
                    }
                    updated
                }
                None => field_json(field),
            }
        })
        .collect();
    template["fields"] = Value::Array(fields);
    template["title"] = json!(item.title);
    template["tags"] = json!(item.tags);
    template["urls"] = urls_json(item);
    Ok(Secret::new(template.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_unmodelled_keys_and_drops_removed_fields() {
        let raw = r#"{"id":"x","title":"Old","category":"LOGIN","vault":{"id":"v","name":"V"},"extra":{"keep":true},
            "fields":[{"id":"username","type":"STRING","purpose":"USERNAME","value":"a","label":"username"},
                      {"id":"pin","type":"CONCEALED","value":"1234","label":"pin"}]}"#;
        let mut item: Item = serde_json::from_str(raw).unwrap();
        item.title = "New".into();
        item.fields.retain(|f| f.id == "username");
        item.fields[0].value = Some(Secret::new("b".into()));
        let merged: Value = serde_json::from_str(merge(raw, &item).unwrap().expose()).unwrap();
        assert_eq!(merged["title"], "New");
        assert_eq!(merged["extra"]["keep"], true);
        assert_eq!(merged["fields"].as_array().unwrap().len(), 1);
        assert_eq!(merged["fields"][0]["value"], "b");
        assert_eq!(merged["fields"][0]["purpose"], "USERNAME");
    }
}
