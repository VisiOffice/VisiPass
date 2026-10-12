use serde_json::Value;
use vp_core::Failure;
use vp_core::secret::Secret;

/// Rewrites a login's item template with a new password, preserving every other
/// field. op's JSON edit cannot preserve passkeys, and unnamed imported fields
/// need explicit repair, so both are refused unless repair is requested.
pub fn with_password(
    raw: &str,
    password: &str,
    repair_imported_fields: bool,
) -> Result<Secret, Failure> {
    let refuse = || {
        Failure::new(
            "Cannot safely edit this login template: passkeys or unnamed imported fields require review; nothing was changed",
        )
    };
    let mut value: Value = serde_json::from_str(raw).map_err(|_| refuse())?;
    let has_passkeys = value
        .get("passkeys")
        .and_then(Value::as_array)
        .is_some_and(|p| !p.is_empty());
    let fields = value
        .get_mut("fields")
        .and_then(Value::as_array_mut)
        .ok_or_else(refuse)?;
    if has_passkeys
        || fields
            .iter()
            .any(|f| f.get("type").and_then(Value::as_str) == Some("PASSKEY"))
    {
        return Err(refuse());
    }
    for (index, field) in fields.iter_mut().enumerate() {
        let named = |key: &str| {
            field
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        };
        if !named("id") && !named("label") {
            if !repair_imported_fields {
                return Err(refuse());
            }
            field["id"] = Value::from(format!("imported_field_{}", index + 1));
            field["label"] = Value::from(format!("Imported field {}", index + 1));
            field["type"] = Value::from("CONCEALED");
        }
    }
    for field in fields.iter_mut() {
        if field.get("id").and_then(Value::as_str) == Some("password")
            && field.get("purpose").and_then(Value::as_str) == Some("PASSWORD")
            && field.get("section").is_none()
        {
            field["value"] = Value::from(password);
        }
    }
    Ok(Secret::new(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_builtin_password_only() {
        let raw = r#"{"fields":[{"id":"password","purpose":"PASSWORD","type":"CONCEALED","value":"old"},
            {"id":"pin","type":"CONCEALED","value":"1234","section":{"id":"s"}}]}"#;
        let out = with_password(raw, "new", false).unwrap();
        let v: Value = serde_json::from_str(out.expose()).unwrap();
        assert_eq!(v["fields"][0]["value"], "new");
        assert_eq!(v["fields"][1]["value"], "1234");
    }

    #[test]
    fn refuses_passkeys_and_unnamed_fields() {
        assert!(with_password(r#"{"passkeys":[{}],"fields":[]}"#, "x", true).is_err());
        let unnamed = r#"{"fields":[{"type":"STRING","value":"v"}]}"#;
        assert!(with_password(unnamed, "x", false).is_err());
        assert!(with_password(unnamed, "x", true).is_ok());
    }
}
