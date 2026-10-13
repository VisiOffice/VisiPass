//! `vp kamal-fetch`: secrets for a Kamal deploy, in the form `kamal secrets fetch`
//! prints, so `.kamal/secrets` can hand them out with `kamal secrets extract`:
//!
//! ```sh
//! SECRETS=$(vp kamal-fetch --from "op://Domus/Production Secrets" RAILS_MASTER_KEY POSTGRES_PASSWORD)
//! RAILS_MASTER_KEY=$(kamal secrets extract RAILS_MASTER_KEY $SECRETS)
//! ```
//!
//! `extract` runs inside Kamal and raises on a missing name, so a failed fetch
//! stops the deploy instead of shipping a blank secret.
//!
//! The output survives three rounds of rewriting inside Kamal, checked against
//! Kamal 2.12 and dotenv 3.2:
//! 1. dotenv expands `$NAME` and `${NAME}` in every value after running its
//!    commands, including a value `extract` returned. Each `$` not followed by `(`
//!    therefore gets a backslash, which dotenv's own escape rule then removes.
//! 2. Kamal splits the `extract` command line like a shell. The JSON is
//!    shell-escaped the way Ruby's `Shellwords.escape` does it, as Kamal's own
//!    `fetch` does when Kamal runs it inline.
//! 3. dotenv also expands `$SECRETS` itself; the JSON carries no `$` at all
//!    (`\u0024`), so nothing inside it can be expanded on the way.
//!
//! Kamal drops a trailing newline or carriage return from every value (`chomp`);
//! nothing here can keep one.

use crate::Failure;
use crate::refs::SecretRef;
use std::fmt::Write as _;
use zeroize::Zeroizing;

/// What to fetch: each `NAME` is that field of the `--from` item, and
/// `NAME=op://vault/item/field` names any other reference.
pub fn plan(from: Option<&str>, specs: &[String]) -> Result<Vec<(String, SecretRef)>, Failure> {
    if specs.is_empty() {
        return Err(Failure::new(
            "Name the secrets to fetch, e.g. vp kamal-fetch --from \"op://Vault/Item\" RAILS_MASTER_KEY",
        ));
    }
    let from = from.map(|f| f.trim_end_matches('/'));
    if let Some(from) = from
        && !(from.starts_with("op://") || from.starts_with("vp://"))
    {
        return Err(Failure::new("--from must be an item, e.g. op://Vault/Item"));
    }
    let mut planned: Vec<(String, SecretRef)> = Vec::new();
    for spec in specs {
        let (name, reference) = match spec.split_once('=') {
            Some((name, reference)) => (name, reference.to_string()),
            None => match from {
                Some(from) => (spec.as_str(), format!("{from}/{spec}")),
                None => {
                    return Err(Failure::new(format!(
                        "{spec} needs --from \"op://Vault/Item\", or write it as {spec}=op://Vault/Item/field"
                    )));
                }
            },
        };
        if !valid_name(name) {
            return Err(Failure::new(format!(
                "\"{name}\" is not a name Kamal can use: letters, digits and _ only"
            )));
        }
        if planned.iter().any(|(n, _)| n == name) {
            return Err(Failure::new(format!("{name} is named twice")));
        }
        planned.push((name.to_string(), SecretRef::parse(&reference)?));
    }
    Ok(planned)
}

/// A name Kamal can extract and a shell can export.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `{"NAME":"value",…}`, escaped for the trip through Kamal (see the module docs).
pub fn fetch_output(secrets: &[(&str, &str)]) -> Zeroizing<String> {
    let mut json = Zeroizing::new(String::from("{"));
    for (i, (name, value)) in secrets.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        push_json_string(&mut json, name);
        json.push(':');
        push_json_string(&mut json, &escape_dollars(value));
    }
    json.push('}');
    shell_escape(&json)
}

/// `$` → `\$`, except before `(`: dotenv leaves `$(` alone and would leave the backslash too.
fn escape_dollars(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 8));
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() != Some(&'(') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// JSON with only ASCII in it, and `$` written as `\u0024`.
fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '$' => out.push_str("\\u0024"),
            c if (c as u32) < 0x20 || !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Ruby's `Shellwords.escape` for ASCII text: a backslash before everything but
/// `[A-Za-z0-9_\-.,:+/@]`.
fn shell_escape(text: &str) -> Zeroizing<String> {
    if text.is_empty() {
        return Zeroizing::new("''".into());
    }
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 2));
    for c in text.chars() {
        if !(c.is_ascii_alphanumeric() || "_-.,:+/@".contains(c)) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each expected string is what Ruby printed for
    /// `JSON.generate({k => v.gsub(/\$(?!\()/, "\\$")}, ascii_only: true).gsub("$", "\\u0024").shellescape`.
    #[test]
    fn matches_what_ruby_produces() {
        let cases = [
            ("A", "plain", r#"\{\"A\":\"plain\"\}"#),
            (
                "B",
                r"a$b`c $(id) ${HOME} $$ \$X",
                r#"\{\"B\":\"a\\\\\\u0024b\`c\ \\u0024\(id\)\ \\\\\\u0024\{HOME\}\ \\\\\\u0024\\\\\\u0024\ \\\\\\\\\\u0024X\"\}"#,
            ),
            (
                "C",
                "é ✓ 😀",
                r#"\{\"C\":\"\\u00e9\ \\u2713\ \\ud83d\\ude00\"\}"#,
            ),
            (
                "D",
                "multi\nline\t\"q\" \\ /",
                r#"\{\"D\":\"multi\\nline\\t\\\"q\\\"\ \\\\\ /\"\}"#,
            ),
            ("E", "", r#"\{\"E\":\"\"\}"#),
        ];
        for (name, value, ruby) in cases {
            assert_eq!(fetch_output(&[(name, value)]).as_str(), ruby, "{name}");
        }
    }

    #[test]
    fn plans_names_from_the_item_and_explicit_references() {
        let planned = plan(
            Some("op://Domus/Production Secrets/"),
            &[
                "RAILS_MASTER_KEY".into(),
                "REG=op://Varda/Production/GITHUB_TOKEN".into(),
            ],
        )
        .unwrap();
        assert_eq!(planned[0].0, "RAILS_MASTER_KEY");
        assert_eq!(
            planned[0].1,
            SecretRef::parse("op://Domus/Production Secrets/RAILS_MASTER_KEY").unwrap()
        );
        assert_eq!(planned[1].0, "REG");
        assert!(
            plan(None, &["A".into()]).is_err(),
            "a bare name needs --from"
        );
        assert!(plan(Some("op://V/I"), &[]).is_err());
        assert!(plan(Some("op://V/I"), &["A".into(), "A".into()]).is_err());
        assert!(plan(Some("op://V/I"), &["a-b".into()]).is_err());
        assert!(plan(Some("Vault/Item"), &["A".into()]).is_err());
    }

    #[test]
    fn several_secrets_and_names() {
        assert_eq!(
            fetch_output(&[("A", "1"), ("B", "2")]).as_str(),
            r#"\{\"A\":\"1\",\"B\":\"2\"\}"#
        );
        assert!(valid_name("RAILS_MASTER_KEY") && valid_name("_x1"));
        assert!(!valid_name("1X") && !valid_name("A-B") && !valid_name(""));
    }
}
