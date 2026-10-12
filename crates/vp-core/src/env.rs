//! `.env` templates whose values are secret references.

use crate::Failure;
use crate::refs::SecretRef;
use crate::secret::Secret;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub reference: SecretRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvLine {
    /// Kept verbatim. `var` is set when the line is a plain `NAME=value` assignment.
    Literal {
        raw: String,
        var: Option<(String, String)>,
    },
    Reference {
        name: String,
        reference: SecretRef,
    },
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses `NAME=op://vault/item/field`.
pub fn parse_assignment(input: &str) -> Result<Assignment, Failure> {
    let Some((name, reference)) = input.split_once('=').filter(|(name, _)| !name.is_empty()) else {
        return Err(Failure::new("Expected NAME=op://reference"));
    };
    // Neither the input nor an invalid name is echoed: a mistyped flag may hold a pasted secret.
    if !valid_name(name) {
        return Err(Failure::new(
            "Invalid environment variable name in NAME=op://reference",
        ));
    }
    if !SecretRef::is_reference(reference) {
        // The value may be a pasted secret, so never echo it back.
        return Err(Failure::new(format!(
            "Secret reference must start with op:// or vp://: {name}"
        )));
    }
    let reference =
        SecretRef::parse(reference).map_err(|e| Failure::new(format!("{name}: {e}")))?;
    Ok(Assignment {
        name: name.to_string(),
        reference,
    })
}

fn unquote(value: &str) -> &str {
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

pub fn parse_env(content: &str) -> Vec<EnvLine> {
    content
        .split('\n')
        .map(|line| {
            let original = line.strip_suffix('\r').unwrap_or(line);
            let literal = |var| EnvLine::Literal {
                raw: original.to_string(),
                var,
            };
            let trimmed = original.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return literal(None);
            }
            let assignment = trimmed
                .strip_prefix("export ")
                .map(str::trim)
                .unwrap_or(trimmed);
            let Some((name, value)) = assignment.split_once('=') else {
                return literal(None);
            };
            let name = name.trim();
            let value = unquote(value.trim());
            if !valid_name(name) {
                return literal(None);
            }
            match SecretRef::parse(value) {
                Ok(reference) => EnvLine::Reference {
                    name: name.to_string(),
                    reference,
                },
                Err(_) => literal(Some((name.to_string(), value.to_string()))),
            }
        })
        .collect()
}

pub fn render_env(assignments: &[Assignment]) -> String {
    assignments
        .iter()
        .map(|a| format!("{}={}\n", a.name, a.reference))
        .collect()
}

/// Unique references, in first-seen order.
pub fn references(lines: &[EnvLine]) -> Vec<SecretRef> {
    let mut seen = Vec::new();
    for line in lines {
        if let EnvLine::Reference { reference, .. } = line
            && !seen.contains(reference)
        {
            seen.push(reference.clone());
        }
    }
    seen
}

pub fn quote_env_value(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

/// Renders a plaintext env file. Returns the content and how many lines were resolved.
pub fn resolve_env(
    lines: &[EnvLine],
    values: &HashMap<SecretRef, Secret>,
) -> Result<(Secret, usize), Failure> {
    let mut out = Vec::with_capacity(lines.len());
    let mut count = 0;
    for line in lines {
        match line {
            EnvLine::Literal { raw, .. } => out.push(raw.clone()),
            EnvLine::Reference { name, reference } => {
                let value = values.get(reference).ok_or_else(|| {
                    Failure::new("Secret resolver returned an unexpected number of values")
                })?;
                let value = value.expose();
                out.push(format!(
                    "{name}={}",
                    quote_env_value(value.strip_suffix('\n').unwrap_or(value))
                ));
                count += 1;
            }
        }
    }
    Ok((Secret::new(out.join("\n")), count))
}

/// Every variable a command run from this file should see: literal assignments
/// as written, references resolved.
pub fn environment(
    lines: &[EnvLine],
    values: &HashMap<SecretRef, Secret>,
) -> Result<Vec<(String, Secret)>, Failure> {
    lines
        .iter()
        .filter_map(|line| match line {
            EnvLine::Literal {
                var: Some((name, value)),
                ..
            } => Some(Ok((name.clone(), Secret::new(value.clone())))),
            EnvLine::Literal { .. } => None,
            EnvLine::Reference { name, reference } => Some(
                values
                    .get(reference)
                    .map(|value| (name.clone(), value.clone()))
                    .ok_or_else(|| {
                        Failure::new("Secret resolver returned an unexpected number of values")
                    }),
            ),
        })
        .collect()
}

/// Whether a plaintext assignment looks like a secret worth moving into the
/// vault. Names like `*_KEY`, `*_TOKEN`, `*SECRET*`, `*PASSWORD*`, and any URL
/// carrying a password (`postgres://user:pass@host`).
pub fn looks_secret(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let by_name = [
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PRIVATE",
        "CREDENTIAL",
        "AUTH",
        "DSN",
        "SALT",
        "COOKIE",
    ]
    .iter()
    .any(|word| {
        upper
            .split('_')
            .any(|part| part == *word || part.ends_with(word) && word.len() > 4)
    }) || upper == "DATABASE_URL";
    let by_value = value
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .is_some_and(|authority| {
            authority.contains('@')
                && authority
                    .split('@')
                    .next()
                    .is_some_and(|user| user.contains(':'))
        });
    !value.trim().is_empty() && (by_name || by_value)
}

/// Rewrites the given variables to references, keeping every other line,
/// comment and `export` prefix as it was.
pub fn rewrite(content: &str, replacements: &HashMap<String, SecretRef>) -> String {
    content
        .split('\n')
        .map(|line| {
            let original = line.strip_suffix('\r').unwrap_or(line);
            let trimmed = original.trim_start();
            let (export, rest) = match trimmed.strip_prefix("export ") {
                Some(rest) => ("export ", rest.trim_start()),
                None => ("", trimmed),
            };
            match rest
                .split_once('=')
                .map(|(n, _)| n.trim())
                .and_then(|n| replacements.get(n).map(|r| (n, r)))
            {
                Some((name, reference)) => format!("{export}{name}={reference}"),
                None => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> SecretRef {
        SecretRef::parse(s).unwrap()
    }

    #[test]
    fn parses_assignments() {
        let a = parse_assignment("OPENAI_API_KEY=op://Personal/OpenAI API Key/credential").unwrap();
        assert_eq!(a.name, "OPENAI_API_KEY");
        assert!(parse_assignment("1BAD=op://a/b/c").is_err());
        assert!(parse_assignment("=op://a/b/c").is_err());
    }

    #[test]
    fn assignment_errors_never_echo_values() {
        for input in [
            "KEY=sentinel-secret-123",
            "sentinel-secret-123",
            "sentinel-secret-123=op://a/b/c",
        ] {
            let error = parse_assignment(input).unwrap_err();
            assert!(!error.0.contains("sentinel"), "{error}");
        }
    }

    #[test]
    fn parses_and_resolves_template() {
        let content =
            "# comment\nexport A=op://V/I/f\nB='op://V/J/f'\nPLAIN=hello\nA2=op://V/I/f\n";
        let lines = parse_env(content);
        assert_eq!(references(&lines), vec![r("op://V/I/f"), r("op://V/J/f")]);
        let values = HashMap::from([
            (r("op://V/I/f"), Secret::new("one\n".into())),
            (r("op://V/J/f"), Secret::new("t\"wo".into())),
        ]);
        let (out, count) = resolve_env(&lines, &values).unwrap();
        assert_eq!(count, 3);
        assert_eq!(
            out.expose(),
            "# comment\nA=\"one\"\nB=\"t\\\"wo\"\nPLAIN=hello\nA2=\"one\"\n"
        );
        let env = environment(&lines, &values).unwrap();
        let names: Vec<_> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["A", "B", "PLAIN", "A2"]);
    }

    #[test]
    fn renders_template() {
        let a = parse_assignment("X=op://a/b/c").unwrap();
        assert_eq!(render_env(&[a]), "X=op://a/b/c\n");
    }

    #[test]
    fn spots_secrets_and_leaves_settings() {
        for (name, value) in [
            ("OPENAI_API_KEY", "sk-1"),
            ("STRIPE_SECRET", "x"),
            ("GITHUB_TOKEN", "x"),
            ("DB_PASSWORD", "x"),
            ("DATABASE_URL", "postgres://localhost/db"),
            ("REDIS_URL", "redis://default:hunter2@host:6379"),
            ("SENTRY_DSN", "https://abc@sentry.io/1"),
        ] {
            assert!(looks_secret(name, value), "{name}");
        }
        for (name, value) in [
            ("PORT", "3000"),
            ("NODE_ENV", "development"),
            ("API_URL", "https://api.example.com"),
            ("KEYBOARD_LAYOUT", "us"),
            ("EMPTY_KEY", ""),
        ] {
            assert!(!looks_secret(name, value), "{name}");
        }
    }

    #[test]
    fn rewrites_only_named_lines() {
        let content =
            "# keys\nexport OPENAI_API_KEY=sk-sentinel\nPORT=3000\nSTRIPE_KEY=\"rk-sentinel\"\n";
        let replacements = HashMap::from([
            (
                "OPENAI_API_KEY".to_string(),
                r("op://Dev/app OPENAI_API_KEY/credential"),
            ),
            (
                "STRIPE_KEY".to_string(),
                r("op://Dev/app STRIPE_KEY/credential"),
            ),
        ]);
        let out = rewrite(content, &replacements);
        assert_eq!(
            out,
            "# keys\nexport OPENAI_API_KEY=op://Dev/app OPENAI_API_KEY/credential\nPORT=3000\nSTRIPE_KEY=op://Dev/app STRIPE_KEY/credential\n"
        );
        assert!(!out.contains("sentinel"));
    }
}
