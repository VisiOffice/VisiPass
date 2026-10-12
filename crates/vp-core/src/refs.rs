use crate::Failure;
use serde::{Deserialize, Serialize};

/// A secret reference: `op://vault/item/[section/]field[?attribute=...]` or the
/// same path under `vp://`. Vault and item may be names or IDs.
///
/// In M0 every reference resolves through 1Password, so `vp://` is a spelling of
/// `op://`. The native store (M0.5) keeps answering to both.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef(String);

impl SecretRef {
    pub fn parse(input: &str) -> Result<Self, Failure> {
        let rest = input
            .strip_prefix("op://")
            .or_else(|| input.strip_prefix("vp://"))
            .ok_or_else(|| Failure::new("Secret reference must start with op:// or vp://"))?;
        let path = rest.split('?').next().unwrap_or_default();
        let segments: Vec<&str> = path.split('/').collect();
        if !(3..=4).contains(&segments.len()) || segments.iter().any(|s| s.trim().is_empty()) {
            return Err(Failure::new(
                "Secret reference must look like op://vault/item/field or op://vault/item/section/field",
            ));
        }
        if input.chars().any(char::is_control) {
            return Err(Failure::new(
                "Secret reference contains a control character",
            ));
        }
        Ok(Self(input.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The reference in 1Password's spelling.
    pub fn to_op(&self) -> String {
        match self.0.strip_prefix("vp://") {
            Some(rest) => format!("op://{rest}"),
            None => self.0.clone(),
        }
    }

    pub fn is_reference(input: &str) -> bool {
        input.starts_with("op://") || input.starts_with("vp://")
    }
}

impl TryFrom<String> for SecretRef {
    type Error = Failure;
    fn try_from(value: String) -> Result<Self, Failure> {
        Self::parse(&value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> String {
        value.0
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_and_four_segments() {
        assert!(SecretRef::parse("op://Personal/OpenAI API Key/credential").is_ok());
        assert!(SecretRef::parse("op://Work/Server/admin/password").is_ok());
        assert!(SecretRef::parse("op://Work/GitHub/one-time password?attribute=otp").is_ok());
    }

    #[test]
    fn vp_maps_to_op() {
        let r = SecretRef::parse("vp://Dev/Stripe/credential").unwrap();
        assert_eq!(r.to_op(), "op://Dev/Stripe/credential");
        assert_eq!(r.as_str(), "vp://Dev/Stripe/credential");
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "Personal/x/y",
            "op://a/b",
            "op://a//c",
            "op://a/b/c/d/e",
            "op://a/b/c\n",
        ] {
            assert!(SecretRef::parse(bad).is_err(), "{bad}");
        }
    }
}
