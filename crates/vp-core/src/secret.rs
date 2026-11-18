use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A secret value. Zeroed on drop, redacted in `Debug`, and deliberately not
/// `Display`, so it cannot reach a format string by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }

    /// A pasted value without the spaces, tabs and line breaks copying leaves
    /// at either end, and whether there were any. Never for a password.
    pub fn trimmed(self) -> (Self, bool) {
        let trimmed = self.0.trim();
        if trimmed.len() == self.0.len() {
            (self, false)
        } else {
            (Self::new(trimmed.to_string()), true)
        }
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// Secrets cross the local IPC socket between visipassd and vp as plain JSON strings.
impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("sentinel-secret-123".into());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn trims_only_the_ends() {
        let (value, trimmed) = Secret::new(" \tab c;\n".into()).trimmed();
        assert_eq!((value.expose(), trimmed), ("ab c;", true));
        let (value, trimmed) = Secret::new("ab c".into()).trimmed();
        assert_eq!((value.expose(), trimmed), ("ab c", false));
    }
}
