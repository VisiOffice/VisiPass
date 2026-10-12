//! The local protocol between `vp` (and later the app and MCP server) and
//! `visipassd`: one JSON request line, one JSON response line, per connection.

use crate::model::{Destination, PasswordRequest, Scope};
use crate::refs::SecretRef;
use crate::secret::Secret;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// What the requester will do with resolved values. Shown to the human in the
/// approval prompt, and grants are given per usage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Usage {
    /// Inject into a child process's environment (`run`, `env run`).
    Run { command: Vec<String> },
    /// Write plaintext to a file (`env resolve`, `inject -o`).
    Materialize { target: String },
    /// Print to stdout, where the agent reads it (`read`, `inject` to stdout).
    Reveal,
}

impl Usage {
    pub fn operation(&self) -> Operation {
        match self {
            Usage::Run { .. } => Operation::Run,
            Usage::Materialize { .. } => Operation::Materialize,
            Usage::Reveal => Operation::Reveal,
        }
    }
}

/// What a grant allows. `Run` is the least exposing use of a secret, `Reveal` the most.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Run,
    Materialize,
    Reveal,
    Write,
}

impl Operation {
    pub fn describe(self) -> &'static str {
        match self {
            Operation::Run => "inject into a command",
            Operation::Materialize => "write to a plaintext file",
            Operation::Reveal => "print to the agent",
            Operation::Write => "write to the vault",
        }
    }
}

/// What visipassd shows the human. Sent as JSON on stdin to `visipass-prompt`,
/// which answers one word on stdout (see `Answer`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalPrompt {
    /// "Claude Code" or "An unrecognised process".
    pub who: String,
    /// "inject 2 secrets into a command".
    pub action: String,
    /// Labelled details: project, command, file, title.
    pub details: Vec<(String, String)>,
    /// References involved, one per entry.
    pub secrets: Vec<String>,
    /// The agent's stated reason, shown as its own words.
    pub purpose: Option<String>,
    /// The prompt denies itself after this long.
    pub timeout_secs: u64,
}

/// The human's answer, as `visipass-prompt` prints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Deny,
    Once,
    Task,
    Hours,
    Always,
    Timeout,
}

impl Answer {
    pub fn word(self) -> &'static str {
        match self {
            Answer::Deny => "deny",
            Answer::Once => "once",
            Answer::Task => "task",
            Answer::Hours => "hours",
            Answer::Always => "always",
            Answer::Timeout => "timeout",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        [
            Answer::Deny,
            Answer::Once,
            Answer::Task,
            Answer::Hours,
            Answer::Always,
            Answer::Timeout,
        ]
        .into_iter()
        .find(|a| a.word() == word.trim())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Request {
    Status,
    Find {
        queries: Vec<String>,
        #[serde(default)]
        scope: Scope,
    },
    Inventory {
        #[serde(default)]
        scope: Scope,
    },
    Audit {
        #[serde(default)]
        scope: Scope,
    },
    Resolve {
        refs: Vec<SecretRef>,
        usage: Usage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    CreateApiCredential {
        destination: Destination,
        value: Secret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    Password {
        request: PasswordRequest,
        value: Secret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    /// Opens the desktop app (or, with `quick`, the Quick Access palette);
    /// visipassd launches it and hands it a private channel.
    OpenApp {
        #[serde(default)]
        quick: bool,
    },
    // ---- Desktop app channel only. Refused on the public socket. ----
    Vaults {
        #[serde(default)]
        account: Option<String>,
    },
    Items {
        #[serde(default)]
        scope: Scope,
    },
    Item {
        id: String,
        vault: String,
    },
    /// Creates (empty `id`) or updates an item, then reads it back and compares.
    SaveItem {
        item: crate::model::Item,
    },
    Archive {
        id: String,
        vault: String,
    },
    SetFavorite {
        id: String,
        vault: String,
        favorite: bool,
    },
    // ---- end of app-only requests ----
    Grants,
    Revoke {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        all: bool,
    },
    Log {
        #[serde(default = "default_log_limit")]
        limit: usize,
    },
}

fn default_log_limit() -> usize {
    50
}

impl Request {
    /// Requests that return or change values for a human to see. Only the app
    /// channel visipassd itself opened may make them.
    pub fn app_only(&self) -> bool {
        matches!(
            self,
            Request::Vaults { .. }
                | Request::Items { .. }
                | Request::Item { .. }
                | Request::SaveItem { .. }
                | Request::Archive { .. }
                | Request::SetFavorite { .. }
        )
    }

    /// A short name for the access log. Never includes values.
    pub fn name(&self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::Find { .. } => "find",
            Request::Inventory { .. } => "inventory",
            Request::Audit { .. } => "audit",
            Request::Resolve { .. } => "resolve",
            Request::CreateApiCredential { .. } => "create",
            Request::Password { .. } => "password",
            Request::OpenApp { .. } => "open-app",
            Request::Vaults { .. } => "vaults",
            Request::Items { .. } => "items",
            Request::Item { .. } => "item",
            Request::SaveItem { .. } => "save-item",
            Request::Archive { .. } => "archive",
            Request::SetFavorite { .. } => "favorite",
            Request::Grants => "grants",
            Request::Revoke { .. } => "revoke",
            Request::Log { .. } => "log",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Ok {
        ok: monostate::True,
        result: serde_json::Value,
    },
    Err {
        ok: monostate::False,
        error: String,
    },
}

/// Tiny stand-ins for literal `true` / `false` tags, so responses read
/// `{"ok":true,"result":...}` and `{"ok":false,"error":"..."}`.
pub mod monostate {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Debug, Clone, Copy, Default)]
    pub struct True;
    #[derive(Debug, Clone, Copy, Default)]
    pub struct False;

    macro_rules! literal {
        ($ty:ident, $value:expr) => {
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_bool($value)
                }
            }
            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    if bool::deserialize(d)? == $value {
                        Ok($ty)
                    } else {
                        Err(serde::de::Error::custom("unexpected ok flag"))
                    }
                }
            }
        };
    }
    literal!(True, true);
    literal!(False, false);
}

impl Response {
    pub fn ok(result: serde_json::Value) -> Self {
        Response::Ok {
            ok: monostate::True,
            result,
        }
    }

    pub fn err(error: impl Into<String>) -> Self {
        Response::Err {
            ok: monostate::False,
            error: error.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let line = serde_json::to_string(&Envelope {
            version: PROTOCOL_VERSION,
            request: Request::Resolve {
                refs: vec![SecretRef::parse("op://a/b/c").unwrap()],
                usage: Usage::Run {
                    command: vec!["env".into()],
                },
                purpose: None,
            },
        })
        .unwrap();
        assert!(line.contains(r#""type":"resolve""#));
        let back: Envelope = serde_json::from_str(&line).unwrap();
        assert!(matches!(back.request, Request::Resolve { .. }));

        let ok = serde_json::to_string(&Response::ok(serde_json::json!({"a":1}))).unwrap();
        assert_eq!(ok, r#"{"ok":true,"result":{"a":1}}"#);
        assert!(matches!(
            serde_json::from_str::<Response>(&ok).unwrap(),
            Response::Ok { .. }
        ));
        let err = serde_json::to_string(&Response::err("nope")).unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&err).unwrap(),
            Response::Err { .. }
        ));
    }
}
