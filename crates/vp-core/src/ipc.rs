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
    /// Fill a login into a web page (the browser extension).
    Fill,
}

impl Operation {
    pub fn describe(self) -> &'static str {
        match self {
            Operation::Run => "inject into a command",
            Operation::Materialize => "write to a plaintext file",
            Operation::Reveal => "print to the agent",
            Operation::Write => "write to the vault",
            Operation::Fill => "fill into a web page",
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
    /// Set when the human is asked to paste a new secret rather than approve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paste: Option<PasteSpec>,
}

/// Characters that change how text reads without being seen: bidirectional
/// overrides and isolates, marks, and zero-width characters. An agent could use
/// them to make "op://Dev/x" read as something else in a prompt.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}'
        | '\u{061C}' | '\u{FEFF}' | '\u{00AD}')
}

/// Prompt text as the human should see it: no control characters (a terminal
/// escape could redraw the terminal prompt), no invisible characters, newlines
/// only where `lines` allows them, at most `max` characters.
pub fn clean_text(text: &str, lines: bool, max: usize) -> String {
    let clean: String = text
        .chars()
        .filter(|c| !invisible(*c))
        .map(|c| match c {
            '\n' if lines => '\n',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    if clean.chars().count() <= max {
        clean
    } else {
        format!("{}…", clean.chars().take(max).collect::<String>())
    }
}

impl ApprovalPrompt {
    /// The prompt with everything a caller chose cleaned and capped, before any
    /// window, dialog or terminal shows it.
    pub fn cleaned(&self) -> Self {
        let mut prompt = self.clone();
        prompt.who = clean_text(&self.who, false, 120);
        prompt.action = clean_text(&self.action, false, 400);
        prompt.details = self
            .details
            .iter()
            .take(12)
            .map(|(label, value)| (clean_text(label, false, 40), clean_text(value, true, 1200)))
            .collect();
        prompt.secrets = self
            .secrets
            .iter()
            .map(|s| clean_text(s, false, 300))
            .collect();
        prompt.purpose = self.purpose.as_deref().map(|p| clean_text(p, true, 400));
        if let Some(paste) = &mut prompt.paste {
            paste.title = clean_text(&paste.title, false, 200);
            paste.vault = clean_text(&paste.vault, false, 200);
        }
        prompt
    }
}

/// What a paste prompt asks for: a new secret, saved where the agent said.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PasteSpec {
    pub title: String,
    pub vault: String,
    #[serde(default)]
    pub mode: PasteMode,
}

/// What the paste window is for. Every mode returns its answer on the pipe
/// only visipassd holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PasteMode {
    /// A new secret an agent asked for (`vp request`).
    #[default]
    Secret,
    /// The master password, to unlock the native vault, or with `purpose` to
    /// confirm it is the human before something sensitive ("show your Emergency Kit").
    Unlock {
        retry: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    /// A new master password (`vp init`); `confirm` is the second entry.
    NewPassword { confirm: bool },
    /// Shows the new Secret Key once, for the Emergency Kit. Answers Cancel.
    ShowKey { key: Secret },
}

impl PasteSpec {
    /// What the paste window asks for, and its confirm button. Shared by every
    /// way of asking: the VisiPass window, zenity and the terminal.
    pub fn instruction(&self) -> (String, &'static str) {
        match &self.mode {
            PasteMode::Secret => (
                format!(
                    "Paste the secret to save as \"{}\" in the vault \"{}\".",
                    self.title, self.vault
                ),
                "Save",
            ),
            PasteMode::Unlock {
                purpose: Some(purpose),
                ..
            } => (
                format!("Enter your master password to {purpose}."),
                "Continue",
            ),
            PasteMode::Unlock { retry: false, .. } => (
                "Enter your master password to unlock VisiPass.".into(),
                "Unlock",
            ),
            PasteMode::Unlock { retry: true, .. } => (
                "That password was wrong. Enter your master password to unlock VisiPass.".into(),
                "Unlock",
            ),
            PasteMode::NewPassword { confirm: false } => (
                "Choose a master password for your new VisiPass vault: at least 10 characters. Nobody can recover it for you, so pick one you will remember.".into(),
                "Continue",
            ),
            PasteMode::NewPassword { confirm: true } => (
                "Type the same master password again.".into(),
                "Create vault",
            ),
            PasteMode::ShowKey { .. } => (KEY_INSTRUCTIONS.into(), "Done"),
        }
    }
}

pub const KEY_INSTRUCTIONS: &str = "This is your Secret Key. It is saved on this device, and you need it with your master password to open your vault anywhere else or after a reinstall. Write it down, or print your Emergency Kit any time with `vp emergency-kit`, and keep it apart from your password.";

/// A paste prompt's answer, as one JSON line on stdout.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "kebab-case")]
pub enum PasteAnswer {
    Save { value: Secret },
    Cancel,
    Timeout,
}

/// One plaintext value `vp env import` moves into the vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportEntry {
    /// The variable name, e.g. `OPENAI_API_KEY`.
    pub name: String,
    /// The item title to create, e.g. `myapp OPENAI_API_KEY`.
    pub title: String,
    pub value: Secret,
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
    /// Creates an empty vault. Always asks the human, unless an agent token
    /// for a vault of that name allows writes.
    CreateVault {
        name: String,
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
    // ---- The native vault ----
    /// Creates VisiPass's own vault; the master password is typed in the VisiPass window.
    InitVault,
    /// Erases the native vault's keys from memory. Without `full`, an open
    /// quick-unlock window keeps the Account Key.
    LockVault {
        #[serde(default)]
        full: bool,
    },
    /// Opens the printable Emergency Kit in the browser after the master password
    /// is entered in the VisiPass window. Nothing secret comes back to the caller.
    EmergencyKit,
    /// Turns quick unlock on (the master password is asked for in the VisiPass
    /// window) or off. `hours` is the window; none turns it off.
    QuickUnlock {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hours: Option<u64>,
    },
    /// Copies items from 1Password into the native vault, keeping their IDs.
    ImportOp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
    },
    /// Ask the human to paste a secret that does not exist yet. The agent
    /// gets back only the reference.
    RequestSecret {
        destination: Destination,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    /// Move plaintext env values into the vault: one approval for the batch.
    ImportEnv {
        vault: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        entries: Vec<ImportEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    /// Report which references resolve. Values never leave the daemon.
    CheckRefs {
        refs: Vec<SecretRef>,
    },
    /// Create a scoped agent token. Always asks the human.
    CreateToken {
        name: String,
        vaults: Vec<String>,
        operations: Vec<Operation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },
    Tokens,
    RevokeToken {
        id: String,
    },
    // ---- Browser extension (through `vp`'s native-messaging host) ----
    /// Logins whose website matches the page, best first. Metadata only.
    BrowserMatch {
        url: String,
        /// Unlock VisiPass's own vault if it is locked. Page loads leave this off and
        /// get `"locked": true` instead, so browsing never opens an unlock prompt.
        #[serde(default)]
        unlock: bool,
    },
    /// Logins matching a search, for the popup. Metadata only.
    BrowserSearch {
        query: String,
    },
    /// Username, password and one-time code for one login, to fill into the
    /// page at `url`. Refused when the login's website does not match the page
    /// unless `force` (the human overrode the warning).
    BrowserFill {
        url: String,
        id: String,
        vault: String,
        #[serde(default)]
        force: bool,
    },
    /// A strong password for a sign-up form. Nothing is saved.
    BrowserGenerate,
    /// The vaults a login saved from the browser can go to. Names only.
    BrowserVaults,
    /// A login typed or generated on the page at `url`. With `check`, compares
    /// it with the saved login for that username and writes nothing ("new",
    /// "same" or "changed"). Without `id`, creates a login in `vault`. With
    /// `id`, updates that login: one saved from this site's generated password
    /// in this daemon's lifetime without asking, any other only after the human
    /// approves.
    BrowserSave {
        url: String,
        #[serde(default)]
        username: String,
        password: Secret,
        #[serde(default)]
        check: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
    },
    /// Adds a one-time-code secret to a login for the page at `url`, read from
    /// a QR code in `image` (a screenshot of the page, base64 PNG or JPEG) or
    /// from `key` (an otpauth:// link or the setup key). Always asks the human.
    BrowserAddTotp {
        url: String,
        id: String,
        vault: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<Secret>,
    },
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
            Request::RequestSecret { .. } => "request",
            Request::ImportEnv { .. } => "env-import",
            Request::CheckRefs { .. } => "env-check",
            Request::CreateToken { .. } => "token-create",
            Request::Tokens => "tokens",
            Request::RevokeToken { .. } => "token-revoke",
            Request::BrowserMatch { .. } => "browser-match",
            Request::BrowserSearch { .. } => "browser-search",
            Request::BrowserFill { .. } => "browser-fill",
            Request::CreateVault { .. } => "create-vault",
            Request::BrowserGenerate => "browser-generate",
            Request::BrowserVaults => "browser-vaults",
            Request::BrowserSave { check: true, .. } => "browser-check",
            Request::BrowserSave { .. } => "browser-save",
            Request::BrowserAddTotp { .. } => "browser-add-totp",
            Request::Grants => "grants",
            Request::Revoke { .. } => "revoke",
            Request::Log { .. } => "log",
            Request::InitVault => "vault-init",
            Request::LockVault { .. } => "vault-lock",
            Request::QuickUnlock { .. } => "vault-quick-unlock",
            Request::EmergencyKit => "vault-emergency-kit",
            Request::ImportOp { .. } => "vault-import",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub request: Request,
    /// An agent token (`VISIPASS_TOKEN`), for agents with no human at hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Secret>,
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
    fn prompt_text_is_cleaned_before_anyone_sees_it() {
        let prompt = ApprovalPrompt {
            who: "Claude\u{1b}[2J Code\nYour terminal".into(),
            action: format!("read {}", "x".repeat(1000)),
            details: vec![("Item".into(), "a\u{202E}lmth.exe\nsecond line".into())],
            secrets: vec!["op://Dev/\u{200B}stripe/key".into()],
            purpose: Some("why\u{7}".into()),
            ..Default::default()
        }
        .cleaned();
        assert_eq!(prompt.who, "Claude [2J Code Your terminal");
        assert!(prompt.action.chars().count() <= 401 && prompt.action.ends_with('…'));
        assert_eq!(prompt.details[0].1, "almth.exe\nsecond line");
        assert_eq!(prompt.secrets[0], "op://Dev/stripe/key");
        assert_eq!(prompt.purpose.as_deref(), Some("why "));
    }

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
            token: None,
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
