//! visipassd: the one long-lived process that talks to the vault.
//!
//! It exists so approvals can be scoped to an agent and a project instead of a
//! shell. Discovery (find, inventory, audit) needs no VisiPass approval, though
//! the backend may still prompt. Anything that hands out a value or writes to
//! the vault needs a grant or a fresh human approval, and every request is
//! written to the access log.

pub mod approval;
pub mod grants;
pub mod kit;
pub mod log;
pub mod paths;
pub mod presence;
pub mod procinfo;
pub mod qr;
pub mod routed;
pub mod session;
pub mod tokens;

use approval::{Approver, Prompt};
use grants::{Decision, Grants, Need};
use log::{AccessLog, Entry};
use procinfo::Requester;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use vp_core::backend::Backend;
use vp_core::ipc::{Envelope, Operation, PROTOCOL_VERSION, PasteMode, Request, Response, Usage};
use vp_core::{Failure, audit, find, time};

const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// A login as the browser extension lists it: never a value.
fn browser_entry(s: &vp_core::model::ItemSummary, exact: bool) -> Value {
    json!({
        "id": s.id,
        "vault": s.vault.id,
        "vaultName": s.vault.name,
        "title": s.title,
        "username": s.additional_information,
        "host": s.urls.first().map(|u| find::saved_host(&u.href)),
        "category": s.category,
        "exact": exact,
    })
}

/// What matching and the prompt need from a full item.
fn summary_of(item: &vp_core::model::Item) -> vp_core::model::ItemSummary {
    vp_core::model::ItemSummary {
        id: item.id.clone(),
        title: item.title.clone(),
        category: item.category.clone(),
        vault: item.vault.clone(),
        tags: item.tags.clone(),
        urls: item
            .urls
            .iter()
            .map(|u| vp_core::model::Url {
                href: u.href.clone(),
            })
            .collect(),
        favorite: item.favorite,
        updated_at: None,
        additional_information: None,
    }
}

/// A Proton Pass export's JSON: the file itself, or `data.json` inside the
/// .zip Proton Pass saves.
fn read_export(path: &str) -> Result<Vec<u8>, Failure> {
    use std::io::Read;
    const MAX: u64 = 256 << 20;
    let file =
        std::fs::File::open(path).map_err(|_| Failure::new(format!("Could not open {path}")))?;
    let mut bytes = Vec::new();
    file.take(MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::new(format!("Could not read {path}")))?;
    if bytes.len() as u64 > MAX {
        return Err(Failure::new(format!(
            "{path} is too large to be a Proton Pass export"
        )));
    }
    if !bytes.starts_with(b"PK") {
        return Ok(bytes);
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| Failure::new(format!("{path} is not a readable .zip")))?;
    if zip.file_names().any(|n| n.ends_with(".pgp")) {
        return Err(Failure::new(
            "This Proton Pass export is encrypted. Export again and choose ZIP (or CSV)",
        ));
    }
    let name = zip
        .file_names()
        .find(|n| n.rsplit('/').next() == Some("data.json"))
        .map(String::from)
        .ok_or_else(|| {
            Failure::new("The .zip has no data.json. Export from Proton Pass and choose ZIP")
        })?;
    let entry = zip
        .by_name(&name)
        .map_err(|_| Failure::new(format!("Could not read {name} in the .zip")))?;
    let mut json = Vec::new();
    entry
        .take(MAX + 1)
        .read_to_end(&mut json)
        .map_err(|_| Failure::new(format!("Could not read {name} in the .zip")))?;
    if json.len() as u64 > MAX {
        return Err(Failure::new("The export is too large"));
    }
    Ok(json)
}

/// The built-in field with this purpose (`USERNAME`, `PASSWORD`).
fn field_value(item: &vp_core::model::Item, purpose: &str) -> Option<String> {
    item.fields
        .iter()
        .find(|f| f.purpose.as_deref() == Some(purpose))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_string())
}

/// Sets the built-in field with this purpose, adding it if the item has none.
fn set_field(fields: &mut Vec<vp_core::model::Field>, purpose: &str, value: &str) {
    let value = Some(vp_core::secret::Secret::new(value.to_string()));
    match fields
        .iter_mut()
        .find(|f| f.purpose.as_deref() == Some(purpose))
    {
        Some(field) => field.value = value,
        None => {
            if let Some(mut field) = vp_core::model::template("LOGIN")
                .into_iter()
                .find(|f| f.purpose.as_deref() == Some(purpose))
            {
                field.value = value;
                fields.push(field);
            }
        }
    }
}

/// Website, login and vault, for a prompt about one saved login.
fn login_details(page: &str, item: &vp_core::model::Item) -> Vec<(String, String)> {
    let username = field_value(item, "USERNAME").filter(|u| !u.is_empty());
    vec![
        ("Website".into(), page.to_string()),
        (
            "Login".into(),
            match username {
                Some(u) => format!("{}  ({u})", item.title),
                None => item.title.clone(),
            },
        ),
        ("Vault".into(), item.vault.name.clone()),
    ]
}

/// Writes a file readable only by this user, atomically.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    let temporary = dir.join(format!(
        ".{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub struct Daemon<B, A> {
    backend: B,
    approver: A,
    grants: Mutex<Grants>,
    tokens: Mutex<tokens::Tokens>,
    log: Mutex<AccessLog>,
    /// One prompt at a time; a request queued behind a prompt re-checks grants first.
    approvals: tokio::sync::Mutex<()>,
    socket: PathBuf,
    state: PathBuf,
    /// PIDs of the desktop app and the Quick Access palette this daemon launched.
    app: tokio::sync::Mutex<Option<u32>>,
    quick: tokio::sync::Mutex<Option<u32>>,
    /// Whether a requester is the extension's native-messaging host.
    browser_host: fn(u32) -> bool,
    /// Who a connecting process is.
    identify: fn(u32) -> Requester,
    /// Logins this daemon saved from a generated password, with the page they
    /// were made on: the extension may finish them (username, the password the
    /// form took) without asking, but only from the same site.
    drafts: Mutex<std::collections::HashMap<String, String>>,
}

/// Where a request arrived. Only `App`, the private socket pair visipassd
/// handed to the desktop app it launched, may make app-only requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Public,
    App,
}

const APP_LABEL: &str = "VisiPass app";

/// What to log about a request, and what it needs from the human.
struct Assessment {
    need: Option<Need>,
    refs: Vec<String>,
    detail: Option<String>,
    prompt: Option<Prompt>,
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

fn shell_words(command: &[String]) -> String {
    command
        .iter()
        .map(|w| {
            if !w.is_empty()
                && w.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
            {
                w.clone()
            } else {
                format!("'{}'", w.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn project_line(requester: &Requester) -> (String, String) {
    let p = &requester.project;
    let value = match &p.remote {
        Some(remote) => format!("{}  ({remote})", p.root),
        None => p.root.clone(),
    };
    ("Project".into(), value)
}

fn who(requester: &Requester) -> String {
    requester
        .agent
        .clone()
        .or_else(|| requester.origin.clone())
        .unwrap_or_else(|| "An unrecognised process".into())
}

/// What a grant to save new items covers: creating in that vault, nothing else.
fn creates_in(vault: &str) -> String {
    format!("create in {vault}")
}

fn assess(request: &Request, requester: &Requester) -> Assessment {
    let none = |detail: Option<String>| Assessment {
        need: None,
        refs: vec![],
        detail,
        prompt: None,
    };
    match request {
        Request::Find { queries, .. } => none(Some(format!("{} queries", queries.len()))),
        Request::Resolve {
            refs,
            usage,
            purpose,
        } => {
            let refs: Vec<String> = refs.iter().map(|r| r.to_string()).collect();
            let count = plural(refs.len(), "secret");
            let (action, mut details, detail) = match usage {
                Usage::Run { command } => {
                    let shown = shell_words(command);
                    (
                        format!("inject {count} into a command"),
                        vec![("Command".to_string(), shown.clone())],
                        Some(shown),
                    )
                }
                Usage::Materialize { target } => (
                    format!("write {count} to a plaintext file"),
                    vec![("File".to_string(), target.clone())],
                    Some(target.clone()),
                ),
                Usage::Reveal => (
                    if requester.agent.is_some() {
                        format!("print {count} where the agent can read them")
                    } else {
                        format!("print {count} to its output")
                    },
                    vec![],
                    None,
                ),
            };
            details.insert(0, project_line(requester));
            Assessment {
                need: Some(Need {
                    operation: usage.operation(),
                    refs: refs.iter().cloned().collect(),
                    vaults: BTreeSet::new(),
                }),
                prompt: Some(Prompt {
                    who: who(requester),
                    action,
                    details,
                    secrets: refs.clone(),
                    purpose: purpose.clone(),
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                }),
                refs,
                detail,
            }
        }
        Request::CreateApiCredential {
            destination,
            purpose,
            ..
        } => Assessment {
            need: Some(Need {
                operation: Operation::Write,
                refs: BTreeSet::from([creates_in(&destination.vault)]),
                vaults: BTreeSet::from([destination.vault.clone()]),
            }),
            refs: vec![],
            detail: Some(format!(
                "create \"{}\" in {}",
                destination.title, destination.vault
            )),
            prompt: Some(Prompt {
                who: who(requester),
                action: format!(
                    "save a new API credential in the vault \"{}\"",
                    destination.vault
                ),
                details: vec![
                    project_line(requester),
                    ("Title".into(), destination.title.clone()),
                ],
                secrets: vec![],
                purpose: purpose.clone(),
                timeout_secs: approval::TIMEOUT.as_secs(),
                paste: None,
            }),
        },
        Request::Password {
            request, purpose, ..
        } => {
            let verb = if request.apply {
                "change the password of"
            } else {
                "check the password of"
            };
            Assessment {
                // This login only, and changing it is not checking it: a grant to
                // save new items, or to check one login, never covers changing another.
                need: Some(Need {
                    operation: Operation::Write,
                    refs: BTreeSet::from([format!(
                        "{} {}/{}",
                        if request.apply { "change" } else { "check" },
                        request.vault,
                        request.item
                    )]),
                    vaults: BTreeSet::from([request.vault.clone()]),
                }),
                refs: vec![],
                detail: Some(format!("{verb} \"{}\" in {}", request.item, request.vault)),
                prompt: Some(Prompt {
                    who: who(requester),
                    action: format!("{verb} a login in the vault \"{}\"", request.vault),
                    details: vec![
                        project_line(requester),
                        ("Item".into(), request.item.clone()),
                    ],
                    secrets: vec![],
                    purpose: purpose.clone(),
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                }),
            }
        }
        Request::Item { id, .. }
        | Request::Archive { id, .. }
        | Request::SetFavorite { id, .. } => none(Some(id.clone())),
        Request::Duplicates { .. } => none(None),
        Request::MergeItems { merges } => none(Some(format!(
            "keep {}, archive {}",
            plural(merges.len(), "item"),
            merges.iter().map(|m| m.archive.len()).sum::<usize>()
        ))),
        Request::BrowserFill { url, id, .. } => Assessment {
            need: None,
            refs: vec![format!("{}#{id}", find::page_host(url))],
            detail: Some(format!("fill on {}", find::page_host(url))),
            prompt: None,
        },
        Request::CreateVault { name, purpose } => Assessment {
            need: Some(Need {
                operation: Operation::Write,
                refs: BTreeSet::from([format!("create vault {name}")]),
                vaults: BTreeSet::from([name.clone()]),
            }),
            refs: vec![],
            detail: Some(format!("create vault {name}")),
            prompt: Some(Prompt {
                who: who(requester),
                action: format!("create a new vault named \"{name}\""),
                details: vec![project_line(requester), ("Vault".into(), name.clone())],
                secrets: vec![],
                purpose: purpose.clone(),
                timeout_secs: approval::TIMEOUT.as_secs(),
                paste: None,
            }),
        },
        Request::BrowserSave { url, id, check, .. } => {
            let page = find::page_host(url);
            none(Some(match (check, id) {
                (true, _) => format!("check a login on {page}"),
                (false, None) => format!("save a new login from {page}"),
                (false, Some(id)) => format!("update {id} from {page}"),
            }))
        }
        Request::BrowserAddTotp { url, id, .. } => Assessment {
            need: None,
            refs: vec![format!("{}#{id}", find::page_host(url))],
            detail: Some(format!("add a two-factor code on {}", find::page_host(url))),
            prompt: None,
        },
        Request::ImportEnv {
            vault,
            entries,
            purpose,
            ..
        } => {
            let names: Vec<String> = entries
                .iter()
                .map(|e| format!("{}  →  {}", e.name, e.title))
                .collect();
            Assessment {
                need: Some(Need {
                    operation: Operation::Write,
                    refs: BTreeSet::from([creates_in(vault)]),
                    vaults: BTreeSet::from([vault.clone()]),
                }),
                refs: vec![],
                detail: Some(format!(
                    "import {} into {vault}",
                    plural(entries.len(), "secret")
                )),
                prompt: Some(Prompt {
                    who: who(requester),
                    action: format!(
                        "move {} from a plaintext env file into the vault \"{vault}\"",
                        plural(entries.len(), "secret")
                    ),
                    details: vec![
                        project_line(requester),
                        ("Will create".into(), names.join("\n")),
                    ],
                    secrets: vec![],
                    purpose: purpose.clone(),
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                }),
            }
        }
        Request::CheckRefs { refs } => Assessment {
            need: None,
            refs: refs.iter().map(|r| r.to_string()).collect(),
            detail: None,
            prompt: None,
        },
        Request::RequestSecret { destination, .. } => none(Some(format!(
            "request \"{}\" in {}",
            destination.title, destination.vault
        ))),
        Request::SaveItem { item } => none(Some(if item.id.is_empty() {
            format!("create \"{}\"", item.title)
        } else {
            format!("update {}", item.id)
        })),
        Request::ImportProton { path } => {
            none(Some(format!("import the Proton Pass export {path}")))
        }
        _ => none(None),
    }
}

impl<B: Backend, A: Approver> Daemon<B, A> {
    pub fn new(backend: B, approver: A, state_dir: &Path, socket: PathBuf) -> Self {
        Self {
            backend,
            approver,
            grants: Mutex::new(Grants::load(state_dir.join("grants.json"))),
            tokens: Mutex::new(tokens::Tokens::load(state_dir.join("tokens.json"))),
            log: Mutex::new(AccessLog::open(state_dir.join("access.log"))),
            approvals: tokio::sync::Mutex::new(()),
            socket,
            state: state_dir.to_path_buf(),
            app: tokio::sync::Mutex::new(None),
            quick: tokio::sync::Mutex::new(None),
            browser_host: procinfo::started_by_browser,
            identify: procinfo::identify,
            drafts: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Replaces the check that browser requests come from a browser's
    /// native-messaging host; for tests, whose host runs under the test.
    pub fn with_browser_host(mut self, check: fn(u32) -> bool) -> Self {
        self.browser_host = check;
        self
    }

    /// Replaces how a connecting process is identified; for tests, which must
    /// not depend on whether an agent happens to be running them.
    pub fn with_identify(mut self, identify: fn(u32) -> Requester) -> Self {
        self.identify = identify;
        self
    }

    fn grants(&self) -> std::sync::MutexGuard<'_, Grants> {
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Copies a Proton Pass export into the native vault, after asking. Each
    /// Proton vault goes into the VisiPass vault of the same name, or a new one.
    /// A login already saved here (same site, username and password) is
    /// skipped, and so is anything imported before (IDs come from Proton's).
    async fn import_proton(&self, path: &str, requester: &Requester) -> Result<Value, Failure> {
        let export = vp_core::proton::parse(&read_export(path)?)?;
        let existing = self.backend.vaults(None).await?;
        let listed = self.backend.list(&vp_core::model::Scope::default()).await?;
        let mut plan = Vec::new();
        let mut duplicates = 0;
        for proton in export.vaults {
            let target = existing
                .iter()
                .find(|v| v.id == proton.id || v.name.eq_ignore_ascii_case(&proton.name))
                .cloned();
            let new = target.is_none();
            let vault = target.unwrap_or(vp_core::model::VaultRef {
                id: proton.id.clone(),
                name: proton.name.clone(),
            });
            let mut items = Vec::new();
            for mut item in proton.items {
                if self.already_saved(&item, &listed).await {
                    duplicates += 1;
                    continue;
                }
                item.vault = vault.clone();
                items.push(item);
            }
            plan.push((vault, new, items));
        }
        let total: usize = plan.iter().map(|(_, _, items)| items.len()).sum();
        if total == 0 {
            return if duplicates == 0 {
                Err(Failure::new("The export has no items to import"))
            } else {
                Ok(json!({
                    "imported": [],
                    "duplicates": duplicates,
                    "next": "Everything in this export is already in VisiPass. Delete the export file: it holds every password in plain text",
                }))
            };
        }
        let into: Vec<String> = plan
            .iter()
            .filter(|(_, _, items)| !items.is_empty())
            .map(|(vault, new, items)| {
                format!(
                    "{}: {}{}",
                    vault.name,
                    plural(items.len(), "item"),
                    if *new { " (new vault)" } else { "" }
                )
            })
            .collect();
        let left = &export.left;
        let mut details = vec![
            ("File".to_string(), path.to_string()),
            ("Into".to_string(), into.join("\n")),
        ];
        if duplicates > 0 {
            details.push((
                "Skipped".into(),
                format!(
                    "{} already in VisiPass (same site, username and password)",
                    plural(duplicates, "login")
                ),
            ));
        }
        let mut not = Vec::new();
        if left.trashed > 0 {
            not.push(format!(
                "{} in Proton's trash",
                plural(left.trashed, "item")
            ));
        }
        if left.aliases > 0 {
            not.push(format!(
                "{} (they stay in Proton)",
                plural(left.aliases, "email alias")
            ));
        }
        if left.unknown > 0 {
            not.push(format!(
                "{} of a kind VisiPass does not know",
                plural(left.unknown, "item")
            ));
        }
        if left.passkeys > 0 {
            not.push(format!(
                "passkeys on {} (the logins come over, the passkeys do not)",
                plural(left.passkeys, "login")
            ));
        }
        if left.incomplete > 0 {
            not.push(format!(
                "{} (a CSV holds only their names; export as ZIP to bring them)",
                plural(left.incomplete, "card, identity or SSH key item")
            ));
        }
        if !not.is_empty() {
            details.push(("Not imported".into(), not.join("\n")));
        }
        self.ask_each_time(&Prompt {
            who: who(requester),
            action: format!("import {} from Proton Pass", plural(total, "item")),
            details,
            secrets: vec![],
            purpose: None,
            timeout_secs: approval::TIMEOUT.as_secs(),
            paste: None,
        })
        .await?;
        let mut report = Vec::new();
        for (vault, _, items) in plan {
            if items.is_empty() {
                continue;
            }
            let count = items.len();
            let (created, skipped) = self.backend.native_import_items(&vault, items).await?;
            report.push(json!({ "vault": vault.name, "items": count, "created": created, "skipped": skipped }));
        }
        Ok(json!({
            "imported": report,
            "duplicates": duplicates,
            "notImported": {
                "trashed": left.trashed,
                "aliases": left.aliases,
                "unknown": left.unknown,
                "passkeys": left.passkeys,
                "incomplete": left.incomplete,
            },
            "next": "Delete the export file: it holds every password in plain text",
        }))
    }

    /// Logins saved more than once, exact copies first. Each group's items are
    /// fetched here to compare passwords; only "A"/"B" labels leave.
    async fn duplicates(&self, scope: &vp_core::model::Scope) -> Result<Value, Failure> {
        use vp_core::dedupe;
        let summaries: Vec<_> = self
            .backend
            .list(scope)
            .await?
            .into_iter()
            .map(|l| l.summary)
            .collect();
        let mut groups = Vec::new();
        for (site, username, members) in dedupe::candidates(&summaries) {
            let mut items = Vec::new();
            for i in members {
                let s = &summaries[i];
                items.push(self.backend.item(&s.id, &s.vault.id).await?);
            }
            groups.push(dedupe::group(site, username, &items));
        }
        groups.sort_by(|a, b| {
            b.same_password
                .cmp(&a.same_password)
                .then(a.site.cmp(&b.site))
        });
        let same = groups.iter().filter(|g| g.same_password).count();
        Ok(json!({
            "groups": groups,
            "samePassword": same,
            "differentPasswords": groups.len() - same,
        }))
    }

    /// Keeps one item of each merge, with what only the others had copied onto
    /// it (saved and read back), then archives the others. Stops at the first
    /// failure; what was done before it stays done.
    async fn merge_items(&self, merges: Vec<vp_core::ipc::Merge>) -> Result<Value, Failure> {
        let mut added = vp_core::dedupe::Added::default();
        let (mut kept, mut archived) = (0, 0);
        for merge in merges {
            if merge.archive.iter().any(|a| a.id == merge.keep.id) {
                return Err(Failure::new("An item cannot be kept and archived at once"));
            }
            let keep = self.backend.item(&merge.keep.id, &merge.keep.vault).await?;
            let mut others = Vec::new();
            for key in &merge.archive {
                others.push(self.backend.item(&key.id, &key.vault).await?);
            }
            let (merged, more) = vp_core::dedupe::merge(keep, &others);
            if more != vp_core::dedupe::Added::default() {
                self.backend.save_item(&merged).await.map_err(|e| {
                    Failure::new(format!(
                        "{} (merged {kept} before this; nothing archived for \"{}\")",
                        e.0, merged.title
                    ))
                })?;
            }
            added.passwords += more.passwords;
            added.urls += more.urls;
            added.codes += more.codes;
            added.notes += more.notes;
            added.fields += more.fields;
            kept += 1;
            for key in &merge.archive {
                self.backend.archive(&key.id, &key.vault).await?;
                archived += 1;
            }
        }
        Ok(json!({ "kept": kept, "archived": archived, "added": added }))
    }

    /// The item was imported before, or a login with the same site, username
    /// and password is already saved.
    async fn already_saved(
        &self,
        item: &vp_core::model::Item,
        listed: &[vp_core::model::Listed],
    ) -> bool {
        // Imported from this export before.
        if listed.iter().any(|l| l.summary.id == item.id) {
            return true;
        }
        if item.category != "LOGIN" {
            return false;
        }
        let (Some(url), Some(password)) = (item.urls.first(), field_value(item, "PASSWORD")) else {
            return false;
        };
        let username = field_value(item, "USERNAME").unwrap_or_default();
        for found in listed.iter().filter(|l| {
            l.summary.category == "LOGIN"
                && find::page_match(&url.href, &l.summary).is_some()
                && l.summary
                    .additional_information
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case(username.trim())
        }) {
            if let Ok(saved) = self
                .backend
                .item(&found.summary.id, &found.summary.vault.id)
                .await
                && field_value(&saved, "PASSWORD").as_deref() == Some(password.as_str())
            {
                return true;
            }
        }
        false
    }

    /// Asks the human, every time, and never records a grant: for changes to a
    /// saved login that would be lost if a page could make them unasked.
    async fn ask_each_time(&self, prompt: &Prompt) -> Result<(), Failure> {
        let decision = {
            let _turn = self.approvals.lock().await;
            self.approver.ask(prompt).await?
        };
        if decision == Decision::Deny {
            return Err(Failure::new(
                "The human denied this request. Do not retry it; ask them how to proceed",
            ));
        }
        Ok(())
    }

    /// Whether the login saved for this site and username already has this
    /// password. Only the answer leaves the daemon.
    async fn compare_login(
        &self,
        url: &str,
        username: &str,
        password: &vp_core::secret::Secret,
    ) -> Result<Value, Failure> {
        let listed = self.backend.list(&vp_core::model::Scope::default()).await?;
        let mut candidates: Vec<(u32, vp_core::model::ItemSummary)> = listed
            .into_iter()
            .filter(|l| l.summary.category == "LOGIN")
            .filter_map(|l| find::page_match(url, &l.summary).map(|score| (score, l.summary)))
            .filter(|(_, s)| {
                s.additional_information
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case(username)
            })
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.0));
        let Some((_, login)) = candidates.into_iter().next() else {
            return Ok(json!({ "status": "new" }));
        };
        let item = self.backend.item(&login.id, &login.vault.id).await?;
        let same = field_value(&item, "PASSWORD").as_deref() == Some(password.expose());
        Ok(json!({
            "status": if same { "same" } else { "changed" },
            "id": item.id,
            "vault": item.vault.id,
            "vaultName": item.vault.name,
            "title": item.title,
        }))
    }

    async fn authorize(
        &self,
        requester: &Requester,
        need: &Need,
        prompt: &Prompt,
    ) -> Result<String, Failure> {
        // A token is checked, never prompted for: there is no human to ask.
        if let Some(token) = &requester.token {
            return if token.covers(need) {
                Ok(format!("token:{}", token.id))
            } else {
                Err(Failure::new(format!(
                    "The agent token \"{}\" does not allow this. It covers {:?} in the vaults {:?}. Ask the human for a token with that scope",
                    token.name, token.operations, token.vaults
                )))
            };
        }
        if let Some(id) = self.grants().find(requester, need) {
            return Ok(id);
        }
        let _turn = self.approvals.lock().await;
        if let Some(id) = self.grants().find(requester, need) {
            return Ok(id);
        }
        let decision = self.approver.ask(prompt).await?;
        if decision == Decision::Deny {
            return Err(Failure::new(
                "The human denied this request. Do not retry it; ask them how to proceed",
            ));
        }
        let id = self
            .grants()
            .record(requester, need, decision)
            .map_err(|_| Failure::new("Approved, but the grant could not be saved"))?;
        Ok(id.unwrap_or_else(|| "once".into()))
    }

    async fn execute(
        &self,
        request: Request,
        requester: &Requester,
        assessment: &Assessment,
        grant: &mut Option<String>,
    ) -> Result<Value, Failure> {
        // Creating a vault checks the name before asking, below.
        if let (Some(need), Some(prompt)) = (&assessment.need, &assessment.prompt)
            && !matches!(request, Request::CreateVault { .. })
        {
            *grant = Some(self.authorize(requester, need, prompt).await?);
        }
        match request {
            Request::Status => Ok(json!({
                "visipassd": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
                "backend": self.backend.name(),
                "approvals": self.approver.method(),
                "socket": self.socket,
                "grants": self.grants().list().len(),
                "vault": self.backend.native_status().map(|status| {
                    let mut vault = json!({
                        "exists": status.exists,
                        "unlocked": status.unlocked,
                    });
                    if let Some(window) = status.quick_unlock {
                        vault["quickUnlock"] = json!({
                            "hours": window.as_secs_f64() / 3600.0,
                            "minutesLeft": status.quick_unlock_remaining.map(|r| r.as_secs() / 60),
                        });
                    }
                    vault
                }),
            })),
            Request::InitVault => {
                match self.backend.native_status() {
                    None => return Err(Failure::new("This visipassd has no native vault")),
                    Some(status) if status.exists => {
                        return Err(Failure::new("You already have a VisiPass vault"));
                    }
                    Some(_) => {}
                }
                let window = |mode| Prompt {
                    who: "VisiPass".into(),
                    action: "create your vault".into(),
                    details: vec![],
                    secrets: vec![],
                    purpose: None,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: Some(vp_core::ipc::PasteSpec {
                        mode,
                        ..Default::default()
                    }),
                };
                let cancelled =
                    || Failure::new("Creating the vault was cancelled; nothing was created");
                // The master password and the Secret Key go between the window and
                // visipassd only, never to the caller.
                let _turn = self.approvals.lock().await;
                let first = self
                    .approver
                    .paste(&window(PasteMode::NewPassword { confirm: false }))
                    .await?
                    .ok_or_else(cancelled)?;
                if first.expose().chars().count() < 10 {
                    return Err(Failure::new(
                        "Choose a master password of at least 10 characters; nothing was created. Run vp init again",
                    ));
                }
                let second = self
                    .approver
                    .paste(&window(PasteMode::NewPassword { confirm: true }))
                    .await?
                    .ok_or_else(cancelled)?;
                if first.expose() != second.expose() {
                    return Err(Failure::new(
                        "The two passwords did not match; nothing was created. Run vp init again",
                    ));
                }
                let key = self.backend.native_init(first).await?;
                let _ = self
                    .approver
                    .paste(&window(PasteMode::ShowKey { key }))
                    .await;
                Ok(json!({
                    "created": true,
                    "secretKey": "saved on this device, next to the vault, and shown once in the VisiPass window",
                    "next": "Run `vp import op` to copy your 1Password items in. Until then VisiPass serves an empty vault",
                }))
            }
            Request::LockVault { full } => {
                self.backend.native_lock(full);
                Ok(json!({ "locked": true, "full": full }))
            }
            Request::EmergencyKit => {
                if !self.backend.native_status().is_some_and(|s| s.exists) {
                    return Err(Failure::new(
                        "There is no VisiPass vault yet. Run `vp init` to create one",
                    ));
                }
                let _turn = self.approvals.lock().await;
                let prompt = Prompt {
                    who: "VisiPass".into(),
                    action: "show your Emergency Kit".into(),
                    details: vec![],
                    secrets: vec![],
                    purpose: None,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: Some(vp_core::ipc::PasteSpec {
                        mode: PasteMode::Unlock {
                            retry: false,
                            purpose: Some("show your Emergency Kit".into()),
                        },
                        ..Default::default()
                    }),
                };
                let password = self
                    .approver
                    .paste(&prompt)
                    .await?
                    .ok_or_else(|| Failure::new("Showing the Emergency Kit was cancelled"))?;
                let details = self.backend.native_emergency_kit(password).await?;
                let date = vp_core::time::now_rfc3339();
                let page = kit::page(&details, date.get(..10).unwrap_or(&date));
                self.approver.show_page(&page).await?;
                Ok(json!({
                    "opened": true,
                    "where": "your browser, from a file in memory that is deleted in 10 minutes",
                    "next": "Print it or write the Secret Key down, and keep it apart from your master password",
                }))
            }
            Request::QuickUnlock { hours } => {
                // Turning it on lowers what unlocks the vault, so it is the human's
                // own act: never an agent's, and the password window says what it is for.
                if hours.is_some() && requester.agent.is_some() {
                    return Err(Failure::new(
                        "Only the human can turn on quick unlock: ask them to run `vp quick-unlock on` in their own terminal",
                    ));
                }
                let window = hours.map(|h| std::time::Duration::from_secs(h.saturating_mul(3600)));
                let _turn = self.approvals.lock().await;
                self.backend.native_quick_unlock(window).await?;
                Ok(match hours {
                    Some(hours) => json!({
                        "quickUnlock": true,
                        "hours": hours,
                        "note": "After a lock, unlocking within the window asks for your fingerprint or login password. Sleep, `vp lock --full` and the window's end need the master password again",
                    }),
                    None => json!({ "quickUnlock": false }),
                })
            }
            Request::ImportOp { vault } => self.backend.native_import(vault).await,
            Request::ImportProton { path } => {
                let result = self.import_proton(&path, requester).await;
                if result.is_ok() {
                    *grant = Some("once".into());
                }
                result
            }
            Request::Find { queries, scope } => {
                if queries.is_empty() {
                    return Err(Failure::new("Give at least one query"));
                }
                let listed = self.backend.list(&scope).await?;
                let searches = find::plan(&queries, &listed);
                let wanted: Vec<_> = find::wanted(&searches, listed.len())
                    .into_iter()
                    .map(|i| listed[i].clone())
                    .collect();
                let details = self.backend.details(&wanted, &scope).await?;
                Ok(to_json(&find::assemble(&searches, &listed, &details)))
            }
            Request::Inventory { scope } => {
                let listed = self.backend.list(&scope).await?;
                let details = self.backend.details(&listed, &scope).await?;
                Ok(json!({ "items": audit::inventory(&details) }))
            }
            Request::Audit { scope } => {
                let listed = self.backend.list(&scope).await?;
                let details = self.backend.details(&listed, &scope).await?;
                Ok(to_json(&audit::audit(
                    &audit::inventory(&details),
                    &time::now_rfc3339(),
                )))
            }
            Request::Resolve { refs, .. } => {
                if refs.is_empty() {
                    return Err(Failure::new("Give at least one secret reference"));
                }
                let values = self.backend.resolve(&refs).await?;
                Ok(json!({ "values": values }))
            }
            Request::CreateApiCredential {
                destination, value, ..
            } => Ok(to_json(
                &self
                    .backend
                    .create_api_credential(&destination, value)
                    .await?,
            )),
            Request::Password { request, value, .. } => {
                Ok(to_json(&self.backend.password(&request, value).await?))
            }
            Request::Grants => Ok(json!({ "grants": self.grants().list() })),
            Request::Revoke { id, all } => {
                if id.is_none() && !all {
                    return Err(Failure::new("Give a grant ID, or --all"));
                }
                let removed = self
                    .grants()
                    .revoke(id.as_deref())
                    .map_err(|_| Failure::new("Could not save the grants file"))?;
                if removed == 0 && id.is_some() {
                    return Err(Failure::new(
                        "No grant has that ID; list them with vp grant list",
                    ));
                }
                Ok(json!({ "revoked": removed }))
            }
            Request::Log { limit } => Ok(self
                .log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tail(limit)),
            Request::Vaults { account } => Ok(json!({
                "vaults": self.backend.vaults(account.as_deref()).await?
            })),
            Request::Items { scope } => {
                let listed = self.backend.list(&scope).await?;
                let items: Vec<_> = listed.into_iter().map(|l| l.summary).collect();
                Ok(json!({ "items": items }))
            }
            Request::Item { id, vault } => Ok(to_json(&self.backend.item(&id, &vault).await?)),
            Request::SaveItem { item } => Ok(to_json(&self.backend.save_item(&item).await?)),
            Request::Archive { id, vault } => {
                self.backend.archive(&id, &vault).await?;
                Ok(json!({ "archived": id }))
            }
            Request::SetFavorite {
                id,
                vault,
                favorite,
            } => {
                self.backend.set_favorite(&id, &vault, favorite).await?;
                Ok(json!({ "id": id, "favorite": favorite }))
            }
            Request::Duplicates { scope } => self.duplicates(&scope).await,
            Request::MergeItems { merges } => self.merge_items(merges).await,
            Request::RequestSecret {
                destination,
                purpose,
            } => {
                if destination.title.trim().is_empty() || destination.vault.trim().is_empty() {
                    return Err(Failure::new("A title and an explicit vault are required"));
                }
                let prompt = Prompt {
                    who: who(requester),
                    action: format!("add a new secret to the vault \"{}\"", destination.vault),
                    details: vec![
                        project_line(requester),
                        ("Title".into(), destination.title.clone()),
                    ],
                    secrets: vec![],
                    purpose,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: Some(vp_core::ipc::PasteSpec {
                        title: destination.title.clone(),
                        vault: destination.vault.clone(),
                        mode: Default::default(),
                    }),
                };
                // The paste window is the approval; one prompt at a time.
                let pasted = {
                    let _turn = self.approvals.lock().await;
                    self.approver.paste(&prompt).await?
                };
                let value = pasted.ok_or_else(|| {
                    Failure::new("The human cancelled. Do not ask again; ask them how to proceed")
                })?;
                Ok(to_json(
                    &self
                        .backend
                        .create_api_credential(&destination, value)
                        .await?,
                ))
            }
            Request::ImportEnv {
                vault,
                account,
                entries,
                ..
            } => {
                if entries.is_empty() {
                    return Err(Failure::new("Nothing to import"));
                }
                let mut imported = Vec::new();
                let mut failed = Vec::new();
                // One at a time, each verified; a failure never stops the rest
                // and is never retried.
                for entry in entries {
                    let destination = vp_core::model::Destination {
                        title: entry.title.clone(),
                        vault: vault.clone(),
                        account: account.clone(),
                        url: None,
                        notes: Some(format!("Imported by vp env import ({})", entry.name)),
                    };
                    match self.backend.create_api_credential(&destination, entry.value).await {
                        Ok(receipt) => imported.push(json!({ "name": entry.name, "title": entry.title, "ref": receipt.reference })),
                        Err(e) => failed.push(json!({ "name": entry.name, "title": entry.title, "error": e.0 })),
                    }
                }
                Ok(json!({ "imported": imported, "failed": failed }))
            }
            Request::CheckRefs { refs } => {
                if refs.is_empty() {
                    return Ok(json!({ "ok": [], "unresolved": [] }));
                }
                // Values are resolved here and dropped; only names leave the daemon.
                if self.backend.resolve(&refs).await.is_ok() {
                    return Ok(json!({ "ok": refs, "unresolved": [] }));
                }
                let mut ok = Vec::new();
                let mut unresolved = Vec::new();
                for reference in refs {
                    match self.backend.resolve(std::slice::from_ref(&reference)).await {
                        Ok(_) => ok.push(reference),
                        Err(_) => unresolved.push(reference),
                    }
                }
                Ok(json!({ "ok": ok, "unresolved": unresolved }))
            }
            Request::CreateToken {
                name,
                vaults,
                operations,
                days,
                purpose,
            } => {
                if requester.token.is_some() {
                    return Err(Failure::new(
                        "An agent token cannot create tokens. Ask the human",
                    ));
                }
                let name = name.trim().to_string();
                if name.is_empty() || vaults.is_empty() {
                    return Err(Failure::new("A token needs a name and at least one vault"));
                }
                let operations: BTreeSet<Operation> = if operations.is_empty() {
                    BTreeSet::from([Operation::Run])
                } else {
                    operations.into_iter().collect()
                };
                let vaults: BTreeSet<String> = vaults.into_iter().collect();
                let ops: Vec<&str> = operations.iter().map(|o| o.describe()).collect();
                let prompt = Prompt {
                    who: who(requester),
                    action: format!(
                        "create an agent token \"{name}\" that works without asking you"
                    ),
                    details: vec![
                        project_line(requester),
                        ("Allows".into(), ops.join(", ")),
                        (
                            "Vaults".into(),
                            vaults.iter().cloned().collect::<Vec<_>>().join(", "),
                        ),
                        (
                            "Expires".into(),
                            days.map(|d| format!("in {d} days"))
                                .unwrap_or_else(|| "never".into()),
                        ),
                        ("Shown to".into(), format!("{}, once", who(requester))),
                    ],
                    secrets: vec![],
                    purpose,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                };
                let decision = {
                    let _turn = self.approvals.lock().await;
                    self.approver.ask(&prompt).await?
                };
                if decision == Decision::Deny {
                    return Err(Failure::new(
                        "The human denied this request. Do not retry it; ask them how to proceed",
                    ));
                }
                let (record, secret) = self
                    .tokens
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .create(&name, vaults, operations, days)
                    .map_err(|_| Failure::new("Could not save the token"))?;
                let mut view = record.view();
                view["token"] = json!(secret);
                view["note"] = json!(
                    "Shown once. Set it as VISIPASS_TOKEN where the agent runs; vp strips it from commands it runs."
                );
                Ok(view)
            }
            Request::Tokens => Ok(
                json!({ "tokens": self.tokens.lock().unwrap_or_else(|e| e.into_inner()).list() }),
            ),
            Request::RevokeToken { id } => {
                let removed = self
                    .tokens
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .revoke(&id)
                    .map_err(|_| Failure::new("Could not save the tokens file"))?;
                if removed {
                    Ok(json!({ "revoked": id }))
                } else {
                    Err(Failure::new(
                        "No token has that ID; list them with vp agent list",
                    ))
                }
            }
            Request::BrowserMatch { url, unlock } => {
                if !unlock
                    && self
                        .backend
                        .native_status()
                        .is_some_and(|s| s.exists && !s.unlocked)
                {
                    return Ok(json!({
                        "host": find::page_host(&url),
                        "logins": [],
                        "locked": true,
                    }));
                }
                let listed = self.backend.list(&vp_core::model::Scope::default()).await?;
                let mut scored: Vec<(u32, vp_core::model::ItemSummary)> = listed
                    .into_iter()
                    .filter_map(|l| {
                        find::page_match(&url, &l.summary).map(|score| (score, l.summary))
                    })
                    .collect();
                scored.sort_by(|a, b| {
                    b.0.cmp(&a.0)
                        .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
                });
                let logins: Vec<Value> = scored
                    .into_iter()
                    .take(20)
                    .map(|(score, s)| browser_entry(&s, score == 3))
                    .collect();
                Ok(json!({ "host": find::page_host(&url), "logins": logins }))
            }
            Request::BrowserSearch { query } => {
                let listed = self.backend.list(&vp_core::model::Scope::default()).await?;
                let mut scored: Vec<(u32, vp_core::model::ItemSummary)> = listed
                    .into_iter()
                    .filter(|l| matches!(l.summary.category.as_str(), "LOGIN" | "PASSWORD"))
                    .filter_map(|l| find::rank(&query, &l.summary).map(|score| (score, l.summary)))
                    .collect();
                scored.sort_by_key(|s| std::cmp::Reverse(s.0));
                let logins: Vec<Value> = scored
                    .into_iter()
                    .take(20)
                    .map(|(_, s)| browser_entry(&s, false))
                    .collect();
                Ok(json!({ "logins": logins }))
            }
            Request::BrowserFill {
                url,
                id,
                vault,
                force,
            } => {
                let page = find::page_host(&url);
                if page.is_empty() || !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(Failure::new(
                        "VisiPass only fills web pages (http and https)",
                    ));
                }
                let item = self.backend.item(&id, &vault).await?;
                let summary = summary_of(&item);
                let matches_page = find::page_match(&url, &summary).is_some();
                let saved_for: Vec<String> = item
                    .urls
                    .iter()
                    .map(|u| find::saved_host(&u.href))
                    .collect();
                // Phishing guard: a login only fills on its own site unless the human overrides.
                if !matches_page && !force {
                    return Err(Failure::new(format!(
                        "This login is saved for {}, not {page}. VisiPass will not fill it here unless you choose to",
                        if saved_for.is_empty() {
                            "no website".to_string()
                        } else {
                            saved_for.join(", ")
                        }
                    )));
                }
                let field = |purpose: &str, fallback: &str| {
                    item.fields
                        .iter()
                        .find(|f| f.purpose.as_deref() == Some(purpose) || f.id == fallback)
                        .and_then(|f| f.value.as_ref())
                        .map(|v| v.expose().to_string())
                        .filter(|v| !v.is_empty())
                };
                let username = field("USERNAME", "username");
                let mut details = vec![
                    ("Website".to_string(), page.clone()),
                    (
                        "Login".to_string(),
                        format!(
                            "{}{}",
                            item.title,
                            username
                                .as_ref()
                                .map(|u| format!("  ({u})"))
                                .unwrap_or_default()
                        ),
                    ),
                    ("Vault".to_string(), item.vault.name.clone()),
                ];
                if !matches_page {
                    details.push((
                        "Warning".to_string(),
                        format!("This login is saved for {}, not this site. Only continue if you are sure.", saved_for.join(", ")),
                    ));
                }
                let need = Need {
                    operation: Operation::Fill,
                    refs: BTreeSet::from([format!("{page}#{}", item.id)]),
                    vaults: BTreeSet::new(),
                };
                let prompt = Prompt {
                    who: who(requester),
                    action: format!("fill your \"{}\" login on {page}", item.title),
                    details,
                    secrets: vec![],
                    purpose: None,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                };
                if matches_page {
                    *grant = Some(self.authorize(requester, &need, &prompt).await?);
                } else {
                    // An override is asked every time and never becomes a standing grant.
                    let decision = {
                        let _turn = self.approvals.lock().await;
                        self.approver.ask(&prompt).await?
                    };
                    if decision == Decision::Deny {
                        return Err(Failure::new(
                            "The human denied this request. Do not retry it; ask them how to proceed",
                        ));
                    }
                    *grant = Some("once".into());
                }
                let totp = item
                    .fields
                    .iter()
                    .filter(|f| f.kind == "OTP")
                    .find_map(|f| vp_core::totp::Totp::parse(f.value.as_ref()?.expose()).ok())
                    .map(|t| t.now().0);
                Ok(json!({
                    "username": username,
                    "password": field("PASSWORD", "password"),
                    "totp": totp,
                    "title": item.title,
                }))
            }
            Request::CreateVault { name, .. } => {
                let name = name.trim();
                if name.is_empty()
                    || name.chars().count() > 100
                    || name.chars().any(char::is_control)
                {
                    return Err(Failure::new(
                        "A vault name needs 1 to 100 characters and no control characters",
                    ));
                }
                if self
                    .backend
                    .vaults(None)
                    .await?
                    .iter()
                    .any(|v| v.name.eq_ignore_ascii_case(name))
                {
                    return Err(Failure::new(format!(
                        "A vault named \"{name}\" already exists; use it with --vault \"{name}\""
                    )));
                }
                if let (Some(need), Some(prompt)) = (&assessment.need, &assessment.prompt) {
                    *grant = Some(self.authorize(requester, need, prompt).await?);
                }
                let vault = self.backend.create_vault(name).await?;
                Ok(json!({ "created": true, "vault": { "id": vault.id, "name": vault.name } }))
            }
            Request::BrowserGenerate => {
                let password = vp_core::generate::generate(&vp_core::generate::Recipe::Random {
                    length: 20,
                    digits: true,
                    symbols: true,
                    avoid_ambiguous: true,
                })?;
                Ok(json!({ "password": password.expose() }))
            }
            Request::BrowserVaults => {
                let vaults = self.backend.vaults(None).await?;
                Ok(json!({
                    "vaults": vaults
                        .iter()
                        .map(|v| json!({ "id": v.id, "name": v.name }))
                        .collect::<Vec<_>>(),
                }))
            }
            Request::BrowserSave {
                url,
                username,
                password,
                check,
                id,
                vault,
            } => {
                let page = find::page_host(&url);
                let Some(website) = find::page_website(&url) else {
                    return Err(Failure::new(
                        "VisiPass only saves logins from web pages (http and https)",
                    ));
                };
                if password.is_blank() {
                    return Err(Failure::new("There is no password to save"));
                }
                let username = username.trim().to_string();
                if check {
                    return self.compare_login(&url, &username, &password).await;
                }
                let saved = match id {
                    None => {
                        let wanted = vault
                            .ok_or_else(|| Failure::new("Choose a vault to save the login in"))?;
                        let vault = self
                            .backend
                            .vaults(None)
                            .await?
                            .into_iter()
                            .find(|v| v.id == wanted || v.name == wanted)
                            .ok_or_else(|| {
                                Failure::new(format!("There is no vault \"{wanted}\""))
                            })?;
                        let mut fields = vp_core::model::template("LOGIN");
                        set_field(&mut fields, "USERNAME", &username);
                        set_field(&mut fields, "PASSWORD", password.expose());
                        let item = vp_core::model::Item {
                            id: String::new(),
                            title: page.clone(),
                            category: "LOGIN".into(),
                            vault,
                            tags: vec![],
                            urls: vec![vp_core::model::UrlEntry {
                                href: website,
                                label: None,
                                primary: true,
                            }],
                            favorite: false,
                            created_at: None,
                            updated_at: None,
                            sections: vec![],
                            fields,
                        };
                        let saved = self.backend.save_item(&item).await?;
                        if let Ok(mut drafts) = self.drafts.lock() {
                            drafts.insert(saved.id.clone(), url.clone());
                        }
                        saved
                    }
                    Some(id) => {
                        let vault =
                            vault.ok_or_else(|| Failure::new("Missing the login's vault"))?;
                        let mut item = self.backend.item(&id, &vault).await?;
                        let drafted = self
                            .drafts
                            .lock()
                            .ok()
                            .and_then(|d| d.get(&id).cloned())
                            .is_some_and(|made_on| find::same_site(&made_on, &url));
                        if !drafted {
                            if find::page_match(&url, &summary_of(&item)).is_none() {
                                return Err(Failure::new(format!(
                                    "\"{}\" is not saved for {page}, so VisiPass will not change it from here",
                                    item.title
                                )));
                            }
                            let old_username = field_value(&item, "USERNAME").unwrap_or_default();
                            let mut details = login_details(&page, &item);
                            if !username.is_empty() && username != old_username {
                                details.push(("New username".into(), username.clone()));
                            }
                            let prompt = Prompt {
                                who: who(requester),
                                action: format!(
                                    "change the password of your \"{}\" login to the one you just used on {page}",
                                    item.title
                                ),
                                details,
                                secrets: vec![],
                                purpose: None,
                                timeout_secs: approval::TIMEOUT.as_secs(),
                                paste: None,
                            };
                            self.ask_each_time(&prompt).await?;
                            *grant = Some("once".into());
                        }
                        if !username.is_empty() {
                            set_field(&mut item.fields, "USERNAME", &username);
                        }
                        set_field(&mut item.fields, "PASSWORD", password.expose());
                        self.backend.save_item(&item).await?
                    }
                };
                Ok(json!({
                    "saved": true,
                    "id": saved.id,
                    "vault": saved.vault.id,
                    "vaultName": saved.vault.name,
                    "title": saved.title,
                }))
            }
            Request::BrowserAddTotp {
                url,
                id,
                vault,
                image,
                key,
            } => {
                let page = find::page_host(&url);
                if page.is_empty() {
                    return Err(Failure::new("Open the site's two-factor setup page first"));
                }
                let (secret, from) = match (key, image) {
                    (Some(key), _) if !key.is_blank() => (key, "the setup key you pasted"),
                    (_, Some(image)) => (qr::otpauth_in(&image)?, "the QR code on the page"),
                    _ => {
                        return Err(Failure::new(
                            "Paste the setup key, or scan the QR code on the page",
                        ));
                    }
                };
                let totp = vp_core::totp::Totp::parse(secret.expose())?;
                let mut item = self.backend.item(&id, &vault).await?;
                if find::page_match(&url, &summary_of(&item)).is_none() {
                    return Err(Failure::new(format!(
                        "\"{}\" is not saved for {page}. Add the code to the login for this site",
                        item.title
                    )));
                }
                let mut details = login_details(&page, &item);
                details.push(("From".into(), from.into()));
                if item.fields.iter().any(|f| f.kind == "OTP") {
                    details.push((
                        "Warning".into(),
                        "This replaces the two-factor code already saved on this login.".into(),
                    ));
                }
                let prompt = Prompt {
                    who: who(requester),
                    action: format!(
                        "add a two-factor code to your \"{}\" login on {page}",
                        item.title
                    ),
                    details,
                    secrets: vec![],
                    purpose: None,
                    timeout_secs: approval::TIMEOUT.as_secs(),
                    paste: None,
                };
                self.ask_each_time(&prompt).await?;
                *grant = Some("once".into());
                item.fields.retain(|f| f.kind != "OTP");
                item.fields.push(vp_core::model::Field {
                    id: format!("TOTP_{}", vp_native::new_id()),
                    label: Some("one-time password".into()),
                    kind: "OTP".into(),
                    purpose: None,
                    section: None,
                    value: Some(secret),
                    reference: None,
                });
                let saved = self.backend.save_item(&item).await?;
                // The site asks for a code to finish turning two-factor on.
                Ok(json!({ "saved": true, "title": saved.title, "code": totp.now().0 }))
            }
            Request::OpenApp { .. } => Err(Failure::new("visipassd could not open the app")),
        }
    }

    pub async fn handle(
        &self,
        request: Request,
        requester: &Requester,
        channel: Channel,
    ) -> Response {
        let name = request.name();
        let assessment = assess(&request, requester);
        // Everything is logged except reading VisiPass's own state, a page load
        // asking which logins it has (titles only, never an unlock), and the
        // app's own browsing, which would bury everything else.
        let quiet = matches!(
            request,
            Request::Status
                | Request::Grants
                | Request::Log { .. }
                | Request::BrowserMatch { unlock: false, .. }
                | Request::BrowserGenerate
                | Request::BrowserVaults
        ) || (channel == Channel::App
            && matches!(request, Request::Vaults { .. } | Request::Items { .. }));
        let writes = matches!(
            request,
            Request::CreateApiCredential { .. }
                | Request::Password { .. }
                | Request::ImportEnv { .. }
                | Request::ImportOp { .. }
                | Request::ImportProton { .. }
                | Request::SaveItem { .. }
                | Request::Archive { .. }
                | Request::SetFavorite { .. }
                | Request::MergeItems { .. }
                | Request::RequestSecret { .. }
                | Request::BrowserSave { check: false, .. }
                | Request::CreateVault { .. }
                | Request::BrowserAddTotp { .. }
        );
        let mut grant = None;
        // The extension's popup is a human surface like the app: it may open,
        // edit, add and archive items, but only through the browser-started host.
        let popup = matches!(
            request,
            Request::Item { .. }
                | Request::SaveItem { .. }
                | Request::Archive { .. }
                | Request::SetFavorite { .. }
        );
        let result = if channel == Channel::Public
            && request.app_only()
            && !(popup && (self.browser_host)(requester.pid))
        {
            Err(Failure::new(
                "Only the VisiPass app can do this. Use vp find, vp run or vp read instead",
            ))
        } else if channel == Channel::Public
            && matches!(
                request,
                Request::BrowserMatch { .. }
                    | Request::BrowserSearch { .. }
                    | Request::BrowserFill { .. }
                    | Request::BrowserGenerate
                    | Request::BrowserVaults
                    | Request::BrowserSave { .. }
                    | Request::BrowserAddTotp { .. }
            )
            && !(self.browser_host)(requester.pid)
        {
            // A fill hands back the password itself, so only the extension's
            // host, started by the browser, may ask for one; an agent sending
            // the same request over the socket is refused.
            Err(Failure::new(
                "Only the VisiPass browser extension can ask for this. Use vp run or vp read instead",
            ))
        } else {
            self.execute(request, requester, &assessment, &mut grant)
                .await
        };
        if !quiet {
            let entry = Entry {
                at: time::now_rfc3339(),
                agent: requester.agent_label().to_string(),
                pid: requester.pid,
                project: requester.project.root.clone(),
                request: name.to_string(),
                operation: assessment.need.as_ref().map(|n| n.operation),
                refs: assessment.refs,
                detail: assessment.detail,
                grant,
                outcome: match &result {
                    Ok(_) => "ok".into(),
                    Err(e) => format!("failed: {e}"),
                },
            };
            if self
                .log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .append(&entry)
                .is_err()
            {
                // A vault change has happened by now: saying it did not would
                // invite a retry and a duplicate.
                return Response::err(if writes && result.is_ok() {
                    "The change was made, but the access log could not be written. Do not retry; check the vault"
                } else {
                    "The access log could not be written, so the request was not completed"
                });
            }
        }
        match result {
            Ok(value) => Response::ok(value),
            Err(e) => Response::err(e.0),
        }
    }

    async fn connection(self: Arc<Self>, stream: UnixStream) {
        let Ok(credentials) = stream.peer_cred() else {
            return;
        };
        // Same-user only; the socket's directory is 0700 as well.
        if credentials.uid() != unsafe { libc::getuid() } {
            return;
        }
        let pid = credentials
            .pid()
            .and_then(|p| u32::try_from(p).ok())
            .unwrap_or(0);
        let (read, mut write) = stream.into_split();
        let mut line = String::new();
        let response = match BufReader::new(read.take(MAX_REQUEST_BYTES))
            .read_line(&mut line)
            .await
        {
            Err(_) | Ok(0) => return,
            Ok(_) => match serde_json::from_str::<Envelope>(&line) {
                Ok(envelope) if envelope.version != PROTOCOL_VERSION => Response::err(
                    "vp and visipassd are different versions; restart the daemon with `vp daemon --restart`",
                ),
                Ok(Envelope {
                    request: Request::OpenApp { quick },
                    ..
                }) => match Arc::clone(&self).open_app(quick).await {
                    Ok(value) => Response::ok(value),
                    Err(e) => Response::err(e.0),
                },
                Ok(envelope) => {
                    let identify = self.identify;
                    let mut requester = tokio::task::spawn_blocking(move || identify(pid))
                        .await
                        .unwrap_or_else(|_| procinfo::identify(0));
                    match envelope.token.map(|t| {
                        self.tokens
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .verify(t.expose())
                    }) {
                        Some(None) => Response::err(
                            "The agent token is not valid, was revoked, or has expired",
                        ),
                        Some(Some(record)) => {
                            requester.agent = Some(format!("token {}", record.name));
                            requester.token = Some(record);
                            self.handle(envelope.request, &requester, Channel::Public)
                                .await
                        }
                        None => {
                            self.handle(envelope.request, &requester, Channel::Public)
                                .await
                        }
                    }
                }
                Err(_) => Response::err("visipassd could not read the request"),
            },
        };
        line.clear();
        if let Ok(mut text) = serde_json::to_string(&response) {
            text.push('\n');
            let _ = write.write_all(text.as_bytes()).await;
        }
    }

    /// Launches the desktop app with one end of a private socket pair as fd 3.
    /// An agent may ask for this; it opens a window the agent cannot read.
    // Boxed with an explicit Send bound: the app channel can call this, and
    // this spawns an app channel, so the compiler needs the cycle cut here.
    fn open_app(
        self: Arc<Self>,
        quick: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, Failure>> + Send>> {
        Box::pin(self.open_app_inner(quick))
    }

    async fn open_app_inner(self: Arc<Self>, quick: bool) -> Result<Value, Failure> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let mut running = if quick {
            self.quick.lock().await
        } else {
            self.app.lock().await
        };
        if let Some(pid) = *running
            && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
        {
            return Ok(json!({ "running": true }));
        }
        // Never from PATH: the app gets the private socket that serves app-only requests.
        let program = approval::trusted_program("visipass-app")
            .ok_or_else(|| Failure::new("visipass-app is not installed next to visipassd"))?;
        let failed = || Failure::new("Could not start the VisiPass app");
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().map_err(|_| failed())?;
        let fd = theirs.as_raw_fd();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.state.join("visipass-app.log"))
            .ok();
        let mut command = std::process::Command::new(program);
        if quick {
            command.arg("--quick");
        }
        command
            .env("VISIPASS_APP_FD", "3")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(
                log.map(std::process::Stdio::from)
                    .unwrap_or(std::process::Stdio::null()),
            );
        unsafe {
            command.pre_exec(move || {
                // dup2 leaves the copy without close-on-exec, so fd 3 survives exec.
                if fd == 3 {
                    let flags = libc::fcntl(3, libc::F_GETFD);
                    libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                } else if libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| failed())?;
        drop(theirs);
        let pid = child.id();
        *running = Some(pid);
        std::thread::spawn(move || child.wait());
        ours.set_nonblocking(true).map_err(|_| failed())?;
        let stream = UnixStream::from_std(ours).map_err(|_| failed())?;
        tokio::spawn(Arc::clone(&self).app_channel(stream, pid, quick));
        Ok(json!({ "opened": true }))
    }

    /// Serves the app's private connection: one request per line, in order.
    async fn app_channel(self: Arc<Self>, stream: UnixStream, pid: u32, quick: bool) {
        let requester = Requester {
            pid,
            agent: Some(APP_LABEL.into()),
            origin: None,
            task: None,
            seated: true,
            project: procinfo::Project {
                root: "(desktop app)".into(),
                remote: None,
            },
            token: None,
        };
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let response = match serde_json::from_str::<Envelope>(&line) {
                Ok(envelope) if envelope.version != PROTOCOL_VERSION => {
                    Response::err("The app and visipassd are different versions; restart both")
                }
                // Quick Access may hand over to the full app.
                Ok(Envelope {
                    request: Request::OpenApp { quick: false },
                    ..
                }) => match Arc::clone(&self).open_app(false).await {
                    Ok(value) => Response::ok(value),
                    Err(e) => Response::err(e.0),
                },
                Ok(Envelope {
                    request: Request::OpenApp { quick: true },
                    ..
                }) => Response::ok(json!({ "running": true })),
                Ok(envelope) => {
                    self.handle(envelope.request, &requester, Channel::App)
                        .await
                }
                Err(_) => Response::err("visipassd could not read the request"),
            };
            let Ok(mut text) = serde_json::to_string(&response) else {
                break;
            };
            text.push('\n');
            if write.write_all(text.as_bytes()).await.is_err() {
                break;
            }
        }
        let mut running = if quick {
            self.quick.lock().await
        } else {
            self.app.lock().await
        };
        if *running == Some(pid) {
            *running = None;
        }
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(Arc::clone(&self).connection(stream));
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }
}
