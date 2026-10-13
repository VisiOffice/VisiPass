//! visipassd: the one long-lived process that talks to the vault.
//!
//! It exists so approvals can be scoped to an agent and a project instead of a
//! shell. Discovery (find, inventory, audit) needs no VisiPass approval, though
//! the backend may still prompt. Anything that hands out a value or writes to
//! the vault needs a grant or a fresh human approval, and every request is
//! written to the access log.

pub mod approval;
pub mod grants;
pub mod log;
pub mod paths;
pub mod presence;
pub mod procinfo;
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
        "host": s.urls.first().map(|u| find::page_host(&u.href)),
        "category": s.category,
        "exact": exact,
    })
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
        .unwrap_or_else(|| "An unrecognised process".into())
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
                    format!("print {count} where the agent can read them"),
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
                refs: BTreeSet::new(),
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
                need: Some(Need {
                    operation: Operation::Write,
                    refs: BTreeSet::new(),
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
        Request::BrowserFill { url, id, .. } => Assessment {
            need: None,
            refs: vec![format!("{}#{id}", find::page_host(url))],
            detail: Some(format!("fill on {}", find::page_host(url))),
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
                    refs: BTreeSet::new(),
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
        }
    }

    fn grants(&self) -> std::sync::MutexGuard<'_, Grants> {
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns the grant that covers the request: an existing one, or the human's answer.
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
        if let (Some(need), Some(prompt)) = (&assessment.need, &assessment.prompt) {
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
            Request::QuickUnlock { hours } => {
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
            Request::BrowserMatch { url } => {
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
                let summary = vp_core::model::ItemSummary {
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
                };
                let matches_page = find::page_match(&url, &summary).is_some();
                let saved_for: Vec<String> =
                    item.urls.iter().map(|u| find::page_host(&u.href)).collect();
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
        let quiet = matches!(
            request,
            Request::Status
                | Request::Grants
                | Request::Log { .. }
                | Request::Vaults { .. }
                | Request::Items { .. }
                | Request::Tokens
                | Request::BrowserMatch { .. }
                | Request::BrowserSearch { .. }
        );
        let mut grant = None;
        let result = if channel == Channel::Public && request.app_only() {
            Err(Failure::new(
                "Only the VisiPass app can do this. Use vp find, vp run or vp read instead",
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
                return Response::err(
                    "The access log could not be written, so the request was not completed",
                );
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
                    let mut requester =
                        tokio::task::spawn_blocking(move || procinfo::identify(pid))
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
        let program = approval::beside_self("visipass-app")
            .or_else(|| approval::on_path("visipass-app"))
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
            task: None,
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
