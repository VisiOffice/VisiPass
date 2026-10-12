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
pub mod procinfo;

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
use vp_core::ipc::{Envelope, Operation, PROTOCOL_VERSION, Request, Response, Usage};
use vp_core::{Failure, audit, find, time};

const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
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
    log: Mutex<AccessLog>,
    /// One prompt at a time; a request queued behind a prompt re-checks grants first.
    approvals: tokio::sync::Mutex<()>,
    socket: PathBuf,
}

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
                }),
            }
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
            log: Mutex::new(AccessLog::open(state_dir.join("access.log"))),
            approvals: tokio::sync::Mutex::new(()),
            socket,
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
            })),
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
        }
    }

    pub async fn handle(&self, request: Request, requester: &Requester) -> Response {
        let name = request.name();
        let assessment = assess(&request, requester);
        let quiet = matches!(
            request,
            Request::Status | Request::Grants | Request::Log { .. }
        );
        let mut grant = None;
        let result = self
            .execute(request, requester, &assessment, &mut grant)
            .await;
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
                Ok(envelope) => {
                    let requester = tokio::task::spawn_blocking(move || procinfo::identify(pid))
                        .await
                        .unwrap_or_else(|_| procinfo::identify(0));
                    self.handle(envelope.request, &requester).await
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
