//! Standing permissions the human gave in an approval prompt.
//!
//! A grant names one agent, one project, the operations and the exact
//! references (or, for writes, vaults) it covers. A request outside every
//! grant goes to the human again: grants never widen silently.

use crate::procinfo::{ProcessId, Requester};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use vp_core::ipc::Operation;
use vp_core::time::{now_unix, rfc3339};

/// What one request needs.
#[derive(Clone, Debug)]
pub struct Need {
    pub operation: Operation,
    pub refs: BTreeSet<String>,
    pub vaults: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Deny,
    Once,
    /// Until the agent process (or, with no known agent, the requesting shell) exits.
    Task,
    Hours(u64),
    Always,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub agent: String,
    pub project: String,
    pub operations: BTreeSet<Operation>,
    #[serde(default)]
    pub refs: BTreeSet<String>,
    #[serde(default)]
    pub vaults: BTreeSet<String>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Task grants live only in memory and end with the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<ProcessId>,
}

impl Grant {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|t| now < t) && self.task.is_none_or(|t| t.alive())
    }

    fn covers(&self, requester: &Requester, need: &Need, now: u64) -> bool {
        self.live(now)
            && self.agent == requester.agent_label()
            && self.project == requester.project.root
            // "This task" means the task that was asked: another session of the
            // same agent in the same project asks again.
            && self.task.is_none_or(|t| requester.task == Some(t))
            && self.operations.contains(&need.operation)
            && need.refs.is_subset(&self.refs)
            && need.vaults.is_subset(&self.vaults)
    }

    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "agent": self.agent,
            "project": self.project,
            "operations": self.operations,
            "refs": self.refs,
            "vaults": self.vaults,
            "createdAt": rfc3339(self.created_at),
            "expires": match (self.task, self.expires_at) {
                (Some(_), _) => "when the task ends".to_string(),
                (None, Some(t)) => rfc3339(t),
                (None, None) => "never".to_string(),
            },
        })
    }
}

pub struct Grants {
    file: PathBuf,
    saved: Vec<Grant>,
    tasks: Vec<Grant>,
}

fn new_id() -> String {
    let mut bytes = [0u8; 6];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .is_err()
    {
        bytes = (now_unix() as u128 ^ std::process::id() as u128).to_le_bytes()[..6]
            .try_into()
            .unwrap_or_default();
    }
    format!(
        "g_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

impl Grants {
    pub fn load(file: PathBuf) -> Self {
        let saved = std::fs::read_to_string(&file)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            file,
            saved,
            tasks: Vec::new(),
        }
    }

    fn save(&self) -> std::io::Result<()> {
        crate::write_private(
            &self.file,
            serde_json::to_string_pretty(&self.saved)?.as_bytes(),
        )
    }

    pub fn find(&mut self, requester: &Requester, need: &Need) -> Option<String> {
        let now = now_unix();
        self.tasks.retain(|g| g.live(now));
        self.saved
            .iter()
            .chain(&self.tasks)
            .find(|g| g.covers(requester, need, now))
            .map(|g| g.id.clone())
    }

    /// Records a decision. Returns the grant ID, or None for `Once` and `Deny`.
    pub fn record(
        &mut self,
        requester: &Requester,
        need: &Need,
        decision: Decision,
    ) -> std::io::Result<Option<String>> {
        let now = now_unix();
        let (expires_at, task) = match decision {
            Decision::Deny | Decision::Once => return Ok(None),
            Decision::Task => (None, requester.task),
            Decision::Hours(h) => (Some(now + h * 3600), None),
            Decision::Always => (None, None),
        };
        if decision == Decision::Task && task.is_none() {
            return Ok(None);
        }
        let grant = Grant {
            id: new_id(),
            agent: requester.agent_label().to_string(),
            project: requester.project.root.clone(),
            operations: BTreeSet::from([need.operation]),
            refs: need.refs.clone(),
            vaults: need.vaults.clone(),
            created_at: now,
            expires_at,
            task,
        };
        let id = grant.id.clone();
        if task.is_some() {
            self.tasks.push(grant);
        } else {
            self.saved.push(grant);
            self.save()?;
        }
        Ok(Some(id))
    }

    pub fn list(&mut self) -> Vec<serde_json::Value> {
        let now = now_unix();
        self.tasks.retain(|g| g.live(now));
        let before = self.saved.len();
        self.saved.retain(|g| g.live(now));
        if self.saved.len() != before {
            let _ = self.save();
        }
        self.saved
            .iter()
            .chain(&self.tasks)
            .map(Grant::view)
            .collect()
    }

    /// Revokes one grant, or all. Returns how many were removed.
    pub fn revoke(&mut self, id: Option<&str>) -> std::io::Result<usize> {
        let keep = |g: &Grant| id.is_some_and(|id| g.id != id);
        let before = self.saved.len() + self.tasks.len();
        self.saved.retain(keep);
        self.tasks.retain(keep);
        self.save()?;
        Ok(before - self.saved.len() - self.tasks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procinfo::Project;

    fn requester(agent: &str, root: &str) -> Requester {
        Requester {
            pid: std::process::id(),
            agent: Some(agent.into()),
            origin: None,
            task: None,
            seated: true,
            project: Project {
                root: root.into(),
                remote: None,
            },
            token: None,
        }
    }

    fn need(op: Operation, refs: &[&str]) -> Need {
        Need {
            operation: op,
            refs: refs.iter().map(|r| r.to_string()).collect(),
            vaults: BTreeSet::new(),
        }
    }

    #[test]
    fn grants_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let mut grants = Grants::load(dir.path().join("grants.json"));
        let claude = requester("Claude Code", "/p");
        let n = need(Operation::Run, &["op://a/b/c", "op://a/d/e"]);
        assert!(grants.find(&claude, &n).is_none());
        grants.record(&claude, &n, Decision::Always).unwrap();
        assert!(grants.find(&claude, &n).is_some());
        assert!(
            grants
                .find(&claude, &need(Operation::Run, &["op://a/b/c"]))
                .is_some(),
            "subset is covered"
        );
        assert!(
            grants
                .find(&claude, &need(Operation::Run, &["op://x/y/z"]))
                .is_none(),
            "new ref"
        );
        assert!(
            grants
                .find(&claude, &need(Operation::Reveal, &["op://a/b/c"]))
                .is_none(),
            "other operation"
        );
        assert!(
            grants.find(&requester("Codex", "/p"), &n).is_none(),
            "other agent"
        );
        assert!(
            grants.find(&requester("Claude Code", "/q"), &n).is_none(),
            "other project"
        );

        let reloaded = Grants::load(dir.path().join("grants.json"));
        assert_eq!(reloaded.saved.len(), 1);
    }

    #[test]
    fn once_is_not_kept_and_expired_grants_lapse() {
        let dir = tempfile::tempdir().unwrap();
        let mut grants = Grants::load(dir.path().join("grants.json"));
        let r = requester("Claude Code", "/p");
        let n = need(Operation::Run, &["op://a/b/c"]);
        assert_eq!(grants.record(&r, &n, Decision::Once).unwrap(), None);
        assert!(grants.find(&r, &n).is_none());
        grants.record(&r, &n, Decision::Hours(1)).unwrap();
        grants.saved[0].expires_at = Some(now_unix() - 1);
        assert!(grants.find(&r, &n).is_none());
        assert!(grants.list().is_empty());
    }

    #[test]
    fn a_task_grant_covers_only_its_own_task() {
        let dir = tempfile::tempdir().unwrap();
        let mut grants = Grants::load(dir.path().join("grants.json"));
        // This test process stands in for a live agent process.
        let pid = std::process::id();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let start = stat[stat.rfind(')').unwrap() + 1..]
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let task = ProcessId { pid, start };
        let mut first = requester("Claude Code", "/p");
        first.task = Some(task);
        let n = need(Operation::Run, &["op://a/b/c"]);
        grants.record(&first, &n, Decision::Task).unwrap();
        assert!(grants.find(&first, &n).is_some());
        let mut second = requester("Claude Code", "/p");
        second.task = Some(ProcessId { pid: 1, start: 0 });
        assert!(grants.find(&second, &n).is_none(), "another session");
        assert!(grants.find(&requester("Claude Code", "/p"), &n).is_none());
    }

    #[test]
    fn a_detached_process_is_not_the_person_at_the_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let mut grants = Grants::load(dir.path().join("grants.json"));
        let mut terminal = requester("x", "/p");
        terminal.agent = None;
        let n = need(Operation::Run, &["op://a/b/c"]);
        grants.record(&terminal, &n, Decision::Always).unwrap();
        assert!(grants.find(&terminal, &n).is_some());
        let detached = Requester {
            seated: false,
            ..terminal
        };
        assert_eq!(detached.agent_label(), "detached");
        assert!(grants.find(&detached, &n).is_none());
    }

    #[test]
    fn revokes() {
        let dir = tempfile::tempdir().unwrap();
        let mut grants = Grants::load(dir.path().join("grants.json"));
        let r = requester("Claude Code", "/p");
        let n = need(Operation::Run, &["op://a/b/c"]);
        let id = grants.record(&r, &n, Decision::Always).unwrap().unwrap();
        grants
            .record(
                &r,
                &need(Operation::Reveal, &["op://a/b/c"]),
                Decision::Always,
            )
            .unwrap();
        assert_eq!(grants.revoke(Some(&id)).unwrap(), 1);
        assert_eq!(grants.revoke(None).unwrap(), 1);
    }
}
