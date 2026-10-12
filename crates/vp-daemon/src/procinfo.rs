//! Who is asking: the requesting process, the coding agent above it, and the
//! project it is working in.
//!
//! The agent label is a hint for the human reading an approval prompt, never
//! an authentication factor: any local process could imitate it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A process that can be told apart from a later one reusing its PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessId {
    pub pid: u32,
    pub start: u64,
}

impl ProcessId {
    pub fn alive(&self) -> bool {
        stat(self.pid).is_some_and(|s| s.start == self.start)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Project {
    /// Git root, or the working directory outside a repository. The grant key.
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Requester {
    pub pid: u32,
    /// The known agent above the requester, if any (e.g. "Claude Code").
    pub agent: Option<String>,
    /// What "this task" binds to: the agent process, else the requester's parent.
    pub task: Option<ProcessId>,
    pub project: Project,
    /// Set when the request carried a valid agent token.
    pub token: Option<crate::tokens::TokenRecord>,
}

impl Requester {
    pub fn agent_label(&self) -> &str {
        self.agent.as_deref().unwrap_or("unknown")
    }
}

struct Stat {
    ppid: u32,
    start: u64,
}

fn stat(pid: u32) -> Option<Stat> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces and parentheses; the fields start after the last ')'.
    let fields: Vec<&str> = text
        .get(text.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    Some(Stat {
        ppid: fields.get(1)?.parse().ok()?,
        start: fields.get(19)?.parse().ok()?,
    })
}

fn base(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.strip_suffix(".js")
        .or_else(|| name.strip_suffix(".mjs"))
        .unwrap_or(name)
}

// Browsers too: the extension's native-messaging host runs under one.
const AGENTS: [(&str, &str); 15] = [
    ("claude", "Claude Code"),
    ("codex", "Codex"),
    ("gemini", "Gemini CLI"),
    ("grok", "Grok CLI"),
    ("opencode", "opencode"),
    ("aider", "Aider"),
    ("cursor-agent", "Cursor Agent"),
    ("amp", "Amp"),
    ("goose", "Goose"),
    ("crush", "Crush"),
    ("chrome", "Chrome"),
    ("google-chrome", "Chrome"),
    ("chromium", "Chromium"),
    ("brave", "Brave"),
    ("vivaldi-bin", "Vivaldi"),
];

fn agent_name(pid: u32) -> Option<&'static str> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let argv: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    // Node and Python agents run as `node .../claude` or `python .../aider`, so argv[1] counts too.
    let candidates = [
        Some(comm.trim()),
        argv.first().map(|a| base(a)),
        argv.get(1).map(|a| base(a)),
        exe.as_deref().map(base),
    ];
    AGENTS
        .iter()
        .find(|(name, _)| candidates.iter().flatten().any(|c| c == name))
        .map(|(_, label)| *label)
}

fn git_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Strips credentials from an https remote (`https://token@github.com/...`).
fn safe_remote(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(authority);
            format!("{scheme}://{host}{path}")
        }
        None => url.to_string(),
    }
}

fn origin(root: &Path) -> Option<String> {
    let config = std::fs::read_to_string(root.join(".git/config")).ok()?;
    let mut in_origin = false;
    for line in config.lines().map(str::trim) {
        if line.starts_with('[') {
            in_origin = line == "[remote \"origin\"]";
        } else if in_origin
            && let Some(url) = line
                .strip_prefix("url")
                .map(str::trim_start)
                .and_then(|l| l.strip_prefix('='))
        {
            return Some(safe_remote(url.trim()));
        }
    }
    None
}

pub fn project_of(cwd: &Path) -> Project {
    match git_root(cwd) {
        Some(root) => Project {
            remote: origin(&root),
            root: root.to_string_lossy().into_owned(),
        },
        None => Project {
            root: cwd.to_string_lossy().into_owned(),
            remote: None,
        },
    }
}

pub fn identify(pid: u32) -> Requester {
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|_| PathBuf::from("/"));
    let mut agent = None;
    let mut task = None;
    let parent = stat(pid).map(|s| s.ppid);
    let mut current = pid;
    for _ in 0..64 {
        let Some(s) = stat(current) else { break };
        if current != pid
            && let Some(name) = agent_name(current)
        {
            agent = Some(name.to_string());
            task = Some(ProcessId {
                pid: current,
                start: s.start,
            });
            break;
        }
        if s.ppid <= 1 {
            break;
        }
        current = s.ppid;
    }
    if task.is_none() {
        task = parent.and_then(|p| {
            stat(p).map(|s| ProcessId {
                pid: p,
                start: s.start,
            })
        });
    }
    Requester {
        pid,
        agent,
        task,
        project: project_of(&cwd),
        token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_remote_credentials() {
        assert_eq!(
            safe_remote("https://ghp_sentinel@github.com/a/b.git"),
            "https://github.com/a/b.git"
        );
        assert_eq!(
            safe_remote("git@github.com:a/b.git"),
            "git@github.com:a/b.git"
        );
    }

    #[test]
    fn identifies_self() {
        let me = identify(std::process::id());
        assert_eq!(me.pid, std::process::id());
        assert!(me.task.is_some_and(|t| t.alive()));
    }
}
