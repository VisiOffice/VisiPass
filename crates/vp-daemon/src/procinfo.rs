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
    /// With no known agent: the program that asked, for the prompt only (e.g.
    /// "kamal (in your terminal)"). Never part of a grant.
    pub origin: Option<String>,
    /// What "this task" binds to: the agent process, else the requester's parent.
    pub task: Option<ProcessId>,
    /// With no known agent: whether a person's terminal (a terminal window, SSH,
    /// a console login) is above the requester. A detached process is not the
    /// person at the terminal and does not share their grants.
    pub seated: bool,
    pub project: Project,
    /// Set when the request carried a valid agent token.
    pub token: Option<crate::tokens::TokenRecord>,
}

impl Requester {
    /// The grant key for who is asking: the agent, else "unknown" for a command
    /// in a person's terminal, else "detached" (started with setsid, nohup &, a
    /// detached tmux), which an agent could otherwise use to pass as the person.
    pub fn agent_label(&self) -> &str {
        match (&self.agent, self.seated) {
            (Some(agent), _) => agent,
            (None, true) => "unknown",
            (None, false) => "detached",
        }
    }
}

use os::{argv, comm, cwd, exe, stat};

struct Stat {
    ppid: u32,
    /// Only ever compared for equality: clock ticks since boot on Linux,
    /// microseconds since the epoch on macOS.
    start: u64,
}

/// What we read about another process, per platform. Every function returns
/// nothing rather than failing when the process is gone or not readable.
#[cfg(target_os = "linux")]
mod os {
    use super::Stat;
    use std::path::PathBuf;

    pub(super) fn stat(pid: u32) -> Option<Stat> {
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

    pub(super) fn comm(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|c| c.trim().to_string())
    }

    pub(super) fn argv(pid: u32) -> Vec<String> {
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        cmdline
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect()
    }

    pub(super) fn exe(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    pub(super) fn cwd(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    }
}

/// libproc and sysctl. They read same-user processes without extra
/// entitlements, which is all the daemon needs: it only serves its own user.
#[cfg(target_os = "macos")]
mod os {
    use super::Stat;
    use std::ffi::CStr;
    use std::mem::{MaybeUninit, size_of};
    use std::path::PathBuf;

    fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is exactly `size` bytes and the kernel writes at most that.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        // SAFETY: a full-size write initialised the struct (and it was zeroed before).
        (written == size).then(|| unsafe { info.assume_init() })
    }

    fn c_text(chars: &[libc::c_char]) -> Option<String> {
        // SAFETY: c_char and u8 have the same size and alignment.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(chars.as_ptr().cast(), chars.len()) };
        let text = CStr::from_bytes_until_nul(bytes).ok()?.to_string_lossy();
        (!text.is_empty()).then(|| text.into_owned())
    }

    pub(super) fn stat(pid: u32) -> Option<Stat> {
        let info = bsdinfo(pid)?;
        Some(Stat {
            ppid: info.pbi_ppid,
            start: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
        })
    }

    pub(super) fn comm(pid: u32) -> Option<String> {
        // pbi_name is the longer form; pbi_comm is cut at 16 bytes.
        let info = bsdinfo(pid)?;
        c_text(&info.pbi_name).or_else(|| c_text(&info.pbi_comm))
    }

    pub(super) fn argv(pid: u32) -> Vec<String> {
        procargs(pid).unwrap_or_default()
    }

    /// KERN_PROCARGS2 is argc (a C int), the executable path, NUL padding,
    /// then argc NUL-terminated arguments, then the environment (never read).
    fn procargs(pid: u32) -> Option<Vec<String>> {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROCARGS2,
            libc::c_int::try_from(pid).ok()?,
        ];
        let mut size: libc::size_t = 0;
        // SAFETY: a null buffer asks only for the size.
        let sized = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if sized != 0 || size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: the buffer is `size` bytes; the kernel updates `size` to what it wrote.
        let read = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buffer.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if read != 0 {
            return None;
        }
        buffer.truncate(size);
        let argc = usize::try_from(i32::from_ne_bytes(buffer.get(..4)?.try_into().ok()?)).ok()?;
        let rest = buffer.get(4..)?;
        let path_end = rest.iter().position(|b| *b == 0)?;
        let args = rest[path_end..]
            .iter()
            .position(|b| *b != 0)
            .map_or(&[][..], |start| &rest[path_end + start..]);
        Some(
            args.split(|b| *b == 0)
                .take(argc)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect(),
        )
    }

    pub(super) fn exe(pid: u32) -> Option<String> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is the size we pass.
        let len =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        let len = usize::try_from(len).ok().filter(|l| *l > 0)?;
        Some(String::from_utf8_lossy(&buffer[..len]).into_owned())
    }

    pub(super) fn cwd(pid: u32) -> Option<PathBuf> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
        let size = size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
        // SAFETY: as in bsdinfo.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written != size {
            return None;
        }
        // SAFETY: fully written above.
        let info = unsafe { info.assume_init() };
        // vip_path is a MAXPATHLEN char array, split into rows by libc.
        let path = info.pvi_cdir.vip_path.as_flattened();
        c_text(path).map(PathBuf::from)
    }
}

fn base(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.strip_suffix(".js")
        .or_else(|| name.strip_suffix(".mjs"))
        .unwrap_or(name)
}

// Browsers too: the extension's native-messaging host runs under one.
const AGENTS: [(&str, &str); 18] = [
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
    // macOS app executables.
    ("Google Chrome", "Chrome"),
    ("Chromium", "Chromium"),
    ("Brave Browser", "Brave"),
];

fn agent_name(pid: u32) -> Option<&'static str> {
    let comm = comm(pid).unwrap_or_default();
    let argv = argv(pid);
    let exe = exe(pid);
    // Node and Python agents run as `node .../claude` or `python .../aider`, so argv[1] counts too.
    let candidates = [
        Some(comm.as_str()),
        argv.first().map(|a| base(a)),
        argv.get(1).map(|a| base(a)),
        exe.as_deref().map(base),
    ];
    AGENTS
        .iter()
        .find(|(name, _)| candidates.iter().flatten().any(|c| c == name))
        .map(|(_, label)| *label)
}

/// Passed over when naming the program that asked: they only carry the request along.
/// `login` sits between a macOS terminal and its shell.
const CARRIERS: [&str; 17] = [
    "sh", "bash", "zsh", "fish", "dash", "nu", "env", "mise", "sudo", "timeout", "xargs", "nohup",
    "vp", "make", "systemd", "init", "login",
];
/// `ruby .../kamal` is kamal.
const INTERPRETERS: [&str; 9] = [
    "ruby", "node", "python", "python3", "perl", "bun", "deno", "bundle", "npx",
];
const TERMINALS: [&str; 12] = [
    "alacritty",
    "ghostty",
    "kitty",
    "foot",
    "footclient",
    "wezterm-gui",
    "konsole",
    "gnome-terminal-server",
    "xterm",
    "tmux: server",
    "Terminal",
    "iTerm2",
];

/// The program name a person would recognise for `pid`.
fn program(pid: u32) -> Option<String> {
    let comm = comm(pid)?;
    let argv = argv(pid);
    let first = argv
        .first()
        .map(|a| base(a).trim_start_matches('-').to_string());
    let name = first.filter(|n| !n.is_empty()).unwrap_or(comm);
    if INTERPRETERS.contains(&name.as_str()) || name.starts_with("python3.") {
        // The first argument that is not an option is the script.
        if let Some(script) = argv.iter().skip(1).find(|a| !a.starts_with('-')) {
            // `bundle exec kamal` and `npx exec x` name the program one word later.
            if base(script) != "exec" {
                return Some(base(script).to_string());
            }
            return argv
                .iter()
                .skip(2)
                .find(|a| !a.starts_with('-'))
                .map(|a| base(a).to_string());
        }
    }
    Some(name)
}

/// "kamal (in your terminal)", "kamal", or "Your terminal" for a command typed there.
/// `names` are the requester's ancestors, nearest first.
fn origin_of(names: &[String]) -> Option<String> {
    let terminal = names.iter().position(|n| {
        // iTerm2 runs shells under an `iTermServer-<version>` helper.
        TERMINALS.contains(&n.as_str()) || n.starts_with("tmux") || n.starts_with("iTermServer")
    });
    let asker = names[..terminal.unwrap_or(names.len())]
        .iter()
        .find(|n| !CARRIERS.contains(&n.as_str()))
        .cloned();
    match (asker, terminal) {
        (Some(asker), Some(_)) => Some(format!("{asker} (in your terminal)")),
        (Some(asker), None) => Some(asker),
        (None, Some(_)) => Some("Your terminal".into()),
        (None, None) => None,
    }
}

/// Where a person can be sitting: a terminal emulator's window, an SSH session,
/// a console login. Not tmux or screen: an agent can start one detached and type
/// into it.
fn seat(comm: &str) -> bool {
    (TERMINALS.contains(&comm) && !comm.starts_with("tmux"))
        || comm.starts_with("sshd")
        || comm == "login"
}

/// Whether `pid` runs in a terminal a person is at: a seat above it and no
/// coding agent anywhere above it. Decides whether visipassd may ask in its own
/// terminal; an agent that ran `vp daemon` through `script` or a detached tmux
/// would otherwise be answering its own approvals.
pub fn human_terminal(pid: u32) -> bool {
    let mut seated = false;
    let mut current = pid;
    for _ in 0..64 {
        let Some(s) = stat(current) else { break };
        if current != pid && agent_name(current).is_some() {
            return false;
        }
        seated |= seat(&comm(current).unwrap_or_default());
        if s.ppid <= 1 {
            break;
        }
        current = s.ppid;
    }
    seated
}

/// Where the system installs the Chromium-family browsers the extension runs in.
#[cfg(target_os = "linux")]
const BROWSER_DIRS: [&str; 8] = [
    "/opt/google/chrome",
    "/opt/google/chrome-beta",
    "/opt/google/chrome-unstable",
    "/usr/lib/chromium",
    "/usr/lib/chromium-browser",
    "/opt/brave.com/brave",
    "/opt/brave-bin",
    "/opt/vivaldi",
];

/// Whether `pid`'s parent is an installed browser: the browser starts the
/// native-messaging host itself. Judged by the parent's executable, which a
/// renamed process (`exec -a chrome`) cannot change and a user cannot write.
#[cfg(target_os = "linux")]
pub fn started_by_browser(pid: u32) -> bool {
    let Some(parent) = stat(pid).map(|s| s.ppid) else {
        return false;
    };
    exe(parent).is_some_and(|exe| {
        BROWSER_DIRS
            .iter()
            .any(|dir| Path::new(&exe).parent() == Some(Path::new(dir)))
    })
}

/// Browsers on macOS, by the team that signs them. Apps in /Applications are
/// usually owned by the user, so the path alone proves nothing: the running
/// parent must pass `codesign` against its maker's team. Chromium is unsigned
/// on macOS and is not accepted.
#[cfg(target_os = "macos")]
const BROWSER_TEAMS: [(&str, &str); 2] = [
    ("Google Chrome", "EQHXZ8M8AV"),
    ("Brave Browser", "KL8N8XSYF4"),
];

/// See the Linux version. A verdict is kept per browser process (pid and start
/// time), so `codesign` runs once per browser launch, not per request.
#[cfg(target_os = "macos")]
pub fn started_by_browser(pid: u32) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static VERDICTS: Mutex<Option<HashMap<(u32, u64), bool>>> = Mutex::new(None);
    let Some(parent) = stat(pid).map(|s| s.ppid) else {
        return false;
    };
    let Some(start) = stat(parent).map(|s| s.start) else {
        return false;
    };
    if let Some(known) = VERDICTS
        .lock()
        .ok()
        .and_then(|v| v.as_ref()?.get(&(parent, start)).copied())
    {
        return known;
    }
    let Some(exe) = exe(parent) else {
        return false;
    };
    let Some((_, team)) = BROWSER_TEAMS
        .iter()
        .find(|(name, _)| exe == format!("/Applications/{name}.app/Contents/MacOS/{name}"))
    else {
        return false;
    };
    // The running process, by pid: its signature as loaded, not the file on disk.
    let signed = std::process::Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg(format!(
            "-R=anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
        ))
        .arg(parent.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if let Ok(mut verdicts) = VERDICTS.lock() {
        verdicts
            .get_or_insert_default()
            .insert((parent, start), signed);
    }
    signed
}

/// When `pid` started, in the platform's own units; for tests that stand in
/// for a live agent process.
#[cfg(test)]
pub(crate) fn start_time(pid: u32) -> Option<u64> {
    stat(pid).map(|s| s.start)
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

/// The directory `pid` runs in.
pub fn working_dir(pid: u32) -> Option<PathBuf> {
    os::cwd(pid)
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
    let cwd = cwd(pid).unwrap_or_else(|| PathBuf::from("/"));
    let mut agent = None;
    let mut task = None;
    let mut agent_cwd = None;
    let mut seated = false;
    let parent = stat(pid).map(|s| s.ppid);
    let mut ancestors = Vec::new();
    let mut current = pid;
    for _ in 0..64 {
        let Some(s) = stat(current) else { break };
        if current != pid {
            ancestors.push(current);
        }
        if current != pid
            && let Some(name) = agent_name(current)
        {
            agent = Some(name.to_string());
            agent_cwd = os::cwd(current);
            task = Some(ProcessId {
                pid: current,
                start: s.start,
            });
            break;
        }
        seated |= seat(&comm(current).unwrap_or_default());
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
    let origin = if agent.is_none() {
        let names: Vec<String> = ancestors.iter().filter_map(|p| program(*p)).collect();
        origin_of(&names)
    } else {
        None
    };
    Requester {
        pid,
        agent,
        origin,
        task,
        seated,
        // An agent's project is its session's, wherever the command it ran has
        // changed directory to: `cd ../other-repo` does not borrow that repo's grants.
        project: project_of(agent_cwd.as_deref().unwrap_or(&cwd)),
        token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_place_a_person_sits_is_a_seat() {
        for comm in ["alacritty", "kitty", "sshd-session", "sshd", "login"] {
            assert!(seat(comm), "{comm}");
        }
        for comm in [
            "tmux: server",
            "screen",
            "script",
            "bash",
            "claude",
            "systemd",
        ] {
            assert!(!seat(comm), "{comm}");
        }
    }

    #[test]
    fn names_the_program_that_asked() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            origin_of(&names(&["sh", "kamal", "bash", "ghostty", "systemd"])).as_deref(),
            Some("kamal (in your terminal)")
        );
        assert_eq!(
            origin_of(&names(&["bash", "ghostty"])).as_deref(),
            Some("Your terminal")
        );
        assert_eq!(
            origin_of(&names(&["sh", "cron", "systemd"])).as_deref(),
            Some("cron")
        );
        assert_eq!(origin_of(&names(&["sh", "bash", "systemd"])), None);
        assert_eq!(
            origin_of(&names(&["zsh", "kamal", "zsh", "login", "Terminal"])).as_deref(),
            Some("kamal (in your terminal)")
        );
        assert_eq!(
            origin_of(&names(&["zsh", "login", "iTermServer-3.5.14", "iTerm2"])).as_deref(),
            Some("Your terminal")
        );
    }

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
