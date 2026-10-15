//! Asking the human.
//!
//! Approval is never a command an agent can run: a `vp approve` would be one
//! shell call away from the agent itself. The human answers in a window the
//! daemon launches and alone holds the output pipe of: `visipass-prompt` (GPUI,
//! styled after the desktop theme), else zenity, or on macOS an AppleScript
//! dialog run by the system's `osascript`. When visipassd runs in the
//! foreground of a terminal a person sits at, with no graphical session, it asks
//! there.
//!
//! Nothing a caller controls picks the channel: the graphical session is found
//! from the sockets in the user's runtime directory, not from DISPLAY or
//! WAYLAND_DISPLAY, and the programs come from beside visipassd or the system
//! directories, not from PATH. Otherwise an agent could start its own daemon with
//! the display cleared, or a fake `visipass-prompt` first on PATH, and answer
//! its own approvals.

use crate::grants::Decision;
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use vp_core::Failure;

pub const TIMEOUT: Duration = Duration::from_secs(120);

pub use vp_core::ipc::ApprovalPrompt as Prompt;
use vp_core::ipc::{Answer, PasteAnswer, PasteMode};
use vp_core::secret::Secret;

pub trait Approver: Send + Sync + 'static {
    fn method(&self) -> &'static str;
    fn ask(&self, prompt: &Prompt) -> impl Future<Output = Result<Decision, Failure>> + Send;
    /// Asks the human to paste a new secret. `None` if they cancel.
    fn paste(
        &self,
        prompt: &Prompt,
    ) -> impl Future<Output = Result<Option<Secret>, Failure>> + Send;
    /// Quick unlock: has the system confirm the human is present.
    fn confirm_presence(&self) -> impl Future<Output = vp_native::Presence> + Send {
        async { vp_native::Presence::Unavailable }
    }
    /// Shows the human a page that holds a secret (the Emergency Kit), in a way
    /// that leaves nothing on disk.
    fn show_page(&self, _html: &str) -> impl Future<Output = Result<(), Failure>> + Send {
        async { Err(Failure::new("This visipassd cannot show pages")) }
    }
}

/// How long a shown page stays in memory before it is deleted.
pub const PAGE_LIFETIME: Duration = Duration::from_secs(10 * 60);

const ONCE: &str = "Allow once";
const TASK: &str = "This task";
const HOURS: &str = "This project, 8 hours";
const ALWAYS: &str = "Always for this project";
const STANDING_HOURS: u64 = 8;

fn truncate(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    if clean.chars().count() <= max {
        clean
    } else {
        format!("{}…", clean.chars().take(max).collect::<String>())
    }
}

fn pango(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn markup(prompt: &Prompt) -> String {
    let mut text = format!(
        "<b>{}</b> wants to {}.\n",
        pango(&prompt.who),
        pango(&prompt.action)
    );
    for (label, value) in &prompt.details {
        text.push_str(&format!(
            "\n<b>{}</b>\n{}\n",
            pango(label),
            pango(&truncate(value, 600))
        ));
    }
    if !prompt.secrets.is_empty() {
        text.push_str(&format!(
            "\n<b>Secrets</b>\n{}\n",
            pango(&truncate(&prompt.secrets.join("\n"), 600))
        ));
    }
    if let Some(purpose) = &prompt.purpose {
        text.push_str(&format!(
            "\n<b>Purpose</b> <i>(the agent's own words)</i>\n{}\n",
            pango(&truncate(purpose, 300))
        ));
    }
    text
}

fn plain(prompt: &Prompt) -> String {
    let mut text = format!("{} wants to {}.\n", prompt.who, prompt.action);
    for (label, value) in &prompt.details {
        text.push_str(&format!(
            "  {label}: {}\n",
            truncate(value, 600).replace('\n', "\n    ")
        ));
    }
    if !prompt.secrets.is_empty() {
        text.push_str(&format!(
            "  Secrets: {}\n",
            truncate(&prompt.secrets.join("\n"), 600).replace('\n', "\n    ")
        ));
    }
    if let Some(purpose) = &prompt.purpose {
        text.push_str(&format!(
            "  Purpose (the agent's own words): {}\n",
            truncate(purpose, 300)
        ));
    }
    text
}

#[derive(Clone)]
pub enum Desktop {
    /// `visipass-prompt`, found next to visipassd or in the system directories.
    Native(PathBuf),
    Zenity(PathBuf),
    /// macOS: `choose from list` and `display dialog`, run by /usr/bin/osascript.
    AppleScript,
    Terminal,
    Unavailable,
}

/// Where VisiPass runs its own helpers from: never PATH, which the caller sets.
#[cfg(not(target_os = "macos"))]
const SYSTEM_DIRS: [&str; 2] = ["/usr/bin", "/usr/local/bin"];
/// Homebrew leaves /usr/local/bin writable by the user on macOS.
#[cfg(target_os = "macos")]
const SYSTEM_DIRS: [&str; 1] = ["/usr/bin"];

/// Part of the system on macOS, under System Integrity Protection.
const OSASCRIPT: &str = "/usr/bin/osascript";

/// A helper program the daemon trusts with approvals, the app socket or the
/// Emergency Kit: beside visipassd, else in the system directories.
pub(crate) fn trusted_program(name: &str) -> Option<PathBuf> {
    beside_self(name).or_else(|| {
        SYSTEM_DIRS
            .iter()
            .map(|dir| PathBuf::from(dir).join(name))
            .find(|p| p.is_file())
    })
}

/// The graphical session, as the environment variables its programs need, found
/// from the sockets themselves: `$WAYLAND_DISPLAY` and `$DISPLAY` are kept only
/// when they name a socket that exists, and otherwise the user's own Wayland
/// socket under /run/user/UID, or an X server's under /tmp/.X11-unix, is used.
pub fn find_display() -> Vec<(&'static str, std::ffi::OsString)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let uid = unsafe { libc::getuid() };
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let ours = |p: &std::path::Path| {
        std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket() && m.uid() == uid)
    };
    let mut found = Vec::new();
    let named = std::env::var_os("WAYLAND_DISPLAY")
        .filter(|v| !v.is_empty())
        .map(|v| runtime.join(v))
        .filter(|p| ours(p));
    let wayland = named.or_else(|| {
        let mut sockets: Vec<PathBuf> = std::fs::read_dir(&runtime)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
                    && ours(p)
            })
            .collect();
        sockets.sort();
        sockets.into_iter().next()
    });
    if let Some(socket) = wayland {
        // An absolute WAYLAND_DISPLAY needs no XDG_RUNTIME_DIR.
        found.push(("WAYLAND_DISPLAY", socket.into_os_string()));
    }
    let x_socket = |display: &str| {
        let number = display.strip_prefix(':')?.split('.').next()?;
        let path = PathBuf::from(format!("/tmp/.X11-unix/X{number}"));
        std::fs::metadata(&path)
            .is_ok_and(|m| m.file_type().is_socket())
            .then_some(display.to_string())
    };
    let x11 = std::env::var("DISPLAY")
        .ok()
        .and_then(|d| x_socket(&d))
        .or_else(|| (0..10).find_map(|n| x_socket(&format!(":{n}"))));
    if let Some(display) = x11 {
        found.push(("DISPLAY", display.into()));
    }
    found
}

pub(crate) fn beside_self(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join(name)).filter(|p| p.is_file())
}

impl Desktop {
    /// Chooses how to ask, once, at startup. `display` is whether
    /// [`find_display`] found a graphical session; `human_terminal` whether
    /// visipassd runs in the foreground of a terminal a person sits at, with no
    /// agent above it ([`crate::procinfo::human_terminal`]).
    pub fn detect(display: bool, human_terminal: bool) -> Self {
        if display && let Some(native) = trusted_program("visipass-prompt") {
            return Desktop::Native(native);
        }
        if cfg!(target_os = "macos") && std::path::Path::new(OSASCRIPT).is_file() {
            return Desktop::AppleScript;
        }
        match trusted_program("zenity") {
            Some(zenity) if display => Desktop::Zenity(zenity),
            _ if human_terminal => Desktop::Terminal,
            _ => Desktop::Unavailable,
        }
    }

    async fn native(program: &PathBuf, prompt: &Prompt) -> Result<Decision, Failure> {
        let unavailable = || Failure::new("Could not show the approval prompt");
        let mut child = tokio::process::Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| unavailable())?;
        let request = serde_json::to_vec(prompt).map_err(|_| unavailable())?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().ok_or_else(unavailable)?;
            stdin.write_all(&request).await.map_err(|_| unavailable())?;
        }
        // The prompt times itself out; this only guards against a hung window.
        let output =
            tokio::time::timeout(TIMEOUT + Duration::from_secs(10), child.wait_with_output())
                .await
                .map_err(|_| Failure::new("No one answered the approval prompt within 2 minutes"))?
                .map_err(|_| unavailable())?;
        Ok(
            match Answer::parse(&String::from_utf8_lossy(&output.stdout)) {
                Some(Answer::Once) => Decision::Once,
                Some(Answer::Task) => Decision::Task,
                Some(Answer::Hours) => Decision::Hours(STANDING_HOURS),
                Some(Answer::Always) => Decision::Always,
                Some(Answer::Timeout) => {
                    return Err(Failure::new(
                        "No one answered the approval prompt within 2 minutes. Ask the human to approve, then run the command again",
                    ));
                }
                // Deny, a closed window, a crash: all deny.
                Some(Answer::Deny) | None => Decision::Deny,
            },
        )
    }

    async fn zenity(zenity: &PathBuf, prompt: &Prompt) -> Result<Decision, Failure> {
        let mut command = tokio::process::Command::new(zenity);
        command
            .args([
                "--question",
                "--title",
                "VisiPass",
                "--width",
                "560",
                "--text",
            ])
            .arg(markup(prompt))
            .args([
                "--ok-label",
                ONCE,
                "--cancel-label",
                "Deny",
                "--default-cancel",
            ])
            .args([
                "--extra-button",
                TASK,
                "--extra-button",
                HOURS,
                "--extra-button",
                ALWAYS,
            ])
            .args(["--timeout", &TIMEOUT.as_secs().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let output = command
            .output()
            .await
            .map_err(|_| Failure::new("Could not show the approval prompt"))?;
        let choice = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(match (output.status.code(), choice.as_str()) {
            (Some(0), _) => Decision::Once,
            (_, TASK) => Decision::Task,
            (_, HOURS) => Decision::Hours(STANDING_HOURS),
            (_, ALWAYS) => Decision::Always,
            (Some(5), _) => {
                return Err(Failure::new(
                    "No one answered the approval prompt within 2 minutes. Ask the human to approve, then run the command again",
                ));
            }
            _ => Decision::Deny,
        })
    }

    /// The prompt text and labels go in as arguments to `on run`, never into the
    /// script, so nothing in them is AppleScript. Deny is preselected, so Return
    /// and Escape both deny.
    async fn applescript(prompt: &Prompt) -> Result<Decision, Failure> {
        const SCRIPT: &str = r#"on run argv
    set choices to items 2 thru -1 of argv
    activate
    set picked to choose from list choices with title "VisiPass" with prompt (item 1 of argv) default items {item 1 of choices} OK button name "Choose" cancel button name "Deny"
    if picked is false then return item 1 of choices
    return item 1 of picked
end run"#;
        let mut child = tokio::process::Command::new(OSASCRIPT)
            .args(["-e", SCRIPT])
            .arg(plain(prompt))
            .args(["Deny", ONCE, TASK, HOURS, ALWAYS])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Failure::new("Could not show the approval prompt"))?;
        let mut stdout = child.stdout.take();
        let answered = tokio::time::timeout(TIMEOUT, async {
            use tokio::io::AsyncReadExt;
            let mut out = String::new();
            if let Some(stdout) = stdout.as_mut() {
                let _ = stdout.read_to_string(&mut out).await;
            }
            let _ = child.wait().await;
            out
        })
        .await
        .map_err(|_| {
            Failure::new(
                "No one answered the approval prompt within 2 minutes. Ask the human to approve, then run the command again",
            )
        })?;
        Ok(match answered.trim() {
            ONCE => Decision::Once,
            TASK => Decision::Task,
            HOURS => Decision::Hours(STANDING_HOURS),
            ALWAYS => Decision::Always,
            // Deny, Escape, an error, a crash: all deny.
            _ => Decision::Deny,
        })
    }

    async fn terminal(prompt: &Prompt) -> Result<Decision, Failure> {
        let text = plain(prompt);
        let answer = tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, Write};
            let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
            let mut out = &tty;
            write!(out, "\n{text}  [d]eny  [o]nce  [t]his task  [p]roject {STANDING_HOURS}h  [a]lways for project: ").ok()?;
            out.flush().ok()?;
            let mut line = String::new();
            std::io::BufReader::new(&tty).read_line(&mut line).ok()?;
            Some(line.trim().to_lowercase())
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Failure::new("Could not read an answer from the visipassd terminal"))?;
        Ok(match answer.as_str() {
            "o" | "once" => Decision::Once,
            "t" | "task" => Decision::Task,
            "p" | "project" => Decision::Hours(STANDING_HOURS),
            "a" | "always" => Decision::Always,
            _ => Decision::Deny,
        })
    }
}

const NO_ANSWER: &str =
    "No one answered the paste window within 2 minutes. Ask the human, then run the command again";

impl Desktop {
    async fn native_paste(program: &PathBuf, prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        let unavailable = || Failure::new("Could not show the paste window");
        let mut child = tokio::process::Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| unavailable())?;
        let request = serde_json::to_vec(prompt).map_err(|_| unavailable())?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().ok_or_else(unavailable)?;
            stdin.write_all(&request).await.map_err(|_| unavailable())?;
        }
        let output =
            tokio::time::timeout(TIMEOUT + Duration::from_secs(10), child.wait_with_output())
                .await
                .map_err(|_| Failure::new(NO_ANSWER))?
                .map_err(|_| unavailable())?;
        let stdout = Secret::new(String::from_utf8_lossy(&output.stdout).into_owned());
        match serde_json::from_str::<PasteAnswer>(stdout.expose().trim()) {
            Ok(PasteAnswer::Save { value }) => Ok(Some(value)),
            Ok(PasteAnswer::Timeout) => Err(Failure::new(NO_ANSWER)),
            // Cancel, a closed window, a crash: nothing is saved.
            Ok(PasteAnswer::Cancel) | Err(_) => Ok(None),
        }
    }

    async fn zenity_show_key(zenity: &PathBuf, key: &Secret) -> Result<Option<Secret>, Failure> {
        use tokio::io::AsyncWriteExt;
        // The key goes in on stdin, never in argv.
        let mut child = tokio::process::Command::new(zenity)
            .args([
                "--text-info",
                "--title",
                "VisiPass: your Secret Key",
                "--width",
                "560",
                "--height",
                "260",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Failure::new("Could not show the Secret Key"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let text = Secret::new(format!(
                "{}\n\n{}\n",
                vp_core::ipc::KEY_INSTRUCTIONS,
                key.expose()
            ));
            let _ = stdin.write_all(text.expose().as_bytes()).await;
        }
        let _ = child.wait().await;
        Ok(None)
    }

    async fn zenity_paste(zenity: &PathBuf, prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        let spec = prompt.paste.clone().unwrap_or_default();
        if let PasteMode::ShowKey { key } = &spec.mode {
            return Self::zenity_show_key(zenity, key).await;
        }
        let (instruction, ok_label) = spec.instruction();
        let text = if matches!(spec.mode, PasteMode::Secret) {
            format!("{}\n\n{instruction}", plain(prompt).trim_end())
        } else {
            instruction
        };
        let output = tokio::process::Command::new(zenity)
            .args([
                "--entry",
                "--hide-text",
                "--title",
                "VisiPass",
                "--width",
                "560",
                "--text",
            ])
            .arg(text)
            .args(["--ok-label", ok_label, "--cancel-label", "Cancel"])
            .args(["--timeout", &TIMEOUT.as_secs().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|_| Failure::new("Could not show the paste window"))?;
        if output.status.code() == Some(5) {
            return Err(Failure::new(NO_ANSWER));
        }
        let value = Secret::new(
            String::from_utf8_lossy(&output.stdout)
                .trim_end_matches('\n')
                .to_string(),
        );
        Ok((output.status.success() && !value.is_blank()).then_some(value))
    }

    /// A hidden-answer dialog; the value comes back on osascript's stdout only.
    async fn applescript_paste(prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        const SCRIPT: &str = r#"on run argv
    activate
    try
        set answer to display dialog (item 1 of argv) with title "VisiPass" default answer "" with hidden answer buttons {"Cancel", item 2 of argv} default button 2 cancel button 1 giving up after (item 3 of argv as integer)
    on error number -128
        return ""
    end try
    if gave up of answer then return character id 5
    return text returned of answer
end run"#;
        let spec = prompt.paste.clone().unwrap_or_default();
        if matches!(spec.mode, PasteMode::ShowKey { .. }) {
            // The key would have to go into the dialog as an argument, which
            // any process can read; the terminal shows it instead.
            return Err(Failure::new(
                "On macOS, create the vault from a terminal: run `vp daemon` there, then `vp init`",
            ));
        }
        let (instruction, ok_label) = spec.instruction();
        let text = if matches!(spec.mode, PasteMode::Secret) {
            format!("{}\n\n{instruction}", plain(prompt).trim_end())
        } else {
            instruction
        };
        let output = tokio::process::Command::new(OSASCRIPT)
            .args(["-e", SCRIPT])
            .arg(text)
            .arg(ok_label)
            .arg(TIMEOUT.as_secs().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|_| Failure::new("Could not show the paste window"))?;
        // osascript ends its result with one newline.
        let value = Secret::new(
            String::from_utf8_lossy(&output.stdout)
                .strip_suffix('\n')
                .unwrap_or_default()
                .to_string(),
        );
        if value.expose() == "\u{5}" {
            return Err(Failure::new(NO_ANSWER));
        }
        Ok((output.status.success() && !value.is_blank()).then_some(value))
    }

    async fn terminal_paste(prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        let spec = prompt.paste.clone().unwrap_or_default();
        let text = plain(prompt);
        tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, Write};
            use std::os::fd::AsRawFd;
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .ok()?;
            let mut out = &tty;
            if let PasteMode::ShowKey { key } = &spec.mode {
                writeln!(
                    out,
                    "\n{}\n\n    {}\n",
                    vp_core::ipc::KEY_INSTRUCTIONS,
                    key.expose()
                )
                .ok()?;
                return Some(None);
            }
            let (instruction, _) = spec.instruction();
            let lead = if matches!(spec.mode, PasteMode::Secret) {
                text
            } else {
                String::new()
            };
            write!(
                out,
                "\n{lead}  {instruction} (Enter on an empty line cancels): "
            )
            .ok()?;
            out.flush().ok()?;
            // Turn echo off while the secret is typed or pasted.
            let fd = tty.as_raw_fd();
            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            let have_termios = unsafe { libc::tcgetattr(fd, &mut original) } == 0;
            if have_termios {
                let mut silent = original;
                silent.c_lflag &= !libc::ECHO;
                unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) };
            }
            let mut line = String::new();
            let read = std::io::BufReader::new(&tty).read_line(&mut line);
            if have_termios {
                unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
            }
            let _ = writeln!(out);
            read.ok()?;
            let value = Secret::new(line.trim_end_matches(['\r', '\n']).to_string());
            Some((!value.is_blank()).then_some(value))
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Failure::new("Could not read from the visipassd terminal"))
    }
}

impl Approver for Desktop {
    /// Writes the page under `$XDG_RUNTIME_DIR` (memory, never disk), opens it
    /// with `xdg-open` and deletes it after [`PAGE_LIFETIME`].
    async fn show_page(&self, html: &str) -> Result<(), Failure> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Failure::new("No XDG_RUNTIME_DIR, so there is nowhere in memory to put the page")
            })?;
        let dir = PathBuf::from(runtime).join("visipass");
        crate::paths::private_dir(&dir)
            .map_err(|_| Failure::new("Could not prepare a place for the page"))?;
        let path = dir.join(format!("emergency-kit-{}.html", vp_native::new_id()));
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(html.as_bytes()));
        if written.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err(Failure::new("Could not write the page"));
        }
        let opened = trusted_program("xdg-open").and_then(|program| {
            let mut child = tokio::process::Command::new(program)
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            tokio::spawn(async move { child.wait().await });
            Some(())
        });
        let cleanup = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(PAGE_LIFETIME).await;
            let _ = std::fs::remove_file(cleanup);
        });
        match opened {
            Some(_) => Ok(()),
            None => {
                let _ = std::fs::remove_file(&path);
                Err(Failure::new(
                    "Could not open a browser (xdg-open is missing)",
                ))
            }
        }
    }

    async fn confirm_presence(&self) -> vp_native::Presence {
        match self {
            Desktop::Unavailable => vp_native::Presence::Unavailable,
            _ => crate::presence::check(TIMEOUT).await,
        }
    }

    fn method(&self) -> &'static str {
        match self {
            Desktop::Native(_) => "VisiPass window",
            Desktop::Zenity(_) => "desktop dialog (zenity)",
            Desktop::AppleScript => "macOS dialog",
            Desktop::Terminal => "visipassd terminal",
            Desktop::Unavailable => "none",
        }
    }

    async fn ask(&self, prompt: &Prompt) -> Result<Decision, Failure> {
        let prompt = &prompt.cleaned();
        match self {
            Desktop::Native(program) => Self::native(program, prompt).await,
            Desktop::Zenity(zenity) => Self::zenity(zenity, prompt).await,
            Desktop::AppleScript => Self::applescript(prompt).await,
            Desktop::Terminal => tokio::time::timeout(TIMEOUT, Self::terminal(prompt))
                .await
                .map_err(|_| {
                    Failure::new("No one answered the approval prompt within 2 minutes")
                })?,
            Desktop::Unavailable => Err(Failure::new(
                "visipassd cannot ask for approval: it has no graphical session and no terminal. Ask the human to run `vp daemon` in a terminal",
            )),
        }
    }

    async fn paste(&self, prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        let prompt = &prompt.cleaned();
        match self {
            Desktop::Native(program) => Self::native_paste(program, prompt).await,
            Desktop::Zenity(zenity) => Self::zenity_paste(zenity, prompt).await,
            Desktop::AppleScript => Self::applescript_paste(prompt).await,
            Desktop::Terminal => tokio::time::timeout(TIMEOUT, Self::terminal_paste(prompt))
                .await
                .map_err(|_| Failure::new(NO_ANSWER))?,
            Desktop::Unavailable => Err(Failure::new(
                "visipassd cannot ask the human: it has no graphical session and no terminal. Ask them to run `vp daemon` in a terminal",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_controls() {
        let prompt = Prompt {
            who: "Claude <Code>".into(),
            action: "inject 1 secret into a command".into(),
            details: vec![("Command".into(), "echo \x1b[31m & done".into())],
            secrets: vec![],
            purpose: Some("<b>trust me</b>".into()),
            timeout_secs: 120,
            paste: None,
        };
        let text = markup(&prompt);
        assert!(text.contains("Claude &lt;Code&gt;"));
        assert!(text.contains("&lt;b&gt;trust me&lt;/b&gt;"));
        assert!(!text.contains('\x1b'));
    }
}
