//! Asking the human.
//!
//! Approval is never a command an agent can run: a `vp approve` would be one
//! shell call away from the agent itself. The human answers in a window the
//! daemon launches and alone holds the output pipe of: `visipass-prompt` (GPUI,
//! styled after the desktop theme), else zenity. When visipassd runs in the
//! foreground of a terminal with no graphical session, it asks there.

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
}

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
    /// `visipass-prompt`, found next to visipassd or on PATH.
    Native(PathBuf),
    Zenity,
    Terminal,
    Unavailable,
}

pub(crate) fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

pub(crate) fn beside_self(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join(name)).filter(|p| p.is_file())
}

impl Desktop {
    /// Chooses how to ask, once, at startup.
    pub fn detect(foreground_terminal: bool) -> Self {
        let display = ["WAYLAND_DISPLAY", "DISPLAY"]
            .iter()
            .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()));
        if display
            && let Some(native) =
                beside_self("visipass-prompt").or_else(|| on_path("visipass-prompt"))
        {
            return Desktop::Native(native);
        }
        if display && on_path("zenity").is_some() {
            Desktop::Zenity
        } else if foreground_terminal {
            Desktop::Terminal
        } else {
            Desktop::Unavailable
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

    async fn zenity(prompt: &Prompt) -> Result<Decision, Failure> {
        let mut command = tokio::process::Command::new("zenity");
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
            .args(["--ok-label", ONCE, "--cancel-label", "Deny"])
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

    async fn zenity_show_key(key: &Secret) -> Result<Option<Secret>, Failure> {
        use tokio::io::AsyncWriteExt;
        // The key goes in on stdin, never in argv.
        let mut child = tokio::process::Command::new("zenity")
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

    async fn zenity_paste(prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        let spec = prompt.paste.clone().unwrap_or_default();
        if let PasteMode::ShowKey { key } = &spec.mode {
            return Self::zenity_show_key(key).await;
        }
        let (instruction, ok_label) = spec.instruction();
        let text = if matches!(spec.mode, PasteMode::Secret) {
            format!("{}\n\n{instruction}", plain(prompt).trim_end())
        } else {
            instruction
        };
        let output = tokio::process::Command::new("zenity")
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
    async fn confirm_presence(&self) -> vp_native::Presence {
        match self {
            Desktop::Unavailable => vp_native::Presence::Unavailable,
            _ => crate::presence::check(TIMEOUT).await,
        }
    }

    fn method(&self) -> &'static str {
        match self {
            Desktop::Native(_) => "VisiPass window",
            Desktop::Zenity => "desktop dialog (zenity)",
            Desktop::Terminal => "visipassd terminal",
            Desktop::Unavailable => "none",
        }
    }

    async fn ask(&self, prompt: &Prompt) -> Result<Decision, Failure> {
        match self {
            Desktop::Native(program) => Self::native(program, prompt).await,
            Desktop::Zenity => Self::zenity(prompt).await,
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
        match self {
            Desktop::Native(program) => Self::native_paste(program, prompt).await,
            Desktop::Zenity => Self::zenity_paste(prompt).await,
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
