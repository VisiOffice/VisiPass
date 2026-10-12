//! Private input: a secret comes from the clipboard or a pipe, never an argument.

use std::io::{IsTerminal, Read};
use std::process::{Command, Stdio};
use vp_core::Failure;
use vp_core::secret::Secret;

#[derive(Clone, Copy)]
pub enum Source {
    Clipboard,
    Stdin,
}

pub fn source(clipboard: bool, stdin: bool) -> Result<Source, Failure> {
    match (clipboard, stdin) {
        (true, false) => Ok(Source::Clipboard),
        (false, true) => Ok(Source::Stdin),
        _ => Err(Failure::new("Choose exactly one of --clipboard or --stdin")),
    }
}

fn clipboard_command() -> Option<Command> {
    if cfg!(target_os = "macos") {
        return Some(Command::new("pbpaste"));
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let mut c = Command::new("wl-paste");
        c.args(["--no-newline", "--type", "text/plain"]);
        return Some(c);
    }
    if std::env::var_os("DISPLAY").is_some() {
        let mut c = Command::new("xclip");
        c.args(["-o", "-selection", "clipboard"]);
        return Some(c);
    }
    None
}

/// Reads a secret without displaying, echoing or clearing it.
pub fn read(source: Source, noun: &str, outcome: &str) -> Result<Secret, Failure> {
    let unreadable = || {
        Failure::new(format!(
            "Could not read the {noun} (details suppressed); {outcome}"
        ))
    };
    let text = match source {
        Source::Clipboard => {
            let mut command = clipboard_command().ok_or_else(|| {
                Failure::new(format!(
                    "--clipboard needs a graphical session; use --stdin; {outcome}"
                ))
            })?;
            let output = command
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .map_err(|_| unreadable())?;
            if !output.status.success() {
                return Err(unreadable());
            }
            String::from_utf8(output.stdout).map_err(|_| unreadable())?
        }
        Source::Stdin => {
            if std::io::stdin().is_terminal() {
                return Err(Failure::new(format!(
                    "Pipe the {noun} to --stdin; interactive input is not supported; {outcome}"
                )));
            }
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|_| unreadable())?;
            text
        }
    };
    let secret = Secret::new(text);
    if secret.is_blank() {
        return Err(Failure::new(format!(
            "The {noun} input is empty; {outcome}"
        )));
    }
    Ok(secret)
}
