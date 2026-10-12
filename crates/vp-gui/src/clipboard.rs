//! Copying secrets without leaving them in clipboard history.
//!
//! Clipboard managers (Omarchy's history, cliphist, KDE Klipper) skip an entry
//! offered with the `x-kde-passwordManagerHint` type. GPUI's clipboard cannot
//! offer extra types, so on Wayland secrets go through `wl-copy --sensitive`,
//! which offers the hint. Elsewhere it falls back to GPUI's clipboard.

use gpui::{App, ClipboardItem};
use std::io::Write;
use std::process::{Command, Stdio};

fn wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        && std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join("wl-copy").is_file()))
}

/// Copies a value. `secret` marks it so clipboard history leaves it out.
pub fn copy(value: &str, secret: bool, cx: &mut App) {
    if secret && wayland() {
        // wl-copy forks a background owner for the selection and exits.
        let child = Command::new("wl-copy")
            .args(["--sensitive", "--type", "text/plain;charset=utf-8"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            let written = child
                .stdin
                .take()
                .map(|mut s| s.write_all(value.as_bytes()).is_ok())
                .unwrap_or(false);
            if written && child.wait().is_ok_and(|s| s.success()) {
                return;
            }
        }
    }
    cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
}

/// Clears the clipboard, but only if it still holds `value`: never wipe
/// something the person copied since.
pub fn clear_if_still(value: &str, cx: &mut App) {
    if wayland() {
        let current = Command::new("wl-paste")
            .args(["--no-newline", "--type", "text"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| o.stdout);
        if current.as_deref() == Some(value.as_bytes()) {
            let _ = Command::new("wl-copy")
                .arg("--clear")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        return;
    }
    if cx
        .read_from_clipboard()
        .and_then(|c| c.text())
        .is_some_and(|t| t == value)
    {
        cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
    }
}
