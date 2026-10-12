//! `vp doctor`: versions and setup. Never authenticates, so it never prompts,
//! and prints nothing private: no account names, emails, vaults, items or paths.

use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vp_core::ipc::Request;

const INSTALL_OP: &str =
    "Install the 1Password CLI: https://developer.1password.com/docs/cli/get-started/";
const ENABLE_INTEGRATION: &str = "No 1Password accounts are visible. In the 1Password app, turn on Settings > Developer > Integrate with 1Password CLI.";
const NO_APPROVALS: &str = "visipassd cannot ask for approval (no graphical session with zenity). Run `vp daemon` in a terminal you keep open.";

fn local(args: &[&str]) -> Option<String> {
    let mut child = Command::new("op")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().ok()?.is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn doctor() -> Value {
    let op = local(&["--version"]);
    let accounts = op.as_ref().map(|_| {
        local(&["account", "list", "--format", "json"])
            .and_then(|t| {
                serde_json::from_str::<Vec<Value>>(if t.is_empty() { "[]" } else { &t }).ok()
            })
            .map(|l| l.len())
            .unwrap_or(0)
    });
    let auth = if std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some_and(|v| !v.is_empty()) {
        "environment service account"
    } else {
        "desktop app"
    };
    let daemon = crate::client::connect(false)
        .ok()
        .and_then(|s| crate::client::call_with(s, Request::Status).ok());
    let approvals = daemon
        .as_ref()
        .and_then(|d| d.get("approvals").and_then(Value::as_str))
        .map(String::from);
    let mut notes = Vec::new();
    if op.is_none() {
        notes.push(INSTALL_OP);
    }
    if auth == "desktop app" && accounts == Some(0) {
        notes.push(ENABLE_INTEGRATION);
    }
    if approvals.as_deref() == Some("none") {
        notes.push(NO_APPROVALS);
    }
    let mut report = json!({
        "vp": env!("CARGO_PKG_VERSION"),
        "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "op": op,
        "accounts": accounts,
        "auth": auth,
        "daemon": daemon.as_ref().map(|d| d.get("visipassd").cloned().unwrap_or(Value::Null)),
        "approvals": approvals,
        "grants": daemon.as_ref().and_then(|d| d.get("grants").cloned()),
    });
    if !notes.is_empty() {
        report["notes"] = json!(notes);
    }
    report
}
