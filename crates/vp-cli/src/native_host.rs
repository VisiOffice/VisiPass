//! The browser extension's native-messaging host.
//!
//! Chrome starts `vp chrome-extension://<id>/` and exchanges messages on
//! stdin/stdout: a 4-byte native-endian length, then JSON. Each message is
//! relayed to visipassd as one request; the daemon matches logins, enforces the
//! phishing guard and asks the human before the first fill on a site.
//!
//! `vp browser install` registers this host with Chrome, Chromium and Brave.

use crate::client;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::PathBuf;
use vp_core::Failure;
use vp_core::ipc::Request;
use vp_core::secret::Secret;

pub const HOST_NAME: &str = "com.visioffice.visipass";
/// Fixed by the public key in extension/manifest.json.
pub const EXTENSION_ID: &str = "pmfmecknoobmojibgpbkpeckpdnmhnpm";
/// Room for a screenshot of the page, for reading a two-factor QR code.
const MAX_MESSAGE: usize = 3 << 20;

fn read_message(input: &mut impl Read) -> Option<Value> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length).ok()?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_MESSAGE {
        return None;
    }
    let mut body = vec![0u8; length];
    input.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

fn write_message(output: &mut impl Write, message: &Value) -> bool {
    let Ok(body) = serde_json::to_vec(message) else {
        return false;
    };
    output
        .write_all(&(body.len() as u32).to_ne_bytes())
        .and_then(|_| output.write_all(&body))
        .and_then(|_| output.flush())
        .is_ok()
}

/// Colours and font from the current Omarchy theme, so the popup matches.
fn theme() -> Value {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let colors =
        std::fs::read_to_string(home.join(".local/state/omarchy/current/theme/colors.toml"))
            .unwrap_or_default();
    let get = |key: &str| {
        colors.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key)
                .then(|| v.trim().trim_matches('"').to_string())
                .filter(|v| v.starts_with('#'))
        })
    };
    let font = std::process::Command::new("fc-match")
        .args(["-f", "%{family[0]}", "monospace"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|f| !f.is_empty());
    json!({
        "background": get("background"),
        "foreground": get("foreground"),
        "accent": get("accent"),
        "muted": get("light_foreground"),
        "well": get("dark_background"),
        "danger": get("red"),
        "font": font,
    })
}

fn handle(message: &Value) -> Result<Value, Failure> {
    let text = |key: &str| message.get(key).and_then(Value::as_str).map(String::from);
    let required = |key: &str| text(key).ok_or_else(|| Failure::new(format!("Missing \"{key}\"")));
    let flag = |key: &str| message.get(key).and_then(Value::as_bool).unwrap_or(false);
    match message.get("type").and_then(Value::as_str).unwrap_or("") {
        "ping" => Ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
        "theme" => Ok(theme()),
        "match" => client::call(Request::BrowserMatch {
            url: required("url")?,
            unlock: message
                .get("unlock")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        "search" => client::call(Request::BrowserSearch {
            query: required("query")?,
        }),
        "fill" => client::call(Request::BrowserFill {
            url: required("url")?,
            id: required("item")?,
            vault: required("vault")?,
            force: message
                .get("force")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        "generate" => client::call(Request::BrowserGenerate),
        "vaults" => client::call(Request::BrowserVaults),
        "save" => client::call(Request::BrowserSave {
            url: required("url")?,
            username: text("username").unwrap_or_default(),
            password: Secret::new(required("password")?),
            check: flag("check"),
            id: text("item"),
            vault: text("vault"),
        }),
        "add-totp" => client::call(Request::BrowserAddTotp {
            url: required("url")?,
            id: required("item")?,
            vault: required("vault")?,
            image: text("image"),
            key: text("key").map(Secret::new),
        }),
        // From the popup only: the extension never lets a page send these.
        "item" => client::call(Request::Item {
            id: required("item")?,
            vault: required("vault")?,
        }),
        "save-item" => client::call(Request::SaveItem {
            item: serde_json::from_value(message.get("data").cloned().unwrap_or(Value::Null))
                .map_err(|_| Failure::new("That item could not be read"))?,
        }),
        "archive" => client::call(Request::Archive {
            id: required("item")?,
            vault: required("vault")?,
        }),
        "favorite" => client::call(Request::SetFavorite {
            id: required("item")?,
            vault: required("vault")?,
            favorite: flag("favorite"),
        }),
        "open-app" => client::call(Request::OpenApp { quick: false }),
        other => Err(Failure::new(format!("Unknown message \"{other}\""))),
    }
}

pub fn serve(origin: &str) -> i32 {
    if origin.trim_end_matches('/') != format!("chrome-extension://{EXTENSION_ID}") {
        eprintln!("visipass: this native-messaging host only serves the VisiPass extension");
        return 1;
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    while let Some(message) = read_message(&mut input) {
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let reply = match handle(&message) {
            Ok(result) => json!({ "id": id, "ok": true, "result": result }),
            Err(e) => json!({ "id": id, "ok": false, "error": e.0 }),
        };
        if !write_message(&mut output, &reply) {
            break;
        }
    }
    0
}

/// Registers the host with every Chromium-family browser that has a profile here.
pub fn install() -> Result<Value, Failure> {
    let exe =
        std::env::current_exe().map_err(|_| Failure::new("Could not find the vp executable"))?;
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let browsers = [
        ("Chrome", home.join(".config/google-chrome")),
        ("Chromium", home.join(".config/chromium")),
        ("Brave", home.join(".config/BraveSoftware/Brave-Browser")),
    ];
    let manifest = json!({
        "name": HOST_NAME,
        "description": "VisiPass: fill logins from the vault",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    let mut installed = Vec::new();
    for (name, profile) in browsers {
        if !profile.is_dir() {
            continue;
        }
        let dir = profile.join("NativeMessagingHosts");
        std::fs::create_dir_all(&dir).map_err(|e| {
            Failure::new(format!("Could not create {}: {}", dir.display(), e.kind()))
        })?;
        let path = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&manifest).unwrap_or_default(),
        )
        .map_err(|e| Failure::new(format!("Could not write {}: {}", path.display(), e.kind())))?;
        installed.push(json!({ "browser": name, "manifest": path }));
    }
    if installed.is_empty() {
        return Err(Failure::new(
            "No Chrome, Chromium or Brave profile found in ~/.config",
        ));
    }
    let extension = ["/usr/share/visipass/extension"]
        .into_iter()
        .map(PathBuf::from)
        .chain(exe.ancestors().map(|a| a.join("extension")))
        .find(|p| p.join("manifest.json").is_file());
    Ok(json!({
        "installed": installed,
        "extensionId": EXTENSION_ID,
        "extensionDir": extension,
        "next": "In the browser open chrome://extensions, turn on Developer mode, choose Load unpacked, and select extensionDir.",
    }))
}
