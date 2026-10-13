//! Where the daemon listens and keeps state. Shared so `vp` and `visipassd` never disagree.

use std::path::PathBuf;

fn set(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `$VISIPASS_SOCKET`, else `$XDG_RUNTIME_DIR/visipass/visipassd.sock`, else the state directory.
pub fn socket() -> PathBuf {
    set("VISIPASS_SOCKET").unwrap_or_else(|| match set("XDG_RUNTIME_DIR") {
        Some(runtime) => runtime.join("visipass").join("visipassd.sock"),
        None => state_dir().join("visipassd.sock"),
    })
}

/// `$VISIPASS_STATE_DIR`, else `$XDG_STATE_HOME/visipass`, else `~/.local/state/visipass`.
pub fn state_dir() -> PathBuf {
    set("VISIPASS_STATE_DIR").unwrap_or_else(|| {
        set("XDG_STATE_HOME")
            .unwrap_or_else(|| {
                set("HOME")
                    .unwrap_or_else(|| PathBuf::from("/"))
                    .join(".local/state")
            })
            .join("visipass")
    })
}

/// `$VISIPASS_DATA_DIR`, else `$XDG_DATA_HOME/visipass`, else `~/.local/share/visipass`.
/// Holds the native vault and its Secret Key.
pub fn data_dir() -> PathBuf {
    set("VISIPASS_DATA_DIR").unwrap_or_else(|| {
        set("XDG_DATA_HOME")
            .unwrap_or_else(|| {
                set("HOME")
                    .unwrap_or_else(|| PathBuf::from("/"))
                    .join(".local/share")
            })
            .join("visipass")
    })
}

/// Where packages install the polkit action quick unlock asks for.
pub const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/com.visioffice.visipass.policy";

/// The native vault's database.
pub fn vault_file() -> PathBuf {
    data_dir().join("vault.vpdb")
}

/// This device's copy of the Secret Key.
pub fn secret_key_file() -> PathBuf {
    data_dir().join("secret-key")
}

/// Brings an already-open VisiPass window to the front, where the desktop
/// allows it. On Hyprland this asks the compositor to focus the window by class;
/// elsewhere it does nothing.
pub fn focus_app_window() {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some() {
        let _ = std::process::Command::new("hyprctl")
            .args(["dispatch", "focuswindow", "class:^(visipass)$"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}
