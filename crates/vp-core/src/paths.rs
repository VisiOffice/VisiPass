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
