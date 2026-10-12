//! Keyboard shortcuts: defaults, user overrides, and the cheat sheet's data.
//!
//! Overrides live in `$XDG_CONFIG_HOME/visipass/keybindings.toml` (created,
//! fully commented, on first launch):
//!
//! ```toml
//! copy-password = "ctrl-shift-c"          # replace the default
//! next-item = ["down", "ctrl-n"]          # several keys
//! open-website = ""                       # no key
//! ```

use gpui::{App, KeyBinding, Keystroke};
use std::path::PathBuf;

pub mod actions {
    gpui::actions!(
        visipass_app,
        [
            FocusSearch,
            NextItem,
            PreviousItem,
            OpenItem,
            FilterCategory,
            ShowAll,
            ShowFavorites,
            ShowAgents,
            ShowHelp,
            CopyUsername,
            CopyPassword,
            CopyOneTimeCode,
            RevealPassword,
            OpenWebsite,
            EditItem,
            NewItem,
            Dismiss,
            SaveItem,
            GeneratePassword,
        ]
    );
}
use actions::*;

pub const APP: &str = "VisiPassApp";
pub const EDITOR: &str = "ItemEditor";

pub struct Shortcut {
    pub name: &'static str,
    pub group: &'static str,
    pub description: &'static str,
    pub defaults: &'static [&'static str],
    context: &'static str,
    bind: fn(&str, Option<&str>) -> KeyBinding,
}

macro_rules! shortcut {
    ($name:literal, $group:literal, $description:literal, [$($key:literal),*], $context:expr, $action:ident) => {
        Shortcut {
            name: $name,
            group: $group,
            description: $description,
            defaults: &[$($key),*],
            context: $context,
            bind: |keys, context| KeyBinding::new(keys, $action, context),
        }
    };
}

/// Every shortcut, in cheat-sheet order. Copy keys follow 1Password's on Linux.
pub const SHORTCUTS: &[Shortcut] = &[
    shortcut!(
        "focus-search",
        "Find",
        "Search",
        ["ctrl-f", "ctrl-l"],
        APP,
        FocusSearch
    ),
    shortcut!(
        "next-item",
        "Find",
        "Next item",
        ["down", "ctrl-j"],
        APP,
        NextItem
    ),
    shortcut!(
        "previous-item",
        "Find",
        "Previous item",
        ["up", "ctrl-k"],
        APP,
        PreviousItem
    ),
    shortcut!(
        "open-item",
        "Find",
        "Open the selected item",
        ["enter"],
        APP,
        OpenItem
    ),
    shortcut!(
        "filter-category",
        "Find",
        "Filter by category",
        ["ctrl-t"],
        APP,
        FilterCategory
    ),
    shortcut!("show-all", "Find", "All items", ["ctrl-1"], APP, ShowAll),
    shortcut!(
        "show-favorites",
        "Find",
        "Favorites",
        ["ctrl-2"],
        APP,
        ShowFavorites
    ),
    shortcut!(
        "show-agents",
        "Find",
        "Agents: grants and requests",
        ["ctrl-3"],
        APP,
        ShowAgents
    ),
    shortcut!(
        "copy-username",
        "Item",
        "Copy username",
        ["ctrl-c"],
        APP,
        CopyUsername
    ),
    shortcut!(
        "copy-password",
        "Item",
        "Copy password",
        ["ctrl-shift-c"],
        APP,
        CopyPassword
    ),
    shortcut!(
        "copy-one-time-code",
        "Item",
        "Copy one-time code",
        ["ctrl-alt-c"],
        APP,
        CopyOneTimeCode
    ),
    shortcut!(
        "reveal-password",
        "Item",
        "Reveal or hide the password",
        ["ctrl-r"],
        APP,
        RevealPassword
    ),
    shortcut!(
        "open-website",
        "Item",
        "Open the website",
        ["ctrl-o"],
        APP,
        OpenWebsite
    ),
    shortcut!("edit-item", "Item", "Edit", ["ctrl-e"], APP, EditItem),
    shortcut!("new-item", "Item", "New item", ["ctrl-n"], APP, NewItem),
    shortcut!("save-item", "Editor", "Save", ["ctrl-s"], EDITOR, SaveItem),
    shortcut!(
        "generate-password",
        "Editor",
        "Generate a password",
        ["ctrl-g"],
        EDITOR,
        GeneratePassword
    ),
    shortcut!(
        "show-help",
        "General",
        "Keyboard shortcuts",
        ["f1", "ctrl-/"],
        APP,
        ShowHelp
    ),
    shortcut!(
        "dismiss",
        "General",
        "Close menu, help or editor",
        ["escape"],
        APP,
        Dismiss
    ),
];

pub struct Keymap {
    /// The keys in effect for each shortcut, index-aligned with `SHORTCUTS`.
    pub keys: Vec<Vec<String>>,
    pub warnings: Vec<String>,
    pub path: PathBuf,
}

pub fn config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("visipass")
        .join("keybindings.toml")
}

fn template() -> String {
    let mut text = String::from(
        "# VisiPass keyboard shortcuts.\n\
         # Uncomment a line to change it. A key looks like \"ctrl-shift-c\", \"alt-k\", \"f2\" or \"enter\";\n\
         # use a list for several keys, or \"\" for none. Restart the app after editing.\n",
    );
    let mut group = "";
    for s in SHORTCUTS {
        if s.group != group {
            group = s.group;
            text.push_str(&format!("\n# {group}\n"));
        }
        let keys = s
            .defaults
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("# {} = [{keys}]   # {}\n", s.name, s.description));
    }
    text
}

fn valid(keys: &str) -> bool {
    !keys.trim().is_empty() && keys.split_whitespace().all(|k| Keystroke::parse(k).is_ok())
}

/// Binds defaults plus the user's overrides. Never panics on a bad config.
pub fn load(cx: &mut App) -> Keymap {
    let path = config_path();
    let mut warnings = Vec::new();
    if !path.exists() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&path, template());
    }
    let overrides: toml::Table = match std::fs::read_to_string(&path) {
        Ok(text) => text.parse().unwrap_or_else(|e: toml::de::Error| {
            warnings.push(format!(
                "keybindings.toml is not valid TOML, using defaults: {}",
                e.message()
            ));
            toml::Table::new()
        }),
        Err(_) => toml::Table::new(),
    };
    for name in overrides.keys() {
        if !SHORTCUTS.iter().any(|s| s.name == name) {
            warnings.push(format!("Unknown shortcut \"{name}\" in keybindings.toml"));
        }
    }
    let mut keys = Vec::new();
    let mut bindings = Vec::new();
    for shortcut in SHORTCUTS {
        let chosen: Vec<String> = match overrides.get(shortcut.name) {
            Some(toml::Value::String(s)) if s.is_empty() => Vec::new(),
            Some(toml::Value::String(s)) => vec![s.clone()],
            Some(toml::Value::Array(list)) => list
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(_) => {
                warnings.push(format!(
                    "\"{}\" should be a key or a list of keys",
                    shortcut.name
                ));
                shortcut.defaults.iter().map(|k| k.to_string()).collect()
            }
            None => shortcut.defaults.iter().map(|k| k.to_string()).collect(),
        };
        let mut used = Vec::new();
        for key in chosen {
            if valid(&key) {
                bindings.push((shortcut.bind)(&key, Some(shortcut.context)));
                used.push(key);
            } else {
                warnings.push(format!(
                    "\"{key}\" for {} is not a key VisiPass understands",
                    shortcut.name
                ));
            }
        }
        keys.push(used);
    }
    cx.bind_keys(bindings);
    Keymap {
        keys,
        warnings,
        path,
    }
}

/// "ctrl-shift-c" -> "Ctrl+Shift+C".
pub fn pretty(keys: &str) -> String {
    keys.split_whitespace()
        .map(|stroke| {
            stroke
                .split('-')
                .map(|part| match part {
                    "ctrl" => "Ctrl".to_string(),
                    "shift" => "Shift".to_string(),
                    "alt" => "Alt".to_string(),
                    "cmd" | "super" | "secondary" => "Super".to_string(),
                    "enter" => "Enter".to_string(),
                    "escape" => "Esc".to_string(),
                    "up" => "↑".to_string(),
                    "down" => "↓".to_string(),
                    "" => "-".to_string(),
                    other => other.to_uppercase(),
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(" ")
}
