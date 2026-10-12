//! The look of the approval window, taken from the desktop theme.
//!
//! On Omarchy it mirrors the shell's own polkit prompt: the `[polkit]`,
//! `[controls]` and `[font]` sections of the generated `shell.toml`, the
//! palette in `colors.toml`, Hyprland's corner rounding, and the fontconfig
//! monospace family. Read fresh on every prompt, so a theme switch shows up on
//! the next one. Anywhere else, a built-in dark theme.

use gpui::Rgba;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Debug)]
pub struct Theme {
    pub background: Rgba,
    pub foreground: Rgba,
    /// Secondary text: labels, hints.
    pub muted: Rgba,
    pub accent: Rgba,
    pub danger: Rgba,
    /// Card border.
    pub border: Rgba,
    /// Full-screen dimming behind the card.
    pub scrim: Rgba,
    /// Wells such as the command line.
    pub well: Rgba,
    pub font_family: String,
    /// The rem root; Omarchy's `[font] base-size`.
    pub base_size: f32,
    pub radius: f32,
    pub controls: Controls,
}

/// Button chrome, from Omarchy's `[controls]` tokens.
#[derive(Clone, Debug)]
pub struct Controls {
    pub color: Rgba,
    pub fill_alpha: f32,
    pub border_alpha: f32,
    pub hover_fill_alpha: f32,
    pub hover_border_alpha: f32,
    pub selected_fill_alpha: f32,
    pub pressed_fill_alpha: f32,
}

impl Theme {
    /// Omarchy's font scale: body = base, title ≈ base × 1.167, and so on.
    pub fn size(&self, factor: f32) -> f32 {
        (self.base_size * factor).round().max(1.0)
    }

    pub fn load() -> Self {
        omarchy().unwrap_or_else(fallback)
    }
}

pub fn alpha(color: Rgba, a: f32) -> Rgba {
    Rgba {
        a: color.a * a.clamp(0.0, 1.0),
        ..color
    }
}

/// `#rrggbb`, `#rrggbbaa`, `rgb(rrggbb)`, `rgba(rrggbbaa)`. For a Hyprland
/// gradient (`rgba(..) rgba(..) 45deg`) the first stop.
pub fn parse_color(value: &str) -> Option<Rgba> {
    let first = value.split_whitespace().next()?;
    let hex = first
        .strip_prefix('#')
        .or_else(|| {
            first
                .strip_prefix("rgba(")
                .and_then(|s| s.strip_suffix(')'))
        })
        .or_else(|| first.strip_prefix("rgb(").and_then(|s| s.strip_suffix(')')))?;
    let channel = |i: usize| {
        u8::from_str_radix(hex.get(i..i + 2)?, 16)
            .ok()
            .map(|v| v as f32 / 255.0)
    };
    match hex.len() {
        6 => Some(Rgba {
            r: channel(0)?,
            g: channel(2)?,
            b: channel(4)?,
            a: 1.0,
        }),
        8 => Some(Rgba {
            r: channel(0)?,
            g: channel(2)?,
            b: channel(4)?,
            a: channel(6)?,
        }),
        _ => None,
    }
}

fn theme_dir() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let dir = home.join(".local/state/omarchy/current/theme");
    dir.join("colors.toml").is_file().then_some(dir)
}

fn read_toml(path: PathBuf) -> Option<toml::Table> {
    std::fs::read_to_string(path).ok()?.parse().ok()
}

/// Runs a small local helper with a short deadline.
fn quick(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
    while child.try_wait().ok()?.is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn font_family() -> String {
    std::env::var("OMARCHY_MENU_FONT")
        .ok()
        .filter(|f| !f.is_empty())
        .or_else(|| {
            quick("fc-match", &["-f", "%{family[0]}", "monospace"]).filter(|f| !f.is_empty())
        })
        .unwrap_or_else(|| "monospace".into())
}

fn hyprland_rounding() -> Option<f32> {
    let json = quick("hyprctl", &["-j", "getoption", "decoration:rounding"])?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    value.get("int")?.as_f64().map(|n| n.max(0.0) as f32)
}

fn omarchy() -> Option<Theme> {
    let dir = theme_dir()?;
    let colors = read_toml(dir.join("colors.toml"))?;
    let shell = read_toml(dir.join("shell.toml")).unwrap_or_default();

    let palette = |key: &str| {
        colors
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(parse_color)
    };
    let section = |name: &str| {
        shell
            .get(name)
            .and_then(|v| v.as_table())
            .cloned()
            .unwrap_or_default()
    };
    let polkit = section("polkit");
    let controls = section("controls");
    let hyprland = section("hyprland");
    let font = section("font");

    // Values may point at another token, e.g. `border = "hyprland.active-border"`.
    let resolve = |table: &toml::Table, key: &str| -> Option<Rgba> {
        let raw = table.get(key)?.as_str()?;
        match raw.strip_prefix("hyprland.") {
            Some(token) => hyprland
                .get(token)
                .and_then(|v| v.as_str())
                .and_then(parse_color),
            None => parse_color(raw),
        }
    };
    let number = |table: &toml::Table, key: &str| -> Option<f32> {
        table
            .get(key)
            .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)))
            .map(|f| f as f32)
    };

    let background = resolve(&polkit, "background").or_else(|| palette("background"))?;
    let foreground = resolve(&polkit, "text").or_else(|| palette("foreground"))?;
    let accent = resolve(&polkit, "accent")
        .or_else(|| palette("accent"))
        .unwrap_or(foreground);
    let scrim = resolve(&polkit, "scrim").unwrap_or(background);
    let control_color = resolve(&controls, "normal-color").unwrap_or(foreground);

    Some(Theme {
        background: alpha(
            background,
            number(&polkit, "background-alpha").unwrap_or(1.0),
        ),
        foreground,
        muted: palette("light_foreground").unwrap_or_else(|| alpha(foreground, 0.6)),
        accent,
        danger: resolve(&polkit, "text-error")
            .or_else(|| palette("red"))
            .unwrap_or(accent),
        border: alpha(
            resolve(&polkit, "border").unwrap_or(accent),
            number(&polkit, "border-alpha").unwrap_or(1.0),
        ),
        scrim: alpha(scrim, number(&polkit, "scrim-alpha").unwrap_or(0.5)),
        well: palette("dark_background").unwrap_or_else(|| alpha(foreground, 0.06)),
        font_family: font_family(),
        base_size: number(&font, "base-size").unwrap_or(12.0).max(1.0),
        radius: hyprland_rounding().unwrap_or(0.0),
        controls: Controls {
            color: control_color,
            fill_alpha: number(&controls, "normal-fill-alpha").unwrap_or(0.04),
            border_alpha: number(&controls, "normal-border-alpha").unwrap_or(0.4),
            hover_fill_alpha: number(&controls, "hover-cursor-fill-alpha").unwrap_or(0.08),
            hover_border_alpha: number(&controls, "hover-cursor-border-alpha").unwrap_or(0.25),
            selected_fill_alpha: number(&controls, "selected-fill-alpha").unwrap_or(0.18),
            pressed_fill_alpha: number(&controls, "pressed-fill-alpha").unwrap_or(0.22),
        },
    })
}

fn fallback() -> Theme {
    let hex = |s: &str| {
        parse_color(s).unwrap_or(Rgba {
            r: 0.5,
            g: 0.5,
            b: 0.5,
            a: 1.0,
        })
    };
    let background = hex("#1a1b26");
    let foreground = hex("#c0caf5");
    Theme {
        background,
        foreground,
        muted: hex("#9aa5ce"),
        accent: hex("#7aa2f7"),
        danger: hex("#f7768e"),
        border: hex("#7aa2f7"),
        scrim: alpha(background, 0.5),
        well: hex("#16161e"),
        font_family: font_family(),
        base_size: 12.0,
        radius: 8.0,
        controls: Controls {
            color: foreground,
            fill_alpha: 0.04,
            border_alpha: 0.4,
            hover_fill_alpha: 0.08,
            hover_border_alpha: 0.25,
            selected_fill_alpha: 0.18,
            pressed_fill_alpha: 0.22,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_color_forms() {
        let c = parse_color("#7fbbb3").unwrap();
        assert!((c.r - 0x7f as f32 / 255.0).abs() < 1e-6 && c.a == 1.0);
        assert!((parse_color("rgba(33ccff80)").unwrap().a - 0x80 as f32 / 255.0).abs() < 1e-6);
        assert!(parse_color("rgba(33ccffee) rgba(00ff99ee) 45deg").is_some());
        assert!(parse_color("hyprland.active-border").is_none());
        assert!(parse_color("#123").is_none());
    }
}
