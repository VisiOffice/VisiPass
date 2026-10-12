//! visipass-prompt: asks the human to approve one VisiPass request.
//!
//! visipassd writes an `ApprovalPrompt` as JSON to stdin and reads one word
//! from stdout: deny, once, task, hours, always or timeout. Closing the window
//! or crashing prints nothing, which visipassd treats as deny.
//!
//! On Wayland compositors with layer-shell (Hyprland, Sway, ...) it is a
//! full-screen overlay with exclusive keyboard focus, like Omarchy's polkit
//! prompt. Elsewhere it is an ordinary window.
//!
//! `visipass-prompt --demo` shows a sample request, for checking the styling.

mod paste;
mod view;

use gpui::{
    App, AppContext, Bounds, Size, WindowBackgroundAppearance, WindowBounds, WindowKind,
    WindowOptions, px,
};
use std::io::Read;
use view::ApprovalView;
use vp_core::ipc::ApprovalPrompt;

fn demo() -> ApprovalPrompt {
    ApprovalPrompt {
        who: "Claude Code".into(),
        action: "inject 2 secrets into a command".into(),
        details: vec![
            (
                "Project".into(),
                "/home/you/Code/visipass  (git@github.com:you/visipass.git)".into(),
            ),
            ("Command".into(), "cargo test --workspace".into()),
        ],
        secrets: vec![
            "op://Private/Stripe/password".into(),
            "op://Dev/OpenAI API Key/credential".into(),
        ],
        purpose: Some("run the integration tests against the sandbox accounts".into()),
        timeout_secs: 120,
        paste: None,
    }
}

fn read_prompt() -> Option<ApprovalPrompt> {
    let mut input = String::new();
    std::io::stdin()
        .take(1 << 20)
        .read_to_string(&mut input)
        .ok()?;
    serde_json::from_str(&input).ok()
}

fn options(overlay: bool, cx: &App) -> WindowOptions {
    let size = Size::new(px(600.), px(560.));
    let mut options = WindowOptions {
        titlebar: None,
        app_id: Some("visipass-prompt".into()),
        window_bounds: Some(WindowBounds::centered(size, cx)),
        is_resizable: false,
        focus: true,
        show: true,
        ..Default::default()
    };
    if overlay {
        #[cfg(target_os = "linux")]
        {
            use gpui::layer_shell::{Anchor, KeyboardInteractivity, Layer, LayerShellOptions};
            options.window_background = WindowBackgroundAppearance::Transparent;
            // Size 0 with all four edges anchored: the compositor stretches it over the output.
            options.window_bounds = Some(WindowBounds::Windowed(Bounds::new(
                gpui::point(px(0.), px(0.)),
                Size::new(px(0.), px(0.)),
            )));
            options.kind = WindowKind::LayerShell(LayerShellOptions {
                namespace: "visipass-approval".into(),
                layer: Layer::Overlay,
                anchor: Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT,
                keyboard_interactivity: KeyboardInteractivity::Exclusive,
                // -1: cover the bar too, as Omarchy's polkit prompt does.
                exclusive_zone: Some(px(-1.)),
                ..Default::default()
            });
        }
    } else {
        options.titlebar = Some(gpui::TitlebarOptions {
            title: Some("VisiPass approval".into()),
            ..Default::default()
        });
        options.kind = WindowKind::Normal;
    }
    options
}

fn main() {
    let prompt = if std::env::args().any(|a| a == "--demo-paste") {
        ApprovalPrompt {
            action: "add a new secret to the vault \"Dev\"".into(),
            details: vec![
                (
                    "Project".into(),
                    "/home/you/Code/visipass  (git@github.com:you/visipass.git)".into(),
                ),
                ("Title".into(), "Stripe Live Key".into()),
            ],
            secrets: vec![],
            purpose: Some("deploy the billing service".into()),
            paste: Some(vp_core::ipc::PasteSpec {
                title: "Stripe Live Key".into(),
                vault: "Dev".into(),
            }),
            ..demo()
        }
    } else if std::env::args().any(|a| a == "--demo") {
        demo()
    } else {
        match read_prompt() {
            Some(prompt) => prompt,
            None => {
                eprintln!("visipass-prompt: expected an approval request on stdin");
                std::process::exit(2);
            }
        }
    };
    let theme = vp_gui::theme::Theme::load();
    let wayland = cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some();

    gpui_platform::application()
        .with_assets(vp_gui::assets::Assets)
        .run(move |cx: &mut App| {
            vp_gui::text_input::bind_keys(cx);
            let open = |overlay: bool, cx: &mut App| -> Result<(), ()> {
                let (prompt, theme) = (prompt.clone(), theme.clone());
                if prompt.paste.is_some() {
                    cx.open_window(options(overlay, cx), move |window, cx| {
                        cx.new(|cx| paste::PasteView::new(prompt, theme, overlay, window, cx))
                    })
                    .map(|_| ())
                    .map_err(|_| ())
                } else {
                    cx.open_window(options(overlay, cx), move |window, cx| {
                        let view = cx.new(|cx| ApprovalView::new(prompt, theme, overlay, cx));
                        let focus = view.read(cx).focus_handle().clone();
                        window.focus(&focus, cx);
                        view
                    })
                    .map(|_| ())
                    .map_err(|_| ())
                }
            };
            // Prefer the overlay; fall back to a window when the compositor has no layer-shell.
            if !(wayland && open(true, cx).is_ok()) && open(false, cx).is_err() {
                eprintln!("visipass-prompt: could not open a window");
                cx.quit();
            }
            cx.on_window_closed(|cx, _| cx.quit()).detach();
        });
}
