//! visipass-app: browse, add and edit items.
//!
//! visipassd launches this binary and hands it a private socket as fd 3
//! (`VISIPASS_APP_FD`); only that channel may read values. Started any other
//! way (a desktop launcher, a shell), it asks the daemon to launch the real
//! instance and exits.

mod app;
mod client;
mod editor;
mod keymap;
mod quick;

use app::VisiPassApp;
use gpui::{App, AppContext, Size, TitlebarOptions, WindowBounds, WindowOptions, px};
use std::sync::Arc;

fn main() {
    let Some(client) = client::Client::inherited() else {
        if let Err(e) = client::hand_off() {
            eprintln!("visipass-app: {e}");
            std::process::exit(1);
        }
        return;
    };
    let client = Arc::new(client);
    let theme = vp_gui::theme::Theme::load();
    let quick_mode = std::env::args().any(|a| a == "--quick");

    gpui_platform::application()
        .with_assets(vp_gui::assets::Assets)
        .run(move |cx: &mut App| {
            vp_gui::text_input::bind_keys(cx);
            let keymap = std::rc::Rc::new(keymap::load(cx));
            if quick_mode {
                open_quick(theme.clone(), client.clone(), cx);
                return;
            }
            let options = WindowOptions {
                titlebar: Some(TitlebarOptions {
                    title: Some("VisiPass".into()),
                    ..Default::default()
                }),
                app_id: Some("visipass".into()),
                window_bounds: Some(WindowBounds::centered(Size::new(px(1180.), px(760.)), cx)),
                ..Default::default()
            };
            let opened = cx.open_window(options, |window, cx| {
                cx.new(|cx| {
                    VisiPassApp::new(theme.clone(), client.clone(), keymap.clone(), window, cx)
                })
            });
            if opened.is_err() {
                eprintln!("visipass-app: could not open a window");
                cx.quit();
            }
            cx.on_window_closed(|cx, _| cx.quit()).detach();
        });
}

/// Quick Access: a full-screen layer-shell overlay with exclusive keyboard
/// focus where the compositor supports it (Hyprland, Sway); a small window
/// elsewhere. It quits itself (after clearing the clipboard if needed).
fn open_quick(theme: vp_gui::theme::Theme, client: Arc<client::Client>, cx: &mut App) {
    // `overlay` and `mut` are used only by the layer-shell code on Linux.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let make = |overlay: bool, cx: &mut App| {
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut options = WindowOptions {
            app_id: Some("visipass-quick".into()),
            window_bounds: Some(WindowBounds::centered(Size::new(px(640.), px(520.)), cx)),
            ..Default::default()
        };
        #[cfg(target_os = "linux")]
        if overlay {
            use gpui::layer_shell::{Anchor, KeyboardInteractivity, Layer, LayerShellOptions};
            options.titlebar = None;
            options.window_background = gpui::WindowBackgroundAppearance::Transparent;
            options.window_bounds = Some(WindowBounds::Windowed(gpui::Bounds::new(
                gpui::point(px(0.), px(0.)),
                Size::new(px(0.), px(0.)),
            )));
            options.kind = gpui::WindowKind::LayerShell(LayerShellOptions {
                namespace: "visipass-quick".into(),
                layer: Layer::Overlay,
                anchor: Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT,
                keyboard_interactivity: KeyboardInteractivity::Exclusive,
                exclusive_zone: Some(px(-1.)),
                ..Default::default()
            });
        }
        let (theme, client) = (theme.clone(), client.clone());
        cx.open_window(options, move |window, cx| {
            cx.new(|cx| quick::QuickView::new(theme, client, window, cx))
        })
    };
    let wayland = cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some();
    if !(wayland && make(true, cx).is_ok()) && make(false, cx).is_err() {
        eprintln!("visipass-app: could not open Quick Access");
        cx.quit();
    }
}
