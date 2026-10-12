//! visipass-app: browse, add and edit items.
//!
//! visipassd launches this binary and hands it a private socket as fd 3
//! (`VISIPASS_APP_FD`); only that channel may read values. Started any other
//! way (a desktop launcher, a shell), it asks the daemon to launch the real
//! instance and exits.

mod app;
mod client;
mod editor;

use app::{CloseEditor, FocusSearch, NewItem, VisiPassApp};
use gpui::{App, AppContext, KeyBinding, Size, TitlebarOptions, WindowBounds, WindowOptions, px};
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

    gpui_platform::application().run(move |cx: &mut App| {
        vp_gui::text_input::bind_keys(cx);
        cx.bind_keys([
            KeyBinding::new("secondary-f", FocusSearch, Some("VisiPassApp")),
            KeyBinding::new("secondary-n", NewItem, Some("VisiPassApp")),
            KeyBinding::new("escape", CloseEditor, Some("VisiPassApp")),
        ]);
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
            cx.new(|cx| VisiPassApp::new(theme.clone(), client.clone(), window, cx))
        });
        if opened.is_err() {
            eprintln!("visipass-app: could not open a window");
            cx.quit();
        }
        cx.on_window_closed(|cx, _| cx.quit()).detach();
    });
}
