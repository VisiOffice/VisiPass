//! Quick Access: a themed overlay to find an item and copy from it, then get
//! out of the way. Opened with `vp quick` (bind it to a key in Hyprland).
//!
//! Enter copies the password. The same shortcuts as the app copy the username
//! or one-time code, or open the website. Esc clears the search, then closes.
//! After copying a secret the window closes but the process waits 90 seconds
//! to clear the clipboard, unless something else was copied since.

use crate::app::category_glyph;
use crate::client::Client;
use crate::keymap::actions::*;
use gpui::prelude::FluentBuilder;
use gpui::{
    AsyncWindowContext, Context, Entity, FocusHandle, Focusable, FontWeight, IntoElement, Render,
    SharedString, WeakEntity, Window, div, prelude::*, px,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vp_core::ipc::Request;
use vp_core::model::{Item, ItemSummary, Scope};
use vp_core::totp::Totp;
use vp_gui::text_input::{InputEvent, TextInput};
use vp_gui::theme::{Theme, alpha};

const ROWS: usize = 8;
const CLIPBOARD_CLEAR: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Take {
    Password,
    Username,
    Code,
    Website,
}

pub struct QuickView {
    theme: Theme,
    client: Arc<Client>,
    focus: FocusHandle,
    search: Entity<TextInput>,
    query: String,
    items: Vec<ItemSummary>,
    visible: Vec<usize>,
    cursor: usize,
    status: Option<(String, bool)>,
    busy_since: Option<Instant>,
}

fn host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_string()
}

impl QuickView {
    pub fn new(
        theme: Theme,
        client: Arc<Client>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search = cx.new(|cx| TextInput::new(theme.clone(), "Search VisiPass", cx));
        cx.subscribe_in(
            &search,
            window,
            |this, input, event: &InputEvent, window, cx| match event {
                InputEvent::Changed => {
                    this.query = input.read(cx).text().to_string();
                    this.apply();
                    cx.notify();
                }
                InputEvent::Submit => this.take(Take::Password, window, cx),
                InputEvent::Cancel => {
                    if input.read(cx).text().is_empty() {
                        cx.quit();
                    } else {
                        input.update(cx, |input, cx| input.set_text("", cx));
                    }
                }
            },
        )
        .detach();
        let focus = search.read(cx).focus_handle(cx);
        window.focus(&focus, cx);
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(400))
                    .await;
                if this.update(cx, |_, cx| cx.notify()).is_err() {
                    break;
                }
            }
        })
        .detach();
        let mut view = Self {
            theme,
            client,
            focus: cx.focus_handle(),
            search,
            query: String::new(),
            items: Vec::new(),
            visible: Vec::new(),
            cursor: 0,
            status: None,
            busy_since: None,
        };
        view.load(window, cx);
        view
    }

    fn call(
        &mut self,
        request: Request,
        window: &mut Window,
        cx: &mut Context<Self>,
        done: impl FnOnce(&mut Self, serde_json::Value, &mut Window, &mut Context<Self>) + 'static,
    ) {
        let client = self.client.clone();
        self.busy_since = Some(Instant::now());
        cx.spawn_in(
            window,
            async move |this: WeakEntity<Self>, cx: &mut AsyncWindowContext| {
                let result = cx
                    .background_executor()
                    .spawn(async move { client.call(request) })
                    .await;
                let _ = this.update_in(cx, |this, window, cx| {
                    this.busy_since = None;
                    match result {
                        Ok(value) => done(this, value, window, cx),
                        Err(e) => this.status = Some((e.0, true)),
                    }
                    cx.notify();
                });
            },
        )
        .detach();
        cx.notify();
    }

    fn load(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.call(
            Request::Items {
                scope: Scope::default(),
            },
            window,
            cx,
            |this, value, _, _| {
                this.items = serde_json::from_value(value["items"].clone()).unwrap_or_default();
                this.items.sort_by_key(|i| i.title.to_lowercase());
                this.apply();
            },
        );
    }

    fn apply(&mut self) {
        let mut scored: Vec<(u32, usize)> = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| vp_core::find::rank(&self.query, item).map(|s| (s, i)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        self.visible = scored.into_iter().take(ROWS).map(|(_, i)| i).collect();
        self.cursor = 0;
    }

    fn step(&mut self, delta: isize, cx: &mut Context<Self>) {
        if !self.visible.is_empty() {
            let last = self.visible.len() as isize - 1;
            self.cursor = (self.cursor as isize + delta).clamp(0, last) as usize;
            cx.notify();
        }
    }

    /// Fetches the selected item, takes what was asked for, and closes.
    fn take(&mut self, take: Take, window: &mut Window, cx: &mut Context<Self>) {
        let Some(summary) = self
            .visible
            .get(self.cursor)
            .map(|&i| self.items[i].clone())
        else {
            return;
        };
        let request = Request::Item {
            id: summary.id.clone(),
            vault: summary.vault.id.clone(),
        };
        self.call(request, window, cx, move |this, value, window, cx| {
            let Ok(item) = serde_json::from_value::<Item>(value) else {
                this.status = Some((
                    "visipassd sent an item Quick Access could not read".into(),
                    true,
                ));
                return;
            };
            let field = |purpose: &str, id: &str| {
                item.fields
                    .iter()
                    .find(|f| f.purpose.as_deref() == Some(purpose) || f.id == id)
                    .and_then(|f| f.value.as_ref())
                    .map(|v| v.expose().to_string())
                    .filter(|v| !v.is_empty())
            };
            let (value, secret, what) = match take {
                Take::Password => (
                    field("PASSWORD", "password").or_else(|| field("", "credential")),
                    true,
                    "password",
                ),
                Take::Username => (field("USERNAME", "username"), false, "username"),
                Take::Code => (
                    item.fields
                        .iter()
                        .filter(|f| f.kind == "OTP")
                        .find_map(|f| Totp::parse(f.value.as_ref()?.expose()).ok())
                        .map(|t| t.now().0),
                    true,
                    "one-time code",
                ),
                Take::Website => {
                    match item
                        .urls
                        .first()
                        .map(|u| u.href.clone())
                        .filter(|h| h.starts_with("https://") || h.starts_with("http://"))
                    {
                        Some(href) => {
                            cx.open_url(&href);
                            cx.quit();
                        }
                        None => this.status = Some(("This item has no website".into(), true)),
                    }
                    return;
                }
            };
            let Some(value) = value else {
                this.status = Some((format!("{} has no {what}", item.title), true));
                return;
            };
            vp_gui::clipboard::copy(&value, secret, cx);
            window.remove_window();
            if secret {
                // No window, but stay long enough to clear what was copied.
                cx.spawn(async move |_, cx| {
                    cx.background_executor().timer(CLIPBOARD_CLEAR).await;
                    cx.update(|cx| {
                        vp_gui::clipboard::clear_if_still(&value, cx);
                        cx.quit();
                    });
                })
                .detach();
            } else {
                cx.quit();
            }
        });
    }

    fn open_in_app(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.call(
            Request::OpenApp { quick: false },
            window,
            cx,
            |_, _, _, cx| cx.quit(),
        );
    }
}

impl Render for QuickView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let slow = self
            .busy_since
            .is_some_and(|s| s.elapsed() > Duration::from_millis(1200));
        let mut rows = div().flex().flex_col();
        for (row, &i) in self.visible.iter().enumerate() {
            let item = &self.items[i];
            let selected = row == self.cursor;
            let detail = item
                .additional_information
                .clone()
                .filter(|u| !u.is_empty())
                .or_else(|| item.urls.first().map(|u| host(&u.href)))
                .unwrap_or_else(|| item.vault.name.clone());
            rows = rows.child(
                div()
                    .id(("quick-row", row))
                    .w_full()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .px(px(12.))
                    .py(px(6.))
                    .rounded(px(t.radius))
                    .cursor_pointer()
                    .when(selected, |d| {
                        d.bg(alpha(t.foreground, t.controls.selected_fill_alpha * 0.6))
                    })
                    .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.cursor = row;
                        this.take(Take::Password, window, cx);
                    }))
                    .child(
                        div()
                            .w(px(18.))
                            .text_color(if selected { t.accent } else { t.muted })
                            .child(category_glyph(&item.category)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .overflow_hidden()
                            .child(div().truncate().child(item.title.clone()))
                            .child(
                                div()
                                    .text_size(px(t.size(0.917)))
                                    .text_color(t.muted)
                                    .truncate()
                                    .child(detail),
                            ),
                    )
                    .when(selected, |d| {
                        d.child(
                            div()
                                .text_size(px(t.size(0.917)))
                                .text_color(t.accent)
                                .child("↵ copy password"),
                        )
                    }),
            );
        }
        let empty = if self.items.is_empty() {
            "Loading your items…"
        } else {
            "No matches. Try url:, user:, tag: or \"exact words\"."
        };
        let (status, error) = match (&self.status, slow) {
            (Some((s, e)), _) => (s.clone(), *e),
            (None, true) => ("Waiting for 1Password… approve its prompt if one is showing.".to_string(), false),
            _ => ("↵ password · Ctrl+C username · Ctrl+Alt+C code · Ctrl+O website · Ctrl+E open in app · Esc".to_string(), false),
        };
        let card = div()
            .id("quick")
            .occlude()
            .w(px(600.))
            .max_w_full()
            .flex()
            .flex_col()
            .gap(px(10.))
            .p(px(14.))
            .bg(t.background)
            .border_2()
            .border_color(t.border)
            .rounded(px(t.radius))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        gpui::svg()
                            .path(vp_gui::assets::MARK)
                            .flex_none()
                            .size(px(t.size(1.5)))
                            .text_color(t.accent),
                    )
                    .child(div().flex_1().child(self.search.clone())),
            )
            .child(if self.visible.is_empty() {
                div()
                    .px(px(12.))
                    .py(px(8.))
                    .text_color(t.muted)
                    .child(empty)
            } else {
                rows
            })
            .child(
                div()
                    .text_size(px(t.size(0.833)))
                    .text_color(if error { t.danger } else { t.muted })
                    .child(status),
            );

        div()
            .size_full()
            .relative()
            .key_context(crate::keymap::APP)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &NextItem, _, cx| this.step(1, cx)))
            .on_action(cx.listener(|this, _: &PreviousItem, _, cx| this.step(-1, cx)))
            .on_action(
                cx.listener(|this, _: &OpenItem, window, cx| this.take(Take::Password, window, cx)),
            )
            .on_action(cx.listener(|this, _: &CopyPassword, window, cx| {
                this.take(Take::Password, window, cx)
            }))
            .on_action(cx.listener(|this, _: &CopyUsername, window, cx| {
                this.take(Take::Username, window, cx)
            }))
            .on_action(cx.listener(|this, _: &CopyOneTimeCode, window, cx| {
                this.take(Take::Code, window, cx)
            }))
            .on_action(
                cx.listener(|this, _: &OpenWebsite, window, cx| {
                    this.take(Take::Website, window, cx)
                }),
            )
            .on_action(cx.listener(|this, _: &EditItem, window, cx| this.open_in_app(window, cx)))
            .on_action(cx.listener(|_, _: &Dismiss, _, cx| cx.quit()))
            .text_color(t.foreground)
            .font_family(SharedString::from(t.font_family.clone()))
            .text_size(px(t.size(1.0)))
            // The backdrop: a click outside the card closes Quick Access.
            .child(
                div()
                    .id("backdrop")
                    .absolute()
                    .size_full()
                    .bg(t.scrim)
                    .on_click(cx.listener(|_, _, _, cx| cx.quit())),
            )
            .child(
                div()
                    .absolute()
                    .size_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .pt(px(140.))
                    .child(card.font_weight(FontWeight::NORMAL)),
            )
    }
}
