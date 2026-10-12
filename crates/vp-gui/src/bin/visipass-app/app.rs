//! The main window: sidebar, searchable item list, item detail.

use crate::client::Client;
use crate::editor::{EditorEvent, ItemEditor};
use gpui::prelude::FluentBuilder;
use gpui::{
    ClipboardItem, Context, Entity, FocusHandle, Focusable, FontWeight, IntoElement, Render,
    SharedString, Window, actions, div, prelude::*, px, uniform_list,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vp_core::ipc::Request;
use vp_core::model::{Item, ItemSummary, Scope, VaultRef, kind};
use vp_core::secret::Secret;
use vp_core::totp::Totp;
use vp_gui::text_input::{InputEvent, TextInput};
use vp_gui::theme::{Theme, alpha};

actions!(visipass_app, [FocusSearch, NewItem, CloseEditor]);

const CLIPBOARD_CLEAR: Duration = Duration::from_secs(90);
const REVEAL_FOR: Duration = Duration::from_secs(30);
const SLOW_CALL: Duration = Duration::from_millis(1500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    Favorites,
    Category(String),
    Vault(String),
    Agents,
}

pub struct VisiPassApp {
    theme: Theme,
    client: Arc<Client>,
    focus: FocusHandle,
    search: Entity<TextInput>,
    query: String,
    vaults: Vec<VaultRef>,
    items: Vec<ItemSummary>,
    visible: Vec<usize>,
    filter: Filter,
    selected: Option<String>,
    detail: Option<Item>,
    editor: Option<Entity<ItemEditor>>,
    revealed: HashMap<String, Instant>,
    copied: Option<(Secret, Instant)>,
    toast: Option<(String, Instant)>,
    error: Option<String>,
    busy_since: Option<Instant>,
    confirm_archive: bool,
    grants: Vec<Value>,
    log: Vec<Value>,
}

pub fn category_name(category: &str) -> String {
    match category {
        "LOGIN" => "Logins".into(),
        "PASSWORD" => "Passwords".into(),
        "API_CREDENTIAL" => "API credentials".into(),
        "SECURE_NOTE" => "Secure notes".into(),
        "CREDIT_CARD" => "Cards".into(),
        "IDENTITY" => "Identities".into(),
        "DATABASE" => "Databases".into(),
        "SERVER" => "Servers".into(),
        "SSH_KEY" => "SSH keys".into(),
        "DOCUMENT" => "Documents".into(),
        other => kind(other).replace('-', " "),
    }
}

pub fn category_glyph(category: &str) -> &'static str {
    match category {
        "LOGIN" => "\u{f007}",
        "PASSWORD" => "\u{f084}",
        "API_CREDENTIAL" => "\u{f121}",
        "SECURE_NOTE" => "\u{f15c}",
        "CREDIT_CARD" => "\u{f09d}",
        "SSH_KEY" | "SERVER" => "\u{f233}",
        "DATABASE" => "\u{f1c0}",
        _ => "\u{f023}",
    }
}

fn host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_string()
}

impl VisiPassApp {
    pub fn new(
        theme: Theme,
        client: Arc<Client>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search =
            cx.new(|cx| TextInput::new(theme.clone(), "Search titles, tags and websites", cx));
        cx.subscribe(&search, |this, input, event: &InputEvent, cx| match event {
            InputEvent::Changed => {
                this.query = input.read(cx).text().to_lowercase();
                this.apply_filter();
                cx.notify();
            }
            InputEvent::Submit => {
                if let Some(&first) = this.visible.first() {
                    let summary = this.items[first].clone();
                    this.open(summary, cx);
                }
            }
            InputEvent::Cancel => {}
        })
        .detach();
        // One tick a second: TOTP countdowns, reveal timeouts, clipboard clearing.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |this, cx| this.tick(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        let focus = cx.focus_handle();
        window.focus(&search.read(cx).focus_handle(cx), cx);
        let mut app = Self {
            theme,
            client,
            focus,
            search,
            query: String::new(),
            vaults: Vec::new(),
            items: Vec::new(),
            visible: Vec::new(),
            filter: Filter::All,
            selected: None,
            detail: None,
            editor: None,
            revealed: HashMap::new(),
            copied: None,
            toast: None,
            error: None,
            busy_since: None,
            confirm_archive: false,
            grants: Vec::new(),
            log: Vec::new(),
        };
        app.reload(cx);
        app
    }

    /// Runs a blocking daemon call off the UI thread, then applies the result.
    fn request(
        &mut self,
        request: Request,
        cx: &mut Context<Self>,
        done: impl FnOnce(&mut Self, Value, &mut Context<Self>) + 'static,
    ) {
        let client = self.client.clone();
        self.busy_since.get_or_insert_with(Instant::now);
        self.error = None;
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { client.call(request) })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.busy_since = None;
                match result {
                    Ok(value) => done(this, value, cx),
                    Err(e) => this.error = Some(e.0),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        self.request(Request::Vaults { account: None }, cx, |this, value, _| {
            this.vaults = serde_json::from_value(value["vaults"].clone()).unwrap_or_default();
            this.vaults.sort_by_key(|a| a.name.to_lowercase());
        });
        self.request(
            Request::Items {
                scope: Scope::default(),
            },
            cx,
            |this, value, _| {
                this.items = serde_json::from_value(value["items"].clone()).unwrap_or_default();
                this.items.sort_by_key(|a| a.title.to_lowercase());
                this.apply_filter();
            },
        );
    }

    fn load_agents(&mut self, cx: &mut Context<Self>) {
        self.request(Request::Grants, cx, |this, value, _| {
            this.grants = value["grants"].as_array().cloned().unwrap_or_default();
        });
        self.request(Request::Log { limit: 100 }, cx, |this, value, _| {
            let mut entries = value["entries"].as_array().cloned().unwrap_or_default();
            entries.reverse();
            this.log = entries;
        });
    }

    fn apply_filter(&mut self) {
        let query: Vec<String> = self.query.split_whitespace().map(String::from).collect();
        self.visible = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| match &self.filter {
                Filter::All | Filter::Agents => true,
                Filter::Favorites => item.favorite,
                Filter::Category(c) => &item.category == c,
                Filter::Vault(v) => &item.vault.id == v,
            })
            .filter(|(_, item)| {
                query.iter().all(|term| {
                    item.title.to_lowercase().contains(term.as_str())
                        || item
                            .tags
                            .iter()
                            .any(|t| t.to_lowercase().contains(term.as_str()))
                        || item
                            .urls
                            .iter()
                            .any(|u| u.href.to_lowercase().contains(term.as_str()))
                })
            })
            .map(|(i, _)| i)
            .collect();
    }

    fn set_filter(&mut self, filter: Filter, cx: &mut Context<Self>) {
        if filter == Filter::Agents {
            self.load_agents(cx);
        }
        self.filter = filter;
        self.apply_filter();
        cx.notify();
    }

    fn open(&mut self, summary: ItemSummary, cx: &mut Context<Self>) {
        self.selected = Some(summary.id.clone());
        self.editor = None;
        self.revealed.clear();
        self.confirm_archive = false;
        self.detail = None;
        let id = summary.id.clone();
        self.request(
            Request::Item {
                id: summary.id,
                vault: summary.vault.id,
            },
            cx,
            move |this, value, _| {
                if this.selected.as_deref() == Some(id.as_str()) {
                    match serde_json::from_value::<Item>(value) {
                        Ok(item) => this.detail = Some(item),
                        Err(_) => {
                            this.error =
                                Some("visipassd sent an item the app could not read".into())
                        }
                    }
                }
            },
        );
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let now = Instant::now();
        self.revealed.retain(|_, until| *until > now);
        if self.toast.as_ref().is_some_and(|(_, until)| *until <= now) {
            self.toast = None;
        }
        if let Some((value, until)) = &self.copied
            && *until <= now
        {
            // Clear only if the clipboard still holds what VisiPass put there.
            let still_ours = cx
                .read_from_clipboard()
                .and_then(|c| c.text())
                .is_some_and(|t| t == value.expose());
            if still_ours {
                cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
            }
            self.copied = None;
        }
        cx.notify();
    }

    fn copy(&mut self, label: &str, value: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        self.copied = Some((
            Secret::new(value.to_string()),
            Instant::now() + CLIPBOARD_CLEAR,
        ));
        self.toast = Some((
            format!("Copied {label}. The clipboard clears in 90 seconds."),
            Instant::now() + Duration::from_secs(4),
        ));
        cx.notify();
    }

    fn new_item(&mut self, category: &str, window: &mut Window, cx: &mut Context<Self>) {
        let vault = match &self.filter {
            Filter::Vault(id) => self.vaults.iter().find(|v| &v.id == id).cloned(),
            _ => None,
        }
        .or_else(|| self.vaults.first().cloned());
        let Some(vault) = vault else {
            self.error = Some("No vaults are available yet".into());
            cx.notify();
            return;
        };
        let item = Item {
            id: String::new(),
            title: String::new(),
            category: category.into(),
            vault,
            tags: Vec::new(),
            urls: Vec::new(),
            favorite: false,
            created_at: None,
            updated_at: None,
            sections: Vec::new(),
            fields: vp_core::model::template(category),
        };
        self.start_editing(item, window, cx);
    }

    fn start_editing(&mut self, item: Item, window: &mut Window, cx: &mut Context<Self>) {
        let theme = self.theme.clone();
        let vaults = self.vaults.clone();
        let editor = cx.new(|cx| ItemEditor::new(theme, item, vaults, window, cx));
        cx.subscribe(&editor, |this, _, event: &EditorEvent, cx| match event {
            EditorEvent::Cancel => {
                this.editor = None;
                cx.notify();
            }
            EditorEvent::Save(item) => this.save((**item).clone(), cx),
        })
        .detach();
        self.editor = Some(editor);
        cx.notify();
    }

    fn save(&mut self, item: Item, cx: &mut Context<Self>) {
        self.request(Request::SaveItem { item }, cx, |this, value, cx| {
            if let Ok(saved) = serde_json::from_value::<Item>(value) {
                this.selected = Some(saved.id.clone());
                this.detail = Some(saved);
                this.editor = None;
                this.toast = Some((
                    "Saved and verified.".into(),
                    Instant::now() + Duration::from_secs(4),
                ));
                this.reload(cx);
            }
        });
    }

    fn archive(&mut self, cx: &mut Context<Self>) {
        let Some(item) = self.detail.clone() else {
            return;
        };
        if !self.confirm_archive {
            self.confirm_archive = true;
            cx.notify();
            return;
        }
        self.request(
            Request::Archive {
                id: item.id,
                vault: item.vault.id,
            },
            cx,
            |this, _, cx| {
                this.detail = None;
                this.selected = None;
                this.confirm_archive = false;
                this.toast = Some((
                    "Moved to the archive.".into(),
                    Instant::now() + Duration::from_secs(4),
                ));
                this.reload(cx);
            },
        );
    }

    fn revoke(&mut self, id: String, cx: &mut Context<Self>) {
        self.request(
            Request::Revoke {
                id: Some(id),
                all: false,
            },
            cx,
            |this, _, cx| this.load_agents(cx),
        );
    }

    // ---- rendering ---------------------------------------------------------

    fn button(
        &self,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
        cx: &mut Context<Self>,
        on: impl Fn(&mut Self, &mut Window, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        let t = &self.theme;
        let c = &t.controls;
        div()
            .id(gpui::ElementId::Name(id.into()))
            .px(px(10.))
            .py(px(4.))
            .rounded(px(t.radius))
            .border_1()
            .border_color(alpha(c.color, c.border_alpha))
            .bg(alpha(c.color, c.fill_alpha))
            .text_color(t.foreground)
            .cursor_pointer()
            .hover(|s| {
                s.bg(alpha(c.color, c.hover_fill_alpha))
                    .border_color(alpha(c.color, c.hover_border_alpha.max(0.25)))
            })
            .active(|s| s.bg(alpha(c.color, c.pressed_fill_alpha)))
            .on_click(cx.listener(move |this, _, window, cx| on(this, window, cx)))
            .child(label.into())
    }

    fn nav_row(
        &self,
        id: String,
        glyph: &'static str,
        label: String,
        count: Option<usize>,
        filter: Filter,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let t = &self.theme;
        let selected = self.filter == filter;
        div()
            .id(gpui::ElementId::Name(id.into()))
            .flex()
            .items_center()
            .gap(px(8.))
            .px(px(10.))
            .py(px(4.))
            .rounded(px(t.radius))
            .cursor_pointer()
            .text_color(if selected { t.accent } else { t.foreground })
            .when(selected, |d| {
                d.bg(alpha(t.foreground, t.controls.selected_fill_alpha * 0.6))
            })
            .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
            .on_click(cx.listener(move |this, _, _, cx| this.set_filter(filter.clone(), cx)))
            .child(
                div()
                    .w(px(16.))
                    .text_color(if selected { t.accent } else { t.muted })
                    .child(glyph),
            )
            .child(div().flex_1().child(label))
            .when_some(count, |d, n| {
                d.child(
                    div()
                        .text_color(t.muted)
                        .text_size(px(t.size(0.917)))
                        .child(n.to_string()),
                )
            })
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let heading = |text: &str| {
            div()
                .px(px(10.))
                .pt(px(14.))
                .pb(px(4.))
                .text_size(px(t.size(0.833)))
                .text_color(t.muted)
                .child(text.to_uppercase())
        };
        let mut categories: Vec<(String, usize)> = Vec::new();
        for item in &self.items {
            match categories.iter_mut().find(|(c, _)| c == &item.category) {
                Some((_, n)) => *n += 1,
                None => categories.push((item.category.clone(), 1)),
            }
        }
        categories.sort_by_key(|a| category_name(&a.0));
        let favorites = self.items.iter().filter(|i| i.favorite).count();

        let mut sidebar = div()
            .id("sidebar")
            .w(px(230.))
            .h_full()
            .flex()
            .flex_col()
            .p(px(8.))
            .bg(t.well)
            .border_r_1()
            .border_color(alpha(t.foreground, 0.08))
            .overflow_y_scroll()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .px(px(10.))
                    .py(px(8.))
                    .child(
                        div()
                            .text_color(t.accent)
                            .text_size(px(t.size(1.5)))
                            .child("\u{f084}"),
                    )
                    .child(
                        div()
                            .text_size(px(t.size(1.167)))
                            .font_weight(FontWeight::BOLD)
                            .child("VisiPass"),
                    ),
            )
            .child(self.nav_row(
                "nav-all".into(),
                "\u{f03a}",
                "All items".into(),
                Some(self.items.len()),
                Filter::All,
                cx,
            ))
            .when(favorites > 0, |d| {
                d.child(self.nav_row(
                    "nav-fav".into(),
                    "\u{f005}",
                    "Favorites".into(),
                    Some(favorites),
                    Filter::Favorites,
                    cx,
                ))
            })
            .child(heading("Categories"));
        for (category, count) in categories {
            sidebar = sidebar.child(self.nav_row(
                format!("cat-{category}"),
                category_glyph(&category),
                category_name(&category),
                Some(count),
                Filter::Category(category),
                cx,
            ));
        }
        sidebar = sidebar.child(heading("Vaults"));
        for vault in &self.vaults {
            let count = self.items.iter().filter(|i| i.vault.id == vault.id).count();
            sidebar = sidebar.child(self.nav_row(
                format!("vault-{}", vault.id),
                "\u{f187}",
                vault.name.clone(),
                Some(count),
                Filter::Vault(vault.id.clone()),
                cx,
            ));
        }
        sidebar
            .child(div().flex_1().min_h(px(12.)))
            .child(self.nav_row(
                "nav-agents".into(),
                "\u{f544}",
                "Agents".into(),
                None,
                Filter::Agents,
                cx,
            ))
    }

    fn render_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let count = self.visible.len();
        let new_menu = div()
            .flex()
            .gap(px(6.))
            .child(self.button("new-login", "+ Login", cx, |this, w, cx| {
                this.new_item("LOGIN", w, cx)
            }))
            .child(self.button("new-api", "+ API key", cx, |this, w, cx| {
                this.new_item("API_CREDENTIAL", w, cx)
            }))
            .child(self.button("new-note", "+ Note", cx, |this, w, cx| {
                this.new_item("SECURE_NOTE", w, cx)
            }));
        div()
            .w(px(330.))
            .h_full()
            .flex()
            .flex_col()
            .border_r_1()
            .border_color(alpha(t.foreground, 0.08))
            .child(
                div()
                    .p(px(10.))
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .child(self.search.clone())
                    .child(new_menu),
            )
            .child(
                uniform_list(
                    "items",
                    count,
                    cx.processor(|this, range: std::ops::Range<usize>, _window, cx| {
                        range
                            .filter_map(|row| {
                                this.visible.get(row).map(|&i| (row, this.items[i].clone()))
                            })
                            .map(|(row, item)| this.render_row(row, item, cx))
                            .collect::<Vec<_>>()
                    }),
                )
                .flex_1(),
            )
    }

    fn render_row(
        &self,
        row: usize,
        item: ItemSummary,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = &self.theme;
        let selected = self.selected.as_deref() == Some(item.id.as_str());
        let subtitle = match item.urls.first() {
            Some(url) => format!("{} · {}", item.vault.name, host(&url.href)),
            None => item.vault.name.clone(),
        };
        let open = item.clone();
        div()
            .id(("row", row))
            .flex()
            .items_center()
            .gap(px(10.))
            .px(px(12.))
            .py(px(6.))
            .cursor_pointer()
            .when(selected, |d| {
                d.bg(alpha(t.foreground, t.controls.selected_fill_alpha * 0.6))
            })
            .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
            .on_click(cx.listener(move |this, _, _, cx| this.open(open.clone(), cx)))
            .child(
                div()
                    .w(px(18.))
                    .text_color(if selected { t.accent } else { t.muted })
                    .child(category_glyph(&item.category)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    .child(
                        div()
                            .text_color(t.foreground)
                            .truncate()
                            .child(item.title.clone()),
                    )
                    .child(
                        div()
                            .text_size(px(t.size(0.917)))
                            .text_color(t.muted)
                            .truncate()
                            .child(subtitle),
                    ),
            )
            .into_any_element()
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let t = self.theme.clone();
        if let Some(editor) = &self.editor {
            return div()
                .flex_1()
                .h_full()
                .child(editor.clone())
                .into_any_element();
        }
        if self.filter == Filter::Agents {
            return self.render_agents(cx).into_any_element();
        }
        let Some(item) = self.detail.clone() else {
            let hint = if self.selected.is_some() {
                "Opening…"
            } else {
                "Select an item, or press Ctrl+N for a new login."
            };
            return div()
                .flex_1()
                .h_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(t.muted)
                .child(hint)
                .into_any_element();
        };

        let mut fields = div().flex().flex_col().gap(px(12.));
        for field in item
            .fields
            .iter()
            .filter(|f| f.value.as_ref().is_some_and(|v| !v.expose().is_empty()))
        {
            let value = field
                .value
                .clone()
                .unwrap_or_else(|| Secret::new(String::new()));
            let label = field.display_label();
            let key = field.id.clone();
            let mut row = div().flex().items_center().gap(px(8.));
            if field.kind == "OTP" {
                match Totp::parse(value.expose()) {
                    Ok(totp) => {
                        let (code, left) = totp.now();
                        let shown =
                            format!("{} {}", &code[..code.len() / 2], &code[code.len() / 2..]);
                        let copy_code = code.clone();
                        row = row
                            .child(
                                div()
                                    .flex_1()
                                    .text_size(px(t.size(1.333)))
                                    .text_color(t.accent)
                                    .font_weight(FontWeight::BOLD)
                                    .child(shown),
                            )
                            .child(
                                div()
                                    .text_color(if left <= 5 { t.danger } else { t.muted })
                                    .child(format!("{left}s")),
                            )
                            .child(self.button(
                                format!("copy-{key}"),
                                "Copy",
                                cx,
                                move |this, _, cx| this.copy("one-time code", &copy_code, cx),
                            ));
                    }
                    Err(_) => {
                        row = row.child(
                            div()
                                .text_color(t.muted)
                                .child("Unsupported one-time password format"),
                        )
                    }
                }
            } else if field.concealed() {
                let shown = if self.revealed.contains_key(&key) {
                    value.expose().to_string()
                } else {
                    "••••••••••••".into()
                };
                let toggle_key = key.clone();
                let copy_value = value.clone();
                let copy_label = label.clone();
                row = row
                    .child(
                        div()
                            .flex_1()
                            .text_color(t.foreground)
                            .overflow_hidden()
                            .truncate()
                            .child(shown),
                    )
                    .child(self.button(
                        format!("reveal-{key}"),
                        if self.revealed.contains_key(&key) {
                            "Hide"
                        } else {
                            "Reveal"
                        },
                        cx,
                        move |this, _, cx| {
                            if this.revealed.remove(&toggle_key).is_none() {
                                this.revealed
                                    .insert(toggle_key.clone(), Instant::now() + REVEAL_FOR);
                            }
                            cx.notify();
                        },
                    ))
                    .child(
                        self.button(format!("copy-{key}"), "Copy", cx, move |this, _, cx| {
                            this.copy(&copy_label, copy_value.expose(), cx)
                        }),
                    );
            } else {
                let copy_value = value.clone();
                let copy_label = label.clone();
                let multiline = field.purpose.as_deref() == Some("NOTES");
                row = row
                    .child(
                        div()
                            .flex_1()
                            .text_color(t.foreground)
                            .when(!multiline, |d| d.truncate())
                            .child(value.expose().to_string()),
                    )
                    .when(!multiline, |d| {
                        d.child(self.button(
                            format!("copy-{key}"),
                            "Copy",
                            cx,
                            move |this, _, cx| this.copy(&copy_label, copy_value.expose(), cx),
                        ))
                    });
            }
            fields = fields.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(
                        div()
                            .text_size(px(t.size(0.917)))
                            .text_color(t.muted)
                            .child(label),
                    )
                    .child(row),
            );
        }
        for (i, url) in item.urls.iter().enumerate() {
            let href = url.href.clone();
            let open_href = url.href.clone();
            let safe = href.starts_with("https://") || href.starts_with("http://");
            fields = fields.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(
                        div()
                            .text_size(px(t.size(0.917)))
                            .text_color(t.muted)
                            .child(
                                url.label
                                    .clone()
                                    .filter(|l| !l.is_empty())
                                    .unwrap_or_else(|| "website".into()),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .flex_1()
                                    .text_color(t.accent)
                                    .truncate()
                                    .child(href.clone()),
                            )
                            .when(safe, |d| {
                                d.child(self.button(
                                    format!("open-{i}"),
                                    "Open",
                                    cx,
                                    move |_, _, cx| cx.open_url(&open_href),
                                ))
                            }),
                    ),
            );
        }
        if !item.tags.is_empty() {
            let mut tags = div().flex().flex_wrap().gap(px(6.));
            for tag in &item.tags {
                tags = tags.child(
                    div()
                        .px(px(8.))
                        .py(px(2.))
                        .rounded(px(t.radius))
                        .bg(t.well)
                        .text_color(t.muted)
                        .child(tag.clone()),
                );
            }
            fields = fields.child(tags);
        }

        let edit_item = item.clone();
        let header = div()
            .flex()
            .items_center()
            .gap(px(12.))
            .child(
                div()
                    .text_size(px(t.size(2.0)))
                    .text_color(t.accent)
                    .child(category_glyph(&item.category)),
            )
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(px(t.size(1.333)))
                            .font_weight(FontWeight::BOLD)
                            .child(item.title.clone()),
                    )
                    .child(div().text_color(t.muted).child(format!(
                        "{} · {}",
                        category_name(&item.category).trim_end_matches('s'),
                        item.vault.name
                    ))),
            )
            .child(self.button("edit", "Edit", cx, move |this, w, cx| {
                this.start_editing(edit_item.clone(), w, cx)
            }))
            .child(self.button(
                "archive",
                if self.confirm_archive {
                    "Click again to archive"
                } else {
                    "Archive"
                },
                cx,
                |this, _, cx| this.archive(cx),
            ));

        div()
            .id("detail")
            .flex_1()
            .h_full()
            .overflow_y_scroll()
            .p(px(24.))
            .flex()
            .flex_col()
            .gap(px(20.))
            .child(header)
            .child(div().h(px(1.)).bg(alpha(t.foreground, 0.08)))
            .child(fields)
            .when_some(item.updated_at.clone(), |d, at| {
                d.child(
                    div()
                        .text_size(px(t.size(0.833)))
                        .text_color(t.muted)
                        .child(format!(
                            "Last edited {}",
                            at.replace('T', " ").trim_end_matches('Z')
                        )),
                )
            })
            .into_any_element()
    }

    fn render_agents(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let list = |v: &Value, k: &str| {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        let mut grants = div().flex().flex_col().gap(px(8.));
        if self.grants.is_empty() {
            grants = grants.child(
                div()
                    .text_color(t.muted)
                    .child("No standing grants. Agents ask each time."),
            );
        }
        for grant in &self.grants {
            let id = s(grant, "id");
            let scope = [list(grant, "refs"), list(grant, "vaults")]
                .into_iter()
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            grants = grants.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .p(px(10.))
                    .rounded(px(t.radius))
                    .bg(t.well)
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(div().child(format!(
                                "{} · {}",
                                s(grant, "agent"),
                                list(grant, "operations")
                            )))
                            .child(
                                div()
                                    .text_color(t.muted)
                                    .truncate()
                                    .child(s(grant, "project")),
                            )
                            .child(div().text_color(t.muted).truncate().child(scope))
                            .child(
                                div()
                                    .text_size(px(t.size(0.833)))
                                    .text_color(t.muted)
                                    .child(format!("expires {}", s(grant, "expires"))),
                            ),
                    )
                    .child(self.button(
                        format!("revoke-{id}"),
                        "Revoke",
                        cx,
                        move |this, _, cx| this.revoke(id.clone(), cx),
                    )),
            );
        }
        let mut log = div().flex().flex_col();
        for entry in &self.log {
            let outcome = s(entry, "outcome");
            let refs = list(entry, "refs");
            let what = if refs.is_empty() {
                s(entry, "detail")
            } else {
                refs
            };
            log = log.child(
                div()
                    .flex()
                    .gap(px(12.))
                    .py(px(4.))
                    .border_b_1()
                    .border_color(alpha(t.foreground, 0.06))
                    .child(
                        div().w(px(150.)).text_color(t.muted).child(
                            s(entry, "at")
                                .replace('T', " ")
                                .trim_end_matches('Z')
                                .to_string(),
                        ),
                    )
                    .child(div().w(px(120.)).truncate().child(s(entry, "agent")))
                    .child(
                        div()
                            .w(px(80.))
                            .text_color(t.muted)
                            .child(s(entry, "request")),
                    )
                    .child(div().flex_1().truncate().child(what))
                    .child(
                        div()
                            .w(px(70.))
                            .text_color(if outcome == "ok" { t.muted } else { t.danger })
                            .child(if outcome == "ok" {
                                "ok".to_string()
                            } else {
                                "failed".to_string()
                            }),
                    ),
            );
        }
        div()
            .id("agents")
            .flex_1()
            .h_full()
            .overflow_y_scroll()
            .p(px(24.))
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(
                div()
                    .text_size(px(t.size(1.333)))
                    .font_weight(FontWeight::BOLD)
                    .child("Agents"),
            )
            .child(div().text_color(t.muted).child(
                "What you have approved, and what agents have asked for. Values are never logged.",
            ))
            .child(
                div()
                    .text_color(t.muted)
                    .text_size(px(t.size(0.917)))
                    .child("STANDING GRANTS"),
            )
            .child(grants)
            .child(
                div()
                    .text_color(t.muted)
                    .text_size(px(t.size(0.917)))
                    .child("RECENT REQUESTS"),
            )
            .child(log)
    }
}

impl Render for VisiPassApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let slow = self
            .busy_since
            .is_some_and(|since| since.elapsed() > SLOW_CALL);
        div()
            .size_full()
            .key_context("VisiPassApp")
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                let focus = this.search.read(cx).focus_handle(cx);
                window.focus(&focus, cx);
            }))
            .on_action(
                cx.listener(|this, _: &NewItem, window, cx| this.new_item("LOGIN", window, cx)),
            )
            .on_action(cx.listener(|this, _: &CloseEditor, _, cx| {
                this.editor = None;
                cx.notify();
            }))
            .flex()
            .flex_col()
            .bg(t.background)
            .text_color(t.foreground)
            .font_family(SharedString::from(t.font_family.clone()))
            .text_size(px(t.size(1.0)))
            .child(
                div()
                    .flex_1()
                    .flex()
                    .overflow_hidden()
                    .child(self.render_sidebar(cx))
                    .child(self.render_list(cx))
                    .child(self.render_detail(cx)),
            )
            .when(slow || self.error.is_some() || self.toast.is_some(), |d| {
                let (text, color) = match (&self.error, slow, &self.toast) {
                    (Some(e), _, _) => (e.clone(), t.danger),
                    (None, true, _) => (
                        "Waiting for 1Password… approve its prompt if one is showing.".into(),
                        t.muted,
                    ),
                    (None, false, Some((toast, _))) => (toast.clone(), t.accent),
                    _ => (String::new(), t.muted),
                };
                d.child(
                    div()
                        .px(px(14.))
                        .py(px(6.))
                        .border_t_1()
                        .border_color(alpha(t.foreground, 0.08))
                        .bg(t.well)
                        .text_color(color)
                        .child(text),
                )
            })
    }
}
