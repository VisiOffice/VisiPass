//! The main window: sidebar, searchable item list, item detail.

use crate::client::Client;
use crate::editor::{EditorEvent, ItemEditor};
use crate::keymap::{Keymap, SHORTCUTS, actions::*, pretty};
use gpui::prelude::FluentBuilder;
use gpui::{
    Context, Entity, FocusHandle, Focusable, FontWeight, IntoElement, Render, ScrollStrategy,
    SharedString, UniformListScrollHandle, Window, deferred, div, prelude::*, px, uniform_list,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vp_core::dedupe::Group;
use vp_core::ipc::{ItemKey, Merge, Request};
use vp_core::model::{Item, ItemSummary, Scope, VaultRef, kind};
use vp_core::secret::Secret;
use vp_core::totp::Totp;
use vp_gui::text_input::{InputEvent, TextInput};
use vp_gui::theme::{Theme, alpha};

const CLIPBOARD_CLEAR: Duration = Duration::from_secs(90);
const REVEAL_FOR: Duration = Duration::from_secs(30);
const SLOW_CALL: Duration = Duration::from_millis(1500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    Favorites,
    Vault(String),
    Agents,
    Duplicates,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Menu {
    Category,
    New,
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
    category: Option<String>,
    cursor: Option<usize>,
    scroll: UniformListScrollHandle,
    menu: Option<Menu>,
    show_help: bool,
    keymap: Rc<Keymap>,
    open_generation: u64,
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
    /// Duplicate logins, once loaded; the item chosen to keep in each group
    /// (by site and username), and groups the human said are not duplicates.
    duplicates: Option<Vec<Group>>,
    keep: HashMap<String, String>,
    not_duplicates: HashSet<String>,
    duplicates_shown: usize,
}

const DUPLICATES_PAGE: usize = 40;

fn group_key(group: &Group) -> String {
    format!("{}\u{0}{}", group.site, group.username)
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
        keymap: Rc<Keymap>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search = cx.new(|cx| {
            TextInput::new(
                theme.clone(),
                "Search · \"exact\" url: user: tag: vault: type:",
                cx,
            )
        });
        cx.subscribe(&search, |this, input, event: &InputEvent, cx| match event {
            InputEvent::Changed => {
                this.query = input.read(cx).text().to_lowercase();
                this.apply_filter();
                cx.notify();
            }
            InputEvent::Submit => this.open_cursor(cx),
            InputEvent::Cancel => {
                // Esc: close a menu first, then clear the search to start over.
                if this.menu.is_some() {
                    this.menu = None;
                } else if !input.read(cx).text().is_empty() {
                    input.update(cx, |input, cx| input.set_text("", cx));
                }
                cx.notify();
            }
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
            category: None,
            cursor: None,
            scroll: UniformListScrollHandle::new(),
            menu: None,
            show_help: false,
            keymap,
            open_generation: 0,
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
            duplicates: None,
            keep: HashMap::new(),
            not_duplicates: HashSet::new(),
            duplicates_shown: DUPLICATES_PAGE,
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
        let mut scored: Vec<(u32, usize)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| match &self.filter {
                Filter::All | Filter::Agents | Filter::Duplicates => true,
                Filter::Favorites => item.favorite,
                Filter::Vault(v) => &item.vault.id == v,
            })
            .filter(|(_, item)| self.category.as_ref().is_none_or(|c| &item.category == c))
            .filter_map(|(i, item)| vp_core::find::rank(&self.query, item).map(|score| (score, i)))
            .collect();
        // Best match first; the item list is already alphabetical for ties.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        self.visible = scored.into_iter().map(|(_, i)| i).collect();
        self.cursor = (!self.visible.is_empty()).then_some(0);
        self.scroll.scroll_to_item(0, ScrollStrategy::Top);
    }

    fn move_cursor(&mut self, delta: isize, cx: &mut Context<Self>) {
        if self.visible.is_empty() {
            return;
        }
        let last = self.visible.len() as isize - 1;
        let next = (self.cursor.map(|c| c as isize).unwrap_or(-1) + delta).clamp(0, last) as usize;
        self.cursor = Some(next);
        self.scroll.scroll_to_item(next, ScrollStrategy::Nearest);
        // Each open is a vault call, so wait until the arrow keys come to rest.
        self.open_generation += 1;
        let generation = self.open_generation;
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(220))
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.open_generation == generation {
                    this.open_cursor(cx);
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn open_cursor(&mut self, cx: &mut Context<Self>) {
        if let Some(summary) = self
            .cursor
            .and_then(|c| self.visible.get(c))
            .map(|&i| self.items[i].clone())
            && (self.selected.as_deref() != Some(summary.id.as_str()) || self.detail.is_none())
        {
            self.open(summary, cx);
        }
    }

    /// The value of the open item's field with this purpose (or id).
    fn field_value(&self, purpose: &str, id: &str) -> Option<String> {
        let item = self.detail.as_ref()?;
        item.fields
            .iter()
            .find(|f| f.purpose.as_deref() == Some(purpose) || f.id == id)
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_string())
            .filter(|v| !v.is_empty())
    }

    fn copy_username(&mut self, cx: &mut Context<Self>) {
        match self.field_value("USERNAME", "username") {
            Some(v) => self.copy("username", &v, false, cx),
            None => self.note("This item has no username", cx),
        }
    }

    fn copy_password(&mut self, cx: &mut Context<Self>) {
        let value = self
            .field_value("PASSWORD", "password")
            .or_else(|| self.field_value("", "credential"));
        match value {
            Some(v) => self.copy("password", &v, true, cx),
            None => self.note("This item has no password", cx),
        }
    }

    fn copy_code(&mut self, cx: &mut Context<Self>) {
        let code = self.detail.as_ref().and_then(|item| {
            item.fields
                .iter()
                .filter(|f| f.kind == "OTP")
                .find_map(|f| Totp::parse(f.value.as_ref()?.expose()).ok())
                .map(|t| t.now().0)
        });
        match code {
            Some(code) => self.copy("one-time code", &code, true, cx),
            None => self.note("This item has no one-time code", cx),
        }
    }

    fn toggle_reveal(&mut self, cx: &mut Context<Self>) {
        let key = self.detail.as_ref().and_then(|item| {
            item.fields
                .iter()
                .find(|f| f.concealed())
                .map(|f| f.id.clone())
        });
        if let Some(key) = key {
            if self.revealed.remove(&key).is_none() {
                self.revealed.insert(key, Instant::now() + REVEAL_FOR);
            }
            cx.notify();
        }
    }

    fn open_website(&mut self, cx: &mut Context<Self>) {
        let href = self
            .detail
            .as_ref()
            .and_then(|i| i.urls.first())
            .map(|u| u.href.clone());
        match href.filter(|h| h.starts_with("https://") || h.starts_with("http://")) {
            Some(href) => cx.open_url(&href),
            None => self.note("This item has no website", cx),
        }
    }

    fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some(item) = self.detail.clone() else {
            return;
        };
        let favorite = !item.favorite;
        let id = item.id.clone();
        self.request(
            Request::SetFavorite {
                id: item.id,
                vault: item.vault.id,
                favorite,
            },
            cx,
            move |this, _, cx| {
                if let Some(detail) = this.detail.as_mut().filter(|d| d.id == id) {
                    detail.favorite = favorite;
                }
                if let Some(summary) = this.items.iter_mut().find(|s| s.id == id) {
                    summary.favorite = favorite;
                }
                this.apply_filter();
                this.note(
                    if favorite {
                        "Added to Favorites."
                    } else {
                        "Removed from Favorites."
                    },
                    cx,
                );
            },
        );
    }

    fn note(&mut self, text: &str, cx: &mut Context<Self>) {
        self.toast = Some((text.to_string(), Instant::now() + Duration::from_secs(3)));
        cx.notify();
    }

    fn set_filter(&mut self, filter: Filter, cx: &mut Context<Self>) {
        if filter == Filter::Agents {
            self.load_agents(cx);
        }
        if filter == Filter::Duplicates {
            self.load_duplicates(cx);
        }
        self.filter = filter;
        self.menu = None;
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
            vp_gui::clipboard::clear_if_still(value.expose(), cx);
            self.copied = None;
        }
        cx.notify();
    }

    /// Secrets are hidden from clipboard history and cleared after 90 seconds.
    fn copy(&mut self, label: &str, value: &str, secret: bool, cx: &mut Context<Self>) {
        vp_gui::clipboard::copy(value, secret, cx);
        let message = if secret {
            self.copied = Some((
                Secret::new(value.to_string()),
                Instant::now() + CLIPBOARD_CLEAR,
            ));
            format!("Copied {label}. Kept out of clipboard history; clears in 90 seconds.")
        } else {
            format!("Copied {label}.")
        };
        self.toast = Some((message, Instant::now() + Duration::from_secs(4)));
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

    fn load_duplicates(&mut self, cx: &mut Context<Self>) {
        self.request(
            Request::Duplicates {
                scope: Scope::default(),
            },
            cx,
            |this, value, _| {
                let groups: Vec<Group> =
                    serde_json::from_value(value["groups"].clone()).unwrap_or_default();
                this.keep.retain(|key, id| {
                    groups
                        .iter()
                        .any(|g| &group_key(g) == key && g.items.iter().any(|m| &m.id == id))
                });
                this.duplicates = Some(groups);
            },
        );
    }

    /// The groups still to review, in order.
    fn open_groups(&self) -> Vec<&Group> {
        self.duplicates
            .iter()
            .flatten()
            .filter(|g| !self.not_duplicates.contains(&group_key(g)))
            .collect()
    }

    fn kept_in<'a>(&'a self, group: &'a Group) -> Option<&'a vp_core::dedupe::Member> {
        let chosen = self.keep.get(&group_key(group));
        group
            .items
            .iter()
            .find(|m| Some(&m.id) == chosen)
            .or_else(|| group.items.iter().find(|m| m.suggested))
    }

    fn merge_for(&self, group: &Group) -> Option<Merge> {
        let keep = self.kept_in(group)?;
        let key = |m: &vp_core::dedupe::Member| ItemKey {
            id: m.id.clone(),
            vault: m.vault.id.clone(),
        };
        Some(Merge {
            keep: key(keep),
            archive: group
                .items
                .iter()
                .filter(|m| m.id != keep.id)
                .map(key)
                .collect(),
        })
    }

    /// Keeps the chosen login of each group, copies over what only the others
    /// have, and archives the others.
    fn merge(&mut self, merges: Vec<Merge>, cx: &mut Context<Self>) {
        if merges.is_empty() {
            return;
        }
        self.request(Request::MergeItems { merges }, cx, |this, value, cx| {
            let n = |k: &str| value[k].as_u64().unwrap_or(0);
            let added = &value["added"];
            let copied: u64 = ["passwords", "urls", "codes", "notes", "fields"]
                .iter()
                .map(|k| added[*k].as_u64().unwrap_or(0))
                .sum();
            this.toast = Some((
                format!(
                    "Kept {}, archived {}{}.",
                    n("kept"),
                    n("archived"),
                    if copied > 0 {
                        format!(", copied {copied} passwords, websites, codes, notes or fields")
                    } else {
                        String::new()
                    }
                ),
                Instant::now() + Duration::from_secs(6),
            ));
            this.reload(cx);
            this.load_duplicates(cx);
        });
    }

    fn open_from_duplicates(&mut self, id: &str, cx: &mut Context<Self>) {
        let Some(summary) = self.items.iter().find(|i| i.id == id).cloned() else {
            return;
        };
        self.search.update(cx, |input, cx| input.set_text("", cx));
        self.query.clear();
        self.set_filter(Filter::All, cx);
        if let Some(row) = self.visible.iter().position(|&i| self.items[i].id == id) {
            self.cursor = Some(row);
            self.scroll.scroll_to_item(row, ScrollStrategy::Center);
        }
        self.open(summary, cx);
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
                        gpui::svg()
                            .path(vp_gui::assets::MARK)
                            .size(px(t.size(1.5)))
                            .text_color(t.accent),
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
            });
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
                "nav-duplicates".into(),
                "\u{f0c5}",
                "Duplicates".into(),
                self.duplicates.as_ref().map(|_| self.open_groups().len()),
                Filter::Duplicates,
                cx,
            ))
            .child(self.nav_row(
                "nav-agents".into(),
                "\u{f06a9}",
                "Agents".into(),
                None,
                Filter::Agents,
                cx,
            ))
    }

    fn render_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let count = self.visible.len();
        let category_label = match &self.category {
            Some(c) => format!("{} ▾", category_name(c)),
            None => "All categories ▾".to_string(),
        };
        let header = div()
            .p(px(10.))
            .flex()
            .flex_col()
            .gap(px(8.))
            .child(self.search.clone())
            .child(
                div()
                    .flex()
                    .gap(px(6.))
                    .child(
                        self.button("category-menu", category_label, cx, |this, _, cx| {
                            this.toggle_menu(Menu::Category, cx)
                        }),
                    )
                    .child(div().flex_1())
                    .child(self.button("new-menu", "+ New ▾", cx, |this, _, cx| {
                        this.toggle_menu(Menu::New, cx)
                    })),
            )
            .child(
                div()
                    .text_size(px(t.size(0.833)))
                    .text_color(t.muted)
                    .child(format!("{count} item{}", if count == 1 { "" } else { "s" })),
            );
        div()
            .w(px(330.))
            .h_full()
            .flex()
            .flex_col()
            .relative()
            .border_r_1()
            .border_color(alpha(t.foreground, 0.08))
            .child(header)
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
                .track_scroll(&self.scroll)
                .flex_1(),
            )
            .when_some(self.menu, |d, menu| d.child(self.render_menu(menu, cx)))
    }

    fn toggle_menu(&mut self, menu: Menu, cx: &mut Context<Self>) {
        self.menu = if self.menu == Some(menu) {
            None
        } else {
            Some(menu)
        };
        cx.notify();
    }

    fn render_menu(&self, menu: Menu, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let entry =
            |id: String, glyph: &'static str, label: String, count: Option<usize>, chosen: bool| {
                div()
                    .id(gpui::ElementId::Name(id.into()))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .px(px(10.))
                    .py(px(4.))
                    .cursor_pointer()
                    .text_color(if chosen { t.accent } else { t.foreground })
                    .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
                    .child(
                        div()
                            .w(px(16.))
                            .text_color(if chosen { t.accent } else { t.muted })
                            .child(glyph),
                    )
                    .child(div().flex_1().child(label))
                    .when_some(count, |d, n| {
                        d.child(div().text_color(t.muted).child(n.to_string()))
                    })
            };
        let mut list = div().flex().flex_col().py(px(4.));
        match menu {
            Menu::Category => {
                // Counts within the current sidebar view, ignoring the category itself.
                let mut counts: Vec<(String, usize)> = Vec::new();
                for item in self.items.iter().filter(|item| match &self.filter {
                    Filter::All | Filter::Agents | Filter::Duplicates => true,
                    Filter::Favorites => item.favorite,
                    Filter::Vault(v) => &item.vault.id == v,
                }) {
                    match counts.iter_mut().find(|(c, _)| c == &item.category) {
                        Some((_, n)) => *n += 1,
                        None => counts.push((item.category.clone(), 1)),
                    }
                }
                counts.sort_by_key(|(c, _)| category_name(c));
                list = list.child(
                    entry(
                        "cat-all".into(),
                        "\u{f03a}",
                        "All categories".into(),
                        None,
                        self.category.is_none(),
                    )
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.category = None;
                        this.menu = None;
                        this.apply_filter();
                        cx.notify();
                    })),
                );
                for (category, n) in counts {
                    let chosen = self.category.as_deref() == Some(category.as_str());
                    let pick = category.clone();
                    list = list.child(
                        entry(
                            format!("cat-{category}"),
                            category_glyph(&category),
                            category_name(&category),
                            Some(n),
                            chosen,
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.category = Some(pick.clone());
                            this.menu = None;
                            this.apply_filter();
                            cx.notify();
                        })),
                    );
                }
            }
            Menu::New => {
                for (category, label) in [
                    ("LOGIN", "Login"),
                    ("PASSWORD", "Password"),
                    ("API_CREDENTIAL", "API credential"),
                    ("SECURE_NOTE", "Secure note"),
                ] {
                    list = list.child(
                        entry(
                            format!("new-{category}"),
                            category_glyph(category),
                            label.into(),
                            None,
                            false,
                        )
                        .on_click(cx.listener(
                            move |this, _, window, cx| {
                                this.menu = None;
                                this.new_item(category, window, cx);
                            },
                        )),
                    );
                }
            }
        }
        deferred(
            div()
                .id("menu")
                .absolute()
                .top(px(84.))
                .when(menu == Menu::Category, |d| d.left(px(10.)))
                .when(menu == Menu::New, |d| d.right(px(10.)))
                .w(px(240.))
                .max_h(px(420.))
                .overflow_y_scroll()
                .occlude()
                .bg(t.background)
                .border_1()
                .border_color(t.border)
                .rounded(px(t.radius))
                .shadow_lg()
                .child(list),
        )
        .with_priority(1)
    }

    fn render_row(
        &self,
        row: usize,
        item: ItemSummary,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = &self.theme;
        let selected = self.selected.as_deref() == Some(item.id.as_str());
        let cursor = self.cursor == Some(row);
        let detail = item
            .additional_information
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| item.urls.first().map(|u| host(&u.href)));
        let subtitle = match detail {
            Some(detail) => format!("{} · {detail}", item.vault.name),
            None => item.vault.name.clone(),
        };
        let open = item.clone();
        div()
            .id(("row", row))
            .w_full()
            .flex()
            .items_center()
            .gap(px(10.))
            .px(px(12.))
            .py(px(6.))
            .cursor_pointer()
            .border_l_2()
            .border_color(if cursor {
                t.accent
            } else {
                gpui::transparent_black().into()
            })
            .when(selected || cursor, |d| {
                d.bg(alpha(t.foreground, t.controls.selected_fill_alpha * 0.6))
            })
            .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.cursor = Some(row);
                this.open(open.clone(), cx)
            }))
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

    fn render_help(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let mut groups = div().flex().gap(px(28.));
        let mut current: Option<&str> = None;
        let mut column = div().flex().flex_col().gap(px(5.));
        for (shortcut, keys) in SHORTCUTS.iter().zip(&self.keymap.keys) {
            if current != Some(shortcut.group) {
                if current.is_some() {
                    groups = groups.child(column);
                    column = div().flex().flex_col().gap(px(5.));
                }
                current = Some(shortcut.group);
                column = column.child(
                    div()
                        .pb(px(2.))
                        .text_size(px(t.size(0.833)))
                        .text_color(t.muted)
                        .child(shortcut.group.to_uppercase()),
                );
            }
            let shown = if keys.is_empty() {
                "—".to_string()
            } else {
                keys.iter()
                    .map(|k| pretty(k))
                    .collect::<Vec<_>>()
                    .join("  ")
            };
            column = column.child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().w(px(150.)).text_color(t.accent).child(shown))
                    .child(div().text_color(t.foreground).child(shortcut.description)),
            );
        }
        groups = groups.child(column);
        let mut card = div()
            .id("help")
            .occlude()
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(14.))
            .bg(t.background)
            .border_2()
            .border_color(t.border)
            .rounded(px(t.radius))
            .child(
                div()
                    .text_size(px(t.size(1.167)))
                    .font_weight(FontWeight::BOLD)
                    .child("Keyboard shortcuts"),
            )
            .child(groups)
            .child(
                div()
                    .text_size(px(t.size(0.917)))
                    .text_color(t.muted)
                    .child(format!(
                        "Change them in {} (restart to apply). Esc closes.",
                        self.keymap.path.display()
                    )),
            );
        for warning in &self.keymap.warnings {
            card = card.child(div().text_color(t.danger).child(warning.clone()));
        }
        deferred(
            div()
                .id("help-scrim")
                .absolute()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(t.scrim)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.show_help = false;
                    cx.notify();
                }))
                .child(card),
        )
        .with_priority(2)
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
                                move |this, _, cx| this.copy("one-time code", &copy_code, true, cx),
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
                            this.copy(&copy_label, copy_value.expose(), true, cx)
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
                            move |this, _, cx| {
                                this.copy(&copy_label, copy_value.expose(), false, cx)
                            },
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
            .child(self.button(
                "favorite",
                if item.favorite {
                    "\u{f005} Favorite"
                } else {
                    "\u{f006} Favorite"
                },
                cx,
                |this, _, cx| this.toggle_favorite(cx),
            ))
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

    fn render_duplicates(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let heading = |text: String| {
            div()
                .text_color(t.muted)
                .text_size(px(t.size(0.917)))
                .child(text)
        };
        let mut page = div()
            .id("duplicates")
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
                    .child("Duplicates"),
            )
            .child(div().text_color(t.muted).child(
                "Logins saved more than once for the same site and username. Keeping one copies \
                 onto it what only the others have (websites, two-factor codes, notes, fields, and \
                 a password that differs, as \"other password\"), then archives the others. \
                 Passwords are compared, never shown here.",
            ));
        let Some(_) = &self.duplicates else {
            return page.child(div().text_color(t.muted).child("Looking for duplicates…"));
        };
        let groups = self.open_groups();
        if groups.is_empty() {
            return page.child(div().text_color(t.muted).child("No duplicate logins."));
        }
        let exact: Vec<Merge> = groups
            .iter()
            .filter(|g| g.same_password)
            .filter_map(|g| self.merge_for(g))
            .collect();
        let different = groups.iter().filter(|g| !g.same_password).count();
        page = page.child(
            div()
                .flex()
                .items_center()
                .gap(px(12.))
                .child(div().flex_1().child(format!(
                    "{} exact copies (same password) · {} with different passwords",
                    exact.len(),
                    different
                )))
                .when(!exact.is_empty(), |d| {
                    let label = format!("Merge all {} exact copies", exact.len());
                    d.child(self.button("merge-exact", label, cx, move |this, _, cx| {
                        this.merge(exact.clone(), cx)
                    }))
                }),
        );
        let mut last_kind = None;
        for group in groups.iter().take(self.duplicates_shown) {
            if last_kind != Some(group.same_password) {
                last_kind = Some(group.same_password);
                page = page.child(heading(if group.same_password {
                    "SAME PASSWORD · keeping one loses nothing".into()
                } else {
                    "DIFFERENT PASSWORDS · choose the one that is current; open them to compare"
                        .into()
                }));
            }
            page = page.child(self.render_group(group, cx));
        }
        if groups.len() > self.duplicates_shown {
            let more = groups.len() - self.duplicates_shown;
            page = page.child(self.button(
                "duplicates-more",
                format!("Show more ({more} left)"),
                cx,
                |this, _, cx| {
                    this.duplicates_shown += DUPLICATES_PAGE;
                    cx.notify();
                },
            ));
        }
        page
    }

    fn render_group(&self, group: &Group, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let key = group_key(group);
        let kept = self.kept_in(group).map(|m| m.id.clone());
        let mut rows = div().flex().flex_col().gap(px(2.));
        for member in &group.items {
            let chosen = kept.as_deref() == Some(member.id.as_str());
            let mut facts = Vec::new();
            if let Some(p) = &member.password {
                facts.push(format!("password {p}"));
            }
            if member.codes > 0 {
                facts.push("2FA".into());
            }
            if member.notes {
                facts.push("notes".into());
            }
            if member.fields > 0 {
                facts.push(format!("+{} fields", member.fields));
            }
            if member.urls.len() > 1 {
                facts.push(format!("{} websites", member.urls.len()));
            }
            if let Some(at) = &member.updated_at {
                facts.push(format!("edited {}", at.get(..10).unwrap_or(at)));
            }
            let (pick_key, pick_id) = (key.clone(), member.id.clone());
            let open_id = member.id.clone();
            rows = rows.child(
                div()
                    .id(gpui::ElementId::Name(format!("dup-{}", member.id).into()))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .px(px(8.))
                    .py(px(6.))
                    .rounded(px(t.radius))
                    .cursor_pointer()
                    .when(chosen, |d| {
                        d.bg(alpha(t.accent, t.controls.selected_fill_alpha * 0.5))
                    })
                    .hover(|s| s.bg(alpha(t.foreground, t.controls.hover_fill_alpha)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.keep.insert(pick_key.clone(), pick_id.clone());
                        cx.notify();
                    }))
                    .child(
                        div()
                            .w(px(64.))
                            .text_color(if chosen { t.accent } else { t.muted })
                            .child(if chosen { "● Keep" } else { "○ Archive" }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .min_w(px(0.))
                            .child(
                                div()
                                    .truncate()
                                    .child(format!("{}  ·  {}", member.title, member.vault.name)),
                            )
                            .child(
                                div()
                                    .text_size(px(t.size(0.917)))
                                    .text_color(t.muted)
                                    .truncate()
                                    .child(facts.join(" · ")),
                            ),
                    )
                    .child(self.button(
                        format!("dup-open-{}", member.id),
                        "Open",
                        cx,
                        move |this, _, cx| this.open_from_duplicates(&open_id, cx),
                    )),
            );
        }
        let merge = self.merge_for(group);
        let others = group.items.len().saturating_sub(1);
        let skip_key = key.clone();
        div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .p(px(10.))
            .rounded(px(t.radius))
            .bg(t.well)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .font_weight(FontWeight::BOLD)
                            .truncate()
                            .child(if group.username.is_empty() {
                                group.site.clone()
                            } else {
                                format!("{} · {}", group.site, group.username)
                            }),
                    )
                    .child(self.button(
                        format!("dup-skip-{key}"),
                        "Not duplicates",
                        cx,
                        move |this, _, cx| {
                            this.not_duplicates.insert(skip_key.clone());
                            cx.notify();
                        },
                    ))
                    .when_some(merge, |d, merge| {
                        d.child(self.button(
                            format!("dup-merge-{key}"),
                            format!(
                                "Keep selected, archive {others} other{}",
                                if others == 1 { "" } else { "s" }
                            ),
                            cx,
                            move |this, _, cx| this.merge(vec![merge.clone()], cx),
                        ))
                    }),
            )
            .child(rows)
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
        let help_key = self
            .keymap
            .keys
            .iter()
            .zip(SHORTCUTS)
            .find(|(_, s)| s.name == "show-help")
            .and_then(|(k, _)| k.first().map(|k| pretty(k)));
        div()
            .size_full()
            .relative()
            .key_context(crate::keymap::APP)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                let focus = this.search.read(cx).focus_handle(cx);
                window.focus(&focus, cx);
            }))
            .on_action(cx.listener(|this, _: &NextItem, _, cx| this.move_cursor(1, cx)))
            .on_action(cx.listener(|this, _: &PreviousItem, _, cx| this.move_cursor(-1, cx)))
            .on_action(cx.listener(|this, _: &OpenItem, _, cx| this.open_cursor(cx)))
            .on_action(
                cx.listener(|this, _: &FilterCategory, _, cx| this.toggle_menu(Menu::Category, cx)),
            )
            .on_action(cx.listener(|this, _: &ShowAll, _, cx| this.set_filter(Filter::All, cx)))
            .on_action(
                cx.listener(|this, _: &ShowFavorites, _, cx| {
                    this.set_filter(Filter::Favorites, cx)
                }),
            )
            .on_action(
                cx.listener(|this, _: &ShowAgents, _, cx| this.set_filter(Filter::Agents, cx)),
            )
            .on_action(cx.listener(|this, _: &ShowHelp, _, cx| {
                this.show_help = !this.show_help;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &CopyUsername, _, cx| this.copy_username(cx)))
            .on_action(cx.listener(|this, _: &CopyPassword, _, cx| this.copy_password(cx)))
            .on_action(cx.listener(|this, _: &CopyOneTimeCode, _, cx| this.copy_code(cx)))
            .on_action(cx.listener(|this, _: &RevealPassword, _, cx| this.toggle_reveal(cx)))
            .on_action(cx.listener(|this, _: &OpenWebsite, _, cx| this.open_website(cx)))
            .on_action(cx.listener(|this, _: &EditItem, window, cx| {
                if let Some(item) = this.detail.clone() {
                    this.start_editing(item, window, cx);
                }
            }))
            .on_action(
                cx.listener(|this, _: &NewItem, window, cx| this.new_item("LOGIN", window, cx)),
            )
            .on_action(cx.listener(|this, _: &ToggleFavorite, _, cx| this.toggle_favorite(cx)))
            .on_action(cx.listener(|this, _: &Dismiss, _, cx| {
                if this.show_help {
                    this.show_help = false;
                } else if this.menu.is_some() {
                    this.menu = None;
                } else {
                    this.editor = None;
                }
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
                    .when(self.filter == Filter::Duplicates, |d| {
                        d.child(self.render_duplicates(cx))
                    })
                    .when(self.filter != Filter::Duplicates, |d| {
                        d.child(self.render_list(cx)).child(self.render_detail(cx))
                    }),
            )
            .child({
                let (text, color) = match (&self.error, slow, &self.toast) {
                    (Some(e), _, _) => (e.clone(), t.danger),
                    (None, true, _) => (
                        "Waiting for 1Password… approve its prompt if one is showing.".into(),
                        t.muted,
                    ),
                    (None, false, Some((toast, _))) => (toast.clone(), t.accent),
                    _ => (String::new(), t.muted),
                };
                div()
                    .flex()
                    .items_center()
                    .px(px(14.))
                    .py(px(4.))
                    .border_t_1()
                    .border_color(alpha(t.foreground, 0.08))
                    .bg(t.well)
                    .text_size(px(t.size(0.917)))
                    .child(div().flex_1().text_color(color).truncate().child(text))
                    .when_some(help_key, |d, key| {
                        d.child(
                            div()
                                .id("help-hint")
                                .cursor_pointer()
                                .text_color(t.muted)
                                .hover(|s| s.text_color(t.accent))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.show_help = true;
                                    cx.notify();
                                }))
                                .child(format!("{key} Shortcuts")),
                        )
                    })
            })
            .when(self.show_help, |d| d.child(self.render_help(cx)))
    }
}
