//! Creating and editing an item, with the password generator.

use crate::app::{category_glyph, category_name};
use gpui::prelude::FluentBuilder;
use gpui::{
    Context, Entity, EventEmitter, Focusable, FontWeight, IntoElement, Render, SharedString,
    Window, div, prelude::*, px,
};
use vp_core::generate::{Recipe, entropy, generate};
use vp_core::model::{Field, Item, UrlEntry, VaultRef};
use vp_core::secret::Secret;
use vp_gui::text_input::{InputEvent, TextInput};
use vp_gui::theme::{Theme, alpha};

pub enum EditorEvent {
    Save(Box<Item>),
    Cancel,
}

struct FieldRow {
    field: Field,
    /// Only custom fields have an editable label.
    label: Option<Entity<TextInput>>,
    value: Entity<TextInput>,
    /// Multi-line text the single-line editor would flatten: shown, kept as is.
    preserved: Option<Secret>,
}

pub struct ItemEditor {
    theme: Theme,
    original: Item,
    vaults: Vec<VaultRef>,
    vault: usize,
    title: Entity<TextInput>,
    website: Entity<TextInput>,
    tags: Entity<TextInput>,
    rows: Vec<FieldRow>,
    recipe: Recipe,
    error: Option<String>,
    added: usize,
}

impl EventEmitter<EditorEvent> for ItemEditor {}

impl ItemEditor {
    pub fn new(
        theme: Theme,
        item: Item,
        vaults: Vec<VaultRef>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let input = |placeholder: &str, text: String, cx: &mut Context<Self>| {
            let entity = cx.new(|cx| {
                let mut input = TextInput::new(theme.clone(), placeholder.to_string(), cx);
                input.set_text(text, cx);
                input
            });
            cx.subscribe(&entity, |_, _, event: &InputEvent, cx| {
                if *event == InputEvent::Cancel {
                    cx.emit(EditorEvent::Cancel);
                }
            })
            .detach();
            entity
        };
        let title = input("Title", item.title.clone(), cx);
        let website = input(
            "https://example.com",
            item.urls
                .first()
                .map(|u| u.href.clone())
                .unwrap_or_default(),
            cx,
        );
        let tags = input("tags, separated by commas", item.tags.join(", "), cx);
        let mut rows = Vec::new();
        for field in &item.fields {
            let text = field
                .value
                .as_ref()
                .map(|v| v.expose().to_string())
                .unwrap_or_default();
            let preserved = text.contains('\n').then(|| Secret::new(text.clone()));
            let value = input(
                &field.display_label(),
                if preserved.is_some() {
                    String::new()
                } else {
                    text
                },
                cx,
            );
            if field.concealed() {
                value.update(cx, |v, cx| v.set_masked(true, cx));
            }
            let custom = !matches!(
                field.purpose.as_deref(),
                Some("USERNAME" | "PASSWORD" | "NOTES")
            ) && !matches!(
                field.id.as_str(),
                "credential" | "username" | "password" | "notesPlain"
            );
            let label = custom.then(|| input("label", field.label.clone().unwrap_or_default(), cx));
            rows.push(FieldRow {
                field: field.clone(),
                label,
                value,
                preserved,
            });
        }
        let vault = vaults
            .iter()
            .position(|v| v.id == item.vault.id)
            .unwrap_or(0);
        window.focus(&title.read(cx).focus_handle(cx), cx);
        Self {
            theme,
            original: item,
            vaults,
            vault,
            title,
            website,
            tags,
            rows,
            recipe: Recipe::default(),
            error: None,
            added: 0,
        }
    }

    fn is_new(&self) -> bool {
        self.original.id.is_empty()
    }

    fn generate_into(&mut self, row: usize, cx: &mut Context<Self>) {
        match generate(&self.recipe) {
            Ok(password) => {
                self.rows[row]
                    .value
                    .update(cx, |v, cx| v.set_text(password.expose().to_string(), cx));
                self.error = None;
            }
            Err(e) => self.error = Some(e.0),
        }
        cx.notify();
    }

    fn add_field(&mut self, concealed: bool, cx: &mut Context<Self>) {
        self.added += 1;
        let theme = self.theme.clone();
        let label = cx.new(|cx| TextInput::new(theme.clone(), "label", cx));
        let value = cx.new(|cx| {
            let mut input = TextInput::new(theme.clone(), "value", cx);
            input.set_masked(concealed, cx);
            input
        });
        self.rows.push(FieldRow {
            field: Field {
                id: format!("custom{}", self.added),
                label: None,
                kind: if concealed {
                    "CONCEALED".into()
                } else {
                    "STRING".into()
                },
                purpose: None,
                section: None,
                value: None,
                reference: None,
            },
            label: Some(label),
            value,
            preserved: None,
        });
        cx.notify();
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let title = self.title.read(cx).text().trim().to_string();
        if title.is_empty() {
            self.error = Some("Give the item a title".into());
            cx.notify();
            return;
        }
        let mut item = self.original.clone();
        item.title = title;
        if self.is_new()
            && let Some(vault) = self.vaults.get(self.vault)
        {
            item.vault = vault.clone();
        }
        let website = self.website.read(cx).text().trim().to_string();
        let rest: Vec<UrlEntry> = item.urls.iter().skip(1).cloned().collect();
        item.urls = if website.is_empty() {
            rest
        } else {
            std::iter::once(UrlEntry {
                href: website,
                label: None,
                primary: true,
            })
            .chain(rest)
            .collect()
        };
        item.tags = self
            .tags
            .read(cx)
            .text()
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        item.fields = self
            .rows
            .iter()
            .filter_map(|row| {
                let mut field = row.field.clone();
                if let Some(label) = &row.label {
                    let label = label.read(cx).text().trim().to_string();
                    // A new custom field left blank is dropped rather than saved empty.
                    if label.is_empty()
                        && row.value.read(cx).text().is_empty()
                        && field.value.is_none()
                    {
                        return None;
                    }
                    field.label = Some(if label.is_empty() {
                        field.id.clone()
                    } else {
                        label
                    });
                }
                field.value = Some(match &row.preserved {
                    Some(original) => original.clone(),
                    None => Secret::new(row.value.read(cx).text().to_string()),
                });
                Some(field)
            })
            .collect();
        cx.emit(EditorEvent::Save(Box::new(item)));
    }

    fn chip(
        &self,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
        selected: bool,
        cx: &mut Context<Self>,
        on: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        let t = &self.theme;
        let c = &t.controls;
        div()
            .id(gpui::ElementId::Name(id.into()))
            .px(px(10.))
            .py(px(4.))
            .rounded(px(t.radius))
            .border_1()
            .border_color(if selected {
                t.accent
            } else {
                alpha(c.color, c.border_alpha)
            })
            .bg(alpha(
                c.color,
                if selected {
                    c.selected_fill_alpha
                } else {
                    c.fill_alpha
                },
            ))
            .text_color(if selected { t.accent } else { t.foreground })
            .cursor_pointer()
            .hover(|s| s.bg(alpha(c.color, c.hover_fill_alpha)))
            .on_click(cx.listener(move |this, _, _, cx| on(this, cx)))
            .child(label.into())
    }

    fn labelled(&self, label: &str, child: impl IntoElement) -> impl IntoElement {
        let t = &self.theme;
        div()
            .flex()
            .flex_col()
            .gap(px(4.))
            .child(
                div()
                    .text_size(px(t.size(0.917)))
                    .text_color(t.muted)
                    .child(label.to_string()),
            )
            .child(child)
    }

    fn render_generator(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let (kind, amount, unit) = match &self.recipe {
            Recipe::Random { length, .. } => ("random", *length, "characters"),
            Recipe::Memorable { words, .. } => ("memorable", *words, "words"),
            Recipe::Pin { length } => ("pin", *length, "digits"),
        };
        let step = |this: &mut Self, delta: i64, cx: &mut Context<Self>| {
            let bump = |n: &mut usize, lo: usize, hi: usize| {
                *n = (*n as i64 + delta).clamp(lo as i64, hi as i64) as usize
            };
            match &mut this.recipe {
                Recipe::Random { length, .. } => bump(length, 8, 128),
                Recipe::Memorable { words, .. } => bump(words, 3, 12),
                Recipe::Pin { length } => bump(length, 4, 12),
            }
            cx.notify();
        };
        let symbols = matches!(self.recipe, Recipe::Random { symbols: true, .. });
        div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(12.))
            .rounded(px(t.radius))
            .bg(t.well)
            .child(
                div()
                    .text_size(px(t.size(0.917)))
                    .text_color(t.muted)
                    .child("GENERATOR"),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        self.chip("gen-random", "Random", kind == "random", cx, |this, cx| {
                            this.recipe = Recipe::default();
                            cx.notify();
                        }),
                    )
                    .child(self.chip(
                        "gen-memorable",
                        "Memorable",
                        kind == "memorable",
                        cx,
                        |this, cx| {
                            this.recipe = Recipe::Memorable {
                                words: 4,
                                separator: "-".into(),
                                capitalize: true,
                                number: true,
                            };
                            cx.notify();
                        },
                    ))
                    .child(self.chip("gen-pin", "PIN", kind == "pin", cx, |this, cx| {
                        this.recipe = Recipe::Pin { length: 6 };
                        cx.notify();
                    }))
                    .child(div().w(px(12.)))
                    .child(self.chip("gen-less", "−", false, cx, move |this, cx| {
                        step(this, -1, cx)
                    }))
                    .child(div().px(px(6.)).child(format!("{amount} {unit}")))
                    .child(self.chip("gen-more", "+", false, cx, move |this, cx| {
                        step(this, 1, cx)
                    }))
                    .when(kind == "random", |d| {
                        d.child(
                            self.chip("gen-symbols", "Symbols", symbols, cx, |this, cx| {
                                if let Recipe::Random { symbols, .. } = &mut this.recipe {
                                    *symbols = !*symbols;
                                }
                                cx.notify();
                            }),
                        )
                    }),
            )
            .child(
                div()
                    .text_size(px(t.size(0.917)))
                    .text_color(t.muted)
                    .child(format!(
                        "About {:.0} bits of entropy",
                        entropy(&self.recipe)
                    )),
            )
    }
}

impl Render for ItemEditor {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let heading = if self.is_new() {
            format!(
                "New {}",
                category_name(&self.original.category)
                    .trim_end_matches('s')
                    .to_lowercase()
            )
        } else {
            format!("Edit {}", self.original.title)
        };
        let has_secret = self.rows.iter().any(|r| r.field.concealed());

        let mut vaults = div().flex().flex_wrap().gap(px(6.));
        if self.is_new() {
            for (i, vault) in self.vaults.iter().enumerate() {
                vaults = vaults.child(self.chip(
                    format!("vault-{i}"),
                    vault.name.clone(),
                    i == self.vault,
                    cx,
                    move |this, cx| {
                        this.vault = i;
                        cx.notify();
                    },
                ));
            }
        } else {
            vaults = vaults.child(
                div()
                    .text_color(t.muted)
                    .child(self.original.vault.name.clone()),
            );
        }

        let mut fields = div().flex().flex_col().gap(px(12.));
        for (index, row) in self.rows.iter().enumerate() {
            let label = row.field.display_label();
            let concealed = row.field.concealed();
            let masked = row.value.read(cx).masked();
            let body = if let Some(preserved) = &row.preserved {
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .child(
                        div()
                            .p(px(8.))
                            .rounded(px(t.radius))
                            .bg(t.well)
                            .text_color(t.foreground)
                            .child(preserved.expose().to_string()),
                    )
                    .child(
                        div()
                            .text_size(px(t.size(0.833)))
                            .text_color(t.muted)
                            .child("Multi-line text is kept as is. Edit it in 1Password."),
                    )
            } else {
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .when_some(row.label.clone(), |d, label| {
                        d.child(div().w(px(160.)).child(label))
                    })
                    .child(div().flex_1().child(row.value.clone()))
                    .when(concealed, |d| {
                        let value = row.value.clone();
                        d.child(self.chip(
                            format!("show-{index}"),
                            if masked { "Show" } else { "Hide" },
                            false,
                            cx,
                            move |_, cx| {
                                value.update(cx, |v, cx| {
                                    let masked = v.masked();
                                    v.set_masked(!masked, cx)
                                });
                            },
                        ))
                        .child(self.chip(
                            format!("gen-{index}"),
                            "Generate",
                            false,
                            cx,
                            move |this, cx| this.generate_into(index, cx),
                        ))
                    })
            };
            fields = fields.child(self.labelled(&label, body));
        }

        div()
            .id("editor")
            .key_context(crate::keymap::EDITOR)
            .on_action(cx.listener(|this, _: &crate::keymap::actions::SaveItem, _, cx| this.save(cx)))
            .on_action(cx.listener(|this, _: &crate::keymap::actions::GeneratePassword, _, cx| {
                if let Some(row) = this.rows.iter().position(|r| r.field.concealed() && r.preserved.is_none()) {
                    this.generate_into(row, cx);
                }
            }))
            .size_full()
            .overflow_y_scroll()
            .p(px(24.))
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(
                        div()
                            .text_size(px(t.size(2.0)))
                            .text_color(t.accent)
                            .child(category_glyph(&self.original.category)),
                    )
                    .child(
                        div()
                            .text_size(px(t.size(1.333)))
                            .font_weight(FontWeight::BOLD)
                            .child(heading),
                    ),
            )
            .child(self.labelled("Title", self.title.clone()))
            .child(self.labelled("Vault", vaults))
            .when(self.original.category != "SECURE_NOTE", |d| {
                d.child(self.labelled("Website", self.website.clone()))
            })
            .child(fields)
            .child(
                div()
                    .flex()
                    .gap(px(6.))
                    .child(
                        self.chip("add-text", "+ Text field", false, cx, |this, cx| {
                            this.add_field(false, cx)
                        }),
                    )
                    .child(
                        self.chip("add-hidden", "+ Hidden field", false, cx, |this, cx| {
                            this.add_field(true, cx)
                        }),
                    ),
            )
            .child(self.labelled("Tags", self.tags.clone()))
            .when(has_secret, |d| d.child(self.render_generator(cx)))
            .when_some(self.error.clone(), |d, e| {
                d.child(div().text_color(t.danger).child(e))
            })
            .child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(self.chip("save", "Save", true, cx, |this, cx| this.save(cx)))
                    .child(self.chip("cancel", "Cancel", false, cx, |_, cx| {
                        cx.emit(EditorEvent::Cancel)
                    })),
            )
            .child(
                div()
                    .text_size(px(t.size(0.833)))
                    .text_color(t.muted)
                    .child("Ctrl+S saves, Ctrl+G generates, Esc cancels. Every save is read back from 1Password and compared before it counts."),
            )
    }
}
