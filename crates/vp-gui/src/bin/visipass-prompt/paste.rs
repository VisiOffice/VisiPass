//! The paste window: a human adds a secret an agent asked for (`vp request`).
//!
//! The secret is typed or pasted here and written, as one JSON line, to stdout:
//! a pipe only visipassd holds. It never passes through the agent's shell,
//! clipboard history or transcript. Esc, closing or a crash cancel.

use gpui::prelude::FluentBuilder;
use gpui::{
    Context, Entity, FocusHandle, FontWeight, IntoElement, Render, SharedString, Window, div,
    prelude::*, px,
};
use std::io::Write;
use std::time::{Duration, Instant};
use vp_core::ipc::{ApprovalPrompt, PasteAnswer};
use vp_core::secret::Secret;
use vp_gui::text_input::{InputEvent, TextInput};
use vp_gui::theme::{Theme, alpha};

const ARM_DELAY: Duration = Duration::from_millis(700);

pub struct PasteView {
    prompt: ApprovalPrompt,
    theme: Theme,
    overlay: bool,
    field: Entity<TextInput>,
    focus: FocusHandle,
    opened: Instant,
    deadline: Instant,
    answered: bool,
}

impl PasteView {
    pub fn new(
        prompt: ApprovalPrompt,
        theme: Theme,
        overlay: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let field = cx.new(|cx| {
            let mut input = TextInput::new(theme.clone(), "Paste the secret here (Ctrl+V)", cx);
            input.set_masked(true, cx);
            input
        });
        cx.subscribe(&field, |this, _, event: &InputEvent, cx| match event {
            InputEvent::Submit => this.save(cx),
            InputEvent::Cancel => this.finish(PasteAnswer::Cancel, cx),
            InputEvent::Changed => cx.notify(),
        })
        .detach();
        let focus = gpui::Focusable::focus_handle(field.read(cx), cx);
        window.focus(&focus, cx);
        let timeout = Duration::from_secs(prompt.timeout_secs.max(5));
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                let alive = this.update(cx, |view, cx| {
                    if Instant::now() >= view.deadline {
                        view.finish(PasteAnswer::Timeout, cx);
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    break;
                }
            }
        })
        .detach();
        let now = Instant::now();
        Self {
            prompt,
            theme,
            overlay,
            field,
            focus: cx.focus_handle(),
            opened: now,
            deadline: now + timeout,
            answered: false,
        }
    }

    fn armed(&self) -> bool {
        self.opened.elapsed() >= ARM_DELAY
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let value = self.field.read(cx).text().to_string();
        if !self.armed() || value.trim().is_empty() {
            return;
        }
        self.finish(
            PasteAnswer::Save {
                value: Secret::new(value),
            },
            cx,
        );
    }

    fn finish(&mut self, answer: PasteAnswer, cx: &mut Context<Self>) {
        if self.answered {
            return;
        }
        self.answered = true;
        if let Ok(line) = serde_json::to_string(&answer) {
            let line = Secret::new(line);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", line.expose()).and_then(|_| stdout.flush());
        }
        cx.quit();
    }

    fn button(
        &self,
        id: &'static str,
        label: &'static str,
        primary: bool,
        cx: &mut Context<Self>,
        on: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        let t = &self.theme;
        let c = &t.controls;
        let armed = self.armed();
        div()
            .id(id)
            .px(px(14.))
            .py(px(6.))
            .rounded(px(t.radius))
            .border_1()
            .border_color(if primary {
                t.accent
            } else {
                alpha(c.color, c.border_alpha)
            })
            .bg(alpha(
                c.color,
                if primary {
                    c.selected_fill_alpha
                } else {
                    c.fill_alpha
                },
            ))
            .text_color(if primary { t.accent } else { t.foreground })
            .when(!armed, |d| d.opacity(0.45))
            .when(armed, |d| {
                d.cursor_pointer()
                    .hover(|s| s.bg(alpha(c.color, c.hover_fill_alpha)))
            })
            .on_click(cx.listener(move |this, _, _, cx| on(this, cx)))
            .child(label)
    }
}

impl Render for PasteView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let spec = self.prompt.paste.clone().unwrap_or_default();
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let masked = self.field.read(cx).masked();
        let label = |text: &str| {
            div()
                .text_size(px(t.size(0.917)))
                .text_color(t.muted)
                .child(text.to_string())
        };

        let mut details = div().flex().flex_col().gap(px(10.));
        // The title is shown with the field it names.
        for (name, value) in self.prompt.details.iter().filter(|(n, _)| n != "Title") {
            details = details.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(label(name))
                    .child(div().child(value.clone())),
            );
        }
        if let Some(purpose) = &self.prompt.purpose {
            details = details.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(label("Purpose, in the agent's words"))
                    .child(div().italic().child(format!("“{purpose}”"))),
            );
        }

        let card = div()
            .w(px(560.))
            .max_w_full()
            .flex()
            .flex_col()
            .gap(px(16.))
            .p(px(18.))
            .bg(t.background)
            .border_2()
            .border_color(t.border)
            .rounded(px(t.radius))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap(px(12.))
                    .child(
                        gpui::svg()
                            .path(vp_gui::assets::MARK)
                            .flex_none()
                            .size(px(t.size(1.5)))
                            .mt(px(2.))
                            .text_color(t.accent),
                    )
                    .child(
                        div().flex_1().text_size(px(t.size(1.167))).child(
                            gpui::StyledText::new(format!(
                                "{} asks you to add a secret.",
                                self.prompt.who
                            ))
                            .with_highlights([(
                                0..self.prompt.who.len(),
                                gpui::HighlightStyle {
                                    color: Some(t.accent.into()),
                                    font_weight: Some(FontWeight::BOLD),
                                    ..Default::default()
                                },
                            )]),
                        ),
                    ),
            )
            .child(details)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(label(&format!(
                        "Saved as \"{}\" in the vault \"{}\"",
                        spec.title, spec.vault
                    )))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().flex_1().child(self.field.clone()))
                            .child(self.button(
                                "show",
                                if masked { "Show" } else { "Hide" },
                                false,
                                cx,
                                |this, cx| {
                                    this.field.update(cx, |f, cx| {
                                        let masked = f.masked();
                                        f.set_masked(!masked, cx)
                                    });
                                },
                            )),
                    ),
            )
            .child(div().h(px(1.)).bg(alpha(t.foreground, 0.12)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(self.button("save", "Save to vault", true, cx, |this, cx| this.save(cx)))
                    .child(self.button("cancel", "Cancel", false, cx, |this, cx| {
                        this.finish(PasteAnswer::Cancel, cx)
                    }))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(t.size(0.833)))
                            .text_color(t.muted)
                            .child(format!(
                                "Enter saves · Esc cancels · {}:{:02}",
                                remaining / 60,
                                remaining % 60
                            )),
                    ),
            )
            .child(
                div()
                    .text_size(px(t.size(0.833)))
                    .text_color(t.muted)
                    .child("The agent gets only a reference to this secret, never the value."),
            );

        div()
            .id("paste")
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap(px(10.))
            .font_family(SharedString::from(t.font_family.clone()))
            .text_size(px(t.size(1.0)))
            .text_color(t.foreground)
            .when(self.overlay, |d| {
                d.bg(t.scrim).child(
                    div()
                        .px(px(12.))
                        .py(px(5.))
                        .bg(t.background)
                        .rounded(px(t.radius))
                        .text_size(px(t.size(0.917)))
                        .child("VisiPass · new secret requested"),
                )
            })
            .when(!self.overlay, |d| d.bg(t.background))
            .child(card)
    }
}
