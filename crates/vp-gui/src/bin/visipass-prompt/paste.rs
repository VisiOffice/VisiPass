//! The paste window: a human adds a secret an agent asked for (`vp request`),
//! types the master password (unlock, `vp init`), or reads the new Secret Key.
//!
//! What is typed is written, as one JSON line, to stdout: a pipe only visipassd
//! holds. It never passes through the agent's shell, clipboard history or
//! transcript. Esc, closing or a crash cancel.

use gpui::prelude::FluentBuilder;
use gpui::{
    Context, Entity, FocusHandle, FontWeight, IntoElement, Render, SharedString, Window, div,
    prelude::*, px,
};
use std::io::Write;
use std::time::{Duration, Instant};
use vp_core::ipc::{ApprovalPrompt, PasteAnswer, PasteMode};
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
    /// Tab stops after the field: Show, Save, Cancel.
    stops: [FocusHandle; 3],
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
        let placeholder = match prompt.paste.as_ref().map(|p| &p.mode) {
            Some(PasteMode::Unlock { .. }) | Some(PasteMode::NewPassword { .. }) => {
                "Master password"
            }
            Some(PasteMode::SecretKey) => "Secret Key (VP1-…)",
            _ => "Paste the secret here (Ctrl+V)",
        };
        let field = cx.new(|cx| {
            let mut input = TextInput::new(theme.clone(), placeholder, cx);
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
        let show_key = matches!(
            prompt.paste.as_ref().map(|p| &p.mode),
            Some(PasteMode::ShowKey { .. })
        );
        let stops = [cx.focus_handle(), cx.focus_handle(), cx.focus_handle()];
        if show_key {
            // No field to type in: start on Done.
            window.focus(&stops[1], cx);
        }
        Self {
            prompt,
            theme,
            overlay,
            field,
            focus: cx.focus_handle(),
            stops,
            opened: now,
            deadline: now + timeout,
            answered: false,
        }
    }

    fn armed(&self) -> bool {
        self.opened.elapsed() >= ARM_DELAY
    }

    fn mode(&self) -> PasteMode {
        self.prompt
            .paste
            .as_ref()
            .map(|p| p.mode.clone())
            .unwrap_or_default()
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        if matches!(self.mode(), PasteMode::ShowKey { .. }) {
            return self.finish(PasteAnswer::Cancel, cx);
        }
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

    /// Which tab stop has focus: 0 the field, 1 Show, 2 Save, 3 Cancel.
    fn focused_stop(&self, window: &Window, cx: &Context<Self>) -> usize {
        if gpui::Focusable::focus_handle(self.field.read(cx), cx).is_focused(window) {
            return 0;
        }
        self.stops
            .iter()
            .position(|h| h.is_focused(window))
            .map(|i| i + 1)
            .unwrap_or(0)
    }

    fn activate(&mut self, stop: usize, cx: &mut Context<Self>) {
        match stop {
            1 => self.toggle_or_copy(cx),
            2 => self.save(cx),
            3 => self.finish(PasteAnswer::Cancel, cx),
            _ => {}
        }
    }

    fn on_key(&mut self, event: &gpui::KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let current = self.focused_stop(window, cx);
        match event.keystroke.key.as_str() {
            "tab" => {
                let next = if event.keystroke.modifiers.shift {
                    (current + 3) % 4
                } else {
                    (current + 1) % 4
                };
                if next == 0 {
                    let field = gpui::Focusable::focus_handle(self.field.read(cx), cx);
                    window.focus(&field, cx);
                } else {
                    window.focus(&self.stops[next - 1], cx);
                }
                cx.stop_propagation();
                cx.notify();
            }
            "enter" | "space" if current > 0 => {
                self.activate(current, cx);
                cx.stop_propagation();
            }
            "escape" => self.finish(PasteAnswer::Cancel, cx),
            _ => {}
        }
    }

    /// The first button: Show/Hide for a typed value, Copy for the Secret Key.
    fn toggle_or_copy(&mut self, cx: &mut Context<Self>) {
        if let PasteMode::ShowKey { key } = self.mode() {
            vp_gui::clipboard::copy(key.expose(), true, cx);
        } else {
            self.field.update(cx, |f, cx| {
                let masked = f.masked();
                f.set_masked(!masked, cx)
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn button(
        &self,
        id: &'static str,
        label: &'static str,
        primary: bool,
        stop: usize,
        focused: bool,
        cx: &mut Context<Self>,
        on: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        let t = &self.theme;
        let c = &t.controls;
        let armed = self.armed();
        div()
            .id(id)
            .track_focus(&self.stops[stop - 1])
            .when(focused, |d| d.border_2().text_color(t.accent))
            .px(px(14.))
            .py(px(6.))
            .rounded(px(t.radius))
            .border_1()
            .border_color(if primary || focused {
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
            .when(focused, |d| d.bg(alpha(t.accent, 0.18)))
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
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let spec = self.prompt.paste.clone().unwrap_or_default();
        let (instruction, ok_label) = spec.instruction();
        let mode = spec.mode.clone();
        let heading = match &mode {
            PasteMode::Secret => format!("{} asks you to add a secret.", self.prompt.who),
            PasteMode::Unlock {
                purpose: Some(_), ..
            } => "Confirm it's you".to_string(),
            PasteMode::Unlock { .. } => "Unlock VisiPass".to_string(),
            PasteMode::NewPassword { .. } => "Create your VisiPass vault".to_string(),
            PasteMode::ShowKey { .. } => "Your Secret Key".to_string(),
            PasteMode::SecretKey => "Open your vault on this device".to_string(),
        };
        let highlight = if matches!(mode, PasteMode::Secret) {
            self.prompt.who.len()
        } else {
            0
        };
        let focused = self.focused_stop(window, cx);
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
                            gpui::StyledText::new(heading)
                            .with_highlights([(
                                0..highlight,
                                gpui::HighlightStyle {
                                    color: Some(t.accent.into()),
                                    font_weight: Some(FontWeight::BOLD),
                                    ..Default::default()
                                },
                            )]),
                        ),
                    ),
            )
            .child(
                div()
                    .text_color(t.muted)
                    .child(match &mode {
                        PasteMode::Secret => "Paste the value to save it in your vault. The agent gets a reference to it, never the value itself.".to_string(),
                        _ => instruction.clone(),
                    }),
            )
            .child(details)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .when(matches!(mode, PasteMode::Secret), |d| {
                        d.child(label(&format!(
                            "Saved as \"{}\" in the vault \"{}\"",
                            spec.title, spec.vault
                        )))
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().flex_1().child(match &mode {
                                PasteMode::ShowKey { key } => div()
                                    .px(px(10.))
                                    .py(px(8.))
                                    .rounded(px(t.radius))
                                    .bg(alpha(t.foreground, 0.06))
                                    .text_size(px(t.size(1.25)))
                                    .text_color(t.accent)
                                    .child(key.expose().to_string())
                                    .into_any_element(),
                                _ => self.field.clone().into_any_element(),
                            }))
                            .child(self.button(
                                "show",
                                match (&mode, masked) {
                                    (PasteMode::ShowKey { .. }, _) => "Copy",
                                    (_, true) => "Show",
                                    (_, false) => "Hide",
                                },
                                false,
                                1,
                                focused == 1,
                                cx,
                                |this, cx| this.toggle_or_copy(cx),
                            )),
                    ),
            )
            .child(div().h(px(1.)).bg(alpha(t.foreground, 0.12)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(self.button("save", match &mode { PasteMode::Secret => "Save to vault", _ => ok_label }, true, 2, focused == 2, cx, |this, cx| this.save(cx)))
                    .child(self.button("cancel", "Cancel", false, 3, focused == 3, cx, |this, cx| {
                        this.finish(PasteAnswer::Cancel, cx)
                    }))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(t.size(0.833)))
                            .text_color(t.muted)
                            .child(format!(
                                "Enter: {} · Esc cancels · {}:{:02}",
                                ok_label.to_lowercase(),
                                remaining / 60,
                                remaining % 60
                            )),
                    ),
            )
            .child(
                div()
                    .text_size(px(t.size(0.833)))
                    .text_color(t.muted)
                    .child("Tab moves between the field and buttons."),
            );

        div()
            .id("paste")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
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
                        .child(match &mode {
                            PasteMode::Secret => "VisiPass · new secret requested",
                            PasteMode::Unlock { .. } => "VisiPass · locked",
                            _ => "VisiPass · new vault",
                        }),
                )
            })
            .when(!self.overlay, |d| d.bg(t.background))
            .child(card)
    }
}
