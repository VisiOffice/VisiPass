//! The approval card.
//!
//! Safety rules for this window:
//! - Deny is the default: it starts selected, and Escape denies.
//! - Nothing is accepted for the first moments after it opens, so a keystroke
//!   the human was already typing cannot answer it.
//! - The answer goes to stdout, a pipe only visipassd holds.

use gpui::prelude::FluentBuilder;
use gpui::{
    Context, FocusHandle, FontWeight, IntoElement, KeyDownEvent, Render, SharedString, Window, div,
    prelude::*, px,
};
use std::io::Write;
use std::time::{Duration, Instant};
use vp_core::ipc::{Answer, ApprovalPrompt};
use vp_gui::theme::{Theme, alpha};

const ARM_DELAY: Duration = Duration::from_millis(700);

struct Choice {
    answer: Answer,
    label: &'static str,
    key: &'static str,
}

const CHOICES: [Choice; 5] = [
    Choice {
        answer: Answer::Deny,
        label: "Deny",
        key: "d",
    },
    Choice {
        answer: Answer::Once,
        label: "Once",
        key: "o",
    },
    Choice {
        answer: Answer::Task,
        label: "This task",
        key: "t",
    },
    Choice {
        answer: Answer::Hours,
        label: "8 hours",
        key: "h",
    },
    Choice {
        answer: Answer::Always,
        label: "Always",
        key: "a",
    },
];

pub struct ApprovalView {
    prompt: ApprovalPrompt,
    theme: Theme,
    /// True for the full-screen layer-shell overlay, false in a plain window.
    overlay: bool,
    focus: FocusHandle,
    selected: usize,
    opened: Instant,
    deadline: Instant,
    answered: bool,
}

/// `op://Private/Stripe/password` -> ("Stripe", "password", "Private").
fn describe_ref(reference: &str) -> (String, String, String) {
    let path = reference
        .split_once("://")
        .map(|(_, p)| p)
        .unwrap_or(reference);
    let path = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        [vault, item, rest @ ..] if !rest.is_empty() => {
            (item.to_string(), rest.join(" › "), vault.to_string())
        }
        _ => (reference.to_string(), String::new(), String::new()),
    }
}

/// The references by item, in the order each item first appears: (item, vault, fields).
fn group_refs(references: &[String]) -> Vec<(String, String, Vec<String>)> {
    let mut groups: Vec<(String, String, Vec<String>)> = Vec::new();
    for reference in references {
        let (item, field, vault) = describe_ref(reference);
        match groups
            .iter_mut()
            .find(|(i, v, _)| *i == item && *v == vault)
        {
            Some((_, _, fields)) => fields.push(field),
            None => groups.push((item, vault, vec![field])),
        }
    }
    groups
}

/// Past this the list scrolls, so the buttons stay on screen.
const SECRETS_MAX_HEIGHT: f32 = 260.;

impl ApprovalView {
    pub fn new(
        prompt: ApprovalPrompt,
        theme: Theme,
        overlay: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let timeout = Duration::from_secs(prompt.timeout_secs.max(5));
        // Redraw for the countdown and the arming delay; answer on timeout.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                let alive = this.update(cx, |view, cx| {
                    if Instant::now() >= view.deadline {
                        view.answer(Answer::Timeout, cx);
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
            focus: cx.focus_handle(),
            selected: 0,
            opened: now,
            deadline: now + timeout,
            answered: false,
        }
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus
    }

    fn armed(&self) -> bool {
        self.opened.elapsed() >= ARM_DELAY
    }

    fn answer(&mut self, answer: Answer, cx: &mut Context<Self>) {
        if self.answered || (answer != Answer::Timeout && !self.armed()) {
            return;
        }
        self.answered = true;
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", answer.word()).and_then(|_| stdout.flush());
        cx.quit();
    }

    fn on_key(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        let shift = event.keystroke.modifiers.shift;
        match key {
            "escape" => self.answer(Answer::Deny, cx),
            "enter" => self.answer(CHOICES[self.selected].answer, cx),
            "left" => self.selected = self.selected.saturating_sub(1),
            "right" => self.selected = (self.selected + 1).min(CHOICES.len() - 1),
            "tab" if shift => self.selected = (self.selected + CHOICES.len() - 1) % CHOICES.len(),
            "tab" => self.selected = (self.selected + 1) % CHOICES.len(),
            _ => {
                if let Some(choice) = CHOICES.iter().find(|c| c.key == key) {
                    self.answer(choice.answer, cx);
                }
            }
        }
        cx.notify();
    }

    fn explain(&self, answer: Answer) -> String {
        let who = &self.prompt.who;
        match answer {
            Answer::Deny => "Refuse. The agent is told not to retry.".into(),
            Answer::Once => "Allow this one request.".into(),
            Answer::Task => format!("Allow until this {who} session ends."),
            Answer::Hours => format!("Allow {who} in this project for 8 hours."),
            Answer::Always => format!("Allow {who} in this project until you revoke it."),
            Answer::Timeout => String::new(),
        }
    }

    fn label(&self, text: &str) -> impl IntoElement {
        let t = &self.theme;
        div()
            .text_size(px(t.size(0.917)))
            .text_color(t.muted)
            .child(text.to_string())
    }

    fn button(&self, index: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let c = &t.controls;
        let choice = &CHOICES[index];
        let selected = index == self.selected;
        let armed = self.armed();
        let text = if choice.answer == Answer::Deny {
            t.danger
        } else {
            t.foreground
        };
        let fill = if selected {
            c.selected_fill_alpha
        } else {
            c.fill_alpha
        };
        let border = if selected {
            alpha(t.accent, 1.0)
        } else {
            alpha(c.color, c.border_alpha)
        };
        let answer = choice.answer;
        div()
            .id(("choice", index))
            .flex_1()
            .flex()
            .items_center()
            .justify_center()
            .gap(px(6.))
            .py(px(7.))
            .px(px(8.))
            .rounded(px(t.radius))
            .border_1()
            .border_color(border)
            .bg(alpha(c.color, fill))
            .when(!armed, |d| d.opacity(0.45))
            .when(armed, |d| {
                d.cursor_pointer()
                    .hover(|s| {
                        s.bg(alpha(c.color, c.hover_fill_alpha.max(fill)))
                            .border_color(if selected {
                                border
                            } else {
                                alpha(c.color, c.hover_border_alpha)
                            })
                    })
                    .active(|s| s.bg(alpha(c.color, c.pressed_fill_alpha)))
            })
            .on_click(cx.listener(move |view, _, _, cx| view.answer(answer, cx)))
            .on_hover(cx.listener(move |view, hovered: &bool, _, cx| {
                if *hovered {
                    view.selected = index;
                    cx.notify();
                }
            }))
            .child(div().text_color(t.accent).child(choice.key))
            .child(div().text_color(text).child(choice.label))
    }

    /// One item: its fields beside it, or wrapped underneath when there are several.
    fn secret_group(&self, item: &str, vault: &str, fields: &[String]) -> impl IntoElement {
        let t = &self.theme;
        let fields: Vec<&str> = fields
            .iter()
            .map(String::as_str)
            .filter(|f| !f.is_empty())
            .collect();
        let several = fields.len() > 1;
        let top = div()
            .flex()
            .items_baseline()
            .gap(px(8.))
            .child(
                div()
                    .text_color(t.foreground)
                    .font_weight(FontWeight::MEDIUM)
                    .child(item.to_string()),
            )
            .when(fields.len() == 1, |d| {
                d.child(div().text_color(t.muted).child(fields[0].to_string()))
            })
            .when(several, |d| {
                d.child(
                    div()
                        .text_size(px(t.size(0.917)))
                        .text_color(t.muted)
                        .child(format!("{} fields", fields.len())),
                )
            })
            .child(div().flex_1())
            .when(!vault.is_empty(), |d| {
                d.child(
                    div()
                        .text_size(px(t.size(0.917)))
                        .text_color(t.muted)
                        .child(vault.to_string()),
                )
            });
        div()
            .flex()
            .flex_col()
            .gap(px(2.))
            .child(top)
            .when(several, |d| {
                d.child(
                    div()
                        .text_size(px(t.size(0.917)))
                        .text_color(t.muted)
                        .child(fields.join(" · ")),
                )
            })
    }
}

impl Render for ApprovalView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = self.theme.clone();
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let body = px(t.size(1.0));
        let family: SharedString = t.font_family.clone().into();

        let mut details = div().flex().flex_col().gap(px(10.));
        for (label, value) in &self.prompt.details {
            let is_command = label == "Command" || label == "File";
            details = details.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(self.label(label))
                    .child(
                        div()
                            .text_color(t.foreground)
                            .when(is_command, |d| {
                                d.bg(t.well).px(px(8.)).py(px(6.)).rounded(px(t.radius))
                            })
                            .child(value.clone()),
                    ),
            );
        }
        if !self.prompt.secrets.is_empty() {
            let mut rows = div()
                .id("secrets")
                .flex()
                .flex_col()
                .gap(px(6.))
                .max_h(px(SECRETS_MAX_HEIGHT))
                .overflow_y_scroll();
            for (item, vault, fields) in group_refs(&self.prompt.secrets) {
                rows = rows.child(self.secret_group(&item, &vault, &fields));
            }
            let count = self.prompt.secrets.len();
            let heading = if count == 1 {
                "Secret".to_string()
            } else {
                format!("{count} secrets")
            };
            details = details.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(self.label(&heading))
                    .child(rows),
            );
        }
        if let Some(purpose) = &self.prompt.purpose {
            details = details.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(self.label("Purpose, in the agent's words"))
                    .child(
                        div()
                            .text_color(t.foreground)
                            .italic()
                            .child(format!("“{purpose}”")),
                    ),
            );
        }

        let mut buttons = div().flex().gap(px(8.));
        for index in 0..CHOICES.len() {
            buttons = buttons.child(self.button(index, cx));
        }

        let header = div()
            .flex()
            .items_start()
            .gap(px(12.))
            .child(
                div().text_size(px(t.size(1.5))).text_color(t.accent).child(
                    gpui::svg()
                        .path(vp_gui::assets::MARK)
                        .flex_none()
                        .size(px(t.size(1.5)))
                        .mt(px(2.))
                        .text_color(t.accent),
                ),
            )
            .child(
                div()
                    .flex_1()
                    .text_size(px(t.size(1.167)))
                    .text_color(t.foreground)
                    .child(
                        div().child(
                            gpui::StyledText::new(format!(
                                "{} wants to {}.",
                                self.prompt.who, self.prompt.action
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
            );

        let footer = div()
            .flex()
            .justify_between()
            .text_size(px(t.size(0.833)))
            .text_color(t.muted)
            .child(self.explain(CHOICES[self.selected].answer))
            .child(format!(
                "Esc denies · {}:{:02}",
                remaining / 60,
                remaining % 60
            ));

        let card = div()
            .w(px(540.))
            .max_w_full()
            .flex()
            .flex_col()
            .gap(px(16.))
            .p(px(18.))
            .bg(t.background)
            .border_2()
            .border_color(t.border)
            .rounded(px(t.radius))
            .child(header)
            .child(details)
            .child(div().h(px(1.)).bg(alpha(t.foreground, 0.12)))
            .child(buttons)
            .child(footer);

        let chip = div()
            .px(px(12.))
            .py(px(5.))
            .bg(t.background)
            .rounded(px(t.radius))
            .text_size(px(t.size(0.917)))
            .text_color(t.foreground)
            .child("VisiPass · approval needed");

        div()
            .id("approval")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap(px(10.))
            .font_family(family)
            .text_size(body)
            .when(self.overlay, |d| d.bg(t.scrim).child(chip))
            .when(!self.overlay, |d| d.bg(t.background))
            .child(card)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_references() {
        assert_eq!(
            describe_ref("op://Private/Stripe/password"),
            ("Stripe".into(), "password".into(), "Private".into())
        );
        assert_eq!(
            describe_ref("op://Work/Server/admin/password?attribute=otp"),
            ("Server".into(), "admin › password".into(), "Work".into())
        );
    }

    #[test]
    fn groups_references_by_item() {
        let refs: Vec<String> = [
            "op://Quarry Admin/prod/A",
            "op://Private/gateway/TOKEN",
            "op://Quarry Admin/prod/B",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            group_refs(&refs),
            vec![
                (
                    "prod".into(),
                    "Quarry Admin".into(),
                    vec!["A".into(), "B".into()]
                ),
                ("gateway".into(), "Private".into(), vec!["TOKEN".into()]),
            ]
        );
    }
}
