use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DialogAction {
    Stay,
    Cancel,
    Confirm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ConfirmDialog {
    title: String,
    message: String,
    confirm_label: String,
    confirm_selected: bool,
}

impl ConfirmDialog {
    pub(super) fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        confirm_label: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            confirm_label: confirm_label.into(),
            // A repeated Enter must not accidentally cross a security boundary.
            confirm_selected: false,
        }
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> DialogAction {
        match code {
            KeyCode::Left
            | KeyCode::Right
            | KeyCode::Tab
            | KeyCode::BackTab => {
                self.confirm_selected = !self.confirm_selected;
                DialogAction::Stay
            }
            KeyCode::Enter | KeyCode::Char(' ') if self.confirm_selected => {
                DialogAction::Confirm
            }
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Esc => {
                DialogAction::Cancel
            }
            _ => DialogAction::Stay,
        }
    }

    #[cfg(test)]
    pub(super) fn confirm_selected(&self) -> bool {
        self.confirm_selected
    }

    pub(super) fn render(&self, frame: &mut Frame, use_color: bool) {
        let outer = frame.area();
        let width = outer.width.saturating_sub(8).clamp(44, 76);
        let height = 10.min(outer.height.saturating_sub(4)).max(7);
        let area = Rect::new(
            outer.x + outer.width.saturating_sub(width) / 2,
            outer.y + outer.height.saturating_sub(height) / 2,
            width,
            height,
        );
        let selected =
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
        let danger = if use_color {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };
        let cancel_style = if self.confirm_selected {
            Style::default()
        } else {
            selected
        };
        let confirm_style = if self.confirm_selected {
            selected.patch(danger)
        } else {
            danger
        };
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(self.message.clone()),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Cancel  ", cancel_style),
                    Span::raw("     "),
                    Span::styled(
                        format!("  {}  ", self.confirm_label),
                        confirm_style,
                    ),
                ]),
                Line::from(""),
                Line::from("←/→ or Tab choose  •  Enter select  •  Esc cancel"),
            ])
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(format!(" {} ", self.title))
                    .borders(Borders::ALL)
                    .border_style(danger),
            ),
            area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_choice_is_default_and_requires_navigation_to_confirm() {
        let mut dialog =
            ConfirmDialog::new("Open access?", "Risk", "Enable OPEN");
        assert!(!dialog.confirm_selected());
        assert_eq!(dialog.handle_key(KeyCode::Enter), DialogAction::Cancel);

        let mut dialog =
            ConfirmDialog::new("Open access?", "Risk", "Enable OPEN");
        assert_eq!(dialog.handle_key(KeyCode::Tab), DialogAction::Stay);
        assert!(dialog.confirm_selected());
        assert_eq!(dialog.handle_key(KeyCode::Enter), DialogAction::Confirm);
    }
}
