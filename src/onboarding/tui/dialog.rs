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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExitDialogAction {
    Stay,
    KeepEditing,
    Discard,
    Save,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitChoice {
    KeepEditing,
    Discard,
    Save,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExitDialog {
    selected: ExitChoice,
}

impl ExitDialog {
    pub(super) fn new() -> Self {
        Self {
            selected: ExitChoice::KeepEditing,
        }
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> ExitDialogAction {
        match code {
            KeyCode::Left | KeyCode::BackTab => {
                self.selected = match self.selected {
                    ExitChoice::KeepEditing => ExitChoice::Save,
                    ExitChoice::Discard => ExitChoice::KeepEditing,
                    ExitChoice::Save => ExitChoice::Discard,
                };
                ExitDialogAction::Stay
            }
            KeyCode::Right | KeyCode::Tab => {
                self.selected = match self.selected {
                    ExitChoice::KeepEditing => ExitChoice::Discard,
                    ExitChoice::Discard => ExitChoice::Save,
                    ExitChoice::Save => ExitChoice::KeepEditing,
                };
                ExitDialogAction::Stay
            }
            KeyCode::Char('d' | 'D') => ExitDialogAction::Discard,
            KeyCode::Char('s' | 'S') => ExitDialogAction::Save,
            KeyCode::Esc => ExitDialogAction::KeepEditing,
            KeyCode::Enter | KeyCode::Char(' ') => match self.selected {
                ExitChoice::KeepEditing => ExitDialogAction::KeepEditing,
                ExitChoice::Discard => ExitDialogAction::Discard,
                ExitChoice::Save => ExitDialogAction::Save,
            },
            _ => ExitDialogAction::Stay,
        }
    }

    pub(super) fn render(&self, frame: &mut Frame, use_color: bool) {
        let outer = frame.area();
        let width =
            outer.width.saturating_sub(4).clamp(30, 76).min(outer.width);
        let height = 11
            .min(outer.height.saturating_sub(2))
            .max(8)
            .min(outer.height);
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
        let safe = if use_color {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };
        let choice_style = |choice, base: Style| {
            if self.selected == choice {
                base.patch(selected)
            } else {
                base
            }
        };
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("Your access changes have not been saved."),
                Line::from("Save them, discard them, or keep editing."),
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        " Keep editing ",
                        choice_style(ExitChoice::KeepEditing, Style::default()),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        " Discard & quit ",
                        choice_style(ExitChoice::Discard, danger),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        " Save changes ",
                        choice_style(ExitChoice::Save, safe),
                    ),
                ]),
                Line::from(""),
                Line::from(
                    "←/→ or Tab choose  •  Enter select  •  Esc keep editing",
                ),
            ])
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(" Unsaved changes ")
                    .borders(Borders::ALL),
            ),
            area,
        );
    }

    #[cfg(test)]
    fn selected(&self) -> ExitChoice {
        self.selected
    }
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

    #[test]
    fn unsaved_exit_defaults_to_keep_editing_and_requires_explicit_discard() {
        let mut dialog = ExitDialog::new();
        assert_eq!(dialog.selected(), ExitChoice::KeepEditing);
        assert_eq!(
            dialog.handle_key(KeyCode::Enter),
            ExitDialogAction::KeepEditing
        );

        let mut dialog = ExitDialog::new();
        assert_eq!(dialog.handle_key(KeyCode::Tab), ExitDialogAction::Stay);
        assert_eq!(dialog.selected(), ExitChoice::Discard);
        assert_eq!(
            dialog.handle_key(KeyCode::Enter),
            ExitDialogAction::Discard
        );
    }

    #[test]
    fn unsaved_exit_supports_direct_save_shortcut() {
        let mut dialog = ExitDialog::new();
        assert_eq!(
            dialog.handle_key(KeyCode::Char('s')),
            ExitDialogAction::Save
        );
        assert_eq!(
            dialog.handle_key(KeyCode::Esc),
            ExitDialogAction::KeepEditing
        );
    }
}
