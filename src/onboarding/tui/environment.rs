use super::dialog::{ConfirmDialog, DialogAction};
use crate::output::escape_control_bytes;
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Wrap,
};
use std::cell::Cell;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    List,
    Search,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Browse,
    Preview {
        name: String,
        disclosure: String,
    },
    ConfirmOpen {
        name: String,
        disclosure: String,
        dialog: ConfirmDialog,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum EnvironmentAction {
    None,
    Prepare(String),
    Approve(String),
    Remove(String),
    Back,
}

pub(super) struct EnvironmentSelector {
    names: Vec<String>,
    approved: BTreeSet<String>,
    selected: usize,
    search: String,
    focus: Focus,
    phase: Phase,
    feedback: String,
    detail_scroll: u16,
    required_detail_scroll: Cell<u16>,
    detail_geometry_ready: Cell<bool>,
}

impl EnvironmentSelector {
    pub(super) fn new(
        mut names: Vec<String>,
        approved: impl IntoIterator<Item = String>,
    ) -> Self {
        names.sort();
        names.dedup();
        Self {
            names,
            approved: approved.into_iter().collect(),
            selected: 0,
            search: String::new(),
            focus: Focus::List,
            phase: Phase::Browse,
            feedback: String::new(),
            detail_scroll: 0,
            required_detail_scroll: Cell::new(0),
            detail_geometry_ready: Cell::new(true),
        }
    }

    pub(super) fn set_error(&mut self, message: String) {
        self.feedback = message;
    }

    pub(super) fn set_preview(&mut self, name: String, disclosure: String) {
        self.detail_scroll = 0;
        self.required_detail_scroll.set(u16::MAX);
        self.detail_geometry_ready.set(false);
        self.phase = Phase::Preview { name, disclosure };
        self.feedback.clear();
    }

    #[cfg(test)]
    pub(super) fn approved_names(&self) -> Vec<String> {
        self.approved.iter().cloned().collect()
    }

    pub(super) fn rollback_approval(&mut self, name: &str) {
        self.approved.remove(name);
    }

    pub(super) fn captures_text_input(&self) -> bool {
        self.focus == Focus::Search
    }

    fn visible_names(&self) -> Vec<&String> {
        let search = self.search.to_ascii_lowercase();
        self.names
            .iter()
            .filter(|name| name.to_ascii_lowercase().contains(&search))
            .collect()
    }

    fn highlighted_name(&self) -> Option<String> {
        self.visible_names()
            .get(self.selected)
            .map(|name| (*name).clone())
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> EnvironmentAction {
        if matches!(
            self.phase,
            Phase::Preview { .. } | Phase::ConfirmOpen { .. }
        ) && self.handle_detail_scroll(code)
        {
            return EnvironmentAction::None;
        }
        let disclosure_reviewed = self.disclosure_reviewed();
        match &mut self.phase {
            Phase::ConfirmOpen {
                name,
                disclosure: _,
                dialog,
            } => match dialog.handle_key(code) {
                DialogAction::Confirm if disclosure_reviewed => {
                    let name = name.clone();
                    self.approved.insert(name.clone());
                    self.phase = Phase::Browse;
                    EnvironmentAction::Approve(name)
                }
                DialogAction::Confirm => {
                    self.feedback = "Review through the final disclosure line before approval.".into();
                    EnvironmentAction::None
                }
                DialogAction::Cancel => {
                    self.detail_scroll = 0;
                    self.required_detail_scroll.set(u16::MAX);
                    self.detail_geometry_ready.set(false);
                    self.phase = Phase::Browse;
                    EnvironmentAction::None
                }
                DialogAction::Stay => EnvironmentAction::None,
            },
            Phase::Preview { name, disclosure } => match code {
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if disclosure_reviewed {
                        self.detail_scroll = 0;
                        self.required_detail_scroll.set(u16::MAX);
                        self.detail_geometry_ready.set(false);
                        self.phase = Phase::ConfirmOpen {
                            name: name.clone(),
                            disclosure: disclosure.clone(),
                            dialog: ConfirmDialog::new(
                                "Share this environment value?",
                                format!(
                                    "{name} will be readable by the jailed process and every child process it starts."
                                ),
                                "Share value (OPEN)",
                            ),
                        };
                    } else {
                        self.feedback =
                            "Review through the final disclosure line before approval.".into();
                    }
                    EnvironmentAction::None
                }
                KeyCode::Esc => {
                    self.phase = Phase::Browse;
                    EnvironmentAction::None
                }
                _ => EnvironmentAction::None,
            },
            Phase::Browse => self.handle_browse_key(code),
        }
    }

    fn handle_detail_scroll(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::PageUp => {
                self.detail_scroll = self.detail_scroll.saturating_sub(8);
                self.feedback.clear();
                true
            }
            KeyCode::PageDown => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_add(8)
                    .min(self.required_detail_scroll.get());
                self.feedback.clear();
                true
            }
            KeyCode::Home => {
                self.detail_scroll = 0;
                self.feedback.clear();
                true
            }
            KeyCode::End => {
                self.detail_scroll = self.required_detail_scroll.get();
                self.feedback.clear();
                true
            }
            _ => false,
        }
    }

    fn disclosure_reviewed(&self) -> bool {
        self.detail_geometry_ready.get()
            && self.detail_scroll >= self.required_detail_scroll.get()
    }

    fn handle_browse_key(&mut self, code: KeyCode) -> EnvironmentAction {
        if self.focus == Focus::Search {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.focus = Focus::List,
                KeyCode::Backspace => {
                    self.search.pop();
                    self.selected = 0;
                }
                KeyCode::Char(value) => {
                    self.search.push(value);
                    self.selected = 0;
                }
                _ => {}
            }
            return EnvironmentAction::None;
        }
        match code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1)
                    .min(self.visible_names().len().saturating_sub(1));
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => {
                self.selected = self.visible_names().len().saturating_sub(1);
            }
            KeyCode::Char('/') => self.focus = Focus::Search,
            KeyCode::Char(' ') | KeyCode::Enter => {
                if let Some(name) = self.highlighted_name() {
                    if self.approved.remove(&name) {
                        return EnvironmentAction::Remove(name);
                    }
                    return EnvironmentAction::Prepare(name);
                }
            }
            KeyCode::Esc => {
                if self.search.is_empty() {
                    return EnvironmentAction::Back;
                }
                self.search.clear();
                self.selected = 0;
            }
            _ => {}
        }
        EnvironmentAction::None
    }
}

pub(super) fn render(
    frame: &mut Frame,
    state: &EnvironmentSelector,
    use_color: bool,
) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(4),
    ])
    .areas(frame.area());
    let [list_area, detail_area] = if body.width >= 92 {
        Layout::horizontal([
            Constraint::Percentage(44),
            Constraint::Percentage(56),
        ])
        .areas(body)
    } else {
        Layout::vertical([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .areas(body)
    };
    let safe_search = escape_control_bytes(&state.search);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Environment variables",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("Names only; values are hidden and never saved."),
            Line::from(match state.focus {
                Focus::Search => format!("Search: {safe_search}█"),
                Focus::List => format!(
                    "Search: {}",
                    if state.search.is_empty() {
                        "none"
                    } else {
                        safe_search.as_str()
                    }
                ),
            }),
        ]),
        header,
    );
    let visible = state.visible_names();
    let items = visible.iter().map(|name| {
        let approved = state.approved.contains(*name);
        let (marker, marker_style) = if approved {
            (
                "✓",
                if use_color {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().add_modifier(Modifier::BOLD)
                },
            )
        } else {
            (
                "○",
                if use_color {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                },
            )
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{marker} "), marker_style),
            Span::raw((*name).clone()),
        ]))
    });
    let selected = if visible.is_empty() {
        None
    } else {
        Some(state.selected.min(visible.len() - 1))
    };
    let mut list_state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Variable names ")
                    .borders(Borders::ALL),
            )
            .highlight_symbol("> ")
            .highlight_style(if use_color {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default()
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD)
            }),
        list_area,
        &mut list_state,
    );
    let detail = match &state.phase {
        Phase::Browse => state.highlighted_name().map_or_else(
            || "No matching variable names.".into(),
            |name| format!(
                "Selected\n{name}\n\nIf approved\nEvery process in the jail can read and copy its current value. The value stays hidden here and is never saved.\n\nSpace/Enter\nReview or remove this variable."
            ),
        ),
        Phase::Preview { name, disclosure } => format!(
            "{name}\n\n{disclosure}\n\nAuthority cannot be verified from a variable name. Review every line, then press Enter to choose."
        ),
        Phase::ConfirmOpen { name, disclosure, .. } => format!(
            "{name}\n\n{disclosure}\n\nOPEN grants the jailed process this host value."
        ),
    };
    let detail_width = detail_area.width.saturating_sub(2).max(1);
    let total = wrapped_line_count(&detail, detail_width);
    let visible_lines = detail_area.height.saturating_sub(2).max(1);
    let max_scroll = total.saturating_sub(visible_lines);
    state.required_detail_scroll.set(max_scroll);
    state.detail_geometry_ready.set(true);
    let scroll = state.detail_scroll.min(max_scroll);
    let last = scroll.saturating_add(visible_lines).min(total);
    frame.render_widget(
        Paragraph::new(detail)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(format!(
                        " Security details • lines {}–{}/{} • PgUp/PgDn ",
                        scroll.saturating_add(1),
                        last,
                        total
                    ))
                    .borders(Borders::ALL),
            ),
        detail_area,
    );
    let help = if state.feedback.is_empty() {
        "↑/↓ move  •  Space/Enter review or remove  •  / search\nEsc clears search or returns  •  values never appear in this screen"
    } else {
        &state.feedback
    };
    frame.render_widget(
        Paragraph::new(help)
            .style(if use_color {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            })
            .block(Block::default().borders(Borders::TOP)),
        footer,
    );
    if let Phase::ConfirmOpen { dialog, .. } = &state.phase {
        dialog.render(frame, use_color);
    }
}

fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| line.chars().count().max(1).div_ceil(width))
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn rendered(state: &EnvironmentSelector) -> String {
        rendered_at(state, 120, 34)
    }

    fn rendered_at(
        state: &EnvironmentSelector,
        width: u16,
        height: u16,
    ) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state, false)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn search_focus_accepts_q_as_text_instead_of_cancelling() {
        let mut state = EnvironmentSelector::new(
            vec!["PATH".into(), "QUERY_TOKEN".into()],
            Vec::<String>::new(),
        );
        state.handle_key(KeyCode::Char('/'));
        state.handle_key(KeyCode::Char('q'));
        assert!(rendered(&state).contains("QUERY_TOKEN"));
        assert!(!rendered(&state).contains("[ ] PATH"));
    }

    #[test]
    fn model_and_rendering_never_need_environment_values() {
        let state = EnvironmentSelector::new(
            vec!["GH_TOKEN".into()],
            vec!["GH_TOKEN".into()],
        );
        let output = rendered(&state);
        assert!(output.contains("GH_TOKEN"));
        assert!(!output.contains("secret-value-that-must-never-appear"));
    }

    #[test]
    fn open_dialog_ignores_text_and_defaults_to_cancel() {
        let mut state = EnvironmentSelector::new(
            vec!["GH_TOKEN".into()],
            Vec::<String>::new(),
        );
        state.set_preview("GH_TOKEN".into(), "Credential authority".into());
        let _ = rendered(&state);
        state.handle_key(KeyCode::Enter);
        let _ = rendered(&state);
        state.handle_key(KeyCode::Char('x'));
        assert_eq!(state.handle_key(KeyCode::Enter), EnvironmentAction::None);
        assert!(state.approved_names().is_empty());
    }

    #[test]
    fn narrow_open_preview_requires_complete_disclosure_review() {
        let disclosure = format!(
            "BEGIN\n{}\nEND",
            (1..=18)
                .map(|line| format!("environment disclosure line {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let mut state = EnvironmentSelector::new(
            vec!["GH_TOKEN".into()],
            Vec::<String>::new(),
        );
        state.set_preview("GH_TOKEN".into(), disclosure);

        let first = rendered_at(&state, 64, 30);
        assert!(first.contains("BEGIN"), "{first}");
        assert!(!first.contains("END"), "{first}");
        assert_eq!(state.handle_key(KeyCode::Enter), EnvironmentAction::None);
        assert!(matches!(state.phase, Phase::Preview { .. }));

        state.handle_key(KeyCode::End);
        let last = rendered_at(&state, 64, 30);
        assert!(last.contains("END"), "{last}");
        state.handle_key(KeyCode::Enter);
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Tab);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            EnvironmentAction::Approve("GH_TOKEN".into())
        );
    }

    #[test]
    fn open_confirmation_keeps_paging_available() {
        let disclosure = (1..=20)
            .map(|line| format!("line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut state = EnvironmentSelector::new(
            vec!["GH_TOKEN".into()],
            Vec::<String>::new(),
        );
        state.set_preview("GH_TOKEN".into(), disclosure);
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Enter);
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Tab);
        state.handle_key(KeyCode::PageUp);
        assert_eq!(state.handle_key(KeyCode::Enter), EnvironmentAction::None);
        state.handle_key(KeyCode::End);
        assert!(matches!(
            state.handle_key(KeyCode::Enter),
            EnvironmentAction::Approve(_)
        ));
    }

    #[test]
    fn actual_geometry_accounts_for_adversarial_long_name() {
        let name = format!("LONG_{}", "NAME".repeat(160));
        let final_line = "FINAL-ENV-DISCLOSURE-LINE";
        let mut state =
            EnvironmentSelector::new(vec![name.clone()], Vec::<String>::new());
        state.set_preview(
            name.clone(),
            format!("Authority details\n{final_line}"),
        );
        let first = rendered_at(&state, 64, 30);
        assert!(!first.contains(final_line), "{first}");
        assert_eq!(state.handle_key(KeyCode::Enter), EnvironmentAction::None);
        assert!(matches!(state.phase, Phase::Preview { .. }));

        state.handle_key(KeyCode::End);
        let last = rendered_at(&state, 64, 30);
        assert!(last.contains(final_line), "{last}");
        state.handle_key(KeyCode::Enter);
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Tab);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            EnvironmentAction::Approve(name)
        );
    }

    #[test]
    fn live_search_escapes_controls_and_bidi() {
        let mut state = EnvironmentSelector::new(
            vec!["QUERY_TOKEN".into()],
            Vec::<String>::new(),
        );
        state.handle_key(KeyCode::Char('/'));
        for value in "q\u{1b}\u{202e}".chars() {
            state.handle_key(KeyCode::Char(value));
        }
        let output = rendered(&state);
        assert!(output.contains("Search: q??"), "{output}");
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{202e}'));
    }
}
