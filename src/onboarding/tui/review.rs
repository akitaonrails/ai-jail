//! Pure state and rendering for the final effective-access review.
//!
//! Finalization and persistence remain controller responsibilities. This
//! component only presents already prepared, display-safe review text and
//! returns a semantic action after the complete disclosure has been reviewed.

use super::dialog::{ConfirmDialog, DialogAction};
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

const MIN_WIDTH: u16 = 64;
const MIN_HEIGHT: u16 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReviewContent {
    pub(super) restricted: String,
    pub(super) allowed: String,
    pub(super) open: String,
    pub(super) effective_policy: String,
}

impl ReviewContent {
    fn grouped_text(&self) -> String {
        fn section(label: &str, body: &str) -> String {
            let body = if body.trim().is_empty() { "None" } else { body };
            format!("{label}\n{body}")
        }

        [
            section("RESTRICTED", &self.restricted),
            section("ALLOWED", &self.allowed),
            section("OPEN", &self.open),
            section("COMPLETE EFFECTIVE POLICY", &self.effective_policy),
        ]
        .join("\n\n")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FinalAction {
    SaveProfile,
    SaveAndLaunch,
    LaunchOnce,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Review,
    ConfirmOpen {
        action: FinalAction,
        dialog: ConfirmDialog,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReviewAction {
    Stay,
    Back,
    Cancel,
    Complete(FinalAction),
}

#[derive(Clone, Debug)]
pub(super) struct ReviewState {
    content: ReviewContent,
    configure_only: bool,
    open_authority: bool,
    scroll: u16,
    required_scroll: u16,
    geometry_ready: bool,
    phase: Phase,
    feedback: String,
    use_color: bool,
}

impl ReviewState {
    pub(super) fn new(
        content: ReviewContent,
        configure_only: bool,
        open_authority: bool,
        use_color: bool,
    ) -> Self {
        Self {
            content,
            configure_only,
            open_authority,
            scroll: 0,
            required_scroll: u16::MAX,
            geometry_ready: false,
            phase: Phase::Review,
            feedback: String::new(),
            use_color,
        }
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> ReviewAction {
        match code {
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(5);
                self.feedback.clear();
                return ReviewAction::Stay;
            }
            KeyCode::PageDown => {
                self.scroll =
                    self.scroll.saturating_add(5).min(self.required_scroll);
                self.feedback.clear();
                return ReviewAction::Stay;
            }
            KeyCode::Home => {
                self.scroll = 0;
                self.feedback.clear();
                return ReviewAction::Stay;
            }
            KeyCode::End => {
                if self.geometry_ready {
                    self.scroll = self.required_scroll;
                }
                self.feedback.clear();
                return ReviewAction::Stay;
            }
            _ => {}
        }

        if let Phase::ConfirmOpen { action, dialog } = &mut self.phase {
            return match dialog.handle_key(code) {
                DialogAction::Confirm => ReviewAction::Complete(*action),
                DialogAction::Cancel => {
                    self.phase = Phase::Review;
                    self.feedback = "Final action cancelled.".into();
                    ReviewAction::Stay
                }
                DialogAction::Stay => ReviewAction::Stay,
            };
        }

        match code {
            KeyCode::Char('b' | 'B') | KeyCode::Esc => ReviewAction::Back,
            KeyCode::Char('q' | 'Q') => ReviewAction::Cancel,
            KeyCode::Char('s' | 'S') => {
                let action = if self.configure_only {
                    FinalAction::SaveProfile
                } else {
                    FinalAction::SaveAndLaunch
                };
                self.begin_action(action)
            }
            KeyCode::Char('o' | 'O') if !self.configure_only => {
                self.begin_action(FinalAction::LaunchOnce)
            }
            _ => ReviewAction::Stay,
        }
    }

    fn begin_action(&mut self, action: FinalAction) -> ReviewAction {
        if !self.disclosure_reviewed() {
            self.feedback =
                "Review through the final effective-access line before continuing."
                    .into();
            return ReviewAction::Stay;
        }
        if self.open_authority {
            self.phase = Phase::ConfirmOpen {
                action,
                dialog: ConfirmDialog::new(
                    "Continue with OPEN authority?",
                    match action {
                        FinalAction::SaveProfile => {
                            "This saves a project profile containing OPEN authority. It does not launch a jail."
                        }
                        FinalAction::SaveAndLaunch => {
                            "This saves the OPEN approvals and starts one jail now."
                        }
                        FinalAction::LaunchOnce => {
                            "This starts one jail with OPEN authority now without saving these approvals."
                        }
                    },
                    match action {
                        FinalAction::SaveProfile => "Save OPEN profile",
                        FinalAction::SaveAndLaunch => "Save & launch",
                        FinalAction::LaunchOnce => "Launch once",
                    },
                ),
            };
            self.feedback.clear();
            ReviewAction::Stay
        } else {
            ReviewAction::Complete(action)
        }
    }

    fn disclosure_reviewed(&self) -> bool {
        self.geometry_ready && self.scroll >= self.required_scroll
    }

    fn set_geometry(&mut self, required_scroll: u16) {
        self.geometry_ready = true;
        self.required_scroll = required_scroll;
        self.scroll = self.scroll.min(self.required_scroll);
    }

    fn invalidate_geometry(&mut self) {
        self.geometry_ready = false;
        self.required_scroll = u16::MAX;
        self.scroll = 0;
    }

    fn prompt(&self) -> Vec<Line<'static>> {
        if let Phase::ConfirmOpen { action, .. } = &self.phase {
            let consequence = match action {
                FinalAction::SaveProfile => {
                    "Save Profile — persists this project profile and does not launch a jail."
                }
                FinalAction::SaveAndLaunch => {
                    "Save & Launch — persists this project profile and starts one jail now."
                }
                FinalAction::LaunchOnce => {
                    "Launch Once — does not save these approvals and starts one jail now."
                }
            };
            let lines = vec![
                Line::from(Span::styled(
                    consequence,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "Final effective access contains OPEN authority. Choose in the dialog.",
                    risk_style(self.use_color),
                )),
            ];
            return lines;
        }
        if !self.feedback.is_empty() {
            return vec![Line::from(self.feedback.clone())];
        }
        if self.configure_only {
            vec![
                Line::from("PgUp/PgDn scroll  •  Home/End first/final line"),
                Line::from("s save profile  •  b back  •  q cancel"),
            ]
        } else {
            vec![
                Line::from("PgUp/PgDn scroll  •  Home/End first/final line"),
                Line::from(
                    "s save & launch  •  o launch once  •  b back  •  q cancel",
                ),
            ]
        }
    }
}

pub(super) fn render(frame: &mut Frame, state: &mut ReviewState) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        state.invalidate_geometry();
        frame.render_widget(
            Paragraph::new(format!(
                "Terminal too small for complete access review.\nResize to at least {MIN_WIDTH}×{MIN_HEIGHT}.\n\nq cancel  •  Esc back"
            ))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(" Complete effective access ")
                    .borders(Borders::ALL),
            ),
            area,
        );
        return;
    }

    let footer_height = if matches!(state.phase, Phase::ConfirmOpen { .. }) {
        if state.feedback.is_empty() { 6 } else { 7 }
    } else {
        4
    };
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(footer_height),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Complete effective access",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(
                "Review every contributing policy layer before choosing a final action.",
            ),
        ]),
        header,
    );

    let inner = body.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    let text = state.content.grouped_text();
    let total = wrapped_line_count(&text, inner.width);
    let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });
    let visible = inner.height.max(1);
    let required = total.saturating_sub(visible);
    state.set_geometry(required);
    let first = state.scroll.saturating_add(1).min(total.max(1));
    let last = state.scroll.saturating_add(visible).min(total.max(1));
    let title = format!(
        " Security review • lines {first}–{last}/{} • PgUp/PgDn ",
        total.max(1)
    );
    frame.render_widget(
        paragraph
            .scroll((state.scroll, 0))
            .block(Block::default().title(title).borders(Borders::ALL)),
        body,
    );
    frame.render_widget(
        Paragraph::new(state.prompt())
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::TOP)),
        footer,
    );
    if let Phase::ConfirmOpen { dialog, .. } = &state.phase {
        dialog.render(frame, state.use_color);
    }
}

fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| {
            let mut rows = 1usize;
            let mut used = 0usize;
            for word in line.split_whitespace() {
                let word_width = word.chars().count();
                let separator = usize::from(used > 0);
                if separator + word_width <= width.saturating_sub(used) {
                    used += separator + word_width;
                    continue;
                }
                rows += 1;
                rows += word_width.saturating_sub(1) / width;
                used = (word_width.saturating_sub(1) % width) + 1;
            }
            rows
        })
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn risk_style(use_color: bool) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if use_color {
        style.fg(Color::Red)
    } else {
        style
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn content(lines: usize) -> ReviewContent {
        ReviewContent {
            restricted: "No host SSH configuration\nNo host GitHub token"
                .into(),
            allowed: (0..lines)
                .map(|index| format!("Allowed resource {index}"))
                .collect::<Vec<_>>()
                .join("\n"),
            open: "None".into(),
            effective_policy: "network = false\nssh = false".into(),
        }
    }

    fn render_at(state: &mut ReviewState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn action_is_blocked_until_final_disclosure_line_is_reviewed() {
        let mut state = ReviewState::new(content(80), true, false, false);
        let first = render_at(&mut state, 64, 30);
        assert!(first.contains("lines 1–"), "{first}");
        assert_eq!(state.handle_key(KeyCode::Char('s')), ReviewAction::Stay);
        assert!(state.feedback.contains("final effective-access line"));

        state.handle_key(KeyCode::End);
        assert_eq!(
            state.handle_key(KeyCode::Char('s')),
            ReviewAction::Complete(FinalAction::SaveProfile)
        );
    }

    #[test]
    fn open_authority_dialog_defaults_to_cancel() {
        let mut state = ReviewState::new(content(1), false, true, false);
        render_at(&mut state, 120, 34);
        state.handle_key(KeyCode::End);
        assert_eq!(state.handle_key(KeyCode::Char('o')), ReviewAction::Stay);
        assert_eq!(state.handle_key(KeyCode::Enter), ReviewAction::Stay);
        assert!(state.feedback.contains("cancelled"));
        assert_eq!(state.handle_key(KeyCode::Char('o')), ReviewAction::Stay);
        state.handle_key(KeyCode::Tab);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            ReviewAction::Complete(FinalAction::LaunchOnce)
        );
    }

    #[test]
    fn open_dialog_ignores_text_and_exposes_explicit_buttons() {
        let mut state = ReviewState::new(content(1), false, true, false);
        render_at(&mut state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Char('o'));
        state.handle_key(KeyCode::Char('x'));

        let dialog = render_at(&mut state, 64, 30);
        assert!(dialog.contains("Continue with OPEN authority?"), "{dialog}");
        assert!(dialog.contains("Launch once"), "{dialog}");
        assert!(dialog.contains("Cancel"), "{dialog}");

        state.handle_key(KeyCode::Tab);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            ReviewAction::Complete(FinalAction::LaunchOnce)
        );
    }

    #[test]
    fn open_confirmation_names_save_profile_persistence_and_no_launch() {
        let mut state = ReviewState::new(content(1), true, true, false);
        render_at(&mut state, 120, 34);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Char('s'));
        let screen = render_at(&mut state, 120, 34);
        assert!(
            screen.contains(
                "Save Profile — persists this project profile and does not launch a jail."
            ),
            "{screen}"
        );
    }

    #[test]
    fn open_confirmation_names_save_and_launch_persistence_and_duration() {
        let mut state = ReviewState::new(content(1), false, true, false);
        render_at(&mut state, 120, 34);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Char('s'));
        let screen = render_at(&mut state, 120, 34);
        assert!(
            screen.contains(
                "Save & Launch — persists this project profile and starts one jail now."
            ),
            "{screen}"
        );
    }

    #[test]
    fn open_confirmation_names_launch_once_non_persistence_and_duration() {
        let mut state = ReviewState::new(content(1), false, true, false);
        render_at(&mut state, 120, 34);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Char('o'));
        let screen = render_at(&mut state, 120, 34);
        assert!(
            screen.contains(
                "Launch Once — does not save these approvals and starts one jail now."
            ),
            "{screen}"
        );
    }

    #[test]
    fn configure_only_exposes_only_save_profile() {
        let mut state = ReviewState::new(content(1), true, false, false);
        let screen = render_at(&mut state, 100, 32);
        assert!(screen.contains("s save profile"), "{screen}");
        assert!(!screen.contains("launch once"), "{screen}");
        state.handle_key(KeyCode::End);
        assert_eq!(state.handle_key(KeyCode::Char('o')), ReviewAction::Stay);
        assert_eq!(
            state.handle_key(KeyCode::Char('s')),
            ReviewAction::Complete(FinalAction::SaveProfile)
        );
    }

    #[test]
    fn normal_mode_distinguishes_both_launch_actions() {
        let mut state = ReviewState::new(content(1), false, false, false);
        let screen = render_at(&mut state, 100, 32);
        assert!(screen.contains("save & launch"), "{screen}");
        assert!(screen.contains("launch once"), "{screen}");
        state.handle_key(KeyCode::End);
        assert_eq!(
            state.handle_key(KeyCode::Char('s')),
            ReviewAction::Complete(FinalAction::SaveAndLaunch)
        );
    }

    #[test]
    fn back_and_cancel_are_always_available() {
        let mut state = ReviewState::new(content(100), false, false, false);
        assert_eq!(state.handle_key(KeyCode::Esc), ReviewAction::Back);
        assert_eq!(state.handle_key(KeyCode::Char('q')), ReviewAction::Cancel);
    }

    #[test]
    fn narrow_layout_scrolls_and_shows_position() {
        let mut state = ReviewState::new(content(100), false, false, false);
        let first = render_at(&mut state, 64, 30);
        assert!(first.contains("lines 1–"), "{first}");
        state.handle_key(KeyCode::PageDown);
        let second = render_at(&mut state, 64, 30);
        assert!(!second.contains("lines 1–"), "{second}");
        assert!(second.contains("PgUp/PgDn"), "{second}");
    }

    #[test]
    fn too_small_terminal_blocks_actions_but_allows_escape() {
        let mut state = ReviewState::new(content(1), true, false, false);
        let screen = render_at(&mut state, 50, 18);
        assert!(screen.contains("Terminal too small"), "{screen}");
        assert_eq!(state.handle_key(KeyCode::Char('s')), ReviewAction::Stay);
        assert_eq!(state.handle_key(KeyCode::Esc), ReviewAction::Back);
    }
}
