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
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DirectoryMode {
    ReadOnly,
    ReadWrite,
}

impl DirectoryMode {
    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::ReadOnly => "READ-ONLY",
            Self::ReadWrite => "READ/WRITE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryEntry {
    pub(super) path: PathBuf,
    pub(super) name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryPreview {
    pub(super) entered: String,
    pub(super) resolved: PathBuf,
    pub(super) disclosure: String,
    pub(super) mode: DirectoryMode,
    pub(super) replaces: Option<DirectoryGrantEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Browser,
    Selected,
    Filter,
    GoToPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Browse,
    Preview(DirectoryPreview),
    ConfirmOpen(DirectoryPreview, ConfirmDialog),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DirectoryAction {
    None,
    Reload {
        directory: PathBuf,
        show_hidden: bool,
    },
    GoTo(String),
    Prepare {
        path: PathBuf,
        mode: DirectoryMode,
    },
    Apply {
        path: PathBuf,
        mode: DirectoryMode,
        replaces: Option<DirectoryGrantEntry>,
    },
    ToggleMode(DirectoryGrantEntry),
    Remove(DirectoryGrantEntry),
    Back,
}

pub(super) struct DirectoryBrowser {
    mode: DirectoryMode,
    current: PathBuf,
    entries: Vec<DirectoryEntry>,
    selected: usize,
    grants: Vec<DirectoryGrantEntry>,
    selected_grant: usize,
    filter: String,
    show_hidden: bool,
    focus: Focus,
    resume_filter_on_text: bool,
    path_input: String,
    phase: Phase,
    feedback: String,
    detail_scroll: u16,
    required_detail_scroll: Cell<u16>,
    detail_geometry_ready: Cell<bool>,
}

impl DirectoryBrowser {
    pub(super) fn new(mode: DirectoryMode, current: PathBuf) -> Self {
        Self {
            mode,
            current,
            entries: Vec::new(),
            selected: 0,
            grants: Vec::new(),
            selected_grant: 0,
            filter: String::new(),
            show_hidden: false,
            focus: Focus::Browser,
            resume_filter_on_text: false,
            path_input: String::new(),
            phase: Phase::Browse,
            feedback: String::new(),
            detail_scroll: 0,
            required_detail_scroll: Cell::new(0),
            detail_geometry_ready: Cell::new(true),
        }
    }

    pub(super) fn mode(&self) -> DirectoryMode {
        self.mode
    }

    pub(super) fn captures_text_input(&self) -> bool {
        matches!(self.focus, Focus::Filter | Focus::GoToPath)
            || self.resume_filter_on_text
    }

    pub(super) fn set_entries(
        &mut self,
        current: PathBuf,
        mut entries: Vec<DirectoryEntry>,
    ) {
        entries.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        self.current = current;
        self.entries = entries;
        self.selected = 0;
        self.feedback.clear();
    }

    pub(super) fn set_error(&mut self, message: String) {
        self.feedback = message;
    }

    pub(super) fn set_preview(&mut self, preview: DirectoryPreview) {
        self.detail_scroll = 0;
        self.required_detail_scroll.set(u16::MAX);
        self.detail_geometry_ready.set(false);
        self.phase = Phase::Preview(preview);
        self.feedback.clear();
    }

    pub(super) fn set_grants(&mut self, mut grants: Vec<DirectoryGrantEntry>) {
        grants.sort_by(|left, right| left.path.cmp(&right.path));
        self.grants = grants;
        self.selected_grant =
            self.selected_grant.min(self.grants.len().saturating_sub(1));
        if self.grants.is_empty() && self.focus == Focus::Selected {
            self.focus = Focus::Browser;
        }
    }

    pub(super) fn add_grant(&mut self, entry: DirectoryGrantEntry) {
        self.grants.retain(|grant| grant.path != entry.path);
        self.grants.push(entry);
        self.grants
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.selected_grant = self.grants.len().saturating_sub(1);
    }

    pub(super) fn remove_grant(&mut self, entry: &DirectoryGrantEntry) {
        self.grants.retain(|grant| grant != entry);
        self.selected_grant =
            self.selected_grant.min(self.grants.len().saturating_sub(1));
        if self.grants.is_empty() {
            self.focus = Focus::Browser;
        }
    }

    pub(super) fn replace_grant(
        &mut self,
        old: &DirectoryGrantEntry,
        new: DirectoryGrantEntry,
    ) {
        self.grants.retain(|grant| grant != old);
        self.grants.push(new);
        self.grants
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.selected_grant = self
            .grants
            .iter()
            .position(|grant| grant.path == old.path)
            .unwrap_or_else(|| self.grants.len().saturating_sub(1));
    }

    fn visible_entries(&self) -> Vec<&DirectoryEntry> {
        let filter = self.filter.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                (self.show_hidden || !entry.name.starts_with('.'))
                    && entry.name.to_ascii_lowercase().contains(&filter)
            })
            .collect()
    }

    fn highlighted_path(&self) -> PathBuf {
        if self.selected == 0 {
            return self.current.clone();
        }
        self.visible_entries()
            .get(self.selected - 1)
            .map_or_else(|| self.current.clone(), |entry| entry.path.clone())
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> DirectoryAction {
        if matches!(self.phase, Phase::Preview(_) | Phase::ConfirmOpen(_, _))
            && self.handle_detail_scroll(code)
        {
            return DirectoryAction::None;
        }
        let disclosure_reviewed = self.disclosure_reviewed();
        match &mut self.phase {
            Phase::ConfirmOpen(preview, dialog) => {
                match dialog.handle_key(code) {
                    DialogAction::Confirm if disclosure_reviewed => {
                        let action = DirectoryAction::Apply {
                            path: preview.resolved.clone(),
                            mode: preview.mode,
                            replaces: preview.replaces.clone(),
                        };
                        self.phase = Phase::Browse;
                        action
                    }
                    DialogAction::Confirm => {
                        self.feedback = "Review through the final disclosure line before approval.".into();
                        DirectoryAction::None
                    }
                    DialogAction::Cancel => {
                        self.detail_scroll = 0;
                        self.required_detail_scroll.set(u16::MAX);
                        self.detail_geometry_ready.set(false);
                        self.phase = Phase::Preview(preview.clone());
                        DirectoryAction::None
                    }
                    DialogAction::Stay => DirectoryAction::None,
                }
            }
            Phase::Preview(preview) => match code {
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if !disclosure_reviewed {
                        self.feedback =
                            "Review through the final disclosure line before approval.".into();
                        DirectoryAction::None
                    } else {
                        self.detail_scroll = 0;
                        self.required_detail_scroll.set(u16::MAX);
                        self.detail_geometry_ready.set(false);
                        self.phase = Phase::ConfirmOpen(
                            preview.clone(),
                            ConfirmDialog::new(
                                "Open this directory boundary?",
                                format!(
                                    "{} access to {} expands host filesystem authority.",
                                    preview.mode.title(),
                                    escape_control_bytes(&preview.entered)
                                ),
                                "Grant OPEN access",
                            ),
                        );
                        DirectoryAction::None
                    }
                }
                KeyCode::Esc => {
                    self.phase = Phase::Browse;
                    DirectoryAction::None
                }
                _ => DirectoryAction::None,
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

    fn handle_browse_key(&mut self, code: KeyCode) -> DirectoryAction {
        match self.focus {
            Focus::Filter => match code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.focus = Focus::Browser;
                    self.resume_filter_on_text = false;
                }
                KeyCode::Down => {
                    self.focus = Focus::Browser;
                    self.resume_filter_on_text = true;
                    self.selected =
                        usize::from(!self.visible_entries().is_empty());
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.selected = 0;
                }
                KeyCode::Char(value) => {
                    self.filter.push(value);
                    self.selected = 0;
                }
                _ => {}
            },
            Focus::GoToPath => match code {
                KeyCode::Esc => {
                    self.focus = Focus::Browser;
                    self.path_input.clear();
                }
                KeyCode::Enter if !self.path_input.is_empty() => {
                    let path = std::mem::take(&mut self.path_input);
                    self.focus = Focus::Browser;
                    return DirectoryAction::GoTo(path);
                }
                KeyCode::Backspace => {
                    self.path_input.pop();
                }
                KeyCode::Char(value) => self.path_input.push(value),
                _ => {}
            },
            Focus::Selected => match code {
                KeyCode::Tab | KeyCode::BackTab => {
                    self.focus = Focus::Browser;
                }
                KeyCode::Up => {
                    self.selected_grant = self.selected_grant.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.selected_grant = (self.selected_grant + 1)
                        .min(self.grants.len().saturating_sub(1));
                }
                KeyCode::Home => self.selected_grant = 0,
                KeyCode::End => {
                    self.selected_grant = self.grants.len().saturating_sub(1);
                }
                KeyCode::Char(' ') if !self.grants.is_empty() => {
                    return DirectoryAction::Remove(
                        self.grants[self.selected_grant].clone(),
                    );
                }
                KeyCode::Char('m') if !self.grants.is_empty() => {
                    return DirectoryAction::ToggleMode(
                        self.grants[self.selected_grant].clone(),
                    );
                }
                KeyCode::Esc => return DirectoryAction::Back,
                _ => {}
            },
            Focus::Browser => match code {
                KeyCode::Tab | KeyCode::BackTab if !self.grants.is_empty() => {
                    self.focus = Focus::Selected;
                    self.resume_filter_on_text = false;
                }
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => {
                    self.selected =
                        (self.selected + 1).min(self.visible_entries().len());
                }
                KeyCode::Home => self.selected = 0,
                KeyCode::End => {
                    self.selected = self.visible_entries().len();
                }
                KeyCode::Enter => {
                    self.resume_filter_on_text = false;
                    if self.selected == 0 {
                        self.feedback =
                            "Press Space to add this directory.".into();
                        return DirectoryAction::None;
                    }
                    let directory = self.highlighted_path();
                    return DirectoryAction::Reload {
                        directory,
                        show_hidden: self.show_hidden,
                    };
                }
                KeyCode::Char(' ') => {
                    self.resume_filter_on_text = false;
                    return DirectoryAction::Prepare {
                        path: self.highlighted_path(),
                        mode: self.mode,
                    };
                }
                KeyCode::Backspace => {
                    self.resume_filter_on_text = false;
                    if let Some(parent) = self.current.parent() {
                        return DirectoryAction::Reload {
                            directory: parent.to_path_buf(),
                            show_hidden: self.show_hidden,
                        };
                    }
                }
                KeyCode::Char('/') => {
                    self.focus = Focus::Filter;
                    self.resume_filter_on_text = false;
                }
                KeyCode::Char(value) if self.resume_filter_on_text => {
                    self.focus = Focus::Filter;
                    self.resume_filter_on_text = false;
                    self.filter.push(value);
                    self.selected = 0;
                }
                KeyCode::Char('g') => {
                    self.focus = Focus::GoToPath;
                    self.path_input.clear();
                }
                KeyCode::Char('.') => {
                    self.show_hidden = !self.show_hidden;
                    self.selected = 0;
                    return DirectoryAction::Reload {
                        directory: self.current.clone(),
                        show_hidden: self.show_hidden,
                    };
                }
                KeyCode::Char('m') => {
                    self.mode = match self.mode {
                        DirectoryMode::ReadOnly => DirectoryMode::ReadWrite,
                        DirectoryMode::ReadWrite => DirectoryMode::ReadOnly,
                    };
                }
                KeyCode::Esc => return DirectoryAction::Back,
                _ => {}
            },
        }
        DirectoryAction::None
    }
}

pub(super) fn render(
    frame: &mut Frame,
    state: &DirectoryBrowser,
    use_color: bool,
) {
    let area = frame.area();
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(4),
    ])
    .areas(area);
    let (workspace, selected_area) = if state.grants.is_empty() {
        (body, None)
    } else {
        let selected_height = (state.grants.len() as u16 + 2).clamp(4, 8);
        let [workspace, selected] = Layout::vertical([
            Constraint::Min(8),
            Constraint::Length(selected_height),
        ])
        .areas(body);
        (workspace, Some(selected))
    };
    let [list_area, detail_area] = if workspace.width >= 92 {
        Layout::horizontal([
            Constraint::Percentage(44),
            Constraint::Percentage(56),
        ])
        .areas(workspace)
    } else {
        Layout::vertical([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .areas(workspace)
    };

    let path = escape_control_bytes(&state.current.to_string_lossy());
    let safe_filter = escape_control_bytes(&state.filter);
    let safe_path_input = escape_control_bytes(&state.path_input);
    let input = match state.focus {
        Focus::Filter => format!("Filter: {safe_filter}█"),
        Focus::GoToPath => format!("Go to: {safe_path_input}█"),
        Focus::Browser | Focus::Selected => format!(
            "Filter: {}  •  hidden: {}",
            if state.filter.is_empty() {
                "none"
            } else {
                safe_filter.as_str()
            },
            if state.show_hidden { "shown" } else { "hidden" }
        ),
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    "Directory access  ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    state.mode.title(),
                    risk_style(state.mode, use_color),
                ),
            ]),
            Line::from(format!("Location: {path}")),
            Line::from(input),
        ]),
        header,
    );

    let visible = state.visible_entries();
    let choose_current = ListItem::new(Line::from(vec![
        Span::styled("✓  ", risk_style(state.mode, use_color)),
        Span::styled(
            "Choose this directory",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    let items =
        std::iter::once(choose_current).chain(visible.iter().map(|entry| {
            ListItem::new(Line::from(vec![
                Span::styled("dir  ", muted(use_color)),
                Span::raw(entry.name.as_str()),
            ]))
        }));
    let selected = Some(state.selected.min(visible.len()));
    let mut list_state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(if state.focus != Focus::Selected {
                        " Directories • ACTIVE "
                    } else {
                        " Directories • Tab to focus "
                    })
                    .borders(Borders::ALL)
                    .border_style(focus_border(
                        state.focus != Focus::Selected,
                        use_color,
                    )),
            )
            .highlight_symbol("> ")
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD),
            ),
        list_area,
        &mut list_state,
    );

    let detail = match &state.phase {
        Phase::Browse => format!(
            "Selected\n{}\n\nUse when\nThe task needs files in this folder outside its existing project access.\n\nSpace\nAdd with {} access.\n\nEnter\nOpen this folder and browse inside it.",
            escape_control_bytes(&state.highlighted_path().to_string_lossy()),
            state.mode.title()
        ),
        Phase::Preview(preview) => format!(
            "Entered: {}\nResolved: {}\n\nUse when\nThe task needs files in this exact resolved folder.\n\n{}\n\n{}",
            escape_control_bytes(&preview.entered),
            escape_control_bytes(&preview.resolved.to_string_lossy()),
            preview.disclosure,
            "OPEN authority — review every line, then press Space to choose."
        ),
        Phase::ConfirmOpen(preview, _) => format!(
            "{}\n\nUse when\nThe task genuinely needs this broad directory scope.\n\nOPEN removes an important boundary.",
            preview.disclosure
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
                        " Security preview • lines {}–{}/{} • PgUp/PgDn ",
                        scroll.saturating_add(1),
                        last,
                        total
                    ))
                    .borders(Borders::ALL),
            ),
        detail_area,
    );

    if let Some(selected_area) = selected_area {
        let inner_width = selected_area.width.saturating_sub(4);
        let items = state.grants.iter().map(|entry| {
            let mode = entry.mode.title();
            let path = escape_control_bytes(&entry.path.to_string_lossy());
            let path_width = usize::from(inner_width)
                .saturating_sub(mode.chars().count() + 2)
                .max(1);
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{mode}  "),
                    risk_style(entry.mode, use_color),
                ),
                Span::raw(visible_path_tail(&path, path_width)),
            ]))
        });
        let mut selected_state = ListState::default().with_selected(
            (state.focus == Focus::Selected).then_some(state.selected_grant),
        );
        frame.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .title(if state.focus == Focus::Selected {
                            " Selected directories • ACTIVE • m changes mode • Space removes "
                        } else {
                            " Selected directories • Tab to focus "
                        })
                        .borders(Borders::ALL)
                        .border_style(focus_border(
                            state.focus == Focus::Selected,
                            use_color,
                        )),
                )
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .add_modifier(Modifier::REVERSED | Modifier::BOLD),
                ),
            selected_area,
            &mut selected_state,
        );
    }

    let help = if state.feedback.is_empty() {
        match state.focus {
            Focus::Selected => {
                "↑/↓ selected grants  •  m read-only/read-write  •  Space remove  •  Tab browse  •  Esc back"
            }
            _ => {
                "↑/↓ browse  •  Enter open  •  Space add  •  Tab selected  •  m read-only/read-write\n/ filter  •  ↓ results  •  type to refine  •  g go to path  •  . hidden  •  Esc back"
            }
        }
    } else {
        &state.feedback
    };
    frame.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::TOP)),
        footer,
    );
    if let Phase::ConfirmOpen(_, dialog) = &state.phase {
        dialog.render(frame, use_color);
    }
}

fn visible_path_tail(path: &str, width: usize) -> String {
    let count = path.chars().count();
    if count <= width {
        return path.to_string();
    }
    if width <= 1 {
        return "…".into();
    }
    let tail = path.chars().skip(count - (width - 1)).collect::<String>();
    format!("…{tail}")
}

fn muted(use_color: bool) -> Style {
    if use_color {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn focus_border(active: bool, use_color: bool) -> Style {
    if active && use_color {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else if active {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        muted(use_color)
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

fn risk_style(mode: DirectoryMode, use_color: bool) -> Style {
    let base = Style::default().add_modifier(Modifier::BOLD);
    if !use_color {
        return base;
    }
    match mode {
        DirectoryMode::ReadOnly => base.fg(Color::Green),
        DirectoryMode::ReadWrite => base.fg(Color::Yellow),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryGrantEntry {
    pub(super) path: PathBuf,
    pub(super) mode: DirectoryMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_selected_paths_keep_the_identifying_tail_visible() {
        assert_eq!(
            visible_path_tail("/very/long/share-café", 11),
            "…share-café"
        );
        assert_eq!(visible_path_tail("/short", 20), "/short");
    }
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn entry(name: &str) -> DirectoryEntry {
        DirectoryEntry {
            path: PathBuf::from("/work").join(name),
            name: name.into(),
        }
    }

    fn rendered(state: &DirectoryBrowser) -> String {
        rendered_at(state, 120, 34)
    }

    fn rendered_at(
        state: &DirectoryBrowser,
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
    fn filter_is_dynamic_and_q_is_text_while_filter_has_focus() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_entries(
            "/work".into(),
            vec![entry("alpha"), entry("quiet"), entry("beta")],
        );
        state.handle_key(KeyCode::Char('/'));
        state.handle_key(KeyCode::Char('q'));
        let output = rendered(&state);
        assert!(output.contains("quiet"));
        assert!(output.contains("Use when"));
        assert!(!output.contains("alpha"));
    }

    #[test]
    fn down_focuses_filtered_results_and_typing_resumes_filtering() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_entries(
            "/work".into(),
            vec![entry("alpha"), entry("alpine"), entry("beta")],
        );

        state.handle_key(KeyCode::Char('/'));
        state.handle_key(KeyCode::Char('a'));
        state.handle_key(KeyCode::Down);
        assert_eq!(state.focus, Focus::Browser);
        assert_eq!(state.selected, 1);
        assert!(state.resume_filter_on_text);

        state.handle_key(KeyCode::Char('l'));
        assert_eq!(state.focus, Focus::Filter);
        assert_eq!(state.filter, "al");
        assert_eq!(state.selected, 0);

        state.handle_key(KeyCode::Down);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            DirectoryAction::Reload {
                directory: PathBuf::from("/work/alpha"),
                show_hidden: false,
            }
        );
    }

    #[test]
    fn navigation_returns_actions_without_touching_the_filesystem() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadWrite, "/work".into());
        state.set_entries("/work".into(), vec![entry("alpha"), entry("beta")]);
        state.handle_key(KeyCode::Down);
        state.handle_key(KeyCode::Down);
        assert_eq!(
            state.handle_key(KeyCode::Enter),
            DirectoryAction::Reload {
                directory: PathBuf::from("/work/beta"),
                show_hidden: false,
            }
        );
    }

    #[test]
    fn current_directory_is_an_explicit_space_action() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_entries("/work".into(), vec![entry("child")]);
        let screen = rendered(&state);
        assert!(screen.contains("Choose this directory"), "{screen}");
        assert_eq!(
            state.handle_key(KeyCode::Char(' ')),
            DirectoryAction::Prepare {
                path: PathBuf::from("/work"),
                mode: DirectoryMode::ReadOnly,
            }
        );
    }

    #[test]
    fn open_preview_dialog_ignores_text_and_defaults_to_cancel() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadWrite, "/work".into());
        state.set_preview(DirectoryPreview {
            entered: "/work".into(),
            resolved: "/work".into(),
            disclosure: "Broad writable scope".into(),
            mode: DirectoryMode::ReadWrite,
            replaces: None,
        });
        let _ = rendered(&state);
        state.handle_key(KeyCode::Enter);
        let _ = rendered(&state);
        state.handle_key(KeyCode::Char('x'));
        assert_eq!(state.handle_key(KeyCode::Enter), DirectoryAction::None);
        assert!(matches!(state.phase, Phase::Preview(_)));
    }

    #[test]
    fn selected_pane_uses_tab_and_space_and_closes_when_empty() {
        let entry = DirectoryGrantEntry {
            path: "/work/shared".into(),
            mode: DirectoryMode::ReadOnly,
        };
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_grants(vec![entry.clone()]);
        assert!(rendered(&state).contains("Selected directories"));
        assert_eq!(state.handle_key(KeyCode::Tab), DirectoryAction::None);
        assert_eq!(
            state.handle_key(KeyCode::Char('m')),
            DirectoryAction::ToggleMode(entry.clone())
        );
        let writable = DirectoryGrantEntry {
            path: entry.path.clone(),
            mode: DirectoryMode::ReadWrite,
        };
        state.replace_grant(&entry, writable.clone());
        assert!(rendered(&state).contains("READ/WRITE"));
        assert_eq!(
            state.handle_key(KeyCode::Char(' ')),
            DirectoryAction::Remove(writable.clone())
        );
        state.remove_grant(&writable);
        assert!(!rendered(&state).contains("Selected directories"));
        assert_eq!(state.focus, Focus::Browser);
    }

    #[test]
    fn open_confirmation_keeps_disclosure_paging_available() {
        let disclosure = (1..=20)
            .map(|line| format!("line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_preview(DirectoryPreview {
            entered: "/work/shared".into(),
            resolved: "/work/shared".into(),
            disclosure,
            mode: DirectoryMode::ReadOnly,
            replaces: None,
        });
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::End);
        state.handle_key(KeyCode::Char(' '));
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::Tab);
        state.handle_key(KeyCode::PageUp);
        assert_eq!(state.handle_key(KeyCode::Enter), DirectoryAction::None);
        state.handle_key(KeyCode::End);
        assert!(matches!(
            state.handle_key(KeyCode::Enter),
            DirectoryAction::Apply { .. }
        ));
    }

    #[test]
    fn actual_geometry_accounts_for_adversarial_long_paths() {
        let long_component = "segment".repeat(40);
        let final_line = "FINAL-DISCLOSURE-LINE";
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.set_preview(DirectoryPreview {
            entered: format!("/work/{long_component}"),
            resolved: PathBuf::from(format!("/work/{long_component}")),
            disclosure: format!("Resource details\n{final_line}"),
            mode: DirectoryMode::ReadOnly,
            replaces: None,
        });
        let first = rendered_at(&state, 64, 30);
        assert!(!first.contains(final_line), "{first}");
        assert_eq!(state.handle_key(KeyCode::Enter), DirectoryAction::None);
        assert!(matches!(state.phase, Phase::Preview(_)));

        state.handle_key(KeyCode::End);
        let last = rendered_at(&state, 64, 30);
        assert!(last.contains(final_line), "{last}");
        state.handle_key(KeyCode::Char(' '));
        let _ = rendered_at(&state, 64, 30);
        state.handle_key(KeyCode::Tab);
        state.handle_key(KeyCode::End);
        assert!(matches!(
            state.handle_key(KeyCode::Enter),
            DirectoryAction::Apply { .. }
        ));
    }

    #[test]
    fn live_filter_and_path_inputs_escape_controls_and_bidi() {
        let mut state =
            DirectoryBrowser::new(DirectoryMode::ReadOnly, "/work".into());
        state.handle_key(KeyCode::Char('/'));
        for value in "filter\u{1b}\u{202e}".chars() {
            state.handle_key(KeyCode::Char(value));
        }
        let filter = rendered(&state);
        assert!(filter.contains("filter??"), "{filter}");
        assert!(!filter.contains('\u{1b}'));
        assert!(!filter.contains('\u{202e}'));

        state.handle_key(KeyCode::Enter);
        let browser = rendered(&state);
        assert!(browser.contains("Filter: filter??"), "{browser}");
        state.handle_key(KeyCode::Char('g'));
        for value in "/tmp/\u{1b}\u{202e}".chars() {
            state.handle_key(KeyCode::Char(value));
        }
        let go_to = rendered(&state);
        assert!(go_to.contains("Go to: /tmp/??"), "{go_to}");
        assert!(!go_to.contains('\u{1b}'));
        assert!(!go_to.contains('\u{202e}'));
    }
}
