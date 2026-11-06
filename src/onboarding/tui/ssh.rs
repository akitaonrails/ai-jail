//! Pure state and rendering for the selected-key SSH editor.
//!
//! The editor deliberately owns only display-safe identity metadata. Host-side
//! key capture and policy validation are requested through [`OperationRequest`]
//! and performed by the onboarding controller; private paths and key contents
//! never enter this state or its rendered buffers.

use crate::output::escape_control_bytes;
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Wrap,
};
use std::collections::BTreeSet;

const MIN_LIFETIME_SECONDS: u32 = 60;
const MAX_LIFETIME_SECONDS: u32 = 86_400;
const LIFETIME_STEP_SECONDS: u32 = 300;
const MAX_INPUT_CHARS: usize = 4096;
const WIDE_LAYOUT_WIDTH: u16 = 110;
const MAX_SECURITY_SCROLL: u16 = 4096;

/// Display-safe metadata for one file-backed SSH identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IdentityRow {
    pub(super) public_path: String,
    pub(super) fingerprint: String,
    pub(super) comment: String,
    pub(super) selected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Focus {
    Available,
    Selected,
    Destinations,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InputMode {
    CustomPath(String),
    Destination {
        replacing: Option<usize>,
        value: String,
    },
}

/// A host operation requested by the pure editor reducer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OperationRequest {
    /// Discover file-backed identities without exposing the ambient agent.
    DiscoverIdentities,
    /// Capture and fingerprint a user-entered private or `.pub` path.
    CapturePath(String),
    /// Add or remove one already discovered identity by stable fingerprint.
    SetIdentitySelected { fingerprint: String, selected: bool },
    /// Validate the complete destination candidate before changing policy.
    ValidateDestinations(Vec<String>),
    /// Validate and apply the requested key lifetime.
    SetLifetime(u32),
    /// Disable selected-key SSH completely.
    Disable,
}

/// Result of handling one key. The parent app owns navigation and host work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum EditorAction {
    Stay,
    Back,
    Request(OperationRequest),
}

#[derive(Clone, Debug)]
pub(super) struct Editor {
    identities: Vec<IdentityRow>,
    destinations: Vec<String>,
    lifetime_seconds: u32,
    focus: Focus,
    available_index: usize,
    selected_index: usize,
    destination_index: usize,
    input: Option<InputMode>,
    error: Option<String>,
    status: String,
    security_scroll: u16,
    required_security_scroll: u16,
    use_color: bool,
}

impl Editor {
    pub(super) fn new(
        identities: Vec<IdentityRow>,
        destinations: Vec<String>,
        lifetime_seconds: u32,
        use_color: bool,
    ) -> Self {
        Self {
            identities,
            destinations,
            lifetime_seconds: lifetime_seconds
                .clamp(MIN_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS),
            focus: Focus::Available,
            available_index: 0,
            selected_index: 0,
            destination_index: 0,
            input: None,
            error: None,
            status: String::new(),
            security_scroll: 0,
            required_security_scroll: 0,
            use_color,
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.identities.iter().any(|identity| identity.selected)
            && !self.destinations.is_empty()
    }

    pub(super) fn selected_fingerprints(&self) -> Vec<String> {
        self.identities
            .iter()
            .filter(|identity| identity.selected)
            .map(|identity| identity.fingerprint.clone())
            .collect()
    }

    pub(super) fn destinations(&self) -> Vec<String> {
        self.destinations.clone()
    }

    pub(super) fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }

    pub(super) fn captures_text_input(&self) -> bool {
        self.input.is_some()
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> EditorAction {
        self.error = None;
        match code {
            KeyCode::PageUp => {
                self.security_scroll = self.security_scroll.saturating_sub(5);
                self.status.clear();
                return EditorAction::Stay;
            }
            KeyCode::PageDown => {
                self.security_scroll =
                    self.security_scroll.saturating_add(5).min(
                        self.required_security_scroll.min(MAX_SECURITY_SCROLL),
                    );
                self.status.clear();
                return EditorAction::Stay;
            }
            KeyCode::Home => {
                self.security_scroll = 0;
                self.status.clear();
                return EditorAction::Stay;
            }
            KeyCode::End => {
                self.security_scroll = self.required_security_scroll;
                self.status.clear();
                return EditorAction::Stay;
            }
            _ => {}
        }
        if self.input.is_some() {
            return self.handle_input(code);
        }
        match code {
            KeyCode::Tab => self.focus_next(),
            KeyCode::BackTab => self.focus_previous(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Home => self.set_selection(0),
            KeyCode::End => self.set_selection(usize::MAX),
            KeyCode::Char(' ') if self.focus == Focus::Available => {
                return self.toggle_available();
            }
            KeyCode::Char(' ') if self.focus == Focus::Selected => {
                return self.remove_selected();
            }
            KeyCode::Enter if self.focus == Focus::Available => {
                return self.toggle_available();
            }
            KeyCode::Enter if self.focus == Focus::Selected => {
                return self.remove_selected();
            }
            KeyCode::Enter | KeyCode::Char('e')
                if self.focus == Focus::Destinations =>
            {
                let replacing = self
                    .destinations
                    .get(self.destination_index)
                    .map(|_| self.destination_index);
                let value = replacing
                    .and_then(|index| self.destinations.get(index).cloned())
                    .unwrap_or_default();
                self.input = Some(InputMode::Destination { replacing, value });
            }
            KeyCode::Char('a') if self.focus == Focus::Destinations => {
                self.input = Some(InputMode::Destination {
                    replacing: None,
                    value: String::new(),
                });
            }
            KeyCode::Delete | KeyCode::Backspace
                if self.focus == Focus::Destinations
                    && !self.destinations.is_empty() =>
            {
                let mut candidate = self.destinations.clone();
                candidate.remove(self.destination_index);
                return EditorAction::Request(
                    OperationRequest::ValidateDestinations(candidate),
                );
            }
            KeyCode::Char('p') if self.focus == Focus::Available => {
                self.input = Some(InputMode::CustomPath(String::new()));
            }
            KeyCode::Char('r') if self.focus == Focus::Available => {
                return EditorAction::Request(
                    OperationRequest::DiscoverIdentities,
                );
            }
            KeyCode::Char('+') => {
                let requested = self
                    .lifetime_seconds
                    .saturating_add(LIFETIME_STEP_SECONDS)
                    .min(MAX_LIFETIME_SECONDS);
                return EditorAction::Request(OperationRequest::SetLifetime(
                    requested,
                ));
            }
            KeyCode::Char('-') => {
                let requested = self
                    .lifetime_seconds
                    .saturating_sub(LIFETIME_STEP_SECONDS)
                    .max(MIN_LIFETIME_SECONDS);
                return EditorAction::Request(OperationRequest::SetLifetime(
                    requested,
                ));
            }
            KeyCode::Char('d') => {
                return EditorAction::Request(OperationRequest::Disable);
            }
            KeyCode::Esc => return EditorAction::Back,
            _ => {}
        }
        EditorAction::Stay
    }

    fn handle_input(&mut self, code: KeyCode) -> EditorAction {
        match code {
            KeyCode::Esc => {
                self.input = None;
                self.status = "Input cancelled.".into();
            }
            KeyCode::Backspace => match self.input.as_mut() {
                Some(InputMode::CustomPath(value))
                | Some(InputMode::Destination { value, .. }) => {
                    value.pop();
                }
                None => {}
            },
            KeyCode::Enter => {
                let Some(input) = self.input.take() else {
                    return EditorAction::Stay;
                };
                match input {
                    InputMode::CustomPath(value) => {
                        if value.trim().is_empty() {
                            self.error =
                                Some("Enter a key path or press Esc.".into());
                            self.input = Some(InputMode::CustomPath(value));
                        } else {
                            return EditorAction::Request(
                                OperationRequest::CapturePath(value),
                            );
                        }
                    }
                    InputMode::Destination { replacing, value } => {
                        let destination = value.trim().to_string();
                        if destination.is_empty() {
                            self.error = Some(
                                "Destination cannot be empty; press Esc to cancel."
                                    .into(),
                            );
                            self.input = Some(InputMode::Destination {
                                replacing,
                                value,
                            });
                        } else {
                            let mut candidate = self.destinations.clone();
                            if let Some(index) = replacing {
                                candidate[index] = destination;
                            } else {
                                candidate.push(destination);
                            }
                            candidate.sort();
                            candidate.dedup();
                            return EditorAction::Request(
                                OperationRequest::ValidateDestinations(
                                    candidate,
                                ),
                            );
                        }
                    }
                }
            }
            KeyCode::Char(character) => match self.input.as_mut() {
                Some(InputMode::CustomPath(value))
                | Some(InputMode::Destination { value, .. })
                    if value.chars().count() < MAX_INPUT_CHARS =>
                {
                    // Text fields consume every printable character, including
                    // q and capability shortcuts, before global handling.
                    value.push(character);
                }
                _ => {}
            },
            _ => {}
        }
        EditorAction::Stay
    }

    fn toggle_available(&mut self) -> EditorAction {
        let Some(identity) = self.identities.get(self.available_index) else {
            return EditorAction::Stay;
        };
        if !identity.selected {
            return EditorAction::Request(
                OperationRequest::SetIdentitySelected {
                    fingerprint: identity.fingerprint.clone(),
                    selected: true,
                },
            );
        }
        EditorAction::Request(OperationRequest::SetIdentitySelected {
            fingerprint: identity.fingerprint.clone(),
            selected: false,
        })
    }

    fn remove_selected(&self) -> EditorAction {
        let selected = self.selected_identities();
        let Some(identity) = selected.get(self.selected_index) else {
            return EditorAction::Stay;
        };
        EditorAction::Request(OperationRequest::SetIdentitySelected {
            fingerprint: identity.fingerprint.clone(),
            selected: false,
        })
    }

    fn selected_identities(&self) -> Vec<&IdentityRow> {
        self.identities
            .iter()
            .filter(|identity| identity.selected)
            .collect()
    }

    fn focus_next(&mut self) {
        self.focus = match self.focus {
            Focus::Available => Focus::Selected,
            Focus::Selected => Focus::Destinations,
            Focus::Destinations => Focus::Available,
        };
    }

    fn focus_previous(&mut self) {
        self.focus = match self.focus {
            Focus::Available => Focus::Destinations,
            Focus::Selected => Focus::Available,
            Focus::Destinations => Focus::Selected,
        };
    }

    fn move_selection(&mut self, delta: isize) {
        let (selected, len) = match self.focus {
            Focus::Available => {
                (&mut self.available_index, self.identities.len())
            }
            Focus::Selected => (
                &mut self.selected_index,
                self.identities.iter().filter(|i| i.selected).count(),
            ),
            Focus::Destinations => {
                (&mut self.destination_index, self.destinations.len())
            }
        };
        if len == 0 {
            *selected = 0;
            return;
        }
        *selected = if delta < 0 {
            selected.saturating_sub(delta.unsigned_abs())
        } else {
            selected.saturating_add(delta as usize).min(len - 1)
        };
    }

    fn set_selection(&mut self, requested: usize) {
        let (selected, len) = match self.focus {
            Focus::Available => {
                (&mut self.available_index, self.identities.len())
            }
            Focus::Selected => (
                &mut self.selected_index,
                self.identities.iter().filter(|i| i.selected).count(),
            ),
            Focus::Destinations => {
                (&mut self.destination_index, self.destinations.len())
            }
        };
        *selected = requested.min(len.saturating_sub(1));
    }

    pub(super) fn apply_identity_selected(
        &mut self,
        fingerprint: &str,
        selected: bool,
    ) {
        if let Some(identity) = self
            .identities
            .iter_mut()
            .find(|identity| identity.fingerprint == fingerprint)
        {
            identity.selected = selected;
            self.status = if selected {
                "Identity selected. Full host SSH will be disabled.".into()
            } else {
                "Identity removed.".into()
            };
        }
        self.clamp_indices();
    }

    pub(super) fn apply_discovered_identities(
        &mut self,
        mut identities: Vec<IdentityRow>,
    ) {
        for identity in &mut identities {
            if self.identities.iter().any(|existing| {
                existing.fingerprint == identity.fingerprint
                    && existing.selected
            }) {
                identity.selected = true;
            }
        }
        for selected in
            self.identities.iter().filter(|identity| identity.selected)
        {
            if !identities
                .iter()
                .any(|identity| identity.fingerprint == selected.fingerprint)
            {
                identities.push(selected.clone());
            }
        }
        let mut fingerprints = BTreeSet::new();
        identities.retain(|identity| {
            fingerprints.insert(identity.fingerprint.clone())
        });
        identities
            .sort_by(|left, right| left.public_path.cmp(&right.public_path));
        self.identities = identities;
        self.status = "Available identities refreshed.".into();
        self.clamp_indices();
    }

    pub(super) fn apply_captured_identity(&mut self, row: IdentityRow) {
        if let Some(existing) = self
            .identities
            .iter_mut()
            .find(|identity| identity.fingerprint == row.fingerprint)
        {
            *existing = row;
        } else {
            self.identities.push(row);
            self.identities.sort_by(|left, right| {
                left.public_path.cmp(&right.public_path)
            });
        }
        self.status = "Identity captured and selected.".into();
        self.clamp_indices();
    }

    pub(super) fn apply_destinations(&mut self, destinations: Vec<String>) {
        self.destinations = destinations;
        self.destination_index = self
            .destination_index
            .min(self.destinations.len().saturating_sub(1));
        self.status = "Destination constraints updated.".into();
    }

    pub(super) fn apply_lifetime(&mut self, seconds: u32) {
        self.lifetime_seconds =
            seconds.clamp(MIN_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS);
        self.status = "Key lifetime updated.".into();
    }

    pub(super) fn apply_error(&mut self, message: String) {
        self.error = Some(message);
    }

    fn clamp_indices(&mut self) {
        self.available_index = self
            .available_index
            .min(self.identities.len().saturating_sub(1));
        self.selected_index = self
            .selected_index
            .min(self.selected_identities().len().saturating_sub(1));
    }
}

pub(super) fn render(frame: &mut Frame, editor: &mut Editor) {
    let [header, content, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(6),
    ])
    .areas(frame.area());
    render_header(frame, editor, header);

    let (available_area, selected_area, destinations_area, security_area) =
        if frame.area().width >= WIDE_LAYOUT_WIDTH {
            let [available, policy, security] = Layout::horizontal([
                Constraint::Percentage(38),
                Constraint::Percentage(29),
                Constraint::Percentage(33),
            ])
            .areas(content);
            let [selected, destinations] = Layout::vertical([
                Constraint::Percentage(45),
                Constraint::Percentage(55),
            ])
            .areas(policy);
            (available, selected, destinations, security)
        } else {
            let [available, selected, destinations, security] =
                Layout::vertical([
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                    Constraint::Percentage(22),
                    Constraint::Percentage(28),
                ])
                .areas(content);
            (available, selected, destinations, security)
        };
    render_available(frame, editor, available_area);
    render_selected(frame, editor, selected_area);
    render_destinations(frame, editor, destinations_area);
    render_security_detail(frame, editor, security_area);
    render_footer(frame, editor, footer);
}

fn render_header(frame: &mut Frame, editor: &Editor, area: Rect) {
    let security = if editor.is_complete() {
        Span::styled(
            "READY — selected-key SSH is destination constrained",
            allowed(editor),
        )
    } else {
        Span::styled("INCOMPLETE — launch and save are blocked", danger(editor))
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Selected SSH keys — fresh agent",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(security),
        ]),
        area,
    );
}

fn render_available(frame: &mut Frame, editor: &mut Editor, area: Rect) {
    let items = editor.identities.iter().map(|identity| {
        let (mark, mark_style) = if identity.selected {
            ("✓", allowed(editor))
        } else {
            ("○", muted(editor))
        };
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!("{mark} "), mark_style),
                Span::raw(escape_control_bytes(&identity.public_path)),
            ]),
            Line::from(vec![
                Span::styled(
                    format!(
                        "  {}",
                        escape_control_bytes(&identity.fingerprint)
                    ),
                    muted(editor),
                ),
                Span::raw(if identity.comment.is_empty() {
                    String::new()
                } else {
                    format!("  {}", escape_control_bytes(&identity.comment))
                }),
            ]),
        ])
    });
    let mut state =
        ListState::default().with_selected(Some(editor.available_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(focused_block(
                " Available public identities ",
                editor.focus == Focus::Available,
            ))
            .highlight_symbol("> ")
            .highlight_style(focus_style(editor)),
        area,
        &mut state,
    );
}

fn render_selected(frame: &mut Frame, editor: &mut Editor, area: Rect) {
    let selected = editor.selected_identities();
    let items = selected.iter().map(|identity| {
        ListItem::new(Line::from(vec![
            Span::styled("✓ ", allowed(editor)),
            Span::raw(format!(
                "{}  {}",
                escape_control_bytes(&identity.fingerprint),
                escape_control_bytes(&identity.comment)
            )),
        ]))
    });
    let mut state =
        ListState::default().with_selected(Some(editor.selected_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(focused_block(
                &format!(
                    " Selected • lifetime {}s (+/-) ",
                    editor.lifetime_seconds
                ),
                editor.focus == Focus::Selected,
            ))
            .highlight_symbol("> ")
            .highlight_style(focus_style(editor)),
        area,
        &mut state,
    );
}

fn render_destinations(frame: &mut Frame, editor: &mut Editor, area: Rect) {
    let items = editor
        .destinations
        .iter()
        .map(|destination| ListItem::new(escape_control_bytes(destination)));
    let mut state =
        ListState::default().with_selected(Some(editor.destination_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(focused_block(
                " Required destinations ",
                editor.focus == Focus::Destinations,
            ))
            .highlight_symbol("> ")
            .highlight_style(focus_style(editor)),
        area,
        &mut state,
    );
}

fn security_detail(editor: &Editor) -> String {
    let destinations = if editor.destinations.is_empty() {
        "none — policy remains INCOMPLETE".into()
    } else {
        editor
            .destinations
            .iter()
            .map(|destination| escape_control_bytes(destination))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "Selected-key SSH\n\
Shares\nA fresh SSH agent containing only the keys you select. Private-key files and your normal host agent stay outside the jail.\n\n\
Can access\nAccounts that accept those keys, only at verified destinations: {}\n\n\
Key lifetime\n{} seconds, then the fresh agent drops them.\n\n\
Also needed\nUnrestricted network access (OPEN).\n\n\
Safety\nLaunch is refused if destination or host-key checks cannot be enforced.\n\n\
Risk\nThe jail can authenticate as accounts accepted by the selected keys for this run.",
        destinations, editor.lifetime_seconds
    )
}

fn render_security_detail(frame: &mut Frame, editor: &mut Editor, area: Rect) {
    let detail = security_detail(editor);
    let inner_width = area.width.saturating_sub(2).max(1);
    let total = wrapped_line_count(&detail, inner_width);
    let visible = area.height.saturating_sub(2).max(1);
    let max_scroll = total.saturating_sub(visible);
    editor.required_security_scroll = max_scroll;
    editor.security_scroll = editor.security_scroll.min(max_scroll);
    let last = editor.security_scroll.saturating_add(visible).min(total);
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: false })
            .scroll((editor.security_scroll, 0))
            .block(
                Block::default()
                    .title(format!(
                        " Security detail • lines {}–{}/{} • PgUp/PgDn ",
                        editor.security_scroll + 1,
                        last,
                        total
                    ))
                    .borders(Borders::ALL),
            ),
        area,
    );
}

fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| line.chars().count().max(1).div_ceil(width))
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn render_footer(frame: &mut Frame, editor: &Editor, area: Rect) {
    let input = match &editor.input {
        Some(InputMode::CustomPath(value)) => {
            format!(
                "Key path (private or .pub): {}█",
                escape_control_bytes(value)
            )
        }
        Some(InputMode::Destination { value, .. }) => {
            format!("Required destination: {}█", escape_control_bytes(value))
        }
        None => String::new(),
    };
    let status = editor
        .error
        .as_deref()
        .map(|error| Line::from(Span::styled(error, danger(editor))))
        .unwrap_or_else(|| {
            if input.is_empty() {
                Line::from(editor.status.clone())
            } else {
                Line::from(input)
            }
        });
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Tab changes pane  •  arrows move  •  Space selects/removes  •  PgUp/PgDn security detail"),
            Line::from("p path  •  a add destination  •  e edit  •  Del remove  •  +/- lifetime  •  d disable"),
            status,
        ])
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::TOP)),
        area,
    );
}

fn focused_block(title: &str, focused: bool) -> Block<'_> {
    let style = if focused {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::default()
        .title(title)
        .title_style(style)
        .borders(Borders::ALL)
}

fn muted(editor: &Editor) -> Style {
    if editor.use_color {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn allowed(editor: &Editor) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if editor.use_color {
        style.fg(Color::Green)
    } else {
        style
    }
}

fn danger(editor: &Editor) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if editor.use_color {
        style.fg(Color::Red)
    } else {
        style
    }
}

fn focus_style(editor: &Editor) -> Style {
    let style =
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
    if editor.use_color {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn identity(name: &str, selected: bool) -> IdentityRow {
        IdentityRow {
            public_path: format!("/home/user/.ssh/{name}.pub"),
            fingerprint: format!("SHA256:{name}"),
            comment: format!("{name}@example"),
            selected,
        }
    }

    fn rendered_at(editor: &mut Editor, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, editor)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn rendered(editor: &mut Editor) -> String {
        rendered_at(editor, 140, 36)
    }

    #[test]
    fn incomplete_policy_is_unmistakable_and_private_material_never_renders() {
        let mut editor = Editor::new(
            vec![identity("id_work", false)],
            Vec::new(),
            3600,
            false,
        );
        let output = rendered(&mut editor);
        assert!(output.contains("INCOMPLETE"), "{output}");
        assert!(output.contains("id_work.pub"), "{output}");
        assert!(output.contains("SHA256:id_work"), "{output}");
        assert!(!output.contains("PRIVATE KEY"), "{output}");
        assert!(!output.contains("SSH_AUTH_SOCK"), "{output}");
    }

    #[test]
    fn security_detail_names_every_selected_key_boundary() {
        let editor = Editor::new(
            vec![identity("id_work", true)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        let detail = security_detail(&editor);
        for expected in [
            "fresh SSH agent",
            "Private-key files",
            "normal host agent stay outside",
            "Accounts that accept those keys",
            "3600 seconds",
            "git@example.com",
            "Unrestricted network access (OPEN)",
            "Risk",
        ] {
            assert!(detail.contains(expected), "missing {expected}: {detail}");
        }
    }

    #[test]
    fn q_is_text_while_destination_input_has_focus() {
        let mut editor = Editor::new(Vec::new(), Vec::new(), 3600, false);
        editor.focus = Focus::Destinations;
        assert_eq!(editor.handle_key(KeyCode::Char('a')), EditorAction::Stay);
        assert_eq!(editor.handle_key(KeyCode::Char('q')), EditorAction::Stay);
        assert_eq!(editor.handle_key(KeyCode::Char('x')), EditorAction::Stay);
        assert_eq!(
            editor.handle_key(KeyCode::Enter),
            EditorAction::Request(OperationRequest::ValidateDestinations(
                vec!["qx".into()]
            ))
        );
    }

    #[test]
    fn identity_selection_is_an_immediate_toggle() {
        let mut editor = Editor::new(
            vec![identity("id_work", false)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        assert_eq!(
            editor.handle_key(KeyCode::Char(' ')),
            EditorAction::Request(OperationRequest::SetIdentitySelected {
                fingerprint: "SHA256:id_work".into(),
                selected: true,
            })
        );
        let _ = rendered_at(&mut editor, 64, 40);
        assert_eq!(editor.handle_key(KeyCode::End), EditorAction::Stay);
        let detail = rendered_at(&mut editor, 64, 40);
        assert!(detail.contains("Security detail"), "{detail}");
        assert!(detail.contains("Risk"), "{detail}");
        editor.apply_identity_selected("SHA256:id_work", true);
        assert!(editor.is_complete());
        assert!(editor.status.contains("Full host SSH will be disabled"));
    }

    #[test]
    fn removing_selected_identity_is_immediate_authority_reduction() {
        let mut editor = Editor::new(
            vec![identity("id_work", true)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        assert_eq!(
            editor.handle_key(KeyCode::Char(' ')),
            EditorAction::Request(OperationRequest::SetIdentitySelected {
                fingerprint: "SHA256:id_work".into(),
                selected: false,
            })
        );
    }

    #[test]
    fn security_disclosure_remains_scrollable_without_confirmation() {
        let mut editor = Editor::new(
            vec![identity("id_work", false)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        assert!(matches!(
            editor.handle_key(KeyCode::Char(' ')),
            EditorAction::Request(OperationRequest::SetIdentitySelected {
                selected: true,
                ..
            })
        ));
        let _ = rendered_at(&mut editor, 64, 40);
        for _ in 0..8 {
            assert_eq!(
                editor.handle_key(KeyCode::PageDown),
                EditorAction::Stay
            );
        }
        let output = rendered_at(&mut editor, 64, 40);
        assert!(output.contains("Security detail"), "{output}");
        assert!(output.contains("PgUp/PgDn"), "{output}");
        assert!(output.contains("Risk"), "{output}");
    }

    #[test]
    fn narrow_layout_stacks_all_zones_and_keeps_security_status_visible() {
        let mut editor = Editor::new(
            vec![identity("id_work", true)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        let output = rendered_at(&mut editor, 64, 40);
        for expected in [
            "Available public identities",
            "Selected",
            "Required destinations",
            "Security detail",
            "READY",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
    }

    #[test]
    fn destination_removal_revalidates_complete_candidate() {
        let mut editor = Editor::new(
            vec![identity("id_work", true)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        editor.focus = Focus::Destinations;
        assert_eq!(
            editor.handle_key(KeyCode::Delete),
            EditorAction::Request(OperationRequest::ValidateDestinations(
                vec![]
            ))
        );
        assert!(editor.is_complete());
        editor.apply_destinations(Vec::new());
        assert!(!editor.is_complete());
    }

    #[test]
    fn escape_closes_input_before_leaving_editor() {
        let mut editor = Editor::new(Vec::new(), Vec::new(), 3600, false);
        assert_eq!(editor.handle_key(KeyCode::Char('p')), EditorAction::Stay);
        assert_eq!(editor.handle_key(KeyCode::Esc), EditorAction::Stay);
        assert_eq!(editor.handle_key(KeyCode::Esc), EditorAction::Back);
    }

    #[test]
    fn discovery_refresh_preserves_selected_identity_without_duplicates() {
        let mut editor = Editor::new(
            vec![identity("id_work", true)],
            vec!["git@example.com".into()],
            3600,
            false,
        );
        editor.apply_discovered_identities(vec![
            identity("id_work", false),
            identity("id_work", false),
            identity("id_personal", false),
        ]);
        assert_eq!(editor.identities.len(), 2);
        assert!(
            editor
                .identities
                .iter()
                .find(|identity| identity.fingerprint == "SHA256:id_work")
                .is_some_and(|identity| identity.selected)
        );
    }

    #[test]
    fn captured_identity_is_selected_without_a_second_confirmation() {
        let mut editor = Editor::new(Vec::new(), Vec::new(), 3600, false);
        editor.apply_captured_identity(identity("id_custom", true));
        assert_eq!(
            editor.selected_fingerprints(),
            vec!["SHA256:id_custom".to_string()]
        );
        assert!(editor.status.contains("captured and selected"));
    }
}
