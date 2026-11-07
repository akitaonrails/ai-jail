use super::app::{
    AccessPreset, App, BuiltinProtection, CapabilityId, ConfirmMode,
    MIN_HEIGHT, MIN_WIDTH, Screen,
};
use super::wrapper::{Decision, resource_label};
use crate::output::escape_control_bytes;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Wrap,
};

const WIDE_WIDTH: u16 = 96;
/// Rows the access header may take when it wraps the shared-policy line.
/// `MIN_HEIGHT` leaves room for this beside the other fixed zones.
const MAX_HEADER_HEIGHT: u16 = 8;

/// Rows `lines` need when word-wrapped to `width` columns. Word wrapping can
/// need one row more than the character count suggests, so a line that
/// wraps reserves that extra row.
fn wrapped_rows(lines: &[Line<'_>], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows: usize = lines
        .iter()
        .map(|line| match line.width() {
            w if w <= width => 1,
            w => w.div_ceil(width) + 1,
        })
        .sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

pub(super) fn render(frame: &mut Frame, app: &mut App<'_>) {
    render_screen(frame, app);
    if let Some(dialog) = &app.exit_dialog {
        dialog.render(frame, app.use_color);
    }
}

fn render_screen(frame: &mut Frame, app: &mut App<'_>) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area.width, area.height);
        return;
    }
    if app.screen == Screen::WrapperRequests {
        render_wrapper_requests(frame, app);
        return;
    }
    if app.screen == Screen::Additional {
        render_additional(frame, app);
        return;
    }
    match app.screen {
        Screen::RestrictedSsh => {
            if let Some(editor) = &mut app.ssh {
                super::ssh::render(frame, editor);
            }
            return;
        }
        Screen::Environment => {
            if let Some(selector) = &app.environment {
                super::environment::render(frame, selector, app.use_color);
            }
            return;
        }
        Screen::DirectoryPicker { .. } => {
            if let Some(browser) = &app.directory {
                super::directory::render(frame, browser, app.use_color);
            }
            return;
        }
        _ => {}
    }
    if app.screen != Screen::Access {
        render_subscreen(frame, app);
        return;
    }

    let mut header = vec![
        Line::from(Span::styled("AI-JAIL", brand(app))),
        Line::from(vec![
            Span::styled("Project  ", muted(app)),
            Span::styled(
                compact_project_path(&app.project),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!("Config   {}", compact_home_path(&app.profile_path)),
            muted(app),
        )),
    ];
    // The shared-policy disclosure comes before the root, and the header
    // wraps and grows to fit, so a long path never truncates it.
    let shared_policy = app.policy_root.is_some();
    if let Some(root) = &app.policy_root {
        header.push(Line::from(vec![
            Span::styled("Policy   ", muted(app)),
            Span::raw(super::super::messages::POLICY_SHARED),
            Span::raw(format!(" \u{b7} {}", compact_home_path(root))),
        ]));
    }
    let header_height = if shared_policy {
        (wrapped_rows(&header, area.width) + 1).clamp(4, MAX_HEADER_HEIGHT)
    } else {
        4
    };

    let [
        header_area,
        preset_area,
        content_area,
        cli_area,
        footer_area,
    ] = Layout::vertical([
        Constraint::Length(header_height),
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(4),
        Constraint::Length(3),
    ])
    .areas(area);

    let header = Paragraph::new(header);
    let header = if shared_policy {
        header.wrap(Wrap { trim: false })
    } else {
        header
    };
    frame.render_widget(header, header_area);
    render_presets(frame, app, preset_area);

    let [access_area, protections_area, detail_area] =
        if area.width >= WIDE_WIDTH {
            let [navigation_area, detail_area] = Layout::horizontal([
                Constraint::Percentage(42),
                Constraint::Percentage(58),
            ])
            .areas(content_area);
            let [access_area, protections_area] =
                Layout::vertical([Constraint::Min(10), Constraint::Length(7)])
                    .areas(navigation_area);
            [access_area, protections_area, detail_area]
        } else {
            Layout::vertical([
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(4),
            ])
            .areas(content_area)
        };
    render_list(frame, app, access_area);
    render_protections(frame, app, protections_area);
    render_detail(frame, app, detail_area);
    render_cli_equivalent(frame, app, cli_area);
    render_footer(frame, app, footer_area);
    if let Some(confirm) = &app.confirmation {
        match confirm {
            ConfirmMode::Open { dialog, .. }
            | ConfirmMode::MostlyOpen { dialog }
            | ConfirmMode::AdditionalOpen { dialog, .. }
            | ConfirmMode::SaveWithGithub { dialog, .. } => {
                dialog.render(frame, app.use_color);
            }
        }
    }
}

fn render_additional(frame: &mut Frame, app: &mut App<'_>) {
    let area = frame.area();
    let [header, content, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(4),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Additional capabilities",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("Nothing on this screen is enabled by a preset."),
        ]),
        header,
    );
    let [list_area, detail_area] = if area.width >= WIDE_WIDTH {
        Layout::horizontal([
            Constraint::Percentage(42),
            Constraint::Percentage(58),
        ])
        .areas(content)
    } else {
        Layout::vertical([Constraint::Percentage(45), Constraint::Min(4)])
            .areas(content)
    };
    let Some(state) = &app.additional else {
        return;
    };
    let items = state.capabilities.iter().map(|capability| {
        let enabled = capability.enabled(&app.selection.additional);
        let open = capability.risk() == super::super::Risk::Open;
        let marker = if enabled { "✓" } else { "○" };
        let marker_style = if enabled && open {
            danger(app)
        } else if enabled {
            granted(app)
        } else {
            muted(app)
        };
        let mut spans = vec![
            Span::styled(format!("{marker} "), marker_style),
            Span::raw(capability.label()),
        ];
        if open {
            spans.push(Span::styled(
                if enabled { "  ! OPEN" } else { "  ✓ CLOSED" },
                if enabled { danger(app) } else { closed(app) },
            ));
        }
        ListItem::new(Line::from(spans))
    });
    let selected = state.selected();
    let mut list_state =
        ListState::default().with_selected(Some(state.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Capabilities ")
                    .borders(Borders::ALL),
            )
            .highlight_symbol("▶ ")
            .highlight_style(focus(app)),
        list_area,
        &mut list_state,
    );
    frame.render_widget(
        Paragraph::new(selected.detail())
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(format!(" Details — {} ", selected.label()))
                    .borders(Borders::ALL),
            ),
        detail_area,
    );
    let feedback = if state.feedback.is_empty() {
        "↑/↓ move  •  PgUp/PgDn jump  •  Space/Enter toggle  •  Esc back  •  q exit"
    } else {
        &state.feedback
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(feedback),
            Line::from(
                "OPEN grants require an explicit dialog when they are enabled.",
            ),
        ])
        .block(Block::default().borders(Borders::TOP)),
        footer,
    );
    if let Some(ConfirmMode::AdditionalOpen { dialog, .. }) = &app.confirmation
    {
        dialog.render(frame, app.use_color);
    }
}

fn render_presets(
    frame: &mut Frame,
    app: &App<'_>,
    area: ratatui::layout::Rect,
) {
    let active = app.active_preset();
    let mut line = Vec::new();
    for (index, preset) in AccessPreset::ALL.into_iter().enumerate() {
        let focused = app.preset_focus && app.preset_cursor == index;
        let applied = active == Some(preset)
            && (!app.preset_focus || !app.preset_preview);
        let marker = if focused {
            "▶"
        } else if applied {
            "✓"
        } else {
            " "
        };
        let label = if matches!(
            preset,
            AccessPreset::Developer | AccessPreset::MostlyOpen
        ) {
            format!(" {marker} ⚠ {} ", preset.label())
        } else {
            format!(" {marker} {} ", preset.label())
        };
        let style = if focused {
            focus(app)
        } else if applied {
            match preset {
                AccessPreset::FullyClosed => closed(app),
                AccessPreset::Developer => danger(app),
                AccessPreset::MostlyOpen => danger(app),
            }
        } else {
            muted(app)
        };
        line.push(Span::styled(label, style));
        line.push(Span::raw(" "));
    }
    if active.is_none() && !app.preset_preview {
        line.push(Span::styled(" ✓ Custom ", granted(app)));
    } else if app.preset_focus && app.preset_preview {
        line.push(Span::styled(" PREVIEW — not applied ", danger(app)));
    }
    frame.render_widget(
        Paragraph::new(Line::from(line)).block(
            Block::default()
                .title(" Presets • ←/→ preview • Enter/Space apply ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_wrapper_requests(frame: &mut Frame, app: &mut App<'_>) {
    let approve_style = granted(app);
    let reject_style = closed(app);
    let undecided_style = muted(app);
    let list_focus_style = focus(app);
    let Some(review) = &mut app.wrapper else {
        return;
    };
    let [banner_area, content_area, footer_area] = Layout::vertical([
        Constraint::Length(6),
        Constraint::Min(10),
        Constraint::Length(5),
    ])
    .areas(frame.area());
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Wrapper-staged access requests",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(
                "APPROVE proposes the fully disclosed access; REJECT keeps it absent.",
            ),
            Line::from("Prior wrapper-derived access was removed from this draft. Overlapping manual access can be re-enabled explicitly."),
        ])
        .wrap(Wrap { trim: true }),
        banner_area,
    );
    let [list_area, detail_area] = if content_area.width >= WIDE_WIDTH {
        Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .areas(content_area)
    } else {
        Layout::vertical([
            Constraint::Percentage(38),
            Constraint::Percentage(62),
        ])
        .areas(content_area)
    };
    let items = review.items.iter().enumerate().map(|(index, request)| {
        let (status, style) = match review.decisions[index] {
            Some(Decision::Approve) => ("✓ APPROVE", approve_style),
            Some(Decision::Reject) => ("✓ REJECT", reject_style),
            None => ("○ UNDECIDED", undecided_style),
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{status}  "), style),
            Span::raw(resource_label(request)),
        ]))
    });
    let mut state = ListState::default().with_selected(Some(review.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" Requests ").borders(Borders::ALL))
            .highlight_symbol("▶ ")
            .highlight_style(list_focus_style),
        list_area,
        &mut state,
    );
    let request = review.selected_request();
    let prior = if review.was_approved(request) {
        "Previously approved; choose again for this review."
    } else {
        "Not previously approved."
    };
    let disclosure = review.disclosure.as_deref().unwrap_or(
        "Press a to validate this staged request and reveal its complete access disclosure before deciding.",
    );
    let detail = format!(
        "Requested by: {}\nResource: {}\n\nUse when\n{}\n\n{prior}\n\n{disclosure}",
        escape_control_bytes(&request.approval.requester),
        resource_label(request),
        escape_control_bytes(&request.reason),
    );
    let total =
        wrapped_line_count(&detail, detail_area.width.saturating_sub(2));
    let visible = detail_area.height.saturating_sub(2).max(1);
    let max_scroll = total.saturating_sub(visible);
    review.set_required_detail_scroll(max_scroll);
    let scroll = review.detail_scroll.min(max_scroll);
    let last = scroll.saturating_add(visible).min(total);
    frame.render_widget(
        Paragraph::new(detail)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(format!(
                        " Complete disclosure • lines {}–{}/{} • PgUp/PgDn ",
                        scroll + 1,
                        last,
                        total
                    ))
                    .borders(Borders::ALL),
            ),
        detail_area,
    );
    let approval_prompt = review.approval_prompt();
    let feedback = if !review.feedback.is_empty() {
        &review.feedback
    } else {
        approval_prompt.as_deref().unwrap_or(
            "a validate/approve  •  r reject  •  ↑/↓ move  •  PgUp/PgDn disclosure  •  Enter continue  •  q cancel",
        )
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(feedback),
            Line::from("Opening this screen or revealing a disclosure approves nothing."),
        ])
        .block(Block::default().borders(Borders::TOP)),
        footer_area,
    );
    if let Some(dialog) = review.confirmation_dialog() {
        dialog.render(frame, app.use_color);
    }
}

fn render_list(
    frame: &mut Frame,
    app: &mut App<'_>,
    area: ratatui::layout::Rect,
) {
    let items = CapabilityId::ALL.into_iter().map(|capability| {
        let has_state = app.grant(capability).is_some()
            || capability == CapabilityId::RestrictedSsh;
        let enabled = has_state && app.displayed_enabled(capability);
        let marker = if has_state {
            if enabled { "✓" } else { "○" }
        } else {
            "•"
        };
        let marker_style = if app
            .grant(capability)
            .is_some_and(|grant| grant.risk == super::super::Risk::Open)
            && enabled
        {
            danger(app)
        } else if enabled {
            granted(app)
        } else {
            muted(app)
        };
        let mut spans = vec![
            Span::styled(format!(" {} ", capability.key()), muted(app)),
            Span::styled(format!("{marker} "), marker_style),
            Span::raw(capability.label()),
        ];
        if app
            .grant(capability)
            .is_some_and(|grant| grant.risk == super::super::Risk::Open)
        {
            if enabled {
                spans.push(Span::styled("  ! OPEN", danger(app)));
            } else {
                spans.push(Span::styled("  ✓ CLOSED", closed(app)));
            }
        }
        ListItem::new(Line::from(spans))
    });
    let access_focused = !app.preset_focus && !app.protection_focus;
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Access choices ")
                .borders(Borders::ALL),
        )
        .highlight_symbol(if access_focused { "▶ " } else { "  " })
        .highlight_style(if access_focused {
            focus(app)
        } else {
            Style::default()
        });
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_protections(
    frame: &mut Frame,
    app: &mut App<'_>,
    area: ratatui::layout::Rect,
) {
    let items = BuiltinProtection::ALL.into_iter().map(|protection| {
        ListItem::new(Line::from(vec![
            Span::styled("◆ ", closed(app)),
            Span::raw(protection.label()),
        ]))
    });
    let mut state =
        ListState::default().with_selected(Some(app.protection_selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Always enforced • Tab to inspect ")
                    .borders(Borders::ALL),
            )
            .highlight_symbol(if app.protection_focus { "▶ " } else { "  " })
            .highlight_style(if app.protection_focus {
                focus(app)
            } else {
                Style::default()
            }),
        area,
        &mut state,
    );
}

fn render_detail(
    frame: &mut Frame,
    app: &App<'_>,
    area: ratatui::layout::Rect,
) {
    if app.protection_focus {
        let protection = app.selected_protection();
        frame.render_widget(
            Paragraph::new(protection.detail())
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .title(format!(
                            " Built-in guarantee — {} ",
                            protection.label()
                        ))
                        .borders(Borders::ALL),
                ),
            area,
        );
        return;
    }
    let capability = app.selected_capability();
    let detail = app.detail(capability);
    let total = wrapped_line_count(&detail, area.width.saturating_sub(2));
    let paragraph =
        Paragraph::new(highlighted_detail(app, capability, &detail))
            .wrap(Wrap { trim: false });
    let visible = area.height.saturating_sub(2).max(1);
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.detail_scroll.min(max_scroll);
    let last = scroll.saturating_add(visible).min(total);
    frame.render_widget(
        paragraph.scroll((scroll, 0)).block(
            Block::default()
                .title(format!(
                    " Details — {} • lines {}–{}/{} • PgUp/PgDn ",
                    capability.label(),
                    scroll + 1,
                    last,
                    total
                ))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn highlighted_detail(
    app: &App<'_>,
    capability: CapabilityId,
    detail: &str,
) -> Text<'static> {
    Text::from(
        detail
            .lines()
            .map(|line| match capability {
                CapabilityId::Environment => line
                    .strip_prefix("• ")
                    .map(|name| {
                        Line::from(vec![
                            Span::raw("• "),
                            Span::styled(name.to_owned(), selected_value(app)),
                        ])
                    })
                    .unwrap_or_else(|| Line::from(line.to_owned())),
                CapabilityId::DirectoryAccess => {
                    ["• READ-ONLY  ", "• READ/WRITE "]
                        .into_iter()
                        .find_map(|prefix| {
                            line.strip_prefix(prefix).map(|path| {
                                Line::from(vec![
                                    Span::raw(prefix),
                                    Span::styled(
                                        path.to_owned(),
                                        selected_value(app),
                                    ),
                                ])
                            })
                        })
                        .unwrap_or_else(|| Line::from(line.to_owned()))
                }
                _ => Line::from(line.to_owned()),
            })
            .collect::<Vec<_>>(),
    )
}

fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| line.chars().count().max(1).div_ceil(width))
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn render_subscreen(frame: &mut Frame, app: &App<'_>) {
    let instruction = "Esc returns to access choices  •  q exits";
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                app.screen.title(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(app.screen.placeholder()),
            Line::from(""),
            Line::from(instruction),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(" ai-jail setup ")
                .borders(Borders::ALL),
        ),
        frame.area(),
    );
}

fn render_cli_equivalent(
    frame: &mut Frame,
    app: &mut App<'_>,
    area: ratatui::layout::Rect,
) {
    let text = app.cli_equivalent_display();
    let width = area.width.saturating_sub(2).max(1);
    let total = wrapped_line_count(&text, width);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .title(format!(
                    " CLI from defaults • y copy anywhere • {} line{} ",
                    total.max(1),
                    if total == 1 { "" } else { "s" }
                ))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_footer(
    frame: &mut Frame,
    app: &App<'_>,
    area: ratatui::layout::Rect,
) {
    let prompt = match &app.confirmation {
        Some(
            ConfirmMode::Open { .. }
            | ConfirmMode::MostlyOpen { .. }
            | ConfirmMode::AdditionalOpen { .. }
            | ConfirmMode::SaveWithGithub { .. },
        ) => Line::from(
            "Choose explicitly in the confirmation dialog; Cancel is selected by default.",
        ),
        None if app.preset_focus => Line::from(if app.preset_preview {
            "PREVIEW only — ←/→ chooses; Enter/Space applies; Tab/Esc changes focus only."
        } else {
            "Preset row focused — ←/→ previews; Enter/Space applies; Tab changes focus only."
        }),
        None if app.protection_focus => Line::from(
            "↑/↓ inspect guarantees  •  Tab presets  •  y copy CLI  •  Esc access choices",
        ),
        None if !app.feedback.is_empty() => Line::from(app.feedback.clone()),
        None => Line::from(
            "↑/↓ move  •  Space/Enter select  •  Tab next panel  •  y copy CLI  •  Esc/q exit",
        ),
    };
    frame.render_widget(
        Paragraph::new(vec![
            prompt,
            Line::from(Span::styled(
                "Repository-scoped forge access is configured separately.",
                muted(app),
            )),
        ])
        .block(Block::default().borders(Borders::TOP)),
        area,
    );
}

fn compact_project_path(path: &str) -> String {
    let components = path
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if components.len() > 2 {
        format!(
            "../{}/{}",
            components[components.len() - 2],
            components[components.len() - 1]
        )
    } else {
        path.to_string()
    }
}

fn compact_home_path(path: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return path.into();
    };
    let home = home.to_string_lossy();
    if path == home {
        "~".into()
    } else if let Some(suffix) = path.strip_prefix(home.as_ref()) {
        if suffix.starts_with('/') {
            return format!("~{suffix}");
        }
        path.into()
    } else {
        path.into()
    }
}

fn render_too_small(frame: &mut Frame, width: u16, height: u16) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Terminal too small",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "Current: {width}×{height}. Minimum: {MIN_WIDTH}×{MIN_HEIGHT}."
            )),
            Line::from("Resize the terminal to continue."),
            Line::from("q cancels  •  Esc goes back"),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(" ai-jail setup ")
                .borders(Borders::ALL),
        ),
        frame.area(),
    );
}

fn muted(app: &App<'_>) -> Style {
    if app.use_color {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn brand(app: &App<'_>) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

fn selected_value(app: &App<'_>) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

fn danger(app: &App<'_>) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Red)
    } else {
        style
    }
}

fn granted(app: &App<'_>) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Yellow)
    } else {
        style
    }
}

fn closed(app: &App<'_>) -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Green)
    } else {
        style
    }
}

fn focus(app: &App<'_>) -> Style {
    let style =
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
    if app.use_color {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::{RequestApproval, RequestSet, WrapperRequest};
    use crate::onboarding::Selection;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn buffer_text(width: u16, height: u16, app: &mut App<'_>) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn header_names_shared_policy_root_for_worktree() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/wt".into(),
            false,
            &Default::default(),
            &[],
        );
        app.policy_root = Some("/work/main".into());
        let rendered = buffer_text(160, 34, &mut app);
        assert!(rendered.contains("/work/main"));
        assert!(rendered.contains("shared with its linked worktrees"));
        assert!(!rendered.contains("AJ-"));
    }

    #[test]
    fn header_omits_policy_line_for_basename() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        let rendered = buffer_text(160, 34, &mut app);
        assert!(!rendered.contains(crate::onboarding::messages::POLICY_SHARED));
        assert!(!rendered.contains("shared with its linked worktrees"));
    }

    #[test]
    fn header_keeps_policy_disclosure_at_80_columns() {
        let mut selection = Selection::default();
        let root = format!("/home/developer/{}/main-checkout", "w".repeat(60));
        let mut app = App::new(
            &mut selection,
            "claude",
            format!("{root}__worktrees/feat-x"),
            false,
            &Default::default(),
            &[],
        );
        app.policy_root = Some(root);
        // 80x24 is below MIN_HEIGHT and renders the too-small screen, so the
        // 80-column case uses the minimum supported height.
        for width in [80, MIN_WIDTH] {
            let rendered = buffer_text(width, MIN_HEIGHT, &mut app);
            assert!(
                rendered.contains("shared with its linked worktrees"),
                "{rendered}"
            );
            assert!(rendered.contains("main-checkout"), "{rendered}");
            assert!(rendered.contains("Access choices"), "{rendered}");
            assert!(!rendered.contains("AJ-"));
        }
    }

    #[test]
    fn wide_view_keeps_choices_and_security_detail_visible() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("Access choices"));
        assert!(rendered.contains("Filtered model API access"));
        assert!(rendered.contains("Details — Filtered model API access"));
        assert!(rendered.contains("api.anthropic.com"));
        assert!(!rendered.contains("AJ-"));
    }

    #[test]
    fn first_run_view_explains_every_preselected_recommended_default() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            github: true,
            ..Selection::default()
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.set_recommended_baseline(true);
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("AI-JAIL"));
        assert!(rendered.contains("/work/project"));
        assert!(!rendered.contains("Repository files cannot grant access"));
        assert!(rendered.contains("For developers"));
        assert!(rendered.contains("Filtered model API access"));
        assert!(rendered.contains("harness login/state"));
        assert!(rendered.contains("Full host GitHub token"));
        assert!(rendered.contains("Dependency tools"));
        assert!(rendered.contains("Always enforced"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("Bubblewrap sandbox"));
        assert!(rendered.contains("✓"));
        assert!(rendered.contains("CLOSED"));
    }

    #[test]
    fn built_in_guarantees_are_focusable_and_replace_the_detail_panel() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/mnt/data/Projects/ai-memory".into(),
            false,
            &Default::default(),
            &[],
        );
        app.handle_key(crossterm::event::KeyCode::Tab);
        assert!(app.protection_focus);
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("../Projects/ai-memory"));
        assert!(rendered.contains("Built-in guarantee"));
        assert!(rendered.contains("Always enforced"));
        assert!(rendered.contains("every child process"));
        assert!(!rendered.contains("Configure claude"));
    }

    #[test]
    fn main_view_shows_granular_access_summaries_without_opening_editors() {
        let mut selection = Selection {
            env_names: vec!["GH_TOKEN".into()],
            ro_dirs: vec![std::path::PathBuf::from("/srv/reference")],
            rw_dirs: vec![std::path::PathBuf::from("/srv/output")],
            ..Selection::default()
        };
        selection.additional.audit_log = true;
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );

        app.selected = CapabilityId::ALL
            .iter()
            .position(|capability| *capability == CapabilityId::Environment)
            .unwrap();
        let environment = buffer_text(140, 34, &mut app);
        assert!(environment.contains("GH_TOKEN"));
        assert!(environment.contains("values hidden"));

        app.selected = CapabilityId::ALL
            .iter()
            .position(|capability| *capability == CapabilityId::DirectoryAccess)
            .unwrap();
        let directories = buffer_text(140, 34, &mut app);
        assert!(directories.contains("READ-ONLY  /srv/reference"));
        assert!(directories.contains("READ/WRITE /srv/output"));

        app.selected = CapabilityId::ALL
            .iter()
            .position(|capability| *capability == CapabilityId::Additional)
            .unwrap();
        let additional = buffer_text(140, 34, &mut app);
        assert!(additional.contains("ALLOWED  Local security audit log"));
        assert_eq!(app.screen, Screen::Access);
    }

    #[test]
    fn detail_highlights_selected_environment_names_and_directory_paths() {
        let mut selection = Selection {
            env_names: vec!["GH_TOKEN".into()],
            ro_dirs: vec![std::path::PathBuf::from("/srv/reference")],
            ..Selection::default()
        };
        let app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            true,
            &Default::default(),
            &[],
        );

        let environment = app.detail(CapabilityId::Environment);
        let environment =
            highlighted_detail(&app, CapabilityId::Environment, &environment);
        let env_span = &environment.lines[1].spans[1];
        assert_eq!(env_span.content, "GH_TOKEN");
        assert_eq!(env_span.style.fg, Some(Color::Cyan));
        assert!(env_span.style.add_modifier.contains(Modifier::BOLD));

        let directories = app.detail(CapabilityId::DirectoryAccess);
        let directories = highlighted_detail(
            &app,
            CapabilityId::DirectoryAccess,
            &directories,
        );
        let path_span = &directories.lines[1].spans[1];
        assert_eq!(path_span.content, "/srv/reference");
        assert_eq!(path_span.style.fg, Some(Color::Cyan));
        assert!(path_span.style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn compact_project_path_keeps_the_identifying_parent_and_name() {
        assert_eq!(
            compact_project_path("/mnt/data/Projects/ai-memory"),
            "../Projects/ai-memory"
        );
        assert_eq!(compact_project_path("/work/project"), "/work/project");
    }

    #[test]
    fn cli_panel_shows_copy_help_without_repeating_config_path() {
        let mut selection = Selection {
            env_names: vec!["GH_TOKEN".into()],
            ..Selection::default()
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.set_profile_path(std::path::Path::new(
            "/home/alice/.config/ai-jail/projects/demo.toml",
        ));
        let rendered = buffer_text(140, 38, &mut app);
        assert!(rendered.contains("CLI from defaults"));
        assert!(rendered.contains("y copy"));
        assert_eq!(rendered.matches("demo.toml").count(), 1);
    }

    #[test]
    fn preset_focus_renders_a_live_unapplied_access_preview() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            ..Selection::default()
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.preset_focus = true;
        app.preset_preview = true;
        app.preset_cursor = 2;
        let rendered = buffer_text(140, 36, &mut app);
        assert!(rendered.contains("Mostly open"));
        assert!(rendered.contains("PREVIEW — not applied"));
        assert!(rendered.contains("Full host SSH access"));
        assert!(rendered.contains("Full host GitHub token"));
        assert!(rendered.matches("! OPEN").count() >= 4);
        assert!(!app.selection.ssh);
        assert!(!app.selection.github);
    }

    #[test]
    fn narrow_view_stacks_without_losing_detail_or_help() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        let rendered = buffer_text(72, 40, &mut app);
        assert!(rendered.contains("Access choices"));
        assert!(rendered.contains("Details — Filtered model API access"));
        assert!(rendered.contains("Space/Enter select"));
    }

    #[test]
    fn narrow_detail_scroll_is_clamped_to_available_geometry() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.selected = 3;
        app.detail_scroll = u16::MAX;
        let rendered = buffer_text(72, 40, &mut app);
        assert!(rendered.contains("lines 8–15/15"), "{rendered}");
        assert!(rendered.contains("Use when"), "{rendered}");
        assert!(rendered.contains("PgUp/PgDn"), "{rendered}");
    }

    #[test]
    fn additional_capability_screen_keeps_platform_relevant_controls_discoverable()
     {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.screen = Screen::Additional;
        app.additional = Some(super::super::additional::State::new());
        let rendered = buffer_text(140, 36, &mut app);
        assert!(rendered.contains("Additional capabilities"));
        assert!(rendered.contains("Entire host home directory"));
        assert!(rendered.contains("OPEN grants require"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("systemd user manager"));
        #[cfg(target_os = "linux")]
        assert!(!rendered.contains("Broad macOS host IPC"));
    }

    #[test]
    fn too_small_view_explains_how_to_recover() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        let rendered = buffer_text(40, 12, &mut app);
        assert!(rendered.contains("Terminal too small"));
        assert!(rendered.contains("Resize the terminal"));
        assert!(rendered.contains("q cancels"));
    }

    #[test]
    fn open_confirmation_is_rendered_inside_the_same_frame() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.selected = 3;
        app.confirmation = Some(ConfirmMode::Open {
            capability: CapabilityId::FullSsh,
            dialog: super::super::dialog::ConfirmDialog::new(
                "Open this boundary?",
                "Full host SSH access removes an important isolation boundary.",
                "Enable OPEN access",
            ),
        });
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("Open this boundary?"));
        assert!(rendered.contains("Enable OPEN access"));
        assert!(rendered.contains("Cancel"));
        assert!(rendered.contains("Full host SSH access"));
        assert!(rendered.contains("every file in ~/.ssh"));
    }

    #[test]
    fn unsaved_exit_dialog_is_rendered_over_the_current_screen() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &Default::default(),
            &[],
        );
        app.handle_key(crossterm::event::KeyCode::Char('1'));
        app.handle_key(crossterm::event::KeyCode::Esc);
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("Unsaved changes"));
        assert!(rendered.contains("Keep editing"));
        assert!(rendered.contains("Discard & quit"));
        assert!(rendered.contains("Save changes"));
    }

    #[test]
    fn wrapper_view_makes_non_grant_and_explicit_decision_state_visible() {
        let requests = RequestSet {
            items: vec![WrapperRequest {
                approval: RequestApproval {
                    requester: "ai-memory".into(),
                    kind: "secret".into(),
                    value: "GH_TOKEN".into(),
                    host: Some("api.github.com".into()),
                    writable: None,
                    port: None,
                },
                reason: "authenticate\u{1b}[31m without exposing the value"
                    .into(),
            }],
        };
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );
        let rendered = buffer_text(120, 34, &mut app);

        assert!(rendered.contains("Wrapper-staged access requests"));
        assert!(rendered.contains("UNDECIDED"));
        assert!(rendered.contains("GH_TOKEN"));
        assert!(rendered.contains("api.github.com"));
        assert!(rendered.contains("approves nothing"));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn narrow_wrapper_view_exposes_complete_scrollable_disclosure() {
        let requests = RequestSet {
            items: vec![WrapperRequest {
                approval: RequestApproval {
                    requester: "wrapper".into(),
                    kind: "host".into(),
                    value: "example.com".into(),
                    host: None,
                    writable: None,
                    port: None,
                },
                reason: "required service".into(),
            }],
        };
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );
        let disclosure = (1..=30)
            .map(|line| format!("disclosure line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let review = app.wrapper.as_mut().unwrap();
        review.begin_approval(disclosure, false);
        let first = buffer_text(72, 40, &mut app);
        app.wrapper
            .as_mut()
            .unwrap()
            .handle_key(crossterm::event::KeyCode::Tab);
        app.wrapper
            .as_mut()
            .unwrap()
            .handle_key(crossterm::event::KeyCode::Enter);
        assert_eq!(
            app.wrapper.as_ref().unwrap().decisions,
            vec![None],
            "approval must wait until the complete disclosure was reviewed: {first}"
        );
        app.wrapper
            .as_mut()
            .unwrap()
            .handle_key(crossterm::event::KeyCode::End);
        let rendered = buffer_text(72, 40, &mut app);

        assert!(rendered.contains("disclosure line 30"), "{rendered}");
        assert!(rendered.contains("final disclosure line"), "{rendered}");
        app.wrapper
            .as_mut()
            .unwrap()
            .handle_key(crossterm::event::KeyCode::Enter);
        assert_eq!(
            app.wrapper.as_ref().unwrap().decisions,
            vec![Some(Decision::Approve)]
        );
    }
}
