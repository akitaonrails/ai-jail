use super::app::{
    AccessPreset, App, CapabilityId, ConfirmMode, MIN_HEIGHT, MIN_WIDTH, Screen,
};
use super::wrapper::{Decision, resource_label};
use crate::output::escape_control_bytes;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Wrap,
};

const WIDE_WIDTH: u16 = 96;

pub(super) fn render(frame: &mut Frame, app: &mut App<'_>) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area.width, area.height);
        return;
    }
    if app.screen == Screen::WrapperRequests {
        render_wrapper_requests(frame, app);
        return;
    }
    if app.screen == Screen::Review {
        if let Some(review) = &mut app.review {
            super::review::render(frame, review);
        }
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

    let intro_height = 3;
    let [
        header_area,
        intro_area,
        preset_area,
        content_area,
        footer_area,
    ] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(intro_height),
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(5),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("Configure {}", app.harness),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw("  •  project access"),
            ]),
            Line::from(vec![
                Span::styled("Project  ", muted(app)),
                Span::raw(&app.project),
            ]),
        ]),
        header_area,
    );
    let mut intro = vec![Line::from(Span::styled(
        super::super::messages::INTRO,
        muted(app),
    ))];
    if app.recommended_baseline {
        intro.push(Line::from(vec![
            Span::styled("✓ For developers applied  ", granted(app)),
            Span::raw(
                "Filtered API, harness login/state, dependency tools, and ",
            ),
            Span::styled("OPEN full GitHub token.", danger(app)),
        ]));
    }
    frame.render_widget(
        Paragraph::new(intro).wrap(Wrap { trim: true }),
        intro_area,
    );
    render_presets(frame, app, preset_area);

    let [list_area, detail_area] = if area.width >= WIDE_WIDTH {
        Layout::horizontal([
            Constraint::Percentage(42),
            Constraint::Percentage(58),
        ])
        .areas(content_area)
    } else {
        Layout::vertical([Constraint::Length(13), Constraint::Min(3)])
            .areas(content_area)
    };
    render_list(frame, app, list_area);
    render_detail(frame, app, detail_area);
    render_footer(frame, app, footer_area);
    if let Some(confirm) = &app.confirmation {
        match confirm {
            ConfirmMode::Open { dialog, .. }
            | ConfirmMode::MostlyOpen { dialog }
            | ConfirmMode::AdditionalOpen { dialog, .. } => {
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
        "↑/↓ move  •  PgUp/PgDn jump  •  Space/Enter toggle  •  Esc back  •  q cancel"
    } else {
        &state.feedback
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(feedback),
            Line::from("OPEN grants require an explicit dialog; final review remains mandatory."),
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
        let applied = active == Some(preset) && !app.preset_focus;
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
    if active.is_none() && !app.preset_focus {
        line.push(Span::styled(" ✓ Custom ", granted(app)));
    } else if app.preset_focus {
        line.push(Span::styled(" PREVIEW — not applied ", danger(app)));
    }
    frame.render_widget(
        Paragraph::new(Line::from(line)).block(
            Block::default()
                .title(" Presets • Tab/Shift-Tab preview • Enter/Space apply ")
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
        "Requested by: {}\nResource: {}\nReason: {}\n\n{prior}\n\n{disclosure}",
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
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Access choices ")
                .borders(Borders::ALL),
        )
        .highlight_symbol("▶ ")
        .highlight_style(focus(app));
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_detail(
    frame: &mut Frame,
    app: &App<'_>,
    area: ratatui::layout::Rect,
) {
    let capability = app.selected_capability();
    let detail = app.detail(capability);
    let total = wrapped_line_count(&detail, area.width.saturating_sub(2));
    let paragraph = Paragraph::new(detail).wrap(Wrap { trim: false });
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

fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| line.chars().count().max(1).div_ceil(width))
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn render_subscreen(frame: &mut Frame, app: &App<'_>) {
    let instruction = "Esc returns to access choices  •  q cancels";
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

fn render_footer(
    frame: &mut Frame,
    app: &App<'_>,
    area: ratatui::layout::Rect,
) {
    let prompt = match &app.confirmation {
        Some(
            ConfirmMode::Open { .. }
            | ConfirmMode::MostlyOpen { .. }
            | ConfirmMode::AdditionalOpen { .. },
        ) => Line::from(
            "Choose explicitly in the confirmation dialog; Cancel is selected by default.",
        ),
        None if app.preset_focus => Line::from(
            "PREVIEW only — the list shows this preset; Enter/Space applies it, Down/Esc returns unchanged.",
        ),
        None if !app.feedback.is_empty() => Line::from(app.feedback.clone()),
        None => Line::from(
            "↑/↓ move  •  Space/Enter select  •  q cancel  •  Esc back",
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
        app.recommended_baseline = true;
        let rendered = buffer_text(140, 34, &mut app);
        assert!(rendered.contains("For developers applied"));
        assert!(rendered.contains("Filtered API"));
        assert!(rendered.contains("harness login/state"));
        assert!(rendered.contains("harness login/state"));
        assert!(rendered.contains("OPEN full GitHub token"));
        assert!(rendered.contains("dependency tools"));
        assert!(rendered.contains("✓"));
        assert!(rendered.contains("CLOSED"));
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
    fn narrow_plain_detail_fits_without_unneeded_scrolling() {
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
        app.detail_scroll = 3;
        let rendered = buffer_text(72, 40, &mut app);
        assert!(rendered.contains("lines 1–11/11"), "{rendered}");
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
