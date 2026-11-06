mod additional;
mod app;
mod dialog;
mod directory;
mod environment;
mod ssh;
mod view;
mod wrapper;

use self::app::{App, AppExit, Transition};
use super::{Outcome, PreparedProfile, Selection, safe_path};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stderr, Write};
use std::path::Path;
use std::sync::Arc;

pub(super) struct RunOptions<'a> {
    pub policy_root: Option<&'a Path>,
    pub configure_only: bool,
    pub recommended_baseline: bool,
    pub profile_path: &'a Path,
}

pub(super) fn run_app<F>(
    selection: &mut Selection,
    harness: &str,
    project: &Path,
    requests: &crate::integration::RequestSet,
    approved_wrapper_requests: &[crate::integration::RequestApproval],
    options: RunOptions,
    mut prepare_profile: F,
) -> Result<Outcome, String>
where
    F: FnMut(
        &Selection,
        &[crate::integration::RequestApproval],
    ) -> Result<PreparedProfile, String>,
{
    let project_path = project.to_path_buf();
    let project = safe_path(project)?;
    let use_color = std::env::var_os("NO_COLOR").is_none();
    let mut app = App::new(
        selection,
        harness,
        project,
        use_color,
        requests,
        approved_wrapper_requests,
    );
    app.set_recommended_baseline(options.recommended_baseline);
    app.set_project_path(&project_path);
    app.set_profile_path(options.profile_path);
    app.policy_root = options.policy_root.map(safe_path).transpose()?;
    let mut session =
        TerminalSession::new().map_err(|error| error.to_string())?;

    loop {
        let area =
            session.terminal.size().map_err(|error| error.to_string())?;
        app.resize(area.width, area.height);
        session
            .terminal
            .draw(|frame| view::render(frame, &mut app))
            .map_err(|error| error.to_string())?;
        let event = event::read().map_err(|error| error.to_string())?;
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.handle_key(key.code) {
            Transition::Stay => {}
            Transition::PrepareSave { save_only } => match prepare_profile(
                app.selection,
                &app.approved_wrapper_requests,
            ) {
                Ok(draft) => {
                    return Ok(if options.configure_only || save_only {
                        Outcome::SaveOnly(draft.profile)
                    } else {
                        Outcome::SaveAndLaunch(draft.profile)
                    });
                }
                Err(error) => app.feedback = app::human_error(error),
            },
            Transition::Exit(AppExit::Cancel) => return Ok(Outcome::Cancel),
        }
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stderr>>,
    _panic_hook: PanicHookGuard,
}

impl TerminalSession {
    fn new() -> io::Result<Self> {
        let panic_hook = PanicHookGuard::install();
        enable_raw_mode()?;
        let mut stderr = io::stderr();
        if let Err(error) = execute!(stderr, EnterAlternateScreen, Hide) {
            restore_terminal();
            return Err(error);
        }
        let backend = CrosstermBackend::new(stderr);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self {
                terminal,
                _panic_hook: panic_hook,
            }),
            Err(error) => {
                restore_terminal();
                Err(error)
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = write_restoration(self.terminal.backend_mut());
        let _ = disable_raw_mode();
    }
}

fn write_restoration(writer: &mut impl Write) -> io::Result<()> {
    execute!(writer, Show, LeaveAlternateScreen)
}

fn restore_terminal() {
    let mut stderr = io::stderr();
    let _ = write_restoration(&mut stderr);
    let _ = disable_raw_mode();
}

type PanicHook = dyn for<'a, 'b> Fn(&'a std::panic::PanicHookInfo<'b>)
    + Send
    + Sync
    + 'static;

struct PanicHookGuard {
    previous: Arc<PanicHook>,
}

impl PanicHookGuard {
    fn install() -> Self {
        let previous: Arc<PanicHook> = std::panic::take_hook().into();
        let fallback = previous.clone();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            fallback(info);
        }));
        Self { previous }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        let _ = std::panic::take_hook();
        let previous = self.previous.clone();
        std::panic::set_hook(Box::new(move |info| previous(info)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoration_sequence_shows_cursor_and_leaves_alternate_screen() {
        let mut output = Vec::new();
        write_restoration(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("\x1b[?25h"), "{text:?}");
        assert!(text.contains("\x1b[?1049l"), "{text:?}");
    }
}
