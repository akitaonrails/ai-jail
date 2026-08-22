#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("ai-jail only supports Linux and macOS");

mod bootstrap;
mod cli;
mod command;
mod config;
mod fsutil;
mod output;
mod pty;
mod sandbox;
mod signals;
mod statusbar;

#[cfg(test)]
mod test_utils;

fn command_needs_direct_tty(command: &[String]) -> bool {
    // Tools that must own the real terminal directly, bypassing the
    // vt100 status-bar proxy:
    //   - crush: requires direct terminal passthrough.
    //   - opencode: its TUI is built almost entirely from East Asian
    //     Ambiguous-width glyphs (the half-block logo ▀▄, separator
    //     dots ·, box drawing). vt100 reconstructs the alt screen with
    //     a fixed narrow-width model and relative cursor moves, so on
    //     terminals that render those glyphs double-width the rebuilt
    //     frame drifts and the glyphs come out as tofu/black boxes
    //     (#57). The codepoints and colors survive the proxy intact —
    //     only the width assumption diverges — and vt100 owns the width
    //     model, so there is no faithful reconstruction. Routing
    //     opencode straight through the terminal (no status bar)
    //     preserves its own absolute glyph positioning.
    matches!(
        command::effective_name(command),
        Some("crush") | Some("opencode")
    )
}

fn command_is_browser(command: &[String]) -> bool {
    command::effective_name(command)
        .is_some_and(sandbox::is_browser_command_name)
}

fn resolve_browser_profile(
    config: &config::Config,
) -> Option<config::BrowserProfile> {
    if config.browser_profile_disabled() {
        return None;
    }
    config.browser_profile().or_else(|| {
        if command_is_browser(&config.command) {
            Some(config::BrowserProfile::Hard)
        } else {
            None
        }
    })
}

fn apply_browser_profile(config: &mut config::Config) {
    let Some(profile) = resolve_browser_profile(config) else {
        return;
    };

    config.browser_profile = Some(profile.as_str().into());
    config.no_gpu.get_or_insert(true);
    config.no_docker = Some(true);
    config.no_worktree = Some(true);
    config.no_mise = Some(true);
    config.no_save_config = Some(true);
    config.ssh = Some(false);
    config.pictures = Some(false);
    config.lockdown = Some(false);
    config.no_status_bar = Some(true);
}

/// Detect a terminal multiplexer around the current process. Nested
/// PTYs (tmux/zellij PTY → ai-jail vt100 PTY → child) conflict over
/// resize, keyboard protocol, and status-bar drawing, so we auto-skip
/// the ai-jail PTY proxy in these environments unless the user has
/// explicitly opted in.
fn running_inside_multiplexer() -> Option<&'static str> {
    if std::env::var_os("TMUX").is_some() {
        Some("tmux")
    } else if std::env::var_os("ZELLIJ").is_some() {
        Some("zellij")
    } else {
        None
    }
}

fn default_resize_redraw_key(command: &[String]) -> Option<&'static str> {
    match command::effective_name(command) {
        Some("codex") => Some("ctrl-shift-l"),
        _ => None,
    }
}

fn run_landlock_exec(cli: &cli::CliArgs) -> Result<i32, String> {
    use std::os::unix::process::CommandExt;

    if cli.command.is_empty() {
        return Err("--landlock-exec requires a command".into());
    }

    let project_dir = std::env::current_dir()
        .map_err(|e| format!("Cannot determine current directory: {e}"))?;

    // Use the fully resolved non-map policy forwarded via internal args.
    // Mounted destinations remain separate opaque paths below.
    let mut config = config::merge(cli, config::Config::default());
    // Idempotent: parent absolutized before serializing wrapper args,
    // but re-running guarantees no relative path reaches landlock.
    config::absolutize_user_paths(&mut config, &project_dir);

    // Apply Landlock inside the sandbox (after bwrap namespace setup).
    // Hidden path flags preserve destinations atomically, including ':'.
    sandbox::apply_landlock(
        &config,
        &project_dir,
        &cli.landlock_ro_paths,
        &cli.landlock_rw_paths,
        cli.verbose,
    )?;

    // Apply seccomp filter after Landlock (reduces kernel syscall
    // surface). Must happen before exec so the user command inherits
    // the filter.
    sandbox::apply_seccomp(&config, cli.verbose)?;

    // Apply NPROC here, inside the sandbox, after bwrap has finished
    // setting up namespaces. RLIMIT_NPROC counts all processes owned
    // by the real UID system-wide, so setting it on the outer ai-jail
    // before bwrap's clone() calls would cause EAGAIN when Chrome or
    // other heavy applications are running.
    #[cfg(target_os = "linux")]
    sandbox::rlimits::apply_nproc(&config, cli.verbose);

    // Drop PATH entries that do not exist in here.
    //
    // The sandbox inherits the host's PATH, which describes the host's
    // layout: under private home it names ~/.local/share/mise/installs/...
    // and similar directories that were never mounted. Tools then look
    // installed as far as PATH is concerned and resolve to nothing, and mise
    // in particular reports shims it cannot satisfy (issue #113). This runs
    // inside the sandbox, which is the only place the answer is knowable.
    if let Some(path) = std::env::var_os("PATH")
        && let Some((pruned, kept, total)) = prune_missing_path_entries(&path)
    {
        if cli.verbose {
            output::verbose(&format!(
                "PATH: kept {kept} of {total} entries that exist here"
            ));
        }
        // SAFETY: single-threaded, before exec.
        unsafe { std::env::set_var("PATH", &pruned) };
    }

    // Replace this process with the real command
    let err = std::process::Command::new(&cli.command[0])
        .args(&cli.command[1..])
        .exec();

    Err(format!("Failed to exec {}: {err}", cli.command[0]))
}

/// Drop `PATH` entries that are not directories here, returning the rewritten
/// value with the kept and original counts. `None` when nothing changed.
fn prune_missing_path_entries(
    path: &std::ffi::OsStr,
) -> Option<(std::ffi::OsString, usize, usize)> {
    let total = std::env::split_paths(path).count();
    let kept: Vec<std::path::PathBuf> = std::env::split_paths(path)
        .filter(|entry| entry.is_dir())
        .collect();
    if kept.len() == total {
        return None;
    }
    let count = kept.len();
    std::env::join_paths(kept)
        .ok()
        .map(|pruned| (pruned, count, total))
}

fn validate_write_flags(cli: &cli::CliArgs) -> Result<(), String> {
    if cli.init && cli.save_config == Some(false) {
        return Err("--init conflicts with --no-save-config".into());
    }
    Ok(())
}

fn exec_requires_terminal_passthrough(
    exec: bool,
    stdout_is_tty: bool,
    terminal_passthrough: bool,
) -> bool {
    // Keys on STDOUT being a TTY: the child's terminal output is the
    // injection surface, so piped stdin must not weaken the guard.
    exec && stdout_is_tty && !terminal_passthrough
}

/// Whether the PTY proxy filters the child's terminal output. Keys on
/// STDOUT being a TTY — piped stdin (`echo prompt | ai-jail claude`)
/// must still be filtered, because the child's escape sequences would
/// otherwise reach the host terminal unfiltered.
fn pty_proxy_active(exec: bool, stdout_is_tty: bool) -> bool {
    stdout_is_tty && !exec
}

/// The status bar's background update check phones home to GitHub.
/// It runs only when the status bar is active AND the user opted in
/// via --update-check / global config (default off).
fn should_check_update(
    config: &config::Config,
    status_bar_active: bool,
) -> bool {
    status_bar_active && config.update_check_enabled()
}

fn should_save_global_preferences(cli: &cli::CliArgs) -> bool {
    // Skip --exec: it forces `status_bar = Some(false)` for clean stdout
    // (see cli.rs), which is indistinguishable here from an explicit
    // --no-status-bar. Without this guard, a one-off `ai-jail --exec
    // ./script` would persist `no_status_bar = true` to the global
    // $HOME/.ai-jail and silently disable the status bar for every later
    // run. --exec is an execution mode, not a UI preference — same reason
    // --dry-run is excluded.
    !cli.dry_run
        && !cli.exec
        && (cli.status_bar.is_some() || cli.status_bar_style.is_some())
}

fn should_auto_save_project_config(
    cli: &cli::CliArgs,
    config: &config::Config,
) -> bool {
    !cli.dry_run && !config.lockdown_enabled() && config.save_config_enabled()
}

fn run() -> Result<i32, String> {
    let cli = cli::parse()?;
    validate_write_flags(&cli)?;

    // Suppress info/warn output in --exec mode for clean stdout
    if cli.exec {
        output::set_quiet(true);
    }

    // Internal: apply Landlock and exec (used inside bwrap sandbox)
    if cli.landlock_exec {
        // Inherit quiet mode from outer ai-jail via env var
        if std::env::var("AI_JAIL_QUIET").is_ok() {
            output::set_quiet(true);
        }
        return run_landlock_exec(&cli);
    }

    // Load local (./.ai-jail), then command-aware global ($HOME/.ai-jail), merge
    let project_config = if cli.clean {
        config::Config::default()
    } else {
        config::load()?
    };
    let global = config::load_global_for_command(&cli, &project_config)?;
    let baseline = config::merge(&cli, global);
    let invocation_cwd = std::env::current_dir()
        .map_err(|e| format!("Cannot determine current directory: {e}"))?;
    // A project `.ai-jail` is untrusted monotonic policy unless the trusted
    // global config lists this directory under `trust_project_config`, in
    // which case it is merged with the same semantics as a global
    // `[commands.<name>]` table and may enable capabilities.
    let project_trusted = config::project_config_is_trusted(
        &baseline.trust_project_config,
        &invocation_cwd,
    );
    let (mut config, security_warnings) = if project_trusted {
        if cli.verbose {
            output::verbose(
                "Project .ai-jail: trusted (listed in global trust_project_config)",
            );
        }
        (
            config::merge_trusted_project(baseline, project_config.clone()),
            Vec::<String>::new(),
        )
    } else {
        config::merge_with_global_report(
            baseline,
            project_config.clone(),
            &invocation_cwd,
        )
    };
    if cli.command.is_empty() && !project_config.command.is_empty() {
        config.command = project_config.command.clone();
    }
    for warning in security_warnings {
        output::security_warn(&warning);
    }
    // Resolve any relative paths in rw_maps/ro_maps against the user's
    // invocation cwd before they reach bwrap/landlock/seatbelt (issue
    // #54). Done here so display_status and the --init save path see
    // the same canonical paths the sandbox will use.
    config::absolutize_user_paths(&mut config, &invocation_cwd);
    apply_browser_profile(&mut config);
    if !config.allow_tcp_ports().is_empty() {
        return Err("--allow-tcp-port is disabled because UDP cannot be isolated; use explicit --network for unrestricted network access".into());
    }

    // Handle status command
    if cli.status {
        config::display_status(&config);
        return Ok(0);
    }

    // Persist user-level preferences (status bar) to $HOME/.ai-jail
    if should_save_global_preferences(&cli) {
        config::save_global(&config)?;
    }

    // Handle --init: save config and exit.
    //
    // Save the project layer only — the existing project file plus whatever
    // this invocation asked for — not the global baseline merged on top of
    // it. Writing the merged result copied personal global settings such as
    // claude_dir and absolute home paths into a repository file, where they
    // are also inert: a project .ai-jail cannot enable capabilities anyway
    // (issue #110).
    if cli.init {
        config::save(&config::project_config_for_init(
            &cli,
            project_config.clone(),
            &invocation_cwd,
        ));
        output::info("Config saved to .ai-jail");
        return Ok(0);
    }

    // Handle --bootstrap: generate AI tool configs and exit
    if cli.bootstrap {
        bootstrap::run(cli.verbose, config.claude_dir.as_deref())?;
        return Ok(0);
    }

    // Check sandbox tool is available
    sandbox::check()?;

    // Platform-specific info messages (e.g. no-op flags on macOS)
    sandbox::platform_notes(&config);

    // Prepare sandbox resources (temp hosts file on Linux, no-op on macOS)
    let guard = sandbox::prepare()?;

    let project_dir = std::env::current_dir()
        .map_err(|e| format!("Cannot determine current directory: {e}"))?;

    // Save config in normal mode. In lockdown mode avoid host writes unless user
    // explicitly requested persistence via --init.
    //
    if should_auto_save_project_config(&cli, &config) {
        let to_save = config::project_config_for_auto_save(
            &cli,
            project_config,
            &invocation_cwd,
        );
        config::save_auto(&to_save);
    }

    // Handle dry run
    if cli.dry_run {
        let formatted =
            sandbox::dry_run(&guard, &config, &project_dir, cli.verbose)?;
        output::dry_run_line(&formatted);
        return Ok(0);
    }

    output::info(&format!("Jail Active: {}", project_dir.display()));

    // Install signal handlers before spawning
    signals::install_handlers();

    // Set up status bar if enabled and stdio is attached to a terminal
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if exec_requires_terminal_passthrough(
        cli.exec,
        stdout_is_tty,
        config.terminal_passthrough_enabled(),
    ) {
        return Err(
            "--exec on a terminal requires --terminal-passthrough".into()
        );
    }
    let needs_direct_tty = command_needs_direct_tty(&config.command);
    let multiplexer = running_inside_multiplexer();
    // Auto-skip the ai-jail status bar / PTY proxy inside a
    // multiplexer unless the user explicitly opted in via -s,
    // --status-bar=..., or `no_status_bar = false` in config.
    let explicit_status_bar =
        cli.status_bar_style.is_some() || config.no_status_bar == Some(false);
    let multiplexer_skip = multiplexer.is_some() && !explicit_status_bar;
    let use_status_bar = config.status_bar_enabled()
        && stdout_is_tty
        && stdin_is_tty
        && !cli.exec
        && !needs_direct_tty
        && !multiplexer_skip;
    // Even without the overlay, interactive children use a PTY proxy so the
    // host terminal never accepts escape sequences directly from the sandbox.
    // The decision keys on stdout: piped stdin + terminal stdout still
    // filters (see pty_proxy_active).
    let use_pty = pty_proxy_active(cli.exec, stdout_is_tty);
    if cli.verbose {
        if config.status_bar_enabled() {
            if needs_direct_tty {
                output::verbose(&format!(
                    "Status bar: skipped ({} requires direct terminal passthrough)",
                    command::effective_name(&config.command)
                        .unwrap_or("command")
                ));
            } else if multiplexer_skip {
                output::verbose(&format!(
                    "Status bar: auto-disabled ({} detected; pass -s to force-enable)",
                    multiplexer.unwrap()
                ));
            } else if stdout_is_tty && stdin_is_tty {
                output::verbose("Status bar: enabled");
            } else {
                output::verbose("Status bar: skipped (stdio is not a tty)");
            }
        } else {
            output::verbose(
                "Status bar: off (use --no-status-bar to disable globally)",
            );
        }
    }
    if use_status_bar {
        statusbar::setup(
            &project_dir,
            &config.command,
            config.status_bar_style(),
            &config,
        );
    }
    // The update check only runs with the status bar active AND an
    // explicit opt-in (phones home to GitHub; default off).
    if should_check_update(&config, use_status_bar) {
        statusbar::check_update_background();
    }

    // Build bwrap command (reads $HOME, /dev, etc. for mount discovery).
    // When Landlock is enabled, the inner command is wrapped with
    // `ai-jail --landlock-exec` so Landlock is applied INSIDE the
    // sandbox after bwrap finishes mount namespace setup.
    // Allocate the PTY before building the command: the macOS profile scopes
    // its terminal ioctl grant to this exact device, so the slave path must be
    // known while the sandbox profile is still being generated.
    let pty = if use_pty { Some(pty::open()?) } else { None };
    let sandbox_tty = pty.as_ref().and_then(pty::Pty::slave_path);
    let mut cmd = sandbox::build(
        &guard,
        &config,
        &project_dir,
        cli.verbose,
        sandbox_tty.as_deref(),
    )?;

    // Apply NOFILE and CORE limits on the parent (inherited by child
    // across fork+exec). NPROC is applied inside the sandbox instead
    // — see run_landlock_exec() — to avoid EAGAIN during bwrap's
    // internal clone() calls for namespace creation.
    sandbox::rlimits::apply(&config, cli.verbose);

    let exit_code = if use_pty {
        let resize_redraw_key =
            match config.resize_redraw_key.as_deref() {
                Some(spec) => match pty::parse_resize_redraw_key(spec) {
                    Ok(seq) => seq,
                    Err(e) => {
                        output::warn(&format!(
                            "Ignoring invalid resize_redraw_key {spec:?}: {e}"
                        ));
                        None
                    }
                },
                None => default_resize_redraw_key(&config.command).and_then(
                    |spec| pty::parse_resize_redraw_key(spec).ok().flatten(),
                ),
            };

        if cli.verbose {
            match (&resize_redraw_key, config.resize_redraw_key.as_deref()) {
                (Some(_), Some(spec)) => output::verbose(&format!(
                    "Resize redraw key: {spec} (used on terminal resize)"
                )),
                (None, Some(spec)) => output::verbose(&format!(
                    "Resize redraw key: {spec} (disabled)"
                )),
                (Some(_), None)
                    if default_resize_redraw_key(&config.command).is_some() =>
                {
                    output::verbose(
                        "Resize redraw key: ctrl-shift-l (codex default)",
                    );
                }
                _ => {}
            }
        }

        // PTY proxy path: ai-jail owns the real terminal, child gets a PTY
        // slave. The overlay remains optional, but output filtering is not.
        // `use_pty` is what put a PTY in `pty` above.
        let pty = pty.expect("PTY allocated when use_pty is set");
        match pty::run_with_config(
            pty,
            &mut cmd,
            resize_redraw_key.as_deref(),
            &config,
            use_status_bar,
        ) {
            Ok(code) => {
                statusbar::teardown();
                code
            }
            Err(e) => {
                statusbar::teardown();
                return Err(e);
            }
        }
    } else {
        // Non-interactive and --exec paths preserve inherited/piped stdio.
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start sandbox: {e}"))?;

        let pid = child.id() as i32;
        signals::set_child_pid(pid);

        let code = signals::wait_child(pid);
        std::mem::forget(child);
        // Defensive terminal reset — see issue #40. The child may
        // have left mouse tracking, alt-screen, etc. on. The PTY path
        // does its own reset in pty::run; here we cover the
        // no-status-bar / multiplexer-detected / crush paths.
        output::terminal_reset();
        code
    };

    // Guard is dropped here, cleaning up any temp files. On macOS the
    // guard is a unit struct (no temp files to clean), so the explicit
    // drop is a no-op there; clippy's drop_non_drop only fires on that
    // platform. The drop stays meaningful on Linux (RAII temp files).
    #[cfg_attr(target_os = "macos", allow(clippy::drop_non_drop))]
    drop(guard);

    Ok(exit_code)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            output::error(&msg);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_browser_profile, command_is_browser, command_needs_direct_tty,
        default_resize_redraw_key, exec_requires_terminal_passthrough,
        prune_missing_path_entries, pty_proxy_active, resolve_browser_profile,
        running_inside_multiplexer, should_auto_save_project_config,
        should_check_update, should_save_global_preferences,
        validate_write_flags,
    };
    use crate::cli::CliArgs;
    use crate::config::{BrowserProfile, Config};
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn crush_requires_direct_tty() {
        assert!(command_needs_direct_tty(&["crush".into()]));
        assert!(command_needs_direct_tty(&["/usr/bin/crush".into()]));
    }

    #[test]
    fn opencode_requires_direct_tty() {
        // opencode's ambiguous-width TUI cannot be faithfully rebuilt
        // by the vt100 proxy; it must own the terminal directly (#57).
        assert!(command_needs_direct_tty(&["opencode".into()]));
        assert!(command_needs_direct_tty(&[
            "/home/x/.opencode/bin/opencode".into()
        ]));
        assert!(command_needs_direct_tty(&[
            "ai-memory".into(),
            "run".into(),
            "opencode".into(),
        ]));
    }

    #[test]
    fn managed_codex_uses_resize_redraw_default() {
        assert_eq!(
            default_resize_redraw_key(&[
                "ai-memory".into(),
                "run".into(),
                "--project".into(),
                "demo".into(),
                "codex".into(),
            ]),
            Some("ctrl-shift-l")
        );
    }

    #[test]
    fn path_pruning_drops_only_missing_entries() {
        // Issue #113: the sandbox inherits a PATH describing the host's
        // layout, so entries that were never mounted dangle and tools look
        // installed while resolving to nothing.
        let real = std::env::temp_dir();
        let missing =
            real.join(format!("ai-jail-no-such-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);

        let path =
            std::env::join_paths([real.clone(), missing.clone()]).unwrap();
        let (pruned, kept, total) =
            prune_missing_path_entries(&path).expect("should prune");
        assert_eq!((kept, total), (1, 2));
        assert_eq!(
            std::env::split_paths(&pruned).collect::<Vec<_>>(),
            vec![real.clone()]
        );

        // Nothing to do when every entry exists: callers skip the rewrite.
        let all_real = std::env::join_paths([real.clone(), real]).unwrap();
        assert!(prune_missing_path_entries(&all_real).is_none());
    }

    #[test]
    fn multiplexer_detects_tmux() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _zellij = EnvVarGuard::remove("ZELLIJ");
        let _tmux = EnvVarGuard::set("TMUX", "/tmp/fake");
        assert_eq!(running_inside_multiplexer(), Some("tmux"));
    }

    #[test]
    fn multiplexer_detects_zellij() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _tmux = EnvVarGuard::remove("TMUX");
        let _zellij = EnvVarGuard::set("ZELLIJ", "session-name");
        assert_eq!(running_inside_multiplexer(), Some("zellij"));
    }

    #[test]
    fn multiplexer_none_when_neither_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _tmux = EnvVarGuard::remove("TMUX");
        let _zellij = EnvVarGuard::remove("ZELLIJ");
        assert_eq!(running_inside_multiplexer(), None);
    }

    #[test]
    fn other_commands_do_not_require_direct_tty() {
        assert!(!command_needs_direct_tty(&[]));
        assert!(!command_needs_direct_tty(&["codex".into()]));
        assert!(!command_needs_direct_tty(&["/usr/bin/bash".into()]));
    }

    #[test]
    fn browser_detection_matches_common_browser_names() {
        assert!(command_is_browser(&["chromium".into()]));
        assert!(command_is_browser(&["/usr/bin/firefox".into()]));
        assert!(command_is_browser(&["google-chrome-stable".into()]));
        assert!(!command_is_browser(&["codex".into()]));
    }

    #[test]
    fn browser_profile_auto_defaults_to_hard_for_browsers() {
        let config = Config {
            command: vec!["chromium".into()],
            ..Config::default()
        };
        assert_eq!(
            resolve_browser_profile(&config),
            Some(BrowserProfile::Hard)
        );
    }

    #[test]
    fn browser_profile_explicit_soft_wins() {
        let config = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("soft".into()),
            ..Config::default()
        };
        assert_eq!(
            resolve_browser_profile(&config),
            Some(BrowserProfile::Soft)
        );
    }

    #[test]
    fn browser_profile_can_be_disabled_for_browser_command() {
        let config = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("off".into()),
            ..Config::default()
        };
        assert_eq!(resolve_browser_profile(&config), None);
    }

    #[test]
    fn browser_profile_applies_hardened_defaults() {
        let mut config = Config {
            command: vec!["chromium".into()],
            ..Config::default()
        };
        apply_browser_profile(&mut config);

        assert_eq!(config.browser_profile.as_deref(), Some("hard"));
        assert_eq!(config.no_gpu, Some(true));
        assert_eq!(config.no_docker, Some(true));
        assert_eq!(config.no_display, None);
        assert_eq!(config.no_worktree, Some(true));
        assert_eq!(config.no_mise, Some(true));
        assert_eq!(config.no_save_config, Some(true));
        assert_eq!(config.ssh, Some(false));
        assert_eq!(config.pictures, Some(false));
        assert_eq!(config.lockdown, Some(false));
        assert_eq!(config.no_status_bar, Some(true));
    }

    #[test]
    fn exec_terminal_requires_explicit_passthrough() {
        // Keys on stdout only: piped stdin must not weaken the guard.
        assert!(exec_requires_terminal_passthrough(true, true, false));
        assert!(!exec_requires_terminal_passthrough(true, true, true));
        assert!(!exec_requires_terminal_passthrough(true, false, false));
        assert!(!exec_requires_terminal_passthrough(false, true, false));
    }

    #[test]
    fn pty_proxy_keys_on_stdout_not_stdin() {
        // Terminal stdout always filters, even with piped stdin (the
        // predicate deliberately has no stdin input); a piped stdout
        // (plain pipe/file) skips the proxy.
        assert!(pty_proxy_active(false, true));
        assert!(!pty_proxy_active(false, false));
        assert!(!pty_proxy_active(true, true));
    }

    #[test]
    fn update_check_requires_opt_in_and_active_status_bar() {
        let default = Config::default();
        assert!(!should_check_update(&default, true));
        assert!(!should_check_update(&default, false));

        let opted_in = Config {
            update_check: Some(true),
            ..Config::default()
        };
        assert!(should_check_update(&opted_in, true));
        assert!(!should_check_update(&opted_in, false));

        let opted_out = Config {
            update_check: Some(false),
            ..Config::default()
        };
        assert!(!should_check_update(&opted_out, true));
    }

    #[test]
    fn validate_write_flags_rejects_init_with_no_save_config() {
        let cli = CliArgs {
            init: true,
            save_config: Some(false),
            ..CliArgs::default()
        };
        assert!(validate_write_flags(&cli).is_err());
    }

    #[test]
    fn validate_write_flags_allows_init_alone() {
        let cli = CliArgs {
            init: true,
            ..CliArgs::default()
        };
        assert!(validate_write_flags(&cli).is_ok());
    }

    #[test]
    fn validate_write_flags_allows_init_with_save_config() {
        let cli = CliArgs {
            init: true,
            save_config: Some(true),
            ..CliArgs::default()
        };
        assert!(validate_write_flags(&cli).is_ok());
    }

    #[test]
    fn validate_write_flags_allows_no_save_config_alone() {
        let cli = CliArgs {
            save_config: Some(false),
            ..CliArgs::default()
        };
        assert!(validate_write_flags(&cli).is_ok());
    }

    #[test]
    fn dry_run_skips_project_auto_save() {
        let cli = CliArgs {
            dry_run: true,
            ..CliArgs::default()
        };
        let config = Config::default();

        assert!(!should_auto_save_project_config(&cli, &config));
    }

    #[test]
    fn normal_run_allows_project_auto_save_by_default() {
        let cli = CliArgs::default();
        let config = Config::default();

        assert!(should_auto_save_project_config(&cli, &config));
    }

    #[test]
    fn dry_run_skips_global_preference_save() {
        let cli = CliArgs {
            dry_run: true,
            status_bar_style: Some("dark".into()),
            ..CliArgs::default()
        };

        assert!(!should_save_global_preferences(&cli));
    }

    #[test]
    fn status_bar_option_allows_global_preference_save() {
        let cli = CliArgs {
            status_bar_style: Some("dark".into()),
            ..CliArgs::default()
        };

        assert!(should_save_global_preferences(&cli));
    }

    #[test]
    fn exec_skips_global_preference_save() {
        // --exec forces status_bar = Some(false) for clean stdout. That
        // must not leak into the global $HOME/.ai-jail — a one-off exec
        // run should never persist no_status_bar for every later run.
        let cli = CliArgs {
            exec: true,
            status_bar: Some(false),
            ..CliArgs::default()
        };

        assert!(!should_save_global_preferences(&cli));
    }

    #[test]
    fn exec_skips_global_preference_save_for_style() {
        // The guard's other disjunct: --status-bar=STYLE combined with
        // --exec must not persist either.
        let cli = CliArgs {
            exec: true,
            status_bar_style: Some("dark".into()),
            ..CliArgs::default()
        };

        assert!(!should_save_global_preferences(&cli));
    }
}
