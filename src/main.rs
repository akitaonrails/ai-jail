#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("ai-jail only supports Linux and macOS");

mod bootstrap;
mod cli;
mod config;
mod output;
mod pty;
mod sandbox;
mod signals;
mod statusbar;

const BROWSER_COMMANDS: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave",
    "brave-browser",
    "firefox",
    "librewolf",
];

fn command_basename(command: &[String]) -> Option<&str> {
    command.first().and_then(|cmd| {
        std::path::Path::new(cmd)
            .file_name()
            .and_then(|name| name.to_str())
    })
}

fn command_needs_direct_tty(command: &[String]) -> bool {
    command_basename(command) == Some("crush")
}

fn command_is_browser(command: &[String]) -> bool {
    command_basename(command)
        .is_some_and(|name| BROWSER_COMMANDS.contains(&name))
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
    config.no_display = Some(false);
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
    match command_basename(command) {
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

    // Use the fully resolved outer policy forwarded via internal args.
    let config = config::merge(cli, config::Config::default());

    // Apply Landlock inside the sandbox (after bwrap namespace setup)
    sandbox::apply_landlock(&config, &project_dir, cli.verbose)?;

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

    // Replace this process with the real command
    let err = std::process::Command::new(&cli.command[0])
        .args(&cli.command[1..])
        .exec();

    Err(format!("Failed to exec {}: {err}", cli.command[0]))
}

fn validate_write_flags(cli: &cli::CliArgs) -> Result<(), String> {
    if cli.init && cli.save_config == Some(false) {
        return Err("--init conflicts with --no-save-config".into());
    }
    Ok(())
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

    // Load global ($HOME/.ai-jail) then local (./.ai-jail), merge
    let global = config::load_global();
    let local = if cli.clean {
        config::Config::default()
    } else {
        config::load()
    };
    let existing = config::merge_with_global(global, local);
    // Capture the stored project command before the CLI command
    // merges on top of it. The auto-save path below restores this
    // so that `ai-jail codex` after `ai-jail claude` does not
    // rewrite the project's stored default to codex. Use `--init`
    // to explicitly change the stored command. See #20.
    let stored_command = existing.command.clone();
    let mut config = config::merge(&cli, existing);
    apply_browser_profile(&mut config);

    // Handle status command
    if cli.status {
        config::display_status(&config);
        return Ok(0);
    }

    // Persist user-level preferences (status bar) to $HOME/.ai-jail
    if cli.status_bar.is_some() || cli.status_bar_style.is_some() {
        config::save_global(&config);
    }

    // Handle --init: save config and exit
    if cli.init {
        config::save(&config);
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
    // A CLI-passed command is NOT persisted when the project already
    // has a stored command — multi-agent users run `ai-jail claude`
    // and `ai-jail codex` on the same project and the stored default
    // should not flip under them. First-run bootstrap (no stored
    // command yet) still persists the CLI command as the new default.
    if !config.lockdown_enabled() && config.save_config_enabled() {
        let mut to_save = config.clone();
        if !stored_command.is_empty() && !cli.command.is_empty() {
            to_save.command = stored_command;
        }
        config::save(&to_save);
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
    if cli.verbose {
        if config.status_bar_enabled() {
            if needs_direct_tty {
                output::verbose(
                    "Status bar: skipped (crush requires direct terminal passthrough)",
                );
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
        statusbar::check_update_background();
    }

    // Build bwrap command (reads $HOME, /dev, etc. for mount discovery).
    // When Landlock is enabled, the inner command is wrapped with
    // `ai-jail --landlock-exec` so Landlock is applied INSIDE the
    // sandbox after bwrap finishes mount namespace setup.
    let mut cmd = sandbox::build(&guard, &config, &project_dir, cli.verbose)?;

    // Apply NOFILE and CORE limits on the parent (inherited by child
    // across fork+exec). NPROC is applied inside the sandbox instead
    // — see run_landlock_exec() — to avoid EAGAIN during bwrap's
    // internal clone() calls for namespace creation.
    sandbox::rlimits::apply(&config, cli.verbose);

    let exit_code = if use_status_bar {
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

        // PTY proxy path: ai-jail owns the real terminal, child
        // gets a PTY slave. This keeps the status bar persistent.
        match pty::run(&mut cmd, resize_redraw_key.as_deref()) {
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
        // Direct spawn path (no status bar)
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start sandbox: {e}"))?;

        let pid = child.id() as i32;
        signals::set_child_pid(pid);

        let code = signals::wait_child(pid);
        std::mem::forget(child);
        code
    };

    // Guard is dropped here, cleaning up any temp files
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
        resolve_browser_profile, running_inside_multiplexer,
        validate_write_flags,
    };
    use crate::cli::CliArgs;
    use crate::config::{BrowserProfile, Config};

    // Serialize tests that mutate process-global env vars.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn crush_requires_direct_tty() {
        assert!(command_needs_direct_tty(&["crush".into()]));
        assert!(command_needs_direct_tty(&["/usr/bin/crush".into()]));
    }

    #[test]
    fn multiplexer_detects_tmux() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_tmux = std::env::var_os("TMUX");
        let saved_zellij = std::env::var_os("ZELLIJ");
        unsafe {
            std::env::remove_var("ZELLIJ");
            std::env::set_var("TMUX", "/tmp/fake");
        }
        assert_eq!(running_inside_multiplexer(), Some("tmux"));
        unsafe {
            std::env::remove_var("TMUX");
            if let Some(v) = saved_tmux {
                std::env::set_var("TMUX", v);
            }
            if let Some(v) = saved_zellij {
                std::env::set_var("ZELLIJ", v);
            }
        }
    }

    #[test]
    fn multiplexer_detects_zellij() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_tmux = std::env::var_os("TMUX");
        let saved_zellij = std::env::var_os("ZELLIJ");
        unsafe {
            std::env::remove_var("TMUX");
            std::env::set_var("ZELLIJ", "session-name");
        }
        assert_eq!(running_inside_multiplexer(), Some("zellij"));
        unsafe {
            std::env::remove_var("ZELLIJ");
            if let Some(v) = saved_tmux {
                std::env::set_var("TMUX", v);
            }
            if let Some(v) = saved_zellij {
                std::env::set_var("ZELLIJ", v);
            }
        }
    }

    #[test]
    fn multiplexer_none_when_neither_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_tmux = std::env::var_os("TMUX");
        let saved_zellij = std::env::var_os("ZELLIJ");
        unsafe {
            std::env::remove_var("TMUX");
            std::env::remove_var("ZELLIJ");
        }
        assert_eq!(running_inside_multiplexer(), None);
        unsafe {
            if let Some(v) = saved_tmux {
                std::env::set_var("TMUX", v);
            }
            if let Some(v) = saved_zellij {
                std::env::set_var("ZELLIJ", v);
            }
        }
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
        assert_eq!(config.no_display, Some(false));
        assert_eq!(config.no_worktree, Some(true));
        assert_eq!(config.no_mise, Some(true));
        assert_eq!(config.no_save_config, Some(true));
        assert_eq!(config.ssh, Some(false));
        assert_eq!(config.pictures, Some(false));
        assert_eq!(config.lockdown, Some(false));
        assert_eq!(config.no_status_bar, Some(true));
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
}
