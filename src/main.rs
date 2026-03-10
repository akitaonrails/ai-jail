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

    // Replace this process with the real command
    let err = std::process::Command::new(&cli.command[0])
        .args(&cli.command[1..])
        .exec();

    Err(format!("Failed to exec {}: {err}", cli.command[0]))
}

fn run() -> Result<i32, String> {
    let cli = cli::parse()?;

    // Internal: apply Landlock and exec (used inside bwrap sandbox)
    if cli.landlock_exec {
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
    let config = config::merge(&cli, existing);

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
        bootstrap::run(cli.verbose)?;
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
    if !config.lockdown_enabled() {
        config::save(&config);
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
    let use_status_bar =
        config.status_bar_enabled() && stdout_is_tty && stdin_is_tty;
    if cli.verbose {
        if config.status_bar_enabled() {
            if stdout_is_tty && stdin_is_tty {
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
        );
        statusbar::check_update_background();
    }

    // Build bwrap command (reads $HOME, /dev, etc. for mount discovery).
    // When Landlock is enabled, the inner command is wrapped with
    // `ai-jail --landlock-exec` so Landlock is applied INSIDE the
    // sandbox after bwrap finishes mount namespace setup.
    let mut cmd = sandbox::build(&guard, &config, &project_dir, cli.verbose)?;

    // Apply resource limits before spawning. Limits are inherited
    // by the child across fork+exec.
    sandbox::rlimits::apply(&config, cli.verbose);

    let exit_code = if use_status_bar {
        // PTY proxy path: ai-jail owns the real terminal, child
        // gets a PTY slave. This keeps the status bar persistent.
        match pty::run(&mut cmd) {
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
