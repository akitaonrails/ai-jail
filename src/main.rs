#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("ai-jail only supports Linux and macOS");

mod audit;
mod bootstrap;
mod cli;
mod command;
mod config;
mod fsutil;
mod github_auth;
mod output;
mod proxy;
mod pty;
mod sandbox;
mod secret;
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

fn apply_browser_profile(config: &mut config::Config, command_trusted: bool) {
    // Capture before we set browser_profile below: an explicit profile comes
    // from `--browser` on the CLI or from trusted global config, both trusted.
    let explicit_profile = config.browser_profile().is_some();
    let Some(profile) = resolve_browser_profile(config) else {
        return;
    };

    config.browser_profile = Some(profile.as_str().into());
    config.no_gpu.get_or_insert(true);
    config.no_docker = Some(true);
    config.no_worktree = Some(true);
    config.no_mise = Some(true);
    config.no_toolchains = Some(true);
    config.agent_state = Some(false);
    config.no_save_config = Some(true);
    config.ssh = Some(false);
    config.pictures = Some(false);
    config.no_status_bar = Some(true);

    // The browser profile clears lockdown so a browser window can actually
    // reach the display and network. That is fine when the browser was chosen
    // by trusted input — an explicit `--browser`/global profile, or a command
    // the user or a trusted layer supplied. It is NOT fine when a browser
    // command was adopted from an untrusted project `.ai-jail`: that would let
    // a cloned repo downgrade a trusted `--lockdown`/global `lockdown = true`
    // (advisory GHSA-w976-gw52-hvx2 #3). In that case keep lockdown; the rest
    // of the profile still applies (it only tightens), so the browser simply
    // will not have display/network — run it from the CLI to open it.
    if explicit_profile || command_trusted || !config.lockdown_enabled() {
        config.lockdown = Some(false);
    } else {
        output::security_warn(
            "project .ai-jail browser command does not clear --lockdown; \
             name the browser on the CLI to open a window",
        );
    }
}

/// Phantom credentials (issue #135): validate every `secret_hosts`
/// binding and rewrite the bound `env_pass` entries to placeholders,
/// moving the real values into supervisor-side `SecretBinding`s for the
/// egress proxy. All violations hard-error; the caller runs this before
/// any sandbox starts.
///
/// A binding requires: filtered egress (CONNECT tunnels are opaque, so
/// there is nothing to substitute into), a bare hostname that the
/// allowlist covers, and the key already present in `env_pass` (via
/// `--env` or `--env-from-file`). Bare `NAME` entries resolve against
/// the host environment here and are rewritten to the explicit
/// `NAME=placeholder` form so the sandbox deterministically sees the
/// placeholder.
fn prepare_secrets(
    config: &mut config::Config,
) -> Result<Vec<secret::SecretBinding>, String> {
    if config.secret_hosts.is_empty() {
        return Ok(Vec::new());
    }
    if config.network_mode() != config::NetworkMode::Filtered {
        return Err("--secret requires filtered egress (--allow-host); CONNECT tunnels stay opaque".into());
    }
    let bindings_spec: Vec<(String, String)> =
        config.secret_hosts.clone().into_iter().collect();
    let mut bindings = Vec::new();
    for (key, host) in bindings_spec {
        if host.contains("://") || host.contains('/') {
            return Err(format!(
                "--secret {key}: host must be a bare hostname, not {host:?}"
            ));
        }
        if !proxy::allowlist_matches(config.allow_hosts(), &host) {
            return Err(format!(
                "--secret {key}: {host} is not in allow_hosts (pass --allow-host {host})"
            ));
        }
        // Resolve the value the child would actually receive. apply_env_pass
        // applies entries in order and the last one wins, so the effective
        // value is the LAST matching entry, not the first. Rewriting only the
        // first (the previous behaviour) left a later `KEY=real` entry intact,
        // and the child received the real value despite phantomization
        // (advisory-class duplicate-entry bypass). Match by parsed key so a
        // value containing '=' cannot be mistaken for the name.
        let last = config.env_pass.iter().rev().find_map(|entry| {
            config::parse_env_entry(entry)
                .ok()
                .filter(|(name, _)| *name == key.as_str())
        });
        let Some((_, explicit)) = last else {
            return Err(format!(
                "--secret {key}: {key} is not in the sandbox env; pass it via --env or --env-from-file"
            ));
        };
        let real = match explicit {
            Some(value) => value.to_string(),
            None => std::env::var(&key).map_err(|_| {
                format!(
                    "--secret {key}: {key} is named in --env but not set in the host environment"
                )
            })?,
        };
        let binding = secret::SecretBinding::new(&key, &real, &host);
        // Remove EVERY entry for this key, then insert exactly one placeholder,
        // so no later duplicate can reintroduce the real value.
        config.env_pass.retain(|entry| {
            config::parse_env_entry(entry)
                .map(|(name, _)| name != key.as_str())
                .unwrap_or(true)
        });
        config
            .env_pass
            .push(format!("{key}={}", binding.placeholder));
        bindings.push(binding);
    }
    Ok(bindings)
}

/// Test-only escape hatches, compiled in ONLY under the `test-hooks` feature.
/// A default build (release, `cargo install`, CI without the feature) gets the
/// inert fallbacks below, so neither the env-var reads nor their strings exist
/// in the shipped binary — the environment is not a control channel over the
/// SSRF guard or the proxy's TLS trust roots (audit B finding).
#[cfg(all(target_os = "linux", feature = "test-hooks"))]
fn test_extra_roots() -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    let Some(path) = std::env::var_os("AI_JAIL_TEST_PROXY_EXTRA_ROOTS") else {
        return Vec::new();
    };
    let Ok(pem) = std::fs::read(&path) else {
        return Vec::new();
    };
    match rustls::pki_types::CertificateDer::from_pem_slice(&pem) {
        Ok(der) => vec![der],
        Err(_) => Vec::new(),
    }
}

#[cfg(all(target_os = "linux", not(feature = "test-hooks")))]
fn test_extra_roots() -> Vec<rustls::pki_types::CertificateDer<'static>> {
    Vec::new()
}

/// Whether the SSRF address-range guard is disabled for loopback fixtures.
/// Compiled to `false` outside the `test-hooks` feature, with no env read.
#[cfg(all(target_os = "linux", feature = "test-hooks"))]
fn test_allow_private() -> bool {
    std::env::var_os("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE").is_some()
}

#[cfg(all(target_os = "linux", not(feature = "test-hooks")))]
fn test_allow_private() -> bool {
    false
}

/// Network-mode contradiction checks, all fail-closed at launch.
/// `--allow-tcp-port` stays dead (the filtered-egress proxy is the
/// strictly better answer, docs/connect-proxy-plan.md), and filtered
/// egress combines with neither unrestricted network nor browser mode.
fn validate_network_flags(config: &config::Config) -> Result<(), String> {
    if !config.allow_tcp_ports().is_empty() {
        return Err("--allow-tcp-port is disabled (UDP cannot be isolated); use --allow-host for filtered egress instead".into());
    }
    if config.network_enabled() && !config.allow_hosts().is_empty() {
        return Err("--network and --allow-host are mutually exclusive: filtered egress and unrestricted network cannot be combined".into());
    }
    if config.browser_profile().is_some() && !config.allow_hosts().is_empty() {
        return Err("--browser and --allow-host cannot be combined: browsers need real DNS and many domains".into());
    }
    Ok(())
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

/// `--audit-verify`: walk the audit log and check its hash chain.
/// Exit 0 intact, 1 broken, 2 when no log exists.
fn audit_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(std::path::PathBuf::from)
}

fn run_audit_verify(cli: &cli::CliArgs) -> Result<i32, String> {
    let home = audit_home().ok_or("HOME is not set or empty")?;
    let path = home.join(".local/share/ai-jail/history.jsonl");
    let Some(file) = audit::open_history(&home)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?
    else {
        output::info(&format!("No audit log at {}", path.display()));
        return Ok(2);
    };
    let report = audit::verify(file)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    if cli.verbose {
        output::verbose(&format!(
            "Audit log: {} chained records",
            report.chained
        ));
    }
    if let Some(line) = report.first_break {
        output::error(&format!("BROKEN at line {line}"));
        return Ok(1);
    }
    output::ok(&format!(
        "OK {} records ({} legacy), chain intact",
        report.total, report.legacy
    ));
    Ok(0)
}

fn run_audit_show() -> Result<i32, String> {
    let home = audit_home().ok_or("HOME is not set or empty")?;
    let report = audit::show(&home, &mut std::io::stdout().lock())
        .map_err(|error| format!("Cannot display audit log: {error}"))?;
    match report {
        None => {
            output::info("No audit log found. Enable it with --audit-log.");
            Ok(2)
        }
        Some(report) => {
            if report.total == 0 {
                output::info("Audit log is empty.");
            }
            Ok(i32::from(report.invalid > 0))
        }
    }
}

/// True when the destination of a toolchain map spec is already the destination
/// of a user-supplied ro/rw/overlay map, so the user's explicit mapping wins
/// over the auto-injected toolchain cache map.
/// Whether the default package-registry egress should be injected: toolchain
/// support on, not lockdown, and the network posture unset — neither
/// `--network` (unrestricted, which cannot combine with filtered egress) nor
/// `--no-network` (which keeps the sandbox fully offline) — and not a browser
/// launch (browsers need real DNS and many domains).
fn default_registry_egress_applies(config: &config::Config) -> bool {
    // Linux only (issue #148): the toolchain default behavior — cache maps and
    // this registry egress — is a Linux feature. macOS keeps its pre-v2.5.0
    // posture (fully offline by default) rather than an unvalidated seatbelt
    // egress path.
    cfg!(target_os = "linux")
        && config.toolchains_enabled()
        && !config.lockdown_enabled()
        && config.network.is_none()
        && config.browser_profile.is_none()
}

fn toolchain_dest_already_mapped(config: &config::Config, spec: &str) -> bool {
    let dest = |p: &std::path::Path| {
        config::MapSpec::parse(p)
            .map(|s| s.destination)
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let target = dest(std::path::Path::new(spec));
    config
        .ro_maps
        .iter()
        .chain(config.rw_maps.iter())
        .chain(config.overlay_maps.iter())
        .any(|entry| dest(entry) == target)
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

    // Filtered egress (Linux): spawn the in-sandbox bridge BEFORE
    // apply_landlock/apply_seccomp below. Both restrict the caller and
    // its future children only, so an already-spawned bridge process
    // stays unrestricted -- it needs loopback listen plus Unix connect,
    // neither of which the sandbox policy would grant. The bridge dies
    // with the sandbox: it sits in the private pid namespace bwrap
    // created (--unshare-pid), and the kernel kills every namespace
    // member when the namespace init -- this process, after the exec
    // below -- exits.
    #[cfg(target_os = "linux")]
    if let Some(port) = cli.proxy_bridge_port {
        spawn_proxy_bridge(port)?;
    }

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

/// Spawn the in-sandbox proxy bridge as a child of the landlock
/// wrapper. Fatal on spawn failure: without the bridge, filtered egress
/// silently means "no egress at all", which is not what the launch
/// asked for. The child is never reaped or waited on -- it lives
/// exactly as long as the sandbox's pid namespace (see the call site).
#[cfg(target_os = "linux")]
fn spawn_proxy_bridge(port: u16) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| {
        format!("Cannot resolve ai-jail binary for the proxy bridge: {e}")
    })?;
    std::process::Command::new(exe)
        .args([
            "--proxy-bridge",
            port.to_string().as_str(),
            proxy::IN_SANDBOX_SOCK_PATH,
        ])
        // The internal-mode marker --proxy-bridge refuses to run
        // without; an agent that can already reach the proxy socket
        // gains nothing by setting it itself.
        .env("AI_JAIL_PROXY_BRIDGE", "1")
        .spawn()
        .map_err(|e| format!("Failed to spawn the proxy bridge: {e}"))?;
    Ok(())
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

fn internal_mode_inherits_quiet(
    landlock_exec: bool,
    proxy_bridge: bool,
    inherited_quiet: bool,
) -> bool {
    inherited_quiet && (landlock_exec || proxy_bridge)
}

fn run() -> Result<i32, String> {
    let cli = cli::parse()?;
    validate_write_flags(&cli)?;

    // Suppress info/warn output in --exec mode for clean stdout
    if cli.exec {
        output::set_quiet(true);
    }

    let internal_quiet = internal_mode_inherits_quiet(
        cli.landlock_exec,
        cli.proxy_bridge.is_some(),
        std::env::var_os("AI_JAIL_QUIET").is_some(),
    );
    if internal_quiet {
        output::set_quiet(true);
    }

    // Internal: apply Landlock and exec (used inside bwrap sandbox)
    if cli.landlock_exec {
        return run_landlock_exec(&cli);
    }

    // Internal: the in-sandbox filtered-egress bridge (spawned by the
    // landlock wrapper, which sets the marker env var; top-level
    // invocation is refused).
    if cli.proxy_bridge.is_some()
        && std::env::var_os("AI_JAIL_PROXY_BRIDGE").is_none()
    {
        return Err(
            "--proxy-bridge is an internal mode, not a launch option".into()
        );
    }
    if let Some((port, socket)) = &cli.proxy_bridge {
        return proxy::run_bridge(*port, socket).map(|()| 0);
    }

    // Offline audit commands bypass configuration and sandbox setup.
    if cli.audit_show {
        return run_audit_show();
    }
    if cli.audit_verify {
        return run_audit_verify(&cli);
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
    // Whether the effective command is trusted for the browser-profile
    // lockdown decision below. It is adopted from the project file only when
    // the CLI gave none and the project supplied one; that command is trusted
    // only if the project directory is itself trusted (#3, browser lockdown
    // downgrade).
    let command_from_untrusted_project = cli.command.is_empty()
        && !project_config.command.is_empty()
        && !project_trusted;
    if cli.command.is_empty() && !project_config.command.is_empty() {
        config.command = project_config.command.clone();
    }
    for warning in security_warnings {
        output::security_warn(&warning);
    }
    // Capability gaps for known API-client agents (issue #131): warn at
    // launch so an upgrade that flips a default does not fail silently.
    // `output::warn` respects --exec quiet mode like other non-security
    // warnings; the launch itself is never blocked.
    for warning in command::capability_gap_warnings(&config) {
        output::warn(&warning);
    }
    // Resolve any relative paths in rw_maps/ro_maps against the user's
    // invocation cwd before they reach bwrap/landlock/seatbelt (issue
    // #54). Done here so display_status and the --init save path see
    // the same canonical paths the sandbox will use.
    config::absolutize_user_paths(&mut config, &invocation_cwd);
    apply_browser_profile(&mut config, !command_from_untrusted_project);
    validate_network_flags(&config)?;

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

    // mise passthrough (issue #113): mise is enabled by default and already
    // activated inside the sandbox, but the default private home maps only
    // dotdirs, so mise's data/config dirs and the `mise` binary were never
    // visible — activation found nothing and every mise-managed tool, the
    // agent executable included, vanished from PATH. Map those paths
    // read-only whenever mise is enabled; `--no-mise` and `--lockdown` opt out
    // (they already disable mise activation). Added after the status/init/
    // bootstrap early returns and the save paths so these derived,
    // host-specific paths are never persisted into a saved `.ai-jail` nor
    // shown as user maps in `ai-jail status`.
    if config.mise_enabled() && !config.lockdown_enabled() {
        for dir in sandbox::mise_auto_map_dirs() {
            if !config.ro_maps.contains(&dir) && !config.rw_maps.contains(&dir)
            {
                config.ro_maps.push(dir);
            }
        }
        // mise's data dir is mapped read-only above, so mise can never finish
        // an auto-install of a declared-but-missing tool inside the jail — it
        // only fails noisily ("Read-only file system") on every shim call.
        // Disable the doomed attempt so a missing tool fails once, cleanly.
        // A user's explicit --env for the same name still wins.
        let var = "MISE_NOT_FOUND_AUTO_INSTALL";
        let already = config
            .env_pass
            .iter()
            .any(|e| e == var || e.starts_with(&format!("{var}=")));
        if !already {
            config.env_pass.push(format!("{var}=false"));
        }
    }

    // Dev-toolchain cache persistence (Part A). On by default outside lockdown;
    // `--no-toolchains` and the untrusted project `.ai-jail` can only disable
    // it. Read-only toolchain binaries and a persistent jail-owned dependency
    // cache are injected as maps so they flow through the same bwrap mount and
    // Landlock rule path as every other map. Injected here, after the
    // status/--init/bootstrap early returns and the save paths, so these
    // derived, host-specific paths are never written into a saved `.ai-jail`
    // nor shown as user maps in `ai-jail status`. A user's own explicit map for
    // the same destination always wins.
    if config.toolchains_enabled() && !config.lockdown_enabled() {
        let maps = sandbox::toolchain_maps();
        for spec in maps.ro {
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.ro_maps.push(std::path::PathBuf::from(spec));
            }
        }
        for spec in maps.rw {
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.rw_maps.push(std::path::PathBuf::from(spec));
            }
        }
    }

    // Default-allow the package registries (filtered egress) so dependency
    // fetches work without the user passing --allow-host. Deny-by-default still
    // holds: only these hosts become reachable. An explicit --allow-host set is
    // unioned with these. Gated on netns availability: filtered egress fences
    // the sandbox in a private netns and fails closed, so where netns is
    // unavailable the auto-default stays offline rather than breaking the launch
    // (an explicit --allow-host keeps its fail-closed behavior).
    if default_registry_egress_applies(&config)
        && sandbox::unprivileged_netns_available()
    {
        for host in sandbox::TOOLCHAIN_REGISTRY_HOSTS {
            if !config.allow_hosts.iter().any(|h| h == host) {
                config.allow_hosts.push((*host).to_string());
            }
        }
    }

    // Opt-in, read-only credential passthrough (aws/kube/gcloud/
    // docker_config): off by default, disabled under --lockdown. Injected
    // here, after the status/--init/bootstrap early returns and the save
    // paths, so these derived, host-specific paths are never written into
    // a saved `.ai-jail` nor shown as user maps in `ai-jail status`. A
    // user's own explicit map for the same destination always wins.
    if !config.lockdown_enabled() {
        for path in sandbox::credential_ro_paths(&config) {
            let spec = path.to_string_lossy().into_owned();
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.ro_maps.push(path);
            }
        }
    }

    // Pre-authenticate API-key harnesses: when agent state is on (the default,
    // off under --lockdown), copy the invoked harness's well-known API-key env
    // var from the host into the sandbox if it is set, so a harness that
    // authenticates via a key (not an OAuth file) also starts authenticated.
    // Injected after the save/--init/bootstrap returns so it is never persisted;
    // an explicit --env for the same name already present wins.
    if config.agent_state_enabled() {
        let harness =
            command::effective_name(&config.command).map(str::to_string);
        if let Some(name) = harness {
            for var in command::harness_api_key_env(&name) {
                let already = config
                    .env_pass
                    .iter()
                    .any(|e| e == var || e.starts_with(&format!("{var}=")));
                if !already && std::env::var_os(var).is_some() {
                    config.env_pass.push((*var).to_string());
                }
            }
        }
    }

    // --env-from-file (phase 6 of docs/connect-proxy-plan.md): validated
    // credential files. Entries apply exactly like --env, and on a
    // conflict the --env entry wins (closest to the user), so the file
    // entries come first; apply_env_pass replaces earlier values with
    // later ones. Forced setenvs (the filtered-egress proxy vars) are
    // applied after all of this and still win. This runs after the
    // status/init/bootstrap early returns so secret values never reach
    // `ai-jail status` output.
    if !config.env_from_file.is_empty() {
        let file_entries =
            config::load_env_files(&config.env_from_file, &invocation_cwd)?;
        let mut env_pass = file_entries;
        env_pass.extend(config.env_pass.iter().cloned());
        config.env_pass = env_pass;
    }

    // The GitHub config directory may live under GH_CONFIG_DIR or
    // XDG_CONFIG_HOME, and its active token may live in the host keyring.
    // Resolve both after --env-from-file is applied, but never fetch a token
    // for dry-run. These derived values are used for this launch only.
    let github =
        github_auth::prepare(&mut config, &invocation_cwd, cli.dry_run);
    if let Some(path) = github.config_dir.filter(|path| path.is_dir()) {
        let spec = path.to_string_lossy().into_owned();
        if !toolchain_dest_already_mapped(&config, &spec) {
            config.ro_maps.push(path);
        }
    }
    if let Some(warning) = github.warning {
        output::warn(warning);
    }

    // Phantom credentials (issue #135): each bound key's env_pass entry
    // is rewritten to a placeholder the sandbox sees; the real value
    // moves into a supervisor-side SecretBinding for the egress proxy.
    // All violations hard-error here, before any sandbox starts.
    let secrets = prepare_secrets(&mut config)?;

    // Check sandbox tool is available
    sandbox::check()?;

    // Platform-specific info messages (e.g. no-op flags on macOS)
    sandbox::platform_notes(&config);

    // Opt-in launch audit log (phase 5 of docs/connect-proxy-plan.md):
    // a supervisor-side JSONL file the sandbox never sees. Opened here
    // so the filtered-egress proxy below can share the handle; the
    // launch record itself is appended when the child exits.
    let audit_home = audit_home();
    let audit_log = if config.audit_log_enabled() {
        match audit_home.as_deref() {
            Some(home) => audit::AuditLog::open(home),
            None => {
                output::security_warn(
                    "audit log disabled: HOME is not set or empty",
                );
                None
            }
        }
    } else {
        None
    };
    let launch_start = std::time::Instant::now();

    // Prepare sandbox resources (temp hosts file on Linux, no-op on macOS)
    let guard = sandbox::prepare()?;

    // Filtered egress: the CONNECT proxy runs as threads in this
    // supervisor process. On Linux the sandbox reaches it through the
    // bind-mounted Unix socket and the in-sandbox bridge; on macOS the
    // child talks to its loopback TCP port directly (no netns there).
    // The handle must outlive the child, so it stays bound for the rest
    // of run() (dropping it unlinks the socket file).
    #[cfg(target_os = "linux")]
    let egress_proxy = if config.network_mode() == config::NetworkMode::Filtered
    {
        let mut proxy_config =
            proxy::ProxyConfig::new(config.allow_hosts().to_vec());
        // Test-only escape hatches (tests/filtered_egress.rs,
        // tests/phantom_secrets.rs): let the end-to-end tests CONNECT to
        // loopback fixtures and trust a self-signed root. These are compiled
        // in ONLY under the `test-hooks` feature; a release build
        // (`cargo build --release`, `cargo install`) has neither the env-var
        // read nor the string, so they cannot be reached at runtime.
        proxy_config.danger_allow_private = test_allow_private();
        proxy_config.danger_extra_roots = test_extra_roots();
        // The audit handle is supervisor-side; the sandbox never sees
        // the file it appends to.
        proxy_config.audit = audit_log.clone();
        proxy_config.secrets = secrets;
        let socket = proxy::default_socket_path();
        let proxy = proxy::Proxy::start(proxy_config, Some(&socket))
            .map_err(|e| format!("Failed to start the egress proxy: {e}"))?;
        Some(proxy)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let egress_proxy = if config.network_mode() == config::NetworkMode::Filtered
    {
        let mut proxy_config =
            proxy::ProxyConfig::new(config.allow_hosts().to_vec());
        proxy_config.audit = audit_log.clone();
        proxy_config.secrets = secrets;
        let proxy = proxy::Proxy::start(proxy_config, None)
            .map_err(|e| format!("Failed to start the egress proxy: {e}"))?;
        Some(proxy)
    } else {
        None
    };

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
        let formatted = sandbox::dry_run(
            &guard,
            &config,
            &project_dir,
            cli.verbose,
            egress_proxy.as_ref(),
        )?;
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
        egress_proxy.as_ref(),
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

    // Append the launch record only now: exit code and duration are
    // what make it an audit trail rather than a log of intentions.
    if let Some(log) = &audit_log {
        let network = match config.network_mode() {
            config::NetworkMode::Off => "off",
            config::NetworkMode::Filtered => "filtered",
            config::NetworkMode::Full => "full",
        };
        log.record(audit::launch_record(&audit::LaunchRecord {
            command: &config.command,
            network_mode: network,
            allow_hosts: config.allow_hosts(),
            lockdown: config.lockdown_enabled(),
            agent_state: config.agent_state_enabled(),
            gpu: config.gpu_enabled(),
            display: config.display_enabled(),
            audio: config.audio_enabled(),
            kvm: config.kvm_enabled(),
            browser_profile: config.browser_profile.as_deref(),
            project_config: !cli.clean
                && invocation_cwd.join(".ai-jail").is_file(),
            project_trusted,
            global_config: audit_home
                .as_ref()
                .is_some_and(|home| home.join(".ai-jail").exists()),
            exit_code,
            duration: launch_start.elapsed(),
        }));
    }

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
        default_registry_egress_applies, default_resize_redraw_key,
        exec_requires_terminal_passthrough, internal_mode_inherits_quiet,
        prune_missing_path_entries, pty_proxy_active, resolve_browser_profile,
        running_inside_multiplexer, should_auto_save_project_config,
        should_check_update, should_save_global_preferences,
        validate_network_flags, validate_write_flags,
    };
    use crate::cli::CliArgs;
    use crate::config::{BrowserProfile, Config};
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn internal_modes_inherit_quiet_output() {
        assert!(internal_mode_inherits_quiet(true, false, true));
        assert!(internal_mode_inherits_quiet(false, true, true));
        assert!(!internal_mode_inherits_quiet(false, false, true));
        assert!(!internal_mode_inherits_quiet(true, true, false));
    }

    #[test]
    fn default_registry_egress_only_when_posture_unset() {
        // Default: toolchains on, network unset, no browser -> applies on
        // Linux (the feature is Linux-only; macOS stays offline, issue #148).
        assert_eq!(
            default_registry_egress_applies(&Config::default()),
            cfg!(target_os = "linux")
        );
        // --no-network keeps the sandbox fully offline.
        assert!(!default_registry_egress_applies(&Config {
            network: Some(false),
            ..Config::default()
        }));
        // --network is unrestricted; no filtered-egress injection.
        assert!(!default_registry_egress_applies(&Config {
            network: Some(true),
            ..Config::default()
        }));
        // Lockdown stays offline.
        assert!(!default_registry_egress_applies(&Config {
            lockdown: Some(true),
            ..Config::default()
        }));
        // Opted out of toolchains.
        assert!(!default_registry_egress_applies(&Config {
            no_toolchains: Some(true),
            ..Config::default()
        }));
        // Browser launches need real DNS, not filtered egress.
        assert!(!default_registry_egress_applies(&Config {
            browser_profile: Some("hard".into()),
            ..Config::default()
        }));
    }

    #[test]
    fn crush_requires_direct_tty() {
        assert!(command_needs_direct_tty(&["crush".into()]));
        assert!(command_needs_direct_tty(&["/usr/bin/crush".into()]));
    }

    #[test]
    fn allow_tcp_port_error_points_at_allow_host() {
        let config = Config {
            allow_tcp_ports: vec![443],
            ..Config::default()
        };
        let error = validate_network_flags(&config).unwrap_err();
        assert!(error.contains("--allow-tcp-port is disabled"));
        assert!(error.contains("--allow-host"));
    }

    #[test]
    fn network_and_allow_host_contradiction_hard_errors() {
        let config = Config {
            network: Some(true),
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        let error = validate_network_flags(&config).unwrap_err();
        assert!(error.contains("mutually exclusive"));
    }

    #[test]
    fn browser_and_allow_host_contradiction_hard_errors() {
        let config = Config {
            browser_profile: Some("hard".into()),
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        let error = validate_network_flags(&config).unwrap_err();
        assert!(error.contains("--browser"));
        assert!(error.contains("--allow-host"));
    }

    #[test]
    fn allow_host_alone_and_with_lockdown_is_valid() {
        let filtered = Config {
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        assert!(validate_network_flags(&filtered).is_ok());
        let locked = Config {
            lockdown: Some(true),
            ..filtered.clone()
        };
        assert!(validate_network_flags(&locked).is_ok());
        assert!(validate_network_flags(&Config::default()).is_ok());
    }

    #[test]
    fn secrets_require_filtered_mode_allowlist_and_env_key() {
        // Not filtered.
        let mut config = Config {
            env_pass: vec!["KEY=real".into()],
            secret_hosts: [("KEY".into(), "example.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        let error = super::prepare_secrets(&mut config).unwrap_err();
        assert!(error.contains("--allow-host"));

        // Key not in env_pass: the error names --env-from-file.
        let mut config = Config {
            allow_hosts: vec!["example.com".into()],
            secret_hosts: [("MISSING".into(), "example.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        let error = super::prepare_secrets(&mut config).unwrap_err();
        assert!(error.contains("--env-from-file"));

        // Host not allowlisted.
        let mut config = Config {
            allow_hosts: vec!["example.com".into()],
            env_pass: vec!["KEY=real".into()],
            secret_hosts: [("KEY".into(), "evil.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        let error = super::prepare_secrets(&mut config).unwrap_err();
        assert!(error.contains("not in allow_hosts"));

        // Scheme/path in the host is rejected.
        let mut config = Config {
            allow_hosts: vec!["example.com".into()],
            env_pass: vec!["KEY=real".into()],
            secret_hosts: [("KEY".into(), "https://example.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        assert!(super::prepare_secrets(&mut config).is_err());
    }

    #[test]
    fn secrets_swap_env_pass_for_placeholders() {
        let _env = ENV_LOCK.lock().unwrap();
        let _bare = EnvVarGuard::set("AI_JAIL_TEST_BARE_KEY", "bare-real");

        let mut config = Config {
            allow_hosts: vec!["example.com".into()],
            env_pass: vec![
                "KEY=real-value".into(),
                "AI_JAIL_TEST_BARE_KEY".into(),
            ],
            secret_hosts: [
                ("KEY".into(), "example.com".into()),
                ("AI_JAIL_TEST_BARE_KEY".into(), "example.com".into()),
            ]
            .into_iter()
            .collect(),
            ..Config::default()
        };
        let bindings = super::prepare_secrets(&mut config).unwrap();
        assert_eq!(bindings.len(), 2);
        for binding in &bindings {
            let entry = config
                .env_pass
                .iter()
                .find(|e| e.starts_with(&format!("{}=", binding.key)))
                .unwrap();
            // The sandbox sees the placeholder, never the real value.
            assert!(entry.ends_with(&binding.placeholder));
            assert!(binding.placeholder.starts_with("AIJAIL-PHANTOM-"));
            assert!(!entry.contains(&binding.real));
        }
        assert_eq!(
            bindings.iter().find(|b| b.key == "KEY").unwrap().real,
            "real-value"
        );
        assert_eq!(
            bindings
                .iter()
                .find(|b| b.key == "AI_JAIL_TEST_BARE_KEY")
                .unwrap()
                .real,
            "bare-real"
        );
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
    fn browser_profile_keeps_lockdown_for_untrusted_command() {
        // Advisory GHSA-w976-gw52-hvx2 #3: a browser command adopted from an
        // untrusted project must not clear a trusted lockdown.
        let mut config = Config {
            command: vec!["chromium".into()],
            lockdown: Some(true),
            ..Config::default()
        };
        apply_browser_profile(&mut config, /* command_trusted */ false);
        assert_eq!(
            config.lockdown,
            Some(true),
            "untrusted project browser command must not clear lockdown"
        );
        // The profile still applies its tightening bits.
        assert_eq!(config.browser_profile.as_deref(), Some("hard"));
        assert_eq!(config.no_docker, Some(true));
    }

    #[test]
    fn browser_profile_clears_lockdown_for_trusted_command() {
        // A user- or trusted-layer command still opens the browser.
        let mut config = Config {
            command: vec!["chromium".into()],
            lockdown: Some(true),
            ..Config::default()
        };
        apply_browser_profile(&mut config, /* command_trusted */ true);
        assert_eq!(config.lockdown, Some(false));
        assert_eq!(config.browser_profile.as_deref(), Some("hard"));
    }

    #[test]
    fn browser_profile_applies_hardened_defaults() {
        let mut config = Config {
            command: vec!["chromium".into()],
            ..Config::default()
        };
        apply_browser_profile(&mut config, true);

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
        // C3: browser collateral — toolchain cache off and agent-state off,
        // so a browser profile never mounts dev caches or the harness's own
        // credential/state dirs.
        assert_eq!(config.no_toolchains, Some(true));
        assert_eq!(config.agent_state, Some(false));
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
