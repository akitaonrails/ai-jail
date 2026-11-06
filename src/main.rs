#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("ai-jail only supports Linux and macOS");

mod audit;
mod authority_inventory;
mod bootstrap;
mod cli;
#[cfg(target_os = "macos")]
mod codex_ps;
mod command;
mod config;
mod config_store;
mod forge_auth;
mod fsutil;
mod github_auth;
mod integration;
mod onboarding;
mod output;
mod proxy;
mod pty;
mod sandbox;
mod secret;
mod signals;
mod ssh_restricted;
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

/// How long a host prompt waits for an answer before counting as a deny.
#[cfg(target_os = "linux")]
const HOST_PROMPT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Interactive host prompt (`--prompt-hosts`) for the egress proxy, never
/// under `--lockdown`. Without a trusted `notify-send`, hosts outside the
/// allowlist stay refused as before.
#[cfg(target_os = "linux")]
fn host_prompt(
    config: &config::Config,
) -> Option<std::sync::Arc<dyn proxy::HostPrompt>> {
    if !config.prompt_hosts_enabled() || config.lockdown_enabled() {
        return None;
    }
    let Some(program) = sandbox::bwrap::trusted_system_binary("notify-send")
    else {
        output::warn(
            "--prompt-hosts: no trusted notify-send found; hosts outside \
             the allowlist stay refused",
        );
        return None;
    };
    let label = command::effective_name(&config.command)
        .unwrap_or("the agent")
        .to_string();
    Some(std::sync::Arc::new(proxy::NotifySendPrompt {
        program,
        label,
        timeout: HOST_PROMPT_TIMEOUT,
    }))
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

/// A one-line hint for a browser profile that will not get a window: on
/// Linux the display is an explicit opt-in, and without it the browser
/// exits with only its own "failed to connect to display" error. Silent
/// when there is no display on the host to pass, under lockdown (which
/// has its own warning above), and on macOS, where the display is
/// system-level.
fn browser_display_hint(
    config: &config::Config,
    host_has_display: bool,
) -> Option<&'static str> {
    (cfg!(target_os = "linux")
        && host_has_display
        && config.browser_profile().is_some()
        && !config.lockdown_enabled()
        && !config.display_enabled()
        && !config.x11_enabled())
    .then_some(
        "ai-jail: browser profile without --display: the browser cannot \
         open a window — pass --display (or --x11 for an X11-only browser)",
    )
}

fn host_has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
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
        if !config.host_is_allowlisted(&host) {
            return Err(format!(
                "--secret {key}: {host} is not in allow_hosts or allow_private_hosts \
                 (pass --allow-host {host} or --allow-private-host {host})"
            ));
        }
        // Resolve the value the child would actually receive. apply_env_pass
        // applies entries in order, skipping bare variables absent from the
        // host, so the effective value is the LAST matching entry that has a
        // value, not the first. Rewriting only the
        // first (the previous behaviour) left a later `KEY=real` entry intact,
        // and the child received the real value despite phantomization
        // (advisory-class duplicate-entry bypass). Match by parsed key so a
        // value containing '=' cannot be mistaken for the name.
        let mut named = false;
        let real = config.env_pass.iter().rev().find_map(|entry| {
            let (name, explicit) = config::parse_env_entry(entry).ok()?;
            if name != key {
                return None;
            }
            named = true;
            explicit
                .map(str::to_string)
                .or_else(|| std::env::var(&key).ok())
        });
        let Some(real) = real else {
            return Err(if named {
                format!(
                    "--secret {key}: {key} is named in --env but not set in the host environment"
                )
            } else {
                format!(
                    "--secret {key}: {key} is not in the sandbox env; pass it via --env or --env-from-file"
                )
            });
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

/// GHSA-v2fr-83mr-f9cg, open question A: when the effective command came
/// from an untrusted project `.ai-jail` and names a known API harness,
/// the harness defaults still provision its credentials (state dir
/// mounted read-write, API key forwarded, API hosts default-allowed).
/// Selecting what runs is an allowed project power; silently gaining the
/// user's agent credentials is not — the launch warns. Returns the
/// harness name when the warning applies.
fn untrusted_project_command_carries_credentials(
    command_from_untrusted_project: bool,
    config: &config::Config,
) -> Option<String> {
    if !command_from_untrusted_project || !config.agent_state_enabled() {
        return None;
    }
    let name = command::effective_name(&config.command)?;
    if command::is_known_api_agent(name) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Network-mode contradiction checks, all fail-closed at launch.
/// `--allow-tcp-port` stays dead (the filtered-egress proxy is the
/// strictly better answer, docs/connect-proxy-plan.md), and filtered
/// egress combines with neither unrestricted network nor browser mode.
fn validate_network_flags(config: &config::Config) -> Result<(), String> {
    if !config.allow_tcp_ports().is_empty() {
        return Err("--allow-tcp-port is disabled (UDP cannot be isolated); use --allow-host for filtered egress instead".into());
    }
    if config.network_enabled() && config.has_filtered_hosts() {
        return Err("--network and --allow-host/--allow-private-host are mutually exclusive: filtered egress and unrestricted network cannot be combined".into());
    }
    if config.browser_profile().is_some() && config.has_filtered_hosts() {
        return Err("--browser and --allow-host/--allow-private-host cannot be combined: browsers need real DNS and many domains".into());
    }
    validate_forward_ports(config)?;
    validate_publish_ports(config)
}

/// `--publish-port` contradiction checks, fail-closed at launch. The
/// forward rules apply, mirrored: a publish only means something while
/// the sandbox has its own loopback, which also rules out macOS (the
/// sandbox shares the host's network stack there). A port cannot be
/// both forwarded and published: both bridges would claim it in here.
fn validate_publish_ports(config: &config::Config) -> Result<(), String> {
    if config.publish_ports().is_empty() {
        return Ok(());
    }
    if cfg!(not(target_os = "linux")) {
        return Err("--publish-port is supported on Linux only".into());
    }
    if config.network_enabled() {
        return Err("--network and --publish-port are mutually exclusive: with unrestricted network the sandbox already listens on the host's loopback".into());
    }
    for &port in config.publish_ports() {
        if port == 0 {
            return Err("--publish-port 0 is not a port".into());
        }
        if port < 1024 {
            return Err(format!(
                "--publish-port {port}: ports below 1024 are not supported"
            ));
        }
        if port == proxy::BRIDGE_PORT {
            return Err(format!(
                "--publish-port {port} is reserved for the proxy bridge"
            ));
        }
        if config.forward_ports().contains(&port) {
            return Err(format!(
                "--forward-port {port} and --publish-port {port} cannot be combined: both need the sandbox's 127.0.0.1:{port}"
            ));
        }
    }
    Ok(())
}

/// `--forward-port` contradiction checks, fail-closed at launch. A
/// forward only means something while the host loopback is otherwise
/// unreachable; the in-sandbox bridge port is taken; port 0 names no
/// service.
fn validate_forward_ports(config: &config::Config) -> Result<(), String> {
    if config.forward_ports().is_empty() {
        return Ok(());
    }
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        return Err(
            "--forward-port is supported on Linux and macOS only".into()
        );
    }
    if config.network_enabled() {
        return Err("--network and --forward-port are mutually exclusive: with unrestricted network the host's loopback is already reachable".into());
    }
    for &port in config.forward_ports() {
        if port == 0 {
            return Err("--forward-port 0 is not a port".into());
        }
        // The Linux netns keeps ip_unprivileged_port_start (1024) and the
        // bridge port; macOS refuses the same ports so one entry fits both.
        if port < 1024 {
            return Err(format!(
                "--forward-port {port}: ports below 1024 are not supported"
            ));
        }
        if port == proxy::BRIDGE_PORT {
            return Err(format!(
                "--forward-port {port} is reserved for the proxy bridge"
            ));
        }
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

/// Give a launch of a known API agent (one with a canonical API host in
/// `command::default_egress_hosts`) filtered egress to those hosts whenever the
/// user has not asserted a network posture (issue #156). Like the
/// package-registry default, this is _unioned_ with any explicit `--allow-host`
/// list rather than suppressed by it: adding a host (`--allow-host github.com
/// claude`) keeps the agent's own API reachable, which is almost always what
/// the user meant. The verbatim "exactly this list, nothing automatic" mode is
/// `--no-network --allow-host …`, which sets `network` and so disables both
/// this and the registry default while still composing to filtered egress. The
/// sandbox stays deny-by-default; `--network`, `--lockdown`, and browser
/// launches keep their existing semantics. Unlike the registry default this is
/// not Linux-only: macOS filtered egress is a seatbelt loopback rule, so it
/// applies there too.
fn default_agent_api_egress_applies(config: &config::Config) -> bool {
    !command::default_egress_hosts(&config.command).is_empty()
        && config.network.is_none()
        && !config.lockdown_enabled()
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

#[derive(Clone, Debug)]
pub(crate) struct FinalizedLaunch {
    pub(crate) config: config::Config,
    secrets: Vec<secret::SecretBinding>,
    github_warning: Option<&'static str>,
    restricted_ssh: Option<ssh_restricted::Plan>,
    pub(crate) reviewed_forge: ReviewedForge,
}

#[derive(Clone, Debug)]
pub(crate) enum ReviewedForge {
    /// Legacy/non-onboarding launches did not present forge authority in a
    /// review screen and retain the established attach behavior.
    Unreviewed,
    /// Onboarding reviewed the exact metadata snapshot, including absence.
    Reviewed(Option<forge_auth::AuthorityPreview>),
}

impl ReviewedForge {
    pub(crate) fn verify(
        &self,
        actual: Option<&forge_auth::Runtime>,
    ) -> Result<(), String> {
        match (self, actual) {
            (Self::Unreviewed, _) | (Self::Reviewed(None), None) => Ok(()),
            (Self::Reviewed(Some(expected)), Some(actual))
                if expected.matches_runtime(actual) => Ok(()),
            (Self::Reviewed(None), Some(_)) => Err(
                "Forge authority appeared after final review; review access again before launch"
                    .into(),
            ),
            (Self::Reviewed(Some(_)), None) => Err(
                "Reviewed forge authority disappeared before launch; review access again"
                    .into(),
            ),
            (Self::Reviewed(Some(_)), Some(_)) => Err(
                "Forge authority changed after final review; review access again before launch"
                    .into(),
            ),
        }
    }
}

/// Immutable owner of all post-finalization launch authority. Production and
/// tests use these same final-consumer methods, so no code between preview and
/// proxy/sandbox handoff can replace or mutate the finalized policy.
struct LaunchRunner {
    finalized: FinalizedLaunch,
    restricted_ssh: Option<ssh_restricted::Runtime>,
    forge: Option<forge_auth::Runtime>,
}

impl LaunchRunner {
    fn new(finalized: FinalizedLaunch) -> Self {
        Self {
            finalized,
            restricted_ssh: None,
            forge: None,
        }
    }

    fn config(&self) -> &config::Config {
        &self.finalized.config
    }

    fn github_warning(&self) -> Option<&'static str> {
        self.finalized.github_warning
    }

    fn finish_proxy_config(
        &self,
        mut proxy_config: proxy::ProxyConfig,
    ) -> proxy::ProxyConfig {
        proxy_config.secrets = self.finalized.secrets.clone();
        proxy_config
    }

    fn build_sandbox<R>(
        &self,
        builder: impl FnOnce(&config::Config) -> R,
    ) -> R {
        builder(&self.finalized.config)
    }

    fn start_restricted_ssh(&mut self) -> Result<(), String> {
        if let Some(plan) = &self.finalized.restricted_ssh {
            self.restricted_ssh = Some(plan.start()?);
        }
        Ok(())
    }

    fn attach_forge(
        &mut self,
        store: &config_store::StorePaths,
    ) -> Result<(), String> {
        if self.finalized.config.lockdown_enabled() {
            return Ok(());
        }
        let runtime = forge_auth::prepare(store)?;
        self.finalized.reviewed_forge.verify(runtime.as_ref())?;
        if let Some(runtime) = runtime {
            runtime.apply(&mut self.finalized.config);
            self.forge = Some(runtime);
        }
        Ok(())
    }
}

/// Apply every host-derived launch mutation exactly once. The returned config
/// is the immutable policy rendered to the user and later passed to sandbox
/// execution; supervisor-only secrets stay beside it.
#[cfg(test)]
pub(crate) fn finalize_launch_config(
    config: config::Config,
    project: &std::path::Path,
    dry_run: bool,
) -> Result<FinalizedLaunch, String> {
    finalize_launch_config_with_ssh(config, project, dry_run, None)
}

pub(crate) fn finalize_launch_config_with_ssh(
    mut config: config::Config,
    project: &std::path::Path,
    dry_run: bool,
    restricted_ssh: Option<ssh_restricted::Policy>,
) -> Result<FinalizedLaunch, String> {
    if config.lockdown_enabled() {
        forge_auth::strip_runtime(&mut config);
    }
    if config.mise_enabled() && !config.lockdown_enabled() {
        for dir in sandbox::mise_auto_map_dirs() {
            if !config.ro_maps.contains(&dir) && !config.rw_maps.contains(&dir)
            {
                config.ro_maps.push(dir);
            }
        }
        if !config.env_pass.iter().any(|entry| {
            entry == "MISE_NOT_FOUND_AUTO_INSTALL"
                || entry.starts_with("MISE_NOT_FOUND_AUTO_INSTALL=")
        }) {
            config
                .env_pass
                .push("MISE_NOT_FOUND_AUTO_INSTALL=false".into());
        }
    }
    if config.toolchains_enabled() && !config.lockdown_enabled() {
        let maps = sandbox::toolchain_maps();
        for spec in maps.ro {
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.ro_maps.push(spec.into());
            }
        }
        for spec in maps.rw {
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.rw_maps.push(spec.into());
            }
        }
    }
    if default_agent_api_egress_applies(&config)
        && sandbox::unprivileged_netns_available()
    {
        for host in command::default_egress_hosts_for(
            &config.runtime_harnesses,
            &config.command,
        ) {
            if !config.allow_hosts.iter().any(|allowed| allowed == host) {
                config.allow_hosts.push((*host).into());
            }
        }
    }
    if default_registry_egress_applies(&config)
        && sandbox::unprivileged_netns_available()
    {
        for host in sandbox::TOOLCHAIN_REGISTRY_HOSTS {
            if !config.allow_hosts.iter().any(|allowed| allowed == host) {
                config.allow_hosts.push((*host).into());
            }
        }
    }
    if !config.lockdown_enabled() {
        for path in sandbox::credential_ro_paths(&config) {
            let spec = path.to_string_lossy().into_owned();
            if !toolchain_dest_already_mapped(&config, &spec) {
                config.ro_maps.push(path);
            }
        }
    }
    if config.agent_state_enabled() {
        let harnesses: Vec<String> = config
            .effective_harnesses()
            .into_iter()
            .map(str::to_string)
            .collect();
        for name in &harnesses {
            for var in command::harness_api_key_env(name) {
                if std::env::var_os(var).is_some()
                    && !config.env_pass.iter().any(|entry| {
                        entry == var || entry.starts_with(&format!("{var}="))
                    })
                {
                    config.env_pass.push((*var).into());
                }
            }
        }
    }
    if !config.env_from_file.is_empty() {
        let mut entries =
            config::load_env_files(&config.env_from_file, project)?;
        entries.extend(config.env_pass);
        config.env_pass = entries;
    }
    let github = github_auth::prepare(&mut config, project, dry_run);
    if let Some(path) = github.config_dir.filter(|path| path.is_dir()) {
        let spec = path.to_string_lossy().into_owned();
        if !toolchain_dest_already_mapped(&config, &spec) {
            config.ro_maps.push(path);
        }
    }
    let restricted_ssh = if config.ssh_enabled() || config.lockdown_enabled() {
        None
    } else if let Some(policy) = restricted_ssh {
        if !config.network_enabled() {
            return Err(format!(
                "{} Selected-key SSH needs Unrestricted network (OPEN): filtered egress carries HTTP(S), not native SSH. Enable it knowingly or disable SSH.",
                onboarding::messages::SSH_NETWORK_ID
            ));
        }
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "HOME is required for restricted SSH".to_string())?;
        Some(ssh_restricted::plan(policy, &mut config, &home)?)
    } else {
        None
    };
    let secrets = prepare_secrets(&mut config)?;
    Ok(FinalizedLaunch {
        config,
        secrets,
        github_warning: github.warning,
        restricted_ssh,
        reviewed_forge: ReviewedForge::Unreviewed,
    })
}

fn build_onboarding_effective(
    global: config::Config,
    proposed: config::Config,
    cli: &cli::CliArgs,
    constraints: config::Config,
    project: &std::path::Path,
    trusted_constraints: bool,
) -> Result<config::Config, String> {
    let trusted = config::merge_trusted_project(global, proposed);
    let baseline = config::merge(cli, trusted);
    let mut effective = if trusted_constraints {
        config::merge_trusted_project(baseline, constraints)
    } else {
        config::merge_with_global_report(baseline, constraints, project).0
    };
    if !cli.command.is_empty() {
        effective.command = cli.command.clone();
    }
    config::absolutize_user_paths(&mut effective, project);
    apply_browser_profile(&mut effective, true);
    Ok(effective)
}

fn build_noninteractive_onboarding_effective(
    global: &config::Config,
    harness: &str,
    cli: &cli::CliArgs,
    constraints: config::Config,
    project: &std::path::Path,
) -> Result<config::Config, String> {
    // Project the global layer through the same monotonic merge used for an
    // untrusted project, then remove the few path/list fields whose presence
    // itself grants authority. This retains lockdown, masks, deny paths, and
    // every explicit disable while dropping host access.
    let mut restrictions =
        config::monotonic_project_constraints(global, project);
    restrictions.command.clear();
    restrictions.ro_maps.clear();
    restrictions.rw_maps.clear();
    restrictions.overlay_maps.clear();
    restrictions.mask_exceptions.clear();
    restrictions.deny_path_exceptions.clear();
    restrictions.allow_hosts.clear();
    restrictions.allow_private_hosts.clear();
    restrictions.allow_tcp_ports.clear();
    restrictions.forward_ports.clear();
    restrictions.publish_ports.clear();
    restrictions.claude_dir = None;
    restrictions.env_pass.clear();
    restrictions.env_from_file.clear();
    restrictions.secret_hosts.clear();
    restrictions.trust_project_config.clear();
    restrictions.browser_profile = None;
    let automatic_api =
        restrictions.network != Some(false) && !restrictions.lockdown_enabled();
    let mut safe_grants = onboarding::Selection {
        api_access: automatic_api,
        ..onboarding::Selection::default()
    }
    .grants(harness);
    safe_grants.no_mise = Some(true);
    build_onboarding_effective(
        restrictions,
        safe_grants,
        cli,
        constraints,
        project,
        false,
    )
}

fn materialize_approved_env_names(
    names: &[String],
    allow_missing: bool,
) -> Result<Vec<String>, String> {
    let mut materialized = Vec::new();
    for name in names {
        onboarding::validate_env_name(name)?;
        if std::env::var_os(name).is_some() {
            materialized.push(name.clone());
        } else if !allow_missing {
            return Err(format!(
                "{} Approved host environment variable {} is missing. Run `ai-jail configure HARNESS` to remove it or restore it before launch",
                onboarding::messages::ENV_MISSING_ID,
                output::escape_control_bytes(name)
            ));
        }
    }
    Ok(materialized)
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
        spawn_bridge(
            "--proxy-bridge",
            port,
            std::path::Path::new(proxy::IN_SANDBOX_SOCK_PATH),
            None,
        )?;
    }
    // Port forwards: the same bridge, one per port, pumping into the
    // host-side forward socket bwrap mounted at the per-port path.
    #[cfg(target_os = "linux")]
    for &port in config.forward_ports() {
        spawn_bridge(
            "--proxy-bridge",
            port,
            &proxy::forward_in_sandbox_path(port),
            Some("--forward-port"),
        )?;
    }
    // Published ports: the reverse bridge, one per port, connected to the
    // supervisor's socket before the agent runs so it is the only peer
    // the supervisor ever accepts there.
    #[cfg(target_os = "linux")]
    for &port in config.publish_ports() {
        spawn_bridge(
            "--publish-bridge",
            port,
            &proxy::publish_in_sandbox_path(port),
            Some("--publish-port"),
        )?;
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

/// Spawn an in-sandbox bridge as a child of the landlock wrapper, in the
/// internal `mode` (`--proxy-bridge`: 127.0.0.1:<port> -> Unix `socket`,
/// for filtered egress and each `--forward-port`; `--publish-bridge`:
/// Unix `socket` -> 127.0.0.1:<port>, for each `--publish-port`). Fatal
/// on spawn failure: without the bridge, the port the launch asked for
/// silently leads nowhere. The child is never reaped or waited on -- it
/// lives exactly as long as the sandbox's pid namespace (see the call
/// site).
///
/// With `wait_ready_for` (the launch flag, for the error), also fatal
/// when the bridge cannot come up, and the agent is not exec'd until it
/// has: the bridge reports `ready` on a piped stdout once bound (or
/// connected), and exits (EOF) if it cannot. Without it (the proxy
/// bridge) behaviour is unchanged: the bridge inherits the agent's
/// stdout, which it must never write to.
#[cfg(target_os = "linux")]
fn spawn_bridge(
    mode: &str,
    port: u16,
    socket: &std::path::Path,
    wait_ready_for: Option<&str>,
) -> Result<(), String> {
    use std::io::BufRead;
    let exe = std::env::current_exe().map_err(|e| {
        format!("Cannot resolve ai-jail binary for the bridge on {port}: {e}")
    })?;
    let mut command = std::process::Command::new(exe);
    command
        .arg(mode)
        .arg(port.to_string())
        .arg(socket)
        // The internal-mode marker both bridge modes refuse to run
        // without; an agent that can already reach the bridge socket
        // gains nothing by setting it itself.
        .env("AI_JAIL_PROXY_BRIDGE", "1");
    if wait_ready_for.is_some() {
        command
            .env(proxy::BRIDGE_READY_ENV, "1")
            .stdout(std::process::Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to spawn the bridge on {port}: {e}"))?;
    if let Some(flag) = wait_ready_for {
        let mut line = String::new();
        let ready = child
            .stdout
            .take()
            .map(|out| std::io::BufReader::new(out).read_line(&mut line))
            .is_some_and(|r| r.is_ok());
        if !ready || line.trim() != "ready" {
            return Err(format!(
                "{flag} {port}: the in-sandbox bridge did not come up"
            ));
        }
    }
    Ok(())
}

/// Drop `PATH` entries that are not directories here, returning the rewritten
/// value with the kept and original counts. `None` when nothing changed.
fn prune_missing_path_entries(
    path: &std::ffi::OsStr,
) -> Option<(std::ffi::OsString, usize, usize)> {
    let total = std::env::split_paths(path).count();
    let kept: Vec<std::path::PathBuf> = std::env::split_paths(path)
        // An empty PATH component means the current directory, not a
        // missing directory. Preserve that spelling and its search order.
        .filter(|entry| entry.as_os_str().is_empty() || entry.is_dir())
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
    if cli.configure.is_some()
        && (cli.save_config == Some(false) || cli.dry_run || cli.init)
    {
        return Err(
            "configure conflicts with --no-save-config, --dry-run, and --init"
                .into(),
        );
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

#[derive(Clone, Copy)]
struct PolicyProvenance {
    source: &'static str,
    grants: bool,
    constraints: bool,
    trusted: bool,
}

fn policy_provenance(
    external_present: bool,
    external_grants: bool,
    external_constraints: bool,
    legacy_present: bool,
    legacy_trusted: bool,
) -> PolicyProvenance {
    if external_present {
        PolicyProvenance {
            source: "external_store",
            grants: external_grants,
            constraints: external_constraints,
            trusted: external_grants,
        }
    } else if legacy_present {
        PolicyProvenance {
            source: if legacy_trusted {
                "legacy_trusted"
            } else {
                "legacy_untrusted"
            },
            grants: legacy_trusted,
            constraints: !legacy_trusted,
            trusted: legacy_trusted,
        }
    } else {
        PolicyProvenance {
            source: "none",
            grants: false,
            constraints: false,
            trusted: false,
        }
    }
}

fn run(
    migration_notices: &mut Vec<config_store::MigrationNotice>,
) -> Result<i32, String> {
    let cli = cli::parse()?;
    if cli.capabilities {
        if !cli.json {
            return Err("capabilities currently requires --json".into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&integration::Capabilities::current())
                .map_err(|e| format!("Cannot serialize capabilities: {e}"))?
        );
        return Ok(0);
    }
    if let Some(fd) = cli.supervised_exec_fd {
        return signals::run_supervised_exec(fd, &cli.command);
    }
    validate_write_flags(&cli)?;

    // Suppress info/warn output in --exec mode for clean stdout
    if cli.exec {
        output::set_quiet(true);
    }

    let internal_quiet = internal_mode_inherits_quiet(
        cli.landlock_exec,
        cli.proxy_bridge.is_some() || cli.publish_bridge.is_some(),
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
    // Internal: the in-sandbox end of a --publish-port, under the same
    // marker.
    if cli.publish_bridge.is_some()
        && std::env::var_os("AI_JAIL_PROXY_BRIDGE").is_none()
    {
        return Err(
            "--publish-bridge is an internal mode, not a launch option".into(),
        );
    }
    if let Some((port, socket)) = &cli.publish_bridge {
        #[cfg(target_os = "linux")]
        return proxy::run_publish_bridge(*port, socket).map(|()| 0);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (port, socket);
            return Err("--publish-bridge is supported on Linux only".into());
        }
    }

    // Offline audit commands bypass configuration and sandbox setup.
    if cli.audit_show {
        return run_audit_show();
    }
    if cli.audit_verify {
        return run_audit_verify(&cli);
    }

    let invocation_cwd = std::env::current_dir()
        .map_err(|e| format!("Cannot determine current directory: {e}"))?;
    let wrapper_requests = integration::RequestSet::load(
        &cli.request_files,
        &cli.requests,
        &invocation_cwd,
    )?;
    if cli.configure.is_some() && !onboarding::is_interactive() {
        let harness = cli.configure.as_deref().unwrap_or("HARNESS");
        output::error(&format!(
            "`ai-jail configure {harness}` needs an interactive terminal. No configuration was changed."
        ));
        return Ok(2);
    }
    let store = config_store::StorePaths::discover(&invocation_cwd)?;
    if let Some(command) = &cli.forge {
        return forge_auth::run_command(command, &store);
    }
    // --no-save-config suppresses profile/constraint auto-save, not the
    // security migration from repository-local policy into the trusted store.
    let migration_writes_allowed = !cli.dry_run && !cli.status;
    if migration_writes_allowed && store.available {
        config_store::migrate(&store, !cli.clean, migration_notices)?;
    }

    // New external policy has explicit provenance. Compatibility reads retain
    // legacy behavior in read-only modes until a writable launch migrates it.
    let mut stored_project = if cli.clean {
        config_store::LoadedProject::default()
    } else if cli.status && cli.json {
        config_store::load_project_for_status(&store)?
    } else {
        config_store::load_project(&store)?
    };
    let mut status_blockers: Vec<(String, String)> = stored_project
        .validation_blockers
        .iter()
        .cloned()
        .map(|message| ("directory_drift".into(), message))
        .collect();
    match materialize_approved_env_names(
        &stored_project.approved_env_names,
        cli.configure.is_some(),
    ) {
        Ok(env) => stored_project.grants.env_pass.extend(env),
        Err(error) if cli.status && cli.json => {
            status_blockers.push(("missing_approved_env".into(), error));
        }
        Err(error) => return Err(error),
    }
    let legacy_project = if cli.clean || stored_project.present {
        config::Config::default()
    } else {
        config::load()?
    };
    let using_external_project = stored_project.present;
    let external_has_grants = stored_project.grants
        != config::Config::default()
        || stored_project.restricted_ssh.is_some();
    let external_has_constraints =
        stored_project.constraints != config::Config::default();
    let stored_grants_for_onboarding = stored_project.grants.clone();
    let stored_env_names_for_onboarding =
        stored_project.approved_env_names.clone();
    let stored_wrapper_approvals =
        stored_project.approved_wrapper_requests.clone();
    let stored_ssh_for_onboarding = stored_project.restricted_ssh.clone();
    let stored_ssh_for_launch = stored_project.restricted_ssh.clone();
    let global_command_selector = if using_external_project {
        &stored_project.grants
    } else {
        &legacy_project
    };
    let global_selection = if store.global.exists() {
        config::global_config_for_command_report(
            config_store::load_global(&store)?,
            &cli,
            global_command_selector,
        )
    } else {
        // Read-only compatibility path. Writable modes migrated this above.
        config::load_global_for_command_report(&cli, global_command_selector)?
    };
    for table in &global_selection.ignored_command_tables {
        output::security_warn(&format!(
            "[commands.{}] command ignored because a positional command was supplied; its other settings still apply",
            table
        ));
    }
    let global = global_selection.config;
    let onboarding_complete = stored_project.onboarding_complete;
    let global_for_onboarding = global.clone();
    let trusted = config::merge_trusted_project(global, stored_project.grants);
    let project_config = if using_external_project {
        stored_project.constraints
    } else {
        legacy_project
    };
    let legacy_project_trusted = !using_external_project
        && config::project_config_is_trusted(
            &trusted.trust_project_config,
            &invocation_cwd,
        );
    let provenance = policy_provenance(
        using_external_project,
        external_has_grants,
        external_has_constraints,
        !cli.clean
            && !using_external_project
            && invocation_cwd.join(".ai-jail").is_file(),
        legacy_project_trusted,
    );
    let project_trusted = provenance.trusted;
    let baseline = config::merge(&cli, trusted);
    let (mut config, security_warnings) = if legacy_project_trusted {
        (
            config::merge_trusted_project(baseline, project_config.clone()),
            Vec::new(),
        )
    } else {
        config::merge_with_global_report(
            baseline,
            project_config.clone(),
            &invocation_cwd,
        )
    };

    let resolved_harnesses =
        command::resolve_harnesses(&config.command, &cli.harnesses)?;
    config.runtime_harnesses = resolved_harnesses.clone();
    let effective_harness = resolved_harnesses.first().cloned();
    let configure_only = cli.configure.is_some();
    let first_run = effective_harness.is_some()
        && !onboarding_complete
        && !cli.dry_run
        && !cli.init
        && !cli.bootstrap
        && !cli.status
        && !cli.clean;
    let mut prepared_launch: Option<FinalizedLaunch> = None;
    let mut final_access_render: Option<(String, Option<bool>, Vec<String>)> =
        None;
    let mut skip_project_auto_save = first_run && !onboarding::is_interactive();
    if configure_only || first_run {
        let harness = effective_harness
            .as_deref()
            .ok_or_else(|| "configure requires a known harness".to_string())?;
        if !onboarding::is_interactive() {
            if !wrapper_requests.items.is_empty() {
                for request in
                    wrapper_requests.pending(&stored_wrapper_approvals)
                {
                    output::error(&format!(
                        "Wrapper request from {} is not approved: {} {}",
                        output::escape_control_bytes(
                            &request.approval.requester
                        ),
                        output::escape_control_bytes(&request.approval.kind),
                        output::escape_control_bytes(&request.approval.value)
                    ));
                }
                return Ok(integration::EXIT_REQUIRED_GRANT);
            }
            config = build_noninteractive_onboarding_effective(
                &global_for_onboarding,
                harness,
                &cli,
                project_config.clone(),
                &invocation_cwd,
            )?;
            onboarding::secure_noninteractive(&mut config, &cli);
            let selection = onboarding::Selection::from_config(&config);
            onboarding::render_summary(
                &selection,
                harness,
                &invocation_cwd,
                false,
            );
            final_access_render =
                Some((harness.to_string(), Some(false), Vec::new()));
        } else {
            let editor_config = if onboarding_complete {
                stored_grants_for_onboarding.clone()
            } else {
                config::Config::default()
            };
            let outcome = onboarding::run(
                harness,
                &invocation_cwd,
                &editor_config,
                configure_only,
                !onboarding_complete,
                onboarding::EffectiveContext {
                    global: &global_for_onboarding,
                    cli: &cli,
                    constraints: &project_config,
                    trusted_constraints: legacy_project_trusted,
                    approved_env_names: &stored_env_names_for_onboarding,
                    restricted_ssh: stored_ssh_for_onboarding.as_ref(),
                    requests: &wrapper_requests,
                    approved_wrapper_requests: &stored_wrapper_approvals,
                    store: &store,
                },
            )?;
            let (mut profile, save, launch) = match outcome {
                onboarding::Outcome::SaveAndLaunch(profile) => {
                    (profile, true, true)
                }
                onboarding::Outcome::LaunchOnce(profile) => {
                    skip_project_auto_save = true;
                    (profile, false, true)
                }
                onboarding::Outcome::SaveOnly(profile) => {
                    (profile, true, false)
                }
                onboarding::Outcome::Cancel => {
                    eprintln!("{}", onboarding::messages::CANCEL);
                    return Ok(130);
                }
            };
            if save {
                config_store::save_project_grants(
                    &store,
                    profile.grants.clone(),
                    profile.approved_env_names.clone(),
                    profile.approved_wrapper_requests.clone(),
                    &profile.directory_grants,
                    profile.restricted_ssh.clone(),
                )?;
                eprintln!(
                    "[OK] Configuration saved\n  Project policy: {}\n  The project cannot edit or enable this policy from inside the jail.",
                    onboarding::safe_path(&store.project)?
                );
            }
            if launch
                && !wrapper_requests
                    .pending(&profile.approved_wrapper_requests)
                    .is_empty()
            {
                output::error(
                    "One or more wrapper requests were refused; the harness was not started",
                );
                return Ok(integration::EXIT_REQUIRED_GRANT);
            }
            if !launch {
                return Ok(0);
            }
            config_store::validate_directory_grants(
                &mut profile.grants,
                &profile.directory_grants,
                &invocation_cwd,
            )?;
            materialize_approved_env_names(&profile.approved_env_names, false)?;
            let finalized = profile.finalized.take().ok_or_else(|| {
                "Onboarding launch was not finalized before confirmation"
                    .to_string()
            })?;
            config = finalized.config.clone();
            prepared_launch = Some(finalized);
            final_access_render = Some((
                harness.to_string(),
                Some(save),
                profile.approved_env_names,
            ));
        }
    } else if onboarding_complete
        && let Some(harness) = effective_harness.as_deref()
        && !cli.dry_run
        && !cli.init
        && !cli.bootstrap
    {
        let pending = wrapper_requests.pending(&stored_wrapper_approvals);
        if !pending.is_empty() && !cli.status {
            for request in pending {
                output::error(&format!(
                    "Wrapper request from {} is not approved: {} {}. Review it with `ai-jail configure --harness {}`.",
                    output::escape_control_bytes(&request.approval.requester),
                    output::escape_control_bytes(&request.approval.kind),
                    output::escape_control_bytes(&request.approval.value),
                    effective_harness.as_deref().unwrap_or("HARNESS")
                ));
            }
            return Ok(integration::EXIT_REQUIRED_GRANT);
        }
        config = build_onboarding_effective(
            global_for_onboarding,
            stored_grants_for_onboarding,
            &cli,
            project_config.clone(),
            &invocation_cwd,
            legacy_project_trusted,
        )?;
        config.runtime_harnesses = resolved_harnesses.clone();
        wrapper_requests
            .apply_approved_runtime(&stored_wrapper_approvals, &mut config);
        let mut saved_selection = onboarding::Selection::from_config(&config);
        if cli.ssh != Some(false) && !config.lockdown_enabled() {
            saved_selection.restricted_ssh = stored_ssh_for_onboarding.clone();
        }
        onboarding::render_summary(
            &saved_selection,
            harness,
            &invocation_cwd,
            true,
        );
        final_access_render = Some((
            harness.to_string(),
            Some(true),
            stored_env_names_for_onboarding.clone(),
        ));
    }
    // A project `.ai-jail` is untrusted monotonic policy unless the trusted
    // global config lists this directory under `trust_project_config`, in
    // which case it is merged with the same semantics as a global
    // `[commands.<name>]` table and may enable capabilities.
    // Whether the effective command is trusted for the browser-profile
    // lockdown decision below. It is adopted from the project file only when
    // the CLI gave none and the project supplied one; that command is trusted
    // only if the project directory is itself trusted (#3, browser lockdown
    // downgrade).
    let command_from_untrusted_project = cli.command.is_empty()
        && !project_config.command.is_empty()
        && !legacy_project_trusted;
    // The trusted project merge may have replaced the baseline command.
    // Command precedence remains CLI > project > global in both trust modes.
    if !cli.command.is_empty() {
        config.command = cli.command.clone();
    } else if !project_config.command.is_empty() {
        config.command = project_config.command.clone();
    }
    // GHSA-v2fr-83mr-f9cg question A: an untrusted project .ai-jail may
    // choose what runs, but when it names a known harness the harness
    // defaults key on that name — its state directory mounts read-write,
    // its API key is forwarded, its API hosts are default-allowed. That
    // is the documented agent-state trade-off; it must not be silent.
    if let Some(name) = untrusted_project_command_carries_credentials(
        command_from_untrusted_project,
        &config,
    ) {
        output::security_warn(&format!(
            "project .ai-jail selected the command {name:?}: its credentials \
             travel with it (state dir mounted read-write, API key forwarded, \
             API host allowed). Remove `command` from the project config or \
             list the directory in the global trust_project_config."
        ));
    }
    for warning in security_warnings {
        output::security_warn(&warning);
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
        if cli.json {
            if !onboarding_complete && !resolved_harnesses.is_empty() {
                status_blockers.push((
                    "onboarding_required".into(),
                    "Interactive onboarding is required before launch".into(),
                ));
            }
            if !wrapper_requests
                .pending(&stored_wrapper_approvals)
                .is_empty()
            {
                status_blockers.push((
                    "required_grant_not_approved".into(),
                    "One or more wrapper requests are pending approval".into(),
                ));
            }
            if let Some(policy) = stored_ssh_for_onboarding.as_ref()
                && let Err(error) = ssh_restricted::validate_policy(policy)
            {
                status_blockers.push(("changed_ssh_key".into(), error));
            }
            if let Err(error) = sandbox::check() {
                status_blockers.push(("backend_unavailable".into(), error));
            }
            let report =
                integration::StatusReport::build(integration::StatusInput {
                    project: &invocation_cwd,
                    profile_present: stored_project.present,
                    onboarding_complete,
                    harnesses: &resolved_harnesses,
                    config: &config,
                    requests: &wrapper_requests,
                    approved: &stored_wrapper_approvals,
                    blockers: status_blockers,
                });
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|e| format!("Cannot serialize status: {e}"))?
            );
            return Ok(0);
        }
        output::status_header("Project policy source", provenance.source);
        output::status_header(
            "Project grants",
            if provenance.grants { "yes" } else { "no" },
        );
        output::status_header(
            "Project constraints",
            if provenance.constraints { "yes" } else { "no" },
        );
        let legacy_status_path = invocation_cwd.join(".ai-jail");
        let contributing_path = match provenance.source {
            "external_store" => Some(store.project.as_path()),
            "legacy_trusted" | "legacy_untrusted" => {
                Some(legacy_status_path.as_path())
            }
            _ => None,
        };
        config::display_status(&config, contributing_path);
        return Ok(0);
    }

    // Persist user-level preferences in the external XDG config store.
    if should_save_global_preferences(&cli) && store.available {
        let mut global = config_store::load_global(&store)?;
        if config.no_status_bar.is_some() {
            global.base.no_status_bar = config.no_status_bar;
        }
        if config.status_bar_style.is_some() {
            global.base.status_bar_style = config.status_bar_style.clone();
        }
        config_store::save_global_document(&store, &global)?;
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
        config_store::save_project_constraints(
            &store,
            config::project_config_for_init(
                &cli,
                project_config.clone(),
                &invocation_cwd,
            ),
        )?;
        output::info(&format!("Config saved to {}", store.project.display()));
        return Ok(0);
    }

    // Handle --bootstrap: generate AI tool configs and exit
    if cli.bootstrap {
        bootstrap::run(cli.verbose, config.claude_dir.as_deref())?;
        return Ok(0);
    }

    let finalized = match prepared_launch.take() {
        Some(finalized) => finalized,
        None => finalize_launch_config_with_ssh(
            config,
            &invocation_cwd,
            cli.dry_run,
            if cli.ssh == Some(false) {
                None
            } else {
                stored_ssh_for_launch
            },
        )?,
    };
    let mut launch_runner = LaunchRunner::new(finalized);
    if let Some(warning) = launch_runner.github_warning() {
        output::warn(warning);
    }
    for warning in command::capability_gap_warnings(launch_runner.config()) {
        output::warn(&warning);
    }
    if let Some(hint) =
        browser_display_hint(launch_runner.config(), host_has_display())
    {
        output::warn(hint);
    }
    if !cli.dry_run {
        signals::install_handlers();
        launch_runner.start_restricted_ssh()?;
        signals::abort_if_cancelled()?;
    }
    let config = launch_runner.config();
    // Check sandbox tool is available
    sandbox::check()?;

    // Platform-specific info messages (e.g. no-op flags on macOS)
    sandbox::platform_notes(config);

    // Opt-in launch audit log (phase 5 of docs/connect-proxy-plan.md):
    // a supervisor-side JSONL file the sandbox never sees. Opened here
    // so the filtered-egress proxy below can share the handle; the
    // launch record itself is appended when the child exits.
    let audit_home = audit_home();
    let audit_log = if !cli.dry_run && config.audit_log_enabled() {
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
        let mut allowlist = config.allow_hosts().to_vec();
        allowlist.extend(config.allow_private_hosts().iter().cloned());
        let mut proxy_config = proxy::ProxyConfig::new(allowlist);
        proxy_config.allow_private_hosts =
            config.allow_private_hosts().to_vec();
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
        proxy_config.prompt = host_prompt(config);
        let proxy_config = launch_runner.finish_proxy_config(proxy_config);
        let socket = proxy::default_socket_path();
        let proxy = proxy::Proxy::start(proxy_config, Some(&socket))
            .map_err(|e| format!("Failed to start the egress proxy: {e}"))?;
        Some(proxy)
    } else {
        if config.prompt_hosts_enabled() {
            output::warn(
                "--prompt-hosts has no effect: network egress is not filtered",
            );
        }
        None
    };
    #[cfg(target_os = "macos")]
    let egress_proxy = if config.network_mode() == config::NetworkMode::Filtered
    {
        let mut allowlist = config.allow_hosts().to_vec();
        allowlist.extend(config.allow_private_hosts().iter().cloned());
        let mut proxy_config = proxy::ProxyConfig::new(allowlist);
        proxy_config.allow_private_hosts =
            config.allow_private_hosts().to_vec();
        proxy_config.audit = audit_log.clone();
        let proxy_config = launch_runner.finish_proxy_config(proxy_config);
        let proxy = proxy::Proxy::start(proxy_config, None)
            .map_err(|e| format!("Failed to start the egress proxy: {e}"))?;
        Some(proxy)
    } else {
        None
    };

    // Port forwards (Linux): one host-side Unix listener per port, bound
    // before the sandbox is built so bwrap can mount each socket. Like the
    // proxy handle, they must outlive the child (dropping unlinks them).
    #[cfg(target_os = "linux")]
    let port_forwards = config
        .forward_ports()
        .iter()
        .map(|&port| {
            proxy::PortForward::start(port, cli.verbose).map_err(|e| {
                format!("Failed to start the forward for port {port}: {e}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Published ports (Linux): the host listens on 127.0.0.1:<port> from
    // here on (a taken port is fatal) and connections wait in the backlog
    // until the in-sandbox bridge connects to the mounted Unix socket.
    #[cfg(target_os = "linux")]
    let port_publishes = config
        .publish_ports()
        .iter()
        .map(|&port| {
            proxy::PortPublish::start(port, cli.verbose).map_err(|e| {
                format!("Failed to publish port {port} on 127.0.0.1: {e}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(target_os = "linux")]
    let bridge_sockets = sandbox::BridgeSockets {
        forward: port_forwards
            .iter()
            .map(|f| (f.port(), f.unix_path().to_path_buf()))
            .collect(),
        publish: port_publishes
            .iter()
            .map(|p| (p.port(), p.unix_path().to_path_buf()))
            .collect(),
    };
    #[cfg(not(target_os = "linux"))]
    let bridge_sockets = sandbox::BridgeSockets::default();

    let project_dir = std::env::current_dir()
        .map_err(|e| format!("Cannot determine current directory: {e}"))?;

    // Save config in normal mode. In lockdown mode avoid host writes unless user
    // explicitly requested persistence via --init.
    //
    if store.available
        && !skip_project_auto_save
        && should_auto_save_project_config(&cli, config)
    {
        let mut to_save = config::project_config_for_auto_save(
            &cli,
            project_config,
            &invocation_cwd,
        );
        forge_auth::strip_runtime(&mut to_save);
        config_store::save_project_constraints(&store, to_save)?;
    }

    // Handle dry run
    if cli.dry_run {
        let formatted = sandbox::dry_run(
            &guard,
            config,
            &project_dir,
            cli.verbose,
            egress_proxy.as_ref(),
            &bridge_sockets,
        )?;
        output::dry_run_line(&formatted);
        return Ok(0);
    }

    // Forge credentials are the final host-derived launch authority. Load and
    // verify them only after every read-only/nonlaunch exit and after the dry
    // run has completed, then keep the revocation guard alive with the runner.
    if !cli.clean {
        launch_runner.attach_forge(&store)?;
    }
    let config = launch_runner.config();
    if let Some((harness, saved, approved_env_names)) =
        final_access_render.take()
    {
        eprintln!(
            "{}",
            onboarding::render_effective_access(
                config,
                &invocation_cwd,
                &harness,
                saved,
                &approved_env_names,
            )?
        );
    }
    if let Some(runtime) = &launch_runner.forge {
        eprintln!("{}", runtime.summary_line());
    }

    // A real host inode gives bwrap a race-resistant mountpoint for the
    // mandatory absent-file mask. Identity-checked RAII removes only the
    // placeholder we created, never a replacement made concurrently. A hard
    // crash may leave an empty 0600 file; it grants no authority and the next
    // migration/launch treats it as recoverable masking debris.
    let _legacy_mask_placeholder =
        config_store::LegacyMaskPlaceholder::prepare(&store)?;

    // macOS has no private /tmp mount. Hard browser profiles therefore live
    // inside the launch's dedicated session scratch directory and must be
    // removed when this supervisor exits. Linux hard profiles live in the
    // sandbox's tmpfs, so this guard is a no-op there.
    let _browser_profile_guard = sandbox::browser_profile_guard(config);

    output::info(&format!("Jail Active: {}", project_dir.display()));

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
            config,
        );
    }
    // The update check only runs with the status bar active AND an
    // explicit opt-in (phones home to GitHub; default off).
    if should_check_update(config, use_status_bar) {
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
    let mut cmd = launch_runner.build_sandbox(|final_config| {
        sandbox::build(
            &guard,
            final_config,
            &project_dir,
            cli.verbose,
            sandbox_tty.as_deref(),
            egress_proxy.as_ref(),
            &bridge_sockets,
        )
    })?;

    // Apply NOFILE and CORE limits on the parent (inherited by child
    // across fork+exec). NPROC is applied inside the sandbox instead
    // — see run_landlock_exec() — to avoid EAGAIN during bwrap's
    // internal clone() calls for namespace creation.
    sandbox::rlimits::apply(config, cli.verbose);

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
            config,
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
        let gate = signals::wrap_supervised_command(&mut cmd)?;
        let child = signals::spawn_supervised(&mut cmd, gate)?;

        let pid = child.id() as i32;

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
        let mut audit_allow_hosts = config.allow_hosts().to_vec();
        audit_allow_hosts.extend(config.allow_private_hosts().iter().cloned());
        log.record(audit::launch_record(&audit::LaunchRecord {
            command: &config.command,
            network_mode: network,
            allow_hosts: &audit_allow_hosts,
            lockdown: config.lockdown_enabled(),
            agent_state: config.agent_state_enabled(),
            gpu: config.gpu_enabled(),
            display: config.display_enabled(),
            audio: config.audio_enabled(),
            kvm: config.kvm_enabled(),
            browser_profile: config.browser_profile.as_deref(),
            project_config: !cli.clean
                && (store.project.is_file()
                    || invocation_cwd.join(".ai-jail").is_file()),
            project_trusted,
            project_source: provenance.source,
            project_grants: provenance.grants,
            project_constraints: provenance.constraints,
            global_config: store.global.exists()
                || audit_home
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
    #[cfg(target_os = "macos")]
    if codex_ps::is_compat_invocation() {
        std::process::exit(codex_ps::run());
    }

    let mut migration_notices = Vec::new();
    let result = run(&mut migration_notices);
    for notice in &migration_notices {
        output::migration_notice(notice.id, &notice.text, notice.warning);
    }
    match result {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            output::error(&msg);
            std::process::exit(error_exit_code(&msg));
        }
    }
}

fn error_exit_code(message: &str) -> i32 {
    if [
        onboarding::messages::ENV_MISSING_ID,
        onboarding::messages::PATH_DRIFT_ID,
        onboarding::messages::PATH_IDENTITY_ID,
        onboarding::messages::SSH_DRIFT_ID,
    ]
    .iter()
    .any(|code| message.contains(code))
    {
        integration::EXIT_BLOCKED
    } else if message.contains("bwrap (bubblewrap) not found")
        || message.contains("Failed to execute bwrap")
        || message.contains("bwrap found at")
        || message.contains("sandbox-exec not found")
    {
        integration::EXIT_BACKEND_UNAVAILABLE
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LaunchRunner, apply_browser_profile, browser_display_hint,
        build_noninteractive_onboarding_effective, build_onboarding_effective,
        command_is_browser, command_needs_direct_tty,
        default_agent_api_egress_applies, default_registry_egress_applies,
        default_resize_redraw_key, error_exit_code,
        exec_requires_terminal_passthrough, finalize_launch_config,
        internal_mode_inherits_quiet, materialize_approved_env_names,
        policy_provenance, prune_missing_path_entries, pty_proxy_active,
        resolve_browser_profile, running_inside_multiplexer,
        should_auto_save_project_config, should_check_update,
        should_save_global_preferences,
        untrusted_project_command_carries_credentials, validate_network_flags,
        validate_write_flags,
    };
    use crate::cli::CliArgs;
    use crate::config::{BrowserProfile, Config};
    use crate::onboarding::Selection;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};
    use std::path::Path;

    #[test]
    fn policy_provenance_matrix_is_consistent() {
        let cases = [
            (
                (false, false, false, false, false),
                ("none", false, false, false),
            ),
            (
                (true, false, true, false, false),
                ("external_store", false, true, false),
            ),
            (
                (true, true, false, false, false),
                ("external_store", true, false, true),
            ),
            (
                (true, true, true, false, false),
                ("external_store", true, true, true),
            ),
            (
                (false, false, false, true, false),
                ("legacy_untrusted", false, true, false),
            ),
            (
                (false, false, false, true, true),
                ("legacy_trusted", true, false, true),
            ),
        ];
        for ((ep, eg, ec, lp, lt), expected) in cases {
            let actual = policy_provenance(ep, eg, ec, lp, lt);
            assert_eq!(
                (
                    actual.source,
                    actual.grants,
                    actual.constraints,
                    actual.trusted
                ),
                expected
            );
        }
    }

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
    fn default_agent_api_egress_follows_the_api_host_table() {
        // A bare launch of a known API agent with a canonical host applies,
        // on both platforms (macOS filtered egress is a seatbelt loopback).
        for agent in ["claude", "codex", "gemini", "grok", "devin"] {
            assert!(
                default_agent_api_egress_applies(&Config {
                    command: vec![agent.into()],
                    ..Config::default()
                }),
                "{agent} should receive its default API host"
            );
        }
        // An agent with no canonical API host (opencode) gets nothing.
        assert!(!default_agent_api_egress_applies(&Config {
            command: vec!["opencode".into()],
            ..Config::default()
        }));
        // A non-agent command gets nothing.
        assert!(!default_agent_api_egress_applies(&Config {
            command: vec!["bash".into()],
            ..Config::default()
        }));
    }

    #[test]
    fn default_agent_api_egress_only_when_posture_unset() {
        let claude = |f: fn(&mut Config)| {
            let mut c = Config {
                command: vec!["claude".into()],
                ..Config::default()
            };
            f(&mut c);
            c
        };
        // Baseline bare claude applies.
        assert!(default_agent_api_egress_applies(&claude(|_| {})));
        // --no-network keeps the sandbox fully offline.
        assert!(!default_agent_api_egress_applies(&claude(|c| {
            c.network = Some(false);
        })));
        // Verbatim escape hatch: --no-network with an explicit --allow-host
        // list composes to filtered egress but suppresses the automatic API
        // host, so the launch reaches only the named hosts.
        assert!(!default_agent_api_egress_applies(&claude(|c| {
            c.network = Some(false);
            c.allow_hosts = vec!["github.com".into()];
        })));
        // --network is unrestricted; no filtered-egress injection.
        assert!(!default_agent_api_egress_applies(&claude(|c| {
            c.network = Some(true);
        })));
        // An explicit --allow-host list is UNIONED with the agent's own API
        // host (like registry egress), not suppressed by it, so long as no
        // network posture is set. `--no-network --allow-host …` is the verbatim
        // escape hatch, and sets `network` (covered by the --no-network case).
        assert!(default_agent_api_egress_applies(&claude(|c| {
            c.allow_hosts = vec!["example.com".into()];
        })));
        // Lockdown stays offline.
        assert!(!default_agent_api_egress_applies(&claude(|c| {
            c.lockdown = Some(true);
        })));
        // Browser launches need real DNS, not filtered egress.
        assert!(!default_agent_api_egress_applies(&claude(|c| {
            c.browser_profile = Some("hard".into());
        })));
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
    fn forward_port_contradictions_hard_error() {
        let with_network = Config {
            network: Some(true),
            forward_ports: vec![49374],
            ..Config::default()
        };
        let error = validate_network_flags(&with_network).unwrap_err();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(error.contains("mutually exclusive"), "{error}");
        } else {
            assert!(error.contains("Linux and macOS only"), "{error}");
        }
        for port in [0, 80, 443, 1023, crate::proxy::BRIDGE_PORT] {
            let config = Config {
                forward_ports: vec![port],
                ..Config::default()
            };
            assert!(validate_network_flags(&config).is_err(), "port {port}");
        }
        let ok = Config {
            forward_ports: vec![49374],
            allow_hosts: vec!["api.anthropic.com".into()],
            lockdown: Some(true),
            ..Config::default()
        };
        assert_eq!(
            validate_network_flags(&ok).is_ok(),
            cfg!(any(target_os = "linux", target_os = "macos"))
        );
    }

    #[test]
    fn publish_port_contradictions_hard_error() {
        let with_network = Config {
            network: Some(true),
            publish_ports: vec![4096],
            ..Config::default()
        };
        let error = validate_network_flags(&with_network).unwrap_err();
        if cfg!(target_os = "linux") {
            assert!(error.contains("mutually exclusive"), "{error}");
        } else {
            assert!(error.contains("Linux only"), "{error}");
        }
        for port in [0, 80, 443, 1023, crate::proxy::BRIDGE_PORT] {
            let config = Config {
                publish_ports: vec![port],
                ..Config::default()
            };
            assert!(validate_network_flags(&config).is_err(), "port {port}");
        }
        let both_ways = Config {
            forward_ports: vec![4096],
            publish_ports: vec![4096],
            ..Config::default()
        };
        assert!(validate_network_flags(&both_ways).is_err());
        let ok = Config {
            publish_ports: vec![4096],
            forward_ports: vec![49374],
            allow_hosts: vec!["api.anthropic.com".into()],
            allow_private_hosts: vec!["git.internal.example".into()],
            audit_log: Some(true),
            lockdown: Some(true),
            ..Config::default()
        };
        assert_eq!(
            validate_network_flags(&ok).is_ok(),
            cfg!(target_os = "linux")
        );
    }

    #[test]
    fn untrusted_project_command_warns_only_with_credentials() {
        let claude = |agent_state| Config {
            command: vec!["claude".into()],
            agent_state,
            ..Config::default()
        };
        // The warning needs all three: untrusted provenance, a known
        // harness, and agent state left on.
        assert_eq!(
            untrusted_project_command_carries_credentials(true, &claude(None))
                .as_deref(),
            Some("claude")
        );
        // Trusted (CLI or trusted project) choice: the user picked it.
        assert!(
            untrusted_project_command_carries_credentials(false, &claude(None))
                .is_none()
        );
        // Unknown commands carry no harness credentials.
        let bash = Config {
            command: vec!["bash".into()],
            ..Config::default()
        };
        assert!(
            untrusted_project_command_carries_credentials(true, &bash)
                .is_none()
        );
        // --no-agent-state / lockdown: no credential surface to warn about.
        assert!(
            untrusted_project_command_carries_credentials(
                true,
                &claude(Some(false))
            )
            .is_none()
        );
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

        let private = Config {
            network: Some(true),
            allow_private_hosts: vec!["git.internal.example".into()],
            ..Config::default()
        };
        assert!(validate_network_flags(&private).is_err());
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

        let private = Config {
            browser_profile: Some("hard".into()),
            allow_private_hosts: vec!["git.internal.example".into()],
            ..Config::default()
        };
        assert!(validate_network_flags(&private).is_err());
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
        assert!(error.contains("not in allow_hosts or allow_private_hosts"));

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
    fn secrets_keep_literal_when_later_host_variable_is_absent() {
        let _env = ENV_LOCK.lock().unwrap();
        let key = "AI_JAIL_TEST_ABSENT_SECRET";
        let _absent = EnvVarGuard::remove(key);
        let cli = CliArgs {
            allow_hosts: vec!["example.com".into()],
            env: vec![key.into(), format!("{key}=synthetic-value"), key.into()],
            secrets: vec![(key.into(), "example.com".into())],
            ..CliArgs::default()
        };
        let mut config = crate::config::merge(&cli, Config::default());
        assert_eq!(
            crate::config::filtered_child_env(&config.env_pass, &[]),
            vec![(key.into(), "synthetic-value".into())]
        );

        let bindings = super::prepare_secrets(&mut config).unwrap();

        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].real, "synthetic-value");
        assert_eq!(
            config.env_pass,
            vec![format!("{key}={}", bindings[0].placeholder)]
        );
        assert!(!config.env_pass[0].contains("synthetic-value"));
    }

    #[test]
    fn secrets_without_any_value_still_fail() {
        let _env = ENV_LOCK.lock().unwrap();
        let key = "AI_JAIL_TEST_ABSENT_SECRET";
        let _absent = EnvVarGuard::remove(key);
        let cli = CliArgs {
            allow_hosts: vec!["example.com".into()],
            env: vec![key.into()],
            secrets: vec![(key.into(), "example.com".into())],
            ..CliArgs::default()
        };
        let mut config = crate::config::merge(&cli, Config::default());
        let error = super::prepare_secrets(&mut config).unwrap_err();
        assert!(
            error
                .contains("named in --env but not set in the host environment")
        );
        assert_eq!(config.env_pass, vec![key]);
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
    fn path_pruning_keeps_empty_current_directory_entries() {
        let empty = std::path::PathBuf::new();
        let missing = std::env::temp_dir()
            .join(format!("ai-jail-missing-path-entry-{}", std::process::id()));
        let path = std::env::join_paths([&empty, &missing, &empty]).unwrap();
        let (pruned, kept, total) = prune_missing_path_entries(&path).unwrap();
        assert_eq!((kept, total), (2, 3));
        assert_eq!(pruned, std::env::join_paths([&empty, &empty]).unwrap());
        assert!(prune_missing_path_entries(std::ffi::OsStr::new("")).is_none());
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
    fn browser_display_hint_only_when_a_window_cannot_open() {
        let browser = |extra: fn(&mut Config)| {
            let mut config = Config {
                command: vec!["chromium".into()],
                ..Config::default()
            };
            apply_browser_profile(&mut config, true);
            extra(&mut config);
            config
        };
        let linux = cfg!(target_os = "linux");

        // A browser profile with no --display on a host that has one.
        assert_eq!(
            browser_display_hint(&browser(|_| {}), true).is_some(),
            linux
        );
        // Display or X11 passed: the browser can open a window.
        assert!(
            browser_display_hint(
                &browser(|c| c.no_display = Some(false)),
                true
            )
            .is_none()
        );
        assert!(
            browser_display_hint(&browser(|c| c.x11 = Some(true)), true)
                .is_none()
        );
        // No display on the host: nothing to pass.
        assert!(browser_display_hint(&browser(|_| {}), false).is_none());
        // Lockdown kept for an untrusted browser command warns on its own.
        assert!(
            browser_display_hint(&browser(|c| c.lockdown = Some(true)), true)
                .is_none()
        );
        // Not a browser launch.
        assert!(browser_display_hint(&Config::default(), true).is_none());
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
    fn configure_rejects_nonwriting_modes() {
        for cli in [
            CliArgs {
                configure: Some("claude".into()),
                save_config: Some(false),
                ..CliArgs::default()
            },
            CliArgs {
                configure: Some("claude".into()),
                dry_run: true,
                ..CliArgs::default()
            },
            CliArgs {
                configure: Some("claude".into()),
                init: true,
                ..CliArgs::default()
            },
        ] {
            assert!(validate_write_flags(&cli).is_err());
        }
    }

    #[test]
    fn noninteractive_onboarding_does_not_inherit_broad_global_access() {
        let global = Config {
            network: Some(true),
            github: Some(true),
            ssh: Some(true),
            no_docker: Some(false),
            inherit_env: Some(true),
            lockdown: Some(true),
            no_mise: Some(true),
            mask: vec!["/host/restricted".into()],
            deny_paths: vec!["/host/denied".into()],
            ro_maps: vec!["/host/grant".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let effective = build_noninteractive_onboarding_effective(
            &global,
            "claude",
            &cli,
            Config::default(),
            Path::new("/project"),
        )
        .unwrap();

        assert_ne!(effective.network, Some(true));
        assert!(!effective.github_enabled());
        assert!(!effective.ssh_enabled());
        assert!(!effective.docker_enabled());
        assert!(!effective.inherit_env_enabled());
        assert!(effective.lockdown_enabled());
        assert!(!effective.mise_enabled());
        assert_eq!(
            effective.mask,
            vec![std::path::PathBuf::from("/host/restricted")]
        );
        assert_eq!(
            effective.deny_paths,
            vec![std::path::PathBuf::from("/host/denied")]
        );
        assert!(
            !effective
                .ro_maps
                .contains(&std::path::PathBuf::from("/host/grant"))
        );
        assert!(
            !effective
                .allow_hosts
                .iter()
                .any(|h| h == "api.anthropic.com")
        );
    }

    #[test]
    fn noninteractive_offline_global_suppresses_automatic_api_host() {
        for global in [
            Config {
                network: Some(false),
                ..Config::default()
            },
            Config {
                lockdown: Some(true),
                ..Config::default()
            },
        ] {
            let effective = build_noninteractive_onboarding_effective(
                &global,
                "claude",
                &CliArgs {
                    command: vec!["claude".into()],
                    ..CliArgs::default()
                },
                Config::default(),
                Path::new("/project"),
            )
            .unwrap();
            assert!(
                !effective
                    .allow_hosts
                    .iter()
                    .any(|host| host == "api.anthropic.com")
            );
        }
    }

    #[test]
    fn noninteractive_offline_global_keeps_explicit_cli_host_grant() {
        let effective = build_noninteractive_onboarding_effective(
            &Config {
                network: Some(false),
                ..Config::default()
            },
            "claude",
            &CliArgs {
                command: vec!["claude".into()],
                allow_hosts: vec!["explicit.example".into()],
                ..CliArgs::default()
            },
            Config::default(),
            Path::new("/project"),
        )
        .unwrap();
        assert_eq!(effective.network, Some(false));
        assert_eq!(effective.allow_hosts, vec!["explicit.example"]);
    }

    #[test]
    fn actual_sandbox_and_proxy_handoffs_receive_finalized_launch_unchanged() {
        let global = Config {
            github: Some(true),
            no_mise: Some(true),
            no_toolchains: Some(true),
            allow_hosts: vec!["github.com".into()],
            env_pass: vec![
                "GH_CONFIG_DIR=/definitely/missing/gh".into(),
                "TEST_TOKEN=super-secret-value".into(),
            ],
            secret_hosts: [("TEST_TOKEN".into(), "github.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        let proposed = Selection {
            api_access: true,
            agent_state: true,
            ..Selection::default()
        }
        .grants("claude");
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let base = build_onboarding_effective(
            global,
            proposed,
            &cli,
            Config::default(),
            Path::new("/project"),
            false,
        )
        .unwrap();
        let finalized =
            finalize_launch_config(base, Path::new("/project"), true).unwrap();
        let expected_config = finalized.config.clone();
        let expected_bindings = finalized
            .secrets
            .iter()
            .map(|binding| {
                (
                    binding.key.clone(),
                    binding.placeholder.clone(),
                    binding.real.clone(),
                    binding.host.clone(),
                )
            })
            .collect::<Vec<_>>();
        let launch_runner = LaunchRunner::new(finalized);
        let config_received_by_sandbox =
            launch_runner.build_sandbox(|config_at_build_boundary| {
                config_at_build_boundary.clone()
            });
        let proxy_config = launch_runner.finish_proxy_config(
            crate::proxy::ProxyConfig::new(vec!["github.com".into()]),
        );
        let bindings_received_by_proxy = proxy_config
            .secrets
            .iter()
            .map(|binding| {
                (
                    binding.key.clone(),
                    binding.placeholder.clone(),
                    binding.real.clone(),
                    binding.host.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(config_received_by_sandbox, expected_config);
        assert_eq!(bindings_received_by_proxy, expected_bindings);
        assert!(
            launch_runner.config().env_pass.iter().any(|entry| {
                entry.starts_with("TEST_TOKEN=AIJAIL-PHANTOM-")
            })
        );
        assert!(
            !launch_runner
                .config()
                .env_pass
                .iter()
                .any(|entry| entry.contains("super-secret-value"))
        );
        assert_eq!(bindings_received_by_proxy.len(), 1);
        let rendered = crate::onboarding::render_effective_access(
            launch_runner.config(),
            Path::new("/project"),
            "claude",
            None,
            &[],
        )
        .unwrap();
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("TEST_TOKEN"));
    }

    #[test]
    fn missing_approved_environment_name_fails_closed_except_in_editor() {
        let name = "AI_JAIL_DEFINITELY_MISSING_APPROVED_ENV_7F4B".to_string();
        assert!(std::env::var_os(&name).is_none());
        let error =
            materialize_approved_env_names(std::slice::from_ref(&name), false)
                .unwrap_err();
        assert!(error.contains(crate::onboarding::messages::ENV_MISSING_ID));
        assert!(
            materialize_approved_env_names(&[name], true)
                .unwrap()
                .is_empty()
        );
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

    #[test]
    fn machine_exit_codes_classify_backend_and_saved_grant_failures() {
        assert_eq!(
            error_exit_code(
                "bwrap (bubblewrap) not found in trusted locations"
            ),
            crate::integration::EXIT_BACKEND_UNAVAILABLE
        );
        assert_eq!(
            error_exit_code(
                "AJ-ENV-002 approved environment variable is missing"
            ),
            crate::integration::EXIT_BLOCKED
        );
        assert_eq!(error_exit_code("ordinary configuration error"), 1);
    }
}
