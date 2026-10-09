//! Command inspection helpers.
//!
//! ai-jail normally treats the first argv element as the active tool. Some
//! launchers, however, select an AI harness later in their argv. Keep that
//! distinction explicit: the invoked command is still executed unchanged,
//! while policy and terminal behavior may use the effective harness.

use std::path::Path;

const AI_MEMORY_GLOBAL_VALUE_OPTIONS: &[&str] = &["--data-dir", "--config"];

const AI_MEMORY_RUN_VALUE_OPTIONS: &[&str] = &[
    "--workspace",
    "--project",
    "--workstream",
    "--new",
    "--executable",
    // Wrapper value options that may precede the harness (#151). Missing
    // ones made effective_name() fall back to "ai-memory", so the harness
    // started without its agent-state mounts.
    "--env",
    "--env-file",
    "--profile",
];

/// ai-memory `run` boolean/toggle options that take no value and may
/// precede the harness. `--jail` is special: it is valid both bare and as
/// `--jail=TOGGLES` (e.g. `--jail=ssh,github`), handled in the `=` branch
/// below. Parsed so these pre-harness flags do not hide the real harness
/// (#151); unknown pre-harness tokens still fail closed to the outer
/// command.
const AI_MEMORY_RUN_BOOL_OPTIONS: &[&str] = &[
    "--yolo",
    "--true-yolo",
    "--jail",
    "--no-jail",
    "--fresh",
    "--no-autowire",
    "--force-unlock",
];

/// A harness selected by `ai-memory run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManagedHarness<'a> {
    /// Canonical ai-jail command/config name.
    pub name: &'static str,
    /// Explicit `--executable` value, when supplied to ai-memory.
    executable: Option<&'a str>,
}

impl<'a> ManagedHarness<'a> {
    /// Executable ai-memory will resolve for the selected harness.
    pub(crate) fn executable(self) -> &'a str {
        self.executable.unwrap_or(self.name)
    }
}

/// Basename of the process ai-jail was asked to invoke.
pub(crate) fn basename(command: &[String]) -> Option<&str> {
    command.first().and_then(|cmd| {
        Path::new(cmd).file_name().and_then(|name| name.to_str())
    })
}

/// Canonical harness selected by an `ai-memory run` command.
///
/// Wrapper options are deliberately parsed narrowly from ai-memory's
/// published interface. Unknown options fail closed to the outer command
/// instead of guessing that a later token is a harness.
pub(crate) fn managed_harness(
    command: &[String],
) -> Option<ManagedHarness<'_>> {
    if basename(command) != Some("ai-memory") {
        return None;
    }

    let mut index = 1;
    loop {
        let argument = command.get(index)?.as_str();
        if argument == "run" {
            index += 1;
            break;
        }
        index =
            skip_value_option(command, index, AI_MEMORY_GLOBAL_VALUE_OPTIONS)?;
    }

    let mut executable = None;
    let mut options_ended = false;
    while let Some(argument) = command.get(index).map(String::as_str) {
        if !options_ended && argument == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        if !options_ended
            && let Some((option, value)) = argument.split_once('=')
        {
            // Attached-value form (--opt=value). Boolean toggles such as
            // --jail=ssh,github may carry a value; value options require a
            // non-empty one. Anything else fails closed.
            if is_run_bool_option(option) {
                index += 1;
                continue;
            }
            if !is_run_value_option(option) || value.is_empty() {
                return None;
            }
            if option == "--executable" {
                executable = Some(value);
            }
            index += 1;
            continue;
        }

        if !options_ended && is_run_bool_option(argument) {
            index += 1;
            continue;
        }

        if !options_ended && is_run_value_option(argument) {
            let value = command.get(index + 1)?.as_str();
            if argument == "--executable" {
                executable = Some(value);
            }
            index += 2;
            continue;
        }

        if argument.starts_with('-') {
            return None;
        }

        let name = canonical_harness_name(argument)?;
        return Some(ManagedHarness { name, executable });
    }

    None
}

fn skip_value_option(
    command: &[String],
    index: usize,
    options: &[&str],
) -> Option<usize> {
    let argument = command.get(index)?.as_str();
    if let Some((option, value)) = argument.split_once('=') {
        return (options.contains(&option) && !value.is_empty())
            .then_some(index + 1);
    }
    if !options.contains(&argument) {
        return None;
    }
    command.get(index + 1)?;
    Some(index + 2)
}

fn is_run_value_option(argument: &str) -> bool {
    AI_MEMORY_GLOBAL_VALUE_OPTIONS.contains(&argument)
        || AI_MEMORY_RUN_VALUE_OPTIONS.contains(&argument)
}

fn is_run_bool_option(argument: &str) -> bool {
    AI_MEMORY_RUN_BOOL_OPTIONS.contains(&argument)
}

/// Command name used for terminal and automatic-profile behavior.
pub(crate) fn effective_name(command: &[String]) -> Option<&str> {
    managed_harness(command)
        .map(|harness| harness.name)
        .or_else(|| basename(command))
}

/// Agents known to be network API clients. Kept in sync with the
/// per-agent state-path tables in the sandbox backends
/// (`bwrap::command_state_paths`, `seatbelt::agent_state_paths`); kimi
/// binaries are matched by prefix like those tables do.
const KNOWN_API_AGENTS: &[&str] = &[
    "claude",
    "codex",
    "gemini",
    "opencode",
    "crush",
    "grok",
    "jcode",
    "pi",
    "aider",
    "soulforge",
    "omp",
    "kiro-cli",
];

fn is_known_api_agent(name: &str) -> bool {
    KNOWN_API_AGENTS.contains(&name) || name.starts_with("kimi")
}

/// The hosted-API hostname an agent needs in filtered-egress mode, for
/// the precise "your allowlist doesn't cover it" warning. Agents not
/// listed have no canonical host we can name.
fn api_host(name: &str) -> Option<&'static str> {
    match name {
        "claude" => Some("api.anthropic.com"),
        "codex" => Some("api.openai.com"),
        "gemini" => Some("generativelanguage.googleapis.com"),
        "grok" => Some("api.x.ai"),
        _ => None,
    }
}

/// The hosted-API host to default-allow (filtered egress) for a bare launch
/// of a known API agent, or `None` when the agent has no canonical host we
/// can name (issue #156). Reuses the same `api_host` table as the
/// capability-gap warning, so the default allowlist and the warning always
/// agree on the agent's host — injecting it here is exactly what silences
/// the warning. Only the functional API host is returned; telemetry hosts
/// are deliberately not default-allowed.
pub(crate) fn default_egress_host(command: &[String]) -> Option<&'static str> {
    api_host(effective_name(command)?)
}

/// The well-known API-key environment variable(s) a harness reads, so that a
/// harness authenticated via an API key (rather than an OAuth file) also starts
/// pre-authenticated. Only unambiguous, single-purpose variables are listed;
/// the value is copied from the host environment only when actually set, and
/// only alongside agent-state (on by default, off under `--lockdown`). Harnesses
/// not listed rely on their OAuth/credential file mount instead.
pub(crate) fn harness_api_key_env(name: &str) -> &'static [&'static str] {
    match name {
        "claude" => &["ANTHROPIC_API_KEY"],
        "codex" => &["OPENAI_API_KEY"],
        "gemini" | "antigravity" => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "grok" => &["XAI_API_KEY"],
        _ if name.starts_with("kimi") => &["MOONSHOT_API_KEY"],
        _ => &[],
    }
}

/// Launch-time warnings for a known API-client agent whose effective
/// config denies a capability it needs (issue #131): `network` to reach
/// the model API and `agent_state` for its login/session data. Warning
/// only -- the launch is never blocked, and unknown commands are silent.
/// Under `--lockdown` the network warning is suppressed: lockdown blocks
/// network regardless of config, and it is an explicit hardening choice,
/// so pointing at `network = true` would mislead. Filtered egress
/// (`allow_hosts`) counts as network-satisfied, with a precise warning
/// when the agent's known API host is not covered by the allowlist.
pub(crate) fn capability_gap_warnings(
    config: &crate::config::Config,
) -> Vec<String> {
    let Some(name) = effective_name(&config.command) else {
        return Vec::new();
    };
    if !is_known_api_agent(name) {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    let filtered =
        matches!(config.network_mode(), crate::config::NetworkMode::Filtered);
    if !config.lockdown_enabled() && !config.network_enabled() && !filtered {
        warnings.push(format!(
            "ai-jail: `{name}` is a network API client but network is off \
             (default since v1.18.0) — set `network = true` or pass \
             --network; see `ai-jail status`"
        ));
    }
    if filtered
        && let Some(host) = api_host(name)
        && !crate::proxy::allowlist_matches(config.allow_hosts(), host)
    {
        warnings.push(format!(
            "ai-jail: filtered egress is on but `{name}`'s API host \
             {host} is not in allow_hosts — add it there or pass \
             --allow-host {host}; see `ai-jail status`"
        ));
    }
    // Agent state is ON by default now, so no gap warning is needed: a plain
    // `ai-jail <harness>` already mounts the harness's login/session data.
    // `--no-agent-state` and `--lockdown` disable it deliberately, so nudging
    // toward `--agent-state` there would just contradict the user's choice.
    if name == "opencode"
        && !config.command.iter().any(|arg| arg == "--standalone")
    {
        warnings.push(
            "ai-jail: opencode 2.x runs as a client of a shared background \
             server, which does not survive the jail — if startup hangs at \
             \"Starting background server\", add `--standalone` to the \
             command (issue #137)"
                .to_string(),
        );
    }
    warnings
}

/// Executables that private-home mode must keep visible.
///
/// A managed run needs both the outer ai-memory launcher and the selected
/// native harness. The argv itself remains untouched.
pub(crate) fn executable_candidates(command: &[String]) -> Vec<&str> {
    let mut candidates = Vec::new();
    if let Some(outer) = command.first() {
        candidates.push(outer.as_str());
    }
    if let Some(harness) = managed_harness(command) {
        let executable = harness.executable();
        if !candidates.contains(&executable) {
            candidates.push(executable);
        }
    }
    candidates
}

fn canonical_harness_name(value: &str) -> Option<&'static str> {
    match value {
        "claude" | "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "opencode" | "open-code" => Some("opencode"),
        "pi" => Some("pi"),
        "omp" | "oh-my-pi" => Some("omp"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn direct_command_uses_its_basename() {
        let command = args(&["/usr/bin/codex", "--yolo"]);
        assert_eq!(basename(&command), Some("codex"));
        assert_eq!(effective_name(&command), Some("codex"));
        assert_eq!(managed_harness(&command), None);
    }

    #[test]
    fn ai_memory_run_detects_supported_harnesses_and_aliases() {
        for (value, expected) in [
            ("claude", "claude"),
            ("claude-code", "claude"),
            ("codex", "codex"),
            ("opencode", "opencode"),
            ("open-code", "opencode"),
            ("pi", "pi"),
            ("omp", "omp"),
            ("oh-my-pi", "omp"),
        ] {
            let command = args(&["/home/u/bin/ai-memory", "run", value]);
            assert_eq!(effective_name(&command), Some(expected));
        }
    }

    #[test]
    fn ai_memory_run_skips_wrapper_options_but_not_native_args() {
        let command = args(&[
            "ai-memory",
            "--config=/etc/ai-memory.toml",
            "--data-dir",
            "/tmp/memory",
            "run",
            "--workspace",
            "team",
            "--project=demo",
            "--workstream",
            "codex",
            "--new=next",
            "claude",
            "--model",
            "opus",
            "codex",
        ]);
        let harness = managed_harness(&command).unwrap();
        assert_eq!(harness.name, "claude");
        assert_eq!(harness.executable(), "claude");
    }

    #[test]
    fn ai_memory_run_detects_harness_behind_pre_harness_wrapper_flags() {
        // Regression for #151: pre-harness wrapper flags (notably
        // --jail=TOGGLES) must not hide the harness, or agent-state mounts
        // are suppressed and the harness re-authenticates.
        let cases: &[&[&str]] = &[
            &[
                "ai-memory",
                "run",
                "--jail=ssh,github,toolchains,mise",
                "claude",
                "--yolo",
                "--true-yolo",
            ],
            &["ai-memory", "run", "--jail", "claude"],
            &[
                "ai-memory",
                "run",
                "--fresh",
                "--no-autowire",
                "--jail=ssh",
                "claude",
            ],
            &["ai-memory", "run", "--yolo", "--true-yolo", "claude"],
            &["ai-memory", "run", "--no-jail", "--force-unlock", "claude"],
        ];
        for case in cases {
            let command = args(case);
            assert_eq!(
                effective_name(&command),
                Some("claude"),
                "harness hidden by wrapper flags in {case:?}"
            );
        }

        // Pre-harness value options (--env/--env-file/--profile) too.
        let command = args(&[
            "ai-memory",
            "run",
            "--env",
            "FOO=bar",
            "--env-file",
            "/tmp/e",
            "--profile=work",
            "codex",
        ]);
        assert_eq!(effective_name(&command), Some("codex"));
    }

    #[test]
    fn ai_memory_run_pre_harness_flags_still_fail_closed_on_unknowns() {
        // The allowlist is extended, not opened: unknown or incomplete
        // pre-harness tokens still resolve to the outer command.
        for command in [
            args(&["ai-memory", "run", "--jail=ssh", "--unknown", "claude"]),
            args(&["ai-memory", "run", "--env"]), // missing value
            args(&["ai-memory", "run", "--jail=ssh"]), // no harness follows
            args(&["ai-memory", "run", "--yolo", "not-a-harness"]),
        ] {
            assert_eq!(effective_name(&command), Some("ai-memory"));
            assert_eq!(managed_harness(&command), None);
        }
    }

    #[test]
    fn ai_memory_run_observes_explicit_executable() {
        let command = args(&[
            "ai-memory",
            "run",
            "--executable=/home/u/bin/custom-codex",
            "codex",
        ]);
        let harness = managed_harness(&command).unwrap();
        assert_eq!(harness.name, "codex");
        assert_eq!(harness.executable(), "/home/u/bin/custom-codex");
        assert_eq!(
            executable_candidates(&command),
            vec!["ai-memory", "/home/u/bin/custom-codex"]
        );
    }

    #[test]
    fn unknown_or_incomplete_wrapper_syntax_stays_outer_scoped() {
        for command in [
            args(&["ai-memory", "status"]),
            args(&["ai-memory", "--unknown", "run", "codex"]),
            args(&["ai-memory", "--config", "run", "codex"]),
            args(&["ai-memory", "run", "--unknown", "codex"]),
            args(&["ai-memory", "run", "--project"]),
            args(&["ai-memory", "run", "not-a-harness"]),
        ] {
            assert_eq!(effective_name(&command), Some("ai-memory"));
            assert_eq!(managed_harness(&command), None);
        }
    }

    fn gap_config(
        command: &str,
        network: Option<bool>,
        agent_state: Option<bool>,
    ) -> crate::config::Config {
        crate::config::Config {
            command: args(&[command]),
            network,
            agent_state,
            ..crate::config::Config::default()
        }
    }

    #[test]
    fn capability_gap_warns_for_claude_with_network_off() {
        let warnings =
            capability_gap_warnings(&gap_config("claude", None, Some(true)));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`claude`"));
        assert!(warnings[0].contains("network is off"));
        assert!(warnings[0].contains("--network"));
        assert!(warnings[0].contains("ai-jail status"));
    }

    #[test]
    fn harness_api_key_env_maps_known_harnesses() {
        assert_eq!(harness_api_key_env("claude"), &["ANTHROPIC_API_KEY"]);
        assert_eq!(harness_api_key_env("codex"), &["OPENAI_API_KEY"]);
        assert_eq!(
            harness_api_key_env("gemini"),
            &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
        );
        assert_eq!(
            harness_api_key_env("antigravity"),
            &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
        );
        assert_eq!(harness_api_key_env("grok"), &["XAI_API_KEY"]);
        assert_eq!(harness_api_key_env("kimi-code"), &["MOONSHOT_API_KEY"]);
        assert!(harness_api_key_env("bash").is_empty());
    }

    #[test]
    fn capability_gap_no_agent_state_warning_now_default_on() {
        // agent_state is ON by default (pre-authentication), so there is no
        // capability-gap warning even when it is left unset.
        let warnings =
            capability_gap_warnings(&gap_config("claude", Some(true), None));
        assert!(
            warnings.is_empty(),
            "no agent_state gap warning expected: {warnings:?}"
        );
    }

    #[test]
    fn capability_gap_silent_when_capabilities_on() {
        let warnings = capability_gap_warnings(&gap_config(
            "claude",
            Some(true),
            Some(true),
        ));
        assert!(warnings.is_empty());
    }

    #[test]
    fn capability_gap_silent_for_unknown_command() {
        let warnings = capability_gap_warnings(&gap_config("bash", None, None));
        assert!(warnings.is_empty());
    }

    #[test]
    fn capability_gap_warns_opencode_without_standalone() {
        // Issue #137: opencode 2.x is a client of a shared background
        // server that does not survive the jail; --standalone avoids it.
        let mut config = gap_config("opencode", Some(true), Some(true));
        let warnings = capability_gap_warnings(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("--standalone"));
        assert!(warnings[0].contains("#137"));

        config.command = args(&["opencode", "--standalone"]);
        assert!(capability_gap_warnings(&config).is_empty());
    }

    #[test]
    fn capability_gap_covers_kimi_prefix_and_managed_harness() {
        // kimi-code is recognized via the kimi prefix: with network off it
        // gets the network-off warning.
        let warnings =
            capability_gap_warnings(&gap_config("kimi-code", None, None));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("network is off"));

        // A managed `ai-memory run ... codex` is detected as codex.
        let mut config = gap_config("ai-memory", None, None);
        config.command =
            args(&["ai-memory", "run", "--project", "demo", "codex"]);
        let warnings = capability_gap_warnings(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`codex`"));
        assert!(warnings[0].contains("network is off"));
    }

    #[test]
    fn capability_gap_suppresses_network_warning_under_lockdown() {
        // Lockdown blocks network regardless of config, and it is an
        // explicit hardening choice -- pointing at `network = true` would
        // mislead. Agent state is also off under lockdown (by design), and its
        // gap warning was removed, so lockdown yields no gap warnings at all.
        let mut config = gap_config("claude", None, None);
        config.lockdown = Some(true);
        let warnings = capability_gap_warnings(&config);
        assert!(
            warnings.is_empty(),
            "lockdown should emit no capability-gap warnings: {warnings:?}"
        );
    }

    #[test]
    fn capability_gap_filtered_mode_satisfies_network() {
        let mut config = gap_config("claude", None, Some(true));
        config.allow_hosts = vec!["api.anthropic.com".into()];
        assert!(capability_gap_warnings(&config).is_empty());
        // Subdomain entries cover the bare host's subdomains too.
        let mut config = gap_config("claude", None, Some(true));
        config.allow_hosts = vec!["anthropic.com".into()];
        assert!(capability_gap_warnings(&config).is_empty());
    }

    #[test]
    fn capability_gap_filtered_mode_names_missing_api_host() {
        let mut config = gap_config("claude", None, Some(true));
        config.allow_hosts = vec!["github.com".into()];
        let warnings = capability_gap_warnings(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("api.anthropic.com"));
        assert!(warnings[0].contains("--allow-host"));
        assert!(!warnings[0].contains("network is off"));
    }

    #[test]
    fn capability_gap_filtered_mode_silent_without_known_api_host() {
        // Agents with no canonical API host in the table get no
        // host-coverage warning in filtered mode.
        let mut config = gap_config("kimi", None, Some(true));
        config.allow_hosts = vec!["example.com".into()];
        assert!(capability_gap_warnings(&config).is_empty());
    }

    #[test]
    fn default_egress_host_matches_api_host_table() {
        // Each agent's default egress host is exactly its api_host entry, so
        // injecting it (issue #156) silences the filtered-mode gap warning.
        assert_eq!(
            default_egress_host(&["claude".into()]),
            Some("api.anthropic.com")
        );
        assert_eq!(
            default_egress_host(&["codex".into()]),
            Some("api.openai.com")
        );
        assert_eq!(default_egress_host(&["grok".into()]), Some("api.x.ai"));
        // Resolved through the same harness/basename logic as warnings.
        assert_eq!(
            default_egress_host(&["/usr/bin/claude".into()]),
            Some("api.anthropic.com")
        );
        // Agents without a canonical host, and non-agents, get nothing — no
        // half-working default allowlist is injected.
        assert_eq!(default_egress_host(&["opencode".into()]), None);
        assert_eq!(default_egress_host(&["kimi".into()]), None);
        assert_eq!(default_egress_host(&["bash".into()]), None);
    }
}
