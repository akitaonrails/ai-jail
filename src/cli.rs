use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
ai-jail — sandbox for AI coding agents (bwrap on Linux, sandbox-exec on macOS)

USAGE:
    ai-jail [OPTIONS] [--] [COMMAND [ARGS...]]

COMMANDS (positional):
    gemini, claude, codex, opencode, crush, soulforge, grok, pi, jcode,
    kimi, kiro-cli, devin, bash
                                            Known AI tool presets
    status                                 Show current effective config
    capabilities --json                    Show the stable wrapper API
    configure HARNESS                      Review and save project access
    configure --harness NAME [--request-file PATH]
                                            Review wrapper requests and access
    forge setup PROVIDER ORIGIN OWNER/REPO [--allow-private]
                                            Configure repository-scoped forge access
    forge status | forge remove             Inspect or remove forge access
    Any other string                       Passed through as the command

OPTIONS:
    --rw-map <PATH|SOURCE:DEST>    Mount read-write, optionally at DEST
                                   (repeatable)
    --map <PATH|SOURCE:DEST>       Mount read-only, optionally at DEST
                                   (repeatable)
    --overlay-map <PATH>           Mount PATH copy-on-write: writes go to a side
                                   layer, PATH itself stays untouched so you can
                                   diff/promote later (repeatable; Linux/bwrap
                                   only, read-only on macOS)
    --hide-dotdir <NAME>           Never mount dotdir NAME (e.g., .my_secrets) (repeatable)
    --mask <PATH|GLOB>             Replace PATH/glob matches with empty files/tmpfs (repeatable)
    --deny-path <PATH|GLOB>        Deny access to PATH/glob with permission errors (repeatable)
    --mask-except <PATH|GLOB>      Do not mask matches; other sandbox rules still apply
                                   (weakens protection; repeatable; no ! negation)
    --deny-path-except <PATH|GLOB> Do not deny matches; other sandbox rules still apply
                                   (weakens protection; repeatable; no ! negation)
    --private-home / --no-private-home
                                   Disable/enable automatic host home dotdir passthrough
    --lockdown / --no-lockdown     Enable/disable strict read-only lockdown mode
    --landlock / --no-landlock     Enable/disable Landlock LSM (Linux 5.13+, default: on)
    --seccomp / --no-seccomp       Enable/disable seccomp syscall filter (Linux, default: on)
    --rlimits / --no-rlimits       Enable/disable resource limits (default: on)
    --profile <NAME>               Apply [profiles.NAME] from the global
                                   config (once; every access it widens is
                                   printed before launch)
    --systemd-user / --no-systemd-user
                                   Expose host systemd --user bus (dangerous; default: off)
    --no-gpu / --gpu               Disable/enable GPU device passthrough (Linux only)
    --no-docker / --docker         Disable/enable Docker socket passthrough (grants host root; default: off)
    --tailscale / --no-tailscale   Enable/disable Tailscale socket passthrough (default: off)
    --no-display / --display       Disable/enable X11/Wayland passthrough (Linux only)
    --audio / --no-audio           Enable/disable host audio passthrough
                                   (PulseAudio/PipeWire sockets + /dev/snd;
                                   Linux only; default: off)
    --github / --no-github         OPEN: share gh config read-only and the active
                                   github.com token from host gh (including
                                   keyring storage); default: off
    --aws / --no-aws               Enable/disable read-only ~/.aws mount
                                   (read-only; opt-in; the agent can use these
                                   credentials; default: off)
    --kube / --no-kube             Enable/disable read-only ~/.kube mount
                                   (read-only; opt-in; the agent can use these
                                   credentials; default: off)
    --gcloud / --no-gcloud         Enable/disable read-only ~/.config/gcloud
                                   mount (read-only; opt-in; the agent can use
                                   these credentials; default: off)
    --docker-config / --no-docker-config
                                   Enable/disable read-only ~/.docker/config.json
                                   mount (read-only; opt-in; the agent can use
                                   these credentials; default: off)
    --kvm / --no-kvm               Enable/disable /dev/kvm passthrough for
                                   hardware virtualization (Linux only;
                                   default: off)
    --network / --no-network       Enable/disable unrestricted network access (default: off)
    --macos-host-ipc / --no-macos-host-ipc
                                    Enable/disable broad macOS host IPC compatibility (default: off)
    --macos-chromium / --no-macos-chromium
                                    Enable/disable Chromium's own Mach rendezvous
                                    service on macOS, needed by headless Chromium
                                    and Playwright (default: off)
    --macos-trustd / --no-macos-trustd
                                    Enable/disable only the macOS trustd service
                                    so TLS clients like gh can verify
                                    certificates (default: off)
    --macos-pasteboard / --no-macos-pasteboard
                                    Allow native macOS clipboard access only (default: off)
    --allow-pty / --no-allow-pty   Allow opening PTY slave nodes allocated at
                                    runtime on macOS, for tools that spawn their
                                    own pseudo-terminals; grants every /dev/ttys*
                                    (default: off, macOS only)
    --allow-loopback-listen / --no-allow-loopback-listen
                                    Allow binding/listening on loopback while
                                    egress stays filtered on macOS (default: off,
                                    macOS only)
    --allow-loopback-connect / --no-allow-loopback-connect
                                    Allow outbound connections to every host
                                    loopback service on macOS (OPEN; default: off)
    --x11 / --no-x11               Enable/disable X11 socket passthrough (default: off)
    --host-shm / --no-host-shm     Enable/disable host shared-memory passthrough (default: off)
    --terminal-passthrough / --no-terminal-passthrough
                                     Enable/disable terminal passthrough (default: off)
    --terminal-appearance / --no-terminal-appearance
                                    Allow OSC 11 background-color discovery, DA1
                                    terminal identity, and Mode 2031 live appearance
                                    changes (PTY only; default: off; independent
                                    of raw terminal passthrough)
    --agent-state / --no-agent-state
                                    Enable/disable mounting the agent's own state
                                    dirs (~/.claude, ~/.codex, ~/.claude.json, ...;
                                    fresh known-harness profiles: off until approved;
                                    off under
                                    --lockdown; repository policy cannot enable)
    --harness <NAME>               Declare the effective harness explicitly
                                   (repeatable; trusted wrapper integration)
    --request-file <PATH>          Load a versioned wrapper request manifest
                                   outside the project (repeatable)
    --request <KIND=VALUE>         Add one wrapper request (repeatable)
    --json                         Machine-readable output for status/capabilities
    --env <NAME[=VALUE]>            Pass environment variable NAME (value copied from
                                    the host) or NAME=VALUE into the sandbox
                                    (repeatable; literal values are not persisted).
                                    A literal NAME=VALUE is visible on ai-jail's
                                    own argv before launch. Use --env NAME or
                                    --env-from-file to avoid that exposure;
                                    --secret keeps a bound HTTP value outside
                                    the sandbox entirely.
    --env-from-file <PATH>          Read KEY=VALUE lines from PATH (repeatable; file
                                    must be user-owned, mode 0600, outside the project;
                                    applies like --env, which wins on conflicts)
    --secret <KEY=host>             Keep KEY's real value out of the sandbox: the child
                                    sees a placeholder; the egress proxy substitutes the
                                    real value only for requests to host (repeatable;
                                    requires filtered egress via --allow-host)
    --inherit-env / --no-inherit-env
                                    Inherit the full host environment (default: off —
                                    only a safe allowlist is passed)
    --update-check / --no-update-check
                                    Enable/disable the status bar's GitHub update
                                    check (default: off)
    --audit-log / --no-audit-log    Enable/disable the launch audit log at
                                    ~/.local/share/ai-jail/history.jsonl
                                    (default: off; repository policy cannot enable)
    --audit-show                   Show the local audit log and exit
    --audit-verify                 Verify the audit log's hash chain and exit
    --egress-log <PATH>            Append one JSON line per egress-proxy
                                   connection to PATH (mode 0600; needs
                                   filtered networking; Linux only)
    --run-summary <PATH>            Write one private JSON report to a new file
                                   after the run; includes Linux teardown
    --teardown-report              Stop processes that outlive the command
                                   (SIGTERM, SIGKILL after 2000 ms) and name
                                   them on stderr (Linux)
    --worktree / --no-worktree     Enable/disable linked Git worktree metadata passthrough
    --no-mise / --mise             Disable/enable mise integration
    --no-toolchains / --toolchains Disable/enable dev-toolchain cache
                                   persistence (rust/cargo, go, node, …;
                                   default: on; Linux)
    --ssh / --no-ssh               OPEN: share ~/.ssh + ambient SSH agent (default: off)
                                     Use `configure` for selected-key SSH
    --pictures / --no-pictures     Share ~/Pictures read-only (default: off)
    --browser[=PROFILE]            Use browser isolation profile (hard | soft; default hard)
    --no-browser                   Disable browser auto-detection/profile
    --save-config / --no-save-config
                                   Enable/disable external profile/constraint auto-save (default: on;
                                   legacy security migration still runs)
    --hide-config / --no-hide-config
                                   Mask the legacy .ai-jail name from the agent (default: on)
    -s, --status-bar[=STYLE]       Set status line theme (pastel | dark | light; default pastel)
                                   Pastel picks a random pastel palette per session
    --no-status-bar                Disable persistent status line
    --exec                         Direct execution mode (no PTY proxy, no status bar)
    --allow-tcp-port <PORT>        Deprecated and rejected at launch (UDP cannot be
                                   isolated); use --allow-host for filtered egress
                                   instead (still parsed for back-compat)
    --allow-host <HOST>            Allow CONNECT egress to HOST and its subdomains via the
                                   built-in filtered proxy (repeatable; implies filtered
                                   network mode; cannot combine with --network)
    --prompt-hosts / --no-prompt-hosts
                                   In filtered egress mode, ask through a desktop
                                   notification (notify-send) before refusing a host
                                   outside the allowlist; Allow/Deny holds for the
                                   session, no answer refuses only that connection
                                   (Linux only; default: off; off under --lockdown)
    --allow-private-host <HOST>    Like --allow-host, and also permit HOST and its subdomains
                                   to resolve to private/CGNAT addresses (repeatable; trusted
                                   config/CLI only; loopback, link-local, and metadata stay denied)
    --forward-port <PORT>          Expose the host's 127.0.0.1:PORT on the sandbox's own
                                   loopback (repeatable; cannot combine with --network;
                                   the service behind PORT is reachable in full)
    --publish-port <PORT>          Expose the sandbox's own 127.0.0.1:PORT on the host's
                                   127.0.0.1:PORT (Linux; repeatable; cannot combine with
                                   --network; every host process on loopback can reach it)
    --claude-dir <PATH>            Use PATH as Claude config dir (sets CLAUDE_CONFIG_DIR)
    --clean                        Ignore saved and legacy project policy, start fresh
    --dry-run                      Print the sandbox command without executing
    --init                         Create/update external per-project config and exit
    --bootstrap                    Generate smart permission configs for AI tools
    -v, --verbose                  Show detailed mount info
    -h, --help                     Show help
    -V, --version                  Show version
";

#[derive(Debug, Default)]
pub struct CliArgs {
    pub command: Vec<String>,
    pub rw_maps: Vec<PathBuf>,
    pub ro_maps: Vec<PathBuf>,
    pub overlay_maps: Vec<PathBuf>,
    pub hide_dotdirs: Vec<String>,
    pub mask: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
    pub mask_exceptions: Vec<PathBuf>,
    pub deny_path_exceptions: Vec<PathBuf>,
    pub private_home: Option<bool>,
    pub lockdown: Option<bool>,
    pub landlock: Option<bool>,
    pub seccomp: Option<bool>,
    pub rlimits: Option<bool>,
    /// `--profile NAME`: a `[profiles.NAME]` table of the global config.
    /// Validated against the global config at load, not here.
    pub profile: Option<String>,
    pub systemd_user: Option<bool>,
    pub gpu: Option<bool>,
    pub docker: Option<bool>,
    pub tailscale: Option<bool>,
    pub display: Option<bool>,
    pub audio: Option<bool>,
    pub github: Option<bool>,
    pub aws: Option<bool>,
    pub kube: Option<bool>,
    pub gcloud: Option<bool>,
    pub docker_config: Option<bool>,
    pub kvm: Option<bool>,
    pub prompt_hosts: Option<bool>,
    pub network: Option<bool>,
    pub macos_host_ipc: Option<bool>,
    pub macos_chromium: Option<bool>,
    pub macos_trustd: Option<bool>,
    pub macos_pasteboard: Option<bool>,
    pub allow_pty: Option<bool>,
    pub allow_loopback_listen: Option<bool>,
    pub allow_loopback_connect: Option<bool>,
    pub x11: Option<bool>,
    pub host_shm: Option<bool>,
    pub terminal_passthrough: Option<bool>,
    pub terminal_appearance: Option<bool>,
    pub worktree: Option<bool>,
    pub mise: Option<bool>,
    pub toolchains: Option<bool>,
    pub save_config: Option<bool>,
    pub hide_config: Option<bool>,
    pub ssh: Option<bool>,
    pub pictures: Option<bool>,
    pub browser_profile: Option<String>,
    pub status_bar: Option<bool>,
    pub status_bar_style: Option<String>,
    pub allow_tcp_ports: Vec<u16>,
    pub allow_hosts: Vec<String>,
    pub allow_private_hosts: Vec<String>,
    pub forward_ports: Vec<u16>,
    pub publish_ports: Vec<u16>,
    pub claude_dir: Option<PathBuf>,
    pub agent_state: Option<bool>,
    pub harnesses: Vec<String>,
    pub request_files: Vec<PathBuf>,
    pub requests: Vec<String>,
    pub json: bool,
    pub inherit_env: Option<bool>,
    pub update_check: Option<bool>,
    pub audit_log: Option<bool>,
    /// `--egress-log <path>`: one JSON line per
    /// connection the filtered-egress proxy accepts. CLI-only, never a
    /// config key.
    pub egress_log: Option<PathBuf>,
    pub run_summary: Option<PathBuf>,
    pub audit_verify: bool,
    pub audit_show: bool,
    /// `--teardown-report`: stop what outlives the command
    /// and name it on stderr. CLI-only, never a config key.
    pub teardown_report: bool,
    pub env_from_file: Vec<PathBuf>,
    /// Phantom credential bindings (`--secret KEY=host`, repeatable):
    /// the sandbox sees a placeholder; the proxy substitutes the real
    /// value only for requests terminating at `host`.
    pub secrets: Vec<(String, String)>,
    pub env: Vec<String>,
    pub exec: bool,
    pub clean: bool,
    pub dry_run: bool,
    pub init: bool,
    pub bootstrap: bool,
    pub verbose: bool,
    pub status: bool,
    pub capabilities: bool,
    pub configure: Option<String>,
    pub forge: Option<ForgeCommand>,
    /// Internal: apply Landlock and exec remaining command.
    /// Used as a wrapper inside the bwrap sandbox.
    pub landlock_exec: bool,
    /// Internal: wait for the supervisor's one-byte execution gate before
    /// replacing this process with `command`.
    pub supervised_exec_fd: Option<i32>,
    /// Internal: run the in-sandbox proxy bridge (filtered egress),
    /// as (loopback port, outer proxy's Unix socket path). Spawned by
    /// the --landlock-exec wrapper before it restricts itself.
    pub proxy_bridge: Option<(u16, PathBuf)>,
    /// Internal: run the in-sandbox end of a `--publish-port`, as
    /// (sandbox loopback port, supervisor's Unix socket path). Spawned
    /// by the --landlock-exec wrapper before it restricts itself.
    pub publish_bridge: Option<(u16, PathBuf)>,
    /// Internal: loopback port the wrapper's proxy bridge should listen
    /// on; only valid with --landlock-exec.
    pub proxy_bridge_port: Option<u16>,
    /// Internal: descriptor the --landlock-exec wrapper writes its one-line
    /// teardown report to; only valid with --landlock-exec.
    pub teardown_report_fd: Option<i32>,
    /// Internal: opaque read-write mount destinations for Landlock.
    pub landlock_rw_paths: Vec<PathBuf>,
    /// Internal: opaque read-only mount destinations for Landlock.
    pub landlock_ro_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgeCommand {
    Setup {
        provider: String,
        origin: String,
        repository: String,
        allow_private: bool,
    },
    Remove,
    Status,
}

pub fn parse() -> Result<CliArgs, String> {
    parse_argv(std::env::args_os().skip(1).collect())
}

/// Split the argument vector on the first `--` so everything after it is the
/// command and its arguments, verbatim: never scanned for sandbox flags, and
/// the `--` separator itself is not forwarded to the child. Options — and a
/// command given *without* `--` — before the separator are parsed normally,
/// including the ambiguity guard that rejects a sandbox flag after a bare
/// command. This is what lets `ai-jail <opts> -- <cmd> --flag` forward `--flag`
/// (e.g. `--env`, `--network`, `--verbose`) to the child even when it collides
/// with an ai-jail flag. lexopt consumes a leading `--` silently and exposes no
/// way to tell "command after `--`" from "bare positional command", so the
/// split is done here rather than inside the lexopt loop.
pub(crate) fn parse_argv(
    argv: Vec<std::ffi::OsString>,
) -> Result<CliArgs, String> {
    match argv.iter().position(|a| a.to_str() == Some("--")) {
        Some(sep) => {
            let (opts, rest) = argv.split_at(sep);
            let mut args =
                parse_from(lexopt::Parser::from_args(opts.iter().cloned()))?;
            // rest[0] is the "--" separator; skip it, take the command as-is.
            args.command.extend(
                rest.iter()
                    .skip(1)
                    .map(|a| a.to_string_lossy().into_owned()),
            );
            Ok(args)
        }
        None => parse_from(lexopt::Parser::from_args(argv)),
    }
}

pub fn parse_from(mut parser: lexopt::Parser) -> Result<CliArgs, String> {
    use lexopt::prelude::*;

    let mut args = CliArgs::default();

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("rw-map") => {
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.rw_maps.push(val);
            }
            // --ro-map is a back-compat alias for --map (read-only mount).
            // It is listed in is_sandbox_long_flag, so it must parse here
            // too, or it errors inconsistently depending on position.
            Long("map" | "ro-map") => {
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.ro_maps.push(val);
            }
            Long("overlay-map") => {
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.overlay_maps.push(val);
            }
            Long("mask") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                if s.is_empty() {
                    return Err("--mask requires a non-empty path".into());
                }
                args.mask.push(PathBuf::from(s.into_owned()));
            }
            Long("deny-path") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                if s.is_empty() {
                    return Err("--deny-path requires a non-empty path".into());
                }
                args.deny_paths.push(PathBuf::from(s.into_owned()));
            }
            Long("mask-except") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                if s.is_empty() {
                    return Err(
                        "--mask-except requires a non-empty path".into()
                    );
                }
                args.mask_exceptions.push(PathBuf::from(s.into_owned()));
            }
            Long("deny-path-except") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                if s.is_empty() {
                    return Err(
                        "--deny-path-except requires a non-empty path".into()
                    );
                }
                args.deny_path_exceptions
                    .push(PathBuf::from(s.into_owned()));
            }
            Long("hide-dotdir") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy().into_owned();
                if s.is_empty() {
                    return Err(
                        "--hide-dotdir requires a non-empty value".into()
                    );
                }
                let normalized = if s.starts_with('.') {
                    s
                } else {
                    format!(".{s}")
                };
                args.hide_dotdirs.push(normalized);
            }
            Long(s @ ("lockdown" | "no-lockdown")) => {
                args.lockdown = Some(s == "lockdown");
            }
            Long(s @ ("private-home" | "no-private-home")) => {
                args.private_home = Some(s == "private-home");
            }
            Long(s @ ("landlock" | "no-landlock")) => {
                args.landlock = Some(s == "landlock");
            }
            Long(s @ ("seccomp" | "no-seccomp")) => {
                args.seccomp = Some(s == "seccomp");
            }
            Long(s @ ("rlimits" | "no-rlimits")) => {
                args.rlimits = Some(s == "rlimits");
            }
            Long(s @ ("systemd-user" | "no-systemd-user")) => {
                args.systemd_user = Some(s == "systemd-user");
            }
            Long("profile") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                if args.profile.is_some() {
                    return Err("--profile given more than once: a launch \
                                selects one profile"
                        .into());
                }
                args.profile = Some(val.to_string_lossy().into_owned());
            }
            Long("allow-tcp-port") => {
                let val: String = parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned();
                let port: u16 = val
                    .parse()
                    .map_err(|_| format!("invalid port number: {val}"))?;
                args.allow_tcp_ports.push(port);
            }
            Long("allow-host") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let host = val.to_string_lossy();
                if host.is_empty() {
                    return Err("--allow-host requires a non-empty host".into());
                }
                args.allow_hosts.push(host.into_owned());
            }
            Long("allow-private-host") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let host = val.to_string_lossy();
                if host.is_empty() {
                    return Err(
                        "--allow-private-host requires a non-empty host".into(),
                    );
                }
                args.allow_private_hosts.push(host.into_owned());
            }
            Long("forward-port") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let port_text = val.to_string_lossy();
                let port: u16 = port_text
                    .parse()
                    .map_err(|_| format!("invalid port number: {port_text}"))?;
                args.forward_ports.push(port);
            }
            Long("publish-port") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let port_text = val.to_string_lossy();
                let port: u16 = port_text
                    .parse()
                    .map_err(|_| format!("invalid port number: {port_text}"))?;
                args.publish_ports.push(port);
            }
            Long("claude-dir") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                args.claude_dir =
                    Some(PathBuf::from(val.to_string_lossy().into_owned()));
            }
            Long(s @ ("gpu" | "no-gpu")) => {
                args.gpu = Some(s == "gpu");
            }
            Long(s @ ("docker" | "no-docker")) => {
                args.docker = Some(s == "docker");
            }
            Long(s @ ("tailscale" | "no-tailscale")) => {
                args.tailscale = Some(s == "tailscale");
            }
            Long(s @ ("display" | "no-display")) => {
                args.display = Some(s == "display");
            }
            Long(s @ ("audio" | "no-audio")) => {
                args.audio = Some(s == "audio");
            }
            Long(s @ ("github" | "no-github")) => {
                args.github = Some(s == "github");
            }
            Long(s @ ("aws" | "no-aws")) => {
                args.aws = Some(s == "aws");
            }
            Long(s @ ("kube" | "no-kube")) => {
                args.kube = Some(s == "kube");
            }
            Long(s @ ("gcloud" | "no-gcloud")) => {
                args.gcloud = Some(s == "gcloud");
            }
            Long(s @ ("docker-config" | "no-docker-config")) => {
                args.docker_config = Some(s == "docker-config");
            }
            Long(s @ ("kvm" | "no-kvm")) => {
                args.kvm = Some(s == "kvm");
            }
            Long(s @ ("prompt-hosts" | "no-prompt-hosts")) => {
                args.prompt_hosts = Some(s == "prompt-hosts");
            }
            Long(s @ ("network" | "no-network")) => {
                args.network = Some(s == "network");
            }
            Long(s @ ("macos-host-ipc" | "no-macos-host-ipc")) => {
                args.macos_host_ipc = Some(s == "macos-host-ipc");
            }
            Long(s @ ("macos-chromium" | "no-macos-chromium")) => {
                args.macos_chromium = Some(s == "macos-chromium");
            }
            Long(s @ ("macos-trustd" | "no-macos-trustd")) => {
                args.macos_trustd = Some(s == "macos-trustd");
            }
            Long(s @ ("macos-pasteboard" | "no-macos-pasteboard")) => {
                args.macos_pasteboard = Some(s == "macos-pasteboard");
            }
            Long(s @ ("allow-pty" | "no-allow-pty")) => {
                args.allow_pty = Some(s == "allow-pty");
            }
            Long(
                s @ ("allow-loopback-listen" | "no-allow-loopback-listen"),
            ) => {
                args.allow_loopback_listen = Some(s == "allow-loopback-listen");
            }
            Long(
                s @ ("allow-loopback-connect" | "no-allow-loopback-connect"),
            ) => {
                args.allow_loopback_connect =
                    Some(s == "allow-loopback-connect");
            }
            Long(s @ ("x11" | "no-x11")) => {
                args.x11 = Some(s == "x11");
            }
            Long(s @ ("host-shm" | "no-host-shm")) => {
                args.host_shm = Some(s == "host-shm");
            }
            Long(s @ ("terminal-passthrough" | "no-terminal-passthrough")) => {
                args.terminal_passthrough = Some(s == "terminal-passthrough");
            }
            Long(s @ ("terminal-appearance" | "no-terminal-appearance")) => {
                args.terminal_appearance = Some(s == "terminal-appearance");
            }
            Long(s @ ("agent-state" | "no-agent-state")) => {
                args.agent_state = Some(s == "agent-state");
            }
            Long("harness") => {
                let value = parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned();
                let value = validate_harness(&value)?;
                if !args.harnesses.contains(&value) {
                    args.harnesses.push(value);
                }
            }
            Long("request-file") => {
                let value: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.request_files.push(value);
            }
            Long("request") => {
                let value = parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned();
                if !value.contains('=') {
                    return Err("--request requires KIND=VALUE".into());
                }
                args.requests.push(value);
            }
            Long("json") => args.json = true,
            Long(s @ ("inherit-env" | "no-inherit-env")) => {
                args.inherit_env = Some(s == "inherit-env");
            }
            Long(s @ ("update-check" | "no-update-check")) => {
                args.update_check = Some(s == "update-check");
            }
            Long(s @ ("audit-log" | "no-audit-log")) => {
                args.audit_log = Some(s == "audit-log");
            }
            Long("audit-verify") => args.audit_verify = true,
            Long("egress-log") => {
                // Kept as an OsString path: a non-UTF-8 name must reach
                // open(2) unchanged, not lossily rewritten.
                let val = parser.value().map_err(|e| e.to_string())?;
                if val.is_empty() {
                    return Err("--egress-log requires a non-empty path".into());
                }
                args.egress_log = Some(PathBuf::from(val));
            }
            Long("run-summary") => {
                let path = parser.value().map_err(|e| e.to_string())?;
                if path.is_empty() || args.run_summary.is_some() {
                    return Err(
                        "--run-summary requires one non-empty path".into()
                    );
                }
                args.run_summary = Some(PathBuf::from(path));
            }
            Long("audit-show") => args.audit_show = true,
            Long("teardown-report") => args.teardown_report = true,
            Long("env") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                let name = s.split('=').next().unwrap_or("");
                if s.is_empty() || name.is_empty() {
                    return Err(
                        "--env requires a non-empty NAME or NAME=VALUE".into(),
                    );
                }
                args.env.push(s.into_owned());
            }
            Long("env-from-file") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let path = val.to_string_lossy();
                if path.is_empty() {
                    return Err(
                        "--env-from-file requires a non-empty path".into()
                    );
                }
                args.env_from_file.push(PathBuf::from(path.into_owned()));
            }
            Long("secret") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val.to_string_lossy();
                let Some((key, host)) = s.split_once('=') else {
                    return Err("--secret requires KEY=host".into());
                };
                if key.is_empty() || host.is_empty() {
                    return Err(
                        "--secret requires non-empty KEY and host".into()
                    );
                }
                args.secrets.push((key.to_string(), host.to_string()));
            }
            Long(s @ ("worktree" | "no-worktree")) => {
                args.worktree = Some(s == "worktree");
            }
            Long(s @ ("mise" | "no-mise")) => {
                args.mise = Some(s == "mise");
            }
            Long(s @ ("toolchains" | "no-toolchains")) => {
                args.toolchains = Some(s == "toolchains");
            }
            Long(s @ ("save-config" | "no-save-config")) => {
                args.save_config = Some(s == "save-config");
            }
            Long(s @ ("hide-config" | "no-hide-config")) => {
                args.hide_config = Some(s == "hide-config");
            }
            Long(s @ ("ssh" | "no-ssh")) => {
                args.ssh = Some(s == "ssh");
            }
            Long(s @ ("pictures" | "no-pictures")) => {
                args.pictures = Some(s == "pictures");
            }
            Long("browser") => {
                let profile = if let Some(val) = parser.optional_value() {
                    let s = val.to_string_lossy();
                    match s.as_ref() {
                        "hard" | "soft" => s.into_owned(),
                        _ => {
                            return Err(format!(
                                "invalid browser profile: \
                                 {s} (expected 'hard' or 'soft')"
                            ));
                        }
                    }
                } else {
                    "hard".into()
                };
                args.browser_profile = Some(profile);
            }
            Long("no-browser") => args.browser_profile = Some("off".into()),
            Long("status-bar") | Short('s') => {
                if let Some(val) = parser.optional_value() {
                    let s = val.to_string_lossy();
                    match s.as_ref() {
                        "dark" | "light" | "pastel" => {
                            args.status_bar_style = Some(s.into_owned());
                        }
                        _ => {
                            return Err(format!(
                                "invalid status bar style: \
                                 {s} (expected 'dark', 'light', or 'pastel')"
                            ));
                        }
                    }
                } else {
                    args.status_bar_style = Some("pastel".into());
                }
            }
            Long("no-status-bar") => args.status_bar = Some(false),
            Long("exec") => {
                args.exec = true;
                args.status_bar = Some(false);
            }
            Long("landlock-exec") => args.landlock_exec = true,
            Long("supervised-exec-fd") => {
                let value = parser.value().map_err(|e| e.to_string())?;
                args.supervised_exec_fd =
                    Some(value.to_string_lossy().parse().map_err(|_| {
                        "invalid supervised execution fd".to_string()
                    })?);
            }
            Long("proxy-bridge") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let port_text = val.to_string_lossy();
                let port: u16 = port_text.parse().map_err(|_| {
                    format!("invalid proxy bridge port: {port_text}")
                })?;
                let sock: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.proxy_bridge = Some((port, sock));
            }
            Long("publish-bridge") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let port_text = val.to_string_lossy();
                let port: u16 = port_text.parse().map_err(|_| {
                    format!("invalid publish bridge port: {port_text}")
                })?;
                let sock: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.publish_bridge = Some((port, sock));
            }
            Long("proxy-bridge-port") => {
                if !args.landlock_exec {
                    return Err(
                        "--proxy-bridge-port is internal and only valid with --landlock-exec"
                            .into(),
                    );
                }
                let val = parser.value().map_err(|e| e.to_string())?;
                let port_text = val.to_string_lossy();
                let port: u16 = port_text.parse().map_err(|_| {
                    format!("invalid proxy bridge port: {port_text}")
                })?;
                args.proxy_bridge_port = Some(port);
            }
            Long("teardown-report-fd") => {
                if !args.landlock_exec {
                    return Err(
                        "--teardown-report-fd is internal and only valid with --landlock-exec"
                            .into(),
                    );
                }
                let val = parser.value().map_err(|e| e.to_string())?;
                let fd_text = val.to_string_lossy();
                let fd: i32 = fd_text.parse().map_err(|_| {
                    format!("invalid teardown report fd: {fd_text}")
                })?;
                args.teardown_report_fd = Some(fd);
            }
            Long("landlock-rw-path") => {
                if !args.landlock_exec {
                    return Err(
                        "--landlock-rw-path is internal and only valid with --landlock-exec"
                            .into(),
                    );
                }
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.landlock_rw_paths.push(val);
            }
            Long("landlock-ro-path") => {
                if !args.landlock_exec {
                    return Err(
                        "--landlock-ro-path is internal and only valid with --landlock-exec"
                            .into(),
                    );
                }
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.landlock_ro_paths.push(val);
            }
            Long("clean") => args.clean = true,
            Long("dry-run") => args.dry_run = true,
            Long("init") => args.init = true,
            Long("bootstrap") => args.bootstrap = true,
            Short('v') | Long("verbose") => args.verbose = true,
            Short('h') | Long("help") => {
                print!("{HELP}");
                std::process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("ai-jail {VERSION}");
                std::process::exit(0);
            }
            Value(val) => {
                let s = val.to_string_lossy().into_owned();
                if s == "status" {
                    args.status = true;
                } else if s == "capabilities" && args.command.is_empty() {
                    args.capabilities = true;
                } else if s == "forge" && args.command.is_empty() {
                    let action = parser
                        .value()
                        .map_err(|_| {
                            "forge requires setup, status, or remove"
                                .to_string()
                        })?
                        .to_string_lossy()
                        .into_owned();
                    args.forge = Some(match action.as_str() {
                        "status" => {
                            if parser
                                .next()
                                .map_err(|e| e.to_string())?
                                .is_some()
                            {
                                return Err(
                                    "forge status accepts no arguments".into(),
                                );
                            }
                            ForgeCommand::Status
                        }
                        "remove" => {
                            if parser
                                .next()
                                .map_err(|e| e.to_string())?
                                .is_some()
                            {
                                return Err(
                                    "forge remove accepts no arguments".into(),
                                );
                            }
                            ForgeCommand::Remove
                        }
                        "setup" => {
                            let provider = parser
                                .value()
                                .map_err(|_| {
                                    "forge setup requires PROVIDER".to_string()
                                })?
                                .to_string_lossy()
                                .into_owned();
                            let origin = parser
                                .value()
                                .map_err(|_| {
                                    "forge setup requires ORIGIN".to_string()
                                })?
                                .to_string_lossy()
                                .into_owned();
                            let repository = parser
                                .value()
                                .map_err(|_| {
                                    "forge setup requires OWNER/REPO"
                                        .to_string()
                                })?
                                .to_string_lossy()
                                .into_owned();
                            let mut allow_private = false;
                            if let Some(next) =
                                parser.next().map_err(|e| e.to_string())?
                            {
                                match next {
                                    lexopt::Arg::Long("allow-private") => allow_private = true,
                                    _ => return Err("forge setup accepts only --allow-private after OWNER/REPO".into()),
                                }
                            }
                            if parser
                                .next()
                                .map_err(|e| e.to_string())?
                                .is_some()
                            {
                                return Err(
                                    "forge setup received too many arguments"
                                        .into(),
                                );
                            }
                            ForgeCommand::Setup {
                                provider,
                                origin,
                                repository,
                                allow_private,
                            }
                        }
                        _ => {
                            return Err(
                                "forge requires setup, status, or remove"
                                    .into(),
                            );
                        }
                    });
                } else if s == "configure" && args.command.is_empty() {
                    let tail = parser
                        .raw_args()
                        .map_err(|e| e.to_string())?
                        .collect::<Vec<_>>();
                    parse_configure_tail(&mut args, tail)?;
                    break;
                } else {
                    args.command.push(s);
                    // Consume ALL remaining args as part of the command
                    // (including --flags that belong to the sub-command)
                    let mut after_separator = false;
                    for raw in parser.raw_args().map_err(|e| e.to_string())? {
                        let raw = raw.to_string_lossy().into_owned();
                        if raw == "--" {
                            after_separator = true;
                            args.command.push(raw);
                            continue;
                        }
                        if !after_separator && is_sandbox_long_flag(&raw) {
                            return Err(format!(
                                "flag {raw} after command would be passed to the child; put sandbox flags before the command or use --"
                            ));
                        }
                        args.command.push(raw);
                    }
                }
            }
            Long(other) => return Err(format!("unknown option: --{other}")),
            Short(c) => return Err(format!("unknown option: -{c}")),
        }
    }

    if args.audit_show
        && (!args.command.is_empty()
            || args.status
            || args.audit_verify
            || args.init
            || args.bootstrap
            || args.dry_run
            || args.landlock_exec
            || args.proxy_bridge.is_some()
            || args.publish_bridge.is_some())
    {
        return Err(
            "--audit-show cannot be combined with another command or action"
                .into(),
        );
    }

    if args.json && !args.status && !args.capabilities {
        return Err("--json is only valid with status or capabilities".into());
    }
    if args.capabilities
        && (!args.command.is_empty()
            || args.status
            || args.configure.is_some()
            || args.forge.is_some())
    {
        return Err(
            "capabilities cannot be combined with another action".into()
        );
    }

    Ok(args)
}

fn validate_harness(value: &str) -> Result<String, String> {
    crate::command::normalize_harness_name(value)
        .map(str::to_string)
        .ok_or_else(|| format!("unknown harness {value:?}"))
}

fn parse_configure_tail(
    args: &mut CliArgs,
    tail: Vec<std::ffi::OsString>,
) -> Result<(), String> {
    let mut index = 0;
    let mut positional: Option<String> = None;
    while index < tail.len() {
        let value = tail[index].to_string_lossy().into_owned();
        match value.as_str() {
            "--harness" => {
                index += 1;
                let harness = tail
                    .get(index)
                    .ok_or_else(|| "--harness requires NAME".to_string())?
                    .to_string_lossy()
                    .into_owned();
                let harness = validate_harness(&harness)?;
                if !args.harnesses.contains(&harness) {
                    args.harnesses.push(harness);
                }
            }
            "--request-file" => {
                index += 1;
                let path = tail.get(index).ok_or_else(|| {
                    "--request-file requires PATH".to_string()
                })?;
                args.request_files.push(PathBuf::from(path));
            }
            "--request" => {
                index += 1;
                let request = tail
                    .get(index)
                    .ok_or_else(|| "--request requires KIND=VALUE".to_string())?
                    .to_string_lossy()
                    .into_owned();
                if !request.contains('=') {
                    return Err("--request requires KIND=VALUE".into());
                }
                args.requests.push(request);
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown configure option: {value}"));
            }
            _ if positional.is_none() => {
                positional = Some(validate_harness(&value)?);
            }
            _ => return Err("configure accepts one positional harness".into()),
        }
        index += 1;
    }
    if let Some(harness) = positional {
        if !args.harnesses.is_empty() && !args.harnesses.contains(&harness) {
            return Err(
                "positional configure harness contradicts --harness".into()
            );
        }
        if args.harnesses.is_empty() {
            args.harnesses.push(harness);
        }
    }
    let harness = args.harnesses.first().cloned().ok_or_else(|| {
        "configure requires HARNESS or --harness NAME".to_string()
    })?;
    args.configure = Some(harness.clone());
    args.command.push(harness);
    Ok(())
}

/// Long flags that configure the sandbox itself (as opposed to the wrapped
/// command). Used to reject a sandbox flag that appears after the command
/// with no `--` separator. Every entry MUST have a matching parse arm in
/// `parse_from`, or it errors inconsistently (the `--ro-map` bug: "unknown
/// option" before the command, "would be passed to the child" after it).
/// The conformance test `every_guarded_sandbox_flag_is_parseable` enforces
/// that invariant.
const SANDBOX_LONG_FLAGS: &[&str] = &[
    "--harness",
    "--request-file",
    "--request",
    "--json",
    "--private-home",
    "--no-private-home",
    "--lockdown",
    "--no-lockdown",
    "--no-display",
    "--display",
    "--audio",
    "--no-audio",
    "--github",
    "--no-github",
    "--aws",
    "--no-aws",
    "--kube",
    "--no-kube",
    "--gcloud",
    "--no-gcloud",
    "--docker-config",
    "--no-docker-config",
    "--kvm",
    "--no-kvm",
    "--prompt-hosts",
    "--no-prompt-hosts",
    "--network",
    "--no-network",
    "--macos-host-ipc",
    "--no-macos-host-ipc",
    "--macos-chromium",
    "--no-macos-chromium",
    "--macos-trustd",
    "--macos-pasteboard",
    "--no-macos-trustd",
    "--no-macos-pasteboard",
    "--allow-pty",
    "--no-allow-pty",
    "--allow-loopback-listen",
    "--no-allow-loopback-listen",
    "--allow-loopback-connect",
    "--no-allow-loopback-connect",
    "--no-gpu",
    "--gpu",
    "--no-docker",
    "--docker",
    "--tailscale",
    "--no-tailscale",
    "--landlock",
    "--no-landlock",
    "--seccomp",
    "--no-seccomp",
    "--rlimits",
    "--no-rlimits",
    "--profile",
    "--ssh",
    "--no-ssh",
    "--pictures",
    "--no-pictures",
    "--clean",
    "--exec",
    "--dry-run",
    "--rw-map",
    "--ro-map",
    "--overlay-map",
    "--map",
    "--mask",
    "--deny-path",
    "--mask-except",
    "--deny-path-except",
    "--hide-dotdir",
    "--allow-tcp-port",
    "--allow-host",
    "--allow-private-host",
    "--systemd-user",
    "--no-systemd-user",
    "--worktree",
    "--no-worktree",
    "--browser",
    "--no-browser",
    "--claude-dir",
    "--x11",
    "--no-x11",
    "--host-shm",
    "--no-host-shm",
    "--terminal-passthrough",
    "--no-terminal-passthrough",
    "--terminal-appearance",
    "--no-terminal-appearance",
    "--agent-state",
    "--no-agent-state",
    "--forward-port",
    "--publish-port",
    "--teardown-report",
    "--inherit-env",
    "--no-inherit-env",
    "--update-check",
    "--no-update-check",
    "--audit-log",
    "--no-audit-log",
    "--audit-verify",
    "--egress-log",
    "--run-summary",
    "--env",
    "--env-from-file",
    "--secret",
    "--mise",
    "--no-mise",
    "--toolchains",
    "--no-toolchains",
    "--save-config",
    "--no-save-config",
    "--hide-config",
    "--no-hide-config",
    "--status-bar",
    "--no-status-bar",
    "--init",
    "--bootstrap",
    "--verbose",
];

fn is_sandbox_long_flag(arg: &str) -> bool {
    let flag = arg.split_once('=').map_or(arg, |(flag, _)| flag);
    SANDBOX_LONG_FLAGS.contains(&flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_test(args: &[&str]) -> Result<CliArgs, String> {
        parse_argv(args.iter().map(std::ffi::OsString::from).collect())
    }

    #[test]
    fn every_documented_cli_option_has_a_tui_parity_classification() {
        let parity = include_str!("../docs/CLI_TUI_PARITY.md");
        let guidelines = include_str!("../CLAUDE.md");
        assert!(guidelines.contains("Interface synchronization contract"));
        assert!(guidelines.contains("CLI/config/TUI capability-parity check"));

        for line in HELP.lines().filter(|line| {
            line.starts_with("    --")
                || (line.starts_with("    -") && line.contains(", --"))
        }) {
            for token in line
                .split_whitespace()
                .filter(|token| token.starts_with("--"))
            {
                let option = token
                    .chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric()
                            || matches!(character, '-' | '_')
                    })
                    .collect::<String>();
                assert!(
                    parity.contains(&format!("`{option}`")),
                    "{option} is in CLI help but missing from docs/CLI_TUI_PARITY.md"
                );
            }
        }
    }

    #[test]
    fn every_guarded_sandbox_flag_is_parseable() {
        // Regression for the --ro-map bug: a flag listed in the sandbox-flag
        // guard but missing its parse arm fails with "unknown option" before
        // the command yet is caught by the guard after it — two contradictory
        // errors. Every guarded long flag must be a recognized option, so no
        // guarded flag may produce "unknown option".
        for &flag in SANDBOX_LONG_FLAGS {
            // Attach a probe value so value-taking flags are satisfied. A
            // boolean/action flag ignores it (lexopt may then complain about
            // an unexpected value, or validation may reject "probe" — but
            // never with "unknown option", which only an unwired flag yields).
            let argv = [format!("{flag}=probe"), "bash".to_string()];
            if let Err(e) =
                parse_argv(argv.iter().map(std::ffi::OsString::from).collect())
            {
                assert!(
                    !e.contains("unknown option"),
                    "guarded flag {flag} has no parse arm: {e}"
                );
            }
        }
    }

    #[test]
    fn profile_is_taken_once_and_refused_after_the_command() {
        let parse = |args: &[&str]| {
            parse_argv(args.iter().map(std::ffi::OsString::from).collect())
        };
        let once = parse(&["--profile", "agent-test", "bash"]).unwrap();
        assert_eq!(once.profile.as_deref(), Some("agent-test"));
        assert!(parse(&["bash"]).unwrap().profile.is_none());
        let twice = parse(&["--profile", "a", "--profile", "b", "bash"])
            .expect_err("a second --profile must be refused");
        assert!(twice.contains("--profile"), "{twice}");
        let after = parse(&["bash", "--profile", "a"])
            .expect_err("--profile after the command must be refused");
        assert!(after.contains("--profile"), "{after}");
    }

    #[test]
    fn guarded_boolean_flags_have_both_polarities() {
        // A --X/--no-X sandbox toggle must have both sides guarded and
        // parseable, or the missing side slips past the post-command guard
        // inconsistently. Action/value flags (--dry-run, --map, --env, …) are
        // intentionally one-sided and excluded.
        let toggles = [
            "private-home",
            "lockdown",
            "display",
            "audio",
            "github",
            "aws",
            "kube",
            "gcloud",
            "docker-config",
            "kvm",
            "prompt-hosts",
            "network",
            "macos-host-ipc",
            "macos-chromium",
            "macos-trustd",
            "macos-pasteboard",
            "allow-pty",
            "allow-loopback-listen",
            "allow-loopback-connect",
            "gpu",
            "docker",
            "tailscale",
            "landlock",
            "seccomp",
            "rlimits",
            "ssh",
            "pictures",
            "systemd-user",
            "worktree",
            "x11",
            "host-shm",
            "terminal-passthrough",
            "agent-state",
            "inherit-env",
            "update-check",
            "audit-log",
            "mise",
            "toolchains",
            "save-config",
            "hide-config",
        ];
        for base in toggles {
            let on = format!("--{base}");
            let off = format!("--no-{base}");
            assert!(
                SANDBOX_LONG_FLAGS.contains(&on.as_str()),
                "toggle --{base} is not in the sandbox-flag guard"
            );
            assert!(
                SANDBOX_LONG_FLAGS.contains(&off.as_str()),
                "toggle --{base} is missing its --no-{base} sibling"
            );
        }
    }

    // ── Basic command parsing ──────────────────────────────────

    #[test]
    fn parse_no_args() {
        let args = parse_test(&[]).unwrap();
        assert!(args.command.is_empty());
        assert_eq!(args.lockdown, None);
        assert!(!args.dry_run);
        assert!(!args.init);
        assert!(!args.verbose);
        assert!(!args.clean);
        assert!(!args.status);
    }

    #[test]
    fn parse_simple_command() {
        let args = parse_test(&["claude"]).unwrap();
        assert_eq!(args.command, vec!["claude"]);
    }

    #[test]
    fn parse_command_with_args() {
        let args = parse_test(&["claude", "--model", "opus"]).unwrap();
        assert_eq!(args.command, vec!["claude", "--model", "opus"]);
    }

    #[test]
    fn parse_bash_command() {
        let args = parse_test(&["bash"]).unwrap();
        assert_eq!(args.command, vec!["bash"]);
    }

    #[test]
    fn parse_pi_command() {
        let args = parse_test(&["pi"]).unwrap();
        assert_eq!(args.command, vec!["pi"]);
    }

    #[test]
    fn help_lists_pi_preset() {
        assert!(HELP.contains("grok, pi, jcode,"));
    }

    #[test]
    fn parse_status_command() {
        let args = parse_test(&["status"]).unwrap();
        assert!(args.status);
        assert!(args.command.is_empty());
    }

    #[test]
    fn parse_configure_known_harness() {
        let args = parse_test(&["configure", "claude"]).unwrap();
        assert_eq!(args.configure.as_deref(), Some("claude"));
        assert_eq!(args.command, vec!["claude"]);
    }

    #[test]
    fn parse_forge_setup_and_private_acknowledgement() {
        let args = parse_test(&[
            "forge",
            "setup",
            "gitlab",
            "https://gitlab.example",
            "owner/repo",
            "--allow-private",
        ])
        .unwrap();
        assert_eq!(
            args.forge,
            Some(ForgeCommand::Setup {
                provider: "gitlab".into(),
                origin: "https://gitlab.example".into(),
                repository: "owner/repo".into(),
                allow_private: true,
            })
        );
        assert!(args.command.is_empty());
    }

    #[test]
    fn parse_forge_status_and_remove() {
        assert_eq!(
            parse_test(&["forge", "status"]).unwrap().forge,
            Some(ForgeCommand::Status)
        );
        assert_eq!(
            parse_test(&["forge", "remove"]).unwrap().forge,
            Some(ForgeCommand::Remove)
        );
        assert!(parse_test(&["forge", "status", "extra"]).is_err());
    }

    #[test]
    fn configure_requires_one_known_harness() {
        assert!(parse_test(&["configure"]).is_err());
        assert!(parse_test(&["configure", "unknown"]).is_err());
        assert!(parse_test(&["configure", "claude", "extra"]).is_err());
    }

    #[test]
    fn separator_preserves_configure_as_a_child_command() {
        let args = parse_test(&["--", "configure", "claude"]).unwrap();
        assert_eq!(args.configure, None);
        assert_eq!(args.command, vec!["configure", "claude"]);
    }

    // ── Flag parsing ───────────────────────────────────────────

    #[test]
    fn parse_dry_run() {
        let args = parse_test(&["--dry-run", "bash"]).unwrap();
        assert!(args.dry_run);
        assert_eq!(args.command, vec!["bash"]);
    }

    #[test]
    fn parse_init() {
        let args = parse_test(&["--init", "claude"]).unwrap();
        assert!(args.init);
        assert_eq!(args.command, vec!["claude"]);
    }

    #[test]
    fn parse_clean() {
        let args = parse_test(&["--clean", "bash"]).unwrap();
        assert!(args.clean);
    }

    #[test]
    fn parse_verbose_short() {
        let args = parse_test(&["-v", "bash"]).unwrap();
        assert!(args.verbose);
    }

    #[test]
    fn parse_verbose_long() {
        let args = parse_test(&["--verbose", "bash"]).unwrap();
        assert!(args.verbose);
    }

    // ── Boolean toggle flags ───────────────────────────────────

    #[test]
    fn parse_no_gpu() {
        let args = parse_test(&["--no-gpu", "bash"]).unwrap();
        assert_eq!(args.gpu, Some(false));
    }

    #[test]
    fn parse_lockdown() {
        let args = parse_test(&["--lockdown", "bash"]).unwrap();
        assert_eq!(args.lockdown, Some(true));
    }

    #[test]
    fn parse_private_home() {
        let args = parse_test(&["--private-home", "bash"]).unwrap();
        assert_eq!(args.private_home, Some(true));
    }

    #[test]
    fn parse_no_private_home() {
        let args = parse_test(&["--no-private-home", "bash"]).unwrap();
        assert_eq!(args.private_home, Some(false));
    }

    #[test]
    fn parse_no_lockdown() {
        let args = parse_test(&["--no-lockdown", "bash"]).unwrap();
        assert_eq!(args.lockdown, Some(false));
    }

    #[test]
    fn parse_systemd_user() {
        let args = parse_test(&["--systemd-user", "bash"]).unwrap();
        assert_eq!(args.systemd_user, Some(true));
    }

    #[test]
    fn parse_no_systemd_user() {
        let args = parse_test(&["--no-systemd-user", "bash"]).unwrap();
        assert_eq!(args.systemd_user, Some(false));
    }

    #[test]
    fn parse_systemd_user_last_wins() {
        let args = parse_test(&[
            "--systemd-user",
            "--no-systemd-user",
            "--systemd-user",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.systemd_user, Some(true));
    }

    #[test]
    fn parse_landlock() {
        let args = parse_test(&["--landlock", "bash"]).unwrap();
        assert_eq!(args.landlock, Some(true));
    }

    #[test]
    fn parse_no_landlock() {
        let args = parse_test(&["--no-landlock", "bash"]).unwrap();
        assert_eq!(args.landlock, Some(false));
    }

    #[test]
    fn parse_gpu() {
        let args = parse_test(&["--gpu", "bash"]).unwrap();
        assert_eq!(args.gpu, Some(true));
    }

    #[test]
    fn parse_no_docker() {
        let args = parse_test(&["--no-docker", "bash"]).unwrap();
        assert_eq!(args.docker, Some(false));
    }

    #[test]
    fn parse_docker() {
        let args = parse_test(&["--docker", "bash"]).unwrap();
        assert_eq!(args.docker, Some(true));
    }

    #[test]
    fn parse_no_tailscale() {
        let args = parse_test(&["--no-tailscale", "bash"]).unwrap();
        assert_eq!(args.tailscale, Some(false));
    }

    #[test]
    fn parse_tailscale() {
        let args = parse_test(&["--tailscale", "bash"]).unwrap();
        assert_eq!(args.tailscale, Some(true));
    }

    #[test]
    fn parse_no_display() {
        let args = parse_test(&["--no-display", "bash"]).unwrap();
        assert_eq!(args.display, Some(false));
    }

    #[test]
    fn parse_display() {
        let args = parse_test(&["--display", "bash"]).unwrap();
        assert_eq!(args.display, Some(true));
    }

    #[test]
    fn parse_audio() {
        let args = parse_test(&["--audio", "bash"]).unwrap();
        assert_eq!(args.audio, Some(true));
    }

    #[test]
    fn parse_no_audio() {
        let args = parse_test(&["--no-audio", "bash"]).unwrap();
        assert_eq!(args.audio, Some(false));
    }

    #[test]
    fn parse_prompt_hosts() {
        assert_eq!(parse_test(&["bash"]).unwrap().prompt_hosts, None);
        let args = parse_test(&["--prompt-hosts", "bash"]).unwrap();
        assert_eq!(args.prompt_hosts, Some(true));
        let args = parse_test(&["--no-prompt-hosts", "bash"]).unwrap();
        assert_eq!(args.prompt_hosts, Some(false));
    }

    #[test]
    fn parse_kvm() {
        let args = parse_test(&["--kvm", "bash"]).unwrap();
        assert_eq!(args.kvm, Some(true));
        let args = parse_test(&["--no-kvm", "bash"]).unwrap();
        assert_eq!(args.kvm, Some(false));
        let args = parse_test(&["--kvm", "--no-kvm", "bash"]).unwrap();
        assert_eq!(args.kvm, Some(false));
    }

    #[test]
    fn parse_audio_last_wins() {
        let args = parse_test(&["--audio", "--no-audio", "bash"]).unwrap();
        assert_eq!(args.audio, Some(false));
        let args = parse_test(&["--no-audio", "--audio", "bash"]).unwrap();
        assert_eq!(args.audio, Some(true));
    }

    #[test]
    fn parse_github() {
        let args = parse_test(&["--github", "bash"]).unwrap();
        assert_eq!(args.github, Some(true));
    }

    #[test]
    fn parse_no_github() {
        let args = parse_test(&["--no-github", "bash"]).unwrap();
        assert_eq!(args.github, Some(false));
    }

    #[test]
    fn parse_docker_config() {
        let args = parse_test(&["--docker-config", "bash"]).unwrap();
        assert_eq!(args.docker_config, Some(true));
    }

    #[test]
    fn parse_no_docker_config() {
        let args = parse_test(&["--no-docker-config", "bash"]).unwrap();
        assert_eq!(args.docker_config, Some(false));
    }

    #[test]
    fn parse_network_last_wins() {
        let args = parse_test(&["--network", "--no-network", "bash"]).unwrap();
        assert_eq!(args.network, Some(false));
    }

    #[test]
    fn parse_macos_host_ipc_last_wins() {
        let args =
            parse_test(&["--macos-host-ipc", "--no-macos-host-ipc", "bash"])
                .unwrap();
        assert_eq!(args.macos_host_ipc, Some(false));
    }

    #[test]
    fn parse_macos_chromium_last_wins() {
        let args =
            parse_test(&["--no-macos-chromium", "--macos-chromium", "bash"])
                .unwrap();
        assert_eq!(args.macos_chromium, Some(true));
    }

    #[test]
    fn parse_macos_trustd_last_wins() {
        let args = parse_test(&["--no-macos-trustd", "--macos-trustd", "bash"])
            .unwrap();
        assert_eq!(args.macos_trustd, Some(true));
        let args = parse_test(&["--macos-trustd", "--no-macos-trustd", "bash"])
            .unwrap();
        assert_eq!(args.macos_trustd, Some(false));
    }

    #[test]
    fn parse_macos_pasteboard_last_wins() {
        let args = parse_test(&[
            "--no-macos-pasteboard",
            "--macos-pasteboard",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.macos_pasteboard, Some(true));
        let args = parse_test(&[
            "--macos-pasteboard",
            "--no-macos-pasteboard",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.macos_pasteboard, Some(false));
    }

    #[test]
    fn parse_allow_pty_last_wins() {
        let args =
            parse_test(&["--no-allow-pty", "--allow-pty", "bash"]).unwrap();
        assert_eq!(args.allow_pty, Some(true));
        let args =
            parse_test(&["--allow-pty", "--no-allow-pty", "bash"]).unwrap();
        assert_eq!(args.allow_pty, Some(false));
    }

    #[test]
    fn parse_allow_loopback_listen_last_wins() {
        let args = parse_test(&[
            "--no-allow-loopback-listen",
            "--allow-loopback-listen",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_loopback_listen, Some(true));
        let args = parse_test(&[
            "--allow-loopback-listen",
            "--no-allow-loopback-listen",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_loopback_listen, Some(false));
    }

    #[test]
    fn parse_allow_loopback_connect_last_wins() {
        let args = parse_test(&[
            "--no-allow-loopback-connect",
            "--allow-loopback-connect",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_loopback_connect, Some(true));
        let args = parse_test(&[
            "--allow-loopback-connect",
            "--no-allow-loopback-connect",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_loopback_connect, Some(false));
    }

    #[test]
    fn sandbox_flag_with_value_after_command_is_rejected() {
        let error = parse_test(&["claude", "--browser=soft"]).unwrap_err();
        assert!(error.contains("flag --browser=soft after command"));
        let error =
            parse_test(&["claude", "--allow-tcp-port=443"]).unwrap_err();
        assert!(error.contains("flag --allow-tcp-port=443 after command"));
    }

    #[test]
    fn parse_x11() {
        let args = parse_test(&["--x11", "--no-x11", "bash"]).unwrap();
        assert_eq!(args.x11, Some(false));
    }

    #[test]
    fn parse_host_shm() {
        let args = parse_test(&["--host-shm", "bash"]).unwrap();
        assert_eq!(args.host_shm, Some(true));
    }

    #[test]
    fn parse_terminal_passthrough() {
        let args = parse_test(&[
            "--terminal-passthrough",
            "--no-terminal-passthrough",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.terminal_passthrough, Some(false));
    }

    #[test]
    fn parse_terminal_appearance_and_help() {
        assert!(
            HELP.contains("--terminal-appearance / --no-terminal-appearance")
        );
        let args = parse_test(&["--terminal-appearance", "bash"]).unwrap();
        assert_eq!(args.terminal_appearance, Some(true));
        let args = parse_test(&[
            "--terminal-appearance",
            "--no-terminal-appearance",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.terminal_appearance, Some(false));
        for flag in ["--terminal-appearance", "--no-terminal-appearance"] {
            let error = parse_test(&["claude", flag]).unwrap_err();
            assert!(error.contains("after command"), "{error}");
        }
    }

    #[test]
    fn sandbox_flag_after_command_is_rejected() {
        let error = parse_test(&["claude", "--private-home"]).unwrap_err();
        assert!(error.contains("flag --private-home after command"));
    }

    #[test]
    fn unknown_child_flag_after_command_is_preserved() {
        let args = parse_test(&["claude", "--foo"]).unwrap();
        assert_eq!(args.command, vec!["claude", "--foo"]);
    }

    #[test]
    fn child_flags_after_separator_are_forwarded_not_rejected() {
        // Regression: the guard scanned past `--` and rejected child flags
        // whose names collide with ai-jail's own (issue: the `--` flag-guard
        // bug). After a `--`, everything is the command + args, verbatim; the
        // `--` is not forwarded to the child.
        let args =
            parse_test(&["--network", "--", "/bin/true", "--env", "X=1"])
                .unwrap();
        assert_eq!(args.network, Some(true));
        assert_eq!(args.command, ["/bin/true", "--env", "X=1"]);

        // Several colliding flags, all forwarded verbatim.
        let args = parse_test(&[
            "--",
            "run",
            "--env",
            "X=1",
            "--network",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(
            args.command,
            ["run", "--env", "X=1", "--network", "--verbose"]
        );
        // The sandbox's own flags were NOT set by the child's copies.
        assert_eq!(args.network, None);
        assert!(!args.verbose);
    }

    #[test]
    fn sandbox_flag_after_bare_command_without_separator_still_errors() {
        // The ambiguous no-`--` case must keep erroring.
        let err = parse_test(&["claude", "--network"]).unwrap_err();
        assert!(err.contains("after command"), "{err}");
    }

    #[test]
    fn parse_toolchains() {
        assert_eq!(
            parse_test(&["--no-toolchains", "bash"]).unwrap().toolchains,
            Some(false)
        );
        assert_eq!(
            parse_test(&["--toolchains", "bash"]).unwrap().toolchains,
            Some(true)
        );
        // Forwarded verbatim as a child flag after `--`.
        let args = parse_test(&["--", "bash", "--toolchains"]).unwrap();
        assert_eq!(args.toolchains, None);
        assert_eq!(args.command, ["bash", "--toolchains"]);
    }

    #[test]
    fn parse_no_mise() {
        let args = parse_test(&["--no-mise", "bash"]).unwrap();
        assert_eq!(args.mise, Some(false));
    }

    #[test]
    fn parse_worktree() {
        let args = parse_test(&["--worktree", "bash"]).unwrap();
        assert_eq!(args.worktree, Some(true));
    }

    #[test]
    fn parse_no_worktree() {
        let args = parse_test(&["--no-worktree", "bash"]).unwrap();
        assert_eq!(args.worktree, Some(false));
    }

    #[test]
    fn parse_mise() {
        let args = parse_test(&["--mise", "bash"]).unwrap();
        assert_eq!(args.mise, Some(true));
    }

    #[test]
    fn parse_ssh() {
        let args = parse_test(&["--ssh", "bash"]).unwrap();
        assert_eq!(args.ssh, Some(true));
    }

    #[test]
    fn parse_no_ssh() {
        let args = parse_test(&["--no-ssh", "bash"]).unwrap();
        assert_eq!(args.ssh, Some(false));
    }

    #[test]
    fn parse_pictures() {
        let args = parse_test(&["--pictures", "bash"]).unwrap();
        assert_eq!(args.pictures, Some(true));
    }

    #[test]
    fn parse_no_pictures() {
        let args = parse_test(&["--no-pictures", "bash"]).unwrap();
        assert_eq!(args.pictures, Some(false));
    }

    #[test]
    fn parse_browser_default_hard() {
        let args = parse_test(&["--browser", "chromium"]).unwrap();
        assert_eq!(args.browser_profile.as_deref(), Some("hard"));
        assert_eq!(args.command, vec!["chromium"]);
    }

    #[test]
    fn parse_browser_soft() {
        let args = parse_test(&["--browser=soft", "firefox"]).unwrap();
        assert_eq!(args.browser_profile.as_deref(), Some("soft"));
        assert_eq!(args.command, vec!["firefox"]);
    }

    #[test]
    fn parse_no_browser() {
        let args = parse_test(&["--no-browser", "chromium"]).unwrap();
        assert_eq!(args.browser_profile.as_deref(), Some("off"));
    }

    #[test]
    fn parse_browser_invalid_errors() {
        let result = parse_test(&["--browser=maybe", "chromium"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_save_config() {
        let args = parse_test(&["--save-config", "bash"]).unwrap();
        assert_eq!(args.save_config, Some(true));
    }

    #[test]
    fn parse_no_save_config() {
        let args = parse_test(&["--no-save-config", "bash"]).unwrap();
        assert_eq!(args.save_config, Some(false));
    }

    #[test]
    fn parse_hide_config() {
        let args = parse_test(&["--hide-config", "bash"]).unwrap();
        assert_eq!(args.hide_config, Some(true));
    }

    #[test]
    fn parse_no_hide_config() {
        let args = parse_test(&["--no-hide-config", "bash"]).unwrap();
        assert_eq!(args.hide_config, Some(false));
    }

    // ── Map flags ──────────────────────────────────────────────

    #[test]
    fn parse_mask_single() {
        let args = parse_test(&["--mask", ".env", "bash"]).unwrap();
        assert_eq!(args.mask, vec![PathBuf::from(".env")]);
    }

    #[test]
    fn parse_mask_multiple() {
        let args =
            parse_test(&["--mask", ".env", "--mask", ".env.local", "bash"])
                .unwrap();
        assert_eq!(
            args.mask,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn parse_mask_empty_errors() {
        let result = parse_test(&["--mask", "", "bash"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_mask_missing_value_errors() {
        let result = parse_test(&["--mask"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_deny_path_single() {
        let args = parse_test(&["--deny-path", ".env", "bash"]).unwrap();
        assert_eq!(args.deny_paths, vec![PathBuf::from(".env")]);
    }

    #[test]
    fn parse_deny_path_multiple() {
        let args = parse_test(&[
            "--deny-path",
            ".env",
            "--deny-path",
            "secrets/*.json",
            "bash",
        ])
        .unwrap();
        assert_eq!(
            args.deny_paths,
            vec![PathBuf::from(".env"), PathBuf::from("secrets/*.json")]
        );
    }

    #[test]
    fn parse_mask_and_deny_path_exceptions() {
        let args = parse_test(&[
            "--mask-except",
            "**/target/**",
            "--deny-path-except",
            "public.key",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.mask_exceptions, vec![PathBuf::from("**/target/**")]);
        assert_eq!(
            args.deny_path_exceptions,
            vec![PathBuf::from("public.key")]
        );
    }

    #[test]
    fn parse_exception_empty_and_missing_values_error() {
        assert!(parse_test(&["--mask-except", "", "bash"]).is_err());
        assert!(parse_test(&["--deny-path-except", "", "bash"]).is_err());
        assert!(parse_test(&["--mask-except"]).is_err());
        assert!(parse_test(&["--deny-path-except"]).is_err());
    }

    #[test]
    fn help_describes_explicit_exceptions() {
        assert!(HELP.contains("--mask-except <PATH|GLOB>"));
        assert!(HELP.contains("weakens protection"));
        assert!(HELP.contains("no ! negation"));
    }

    #[test]
    fn parse_deny_path_empty_errors() {
        let result = parse_test(&["--deny-path", "", "bash"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_deny_path_missing_value_errors() {
        let result = parse_test(&["--deny-path"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rw_map() {
        let args = parse_test(&["--rw-map", "/tmp/test", "bash"]).unwrap();
        assert_eq!(args.rw_maps, vec![PathBuf::from("/tmp/test")]);
    }

    #[test]
    fn parse_overlay_map() {
        let args = parse_test(&[
            "--overlay-map",
            "/home/u/.claude",
            "--overlay-map",
            "/home/u/.config/foo",
            "bash",
        ])
        .unwrap();
        assert_eq!(
            args.overlay_maps,
            vec![
                PathBuf::from("/home/u/.claude"),
                PathBuf::from("/home/u/.config/foo"),
            ]
        );
    }

    #[test]
    fn parse_ro_map() {
        let args = parse_test(&["--map", "/opt/data", "bash"]).unwrap();
        assert_eq!(args.ro_maps, vec![PathBuf::from("/opt/data")]);
    }

    #[test]
    fn parse_ro_map_alias_matches_map() {
        // --ro-map is a back-compat alias for --map; it is in the sandbox
        // flag guard, so it must parse into ro_maps instead of erroring.
        let args = parse_test(&["--ro-map", "/opt/data", "bash"]).unwrap();
        assert_eq!(args.ro_maps, vec![PathBuf::from("/opt/data")]);
    }

    #[test]
    fn parse_maps_with_alternate_destinations() {
        let args = parse_test(&[
            "--map",
            "~/.ssh/ai-jail:~/.ssh",
            "--rw-map",
            "data:vendor/data",
            "bash",
        ])
        .unwrap();

        assert_eq!(args.ro_maps, vec![PathBuf::from("~/.ssh/ai-jail:~/.ssh")]);
        assert_eq!(args.rw_maps, vec![PathBuf::from("data:vendor/data")]);
    }

    #[test]
    fn parse_multiple_maps() {
        let args = parse_test(&[
            "--rw-map", "/tmp/a", "--rw-map", "/tmp/b", "--map", "/opt/c",
            "bash",
        ])
        .unwrap();
        assert_eq!(
            args.rw_maps,
            vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
        );
        assert_eq!(args.ro_maps, vec![PathBuf::from("/opt/c")]);
    }

    // ── Hide dotdir tests ────────────────────────────────────────

    #[test]
    fn parse_hide_dotdir() {
        let args =
            parse_test(&["--hide-dotdir", ".my_secrets", "bash"]).unwrap();
        assert_eq!(args.hide_dotdirs, vec![".my_secrets"]);
    }

    #[test]
    fn parse_multiple_hide_dotdirs() {
        let args = parse_test(&[
            "--hide-dotdir",
            ".my_secrets",
            "--hide-dotdir",
            ".proton",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.hide_dotdirs, vec![".my_secrets", ".proton"]);
    }

    #[test]
    fn parse_hide_dotdir_with_maps() {
        let args = parse_test(&[
            "--hide-dotdir",
            ".aws",
            "--rw-map",
            "/tmp/test",
            "--map",
            "/opt/data",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.hide_dotdirs, vec![".aws"]);
        assert_eq!(args.rw_maps, vec![PathBuf::from("/tmp/test")]);
        assert_eq!(args.ro_maps, vec![PathBuf::from("/opt/data")]);
    }

    #[test]
    fn parse_hide_dotdir_normalizes_no_dot() {
        let args =
            parse_test(&["--hide-dotdir", "my_secrets", "bash"]).unwrap();
        assert_eq!(args.hide_dotdirs, vec![".my_secrets"]);
    }

    #[test]
    fn parse_hide_dotdir_keeps_existing_dot() {
        let args =
            parse_test(&["--hide-dotdir", ".my_secrets", "bash"]).unwrap();
        assert_eq!(args.hide_dotdirs, vec![".my_secrets"]);
    }

    #[test]
    fn parse_hide_dotdir_empty_errors() {
        let result = parse_test(&["--hide-dotdir", "", "bash"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-empty"));
    }

    // ── Combined flags ─────────────────────────────────────────

    #[test]
    fn parse_multiple_flags_combined() {
        let args = parse_test(&[
            "--dry-run",
            "--verbose",
            "--no-gpu",
            "--no-docker",
            "--worktree",
            "--rw-map",
            "/tmp/test",
            "claude",
        ])
        .unwrap();
        assert!(args.dry_run);
        assert!(args.verbose);
        assert_eq!(args.gpu, Some(false));
        assert_eq!(args.docker, Some(false));
        assert_eq!(args.worktree, Some(true));
        assert_eq!(args.rw_maps, vec![PathBuf::from("/tmp/test")]);
        assert_eq!(args.command, vec!["claude"]);
    }

    #[test]
    fn parse_init_clean_together() {
        let args = parse_test(&["--clean", "--init", "bash"]).unwrap();
        assert!(args.clean);
        assert!(args.init);
        assert_eq!(args.command, vec!["bash"]);
    }

    // ── Error cases ────────────────────────────────────────────

    #[test]
    fn parse_bootstrap() {
        let args = parse_test(&["--bootstrap"]).unwrap();
        assert!(args.bootstrap);
        assert!(args.command.is_empty());
    }

    #[test]
    fn parse_bootstrap_with_verbose() {
        let args = parse_test(&["--bootstrap", "-v"]).unwrap();
        assert!(args.bootstrap);
        assert!(args.verbose);
    }

    // ── Error cases ────────────────────────────────────────────

    #[test]
    fn parse_unknown_flag_errors() {
        let result = parse_test(&["--unknown-flag"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_short_flag_errors() {
        let result = parse_test(&["-z"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rw_map_missing_value_errors() {
        let result = parse_test(&["--rw-map"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_hide_dotdir_missing_value_errors() {
        let result = parse_test(&["--hide-dotdir"]);
        assert!(result.is_err());
    }

    // ── Internal flags ─────────────────────────────────────────

    #[test]
    fn parse_landlock_exec() {
        let args =
            parse_test(&["--landlock-exec", "--", "claude", "--continue"])
                .unwrap();
        assert!(args.landlock_exec);
        assert_eq!(args.command, vec!["claude", "--continue"]);
    }

    #[test]
    fn parse_landlock_exec_with_lockdown() {
        let args = parse_test(&[
            "--landlock-exec",
            "--lockdown",
            "--verbose",
            "--",
            "bash",
        ])
        .unwrap();
        assert!(args.landlock_exec);
        assert_eq!(args.lockdown, Some(true));
        assert!(args.verbose);
        assert_eq!(args.command, vec!["bash"]);
    }

    #[test]
    fn parse_internal_landlock_paths_are_opaque() {
        let rw = PathBuf::from("/jail/name:/etc");
        let ro = PathBuf::from("/jail/ro:name");
        let args = parse_test(&[
            "--landlock-exec",
            "--landlock-rw-path",
            rw.to_str().unwrap(),
            "--landlock-ro-path",
            ro.to_str().unwrap(),
            "--",
            "bash",
        ])
        .unwrap();

        assert_eq!(args.landlock_rw_paths, vec![rw]);
        assert_eq!(args.landlock_ro_paths, vec![ro]);
        assert!(!HELP.contains("--landlock-rw-path"));
        assert!(!HELP.contains("--landlock-ro-path"));
    }

    #[test]
    fn parse_internal_landlock_paths_rejected_without_exec() {
        let result =
            parse_test(&["--landlock-rw-path", "/jail/rw", "--", "bash"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("internal"));
    }

    // ── Exec mode ──────────────────────────────────────────────

    #[test]
    fn parse_exec_simple() {
        let args = parse_test(&["--exec", "my-script.sh"]).unwrap();
        assert!(args.exec);
        assert_eq!(args.status_bar, Some(false));
        assert_eq!(args.command, vec!["my-script.sh"]);
    }

    #[test]
    fn parse_exec_with_args() {
        let args = parse_test(&[
            "--exec",
            "--",
            "my-script.sh",
            "--flag",
            "-o",
            "out",
        ])
        .unwrap();
        assert!(args.exec);
        assert_eq!(args.command, vec!["my-script.sh", "--flag", "-o", "out"]);
    }

    #[test]
    fn parse_exec_with_sandbox_flags() {
        let args = parse_test(&["--lockdown", "--exec", "--", "cargo", "test"])
            .unwrap();
        assert!(args.exec);
        assert_eq!(args.lockdown, Some(true));
        assert_eq!(args.command, vec!["cargo", "test"]);
    }

    // ── Dash-dash separator ────────────────────────────────────

    #[test]
    fn parse_dashdash_passes_remaining_as_command() {
        let args =
            parse_test(&["--dry-run", "--", "my-tool", "--some-flag"]).unwrap();
        assert!(args.dry_run);
        assert_eq!(args.command, vec!["my-tool", "--some-flag"]);
    }

    // ── Last-wins behavior for toggles ─────────────────────────

    #[test]
    fn parse_status_bar() {
        let args = parse_test(&["--status-bar", "bash"]).unwrap();
        assert_eq!(args.status_bar, None);
        assert_eq!(args.status_bar_style.as_deref(), Some("pastel"));
    }

    #[test]
    fn parse_no_status_bar() {
        let args = parse_test(&["--no-status-bar", "bash"]).unwrap();
        assert_eq!(args.status_bar, Some(false));
    }

    #[test]
    fn parse_status_bar_short() {
        let args = parse_test(&["-s", "bash"]).unwrap();
        assert_eq!(args.status_bar, None);
        assert_eq!(args.status_bar_style.as_deref(), Some("pastel"));
    }

    #[test]
    fn parse_status_bar_eq_light() {
        let args = parse_test(&["--status-bar=light", "bash"]).unwrap();
        assert_eq!(args.status_bar, None);
        assert_eq!(args.status_bar_style.as_deref(), Some("light"));
    }

    #[test]
    fn parse_status_bar_eq_dark() {
        let args = parse_test(&["--status-bar=dark", "bash"]).unwrap();
        assert_eq!(args.status_bar, None);
        assert_eq!(args.status_bar_style.as_deref(), Some("dark"));
    }

    #[test]
    fn parse_status_bar_eq_invalid() {
        let result = parse_test(&["--status-bar=neon", "bash"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_forward_port_repeatable() {
        let args = parse_test(&[
            "--forward-port",
            "49374",
            "--forward-port",
            "64342",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.forward_ports, vec![49374, 64342]);
        assert_eq!(args.command, vec!["bash"]);
    }

    #[test]
    fn forward_port_after_the_command_is_refused() {
        // It would otherwise reach the child as its own argument.
        assert!(parse_test(&["bash", "--forward-port", "49374"]).is_err());
        // After `--` it belongs to the child, as for every sandbox flag.
        assert!(parse_test(&["bash", "--", "--forward-port", "49374"]).is_ok());
    }

    #[test]
    fn parse_publish_port_repeatable() {
        let args = parse_test(&[
            "--publish-port",
            "4096",
            "--publish-port",
            "3000",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.publish_ports, vec![4096, 3000]);
        assert!(args.forward_ports.is_empty());
        assert_eq!(args.command, vec!["bash"]);
    }

    #[test]
    fn publish_port_after_the_command_is_refused() {
        assert!(parse_test(&["bash", "--publish-port", "4096"]).is_err());
        assert!(parse_test(&["bash", "--", "--publish-port", "4096"]).is_ok());
    }

    #[test]
    fn parse_publish_port_invalid() {
        assert!(parse_test(&["--publish-port", "70000", "bash"]).is_err());
        assert!(parse_test(&["--publish-port", "http", "bash"]).is_err());
        assert!(parse_test(&["--publish-port"]).is_err());
    }

    #[test]
    fn parse_forward_port_invalid() {
        assert!(parse_test(&["--forward-port", "70000", "bash"]).is_err());
        assert!(parse_test(&["--forward-port", "http", "bash"]).is_err());
        assert!(parse_test(&["--forward-port"]).is_err());
    }

    #[test]
    fn parse_allow_tcp_port_single() {
        let args =
            parse_test(&["--lockdown", "--allow-tcp-port", "32000", "bash"])
                .unwrap();
        assert_eq!(args.allow_tcp_ports, vec![32000]);
        assert_eq!(args.lockdown, Some(true));
    }

    #[test]
    fn parse_allow_tcp_port_multiple() {
        let args = parse_test(&[
            "--allow-tcp-port",
            "32000",
            "--allow-tcp-port",
            "8080",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_tcp_ports, vec![32000, 8080]);
    }

    #[test]
    fn parse_allow_tcp_port_boundary_values() {
        let args = parse_test(&[
            "--allow-tcp-port",
            "0",
            "--allow-tcp-port",
            "65535",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.allow_tcp_ports, vec![0, 65535]);
    }

    #[test]
    fn parse_allow_tcp_port_overflow() {
        assert!(parse_test(&["--allow-tcp-port", "65536"]).is_err());
    }

    #[test]
    fn parse_allow_tcp_port_invalid() {
        assert!(parse_test(&["--allow-tcp-port", "abc"]).is_err());
    }

    #[test]
    fn parse_allow_tcp_port_missing_value() {
        assert!(parse_test(&["--allow-tcp-port"]).is_err());
    }

    #[test]
    fn parse_allow_host_single() {
        let args = parse_test(&["--allow-host", "api.anthropic.com", "claude"])
            .unwrap();
        assert_eq!(args.allow_hosts, vec!["api.anthropic.com".to_string()]);
    }

    #[test]
    fn parse_allow_host_repeatable() {
        let args = parse_test(&[
            "--allow-host",
            "api.anthropic.com",
            "--allow-host=github.com",
            "claude",
        ])
        .unwrap();
        assert_eq!(
            args.allow_hosts,
            vec!["api.anthropic.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn parse_allow_host_missing_value() {
        assert!(parse_test(&["--allow-host"]).is_err());
    }

    #[test]
    fn parse_allow_host_after_command_rejected() {
        let error =
            parse_test(&["claude", "--allow-host=example.com"]).unwrap_err();
        assert!(error.contains("after command"));
    }

    #[test]
    fn parse_allow_private_host_repeatable_and_guarded() {
        let args = parse_test(&[
            "--allow-private-host",
            "gitlab.example.com",
            "--allow-private-host=registry.example.com",
            "bash",
        ])
        .unwrap();
        assert_eq!(
            args.allow_private_hosts,
            vec![
                "gitlab.example.com".to_string(),
                "registry.example.com".to_string()
            ]
        );
        assert!(parse_test(&["--allow-private-host"]).is_err());
        assert!(
            parse_test(&["bash", "--allow-private-host=gitlab.example.com"])
                .unwrap_err()
                .contains("after command")
        );
    }

    #[test]
    fn parse_proxy_bridge_internal_mode() {
        let args = parse_test(&[
            "--proxy-bridge",
            "15919",
            "/tmp/.ai-jail-proxy.sock",
        ])
        .unwrap();
        assert_eq!(
            args.proxy_bridge,
            Some((15919, PathBuf::from("/tmp/.ai-jail-proxy.sock")))
        );
        assert!(parse_test(&["--proxy-bridge", "nope", "/tmp/s"]).is_err());
        assert!(parse_test(&["--proxy-bridge", "15919"]).is_err());
    }

    #[test]
    fn parse_publish_bridge_internal_mode() {
        let args = parse_test(&[
            "--publish-bridge",
            "4096",
            "/tmp/.ai-jail-publish.4096.sock",
        ])
        .unwrap();
        assert_eq!(
            args.publish_bridge,
            Some((4096, PathBuf::from("/tmp/.ai-jail-publish.4096.sock")))
        );
        assert!(parse_test(&["--publish-bridge", "nope", "/tmp/s"]).is_err());
        assert!(parse_test(&["--publish-bridge", "4096"]).is_err());
    }

    #[test]
    fn parse_teardown_report_fd_requires_landlock_exec() {
        assert!(parse_test(&["--teardown-report-fd", "9"]).is_err());
        assert!(
            parse_test(&["--landlock-exec", "--teardown-report-fd", "x"])
                .is_err()
        );
        let args = parse_test(&[
            "--landlock-exec",
            "--teardown-report-fd",
            "9",
            "--",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.teardown_report_fd, Some(9));
        // Without the flag the wrapper keeps its exec path.
        let args = parse_test(&["--landlock-exec", "--", "bash"]).unwrap();
        assert_eq!(args.teardown_report_fd, None);
    }

    #[test]
    fn parse_teardown_report_flag() {
        let args = parse_test(&["--teardown-report", "bash"]).unwrap();
        assert!(args.teardown_report);
        assert!(!parse_test(&["bash"]).unwrap().teardown_report);
        // No `--no-` form: it is not a toggle.
        assert!(parse_test(&["--no-teardown-report", "bash"]).is_err());
        // A sandbox flag after the command is refused, like the others.
        let error = parse_test(&["bash", "--teardown-report"]).unwrap_err();
        assert!(error.contains("--teardown-report"), "{error}");
        // It takes no value.
        assert!(parse_test(&["--teardown-report=yes", "bash"]).is_err());
    }

    #[test]
    fn parse_proxy_bridge_port_requires_landlock_exec() {
        assert!(parse_test(&["--proxy-bridge-port", "15919"]).is_err());
        let args = parse_test(&[
            "--landlock-exec",
            "--proxy-bridge-port",
            "15919",
            "--",
            "bash",
        ])
        .unwrap();
        assert_eq!(args.proxy_bridge_port, Some(15919));
    }

    #[test]
    fn parse_audit_log_flag_pair() {
        let args = parse_test(&["--audit-log", "bash"]).unwrap();
        assert_eq!(args.audit_log, Some(true));
        let args = parse_test(&["--no-audit-log", "bash"]).unwrap();
        assert_eq!(args.audit_log, Some(false));
        let error = parse_test(&["claude", "--audit-log"]).unwrap_err();
        assert!(error.contains("after command"));
    }

    #[test]
    fn parse_audit_verify() {
        let args = parse_test(&["--audit-verify"]).unwrap();
        assert!(args.audit_verify);
        let error = parse_test(&["claude", "--audit-verify"]).unwrap_err();
        assert!(error.contains("after command"));
    }

    #[test]
    fn audit_show_preserves_positional_commands() {
        assert!(parse_test(&["--audit-show"]).unwrap().audit_show);
        for argv in [vec!["audit", "report"], vec!["--", "audit", "report"]] {
            let args = parse_test(&argv).unwrap();
            assert_eq!(args.command, ["audit", "report"]);
            assert!(!args.audit_show);
        }
        // `--audit-show` as or after a command positional is a child concern,
        // never the ai-jail action. The first `--` is the option terminator:
        // consumed, not forwarded to the child (so all three yield the same
        // command).
        for argv in [
            vec!["command", "--audit-show"],
            vec!["--", "command", "--audit-show"],
            vec!["command", "--", "--audit-show"],
        ] {
            let args = parse_test(&argv).unwrap();
            assert_eq!(
                args.command,
                ["command", "--audit-show"],
                "argv: {argv:?}"
            );
            assert!(!args.audit_show);
        }
    }

    #[test]
    fn audit_show_rejects_conflicting_actions() {
        for action in [
            "bash",
            "status",
            "--audit-verify",
            "--init",
            "--bootstrap",
            "--dry-run",
            "--landlock-exec",
        ] {
            let error = parse_test(&["--audit-show", action]).unwrap_err();
            assert!(error.contains("cannot be combined"), "{action}: {error}");
        }
        assert!(
            parse_test(&[
                "--audit-show",
                "--proxy-bridge",
                "8080",
                "/tmp/socket"
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_env_from_file_repeatable() {
        let args = parse_test(&[
            "--env-from-file",
            "/run/secrets/anthropic",
            "--env-from-file=/run/secrets/openai",
            "claude",
        ])
        .unwrap();
        assert_eq!(
            args.env_from_file,
            vec![
                PathBuf::from("/run/secrets/anthropic"),
                PathBuf::from("/run/secrets/openai"),
            ]
        );
    }

    #[test]
    fn parse_env_from_file_missing_value() {
        assert!(parse_test(&["--env-from-file"]).is_err());
    }

    #[test]
    fn parse_env_from_file_after_command_rejected() {
        let error =
            parse_test(&["claude", "--env-from-file=/tmp/keys"]).unwrap_err();
        assert!(error.contains("after command"));
    }

    #[test]
    fn parse_secret_repeatable_and_strict() {
        let args = parse_test(&[
            "--secret",
            "ANTHROPIC_API_KEY=api.anthropic.com",
            "--secret=OPENAI_API_KEY=api.openai.com",
            "claude",
        ])
        .unwrap();
        assert_eq!(
            args.secrets,
            vec![
                (
                    "ANTHROPIC_API_KEY".to_string(),
                    "api.anthropic.com".to_string()
                ),
                ("OPENAI_API_KEY".to_string(), "api.openai.com".to_string()),
            ]
        );
        for bad in ["KEY", "=example.com", "KEY="] {
            assert!(parse_test(&["--secret", bad]).is_err(), "{bad}");
        }
        assert!(parse_test(&["--secret"]).is_err());
        let error =
            parse_test(&["claude", "--secret", "K=example.com"]).unwrap_err();
        assert!(error.contains("after command"));
    }

    #[test]
    fn parse_claude_dir() {
        let args = parse_test(&[
            "--claude-dir",
            "/home/user/.claude-example",
            "claude",
        ])
        .unwrap();
        assert_eq!(
            args.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
        assert_eq!(args.command, vec!["claude"]);
    }

    #[test]
    fn parse_claude_dir_missing_value_errors() {
        assert!(parse_test(&["--claude-dir"]).is_err());
    }

    #[test]
    fn parse_last_wins_gpu() {
        let args = parse_test(&["--no-gpu", "--gpu", "bash"]).unwrap();
        assert_eq!(args.gpu, Some(true));
    }

    #[test]
    fn parse_last_wins_docker() {
        let args = parse_test(&["--docker", "--no-docker", "bash"]).unwrap();
        assert_eq!(args.docker, Some(false));
    }

    #[test]
    fn parse_last_wins_tailscale() {
        let args =
            parse_test(&["--tailscale", "--no-tailscale", "bash"]).unwrap();
        assert_eq!(args.tailscale, Some(false));
    }

    #[test]
    fn parse_last_wins_save_config_enabled() {
        let args =
            parse_test(&["--no-save-config", "--save-config", "bash"]).unwrap();
        assert_eq!(args.save_config, Some(true));
    }

    #[test]
    fn parse_last_wins_save_config_disabled() {
        let args =
            parse_test(&["--save-config", "--no-save-config", "bash"]).unwrap();
        assert_eq!(args.save_config, Some(false));
    }

    // ── Trusted capability flags (agent state / env / update) ──

    #[test]
    fn parse_agent_state_last_wins() {
        let args = parse_test(&["--agent-state", "bash"]).unwrap();
        assert_eq!(args.agent_state, Some(true));
        let args =
            parse_test(&["--agent-state", "--no-agent-state", "bash"]).unwrap();
        assert_eq!(args.agent_state, Some(false));
        let args =
            parse_test(&["--no-agent-state", "--agent-state", "bash"]).unwrap();
        assert_eq!(args.agent_state, Some(true));
    }

    #[test]
    fn parse_inherit_env_last_wins() {
        let args =
            parse_test(&["--inherit-env", "--no-inherit-env", "bash"]).unwrap();
        assert_eq!(args.inherit_env, Some(false));
        let args =
            parse_test(&["--no-inherit-env", "--inherit-env", "bash"]).unwrap();
        assert_eq!(args.inherit_env, Some(true));
    }

    #[test]
    fn parse_update_check_last_wins() {
        let args = parse_test(&["--update-check", "--no-update-check", "bash"])
            .unwrap();
        assert_eq!(args.update_check, Some(false));
        let args = parse_test(&["--no-update-check", "--update-check", "bash"])
            .unwrap();
        assert_eq!(args.update_check, Some(true));
    }

    #[test]
    fn parse_env_flag_repeatable_with_name_and_assignment() {
        let args = parse_test(&[
            "--env",
            "ANTHROPIC_API_KEY",
            "--env",
            "CUSTOM=value",
            "bash",
        ])
        .unwrap();
        assert_eq!(
            args.env,
            vec!["ANTHROPIC_API_KEY".to_string(), "CUSTOM=value".to_string()]
        );
    }

    #[test]
    fn parse_env_flag_rejects_empty_name() {
        assert!(parse_test(&["--env", "", "bash"]).is_err());
        assert!(parse_test(&["--env", "=value", "bash"]).is_err());
        assert!(parse_test(&["--env"]).is_err());
    }

    #[test]
    fn env_flag_after_command_is_rejected() {
        let error = parse_test(&["claude", "--env", "SECRET"]).unwrap_err();
        assert!(error.contains("flag --env after command"));
    }

    #[test]
    fn parses_wrapper_contract_flags_before_separator() {
        let args = parse_test(&[
            "--harness",
            "claude",
            "--harness",
            "codex",
            "--request-file",
            "/tmp/requests.json",
            "--request",
            "env=AI_MEMORY_SERVER_URL",
            "--",
            "ai-memory",
            "run",
            "--some-future-flag",
            "x",
            "claude",
        ])
        .unwrap();
        assert_eq!(args.harnesses, vec!["claude", "codex"]);
        assert_eq!(
            args.request_files,
            vec![PathBuf::from("/tmp/requests.json")]
        );
        assert_eq!(args.requests, vec!["env=AI_MEMORY_SERVER_URL"]);
        assert_eq!(args.command.first().map(String::as_str), Some("ai-memory"));
    }

    #[test]
    fn configure_accepts_harness_and_request_file_options() {
        let args = parse_test(&[
            "configure",
            "--harness",
            "claude",
            "--request-file",
            "/tmp/requests.json",
        ])
        .unwrap();
        assert_eq!(args.configure.as_deref(), Some("claude"));
        assert_eq!(args.harnesses, vec!["claude"]);
        assert_eq!(
            args.request_files,
            vec![PathBuf::from("/tmp/requests.json")]
        );
    }

    #[test]
    fn parses_machine_readable_status_and_capabilities() {
        let status =
            parse_test(&["status", "--json", "--harness", "claude"]).unwrap();
        assert!(status.status && status.json);
        assert_eq!(status.harnesses, vec!["claude"]);
        let capabilities = parse_test(&["capabilities", "--json"]).unwrap();
        assert!(capabilities.capabilities && capabilities.json);
    }
}

// The interface-synchronization contract for `--profile`. The documents
// name it an advanced CLI/config-only control: the user guide as a
// "named profile (`[profiles.NAME]`)", kept apart from the onboarding
// access profile; the TUI design with the reason it has no onboarding
// control; the onboarding provenance with an entry in its existing
// shape. And a drift test: every `Config` field and every
// `SANDBOX_LONG_FLAGS` entry appears in `docs/USER_GUIDE.md` as a whole
// token, or is allowlisted. The allowlist has two parts: fields that are
// internal, and the names already undocumented at f0dc67e (v3.5.0 plus
// #247), so the test is a ratchet — nothing new may land undocumented, and a name
// leaves the baseline once the guide documents it.
#[cfg(test)]
mod interface_profile_tests {
    use super::SANDBOX_LONG_FLAGS;

    const GUIDE: &str = include_str!("../docs/USER_GUIDE.md");
    const TUI_DESIGN: &str = include_str!("../docs/TUI_DESIGN.md");
    const PROVENANCE: &str = include_str!("../docs/onboarding-provenance.toml");
    const CONFIG_RS: &str = include_str!("config.rs");

    /// `Config` fields that no user sets: runtime state, never parsed.
    const INTERNAL_FIELDS: &[&str] = &["runtime_harnesses"];

    /// `Config` fields already missing from the guide at f0dc67e.
    const UNDOCUMENTED_FIELDS_AT_F0DC67E: &str = r"
    rw_maps overlay_maps hide_dotdirs mask deny_paths mask_exceptions
    deny_path_exceptions no_gpu no_docker tailscale no_display audio
    aws kube gcloud docker_config kvm prompt_hosts macos_host_ipc
    macos_chromium macos_trustd macos_pasteboard allow_pty
    allow_loopback_listen terminal_appearance
    allow_loopback_connect x11 host_shm terminal_passthrough
    no_worktree no_mise no_toolchains no_save_config no_hide_config
    pictures browser_profile private_home no_landlock no_status_bar
    status_bar_style resize_redraw_key no_seccomp no_rlimits
    systemd_user allow_tcp_ports allow_hosts allow_private_hosts
    forward_ports publish_ports claude_dir inherit_env env_pass
    env_from_file secret_hosts trust_project_config update_check
    audit_log
";

    /// Sandbox long flags already missing from the guide at f0dc67e.
    const UNDOCUMENTED_FLAGS_AT_F0DC67E: &str = r"
    --harness --request-file --request --private-home
    --no-private-home --no-lockdown --no-display --display
    --audio --no-audio --no-github --aws --no-aws --kube --no-kube
    --gcloud --no-gcloud --docker-config --no-docker-config --kvm
    --no-kvm --prompt-hosts --no-prompt-hosts --network --no-network
    --macos-host-ipc --no-macos-host-ipc --macos-chromium
    --no-macos-chromium --macos-trustd --no-macos-trustd
    --macos-pasteboard --no-macos-pasteboard --allow-pty
    --no-allow-pty --allow-loopback-listen --no-allow-loopback-listen
    --allow-loopback-connect --no-allow-loopback-connect --no-gpu
    --gpu --no-docker --docker --tailscale --no-tailscale --landlock
    --no-landlock --seccomp --no-seccomp --rlimits --no-rlimits --ssh
    --no-ssh --pictures --no-pictures --clean   --dry-run
    --rw-map --ro-map --overlay-map --map --mask --deny-path
    --mask-except --deny-path-except --hide-dotdir --allow-tcp-port
    --allow-private-host --systemd-user --no-systemd-user
    --worktree --no-worktree --browser --no-browser --claude-dir --x11
    --no-x11 --host-shm --no-host-shm --terminal-passthrough
    --no-terminal-passthrough --agent-state --no-agent-state
    --publish-port --inherit-env --no-inherit-env --update-check
    --no-update-check --audit-log --no-audit-log --audit-verify
    --env-from-file --secret --mise --no-mise --toolchains
    --no-toolchains --save-config --no-save-config --hide-config
    --no-hide-config --status-bar --no-status-bar --bootstrap
    --verbose
";

    /// A name counts as documented only as a whole token: the bytes on
    /// either side are not `[A-Za-z0-9_-]`, so `--map` inside `--ro-map`
    /// or `profile` inside `browser_profile` documents nothing.
    fn documented(name: &str, doc: &str) -> bool {
        let is_word =
            |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
        let bytes = doc.as_bytes();
        doc.match_indices(name).any(|(at, _)| {
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + name.len()).copied();
            !before.is_some_and(is_word) && !after.is_some_and(is_word)
        })
    }

    /// The names neither documented in `doc` nor allowlisted.
    fn undocumented<'a>(
        names: &[&'a str],
        doc: &str,
        allowed: &[&str],
    ) -> Vec<&'a str> {
        names
            .iter()
            .copied()
            .filter(|n| !allowed.contains(n) && !documented(n, doc))
            .collect()
    }

    /// The `pub` fields of `pub struct Config`, read from its source.
    fn config_fields() -> Vec<&'static str> {
        let body = CONFIG_RS
            .split_once("\npub struct Config {\n")
            .expect("pub struct Config in config.rs")
            .1
            .split_once("\n}\n")
            .expect("end of struct Config")
            .0;
        body.lines()
            .filter_map(|l| l.strip_prefix("    pub "))
            .filter_map(|l| l.split_once(':').map(|(n, _)| n))
            .map(|n| n.trim_start_matches("r#"))
            .collect()
    }

    #[test]
    fn drift_check_fires_for_a_name_that_appears_only_inside_another() {
        // A near-identical documented name must not
        // count for the undocumented one, in either direction.
        let guide = "Use `--ro-map PATH` and `browser_profile = \"soft\"`.";
        assert_eq!(undocumented(&["--map"], guide, &[]), ["--map"]);
        assert_eq!(undocumented(&["profile"], guide, &[]), ["profile"]);
        assert_eq!(undocumented(&["--ro"], guide, &[]), ["--ro"]);
        // A new field nobody wrote down fails ...
        assert_eq!(
            undocumented(&["brand_new_field"], guide, &[]),
            ["brand_new_field"]
        );
        // ... unless allowlisted, and a whole-token mention documents.
        assert!(
            undocumented(&["brand_new_field"], guide, &["brand_new_field"])
                .is_empty()
        );
        assert!(
            undocumented(&["--ro-map", "browser_profile"], guide, &[])
                .is_empty()
        );
        assert!(
            undocumented(&["--profile"], "`--profile NAME`", &[]).is_empty()
        );
    }

    #[test]
    fn every_config_field_and_sandbox_flag_is_in_the_user_guide() {
        let fields = config_fields();
        assert!(fields.contains(&"allow_hosts"), "field parse: {fields:?}");
        let baseline_fields: Vec<&str> =
            UNDOCUMENTED_FIELDS_AT_F0DC67E.split_whitespace().collect();
        let mut allowed_fields = INTERNAL_FIELDS.to_vec();
        allowed_fields.extend(&baseline_fields);
        let missing_fields = undocumented(&fields, GUIDE, &allowed_fields);
        let baseline_flags: Vec<&str> =
            UNDOCUMENTED_FLAGS_AT_F0DC67E.split_whitespace().collect();
        let missing_flags =
            undocumented(SANDBOX_LONG_FLAGS, GUIDE, &baseline_flags);
        assert!(
            missing_fields.is_empty() && missing_flags.is_empty(),
            "missing from docs/USER_GUIDE.md: fields {missing_fields:?}, \
             flags {missing_flags:?}"
        );
    }

    #[test]
    fn drift_baseline_holds_only_names_that_exist_and_are_undocumented() {
        // The ratchet only tightens: a name documented since, or removed,
        // must leave the baseline.
        let fields = config_fields();
        for name in UNDOCUMENTED_FIELDS_AT_F0DC67E.split_whitespace() {
            assert!(fields.contains(&name), "{name} is no longer a field");
            assert!(!documented(name, GUIDE), "{name} is documented now");
        }
        for name in UNDOCUMENTED_FLAGS_AT_F0DC67E.split_whitespace() {
            assert!(
                SANDBOX_LONG_FLAGS.contains(&name),
                "{name} is no longer a sandbox flag"
            );
            assert!(!documented(name, GUIDE), "{name} is documented now");
        }
    }

    #[test]
    fn user_guide_introduces_the_named_profile_apart_from_onboarding() {
        assert!(documented("--profile", GUIDE), "--profile not in the guide");
        assert!(GUIDE.contains("[profiles.NAME]"), "[profiles.NAME] missing");
        assert!(
            GUIDE.to_lowercase().contains("named profile"),
            "the guide must say \"named profile\" to keep it apart from \
             the onboarding access profile"
        );
    }

    #[test]
    fn tui_design_names_profile_cli_config_only_with_its_reason() {
        let paragraph = TUI_DESIGN
            .split("\n\n")
            .find(|p| documented("--profile", p))
            .expect("docs/TUI_DESIGN.md has no --profile entry");
        let lower = paragraph.to_lowercase();
        assert!(lower.contains("config-only"), "{paragraph}");
        assert!(lower.contains("onboarding"), "reason missing: {paragraph}");
    }

    #[test]
    fn onboarding_provenance_covers_the_profile_selection() {
        let doc: toml::Table = PROVENANCE.parse().expect("provenance TOML");
        let claims = doc["claim"].as_array().expect("[[claim]] entries");
        let claim = claims
            .iter()
            .find(|c| {
                let text = toml::to_string(c).unwrap_or_default();
                documented("--profile", &text)
                    || text.contains("select_profile")
                    || text.contains("[profiles")
            })
            .expect("no provenance claim for the profile selection");
        // The file's existing shape.
        for key in ["policy", "enforced_by", "verified_by", "guide_sections"] {
            assert!(claim.get(key).is_some(), "claim lacks {key}: {claim:?}");
        }
        for section in claim["guide_sections"].as_array().unwrap() {
            let heading = section.as_str().unwrap();
            assert!(
                GUIDE.lines().any(|l| {
                    l.trim_start_matches('#').trim() == heading
                        && l.starts_with('#')
                }),
                "guide section {heading:?} is not a heading in USER_GUIDE.md"
            );
        }
    }
}
