use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
ai-jail — sandbox for AI coding agents (bwrap on Linux, sandbox-exec on macOS)

USAGE:
    ai-jail [OPTIONS] [--] [COMMAND [ARGS...]]

COMMANDS (positional):
    claude, codex, opencode, crush, bash   Known AI tool presets
    status                                 Show current .ai-jail config
    Any other string                       Passed through as the command

OPTIONS:
    --rw-map <PATH>                Mount PATH read-write inside sandbox (repeatable)
    --map <PATH>                   Mount PATH read-only inside sandbox (repeatable)
    --hide-dotdir <NAME>           Never mount dotdir NAME (e.g., .my_secrets) (repeatable)
    --lockdown / --no-lockdown     Enable/disable strict read-only lockdown mode
    --landlock / --no-landlock     Enable/disable Landlock LSM (Linux 5.13+, default: on)
    --seccomp / --no-seccomp       Enable/disable seccomp syscall filter (Linux, default: on)
    --rlimits / --no-rlimits       Enable/disable resource limits (default: on)
    --no-gpu / --gpu               Disable/enable GPU device passthrough (Linux only)
    --no-docker / --docker         Disable/enable Docker socket passthrough
    --no-display / --display       Disable/enable X11/Wayland passthrough (Linux only)
    --no-mise / --mise             Disable/enable mise integration
    --save-config / --no-save-config
                                   Enable/disable automatic .ai-jail writes
    -s, --status-bar[=STYLE]       Set status line theme (dark | light | pastel; default dark)
                                   Pastel picks a random pastel palette per session
    --no-status-bar                Disable persistent status line
    --exec                         Direct execution mode (no PTY proxy, no status bar)
    --allow-tcp-port <PORT>        Allow outbound TCP to PORT in lockdown (repeatable)
    --clean                        Ignore existing .ai-jail config, start fresh
    --dry-run                      Print the sandbox command without executing
    --init                         Create/update .ai-jail config and exit
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
    pub hide_dotdirs: Vec<String>,
    pub lockdown: Option<bool>,
    pub landlock: Option<bool>,
    pub seccomp: Option<bool>,
    pub rlimits: Option<bool>,
    pub gpu: Option<bool>,
    pub docker: Option<bool>,
    pub display: Option<bool>,
    pub mise: Option<bool>,
    pub save_config: Option<bool>,
    pub status_bar: Option<bool>,
    pub status_bar_style: Option<String>,
    pub allow_tcp_ports: Vec<u16>,
    pub exec: bool,
    pub clean: bool,
    pub dry_run: bool,
    pub init: bool,
    pub bootstrap: bool,
    pub verbose: bool,
    pub status: bool,
    /// Internal: apply Landlock and exec remaining command.
    /// Used as a wrapper inside the bwrap sandbox.
    pub landlock_exec: bool,
}

pub fn parse() -> Result<CliArgs, String> {
    parse_from(lexopt::Parser::from_env())
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
            Long("map") => {
                let val: PathBuf =
                    parser.value().map_err(|e| e.to_string())?.into();
                args.ro_maps.push(val);
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
                    format!(".{}", s)
                };
                args.hide_dotdirs.push(normalized);
            }
            Long("lockdown") => args.lockdown = Some(true),
            Long("no-lockdown") => args.lockdown = Some(false),
            Long("landlock") => args.landlock = Some(true),
            Long("no-landlock") => args.landlock = Some(false),
            Long("seccomp") => args.seccomp = Some(true),
            Long("no-seccomp") => args.seccomp = Some(false),
            Long("rlimits") => args.rlimits = Some(true),
            Long("no-rlimits") => args.rlimits = Some(false),
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
            Long("gpu") => args.gpu = Some(true),
            Long("no-gpu") => args.gpu = Some(false),
            Long("docker") => args.docker = Some(true),
            Long("no-docker") => args.docker = Some(false),
            Long("display") => args.display = Some(true),
            Long("no-display") => args.display = Some(false),
            Long("mise") => args.mise = Some(true),
            Long("no-mise") => args.mise = Some(false),
            Long("save-config") => args.save_config = Some(true),
            Long("no-save-config") => args.save_config = Some(false),
            Long("status-bar") | Short('s') => {
                if let Some(val) = parser.optional_value() {
                    let s = val.to_string_lossy();
                    match s.as_ref() {
                        "dark" | "light" | "pastel" => {
                            args.status_bar_style = Some(s.into_owned())
                        }
                        _ => {
                            return Err(format!(
                                "invalid status bar style: \
                                 {s} (expected 'dark', 'light', or 'pastel')"
                            ));
                        }
                    }
                } else {
                    args.status_bar_style = Some("dark".into());
                }
            }
            Long("no-status-bar") => args.status_bar = Some(false),
            Long("exec") => {
                args.exec = true;
                args.status_bar = Some(false);
            }
            Long("landlock-exec") => args.landlock_exec = true,
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
                } else {
                    args.command.push(s);
                    // Consume ALL remaining args as part of the command
                    // (including --flags that belong to the sub-command)
                    for raw in parser.raw_args().map_err(|e| e.to_string())? {
                        args.command.push(raw.to_string_lossy().into_owned());
                    }
                }
            }
            Long(other) => return Err(format!("unknown option: --{other}")),
            Short(c) => return Err(format!("unknown option: -{c}")),
        }
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_test(args: &[&str]) -> Result<CliArgs, String> {
        let parser = lexopt::Parser::from_args(args);
        parse_from(parser)
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
    fn parse_status_command() {
        let args = parse_test(&["status"]).unwrap();
        assert!(args.status);
        assert!(args.command.is_empty());
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
    fn parse_no_lockdown() {
        let args = parse_test(&["--no-lockdown", "bash"]).unwrap();
        assert_eq!(args.lockdown, Some(false));
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
    fn parse_no_mise() {
        let args = parse_test(&["--no-mise", "bash"]).unwrap();
        assert_eq!(args.mise, Some(false));
    }

    #[test]
    fn parse_mise() {
        let args = parse_test(&["--mise", "bash"]).unwrap();
        assert_eq!(args.mise, Some(true));
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

    // ── Map flags ──────────────────────────────────────────────

    #[test]
    fn parse_rw_map() {
        let args = parse_test(&["--rw-map", "/tmp/test", "bash"]).unwrap();
        assert_eq!(args.rw_maps, vec![PathBuf::from("/tmp/test")]);
    }

    #[test]
    fn parse_ro_map() {
        let args = parse_test(&["--map", "/opt/data", "bash"]).unwrap();
        assert_eq!(args.ro_maps, vec![PathBuf::from("/opt/data")]);
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
            "--rw-map",
            "/tmp/test",
            "claude",
        ])
        .unwrap();
        assert!(args.dry_run);
        assert!(args.verbose);
        assert_eq!(args.gpu, Some(false));
        assert_eq!(args.docker, Some(false));
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
        assert_eq!(args.status_bar_style.as_deref(), Some("dark"));
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
        assert_eq!(args.status_bar_style.as_deref(), Some("dark"));
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
}
