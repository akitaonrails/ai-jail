use crate::config::Config;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
pub(crate) mod bwrap;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "macos")]
mod seatbelt;
#[cfg(target_os = "linux")]
mod seccomp;

pub(crate) mod rlimits;

#[cfg(target_os = "linux")]
pub use bwrap::SandboxGuard;
#[cfg(target_os = "macos")]
pub use seatbelt::SandboxGuard;

// Dotdirs never mounted (sensitive data)
const DOTDIR_DENY: &[&str] = &[
    ".gnupg",
    ".aws",
    ".ssh",
    ".mozilla",
    ".basilisk-dev",
    ".sparrow",
];

// Dotdirs requiring read-write access
const DOTDIR_RW: &[&str] = &[
    ".claude",
    ".crush",
    ".codex",
    ".aider",
    ".config",
    ".cargo",
    ".cache",
    ".docker",
    ".bundle",
    ".gem",
    ".rustup",
    ".npm",
    ".bun",
    ".deno",
    ".yarn",
    ".pnpm",
    ".m2",
    ".gradle",
    ".dotnet",
    ".nuget",
    ".pub-cache",
    ".mix",
    ".hex",
];

#[derive(Debug, Clone)]
pub struct LaunchCommand {
    pub program: String,
    pub args: Vec<String>,
}

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

fn path_exists(p: &Path) -> bool {
    p.exists() || p.symlink_metadata().is_ok()
}

fn mise_bin() -> Option<PathBuf> {
    std::env::var("PATH").ok().and_then(|paths| {
        paths.split(':').find_map(|dir| {
            let p = PathBuf::from(dir).join("mise");
            if p.is_file() {
                Some(p)
            } else {
                None
            }
        })
    })
}

fn default_launch_command(config: &Config) -> LaunchCommand {
    if config.command.is_empty() {
        return LaunchCommand {
            program: "bash".into(),
            args: vec![],
        };
    }

    let mut iter = config.command.iter();
    let program = iter.next().cloned().unwrap_or_else(|| "bash".to_string());
    let args = iter.cloned().collect::<Vec<_>>();
    LaunchCommand { program, args }
}

fn mise_wrapper_command(
    mise_path: &Path,
    user_cmd: LaunchCommand,
) -> LaunchCommand {
    // Command argv is passed via "$@" to avoid shell interpretation of user arguments.
    let script = "MISE=\"$1\"; shift; \"$MISE\" trust && eval \"$($MISE activate bash)\" && eval \"$($MISE env)\" && exec \"$@\"";
    let mut args = vec![
        "-lc".into(),
        script.into(),
        "ai-jail-mise".into(),
        mise_path.display().to_string(),
        user_cmd.program,
    ];
    args.extend(user_cmd.args);

    LaunchCommand {
        program: "bash".into(),
        args,
    }
}

pub fn build_launch_command(config: &Config) -> LaunchCommand {
    let user_cmd = default_launch_command(config);
    if config.lockdown_enabled() || !config.mise_enabled() {
        return user_cmd;
    }

    if let Some(mise) = mise_bin() {
        return mise_wrapper_command(&mise, user_cmd);
    }

    user_cmd
}

pub fn apply_landlock(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        landlock::apply(config, project_dir, verbose)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, project_dir, verbose);
        Ok(())
    }
}

pub fn apply_seccomp(config: &Config, verbose: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        seccomp::apply(config, verbose)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, verbose);
        Ok(())
    }
}

pub fn check() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        bwrap::check()
    }
    #[cfg(target_os = "macos")]
    {
        seatbelt::check()
    }
}

pub fn prepare() -> Result<SandboxGuard, String> {
    #[cfg(target_os = "linux")]
    {
        bwrap::prepare()
    }
    #[cfg(target_os = "macos")]
    {
        Ok(seatbelt::SandboxGuard)
    }
}

pub fn platform_notes(config: &Config) {
    if config.lockdown_enabled() {
        crate::output::info("Lockdown mode enabled: read-only project, no host write mounts, no mise.");
    }
    #[cfg(target_os = "macos")]
    {
        seatbelt::platform_notes(config);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = config;
    }
}

pub fn build(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<Command, String> {
    #[cfg(target_os = "linux")]
    {
        bwrap::build(guard, config, project_dir, verbose)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = guard;
        Ok(seatbelt::build(config, project_dir, verbose))
    }
}

pub fn dry_run(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        bwrap::dry_run(guard, config, project_dir, verbose)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = guard;
        Ok(seatbelt::dry_run(config, project_dir, verbose))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_launch_is_bash() {
        let cfg = Config::default();
        let cmd = default_launch_command(&cfg);
        assert_eq!(cmd.program, "bash");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn default_launch_uses_first_token_as_program() {
        let cfg = Config {
            command: vec!["claude".into(), "--model".into(), "opus".into()],
            ..Config::default()
        };
        let cmd = default_launch_command(&cfg);
        assert_eq!(cmd.program, "claude");
        assert_eq!(cmd.args, vec!["--model", "opus"]);
    }

    #[test]
    fn build_launch_respects_no_mise() {
        let cfg = Config {
            command: vec!["claude".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn build_launch_disables_mise_in_lockdown() {
        let cfg = Config {
            command: vec!["claude".into()],
            lockdown: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn regression_user_args_are_not_shell_interpreted() {
        let cfg = Config {
            command: vec!["echo".into(), "$(id)".into(), ";rm".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        assert_eq!(cmd.program, "echo");
        assert_eq!(cmd.args, vec!["$(id)", ";rm"]);
    }

    #[test]
    fn regression_mise_wrapper_forwards_user_argv_verbatim() {
        let user_cmd = LaunchCommand {
            program: "echo".into(),
            args: vec!["$(id)".into(), "a b".into()],
        };
        let wrapped =
            mise_wrapper_command(Path::new("/usr/bin/mise"), user_cmd);
        assert_eq!(wrapped.program, "bash");
        assert!(
            wrapped.args.iter().any(|a| a.contains("exec \"$@\"")),
            "mise wrapper should forward command argv via exec \"$@\""
        );
        assert_eq!(wrapped.args.last(), Some(&"a b".to_string()));
    }

    #[test]
    fn deny_list_contains_sensitive_dirs() {
        for name in &[
            ".gnupg",
            ".aws",
            ".ssh",
            ".mozilla",
            ".basilisk-dev",
            ".sparrow",
        ] {
            assert!(
                DOTDIR_DENY.contains(name),
                "{name} should be in deny list"
            );
        }
    }

    #[test]
    fn rw_list_contains_ai_tool_dirs() {
        for name in &[".claude", ".crush", ".codex", ".aider"] {
            assert!(DOTDIR_RW.contains(name), "{name} should be in rw list");
        }
    }

    #[test]
    fn rw_list_contains_tool_dirs() {
        for name in &[".config", ".cargo", ".cache", ".docker"] {
            assert!(DOTDIR_RW.contains(name), "{name} should be in rw list");
        }
    }

    #[test]
    fn deny_and_rw_lists_do_not_overlap() {
        for name in DOTDIR_DENY {
            assert!(
                !DOTDIR_RW.contains(name),
                "{name} is in both deny and rw lists"
            );
        }
    }
}
