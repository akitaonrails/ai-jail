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

/// Returns true if the dotdir name requires read-write access.
/// `name` should be the dotdir name with or without leading dot (e.g., ".cargo" or "cargo").
fn is_dotdir_rw(name: &str) -> bool {
    let normalized = name.strip_prefix('.').unwrap_or(name);
    DOTDIR_RW
        .iter()
        .any(|&d| d.strip_prefix('.').unwrap_or(d) == normalized)
}

/// Returns true if the dotdir name is in the deny list.
/// Checks both built-in DOTDIR_DENY and user-specified extras.
/// `name` should be the dotdir name with or without leading dot (e.g., ".aws" or "aws").
/// If user tries to deny a built-in RW directory, warns and returns false.
#[allow(dead_code)] // unused on macOS where seatbelt uses denied_dotdirs instead
pub fn is_dotdir_denied(name: &str, extra: &[String]) -> bool {
    let normalized = name.strip_prefix('.').unwrap_or(name);
    // Check built-in list
    if DOTDIR_DENY
        .iter()
        .any(|&d| d.strip_prefix('.').unwrap_or(d) == normalized)
    {
        return true;
    }
    // Check user-specified extras, but reject RW-required dirs
    for e in extra {
        let e_normalized = e.strip_prefix('.').unwrap_or(e);
        if e_normalized == normalized {
            if is_dotdir_rw(normalized) {
                crate::output::warn(&format!(
                    "Cannot hide {e}: it is required for sandboxed tool operation"
                ));
                return false;
            }
            return true;
        }
    }
    false
}

/// Returns an iterator over all denied dotdir names (without leading dot).
/// Includes both built-in DOTDIR_DENY and user-specified extras.
#[allow(dead_code)] // unused on Linux where bwrap/landlock use is_dotdir_denied instead
pub fn denied_dotdirs(extra: &[String]) -> impl Iterator<Item = String> + '_ {
    DOTDIR_DENY
        .iter()
        .map(|s| s.strip_prefix('.').unwrap_or(s).to_string())
        .chain(
            extra
                .iter()
                .map(|s| s.strip_prefix('.').unwrap_or(s).to_string()),
        )
}

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
            if p.is_file() { Some(p) } else { None }
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
        crate::output::info(
            "Lockdown mode enabled: read-only project, no host write mounts, no mise.",
        );
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

    #[test]
    fn is_dotdir_denied_builtin() {
        assert!(is_dotdir_denied(".gnupg", &[]));
        assert!(is_dotdir_denied("gnupg", &[])); // Without dot
        assert!(is_dotdir_denied(".aws", &[]));
        assert!(is_dotdir_denied(".ssh", &[]));
        assert!(is_dotdir_denied(".mozilla", &[]));
        assert!(is_dotdir_denied(".basilisk-dev", &[]));
        assert!(is_dotdir_denied(".sparrow", &[]));
    }

    #[test]
    fn is_dotdir_denied_extra() {
        let extra = vec![".my_secrets".into(), ".proton".into()];
        assert!(is_dotdir_denied(".my_secrets", &extra));
        assert!(is_dotdir_denied("my_secrets", &extra)); // Without dot
        assert!(is_dotdir_denied(".proton", &extra));
        assert!(is_dotdir_denied("proton", &extra));
    }

    #[test]
    fn is_dotdir_denied_not_in_list() {
        assert!(!is_dotdir_denied(".cargo", &[]));
        assert!(!is_dotdir_denied(".config", &[]));
        assert!(!is_dotdir_denied(".my_custom", &[]));
    }

    #[test]
    fn is_dotdir_denied_combined() {
        let extra = vec![".my_secrets".into()];
        // Built-in
        assert!(is_dotdir_denied(".aws", &extra));
        // Extra
        assert!(is_dotdir_denied(".my_secrets", &extra));
        // Not denied
        assert!(!is_dotdir_denied(".cargo", &extra));
    }

    #[test]
    fn cannot_deny_rw_required_dirs() {
        for name in &[".cargo", ".cache", ".config", ".claude"] {
            let extra = vec![name.to_string()];
            assert!(
                !is_dotdir_denied(name, &extra),
                "{name} should not be deniable - it's RW-required"
            );
        }
    }

    #[test]
    fn is_dotdir_rw_check() {
        assert!(is_dotdir_rw(".cargo"));
        assert!(is_dotdir_rw("cargo"));
        assert!(is_dotdir_rw(".config"));
        assert!(is_dotdir_rw(".cache"));
        assert!(!is_dotdir_rw(".aws"));
        assert!(!is_dotdir_rw(".my_secrets"));
    }

    #[test]
    fn denied_dotdirs_iter() {
        let extra: Vec<String> = vec![".my_secrets".into(), ".proton".into()];
        let denied: Vec<String> = denied_dotdirs(&extra).collect();
        assert!(denied.contains(&"gnupg".to_string()));
        assert!(denied.contains(&"aws".to_string()));
        assert!(denied.contains(&"my_secrets".to_string()));
        assert!(denied.contains(&"proton".to_string()));
    }
}
