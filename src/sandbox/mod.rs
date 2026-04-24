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
/// `exempt` lists dotdir names explicitly allowed by the user (e.g. ".ssh" via --ssh).
#[allow(dead_code)] // unused on macOS where seatbelt uses denied_dotdirs instead
pub fn is_dotdir_denied(name: &str, extra: &[String], exempt: &[&str]) -> bool {
    let normalized = name.strip_prefix('.').unwrap_or(name);
    // Check exemptions first
    if exempt
        .iter()
        .any(|&e| e.strip_prefix('.').unwrap_or(e) == normalized)
    {
        return false;
    }
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
/// Includes both built-in DOTDIR_DENY and user-specified extras,
/// minus any names in `exempt`.
#[allow(dead_code)] // unused on Linux where bwrap/landlock use is_dotdir_denied instead
pub fn denied_dotdirs<'a>(
    extra: &'a [String],
    exempt: &'a [&'a str],
) -> impl Iterator<Item = String> + 'a {
    DOTDIR_DENY
        .iter()
        .map(|s| s.strip_prefix('.').unwrap_or(s).to_string())
        .chain(
            extra
                .iter()
                .map(|s| s.strip_prefix('.').unwrap_or(s).to_string()),
        )
        .filter(move |name| {
            !exempt
                .iter()
                .any(|&e| e.strip_prefix('.').unwrap_or(e) == name)
        })
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

/// Build the list of dotdir names exempted from the deny list by
/// explicit user flags (e.g. --ssh exempts ".ssh").
pub fn dotdir_exemptions(config: &Config) -> Vec<&'static str> {
    let mut exempt = Vec::new();
    if config.ssh_enabled() {
        exempt.push(".ssh");
    }
    exempt
}

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

fn path_exists(p: &Path) -> bool {
    p.exists() || p.symlink_metadata().is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitWorktreePaths {
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
}

impl GitWorktreePaths {
    pub(crate) fn unique_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = Vec::new();
        for path in [self.git_dir.clone(), self.common_dir.clone()] {
            if !paths
                .iter()
                .any(|existing| paths_equivalent(existing, &path))
            {
                paths.push(path);
            }
        }
        paths
    }
}

pub(crate) fn discover_git_worktree_paths(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Option<GitWorktreePaths> {
    if !config.worktree_enabled() {
        if verbose {
            crate::output::verbose("Git worktree: disabled");
        }
        return None;
    }

    match validate_linked_git_worktree(project_dir) {
        Ok(Some(paths)) => {
            if verbose {
                crate::output::verbose(&format!(
                    "Git worktree: exposing {}",
                    paths
                        .unique_paths()
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Some(paths)
        }
        Ok(None) => {
            if verbose {
                crate::output::verbose(
                    "Git worktree: not a linked worktree root",
                );
            }
            None
        }
        Err(reason) => {
            if verbose {
                crate::output::verbose(&format!(
                    "Git worktree: skipped ({reason})"
                ));
            }
            None
        }
    }
}

fn validate_linked_git_worktree(
    project_dir: &Path,
) -> Result<Option<GitWorktreePaths>, String> {
    let project_git = project_dir.join(".git");
    if project_git.is_dir() {
        return Ok(None);
    }
    if !project_git.is_file() {
        return Ok(None);
    }

    let git_dir = parse_gitfile_target(&project_git)?;
    if !git_dir.is_dir() {
        return Err(format!(
            "gitdir target {} is not a directory",
            git_dir.display()
        ));
    }

    let reverse_gitdir = read_resolved_path_file(&git_dir.join("gitdir"))?;
    if !paths_equivalent(&reverse_gitdir, &project_git) {
        return Err(format!(
            "{} does not point back to {}",
            git_dir.join("gitdir").display(),
            project_git.display()
        ));
    }

    let common_dir = read_resolved_path_file(&git_dir.join("commondir"))?;
    if !common_dir.is_dir() {
        return Err(format!(
            "commondir target {} is not a directory",
            common_dir.display()
        ));
    }

    Ok(Some(GitWorktreePaths {
        git_dir,
        common_dir,
    }))
}

fn parse_gitfile_target(gitfile: &Path) -> Result<PathBuf, String> {
    let contents = std::fs::read_to_string(gitfile)
        .map_err(|e| format!("cannot read {}: {e}", gitfile.display()))?;
    let line = contents.trim();
    let raw = line
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("{} is not a valid gitfile", gitfile.display())
        })?;
    Ok(resolve_path_from_file(gitfile, Path::new(raw)))
}

fn read_resolved_path_file(path: &Path) -> Result<PathBuf, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let raw = contents.trim();
    if raw.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(resolve_path_from_file(path, Path::new(raw)))
}

fn resolve_path_from_file(file: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        file.parent().unwrap_or_else(|| Path::new(".")).join(path)
    }
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
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
    use std::time::{SystemTime, UNIX_EPOCH};

    struct LinkedWorktreeFixture {
        root: PathBuf,
        project_dir: PathBuf,
        git_dir: PathBuf,
        common_dir: PathBuf,
    }

    impl Drop for LinkedWorktreeFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("ai-jail-{prefix}-{}-{nonce}", std::process::id()))
    }

    fn create_linked_worktree_fixture() -> LinkedWorktreeFixture {
        let root = temp_test_dir("worktree");
        let project_dir = root.join("project");
        let common_dir = root.join("common/.git");
        let git_dir = common_dir.join("worktrees/wt1");

        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::create_dir_all(&git_dir).unwrap();

        std::fs::write(
            project_dir.join(".git"),
            "gitdir: ../common/.git/worktrees/wt1\n",
        )
        .unwrap();
        std::fs::write(git_dir.join("gitdir"), "../../../../project/.git\n")
            .unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();

        LinkedWorktreeFixture {
            root,
            project_dir,
            git_dir,
            common_dir,
        }
    }

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
        assert!(is_dotdir_denied(".gnupg", &[], &[]));
        assert!(is_dotdir_denied("gnupg", &[], &[])); // Without dot
        assert!(is_dotdir_denied(".aws", &[], &[]));
        assert!(is_dotdir_denied(".ssh", &[], &[]));
        assert!(is_dotdir_denied(".mozilla", &[], &[]));
        assert!(is_dotdir_denied(".basilisk-dev", &[], &[]));
        assert!(is_dotdir_denied(".sparrow", &[], &[]));
    }

    #[test]
    fn is_dotdir_denied_extra() {
        let extra = vec![".my_secrets".into(), ".proton".into()];
        assert!(is_dotdir_denied(".my_secrets", &extra, &[]));
        assert!(is_dotdir_denied("my_secrets", &extra, &[])); // Without dot
        assert!(is_dotdir_denied(".proton", &extra, &[]));
        assert!(is_dotdir_denied("proton", &extra, &[]));
    }

    #[test]
    fn is_dotdir_denied_not_in_list() {
        assert!(!is_dotdir_denied(".cargo", &[], &[]));
        assert!(!is_dotdir_denied(".config", &[], &[]));
        assert!(!is_dotdir_denied(".my_custom", &[], &[]));
    }

    #[test]
    fn is_dotdir_denied_combined() {
        let extra = vec![".my_secrets".into()];
        // Built-in
        assert!(is_dotdir_denied(".aws", &extra, &[]));
        // Extra
        assert!(is_dotdir_denied(".my_secrets", &extra, &[]));
        // Not denied
        assert!(!is_dotdir_denied(".cargo", &extra, &[]));
    }

    #[test]
    fn ssh_exempt_removes_from_deny() {
        assert!(is_dotdir_denied(".ssh", &[], &[]));
        assert!(!is_dotdir_denied(".ssh", &[], &[".ssh"]));
        // Other denied dirs unaffected
        assert!(is_dotdir_denied(".gnupg", &[], &[".ssh"]));
    }

    #[test]
    fn cannot_deny_rw_required_dirs() {
        for name in &[".cargo", ".cache", ".config", ".claude"] {
            let extra = vec![name.to_string()];
            assert!(
                !is_dotdir_denied(name, &extra, &[]),
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
        let denied: Vec<String> = denied_dotdirs(&extra, &[]).collect();
        assert!(denied.contains(&"gnupg".to_string()));
        assert!(denied.contains(&"aws".to_string()));
        assert!(denied.contains(&"my_secrets".to_string()));
        assert!(denied.contains(&"proton".to_string()));
    }

    #[test]
    fn validate_linked_git_worktree_skips_normal_repo_root() {
        let root = temp_test_dir("normal-repo");
        let project_dir = root.join("project");
        std::fs::create_dir_all(project_dir.join(".git")).unwrap();

        assert!(
            validate_linked_git_worktree(&project_dir)
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_linked_git_worktree_discovers_valid_layout() {
        let fixture = create_linked_worktree_fixture();

        let paths = validate_linked_git_worktree(&fixture.project_dir)
            .unwrap()
            .unwrap();

        assert!(paths_equivalent(&paths.git_dir, &fixture.git_dir));
        assert!(paths_equivalent(&paths.common_dir, &fixture.common_dir));
        assert_eq!(paths.unique_paths().len(), 2);
    }

    #[test]
    fn validate_linked_git_worktree_rejects_malformed_gitfile() {
        let root = temp_test_dir("bad-gitfile");
        let project_dir = root.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join(".git"), "definitely not a gitfile\n")
            .unwrap();

        let err = validate_linked_git_worktree(&project_dir).unwrap_err();
        assert!(err.contains("valid gitfile"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_linked_git_worktree_rejects_mismatched_reverse_link() {
        let fixture = create_linked_worktree_fixture();
        std::fs::write(
            fixture.git_dir.join("gitdir"),
            "../../../../other/.git\n",
        )
        .unwrap();

        let err =
            validate_linked_git_worktree(&fixture.project_dir).unwrap_err();
        assert!(err.contains("does not point back"));
    }

    #[test]
    fn discover_git_worktree_paths_respects_disabled_config() {
        let fixture = create_linked_worktree_fixture();
        let config = Config {
            no_worktree: Some(true),
            ..Config::default()
        };

        assert!(
            discover_git_worktree_paths(&config, &fixture.project_dir, false)
                .is_none()
        );
    }
}
