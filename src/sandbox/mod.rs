use crate::config::Config;
use crate::output;
use std::ffi::OsStr;
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

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(target_os = "linux")]
pub use bwrap::SandboxGuard;
#[cfg(target_os = "macos")]
pub use seatbelt::SandboxGuard;

pub(crate) const LOCKDOWN_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub(crate) const TERM_ENV_VARS: &[&str] =
    &["TERM", "COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION"];
pub(crate) const JAIL_PS1: &str = "(jail) \\w \\$ ";

// Dotdirs never mounted (sensitive data)
const DOTDIR_DENY: &[&str] = &[
    ".gnupg",
    ".aws",
    ".ssh",
    ".mozilla",
    ".thunderbird",
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
    ".gemini",
    ".claude",
    ".crush",
    ".codex",
    ".aider",
    ".kiro",
    ".soulforge",
    ".grok",
    ".agents",
    ".omp",
    ".pi",
    ".pi-lens",
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

pub(crate) fn is_browser_command_name(name: &str) -> bool {
    BROWSER_COMMANDS.contains(&name)
}

fn has_glob_meta(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .chars()
        .any(|c| matches!(c, '*' | '?' | '['))
}

fn component_has_glob_meta(component: &OsStr) -> bool {
    component
        .to_string_lossy()
        .chars()
        .any(|c| matches!(c, '*' | '?' | '['))
}

fn glob_base_and_pattern(
    pattern: &Path,
    project_dir: &Path,
) -> (PathBuf, Vec<String>) {
    let absolute =
        crate::config::to_absolute(pattern.to_path_buf(), project_dir);
    let mut base = PathBuf::new();
    let mut pattern_components = Vec::new();
    let mut seen_glob = false;

    for component in absolute.components() {
        let os = component.as_os_str();
        if !seen_glob && !component_has_glob_meta(os) {
            base.push(os);
        } else {
            seen_glob = true;
            pattern_components.push(os.to_string_lossy().into_owned());
        }
    }

    if base.as_os_str().is_empty() {
        base.push(project_dir);
    }

    (base, pattern_components)
}

/// Match a single character against a glob `[...]` class body
/// (literals and `a-z` ranges).
///
/// Deliberately minimal — this hand-rolled glob avoids a crate
/// dependency. Unsupported syntax, by design:
///   - negation (`[!...]` / `[^...]`) — `!`/`^` are treated as
///     literal characters;
///   - an unclosed `[` is treated as a literal bracket by the
///     caller, not a class.
fn matches_char_class(class: &[char], ch: char) -> bool {
    let mut i = 0;
    let mut matched = false;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == '-' {
            if class[i] <= ch && ch <= class[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if class[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }
    matched
}

fn glob_component_matches(pattern: &str, text: &str) -> bool {
    fn inner(pattern: &[char], text: &[char]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }

        match pattern[0] {
            '*' => {
                inner(&pattern[1..], text)
                    || (!text.is_empty() && inner(pattern, &text[1..]))
            }
            '?' => !text.is_empty() && inner(&pattern[1..], &text[1..]),
            '[' => {
                let Some(end) = pattern.iter().position(|c| *c == ']') else {
                    return !text.is_empty()
                        && pattern[0] == text[0]
                        && inner(&pattern[1..], &text[1..]);
                };
                !text.is_empty()
                    && matches_char_class(&pattern[1..end], text[0])
                    && inner(&pattern[end + 1..], &text[1..])
            }
            c => {
                !text.is_empty()
                    && c == text[0]
                    && inner(&pattern[1..], &text[1..])
            }
        }
    }

    inner(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
}

fn glob_path_matches(pattern: &[String], components: &[String]) -> bool {
    if pattern.is_empty() {
        return components.is_empty();
    }

    if pattern[0] == "**" {
        glob_path_matches(&pattern[1..], components)
            || (!components.is_empty()
                && glob_path_matches(pattern, &components[1..]))
    } else {
        !components.is_empty()
            && glob_component_matches(&pattern[0], &components[0])
            && glob_path_matches(&pattern[1..], &components[1..])
    }
}

fn collect_glob_candidates(
    base: &Path,
    current: &Path,
    out: &mut Vec<PathBuf>,
) {
    out.push(current.to_path_buf());

    let Ok(meta) = std::fs::symlink_metadata(current) else {
        return;
    };
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return;
    }

    let Ok(entries) = std::fs::read_dir(current) else {
        output::warn(&format!(
            "Mask glob: cannot read {}, skipping nested entries",
            current.display()
        ));
        return;
    };

    let mut paths = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        if path.starts_with(base) {
            collect_glob_candidates(base, &path, out);
        }
    }
}

fn path_components_relative_to(path: &Path, base: &Path) -> Vec<String> {
    path.strip_prefix(base)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect()
}

/// Expand mask entries that contain glob metacharacters (`*`, `?`, `[...]`).
/// Literal entries keep their existing project-relative semantics. Globs are
/// expanded at sandbox-policy time so config files can keep portable patterns.
pub(crate) fn expand_mask_patterns(
    mask: &[PathBuf],
    project_dir: &Path,
) -> Vec<PathBuf> {
    let mut out = Vec::new();

    for entry in mask {
        if !has_glob_meta(entry) {
            out.push(if entry.is_absolute() {
                entry.clone()
            } else {
                project_dir.join(entry)
            });
            continue;
        }

        let (base, pattern) = glob_base_and_pattern(entry, project_dir);
        let mut candidates = Vec::new();
        collect_glob_candidates(&base, &base, &mut candidates);
        let before = out.len();
        for candidate in candidates {
            let rel = path_components_relative_to(&candidate, &base);
            if glob_path_matches(&pattern, &rel) && !out.contains(&candidate) {
                out.push(candidate);
            }
        }

        if out.len() == before {
            output::warn(&format!(
                "Mask glob: {} matched nothing, skipping",
                entry.display()
            ));
        }
    }

    out
}

fn browser_basename(program: &str) -> Option<&str> {
    let name = Path::new(program).file_name()?.to_str()?;
    if is_browser_command_name(name) {
        Some(name)
    } else {
        None
    }
}

pub(crate) fn browser_state_dir(config: &Config) -> Option<PathBuf> {
    let profile = config.browser_profile()?;
    let browser = browser_basename(config.command.first()?)?;
    match profile {
        crate::config::BrowserProfile::Hard => None,
        crate::config::BrowserProfile::Soft => Some(
            home_dir()
                .join(".local/share/ai-jail/browsers")
                .join(browser),
        ),
    }
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

/// Paths under `$HOME` that must stay visible in private-home mode for
/// the sandboxed command itself to start (issue #81). Private home
/// replaces `$HOME` with a tmpfs and skips all dotdir binds, which
/// also hides the agent binary when it was installed under the home
/// directory — e.g. the official Claude installer symlinks
/// `~/.local/bin/claude` to `~/.local/share/claude/versions/<v>`.
///
/// Resolves the command the way exec will (host `PATH` search), then
/// walks the symlink chain: every hop under `$HOME` is collected, and
/// for the final regular-file target its parent directory is collected
/// so version payloads and launcher siblings resolve. Tools with needs
/// beyond their install directory stay on the `--map` escape hatch.
pub(crate) fn command_home_paths(config: &Config) -> Vec<PathBuf> {
    let Some(cmd) = config.command.first() else {
        return vec![];
    };
    let path_env = std::env::var("PATH").unwrap_or_default();
    command_home_paths_impl(cmd, &home_dir(), &path_env)
}

fn command_home_paths_impl(
    cmd: &str,
    home: &Path,
    path_env: &str,
) -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let is_executable_file = |p: &Path| {
        p.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };

    let start = if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        if !p.is_absolute() {
            // Relative-with-slash resolves against the project cwd,
            // which is always mounted.
            return vec![];
        }
        p
    } else {
        match path_env
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| Path::new(d).join(cmd))
            .find(|c| is_executable_file(c))
        {
            Some(p) => p,
            None => return vec![],
        }
    };

    let mut paths: Vec<PathBuf> = Vec::new();
    let push_unique = |paths: &mut Vec<PathBuf>, p: PathBuf| {
        if !paths.contains(&p) {
            paths.push(p);
        }
    };

    let mut cur = start;
    // Cap the walk so a symlink loop can't hang sandbox setup.
    for _ in 0..16 {
        match std::fs::read_link(&cur) {
            Ok(target) => {
                // A symlink hop; the chain may leave and re-enter
                // $HOME, so collect per hop rather than bailing early.
                if cur.starts_with(home) {
                    push_unique(&mut paths, cur.clone());
                }
                cur = if target.is_absolute() {
                    target
                } else {
                    match cur.parent() {
                        Some(parent) => parent.join(target),
                        None => break,
                    }
                };
            }
            Err(_) => {
                // Terminal: a regular file (or a broken link target —
                // warn-and-skip philosophy, exec will report it).
                if cur.starts_with(home)
                    && cur.is_file()
                    && let Some(parent) = cur.parent()
                {
                    push_unique(&mut paths, parent.to_path_buf());
                }
                break;
            }
        }
    }

    paths
}

/// Resolve `$XDG_CONFIG_HOME` per the XDG Base Directory spec:
/// return its value if set and non-empty, otherwise fall back to
/// `$HOME/.config`. Used by sandbox setup to find tools that store
/// state under the XDG config dir (e.g. global git config/ignore).
fn xdg_config_home() -> PathBuf {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir().join(".config"),
    }
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

pub(crate) fn quote_shell_arg(arg: &str) -> String {
    if arg.is_empty()
        || arg.contains(|c: char| {
            c.is_whitespace() || "'\"\\$`(){}[]|&;<>*!?".contains(c)
        })
    {
        return format!("'{}'", arg.replace('\'', "'\\''"));
    }
    arg.to_string()
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
    let script = "MISE=\"$1\"; shift; \"$MISE\" trust -q && eval \"$($MISE activate bash)\" && eval \"$($MISE env)\" && exec \"$@\"";
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

fn browser_profile_launch_command(
    config: &Config,
    mut user_cmd: LaunchCommand,
) -> LaunchCommand {
    let Some(profile) = config.browser_profile() else {
        return user_cmd;
    };
    let Some(browser) = browser_basename(&user_cmd.program) else {
        return user_cmd;
    };

    match browser {
        "firefox" | "librewolf" => {
            let profile_dir = match profile {
                crate::config::BrowserProfile::Hard => {
                    format!("/tmp/ai-jail-browser-{browser}")
                }
                crate::config::BrowserProfile::Soft => {
                    browser_state_dir(config)
                        .unwrap_or_else(|| {
                            home_dir()
                                .join(".local/share/ai-jail/browsers")
                                .join(browser)
                        })
                        .display()
                        .to_string()
                }
            };
            user_cmd.args.extend([
                "--no-remote".into(),
                "--profile".into(),
                profile_dir,
            ]);
        }
        _ => {
            let data_dir = match profile {
                crate::config::BrowserProfile::Hard => {
                    format!("/tmp/ai-jail-browser-{browser}/data")
                }
                crate::config::BrowserProfile::Soft => {
                    browser_state_dir(config)
                        .unwrap_or_else(|| {
                            home_dir()
                                .join(".local/share/ai-jail/browsers")
                                .join(browser)
                        })
                        .join("data")
                        .display()
                        .to_string()
                }
            };
            let cache_dir = match profile {
                crate::config::BrowserProfile::Hard => {
                    format!("/tmp/ai-jail-browser-{browser}/cache")
                }
                crate::config::BrowserProfile::Soft => {
                    browser_state_dir(config)
                        .unwrap_or_else(|| {
                            home_dir()
                                .join(".local/share/ai-jail/browsers")
                                .join(browser)
                        })
                        .join("cache")
                        .display()
                        .to_string()
                }
            };
            user_cmd.args.extend([
                // The outer ai-jail sandbox provides process/filesystem
                // isolation. Chromium's own zygote/setuid sandbox does not
                // survive this bwrap/userns setup reliably, so browser
                // profiles run Chromium without its internal sandbox.
                "--no-sandbox".into(),
                // Suppresses Chromium's unsupported-flag infobar for the
                // intentional --no-sandbox flag above.
                "--test-type".into(),
                "--disable-crash-reporter".into(),
                "--disable-breakpad".into(),
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                "--disable-background-networking".into(),
                "--disable-sync".into(),
                "--password-store=basic".into(),
                format!("--user-data-dir={data_dir}"),
                format!("--disk-cache-dir={cache_dir}"),
            ]);
            if !config.gpu_enabled() {
                user_cmd.args.extend([
                    "--disable-gpu".into(),
                    "--disable-gpu-compositing".into(),
                    "--disable-accelerated-video-decode".into(),
                    "--disable-accelerated-video-encode".into(),
                ]);
            }
        }
    }

    user_cmd
}

pub fn build_launch_command(config: &Config) -> LaunchCommand {
    let user_cmd =
        browser_profile_launch_command(config, default_launch_command(config));
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

    use super::test_support::linked_worktree_fixture;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("ai-jail-{prefix}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn expand_mask_patterns_keeps_literal_project_relative() {
        let project = PathBuf::from("/tmp/project");
        let expanded = expand_mask_patterns(&[PathBuf::from(".env")], &project);

        assert_eq!(expanded, vec![PathBuf::from("/tmp/project/.env")]);
    }

    #[test]
    fn expand_mask_patterns_supports_recursive_globs() {
        let root = temp_test_dir("mask-glob-recursive");
        let project = root.join("project");
        std::fs::create_dir_all(project.join("a/b")).unwrap();
        std::fs::create_dir_all(project.join("node_modules/pkg")).unwrap();
        std::fs::write(project.join(".env"), "root").unwrap();
        std::fs::write(project.join("a/.env"), "nested").unwrap();
        std::fs::write(project.join("a/b/app.env"), "deep").unwrap();
        std::fs::write(project.join("a/b/app.txt"), "nope").unwrap();
        std::fs::write(project.join("node_modules/pkg/.env"), "vendor")
            .unwrap();

        let expanded =
            expand_mask_patterns(&[PathBuf::from("**/*.env")], &project);

        assert_eq!(
            expanded,
            vec![
                project.join(".env"),
                project.join("a/.env"),
                project.join("a/b/app.env"),
                project.join("node_modules/pkg/.env"),
            ]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn expand_mask_patterns_supports_question_and_bracket_classes() {
        let root = temp_test_dir("mask-glob-classes");
        let project = root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("app1.env"), "one").unwrap();
        std::fs::write(project.join("app2.env"), "two").unwrap();
        std::fs::write(project.join("app9.env"), "nine").unwrap();
        std::fs::write(project.join("app10.env"), "ten").unwrap();

        let expanded =
            expand_mask_patterns(&[PathBuf::from("app[1-2].env")], &project);
        assert_eq!(
            expanded,
            vec![project.join("app1.env"), project.join("app2.env")]
        );

        let expanded =
            expand_mask_patterns(&[PathBuf::from("app?.env")], &project);
        assert_eq!(
            expanded,
            vec![
                project.join("app1.env"),
                project.join("app2.env"),
                project.join("app9.env"),
            ]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn expand_mask_patterns_supports_parent_relative_glob() {
        let root = temp_test_dir("mask-glob-parent");
        let project = root.join("repo/app");
        let shared = root.join("repo/shared");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("secret.env"), "secret").unwrap();
        std::fs::write(shared.join("public.txt"), "public").unwrap();

        let expanded =
            expand_mask_patterns(&[PathBuf::from("../shared/*.env")], &project);

        assert_eq!(expanded, vec![shared.join("secret.env")]);

        let _ = std::fs::remove_dir_all(&root);
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
    fn browser_hard_profile_adds_chromium_ephemeral_args() {
        let cfg = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("hard".into()),
            no_mise: Some(true),
            no_gpu: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        assert_eq!(cmd.program, "chromium");
        assert!(cmd.args.contains(&"--no-sandbox".into()));
        assert!(cmd.args.contains(&"--test-type".into()));
        assert!(cmd.args.contains(&"--disable-breakpad".into()));
        assert!(cmd.args.contains(&"--disable-gpu".into()));
        assert!(cmd.args.contains(&"--no-first-run".into()));
        assert!(cmd.args.contains(&"--disable-sync".into()));
        assert!(cmd.args.contains(&"--password-store=basic".into()));
        assert!(
            cmd.args.iter().any(|arg| arg
                == "--user-data-dir=/tmp/ai-jail-browser-chromium/data")
        );
        assert!(
            cmd.args.iter().any(|arg| arg
                == "--disk-cache-dir=/tmp/ai-jail-browser-chromium/cache")
        );
    }

    #[test]
    fn browser_soft_profile_uses_ai_jail_state_dir() {
        let cfg = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("soft".into()),
            no_mise: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        let state = browser_state_dir(&cfg).unwrap();

        assert!(state.ends_with(".local/share/ai-jail/browsers/chromium"));
        assert!(cmd.args.iter().any(|arg| {
            arg == &format!("--user-data-dir={}", state.join("data").display())
        }));
        assert!(cmd.args.iter().any(|arg| {
            arg == &format!(
                "--disk-cache-dir={}",
                state.join("cache").display()
            )
        }));
    }

    #[test]
    fn browser_chromium_profile_respects_explicit_gpu() {
        let cfg = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("hard".into()),
            no_mise: Some(true),
            no_gpu: Some(false),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);

        assert!(!cmd.args.contains(&"--disable-gpu".into()));
        assert!(!cmd.args.contains(&"--disable-gpu-compositing".into()));
    }

    #[test]
    fn browser_firefox_profile_adds_isolated_profile_args() {
        let cfg = Config {
            command: vec!["firefox".into()],
            browser_profile: Some("hard".into()),
            no_mise: Some(true),
            ..Config::default()
        };
        let cmd = build_launch_command(&cfg);
        assert_eq!(cmd.program, "firefox");
        assert!(cmd.args.contains(&"--no-remote".into()));
        assert!(cmd.args.contains(&"--profile".into()));
        assert!(cmd.args.contains(&"/tmp/ai-jail-browser-firefox".into()));
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
            ".thunderbird",
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
        for name in &[
            ".gemini",
            ".claude",
            ".crush",
            ".codex",
            ".aider",
            ".kiro",
            ".soulforge",
            ".grok",
            ".agents",
            ".omp",
            ".pi",
            ".pi-lens",
        ] {
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
        assert!(is_dotdir_denied(".thunderbird", &[], &[]));
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
        let required = [
            ".cargo", ".cache", ".config", ".claude", ".gemini", ".kiro",
            ".omp", ".pi", ".pi-lens",
        ];
        for name in required {
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
        assert!(is_dotdir_rw(".omp"));
        assert!(is_dotdir_rw("omp"));
        assert!(is_dotdir_rw(".kiro"));
        assert!(is_dotdir_rw("kiro"));
        assert!(is_dotdir_rw(".pi"));
        assert!(is_dotdir_rw("pi"));
        assert!(is_dotdir_rw(".pi-lens"));
        assert!(is_dotdir_rw("pi-lens"));
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
        let fixture = linked_worktree_fixture("worktree");

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
        let fixture = linked_worktree_fixture("worktree");
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
        let fixture = linked_worktree_fixture("worktree");
        let config = Config {
            no_worktree: Some(true),
            ..Config::default()
        };

        assert!(
            discover_git_worktree_paths(&config, &fixture.project_dir, false)
                .is_none()
        );
    }

    #[test]
    fn xdg_config_home_falls_back_to_home_dot_config() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/test-user");
        let _xdg = EnvVarGuard::remove("XDG_CONFIG_HOME");
        assert_eq!(xdg_config_home(), PathBuf::from("/home/test-user/.config"));
    }

    #[test]
    fn xdg_config_home_falls_back_when_env_is_empty() {
        // XDG spec: treat empty value the same as unset.
        let _lock = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/test-user");
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", "");
        assert_eq!(xdg_config_home(), PathBuf::from("/home/test-user/.config"));
    }

    #[test]
    fn xdg_config_home_honors_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/test-user");
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", "/opt/custom-config");
        assert_eq!(xdg_config_home(), PathBuf::from("/opt/custom-config"));
    }

    /// Fixture mirroring the official Claude installer layout:
    /// `<home>/.local/bin/agent` → `<home>/.local/share/agent/versions/1.0`.
    fn command_home_fixture(tag: &str) -> PathBuf {
        let home = std::env::temp_dir()
            .join(format!("ai-jail-cmd-home-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let versions = home.join(".local/share/agent/versions");
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(&versions).unwrap();
        let target = versions.join("1.0");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &target,
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(&target, home.join(".local/bin/agent"))
            .unwrap();
        home
    }

    #[test]
    fn command_home_paths_follows_installer_symlink_chain() {
        // Regression for #81: PATH entry + final target's parent dir
        // must both surface so private-home mode can exec the agent.
        let home = command_home_fixture("chain");
        let path_env =
            format!("/usr/bin:{}", home.join(".local/bin").display());

        let paths = command_home_paths_impl("agent", &home, &path_env);

        assert_eq!(
            paths,
            vec![
                home.join(".local/bin/agent"),
                home.join(".local/share/agent/versions"),
            ]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn command_home_paths_resolves_absolute_command() {
        let home = command_home_fixture("abs");
        let cmd = home.join(".local/bin/agent");

        let paths =
            command_home_paths_impl(cmd.to_str().unwrap(), &home, "/usr/bin");

        assert_eq!(
            paths,
            vec![
                home.join(".local/bin/agent"),
                home.join(".local/share/agent/versions"),
            ]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn command_home_paths_ignores_system_binaries() {
        // A command outside $HOME needs no extra mounts.
        let home = PathBuf::from("/home/definitely-not-this-user");
        assert!(
            command_home_paths_impl("sh", &home, "/usr/bin:/bin").is_empty()
        );
        assert!(
            command_home_paths_impl("/bin/sh", &home, "/usr/bin").is_empty()
        );
    }

    #[test]
    fn command_home_paths_ignores_missing_and_relative_commands() {
        let home = command_home_fixture("miss");
        let path_env = home.join(".local/bin").display().to_string();

        // Not on PATH at all.
        assert!(
            command_home_paths_impl("no-such-agent", &home, &path_env)
                .is_empty()
        );
        // Relative-with-slash resolves against the project cwd, which
        // is always mounted.
        assert!(
            command_home_paths_impl("./agent", &home, &path_env).is_empty()
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn command_home_paths_survives_symlink_loops() {
        // The chain walk is capped; a loop must not hang or panic.
        let home = std::env::temp_dir()
            .join(format!("ai-jail-cmd-home-loop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(bin.join("b"), bin.join("a")).unwrap();
        std::os::unix::fs::symlink(bin.join("a"), bin.join("b")).unwrap();

        let cmd = bin.join("a");
        let paths = command_home_paths_impl(cmd.to_str().unwrap(), &home, "");

        // Only the symlink hops are collected; no final dir exists.
        assert!(paths.iter().all(|p| p.starts_with(&home)));
        let _ = std::fs::remove_dir_all(&home);
    }
}
