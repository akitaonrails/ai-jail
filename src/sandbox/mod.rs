use crate::config::Config;
use crate::config::MapSpec;
use crate::output;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Dangerous capabilities a project `.ai-jail` can enable. Items are
/// stable strings so we can diff the project config against a baseline
/// (global config + CLI overrides) and warn only about new additions.
fn project_config_dangerous_opt_ins(
    config: &Config,
    project_dir: &Path,
) -> Vec<String> {
    let mut items = Vec::new();

    if config.docker_enabled() {
        items.push("Docker socket".into());
    }
    if config.tailscale_enabled() {
        items.push("Tailscale socket".into());
    }
    if config.ssh == Some(true) {
        items.push("SSH keys/agent".into());
    }
    if config.pictures == Some(true) {
        items.push("Pictures directory".into());
    }
    if config.systemd_user == Some(true) {
        items.push("systemd user bus".into());
    }

    for encoded in &config.rw_maps {
        if let Ok(spec) = MapSpec::parse(encoded)
            && is_outside_project(&spec.source, project_dir)
        {
            items.push(format!("rw-map {}", spec.source.display()));
        }
    }
    for encoded in &config.ro_maps {
        if let Ok(spec) = MapSpec::parse(encoded)
            && is_outside_project(&spec.source, project_dir)
        {
            items.push(format!("ro-map {}", spec.source.display()));
        }
    }
    for path in &config.overlay_maps {
        if is_outside_project(path, project_dir) {
            items.push(format!("overlay-map {}", path.display()));
        }
    }

    items
}

fn is_outside_project(path: &Path, project_dir: &Path) -> bool {
    path.is_absolute() && !path.starts_with(project_dir)
}

/// Warn when a project `.ai-jail` introduces dangerous passthroughs or
/// host path maps that are not already enabled by the user's global
/// config or explicit CLI flags. This keeps the trust-boundary signal
/// without warning users who have already opted in globally.
pub fn warn_project_config_opt_ins(
    project_config: &Config,
    baseline_config: &Config,
    project_dir: &Path,
) {
    // Paths may be relative or use `~/...`; resolve them the same way the
    // sandbox will before checking scope.
    let mut project = project_config.clone();
    let mut baseline = baseline_config.clone();
    crate::config::absolutize_user_paths(&mut project, project_dir);
    crate::config::absolutize_user_paths(&mut baseline, project_dir);

    let project_items = project_config_dangerous_opt_ins(&project, project_dir);
    if project_items.is_empty() {
        return;
    }
    let baseline_items =
        project_config_dangerous_opt_ins(&baseline, project_dir);

    let new_items: Vec<String> = project_items
        .into_iter()
        .filter(|item| !baseline_items.contains(item))
        .collect();
    if new_items.is_empty() {
        return;
    }

    output::warn(&format!(
        "Project .ai-jail enables capabilities not in your global config or CLI flags: {}. Review the file if you did not write it.",
        new_items.join(", ")
    ));
}

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
    ".kimi-code",
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

/// Expand include patterns, then subtract matching exceptions. Literal paths
/// keep their project-relative semantics, including paths beginning with `!`;
/// exceptions are always supplied explicitly rather than through gitignore
/// syntax. Globs are expanded at sandbox-policy time so config files can keep
/// portable patterns.
pub(crate) fn expand_mask_patterns(
    includes: &[PathBuf],
    exceptions: &[PathBuf],
    project_dir: &Path,
) -> Vec<PathBuf> {
    let mut out = Vec::new();

    for entry in includes {
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

    for entry in exceptions {
        if !has_glob_meta(entry) {
            let path = if entry.is_absolute() {
                entry.clone()
            } else {
                project_dir.join(entry)
            };
            let path = crate::config::normalize_path(&path);
            out.retain(|candidate| {
                let candidate = crate::config::normalize_path(candidate);
                candidate != path && !candidate.starts_with(&path)
            });
            continue;
        }

        let (base, pattern) = glob_base_and_pattern(entry, project_dir);
        let base = crate::config::normalize_path(&base);
        out.retain(|candidate| {
            let candidate = crate::config::normalize_path(candidate);
            !candidate.starts_with(&base)
                || !glob_path_matches(
                    &pattern,
                    &path_components_relative_to(&candidate, &base),
                )
        });
    }

    out
}

/// User masks with exceptions applied, followed by the mandatory project
/// policy mask. Exceptions must never expose `.ai-jail`; only
/// `--no-hide-config` may do that.
pub(crate) fn effective_mask_patterns(
    config: &Config,
    project_dir: &Path,
) -> Vec<PathBuf> {
    let mut masks = expand_mask_patterns(
        &config.mask,
        &config.mask_exceptions,
        project_dir,
    );
    let local_config = project_dir.join(".ai-jail");
    if config.hide_config_enabled()
        && path_exists(&local_config)
        && !masks.contains(&local_config)
    {
        masks.push(local_config);
    }
    masks
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
    let path_env = std::env::var("PATH").unwrap_or_default();
    let home = home_dir();
    let mut paths = Vec::new();
    for executable in crate::command::executable_candidates(&config.command) {
        for path in command_home_paths_impl(executable, &home, &path_env) {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    paths
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

/// Host path of the Docker/Podman socket to expose, if any: the
/// first candidate we can actually reach.
///
/// `$DOCKER_HOST` leads because it outranks every other endpoint
/// source in the Docker CLI's own resolution order, and rootless
/// Docker's setup instructs exporting it. Rootless Podman keeps its
/// socket under `$XDG_RUNTIME_DIR`, while the `podman-docker` compat
/// package symlinks `/var/run/docker.sock` to the *rootful* socket
/// under root-only `/run/podman` — the wrong daemon, and unreachable.
///
/// Docker contexts (`~/.docker/config.json`) are not consulted. That
/// misses setups that register a context without exporting
/// `$DOCKER_HOST` and whose socket is not one of the paths below
/// (Colima's `~/.colima/<profile>/docker.sock`, for one); add context
/// parsing if that turns up in practice.
pub(crate) fn docker_socket() -> Option<PathBuf> {
    let docker_host = std::env::var("DOCKER_HOST").ok();
    let candidates = [
        docker_host.as_deref().and_then(docker_host_socket_path),
        Some(PathBuf::from("/var/run/docker.sock")),
        Some(home_dir().join(".docker/run/docker.sock")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|p| docker_socket_usable(p))
}

/// `$DOCKER_HOST` as a bindable socket path, if it names one.
/// `tcp://` and `ssh://` reach the daemon over the network and
/// `npipe://` is a Windows named pipe; none of them is a path we can
/// bind, so they drop out of the candidate list.
fn docker_host_socket_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value.strip_prefix("unix://")?);
    path.is_absolute().then_some(path)
}

/// Unlike [`path_exists`], this rejects a symlink whose target cannot
/// be stat'd. bwrap resolves the link itself and aborts the entire
/// launch with `Can't find source path ...: Permission denied`, so an
/// optional socket we cannot reach must be skipped, not mounted.
pub(crate) fn docker_socket_usable(p: &Path) -> bool {
    p.exists()
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
    mounted_ro_paths: &[PathBuf],
    mounted_rw_paths: &[PathBuf],
    verbose: bool,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        landlock::apply(
            config,
            project_dir,
            mounted_ro_paths,
            mounted_rw_paths,
            verbose,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            config,
            project_dir,
            mounted_ro_paths,
            mounted_rw_paths,
            verbose,
        );
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
    warn_docker_passthrough(config);
    #[cfg(target_os = "macos")]
    {
        seatbelt::platform_notes(config);
    }
}

/// True when the raw host Docker socket will be exposed inside the
/// sandbox. Passthrough is opt-in (issue #88): the socket grants
/// effective root on the host, bypassing masks, deny-paths, and
/// Landlock. Lockdown and browser profiles never expose it.
fn docker_passthrough_active(config: &Config, socket_present: bool) -> bool {
    socket_present
        && config.docker_enabled()
        && !config.lockdown_enabled()
        && config.browser_profile().is_none()
}

fn warn_docker_passthrough(config: &Config) {
    let socket_present = docker_socket().is_some();
    if docker_passthrough_active(config, socket_present) {
        output::warn(
            "Docker socket passthrough is enabled: the sandboxed process \
             gets effective root on the host through the Docker daemon, \
             bypassing --mask, --deny-path, and Landlock. \
             Disable with --no-docker.",
        );
    }
}

#[cfg(any(target_os = "macos", test))]
fn prepare_seatbelt_maps(
    paths: &[PathBuf],
    access: &str,
) -> Result<Vec<PathBuf>, String> {
    let mut prepared = Vec::new();
    for encoded in paths {
        let Some(spec) = MapSpec::parse_validated(encoded, access) else {
            continue;
        };
        if spec.is_alternate() {
            return Err(format!(
                "alternate map destinations are not supported on macOS: {}; \
                 use Linux/bubblewrap or map the path at its host location",
                encoded.display()
            ));
        }
        if !path_exists(&spec.source) {
            output::warn(&format!(
                "Path {} not found, skipping.",
                spec.source.display()
            ));
            continue;
        }
        prepared.push(spec.encode());
    }
    Ok(prepared)
}

#[cfg(any(target_os = "macos", test))]
fn prepare_seatbelt_config(config: &Config) -> Result<Config, String> {
    let mut prepared = config.clone();
    prepared.rw_maps = prepare_seatbelt_maps(&config.rw_maps, "read-write")?;
    prepared.ro_maps = prepare_seatbelt_maps(&config.ro_maps, "read-only")?;
    Ok(prepared)
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
        let prepared = prepare_seatbelt_config(config)?;
        Ok(seatbelt::build(&prepared, project_dir, verbose))
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
        let prepared = prepare_seatbelt_config(config)?;
        Ok(seatbelt::dry_run(&prepared, project_dir, verbose))
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
    fn project_config_dangerous_opt_ins_lists_enabled_features() {
        let project = temp_test_dir("dangerous-optins");
        std::fs::create_dir_all(&project).unwrap();

        let default = Config::default();
        assert!(
            project_config_dangerous_opt_ins(&default, &project).is_empty()
        );

        let all_on = Config {
            no_docker: Some(false),
            tailscale: Some(true),
            ssh: Some(true),
            pictures: Some(true),
            systemd_user: Some(true),
            ..Config::default()
        };
        let items = project_config_dangerous_opt_ins(&all_on, &project);
        assert!(items.iter().any(|i| i.contains("Docker")));
        assert!(items.iter().any(|i| i.contains("Tailscale")));
        assert!(items.iter().any(|i| i.contains("SSH")));
        assert!(items.iter().any(|i| i.contains("Pictures")));
        assert!(items.iter().any(|i| i.contains("systemd")));
    }

    #[test]
    fn project_config_dangerous_opt_ins_lists_outside_maps() {
        let project = temp_test_dir("outside-maps");
        std::fs::create_dir_all(&project).unwrap();
        let outside = PathBuf::from("/tmp/ai-jail-audit-outside");

        let cfg = Config {
            rw_maps: vec![outside.clone()],
            ro_maps: vec![outside.clone()],
            overlay_maps: vec![outside.clone()],
            ..Config::default()
        };
        let items = project_config_dangerous_opt_ins(&cfg, &project);
        assert!(items.iter().any(|i| i.starts_with("rw-map ")));
        assert!(items.iter().any(|i| i.starts_with("ro-map ")));
        assert!(items.iter().any(|i| i.starts_with("overlay-map ")));

        let inside = project.join("src");
        let cfg = Config {
            rw_maps: vec![inside.clone()],
            ..Config::default()
        };
        assert!(project_config_dangerous_opt_ins(&cfg, &project).is_empty());

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn warn_project_config_opt_ins_diffs_against_baseline() {
        let project = temp_test_dir("warn-diff");
        std::fs::create_dir_all(&project).unwrap();
        let outside = PathBuf::from("/tmp/ai-jail-warn-outside");

        let project_cfg = Config {
            ssh: Some(true),
            pictures: Some(true),
            rw_maps: vec![outside.clone()],
            ..Config::default()
        };
        let baseline = Config::default();
        let project_items =
            project_config_dangerous_opt_ins(&project_cfg, &project);
        let baseline_items =
            project_config_dangerous_opt_ins(&baseline, &project);
        let new_items: Vec<_> = project_items
            .into_iter()
            .filter(|item| !baseline_items.contains(item))
            .collect();

        assert!(new_items.iter().any(|i| i.contains("SSH")));
        assert!(new_items.iter().any(|i| i.contains("Pictures")));
        assert!(new_items.iter().any(|i| i.starts_with("rw-map ")));

        // If the baseline already has the capability, it is not flagged.
        let baseline_with_ssh = Config {
            ssh: Some(true),
            ..Config::default()
        };
        let baseline_items =
            project_config_dangerous_opt_ins(&baseline_with_ssh, &project);
        let new_items: Vec<_> = project_config_dangerous_opt_ins(
            &Config {
                ssh: Some(true),
                ..Config::default()
            },
            &project,
        )
        .into_iter()
        .filter(|item| !baseline_items.contains(item))
        .collect();
        assert!(!new_items.iter().any(|i| i.contains("SSH")));

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn docker_passthrough_requires_explicit_opt_in() {
        // Issue #88: unset no_docker must not expose the socket even
        // when it exists on the host.
        let default_config = Config::default();
        assert!(!docker_passthrough_active(&default_config, true));

        let opted_in = Config {
            no_docker: Some(false),
            ..Config::default()
        };
        assert!(docker_passthrough_active(&opted_in, true));
        assert!(!docker_passthrough_active(&opted_in, false));
    }

    #[test]
    fn docker_passthrough_stays_off_in_lockdown_and_browser_modes() {
        let lockdown = Config {
            no_docker: Some(false),
            lockdown: Some(true),
            ..Config::default()
        };
        assert!(!docker_passthrough_active(&lockdown, true));

        let browser = Config {
            no_docker: Some(false),
            browser_profile: Some("hard".into()),
            ..Config::default()
        };
        assert!(!docker_passthrough_active(&browser, true));
    }

    #[test]
    fn seatbelt_config_rejects_alternate_map_destinations() {
        let config = Config {
            ro_maps: vec![PathBuf::from("/host/data:/jail/data")],
            ..Config::default()
        };

        let error = prepare_seatbelt_config(&config).unwrap_err();

        assert!(error.contains("alternate map destinations"));
        assert!(error.contains("Linux/bubblewrap"));
    }

    #[test]
    fn seatbelt_config_keeps_existing_same_path_maps() {
        let path = temp_test_dir("seatbelt-map-existing");
        std::fs::create_dir_all(&path).unwrap();
        let config = Config {
            rw_maps: vec![path.clone()],
            ..Config::default()
        };

        let prepared = prepare_seatbelt_config(&config).unwrap();

        assert_eq!(prepared.rw_maps, vec![path.clone()]);
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn seatbelt_config_skips_invalid_and_missing_same_path_maps() {
        let config = Config {
            ro_maps: vec![
                PathBuf::from("/"),
                PathBuf::from(":/invalid"),
                PathBuf::from("/definitely/missing/ai-jail-map"),
            ],
            ..Config::default()
        };

        let prepared = prepare_seatbelt_config(&config).unwrap();

        assert!(prepared.ro_maps.is_empty());
    }

    #[test]
    fn expand_mask_patterns_keeps_literal_project_relative() {
        let project = PathBuf::from("/tmp/project");
        let expanded =
            expand_mask_patterns(&[PathBuf::from(".env")], &[], &project);

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
            expand_mask_patterns(&[PathBuf::from("**/*.env")], &[], &project);

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

        let expanded = expand_mask_patterns(
            &[PathBuf::from("app[1-2].env")],
            &[],
            &project,
        );
        assert_eq!(
            expanded,
            vec![project.join("app1.env"), project.join("app2.env")]
        );

        let expanded =
            expand_mask_patterns(&[PathBuf::from("app?.env")], &[], &project);
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

        let expanded = expand_mask_patterns(
            &[PathBuf::from("../shared/*.env")],
            &[],
            &project,
        );

        assert_eq!(expanded, vec![shared.join("secret.env")]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn expand_mask_patterns_applies_scoped_exceptions_and_keeps_bangs_positive()
    {
        let root = temp_test_dir("mask-exceptions");
        let project = root.join("project");
        std::fs::create_dir_all(project.join("target")).unwrap();
        std::fs::create_dir_all(project.join("other/target")).unwrap();
        std::fs::write(project.join("app.key"), "key").unwrap();
        std::fs::write(project.join("target/generated.key"), "key").unwrap();
        std::fs::write(project.join("other/target/kept.key"), "key").unwrap();
        std::fs::write(project.join("!secret.txt"), "key").unwrap();
        std::fs::write(project.join("!glob.key"), "key").unwrap();

        let expanded = expand_mask_patterns(
            &[PathBuf::from("**/*.key"), PathBuf::from("!secret.txt")],
            &[PathBuf::from("target/**")],
            &project,
        );

        assert_eq!(
            expanded,
            vec![
                project.join("!glob.key"),
                project.join("app.key"),
                project.join("other/target/kept.key"),
                project.join("!secret.txt"),
            ]
        );

        let issue_pattern = expand_mask_patterns(
            &[PathBuf::from("**/*.key")],
            &[PathBuf::from("**/target/**")],
            &project,
        );
        assert_eq!(
            issue_pattern,
            vec![project.join("!glob.key"), project.join("app.key")]
        );

        let scoped = expand_mask_patterns(
            &[PathBuf::from("**/*.key")],
            &[PathBuf::from("target/**/*.key")],
            &project,
        );
        assert!(!scoped.contains(&project.join("target/generated.key")));
        assert!(scoped.contains(&project.join("other/target/kept.key")));

        let literal = expand_mask_patterns(
            &[PathBuf::from("target/generated.key")],
            &[PathBuf::from("target")],
            &project,
        );
        assert!(literal.is_empty());

        let bang_glob =
            expand_mask_patterns(&[PathBuf::from("!*.key")], &[], &project);
        assert_eq!(bang_glob, vec![project.join("!glob.key")]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exception_bases_are_scoped_for_absolute_parent_and_missing_paths() {
        let root = temp_test_dir("exception-bases");
        let project = root.join("repo/project");
        let shared = root.join("repo/shared");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(project.join("local.key"), "key").unwrap();
        std::fs::write(shared.join("shared.key"), "key").unwrap();
        let includes =
            vec![project.join("local.key"), shared.join("shared.key")];

        let parent = expand_mask_patterns(
            &includes,
            &[PathBuf::from("../shared/**")],
            &project,
        );
        assert_eq!(parent, vec![project.join("local.key")]);

        let absolute =
            expand_mask_patterns(&includes, &[shared.join("**")], &project);
        assert_eq!(absolute, vec![project.join("local.key")]);

        let missing = expand_mask_patterns(
            &includes,
            &[PathBuf::from("typo/**")],
            &project,
        );
        assert_eq!(missing, includes);
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
            ".kimi-code",
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
            ".cargo",
            ".cache",
            ".config",
            ".claude",
            ".gemini",
            ".kiro",
            ".omp",
            ".pi",
            ".pi-lens",
            ".kimi-code",
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
        assert!(is_dotdir_rw(".kimi-code"));
        assert!(is_dotdir_rw("kimi-code"));
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
    fn command_home_paths_include_managed_outer_and_inner_executables() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-managed-cmd-home-{}", std::process::id()));
        let outer_dir = home.join(".local/bin");
        let inner_dir = home.join("tools/codex");
        std::fs::create_dir_all(&outer_dir).unwrap();
        std::fs::create_dir_all(&inner_dir).unwrap();
        let outer = outer_dir.join("ai-memory");
        let inner = inner_dir.join("codex-custom");
        std::fs::write(&outer, "#!/bin/sh\n").unwrap();
        std::fs::write(&inner, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &outer,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(
            &inner,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _path = EnvVarGuard::set("PATH", outer_dir.as_os_str());
        let config = Config {
            command: vec![
                "ai-memory".into(),
                "run".into(),
                "--executable".into(),
                inner.display().to_string(),
                "codex".into(),
            ],
            ..Config::default()
        };

        assert_eq!(command_home_paths(&config), vec![outer_dir, inner_dir]);
        let _ = std::fs::remove_dir_all(home);
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

    fn docker_socket_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-docker-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn docker_socket_prefers_reachable_docker_host() {
        let _lock = crate::test_utils::ENV_LOCK.lock().unwrap();
        let root = docker_socket_fixture("host");
        let sock = root.join("podman.sock");
        std::fs::File::create(&sock).unwrap();
        let _guard = crate::test_utils::EnvVarGuard::set(
            "DOCKER_HOST",
            format!("unix://{}", sock.display()),
        );

        // Wins over the well-known paths whether or not they exist.
        assert_eq!(docker_socket(), Some(sock));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn docker_socket_skips_unreachable_docker_host() {
        // Backward compat: a stale or unreachable $DOCKER_HOST must
        // not suppress the candidates behind it.
        let _lock = crate::test_utils::ENV_LOCK.lock().unwrap();
        let root = docker_socket_fixture("stale");
        let missing = root.join("gone.sock");
        let _guard = crate::test_utils::EnvVarGuard::set(
            "DOCKER_HOST",
            format!("unix://{}", missing.display()),
        );

        let resolved = docker_socket();

        assert_ne!(resolved, Some(missing));
        // Whatever is left is one of the well-known paths, or nothing
        // — this runs on hosts with and without a Docker socket.
        if let Some(p) = resolved {
            let well_known = [
                PathBuf::from("/var/run/docker.sock"),
                home_dir().join(".docker/run/docker.sock"),
            ];
            assert!(
                well_known.iter().any(|candidate| candidate == &p),
                "unexpected fallback: {}",
                p.display()
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn docker_host_socket_path_accepts_only_absolute_unix_paths() {
        assert_eq!(
            docker_host_socket_path("unix:///run/user/1000/podman/podman.sock"),
            Some(PathBuf::from("/run/user/1000/podman/podman.sock"))
        );

        // No socket path to bind for these: tcp/ssh reach the daemon
        // over the network, npipe is Windows-only.
        for value in [
            "tcp://localhost:2375",
            "ssh://user@host",
            "npipe:////./pipe/docker_engine",
            "/run/user/1000/podman/podman.sock",
            // Relative path — not something we can bind.
            "unix://run/user/1000/podman/podman.sock",
        ] {
            assert_eq!(docker_host_socket_path(value), None, "for {value}");
        }
    }

    #[test]
    fn docker_socket_ignores_non_unix_docker_host() {
        // A tcp:// endpoint must resolve exactly as an unset
        // $DOCKER_HOST does: to the well-known paths only.
        let _lock = crate::test_utils::ENV_LOCK.lock().unwrap();

        let guard = crate::test_utils::EnvVarGuard::remove("DOCKER_HOST");
        let unset = docker_socket();
        drop(guard);

        let _guard = crate::test_utils::EnvVarGuard::set(
            "DOCKER_HOST",
            "tcp://localhost:2375",
        );
        assert_eq!(docker_socket(), unset);
    }

    #[test]
    fn docker_socket_rejects_unfollowable_symlink() {
        // Regression: /var/run/docker.sock -> /run/podman/podman.sock
        // with /run/podman mode 0700 root. path_exists() accepts the
        // dangling link, and bwrap then aborts the whole launch with
        // "Can't find source path: Permission denied".
        let _lock = crate::test_utils::ENV_LOCK.lock().unwrap();
        let root = docker_socket_fixture("symlink");
        let hidden = root.join("hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        let target = hidden.join("podman.sock");
        std::fs::File::create(&target).unwrap();
        let link = root.join("docker.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        std::fs::set_permissions(
            &hidden,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();

        // Root traverses mode-000 directories; nothing to assert.
        if std::fs::metadata(&target).is_ok() {
            let _ = std::fs::set_permissions(
                &hidden,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
            let _ = std::fs::remove_dir_all(&root);
            return;
        }

        assert!(path_exists(&link), "lstat still succeeds on the link");
        assert!(!docker_socket_usable(&link));

        let _guard = crate::test_utils::EnvVarGuard::set(
            "DOCKER_HOST",
            format!("unix://{}", link.display()),
        );
        assert_ne!(docker_socket(), Some(link));

        let _ = std::fs::set_permissions(
            &hidden,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        );
        let _ = std::fs::remove_dir_all(&root);
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
