use crate::config::Config;
use crate::output;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct SandboxGuard;

pub fn check() -> Result<(), String> {
    let path = Path::new("/usr/bin/sandbox-exec");
    if path.is_file() {
        Ok(())
    } else {
        Err("sandbox-exec not found at /usr/bin/sandbox-exec. \
             This tool is required for sandboxing on macOS."
            .into())
    }
}

pub fn platform_notes(config: &Config) {
    output::warn(
        "macOS backend uses deprecated sandbox-exec; treat this as legacy containment.",
    );
    if !config.gpu_enabled() {
        output::info("--no-gpu has no effect on macOS (Metal is system-level)");
    }
    if !config.display_enabled() {
        output::info(
            "--no-display has no effect on macOS (Cocoa is system-level)",
        );
    }
    if config.systemd_user_enabled() {
        output::warn("--systemd-user has no effect on macOS");
    }
    if config.tailscale_enabled() {
        output::warn(
            "--tailscale has no effect on macOS (no socket bind; \
             tailscaled is reachable only if seatbelt network rules \
             already allow it)",
        );
    }
    if !config.allow_tcp_ports().is_empty() && config.lockdown_enabled() {
        output::warn(
            "--allow-tcp-port has no effect on macOS \
             lockdown (seatbelt blocks all network)",
        );
    }
    if !config.overlay_maps.is_empty() {
        output::warn(
            "overlay maps are read-only on macOS (no overlayfs); \
             writes to those paths will be denied",
        );
    }
}

pub fn build(config: &Config, project_dir: &Path, verbose: bool) -> Command {
    let lockdown = config.lockdown_enabled();
    let profile = build_profile(config, project_dir, verbose);
    let launch = super::build_launch_command(config);

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(&profile);
    cmd.arg("--");
    cmd.arg(&launch.program);
    cmd.args(&launch.args);
    cmd.current_dir(project_dir);

    if lockdown {
        cmd.env_clear();
        cmd.env("PATH", super::LOCKDOWN_PATH);
        cmd.env("HOME", super::home_dir());
        // Pass through terminal-related env vars so child
        // programs can detect capabilities (truecolor, kitty
        // keyboard protocol, etc.).
        for &var in super::TERM_ENV_VARS {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }
    }

    cmd.env("PS1", super::JAIL_PS1);
    cmd.env("_ZO_DOCTOR", "0");

    if let Some(dir) = &config.claude_dir {
        cmd.env("CLAUDE_CONFIG_DIR", dir);
    }

    cmd
}

pub fn dry_run(config: &Config, project_dir: &Path, verbose: bool) -> String {
    let profile = build_profile(config, project_dir, verbose);
    let launch = super::build_launch_command(config);

    let mut command_line = String::from("sandbox-exec -p '<profile>' -- ");
    command_line.push_str(&super::quote_shell_arg(&launch.program));
    for arg in &launch.args {
        command_line.push(' ');
        command_line.push_str(&super::quote_shell_arg(arg));
    }

    format_dry_run_macos(&command_line, &profile)
}

fn build_profile(config: &Config, project_dir: &Path, verbose: bool) -> String {
    let profile = generate_sbpl_profile(
        config,
        project_dir,
        config.docker_enabled(),
        config.lockdown_enabled(),
    );

    if verbose {
        output::verbose("SBPL profile:");
        for line in profile.lines() {
            output::verbose(&format!("  {line}"));
        }
    }

    profile
}

fn canonicalize_or_keep(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Append one character to an SBPL-string-escaped output. Shared
/// between `sbpl_escape` (plain literal) and `sbpl_regex_escape`
/// (regex literal — adds metacharacter escaping on top).
fn push_sbpl_escaped(c: char, out: &mut String) {
    match c {
        '\\' => out.push_str("\\\\"),
        '"' => out.push_str("\\\""),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ => out.push(c),
    }
}

fn sbpl_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        push_sbpl_escaped(c, &mut out);
    }
    out
}

/// Escape a literal path for use as an SBPL regex pattern.
/// Escapes both regex metacharacters and SBPL string characters.
fn sbpl_regex_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            // Regex metacharacters get a single backslash; the SBPL
            // string-escape pass below then escapes that backslash again.
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^'
            | '$' | '|' => {
                out.push('\\');
                out.push(c);
            }
            _ => push_sbpl_escaped(c, &mut out),
        }
    }
    out
}

fn sbpl_path(p: &Path) -> String {
    sbpl_escape(canonicalize_or_keep(p).to_string_lossy().as_ref())
}

fn generate_sbpl_profile(
    config: &Config,
    project_dir: &Path,
    enable_docker: bool,
    lockdown: bool,
) -> String {
    let browser_mode = config.browser_profile().is_some();
    let private_home = config.private_home_enabled();
    let restricted_files = lockdown || browser_mode || private_home;
    let exempt = super::dotdir_exemptions(config);
    let mut deny_paths = macos_read_deny_paths(&config.hide_dotdirs, &exempt);
    deny_paths.extend(super::expand_mask_patterns(&config.mask, project_dir));
    let explicit_deny_paths =
        super::expand_mask_patterns(&config.deny_paths, project_dir);
    deny_paths.extend(explicit_deny_paths.clone());
    let writable_paths = macos_writable_paths(project_dir, config, lockdown);
    let atomic_paths = macos_atomic_write_paths(config);

    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    push_static_sections(&mut profile);
    push_network_section(&mut profile, lockdown);
    push_file_read_section(
        &mut profile,
        config,
        project_dir,
        restricted_files,
        &deny_paths,
    );
    push_file_write_section(
        &mut profile,
        lockdown,
        &writable_paths,
        &atomic_paths,
        &explicit_deny_paths,
    );
    push_docker_section(&mut profile, lockdown, enable_docker);

    profile
}

/// Emit an allow/deny rule for a single host path. Uses `subpath` if
/// the path is (or will be) a directory, otherwise `literal`. This is
/// the helper that used to be open-coded four times inside
/// generate_sbpl_profile.
fn push_path_rule(profile: &mut String, verb: &str, action: &str, path: &Path) {
    let canonical = canonicalize_or_keep(path);
    let escaped = sbpl_escape(canonical.to_string_lossy().as_ref());
    let pattern = if canonical.is_dir() || !canonical.exists() {
        "subpath"
    } else {
        "literal"
    };
    profile.push_str(&format!("({verb} {action} ({pattern} \"{escaped}\"))\n"));
}

/// Sections that don't depend on config — process, IPC, ptys,
/// devices, IOKit. Always emitted first so the file structure is
/// predictable across modes.
fn push_static_sections(profile: &mut String) {
    profile.push_str("; Process operations\n");
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow process-info* (target same-sandbox))\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow sysctl-read)\n\n");

    profile.push_str("; IPC and Mach\n");
    profile.push_str("(allow mach-lookup)\n");
    profile.push_str("(allow mach-register)\n");
    profile.push_str("(allow mach-host*)\n");
    profile.push_str("(allow ipc-posix-shm-read-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n");
    profile.push_str("(allow ipc-posix-shm-read-metadata)\n");
    profile.push_str("(allow ipc-posix-shm-write-create)\n");
    profile.push_str("(allow ipc-posix-sem)\n\n");

    profile.push_str("; Pseudo-terminal and ioctl\n");
    profile.push_str("(allow pseudo-tty)\n");
    profile.push_str("(allow file-ioctl)\n");
    profile
        .push_str("(allow file-read* file-write* (literal \"/dev/ptmx\"))\n");
    profile.push_str(
        "(allow file-read* file-write* (regex #\"^/dev/ttys[0-9]+\"))\n\n",
    );

    profile.push_str("; Standard devices\n");
    profile.push_str("(allow file-write* (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/zero\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/random\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/urandom\"))\n\n");

    profile.push_str("; IOKit (power management, hardware queries)\n");
    profile.push_str("(allow iokit-open)\n\n");
}

fn push_network_section(profile: &mut String, lockdown: bool) {
    if lockdown {
        return;
    }
    profile.push_str("; Network\n");
    profile.push_str("(allow network-outbound)\n");
    profile.push_str("(allow network-inbound)\n");
    profile.push_str("(allow network-bind)\n");
    profile.push_str("(allow system-socket)\n\n");
}

fn push_file_read_section(
    profile: &mut String,
    config: &Config,
    project_dir: &Path,
    restricted_files: bool,
    deny_paths: &[PathBuf],
) {
    if restricted_files {
        profile.push_str("; File reads: restricted allow-list\n");
        // The root node itself must be readable, or the dyld loader on
        // macOS 26 (Tahoe) can't resolve absolute paths and every
        // dynamically-linked process aborts with SIGABRT before it runs.
        // This is a `literal` (not `subpath`) rule on purpose: it grants
        // read of `/` alone — listing top-level names — without opening
        // up any subtree the allow-list below hasn't already granted.
        profile.push_str("(allow file-read* (literal \"/\"))\n");
        for rd_path in macos_lockdown_read_paths(config, project_dir) {
            push_path_rule(profile, "allow", "file-read*", &rd_path);
        }
        profile.push('\n');
        profile.push_str("; Deny sensitive home paths explicitly\n");
    } else {
        profile
            .push_str("; File reads: allow globally, deny sensitive paths\n");
        profile.push_str("(allow file-read*)\n");
    }
    for deny_path in deny_paths {
        push_path_rule(profile, "deny", "file-read*", deny_path);
    }
    profile.push('\n');
}

fn push_file_write_section(
    profile: &mut String,
    lockdown: bool,
    writable_paths: &[PathBuf],
    atomic_paths: &[PathBuf],
    deny_paths: &[PathBuf],
) {
    if lockdown {
        for deny_path in deny_paths {
            push_path_rule(profile, "deny", "file-write*", deny_path);
        }
        profile.push_str("; Lockdown: no host file-write allowances\n\n");
        return;
    }
    profile.push_str("; File writes: allow specific paths\n");
    for wr_path in writable_paths {
        push_path_rule(profile, "allow", "file-write*", wr_path);
    }
    if !atomic_paths.is_empty() {
        profile.push('\n');
        profile.push_str(
            "; Atomic-write paths (literal + bounded temp siblings)\n",
        );
        for ap in atomic_paths {
            let canonical = canonicalize_or_keep(ap);
            let path_str = canonical.to_string_lossy();
            let escaped = sbpl_escape(&path_str);
            profile.push_str(&format!(
                "(allow file-write* (literal \"{escaped}\"))\n"
            ));
            let regex_escaped = sbpl_regex_escape(&path_str);
            let siblings = format!(
                "^{regex_escaped}(\\.tmp\\.[0-9]+\\.[0-9a-f]+|\\.lock)$"
            );
            profile.push_str(&format!(
                "(allow file-write* (regex #\"{siblings}\"))\n"
            ));
        }
    }
    for deny_path in deny_paths {
        push_path_rule(profile, "deny", "file-write*", deny_path);
    }
    profile.push('\n');
}

fn push_docker_section(
    profile: &mut String,
    lockdown: bool,
    enable_docker: bool,
) {
    if lockdown || !enable_docker {
        return;
    }
    let Some(sock) = macos_docker_socket() else {
        return;
    };
    let escaped = sbpl_path(&sock);
    profile.push_str("; Docker socket\n");
    profile.push_str(&format!("(allow file-write* (literal \"{escaped}\"))\n"));
    profile.push('\n');
}

fn format_dry_run_macos(command_line: &str, profile: &str) -> String {
    let mut out = String::new();
    out.push_str("# sandbox-exec command:\n");
    out.push_str(command_line);
    out.push('\n');
    out.push_str("\n# SBPL profile:\n");
    out.push_str(profile);
    out
}

fn macos_read_deny_paths(
    hide_dotdirs: &[String],
    exempt: &[&str],
) -> Vec<PathBuf> {
    let home = super::home_dir();

    let mut candidates: Vec<PathBuf> =
        super::denied_dotdirs(hide_dotdirs, exempt)
            .map(|name| home.join(format!(".{}", name)))
            .collect();

    candidates.extend([
        home.join("Library/Mail"),
        home.join("Library/Messages"),
        home.join("Library/Safari"),
        home.join("Library/Cookies"),
    ]);

    candidates
        .into_iter()
        .filter(|p| super::path_exists(p))
        .collect()
}

fn macos_writable_paths(
    project_dir: &Path,
    config: &Config,
    lockdown: bool,
) -> Vec<PathBuf> {
    if lockdown {
        return Vec::new();
    }

    let home = super::home_dir();
    let mut paths = Vec::new();

    let browser_mode = config.browser_profile().is_some();
    let private_home = config.private_home_enabled();

    if browser_mode {
        if let Some(state) = super::browser_state_dir(config) {
            let _ = std::fs::create_dir_all(&state);
            paths.push(state);
        }
        paths.push(PathBuf::from("/tmp"));
        paths.push(PathBuf::from("/private/tmp"));
        paths.push(PathBuf::from("/private/var/tmp"));
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let p = PathBuf::from(&tmpdir);
            if super::path_exists(&p) {
                paths.push(canonicalize_or_keep(&p));
            }
        }
        paths.push(PathBuf::from("/private/var/folders"));
        return paths;
    }

    paths.push(project_dir.to_path_buf());

    if let Some(worktree) =
        super::discover_git_worktree_paths(config, project_dir, false)
    {
        paths.extend(worktree.unique_paths());
    }

    if !private_home {
        for name in super::DOTDIR_RW {
            let p = home.join(name);
            if super::path_exists(&p) {
                paths.push(p);
            }
        }

        let local = home.join(".local");
        if super::path_exists(&local) {
            paths.push(local);
        }
    }

    if let Some(dir) = &config.claude_dir
        && super::path_exists(dir)
    {
        paths.push(dir.clone());
    }

    paths.push(PathBuf::from("/tmp"));
    paths.push(PathBuf::from("/private/tmp"));
    paths.push(PathBuf::from("/private/var/tmp"));

    // macOS per-user temp dir ($TMPDIR -> /private/var/folders/.../T/)
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let p = PathBuf::from(&tmpdir);
        if super::path_exists(&p) {
            paths.push(canonicalize_or_keep(&p));
        }
    }
    // Fallback: allow the entire /private/var/folders tree
    paths.push(PathBuf::from("/private/var/folders"));

    // macOS-native caches (Xcode tooling, Homebrew, etc.)
    if !private_home {
        let lib_caches = home.join("Library/Caches");
        if super::path_exists(&lib_caches) {
            paths.push(lib_caches);
        }
    }

    for p in &config.rw_maps {
        if super::path_exists(p) {
            paths.push(p.clone());
        }
    }

    paths
}

fn macos_atomic_write_paths(config: &Config) -> Vec<PathBuf> {
    if config.private_home_enabled() || config.lockdown_enabled() {
        return Vec::new();
    }
    let claude_json = super::home_dir().join(".claude.json");
    if claude_json.is_file() {
        vec![claude_json]
    } else {
        Vec::new()
    }
}

fn macos_docker_socket() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("/var/run/docker.sock"),
        super::home_dir().join(".docker/run/docker.sock"),
    ];
    candidates.into_iter().find(|p| super::path_exists(p))
}

fn macos_lockdown_read_paths(
    config: &Config,
    project_dir: &Path,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !paths.contains(&p) {
            paths.push(p);
        }
    };

    // Always allow reading the project tree.
    push_unique(canonicalize_or_keep(project_dir));

    if let Some(worktree) =
        super::discover_git_worktree_paths(config, project_dir, false)
    {
        for path in worktree.unique_paths() {
            push_unique(canonicalize_or_keep(&path));
        }
    }

    // Overlay maps degrade to read-only on macOS (no overlayfs), so
    // they are always readable but never writable. Writes are denied
    // because the paths are not in the writable set — this protects
    // the original directory. A warning is emitted in platform_notes.
    for p in &config.overlay_maps {
        if super::path_exists(p) {
            push_unique(canonicalize_or_keep(p));
        }
    }

    // Core runtime and toolchain locations needed to execute binaries
    // and resolve dynamic libraries on macOS.
    for p in [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/etc",
        "/private/etc",
        "/Library",
        "/Applications",
        "/dev",
        "/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/private/var/folders",
        "/private/var/db",
    ] {
        let pb = PathBuf::from(p);
        if super::path_exists(&pb) {
            push_unique(pb);
        }
    }

    let browser_mode = config.browser_profile().is_some();
    let private_home = config.private_home_enabled();

    if browser_mode && let Some(state) = super::browser_state_dir(config) {
        push_unique(canonicalize_or_keep(&state));
    }

    if !private_home {
        for filename in [".gitconfig", ".gitignore"] {
            let git_file = super::home_dir().join(filename);
            if git_file.is_file() {
                push_unique(canonicalize_or_keep(&git_file));
            }
        }
        // XDG-style global git settings: $XDG_CONFIG_HOME/git/{config,ignore,...}
        // (defaults to $HOME/.config/git when XDG_CONFIG_HOME is unset).
        // Push the directory; push_path_rule emits a subpath allow that
        // covers every file Git reads from there.
        let xdg_git = super::xdg_config_home().join("git");
        if xdg_git.is_dir() {
            push_unique(canonicalize_or_keep(&xdg_git));
        }
    }

    if private_home && !browser_mode && !config.lockdown_enabled() {
        for p in config.rw_maps.iter().chain(config.ro_maps.iter()) {
            if super::path_exists(p) {
                push_unique(canonicalize_or_keep(p));
            }
        }
        if config.ssh_enabled() {
            let ssh_dir = super::home_dir().join(".ssh");
            if ssh_dir.is_dir() {
                push_unique(canonicalize_or_keep(&ssh_dir));
            }
        }
        if config.pictures_enabled() {
            let pictures = super::home_dir().join("Pictures");
            if pictures.is_dir() {
                push_unique(canonicalize_or_keep(&pictures));
            }
        }
    }

    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let p = PathBuf::from(tmpdir);
        if super::path_exists(&p) {
            push_unique(canonicalize_or_keep(&p));
        }
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::test_support::linked_worktree_fixture;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    fn create_linked_worktree_fixture()
    -> crate::sandbox::test_support::LinkedWorktreeFixture {
        linked_worktree_fixture("seatbelt-worktree")
    }

    #[test]
    fn sbpl_profile_has_deny_default() {
        let config = Config {
            command: vec!["bash".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project, false, false);
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn sbpl_profile_allows_network_by_default() {
        let config = Config::default();
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project, false, false);
        assert!(profile.contains("(allow network-outbound)"));
        assert!(profile.contains("(allow network-inbound)"));
        assert!(profile.contains("(allow file-read*)"));
    }

    #[test]
    fn sbpl_profile_denies_deny_paths_for_read_and_write() {
        let config = Config {
            deny_paths: vec![PathBuf::from(".env")],
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project, false, false);
        assert!(profile.contains(
            "(deny file-read* (subpath \"/tmp/test-project/.env\"))"
        ));
        assert!(profile.contains(
            "(deny file-write* (subpath \"/tmp/test-project/.env\"))"
        ));
    }

    #[test]
    fn sbpl_profile_lockdown_disables_network_and_writes() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project, false, true);
        assert!(!profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(allow file-read*)\n"));
        assert!(
            profile
                .contains("(allow file-read* (subpath \"/tmp/test-project\"))")
        );
        // Lockdown should have no path-based write allowances (project, dotfiles, tmp)
        // but still allows device writes (/dev/null etc.) and PTY writes
        assert!(profile.contains("no host file-write allowances"));
        assert!(!profile.contains("(allow file-write* (subpath"));
    }

    #[test]
    fn sbpl_profile_escapes_quotes_in_paths() {
        let escaped = sbpl_escape("/tmp/with\"quote");
        assert_eq!(escaped, "/tmp/with\\\"quote");
    }

    #[test]
    fn regression_sbpl_escape_controls() {
        let escaped = sbpl_escape("line1\nline2\t\\");
        assert_eq!(escaped, "line1\\nline2\\t\\\\");
    }

    #[test]
    fn sbpl_regex_escape_dots_and_specials() {
        // Dots must be escaped so they match literally in the regex
        let escaped = sbpl_regex_escape("/Users/user/.claude.json");
        assert_eq!(escaped, "/Users/user/\\.claude\\.json");
    }

    #[test]
    fn sbpl_regex_escape_handles_all_metacharacters() {
        let escaped = sbpl_regex_escape("/a.b*c+d?e(f)g[h]i{j}k^l$m|n");
        assert_eq!(
            escaped,
            "/a\\.b\\*c\\+d\\?e\\(f\\)g\\[h\\]i\\{j\\}k\\^l\\$m\\|n"
        );
    }

    #[test]
    fn atomic_paths_gets_bounded_atomic_write_rules() {
        let _env = ENV_LOCK.lock().unwrap();
        use std::fs;
        let fake_home = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-atomic-{}", std::process::id()));
        fs::create_dir_all(&fake_home).unwrap();
        let claude_json = fake_home.join(".claude.json");
        fs::write(&claude_json, "{}").unwrap();
        let _home = EnvVarGuard::set("HOME", fake_home.as_os_str());

        let config = Config {
            no_mise: Some(true),
            ..Config::default()
        };
        let profile = generate_sbpl_profile(
            &config,
            Path::new("/tmp/proj"),
            false,
            false,
        );

        let canonical = canonicalize_or_keep(&claude_json);
        let path_str = canonical.to_string_lossy();
        let regex_escaped = sbpl_regex_escape(&path_str);

        let _ = fs::remove_dir_all(&fake_home);

        assert!(
            profile.contains(&format!(
                "(allow file-write* (literal \"{path_str}\"))"
            )),
            ".claude.json must have a literal write rule"
        );
        let bounded = format!(
            "(allow file-write* (regex #\"^{regex_escaped}\
             (\\.tmp\\.[0-9]+\\.[0-9a-f]+|\\.lock)$\"))"
        );
        assert!(
            profile.contains(&bounded),
            ".claude.json must have a bounded temp-sibling regex rule"
        );
        // Unbounded prefix would grant access to unrelated paths like
        // .claude.json.bak — the regex must be anchored at both ends.
        assert!(
            !profile.contains(&format!(
                "(allow file-write* (regex #\"^{regex_escaped}\"))"
            )),
            "regex must not be an unbounded prefix"
        );
    }

    #[test]
    fn dry_run_macos_output() {
        let config = Config {
            command: vec!["bash".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let output = dry_run(&config, &project, false);
        assert!(output.contains("sandbox-exec"));
        assert!(output.contains("SBPL profile"));
    }

    #[test]
    fn macos_writable_paths_empty_in_lockdown() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let paths = macos_writable_paths(&project, &config, true);
        assert!(paths.is_empty());
    }

    #[test]
    fn private_home_writable_paths_skip_host_home_state() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-seatbelt-private-home-{}",
            std::process::id()
        ));
        let project = home.join("project");
        let extra = home.join("extra");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::create_dir_all(home.join(".local")).unwrap();
        std::fs::create_dir_all(home.join("Library/Caches")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&extra).unwrap();
        let _home = EnvVarGuard::set("HOME", home.as_os_str());

        let config = Config {
            private_home: Some(true),
            rw_maps: vec![extra.clone()],
            ..Config::default()
        };
        let paths = macos_writable_paths(&project, &config, false);

        assert!(paths.contains(&project));
        assert!(paths.contains(&extra));
        assert!(!paths.contains(&home.join(".config")));
        assert!(!paths.contains(&home.join(".local")));
        assert!(!paths.contains(&home.join("Library/Caches")));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn private_home_profile_uses_restricted_reads() {
        let config = Config {
            private_home: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project, false, false);
        assert!(profile.contains("; File reads: restricted allow-list"));
        assert!(!profile.contains("(allow file-read*)\n"));
    }

    #[test]
    fn restricted_reads_allow_root_node() {
        // Regression: without a read rule on the root node itself, the
        // dyld loader on macOS 26 aborts every dynamically-linked process
        // with SIGABRT. Must be `literal "/"` (not `subpath "/"`, which
        // would grant read of the whole filesystem). All three restricted
        // modes (private-home, lockdown, browser) need it.
        let private_home = Config {
            private_home: Some(true),
            ..Config::default()
        };
        let lockdown = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let browser = Config {
            browser_profile: Some("soft".into()),
            ..Config::default()
        };
        let cases = [
            ("private-home", private_home, false),
            ("lockdown", lockdown, true),
            ("browser", browser, false),
        ];
        for (mode, config, lockdown) in cases {
            let project = PathBuf::from("/tmp/test-project");
            let profile =
                generate_sbpl_profile(&config, &project, false, lockdown);
            assert!(
                profile.contains("(allow file-read* (literal \"/\"))"),
                "restricted read profile must grant the root node ({mode})"
            );
            assert!(
                !profile.contains("(allow file-read* (subpath \"/\"))"),
                "must not grant subpath / (would expose everything, {mode})"
            );
        }
    }

    #[test]
    fn lockdown_read_paths_include_project() {
        let project = PathBuf::from("/tmp/test-project");
        let paths = macos_lockdown_read_paths(&Config::default(), &project);
        assert!(paths.contains(&project));
    }

    #[test]
    fn lockdown_read_paths_include_home_gitignore() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-seatbelt-gitignore-home-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let gitignore = home.join(".gitignore");
        std::fs::write(&gitignore, b"target\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.as_os_str());

        let paths = macos_lockdown_read_paths(
            &Config {
                lockdown: Some(true),
                ..Config::default()
            },
            Path::new("/tmp/test-project"),
        );

        assert!(paths.contains(&canonicalize_or_keep(&gitignore)));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn lockdown_read_paths_include_xdg_git_dir() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-seatbelt-xdg-git-home-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        let xdg_git = home.join(".config").join("git");
        std::fs::create_dir_all(&xdg_git).unwrap();
        std::fs::write(xdg_git.join("ignore"), b"target\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.as_os_str());
        let _xdg = EnvVarGuard::remove("XDG_CONFIG_HOME");

        let paths = macos_lockdown_read_paths(
            &Config {
                lockdown: Some(true),
                ..Config::default()
            },
            Path::new("/tmp/test-project"),
        );

        assert!(paths.contains(&canonicalize_or_keep(&xdg_git)));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn writable_paths_include_linked_worktree_git_dirs() {
        let fixture = create_linked_worktree_fixture();
        let config = Config {
            no_mise: Some(true),
            ..Config::default()
        };
        let paths = macos_writable_paths(&fixture.project_dir, &config, false);
        // Compare via canonicalize: on macOS the fixture path contains
        // `..` segments (e.g. project_dir/../common/.git/worktrees/...)
        // because validate_linked_git_worktree resolves the gitdir
        // relative to the project dir without collapsing. Raw PathBuf
        // equality fails even though the paths refer to the same dir.
        let same = |a: &Path, b: &Path| {
            std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok()
        };
        assert!(paths.iter().any(|path| same(path, &fixture.git_dir)));
        assert!(paths.iter().any(|path| same(path, &fixture.common_dir)));
    }

    #[test]
    fn lockdown_read_paths_include_linked_worktree_git_dirs() {
        let fixture = create_linked_worktree_fixture();
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let paths = macos_lockdown_read_paths(&config, &fixture.project_dir);
        assert!(
            paths
                .iter()
                .any(|path| path == &canonicalize_or_keep(&fixture.git_dir))
        );
        assert!(
            paths
                .iter()
                .any(|path| path == &canonicalize_or_keep(&fixture.common_dir))
        );
    }
}
