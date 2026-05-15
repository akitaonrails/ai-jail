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
    if !config.allow_tcp_ports().is_empty() && config.lockdown_enabled() {
        output::warn(
            "--allow-tcp-port has no effect on macOS \
             lockdown (seatbelt blocks all network)",
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
        cmd.env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        cmd.env("HOME", super::home_dir());
        // Pass through terminal-related env vars so child
        // programs can detect capabilities (truecolor, kitty
        // keyboard protocol, etc.).
        for var in ["TERM", "COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION"]
        {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }
    }

    cmd.env("PS1", "(jail) \\w \\$ ");
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
    command_line.push_str(&quote_arg(&launch.program));
    for arg in &launch.args {
        command_line.push(' ');
        command_line.push_str(&quote_arg(arg));
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
    // Extend deny list with user-specified mask paths
    for p in &config.mask {
        let abs = if p.is_absolute() {
            p.clone()
        } else {
            project_dir.join(p)
        };
        deny_paths.push(abs);
    }
    let writable_paths = macos_writable_paths(project_dir, config, lockdown);
    let atomic_paths = macos_atomic_write_paths(config);

    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

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

    if !lockdown {
        profile.push_str("; Network\n");
        profile.push_str("(allow network-outbound)\n");
        profile.push_str("(allow network-inbound)\n");
        profile.push_str("(allow network-bind)\n");
        profile.push_str("(allow system-socket)\n\n");
    }

    if restricted_files {
        profile.push_str("; File reads: restricted allow-list\n");
        for rd_path in macos_lockdown_read_paths(config, project_dir) {
            let canonical = canonicalize_or_keep(&rd_path);
            let escaped = sbpl_escape(canonical.to_string_lossy().as_ref());
            if canonical.is_dir() || !canonical.exists() {
                profile.push_str(&format!(
                    "(allow file-read* (subpath \"{escaped}\"))\n"
                ));
            } else {
                profile.push_str(&format!(
                    "(allow file-read* (literal \"{escaped}\"))\n"
                ));
            }
        }
        profile.push('\n');

        profile.push_str("; Deny sensitive home paths explicitly\n");
        for deny_path in &deny_paths {
            let escaped = sbpl_path(deny_path);
            if canonicalize_or_keep(deny_path).is_dir() {
                profile.push_str(&format!(
                    "(deny file-read* (subpath \"{escaped}\"))\n"
                ));
            } else {
                profile.push_str(&format!(
                    "(deny file-read* (literal \"{escaped}\"))\n"
                ));
            }
        }
        profile.push('\n');
    } else {
        profile
            .push_str("; File reads: allow globally, deny sensitive paths\n");
        profile.push_str("(allow file-read*)\n");

        for deny_path in &deny_paths {
            let escaped = sbpl_path(deny_path);
            if canonicalize_or_keep(deny_path).is_dir() {
                profile.push_str(&format!(
                    "(deny file-read* (subpath \"{escaped}\"))\n"
                ));
            } else {
                profile.push_str(&format!(
                    "(deny file-read* (literal \"{escaped}\"))\n"
                ));
            }
        }
        profile.push('\n');
    }

    if lockdown {
        profile.push_str("; Lockdown: no host file-write allowances\n\n");
    } else {
        profile.push_str("; File writes: allow specific paths\n");
        for wr_path in &writable_paths {
            let canonical = canonicalize_or_keep(wr_path);
            let escaped = sbpl_escape(canonical.to_string_lossy().as_ref());
            if canonical.is_dir() || !canonical.exists() {
                profile.push_str(&format!(
                    "(allow file-write* (subpath \"{escaped}\"))\n"
                ));
            } else {
                profile.push_str(&format!(
                    "(allow file-write* (literal \"{escaped}\"))\n"
                ));
            }
        }
        if !atomic_paths.is_empty() {
            profile.push('\n');
            profile.push_str(
                "; Atomic-write paths (literal + bounded temp siblings)\n",
            );
            for ap in &atomic_paths {
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
        profile.push('\n');
    }

    if !lockdown && enable_docker {
        if let Some(sock) = macos_docker_socket() {
            let escaped = sbpl_path(&sock);
            profile.push_str("; Docker socket\n");
            profile.push_str(&format!(
                "(allow file-write* (literal \"{escaped}\"))\n"
            ));
            profile.push('\n');
        }
    }

    profile
}

fn quote_arg(arg: &str) -> String {
    if arg.is_empty()
        || arg.contains(|c: char| {
            c.is_whitespace() || "'\"\\$`(){}[]|&;<>*!?".contains(c)
        })
    {
        return format!("'{}'", arg.replace('\'', "'\\''"));
    }
    arg.to_string()
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

    if let Some(dir) = &config.claude_dir {
        if super::path_exists(dir) {
            paths.push(dir.clone());
        }
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

    if browser_mode {
        if let Some(state) = super::browser_state_dir(config) {
            push_unique(canonicalize_or_keep(&state));
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
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    fn create_linked_worktree_fixture() -> LinkedWorktreeFixture {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "ai-jail-seatbelt-worktree-{}-{nonce}",
            std::process::id()
        ));
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
    fn sbpl_profile_lockdown_disables_network_and_writes() {
        let mut config = Config::default();
        config.lockdown = Some(true);
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
        let saved_home = std::env::var_os("HOME");
        let fake_home = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-atomic-{}", std::process::id()));
        fs::create_dir_all(&fake_home).unwrap();
        let claude_json = fake_home.join(".claude.json");
        fs::write(&claude_json, "{}").unwrap();
        unsafe { std::env::set_var("HOME", &fake_home) };

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

        unsafe {
            if let Some(value) = saved_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
        }
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
        let saved_home = std::env::var_os("HOME");
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
        unsafe { std::env::set_var("HOME", &home) };

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

        unsafe {
            if let Some(value) = saved_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
        }
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
    fn lockdown_read_paths_include_project() {
        let project = PathBuf::from("/tmp/test-project");
        let paths = macos_lockdown_read_paths(&Config::default(), &project);
        assert!(paths.contains(&project));
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
