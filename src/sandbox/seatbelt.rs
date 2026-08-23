use crate::config::Config;
use crate::output;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Core runtime and toolchain locations granted read-only so the sandboxed
/// command can exec and resolve its dynamic libraries. This is the macOS
/// counterpart of the Linux base mounts in `bwrap.rs`, and it carries the
/// same entries: `/opt` belongs here because Homebrew on Apple Silicon
/// installs there, exactly as the Intel prefix `/usr/local` — already
/// covered by `/usr` — does on the other architecture (issue #120).
const SYSTEM_READ_PATHS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/private/etc",
    "/Library",
    "/opt",
    "/dev",
];

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

pub fn build(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
    sandbox_tty: Option<&Path>,
) -> Command {
    let lockdown = config.lockdown_enabled();
    let profile = build_profile(config, project_dir, verbose, sandbox_tty);
    let launch = super::build_launch_command(config);

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(&profile);
    cmd.arg("--");
    cmd.arg(&launch.program);
    cmd.args(&launch.args);
    cmd.current_dir(project_dir);

    apply_child_env(&mut cmd, config);

    // The profile only grants RW inside the dedicated session scratch
    // dir; TMPDIR must point there or every temp operation in the
    // child is denied.
    if !lockdown && let Some(tmpdir) = macos_session_tmpdir() {
        cmd.env("TMPDIR", tmpdir);
    }

    cmd
}

/// Build the child environment from the shared allowlist in
/// `config.rs` instead of inheriting the host env wholesale (host env
/// often carries tokens and machine-specific state). `env_pass`
/// entries (`NAME` or `NAME=VALUE`) are always applied verbatim on
/// top. Mirrors `bwrap::env_args` so both backends filter identically.
fn apply_child_env(cmd: &mut Command, config: &Config) {
    cmd.env_clear();

    let host_env: Vec<(String, String)> = std::env::vars().collect();
    let env = if config.inherit_env_enabled() {
        // The whole parent environment, secrets included — that is what
        // the opt-in means. Starting from an empty vector here handed the
        // child nothing at all (not even PATH), because `env_clear` above
        // has already dropped what `Command` would otherwise inherit;
        // bwrap reaches the same result by omitting `--clearenv`.
        let mut env = host_env.clone();
        crate::config::apply_env_pass(&mut env, config.env_pass(), &host_env);
        env
    } else {
        crate::config::filtered_child_env(config.env_pass(), &host_env)
    };
    for (key, value) in env {
        cmd.env(key, value);
    }

    if config.lockdown_enabled() {
        cmd.env("PATH", super::LOCKDOWN_PATH);
    }

    cmd.env("PS1", super::JAIL_PS1);
    cmd.env("_ZO_DOCTOR", "0");

    if let Some(dir) = &config.claude_dir {
        cmd.env("CLAUDE_CONFIG_DIR", dir);
    }
}

pub fn dry_run(config: &Config, project_dir: &Path, verbose: bool) -> String {
    // No PTY exists for a dry run, so no terminal ioctl rule is emitted.
    let profile = build_profile(config, project_dir, verbose, None);
    let launch = super::build_launch_command(config);

    let mut command_line = String::from("sandbox-exec -p '<profile>' -- ");
    command_line.push_str(&super::quote_shell_arg(&launch.program));
    for arg in &launch.args {
        command_line.push(' ');
        command_line.push_str(&super::quote_shell_arg(arg));
    }

    format_dry_run_macos(&command_line, &profile)
}

fn build_profile(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
    sandbox_tty: Option<&Path>,
) -> String {
    let profile =
        generate_sbpl_profile_for_tty(config, project_dir, sandbox_tty);

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

/// Profile with no terminal ioctl grant, for tests that do not exercise a
/// PTY; see [`generate_sbpl_profile_for_tty`].
#[cfg(test)]
fn generate_sbpl_profile(config: &Config, project_dir: &Path) -> String {
    generate_sbpl_profile_for_tty(config, project_dir, None)
}

fn generate_sbpl_profile_for_tty(
    config: &Config,
    project_dir: &Path,
    sandbox_tty: Option<&Path>,
) -> String {
    let lockdown = config.lockdown_enabled();
    let exempt = super::dotdir_exemptions(config);
    let agent_state = agent_state_paths(config);
    let mut deny_paths = macos_read_deny_paths(&config.hide_dotdirs, &exempt);
    if !agent_state.is_empty() {
        // Agent-state passthrough is an explicit opt-in; like the
        // Linux backend's per-command state binds, the mounted dirs
        // outrank the generic dotdir-deny list (e.g. .kimi-code is a
        // built-in hide) or the opt-in would be silently defeated.
        // Explicit --deny-path/--mask entries still win: they are
        // appended below, after this retain.
        deny_paths.retain(|p| !agent_state.contains(p));
    }
    deny_paths.extend(super::effective_mask_patterns(config, project_dir));
    let explicit_deny_paths = super::expand_mask_patterns(
        &config.deny_paths,
        &config.deny_path_exceptions,
        project_dir,
    );
    deny_paths.extend(explicit_deny_paths.clone());
    let writable_paths = macos_writable_paths(project_dir, config, lockdown);
    let atomic_paths = macos_atomic_write_paths(config);
    // Read-only intents need explicit write denies: SBPL is
    // last-match-wins, so an `--map` or `--overlay-map` path inside the
    // project would otherwise stay writable through the project-subtree
    // write allowance (#83). Overlay maps are read-only fallbacks on
    // macOS (no overlayfs), so they get the same deny.
    let mut write_deny_paths = explicit_deny_paths.clone();
    write_deny_paths.extend(
        config
            .ro_maps
            .iter()
            .chain(config.overlay_maps.iter())
            .filter(|p| super::path_exists(p))
            .cloned(),
    );

    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    push_static_sections(
        &mut profile,
        config.macos_host_ipc_enabled(),
        sandbox_tty,
    );
    push_network_section(&mut profile, config);
    let is_claude =
        crate::command::effective_name(&config.command) == Some("claude");
    push_file_read_section(
        &mut profile,
        config,
        project_dir,
        &deny_paths,
        is_claude,
    );
    push_file_write_section(
        &mut profile,
        lockdown,
        &writable_paths,
        &atomic_paths,
        &write_deny_paths,
        is_claude,
    );
    push_docker_section(&mut profile, docker_active(config, lockdown));

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

/// Sections that don't depend on filesystem policy. Always emitted first so
/// the file structure is predictable across modes.
fn push_static_sections(
    profile: &mut String,
    allow_host_ipc: bool,
    sandbox_tty: Option<&Path>,
) {
    profile.push_str("; Process operations\n");
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow process-info* (target same-sandbox))\n");
    profile.push_str("(allow sysctl-read)\n\n");

    profile.push_str("; IPC and Mach\n");
    // Minimal literal bootstrap services required to exec an ordinary
    // dynamically linked command. A global `(allow mach-lookup)` would
    // expose arbitrary host services; only these two literals are
    // permitted by default:
    // - com.apple.cfprefsd.daemon: CFPreferences lookups nearly every
    //   Apple-linked binary performs during startup (locale, system
    //   directories, tool settings); hard failures abort some tools.
    // - com.apple.system.logger: the unified logging service (os_log)
    //   that libSystem itself initializes at exec.
    for service in ["com.apple.cfprefsd.daemon", "com.apple.system.logger"] {
        profile.push_str(&format!(
            "(allow mach-lookup (global-name \"{service}\"))\n"
        ));
    }
    profile.push('\n');

    if allow_host_ipc {
        // Explicit compatibility opt-in; nothing in this block is ever
        // allowed by default because each rule is a broad host-IPC
        // surface that escapes the file policy:
        // - signal: signaling host processes outside the sandbox
        // - ipc-posix-shm*: reading/writing/creating host-visible
        //   POSIX shared-memory segments
        // - ipc-posix-sem: host POSIX named semaphores
        // - mach-lookup: every host bootstrap service
        // - mach-host*: host statistics and privilege ports
        // - file-ioctl / iokit-open: device ioctls and IOKit drivers
        profile.push_str("; Explicit macOS host IPC compatibility opt-in\n");
        profile.push_str("(allow signal)\n");
        profile.push_str("(allow ipc-posix-shm-read-data)\n");
        profile.push_str("(allow ipc-posix-shm-write-data)\n");
        profile.push_str("(allow ipc-posix-shm-read-metadata)\n");
        profile.push_str("(allow ipc-posix-shm-write-create)\n");
        profile.push_str("(allow ipc-posix-sem)\n");
        profile.push_str("(allow mach-lookup)\n");
        profile.push_str("(allow mach-host*)\n");
        profile.push_str("(allow file-ioctl)\n");
        profile.push_str("(allow iokit-open)\n");
        profile.push('\n');
    }

    profile.push_str("; Pseudo-terminal\n");
    profile.push_str("(allow pseudo-tty)\n");
    profile
        .push_str("(allow file-read* file-write* (literal \"/dev/ptmx\"))\n");
    profile.push_str(
        "(allow file-read* file-write* (regex #\"^/dev/ttys[0-9]+\"))\n",
    );
    // Terminal ioctl, scoped to the one PTY ai-jail allocated for this
    // child.
    //
    // Without any grant, every ioctl on the child's own controlling
    // terminal -- including TIOCGETD/TIOCSETA, which Node's
    // tty.setRawMode() and libc's stty/tcsetattr need -- is denied under
    // (deny default), and the agent cannot put its stdin into raw mode.
    //
    // The obvious rule, a regex over ^/dev/ttys[0-9]+, would also cover
    // every *other* terminal this user has open. SBPL cannot filter by
    // ioctl request number, so that would hand the sandbox TIOCSTI on
    // those devices -- injecting keystrokes into another of the user's
    // shells, which is a straightforward escape. Linux denies TIOCSTI
    // through seccomp; macOS has no equivalent, so the grant is narrowed
    // by path instead. When ai-jail is not proxying a PTY the child is
    // talking to the host's own terminal, and no grant is emitted at all.
    if let Some(tty) = sandbox_tty {
        profile.push_str(&format!(
            "(allow file-ioctl (literal \"{}\"))\n",
            sbpl_path(tty)
        ));
    }
    // /dev/ptmx stays allowed so the sandbox can allocate its own PTYs.
    profile.push_str("(allow file-ioctl (literal \"/dev/ptmx\"))\n\n");

    profile.push_str("; Standard devices\n");
    profile.push_str("(allow file-write* (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/zero\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/random\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/urandom\"))\n\n");

    profile.push('\n');
}

fn push_network_section(profile: &mut String, config: &Config) {
    if !config.network_enabled() || config.lockdown_enabled() {
        return;
    }
    // Full network can exfiltrate every file this profile permits reading.
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
    deny_paths: &[PathBuf],
    is_claude: bool,
) {
    profile.push_str("; File reads: explicit allow-list\n");
    // dyld needs the root node to resolve absolute paths. This literal rule
    // does not grant any filesystem subtree.
    profile.push_str("(allow file-read* (literal \"/\"))\n");
    if is_claude {
        // /tmp is a symlink into /private/tmp; push_path_rule
        // canonicalizes every path it emits, so the write grant for
        // Claude Code's /tmp/claude-<uid> below never covers the /tmp
        // symlink node itself -- only its resolved target. Resolving
        // a symlink needs a separate kernel read-metadata check on
        // the symlink node, so without this, the mkdir Claude Code
        // does via the literal "/tmp/..." path (not "/private/tmp/...")
        // still gets EPERM even with the write rule below in place.
        profile.push_str("(allow file-read* (literal \"/tmp\"))\n");
    }
    for rd_path in macos_read_paths(config, project_dir) {
        push_path_rule(profile, "allow", "file-read*", &rd_path);
    }
    profile.push('\n');
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
    is_claude: bool,
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
    if is_claude {
        // Claude Code hardcodes a working directory at
        // /tmp/claude-<uid> (session/tool-output scratch state) and
        // creates it unconditionally at startup -- ignoring $TMPDIR,
        // which is otherwise how this sandbox hands out scratch
        // space (see macos_session_tmpdir). Without *some* write
        // access to that exact path, that first mkdir throws and
        // Claude Code never gets past its own startup, regardless of
        // --rw-map:
        //   EPERM: operation not permitted, mkdir '/tmp/claude-501'
        // Scoped to this user's own directory (not `claude-[0-9]+`,
        // which would also cover another account's scratch dir on a
        // shared machine) and not a general /private/tmp grant, so it
        // doesn't require -- or interact with -- --rw-map /tmp at all.
        let uid = unsafe { nix::libc::getuid() };
        profile.push_str(&format!(
            "(allow file-write* (regex #\"^/private/tmp/claude-{uid}(/.*)?$\"))\n"
        ));
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

fn docker_active(config: &Config, lockdown: bool) -> bool {
    config.docker_enabled() && config.browser_profile().is_none() && !lockdown
}

fn push_docker_section(profile: &mut String, active: bool) {
    if !active {
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

fn validated_macos_tmpdir() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    // Only Darwin's trusted, per-user root is eligible. A TMPDIR value is
    // accepted only when it canonicalizes to that exact directory.
    let length = unsafe {
        nix::libc::confstr(
            nix::libc::_CS_DARWIN_USER_TEMP_DIR,
            std::ptr::null_mut(),
            0,
        )
    };
    if length == 0 {
        return None;
    }
    let mut bytes = vec![0_u8; length as usize];
    if unsafe {
        nix::libc::confstr(
            nix::libc::_CS_DARWIN_USER_TEMP_DIR,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    } == 0
    {
        return None;
    }
    let trusted = PathBuf::from(std::ffi::OsStr::from_bytes(
        &bytes[..bytes.len().saturating_sub(1)],
    ));
    let trusted = std::fs::canonicalize(trusted).ok()?;
    let metadata = trusted.metadata().ok()?;
    let mode = metadata.mode();
    // Darwin's mode_t is u16, so S_ISVTX must widen to match mode().
    let sticky = u32::from(nix::libc::S_ISVTX);
    let unsafe_writable = mode & 0o022 != 0 && mode & sticky == 0;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || unsafe_writable
    {
        return None;
    }
    if let Some(tmpdir) = std::env::var_os("TMPDIR")
        && std::fs::canonicalize(tmpdir).ok().as_ref() != Some(&trusted)
    {
        output::warn(
            "ignoring TMPDIR that differs from Darwin's trusted per-user temporary directory",
        );
    }
    Some(trusted)
}

/// Dedicated per-session scratch directory inside Darwin's trusted
/// per-user temp root: `<tmp>/ai-jail-<pid>`, created with mode 0700.
/// Allowing the whole validated root would expose every host temp
/// file to the sandbox; the child only ever sees its own session
/// subtree, and the child's TMPDIR is pointed at it in [`build`].
fn macos_session_tmpdir() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let root = validated_macos_tmpdir()?;
    let session = root.join(format!("ai-jail-{}", std::process::id()));
    if std::fs::create_dir(&session).is_err() && !session.is_dir() {
        output::warn(&format!(
            "cannot create session temp dir {}; temp access disabled",
            session.display()
        ));
        return None;
    }
    // Enforce the mode on every call: a stale directory left by an
    // earlier process that recycled this pid must not carry looser
    // group/other bits.
    let _ = std::fs::set_permissions(
        &session,
        std::fs::Permissions::from_mode(0o700),
    );
    Some(session)
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

/// Command-specific agent state paths (state directories plus
/// claude's `~/.claude.json` status file) that are mounted read-write
/// when agent-state passthrough is enabled. Returns an empty list
/// otherwise — agent state never leaks in by default.
///
/// Mirrors the command-state list the Linux backend mounts so both
/// platforms expose identical agent state. Kept local to this file
/// because the bwrap-side list is private to that module.
fn agent_state_paths(config: &Config) -> Vec<PathBuf> {
    if !config.agent_state_enabled() {
        return Vec::new();
    }
    let home = super::home_dir();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut push = |rel: &str| {
        let path = home.join(rel);
        if super::path_exists(&path) && !paths.contains(&path) {
            paths.push(path);
        }
    };
    match crate::command::effective_name(&config.command) {
        Some("claude") => {
            push(".claude");
            push(".claude.json");
        }
        Some("codex") => push(".codex"),
        Some("opencode") => {
            push(".config/opencode");
            push(".local/share/opencode");
        }
        Some("crush") => push(".crush"),
        Some(name) if name.starts_with("kimi") => push(".kimi-code"),
        Some("gemini") => push(".gemini"),
        Some("grok") => push(".grok"),
        Some("jcode") => {
            push(".jcode");
            push(".config/jcode");
        }
        Some("pi") => {
            push(".pi");
            push(".pi-lens");
        }
        Some("aider") => push(".aider"),
        Some("soulforge") => push(".soulforge"),
        Some("omp") => push(".omp"),
        _ => {}
    }
    paths
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
    let agent_state = agent_state_paths(config);

    let browser_mode = config.browser_profile().is_some();
    let private_home = config.private_home_enabled();

    if browser_mode {
        for p in &agent_state {
            paths.push(p.clone());
        }
        if let Some(state) = super::browser_state_dir(config) {
            let _ = std::fs::create_dir_all(&state);
            paths.push(state);
        }
        if let Some(tmpdir) = macos_session_tmpdir() {
            paths.push(tmpdir);
        }
        return paths;
    }

    paths.push(project_dir.to_path_buf());

    if let Some(worktree) =
        super::discover_git_worktree_paths(config, project_dir, false)
    {
        // Both the per-worktree git dir (HEAD, index, ORIG_HEAD,
        // worktree-local refs) and the shared common dir need writes:
        // the common dir holds the object database, refs, and
        // packed-refs, so `git add` and `git commit` write there.
        // Granting only the git dir made every write fail with
        // "Read-only file system" (issue #101). Lockdown returns
        // early above, so these stay read-only there.
        for path in worktree.unique_paths() {
            paths.push(path);
        }
    }

    // Explicit agent-state opt-in: mount the command's state dirs RW.
    // Independent of --no-private-home below; an explicit
    // --claude-dir is likewise its own opt-in and handled further
    // down.
    for p in agent_state {
        if !paths.contains(&p) {
            paths.push(p);
        }
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

    // Grant only the dedicated session scratch dir, never the whole
    // validated per-user temp root (host temp files stay invisible).
    if let Some(tmpdir) = macos_session_tmpdir() {
        paths.push(tmpdir);
    }

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
    // ~/.claude.json is command agent state; without the agent-state
    // opt-in the file stays host-private (the earlier
    // --no-private-home allowance was retired with that opt-in).
    if config.lockdown_enabled() || !config.agent_state_enabled() {
        return Vec::new();
    }
    if crate::command::effective_name(&config.command) != Some("claude") {
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
    // Shared with Linux: honours $DOCKER_HOST before the well-known
    // paths. Docker Desktop, Colima, and `podman machine` all place
    // their socket under $HOME rather than /var/run/docker.sock.
    super::docker_socket()
}

fn macos_read_paths(config: &Config, project_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !paths.contains(&p) {
            paths.push(p);
        }
    };

    // Every mode may read its project tree, but only non-lockdown profiles
    // receive write access through macos_writable_paths.
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

    for p in SYSTEM_READ_PATHS {
        let pb = PathBuf::from(p);
        if super::path_exists(&pb) {
            // Canonicalize before deduplicating: `/etc` and `/private/etc`
            // are the same directory on macOS and the rules are emitted
            // canonically, so the raw forms would produce one duplicate
            // allow in every profile.
            push_unique(canonicalize_or_keep(&pb));
        }
    }

    let browser_mode = config.browser_profile().is_some();
    let private_home = config.private_home_enabled();

    if browser_mode && let Some(state) = super::browser_state_dir(config) {
        push_unique(canonicalize_or_keep(&state));
    }

    // Explicit agent-state opt-in: the command's state dirs must be
    // readable as well as writable. Under private-home these are the
    // only home paths exposed; under --no-private-home they are
    // already covered by the compat list below.
    for path in agent_state_paths(config) {
        push_unique(canonicalize_or_keep(&path));
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

    if !private_home && !browser_mode {
        // --no-private-home is explicit compatibility opt-in. Keep it to
        // agent/tool state dotdirs rather than granting the whole home.
        for name in [
            ".gemini",
            ".claude",
            ".crush",
            ".codex",
            ".aider",
            ".kiro",
            ".soulforge",
            ".grok",
            ".jcode",
            ".agents",
            ".omp",
            ".pi",
            ".pi-lens",
            ".config",
            ".cargo",
            ".cache",
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
            ".local",
        ] {
            let path = super::home_dir().join(name);
            if path.is_dir() {
                push_unique(canonicalize_or_keep(&path));
            }
        }
    }

    if !browser_mode && !config.lockdown_enabled() {
        for p in config.rw_maps.iter().chain(config.ro_maps.iter()) {
            if super::path_exists(p) {
                push_unique(canonicalize_or_keep(p));
            }
        }
        // Without a read allowance on the command's install paths the
        // exec fails before the agent starts (#81). Unlike Linux, where
        // everything outside the private $HOME is already bind-mounted,
        // a macOS profile denies by default everywhere, so the search
        // covers the whole filesystem rather than just $HOME — an agent
        // installed under /Applications or /nix/store needs the same
        // grant that a ~/.local/bin one does (issue #120).
        for p in super::command_paths_under(config, Path::new("/")) {
            push_unique(canonicalize_or_keep(&p));
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

    // A command under /Applications needs its bundle, but do not expose all
    // installed applications merely because one command is launched.
    for command in crate::command::executable_candidates(&config.command) {
        let path = PathBuf::from(command);
        if path.starts_with("/Applications") && path.exists() {
            push_unique(canonicalize_or_keep(&path));
        }
    }

    for p in config.rw_maps.iter().chain(config.ro_maps.iter()) {
        let source = crate::config::map_source(p);
        if super::path_exists(&source) {
            push_unique(canonicalize_or_keep(&source));
        }
    }

    // Only the dedicated session scratch dir is readable/writable in
    // the temp area; the rest of the per-user temp root stays hidden.
    // Lockdown gets no temp access at all (no writes anywhere, so a
    // fresh TMPDIR would only mislead).
    if !config.lockdown_enabled()
        && let Some(tmpdir) = macos_session_tmpdir()
    {
        push_unique(tmpdir);
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
        let profile = generate_sbpl_profile(&config, &project);
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn docker_is_disabled_in_browser_and_lockdown_modes() {
        let enabled = Config {
            no_docker: Some(false),
            ..Config::default()
        };
        assert!(docker_active(&enabled, false));
        let browser = Config {
            browser_profile: Some("soft".into()),
            ..enabled.clone()
        };
        assert!(!docker_active(&browser, false));
        assert!(!docker_active(&enabled, true));
    }

    #[test]
    fn sbpl_profile_defaults_to_no_network_or_global_reads() {
        let _env = ENV_LOCK.lock().unwrap();
        // Empty fixture home: the --no-private-home mode below would
        // otherwise add whatever dotdirs the invoking user happens to
        // have, making the "no home subpath allows" assertion
        // machine-dependent.
        let home = std::env::temp_dir().join(format!(
            "ai-jail-seatbelt-defaults-home-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let _home = EnvVarGuard::set("HOME", home.as_os_str());

        let project = PathBuf::from("/tmp/test-project");
        let modes = [
            Config::default(),
            Config {
                private_home: Some(false),
                ..Config::default()
            },
            Config {
                lockdown: Some(true),
                ..Config::default()
            },
            Config {
                browser_profile: Some("soft".into()),
                ..Config::default()
            },
        ];
        for config in modes {
            let profile = generate_sbpl_profile(&config, &project);
            assert!(!profile.contains("(allow network-outbound)"));
            assert!(!profile.contains("(allow file-read*)\n"));
            assert!(!profile.contains("(subpath \"/Users/"));
            assert!(!profile.contains("(allow mach-lookup)\n"));
            assert!(!profile.contains("(allow mach-host*)"));
            assert!(!profile.contains("(allow mach-register)"));
            assert!(!profile.contains("(allow file-ioctl)"));
            assert!(!profile.contains("(allow iokit-open)"));
            // Broad host IPC is opt-in only: signaling host processes,
            // POSIX shm, and POSIX semaphores stay denied by default.
            assert!(!profile.contains("(allow signal)"));
            assert!(!profile.contains("ipc-posix-shm"));
            assert!(!profile.contains("(allow ipc-posix-sem)"));
            // The only mach-lookup allowances are the two literal
            // bootstrap services required for exec.
            assert_eq!(
                profile.matches("(allow mach-lookup").count(),
                profile
                    .matches("(allow mach-lookup (global-name \"")
                    .count(),
                "default profile must not allow non-literal mach-lookup"
            );
        }

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn sbpl_network_and_host_ipc_require_explicit_opt_in() {
        let config = Config {
            network: Some(true),
            macos_host_ipc: Some(true),
            ..Config::default()
        };
        let profile =
            generate_sbpl_profile(&config, Path::new("/tmp/test-project"));
        assert!(profile.contains("(allow network-outbound)"));
        assert!(profile.contains("(allow mach-lookup)"));
        assert!(profile.contains("(allow mach-host*)"));
        assert!(profile.contains("(allow file-ioctl)"));
        assert!(profile.contains("(allow iokit-open)"));
        assert!(profile.contains("(allow signal)"));
        assert!(profile.contains("(allow ipc-posix-shm-read-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-read-metadata)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-create)"));
        assert!(profile.contains("(allow ipc-posix-sem)"));
        assert!(!profile.contains("mach-register"));
    }

    #[test]
    fn sbpl_profile_denies_deny_paths_for_read_and_write() {
        let config = Config {
            deny_paths: vec![PathBuf::from(".env")],
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project);
        assert!(profile.contains(
            "(deny file-read* (subpath \"/tmp/test-project/.env\"))"
        ));
        assert!(profile.contains(
            "(deny file-write* (subpath \"/tmp/test-project/.env\"))"
        ));
    }

    #[test]
    fn sbpl_profile_honors_exceptions_but_keeps_policy_hidden() {
        let project = std::env::temp_dir().join("ai-jail-seatbelt-exceptions");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join(".ai-jail"), "mask = []").unwrap();
        let config = Config {
            mask: vec![PathBuf::from(".env")],
            mask_exceptions: vec![PathBuf::from(".env")],
            deny_paths: vec![PathBuf::from("secret")],
            deny_path_exceptions: vec![PathBuf::from("secret")],
            ..Config::default()
        };
        let profile = generate_sbpl_profile(&config, &project);
        assert!(!profile.contains("/.env\"))"));
        assert!(!profile.contains("/secret\"))"));
        assert!(profile.contains(&format!("{}/.ai-jail", project.display())));

        let visible = Config {
            no_hide_config: Some(true),
            ..Config::default()
        };
        let visible_profile = generate_sbpl_profile(&visible, &project);
        assert!(
            !visible_profile
                .contains(&format!("{}/.ai-jail", project.display()))
        );
        let _ = std::fs::remove_dir_all(project);
    }

    #[test]
    fn sbpl_profile_lockdown_disables_network_and_writes() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project);
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

        // ~/.claude.json is command agent state: the atomic-write rules
        // only exist behind the explicit agent-state opt-in (secure
        // default: private home on, agent state off).
        let config = Config {
            command: vec!["claude".into()],
            no_mise: Some(true),
            agent_state: Some(true),
            ..Config::default()
        };
        let profile = generate_sbpl_profile(&config, Path::new("/tmp/proj"));

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
        let profile = generate_sbpl_profile(&config, &project);
        assert!(profile.contains("; File reads: explicit allow-list"));
        assert!(!profile.contains("(allow file-read*)\n"));
    }

    /// Regression for #83 on the macOS side: SBPL is last-match-wins,
    /// so without an explicit write deny an `--map` (or `--overlay-map`)
    /// path inside the project stays writable through the project
    /// subtree's write allowance.
    #[test]
    fn ro_and_overlay_maps_get_write_denies_after_project_allow() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-ro-map-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let project = home.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::create_dir_all(project.join("vendor")).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let config = Config {
            ro_maps: vec![project.join(".git")],
            overlay_maps: vec![project.join("vendor")],
            ..Config::default()
        };
        let profile = generate_sbpl_profile(&config, &project);

        let allow_project = format!(
            "(allow file-write* (subpath \"{}\"))",
            sbpl_path(&project)
        );
        let deny_ro_map = format!(
            "(deny file-write* (subpath \"{}\"))",
            sbpl_path(&project.join(".git"))
        );
        let deny_overlay = format!(
            "(deny file-write* (subpath \"{}\"))",
            sbpl_path(&project.join("vendor"))
        );
        let allow_at = profile
            .find(&allow_project)
            .expect("project write allowance present");
        let deny_ro_at = profile
            .find(&deny_ro_map)
            .expect("ro map write deny present");
        assert!(
            profile.contains(&deny_overlay),
            "overlay map write deny present (read-only fallback on macOS)"
        );
        assert!(
            deny_ro_at > allow_at,
            "write deny must come after the project allow (last match wins)"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn private_home_reads_allow_home_installed_command() {
        // Regression for #81: an agent installed the official way
        // (~/.local/bin symlink into ~/.local/share/<tool>/versions)
        // must stay readable in private-home mode or the exec fails
        // before the agent starts.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-cmd-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let versions = home.join(".local/share/agent/versions");
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(&versions).unwrap();
        let target = versions.join("1.0");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, home.join(".local/bin/agent"))
            .unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _path =
            EnvVarGuard::set("PATH", home.join(".local/bin").as_os_str());

        let config = Config {
            command: vec!["agent".into()],
            private_home: Some(true),
            ..Config::default()
        };
        let project = home.join("project");
        let profile = generate_sbpl_profile(&config, &project);

        // The versions dir surfaces as a subpath read allowance; the
        // PATH entry canonicalizes to the target file (literal rule).
        assert!(
            profile
                .contains(&format!("(subpath \"{}\")", sbpl_path(&versions)))
        );
        assert!(
            profile.contains(&format!("(literal \"{}\")", sbpl_path(&target)))
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn system_reads_cover_both_homebrew_prefixes() {
        // Regression for #120. The Intel prefix /usr/local is reachable
        // through /usr, so only the Apple Silicon prefix can go missing —
        // and it did, leaving Homebrew-installed agents unexecutable on
        // exactly one architecture.
        assert!(SYSTEM_READ_PATHS.contains(&"/opt"));
        assert!(SYSTEM_READ_PATHS.contains(&"/usr"));
    }

    #[test]
    fn reads_allow_command_installed_outside_home() {
        // Regression for #120: the read grant for the invoked command
        // used to stop at $HOME, so an agent installed anywhere else —
        // a Homebrew prefix, /Applications, /nix/store — was denied and
        // the exec failed before the agent started.
        let _lock = ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-cmd-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let prefix = root.join("prefix");
        let libexec = prefix.join("libexec");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        let target = libexec.join("agent-1.0");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, prefix.join("bin/agent")).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _path = EnvVarGuard::set("PATH", prefix.join("bin").as_os_str());

        // The install prefix is deliberately outside $HOME; if the fixture
        // ever landed inside it, the test would pass without proving
        // anything.
        assert!(!prefix.starts_with(&home));

        let config = Config {
            command: vec!["agent".into()],
            private_home: Some(true),
            ..Config::default()
        };
        let profile = generate_sbpl_profile(&config, &home.join("project"));

        assert!(
            profile.contains(&format!("(subpath \"{}\")", sbpl_path(&libexec)))
        );
        assert!(
            profile.contains(&format!("(literal \"{}\")", sbpl_path(&target)))
        );

        let _ = std::fs::remove_dir_all(&root);
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
            ("private-home", private_home),
            ("lockdown", lockdown),
            ("browser", browser),
        ];
        for (mode, config) in cases {
            let project = PathBuf::from("/tmp/test-project");
            let profile = generate_sbpl_profile(&config, &project);
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
    fn static_section_grants_ioctl_on_pty_devices() {
        // Without this, any ioctl on the child's own controlling
        // terminal (TIOCGETD/TIOCSETA -- what tty.setRawMode() and
        // stty/tcsetattr need) is denied under (deny default). The
        // child then can't switch its stdin into raw mode: canonical
        // line discipline still delivers plain Enter as a normal
        // line, but special key encodings (Shift+Enter's xterm/kitty
        // CSI sequences) are never intercepted and show up as
        // literal bytes instead.
        let tty = PathBuf::from("/dev/ttys003");
        let profile = generate_sbpl_profile_for_tty(
            &Config::default(),
            &PathBuf::from("/tmp/test-project"),
            Some(&tty),
        );
        assert!(
            profile.contains("(allow file-ioctl (literal \"/dev/ttys003\"))")
        );
        assert!(profile.contains("(allow file-ioctl (literal \"/dev/ptmx\"))"));
        // A regex over every terminal would also hand the sandbox TIOCSTI
        // on the user's other shells, which is an escape.
        assert!(
            !profile
                .contains("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+\"))"),
            "terminal ioctl must not be granted on every /dev/ttys*"
        );
    }

    #[test]
    fn no_terminal_ioctl_granted_without_a_sandbox_pty() {
        // Without a proxied PTY the child talks to the host's own
        // terminal, so granting ioctl there is exactly the case that
        // would allow injecting input into the user's shell.
        let profile = generate_sbpl_profile_for_tty(
            &Config::default(),
            &PathBuf::from("/tmp/test-project"),
            None,
        );
        assert!(!profile.contains("(allow file-ioctl (literal \"/dev/ttys"));
        assert!(
            !profile
                .contains("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+\"))")
        );
        // Allocating a fresh PTY inside the sandbox stays possible.
        assert!(profile.contains("(allow file-ioctl (literal \"/dev/ptmx\"))"));
    }

    #[test]
    fn stty_ioctl_on_pty_succeeds_under_generated_profile() {
        // Regression for the bug above, exercised for real: allocate
        // an actual PTY, attach it as the sandboxed child's stdin, and
        // confirm `stty -a` can query it (TIOCGETD et al.) instead of
        // failing with "Operation not permitted".
        if !Path::new("/usr/bin/sandbox-exec").is_file() {
            return;
        }
        let config = Config::default();
        let project = PathBuf::from("/tmp/test-project");

        // Allocate through the same path main.rs uses, so the profile is
        // scoped to this exact device rather than to every terminal.
        let pty = crate::pty::open().expect("openpty");
        let tty = pty.slave_path().expect("ptsname");
        let profile =
            generate_sbpl_profile_for_tty(&config, &project, Some(&tty));

        let output = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg("--")
            .arg("/bin/stty")
            .arg("-a")
            .stdin(pty.slave_try_clone().expect("dup slave"))
            .output()
            .expect("failed to run sandbox-exec");
        drop(pty);

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("Operation not permitted"),
            "stty ioctl on the child's controlling PTY was denied: \
             status={:?} stderr={stderr} profile:\n{profile}",
            output.status,
        );
    }

    #[test]
    fn claude_profile_grants_tmp_claude_dir_write_and_tmp_symlink_read() {
        // Claude Code hardcodes mkdir('/tmp/claude-<uid>') at startup,
        // unconditionally, ignoring $TMPDIR -- with neither of these
        // two rules, that first mkdir throws EPERM before the agent
        // does anything. Scoped to the "claude" command only: a
        // different command has no reason to touch this path.
        let claude_profile = generate_sbpl_profile(
            &Config {
                command: vec!["claude".into()],
                ..Config::default()
            },
            &PathBuf::from("/tmp/test-project"),
        );
        let uid = unsafe { nix::libc::getuid() };
        assert!(claude_profile.contains(&format!(
            "(allow file-write* (regex #\"^/private/tmp/claude-{uid}(/.*)?$\"))"
        )));
        assert!(
            claude_profile.contains("(allow file-read* (literal \"/tmp\"))")
        );

        let other_profile = generate_sbpl_profile(
            &Config {
                command: vec!["bash".into()],
                ..Config::default()
            },
            &PathBuf::from("/tmp/test-project"),
        );
        assert!(!other_profile.contains("/private/tmp/claude-"));
        assert!(
            !other_profile.contains("(allow file-read* (literal \"/tmp\"))")
        );
    }

    #[test]
    fn mkdir_tmp_claude_dir_succeeds_under_generated_claude_profile() {
        // Real end-to-end reproduction of the reported failure:
        //   EPERM: operation not permitted, mkdir '/tmp/claude-501'
        // Probes a throwaway subdirectory of the real uid-scoped path
        // rather than the path itself: the rule covers descendants, so
        // this still exercises the grant without disturbing a live
        // Claude Code session's own /tmp/claude-<uid> directory.
        if !Path::new("/usr/bin/sandbox-exec").is_file() {
            return;
        }
        let profile = generate_sbpl_profile(
            &Config {
                command: vec!["claude".into()],
                ..Config::default()
            },
            &PathBuf::from("/tmp/test-project"),
        );

        // Must match the uid-scoped rule the profile emits.
        let parent = format!("/tmp/claude-{}", unsafe { nix::libc::getuid() });
        let target = format!("{parent}/ai-jail-probe-{}", std::process::id());
        let _ = std::fs::remove_dir(format!("/private{target}"));

        // One non-recursive mkdir, which is the call Claude Code makes.
        // `mkdir -p` would instead walk down from `/tmp` and try to create
        // it: the sandbox answers a denied write with EPERM rather than
        // the EEXIST that mkdir tolerates, so the probe would fail on a
        // path the agent never touches. Create the uid-scoped dir itself
        // when it is absent — the exact reported operation — and fall
        // back to a throwaway child so a live Claude Code session's
        // directory is left alone.
        let parent_exists = Path::new(&format!("/private{parent}")).is_dir();
        let probe = if parent_exists { &target } else { &parent };

        let output = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg("--")
            .arg("/bin/mkdir")
            .arg(probe)
            .output()
            .expect("failed to run sandbox-exec");

        // Remove only what this probe created; the parent may belong to
        // a real session, and remove_dir leaves it alone unless empty.
        let _ = std::fs::remove_dir(format!("/private{target}"));
        let _ = std::fs::remove_dir(format!("/private{parent}"));

        assert!(
            output.status.success(),
            "mkdir of Claude Code's /tmp/claude-<uid> dir was denied: \
             status={:?} stderr={} profile:\n{profile}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn read_paths_include_project() {
        let project = PathBuf::from("/tmp/test-project");
        let paths = macos_read_paths(&Config::default(), &project);
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

        let paths = macos_read_paths(
            &Config {
                lockdown: Some(true),
                // Private home is the default; git config exposure is a
                // --no-private-home compatibility opt-in.
                private_home: Some(false),
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

        let paths = macos_read_paths(
            &Config {
                lockdown: Some(true),
                // Private home is the default; git config exposure is a
                // --no-private-home compatibility opt-in.
                private_home: Some(false),
                ..Config::default()
            },
            Path::new("/tmp/test-project"),
        );

        assert!(paths.contains(&canonicalize_or_keep(&xdg_git)));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn writable_paths_grant_worktree_git_dir_and_common_dir() {
        let fixture = create_linked_worktree_fixture();
        // Worktree metadata is opt-in; without --worktree discovery
        // returns nothing and the assertions below have no subject.
        let config = Config {
            no_mise: Some(true),
            no_worktree: Some(false),
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
        // Regression for #101: the per-worktree git dir carries HEAD,
        // index and worktree-local refs, but the object database and
        // shared refs live in the common dir, so both must be
        // writable or `git add` fails with "Read-only file system".
        assert!(paths.iter().any(|path| same(path, &fixture.git_dir)));
        assert!(
            paths.iter().any(|path| same(path, &fixture.common_dir)),
            "common git dir must be writable so git can write objects"
        );
    }

    #[test]
    fn lockdown_read_paths_include_linked_worktree_git_dirs() {
        let fixture = create_linked_worktree_fixture();
        let config = Config {
            lockdown: Some(true),
            no_worktree: Some(false),
            ..Config::default()
        };
        let paths = macos_read_paths(&config, &fixture.project_dir);
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

    /// Fake `$HOME` containing every command-state path, with the env
    /// lock held and HOME pointed at the fixture.
    struct AgentStateFixture {
        home: PathBuf,
        _home: EnvVarGuard,
        _env: std::sync::MutexGuard<'static, ()>,
    }

    fn agent_state_fixture_home(prefix: &str) -> AgentStateFixture {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-seatbelt-{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        for dir in [
            ".claude",
            ".codex",
            ".config/opencode",
            ".local/share/opencode",
            ".crush",
            ".kimi-code",
            ".gemini",
            ".grok",
            ".pi",
            ".pi-lens",
            ".aider",
            ".soulforge",
            ".omp",
        ] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".claude.json"), "{}").unwrap();
        let _home = EnvVarGuard::set("HOME", home.as_os_str());
        AgentStateFixture { home, _home, _env }
    }

    #[test]
    fn agent_state_is_gated_off_by_default() {
        let fixture = agent_state_fixture_home("state-default");
        let home = &fixture.home;
        let config = Config {
            command: vec!["claude".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        assert!(agent_state_paths(&config).is_empty());
        let project = PathBuf::from("/tmp/test-project");
        let writable = macos_writable_paths(&project, &config, false);
        assert!(!writable.contains(&home.join(".claude")));
        assert!(!writable.contains(&home.join(".claude.json")));
        let profile = generate_sbpl_profile(&config, &project);
        assert!(!profile.contains(".claude.json"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn agent_state_mounts_claude_state_read_write() {
        let fixture = agent_state_fixture_home("state-claude");
        let home = &fixture.home;
        let config = Config {
            command: vec!["claude".into()],
            no_mise: Some(true),
            agent_state: Some(true),
            ..Config::default()
        };
        let expected = vec![home.join(".claude"), home.join(".claude.json")];
        assert_eq!(agent_state_paths(&config), expected);

        let project = PathBuf::from("/tmp/test-project");
        let writable = macos_writable_paths(&project, &config, false);
        assert!(writable.contains(&home.join(".claude")));
        assert!(writable.contains(&home.join(".claude.json")));

        let reads = macos_read_paths(&config, &project);
        assert!(reads.contains(&canonicalize_or_keep(&home.join(".claude"))));

        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn agent_state_covers_full_command_list() {
        let fixture = agent_state_fixture_home("state-list");
        let home = &fixture.home;
        for (command, expected) in [
            (vec!["claude"], vec![".claude", ".claude.json"]),
            (vec!["codex"], vec![".codex"]),
            (
                vec!["opencode"],
                vec![".config/opencode", ".local/share/opencode"],
            ),
            (vec!["crush"], vec![".crush"]),
            (vec!["kimi"], vec![".kimi-code"]),
            (vec!["gemini"], vec![".gemini"]),
            (vec!["grok"], vec![".grok"]),
            (vec!["pi"], vec![".pi", ".pi-lens"]),
            (vec!["aider"], vec![".aider"]),
            (vec!["soulforge"], vec![".soulforge"]),
            (vec!["omp"], vec![".omp"]),
        ] {
            let config = Config {
                command: command
                    .clone()
                    .into_iter()
                    .map(String::from)
                    .collect(),
                no_mise: Some(true),
                agent_state: Some(true),
                ..Config::default()
            };
            let expected: Vec<PathBuf> =
                expected.iter().map(|rel| home.join(rel)).collect();
            assert_eq!(
                agent_state_paths(&config),
                expected,
                "state mapping mismatch for {}",
                command[0]
            );
        }
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn agent_state_opt_in_outranks_builtin_dotdir_deny() {
        let fixture = agent_state_fixture_home("state-kimi");
        let home = &fixture.home;
        let config = Config {
            command: vec!["kimi".into()],
            no_mise: Some(true),
            agent_state: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-project");
        let profile = generate_sbpl_profile(&config, &project);
        let kimi = home.join(".kimi-code");
        assert!(
            !profile.contains(&format!(
                "(deny file-read* (subpath \"{}\"))",
                sbpl_path(&kimi)
            )),
            ".kimi-code is a built-in hide, but the explicit state \
             opt-in must outrank it"
        );
        assert!(profile.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            sbpl_path(&kimi)
        )));

        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn writable_paths_use_dedicated_session_tmpdir() {
        let Some(root) = validated_macos_tmpdir() else {
            // Trusted temp root unavailable (unusual host setup);
            // macos_session_tmpdir then disables temp access.
            assert!(macos_session_tmpdir().is_none());
            return;
        };
        let session = root.join(format!("ai-jail-{}", std::process::id()));
        let config = Config::default();
        let project = PathBuf::from("/tmp/test-project");
        let writable = macos_writable_paths(&project, &config, false);
        assert!(writable.contains(&session));
        assert!(
            !writable.contains(&root),
            "the whole per-user temp root must not be writable"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = session.metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "session tmpdir must be mode 0700");
    }

    #[test]
    fn build_sets_child_tmpdir_to_session_dir() {
        let Some(root) = validated_macos_tmpdir() else {
            return;
        };
        let config = Config {
            command: vec!["bash".into()],
            no_mise: Some(true),
            ..Config::default()
        };
        let cmd = build(&config, Path::new("/tmp/test-project"), false, None);
        let session = root.join(format!("ai-jail-{}", std::process::id()));
        let tmpdir = cmd
            .get_envs()
            .find(|(key, _)| key == &std::ffi::OsStr::new("TMPDIR"))
            .and_then(|(_, value)| value);
        assert_eq!(tmpdir, Some(session.as_os_str()));
    }

    #[test]
    fn build_child_env_is_allowlisted_with_env_pass() {
        let _env = ENV_LOCK.lock().unwrap();
        let _dropped = EnvVarGuard::set("AI_JAIL_HOST_STATE", "secret");
        let _locale = EnvVarGuard::set("LC_CTYPE", "UTF-8");
        let _xdg = EnvVarGuard::set("XDG_DATA_HOME", "/tmp/xdg-data");
        let _passed = EnvVarGuard::set("AI_JAIL_TEST_SECRET", "hunter2");

        let config = Config {
            command: vec!["bash".into()],
            no_mise: Some(true),
            env_pass: vec![
                "AI_JAIL_TEST_SECRET".into(),
                "AI_JAIL_LITERAL=xyz".into(),
            ],
            ..Config::default()
        };
        let cmd = build(&config, Path::new("/tmp/test-project"), false, None);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        let get = |name: &str| {
            env.get(&std::ffi::OsStr::new(name)).copied().flatten()
        };
        assert!(
            get("AI_JAIL_HOST_STATE").is_none(),
            "non-allowlisted host state must be dropped"
        );
        assert!(get("PATH").is_some());
        assert!(get("HOME").is_some());
        assert_eq!(get("LC_CTYPE"), Some(std::ffi::OsStr::new("UTF-8")));
        assert_eq!(
            get("XDG_DATA_HOME"),
            Some(std::ffi::OsStr::new("/tmp/xdg-data"))
        );
        // env_pass: bare NAME passes the host value, NAME=VALUE sets it.
        assert_eq!(
            get("AI_JAIL_TEST_SECRET"),
            Some(std::ffi::OsStr::new("hunter2"))
        );
        assert_eq!(get("AI_JAIL_LITERAL"), Some(std::ffi::OsStr::new("xyz")));
        assert_eq!(
            get("PS1"),
            Some(std::ffi::OsStr::new(crate::sandbox::JAIL_PS1))
        );
    }

    #[test]
    fn inherit_env_opt_in_passes_host_environment() {
        let _env = ENV_LOCK.lock().unwrap();
        let _state = EnvVarGuard::set("AI_JAIL_HOST_STATE", "secret");

        let config = Config {
            command: vec!["bash".into()],
            no_mise: Some(true),
            inherit_env: Some(true),
            ..Config::default()
        };
        let cmd = build(&config, Path::new("/tmp/test-project"), false, None);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();
        assert_eq!(
            env.get(&std::ffi::OsStr::new("AI_JAIL_HOST_STATE"))
                .copied()
                .flatten(),
            Some(std::ffi::OsStr::new("secret"))
        );
    }
}
