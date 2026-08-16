use crate::config::{Config, MapSpec};
use crate::output;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const WSL_DOCKER_DESKTOP_CLI_TOOLS: &str = "/mnt/wsl/docker-desktop/cli-tools";
/// Also granted read-write by Landlock (`collect_normal_paths`) —
/// keep the two in sync via this shared constant.
pub(crate) const TAILSCALE_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";
/// DBus session bus socket, relative to `XDG_RUNTIME_DIR`.
const SYSTEMD_USER_BUS_SUBPATH: &str = "bus";
/// Socket paths (relative to `XDG_RUNTIME_DIR`) that `--systemd-user`
/// exposes. Also granted read-write by Landlock (`systemd_user_paths`)
/// — keep the two in sync via this shared constant.
pub(crate) const SYSTEMD_USER_SUBPATHS: &[&str] =
    &[SYSTEMD_USER_BUS_SUBPATH, "systemd/private"];

#[derive(Debug, Clone)]
enum Mount {
    RoBind {
        src: PathBuf,
        dest: PathBuf,
    },
    Bind {
        src: PathBuf,
        dest: PathBuf,
    },
    DevBind {
        src: PathBuf,
        dest: PathBuf,
    },
    Dev {
        dest: PathBuf,
    },
    Proc {
        dest: PathBuf,
    },
    Tmpfs {
        dest: PathBuf,
    },
    Symlink {
        src: String,
        dest: PathBuf,
    },
    FileRoBind {
        src: PathBuf,
        dest: PathBuf,
    },
    /// Copy-on-write overlay: `lower` is mounted read-only as the base
    /// at `dest`, writes go to `upper` (with overlayfs scratch in
    /// `work`). The original `lower` directory is never modified.
    Overlay {
        lower: PathBuf,
        upper: PathBuf,
        work: PathBuf,
        dest: PathBuf,
    },
}

impl Mount {
    fn dest(&self) -> &Path {
        match self {
            Mount::RoBind { dest, .. }
            | Mount::FileRoBind { dest, .. }
            | Mount::Bind { dest, .. }
            | Mount::DevBind { dest, .. }
            | Mount::Dev { dest }
            | Mount::Proc { dest }
            | Mount::Tmpfs { dest }
            | Mount::Symlink { dest, .. }
            | Mount::Overlay { dest, .. } => dest,
        }
    }

    fn to_args(&self) -> Vec<String> {
        match self {
            Mount::RoBind { src, dest } | Mount::FileRoBind { src, dest } => {
                vec![
                    "--ro-bind".into(),
                    src.display().to_string(),
                    dest.display().to_string(),
                ]
            }
            Mount::Bind { src, dest } => {
                vec![
                    "--bind".into(),
                    src.display().to_string(),
                    dest.display().to_string(),
                ]
            }
            Mount::DevBind { src, dest } => {
                vec![
                    "--dev-bind".into(),
                    src.display().to_string(),
                    dest.display().to_string(),
                ]
            }
            Mount::Dev { dest } => {
                vec!["--dev".into(), dest.display().to_string()]
            }
            Mount::Proc { dest } => {
                vec!["--proc".into(), dest.display().to_string()]
            }
            Mount::Tmpfs { dest } => {
                vec!["--tmpfs".into(), dest.display().to_string()]
            }
            Mount::Symlink { src, dest } => {
                vec![
                    "--symlink".into(),
                    src.clone(),
                    dest.display().to_string(),
                ]
            }
            Mount::Overlay {
                lower,
                upper,
                work,
                dest,
            } => {
                // `--overlay-src` sets the read-only lower layer for
                // the `--overlay` that immediately follows it.
                vec![
                    "--overlay-src".into(),
                    lower.display().to_string(),
                    "--overlay".into(),
                    upper.display().to_string(),
                    work.display().to_string(),
                    dest.display().to_string(),
                ]
            }
        }
    }
}

fn mounted_map_args<'a>(
    mounts: impl IntoIterator<Item = &'a Mount>,
) -> Vec<String> {
    let mut args = Vec::new();
    for mount in mounts {
        match mount {
            Mount::RoBind { dest, .. } => {
                // Internal flags carry mounted destinations opaquely; public
                // map flags would reinterpret ':' as source/destination syntax.
                args.push("--landlock-ro-path".into());
                args.push(dest.display().to_string());
            }
            Mount::Bind { dest, .. } => {
                args.push("--landlock-rw-path".into());
                args.push(dest.display().to_string());
            }
            _ => {}
        }
    }
    args
}

struct MountSet {
    base: Vec<Mount>,
    sys_masks: Vec<Mount>,
    home_dotfiles: Vec<Mount>,
    config_hide: Vec<Mount>,
    cache_hide: Vec<Mount>,
    local_overrides: Vec<Mount>,
    /// Read-only binds keeping the invoked command startable in
    /// private-home mode when it is installed under `$HOME` (#81).
    command_binary: Vec<Mount>,
    git_worktree: Vec<Mount>,
    gpu: Vec<Mount>,
    docker: Vec<Mount>,
    tailscale: Vec<Mount>,
    shm: Vec<Mount>,
    display: Vec<Mount>,
    display_env: Vec<(String, String)>,
    systemd_user: Vec<Mount>,
    systemd_env: Vec<(String, String)>,
    ssh_agent: Vec<Mount>,
    ssh_env: Vec<(String, String)>,
    claude_env: Vec<(String, String)>,
    pictures: Vec<Mount>,
    browser_state: Vec<Mount>,
    extra: Vec<Mount>,
    overlay: Vec<Mount>,
    project: Vec<Mount>,
    /// `--map` / `--rw-map` mounts whose destination sits inside the
    /// project directory. Applied after the project bind — bwrap gives
    /// the later mount precedence, so emitting these earlier would let
    /// the read-write project bind silently shadow them (#83).
    extra_inside: Vec<Mount>,
    /// `--overlay-map` mounts inside the project directory; same
    /// shadowing rule as `extra_inside` (#83). Without this, writes
    /// bypassed the copy-on-write layer and landed in the real files.
    overlay_inside: Vec<Mount>,
    mask: Vec<Mount>,
    deny: Vec<Mount>,
    /// tmpfs that hides the on-host overlay upper/work storage from
    /// inside the sandbox. Applied last so it sits on top of the
    /// project mount that contains it.
    overlay_hide: Vec<Mount>,
}

impl MountSet {
    fn ordered_mounts(&self) -> [&[Mount]; 25] {
        [
            &self.base,
            &self.sys_masks,
            &self.gpu,
            &self.docker,
            &self.tailscale,
            &self.shm,
            &self.display,
            &self.systemd_user,
            &self.home_dotfiles,
            &self.config_hide,
            &self.cache_hide,
            &self.local_overrides,
            &self.command_binary,
            &self.git_worktree,
            &self.ssh_agent,
            &self.pictures,
            &self.browser_state,
            &self.extra,
            &self.overlay,
            &self.project,
            &self.extra_inside,
            &self.overlay_inside,
            &self.mask,
            &self.deny,
            &self.overlay_hide,
        ]
    }

    fn all_mount_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for group in self.ordered_mounts() {
            for m in group {
                args.extend(m.to_args());
            }
        }
        args
    }

    fn isolation_args(
        &self,
        project_dir: &Path,
        lockdown: bool,
        network_enabled: bool,
        inherit_env: bool,
        env_pass: &[String],
    ) -> Vec<String> {
        let mut args = vec![
            "--chdir".into(),
            project_dir.display().to_string(),
            "--die-with-parent".into(),
            "--unshare-pid".into(),
            "--unshare-uts".into(),
            "--unshare-ipc".into(),
            "--hostname".into(),
            "ai-sandbox".into(),
        ];

        if lockdown || should_use_new_session() {
            args.push("--new-session".into());
        }

        if !network_enabled {
            args.push("--unshare-net".into());
        }

        if lockdown {
            args.push("--clearenv".into());

            args.extend([
                "--setenv".into(),
                "PATH".into(),
                super::LOCKDOWN_PATH.into(),
            ]);
            args.extend([
                "--setenv".into(),
                "HOME".into(),
                super::home_dir().display().to_string(),
            ]);
            // Pass through terminal-related env vars so child
            // programs can detect capabilities (truecolor, kitty
            // keyboard protocol, etc.).
            for &var in super::TERM_ENV_VARS {
                if let Ok(val) = std::env::var(var) {
                    args.extend(["--setenv".into(), var.into(), val]);
                }
            }
        } else {
            for var in [
                "SSH_AUTH_SOCK",
                "GPG_AGENT_INFO",
                "DOCKER_HOST",
                "BWRAP_BIN",
            ] {
                args.extend(["--unsetenv".into(), var.into()]);
            }
            if self.systemd_env.is_empty() {
                args.extend([
                    "--unsetenv".into(),
                    "DBUS_SESSION_BUS_ADDRESS".into(),
                ]);
            }
            for (key, val) in &self.display_env {
                args.push("--setenv".into());
                args.push(key.clone());
                args.push(val.clone());
            }
            for (key, val) in &self.systemd_env {
                args.push("--setenv".into());
                args.push(key.clone());
                args.push(val.clone());
            }
            // Environment hardening: by default the sandbox inherits
            // only the safe allowlist (plus explicit env_pass
            // entries); --inherit-env keeps the full host
            // environment. Landlock-wrapper inner args are argv, not
            // environment, and are unaffected.
            args.extend(env_args(inherit_env, env_pass));
        }

        // SSH agent env (non-lockdown only — lockdown clears env)
        if !lockdown {
            for (key, val) in &self.ssh_env {
                args.push("--setenv".into());
                args.push(key.clone());
                args.push(val.clone());
            }
        }

        // Claude config dir env (always, even in lockdown)
        for (key, val) in &self.claude_env {
            args.push("--setenv".into());
            args.push(key.clone());
            args.push(val.clone());
        }

        args.extend([
            "--setenv".into(),
            "PS1".into(),
            super::JAIL_PS1.into(),
            "--setenv".into(),
            "_ZO_DOCTOR".into(),
            "0".into(),
        ]);

        args
    }
}

/// bwrap environment arguments for normal (non-lockdown) mode.
///
/// Full inheritance (`--inherit-env`) keeps the host environment as
/// bwrap would by default, with env_pass entries forced verbatim via
/// `--setenv` (winning over the `--unsetenv` hardening above). The
/// default filters to the safe allowlist: `--clearenv` followed by a
/// `--setenv` per kept variable. `--setenv` values survive
/// `--clearenv` regardless of argv order (bwrap applies them after
/// clearing), so the later ssh/claude/PS1 setenvs are unaffected.
fn env_args(inherit_env: bool, env_pass: &[String]) -> Vec<String> {
    let host_env: Vec<(String, String)> = std::env::vars().collect();
    let mut args = Vec::new();
    if inherit_env {
        let mut env = Vec::new();
        crate::config::apply_env_pass(&mut env, env_pass, &host_env);
        for (name, value) in env {
            args.extend(["--setenv".into(), name, value]);
        }
    } else {
        args.push("--clearenv".into());
        for (name, value) in
            crate::config::filtered_child_env(env_pass, &host_env)
        {
            args.extend(["--setenv".into(), name, value]);
        }
    }
    args
}

struct MountSources<'a> {
    hosts_mount: (&'a Path, &'a Path),
    resolv_mount: Option<(&'a Path, &'a Path)>,
    resolv_intermediate_mount: Option<(&'a Path, &'a Path)>,
    empty_path: &'a Path,
    deny_file_path: &'a Path,
    deny_dir_path: &'a Path,
}

impl<'a> MountSources<'a> {
    fn from_guard(guard: &'a SandboxGuard) -> Self {
        Self {
            hosts_mount: guard.hosts_mount(),
            resolv_mount: guard.resolv_mount(),
            resolv_intermediate_mount: guard.resolv_intermediate_mount(),
            empty_path: guard.empty_path(),
            deny_file_path: guard.deny_file_path(),
            deny_dir_path: guard.deny_dir_path(),
        }
    }

    #[cfg(test)]
    fn legacy(
        hosts_mount: (&'a Path, &'a Path),
        resolv_mount: Option<(&'a Path, &'a Path)>,
        empty_path: &'a Path,
    ) -> Self {
        Self {
            hosts_mount,
            resolv_mount,
            resolv_intermediate_mount: None,
            empty_path,
            deny_file_path: empty_path,
            deny_dir_path: empty_path,
        }
    }
}

pub struct SandboxGuard {
    hosts_path: PathBuf,
    /// Where to mount the private hosts file inside the sandbox.
    /// If /etc/hosts is a symlink (e.g. NixOS), this is the symlink
    /// target so the symlink inherited from --ro-bind /etc resolves.
    /// If it is a regular file, this is /etc/hosts itself.
    hosts_dest: PathBuf,
    resolv_path: Option<PathBuf>,
    /// Where to mount the resolv temp file inside the sandbox.
    /// If /etc/resolv.conf is a symlink, this is the symlink target
    /// so the symlink inside /etc (from --ro-bind /etc) resolves.
    /// If it's a regular file, this is /etc/resolv.conf itself.
    resolv_dest: Option<PathBuf>,
    /// Additional mount point for intermediate symlink hops that live
    /// under /run or /tmp (e.g. Fedora toolbox's /run/host/etc/resolv.conf).
    resolv_intermediate_dest: Option<PathBuf>,
    /// Empty tempfile used as the source for --mask file overlays.
    empty_path: PathBuf,
    /// Mode-000 tempfile used as the source for --deny-path file overlays.
    deny_file_path: PathBuf,
    /// Mode-000 temp directory used as the source for --deny-path directory overlays.
    deny_dir_path: PathBuf,
}

impl SandboxGuard {
    #[cfg(test)]
    fn hosts_path(&self) -> &Path {
        &self.hosts_path
    }

    fn hosts_mount(&self) -> (&Path, &Path) {
        (&self.hosts_path, &self.hosts_dest)
    }

    fn resolv_mount(&self) -> Option<(&Path, &Path)> {
        match (&self.resolv_path, &self.resolv_dest) {
            (Some(src), Some(dest)) => Some((src, dest)),
            _ => None,
        }
    }

    fn resolv_intermediate_mount(&self) -> Option<(&Path, &Path)> {
        match (&self.resolv_path, &self.resolv_intermediate_dest) {
            (Some(src), Some(dest)) => Some((src, dest)),
            _ => None,
        }
    }

    fn empty_path(&self) -> &Path {
        &self.empty_path
    }

    fn deny_file_path(&self) -> &Path {
        &self.deny_file_path
    }

    fn deny_dir_path(&self) -> &Path {
        &self.deny_dir_path
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.hosts_path);
        if let Some(ref p) = self.resolv_path {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_file(&self.empty_path);
        let _ = std::fs::remove_file(&self.deny_file_path);
        let _ = std::fs::remove_dir(&self.deny_dir_path);
    }
}

#[cfg(test)]
impl SandboxGuard {
    fn test_with_hosts(path: PathBuf) -> Self {
        SandboxGuard {
            hosts_path: path,
            hosts_dest: PathBuf::from("/etc/hosts"),
            resolv_path: None,
            resolv_dest: None,
            resolv_intermediate_dest: None,
            empty_path: PathBuf::from("/tmp/ai-jail-test-empty"),
            deny_file_path: PathBuf::from("/tmp/ai-jail-test-deny-file"),
            deny_dir_path: PathBuf::from("/tmp/ai-jail-test-deny-dir"),
        }
    }
}

const CONFIG_DENY: &[&str] = &["BraveSoftware", "Bitwarden"];

const CACHE_DENY: &[&str] = &[
    "BraveSoftware",
    "basilisk-dev",
    "chromium",
    "spotify",
    "nvidia",
    "mesa_shader_cache",
];

const LOCAL_SHARE_RW: &[&str] = &[
    "ai-memory",
    "zoxide",
    "crush",
    "kiro-cli",
    "opencode",
    "soulforge",
    "atuin",
    "mise",
    "yarn",
    "flutter",
    "kotlin",
    "NuGet",
    "pipx",
    "ruby-advisory-db",
    "uv",
];

const BWRAP_ENV_VAR: &str = "BWRAP_BIN";
const BWRAP_CANDIDATES: &[&str] = &[
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/usr/local/bin/bwrap",
    "/run/wrappers/bin/bwrap",
    "/run/current-system/sw/bin/bwrap",
];

/// Fixed path inside the sandbox where ai-jail is bind-mounted
/// for the Landlock wrapper.  Lives under /tmp (always a fresh
/// tmpfs in the sandbox) so it works regardless of where the host
/// binary is installed.
const LANDLOCK_WRAPPER_DEST: &str = "/tmp/.ai-jail-landlock";

fn self_binary_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

pub(crate) fn bwrap_binary_path() -> Result<PathBuf, String> {
    let mut override_error: Option<String> = None;

    if let Some(raw) = std::env::var_os(BWRAP_ENV_VAR) {
        let p = PathBuf::from(raw);
        if let Some(path) = trusted_bwrap_path(&p) {
            return Ok(path);
        }
        output::security_warn(
            "ignoring BWRAP_BIN: target failed trusted binary validation",
        );
        override_error = Some(format!(
            "{BWRAP_ENV_VAR} is set to {} but it is not a trusted executable",
            p.display()
        ));
    }

    for candidate in BWRAP_CANDIDATES {
        let p = PathBuf::from(candidate);
        if let Some(path) = trusted_bwrap_path(&p) {
            return Ok(path);
        }
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("bwrap");
            if let Some(path) = trusted_bwrap_path(&candidate) {
                return Ok(path);
            }
        }
    }

    let mut msg = String::from(
        "bwrap (bubblewrap) not found in trusted locations. Install it:\n  \
         Arch: pacman -S bubblewrap\n  \
         Debian/Ubuntu: apt install bubblewrap\n  \
         Fedora: dnf install bubblewrap\n\
         Or set BWRAP_BIN=/absolute/path/to/bwrap",
    );
    if let Some(err) = override_error {
        msg.push('\n');
        msg.push_str(&err);
    }
    Err(msg)
}

/// Use --new-session only when stdin is NOT a terminal.
///
/// bwrap's --new-session calls setsid() inside the sandbox, which
/// creates a new session with NO controlling terminal. This
/// completely blocks SIGWINCH delivery, so the child never sees
/// terminal resize events.
///
/// When stdin IS a terminal (interactive use), we skip
/// --new-session so the child stays in the same session and
/// receives SIGWINCH from the kernel when the terminal is
/// resized. The PTY proxy (status bar) path already skips
/// --new-session because the child has its own controlling
/// terminal (the PTY slave).
///
/// --new-session is still used for non-interactive invocations
/// (piped input, scripts) where SIGWINCH doesn't apply and the
/// extra session isolation is beneficial.
fn should_use_new_session() -> bool {
    use std::io::IsTerminal;
    !crate::statusbar::is_active() && !std::io::stdin().is_terminal()
}

fn trusted_bwrap_path(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    let metadata = canonical.metadata().ok()?;
    let in_nix_store = canonical.starts_with("/nix/store");
    trusted_binary_metadata(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
        in_nix_store,
    )
    .then_some(canonical)
}

fn trusted_binary_metadata(
    is_file: bool,
    uid: u32,
    mode: u32,
    in_nix_store: bool,
) -> bool {
    if !is_file || mode & 0o111 == 0 {
        return false;
    }
    if uid == 0 {
        mode & 0o022 == 0
    } else if in_nix_store {
        mode & 0o222 == 0
    } else {
        false
    }
}

fn new_hosts_file() -> Result<(PathBuf, std::fs::File), String> {
    let tmp = std::env::temp_dir();

    for attempt in 0..128_u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name =
            format!("bwrap-hosts.{}.{}.{}", std::process::id(), nonce, attempt);
        let path = tmp.join(name);

        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => {
                let _ = std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(0o600),
                );
                return Ok((path, file));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!("Failed to create temp hosts file: {e}"));
            }
        }
    }

    Err(
        "Failed to create unique temp hosts file after multiple attempts"
            .into(),
    )
}

pub fn check() -> Result<(), String> {
    let bwrap = bwrap_binary_path()?;
    match Command::new(&bwrap).arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(_) => Err(format!(
            "bwrap found at {} but returned an error. Check your installation.",
            bwrap.display()
        )),
        Err(e) => Err(format!(
            "Failed to execute bwrap at {}: {e}",
            bwrap.display()
        )),
    }
}

pub fn prepare() -> Result<SandboxGuard, String> {
    let (path, mut file) = new_hosts_file()?;
    let hosts_dest = resolved_hosts_dest();
    let contents =
        b"127.0.0.1 localhost ai-sandbox\n::1       localhost ai-sandbox\n";

    file.write_all(contents)
        .map_err(|e| format!("Failed to create temp hosts file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync temp hosts file: {e}"))?;

    let (resolv_path, resolv_dest, resolv_intermediate_dest) =
        new_resolv_file();
    let empty_path = new_empty_file()?;
    let deny_file_path = new_deny_file()?;
    let deny_dir_path = new_deny_dir()?;

    Ok(SandboxGuard {
        hosts_path: path,
        hosts_dest,
        resolv_path,
        resolv_dest,
        resolv_intermediate_dest,
        empty_path,
        deny_file_path,
        deny_dir_path,
    })
}

fn resolved_hosts_dest() -> PathBuf {
    std::fs::canonicalize("/etc/hosts")
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"))
}

/// Create a zero-byte tempfile used as the source for --mask
/// overlays. Same permissions pattern as the hosts file.
fn new_empty_file() -> Result<PathBuf, String> {
    let tmp = std::env::temp_dir();
    for attempt in 0..128_u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!(
            "ai-jail-empty.{}.{}.{}",
            std::process::id(),
            nonce,
            attempt
        );
        let path = tmp.join(name);
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(_file) => {
                let _ = std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(0o400),
                );
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!("Failed to create empty tempfile: {e}"));
            }
        }
    }
    Err("Failed to create empty tempfile after 128 attempts".into())
}

/// Create a mode-000 tempfile used as the source for --deny-path file overlays.
fn new_deny_file() -> Result<PathBuf, String> {
    let path = new_empty_file()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .map_err(|e| format!("Failed to chmod deny tempfile: {e}"))?;
    Ok(path)
}

/// Create a mode-000 temp directory used as the source for --deny-path directory overlays.
fn new_deny_dir() -> Result<PathBuf, String> {
    let tmp = std::env::temp_dir();
    for attempt in 0..128_u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!(
            "ai-jail-deny-dir.{}.{}.{}",
            std::process::id(),
            nonce,
            attempt
        );
        let path = tmp.join(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {
                std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(0o000),
                )
                .map_err(|e| format!("Failed to chmod deny tempdir: {e}"))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!("Failed to create deny tempdir: {e}"));
            }
        }
    }
    Err("Failed to create deny tempdir after 128 attempts".into())
}

/// Create a temp copy of /etc/resolv.conf and determine where to
/// mount it inside the sandbox.
///
/// If /etc/resolv.conf is a symlink (common on WSL and systemd-resolved),
/// we mount the temp file at the symlink *target* so the symlink inside
/// the sandbox (inherited from --ro-bind /etc) resolves correctly.
/// If it is a regular file, we mount directly over /etc/resolv.conf.
///
/// On systemd-resolved systems the stub resolv.conf contains
/// `nameserver 127.0.0.53`.  While the stub listener is reachable
/// over a shared network namespace, some runtimes (notably Go's
/// pure-Go resolver) fail to use it reliably inside a sandbox.
/// When we detect the stub address we replace the contents with the
/// real upstream nameservers from `/run/systemd/resolve/resolv.conf`.
fn new_resolv_file() -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let resolv = Path::new("/etc/resolv.conf");

    // canonicalize resolves all symlinks and normalizes ".." segments.
    // read_link only reads one level and can produce paths like
    // /etc/../run/systemd/resolve/stub-resolv.conf which may confuse
    // bwrap when creating intermediate mount-point directories.
    let canonical_dest = match std::fs::canonicalize(resolv) {
        Ok(canonical) => canonical,
        Err(_) => resolv.to_path_buf(),
    };

    // Detect intermediate symlink hops that live in tmpfs directories and
    // would not survive the sandbox's private /run and /tmp mounts.
    let intermediate_dest =
        std::fs::read_link(resolv).ok().and_then(|target| {
            let first_hop = if target.is_absolute() {
                target
            } else {
                resolve_relative_symlink(resolv, &target)
            };
            let under_tmpfs = first_hop.starts_with("/run/")
                || first_hop.starts_with("/tmp/");
            if under_tmpfs && first_hop != canonical_dest {
                Some(first_hop)
            } else {
                None
            }
        });

    let contents = match std::fs::read(resolv) {
        Ok(c) => c,
        Err(e) => {
            output::warn(&format!("Cannot read /etc/resolv.conf: {e}"));
            return (None, None, None);
        }
    };

    // Replace systemd-resolved stub address with real upstream
    // nameservers when available.
    let contents = resolve_real_nameservers(contents);

    let tmp = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let name = format!("bwrap-resolv.{}.{}", std::process::id(), nonce);
    let path = tmp.join(name);

    match OpenOptions::new().create_new(true).write(true).open(&path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&contents) {
                output::warn(&format!("Cannot write temp resolv.conf: {e}"));
                let _ = std::fs::remove_file(&path);
                return (None, None, None);
            }
            let _ = f.sync_all();
            let _ = std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o600),
            );
            (Some(path), Some(canonical_dest), intermediate_dest)
        }
        Err(e) => {
            output::warn(&format!("Cannot create temp resolv.conf: {e}"));
            (None, None, None)
        }
    }
}

/// Resolve a symlink target that is relative to the symlink itself.
fn resolve_relative_symlink(link: &Path, target: &Path) -> PathBuf {
    let base = link.parent().unwrap_or(Path::new("/"));
    normalize_path(&base.join(target))
}

/// Remove `.` and `..` components from a path without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(p) => out.push(p),
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::RootDir => out = PathBuf::from("/"),
            _ => {}
        }
    }
    out
}

/// If `contents` references the systemd-resolved stub listener
/// (`nameserver 127.0.0.53`), try to replace with the real upstream
/// nameservers from `/run/systemd/resolve/resolv.conf`.
///
/// The substitution exists because some sandboxed runtimes (notably
/// Go's pure-Go resolver) cannot reliably dial the 127.0.0.53 stub
/// from inside the bwrap mount/PID namespace.
///
/// **Exception — split-DNS scenarios** (issue #49). When tailscale or
/// a similar tunnel registers its DNS with systemd-resolved, the
/// uplink file lists the tunnel's DNS server alongside (or instead of)
/// the real upstream. Flattening that into resolv.conf loses
/// systemd-resolved's per-domain routing knowledge: the resolver
/// dials the first nameserver, gets NXDOMAIN for a public host the
/// tunnel doesn't know about, and gives up. Detect this and keep the
/// stub, which still does the right routing internally.
fn resolve_real_nameservers(contents: Vec<u8>) -> Vec<u8> {
    if !contents_have_stub(&contents) {
        return contents;
    }
    let real = Path::new("/run/systemd/resolve/resolv.conf");
    let Ok(real_contents) = std::fs::read(real) else {
        return contents;
    };
    pick_resolv_contents(contents, real_contents)
}

fn contents_have_stub(contents: &[u8]) -> bool {
    String::from_utf8_lossy(contents).lines().any(|line| {
        let line = line.trim();
        line.starts_with("nameserver") && line.contains("127.0.0.53")
    })
}

/// Decide which resolv.conf body to mount into the sandbox.
///
/// When `uplink` shows split-DNS markers (tunnel DNS in the CGNAT
/// range or link-local DNS), or either file mentions Tailscale
/// MagicDNS search domains, we keep the original stub so the stub
/// listener at 127.0.0.53 keeps doing the per-domain routing. In
/// every other case we use the uplink, preserving the original
/// Go-resolver workaround.
fn pick_resolv_contents(original: Vec<u8>, uplink: Vec<u8>) -> Vec<u8> {
    if uplink_has_split_dns_markers(&uplink)
        || resolv_has_tailscale_magicdns_domain(&original)
        || resolv_has_tailscale_magicdns_domain(&uplink)
    {
        original
    } else {
        uplink
    }
}

/// True iff `uplink` lists any nameserver address that strongly
/// suggests split-DNS (tunnel/VPN). Currently:
///
/// * Carrier-grade NAT (`100.64.0.0/10`) — tailscale's DNS sits at
///   `100.100.100.100` by default; many other tunnels use this range.
/// * Link-local (`169.254.0.0/16`) — sometimes used by VPN agents
///   for split-DNS forwarders.
///
/// Public DNS (8.8.8.8, 1.1.1.1, ISP ranges) and RFC1918 home/office
/// LAN ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are NOT
/// flagged: they're far more often the legitimate upstream than a
/// tunnel forwarder.
fn uplink_has_split_dns_markers(uplink: &[u8]) -> bool {
    String::from_utf8_lossy(uplink).lines().any(|line| {
        let Some(rest) = line.trim().strip_prefix("nameserver") else {
            return false;
        };
        let token = rest.split_whitespace().next().unwrap_or("");
        is_split_dns_marker_ip(token)
    })
}

fn is_split_dns_marker_ip(s: &str) -> bool {
    let Ok(addr) = s.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let [a, b, _, _] = addr.octets();
    // 100.64.0.0/10  →  first octet 100 AND second octet in [64, 127]
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // 169.254.0.0/16
    if a == 169 && b == 254 {
        return true;
    }
    false
}

/// Tailscale MagicDNS domains always live under this public TLD
/// (`<tailnet>.ts.net`); its presence in resolv.conf search/domain
/// lines signals a tailscale split-DNS setup.
const TAILSCALE_MAGICDNS_TLD: &str = "ts.net";

fn resolv_has_tailscale_magicdns_domain(contents: &[u8]) -> bool {
    String::from_utf8_lossy(contents).lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next() else {
            return false;
        };
        if kind != "search" && kind != "domain" {
            return false;
        }
        fields.any(|token| {
            let token = token.trim_end_matches('.');
            token == TAILSCALE_MAGICDNS_TLD
                || token
                    .strip_suffix(TAILSCALE_MAGICDNS_TLD)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    })
}

fn resolve_landlock_wrapper(
    config: &Config,
) -> Result<Option<PathBuf>, String> {
    if !config.landlock_enabled()
        && !config.seccomp_enabled()
        && !config.rlimits_enabled()
    {
        return Ok(None);
    }

    match self_binary_path() {
        Some(path) => Ok(Some(path)),
        None => Err(
            "Cannot resolve ai-jail binary for enabled sandbox wrapper controls"
                .into(),
        ),
    }
}

fn landlock_wrapper_args(
    config: &Config,
    map_args: &[String],
    verbose: bool,
) -> Vec<String> {
    let mut args = vec![
        LANDLOCK_WRAPPER_DEST.into(),
        "--landlock-exec".into(),
        if config.landlock_enabled() {
            "--landlock".into()
        } else {
            "--no-landlock".into()
        },
    ];

    if config.lockdown_enabled() {
        args.push("--lockdown".into());
    }
    if config.private_home_enabled() {
        args.push("--private-home".into());
    }
    // Forward the agent_state capability so the inner wrapper's
    // Landlock rules match the outer bwrap state mounts.
    if config.agent_state_enabled() {
        args.push("--agent-state".into());
    }
    args.push(if config.seccomp_enabled() {
        "--seccomp".into()
    } else {
        "--no-seccomp".into()
    });
    args.push(if config.rlimits_enabled() {
        "--rlimits".into()
    } else {
        "--no-rlimits".into()
    });

    args.push(if config.gpu_enabled() {
        "--gpu".into()
    } else {
        "--no-gpu".into()
    });
    args.push(if config.docker_enabled() {
        "--docker".into()
    } else {
        "--no-docker".into()
    });
    args.push(if config.tailscale_enabled() {
        "--tailscale".into()
    } else {
        "--no-tailscale".into()
    });
    args.push(if config.display_enabled() {
        "--display".into()
    } else {
        "--no-display".into()
    });
    if let Some(enabled) = config.systemd_user {
        args.push(if enabled {
            "--systemd-user".into()
        } else {
            "--no-systemd-user".into()
        });
    }
    if let Some(enabled) = config.no_worktree.map(|value| !value) {
        args.push(if enabled {
            "--worktree".into()
        } else {
            "--no-worktree".into()
        });
    }
    if config.ssh_enabled() {
        args.push("--ssh".into());
    }
    if config.pictures_enabled() {
        args.push("--pictures".into());
    }
    if let Some(profile) = config.browser_profile() {
        args.push(format!("--browser={}", profile.as_str()));
    }

    for port in config.allow_tcp_ports() {
        args.push("--allow-tcp-port".into());
        args.push(port.to_string());
    }

    if config.browser_profile().is_none() {
        args.extend_from_slice(map_args);
    }
    for path in &config.mask {
        args.push("--mask".into());
        args.push(path.display().to_string());
    }
    for path in &config.deny_paths {
        args.push("--deny-path".into());
        args.push(path.display().to_string());
    }
    if let Some(dir) = &config.claude_dir {
        args.push("--claude-dir".into());
        args.push(dir.display().to_string());
    }

    if verbose {
        args.push("--verbose".into());
    }

    args.push("--".into());
    args
}

pub fn build(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<Command, String> {
    let sources = MountSources::from_guard(guard);
    let mount_set =
        discover_mounts_full(config, project_dir, &sources, verbose)?;
    let map_args = mounted_map_args(
        mount_set.extra.iter().chain(mount_set.extra_inside.iter()),
    );
    let lockdown = config.lockdown_enabled();
    let bwrap = bwrap_binary_path()?;
    let launch = super::build_launch_command(config);

    // Landlock wrapper: bind-mount ai-jail into /tmp inside the
    // sandbox so it can apply Landlock after bwrap namespace setup.
    let wrapper = resolve_landlock_wrapper(config)?;

    let mut cmd = Command::new(bwrap);

    for arg in mount_set.all_mount_args() {
        cmd.arg(arg);
    }

    // Self binary mount for Landlock wrapper (after all other
    // mounts so /tmp tmpfs already exists)
    if let Some(ref wrapper_path) = wrapper {
        let m = Mount::FileRoBind {
            src: wrapper_path.clone(),
            dest: PathBuf::from(LANDLOCK_WRAPPER_DEST),
        };
        for arg in m.to_args() {
            cmd.arg(arg);
        }
    }

    for arg in mount_set.isolation_args(
        project_dir,
        lockdown,
        config.network_enabled(),
        config.inherit_env_enabled(),
        config.env_pass(),
    ) {
        cmd.arg(arg);
    }

    // Propagate quiet mode into the sandbox so the inner
    // landlock-exec process suppresses its output too.
    if crate::output::is_quiet() {
        cmd.arg("--setenv").arg("AI_JAIL_QUIET").arg("1");
    }

    cmd.arg("--");

    if wrapper.is_some() {
        for arg in landlock_wrapper_args(config, &map_args, verbose) {
            cmd.arg(arg);
        }
    }

    cmd.arg(&launch.program);
    for arg in &launch.args {
        cmd.arg(arg);
    }

    Ok(cmd)
}

pub fn dry_run(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<String, String> {
    let sources = MountSources::from_guard(guard);
    let args = build_dry_run_args_full(config, project_dir, &sources, verbose)?;
    Ok(format_dry_run_args(&args))
}

#[cfg(test)]
fn build_dry_run_args(
    config: &Config,
    project_dir: &Path,
    hosts_mount: (&Path, &Path),
    resolv_mount: Option<(&Path, &Path)>,
    empty_path: &Path,
    verbose: bool,
) -> Result<Vec<String>, String> {
    let sources = MountSources::legacy(hosts_mount, resolv_mount, empty_path);
    build_dry_run_args_full(config, project_dir, &sources, verbose)
}

fn build_dry_run_args_full(
    config: &Config,
    project_dir: &Path,
    sources: &MountSources<'_>,
    verbose: bool,
) -> Result<Vec<String>, String> {
    let mount_set =
        discover_mounts_full(config, project_dir, sources, verbose)?;
    let map_args = mounted_map_args(
        mount_set.extra.iter().chain(mount_set.extra_inside.iter()),
    );
    let lockdown = config.lockdown_enabled();
    let launch = super::build_launch_command(config);
    let mut args: Vec<String> =
        vec![bwrap_binary_path()?.display().to_string()];

    args.extend(mount_set.all_mount_args());

    // Self binary mount for Landlock wrapper
    let wrapper = resolve_landlock_wrapper(config)?;
    if let Some(ref self_bin) = wrapper {
        let m = Mount::FileRoBind {
            src: self_bin.clone(),
            dest: PathBuf::from(LANDLOCK_WRAPPER_DEST),
        };
        args.extend(m.to_args());
    }

    args.extend(mount_set.isolation_args(
        project_dir,
        lockdown,
        config.network_enabled(),
        config.inherit_env_enabled(),
        config.env_pass(),
    ));

    args.push("--".into());

    if wrapper.is_some() {
        args.extend(landlock_wrapper_args(config, &map_args, verbose));
    }

    args.push(launch.program);
    args.extend(launch.args);

    Ok(args)
}

fn format_dry_run_args(args: &[String]) -> String {
    if args.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&super::quote_shell_arg(&args[0]));
    out.push_str(" \\\n");

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            out.push_str("  -- \\\n");
            out.push_str("  ");
            for (idx, val) in args.iter().enumerate().skip(i + 1) {
                if idx > i + 1 {
                    out.push(' ');
                }
                out.push_str(&super::quote_shell_arg(val));
            }
            out.push('\n');
            break;
        }

        if arg.starts_with("--") {
            out.push_str("  ");
            out.push_str(arg);
            let mut j = i + 1;
            while j < args.len()
                && !args[j].starts_with("--")
                && args[j] != "--"
            {
                out.push(' ');
                out.push_str(&super::quote_shell_arg(&args[j]));
                j += 1;
            }
            out.push_str(" \\\n");
            i = j;
            continue;
        }

        out.push_str("  ");
        for (idx, val) in args.iter().enumerate().skip(i) {
            if idx > i {
                out.push(' ');
            }
            out.push_str(&super::quote_shell_arg(val));
        }
        out.push('\n');
        break;
    }

    out
}

fn discover_mounts_full(
    config: &Config,
    project_dir: &Path,
    sources: &MountSources<'_>,
    verbose: bool,
) -> Result<MountSet, String> {
    let lockdown = config.lockdown_enabled();
    let browser_profile = config.browser_profile();
    let browser_mode = browser_profile.is_some();
    let private_home =
        lockdown || browser_mode || config.private_home_enabled();
    let enable_gpu = !lockdown && config.gpu_enabled();
    let enable_docker = !lockdown && config.docker_enabled();
    let enable_tailscale = !lockdown && config.tailscale_enabled();
    let enable_display = !lockdown && config.display_enabled();
    let exempt = super::dotdir_exemptions(config);

    let (display_mounts, display_env) = if enable_display {
        discover_display(config, verbose)
    } else {
        (vec![], vec![])
    };
    let (systemd_mounts, systemd_env) = discover_systemd_user(
        config,
        lockdown,
        browser_mode,
        enable_display,
        sources.deny_file_path,
        verbose,
    );
    let (ssh_agent_mount, ssh_env) =
        discover_ssh(config, lockdown, browser_mode, private_home, verbose);
    let claude_env = discover_claude_env(config);
    let mask_mounts =
        discover_mask_mounts(config, project_dir, sources.empty_path, verbose);
    let deny_mounts = discover_deny_mounts(
        config,
        project_dir,
        sources.deny_file_path,
        sources.deny_dir_path,
        verbose,
    );
    let pictures_mount =
        discover_pictures_mount(config, lockdown, browser_mode);
    let browser_state_mount =
        discover_browser_state_mount(config, browser_profile, verbose);
    let home_dotfiles = discover_home_dotfiles_full(
        config,
        private_home,
        &exempt,
        lockdown,
        verbose,
    );
    // Overlay maps are opt-in and only meaningful when the sandbox
    // can write: disabled under lockdown (read-only) and browser mode.
    let (overlay_mounts_v, overlay_hide_v) = if lockdown || browser_mode {
        if !config.overlay_maps.is_empty() {
            output::warn(
                "Overlay maps are disabled under lockdown/browser \
                     mode; skipping.",
            );
        }
        (vec![], vec![])
    } else {
        overlay_mounts(&config.overlay_maps, project_dir, verbose)?
    };
    let (extra_outside, extra_inside) = if lockdown || browser_mode {
        (vec![], vec![])
    } else {
        split_by_project(
            extra_mounts(&config.rw_maps, &config.ro_maps),
            project_dir,
        )
    };
    let (overlay_outside, overlay_inside) =
        split_by_project(overlay_mounts_v, project_dir);

    Ok(MountSet {
        base: discover_base(
            sources.hosts_mount,
            sources.resolv_mount,
            sources.resolv_intermediate_mount,
        ),
        sys_masks: {
            let mut masks = discover_sys_masks(lockdown);
            if (!display_mounts.is_empty() || !systemd_mounts.is_empty())
                && let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR")
            {
                let runtime = PathBuf::from(runtime);
                for name in
                    ["bus", "systemd", "podman", "docker", "docker.sock"]
                {
                    masks.push(Mount::Tmpfs {
                        dest: runtime.join(name),
                    });
                }
            }
            masks
        },
        home_dotfiles,
        config_hide: if private_home {
            vec![]
        } else {
            discover_subdir_hide(".config", CONFIG_DENY)
        },
        cache_hide: if private_home {
            vec![]
        } else {
            discover_subdir_hide(".cache", CACHE_DENY)
        },
        local_overrides: if private_home {
            vec![]
        } else {
            discover_local_overrides()
        },
        // Only for user-requested private home: lockdown clears the
        // environment (system PATH only), and browser mode runs
        // system-installed browsers.
        command_binary: if config.private_home_enabled() && !lockdown {
            discover_command_binary(config, verbose)
        } else {
            vec![]
        },
        git_worktree: git_worktree_mounts(config, project_dir, verbose),
        gpu: if enable_gpu {
            discover_gpu(verbose)
        } else {
            vec![]
        },
        docker: if enable_docker {
            discover_docker()
        } else {
            vec![]
        },
        tailscale: if enable_tailscale {
            discover_tailscale()
        } else {
            vec![]
        },
        shm: if lockdown {
            vec![]
        } else {
            discover_shm(config.host_shm_enabled())
        },
        display: display_mounts,
        display_env,
        systemd_user: systemd_mounts,
        systemd_env,
        ssh_agent: ssh_agent_mount,
        ssh_env,
        claude_env,
        pictures: pictures_mount,
        browser_state: browser_state_mount,
        extra: extra_outside,
        overlay: overlay_outside,
        project: project_mount(project_dir, lockdown || browser_mode),
        extra_inside,
        overlay_inside,
        mask: mask_mounts,
        deny: deny_mounts,
        overlay_hide: overlay_hide_v,
    })
}

/// Split mounts into (outside, inside) the project directory. A mount
/// whose destination sits inside the project must be applied after the
/// project bind: bwrap gives the later mount precedence, so emitting it
/// earlier lets the project bind silently shadow it — `--map .git`
/// stayed writable and `--overlay-map` writes hit the real files (#83).
fn split_by_project(
    mounts: Vec<Mount>,
    project_dir: &Path,
) -> (Vec<Mount>, Vec<Mount>) {
    mounts
        .into_iter()
        .partition(|m| !m.dest().starts_with(project_dir))
}

/// SSH agent socket + ~/.ssh + tmpfs over /etc/ssh/ssh_config.d.
/// The tmpfs prevents "bad owner or permissions" errors caused by
/// bwrap's user namespace remapping root-owned ssh config files to
/// nobody. Returns the mount list and any env vars (`SSH_AUTH_SOCK`)
/// to propagate into the sandbox.
fn discover_ssh(
    config: &Config,
    lockdown: bool,
    browser_mode: bool,
    private_home: bool,
    verbose: bool,
) -> (Vec<Mount>, Vec<(String, String)>) {
    if lockdown || browser_mode || !config.ssh_enabled() {
        return (vec![], vec![]);
    }
    let mut mounts = vec![Mount::Tmpfs {
        dest: "/etc/ssh/ssh_config.d".into(),
    }];
    let mut env = vec![];
    let ssh_dir = super::home_dir().join(".ssh");
    if private_home && ssh_dir.is_dir() {
        mounts.push(Mount::RoBind {
            src: ssh_dir.clone(),
            dest: ssh_dir,
        });
    }
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        let sock_path = PathBuf::from(&sock);
        if sock_path.exists() {
            if verbose {
                output::verbose(&format!("SSH agent: {}", sock_path.display()));
            }
            mounts.push(Mount::Bind {
                src: sock_path.clone(),
                dest: sock_path,
            });
            env.push(("SSH_AUTH_SOCK".into(), sock));
        }
    }
    (mounts, env)
}

/// `CLAUDE_CONFIG_DIR` env if --claude-dir is set, else empty.
fn discover_claude_env(config: &Config) -> Vec<(String, String)> {
    config
        .claude_dir
        .as_ref()
        .map(|dir| {
            vec![("CLAUDE_CONFIG_DIR".into(), dir.display().to_string())]
        })
        .unwrap_or_default()
}

/// Mask mounts: user-specified `mask` list, plus the project's own
/// .ai-jail file when `hide_config_enabled()` (issue #41). The latter
/// is deduped against the user list so we don't double-mount the
/// same path.
fn discover_mask_mounts(
    config: &Config,
    project_dir: &Path,
    empty_path: &Path,
    verbose: bool,
) -> Vec<Mount> {
    let expanded = super::effective_mask_patterns(config, project_dir);
    build_mask_mounts(&expanded, project_dir, empty_path, verbose)
}

fn discover_deny_mounts(
    config: &Config,
    project_dir: &Path,
    deny_file_path: &Path,
    deny_dir_path: &Path,
    verbose: bool,
) -> Vec<Mount> {
    let expanded = super::expand_mask_patterns(
        &config.deny_paths,
        &config.deny_path_exceptions,
        project_dir,
    );
    build_deny_mounts(
        &expanded,
        project_dir,
        deny_file_path,
        deny_dir_path,
        verbose,
    )
}

fn discover_pictures_mount(
    config: &Config,
    lockdown: bool,
    browser_mode: bool,
) -> Vec<Mount> {
    if lockdown || browser_mode || !config.pictures_enabled() {
        return vec![];
    }
    let p = super::home_dir().join("Pictures");
    if p.is_dir() {
        vec![Mount::RoBind {
            src: p.clone(),
            dest: p,
        }]
    } else {
        vec![]
    }
}

/// `discover_home_dotfiles` plus the post-fix append of an explicit
/// `--claude-dir` bind mount when applicable.
fn discover_home_dotfiles_full(
    config: &Config,
    private_home: bool,
    exempt: &[&str],
    lockdown: bool,
    verbose: bool,
) -> Vec<Mount> {
    // Command-specific agent state (~/.claude, ~/.codex,
    // ~/.claude.json, ...) is a trusted capability: mounted only when
    // explicitly enabled. User hide_dotdirs always win over the
    // capability ("user hides win").
    let agent_state = config.agent_state_enabled();
    let mut mounts = discover_home_dotfiles(
        private_home,
        &config.hide_dotdirs,
        exempt,
        verbose,
    );
    if private_home {
        let home = super::home_dir();
        if agent_state {
            for relative in command_state_paths(config) {
                if state_path_hidden(relative, &config.hide_dotdirs) {
                    continue;
                }
                let path = home.join(relative);
                if safe_state_dir(&path) {
                    mounts.push(Mount::Bind {
                        src: path.clone(),
                        dest: path,
                    });
                }
            }
        }
        for name in [".gitconfig", ".gitignore"] {
            let path = home.join(name);
            if safe_state_file(&path) {
                mounts.push(Mount::RoBind {
                    src: path.clone(),
                    dest: path,
                });
            }
        }
        let claude_json = home.join(".claude.json");
        if agent_state
            && !state_path_hidden(".claude", &config.hide_dotdirs)
            && crate::command::effective_name(&config.command) == Some("claude")
            && safe_state_file(&claude_json)
        {
            mounts.push(Mount::Bind {
                src: claude_json.clone(),
                dest: claude_json,
            });
        }
    } else if agent_state {
        // Non-private-home passthrough still gates the command-state
        // extras that the generic dotdir enumeration never mounts
        // (.kimi-code is in DOTDIR_DENY; .claude.json is a file).
        if crate::command::effective_name(&config.command)
            .is_some_and(|name| name.starts_with("kimi"))
            && !state_path_hidden(".kimi-code", &config.hide_dotdirs)
        {
            let path = super::home_dir().join(".kimi-code");
            if safe_state_dir(&path) {
                mounts.push(Mount::Bind {
                    src: path.clone(),
                    dest: path,
                });
            }
        }
        let claude_json = super::home_dir().join(".claude.json");
        if !state_path_hidden(".claude", &config.hide_dotdirs)
            && safe_state_file(&claude_json)
        {
            mounts.push(Mount::Bind {
                src: claude_json.clone(),
                dest: claude_json,
            });
        }
    }
    if !private_home && config.docker_enabled() {
        let docker_config = super::home_dir().join(".docker/config.json");
        if docker_config.is_file() {
            mounts.push(Mount::RoBind {
                src: docker_config.clone(),
                dest: docker_config,
            });
        }
    }
    if !lockdown
        && let Some(dir) = &config.claude_dir
        && super::path_exists(dir)
    {
        if verbose {
            output::verbose(&format!("claude-dir: {}", dir.display()));
        }
        mounts.push(Mount::Bind {
            src: dir.clone(),
            dest: dir.clone(),
        });
    }
    mounts
}

fn command_state_paths(config: &Config) -> &'static [&'static str] {
    match crate::command::effective_name(&config.command) {
        Some("claude") => &[".claude"],
        Some("codex") => &[".codex"],
        Some("opencode") => &[".config/opencode", ".local/share/opencode"],
        Some("crush") => &[".crush"],
        Some(name) if name.starts_with("kimi") => &[".kimi-code"],
        Some("gemini") => &[".gemini"],
        Some("grok") => &[".grok"],
        Some("pi") => &[".pi", ".pi-lens"],
        Some("aider") => &[".aider"],
        Some("soulforge") => &[".soulforge"],
        Some("omp") => &[".omp"],
        _ => &[],
    }
}

/// User hide_dotdirs override for command agent-state mounts: hiding
/// the state path's top-level dotdir wins over the agent_state
/// capability opt-in. Unlike the generic dotdir rules, built-in
/// DOTDIR_DENY does not apply here — these mounts exist precisely to
/// expose the invoked agent's own state on an explicit opt-in
/// (.kimi-code is in DOTDIR_DENY but is kimi's state dir).
fn state_path_hidden(relative: &str, hide_dotdirs: &[String]) -> bool {
    let top = relative.split('/').next().unwrap_or(relative);
    let normalized = top.strip_prefix('.').unwrap_or(top);
    hide_dotdirs.iter().any(|hide| {
        let hide = hide.strip_prefix('.').unwrap_or(hide.as_str());
        hide == normalized
    })
}

fn safe_state_dir(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn safe_state_file(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|metadata| {
            metadata.is_file() && !metadata.file_type().is_symlink()
        })
        .unwrap_or(false)
}

fn discover_browser_state_mount(
    config: &Config,
    profile: Option<crate::config::BrowserProfile>,
    verbose: bool,
) -> Vec<Mount> {
    if profile != Some(crate::config::BrowserProfile::Soft) {
        return vec![];
    }
    let Some(path) = super::browser_state_dir(config) else {
        return vec![];
    };
    if let Err(e) = std::fs::create_dir_all(&path) {
        output::warn(&format!(
            "Browser profile: cannot create {}: {e}",
            path.display()
        ));
        return vec![];
    }
    if verbose {
        output::verbose(&format!("Browser profile: {} rw", path.display()));
    }
    vec![Mount::Bind {
        src: path.clone(),
        dest: path,
    }]
}

/// Build bwrap mounts that replace each user-specified path with
/// an empty file (for regular files) or a tmpfs (for directories).
/// Relative paths resolve against the project directory so
/// `--mask .env` just works from the project root.
fn build_mask_mounts(
    mask: &[PathBuf],
    project_dir: &Path,
    empty_path: &Path,
    verbose: bool,
) -> Vec<Mount> {
    let mut mounts = Vec::new();
    for p in mask {
        let target = if p.is_absolute() {
            p.clone()
        } else {
            project_dir.join(p)
        };
        if !super::path_exists(&target) {
            // A skipped mask is a dropped confidentiality control, so it
            // must stay visible even under --exec quiet.
            output::security_warn(&format!(
                "Mask: {} does not exist; rule not applied",
                target.display()
            ));
            continue;
        }
        if target.is_dir() {
            if verbose {
                output::verbose(&format!("Mask: {} (tmpfs)", target.display()));
            }
            mounts.push(Mount::Tmpfs { dest: target });
        } else {
            if verbose {
                output::verbose(&format!(
                    "Mask: {} (empty file)",
                    target.display()
                ));
            }
            mounts.push(Mount::FileRoBind {
                src: empty_path.to_path_buf(),
                dest: target,
            });
        }
    }
    mounts
}

/// Build bwrap mounts that replace each denied path with a mode-000 file or
/// directory, causing reads/listing/writes to fail with permission denied.
fn build_deny_mounts(
    deny_paths: &[PathBuf],
    project_dir: &Path,
    deny_file_path: &Path,
    deny_dir_path: &Path,
    verbose: bool,
) -> Vec<Mount> {
    let mut mounts = Vec::new();
    for p in deny_paths {
        let target = if p.is_absolute() {
            p.clone()
        } else {
            project_dir.join(p)
        };
        if !super::path_exists(&target) {
            // A skipped deny is a dropped confidentiality control, so it
            // must stay visible even under --exec quiet.
            output::security_warn(&format!(
                "Deny: {} does not exist; rule not applied",
                target.display()
            ));
            continue;
        }
        if target.is_dir() {
            if verbose {
                output::verbose(&format!(
                    "Deny: {} (000 dir)",
                    target.display()
                ));
            }
            mounts.push(Mount::RoBind {
                src: deny_dir_path.to_path_buf(),
                dest: target,
            });
        } else {
            if verbose {
                output::verbose(&format!(
                    "Deny: {} (000 file)",
                    target.display()
                ));
            }
            mounts.push(Mount::FileRoBind {
                src: deny_file_path.to_path_buf(),
                dest: target,
            });
        }
    }
    mounts
}

fn optional_ro_bind(path: &Path) -> Option<Mount> {
    if path.is_dir() {
        let path = path.to_path_buf();
        Some(Mount::RoBind {
            src: path.clone(),
            dest: path,
        })
    } else {
        None
    }
}

fn path_resolves_under(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
        || path
            .canonicalize()
            .is_ok_and(|canonical| canonical.starts_with(prefix))
}

fn needs_nix_mount(hosts_dest: &Path, nix_root: &Path) -> bool {
    path_resolves_under(hosts_dest, nix_root)
        || std::env::current_exe()
            .is_ok_and(|p| path_resolves_under(&p, nix_root))
        || std::env::var_os(BWRAP_ENV_VAR)
            .is_some_and(|p| path_resolves_under(Path::new(&p), nix_root))
}

fn discover_base(
    hosts_mount: (&Path, &Path),
    resolv_mount: Option<(&Path, &Path)>,
    resolv_intermediate_mount: Option<(&Path, &Path)>,
) -> Vec<Mount> {
    discover_base_with_nix_root(
        hosts_mount,
        resolv_mount,
        resolv_intermediate_mount,
        Path::new("/nix"),
    )
}

fn discover_base_with_nix_root(
    hosts_mount: (&Path, &Path),
    resolv_mount: Option<(&Path, &Path)>,
    resolv_intermediate_mount: Option<(&Path, &Path)>,
    nix_root: &Path,
) -> Vec<Mount> {
    let (hosts_file, hosts_dest) = hosts_mount;
    let mut mounts = Vec::new();

    if let Some(m) = optional_ro_bind(Path::new("/usr")) {
        mounts.push(m);
    }

    // /bin, /lib, /lib64, /sbin: on merged-/usr distros these are
    // symlinks to /usr/* and we recreate the symlink inside the
    // sandbox.  On non-merged distros (e.g. Slackware, older
    // Debian) they are real directories with cross-symlinks into
    // /usr; a --symlink would create loops, so we ro-bind them.
    for (dir, usr_sub) in [
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
        ("/sbin", "usr/sbin"),
    ] {
        let p = Path::new(dir);
        if p.is_symlink() {
            mounts.push(Mount::Symlink {
                src: usr_sub.into(),
                dest: p.into(),
            });
        } else if p.is_dir() {
            mounts.push(Mount::RoBind {
                src: p.into(),
                dest: p.into(),
            });
        }
        // else: does not exist, skip
    }

    // On NixOS and Nix environments, /etc/hosts can be a symlink into /nix/store,
    // or ai-jail/bwrap itself runs from /nix/store and requires its dynamic
    // dependencies.
    if needs_nix_mount(hosts_dest, nix_root) {
        mounts.extend(optional_ro_bind(nix_root));
    }

    if let Some(m) = optional_ro_bind(Path::new("/etc")) {
        mounts.push(m);
    }
    mounts.push(Mount::FileRoBind {
        src: hosts_file.to_path_buf(),
        dest: hosts_dest.to_path_buf(),
    });
    // /opt is optional on some hosts; bwrap rejects missing bind sources.
    if let Some(m) = optional_ro_bind(Path::new("/opt")) {
        mounts.push(m);
    }
    if let Some(m) = optional_ro_bind(Path::new("/sys")) {
        mounts.push(m);
    }
    mounts.extend([
        Mount::Dev {
            dest: "/dev".into(),
        },
        Mount::Proc {
            dest: "/proc".into(),
        },
        Mount::Tmpfs {
            dest: "/tmp".into(),
        },
        Mount::Tmpfs {
            dest: "/run".into(),
        },
    ]);

    // Keep resolv mount after /run tmpfs. On WSL/systemd-resolved
    // `/etc/resolv.conf` often points into `/run`, which must not
    // be shadowed by a later tmpfs mount.
    if let Some((src, dest)) = resolv_mount {
        mounts.push(Mount::FileRoBind {
            src: src.to_path_buf(),
            dest: dest.to_path_buf(),
        });
    }
    if let Some((src, dest)) = resolv_intermediate_mount {
        mounts.push(Mount::FileRoBind {
            src: src.to_path_buf(),
            dest: dest.to_path_buf(),
        });
    }

    mounts
}

fn discover_home_dotfiles(
    lockdown: bool,
    hide_dotdirs: &[String],
    exempt: &[&str],
    verbose: bool,
) -> Vec<Mount> {
    let home = super::home_dir();
    let mut mounts = vec![Mount::Tmpfs { dest: home.clone() }];

    if lockdown {
        return mounts;
    }

    let entries = match std::fs::read_dir(&home) {
        Ok(e) => e,
        Err(e) => {
            output::warn(&format!("Cannot read home directory: {e}"));
            return mounts;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with('.') || name_str == "." || name_str == ".." {
            continue;
        }

        let path = entry.path();
        if !safe_state_dir(&path) {
            continue;
        }

        if super::is_dotdir_denied(&name_str, hide_dotdirs, exempt) {
            if verbose {
                output::verbose(&format!("deny: {}", path.display()));
            }
            continue;
        }

        let dest = home.join(name_str.as_ref());
        if super::DOTDIR_RW.contains(&name_str.as_ref()) {
            if verbose {
                output::verbose(&format!("rw: {}", path.display()));
            }
            mounts.push(Mount::Bind { src: path, dest });
        } else {
            if verbose {
                output::verbose(&format!("ro: {}", path.display()));
            }
            mounts.push(Mount::RoBind { src: path, dest });
        }
    }

    for filename in [".gitconfig", ".gitignore"] {
        let git_file = home.join(filename);
        if git_file.is_file() {
            mounts.push(Mount::RoBind {
                src: git_file.clone(),
                dest: git_file,
            });
        }
    }
    // XDG-style global git settings: $XDG_CONFIG_HOME/git/{config,ignore,attributes,...}
    // (defaults to $HOME/.config/git when XDG_CONFIG_HOME is unset).
    // This is Git's default location when ~/.gitconfig/~/.gitignore are absent.
    // Mounted as a read-only directory so all the files Git looks for there
    // (config, ignore, attributes) come through in one shot.
    let xdg_git = super::xdg_config_home().join("git");
    if xdg_git.is_dir() {
        mounts.push(Mount::RoBind {
            src: xdg_git.clone(),
            dest: xdg_git,
        });
    }
    // ~/.claude.json used to be mounted here unconditionally; it is
    // Claude Code state (auth tokens) and now lives in
    // `discover_home_dotfiles_full`, gated on the agent_state
    // capability with the user's hide_dotdirs winning.

    mounts
}

fn discover_subdir_hide(parent: &str, deny_list: &[&str]) -> Vec<Mount> {
    let home = super::home_dir();
    deny_list
        .iter()
        .filter_map(|name| {
            let path = home.join(parent).join(name);
            if path.is_dir() {
                Some(Mount::Tmpfs { dest: path })
            } else {
                None
            }
        })
        .collect()
}

/// Read-only binds for the invoked command's binary when it lives
/// under `$HOME` (#81). Private home replaces `$HOME` with a tmpfs,
/// which would otherwise hide agents installed the official way
/// (e.g. `~/.local/bin/claude` → `~/.local/share/claude/versions/<v>`)
/// and make the inner exec fail with ENOENT.
fn discover_command_binary(config: &Config, verbose: bool) -> Vec<Mount> {
    super::command_home_paths(config)
        .into_iter()
        .map(|path| {
            if verbose {
                output::verbose(&format!(
                    "Command binary: {} ro",
                    path.display()
                ));
            }
            Mount::RoBind {
                src: path.clone(),
                dest: path,
            }
        })
        .collect()
}

fn discover_local_overrides() -> Vec<Mount> {
    let home = super::home_dir();
    let mut mounts = Vec::new();

    let state = home.join(".local/state");
    if state.is_dir() {
        mounts.push(Mount::Bind {
            src: state.clone(),
            dest: state,
        });
    }

    for name in LOCAL_SHARE_RW {
        let path = home.join(".local/share").join(name);
        if path.is_dir() {
            mounts.push(Mount::Bind {
                src: path.clone(),
                dest: path,
            });
        }
    }

    mounts
}

// Sensitive /sys paths masked with tmpfs to reduce information
// leakage useful for kernel/namespace escape reconnaissance.
const SYS_MASK_ALWAYS: &[&str] = &[
    "/sys/firmware",        // BIOS/UEFI/ACPI tables
    "/sys/kernel/security", // LSM interfaces
    "/sys/kernel/debug",    // debugfs
    "/sys/fs/fuse",         // FUSE control
];

const SYS_MASK_LOCKDOWN: &[&str] = &[
    "/sys/module",              // loaded kernel modules
    "/sys/devices/virtual/dmi", // DMI/SMBIOS tables
    "/sys/class/net",           // network interface enumeration
];

fn discover_sys_masks(lockdown: bool) -> Vec<Mount> {
    let mut mounts = Vec::new();
    let lists: &[&[&str]] = if lockdown {
        &[SYS_MASK_ALWAYS, SYS_MASK_LOCKDOWN]
    } else {
        &[SYS_MASK_ALWAYS]
    };
    for list in lists {
        for &path in *list {
            if super::path_exists(&PathBuf::from(path)) {
                mounts.push(Mount::Tmpfs { dest: path.into() });
            }
        }
    }
    mounts
}

fn discover_gpu(verbose: bool) -> Vec<Mount> {
    let mut mounts = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("nvidia") {
                let path = entry.path();
                if verbose {
                    output::verbose(&format!("gpu: {}", path.display()));
                }
                mounts.push(Mount::DevBind {
                    src: path.clone(),
                    dest: path,
                });
            }
        }
    }

    let dri = PathBuf::from("/dev/dri");
    if super::path_exists(&dri) {
        if verbose {
            output::verbose(&format!("gpu: {}", dri.display()));
        }
        mounts.push(Mount::DevBind {
            src: dri.clone(),
            dest: dri,
        });
    }

    mounts
}

fn discover_docker() -> Vec<Mount> {
    let Some(sock) = super::docker_socket() else {
        return Vec::new();
    };
    discover_docker_paths(&sock, Path::new(WSL_DOCKER_DESKTOP_CLI_TOOLS))
}

fn discover_docker_paths(sock: &Path, wsl_cli_tools: &Path) -> Vec<Mount> {
    let mut mounts = Vec::new();
    if super::docker_socket_usable(sock) {
        mounts.push(Mount::Bind {
            src: sock.to_path_buf(),
            dest: sock.to_path_buf(),
        });

        // Docker Desktop on WSL commonly installs /usr/bin/docker
        // as a symlink into this directory. /usr is already mounted,
        // but the symlink target is outside /usr, so expose it too.
        if wsl_cli_tools.is_dir() {
            mounts.push(Mount::RoBind {
                src: wsl_cli_tools.to_path_buf(),
                dest: wsl_cli_tools.to_path_buf(),
            });
        }
    }

    mounts
}

fn discover_tailscale() -> Vec<Mount> {
    discover_tailscale_paths(Path::new(TAILSCALE_SOCKET))
}

fn discover_tailscale_paths(sock: &Path) -> Vec<Mount> {
    if super::path_exists(sock) {
        vec![Mount::Bind {
            src: sock.to_path_buf(),
            dest: sock.to_path_buf(),
        }]
    } else {
        vec![]
    }
}

fn discover_shm(host_shared: bool) -> Vec<Mount> {
    let shm = PathBuf::from("/dev/shm");
    if host_shared && shm.is_dir() {
        vec![Mount::DevBind {
            src: shm.clone(),
            dest: shm,
        }]
    } else {
        vec![Mount::Tmpfs { dest: shm }]
    }
}

fn discover_display(
    config: &Config,
    verbose: bool,
) -> (Vec<Mount>, Vec<(String, String)>) {
    let mut mounts = Vec::new();
    let mut env = Vec::new();

    let x11 = PathBuf::from("/tmp/.X11-unix");
    if config.x11_enabled() && x11.is_dir() {
        mounts.push(Mount::Bind {
            src: x11.clone(),
            dest: x11,
        });
    }

    if config.x11_enabled()
        && let Ok(display) = std::env::var("DISPLAY")
    {
        env.push(("DISPLAY".into(), display));
    }

    if config.x11_enabled()
        && let Ok(xauth) = std::env::var("XAUTHORITY")
    {
        let xauth_path = PathBuf::from(&xauth);
        if safe_xauthority(&xauth_path) {
            mounts.push(Mount::RoBind {
                src: xauth_path.clone(),
                dest: xauth_path,
            });
            env.push(("XAUTHORITY".into(), xauth));
        } else {
            output::security_warn(
                "ignoring XAUTHORITY mount: failed validation",
            );
        }
    }

    if let (Ok(xdg_dir), Ok(wayland)) = (
        std::env::var("XDG_RUNTIME_DIR"),
        std::env::var("WAYLAND_DISPLAY"),
    ) {
        let xdg_path = PathBuf::from(&xdg_dir);
        if is_safe_xdg_runtime(&xdg_path) {
            if let Ok(runtime) = xdg_path.canonicalize()
                && Path::new(&wayland).components().count() == 1
            {
                let socket = runtime.join(&wayland);
                if socket
                    .symlink_metadata()
                    .map(|metadata| metadata.file_type().is_socket())
                    .unwrap_or(false)
                {
                    mounts.push(Mount::Bind {
                        src: socket.clone(),
                        dest: socket,
                    });
                    env.push(("XDG_RUNTIME_DIR".into(), xdg_dir));
                    env.push(("WAYLAND_DISPLAY".into(), wayland));
                }
            }
        } else {
            output::security_warn(
                "ignoring XDG_RUNTIME_DIR mount: failed validation",
            );
        }
    }

    if verbose {
        for m in &mounts {
            if let Mount::Bind { src, .. } | Mount::RoBind { src, .. } = m {
                output::verbose(&format!("display: {}", src.display()));
            }
        }
    }

    (mounts, env)
}

pub(crate) fn is_safe_xdg_runtime(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    // nix's safe wrapper requires its optional `user` feature, which this
    // binary deliberately does not enable.
    let uid = unsafe { nix::libc::geteuid() };
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    let expected = PathBuf::from("/run/user").join(uid.to_string());
    let Ok(expected) = expected.canonicalize() else {
        return false;
    };
    let Ok(metadata) = canonical.metadata() else {
        return false;
    };
    canonical == expected
        && metadata.is_dir()
        && metadata.uid() == uid
        && metadata.mode() & 0o077 <= 0o055
}

fn safe_xauthority(path: &Path) -> bool {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(true)
    {
        return false;
    }
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    let Some(name) = canonical.file_name().and_then(|name| name.to_str())
    else {
        return false;
    };
    (name.starts_with(".x-") || name.contains("Xauthority"))
        && canonical
            .metadata()
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
}

fn discover_systemd_user(
    config: &Config,
    lockdown: bool,
    browser_mode: bool,
    _display_enabled: bool,
    deny_file_path: &Path,
    verbose: bool,
) -> (Vec<Mount>, Vec<(String, String)>) {
    if !config.systemd_user_enabled() {
        return (vec![], vec![]);
    }
    if lockdown {
        output::warn("--systemd-user is not supported in lockdown; skipping");
        return (vec![], vec![]);
    }
    let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") else {
        output::warn("--systemd-user requires XDG_RUNTIME_DIR; skipping");
        return (vec![], vec![]);
    };
    let xdg_path = PathBuf::from(&xdg_dir);
    if !is_safe_xdg_runtime(&xdg_path) {
        output::security_warn(
            "--systemd-user XDG_RUNTIME_DIR failed validation; skipping",
        );
        return (vec![], vec![]);
    }

    let candidates: Vec<PathBuf> = SYSTEMD_USER_SUBPATHS
        .iter()
        .map(|sub| xdg_path.join(sub))
        .collect();
    let existing_paths: Vec<&Path> = candidates
        .iter()
        .filter(|path| {
            path.symlink_metadata()
                .map(|metadata| metadata.file_type().is_socket())
                .unwrap_or(false)
        })
        .map(PathBuf::as_path)
        .collect();
    if existing_paths.is_empty() {
        output::warn(
            "--systemd-user found no user bus sockets in XDG_RUNTIME_DIR; skipping",
        );
        return (vec![], vec![]);
    }

    let mut mounts = Vec::new();

    if browser_mode {
        output::warn(
            "--systemd-user is not supported in browser profile mode; denying known user bus sockets",
        );
        for path in existing_paths {
            mounts.push(Mount::FileRoBind {
                src: deny_file_path.to_path_buf(),
                dest: path.to_path_buf(),
            });
        }
        return (mounts, vec![]);
    }

    let mut env = Vec::new();
    env.push(("XDG_RUNTIME_DIR".into(), xdg_dir.clone()));

    for path in existing_paths {
        if verbose {
            output::verbose(&format!("systemd-user: {} rw", path.display()));
        }
        mounts.push(Mount::Bind {
            src: path.to_path_buf(),
            dest: path.to_path_buf(),
        });
    }

    let bus = xdg_path.join(SYSTEMD_USER_BUS_SUBPATH);
    if super::path_exists(&bus) {
        let explicit = format!("unix:path={}", bus.display());
        let value = match std::env::var("DBUS_SESSION_BUS_ADDRESS") {
            Ok(existing) if existing == explicit => existing,
            _ => explicit,
        };
        env.push(("DBUS_SESSION_BUS_ADDRESS".into(), value));
    }

    (mounts, env)
}

fn git_worktree_mounts(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Vec<Mount> {
    let Some(paths) =
        super::discover_git_worktree_paths(config, project_dir, verbose)
    else {
        return vec![];
    };

    let common = Mount::RoBind {
        src: paths.common_dir.clone(),
        dest: paths.common_dir,
    };
    let git_dir = if config.lockdown_enabled() {
        Mount::RoBind {
            src: paths.git_dir.clone(),
            dest: paths.git_dir,
        }
    } else {
        Mount::Bind {
            src: paths.git_dir.clone(),
            dest: paths.git_dir,
        }
    };
    vec![common, git_dir]
}

fn extra_mounts(rw_maps: &[PathBuf], ro_maps: &[PathBuf]) -> Vec<Mount> {
    extra_mounts_with_check(rw_maps, ro_maps, super::path_exists)
}

/// Inner implementation of [`extra_mounts`] that accepts an injectable
/// path-existence predicate. This makes the logic unit-testable in hermetic
/// environments (e.g. the Nix build sandbox) where host paths like `/usr`
/// may not exist.
fn extra_mounts_with_check(
    rw_maps: &[PathBuf],
    ro_maps: &[PathBuf],
    path_exists: impl Fn(&Path) -> bool,
) -> Vec<Mount> {
    let mut mounts = Vec::new();

    let trusted_ro_destinations: Vec<PathBuf> = ro_maps
        .iter()
        .filter_map(|encoded| MapSpec::parse_validated(encoded, "read-only"))
        .map(|spec| spec.destination)
        .collect();

    // Read-only destinations are policy boundaries: no RW map may shadow
    // them or a subtree beneath them.
    for encoded in ro_maps {
        let Some(spec) = MapSpec::parse_validated(encoded, "read-only") else {
            continue;
        };
        if path_exists(&spec.source) {
            mounts.push(Mount::RoBind {
                src: spec.source,
                dest: spec.destination,
            });
        } else {
            output::warn(&format!(
                "Path {} not found, skipping.",
                spec.source.display()
            ));
        }
    }

    for encoded in rw_maps {
        let Some(spec) = MapSpec::parse_validated(encoded, "read-write") else {
            continue;
        };
        // Overlap must be rejected in BOTH directions: an RW child
        // under an RO destination would be shadowed read-only (the
        // original check), and an RW parent over an RO destination
        // would silently re-expose the read-only subtree as writable
        // because the later RW bind wins in bwrap's mount order.
        if trusted_ro_destinations.iter().any(|ro| {
            spec.destination.starts_with(ro)
                || ro.starts_with(&spec.destination)
        }) {
            output::security_warn(
                "ignoring rw-map that overlaps a read-only map destination",
            );
            continue;
        }
        if path_exists(&spec.source) {
            mounts.push(Mount::Bind {
                src: spec.source,
                dest: spec.destination,
            });
        } else {
            output::warn(&format!(
                "Path {} not found, skipping.",
                spec.source.display()
            ));
        }
    }

    mounts
}

/// Directory (inside the project) that holds the on-host upper and
/// work layers for overlay maps. Masked from inside the sandbox.
const OVERLAY_STORAGE_DIR: &str = ".ai-jail-overlays";

/// Turn an absolute destination path into a filesystem-safe, readable
/// directory name for its overlay layer storage. `/home/u/.claude`
/// becomes `home_u_.claude`. Preserving the full path keeps distinct
/// destinations collision-free.
fn overlay_storage_name(dest: &Path) -> String {
    let s = dest.to_string_lossy();
    let mut name = String::with_capacity(s.len());
    for ch in s.trim_start_matches('/').chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    if name.is_empty() {
        name.push_str("root");
    }
    name
}

/// Build overlayfs mounts for `--overlay-map` destinations, plus the
/// tmpfs that hides their on-host upper/work storage from inside the
/// sandbox.
///
/// Each map mounts the real directory (read-only lower) at the same
/// path inside the sandbox with a writable upper layer under
/// `<project>/.ai-jail-overlays/<name>/upper`. Writes land in the
/// upper layer; the original directory is never modified, so the user
/// can diff the upper layer afterwards and promote changes.
///
/// Returns `(overlay_mounts, storage_hide_mounts)`. Overlays that
/// cannot be set up (missing source, unwritable storage, overlapping
/// destination) are skipped with a warning — never fatal.
fn overlay_mounts(
    overlay_maps: &[PathBuf],
    project_dir: &Path,
    verbose: bool,
) -> Result<(Vec<Mount>, Vec<Mount>), String> {
    if overlay_maps.is_empty() {
        return Ok((vec![], vec![]));
    }
    let storage_root = project_dir.join(OVERLAY_STORAGE_DIR);
    match storage_root.symlink_metadata() {
        Ok(metadata)
            if metadata.file_type().is_symlink() || !metadata.is_dir() =>
        {
            return Err("overlay storage root failed validation".into());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err("overlay storage root failed validation".into());
        }
        _ => {}
    }
    let mut mounts = Vec::new();
    let mut accepted: Vec<PathBuf> = Vec::new();

    for dest in overlay_maps {
        if !super::path_exists(dest) {
            output::warn(&format!(
                "Overlay map {} not found, skipping.",
                dest.display()
            ));
            continue;
        }
        // Reject overlapping destinations (equal / parent / child):
        // two overlays sharing a subtree give overlayfs ambiguous
        // layering and risk silent data confusion.
        if let Some(conflict) = accepted
            .iter()
            .find(|a| *a == dest || a.starts_with(dest) || dest.starts_with(a))
        {
            output::warn(&format!(
                "Overlay map {} overlaps {}, skipping.",
                dest.display(),
                conflict.display()
            ));
            continue;
        }

        let base = storage_root.join(overlay_storage_name(dest));
        let upper = base.join("upper");
        let work = base.join("work");
        if let Err(e) =
            create_safe_overlay_dirs(&[&storage_root, &base, &upper, &work])
        {
            output::warn(&format!(
                "Overlay map {}: cannot create layer storage {}: {e}; \
                 skipping.",
                dest.display(),
                base.display()
            ));
            continue;
        }

        // Always surface this, even without --verbose: the feature is
        // opt-in and the whole point is that writes do NOT touch the
        // original. Tell the user where the captured changes live so
        // nobody loses work unknowingly.
        output::info(&format!(
            "Overlay: {} is copy-on-write; changes captured in {} \
             (original untouched)",
            dest.display(),
            upper.display()
        ));

        mounts.push(Mount::Overlay {
            lower: dest.clone(),
            upper,
            work,
            dest: dest.clone(),
        });
        accepted.push(dest.clone());
    }

    if mounts.is_empty() {
        return Ok((vec![], vec![]));
    }

    // Drop a .gitignore so overlay layers never get committed by
    // accident, then hide the raw storage from inside the sandbox so
    // the agent cannot read or tamper with the upper/work layers
    // directly — it must go through the overlay mount at the dest.
    write_overlay_gitignore(&storage_root);
    if verbose {
        output::verbose(&format!("Overlay maps: {} active", mounts.len()));
    }
    let hide = vec![Mount::Tmpfs { dest: storage_root }];
    Ok((mounts, hide))
}

/// Create each overlay component without ever following a pre-existing
/// symlink. Overlay storage is host-writable state, so following one could
/// write outside the project before bwrap starts.
fn create_safe_overlay_dirs(paths: &[&Path]) -> std::io::Result<()> {
    for path in paths {
        match path.symlink_metadata() {
            Ok(metadata)
                if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(std::io::Error::other(
                    "overlay storage component is not a directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(path)?;
                let metadata = path.symlink_metadata()?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(std::io::Error::other(
                        "overlay storage component failed validation",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Write a `.gitignore` into the overlay storage root so the layers
/// are never accidentally committed. Best-effort; failure is silent.
fn write_overlay_gitignore(storage_root: &Path) {
    let gitignore = storage_root.join(".gitignore");
    if !super::path_exists(&gitignore) {
        let _ = std::fs::write(
            &gitignore,
            "# ai-jail overlay layers — do not commit\n*\n",
        );
    }
}

fn project_mount(project_dir: &Path, readonly: bool) -> Vec<Mount> {
    if readonly {
        vec![Mount::RoBind {
            src: project_dir.to_path_buf(),
            dest: project_dir.to_path_buf(),
        }]
    } else {
        vec![Mount::Bind {
            src: project_dir.to_path_buf(),
            dest: project_dir.to_path_buf(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::test_support::linked_worktree_fixture;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    fn create_linked_worktree_fixture()
    -> crate::sandbox::test_support::LinkedWorktreeFixture {
        linked_worktree_fixture("bwrap-worktree")
    }

    fn minimal_test_config() -> Config {
        Config {
            command: vec!["bash".into()],
            no_gpu: Some(true),
            no_docker: Some(true),
            no_display: Some(true),
            no_mise: Some(true),
            ..Config::default()
        }
    }

    #[test]
    fn mount_args_ro_bind() {
        let m = Mount::RoBind {
            src: "/usr".into(),
            dest: "/usr".into(),
        };
        assert_eq!(m.to_args(), vec!["--ro-bind", "/usr", "/usr"]);
    }

    #[test]
    fn mount_args_bind() {
        let m = Mount::Bind {
            src: "/tmp".into(),
            dest: "/tmp".into(),
        };
        assert_eq!(m.to_args(), vec!["--bind", "/tmp", "/tmp"]);
    }

    #[test]
    fn optional_ro_bind_mounts_directories_and_skips_other_paths() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-optional-ro-bind-{}", std::process::id()));
        let directory = root.join("directory");
        let file = root.join("file");
        let missing = root.join("missing");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(&file, b"not a directory").unwrap();

        assert!(matches!(
            optional_ro_bind(&directory),
            Some(Mount::RoBind { src, dest })
                if src == directory && dest == directory
        ));
        assert!(optional_ro_bind(&file).is_none());
        assert!(optional_ro_bind(&missing).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mounted_map_args_forward_only_destinations() {
        let mounts = [
            Mount::RoBind {
                src: "/host/ro".into(),
                dest: "/jail/ro".into(),
            },
            Mount::Bind {
                src: "/host/rw".into(),
                dest: "/jail/rw".into(),
            },
        ];

        assert_eq!(
            mounted_map_args(&mounts),
            vec![
                "--landlock-ro-path",
                "/jail/ro",
                "--landlock-rw-path",
                "/jail/rw",
            ]
        );
    }

    #[test]
    fn docker_discovery_mounts_socket_and_wsl_cli_tools() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-docker-wsl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sock = root.join("docker.sock");
        let cli_tools = root.join("cli-tools");
        std::fs::create_dir_all(&cli_tools).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let mounts = discover_docker_paths(&sock, &cli_tools);

        assert!(matches!(
            &mounts[0],
            Mount::Bind { src, dest } if src == &sock && dest == &sock
        ));
        assert!(matches!(
            &mounts[1],
            Mount::RoBind { src, dest } if src == &cli_tools && dest == &cli_tools
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn docker_discovery_skips_wsl_cli_tools_without_socket() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-docker-no-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sock = root.join("docker.sock");
        let cli_tools = root.join("cli-tools");
        std::fs::create_dir_all(&cli_tools).unwrap();

        let mounts = discover_docker_paths(&sock, &cli_tools);

        assert!(mounts.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tailscale_discovery_mounts_socket_when_present() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-tailscale-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sock = root.join("tailscaled.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let mounts = discover_tailscale_paths(&sock);

        assert_eq!(mounts.len(), 1);
        assert!(matches!(
            &mounts[0],
            Mount::Bind { src, dest } if src == &sock && dest == &sock
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tailscale_discovery_skips_missing_socket() {
        let sock = std::env::temp_dir().join(format!(
            "ai-jail-missing-tailscale-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&sock);

        let mounts = discover_tailscale_paths(&sock);

        assert!(mounts.is_empty());
    }

    #[test]
    fn tailscale_bind_absent_from_args_when_disabled_or_missing() {
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        // Disabled (the default) → the socket bind must never be
        // emitted, even on hosts running tailscaled.
        let mut config = minimal_test_config();
        config.no_worktree = Some(false);
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        assert!(!args.iter().any(|a| a == TAILSCALE_SOCKET));

        // Enabled but socket absent → warn-and-skip with no dangling
        // bind (bwrap aborts on a missing bind source). Only
        // assertable on hosts without a live tailscaled.
        if !Path::new(TAILSCALE_SOCKET).exists() {
            let mut config = minimal_test_config();
            config.tailscale = Some(true);
            let args = build_dry_run_args(
                &config,
                &project,
                guard.hosts_mount(),
                guard.resolv_mount(),
                guard.empty_path(),
                false,
            )
            .unwrap();
            assert!(!args.iter().any(|a| a == TAILSCALE_SOCKET));
        }
    }

    #[test]
    fn build_mask_mounts_file_uses_empty_ro_bind() {
        use std::io::Write;
        // Create a temp project dir with a real file to mask
        let project = std::env::temp_dir()
            .join(format!("ai-jail-mask-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&project);
        let env_file = project.join(".env");
        let mut f = std::fs::File::create(&env_file).unwrap();
        f.write_all(b"SECRET=xyz").unwrap();

        let empty = std::env::temp_dir().join("ai-jail-mask-empty-src");
        let _ = std::fs::File::create(&empty).unwrap();

        let mounts = build_mask_mounts(
            &[PathBuf::from(".env")],
            &project,
            &empty,
            false,
        );

        assert_eq!(mounts.len(), 1);
        match &mounts[0] {
            Mount::FileRoBind { src, dest } => {
                assert_eq!(src, &empty);
                assert_eq!(dest, &env_file);
            }
            _ => panic!("expected FileRoBind for mask on a regular file"),
        }

        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn build_mask_mounts_directory_uses_tmpfs() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-mask-dir-{}", std::process::id()));
        let secrets_dir = project.join("secrets");
        let _ = std::fs::create_dir_all(&secrets_dir);
        let empty = std::env::temp_dir().join("ai-jail-mask-empty-dir");
        let _ = std::fs::File::create(&empty).unwrap();

        let mounts = build_mask_mounts(
            &[PathBuf::from("secrets")],
            &project,
            &empty,
            false,
        );

        assert_eq!(mounts.len(), 1);
        match &mounts[0] {
            Mount::Tmpfs { dest } => assert_eq!(dest, &secrets_dir),
            _ => panic!("expected Tmpfs for mask on a directory"),
        }

        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn build_mask_mounts_missing_path_skips() {
        let project = PathBuf::from("/tmp");
        let empty = std::env::temp_dir().join("ai-jail-mask-empty-miss");
        let _ = std::fs::File::create(&empty).unwrap();

        let mounts = build_mask_mounts(
            &[PathBuf::from("definitely-not-a-real-file-xyz123")],
            &project,
            &empty,
            false,
        );

        assert!(mounts.is_empty());
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn deny_temp_file_and_dir_permissions_are_000() {
        let file = new_deny_file().unwrap();
        let dir = new_deny_dir().unwrap();

        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0
        );

        let _ = std::fs::remove_file(file);
        let _ = std::fs::set_permissions(
            &dir,
            std::fs::Permissions::from_mode(0o700),
        );
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn build_deny_mounts_file_and_dir_use_000_ro_bind() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-deny-mounts-{}", std::process::id()));
        let secrets_dir = project.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let env_file = project.join(".env");
        std::fs::write(&env_file, "SECRET=xyz").unwrap();
        let deny_file = std::env::temp_dir().join("ai-jail-deny-file-src");
        let deny_dir = std::env::temp_dir().join("ai-jail-deny-dir-src");
        let _ = std::fs::File::create(&deny_file).unwrap();
        let _ = std::fs::create_dir_all(&deny_dir);

        let mounts = build_deny_mounts(
            &[PathBuf::from(".env"), PathBuf::from("secrets")],
            &project,
            &deny_file,
            &deny_dir,
            false,
        );

        assert_eq!(mounts.len(), 2);
        assert!(matches!(
            &mounts[0],
            Mount::FileRoBind { src, dest } if src == &deny_file && dest == &env_file
        ));
        assert!(matches!(
            &mounts[1],
            Mount::RoBind { src, dest } if src == &deny_dir && dest == &secrets_dir
        ));

        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_file(&deny_file);
        let _ = std::fs::remove_dir_all(&deny_dir);
    }

    #[test]
    fn mask_glob_expands_into_dry_run_mounts() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-mask-glob-{}", std::process::id()));
        let nested = project.join("app/config");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(project.join(".env"), "root").unwrap();
        std::fs::write(nested.join("local.env"), "nested").unwrap();
        std::fs::write(nested.join("public.txt"), "public").unwrap();

        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let config = Config {
            mask: vec![PathBuf::from("**/*.env")],
            no_hide_config: Some(true),
            ..minimal_test_config()
        };
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let empty_str = guard.empty_path().display().to_string();
        for masked in [project.join(".env"), nested.join("local.env")] {
            let masked_str = masked.display().to_string();
            assert!(
                args.windows(3).any(|w| {
                    w[0] == "--ro-bind"
                        && w[1] == empty_str
                        && w[2] == masked_str
                }),
                "expected glob-expanded mask for {}; args: {args:?}",
                masked.display()
            );
        }
        assert!(
            !args.iter().any(|arg| arg.ends_with("public.txt")),
            "non-matching files must not be masked; args: {args:?}"
        );

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn mask_glob_exception_keeps_maven_target_deletable() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-mask-maven-target-{}", std::process::id()));
        let fixture = project.join("src/test/resources/crypto/private.key");
        let generated = project.join("target/test-classes/crypto/private.key");
        std::fs::create_dir_all(fixture.parent().unwrap()).unwrap();
        std::fs::create_dir_all(generated.parent().unwrap()).unwrap();
        std::fs::write(&fixture, "fixture").unwrap();
        std::fs::write(&generated, "generated").unwrap();

        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let config = Config {
            mask: vec![PathBuf::from("**/*.key")],
            mask_exceptions: vec![PathBuf::from("**/target/**")],
            no_hide_config: Some(true),
            ..minimal_test_config()
        };
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let empty = guard.empty_path().display().to_string();
        let is_masked = |path: &Path| {
            let destination = path.display().to_string();
            args.windows(3).any(|window| {
                window[0] == "--ro-bind"
                    && window[1] == empty
                    && window[2] == destination
            })
        };
        assert!(is_masked(&fixture));
        assert!(!is_masked(&generated));

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn deny_paths_honor_exceptions_in_dry_run() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-deny-dry-run-{}", std::process::id()));
        let secrets_dir = project.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let env_file = project.join(".env");
        std::fs::write(&env_file, "root").unwrap();

        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let config = Config {
            deny_paths: vec![PathBuf::from(".env"), PathBuf::from("secrets")],
            deny_path_exceptions: vec![PathBuf::from("secrets")],
            no_hide_config: Some(true),
            ..minimal_test_config()
        };
        let sources = MountSources::from_guard(&guard);
        let args = build_dry_run_args_full(&config, &project, &sources, false)
            .unwrap();

        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && w[1] == guard.deny_file_path().display().to_string()
                && w[2] == env_file.display().to_string()
        }));
        assert!(!args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && w[1] == guard.deny_dir_path().display().to_string()
                && w[2] == secrets_dir.display().to_string()
        }));

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn systemd_user_dry_run_rejects_untrusted_runtime_paths() {
        let _env = ENV_LOCK.lock().unwrap();
        let runtime = std::env::temp_dir()
            .join(format!("ai-jail-systemd-user-{}", std::process::id()));
        let systemd_dir = runtime.join("systemd");
        std::fs::create_dir_all(&systemd_dir).unwrap();
        let bus = runtime.join("bus");
        let private = systemd_dir.join("private");
        std::fs::write(&bus, "").unwrap();
        std::fs::write(&private, "").unwrap();
        let _xdg = EnvVarGuard::set("XDG_RUNTIME_DIR", runtime.as_os_str());
        let _dbus = EnvVarGuard::remove("DBUS_SESSION_BUS_ADDRESS");

        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let config = Config {
            systemd_user: Some(true),
            no_display: Some(true),
            ..minimal_test_config()
        };
        let sources = MountSources::from_guard(&guard);
        let args = build_dry_run_args_full(
            &config,
            &std::env::temp_dir(),
            &sources,
            false,
        )
        .unwrap();

        assert!(!args.iter().any(|arg| arg == &bus.display().to_string()));
        assert!(!args.iter().any(|arg| arg == &private.display().to_string()));

        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn systemd_user_dry_run_skips_in_lockdown_and_browser() {
        let _env = ENV_LOCK.lock().unwrap();
        let runtime = std::env::temp_dir()
            .join(format!("ai-jail-systemd-user-skip-{}", std::process::id()));
        let systemd_dir = runtime.join("systemd");
        std::fs::create_dir_all(&systemd_dir).unwrap();
        let bus = runtime.join("bus");
        let private = systemd_dir.join("private");
        std::fs::write(&bus, "").unwrap();
        std::fs::write(&private, "").unwrap();
        let _xdg = EnvVarGuard::set("XDG_RUNTIME_DIR", runtime.as_os_str());

        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let lockdown_config = Config {
            systemd_user: Some(true),
            lockdown: Some(true),
            no_display: Some(true),
            ..minimal_test_config()
        };
        let sources = MountSources::from_guard(&guard);
        let args = build_dry_run_args_full(
            &lockdown_config,
            &std::env::temp_dir(),
            &sources,
            false,
        )
        .unwrap();
        let bus_str = bus.display().to_string();
        let private_str = private.display().to_string();
        assert!(!args.windows(3).any(|w| {
            w[0] == "--bind" && (w[1] == bus_str || w[1] == private_str)
        }));

        let browser_config = Config {
            systemd_user: Some(true),
            browser_profile: Some("hard".into()),
            ..minimal_test_config()
        };
        let sources = MountSources::from_guard(&guard);
        let args = build_dry_run_args_full(
            &browser_config,
            &std::env::temp_dir(),
            &sources,
            false,
        )
        .unwrap();
        assert!(!args.iter().any(|arg| arg == &bus_str));
        assert!(!args.iter().any(|arg| arg == &private_str));

        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn hide_config_auto_masks_project_ai_jail_by_default() {
        use std::io::Write;
        let project = std::env::temp_dir()
            .join(format!("ai-jail-hide-config-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&project);
        let cfg = project.join(".ai-jail");
        let mut f = std::fs::File::create(&cfg).unwrap();
        f.write_all(b"command = [\"bash\"]\n").unwrap();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let mut config = minimal_test_config();
        config.mask = vec![PathBuf::from(".ai-jail")];
        config.mask_exceptions = vec![PathBuf::from(".ai-jail")];
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        // The mask mount group puts the .ai-jail file under --ro-bind
        // from the empty tempfile. Find a `--ro-bind <empty> <cfg>` triple.
        let cfg_str = cfg.display().to_string();
        let empty_str = guard.empty_path().display().to_string();
        let found = args.windows(3).any(|w| {
            w[0] == "--ro-bind" && w[1] == empty_str && w[2] == cfg_str
        });
        assert!(
            found,
            "default behavior must auto-mask .ai-jail with the empty tempfile; args: {args:?}"
        );

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn no_hide_config_opts_out_of_auto_mask() {
        use std::io::Write;
        let project = std::env::temp_dir()
            .join(format!("ai-jail-no-hide-config-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&project);
        let cfg = project.join(".ai-jail");
        let mut f = std::fs::File::create(&cfg).unwrap();
        f.write_all(b"command = [\"bash\"]\n").unwrap();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let mut config = minimal_test_config();
        config.no_hide_config = Some(true);
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let cfg_str = cfg.display().to_string();
        let empty_str = guard.empty_path().display().to_string();
        let found = args.windows(3).any(|w| {
            w[0] == "--ro-bind" && w[1] == empty_str && w[2] == cfg_str
        });
        assert!(
            !found,
            "no_hide_config=true must skip the auto-mask of .ai-jail; args: {args:?}"
        );

        let _ = std::fs::remove_dir_all(&project);
    }

    /// `--browser=soft` must produce a persistent rw bind at the
    /// per-browser state dir under `~/.local/share/ai-jail/browsers/`,
    /// and the dir must be created on disk so bwrap's bind has
    /// something to point at.
    #[test]
    fn browser_soft_profile_emits_persistent_state_mount() {
        let _env = ENV_LOCK.lock().unwrap();
        let fake_home = std::env::temp_dir()
            .join(format!("ai-jail-browser-soft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();
        let _home = EnvVarGuard::set("HOME", fake_home.as_os_str());

        let config = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("soft".into()),
            ..Config::default()
        };
        let mounts = discover_browser_state_mount(
            &config,
            Some(crate::config::BrowserProfile::Soft),
            false,
        );

        let expected = fake_home.join(".local/share/ai-jail/browsers/chromium");
        let bind_present = mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &expected && dest == &expected
        ));
        assert!(
            bind_present,
            "soft profile should produce a Bind mount at {} — got {mounts:?}",
            expected.display()
        );
        assert!(
            expected.is_dir(),
            "soft profile should pre-create the state dir on disk"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    /// Hard profile is ephemeral; no persistent bind mount should be
    /// emitted regardless of browser command.
    #[test]
    fn browser_hard_profile_emits_no_persistent_state_mount() {
        let _env = ENV_LOCK.lock().unwrap();
        let fake_home = std::env::temp_dir()
            .join(format!("ai-jail-browser-hard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();
        let _home = EnvVarGuard::set("HOME", fake_home.as_os_str());

        let config = Config {
            command: vec!["chromium".into()],
            browser_profile: Some("hard".into()),
            ..Config::default()
        };
        let mounts = discover_browser_state_mount(
            &config,
            Some(crate::config::BrowserProfile::Hard),
            false,
        );
        assert!(
            mounts.is_empty(),
            "hard profile must not emit any persistent state mount: {mounts:?}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    /// If the user already has `.ai-jail` in their `mask`, the auto-
    /// append from `hide_config_enabled` must not produce a duplicate
    /// `--ro-bind <empty> <cfg>` triple. Otherwise bwrap would either
    /// emit a warning or mount the same path twice — pointless and
    /// suggests the dedup logic broke. Tests `discover_mask_mounts`
    /// through the full dry-run pipeline.
    #[test]
    fn hide_config_does_not_duplicate_when_user_already_masks_ai_jail() {
        use std::io::Write;
        let project = std::env::temp_dir()
            .join(format!("ai-jail-hide-config-dedup-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&project);
        let cfg = project.join(".ai-jail");
        let mut f = std::fs::File::create(&cfg).unwrap();
        f.write_all(b"command = [\"bash\"]\n").unwrap();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        // User explicitly listed `.ai-jail` as a mask path. The
        // hide_config auto-add must notice that and skip.
        let mut config = minimal_test_config();
        config.mask = vec![PathBuf::from(".ai-jail")];
        // hide_config_enabled() defaults to true; leave it set.

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let cfg_str = cfg.display().to_string();
        let empty_str = guard.empty_path().display().to_string();
        let occurrences = args
            .windows(3)
            .filter(|w| {
                w[0] == "--ro-bind" && w[1] == empty_str && w[2] == cfg_str
            })
            .count();
        assert_eq!(
            occurrences, 1,
            "Exactly one --ro-bind for .ai-jail expected, got {occurrences}.\n\
             Auto-mask dedup is broken — full args: {args:?}"
        );

        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn extra_mounts_rw_child_overrides_ro_parent() {
        // Inject |_| true so the test is hermetic: it doesn't require
        // /usr or /usr/bin to exist on the host (they won't in the Nix
        // build sandbox). The ordering guarantee — ro first, rw after —
        // is the invariant under test, not path existence.
        let ro = vec![PathBuf::from("/usr")];
        let rw = vec![PathBuf::from("/usr/bin")];
        let mounts = extra_mounts_with_check(&rw, &ro, |_| true);
        assert_eq!(mounts.len(), 1);
        match &mounts[0] {
            Mount::RoBind { src, .. } => {
                assert_eq!(src, &PathBuf::from("/usr"));
            }
            _ => panic!("first mount must be RoBind of the ro-parent"),
        }
        assert!(matches!(&mounts[0], Mount::RoBind { .. }));
    }

    #[test]
    fn extra_mounts_rw_parent_shadowing_ro_child_is_rejected() {
        // The reverse overlap: an RW map of a PARENT directory would
        // be mounted after the RO child (rw maps are emitted last),
        // and bwrap's later mount wins — silently re-exposing the
        // read-only subtree as writable. Must be rejected in both
        // directions.
        let ro = vec![PathBuf::from("/data/keys")];
        let rw = vec![PathBuf::from("/data")];
        let mounts = extra_mounts_with_check(&rw, &ro, |_| true);
        assert_eq!(
            mounts.len(),
            1,
            "rw parent must be dropped, keeping only the ro child"
        );
        assert!(matches!(
            &mounts[0],
            Mount::RoBind { src, dest }
                if src == Path::new("/data/keys")
                    && dest == Path::new("/data/keys")
        ));

        // Component boundaries matter: /data-keys is NOT under /data.
        let rw = vec![PathBuf::from("/data-keys")];
        let mounts = extra_mounts_with_check(&rw, &ro, |_| true);
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn extra_mounts_use_alternate_source_and_destination() {
        let ro = vec![PathBuf::from("/host/ro:/jail/ro")];
        let rw = vec![PathBuf::from("/host/rw:/jail/rw")];

        let mounts =
            extra_mounts_with_check(&rw, &ro, |path| path.starts_with("/host"));

        assert_eq!(mounts.len(), 2);
        assert!(matches!(
            &mounts[0],
            Mount::RoBind { src, dest }
                if src == Path::new("/host/ro")
                    && dest == Path::new("/jail/ro")
        ));
        assert!(matches!(
            &mounts[1],
            Mount::Bind { src, dest }
                if src == Path::new("/host/rw")
                    && dest == Path::new("/jail/rw")
        ));
    }

    #[test]
    fn extra_mounts_check_source_and_reject_invalid_specs() {
        let ro = vec![
            PathBuf::from("/missing:/existing"),
            PathBuf::from(":/invalid"),
        ];
        let rw = vec![PathBuf::from("/host:/")];
        let checked = std::cell::RefCell::new(Vec::new());

        let mounts = extra_mounts_with_check(&rw, &ro, |path| {
            checked.borrow_mut().push(path.to_path_buf());
            false
        });

        assert!(mounts.is_empty());
        assert_eq!(checked.into_inner(), vec![PathBuf::from("/missing")]);
    }

    #[test]
    fn extra_mounts_reject_non_utf8_before_source_check() {
        use std::os::unix::ffi::OsStringExt;

        let ro = vec![PathBuf::from(std::ffi::OsString::from_vec(
            b"/host/ro:/jail/\xff".to_vec(),
        ))];
        let checks = std::cell::Cell::new(0);

        let mounts = extra_mounts_with_check(&[], &ro, |_| {
            checks.set(checks.get() + 1);
            true
        });

        assert!(mounts.is_empty());
        assert_eq!(checks.get(), 0);
    }

    #[test]
    fn extra_mounts_refuses_root_maps() {
        // Use |_| true so real host paths aren't required (hermetic in
        // the Nix sandbox). The invariant under test is that "/" entries
        // are filtered out regardless of existence.
        let ro = vec![PathBuf::from("/"), PathBuf::from("/usr")];
        let rw = vec![PathBuf::from("/"), PathBuf::from("/usr/bin")];
        let mounts = extra_mounts_with_check(&rw, &ro, |_| true);

        assert_eq!(mounts.len(), 1);
        assert!(mounts.iter().all(|m| match m {
            Mount::Bind { src, dest } | Mount::RoBind { src, dest } => {
                src != Path::new("/") && dest != Path::new("/")
            }
            _ => true,
        }));
        assert!(matches!(
            &mounts[0],
            Mount::RoBind { src, dest }
                if src == Path::new("/usr") && dest == Path::new("/usr")
        ));
    }

    #[test]
    fn local_share_kiro_cli_is_mounted_read_write() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-kiro-cli-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let kiro_cli = home.join(".local/share/kiro-cli");
        std::fs::create_dir_all(&kiro_cli).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_local_overrides();

        assert!(mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &kiro_cli && dest == &kiro_cli
        )));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn local_share_ai_memory_is_mounted_read_write() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-ai-memory-home-{}", std::process::id()));
        let ai_memory = home.join(".local/share/ai-memory");
        std::fs::create_dir_all(&ai_memory).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_local_overrides();

        assert!(mounts.iter().any(|mount| matches!(
            mount,
            Mount::Bind { src, dest }
                if src == &ai_memory && dest == &ai_memory
        )));

        let _ = std::fs::remove_dir_all(home);
    }

    /// Index of the first exact `[flag, src, dest]` triple in the args.
    fn mount_arg_index(
        args: &[String],
        flag: &str,
        src: &Path,
        dest: &Path,
    ) -> usize {
        let src = src.display().to_string();
        let dest = dest.display().to_string();
        args.windows(3)
            .position(|w| w[0] == flag && w[1] == src && w[2] == dest)
            .unwrap_or_else(|| panic!("no `{flag} {src} {dest}` in args"))
    }

    /// Regression for #83: an `--map` path inside the project must be
    /// bound after the project mount, or bwrap's later project bind
    /// silently shadows the read-only bind and the path stays writable.
    #[test]
    fn in_project_ro_map_binds_after_project_mount() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-map-order-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let project = home.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".ai-jail"), "").unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let config = Config {
            ro_maps: vec![project.join(".git")],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let project_at = mount_arg_index(&args, "--bind", &project, &project);
        let git = project.join(".git");
        let ro_map_at = mount_arg_index(&args, "--ro-bind", &git, &git);
        assert!(
            ro_map_at > project_at,
            "in-project ro map (idx {ro_map_at}) must come after the \
             project bind (idx {project_at})"
        );
        // Mask overlays (the hidden project .ai-jail among them) must
        // still stack above in-project maps.
        let hide = project.join(".ai-jail");
        let hide_at = args
            .windows(3)
            .position(|w| {
                w[0] == "--ro-bind" && w[2] == hide.display().to_string()
            })
            .expect("hidden project .ai-jail bind present");
        assert!(hide_at > ro_map_at);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn out_of_project_ro_map_stays_before_project_mount() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-map-order-out-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let project = home.join("project");
        let outside = home.join("shared-data");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let config = Config {
            ro_maps: vec![outside.clone()],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let project_at = mount_arg_index(&args, "--bind", &project, &project);
        let ro_map_at = mount_arg_index(&args, "--ro-bind", &outside, &outside);
        assert!(ro_map_at < project_at);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn alternate_destination_inside_project_binds_after_project() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-alternate-map-order-home-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        let project = home.join("project");
        let source = home.join("shared-data");
        let destination = project.join("vendor/shared");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let config = Config {
            ro_maps: vec![PathBuf::from(format!(
                "{}:{}",
                source.display(),
                destination.display()
            ))],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let project_at = mount_arg_index(&args, "--bind", &project, &project);
        let ro_map_at =
            mount_arg_index(&args, "--ro-bind", &source, &destination);
        assert!(
            ro_map_at > project_at,
            "alternate in-project destination (idx {ro_map_at}) must come \
             after the project bind (idx {project_at})"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    /// Regression for #83's overlay sibling: an in-project overlay map
    /// emitted before the project bind was shadowed by it, so writes
    /// bypassed the copy-on-write layer and mutated the real files.
    #[test]
    fn in_project_overlay_map_mounts_after_project_mount() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-overlay-order-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let project = home.join("project");
        std::fs::create_dir_all(project.join("vendor")).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let config = Config {
            overlay_maps: vec![project.join("vendor")],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let project_at = mount_arg_index(&args, "--bind", &project, &project);
        let overlay_at = args
            .iter()
            .position(|a| a == "--overlay-src")
            .expect("overlay args present");
        assert!(
            overlay_at > project_at,
            "in-project overlay (idx {overlay_at}) must come after the \
             project bind (idx {project_at})"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    /// Fixture mirroring the official Claude installer layout:
    /// `<home>/.local/bin/agent` → `<home>/.local/share/agent/versions/1.0`.
    fn installer_layout_home(tag: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "ai-jail-bwrap-cmd-home-{tag}-{}",
            std::process::id()
        ));
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
        home
    }

    fn has_ro_bind(args: &[String], path: &Path) -> bool {
        let p = path.display().to_string();
        args.windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == p && w[2] == p)
    }

    fn prepend_path(dir: &Path) -> std::ffi::OsString {
        std::env::var_os("PATH").map_or_else(
            || dir.as_os_str().to_os_string(),
            |old| {
                let mut paths = vec![dir.to_path_buf()];
                paths.extend(std::env::split_paths(&old));
                std::env::join_paths(paths).unwrap()
            },
        )
    }

    #[test]
    fn private_home_binds_command_binary_from_home() {
        // Regression for #81: `ai-jail --private-home claude` must be
        // able to exec an agent installed under $HOME.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = installer_layout_home("private");
        let _home = EnvVarGuard::set("HOME", &home);
        let _path =
            EnvVarGuard::set("PATH", prepend_path(&home.join(".local/bin")));

        let config = Config {
            command: vec!["agent".into()],
            private_home: Some(true),
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &home.join("project"),
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(has_ro_bind(&args, &home.join(".local/bin/agent")));
        assert!(has_ro_bind(
            &args,
            &home.join(".local/share/agent/versions")
        ));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn lockdown_skips_command_binary_mounts() {
        // Lockdown clears the environment down to the system PATH, so
        // home-installed binaries stay hidden there by design.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = installer_layout_home("lockdown");
        let _home = EnvVarGuard::set("HOME", &home);
        let _path =
            EnvVarGuard::set("PATH", prepend_path(&home.join(".local/bin")));

        let config = Config {
            command: vec!["agent".into()],
            private_home: Some(true),
            lockdown: Some(true),
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &home.join("project"),
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(!has_ro_bind(&args, &home.join(".local/bin/agent")));
        assert!(!has_ro_bind(
            &args,
            &home.join(".local/share/agent/versions")
        ));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn format_dry_run_empty() {
        let args: Vec<String> = vec![];
        let output = format_dry_run_args(&args);
        assert!(output.is_empty());
    }

    #[test]
    fn dry_run_contains_separator_before_command() {
        let config = minimal_test_config();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        let sep = args.iter().position(|a| a == "--");
        assert!(sep.is_some(), "dry-run args must include -- separator");
    }

    #[test]
    fn dry_run_contains_isolation_flags() {
        let config = minimal_test_config();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.contains(&"--die-with-parent".to_string()));
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        // --new-session is environment-dependent; see should_use_new_session.
        if should_use_new_session() {
            assert!(args.contains(&"--new-session".to_string()));
        } else {
            assert!(!args.contains(&"--new-session".to_string()));
        }
    }

    #[test]
    fn lockdown_project_is_read_only() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.no_worktree = Some(false);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        let has_project_ro = args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && w[1] == "/home/user/project"
                && w[2] == "/home/user/project"
        });
        assert!(has_project_ro);
    }

    #[test]
    fn browser_profile_project_is_read_only_without_network_lockdown() {
        let mut config = minimal_test_config();
        config.command = vec!["chromium".into()];
        config.browser_profile = Some("hard".into());
        config.rw_maps = vec![PathBuf::from("/usr/bin")];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && w[1] == "/home/user/project"
                && w[2] == "/home/user/project"
        }));
        assert!(
            args.contains(&"--unshare-net".to_string()),
            "network is isolated unless explicitly enabled"
        );
        assert!(
            !args.windows(3).any(|w| {
                w[0] == "--bind" && w[1] == "/usr/bin" && w[2] == "/usr/bin"
            }),
            "browser profiles ignore extra rw maps"
        );
    }

    #[test]
    fn private_home_hides_host_dotdirs_but_keeps_normal_mounts() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-private-home-{}", std::process::id()));
        let extra = home.join("extra");
        let project = home.join("project");
        let _ = std::fs::create_dir_all(home.join(".config"));
        let _ = std::fs::create_dir_all(home.join(".cache"));
        let _ = std::fs::create_dir_all(&extra);
        let _ = std::fs::create_dir_all(&project);
        let _home = EnvVarGuard::set("HOME", home.as_os_str());

        let mut config = minimal_test_config();
        config.private_home = Some(true);
        config.rw_maps = vec![extra.clone()];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let home_s = home.display().to_string();
        let project_s = project.display().to_string();
        let extra_s = extra.display().to_string();
        assert!(args.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == home_s));
        assert!(!args.windows(3).any(|w| {
            (w[0] == "--bind" || w[0] == "--ro-bind")
                && (w[1] == home.join(".config").display().to_string()
                    || w[1] == home.join(".cache").display().to_string())
        }));
        assert!(args.windows(3).any(|w| {
            w[0] == "--bind" && w[1] == project_s && w[2] == project_s
        }));
        assert!(args.windows(3).any(|w| {
            w[0] == "--bind" && w[1] == extra_s && w[2] == extra_s
        }));
        assert!(args.contains(&"--unshare-net".to_string()));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn browser_soft_profile_mounts_only_ai_jail_browser_state() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-browser-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        let _home = EnvVarGuard::set("HOME", home.as_os_str());

        let mut config = minimal_test_config();
        config.command = vec!["chromium".into()];
        config.browser_profile = Some("soft".into());
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = home.join("project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let state = home.join(".local/share/ai-jail/browsers/chromium");
        assert!(state.is_dir());
        assert!(args.windows(3).any(|w| {
            w[0] == "--bind"
                && w[1] == state.display().to_string()
                && w[2] == state.display().to_string()
        }));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn lockdown_forces_new_session() {
        // --new-session must be present in lockdown mode regardless of
        // whether stdin is a terminal. The README documents lockdown as
        // enabling --new-session unconditionally; should_use_new_session()
        // alone is TTY-dependent, so lockdown needs its own short-circuit.
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            args.contains(&"--new-session".to_string()),
            "--new-session must be present in lockdown mode regardless of stdin"
        );
    }

    #[test]
    fn lockdown_disables_network_and_clears_env() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"--clearenv".to_string()));
    }

    #[test]
    fn lockdown_skips_extra_maps() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.rw_maps = vec![PathBuf::from("/tmp")];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let has_tmp_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/tmp" && w[2] == "/tmp");
        assert!(!has_tmp_bind);
    }

    #[test]
    fn root_extra_maps_are_not_emitted_in_dry_run() {
        let mut config = minimal_test_config();
        config.ro_maps = vec![PathBuf::from("/")];
        config.rw_maps = vec![PathBuf::from("/")];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        let has_root_ro_bind = args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/" && w[2] == "/");
        let has_root_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/" && w[2] == "/");
        assert!(!has_root_ro_bind);
        assert!(!has_root_bind);
    }

    /// Create a fresh `(project_dir, source_dir)` pair under the temp
    /// dir for overlay tests. Caller removes the parent when done.
    fn overlay_test_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ovl-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        let project = root.join("project");
        let source = root.join("source");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        (project, source)
    }

    #[test]
    fn mount_overlay_to_args() {
        let m = Mount::Overlay {
            lower: PathBuf::from("/home/u/.claude"),
            upper: PathBuf::from("/p/.ai-jail-overlays/x/upper"),
            work: PathBuf::from("/p/.ai-jail-overlays/x/work"),
            dest: PathBuf::from("/home/u/.claude"),
        };
        assert_eq!(
            m.to_args(),
            vec![
                "--overlay-src".to_string(),
                "/home/u/.claude".into(),
                "--overlay".into(),
                "/p/.ai-jail-overlays/x/upper".into(),
                "/p/.ai-jail-overlays/x/work".into(),
                "/home/u/.claude".into(),
            ]
        );
    }

    #[test]
    fn overlay_storage_name_sanitizes_path() {
        assert_eq!(
            overlay_storage_name(Path::new("/home/u/.claude")),
            "home_u_.claude"
        );
        assert_eq!(overlay_storage_name(Path::new("/a b/c@d")), "a_b_c_d");
    }

    #[test]
    fn overlay_mounts_creates_layers_and_hide() {
        let (project, source) = overlay_test_dirs("create");
        let (mounts, hide) =
            overlay_mounts(std::slice::from_ref(&source), &project, false)
                .unwrap();

        assert_eq!(mounts.len(), 1);
        match &mounts[0] {
            Mount::Overlay {
                lower,
                upper,
                work,
                dest,
            } => {
                assert_eq!(lower, &source);
                assert_eq!(dest, &source);
                assert!(upper.is_dir(), "upper layer must be created");
                assert!(work.is_dir(), "work dir must be created");
                assert!(upper.starts_with(project.join(".ai-jail-overlays")));
            }
            other => panic!("expected Overlay, got {other:?}"),
        }

        assert_eq!(hide.len(), 1);
        match &hide[0] {
            Mount::Tmpfs { dest } => {
                assert_eq!(dest, &project.join(".ai-jail-overlays"));
            }
            other => panic!("expected Tmpfs hide, got {other:?}"),
        }
        assert!(
            project.join(".ai-jail-overlays/.gitignore").is_file(),
            "a .gitignore must guard the storage dir"
        );

        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_mounts_skips_overlapping() {
        let (project, source) = overlay_test_dirs("overlap");
        let child = source.join("sub");
        std::fs::create_dir_all(&child).unwrap();
        // child overlaps source → only the first (source) is accepted.
        let maps = vec![source.clone(), child];
        let (mounts, _hide) = overlay_mounts(&maps, &project, false).unwrap();
        assert_eq!(mounts.len(), 1);
        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_mounts_skips_missing_source() {
        let (project, _source) = overlay_test_dirs("missing");
        let missing = project.join("does-not-exist");
        let (mounts, hide) =
            overlay_mounts(std::slice::from_ref(&missing), &project, false)
                .unwrap();
        assert!(mounts.is_empty());
        assert!(hide.is_empty());
        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_mounts_rejects_symlinked_storage_root() {
        let (project, source) = overlay_test_dirs("symlink-storage");
        let outside = project.parent().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project.join(OVERLAY_STORAGE_DIR))
            .unwrap();

        let err =
            overlay_mounts(std::slice::from_ref(&source), &project, false)
                .unwrap_err();
        assert!(err.contains("storage root"));
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());

        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_present_in_normal_mode() {
        let (project, source) = overlay_test_dirs("normal");
        let mut config = minimal_test_config();
        config.overlay_maps = vec![source.clone()];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.windows(2).any(|w| {
            w[0] == "--overlay-src" && Path::new(&w[1]) == source
        }));
        assert!(args.iter().any(|a| a == "--overlay"));
        // Raw storage is hidden from inside the sandbox.
        let storage = project.join(".ai-jail-overlays");
        assert!(
            args.windows(2)
                .any(|w| { w[0] == "--tmpfs" && Path::new(&w[1]) == storage })
        );

        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_disabled_in_lockdown() {
        let (project, source) = overlay_test_dirs("lockdown");
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.overlay_maps = vec![source];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(!args.iter().any(|a| a == "--overlay"));
        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn linked_worktree_paths_are_rw_in_normal_mode() {
        let fixture = create_linked_worktree_fixture();
        let mut config = minimal_test_config();
        config.no_worktree = Some(false);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.windows(3).any(|w| {
            w[0] == "--bind"
                && super::super::paths_equivalent(
                    Path::new(&w[1]),
                    &fixture.git_dir,
                )
                && super::super::paths_equivalent(
                    Path::new(&w[2]),
                    &fixture.git_dir,
                )
        }));
        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && super::super::paths_equivalent(
                    Path::new(&w[1]),
                    &fixture.common_dir,
                )
                && super::super::paths_equivalent(
                    Path::new(&w[2]),
                    &fixture.common_dir,
                )
        }));
    }

    #[test]
    fn linked_worktree_paths_are_ro_in_lockdown() {
        let fixture = create_linked_worktree_fixture();
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.no_worktree = Some(false);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && super::super::paths_equivalent(
                    Path::new(&w[1]),
                    &fixture.git_dir,
                )
                && super::super::paths_equivalent(
                    Path::new(&w[2]),
                    &fixture.git_dir,
                )
        }));
        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && super::super::paths_equivalent(
                    Path::new(&w[1]),
                    &fixture.common_dir,
                )
                && super::super::paths_equivalent(
                    Path::new(&w[2]),
                    &fixture.common_dir,
                )
        }));
    }

    #[test]
    fn invalid_linked_worktree_layout_is_ignored() {
        let fixture = create_linked_worktree_fixture();
        std::fs::remove_file(fixture.git_dir.join("commondir")).unwrap();
        let config = minimal_test_config();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(!args.iter().any(|arg| {
            super::super::paths_equivalent(Path::new(arg), &fixture.git_dir)
        }));
        assert!(!args.iter().any(|arg| {
            super::super::paths_equivalent(Path::new(arg), &fixture.common_dir)
        }));
    }

    #[test]
    fn disabled_worktree_passthrough_skips_mounts() {
        let fixture = create_linked_worktree_fixture();
        let mut config = minimal_test_config();
        config.no_worktree = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(!args.iter().any(|arg| {
            super::super::paths_equivalent(Path::new(arg), &fixture.git_dir)
        }));
        assert!(!args.iter().any(|arg| {
            super::super::paths_equivalent(Path::new(arg), &fixture.common_dir)
        }));
    }

    #[test]
    fn lockdown_with_allowed_ports_skips_unshare_net() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.allow_tcp_ports = vec![32000];
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            args.contains(&"--unshare-net".to_string()),
            "allow-tcp-port does not re-enable host networking"
        );
        assert!(args.contains(&"--clearenv".to_string()));
    }

    #[test]
    fn lockdown_without_allowed_ports_keeps_unshare_net() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            args.contains(&"--unshare-net".to_string()),
            "lockdown without allowed ports must keep --unshare-net"
        );
    }

    #[test]
    fn lockdown_wrapper_forwards_allowed_ports() {
        let mut config = minimal_test_config();
        config.lockdown = Some(true);
        config.allow_tcp_ports = vec![32000, 8080];

        let wrapper_args = landlock_wrapper_args(&config, &[], false);
        let port_args: Vec<_> = wrapper_args
            .windows(2)
            .filter(|w| w[0] == "--allow-tcp-port")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(port_args, vec!["32000", "8080"]);
    }

    #[test]
    fn landlock_wrapper_forwards_only_successfully_mounted_destinations() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-landlock-wrapper-maps-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let source = root.join("source");
        let destination = project.join("destination");
        let missing_source = root.join("missing-source");
        let missing_destination = project.join("missing-destination");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::create_dir_all(&source).unwrap();

        let config = Config {
            rw_maps: vec![
                MapSpec {
                    source: source.clone(),
                    destination: destination.clone(),
                }
                .encode(),
                MapSpec {
                    source: missing_source.clone(),
                    destination: missing_destination.clone(),
                }
                .encode(),
            ],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        let wrapper_args = &args[separator + 1..];

        assert!(wrapper_args.windows(2).any(|args| {
            args[0] == "--landlock-rw-path"
                && args[1] == destination.display().to_string()
        }));
        assert!(!wrapper_args.contains(&source.display().to_string()));
        assert!(!wrapper_args.contains(&missing_source.display().to_string()));
        assert!(
            !wrapper_args.contains(&missing_destination.display().to_string())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn landlock_wrapper_keeps_colon_destination_opaque() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-landlock-wrapper-colon-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let source = root.join("source");
        let destination = project.join("name:/etc");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source).unwrap();

        let config = Config {
            rw_maps: vec![
                MapSpec {
                    source,
                    destination: destination.clone(),
                }
                .encode(),
            ],
            ..minimal_test_config()
        };
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        let wrapper_args = &args[separator + 1..];

        assert!(wrapper_args.windows(2).any(|args| {
            args[0] == "--landlock-rw-path"
                && args[1] == destination.display().to_string()
        }));
        assert!(!wrapper_args.contains(&"--rw-map".to_string()));
        assert!(!wrapper_args.contains(&"--map".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn browser_wrapper_skips_extra_maps() {
        let mut config = minimal_test_config();
        config.command = vec!["chromium".into()];
        config.browser_profile = Some("hard".into());
        config.rw_maps = vec![PathBuf::from("/tmp/browser-rw")];
        config.ro_maps = vec![PathBuf::from("/tmp/browser-ro")];

        let wrapper_args = landlock_wrapper_args(&config, &[], false);

        assert!(!wrapper_args.contains(&"--rw-map".into()));
        assert!(!wrapper_args.contains(&"--map".into()));
        assert!(wrapper_args.contains(&"--browser=hard".into()));
    }

    #[test]
    fn regression_omp_home_dir_is_writable() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-omp-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let omp = home.join(".omp");
        std::fs::create_dir_all(omp.join("logs")).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(
            mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest } if src == &omp && dest == &omp
            )),
            "~/.omp must be mounted read-write so OMP can create logs"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn regression_pi_home_dir_is_writable() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-pi-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let pi = home.join(".pi");
        std::fs::create_dir_all(pi.join("agent").join("sessions")).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(
            mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest } if src == &pi && dest == &pi
            )),
            "~/.pi must be mounted read-write so pi can write settings and sessions"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn regression_pi_lens_home_dir_is_writable() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-pi-lens-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let pi_lens = home.join(".pi-lens");
        std::fs::create_dir_all(pi_lens.join("sessions")).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(
            mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest } if src == &pi_lens && dest == &pi_lens
            )),
            "~/.pi-lens must be mounted read-write so pi can write lens state"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn kimi_code_home_dir_is_writable_only_for_kimi_commands() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-kimi-code-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let kimi_code = home.join(".kimi-code");
        std::fs::create_dir_all(kimi_code.join("sessions")).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mut kimi = minimal_test_config();
        kimi.command = vec!["kimi-code".into()];
        kimi.agent_state = Some(true);
        let mounts =
            discover_home_dotfiles_full(&kimi, false, &[], false, false);

        assert!(
            mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest } if src == &kimi_code && dest == &kimi_code
            )),
            "~/.kimi-code must be mounted read-write so kimi can write sessions and logs"
        );

        // Without the agent_state opt-in the state dir stays hidden.
        let gated = minimal_test_config();
        let mounts =
            discover_home_dotfiles_full(&gated, false, &[], false, false);
        assert!(!mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &kimi_code && dest == &kimi_code
        )));

        let mut non_kimi = minimal_test_config();
        non_kimi.command = vec!["claude".into()];
        non_kimi.agent_state = Some(true);
        let mounts =
            discover_home_dotfiles_full(&non_kimi, false, &[], false, false);
        assert!(!mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &kimi_code && dest == &kimi_code
        )));

        let _ = std::fs::remove_dir_all(&home);
    }

    // ── Agent-state capability gating ───────────────────────────

    #[test]
    fn claude_state_requires_agent_state_opt_in() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-agent-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let claude_dir = home.join(".claude");
        std::fs::create_dir_all(claude_dir.join("projects")).unwrap();
        let claude_json = home.join(".claude.json");
        std::fs::write(&claude_json, b"{}").unwrap();

        let _home = EnvVarGuard::set("HOME", &home);

        // Project command without opt-in: no ~/.claude or
        // ~/.claude.json mounts.
        let mut config = minimal_test_config();
        config.command = vec!["claude".into()];
        let mounts =
            discover_home_dotfiles_full(&config, true, &[], false, false);
        assert!(
            !mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest }
                    if src == &claude_dir && dest == &claude_dir
            )),
            "~/.claude must stay hidden without agent_state opt-in"
        );
        assert!(
            !mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest }
                    if src == &claude_json && dest == &claude_json
            )),
            "~/.claude.json must stay hidden without agent_state opt-in"
        );

        // With opt-in: state dir and state file are mounted rw.
        config.agent_state = Some(true);
        let mounts =
            discover_home_dotfiles_full(&config, true, &[], false, false);
        assert!(mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &claude_dir && dest == &claude_dir
        )));
        assert!(mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest } if src == &claude_json && dest == &claude_json
        )));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn hide_dotdir_overrides_agent_state_mounts() {
        // "User hides win": --hide-dotdir .claude suppresses the
        // agent-state mounts even with the capability enabled.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-agent-state-hide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let claude_dir = home.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let claude_json = home.join(".claude.json");
        std::fs::write(&claude_json, b"{}").unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mut config = minimal_test_config();
        config.command = vec!["claude".into()];
        config.agent_state = Some(true);
        config.hide_dotdirs = vec![".claude".into()];
        let mounts =
            discover_home_dotfiles_full(&config, true, &[], false, false);

        assert!(
            !mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest }
                    if src == &claude_dir && dest == &claude_dir
            )),
            "hidden ~/.claude must not be mounted even with agent_state"
        );
        assert!(
            !mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest }
                    if src == &claude_json && dest == &claude_json
            )),
            "hidden ~/.claude.json must not be mounted even with agent_state"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn opencode_state_paths_hide_under_top_level_dotdir() {
        // Multi-component state paths (".config/opencode") hide via
        // their top-level dotdir (".config").
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-agent-state-opencode-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        let state = home.join(".config").join("opencode");
        std::fs::create_dir_all(&state).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mut config = minimal_test_config();
        config.command = vec!["opencode".into()];
        config.agent_state = Some(true);
        config.hide_dotdirs = vec![".config".into()];
        let mounts =
            discover_home_dotfiles_full(&config, true, &[], false, false);

        assert!(
            !mounts.iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest } if src == &state && dest == &state
            )),
            "hidden top-level dotdir must suppress nested state mount"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn command_state_paths_cover_full_command_list() {
        // Parity with the macOS seatbelt agent-state mapping
        // (seatbelt.rs agent_state_paths): both platforms must map the
        // same commands to the same state dirs, including soulforge
        // and omp.
        let cases: &[(&str, &[&str])] = &[
            ("claude", &[".claude"]),
            ("codex", &[".codex"]),
            ("opencode", &[".config/opencode", ".local/share/opencode"]),
            ("crush", &[".crush"]),
            ("kimi", &[".kimi-code"]),
            ("gemini", &[".gemini"]),
            ("grok", &[".grok"]),
            ("pi", &[".pi", ".pi-lens"]),
            ("aider", &[".aider"]),
            ("soulforge", &[".soulforge"]),
            ("omp", &[".omp"]),
        ];
        for (command, expected) in cases {
            let mut config = minimal_test_config();
            config.command = vec![(*command).into()];
            assert_eq!(
                command_state_paths(&config),
                *expected,
                "state mapping mismatch for {command}"
            );
        }
    }

    // ── Sandbox environment filtering ───────────────────────────

    #[test]
    fn env_args_filters_credentials_by_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _api_key = EnvVarGuard::set("ANTHROPIC_API_KEY", "sk-ant-secret");
        let _aws = EnvVarGuard::set("AWS_SECRET_ACCESS_KEY", "aws-secret");

        let args = env_args(false, &[]);
        assert!(args.contains(&"--clearenv".to_string()));
        assert!(
            !args
                .windows(3)
                .any(|w| { w[0] == "--setenv" && w[1] == "ANTHROPIC_API_KEY" }),
            "API keys must be dropped by default"
        );
        assert!(
            !args.windows(3).any(|w| {
                w[0] == "--setenv" && w[1] == "AWS_SECRET_ACCESS_KEY"
            }),
            "AWS credentials must be dropped by default"
        );
        // PATH is allowlisted and re-set after the clear.
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--setenv" && w[1] == "PATH")
        );
    }

    #[test]
    fn env_args_keeps_credentials_with_env_pass_and_inherit() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _api_key = EnvVarGuard::set("ANTHROPIC_API_KEY", "sk-ant-secret");
        let _token = EnvVarGuard::set("GITHUB_TOKEN", "gh-token");

        // --env ANTHROPIC_API_KEY passes the host value through the
        // default filter.
        let args = env_args(false, &["ANTHROPIC_API_KEY".to_string()]);
        assert!(args.contains(&"--clearenv".to_string()));
        assert!(args.windows(3).any(|w| {
            w[0] == "--setenv"
                && w[1] == "ANTHROPIC_API_KEY"
                && w[2] == "sk-ant-secret"
        }));
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--setenv" && w[1] == "GITHUB_TOKEN"),
            "unlisted variables stay dropped"
        );

        // --inherit-env keeps the whole host environment; no clearenv.
        let args = env_args(true, &["GITHUB_TOKEN=explicit".to_string()]);
        assert!(!args.contains(&"--clearenv".to_string()));
        assert!(args.windows(3).any(|w| {
            w[0] == "--setenv" && w[1] == "GITHUB_TOKEN" && w[2] == "explicit"
        }));
    }

    #[test]
    fn home_gitignore_is_mounted_read_only() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-gitignore-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let gitignore = home.join(".gitignore");
        std::fs::write(&gitignore, b"target\n").unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(mounts.iter().any(|m| matches!(
            m,
            Mount::RoBind { src, dest } if src == &gitignore && dest == &gitignore
        )));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn home_xdg_git_dir_is_mounted_read_only() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-xdg-git-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let xdg_git = home.join(".config").join("git");
        std::fs::create_dir_all(&xdg_git).unwrap();
        std::fs::write(xdg_git.join("ignore"), b"target\n").unwrap();
        std::fs::write(xdg_git.join("config"), b"[user]\n").unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _xdg = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(
            mounts.iter().any(|m| matches!(
                m,
                Mount::RoBind { src, dest } if src == &xdg_git && dest == &xdg_git
            )),
            "expected RoBind of ~/.config/git, got: {mounts:#?}"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn xdg_config_home_env_overrides_dot_config_location() {
        // XDG spec: $XDG_CONFIG_HOME wins when set. A user with
        // XDG_CONFIG_HOME=/opt/cfg keeps their git config at
        // /opt/cfg/git — ai-jail must follow the env var, not the
        // hardcoded ~/.config fallback.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-xdg-env-home-{}", std::process::id()));
        let xdg = std::env::temp_dir()
            .join(format!("ai-jail-xdg-env-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&xdg);
        std::fs::create_dir_all(&home).unwrap();
        let xdg_git = xdg.join("git");
        std::fs::create_dir_all(&xdg_git).unwrap();
        std::fs::write(xdg_git.join("config"), b"[user]\n").unwrap();
        // Decoy: a fallback path that should NOT be picked because
        // XDG_CONFIG_HOME is set.
        let decoy = home.join(".config").join("git");
        std::fs::create_dir_all(&decoy).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _xdg_env = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg);
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        assert!(
            mounts.iter().any(|m| matches!(
                m, Mount::RoBind { src, .. } if src == &xdg_git
            )),
            "expected RoBind of {}, got: {mounts:#?}",
            xdg_git.display()
        );
        assert!(
            !mounts.iter().any(|m| matches!(
                m, Mount::RoBind { src, .. } if src == &decoy
            )),
            "must not mount ~/.config/git fallback when XDG_CONFIG_HOME is set"
        );

        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&xdg);
    }

    #[test]
    fn home_xdg_git_dir_skipped_when_absent() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-xdg-git-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _xdg = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let mounts = discover_home_dotfiles(false, &[], &[], false);

        let xdg_git = home.join(".config").join("git");
        assert!(
            !mounts.iter().any(|m| matches!(
                m, Mount::RoBind { src, .. } if src == &xdg_git
            )),
            "must not mount nonexistent ~/.config/git"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn lockdown_skips_host_home_dotfiles() {
        let mounts = discover_home_dotfiles(true, &[], &[], false);
        assert_eq!(mounts.len(), 1, "lockdown should only mount tmpfs home");
        match &mounts[0] {
            Mount::Tmpfs { .. } => {}
            _ => panic!("first lockdown home mount must be tmpfs"),
        }
    }

    #[test]
    fn prepare_creates_private_hosts_file() {
        let guard = prepare().unwrap();
        let meta = std::fs::metadata(guard.hosts_path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn new_session_when_not_interactive() {
        // --new-session is only used when stdin is not a terminal.
        // In CI/test environments, stdin is typically NOT a terminal,
        // so --new-session should be used.
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            assert!(should_use_new_session());
        }
        // When stdin IS a terminal (interactive use), --new-session
        // is skipped so the child receives SIGWINCH.
    }

    #[test]
    fn trusted_bwrap_metadata_requires_root_or_nix_store_nonwritable_executable()
     {
        assert!(trusted_binary_metadata(true, 0, 0o755, false));
        assert!(trusted_binary_metadata(true, 1000, 0o555, true));
        assert!(!trusted_binary_metadata(true, 1000, 0o755, true));
        assert!(!trusted_binary_metadata(true, 1000, 0o555, false));
        assert!(!trusted_binary_metadata(true, 0, 0o775, false));
        assert!(!trusted_binary_metadata(true, 0, 0o644, false));
    }

    #[test]
    fn needs_nix_mount_triggers_for_nix_hosts_dest() {
        let nix = Path::new("/nix");
        let hosts_in_nix = Path::new("/nix/store/1234-hosts/hosts");
        assert!(needs_nix_mount(hosts_in_nix, nix));

        let root = std::env::temp_dir()
            .join(format!("ai-jail-nix-mount-test-{}", std::process::id()));
        let nix_dir = root.join("nix/store/pkg");
        let symlink = root.join("symlink-to-nix");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&nix_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&nix_dir, &symlink).unwrap();

        assert!(path_resolves_under(&symlink, &root.join("nix")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regression_dry_run_uses_absolute_bwrap_path() {
        let config = minimal_test_config();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();
        assert!(
            args.first().is_some_and(|s| s.starts_with('/')),
            "dry-run must show absolute bwrap path"
        );
    }

    #[test]
    fn landlock_wrapper_in_dry_run() {
        let config = minimal_test_config();
        assert!(config.landlock_enabled());
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        // Should contain the wrapper dest path
        assert!(
            args.contains(&LANDLOCK_WRAPPER_DEST.to_string()),
            "dry-run must include Landlock wrapper path"
        );
        assert!(
            args.contains(&"--landlock-exec".to_string()),
            "dry-run must include --landlock-exec"
        );

        // Two -- separators: one for bwrap, one for wrapper
        let seps: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--")
            .collect();
        assert!(
            seps.len() >= 2,
            "expected at least 2 -- separators, got {}",
            seps.len()
        );
    }

    #[test]
    fn wrapper_remains_when_landlock_disabled_for_seccomp_and_rlimits() {
        let mut config = minimal_test_config();
        config.no_landlock = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_mount(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            args.contains(&"--landlock-exec".to_string()),
            "wrapper must retain seccomp and rlimits when Landlock is disabled"
        );
    }

    #[test]
    fn resolv_bind_after_run_tmpfs() {
        let mounts = discover_base(
            (Path::new("/tmp/test-hosts"), Path::new("/etc/hosts")),
            Some((
                Path::new("/tmp/test-resolv"),
                Path::new("/run/resolvconf/resolv.conf"),
            )),
            None,
        );

        let mut run_tmpfs_idx = None;
        let mut resolv_idx = None;
        for (i, m) in mounts.iter().enumerate() {
            match m {
                Mount::Tmpfs { dest } if dest == Path::new("/run") => {
                    run_tmpfs_idx = Some(i);
                }
                Mount::FileRoBind { dest, .. }
                    if dest == Path::new("/run/resolvconf/resolv.conf") =>
                {
                    resolv_idx = Some(i);
                }
                _ => {}
            }
        }

        assert!(run_tmpfs_idx.is_some(), "expected tmpfs /run mount");
        assert!(resolv_idx.is_some(), "expected resolv file bind mount");
        assert!(
            run_tmpfs_idx.unwrap() < resolv_idx.unwrap(),
            "resolv bind must come after /run tmpfs"
        );
    }

    #[test]
    fn resolv_intermediate_tmpfs_hop_is_mounted() {
        // Fedora toolbox chains symlinks:
        //   /etc/resolv.conf -> /run/host/etc/resolv.conf -> .../stub-resolv.conf
        // The canonical target is mounted, but the inherited /etc/resolv.conf
        // symlink still dangles at the intermediate /run/host/etc hop. We must
        // also bind the generated file at that intermediate path.
        let mounts = discover_base(
            (Path::new("/tmp/test-hosts"), Path::new("/etc/hosts")),
            Some((
                Path::new("/tmp/test-resolv"),
                Path::new("/run/host/run/systemd/resolve/stub-resolv.conf"),
            )),
            Some((
                Path::new("/tmp/test-resolv"),
                Path::new("/run/host/etc/resolv.conf"),
            )),
        );

        let canonical = mounts.iter().any(|m| matches!(
            m,
            Mount::FileRoBind { dest, .. }
                if dest == Path::new("/run/host/run/systemd/resolve/stub-resolv.conf")
        ));
        let intermediate = mounts.iter().any(|m| {
            matches!(
                m,
                Mount::FileRoBind { dest, .. }
                    if dest == Path::new("/run/host/etc/resolv.conf")
            )
        });

        assert!(canonical, "expected bind at canonical resolv target");
        assert!(
            intermediate,
            "expected bind at intermediate /run hop for dangling symlink cases"
        );
    }

    #[test]
    fn resolv_regular_file_does_not_double_mount() {
        // When /etc/resolv.conf is a regular file, dest is /etc/resolv.conf
        // itself; we should not emit a duplicate mount.
        let mounts = discover_base(
            (Path::new("/tmp/test-hosts"), Path::new("/etc/hosts")),
            Some((
                Path::new("/tmp/test-resolv"),
                Path::new("/etc/resolv.conf"),
            )),
            None,
        );

        let resolv_binds: Vec<_> = mounts
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    Mount::FileRoBind { dest, .. }
                        if dest == Path::new("/etc/resolv.conf")
                )
            })
            .collect();
        assert_eq!(
            resolv_binds.len(),
            1,
            "regular /etc/resolv.conf should produce exactly one bind"
        );
    }

    #[test]
    fn nix_hosts_dest_mounts_nix_before_hosts_bind() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-nix-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let nix = root.join("nix");
        let hosts_dest = nix.join("store/abcd-hosts/hosts");
        let hosts_src = root.join("private-hosts");
        std::fs::create_dir_all(hosts_dest.parent().unwrap()).unwrap();
        std::fs::write(&hosts_dest, "host hosts").unwrap();
        std::fs::write(&hosts_src, "private hosts").unwrap();

        let mounts = discover_base_with_nix_root(
            (&hosts_src, &hosts_dest),
            None,
            None,
            &nix,
        );

        let nix_idx = mounts.iter().position(|m| {
            matches!(m, Mount::RoBind { src, dest } if src == &nix && dest == &nix)
        });
        let hosts_idx = mounts.iter().position(|m| {
            matches!(
                m,
                Mount::FileRoBind { src, dest }
                    if src == &hosts_src && dest == &hosts_dest
            )
        });

        assert!(nix_idx.is_some(), "expected early /nix-style mount");
        assert!(hosts_idx.is_some(), "expected private hosts bind");
        assert!(
            nix_idx.unwrap() < hosts_idx.unwrap(),
            "/nix-style mount must come before hosts bind"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_real_nameservers_no_stub() {
        let input = b"nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        let result = resolve_real_nameservers(input.to_vec());
        assert_eq!(result, input.to_vec());
    }

    #[test]
    fn resolve_real_nameservers_detects_stub() {
        let input = b"nameserver 127.0.0.53\noptions edns0 trust-ad\n";
        let result = resolve_real_nameservers(input.to_vec());
        // If /run/systemd/resolve/resolv.conf exists, we either get
        // its contents (no split-DNS markers) or the original stub
        // back (split-DNS markers present, e.g. tailscale). Otherwise
        // we always fall back to the original.
        let real = Path::new("/run/systemd/resolve/resolv.conf");
        if real.exists() {
            let real_contents = std::fs::read(real).unwrap();
            let expected = pick_resolv_contents(input.to_vec(), real_contents);
            assert_eq!(result, expected);
        } else {
            assert_eq!(result, input.to_vec());
        }
    }

    // ── split-DNS detection (issue #49) ────────────────────────

    #[test]
    fn pick_resolv_swaps_in_uplink_when_clean() {
        let original = b"nameserver 127.0.0.53\n".to_vec();
        let uplink = b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n".to_vec();
        let out = pick_resolv_contents(original, uplink.clone());
        assert_eq!(out, uplink);
    }

    #[test]
    fn pick_resolv_keeps_stub_when_uplink_has_cgnat() {
        let original = b"nameserver 127.0.0.53\n".to_vec();
        // Tailscale's MagicDNS at 100.100.100.100 is the canonical
        // case. Even with a "real" upstream listed alongside, glibc's
        // resolver hits the CGNAT one first and gives up on NXDOMAIN,
        // so the only safe answer is to fall back to the stub.
        let uplink = b"\
nameserver 100.100.100.100
nameserver 1.1.1.1
"
        .to_vec();
        let out = pick_resolv_contents(original.clone(), uplink);
        assert_eq!(out, original);
    }

    #[test]
    fn pick_resolv_keeps_stub_when_uplink_has_link_local() {
        let original = b"nameserver 127.0.0.53\n".to_vec();
        let uplink = b"nameserver 169.254.10.42\n".to_vec();
        let out = pick_resolv_contents(original.clone(), uplink);
        assert_eq!(out, original);
    }

    #[test]
    fn pick_resolv_swaps_in_uplink_for_rfc1918() {
        // RFC1918 ranges are normal home/office LAN DNS, not a
        // split-DNS marker — let the substitution happen.
        let original = b"nameserver 127.0.0.53\n".to_vec();
        let lan = b"nameserver 192.168.1.1\n".to_vec();
        let out = pick_resolv_contents(original, lan.clone());
        assert_eq!(out, lan);

        let original = b"nameserver 127.0.0.53\n".to_vec();
        let lan = b"nameserver 10.0.0.1\n".to_vec();
        let out = pick_resolv_contents(original, lan.clone());
        assert_eq!(out, lan);

        let original = b"nameserver 127.0.0.53\n".to_vec();
        let lan = b"nameserver 172.20.0.1\n".to_vec();
        let out = pick_resolv_contents(original, lan.clone());
        assert_eq!(out, lan);
    }

    #[test]
    fn pick_resolv_keeps_stub_for_tailscale_search_domain() {
        let original =
            b"nameserver 127.0.0.53\nsearch tailnet.ts.net\n".to_vec();
        let uplink = b"nameserver 192.168.1.1\n".to_vec();
        let out = pick_resolv_contents(original.clone(), uplink);
        assert_eq!(out, original);
    }

    #[test]
    fn pick_resolv_keeps_stub_for_tailscale_domain_in_uplink() {
        let original = b"nameserver 127.0.0.53\n".to_vec();
        let uplink = b"nameserver 192.168.1.1\ndomain ts.net\n".to_vec();
        let out = pick_resolv_contents(original.clone(), uplink);
        assert_eq!(out, original);
    }

    #[test]
    fn tailscale_magicdns_domain_detection() {
        assert!(resolv_has_tailscale_magicdns_domain(b"search ts.net\n"));
        assert!(resolv_has_tailscale_magicdns_domain(
            b"search corp.example tailnet.ts.net\n"
        ));
        assert!(!resolv_has_tailscale_magicdns_domain(
            b"search notts.net example.com\n"
        ));
    }

    #[test]
    fn split_dns_marker_classification() {
        // CGNAT
        assert!(is_split_dns_marker_ip("100.64.0.1"));
        assert!(is_split_dns_marker_ip("100.100.100.100"));
        assert!(is_split_dns_marker_ip("100.127.255.254"));
        // CGNAT boundary — first octet only matches when second
        // octet is in [64, 127].
        assert!(!is_split_dns_marker_ip("100.63.255.254"));
        assert!(!is_split_dns_marker_ip("100.128.0.1"));
        // Link-local
        assert!(is_split_dns_marker_ip("169.254.10.42"));
        assert!(!is_split_dns_marker_ip("169.253.10.42"));
        // Public
        assert!(!is_split_dns_marker_ip("8.8.8.8"));
        assert!(!is_split_dns_marker_ip("1.1.1.1"));
        // RFC1918 (deliberately NOT flagged)
        assert!(!is_split_dns_marker_ip("10.0.0.1"));
        assert!(!is_split_dns_marker_ip("172.20.0.1"));
        assert!(!is_split_dns_marker_ip("192.168.1.1"));
        // Loopback
        assert!(!is_split_dns_marker_ip("127.0.0.53"));
        // Garbage
        assert!(!is_split_dns_marker_ip(""));
        assert!(!is_split_dns_marker_ip("notanip"));
        assert!(!is_split_dns_marker_ip("100.100.100"));
    }

    #[test]
    fn uplink_split_dns_picks_up_extra_whitespace_and_comments() {
        // systemd-resolved sometimes prepends a # banner. The detector
        // should not be fooled by indentation or comment lines.
        let uplink = b"\
# Generated by systemd-resolved
    nameserver   100.100.100.100   # tailscale
nameserver 8.8.8.8
"
        .to_vec();
        assert!(uplink_has_split_dns_markers(&uplink));

        let clean = b"\
# Generated by systemd-resolved
nameserver 1.1.1.1
nameserver 8.8.8.8
"
        .to_vec();
        assert!(!uplink_has_split_dns_markers(&clean));
    }

    #[test]
    fn contents_have_stub_detects_127_0_0_53() {
        assert!(contents_have_stub(b"nameserver 127.0.0.53\n"));
        assert!(contents_have_stub(
            b"# header\nnameserver 127.0.0.53\noptions edns0\n"
        ));
        assert!(!contents_have_stub(b"nameserver 1.1.1.1\n"));
        assert!(!contents_have_stub(b""));
    }

    #[test]
    fn bwrap_bin_env_project_executable_is_rejected() {
        let _env = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir()
            .join(format!("ai-jail-bwrap.{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let bwrap = tmp.join("bwrap");
        std::fs::write(&bwrap, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            &bwrap,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let _bwrap_bin = EnvVarGuard::set(BWRAP_ENV_VAR, bwrap.as_os_str());
        assert_ne!(bwrap_binary_path().ok().as_ref(), Some(&bwrap));
        let _ = std::fs::remove_file(&bwrap);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn bwrap_bin_env_override_invalid_path_is_not_selected() {
        let _env = ENV_LOCK.lock().unwrap();
        let _bwrap_bin =
            EnvVarGuard::set(BWRAP_ENV_VAR, "/definitely/not/a/real/bwrap");
        assert_ne!(
            bwrap_binary_path().ok().as_ref(),
            Some(&PathBuf::from("/definitely/not/a/real/bwrap"))
        );
    }

    #[test]
    fn claude_dir_produces_bind_mount_and_setenv() {
        let tmp_root = std::env::temp_dir()
            .join(format!("ai-jail-bwrap-claude-{}", std::process::id()));
        let claude_dir = tmp_root.join(".claude-example");
        let _ = std::fs::create_dir_all(&claude_dir);

        let config = Config {
            command: vec!["claude".into()],
            claude_dir: Some(claude_dir.clone()),
            no_gpu: Some(true),
            no_docker: Some(true),
            no_display: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/project");

        let args = build_dry_run_args(
            &config,
            &project,
            (Path::new("/tmp/hosts"), Path::new("/etc/hosts")),
            None,
            Path::new("/tmp/empty"),
            false,
        )
        .unwrap();

        let bind_pos = args.windows(3).position(|w| {
            w[0] == "--bind"
                && w[1] == claude_dir.display().to_string()
                && w[2] == claude_dir.display().to_string()
        });
        assert!(
            bind_pos.is_some(),
            "--bind for claude_dir not found in argv: {args:?}"
        );

        let setenv_pos = args.windows(3).position(|w| {
            w[0] == "--setenv"
                && w[1] == "CLAUDE_CONFIG_DIR"
                && w[2] == claude_dir.display().to_string()
        });
        assert!(
            setenv_pos.is_some(),
            "--setenv CLAUDE_CONFIG_DIR not found in argv: \
             {args:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn no_claude_dir_no_setenv() {
        let config = Config {
            command: vec!["claude".into()],
            claude_dir: None,
            no_gpu: Some(true),
            no_docker: Some(true),
            no_display: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/project");
        let args = build_dry_run_args(
            &config,
            &project,
            (Path::new("/tmp/hosts"), Path::new("/etc/hosts")),
            None,
            Path::new("/tmp/empty"),
            false,
        )
        .unwrap();

        assert!(
            !args.iter().any(|a| a == "CLAUDE_CONFIG_DIR"),
            "CLAUDE_CONFIG_DIR must not appear when \
             claude_dir is None"
        );
    }
}
