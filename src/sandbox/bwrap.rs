use crate::config::Config;
use crate::output;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const WSL_DOCKER_DESKTOP_CLI_TOOLS: &str = "/mnt/wsl/docker-desktop/cli-tools";
const TAILSCALE_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

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

struct MountSet {
    base: Vec<Mount>,
    sys_masks: Vec<Mount>,
    home_dotfiles: Vec<Mount>,
    config_hide: Vec<Mount>,
    cache_hide: Vec<Mount>,
    local_overrides: Vec<Mount>,
    git_worktree: Vec<Mount>,
    gpu: Vec<Mount>,
    docker: Vec<Mount>,
    tailscale: Vec<Mount>,
    shm: Vec<Mount>,
    display: Vec<Mount>,
    display_env: Vec<(String, String)>,
    ssh_agent: Vec<Mount>,
    ssh_env: Vec<(String, String)>,
    claude_env: Vec<(String, String)>,
    pictures: Vec<Mount>,
    browser_state: Vec<Mount>,
    extra: Vec<Mount>,
    overlay: Vec<Mount>,
    project: Vec<Mount>,
    mask: Vec<Mount>,
    /// tmpfs that hides the on-host overlay upper/work storage from
    /// inside the sandbox. Applied last so it sits on top of the
    /// project mount that contains it.
    overlay_hide: Vec<Mount>,
}

impl MountSet {
    fn ordered_mounts(&self) -> [&[Mount]; 20] {
        [
            &self.base,
            &self.sys_masks,
            &self.gpu,
            &self.docker,
            &self.tailscale,
            &self.shm,
            &self.display,
            &self.home_dotfiles,
            &self.config_hide,
            &self.cache_hide,
            &self.local_overrides,
            &self.git_worktree,
            &self.ssh_agent,
            &self.pictures,
            &self.browser_state,
            &self.extra,
            &self.overlay,
            &self.project,
            &self.mask,
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
        allow_tcp_ports: &[u16],
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

        if lockdown {
            if allow_tcp_ports.is_empty() {
                args.push("--unshare-net".into());
            }
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
            for (key, val) in &self.display_env {
                args.push("--setenv".into());
                args.push(key.clone());
                args.push(val.clone());
            }
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

pub struct SandboxGuard {
    hosts_path: PathBuf,
    resolv_path: Option<PathBuf>,
    /// Where to mount the resolv temp file inside the sandbox.
    /// If /etc/resolv.conf is a symlink, this is the symlink target
    /// so the symlink inside /etc (from --ro-bind /etc) resolves.
    /// If it's a regular file, this is /etc/resolv.conf itself.
    resolv_dest: Option<PathBuf>,
    /// Empty tempfile used as the source for --mask file overlays.
    empty_path: PathBuf,
}

impl SandboxGuard {
    fn hosts_path(&self) -> &Path {
        &self.hosts_path
    }

    fn resolv_mount(&self) -> Option<(&Path, &Path)> {
        match (&self.resolv_path, &self.resolv_dest) {
            (Some(src), Some(dest)) => Some((src, dest)),
            _ => None,
        }
    }

    fn empty_path(&self) -> &Path {
        &self.empty_path
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.hosts_path);
        if let Some(ref p) = self.resolv_path {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_file(&self.empty_path);
    }
}

#[cfg(test)]
impl SandboxGuard {
    fn test_with_hosts(path: PathBuf) -> Self {
        SandboxGuard {
            hosts_path: path,
            resolv_path: None,
            resolv_dest: None,
            empty_path: PathBuf::from("/tmp/ai-jail-test-empty"),
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
    "zoxide",
    "crush",
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
const BWRAP_CANDIDATES: &[&str] =
    &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

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
        if p.is_absolute() && p.is_file() {
            return Ok(p);
        }
        override_error = Some(format!(
            "{BWRAP_ENV_VAR} is set to {} but it is not an absolute existing file",
            p.display()
        ));
    }

    for candidate in BWRAP_CANDIDATES {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Ok(p);
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

fn bwrap_program_for_exec() -> PathBuf {
    bwrap_binary_path().unwrap_or_else(|_| PathBuf::from("/usr/bin/bwrap"))
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
    let contents =
        b"127.0.0.1 localhost ai-sandbox\n::1       localhost ai-sandbox\n";

    file.write_all(contents)
        .map_err(|e| format!("Failed to create temp hosts file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync temp hosts file: {e}"))?;

    let (resolv_path, resolv_dest) = new_resolv_file();
    let empty_path = new_empty_file()?;

    Ok(SandboxGuard {
        hosts_path: path,
        resolv_path,
        resolv_dest,
        empty_path,
    })
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
fn new_resolv_file() -> (Option<PathBuf>, Option<PathBuf>) {
    let resolv = Path::new("/etc/resolv.conf");

    // canonicalize resolves all symlinks and normalizes ".." segments.
    // read_link only reads one level and can produce paths like
    // /etc/../run/systemd/resolve/stub-resolv.conf which may confuse
    // bwrap when creating intermediate mount-point directories.
    let dest = match std::fs::canonicalize(resolv) {
        Ok(canonical) => canonical,
        Err(_) => resolv.to_path_buf(),
    };

    let contents = match std::fs::read(resolv) {
        Ok(c) => c,
        Err(e) => {
            output::warn(&format!("Cannot read /etc/resolv.conf: {e}"));
            return (None, None);
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
                return (None, None);
            }
            let _ = f.sync_all();
            let _ = std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o600),
            );
            (Some(path), Some(dest))
        }
        Err(e) => {
            output::warn(&format!("Cannot create temp resolv.conf: {e}"));
            (None, None)
        }
    }
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
            token == "ts.net" || token.ends_with(".ts.net")
        })
    })
}

fn resolve_landlock_wrapper(
    config: &Config,
) -> Result<Option<PathBuf>, String> {
    if !config.landlock_enabled() {
        return Ok(None);
    }

    match self_binary_path() {
        Some(path) => Ok(Some(path)),
        None if config.lockdown_enabled() => Err(
            "Cannot resolve ai-jail binary for inner Landlock wrapper in lockdown mode"
                .into(),
        ),
        None => Ok(None),
    }
}

fn landlock_wrapper_args(config: &Config, verbose: bool) -> Vec<String> {
    let mut args = vec![
        LANDLOCK_WRAPPER_DEST.into(),
        "--landlock-exec".into(),
        "--landlock".into(),
    ];

    if config.lockdown_enabled() {
        args.push("--lockdown".into());
    }
    if config.private_home_enabled() {
        args.push("--private-home".into());
    }

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
        for path in &config.rw_maps {
            args.push("--rw-map".into());
            args.push(path.display().to_string());
        }
        for path in &config.ro_maps {
            args.push("--map".into());
            args.push(path.display().to_string());
        }
    }
    for path in &config.mask {
        args.push("--mask".into());
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
    let mount_set = discover_mounts(
        config,
        project_dir,
        guard.hosts_path(),
        guard.resolv_mount(),
        guard.empty_path(),
        verbose,
    );
    let lockdown = config.lockdown_enabled();
    let bwrap = bwrap_program_for_exec();
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
        config.allow_tcp_ports(),
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
        for arg in landlock_wrapper_args(config, verbose) {
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
    let args = build_dry_run_args(
        config,
        project_dir,
        guard.hosts_path(),
        guard.resolv_mount(),
        guard.empty_path(),
        verbose,
    )?;
    Ok(format_dry_run_args(&args))
}

fn build_dry_run_args(
    config: &Config,
    project_dir: &Path,
    hosts_file: &Path,
    resolv_mount: Option<(&Path, &Path)>,
    empty_path: &Path,
    verbose: bool,
) -> Result<Vec<String>, String> {
    let mount_set = discover_mounts(
        config,
        project_dir,
        hosts_file,
        resolv_mount,
        empty_path,
        verbose,
    );
    let lockdown = config.lockdown_enabled();
    let launch = super::build_launch_command(config);
    let mut args: Vec<String> =
        vec![bwrap_program_for_exec().display().to_string()];

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
        config.allow_tcp_ports(),
    ));

    args.push("--".into());

    if wrapper.is_some() {
        args.extend(landlock_wrapper_args(config, verbose));
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

fn discover_mounts(
    config: &Config,
    project_dir: &Path,
    hosts_file: &Path,
    resolv_mount: Option<(&Path, &Path)>,
    empty_path: &Path,
    verbose: bool,
) -> MountSet {
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
        discover_display(verbose)
    } else {
        (vec![], vec![])
    };
    let (ssh_agent_mount, ssh_env) =
        discover_ssh(config, lockdown, browser_mode, private_home, verbose);
    let claude_env = discover_claude_env(config);
    let mask_mounts =
        discover_mask_mounts(config, project_dir, empty_path, verbose);
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
        overlay_mounts(&config.overlay_maps, project_dir, verbose)
    };

    MountSet {
        base: discover_base(hosts_file, resolv_mount),
        sys_masks: discover_sys_masks(lockdown),
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
        shm: if lockdown { vec![] } else { discover_shm() },
        display: display_mounts,
        display_env,
        ssh_agent: ssh_agent_mount,
        ssh_env,
        claude_env,
        pictures: pictures_mount,
        browser_state: browser_state_mount,
        extra: if lockdown || browser_mode {
            vec![]
        } else {
            extra_mounts(&config.rw_maps, &config.ro_maps)
        },
        overlay: overlay_mounts_v,
        project: project_mount(project_dir, lockdown || browser_mode),
        mask: mask_mounts,
        overlay_hide: overlay_hide_v,
    }
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
    let mut effective: Vec<PathBuf> = config.mask.clone();
    if config.hide_config_enabled() {
        let local_config = project_dir.join(".ai-jail");
        let already_masked = config.mask.iter().any(|p| {
            let resolved = if p.is_absolute() {
                p.clone()
            } else {
                project_dir.join(p)
            };
            resolved == local_config
        });
        if !already_masked && super::path_exists(&local_config) {
            effective.push(local_config);
        }
    }
    let expanded = super::expand_mask_patterns(&effective, project_dir);
    build_mask_mounts(&expanded, project_dir, empty_path, verbose)
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
    let mut mounts = discover_home_dotfiles(
        private_home,
        &config.hide_dotdirs,
        exempt,
        verbose,
    );
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
            output::warn(&format!(
                "Mask: {} not found, skipping",
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

fn discover_base(
    hosts_file: &Path,
    resolv_mount: Option<(&Path, &Path)>,
) -> Vec<Mount> {
    let mut mounts = vec![Mount::RoBind {
        src: "/usr".into(),
        dest: "/usr".into(),
    }];

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

    // Resolve /etc/hosts symlink (e.g. on NixOS) so bwrap can bind-mount over it.
    let hosts_dest = std::fs::canonicalize("/etc/hosts")
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"));

    mounts.extend([
        Mount::RoBind {
            src: "/etc".into(),
            dest: "/etc".into(),
        },
        Mount::FileRoBind {
            src: hosts_file.to_path_buf(),
            dest: hosts_dest,
        },
        Mount::RoBind {
            src: "/opt".into(),
            dest: "/opt".into(),
        },
        Mount::RoBind {
            src: "/sys".into(),
            dest: "/sys".into(),
        },
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
        if !path.is_dir() {
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
    let claude_json = home.join(".claude.json");
    if claude_json.is_file() {
        mounts.push(Mount::Bind {
            src: claude_json.clone(),
            dest: claude_json,
        });
    }

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
    discover_docker_paths(
        Path::new(DOCKER_SOCKET),
        Path::new(WSL_DOCKER_DESKTOP_CLI_TOOLS),
    )
}

fn discover_docker_paths(sock: &Path, wsl_cli_tools: &Path) -> Vec<Mount> {
    let mut mounts = Vec::new();
    if super::path_exists(sock) {
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

fn discover_shm() -> Vec<Mount> {
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        vec![Mount::DevBind {
            src: shm.clone(),
            dest: shm,
        }]
    } else {
        vec![]
    }
}

fn discover_display(verbose: bool) -> (Vec<Mount>, Vec<(String, String)>) {
    let mut mounts = Vec::new();
    let mut env = Vec::new();

    let x11 = PathBuf::from("/tmp/.X11-unix");
    if x11.is_dir() {
        mounts.push(Mount::Bind {
            src: x11.clone(),
            dest: x11,
        });
    }

    if let Ok(display) = std::env::var("DISPLAY") {
        env.push(("DISPLAY".into(), display));
    }

    if let Ok(xauth) = std::env::var("XAUTHORITY") {
        let xauth_path = PathBuf::from(&xauth);
        if super::path_exists(&xauth_path) {
            mounts.push(Mount::RoBind {
                src: xauth_path.clone(),
                dest: xauth_path,
            });
        }
        env.push(("XAUTHORITY".into(), xauth));
    }

    if let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let xdg_path = PathBuf::from(&xdg_dir);
        if xdg_path.is_dir() {
            mounts.push(Mount::Bind {
                src: xdg_path.clone(),
                dest: xdg_path,
            });
            env.push(("XDG_RUNTIME_DIR".into(), xdg_dir));
            if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
                env.push(("WAYLAND_DISPLAY".into(), wayland));
            }
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

    let readonly = config.lockdown_enabled();
    paths
        .unique_paths()
        .into_iter()
        .map(|path| {
            if readonly {
                Mount::RoBind {
                    src: path.clone(),
                    dest: path,
                }
            } else {
                Mount::Bind {
                    src: path.clone(),
                    dest: path,
                }
            }
        })
        .collect()
}

fn extra_mounts(rw_maps: &[PathBuf], ro_maps: &[PathBuf]) -> Vec<Mount> {
    let mut mounts = Vec::new();

    // Apply ro-maps first, then rw-maps on top. This lets a
    // rw-subdirectory override an ro-parent, e.g.:
    //   --map ~/Projects --rw-map ~/Projects/ai-jail
    // makes ~/Projects read-only except the ai-jail subdir.
    for path in ro_maps {
        if super::path_exists(path) {
            mounts.push(Mount::RoBind {
                src: path.clone(),
                dest: path.clone(),
            });
        } else {
            output::warn(&format!(
                "Path {} not found, skipping.",
                path.display()
            ));
        }
    }

    for path in rw_maps {
        if super::path_exists(path) {
            mounts.push(Mount::Bind {
                src: path.clone(),
                dest: path.clone(),
            });
        } else {
            output::warn(&format!(
                "Path {} not found, skipping.",
                path.display()
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
) -> (Vec<Mount>, Vec<Mount>) {
    if overlay_maps.is_empty() {
        return (vec![], vec![]);
    }
    let storage_root = project_dir.join(OVERLAY_STORAGE_DIR);
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
        if let Err(e) = std::fs::create_dir_all(&upper)
            .and_then(|_| std::fs::create_dir_all(&work))
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
        return (vec![], vec![]);
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
    (mounts, hide)
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
    fn docker_discovery_mounts_socket_and_wsl_cli_tools() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-docker-wsl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sock = root.join("docker.sock");
        let cli_tools = root.join("cli-tools");
        std::fs::create_dir_all(&cli_tools).unwrap();
        std::fs::File::create(&sock).unwrap();

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
        std::fs::File::create(&sock).unwrap();

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
            guard.hosts_path(),
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

        let config = minimal_test_config();
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
        // Use /usr and /usr/bin which always exist. The order
        // of returned mounts must be: ro first, rw after — so a
        // rw subdirectory can overlay its ro parent.
        let ro = vec![PathBuf::from("/usr")];
        let rw = vec![PathBuf::from("/usr/bin")];
        let mounts = extra_mounts(&rw, &ro);
        assert_eq!(mounts.len(), 2);
        match &mounts[0] {
            Mount::RoBind { src, .. } => {
                assert_eq!(src, &PathBuf::from("/usr"));
            }
            _ => panic!("first mount must be RoBind of the ro-parent"),
        }
        match &mounts[1] {
            Mount::Bind { src, .. } => {
                assert_eq!(src, &PathBuf::from("/usr/bin"));
            }
            _ => panic!("second mount must be Bind of the rw-child"),
        }
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");

        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            !args.contains(&"--unshare-net".to_string()),
            "browser profiles keep network access for browsing"
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
            guard.hosts_path(),
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
        assert!(!args.contains(&"--unshare-net".to_string()));

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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            overlay_mounts(std::slice::from_ref(&source), &project, false);

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
        let (mounts, _hide) = overlay_mounts(&maps, &project, false);
        assert_eq!(mounts.len(), 1);
        let _ = std::fs::remove_dir_all(project.parent().unwrap());
    }

    #[test]
    fn overlay_mounts_skips_missing_source() {
        let (project, _source) = overlay_test_dirs("missing");
        let missing = project.join("does-not-exist");
        let (mounts, hide) =
            overlay_mounts(std::slice::from_ref(&missing), &project, false);
        assert!(mounts.is_empty());
        assert!(hide.is_empty());
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
        let config = minimal_test_config();
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_path(),
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
            w[0] == "--bind"
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
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));

        let args = build_dry_run_args(
            &config,
            &fixture.project_dir,
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
            guard.hosts_path(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "lockdown with allowed ports must skip --unshare-net"
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
            guard.hosts_path(),
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

        let wrapper_args = landlock_wrapper_args(&config, false);
        let port_args: Vec<_> = wrapper_args
            .windows(2)
            .filter(|w| w[0] == "--allow-tcp-port")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(port_args, vec!["32000", "8080"]);
    }

    #[test]
    fn browser_wrapper_skips_extra_maps() {
        let mut config = minimal_test_config();
        config.command = vec!["chromium".into()];
        config.browser_profile = Some("hard".into());
        config.rw_maps = vec![PathBuf::from("/tmp/browser-rw")];
        config.ro_maps = vec![PathBuf::from("/tmp/browser-ro")];

        let wrapper_args = landlock_wrapper_args(&config, false);

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
    fn regression_bwrap_exec_program_is_absolute() {
        let p = bwrap_program_for_exec();
        assert!(p.is_absolute(), "bwrap exec path must be absolute");
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("bwrap"));
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
            guard.hosts_path(),
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
            guard.hosts_path(),
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
    fn no_landlock_wrapper_when_disabled() {
        let mut config = minimal_test_config();
        config.no_landlock = Some(true);
        let guard =
            SandboxGuard::test_with_hosts(PathBuf::from("/tmp/test-hosts"));
        let project = PathBuf::from("/home/user/project");
        let args = build_dry_run_args(
            &config,
            &project,
            guard.hosts_path(),
            guard.resolv_mount(),
            guard.empty_path(),
            false,
        )
        .unwrap();

        assert!(
            !args.contains(&"--landlock-exec".to_string()),
            "dry-run must NOT include --landlock-exec when disabled"
        );
    }

    #[test]
    fn resolv_bind_after_run_tmpfs() {
        let mounts = discover_base(
            Path::new("/tmp/test-hosts"),
            Some((
                Path::new("/tmp/test-resolv"),
                Path::new("/run/resolvconf/resolv.conf"),
            )),
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
    fn bwrap_bin_env_override_is_used() {
        let _env = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir()
            .join(format!("ai-jail-bwrap.{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let bwrap = tmp.join("bwrap");
        std::fs::write(&bwrap, b"#!/bin/sh\n").unwrap();

        let _bwrap_bin = EnvVarGuard::set(BWRAP_ENV_VAR, bwrap.as_os_str());
        let selected = bwrap_program_for_exec();

        assert_eq!(selected, bwrap);
        let _ = std::fs::remove_file(&bwrap);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn bwrap_bin_env_override_invalid_path_falls_back() {
        let _env = ENV_LOCK.lock().unwrap();
        let _bwrap_bin =
            EnvVarGuard::set(BWRAP_ENV_VAR, "/definitely/not/a/real/bwrap");
        let selected = bwrap_program_for_exec();

        assert!(selected.is_absolute());
        assert_eq!(
            selected.file_name().and_then(|s| s.to_str()),
            Some("bwrap")
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
            Path::new("/tmp/hosts"),
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
            Path::new("/tmp/hosts"),
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
