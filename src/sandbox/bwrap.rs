use crate::config::Config;
use crate::output;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
enum Mount {
    RoBind { src: PathBuf, dest: PathBuf },
    Bind { src: PathBuf, dest: PathBuf },
    DevBind { src: PathBuf, dest: PathBuf },
    Dev { dest: PathBuf },
    Proc { dest: PathBuf },
    Tmpfs { dest: PathBuf },
    Symlink { src: String, dest: PathBuf },
    FileRoBind { src: PathBuf, dest: PathBuf },
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
        }
    }
}

struct MountSet {
    base: Vec<Mount>,
    home_dotfiles: Vec<Mount>,
    config_hide: Vec<Mount>,
    cache_hide: Vec<Mount>,
    local_overrides: Vec<Mount>,
    gpu: Vec<Mount>,
    docker: Vec<Mount>,
    shm: Vec<Mount>,
    display: Vec<Mount>,
    display_env: Vec<(String, String)>,
    extra: Vec<Mount>,
    project: Vec<Mount>,
}

impl MountSet {
    fn ordered_mounts(&self) -> [&[Mount]; 11] {
        [
            &self.base,
            &self.gpu,
            &self.shm,
            &self.docker,
            &self.display,
            &self.home_dotfiles,
            &self.config_hide,
            &self.cache_hide,
            &self.local_overrides,
            &self.extra,
            &self.project,
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
    ) -> Vec<String> {
        let use_new_session = should_use_new_session(lockdown);
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

        if use_new_session {
            args.push("--new-session".into());
        }

        if lockdown {
            args.push("--unshare-net".into());
            args.push("--clearenv".into());

            args.extend([
                "--setenv".into(),
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    .into(),
            ]);
            args.extend([
                "--setenv".into(),
                "HOME".into(),
                super::home_dir().display().to_string(),
            ]);
            if let Ok(term) = std::env::var("TERM") {
                args.extend(["--setenv".into(), "TERM".into(), term]);
            }
        } else {
            for (key, val) in &self.display_env {
                args.push("--setenv".into());
                args.push(key.clone());
                args.push(val.clone());
            }
        }

        args.extend([
            "--setenv".into(),
            "PS1".into(),
            "(jail) \\w \\$ ".into(),
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
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.hosts_path);
        if let Some(ref p) = self.resolv_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
impl SandboxGuard {
    fn test_with_hosts(path: PathBuf) -> Self {
        SandboxGuard {
            hosts_path: path,
            resolv_path: None,
            resolv_dest: None,
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

fn should_use_new_session(lockdown: bool) -> bool {
    if lockdown {
        return true;
    }
    !std::io::stdin().is_terminal()
}

fn bwrap_program_for_exec() -> PathBuf {
    bwrap_binary_path().unwrap_or_else(|_| PathBuf::from("/usr/bin/bwrap"))
}

fn new_hosts_file() -> Result<(PathBuf, std::fs::File), String> {
    let tmp = std::env::temp_dir();

    for attempt in 0..128_u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
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
                return Err(format!("Failed to create temp hosts file: {e}"))
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

    Ok(SandboxGuard {
        hosts_path: path,
        resolv_path,
        resolv_dest,
    })
}

/// Create a temp copy of /etc/resolv.conf and determine where to
/// mount it inside the sandbox.
///
/// If /etc/resolv.conf is a symlink (common on WSL and systemd-resolved),
/// we mount the temp file at the symlink *target* so the symlink inside
/// the sandbox (inherited from --ro-bind /etc) resolves correctly.
/// If it is a regular file, we mount directly over /etc/resolv.conf.
fn new_resolv_file() -> (Option<PathBuf>, Option<PathBuf>) {
    let resolv = Path::new("/etc/resolv.conf");

    // Determine where to mount inside the sandbox
    let dest = match std::fs::read_link(resolv) {
        Ok(target) => {
            // Symlink: mount at the target path so the symlink works
            if target.is_absolute() {
                target
            } else {
                PathBuf::from("/etc").join(target)
            }
        }
        Err(_) => {
            // Regular file: mount directly over /etc/resolv.conf
            resolv.to_path_buf()
        }
    };

    let contents = match std::fs::read(resolv) {
        Ok(c) => c,
        Err(e) => {
            output::warn(&format!("Cannot read /etc/resolv.conf: {e}"));
            return (None, None);
        }
    };

    let tmp = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
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

pub fn build(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Command {
    let mount_set = discover_mounts(
        config,
        project_dir,
        guard.hosts_path(),
        guard.resolv_mount(),
        verbose,
    );
    let lockdown = config.lockdown_enabled();
    let bwrap = bwrap_program_for_exec();
    let launch = super::build_launch_command(config);

    // Landlock wrapper: bind-mount ai-jail into /tmp inside the
    // sandbox so it can apply Landlock after bwrap namespace setup.
    let wrapper = if config.landlock_enabled() {
        self_binary_path()
    } else {
        None
    };

    let mut cmd = Command::new(bwrap);

    for arg in mount_set.all_mount_args() {
        cmd.arg(arg);
    }

    // Self binary mount for Landlock wrapper (after all other
    // mounts so /tmp tmpfs already exists)
    if wrapper.is_some() {
        let m = Mount::FileRoBind {
            src: wrapper.clone().unwrap(),
            dest: PathBuf::from(LANDLOCK_WRAPPER_DEST),
        };
        for arg in m.to_args() {
            cmd.arg(arg);
        }
    }

    for arg in mount_set.isolation_args(project_dir, lockdown) {
        cmd.arg(arg);
    }

    cmd.arg("--");

    if wrapper.is_some() {
        cmd.arg(LANDLOCK_WRAPPER_DEST);
        cmd.arg("--landlock-exec");
        if lockdown {
            cmd.arg("--lockdown");
        }
        if verbose {
            cmd.arg("--verbose");
        }
        cmd.arg("--");
    }

    cmd.arg(&launch.program);
    for arg in &launch.args {
        cmd.arg(arg);
    }

    cmd
}

pub fn dry_run(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> String {
    let args = build_dry_run_args(
        config,
        project_dir,
        guard.hosts_path(),
        guard.resolv_mount(),
        verbose,
    );
    format_dry_run_args(&args)
}

fn build_dry_run_args(
    config: &Config,
    project_dir: &Path,
    hosts_file: &Path,
    resolv_mount: Option<(&Path, &Path)>,
    verbose: bool,
) -> Vec<String> {
    let mount_set =
        discover_mounts(config, project_dir, hosts_file, resolv_mount, verbose);
    let lockdown = config.lockdown_enabled();
    let launch = super::build_launch_command(config);
    let mut args: Vec<String> =
        vec![bwrap_program_for_exec().display().to_string()];

    args.extend(mount_set.all_mount_args());

    // Self binary mount for Landlock wrapper
    let wrapper = if config.landlock_enabled() {
        self_binary_path()
    } else {
        None
    };
    if let Some(ref self_bin) = wrapper {
        let m = Mount::FileRoBind {
            src: self_bin.clone(),
            dest: PathBuf::from(LANDLOCK_WRAPPER_DEST),
        };
        args.extend(m.to_args());
    }

    args.extend(mount_set.isolation_args(project_dir, lockdown));

    args.push("--".into());

    if wrapper.is_some() {
        args.push(LANDLOCK_WRAPPER_DEST.into());
        args.push("--landlock-exec".into());
        if lockdown {
            args.push("--lockdown".into());
        }
        if verbose {
            args.push("--verbose".into());
        }
        args.push("--".into());
    }

    args.push(launch.program);
    args.extend(launch.args);

    args
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

fn format_dry_run_args(args: &[String]) -> String {
    if args.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&quote_arg(&args[0]));
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
                out.push_str(&quote_arg(val));
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
                out.push_str(&quote_arg(&args[j]));
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
            out.push_str(&quote_arg(val));
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
    verbose: bool,
) -> MountSet {
    let lockdown = config.lockdown_enabled();
    let enable_gpu = !lockdown && config.gpu_enabled();
    let enable_docker = !lockdown && config.docker_enabled();
    let enable_display = !lockdown && config.display_enabled();

    let (display_mounts, display_env) = if enable_display {
        discover_display(verbose)
    } else {
        (vec![], vec![])
    };

    MountSet {
        base: discover_base(hosts_file, resolv_mount),
        home_dotfiles: discover_home_dotfiles(lockdown, verbose),
        config_hide: if lockdown {
            vec![]
        } else {
            discover_subdir_hide(".config", CONFIG_DENY)
        },
        cache_hide: if lockdown {
            vec![]
        } else {
            discover_subdir_hide(".cache", CACHE_DENY)
        },
        local_overrides: if lockdown {
            vec![]
        } else {
            discover_local_overrides()
        },
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
        shm: if lockdown { vec![] } else { discover_shm() },
        display: display_mounts,
        display_env,
        extra: if lockdown {
            vec![]
        } else {
            extra_mounts(&config.rw_maps, &config.ro_maps)
        },
        project: project_mount(project_dir, lockdown),
    }
}

fn discover_base(
    hosts_file: &Path,
    resolv_mount: Option<(&Path, &Path)>,
) -> Vec<Mount> {
    let mut mounts = vec![
        Mount::RoBind {
            src: "/usr".into(),
            dest: "/usr".into(),
        },
        Mount::Symlink {
            src: "usr/bin".into(),
            dest: "/bin".into(),
        },
        Mount::Symlink {
            src: "usr/lib".into(),
            dest: "/lib".into(),
        },
        Mount::Symlink {
            src: "usr/lib64".into(),
            dest: "/lib64".into(),
        },
        Mount::RoBind {
            src: "/etc".into(),
            dest: "/etc".into(),
        },
        Mount::FileRoBind {
            src: hosts_file.to_path_buf(),
            dest: "/etc/hosts".into(),
        },
    ];

    if let Some((src, dest)) = resolv_mount {
        mounts.push(Mount::FileRoBind {
            src: src.to_path_buf(),
            dest: dest.to_path_buf(),
        });
    }

    mounts.extend([
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

    mounts
}

fn discover_home_dotfiles(lockdown: bool, verbose: bool) -> Vec<Mount> {
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

        if super::DOTDIR_DENY.contains(&name_str.as_ref()) {
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

    let gitconfig = home.join(".gitconfig");
    if gitconfig.is_file() {
        mounts.push(Mount::RoBind {
            src: gitconfig.clone(),
            dest: gitconfig,
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
    let sock = PathBuf::from("/var/run/docker.sock");
    if super::path_exists(&sock) {
        vec![Mount::Bind {
            src: sock.clone(),
            dest: sock,
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

fn extra_mounts(rw_maps: &[PathBuf], ro_maps: &[PathBuf]) -> Vec<Mount> {
    let mut mounts = Vec::new();

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

    mounts
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

    // Tests that mutate process-global env vars must hold this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            false,
        );
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
            false,
        );

        assert!(args.contains(&"--die-with-parent".to_string()));
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert_eq!(
            args.contains(&"--new-session".to_string()),
            should_use_new_session(false),
            "new-session presence should follow tty/lockdown policy",
        );
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
            false,
        );
        let has_project_ro = args.windows(3).any(|w| {
            w[0] == "--ro-bind"
                && w[1] == "/home/user/project"
                && w[2] == "/home/user/project"
        });
        assert!(has_project_ro);
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
            false,
        );

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
            false,
        );

        let has_tmp_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/tmp" && w[2] == "/tmp");
        assert!(!has_tmp_bind);
    }

    #[test]
    fn lockdown_skips_host_home_dotfiles() {
        let mounts = discover_home_dotfiles(true, false);
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
    fn lockdown_always_uses_new_session() {
        assert!(should_use_new_session(true));
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
            false,
        );
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
            false,
        );

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
            false,
        );

        assert!(
            !args.contains(&"--landlock-exec".to_string()),
            "dry-run must NOT include --landlock-exec when disabled"
        );
    }

    #[test]
    fn bwrap_bin_env_override_is_used() {
        let _env = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir()
            .join(format!("ai-jail-bwrap.{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let bwrap = tmp.join("bwrap");
        std::fs::write(&bwrap, b"#!/bin/sh\n").unwrap();

        unsafe { std::env::set_var(BWRAP_ENV_VAR, &bwrap) };
        let selected = bwrap_program_for_exec();
        unsafe { std::env::remove_var(BWRAP_ENV_VAR) };

        assert_eq!(selected, bwrap);
        let _ = std::fs::remove_file(&bwrap);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn bwrap_bin_env_override_invalid_path_falls_back() {
        let _env = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(BWRAP_ENV_VAR, "/definitely/not/a/real/bwrap")
        };
        let selected = bwrap_program_for_exec();
        unsafe { std::env::remove_var(BWRAP_ENV_VAR) };

        assert!(selected.is_absolute());
        assert_eq!(
            selected.file_name().and_then(|s| s.to_str()),
            Some("bwrap")
        );
    }
}
