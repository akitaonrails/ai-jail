// Landlock LSM filesystem and network restrictions for Linux.
//
// Applied before seccomp (but after bwrap sets up the mount
// namespace) to restrict which paths the sandboxed process can
// read, write, and execute — even if bwrap's bind mounts expose
// them.
//
// THREAT MODEL
//
// bwrap provides mount-namespace isolation: only explicitly bound
// paths are visible inside the sandbox. Landlock adds a second,
// independent filesystem restriction layer that:
//
//  1. Survives mount-namespace escapes — if an attacker finds a
//     way to remount or move_mount (blocked by seccomp, but
//     defense-in-depth), Landlock still prevents access to paths
//     outside the allowed set.
//  2. Enforces read-only where bwrap uses ro-bind — Landlock's
//     VFS-level checks catch writes even through /proc/self/fd
//     or mmap(PROT_WRITE) on a read-only bind mount.
//  3. Restricts network (V4, kernel ≥ 6.5) — in lockdown mode,
//     denies all TCP bind/connect as defense-in-depth alongside
//     bwrap's --unshare-net.
//
// Path selection philosophy:
//  - System dirs (/usr, /etc, /opt, …) are read-only: agents
//    need compilers and libraries but must not modify them.
//  - /proc is read-write: bwrap writes /proc/self/uid_map
//    during namespace setup. Individual /proc files are further
//    restricted by the kernel's own permission checks.
//  - /dev is read-write: bwrap creates a minimal private /dev
//    (null, zero, random, urandom, tty). GPU passthrough needs
//    write access to /dev/nvidia* and /dev/dri/*.
//  - /tmp is read-write: language runtimes and build tools
//    create temporary files here.
//  - $HOME is a tmpfs: Landlock allows writes because the real
//    home is hidden; individual dotdirs are bind-mounted ro/rw
//    by bwrap (Landlock defers to the stricter of the two).
//  - Project dir is read-write (normal) or read-only (lockdown):
//    the primary work directory for the AI agent.
//  - In lockdown mode, the allowed set is minimal: system ro,
//    /proc + /dev + /tmp rw, project ro. No $HOME, no dotdirs,
//    no Docker, no GPU, no display.

use crate::config::Config;
use crate::output;
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::{Path, PathBuf};

const ABI_VERSION: ABI = ABI::V3;
const ABI_NET: ABI = ABI::V4;

pub fn apply(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<(), String> {
    if !config.landlock_enabled() {
        if config.lockdown_enabled() {
            return Err("Landlock cannot be disabled in lockdown mode".into());
        }
        if verbose {
            output::verbose("Landlock: disabled by config/flag");
        }
        return Ok(());
    }

    match do_apply(config, project_dir, verbose) {
        Ok(status) => match status {
            RulesetStatus::FullyEnforced => {
                output::info("Landlock: fully enforced");
                Ok(())
            }
            RulesetStatus::PartiallyEnforced => {
                if config.lockdown_enabled() {
                    Err("Landlock: partially enforced in lockdown mode".into())
                } else {
                    output::info(
                        "Landlock: partially enforced \
                         (kernel lacks some features)",
                    );
                    Ok(())
                }
            }
            RulesetStatus::NotEnforced => {
                if config.lockdown_enabled() {
                    Err("Landlock: not enforced in lockdown mode \
                         (kernel too old, bwrap-only)"
                        .into())
                } else {
                    output::warn(
                        "Landlock: not enforced \
                         (kernel too old, bwrap-only)",
                    );
                    Ok(())
                }
            }
        },
        Err(e) => {
            if config.lockdown_enabled() {
                Err(format!("Landlock: failed to apply in lockdown mode ({e})"))
            } else {
                output::warn(&format!(
                    "Landlock: failed to apply ({e}), \
                     falling back to bwrap-only"
                ));
                Ok(())
            }
        }
    }
}

/// Collect paths that need read-only access and paths that
/// need read-write access, then build and apply the ruleset.
///
/// Two rulesets are stacked:
///  1. Filesystem (V3): ro/rw path rules. handle_access(all)
///     means any filesystem operation not covered by a rule is
///     denied — this is an allowlist, not a blocklist.
///  2. Network (V4): TCP bind/connect rules, lockdown only.
///     Stacked separately so V3-only kernels still get full
///     filesystem protection.
fn do_apply(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<RulesetStatus, landlock::RulesetError> {
    let access_all = AccessFs::from_all(ABI_VERSION);
    let access_read = AccessFs::from_read(ABI_VERSION);

    let (ro_paths, rw_paths) = if config.lockdown_enabled() {
        collect_lockdown_paths(project_dir, verbose)
    } else {
        collect_normal_paths(config, project_dir, verbose)
    };

    let status = Ruleset::default()
        .handle_access(access_all)?
        .create()?
        .add_rules(path_beneath_rules(ro_paths, access_read))?
        .add_rules(path_beneath_rules(rw_paths, access_all))?
        .restrict_self()?;

    // Stack a second ruleset for V4 network restrictions.
    // This is separate from the filesystem ruleset so V3
    // behavior is preserved on kernels without V4 support.
    apply_net_rules(config, verbose);

    Ok(status.ruleset)
}

/// Apply Landlock V4 (kernel ≥ 6.5) network restrictions.
///
/// In lockdown mode: handle BindTcp + ConnectTcp but add NO port
/// rules → all TCP is denied. This is defense-in-depth alongside
/// bwrap's --unshare-net (network namespace with no interfaces).
/// Even if an attacker escapes the network namespace, Landlock
/// still blocks TCP.
///
/// In normal mode: no network restrictions via Landlock. Agents
/// need outbound HTTP(S) for package downloads, API calls, etc.
///
/// Best-effort: silently skipped if kernel lacks V4 support.
fn apply_net_rules(config: &Config, verbose: bool) {
    if !config.lockdown_enabled() {
        // Normal mode: no network restrictions via Landlock.
        return;
    }

    let net_access = AccessNet::from_all(ABI_NET);
    if net_access.is_empty() {
        return;
    }

    // Handle net access but add NO NetPort rules → all TCP
    // bind/connect is denied (defense-in-depth alongside
    // bwrap's --unshare-net).
    match Ruleset::default()
        .handle_access(net_access)
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self())
    {
        Ok(status) => {
            if verbose {
                let enforced = match status.ruleset {
                    RulesetStatus::FullyEnforced => "fully enforced",
                    RulesetStatus::PartiallyEnforced => "partially enforced",
                    RulesetStatus::NotEnforced => "not enforced",
                };
                output::verbose(&format!(
                    "Landlock V4 net: {enforced} (lockdown)"
                ));
            }
        }
        Err(_) => {
            if verbose {
                output::verbose(
                    "Landlock V4 net: unavailable \
                     (kernel < 6.5, using --unshare-net only)",
                );
            }
        }
    }
}

/// Lockdown paths: minimal set for a read-only sandbox.
///
/// Only system libraries (ro), /proc + /dev + /tmp (rw), and the
/// project directory (ro) are accessible. This prevents the agent
/// from writing anywhere except /tmp, so it cannot persist
/// backdoors, modify configs, or exfiltrate data to disk.
fn collect_lockdown_paths(
    project_dir: &Path,
    verbose: bool,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    // Root filesystem: read-only (bwrap needs "/" to set up mount
    // namespaces via `mount --make-rslave /`).  This covers all
    // subdirectories, so individual system paths below are technically
    // redundant but kept for documentation.
    ro.push(PathBuf::from("/"));

    // System paths: read-only
    for p in &[
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/sys",
        "/run",
    ] {
        ro.push(PathBuf::from(p));
    }
    if verbose {
        output::verbose("Landlock lockdown: system ro");
    }

    // /proc: read-write — bwrap writes /proc/self/uid_map
    // during user-namespace setup. The kernel's own permission
    // model further restricts what /proc files are accessible
    // (e.g. /proc/kcore, /proc/sysrq-trigger are root-only).
    rw.push(PathBuf::from("/proc"));
    // /dev: read-write — bwrap creates a minimal private /dev
    // with null, zero, random, urandom, tty. Write access is
    // needed for PTY allocation and /dev/null output.
    rw.push(PathBuf::from("/dev"));

    // /tmp: read-write — the only user-writable location in
    // lockdown. Build tools, language runtimes, and package
    // managers all need scratch space for temp files.
    rw.push(PathBuf::from("/tmp"));
    if verbose {
        output::verbose("Landlock lockdown: /proc, /dev, /tmp rw");
    }

    // Project: read-only — the agent can read source code but
    // cannot modify it, write backdoors, or alter build configs.
    ro.push(project_dir.to_path_buf());
    if verbose {
        output::verbose(&format!(
            "Landlock lockdown: {} ro",
            project_dir.display()
        ));
    }

    (ro, rw)
}

/// Normal-mode paths: broader access for day-to-day development.
///
/// The agent can read system libraries, write to /tmp and the
/// project directory, and access home dotdirs needed by dev tools
/// (mise, npm, cargo, etc.). Optional passthrough for Docker,
/// GPU, and display sockets is controlled by config flags.
///
/// Security invariant: even with broad Landlock access, bwrap's
/// mount namespace hides paths not explicitly bind-mounted. The
/// two layers are complementary — Landlock prevents writes to
/// ro-bind-mounted paths, bwrap prevents access to unmounted
/// paths.
fn collect_normal_paths(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = super::home_dir();
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    // Root filesystem: read-only (bwrap needs "/" to set up mount
    // namespaces via `mount --make-rslave /`).  This covers all
    // subdirectories, so individual system paths below are technically
    // redundant but kept for documentation.
    ro.push(PathBuf::from("/"));

    // System paths: read-only
    for p in &[
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/sys",
        "/run",
    ] {
        ro.push(PathBuf::from(p));
    }
    if verbose {
        output::verbose("Landlock: system paths ro");
    }

    // Writable system paths
    // /proc must be rw: bwrap writes /proc/self/uid_map for
    // namespace setup; /proc/self/fd is used for fd passing.
    // /tmp must be rw: compilers, language runtimes, and
    // package managers create temp files and sockets here.
    // /dev must be rw: PTY allocation, /dev/null output, and
    // optional GPU device access.
    rw.push(PathBuf::from("/proc"));
    rw.push(PathBuf::from("/tmp"));
    rw.push(PathBuf::from("/dev"));
    if verbose {
        output::verbose("Landlock: /proc, /tmp, /dev rw");
    }

    // /dev/shm: shared memory for IPC. Some runtimes (Chrome/
    // Electron, Node.js workers) need this for shared memory
    // segments. Only added if it exists on the host.
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        rw.push(shm);
    }

    // Project directory: read-write — the agent's primary work
    // area. Must be writable so it can edit source, run builds,
    // and create output files.
    rw.push(project_dir.to_path_buf());
    if verbose {
        output::verbose(&format!("Landlock: {} rw", project_dir.display()));
    }

    // $HOME: read-write.  Inside the sandbox $HOME is a tmpfs,
    // so this allows tools (mise, gem, etc.) to create dirs.
    // bwrap ro-bind mounts for individual dotdirs still prevent
    // writes to those — filesystem permissions override Landlock.
    rw.push(home.clone());
    if verbose {
        output::verbose("Landlock: $HOME rw");
    }

    // Home dotdirs: classified as ro or rw based on DOTDIR_RW /
    // DOTDIR_DENY lists in sandbox/mod.rs. Dirs like .cargo,
    // .npm, .local/share are rw (caches, tool state). Dirs like
    // .ssh, .gnupg are denied entirely (never bind-mounted by
    // bwrap, so Landlock allowing them is moot — but we still
    // skip them for defense-in-depth). Everything else is ro.
    collect_home_paths(&home, &mut ro, &mut rw, verbose);

    // $HOME/.local: read-write — mise, pipx, and other tools
    // store binaries and state here.
    let dot_local = home.join(".local");
    if dot_local.is_dir() {
        if verbose {
            output::verbose("Landlock: ~/.local rw");
        }
        rw.push(dot_local);
    }

    // $HOME/.claude.json: read-write — Claude Code stores its
    // auth token and settings here. Must be writable so the
    // agent can update its own config during bootstrap.
    let claude_json = home.join(".claude.json");
    if claude_json.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.claude.json rw");
        }
        rw.push(claude_json);
    }

    // $HOME/.gitconfig: read-only — git needs user.name and
    // user.email for commits, but the agent must not modify
    // the user's git identity or credential helpers.
    let gitconfig = home.join(".gitconfig");
    if gitconfig.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.gitconfig ro");
        }
        ro.push(gitconfig);
    }

    // Extra user mounts: --rw-map and --ro-map from CLI/config.
    // These extend the sandbox with user-specified paths. Missing
    // paths are skipped with a warning (never crash on missing).
    for p in &config.rw_maps {
        if super::path_exists(p) {
            rw.push(p.clone());
        } else {
            output::warn(&format!(
                "Landlock: rw map {} not found, skipping",
                p.display()
            ));
        }
    }
    for p in &config.ro_maps {
        if super::path_exists(p) {
            ro.push(p.clone());
        } else {
            output::warn(&format!(
                "Landlock: ro map {} not found, skipping",
                p.display()
            ));
        }
    }
    if verbose && (!config.rw_maps.is_empty() || !config.ro_maps.is_empty()) {
        output::verbose("Landlock: extra maps");
    }

    // Docker socket: read-write — allows the agent to build and
    // run containers. This is a deliberate trust extension: the
    // Docker socket grants effective root on the host. Controlled
    // by --no-docker / config flag; auto-enabled if the socket
    // exists on the host.
    if config.docker_enabled() {
        let sock = PathBuf::from("/var/run/docker.sock");
        if super::path_exists(&sock) {
            if verbose {
                output::verbose("Landlock: docker socket rw");
            }
            rw.push(sock);
        }
    }

    // GPU devices: read-write — needed for CUDA/OpenCL/Vulkan
    // workloads. Grants access to /dev/nvidia* and /dev/dri/*.
    // Controlled by --no-gpu config flag.
    if config.gpu_enabled() {
        collect_gpu_paths(&mut rw, verbose);
    }

    // Display runtime: read-write — Wayland/X11 sockets live in
    // XDG_RUNTIME_DIR. Needed for GUI apps the agent might
    // launch (browsers for testing, display servers for
    // screenshots). Controlled by --no-display.
    if config.display_enabled() {
        if let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let xdg_path = PathBuf::from(&xdg_dir);
            if xdg_path.is_dir() {
                if verbose {
                    output::verbose(&format!(
                        "Landlock: XDG runtime {} rw",
                        xdg_path.display()
                    ));
                }
                rw.push(xdg_path);
            }
        }
    }

    // bwrap binary: read+execute — Landlock's from_read()
    // includes execute permission. Without this, the initial
    // bwrap exec would fail after Landlock restricts the
    // process.
    if let Ok(bwrap) = super::bwrap::bwrap_binary_path() {
        if verbose {
            output::verbose(&format!("Landlock: bwrap {} ro", bwrap.display()));
        }
        ro.push(bwrap);
    }

    (ro, rw)
}

/// Classify home dotdirs into read-only or read-write.
///
/// Sensitive dirs (DOTDIR_DENY: .ssh, .gnupg, etc.) are skipped
/// entirely — bwrap never bind-mounts them, so they are invisible
/// inside the sandbox. Writable dirs (DOTDIR_RW: .cargo, .npm,
/// .cache, etc.) are tool caches that agents legitimately modify.
/// Everything else defaults to read-only (safe to read config
/// from but not modify).
fn collect_home_paths(
    home: &Path,
    ro: &mut Vec<PathBuf>,
    rw: &mut Vec<PathBuf>,
    verbose: bool,
) {
    let entries = match std::fs::read_dir(home) {
        Ok(e) => e,
        Err(_) => return,
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
            continue;
        }

        if super::DOTDIR_RW.contains(&name_str.as_ref()) {
            if verbose {
                output::verbose(&format!("Landlock: ~/{name_str} rw"));
            }
            rw.push(path);
        } else {
            if verbose {
                output::verbose(&format!("Landlock: ~/{name_str} ro"));
            }
            ro.push(path);
        }
    }
}

/// Grant rw access to GPU device nodes.
///
/// Covers NVIDIA (/dev/nvidia0, /dev/nvidiactl, /dev/nvidia-uvm,
/// etc.) and DRI (/dev/dri/card*, /dev/dri/renderD*). These are
/// needed for CUDA, OpenCL, and Vulkan workloads that some AI
/// agents run (e.g. local model inference). Note: AMD RDNA GPUs
/// are accessed through DRI, not separate device nodes.
fn collect_gpu_paths(rw: &mut Vec<PathBuf>, verbose: bool) {
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("nvidia") {
                let p = entry.path();
                if verbose {
                    output::verbose(&format!(
                        "Landlock: gpu {} rw",
                        p.display()
                    ));
                }
                rw.push(p);
            }
        }
    }

    let dri = PathBuf::from("/dev/dri");
    if super::path_exists(&dri) {
        if verbose {
            output::verbose("Landlock: gpu /dev/dri rw");
        }
        rw.push(dri);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Tests mutating process-global env vars must hold this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn apply_disabled_is_noop() {
        let config = Config {
            no_landlock: Some(true),
            ..Config::default()
        };
        // Should return without error or panic
        assert!(apply(&config, Path::new("/tmp"), false).is_ok());
    }

    #[test]
    fn apply_enabled_does_not_panic() {
        let config = Config::default();
        assert!(config.landlock_enabled());
        // On kernels without landlock this prints a warning;
        // on kernels with landlock it enforces rules.
        // Either way it must not panic.
        assert!(apply(&config, Path::new("/tmp"), false).is_ok());
    }

    #[test]
    fn apply_lockdown_does_not_panic() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let _ = apply(&config, Path::new("/tmp"), false);
    }

    #[test]
    fn lockdown_rejects_disabled_landlock() {
        let config = Config {
            lockdown: Some(true),
            no_landlock: Some(true),
            ..Config::default()
        };
        assert!(apply(&config, Path::new("/tmp"), false).is_err());
    }

    #[test]
    fn lockdown_paths_project_is_readonly() {
        let project = PathBuf::from("/home/user/project");
        let (ro, rw) = collect_lockdown_paths(&project, false);
        assert!(ro.contains(&project), "project must be in ro list");
        assert!(!rw.contains(&project), "project must not be in rw list");
    }

    #[test]
    fn lockdown_paths_tmp_is_writable() {
        let (_, rw) = collect_lockdown_paths(Path::new("/tmp/proj"), false);
        assert!(rw.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn lockdown_paths_dev_is_writable() {
        let (ro, rw) = collect_lockdown_paths(Path::new("/tmp/proj"), false);
        assert!(rw.contains(&PathBuf::from("/dev")));
        assert!(!ro.contains(&PathBuf::from("/dev")));
    }

    #[test]
    fn normal_paths_project_is_writable() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-proj");
        let (_, rw) = collect_normal_paths(&config, &project, false);
        assert!(rw.contains(&project), "project must be in rw list");
    }

    #[test]
    fn normal_paths_root_is_readable() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            ..Config::default()
        };
        let (ro, _) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(
            ro.contains(&PathBuf::from("/")),
            "/ must be in ro list so bwrap can set up mount namespaces"
        );
    }

    #[test]
    fn lockdown_paths_root_is_readable() {
        let (ro, _) = collect_lockdown_paths(Path::new("/tmp/proj"), false);
        assert!(
            ro.contains(&PathBuf::from("/")),
            "/ must be in ro list so bwrap can set up mount namespaces"
        );
    }

    #[test]
    fn normal_paths_extra_maps_included() {
        let tmp_root = std::env::temp_dir()
            .join(format!("ai-jail-landlock-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_root);
        let rw_extra = tmp_root.join("extra-rw");
        let ro_extra = tmp_root.join("extra-ro");
        let _ = std::fs::create_dir_all(&rw_extra);
        let mut f = std::fs::File::create(&ro_extra).unwrap();
        let _ = f.write_all(b"x");

        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            rw_maps: vec![rw_extra.clone()],
            ro_maps: vec![ro_extra.clone()],
            ..Config::default()
        };
        let (ro, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(rw.contains(&rw_extra));
        assert!(ro.contains(&ro_extra));

        let _ = std::fs::remove_file(&ro_extra);
        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn normal_paths_missing_extra_maps_are_skipped() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            rw_maps: vec![PathBuf::from("/definitely/missing/rw")],
            ro_maps: vec![PathBuf::from("/definitely/missing/ro")],
            ..Config::default()
        };
        let (ro, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(!rw.contains(&PathBuf::from("/definitely/missing/rw")));
        assert!(!ro.contains(&PathBuf::from("/definitely/missing/ro")));
    }

    #[test]
    fn normal_paths_display_runtime_included_when_enabled() {
        let _env = ENV_LOCK.lock().unwrap();
        let tmp_root = std::env::temp_dir()
            .join(format!("ai-jail-landlock-xdg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_root);
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &tmp_root) };

        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            no_display: Some(false),
            ..Config::default()
        };
        let (_, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(rw.contains(&tmp_root));

        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn abi_net_returns_nonempty_access() {
        // Verify that our ABI_NET constant produces valid
        // AccessNet flags (BindTcp + ConnectTcp).
        let access = AccessNet::from_all(ABI_NET);
        assert!(!access.is_empty());
        assert!(access.contains(AccessNet::BindTcp));
        assert!(access.contains(AccessNet::ConnectTcp));
    }

    #[test]
    fn abi_v3_returns_empty_net_access() {
        // Confirm that V3 has no network access, justifying
        // the separate ABI_NET constant for stacked rulesets.
        let access = AccessNet::from_all(ABI::V3);
        assert!(access.is_empty());
    }

    #[test]
    fn apply_net_rules_normal_is_noop() {
        // Normal mode should not apply any net restrictions.
        let config = Config::default();
        assert!(!config.lockdown_enabled());
        // Must not panic or error
        apply_net_rules(&config, true);
    }

    #[test]
    fn apply_net_rules_lockdown_does_not_panic() {
        // On macOS/kernels without V4, this is best-effort.
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        // Must not panic regardless of kernel support
        apply_net_rules(&config, true);
    }
}
