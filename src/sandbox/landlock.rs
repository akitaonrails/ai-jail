use crate::config::Config;
use crate::output;
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, NetPort, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
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

/// Apply Landlock V4 network restrictions as a stacked ruleset.
/// In lockdown mode: deny all TCP bind/connect.
/// In normal mode: no restrictions (don't handle net access).
/// Best-effort: silently skipped if kernel < 6.5 (no V4).
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

    // /proc: read-write (bwrap writes /proc/self/uid_map)
    rw.push(PathBuf::from("/proc"));
    // /dev: read-write for null/tty compatibility inside sandbox's private /dev
    rw.push(PathBuf::from("/dev"));

    // /tmp: read-write (only writable user location)
    rw.push(PathBuf::from("/tmp"));
    if verbose {
        output::verbose("Landlock lockdown: /proc, /dev, /tmp rw");
    }

    // Project: read-only
    ro.push(project_dir.to_path_buf());
    if verbose {
        output::verbose(&format!(
            "Landlock lockdown: {} ro",
            project_dir.display()
        ));
    }

    (ro, rw)
}

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
    // /proc must be rw: bwrap writes /proc/self/uid_map for namespace setup
    rw.push(PathBuf::from("/proc"));
    rw.push(PathBuf::from("/tmp"));
    rw.push(PathBuf::from("/dev"));
    if verbose {
        output::verbose("Landlock: /proc, /tmp, /dev rw");
    }

    // /dev/shm
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        rw.push(shm);
    }

    // Project directory: read-write
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

    // Home dotdirs
    collect_home_paths(&home, &mut ro, &mut rw, verbose);

    // $HOME/.local: read-write
    let dot_local = home.join(".local");
    if dot_local.is_dir() {
        if verbose {
            output::verbose("Landlock: ~/.local rw");
        }
        rw.push(dot_local);
    }

    // $HOME/.claude.json: read-write
    let claude_json = home.join(".claude.json");
    if claude_json.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.claude.json rw");
        }
        rw.push(claude_json);
    }

    // $HOME/.gitconfig: read-only
    let gitconfig = home.join(".gitconfig");
    if gitconfig.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.gitconfig ro");
        }
        ro.push(gitconfig);
    }

    // Extra user mounts
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

    // Docker socket
    if config.docker_enabled() {
        let sock = PathBuf::from("/var/run/docker.sock");
        if super::path_exists(&sock) {
            if verbose {
                output::verbose("Landlock: docker socket rw");
            }
            rw.push(sock);
        }
    }

    // GPU devices
    if config.gpu_enabled() {
        collect_gpu_paths(&mut rw, verbose);
    }

    // Display runtime directory is bind-mounted by bwrap in normal mode.
    // Ensure Landlock allows writes there for Wayland/XDG sockets.
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

    // bwrap binary: read+execute (covered by from_read)
    if let Ok(bwrap) = super::bwrap::bwrap_binary_path() {
        if verbose {
            output::verbose(&format!("Landlock: bwrap {} ro", bwrap.display()));
        }
        ro.push(bwrap);
    }

    (ro, rw)
}

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
