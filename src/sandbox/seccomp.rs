// Seccomp BPF syscall filter for Linux.
//
// Applied inside the bwrap sandbox (after Landlock) to reduce the
// kernel attack surface. Uses a blocklist approach: dangerous syscalls
// are denied with EPERM, everything else is allowed.

use crate::config::Config;
use crate::output;
use seccompiler::{SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::convert::TryInto;

// Syscalls blocked in all modes. These have no legitimate use
// for AI coding agents and are common exploit primitives.
const DENY_ALWAYS: &[i64] = &[
    // Kernel module loading
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    // Kernel / system control
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_acct,
    // Swap / mount (bwrap already set up mounts)
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    // New mount API (Linux 5.2+) — bypasses classic mount()
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    // Process introspection
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    // Kernel exploit primitives
    libc::SYS_userfaultfd,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_personality,
    // io_uring — powerful async I/O that can bypass seccomp
    // filters on individual syscalls, enabling sandbox escapes
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // Namespace escape vectors
    libc::SYS_clone3,
    libc::SYS_open_by_handle_at,
    libc::SYS_unshare,
    libc::SYS_setns,
    // Time modification
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_adjtimex,
    // Keyring
    libc::SYS_add_key,
    libc::SYS_keyctl,
    libc::SYS_request_key,
    // Misc privileged
    libc::SYS_quotactl,
    libc::SYS_lookup_dcookie,
];

// Additional syscalls blocked only in lockdown mode.
const DENY_LOCKDOWN: &[i64] = &[
    // NUMA memory policy (info leak vectors)
    libc::SYS_mbind,
    libc::SYS_set_mempolicy,
    libc::SYS_move_pages,
    // Hostname changes (redundant with UTS ns)
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
];

// Architecture-specific syscalls (only exist on x86_64).
#[cfg(target_arch = "x86_64")]
const DENY_ARCH: &[i64] =
    &[libc::SYS_ioperm, libc::SYS_iopl, libc::SYS_modify_ldt];
#[cfg(not(target_arch = "x86_64"))]
const DENY_ARCH: &[i64] = &[];

/// Build and apply a seccomp BPF filter.
pub fn apply(config: &Config, verbose: bool) -> Result<(), String> {
    if !config.seccomp_enabled() {
        if verbose {
            output::verbose("Seccomp: disabled");
        }
        return Ok(());
    }

    let lockdown = config.lockdown_enabled();

    // Build the syscall → empty rules map (empty vec = match
    // unconditionally regardless of arguments).
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        BTreeMap::new();

    for &nr in DENY_ALWAYS {
        rules.insert(nr, vec![]);
    }
    for &nr in DENY_ARCH {
        rules.insert(nr, vec![]);
    }
    if lockdown {
        for &nr in DENY_LOCKDOWN {
            rules.insert(nr, vec![]);
        }
    }

    let arch: seccompiler::TargetArch =
        std::env::consts::ARCH.try_into().map_err(|_| {
            format!(
                "Seccomp: unsupported architecture: {}",
                std::env::consts::ARCH
            )
        })?;

    // Default action: allow (blocklist approach).
    // Match action: return EPERM for blocked syscalls.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| format!("Seccomp: failed to build filter: {e}"))?;

    let bpf: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| format!("Seccomp: failed to compile BPF: {e}"))?;

    seccompiler::apply_filter(&bpf)
        .map_err(|e| format!("Seccomp: failed to install filter: {e}"))?;

    if verbose {
        let count = DENY_ALWAYS.len()
            + DENY_ARCH.len()
            + if lockdown { DENY_LOCKDOWN.len() } else { 0 };
        output::verbose(&format!(
            "Seccomp: {} syscalls blocked ({})",
            count,
            if lockdown { "lockdown" } else { "normal" }
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_compiles_normal_mode() {
        let config = Config::default();
        // Just verify it doesn't error
        apply(&config, true).unwrap();
    }

    #[test]
    fn filter_compiles_lockdown_mode() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        apply(&config, true).unwrap();
    }

    #[test]
    fn filter_respects_disabled() {
        let config = Config {
            no_seccomp: Some(true),
            ..Config::default()
        };
        // Should be a no-op
        apply(&config, false).unwrap();
    }

    #[test]
    fn deny_lists_have_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &nr in DENY_ALWAYS
            .iter()
            .chain(DENY_ARCH.iter())
            .chain(DENY_LOCKDOWN.iter())
        {
            assert!(
                seen.insert(nr),
                "Duplicate syscall number {} in deny lists",
                nr
            );
        }
    }

    #[test]
    fn lockdown_blocks_more_than_normal() {
        assert!(!DENY_LOCKDOWN.is_empty());
    }
}
