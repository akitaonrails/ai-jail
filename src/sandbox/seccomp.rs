// Seccomp BPF syscall filter for Linux.
//
// Applied inside the bwrap sandbox (after Landlock) to reduce the
// kernel attack surface. Uses a blocklist approach: dangerous syscalls
// are denied with EPERM, everything else is allowed.
//
// THREAT MODEL
//
// AI coding agents run untrusted code (tool output, generated scripts,
// fetched packages). Even inside a bwrap namespace + Landlock VFS
// sandbox, the kernel syscall surface remains exposed. Seccomp is
// the third defense layer — it removes syscalls that:
//
//  1. Allow direct kernel manipulation (module loading, kexec,
//     reboot) — an agent should never need these.
//  2. Enable sandbox escape (mount, unshare, setns, clone3,
//     open_by_handle_at, io_uring) — these can break out of
//     namespace/Landlock/seccomp boundaries.
//  3. Provide exploit primitives (userfaultfd, bpf,
//     perf_event_open, ptrace) — commonly used in kernel
//     exploits to win race conditions or inspect memory.
//  4. Leak host information (kcmp, personality, lookup_dcookie)
//     — useful for fingerprinting or KASLR bypass.
//
// The blocklist approach (allow-by-default) was chosen over an
// allowlist because AI agents invoke arbitrary compilers, language
// runtimes, and tools whose syscall needs are unpredictable.
// Blocking only known-dangerous syscalls gives the best balance
// of security and compatibility.

use crate::config::Config;
use crate::output;
use seccompiler::{SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::convert::TryInto;

// Syscalls blocked in all modes. These have no legitimate use
// for AI coding agents and are common exploit primitives.
const DENY_ALWAYS: &[i64] = &[
    // -- Kernel module loading --
    // Threat: a compromised agent could load a malicious kernel
    // module to gain ring-0 execution, escaping all userspace
    // sandboxing (namespaces, Landlock, seccomp itself).
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    // -- Kernel / system control --
    // Threat: kexec replaces the running kernel, reboot halts the
    // host, acct enables process accounting to an arbitrary file.
    // None are needed by build tools or language runtimes.
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_acct,
    // -- Classic mount API --
    // Threat: mount/umount/pivot_root could rearrange the
    // filesystem namespace that bwrap set up, re-exposing host
    // paths the sandbox intentionally hides. Swap calls could
    // exhaust host memory or read swapped-out secrets.
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    // -- New mount API (Linux 5.2+) --
    // Threat: fsopen/fsconfig/fsmount/fspick/open_tree/move_mount
    // and mount_setattr provide an fd-based mount interface that
    // bypasses the classic mount() blocked above. Without blocking
    // these, an attacker could mount a new filesystem or move
    // existing mounts to escape bwrap's layout.
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    // -- Process introspection --
    // Threat: ptrace allows reading/writing another process's
    // memory and registers — an agent could attach to the parent
    // ai-jail process or other sandbox peers to steal credentials
    // or inject code. process_vm_readv/writev provide the same
    // cross-process memory access without PTRACE_ATTACH. kcmp
    // compares kernel objects between processes, leaking kernel
    // addresses useful for KASLR bypass.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    // -- Kernel exploit primitives --
    // Threat: userfaultfd is used in nearly every modern kernel
    // use-after-free exploit to win TOCTOU races by stalling page
    // faults. bpf loads code into the kernel (eBPF programs) that
    // could read arbitrary kernel memory. perf_event_open exposes
    // hardware performance counters that can side-channel leak
    // data (e.g. Spectre-style). personality changes the process
    // execution domain; some modes (READ_IMPLIES_EXEC) weaken
    // W^X protections.
    libc::SYS_userfaultfd,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_personality,
    // -- io_uring --
    // Threat: io_uring submits syscalls asynchronously from
    // kernel context, meaning individual blocked syscalls (like
    // openat on a restricted path) can be issued through
    // io_uring_enter without hitting seccomp filters on those
    // inner operations. This is a well-known seccomp bypass
    // (CVE-2021-41073 and related issues). AI agents have no
    // need for io_uring's async I/O — standard read/write and
    // epoll are sufficient.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // -- Namespace escape vectors --
    // Threat: clone3 is the extensible clone variant whose
    // struct-based arguments are harder to filter by seccomp
    // (argument inspection) and can create new namespaces.
    // open_by_handle_at converts a file handle (obtainable via
    // name_to_handle_at) back to an fd, bypassing path-based
    // access controls — the classic Docker/container escape
    // (CVE-2015-1335). unshare/setns create or join namespaces,
    // potentially escaping the bwrap-created sandbox.
    libc::SYS_clone3,
    libc::SYS_open_by_handle_at,
    libc::SYS_unshare,
    libc::SYS_setns,
    // -- Time modification --
    // Threat: modifying the system clock can break TLS
    // certificate validation (replay attacks), corrupt
    // timestamps in build artifacts, or interfere with
    // time-based security mechanisms on the host.
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_adjtimex,
    // -- Kernel keyring --
    // Threat: the kernel keyring stores encryption keys, auth
    // tokens, and other secrets. An agent could read keys
    // belonging to other processes (same UID) or add poisoned
    // keys that other programs trust.
    libc::SYS_add_key,
    libc::SYS_keyctl,
    libc::SYS_request_key,
    // -- Misc privileged --
    // Threat: quotactl manipulates filesystem quotas (DoS
    // vector). lookup_dcookie translates kernel dcache cookies
    // to pathnames, leaking filesystem layout information.
    libc::SYS_quotactl,
    libc::SYS_lookup_dcookie,
];

// Additional syscalls blocked only in lockdown mode.
// These are lower-risk but provide information or control
// that a fully locked-down agent should not have.
const DENY_LOCKDOWN: &[i64] = &[
    // Threat: NUMA topology queries (mbind, set_mempolicy,
    // move_pages) reveal physical memory layout, which aids
    // side-channel attacks (Rowhammer, cache-timing). Normal
    // mode allows them because some runtimes (JVM, Go) use
    // NUMA-aware allocation legitimately.
    libc::SYS_mbind,
    libc::SYS_set_mempolicy,
    libc::SYS_move_pages,
    // Threat: changing the hostname/domainname inside the
    // sandbox is harmless with UTS namespace isolation (which
    // lockdown enables), but blocking these provides defense-
    // in-depth if UTS unshare fails or is bypassed.
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
];

// Architecture-specific syscalls (only exist on x86_64).
// Threat: ioperm/iopl grant direct I/O port access to hardware
// — a ring-0 equivalent that bypasses all OS isolation.
// modify_ldt changes the local descriptor table, enabling
// segmentation tricks used in some kernel exploits.
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
