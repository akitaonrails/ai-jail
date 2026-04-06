use crate::config::Config;
use crate::output;
use nix::sys::resource::{Resource, getrlimit, setrlimit};

// Normal mode: generous limits that prevent abuse
// without breaking build tools or AI agents.
#[cfg(target_os = "linux")]
const NPROC_NORMAL: u64 = 4096;
const NOFILE_NORMAL: u64 = 65536;

// Lockdown mode: tighter limits for untrusted workloads.
#[cfg(target_os = "linux")]
const NPROC_LOCKDOWN: u64 = 1024;
const NOFILE_LOCKDOWN: u64 = 4096;

struct Limit {
    resource: Resource,
    soft: u64,
    name: &'static str,
}

fn limits_for(config: &Config) -> Vec<Limit> {
    let lockdown = config.lockdown_enabled();
    #[allow(unused_mut)]
    let mut limits = vec![
        Limit {
            resource: Resource::RLIMIT_NOFILE,
            soft: if lockdown {
                NOFILE_LOCKDOWN
            } else {
                NOFILE_NORMAL
            },
            name: "NOFILE",
        },
        Limit {
            resource: Resource::RLIMIT_CORE,
            soft: 0,
            name: "CORE",
        },
    ];

    limits
}

/// Apply resource limits before spawning the sandbox.
/// Limits are inherited across fork+exec.
pub fn apply(config: &Config, verbose: bool) {
    if !config.rlimits_enabled() {
        if verbose {
            output::verbose("Resource limits: disabled");
        }
        return;
    }

    for lim in limits_for(config) {
        let Ok((_, hard)) = getrlimit(lim.resource) else {
            output::warn(&format!(
                "Failed to read RLIMIT_{}, skipping",
                lim.name
            ));
            continue;
        };

        // Never exceed the current hard limit.
        let effective = lim.soft.min(hard);

        if let Err(e) = setrlimit(lim.resource, effective, hard) {
            output::warn(&format!("Failed to set RLIMIT_{}: {e}", lim.name));
        } else if verbose {
            output::verbose(&format!(
                "RLIMIT_{}: {} (hard: {})",
                lim.name, effective, hard
            ));
        }
    }
}

/// Apply RLIMIT_NPROC in the current process. Must be called inside
/// the bwrap sandbox (from --landlock-exec), not on the bwrap parent:
/// bwrap uses clone() for namespace creation, which counts against
/// RLIMIT_NPROC system-wide. Applying the limit before bwrap's clone()
/// causes EAGAIN when other user processes (e.g. Chrome) are running.
#[cfg(target_os = "linux")]
pub fn apply_nproc(config: &Config, verbose: bool) {
    if !config.rlimits_enabled() {
        return;
    }
    let soft = if config.lockdown_enabled() {
        NPROC_LOCKDOWN
    } else {
        NPROC_NORMAL
    };
    let Ok((_, hard)) = getrlimit(Resource::RLIMIT_NPROC) else {
        return;
    };
    let effective = soft.min(hard);
    if let Err(e) = setrlimit(Resource::RLIMIT_NPROC, effective, hard) {
        output::warn(&format!("Failed to set RLIMIT_NPROC: {e}"));
    } else if verbose {
        output::verbose(&format!(
            "RLIMIT_NPROC: {} (hard: {})",
            effective, hard
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_sets_core_to_zero() {
        let config = Config::default();
        apply(&config, false);

        let (soft, _) = getrlimit(Resource::RLIMIT_CORE).unwrap();
        assert_eq!(soft, 0);
    }

    #[test]
    fn apply_respects_disabled() {
        let config = Config {
            no_rlimits: Some(true),
            ..Config::default()
        };
        // Should be a no-op — just verify it doesn't panic
        apply(&config, true);
    }

    #[test]
    fn limits_lockdown_tighter_than_normal() {
        let normal = Config::default();
        let lockdown = Config {
            lockdown: Some(true),
            ..Config::default()
        };

        let normal_limits = limits_for(&normal);
        let lockdown_limits = limits_for(&lockdown);

        for (n, l) in normal_limits.iter().zip(lockdown_limits.iter()) {
            assert!(
                l.soft <= n.soft,
                "Lockdown {} ({}) should be <= normal ({})",
                n.name,
                l.soft,
                n.soft
            );
        }
    }
}
