//! `--cpus`: CPU affinity for the sandbox, locked by seccomp.
//!
//! Affinity needs no privilege, and the seccomp rule in `seccomp.rs` is
//! what stops the sandbox from widening it again.

use std::collections::BTreeSet;
use std::path::Path;

use crate::sandbox::rlimits::LimitSource;

/// Upper bound on a CPU number, matching glibc's `CPU_SETSIZE`.
const MAX_CPU: usize = 1024;

/// `8,24`, `0-3`, `0-3,8`: the `taskset -c` / cpuset list syntax.
pub fn parse_cpu_list(text: &str) -> Result<BTreeSet<usize>, String> {
    let mut set = BTreeSet::new();
    for part in text.split(',') {
        let part = part.trim();
        let cpu = |s: &str| -> Result<usize, String> {
            let n: usize = s
                .trim()
                .parse()
                .map_err(|_| format!("invalid CPU list {text:?}"))?;
            if n >= MAX_CPU {
                return Err(format!("CPU {n} is out of range"));
            }
            Ok(n)
        };
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (cpu(lo)?, cpu(hi)?);
                if lo > hi {
                    return Err(format!("invalid CPU range {part:?}"));
                }
                set.extend(lo..=hi);
            }
            None => {
                set.insert(cpu(part)?);
            }
        }
    }
    if set.is_empty() {
        return Err("empty CPU list".into());
    }
    Ok(set)
}

pub fn format_cpu_list(cpus: &BTreeSet<usize>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut iter = cpus.iter().copied().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end += 1;
            iter.next();
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    out.join(",")
}

/// Project CPUs narrow the baseline to their intersection. Returns the
/// value to keep and whether the project value was (partly) dropped.
///
/// An empty intersection is kept as the empty list rather than falling
/// back to the baseline: the project asked for CPUs the trusted layers
/// never allow, so nothing is left to run on, and the launch refuses it
/// (`check_launch`) instead of quietly running on CPUs the project
/// excluded.
pub fn tighten_cpus(
    base: Option<String>,
    local: Option<String>,
) -> (Option<String>, bool) {
    match (base, local) {
        (base, None) => (base, false),
        (None, local) => (local, false),
        (Some(b), Some(l)) => match (parse_cpu_list(&b), parse_cpu_list(&l)) {
            (Ok(bs), Ok(ls)) => {
                let both: BTreeSet<usize> =
                    bs.intersection(&ls).copied().collect();
                let dropped = both != ls;
                (Some(format_cpu_list(&both)), dropped)
            }
            // A trusted value that does not parse is kept so the launch
            // fails closed at `check_launch`: a valid project value must
            // never stand in for it.
            // Not the project's fault: `check_launch` names the trusted
            // value when it refuses.
            (Err(_), _) => (Some(b), false),
            // A project value that does not parse is kept for the same
            // reason: dropping it would silently widen its own policy.
            (Ok(_), Err(_)) => (Some(l), false),
        },
    }
}

/// CPUs the calling process may run on right now.
#[cfg(target_os = "linux")]
fn allowed_cpus() -> Result<BTreeSet<usize>, String> {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;
    let set = sched_getaffinity(Pid::from_raw(0))
        .map_err(|e| format!("cannot read CPU affinity: {e}"))?;
    Ok((0..CpuSet::count())
        .filter(|&i| set.is_set(i).unwrap_or(false))
        .collect())
}

/// Refuse CPUs this process cannot use: the kernel would silently drop
/// them, and `--cpus 40` on a 32-CPU host must not mean "any CPU".
#[cfg(target_os = "linux")]
pub fn validate_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    let allowed = allowed_cpus()?;
    let missing: BTreeSet<usize> = cpus.difference(&allowed).copied().collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--cpus {} names CPUs this process cannot use: {} (available: {})",
            format_cpu_list(cpus),
            format_cpu_list(&missing),
            format_cpu_list(&allowed)
        ))
    }
}

/// Every refusal a CPU set can produce, checked before anything starts.
///
/// A refusal caused by the project names its stored policy, the file the
/// operator can still edit: the launch has already migrated a legacy
/// project file away. A refusal caused by `--cpus` (or by a source this
/// launch cannot name) keeps the flag's wording.
pub fn check_launch(
    cpus: Option<&str>,
    source: Option<LimitSource>,
    project_path: Option<&Path>,
    seccomp_enabled: bool,
) -> Result<(), String> {
    let Some(text) = cpus else {
        return Ok(());
    };
    let refuse = |cli: String, reason: String| match (source, project_path) {
        (Some(LimitSource::Project), Some(path)) => {
            format!("project policy {}: cpus {reason}", path.display())
        }
        (Some(LimitSource::Global), _) => {
            format!("global config cpus {reason}")
        }
        _ => cli,
    };
    if text.is_empty() {
        return Err(refuse(
            "--cpus: the project .ai-jail CPU set shares no CPU with the \
             trusted set, so nothing is left to run on"
                .into(),
            "shares no CPU with the trusted set, so nothing is left to \
             run on"
                .into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = seccomp_enabled;
        Err(refuse(
            "--cpus is Linux only".into(),
            "is Linux only".into(),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        // Affinity alone is advisory: any process may widen its own.
        // Seccomp is what makes --cpus a limit rather than a hint.
        if !seccomp_enabled {
            return Err(refuse(
                "--cpus needs seccomp, which stops the sandbox from \
                 widening its own CPU set; drop --no-seccomp"
                    .into(),
                "needs seccomp, which stops the sandbox from widening \
                 its own CPU set; drop --no-seccomp"
                    .into(),
            ));
        }
        let set = parse_cpu_list(text)
            .map_err(|e| refuse(format!("--cpus: {e}"), e))?;
        validate_cpus(&set).map_err(|e| {
            let reason = e.strip_prefix("--cpus ").unwrap_or(&e).to_string();
            refuse(e, reason)
        })
    }
}

/// Pin the calling thread -- and everything it later execs or forks --
/// to `cpus`. Must run before seccomp refuses `sched_setaffinity`.
#[cfg(target_os = "linux")]
pub fn apply_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    use nix::sched::{CpuSet, sched_setaffinity};
    use nix::unistd::Pid;
    validate_cpus(cpus)?;
    let mut set = CpuSet::new();
    for &cpu in cpus {
        set.set(cpu)
            .map_err(|e| format!("cannot select CPU {cpu}: {e}"))?;
    }
    sched_setaffinity(Pid::from_raw(0), &set)
        .map_err(|e| format!("cannot set CPU affinity: {e}"))
}

// `--cpus`: parsing, formatting, validation and project narrowing.
//
// The module exposes
// `parse_cpu_list(&str) -> Result<BTreeSet<usize>, String>`,
// `format_cpu_list(&BTreeSet<usize>) -> String`,
// `validate_cpus(&BTreeSet<usize>) -> Result<(), String>`,
// `tighten_cpus(Option<String>, Option<String>) -> (Option<String>, bool)`.
// The empty-intersection refusal is asserted at launch level in
// `tests/rlimit_values.rs`, not here.
#[cfg(test)]
mod affinity_tests {
    use std::collections::BTreeSet;

    use super::*;

    fn set(cpus: &[usize]) -> BTreeSet<usize> {
        cpus.iter().copied().collect()
    }

    /// The kernel's own view of this process's CPUs, as `0-31` text.
    /// Reads `/proc`, so Linux only, like `validate_cpus`.
    #[cfg(target_os = "linux")]
    fn kernel_allowed_list() -> String {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .map(|v| v.trim().to_string())
            .expect("Cpus_allowed_list in /proc/self/status")
    }

    #[test]
    fn cpu_lists_parse_single_cpus_and_ranges() {
        assert_eq!(parse_cpu_list("8,24").unwrap(), set(&[8, 24]));
        assert_eq!(parse_cpu_list("0-3,8").unwrap(), set(&[0, 1, 2, 3, 8]));
        assert_eq!(parse_cpu_list("5").unwrap(), set(&[5]));
        assert_eq!(parse_cpu_list("2-2").unwrap(), set(&[2]));
    }

    #[test]
    fn malformed_cpu_lists_are_refused() {
        for text in ["", "a", "3-1", "0,,1", "-1", "1024", "0-1024", "1.5"] {
            assert!(parse_cpu_list(text).is_err(), "{text:?} must be refused");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpus_outside_the_supervisors_set_are_refused_naming_entry_and_set() {
        let allowed = kernel_allowed_list();
        let allowed_set = parse_cpu_list(&allowed).unwrap();
        let outside = (0..1024)
            .rev()
            .find(|c| !allowed_set.contains(c))
            .expect("some CPU number below 1024 is not allowed here");
        let err = validate_cpus(&set(&[outside])).unwrap_err();
        assert!(err.contains(&outside.to_string()), "names the entry: {err}");
        assert!(
            err.contains(&format_cpu_list(&allowed_set)),
            "names the allowed set {allowed}: {err}"
        );
        let first = *allowed_set.iter().next().unwrap();
        assert!(validate_cpus(&set(&[first])).is_ok());
    }

    #[test]
    fn project_cpus_narrow_the_trusted_set_to_the_intersection() {
        let (got, _) = tighten_cpus(Some("0-3".into()), Some("2-5".into()));
        assert_eq!(got.as_deref(), Some("2-3"));
        let (got, _) = tighten_cpus(Some("0-3".into()), None);
        assert_eq!(got.as_deref(), Some("0-3"));
    }

    #[test]
    fn affinity_code_carries_no_privileged_path() {
        // no systemd-run, sudo, setuid helper or cgroup write.
        let src = include_str!("affinity.rs");
        let code: String = src
            .lines()
            .take_while(|l| !l.contains("mod affinity_tests"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in ["systemd-run", "\"sudo\"", "/sys/fs/cgroup", "setuid("] {
            assert!(!code.contains(needle), "affinity.rs mentions {needle}");
        }
    }
}

// A CPU-set refusal names the layer that caused it.
//
// The launch migrates a legacy project file into the policy store before
// it checks `cpus`, so a refusal caused by the project must point at the
// stored policy, which still exists, and never at `--cpus`, which the
// operator did not pass. A refusal caused by `--cpus` keeps its text.
//
// - `Config.cpus_source: Option<LimitSource>`, runtime only, set by the
//   layer that last decided `cpus` (`Cli` from `merge`, `Project` when a
//   project value is what the launch keeps);
// - `check_launch(cpus: Option<&str>, source: Option<LimitSource>,
//   project_path: Option<&Path>, seccomp_enabled: bool)`.
// A `None` source is treated as the command line, as for `rlimit`.
#[cfg(test)]
mod refusal_layer_tests {
    use std::path::Path;

    use super::*;
    use crate::{config::Config, sandbox::rlimits::LimitSource};

    /// Where the policy store keeps the project's document. No `.ai-jail`
    /// in it, so a message naming the legacy file is told apart.
    const POLICY: &str = "/srv/xdg/ai-jail/projects/proj-refusal.toml";

    fn policy() -> &'static Path {
        Path::new(POLICY)
    }

    fn refusal(
        cpus: &str,
        source: Option<LimitSource>,
        seccomp_enabled: bool,
    ) -> String {
        match check_launch(Some(cpus), source, Some(policy()), seccomp_enabled)
        {
            Ok(()) => panic!("cpus {cpus:?} from {source:?} must be refused"),
            Err(e) => e,
        }
    }

    fn assert_blames_the_command_line(err: &str, case: &str) {
        assert!(err.starts_with("--cpus"), "{case}: keeps --cpus: {err}");
        assert!(!err.contains("project policy"), "{case}: {err}");
        assert!(!err.contains(POLICY), "{case}: names the policy: {err}");
    }

    fn assert_blames_the_project_policy(err: &str, case: &str) {
        assert!(err.contains("project policy"), "{case}: {err}");
        assert!(err.contains(POLICY), "{case}: names the path: {err}");
        assert!(!err.starts_with("--cpus"), "{case}: blames --cpus: {err}");
        assert!(!err.contains("--cpus:"), "{case}: blames --cpus: {err}");
        assert!(!err.contains(".ai-jail"), "{case}: legacy file: {err}");
        assert!(err.contains("cpus"), "{case}: names the control: {err}");
    }

    fn cli_args(args: &[&str]) -> crate::cli::CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .expect("test arguments parse")
    }

    #[test]
    fn refusal_layer_cli_empty_set_keeps_the_cpus_text() {
        // Hostile half first: the stored policy path is known at every
        // launch, so it must not be blamed for a value it did not set.
        for source in [Some(LimitSource::Cli), None] {
            let err = refusal("", source, true);
            assert_blames_the_command_line(&err, "empty set");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal_layer_cli_invalid_list_and_no_seccomp_keep_the_cpus_text() {
        for source in [Some(LimitSource::Cli), None] {
            let err = refusal("x", source, true);
            assert_blames_the_command_line(&err, "invalid list");
            let err = refusal("0", source, false);
            assert_blames_the_command_line(&err, "seccomp off");
            assert!(err.contains("seccomp"), "says why: {err}");
        }
    }

    #[test]
    fn refusal_layer_project_empty_intersection_names_the_policy() {
        // Project `cpus = "8-9"` under `--cpus 0-3`: nothing is left.
        let (kept, _) = tighten_cpus(Some("0-3".into()), Some("8-9".into()));
        assert_eq!(kept.as_deref(), Some(""));
        let err = refusal("", Some(LimitSource::Project), true);
        assert_blames_the_project_policy(&err, "empty intersection");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal_layer_project_invalid_list_names_the_policy() {
        let err = refusal("x", Some(LimitSource::Project), true);
        assert_blames_the_project_policy(&err, "invalid list");
        assert!(err.contains("\"x\""), "names the value: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal_layer_project_cpus_without_seccomp_names_the_policy() {
        let err = refusal("0", Some(LimitSource::Project), false);
        assert_blames_the_project_policy(&err, "seccomp off");
        assert!(err.contains("seccomp"), "says why: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal_layer_valid_project_cpus_still_launch() {
        // Naming the layer must not turn a usable set into a refusal.
        let first = *allowed_cpus().unwrap().iter().next().unwrap();
        let text = first.to_string();
        for source in [Some(LimitSource::Project), Some(LimitSource::Cli)] {
            assert_eq!(
                check_launch(Some(&text), source, Some(policy()), true),
                Ok(()),
                "cpus {text} from {source:?}"
            );
        }
        assert_eq!(
            check_launch(
                None,
                Some(LimitSource::Project),
                Some(policy()),
                false
            ),
            Ok(()),
            "no cpus at all"
        );
    }

    #[test]
    fn refusal_layer_merge_records_which_layer_decided_cpus() {
        let args = cli_args(&["--cpus", "0-3", "bash"]);
        let baseline = crate::config::merge(&args, Config::default());
        assert_eq!(baseline.cpus_source, Some(LimitSource::Cli));

        // Hostile half first: a project without `cpus` decides nothing.
        let (merged, _) = crate::config::merge_with_global_report(
            baseline.clone(),
            Config::default(),
            Path::new("/project"),
        );
        assert_eq!(merged.cpus.as_deref(), Some("0-3"));
        assert_eq!(merged.cpus_source, Some(LimitSource::Cli));

        // A trusted list that does not parse is kept over a valid project
        // list, so the refusal that follows is not the project's.
        let malformed = Config {
            cpus: Some("0-3x".into()),
            cpus_source: Some(LimitSource::Global),
            ..Config::default()
        };
        let project = Config {
            cpus: Some("0-63".into()),
            ..Config::default()
        };
        let (merged, _) = crate::config::merge_with_global_report(
            malformed,
            project,
            Path::new("/project"),
        );
        assert_eq!(merged.cpus.as_deref(), Some("0-3x"));
        assert_ne!(merged.cpus_source, Some(LimitSource::Project));

        // Project `cpus = "8-9"` under `--cpus 0-3`: the project decided.
        let project = Config {
            cpus: Some("8-9".into()),
            ..Config::default()
        };
        let (merged, _) = crate::config::merge_with_global_report(
            baseline,
            project,
            Path::new("/project"),
        );
        assert_eq!(merged.cpus.as_deref(), Some(""));
        assert_eq!(merged.cpus_source, Some(LimitSource::Project));
        let err = match check_launch(
            merged.cpus.as_deref(),
            merged.cpus_source,
            Some(policy()),
            true,
        ) {
            Ok(()) => panic!("an empty CPU set must be refused"),
            Err(e) => e,
        };
        assert_blames_the_project_policy(&err, "merged empty set");
    }
}

// A trusted CPU set written in another order is still the trusted value,
// and a refusal caused by the global config names it, not `--cpus`.
#[cfg(test)]
mod refusal_layer_trusted_tests {
    use std::path::Path;

    use super::*;
    use crate::config::Config;

    #[test]
    fn refusal_layer_trusted_set_in_another_order_stays_trusted() {
        // The project names a superset, so the kept value is the trusted
        // set itself: the trusted layer decided, whatever its spelling.
        for spelling in ["1-3", "3,1-2"] {
            let trusted = Config {
                cpus: Some(spelling.into()),
                cpus_source: Some(LimitSource::Global),
                ..Config::default()
            };
            let project = Config {
                cpus: Some("0-7".into()),
                ..Config::default()
            };
            let (merged, _) = crate::config::merge_with_global_report(
                trusted,
                project,
                Path::new("/project"),
            );
            assert_eq!(
                merged.cpus_source,
                Some(LimitSource::Global),
                "trusted {spelling}"
            );
        }
    }

    #[test]
    fn refusal_layer_global_refusal_names_the_global_config() {
        let err = match check_launch(
            Some(""),
            Some(LimitSource::Global),
            Some(Path::new("/srv/xdg/ai-jail/projects/p.toml")),
            true,
        ) {
            Ok(()) => panic!("an empty CPU set must be refused"),
            Err(e) => e,
        };
        assert!(err.starts_with("global config cpus"), "{err}");
        assert!(!err.contains("--cpus"), "{err}");
        assert!(!err.contains("project policy"), "{err}");
    }
}
