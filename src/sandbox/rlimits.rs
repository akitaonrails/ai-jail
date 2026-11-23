use crate::config::Config;
use crate::output;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use std::collections::BTreeMap;
use std::path::Path;

// Normal mode: generous limits that prevent abuse
// without breaking build tools or AI agents.
#[cfg(target_os = "linux")]
const NPROC_NORMAL: u64 = 4096;
const NOFILE_NORMAL: u64 = 65536;

// Lockdown mode: tighter limits for untrusted workloads.
#[cfg(target_os = "linux")]
const NPROC_LOCKDOWN: u64 = 1024;
const NOFILE_LOCKDOWN: u64 = 4096;
const FSIZE_LOCKDOWN: u64 = 1024 * 1024 * 1024;

/// A per-process limit the operator may set with `--rlimit NAME=VALUE`.
///
/// The set is deliberately small: these are the rlimits that bound a
/// runaway agent without privilege. Anything needing a cgroup
/// (memory.max, cpu.max, io.max) is out of reach for an unprivileged
/// process and is documented as such instead of half-offered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RlimitName {
    Nproc,
    Nofile,
    Core,
    Cpu,
    Fsize,
    Data,
    As,
}

impl RlimitName {
    pub const ALL: [RlimitName; 7] = [
        RlimitName::Nproc,
        RlimitName::Nofile,
        RlimitName::Core,
        RlimitName::Cpu,
        RlimitName::Fsize,
        RlimitName::Data,
        RlimitName::As,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RlimitName::Nproc => "nproc",
            RlimitName::Nofile => "nofile",
            RlimitName::Core => "core",
            RlimitName::Cpu => "cpu",
            RlimitName::Fsize => "fsize",
            RlimitName::Data => "data",
            RlimitName::As => "as",
        }
    }

    /// `None` where the platform has no such resource: nix defines
    /// `RLIMIT_NPROC` for Linux and the BSDs but not for macOS. Off Linux
    /// nothing reaches it anyway — the `nproc` default is Linux-only and
    /// explicit limits are refused there — so `None` is a failure path,
    /// never a silent skip.
    pub fn resource(self) -> Option<Resource> {
        match self {
            #[cfg(target_os = "linux")]
            RlimitName::Nproc => Some(Resource::RLIMIT_NPROC),
            #[cfg(not(target_os = "linux"))]
            RlimitName::Nproc => None,
            RlimitName::Nofile => Some(Resource::RLIMIT_NOFILE),
            RlimitName::Core => Some(Resource::RLIMIT_CORE),
            RlimitName::Cpu => Some(Resource::RLIMIT_CPU),
            RlimitName::Fsize => Some(Resource::RLIMIT_FSIZE),
            RlimitName::Data => Some(Resource::RLIMIT_DATA),
            RlimitName::As => Some(Resource::RLIMIT_AS),
        }
    }

    /// Byte-sized limits accept the K/M/G/T suffixes; counts and CPU
    /// seconds do not, because "4K processes" reads as 4000 to most
    /// people and 4096 to this parser.
    fn is_bytes(self) -> bool {
        matches!(self, RlimitName::Fsize | RlimitName::Data | RlimitName::As)
    }

    fn accepted_forms(self) -> &'static str {
        if self.is_bytes() {
            "a decimal integer, an integer with a K/M/G/T suffix (powers of 1024), or unlimited"
        } else {
            "a decimal integer or unlimited"
        }
    }
}

impl std::str::FromStr for RlimitName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        RlimitName::ALL
            .into_iter()
            .find(|name| name.as_str() == text)
            .ok_or_else(|| {
                let known: Vec<&str> =
                    RlimitName::ALL.iter().map(|n| n.as_str()).collect();
                format!(
                    "unknown rlimit name {text:?}; expected one of {}",
                    known.join(", ")
                )
            })
    }
}

/// A parsed limit value. `Unlimited` maps to `RLIM_INFINITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitValue {
    Finite(u64),
    Unlimited,
}

impl RlimitValue {
    pub fn parse(name: RlimitName, text: &str) -> Result<RlimitValue, String> {
        let refuse = || {
            format!(
                "invalid value {text:?} for rlimit {}: expected {}",
                name.as_str(),
                name.accepted_forms()
            )
        };
        if text == "unlimited" {
            return Ok(RlimitValue::Unlimited);
        }
        let (digits, multiplier) = match text.as_bytes().last() {
            Some(b'K') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 10)
            }
            Some(b'M') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 20)
            }
            Some(b'G') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 30)
            }
            Some(b'T') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 40)
            }
            _ => (text, 1),
        };
        // `u64::from_str` would accept a leading '+'; the grammar is
        // decimal digits only.
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refuse());
        }
        let base: u64 = digits.parse().map_err(|_| refuse())?;
        // At 0 the kernel sends SIGXCPU at once: a wrapper that has
        // already used CPU time dies before `exec`, with no message.
        if name == RlimitName::Cpu && base == 0 {
            return Err(format!(
                "invalid value {text:?} for rlimit cpu: cpu needs at least \
                 1 second"
            ));
        }
        base.checked_mul(multiplier)
            .map(RlimitValue::Finite)
            .ok_or_else(refuse)
    }

    /// The raw `rlim_t` value, with `Unlimited` as `RLIM_INFINITY`.
    pub fn as_raw(self) -> u64 {
        match self {
            RlimitValue::Finite(n) => n,
            RlimitValue::Unlimited => nix::libc::RLIM_INFINITY,
        }
    }
}

/// Which layer supplied an effective limit. Recorded for `--dry-run` and
/// the audit record; it never changes what is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitSource {
    Default,
    Cli,
    Global,
    Project,
}

impl LimitSource {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitSource::Default => "default",
            LimitSource::Cli => "cli",
            LimitSource::Global => "global",
            LimitSource::Project => "project",
        }
    }
}

/// What lowered an explicit value below the one asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitCeiling {
    Supervisor,
    Host,
}

impl LimitCeiling {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitCeiling::Supervisor => "supervisor",
            LimitCeiling::Host => "host",
        }
    }
}

/// A limit value as the operator types it: `RLIM_INFINITY` is
/// `unlimited`, which `--rlimit` accepts back; a 20-digit number is not.
pub fn fmt_rlim(v: u64) -> String {
    if v == nix::libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        v.to_string()
    }
}

/// One limit as it will be applied inside the sandbox.
pub struct EffectiveLimit {
    pub name: RlimitName,
    pub soft: u64,
    pub hard: u64,
    pub source: LimitSource,
    pub ceiling: Option<LimitCeiling>,
}

/// The defaults ai-jail has always applied. `nproc` is applied only
/// inside the sandbox (see `apply_sandbox`).
fn default_limits(config: &Config) -> Vec<(RlimitName, u64)> {
    let lockdown = config.lockdown_enabled();
    let mut limits = vec![
        (
            RlimitName::Nofile,
            if lockdown {
                NOFILE_LOCKDOWN
            } else {
                NOFILE_NORMAL
            },
        ),
        (RlimitName::Core, 0),
    ];
    if lockdown {
        limits.push((RlimitName::Fsize, FSIZE_LOCKDOWN));
    }
    #[cfg(target_os = "linux")]
    limits.push((
        RlimitName::Nproc,
        if lockdown {
            NPROC_LOCKDOWN
        } else {
            NPROC_NORMAL
        },
    ));

    // RLIMIT_AS is intentionally not a default: JVMs and Chromium reserve
    // large virtual address spaces even when their physical use is
    // modest. An operator may still set it explicitly.

    limits
}

/// The ceiling `--lockdown` puts on an explicit value. Lockdown exists to
/// tighten, so an explicit value may only match or tighten its defaults.
fn lockdown_ceiling(name: RlimitName) -> Option<u64> {
    match name {
        RlimitName::Nofile => Some(NOFILE_LOCKDOWN),
        RlimitName::Core => Some(0),
        RlimitName::Fsize => Some(FSIZE_LOCKDOWN),
        #[cfg(target_os = "linux")]
        RlimitName::Nproc => Some(NPROC_LOCKDOWN),
        _ => None,
    }
}

/// The `--lockdown` ceiling an explicit `value` is clamped to, when it is
/// above it.
fn lockdown_clamp(
    config: &Config,
    name: RlimitName,
    value: u64,
) -> Option<u64> {
    if !config.lockdown_enabled() {
        return None;
    }
    lockdown_ceiling(name).filter(|&ceiling| value > ceiling)
}

/// Each explicit limit `--lockdown` clamps: its name, the value asked
/// for, and the ceiling it runs at instead.
pub fn lockdown_clamps(config: &Config) -> Vec<(RlimitName, &str, u64)> {
    config
        .rlimit
        .iter()
        .filter_map(|(key, text)| {
            let name: RlimitName = key.parse().ok()?;
            let value = RlimitValue::parse(name, text).ok()?.as_raw();
            lockdown_clamp(config, name, value)
                .map(|ceiling| (name, text.as_str(), ceiling))
        })
        .collect()
}

/// Refuse explicit limits where they cannot be applied. They are applied
/// only by the in-sandbox wrapper, which exists on Linux alone; elsewhere
/// an explicit value would replace a default and then be applied nowhere.
/// The platform is a parameter so both arms are testable.
pub fn check_platform(
    config: &Config,
    linux: bool,
    project_path: Option<&Path>,
) -> Result<(), String> {
    if linux || config.rlimit.is_empty() {
        return Ok(());
    }
    // Name every layer holding an entry, so the operator can find the
    // file: a project policy refuses every launch of that project.
    let mut layers: Vec<String> = Vec::new();
    for key in config.rlimit.keys() {
        let layer = match config.rlimit_source.get(key) {
            Some(LimitSource::Project) => match project_path {
                Some(path) => format!("project policy {}", path.display()),
                None => "project policy".to_string(),
            },
            Some(LimitSource::Global) => "global config rlimit".to_string(),
            Some(LimitSource::Default) | Some(LimitSource::Cli) | None => {
                "--rlimit".to_string()
            }
        };
        if !layers.contains(&layer) {
            layers.push(layer);
        }
    }
    Err(format!(
        "explicit limits are Linux only (set by {})",
        layers.join(", ")
    ))
}

/// The hard limit the sandbox inherits from the supervisor for `name`.
/// `apply` pins the supervisor's `core` and `nofile` defaults with hard
/// equal to soft, and an unprivileged process cannot raise a hard limit,
/// so an explicit value above them can never take effect in the sandbox.
fn supervisor_ceiling(config: &Config, name: RlimitName) -> Option<u64> {
    if !matches!(name, RlimitName::Core | RlimitName::Nofile) {
        return None;
    }
    supervisor_limits(config)
        .into_iter()
        .find(|limit| limit.name == name)
        .map(|limit| limit.hard)
}

/// The value an explicit entry asked for, before any clamp. Only the
/// in-sandbox wrapper reports clamps, and it exists on Linux alone.
#[cfg(target_os = "linux")]
fn requested_value(config: &Config, name: RlimitName) -> Option<u64> {
    let text = config.rlimit.get(name.as_str())?;
    RlimitValue::parse(name, text).ok().map(RlimitValue::as_raw)
}

/// Every limit that applies inside the sandbox: the defaults (unless
/// `--no-rlimits`), each replaced by an explicit value of the same name,
/// plus the explicit values that have no default.
pub fn effective(config: &Config) -> Result<Vec<EffectiveLimit>, String> {
    let mut chosen: BTreeMap<
        RlimitName,
        (u64, LimitSource, Option<LimitCeiling>),
    > = BTreeMap::new();
    if config.rlimits_enabled() {
        for (name, soft) in default_limits(config) {
            chosen.insert(name, (soft, LimitSource::Default, None));
        }
    }
    for (key, text) in &config.rlimit {
        let name: RlimitName = key.parse()?;
        let value = RlimitValue::parse(name, text)?.as_raw();
        // Lockdown only tightens: a value above its ceiling runs at the
        // ceiling (warned about by `apply_sandbox`), so a project
        // `lockdown = true` never turns a working trusted config into a
        // refusal.
        let value = match lockdown_clamp(config, name, value) {
            Some(ceiling) => ceiling,
            None => value,
        };
        // Report what the sandbox gets, not what was asked: the dry run
        // and the audit record must agree with the launch.
        let (value, ceiling) = match supervisor_ceiling(config, name) {
            Some(ceiling) if value > ceiling => {
                (ceiling, Some(LimitCeiling::Supervisor))
            }
            _ => (value, None),
        };
        let source = config
            .rlimit_source
            .get(key)
            .copied()
            .unwrap_or(LimitSource::Cli);
        chosen.insert(name, (value, source, ceiling));
    }
    Ok(chosen
        .into_iter()
        .map(|(name, (soft, source, ceiling))| EffectiveLimit {
            name,
            soft,
            // RLIMIT_CPU: at the soft limit the kernel sends SIGXCPU, at
            // the hard limit SIGKILL. With soft == hard the process gets
            // SIGKILL straight away and no chance to report; five seconds
            // of grace keep the catchable signal first.
            hard: if name == RlimitName::Cpu {
                soft.saturating_add(5)
            } else {
                soft
            },
            source,
            ceiling,
        })
        .collect())
}

/// Lower each limit to the hard limit ai-jail itself runs under:
/// `apply` only lowers, so the sandbox inherits at most that value, and
/// the dry run and the audit record must show what it gets. A line is
/// marked `host` when the host lowers its soft or its hard value, unless
/// the supervisor ceiling already holds it at or below the host's.
/// `None` from `host_hard` means the limit is unknown: no clamp.
pub fn clamp_to_host(
    limits: &mut [EffectiveLimit],
    host_hard: impl Fn(RlimitName) -> Option<u64>,
) {
    for limit in limits.iter_mut() {
        let Some(host) = host_hard(limit.name) else {
            continue;
        };
        let soft = limit.soft.min(host);
        // The cpu grace is recomputed from the clamped soft limit, so
        // `cpu=unlimited` under a host limit of 30 gives 30/30.
        let hard = if limit.name == RlimitName::Cpu {
            soft.saturating_add(5).min(host)
        } else {
            limit.hard.min(host)
        };
        if soft != limit.soft || hard != limit.hard {
            limit.soft = soft;
            limit.hard = hard;
            limit.ceiling = Some(LimitCeiling::Host);
        }
    }
}

/// The hard limit this process runs under, as `clamp_to_host` reads it.
pub fn host_hard_limit(name: RlimitName) -> Option<u64> {
    name.resource()
        .and_then(|r| getrlimit(r).ok())
        .map(|(_, hard)| hard)
}

/// The value a layer holds for one limit: its explicit entry, else the
/// default, else `RLIM_INFINITY` (no limit). An entry that does not parse
/// counts as `RLIM_INFINITY`, so a comparison against it fails closed:
/// a malformed value never reads as a tightening.
pub fn value_in(config: &Config, name: RlimitName) -> u64 {
    if let Some(text) = config.rlimit.get(name.as_str()) {
        return RlimitValue::parse(name, text)
            .map(RlimitValue::as_raw)
            .unwrap_or(nix::libc::RLIM_INFINITY);
    }
    if !config.rlimits_enabled() {
        return nix::libc::RLIM_INFINITY;
    }
    default_limits(config)
        .into_iter()
        .find(|(n, _)| *n == name)
        .map_or(nix::libc::RLIM_INFINITY, |(_, v)| v)
}

/// Whether `candidate` holds any `rlimit` entry looser than `baseline`
/// (higher, `unlimited`, malformed, or an unknown name).
pub fn widens(candidate: &Config, baseline: &Config) -> bool {
    candidate
        .rlimit
        .keys()
        .any(|key| match key.parse::<RlimitName>() {
            Ok(name) => {
                candidate
                    .rlimit
                    .get(key)
                    .is_some_and(|text| RlimitValue::parse(name, text).is_err())
                    || value_in(candidate, name) > value_in(baseline, name)
            }
            Err(_) => true,
        })
}

/// Apply one limit. A default limit that cannot be read or set keeps
/// upstream's warn-and-skip; an explicit one is an error, because the
/// operator asked for it and silently running without it fails open.
///
/// `warn_clamp` is false for a default the supervisor already applied
/// and warned about, so a host clamp is reported once per launch.
fn apply_one(
    limit: &EffectiveLimit,
    warn_clamp: bool,
    verbose: bool,
) -> Result<bool, String> {
    let explicit = limit.source != LimitSource::Default;
    let label = format!("RLIMIT_{}", limit.name.as_str().to_uppercase());
    let fail = |msg: String| {
        if explicit {
            Err(msg)
        } else {
            output::warn(&format!("{msg}, skipping"));
            Ok(false)
        }
    };
    let Some(resource) = limit.name.resource() else {
        return fail(format!("{label} is not available on this platform"));
    };
    let current_hard = match getrlimit(resource) {
        Ok((_, hard)) => hard,
        Err(e) => return fail(format!("Failed to read {label}: {e}")),
    };
    // An unprivileged process cannot raise its hard limit: clamp, but
    // say so, since the operator asked for a different number.
    let soft = limit.soft.min(current_hard);
    let hard = limit.hard.min(current_hard);
    if warn_clamp && soft < limit.soft {
        // A clamped `cpu` also loses its SIGXCPU grace when soft == hard.
        let grace = if limit.name == RlimitName::Cpu && hard - soft < 5 {
            format!(
                ", leaving {} s of the 5 s grace before SIGKILL",
                hard - soft
            )
        } else {
            String::new()
        };
        output::warn(&format!(
            "{label}: requested {}, hard limit {}, applied {}{grace}",
            fmt_rlim(limit.soft),
            fmt_rlim(current_hard),
            fmt_rlim(soft)
        ));
    } else if explicit
        && limit.name == RlimitName::Cpu
        && soft == limit.soft
        && hard < limit.hard
    {
        // The soft limit fits, but the host hard limit eats the grace that
        // keeps SIGXCPU ahead of SIGKILL.
        output::warn(&format!(
            "{label}: requested soft {}, hard limit {} \
             leaves {} s of the 5 s grace before SIGKILL",
            fmt_rlim(soft),
            fmt_rlim(current_hard),
            hard.saturating_sub(soft)
        ));
    }
    if let Err(e) = setrlimit(resource, soft, hard) {
        return fail(format!("Failed to set {label}: {e}"));
    }
    if verbose {
        output::verbose(&format!(
            "{label}: {} (hard: {})",
            fmt_rlim(soft),
            fmt_rlim(hard)
        ));
    }
    Ok(true)
}

/// The limits `apply` sets on the supervisor — the ai-jail process that
/// holds the PTY loop, the egress proxy with its secret substitution, and
/// the audit writer. Only defaults, with hard pinned to soft:
///
/// - `core`, `nofile` and lockdown's `fsize` always: an explicit value for
///   them is the sandbox's alone. Dropping a default because an explicit
///   value exists would loosen the supervisor — `--rlimit core=0` left it
///   dumpable, with the proxy's secrets in a core file, and any explicit
///   `fsize` removed lockdown's 1 GiB. Keeping them never caps the
///   wrapper: an explicit value is at most the default (lockdown clamps
///   it), and a process can always lower its own limit.
/// - never an explicit `cpu`, `data` or `as`, and no default exists for
///   them: on the supervisor they would kill or cap it and orphan the
///   sandbox.
/// - never `nproc`, which counts against bwrap's own clone(); see
///   `apply_sandbox`.
pub fn supervisor_limits(config: &Config) -> Vec<EffectiveLimit> {
    if !config.rlimits_enabled() {
        return Vec::new();
    }
    default_limits(config)
        .into_iter()
        .filter(|(name, _)| match name {
            RlimitName::Core | RlimitName::Nofile | RlimitName::Fsize => true,
            // nproc counts against bwrap's clone(); cpu, data and as
            // have no default, and on the supervisor they would kill or
            // cap it.
            RlimitName::Nproc
            | RlimitName::Cpu
            | RlimitName::Data
            | RlimitName::As => false,
        })
        .map(|(name, soft)| EffectiveLimit {
            name,
            soft,
            hard: soft,
            source: LimitSource::Default,
            ceiling: None,
        })
        .collect()
}

/// Apply the supervisor's limits before spawning the sandbox. Limits are
/// inherited across fork+exec. The set is exactly `supervisor_limits`;
/// explicit values are applied inside the sandbox by `apply_sandbox`.
///
/// Returns whether RLIMIT_FSIZE was set, so a later explanation of a
/// SIGXFSZ death only quotes a value ai-jail actually put in force (#247).
pub fn apply(config: &Config, verbose: bool) -> Result<bool, String> {
    if !config.rlimits_enabled() {
        if verbose {
            output::verbose("Resource limits: disabled");
        }
        return Ok(false);
    }
    let mut file_size_set = false;
    for limit in supervisor_limits(config) {
        // A default kept under an explicit value of the same name is
        // clamped silently here: the wrapper reports that name's clamp, so
        // each clamp is reported once per launch.
        let shadowed = config.rlimit.contains_key(limit.name.as_str());
        let applied = apply_one(&limit, !shadowed, verbose)?;
        file_size_set |= applied && limit.name == RlimitName::Fsize;
    }
    Ok(file_size_set)
}

/// Apply the full effective set — defaults and explicit values, NPROC
/// included — in the current process. Must be called inside the bwrap
/// sandbox (from --landlock-exec), after the bridges are spawned, not on
/// the bwrap parent: bwrap uses clone() for namespace creation, which
/// counts against RLIMIT_NPROC system-wide, and applying the limit before
/// that clone() causes EAGAIN when other user processes are running.
///
/// Hard is pinned to soft (soft + 5 for CPU) so the sandboxed process
/// cannot raise a limit back: lowering a hard limit is irreversible for
/// an unprivileged process.
#[cfg(target_os = "linux")]
pub fn apply_sandbox(config: &Config, verbose: bool) -> Result<(), String> {
    let clamps = lockdown_clamps(config);
    for limit in effective(config)? {
        // One warning per limit: a lockdown clamp names the host clamp
        // too, when the host hard limit is lower still.
        if let Some((_, requested, ceiling)) =
            clamps.iter().find(|(name, ..)| *name == limit.name)
        {
            let host = limit
                .name
                .resource()
                .and_then(|r| getrlimit(r).ok())
                .map_or(*ceiling, |(_, hard)| hard);
            let applied = (*ceiling).min(host);
            let note = if applied < *ceiling {
                format!(", hard limit {}", fmt_rlim(host))
            } else {
                String::new()
            };
            output::warn(&format!(
                "RLIMIT_{}: requested {requested}, --lockdown allows \
                 {}{note}, applied {}",
                limit.name.as_str().to_uppercase(),
                fmt_rlim(*ceiling),
                fmt_rlim(applied)
            ));
            let _ = apply_one(&limit, false, verbose)?;
            continue;
        }
        // `effective` already lowered this value to the supervisor's hard
        // limit, so `apply_one` would see nothing to clamp: name the value
        // the operator asked for here, once.
        if limit.ceiling.is_some() {
            let requested =
                requested_value(config, limit.name).unwrap_or(limit.soft);
            let host = limit
                .name
                .resource()
                .and_then(|r| getrlimit(r).ok())
                .map_or(limit.hard, |(_, hard)| hard);
            output::warn(&format!(
                "RLIMIT_{}: requested {}, hard limit {}, applied {}",
                limit.name.as_str().to_uppercase(),
                fmt_rlim(requested),
                fmt_rlim(host),
                fmt_rlim(limit.soft.min(host))
            ));
            let _ = apply_one(&limit, false, verbose)?;
            continue;
        }
        // The supervisor applied every default except NPROC and warned
        // about its clamps; the wrapper warns only for what it alone sets.
        let warn_clamp = limit.source != LimitSource::Default
            || limit.name == RlimitName::Nproc;
        let _ = apply_one(&limit, warn_clamp, verbose)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_sets_core_to_zero() {
        let config = Config::default();
        apply(&config, false).unwrap();

        let (soft, _) = getrlimit(Resource::RLIMIT_CORE).unwrap();
        assert_eq!(soft, 0);
    }

    #[test]
    fn apply_reports_no_file_size_limit_unless_lockdown_sets_one() {
        // Only --lockdown asks for RLIMIT_FSIZE, and disabled rlimits
        // set nothing even under it: neither may report a value in
        // force. The lockdown case lowers a hard limit for good, so it
        // runs in a child process (exit_reason's read-back tests).
        assert!(!apply(&Config::default(), false).unwrap());
        let lockdown_no_rlimits = Config {
            lockdown: Some(true),
            no_rlimits: Some(true),
            ..Config::default()
        };
        assert!(!apply(&lockdown_no_rlimits, false).unwrap());
    }

    #[test]
    fn apply_reports_the_file_size_limit_it_sets() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "sandbox::rlimits::tests::apply_reports_the_file_size_limit_it_sets_child",
            )
            .arg("--ignored")
            .env("AI_JAIL_RLIMIT_CHILD", "1")
            .output()
            .expect("spawn child rlimit test");
        assert!(output.status.success(), "child rlimit test failed");
    }

    #[test]
    #[ignore]
    fn apply_reports_the_file_size_limit_it_sets_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        let lockdown = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        assert!(
            apply(&lockdown, false).unwrap(),
            "lockdown sets RLIMIT_FSIZE"
        );
    }

    #[test]
    fn apply_respects_disabled() {
        let config = Config {
            no_rlimits: Some(true),
            ..Config::default()
        };
        // Should be a no-op — just verify it doesn't fail
        apply(&config, true).unwrap();
    }

    #[test]
    fn limits_lockdown_tighter_than_normal() {
        let normal = Config::default();
        let lockdown = Config {
            lockdown: Some(true),
            ..Config::default()
        };

        let normal_limits = effective(&normal).unwrap();
        let lockdown_limits = effective(&lockdown).unwrap();

        for n in &normal_limits {
            let l = lockdown_limits
                .iter()
                .find(|l| l.name == n.name)
                .expect("lockdown keeps every normal default");
            assert!(
                l.soft <= n.soft,
                "Lockdown {} ({}) should be <= normal ({})",
                n.name.as_str(),
                l.soft,
                n.soft
            );
        }
    }

    /// `apply_sandbox` carries the post-#21/#22 fix that moves NPROC
    /// enforcement inside the sandbox. The key invariant is that
    /// the hard limit is pinned equal to the soft limit so a
    /// compromised child can't raise NPROC back up. Verify that
    /// invariant directly.
    ///
    /// Run the assertion in a child test process so the lowered hard
    /// limit cannot leak into the rest of the test suite.
    #[cfg(target_os = "linux")]
    #[test]
    fn apply_nproc_pins_hard_equal_to_soft() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "sandbox::rlimits::tests::apply_nproc_pins_hard_equal_to_soft_child",
            )
            .arg("--ignored")
            .env("AI_JAIL_RLIMIT_CHILD", "1")
            .output()
            .expect("spawn child rlimit test");
        assert!(
            output.status.success(),
            "child rlimit test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn apply_pins_nofile_and_core_hard_equal_to_soft() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "sandbox::rlimits::tests::apply_pins_nofile_and_core_hard_equal_to_soft_child",
            )
            .arg("--ignored")
            .env("AI_JAIL_RLIMIT_CHILD", "1")
            .output()
            .expect("spawn child rlimit test");
        assert!(output.status.success(), "child rlimit test failed");
    }

    #[test]
    #[ignore]
    fn apply_pins_nofile_and_core_hard_equal_to_soft_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        apply(&Config::default(), false).unwrap();
        for resource in [Resource::RLIMIT_NOFILE, Resource::RLIMIT_CORE] {
            let (soft, hard) = getrlimit(resource).expect("getrlimit");
            assert_eq!(soft, hard, "{resource:?} hard limit must be pinned");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn apply_nproc_pins_hard_equal_to_soft_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        // Skip if the current hard limit is already below
        // NPROC_NORMAL — apply_sandbox would clamp to whatever's
        // currently in effect, so the post-condition is then
        // soft == hard == previous-hard. Still asserts the
        // pin invariant.
        let (_, hard_before) =
            getrlimit(Resource::RLIMIT_NPROC).expect("getrlimit");

        let config = Config::default();
        apply_sandbox(&config, false).unwrap();

        let (soft_after, hard_after) =
            getrlimit(Resource::RLIMIT_NPROC).expect("getrlimit");
        assert_eq!(
            soft_after, hard_after,
            "apply_sandbox must pin hard == soft so the sandbox can't raise it"
        );
        let expected = NPROC_NORMAL.min(hard_before);
        assert_eq!(
            soft_after, expected,
            "soft limit should match NPROC_NORMAL clamped to current hard"
        );
    }
}

// The limit grammar.
//
// `RlimitName` implements `FromStr` and
// `as_str`; `RlimitValue::{Finite(u64), Unlimited}` has
// `parse(name: RlimitName, text: &str) -> Result<RlimitValue, String>`.
// K/M/G/T are powers of 1024 and are accepted only for fsize, data, as.
// No `Debug`/`PartialEq` derive is assumed on the new types.
#[cfg(test)]
mod grammar_tests {
    use super::*;

    const ALL: [&str; 7] =
        ["nproc", "nofile", "core", "cpu", "fsize", "data", "as"];

    fn name(text: &str) -> RlimitName {
        text.parse::<RlimitName>()
            .ok()
            .unwrap_or_else(|| panic!("{text} must be a known limit name"))
    }

    fn parsed(limit: &str, text: &str) -> RlimitValue {
        match RlimitValue::parse(name(limit), text) {
            Ok(v) => v,
            Err(e) => panic!("{limit}={text} must parse, got Err({e})"),
        }
    }

    fn refused(limit: &str, text: &str) -> String {
        match RlimitValue::parse(name(limit), text) {
            Ok(_) => panic!("{limit}={text} must be refused"),
            Err(e) => e,
        }
    }

    fn finite(limit: &str, text: &str) -> u64 {
        match parsed(limit, text) {
            RlimitValue::Finite(n) => n,
            RlimitValue::Unlimited => {
                panic!("{limit}={text} must be finite, got Unlimited")
            }
        }
    }

    #[test]
    fn every_documented_name_parses_and_round_trips_through_as_str() {
        for text in ALL {
            assert_eq!(name(text).as_str(), text);
        }
    }

    #[test]
    fn names_outside_the_set_are_refused() {
        // Near misses first: each looks like a limit but is not one of
        // the seven `--rlimit` accepts.
        for text in ["nprocs", "rss", "stack", "memlock", "nice", "", " nofile"]
        {
            assert!(
                text.parse::<RlimitName>().is_err(),
                "{text:?} must not be a limit name"
            );
        }
    }

    #[test]
    fn binary_suffix_is_refused_for_count_and_time_limits() {
        // Hostile half first: a suffix that would wrongly be accepted on a
        // limit that is not measured in bytes.
        for limit in ["nofile", "nproc", "cpu", "core"] {
            let err = refused(limit, "4K");
            assert!(err.contains("4K"), "error must name the value: {err}");
        }
    }

    #[test]
    fn binary_suffixes_are_powers_of_1024_for_byte_limits() {
        for limit in ["fsize", "data", "as"] {
            assert_eq!(finite(limit, "4K"), 4 * 1024);
            assert_eq!(finite(limit, "3M"), 3 * 1024 * 1024);
            assert_eq!(finite(limit, "8G"), 8 * 1024 * 1024 * 1024);
            assert_eq!(finite(limit, "2T"), 2 * 1024_u64.pow(4));
        }
    }

    #[test]
    fn decimal_integers_parse_for_every_name() {
        for limit in ALL {
            // cpu has a floor of one second (`cpu_floor_tests`).
            let low = if limit == "cpu" { "1" } else { "0" };
            assert_eq!(finite(limit, low), low.parse::<u64>().unwrap());
            assert_eq!(finite(limit, "4096"), 4096);
        }
        assert_eq!(finite("nofile", "18446744073709551614"), u64::MAX - 1);
    }

    #[test]
    fn unlimited_is_accepted_for_every_name() {
        for limit in ALL {
            assert!(
                matches!(parsed(limit, "unlimited"), RlimitValue::Unlimited),
                "{limit}=unlimited"
            );
        }
    }

    #[test]
    fn overflowing_values_are_refused_not_wrapped() {
        // u64::MAX + 1 as a decimal.
        let err = refused("nofile", "18446744073709551616");
        assert!(err.contains("18446744073709551616"), "{err}");
        // 2^24 * 2^40 = 2^64: one past u64::MAX through the suffix.
        let err = refused("fsize", "16777216T");
        assert!(err.contains("16777216T"), "{err}");
        // The largest suffixed value that still fits is accepted.
        assert_eq!(finite("fsize", "16777215T"), 16_777_215 * 1024_u64.pow(4));
    }

    #[test]
    fn malformed_values_are_refused() {
        for text in ["", "-1", "1.5G", "1 G", "1KB", "0x10", "ten"] {
            refused("data", text);
        }
    }

    #[test]
    fn errors_name_the_limit_the_value_and_the_accepted_forms() {
        let err = refused("data", "12X");
        assert!(err.contains("data"), "must name the limit: {err}");
        assert!(err.contains("12X"), "must name the value: {err}");
        assert!(
            err.contains("unlimited"),
            "must list the accepted forms (decimal, K/M/G/T, unlimited): {err}"
        );
    }
}

// Effective limits and their application.
//
// - `Config.rlimit: BTreeMap<String, String>` (values in the CLI grammar)
//   and `Config.rlimit_source: BTreeMap<String, LimitSource>` (serde skip);
// - `pub fn effective(config: &Config) -> Result<Vec<EffectiveLimit>, String>`;
// - `EffectiveLimit { name: RlimitName, soft: u64, hard: u64,
//   source: LimitSource }`, `LimitSource::{Default, Cli, Global, Profile,
//   Project}`, `RlimitName::as_str`;
// - the supervisor's `apply(config, verbose) -> Result<(), String>` applies
//   only today's defaults (NOFILE, CORE, lockdown FSIZE) and warns, naming
//   the requested and the applied value, when it clamps to the hard limit
//   instead of clamping silently.
// `unlimited` is RLIM_INFINITY, which is u64::MAX on Linux.
#[cfg(test)]
mod effective_tests {
    use std::collections::BTreeMap;

    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let rlimit: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let rlimit_source: BTreeMap<String, LimitSource> = pairs
            .iter()
            .map(|(k, _)| (k.to_string(), LimitSource::Cli))
            .collect();
        Config {
            rlimit,
            rlimit_source,
            ..Config::default()
        }
    }

    fn limits(config: &Config) -> Vec<EffectiveLimit> {
        match effective(config) {
            Ok(v) => v,
            Err(e) => panic!("effective() must succeed, got Err({e})"),
        }
    }

    fn find<'a>(
        limits: &'a [EffectiveLimit],
        name: &str,
    ) -> &'a EffectiveLimit {
        limits
            .iter()
            .find(|l| l.name.as_str() == name)
            .unwrap_or_else(|| panic!("no effective limit named {name}"))
    }

    fn names(limits: &[EffectiveLimit]) -> Vec<&'static str> {
        let mut v: Vec<&'static str> =
            limits.iter().map(|l| l.name.as_str()).collect();
        v.sort_unstable();
        v
    }

    fn pair(limits: &[EffectiveLimit], name: &str) -> (u64, u64) {
        let l = find(limits, name);
        (l.soft, l.hard)
    }

    #[test]
    fn defaults_are_unchanged_when_no_value_is_given() {
        let normal = limits(&Config::default());
        // NPROC has a default on Linux only (`default_limits`).
        #[cfg(target_os = "linux")]
        assert_eq!(names(&normal), vec!["core", "nofile", "nproc"]);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(names(&normal), vec!["core", "nofile"]);
        assert_eq!(pair(&normal, "nofile"), (65536, 65536));
        assert_eq!(pair(&normal, "core"), (0, 0));
        #[cfg(target_os = "linux")]
        assert_eq!(pair(&normal, "nproc"), (4096, 4096));
        for l in &normal {
            assert!(matches!(l.source, LimitSource::Default));
        }

        let lockdown = limits(&Config {
            lockdown: Some(true),
            ..Config::default()
        });
        #[cfg(target_os = "linux")]
        assert_eq!(names(&lockdown), vec!["core", "fsize", "nofile", "nproc"]);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(names(&lockdown), vec!["core", "fsize", "nofile"]);
        assert_eq!(pair(&lockdown, "nofile"), (4096, 4096));
        assert_eq!(pair(&lockdown, "fsize"), (GIB, GIB));
        #[cfg(target_os = "linux")]
        assert_eq!(pair(&lockdown, "nproc"), (1024, 1024));
    }

    #[test]
    fn explicit_value_replaces_only_that_default() {
        let got = limits(&config(&[("nofile", "1024")]));
        assert_eq!(pair(&got, "nofile"), (1024, 1024));
        assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));
        // The other defaults stay, still labelled as defaults.
        assert_eq!(pair(&got, "core"), (0, 0));
        assert!(matches!(find(&got, "core").source, LimitSource::Default));
        #[cfg(target_os = "linux")]
        assert_eq!(pair(&got, "nproc"), (4096, 4096));
    }

    #[test]
    fn explicit_value_adds_a_limit_with_no_default() {
        let got = limits(&config(&[("data", "8G"), ("as", "unlimited")]));
        assert_eq!(pair(&got, "data"), (8 * GIB, 8 * GIB));
        assert_eq!(pair(&got, "as"), (u64::MAX, u64::MAX));
        assert_eq!(pair(&got, "nofile"), (65536, 65536));
    }

    #[test]
    fn no_rlimits_applies_only_the_explicit_values() {
        let mut only = config(&[("nofile", "1024")]);
        only.no_rlimits = Some(true);
        let got = limits(&only);
        assert_eq!(names(&got), vec!["nofile"], "no default may remain");
        assert_eq!(pair(&got, "nofile"), (1024, 1024));

        let none = Config {
            no_rlimits: Some(true),
            ..Config::default()
        };
        assert!(limits(&none).is_empty());
    }

    #[test]
    fn lockdown_accepts_values_at_or_below_its_defaults() {
        // Hostile half first: the refusal must not fire on a value that
        // only matches or tightens the lockdown default.
        for (name, value) in
            [("nofile", "4096"), ("nofile", "1024"), ("nproc", "512")]
        {
            let mut c = config(&[(name, value)]);
            c.lockdown = Some(true);
            assert!(effective(&c).is_ok(), "lockdown {name}={value}");
        }
        // A limit lockdown has no default for is not capped by it.
        let mut c = config(&[("cpu", "600")]);
        c.lockdown = Some(true);
        assert!(effective(&c).is_ok());
    }

    #[test]
    fn cpu_hard_limit_is_five_seconds_above_soft() {
        assert_eq!(pair(&limits(&config(&[("cpu", "60")])), "cpu"), (60, 65));
        assert_eq!(pair(&limits(&config(&[("cpu", "1")])), "cpu"), (1, 6));
        // Saturating, never wrapping to a tiny hard limit.
        let near = (u64::MAX - 2).to_string();
        assert_eq!(
            pair(&limits(&config(&[("cpu", &near)])), "cpu"),
            (u64::MAX - 2, u64::MAX)
        );
        assert_eq!(
            pair(&limits(&config(&[("cpu", "unlimited")])), "cpu"),
            (u64::MAX, u64::MAX)
        );
    }

    #[test]
    fn every_limit_but_cpu_pins_hard_to_soft() {
        let got = limits(&config(&[
            ("nproc", "100"),
            ("nofile", "200"),
            ("core", "0"),
            ("fsize", "1M"),
            ("data", "1G"),
            ("as", "2G"),
        ]));
        for l in &got {
            assert_eq!(
                l.soft,
                l.hard,
                "{} must have soft == hard",
                l.name.as_str()
            );
        }
    }

    #[test]
    fn invalid_entries_are_errors_not_silently_skipped() {
        for (name, value) in [
            ("rss", "1"),
            ("nofile", "12X"),
            ("nofile", "4K"),
            ("data", ""),
        ] {
            assert!(
                effective(&config(&[(name, value)])).is_err(),
                "{name}={value} must be an error"
            );
        }
    }

    /// clamping to the current hard limit is never silent. The hard
    /// limit is lowered irreversibly, so the check runs in a child test
    /// process (the pattern of `apply_nproc_pins_hard_equal_to_soft`).
    #[test]
    fn clamping_to_the_hard_limit_warns_with_requested_and_applied() {
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("sandbox::rlimits::effective_tests::clamping_child")
                .arg("--ignored")
                .arg("--nocapture")
                .env("AI_JAIL_RLIMIT_CHILD", "1")
                .output()
                .expect("spawn child rlimit test");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        let warning = stderr
            .lines()
            .find(|l| l.contains("65536") && l.contains("2000"))
            .unwrap_or_else(|| {
                panic!("no warning naming requested 65536 and applied 2000: {stderr}")
            });
        assert!(
            warning.to_ascii_lowercase().contains("nofile"),
            "the warning must name the limit: {warning}"
        );
    }

    #[test]
    #[ignore]
    fn clamping_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
        assert!(hard >= 2000, "test needs a NOFILE hard limit >= 2000");
        setrlimit(Resource::RLIMIT_NOFILE, 2000, 2000).expect("lower hard");
        // The default NOFILE (65536) is above the new hard limit.
        apply(&Config::default(), false).expect("apply defaults");
        let (soft, hard) =
            getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
        assert_eq!(
            (soft, hard),
            (2000, 2000),
            "applied value is the hard limit"
        );
    }
}

// An explicit limit is applied or refused, never dropped.
//
// - `check_platform(config: &Config, linux: bool) -> Result<(), String>`
//   decides whether the explicit limits in `config` may run; the launch
//   calls it with `cfg!(target_os = "linux")`. The platform is a parameter
//   so a Linux test can exercise the non-Linux refusal, which says that
//   explicit limits are "Linux only".
// - `effective()` applies an explicit value above a `--lockdown` ceiling
//   at the ceiling instead of refusing the launch.
// - Applying the limits warns once, naming the limit, the requested value
//   and the value applied, for a lockdown clamp; and names the requested
//   soft limit and the hard limit applied when the host hard limit leaves
//   less than the 5-second `cpu` grace.
// Warnings are read from a child test process, because lowering a hard
// limit cannot be undone (the pattern of `clamping_child`).
#[cfg(test)]
mod rlimit_explicit_tests {
    use std::collections::BTreeMap;

    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    // The child-process cases drive `apply_sandbox`, which is Linux only.
    #[cfg(target_os = "linux")]
    const CHILD_ENV: &str = "AI_JAIL_EXPLICIT_LIMIT_CHILD";

    fn explicit(pairs: &[(&str, &str)], source: LimitSource) -> Config {
        Config {
            rlimit: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            rlimit_source: pairs
                .iter()
                .map(|(k, _)| (k.to_string(), source))
                .collect::<BTreeMap<_, _>>(),
            ..Config::default()
        }
    }

    fn pair(config: &Config, name: &str) -> (u64, u64) {
        let limits = match effective(config) {
            Ok(v) => v,
            Err(e) => panic!("effective() must succeed, got Err({e})"),
        };
        let l = limits
            .iter()
            .find(|l| l.name.as_str() == name)
            .unwrap_or_else(|| panic!("no effective limit named {name}"));
        (l.soft, l.hard)
    }

    /// Run `explicit_child` in a fresh test process for `case`; return its
    /// warning lines (`⚠ ...` on a non-terminal stderr).
    #[cfg(target_os = "linux")]
    fn child_warnings(case: &str) -> Vec<String> {
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("sandbox::rlimits::rlimit_explicit_tests::explicit_child")
                .arg("--ignored")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(CHILD_ENV, case)
                .env_remove("NO_COLOR")
                .output()
                .expect("spawn child rlimit test");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "child {case} failed\nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        stderr
            .lines()
            .filter(|l| l.contains('⚠'))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn non_linux_launch_without_explicit_limits_is_not_refused() {
        // Hostile half first: the refusal must not catch a launch that
        // only runs the defaults, or none at all.
        for config in [
            Config::default(),
            Config {
                lockdown: Some(true),
                ..Config::default()
            },
            Config {
                no_rlimits: Some(true),
                ..Config::default()
            },
        ] {
            assert!(
                check_platform(&config, false, None).is_ok(),
                "no explicit limit: {config:?}"
            );
        }
    }

    #[test]
    fn non_linux_refuses_any_explicit_limit_saying_linux_only() {
        for source in [LimitSource::Cli, LimitSource::Global] {
            let config = explicit(&[("nofile", "1024")], source);
            let err = match check_platform(&config, false, None) {
                Ok(()) => panic!("{source:?} rlimit must be refused off Linux"),
                Err(e) => e,
            };
            assert!(err.contains("Linux only"), "{err}");
            assert!(err.contains("rlimit"), "must name the control: {err}");
        }
        let with_no_rlimits = Config {
            no_rlimits: Some(true),
            ..explicit(&[("cpu", "60")], LimitSource::Cli)
        };
        assert!(check_platform(&with_no_rlimits, false, None).is_err());
        // The same limits are accepted on Linux.
        assert!(
            check_platform(
                &explicit(&[("nofile", "1024")], LimitSource::Cli),
                true,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn lockdown_keeps_values_at_or_below_its_ceiling() {
        // Hostile half first: a value that already tightens must not be
        // raised to the ceiling.
        for (name, value, want) in [
            ("nofile", "1024", 1024),
            ("nofile", "4096", 4096),
            ("nproc", "512", 512),
        ] {
            let mut c = explicit(&[(name, value)], LimitSource::Cli);
            c.lockdown = Some(true);
            assert_eq!(pair(&c, name), (want, want), "lockdown {name}={value}");
        }
        // A limit lockdown has no ceiling for is left alone.
        let mut c = explicit(&[("cpu", "600")], LimitSource::Cli);
        c.lockdown = Some(true);
        assert_eq!(pair(&c, "cpu"), (600, 605));
    }

    #[test]
    fn lockdown_clamps_a_value_above_its_ceiling() {
        for (name, value, ceiling) in [
            ("nofile", "8192", 4096),
            ("nofile", "unlimited", 4096),
            ("fsize", "2G", GIB),
            ("core", "1", 0),
        ] {
            let mut c = explicit(&[(name, value)], LimitSource::Cli);
            c.lockdown = Some(true);
            assert_eq!(
                pair(&c, name),
                (ceiling, ceiling),
                "lockdown {name}={value} applies the ceiling"
            );
        }
        // The NPROC ceiling exists on Linux only (`lockdown_ceiling`).
        #[cfg(target_os = "linux")]
        {
            let mut c = explicit(&[("nproc", "2048")], LimitSource::Cli);
            c.lockdown = Some(true);
            assert_eq!(pair(&c, "nproc"), (1024, 1024), "lockdown nproc=2048");
        }
        // A trusted layer's value is clamped the same way, and so is a
        // value under --no-rlimits: lockdown only tightens.
        let mut global = explicit(&[("nofile", "8192")], LimitSource::Global);
        global.lockdown = Some(true);
        assert_eq!(pair(&global, "nofile"), (4096, 4096));
        global.no_rlimits = Some(true);
        assert_eq!(pair(&global, "nofile"), (4096, 4096));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lockdown_clamp_warns_once_naming_limit_requested_and_applied() {
        let warnings = child_warnings("lockdown");
        let named: Vec<&String> = warnings
            .iter()
            .filter(|w| w.contains("8192") && w.contains("4096"))
            .collect();
        assert_eq!(
            named.len(),
            1,
            "one warning naming requested 8192 and applied 4096: {warnings:?}"
        );
        assert!(
            named[0].to_ascii_lowercase().contains("nofile"),
            "the warning names the limit: {}",
            named[0]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_grace_kept_at_five_seconds_does_not_warn() {
        // Hostile half first: host hard 100, cpu=95 leaves exactly the
        // 5-second grace, which is not a loss.
        let warnings = child_warnings("cpu-exact");
        assert!(
            !warnings
                .iter()
                .any(|w| w.to_ascii_lowercase().contains("cpu")),
            "no cpu warning when the grace fits: {warnings:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_grace_below_five_seconds_warns_naming_soft_and_hard() {
        // Host hard 100, cpu=98: soft 98, hard 100 — 2 seconds of grace.
        let warnings = child_warnings("cpu-short");
        let hit = warnings
            .iter()
            .find(|w| w.to_ascii_lowercase().contains("cpu"))
            .unwrap_or_else(|| panic!("no cpu grace warning: {warnings:?}"));
        assert!(
            hit.contains("98") && hit.contains("100"),
            "names soft 98 and hard 100: {hit}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn explicit_child() {
        let Some(case) = std::env::var_os(CHILD_ENV) else {
            return;
        };
        match case.to_str() {
            Some("lockdown") => {
                let (_, hard) =
                    getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
                assert!(hard >= 8192, "test needs a NOFILE hard limit >= 8192");
                let mut c = explicit(&[("nofile", "8192")], LimitSource::Cli);
                c.lockdown = Some(true);
                c.no_rlimits = Some(true);
                apply_sandbox(&c, false).expect("apply_sandbox");
                assert_eq!(
                    getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit"),
                    (4096, 4096)
                );
            }
            Some(case @ ("cpu-short" | "cpu-exact")) => {
                setrlimit(Resource::RLIMIT_CPU, 100, 100).expect("lower cpu");
                let soft = if case == "cpu-short" { "98" } else { "95" };
                let mut c = explicit(&[("cpu", soft)], LimitSource::Cli);
                c.no_rlimits = Some(true);
                apply_sandbox(&c, false).expect("apply_sandbox");
                let want = soft.parse::<u64>().unwrap();
                assert_eq!(
                    getrlimit(Resource::RLIMIT_CPU).expect("getrlimit"),
                    (want, 100)
                );
            }
            other => panic!("unknown child case {other:?}"),
        }
    }
}

// The supervisor keeps its `core` and `nofile` defaults whatever explicit
// values are given, and the README says `--lockdown` clamps with a
// warning instead of refusing.
//
// Contract the implementation must meet:
// - `supervisor_limits(config: &Config) -> Vec<EffectiveLimit>` is the pure
//   function that computes the limits `apply` sets on the supervisor (the
//   ai-jail process that holds the PTY loop, the egress proxy and its secret
//   substitution, and the audit writer). `apply` applies exactly that set,
//   so a default is never skipped because an explicit value of the same
//   name exists.
// - With the default set on, the supervisor set holds `core` 0 and the
//   `nofile` default (65536; 4096 under `--lockdown`), each with hard ==
//   soft, whatever explicit `core`/`nofile` values are given. An explicit
//   value for those names reaches the sandbox only.
// - It never holds `nproc` (counted against bwrap's clone()) nor an
//   explicit `cpu`, `data` or `as`, which would kill or cap the supervisor.
// - Under `--no-rlimits` it is empty: an explicit value never moves onto
//   the supervisor.
// Expected values are the literals the README and design state (65536,
// 4096, 0), never recomputed from `default_limits`.
#[cfg(test)]
mod rlimit_supervisor_tests {
    use std::collections::BTreeMap;

    use super::*;

    const CHILD_ENV: &str = "AI_JAIL_SUPERVISOR_CHILD";

    fn explicit(pairs: &[(&str, &str)]) -> Config {
        Config {
            rlimit: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            rlimit_source: pairs
                .iter()
                .map(|(k, _)| (k.to_string(), LimitSource::Cli))
                .collect::<BTreeMap<_, _>>(),
            ..Config::default()
        }
    }

    /// The supervisor set as `(name, soft, hard)`, sorted by name.
    fn supervisor_set(config: &Config) -> Vec<(RlimitName, u64, u64)> {
        let mut set: Vec<(RlimitName, u64, u64)> = supervisor_limits(config)
            .iter()
            .map(|l| (l.name, l.soft, l.hard))
            .collect();
        set.sort();
        set
    }

    fn entry(
        set: &[(RlimitName, u64, u64)],
        name: RlimitName,
    ) -> Option<(u64, u64)> {
        set.iter()
            .find(|(n, ..)| *n == name)
            .map(|(_, soft, hard)| (*soft, *hard))
    }

    #[test]
    fn supervisor_set_never_holds_an_explicit_cpu_data_or_as() {
        // Guard first: keeping the core/nofile defaults must not drag the
        // other explicit values onto the supervisor.
        for pairs in [
            &[("cpu", "10")][..],
            &[("cpu", "10"), ("data", "8G"), ("as", "16G")][..],
            &[("cpu", "10"), ("core", "0"), ("nofile", "65536")][..],
        ] {
            let set = supervisor_set(&explicit(pairs));
            for name in [
                RlimitName::Cpu,
                RlimitName::Data,
                RlimitName::As,
                RlimitName::Nproc,
            ] {
                assert_eq!(
                    entry(&set, name),
                    None,
                    "{pairs:?}: the supervisor must not hold {}: {set:?}",
                    name.as_str()
                );
            }
        }
    }

    #[test]
    fn supervisor_set_is_empty_under_no_rlimits_even_with_explicit_core() {
        // Guard: with the default set off, an explicit value is the
        // sandbox's alone and never becomes a supervisor limit.
        let mut config = explicit(&[("core", "0"), ("nofile", "65536")]);
        config.no_rlimits = Some(true);
        let set = supervisor_set(&config);
        assert!(set.is_empty(), "--no-rlimits: {set:?}");
    }

    #[test]
    fn supervisor_set_keeps_core_and_nofile_defaults_given_explicitly() {
        // Asking for the default values must keep them on the supervisor,
        // not leave core unlimited and nofile at the host's.
        let set =
            supervisor_set(&explicit(&[("core", "0"), ("nofile", "65536")]));
        assert_eq!(entry(&set, RlimitName::Core), Some((0, 0)), "{set:?}");
        assert_eq!(
            entry(&set, RlimitName::Nofile),
            Some((65536, 65536)),
            "{set:?}"
        );
    }

    #[test]
    fn supervisor_set_keeps_defaults_when_explicit_core_nofile_differ() {
        // A different explicit value is the sandbox's, not the
        // supervisor's: a looser core does not make the supervisor
        // dumpable, and a tighter nofile does not starve the proxy.
        let set =
            supervisor_set(&explicit(&[("core", "1024"), ("nofile", "1024")]));
        assert_eq!(entry(&set, RlimitName::Core), Some((0, 0)), "{set:?}");
        assert_eq!(
            entry(&set, RlimitName::Nofile),
            Some((65536, 65536)),
            "{set:?}"
        );
    }

    #[test]
    fn supervisor_set_keeps_lockdown_defaults_given_explicit_values() {
        let mut config = explicit(&[("core", "0"), ("nofile", "1024")]);
        config.lockdown = Some(true);
        let set = supervisor_set(&config);
        assert_eq!(entry(&set, RlimitName::Core), Some((0, 0)), "{set:?}");
        assert_eq!(
            entry(&set, RlimitName::Nofile),
            Some((4096, 4096)),
            "{set:?}"
        );
    }

    #[test]
    fn supervisor_apply_sets_core_and_nofile_defaults_despite_explicit() {
        // Through `apply` itself, in a child test process: lowering a hard
        // limit cannot be undone.
        let output = std::process::Command::new(
            std::env::current_exe().unwrap(),
        )
        .arg("--exact")
        .arg("sandbox::rlimits::rlimit_supervisor_tests::supervisor_child")
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn child supervisor test");
        assert!(
            output.status.success(),
            "child supervisor test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn supervisor_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        // Start from a dumpable process with a host `nofile` soft limit
        // below the default.
        let (_, core_hard) = getrlimit(Resource::RLIMIT_CORE).expect("core");
        setrlimit(Resource::RLIMIT_CORE, core_hard, core_hard)
            .expect("raise core soft to hard");
        let (_, nofile_hard) =
            getrlimit(Resource::RLIMIT_NOFILE).expect("nofile");
        assert!(nofile_hard >= 65536, "test needs NOFILE hard >= 65536");
        setrlimit(Resource::RLIMIT_NOFILE, 1024, nofile_hard)
            .expect("lower nofile soft");

        apply(&explicit(&[("core", "0"), ("nofile", "65536")]), false)
            .expect("apply");

        assert_eq!(
            getrlimit(Resource::RLIMIT_CORE).expect("core"),
            (0, 0),
            "the supervisor's core size after --rlimit core=0"
        );
        assert_eq!(
            getrlimit(Resource::RLIMIT_NOFILE).expect("nofile"),
            (65536, 65536),
            "the supervisor's nofile after --rlimit nofile=65536"
        );
    }

    /// The `--lockdown` clauses of the bullets in the README's
    /// resource-limits section (the intro paragraph lists the lockdown
    /// defaults, not what happens to an explicit value).
    fn readme_lockdown_clauses() -> Vec<String> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
        let readme = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let start = readme
            .find("### Resource limits without root")
            .expect("README has the resource-limits section");
        let section = &readme[start..];
        let body_start = section.find('\n').map_or(section.len(), |i| i + 1);
        let end = section[body_start..]
            .find("\n#")
            .map_or(section.len(), |i| body_start + i);
        section[body_start..end]
            .split("\n- ")
            .skip(1)
            .map(|bullet| {
                bullet.split_whitespace().collect::<Vec<_>>().join(" ")
            })
            .flat_map(|bullet| {
                bullet
                    .split("; ")
                    .flat_map(|c| c.split(". "))
                    .map(|c| c.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|c| c.contains("`--lockdown`"))
            .collect()
    }

    #[test]
    fn supervisor_readme_lockdown_clause_clamps_with_a_warning() {
        // A value above a lockdown default runs at that default with
        // a warning; the launch is not refused.
        let clauses = readme_lockdown_clauses();
        assert!(
            !clauses.is_empty(),
            "the section still says what --lockdown does to an explicit value"
        );
        for clause in &clauses {
            assert!(
                !clause.to_ascii_lowercase().contains("refus"),
                "README says --lockdown refuses: {clause:?}"
            );
        }
        assert!(
            clauses
                .iter()
                .any(|c| c.to_ascii_lowercase().contains("warn")),
            "README names the warning: {clauses:?}"
        );
    }
}

// Under `--lockdown` the supervisor keeps the 1 GiB `fsize` default
// whatever explicit `fsize` is given, from the CLI or from a project
// policy the operator never reviewed. Appended to `src/sandbox/rlimits.rs`.
//
// Keeping the default never constrains the sandbox: under `--lockdown` an
// explicit `fsize` is clamped to at most 1 GiB, and a process can always
// lower its own hard limit, so the wrapper still applies the smaller
// explicit value. Dropping the default, on the other hand, leaves the
// supervisor (the PTY loop, the egress proxy and the audit writer) with no
// file-size limit at all.
//
// `cpu`, `data` and `as` have no supervisor default; an explicit value for
// them stays the sandbox's alone, since on the supervisor it would kill or
// cap it and orphan the sandbox.
//
// Expected values are the literals lockdown documents (1 GiB, 512 MiB),
// never recomputed from `default_limits`.
#[cfg(test)]
mod supervisor_fsize_tests {
    use std::collections::BTreeMap;

    use super::*;

    const ONE_GIB: u64 = 1_073_741_824;
    const CHILD_ENV: &str = "AI_JAIL_SUPERVISOR_FSIZE_CHILD";

    fn config_with(pairs: &[(&str, &str)], source: LimitSource) -> Config {
        Config {
            rlimit: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            rlimit_source: pairs
                .iter()
                .map(|(k, _)| (k.to_string(), source))
                .collect::<BTreeMap<_, _>>(),
            ..Config::default()
        }
    }

    fn lockdown_with(pairs: &[(&str, &str)], source: LimitSource) -> Config {
        let mut config = config_with(pairs, source);
        config.lockdown = Some(true);
        config
    }

    /// The supervisor set as `(name, soft, hard, source)`, sorted by name.
    fn supervisor_set(
        config: &Config,
    ) -> Vec<(RlimitName, u64, u64, LimitSource)> {
        let mut set: Vec<_> = supervisor_limits(config)
            .iter()
            .map(|l| (l.name, l.soft, l.hard, l.source))
            .collect();
        set.sort_by_key(|(name, ..)| *name);
        set
    }

    /// The supervisor's `fsize` entry as `(soft, hard, source)`.
    fn fsize_entry(config: &Config) -> Option<(u64, u64, LimitSource)> {
        supervisor_limits(config)
            .into_iter()
            .find(|l| l.name == RlimitName::Fsize)
            .map(|l| (l.soft, l.hard, l.source))
    }

    #[test]
    fn supervisor_fsize_holds_no_fsize_without_lockdown() {
        // Guard, green by design: only lockdown has an `fsize` default, so
        // keeping that default must not invent one for a normal launch,
        // and an explicit value never moves onto the supervisor.
        for pairs in [&[][..], &[("fsize", "512M")][..]] {
            let config = config_with(pairs, LimitSource::Cli);
            assert_eq!(
                fsize_entry(&config),
                None,
                "{pairs:?} without --lockdown: {:?}",
                supervisor_set(&config)
            );
        }
    }

    #[test]
    fn supervisor_fsize_keeps_cpu_data_as_off_under_lockdown() {
        // Guard, green by design: `cpu`, `data` and `as` have no default,
        // and an explicit value for them on the supervisor would kill or
        // cap it. Keeping `fsize` must not drag them along.
        let config = lockdown_with(
            &[
                ("cpu", "10"),
                ("data", "8G"),
                ("as", "16G"),
                ("fsize", "512M"),
            ],
            LimitSource::Cli,
        );
        let set = supervisor_set(&config);
        for name in [
            RlimitName::Cpu,
            RlimitName::Data,
            RlimitName::As,
            RlimitName::Nproc,
        ] {
            assert!(
                set.iter().all(|(n, ..)| *n != name),
                "the supervisor must not hold {}: {set:?}",
                name.as_str()
            );
        }
    }

    #[test]
    fn supervisor_fsize_is_empty_under_no_rlimits() {
        // Guard, green by design: with the default set off, an explicit
        // `fsize` is the sandbox's alone.
        let mut config = lockdown_with(&[("fsize", "512M")], LimitSource::Cli);
        config.no_rlimits = Some(true);
        let set = supervisor_set(&config);
        assert!(set.is_empty(), "--no-rlimits: {set:?}");
    }

    #[test]
    fn supervisor_fsize_keeps_lockdown_default_under_cli_fsize() {
        // `--lockdown --rlimit fsize=512M` must keep lockdown's file size
        // on the supervisor. The 512 MiB is the sandbox's: the supervisor
        // holds the default, not the explicit value.
        let config = lockdown_with(&[("fsize", "512M")], LimitSource::Cli);
        assert_eq!(
            fsize_entry(&config),
            Some((ONE_GIB, ONE_GIB, LimitSource::Default)),
            "{:?}",
            supervisor_set(&config)
        );
    }

    #[test]
    fn supervisor_fsize_keeps_lockdown_default_under_project_fsize() {
        // A project policy is untrusted input: its `fsize` must not
        // loosen the process that holds the proxy's secrets.
        let config = lockdown_with(&[("fsize", "512M")], LimitSource::Project);
        assert_eq!(
            fsize_entry(&config),
            Some((ONE_GIB, ONE_GIB, LimitSource::Default)),
            "{:?}",
            supervisor_set(&config)
        );
    }

    #[test]
    fn supervisor_fsize_keeps_lockdown_default_given_the_default_value() {
        // Asking for exactly the default must not remove it either.
        let config = lockdown_with(&[("fsize", "1G")], LimitSource::Cli);
        assert_eq!(
            fsize_entry(&config),
            Some((ONE_GIB, ONE_GIB, LimitSource::Default)),
            "{:?}",
            supervisor_set(&config)
        );
    }

    #[test]
    fn supervisor_fsize_apply_sets_lockdown_default_despite_explicit() {
        // Through `apply` itself, in a child test process: lowering a hard
        // limit cannot be undone in this one.
        let output = std::process::Command::new(
            std::env::current_exe().unwrap(),
        )
        .arg("--exact")
        .arg("sandbox::rlimits::supervisor_fsize_tests::supervisor_fsize_child")
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn child supervisor test");
        assert!(
            output.status.success(),
            "child supervisor test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn supervisor_fsize_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let (_, hard) = getrlimit(Resource::RLIMIT_FSIZE).expect("fsize");
        assert!(hard > ONE_GIB, "test needs FSIZE hard above 1 GiB");

        apply(
            &lockdown_with(&[("fsize", "512M")], LimitSource::Cli),
            false,
        )
        .expect("apply");

        assert_eq!(
            getrlimit(Resource::RLIMIT_FSIZE).expect("fsize"),
            (ONE_GIB, ONE_GIB),
            "the supervisor's file size after --lockdown --rlimit fsize=512M"
        );
    }
}

// The effective view reports the value the sandbox actually receives, and
// every printed limit spells `RLIM_INFINITY` as `unlimited`.
//
// Why a ceiling exists: the supervisor always applies its `core` and
// `nofile` defaults with hard pinned to soft, and the sandbox inherits that
// hard limit, so an explicit value above it can never be reached. The
// effective view must say so instead of repeating the request.
//
// - `EffectiveLimit.ceiling: Option<LimitCeiling>`, `Some` only when the
//   supervisor ceiling changed the value;
// - `LimitCeiling::Supervisor`, with `as_str()` == "supervisor" (the text
//   of `ceiling=` on the dry-run line);
// - `pub fn fmt_rlim(v: u64) -> String`.
// `unlimited` is RLIM_INFINITY, which is u64::MAX on Linux.
#[cfg(test)]
mod effective_ceiling_tests {
    use std::collections::BTreeMap;

    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let rlimit: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let rlimit_source: BTreeMap<String, LimitSource> = pairs
            .iter()
            .map(|(k, _)| (k.to_string(), LimitSource::Cli))
            .collect();
        Config {
            rlimit,
            rlimit_source,
            ..Config::default()
        }
    }

    fn limits(config: &Config) -> Vec<EffectiveLimit> {
        match effective(config) {
            Ok(v) => v,
            Err(e) => panic!("effective() must succeed, got Err({e})"),
        }
    }

    fn find<'a>(
        limits: &'a [EffectiveLimit],
        name: &str,
    ) -> &'a EffectiveLimit {
        limits
            .iter()
            .find(|l| l.name.as_str() == name)
            .unwrap_or_else(|| panic!("no effective limit named {name}"))
    }

    fn pair(limits: &[EffectiveLimit], name: &str) -> (u64, u64) {
        let l = find(limits, name);
        (l.soft, l.hard)
    }

    fn marker(limits: &[EffectiveLimit], name: &str) -> Option<&'static str> {
        find(limits, name).ceiling.map(LimitCeiling::as_str)
    }

    #[test]
    fn effective_leaves_values_within_the_ceiling_unmarked() {
        // The marker must not fire where the ceiling changed nothing: a
        // value equal to the supervisor default or below it is what the
        // sandbox gets, as asked.
        for (nofile, core) in [("65536", "0"), ("1024", "0")] {
            let got = limits(&config(&[("nofile", nofile), ("core", core)]));
            let want: u64 = nofile.parse().unwrap();
            assert_eq!(pair(&got, "nofile"), (want, want), "nofile={nofile}");
            assert_eq!(pair(&got, "core"), (0, 0));
            assert_eq!(marker(&got, "nofile"), None, "nofile={nofile}");
            assert_eq!(marker(&got, "core"), None);
            assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));
        }
        // Defaults are never marked: they are the ceiling.
        for l in limits(&Config::default()) {
            assert!(l.ceiling.is_none(), "{} marked", l.name.as_str());
        }
    }

    #[test]
    fn effective_clamps_core_and_nofile_to_the_supervisor_default() {
        let got =
            limits(&config(&[("nofile", "100000"), ("core", "unlimited")]));
        assert_eq!(pair(&got, "nofile"), (65536, 65536));
        assert_eq!(pair(&got, "core"), (0, 0));
        assert_eq!(marker(&got, "nofile"), Some("supervisor"));
        assert_eq!(marker(&got, "core"), Some("supervisor"));
        // The layer that asked is still the one reported.
        assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));
        assert!(matches!(find(&got, "core").source, LimitSource::Cli));
    }

    #[test]
    fn effective_ceiling_reaches_only_limits_the_supervisor_holds() {
        // Limits with no supervisor default are not capped by it: the
        // supervisor never applies an explicit `data`, `as`, `fsize` or
        // `cpu`, so the sandbox can be given any of them.
        let got = limits(&config(&[
            ("nofile", "100000"),
            ("data", "unlimited"),
            ("as", "unlimited"),
            ("fsize", "unlimited"),
            ("cpu", "600"),
        ]));
        assert_eq!(pair(&got, "nofile"), (65536, 65536));
        for name in ["data", "as", "fsize"] {
            assert_eq!(pair(&got, name), (u64::MAX, u64::MAX), "{name}");
            assert_eq!(marker(&got, name), None, "{name}");
        }
        assert_eq!(pair(&got, "cpu"), (600, 605));
        assert_eq!(marker(&got, "cpu"), None);
    }

    #[test]
    fn effective_without_the_default_set_reports_the_request_unmarked() {
        // `--no-rlimits` leaves the supervisor without its defaults, so
        // there is no ceiling and the request is what the sandbox gets.
        let mut c = config(&[("nofile", "100000"), ("core", "unlimited")]);
        c.no_rlimits = Some(true);
        let got = limits(&c);
        assert_eq!(pair(&got, "nofile"), (100000, 100000));
        assert_eq!(pair(&got, "core"), (u64::MAX, u64::MAX));
        assert_eq!(marker(&got, "nofile"), None);
        assert_eq!(marker(&got, "core"), None);
    }

    #[test]
    fn effective_under_lockdown_reports_the_lockdown_supervisor_value() {
        // Under lockdown the supervisor holds `nofile` at 4096, so the
        // value reported is 4096 whatever was asked above it.
        let mut c = config(&[("nofile", "100000"), ("core", "unlimited")]);
        c.lockdown = Some(true);
        let got = limits(&c);
        assert_eq!(pair(&got, "nofile"), (4096, 4096));
        assert_eq!(pair(&got, "core"), (0, 0));
    }

    #[test]
    fn fmt_rlim_spells_infinity_as_unlimited() {
        assert_eq!(fmt_rlim(nix::libc::RLIM_INFINITY), "unlimited");
        assert_eq!(fmt_rlim(4096), "4096");
    }

    #[test]
    fn fmt_rlim_keeps_every_finite_value_a_plain_number() {
        // Only RLIM_INFINITY itself is `unlimited`: the largest finite
        // value and zero must not collide with it, and no digit grouping
        // is added, since the dry-run line is read by scripts.
        assert_eq!(
            fmt_rlim(nix::libc::RLIM_INFINITY - 1),
            "18446744073709551614"
        );
        assert_eq!(fmt_rlim(0), "0");
        assert_eq!(fmt_rlim(65536), "65536");
        assert_eq!(fmt_rlim(1073741824), "1073741824");
    }
}

#[cfg(test)]
mod clamp_to_host_tests {
    use std::collections::BTreeMap;

    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let rlimit: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let rlimit_source: BTreeMap<String, LimitSource> = pairs
            .iter()
            .map(|(k, _)| (k.to_string(), LimitSource::Cli))
            .collect();
        Config {
            rlimit,
            rlimit_source,
            ..Config::default()
        }
    }

    /// `effective()` for `pairs`, then clamped against a fake host whose
    /// hard limits are `host`; a name missing from `host` reads as
    /// unknown (`None`).
    fn clamped(
        pairs: &[(&str, &str)],
        host: &[(RlimitName, u64)],
    ) -> Vec<EffectiveLimit> {
        let mut limits = match effective(&config(pairs)) {
            Ok(v) => v,
            Err(e) => panic!("effective() must succeed, got Err({e})"),
        };
        let host: BTreeMap<RlimitName, u64> = host.iter().copied().collect();
        clamp_to_host(&mut limits, |name| host.get(&name).copied());
        limits
    }

    fn find<'a>(
        limits: &'a [EffectiveLimit],
        name: &str,
    ) -> &'a EffectiveLimit {
        limits
            .iter()
            .find(|l| l.name.as_str() == name)
            .unwrap_or_else(|| panic!("no effective limit named {name}"))
    }

    fn pair(limits: &[EffectiveLimit], name: &str) -> (u64, u64) {
        let l = find(limits, name);
        (l.soft, l.hard)
    }

    fn marker(limits: &[EffectiveLimit], name: &str) -> Option<&'static str> {
        find(limits, name).ceiling.map(LimitCeiling::as_str)
    }

    #[test]
    fn clamp_to_host_leaves_values_within_the_host_limit_unmarked() {
        // The marker must not fire where the host changed nothing: below
        // the host limit, exactly at it, and with the host unlimited.
        let got = clamped(
            &[("nofile", "1024"), ("cpu", "60")],
            &[(RlimitName::Nofile, 2048), (RlimitName::Cpu, 65)],
        );
        assert_eq!(pair(&got, "nofile"), (1024, 1024));
        assert_eq!(marker(&got, "nofile"), None);
        assert_eq!(pair(&got, "cpu"), (60, 65));
        assert_eq!(marker(&got, "cpu"), None);

        let got = clamped(&[("nofile", "2048")], &[(RlimitName::Nofile, 2048)]);
        assert_eq!(pair(&got, "nofile"), (2048, 2048));
        assert_eq!(marker(&got, "nofile"), None);

        let got = clamped(
            &[("cpu", "60"), ("as", "unlimited")],
            &[
                (RlimitName::Cpu, nix::libc::RLIM_INFINITY),
                (RlimitName::As, nix::libc::RLIM_INFINITY),
            ],
        );
        assert_eq!(pair(&got, "cpu"), (60, 65));
        assert_eq!(pair(&got, "as"), (u64::MAX, u64::MAX));
        assert_eq!(marker(&got, "cpu"), None);
        assert_eq!(marker(&got, "as"), None);
    }

    #[test]
    fn clamp_to_host_keeps_the_supervisor_ceiling_when_it_is_lower() {
        // Both ceilings bind only nominally here: the supervisor's 65536
        // is the lower one, so it stays the value and the name shown. A
        // host limit equal to it does not take the marker either.
        for host in [70000, 65536] {
            let got =
                clamped(&[("nofile", "100000")], &[(RlimitName::Nofile, host)]);
            assert_eq!(pair(&got, "nofile"), (65536, 65536), "host {host}");
            assert_eq!(marker(&got, "nofile"), Some("supervisor"), "{host}");
        }
    }

    #[test]
    fn clamp_to_host_marks_the_host_when_it_is_below_the_supervisor() {
        let got =
            clamped(&[("nofile", "100000")], &[(RlimitName::Nofile, 2048)]);
        assert_eq!(pair(&got, "nofile"), (2048, 2048));
        assert_eq!(marker(&got, "nofile"), Some("host"));
        // The layer that asked is still the one reported.
        assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));
    }

    #[test]
    fn clamp_to_host_lowers_an_explicit_value_above_the_host_limit() {
        let got = clamped(&[("nofile", "3000")], &[(RlimitName::Nofile, 2048)]);
        assert_eq!(pair(&got, "nofile"), (2048, 2048));
        assert_eq!(marker(&got, "nofile"), Some("host"));
        assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));

        // `unlimited` is a value like any other: a finite host limit
        // bounds it.
        let got = clamped(
            &[("as", "unlimited")],
            &[(RlimitName::As, 8 * 1024 * 1024 * 1024)],
        );
        assert_eq!(pair(&got, "as"), (8589934592, 8589934592));
        assert_eq!(marker(&got, "as"), Some("host"));
    }

    #[test]
    fn clamp_to_host_gives_cpu_the_host_limit_as_soft_and_hard() {
        // The host hard limit is below the soft limit itself: the kernel
        // bounds both values by it, so there is no grace left at all.
        let got = clamped(&[("cpu", "60")], &[(RlimitName::Cpu, 30)]);
        assert_eq!(pair(&got, "cpu"), (30, 30));
        assert_eq!(marker(&got, "cpu"), Some("host"));
        assert!(matches!(find(&got, "cpu").source, LimitSource::Cli));

        let got = clamped(&[("cpu", "unlimited")], &[(RlimitName::Cpu, 30)]);
        assert_eq!(pair(&got, "cpu"), (30, 30));
        assert_eq!(marker(&got, "cpu"), Some("host"));
    }

    #[test]
    fn clamp_to_host_shortens_the_cpu_grace_to_the_host_limit() {
        // The soft limit fits under the host limit, the five-second grace
        // above it does not: the hard value is the host's.
        let got = clamped(&[("cpu", "60")], &[(RlimitName::Cpu, 62)]);
        assert_eq!(pair(&got, "cpu"), (60, 62));
        // Only the grace shrank, and the line still says why the hard
        // value is not the soft value plus five.
        assert_eq!(marker(&got, "cpu"), Some("host"));

        let got = clamped(&[("cpu", "60")], &[(RlimitName::Cpu, 60)]);
        assert_eq!(pair(&got, "cpu"), (60, 60));
    }

    #[test]
    fn clamp_to_host_touches_only_the_names_the_host_bounds() {
        // A low host limit on one resource must not leak into another,
        // and an unreadable host limit (`None`) changes nothing.
        let got = clamped(
            &[("nofile", "3000"), ("cpu", "60"), ("fsize", "64M")],
            &[(RlimitName::Nofile, 2048)],
        );
        assert_eq!(pair(&got, "nofile"), (2048, 2048));
        assert_eq!(pair(&got, "cpu"), (60, 65));
        assert_eq!(pair(&got, "fsize"), (67108864, 67108864));
        assert_eq!(pair(&got, "core"), (0, 0));
        assert_eq!(marker(&got, "cpu"), None);
        assert_eq!(marker(&got, "fsize"), None);
        assert_eq!(marker(&got, "core"), None);
        assert!(matches!(find(&got, "core").source, LimitSource::Default));

        let got = clamped(&[("nofile", "3000"), ("cpu", "60")], &[]);
        assert_eq!(pair(&got, "nofile"), (3000, 3000));
        assert_eq!(pair(&got, "cpu"), (60, 65));
        assert_eq!(marker(&got, "nofile"), None);
        assert_eq!(marker(&got, "cpu"), None);
    }

    #[test]
    fn clamp_to_host_marks_a_default_the_host_lowers() {
        // The defaults are bounded by the host like any other value; the
        // source stays `default`.
        let got = clamped(&[], &[(RlimitName::Nofile, 1024)]);
        assert_eq!(pair(&got, "nofile"), (1024, 1024));
        assert_eq!(marker(&got, "nofile"), Some("host"));
        assert!(matches!(find(&got, "nofile").source, LimitSource::Default));
    }

    #[test]
    fn clamp_to_host_names_its_ceiling_host() {
        assert_eq!(LimitCeiling::Host.as_str(), "host");
        assert_eq!(LimitCeiling::Supervisor.as_str(), "supervisor");
    }
}

// `cpu` needs at least one second of CPU time.
//
// Why a floor exists: the limit is set on the wrapper, which has already
// spent CPU time before it execs the command. At `cpu=0` the kernel sends
// SIGXCPU before `exec`, so the jail dies with exit 152 and no message.
// The grammar refuses the value instead, for `--rlimit` and for every
// config layer, saying "cpu needs at least 1 second".
//
// The floor is about `cpu` alone: `0` stays a valid value for every other
// limit (`core = 0` is the supervisor's own default).
#[cfg(test)]
mod cpu_floor_tests {
    use super::*;

    fn cpu_floor_cli(spec: &str) -> Result<crate::cli::CliArgs, String> {
        crate::cli::parse_from(lexopt::Parser::from_args(
            ["--rlimit", spec, "bash"]
                .iter()
                .map(std::ffi::OsString::from),
        ))
    }

    #[test]
    fn cpu_floor_leaves_zero_valid_for_every_other_limit() {
        // Hostile half first: a floor that fired on the value rather than
        // on the name would refuse the supervisor's own `core = 0`.
        for limit in ["nproc", "nofile", "core", "fsize", "data", "as"] {
            let name: RlimitName = limit.parse().unwrap();
            assert_eq!(
                RlimitValue::parse(name, "0"),
                Ok(RlimitValue::Finite(0)),
                "{limit}=0 must stay valid"
            );
            let spec = format!("{limit}=0");
            assert!(cpu_floor_cli(&spec).is_ok(), "--rlimit {spec}");
        }
    }

    #[test]
    fn cpu_floor_accepts_one_second_and_unlimited() {
        // Hostile half: the smallest value above the floor, and the value
        // with no limit at all, are not refused.
        assert_eq!(
            RlimitValue::parse(RlimitName::Cpu, "1"),
            Ok(RlimitValue::Finite(1))
        );
        assert_eq!(
            RlimitValue::parse(RlimitName::Cpu, "unlimited"),
            Ok(RlimitValue::Unlimited)
        );
        for spec in ["cpu=1", "cpu=unlimited"] {
            let args = cpu_floor_cli(spec)
                .unwrap_or_else(|e| panic!("--rlimit {spec}: {e}"));
            let (_, value) = spec.split_once('=').unwrap();
            assert!(
                args.rlimit.iter().any(|(k, v)| k == "cpu" && v == value),
                "{:?}",
                args.rlimit
            );
        }
    }

    #[test]
    fn cpu_floor_refuses_zero_in_every_spelling() {
        // Hostile half: "00" is the same zero spelled differently, and a
        // check on the text instead of the value would let it through.
        for text in ["0", "00"] {
            let err = match RlimitValue::parse(RlimitName::Cpu, text) {
                Ok(v) => panic!("cpu={text} must be refused, got {v:?}"),
                Err(e) => e,
            };
            assert!(err.contains("cpu"), "must name the limit: {err}");
            assert!(
                err.contains("at least 1 second"),
                "must say what the floor is: {err}"
            );
        }
    }

    #[test]
    fn cpu_floor_refuses_the_cli_flag_naming_it() {
        let err = match cpu_floor_cli("cpu=0") {
            Ok(_) => panic!("--rlimit cpu=0 must be refused"),
            Err(e) => e,
        };
        assert!(err.contains("--rlimit"), "must name the flag: {err}");
        assert!(err.contains("cpu=0"), "must name the value: {err}");
        assert!(
            err.contains("at least 1 second"),
            "must say what the floor is: {err}"
        );
    }
}

// Off Linux, the refusal of an explicit limit names the layers that hold
// one, so the operator can find the file.
//
// A project policy holding `[rlimit]` refuses every non-Linux launch of
// that project; a refusal that says only "--rlimit" sends the operator to
// a flag they never passed.
//
// - `check_platform(config: &Config, linux: bool,
//   project_path: Option<&Path>) -> Result<(), String>`, where
//   `project_path` is the stored project policy; the layers come from
//   `rlimit_source`, an entry without one counting as the command line.
// The platform stays a parameter, so these run on Linux too.
#[cfg(test)]
mod platform_layer_tests {
    use std::{collections::BTreeMap, path::Path};

    use super::*;

    /// Where the policy store keeps the project's document.
    const POLICY: &str = "/srv/xdg/ai-jail/projects/proj-platform.toml";

    fn policy() -> &'static Path {
        Path::new(POLICY)
    }

    fn layered(entries: &[(&str, &str, LimitSource)]) -> Config {
        Config {
            rlimit: entries
                .iter()
                .map(|(k, v, _)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            rlimit_source: entries
                .iter()
                .map(|(k, _, s)| (k.to_string(), *s))
                .collect::<BTreeMap<_, _>>(),
            ..Config::default()
        }
    }

    fn refusal(config: &Config) -> String {
        match check_platform(config, false, Some(policy())) {
            Ok(()) => panic!("explicit limits must be refused off Linux"),
            Err(e) => e,
        }
    }

    #[test]
    fn platform_layer_cli_limit_does_not_blame_the_project() {
        // Hostile half first: the policy path is known at every launch,
        // so it must not be named for a limit it does not hold.
        let err = refusal(&layered(&[("nofile", "1024", LimitSource::Cli)]));
        assert!(err.contains("Linux only"), "{err}");
        assert!(err.contains("--rlimit"), "names the flag: {err}");
        assert!(!err.contains("project policy"), "{err}");
        assert!(!err.contains(POLICY), "names the policy: {err}");

        // An entry without a recorded source is the command line's.
        let unsourced = Config {
            rlimit: BTreeMap::from([("cpu".into(), "60".into())]),
            ..Config::default()
        };
        let err = refusal(&unsourced);
        assert!(err.contains("--rlimit"), "names the flag: {err}");
        assert!(!err.contains(POLICY), "names the policy: {err}");
    }

    #[test]
    fn platform_layer_global_limit_blames_neither_flag_nor_project() {
        let err = refusal(&layered(&[("nofile", "1024", LimitSource::Global)]));
        assert!(err.contains("Linux only"), "{err}");
        assert!(err.contains("rlimit"), "names the control: {err}");
        assert!(!err.contains("--rlimit"), "blames the flag: {err}");
        assert!(!err.contains("project policy"), "{err}");
        assert!(!err.contains(POLICY), "names the policy: {err}");
    }

    #[test]
    fn platform_layer_project_limit_names_the_stored_policy() {
        let err = refusal(&layered(&[("nproc", "512", LimitSource::Project)]));
        assert!(err.contains("Linux only"), "{err}");
        assert!(err.contains("project policy"), "{err}");
        assert!(err.contains(POLICY), "names the path: {err}");
        assert!(!err.contains("--rlimit"), "blames the flag: {err}");
        assert!(!err.contains(".ai-jail"), "names the legacy file: {err}");
    }

    #[test]
    fn platform_layer_names_every_layer_that_holds_a_limit() {
        let err = refusal(&layered(&[
            ("nofile", "1024", LimitSource::Cli),
            ("nproc", "512", LimitSource::Project),
        ]));
        assert!(err.contains("--rlimit"), "names the flag: {err}");
        assert!(err.contains("project policy"), "{err}");
        assert!(err.contains(POLICY), "names the path: {err}");
    }

    #[test]
    fn platform_layer_accepts_what_it_accepted() {
        // Naming layers must not refuse a launch that runs.
        let project = layered(&[("nproc", "512", LimitSource::Project)]);
        assert_eq!(check_platform(&project, true, Some(policy())), Ok(()));
        assert_eq!(
            check_platform(&Config::default(), false, Some(policy())),
            Ok(())
        );
        assert_eq!(check_platform(&project, true, None), Ok(()));
    }
}
