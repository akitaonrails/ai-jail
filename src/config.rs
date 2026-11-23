use crate::cli::CliArgs;
use crate::command;
use crate::output;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = ".ai-jail";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Hard,
    Soft,
}

impl BrowserProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserProfile::Hard => "hard",
            BrowserProfile::Soft => "soft",
        }
    }
}

pub fn parse_browser_profile_spec(value: &str) -> Option<BrowserProfile> {
    match value {
        "hard" | "isolated" | "ephemeral" => Some(BrowserProfile::Hard),
        "soft" | "persistent" | "survivable" => Some(BrowserProfile::Soft),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSpec {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl MapSpec {
    pub fn parse(value: &Path) -> Result<Self, String> {
        let bytes = value.as_os_str().as_bytes();
        let Some(separator) = bytes.iter().position(|byte| *byte == b':')
        else {
            if bytes.is_empty() {
                return Err("map has empty source and destination".into());
            }
            return Ok(Self {
                source: value.to_path_buf(),
                destination: value.to_path_buf(),
            });
        };

        let source = &bytes[..separator];
        let destination = &bytes[separator + 1..];
        if source.is_empty() {
            return Err("map has empty source".into());
        }
        if destination.is_empty() {
            return Err("map has empty destination".into());
        }

        Ok(Self {
            source: PathBuf::from(OsString::from_vec(source.to_vec())),
            destination: PathBuf::from(OsString::from_vec(
                destination.to_vec(),
            )),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.source.as_os_str().is_empty() {
            return Err("map has empty source".into());
        }
        if self.destination.as_os_str().is_empty() {
            return Err("map has empty destination".into());
        }
        if self.source.to_str().is_none() {
            return Err("map source must be valid UTF-8".into());
        }
        if self.destination.to_str().is_none() {
            return Err("map destination must be valid UTF-8".into());
        }
        if self.source == Path::new("/") {
            return Err("map cannot use root source".into());
        }
        if self.destination == Path::new("/") {
            return Err("map cannot use root destination".into());
        }
        Ok(())
    }

    pub fn is_alternate(&self) -> bool {
        self.source != self.destination
    }

    /// Parse and validate an encoded map entry, warning and returning
    /// `None` on malformed input (warn-and-skip convention). `label`
    /// names the map kind in the warning, e.g. "read-only".
    pub fn parse_validated(encoded: &Path, label: &str) -> Option<Self> {
        let parsed = Self::parse(encoded).and_then(|spec| {
            spec.validate()?;
            Ok(spec)
        });
        match parsed {
            Ok(spec) => Some(spec),
            Err(reason) => {
                output::warn(&format!(
                    "Invalid {label} map {}: {reason}; skipping.",
                    encoded.display()
                ));
                None
            }
        }
    }

    pub fn encode(&self) -> PathBuf {
        if !self.is_alternate() {
            return self.source.clone();
        }

        let mut encoded = self.source.as_os_str().as_bytes().to_vec();
        encoded.push(b':');
        encoded.extend_from_slice(self.destination.as_os_str().as_bytes());
        PathBuf::from(OsString::from_vec(encoded))
    }
}

fn transform_map_specs(
    paths: &mut [PathBuf],
    mut transform: impl FnMut(PathBuf) -> PathBuf,
) {
    for path in paths {
        let Ok(spec) = MapSpec::parse(path) else {
            continue;
        };
        *path = MapSpec {
            source: transform(spec.source),
            destination: transform(spec.destination),
        }
        .encode();
    }
}

/// Accept `nofile = 4096` as well as `data = "8G"` in an `[rlimit]`
/// table: both are natural to write by hand, and the CLI grammar is the
/// one stored representation.
fn deserialize_rlimit_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawLimit {
        Int(u64),
        Text(String),
    }
    use crate::sandbox::rlimits::{RlimitName, RlimitValue};
    let raw = BTreeMap::<String, RawLimit>::deserialize(deserializer)?;
    let mut out = BTreeMap::new();
    for (key, value) in raw {
        let text = match value {
            RawLimit::Int(n) => n.to_string(),
            RawLimit::Text(t) => t,
        };
        // Checked at load in every layer: a typo in a limit must stop
        // the launch, never silently drop the restriction it meant.
        let name: RlimitName = key
            .parse()
            .map_err(|e| serde::de::Error::custom(format!("rlimit: {e}")))?;
        RlimitValue::parse(name, &text).map_err(serde::de::Error::custom)?;
        out.insert(key, text);
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Explicit harness identities supplied by a trusted wrapper. Runtime
    /// only: profiles store approvals, never wrapper invocation metadata.
    #[serde(default, skip)]
    pub runtime_harnesses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rw_maps: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ro_maps: Vec<PathBuf>,
    /// Copy-on-write overlay mounts: PATH is visible read-write inside
    /// the sandbox, but writes land on a side layer under
    /// `<project>/.ai-jail-overlays/` while the original stays
    /// untouched (Linux/bwrap only; read-only fallback on macOS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlay_maps: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hide_dotdirs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask_exceptions: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_path_exceptions: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_gpu: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_docker: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_display: Option<bool>,
    /// Trusted capability: expose the host audio stack — the
    /// PipeWire/PulseAudio sockets in the validated
    /// `XDG_RUNTIME_DIR`, plus `/dev/snd` for pure-ALSA clients.
    /// Opt-in (Linux only); the untrusted project `.ai-jail` may
    /// only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    /// Trusted capability: read-only mount `~/.config/gh` (GitHub CLI
    /// credentials) into the sandbox. Opt-in; the untrusted project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<bool>,
    /// Trusted capability: read-only mount `~/.aws` (AWS CLI
    /// credentials) into the sandbox. Opt-in; the untrusted project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<bool>,
    /// Trusted capability: read-only mount `~/.kube` (kubectl
    /// credentials) into the sandbox. Opt-in; the untrusted project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube: Option<bool>,
    /// Trusted capability: read-only mount `~/.config/gcloud` (gcloud
    /// CLI credentials) into the sandbox. Opt-in; the untrusted project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcloud: Option<bool>,
    /// Trusted capability: read-only mount `~/.docker/config.json`
    /// (Docker registry credentials) into the sandbox. Opt-in; the
    /// untrusted project `.ai-jail` may only disable it, never enable
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_config: Option<bool>,
    /// Trusted capability: expose `/dev/kvm` for hardware
    /// virtualization (QEMU/Firecracker/Android emulator). Opt-in
    /// (Linux only); the untrusted project `.ai-jail` may only
    /// disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvm: Option<bool>,
    /// Trusted capability: in filtered egress mode, ask through a desktop
    /// notification (`notify-send`) before refusing a host outside the
    /// allowlist. Each answer holds for the session only. Opt-in (Linux
    /// only); the untrusted project `.ai-jail` may only disable it, never
    /// enable it. `--lockdown` disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_hosts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<bool>,
    /// Permit macOS Seatbelt's broad host IPC compatibility rules. This is
    /// intentionally opt-in because those rules weaken process isolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_host_ipc: Option<bool>,
    /// Let Chromium register and look up its own Mach rendezvous service
    /// on macOS. Opt-in, but far narrower than `macos_host_ipc`: only the
    /// `*.MachPortRendezvousServer.<pid>` names are reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_chromium: Option<bool>,
    /// Let Apple's TLS trust evaluation reach `trustd` on macOS, so Go and
    /// Security.framework clients (e.g. `gh`) can verify certificates.
    /// Opt-in, but far narrower than `macos_host_ipc`: only the
    /// `com.apple.trustd.agent` lookup is granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_trustd: Option<bool>,
    /// Native clipboard access through only com.apple.pasteboard.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_pasteboard: Option<bool>,
    /// Allow the sandboxed process to open PTY slave nodes it allocates at
    /// runtime (`/dev/ttysNNN`) on macOS. Needed by tools that spawn their
    /// own pseudo-terminals -- `expect`, `script`, terminal multiplexers,
    /// and `xcodebuild` driving an iOS Simulator. Opt-in: the grant covers
    /// every `/dev/ttys*`, including the user's other terminals, so it is
    /// off by default and dropped under `--lockdown` (issue #209).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_pty: Option<bool>,
    /// Allow the sandboxed process to bind and listen on loopback while
    /// egress stays filtered (`--allow-host`) on macOS. Needed by tools
    /// that start a local server on `127.0.0.1` without dropping egress
    /// filtering the way `--network` would. Opt-in, dropped under
    /// `--lockdown` (issue #213).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_loopback_listen: Option<bool>,
    /// Allow a macOS sandbox to connect to any service bound on the host's
    /// loopback interface. This is broader than `forward_ports`, so it is an
    /// explicit trusted capability, off by default and removed by lockdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_loopback_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x11: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_shm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_passthrough: Option<bool>,
    /// Opt in to narrow terminal appearance discovery and live background
    /// change notifications in the PTY proxy. Independent of full terminal
    /// passthrough; untrusted project config may only disable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_appearance: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_worktree: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_mise: Option<bool>,
    /// Dev-toolchain cache persistence (rust/cargo, go, node, …): enabled by
    /// default. ai-jail maps a persistent jail-owned cache store and (for
    /// rust) the host toolchain binaries read-only, so builds work and their
    /// caches survive across sessions. The untrusted project `.ai-jail` may
    /// only disable it, never enable it. `--lockdown` disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_toolchains: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_save_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_hide_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pictures: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_home: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockdown: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_landlock: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_status_bar: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_bar_style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resize_redraw_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_seccomp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_rlimits: Option<bool>,
    /// Explicit per-process limits, `NAME = VALUE` in the `--rlimit`
    /// grammar. A TOML integer is accepted and stored as its
    /// decimal string so every layer compares one representation.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_rlimit_map"
    )]
    pub rlimit: BTreeMap<String, String>,
    /// Which layer supplied each `rlimit` entry, for `--dry-run` and the
    /// audit record. Runtime only: never read from or written to a file.
    #[serde(skip)]
    pub rlimit_source: BTreeMap<String, crate::sandbox::rlimits::LimitSource>,
    /// Which layer decided `cpus`, so a refusal names the file that caused
    /// it. Runtime only: never read from or written to a file.
    #[serde(skip)]
    pub cpus_source: Option<crate::sandbox::rlimits::LimitSource>,
    /// CPUs the sandbox may run on (`8,24`, `0-3`), applied as CPU
    /// affinity and locked by seccomp. The project `.ai-jail` may only
    /// narrow it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemd_user: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_tcp_ports: Vec<u16>,
    /// Hosts reachable through the filtered-egress CONNECT proxy
    /// (docs/connect-proxy-plan.md). A non-empty list selects filtered
    /// network mode; an entry matches the host itself and its
    /// subdomains. The untrusted project `.ai-jail` may only shrink
    /// this list, never grow it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Hosts whose explicit trusted grant may resolve to RFC1918/ULA or
    /// carrier-grade NAT addresses. Loopback, link-local, multicast,
    /// unspecified, and cloud-metadata addresses remain denied. This is a
    /// trusted capability: an untrusted project may not add entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_private_hosts: Vec<String>,
    /// Host loopback ports exposed on the sandbox's own loopback (Linux).
    /// Each is relayed through a Unix socket, so the private netns stays
    /// in place and only the named port crosses it. Trusted capability:
    /// the untrusted project `.ai-jail` may only shrink this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forward_ports: Vec<u16>,
    /// Sandbox loopback ports exposed on the host's 127.0.0.1 (Linux),
    /// the reverse of `forward_ports`: a jailed service becomes reachable
    /// from every process on the host's loopback. Trusted capability:
    /// the untrusted project `.ai-jail` may only shrink this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub publish_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_dir: Option<PathBuf>,
    /// Trusted capability: mount the invoked agent's own state
    /// directories and files (`~/.claude`, `~/.codex`,
    /// `~/.claude.json`, ...). Opt-in; the untrusted project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_state: Option<bool>,
    /// Trusted capability: inherit the full host environment into
    /// the sandbox. Opt-in; by default only a safe allowlist
    /// (see [`DEFAULT_ENV_ALLOWLIST`]) is passed. The project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherit_env: Option<bool>,
    /// Environment variables passed into the sandbox in addition to
    /// the default allowlist: `NAME` copies the current host value at
    /// launch, `NAME=VALUE` sets an explicit value. Trusted layers
    /// only (CLI `--env` / global config) — entries from the
    /// untrusted project `.ai-jail` are ignored. Never serialized:
    /// entries can carry secret values.
    #[serde(default, skip_serializing)]
    pub env_pass: Vec<String>,
    /// Credential files read like `--env` entries (`KEY=VALUE` lines).
    /// Each file must exist, be a user-owned regular file (not a
    /// symlink), mode 0600 or stricter, and live outside the project
    /// directory. Trusted layers only — the project `.ai-jail` is
    /// ignored. Never serialized: the paths point at secret material.
    #[serde(default, skip_serializing)]
    pub env_from_file: Vec<PathBuf>,
    /// Phantom credential bindings (issue #135): `KEY = "host"` — the
    /// sandbox env holds a placeholder for KEY and the egress proxy
    /// substitutes the real value only for requests terminating at
    /// host. Trusted layers only — the project `.ai-jail` is ignored.
    /// Never serialized: it names which variables are secrets.
    #[serde(default, skip_serializing)]
    pub secret_hosts: std::collections::BTreeMap<String, String>,
    /// Directories whose project `.ai-jail` is trusted to grant
    /// capabilities, instead of being treated as untrusted monotonic
    /// policy. A project matches when it is one of these directories or
    /// sits beneath one, compared after resolving both paths.
    ///
    /// Trusted layers only: an entry in a project `.ai-jail` is ignored,
    /// because a repository must never be able to declare itself trusted.
    /// Listing a directory means every repository you ever place under it
    /// may enable capabilities, so keep the list narrow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_project_config: Vec<PathBuf>,
    /// Trusted capability: let the status bar check GitHub for a
    /// newer ai-jail release. Opt-in (phones home); the project
    /// `.ai-jail` may only disable it, never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_check: Option<bool>,
    /// Opt-in launch audit log at `~/.local/share/ai-jail/history.jsonl`
    /// (phase 5 of docs/connect-proxy-plan.md). Enabling writes a host
    /// file, so the untrusted project `.ai-jail` may only disable it,
    /// never enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct GlobalConfig {
    #[serde(flatten)]
    pub(crate) base: Config,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) commands: BTreeMap<String, Config>,
    /// How a project is identified for saved policy. Global-only: it is
    /// trusted and never read from a project `.ai-jail`.
    #[serde(default, skip_serializing_if = "ProjectStrategy::is_basename")]
    pub(crate) project_strategy: ProjectStrategy,
    /// Named `[profiles.NAME]` tables, selected only by `--profile NAME`.
    /// Kept as raw values, not even required to be tables, so a stray or
    /// malformed entry that no launch selects cannot break a launch;
    /// `select_profile` validates the chosen one.
    #[serde(default, skip_serializing_if = "ProfilesKey::is_empty")]
    pub(crate) profiles: ProfilesKey,
}

/// The top-level `profiles` key as found. v3.3.0 has no such key and
/// ignores an unknown `profiles = 5`, so a value that is not a table is
/// kept raw instead of failing the whole file, and refused only when
/// `--profile` asks for an entry in it. Kept, not dropped,
/// so a rewrite of the global config does not lose it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ProfilesKey {
    Tables(BTreeMap<String, toml::Value>),
    NotATable(toml::Value),
}

impl Default for ProfilesKey {
    fn default() -> Self {
        ProfilesKey::Tables(BTreeMap::new())
    }
}

impl ProfilesKey {
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, ProfilesKey::Tables(map) if map.is_empty())
    }

    /// The entries `--profile` selects from, or the refusal when the key
    /// cannot hold any.
    pub(crate) fn tables(
        &self,
    ) -> Result<&BTreeMap<String, toml::Value>, String> {
        match self {
            ProfilesKey::Tables(map) => Ok(map),
            ProfilesKey::NotATable(value) => Err(format!(
                "--profile: `profiles` in the global config is of type {}, not \
                 a table: write each profile as [profiles.NAME]",
                value.type_str()
            )),
        }
    }

    /// Stable text for comparing two configs; raw TOML so a `nan` in an
    /// unselected profile still equals itself.
    fn policy_text(&self) -> Option<String> {
        match self {
            ProfilesKey::Tables(map) => toml::to_string(map).ok(),
            ProfilesKey::NotATable(value) => Some(value.to_string()),
        }
    }
}

impl Serialize for ProfilesKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ProfilesKey::Tables(map) => map.serialize(s),
            ProfilesKey::NotATable(value) => value.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for ProfilesKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Self, D::Error> {
        Ok(match toml::Value::deserialize(d)? {
            toml::Value::Table(table) => {
                ProfilesKey::Tables(table.into_iter().collect())
            }
            other => ProfilesKey::NotATable(other),
        })
    }
}

impl GlobalConfig {
    /// Whether two global configs carry the same policy. Profiles are
    /// raw TOML compared as text: a `nan` in an unselected profile is
    /// never equal to itself as a value, and must not make a rewrite of
    /// the global config look like a loss (profiles stay inert unless
    /// selected).
    pub(crate) fn same_policy(&self, other: &GlobalConfig) -> bool {
        let text = |g: &GlobalConfig| g.profiles.policy_text();
        let strip = |g: &GlobalConfig| GlobalConfig {
            profiles: ProfilesKey::default(),
            ..g.clone()
        };
        strip(self) == strip(other)
            && text(self).is_some()
            && text(self) == text(other)
    }
}

/// The only profile format this build reads (`profile_version = 1`).
const PROFILE_VERSION: i64 = 1;

/// `Config` keys a profile may not carry (see `select_profile`).
const PROFILE_REFUSED_KEYS: &[&str] = &[
    "command",
    "no_status_bar",
    "status_bar_style",
    "resize_redraw_key",
];

/// Every key `Config` deserializes, read from serde's derive: a derived
/// `Deserialize` for a struct hands its field list to `deserialize_struct`
/// before reading anything. `Config` has no `flatten`, which would bypass
/// that call; `config_schema_keys_lists_every_field` fails if one appears.
fn config_schema_keys() -> &'static [&'static str] {
    use serde::de::{self, Visitor};

    #[derive(Debug)]
    struct Stop;
    impl std::fmt::Display for Stop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("field probe")
        }
    }
    impl std::error::Error for Stop {}
    impl de::Error for Stop {
        fn custom<T: std::fmt::Display>(_: T) -> Self {
            Stop
        }
    }

    struct FieldProbe<'a>(&'a mut &'static [&'static str]);
    impl<'de> de::Deserializer<'de> for FieldProbe<'_> {
        type Error = Stop;
        fn deserialize_any<V: Visitor<'de>>(
            self,
            _: V,
        ) -> Result<V::Value, Stop> {
            Err(Stop)
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Stop> {
            *self.0 = fields;
            Err(Stop)
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str
            string bytes byte_buf option unit unit_struct newtype_struct seq
            tuple tuple_struct map enum identifier ignored_any
        }
    }

    static KEYS: std::sync::OnceLock<&'static [&'static str]> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let mut fields: &'static [&'static str] = &[];
        // The probe always stops with `Stop`; only the captured list matters.
        let _ = <Config as serde::Deserialize>::deserialize(FieldProbe(
            &mut fields,
        ));
        fields
    })
}

/// The fields whose values are secrets, and the TOML shape each takes.
const SECRET_FIELD_TYPES: &[(&str, &str)] = &[
    ("env_pass", "an array of strings"),
    ("env_from_file", "an array of strings"),
    ("secret_hosts", "a table of strings"),
];

/// Refuse a secret field of the wrong shape before serde sees it: serde's
/// message quotes the value, and the value is the secret.
fn check_secret_field_types(
    name: &str,
    table: &toml::Table,
) -> Result<(), String> {
    for (field, expected) in SECRET_FIELD_TYPES {
        let Some(value) = table.get(*field) else {
            continue;
        };
        let ok = match value {
            toml::Value::Array(items) => {
                *field != "secret_hosts" && items.iter().all(|v| v.is_str())
            }
            toml::Value::Table(items) => {
                *field == "secret_hosts" && items.values().all(|v| v.is_str())
            }
            _ => false,
        };
        if !ok {
            return Err(format!(
                "profile '{name}': {field} must be {expected}; the value is not shown"
            ));
        }
    }
    Ok(())
}

/// Report only the top-level schema key and a known type description.
/// Parser diagnostics can include excerpts of malformed values.
fn value_free_error(name: &str, error: &str) -> String {
    let field = error.rfind("in `").and_then(|at| {
        let path = &error[at + 4..];
        let (field, _) = path.split_once('`')?;
        config_schema_keys()
            .iter()
            .copied()
            .find(|key| *key == field)
    });
    let expected = error
        .rfind("expected ")
        .and_then(|at| error[at + 9..].lines().next())
        .and_then(|kind| {
            ["a boolean", "an integer", "a sequence", "a string", "a map"]
                .into_iter()
                .find(|known| *known == kind.trim())
        });
    match (field, expected) {
        (Some(field), Some(expected)) => format!(
            "profile '{name}': {field} has the wrong type, expected {expected}; the value is not shown"
        ),
        (Some(field), None) => format!(
            "profile '{name}': {field} is invalid; the value is not shown"
        ),
        _ => format!(
            "profile '{name}': a value has the wrong type; the value is not shown"
        ),
    }
}

/// Profile names: `^[a-z0-9][a-z0-9_-]{0,63}$`. Written by hand so no
/// regex crate is needed; nothing is normalised, so `agent-test` and
/// `agent_test` stay two names.
fn valid_profile_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    first_ok
        && bytes.len() <= 64
        && bytes[1..].iter().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || *b == b'_'
                || *b == b'-'
        })
}

/// Select and validate one `[profiles.NAME]` table from the trusted
/// global config. A profile is untrusted-shaped input even though it
/// lives in a trusted file: a typo in a restriction must fail the launch
/// rather than be dropped, so every check here fails closed.
pub(crate) fn select_profile(
    profiles: &BTreeMap<String, toml::Value>,
    name: &str,
) -> Result<Config, String> {
    if !valid_profile_name(name) {
        return Err(format!(
            "invalid profile name {:?}: must match [a-z0-9][a-z0-9_-]{{0,63}}",
            output::escape_control_bytes(name)
        ));
    }
    let Some(value) = profiles.get(name) else {
        let defined: Vec<&str> = profiles.keys().map(String::as_str).collect();
        let defined = if defined.is_empty() {
            "none".to_string()
        } else {
            defined.join(", ")
        };
        return Err(format!(
            "profile '{name}' is not defined in the global config \
             (defined profiles: {defined})"
        ));
    };
    let Some(table) = value.as_table() else {
        return Err(format!(
            "profile '{name}' is of type {}, not a table: write it as \
             [profiles.{name}]",
            value.type_str()
        ));
    };
    let mut table = table.clone();
    check_secret_field_types(name, &table)?;
    match table.remove("profile_version") {
        Some(toml::Value::Integer(PROFILE_VERSION)) => {}
        Some(_) => {
            return Err(format!(
                "profile '{name}': this profile_version is not supported; \
                 this ai-jail reads profile_version = {PROFILE_VERSION} (the \
                 value is not shown)"
            ));
        }
        None => {
            return Err(format!(
                "profile '{name}': profile_version is missing; add \
                 profile_version = {PROFILE_VERSION}"
            ));
        }
    }
    if table.contains_key("trust_project_config") {
        return Err(format!(
            "profile '{name}': trust_project_config is only read from the \
             global base config, never from a profile"
        ));
    }
    // `command` would switch programs after the command table was chosen,
    // so the new program would run under the old program's table; the UI
    // preferences are never applied from a trusted layer. Refusing all
    // four is the honest answer to a key that would otherwise do nothing
    // or the wrong thing.
    if let Some(key) = PROFILE_REFUSED_KEYS
        .iter()
        .find(|key| table.contains_key(**key))
    {
        return Err(format!(
            "profile '{name}': {key} cannot be set in a profile; set it in \
             the global config or on the command line"
        ));
    }
    let config: Config = toml::Value::Table(table.clone())
        .try_into()
        .map_err(|e| value_free_error(name, &e.to_string()))?;
    // Judged against the struct's own field list, not a serialize round
    // trip: the round trip drops empty arrays and tables, so a misspelt key
    // holding `[]` or an empty `[profiles.NAME.key]` table passed unseen
    // (maintainer's review of #230).
    let schema = config_schema_keys();
    let unknown: Vec<String> = table
        .keys()
        .filter(|key| !schema.contains(&key.as_str()))
        .map(|key| output::escape_control_bytes(key))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "profile '{name}': unknown key(s) {}; a misspelt restriction \
             would otherwise be dropped",
            unknown.join(", ")
        ));
    }
    if let Some(cpus) = &config.cpus
        && crate::sandbox::affinity::parse_cpu_list(cpus).is_err()
    {
        return Err(format!(
            "profile '{name}': cpus requires a valid CPU list"
        ));
    }
    Ok(config)
}

/// How the global config identifies a project.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProjectStrategy {
    /// Key by the launch directory's full canonical path: its sanitized
    /// basename plus a hash of the path (default).
    #[default]
    Basename,
    /// Key by the main repository root, shared by linked worktrees.
    RepoRoot,
}

impl ProjectStrategy {
    pub(crate) fn is_basename(&self) -> bool {
        matches!(self, Self::Basename)
    }
}

/// Effective network posture of a launch (docs/connect-proxy-plan.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network (default).
    Off,
    /// CONNECT-only egress to `allow_hosts` via the built-in proxy.
    Filtered,
    /// Unrestricted network (`network = true` / `--network`).
    Full,
}

impl Config {
    pub(crate) fn effective_harnesses(&self) -> Vec<&str> {
        if self.runtime_harnesses.is_empty() {
            crate::command::effective_name(&self.command)
                .into_iter()
                .collect()
        } else {
            self.runtime_harnesses.iter().map(String::as_str).collect()
        }
    }

    pub(crate) fn has_harness(&self, name: &str) -> bool {
        self.effective_harnesses()
            .into_iter()
            .any(|harness| harness == name)
    }
    pub fn gpu_enabled(&self) -> bool {
        self.no_gpu == Some(false)
    }
    /// Docker socket passthrough is opt-in: the socket grants effective
    /// root on the host, so it is only exposed when explicitly enabled
    /// (`--docker` or `no_docker = false`). Unset means disabled.
    pub fn docker_enabled(&self) -> bool {
        self.no_docker == Some(false)
    }
    pub fn tailscale_enabled(&self) -> bool {
        self.tailscale == Some(true)
    }
    pub fn display_enabled(&self) -> bool {
        self.no_display == Some(false)
    }
    pub fn audio_enabled(&self) -> bool {
        self.audio == Some(true)
    }
    pub fn github_enabled(&self) -> bool {
        self.github == Some(true)
    }
    pub fn aws_enabled(&self) -> bool {
        self.aws == Some(true)
    }
    pub fn kube_enabled(&self) -> bool {
        self.kube == Some(true)
    }
    pub fn gcloud_enabled(&self) -> bool {
        self.gcloud == Some(true)
    }
    pub fn docker_config_enabled(&self) -> bool {
        self.docker_config == Some(true)
    }
    pub fn kvm_enabled(&self) -> bool {
        self.kvm == Some(true)
    }
    pub fn prompt_hosts_enabled(&self) -> bool {
        self.prompt_hosts == Some(true)
    }
    pub fn x11_enabled(&self) -> bool {
        self.x11 == Some(true)
    }
    pub fn host_shm_enabled(&self) -> bool {
        self.host_shm == Some(true)
    }
    pub fn terminal_passthrough_enabled(&self) -> bool {
        self.terminal_passthrough == Some(true)
    }
    pub fn terminal_appearance_enabled(&self) -> bool {
        self.terminal_appearance == Some(true)
    }
    pub fn network_enabled(&self) -> bool {
        self.network == Some(true)
    }
    pub fn macos_host_ipc_enabled(&self) -> bool {
        self.macos_host_ipc == Some(true)
    }
    pub fn macos_chromium_enabled(&self) -> bool {
        self.macos_chromium == Some(true)
    }
    pub fn macos_trustd_enabled(&self) -> bool {
        self.macos_trustd == Some(true)
    }
    pub fn macos_pasteboard_enabled(&self) -> bool {
        self.macos_pasteboard == Some(true)
    }
    pub fn allow_pty_enabled(&self) -> bool {
        self.allow_pty == Some(true)
    }
    pub fn allow_loopback_listen_enabled(&self) -> bool {
        self.allow_loopback_listen == Some(true)
    }
    pub fn allow_loopback_connect_enabled(&self) -> bool {
        self.allow_loopback_connect == Some(true) && !self.lockdown_enabled()
    }
    pub fn mise_enabled(&self) -> bool {
        self.no_mise != Some(true)
    }
    pub fn toolchains_enabled(&self) -> bool {
        self.no_toolchains != Some(true)
    }
    pub fn worktree_enabled(&self) -> bool {
        self.no_worktree == Some(false)
    }
    pub fn lockdown_enabled(&self) -> bool {
        self.lockdown == Some(true)
    }
    pub fn save_config_enabled(&self) -> bool {
        self.no_save_config != Some(true)
    }
    /// Whether to automatically mask the project's `.ai-jail` file
    /// from the sandbox (default on). Opt-out via `--no-hide-config`
    /// or `no_hide_config = true` in the config file.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn hide_config_enabled(&self) -> bool {
        self.no_hide_config != Some(true)
    }
    pub fn ssh_enabled(&self) -> bool {
        self.ssh == Some(true)
    }
    pub fn pictures_enabled(&self) -> bool {
        self.pictures == Some(true)
    }
    pub fn browser_profile(&self) -> Option<BrowserProfile> {
        self.browser_profile
            .as_deref()
            .and_then(parse_browser_profile_spec)
    }
    pub fn browser_profile_disabled(&self) -> bool {
        matches!(
            self.browser_profile.as_deref(),
            Some("off" | "none" | "disabled")
        )
    }
    pub fn private_home_enabled(&self) -> bool {
        self.private_home != Some(false)
    }
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn landlock_enabled(&self) -> bool {
        self.no_landlock != Some(true)
    }
    pub fn status_bar_enabled(&self) -> bool {
        self.no_status_bar != Some(true)
    }
    pub fn status_bar_style(&self) -> &str {
        match self.status_bar_style.as_deref() {
            Some("light") => "light",
            Some("dark") => "dark",
            _ => "pastel",
        }
    }
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn seccomp_enabled(&self) -> bool {
        self.no_seccomp != Some(true)
    }
    pub fn rlimits_enabled(&self) -> bool {
        self.no_rlimits != Some(true)
    }
    pub fn systemd_user_enabled(&self) -> bool {
        self.systemd_user == Some(true)
    }
    pub fn allow_tcp_ports(&self) -> &[u16] {
        &self.allow_tcp_ports
    }
    pub fn allow_hosts(&self) -> &[String] {
        &self.allow_hosts
    }
    pub fn allow_private_hosts(&self) -> &[String] {
        &self.allow_private_hosts
    }
    pub fn host_is_allowlisted(&self, host: &str) -> bool {
        crate::proxy::allowlist_matches(&self.allow_hosts, host)
            || crate::proxy::allowlist_matches(&self.allow_private_hosts, host)
    }
    pub fn has_filtered_hosts(&self) -> bool {
        !self.allow_hosts.is_empty() || !self.allow_private_hosts.is_empty()
    }
    pub fn forward_ports(&self) -> &[u16] {
        &self.forward_ports
    }
    pub fn publish_ports(&self) -> &[u16] {
        &self.publish_ports
    }
    /// Effective network posture: `network = true` wins as unrestricted,
    /// a non-empty filtered host list selects filtered egress through the
    /// CONNECT proxy, otherwise networking stays off. The
    /// Full-plus-filtered-hosts contradiction is a launch error, checked in
    /// main (`validate_network_flags`).
    pub fn network_mode(&self) -> NetworkMode {
        if self.network_enabled() {
            NetworkMode::Full
        } else if self.has_filtered_hosts() {
            // `--no-network` (network == Some(false)) with filtered hosts is NOT
            // a contradiction: it composes to filtered egress, and the
            // landlock wrapper itself re-execs with `--no-network` +
            // `--allow-host` to express exactly this (see bwrap.rs). Strict
            // offline is `--no-network` with no filtered hosts.
            NetworkMode::Filtered
        } else {
            NetworkMode::Off
        }
    }
    /// Command-specific agent state mounts (`~/.claude`, `~/.codex`,
    /// `~/.claude.json`, ...) so the invoked harness starts pre-authenticated.
    /// ON by default (reverses the former opt-in #84 stance): a plain
    /// `ai-jail <harness>` mounts that harness's own credential/state dir
    /// read-write, so OAuth/login persist and it does not re-authenticate each
    /// session. `--no-agent-state` (or `agent_state = false`) opts out for an
    /// isolated, logged-out run. Monotonic (an untrusted project `.ai-jail`
    /// may only disable it, never force it on past a trusted opt-out) and
    /// disabled under `--lockdown`.
    ///
    /// The `--lockdown` gate is folded in here (unlike the opt-in capability
    /// accessors, which gate at the mount site) precisely because this one is
    /// on by default: folding it in guarantees every call site — the bwrap and
    /// seatbelt mounts, the Landlock wrapper forward, and the audit record —
    /// keeps a lockdown launch fully isolated without a separate `!lockdown`
    /// check each place.
    pub fn agent_state_enabled(&self) -> bool {
        self.agent_state != Some(false) && !self.lockdown_enabled()
    }
    /// Full host-environment inheritance is a trusted capability:
    /// disabled unless explicitly enabled. Default keeps only the
    /// safe allowlist plus `env_pass` entries.
    pub fn inherit_env_enabled(&self) -> bool {
        self.inherit_env == Some(true)
    }
    pub fn env_pass(&self) -> &[String] {
        &self.env_pass
    }
    /// The status-bar update check phones home to GitHub; it is
    /// disabled unless explicitly enabled via CLI or global config.
    pub fn update_check_enabled(&self) -> bool {
        self.update_check == Some(true)
    }
    /// Opt-in launch audit log: off unless explicitly enabled.
    pub fn audit_log_enabled(&self) -> bool {
        self.audit_log == Some(true)
    }
}

fn config_path() -> PathBuf {
    Path::new(CONFIG_FILE).to_path_buf()
}

/// Environment variables the sandbox inherits by default in normal
/// (non-lockdown) mode. Everything else — API keys, cloud
/// credentials, tokens — is dropped unless the user passes it
/// explicitly with `--env`/`env_pass` or enables `inherit_env`.
pub const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TERM",
    "LANG",
    "SHELL",
    "TMPDIR",
    "COLORTERM",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
];

/// Variable-name prefixes whose whole family is inherited by
/// default: locale (`LC_*`), XDG base dirs (`XDG_*`), and terminal
/// program metadata (`TERM_PROGRAM`, `TERM_PROGRAM_VERSION`).
pub const DEFAULT_ENV_PREFIXES: &[&str] = &["LC_", "XDG_", "TERM_PROGRAM"];

/// Whether `name` is inherited into the sandbox by default.
pub fn env_inherited_by_default(name: &str) -> bool {
    DEFAULT_ENV_ALLOWLIST.contains(&name)
        || DEFAULT_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Split an `--env` / `env_pass` entry into its variable name and
/// optional explicit value: `NAME` copies the host value at launch,
/// `NAME=VALUE` is verbatim. Errors on an empty variable name.
pub fn parse_env_entry(entry: &str) -> Result<(&str, Option<&str>), String> {
    let (name, value) = match entry.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (entry, None),
    };
    if name.is_empty() {
        return Err(format!("env entry {entry:?} has an empty variable name"));
    }
    Ok((name, value))
}

/// Apply `env_pass` entries on top of `env` (in place): explicit
/// `NAME=VALUE` entries verbatim, bare `NAME` entries copied from
/// `host_env` when present there (missing host vars are skipped).
pub fn apply_env_pass(
    env: &mut Vec<(String, String)>,
    env_pass: &[String],
    host_env: &[(String, String)],
) {
    for entry in env_pass {
        let Ok((name, explicit)) = parse_env_entry(entry) else {
            output::warn(&format!("Ignoring invalid {entry:?}: bad name"));
            continue;
        };
        let value = explicit.map(str::to_string).or_else(|| {
            host_env
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        });
        if let Some(value) = value {
            env.retain(|(key, _)| key != name);
            env.push((name.to_string(), value));
        }
    }
}

/// Load `--env-from-file` credential files into `NAME=VALUE` env_pass
/// entries. Every refusal here is a launch error, not a warning: this
/// is credential material, so it fails closed.
pub fn load_env_files(
    paths: &[PathBuf],
    project_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for path in paths {
        let absolute = to_absolute(path.clone(), project_dir);
        let directory = open_env_parent(&absolute, project_dir)?;
        let file = open_env_file_at(&directory, &absolute)?;
        read_env_file(file, &absolute, &mut entries)?;
    }
    Ok(entries)
}

fn read_env_file(
    mut file: std::fs::File,
    path: &Path,
    entries: &mut Vec<String>,
) -> Result<(), String> {
    use std::io::Read;

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("--env-from-file {}: {e}", path.display()))?;
    parse_env_file(&content, path, entries)
}

fn open_env_entry(
    directory: &std::fs::File,
    name: &std::ffi::CStr,
    flags: nix::libc::c_int,
) -> std::io::Result<std::fs::File> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd};

    // SAFETY: directory is live and name is NUL-terminated. No O_CREAT
    // flag is used, so openat does not need a mode argument.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | flags,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor owned by this function.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Directory handles need lookup and metadata, not read access.
fn env_directory_flags() -> nix::libc::c_int {
    #[cfg(target_os = "linux")]
    {
        nix::libc::O_PATH | nix::libc::O_DIRECTORY
    }
    #[cfg(target_os = "macos")]
    {
        nix::libc::O_SEARCH
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        nix::libc::O_RDONLY | nix::libc::O_DIRECTORY
    }
}

/// Check the opened directory's ancestry, rather than resolving a path
/// which could now refer to a replacement. Directory aliases remain
/// supported, including /tmp and /var on macOS.
fn env_parent_is_outside_project(
    directory: &std::fs::File,
    project: &std::fs::File,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let project = project.metadata()?;
    let same = |a: &std::fs::Metadata, b: &std::fs::Metadata| {
        a.dev() == b.dev() && a.ino() == b.ino()
    };
    let mut current = directory.try_clone()?;
    loop {
        let metadata = current.metadata()?;
        if same(&metadata, &project) {
            return Ok(false);
        }
        let parent = open_env_entry(&current, c"..", env_directory_flags())?;
        let parent_metadata = parent.metadata()?;
        if same(&metadata, &parent_metadata) {
            return Ok(true);
        }
        current = parent;
    }
}

fn open_env_parent(
    path: &Path,
    project_dir: &Path,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let open_directory = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(env_directory_flags())
            .open(path)
    };
    let label = || format!("--env-from-file {}", path.display());
    let parent = path
        .parent()
        .ok_or_else(|| format!("{}: not a regular file", label()))?;
    let directory = open_directory(parent).map_err(|e| {
        format!("{}: cannot open parent directory: {e}", label())
    })?;
    let project = open_directory(project_dir).map_err(|e| {
        format!("{}: cannot open project directory: {e}", label())
    })?;
    if !env_parent_is_outside_project(&directory, &project).map_err(|e| {
        format!("{}: cannot check directory ancestry: {e}", label())
    })? {
        return Err(format!(
            "{}: credential files must live outside the project directory",
            label()
        ));
    }
    Ok(directory)
}

fn open_env_file_at(
    directory: &std::fs::File,
    path: &Path,
) -> Result<std::fs::File, String> {
    let label = || format!("--env-from-file {}", path.display());
    let name = path
        .file_name()
        .ok_or_else(|| format!("{}: not a regular file", label()))?;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|e| format!("{}: invalid file name: {e}", label()))?;
    // NONBLOCK prevents a substituted FIFO from blocking before fstat.
    let file = open_env_entry(directory, &name, nix::libc::O_NONBLOCK)
        .map_err(|e| {
            format!("{}: cannot open without following symlinks: {e}", label())
        })?;
    validate_env_file(&file, path)?;
    Ok(file)
}

/// A credential file must be an existing, user-owned regular file,
/// mode 0600 or stricter. Inspect the fd that will supply its contents.
fn validate_env_file(file: &std::fs::File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let label = || format!("--env-from-file {}", path.display());
    let metadata = file.metadata().map_err(|e| format!("{}: {e}", label()))?;
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", label()));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { nix::libc::geteuid() };
    if metadata.uid() != euid {
        return Err(format!("{}: must be owned by the current user", label()));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{}: must be mode 0600 or stricter (is {:04o})",
            label(),
            mode
        ));
    }
    Ok(())
}

/// Strict `KEY=VALUE` lines: `#` comments and blank lines are skipped,
/// keys must match `[A-Za-z_][A-Za-z0-9_]*` (no `export` prefix), and
/// values are used verbatim after the first `=` -- no quote stripping.
fn parse_env_file(
    content: &str,
    path: &Path,
    entries: &mut Vec<String>,
) -> Result<(), String> {
    for (lineno, line) in content.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "--env-from-file {}:{}: not a KEY=VALUE line",
                path.display(),
                lineno + 1
            ));
        };
        if !valid_env_key(key) {
            return Err(format!(
                "--env-from-file {}:{}: invalid variable name {key:?}",
                path.display(),
                lineno + 1
            ));
        }
        entries.push(format!("{key}={value}"));
    }
    Ok(())
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The sandbox environment for normal mode when full inheritance is
/// off: the default allowlist (plus prefix families) present in
/// `host_env`, plus explicit `env_pass` entries applied verbatim.
pub fn filtered_child_env(
    env_pass: &[String],
    host_env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = host_env
        .iter()
        .filter(|(name, _)| env_inherited_by_default(name))
        .cloned()
        .collect();
    apply_env_pass(&mut env, env_pass, host_env);
    env
}

fn global_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(CONFIG_FILE))
}

pub fn parse_toml(contents: &str) -> Result<Config, String> {
    toml::from_str(contents).map_err(|e| e.to_string())
}

pub(crate) fn parse_global_toml(
    contents: &str,
) -> Result<GlobalConfig, String> {
    let global: GlobalConfig = toml::from_str(contents).map_err(|e| {
        // TOML refuses a duplicate profile or key for the whole file, before
        // any profile is selected, and its message quotes the source line:
        // inside `[profiles.*]` that line may hold a secret. Keep where and
        // what, never the excerpt. Elsewhere the excerpt stays as before.
        let start = e.span().map(|span| span.start.min(contents.len()));
        let in_profiles = e.message().contains("table `profiles")
            || start.is_some_and(|at| in_profiles_section(contents, at));
        if !in_profiles {
            return e.to_string();
        }
        let line =
            start.map_or(0, |at| contents[..at].matches('\n').count() + 1);
        format!(
            "TOML parse error at line {line} in [profiles]: {}",
            output::escape_control_bytes(e.message().trim_end())
        )
    })?;
    // A trusted CPU set is checked at load, as `rlimit` is: a typo must
    // stop the launch, never let a project value stand in for it.
    check_trusted_cpus("cpus", &global.base)?;
    for (name, table) in &global.commands {
        check_trusted_cpus(&format!("commands.{name}.cpus"), table)?;
    }
    Ok(global)
}

fn check_trusted_cpus(field: &str, config: &Config) -> Result<(), String> {
    match config.cpus.as_deref() {
        Some(text) => crate::sandbox::affinity::parse_cpu_list(text)
            .map(|_| ())
            .map_err(|e| format!("{field} = \"{text}\": {e}")),
        None => Ok(()),
    }
}

/// Whether byte `at` of a TOML document belongs to a profile: under a
/// `[profiles…]` / `[[profiles…]]` header (quoted or not), or on a line
/// that is itself a `profiles…` dotted key or inline table.
fn in_profiles_section(contents: &str, at: usize) -> bool {
    // Quotes and spaces never change which table a key names.
    let names_profiles = |text: &str| {
        let bare: String = text
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | ' ' | '\t'))
            .collect();
        bare.strip_prefix("profiles")
            .is_some_and(|rest| rest.starts_with(['.', ']', '=']))
    };
    let line_start = contents[..at].rfind('\n').map_or(0, |i| i + 1);
    let line_end = contents[at..].find('\n').map_or(contents.len(), |i| at + i);
    if names_profiles(contents[line_start..line_end].trim_start()) {
        return true;
    }
    contents[..at]
        .lines()
        .rev()
        .map(str::trim_start)
        .find(|line| line.starts_with('['))
        .is_some_and(|header| names_profiles(header.trim_start_matches('[')))
}

#[test]
fn global_config_example_is_inert_and_documents_public_keys() {
    let example = include_str!("../docs/config.example.toml");
    assert_eq!(parse_global_toml(example).unwrap(), GlobalConfig::default());

    let uncommented = example
        .lines()
        .filter_map(|line| line.strip_prefix("# "))
        .filter(|line| {
            line.starts_with('[')
                || line.split_once(" = ").is_some_and(|(key, _)| {
                    key.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'_'
                    })
                })
        })
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_global_toml(&uncommented).unwrap();
    let expected_keys = include_str!("config.rs")
        .split_once("pub struct Config {\n")
        .unwrap()
        .1
        .split_once("\n}\n")
        .unwrap()
        .0
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub "))
        .filter_map(|line| line.split_once(':').map(|(key, _)| key))
        // Runtime-only fields, `#[serde(skip)]`: never read from a file.
        .filter(|key| {
            !matches!(
                *key,
                "runtime_harnesses" | "rlimit_source" | "cpus_source"
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let raw = uncommented.parse::<toml::Table>().unwrap();
    for key in &expected_keys {
        assert!(raw.contains_key(*key), "missing example for {key}");
    }
    for key in raw.keys() {
        assert!(
            expected_keys.contains(key.as_str())
                || matches!(key.as_str(), "commands" | "project_strategy"),
            "unknown example key {key}",
        );
    }
    assert_eq!(parsed.base.agent_state, Some(false));
    assert_eq!(parsed.commands["claude"].agent_state, Some(true));
}

/// Whether a symlinked config may be followed.
///
/// The project `.ai-jail` is untrusted input, so it is always read as a
/// plain file. The global `~/.ai-jail` is trusted policy that can enable
/// capabilities, but dotfile managers such as GNU stow legitimately install
/// it as a symlink, so it may be followed under the conditions in
/// [`trusted_symlink_target`].
#[derive(Clone, Copy, PartialEq)]
enum SymlinkPolicy {
    Reject,
    FollowIfTrusted,
}

/// Resolve a symlinked global config, or explain why it is not trustworthy.
///
/// Following a symlink hands whoever can write its target control of trusted
/// policy, so the resolved file must be a regular file this user owns, with
/// no group or other write bits, and must sit outside the project directory.
/// That last condition is the important one: the project is mounted
/// read-write by default, so a target inside it could be rewritten by the
/// very agent the policy is meant to constrain, and the next launch would
/// then honor whatever capabilities it granted itself.
fn trusted_symlink_target(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;

    let target = std::fs::canonicalize(path)
        .map_err(|e| format!("cannot resolve symlink ({e})"))?;
    let metadata = std::fs::metadata(&target)
        .map_err(|e| format!("cannot stat {} ({e})", target.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", target.display()));
    }
    let uid = unsafe { nix::libc::geteuid() };
    if metadata.uid() != uid {
        return Err(format!("{} is not owned by uid {uid}", target.display()));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is group- or world-writable",
            target.display()
        ));
    }
    if let Ok(project) = std::env::current_dir()
        && let Ok(project) = std::fs::canonicalize(project)
        && target.starts_with(&project)
    {
        return Err(format!(
            "{} is inside the project directory, which the sandbox can write",
            target.display()
        ));
    }
    Ok(target)
}

fn load_toml_from_path<T: Default>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    load_toml_with_policy(path, parse, SymlinkPolicy::Reject)
}

fn load_toml_with_policy<T: Default>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T, String>,
    policy: SymlinkPolicy,
) -> Result<T, String> {
    let mut path = path.to_path_buf();
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if policy == SymlinkPolicy::Reject {
                return Err(format!(
                    "Refusing to read {}: path is a symlink",
                    path.display()
                ));
            }
            // Read through the resolved path so the decision and the read
            // cannot disagree if a hop is swapped in between.
            path = trusted_symlink_target(&path).map_err(|e| {
                format!("Refusing to read {}: {e}", path.display())
            })?;
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("Failed to stat {}: {e}", path.display()));
        }
    }
    let path = path.as_path();
    match std::fs::read_to_string(path) {
        Ok(contents) => parse(&contents).map_err(|e| {
            format!(
                "Failed to parse {}: {}",
                path.display(),
                redact_env_assignments(&e)
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("Failed to read {}: {e}", path.display())),
    }
}

/// Variable names carried by `env_pass` entries, without their values.
///
/// Diagnostics (`status`, `--dry-run`) show names only: an entry is how a
/// secret enters the sandbox, so its value must not reach terminal
/// scrollback or CI logs.
pub(crate) fn env_pass_names(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            parse_env_entry(entry)
                .map(|(name, _)| name.to_string())
                .unwrap_or_else(|_| entry.clone())
        })
        .collect()
}

/// Mask the value half of every `NAME=VALUE` token in `text`.
///
/// Used for diagnostics that quote user configuration: an `env_pass`
/// entry carries a secret by design, so a parse error must never echo it
/// into terminal scrollback or CI logs. Variable names stay, because they
/// are what the user needs to find the line.
pub(crate) fn redact_env_assignments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(eq) = rest.find('=') {
        let (before, after) = rest.split_at(eq);
        let name_start = before
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map(|index| index + 1)
            .unwrap_or(0);
        let name = &before[name_start..];
        let value_and_rest = &after[1..];
        let value_len = value_and_rest
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '"' | '\'' | ',' | ']' | '}' | '|')
            })
            .unwrap_or(value_and_rest.len());
        let is_assignment = !name.is_empty()
            && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        out.push_str(&before[..name_start]);
        if is_assignment && value_len > 0 {
            out.push_str(name);
            out.push_str("=<redacted>");
        } else {
            out.push_str(&before[name_start..]);
            out.push('=');
        }
        rest = &value_and_rest[value_len..];
    }
    out.push_str(rest);
    out
}

fn load_from_path(path: &Path) -> Result<Config, String> {
    load_toml_from_path(path, |text| {
        warn_if_project_selects_profile(text, &[]);
        parse_toml(text)
    })
}

/// The warning printed when a project policy names a profile.
pub(crate) const PROJECT_PROFILE_IGNORED: &str = concat!(
    "project .ai-jail profile ignored: ",
    "only the CLI (--profile) selects a profile",
);

/// Whether a project policy document tries to select or define a
/// profile: a `profile` key or a `[profiles]` table at the top level, or
/// inside one of the tables named by `nested` (the store document keeps
/// its policy under `[grants]` and `[constraints]`). `Config` ignores
/// both keys, so the only effect is this warning.
pub(crate) fn project_selects_profile(text: &str, nested: &[&str]) -> bool {
    let Ok(root) = text.parse::<toml::Table>() else {
        return false;
    };
    let names = |table: &toml::Table| {
        table.contains_key("profile") || table.contains_key("profiles")
    };
    names(&root)
        || nested.iter().any(|key| {
            root.get(*key)
                .and_then(toml::Value::as_table)
                .is_some_and(names)
        })
}

pub(crate) fn warn_if_project_selects_profile(text: &str, nested: &[&str]) {
    if project_selects_profile(text, nested) {
        output::warn(PROJECT_PROFILE_IGNORED);
    }
}

fn load_global_from_path(path: &Path) -> Result<GlobalConfig, String> {
    load_toml_with_policy(
        path,
        parse_global_toml,
        SymlinkPolicy::FollowIfTrusted,
    )
}

/// Read `project_strategy` from the legacy `$HOME/.ai-jail`, defaulting
/// to `Basename` when the file does not exist.
pub(crate) fn load_legacy_global_project_strategy()
-> Result<ProjectStrategy, String> {
    match global_config_path() {
        Some(path) if path.exists() => {
            Ok(load_global_from_path(&path)?.project_strategy)
        }
        _ => Ok(ProjectStrategy::Basename),
    }
}

/// Load project-level config from `.ai-jail` in the current dir.
pub fn load() -> Result<Config, String> {
    load_from_path(&config_path())
}

/// Load global user config from `$HOME/.ai-jail`, applying a matching
/// `[commands.<name>]` table when present. Only a CLI command can select a
/// command table; otherwise the global base command is used. Project config is
/// untrusted and may select what runs, but cannot activate global policy.
#[derive(Debug)]
pub(crate) struct GlobalCommandSelection {
    pub config: Config,
    /// The same selection without the profile: the global base and the
    /// command table only. It is what the launch would be without
    /// `--profile`, so the widenings can be measured after every layer.
    pub without_profile: Config,
    pub ignored_command_tables: Vec<String>,
    /// The profile `--profile` selected, with what it asked for beyond the
    /// global base and the command table. What it widens in the launch is
    /// [`ProfileReport::applied`].
    pub profile: Option<ProfileReport>,
}

/// A selected profile and the access it grants beyond the layers beneath
/// it: first measured against the global base and the command table, then
/// narrowed by [`ProfileReport::applied`] to what the launch applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileReport {
    pub name: String,
    pub widenings: Vec<Widening>,
}

/// One widening: the field and only the values the profile added. Key
/// names only for the secret fields (`env_pass`, `env_from_file`,
/// `secret_hosts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Widening {
    pub field: String,
    pub granted: Vec<String>,
}

impl ProfileReport {
    /// The stderr lines, one per widening:
    /// `profile=NAME widens=FIELD granted="v1,v2"`.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.widenings
            .iter()
            .map(|w| {
                format!(
                    "profile={} widens={} granted=\"{}\"",
                    self.name,
                    w.field,
                    quote_granted(&w.granted)
                )
            })
            .collect()
    }
}

/// The pure layers of one launch, with and without its profile: global
/// base and command table (plus the profile), project grants, the CLI and
/// project constraints. Onboarding and lockdown are not in them; they act
/// on the launch config [`ProfileReport::applied`] is given.
pub(crate) struct ProfileLayers {
    pub without_profile: Config,
    pub with_profile: Config,
}

impl ProfileReport {
    /// What the profile still widens once every layer has spoken (#230
    /// review: name only what this launch applies). A value is kept when
    /// the profile adds it over the other layers AND the launch config
    /// still grants it over those layers: onboarding's restricted
    /// defaults, the CLI or a project grant that already gives it, and a
    /// grant `--lockdown` drops all leave it out. Nothing left, no line.
    pub(crate) fn applied(
        &self,
        layers: ProfileLayers,
        launch: &Config,
        cwd: &Path,
    ) -> Result<ProfileReport, String> {
        let label = format!("profile '{}'", self.name);
        let ProfileLayers {
            mut without_profile,
            mut with_profile,
        } = layers;
        // The launch config's paths are absolute by now; compare like with
        // like.
        absolutize_user_paths(&mut without_profile, cwd);
        absolutize_user_paths(&mut with_profile, cwd);
        // A few fields (`env_pass`, `claude_dir`, the exceptions, …) are
        // reported for every entry whatever the baseline holds, so measured
        // against itself the baseline names its own entries: those are the
        // CLI's, the project's or the global base's, never the profile's.
        let own =
            profile_widenings(&without_profile, &without_profile, cwd, &label)?;
        let not_own = |found: Vec<Refusal>| -> Vec<Refusal> {
            found
                .into_iter()
                .map(|mut r| {
                    if let Some(base) = own.iter().find(|o| o.field == r.field)
                    {
                        r.granted.retain(|v| !base.granted.contains(v));
                    }
                    r
                })
                .filter(|r| !r.granted.is_empty())
                .collect()
        };
        let by_profile = not_own(profile_widenings(
            &without_profile,
            &with_profile,
            cwd,
            &label,
        )?);
        let by_launch =
            not_own(profile_widenings(&without_profile, launch, cwd, &label)?);
        let lockdown = launch.lockdown_enabled();
        let mut widenings: Vec<Widening> = by_profile
            .into_iter()
            .filter(|asked| {
                !matches!(asked.field.as_str(), "secret_hosts" | "cpus")
            })
            .filter(|asked| {
                !(lockdown && LOCKDOWN_DROPS.contains(&asked.field.as_str()))
            })
            .filter_map(|asked| {
                let granted =
                    by_launch.iter().find(|r| r.field == asked.field)?;
                let kept: Vec<String> = asked
                    .granted
                    .into_iter()
                    .filter(|value| granted.granted.contains(value))
                    .collect();
                (!kept.is_empty()).then_some(Widening {
                    field: asked.field,
                    granted: kept,
                })
            })
            .collect();
        // A project constraint can intersect a profile's wider CPU set.
        // Disclose just the additional CPUs that remain in the launch.
        let parse_cpus = |config: &Config| {
            config.cpus.as_deref().and_then(|cpus| {
                crate::sandbox::affinity::parse_cpu_list(cpus).ok()
            })
        };
        if let (Some(base), Some(profile), Some(actual)) = (
            parse_cpus(&without_profile),
            parse_cpus(&with_profile),
            parse_cpus(launch),
        ) {
            let added = actual
                .intersection(&profile)
                .copied()
                .filter(|cpu| !base.contains(cpu))
                .collect::<std::collections::BTreeSet<_>>();
            if !added.is_empty() {
                widenings.push(Widening {
                    field: "cpus".into(),
                    granted: vec![crate::sandbox::affinity::format_cpu_list(
                        &added,
                    )],
                });
            }
        }
        // Compare the destination before redacting. A baseline binding
        // for the same variable does not authorize a different host.
        let changed_bindings: Vec<String> = with_profile
            .secret_hosts
            .iter()
            .filter(|(name, host)| {
                without_profile.secret_hosts.get(*name) != Some(*host)
                    && launch.secret_hosts.get(*name) == Some(*host)
            })
            .map(|(name, _)| name.clone())
            .collect();
        if !changed_bindings.is_empty() {
            widenings.push(Widening {
                field: "secret_hosts".into(),
                granted: changed_bindings,
            });
        }
        Ok(ProfileReport {
            name: self.name.clone(),
            widenings,
        })
    }
}

/// Fields whose grant has no effect at all under `--lockdown`, so a
/// profile that sets them widens nothing in a lockdown launch. Read from
/// the code that drops each one, which differs by backend; a grant lockdown
/// only narrows (a read-only worktree, the proxy hosts, forwarded ports,
/// the `CLAUDE_CONFIG_DIR` variable) is still a widening and stays listed.
#[cfg(target_os = "linux")]
const LOCKDOWN_DROPS: &[&str] = &[
    // bwrap.rs `discover_mounts_full`: no maps, devices or sockets, and a
    // private home whatever `private_home` says.
    "rw_maps",
    "ro_maps",
    "overlay_maps",
    "no_gpu",
    "kvm",
    "no_docker",
    "tailscale",
    "no_display",
    "x11",
    "audio",
    "host_shm",
    "pictures",
    "ssh",
    "systemd_user",
    "private_home",
    // bwrap.rs: `--unshare-net` and `--clearenv` without the passed env.
    "network",
    "inherit_env",
    // main.rs `finalize_launch_config_with_ssh` and the accessors.
    "github",
    "aws",
    "kube",
    "gcloud",
    "docker_config",
    "prompt_hosts",
    "no_mise",
    "no_toolchains",
    "agent_state",
    "allow_loopback_connect",
];
#[cfg(not(target_os = "linux"))]
const LOCKDOWN_DROPS: &[&str] = &[
    // seatbelt.rs: each opt-in rule is skipped under lockdown. Unlike
    // Linux, macOS lockdown keeps `macos_host_ipc`, the environment
    // (`inherit_env`, `env_pass`) and read access to the maps.
    "no_docker",
    "network",
    "macos_chromium",
    "macos_trustd",
    "macos_pasteboard",
    "allow_pty",
    "allow_loopback_listen",
    "allow_tcp_ports",
    "pictures",
    "ssh",
    // main.rs `finalize_launch_config_with_ssh` and the accessors.
    "github",
    "aws",
    "kube",
    "gcloud",
    "docker_config",
    "no_mise",
    "no_toolchains",
    "agent_state",
    "allow_loopback_connect",
];

/// The `granted="…"` payload: values joined by `,`, with `\\`, `"` and
/// `,` inside a value backslash-escaped and control bytes neutralised,
/// so a crafted path cannot forge a second field or a second value.
fn quote_granted(values: &[String]) -> String {
    values
        .iter()
        .map(|value| {
            let mut out = String::with_capacity(value.len());
            for ch in output::escape_control_bytes(value).chars() {
                if matches!(ch, '\\' | '"' | ',') {
                    out.push('\\');
                }
                out.push(ch);
            }
            out
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn load_global_for_command_report(
    cli: &CliArgs,
    project: &Config,
) -> Result<GlobalCommandSelection, String> {
    let global = match global_config_path() {
        Some(path) => load_global_from_path(&path)?,
        None => GlobalConfig::default(),
    };
    global_config_for_command_report(global, cli, project)
}

/// Load the global config at `path` and select as a launch does: the
/// command table, then the profile `cli` names. The path-taking twin of
/// the store loader, so a test can point it at a fixture.
#[cfg(test)]
pub(crate) fn load_global_for_command_from_path(
    path: &Path,
    cli: &CliArgs,
    project: &Config,
) -> Result<(Config, Option<ProfileReport>), String> {
    let selection = global_config_for_command_report(
        load_global_from_path(path)?,
        cli,
        project,
    )?;
    Ok((selection.config, selection.profile))
}

pub(crate) fn global_config_for_command(
    global: GlobalConfig,
    cli: &CliArgs,
    _project: &Config,
) -> Result<Config, String> {
    Ok(global_config_for_command_report(global, cli, _project)?.config)
}

pub(crate) fn global_config_for_command_report(
    global: GlobalConfig,
    cli: &CliArgs,
    _project: &Config,
) -> Result<GlobalCommandSelection, String> {
    let selected_command = if !cli.command.is_empty() {
        cli.command.clone()
    } else {
        global.base.command.clone()
    };

    let GlobalConfig {
        mut base,
        commands,
        profiles,
        ..
    } = global;
    // The global file's own `[rlimit]` entries are labelled here; command
    // tables are labelled by `merge_trusted`.
    for name in base.rlimit.keys() {
        base.rlimit_source
            .insert(name.clone(), crate::sandbox::rlimits::LimitSource::Global);
    }
    if base.cpus.is_some() {
        base.cpus_source = Some(crate::sandbox::rlimits::LimitSource::Global);
    }
    let mut ignored_command_tables = Vec::new();
    let mut apply = |name: &str, base: &mut Config| {
        let Some(command_config) = commands.get(name) else {
            return;
        };
        if !cli.command.is_empty()
            && !command_config.command.is_empty()
            && command_config.command != cli.command
        {
            ignored_command_tables.push(output::escape_control_bytes(name));
        }
        *base = merge_trusted(base.clone(), command_config.clone());
    };
    if let Some(name) = selected_command.first() {
        apply(name, &mut base);
    }
    // `ai-memory run` is both a wrapper invocation and a harness launch.
    // Preserve an existing [commands.ai-memory] layer, then let the selected
    // harness add/override its own global preferences.
    if let Some(harness) = command::managed_harness(&selected_command)
        && selected_command
            .first()
            .is_none_or(|name| name != harness.name)
    {
        apply(harness.name, &mut base);
    }
    let without_profile = base.clone();
    // The profile is the last trusted layer before the CLI. Only the CLI
    // selects one, so a malformed profile no launch names stays inert.
    let profile = match cli.profile.as_deref() {
        Some(name) => {
            let layer = select_profile(profiles.tables()?, name)?;
            let project_dir = std::env::current_dir().map_err(|e| {
                format!(
                    "profile '{name}': cannot read the launch directory: {e}"
                )
            })?;
            let refusals = profile_widenings(
                &base,
                &layer,
                &project_dir,
                &format!("profile '{name}'"),
            )?;
            base = merge_trusted(base, layer);
            Some(ProfileReport {
                name: name.to_string(),
                widenings: refusals
                    .into_iter()
                    .map(|r| Widening {
                        field: r.field,
                        granted: r.granted,
                    })
                    .collect(),
            })
        }
        None => None,
    };
    Ok(GlobalCommandSelection {
        config: base,
        without_profile,
        ignored_command_tables,
        profile,
    })
}

/// Every field `layer` widens over `base`. The untrusted-layer filter
/// keeps a refused field at the baseline, which can hide a widening in
/// another field: a refused `lockdown = false` leaves lockdown on, so an
/// `agent_state = true` beside it reads as no change, while the trusted
/// merge applies both. Each round therefore moves the refused switches to
/// their merged values and asks again, until no new field appears.
/// A refusal whose single granted value is a boolean: a switch such as
/// `lockdown` or `private_home`, the only kind that can mask another field.
fn is_switch(r: &Refusal) -> bool {
    matches!(r.granted.as_slice(), [v] if v == "true" || v == "false")
}

fn profile_widenings(
    base: &Config,
    layer: &Config,
    project_dir: &Path,
    label: &str,
) -> Result<Vec<Refusal>, String> {
    let as_table = |config: &Config| {
        toml::Table::try_from(config)
            .map_err(|e| format!("{label}: cannot compare layers: {e}"))
    };
    let merged = as_table(&merge_trusted(base.clone(), layer.clone()))?;
    let mut baseline = base.clone();
    let mut found: Vec<Refusal> = Vec::new();
    loop {
        let (_, refusals) = merge_layer_report(
            baseline.clone(),
            layer.clone(),
            project_dir,
            label,
        );
        let mut new: Vec<Refusal> = Vec::new();
        for refusal in refusals {
            if found.iter().any(|prior| prior.field == refusal.field) {
                continue;
            }
            if let Some(entry) =
                new.iter_mut().find(|entry| entry.field == refusal.field)
            {
                for value in refusal.granted {
                    if !entry.granted.contains(&value) {
                        entry.granted.push(value);
                    }
                }
            } else {
                new.push(refusal);
            }
        }
        if new.is_empty() {
            return Ok(found);
        }
        // Only a switch can mask another field (lockdown, private_home …);
        // moving a map or a host list into the baseline would make the
        // profile's own entries look like widenings of each other.
        let switches: Vec<&Refusal> =
            new.iter().filter(|r| is_switch(r)).collect();
        if switches.is_empty() {
            found.extend(new);
            return Ok(found);
        }
        let mut table = as_table(&baseline)?;
        for refusal in switches {
            match merged.get(&refusal.field) {
                Some(value) => {
                    table.insert(refusal.field.clone(), value.clone());
                }
                None => {
                    table.remove(&refusal.field);
                }
            }
        }
        let next: Config = toml::Value::Table(table)
            .try_into()
            .map_err(|e| format!("{label}: cannot compare layers: {e}"))?;
        // Fields that do not serialise (secrets) keep the baseline's values.
        baseline = Config {
            env_pass: baseline.env_pass,
            env_from_file: baseline.env_from_file,
            secret_hosts: baseline.secret_hosts,
            ..next
        };
        found.extend(new);
    }
}

/// Merge two trusted configuration layers, such as global base and a global
/// command table.
fn merge_trusted(global: Config, local: Config) -> Config {
    let mut c = global;
    // Trust is conferred by the global config, never claimed by the layer
    // being merged in, so this field is deliberately not taken from `local`.
    if !local.command.is_empty() {
        c.command = local.command;
    }
    c.rw_maps.extend(local.rw_maps);
    dedup_paths(&mut c.rw_maps);
    c.ro_maps.extend(local.ro_maps);
    dedup_paths(&mut c.ro_maps);
    c.overlay_maps.extend(local.overlay_maps);
    dedup_paths(&mut c.overlay_maps);
    c.hide_dotdirs.extend(local.hide_dotdirs);
    dedup_strings(&mut c.hide_dotdirs);
    c.mask.extend(local.mask);
    dedup_paths(&mut c.mask);
    c.deny_paths.extend(local.deny_paths);
    dedup_paths(&mut c.deny_paths);
    c.mask_exceptions.extend(local.mask_exceptions);
    dedup_paths(&mut c.mask_exceptions);
    c.deny_path_exceptions.extend(local.deny_path_exceptions);
    dedup_paths(&mut c.deny_path_exceptions);
    // Each Option-typed field follows the same pattern: local
    // overrides global iff local explicitly set it. The macro is
    // local to the function so it stays scoped to this single use.
    macro_rules! take {
        ($field:ident) => {
            if local.$field.is_some() {
                c.$field = local.$field;
            }
        };
    }
    take!(no_gpu);
    take!(no_docker);
    take!(tailscale);
    take!(no_display);
    take!(audio);
    take!(github);
    take!(aws);
    take!(kube);
    take!(gcloud);
    take!(docker_config);
    take!(kvm);
    take!(prompt_hosts);
    take!(network);
    take!(macos_host_ipc);
    take!(macos_chromium);
    take!(macos_trustd);
    take!(macos_pasteboard);
    take!(allow_pty);
    take!(allow_loopback_listen);
    take!(allow_loopback_connect);
    take!(x11);
    take!(host_shm);
    take!(terminal_passthrough);
    take!(terminal_appearance);
    take!(no_mise);
    take!(no_toolchains);
    take!(no_worktree);
    take!(no_save_config);
    take!(no_hide_config);
    take!(ssh);
    take!(pictures);
    take!(browser_profile);
    take!(private_home);
    take!(lockdown);
    take!(no_landlock);
    take!(no_seccomp);
    take!(no_rlimits);
    if local.cpus.is_some() {
        c.cpus_source = Some(crate::sandbox::rlimits::LimitSource::Global);
    }
    take!(cpus);
    for (name, value) in local.rlimit {
        c.rlimit_source
            .insert(name.clone(), crate::sandbox::rlimits::LimitSource::Global);
        c.rlimit.insert(name, value);
    }
    take!(systemd_user);
    take!(agent_state);
    take!(inherit_env);
    take!(update_check);
    take!(audit_log);
    c.env_pass.extend(local.env_pass);
    dedup_env_pass(&mut c.env_pass);
    c.env_from_file.extend(local.env_from_file);
    dedup_paths(&mut c.env_from_file);
    c.secret_hosts.extend(local.secret_hosts);
    c.allow_tcp_ports.extend(local.allow_tcp_ports);
    c.allow_tcp_ports.sort_unstable();
    c.allow_tcp_ports.dedup();
    // Trusted layers union the filtered-egress allowlist.
    c.allow_hosts.extend(local.allow_hosts);
    dedup_strings(&mut c.allow_hosts);
    c.allow_private_hosts.extend(local.allow_private_hosts);
    dedup_strings(&mut c.allow_private_hosts);
    c.forward_ports.extend(local.forward_ports);
    c.forward_ports.sort_unstable();
    c.forward_ports.dedup();
    c.publish_ports.extend(local.publish_ports);
    c.publish_ports.sort_unstable();
    c.publish_ports.dedup();
    take!(claude_dir);
    // Status bar + resize redraw key stay from global — local should
    // not override user-level preferences.
    c
}

/// Returns whether `path` resolves inside `project_dir`. Existing
/// paths use canonical resolution; paths which do not yet exist walk
/// to their deepest existing ancestor (via `symlink_metadata`) and
/// validate containment from there, rejecting ancestor chains that
/// contain symlinks — a lexical prefix match alone would accept
/// `project/link/tail` even when `project/link` points outside the
/// project, silently redirecting sandbox mounts.
pub fn resolves_inside_project(path: &Path, project_dir: &Path) -> bool {
    let project = std::fs::canonicalize(project_dir).unwrap_or_else(|_| {
        to_absolute(project_dir.to_path_buf(), project_dir)
    });
    let absolute = to_absolute(path.to_path_buf(), project_dir);
    if let Ok(resolved) = std::fs::canonicalize(&absolute) {
        return resolved.starts_with(&project);
    }
    // The mapped path does not exist yet: resolve the deepest
    // existing ancestor and validate containment from there.
    let Some((ancestor, tail)) = deepest_existing_ancestor(&absolute) else {
        return false;
    };
    if ancestor_chain_has_symlink(&ancestor, &project) {
        return false;
    }
    match std::fs::canonicalize(&ancestor) {
        Ok(resolved_ancestor) => {
            resolved_ancestor.join(tail).starts_with(&project)
        }
        Err(_) => false,
    }
}

/// Walk `path` up to the deepest ancestor that exists, returning it
/// together with the non-existent tail. `symlink_metadata` is used so
/// the returned ancestor may itself be a symlink (callers validate
/// that). Fails closed (None) when a component cannot be stat'd or
/// the filesystem root is reached without an existing component.
fn deepest_existing_ancestor(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => {
                let mut resolved_tail = PathBuf::new();
                for component in tail {
                    resolved_tail.push(component);
                }
                return Some((existing, resolved_tail));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name()?.to_os_string();
                tail.insert(0, name);
                existing.pop();
            }
            Err(_) => return None,
        }
    }
}

/// Whether the chain of existing components between `start` and the
/// project root `stop` contains a symlink (or a component that
/// cannot be stat'd — fail closed). Symlinks above the project root
/// are irrelevant: the canonicalized `stop` already resolved them.
fn ancestor_chain_has_symlink(start: &Path, stop: &Path) -> bool {
    // `stop` is canonical while `start` is not, so textual equality alone
    // never fires when any component above the project root is a symlink —
    // the walk then runs past the root and rejects on that symlink, which
    // is exactly what this function documents as irrelevant. macOS makes it
    // routine (`/var` -> `private/var`, `/tmp` -> `private/tmp`), but a
    // Linux home behind a symlink hits it too.
    let reached_stop = |path: &Path| {
        path == stop
            || std::fs::canonicalize(path).is_ok_and(|real| real == stop)
    };
    let mut current = start;
    loop {
        if reached_stop(current) {
            return false;
        }
        match std::fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return true;
            }
            Ok(_) => {}
            Err(_) => return true,
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => return false,
        }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn map_source(path: &Path) -> PathBuf {
    MapSpec::parse(path)
        .map(|map| map.source)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn same_map(left: &Path, right: &Path, project_dir: &Path) -> bool {
    let resolve = |path: PathBuf| {
        let path = to_absolute(path, project_dir);
        std::fs::canonicalize(&path).unwrap_or(path)
    };
    let left = MapSpec::parse(left).unwrap_or_else(|_| MapSpec {
        source: left.to_path_buf(),
        destination: left.to_path_buf(),
    });
    let right = MapSpec::parse(right).unwrap_or_else(|_| MapSpec {
        source: right.to_path_buf(),
        destination: right.to_path_buf(),
    });
    resolve(left.source) == resolve(right.source)
        && resolve(left.destination) == resolve(right.destination)
}

/// One thing a layer asked for that its baseline did not grant. For the
/// untrusted project it is refused and `text` is printed; for a profile
/// the same record is a widening that is applied, printed and audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The `Config` field, as spelt in TOML.
    pub field: String,
    /// What was asked for: hosts, paths, ports, `true`/`false` for a
    /// switch. Key names only when `secret`.
    pub granted: Vec<String>,
    /// The field names or carries secrets, so `granted` holds keys only.
    pub secret: bool,
    /// The project-facing warning, unchanged from before refusals had a
    /// structure.
    pub text: String,
}

impl Refusal {
    fn new(field: &str, granted: Vec<String>, text: String) -> Self {
        Self {
            field: field.to_string(),
            granted,
            secret: false,
            text,
        }
    }

    fn secret(field: &str, granted: Vec<String>, text: String) -> Self {
        Self {
            secret: true,
            ..Self::new(field, granted, text)
        }
    }
}

fn path_strings(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| p.display().to_string()).collect()
}

/// The name of an `env_pass` entry, never its value: `NAME=VALUE` gives
/// `NAME`, and a bare `NAME` gives itself.
fn env_entry_key(entry: &str) -> String {
    entry
        .split_once('=')
        .map_or(entry, |(key, _)| key)
        .to_string()
}

fn append_project_maps(
    baseline: &mut Vec<PathBuf>,
    project: Vec<PathBuf>,
    project_dir: &Path,
    field: &str,
    layer: &str,
    refusals: &mut Vec<Refusal>,
) {
    for map in project {
        let map = match MapSpec::parse(&map) {
            Ok(spec) => MapSpec {
                source: expand_tilde(spec.source),
                destination: expand_tilde(spec.destination),
            }
            .encode(),
            Err(_) => expand_tilde(map),
        };
        let spec = MapSpec::parse(&map).ok();
        let source = spec
            .as_ref()
            .map(|spec| spec.source.clone())
            .unwrap_or_else(|| map.clone());
        let destination = spec
            .as_ref()
            .map(|spec| spec.destination.clone())
            .unwrap_or_else(|| map.clone());
        let trusted_same_map = baseline
            .iter()
            .any(|allowed| same_map(allowed, &map, project_dir));
        if (!resolves_inside_project(&source, project_dir)
            || !resolves_inside_project(&destination, project_dir))
            && !trusted_same_map
        {
            refusals.push(Refusal::new(
                field,
                vec![map.display().to_string()],
                format!(
                    "{layer} map {} outside project ignored \
                     (use --rw-map/--ro-map or global config)",
                    source.display()
                ),
            ));
            continue;
        }
        if trusted_same_map
            || resolves_inside_project(&destination, project_dir)
        {
            baseline.push(map);
        }
    }
    dedup_paths(baseline);
}

/// Merge untrusted project configuration into an already trusted baseline
/// (global configuration plus CLI). Project configuration may add restrictions,
/// but never grants a capability the baseline did not already grant.
/// Whether `project_dir`'s own `.ai-jail` may grant capabilities.
///
/// Directory containment rather than glob matching: this is a trust
/// decision, and "at or beneath one of these directories" is a rule with no
/// edge cases to get wrong. Both sides are resolved first, so `..` segments
/// and symlinks cannot smuggle an unlisted project past the check.
pub fn project_config_is_trusted(
    trusted_dirs: &[PathBuf],
    project_dir: &Path,
) -> bool {
    if trusted_dirs.is_empty() {
        return false;
    }
    let Ok(project) = std::fs::canonicalize(project_dir) else {
        return false;
    };
    trusted_dirs.iter().any(|dir| {
        std::fs::canonicalize(expand_tilde(dir.clone()))
            .is_ok_and(|dir| project.starts_with(&dir))
    })
}

/// Merge a project `.ai-jail` that the global config marked trusted via
/// `trust_project_config`, using the same semantics as a global
/// `[commands.<name>]` table: it may enable capabilities, not only tighten.
pub fn merge_trusted_project(global: Config, mut local: Config) -> Config {
    // The project layer is merged after `merge` has already expanded global
    // and CLI paths, so its own `~/...` entries have to be expanded here.
    // Without this they stay relative and `absolutize_user_paths` prepends
    // the project directory, turning `~/.npmrc` into `<project>/~/.npmrc`
    // (#126). The untrusted path already expands, in `append_project_maps`.
    expand_user_paths(&mut local);
    merge_trusted(global, local)
}

pub fn merge_with_global_report(
    baseline: Config,
    local: Config,
    project_dir: &Path,
) -> (Config, Vec<Refusal>) {
    merge_layer_report(baseline, local, project_dir, PROJECT_LAYER)
}

/// The label the project merge has always printed in front of a refusal.
const PROJECT_LAYER: &str = "project .ai-jail";

/// [`merge_with_global_report`] for any layer that must not widen
/// `baseline` silently. `layer` heads every refusal text: the project
/// passes [`PROJECT_LAYER`], so its messages stay byte-identical, and a
/// profile passes `profile 'NAME'`, whose refusals are its widenings.
pub(crate) fn merge_layer_report(
    baseline: Config,
    local: Config,
    project_dir: &Path,
    layer: &str,
) -> (Config, Vec<Refusal>) {
    let mut c = baseline;
    let mut warnings: Vec<Refusal> = Vec::new();
    // A project cannot nominate itself, or anything else, as trusted.
    if !local.trust_project_config.is_empty() {
        warnings.push(Refusal::new(
            "trust_project_config",
            path_strings(&local.trust_project_config),
            format!(
                "{layer} trust_project_config ignored: only the global \
                 config can mark a directory trusted"
            ),
        ));
    }
    if c.command.is_empty() && !local.command.is_empty() {
        c.command = local.command;
    }
    let trusted_rw_maps = c.rw_maps.clone();
    append_project_maps(
        &mut c.ro_maps,
        local.ro_maps,
        project_dir,
        "ro_maps",
        layer,
        &mut warnings,
    );
    append_project_maps(
        &mut c.rw_maps,
        local.rw_maps,
        project_dir,
        "rw_maps",
        layer,
        &mut warnings,
    );
    c.rw_maps.retain(|map| {
        let destination = to_absolute(
            MapSpec::parse(map)
                .map(|spec| spec.destination)
                .unwrap_or_else(|_| map.clone()),
            project_dir,
        );
        let overlaps_ro = c.ro_maps.iter().any(|ro| {
            let ro_destination = to_absolute(
                MapSpec::parse(ro)
                    .map(|spec| spec.destination)
                    .unwrap_or_else(|_| ro.clone()),
                project_dir,
            );
            destination.starts_with(&ro_destination)
                || ro_destination.starts_with(&destination)
        });
        if overlaps_ro && trusted_rw_maps.contains(map) {
            return true;
        }
        if overlaps_ro {
            warnings.push(Refusal::new(
                "rw_maps",
                vec![destination.display().to_string()],
                format!(
                    "{layer} rw map {} ignored because it overlaps a \
                     trusted read-only map",
                    destination.display()
                ),
            ));
            return false;
        }
        true
    });
    append_project_maps(
        &mut c.overlay_maps,
        local.overlay_maps,
        project_dir,
        "overlay_maps",
        layer,
        &mut warnings,
    );
    c.hide_dotdirs.extend(local.hide_dotdirs);
    dedup_strings(&mut c.hide_dotdirs);
    c.mask.extend(local.mask);
    dedup_paths(&mut c.mask);
    c.deny_paths.extend(local.deny_paths);
    dedup_paths(&mut c.deny_paths);
    for exception in local.mask_exceptions {
        warnings.push(Refusal::new(
            "mask_exceptions",
            vec![exception.display().to_string()],
            format!("{layer} mask exception {} ignored", exception.display()),
        ));
    }
    for exception in local.deny_path_exceptions {
        warnings.push(Refusal::new(
            "deny_path_exceptions",
            vec![exception.display().to_string()],
            format!(
                "{layer} deny-path exception {} ignored",
                exception.display()
            ),
        ));
    }
    dedup_paths(&mut c.mask_exceptions);
    dedup_paths(&mut c.deny_path_exceptions);

    macro_rules! monotonic {
        ($field:ident, $enabled:expr) => {
            if let Some(value) = local.$field {
                let candidate = Config {
                    $field: Some(value),
                    ..c.clone()
                };
                if !$enabled(&candidate) || $enabled(&c) {
                    c.$field = Some(value);
                } else {
                    warnings.push(Refusal::new(
                        stringify!($field),
                        vec![value.to_string()],
                        format!(
                            "{layer} {} ignored because it weakens the \
                             baseline sandbox",
                            stringify!($field)
                        ),
                    ));
                }
            }
        };
    }
    monotonic!(no_gpu, |config: &Config| config.gpu_enabled());
    monotonic!(no_docker, |config: &Config| config.docker_enabled());
    monotonic!(tailscale, |config: &Config| config.tailscale_enabled());
    monotonic!(no_display, |config: &Config| config.display_enabled());
    monotonic!(audio, |config: &Config| config.audio_enabled());
    monotonic!(github, |config: &Config| config.github_enabled());
    monotonic!(aws, |config: &Config| config.aws_enabled());
    monotonic!(kube, |config: &Config| config.kube_enabled());
    monotonic!(gcloud, |config: &Config| config.gcloud_enabled());
    monotonic!(docker_config, |config: &Config| config
        .docker_config_enabled());
    monotonic!(kvm, |config: &Config| config.kvm_enabled());
    monotonic!(prompt_hosts, |config: &Config| config
        .prompt_hosts_enabled());
    monotonic!(network, |config: &Config| config.network_enabled());
    monotonic!(macos_host_ipc, |config: &Config| config
        .macos_host_ipc_enabled());
    monotonic!(macos_chromium, |config: &Config| config
        .macos_chromium_enabled());
    monotonic!(macos_trustd, |config: &Config| config
        .macos_trustd_enabled());
    monotonic!(macos_pasteboard, |config: &Config| config
        .macos_pasteboard_enabled());
    monotonic!(allow_pty, |config: &Config| config.allow_pty_enabled());
    monotonic!(allow_loopback_listen, |config: &Config| config
        .allow_loopback_listen_enabled());
    monotonic!(allow_loopback_connect, |config: &Config| config
        .allow_loopback_connect
        == Some(true));
    monotonic!(x11, |config: &Config| config.x11_enabled());
    monotonic!(host_shm, |config: &Config| config.host_shm_enabled());
    monotonic!(terminal_passthrough, |config: &Config| {
        config.terminal_passthrough_enabled()
    });
    monotonic!(terminal_appearance, |config: &Config| {
        config.terminal_appearance_enabled()
    });
    monotonic!(no_hide_config, |config: &Config| !config
        .hide_config_enabled());
    monotonic!(ssh, |config: &Config| config.ssh_enabled());
    monotonic!(pictures, |config: &Config| config.pictures_enabled());
    monotonic!(private_home, |config: &Config| !config
        .private_home_enabled());
    monotonic!(lockdown, |config: &Config| !config.lockdown_enabled());
    monotonic!(no_landlock, |config: &Config| !config.landlock_enabled());
    monotonic!(no_seccomp, |config: &Config| !config.seccomp_enabled());
    monotonic!(no_rlimits, |config: &Config| !config.rlimits_enabled());
    // Project CPUs narrow the trusted set; a set sharing no CPU with it
    // becomes the empty list, which the launch refuses.
    let kept_project = local.cpus.clone();
    let trusted = c.cpus.clone();
    let (cpus, dropped) =
        crate::sandbox::affinity::tighten_cpus(c.cpus.take(), local.cpus);
    // The kept value is the project's unless it is the trusted text
    // unchanged (no project value, or a malformed trusted list kept).
    // Compared as CPU sets: `3,1-2` and `1-3` are the same trusted value.
    let same_set = |a: &Option<String>, b: &Option<String>| match (a, b) {
        (Some(a), Some(b)) => {
            match (
                crate::sandbox::affinity::parse_cpu_list(a),
                crate::sandbox::affinity::parse_cpu_list(b),
            ) {
                (Ok(x), Ok(y)) => x == y,
                _ => a == b,
            }
        }
        _ => a == b,
    };
    if kept_project.is_some() && !same_set(&cpus, &trusted) {
        c.cpus_source = Some(crate::sandbox::rlimits::LimitSource::Project);
    }
    c.cpus = cpus;
    if dropped {
        let description = match (&c.cpus, &kept_project) {
            // The intersection is in use: say which CPUs remain.
            // No CPU left: `check_launch` refuses the launch and says why.
            (Some(set), _) if set.is_empty() => {
                format!(
                    "{layer} cpus shares no CPU with the baseline \
                 sandbox"
                )
            }
            (Some(set), Some(project))
                if set != project
                    && crate::sandbox::affinity::parse_cpu_list(set)
                        .is_ok() =>
            {
                format!(
                    "{layer} cpus narrowed to {set}: it named CPUs \
                     outside the baseline sandbox"
                )
            }
            _ => format!(
                "{layer} cpus ignored because it weakens the baseline sandbox"
            ),
        };
        let granted = kept_project
            .as_deref()
            .and_then(|set| crate::sandbox::affinity::parse_cpu_list(set).ok())
            .map(|set| crate::sandbox::affinity::format_cpu_list(&set))
            .into_iter()
            .collect();
        warnings.push(Refusal::new("cpus", granted, description));
    }
    // Per limit, the project may only tighten: its value is kept when it
    // is at or below what the trusted layers (or the default) give.
    // Compared as numbers, so "4G" tightens a trusted 8589934592.
    for (key, text) in local.rlimit {
        let candidate = Config {
            rlimit: BTreeMap::from([(key.clone(), text.clone())]),
            ..c.clone()
        };
        if crate::sandbox::rlimits::widens(&candidate, &c) {
            let field = format!("rlimit.{key}");
            let granted = key
                .parse()
                .ok()
                .and_then(|name| {
                    crate::sandbox::rlimits::RlimitValue::parse(name, &text)
                        .ok()
                })
                .map(|value| crate::sandbox::rlimits::fmt_rlim(value.as_raw()))
                .into_iter()
                .collect();
            warnings.push(Refusal::new(
                &field,
                granted,
                format!("{layer} {field} ignored because it weakens the baseline sandbox"),
            ));
        } else {
            c.rlimit_source.insert(
                key.clone(),
                crate::sandbox::rlimits::LimitSource::Project,
            );
            c.rlimit.insert(key, text);
        }
    }
    monotonic!(systemd_user, |config: &Config| config
        .systemd_user_enabled());
    monotonic!(no_mise, |config: &Config| config.mise_enabled());
    monotonic!(no_toolchains, |config: &Config| config.toolchains_enabled());
    monotonic!(no_worktree, |config: &Config| config.worktree_enabled());
    monotonic!(agent_state, |config: &Config| config.agent_state_enabled());
    monotonic!(inherit_env, |config: &Config| config.inherit_env_enabled());
    monotonic!(update_check, |config: &Config| config
        .update_check_enabled());
    monotonic!(audit_log, |config: &Config| config.audit_log_enabled());
    // These three name or carry secrets: `granted` holds key names only
    // and the text holds none, so neither can leak a value.
    if !local.env_pass.is_empty() {
        let keys = local
            .env_pass
            .iter()
            .map(|entry| env_entry_key(entry))
            .collect();
        warnings.push(Refusal::secret(
            "env_pass",
            keys,
            format!("{layer} env_pass ignored (use --env or global config)"),
        ));
    }
    if !local.env_from_file.is_empty() {
        warnings.push(Refusal::secret(
            "env_from_file",
            path_strings(&local.env_from_file),
            format!(
                "{layer} env_from_file ignored \
                 (use --env-from-file or global config)"
            ),
        ));
    }
    if !local.secret_hosts.is_empty() {
        warnings.push(Refusal::secret(
            "secret_hosts",
            local.secret_hosts.keys().cloned().collect(),
            format!(
                "{layer} secret_hosts ignored (use --secret or global config)"
            ),
        ));
    }
    if local.no_save_config.is_some() {
        c.no_save_config = local.no_save_config;
    }
    if let Some(profile) = local.browser_profile
        && c.browser_profile.as_deref() != Some(profile.as_str())
    {
        warnings.push(Refusal::new(
            "browser_profile",
            vec![profile],
            format!(
                "{layer} browser_profile ignored because it weakens the \
                 baseline sandbox"
            ),
        ));
    }
    let dropped_ports: Vec<_> = local
        .allow_tcp_ports
        .into_iter()
        .filter(|port| !c.allow_tcp_ports.contains(port))
        .collect();
    if !dropped_ports.is_empty() {
        let granted: Vec<String> =
            dropped_ports.iter().map(u16::to_string).collect();
        let text =
            format!("{layer} allow_tcp_ports ignored: {}", granted.join(", "));
        warnings.push(Refusal::new("allow_tcp_ports", granted, text));
    }
    // Filtered egress is shrink-only from an untrusted project: entries
    // already in the baseline survive (the project may narrow by
    // omission), anything new is dropped with a warning.
    let dropped_hosts: Vec<_> = local
        .allow_hosts
        .into_iter()
        .filter(|host| !c.allow_hosts.contains(host))
        .collect();
    if !dropped_hosts.is_empty() {
        let text = format!(
            "{layer} allow_hosts ignored: {}",
            dropped_hosts.join(", ")
        );
        warnings.push(Refusal::new("allow_hosts", dropped_hosts, text));
    }
    let dropped_private_hosts: Vec<_> = local
        .allow_private_hosts
        .into_iter()
        .filter(|host| !c.allow_private_hosts.contains(host))
        .collect();
    if !dropped_private_hosts.is_empty() {
        let text = format!(
            "{layer} allow_private_hosts ignored: {}",
            dropped_private_hosts.join(", ")
        );
        warnings.push(Refusal::new(
            "allow_private_hosts",
            dropped_private_hosts,
            text,
        ));
    }
    // Port forwarding is shrink-only from an untrusted project, like
    // allow_hosts: a project cannot open a path to a host service.
    let dropped_forwards: Vec<_> = local
        .forward_ports
        .into_iter()
        .filter(|port| !c.forward_ports.contains(port))
        .collect();
    if !dropped_forwards.is_empty() {
        let granted: Vec<String> =
            dropped_forwards.iter().map(u16::to_string).collect();
        let text =
            format!("{layer} forward_ports ignored: {}", granted.join(", "));
        warnings.push(Refusal::new("forward_ports", granted, text));
    }
    // Publishing is shrink-only too: a project cannot expose a jailed
    // service on the host's loopback.
    let dropped_publishes: Vec<_> = local
        .publish_ports
        .into_iter()
        .filter(|port| !c.publish_ports.contains(port))
        .collect();
    if !dropped_publishes.is_empty() {
        let granted: Vec<String> =
            dropped_publishes.iter().map(u16::to_string).collect();
        let text =
            format!("{layer} publish_ports ignored: {}", granted.join(", "));
        warnings.push(Refusal::new("publish_ports", granted, text));
    }
    if let Some(dir) = local.claude_dir {
        warnings.push(Refusal::new(
            "claude_dir",
            vec![dir.display().to_string()],
            format!(
                "{layer} claude_dir ignored \
                 (set it in global config or --claude-dir)"
            ),
        ));
    }
    (c, warnings)
}

/// Compatibility helper for trusted config-layer callers. Runtime project
/// merging must use [`merge_with_global_report`] with an explicit project dir.
#[cfg(test)]
pub fn merge_with_global(global: Config, local: Config) -> Config {
    merge_trusted(global, local)
}

/// Save project-level config to `.ai-jail` in the current dir.
/// User-level fields (status bar + resize redraw key) are excluded —
/// they belong in the global `$HOME/.ai-jail`.
#[allow(dead_code)]
pub fn save(config: &Config) {
    save_project(config, true);
}

/// Auto-save variant used by ordinary runs.
///
/// Writes nothing when the project config would carry no settings at all, so
/// a plain first run in a clean directory no longer leaves a comment-only
/// `.ai-jail` behind (issue #103). `--init` still writes that file, because
/// there the user explicitly asked for one to edit.
///
/// An untrusted project file keeps only what its next load would accept,
/// so a capability passed once on the CLI is not saved into a file that
/// then ignores it, with a warning, on every later run. A project listed
/// in the global `trust_project_config` is saved as is.
#[allow(dead_code)]
pub fn save_auto(config: &Config, project_trusted: bool, project_dir: &Path) {
    if project_trusted {
        save_project(config, false);
    } else {
        save_project(&untrusted_project_view(config, project_dir), false);
    }
}

/// The well-formed `rlimit` entries of a stored policy, values verbatim.
/// Storing does not judge a value against the built-in defaults: the
/// launch merge applies it only where it tightens the trusted value. A
/// malformed or unknown entry is dropped, as the launch merge would
/// refuse it anyway.
pub(crate) fn well_formed_rlimits(
    rlimit: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    use crate::sandbox::rlimits::{RlimitName, RlimitValue};
    rlimit
        .iter()
        .filter(|(key, text)| {
            key.parse::<RlimitName>()
                .is_ok_and(|name| RlimitValue::parse(name, text).is_ok())
        })
        .map(|(key, text)| (key.clone(), text.clone()))
        .collect()
}

/// Two stored project policies combined: per name, the smaller of the two
/// well-formed values. Merging one stored policy over another with
/// [`merge_with_global_report`] would compare against the built-in
/// defaults and drop a value between the default and the trusted value.
pub(crate) fn tighter_project_rlimits(
    stored: &BTreeMap<String, String>,
    incoming: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    use crate::sandbox::rlimits::{RlimitName, RlimitValue};
    let raw = |key: &str, text: &str| -> Option<u64> {
        let name = key.parse::<RlimitName>().ok()?;
        RlimitValue::parse(name, text).ok().map(RlimitValue::as_raw)
    };
    let mut out = well_formed_rlimits(stored);
    for (key, text) in well_formed_rlimits(incoming) {
        let tighter = out
            .get(&key)
            .and_then(|old| Some((raw(&key, old)?, raw(&key, &text)?)))
            .is_none_or(|(old, new)| new < old);
        if tighter {
            out.insert(key, text);
        }
    }
    out
}

/// What an untrusted project `.ai-jail` keeps once loaded: the project
/// layer of [`merge_with_global_report`] over a default baseline. Using the
/// merge itself keeps auto-save and loading from drifting apart when a
/// capability is added. `rlimit` is the exception: the default baseline
/// would drop a value above the built-in default that the launch merge,
/// against the trusted value, applies.
pub(crate) fn monotonic_project_constraints(
    config: &Config,
    project_dir: &Path,
) -> Config {
    let mut projected = merge_with_global_report(
        Config::default(),
        config.clone(),
        project_dir,
    )
    .0;
    projected.rlimit = well_formed_rlimits(&config.rlimit);
    projected.rlimit_source = projected
        .rlimit
        .keys()
        .map(|key| (key.clone(), crate::sandbox::rlimits::LimitSource::Project))
        .collect();
    // Command selection is execution policy rather than a restriction. It is
    // deliberately not imported from repository-controlled legacy files.
    projected.command.clear();
    projected.no_save_config = None;
    projected.no_hide_config = None;
    projected.no_status_bar = None;
    projected.status_bar_style = None;
    projected.resize_redraw_key = None;
    projected.update_check = None;
    projected.audit_log = None;
    projected
}

#[allow(dead_code)]
fn untrusted_project_view(config: &Config, project_dir: &Path) -> Config {
    merge_with_global_report(Config::default(), config.clone(), project_dir).0
}

#[allow(dead_code)]
fn save_project(config: &Config, write_when_empty: bool) {
    let mut local = config.clone();
    // Strip user-level fields from project config
    local.no_status_bar = None;
    local.status_bar_style = None;
    local.resize_redraw_key = None;
    // env_pass entries can carry secret values (--env NAME=VALUE) and
    // the project config is untrusted at merge time anyway — never
    // persist them to the project .ai-jail.
    local.env_pass.clear();
    // Only the global config can mark a directory trusted, so never write
    // this into a project file where it would be silently ignored.
    local.trust_project_config.clear();

    if !write_when_empty && config_body_is_empty(&local) {
        return;
    }
    save_to_path(&config_path(), &local);
}

/// Whether a config serializes to no settings at all — only defaults, which
/// are skipped on write, leaving a file of nothing but the header comment.
#[allow(dead_code)]
fn config_body_is_empty(config: &Config) -> bool {
    toml::to_string_pretty(config)
        .map(|body| body.trim().is_empty())
        .unwrap_or(false)
}

/// Persist user-level preferences (status bar) to `$HOME/.ai-jail`.
/// Loads the existing global config first so other fields are kept.
#[allow(dead_code)]
pub fn save_global(config: &Config) -> Result<(), String> {
    if config.no_status_bar.is_none() && config.status_bar_style.is_none() {
        return Ok(());
    }
    let Some(path) = global_config_path() else {
        return Ok(());
    };
    save_global_to_path(&path, config)
}

#[allow(dead_code)]
fn save_global_to_path(path: &Path, config: &Config) -> Result<(), String> {
    let mut global = load_global_from_path(path)?;
    if config.no_status_bar.is_some() {
        global.base.no_status_bar = config.no_status_bar;
    }
    if config.status_bar_style.is_some() {
        global.base.status_bar_style = config.status_bar_style.clone();
    }
    save_global_doc_to_path(path, &global);
    Ok(())
}

/// Comment block written at the top of every saved `.ai-jail` file
/// (project and global).
#[allow(dead_code)]
const CONFIG_FILE_HEADER: &str = "# ai-jail sandbox configuration\n\
                  # https://github.com/akitaonrails/ai-jail\n\
                  # Edit freely. Regenerate with: \
                  ai-jail --clean --init\n\n";

#[allow(dead_code)]
fn save_global_doc_to_path(path: &Path, global: &GlobalConfig) {
    let header = CONFIG_FILE_HEADER;
    // A trusted symlink is followed for writes too, so a stow-managed
    // global config stays writable instead of reading fine but failing to
    // save. The target passes the same checks load applies.
    let resolved;
    let mut path = path;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    {
        match trusted_symlink_target(path) {
            Ok(target) => {
                resolved = target;
                path = resolved.as_path();
            }
            Err(e) => {
                output::warn(&format!(
                    "Refusing to write {}: {e}",
                    path.display()
                ));
                return;
            }
        }
    }
    if let Err(e) = ensure_regular_target_or_absent(path) {
        output::warn(&format!("Refusing to write {}: {e}", path.display()));
        return;
    }
    let mut on_disk = global.clone();
    collapse_tilde_config(&mut on_disk.base);
    for command_config in on_disk.commands.values_mut() {
        collapse_tilde_config(command_config);
    }
    match toml::to_string_pretty(&on_disk) {
        Ok(body) => {
            let contents = format!("{header}{body}");
            if let Err(e) = write_atomic(path, &contents) {
                output::warn(&format!(
                    "Failed to write {}: {e}",
                    path.display()
                ));
            }
        }
        Err(e) => {
            output::warn(&format!("Failed to serialize config: {e}"));
        }
    }
}

#[allow(dead_code)]
fn save_to_path(path: &Path, config: &Config) {
    let header = CONFIG_FILE_HEADER;
    if let Err(e) = ensure_regular_target_or_absent(path) {
        output::warn(&format!("Refusing to write {}: {e}", path.display()));
        return;
    }
    // Re-collapse `$HOME/...` prefixes back to `~/...` so the on-disk
    // file stays portable across machines and stable across runs.
    // Issue #52: configs typed with `~/.claude` were rewritten to
    // absolute paths and lost their shareability.
    let mut on_disk = config.clone();
    collapse_tilde_config(&mut on_disk);
    match toml::to_string_pretty(&on_disk) {
        Ok(body) => {
            let contents = format!("{header}{body}");
            if let Err(e) = write_atomic(path, &contents) {
                output::warn(&format!(
                    "Failed to write {}: {e}",
                    path.display()
                ));
            }
        }
        Err(e) => {
            output::warn(&format!("Failed to serialize config: {e}"));
        }
    }
}

#[allow(dead_code)]
fn collapse_tilde_config(config: &mut Config) {
    transform_map_specs(&mut config.rw_maps, |path| collapse_tilde(&path));
    transform_map_specs(&mut config.ro_maps, |path| collapse_tilde(&path));
    collapse_tilde_vec(&mut config.overlay_maps);
    collapse_tilde_vec(&mut config.mask);
    collapse_tilde_vec(&mut config.deny_paths);
    collapse_tilde_vec(&mut config.mask_exceptions);
    collapse_tilde_vec(&mut config.deny_path_exceptions);
    if let Some(p) = config.claude_dir.take() {
        config.claude_dir = Some(collapse_tilde(&p));
    }
}

#[allow(dead_code)]
fn ensure_regular_target_or_absent(path: &Path) -> Result<(), String> {
    crate::fsutil::ensure_regular_file_or_absent(path)
}

#[allow(dead_code)]
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    crate::fsutil::write_atomic(path, contents, false, "ai-jail")
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
}

fn dedup_strings(strings: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    strings.retain(|s| seen.insert(s.clone()));
}

fn dedup_env_pass(entries: &mut Vec<String>) {
    // Environment overrides are ordered: keep the last occurrence, so
    // MODE=a, MODE=b, MODE=a still ends with MODE=a. Deduplicate complete
    // entries, not names: a missing bare host variable must not erase an
    // earlier literal value when apply_env_pass skips it.
    entries.reverse();
    dedup_strings(entries);
    entries.reverse();
}

/// Expand a leading `~` or `~/` in a path using `$HOME`.
/// Returns the path unchanged if `$HOME` is unset or the path
/// does not start with `~`. Only leading-tilde forms are
/// rewritten; `~user` (other-user home) is left alone.
pub fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = match path.to_str() {
        Some(s) => s,
        None => return path,
    };
    if s == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
        return path;
    }
    if let Some(rest) = s.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path
}

fn expand_tilde_vec(paths: &mut [PathBuf]) {
    for p in paths.iter_mut() {
        *p = expand_tilde(std::mem::take(p));
    }
}

/// Lexically normalize a path: collapse `.` and `..` components without
/// touching the filesystem. Symbolic links are NOT resolved — we use
/// this for user-supplied paths that may not exist at config time and
/// don't want surprising symlink-following semantics.
///
/// `..` that would escape the root is dropped (so `/..` stays `/`),
/// matching the behaviour of `cd /..` in a shell.
pub fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                // Pop the last Normal component; otherwise we're at a
                // root or about to escape it, so drop the `..`.
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else if !matches!(
                    out.last(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    // Relative path with leading `..` and nothing to pop:
                    // preserve the `..` literally.
                    out.push(comp);
                }
            }
            other => out.push(other),
        }
    }
    let mut result = PathBuf::new();
    for c in out {
        result.push(c.as_os_str());
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Resolve a user-supplied path to an absolute, lexically-normalized
/// form. Relative paths are joined with `base` (typically the user's
/// invocation cwd / project dir) before normalization. Absolute paths
/// are normalized in place.
pub fn to_absolute(path: PathBuf, base: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    normalize_path(&joined)
}

fn absolutize_vec(paths: &mut [PathBuf], base: &Path) {
    for p in paths.iter_mut() {
        *p = to_absolute(std::mem::take(p), base);
    }
}

/// Resolve relative paths in user-supplied fields against `cwd` so
/// downstream sandbox code (bwrap, landlock, seatbelt) sees absolute
/// paths consistently. Called once after [`merge`] in `main`.
///
/// Without this, `ai-jail --map ../sister-project` would hand bwrap
/// a relative path which it silently rejects, leaving the mount
/// invisible inside the sandbox (issue #54).
pub fn absolutize_user_paths(config: &mut Config, cwd: &Path) {
    transform_map_specs(&mut config.rw_maps, |path| to_absolute(path, cwd));
    transform_map_specs(&mut config.ro_maps, |path| to_absolute(path, cwd));
    absolutize_vec(&mut config.overlay_maps, cwd);
}

/// Inverse of `expand_tilde`: if `path` starts with `$HOME`, rewrite
/// that prefix to `~`. Used at save time so `.ai-jail` keeps its
/// `~/...` notation across runs and stays portable across machines.
/// Returns the path unchanged if `$HOME` is unset or the path is not
/// a `$HOME` descendant.
#[allow(dead_code)]
pub fn collapse_tilde(path: &Path) -> PathBuf {
    let Ok(home) = std::env::var("HOME") else {
        return path.to_path_buf();
    };
    if home.is_empty() {
        return path.to_path_buf();
    }
    let home_path = PathBuf::from(&home);
    if path == home_path {
        return PathBuf::from("~");
    }
    if let Ok(rest) = path.strip_prefix(&home_path) {
        // Preserve `~/` form even when the rest is empty (unreachable
        // in practice — covered by the path==home branch above — but
        // cheap to handle for safety).
        if rest.as_os_str().is_empty() {
            return PathBuf::from("~");
        }
        return PathBuf::from("~").join(rest);
    }
    path.to_path_buf()
}

#[allow(dead_code)]
fn collapse_tilde_vec(paths: &mut [PathBuf]) {
    for p in paths.iter_mut() {
        *p = collapse_tilde(p);
    }
}

pub fn merge(cli: &CliArgs, existing: Config) -> Config {
    let mut config = existing;

    // command: CLI replaces config
    if !cli.command.is_empty() {
        config.command = cli.command.clone();
    }

    // rw_maps/ro_maps: CLI values appended, deduplicated
    config.rw_maps.extend(cli.rw_maps.iter().cloned());
    dedup_paths(&mut config.rw_maps);

    config.ro_maps.extend(cli.ro_maps.iter().cloned());
    dedup_paths(&mut config.ro_maps);

    config.overlay_maps.extend(cli.overlay_maps.iter().cloned());
    dedup_paths(&mut config.overlay_maps);

    // hide_dotdirs: CLI values appended, deduplicated
    config.hide_dotdirs.extend(cli.hide_dotdirs.iter().cloned());
    dedup_strings(&mut config.hide_dotdirs);

    config.mask.extend(cli.mask.iter().cloned());
    dedup_paths(&mut config.mask);

    config.deny_paths.extend(cli.deny_paths.iter().cloned());
    dedup_paths(&mut config.deny_paths);
    config
        .mask_exceptions
        .extend(cli.mask_exceptions.iter().cloned());
    dedup_paths(&mut config.mask_exceptions);
    config
        .deny_path_exceptions
        .extend(cli.deny_path_exceptions.iter().cloned());
    dedup_paths(&mut config.deny_path_exceptions);

    // Boolean flags: CLI overrides config (--no-gpu => no_gpu=Some(true), --gpu => no_gpu=Some(false))
    // Three macros for the three patterns the CLI uses:
    //  invert!: CLI positive flag flips a `no_*` config field
    //           (e.g. `--no-gpu` sets `cli.gpu=Some(false)` → `no_gpu=Some(true)`)
    //  direct!: CLI flag maps straight onto a same-named config field
    //  clone_into!: same as direct! but for non-Copy types (String, PathBuf)
    macro_rules! invert {
        ($cli_field:ident, $config_field:ident) => {
            if let Some(v) = cli.$cli_field {
                config.$config_field = Some(!v);
            }
        };
    }
    macro_rules! direct {
        ($field:ident) => {
            if let Some(v) = cli.$field {
                config.$field = Some(v);
            }
        };
    }
    macro_rules! clone_into {
        ($field:ident) => {
            if let Some(ref v) = cli.$field {
                config.$field = Some(v.clone());
            }
        };
    }

    invert!(gpu, no_gpu);
    invert!(docker, no_docker);
    direct!(tailscale);
    invert!(display, no_display);
    direct!(audio);
    direct!(github);
    direct!(aws);
    direct!(kube);
    direct!(gcloud);
    direct!(docker_config);
    direct!(kvm);
    direct!(prompt_hosts);
    direct!(network);
    direct!(macos_host_ipc);
    direct!(macos_chromium);
    direct!(macos_trustd);
    direct!(macos_pasteboard);
    direct!(allow_pty);
    direct!(allow_loopback_listen);
    direct!(allow_loopback_connect);
    direct!(x11);
    direct!(host_shm);
    direct!(terminal_passthrough);
    direct!(terminal_appearance);
    direct!(agent_state);
    direct!(inherit_env);
    direct!(update_check);
    direct!(audit_log);
    invert!(mise, no_mise);
    invert!(toolchains, no_toolchains);
    invert!(save_config, no_save_config);
    invert!(hide_config, no_hide_config);
    direct!(ssh);
    direct!(pictures);
    clone_into!(browser_profile);
    direct!(private_home);
    invert!(worktree, no_worktree);
    direct!(lockdown);
    direct!(systemd_user);
    invert!(landlock, no_landlock);
    invert!(seccomp, no_seccomp);
    invert!(rlimits, no_rlimits);
    for (name, value) in &cli.rlimit {
        config.rlimit.insert(name.clone(), value.clone());
        config
            .rlimit_source
            .insert(name.clone(), crate::sandbox::rlimits::LimitSource::Cli);
    }
    invert!(status_bar, no_status_bar);
    clone_into!(status_bar_style);
    if cli.cpus.is_some() {
        config.cpus_source = Some(crate::sandbox::rlimits::LimitSource::Cli);
    }
    clone_into!(cpus);

    config
        .allow_tcp_ports
        .extend(cli.allow_tcp_ports.iter().copied());
    config.allow_tcp_ports.sort_unstable();
    config.allow_tcp_ports.dedup();

    config.allow_hosts.extend(cli.allow_hosts.iter().cloned());
    dedup_strings(&mut config.allow_hosts);

    config
        .allow_private_hosts
        .extend(cli.allow_private_hosts.iter().cloned());
    dedup_strings(&mut config.allow_private_hosts);

    config
        .forward_ports
        .extend(cli.forward_ports.iter().copied());
    config.forward_ports.sort_unstable();
    config.forward_ports.dedup();

    config
        .publish_ports
        .extend(cli.publish_ports.iter().copied());
    config.publish_ports.sort_unstable();
    config.publish_ports.dedup();

    config.env_pass.extend(cli.env.iter().cloned());
    dedup_env_pass(&mut config.env_pass);

    config
        .env_from_file
        .extend(cli.env_from_file.iter().cloned());
    dedup_paths(&mut config.env_from_file);

    for (key, host) in &cli.secrets {
        config.secret_hosts.insert(key.clone(), host.clone());
    }

    if let Some(p) = cli.claude_dir.clone() {
        config.claude_dir = Some(p);
    }

    expand_user_paths(&mut config);

    config
}

/// Expand a leading `~` / `~/` in every user-provided path field.
///
/// Config files are TOML, which does no shell expansion; CLI arguments are
/// shell-expanded already but re-running is harmless because `expand_tilde`
/// is idempotent. Only a leading tilde is recognized; `~user` is left alone.
///
/// Every layer that reaches the sandbox has to pass through here. `merge`
/// covers global + CLI, and a trusted project layer is merged in after that,
/// so it expands separately (#126) — the field list lives in one place so the
/// two cannot drift apart.
fn expand_user_paths(config: &mut Config) {
    transform_map_specs(&mut config.rw_maps, expand_tilde);
    transform_map_specs(&mut config.ro_maps, expand_tilde);
    expand_tilde_vec(&mut config.overlay_maps);
    expand_tilde_vec(&mut config.mask);
    expand_tilde_vec(&mut config.deny_paths);
    expand_tilde_vec(&mut config.mask_exceptions);
    expand_tilde_vec(&mut config.deny_path_exceptions);
    expand_tilde_vec(&mut config.env_from_file);
    if let Some(p) = config.claude_dir.take() {
        config.claude_dir = Some(expand_tilde(p));
    }
}

/// Build the project-local config to write during automatic saves.
///
/// Runtime config may include values inherited from `$HOME/.ai-jail` via
/// [`merge_with_global`]. Auto-save must not copy those inherited values into
/// the project `.ai-jail`; it should persist only the existing project config
/// plus CLI-persistable changes from this invocation.
/// Project layer to persist for `--init`: the project file as it stands plus
/// whatever this invocation asked for.
///
/// Deliberately not the fully merged config. Merging the global baseline in
/// copied personal settings such as `claude_dir` and absolute home paths into
/// a repository file, where they are also inert — a project `.ai-jail` cannot
/// enable capabilities regardless (issue #110).
pub fn project_config_for_init(
    cli: &CliArgs,
    project: Config,
    invocation_cwd: &Path,
) -> Config {
    let mut to_save = merge(cli, project);
    drop_launch_only_fields(&mut to_save);
    absolutize_user_paths(&mut to_save, invocation_cwd);
    to_save
}

/// Fields a project file must not carry even when the CLI set them.
/// These fields are trusted-only. Written into the untrusted project file,
/// they could never take effect and would only warn on every launch. Forwarded
/// and published ports also tend to change from one launch to the next.
fn drop_launch_only_fields(to_save: &mut Config) {
    to_save.forward_ports.clear();
    to_save.publish_ports.clear();
    to_save.allow_private_hosts.clear();
}

pub fn project_config_for_auto_save(
    cli: &CliArgs,
    project: Config,
    invocation_cwd: &Path,
) -> Config {
    let stored_project_command = project.command.clone();
    // `--rlimit` and `--cpus` are this launch's choice. Only the project
    // policy's own entries are saved: a CLI value written here would pin
    // every later launch to it.
    let project_rlimit = project.rlimit.clone();
    let project_cpus = project.cpus.clone();
    let mut to_save = merge(cli, project);
    to_save.rlimit = project_rlimit;
    to_save.cpus = project_cpus;

    // A CLI-passed command is transient when the project already has a stored
    // command. Preserve that project default instead of flipping it between
    // agents on ordinary runs; `--init` remains the explicit way to change it.
    if !stored_project_command.is_empty() && !cli.command.is_empty() {
        to_save.command = stored_project_command;
    }

    // The project's own limits are saved as they are. Filtering them
    // against the built-in defaults erased a value between the default and
    // a raised trusted value, which the launch merge had just applied.
    // That merge stays the only tighten-only decision.
    to_save.rlimit = well_formed_rlimits(&to_save.rlimit);
    to_save.rlimit_source.clear();
    to_save.cpus_source = None;

    drop_launch_only_fields(&mut to_save);
    absolutize_user_paths(&mut to_save, invocation_cwd);
    to_save
}

pub fn display_status(config: &Config, stored_path: Option<&Path>) {
    let Some(path) = stored_path.map(Path::to_path_buf) else {
        output::info("No contributing project policy.");
        return;
    };
    if !path.exists() {
        output::info("No .ai-jail config file found in current directory.");
        return;
    }
    output::info(&format!("Config: {}", path.display()));

    print_command(config);
    print_path_list("  RW maps", &config.rw_maps);
    print_path_list("  RO maps", &config.ro_maps);
    print_path_list("  Overlay maps", &config.overlay_maps);
    print_string_list("  Hide dotdirs", &config.hide_dotdirs);
    print_path_list("  Masked files", &config.mask);
    print_path_list("  Denied paths", &config.deny_paths);
    print_path_list("  Mask exceptions", &config.mask_exceptions);
    print_path_list("  Deny exceptions", &config.deny_path_exceptions);

    print_opt_in_tristate("  GPU", config.no_gpu);
    print_opt_in_tristate("  Docker", config.no_docker);
    print_shared_or_hidden("  Tailscale", config.tailscale);
    print_opt_in_tristate("  Display", config.no_display);
    print_opt_in_enabled("  Audio", config.audio);
    print_opt_in_enabled("  GitHub creds", config.github);
    print_opt_in_enabled("  AWS creds", config.aws);
    print_opt_in_enabled("  Kube creds", config.kube);
    print_opt_in_enabled("  gcloud creds", config.gcloud);
    print_opt_in_enabled("  Docker config", config.docker_config);
    print_opt_in_enabled("  KVM", config.kvm);
    print_network_mode(config);
    print_opt_in_enabled("  Host prompt", config.prompt_hosts);
    print_opt_in_enabled("  macOS host IPC", config.macos_host_ipc);
    print_opt_in_enabled("  macOS Chromium", config.macos_chromium);
    print_opt_in_enabled("  macOS trustd", config.macos_trustd);
    print_opt_in_enabled("  macOS pasteboard", config.macos_pasteboard);
    print_opt_in_enabled("  Allow PTY", config.allow_pty);
    print_opt_in_enabled("  Loopback listen", config.allow_loopback_listen);
    print_opt_in_enabled(
        "  Loopback connect (OPEN)",
        config.allow_loopback_connect,
    );
    print_opt_in_enabled("  X11", config.x11);
    print_opt_in_enabled("  Host shared memory", config.host_shm);
    print_opt_in_enabled("  Terminal passthrough", config.terminal_passthrough);
    print_opt_in_enabled("  Terminal appearance", config.terminal_appearance);
    print_default_on_enabled("  Agent state", config.agent_state);
    print_opt_in_enabled("  Full env inherit", config.inherit_env);
    // Names only: an env_pass entry is how a secret enters the sandbox, so
    // `status` must never print its value.
    print_string_list("  Env passthrough", &env_pass_names(&config.env_pass));
    print_path_list("  Env from file", &config.env_from_file);
    print_opt_in_enabled("  Update check", config.update_check);
    print_opt_in_enabled("  Audit log", config.audit_log);
    print_opt_in_tristate("  Git worktree", config.no_worktree);
    print_auto_tristate("  Mise", config.no_mise);
    print_auto_tristate("  Toolchains", config.no_toolchains);
    print_default_on_tristate("  Save config", config.no_save_config);
    print_default_on_tristate("  Hide .ai-jail", config.no_hide_config);
    print_shared_or_hidden("  SSH keys", config.ssh);
    print_shared_or_hidden("  Pictures", config.pictures);
    print_browser_profile(config.browser_profile.as_deref());
    print_private_home(config.private_home);
    print_auto_tristate("  Landlock", config.no_landlock);
    print_auto_tristate("  Seccomp", config.no_seccomp);
    print_auto_tristate("  Rlimits", config.no_rlimits);
    print_shared_or_hidden("  systemd --user", config.systemd_user);
    print_auto_tristate("  Lockdown", config.lockdown.map(|v| !v));
    print_allow_tcp_ports(&config.allow_tcp_ports, config.lockdown_enabled());
    print_default_on_tristate("  Status bar", config.no_status_bar);
    if config.status_bar_enabled() {
        output::status_header("  Style", config.status_bar_style());
    }
    if let Some(key) = config.resize_redraw_key.as_deref() {
        output::status_header("  Resize redraw", key);
    }
    if let Some(dir) = &config.claude_dir {
        output::status_header("  Claude dir", &dir.display().to_string());
    }
}

fn print_command(config: &Config) {
    if config.command.is_empty() {
        output::status_header("  Command", "(default: bash)");
    } else {
        output::status_header("  Command", &config.command.join(" "));
    }
}

fn print_path_list(label: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let joined = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    output::status_header(label, &joined);
}

fn print_string_list(label: &str, strings: &[String]) {
    if strings.is_empty() {
        return;
    }
    output::status_header(label, &strings.join(", "));
}

/// Render a `no_*` field with the default-off convention:
/// Some(true) → "disabled", Some(false) → "enabled", None → "auto".
fn print_auto_tristate(label: &str, val: Option<bool>) {
    let v = match val {
        Some(true) => "disabled",
        Some(false) => "enabled",
        None => "auto",
    };
    output::status_header(label, v);
}

/// Render a `no_*` field that is disabled unless explicitly enabled:
/// Some(true)/None → "disabled", Some(false) → "enabled".
fn print_opt_in_tristate(label: &str, val: Option<bool>) {
    let v = match val {
        Some(false) => "enabled",
        Some(true) => "disabled",
        None => "disabled (default)",
    };
    output::status_header(label, v);
}

/// Render a `no_*` field with the default-on convention:
/// Some(true) → "disabled", Some(false) → "enabled", None → "enabled (default)".
fn print_default_on_tristate(label: &str, val: Option<bool>) {
    let v = match val {
        Some(true) => "disabled",
        Some(false) => "enabled",
        None => "enabled (default)",
    };
    output::status_header(label, v);
}

/// For ssh/pictures: explicit-on shares the dir, anything else hides it.
fn print_shared_or_hidden(label: &str, val: Option<bool>) {
    let v = if val == Some(true) {
        "shared (read-only)"
    } else {
        "hidden"
    };
    output::status_header(label, v);
}

fn print_opt_in_enabled(label: &str, val: Option<bool>) {
    let v = if val == Some(true) {
        "enabled"
    } else {
        "disabled"
    };
    output::status_header(label, v);
}

/// Render a capability that is enabled by default: disabled only on an
/// explicit `Some(false)`.
fn print_default_on_enabled(label: &str, val: Option<bool>) {
    let v = if val == Some(false) {
        "disabled"
    } else {
        "enabled"
    };
    output::status_header(label, v);
}

fn print_browser_profile(profile: Option<&str>) {
    let v = match profile {
        Some("off" | "none" | "disabled") => "disabled",
        Some(value) => value,
        None => "auto",
    };
    output::status_header("  Browser profile", v);
}

fn print_private_home(val: Option<bool>) {
    let v = match val {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "enabled (default)",
    };
    output::status_header("  Private home", v);
}

fn print_allow_tcp_ports(ports: &[u16], lockdown: bool) {
    if ports.is_empty() {
        return;
    }
    let joined = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let note = if lockdown {
        ""
    } else {
        " (only effective in lockdown mode)"
    };
    output::status_header("  Allow TCP ports", &format!("{joined}{note}"));
}

fn print_network_mode(config: &Config) {
    let v = match config.network_mode() {
        NetworkMode::Full => "enabled".to_string(),
        NetworkMode::Filtered => {
            format!(
                "filtered ({} hosts)",
                config.allow_hosts.len() + config.allow_private_hosts.len()
            )
        }
        NetworkMode::Off => "disabled".to_string(),
    };
    output::status_header("  Network", &v);
    if config.network_mode() == NetworkMode::Filtered {
        print_string_list("  Allow hosts", &config.allow_hosts);
        print_string_list("  Allow private hosts", &config.allow_private_hosts);
    }
    if !config.forward_ports.is_empty() {
        let joined = config
            .forward_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        output::status_header("  Forward ports", &joined);
    }
    if !config.publish_ports.is_empty() {
        let joined = config
            .publish_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        output::status_header("  Publish ports", &joined);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn redaction_masks_env_values_but_keeps_names() {
        let text = "Failed to parse /x/config.toml: TOML parse error at line 1\n1 | env_pass = [\"API_TOKEN=s3cr3t-value\"]\n  |  ^\n";
        let redacted = super::redact_env_assignments(text);
        assert!(redacted.contains("API_TOKEN=<redacted>"), "{redacted}");
        assert!(!redacted.contains("s3cr3t-value"), "{redacted}");
        assert!(redacted.contains("Failed to parse /x/config.toml"));
        // A bare token that is not an assignment is left alone.
        assert_eq!(
            super::redact_env_assignments("a = 1 and b=2"),
            "a = 1 and b=<redacted>"
        );
    }

    #[test]
    fn env_pass_names_hide_values_and_survive_malformed_entries() {
        let names = super::env_pass_names(&[
            "API_TOKEN=s3cr3t".into(),
            "PLAIN".into(),
            "=broken".into(),
        ]);
        assert_eq!(names, vec!["API_TOKEN", "PLAIN", "=broken"]);
        assert!(!names.iter().any(|name| name.contains("s3cr3t")));
    }

    use super::*;
    use crate::cli::CliArgs;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    // Tests that call set_current_dir take the crate-wide ENV_LOCK: the
    // working directory is process-global, so no other env-mutating or
    // child-spawning test may interleave with the window.
    fn cwd_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn serialize_config(config: &Config) -> Result<String, String> {
        toml::to_string_pretty(config).map_err(|e| e.to_string())
    }

    // ── Parsing tests ──────────────────────────────────────────

    #[test]
    fn map_spec_parses_same_path_and_alternate_destination() {
        let same = MapSpec::parse(Path::new("/opt/data")).unwrap();
        assert_eq!(same.source, PathBuf::from("/opt/data"));
        assert_eq!(same.destination, PathBuf::from("/opt/data"));
        assert!(!same.is_alternate());

        let alternate =
            MapSpec::parse(Path::new("/host/data:/jail/data:copy")).unwrap();
        assert_eq!(alternate.source, PathBuf::from("/host/data"));
        assert_eq!(alternate.destination, PathBuf::from("/jail/data:copy"));
        assert!(alternate.is_alternate());
    }

    #[test]
    fn map_spec_rejects_empty_components_and_root() {
        let error = MapSpec::parse(Path::new(":/jail")).unwrap_err();
        assert!(error.contains("empty source"));

        let error = MapSpec::parse(Path::new("/host:")).unwrap_err();
        assert!(error.contains("empty destination"));

        let root_source = MapSpec::parse(Path::new("/:/jail")).unwrap();
        let error = root_source.validate().unwrap_err();
        assert!(error.contains("root source"));

        let root_destination = MapSpec::parse(Path::new("/host:/")).unwrap();
        let error = root_destination.validate().unwrap_err();
        assert!(error.contains("root destination"));
    }

    #[test]
    fn map_spec_validate_rejects_empty_components() {
        let empty_source = MapSpec {
            source: PathBuf::new(),
            destination: PathBuf::from("/jail"),
        };
        let error = empty_source.validate().unwrap_err();
        assert!(error.contains("empty source"));

        let empty_destination = MapSpec {
            source: PathBuf::from("/host"),
            destination: PathBuf::new(),
        };
        let error = empty_destination.validate().unwrap_err();
        assert!(error.contains("empty destination"));
    }

    #[test]
    fn map_spec_encoding_keeps_legacy_shape() {
        let same = MapSpec {
            source: PathBuf::from("/opt/data"),
            destination: PathBuf::from("/opt/data"),
        };
        assert_eq!(same.encode(), PathBuf::from("/opt/data"));

        let alternate = MapSpec {
            source: PathBuf::from("/host/data"),
            destination: PathBuf::from("/jail/data"),
        };
        assert_eq!(alternate.encode(), PathBuf::from("/host/data:/jail/data"));
    }

    #[test]
    fn map_spec_preserves_but_rejects_non_utf8_bytes() {
        fn assert_rejected(
            encoded_bytes: &[u8],
            source: &[u8],
            destination: &[u8],
            component: &str,
        ) {
            let encoded =
                PathBuf::from(OsString::from_vec(encoded_bytes.to_vec()));
            let map = MapSpec::parse(&encoded).unwrap();

            assert_eq!(map.source.as_os_str().as_bytes(), source);
            assert_eq!(map.destination.as_os_str().as_bytes(), destination);
            assert_eq!(map.encode().as_os_str().as_bytes(), encoded_bytes);

            let error = map.validate().unwrap_err();
            assert!(error.contains(component), "unexpected error: {error}");
            assert!(error.contains("UTF-8"), "unexpected error: {error}");
        }

        assert_rejected(
            b"/host/\xff/data:/jail/data",
            b"/host/\xff/data",
            b"/jail/data",
            "source",
        );
        assert_rejected(
            b"/host/data:/jail/\xfe/data:copy",
            b"/host/data",
            b"/jail/\xfe/data:copy",
            "destination",
        );
    }

    #[test]
    fn regression_v3_4_2_config_without_pasteboard() {
        let cfg = parse_toml("macos_host_ipc = false\nmacos_trustd = true\n")
            .unwrap();
        assert!(!cfg.macos_host_ipc_enabled());
        assert!(cfg.macos_trustd_enabled());
        assert!(!serialize_config(&cfg).unwrap().contains("macos_pasteboard"));
    }

    #[test]
    fn parse_minimal_config() {
        let cfg = parse_toml("").unwrap();
        assert!(cfg.command.is_empty());
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
        assert_eq!(cfg.no_save_config, None);
        assert_eq!(cfg.lockdown, None);
        assert_eq!(cfg.macos_host_ipc, None);
        assert!(!cfg.macos_host_ipc_enabled());
        assert_eq!(cfg.macos_chromium, None);
        assert!(!cfg.macos_chromium_enabled());
        assert_eq!(cfg.macos_trustd, None);
        assert!(!cfg.macos_trustd_enabled());
        assert_eq!(cfg.allow_pty, None);
        assert!(!cfg.allow_pty_enabled());
        assert_eq!(cfg.allow_loopback_listen, None);
        assert!(!cfg.allow_loopback_listen_enabled());
    }

    #[test]
    fn macos_trustd_is_opt_in_and_project_cannot_enable_it() {
        let project = Config {
            macos_trustd: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.macos_trustd_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("macos_trustd"))
        );

        // A trusted layer may enable it, and the project may still
        // tighten it back off.
        let global = Config {
            macos_trustd: Some(true),
            ..Config::default()
        };
        let project = Config {
            macos_trustd: Some(false),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(global, project, Path::new("/project"));
        assert!(!merged.macos_trustd_enabled());
        assert!(warnings.is_empty());

        let enabled = Config {
            macos_trustd: Some(true),
            ..Config::default()
        };
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("macos_trustd = true")
        );
    }

    #[test]
    fn macos_pasteboard_is_opt_in_and_project_cannot_enable_it() {
        let project = Config {
            macos_pasteboard: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.macos_pasteboard_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("macos_pasteboard"))
        );

        // A trusted layer may enable it, and the project may still
        // tighten it back off.
        let global = Config {
            macos_pasteboard: Some(true),
            ..Config::default()
        };
        let project = Config {
            macos_pasteboard: Some(false),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(global, project, Path::new("/project"));
        assert!(!merged.macos_pasteboard_enabled());
        assert!(warnings.is_empty());

        let enabled = Config {
            macos_pasteboard: Some(true),
            ..Config::default()
        };
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("macos_pasteboard = true")
        );
    }

    #[test]
    fn allow_pty_is_opt_in_and_project_cannot_enable_it() {
        let project = Config {
            allow_pty: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.allow_pty_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("allow_pty"))
        );

        // A trusted layer may enable it, and the project may still tighten
        // it back off.
        let global = Config {
            allow_pty: Some(true),
            ..Config::default()
        };
        let project = Config {
            allow_pty: Some(false),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(global, project, Path::new("/project"));
        assert!(!merged.allow_pty_enabled());
        assert!(warnings.is_empty());

        let enabled = Config {
            allow_pty: Some(true),
            ..Config::default()
        };
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("allow_pty = true")
        );
    }

    #[test]
    fn allow_loopback_listen_is_opt_in_and_project_cannot_enable_it() {
        let project = Config {
            allow_loopback_listen: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.allow_loopback_listen_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("allow_loopback_listen"))
        );

        let global = Config {
            allow_loopback_listen: Some(true),
            ..Config::default()
        };
        let project = Config {
            allow_loopback_listen: Some(false),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(global, project, Path::new("/project"));
        assert!(!merged.allow_loopback_listen_enabled());
        assert!(warnings.is_empty());

        let enabled = Config {
            allow_loopback_listen: Some(true),
            ..Config::default()
        };
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("allow_loopback_listen = true")
        );
    }

    #[test]
    fn allow_loopback_connect_is_trusted_only_and_lockdown_disables_it() {
        let project = Config {
            allow_loopback_connect: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.allow_loopback_connect_enabled());
        assert!(warnings.iter().any(|warning| {
            warning.text.contains("allow_loopback_connect")
        }));

        let enabled = Config {
            allow_loopback_connect: Some(true),
            ..Config::default()
        };
        assert!(enabled.allow_loopback_connect_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("allow_loopback_connect = true")
        );
        let locked = Config {
            allow_loopback_connect: Some(true),
            lockdown: Some(true),
            ..Config::default()
        };
        assert!(!locked.allow_loopback_connect_enabled());
    }

    #[test]
    fn previous_config_without_loopback_connect_keeps_it_disabled() {
        let parsed =
            parse_toml("command = ['claude']\nallow_loopback_listen = true\n")
                .unwrap();
        assert_eq!(parsed.allow_loopback_connect, None);
        assert!(!parsed.allow_loopback_connect_enabled());
    }

    #[test]
    fn macos_chromium_is_opt_in_and_project_cannot_enable_it() {
        let project = Config {
            macos_chromium: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.macos_chromium_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("macos_chromium"))
        );

        let enabled = Config {
            macos_chromium: Some(true),
            ..Config::default()
        };
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("macos_chromium = true")
        );
    }

    #[test]
    fn macos_host_ipc_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            macos_host_ipc: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.macos_host_ipc_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("macos_host_ipc"))
        );

        let enabled = Config {
            macos_host_ipc: Some(true),
            ..Config::default()
        };
        assert!(enabled.macos_host_ipc_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("macos_host_ipc = true")
        );
    }

    #[test]
    fn audio_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            audio: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.audio_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("audio"))
        );

        let enabled = Config {
            audio: Some(true),
            ..Config::default()
        };
        assert!(enabled.audio_enabled());
        assert!(serialize_config(&enabled).unwrap().contains("audio = true"));
    }

    #[test]
    fn github_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            github: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.github_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("github"))
        );

        let enabled = Config {
            github: Some(true),
            ..Config::default()
        };
        assert!(enabled.github_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("github = true")
        );
    }

    #[test]
    fn aws_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            aws: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.aws_enabled());
        assert!(warnings.iter().any(|warning| warning.text.contains("aws")));

        let enabled = Config {
            aws: Some(true),
            ..Config::default()
        };
        assert!(enabled.aws_enabled());
        assert!(serialize_config(&enabled).unwrap().contains("aws = true"));
    }

    #[test]
    fn kube_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            kube: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.kube_enabled());
        assert!(warnings.iter().any(|warning| warning.text.contains("kube")));

        let enabled = Config {
            kube: Some(true),
            ..Config::default()
        };
        assert!(enabled.kube_enabled());
        assert!(serialize_config(&enabled).unwrap().contains("kube = true"));
    }

    #[test]
    fn gcloud_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            gcloud: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.gcloud_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("gcloud"))
        );

        let enabled = Config {
            gcloud: Some(true),
            ..Config::default()
        };
        assert!(enabled.gcloud_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("gcloud = true")
        );
    }

    #[test]
    fn docker_config_is_opt_in_and_project_cannot_enable_it() {
        let baseline = Config::default();
        let project = Config {
            docker_config: Some(true),
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.docker_config_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("docker_config"))
        );

        let enabled = Config {
            docker_config: Some(true),
            ..Config::default()
        };
        assert!(enabled.docker_config_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("docker_config = true")
        );
    }

    #[test]
    fn kvm_is_opt_in_and_project_cannot_enable_it() {
        assert!(!Config::default().kvm_enabled());
        let project = Config {
            kvm: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.kvm_enabled());
        assert!(warnings.iter().any(|warning| warning.text.contains("kvm")));

        let enabled = Config {
            kvm: Some(true),
            ..Config::default()
        };
        assert!(enabled.kvm_enabled());
        assert!(serialize_config(&enabled).unwrap().contains("kvm = true"));

        // A project may still turn off a globally enabled KVM.
        let project = Config {
            kvm: Some(false),
            ..Config::default()
        };
        let (merged, _) =
            merge_with_global_report(enabled, project, Path::new("/project"));
        assert!(!merged.kvm_enabled());
    }

    #[test]
    fn prompt_hosts_is_opt_in_and_project_cannot_enable_it() {
        assert!(!Config::default().prompt_hosts_enabled());
        let project = Config {
            prompt_hosts: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.prompt_hosts_enabled());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("prompt_hosts"))
        );

        let enabled = Config {
            prompt_hosts: Some(true),
            ..Config::default()
        };
        assert!(enabled.prompt_hosts_enabled());
        assert!(
            serialize_config(&enabled)
                .unwrap()
                .contains("prompt_hosts = true")
        );

        // A project may still turn off a globally enabled prompt.
        let project = Config {
            prompt_hosts: Some(false),
            ..Config::default()
        };
        let (merged, _) =
            merge_with_global_report(enabled, project, Path::new("/project"));
        assert!(!merged.prompt_hosts_enabled());
    }

    #[test]
    fn merge_prompt_hosts_flag_overrides() {
        let cli = CliArgs {
            prompt_hosts: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, Config::default());
        assert!(merged.prompt_hosts_enabled());
    }

    #[test]
    fn merge_kvm_flag_overrides() {
        let cli = CliArgs {
            kvm: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, Config::default());
        assert!(merged.kvm_enabled());
    }

    // ── Trusted capabilities: agent_state / env / update_check ──

    #[test]
    fn parse_trusted_capabilities_and_env_pass() {
        let cfg = parse_toml(
            r#"
command = ["claude"]
agent_state = true
inherit_env = false
update_check = true
env_pass = ["ANTHROPIC_API_KEY", "CUSTOM_TOKEN=abc"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.agent_state, Some(true));
        assert!(cfg.agent_state_enabled());
        assert_eq!(cfg.inherit_env, Some(false));
        assert!(!cfg.inherit_env_enabled());
        assert_eq!(cfg.update_check, Some(true));
        assert!(cfg.update_check_enabled());
        assert_eq!(
            cfg.env_pass(),
            &[
                "ANTHROPIC_API_KEY".to_string(),
                "CUSTOM_TOKEN=abc".to_string()
            ]
        );
    }

    #[test]
    fn regression_v1_17_0_config_without_trusted_capabilities() {
        // Configs written before agent_state / inherit_env / env_pass /
        // update_check existed must still parse, defaulting each new
        // field to its safe default (capabilities off, no env pass).
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.agent_state, None);
        // agent-state is ON by default now (pre-authentication); the rest of
        // the trusted capabilities stay opt-in/off.
        assert!(cfg.agent_state_enabled());
        assert_eq!(cfg.inherit_env, None);
        assert!(!cfg.inherit_env_enabled());
        assert!(cfg.env_pass().is_empty());
        assert_eq!(cfg.update_check, None);
        assert!(!cfg.update_check_enabled());
    }

    #[test]
    fn trusted_capability_accessors() {
        let config = Config::default();
        // agent-state is now ON by default (pre-authentication); inherit_env
        // and update_check stay opt-in/off.
        assert!(config.agent_state_enabled());
        assert!(!config.inherit_env_enabled());
        assert!(!config.update_check_enabled());
        // Explicit false disables it...
        assert!(
            !Config {
                agent_state: Some(false),
                ..Config::default()
            }
            .agent_state_enabled()
        );
        // ...and --lockdown disables it (folded into the accessor).
        assert!(
            !Config {
                lockdown: Some(true),
                ..Config::default()
            }
            .agent_state_enabled()
        );
    }

    #[test]
    fn merge_cli_trusted_capability_flags_and_env() {
        let existing = Config::default();
        let cli = CliArgs {
            agent_state: Some(true),
            inherit_env: Some(true),
            update_check: Some(false),
            env: vec![
                "ANTHROPIC_API_KEY".into(),
                "CUSTOM=value".into(),
                "ANTHROPIC_API_KEY".into(),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.agent_state, Some(true));
        assert_eq!(merged.inherit_env, Some(true));
        assert_eq!(merged.update_check, Some(false));
        assert_eq!(
            merged.env_pass,
            vec!["CUSTOM=value".to_string(), "ANTHROPIC_API_KEY".to_string()]
        );
    }

    #[test]
    fn project_config_cannot_enable_trusted_capabilities() {
        let project = Config {
            agent_state: Some(true),
            inherit_env: Some(true),
            update_check: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        // agent-state is ON by default, so a project asserting it is a no-op
        // (nothing to escalate, no warning) — it stays on. inherit_env and
        // update_check remain off and warn when a project tries to enable them.
        assert!(merged.agent_state_enabled());
        assert!(!merged.inherit_env_enabled());
        assert!(!merged.update_check_enabled());
        for field in ["inherit_env", "update_check"] {
            assert!(
                warnings.iter().any(|warning| warning.text.contains(field)),
                "missing warning for {field}"
            );
        }

        // Explicitly disabling is a tightening: always accepted.
        let project = Config {
            agent_state: Some(false),
            inherit_env: Some(false),
            update_check: Some(false),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config {
                agent_state: Some(true),
                inherit_env: Some(true),
                update_check: Some(true),
                ..Config::default()
            },
            project,
            Path::new("/project"),
        );
        assert!(!merged.agent_state_enabled());
        assert!(!merged.inherit_env_enabled());
        assert!(!merged.update_check_enabled());
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_env_pass_is_ignored() {
        let project = Config {
            env_pass: vec!["AWS_SESSION_TOKEN".into()],
            trust_project_config: vec![],
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.env_pass.is_empty());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("env_pass ignored"))
        );
    }

    #[test]
    fn global_command_table_layers_trusted_capabilities() {
        let global = parse_global_toml(
            r#"
[commands.claude]
agent_state = true
env_pass = ["ANTHROPIC_API_KEY"]
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();
        assert!(selected.agent_state_enabled());
        assert_eq!(selected.env_pass, vec!["ANTHROPIC_API_KEY".to_string()]);
    }

    #[test]
    fn save_does_not_persist_env_pass() {
        let config = Config {
            runtime_harnesses: Vec::new(),
            command: vec!["claude".into()],
            env_pass: vec!["ANTHROPIC_API_KEY=sk-secret".into()],
            trust_project_config: vec![],
            ..Config::default()
        };
        let serialized = serialize_config(&config).unwrap();
        assert!(!serialized.contains("env_pass"));
        assert!(!serialized.contains("sk-secret"));
    }

    // ── Sandbox environment filtering ──────────────────────────

    fn sample_host_env() -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/u".to_string()),
            ("TERM".to_string(), "xterm-256color".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ("LC_ALL".to_string(), "C".to_string()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1".to_string()),
            ("TERM_PROGRAM_VERSION".to_string(), "3.4".to_string()),
            ("http_proxy".to_string(), "http://proxy:3128".to_string()),
            ("ANTHROPIC_API_KEY".to_string(), "sk-ant-secret".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "aws-secret".to_string(),
            ),
            ("GITHUB_TOKEN".to_string(), "gh-token".to_string()),
        ]
    }

    #[test]
    fn filtered_child_env_drops_credentials_by_default() {
        let env = filtered_child_env(&[], &sample_host_env());
        for leaked in ["ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"] {
            assert!(
                !env.iter().any(|(name, _)| name == leaked),
                "{leaked} must not be inherited by default"
            );
        }
    }

    #[test]
    fn filtered_child_env_keeps_allowlist_and_prefix_families() {
        let env = filtered_child_env(&[], &sample_host_env());
        for kept in [
            "PATH",
            "HOME",
            "TERM",
            "LANG",
            "LC_ALL",
            "XDG_RUNTIME_DIR",
            "TERM_PROGRAM_VERSION",
            "http_proxy",
        ] {
            assert!(
                env.iter().any(|(name, _)| name == kept),
                "{kept} must be inherited by default"
            );
        }
    }

    #[test]
    fn env_pass_keeps_credentials_with_name_and_literal() {
        // Bare NAME copies the host value; NAME=VALUE is verbatim and
        // overrides any host value.
        let env = filtered_child_env(
            &[
                "ANTHROPIC_API_KEY".to_string(),
                "GITHUB_TOKEN=explicit-token".to_string(),
            ],
            &sample_host_env(),
        );
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "ANTHROPIC_API_KEY")
                .map(|(_, value)| value.as_str()),
            Some("sk-ant-secret")
        );
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "GITHUB_TOKEN")
                .map(|(_, value)| value.as_str()),
            Some("explicit-token")
        );
    }

    #[test]
    fn env_pass_missing_host_variable_is_skipped() {
        let env = filtered_child_env(
            &["NOT_SET_ANYWHERE".to_string()],
            &sample_host_env(),
        );
        assert!(!env.iter().any(|(name, _)| name == "NOT_SET_ANYWHERE"));
    }

    #[test]
    fn merge_cli_env_restores_an_earlier_value() {
        for entries in [
            vec!["MODE=first", "MODE=second", "MODE=first"],
            vec!["MODE", "MODE=second", "MODE"],
        ] {
            let cli = CliArgs {
                env: entries.iter().map(|entry| (*entry).into()).collect(),
                ..CliArgs::default()
            };
            let merged = merge(&cli, Config::default());
            let env = filtered_child_env(
                &merged.env_pass,
                &[("MODE".into(), "first".into())],
            );
            assert_eq!(
                env,
                vec![("MODE".into(), "first".into())],
                "{entries:?}"
            );
        }
    }

    #[test]
    fn regression_env_pass_config_keeps_last_value_after_merge() {
        // Existing string-list format: repeat an earlier value after an
        // override. Loading and merging must preserve the documented order.
        let existing = parse_toml(
            r#"
command = ["sh"]
env_pass = ["MODE=first", "MODE=second", "MODE=first"]
"#,
        )
        .unwrap();
        let merged = merge(&CliArgs::default(), existing);
        assert_eq!(
            filtered_child_env(&merged.env_pass, &[]),
            vec![("MODE".into(), "first".into())]
        );
    }

    #[test]
    fn command_env_and_cli_can_restore_a_global_value() {
        let global = parse_global_toml(
            r#"
env_pass = ["MODE=first", "MODE=second"]

[commands.sh]
env_pass = ["MODE=first"]
"#,
        )
        .unwrap();
        let mut cli = CliArgs {
            command: vec!["sh".into()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();
        assert_eq!(
            filtered_child_env(&selected.env_pass, &[]),
            vec![("MODE".into(), "first".into())]
        );

        // The CLI can in turn restore the base table's other value.
        cli.env = vec!["MODE=second".into()];
        let merged = merge(&cli, selected);
        assert_eq!(
            filtered_child_env(&merged.env_pass, &[]),
            vec![("MODE".into(), "second".into())]
        );
    }

    #[test]
    fn merge_env_keeps_literal_when_later_host_variable_is_absent() {
        let cli = CliArgs {
            env: vec!["MODE=literal".into(), "MODE".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, Config::default());
        assert_eq!(
            filtered_child_env(&merged.env_pass, &[]),
            vec![("MODE".into(), "literal".into())]
        );
    }

    #[test]
    fn parse_env_entry_rejects_empty_name() {
        assert!(parse_env_entry("").is_err());
        assert!(parse_env_entry("=value").is_err());
        assert_eq!(parse_env_entry("NAME").unwrap(), ("NAME", None));
        assert_eq!(
            parse_env_entry("NAME=value").unwrap(),
            ("NAME", Some("value"))
        );
    }

    // ── Project-map symlink containment ────────────────────────

    #[test]
    fn resolves_inside_project_accepts_missing_tail_under_real_dir() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-resolve-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();

        assert!(resolves_inside_project(
            &project.join("src/newdir/nested"),
            &project
        ));
        assert!(resolves_inside_project(&project.join("newdir"), &project));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_inside_project_ignores_symlink_above_the_project_root() {
        // The project root is reached through a symlink, so the
        // canonicalized root and the caller's path spell it differently.
        // The chain walk must still terminate at the root: a symlink
        // *above* it was already resolved by canonicalizing, and treating
        // it as an escape rejected every in-project map. This is the
        // permanent state of affairs on macOS, where $TMPDIR lives under
        // `/var` -> `private/var`.
        let root = std::env::temp_dir()
            .join(format!("ai-jail-resolve-above-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let real = root.join("real");
        std::fs::create_dir_all(real.join("project/src")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let project = link.join("project");
        assert!(resolves_inside_project(
            &project.join("src/newdir"),
            &project
        ));
        assert!(resolves_inside_project(&project.join("newdir"), &project));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_inside_project_rejects_parent_traversal_in_missing_tail() {
        // The containment check ends in a lexical `starts_with`, so a `..`
        // surviving into the non-existent tail would read as inside the
        // project while resolving outside it. `to_absolute` normalizes the
        // path before the ancestor walk, which is what prevents that —
        // assert it here so the ordering cannot be refactored apart.
        let root = std::env::temp_dir()
            .join(format!("ai-jail-resolve-dotdot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();

        assert!(!resolves_inside_project(
            &project.join("missing/../../outside/loot"),
            &project
        ));
        assert!(!resolves_inside_project(
            &project.join("missing/../.."),
            &project
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_inside_project_rejects_symlink_escape_via_missing_tail() {
        // Regression: a non-existent path whose deepest existing
        // ancestor is a symlink pointing outside the project used to
        // pass the lexical check and redirect sandbox mounts.
        let root = std::env::temp_dir()
            .join(format!("ai-jail-resolve-evil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let outside = root.join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project.join("link")).unwrap();

        assert!(
            !resolves_inside_project(&project.join("link/newdir"), &project),
            "missing tail under a symlink must be rejected"
        );
        // The symlink itself (existing path) is resolved canonically.
        assert!(!resolves_inside_project(&project.join("link"), &project));

        let _ = std::fs::remove_file(project.join("link"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_inside_project_rejects_internal_symlink_ancestor_too() {
        // Fail closed: even a symlink that currently resolves inside
        // the project is rejected for missing-tail paths — it can be
        // retargeted after the check, and mount destinations should
        // use the real path instead.
        let root = std::env::temp_dir()
            .join(format!("ai-jail-resolve-internal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        std::fs::create_dir_all(project.join("data")).unwrap();
        std::os::unix::fs::symlink("data", project.join("alias")).unwrap();

        assert!(
            !resolves_inside_project(&project.join("alias/file"), &project),
            "missing tail under a symlink must fail closed"
        );

        let _ = std::fs::remove_file(project.join("alias"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regression_old_config_with_claude_dir_and_outside_map_parses() {
        let old = r#"
claude_dir = "/home/user/.claude"
rw_maps = ["/home/user/.ssh"]
"#;
        let project = parse_toml(old).unwrap();
        assert_eq!(
            project.claude_dir,
            Some(PathBuf::from("/home/user/.claude"))
        );
        assert_eq!(project.rw_maps, vec![PathBuf::from("/home/user/.ssh")]);

        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.claude_dir.is_none());
        assert!(merged.rw_maps.is_empty());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("claude_dir ignored"))
        );
        assert!(
            warnings.iter().any(|warning| warning
                .text
                .contains("outside project ignored"))
        );
    }

    #[test]
    fn project_merge_cannot_expand_baseline_capabilities() {
        let baseline = Config {
            no_gpu: Some(true),
            no_display: Some(true),
            lockdown: Some(true),
            private_home: Some(true),
            ssh: Some(false),
            allow_tcp_ports: vec![443],
            ..Config::default()
        };
        let project = Config {
            no_gpu: Some(false),
            no_display: Some(false),
            network: Some(true),
            lockdown: Some(false),
            private_home: Some(false),
            no_worktree: Some(false),
            ssh: Some(true),
            allow_tcp_ports: vec![22, 443],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(!merged.gpu_enabled());
        assert!(!merged.display_enabled());
        assert!(!merged.ssh_enabled());
        assert!(merged.lockdown_enabled());
        assert!(merged.private_home_enabled());
        assert!(!merged.network_enabled());
        assert!(!merged.worktree_enabled());
        assert_eq!(merged.allow_tcp_ports, vec![443]);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("allow_tcp_ports"))
        );
    }

    #[test]
    fn project_maps_cannot_escape_destinations_or_override_trusted_ro() {
        let baseline = Config {
            ro_maps: vec![PathBuf::from("/project/read-only")],
            mask: vec![PathBuf::from("/project/.env")],
            ..Config::default()
        };
        let project = Config {
            rw_maps: vec![
                PathBuf::from("src:/etc"),
                PathBuf::from("read-only/subdir"),
            ],
            mask: vec![PathBuf::from("*")],
            mask_exceptions: vec![PathBuf::from("*")],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert!(merged.rw_maps.is_empty());
        assert!(merged.mask.contains(&PathBuf::from("/project/.env")));
        assert_eq!(merged.mask_exceptions.len(), 0);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("outside project"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("read-only map"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.text.contains("mask exception"))
        );
    }

    #[test]
    fn gpu_and_new_opt_in_accessors_default_to_disabled() {
        let config = Config::default();
        assert!(!config.gpu_enabled());
        assert!(!config.x11_enabled());
        assert!(!config.host_shm_enabled());
        assert!(!config.terminal_passthrough_enabled());
        assert_eq!(config.terminal_appearance, None);
        assert!(!config.terminal_appearance_enabled());
        let enabled = Config {
            no_gpu: Some(false),
            x11: Some(true),
            host_shm: Some(true),
            terminal_passthrough: Some(true),
            terminal_appearance: Some(true),
            ..Config::default()
        };
        assert!(enabled.gpu_enabled());
        assert!(enabled.x11_enabled());
        assert!(enabled.host_shm_enabled());
        assert!(enabled.terminal_passthrough_enabled());
        assert!(enabled.terminal_appearance_enabled());
        assert!(
            !Config {
                terminal_appearance: Some(false),
                ..Config::default()
            }
            .terminal_appearance_enabled()
        );
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/test"]
ro_maps = ["/opt/data"]
no_gpu = true
no_docker = false
no_display = true
no_mise = false
no_save_config = true
browser_profile = "soft"
private_home = true
lockdown = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/test")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("/opt/data")]);
        assert_eq!(cfg.no_gpu, Some(true));
        assert_eq!(cfg.no_docker, Some(false));
        assert_eq!(cfg.no_display, Some(true));
        assert_eq!(cfg.no_worktree, None);
        assert_eq!(cfg.no_mise, Some(false));
        assert_eq!(cfg.no_save_config, Some(true));
        assert_eq!(cfg.browser_profile.as_deref(), Some("soft"));
        assert_eq!(cfg.browser_profile(), Some(BrowserProfile::Soft));
        assert_eq!(cfg.private_home, Some(true));
        assert!(cfg.private_home_enabled());
        assert_eq!(cfg.lockdown, Some(true));
    }

    #[test]
    fn parse_command_only() {
        let toml = r#"command = ["bash"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["bash"]);
        assert!(cfg.rw_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
    }

    #[test]
    fn parse_no_save_config_false() {
        let cfg = parse_toml("no_save_config = false").unwrap();
        assert_eq!(cfg.no_save_config, Some(false));
    }

    #[test]
    fn parse_no_save_config_true() {
        let cfg = parse_toml("no_save_config = true").unwrap();
        assert_eq!(cfg.no_save_config, Some(true));
    }

    #[test]
    fn parse_multi_word_command() {
        let toml = r#"command = ["claude", "--verbose", "--model", "opus"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude", "--verbose", "--model", "opus"]);
    }

    // ── Backward compatibility regression tests ────────────────
    // NEVER DELETE THESE. Add new ones when the format changes.

    #[test]
    fn regression_global_command_table_without_terminal_appearance_parses() {
        let global = parse_global_toml(
            r#"
terminal_passthrough = true
[commands.claude]
terminal_passthrough = false
"#,
        )
        .unwrap();
        assert_eq!(global.base.terminal_passthrough, Some(true));
        assert_eq!(global.commands["claude"].terminal_passthrough, Some(false));
        assert_eq!(global.base.terminal_appearance, None);
        assert_eq!(global.commands["claude"].terminal_appearance, None);
    }

    #[test]
    fn terminal_appearance_trusted_command_cli_and_project_precedence() {
        let global = parse_global_toml(
            r#"
terminal_appearance = false
[commands.claude]
terminal_appearance = true
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();
        assert!(selected.terminal_appearance_enabled());
        assert_eq!(
            merge(
                &CliArgs {
                    terminal_appearance: Some(false),
                    ..CliArgs::default()
                },
                selected.clone(),
            )
            .terminal_appearance,
            Some(false)
        );
        let cli_grant = merge(
            &CliArgs {
                terminal_appearance: Some(true),
                ..CliArgs::default()
            },
            Config::default(),
        );
        assert!(cli_grant.terminal_appearance_enabled());
        let (restricted, warnings) = merge_with_global_report(
            cli_grant,
            Config {
                terminal_appearance: Some(false),
                ..Config::default()
            },
            Path::new("/project"),
        );
        assert_eq!(restricted.terminal_appearance, Some(false));
        assert!(warnings.is_empty());
        let (ignored, warnings) = merge_with_global_report(
            Config::default(),
            Config {
                terminal_appearance: Some(true),
                ..Config::default()
            },
            Path::new("/project"),
        );
        assert!(!ignored.terminal_appearance_enabled());
        assert!(
            warnings
                .iter()
                .any(|w| w.text.contains("terminal_appearance"))
        );
    }

    #[test]
    fn regression_pre_alternate_destination_map_format() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/shared"]
ro_maps = ["~/.ssh"]
"#;
        let cfg = parse_toml(toml).unwrap();

        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/shared")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("~/.ssh")]);
    }

    #[test]
    fn regression_v0_1_0_config_format() {
        // This is the exact format generated by v0.1.0.
        // It must always parse successfully.
        let toml = r#"
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = []
ro_maps = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
    }

    #[test]
    fn regression_v0_1_0_config_with_maps() {
        let toml = r#"
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = ["/tmp/test"]
ro_maps = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/test")]);
    }

    #[test]
    fn regression_unknown_fields_are_ignored() {
        // A future version might remove a field. Old config files with that
        // field must still parse without error.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
some_future_field = "hello"
another_removed_field = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
    }

    #[test]
    fn regression_missing_optional_fields() {
        // A config from a newer version that only has command.
        // All other fields should default.
        let toml = r#"command = ["bash"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["bash"]);
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
        assert_eq!(cfg.no_docker, None);
        assert_eq!(cfg.no_display, None);
        assert_eq!(cfg.no_worktree, None);
        assert_eq!(cfg.no_mise, None);
        assert_eq!(cfg.no_save_config, None);
        assert_eq!(cfg.lockdown, None);
        assert_eq!(cfg.no_landlock, None);
        assert_eq!(cfg.no_status_bar, None);
        assert_eq!(cfg.resize_redraw_key, None);
        assert_eq!(cfg.browser_profile, None);
        assert_eq!(cfg.private_home, None);
        assert_eq!(cfg.no_seccomp, None);
        assert_eq!(cfg.no_rlimits, None);
        assert!(cfg.allow_tcp_ports.is_empty());
        assert_eq!(cfg.claude_dir, None);
    }

    #[test]
    fn regression_v0_3_0_config_without_no_landlock() {
        // v0.3.0 configs don't have no_landlock field.
        // They must still parse and default to landlock enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_landlock, None);
        assert!(cfg.landlock_enabled());
    }

    #[test]
    fn regression_v0_4_5_config_without_no_status_bar() {
        // v0.4.5 configs don't have no_status_bar field.
        // They must still parse and default to status bar enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_status_bar, None);
        assert!(cfg.status_bar_enabled());
    }

    #[test]
    fn regression_v3_3_0_config_without_cpus() {
        let cfg =
            parse_toml("command = [\"claude\"]\nno_rlimits = false\n").unwrap();
        assert_eq!(cfg.cpus, None);
        assert!(
            !toml::to_string(&Config::default())
                .unwrap()
                .contains("cpus")
        );
    }

    #[test]
    fn regression_v0_5_3_config_without_seccomp_rlimits() {
        // v0.5.3 configs don't have no_seccomp or no_rlimits fields.
        // They must still parse and default to both enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_seccomp, None);
        assert_eq!(cfg.no_rlimits, None);
        assert!(cfg.seccomp_enabled());
        assert!(cfg.rlimits_enabled());
    }

    #[test]
    fn regression_v0_6_0_config_without_allow_tcp_ports() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = true
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.allow_tcp_ports.is_empty());
        assert_eq!(cfg.lockdown, Some(true));
    }

    #[test]
    fn regression_v0_6_0_config_without_hide_dotdirs() {
        // v0.6.0 configs don't have hide_dotdirs field.
        // They must still parse and default to empty.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.hide_dotdirs.is_empty());
    }

    #[test]
    fn regression_v0_8_0_config_without_no_worktree() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
hide_dotdirs = []
no_gpu = false
no_docker = false
no_display = false
no_mise = false
lockdown = false
no_landlock = false
no_status_bar = false
status_bar_style = "dark"
no_seccomp = false
no_rlimits = false
allow_tcp_ports = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_worktree, None);
        assert!(!cfg.worktree_enabled());
    }

    #[test]
    fn regression_v0_10_0_config_without_private_home() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
hide_dotdirs = []
mask = []
no_gpu = false
no_docker = false
no_display = false
no_worktree = false
no_mise = false
no_save_config = false
browser_profile = "off"
lockdown = false
no_landlock = false
no_status_bar = false
status_bar_style = "pastel"
resize_redraw_key = "ctrl-shift-l"
no_seccomp = false
no_rlimits = false
allow_tcp_ports = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.private_home, None);
        assert!(cfg.private_home_enabled());
    }

    #[test]
    fn regression_v1_7_0_config_without_overlay_maps() {
        // Configs written before overlay_maps existed must still parse,
        // defaulting the new field to an empty list.
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
ro_maps = ["/opt/ro"]
hide_dotdirs = []
mask = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/rw")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("/opt/ro")]);
        assert!(cfg.overlay_maps.is_empty());
    }

    #[test]
    fn regression_old_config_without_deny_paths() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
mask = [".env"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.deny_paths.is_empty());
        assert!(cfg.mask_exceptions.is_empty());
        assert!(cfg.deny_path_exceptions.is_empty());
    }

    #[test]
    fn regression_old_config_without_systemd_user() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.systemd_user, None);
        assert!(!cfg.systemd_user_enabled());
    }

    #[test]
    fn regression_v2_2_1_config_without_kvm() {
        // Configs written before kvm existed must still parse, with KVM
        // left off.
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
no_gpu = false
audio = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.kvm, None);
        assert!(!cfg.kvm_enabled());
        assert!(cfg.audio_enabled());
    }

    #[test]
    fn regression_v2_13_1_config_without_prompt_hosts() {
        // Configs written before prompt_hosts existed must still parse,
        // with the interactive host prompt left off.
        let toml = r#"
command = ["claude"]
allow_hosts = ["github.com"]
kvm = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.prompt_hosts, None);
        assert!(!cfg.prompt_hosts_enabled());
        assert!(cfg.kvm_enabled());
    }

    #[test]
    fn parse_config_with_overlay_maps() {
        let toml = r#"
command = ["claude"]
overlay_maps = ["/home/u/.claude", "/home/u/.config/foo"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.overlay_maps,
            vec![
                PathBuf::from("/home/u/.claude"),
                PathBuf::from("/home/u/.config/foo"),
            ]
        );
    }

    #[test]
    fn parse_deny_paths() {
        let toml = r#"
command = ["claude"]
deny_paths = [".env", "secrets/*.json"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.deny_paths,
            vec![PathBuf::from(".env"), PathBuf::from("secrets/*.json")]
        );
    }

    #[test]
    fn parse_mask_and_deny_path_exceptions() {
        let cfg = parse_toml(
            "mask_exceptions = [\"**/target/**\"]\ndeny_path_exceptions = [\"public.key\"]",
        )
        .unwrap();
        assert_eq!(cfg.mask_exceptions, vec![PathBuf::from("**/target/**")]);
        assert_eq!(cfg.deny_path_exceptions, vec![PathBuf::from("public.key")]);
    }

    #[test]
    fn parse_systemd_user() {
        let cfg = parse_toml("systemd_user = true\n").unwrap();
        assert_eq!(cfg.systemd_user, Some(true));
        assert!(cfg.systemd_user_enabled());
    }

    #[test]
    fn regression_empty_config_file() {
        // An empty .ai-jail file must not crash
        let cfg = parse_toml("").unwrap();
        assert!(cfg.command.is_empty());
    }

    #[test]
    fn regression_comment_only_config() {
        let toml = "# just a comment\n# another comment\n";
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.command.is_empty());
    }

    #[test]
    fn regression_old_config_without_tailscale_parses() {
        let toml = r#"
command = ["claude"]
no_docker = false
no_gpu = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.tailscale, None);
        assert!(!cfg.tailscale_enabled());
    }

    // ── Roundtrip tests ────────────────────────────────────────

    #[test]
    fn roundtrip_serialize_deserialize() {
        let config = Config {
            runtime_harnesses: Vec::new(),
            command: vec!["claude".into()],
            rw_maps: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            ro_maps: vec![PathBuf::from("/opt/data")],
            overlay_maps: vec![PathBuf::from("/home/u/.claude")],
            hide_dotdirs: vec![".my_secrets".into(), ".proton".into()],
            mask: vec![PathBuf::from(".env")],
            deny_paths: vec![PathBuf::from("secrets.json")],
            mask_exceptions: vec![PathBuf::from("target")],
            deny_path_exceptions: vec![PathBuf::from("public.json")],
            no_gpu: Some(true),
            no_docker: None,
            tailscale: Some(true),
            no_display: Some(false),
            audio: Some(true),
            github: None,
            aws: None,
            kube: None,
            gcloud: None,
            docker_config: None,
            kvm: Some(true),
            prompt_hosts: Some(true),
            network: None,
            macos_host_ipc: None,
            macos_chromium: None,
            macos_trustd: None,
            macos_pasteboard: None,
            allow_pty: None,
            allow_loopback_listen: None,
            allow_loopback_connect: Some(true),
            x11: Some(true),
            host_shm: Some(true),
            terminal_passthrough: Some(true),
            terminal_appearance: Some(true),
            no_worktree: Some(false),
            no_mise: None,
            no_toolchains: None,
            no_save_config: Some(true),
            no_hide_config: Some(false),
            ssh: Some(true),
            pictures: None,
            browser_profile: Some("soft".into()),
            private_home: Some(true),
            lockdown: Some(true),
            no_landlock: Some(false),
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            rlimit: BTreeMap::from([("nofile".into(), "1024".into())]),
            rlimit_source: BTreeMap::new(),
            cpus_source: None,
            cpus: Some("0-3,8".into()),
            systemd_user: Some(true),
            allow_tcp_ports: vec![32000, 8080],
            allow_hosts: vec!["api.anthropic.com".into()],
            allow_private_hosts: vec!["git.internal.example".into()],
            forward_ports: vec![49374],
            publish_ports: vec![4096],
            claude_dir: None,
            agent_state: Some(true),
            inherit_env: None,
            env_pass: vec!["ANTHROPIC_API_KEY".into()],
            env_from_file: vec![PathBuf::from("/run/secrets/anthropic")],
            secret_hosts: [(
                "ANTHROPIC_API_KEY".to_string(),
                "api.anthropic.com".to_string(),
            )]
            .into_iter()
            .collect(),
            trust_project_config: vec![],
            update_check: Some(false),
            audit_log: Some(true),
        };
        let serialized = serialize_config(&config).unwrap();
        let deserialized = parse_toml(&serialized).unwrap();
        assert_eq!(deserialized.command, config.command);
        assert_eq!(deserialized.rw_maps, config.rw_maps);
        assert_eq!(deserialized.ro_maps, config.ro_maps);
        assert_eq!(deserialized.hide_dotdirs, config.hide_dotdirs);
        assert_eq!(deserialized.deny_paths, config.deny_paths);
        assert_eq!(deserialized.mask_exceptions, config.mask_exceptions);
        assert_eq!(
            deserialized.deny_path_exceptions,
            config.deny_path_exceptions
        );
        assert_eq!(deserialized.no_gpu, config.no_gpu);
        assert_eq!(deserialized.kvm, config.kvm);
        assert_eq!(deserialized.prompt_hosts, config.prompt_hosts);
        assert_eq!(deserialized.no_docker, config.no_docker);
        assert_eq!(deserialized.tailscale, config.tailscale);
        assert_eq!(deserialized.no_display, config.no_display);
        assert_eq!(
            deserialized.terminal_appearance,
            config.terminal_appearance
        );
        assert_eq!(deserialized.no_worktree, config.no_worktree);
        assert_eq!(deserialized.no_mise, config.no_mise);
        assert_eq!(deserialized.no_save_config, config.no_save_config);
        assert_eq!(deserialized.browser_profile, config.browser_profile);
        assert_eq!(deserialized.private_home, config.private_home);
        assert_eq!(deserialized.lockdown, config.lockdown);
        assert_eq!(deserialized.no_landlock, config.no_landlock);
        assert_eq!(deserialized.resize_redraw_key, config.resize_redraw_key);
        assert_eq!(deserialized.no_seccomp, config.no_seccomp);
        assert_eq!(deserialized.no_rlimits, config.no_rlimits);
        assert_eq!(deserialized.systemd_user, config.systemd_user);
        assert_eq!(deserialized.allow_tcp_ports, config.allow_tcp_ports);
        assert_eq!(deserialized.allow_hosts, config.allow_hosts);
        assert_eq!(
            deserialized.allow_private_hosts,
            config.allow_private_hosts
        );
        assert_eq!(deserialized.forward_ports, config.forward_ports);
        assert_eq!(deserialized.publish_ports, config.publish_ports);
        assert_eq!(deserialized.claude_dir, config.claude_dir);
        assert_eq!(deserialized.agent_state, config.agent_state);
        assert_eq!(deserialized.inherit_env, config.inherit_env);
        // env_pass is intentionally NOT round-tripped: entries may
        // carry `NAME=secret` literals and must never be written to
        // a config file (see save_does_not_persist_env_pass).
        // Deserialization of hand-written `env_pass` is covered by
        // parse tests.
        assert!(deserialized.env_pass.is_empty());
        // env_from_file is likewise never serialized: the paths point
        // at credential material and must not land in a config file.
        assert!(deserialized.env_from_file.is_empty());
        // secret_hosts names which variables are secrets; it is never
        // serialized either.
        assert!(deserialized.secret_hosts.is_empty());
        assert_eq!(deserialized.update_check, config.update_check);
        assert_eq!(deserialized.audit_log, config.audit_log);
    }

    #[test]
    fn serialize_default_omits_empty_defaults() {
        let serialized = serialize_config(&Config::default()).unwrap();
        assert!(
            serialized.trim().is_empty(),
            "default config should not write empty/default fields: {serialized:?}"
        );
        assert!(!serialized.contains("terminal_appearance"));
        let serialized = serialize_config(&Config {
            terminal_appearance: Some(true),
            ..Config::default()
        })
        .unwrap();
        assert!(serialized.contains("terminal_appearance = true"));
    }

    // ── Merge tests ────────────────────────────────────────────

    #[test]
    fn merge_cli_command_replaces_config() {
        let existing = Config {
            command: vec!["bash".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.command, vec!["claude"]);
    }

    #[test]
    fn merge_empty_cli_preserves_config_command() {
        let existing = Config {
            command: vec!["claude".into()],
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(merged.command, vec!["claude"]);
    }

    #[test]
    fn merge_rw_maps_appended_and_deduplicated() {
        let existing = Config {
            rw_maps: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            ..Config::default()
        };
        let cli = CliArgs {
            rw_maps: vec![PathBuf::from("/tmp/b"), PathBuf::from("/tmp/c")],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/tmp/a"),
                PathBuf::from("/tmp/b"),
                PathBuf::from("/tmp/c"),
            ]
        );
    }

    #[test]
    fn merge_ro_maps_appended_and_deduplicated() {
        let existing = Config {
            ro_maps: vec![PathBuf::from("/opt/x")],
            ..Config::default()
        };
        let cli = CliArgs {
            ro_maps: vec![PathBuf::from("/opt/x"), PathBuf::from("/opt/y")],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.ro_maps,
            vec![PathBuf::from("/opt/x"), PathBuf::from("/opt/y")]
        );
    }

    #[test]
    fn merge_deduplicates_complete_map_specifications() {
        let existing = Config {
            rw_maps: vec![PathBuf::from("/host/data:/jail/one")],
            ..Config::default()
        };
        let cli = CliArgs {
            rw_maps: vec![
                PathBuf::from("/host/data:/jail/one"),
                PathBuf::from("/host/data:/jail/two"),
            ],
            ..CliArgs::default()
        };

        let merged = merge(&cli, existing);

        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/host/data:/jail/one"),
                PathBuf::from("/host/data:/jail/two"),
            ]
        );
    }

    #[test]
    fn merge_deny_paths_appended_and_deduplicated() {
        let existing = Config {
            deny_paths: vec![PathBuf::from(".env")],
            ..Config::default()
        };
        let cli = CliArgs {
            deny_paths: vec![
                PathBuf::from(".env"),
                PathBuf::from("secrets/*.json"),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.deny_paths,
            vec![PathBuf::from(".env"), PathBuf::from("secrets/*.json")]
        );
    }

    #[test]
    fn merge_exceptions_appended_and_deduplicated() {
        let existing = Config {
            mask_exceptions: vec![PathBuf::from("target")],
            deny_path_exceptions: vec![PathBuf::from("public")],
            ..Config::default()
        };
        let cli = CliArgs {
            mask_exceptions: vec![
                PathBuf::from("target"),
                PathBuf::from("build"),
            ],
            deny_path_exceptions: vec![
                PathBuf::from("public"),
                PathBuf::from("docs"),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.mask_exceptions,
            vec![PathBuf::from("target"), PathBuf::from("build")]
        );
        assert_eq!(
            merged.deny_path_exceptions,
            vec![PathBuf::from("public"), PathBuf::from("docs")]
        );
    }

    #[test]
    fn merge_systemd_user_from_cli() {
        let existing = Config {
            systemd_user: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            systemd_user: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.systemd_user, Some(true));
    }

    #[test]
    fn merge_hide_dotdirs_appended_and_deduplicated() {
        let existing = Config {
            hide_dotdirs: vec![".my_secrets".into(), ".proton".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            hide_dotdirs: vec![".proton".into(), ".password-store".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.hide_dotdirs,
            vec![".my_secrets", ".proton", ".password-store"]
        );
    }

    #[test]
    fn parse_config_with_no_worktree() {
        let toml = r#"
command = ["claude"]
no_worktree = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_worktree, Some(true));
        assert!(!cfg.worktree_enabled());
    }

    #[test]
    fn parse_hide_dotdirs() {
        let toml = r#"
command = ["claude"]
hide_dotdirs = [".my_secrets", ".proton", ".password-store"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.hide_dotdirs,
            vec![".my_secrets", ".proton", ".password-store"]
        );
    }

    #[test]
    fn parse_tailscale_config() {
        let toml = r#"
command = ["claude"]
tailscale = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.tailscale, Some(true));
        assert!(cfg.tailscale_enabled());
    }

    #[test]
    fn merge_gpu_flag_overrides() {
        let existing = Config {
            no_gpu: Some(true),
            ..Config::default()
        };

        // --gpu sets no_gpu to false
        let cli = CliArgs {
            gpu: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_gpu, Some(false));

        // --no-gpu sets no_gpu to true
        let cli = CliArgs {
            gpu: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
    }

    #[test]
    fn merge_no_cli_flags_preserves_config_booleans() {
        let existing = Config {
            no_gpu: Some(true),
            no_docker: Some(false),
            tailscale: Some(true),
            no_display: None,
            network: None,
            macos_host_ipc: None,
            macos_chromium: None,
            macos_trustd: None,
            macos_pasteboard: None,
            allow_pty: None,
            allow_loopback_listen: None,
            allow_loopback_connect: None,
            no_worktree: Some(true),
            no_mise: Some(true),
            no_save_config: Some(true),
            lockdown: Some(true),
            no_landlock: Some(true),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.no_docker, Some(false));
        assert_eq!(merged.tailscale, Some(true));
        assert_eq!(merged.no_display, None);
        assert_eq!(merged.no_worktree, Some(true));
        assert_eq!(merged.no_mise, Some(true));
        assert_eq!(merged.no_save_config, Some(true));
        assert_eq!(merged.lockdown, Some(true));
        assert_eq!(merged.no_landlock, Some(true));
    }

    #[test]
    fn merge_all_boolean_flags() {
        let existing = Config::default();
        let cli = CliArgs {
            gpu: Some(false),         // --no-gpu
            docker: Some(false),      // --no-docker
            tailscale: Some(true),    // --tailscale
            display: Some(true),      // --display
            worktree: Some(false),    // --no-worktree
            mise: Some(true),         // --mise
            save_config: Some(false), // --no-save-config
            private_home: Some(true), // --private-home
            lockdown: Some(true),     // --lockdown
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.no_docker, Some(true));
        assert_eq!(merged.tailscale, Some(true));
        assert_eq!(merged.no_display, Some(false));
        assert_eq!(merged.no_worktree, Some(true));
        assert_eq!(merged.no_mise, Some(false));
        assert_eq!(merged.no_save_config, Some(true));
        assert_eq!(merged.private_home, Some(true));
        assert_eq!(merged.lockdown, Some(true));
    }

    #[test]
    fn merge_landlock_flag_overrides() {
        let existing = Config {
            no_landlock: None,
            ..Config::default()
        };

        // --landlock sets no_landlock to false
        let cli = CliArgs {
            landlock: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_landlock, Some(false));

        // --no-landlock sets no_landlock to true
        let cli = CliArgs {
            landlock: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_landlock, Some(true));
    }

    #[test]
    fn merge_worktree_flag_overrides() {
        let existing = Config {
            no_worktree: None,
            ..Config::default()
        };

        let cli = CliArgs {
            worktree: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_worktree, Some(false));

        let cli = CliArgs {
            worktree: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_worktree, Some(true));
    }

    #[test]
    fn merge_browser_profile_from_cli() {
        let existing = Config::default();
        let cli = CliArgs {
            browser_profile: Some("soft".into()),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.browser_profile.as_deref(), Some("soft"));
        assert_eq!(merged.browser_profile(), Some(BrowserProfile::Soft));
    }

    #[test]
    fn merge_private_home_from_cli() {
        let existing = Config {
            private_home: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            private_home: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.private_home, Some(true));
        assert!(merged.private_home_enabled());
    }

    #[test]
    fn merge_with_global_local_private_home_wins() {
        let global = Config {
            private_home: Some(true),
            ..Config::default()
        };
        let local = Config {
            private_home: Some(false),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.private_home, Some(false));
    }

    #[test]
    fn merge_with_global_local_tailscale_wins() {
        let global = Config {
            tailscale: Some(false),
            ..Config::default()
        };
        let local = Config {
            tailscale: Some(true),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.tailscale, Some(true));
    }

    #[test]
    fn auto_save_project_config_does_not_copy_global_only_scalars() {
        let global = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            tailscale: Some(true),
            private_home: Some(true),
            claude_dir: Some(PathBuf::from("/home/u/.claude-global")),
            ..Config::default()
        };
        let project = Config::default();
        let runtime = merge_with_global(global, project.clone());
        assert_eq!(runtime.no_gpu, Some(true));
        assert_eq!(
            runtime.claude_dir,
            Some(PathBuf::from("/home/u/.claude-global"))
        );

        let to_save = project_config_for_auto_save(
            &CliArgs::default(),
            project,
            Path::new("/project"),
        );
        assert_eq!(to_save.no_gpu, None);
        assert_eq!(to_save.no_docker, None);
        assert_eq!(to_save.tailscale, None);
        assert_eq!(to_save.private_home, None);
        assert_eq!(to_save.claude_dir, None);
    }

    #[test]
    fn auto_save_project_config_keeps_project_and_cli_vectors_not_global() {
        let global = Config {
            rw_maps: vec![PathBuf::from("/global/rw")],
            ro_maps: vec![PathBuf::from("/global/ro")],
            overlay_maps: vec![PathBuf::from("/global/overlay")],
            hide_dotdirs: vec![".global".into()],
            mask: vec![PathBuf::from("/global/mask")],
            allow_tcp_ports: vec![1111],
            ..Config::default()
        };
        let project = Config {
            rw_maps: vec![PathBuf::from("/project/rw")],
            ro_maps: vec![PathBuf::from("/project/ro")],
            overlay_maps: vec![PathBuf::from("/project/overlay")],
            hide_dotdirs: vec![".project".into()],
            mask: vec![PathBuf::from("/project/mask")],
            allow_tcp_ports: vec![2222],
            ..Config::default()
        };
        let runtime = merge_with_global(global, project.clone());
        assert!(runtime.rw_maps.contains(&PathBuf::from("/global/rw")));

        let cli = CliArgs {
            rw_maps: vec![PathBuf::from("cli-rw")],
            ro_maps: vec![PathBuf::from("cli-ro")],
            overlay_maps: vec![PathBuf::from("cli-overlay")],
            hide_dotdirs: vec![".cli".into()],
            mask: vec![PathBuf::from("/cli/mask")],
            allow_tcp_ports: vec![3333],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));

        assert_eq!(
            to_save.rw_maps,
            vec![
                PathBuf::from("/project/rw"),
                PathBuf::from("/project/cli-rw")
            ]
        );
        assert_eq!(
            to_save.ro_maps,
            vec![
                PathBuf::from("/project/ro"),
                PathBuf::from("/project/cli-ro")
            ]
        );
        assert_eq!(
            to_save.overlay_maps,
            vec![
                PathBuf::from("/project/overlay"),
                PathBuf::from("/project/cli-overlay"),
            ]
        );
        assert_eq!(to_save.hide_dotdirs, vec![".project", ".cli"]);
        assert_eq!(
            to_save.mask,
            vec![PathBuf::from("/project/mask"), PathBuf::from("/cli/mask")]
        );
        assert_eq!(to_save.allow_tcp_ports, vec![2222, 3333]);
    }

    #[test]
    fn auto_save_persists_cli_command_when_only_global_command_exists() {
        let global = Config {
            command: vec!["global-agent".into()],
            ..Config::default()
        };
        let project = Config::default();
        let runtime = merge_with_global(global, project.clone());
        assert_eq!(runtime.command, vec!["global-agent"]);

        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));
        assert_eq!(to_save.command, vec!["claude"]);
    }

    #[test]
    fn auto_save_project_config_preserves_existing_project_command() {
        let project = Config {
            command: vec!["claude".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            command: vec!["codex".into()],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));
        assert_eq!(to_save.command, vec!["claude"]);
    }

    #[test]
    fn auto_save_project_config_persists_cli_boolean_overrides() {
        let project = Config {
            no_gpu: Some(false),
            no_docker: Some(true),
            tailscale: Some(false),
            no_seccomp: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            gpu: Some(false),
            docker: Some(true),
            tailscale: Some(true),
            seccomp: Some(false),
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));

        assert_eq!(to_save.no_gpu, Some(true));
        assert_eq!(to_save.no_docker, Some(false));
        assert_eq!(to_save.tailscale, Some(true));
        assert_eq!(to_save.no_seccomp, Some(true));
    }

    #[test]
    fn untrusted_auto_save_drops_what_the_project_merge_refuses() {
        // Everything one CLI run can put into the project file that the
        // untrusted merge refuses on the next load, beside values it keeps.
        let to_save = Config {
            command: vec!["claude".into()],
            network: Some(false),
            mask: vec![PathBuf::from("/project/.env")],
            ro_maps: vec![
                PathBuf::from("/project/docs"),
                PathBuf::from("/etc/hostname"),
            ],
            no_gpu: Some(false),
            no_display: Some(false),
            x11: Some(true),
            ssh: Some(true),
            pictures: Some(true),
            github: Some(true),
            private_home: Some(false),
            inherit_env: Some(true),
            claude_dir: Some(PathBuf::from("/tmp/cd")),
            mask_exceptions: vec![PathBuf::from("/project/.env")],
            ..Config::default()
        };
        let saved = untrusted_project_view(&to_save, Path::new("/project"));

        assert_eq!(saved.command, vec!["claude"]);
        assert_eq!(saved.network, Some(false));
        assert_eq!(saved.mask, vec![PathBuf::from("/project/.env")]);
        assert_eq!(saved.ro_maps, vec![PathBuf::from("/project/docs")]);
        assert_eq!(saved.no_gpu, None);
        assert_eq!(saved.no_display, None);
        assert_eq!(saved.x11, None);
        assert_eq!(saved.ssh, None);
        assert_eq!(saved.pictures, None);
        assert_eq!(saved.github, None);
        assert_eq!(saved.private_home, None);
        assert_eq!(saved.inherit_env, None);
        assert_eq!(saved.claude_dir, None);
        assert!(saved.mask_exceptions.is_empty());

        // The file auto-save writes loads again without a single warning.
        let (_, warnings) = merge_with_global_report(
            Config::default(),
            saved,
            Path::new("/project"),
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn untrusted_auto_save_keeps_tightening_values() {
        let to_save = Config {
            no_gpu: Some(true),
            lockdown: Some(true),
            no_toolchains: Some(true),
            no_save_config: Some(true),
            hide_dotdirs: vec![".aws".into()],
            deny_paths: vec![PathBuf::from("/project/secrets")],
            rw_maps: vec![PathBuf::from("/project/out")],
            ..Config::default()
        };
        let saved = untrusted_project_view(&to_save, Path::new("/project"));
        assert_eq!(saved.no_gpu, Some(true));
        assert_eq!(saved.lockdown, Some(true));
        assert_eq!(saved.no_toolchains, Some(true));
        assert_eq!(saved.no_save_config, Some(true));
        assert_eq!(saved.hide_dotdirs, vec![".aws"]);
        assert_eq!(saved.deny_paths, vec![PathBuf::from("/project/secrets")]);
        assert_eq!(saved.rw_maps, vec![PathBuf::from("/project/out")]);
    }

    #[test]
    fn command_scoped_global_applies_for_cli_command() {
        let global = parse_global_toml(
            r#"
rw_maps = ["~/common"]
no_gpu = true

[commands.pi]
rw_maps = ["~/.pi", "~/.pi-lens"]
tailscale = true

[commands.claude]
rw_maps = ["~/.claude"]
tailscale = false
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["pi".into()],
            ..CliArgs::default()
        };

        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();

        assert_eq!(
            selected.rw_maps,
            vec![
                PathBuf::from("~/common"),
                PathBuf::from("~/.pi"),
                PathBuf::from("~/.pi-lens"),
            ]
        );
        assert_eq!(selected.no_gpu, Some(true));
        assert_eq!(selected.tailscale, Some(true));
        assert!(!selected.rw_maps.contains(&PathBuf::from("~/.claude")));
    }

    #[test]
    fn project_command_does_not_select_global_command_table() {
        let global = parse_global_toml(
            r#"
command = ["bash"]

[commands.claude]
ssh = true
"#,
        )
        .unwrap();
        let project = Config {
            command: vec!["claude".into()],
            ..Config::default()
        };
        let selected =
            global_config_for_command(global, &CliArgs::default(), &project)
                .unwrap();
        assert!(!selected.ssh_enabled());
    }

    #[test]
    fn managed_harness_layers_wrapper_then_harness_global_config() {
        let global = parse_global_toml(
            r#"
rw_maps = ["~/common"]
no_gpu = true

[commands.ai-memory]
rw_maps = ["~/.local/share/ai-memory"]
tailscale = true
no_docker = true

[commands.codex]
rw_maps = ["~/.codex"]
tailscale = false
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec![
                "ai-memory".into(),
                "run".into(),
                "--project".into(),
                "demo".into(),
                "codex".into(),
                "--yolo".into(),
            ],
            ..CliArgs::default()
        };

        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();

        assert_eq!(
            selected.rw_maps,
            vec![
                PathBuf::from("~/common"),
                PathBuf::from("~/.local/share/ai-memory"),
                PathBuf::from("~/.codex"),
            ]
        );
        assert_eq!(selected.no_gpu, Some(true));
        assert_eq!(selected.no_docker, Some(true));
        assert_eq!(selected.tailscale, Some(false));
    }

    #[test]
    fn positional_command_reports_each_different_applied_table_command() {
        let global = parse_global_toml(
            r#"
[commands.ai-memory]
command = ["ignored-wrapper", "secret"]
no_docker = true

[commands.codex]
command = ["ignored-harness", "secret"]
tailscale = true
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["ai-memory".into(), "run".into(), "codex".into()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command_report(global, &cli, &Config::default())
                .unwrap();
        assert_eq!(selected.ignored_command_tables, ["ai-memory", "codex"]);
        assert_eq!(selected.config.command, vec!["ignored-harness", "secret"]);
    }

    #[test]
    fn command_warning_report_omits_fallback_preference_and_redundancy() {
        let global = parse_global_toml(
            r#"
[commands.claude]
command = ["claude", "--safe"]

[commands.codex]
no_gpu = true
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["claude".into(), "--safe".into()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command_report(global, &cli, &Config::default())
                .unwrap();
        assert!(selected.ignored_command_tables.is_empty());

        let global = parse_global_toml(
            "command = ['claude']\n[commands.claude]\ncommand = ['fallback']",
        )
        .unwrap();
        let selected = global_config_for_command_report(
            global,
            &CliArgs::default(),
            &Config::default(),
        )
        .unwrap();
        assert!(selected.ignored_command_tables.is_empty());
    }

    #[test]
    fn global_project_strategy_parses_repo_root() {
        let g =
            parse_global_toml("project_strategy = \"repo-root\"\n").unwrap();
        assert_eq!(g.project_strategy, ProjectStrategy::RepoRoot);
    }

    #[test]
    fn global_without_project_strategy_defaults_to_basename() {
        let g = parse_global_toml("network = true\n").unwrap();
        assert_eq!(g.project_strategy, ProjectStrategy::Basename);
        assert_eq!(g.base.network, Some(true));
    }

    #[test]
    fn unknown_project_strategy_is_a_parse_error() {
        assert!(
            parse_global_toml("project_strategy = \"repo_root\"\n").is_err()
        );
    }

    #[test]
    fn basename_strategy_is_not_serialized() {
        let text = toml::to_string(&GlobalConfig::default()).unwrap();
        assert!(!text.contains("project_strategy"), "{text}");
    }

    #[test]
    fn project_level_project_strategy_is_ignored() {
        let cfg = parse_toml("project_strategy = \"repo-root\"\n").unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn command_warning_report_escapes_hostile_table_name() {
        let hostile = "claude\u{1b}]0;owned\u{7}";
        let global = GlobalConfig {
            commands: [(
                hostile.to_string(),
                Config {
                    command: vec!["ignored".into()],
                    ..Config::default()
                },
            )]
            .into_iter()
            .collect(),
            ..GlobalConfig::default()
        };
        let cli = CliArgs {
            command: vec![hostile.to_string()],
            ..CliArgs::default()
        };
        let selected =
            global_config_for_command_report(global, &cli, &Config::default())
                .unwrap();
        assert_eq!(selected.ignored_command_tables.len(), 1);
        assert!(!selected.ignored_command_tables[0].contains('\u{1b}'));
        assert!(!selected.ignored_command_tables[0].contains('\u{7}'));
        assert_eq!(selected.ignored_command_tables[0], "claude?]0;owned?");
    }

    #[test]
    fn ai_memory_non_run_subcommand_does_not_apply_harness_scope() {
        let global = parse_global_toml(
            r#"
[commands.ai-memory]
no_docker = true

[commands.codex]
tailscale = true
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["ai-memory".into(), "status".into(), "codex".into()],
            ..CliArgs::default()
        };

        let selected =
            global_config_for_command(global, &cli, &Config::default())
                .unwrap();

        assert_eq!(selected.no_docker, Some(true));
        assert_eq!(selected.tailscale, None);
    }

    #[test]
    fn managed_harness_scope_ignores_project_command_when_cli_absent() {
        let global = parse_global_toml(
            r#"
[commands.ai-memory]
no_docker = true

[commands.claude]
tailscale = true
"#,
        )
        .unwrap();
        let project = Config {
            command: vec![
                "ai-memory".into(),
                "run".into(),
                "--workspace=team".into(),
                "claude".into(),
            ],
            ..Config::default()
        };

        let selected =
            global_config_for_command(global, &CliArgs::default(), &project)
                .unwrap();

        assert_eq!(selected.no_docker, None);
        assert_eq!(selected.tailscale, None);
    }

    #[test]
    fn command_scoped_global_ignores_project_command_when_cli_absent() {
        let global = parse_global_toml(
            r#"
rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi"]
tailscale = true
"#,
        )
        .unwrap();
        let project = Config {
            command: vec!["pi".into()],
            ..Config::default()
        };

        let selected =
            global_config_for_command(global, &CliArgs::default(), &project)
                .unwrap();

        assert_eq!(selected.rw_maps, vec![PathBuf::from("~/common")]);
        assert_eq!(selected.tailscale, None);
    }

    #[test]
    fn command_scoped_global_uses_base_command_as_fallback() {
        let global = parse_global_toml(
            r#"
command = ["pi"]
rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi"]
tailscale = true
"#,
        )
        .unwrap();

        let selected = global_config_for_command(
            global,
            &CliArgs::default(),
            &Config::default(),
        )
        .unwrap();

        assert_eq!(selected.command, vec!["pi"]);
        assert_eq!(
            selected.rw_maps,
            vec![PathBuf::from("~/common"), PathBuf::from("~/.pi")]
        );
        assert_eq!(selected.tailscale, Some(true));
    }

    #[test]
    fn project_config_overrides_command_scoped_global() {
        let global = parse_global_toml(
            r#"
no_gpu = true
rw_maps = ["~/common"]

[commands.pi]
tailscale = true
no_docker = true
rw_maps = ["~/.pi"]
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["pi".into()],
            ..CliArgs::default()
        };
        let project = Config {
            tailscale: Some(false),
            no_docker: Some(false),
            rw_maps: vec![PathBuf::from("/project/rw")],
            ..Config::default()
        };

        let selected =
            global_config_for_command(global, &cli, &project).unwrap();
        let merged = merge_with_global(selected, project);

        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.tailscale, Some(false));
        assert_eq!(merged.no_docker, Some(false));
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("~/common"),
                PathBuf::from("~/.pi"),
                PathBuf::from("/project/rw"),
            ]
        );
    }

    #[test]
    fn project_parse_toml_ignores_commands_table() {
        let cfg = parse_toml(
            r#"
rw_maps = ["/project"]

[commands.pi]
rw_maps = ["/global-pi"]
tailscale = true
"#,
        )
        .unwrap();

        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/project")]);
        assert_eq!(cfg.tailscale, None);
    }

    #[test]
    fn browser_profile_disabled_accessor() {
        assert!(
            !Config {
                browser_profile: Some("hard".into()),
                ..Config::default()
            }
            .browser_profile_disabled()
        );
        assert!(
            Config {
                browser_profile: Some("off".into()),
                ..Config::default()
            }
            .browser_profile_disabled()
        );
    }

    #[test]
    fn merge_allow_tcp_ports_from_cli() {
        let existing = Config {
            allow_tcp_ports: vec![32000],
            ..Config::default()
        };
        let cli = CliArgs {
            allow_tcp_ports: vec![8080, 32000],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.allow_tcp_ports, vec![8080, 32000]);
    }

    #[test]
    fn merge_allow_tcp_ports_with_global() {
        let global = Config {
            allow_tcp_ports: vec![443],
            ..Config::default()
        };
        let local = Config {
            allow_tcp_ports: vec![32000, 443],
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.allow_tcp_ports, vec![443, 32000]);
    }

    #[test]
    fn allow_tcp_ports_accessor() {
        let cfg = Config {
            allow_tcp_ports: vec![32000, 8080],
            ..Config::default()
        };
        assert_eq!(cfg.allow_tcp_ports(), &[32000, 8080]);
        assert_eq!(Config::default().allow_tcp_ports(), &[] as &[u16]);
    }

    #[test]
    fn parse_config_with_allow_tcp_ports() {
        let toml = r#"
command = ["opencode"]
lockdown = true
allow_tcp_ports = [32000, 8080]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.allow_tcp_ports, vec![32000, 8080]);
    }

    #[test]
    fn parse_config_with_allow_hosts() {
        let toml = r#"
command = ["claude"]
allow_hosts = ["api.anthropic.com", "github.com"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.allow_hosts,
            vec!["api.anthropic.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn parse_config_with_allow_private_hosts() {
        let cfg = parse_toml(
            r#"allow_private_hosts = ["git.internal.example", "registry.internal.example"]"#,
        )
        .unwrap();
        assert_eq!(
            cfg.allow_private_hosts,
            vec![
                "git.internal.example".to_string(),
                "registry.internal.example".to_string()
            ]
        );
    }

    #[test]
    fn regression_v1_22_0_config_without_allow_hosts() {
        // Configs written before allow_hosts existed must still parse,
        // defaulting to an empty list (network mode unchanged).
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
hide_dotdirs = []
mask = []
deny_paths = []
no_gpu = false
no_docker = false
no_display = false
lockdown = false
no_landlock = false
no_seccomp = false
no_rlimits = false
allow_tcp_ports = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.allow_hosts.is_empty());
        assert!(cfg.allow_private_hosts.is_empty());
        assert_eq!(cfg.network_mode(), NetworkMode::Off);
    }

    #[test]
    fn network_mode_resolution() {
        assert_eq!(Config::default().network_mode(), NetworkMode::Off);
        assert_eq!(
            Config {
                allow_hosts: vec!["api.anthropic.com".into()],
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Filtered
        );
        assert_eq!(
            Config {
                allow_private_hosts: vec!["git.internal.example".into()],
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Filtered
        );
        assert_eq!(
            Config {
                network: Some(true),
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Full
        );
        // The contradictory combination resolves Full here; it is a
        // hard launch error via validate_network_flags in main.
        assert_eq!(
            Config {
                network: Some(true),
                allow_hosts: vec!["api.anthropic.com".into()],
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Full
        );
        // Explicit --no-network WITH allow_hosts composes to filtered egress
        // (not strict offline): the landlock wrapper itself re-execs with
        // `--no-network --allow-host` to express this. Strict offline is
        // `--no-network` with NO allow_hosts (the branch below).
        assert_eq!(
            Config {
                network: Some(false),
                allow_hosts: vec!["api.anthropic.com".into()],
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Filtered
        );
        // --no-network with no allow_hosts is strict offline.
        assert_eq!(
            Config {
                network: Some(false),
                ..Config::default()
            }
            .network_mode(),
            NetworkMode::Off
        );
    }

    #[test]
    fn merge_allow_hosts_from_cli() {
        let existing = Config {
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            allow_hosts: vec!["github.com".into(), "api.anthropic.com".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.allow_hosts,
            vec!["api.anthropic.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn merge_allow_private_hosts_from_trusted_layers() {
        let existing = Config {
            allow_private_hosts: vec!["git.internal.example".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            allow_private_hosts: vec![
                "registry.internal.example".into(),
                "git.internal.example".into(),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.allow_private_hosts,
            vec![
                "git.internal.example".to_string(),
                "registry.internal.example".to_string()
            ]
        );

        let trusted = merge_with_global(
            merged,
            Config {
                allow_private_hosts: vec!["ci.internal.example".into()],
                ..Config::default()
            },
        );
        assert_eq!(trusted.allow_private_hosts.len(), 3);
        assert!(trusted.host_is_allowlisted("build.ci.internal.example"));
    }

    #[test]
    fn project_allow_private_hosts_cannot_grant_access() {
        let project = Config {
            allow_private_hosts: vec!["git.internal.example".into()],
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.allow_private_hosts.is_empty());
        assert!(warnings.iter().any(|warning| {
            warning.text.contains("allow_private_hosts")
                && warning.text.contains("git.internal.example")
        }));
    }

    #[test]
    fn merge_allow_hosts_trusted_union() {
        let global = Config {
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        let local = Config {
            allow_hosts: vec!["github.com".into(), "api.anthropic.com".into()],
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(
            merged.allow_hosts,
            vec!["api.anthropic.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn project_allow_hosts_shrinks_silently() {
        // A project may narrow the baseline by omission or subset.
        let baseline = Config {
            allow_hosts: vec!["api.anthropic.com".into(), "github.com".into()],
            ..Config::default()
        };
        let project = Config {
            allow_hosts: vec!["github.com".into()],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert_eq!(
            merged.allow_hosts,
            vec!["api.anthropic.com".to_string(), "github.com".to_string()]
        );
        assert!(!warnings.iter().any(|w| w.text.contains("allow_hosts")));
    }

    #[test]
    fn project_allow_hosts_cannot_extend_baseline() {
        let baseline = Config {
            allow_hosts: vec!["api.anthropic.com".into()],
            ..Config::default()
        };
        let project = Config {
            allow_hosts: vec!["api.anthropic.com".into(), "evil.com".into()],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert_eq!(merged.allow_hosts, vec!["api.anthropic.com".to_string()]);
        assert!(
            warnings.iter().any(|w| w.text.contains("allow_hosts")
                && w.text.contains("evil.com"))
        );
    }

    #[test]
    fn regression_v2_11_2_config_without_macos_chromium() {
        // Configs written before macos_chromium existed must still parse,
        // with the Chromium rendezvous rules left off.
        let toml = r#"
command = ["claude"]
network = true
macos_host_ipc = false
rw_maps = []
ro_maps = []
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.macos_chromium_enabled());
        assert!(!toml::to_string(&config).unwrap().contains("macos_chromium"));
    }

    #[test]
    fn regression_v2_14_0_config_without_macos_trustd() {
        // Configs written before macos_trustd existed must still parse,
        // with the trustd Mach lookup left off.
        let toml = r#"
command = ["claude"]
network = true
macos_host_ipc = false
macos_chromium = false
rw_maps = []
ro_maps = []

[commands.claude]
macos_host_ipc = false
"#;
        let config: GlobalConfig = toml::from_str(toml).unwrap();
        assert!(!config.base.macos_trustd_enabled());
        assert!(!config.commands["claude"].macos_trustd_enabled());
        assert!(
            !toml::to_string(&config.base)
                .unwrap()
                .contains("macos_trustd")
        );
    }

    #[test]
    fn regression_v2_14_0_config_without_allow_pty_or_loopback_listen() {
        // Configs written before allow_pty / allow_loopback_listen existed
        // must still parse, with both grants left off and nothing new
        // serialized back.
        let toml = r#"
command = ["claude"]
network = true
macos_host_ipc = false
rw_maps = []
ro_maps = []

[commands.claude]
macos_host_ipc = false
"#;
        let config: GlobalConfig = toml::from_str(toml).unwrap();
        assert!(!config.base.allow_pty_enabled());
        assert!(!config.base.allow_loopback_listen_enabled());
        assert!(!config.commands["claude"].allow_pty_enabled());
        assert!(!config.commands["claude"].allow_loopback_listen_enabled());
        let serialized = toml::to_string(&config.base).unwrap();
        assert!(!serialized.contains("allow_pty"));
        assert!(!serialized.contains("allow_loopback_listen"));
    }

    #[test]
    fn regression_v2_2_0_config_without_forward_ports() {
        // Configs written before forward_ports existed must still parse,
        // with no port forwarded.
        let toml = r#"
command = ["claude"]
allow_hosts = ["api.anthropic.com"]
rw_maps = []
ro_maps = []
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.forward_ports().is_empty());
        // And an empty list is never written back.
        assert!(!toml::to_string(&config).unwrap().contains("forward_ports"));
    }

    #[test]
    fn regression_v2_12_0_config_without_publish_ports() {
        // Configs written before publish_ports existed must still parse,
        // with no port published.
        let toml = r#"
command = ["claude"]
allow_hosts = ["api.anthropic.com"]
forward_ports = [49374]
rw_maps = []
ro_maps = []
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.publish_ports().is_empty());
        assert_eq!(config.forward_ports(), &[49374]);
        // And an empty list is never written back.
        assert!(!toml::to_string(&config).unwrap().contains("publish_ports"));
    }

    #[test]
    fn regression_v3_3_0_global_without_profiles() {
        // Global files written before [profiles] existed must parse to
        // the same base and command tables, and must not gain a
        // `profiles` key when written back.
        let toml = r#"
allow_hosts = ["api.anthropic.com"]

[commands.claude]
ssh = true
mask = ["/usr/bin/ssh"]
"#;
        let global = parse_global_toml(toml).unwrap();
        assert_eq!(global.base.allow_hosts, ["api.anthropic.com"]);
        let claude = global.commands.get("claude").expect("command table");
        assert_eq!(claude.ssh, Some(true));
        assert_eq!(claude.mask, [PathBuf::from("/usr/bin/ssh")]);
        let written = toml::to_string(&global).unwrap();
        assert!(!written.contains("profiles"), "{written}");
        assert_eq!(parse_global_toml(&written).unwrap(), global);
    }

    #[test]
    fn project_publish_ports_cannot_extend_baseline() {
        let baseline = Config {
            publish_ports: vec![4096],
            ..Config::default()
        };
        let project = Config {
            publish_ports: vec![4096, 3000],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert_eq!(merged.publish_ports, vec![4096]);
        assert!(warnings.iter().any(
            |w| w.text.contains("publish_ports") && w.text.contains("3000")
        ));
    }

    #[test]
    fn project_publish_ports_alone_grant_nothing() {
        let project = Config {
            publish_ports: vec![4096],
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.publish_ports.is_empty());
        assert!(warnings.iter().any(|w| w.text.contains("publish_ports")));
    }

    #[test]
    fn publish_ports_are_never_saved_into_the_project() {
        let cli = CliArgs {
            publish_ports: vec![4096],
            ..CliArgs::default()
        };
        let project = Config {
            publish_ports: vec![3000],
            ..Config::default()
        };
        let auto = project_config_for_auto_save(
            &cli,
            project.clone(),
            Path::new("/project"),
        );
        assert!(auto.publish_ports.is_empty());
        let init =
            project_config_for_init(&cli, project, Path::new("/project"));
        assert!(init.publish_ports.is_empty());
    }

    #[test]
    fn trusted_layers_and_cli_union_publish_ports() {
        let global = Config {
            publish_ports: vec![4096, 3000],
            ..Config::default()
        };
        let trusted = merge_with_global(
            global,
            Config {
                publish_ports: vec![3000, 8080],
                ..Config::default()
            },
        );
        assert_eq!(trusted.publish_ports, vec![3000, 4096, 8080]);
        let cli = CliArgs {
            publish_ports: vec![5173, 8080],
            ..CliArgs::default()
        };
        assert_eq!(
            merge(&cli, trusted).publish_ports,
            vec![3000, 4096, 5173, 8080]
        );
    }

    #[test]
    fn command_table_publish_ports_apply_only_to_that_command() {
        let toml = r#"
publish_ports = [3000]

[commands.openchamber]
publish_ports = [4096]
"#;
        let for_command = |name: &str| {
            let cli = CliArgs {
                command: vec![name.into()],
                ..CliArgs::default()
            };
            global_config_for_command(
                parse_global_toml(toml).unwrap(),
                &cli,
                &Config::default(),
            )
            .unwrap()
            .publish_ports
        };
        assert_eq!(for_command("openchamber"), vec![3000, 4096]);
        assert_eq!(for_command("claude"), vec![3000]);
    }

    #[test]
    fn project_forward_ports_cannot_extend_baseline() {
        let baseline = Config {
            forward_ports: vec![49374],
            ..Config::default()
        };
        let project = Config {
            forward_ports: vec![49374, 5432],
            ..Config::default()
        };
        let (merged, warnings) =
            merge_with_global_report(baseline, project, Path::new("/project"));
        assert_eq!(merged.forward_ports, vec![49374]);
        assert!(warnings.iter().any(
            |w| w.text.contains("forward_ports") && w.text.contains("5432")
        ));
    }

    #[test]
    fn trusted_launch_only_network_grants_are_never_saved_into_the_project() {
        let cli = CliArgs {
            forward_ports: vec![49374],
            allow_private_hosts: vec!["git.internal.example".into()],
            ..CliArgs::default()
        };
        let project = Config {
            forward_ports: vec![5432],
            allow_private_hosts: vec!["registry.internal.example".into()],
            ..Config::default()
        };
        let auto = project_config_for_auto_save(
            &cli,
            project.clone(),
            Path::new("/project"),
        );
        assert!(auto.forward_ports.is_empty());
        assert!(auto.allow_private_hosts.is_empty());
        let init =
            project_config_for_init(&cli, project, Path::new("/project"));
        assert!(init.forward_ports.is_empty());
        assert!(init.allow_private_hosts.is_empty());
    }

    #[test]
    fn project_forward_ports_alone_grant_nothing() {
        let project = Config {
            forward_ports: vec![49374],
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.forward_ports.is_empty());
        assert!(warnings.iter().any(|w| w.text.contains("forward_ports")));
    }

    #[test]
    fn trusted_layers_and_cli_union_forward_ports() {
        let global = Config {
            forward_ports: vec![64342, 49374],
            ..Config::default()
        };
        let trusted = merge_with_global(
            global,
            Config {
                forward_ports: vec![49374, 8080],
                ..Config::default()
            },
        );
        assert_eq!(trusted.forward_ports, vec![8080, 49374, 64342]);
        let cli = CliArgs {
            forward_ports: vec![5173, 8080],
            ..CliArgs::default()
        };
        assert_eq!(
            merge(&cli, trusted).forward_ports,
            vec![5173, 8080, 49374, 64342]
        );
    }

    #[test]
    fn regression_v1_22_0_config_without_audit_log() {
        // Configs written before audit_log existed must still parse,
        // defaulting the audit log to off.
        let toml = r#"
command = ["claude"]
lockdown = false
update_check = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.audit_log, None);
        assert!(!cfg.audit_log_enabled());
    }

    #[test]
    fn project_cannot_enable_audit_log_but_may_disable() {
        // Enabling writes a host file: a capability the untrusted
        // project layer never gets.
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            Config {
                audit_log: Some(true),
                ..Config::default()
            },
            Path::new("/project"),
        );
        assert!(!merged.audit_log_enabled());
        assert!(warnings.iter().any(|w| w.text.contains("audit_log")));

        let (merged, warnings) = merge_with_global_report(
            Config {
                audit_log: Some(true),
                ..Config::default()
            },
            Config {
                audit_log: Some(false),
                ..Config::default()
            },
            Path::new("/project"),
        );
        assert!(!merged.audit_log_enabled());
        assert!(!warnings.iter().any(|w| w.text.contains("audit_log")));
    }

    #[test]
    fn regression_v1_22_0_config_without_env_from_file() {
        // Configs written before env_from_file existed must still
        // parse, defaulting to no credential files.
        let toml = r#"
command = ["claude"]
env_pass = ["ANTHROPIC_API_KEY"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.env_from_file.is_empty());
    }

    #[test]
    fn parse_config_with_env_from_file() {
        let toml = r#"
command = ["claude"]
env_from_file = ["/run/secrets/anthropic"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.env_from_file,
            vec![PathBuf::from("/run/secrets/anthropic")]
        );
    }

    #[test]
    fn project_env_from_file_is_ignored_with_warning() {
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            Config {
                env_from_file: vec![PathBuf::from("keys")],
                ..Config::default()
            },
            Path::new("/project"),
        );
        assert!(merged.env_from_file.is_empty());
        assert!(warnings.iter().any(|w| w.text.contains("env_from_file")));
    }

    #[test]
    fn merge_env_from_file_trusted_union_and_cli() {
        let global = Config {
            env_from_file: vec![PathBuf::from("/run/secrets/anthropic")],
            ..Config::default()
        };
        let command_table = Config {
            env_from_file: vec![PathBuf::from("/run/secrets/openai")],
            ..Config::default()
        };
        let merged = merge_with_global(global, command_table);
        assert_eq!(
            merged.env_from_file,
            vec![
                PathBuf::from("/run/secrets/anthropic"),
                PathBuf::from("/run/secrets/openai"),
            ]
        );

        let cli = CliArgs {
            env_from_file: vec![PathBuf::from("/run/secrets/grok")],
            ..CliArgs::default()
        };
        let merged = merge(&cli, merged);
        assert_eq!(merged.env_from_file.len(), 3);
    }

    fn env_file_fixture(name: &str, content: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-env-file-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let file = root.join(name);
        std::fs::write(&file, content).unwrap();
        std::fs::set_permissions(
            &file,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        (root, file)
    }

    struct EnvFileFixture {
        root: PathBuf,
        file: PathBuf,
    }

    impl EnvFileFixture {
        fn new(name: &str) -> Self {
            let (root, file) = env_file_fixture(name, "TOKEN=trusted\n");
            Self { root, file }
        }

        fn project(&self) -> PathBuf {
            self.root.join("project")
        }
    }

    impl Drop for EnvFileFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn env_from_file_parses_strict_key_value_lines() {
        let (root, file) = env_file_fixture(
            "parse",
            "# comment\n\nAPI_KEY=sk-123\nEMPTY=\nURL=https://x?a=b&c=d\nQUOTED=\"keep me\"\n",
        );
        let entries = load_env_files(&[file], &root.join("project")).unwrap();
        assert_eq!(
            entries,
            vec![
                "API_KEY=sk-123".to_string(),
                "EMPTY=".to_string(),
                // Verbatim after the first '=': no quote stripping.
                "URL=https://x?a=b&c=d".to_string(),
                "QUOTED=\"keep me\"".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regression_v1_22_0_env_from_file_preserves_legacy_loading() {
        let fixture = EnvFileFixture::new("legacy-loading");
        let file = &fixture.file;
        let text = format!(
            "command = [\"sh\"]\nno_gpu = true\nenv_from_file = [{}]\nenv_pass = [\"TOKEN=cli\"]\n",
            toml::Value::String(file.to_string_lossy().into_owned())
        );
        let config: Config = toml::from_str(&text).unwrap();
        assert_eq!(config.command, ["sh"]);
        assert_eq!(config.no_gpu, Some(true));
        let mut entries =
            load_env_files(&config.env_from_file, &fixture.project()).unwrap();
        assert_eq!(entries, ["TOKEN=trusted"]);
        entries.extend(config.env_pass);
        let mut env = Vec::new();
        apply_env_pass(&mut env, &entries, &[]);
        assert_eq!(env, [("TOKEN".to_string(), "cli".to_string())]);
    }

    #[test]
    fn env_from_file_reads_the_validated_fd_after_leaf_replacement() {
        use std::os::unix::fs::PermissionsExt;

        for symlink in [false, true] {
            let fixture =
                EnvFileFixture::new(&format!("pinned-leaf-{symlink}"));
            let directory =
                open_env_parent(&fixture.file, &fixture.project()).unwrap();
            let file = open_env_file_at(&directory, &fixture.file).unwrap();
            std::fs::rename(&fixture.file, fixture.root.join("moved")).unwrap();
            let replacement = if symlink {
                fixture.project().join("untrusted")
            } else {
                fixture.file.clone()
            };
            std::fs::write(&replacement, "TOKEN=replacement\n").unwrap();
            std::fs::set_permissions(
                &replacement,
                PermissionsExt::from_mode(0o644),
            )
            .unwrap();
            if symlink {
                std::os::unix::fs::symlink(&replacement, &fixture.file)
                    .unwrap();
            }
            let mut entries = Vec::new();
            read_env_file(file, &fixture.file, &mut entries).unwrap();
            assert_eq!(entries, ["TOKEN=trusted"]);
            assert_eq!(
                std::fs::read_to_string(&replacement).unwrap(),
                "TOKEN=replacement\n"
            );
            assert_eq!(
                std::fs::metadata(&replacement)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
    }

    #[test]
    fn env_from_file_reads_from_the_pinned_parent_after_replacement() {
        let fixture = EnvFileFixture::new("pinned-parent");
        let parent = fixture.root.join("credentials");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("keys");
        std::fs::rename(&fixture.file, &path).unwrap();
        let directory = open_env_parent(&path, &fixture.project()).unwrap();
        std::fs::rename(&parent, fixture.root.join("moved-parent")).unwrap();
        let replacement = fixture.project().join("keys");
        std::fs::write(&replacement, "TOKEN=replacement\n").unwrap();
        std::fs::set_permissions(
            &replacement,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        std::os::unix::fs::symlink(fixture.project(), &parent).unwrap();
        let file = open_env_file_at(&directory, &path).unwrap();
        let mut entries = Vec::new();
        read_env_file(file, &path, &mut entries).unwrap();
        assert_eq!(entries, ["TOKEN=trusted"]);
        // A new open of the alias must still enforce outside-project.
        let error = load_env_files(&[path], &fixture.project()).unwrap_err();
        assert!(error.contains("outside the project"));
        assert_eq!(
            std::fs::read_to_string(replacement).unwrap(),
            "TOKEN=replacement\n"
        );
    }

    #[test]
    fn env_from_file_checks_permissions_on_the_replacement_fd() {
        let fixture = EnvFileFixture::new("replacement-mode");
        let directory =
            open_env_parent(&fixture.file, &fixture.project()).unwrap();
        std::fs::rename(&fixture.file, fixture.root.join("moved")).unwrap();
        std::fs::write(&fixture.file, "TOKEN=replacement\n").unwrap();
        std::fs::set_permissions(
            &fixture.file,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        let error = open_env_file_at(&directory, &fixture.file).unwrap_err();
        assert!(error.contains("0600 or stricter"));
    }

    #[test]
    fn env_from_file_preserves_directory_aliases_and_read_only_files() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = EnvFileFixture::new("directory-alias");
        let alias = fixture.root.join("alias");
        std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
        std::fs::set_permissions(
            &fixture.file,
            PermissionsExt::from_mode(0o400),
        )
        .unwrap();
        let path = alias.join(fixture.file.file_name().unwrap());
        let entries = load_env_files(&[path], &fixture.project()).unwrap();
        assert_eq!(entries, ["TOKEN=trusted"]);
        assert_eq!(
            std::fs::metadata(&fixture.file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        let result = load_env_files(
            std::slice::from_ref(&fixture.file),
            &alias.join("project"),
        );
        assert!(result.is_ok(), "project aliases remain supported");
    }

    #[test]
    fn env_from_file_preserves_search_only_directories() {
        use std::os::unix::fs::PermissionsExt;

        struct RestoreModes(Vec<PathBuf>);
        impl Drop for RestoreModes {
            fn drop(&mut self) {
                for path in &self.0 {
                    let _ = std::fs::set_permissions(
                        path,
                        PermissionsExt::from_mode(0o700),
                    );
                }
            }
        }

        let fixture = EnvFileFixture::new("search-only");
        let parent = fixture.root.join("credentials");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("keys");
        std::fs::rename(&fixture.file, &path).unwrap();
        let restore =
            RestoreModes(vec![fixture.root.clone(), fixture.project(), parent]);
        for directory in &restore.0 {
            std::fs::set_permissions(
                directory,
                PermissionsExt::from_mode(0o111),
            )
            .unwrap();
        }
        let entries = load_env_files(&[path], &fixture.project()).unwrap();
        assert_eq!(entries, ["TOKEN=trusted"]);
        for directory in &restore.0 {
            assert_eq!(
                std::fs::metadata(directory).unwrap().permissions().mode()
                    & 0o777,
                0o111
            );
        }
    }

    #[test]
    fn env_from_file_refuses_nested_project_directory_aliases() {
        let fixture = EnvFileFixture::new("inside-alias");
        let nested = fixture.project().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::rename(&fixture.file, nested.join("keys")).unwrap();
        let alias = fixture.root.join("alias");
        std::os::unix::fs::symlink(&nested, &alias).unwrap();
        let error = load_env_files(&[alias.join("keys")], &fixture.project())
            .unwrap_err();
        assert!(error.contains("outside the project"));
    }

    #[test]
    fn env_from_file_read_errors_do_not_produce_entries() {
        let fixture = EnvFileFixture::new("read-error");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.file)
            .unwrap();
        let mut entries = vec!["EXISTING=1".to_string()];
        assert!(read_env_file(file, &fixture.file, &mut entries).is_err());
        assert_eq!(entries, ["EXISTING=1"]);
        std::fs::write(&fixture.file, b"TOKEN=trusted\n\xff").unwrap();
        assert!(
            load_env_files(
                std::slice::from_ref(&fixture.file),
                &fixture.project()
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires root to read a file owned by another UID"]
    fn env_from_file_refuses_foreign_owner_with_readable_fd() {
        use std::os::unix::fs::{MetadataExt, chown};

        // SAFETY: geteuid has no preconditions.
        assert_eq!(unsafe { nix::libc::geteuid() }, 0, "run as root");
        let fixture = EnvFileFixture::new("foreign-owner-fd");
        chown(&fixture.file, Some(1), None).unwrap();
        assert_eq!(std::fs::metadata(&fixture.file).unwrap().uid(), 1);
        assert_eq!(
            std::fs::read_to_string(&fixture.file).unwrap(),
            "TOKEN=trusted\n"
        );
        let error = load_env_files(
            std::slice::from_ref(&fixture.file),
            &fixture.project(),
        )
        .unwrap_err();
        assert!(error.contains("owned by the current user"));
        assert_eq!(
            std::fs::metadata(&fixture.file).unwrap().mode() & 0o777,
            0o600
        );
        chown(&fixture.file, Some(0), None).unwrap();
        let entries = load_env_files(
            std::slice::from_ref(&fixture.file),
            &fixture.project(),
        )
        .unwrap();
        assert_eq!(entries, ["TOKEN=trusted"]);
    }

    #[test]
    fn env_from_file_rejects_bad_lines_and_keys() {
        for (name, content) in [
            ("no-eq", "JUST_A_NAME\n"),
            ("bad-key", "1KEY=value\n"),
            ("export", "export KEY=value\n"),
            ("spaced-key", "KEY WITH SPACE=value\n"),
            ("empty-key", "=value\n"),
        ] {
            let (root, file) = env_file_fixture(name, content);
            assert!(
                load_env_files(&[file], &root.join("project")).is_err(),
                "{name} must fail closed"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn env_from_file_refuses_unsafe_files() {
        use std::os::unix::fs::PermissionsExt;

        // Missing file.
        let root = std::env::temp_dir()
            .join(format!("ai-jail-env-file-missing-{}", std::process::id()));
        let project = root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        assert!(load_env_files(&[root.join("nope")], &project).is_err());

        // Loose permissions.
        let (root, file) = env_file_fixture("loose", "A=1\n");
        std::fs::set_permissions(&file, PermissionsExt::from_mode(0o644))
            .unwrap();
        assert!(load_env_files(&[file], &root.join("project")).is_err());
        let _ = std::fs::remove_dir_all(&root);

        // Symlink.
        let (root, file) = env_file_fixture("linked", "A=1\n");
        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(load_env_files(&[link], &root.join("project")).is_err());
        let _ = std::fs::remove_dir_all(&root);

        // Inside the project directory.
        let (root, file) = env_file_fixture("outside", "A=1\n");
        let inside = root.join("project").join("keys");
        std::fs::write(&inside, "A=1\n").unwrap();
        std::fs::set_permissions(&inside, PermissionsExt::from_mode(0o600))
            .unwrap();
        let result = load_env_files(&[inside], &root.join("project"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside the project"));
        let _ = std::fs::remove_dir_all(&root);
        let _ = file;

        // Not a regular file.
        let (root, _file) = env_file_fixture("regular", "A=1\n");
        let dir = root.join("a-directory");
        std::fs::create_dir(&dir).unwrap();
        assert!(load_env_files(&[dir], &root.join("project")).is_err());
        let _ = std::fs::remove_dir_all(&root);

        // Not owned by the current user (root-owned system file; skip
        // when absent or when running as root).
        // It must be readable so refusal exercises our fd ownership
        // policy, rather than failing earlier on an OS permission error.
        let system = PathBuf::from("/etc/passwd");
        let euid = unsafe { nix::libc::geteuid() };
        if euid != 0
            && let Ok(metadata) = std::fs::symlink_metadata(&system)
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != euid {
                let (root, _file) = env_file_fixture("owned", "A=1\n");
                let result = load_env_files(&[system], &root.join("project"));
                assert!(result.is_err());
                assert!(
                    result.unwrap_err().contains("owned by the current user")
                );
                let _ = std::fs::remove_dir_all(&root);
            }
        }
    }

    #[test]
    fn env_from_file_entries_yield_to_env_flag() {
        // apply_env_pass replaces earlier values with later ones, so
        // file entries first + --env entries after = --env wins.
        let (root, file) = env_file_fixture("precedence", "TOKEN=file-value\n");
        let file_entries =
            load_env_files(&[file], &root.join("project")).unwrap();
        let mut env: Vec<(String, String)> = Vec::new();
        apply_env_pass(&mut env, &file_entries, &[]);
        apply_env_pass(&mut env, &["TOKEN=cli-value".to_string()], &[]);
        assert_eq!(env, vec![("TOKEN".to_string(), "cli-value".to_string())]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regression_v2_1_0_config_without_secret_hosts() {
        // Configs written before secret_hosts existed must still parse,
        // defaulting to no phantom bindings.
        let toml = r#"
command = ["claude"]
env_pass = ["ANTHROPIC_API_KEY"]
env_from_file = ["/run/secrets/anthropic"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.secret_hosts.is_empty());
    }

    #[test]
    fn regression_v2_8_1_auto_saved_capability_opt_ins_parse() {
        // 2.8.1 auto-save wrote CLI capability opt-ins into the project
        // file (`--pictures`, `--display`, `--claude-dir`, a map outside the
        // project). Those files must keep parsing, and the untrusted merge
        // keeps ignoring the opt-ins with a warning.
        let toml = r#"
command = ["true"]
network = false
pictures = true
no_display = false
claude_dir = "/tmp/cd"
ro_maps = ["/etc/hostname"]
mask = ["/project/.env"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.pictures, Some(true));
        assert_eq!(cfg.no_display, Some(false));
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            cfg,
            Path::new("/project"),
        );
        assert!(!merged.pictures_enabled());
        assert!(!merged.display_enabled());
        assert_eq!(merged.claude_dir, None);
        assert!(merged.ro_maps.is_empty());
        assert_eq!(merged.mask, vec![PathBuf::from("/project/.env")]);
        for field in ["pictures", "no_display", "claude_dir", "/etc/hostname"] {
            assert!(
                warnings.iter().any(|w| w.text.contains(field)),
                "no warning for {field}: {warnings:?}"
            );
        }
    }

    #[test]
    fn parse_config_with_secret_hosts_table() {
        let toml = r#"
command = ["claude"]
allow_hosts = ["api.anthropic.com"]

[secret_hosts]
ANTHROPIC_API_KEY = "api.anthropic.com"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.secret_hosts
                .get("ANTHROPIC_API_KEY")
                .map(String::as_str),
            Some("api.anthropic.com")
        );
    }

    #[test]
    fn project_secret_hosts_is_ignored_with_warning() {
        let mut project = Config::default();
        project
            .secret_hosts
            .insert("KEY".into(), "example.com".into());
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(merged.secret_hosts.is_empty());
        assert!(warnings.iter().any(|w| w.text.contains("secret_hosts")));
    }

    #[test]
    fn merge_secret_hosts_trusted_union_and_cli() {
        let mut global = Config::default();
        global
            .secret_hosts
            .insert("A_KEY".into(), "a.example.com".into());
        let mut table = Config::default();
        table
            .secret_hosts
            .insert("B_KEY".into(), "b.example.com".into());
        let merged = merge_with_global(global, table);
        assert_eq!(merged.secret_hosts.len(), 2);

        let cli = CliArgs {
            secrets: vec![("C_KEY".into(), "c.example.com".into())],
            ..CliArgs::default()
        };
        let merged = merge(&cli, merged);
        assert_eq!(merged.secret_hosts.len(), 3);
        assert_eq!(
            merged.secret_hosts.get("C_KEY").map(String::as_str),
            Some("c.example.com")
        );
    }

    #[test]
    fn merge_lockdown_flag_overrides() {
        let existing = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            lockdown: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.lockdown, Some(false));
    }

    #[test]
    fn merge_with_global_local_no_save_config_wins_false() {
        let global = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let local = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_save_config, Some(false));
    }

    #[test]
    fn merge_with_global_local_no_save_config_wins_true() {
        let global = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let local = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_save_config, Some(true));
    }

    #[test]
    fn merge_cli_save_config_overrides_config() {
        let existing = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            save_config: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_save_config, Some(false));
    }

    #[test]
    fn merge_cli_no_save_config_overrides_config() {
        let existing = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            save_config: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_save_config, Some(true));
    }

    // ── Dedup tests ────────────────────────────────────────────

    #[test]
    fn dedup_paths_removes_duplicates_preserves_order() {
        let mut paths = vec![
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            PathBuf::from("/a"),
            PathBuf::from("/c"),
            PathBuf::from("/b"),
        ];
        dedup_paths(&mut paths);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ]
        );
    }

    #[test]
    fn dedup_paths_empty() {
        let mut paths: Vec<PathBuf> = vec![];
        dedup_paths(&mut paths);
        assert!(paths.is_empty());
    }

    #[test]
    fn dedup_strings_removes_duplicates_preserves_order() {
        let mut strings = vec![
            ".my_secrets".into(),
            ".proton".into(),
            ".my_secrets".into(),
            ".aws".into(),
            ".proton".into(),
        ];
        dedup_strings(&mut strings);
        assert_eq!(strings, vec![".my_secrets", ".proton", ".aws"]);
    }

    #[test]
    fn dedup_strings_empty() {
        let mut strings: Vec<String> = vec![];
        dedup_strings(&mut strings);
        assert!(strings.is_empty());
    }

    // ── Accessor method tests ─────────────────────────────────

    #[test]
    fn gpu_enabled_accessor() {
        assert!(!Config::default().gpu_enabled());
        assert!(
            !Config {
                no_gpu: Some(true),
                ..Config::default()
            }
            .gpu_enabled()
        );
        assert!(
            Config {
                no_gpu: Some(false),
                ..Config::default()
            }
            .gpu_enabled()
        );
    }

    #[test]
    fn docker_enabled_accessor() {
        // Docker passthrough is opt-in: unset means disabled because the
        // socket grants effective host root (issue #88).
        assert!(
            !Config {
                no_docker: None,
                ..Config::default()
            }
            .docker_enabled()
        );
        assert!(
            !Config {
                no_docker: Some(true),
                ..Config::default()
            }
            .docker_enabled()
        );
        assert!(
            Config {
                no_docker: Some(false),
                ..Config::default()
            }
            .docker_enabled()
        );
    }

    #[test]
    fn tailscale_enabled_accessor() {
        assert!(!Config::default().tailscale_enabled());
        assert!(
            Config {
                tailscale: Some(true),
                ..Config::default()
            }
            .tailscale_enabled()
        );
        assert!(
            !Config {
                tailscale: Some(false),
                ..Config::default()
            }
            .tailscale_enabled()
        );
    }

    #[test]
    fn display_enabled_accessor() {
        assert!(!Config::default().display_enabled());
        assert!(
            !Config {
                no_display: Some(true),
                ..Config::default()
            }
            .display_enabled()
        );
        assert!(
            Config {
                no_display: Some(false),
                ..Config::default()
            }
            .display_enabled()
        );
    }

    #[test]
    fn audio_enabled_accessor() {
        assert!(!Config::default().audio_enabled());
        assert!(
            !Config {
                audio: Some(false),
                ..Config::default()
            }
            .audio_enabled()
        );
        assert!(
            Config {
                audio: Some(true),
                ..Config::default()
            }
            .audio_enabled()
        );
    }

    #[test]
    fn worktree_enabled_accessor() {
        assert!(!Config::default().worktree_enabled());
        assert!(
            !Config {
                no_worktree: Some(true),
                ..Config::default()
            }
            .worktree_enabled()
        );
        assert!(
            Config {
                no_worktree: Some(false),
                ..Config::default()
            }
            .worktree_enabled()
        );
    }

    #[test]
    fn network_and_private_home_accessors_are_opt_in_safe() {
        assert!(!Config::default().network_enabled());
        assert!(
            !Config {
                network: Some(false),
                ..Config::default()
            }
            .network_enabled()
        );
        assert!(
            Config {
                network: Some(true),
                ..Config::default()
            }
            .network_enabled()
        );
        assert!(Config::default().private_home_enabled());
        assert!(
            !Config {
                private_home: Some(false),
                ..Config::default()
            }
            .private_home_enabled()
        );
    }

    #[test]
    fn toolchains_enabled_by_default_and_project_cannot_enable() {
        // Default on; a config without the key parses and stays enabled.
        let cfg = parse_toml("command = [\"claude\"]\n").unwrap();
        assert_eq!(cfg.no_toolchains, None);
        assert!(cfg.toolchains_enabled());

        // Globally disabled, a project .ai-jail cannot re-enable it (monotonic).
        let global = Config {
            no_toolchains: Some(true),
            ..Config::default()
        };
        let project = Config {
            no_toolchains: Some(false),
            ..Config::default()
        };
        let (merged, _) =
            merge_with_global_report(global, project, Path::new("/project"));
        assert!(!merged.toolchains_enabled());

        // A project may still disable a globally enabled toolchain pass.
        let project = Config {
            no_toolchains: Some(true),
            ..Config::default()
        };
        let (merged, _) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/project"),
        );
        assert!(!merged.toolchains_enabled());
    }

    #[test]
    fn mise_enabled_accessor() {
        assert!(
            Config {
                no_mise: None,
                ..Config::default()
            }
            .mise_enabled()
        );
        assert!(
            !Config {
                no_mise: Some(true),
                ..Config::default()
            }
            .mise_enabled()
        );
        assert!(
            Config {
                no_mise: Some(false),
                ..Config::default()
            }
            .mise_enabled()
        );
    }

    #[test]
    fn save_config_enabled_accessor() {
        assert!(
            Config {
                no_save_config: None,
                ..Config::default()
            }
            .save_config_enabled()
        );
        assert!(
            !Config {
                no_save_config: Some(true),
                ..Config::default()
            }
            .save_config_enabled()
        );
        assert!(
            Config {
                no_save_config: Some(false),
                ..Config::default()
            }
            .save_config_enabled()
        );
    }

    #[test]
    fn hide_config_enabled_accessor() {
        // Default: hidden
        assert!(Config::default().hide_config_enabled());
        // Explicit on
        assert!(
            Config {
                no_hide_config: Some(false),
                ..Config::default()
            }
            .hide_config_enabled()
        );
        // Opt-out
        assert!(
            !Config {
                no_hide_config: Some(true),
                ..Config::default()
            }
            .hide_config_enabled()
        );
    }

    #[test]
    fn merge_cli_no_hide_config_overrides_config() {
        let existing = Config {
            no_hide_config: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            hide_config: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_hide_config, Some(true));
        assert!(!merged.hide_config_enabled());
    }

    #[test]
    fn merge_cli_hide_config_overrides_config() {
        let existing = Config {
            no_hide_config: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            hide_config: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_hide_config, Some(false));
        assert!(merged.hide_config_enabled());
    }

    #[test]
    fn landlock_enabled_accessor() {
        assert!(
            Config {
                no_landlock: None,
                ..Config::default()
            }
            .landlock_enabled()
        );
        assert!(
            !Config {
                no_landlock: Some(true),
                ..Config::default()
            }
            .landlock_enabled()
        );
        assert!(
            Config {
                no_landlock: Some(false),
                ..Config::default()
            }
            .landlock_enabled()
        );
    }

    #[test]
    fn lockdown_enabled_accessor() {
        assert!(
            !Config {
                lockdown: None,
                ..Config::default()
            }
            .lockdown_enabled()
        );
        assert!(
            Config {
                lockdown: Some(true),
                ..Config::default()
            }
            .lockdown_enabled()
        );
        assert!(
            !Config {
                lockdown: Some(false),
                ..Config::default()
            }
            .lockdown_enabled()
        );
    }

    #[test]
    fn status_bar_enabled_accessor() {
        // Default ON: None means enabled
        assert!(
            Config {
                no_status_bar: None,
                ..Config::default()
            }
            .status_bar_enabled()
        );
        // Explicitly disabled
        assert!(
            !Config {
                no_status_bar: Some(true),
                ..Config::default()
            }
            .status_bar_enabled()
        );
        // Explicitly enabled
        assert!(
            Config {
                no_status_bar: Some(false),
                ..Config::default()
            }
            .status_bar_enabled()
        );
    }

    #[test]
    fn merge_status_bar_flag_overrides() {
        let existing = Config {
            no_status_bar: None,
            ..Config::default()
        };

        // --status-bar only changes style
        let cli = CliArgs {
            status_bar_style: Some("light".into()),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_status_bar, None);
        assert!(merged.status_bar_enabled());
        assert_eq!(merged.status_bar_style.as_deref(), Some("light"));

        // --no-status-bar sets no_status_bar to true (disabled)
        let cli = CliArgs {
            status_bar: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_status_bar, Some(true));
        assert!(!merged.status_bar_enabled());
    }

    // ── File I/O tests (using temp dirs) ───────────────────────

    #[test]
    fn missing_config_file_uses_defaults() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-missing-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let config = load_from_path(&dir.join(".ai-jail")).unwrap();

        assert!(config.command.is_empty());
        assert!(config.rw_maps.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_config_file_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-malformed-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        std::fs::write(&path, "command = [\"bash\"\n").unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to parse {}", path.display())));
        assert!(error.contains("TOML parse error"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_config_path_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-unreadable-config-{}", std::process::id()));
        let path = dir.join(".ai-jail");
        std::fs::create_dir_all(&path).unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to read {}", path.display())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_utf8_config_file_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-non-utf8-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        std::fs::write(&path, [0xff]).unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to read {}", path.display())));
        assert_eq!(std::fs::read(&path).unwrap(), [0xff]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_preference_save_preserves_malformed_file() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-malformed-global-config-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        let original = "no_gpu = tru\n";
        std::fs::write(&path, original).unwrap();
        let config = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };

        let error = save_global_to_path(&path, &config).unwrap_err();

        assert!(error.contains(&format!("Failed to parse {}", path.display())));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_global_status_bar_theme_persists() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-home-global-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");

        let cfg = Config {
            no_status_bar: None,
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_from_path(&path).unwrap();
        assert_eq!(global.no_status_bar, None);
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_config_may_be_a_trusted_symlink() {
        // Issue #102: dotfile managers such as GNU stow install
        // ~/.ai-jail as a symlink, which used to be a fatal error.
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir()
            .join(format!("ai-jail-symlink-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("dotfiles-ai-jail");
        std::fs::write(&target, "lockdown = true\n").unwrap();
        let link = dir.join(".ai-jail");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let loaded = load_global_from_path(&link).unwrap();
        assert_eq!(loaded.base.lockdown, Some(true));

        // A group-writable target is not trustworthy: anyone in that group
        // could grant themselves capabilities through it.
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let err = load_global_from_path(&link).unwrap_err();
        assert!(err.contains("group- or world-writable"), "{err}");
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        // The project config is untrusted input and stays strict.
        let project_link = dir.join("project-link");
        std::os::unix::fs::symlink(&target, &project_link).unwrap();
        let err = load_from_path(&project_link).unwrap_err();
        assert!(err.contains("path is a symlink"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_config_symlink_into_the_project_is_refused() {
        // The project directory is mounted read-write, so a target inside
        // it could be rewritten by the agent the policy constrains. Tests
        // run with the crate root as the working directory, so a file
        // created here is inside the "project" for this check.
        let target = std::env::current_dir()
            .unwrap()
            .join(format!(".ai-jail-symlink-probe-{}", std::process::id()));
        std::fs::write(&target, "lockdown = true\n").unwrap();
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-symlink-proj-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join(".ai-jail");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = load_global_from_path(&link).unwrap_err();
        assert!(
            err.contains("inside the project directory"),
            "expected project-containment refusal, got: {err}"
        );

        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_trust_project_config_files_still_parse() {
        // Backward compatibility: configs written before
        // trust_project_config existed must keep loading, with the field
        // defaulting to empty (nothing trusted).
        let old = r#"
command = ["claude"]
rw_maps = ["/tmp/a"]
network = true
"#;
        let cfg = parse_toml(old).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert!(cfg.trust_project_config.is_empty());

        // And a global config of the same vintage.
        let global = parse_global_toml(old).unwrap();
        assert!(global.base.trust_project_config.is_empty());
    }

    #[test]
    fn trusted_project_dirs_match_by_containment_only() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-trust-dirs-{}", std::process::id()));
        let allowed = root.join("work/repos");
        let inside = allowed.join("team-app");
        let outside = root.join("elsewhere/other-app");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let trusted = vec![allowed.clone()];
        assert!(project_config_is_trusted(&trusted, &inside));
        assert!(project_config_is_trusted(&trusted, &allowed));
        assert!(!project_config_is_trusted(&trusted, &outside));
        // An empty list is the default: nothing is trusted.
        assert!(!project_config_is_trusted(&[], &inside));
        // `..` cannot walk out of a listed directory, because both sides
        // are resolved before comparison.
        let escape = inside.join("../../../elsewhere/other-app");
        assert!(!project_config_is_trusted(&trusted, &escape));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn trusted_project_expands_tilde_in_its_own_paths() {
        // Issue #126: a trusted project layer is merged after `merge` has
        // already expanded global and CLI paths, so it needs its own pass.
        // Without one the entries stay relative and `absolutize_user_paths`
        // prepends the project directory — `~/.npmrc` became
        // `<project>/~/.npmrc`, a path that cannot exist.
        let _lock = ENV_LOCK.lock().unwrap();
        let home = "/home/tildeuser";
        let _home = EnvVarGuard::set("HOME", home);

        let global = Config {
            trust_project_config: vec![PathBuf::from("/srv/test")],
            ..Config::default()
        };
        let project = Config {
            ro_maps: vec![PathBuf::from("~/.npmrc")],
            rw_maps: vec![PathBuf::from("~/.cache/build")],
            mask: vec![PathBuf::from("~/secret")],
            claude_dir: Some(PathBuf::from("~/.claude-jail")),
            ..Config::default()
        };

        let mut merged = merge_trusted_project(global, project);
        // Absolutizing is what used to corrupt the path, so run it too:
        // the bug only became visible on the far side of this call.
        absolutize_user_paths(&mut merged, Path::new("/srv/test"));

        assert_eq!(
            merged.ro_maps,
            vec![PathBuf::from("/home/tildeuser/.npmrc")]
        );
        assert_eq!(
            merged.rw_maps,
            vec![PathBuf::from("/home/tildeuser/.cache/build")]
        );
        // Fields beyond the maps go through the same helper, so they are
        // covered here rather than left to drift.
        assert_eq!(merged.mask, vec![PathBuf::from("/home/tildeuser/secret")]);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/tildeuser/.claude-jail"))
        );
        for path in merged.ro_maps.iter().chain(merged.rw_maps.iter()) {
            assert!(
                !path.to_string_lossy().contains('~'),
                "an unexpanded tilde survived into {}",
                path.display()
            );
        }
    }

    #[test]
    fn trusted_project_config_may_enable_capabilities() {
        // Issue #104: teams that ship per-repo policy need project config
        // to grant, not only tighten — but only where the trusted global
        // config says so.
        let global = Config {
            trust_project_config: vec![PathBuf::from("/anything")],
            ..Config::default()
        };
        let project = Config {
            network: Some(true),
            ..Config::default()
        };

        // Untrusted path: enabling a capability is refused and reported.
        let (untrusted, warnings) = merge_with_global_report(
            global.clone(),
            project.clone(),
            Path::new("/tmp"),
        );
        assert!(!untrusted.network_enabled());
        assert!(
            warnings.iter().any(|w| w.text.contains("network")),
            "{warnings:?}"
        );

        // Trusted path: the same file is honored.
        let trusted = merge_trusted_project(global, project);
        assert!(trusted.network_enabled());
    }

    #[test]
    fn a_project_cannot_declare_itself_trusted() {
        // The claim must come from the global config, never from the file
        // being judged.
        let project = Config {
            trust_project_config: vec![PathBuf::from("/")],
            network: Some(true),
            ..Config::default()
        };
        let (merged, warnings) = merge_with_global_report(
            Config::default(),
            project,
            Path::new("/tmp"),
        );
        assert!(merged.trust_project_config.is_empty());
        assert!(!merged.network_enabled());
        assert!(
            warnings
                .iter()
                .any(|w| w.text.contains("trust_project_config")),
            "{warnings:?}"
        );
    }

    #[test]
    fn init_saves_only_the_project_layer_not_the_global_baseline() {
        // Issue #110: --init wrote the fully merged config, so a global
        // ~/.ai-jail full of personal settings was copied into the
        // repository's .ai-jail — where it is also inert, since a project
        // file cannot enable capabilities.
        let global_ish = Config {
            claude_dir: Some(PathBuf::from("/home/someone/.claude")),
            rw_maps: vec![PathBuf::from("/home/someone/dir")],
            network: Some(true),
            tailscale: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            network: Some(false),
            ..CliArgs::default()
        };

        let saved =
            project_config_for_init(&cli, Config::default(), Path::new("/tmp"));

        // Only what this invocation asked for.
        assert_eq!(saved.network, Some(false));
        assert!(saved.claude_dir.is_none(), "global claude_dir leaked");
        assert!(saved.rw_maps.is_empty(), "global rw_maps leaked");
        assert!(saved.tailscale.is_none(), "global tailscale leaked");
        // Sanity: those really were set on the global-shaped config.
        assert!(global_ish.claude_dir.is_some());
    }

    #[test]
    fn auto_save_skips_a_config_with_no_settings() {
        // Issue #103: a plain first run in a clean directory used to leave
        // behind a .ai-jail containing nothing but the header comment.
        assert!(config_body_is_empty(&Config::default()));
        assert!(!config_body_is_empty(&Config {
            lockdown: Some(true),
            ..Config::default()
        }));
        // A recorded command is a real setting, so ordinary runs that name
        // one still save.
        assert!(!config_body_is_empty(&Config {
            command: vec!["claude".into()],
            ..Config::default()
        }));
    }

    #[test]
    fn save_global_theme_does_not_reenable_disabled_status_bar() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-home-global-preserve-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);

        let path = dir.join(".ai-jail");
        let existing = Config {
            no_status_bar: Some(true),
            status_bar_style: Some("light".into()),
            ..Config::default()
        };
        save_to_path(&path, &existing);

        let cfg = Config {
            no_status_bar: None,
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_from_path(&path).unwrap();
        assert_eq!(global.no_status_bar, Some(true));
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_global_preserves_command_scoped_tables() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-home-global-commands-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");
        std::fs::write(
            &path,
            r#"rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi", "~/.pi-lens"]
tailscale = true

[commands.claude]
rw_maps = ["~/.claude"]
"#,
        )
        .unwrap();

        let cfg = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_global_from_path(&path).unwrap();
        assert_eq!(global.base.status_bar_style.as_deref(), Some("dark"));
        assert_eq!(global.base.rw_maps, vec![PathBuf::from("~/common")]);
        assert_eq!(global.commands.len(), 2);
        assert_eq!(
            global.commands["pi"].rw_maps,
            vec![PathBuf::from("~/.pi"), PathBuf::from("~/.pi-lens")]
        );
        assert_eq!(global.commands["pi"].tailscale, Some(true));
        assert_eq!(
            global.commands["claude"].rw_maps,
            vec![PathBuf::from("~/.claude")]
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regression_old_plain_global_roundtrips_through_save() {
        // A global .ai-jail written before [commands.*] tables existed
        // (plain Config fields only) must survive a save cycle: the
        // serde(flatten) load/save path must not drop or reshape any
        // base field, and must not invent a [commands] table.
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-old-plain-global-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");
        std::fs::write(
            &path,
            r#"command = ["claude"]
rw_maps = ["~/shared"]
no_gpu = true
hide_dotdirs = [".my_secrets"]
"#,
        )
        .unwrap();

        let cfg = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_global_from_path(&path).unwrap();
        assert_eq!(global.base.command, vec!["claude"]);
        assert_eq!(global.base.rw_maps, vec![PathBuf::from("~/shared")]);
        assert_eq!(global.base.no_gpu, Some(true));
        assert_eq!(global.base.hide_dotdirs, vec![".my_secrets"]);
        assert_eq!(global.base.status_bar_style.as_deref(), Some("dark"));
        assert!(global.commands.is_empty());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("[commands"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_with_global_keeps_status_bar_preferences_from_global() {
        let global = Config {
            no_status_bar: Some(false),
            status_bar_style: Some("light".into()),
            resize_redraw_key: Some("ctrl-l".into()),
            ..Config::default()
        };
        let local = Config {
            no_status_bar: Some(true),
            status_bar_style: Some("dark".into()),
            resize_redraw_key: Some("disabled".into()),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_status_bar, Some(false));
        assert_eq!(merged.status_bar_style.as_deref(), Some("light"));
        assert_eq!(merged.resize_redraw_key.as_deref(), Some("ctrl-l"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let _cwd = cwd_guard();
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original_dir = std::env::current_dir().unwrap();

        // Change to temp dir so save/load use the right path
        std::env::set_current_dir(&dir).unwrap();

        let config = Config {
            runtime_harnesses: Vec::new(),
            command: vec!["codex".into()],
            rw_maps: vec![PathBuf::from("/tmp/shared")],
            ro_maps: vec![],
            overlay_maps: vec![],
            hide_dotdirs: vec![],
            mask: vec![],
            deny_paths: vec![PathBuf::from("secrets.json")],
            mask_exceptions: vec![],
            deny_path_exceptions: vec![],
            no_gpu: Some(true),
            no_docker: None,
            tailscale: Some(true),
            no_display: None,
            audio: None,
            github: None,
            aws: None,
            kube: None,
            gcloud: None,
            docker_config: None,
            kvm: None,
            prompt_hosts: None,
            network: None,
            macos_host_ipc: None,
            macos_chromium: None,
            macos_trustd: None,
            macos_pasteboard: None,
            allow_pty: None,
            allow_loopback_listen: None,
            allow_loopback_connect: None,
            x11: None,
            host_shm: None,
            terminal_passthrough: None,
            terminal_appearance: None,
            no_worktree: None,
            no_mise: None,
            no_toolchains: None,
            no_save_config: Some(true),
            no_hide_config: None,
            ssh: None,
            pictures: Some(true),
            browser_profile: Some("hard".into()),
            private_home: Some(true),
            lockdown: Some(false),
            no_landlock: None,
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            rlimit: BTreeMap::new(),
            rlimit_source: BTreeMap::new(),
            cpus_source: None,
            cpus: None,
            systemd_user: Some(true),
            allow_tcp_ports: vec![32000],
            allow_hosts: vec![],
            allow_private_hosts: vec![],
            forward_ports: vec![],
            publish_ports: vec![],
            claude_dir: None,
            agent_state: None,
            inherit_env: None,
            env_pass: vec![],
            env_from_file: vec![],
            secret_hosts: Default::default(),
            trust_project_config: vec![],
            update_check: None,
            audit_log: None,
        };
        save(&config);

        let loaded = load().unwrap();
        assert_eq!(loaded.command, vec!["codex"]);
        assert_eq!(loaded.rw_maps, vec![PathBuf::from("/tmp/shared")]);
        assert_eq!(loaded.no_gpu, Some(true));
        assert_eq!(loaded.lockdown, Some(false));
        assert_eq!(loaded.allow_tcp_ports, vec![32000]);
        assert_eq!(loaded.systemd_user, Some(true));
        assert_eq!(loaded.deny_paths, vec![PathBuf::from("secrets.json")]);
        assert_eq!(loaded.resize_redraw_key, None);
        assert_eq!(loaded.browser_profile.as_deref(), Some("hard"));
        assert_eq!(loaded.claude_dir, None);

        // Cleanup
        std::env::set_current_dir(&original_dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_rejects_symlink_target() {
        let _cwd = cwd_guard();
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-test-{}-symlink", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original_dir = std::env::current_dir().unwrap();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "KEEP").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".ai-jail")).unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let config = Config {
            command: vec!["bash".into()],
            ..Default::default()
        };
        save(&config);

        let victim_after = std::fs::read_to_string(&victim).unwrap();
        assert_eq!(victim_after, "KEEP");

        std::env::set_current_dir(&original_dir).unwrap();
        let _ = std::fs::remove_file(dir.join(".ai-jail"));
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Tilde expansion tests ─────────────────────────────────

    #[test]
    fn expand_tilde_with_slash() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/example");
        let out = expand_tilde(PathBuf::from("~/projects/x"));
        assert_eq!(out, PathBuf::from("/home/example/projects/x"));
    }

    #[test]
    fn expand_tilde_bare() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/bare");
        assert_eq!(
            expand_tilde(PathBuf::from("~")),
            PathBuf::from("/home/bare")
        );
    }

    #[test]
    fn expand_tilde_leaves_other_user_home_alone() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/me");
        // ~otheruser should not be rewritten
        let p = PathBuf::from("~otheruser/file");
        assert_eq!(expand_tilde(p.clone()), p);
    }

    #[test]
    fn expand_tilde_passes_through_absolute_paths() {
        let _env = ENV_LOCK.lock().unwrap();
        let p = PathBuf::from("/tmp/abs");
        assert_eq!(expand_tilde(p.clone()), p);
    }

    #[test]
    fn merge_expands_tilde_in_ro_and_rw_maps_and_mask() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");

        let existing = Config {
            ro_maps: vec![
                PathBuf::from("~/.bashrc"),
                PathBuf::from("/absolute/path"),
            ],
            rw_maps: vec![PathBuf::from("~/work")],
            mask: vec![PathBuf::from("~/secret.env")],
            ..Config::default()
        };
        let merged = merge(&CliArgs::default(), existing);

        assert_eq!(
            merged.ro_maps,
            vec![
                PathBuf::from("/home/user/.bashrc"),
                PathBuf::from("/absolute/path"),
            ]
        );
        assert_eq!(merged.rw_maps, vec![PathBuf::from("/home/user/work")]);
        assert_eq!(merged.mask, vec![PathBuf::from("/home/user/secret.env")]);
    }

    #[test]
    fn merge_expands_tilde_on_both_map_sides() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let existing = Config {
            ro_maps: vec![PathBuf::from("~/.ssh/ai-jail:~/.ssh")],
            ..Config::default()
        };

        let merged = merge(&CliArgs::default(), existing);

        assert_eq!(
            merged.ro_maps,
            vec![PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh")]
        );
    }

    // ── Relative-path resolution tests (issue #54) ────────────

    #[test]
    fn normalize_path_collapses_parent_and_current() {
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(normalize_path(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(
            normalize_path(Path::new("/a/b/c/..")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn normalize_path_drops_dotdot_above_root() {
        // /.. is /, /../foo is /foo. Matches `cd /..` shell behaviour.
        assert_eq!(normalize_path(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(normalize_path(Path::new("/../foo")), PathBuf::from("/foo"));
        assert_eq!(
            normalize_path(Path::new("/a/../../b")),
            PathBuf::from("/b")
        );
    }

    #[test]
    fn normalize_path_preserves_leading_dotdot_when_relative() {
        // Relative input with no base to resolve against: keep `..`.
        // (In practice we always call this on absolute paths via
        // to_absolute, but the helper itself should be sane.)
        assert_eq!(
            normalize_path(Path::new("../foo")),
            PathBuf::from("../foo")
        );
    }

    #[test]
    fn normalize_path_empty_becomes_dot() {
        assert_eq!(normalize_path(Path::new("./.")), PathBuf::from("."));
    }

    #[test]
    fn to_absolute_resolves_parent_relative_against_base() {
        // Core repro for #54: `--map ../sister-project` from
        // /home/user/Projects/myproject must yield the absolute
        // sibling, not be passed through to bwrap as `../sister-project`.
        let cwd = Path::new("/home/user/Projects/myproject");
        assert_eq!(
            to_absolute(PathBuf::from("../sister-project"), cwd),
            PathBuf::from("/home/user/Projects/sister-project")
        );
    }

    #[test]
    fn to_absolute_leaves_absolute_paths_alone_modulo_normalization() {
        let cwd = Path::new("/home/user");
        assert_eq!(
            to_absolute(PathBuf::from("/opt/data"), cwd),
            PathBuf::from("/opt/data")
        );
        // Absolute path with `..` still gets normalized.
        assert_eq!(
            to_absolute(PathBuf::from("/opt/foo/../data"), cwd),
            PathBuf::from("/opt/data")
        );
    }

    #[test]
    fn to_absolute_resolves_bare_relative() {
        let cwd = Path::new("/home/user/project");
        assert_eq!(
            to_absolute(PathBuf::from("subdir"), cwd),
            PathBuf::from("/home/user/project/subdir")
        );
        assert_eq!(
            to_absolute(PathBuf::from("./subdir"), cwd),
            PathBuf::from("/home/user/project/subdir")
        );
    }

    #[test]
    fn absolutize_user_paths_handles_rw_and_ro_maps() {
        let mut config = Config {
            rw_maps: vec![
                PathBuf::from("../sister"),
                PathBuf::from("/opt/abs"),
            ],
            ro_maps: vec![PathBuf::from("./sub")],
            // mask is intentionally NOT touched by absolutize; its
            // existing "relative-to-project-dir at mount time" semantic
            // (see build_mask_mounts) is left alone.
            mask: vec![PathBuf::from("secret.env")],
            ..Config::default()
        };
        absolutize_user_paths(
            &mut config,
            Path::new("/home/user/Projects/myproject"),
        );
        assert_eq!(
            config.rw_maps,
            vec![
                PathBuf::from("/home/user/Projects/sister"),
                PathBuf::from("/opt/abs"),
            ]
        );
        assert_eq!(
            config.ro_maps,
            vec![PathBuf::from("/home/user/Projects/myproject/sub")]
        );
        assert_eq!(config.mask, vec![PathBuf::from("secret.env")]);
    }

    #[test]
    fn absolutize_user_paths_is_idempotent() {
        // The landlock-exec re-entry calls absolutize again; absolute
        // paths must not be mangled.
        let mut config = Config {
            rw_maps: vec![PathBuf::from("/home/user/work")],
            ro_maps: vec![PathBuf::from("/opt/data")],
            ..Config::default()
        };
        absolutize_user_paths(&mut config, Path::new("/somewhere/else"));
        absolutize_user_paths(&mut config, Path::new("/elsewhere"));
        assert_eq!(config.rw_maps, vec![PathBuf::from("/home/user/work")]);
        assert_eq!(config.ro_maps, vec![PathBuf::from("/opt/data")]);
    }

    #[test]
    fn absolutize_user_paths_resolves_both_map_sides() {
        let mut config = Config {
            rw_maps: vec![PathBuf::from("../shared:vendor/shared")],
            ..Config::default()
        };

        absolutize_user_paths(&mut config, Path::new("/work/project"));

        assert_eq!(
            config.rw_maps,
            vec![PathBuf::from("/work/shared:/work/project/vendor/shared")]
        );
    }

    #[test]
    fn alternate_map_absolutization_is_idempotent() {
        let mut config = Config {
            rw_maps: vec![PathBuf::from("/host/data:/jail/data")],
            ..Config::default()
        };

        absolutize_user_paths(&mut config, Path::new("/first"));
        absolutize_user_paths(&mut config, Path::new("/second"));

        assert_eq!(
            config.rw_maps,
            vec![PathBuf::from("/host/data:/jail/data")]
        );
    }

    // ── Tilde collapse tests (issue #52) ──────────────────────

    #[test]
    fn collapse_tilde_rewrites_home_prefix() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        assert_eq!(
            collapse_tilde(Path::new("/home/user/.claude")),
            PathBuf::from("~/.claude")
        );
    }

    #[test]
    fn collapse_tilde_rewrites_bare_home() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        assert_eq!(collapse_tilde(Path::new("/home/user")), PathBuf::from("~"));
    }

    #[test]
    fn collapse_tilde_leaves_unrelated_paths_alone() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let p = Path::new("/opt/data");
        assert_eq!(collapse_tilde(p), PathBuf::from("/opt/data"));
    }

    #[test]
    fn collapse_tilde_does_not_match_sibling_directories() {
        // /home/user2/foo must NOT collapse just because $HOME is /home/user.
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let p = Path::new("/home/user2/foo");
        assert_eq!(collapse_tilde(p), PathBuf::from("/home/user2/foo"));
    }

    #[test]
    fn collapse_tilde_returns_input_when_home_unset() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::remove("HOME");
        let p = Path::new("/home/user/.claude");
        assert_eq!(collapse_tilde(p), PathBuf::from("/home/user/.claude"));
    }

    #[test]
    fn save_round_trip_preserves_tilde_notation() {
        // Round-trip: write a config with `~/.claude` paths, run
        // through save_to_path, parse the resulting TOML back, and
        // confirm the on-disk file kept the `~/` form.
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");

        let tmp_dir = std::env::temp_dir().join(format!(
            "ai-jail-collapse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let path = tmp_dir.join(".ai-jail");

        let cfg = Config {
            command: vec!["claude".into()],
            // These are expanded as if they had passed through merge().
            rw_maps: vec![
                PathBuf::from("/home/user/.claude"),
                PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh"),
            ],
            ro_maps: vec![PathBuf::from("/home/user/.bashrc")],
            mask: vec![PathBuf::from("/home/user/secret.env")],
            claude_dir: Some(PathBuf::from("/home/user/.claude-work")),
            ..Config::default()
        };
        save_to_path(&path, &cfg);

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("\"~/.claude\""),
            "expected ~/.claude in TOML, got:\n{written}"
        );
        assert!(
            written.contains("\"~/.ssh/ai-jail:~/.ssh\""),
            "alternate map not collapsed: {written}"
        );
        assert!(written.contains("\"~/.bashrc\""), "rw_maps not collapsed");
        assert!(written.contains("\"~/secret.env\""), "mask not collapsed");
        assert!(
            written.contains("\"~/.claude-work\""),
            "claude_dir not collapsed"
        );
        // And the round-trip: parse it back and re-expand via merge
        // should yield the same absolute paths we started with.
        let parsed = parse_toml(&written).unwrap();
        let merged = merge(&CliArgs::default(), parsed);
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/home/user/.claude"),
                PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh"),
            ]
        );
        assert_eq!(merged.ro_maps, vec![PathBuf::from("/home/user/.bashrc")]);
        assert_eq!(merged.mask, vec![PathBuf::from("/home/user/secret.env")]);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-work"))
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ── claude_dir tests ──────────────────────────────────────

    #[test]
    fn regression_v0_9_0_config_without_claude_dir() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.claude_dir, None);
    }

    #[test]
    fn parse_claude_dir_from_toml() {
        let toml = r#"
command = ["claude"]
claude_dir = "/home/user/.claude-example"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_claude_dir_from_cli() {
        let existing = Config::default();
        let cli = CliArgs {
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_claude_dir_expands_tilde() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/testuser");

        let existing = Config::default();
        let cli = CliArgs {
            claude_dir: Some(PathBuf::from("~/.claude-example")),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/testuser/.claude-example"))
        );
    }

    #[test]
    fn merge_cli_no_claude_dir_preserves_config_claude_dir() {
        let existing = Config {
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_expands_tilde_from_config_file() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/testuser");

        let existing = Config {
            claude_dir: Some(PathBuf::from("~/.claude-example")),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/testuser/.claude-example"))
        );
    }

    #[test]
    fn roundtrip_claude_dir() {
        let config = Config {
            command: vec!["claude".into()],
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..Config::default()
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized = parse_toml(&serialized).unwrap();
        assert_eq!(deserialized.claude_dir, config.claude_dir);
    }

    #[test]
    fn roundtrip_claude_dir_none_not_written() {
        let config = Config {
            command: vec!["claude".into()],
            claude_dir: None,
            ..Config::default()
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        assert!(!serialized.contains("claude_dir"));
    }
}

// `--rlimit` flag, `rlimit` config field and the project tighten-only
// rule.
//
// - `Config.rlimit: BTreeMap<String, String>`, skipped when empty; a TOML
//   integer is accepted and stored as its decimal string;
// - `merge()` puts CLI `--rlimit NAME=VALUE` entries over the trusted map;
// - `merge_with_global_report` keeps min(project, trusted) per name and
//   warns `... rlimit.<name> ignored ...` for a project value that raises
//   or removes a limit; a name the trusted side leaves at its default is
//   compared with that default.
// The report of `merge_with_global_report` is read through `Debug`, so
// these tests hold for `Vec<String>` and for `feat/profiles`' `Vec<Refusal>`.
#[cfg(test)]
mod rlimit_config_tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;

    fn cli(args: &[&str]) -> Result<CliArgs, String> {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
    }

    fn rl(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn with_rlimit(pairs: &[(&str, &str)]) -> Config {
        Config {
            rlimit: rl(pairs),
            ..Config::default()
        }
    }

    /// Warnings as text. `format!("{w:?}")` works whether the report is
    /// today's `Vec<String>` or the `Vec<Refusal>` of `feat/profiles`
    /// (whose `text` field carries the same warning), so this file
    /// survives the merge into `integration` unchanged.
    fn project_merge(
        trusted: Config,
        project: Config,
    ) -> (Config, Vec<String>) {
        let (merged, report) =
            merge_with_global_report(trusted, project, Path::new("/tmp"));
        (merged, report.iter().map(|w| format!("{w:?}")).collect())
    }

    #[test]
    fn rlimit_table_accepts_quoted_and_unquoted_values() {
        let config = parse_toml(
            "[rlimit]\nnofile = 4096\ndata = \"8G\"\ncpu = \"unlimited\"\n",
        )
        .unwrap();
        assert_eq!(
            config.rlimit,
            rl(&[("cpu", "unlimited"), ("data", "8G"), ("nofile", "4096")])
        );
    }

    #[test]
    fn regression_v3_3_0_config_without_rlimit() {
        let config =
            parse_toml("no_rlimits = true\ncommand = [\"bash\"]\n").unwrap();
        assert!(config.rlimit.is_empty());
        assert_eq!(config.no_rlimits, Some(true));
        let body = toml::to_string(&Config::default()).unwrap();
        assert!(
            !body.contains("rlimit"),
            "empty map must not be written: {body}"
        );
    }

    #[test]
    fn cli_rlimit_overrides_the_trusted_map_per_name() {
        let args =
            cli(&["--rlimit", "nofile=64", "--rlimit", "cpu=30", "bash"])
                .unwrap();
        let trusted = with_rlimit(&[("nofile", "2048"), ("core", "0")]);
        let merged = merge(&args, trusted);
        assert_eq!(
            merged.rlimit,
            rl(&[("core", "0"), ("cpu", "30"), ("nofile", "64")])
        );
    }

    #[test]
    fn cli_rlimit_after_the_command_is_refused() {
        assert!(cli(&["bash", "--rlimit", "nofile=64"]).is_err());
        assert!(cli(&["bash", "--", "--rlimit", "nofile=64"]).is_ok());
    }

    #[test]
    fn project_rlimit_that_removes_a_limit_is_ignored_with_a_warning() {
        // Hostile halves first: a project value that would loosen.
        let (merged, warnings) = project_merge(
            with_rlimit(&[("nofile", "1024")]),
            with_rlimit(&[("nofile", "unlimited")]),
        );
        assert_eq!(
            merged.rlimit.get("nofile").map(String::as_str),
            Some("1024")
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("rlimit.nofile") && w.contains("ignored")),
            "{warnings:?}"
        );
    }

    #[test]
    fn project_rlimit_that_raises_a_trusted_value_is_ignored() {
        let (merged, warnings) = project_merge(
            with_rlimit(&[("nofile", "1024")]),
            with_rlimit(&[("nofile", "2048")]),
        );
        assert_eq!(
            merged.rlimit.get("nofile").map(String::as_str),
            Some("1024")
        );
        assert!(
            warnings.iter().any(|w| w.contains("rlimit.nofile")),
            "{warnings:?}"
        );
    }

    #[test]
    fn project_rlimit_above_an_untouched_default_is_ignored() {
        // The trusted side leaves core at its default (0): raising it, or
        // removing nofile's default, is a weakening too.
        let (merged, warnings) = project_merge(
            Config::default(),
            with_rlimit(&[("core", "100"), ("nofile", "unlimited")]),
        );
        assert!(!merged.rlimit.contains_key("core"), "{:?}", merged.rlimit);
        assert!(!merged.rlimit.contains_key("nofile"), "{:?}", merged.rlimit);
        assert!(
            warnings.iter().any(|w| w.contains("rlimit.core")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("rlimit.nofile")),
            "{warnings:?}"
        );
    }

    #[test]
    fn project_rlimit_that_tightens_is_kept_without_warning() {
        let (merged, warnings) = project_merge(
            with_rlimit(&[("nofile", "1024"), ("data", "8G")]),
            with_rlimit(&[("nofile", "512"), ("data", "4G"), ("nproc", "100")]),
        );
        assert_eq!(
            merged.rlimit.get("nofile").map(String::as_str),
            Some("512")
        );
        assert_eq!(merged.rlimit.get("data").map(String::as_str), Some("4G"));
        // nproc was at its default (4096) on the trusted side: 100 tightens.
        assert_eq!(merged.rlimit.get("nproc").map(String::as_str), Some("100"));
        assert!(
            !warnings.iter().any(|w| w.contains("rlimit.")),
            "a tightening must not warn: {warnings:?}"
        );
    }

    #[test]
    fn project_rlimit_compares_values_not_spellings() {
        // "4G" is smaller than a trusted 8589934592 (8 GiB) even though the
        // strings compare the other way round; "1G" equals 1073741824.
        let (merged, warnings) = project_merge(
            with_rlimit(&[("data", "8589934592"), ("fsize", "1073741824")]),
            with_rlimit(&[("data", "4G"), ("fsize", "1G")]),
        );
        assert_eq!(merged.rlimit.get("data").map(String::as_str), Some("4G"));
        assert!(
            !warnings.iter().any(|w| w.contains("rlimit.")),
            "{warnings:?}"
        );
        let fsize = merged.rlimit.get("fsize").map(String::as_str);
        assert!(
            fsize == Some("1G") || fsize == Some("1073741824"),
            "an equal value is neither a raise nor dropped: {fsize:?}"
        );
    }
}

#[cfg(test)]
mod rlimit_auto_save_tests {
    use super::*;

    #[test]
    fn auto_save_writes_no_cli_rlimit_tight_or_loose() {
        let cli = crate::cli::parse_from(lexopt::Parser::from_args(
            [
                "--rlimit",
                "nofile=1024",
                "--rlimit",
                "nproc=unlimited",
                "--rlimit",
                "core=100",
                "--rlimit",
                "data=4G",
                "bash",
            ]
            .iter()
            .map(std::ffi::OsString::from),
        ))
        .unwrap();
        let saved = project_config_for_auto_save(
            &cli,
            Config::default(),
            Path::new("/tmp"),
        );
        // A CLI limit is this launch's choice, whether it tightens
        // (nofile, data) or not (nproc, core): none is saved.
        assert!(saved.rlimit.is_empty(), "{:?}", saved.rlimit);
        assert!(saved.rlimit_source.is_empty());
    }
}

// Limits are never sticky and trusted CPU sets fail closed.
//
// - Auto-save never writes a CLI `--rlimit` or `--cpus` into the project
//   policy; the project policy's own entries are what it keeps.
// - A trusted `cpus` that does not parse is refused when the config
//   loads, as `rlimit` is: the error names the file (the layer) and the
//   field. `tighten_cpus` never lets a project value replace a malformed
//   trusted one.
// - A project `cpus` that overlaps the trusted set is reported as
//   "narrowed to <set>", naming the set the launch runs on.
// The merge report is read through `Debug`, so these tests hold for
// `Vec<String>` and for `feat/profiles`' `Vec<Refusal>`.
#[cfg(test)]
mod config_explicit_rlimit_tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .unwrap()
    }

    fn rl(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn auto_save(cli: &CliArgs, project: Config) -> Config {
        project_config_for_auto_save(cli, project, Path::new("/project"))
    }

    #[test]
    fn auto_save_never_writes_cli_rlimit_or_cpus() {
        let args = cli(&["--rlimit", "nofile=1024", "--cpus", "0", "bash"]);
        let saved = auto_save(&args, Config::default());
        assert!(saved.rlimit.is_empty(), "{:?}", saved.rlimit);
        assert!(saved.rlimit_source.is_empty(), "{:?}", saved.rlimit_source);
        assert_eq!(saved.cpus, None);
    }

    #[test]
    fn auto_save_keeps_only_the_project_policy_own_rlimit_and_cpus() {
        let project = Config {
            rlimit: rl(&[("nofile", "512")]),
            cpus: Some("0-3".into()),
            ..Config::default()
        };
        // Hostile half first: the project policy's own entries survive an
        // auto-save; dropping them would loosen it on the next launch.
        let saved = auto_save(&cli(&["bash"]), project.clone());
        assert_eq!(saved.rlimit, rl(&[("nofile", "512")]));
        assert_eq!(saved.cpus.as_deref(), Some("0-3"));
        // A CLI value for the same name is this launch's, not the
        // project's: the saved policy keeps the project's own.
        let args = cli(&["--rlimit", "nofile=1024", "--cpus", "0-1", "bash"]);
        let saved = auto_save(&args, project);
        assert_eq!(saved.rlimit, rl(&[("nofile", "512")]));
        assert_eq!(saved.cpus.as_deref(), Some("0-3"));
    }

    #[test]
    fn trusted_cpus_that_parses_loads() {
        // Hostile half first: valid lists in the base and in a command
        // table are not refused.
        let global = parse_global_toml(
            "cpus = \"0-3\"\n[commands.claude]\ncpus = \"0,2\"\n",
        )
        .unwrap();
        assert_eq!(global.base.cpus.as_deref(), Some("0-3"));
    }

    #[test]
    fn malformed_trusted_cpus_is_refused_at_load_naming_the_layer() {
        let base = parse_global_toml("cpus = \"0-3x\"\n");
        let err = base.expect_err("a malformed global cpus must not load");
        assert!(err.contains("cpus") && err.contains("0-3x"), "{err}");

        let table = parse_global_toml("[commands.claude]\ncpus = \"8-x\"\n");
        let err =
            table.expect_err("a malformed command-table cpus must not load");
        assert!(err.contains("cpus") && err.contains("8-x"), "{err}");

        let dir = std::env::temp_dir()
            .join(format!("ai-jail-explicit-cpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "cpus = \"0-3x\"\n").unwrap();
        let loaded = load_global_from_path(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        let err = loaded.expect_err("the global file must be refused");
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("cpus"), "{err}");
    }

    #[test]
    fn tighten_cpus_keeps_a_malformed_trusted_value() {
        use crate::sandbox::affinity::{check_launch, tighten_cpus};
        // A valid project list must not replace a trusted list that does
        // not parse: the launch has to fail closed on the trusted text.
        let (kept, _) = tighten_cpus(Some("0-3x".into()), Some("0-63".into()));
        assert_eq!(kept.as_deref(), Some("0-3x"));
        assert!(check_launch(kept.as_deref(), None, None, true).is_err());
        let (kept, _) = tighten_cpus(Some("0-3x".into()), Some("zz".into()));
        assert_eq!(kept.as_deref(), Some("0-3x"));
    }

    #[test]
    fn project_cpus_overlap_is_reported_as_narrowed_to_the_set() {
        let trusted = Config {
            cpus: Some("0-7".into()),
            ..Config::default()
        };
        let project = Config {
            cpus: Some("4-11".into()),
            ..Config::default()
        };
        let (merged, report) =
            merge_with_global_report(trusted, project, Path::new("/tmp"));
        let warnings: Vec<String> =
            report.iter().map(|w| format!("{w:?}")).collect();
        let set = merged.cpus.clone().expect("the intersection is used");
        assert_eq!(set, "4-7");
        let cpus: Vec<&String> =
            warnings.iter().filter(|w| w.contains("cpus")).collect();
        assert_eq!(cpus.len(), 1, "{warnings:?}");
        assert!(
            cpus[0].contains(&format!("narrowed to {set}")),
            "names the set used: {}",
            cpus[0]
        );
        assert!(!cpus[0].contains("ignored"), "{}", cpus[0]);
    }
}

// The project's own limit survives save and migration.
//
// The case pinned here:
// a trusted `nproc = 8192` raised above the built-in default (4096) and a
// project `nproc = 6000` between the two. The launch merge applies 6000;
// saving or migrating the project policy must keep it, or the next launch
// silently runs at 8192.
//
// - Auto-save keeps every well-formed project `rlimit` entry, including a
//   value above the built-in default.
// - The legacy-file migration projection keeps it too.
// - Keeping a value is not applying it: a project value that raises the
//   trusted limit is still stored, and still ignored, with a warning, at
//   launch. The launch merge stays the only tighten-only decision.
// The merge report is read through `Debug`, so these tests hold for
// `Vec<String>` and for `feat/profiles`' `Vec<Refusal>`.
#[cfg(test)]
mod config_project_rlimit_save_tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use crate::sandbox::rlimits::LimitSource;

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .unwrap()
    }

    fn nproc(value: &str) -> Config {
        Config {
            rlimit: BTreeMap::from([("nproc".to_string(), value.to_string())]),
            ..Config::default()
        }
    }

    /// The trusted layer of the failing case: `nproc` raised above the default.
    fn trusted() -> Config {
        nproc("8192")
    }

    /// The launch-time merge of the trusted layer and a project policy.
    fn launch(project: Config) -> (Config, Vec<String>) {
        let (merged, report) =
            merge_with_global_report(trusted(), project, Path::new("/project"));
        let warnings = report.iter().map(|w| format!("{w:?}")).collect();
        (merged, warnings)
    }

    fn auto_save(project: Config) -> Config {
        project_config_for_auto_save(
            &cli(&["bash"]),
            project,
            Path::new("/project"),
        )
    }

    fn assert_project_nproc(merged: &Config, value: &str, step: &str) {
        assert_eq!(
            merged.rlimit.get("nproc").map(String::as_str),
            Some(value),
            "{step}: {:?}",
            merged.rlimit
        );
        assert_eq!(
            merged.rlimit_source.get("nproc"),
            Some(&LimitSource::Project),
            "{step}: {:?}",
            merged.rlimit_source
        );
    }

    #[test]
    fn auto_save_keeps_a_project_nproc_between_default_and_trusted() {
        // The launch applies the project's 6000 under the trusted 8192.
        let (first, _) = launch(nproc("6000"));
        assert_project_nproc(&first, "6000", "first launch");

        // Saving that project policy must keep 6000: dropping it because
        // it is above the built-in 4096 loosens the next launch to 8192.
        let saved = auto_save(nproc("6000"));
        assert_eq!(
            saved.rlimit.get("nproc").map(String::as_str),
            Some("6000"),
            "auto-save erased the project's own nproc: {:?}",
            saved.rlimit
        );

        let (next, _) = launch(saved);
        assert_project_nproc(&next, "6000", "launch from the saved policy");
    }

    #[test]
    fn migration_keeps_a_project_nproc_between_default_and_trusted() {
        // What the legacy-file migration writes as the project constraints.
        let projected = monotonic_project_constraints(
            &nproc("6000"),
            Path::new("/project"),
        );
        assert_eq!(
            projected.rlimit.get("nproc").map(String::as_str),
            Some("6000"),
            "migration dropped the project's own nproc: {:?}",
            projected.rlimit
        );

        let (next, _) = launch(projected);
        assert_project_nproc(&next, "6000", "launch from the migrated policy");
    }

    #[test]
    fn auto_save_still_stores_a_raising_project_nproc() {
        // Saving keeps every well-formed entry: the save does not judge
        // the value, the launch does (next test).
        let saved = auto_save(nproc("9000"));
        assert_eq!(
            saved.rlimit.get("nproc").map(String::as_str),
            Some("9000"),
            "{:?}",
            saved.rlimit
        );
    }

    #[test]
    fn raising_project_nproc_is_still_ignored_at_launch() {
        // Guard: keeping a raising value on disk must never let it apply.
        let (merged, warnings) = launch(nproc("9000"));
        assert_eq!(
            merged.rlimit.get("nproc").map(String::as_str),
            Some("8192"),
            "{:?}",
            merged.rlimit
        );
        assert_ne!(
            merged.rlimit_source.get("nproc"),
            Some(&LimitSource::Project),
            "{:?}",
            merged.rlimit_source
        );
        let named: Vec<&String> = warnings
            .iter()
            .filter(|w| w.contains("rlimit.nproc") && w.contains("ignored"))
            .collect();
        assert_eq!(named.len(), 1, "{warnings:?}");

        // The same holds for a raising value that came through migration.
        let projected = monotonic_project_constraints(
            &nproc("9000"),
            Path::new("/project"),
        );
        let (merged, _) = launch(projected);
        assert_eq!(
            merged.rlimit.get("nproc").map(String::as_str),
            Some("8192"),
            "{:?}",
            merged.rlimit
        );
    }
}

// A config layer holding `cpu = 0` fails to load, naming the file.
//
// The value is refused where every other malformed limit is: at load, so
// the operator learns which file to fix before anything runs. TOML gives
// the value as an integer or as a string; both spellings are the same
// zero. Other limits keep `0` as a valid value.
#[cfg(test)]
mod config_cpu_floor_tests {
    use std::path::PathBuf;

    use super::*;

    struct CpuFloorDir(PathBuf);

    impl CpuFloorDir {
        fn new(tag: &str) -> CpuFloorDir {
            let dir = std::env::temp_dir().join(format!(
                "ai-jail-config-cpu-floor-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            CpuFloorDir(dir)
        }

        fn load_global(&self, body: &str) -> (PathBuf, Result<(), String>) {
            let path = self.0.join("config.toml");
            std::fs::write(&path, body).unwrap();
            let loaded = load_global_from_path(&path).map(|_| ());
            (path, loaded)
        }
    }

    impl Drop for CpuFloorDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn config_cpu_floor_loads_one_second_unlimited_and_other_zeros() {
        // Hostile half first: values next to the floor, and `0` on limits
        // the floor is not about, still load.
        let dir = CpuFloorDir::new("ok");
        for body in [
            "[rlimit]\ncpu = 1\n",
            "[rlimit]\ncpu = \"unlimited\"\n",
            "[rlimit]\ncore = 0\nnofile = 0\nfsize = \"0\"\n",
        ] {
            let (path, loaded) = dir.load_global(body);
            assert!(
                loaded.is_ok(),
                "{} with {body:?}: {loaded:?}",
                path.display()
            );
        }
        assert!(parse_toml("[rlimit]\ncpu = 1\ncore = 0\n").is_ok());
    }

    #[test]
    fn config_cpu_floor_refuses_a_global_zero_naming_the_file() {
        let dir = CpuFloorDir::new("zero");
        // Hostile half: the quoted zero is the same value as the bare one.
        for body in ["[rlimit]\ncpu = 0\n", "[rlimit]\ncpu = \"0\"\n"] {
            let (path, loaded) = dir.load_global(body);
            let err = match loaded {
                Ok(()) => panic!("{body:?} must not load"),
                Err(e) => e,
            };
            assert!(
                err.contains(&path.display().to_string()),
                "must name the layer's file: {err}"
            );
            assert!(err.contains("cpu"), "must name the limit: {err}");
            assert!(
                err.contains("at least 1 second"),
                "must say what the floor is: {err}"
            );
        }
    }

    #[test]
    fn config_cpu_floor_refuses_a_project_zero() {
        let err = match parse_toml("[rlimit]\ncpu = 0\n") {
            Ok(_) => panic!("a project cpu = 0 must not parse"),
            Err(e) => e,
        };
        assert!(err.contains("at least 1 second"), "{err}");
    }
}

// Selecting and validating one profile.
//
// The module name starts with `profile` so `cargo test config::profile`
// selects it.
//
// Contract:
// `fn select_profile(profiles: &BTreeMap<String, toml::Value>, name: &str)
//     -> Result<Config, String>`, checking in order: name grammar
// `^[a-z0-9][a-z0-9_-]{0,63}$`, existence (error lists the defined names),
// `profile_version` present and integer 1, no `trust_project_config`,
// no unknown key (serde aliases, `skip_serializing` fields and empty
// arrays/tables are not unknown), then the parser's type errors prefixed
// with the profile name. Fixtures use only keys a v3.3.0 config can hold.
#[cfg(test)]
mod profile_select_tests {
    use std::collections::BTreeMap;

    use super::*;

    /// Build the profiles map from a TOML document of `[name]` tables.
    fn profiles(doc: &str) -> BTreeMap<String, toml::Value> {
        let root: toml::Table = doc.parse().expect("fixture TOML");
        root.into_iter().collect()
    }

    /// One profile named `name` (inserted verbatim, never re-parsed as
    /// TOML, so hostile names stay intact) with `profile_version = 1` plus
    /// the keys of `body`.
    fn one(name: &str, body: &str) -> BTreeMap<String, toml::Value> {
        let mut table: toml::Table = body.parse().expect("fixture TOML");
        table.insert("profile_version".into(), toml::Value::Integer(1));
        BTreeMap::from([(name.to_string(), toml::Value::Table(table))])
    }

    fn refused(map: &BTreeMap<String, toml::Value>, name: &str) -> String {
        match select_profile(map, name) {
            Ok(c) => panic!("profile {name:?} must be refused, got {c:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn profile_names_off_the_grammar_are_refused_naming_the_rule() {
        // Near misses of a valid name. Each is put in
        // the map, so only the grammar can refuse it.
        let long = "a".repeat(65);
        for bad in [
            "Agent",
            "-agent",
            "_agent",
            "agent.test",
            "agent test",
            "../x",
            "agent/x",
            "agent-test\n",
            long.as_str(),
        ] {
            let map = one(bad, "no_gpu = true\n");
            let err = refused(&map, bad);
            assert!(
                err.contains("a-z0-9"),
                "{bad:?}: must name the rule: {err}"
            );
        }
        assert!(refused(&BTreeMap::new(), "").contains("a-z0-9"));
    }

    #[test]
    fn profile_names_on_the_grammar_are_accepted() {
        let max = "a".repeat(64);
        for good in [
            "a",
            "0",
            "agent-test",
            "agent_test",
            "a1-b2_c3",
            max.as_str(),
        ] {
            let map = one(good, "no_gpu = true\n");
            assert!(select_profile(&map, good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn profile_names_are_not_normalised_into_each_other() {
        // `agent-test` and `agent_test` are two profiles, never one.
        let map = profiles(
            "[agent-test]\nprofile_version = 1\nallow_hosts = [\"a.example\"]\n\
             [agent_test]\nprofile_version = 1\n\
             allow_hosts = [\"b.example\"]\n",
        );
        assert_eq!(
            select_profile(&map, "agent-test").unwrap().allow_hosts,
            ["a.example"]
        );
        assert_eq!(
            select_profile(&map, "agent_test").unwrap().allow_hosts,
            ["b.example"]
        );
        assert!(select_profile(&map, "agenttest").is_err());
    }

    #[test]
    fn profile_missing_lists_the_defined_names() {
        let map = profiles(
            "[alpha]\nprofile_version = 1\n[beta]\nprofile_version = 1\n",
        );
        let err = refused(&map, "gamma");
        for needle in ["gamma", "alpha", "beta"] {
            assert!(err.contains(needle), "missing {needle}: {err}");
        }
    }

    #[test]
    fn profile_version_must_be_the_integer_one() {
        for body in [
            "no_gpu = true\n",
            "profile_version = 2\n",
            "profile_version = 0\n",
            "profile_version = \"1\"\n",
            "profile_version = 1.0\n",
        ] {
            let map = profiles(&format!("[agent-test]\n{body}"));
            let err = refused(&map, "agent-test");
            assert!(err.contains("agent-test"), "names the profile: {err}");
            assert!(err.contains("profile_version"), "{body}: {err}");
            assert!(err.contains('1'), "names the supported version: {err}");
        }
    }

    // #230 review: a selected profile that is refused names the field and
    // never its value, whatever the field. "SECRET-VALUE" stands for a value
    // that must not reach stderr.
    const LEAK: &str = "SECRET-VALUE";

    #[test]
    fn a_refused_profile_version_is_named_without_its_value() {
        for body in [
            "profile_version = \"SECRET-VALUE\"\n",
            "profile_version = [\"SECRET-VALUE\"]\n",
        ] {
            let map = profiles(&format!("[agent-test]\n{body}"));
            let err = refused(&map, "agent-test");
            assert!(err.contains("profile_version"), "{body}: {err}");
            assert!(!err.contains(LEAK), "{body}: the value leaked: {err}");
        }
    }

    #[test]
    fn a_wrongly_typed_field_is_named_without_its_value() {
        for (body, field) in [
            ("network = \"SECRET-VALUE\"\n", "network"),
            ("allow_hosts = \"SECRET-VALUE\"\n", "allow_hosts"),
            ("rw_maps = [1, \"SECRET-VALUE\"]\n", "rw_maps"),
            ("github = { a = \"SECRET-VALUE\" }\n", "github"),
            // A value holding the word itself: serde's "expected" is last.
            ("network = \"expected SECRET-VALUE\"\n", "network"),
        ] {
            let map = one("agent-test", body);
            let err = refused(&map, "agent-test");
            assert!(err.contains(field), "{body}: names {field}: {err}");
            assert!(!err.contains(LEAK), "{body}: the value leaked: {err}");
        }
    }

    #[test]
    fn an_unknown_key_is_named_with_its_control_bytes_escaped() {
        let map = one("agent-test", "\"ne\\u001btwork\" = \"SECRET-VALUE\"\n");
        let err = refused(&map, "agent-test");
        assert!(!err.contains('\u{1b}'), "a raw ESC reached stderr: {err:?}");
        assert!(err.contains("unknown key"), "{err}");
        assert!(!err.contains(LEAK), "the value leaked: {err}");
    }

    #[test]
    fn a_duplicate_inside_profiles_is_refused_without_the_source_line() {
        // TOML itself refuses both, for the whole file, before any profile
        // is selected; its message quotes the offending source line.
        for (text, needle) in [
            (
                "[profiles.web]\nprofile_version = 1\n\
                 env_pass = [\"K=x\"]\nenv_pass = [\"TOKEN=SECRET-VALUE\"]\n",
                "env_pass",
            ),
            (
                "[profiles.web]\nprofile_version = 1\nnetwork = true\n\
                 network = \"SECRET-VALUE\"\n",
                "network",
            ),
            (
                "[profiles.web]\nprofile_version = 1\n\
                 [profiles.\"web\"]\nallow_hosts = [\"SECRET-VALUE\"]\n",
                "web",
            ),
        ] {
            let err = parse_global_toml(text).unwrap_err();
            assert!(err.contains(needle), "names {needle}: {err}");
            assert!(err.contains("duplicate"), "{err}");
            assert!(err.contains("line"), "says where: {err}");
            assert!(!err.contains(LEAK), "the value leaked: {err}");
        }
    }

    #[test]
    fn a_profile_written_another_way_loses_the_excerpt_too() {
        for text in [
            "[\"profiles\".web]\nprofile_version = 1\nnetwork = \"SECRET-VALUE\n",
            "profiles.web.secret_hosts = { h = \"SECRET-VALUE }\n",
            "profiles = { web = { env_pass = [\"SECRET-VALUE ] } }\n",
        ] {
            let err = parse_global_toml(text).unwrap_err();
            assert!(err.contains("[profiles]"), "{text}: {err}");
            assert!(!err.contains(LEAK), "{text}: the value leaked: {err}");
        }
    }

    #[test]
    fn a_global_parse_error_outside_profiles_keeps_its_source_line() {
        // Only `[profiles.*]` loses the excerpt: elsewhere the operator still
        // sees the line, as before (with `NAME=VALUE` redacted by the caller).
        let err =
            parse_global_toml("network = true\nnetwork = false\n").unwrap_err();
        assert!(err.contains("network = false"), "{err}");
    }

    #[test]
    fn every_lockdown_drop_is_a_config_field() {
        // A renamed field would silently stop being filtered.
        const SOURCE: &str = include_str!("config.rs");
        for field in LOCKDOWN_DROPS {
            assert!(
                SOURCE.contains(&format!("    pub {field}: ")),
                "{field} is not a Config field"
            );
        }
    }

    #[test]
    fn profile_version_is_not_reported_as_an_unknown_key() {
        let map = one("agent-test", "allow_hosts = [\"a.example\"]\n");
        let config = select_profile(&map, "agent-test").unwrap();
        assert_eq!(config.allow_hosts, ["a.example"]);
    }

    #[test]
    fn profile_carrying_trust_project_config_is_refused() {
        let map = one("agent-test", "trust_project_config = [\"/srv/x\"]\n");
        let err = refused(&map, "agent-test");
        assert!(err.contains("trust_project_config"), "{err}");
        assert!(
            err.contains("global"),
            "trust comes from the global base: {err}"
        );
    }

    #[test]
    fn profile_unknown_keys_are_refused_naming_profile_and_key() {
        // A typo in a restriction must not be dropped.
        for (key, body) in [
            ("allow_host", "allow_host = [\"a.example\"]\n"),
            ("mask_exept", "mask_exept = [\"/x\"]\n"),
            ("no_gpus", "no_gpus = true\n"),
            ("profile", "profile = \"other\"\n"),
            // Empty values: a serialize round trip drops them, which is how
            // they once passed as known (maintainer's review of #230).
            ("allow_hostz", "allow_hostz = []\n"),
            ("mask_exeptions", "mask_exeptions = {}\n"),
            ("bogus_table", "[bogus_table]\n"),
            ("bogus_text", "bogus_text = \"\"\n"),
        ] {
            let map = one("agent-test", body);
            let err = refused(&map, "agent-test");
            assert!(err.contains("agent-test"), "{key}: {err}");
            assert!(err.contains(key), "{key}: must name the key: {err}");
        }
    }

    #[test]
    fn config_schema_keys_lists_every_field() {
        // The unknown-key check trusts this list, so it must be the struct's
        // fields exactly: one entry per `pub name:` line in `Config`.
        let src = include_str!("config.rs");
        let start = src.find("pub struct Config {").expect("Config");
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        assert!(
            !body.contains("flatten"),
            "serde(flatten) bypasses deserialize_struct's field list"
        );
        // A `#[serde(skip)]` field is never deserialized (runtime-only, such
        // as `runtime_harnesses`), so it is rightly absent from the schema.
        let mut declared: Vec<&str> = Vec::new();
        let mut skipped = false;
        for line in body.lines().map(str::trim) {
            if line.starts_with("#[serde(") {
                skipped |= line
                    .trim_start_matches("#[serde(")
                    .trim_end_matches(")]")
                    .split(',')
                    .any(|attr| attr.trim() == "skip");
            } else if let Some(rest) = line.strip_prefix("pub ") {
                if let Some((name, _)) = rest.split_once(':')
                    && !skipped
                {
                    declared.push(name.trim());
                }
                skipped = false;
            }
        }
        declared.sort_unstable();
        let mut schema = config_schema_keys().to_vec();
        schema.sort_unstable();
        assert_eq!(schema, declared);
    }

    #[test]
    fn profile_known_keys_with_empty_or_unserialised_values_are_accepted() {
        // The other half: known keys that a serialize round trip drops
        // must not look unknown.
        let map = one(
            "agent-test",
            "mask = []\nallow_hosts = []\nno_gpu = false\n\
             env_pass = [\"AJ_PROFILE_NAME\"]\n\
             env_from_file = [\"/tmp/aj-profile.env\"]\n\
             [secret_hosts]\nAJ_PROFILE_TOKEN = \"api.example.com\"\n",
        );
        let config = select_profile(&map, "agent-test").unwrap();
        assert_eq!(config.env_pass, ["AJ_PROFILE_NAME"]);
        assert_eq!(config.no_gpu, Some(false));
        assert_eq!(
            config
                .secret_hosts
                .get("AJ_PROFILE_TOKEN")
                .map(String::as_str),
            Some("api.example.com")
        );
    }

    /// Guard over the exclusion list: every `skip_serializing` field and
    /// every serde alias of `Config` must be accepted in a profile. The
    /// source is scanned so a field added later cannot become a false
    /// "unknown key". Each key is tried with values of several types; it
    /// passes when one of them is accepted.
    #[test]
    fn profile_accepts_every_unserialised_field_and_alias_in_config_rs() {
        let src = include_str!("config.rs");
        let skip_attr = concat!("skip_serial", "izing)]");
        let alias_attr = concat!("alias", " = \"");
        let mut keys: Vec<String> = Vec::new();
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("#[serde(") && line.contains(skip_attr) {
                let field = lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| l.starts_with("pub "))
                    .and_then(|l| l.strip_prefix("pub "))
                    .and_then(|l| l.split(':').next())
                    .expect("field after skip_serializing");
                keys.push(field.trim().to_string());
            }
            let mut rest = *line;
            while let Some(at) = rest.find(alias_attr) {
                let tail = &rest[at + alias_attr.len()..];
                let end = tail.find('"').expect("closing quote");
                keys.push(tail[..end].to_string());
                rest = &tail[end..];
            }
        }
        assert!(
            ["env_pass", "env_from_file", "secret_hosts"]
                .iter()
                .all(|k| keys.iter().any(|x| x == k)),
            "scanner missed a known skip_serializing field: {keys:?}"
        );
        let candidates = [
            "true",
            "1",
            "\"x\"",
            "[\"x\"]",
            "[\"/tmp/x\"]",
            "{ x = \"y\" }",
        ];
        for key in &keys {
            let accepted = candidates.iter().any(|value| {
                let map = one("guard", &format!("{key} = {value}\n"));
                select_profile(&map, "guard").is_ok()
            });
            assert!(accepted, "{key} is reported unknown for every value type");
        }
    }

    #[test]
    fn profile_type_errors_carry_the_profile_name() {
        let map = one("agent-test", "allow_hosts = \"not-a-list\"\n");
        let err = refused(&map, "agent-test");
        assert!(err.contains("agent-test"), "{err}");
        assert!(
            err.contains("allow_hosts") || err.contains("sequence"),
            "{err}"
        );
    }

    #[test]
    fn profile_reads_the_same_keys_as_a_command_table() {
        let map = one(
            "agent-test",
            "allow_hosts = [\"registry.npmjs.org\"]\n\
             mask = [\"/usr/bin/ssh\"]\n\
             ssh = true\n",
        );
        let config = select_profile(&map, "agent-test").unwrap();
        assert_eq!(config.allow_hosts, ["registry.npmjs.org"]);
        assert_eq!(config.mask, [PathBuf::from("/usr/bin/ssh")]);
        assert_eq!(config.ssh, Some(true));
    }
}

// Merge order and widenings.
//
// Module name starts with `profile` so `cargo test config::profile` runs it.
//
// Contract:
// - `merge_with_global_report(baseline, local, project_dir)
//     -> (Config, Vec<Refusal>)`, with
//   `Refusal { field: String, granted: Vec<String>, secret: bool,
//   text: String }`; `text` is today's exact warning string;
// - `load_global_for_command_from_path(path, cli, project)
//     -> Result<(Config, Option<ProfileReport>), String>` (the path-taking
//   twin of the global loader), with
//   `ProfileReport { name: String, widenings: Vec<Widening> }` and
//   `Widening { field: String, granted: Vec<String> }`;
// - order: global base, `[commands.<name>]`, profile (then CLI, then
//   project, in main). For secret fields `granted` holds key names only.
// The fixture is the trusted global config as v3.3.0 stores it:
// `<XDG_CONFIG_HOME>/ai-jail/config.toml`, directory 0700, file 0600
// (`config_store::StorePaths.global`); `~/.ai-jail` is only the legacy
// file the store migration consumes.
// Fixtures use only keys a v3.3.0 config can hold.
#[cfg(test)]
mod profile_merge_tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .expect("test CLI parses")
    }

    /// Write a trusted global config where v3.3.0 keeps it — a fresh
    /// `<tmp>/xdg/ai-jail/config.toml`, owner-only — and return
    /// (temp root, config path).
    fn global_file(body: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "ai-jail-profile-merge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = root.join("xdg").join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        (root, path)
    }

    fn load(body: &str, args: &[&str]) -> (Config, Option<ProfileReport>) {
        let (root, path) = global_file(body);
        let got = load_global_for_command_from_path(
            &path,
            &cli(args),
            &Config::default(),
        );
        let _ = std::fs::remove_dir_all(&root);
        got.expect("global config with profile loads")
    }

    fn widening<'a>(
        report: &'a ProfileReport,
        field: &str,
    ) -> Option<&'a Widening> {
        report.widenings.iter().find(|w| w.field == field)
    }

    #[test]
    fn profile_refusal_text_is_todays_exact_warning() {
        let local = Config {
            ssh: Some(true),
            allow_hosts: vec!["b.example".into()],
            ..Config::default()
        };
        let (_, refusals) = merge_with_global_report(
            Config::default(),
            local,
            Path::new("/tmp"),
        );
        let texts: Vec<&str> =
            refusals.iter().map(|r| r.text.as_str()).collect();
        assert!(
            texts.contains(
                &"project .ai-jail ssh ignored because it weakens the \
                  baseline sandbox"
            ),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"project .ai-jail allow_hosts ignored: b.example"),
            "{texts:?}"
        );
        let hosts = refusals.iter().find(|r| r.field == "allow_hosts").unwrap();
        assert_eq!(hosts.granted, ["b.example"]);
        assert!(!hosts.secret);
    }

    #[test]
    fn profile_secret_refusals_carry_key_names_never_values() {
        let local = Config {
            env_pass: vec!["AJ_PROFILE_SECRET=topsecret-value".into()],
            ..Config::default()
        };
        let (_, refusals) = merge_with_global_report(
            Config::default(),
            local,
            Path::new("/tmp"),
        );
        let env = refusals
            .iter()
            .find(|r| r.field == "env_pass")
            .expect("env_pass");
        assert!(env.secret);
        assert_eq!(env.granted, ["AJ_PROFILE_SECRET"]);
        for r in &refusals {
            assert!(
                !r.text.contains("topsecret")
                    && !r.granted.iter().any(|g| g.contains("topsecret")),
                "secret value leaked: {r:?}"
            );
        }
    }

    #[test]
    fn profile_that_only_tightens_reports_no_widening() {
        // Tightening must never be called a widening.
        let (config, report) = load(
            "[profiles.tight]\nprofile_version = 1\nno_gpu = true\n\
             mask = [\"/usr/bin/ssh\"]\n",
            &["--profile", "tight", "bash"],
        );
        let report = report.expect("a selected profile yields a report");
        assert_eq!(report.name, "tight");
        assert!(
            report.widenings.is_empty(),
            "{:?}",
            report
                .widenings
                .iter()
                .map(|w| &w.field)
                .collect::<Vec<_>>()
        );
        assert_eq!(config.no_gpu, Some(true));
    }

    #[test]
    fn profile_widenings_name_capability_hosts_and_outside_maps() {
        let (config, report) = load(
            "allow_hosts = [\"a.example\"]\n\
             [profiles.wide]\nprofile_version = 1\nssh = true\n\
             allow_hosts = [\"a.example\", \"b.example\"]\n\
             rw_maps = [\"/opt/aj-outside\"]\n",
            &["--profile", "wide", "bash"],
        );
        let report = report.unwrap();
        assert!(widening(&report, "ssh").is_some(), "capability widening");
        // Only what the base did not already grant is a widening.
        let hosts = widening(&report, "allow_hosts").expect("host widening");
        assert_eq!(hosts.granted, ["b.example"]);
        let maps = widening(&report, "rw_maps").expect("outside-map widening");
        assert!(
            maps.granted.iter().any(|g| g.contains("/opt/aj-outside")),
            "{:?}",
            maps.granted
        );
        // And the profile was applied as a trusted layer.
        assert_eq!(config.ssh, Some(true));
        assert!(config.allow_hosts.iter().any(|h| h == "b.example"));
    }

    #[test]
    fn profile_secret_widening_lists_keys_only() {
        let (_, report) = load(
            "[profiles.sec]\nprofile_version = 1\n\
             env_pass = [\"AJ_PROFILE_SECRET=topsecret-value\"]\n",
            &["--profile", "sec", "bash"],
        );
        let report = report.unwrap();
        let env = widening(&report, "env_pass").expect("env_pass widening");
        assert_eq!(env.granted, ["AJ_PROFILE_SECRET"]);
    }

    #[test]
    fn profile_applies_after_the_command_table_and_before_the_cli() {
        let body = "[commands.bash]\nssh = true\nno_gpu = true\n\
                    [profiles.nossh]\nprofile_version = 1\nssh = false\n";
        let (config, _) = load(body, &["--profile", "nossh", "bash"]);
        assert_eq!(
            config.ssh,
            Some(false),
            "profile overrides the command table"
        );
        assert_eq!(
            config.no_gpu,
            Some(true),
            "untouched command-table keys stay"
        );
        let with_cli =
            merge(&cli(&["--profile", "nossh", "--ssh", "bash"]), config);
        assert_eq!(with_cli.ssh, Some(true), "the CLI overrides the profile");
    }

    #[test]
    fn profile_absent_means_no_report_even_with_a_malformed_table() {
        let (config, report) = load(
            "no_gpu = true\n[profiles.bad]\nprofile_version = \"x\"\n\
             allow_hosts = 3\n",
            &["bash"],
        );
        assert!(report.is_none());
        assert_eq!(config.no_gpu, Some(true));
    }
}

#[cfg(test)]
mod profile_field_coverage_tests {
    use std::path::Path;

    use super::*;

    /// `Config` fields that cannot widen the jail, so no refusal rule is
    /// owed: restrictions a layer may only add, what runs, and UI or
    /// persistence preferences. `runtime_harnesses` is `serde(skip)` and
    /// cannot come from a file at all.
    const NEVER_WIDENS: &[&str] = &[
        "runtime_harnesses",
        "rlimit_source",
        "cpus_source",
        "command",
        "hide_dotdirs",
        "mask",
        "deny_paths",
        "no_status_bar",
        "status_bar_style",
        "resize_redraw_key",
        "no_save_config",
    ];

    fn config_fields() -> Vec<String> {
        let src = include_str!("config.rs");
        let body = src
            .split_once("pub struct Config {")
            .expect("struct Config")
            .1;
        let body = &body[..body.find("\n}").expect("end of struct Config")];
        body.lines()
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter_map(|l| l.split_once(':').map(|(name, _)| name))
            .map(str::to_string)
            .collect()
    }

    /// A field is covered when some value of it, asked for by a layer over
    /// a default baseline, comes back as a refusal naming that field. A
    /// new field with no rule fails here, so a profile can never widen
    /// through a field the report does not see.
    #[test]
    fn profile_every_config_field_is_refused_or_never_widens() {
        let candidates = [
            "true",
            "false",
            "\"x\"",
            "\"0-2\"",
            "\"1-3\"",
            "\"/opt/aj-outside\"",
            "[\"/opt/aj-outside\"]",
            "[\"x.example\"]",
            "[4242]",
            "{ AJ_PROFILE_KEY = \"x.example\" }",
            "{ nofile = \"unlimited\" }",
        ];
        let fields = config_fields();
        assert!(fields.len() > 40, "scanner found {fields:?}");
        let mut uncovered = Vec::new();
        for field in &fields {
            if NEVER_WIDENS.contains(&field.as_str()) {
                continue;
            }
            // Default-on switches widen only over a baseline that turned
            // them off, so every parsable value is also tried as baseline.
            let values: Vec<Config> = candidates
                .iter()
                .filter_map(|v| parse_toml(&format!("{field} = {v}\n")).ok())
                .collect();
            let baselines =
                std::iter::once(Config::default()).chain(values.clone());
            let refused = baselines.into_iter().any(|baseline| {
                values.iter().any(|local| {
                    let (_, refusals) = merge_layer_report(
                        baseline.clone(),
                        local.clone(),
                        Path::new("/project"),
                        "profile 'coverage'",
                    );
                    refusals.iter().any(|r| {
                        r.field == *field
                            || r.field
                                .strip_prefix(field)
                                .is_some_and(|suffix| suffix.starts_with('.'))
                    })
                })
            });
            if !refused {
                uncovered.push(field.clone());
            }
        }
        assert!(
            uncovered.is_empty(),
            "no refusal rule and not in NEVER_WIDENS: {uncovered:?}"
        );
    }
}

#[cfg(test)]
mod profile_review_tests {
    use std::collections::BTreeMap;

    use super::*;

    fn one(body: &str) -> BTreeMap<String, toml::Value> {
        let mut table: toml::Table = body.parse().unwrap();
        table.insert("profile_version".into(), toml::Value::Integer(1));
        BTreeMap::from([("p".to_string(), toml::Value::Table(table))])
    }

    #[test]
    fn profile_refuses_command_and_ui_preferences() {
        for (key, body) in [
            ("command", "command = [\"codex\"]\n"),
            ("no_status_bar", "no_status_bar = true\n"),
            ("status_bar_style", "status_bar_style = \"light\"\n"),
            ("resize_redraw_key", "resize_redraw_key = \"ctrl-l\"\n"),
        ] {
            let err = select_profile(&one(body), "p").unwrap_err();
            assert!(err.contains(key) && err.contains("'p'"), "{err}");
        }
    }

    #[test]
    fn profile_widening_line_cannot_be_forged_by_a_value() {
        let report = ProfileReport {
            name: "p".into(),
            widenings: vec![Widening {
                field: "rw_maps".into(),
                granted: vec![
                    "/x\" widens=network granted=\"y".into(),
                    "a,b".into(),
                ],
            }],
        };
        let line = &report.lines()[0];
        assert_eq!(
            line,
            concat!(
                r#"profile=p widens=rw_maps granted="/x\" "#,
                r#"widens=network granted=\"y,a\,b""#,
            )
        );
        assert_eq!(
            line.matches("widens=").count()
                - line.matches("\\\" widens=").count(),
            1
        );
    }
}

// A global rewrite keeps every profile.
//
// Module name starts with `profile` so `cargo test config::profile` runs it.
//
// Contract: every path that rewrites the trusted global config round-trips
// `[profiles.*]` tables with every key and value. In v3.3.0 (fe4dfe0)
// those paths are `config_store::save_global_preferences` (the
// status-bar preference save) and `config_store::migrate` (the legacy
// `~/.ai-jail` moved to `$XDG_CONFIG_HOME/ai-jail/config.toml`).
// Values are compared, not bytes: comments and table order may be lost by
// a rewrite.
#[cfg(test)]
mod profile_save_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::config_store::{self, StorePaths};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A private temp root with `home/`, `project/` and an owner-only
    /// store at `xdg/ai-jail`, and the `StorePaths` that `discover` would
    /// build for it (built by hand: no process environment is touched).
    struct Fixture {
        root: PathBuf,
        paths: StorePaths,
    }

    impl Fixture {
        fn new() -> Self {
            // The trusted store refuses a symlink anywhere in its path, and
            // macOS's temp dir sits under the /var -> /private/var symlink:
            // resolve it first, as config_store's own tests do.
            let temp = std::fs::canonicalize(std::env::temp_dir())
                .expect("temp dir resolves");
            let root = temp.join(format!(
                "ai-jail-profile-save-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let home = root.join("home");
            let project = root.join("project");
            let store = root.join("xdg").join("ai-jail");
            for dir in [&home, &project, &store] {
                std::fs::create_dir_all(dir).unwrap();
            }
            std::fs::set_permissions(
                &store,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let canonical_project = std::fs::canonicalize(&project).unwrap();
            let paths = StorePaths {
                available: true,
                root: store.clone(),
                global: store.join("config.toml"),
                global_provenance: store.join("global-migration.toml"),
                project: store
                    .join("projects")
                    .join("ai-jail-profile-save.toml"),
                legacy_global: home.join(".ai-jail"),
                legacy_project: canonical_project.join(".ai-jail"),
                policy_root: canonical_project.clone(),
                canonical_project,
                project_strategy: ProjectStrategy::Basename,
            };
            Self { root, paths }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn write_owner_only(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn table(path: &Path) -> toml::Table {
        std::fs::read_to_string(path).unwrap().parse().unwrap()
    }

    const GLOBAL: &str = "\
allow_hosts = [\"platform.claude.com\"]

[commands.claude]
agent_state = true

[profiles.agent-test]
profile_version = 1
allow_hosts = [\"registry.npmjs.org\", \"api.example.com\"]
mask = [\"/usr/bin/ssh\", \"/usr/bin/scp\"]
no_gpu = true
some_future_key = { nested = [1, 2, 3], flag = true }

[profiles.empty_one]
profile_version = 1

[profiles.malformed]
profile_version = \"not-an-int\"
allow_hosts = 3
";

    #[test]
    fn profile_tables_survive_a_status_bar_rewrite_key_for_key() {
        let fx = Fixture::new();
        write_owner_only(&fx.paths.global, GLOBAL);
        let before = table(&fx.paths.global);
        config_store::save_global_preferences(&fx.paths, None, Some("dark"))
            .expect("rewrite succeeds");
        let after = table(&fx.paths.global);

        // The rewrite did happen.
        assert_eq!(
            after.get("status_bar_style").and_then(|v| v.as_str()),
            Some("dark")
        );
        // Every profile, malformed or not, keeps every key and value.
        assert_eq!(after.get("profiles"), before.get("profiles"), "{after:#?}");
        // The rest of the file is untouched in value.
        assert_eq!(after.get("commands"), before.get("commands"));
        assert_eq!(after.get("allow_hosts"), before.get("allow_hosts"));
    }

    #[test]
    fn profile_tables_survive_the_legacy_global_migration_key_for_key() {
        let fx = Fixture::new();
        write_owner_only(&fx.paths.legacy_global, GLOBAL);
        let before = table(&fx.paths.legacy_global);
        let mut notices = Vec::new();
        config_store::migrate(&fx.paths, false, &mut notices)
            .expect("migration succeeds");
        let after = table(&fx.paths.global);

        // The migration did happen.
        assert!(!fx.paths.legacy_global.exists(), "legacy file still there");
        // Every profile, malformed or not, keeps every key and value.
        assert_eq!(after.get("profiles"), before.get("profiles"), "{after:#?}");
        assert_eq!(after.get("commands"), before.get("commands"));
        assert_eq!(after.get("allow_hosts"), before.get("allow_hosts"));
    }
}

#[cfg(test)]
mod profile_project_tests {
    use super::*;

    #[test]
    fn profile_keys_in_a_project_document_are_detected() {
        assert!(project_selects_profile("profile = \"wide\"\n", &[]));
        assert!(project_selects_profile(
            "[profiles.evil]\nnetwork = true\n",
            &[]
        ));
        let store = "[grants]\nprofile = \"wide\"\n";
        assert!(!project_selects_profile(store, &[]));
        assert!(project_selects_profile(store, &["grants", "constraints"]));
        assert!(!project_selects_profile("no_gpu = true\n", &["grants"]));
        assert!(!project_selects_profile("not toml [", &[]));
    }

    #[test]
    fn a_project_profile_key_changes_nothing_in_the_policy() {
        let with = parse_toml("no_gpu = true\nprofile = \"wide\"\n").unwrap();
        assert_eq!(with, parse_toml("no_gpu = true\n").unwrap());
    }
}

// A profile table and a `[commands.<name>]` table with the same keys
// produce the same Config, and that Config survives a serialize/parse
// round trip. Test names contain `roundtrip`. Fixtures use only keys a
// v3.3.0 config can hold.
#[cfg(test)]
mod roundtrip_profiles_tests {
    use std::collections::BTreeMap;

    use super::*;

    const KEYS: &str = "\
allow_hosts = [\"registry.npmjs.org\", \"api.example.com\"]
mask = [\"/usr/bin/ssh\", \"/usr/bin/scp\"]
ssh = true
no_gpu = true
hide_dotdirs = [\".secrets\"]
";

    fn as_toml(config: &Config) -> toml::Table {
        toml::to_string(config).unwrap().parse().unwrap()
    }

    #[test]
    fn roundtrip_profile_equals_the_same_keys_as_a_command_table() {
        let mut profile: toml::Table = KEYS.parse().unwrap();
        profile.insert("profile_version".into(), toml::Value::Integer(1));
        let profiles = BTreeMap::from([(
            "agent-test".to_string(),
            toml::Value::Table(profile),
        )]);
        let from_profile = select_profile(&profiles, "agent-test").unwrap();
        let global =
            parse_global_toml(&format!("[commands.bash]\n{KEYS}")).unwrap();
        let from_command = global.commands.get("bash").unwrap();
        assert_eq!(as_toml(&from_profile), as_toml(from_command));
    }

    #[test]
    fn roundtrip_selected_profile_serializes_and_parses_back_unchanged() {
        let mut profile: toml::Table = KEYS.parse().unwrap();
        profile.insert("profile_version".into(), toml::Value::Integer(1));
        let profiles =
            BTreeMap::from([("p".to_string(), toml::Value::Table(profile))]);
        let config = select_profile(&profiles, "p").unwrap();
        let body = toml::to_string(&config).unwrap();
        assert!(!body.contains("profile_version"), "{body}");
        assert_eq!(as_toml(&parse_toml(&body).unwrap()), as_toml(&config));
    }
}

// A stray non-table entry under `[profiles]` is inert unless selected, and
// refused naming the profile when it is; a wrong-typed secret field is
// refused naming profile, field and expected type, never the value; and a
// field the profile-layer filter refuses cannot hide a widening in another
// field. Fixtures are the trusted global config
// `<XDG_CONFIG_HOME>/ai-jail/config.toml` (dir 0700, file 0600), loaded
// through `load_global_for_command_from_path`, as a launch loads it.
#[cfg(test)]
mod profile_trust_tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .expect("test CLI parses")
    }

    fn global_file(body: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "aj-profile-trust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = root.join("xdg").join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        (root, path)
    }

    fn load(
        body: &str,
        args: &[&str],
    ) -> Result<(Config, Option<ProfileReport>), String> {
        let (root, path) = global_file(body);
        let got = load_global_for_command_from_path(
            &path,
            &cli(args),
            &Config::default(),
        );
        let _ = std::fs::remove_dir_all(&root);
        got
    }

    fn fields(report: &ProfileReport) -> Vec<&str> {
        report.widenings.iter().map(|w| w.field.as_str()).collect()
    }

    const WIDE: &str = "\
[profiles.wide]
profile_version = 1
allow_hosts = [\"api.example.com\"]
";

    // ── Non-table entries under [profiles] ────────────

    #[test]
    fn stray_non_table_profiles_entry_is_inert_without_profile() {
        // Entries a user plausibly writes by mistake.
        // Each must leave a launch that names no profile untouched.
        for stray in [
            "default = \"agent-test\"",
            "default = 1",
            "default = [\"agent-test\"]",
            "enabled = true",
        ] {
            let body = format!("no_gpu = true\n[profiles]\n{stray}\n");
            let (config, report) =
                load(&body, &["claude"]).unwrap_or_else(|e| {
                    panic!("{stray:?} must not break a plain launch: {e}")
                });
            assert!(report.is_none(), "{stray:?}");
            assert_eq!(config.no_gpu, Some(true), "{stray:?}: base lost");
        }
    }

    #[test]
    fn stray_entry_does_not_stop_a_sibling_profile_from_selecting() {
        let body = format!("[profiles]\ndefault = \"wide\"\n\n{WIDE}");
        let (config, report) = load(&body, &["--profile", "wide", "claude"])
            .unwrap_or_else(|e| panic!("sibling must select: {e}"));
        assert_eq!(report.expect("report").name, "wide");
        assert_eq!(config.allow_hosts, ["api.example.com"]);
    }

    #[test]
    fn selected_non_table_profiles_entry_is_refused_naming_the_profile() {
        let body = format!("[profiles]\ndefault = \"wide\"\n\n{WIDE}");
        let err = load(&body, &["--profile", "default", "claude"])
            .expect_err("a non-table entry cannot be a profile");
        assert!(err.contains("profile 'default'"), "{err}");
        assert!(err.contains("table"), "must say a table is needed: {err}");
    }

    // ── Wrong-typed secret fields ──────────────────────

    /// Every fragment of a fixture value; none may reach the message.
    const LEAK: [&str; 4] = ["API_KEY", "sk-live", "TOPSECRET", "SECRETPATH"];

    fn secret_refusal(field_line: &str) -> String {
        let body = format!("[profiles.p]\nprofile_version = 1\n{field_line}\n");
        let err = load(&body, &["--profile", "p", "claude"])
            .expect_err("a wrong-typed secret field must refuse the launch");
        for fragment in LEAK {
            assert!(
                !err.contains(fragment),
                "secret fragment {fragment:?} echoed: {err}"
            );
        }
        assert!(err.contains("profile 'p'"), "{err}");
        err
    }

    fn names_one_of(err: &str, words: &[&str]) -> bool {
        let lower = err.to_lowercase();
        words.iter().any(|w| lower.contains(w))
    }

    #[test]
    fn env_pass_of_the_wrong_type_is_refused_without_its_value() {
        // Brackets forgotten: the most likely mistake, and the leaky one.
        let err = secret_refusal("env_pass = \"API_KEY=sk-live-TOPSECRET\"");
        assert!(err.contains("env_pass"), "{err}");
        assert!(
            names_one_of(&err, &["array", "sequence", "list"]),
            "must name the expected type: {err}"
        );
    }

    #[test]
    fn env_from_file_of_the_wrong_type_is_refused_without_its_value() {
        let err = secret_refusal(
            "env_from_file = \"/home/u/API_KEY/sk-live-TOPSECRET/SECRETPATH\"",
        );
        assert!(err.contains("env_from_file"), "{err}");
        assert!(
            names_one_of(&err, &["array", "sequence", "list"]),
            "must name the expected type: {err}"
        );
    }

    #[test]
    fn secret_hosts_of_the_wrong_type_is_refused_without_its_value() {
        let err =
            secret_refusal("secret_hosts = \"API_KEY=sk-live-TOPSECRET\"");
        assert!(err.contains("secret_hosts"), "{err}");
        assert!(
            names_one_of(&err, &["table", "map"]),
            "must name the expected type: {err}"
        );
    }

    #[test]
    fn non_secret_type_error_names_the_field_and_the_expected_type() {
        // Since the #230 review every field is value-free, not only the
        // three secret ones: the field and the type it expects stay, the
        // parser's quote of the value does not.
        let body = "[profiles.p]\nprofile_version = 1\nallow_hosts = 3\n";
        let err = load(body, &["--profile", "p", "claude"])
            .expect_err("wrong type refuses");
        assert!(err.contains("profile 'p'"), "{err}");
        assert!(err.contains("allow_hosts"), "{err}");
        assert!(err.contains("expected a sequence"), "{err}");
        assert!(!err.contains("invalid type"), "parser message kept: {err}");
    }

    // ── Widenings against the merged result ───────────────────

    #[test]
    fn profile_reports_a_raised_resource_limit_unless_the_cli_chooses_it() {
        let body = "\
[rlimit]
nofile = 512
[profiles.more]
profile_version = 1
[profiles.more.rlimit]
nofile = 1024
";
        let (_, report) = load(body, &["--profile", "more", "claude"]).unwrap();
        assert!(report.unwrap().widenings.iter().any(|widening| {
            widening.field == "rlimit.nofile" && widening.granted == ["1024"]
        }));
        let args =
            cli(&["--profile", "more", "--rlimit", "nofile=1024", "claude"]);
        let base = parse_toml("[rlimit]\nnofile = 512\n").unwrap();
        let (profiled, report) =
            load(body, &["--profile", "more", "claude"]).unwrap();
        let launch = merge(&args, profiled);
        let report = report
            .unwrap()
            .applied(
                ProfileLayers {
                    without_profile: merge(&args, base),
                    with_profile: launch.clone(),
                },
                &launch,
                Path::new("."),
            )
            .unwrap();
        assert!(
            !report
                .widenings
                .iter()
                .any(|widening| { widening.field == "rlimit.nofile" })
        );
    }

    #[test]
    fn cpu_profile_reports_only_additional_cpus_kept_for_the_launch() {
        let body = "\
cpus = \"0-1\"
[profiles.more]
profile_version = 1
cpus = \"0-3\"
";
        let (profiled, report) =
            load(body, &["--profile", "more", "claude"]).unwrap();
        let base = parse_toml("cpus = \"0-1\"\n").unwrap();
        let launch = Config {
            cpus: Some("1-2".into()),
            ..profiled.clone()
        };
        let report = report
            .unwrap()
            .applied(
                ProfileLayers {
                    without_profile: base,
                    with_profile: profiled,
                },
                &launch,
                Path::new("."),
            )
            .unwrap();
        assert!(report.widenings.iter().any(|widening| {
            widening.field == "cpus" && widening.granted == ["2"]
        }));
    }

    #[test]
    fn refused_lockdown_does_not_hide_the_agent_state_widening() {
        let body = "\
lockdown = true
agent_state = false
[profiles.open]
profile_version = 1
lockdown = false
agent_state = true
pictures = true
";
        let (config, report) = load(body, &["--profile", "open", "claude"])
            .expect("profile loads");
        // What actually applies: the profile opened agent state ...
        assert!(config.agent_state_enabled(), "fixture premise");
        let report = report.expect("report");
        let got = fields(&report);
        // ... so every field it opened has a line, not just the first.
        for field in ["lockdown", "agent_state", "pictures"] {
            assert!(got.contains(&field), "{field} hidden: {got:?}");
        }
    }

    #[test]
    fn profile_restating_the_base_reports_no_widening() {
        // The rule must not fire wrongly: a profile that grants nothing
        // the base did not already have prints nothing.
        let body = "\
lockdown = true
agent_state = false
[profiles.same]
profile_version = 1
lockdown = true
agent_state = false
";
        let (_, report) = load(body, &["--profile", "same", "claude"])
            .expect("profile loads");
        let report = report.expect("report");
        assert!(report.widenings.is_empty(), "{:?}", fields(&report));
    }
}

// Review regressions: a map the profile adds is not a widening of
// another map it adds, and a `nan` in an unselected profile does not make
// a global rewrite look like a loss.
#[cfg(test)]
mod profile_review_regression_tests {
    use super::*;

    #[test]
    fn profile_in_project_rw_map_under_its_own_ro_parent_is_not_a_widening() {
        let cwd = std::env::current_dir().unwrap();
        let parent = cwd.parent().unwrap().display().to_string();
        let inside = cwd.join("src").display().to_string();
        let root = std::env::temp_dir()
            .join(format!("aj-profile-review-{}", std::process::id()));
        let store = root.join("xdg").join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        let path = store.join("config.toml");
        std::fs::write(
            &path,
            format!(
                "[profiles.p]\nprofile_version = 1\nro_maps = [{parent:?}]\n\
                 rw_maps = [{inside:?}]\n"
            ),
        )
        .unwrap();
        let cli = crate::cli::parse_from(lexopt::Parser::from_args(
            ["--profile", "p", "bash"]
                .iter()
                .map(std::ffi::OsString::from),
        ))
        .unwrap();
        let got =
            load_global_for_command_from_path(&path, &cli, &Config::default());
        std::fs::remove_dir_all(&root).unwrap();
        let (_, report) = got.expect("profile loads");
        let fields: Vec<String> = report
            .expect("report")
            .widenings
            .into_iter()
            .map(|w| w.field)
            .collect();
        assert!(fields.contains(&"ro_maps".to_string()), "{fields:?}");
        assert!(!fields.contains(&"rw_maps".to_string()), "{fields:?}");
    }

    #[test]
    fn nan_in_an_unselected_profile_still_compares_equal() {
        let text = "no_gpu = true\n[profiles]\nstray = nan\n";
        let a = parse_global_toml(text).unwrap();
        let b = parse_global_toml(text).unwrap();
        assert!(a.same_policy(&b));
        let c = parse_global_toml("no_gpu = false\n[profiles]\nstray = nan\n")
            .unwrap();
        assert!(!a.same_policy(&c), "a base difference is still seen");
    }
}

// The `[profiles]` container itself is lenient. A release without
// profiles has no `profiles` field, so a top-level `profiles = 5` is an
// unknown key it ignores; a launch that names no profile must keep
// ignoring it, and only `--profile` refuses it, saying `profiles` must be
// a table. And the effective-access review of a launch that selects no
// profile carries no named-profile line at all, so it
// reads as it did before profiles existed. Fixtures are the trusted global
// config `<root>/xdg/ai-jail/config.toml` (dir 0700, file 0600) under the
// test temp dir, loaded through `load_global_for_command_from_path`, as a
// launch loads it.
#[cfg(test)]
mod profile_stray_key_tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .expect("test CLI parses")
    }

    fn scratch_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aj-profile-stray-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn load(
        body: &str,
        args: &[&str],
    ) -> Result<(Config, Option<ProfileReport>), String> {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch_root();
        let store = root.join("xdg").join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let got = load_global_for_command_from_path(
            &path,
            &cli(args),
            &Config::default(),
        );
        let _ = std::fs::remove_dir_all(&root);
        got
    }

    /// Top-level `profiles` values that are not a table. `[[profiles]]`
    /// is an array of tables: table-shaped entries, still not a table.
    const NOT_A_TABLE: [&str; 5] = [
        "profiles = 5\n",
        "profiles = \"agent-test\"\n",
        "profiles = true\n",
        "profiles = [\"agent-test\"]\n",
        "[[profiles]]\nprofile_version = 1\npictures = true\n",
    ];

    // ── Inert without --profile ──────────────────────────────────────

    #[test]
    fn non_table_profiles_key_is_inert_without_profile() {
        // An existing config that happens to carry an unknown `profiles`
        // key must launch exactly as it does without profile support,
        // base policy intact, with no profile reported.
        for stray in NOT_A_TABLE {
            let body = format!(
                "no_gpu = true\nallow_hosts = [\"a.example\"]\n{stray}"
            );
            let (config, report) =
                load(&body, &["claude"]).unwrap_or_else(|e| {
                    panic!("{stray:?} must not break a plain launch: {e}")
                });
            assert!(report.is_none(), "{stray:?}: a profile was reported");
            assert_eq!(config.no_gpu, Some(true), "{stray:?}: base lost");
            assert_eq!(config.allow_hosts, ["a.example"], "{stray:?}");
            assert_ne!(
                config.pictures,
                Some(true),
                "{stray:?}: an unselected entry leaked into the policy"
            );
        }
    }

    // ── Refused with --profile, naming `profiles` and "table" ────────

    #[test]
    fn non_table_profiles_key_is_refused_with_profile() {
        for stray in NOT_A_TABLE {
            let body = format!("no_gpu = true\n{stray}");
            let err = load(&body, &["--profile", "x", "claude"])
                .expect_err("a non-table `profiles` cannot hold profile x");
            assert!(err.contains("profiles"), "{stray:?}: {err}");
            assert!(
                err.contains("table"),
                "{stray:?}: must say `profiles` must be a table: {err}"
            );
            // The refusal is the selection's, not a parse failure of the
            // whole file: the same file loads without --profile.
            assert!(
                !err.contains("parse error"),
                "{stray:?}: refused at parse time, not at selection: {err}"
            );
        }
    }

    #[test]
    fn table_profiles_still_select_through_the_lenient_container() {
        // The converse: leniency must not swallow a real table, in either
        // spelling, nor turn a missing name into the "must be a table"
        // refusal.
        for body in [
            "[profiles.w]\nprofile_version = 1\npictures = true\n",
            "profiles = { w = { profile_version = 1, pictures = true } }\n",
        ] {
            let (config, report) = load(body, &["--profile", "w", "claude"])
                .unwrap_or_else(|e| panic!("{body:?} must select w: {e}"));
            assert_eq!(report.expect("report").name, "w", "{body:?}");
            assert_eq!(config.pictures, Some(true), "{body:?}");
        }
        let err = load(
            "[profiles.w]\nprofile_version = 1\n",
            &["--profile", "x", "claude"],
        )
        .expect_err("x is not defined");
        assert!(err.contains("profile 'x'"), "{err}");
        assert!(err.contains("defined"), "not an existence refusal: {err}");
    }

    // ── The review names no profile when none is selected ────────────

    fn review(named: Option<&str>) -> String {
        let project = Path::new("/var/empty/aj-stray-key-project");
        crate::onboarding::render_effective_access_with_profile(
            &Config::default(),
            project,
            "claude",
            None,
            &[],
            named,
        )
        .expect("review renders")
    }

    #[test]
    fn review_without_a_profile_has_no_named_profile_line() {
        let plain = crate::onboarding::render_effective_access(
            &Config::default(),
            Path::new("/var/empty/aj-stray-key-project"),
            "claude",
            None,
            &[],
        )
        .expect("review renders");
        assert!(
            !plain.contains("Named profile"),
            "a launch with no profile gained a profile line:\n{plain}"
        );
        assert_eq!(plain, review(None), "the two entry points disagree");
    }

    #[test]
    fn review_with_a_profile_still_names_it() {
        // The converse: dropping the "none" line must not drop the line
        // that names a selected profile, which the interface test needs.
        let named = review(Some("w"));
        assert!(named.contains("profile=w"), "{named}");
        // And a selected profile is the only difference: one extra line.
        let plain = review(None);
        let extra: Vec<&str> = named
            .lines()
            .filter(|l| !plain.lines().any(|p| p == *l))
            .collect();
        assert_eq!(extra.len(), 1, "{extra:?}");
        assert!(extra[0].contains("profile=w"), "{extra:?}");
    }
}

// The `--profile` refusals name the TOML type of the value that is not a
// table. `toml::Value::type_str()` returns a bare noun ("integer",
// "array"), so a message built as "is a {}" reads "is a integer" and
// "is a array". The wording "is of type {}" is grammatical for every
// type name, so these tests pin it on both refusals: the top-level
// `profiles` key, and one entry under `[profiles]`. Fixtures are the
// trusted global config `<root>/xdg/ai-jail/config.toml` (dir 0700, file
// 0600) under the test temp dir, loaded as a launch loads it.
#[cfg(test)]
mod profile_type_word_tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn cli(args: &[&str]) -> CliArgs {
        crate::cli::parse_from(lexopt::Parser::from_args(
            args.iter().map(std::ffi::OsString::from),
        ))
        .expect("test CLI parses")
    }

    fn scratch_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aj-profile-type-words-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The refusal `--profile w` gets for the global config `body`.
    fn refusal(body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch_root();
        let store = root.join("xdg").join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let got = load_global_for_command_from_path(
            &path,
            &cli(&["--profile", "w", "claude"]),
            &Config::default(),
        );
        let _ = std::fs::remove_dir_all(&root);
        match got {
            Ok(_) => panic!("{body:?}: --profile w must be refused"),
            Err(e) => e,
        }
    }

    /// The article form is ungrammatical for these type names; no refusal
    /// may carry it, whichever site produced it.
    fn assert_no_bare_article(body: &str, err: &str) {
        for bad in ["is a integer", "is a array"] {
            assert!(
                !err.contains(bad),
                "{body:?}: refusal still says {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn type_words_top_level_integer_profiles_says_of_type_integer() {
        let body = "profiles = 5\n";
        let err = refusal(body);
        assert_no_bare_article(body, &err);
        assert!(
            err.contains("is of type integer"),
            "{body:?}: must name the type as \"is of type integer\": {err}"
        );
        // The rewording keeps what the refusal is for: `profiles` must be
        // a table.
        assert!(err.contains("profiles"), "{body:?}: {err}");
        assert!(err.contains("table"), "{body:?}: {err}");
    }

    #[test]
    fn type_words_top_level_array_profiles_says_of_type_array() {
        // A mixed array, so the type word cannot come from an element.
        let body = "profiles = [1, \"a\"]\n";
        let err = refusal(body);
        assert_no_bare_article(body, &err);
        assert!(
            err.contains("is of type array"),
            "{body:?}: must name the type as \"is of type array\": {err}"
        );
        assert!(err.contains("table"), "{body:?}: {err}");
    }

    #[test]
    fn type_words_non_table_entry_says_of_type_integer() {
        // The per-entry refusal is a second message site: fixing only the
        // top-level one would leave this one reading "is a integer".
        let body = "[profiles]\nw = 5\n";
        let err = refusal(body);
        assert_no_bare_article(body, &err);
        assert!(
            err.contains("is of type integer"),
            "{body:?}: must name the type as \"is of type integer\": {err}"
        );
        assert!(err.contains("'w'"), "{body:?}: names the entry: {err}");
        assert!(err.contains("table"), "{body:?}: {err}");
    }

    #[test]
    fn type_words_non_table_array_entry_says_of_type_array() {
        let body = "[profiles]\nw = [1, \"a\"]\n";
        let err = refusal(body);
        assert_no_bare_article(body, &err);
        assert!(
            err.contains("is of type array"),
            "{body:?}: must name the type as \"is of type array\": {err}"
        );
        assert!(err.contains("table"), "{body:?}: {err}");
    }
}
