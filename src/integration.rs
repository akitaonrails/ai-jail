//! Stable machine-facing contract for trusted wrappers such as ai-memory.
//!
//! A wrapper request describes desired authority; it never grants authority.
//! Exact normalized requests must be approved in the trusted external project
//! document before a non-interactive launch can use them.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const EXIT_REQUIRED_GRANT: i32 = 3;
pub(crate) const EXIT_BLOCKED: i32 = 4;
pub(crate) const EXIT_BACKEND_UNAVAILABLE: i32 = 5;
const MAX_REQUEST_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFile {
    version: u32,
    requester: String,
    requests: Vec<RawRequest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    kind: String,
    value: Value,
    reason: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    writable: Option<bool>,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestApproval {
    pub(crate) requester: String,
    pub(crate) kind: String,
    pub(crate) value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) writable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<u16>,
}

#[derive(Clone, Debug)]
pub(crate) struct WrapperRequest {
    pub(crate) approval: RequestApproval,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RequestSet {
    pub(crate) items: Vec<WrapperRequest>,
}

#[derive(Serialize)]
pub(crate) struct Capabilities {
    version: &'static str,
    schema_version: u32,
    flags: &'static [&'static str],
    request_kinds: &'static [&'static str],
    features: Features,
    exit_codes: ExitCodes,
}

#[derive(Serialize)]
pub(crate) struct StatusReport {
    version: &'static str,
    schema_version: u32,
    project: StatusProject,
    harnesses: Vec<StatusHarness>,
    grants: StatusGrants,
    requests: StatusRequests,
    blockers: Vec<StatusBlocker>,
}

pub(crate) struct StatusInput<'a> {
    pub(crate) project: &'a Path,
    pub(crate) policy_path: &'a Path,
    pub(crate) profile_present: bool,
    pub(crate) onboarding_complete: bool,
    pub(crate) harnesses: &'a [String],
    pub(crate) config: &'a crate::config::Config,
    pub(crate) requests: &'a RequestSet,
    pub(crate) approved: &'a [RequestApproval],
    pub(crate) blockers: Vec<(String, String)>,
}

#[derive(Serialize)]
struct StatusProject {
    canonical_path: String,
    policy_path: String,
    profile_present: bool,
}

#[derive(Serialize)]
struct StatusHarness {
    name: String,
    onboarding_complete: bool,
}

#[derive(Serialize)]
struct StatusGrants {
    restricted: Vec<String>,
    allowed: Vec<String>,
    open: Vec<String>,
}

#[derive(Serialize)]
struct StatusRequests {
    approved: Vec<RequestApproval>,
    pending: Vec<RequestApproval>,
}

#[derive(Serialize)]
struct StatusBlocker {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct Features {
    harness_flag: bool,
    request_file: bool,
    status_json: bool,
    secret_private_http: bool,
    configure_requests: bool,
    inside_marker: bool,
}

#[derive(Serialize)]
struct ExitCodes {
    cancelled: i32,
    required_grant: i32,
    blocked: i32,
    backend_unavailable: i32,
}

impl Capabilities {
    pub(crate) fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            schema_version: SCHEMA_VERSION,
            flags: &["--harness", "--request-file", "--request", "--json"],
            request_kinds: &[
                "private_host",
                "host",
                "env",
                "secret",
                "agent_state",
                "map",
            ],
            features: Features {
                harness_flag: true,
                request_file: true,
                status_json: true,
                secret_private_http: true,
                configure_requests: true,
                // Linux support is added separately when the backend can
                // provide a mount that cannot be spoofed from outside.
                inside_marker: false,
            },
            exit_codes: ExitCodes {
                cancelled: 130,
                required_grant: EXIT_REQUIRED_GRANT,
                blocked: EXIT_BLOCKED,
                backend_unavailable: EXIT_BACKEND_UNAVAILABLE,
            },
        }
    }
}

impl StatusReport {
    pub(crate) fn build(input: StatusInput<'_>) -> Self {
        let StatusInput {
            project,
            policy_path,
            profile_present,
            onboarding_complete,
            harnesses,
            config,
            requests,
            approved,
            blockers,
        } = input;
        let mut restricted = Vec::new();
        let mut allowed = Vec::new();
        let mut open = Vec::new();
        if config.network == Some(true) {
            open.push("unrestricted_network".into());
        } else {
            restricted.push("unrestricted_network".into());
        }
        if !config.allow_hosts.is_empty() {
            allowed.push("filtered_hosts".into());
        }
        if !config.allow_private_hosts.is_empty() {
            open.push("private_hosts".into());
        }
        if onboarding_complete && config.agent_state_enabled() {
            allowed.push("agent_state".into());
        } else {
            restricted.push("agent_state".into());
        }
        if !config.ro_maps.is_empty() {
            allowed.push("read_only_directories".into());
        }
        if !config.rw_maps.is_empty() {
            allowed.push("read_write_directories".into());
        }
        if !config.env_pass.is_empty() {
            open.push("environment_variables".into());
        }
        for (name, enabled) in [
            ("full_ssh", config.ssh_enabled()),
            ("full_github", config.github_enabled()),
            ("inherit_environment", config.inherit_env_enabled()),
        ] {
            if enabled {
                open.push(name.into());
            } else {
                restricted.push(name.into());
            }
        }
        let pending = requests
            .pending(approved)
            .into_iter()
            .map(|request| request.approval.clone())
            .collect();
        let approved_current = requests
            .items
            .iter()
            .filter(|request| approved.contains(&request.approval))
            .map(|request| request.approval.clone())
            .collect();
        Self {
            version: env!("CARGO_PKG_VERSION"),
            schema_version: SCHEMA_VERSION,
            project: StatusProject {
                canonical_path: project.to_string_lossy().into_owned(),
                policy_path: policy_path.to_string_lossy().into_owned(),
                profile_present,
            },
            harnesses: harnesses
                .iter()
                .map(|name| StatusHarness {
                    name: name.clone(),
                    onboarding_complete,
                })
                .collect(),
            grants: StatusGrants {
                restricted,
                allowed,
                open,
            },
            requests: StatusRequests {
                approved: approved_current,
                pending,
            },
            blockers: blockers
                .into_iter()
                .map(|(code, message)| StatusBlocker { code, message })
                .collect(),
        }
    }
}

impl RequestSet {
    pub(crate) fn load(
        files: &[PathBuf],
        inline: &[String],
        project: &Path,
    ) -> Result<Self, String> {
        let mut items = Vec::new();
        for path in files {
            items.extend(load_file(path, project)?);
        }
        for spec in inline {
            let (kind, value) = spec
                .split_once('=')
                .ok_or_else(|| "--request requires KIND=VALUE".to_string())?;
            items.push(normalize(
                "command-line",
                RawRequest {
                    kind: kind.into(),
                    value: Value::String(value.into()),
                    reason: "requested by the invoking wrapper".into(),
                    host: None,
                    writable: None,
                },
            )?);
        }
        let mut seen = BTreeSet::new();
        items.retain(|request| seen.insert(request.approval.clone()));
        Ok(Self { items })
    }

    pub(crate) fn pending<'a>(
        &'a self,
        approved: &[RequestApproval],
    ) -> Vec<&'a WrapperRequest> {
        self.items
            .iter()
            .filter(|request| !approved.contains(&request.approval))
            .collect()
    }

    pub(crate) fn apply_approved_runtime(
        &self,
        approved: &[RequestApproval],
        config: &mut crate::config::Config,
    ) {
        for request in &self.items {
            if !approved.contains(&request.approval) {
                continue;
            }
            let approval = &request.approval;
            if approval.kind == "secret" {
                if !config.env_pass.iter().any(|entry| {
                    entry == &approval.value
                        || entry.starts_with(&format!("{}=", approval.value))
                }) {
                    config.env_pass.push(approval.value.clone());
                }
                if let Some(host) = &approval.host {
                    config
                        .secret_hosts
                        .insert(approval.value.clone(), host.clone());
                }
            }
        }
    }
}

fn load_file(
    path: &Path,
    project: &Path,
) -> Result<Vec<WrapperRequest>, String> {
    if !path.is_absolute() {
        return Err("--request-file must be an absolute path".into());
    }
    let canonical_project = project.canonicalize().map_err(|e| {
        format!("Cannot resolve project path {}: {e}", project.display())
    })?;
    let canonical = path.canonicalize().map_err(|e| {
        format!("Cannot resolve request file {}: {e}", path.display())
    })?;
    if canonical.starts_with(&canonical_project) {
        return Err(
            "--request-file must live outside the project checkout".into()
        );
    }
    if std::fs::symlink_metadata(path)
        .map_err(|e| {
            format!("Cannot inspect request file {}: {e}", path.display())
        })?
        .file_type()
        .is_symlink()
    {
        return Err("--request-file cannot be a symlink".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&canonical)
        .map_err(|e| {
            format!("Cannot open request file {}: {e}", canonical.display())
        })?;
    let metadata = file.metadata().map_err(|e| {
        format!("Cannot inspect request file {}: {e}", canonical.display())
    })?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err("--request-file must be a user-owned, non-hard-linked regular file that is not group/world writable".into());
    }
    if metadata.len() > MAX_REQUEST_FILE_BYTES {
        return Err("--request-file exceeds the 64 KiB limit".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|e| {
        format!("Cannot read request file {}: {e}", canonical.display())
    })?;
    let document: RequestFile =
        serde_json::from_slice(&bytes).map_err(|e| {
            format!("Invalid request file {}: {e}", canonical.display())
        })?;
    if document.version != SCHEMA_VERSION {
        return Err(format!(
            "Unsupported request-file version {}; expected {}",
            document.version, SCHEMA_VERSION
        ));
    }
    validate_requester(&document.requester)?;
    if document.requests.len() > 128 {
        return Err("--request-file contains more than 128 requests".into());
    }
    document
        .requests
        .into_iter()
        .map(|request| normalize(&document.requester, request))
        .collect()
}

fn normalize(
    requester: &str,
    raw: RawRequest,
) -> Result<WrapperRequest, String> {
    validate_requester(requester)?;
    validate_text("reason", &raw.reason, 256)?;
    let kind = raw.kind.to_ascii_lowercase();
    let (value, host, writable, port) = match kind.as_str() {
        "private_host" | "host" => {
            let value = string_value(&raw.value, &kind)?;
            let (host, port) = split_host_port(&value)?;
            (host, None, None, port)
        }
        "env" => {
            let value = string_value(&raw.value, &kind)?;
            (value, None, None, None)
        }
        "secret" => {
            let value = string_value(&raw.value, &kind)?;
            let host = raw
                .host
                .ok_or_else(|| "secret request requires host".to_string())?;
            validate_host(&host)?;
            (value, Some(host.to_ascii_lowercase()), None, None)
        }
        "agent_state" => {
            if raw.value != Value::Bool(true) {
                return Err("agent_state request value must be true".into());
            }
            ("true".into(), None, None, None)
        }
        "map" => {
            let value = string_value(&raw.value, &kind)?;
            if !Path::new(&value).is_absolute() {
                return Err("map request value must be an absolute path".into());
            }
            (value, None, Some(raw.writable.unwrap_or(false)), None)
        }
        _ => return Err(format!("Unsupported wrapper request kind {kind:?}")),
    };
    if kind == "env" || kind == "secret" {
        crate::onboarding::validate_env_name(&value)?;
    }
    if kind == "host" || kind == "private_host" {
        validate_host(&value)?;
    }
    Ok(WrapperRequest {
        approval: RequestApproval {
            requester: requester.into(),
            kind,
            value,
            host,
            writable,
            port,
        },
        reason: raw.reason,
    })
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>), String> {
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        validate_host(host)?;
        let port = port.parse::<u16>().map_err(|_| {
            format!("Invalid wrapper-request port in {value:?}")
        })?;
        if port == 0 {
            return Err("Wrapper-request port cannot be zero".into());
        }
        return Ok((host.to_ascii_lowercase(), Some(port)));
    }
    validate_host(value)?;
    Ok((value.to_ascii_lowercase(), None))
}

fn string_value(value: &Value, kind: &str) -> Result<String, String> {
    let value = value
        .as_str()
        .ok_or_else(|| format!("{kind} request value must be a string"))?;
    validate_text("request value", value, 1024)?;
    Ok(value.into())
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.contains("//")
        || host.contains('/')
        || host.contains(':')
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(format!("Invalid wrapper-request host {host:?}"));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|ch| {
            ch.is_control()
                || matches!(
                    ch,
                    '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        })
    {
        return Err(format!("Invalid wrapper-request {label}"));
    }
    Ok(())
}

fn validate_requester(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err("Invalid wrapper-request requester".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_secret_without_a_value() {
        let request = normalize(
            "ai-memory",
            RawRequest {
                kind: "secret".into(),
                value: Value::String("AI_MEMORY_AUTH_TOKEN".into()),
                reason: "memory server login".into(),
                host: Some("memory.example".into()),
                writable: None,
            },
        )
        .unwrap();
        assert_eq!(request.approval.value, "AI_MEMORY_AUTH_TOKEN");
        assert_eq!(request.approval.host.as_deref(), Some("memory.example"));
        assert!(!format!("{request:?}").contains("token-value"));
    }

    #[test]
    fn rejects_control_characters_in_reasons() {
        let error = normalize(
            "wrapper",
            RawRequest {
                kind: "host".into(),
                value: Value::String("example.com".into()),
                reason: "safe\nforged".into(),
                host: None,
                writable: None,
            },
        )
        .unwrap_err();
        assert!(error.contains("reason"));
    }

    #[test]
    fn approval_identity_is_exact_and_changed_ports_are_pending() {
        let request = normalize(
            "wrapper",
            RawRequest {
                kind: "private_host".into(),
                value: Value::String("memory.example:49374".into()),
                reason: "memory server".into(),
                host: None,
                writable: None,
            },
        )
        .unwrap();
        let requests = RequestSet {
            items: vec![request.clone()],
        };
        assert!(
            requests
                .pending(std::slice::from_ref(&request.approval))
                .is_empty()
        );
        let mut changed = request.approval;
        changed.port = Some(49375);
        assert_eq!(requests.pending(&[changed]).len(), 1);
    }

    #[test]
    fn status_labels_private_hosts_and_full_credentials_as_open() {
        let config = crate::config::Config {
            allow_private_hosts: vec!["memory.example".into()],
            github: Some(true),
            ..crate::config::Config::default()
        };
        let report = StatusReport::build(StatusInput {
            project: Path::new("/project"),
            policy_path: Path::new("/project"),
            profile_present: true,
            onboarding_complete: true,
            harnesses: &["claude".into()],
            config: &config,
            requests: &RequestSet::default(),
            approved: &[],
            blockers: Vec::new(),
        });
        let json = serde_json::to_value(report).unwrap();
        let open = json["grants"]["open"].as_array().unwrap();
        assert!(open.iter().any(|grant| grant == "private_hosts"));
        assert!(open.iter().any(|grant| grant == "full_github"));
    }

    #[test]
    fn documentation_tracks_the_v1_machine_contract() {
        let guide = include_str!("../docs/WRAPPER_INTEGRATION.md");
        for required in [
            "ai-jail capabilities --json",
            "--harness",
            "--request-file",
            "status --json",
            "secret_private_http",
            "inside_marker",
            "required_grant_not_approved",
            "missing_approved_env",
            "directory_drift",
            "changed_ssh_key",
            "backend_unavailable",
            "`--no-save-config` suppresses profile and project-constraint auto-save",
            "A request is never a grant",
            "authorizes the named host on any requested TCP port",
            "private host is OPEN",
            "The real value is not put in",
        ] {
            assert!(
                guide.contains(required),
                "missing contract text: {required}"
            );
        }
    }
}
