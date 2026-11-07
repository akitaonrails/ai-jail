//! First-run access review for known AI harnesses.

use crate::config::Config;
use crate::output::escape_control_bytes;
use nix::sys::termios::{self, SetArg, Termios};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

mod tui;

// Stable provenance identifiers stay available to contract tests and
// documentation without leaking into the human-facing TUI.
#[allow(dead_code)]
pub(crate) mod messages {
    pub const INTRO_ID: &str = "AJ-ONB-001";
    pub const CHOICE_ID: &str = "AJ-CHOICE-001";
    pub const GRANT_ID: &str = "AJ-GRANT-001";
    pub const OPEN_ID: &str = "AJ-OPEN-001";
    pub const PRESET_ID: &str = "AJ-PRESET-001";
    pub const SUMMARY_ID: &str = "AJ-SUM-001";
    pub const SAVE_ID: &str = "AJ-SAVE-001";
    pub const CANCEL_ID: &str = "AJ-CANCEL-001";
    pub const NON_TTY_ID: &str = "AJ-NONTTY-001";
    pub const CONFIG_NON_TTY_ID: &str = "AJ-NONTTY-002";
    pub const FINAL_ID: &str = "AJ-FINAL-001";
    pub const PATH_REFUSED_ID: &str = "AJ-PATH-001";
    pub const CREDENTIAL_PATH_ID: &str = "AJ-PATH-002";
    pub const PATH_IDENTITY_ID: &str = "AJ-PATH-003";
    pub const PATH_DRIFT_ID: &str = "AJ-PATH-004";
    pub const ENV_ID: &str = "AJ-ENV-001";
    pub const ENV_MISSING_ID: &str = "AJ-ENV-002";
    pub const SSH_ID: &str = "AJ-SSH-001";
    pub const SSH_SCOPE_ID: &str = "AJ-SSH-002";
    pub const SSH_DRIFT_ID: &str = "AJ-SSH-003";
    pub const SSH_NETWORK_ID: &str = "AJ-SSH-004";
    pub const POLICY_SHARED_ID: &str = "AJ-PROJ-001";

    pub const INTRO: &str = "Choose the access this project needs.";
    pub const POLICY_SHARED: &str =
        "shared with its linked worktrees (project_strategy = \"repo-root\")";
    pub const CANCEL: &str = "Onboarding cancelled. No onboarding grants were saved and the harness was not started. A completed legacy migration is not rolled back.";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Risk {
    Allowed,
    Open,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AdditionalSelection {
    /// The user reviewed this capability set, so disabled rows are explicit
    /// constraints rather than absent preferences.
    pub explicit: bool,
    pub share_host_home: bool,
    pub lockdown: bool,
    pub systemd_user: bool,
    pub gpu: bool,
    pub tailscale: bool,
    pub display: bool,
    pub audio: bool,
    pub kvm: bool,
    pub x11: bool,
    pub host_shm: bool,
    pub terminal_passthrough: bool,
    pub aws: bool,
    pub kube: bool,
    pub gcloud: bool,
    pub docker_config: bool,
    pub macos_host_ipc: bool,
    pub macos_chromium: bool,
    pub macos_trustd: bool,
    pub allow_pty: bool,
    pub allow_loopback_listen: bool,
    pub inherit_env: bool,
    pub worktree: bool,
    pub pictures: bool,
    pub audit_log: bool,
}

impl AdditionalSelection {
    pub(crate) fn any_enabled(&self) -> bool {
        self.share_host_home
            || self.lockdown
            || self.systemd_user
            || self.gpu
            || self.tailscale
            || self.display
            || self.audio
            || self.kvm
            || self.x11
            || self.host_shm
            || self.terminal_passthrough
            || self.aws
            || self.kube
            || self.gcloud
            || self.docker_config
            || self.macos_host_ipc
            || self.macos_chromium
            || self.macos_trustd
            || self.allow_pty
            || self.allow_loopback_listen
            || self.inherit_env
            || self.worktree
            || self.pictures
            || self.audit_log
    }

    fn from_config(config: &Config) -> Self {
        Self {
            explicit: true,
            share_host_home: !config.private_home_enabled(),
            lockdown: config.lockdown_enabled(),
            systemd_user: config.systemd_user_enabled(),
            gpu: config.gpu_enabled(),
            tailscale: config.tailscale_enabled(),
            display: config.display_enabled(),
            audio: config.audio_enabled(),
            kvm: config.kvm_enabled(),
            x11: config.x11_enabled(),
            host_shm: config.host_shm_enabled(),
            terminal_passthrough: config.terminal_passthrough_enabled(),
            aws: config.aws_enabled(),
            kube: config.kube_enabled(),
            gcloud: config.gcloud_enabled(),
            docker_config: config.docker_config_enabled(),
            macos_host_ipc: config.macos_host_ipc_enabled(),
            macos_chromium: config.macos_chromium_enabled(),
            macos_trustd: config.macos_trustd_enabled(),
            allow_pty: config.allow_pty_enabled(),
            allow_loopback_listen: config.allow_loopback_listen_enabled(),
            inherit_env: config.inherit_env_enabled(),
            worktree: config.worktree_enabled(),
            pictures: config.pictures_enabled(),
            audit_log: config.audit_log_enabled(),
        }
    }

    fn apply_to(&self, config: &mut Config) {
        if self.explicit {
            // A CLOSED reviewed choice must constrain a broader global policy
            // rather than disappear as an unset field.
            config.private_home = Some(!self.share_host_home);
            config.lockdown = Some(self.lockdown);
            config.systemd_user = Some(self.systemd_user);
            config.no_gpu = Some(!self.gpu);
            config.tailscale = Some(self.tailscale);
            config.no_display = Some(!self.display);
            config.audio = Some(self.audio);
            config.kvm = Some(self.kvm);
            config.x11 = Some(self.x11);
            config.host_shm = Some(self.host_shm);
            config.terminal_passthrough = Some(self.terminal_passthrough);
            config.aws = Some(self.aws);
            config.kube = Some(self.kube);
            config.gcloud = Some(self.gcloud);
            config.docker_config = Some(self.docker_config);
            config.macos_host_ipc = Some(self.macos_host_ipc);
            config.macos_chromium = Some(self.macos_chromium);
            config.macos_trustd = Some(self.macos_trustd);
            config.allow_pty = Some(self.allow_pty);
            config.allow_loopback_listen = Some(self.allow_loopback_listen);
            config.inherit_env = Some(self.inherit_env);
            config.no_worktree = Some(!self.worktree);
            config.pictures = Some(self.pictures);
            config.audit_log = Some(self.audit_log);
            return;
        }
        // Programmatic/default selections may still opt in without silently
        // overriding unrelated restrictive global policy.
        config.private_home = self.share_host_home.then_some(false);
        config.lockdown = self.lockdown.then_some(true);
        config.systemd_user = self.systemd_user.then_some(true);
        config.no_gpu = self.gpu.then_some(false);
        config.tailscale = self.tailscale.then_some(true);
        config.no_display = self.display.then_some(false);
        config.audio = self.audio.then_some(true);
        config.kvm = self.kvm.then_some(true);
        config.x11 = self.x11.then_some(true);
        config.host_shm = self.host_shm.then_some(true);
        config.terminal_passthrough = self.terminal_passthrough.then_some(true);
        config.aws = self.aws.then_some(true);
        config.kube = self.kube.then_some(true);
        config.gcloud = self.gcloud.then_some(true);
        config.docker_config = self.docker_config.then_some(true);
        config.macos_host_ipc = self.macos_host_ipc.then_some(true);
        config.macos_chromium = self.macos_chromium.then_some(true);
        config.macos_trustd = self.macos_trustd.then_some(true);
        config.allow_pty = self.allow_pty.then_some(true);
        config.allow_loopback_listen =
            self.allow_loopback_listen.then_some(true);
        config.inherit_env = self.inherit_env.then_some(true);
        config.no_worktree = self.worktree.then_some(false);
        config.pictures = self.pictures.then_some(true);
        config.audit_log = self.audit_log.then_some(true);
    }
}

/// All authority disclosures use this type. A grant cannot be rendered
/// without naming every security-relevant dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GrantSpec {
    pub resource: String,
    pub access: String,
    pub process: String,
    pub duration: String,
    pub scope: String,
    pub limits: String,
    pub default: String,
    pub consequence: String,
    pub remote: Option<String>,
    pub authority: Option<String>,
    pub risk: Risk,
}

impl GrantSpec {
    pub(crate) fn render(&self) -> String {
        let mut lines = vec![
            "Access grant".to_string(),
            format!("Resource:    {}", self.resource),
            format!("Access:      {}", self.access),
            format!("Process:     {}", self.process),
            format!("Duration:    {}", self.duration),
            format!("Scope:       {}", self.scope),
            format!("Limits:      {}", self.limits),
            format!("Default:     {}", self.default),
            format!("Consequence: {}", self.consequence),
        ];
        if let Some(remote) = &self.remote {
            lines.push(format!("Remote:      {remote}"));
        }
        if let Some(authority) = &self.authority {
            lines.push(format!("Authority:   {authority}"));
        }
        lines.join("\n")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Selection {
    pub api_access: bool,
    pub agent_state: bool,
    pub dependency_hosts: bool,
    pub ssh: bool,
    pub github: bool,
    pub container_engine: bool,
    pub unrestricted_network: bool,
    pub loopback_connect: bool,
    pub ro_dirs: Vec<PathBuf>,
    pub rw_dirs: Vec<PathBuf>,
    pub env_names: Vec<String>,
    pub requested_hosts: Vec<String>,
    pub requested_private_hosts: Vec<String>,
    pub requested_secrets: std::collections::BTreeMap<String, String>,
    pub restricted_ssh: Option<crate::ssh_restricted::Policy>,
    pub additional: AdditionalSelection,
}

impl Selection {
    fn apply_recommended_developer_baseline(&mut self, harness: &str) {
        self.api_access = !api_hosts(harness).is_empty();
        self.agent_state = true;
        self.dependency_hosts = true;
        self.github = true;
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            agent_state: config.agent_state_enabled(),
            api_access: config.network == Some(true)
                || (config.network != Some(false)
                    && crate::sandbox::unprivileged_netns_available()),
            dependency_hosts: config.toolchains_enabled(),
            ssh: config.ssh_enabled(),
            github: config.github_enabled(),
            container_engine: config.docker_enabled(),
            unrestricted_network: config.network == Some(true),
            loopback_connect: config.allow_loopback_connect_enabled(),
            ro_dirs: config.ro_maps.clone(),
            rw_dirs: config.rw_maps.clone(),
            env_names: Vec::new(),
            requested_hosts: Vec::new(),
            requested_private_hosts: Vec::new(),
            requested_secrets: std::collections::BTreeMap::new(),
            restricted_ssh: None,
            additional: AdditionalSelection::from_config(config),
        }
    }

    fn from_project_grants(
        config: &Config,
        harness: &str,
        approved_env_names: &[String],
        restricted_ssh: Option<&crate::ssh_restricted::Policy>,
    ) -> Self {
        Self {
            agent_state: config.agent_state == Some(true),
            api_access: config.network == Some(true)
                || api_hosts(harness).iter().any(|host| {
                    config.allow_hosts.iter().any(|allowed| allowed == host)
                }),
            dependency_hosts: config.no_toolchains == Some(false),
            ssh: config.ssh == Some(true),
            github: config.github == Some(true),
            container_engine: config.no_docker == Some(false),
            unrestricted_network: config.network == Some(true),
            loopback_connect: config.allow_loopback_connect == Some(true),
            ro_dirs: config.ro_maps.clone(),
            rw_dirs: config.rw_maps.clone(),
            env_names: approved_env_names.to_vec(),
            requested_hosts: config
                .allow_hosts
                .iter()
                .filter(|host| !api_hosts(harness).contains(&host.as_str()))
                .cloned()
                .collect(),
            requested_private_hosts: config.allow_private_hosts.clone(),
            requested_secrets: config.secret_hosts.clone(),
            restricted_ssh: restricted_ssh.cloned(),
            additional: AdditionalSelection::from_config(config),
        }
    }

    pub(crate) fn grants(&self, harness: &str) -> Config {
        self.grants_for(&[harness.to_string()])
    }

    pub(crate) fn grants_for(&self, harnesses: &[String]) -> Config {
        let mut allow_hosts = self.requested_hosts.clone();
        // Unrestricted network already reaches the model API, and the launcher
        // refuses --network combined with any filtered host.
        if self.api_access && !self.unrestricted_network {
            for harness in harnesses {
                for host in api_hosts(harness) {
                    if !allow_hosts.iter().any(|existing| existing == host) {
                        allow_hosts.push((*host).into());
                    }
                }
            }
        }
        let mut grants = Config {
            runtime_harnesses: harnesses.to_vec(),
            ro_maps: self.ro_dirs.clone(),
            rw_maps: self.rw_dirs.clone(),
            agent_state: Some(self.agent_state),
            no_mise: Some(!self.dependency_hosts),
            no_toolchains: Some(!self.dependency_hosts),
            ssh: Some(self.ssh),
            github: Some(self.github),
            no_docker: Some(!self.container_engine),
            network: self.unrestricted_network.then_some(true),
            allow_loopback_connect: self.loopback_connect.then_some(true),
            allow_hosts,
            allow_private_hosts: self.requested_private_hosts.clone(),
            secret_hosts: self.requested_secrets.clone(),
            ..Config::default()
        };
        self.additional.apply_to(&mut grants);
        grants
    }

    fn profile(&self, harness: &str) -> ProposedProfile {
        self.profile_for(&[harness.to_string()])
    }

    fn profile_for(&self, harnesses: &[String]) -> ProposedProfile {
        let mut grants = self.grants_for(harnesses);
        grants.env_pass = self.env_names.clone();
        ProposedProfile {
            grants,
            approved_env_names: self.env_names.clone(),
            approved_wrapper_requests: Vec::new(),
            finalized: None,
            directory_grants: Vec::new(),
            restricted_ssh: self.restricted_ssh.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProposedProfile {
    pub(crate) grants: Config,
    pub(crate) approved_env_names: Vec<String>,
    pub(crate) approved_wrapper_requests:
        Vec<crate::integration::RequestApproval>,
    pub(crate) finalized: Option<crate::FinalizedLaunch>,
    pub(crate) directory_grants:
        Vec<crate::config_store::DirectoryGrantIdentity>,
    pub(crate) restricted_ssh: Option<crate::ssh_restricted::Policy>,
}

#[derive(Debug)]
pub(crate) enum Outcome {
    SaveAndLaunch(ProposedProfile),
    LaunchOnce(ProposedProfile),
    SaveOnly(ProposedProfile),
    Cancel,
}

pub(crate) struct EffectiveContext<'a> {
    pub(crate) global: &'a Config,
    pub(crate) cli: &'a crate::cli::CliArgs,
    pub(crate) constraints: &'a Config,
    pub(crate) trusted_constraints: bool,
    pub(crate) approved_env_names: &'a [String],
    pub(crate) restricted_ssh: Option<&'a crate::ssh_restricted::Policy>,
    pub(crate) requests: &'a crate::integration::RequestSet,
    pub(crate) approved_wrapper_requests:
        &'a [crate::integration::RequestApproval],
    pub(crate) store: &'a crate::config_store::StorePaths,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct PreparedDisplay {
    pub(crate) allowed: String,
    pub(crate) open: String,
    pub(crate) effective_access: String,
    pub(crate) has_open_authority: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedProfile {
    pub(crate) profile: ProposedProfile,
    #[cfg(test)]
    pub(crate) display: PreparedDisplay,
}

pub(crate) fn prepare_profile(
    selection: &Selection,
    _harness: &str,
    harnesses: &[String],
    project: &Path,
    approved_wrapper_requests: &[crate::integration::RequestApproval],
    effective: &EffectiveContext<'_>,
) -> Result<PreparedProfile, String> {
    let mut proposed = selection.profile_for(harnesses);
    proposed.approved_wrapper_requests = approved_wrapper_requests.to_vec();
    proposed.directory_grants = crate::config_store::capture_directory_grants(
        &proposed.grants,
        effective.store.policy_root(),
    )?;
    crate::materialize_approved_env_names(&proposed.approved_env_names, false)?;
    let base = crate::build_onboarding_effective(
        effective.global.clone(),
        proposed.grants.clone(),
        effective.cli,
        effective.constraints.clone(),
        project,
        effective.trusted_constraints,
    )?;
    let mut finalized = crate::finalize_launch_config_with_ssh(
        base,
        project,
        effective.cli.dry_run,
        if effective.cli.ssh == Some(false) {
            None
        } else {
            proposed.restricted_ssh.clone()
        },
    )?;
    let forge_preview =
        if effective.cli.clean || finalized.config.lockdown_enabled() {
            None
        } else {
            crate::forge_auth::authority_preview(effective.store)?
        };
    finalized.reviewed_forge =
        crate::ReviewedForge::Reviewed(forge_preview.clone());
    #[cfg(test)]
    let display = {
        let summary = summary_text(selection, _harness, project, None);
        let (_, grouped) =
            summary.split_once("[LOCK] RESTRICTED\n").ok_or_else(|| {
                "Cannot group restricted review disclosure".to_string()
            })?;
        let (_restricted, grouped) =
            grouped.split_once("\n[WARN] ALLOWED\n").ok_or_else(|| {
                "Cannot group allowed review disclosure".to_string()
            })?;
        let (allowed, open) = grouped
            .split_once("\n[ERROR] OPEN\n")
            .ok_or_else(|| "Cannot group OPEN review disclosure".to_string())?;
        let mut allowed = allowed.trim().to_string();
        let mut open = open.trim().to_string();
        let mut effective_access = render_effective_access(
            &finalized.config,
            project,
            _harness,
            None,
            &selection.env_names,
        )?;
        if let Some(preview) = &forge_preview {
            let line = preview.summary_line();
            if preview.is_open() {
                if open == "None" {
                    open.clear();
                }
                if !open.is_empty() {
                    open.push('\n');
                }
                open.push_str(&line);
            } else {
                allowed.push_str(&format!("\n{line}"));
            }
            effective_access.push_str(&format!(
                "\nForge authority reviewed before launch:\n{line}"
            ));
        }
        PreparedDisplay {
            allowed,
            open,
            effective_access,
            has_open_authority: effective_has_open_authority(
                &finalized.config,
                project,
            )? || forge_preview
                .as_ref()
                .is_some_and(|preview| preview.is_open()),
        }
    };
    proposed.finalized = Some(finalized);
    Ok(PreparedProfile {
        profile: proposed,
        #[cfg(test)]
        display,
    })
}

fn process_label(harness: &str) -> String {
    format!("{harness} and every child process it starts inside this jail")
}

fn project_grant(
    project: &Path,
    harness: &str,
    saved: Option<bool>,
) -> GrantSpec {
    GrantSpec {
        resource: safe_path(project).unwrap_or_else(|_| "[invalid path refused]".into()),
        access: "Read and write the complete directory tree".into(),
        process: process_label(harness),
        duration: duration(saved),
        scope: "This canonical project path only".into(),
        limits: "Readable project data can be sent to an allowed network destination".into(),
        default: "Allowed because this is the working project".into(),
        consequence: "The harness can inspect, create, modify, rename, and delete project files".into(),
        remote: None,
        authority: None,
        risk: Risk::Allowed,
    }
}

fn api_grant(harness: &str, hosts: &[&str], saved: Option<bool>) -> GrantSpec {
    let host_list = hosts.join(", ");
    GrantSpec {
        resource: format!("TCP connections to {host_list} and their subdomains"),
        access: "Connect to any requested TCP port through the filtered proxy".into(),
        process: process_label(harness),
        duration: duration(saved),
        scope: "Public addresses for this hostname; private and loopback addresses stay blocked".into(),
        limits: "TLS contents are opaque; allowed endpoints can receive readable jail data".into(),
        default: "Enabled by the first-run For developers preset for known harnesses".into(),
        consequence: "The harness can send prompts and readable data to this API".into(),
        remote: Some(format!("Services operating under {host_list}")),
        authority: None,
        risk: Risk::Allowed,
    }
}

fn directory_grant(
    path: &Path,
    write: bool,
    harness: &str,
    saved: Option<bool>,
) -> GrantSpec {
    GrantSpec {
        resource: safe_path(path).unwrap_or_else(|_| "[invalid path refused]".into()),
        access: if write {
            "Read and write the complete directory tree"
        } else {
            "Read the complete directory tree; writes are denied"
        }
        .into(),
        process: process_label(harness),
        duration: duration(saved),
        scope: "This resolved directory tree only".into(),
        limits: if write {
            "The harness can delete or corrupt these files; readable data can leave through allowed network access"
        } else {
            "Contents can be copied into the project or sent to an allowed network destination"
        }
        .into(),
        default: "Not shared".into(),
        consequence: if write {
            "The harness can inspect, create, modify, rename, and delete files here"
        } else {
            "The harness can inspect these host files but cannot modify them through this grant"
        }
        .into(),
        remote: None,
        authority: None,
        risk: Risk::Allowed,
    }
}

fn classified_directory_grant(
    path: &Path,
    write: bool,
    harness: &str,
    project: &Path,
    saved: Option<bool>,
) -> GrantSpec {
    let mut grant = directory_grant(path, write, harness, saved);
    if broad_directory(path, project) {
        grant.risk = Risk::Open;
        grant.scope =
            "The complete selected ancestor tree, except mandatory ai-jail masks"
                .into();
        grant.limits = "This can expose unrelated personal files and credentials; mandatory ai-jail credential and policy-store masks still apply"
            .into();
        grant.consequence = if write {
            "The harness can inspect, create, modify, rename, and delete unrelated host files in this tree"
        } else {
            "The harness can inspect unrelated host files in this tree and copy readable data through allowed network access"
        }
        .into();
    }
    grant
}

#[derive(Clone, Debug)]
pub(crate) struct DirectoryCandidate {
    pub(crate) entered: String,
    pub(crate) resolved: PathBuf,
    pub(crate) write: bool,
    pub(crate) grant: GrantSpec,
}

pub(crate) fn list_directory(
    directory: &Path,
) -> Result<(PathBuf, Vec<(PathBuf, String)>), String> {
    let resolved = std::fs::canonicalize(directory).map_err(|error| {
        format!(
            "Cannot open directory {}: {error}",
            safe_path(directory).unwrap_or_else(|_| "[unsafe path]".into())
        )
    })?;
    if !resolved.is_dir() {
        return Err(format!("{} is not a directory", safe_path(&resolved)?));
    }
    let resolved_label = safe_path(&resolved)?;
    let mut entries = std::fs::read_dir(&resolved)
        .map_err(|error| format!("Cannot read {resolved_label}: {error}"))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            path.is_dir().then(|| {
                let name =
                    escape_control_bytes(&entry.file_name().to_string_lossy());
                (path, name)
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.1.cmp(&right.1));
    Ok((resolved, entries))
}

pub(crate) fn prepare_directory_candidate(
    entered: &Path,
    write: bool,
    selection: &Selection,
    harness: &str,
    project: &Path,
) -> Result<DirectoryCandidate, String> {
    let entered_label = safe_path(entered)?;
    let resolved = std::fs::canonicalize(entered).map_err(|error| {
        format!("Cannot resolve directory {entered_label}: {error}")
    })?;
    if !resolved.is_dir() {
        return Err(format!("{} is not a directory", safe_path(&resolved)?));
    }
    if resolved.as_os_str().as_bytes().contains(&b':') {
        return Err(
            "Directory paths containing ':' cannot be stored safely".into()
        );
    }
    if resolved == Path::new("/") {
        return Err(
            "The sandbox cannot share the filesystem root. Choose a narrower directory"
                .into(),
        );
    }
    reject_credential_root(&resolved)?;
    if selection
        .ro_dirs
        .iter()
        .chain(&selection.rw_dirs)
        .any(|path| {
            path != &resolved
                && (path.starts_with(&resolved) || resolved.starts_with(path))
        })
    {
        return Err(
            "Overlapping directory grants must be removed before changing scope"
                .into(),
        );
    }
    Ok(DirectoryCandidate {
        entered: entered_label,
        resolved: resolved.clone(),
        write,
        grant: classified_directory_grant(
            &resolved, write, harness, project, None,
        ),
    })
}

pub(crate) fn apply_directory_candidate(
    selection: &mut Selection,
    candidate: &DirectoryCandidate,
) {
    selection.ro_dirs.retain(|path| path != &candidate.resolved);
    selection.rw_dirs.retain(|path| path != &candidate.resolved);
    if candidate.write {
        selection.rw_dirs.push(candidate.resolved.clone());
        selection.rw_dirs.sort();
        selection.rw_dirs.dedup();
    } else {
        selection.ro_dirs.push(candidate.resolved.clone());
        selection.ro_dirs.sort();
        selection.ro_dirs.dedup();
    }
}

pub(crate) fn remove_directory_grant(
    selection: &mut Selection,
    path: &Path,
    write: bool,
) {
    if write {
        selection.rw_dirs.retain(|candidate| candidate != path);
    } else {
        selection.ro_dirs.retain(|candidate| candidate != path);
    }
}

fn state_grant(harness: &str, saved: Option<bool>) -> GrantSpec {
    let vars: Vec<&str> = crate::command::harness_api_key_env(harness)
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .collect();
    let key_note = if vars.is_empty() {
        String::new()
    } else {
        format!(" and detected host key(s) {}", vars.join(", "))
    };
    let state = match harness {
        "claude" => {
            "~/.claude and ~/.claude.json; on macOS, Claude credential lookup"
        }
        "codex" => "~/.codex",
        "gemini" => "~/.gemini",
        "opencode" => "~/.config/opencode and ~/.local/share/opencode",
        "crush" => "~/.crush, ~/.config/crush, and ~/.local/share/crush",
        "grok" => "~/.grok",
        "devin" => {
            "the effective Devin XDG state and configuration directories"
        }
        name if name.starts_with("kimi") => "~/.kimi and ~/.kimi-code",
        _ => "the command-specific host state paths",
    };
    GrantSpec {
        resource: format!("The host {harness} state at {state}{key_note}"),
        access: "Read and write harness state; read and use detected API-key environment values".into(),
        process: process_label(harness),
        duration: format!("{}; key values are never saved by ai-jail", duration(saved)),
        scope: "The command-specific state paths and detected well-known API-key variables".into(),
        limits: "Readable sessions or keys can be copied; writes can change host-side harness state".into(),
        default: "Enabled by the first-run For developers preset; Fully closed leaves it private".into(),
        consequence: "The harness starts with the host login and may modify its host-side state".into(),
        remote: None,
        authority: Some("The accounts and service limits carried by the exposed login or keys".into()),
        risk: Risk::Allowed,
    }
}

fn dependency_grant(harness: &str, saved: Option<bool>) -> GrantSpec {
    GrantSpec {
        resource: format!(
            "Jail-owned dependency caches and filtered connections to {}",
            crate::sandbox::TOOLCHAIN_REGISTRY_HOSTS.join(", ")
        ),
        access: "Read toolchain binaries, write isolated caches, and connect to the named hosts".into(),
        process: process_label(harness),
        duration: format!("{}; jail-owned caches persist across runs", duration(saved)),
        scope: "Jail-owned caches and the listed public hostnames plus their subdomains".into(),
        limits: "Downloaded packages execute inside the jail; allowed endpoints can receive readable jail data".into(),
        default: "Enabled by the first-run For developers preset; Fully closed disables it".into(),
        consequence: "Build tools can download dependencies without accessing the host's real caches".into(),
        remote: Some("Services operating under the listed dependency hosts".into()),
        authority: None,
        risk: Risk::Allowed,
    }
}

fn env_grant(name: &str, harness: &str) -> GrantSpec {
    GrantSpec {
        resource: format!("Host environment variable {} (value hidden)", escape_control_bytes(name)),
        access: "Read and use the current host value; the value is never displayed or saved by ai-jail".into(),
        process: process_label(harness),
        duration: duration(None),
        scope: "This exact variable name; the current value is read again for each launch".into(),
        limits: "Every jailed descendant can read and copy the value; allowed network access can carry it outside the jail".into(),
        default: "Arbitrary host variables are not shared; the documented safe baseline remains available".into(),
        consequence: "The harness and every child process can use or disclose the current value".into(),
        remote: None,
        authority: Some(if secret_env_name(name) {
            "The name looks credential-bearing; its authority cannot be verified without exposing the value"
        } else {
            "The authority of an arbitrary host value cannot be verified from its name"
        }.into()),
        // A harmless-looking name may still hold a credential or sensitive
        // data. Every non-baseline host value therefore needs explicit OPEN.
        risk: Risk::Open,
    }
}

pub(crate) fn validate_env_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic());
    if !valid_start
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(format!(
            "Invalid environment variable name {}; assignments, NUL bytes, and non-portable names are refused",
            escape_control_bytes(name)
        ));
    }
    Ok(())
}

fn secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let tokens = upper.split('_').collect::<Vec<_>>();
    tokens.iter().any(|token| {
        matches!(
            *token,
            "TOKEN"
                | "SECRET"
                | "PASSWORD"
                | "PASSWD"
                | "KEY"
                | "CRED"
                | "CREDENTIAL"
                | "CREDENTIALS"
                | "AUTH"
                | "COOKIE"
                | "SESSION"
                | "BEARER"
                | "SIGNING"
                | "CERT"
                | "CERTIFICATE"
        )
    }) || tokens.first().is_some_and(|token| {
        matches!(*token, "AWS" | "GH" | "GITHUB" | "GOOGLE" | "AZURE")
    })
}

fn open_env_entry(entry: &str) -> bool {
    entry != "MISE_NOT_FOUND_AUTO_INSTALL=false"
        && !crate::ssh_restricted::is_runtime_env(entry)
        && !crate::forge_auth::is_runtime_env(entry)
}

fn open_grant(kind: &str, harness: &str, saved: Option<bool>) -> GrantSpec {
    let process = process_label(harness);
    match kind {
        "ssh" => GrantSpec {
            resource: "~/.ssh and the ambient SSH_AUTH_SOCK".into(),
            access: "Read every SSH file and request signatures from every loaded agent identity".into(),
            process,
            duration: duration(saved),
            scope: "Any reachable SSH destination and every identity exposed by the host agent".into(),
            limits: "Read-only private key files can still be copied; signatures are not destination-scoped".into(),
            default: "Not shared unless explicitly selected; Mostly open enables it".into(),
            consequence: "Jailed processes may impersonate the host user to SSH services".into(),
            remote: None,
            authority: Some("Every account accepted by an exposed key".into()),
            risk: Risk::Open,
        },
        "github" => GrantSpec {
            resource: "The effective host gh configuration and active github.com token".into(),
            access: "Read configuration and use the token for GitHub API and Git HTTPS operations".into(),
            process,
            duration: duration(saved),
            scope: "Every repository and organization allowed by the active host token".into(),
            limits: "Read-only configuration does not restrict use or copying of the token".into(),
            default: "Enabled by the first-run For developers preset; otherwise not shared unless explicitly selected".into(),
            consequence: "Jailed processes can act with the host token's complete GitHub authority".into(),
            remote: Some("github.com and api.github.com when network policy permits".into()),
            authority: Some("Every permission granted to the active github.com token".into()),
            risk: Risk::Open,
        },
        "container-engine" => GrantSpec {
            resource: "The host Docker or Podman daemon socket".into(),
            access: "Send unrestricted container-engine API requests through the mounted Unix socket".into(),
            process,
            duration: duration(saved),
            scope: "Every container, image, volume, network, and host path the selected daemon can access".into(),
            limits: "Rootless engines reduce operating-system privilege but still expose that daemon user's files and services".into(),
            default: "Closed; no container-engine socket is shared by any preset".into(),
            consequence: "A jailed process can create privileged containers or mount host paths, bypassing the jail's filesystem boundary".into(),
            remote: None,
            authority: Some("Effectively the complete authority of the Docker or Podman daemon owner".into()),
            risk: Risk::Open,
        },
        "loopback-connect" => GrantSpec {
            resource: "Every service listening on the host loopback interface".into(),
            access: "Connect to every localhost TCP service from the macOS jail".into(),
            process,
            duration: duration(saved),
            scope: "ALL host loopback services on every port".into(),
            limits: "macOS only; does not permit non-loopback destinations".into(),
            default: "No host loopback service is reachable except a specifically forwarded port".into(),
            consequence: "Jailed processes can access unauthenticated or locally trusted host services".into(),
            remote: Some("localhost on the host, all ports".into()),
            authority: Some("Every service that trusts localhost callers".into()),
            risk: Risk::Open,
        },
        _ => GrantSpec {
            resource: "The host's reachable network".into(),
            access: "Connect using any protocol and destination permitted by the host".into(),
            process,
            duration: duration(saved),
            scope: "Public, private, local-network, and other host-reachable services".into(),
            limits: "Hostname filtering and destination audit enforcement no longer apply".into(),
            default: "Filtered to explicitly allowed hosts".into(),
            consequence: "Any readable jail data can be sent to any reachable service".into(),
            remote: Some("Any reachable service".into()),
            authority: None,
            risk: Risk::Open,
        },
    }
}

fn restricted_ssh_grant(
    policy: &crate::ssh_restricted::Policy,
    harness: &str,
    saved: Option<bool>,
) -> GrantSpec {
    let fingerprints = policy
        .keys
        .iter()
        .map(|key| escape_control_bytes(&key.fingerprint))
        .collect::<Vec<_>>()
        .join(", ");
    let constrained = !policy.destinations.is_empty();
    GrantSpec {
        resource: format!("Fresh SSH agent containing only {fingerprints}"),
        access: "Request signatures; private key files and the ambient agent stay outside the jail".into(),
        process: process_label(harness),
        duration: format!(
            "Agent lives for this jail; loaded keys expire after {} seconds; {}",
            policy.lifetime_seconds,
            duration(saved)
        ),
        scope: if constrained {
            format!(
                "Only verified destination constraints: {}",
                policy.destinations.join(", ")
            )
        } else {
            "Incomplete: no destination constraint; launch and save are refused"
                .into()
        },
        limits: if constrained {
            "Destination constraints depend on OpenSSH support and verified known_hosts entries; unrestricted network is separately OPEN; failure refuses launch".into()
        } else {
            "No raw selected-key agent is exposed without an enforced OpenSSH destination constraint".into()
        },
        default: "Disabled until keys are selected in trusted configuration".into(),
        consequence: "The harness can authenticate as accounts accepted by the selected keys during this jail run".into(),
        remote: constrained.then(|| policy.destinations.join(", ")),
        authority: Some("Only accounts accepted by the selected fingerprints".into()),
        risk: Risk::Allowed,
    }
}

fn duration(saved: Option<bool>) -> String {
    match saved {
        Some(true) => {
            "While each jail runs; approval remains saved for this project"
        }
        Some(false) => "This jail run only; no approval is saved",
        None => {
            "This jail run; saving keeps approval for later runs, while launch once does not"
        }
    }
    .into()
}

fn api_hosts(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude" => &["api.anthropic.com"],
        "codex" => &["api.openai.com", "chatgpt.com"],
        "gemini" => &["generativelanguage.googleapis.com"],
        "grok" => &["api.x.ai"],
        "devin" => &["server.codeium.com"],
        _ => &[],
    }
}

pub(crate) fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

pub(crate) fn secure_noninteractive(
    config: &mut Config,
    cli: &crate::cli::CliArgs,
) {
    apply_secure_defaults(config, cli);
    eprintln!(
        "[WARN] Interactive setup skipped because no terminal is attached.\n  Running once with restricted defaults; no profile was saved.\n  Use `ai-jail configure {}` in a terminal to review or save access.",
        crate::command::effective_name(&config.command).unwrap_or("HARNESS")
    );
}

pub(crate) fn apply_secure_defaults(
    config: &mut Config,
    cli: &crate::cli::CliArgs,
) {
    if cli.agent_state.is_none() {
        config.agent_state = Some(false);
    }
    if cli.toolchains.is_none() {
        config.no_toolchains = Some(true);
    }
    if cli.ssh.is_none() {
        config.ssh = Some(false);
    }
    if cli.github.is_none() {
        config.github = Some(false);
    }
}

fn initial_selection(
    existing: &Config,
    harness: &str,
    approved_env_names: &[String],
    restricted_ssh: Option<&crate::ssh_restricted::Policy>,
    use_recommended_defaults: bool,
) -> Selection {
    let mut selection = Selection::from_project_grants(
        existing,
        harness,
        approved_env_names,
        restricted_ssh,
    );
    if use_recommended_defaults {
        selection.apply_recommended_developer_baseline(harness);
    }
    selection
}

/// The policy root, only when it differs from the launch directory.
pub(crate) fn shared_policy_root<'a>(
    project: &Path,
    store: &'a crate::config_store::StorePaths,
) -> Option<&'a Path> {
    let root = store.policy_root();
    (root != project && root != store.canonical_project).then_some(root)
}

fn plain_header(
    harness: &str,
    project: &Path,
    policy_root: Option<&Path>,
) -> Result<String, String> {
    let mut header = format!(
        "\nConfigure {harness} for this project\n\nProject: {}\n",
        safe_path(project)?
    );
    if let Some(root) = policy_root {
        header.push_str(&format!(
            "Policy:  {} \u{b7} {}\n",
            safe_path(root)?,
            messages::POLICY_SHARED
        ));
    }
    Ok(header)
}

pub(crate) fn run(
    harness: &str,
    project: &Path,
    existing: &Config,
    configure_only: bool,
    use_recommended_defaults: bool,
    effective: EffectiveContext<'_>,
) -> Result<Outcome, String> {
    if !is_interactive() {
        return Err(format!(
            "`ai-jail configure {harness}` needs an interactive terminal. No configuration was changed."
        ));
    }
    let mut selection = initial_selection(
        existing,
        harness,
        effective.approved_env_names,
        effective.restricted_ssh,
        use_recommended_defaults,
    );
    let harnesses = if effective.cli.harnesses.is_empty() {
        vec![harness.to_string()]
    } else {
        effective.cli.harnesses.clone()
    };
    let policy_root = shared_policy_root(project, effective.store);
    eprintln!("{}", plain_header(harness, project, policy_root)?);
    eprintln!("{}\n", messages::INTRO);
    if std::env::var_os("TERM").is_some_and(|value| value == "dumb") {
        let approved_wrapper_requests = review_wrapper_requests(
            &mut selection,
            effective.requests,
            effective.approved_wrapper_requests,
            harness,
            project,
        )?;
        return run_sequential(
            selection,
            harness,
            project,
            configure_only,
            &effective,
            approved_wrapper_requests,
        );
    }

    tui::run_app(
        &mut selection,
        harness,
        project,
        effective.requests,
        effective.approved_wrapper_requests,
        tui::RunOptions {
            configure_only,
            recommended_baseline: use_recommended_defaults,
            profile_path: &effective.store.project,
            policy_root,
        },
        |current, approved| {
            prepare_profile(
                current, harness, &harnesses, project, approved, &effective,
            )
        },
    )
}

fn review_wrapper_requests(
    selection: &mut Selection,
    requests: &crate::integration::RequestSet,
    existing: &[crate::integration::RequestApproval],
    harness: &str,
    project: &Path,
) -> Result<Vec<crate::integration::RequestApproval>, String> {
    if requests.items.is_empty() {
        return Ok(existing.to_vec());
    }
    for approval in existing {
        revoke_wrapper_request(selection, approval);
    }
    let mut approved = Vec::new();
    eprintln!(
        "Wrapper-staged access requests. Prior wrapper-derived access was removed from this draft; approve each request again or re-enable overlapping manual access explicitly."
    );
    for request in &requests.items {
        let approval = &request.approval;
        eprintln!(
            "  requested by {}: {}",
            escape_control_bytes(&approval.requester),
            escape_control_bytes(&request.reason)
        );
        let resource = if approval.kind == "secret" {
            format!(
                "secret variable {} bound to {} (value stays hidden)",
                escape_control_bytes(&approval.value),
                escape_control_bytes(approval.host.as_deref().unwrap_or(""))
            )
        } else {
            let value = match approval.port {
                Some(port) => format!("{}:{port}", approval.value),
                None => approval.value.clone(),
            };
            format!(
                "{} {}",
                escape_control_bytes(&approval.kind),
                escape_control_bytes(&value)
            )
        };
        eprintln!("  Resource: {resource}");
        let prepared =
            prepare_wrapper_request(approval, selection, harness, project)?;
        eprintln!("{}\n", prepared.grant().render());
        let accepted = if prepared.grant().risk == Risk::Open {
            open_confirmation(&prompt(
                "  Type OPEN exactly to approve this staged access: ",
            )?)
        } else {
            let answer = prompt("  Approve this staged access? [y/N/q] ")?;
            if answer.eq_ignore_ascii_case("q") {
                return Err("Wrapper request review cancelled".into());
            }
            answer.eq_ignore_ascii_case("y")
        };
        if accepted {
            apply_wrapper_request(selection, &prepared);
            approved.push(approval.clone());
        }
    }
    eprintln!();
    Ok(approved)
}

#[derive(Clone, Debug)]
pub(crate) enum PreparedWrapperRequest {
    Direct {
        approval: crate::integration::RequestApproval,
        grant: GrantSpec,
    },
    Directory {
        approval: crate::integration::RequestApproval,
        candidate: DirectoryCandidate,
    },
}

impl PreparedWrapperRequest {
    pub(crate) fn grant(&self) -> &GrantSpec {
        match self {
            Self::Direct { grant, .. } => grant,
            Self::Directory { candidate, .. } => &candidate.grant,
        }
    }

    fn approval(&self) -> &crate::integration::RequestApproval {
        match self {
            Self::Direct { approval, .. }
            | Self::Directory { approval, .. } => approval,
        }
    }
}

pub(crate) fn revoke_wrapper_request(
    selection: &mut Selection,
    request: &crate::integration::RequestApproval,
) {
    match request.kind.as_str() {
        "host" => selection
            .requested_hosts
            .retain(|value| value != &request.value),
        "private_host" => selection
            .requested_private_hosts
            .retain(|value| value != &request.value),
        "env" => remove_env_name(selection, &request.value),
        "secret" => {
            remove_env_name(selection, &request.value);
            selection.requested_secrets.remove(&request.value);
        }
        "agent_state" => selection.agent_state = false,
        "map" => {
            let presented = PathBuf::from(&request.value);
            let current = std::fs::canonicalize(&presented).ok();
            let had_directory_authority =
                !selection.ro_dirs.is_empty() || !selection.rw_dirs.is_empty();
            let traverses_symlink = {
                let mut prefix = PathBuf::new();
                presented.components().any(|component| {
                    prefix.push(component);
                    std::fs::symlink_metadata(&prefix)
                        .is_ok_and(|metadata| metadata.file_type().is_symlink())
                })
            };
            if traverses_symlink && had_directory_authority {
                selection.ro_dirs.clear();
                selection.rw_dirs.clear();
                return;
            }
            let matches_request = |candidate: &PathBuf| {
                candidate == &presented
                    || current
                        .as_ref()
                        .is_some_and(|resolved| candidate == resolved)
            };
            let matched = selection.ro_dirs.iter().any(matches_request)
                || selection.rw_dirs.iter().any(matches_request);
            if matched {
                selection
                    .ro_dirs
                    .retain(|candidate| !matches_request(candidate));
                selection
                    .rw_dirs
                    .retain(|candidate| !matches_request(candidate));
            } else if had_directory_authority {
                // Older approvals do not carry the canonical path that was
                // actually persisted. If the presented path drifted or
                // disappeared, retaining any additional map could preserve
                // the wrapper-derived authority under an unmatchable name.
                selection.ro_dirs.clear();
                selection.rw_dirs.clear();
            }
        }
        _ => {}
    }
}

pub(crate) fn prepare_wrapper_request(
    request: &crate::integration::RequestApproval,
    selection: &Selection,
    harness: &str,
    project: &Path,
) -> Result<PreparedWrapperRequest, String> {
    let direct = |grant| PreparedWrapperRequest::Direct {
        approval: request.clone(),
        grant,
    };
    match request.kind.as_str() {
        "host" | "private_host" => {
            let private = request.kind == "private_host";
            let port_note = request.port.map_or_else(
                || "any requested TCP port".to_string(),
                |port| format!(
                    "any requested TCP port; the wrapper requested port {port}, but the saved host grant is not port-limited"
                ),
            );
            Ok(direct(GrantSpec {
                resource: format!(
                    "TCP connections to {}",
                    escape_control_bytes(&request.value)
                ),
                access: if private {
                    "Connect through the filtered proxy, including private address ranges"
                } else {
                    "Connect through the filtered proxy; private and loopback addresses remain blocked"
                }
                .into(),
                process: process_label(harness),
                duration: duration(None),
                scope: format!(
                    "This exact normalized host; {port_note}"
                ),
                limits: if private {
                    "Metadata, link-local, and loopback addresses remain blocked; the named host can still reach private services"
                } else {
                    "DNS is pinned by the filtered proxy and private address ranges remain blocked"
                }
                .into(),
                default: "Not shared unless this staged request is approved".into(),
                consequence: "Readable jail data can be sent to this destination".into(),
                remote: Some(format!(
                    "Services operating under {}",
                    escape_control_bytes(&request.value)
                )),
                authority: private.then(|| {
                    "Private-capable network access can reach services that are not public"
                        .into()
                }),
                risk: if private { Risk::Open } else { Risk::Allowed },
            }))
        }
        "env" => Ok(direct(prepare_env_candidate(&request.value, harness)?)),
        "secret" => {
            let mut grant = prepare_env_candidate(&request.value, harness)?;
            let host = request
                .host
                .as_deref()
                .ok_or_else(|| "secret request has no host".to_string())?;
            grant.scope = format!(
                "This exact variable name, bound to filtered destination {}",
                escape_control_bytes(host)
            );
            grant.remote = Some(format!(
                "Services operating under {}",
                escape_control_bytes(host)
            ));
            Ok(direct(grant))
        }
        "agent_state" => Ok(direct(state_grant(harness, None))),
        "map" => Ok(PreparedWrapperRequest::Directory {
            approval: request.clone(),
            candidate: prepare_directory_candidate(
                Path::new(&request.value),
                request.writable.unwrap_or(false),
                selection,
                harness,
                project,
            )?,
        }),
        kind => Err(format!("Unsupported wrapper request kind {kind:?}")),
    }
}

pub(crate) fn apply_wrapper_request(
    selection: &mut Selection,
    prepared: &PreparedWrapperRequest,
) {
    if let PreparedWrapperRequest::Directory { candidate, .. } = prepared {
        apply_directory_candidate(selection, candidate);
        return;
    }
    let request = prepared.approval();
    match request.kind.as_str() {
        "host" => push_unique(&mut selection.requested_hosts, &request.value),
        "private_host" => {
            push_unique(&mut selection.requested_private_hosts, &request.value)
        }
        "env" => apply_env_name(selection, request.value.clone()),
        "secret" => {
            apply_env_name(selection, request.value.clone());
            selection.requested_secrets.insert(
                request.value.clone(),
                request.host.clone().expect("prepared secret has a host"),
            );
        }
        "agent_state" => selection.agent_state = true,
        _ => unreachable!("prepared wrapper kind"),
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn run_sequential(
    mut selection: Selection,
    harness: &str,
    project: &Path,
    configure_only: bool,
    effective: &EffectiveContext<'_>,
    approved_wrapper_requests: Vec<crate::integration::RequestApproval>,
) -> Result<Outcome, String> {
    eprintln!(
        "Plain-terminal mode: each access choice is reviewed in order.\n"
    );
    let Some(review) =
        review_choice("Review filtered model API access? [y/N/q] ")?
    else {
        return Ok(Outcome::Cancel);
    };
    if review {
        toggle_allowed(
            &mut selection.api_access,
            &api_grant(harness, api_hosts(harness), None),
        )?;
    }
    let Some(review) =
        review_choice("Review host harness login/state? [y/N/q] ")?
    else {
        return Ok(Outcome::Cancel);
    };
    if review {
        toggle_allowed(
            &mut selection.agent_state,
            &state_grant(harness, None),
        )?;
    }
    let Some(review) =
        review_choice("Review dependency tools and download hosts? [y/N/q] ")?
    else {
        return Ok(Outcome::Cancel);
    };
    if review {
        toggle_allowed(
            &mut selection.dependency_hosts,
            &dependency_grant(harness, None),
        )?;
    }
    let Some(review) =
        review_choice("Configure selected-key SSH (fresh agent)? [y/N/q] ")?
    else {
        return Ok(Outcome::Cancel);
    };
    if review {
        edit_restricted_ssh(&mut selection)?;
    }
    for (label, field, kind) in [
        ("full host SSH", &mut selection.ssh, "ssh"),
        ("full host GitHub token", &mut selection.github, "github"),
        (
            "host Docker/Podman daemon",
            &mut selection.container_engine,
            "container-engine",
        ),
        (
            "unrestricted network",
            &mut selection.unrestricted_network,
            "network",
        ),
        (
            "all host loopback services",
            &mut selection.loopback_connect,
            "loopback-connect",
        ),
    ] {
        let Some(review) =
            review_choice(&format!("Review {label} (OPEN)? [y/N/q] "))?
        else {
            return Ok(Outcome::Cancel);
        };
        if review {
            toggle_open(field, kind, harness)?;
        }
    }
    if selection.ssh {
        selection.restricted_ssh = None;
    }
    loop {
        match prompt("Additional directory: read-only [r], read/write [w], done [Enter], cancel [q]: ")?.as_str() {
            "r" => {
                if let Err(error) = add_directory(&mut selection, false, harness, project) { eprintln!("[ERROR] {error}"); }
            }
            "w" => {
                if let Err(error) = add_directory(&mut selection, true, harness, project) { eprintln!("[ERROR] {error}"); }
            }
            "q" => return Ok(Outcome::Cancel),
            _ => break,
        }
    }
    let Some(review) =
        review_choice("Review host environment variables? [y/N/q] ")?
    else {
        return Ok(Outcome::Cancel);
    };
    if review {
        edit_environment(&mut selection, harness)?;
    }
    render_summary(&selection, harness, project, true);
    let mut proposed = selection.profile(harness);
    proposed.approved_wrapper_requests = approved_wrapper_requests;
    proposed.directory_grants = crate::config_store::capture_directory_grants(
        &proposed.grants,
        effective.store.policy_root(),
    )?;
    crate::materialize_approved_env_names(&proposed.approved_env_names, false)?;
    let base = crate::build_onboarding_effective(
        effective.global.clone(),
        proposed.grants.clone(),
        effective.cli,
        effective.constraints.clone(),
        project,
        effective.trusted_constraints,
    )?;
    let finalized = crate::finalize_launch_config_with_ssh(
        base,
        project,
        effective.cli.dry_run,
        if effective.cli.ssh == Some(false) {
            None
        } else {
            proposed.restricted_ssh.clone()
        },
    )?;
    eprintln!(
        "{}",
        render_effective_access(
            &finalized.config,
            project,
            harness,
            None,
            &selection.env_names,
        )?
    );
    if effective_has_open_authority(&finalized.config, project)?
        && !open_confirmation(&prompt(
            "Complete effective access contains OPEN authority. Type OPEN to continue: ",
        )?)
    {
        return Ok(Outcome::Cancel);
    }
    proposed.finalized = Some(finalized);
    if configure_only {
        return if prompt("Save this project profile? [y/N] ")?
            .eq_ignore_ascii_case("y")
        {
            Ok(Outcome::SaveOnly(proposed))
        } else {
            Ok(Outcome::Cancel)
        };
    }
    match prompt("Save and launch [s], launch once [o], cancel [q]: ")?.as_str()
    {
        "s" => Ok(Outcome::SaveAndLaunch(proposed)),
        "o" => Ok(Outcome::LaunchOnce(proposed)),
        _ => Ok(Outcome::Cancel),
    }
}

fn toggle_allowed(value: &mut bool, grant: &GrantSpec) -> Result<(), String> {
    if *value {
        *value = false;
        return Ok(());
    }
    eprintln!("\n{}\n", grant.render());
    if prompt("Enable this grant? [y/N] ")?.eq_ignore_ascii_case("y") {
        *value = true;
    }
    Ok(())
}

fn edit_restricted_ssh(selection: &mut Selection) -> Result<(), String> {
    eprintln!(
        "\nSelected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared."
    );
    if let Some(policy) = &selection.restricted_ssh {
        eprintln!("Selected identities:");
        for (index, key) in policy.keys.iter().enumerate() {
            eprintln!(
                "  {}. {}  {}  {}",
                index + 1,
                safe_path(&key.public_path)?,
                escape_control_bytes(&key.fingerprint),
                escape_control_bytes(&key.comment)
            );
        }
        eprintln!(
            "Lifetime: {} seconds; destinations: {}",
            policy.lifetime_seconds,
            if policy.destinations.is_empty() {
                "not configured (launch and save are refused)".into()
            } else {
                policy.destinations.join(", ")
            }
        );
    }
    match prompt("Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: ")?.as_str() {
        "a" => {
            let available = discover_public_ssh_keys();
            if !available.is_empty() {
                eprintln!("Available file-backed identities:");
                for (index, key) in available.iter().enumerate() {
                    eprintln!(
                        "  {}. {}  {}  {}",
                        index + 1,
                        safe_path(&key.public_path)?,
                        escape_control_bytes(&key.fingerprint),
                        escape_control_bytes(&key.comment)
                    );
                }
            }
            let choice = prompt("Key number, private-key path, or .pub path: ")?;
            let key = choice
                .parse::<usize>()
                .ok()
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| available.get(index).cloned())
                .map(Ok)
                .unwrap_or_else(|| {
                    crate::ssh_restricted::capture_key(Path::new(&choice))
                })?;
            let mut policy = selection.restricted_ssh.take().unwrap_or(crate::ssh_restricted::Policy {
                keys: Vec::new(),
                lifetime_seconds: crate::ssh_restricted::DEFAULT_LIFETIME_SECONDS,
                destinations: Vec::new(),
            });
            if !policy.keys.iter().any(|item| item.fingerprint == key.fingerprint) {
                policy.keys.push(key);
            }
            selection.restricted_ssh = Some(policy);
            selection.ssh = false;
        }
        "r" => {
            if let Some(policy) = &mut selection.restricted_ssh {
                let index = prompt("Key number to remove: ")?
                    .parse::<usize>()
                    .map_err(|_| "Key number must be numeric".to_string())?;
                if index == 0 || index > policy.keys.len() {
                    return Err("Key number is out of range".into());
                }
                policy.keys.remove(index - 1);
                if policy.keys.is_empty() {
                    selection.restricted_ssh = None;
                }
            }
        }
        "h" => {
            let value = prompt("Required destinations, comma-separated: ")?;
            if let Some(policy) = &mut selection.restricted_ssh {
                let destinations = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let mut candidate = policy.clone();
                candidate.destinations = destinations;
                crate::ssh_restricted::validate_policy(&candidate)?;
                *policy = candidate;
            } else {
                eprintln!("[LOCK] Add a key before setting destinations.");
            }
        }
        "d" => selection.restricted_ssh = None,
        _ => {}
    }
    Ok(())
}

pub(crate) fn discover_public_ssh_keys()
-> Vec<crate::ssh_restricted::KeyIdentity> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    discover_public_ssh_keys_in(&PathBuf::from(home).join(".ssh"))
}

pub(crate) fn validate_ssh_destinations(
    mut destinations: Vec<String>,
) -> Result<Vec<String>, String> {
    destinations.sort();
    destinations.dedup();
    for destination in &destinations {
        crate::ssh_restricted::validate_destination(destination)?;
    }
    Ok(destinations)
}

pub(crate) fn validate_ssh_lifetime(seconds: u32) -> Result<u32, String> {
    if !(60..=86_400).contains(&seconds) {
        return Err(
            "Restricted SSH lifetime must be between 60 and 86400 seconds"
                .into(),
        );
    }
    Ok(seconds)
}

fn discover_public_ssh_keys_in(
    directory: &Path,
) -> Vec<crate::ssh_restricted::KeyIdentity> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut keys: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pub"))
        .filter_map(|path| crate::ssh_restricted::capture_key(&path).ok())
        .collect();
    keys.sort_by(|a, b| a.public_path.cmp(&b.public_path));
    keys
}

fn toggle_open(
    value: &mut bool,
    kind: &str,
    harness: &str,
) -> Result<(), String> {
    if *value {
        *value = false;
        return Ok(());
    }
    eprintln!("\nOPEN access removes an important boundary.\n");
    eprintln!("{}\n", open_grant(kind, harness, None).render());
    if open_confirmation(&prompt("Type OPEN to enable this exact grant: ")?) {
        *value = true;
    } else {
        eprintln!("Kept restricted.");
    }
    Ok(())
}

fn open_confirmation(value: &str) -> bool {
    value == "OPEN"
}

fn prompt(label: &str) -> Result<String, String> {
    eprint!("{label}");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    let read = io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok("q".into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn review_choice(label: &str) -> Result<Option<bool>, String> {
    let answer = prompt(label)?;
    if answer.eq_ignore_ascii_case("q") {
        Ok(None)
    } else {
        Ok(Some(answer.eq_ignore_ascii_case("y")))
    }
}

fn escape_tail() -> Result<Option<[u8; 2]>, String> {
    let stdin = io::stdin();
    let saved =
        termios::tcgetattr(&stdin).map_err(|error| error.to_string())?;
    let mut timed = saved.clone();
    timed.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 0;
    timed.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 1;
    termios::tcsetattr(&stdin, SetArg::TCSANOW, &timed)
        .map_err(|error| error.to_string())?;
    let mut sequence = [0u8; 2];
    let read = stdin
        .lock()
        .read(&mut sequence)
        .map_err(|error| error.to_string());
    let _ = termios::tcsetattr(&stdin, SetArg::TCSANOW, &saved);
    match read? {
        0 => Ok(None),
        2 => Ok(Some(sequence)),
        _ => Ok(None),
    }
}

struct RawModeGuard(Termios);

impl RawModeGuard {
    fn enter() -> Result<Self, String> {
        let stdin = io::stdin();
        let saved = termios::tcgetattr(&stdin).map_err(|e| e.to_string())?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &raw)
            .map_err(|e| e.to_string())?;
        Ok(Self(saved))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.0);
    }
}

fn directory_prompt() -> Result<String, String> {
    let _raw = RawModeGuard::enter()?;
    let mut value = String::new();
    eprint!("Directory (Tab completes; absolute path or ~/...): ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    loop {
        let mut byte = [0u8; 1];
        io::stdin()
            .read_exact(&mut byte)
            .map_err(|e| e.to_string())?;
        match byte[0] {
            b'\r' | b'\n' => {
                eprintln!("\r");
                return Ok(value);
            }
            3 | 27 => {
                eprintln!("\r");
                return Ok("q".into());
            }
            8 | 127 => {
                if value.pop().is_some() {
                    eprint!("\x08 \x08");
                    io::stderr().flush().map_err(|e| e.to_string())?;
                }
            }
            b'\t' => match complete_directories(&value) {
                Ok(candidates) if candidates.len() == 1 => {
                    value = safe_path(&candidates[0])?;
                    eprint!(
                        "\r\x1b[2KDirectory (Tab completes; absolute path or ~/...): {}",
                        escape_control_bytes(&value)
                    );
                    io::stderr().flush().map_err(|e| e.to_string())?;
                }
                Ok(candidates) if !candidates.is_empty() => {
                    eprintln!("\r");
                    for candidate in candidates {
                        eprintln!("  {}\r", safe_path(&candidate)?);
                    }
                    eprint!(
                        "Directory (Tab completes; absolute path or ~/...): {}",
                        escape_control_bytes(&value)
                    );
                    io::stderr().flush().map_err(|e| e.to_string())?;
                }
                _ => {}
            },
            b if b.is_ascii_graphic() || b == b' ' => {
                value.push(b as char);
                eprint!("{}", b as char);
                io::stderr().flush().map_err(|e| e.to_string())?;
            }
            first if first >= 0x80 => {
                let width = match first {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => {
                        return Err("Directory input is not valid UTF-8".into());
                    }
                };
                let mut encoded = vec![first];
                for _ in 1..width {
                    let mut continuation = [0u8; 1];
                    io::stdin()
                        .read_exact(&mut continuation)
                        .map_err(|e| e.to_string())?;
                    encoded.push(continuation[0]);
                }
                let text = std::str::from_utf8(&encoded)
                    .map_err(|_| "Directory input is not valid UTF-8")?;
                value.push_str(text);
                eprint!("{}", escape_control_bytes(text));
                io::stderr().flush().map_err(|error| error.to_string())?;
            }
            _ => {}
        }
    }
}

pub(crate) fn environment_name_catalog(selection: &Selection) -> Vec<String> {
    let mut names = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| validate_env_name(name).is_ok())
        .filter(|name| !crate::config::env_inherited_by_default(name))
        .collect::<Vec<_>>();
    names.extend(selection.env_names.iter().cloned());
    names.sort();
    names.dedup();
    names
}

pub(crate) fn prepare_env_candidate(
    name: &str,
    harness: &str,
) -> Result<GrantSpec, String> {
    validate_env_name(name)?;
    if std::env::var_os(name).is_none() {
        return Err(format!(
            "Host variable {} is not currently set; no approval was added",
            escape_control_bytes(name)
        ));
    }
    Ok(env_grant(name, harness))
}

pub(crate) fn apply_env_name(selection: &mut Selection, name: String) {
    selection.env_names.push(name);
    selection.env_names.sort();
    selection.env_names.dedup();
}

pub(crate) fn remove_env_name(selection: &mut Selection, name: &str) {
    selection.env_names.retain(|existing| existing != name);
}

fn choose_env_name(selection: &Selection) -> Result<Option<String>, String> {
    if std::env::var_os("TERM").is_some_and(|value| value == "dumb") {
        let name = prompt(
            "Environment variable name (value stays hidden; Enter returns): ",
        )?;
        if name.is_empty() || name == "q" {
            return Ok(None);
        }
        validate_env_name(&name)?;
        return Ok(Some(name));
    }
    let all = environment_name_catalog(selection);
    let _raw = RawModeGuard::enter()?;
    let mut filter = String::new();
    let mut selected = 0usize;
    loop {
        let matches = all
            .iter()
            .filter(|name| {
                name.to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
            })
            .collect::<Vec<_>>();
        selected = selected.min(matches.len().saturating_sub(1));
        eprintln!(
            "\rEnvironment names only. Type to filter; arrows move; Space/Enter selects for approval; q/Esc returns. Values are never shown.\r"
        );
        eprintln!("  Filter: {}\r", escape_control_bytes(&filter));
        for (index, name) in matches.iter().take(12).enumerate() {
            let cursor = if index == selected { '>' } else { ' ' };
            let mark = if selection.env_names.contains(name) {
                'x'
            } else {
                ' '
            };
            eprintln!("  {cursor} [{mark}] {}\r", escape_control_bytes(name));
        }
        let mut byte = [0u8; 1];
        io::stdin()
            .read_exact(&mut byte)
            .map_err(|e| e.to_string())?;
        match byte[0] {
            b'q' if filter.is_empty() => return Ok(None),
            b'\r' | b'\n' | b' ' if !matches.is_empty() => {
                return Ok(Some(matches[selected].clone()));
            }
            8 | 127 => {
                filter.pop();
                selected = 0;
            }
            0x1b => {
                let Some(sequence) = escape_tail()? else {
                    return Ok(None);
                };
                match sequence {
                    [b'[', b'A'] => selected = selected.saturating_sub(1),
                    [b'[', b'B'] => {
                        selected =
                            (selected + 1).min(matches.len().saturating_sub(1))
                    }
                    _ => return Ok(None),
                }
            }
            b if b.is_ascii_alphanumeric() || b == b'_' => {
                filter.push(b as char);
                selected = 0;
            }
            _ => {}
        }
    }
}

fn edit_environment(
    selection: &mut Selection,
    harness: &str,
) -> Result<(), String> {
    let Some(name) = choose_env_name(selection)? else {
        return Ok(());
    };
    validate_env_name(&name)?;
    if selection.env_names.contains(&name) {
        selection.env_names.retain(|existing| existing != &name);
        eprintln!(
            "[LOCK] Removed approval for {}",
            escape_control_bytes(&name)
        );
        return Ok(());
    }
    if std::env::var_os(&name).is_none() {
        return Err(format!(
            "Host variable {} is not currently set; no approval was added",
            escape_control_bytes(&name)
        ));
    }
    let grant = env_grant(&name, harness);
    eprintln!("\n{}\n", grant.render());
    let approved = if grant.risk == Risk::Open {
        open_confirmation(&prompt(&format!(
            "Host variable {} has unverifiable authority. Type OPEN to approve its name: ",
            escape_control_bytes(&name)
        ))?)
    } else {
        prompt("Approve this variable name? [y/N] ")?.eq_ignore_ascii_case("y")
    };
    if approved {
        selection.env_names.push(name);
        selection.env_names.sort();
    }
    Ok(())
}

fn add_directory(
    selection: &mut Selection,
    write: bool,
    harness: &str,
    project: &Path,
) -> Result<(), String> {
    let mut entered = if std::env::var_os("TERM").is_some_and(|v| v == "dumb") {
        prompt("Directory (absolute path or ~/...): ")?
    } else {
        directory_prompt()?
    };
    if entered.contains('\t') {
        let prefix = entered.replace('\t', "");
        let candidates = complete_directories(&prefix)?;
        if candidates.is_empty() {
            eprintln!("No matching directories.");
            entered = prompt("Directory: ")?;
        } else if candidates.len() == 1 {
            entered = safe_path(&candidates[0])?;
            eprintln!("Completed: {entered}");
        } else {
            for candidate in &candidates {
                eprintln!("  {}", safe_path(candidate)?);
            }
            entered = prompt("Directory: ")?;
        }
    }
    if entered == "q" || entered.is_empty() {
        return Ok(());
    }
    let expanded = expand_home(&entered)?;
    let expanded_label = safe_path(&expanded)?;
    let resolved = std::fs::canonicalize(&expanded).map_err(|e| {
        format!("Cannot resolve directory {expanded_label}: {e}")
    })?;
    if !resolved.is_dir() {
        return Err(format!("{} is not a directory", safe_path(&resolved)?));
    }
    if resolved.as_os_str().as_bytes().contains(&b':') {
        return Err(
            "Directory paths containing ':' cannot be stored safely".into()
        );
    }
    if resolved == Path::new("/") {
        return Err(
            "The sandbox cannot share the filesystem root. Choose a narrower directory"
                .into(),
        );
    }
    reject_credential_root(&resolved)?;
    if selection
        .ro_dirs
        .iter()
        .chain(&selection.rw_dirs)
        .any(|path| {
            path != &resolved
                && (path.starts_with(&resolved) || resolved.starts_with(path))
        })
    {
        return Err(
            "Overlapping directory grants must be removed before changing scope"
                .into(),
        );
    }
    eprintln!("Entered:  {}", escape_control_bytes(&entered));
    eprintln!("Resolved: {}\n", safe_path(&resolved)?);
    let grant =
        classified_directory_grant(&resolved, write, harness, project, None);
    if grant.risk == Risk::Open {
        eprintln!("OPEN: this path contains a broad host filesystem scope.");
    }
    eprintln!("{}\n", grant.render());
    if grant.risk == Risk::Open
        && !open_confirmation(&prompt("Type OPEN to add this path: ")?)
    {
        eprintln!("Kept restricted.");
        return Ok(());
    }
    if grant.risk == Risk::Allowed
        && !prompt("Add this directory? [y/N] ")?.eq_ignore_ascii_case("y")
    {
        return Ok(());
    }
    selection.ro_dirs.retain(|path| path != &resolved);
    selection.rw_dirs.retain(|path| path != &resolved);
    if write {
        selection.rw_dirs.push(resolved);
    } else {
        selection.ro_dirs.push(resolved);
    }
    Ok(())
}

#[allow(dead_code)] // Pure validation is retained for the upcoming TUI editor.
fn remove_directory(selection: &mut Selection) -> Result<(), String> {
    let entries: Vec<(bool, PathBuf)> = selection
        .ro_dirs
        .iter()
        .cloned()
        .map(|p| (false, p))
        .chain(selection.rw_dirs.iter().cloned().map(|p| (true, p)))
        .collect();
    if entries.is_empty() {
        eprintln!("No additional directories are shared.");
        return Ok(());
    }
    for (index, (write, path)) in entries.iter().enumerate() {
        eprintln!(
            "  {}. {} ({})",
            index + 1,
            safe_path(path)?,
            if *write { "read/write" } else { "read-only" }
        );
    }
    let choice = prompt("Remove number (Enter keeps all): ")?;
    let Ok(index) = choice.parse::<usize>() else {
        return Ok(());
    };
    let Some((write, path)) = entries.get(index.saturating_sub(1)) else {
        return Ok(());
    };
    if prompt("Remove this grant? [y/N] ")?.eq_ignore_ascii_case("y") {
        if *write {
            selection.rw_dirs.retain(|p| p != path);
        } else {
            selection.ro_dirs.retain(|p| p != path);
        }
    }
    Ok(())
}

fn expand_home(value: &str) -> Result<PathBuf, String> {
    if value == "~" || value.starts_with("~/") {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        return Ok(PathBuf::from(home).join(value.trim_start_matches("~/")));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("Directory must be absolute or start with ~/".into());
    }
    Ok(path)
}

fn reject_credential_root(path: &Path) -> Result<(), String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home else { return Ok(()) };
    reject_credential_root_for_home(path, &home)
}

fn reject_credential_root_for_home(
    path: &Path,
    home: &Path,
) -> Result<(), String> {
    if crate::authority_inventory::is_protected(path, home)? {
        return Err(format!(
            "Refusing credential-bearing path {}; use its dedicated access choice",
            safe_path(path)?
        ));
    }
    Ok(())
}

fn complete_directories(value: &str) -> Result<Vec<PathBuf>, String> {
    let expanded = expand_home(value)?;
    let (parent, prefix) = if expanded.is_dir() {
        (expanded.as_path(), "")
    } else {
        (
            expanded.parent().unwrap_or_else(|| Path::new("/")),
            expanded
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(""),
        )
    };
    let mut matches = Vec::new();
    let parent_label = safe_path(parent)?;
    for entry in std::fs::read_dir(parent)
        .map_err(|e| format!("Cannot list {parent_label}: {e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if !name_text.starts_with(prefix)
            || (name_text.starts_with('.') && !prefix.starts_with('.'))
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            matches.push(path);
        }
    }
    matches.sort();
    Ok(matches)
}

fn broad_directory(path: &Path, project: &Path) -> bool {
    std::env::var_os("HOME").is_some_and(|home| {
        let configured = PathBuf::from(home);
        let canonical =
            std::fs::canonicalize(&configured).unwrap_or(configured);
        path == canonical
    }) || (project.starts_with(path) && path != project)
}

pub(crate) fn render_summary(
    selection: &Selection,
    harness: &str,
    project: &Path,
    saved: bool,
) {
    eprintln!("{}", summary_text(selection, harness, project, Some(saved)));
}

pub(crate) fn summary_text(
    selection: &Selection,
    harness: &str,
    project: &Path,
    saved: Option<bool>,
) -> String {
    use std::fmt::Write as _;

    let mut output =
        format!("\nFinal access for {harness}\n\n[LOCK] RESTRICTED\n");
    if !selection.ssh && selection.restricted_ssh.is_none() {
        writeln!(
            output,
            "  SSH       No key files, host agent socket, or SSH configuration"
        )
        .expect("writing to String");
    }
    if selection
        .restricted_ssh
        .as_ref()
        .is_some_and(|policy| policy.destinations.is_empty())
    {
        writeln!(output,
            "  SSH       Selected identity is incomplete; add at least one verified destination before launch or save"
        ).expect("writing to String");
    }
    if !selection.github {
        writeln!(output, "  GitHub    No host gh configuration or token")
            .expect("writing to String");
    }
    writeln!(
        output,
        "  Host home See the complete effective access below"
    )
    .expect("writing to String");
    if !selection.api_access && !selection.dependency_hosts {
        writeln!(output, "  Network   All destinations are blocked")
            .expect("writing to String");
    } else if !selection.unrestricted_network {
        writeln!(output,
            "  Network   Every destination except the named API/dependency hosts"
        ).expect("writing to String");
    }
    write!(
        output,
        "\n[WARN] ALLOWED\n{}\n",
        project_grant(project, harness, saved).render()
    )
    .expect("writing to String");
    let hosts = api_hosts(harness);
    if selection.api_access && !hosts.is_empty() {
        write!(output, "\n{}\n", api_grant(harness, hosts, saved).render())
            .expect("writing to String");
    }
    if selection.agent_state {
        write!(output, "\n{}\n", state_grant(harness, saved).render())
            .expect("writing to String");
    }
    if selection.dependency_hosts {
        write!(output, "\n{}\n", dependency_grant(harness, saved).render())
            .expect("writing to String");
    }
    if let Some(policy) = &selection.restricted_ssh
        && !policy.destinations.is_empty()
    {
        write!(
            output,
            "\n{}\n",
            restricted_ssh_grant(policy, harness, saved).render()
        )
        .expect("writing to String");
    }
    for path in &selection.ro_dirs {
        if !broad_directory(path, project) {
            write!(
                output,
                "\n{}\n",
                classified_directory_grant(
                    path, false, harness, project, saved,
                )
                .render()
            )
            .expect("writing to String");
        }
    }
    for path in &selection.rw_dirs {
        if !broad_directory(path, project) {
            write!(
                output,
                "\n{}\n",
                classified_directory_grant(
                    path,
                    true,
                    harness,
                    project,
                    saved,
                )
                .render()
            )
            .expect("writing to String");
        }
    }
    output.push_str("\n[ERROR] OPEN\n");
    let mut any = false;
    for (enabled, kind) in [
        (selection.ssh, "ssh"),
        (selection.github, "github"),
        (selection.unrestricted_network, "network"),
        (selection.loopback_connect, "loopback-connect"),
    ] {
        if enabled {
            any = true;
            write!(output, "\n{}\n", open_grant(kind, harness, saved).render())
                .expect("writing to String");
        }
    }
    for (write, paths) in
        [(false, &selection.ro_dirs), (true, &selection.rw_dirs)]
    {
        for path in paths {
            if broad_directory(path, project) {
                any = true;
                write!(
                    output,
                    "\n{}\n",
                    classified_directory_grant(
                        path, write, harness, project, saved,
                    )
                    .render()
                )
                .expect("writing to String");
            }
        }
    }
    if !any {
        output.push_str("  None\n");
    }
    output
}

pub(crate) fn render_effective_access(
    config: &Config,
    project: &Path,
    harness: &str,
    saved: Option<bool>,
    approved_env_names: &[String],
) -> Result<String, String> {
    let project_label = safe_path(project)?;
    // Launch-scoped SSH paths contain a PID and sequence number. Show stable,
    // descriptive placeholders so the disclosure is readable and can be
    // compared byte-for-byte without hiding any user-controlled field.
    let mut display_config = config.clone();
    for (original, displayed) in config
        .rw_maps
        .iter()
        .zip(display_config.rw_maps.iter_mut())
        .chain(config.ro_maps.iter().zip(display_config.ro_maps.iter_mut()))
    {
        if crate::ssh_restricted::is_runtime_map(config, original)
            && let Ok(spec) = crate::config::MapSpec::parse(original)
        {
            let leaf = if spec.source.ends_with("agent.sock") {
                "agent.sock"
            } else {
                "public"
            };
            *displayed = crate::config::MapSpec {
                source: PathBuf::from(format!("<SSH-RUNTIME>/{leaf}")),
                destination: spec.destination,
            }
            .encode();
        }
    }
    for (original, displayed) in config
        .env_pass
        .iter()
        .zip(display_config.env_pass.iter_mut())
    {
        if !crate::ssh_restricted::is_runtime_env(original) {
            continue;
        }
        let Some((name, _)) = original.split_once('=') else {
            continue;
        };
        *displayed = match name {
            "SSH_AUTH_SOCK" => "SSH_AUTH_SOCK=<SSH-RUNTIME>/agent.sock".into(),
            "GIT_SSH_COMMAND" => {
                "GIT_SSH_COMMAND=<TRUSTED-SSH> -F <SSH-RUNTIME>/public/config"
                    .into()
            }
            "AI_JAIL_SSH" => "AI_JAIL_SSH=<TRUSTED-SSH>".into(),
            "AI_JAIL_SSH_CONFIG" => {
                "AI_JAIL_SSH_CONFIG=<SSH-RUNTIME>/public/config".into()
            }
            _ => original.clone(),
        };
    }
    let mut safe_value = serde_json::to_value(&display_config)
        .map_err(|error| format!("Cannot render effective access: {error}"))?;
    sanitize_serialized_strings(&mut safe_value);
    let safe_config: Config = serde_json::from_value(safe_value)
        .map_err(|error| format!("Cannot render effective access: {error}"))?;
    let policy = toml::to_string(&safe_config)
        .map_err(|error| format!("Cannot render effective access: {error}"))?;
    let mut lines = vec![
        "Complete effective access".into(),
        format!("Recipient: {}", escape_control_bytes(&process_label(harness))),
        format!("Duration: {}", duration(saved)),
        format!("Project: {project_label} (read and write)"),
        "Scope: global policy, proposed project grants, command-line grants, project constraints, and derived platform defaults".into(),
        "Effective policy (every nondefault field):".into(),
        policy
            .trim_end()
            .lines()
            .map(escape_control_bytes)
            .collect::<Vec<_>>()
            .join("\n"),
        format!(
            "Built-in environment names: {}; prefixes: {}",
            crate::config::DEFAULT_ENV_ALLOWLIST.join(", "),
            crate::config::DEFAULT_ENV_PREFIXES.join(", ")
        ),
        "Authority details (resource; access; scope/limits; consequence):".into(),
    ];
    let mut authority = |enabled: bool, text: &str| {
        if enabled {
            if let Some(text) = text.strip_prefix("ALLOWED: ") {
                lines.push(format!("- [WARN] ALLOWED: {text}"));
            } else {
                lines.push(format!("- [ERROR] OPEN: {text}"));
            }
        }
    };
    authority(
        config.network_enabled(),
        "host network; unrestricted connections; every host-reachable destination and protocol; readable jail data can reach any service",
    );
    authority(
        config.docker_enabled(),
        "Docker socket; read/write Docker API; all host containers and daemon authority; jailed processes can gain host-root-equivalent control",
    );
    authority(
        config.ssh_enabled(),
        "~/.ssh and SSH_AUTH_SOCK; read keys/config and request signatures; every loaded identity and reachable SSH service; jailed processes can impersonate the user",
    );
    authority(
        config
            .env_pass
            .iter()
            .any(|entry| crate::ssh_restricted::is_runtime_env(entry)),
        "ALLOWED: launch-scoped selected-key SSH agent; request signatures without reading private keys or the ambient agent; selected identities and saved destination constraints; accepted accounts can be used during this jail run",
    );
    authority(
        config.github_enabled(),
        "effective gh config and active github.com token; read and use; every permission carried by the token; jailed processes can act with that GitHub authority",
    );
    authority(
        config.aws_enabled(),
        "~/.aws; read credentials/config; every AWS account and role those credentials authorize; credentials can be copied and used",
    );
    authority(
        config.kube_enabled(),
        "~/.kube; read cluster credentials/config; every cluster and identity in kubeconfig; credentials can be copied and used",
    );
    authority(
        config.gcloud_enabled(),
        "~/.config/gcloud; read Google Cloud credentials/config; every project and account authorized there; credentials can be copied and used",
    );
    authority(
        config.docker_config_enabled(),
        "~/.docker/config.json; read registry credentials; every registry authorized there; credentials can be copied and used",
    );
    authority(
        config.agent_state_enabled(),
        "ALLOWED: host harness state and detected harness API-key variables; read/write state and use keys; current harness account; sessions or keys can be copied and state can change",
    );
    authority(
        config.inherit_env_enabled(),
        "complete host environment; read every exported variable; all names and values present at launch; secrets in the environment become readable",
    );
    authority(
        config.display_enabled() || config.x11_enabled(),
        "host display sockets; connect to the active display; compositor/X11 authority allowed by the platform; jailed processes may observe or control windows",
    );
    authority(
        config.audio_enabled(),
        "host audio sockets and /dev/snd; capture and play audio; active user audio session; jailed processes may record microphone/system audio",
    );
    authority(
        config.tailscale_enabled(),
        "Tailscale socket; use host tailnet control/data access; host tailnet identity; jailed processes can reach tailnet resources",
    );
    authority(
        config.gpu_enabled(),
        "host GPU devices; issue device and driver requests; GPU resources available to the host user; a large kernel/driver interface crosses the jail boundary",
    );
    authority(
        config.kvm_enabled(),
        "/dev/kvm; issue virtualization ioctls; host KVM device; jailed processes can run hardware-assisted virtual machines",
    );
    authority(
        config.host_shm_enabled(),
        "host shared-memory namespace; read/write reachable shared-memory objects; host IPC participants; data can cross the sandbox boundary",
    );
    authority(
        config.systemd_user_enabled(),
        "systemd user bus; send user-manager requests; current user services; jailed processes can control authorized user units",
    );
    authority(
        config.pictures_enabled(),
        "host Pictures directory; read only; complete Pictures tree; files can be inspected and copied but not changed through this grant",
    );
    authority(
        !config.private_home_enabled(),
        "host home directory; read and write according to normal host permissions; the complete home tree except mandatory masks; jailed processes can inspect or change unrelated personal files",
    );
    authority(
        config.private_home_enabled(),
        "ALLOWED: private persistent jail home; read and write; this harness profile only; state persists across launches",
    );
    authority(
        config.prompt_hosts_enabled(),
        "ALLOWED: desktop host prompt broker; request session-only filtered destinations; user-approved hosts for this run; approved services can receive readable jail data",
    );
    authority(
        config.terminal_passthrough_enabled(),
        "real terminal device; direct terminal I/O; invoking terminal session; jailed processes can change terminal modes and exchange input/output",
    );
    authority(
        config.macos_host_ipc_enabled(),
        "macOS host IPC compatibility services; send allowed Mach IPC; platform-defined broad host IPC scope; process isolation is weakened",
    );
    authority(
        config.macos_chromium_enabled(),
        "ALLOWED: Chromium Mach rendezvous service; register and look up browser rendezvous names; current browser process family; jailed Chromium processes can rendezvous",
    );
    authority(
        config.macos_trustd_enabled(),
        "ALLOWED: macOS trustd agent; request TLS trust evaluation; system trust service only; jailed clients can validate TLS through host trustd",
    );
    authority(
        config.allow_pty_enabled(),
        "macOS /dev/ttys* nodes; open PTY slaves; every matching terminal node; other user terminals may be reachable",
    );
    authority(
        config.allow_loopback_listen_enabled(),
        "ALLOWED: sandbox loopback listeners; bind local ports; sandbox loopback only; jailed services can accept local connections",
    );
    authority(
        config.allow_loopback_connect_enabled(),
        "OPEN: every host loopback service; connect to localhost on every port; ALL services that trust local callers become reachable",
    );
    authority(
        config.update_check_enabled(),
        "ALLOWED: GitHub release endpoint; outbound version check; ai-jail release metadata; launch contacts GitHub",
    );
    authority(
        config.audit_log_enabled(),
        "ALLOWED: host ai-jail history log; append launch records; user audit-log path; launch metadata persists outside the jail",
    );
    for (label, paths) in [
        ("read-only map", &config.ro_maps),
        ("read/write map", &config.rw_maps),
        ("copy-on-write overlay", &config.overlay_maps),
    ] {
        for path in paths {
            let runtime_map =
                crate::ssh_restricted::is_runtime_map(config, path);
            let category = if !runtime_map
                && (broad_directory(path, project)
                    || credential_authority_path(path)?)
            {
                "[ERROR] OPEN"
            } else {
                "[WARN] ALLOWED"
            };
            let displayed_path = if runtime_map {
                let spec = crate::config::MapSpec::parse(path)?;
                let leaf = if spec.source.ends_with("agent.sock") {
                    "agent.sock"
                } else {
                    "public"
                };
                crate::config::MapSpec {
                    source: PathBuf::from(format!("<SSH-RUNTIME>/{leaf}")),
                    destination: spec.destination,
                }
                .encode()
            } else {
                path.clone()
            };
            lines.push(format!("- {category}: {label} {}; mapped tree access; exact encoded source/destination; readable data can leave through allowed network access", safe_path(&displayed_path)?));
        }
    }
    if !config.allow_hosts.is_empty() {
        lines.push(format!("- [WARN] ALLOWED: public hosts {}; filtered TCP connections; named hosts and subdomains with private/loopback resolution blocked; services can receive readable jail data", config.allow_hosts.iter().map(|v| escape_control_bytes(v)).collect::<Vec<_>>().join(", ")));
    }
    if !config.allow_private_hosts.is_empty() {
        lines.push(format!("- [ERROR] OPEN: private-capable hosts {}; filtered TCP connections; named hosts may resolve to RFC1918/ULA/CGNAT addresses while metadata/link-local/loopback remain blocked; private services can receive readable jail data", config.allow_private_hosts.iter().map(|v| escape_control_bytes(v)).collect::<Vec<_>>().join(", ")));
    }
    for (label, ports, effect) in [
        (
            "allowed TCP ports",
            &config.allow_tcp_ports,
            "filtered outbound connections may use these destination ports",
        ),
        (
            "forwarded host loopback ports",
            &config.forward_ports,
            "jailed processes can reach the named host loopback services",
        ),
        (
            "published sandbox ports",
            &config.publish_ports,
            "every host process can reach jailed services on these loopback ports",
        ),
    ] {
        if !ports.is_empty() {
            lines.push(format!("- [WARN] ALLOWED: {label} {}; TCP access; exact listed ports; {effect}", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")));
        }
    }
    if config.env_pass.is_empty() {
        lines.push(
            "Environment names: none beyond the built-in safe allowlist".into(),
        );
    } else {
        let mut names = Vec::new();
        for entry in &config.env_pass {
            let name = entry.split_once('=').map_or(entry.as_str(), |v| v.0);
            names.push(escape_control_bytes(name));
        }
        names.sort();
        names.dedup();
        lines.push(format!("Environment names: {}", names.join(", ")));
        for name in names {
            let restricted_ssh_runtime = matches!(
                name.as_str(),
                "SSH_AUTH_SOCK"
                    | "GIT_SSH_COMMAND"
                    | "AI_JAIL_SSH"
                    | "AI_JAIL_SSH_CONFIG"
            ) && config
                .env_pass
                .iter()
                .any(|entry| crate::ssh_restricted::is_runtime_env(entry));
            let forge_runtime = config
                .env_pass
                .iter()
                .any(|entry| crate::forge_auth::is_runtime_env(entry))
                && matches!(
                    name.as_str(),
                    "AI_JAIL_FORGE_TOKEN"
                        | "AI_JAIL_FORGE_ORIGIN"
                        | "AI_JAIL_FORGE_REPOSITORY"
                        | "AI_JAIL_FORGE_AUTHORITY"
                        | "GH_TOKEN"
                        | "GITLAB_TOKEN"
                        | "GITEA_TOKEN"
                        | "GIT_CONFIG_COUNT"
                        | "GIT_CONFIG_KEY_0"
                        | "GIT_CONFIG_VALUE_0"
                        | "GIT_CONFIG_KEY_1"
                        | "GIT_CONFIG_VALUE_1"
                        | "GIT_CONFIG_KEY_2"
                        | "GIT_CONFIG_VALUE_2"
                );
            let forge_open = forge_runtime
                && config
                    .env_pass
                    .iter()
                    .any(|entry| entry == "AI_JAIL_FORGE_AUTHORITY=OPEN");
            let category = if forge_open {
                "[ERROR] OPEN"
            } else if name == "MISE_NOT_FOUND_AUTO_INSTALL"
                || restricted_ssh_runtime
                || forge_runtime
            {
                "[WARN] ALLOWED"
            } else {
                "[ERROR] OPEN"
            };
            if restricted_ssh_runtime {
                lines.push(format!("- {category}: generated launch-scoped SSH variable {name}; points only to the dedicated agent or generated strict SSH configuration; jailed descendants can use the selected-key authority"));
            } else if forge_open {
                lines.push(format!("- {category}: unverified persistent forge runtime variable {name}; value hidden; jailed descendants can use and copy it, and ai-jail cannot prove the token lacks authority outside the selected repository"));
            } else if forge_runtime {
                lines.push(format!("- {category}: repository-bound forge runtime variable {name}; value hidden; jailed descendants can use and copy the launch credential, whose server-side repository scope is the security boundary"));
            } else {
                lines.push(format!("- {category}: host environment variable {name} (value hidden); every jailed descendant can read, use, and copy the current launch value; allowed network access can carry it outside the jail"));
            }
        }
    }
    if approved_env_names.is_empty() {
        lines.push("User-approved host environment names: none".into());
    } else {
        lines.push(format!(
            "User-approved host environment names: {}",
            approved_env_names
                .iter()
                .map(|name| escape_control_bytes(name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !config.env_from_file.is_empty() {
        let paths = config
            .env_from_file
            .iter()
            .map(|path| safe_path(path))
            .collect::<Result<Vec<_>, _>>()?;
        lines.push(format!(
            "Credential files read at launch: {}",
            paths.join(", ")
        ));
    }
    if !config.secret_hosts.is_empty() {
        let bindings = config
            .secret_hosts
            .iter()
            .map(|(name, host)| {
                format!(
                    "{} -> {}",
                    escape_control_bytes(name),
                    escape_control_bytes(host)
                )
            })
            .collect::<Vec<_>>();
        lines.push(format!("Proxy-bound credentials: {}", bindings.join(", ")));
    }
    lines.push("Limits: mandatory masks, platform support, and monotonic project restrictions still apply".into());
    Ok(lines.join("\n"))
}

fn sanitize_serialized_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = escape_control_bytes(text);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sanitize_serialized_strings(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                sanitize_serialized_strings(value);
            }
        }
        _ => {}
    }
}

pub(crate) fn effective_has_open_authority(
    config: &Config,
    project: &Path,
) -> Result<bool, String> {
    let direct = config.network_enabled()
        || !config.private_home_enabled()
        || config.docker_enabled()
        || config.ssh_enabled()
        || config.github_enabled()
        || config.aws_enabled()
        || config.kube_enabled()
        || config.gcloud_enabled()
        || config.docker_config_enabled()
        || config.inherit_env_enabled()
        || config.display_enabled()
        || config.x11_enabled()
        || config.audio_enabled()
        || config.tailscale_enabled()
        || config.gpu_enabled()
        || config.kvm_enabled()
        || config.host_shm_enabled()
        || config.systemd_user_enabled()
        || config.pictures_enabled()
        || config.terminal_passthrough_enabled()
        || config.macos_host_ipc_enabled()
        || config.allow_pty_enabled()
        || config.allow_loopback_connect_enabled()
        || !config.allow_private_hosts.is_empty()
        || config.env_pass.iter().any(|entry| open_env_entry(entry));
    if direct {
        return Ok(true);
    }
    for path in config
        .ro_maps
        .iter()
        .chain(&config.rw_maps)
        .chain(&config.overlay_maps)
    {
        if !crate::ssh_restricted::is_runtime_map(config, path)
            && (broad_directory(path, project)
                || credential_authority_path(path)?)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn credential_authority_path(encoded: &Path) -> Result<bool, String> {
    crate::authority_inventory::map_is_protected(encoded)
}

pub(crate) fn safe_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "Refusing a path that is not valid UTF-8".to_string())?;
    Ok(escape_control_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review_store(
        base: &Path,
        project: &Path,
    ) -> crate::config_store::StorePaths {
        let root = base.join("store");
        crate::config_store::StorePaths {
            available: true,
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root.join("projects/project.toml"),
            legacy_global: base.join("legacy-global"),
            legacy_project: project.join(".ai-jail"),
            canonical_project: std::fs::canonicalize(project).unwrap(),
            policy_root: std::fs::canonicalize(project).unwrap(),
            project_strategy: crate::config::ProjectStrategy::Basename,
            root,
        }
    }

    #[test]
    fn review_classifies_exact_forge_authority_and_gates_open() {
        let base = std::env::temp_dir()
            .join(format!("ai-jail-review-forge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let project = base.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::set_permissions(
            &base,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        // Darwin's per-user temporary directory begins with `/var`, which is
        // itself a symlink to `/private/var`. The trusted store correctly
        // rejects symlinked ancestors, so exercise it through the canonical
        // path on every platform.
        let base = std::fs::canonicalize(base).unwrap();
        let project = base.join("project");
        let store = review_store(&base, &project);
        let global = Config::default();
        let constraints = Config::default();
        let cli = crate::cli::CliArgs::default();
        let requests = crate::integration::RequestSet::default();
        let context = EffectiveContext {
            global: &global,
            cli: &cli,
            constraints: &constraints,
            trusted_constraints: false,
            approved_env_names: &[],
            restricted_ssh: None,
            requests: &requests,
            approved_wrapper_requests: &[],
            store: &store,
        };
        let harnesses = vec!["claude".to_string()];

        crate::forge_auth::install_test_binding_metadata(&store, false)
            .unwrap();
        let open = prepare_profile(
            &Selection::default(),
            "claude",
            &harnesses,
            &project,
            &[],
            &context,
        )
        .unwrap();
        assert!(open.display.has_open_authority);
        assert!(open.display.open.contains("GitLab project token"));
        assert!(open.display.effective_access.contains("[ERROR] OPEN"));

        crate::forge_auth::install_test_binding_metadata(&store, true).unwrap();
        let scoped = prepare_profile(
            &Selection::default(),
            "claude",
            &harnesses,
            &project,
            &[],
            &context,
        )
        .unwrap();
        assert!(!scoped.display.has_open_authority);
        assert!(scoped.display.allowed.contains("GitHub App"));
        assert!(scoped.display.effective_access.contains("[WARN] ALLOWED"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn review_preparation_recomputes_from_current_selection() {
        let project = std::env::temp_dir()
            .join(format!("ai-jail-review-recompute-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&project);
        std::fs::create_dir_all(&project).unwrap();
        let global = Config::default();
        let constraints = Config::default();
        let cli = crate::cli::CliArgs::default();
        let requests = crate::integration::RequestSet::default();
        let store =
            crate::config_store::StorePaths::discover(&project).unwrap();
        let context = EffectiveContext {
            global: &global,
            cli: &cli,
            constraints: &constraints,
            trusted_constraints: false,
            approved_env_names: &[],
            restricted_ssh: None,
            requests: &requests,
            approved_wrapper_requests: &[],
            store: &store,
        };
        let harnesses = vec!["claude".to_string()];
        let mut selection = Selection::default();
        let first = prepare_profile(
            &selection,
            "claude",
            &harnesses,
            &project,
            &[],
            &context,
        )
        .unwrap();
        selection.github = true;
        let second = prepare_profile(
            &selection,
            "claude",
            &harnesses,
            &project,
            &[],
            &context,
        )
        .unwrap();

        assert_eq!(first.profile.grants.github, Some(false));
        assert_eq!(second.profile.grants.github, Some(true));
        assert!(!first.display.open.contains("host gh configuration"));
        assert!(second.display.open.contains("host gh configuration"));
        assert!(second.display.has_open_authority);
        std::fs::remove_dir_all(project).unwrap();
    }

    #[test]
    fn grant_disclosure_contains_every_required_field() {
        let rendered =
            project_grant(Path::new("/work"), "claude", Some(true)).render();
        for field in [
            "Resource:",
            "Access:",
            "Process:",
            "Duration:",
            "Scope:",
            "Limits:",
            "Default:",
            "Consequence:",
        ] {
            assert!(rendered.contains(field), "missing {field}");
        }
    }

    #[test]
    fn effective_output_escapes_inline_terminal_controls() {
        let hostile = "bad\n\r\t\x1b]52;clipboard\x07\u{202e}host";
        let root = std::env::temp_dir()
            .join(format!("ai-jail-inline-controls-{}", std::process::id()));
        let hostile_path = root.join(hostile);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&hostile_path).unwrap();
        let rendered = render_effective_access(
            &Config {
                allow_hosts: vec![hostile.into()],
                ro_maps: vec![hostile_path],
                ..Config::default()
            },
            Path::new(hostile),
            hostile,
            None,
            &[],
        )
        .unwrap();
        for forbidden in ['\r', '\t', '\x1b', '\x07', '\u{202e}'] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(!rendered.lines().any(|line| line == "bad"), "{rendered}");
        assert!(rendered.contains("bad????]52;clipboard??host"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn secure_selection_denies_optional_credentials_and_registries() {
        let grants = Selection::default().grants("claude");
        assert_eq!(grants.agent_state, Some(false));
        assert_eq!(grants.no_toolchains, Some(true));
        assert_eq!(grants.ssh, Some(false));
        assert_eq!(grants.github, Some(false));
        assert_eq!(grants.no_docker, Some(true));
        assert_eq!(grants.network, None);
        assert!(grants.private_home.is_none());
        assert!(grants.inherit_env.is_none());
        assert!(grants.aws.is_none());
    }

    #[test]
    fn empty_project_grants_stay_empty_until_baseline_is_explicitly_applied() {
        let selection = Selection::from_project_grants(
            &Config::default(),
            "claude",
            &[],
            None,
        );
        assert!(!selection.api_access);
        assert!(!selection.agent_state);
        assert!(!selection.dependency_hosts);
        assert!(!selection.ssh);
        assert!(!selection.github);
        assert!(!selection.container_engine);
        assert!(selection.additional.explicit);
        assert!(!selection.additional.any_enabled());
        assert!(selection.ro_dirs.is_empty());
        assert!(selection.rw_dirs.is_empty());
    }

    #[test]
    fn recommended_developer_baseline_includes_visible_github_open_access() {
        let mut selection = Selection::default();
        selection.apply_recommended_developer_baseline("claude");

        assert!(selection.api_access);
        assert!(selection.agent_state);
        assert!(selection.dependency_hosts);
        assert!(!selection.ssh);
        assert!(selection.github);
        assert!(!selection.container_engine);
        assert_eq!(selection.additional, AdditionalSelection::default());
        assert!(!selection.unrestricted_network);
        assert!(!selection.loopback_connect);
        assert!(selection.ro_dirs.is_empty());
        assert!(selection.rw_dirs.is_empty());
        assert!(selection.env_names.is_empty());
    }

    #[test]
    fn unknown_harness_baseline_does_not_invent_an_api_destination() {
        let mut selection = Selection::default();
        selection.apply_recommended_developer_baseline("custom-harness");

        assert!(!selection.api_access);
        assert!(selection.agent_state);
        assert!(selection.dependency_hosts);
        assert!(selection.github);
        assert!(selection.requested_hosts.is_empty());
    }

    #[test]
    fn tui_container_and_additional_choices_map_to_the_same_config_fields_as_cli()
     {
        let selection = Selection {
            container_engine: true,
            additional: AdditionalSelection {
                share_host_home: true,
                lockdown: true,
                gpu: true,
                aws: true,
                inherit_env: true,
                worktree: true,
                audit_log: true,
                ..AdditionalSelection::default()
            },
            ..Selection::default()
        };
        let grants = selection.grants("claude");

        assert!(grants.docker_enabled());
        assert!(!grants.private_home_enabled());
        assert!(grants.lockdown_enabled());
        assert!(grants.gpu_enabled());
        assert!(grants.aws_enabled());
        assert!(grants.inherit_env_enabled());
        assert!(grants.worktree_enabled());
        assert!(grants.audit_log_enabled());
    }

    #[test]
    fn unrestricted_network_does_not_persist_the_model_api_host() {
        let selection = Selection {
            api_access: true,
            unrestricted_network: true,
            ..Selection::default()
        };
        let grants = selection.grants("claude");

        assert!(grants.network_enabled());
        assert!(grants.allow_hosts.is_empty());
        assert!(!grants.has_filtered_hosts());
    }

    #[test]
    fn every_additional_tui_choice_round_trips_through_config() {
        let all = AdditionalSelection {
            explicit: true,
            share_host_home: true,
            lockdown: true,
            systemd_user: true,
            gpu: true,
            tailscale: true,
            display: true,
            audio: true,
            kvm: true,
            x11: true,
            host_shm: true,
            terminal_passthrough: true,
            aws: true,
            kube: true,
            gcloud: true,
            docker_config: true,
            macos_host_ipc: true,
            macos_chromium: true,
            macos_trustd: true,
            allow_pty: true,
            allow_loopback_listen: true,
            inherit_env: true,
            worktree: true,
            pictures: true,
            audit_log: true,
        };
        let mut config = Config::default();
        all.apply_to(&mut config);
        assert_eq!(AdditionalSelection::from_config(&config), all);

        let none = AdditionalSelection {
            explicit: true,
            ..AdditionalSelection::default()
        };
        none.apply_to(&mut config);
        assert_eq!(AdditionalSelection::from_config(&config), none);
    }

    #[test]
    fn completed_onboarding_reopens_saved_choices_without_applying_baseline() {
        let config = Config {
            agent_state: Some(false),
            no_toolchains: Some(true),
            github: Some(true),
            ..Config::default()
        };
        let approved_env = vec!["GH_TOKEN".to_string()];
        let selection =
            initial_selection(&config, "claude", &approved_env, None, false);

        assert!(!selection.api_access);
        assert!(!selection.agent_state);
        assert!(!selection.dependency_hosts);
        assert!(selection.github);
        assert_eq!(selection.env_names, approved_env);
    }

    #[test]
    fn wrapper_requests_become_explicit_profile_grants() {
        let mut selection = Selection::default();
        let private = crate::integration::RequestApproval {
            requester: "ai-memory".into(),
            kind: "private_host".into(),
            value: "192.168.0.90".into(),
            host: None,
            writable: None,
            port: Some(49374),
        };
        let secret = crate::integration::RequestApproval {
            requester: "ai-memory".into(),
            kind: "secret".into(),
            value: "AI_MEMORY_AUTH_TOKEN".into(),
            host: Some("192.168.0.90".into()),
            writable: None,
            port: None,
        };
        let private = prepare_wrapper_request(
            &private,
            &selection,
            "claude",
            Path::new("/work/project"),
        )
        .unwrap();
        apply_wrapper_request(&mut selection, &private);
        let secret = PreparedWrapperRequest::Direct {
            grant: env_grant(&secret.value, "claude"),
            approval: secret,
        };
        apply_wrapper_request(&mut selection, &secret);
        let profile = selection.profile_for(&["claude".into()]);
        assert_eq!(profile.grants.allow_private_hosts, ["192.168.0.90"]);
        assert_eq!(
            profile.grants.secret_hosts.get("AI_MEMORY_AUTH_TOKEN"),
            Some(&"192.168.0.90".into())
        );
        assert_eq!(profile.approved_env_names, ["AI_MEMORY_AUTH_TOKEN"]);
    }

    #[test]
    fn wrapper_map_requests_cannot_bypass_root_or_overlap_checks() {
        let root_request = crate::integration::RequestApproval {
            requester: "wrapper".into(),
            kind: "map".into(),
            value: "/".into(),
            host: None,
            writable: Some(false),
            port: None,
        };
        let root_error = prepare_wrapper_request(
            &root_request,
            &Selection::default(),
            "claude",
            Path::new("/work/project"),
        )
        .unwrap_err();
        assert!(root_error.contains("filesystem root"), "{root_error}");

        let base = std::env::temp_dir()
            .join(format!("ai-jail-wrapper-overlap-{}", std::process::id()));
        let parent = base.join("shared");
        let child = parent.join("nested");
        std::fs::create_dir_all(&child).unwrap();
        let parent = std::fs::canonicalize(parent).unwrap();
        let child = std::fs::canonicalize(child).unwrap();
        let selection = Selection {
            ro_dirs: vec![parent],
            ..Selection::default()
        };
        let overlap_request = crate::integration::RequestApproval {
            requester: "wrapper".into(),
            kind: "map".into(),
            value: child.to_string_lossy().into_owned(),
            host: None,
            writable: Some(true),
            port: None,
        };
        let overlap_error = prepare_wrapper_request(
            &overlap_request,
            &selection,
            "claude",
            &base,
        )
        .unwrap_err();
        assert!(overlap_error.contains("Overlapping"), "{overlap_error}");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn wrapper_map_revoke_matches_the_canonical_persisted_grant() {
        let base = std::env::temp_dir().join(format!(
            "ai-jail-wrapper-canonical-revoke-{}",
            std::process::id()
        ));
        let lexical_parent = base.join("a");
        let real = base.join("real");
        std::fs::create_dir_all(&lexical_parent).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        let presented = lexical_parent.join("..").join("real");
        let approval = crate::integration::RequestApproval {
            requester: "wrapper".into(),
            kind: "map".into(),
            value: presented.to_string_lossy().into_owned(),
            host: None,
            writable: Some(false),
            port: None,
        };
        let mut selection = Selection::default();
        let prepared =
            prepare_wrapper_request(&approval, &selection, "claude", &base)
                .unwrap();
        apply_wrapper_request(&mut selection, &prepared);
        assert_eq!(
            selection.ro_dirs,
            vec![std::fs::canonicalize(&real).unwrap()]
        );

        revoke_wrapper_request(&mut selection, &approval);
        assert!(selection.ro_dirs.is_empty());
        assert!(selection.rw_dirs.is_empty());
        let profile = selection.profile("claude");
        assert!(profile.grants.ro_maps.is_empty());
        assert!(profile.grants.rw_maps.is_empty());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn wrapper_map_revoke_fails_closed_after_symlink_drift_or_removal() {
        for scenario in ["retarget", "remove"] {
            let base = std::env::temp_dir().join(format!(
                "ai-jail-wrapper-symlink-revoke-{scenario}-{}",
                std::process::id()
            ));
            let original = base.join("original");
            let replacement = base.join("replacement");
            let unrelated = base.join("unrelated");
            let link = base.join("selected");
            std::fs::create_dir_all(&original).unwrap();
            std::fs::create_dir_all(&replacement).unwrap();
            std::fs::create_dir_all(&unrelated).unwrap();
            std::os::unix::fs::symlink(&original, &link).unwrap();
            let approval = crate::integration::RequestApproval {
                requester: "wrapper".into(),
                kind: "map".into(),
                value: link.to_string_lossy().into_owned(),
                host: None,
                writable: Some(false),
                port: None,
            };
            let mut selection = Selection::default();
            let prepared =
                prepare_wrapper_request(&approval, &selection, "claude", &base)
                    .unwrap();
            apply_wrapper_request(&mut selection, &prepared);
            selection
                .rw_dirs
                .push(std::fs::canonicalize(&unrelated).unwrap());
            if scenario == "retarget" {
                selection
                    .rw_dirs
                    .push(std::fs::canonicalize(&replacement).unwrap());
            }

            std::fs::remove_file(&link).unwrap();
            if scenario == "retarget" {
                std::os::unix::fs::symlink(&replacement, &link).unwrap();
            }
            revoke_wrapper_request(&mut selection, &approval);

            assert!(selection.ro_dirs.is_empty(), "scenario {scenario}");
            assert!(selection.rw_dirs.is_empty(), "scenario {scenario}");
            let profile = selection.profile("claude");
            assert!(profile.grants.ro_maps.is_empty());
            assert!(profile.grants.rw_maps.is_empty());
            std::fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn open_grants_are_classified_open() {
        for kind in ["ssh", "github", "network", "loopback-connect"] {
            assert_eq!(open_grant(kind, "claude", None).risk, Risk::Open);
        }
    }

    #[test]
    fn restricted_ssh_disclosure_names_scope_and_private_key_boundary() {
        let policy = crate::ssh_restricted::Policy {
            keys: vec![crate::ssh_restricted::KeyIdentity {
                private_path: "/home/test/.ssh/id_test".into(),
                public_path: "/home/test/.ssh/id_test.pub".into(),
                fingerprint: "SHA256:fixture".into(),
                comment: "fixture@example".into(),
                private_dev: 1,
                private_ino: 2,
                public_dev: 1,
                public_ino: 3,
            }],
            lifetime_seconds: 600,
            destinations: vec!["github.com".into()],
        };
        let rendered =
            restricted_ssh_grant(&policy, "claude", Some(true)).render();
        assert!(rendered.contains("SHA256:fixture"));
        assert!(rendered.contains("private key files"));
        assert!(rendered.contains("Only verified destination constraints"));
        assert!(rendered.contains("github.com"));
    }

    #[test]
    fn restricted_ssh_design_and_provenance_are_linked() {
        let design = include_str!("../docs/TUI_DESIGN.md");
        assert!(design.contains("## Selected-key SSH editor"));
        assert!(design.contains("Private-key contents and the ambient agent are never displayed or shared"));
        let provenance = include_str!("../docs/onboarding-provenance.toml");
        assert!(
            provenance.contains(
                "policy = \"onboarding.restricted_ssh_selected_keys\""
            )
        );
        assert!(provenance.contains("onboarding::tui::ssh::tests::security_detail_names_every_selected_key_boundary"));
    }

    #[test]
    fn restricted_ssh_discovery_refuses_symlinked_public_entries() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-discover-ssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("id_test"), "private fixture").unwrap();
        std::fs::write(root.join("real.pub"), "public fixture").unwrap();
        std::os::unix::fs::symlink(
            root.join("real.pub"),
            root.join("id_test.pub"),
        )
        .unwrap();
        assert!(discover_public_ssh_keys_in(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restricted_ssh_does_not_pretend_filtered_http_egress_carries_ssh() {
        let selection = Selection {
            restricted_ssh: Some(crate::ssh_restricted::Policy {
                keys: Vec::new(),
                lifetime_seconds: 600,
                destinations: vec!["git@github.com".into()],
            }),
            ..Selection::default()
        };
        let grants = selection.grants("claude");
        assert!(!grants.network_enabled());
        assert!(!grants.allow_hosts.iter().any(|host| host == "github.com"));
    }

    #[test]
    fn summary_duration_distinguishes_saved_and_one_run_access() {
        assert!(duration(Some(true)).contains("remains saved"));
        assert!(duration(Some(false)).contains("no approval is saved"));
        assert!(duration(None).contains("launch once"));
    }

    #[test]
    fn broad_directory_disclosure_names_unrelated_files_and_credentials() {
        let grant = classified_directory_grant(
            Path::new("/work"),
            true,
            "claude",
            Path::new("/work/project"),
            Some(true),
        );
        assert_eq!(grant.risk, Risk::Open);
        assert!(grant.limits.contains("credentials"));
        assert!(grant.consequence.contains("unrelated host files"));
    }

    #[test]
    fn credential_roots_are_refused_through_home_aliases() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "ai-jail-onboarding-home-alias-{}",
            std::process::id()
        ));
        let real_home = base.join("real-home");
        let alias_home = base.join("alias-home");
        let aws = real_home.join(".aws");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&aws).unwrap();
        symlink(&real_home, &alias_home).unwrap();

        let canonical = std::fs::canonicalize(alias_home.join(".aws")).unwrap();
        let error = reject_credential_root_for_home(&canonical, &alias_home)
            .unwrap_err();
        assert!(error.contains("Refusing credential-bearing path"));
        assert!(!error.contains("AJ-"));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn open_confirmation_is_exact() {
        assert!(open_confirmation("OPEN"));
        for value in ["open", " OPEN", "OPEN ", "yes"] {
            assert!(!open_confirmation(value));
        }
    }

    #[test]
    fn cancel_copy_only_claims_onboarding_writes() {
        assert!(messages::CANCEL.contains("No onboarding grants"));
        assert!(messages::CANCEL.contains("migration"));
    }

    #[test]
    fn environment_names_reject_assignments_and_values_never_render() {
        for invalid in ["TOKEN=value", "", "9NAME", "BAD-NAME", "BAD\0NAME"] {
            assert!(validate_env_name(invalid).is_err());
        }
        assert!(validate_env_name("CUSTOM_MODE").is_ok());
        let grant = env_grant("GITHUB_TOKEN", "claude");
        let rendered = grant.render();
        assert_eq!(grant.risk, Risk::Open);
        assert!(rendered.contains("GITHUB_TOKEN"));
        assert!(rendered.contains("value hidden"));
        assert!(!rendered.contains("secret-value"));
        assert_eq!(env_grant("CUSTOM_MODE", "claude").risk, Risk::Open);
        for name in [
            "KEY_DATA",
            "DATA_KEY",
            "APP_CRED",
            "CREDENTIAL_FILE",
            "BEARER_VALUE",
            "SIGNING_MATERIAL",
            "TLS_CERT",
            "CLIENT_CERTIFICATE",
            "github_token",
            "AWS_PROFILE",
        ] {
            assert!(secret_env_name(name), "missed secret-like name {name}");
        }
        for name in ["MONKEY", "KEYBOARD", "AUTHORITY", "SESSIONAL"] {
            assert!(!secret_env_name(name), "false positive for {name}");
        }
    }

    #[test]
    fn approved_environment_profile_saves_names_without_values() {
        let selection = Selection {
            env_names: vec!["CUSTOM_MODE".into()],
            ..Selection::default()
        };
        let profile = selection.profile("claude");
        assert_eq!(profile.approved_env_names, vec!["CUSTOM_MODE"]);
        assert_eq!(profile.grants.env_pass, vec!["CUSTOM_MODE"]);
        assert!(
            !toml::to_string(&profile.grants)
                .unwrap()
                .contains("CUSTOM_MODE")
        );
    }

    #[test]
    fn environment_approval_design_and_provenance_are_linked() {
        let design = include_str!("../docs/TUI_DESIGN.md");
        assert!(design.contains("## Environment selector"));
        assert!(design.contains("Values are never loaded for"));
        assert!(design.contains("rendering, displayed, logged, or persisted"));
        let provenance = include_str!("../docs/onboarding-provenance.toml");
        assert!(
            provenance
                .contains("policy = \"onboarding.environment_name_approval\"")
        );
        assert!(provenance.contains("onboarding::tui::environment::tests::model_and_rendering_never_need_environment_values"));
    }

    #[test]
    fn catalog_ids_are_stable_and_unique() {
        let ids = [
            messages::INTRO_ID,
            messages::CHOICE_ID,
            messages::GRANT_ID,
            messages::OPEN_ID,
            messages::PRESET_ID,
            messages::SUMMARY_ID,
            messages::SAVE_ID,
            messages::CANCEL_ID,
            messages::NON_TTY_ID,
            messages::CONFIG_NON_TTY_ID,
            messages::FINAL_ID,
            messages::PATH_REFUSED_ID,
            messages::CREDENTIAL_PATH_ID,
            messages::PATH_IDENTITY_ID,
            messages::PATH_DRIFT_ID,
            messages::ENV_ID,
            messages::ENV_MISSING_ID,
            messages::SSH_ID,
            messages::SSH_SCOPE_ID,
            messages::SSH_DRIFT_ID,
            messages::SSH_NETWORK_ID,
            messages::POLICY_SHARED_ID,
        ];
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn plain_header_names_shared_policy_root() {
        let shared = plain_header(
            "claude",
            Path::new("/work/wt"),
            Some(Path::new("/work/main")),
        )
        .unwrap();
        assert!(shared.contains("/work/main"));
        assert!(shared.contains("shared with its linked worktrees"));
        assert!(!shared.contains("AJ-"));
        let own = plain_header("claude", Path::new("/work/wt"), None).unwrap();
        assert!(!own.contains("Policy"));
    }

    #[test]
    fn directory_completion_never_expands_shell_syntax() {
        assert!(expand_home("$HOME/private").is_err());
        assert!(expand_home("*.toml").is_err());
    }

    #[test]
    fn internal_catalog_and_provenance_cannot_drift() {
        let provenance = include_str!("../docs/onboarding-provenance.toml");

        let document: toml::Value = toml::from_str(provenance).unwrap();
        let claims = document["claim"].as_array().unwrap();
        let mut claimed_ids = claims
            .iter()
            .flat_map(|claim| claim["message_ids"].as_array().unwrap())
            .map(|id| id.as_str().unwrap())
            .collect::<Vec<_>>();
        claimed_ids.sort_unstable();
        let claimed_count = claimed_ids.len();
        claimed_ids.dedup();
        assert_eq!(claimed_ids.len(), claimed_count, "duplicate provenance ID");
        let mut catalog_ids = vec![
            messages::INTRO_ID,
            messages::CHOICE_ID,
            messages::GRANT_ID,
            messages::OPEN_ID,
            messages::PRESET_ID,
            messages::SUMMARY_ID,
            messages::SAVE_ID,
            messages::CANCEL_ID,
            messages::NON_TTY_ID,
            messages::CONFIG_NON_TTY_ID,
            messages::FINAL_ID,
            messages::PATH_REFUSED_ID,
            messages::CREDENTIAL_PATH_ID,
            messages::PATH_IDENTITY_ID,
            messages::PATH_DRIFT_ID,
            messages::ENV_ID,
            messages::ENV_MISSING_ID,
            messages::SSH_ID,
            messages::SSH_SCOPE_ID,
            messages::SSH_DRIFT_ID,
            messages::SSH_NETWORK_ID,
            messages::POLICY_SHARED_ID,
        ];
        catalog_ids.sort_unstable();
        assert_eq!(claimed_ids, catalog_ids, "catalog/provenance ID drift");

        let listed =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--list")
                .arg("--format=terse")
                .output()
                .unwrap();
        assert!(listed.status.success());
        let mut executable_tests = String::from_utf8(listed.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_suffix(": test"))
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>();
        let integration_source = include_str!("../tests/onboarding.rs");
        let mut test_attribute = false;
        for line in integration_source.lines().map(str::trim) {
            if line == "#[test]" {
                test_attribute = true;
                continue;
            }
            if test_attribute && line.starts_with("#[") {
                continue;
            }
            if test_attribute {
                let name = line
                    .strip_prefix("fn ")
                    .and_then(|rest| rest.split_once('(').map(|pair| pair.0))
                    .unwrap_or_else(|| {
                        panic!("#[test] is not followed by a function: {line}")
                    });
                executable_tests.insert(name.to_string());
                test_attribute = false;
            }
        }
        assert!(!test_attribute, "dangling #[test] in tests/onboarding.rs");
        for reference in claims
            .iter()
            .flat_map(|claim| claim["verified_by"].as_array().unwrap())
            .map(|test| test.as_str().unwrap())
        {
            assert!(
                executable_tests.contains(reference),
                "provenance references nonexistent executable test {reference}"
            );
            let selector_matches = executable_tests
                .iter()
                .filter(|name| name.contains(reference))
                .count();
            assert_eq!(
                selector_matches, 1,
                "cargo test {reference} would select {selector_matches} documented tests"
            );
        }
    }

    #[test]
    fn effective_secure_review_matches_tui_design_contract() {
        let rendered = render_effective_access(
            &Config {
                command: vec!["claude".into()],
                github: Some(false),
                no_mise: Some(true),
                no_toolchains: Some(true),
                ssh: Some(false),
                allow_hosts: vec!["api.anthropic.com".into()],
                agent_state: Some(false),
                ..Config::default()
            },
            Path::new("/home/alice/src/demo"),
            "claude",
            Some(true),
            &[],
        )
        .unwrap()
            + "\n";
        assert!(rendered.contains("Complete effective access"));
        assert!(rendered.contains("github = false"));
        assert!(rendered.contains("ssh = false"));
        assert!(rendered.contains("[WARN] ALLOWED"));
        let design = include_str!("../docs/TUI_DESIGN.md");
        assert!(design.contains("## Saving"));
        assert!(design.contains("exact external config path"));
        let provenance = include_str!("../docs/onboarding-provenance.toml");
        assert!(
            provenance
                .contains("policy = \"onboarding.complete_effective_access\"")
        );
        assert!(provenance.contains(
            "scripted_pty_confirms_recommended_github_and_saves_without_final_review"
        ));
    }
}
