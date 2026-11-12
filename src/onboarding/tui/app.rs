use super::super::{
    GrantSpec, Risk, Selection, api_grant, api_hosts,
    apply_directory_candidate, apply_env_name, apply_wrapper_request,
    dependency_grant, discover_public_ssh_keys, environment_name_catalog,
    expand_home, list_directory, open_grant, prepare_directory_candidate,
    prepare_env_candidate, prepare_wrapper_request, remove_directory_grant,
    remove_env_name, revoke_wrapper_request, safe_path, state_grant,
    validate_ssh_destinations, validate_ssh_lifetime,
};
use super::additional::{
    Capability as AdditionalCapability, State as AdditionalState,
};
use super::dialog::{
    ConfirmDialog, DialogAction, ExitDialog, ExitDialogAction,
};
use super::directory::{
    DirectoryAction, DirectoryBrowser, DirectoryEntry, DirectoryGrantEntry,
    DirectoryMode, DirectoryPreview,
};
use super::environment::{EnvironmentAction, EnvironmentSelector};
use super::ssh::{
    Editor as SshEditor, EditorAction as SshAction, IdentityRow,
    OperationRequest as SshRequest,
};
use super::wrapper::{WrapperAction, WrapperReview};
use crate::integration::{RequestApproval, RequestSet};
use crate::output::escape_control_bytes;
use crossterm::event::KeyCode;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(super) const MIN_WIDTH: u16 = 64;
pub(super) const MIN_HEIGHT: u16 = 30;
const MAX_DETAIL_SCROLL: u16 = 4096;

pub(super) fn human_error(error: String) -> String {
    let Some((prefix, message)) = error.split_once(' ') else {
        return error;
    };
    if prefix.starts_with("AJ-") {
        message.into()
    } else {
        error
    }
}

fn copy_to_clipboard(text: &str) -> Result<&'static str, String> {
    #[cfg(target_os = "linux")]
    let candidates: &[(&str, &[&str])] =
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            &[
                ("wl-copy", &[]),
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["--clipboard", "--input"]),
            ]
        } else {
            &[
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["--clipboard", "--input"]),
                ("wl-copy", &[]),
            ]
        };

    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("pbcopy", &[])];

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let candidates: &[(&str, &[&str])] = &[];

    for (name, arguments) in candidates {
        #[cfg(target_os = "linux")]
        let program = crate::sandbox::bwrap::trusted_system_binary(name);
        #[cfg(target_os = "macos")]
        let program = {
            let path = PathBuf::from("/usr/bin").join(name);
            path.is_file().then_some(path)
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let program: Option<PathBuf> = None;

        let Some(program) = program else {
            continue;
        };
        let mut child = Command::new(program)
            .args(*arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("Could not start {name}: {error}"))?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| format!("Could not open {name} input."))?
            .write_all(text.as_bytes());
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Could not copy with {name}: {error}"));
        }
        let status = child
            .wait()
            .map_err(|error| format!("Could not wait for {name}: {error}"))?;
        if status.success() {
            return Ok(name);
        }
    }
    Err("Clipboard unavailable. Install wl-clipboard, xclip, or xsel (pbcopy is used on macOS).".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CapabilityId {
    ModelApi,
    HarnessState,
    Dependencies,
    FullSsh,
    RestrictedSsh,
    FullGithub,
    ContainerEngine,
    UnrestrictedNetwork,
    Loopback,
    Environment,
    DirectoryAccess,
    Additional,
    Review,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessPreset {
    FullyClosed,
    Developer,
    MostlyOpen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BuiltinProtection {
    PlatformSandbox,
    ExternalPolicy,
    DirectoryIdentity,
    CredentialRoots,
    EnvironmentValues,
}

impl BuiltinProtection {
    pub(super) const ALL: [Self; 5] = [
        Self::PlatformSandbox,
        Self::ExternalPolicy,
        Self::DirectoryIdentity,
        Self::CredentialRoots,
        Self::EnvironmentValues,
    ];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::PlatformSandbox => {
                #[cfg(target_os = "linux")]
                {
                    "Bubblewrap sandbox"
                }
                #[cfg(target_os = "macos")]
                {
                    "macOS sandbox-exec boundary"
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    "Platform sandbox"
                }
            }
            Self::ExternalPolicy => "Approvals stored outside project",
            Self::DirectoryIdentity => "Saved directory identity checks",
            Self::CredentialRoots => "Credential-folder refusal",
            Self::EnvironmentValues => "Environment values are not stored",
        }
    }

    pub(super) const fn detail(self) -> &'static str {
        match self {
            Self::PlatformSandbox => {
                #[cfg(target_os = "linux")]
                {
                    "Always enforced\nThe harness and every child process start inside Bubblewrap. Access choices add specific resources inside that boundary; this setup screen cannot turn the sandbox off.\n\nWhy it matters\nOptional grants widen a sandboxed process; they never become an unsandboxed launch."
                }
                #[cfg(target_os = "macos")]
                {
                    "Always enforced\nThe harness and every child process start inside Apple's sandbox-exec boundary. Access choices add specific resources inside it; this setup screen cannot turn the sandbox off.\n\nWhy it matters\nOptional grants widen a sandboxed process; they never become an unsandboxed launch."
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    "Always enforced\nThe harness and every child process start inside the platform sandbox. Access choices add resources inside it; this setup screen cannot turn the sandbox off.\n\nWhy it matters\nOptional grants widen a sandboxed process; they never become an unsandboxed launch."
                }
            }
            Self::ExternalPolicy => {
                "Always enforced\nAccess approvals are read from the external config path shown above, not from this project.\n\nWhy it matters\nProject content cannot silently change the host access you approved."
            }
            Self::DirectoryIdentity => {
                "Always enforced\nEvery saved directory approval is tied to the reviewed filesystem object. If the path disappears, moves, or changes identity, ai-jail refuses the grant.\n\nWhy it matters\nA replaced path cannot silently inherit an earlier directory approval."
            }
            Self::CredentialRoots => {
                "Always enforced\nThe general directory picker refuses credential roots such as ~/.ssh. Credential access must use a dedicated, clearly disclosed capability instead.\n\nWhy it matters\nA convenient directory grant cannot quietly expose a whole credential store."
            }
            Self::EnvironmentValues => {
                "Always enforced\nEnvironment approvals store names only. Values never appear in this TUI or the saved profile; ai-jail reads the current value only when launching a jail.\n\nWhy it matters\nRotated secrets stay current without being copied into persistent ai-jail configuration."
            }
        }
    }
}

impl AccessPreset {
    pub(super) const ALL: [Self; 3] =
        [Self::FullyClosed, Self::Developer, Self::MostlyOpen];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::FullyClosed => "Fully closed",
            Self::Developer => "For developers",
            Self::MostlyOpen => "Mostly open",
        }
    }
}

impl CapabilityId {
    pub(super) const ALL: [Self; 13] = [
        Self::ModelApi,
        Self::HarnessState,
        Self::Dependencies,
        Self::FullSsh,
        Self::RestrictedSsh,
        Self::FullGithub,
        Self::ContainerEngine,
        Self::UnrestrictedNetwork,
        Self::Loopback,
        Self::Environment,
        Self::DirectoryAccess,
        Self::Additional,
        Self::Review,
    ];
    pub(super) const fn key(self) -> char {
        match self {
            Self::ModelApi => '1',
            Self::HarnessState => '2',
            Self::Dependencies => '3',
            Self::FullSsh => '4',
            Self::RestrictedSsh => 'k',
            Self::FullGithub => '5',
            Self::ContainerEngine => 'c',
            Self::UnrestrictedNetwork => '6',
            Self::Loopback => '7',
            Self::Environment => 'e',
            Self::DirectoryAccess => 'd',
            Self::Additional => 'a',
            Self::Review => 's',
        }
    }
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::ModelApi => "Filtered model API access",
            Self::HarnessState => "Host harness login/state",
            Self::Dependencies => "Dependency tools and download hosts",
            Self::FullSsh => "Full host SSH access",
            Self::RestrictedSsh => "Selected SSH keys (fresh agent)",
            Self::FullGithub => "Full host GitHub token",
            Self::ContainerEngine => "Host container engine (Docker/Podman)",
            Self::UnrestrictedNetwork => "Network: unrestricted (OPEN)",
            Self::Loopback => "All host loopback services (macOS)",
            Self::Environment => "Environment variables (names only)",
            Self::DirectoryAccess => "Directory access",
            Self::Additional => "Additional capabilities",
            Self::Review => "Save configuration",
        }
    }

    pub(super) const fn use_when(self) -> &'static str {
        match self {
            Self::ModelApi => "The harness needs its hosted model API.",
            Self::HarnessState => {
                "You want to reuse the host login and persist harness settings or history."
            }
            Self::Dependencies => {
                "The project needs package managers, registries, or development tools."
            }
            Self::FullSsh => {
                "The harness must use arbitrary host SSH identities and selected-key SSH is too narrow."
            }
            Self::RestrictedSsh => {
                "The harness needs SSH or Git access to specific known destinations."
            }
            Self::FullGithub => {
                "The harness must use gh across everything your current token can access."
            }
            Self::ContainerEngine => {
                "The harness must build, run, inspect, or debug host Docker/Podman workloads."
            }
            Self::UnrestrictedNetwork => {
                "The task needs destinations that cannot be expressed as a small reviewed host list."
            }
            Self::Loopback => {
                "A macOS task must reach an existing service on host localhost."
            }
            Self::Environment => {
                "A tool needs specific host configuration or credential variables."
            }
            Self::DirectoryAccess => {
                "The task needs files outside the project directory."
            }
            Self::Additional => {
                "The task needs a less common host integration, device, credential store, or compatibility grant."
            }
            Self::Review => "You are ready to save these choices and continue.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Screen {
    WrapperRequests,
    Access,
    RestrictedSsh,
    Environment,
    DirectoryPicker { writable: bool },
    Additional,
}
impl Screen {
    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::WrapperRequests => "Wrapper requests",
            Self::Access => "Access choices",
            Self::RestrictedSsh => "Selected SSH keys",
            Self::Environment => "Environment variables",
            Self::DirectoryPicker { writable: false } => "Read-only directory",
            Self::DirectoryPicker { writable: true } => "Read/write directory",
            Self::Additional => "Additional capabilities",
        }
    }
    pub(super) const fn placeholder(self) -> &'static str {
        match self {
            Self::WrapperRequests => "",
            Self::RestrictedSsh => {
                "The selected-key identity and destination editor opens here. Private keys and the ambient host agent remain outside the jail."
            }
            Self::Environment => {
                "The searchable environment-name selector opens here. Values remain hidden."
            }
            Self::DirectoryPicker { writable: false } => {
                "The read-only directory browser opens here."
            }
            Self::DirectoryPicker { writable: true } => {
                "The read/write directory browser opens here."
            }
            Self::Additional => {
                "Less common host integrations and security-sensitive compatibility grants open here."
            }
            Self::Access => "",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ConfirmMode {
    Open {
        capability: CapabilityId,
        dialog: ConfirmDialog,
    },
    MostlyOpen {
        dialog: ConfirmDialog,
    },
    AdditionalOpen {
        capability: AdditionalCapability,
        dialog: ConfirmDialog,
    },
    SaveWithGithub {
        save_only: bool,
        dialog: ConfirmDialog,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppExit {
    Cancel,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Transition {
    Stay,
    PrepareSave { save_only: bool },
    Exit(AppExit),
}

pub(super) struct App<'a> {
    pub(super) selection: &'a mut Selection,
    pub(super) harness: String,
    pub(super) project: String,
    pub(super) profile_path: String,
    /// Set only when the policy root differs from the launch directory.
    pub(super) policy_root: Option<String>,
    pub(super) screen: Screen,
    pub(super) wrapper: Option<WrapperReview>,
    pub(super) directory: Option<DirectoryBrowser>,
    pub(super) environment: Option<EnvironmentSelector>,
    pub(super) ssh: Option<SshEditor>,
    pub(super) additional: Option<AdditionalState>,
    ssh_identities: Vec<crate::ssh_restricted::KeyIdentity>,
    project_path: PathBuf,
    pub(super) approved_wrapper_requests: Vec<RequestApproval>,
    pub(super) selected: usize,
    pub(super) confirmation: Option<ConfirmMode>,
    pub(super) exit_dialog: Option<ExitDialog>,
    pub(super) feedback: String,
    pub(super) detail_scroll: u16,
    pub(super) viewport_safe: bool,
    pub(super) use_color: bool,
    pub(super) recommended_baseline: bool,
    pub(super) preset_focus: bool,
    pub(super) preset_preview: bool,
    pub(super) preset_cursor: usize,
    pub(super) protection_focus: bool,
    pub(super) protection_selected: usize,
    github_open_confirmed: bool,
    initial_selection: Selection,
    initial_approved_wrapper_requests: Vec<RequestApproval>,
}

impl<'a> App<'a> {
    pub(super) fn new(
        selection: &'a mut Selection,
        harness: &str,
        project: String,
        use_color: bool,
        requests: &RequestSet,
        approved_wrapper_requests: &[RequestApproval],
    ) -> Self {
        let initial_selection = selection.clone();
        let github_open_confirmed = selection.github;
        let initial_approved_wrapper_requests =
            approved_wrapper_requests.to_vec();
        if !requests.items.is_empty() {
            for approval in approved_wrapper_requests {
                revoke_wrapper_request(selection, approval);
            }
        }
        let wrapper = WrapperReview::new(requests, approved_wrapper_requests);
        let project_path = PathBuf::from(&project);
        Self {
            selection,
            harness: harness.into(),
            project,
            profile_path: "[external profile path unavailable]".into(),
            policy_root: None,
            screen: if wrapper.is_some() {
                Screen::WrapperRequests
            } else {
                Screen::Access
            },
            wrapper,
            directory: None,
            environment: None,
            ssh: None,
            additional: None,
            ssh_identities: Vec::new(),
            project_path,
            approved_wrapper_requests: approved_wrapper_requests.to_vec(),
            selected: 0,
            confirmation: None,
            exit_dialog: None,
            feedback: String::new(),
            detail_scroll: 0,
            viewport_safe: true,
            use_color,
            recommended_baseline: false,
            preset_focus: false,
            preset_preview: false,
            preset_cursor: 1,
            protection_focus: false,
            protection_selected: 0,
            github_open_confirmed,
            initial_selection,
            initial_approved_wrapper_requests,
        }
    }

    pub(super) fn has_unsaved_changes(&self) -> bool {
        self.recommended_baseline
            || *self.selection != self.initial_selection
            || self.approved_wrapper_requests
                != self.initial_approved_wrapper_requests
    }

    pub(super) fn set_recommended_baseline(&mut self, enabled: bool) {
        self.recommended_baseline = enabled;
        if enabled && self.selection.github {
            self.github_open_confirmed = false;
        }
    }

    fn request_save(&mut self, save_only: bool) -> Transition {
        if self.selection.github && !self.github_open_confirmed {
            self.confirmation = Some(ConfirmMode::SaveWithGithub {
                save_only,
                dialog: ConfirmDialog::new(
                    "Save with full GitHub access?",
                    "The active host gh token is OPEN: the harness can use every repository and organization permission carried by that token, not only this project.",
                    "Save with OPEN GitHub",
                ),
            });
            Transition::Stay
        } else {
            Transition::PrepareSave { save_only }
        }
    }

    fn request_exit(&mut self) -> Transition {
        if self.has_unsaved_changes() {
            self.exit_dialog = Some(ExitDialog::new());
            Transition::Stay
        } else {
            Transition::Exit(AppExit::Cancel)
        }
    }

    fn handle_exit_dialog(&mut self, code: KeyCode) -> Transition {
        let Some(mut dialog) = self.exit_dialog.take() else {
            return Transition::Stay;
        };
        match dialog.handle_key(code) {
            ExitDialogAction::Stay => {
                self.exit_dialog = Some(dialog);
                Transition::Stay
            }
            ExitDialogAction::KeepEditing => {
                self.feedback = "Unsaved changes kept for editing.".into();
                Transition::Stay
            }
            ExitDialogAction::Discard => Transition::Exit(AppExit::Cancel),
            ExitDialogAction::Save => self.request_save(true),
        }
    }
    pub(super) fn resize(&mut self, width: u16, height: u16) {
        self.viewport_safe = width >= MIN_WIDTH && height >= MIN_HEIGHT;
    }
    pub(super) fn set_project_path(&mut self, project: &Path) {
        self.project_path = project.to_path_buf();
    }
    pub(super) fn set_profile_path(&mut self, path: &Path) {
        self.profile_path = safe_path(path)
            .unwrap_or_else(|_| "[invalid profile path refused]".into());
    }
    pub(super) fn selected_capability(&self) -> CapabilityId {
        CapabilityId::ALL[self.selected]
    }
    pub(super) fn selected_protection(&self) -> BuiltinProtection {
        BuiltinProtection::ALL[self.protection_selected]
    }

    pub(super) fn cli_equivalent(&self) -> String {
        self.cli_equivalent_inner(false)
    }

    pub(super) fn cli_equivalent_display(&self) -> String {
        self.cli_equivalent_inner(true)
    }

    fn cli_equivalent_inner(&self, display_safe: bool) -> String {
        fn quote(value: &str, display_safe: bool) -> String {
            let escaped;
            let value = if display_safe {
                escaped = escape_control_bytes(value);
                escaped.as_str()
            } else {
                value
            };
            if !value.is_empty()
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(
                            character,
                            '_' | '-' | '.' | '/' | ':' | '@'
                        )
                })
            {
                value.into()
            } else {
                format!("'{}'", value.replace('\'', "'\\''"))
            }
        }
        fn path_option(
            parts: &mut Vec<String>,
            notes: &mut Vec<String>,
            option: &str,
            path: &Path,
            display_safe: bool,
        ) {
            if let Some(path) = path.to_str() {
                parts.push(option.into());
                parts.push(quote(path, display_safe));
            } else {
                notes.push(format!(
                    "Profile-only: one {option} path is not valid UTF-8."
                ));
            }
        }

        let mut parts = vec!["ai-jail".into()];
        let mut notes = Vec::new();
        if !self.selection.agent_state {
            parts.push("--no-agent-state".into());
        }
        if !self.selection.dependency_hosts {
            parts.push("--no-mise".into());
            parts.push("--no-toolchains".into());
        }
        if self.selection.ssh {
            parts.push("--ssh".into());
        }
        if self.selection.github {
            parts.push("--github".into());
        }
        if self.selection.container_engine {
            parts.push("--docker".into());
        }
        if self.selection.unrestricted_network {
            parts.push("--network".into());
        }
        if self.selection.loopback_connect {
            parts.push("--allow-loopback-connect".into());
        }
        if !self.selection.unrestricted_network {
            let automatic_api_hosts = api_hosts(&self.harness);
            let suppress_automatic_hosts =
                !self.selection.api_access && !automatic_api_hosts.is_empty();
            if suppress_automatic_hosts {
                parts.push("--no-network".into());
                #[cfg(target_os = "linux")]
                if self.selection.dependency_hosts {
                    for host in crate::sandbox::TOOLCHAIN_REGISTRY_HOSTS {
                        parts.push("--allow-host".into());
                        parts.push(quote(host, display_safe));
                    }
                }
            }
            for host in &self.selection.requested_hosts {
                parts.push("--allow-host".into());
                parts.push(quote(host, display_safe));
            }
            for host in &self.selection.requested_private_hosts {
                parts.push("--allow-private-host".into());
                parts.push(quote(host, display_safe));
            }
            for (name, host) in &self.selection.requested_secrets {
                parts.push("--secret".into());
                parts.push(quote(&format!("{name}={host}"), display_safe));
            }
        }
        for name in &self.selection.env_names {
            parts.push("--env".into());
            parts.push(quote(name, display_safe));
        }
        for path in &self.selection.ro_dirs {
            path_option(&mut parts, &mut notes, "--map", path, display_safe);
        }
        for path in &self.selection.rw_dirs {
            path_option(&mut parts, &mut notes, "--rw-map", path, display_safe);
        }

        let additional = &self.selection.additional;
        let mut enabled_flag = |enabled: bool, flag: &str| {
            if enabled {
                parts.push(flag.into());
            }
        };
        enabled_flag(additional.share_host_home, "--no-private-home");
        enabled_flag(additional.lockdown, "--lockdown");
        enabled_flag(additional.systemd_user, "--systemd-user");
        enabled_flag(additional.gpu, "--gpu");
        enabled_flag(additional.tailscale, "--tailscale");
        enabled_flag(additional.display, "--display");
        enabled_flag(additional.audio, "--audio");
        enabled_flag(additional.kvm, "--kvm");
        enabled_flag(additional.x11, "--x11");
        enabled_flag(additional.host_shm, "--host-shm");
        enabled_flag(additional.terminal_passthrough, "--terminal-passthrough");
        enabled_flag(additional.terminal_appearance, "--terminal-appearance");
        enabled_flag(
            additional.explicit && !additional.terminal_appearance,
            "--no-terminal-appearance",
        );
        enabled_flag(additional.aws, "--aws");
        enabled_flag(additional.kube, "--kube");
        enabled_flag(additional.gcloud, "--gcloud");
        enabled_flag(additional.docker_config, "--docker-config");
        enabled_flag(additional.macos_host_ipc, "--macos-host-ipc");
        enabled_flag(additional.macos_chromium, "--macos-chromium");
        enabled_flag(additional.macos_trustd, "--macos-trustd");
        enabled_flag(additional.allow_pty, "--allow-pty");
        enabled_flag(
            additional.allow_loopback_listen,
            "--allow-loopback-listen",
        );
        enabled_flag(additional.inherit_env, "--inherit-env");
        enabled_flag(additional.worktree, "--worktree");
        enabled_flag(additional.pictures, "--pictures");
        enabled_flag(additional.audit_log, "--audit-log");

        if self.selection.restricted_ssh.is_some() {
            notes.push(
                "Profile-only: selected-key SSH cannot be expressed as launch flags; keep the saved profile."
                    .into(),
            );
        }
        if !self.approved_wrapper_requests.is_empty() {
            notes.push(
                "Profile-only: approved wrapper requests require their trusted request manifest."
                    .into(),
            );
        }
        parts.push(quote(&self.harness, display_safe));
        let mut output = parts.join(" ");
        for note in notes {
            output.push('\n');
            output.push_str("# ");
            output.push_str(&note);
        }
        output
    }
    pub(super) fn grant(&self, c: CapabilityId) -> Option<GrantSpec> {
        match c {
            CapabilityId::ModelApi => {
                Some(api_grant(&self.harness, api_hosts(&self.harness), None))
            }
            CapabilityId::HarnessState => {
                Some(state_grant(&self.harness, None))
            }
            CapabilityId::Dependencies => {
                Some(dependency_grant(&self.harness, None))
            }
            CapabilityId::FullSsh => {
                Some(open_grant("ssh", &self.harness, None))
            }
            CapabilityId::FullGithub => {
                Some(open_grant("github", &self.harness, None))
            }
            CapabilityId::ContainerEngine => {
                Some(open_grant("container-engine", &self.harness, None))
            }
            CapabilityId::UnrestrictedNetwork => {
                Some(open_grant("network", &self.harness, None))
            }
            CapabilityId::Loopback => {
                Some(open_grant("loopback-connect", &self.harness, None))
            }
            _ => None,
        }
    }

    pub(super) fn detail(&self, c: CapabilityId) -> String {
        let saved = "This run. Saving keeps this choice for this project.";
        let detail = match c {
            CapabilityId::ModelApi => {
                let hosts = api_hosts(&self.harness);
                if hosts.is_empty() {
                    format!(
                        "Allows\nNo model API is known for {}. This choice adds no destination.\n\n{saved}",
                        self.harness
                    )
                } else {
                    format!(
                        "Allows\n{} and its child processes can connect only to {} and subdomains.\n\nStill blocked\nOther hosts, private IP addresses, and localhost.\n\nRisk\nThese API services can receive prompts and any jail data the process sends.\n\n{saved}",
                        self.harness,
                        hosts.join(", ")
                    )
                }
            }
            CapabilityId::HarnessState => {
                let resource = state_grant(&self.harness, None).resource;
                format!(
                    "Shares\n{resource}.\n\nAllows\n{} and its child processes can use the host login and update that state.\n\nRisk\nSessions and detected API keys can be copied; host state can be changed.\n\n{saved}",
                    self.harness
                )
            }
            CapabilityId::Dependencies => format!(
                "Allows\n{} and its child processes can use development tools, persistent jail-only caches, and standard package registries.\n\nStill private\nYour real host dependency caches are not shared.\n\nRisk\nRegistries can receive readable jail data, and downloaded packages run inside the jail.\n\n{saved}",
                self.harness
            ),
            CapabilityId::FullSsh => format!(
                "OPEN access\n{} and its child processes can read every file in ~/.ssh and use every key in your host SSH agent.\n\nScope\nAny SSH account accepted by those keys.\n\nRisk\nPrivate keys can be copied and agent signatures can impersonate you.\n\n{saved}",
                self.harness
            ),
            CapabilityId::RestrictedSsh => {
                let selected = self
                    .selection
                    .restricted_ssh
                    .as_ref()
                    .map(|policy| {
                        let keys = policy
                            .keys
                            .iter()
                            .map(|key| {
                                format!(
                                    "• {}  {}",
                                    key.fingerprint,
                                    safe_path(&key.public_path).unwrap_or_else(
                                        |_| "[invalid path refused]".into()
                                    )
                                )
                            })
                            .collect::<Vec<_>>();
                        let destinations = policy
                            .destinations
                            .iter()
                            .map(|destination| {
                                format!(
                                    "• {}",
                                    escape_control_bytes(destination)
                                )
                            })
                            .collect::<Vec<_>>();
                        format!(
                            "Selected keys\n{}\n\nDestinations\n{}\n\nLifetime\n{} seconds",
                            if keys.is_empty() {
                                "None".into()
                            } else {
                                keys.join("\n")
                            },
                            if destinations.is_empty() {
                                "None".into()
                            } else {
                                destinations.join("\n")
                            },
                            policy.lifetime_seconds
                        )
                    })
                    .unwrap_or_else(|| {
                        "Selected keys\nNone\n\nDestinations\nNone".into()
                    });
                format!(
                    "{selected}\n\nTo change\nPress Enter or Space to add or remove keys and destinations.\n\nStill private\nPrivate-key files and your normal host agent never enter the jail.\n\nAlso needed\nSSH network access must be enabled separately."
                )
            }
            CapabilityId::FullGithub => format!(
                "OPEN access\n{} and its child processes can use and copy your active github.com gh token.\n\nScope\nEvery repository and organization that token can access—not only this project.\n\nRisk\nA jailed process can act on GitHub with all permissions carried by the token.\n\n{saved}",
                self.harness
            ),
            CapabilityId::ContainerEngine => format!(
                "OPEN access\n{} and its child processes can control the host Docker or Podman daemon through its Unix socket.\n\nScope\nEvery container, image, volume, network, and host path that daemon can access.\n\nRisk\nThe process can mount host paths or start privileged containers, effectively bypassing the jail. Rootless engines reduce privilege but still expose the daemon user's authority.\n\n{saved}",
                self.harness
            ),
            CapabilityId::UnrestrictedNetwork => format!(
                "OPEN access\n{} and its child processes can connect to any public, private, or local-network destination.\n\nWhen closed\nSelected model APIs and package registries may still work through filtered access. Fully closed blocks all destinations.\n\nRisk\nAny readable jail data can be sent to any reachable service.\n\n{saved}",
                self.harness
            ),
            CapabilityId::Loopback => format!(
                "OPEN access — macOS only\n{} and its child processes can connect to every service and port on the host's localhost interface.\n\nRisk\nLocal services may trust localhost and have no authentication. Prefer one forwarded port when possible.\n\n{saved}",
                self.harness
            ),
            CapabilityId::Environment => {
                let selected = if self.selection.env_names.is_empty() {
                    "None".into()
                } else {
                    self.selection
                        .env_names
                        .iter()
                        .map(|name| format!("• {name}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                format!(
                    "Selected names — values hidden\n{selected}\n\nTo change\nPress Enter or Space to add or remove names. Values never appear here or in the saved profile.\n\nRisk\nEvery jailed child process can read and copy an approved value."
                )
            }
            CapabilityId::DirectoryAccess => {
                let mut selected = self
                    .selection
                    .ro_dirs
                    .iter()
                    .map(|path| {
                        format!(
                            "• READ-ONLY  {}",
                            safe_path(path)
                                .unwrap_or_else(|_| "[invalid path refused]".into())
                        )
                    })
                    .chain(self.selection.rw_dirs.iter().map(|path| {
                        format!(
                            "• READ/WRITE {}",
                            safe_path(path)
                                .unwrap_or_else(|_| "[invalid path refused]".into())
                        )
                    }))
                    .collect::<Vec<_>>();
                selected.sort();
                let selected = if selected.is_empty() {
                    "None beyond the project directory".into()
                } else {
                    selected.join("\n")
                };
                format!(
                    "Selected extra directories\n{selected}\n\nTo change\nPress Enter or Space to add, remove, or change access.\n\nSafety\nCredential folders are refused. Broad folders require OPEN approval."
                )
            }
            CapabilityId::Additional => {
                let enabled = AdditionalCapability::available()
                    .into_iter()
                    .filter(|capability| {
                        capability.enabled(&self.selection.additional)
                    })
                    .map(|capability| {
                        let state = match capability.risk() {
                            Risk::Allowed => "ALLOWED",
                            Risk::Open => "OPEN",
                        };
                        format!("• {state}  {}", capability.label())
                    })
                    .collect::<Vec<_>>();
                let enabled = if enabled.is_empty() {
                    "None".into()
                } else {
                    enabled.join("\n")
                };
                format!(
                    "Enabled additional capabilities\n{enabled}\n\nTo change\nPress Enter or Space to add or remove capabilities.\n\nSafety\nNothing here is enabled by a preset. Broad grants require an explicit OPEN dialog."
                )
            }
            CapabilityId::Review => {
                "Save the choices shown in this screen. Normal onboarding then launches the harness; `ai-jail configure` saves and exits."
                    .into()
            }
        };
        format!("{detail}\n\nUse when\n{}", c.use_when())
    }

    pub(super) fn enabled(&self, c: CapabilityId) -> bool {
        match c {
            CapabilityId::ModelApi => self.selection.api_access,
            CapabilityId::HarnessState => self.selection.agent_state,
            CapabilityId::Dependencies => self.selection.dependency_hosts,
            CapabilityId::FullSsh => self.selection.ssh,
            CapabilityId::RestrictedSsh => {
                self.selection.restricted_ssh.is_some()
            }
            CapabilityId::FullGithub => self.selection.github,
            CapabilityId::ContainerEngine => self.selection.container_engine,
            CapabilityId::UnrestrictedNetwork => {
                self.selection.unrestricted_network
            }
            CapabilityId::Loopback => self.selection.loopback_connect,
            _ => false,
        }
    }

    pub(super) fn displayed_enabled(&self, c: CapabilityId) -> bool {
        if self.preset_focus && self.preset_preview {
            return self
                .preset_enabled(AccessPreset::ALL[self.preset_cursor], c);
        }
        self.enabled(c)
    }

    pub(super) fn active_preset(&self) -> Option<AccessPreset> {
        AccessPreset::ALL
            .into_iter()
            .find(|preset| self.selection_matches_preset(*preset))
    }

    fn has_granular_access(&self) -> bool {
        !self.selection.ro_dirs.is_empty()
            || !self.selection.rw_dirs.is_empty()
            || !self.selection.env_names.is_empty()
            || !self.selection.requested_hosts.is_empty()
            || !self.selection.requested_private_hosts.is_empty()
            || !self.selection.requested_secrets.is_empty()
            || self.selection.restricted_ssh.is_some()
            || self.selection.additional.any_enabled()
            || !self.approved_wrapper_requests.is_empty()
    }

    fn preset_enabled(&self, preset: AccessPreset, c: CapabilityId) -> bool {
        match preset {
            AccessPreset::FullyClosed => false,
            AccessPreset::Developer => match c {
                CapabilityId::ModelApi => !api_hosts(&self.harness).is_empty(),
                CapabilityId::HarnessState
                | CapabilityId::Dependencies
                | CapabilityId::FullGithub => true,
                _ => false,
            },
            AccessPreset::MostlyOpen => match c {
                CapabilityId::ModelApi => !api_hosts(&self.harness).is_empty(),
                CapabilityId::HarnessState
                | CapabilityId::Dependencies
                | CapabilityId::FullSsh
                | CapabilityId::FullGithub
                | CapabilityId::UnrestrictedNetwork
                | CapabilityId::Loopback => true,
                _ => false,
            },
        }
    }

    fn selection_matches_preset(&self, preset: AccessPreset) -> bool {
        if self.has_granular_access() {
            return false;
        }
        CapabilityId::ALL
            .into_iter()
            .all(|capability| match capability {
                CapabilityId::Environment
                | CapabilityId::DirectoryAccess
                | CapabilityId::Additional
                | CapabilityId::Review => true,
                _ => {
                    self.enabled(capability)
                        == self.preset_enabled(preset, capability)
                }
            })
    }

    fn apply_preset(&mut self, preset: AccessPreset) {
        *self.selection = Selection::default();
        self.selection.additional.explicit = true;
        self.approved_wrapper_requests.clear();
        match preset {
            AccessPreset::FullyClosed => {}
            AccessPreset::Developer => {
                self.selection.api_access =
                    !api_hosts(&self.harness).is_empty();
                self.selection.agent_state = true;
                self.selection.dependency_hosts = true;
                self.selection.github = true;
                self.github_open_confirmed = false;
            }
            AccessPreset::MostlyOpen => {
                self.selection.api_access =
                    !api_hosts(&self.harness).is_empty();
                self.selection.agent_state = true;
                self.selection.dependency_hosts = true;
                self.selection.ssh = true;
                self.selection.github = true;
                self.selection.unrestricted_network = true;
                self.selection.loopback_connect = true;
            }
        }
        self.preset_focus = false;
        self.preset_preview = false;
        self.feedback = format!("Applied {} preset.", preset.label());
    }

    fn activate_preset(&mut self) {
        let preset = AccessPreset::ALL[self.preset_cursor];
        if preset == AccessPreset::MostlyOpen {
            self.confirmation = Some(ConfirmMode::MostlyOpen {
                dialog: ConfirmDialog::new(
                    "Apply Mostly open?",
                    "This opens unrestricted network, the full host GitHub token, the ambient SSH agent, and host loopback services. It clears selected directories, environment variables, selected-key SSH, and wrapper approvals. The resulting OPEN choices remain visible in the access list.",
                    "Apply Mostly open",
                ),
            });
        } else {
            self.apply_preset(preset);
        }
    }

    fn focus_presets(&mut self) {
        self.protection_focus = false;
        self.preset_focus = true;
        self.preset_preview = false;
        self.preset_cursor = self
            .active_preset()
            .and_then(|active| {
                AccessPreset::ALL
                    .iter()
                    .position(|preset| *preset == active)
            })
            .unwrap_or(1);
        self.feedback.clear();
    }
    fn set_enabled(&mut self, c: CapabilityId, on: bool) {
        match c {
            CapabilityId::ModelApi => self.selection.api_access = on,
            CapabilityId::HarnessState => self.selection.agent_state = on,
            CapabilityId::Dependencies => self.selection.dependency_hosts = on,
            CapabilityId::FullSsh => {
                self.selection.ssh = on;
                if on {
                    self.selection.restricted_ssh = None;
                }
            }
            CapabilityId::FullGithub => self.selection.github = on,
            CapabilityId::ContainerEngine => {
                self.selection.container_engine = on
            }
            CapabilityId::UnrestrictedNetwork => {
                self.selection.unrestricted_network = on
            }
            CapabilityId::Loopback => self.selection.loopback_connect = on,
            _ => {}
        }
    }
    #[allow(dead_code)]
    pub(super) fn apply_restricted_ssh(
        &mut self,
        p: Option<crate::ssh_restricted::Policy>,
    ) {
        self.selection.restricted_ssh = p;
        if self.selection.restricted_ssh.is_some() {
            self.selection.ssh = false;
        }
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> Transition {
        if self.exit_dialog.is_some() {
            return self.handle_exit_dialog(code);
        }
        if !self.viewport_safe {
            return match code {
                KeyCode::Char('q') => self.request_exit(),
                KeyCode::Esc if self.screen == Screen::WrapperRequests => {
                    self.request_exit()
                }
                KeyCode::Esc => {
                    if self.screen == Screen::Access {
                        self.request_exit()
                    } else {
                        self.screen = Screen::Access;
                        self.feedback =
                            "Resize the terminal to continue.".into();
                        Transition::Stay
                    }
                }
                _ => Transition::Stay,
            };
        }
        if self.screen == Screen::WrapperRequests {
            return self.handle_wrapper(code);
        }
        match self.screen {
            Screen::RestrictedSsh => return self.handle_ssh(code),
            Screen::Environment => return self.handle_environment(code),
            Screen::DirectoryPicker { .. } => {
                return self.handle_directory(code);
            }
            Screen::Additional => return self.handle_additional(code),
            _ => {}
        }
        if code == KeyCode::Char('q') {
            return self.request_exit();
        }
        debug_assert_eq!(self.screen, Screen::Access);
        if let Some(confirm) = self.confirmation.take() {
            if matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
                self.confirmation = Some(confirm);
                self.detail_scroll = match code {
                    KeyCode::PageUp => self.detail_scroll.saturating_sub(3),
                    KeyCode::PageDown => self
                        .detail_scroll
                        .saturating_add(3)
                        .min(MAX_DETAIL_SCROLL),
                    _ => self.detail_scroll,
                };
                return Transition::Stay;
            }
            return self.handle_confirmation(confirm, code);
        }
        if code == KeyCode::Char('y') {
            self.feedback = match copy_to_clipboard(&self.cli_equivalent()) {
                Ok(helper) => {
                    format!("Copied CLI from defaults with {helper}.")
                }
                Err(error) => error,
            };
            return Transition::Stay;
        }
        if self.protection_focus {
            match code {
                KeyCode::Tab => self.focus_presets(),
                KeyCode::BackTab | KeyCode::Esc | KeyCode::Left => {
                    self.protection_focus = false;
                    self.feedback.clear();
                }
                KeyCode::Up => {
                    self.protection_selected =
                        self.protection_selected.saturating_sub(1);
                    self.reset_detail();
                }
                KeyCode::Down => {
                    self.protection_selected = (self.protection_selected + 1)
                        .min(BuiltinProtection::ALL.len() - 1);
                    self.reset_detail();
                }
                KeyCode::Home => {
                    self.protection_selected = 0;
                    self.reset_detail();
                }
                KeyCode::End => {
                    self.protection_selected = BuiltinProtection::ALL.len() - 1;
                    self.reset_detail();
                }
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right => {
                    self.feedback =
                        "Built-in protection; there is nothing to enable."
                            .into();
                }
                _ => {}
            }
            return Transition::Stay;
        }
        if self.preset_focus {
            match code {
                KeyCode::Right => {
                    self.preset_preview = true;
                    self.preset_cursor =
                        (self.preset_cursor + 1) % AccessPreset::ALL.len();
                }
                KeyCode::Left => {
                    self.preset_preview = true;
                    self.preset_cursor = if self.preset_cursor == 0 {
                        AccessPreset::ALL.len() - 1
                    } else {
                        self.preset_cursor - 1
                    };
                }
                KeyCode::Tab => {
                    self.preset_focus = false;
                    self.preset_preview = false;
                    self.feedback.clear();
                }
                KeyCode::BackTab => {
                    self.preset_focus = false;
                    self.preset_preview = false;
                    self.protection_focus = true;
                    self.feedback.clear();
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.activate_preset(),
                KeyCode::Down | KeyCode::Esc => {
                    self.preset_focus = false;
                    self.preset_preview = false;
                    self.feedback =
                        "Preset preview closed without applying it.".into();
                }
                _ => {}
            }
            return Transition::Stay;
        }
        match code {
            KeyCode::Tab => {
                self.protection_focus = true;
                self.feedback.clear();
            }
            KeyCode::BackTab => self.focus_presets(),
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                self.reset_detail();
            }
            KeyCode::Down => {
                self.selected =
                    (self.selected + 1).min(CapabilityId::ALL.len() - 1);
                self.reset_detail();
            }
            KeyCode::Home => {
                self.selected = 0;
                self.reset_detail();
            }
            KeyCode::End => {
                self.selected = CapabilityId::ALL.len() - 1;
                self.reset_detail();
            }
            KeyCode::PageUp => {
                self.detail_scroll = self.detail_scroll.saturating_sub(3)
            }
            KeyCode::PageDown => {
                self.detail_scroll =
                    self.detail_scroll.saturating_add(3).min(MAX_DETAIL_SCROLL)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                return self.activate(self.selected_capability());
            }
            KeyCode::Esc => {
                return self.request_exit();
            }
            KeyCode::Char(v) => {
                if let Some(i) =
                    CapabilityId::ALL.iter().position(|c| c.key() == v)
                {
                    self.selected = i;
                    self.reset_detail();
                    return self.activate(CapabilityId::ALL[i]);
                }
            }
            _ => {}
        }
        Transition::Stay
    }
    fn handle_wrapper(&mut self, code: KeyCode) -> Transition {
        let Some(wrapper) = &mut self.wrapper else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        match wrapper.handle_key(code) {
            WrapperAction::Stay => Transition::Stay,
            WrapperAction::Cancel => self.request_exit(),
            WrapperAction::PrepareApprove => {
                let approval = wrapper.selected_request().approval.clone();
                match prepare_wrapper_request(
                    &approval,
                    self.selection,
                    &self.harness,
                    &self.project_path,
                ) {
                    Ok(prepared) => wrapper.begin_approval(
                        prepared.grant().render(),
                        prepared.grant().risk == Risk::Open,
                    ),
                    Err(error) => wrapper.feedback = human_error(error),
                }
                Transition::Stay
            }
            WrapperAction::Complete => {
                let approved = wrapper.approved();
                let mut proposed = self.selection.clone();
                for approval in &approved {
                    let prepared = match prepare_wrapper_request(
                        approval,
                        &proposed,
                        &self.harness,
                        &self.project_path,
                    ) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            wrapper.feedback = human_error(error);
                            return Transition::Stay;
                        }
                    };
                    apply_wrapper_request(&mut proposed, &prepared);
                }
                *self.selection = proposed;
                self.approved_wrapper_requests = approved;
                self.screen = Screen::Access;
                self.feedback = "Wrapper requests reviewed.".into();
                Transition::Stay
            }
        }
    }

    fn open_directory(&mut self, mode: DirectoryMode) {
        let mut browser =
            DirectoryBrowser::new(mode, self.project_path.clone());
        browser.set_grants(
            self.selection
                .ro_dirs
                .iter()
                .cloned()
                .map(|path| DirectoryGrantEntry {
                    path,
                    mode: DirectoryMode::ReadOnly,
                })
                .chain(self.selection.rw_dirs.iter().cloned().map(|path| {
                    DirectoryGrantEntry {
                        path,
                        mode: DirectoryMode::ReadWrite,
                    }
                }))
                .collect(),
        );
        match list_directory(&self.project_path) {
            Ok((current, entries)) => browser.set_entries(
                current,
                entries
                    .into_iter()
                    .map(|(path, name)| DirectoryEntry { path, name })
                    .collect(),
            ),
            Err(error) => browser.set_error(human_error(error)),
        }
        self.directory = Some(browser);
    }

    fn handle_directory(&mut self, code: KeyCode) -> Transition {
        let Some(mut browser) = self.directory.take() else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        let captures_text = browser.captures_text_input();
        let action = browser.handle_key(code);
        if code == KeyCode::Char('q') && !captures_text {
            self.directory = Some(browser);
            return self.request_exit();
        }
        match action {
            DirectoryAction::None => {}
            DirectoryAction::Back => {
                self.screen = Screen::Access;
                return Transition::Stay;
            }
            DirectoryAction::Reload { directory, .. } => {
                match list_directory(&directory) {
                    Ok((current, entries)) => browser.set_entries(
                        current,
                        entries
                            .into_iter()
                            .map(|(path, name)| DirectoryEntry { path, name })
                            .collect(),
                    ),
                    Err(error) => browser.set_error(human_error(error)),
                }
            }
            DirectoryAction::GoTo(value) => match expand_home(&value) {
                Ok(path) => match list_directory(&path) {
                    Ok((current, entries)) => browser.set_entries(
                        current,
                        entries
                            .into_iter()
                            .map(|(path, name)| DirectoryEntry { path, name })
                            .collect(),
                    ),
                    Err(error) => browser.set_error(human_error(error)),
                },
                Err(error) => browser.set_error(human_error(error)),
            },
            DirectoryAction::Prepare { path, mode } => {
                match prepare_directory_candidate(
                    &path,
                    mode == DirectoryMode::ReadWrite,
                    self.selection,
                    &self.harness,
                    &self.project_path,
                ) {
                    Ok(candidate) if candidate.grant.risk == Risk::Open => {
                        browser.set_preview(DirectoryPreview {
                            entered: candidate.entered,
                            resolved: candidate.resolved,
                            disclosure: candidate.grant.render(),
                            mode,
                            replaces: None,
                        });
                    }
                    Ok(candidate) => {
                        let resolved = candidate.resolved.clone();
                        apply_directory_candidate(self.selection, &candidate);
                        browser.add_grant(DirectoryGrantEntry {
                            path: resolved.clone(),
                            mode,
                        });
                        browser.set_error(format!(
                            "Added {} access to {}. Tab opens selected directories.",
                            mode.title(),
                            safe_path(&resolved)
                                .unwrap_or_else(|_| "[unsafe path]".into())
                        ));
                    }
                    Err(error) => browser.set_error(human_error(error)),
                }
            }
            DirectoryAction::Apply {
                path,
                mode,
                replaces,
            } => {
                let mut proposed = self.selection.clone();
                if let Some(old) = &replaces {
                    remove_directory_grant(
                        &mut proposed,
                        &old.path,
                        old.mode == DirectoryMode::ReadWrite,
                    );
                }
                match prepare_directory_candidate(
                    &path,
                    mode == DirectoryMode::ReadWrite,
                    &proposed,
                    &self.harness,
                    &self.project_path,
                ) {
                    Ok(candidate) => {
                        let resolved = candidate.resolved.clone();
                        if let Some(old) = &replaces {
                            remove_directory_grant(
                                self.selection,
                                &old.path,
                                old.mode == DirectoryMode::ReadWrite,
                            );
                        }
                        apply_directory_candidate(self.selection, &candidate);
                        let new_entry = DirectoryGrantEntry {
                            path: resolved.clone(),
                            mode,
                        };
                        if let Some(old) = &replaces {
                            browser.replace_grant(old, new_entry);
                        } else {
                            browser.add_grant(new_entry);
                        }
                        browser.set_error(format!(
                            "Set {} access for {}.",
                            mode.title(),
                            safe_path(&resolved)
                                .unwrap_or_else(|_| "[unsafe path]".into())
                        ));
                    }
                    Err(error) => browser.set_error(human_error(error)),
                }
            }
            DirectoryAction::ToggleMode(entry) => {
                let mode = match entry.mode {
                    DirectoryMode::ReadOnly => DirectoryMode::ReadWrite,
                    DirectoryMode::ReadWrite => DirectoryMode::ReadOnly,
                };
                let mut proposed = self.selection.clone();
                remove_directory_grant(
                    &mut proposed,
                    &entry.path,
                    entry.mode == DirectoryMode::ReadWrite,
                );
                match prepare_directory_candidate(
                    &entry.path,
                    mode == DirectoryMode::ReadWrite,
                    &proposed,
                    &self.harness,
                    &self.project_path,
                ) {
                    Ok(candidate)
                        if entry.mode == DirectoryMode::ReadOnly
                            && candidate.grant.risk == Risk::Open =>
                    {
                        browser.set_preview(DirectoryPreview {
                            entered: candidate.entered,
                            resolved: candidate.resolved,
                            disclosure: candidate.grant.render(),
                            mode,
                            replaces: Some(entry),
                        });
                    }
                    Ok(candidate) => {
                        let resolved = candidate.resolved.clone();
                        remove_directory_grant(
                            self.selection,
                            &entry.path,
                            entry.mode == DirectoryMode::ReadWrite,
                        );
                        apply_directory_candidate(self.selection, &candidate);
                        browser.replace_grant(
                            &entry,
                            DirectoryGrantEntry {
                                path: resolved.clone(),
                                mode,
                            },
                        );
                        browser.set_error(format!(
                            "Set {} access for {}.",
                            mode.title(),
                            safe_path(&resolved)
                                .unwrap_or_else(|_| "[unsafe path]".into())
                        ));
                    }
                    Err(error) => browser.set_error(human_error(error)),
                }
            }
            DirectoryAction::Remove(entry) => {
                remove_directory_grant(
                    self.selection,
                    &entry.path,
                    entry.mode == DirectoryMode::ReadWrite,
                );
                browser.remove_grant(&entry);
                browser.set_error(format!(
                    "Removed directory access to {}.",
                    safe_path(&entry.path)
                        .unwrap_or_else(|_| "[unsafe path]".into())
                ));
            }
        }
        self.screen = Screen::DirectoryPicker {
            writable: browser.mode() == DirectoryMode::ReadWrite,
        };
        self.directory = Some(browser);
        Transition::Stay
    }

    fn handle_environment(&mut self, code: KeyCode) -> Transition {
        let Some(selector) = &mut self.environment else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        let captures_text = selector.captures_text_input();
        let action = selector.handle_key(code);
        if code == KeyCode::Char('q') && !captures_text {
            return self.request_exit();
        }
        match action {
            EnvironmentAction::None => {}
            EnvironmentAction::Back => {
                self.screen = Screen::Access;
                self.environment = None;
            }
            EnvironmentAction::Prepare(name) => {
                match prepare_env_candidate(&name, &self.harness) {
                    Ok(grant) => selector.set_preview(name, grant.render()),
                    Err(error) => selector.set_error(human_error(error)),
                }
            }
            EnvironmentAction::Approve(name) => {
                match prepare_env_candidate(&name, &self.harness) {
                    Ok(_) => apply_env_name(self.selection, name),
                    Err(error) => {
                        remove_env_name(self.selection, &name);
                        selector.rollback_approval(&name);
                        selector.set_error(human_error(error));
                    }
                }
            }
            EnvironmentAction::Remove(name) => {
                remove_env_name(self.selection, &name);
            }
        }
        Transition::Stay
    }

    fn identity_row(
        identity: &crate::ssh_restricted::KeyIdentity,
        selected: bool,
    ) -> IdentityRow {
        IdentityRow {
            public_path: safe_path(&identity.public_path)
                .unwrap_or_else(|_| "[unsafe path]".into()),
            fingerprint: crate::output::escape_control_bytes(
                &identity.fingerprint,
            ),
            comment: crate::output::escape_control_bytes(&identity.comment),
            selected,
        }
    }

    fn open_ssh_editor(&mut self) {
        let existing = self.selection.restricted_ssh.clone();
        let mut identities = discover_public_ssh_keys();
        if let Some(policy) = &existing {
            for key in &policy.keys {
                if !identities
                    .iter()
                    .any(|item| item.fingerprint == key.fingerprint)
                {
                    identities.push(key.clone());
                }
            }
        }
        identities
            .sort_by(|left, right| left.public_path.cmp(&right.public_path));
        let mut fingerprints = std::collections::BTreeSet::new();
        identities.retain(|identity| {
            fingerprints.insert(identity.fingerprint.clone())
        });
        let rows = identities
            .iter()
            .map(|identity| {
                let selected = existing.as_ref().is_some_and(|policy| {
                    policy
                        .keys
                        .iter()
                        .any(|key| key.fingerprint == identity.fingerprint)
                });
                Self::identity_row(identity, selected)
            })
            .collect();
        let destinations = existing
            .as_ref()
            .map_or_else(Vec::new, |policy| policy.destinations.clone());
        let lifetime = existing.as_ref().map_or(
            crate::ssh_restricted::DEFAULT_LIFETIME_SECONDS,
            |policy| policy.lifetime_seconds,
        );
        self.ssh_identities = identities;
        self.ssh =
            Some(SshEditor::new(rows, destinations, lifetime, self.use_color));
    }

    fn sync_ssh_policy(&mut self, editor: &SshEditor) {
        let selected = editor.selected_fingerprints();
        let keys = self
            .ssh_identities
            .iter()
            .filter(|identity| selected.contains(&identity.fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        if keys.is_empty() {
            self.selection.restricted_ssh = None;
            return;
        }
        self.selection.restricted_ssh = Some(crate::ssh_restricted::Policy {
            keys,
            destinations: editor.destinations(),
            lifetime_seconds: editor.lifetime_seconds(),
        });
        self.selection.ssh = false;
    }

    fn handle_ssh(&mut self, code: KeyCode) -> Transition {
        let Some(mut editor) = self.ssh.take() else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        let captures_text = editor.captures_text_input();
        let action = editor.handle_key(code);
        if code == KeyCode::Char('q') && !captures_text {
            self.ssh = Some(editor);
            return self.request_exit();
        }
        match action {
            SshAction::Stay => {}
            SshAction::Back => {
                self.screen = Screen::Access;
                return Transition::Stay;
            }
            SshAction::Request(request) => match request {
                SshRequest::DiscoverIdentities => {
                    let selected = editor.selected_fingerprints();
                    let mut identities = discover_public_ssh_keys();
                    for identity in &self.ssh_identities {
                        if selected.contains(&identity.fingerprint)
                            && !identities.iter().any(|candidate| {
                                candidate.fingerprint == identity.fingerprint
                            })
                        {
                            identities.push(identity.clone());
                        }
                    }
                    let rows = identities
                        .iter()
                        .map(|identity| {
                            Self::identity_row(
                                identity,
                                selected.contains(&identity.fingerprint),
                            )
                        })
                        .collect();
                    self.ssh_identities = identities;
                    editor.apply_discovered_identities(rows);
                }
                SshRequest::CapturePath(value) => match expand_home(&value)
                    .and_then(|path| crate::ssh_restricted::capture_key(&path))
                {
                    Ok(identity) => {
                        let row = Self::identity_row(&identity, true);
                        if let Some(existing) =
                            self.ssh_identities.iter_mut().find(|item| {
                                item.fingerprint == identity.fingerprint
                            })
                        {
                            *existing = identity;
                        } else {
                            self.ssh_identities.push(identity);
                        }
                        editor.apply_captured_identity(row);
                        self.sync_ssh_policy(&editor);
                    }
                    Err(error) => editor.apply_error(human_error(error)),
                },
                SshRequest::SetIdentitySelected {
                    fingerprint,
                    selected,
                } => {
                    editor.apply_identity_selected(&fingerprint, selected);
                    self.sync_ssh_policy(&editor);
                }
                SshRequest::ValidateDestinations(destinations) => {
                    match validate_ssh_destinations(destinations) {
                        Ok(destinations) => {
                            editor.apply_destinations(destinations);
                            self.sync_ssh_policy(&editor);
                        }
                        Err(error) => editor.apply_error(human_error(error)),
                    }
                }
                SshRequest::SetLifetime(seconds) => {
                    match validate_ssh_lifetime(seconds) {
                        Ok(seconds) => {
                            editor.apply_lifetime(seconds);
                            self.sync_ssh_policy(&editor);
                        }
                        Err(error) => editor.apply_error(human_error(error)),
                    }
                }
                SshRequest::Disable => {
                    self.selection.restricted_ssh = None;
                    self.screen = Screen::Access;
                    self.feedback = "Selected-key SSH disabled.".into();
                    return Transition::Stay;
                }
            },
        }
        self.ssh = Some(editor);
        Transition::Stay
    }
    fn activate(&mut self, c: CapabilityId) -> Transition {
        let Some(grant) = self.grant(c) else {
            self.screen = match c {
                CapabilityId::RestrictedSsh => {
                    self.open_ssh_editor();
                    Screen::RestrictedSsh
                }
                CapabilityId::Environment => {
                    self.environment = Some(EnvironmentSelector::new(
                        environment_name_catalog(self.selection),
                        self.selection.env_names.clone(),
                    ));
                    Screen::Environment
                }
                CapabilityId::DirectoryAccess => {
                    self.open_directory(DirectoryMode::ReadOnly);
                    Screen::DirectoryPicker { writable: false }
                }
                CapabilityId::Additional => {
                    self.selection.additional.explicit = true;
                    self.additional = Some(AdditionalState::new());
                    Screen::Additional
                }
                CapabilityId::Review => {
                    return self.request_save(false);
                }
                _ => Screen::Access,
            };
            self.feedback.clear();
            return Transition::Stay;
        };
        if self.enabled(c) {
            self.set_enabled(c, false);
            self.feedback = "Grant disabled.".into();
            return Transition::Stay;
        }
        match grant.risk {
            Risk::Allowed => {
                self.set_enabled(c, true);
                self.feedback = "Grant enabled.".into();
            }
            Risk::Open => {
                self.feedback.clear();
                self.confirmation = Some(ConfirmMode::Open {
                    capability: c,
                    dialog: ConfirmDialog::new(
                        "Open this boundary?",
                        format!(
                            "{} removes an important isolation boundary. The resulting OPEN state remains visible in the access list.",
                            c.label()
                        ),
                        "Enable OPEN access",
                    ),
                });
            }
        }
        Transition::Stay
    }
    fn handle_confirmation(
        &mut self,
        c: ConfirmMode,
        code: KeyCode,
    ) -> Transition {
        match c {
            ConfirmMode::Open {
                capability,
                mut dialog,
            } => match dialog.handle_key(code) {
                DialogAction::Confirm => {
                    self.set_enabled(capability, true);
                    if capability == CapabilityId::FullGithub {
                        self.github_open_confirmed = true;
                    }
                    self.feedback = "OPEN grant enabled.".into();
                }
                DialogAction::Cancel => {
                    self.feedback = "Kept CLOSED.".into();
                }
                DialogAction::Stay => {
                    self.confirmation =
                        Some(ConfirmMode::Open { capability, dialog })
                }
            },
            ConfirmMode::MostlyOpen { mut dialog } => {
                match dialog.handle_key(code) {
                    DialogAction::Confirm => {
                        self.apply_preset(AccessPreset::MostlyOpen);
                        self.github_open_confirmed = true;
                    }
                    DialogAction::Cancel => {
                        self.feedback = "Mostly open was not applied.".into();
                    }
                    DialogAction::Stay => {
                        self.confirmation =
                            Some(ConfirmMode::MostlyOpen { dialog });
                    }
                }
            }
            ConfirmMode::AdditionalOpen {
                capability,
                mut dialog,
            } => match dialog.handle_key(code) {
                DialogAction::Confirm => {
                    capability.set(&mut self.selection.additional, true);
                    self.feedback = "OPEN grant enabled.".into();
                }
                DialogAction::Cancel => {
                    self.feedback = "Kept CLOSED.".into();
                }
                DialogAction::Stay => {
                    self.confirmation = Some(ConfirmMode::AdditionalOpen {
                        capability,
                        dialog,
                    });
                }
            },
            ConfirmMode::SaveWithGithub {
                save_only,
                mut dialog,
            } => match dialog.handle_key(code) {
                DialogAction::Confirm => {
                    self.github_open_confirmed = true;
                    return Transition::PrepareSave { save_only };
                }
                DialogAction::Cancel => {
                    self.feedback = "GitHub remains OPEN in the draft; configuration was not saved.".into();
                }
                DialogAction::Stay => {
                    self.confirmation =
                        Some(ConfirmMode::SaveWithGithub { save_only, dialog });
                }
            },
        }
        Transition::Stay
    }

    fn handle_additional(&mut self, code: KeyCode) -> Transition {
        if let Some(confirm) = self.confirmation.take() {
            return self.handle_confirmation(confirm, code);
        }
        let Some(state) = &mut self.additional else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        match code {
            KeyCode::Esc => {
                self.screen = Screen::Access;
                self.additional = None;
            }
            KeyCode::Char('q') => return self.request_exit(),
            KeyCode::Up => {
                state.selected = state.selected.saturating_sub(1);
                state.feedback.clear();
            }
            KeyCode::Down => {
                state.selected = (state.selected + 1)
                    .min(state.capabilities.len().saturating_sub(1));
                state.feedback.clear();
            }
            KeyCode::PageUp => {
                state.selected = state.selected.saturating_sub(5);
                state.feedback.clear();
            }
            KeyCode::PageDown => {
                state.selected = (state.selected + 5)
                    .min(state.capabilities.len().saturating_sub(1));
                state.feedback.clear();
            }
            KeyCode::Home => state.selected = 0,
            KeyCode::End => {
                state.selected = state.capabilities.len().saturating_sub(1)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let capability = state.selected();
                if capability.enabled(&self.selection.additional) {
                    capability.set(&mut self.selection.additional, false);
                    state.feedback = "Grant disabled.".into();
                } else if capability.risk() == Risk::Open {
                    self.confirmation = Some(ConfirmMode::AdditionalOpen {
                        capability,
                        dialog: ConfirmDialog::new(
                            "Open this boundary?",
                            format!(
                                "{} removes an important isolation boundary. The resulting OPEN state remains visible in this screen.",
                                capability.label()
                            ),
                            "Enable OPEN access",
                        ),
                    });
                } else {
                    capability.set(&mut self.selection.additional, true);
                    state.feedback = "Grant enabled.".into();
                }
            }
            _ => {}
        }
        Transition::Stay
    }
    fn reset_detail(&mut self) {
        self.detail_scroll = 0;
        self.feedback.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::WrapperRequest;

    fn wrapper_request(kind: &str, value: &str) -> WrapperRequest {
        WrapperRequest {
            approval: RequestApproval {
                requester: "ai-memory".into(),
                kind: kind.into(),
                value: value.into(),
                host: None,
                writable: None,
                port: None,
            },
            reason: "needed for project memory".into(),
        }
    }

    fn app(s: &mut Selection) -> App<'_> {
        App::new(
            s,
            "claude",
            "/work/project".into(),
            false,
            &RequestSet::default(),
            &[],
        )
    }
    #[test]
    fn catalog_has_all_unique_shortcuts() {
        assert_eq!(CapabilityId::ALL.len(), 13);
        let mut k = CapabilityId::ALL
            .iter()
            .map(|c| c.key())
            .collect::<Vec<_>>();
        k.sort_unstable();
        k.dedup();
        assert_eq!(k.len(), CapabilityId::ALL.len());
        assert!(CapabilityId::ALL.contains(&CapabilityId::Loopback));
    }

    #[test]
    fn allowed_capability_toggles_without_confirmation() {
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &RequestSet::default(),
            &[],
        );
        assert_eq!(app.handle_key(KeyCode::Char('1')), Transition::Stay);
        assert!(app.selection.api_access);
        assert!(app.confirmation.is_none());
        assert_eq!(app.handle_key(KeyCode::Char('1')), Transition::Stay);
        assert!(!app.selection.api_access);
        assert!(app.confirmation.is_none());
    }

    #[test]
    fn every_capability_detail_is_short_plain_and_action_specific() {
        let mut selection = Selection::default();
        let app = app(&mut selection);
        for capability in CapabilityId::ALL {
            let detail = app.detail(capability);
            assert!(!detail.trim().is_empty(), "missing {capability:?} detail");
            assert!(
                detail.contains("Use when\n"),
                "missing use case for {capability:?}: {detail}"
            );
            assert!(
                detail.split_whitespace().count() <= 90,
                "{capability:?} detail is too long: {detail}"
            );
            for internal_label in [
                "Resource:",
                "Access:",
                "Process:",
                "Duration:",
                "Limits:",
                "Default:",
                "Consequence:",
                "Authority:",
                "Remote:",
            ] {
                assert!(
                    !detail.contains(internal_label),
                    "{capability:?} exposes {internal_label}: {detail}"
                );
            }
        }
        let github = app.detail(CapabilityId::FullGithub);
        assert!(github.contains("active github.com gh token"));
        assert!(github.contains("Every repository and organization"));
        assert!(github.contains("all permissions"));
        let api = app.detail(CapabilityId::ModelApi);
        assert!(api.contains("api.anthropic.com"));
        assert!(api.contains("private IP addresses, and localhost"));
    }

    #[test]
    fn main_details_summarize_environment_and_directory_selections() {
        let mut selection = Selection {
            env_names: vec!["GH_TOKEN".into(), "CUSTOM_MODE".into()],
            ro_dirs: vec![PathBuf::from("/srv/reference")],
            rw_dirs: vec![PathBuf::from("/srv/output")],
            restricted_ssh: Some(crate::ssh_restricted::Policy {
                keys: vec![crate::ssh_restricted::KeyIdentity {
                    private_path: PathBuf::from("/keys/id_test"),
                    public_path: PathBuf::from("/keys/id_test.pub"),
                    fingerprint: "SHA256:TEST".into(),
                    comment: "not rendered".into(),
                    private_dev: 1,
                    private_ino: 2,
                    public_dev: 1,
                    public_ino: 3,
                }],
                lifetime_seconds: 900,
                destinations: vec!["git@example.test".into()],
            }),
            ..Selection::default()
        };
        selection.additional.audit_log = true;
        selection.additional.aws = true;
        let app = app(&mut selection);

        let environment = app.detail(CapabilityId::Environment);
        assert!(environment.contains("GH_TOKEN"));
        assert!(environment.contains("CUSTOM_MODE"));
        assert!(environment.contains("values hidden"));
        assert!(environment.contains("Press Enter or Space"));

        let directories = app.detail(CapabilityId::DirectoryAccess);
        assert!(directories.contains("READ-ONLY  /srv/reference"));
        assert!(directories.contains("READ/WRITE /srv/output"));
        assert!(directories.contains("Press Enter or Space"));

        let additional = app.detail(CapabilityId::Additional);
        assert!(additional.contains("ALLOWED  Local security audit log"));
        assert!(additional.contains("OPEN  AWS credentials"));
        assert!(additional.contains("Press Enter or Space"));

        let ssh = app.detail(CapabilityId::RestrictedSsh);
        assert!(ssh.contains("SHA256:TEST  /keys/id_test.pub"));
        assert!(ssh.contains("git@example.test"));
        assert!(ssh.contains("900 seconds"));
        assert!(!ssh.contains("not rendered"));
    }

    #[test]
    fn preset_navigation_previews_access_without_applying_it() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            github: true,
            ..Selection::default()
        };
        let mut app = app(&mut selection);
        assert_eq!(app.active_preset(), Some(AccessPreset::Developer));

        app.handle_key(KeyCode::Tab);
        assert!(app.protection_focus);
        app.handle_key(KeyCode::Tab);
        assert!(app.preset_focus);
        app.handle_key(KeyCode::BackTab);
        assert!(app.protection_focus);
        assert!(!app.preset_focus);
        app.handle_key(KeyCode::Tab);
        assert!(app.preset_focus);
        assert_eq!(app.preset_cursor, 1);
        assert!(!app.preset_preview);
        assert!(!app.displayed_enabled(CapabilityId::FullSsh));
        assert!(app.displayed_enabled(CapabilityId::FullGithub));
        assert!(!app.displayed_enabled(CapabilityId::UnrestrictedNetwork));
        app.handle_key(KeyCode::Right);
        assert!(app.preset_preview);
        assert_eq!(app.preset_cursor, 2);
        assert!(app.displayed_enabled(CapabilityId::FullSsh));
        assert!(app.displayed_enabled(CapabilityId::FullGithub));
        assert!(app.displayed_enabled(CapabilityId::UnrestrictedNetwork));
        assert!(!app.selection.ssh);
        assert!(app.selection.github);
        assert!(!app.selection.unrestricted_network);
    }

    #[test]
    fn tab_focuses_the_preset_row_without_changing_a_custom_checklist() {
        let mut selection = Selection {
            api_access: true,
            loopback_connect: true,
            ..Selection::default()
        };
        let mut app = app(&mut selection);
        assert_eq!(app.active_preset(), None);

        app.handle_key(KeyCode::BackTab);

        assert!(app.preset_focus);
        assert!(!app.preset_preview);
        assert!(app.displayed_enabled(CapabilityId::ModelApi));
        assert!(app.displayed_enabled(CapabilityId::Loopback));
        assert!(!app.displayed_enabled(CapabilityId::FullGithub));
        assert_eq!(app.active_preset(), None);
    }

    #[test]
    fn cli_equivalent_is_shell_safe_and_names_profile_only_choices() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            github: true,
            env_names: vec!["GH_TOKEN".into(), "SPOOF\n\x1b[31m".into()],
            ro_dirs: vec![PathBuf::from("/srv/reference files")],
            restricted_ssh: Some(crate::ssh_restricted::Policy {
                keys: Vec::new(),
                lifetime_seconds: 900,
                destinations: vec!["git@example.test".into()],
            }),
            ..Selection::default()
        };
        selection.additional.explicit = true;
        selection.additional.display = true;
        let app = app(&mut selection);

        let command = app.cli_equivalent();
        assert!(command.starts_with("ai-jail --github"), "{command}");
        assert!(!command.contains("--agent-state"));
        assert!(!command.contains("--allow-host api.anthropic.com"));
        assert!(!command.contains("--no-network"));
        assert!(command.contains("--github"));
        assert!(command.contains("--env GH_TOKEN"));
        assert!(command.contains("--map '/srv/reference files'"));
        assert!(command.contains("--display"));
        assert!(command.ends_with("keep the saved profile."), "{command}");
        assert!(!command.contains("GH_TOKEN="));
        assert!(command.contains("\n\x1b[31m"));

        let displayed = app.cli_equivalent_display();
        assert_eq!(displayed.lines().count(), 2, "{displayed}");
        assert!(!displayed.contains('\x1b'));
        assert!(displayed.contains("SPOOF??[31m"), "{displayed}");
    }

    #[test]
    fn developer_preset_cli_uses_built_in_defaults() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            github: true,
            ..Selection::default()
        };
        let app = app(&mut selection);

        assert_eq!(app.cli_equivalent(), "ai-jail --github claude");
    }

    #[test]
    fn terminal_appearance_cli_preview_tracks_reviewed_grant_and_constraint() {
        let mut selection = Selection::default();
        let app = app(&mut selection);
        assert!(!app.cli_equivalent().contains("terminal-appearance"));
        app.selection.additional.explicit = true;
        assert!(app.cli_equivalent().contains("--no-terminal-appearance"));
        app.selection.additional.terminal_appearance = true;
        let command = app.cli_equivalent();
        assert!(command.contains("--terminal-appearance"));
        assert!(!command.contains("--no-terminal-appearance"));
    }

    #[test]
    fn mostly_open_preset_requires_explicit_dialog_confirmation() {
        let mut selection = Selection {
            env_names: vec!["GH_TOKEN".into()],
            ro_dirs: vec![PathBuf::from("/shared")],
            requested_hosts: vec!["example.com".into()],
            ..Selection::default()
        };
        let mut app = app(&mut selection);
        app.preset_focus = true;
        app.preset_cursor = 2;
        app.handle_key(KeyCode::Enter);
        assert!(matches!(
            &app.confirmation,
            Some(ConfirmMode::MostlyOpen { dialog }) if !dialog.confirm_selected()
        ));
        app.handle_key(KeyCode::Enter);
        assert!(!app.selection.ssh);
        assert!(!app.selection.github);

        app.preset_focus = true;
        app.preset_cursor = 2;
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.active_preset(), Some(AccessPreset::MostlyOpen));
        assert!(app.selection.ssh);
        assert!(app.selection.github);
        assert!(app.selection.unrestricted_network);
        assert!(app.selection.loopback_connect);
        assert!(app.selection.env_names.is_empty());
        assert!(app.selection.ro_dirs.is_empty());
        assert!(app.selection.requested_hosts.is_empty());
    }

    #[test]
    fn mostly_open_preset_saves_a_launchable_network_policy() {
        let mut selection = Selection::default();
        let mut app = app(&mut selection);
        app.apply_preset(AccessPreset::MostlyOpen);
        assert_eq!(app.active_preset(), Some(AccessPreset::MostlyOpen));

        let grants = selection.grants("claude");
        assert!(grants.network_enabled());
        assert!(!grants.has_filtered_hosts());
    }

    #[test]
    fn granular_change_is_reported_as_custom() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            github: true,
            ..Selection::default()
        };
        let mut app = app(&mut selection);
        assert_eq!(app.active_preset(), Some(AccessPreset::Developer));
        app.handle_key(KeyCode::Char('1'));
        assert_eq!(app.active_preset(), None);
    }

    #[test]
    fn fully_closed_preset_clears_every_optional_and_granular_grant() {
        let mut selection = Selection {
            api_access: true,
            agent_state: true,
            dependency_hosts: true,
            ssh: true,
            github: true,
            unrestricted_network: true,
            loopback_connect: true,
            ro_dirs: vec![PathBuf::from("/shared")],
            env_names: vec!["GH_TOKEN".into()],
            requested_hosts: vec!["example.com".into()],
            ..Selection::default()
        };
        let mut app = app(&mut selection);
        app.apply_preset(AccessPreset::FullyClosed);

        assert_eq!(app.active_preset(), Some(AccessPreset::FullyClosed));
        assert!(!app.selection.api_access);
        assert!(!app.selection.agent_state);
        assert!(!app.selection.dependency_hosts);
        assert!(!app.selection.ssh);
        assert!(!app.selection.github);
        assert!(!app.selection.unrestricted_network);
        assert!(!app.selection.loopback_connect);
        assert!(app.selection.ro_dirs.is_empty());
        assert!(app.selection.env_names.is_empty());
        assert!(app.selection.requested_hosts.is_empty());
    }
    #[test]
    fn inline_errors_hide_internal_provenance_ids() {
        assert_eq!(
            human_error("AJ-PATH-002 Refusing credential path".into()),
            "Refusing credential path"
        );
        assert_eq!(
            human_error("Ordinary validation error".into()),
            "Ordinary validation error"
        );
    }
    #[test]
    fn open_dialog_defaults_to_cancel_and_requires_explicit_enable_choice() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('4'));
        assert!(
            matches!(&a.confirmation, Some(ConfirmMode::Open { dialog, .. }) if !dialog.confirm_selected())
        );
        a.handle_key(KeyCode::Enter);
        assert!(!a.selection.ssh);
        assert!(a.confirmation.is_none());

        a.handle_key(KeyCode::Char('4'));
        a.handle_key(KeyCode::Tab);
        a.handle_key(KeyCode::Enter);
        assert!(a.selection.ssh);
        assert!(a.confirmation.is_none());
    }

    #[test]
    fn container_engine_is_closed_by_every_preset_and_requires_open_confirmation()
     {
        let mut selection = Selection::default();
        let mut app = app(&mut selection);
        app.handle_key(KeyCode::Char('c'));
        assert!(matches!(
            app.confirmation,
            Some(ConfirmMode::Open {
                capability: CapabilityId::ContainerEngine,
                ..
            })
        ));
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert!(app.selection.container_engine);

        for preset in [AccessPreset::FullyClosed, AccessPreset::Developer] {
            app.apply_preset(preset);
            assert!(!app.selection.container_engine);
        }
    }

    #[test]
    fn additional_capabilities_are_outside_presets_and_open_grants_confirm() {
        let mut selection = Selection::default();
        let mut app = app(&mut selection);
        app.handle_key(KeyCode::Char('a'));
        assert_eq!(app.screen, Screen::Additional);
        assert!(app.additional.is_some());

        // Entire host home is the first row and is OPEN.
        app.handle_key(KeyCode::Char(' '));
        assert!(matches!(
            app.confirmation,
            Some(ConfirmMode::AdditionalOpen { .. })
        ));
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert!(app.selection.additional.share_host_home);
        assert_eq!(app.active_preset(), None);
    }

    #[test]
    fn terminal_appearance_is_an_immediate_allowed_additional_toggle() {
        let mut selection = Selection::default();
        let mut app = app(&mut selection);
        app.handle_key(KeyCode::Char('a'));
        let state = app.additional.as_mut().unwrap();
        state.selected = state
            .capabilities
            .iter()
            .position(|entry| {
                *entry == AdditionalCapability::TerminalAppearance
            })
            .unwrap();
        assert_eq!(state.selected().risk(), Risk::Allowed);
        assert!(
            app.additional
                .as_ref()
                .unwrap()
                .selected()
                .detail()
                .contains("OSC 11")
        );
        app.handle_key(KeyCode::Enter);
        assert!(app.selection.additional.terminal_appearance);
        assert!(app.confirmation.is_none());
        app.handle_key(KeyCode::Enter);
        assert!(!app.selection.additional.terminal_appearance);
    }
    #[test]
    fn disclosure_scroll_remains_available_during_confirmation() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('4'));
        assert!(a.confirmation.is_some());
        a.handle_key(KeyCode::PageDown);
        assert_eq!(a.detail_scroll, 3);
        assert!(a.confirmation.is_some());
        a.handle_key(KeyCode::PageUp);
        assert_eq!(a.detail_scroll, 0);
        assert!(a.confirmation.is_some());
    }

    #[test]
    fn wrapper_review_is_the_initial_screen_only_when_requests_exist() {
        let mut selection = Selection::default();
        let requests = RequestSet {
            items: vec![wrapper_request("host", "memory.example")],
        };
        let wrapper_app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );
        assert_eq!(wrapper_app.screen, Screen::WrapperRequests);

        let mut selection = Selection::default();
        assert_eq!(app(&mut selection).screen, Screen::Access);
    }

    #[test]
    fn wrapper_screen_owns_input_until_every_request_is_decided() {
        let mut selection = Selection::default();
        let requests = RequestSet {
            items: vec![wrapper_request("host", "memory.example")],
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );

        app.handle_key(KeyCode::Char('1'));
        assert!(!app.selection.api_access);
        assert_eq!(app.screen, Screen::WrapperRequests);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::WrapperRequests);

        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Access);
        assert_eq!(app.selection.requested_hosts, vec!["memory.example"]);
        assert_eq!(app.approved_wrapper_requests.len(), 1);
    }

    #[test]
    fn rejecting_a_previous_wrapper_request_revokes_its_effect() {
        let old = wrapper_request("host", "memory.example");
        let requests = RequestSet {
            items: vec![old.clone()],
        };
        let mut selection = Selection {
            requested_hosts: vec!["memory.example".into()],
            ..Selection::default()
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[old.approval],
        );
        assert!(app.selection.requested_hosts.is_empty());
        app.handle_key(KeyCode::Char('r'));
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Access);
        assert!(app.approved_wrapper_requests.is_empty());
        assert!(app.selection.grants("claude").allow_hosts.is_empty());
    }

    #[test]
    fn secret_wrapper_request_uses_explicit_dialog_choice() {
        let request = WrapperRequest {
            approval: RequestApproval {
                requester: "ai-memory".into(),
                kind: "secret".into(),
                value: "PATH".into(),
                host: Some("api.example.com".into()),
                writable: None,
                port: None,
            },
            reason: "authenticate".into(),
        };
        let requests = RequestSet {
            items: vec![request],
        };
        let mut selection = Selection::default();
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );
        app.handle_key(KeyCode::Char('a'));
        // Cancel is focused by default, so Enter cannot accidentally approve.
        app.handle_key(KeyCode::Enter);
        assert!(app.selection.env_names.is_empty());
        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.selection.env_names, vec!["PATH"]);
        assert_eq!(
            app.selection
                .requested_secrets
                .get("PATH")
                .map(String::as_str),
            Some("api.example.com")
        );
    }

    #[test]
    fn unsafe_viewport_cannot_bypass_wrapper_review() {
        let mut selection = Selection::default();
        let requests = RequestSet {
            items: vec![wrapper_request("host", "memory.example")],
        };
        let mut app = App::new(
            &mut selection,
            "claude",
            "/work/project".into(),
            false,
            &requests,
            &[],
        );
        app.resize(MIN_WIDTH - 1, MIN_HEIGHT - 1);

        assert_eq!(
            app.handle_key(KeyCode::Esc),
            Transition::Exit(AppExit::Cancel)
        );
        assert_eq!(app.screen, Screen::WrapperRequests);
        assert!(app.approved_wrapper_requests.is_empty());
    }
    #[test]
    fn unsafe_viewport_allows_only_cancel_and_back() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.resize(MIN_WIDTH - 1, MIN_HEIGHT - 1);
        for k in [KeyCode::Char('1'), KeyCode::Char(' '), KeyCode::Down] {
            a.handle_key(k);
        }
        assert!(!a.selection.api_access);
        assert_eq!(a.selected, 0);
        assert!(a.confirmation.is_none());
        assert_eq!(
            a.handle_key(KeyCode::Esc),
            Transition::Exit(AppExit::Cancel)
        );
        assert_eq!(
            a.handle_key(KeyCode::Char('q')),
            Transition::Exit(AppExit::Cancel)
        );
    }
    #[test]
    fn actions_change_screen_without_exit() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        assert_eq!(a.handle_key(KeyCode::Char('e')), Transition::Stay);
        assert_eq!(a.screen, Screen::Environment);
        a.handle_key(KeyCode::Esc);
        assert_eq!(a.screen, Screen::Access);
        assert_eq!(
            a.handle_key(KeyCode::Char('s')),
            Transition::PrepareSave { save_only: false }
        );
        assert_eq!(a.screen, Screen::Access);
        assert_eq!(a.screen, Screen::Access);
    }

    #[test]
    fn recommended_github_requires_cancel_first_open_confirmation_on_save() {
        let mut s = Selection {
            github: true,
            ..Selection::default()
        };
        let mut a = app(&mut s);
        a.set_recommended_baseline(true);

        assert_eq!(a.handle_key(KeyCode::Char('s')), Transition::Stay);
        assert!(matches!(
            &a.confirmation,
            Some(ConfirmMode::SaveWithGithub { dialog, .. })
                if !dialog.confirm_selected()
        ));
        assert_eq!(a.handle_key(KeyCode::Enter), Transition::Stay);
        assert!(a.confirmation.is_none());

        assert_eq!(a.handle_key(KeyCode::Char('s')), Transition::Stay);
        assert_eq!(a.handle_key(KeyCode::Tab), Transition::Stay);
        assert_eq!(
            a.handle_key(KeyCode::Enter),
            Transition::PrepareSave { save_only: false }
        );
    }

    #[test]
    fn previously_saved_github_grant_does_not_require_reconfirmation() {
        let mut s = Selection {
            github: true,
            ..Selection::default()
        };
        let mut a = app(&mut s);

        assert_eq!(
            a.handle_key(KeyCode::Char('s')),
            Transition::PrepareSave { save_only: false }
        );
        assert!(a.confirmation.is_none());
    }

    #[test]
    fn changed_draft_intercepts_escape_and_q_until_exit_choice_is_explicit() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('1'));
        assert!(a.has_unsaved_changes());

        assert_eq!(a.handle_key(KeyCode::Esc), Transition::Stay);
        assert!(a.exit_dialog.is_some());
        assert_eq!(a.handle_key(KeyCode::Esc), Transition::Stay);
        assert!(a.exit_dialog.is_none());

        assert_eq!(a.handle_key(KeyCode::Char('q')), Transition::Stay);
        assert!(a.exit_dialog.is_some());
        assert_eq!(
            a.handle_key(KeyCode::Char('d')),
            Transition::Exit(AppExit::Cancel)
        );
    }

    #[test]
    fn exit_save_choice_requests_save_only_without_launching() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('1'));
        assert_eq!(a.handle_key(KeyCode::Char('q')), Transition::Stay);
        assert_eq!(
            a.handle_key(KeyCode::Char('s')),
            Transition::PrepareSave { save_only: true }
        );
        assert!(a.exit_dialog.is_none());
    }

    #[test]
    fn unchanged_or_reverted_draft_exits_without_an_unsaved_prompt() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        assert_eq!(
            a.handle_key(KeyCode::Esc),
            Transition::Exit(AppExit::Cancel)
        );
        assert!(a.exit_dialog.is_none());

        a.handle_key(KeyCode::Char('1'));
        a.handle_key(KeyCode::Char('1'));
        assert!(!a.has_unsaved_changes());
        assert_eq!(
            a.handle_key(KeyCode::Char('q')),
            Transition::Exit(AppExit::Cancel)
        );
    }

    #[test]
    fn first_run_recommended_profile_is_unsaved_before_manual_edits() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.set_recommended_baseline(true);
        assert!(a.has_unsaved_changes());
        assert_eq!(a.handle_key(KeyCode::Esc), Transition::Stay);
        assert!(a.exit_dialog.is_some());
    }
    #[test]
    fn editor_text_focus_consumes_q_before_global_cancel() {
        let mut s = Selection::default();
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('e'));
        a.handle_key(KeyCode::Char('/'));
        assert_eq!(a.handle_key(KeyCode::Char('q')), Transition::Stay);
        assert_eq!(a.screen, Screen::Environment);
        assert_eq!(
            a.handle_key(KeyCode::Esc),
            Transition::Stay,
            "Esc closes search before leaving the editor"
        );
        assert_eq!(
            a.handle_key(KeyCode::Char('q')),
            Transition::Exit(AppExit::Cancel)
        );
    }

    #[test]
    fn selecting_a_key_disables_full_ssh_at_parent_boundary() {
        let mut s = Selection {
            ssh: true,
            ..Selection::default()
        };
        let mut a = app(&mut s);
        let identity = crate::ssh_restricted::KeyIdentity {
            private_path: "/keys/id_work".into(),
            public_path: "/keys/id_work.pub".into(),
            fingerprint: "SHA256:work".into(),
            comment: "work@example".into(),
            private_dev: 1,
            private_ino: 2,
            public_dev: 1,
            public_ino: 3,
        };
        a.ssh_identities = vec![identity.clone()];
        a.ssh = Some(SshEditor::new(
            vec![App::identity_row(&identity, false)],
            vec!["git@example.com".into()],
            crate::ssh_restricted::DEFAULT_LIFETIME_SECONDS,
            false,
        ));
        a.screen = Screen::RestrictedSsh;

        assert_eq!(a.handle_key(KeyCode::Char(' ')), Transition::Stay);
        assert!(!a.selection.ssh);
        assert_eq!(
            a.selection
                .restricted_ssh
                .as_ref()
                .map(|policy| policy.keys.len()),
            Some(1)
        );
    }
    #[test]
    fn ssh_modes_are_mutually_exclusive() {
        let mut s = Selection {
            restricted_ssh: Some(crate::ssh_restricted::Policy {
                keys: Vec::new(),
                lifetime_seconds:
                    crate::ssh_restricted::DEFAULT_LIFETIME_SECONDS,
                destinations: Vec::new(),
            }),
            ..Selection::default()
        };
        let mut a = app(&mut s);
        a.handle_key(KeyCode::Char('4'));
        a.handle_key(KeyCode::Tab);
        a.handle_key(KeyCode::Enter);
        assert!(a.selection.ssh);
        assert!(a.selection.restricted_ssh.is_none());
        a.apply_restricted_ssh(Some(crate::ssh_restricted::Policy {
            keys: Vec::new(),
            lifetime_seconds: crate::ssh_restricted::DEFAULT_LIFETIME_SECONDS,
            destinations: Vec::new(),
        }));
        assert!(!a.selection.ssh);
    }
}
