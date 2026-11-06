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
use super::dialog::{ConfirmDialog, DialogAction};
use super::directory::{
    DirectoryAction, DirectoryBrowser, DirectoryEntry, DirectoryGrantEntry,
    DirectoryMode, DirectoryPreview,
};
use super::environment::{EnvironmentAction, EnvironmentSelector};
use super::review::{FinalAction, ReviewAction, ReviewState};
use super::ssh::{
    Editor as SshEditor, EditorAction as SshAction, IdentityRow,
    OperationRequest as SshRequest,
};
use super::wrapper::{WrapperAction, WrapperReview};
use crate::integration::{RequestApproval, RequestSet};
use crossterm::event::KeyCode;
use std::path::{Path, PathBuf};

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
            Self::Review => "Review complete access",
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
    Review,
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
            Self::Review => "Review complete access",
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
            Self::Review => {
                "Continue to the complete effective-access review, including every contributing policy layer."
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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppExit {
    Final(FinalAction),
    Cancel,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Transition {
    Stay,
    PrepareReview,
    DiscardReview,
    Exit(AppExit),
}

pub(super) struct App<'a> {
    pub(super) selection: &'a mut Selection,
    pub(super) harness: String,
    pub(super) project: String,
    pub(super) screen: Screen,
    pub(super) wrapper: Option<WrapperReview>,
    pub(super) directory: Option<DirectoryBrowser>,
    pub(super) environment: Option<EnvironmentSelector>,
    pub(super) review: Option<ReviewState>,
    pub(super) ssh: Option<SshEditor>,
    pub(super) additional: Option<AdditionalState>,
    ssh_identities: Vec<crate::ssh_restricted::KeyIdentity>,
    project_path: PathBuf,
    pub(super) approved_wrapper_requests: Vec<RequestApproval>,
    pub(super) selected: usize,
    pub(super) confirmation: Option<ConfirmMode>,
    pub(super) feedback: String,
    pub(super) detail_scroll: u16,
    pub(super) viewport_safe: bool,
    pub(super) use_color: bool,
    pub(super) recommended_baseline: bool,
    pub(super) preset_focus: bool,
    pub(super) preset_cursor: usize,
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
            screen: if wrapper.is_some() {
                Screen::WrapperRequests
            } else {
                Screen::Access
            },
            wrapper,
            directory: None,
            environment: None,
            review: None,
            ssh: None,
            additional: None,
            ssh_identities: Vec::new(),
            project_path,
            approved_wrapper_requests: approved_wrapper_requests.to_vec(),
            selected: 0,
            confirmation: None,
            feedback: String::new(),
            detail_scroll: 0,
            viewport_safe: true,
            use_color,
            recommended_baseline: false,
            preset_focus: false,
            preset_cursor: 1,
        }
    }
    pub(super) fn resize(&mut self, width: u16, height: u16) {
        self.viewport_safe = width >= MIN_WIDTH && height >= MIN_HEIGHT;
    }
    pub(super) fn set_project_path(&mut self, project: &Path) {
        self.project_path = project.to_path_buf();
    }
    pub(super) fn show_review(&mut self, review: ReviewState) {
        self.review = Some(review);
        self.screen = Screen::Review;
        self.feedback.clear();
    }
    pub(super) fn selected_capability(&self) -> CapabilityId {
        CapabilityId::ALL[self.selected]
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
        match c {
            CapabilityId::ModelApi => {
                let hosts = api_hosts(&self.harness);
                if hosts.is_empty() {
                    return format!(
                        "Allows\nNo model API is known for {}. This choice adds no destination.\n\n{saved}",
                        self.harness
                    );
                }
                format!(
                    "Allows\n{} and its child processes can connect only to {} and subdomains.\n\nStill blocked\nOther hosts, private IP addresses, and localhost.\n\nRisk\nThese API services can receive prompts and any jail data the process sends.\n\n{saved}",
                    self.harness,
                    hosts.join(", ")
                )
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
                "Allows\nCreate a fresh SSH agent with only the keys you select. Keys must be limited to verified destinations.\n\nStill private\nPrivate-key files and your normal host agent never enter the jail.\n\nAlso needed\nSSH network access must be enabled separately."
                    .into()
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
                "Choose exact variable names to pass into the jail. Values stay hidden and are never saved.\n\nRisk\nEvery jailed child process can read and copy an approved value."
                    .into()
            }
            CapabilityId::DirectoryAccess => {
                "Choose extra host directories and set each one read-only or read/write.\n\nSafety\nCredential folders are refused. Broad folders require OPEN approval."
                    .into()
            }
            CapabilityId::Additional => {
                "Open a categorized list of less common host integrations, credentials, devices, and compatibility grants.\n\nSafety\nNothing here is enabled by a preset. Broad grants require an explicit OPEN dialog."
                    .into()
            }
            CapabilityId::Review => {
                "See the final combined access before saving or launching. This includes presets, granular choices, CLI flags, and policy defaults."
                    .into()
            }
        }
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
        if self.preset_focus {
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
        self.feedback = format!("Applied {} preset.", preset.label());
    }

    fn activate_preset(&mut self) {
        let preset = AccessPreset::ALL[self.preset_cursor];
        if preset == AccessPreset::MostlyOpen {
            self.confirmation = Some(ConfirmMode::MostlyOpen {
                dialog: ConfirmDialog::new(
                    "Apply Mostly open?",
                    "This opens unrestricted network, the full host GitHub token, the ambient SSH agent, and host loopback services. It clears selected directories, environment variables, selected-key SSH, and wrapper approvals. The final review still shows the complete effective access.",
                    "Apply Mostly open",
                ),
            });
        } else {
            self.apply_preset(preset);
        }
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
        if !self.viewport_safe {
            return match code {
                KeyCode::Char('q') => Transition::Exit(AppExit::Cancel),
                KeyCode::Esc if self.screen == Screen::WrapperRequests => {
                    Transition::Exit(AppExit::Cancel)
                }
                KeyCode::Esc if self.screen == Screen::Review => {
                    self.review = None;
                    self.screen = Screen::Access;
                    self.feedback =
                        "Review draft discarded; resize to continue.".into();
                    Transition::DiscardReview
                }
                KeyCode::Esc => {
                    self.screen = Screen::Access;
                    self.feedback = "Resize the terminal to continue.".into();
                    Transition::Stay
                }
                _ => Transition::Stay,
            };
        }
        if self.screen == Screen::WrapperRequests {
            return self.handle_wrapper(code);
        }
        match self.screen {
            Screen::Review => return self.handle_review(code),
            Screen::RestrictedSsh => return self.handle_ssh(code),
            Screen::Environment => return self.handle_environment(code),
            Screen::DirectoryPicker { .. } => {
                return self.handle_directory(code);
            }
            Screen::Additional => return self.handle_additional(code),
            _ => {}
        }
        if code == KeyCode::Char('q') {
            return Transition::Exit(AppExit::Cancel);
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
        if self.preset_focus {
            match code {
                KeyCode::Tab | KeyCode::Right => {
                    self.preset_cursor =
                        (self.preset_cursor + 1) % AccessPreset::ALL.len();
                }
                KeyCode::BackTab | KeyCode::Left => {
                    self.preset_cursor = if self.preset_cursor == 0 {
                        AccessPreset::ALL.len() - 1
                    } else {
                        self.preset_cursor - 1
                    };
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.activate_preset(),
                KeyCode::Down | KeyCode::Esc => {
                    self.preset_focus = false;
                    self.feedback =
                        "Preset preview closed without applying it.".into();
                }
                _ => {}
            }
            return Transition::Stay;
        }
        match code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.preset_focus = true;
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
                self.feedback =
                    "Already at the access overview; q cancels setup.".into()
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
    fn handle_review(&mut self, code: KeyCode) -> Transition {
        let Some(review) = &mut self.review else {
            self.screen = Screen::Access;
            self.feedback = "Review must be prepared again.".into();
            return Transition::DiscardReview;
        };
        match review.handle_key(code) {
            ReviewAction::Stay => Transition::Stay,
            ReviewAction::Back => {
                self.review = None;
                self.screen = Screen::Access;
                self.feedback =
                    "Review draft discarded; access choices are editable."
                        .into();
                Transition::DiscardReview
            }
            ReviewAction::Cancel => Transition::Exit(AppExit::Cancel),
            ReviewAction::Complete(action) => {
                Transition::Exit(AppExit::Final(action))
            }
        }
    }
    fn handle_wrapper(&mut self, code: KeyCode) -> Transition {
        let Some(wrapper) = &mut self.wrapper else {
            self.screen = Screen::Access;
            return Transition::Stay;
        };
        match wrapper.handle_key(code) {
            WrapperAction::Stay => Transition::Stay,
            WrapperAction::Cancel => Transition::Exit(AppExit::Cancel),
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
            return Transition::Exit(AppExit::Cancel);
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
            return Transition::Exit(AppExit::Cancel);
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
            return Transition::Exit(AppExit::Cancel);
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
                CapabilityId::Review => return Transition::PrepareReview,
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
                            "{} removes an important isolation boundary. The complete effect remains visible in the final review.",
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
            KeyCode::Char('q') => return Transition::Exit(AppExit::Cancel),
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
                                "{} removes an important isolation boundary. The final review shows the effective result.",
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
        assert!(app.preset_focus);
        assert_eq!(app.preset_cursor, 1);
        app.handle_key(KeyCode::Right);
        assert_eq!(app.preset_cursor, 2);
        assert!(app.displayed_enabled(CapabilityId::FullSsh));
        assert!(app.displayed_enabled(CapabilityId::FullGithub));
        assert!(app.displayed_enabled(CapabilityId::UnrestrictedNetwork));
        assert!(!app.selection.ssh);
        assert!(app.selection.github);
        assert!(!app.selection.unrestricted_network);
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
        assert_eq!(a.handle_key(KeyCode::Esc), Transition::Stay);
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
        assert_eq!(a.handle_key(KeyCode::Char('s')), Transition::PrepareReview);
        assert_eq!(a.screen, Screen::Access);
        a.show_review(ReviewState::new(
            super::super::review::ReviewContent {
                restricted: "restricted".into(),
                allowed: "allowed".into(),
                open: "open".into(),
                effective_policy: "effective".into(),
            },
            true,
            false,
            false,
        ));
        assert_eq!(a.screen, Screen::Review);
        assert_eq!(a.handle_key(KeyCode::Esc), Transition::DiscardReview);
        assert_eq!(a.screen, Screen::Access);
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
