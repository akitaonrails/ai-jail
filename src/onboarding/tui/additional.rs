use super::super::{AdditionalSelection, Risk};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Capability {
    ShareHostHome,
    Lockdown,
    SystemdUser,
    Gpu,
    Tailscale,
    Display,
    Audio,
    Kvm,
    X11,
    HostShm,
    RawTerminal,
    Aws,
    Kubernetes,
    Gcloud,
    RegistryCredentials,
    MacosHostIpc,
    MacosChromium,
    MacosTrustd,
    MacosPty,
    MacosLoopbackListen,
    FullEnvironment,
    Worktree,
    Pictures,
    AuditLog,
}

impl Capability {
    const ALL: [Self; 24] = [
        Self::ShareHostHome,
        Self::Lockdown,
        Self::SystemdUser,
        Self::Gpu,
        Self::Tailscale,
        Self::Display,
        Self::Audio,
        Self::Kvm,
        Self::X11,
        Self::HostShm,
        Self::RawTerminal,
        Self::Aws,
        Self::Kubernetes,
        Self::Gcloud,
        Self::RegistryCredentials,
        Self::MacosHostIpc,
        Self::MacosChromium,
        Self::MacosTrustd,
        Self::MacosPty,
        Self::MacosLoopbackListen,
        Self::FullEnvironment,
        Self::Worktree,
        Self::Pictures,
        Self::AuditLog,
    ];

    pub(super) fn available() -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|capability| match capability {
                Self::MacosHostIpc
                | Self::MacosChromium
                | Self::MacosTrustd
                | Self::MacosPty
                | Self::MacosLoopbackListen => cfg!(target_os = "macos"),
                Self::SystemdUser
                | Self::Gpu
                | Self::Tailscale
                | Self::Display
                | Self::Audio
                | Self::Kvm
                | Self::X11
                | Self::HostShm => {
                    cfg!(target_os = "linux")
                }
                _ => true,
            })
            .collect()
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::ShareHostHome => "Entire host home directory",
            Self::Lockdown => "Lockdown mode",
            Self::SystemdUser => "systemd user manager",
            Self::Gpu => "GPU devices",
            Self::Tailscale => "Host Tailscale identity",
            Self::Display => "Wayland display",
            Self::Audio => "Audio and microphone",
            Self::Kvm => "KVM virtualization",
            Self::X11 => "X11 display",
            Self::HostShm => "Host shared memory",
            Self::RawTerminal => "Raw terminal protocol",
            Self::Aws => "AWS credentials",
            Self::Kubernetes => "Kubernetes credentials",
            Self::Gcloud => "Google Cloud credentials",
            Self::RegistryCredentials => "Docker registry credentials",
            Self::MacosHostIpc => "Broad macOS host IPC",
            Self::MacosChromium => "macOS Chromium rendezvous",
            Self::MacosTrustd => "macOS TLS trust service",
            Self::MacosPty => "macOS runtime PTYs",
            Self::MacosLoopbackListen => "macOS loopback server",
            Self::FullEnvironment => "Every host environment variable",
            Self::Worktree => "Linked-worktree Git metadata",
            Self::Pictures => "Pictures directory",
            Self::AuditLog => "Local security audit log",
        }
    }

    pub(super) const fn risk(self) -> Risk {
        match self {
            Self::Lockdown
            | Self::MacosChromium
            | Self::MacosTrustd
            | Self::MacosLoopbackListen
            | Self::Worktree
            | Self::AuditLog => Risk::Allowed,
            _ => Risk::Open,
        }
    }

    pub(super) const fn enabled(self, s: &AdditionalSelection) -> bool {
        match self {
            Self::ShareHostHome => s.share_host_home,
            Self::Lockdown => s.lockdown,
            Self::SystemdUser => s.systemd_user,
            Self::Gpu => s.gpu,
            Self::Tailscale => s.tailscale,
            Self::Display => s.display,
            Self::Audio => s.audio,
            Self::Kvm => s.kvm,
            Self::X11 => s.x11,
            Self::HostShm => s.host_shm,
            Self::RawTerminal => s.terminal_passthrough,
            Self::Aws => s.aws,
            Self::Kubernetes => s.kube,
            Self::Gcloud => s.gcloud,
            Self::RegistryCredentials => s.docker_config,
            Self::MacosHostIpc => s.macos_host_ipc,
            Self::MacosChromium => s.macos_chromium,
            Self::MacosTrustd => s.macos_trustd,
            Self::MacosPty => s.allow_pty,
            Self::MacosLoopbackListen => s.allow_loopback_listen,
            Self::FullEnvironment => s.inherit_env,
            Self::Worktree => s.worktree,
            Self::Pictures => s.pictures,
            Self::AuditLog => s.audit_log,
        }
    }

    pub(super) fn set(self, s: &mut AdditionalSelection, value: bool) {
        match self {
            Self::ShareHostHome => s.share_host_home = value,
            Self::Lockdown => s.lockdown = value,
            Self::SystemdUser => s.systemd_user = value,
            Self::Gpu => s.gpu = value,
            Self::Tailscale => s.tailscale = value,
            Self::Display => s.display = value,
            Self::Audio => s.audio = value,
            Self::Kvm => s.kvm = value,
            Self::X11 => s.x11 = value,
            Self::HostShm => s.host_shm = value,
            Self::RawTerminal => s.terminal_passthrough = value,
            Self::Aws => s.aws = value,
            Self::Kubernetes => s.kube = value,
            Self::Gcloud => s.gcloud = value,
            Self::RegistryCredentials => s.docker_config = value,
            Self::MacosHostIpc => s.macos_host_ipc = value,
            Self::MacosChromium => s.macos_chromium = value,
            Self::MacosTrustd => s.macos_trustd = value,
            Self::MacosPty => s.allow_pty = value,
            Self::MacosLoopbackListen => s.allow_loopback_listen = value,
            Self::FullEnvironment => s.inherit_env = value,
            Self::Worktree => s.worktree = value,
            Self::Pictures => s.pictures = value,
            Self::AuditLog => s.audit_log = value,
        }
    }

    const fn security_detail(self) -> &'static str {
        match self {
            Self::ShareHostHome => {
                "Shares\nYour entire host home directory read/write.\n\nRisk\nThe harness can read credentials and personal files and modify anything your user owns. Prefer specific directory grants."
            }
            Self::Lockdown => {
                "Restricts\nRemoves optional host integration and keeps writable access narrow.\n\nNote\nThis can override other enabled choices. The resulting state remains visible in this screen."
            }
            Self::SystemdUser => {
                "Allows\nRequests to your host systemd user manager.\n\nRisk\nThe harness may start or change services as your host user."
            }
            Self::Gpu => {
                "Allows\nDirect access to host GPU devices.\n\nRisk\nThis exposes a large kernel and driver interface and GPU workloads owned by your user."
            }
            Self::Tailscale => {
                "Allows\nUse of the host Tailscale socket and identity.\n\nRisk\nThe harness can reach resources trusted by your tailnet identity."
            }
            Self::Display => {
                "Allows\nConnect to the active Wayland display.\n\nRisk\nThe compositor decides what can be observed or controlled; do not treat this as display isolation."
            }
            Self::Audio => {
                "Allows\nCapture and play host audio through PipeWire, PulseAudio, or ALSA.\n\nRisk\nThe harness may record microphone or system audio."
            }
            Self::Kvm => {
                "Allows\nUse /dev/kvm for hardware-accelerated virtual machines.\n\nRisk\nThis exposes the host kernel's KVM interface."
            }
            Self::X11 => {
                "Allows\nConnect to the host X11 display.\n\nRisk\nX11 clients can generally inspect input and other windows, including keystrokes."
            }
            Self::HostShm => {
                "Allows\nUse the host's shared-memory namespace.\n\nRisk\nThis opens a cross-process IPC channel with host applications."
            }
            Self::RawTerminal => {
                "Allows\nSend raw terminal control sequences without ai-jail's VT filtering.\n\nRisk\nThis exposes clipboard, terminal queries, and terminal-parser attack surface."
            }
            Self::Aws => {
                "Shares\nYour read-only ~/.aws files.\n\nRisk\nRead-only files still let the harness copy credentials and act with their AWS authority."
            }
            Self::Kubernetes => {
                "Shares\nYour read-only ~/.kube configuration.\n\nRisk\nThe harness can copy credentials and act against every configured cluster they authorize."
            }
            Self::Gcloud => {
                "Shares\nYour read-only gcloud configuration.\n\nRisk\nThe harness can copy credentials and act as configured Google Cloud accounts."
            }
            Self::RegistryCredentials => {
                "Shares\nYour read-only Docker registry configuration.\n\nRisk\nThe harness can copy credentials and pull or push as those registry accounts."
            }
            Self::MacosHostIpc => {
                "Allows\nBroad macOS Mach, IOKit, and host IPC compatibility.\n\nRisk\nThis substantially weakens process isolation. Prefer the narrow Chromium or trust-service options."
            }
            Self::MacosChromium => {
                "Allows\nOnly Chromium's macOS Mach rendezvous service.\n\nStill blocked\nOther broad host IPC remains unavailable."
            }
            Self::MacosTrustd => {
                "Allows\nOnly macOS trustd lookup so TLS clients can verify certificates.\n\nStill blocked\nOther broad host IPC remains unavailable."
            }
            Self::MacosPty => {
                "Allows\nOpening runtime PTY devices on macOS.\n\nRisk\nThe path rule can cover other terminals owned by your user."
            }
            Self::MacosLoopbackListen => {
                "Allows\nBind a local server while filtered network access remains active.\n\nStill blocked\nThis does not open outbound destinations or all host localhost services."
            }
            Self::FullEnvironment => {
                "Shares\nEvery exported host environment variable.\n\nRisk\nThis commonly includes tokens, credentials, internal endpoints, and other secrets. Prefer selecting exact names."
            }
            Self::Worktree => {
                "Allows\nWrite validated linked-worktree Git metadata outside the project so commits work.\n\nStill blocked\nUnrelated paths remain private; lockdown keeps this metadata read-only."
            }
            Self::Pictures => {
                "Shares\nYour Pictures directory read-only.\n\nRisk\nThe harness can inspect and copy every readable image there."
            }
            Self::AuditLog => {
                "Records\nLocal launch and filtered-network security decisions in ai-jail's audit log.\n\nPrivacy\nLogs contain policy decisions and destination names, not secret values."
            }
        }
    }

    pub(super) const fn use_when(self) -> &'static str {
        match self {
            Self::ShareHostHome => {
                "A task genuinely needs broad access across your home and specific directories are impractical."
            }
            Self::Lockdown => {
                "You want the strictest supported baseline and can accept reduced tool compatibility."
            }
            Self::SystemdUser => {
                "The harness must inspect, start, stop, or debug your user services."
            }
            Self::Gpu => {
                "The task runs GPU compute, rendering, or hardware-accelerated tests."
            }
            Self::Tailscale => {
                "The task must reach a service available only through your tailnet identity."
            }
            Self::Display => {
                "GUI applications must open on Wayland so the harness can run, instrument, or debug them."
            }
            Self::Audio => {
                "The task must record, inspect, test, or play microphone or system audio."
            }
            Self::Kvm => {
                "The task launches hardware-accelerated virtual machines or VM-based tests."
            }
            Self::X11 => {
                "A GUI application requires X11 and cannot use Wayland or a headless display."
            }
            Self::HostShm => {
                "A host application and jailed process must exchange data through shared memory."
            }
            Self::RawTerminal => {
                "A trusted interactive program requires terminal features blocked by VT filtering."
            }
            Self::Aws => {
                "The task must inspect or change AWS resources using your configured identity."
            }
            Self::Kubernetes => {
                "The task must inspect, deploy, or debug workloads in your configured clusters."
            }
            Self::Gcloud => {
                "The task must inspect or change Google Cloud resources using your configured identity."
            }
            Self::RegistryCredentials => {
                "The task must pull or push private images with your configured registry accounts."
            }
            Self::MacosHostIpc => {
                "A macOS application cannot run with the narrower Chromium or trust-service grants."
            }
            Self::MacosChromium => {
                "Chromium-based applications on macOS need their narrow rendezvous service."
            }
            Self::MacosTrustd => {
                "A macOS TLS client needs the host trust service to verify certificates."
            }
            Self::MacosPty => {
                "A macOS task must create runtime pseudo-terminals for interactive subprocesses."
            }
            Self::MacosLoopbackListen => {
                "A macOS development server must listen locally while outbound access stays filtered."
            }
            Self::FullEnvironment => {
                "A legacy tool needs many unpredictable variables and selecting exact names is not workable."
            }
            Self::Worktree => {
                "The project is a linked Git worktree and the harness must create commits or update metadata."
            }
            Self::Pictures => {
                "The task needs to inspect or process images from your Pictures directory."
            }
            Self::AuditLog => {
                "You need a local record of launches and filtered-network policy decisions."
            }
        }
    }

    pub(super) fn detail(self) -> String {
        format!(
            "{}\n\nUse when\n{}",
            self.security_detail(),
            self.use_when()
        )
    }
}

pub(super) struct State {
    pub(super) capabilities: Vec<Capability>,
    pub(super) selected: usize,
    pub(super) feedback: String,
}

impl State {
    pub(super) fn new() -> Self {
        Self {
            capabilities: Capability::available(),
            selected: 0,
            feedback: String::new(),
        }
    }

    pub(super) fn selected(&self) -> Capability {
        self.capabilities[self.selected]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_unique_and_every_detail_is_short_and_explicit() {
        assert_eq!(Capability::ALL.len(), 24);
        let mut labels = Capability::ALL
            .into_iter()
            .map(Capability::label)
            .collect::<Vec<_>>();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), Capability::ALL.len());

        for capability in Capability::ALL {
            let detail = capability.detail();
            assert!(!detail.trim().is_empty(), "{capability:?}");
            assert!(detail.contains("Use when\n"), "{capability:?}: {detail}");
            assert!(
                detail.split_whitespace().count() <= 70,
                "{capability:?} is too verbose: {detail}"
            );
            if capability.risk() == Risk::Open {
                assert!(
                    detail.contains("Risk\n"),
                    "{capability:?} does not name its OPEN risk: {detail}"
                );
            }
        }
    }

    #[test]
    fn every_catalog_entry_reads_and_writes_its_selection_state() {
        let mut selection = AdditionalSelection::default();
        for capability in Capability::ALL {
            assert!(!capability.enabled(&selection), "{capability:?}");
            capability.set(&mut selection, true);
            assert!(capability.enabled(&selection), "{capability:?}");
            capability.set(&mut selection, false);
            assert!(!capability.enabled(&selection), "{capability:?}");
        }
        assert_eq!(selection, AdditionalSelection::default());
    }
}
