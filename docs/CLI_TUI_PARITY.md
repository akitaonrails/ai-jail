# CLI and TUI capability parity

This inventory is a release contract. Every long option shown by `ai-jail
--help` must appear here. Adding a CLI option without classifying its onboarding
experience fails the parity test.

`TUI` means the persistent onboarding interface exposes the capability or its
equivalent. `Gap` means a broadly useful security or compatibility choice still
needs a discoverable TUI control. `Advanced` means the option remains CLI-only
because it is a precise policy primitive; its effective result must still be
visible in final review. `Operational` means it controls invocation, diagnostics,
or integration rather than saved sandbox authority.

## TUI

- Harness state: `--agent-state`, `--no-agent-state`
- Dependency tooling: `--toolchains`, `--no-toolchains`
- GitHub authority: `--github`, `--no-github`
- Host container engine: `--docker`, `--no-docker`
- Network posture: `--network`, `--no-network`
- macOS broad loopback: `--allow-loopback-connect`,
  `--no-allow-loopback-connect`
- Environment names: `--env`
- Directory access: `--map`, `--rw-map`
- Full SSH and the safer selected-key workflow: `--ssh`, `--no-ssh`
- Trusted wrapper requests are reviewed in the TUI: `--request`,
  `--request-file`
- Additional capabilities screen:
  - Isolation posture: `--private-home`, `--no-private-home`, `--lockdown`,
    `--no-lockdown`
  - Host services/devices: `--systemd-user`, `--no-systemd-user`, `--gpu`,
    `--no-gpu`, `--tailscale`, `--no-tailscale`, `--display`, `--no-display`,
    `--audio`, `--no-audio`, `--kvm`, `--no-kvm`, `--x11`, `--no-x11`,
    `--host-shm`, `--no-host-shm`, `--terminal-passthrough`,
    `--no-terminal-passthrough`
  - Read-only credential stores: `--aws`, `--no-aws`, `--kube`, `--no-kube`,
    `--gcloud`, `--no-gcloud`, `--docker-config`, `--no-docker-config`
  - macOS compatibility: `--macos-host-ipc`, `--no-macos-host-ipc`,
    `--macos-chromium`, `--no-macos-chromium`, `--macos-trustd`,
    `--no-macos-trustd`, `--allow-pty`, `--no-allow-pty`,
    `--allow-loopback-listen`, `--no-allow-loopback-listen`
  - Workspace and audit: `--inherit-env`, `--no-inherit-env`, `--worktree`,
    `--no-worktree`, `--pictures`, `--no-pictures`, `--audit-log`,
    `--no-audit-log`
- Dependency-tools choice also controls mise activation: `--mise`, `--no-mise`

## Advanced CLI-only policy

- Filesystem overlays and exclusions: `--overlay-map`, `--hide-dotdir`,
  `--mask`, `--mask-except`, `--deny-path`, `--deny-path-except`
- Kernel enforcement overrides: `--landlock`, `--no-landlock`, `--seccomp`,
  `--no-seccomp`, `--rlimits`, `--no-rlimits`
- Filtered egress policy: `--allow-host`, `--allow-private-host`,
  `--prompt-hosts`, `--no-prompt-hosts`
- Port bridges: `--forward-port`, `--publish-port`
- Environment/secret sources: `--env-from-file`, `--secret`
- Harness-specific path override: `--claude-dir`
- Browser command/profile mode: `--browser`, `--no-browser` (command-specific;
  known browser commands are detected automatically, and the final review
  exposes the effective hard/soft profile)
- Persistence and presentation preferences: `--save-config`,
  `--no-save-config`, `--hide-config`, `--no-hide-config`, `--update-check`,
  `--no-update-check`, `--status-bar`, `--no-status-bar`

## Operational and compatibility-only CLI

- Invocation/integration: `--harness`, `--json`, `--exec`
- Maintenance and inspection: `--clean`, `--dry-run`, `--init`, `--bootstrap`,
  `--audit-show`, `--audit-verify`
- Standard process information: `--help`, `--version`, `--verbose`
- Backward-compatible rejected option: `--allow-tcp-port`

## Release rule

A release audit must resolve every `Gap`, or explicitly retain it here with a
current rationale and user-facing documentation. Advanced and operational
options do not require a direct onboarding control, but security-relevant
effects must be represented in the complete effective-access review.
