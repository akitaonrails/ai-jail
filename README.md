# ai-jail

`ai-jail` runs AI coding agents in an OS sandbox: bubblewrap plus Landlock,
seccomp, and limits on Linux; `sandbox-exec` on macOS. It is a useful layer,
not a replacement for a disposable VM when running hostile code.

## Install

```bash
# Homebrew
brew tap akitaonrails/tap && brew install ai-jail

# Arch Linux
yay -S ai-jail-bin       # prebuilt Linux x86_64 binary
yay -S ai-jail           # build from source

# crates.io
cargo install --locked ai-jail

# Nix (flake) — sets BWRAP_BIN automatically
nix run github:akitaonrails/ai-jail -- claude
nix profile install github:akitaonrails/ai-jail

# GitHub Releases (signed archives, checksums alongside)
# ai-jail-linux-x86_64.tar.gz / ai-jail-macos-aarch64.tar.gz
```

Build from source with Rust `1.97.1`:

```bash
cargo build --release --locked
install -Dm755 target/release/ai-jail ~/.local/bin/ai-jail
```

Linux requires `bwrap` (`bubblewrap`): `pacman -S bubblewrap`,
`apt install bubblewrap`, or `dnf install bubblewrap`. `BWRAP_BIN` is accepted
only when it canonically resolves to a root-owned executable that is not
group- or world-writable, or to an executable with no write bits under a
`/nix/store` whose own owner is root (or an unmapped owner inside a user
namespace) and which is not world-writable — the standard multi-user store
layout. A single-user store owned by the invoking user does not qualify.
macOS uses Apple's deprecated `/usr/bin/sandbox-exec` interface. Windows is not
supported; use WSL2 and the Linux backend inside it.

## Quick start

```bash
cd ~/Projects/my-app
ai-jail claude                 # no agent credentials mounted
ai-jail --agent-state claude   # mount Claude's credential state
ai-jail --dry-run claude
```

The project directory is writable by default; host capabilities are not. The
first ordinary run may create `.ai-jail`; `--dry-run` never writes it. Existing
unreadable or invalid project/global configuration fails closed rather than
launching with a weakened policy. Bootstrap output is always mode `0600`.

## Secure defaults

Private home is **on** by default: the agent gets a fresh tmpfs `$HOME`, not
your host home. Agent credential state (Claude's `~/.claude` and
`~/.claude.json`, for example) is **not** mounted unless you ask for it:

```bash
ai-jail --agent-state claude
```

or in trusted global config:

```toml
# ~/.ai-jail
[commands.claude]
agent_state = true
```

Mounting agent state exposes that agent's login/session material to everything
running in the sandbox, so it stays opt-in. Use `--no-private-home` only when
deliberately granting broad host-home access; `--map` and `--rw-map` remain
explicit, narrow alternatives.

The following capabilities default **off**: network, GPU, display, linked Git
worktree metadata, X11, host shared memory, terminal passthrough, update
check, and macOS host IPC. Docker, SSH, Pictures, Tailscale, and the systemd
user bus are also off by default.

| Flag pair                                              | Effect and security consequence                                                                                                                                                                |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--network` / `--no-network`                           | Enables/disables unrestricted network. `--network` permits full network exfiltration of any readable data.                                                                                     |
| `--gpu` / `--no-gpu`                                   | Enables/disables GPU device access.                                                                                                                                                            |
| `--display` / `--no-display`                           | Enables/disables display access. Only the validated Wayland socket is mounted; ai-jail never mounts all of `XDG_RUNTIME_DIR`. X11 is separate (`--x11`).                                       |
| `--x11` / `--no-x11`                                   | Enables/disables X11 separately. X11 access permits keylogging and screenshots.                                                                                                                |
| `--host-shm` / `--no-host-shm`                         | Enables/disables host `/dev/shm`; enabling it opens host cross-process IPC.                                                                                                                    |
| `--terminal-passthrough` / `--no-terminal-passthrough` | Enables/disables raw terminal forwarding. Output is filtered through a VT parser by default; raw forwarding exposes terminal clipboard, query, and parser surface.                             |
| `--agent-state` / `--no-agent-state`                   | Enables/disables mounting the invoked command's credential state (default off). Enables the agent to authenticate — and lets anything in the sandbox use those credentials.                    |
| `--inherit-env` / `--no-inherit-env`                   | Default is a minimal environment allowlist. `--inherit-env` passes the full parent environment, secrets included.                                                                              |
| `--update-check` / `--no-update-check`                 | Enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active (default off; all other launches make no network requests).      |
| `--macos-host-ipc` / `--no-macos-host-ipc`             | Enables/disables macOS Mach, IOKit, and host IPC exposure.                                                                                                                                     |
| `--worktree` / `--no-worktree`                         | Enables/disables validated linked-worktree metadata. When enabled, the per-worktree git dir and the shared common dir are writable so the agent can commit; `--lockdown` keeps both read-only. |
| `--private-home` / `--no-private-home`                 | Enables/disables the default private home. Disabling it is broad host-home access.                                                                                                             |

`--allow-tcp-port` remains accepted for backward compatibility, but launch
fails closed because UDP cannot be securely constrained through this option.
Use `--network` only when unrestricted network access is explicitly desired.

`--docker` mounts an actual Unix Docker socket and is effectively host-root:
the daemon can create host-mounted containers. `DOCKER_HOST` must identify an
actual Unix socket; TCP/SSH endpoints are not mounted. `~/.docker` is not
broadly mounted. `--systemd-user` exposes only explicit user-bus sockets, but
can still ask the host user manager to run services.

## Environment policy

By default the sandbox receives only a minimal allowlist of terminal, locale,
and toolchain variables — not your shell environment. Extend it explicitly:

```bash
ai-jail --env CI --env API_BASE=https://internal.example claude
```

- `--env NAME` forwards one variable from the parent environment.
- `--env NAME=VALUE` sets a literal value.
- Both forms are repeatable; a later `--env` for the same name wins.
- `--inherit-env` passes the entire parent environment instead. This exports
  every secret currently in your shell into the sandbox; avoid it.

## Project secrets

The project directory is writable by default, so secrets inside it are
readable by the agent unless you mask or deny them:

```toml
# .ai-jail (project config — untrusted, but tightening like this is honored)
mask = [".env", ".env.*", "*.pem"]
deny_paths = ["secrets/"]
```

- `--mask PATH|GLOB` replaces matching project paths with empty placeholders:
  the agent sees the path exists but gets no content.
- `--deny-path PATH|GLOB` makes matching paths inaccessible entirely.
- `--mask-except` / `--deny-path-except` carve out exceptions.

Masks and denies apply to paths that **exist when the sandbox is built**.
A literal path that is missing at launch, or a glob that matches nothing, is
skipped with a warning — and a file created later, inside the session, is not
covered. Create the file before launching (an empty `.env` is enough) when you
need the rule enforced. Quote glob patterns so ai-jail receives the pattern
instead of your shell expanding it first.

## Ephemeral home and temp

The private home is a fresh tmpfs per launch. Nothing persists between runs
except state you explicitly mount (agent state, `--rw-map`, command tables).
On Linux `/tmp` inside the sandbox is sandbox-local and discarded on exit;
writes to dotfiles and caches vanish with the sandbox. macOS has no mount
namespace, so `/tmp` is the host's: `TMPDIR` instead points at a private
per-launch session directory (mode `0700`), and that is the only temp path
the profile grants. The one exception is `ai-jail claude` on macOS, which is
also granted write access to `/private/tmp/claude-<your uid>` because Claude
Code creates that directory unconditionally at startup and ignores `TMPDIR`;
unlike the session directory, it persists between runs. Use a map or
`--agent-state` for anything durable.

## Browsers

`--browser[=hard|soft]` reuses an isolated browser profile, but browsers still
need `--network` and `--display` passed explicitly on Linux (on macOS the
display is system-level, so only `--network` applies there); `--browser` alone
produces a browser that cannot load pages — and on Linux cannot open a window.
X11-based browsers need `--x11` instead of `--display`.

## Configuration

Two config files plus CLI flags, in increasing authority:

1. `./.ai-jail` (project) — untrusted, monotonic policy: it may tighten the
   sandbox but can never enable capabilities, outside maps, ports,
   `claude_dir`, or exceptions. It is hidden from the sandbox by default.
   To let specific checkouts ship their own capability opt-ins, list their
   parent directory under `trust_project_config` in the global config (see
   below).
2. `~/.ai-jail` (global, trusted) — a base table plus optional
   `[commands.<name>]` tables keyed by the first word of the command.
3. CLI flags — highest authority.

A `[commands.<name>]` table merges over the global base: scalar fields it sets
override the base (status-bar fields stay from the base), list fields (maps,
masks) append.

Common fields: `command`, `rw_maps`, `ro_maps`, `overlay_maps`, `mask`,
`deny_paths`, `mask_exceptions`, `deny_path_exceptions`, `hide_dotdirs`,
`network`, `x11`, `host_shm`, `terminal_passthrough`, `macos_host_ipc`,
`systemd_user`, `ssh`, `pictures`, `private_home`, `lockdown`,
`browser_profile`, `claude_dir`, `allow_tcp_ports`, `status_bar_style`.

Global config only: `trust_project_config` lists directories whose project
`.ai-jail` may enable capabilities rather than only tighten, for teams that
ship per-repository policy:

```toml
# ~/.ai-jail
trust_project_config = ["~/work/repos"]
```

Everything at or beneath a listed directory is trusted, including repositories
cloned there later, so keep the list narrow. A project file that sets this
itself is ignored.

Legacy polarity warning: older boolean fields keep their inverted `no_*`
names (`no_gpu`, `no_docker`, `no_display`, `no_worktree`, `no_mise`,
`no_landlock`, `no_seccomp`, `no_rlimits`, `no_save_config`, `no_hide_config`,
`no_status_bar`), where `true` disables the capability. Newer fields use
positive names (`network`, `x11`, `ssh`, `agent_state`, ...) where `true`
enables it. Unknown fields are ignored, and missing fields keep their
defaults, so old config files keep parsing across upgrades.

## Useful options

```text
ai-jail [OPTIONS] [--] [COMMAND [ARGS...]]

--map PATH|SOURCE:DEST          read-only extra mount (repeatable)
--rw-map PATH|SOURCE:DEST       read-write extra mount (repeatable)
--overlay-map PATH              copy-on-write mount (Linux only; read-only map on macOS)
--mask PATH|GLOB                replace project paths with empty placeholders
--deny-path PATH|GLOB           deny project paths
--agent-state / --no-agent-state  mount the command's credential state (default off)
--env NAME[=VALUE]              forward or set an environment variable (repeatable)
--inherit-env / --no-inherit-env  pass the full parent environment (default: allowlist)
--update-check / --no-update-check  host-side version check (default off)
--lockdown / --no-lockdown      strict read-only mode, no network by default
                                (on Linux --network still overrides network
                                isolation, subject to Landlock V4; macOS
                                lockdown always blocks network)
--docker / --no-docker          Docker socket (root-equivalent; off by default)
--systemd-user / --no-systemd-user  host user manager access (off by default)
--ssh / --no-ssh                read-only SSH/agent sharing (off by default)
--claude-dir PATH               explicit Claude state directory
--browser[=hard|soft]           isolated browser profile (needs --network --display)
--dry-run                       print the backend invocation
--init                          write configuration and exit
```

Linked worktrees are opt-in. When requested, ai-jail validates gitfile and
common-directory metadata and mounts the common metadata read-only. Kimi and
other agent state stays command-specific under private home.

## mise integration

If [mise](https://mise.jdx.dev/) is on `$PATH`, the sandbox runs
`mise trust -q`, `mise activate bash`, and `mise env` before your command, so
agents get the project's language versions. Disable with `--no-mise` or
`no_mise = true`. It is skipped automatically in `--lockdown` and browser
profile modes.

Activation is best-effort: if mise cannot run, or has neither its config nor
its installs inside the sandbox, it is skipped and your command still starts.

**Under the default private home, mise has neither.** `$HOME` is a fresh
tmpfs, so `~/.config/mise` and `~/.local/share/mise` are not mounted, and the
inherited `PATH` still names the host's `~/.local/share/mise/installs/...`
directories even though nothing is there. Activation is therefore skipped
rather than left to fail slowly against the network. To give an agent a real
mise toolchain, map it in explicitly from trusted global config:

```toml
# ~/.ai-jail
[commands.claude]
ro_maps = ["~/.config/mise", "~/.local/share/mise"]
```

or use `--no-private-home` when you deliberately want the whole host home.

## Herdr

[Herdr](https://herdr.dev/) runs outside the sandbox, one `ai-jail` per pane,
the same as tmux. ai-jail needs no configuration for this, and the working
directory already lines up: the project is bound at its real path and the
sandbox `chdir`s there, so the pane's cwd matches inside and out.

Agent detection needs one variable. Herdr identifies the agent from the pane's
foreground process, and ai-jail's PTY proxy and PID namespace hide it, so name
the agent explicitly:

```bash
HERDR_AGENT=claude ai-jail claude
```

If Herdr still cannot resolve the process group through the sandbox, set
`HERDR_PROCESS_DETECTION=child-groups` in the Herdr environment.

If agent state is reported incorrectly, note that Herdr classifies state from
the pane's bottom screen rows, which is also where ai-jail's status bar draws;
`--no-status-bar` removes that overlap.

**Do not mount the Herdr control socket into the sandbox.** `HERDR_*` variables
and `~/.config/herdr/herdr.sock` are not passed in, and that is deliberate:
`herdr tab create` runs a command on the host, so an agent that can reach the
socket can execute outside the jail. Hook-based state reporting from inside the
sandbox would require exactly that, and it trades away the sandbox — leave
detection to `HERDR_AGENT` and screen manifests instead.

## Troubleshooting

**`bwrap: setting up uid map: Permission denied` (Ubuntu 24.04+ / Debian 13+).**
These distros ship an AppArmor policy denying unprivileged user namespaces,
which is how `bwrap` isolates the sandbox. This affects every rootless
user-namespace tool (Distrobox, rootless Podman, Flatpak from non-standard
paths), not just ai-jail. Relax it system-wide:

```bash
echo 'kernel.apparmor_restrict_unprivileged_userns=0' \
  | sudo tee /etc/sysctl.d/60-userns.conf
sudo sysctl --system
```

Or keep the rest of the policy intact with an unconfined profile for `bwrap`
only, in `/etc/apparmor.d/bwrap`:

```
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
```

Then `sudo apparmor_parser -r /etc/apparmor.d/bwrap`.

**`Failed to create stream fd: No such file or directory` at startup.**
This comes from mise setup, not from ai-jail. mise activation runs under a
login shell, which sources `/etc/profile.d/*.sh`; on Ubuntu desktop one of
those scripts (for example `im-config_wayland.sh`) logs through `systemd-cat`,
and the journald socket does not exist inside the sandbox. It is harmless and
mise still initializes. Silence it by masking the offending script
(`mask = ["/etc/profile.d/im-config_wayland.sh"]`) or by skipping mise setup
entirely with `--no-mise`.

## Platform and threat model

Linux uses namespace isolation and, where available, Landlock, seccomp, and
resource limits. macOS has no global filesystem reads, network, or host IPC by
default; `--agent-state` and other state mounts work on both platforms.
Overlay maps are copy-on-write on Linux only; on macOS they are honored as
read-only maps. `sandbox-exec` is deprecated and neither backend protects
against kernel/driver vulnerabilities, terminal emulator vulnerabilities, or
all IPC and side-channel classes. For truly hostile workloads, use a
disposable VM.

See [docs/SECURITY.md](docs/SECURITY.md) for the complete threat model,
capability matrix, residual risks, and disclosure guidance. Release
administrators should follow [docs/RELEASE_SECURITY.md](docs/RELEASE_SECURITY.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
