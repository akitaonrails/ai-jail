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
```

Build from source with Rust `1.97.1`:

```bash
cargo build --release --locked
install -Dm755 target/release/ai-jail ~/.local/bin/ai-jail
```

Linux requires `bwrap` (`bubblewrap`). `BWRAP_BIN` is accepted only when it
canonically resolves to a root-owned executable that is not group- or
world-writable. A typical protected Nix-store executable is accepted. macOS
uses Apple's deprecated `/usr/bin/sandbox-exec` interface. Windows is not
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

| Flag pair | Effect and security consequence |
|---|---|
| `--network` / `--no-network` | Enables/disables unrestricted network. `--network` permits full network exfiltration of any readable data. |
| `--gpu` / `--no-gpu` | Enables/disables GPU device access. |
| `--display` / `--no-display` | Enables/disables display access. Only the validated Wayland socket is mounted; ai-jail never mounts all of `XDG_RUNTIME_DIR`. X11 is separate (`--x11`). |
| `--x11` / `--no-x11` | Enables/disables X11 separately. X11 access permits keylogging and screenshots. |
| `--host-shm` / `--no-host-shm` | Enables/disables host `/dev/shm`; enabling it opens host cross-process IPC. |
| `--terminal-passthrough` / `--no-terminal-passthrough` | Enables/disables raw terminal forwarding. Output is filtered through a VT parser by default; raw forwarding exposes terminal clipboard, query, and parser surface. |
| `--agent-state` / `--no-agent-state` | Enables/disables mounting the invoked command's credential state (default off). Enables the agent to authenticate — and lets anything in the sandbox use those credentials. |
| `--inherit-env` / `--no-inherit-env` | Default is a minimal environment allowlist. `--inherit-env` passes the full parent environment, secrets included. |
| `--update-check` / `--no-update-check` | Enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active (default off; all other launches make no network requests). |
| `--macos-host-ipc` / `--no-macos-host-ipc` | Enables/disables macOS Mach, IOKit, and host IPC exposure. |
| `--worktree` / `--no-worktree` | Enables/disables validated linked-worktree common metadata, mounted read-only when enabled. |
| `--private-home` / `--no-private-home` | Enables/disables the default private home. Disabling it is broad host-home access. |

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

## Ephemeral home and temp

The private home is a fresh tmpfs per launch. Nothing persists between runs
except state you explicitly mount (agent state, `--rw-map`, command tables).
`/tmp` inside the sandbox is sandbox-local and discarded on exit; writes to
dotfiles and caches vanish with the sandbox. Use a map or `--agent-state` for
anything durable.

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
