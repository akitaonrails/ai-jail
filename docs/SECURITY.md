# Security model

ai-jail is a process sandbox for AI tools, not a malware-analysis boundary.
It limits ordinary filesystem, namespace, and IPC exposure; a kernel, driver,
or sandbox escape is outside its boundary. Use a disposable VM for truly
hostile workloads.

## Defaults and explicit capabilities

| Capability               | Linux default     | macOS default     | Explicit opt-in and risk                                                                                                                                                                     |
| ------------------------ | ----------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Private home             | on                | on                | `--no-private-home` grants broad host-home visibility; prefer command-specific state or maps.                                                                                                |
| Network                  | off               | off               | `--network` permits unrestricted traffic and therefore full network exfiltration of readable data.                                                                                           |
| GPU                      | off               | n/a               | `--gpu` exposes host GPU devices/driver attack surface.                                                                                                                                      |
| Wayland                  | off               | n/a               | `--display` exposes only the validated Wayland socket, not all of `XDG_RUNTIME_DIR`.                                                                                                         |
| X11                      | off               | n/a               | `--x11` permits X11 keylogging and screenshots.                                                                                                                                              |
| Host shared memory       | off               | n/a               | `--host-shm` enables host cross-process IPC.                                                                                                                                                 |
| Raw terminal protocol    | filtered          | filtered          | `--terminal-passthrough` restores clipboard/query/parser surface; agent output passes through a filtering VT parser by default.                                                              |
| Agent credential state   | off               | off               | `--agent-state` mounts the invoked agent's credential state (for example Claude's `~/.claude`) on Linux and macOS; anything in the sandbox can then use those credentials.                   |
| Environment variables    | minimal allowlist | minimal allowlist | `--env NAME[=VALUE]` adds named variables; `--inherit-env` passes the entire parent environment, secrets included.                                                                           |
| Update check             | off               | off               | `--update-check` enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active; all other launches make no network requests. |
| macOS host IPC           | n/a               | off               | `--macos-host-ipc` permits Mach, IOKit, and host IPC exposure.                                                                                                                               |
| Linked-worktree metadata | off               | off               | `--worktree` exposes validated worktree metadata read-write so git can write objects and refs; the common dir may sit outside the project. `--lockdown` keeps it read-only.                  |
| Docker                   | off               | off               | `--docker` is root-equivalent through the daemon.                                                                                                                                            |
| systemd user bus         | off               | n/a               | `--systemd-user` can ask the host user manager to run services.                                                                                                                              |

`--display` does not imply X11: X11 needs `--x11`. `--browser` reuses an
isolated profile but still requires explicit `--network` and, on Linux,
`--display` (or `--x11`) to reach anything; on macOS the display is
system-level, so only `--network` applies there. Systemd user integration
uses explicit narrow sockets only. Docker requires `DOCKER_HOST` to name an
actual Unix socket; network endpoints are not mounted, and `~/.docker` is not
broadly mounted. Kimi and other agent state is command-specific under private
home.

`--allow-tcp-port` is accepted for compatibility but launch fails closed. UDP
cannot be securely constrained by that interface. Use `--network` if the
resulting unrestricted network access is explicitly intended.

## Configuration trust boundary

Project `.ai-jail` is untrusted input. Its policy is monotonic: it can tighten
the effective sandbox but cannot enable capabilities, outside-source or
outside-destination maps, ports, `claude_dir`, or policy exceptions. Put
capability opt-ins in `~/.ai-jail` command-specific tables or on the CLI.

Teams that ship per-repository policy can opt specific directories out of that
rule from the trusted global config:

```toml
# ~/.ai-jail
trust_project_config = ["~/work/repos"]
```

A project at or beneath a listed directory is merged with the same semantics
as a global `[commands.<name>]` table, so its `.ai-jail` may enable
capabilities. Both paths are resolved before comparison, so `..` segments and
symlinks cannot smuggle an unlisted project past the check, and a project that
sets `trust_project_config` itself is ignored — trust is only ever conferred by
the global config. Everything under a listed directory is trusted, including
repositories cloned there later, so keep the list narrow.
Existing unreadable or invalid config fails closed. Bootstrap output is mode
`0600`; launch wrappers and overlay setup also fail closed.

The project `.ai-jail` is never followed through a symlink. The global
`~/.ai-jail` may be one, so dotfile managers such as GNU stow work, but only
when the resolved target is a regular file this user owns, carries no group or
other write bits, and lies outside the project directory — a target inside the
project could be rewritten by the very agent the policy constrains.

Private home is on by default. ai-jail exposes only state needed by the invoked
agent, and agent credential state itself is opt-in (`--agent-state`, also
settable per command in `~/.ai-jail`). Use
`--no-private-home` only as an explicit broad host-home exception.

## Platform notes and residual risks

Linux combines bubblewrap namespaces with Landlock, seccomp, and resource
limits where available. `BWRAP_BIN` must resolve canonically either to a
root-owned executable with no group- or world-write bits, or to an executable
with no write bits at all under a `/nix/store` that the invoking user cannot
write. A single-user Nix store owned by that user does not qualify: anything
running as them could otherwise supply a fake bwrap and silently disable the
sandbox.

macOS starts with no global reads, network, or host IPC, and supports the same
opt-in `--agent-state` credential mounts as Linux. Temp access is limited to a
private per-launch session directory pointed to by `TMPDIR`, with one
command-specific exception: `claude` is also granted write access to
`/private/tmp/claude-<uid>`, scoped to the invoking uid, because Claude Code
creates that path unconditionally at startup and ignores `TMPDIR`. It is
outside the project and persists between runs; `--overlay-map` is honored
as a read-only map because copy-on-write overlays are Linux-only.
`sandbox-exec` is deprecated by Apple and is not equivalent to Linux
isolation; use a disposable VM for hostile workloads. Agents need `file-ioctl`
on their own terminal to enter raw mode, and SBPL cannot filter by ioctl
request, so the grant is scoped by path to the single PTY ai-jail allocated
for that run — never a pattern covering every `/dev/ttys*`, which would let a
compromised agent use `TIOCSTI` to inject input into another of your shells.
When ai-jail is not proxying a PTY, no terminal ioctl is granted at all.
`/dev/ptmx` stays available so the sandbox can allocate its own PTYs; a PTY
created inside the sandbox is not covered by the path-scoped rule. Linux
denies `TIOCSTI` outright through seccomp. On both platforms,
kernel and driver bugs, terminal emulator bugs (especially after terminal
passthrough), and sandbox backend defects remain residual risk.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting: go to the repository's **Security** tab and choose
**Report a vulnerability**, or open
<https://github.com/akitaonrails/ai-jail/security/advisories/new> directly.
Include reproduction steps and affected versions, and allow time to coordinate
a fix and disclosure.
