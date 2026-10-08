# Security model

**Read this first: ai-jail is an accident guard, not a security boundary.**
It exists to stop a trusted-but-fallible AI agent from making a mistake —
a mistyped command that deletes files outside the project, a script that
walks up past the project root, a `git` or package-manager command that
touches something it shouldn't — not to contain a motivated adversary or
malicious code. The threat model is accidental damage and scope-creep from
a tool you already chose to run, not a hostile party actively trying to
break out of the sandbox.

Consequently, ai-jail's defaults are tuned for developer convenience, not
lockdown security: your project directory is writable, the invoked agent's
own credentials and dev toolchains are available out of the box, and
capabilities tighten only as you opt in (see the table below). This is a
deliberate trade: it is what makes it reasonable to run an AI harness in an
auto-accept / "YOLO" mode with confidence that the worst case stays inside
the project, not a claim that nothing inside the sandbox can be abused by
something that is actually trying to.

ai-jail is a process sandbox for AI tools, not a malware-analysis boundary.
It limits ordinary filesystem, namespace, and IPC exposure; a kernel,
driver, or sandbox escape is outside its boundary, and it makes no attempt
to resist a determined attacker who controls what runs inside it. **Use a
disposable VM for hostile code or untrusted workloads** — ai-jail is not a
substitute for one.

## Defaults and explicit capabilities

The table below is not a list of things ai-jail blocks by default so much as
a map of what is exposed for developer convenience and what still requires
an explicit opt-in. Everything marked "on" is a deliberate dev-friendly
default, not an oversight.

| Capability                  | Linux default                                                                                                   | macOS default                               | Explicit opt-in and risk                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Private home                | on                                                                                                              | on                                          | `--no-private-home` grants broad host-home visibility; prefer command-specific state or maps.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Network                     | off, except filtered registry egress for toolchains and documented Claude hosts when applicable | off, except documented Claude hosts for a normal Claude launch | `--network` permits unrestricted traffic and therefore full network exfiltration of readable data. With no explicit network posture or host list, Claude launches receive filtered egress to `api.anthropic.com`, `statsig.anthropic.com`, and `sentry.io` (Anthropic's documented Claude Code endpoints). Linux also adds package-registry hosts when toolchains are enabled. Linux defaults are gated on an unprivileged network-namespace probe and stay offline when unavailable. An explicit `--no-network`, `--allow-host` list, browser launch, or lockdown suppresses the Claude defaults. |
| GPU                         | off                                                                                                             | n/a                                         | `--gpu` exposes host GPU devices/driver attack surface.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| KVM                         | off                                                                                                             | n/a                                         | `--kvm` (Linux) binds `/dev/kvm`, exposing the host kernel's KVM ioctl interface to sandboxed processes.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Wayland                     | off                                                                                                             | n/a                                         | `--display` exposes only the validated Wayland socket, not all of `XDG_RUNTIME_DIR`.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| X11                         | off                                                                                                             | n/a                                         | `--x11` permits X11 keylogging and screenshots.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Audio                       | off                                                                                                             | n/a                                         | `--audio` (Linux) binds the validated PipeWire/PulseAudio sockets in `XDG_RUNTIME_DIR` and `/dev/snd`; a sandboxed process can record and play audio while enabled.                                                                                                                                                                                                                                                                                                                                                                    |
| Host shared memory          | off                                                                                                             | n/a                                         | `--host-shm` enables host cross-process IPC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Raw terminal protocol       | filtered                                                                                                        | filtered                                    | `--terminal-passthrough` restores clipboard/query/parser surface; agent output passes through a filtering VT parser by default.                                                                                                                                                                                                                                                                                                                                                                                                        |
| Agent credential state      | on                                                                                                              | on                                          | On by default: mounts the invoked harness's own credential/state dir (for example Claude's `~/.claude`) read-write on Linux and macOS, and copies its known API-key env var from the host when set, so it starts pre-authenticated. `--no-agent-state` opts out for an isolated, logged-out run; disabled under `--lockdown`. Anything in the sandbox can use those credentials while mounted, which is the trade-off for not having to re-authenticate every launch.                                                                  |
| Environment variables       | minimal allowlist                                                                                               | minimal allowlist                           | `--env NAME[=VALUE]` adds named variables; `--inherit-env` passes the entire parent environment, secrets included. On Linux, explicit `--env` and `--env-from-file` values travel to bwrap through a memfd; macOS sets the child environment. Literal `--env NAME=VALUE` remains visible on ai-jail's own argv; sandboxed processes can read passed values. Use `--secret KEY=host` to keep a bound HTTP secret outside the jail.                                                                                                      |
| Update check                | off                                                                                                             | off                                         | `--update-check` enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active; all other launches make no network requests.                                                                                                                                                                                                                                                                                                                                           |
| macOS host IPC              | n/a                                                                                                             | off                                         | `--macos-host-ipc` permits Mach, IOKit, and host IPC exposure.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Linked-worktree metadata    | off                                                                                                             | off                                         | `--worktree` exposes validated worktree metadata read-write so git can write objects and refs; the common dir may sit outside the project. `--lockdown` keeps it read-only.                                                                                                                                                                                                                                                                                                                                                            |
| Docker                      | off                                                                                                             | off                                         | `--docker` is root-equivalent through the daemon.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| systemd user bus            | off                                                                                                             | n/a                                         | `--systemd-user` can ask the host user manager to run services.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Dev toolchains              | on                                                                                                              | no effect (Linux-only)                      | `--no-toolchains` disables it. On Linux, on by default it exposes read-only toolchain binaries (for example `~/.cargo/bin`, `~/.rustup`) and a jail-owned, read-write dependency cache kept separate from the host's own caches (never the host's real cache dirs), plus the default registry egress above; disabled under `--lockdown`. The cache maps use alternate destinations, which macOS seatbelt cannot express, so the whole toolchain cache + registry egress is Linux-only (issue #148).                                    |
| GitHub CLI credentials      | off                                                                                                             | off                                         | `--github` mounts the effective gh config directory read-only and forwards the active github.com token from host gh, including keyring storage; sandboxed programs can act with that token.                                                                                                                                                                                                                                                                                                                                            |
| AWS credentials             | off                                                                                                             | off                                         | `--aws` mounts `~/.aws` read-only; the agent can then act as you on AWS.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Kubernetes credentials      | off                                                                                                             | off                                         | `--kube` mounts `~/.kube` read-only; the agent can then act as you against your clusters.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| gcloud credentials          | off                                                                                                             | off                                         | `--gcloud` mounts `~/.config/gcloud` read-only; the agent can then act as you on GCP.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Docker registry credentials | off                                                                                                             | off                                         | `--docker-config` mounts `~/.docker/config.json` read-only; the agent can then push/pull as you against your registries.                                                                                                                                                                                                                                                                                                                                                                                                               |

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

Read-only for the five credential flags above protects the file from
modification, not the credential from use: anything in the sandbox can act as
you on that service for as long as the credential is valid. That is why each
stays opt-in, monotonic (an untrusted project `.ai-jail` may only disable one,
never enable it), and disabled under `--lockdown`. The same monotonic rule
applies to dev-toolchain support (`--no-toolchains` may only be set tighter
by a project file, never relaxed) and to agent-state, which is on by default
rather than opt-in but is monotonic in the other direction: a project file
may only disable it (`agent_state = false`), never force it back on past a
trusted `--no-agent-state`.

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

Private home is on by default. ai-jail exposes only state needed by the
invoked agent, and agent credential state is itself on by default
(`--agent-state`, also settable per command in `~/.ai-jail`) so the harness
starts pre-authenticated; `--no-agent-state` opts back out to an isolated,
logged-out run. Use `--no-private-home` only as an explicit broad host-home
exception.

## Platform notes and residual risks

Linux combines bubblewrap namespaces with Landlock, seccomp, and resource
limits where available. Seccomp denies raw and packet sockets, with one
narrow exception: `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`, which
`getifaddrs()` uses to enumerate local interfaces, is permitted when the
sandbox already has unrestricted network and is not in lockdown. Blocking it
there bought nothing — an agent with `--network` can learn the same addresses
by connecting out — while breaking any tool that calls `getifaddrs()`. Every
other netlink protocol and every other raw socket domain stays denied, and
under `--lockdown` or without `--network` so does this one, so lockdown's
`/sys/class/net` mask cannot be walked around. `BWRAP_BIN` must resolve canonically either to a
root-owned executable with no group- or world-write bits, or to an executable
with no write bits at all under a `/nix/store` that is itself owned by root
(or by an unmapped owner, which a user namespace reports as the overflow uid)
and is not world-writable. A single-user store owned by the invoking user does
not qualify: anything running as them could otherwise supply a fake bwrap and
silently disable the sandbox.

The store check deliberately stops at ownership and mode rather than asking
the kernel whether this process can write the directory. The standard
multi-user store is `root:nixbld` mode `1775`, and Nix builds run as a nixbld
member, so a writability probe answers "yes" for exactly the legitimate case
and rejects every such install. The sticky bit is what makes that group write
safe — a member can add store paths but not replace someone else's — so it is
required rather than assumed: a group-writable store without it is refused.
The binary itself must still carry no write bits.

macOS starts with no global reads, network, or host IPC, and supports the same
opt-in `--agent-state` credential mounts as Linux. Filtered egress
(`--allow-host`) replaces the blanket network denial with one endpoint-scoped
rule — outbound to `localhost:<proxy-port>` only, no inbound or bind — so the
child reaches nothing but the CONNECT proxy, which decides which targets are
allowed. The system resolver is not fenced: `getaddrinfo()` still works via
mDNSResponder even when `connect()` is denied, so a low-bandwidth DNS channel
remains (the same gap Anthropic's sandbox-runtime documents). Signalling between processes
inside the same sandbox is always allowed (`signal` targeting `same-sandbox`),
so an agent can manage the workers it spawns; signalling host processes stays
denied without `--macos-host-ipc`. The default profile also grants
file-read-metadata on `/private/var/select` and file-read on
`/private/var/select/sh`: since Catalina `/bin/sh` consults that file to pick
bash vs zsh, and without it every hook shell exits `EPERM` before it can exec.
Temp access is limited to a
private per-launch session directory pointed to by `TMPDIR`, with two
command-specific exceptions for `claude`, both matched under `/private/tmp`:
the per-uid directory `/private/tmp/claude-<uid>`, which Claude Code creates
unconditionally at startup and ignores `TMPDIR`, and the
`/private/tmp/claude-<hex>-cwd` marker file it writes loose in `/tmp` on every
Bash tool call, matched by a hex-scoped regex. They are
outside the project and persist between runs; `--overlay-map` is honored
as a read-only map because copy-on-write overlays are Linux-only.
`sandbox-exec` is deprecated by Apple and is not equivalent to Linux
isolation; use a disposable VM for hostile workloads. Agents need `file-ioctl`
on their own terminal to enter raw mode, and SBPL cannot filter by ioctl
request, so the grant is scoped by path to the single PTY ai-jail allocated
for that run — never a pattern covering every `/dev/ttys*`, which would let a
compromised agent use `TIOCSTI` to inject input into another of your shells.
Terminal read/write is scoped the same way — the allocated PTY plus the
caller's own `/dev/tty` — rather than a blanket `/dev/ttys*` grant, so the
sandbox cannot open another of your terminals by path and write escape
sequences to it. When ai-jail is not proxying a PTY, no terminal ioctl is
granted at all. `/dev/ptmx` stays available so the sandbox can allocate its own
PTYs; a PTY created inside the sandbox is not covered by the path-scoped rule.
Masked project paths (`--mask`) are denied for writes as well as reads, so a
file the agent cannot read cannot be blindly overwritten either. Linux denies
`TIOCSTI` outright through seccomp, and compares the ioctl request as the
kernel does (32-bit) so a high-bit variant cannot slip past the filter.
On kernels ≥ 6.12 Landlock also scopes abstract Unix sockets and signals
(best-effort) as a further backstop.

Phantom credentials (`--secret KEY=host`, filtered egress only) shift part of
the trust boundary to the supervisor: the sandbox env holds an
`AIJAIL-PHANTOM-…` placeholder, and the egress proxy substitutes the real
value only in the request head of plain-HTTP proxy requests terminating at the
bound host, re-originating them over TLS. Placeholders are not credentials —
knowing one authorizes nothing — and real values live only in supervisor
memory, never in any config file, the audit log, or the sandbox. The cost:
for secret-bound hosts the supervisor (and the proxy's TLS endpoint) sees the
request plaintext, by construction. CONNECT tunnels to any host stay opaque
and carry no substitution.

The macOS profile also grants `file-read-metadata` on each directory above an
allowed path, and on the symlink nodes leading to the command. Seatbelt
resolves a path one component at a time, so without this an allowed leaf stays
unreachable through the path callers actually walk. The grant is `stat()` of
those directory nodes only: it does not make them listable and does not reach
anything inside them, so it exposes the existence, mode and mtime of
directories the profile already grants access underneath — for a default run,
the chain down to the project and to the agent's own install. It is deliberately
narrower than a blanket `(allow file-read-metadata (subpath "/"))`, which would
also override the profile's own deny-list and let `stat` answer for `~/.ssh`
and `~/.aws`.

Naming the command's PATH entry matters for containment, not only for startup:
when that node is invisible, `execvp` does not fail, it continues down `PATH`
and runs the first match inside an already-readable prefix such as the Homebrew
one — a different build of the same tool than the one ai-jail resolved and
granted access to. On both platforms, kernel and driver bugs, terminal emulator
bugs (especially after terminal passthrough), and sandbox backend defects remain
residual risk.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting: go to the repository's **Security** tab and choose
**Report a vulnerability**, or open
<https://github.com/akitaonrails/ai-jail/security/advisories/new> directly.
Include reproduction steps and affected versions, and allow time to coordinate
a fix and disclosure.
