# Security model

**Read this first: ai-jail is an accident guard, not a security boundary.**
It exists to stop a trusted-but-fallible AI agent from making a mistake —
a mistyped command that deletes files outside the project, a script that
walks up past the project root, a `git` or package-manager command that
touches something it shouldn't — not to contain a motivated adversary or
malicious code. The threat model is accidental damage and scope-creep from
a tool you already chose to run, not a hostile party actively trying to
break out of the sandbox.

Consequently, ai-jail's defaults are tuned for development work, not hostile
code. The project directory is writable. A fresh known-harness profile reviews
harness credentials, toolchains, and network access before saving any of them.
Approved capabilities remain usable by every process in the jail. This makes
the expected blast radius visible; it does not make malicious code safe.

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

| Capability             | Linux default                  | macOS default                  | Explicit opt-in and risk                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------- | ------------------------------ | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Private home           | on                             | on                             | `--no-private-home` grants broad host-home visibility; prefer command-specific state or maps.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Network                | fresh profile: off             | fresh profile: off             | The checklist can approve filtered access to the known harness API, dependency registries, or unrestricted OPEN network. In legacy/no-profile evaluation, an unset posture still derives the known API host and, on Linux with toolchains enabled, registry hosts (issue #156). Explicit `--allow-host` entries union with those derived hosts; use `--no-network --allow-host …` for only the named hosts. `--network` is unrestricted. `--allow-private-host` permits one named host to resolve to private, ULA, or CGNAT addresses but still rejects loopback, link-local, metadata, multicast, and unspecified addresses. An unavailable Linux network namespace fails offline. Browser launches, `--network`, `--no-network`, and `--lockdown` suppress automatic derived hosts. |
| GPU                    | off                            | n/a                            | `--gpu` exposes host GPU devices/driver attack surface.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| KVM                    | off                            | n/a                            | `--kvm` (Linux) binds `/dev/kvm`, exposing the host kernel's KVM ioctl interface to sandboxed processes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Wayland                | off                            | n/a                            | `--display` exposes only the validated Wayland socket, not all of `XDG_RUNTIME_DIR`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| X11                    | off                            | n/a                            | `--x11` permits X11 keylogging and screenshots.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Audio                  | off                            | n/a                            | `--audio` (Linux) binds the validated PipeWire/PulseAudio sockets in `XDG_RUNTIME_DIR` and `/dev/snd`; a sandboxed process can record and play audio while enabled.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Host shared memory     | off                            | n/a                            | `--host-shm` enables host cross-process IPC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Raw terminal protocol  | filtered                       | filtered                       | `--terminal-passthrough` restores clipboard/query/parser surface; agent output passes through a filtering VT parser by default. Window titles (OSC 0/1/2) are forwarded by default, rebuilt from printable UTF-8 text of at most 1024 bytes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Terminal appearance    | off                            | off                            | `--terminal-appearance` permits OSC 11 background-color query/reply, DA1 terminal-identity query/reply (including the Kitty trailing-semicolon form), and Mode 2031 support probe, enable/disable, and light/dark notifications in the interactive ai-jail PTY. `--no-terminal-appearance` disables that permission. Independent of raw terminal passthrough; it does not grant clipboard or unrelated queries and has no effect for non-TTY or `--exec` launches. |
| Agent credential state | first-run developer preset: on | first-run developer preset: on | The raw CLI/config default is off. The visible first-run developer preset selects this grant. When approved or passed as `--agent-state`, it mounts the invoked harness's credential/state directory read-write and copies its known API-key environment variable when set. Anything in the jail can use those credentials for the launch. `--no-agent-state` forces an isolated, logged-out run; `--lockdown` disables the grant. Legacy `--ssh` and `--github` remain separate OPEN grants.                                                                                                                                                                                                                                                                                         |
| Selected-key SSH       | off                            | off                            | Guided setup loads selected file-backed keys into a fresh bounded-lifetime agent, requires verified destination constraints, and never mounts private key files or the ambient agent. Native SSH also requires unrestricted-network OPEN. Direct SSH must use the generated `AI_JAIL_SSH` and `AI_JAIL_SSH_CONFIG` variables.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Full host SSH          | off                            | off                            | Legacy `--ssh` is OPEN: it shares `~/.ssh` and the ambient agent. Prefer selected-key SSH from `configure`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Environment variables  | minimal allowlist              | minimal allowlist              | `--env NAME[=VALUE]` adds named variables; `--inherit-env` passes the entire parent environment, secrets included. On Linux, explicit `--env` and `--env-from-file` values travel to bwrap through a memfd; macOS sets the child environment. Literal `--env NAME=VALUE` remains visible on ai-jail's own argv; sandboxed processes can read passed values. Diagnostics never print those values: `status` lists names only, `--dry-run` shows `--setenv NAME <redacted>`, and a config parse error masks the value half of every `NAME=VALUE` token while keeping the file, line, and column. Use `--secret KEY=host` to keep a bound HTTP secret outside the jail.                                                                                                                  |
| Update check           | off                            | off                            | `--update-check` enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active; all other launches make no network requests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

| macOS host IPC | n/a | off | `--macos-host-ipc` permits Mach, IOKit, and host IPC exposure. |
| macOS Chromium | n/a | off | `--macos-chromium` permits only `mach-register`/`mach-lookup` of `*.MachPortRendezvousServer.<pid>`. |
| macOS trustd | n/a | off | `--macos-trustd` permits only `mach-lookup` of `com.apple.trustd.agent`. |
| macOS runtime PTYs | n/a | off | `--allow-pty` grants `file-read*`/`file-write*`/`file-ioctl` over `^/dev/ttys[0-9]+$` so a process can open PTY slave nodes it allocates at runtime (issue #209). SBPL cannot scope the rule to the sandbox's own process tree, so it is path-scoped and also covers the user's other terminals, including `TIOCSTI`/write — the surface advisory GHSA-w976-gw52-hvx2 #4 removed from the default. It is still far narrower than the only previous workaround, `rw_maps = ["/dev"]`, which makes every device node writable. Off by default and dropped under `--lockdown`. |
| macOS loopback listen | n/a | off | `--allow-loopback-listen` adds `network-bind`/`network-inbound` scoped to `localhost` under filtered egress, so a sandboxed process can run a local server on `127.0.0.1` without `--network` dropping egress filtering (issue #213). Seatbelt shares the host network stack, so this binds the host's loopback. Off by default and dropped under `--lockdown`. |
| Linked-worktree metadata | off | off | `--worktree` exposes validated worktree metadata read-write so git can write objects and refs; the common dir may sit outside the project. `--lockdown` keeps it read-only. |
| Docker | off | off | `--docker` is root-equivalent through the daemon. |
| systemd user bus | off | n/a | `--systemd-user` can ask the host user manager to run services. |
| Host loopback forward | off | off | `--forward-port PORT` exposes the host service on `127.0.0.1:PORT` (or `::1`) in full, under `--lockdown` too, with no allowlist, inspection or audit record; at most 256 relays at once on Linux; on macOS a Seatbelt outbound rule names the port instead of a relay. Under filtered egress, Linux always exempts loopback from the proxy environment because its isolated network namespace has no host services; macOS exempts loopback only when a forwarded port is present. Unforwarded host loopback ports stay closed. |
| All host loopback services | no effect | off | `--allow-loopback-connect` is an explicit **OPEN** macOS grant for outbound connections to ALL host loopback services and every port. It emits only a localhost-scoped Seatbelt rule and composes `NO_PROXY`/`no_proxy` so those connections bypass the filtered CONNECT proxy. Trusted config or CLI only; untrusted project policy cannot enable it, and `--lockdown` disables it. Prefer fixed-port `--forward-port PORT`. Linux accepts the field for portable config but does not widen access. |
| Sandbox loopback publish | off | n/a | `--publish-port PORT` (Linux) listens on the host's `127.0.0.1:PORT`, never `0.0.0.0`, and relays each connection to the sandbox's own `127.0.0.1:PORT` (or `::1`): the jailed service is reachable by every process on the host's loopback, with no authentication added. The supervisor hands each accepted connection to the in-sandbox bridge over the mounted Unix socket, so the sandbox gains no outbound path (the bridge holding them is non-dumpable); at most 256 relays at once. Under `--lockdown` the service may bind that port only, and it joins the connect allow set like a forward. Refused with `--network`, for ports below 1024, and on macOS. |
| Dev toolchains | first-run developer preset: on | no effect (Linux-only) | The raw CLI/config default is on, and the visible first-run developer preset selects it. Linux exposes read-only toolchain binaries (for example `~/.cargo/bin`, `~/.rustup`) and a jail-owned, read-write dependency cache separate from the host caches, plus filtered registry egress when no network posture is asserted. `--no-toolchains` and `--lockdown` disable it. The cache maps use alternate destinations, which macOS Seatbelt cannot express (issue #148). |
| GitHub CLI credentials | off | off | Legacy `--github` is OPEN: it mounts the effective gh config directory read-only and forwards the active github.com token from host gh, including keyring storage. Sandboxed programs can act with the token's complete authority. Prefer `ai-jail forge setup` for repository-bound access. |
| AWS credentials | off | off | `--aws` mounts `~/.aws` read-only; the agent can then act as you on AWS. |
| Kubernetes credentials | off | off | `--kube` mounts `~/.kube` read-only; the agent can then act as you against your clusters. |
| gcloud credentials | off | off | `--gcloud` mounts `~/.config/gcloud` read-only; the agent can then act as you on GCP. |
| Docker registry credentials | off | off | `--docker-config` mounts `~/.docker/config.json` read-only; the agent can then push/pull as you against your registries. |
| Browser profile | off (`hard` when the command is a known browser) | off (`hard` when the command is a known browser) | `--browser[=hard\|soft]`, automatic for a known browser command (`--no-browser` turns it off). Chromium, Chrome and Brave run with `--no-sandbox`, so ai-jail is the only boundary between a web page and what the browser can reach: the profile (`soft` keeps cookies and logins), the project, and the network under `--network`. ai-jail passes no such flag to Firefox or LibreWolf. |

`--display` does not imply X11: X11 needs `--x11`. `--browser` reuses an
isolated profile but still requires explicit `--network` and, on Linux,
`--display` (or `--x11`) to reach anything; on macOS the display is
system-level, so only `--network` applies there. A macOS hard browser profile
lives in the launch's dedicated session scratch directory and is removed when
the browser exits; only the selected native `.app` bundle is readable, not all
of `/Applications`. Systemd user integration uses explicit narrow sockets
only. Docker/Podman control is opt-in and requires an actual reachable Unix
socket. ai-jail checks `DOCKER_HOST`, `CONTAINER_HOST`, standard rootless
runtime locations, common macOS Docker Desktop/Colima locations, then rootful
Podman and Docker sockets. Network endpoints are not mounted, the resolved
Unix endpoint is forwarded to both CLIs, and `~/.docker` is not broadly
mounted. Kimi and other agent state is command-specific under private home.

`--allow-tcp-port` is accepted for compatibility but launch fails closed. UDP
cannot be securely constrained by that interface. Use `--network` if the
resulting unrestricted network access is explicitly intended.

On Linux, `--prompt-hosts` turns a filtered-egress refusal into an interactive
desktop approval. This is a trusted capability: only the CLI or global config
may enable it, and `--lockdown` disables it. Decisions last only for the
current process. The proxy resolves the hostname before prompting and dials
only that answer set; loopback, link-local, multicast, unspecified, and cloud
metadata addresses are always refused without prompting. Private, unique-local,
and carrier-grade NAT answers are identified in the prompt and require an
explicit approval. A missing notification helper, dismissal, timeout, or any
prompt error fails closed for that connection. The waiting helper is closed
with SIGINT at that deadline, and any prompt still waiting at exit is
interrupted the same way, because a killed helper leaves a critical
notification behind that the desktop never expires; the timeout passed to the
helper also outlives ai-jail's own deadline so the daemon cannot answer for it. The helper is accepted only
from a fixed system directory with trusted ownership and permissions.

Read-only for the five legacy credential flags above protects the file from
modification, not the credential from use: anything in the sandbox can act as
you on that service for as long as the credential is valid. That is why each
stays opt-in and is disabled under `--lockdown`. The raw defaults are off;
first-run `For developers` visibly preselects only GitHub and requires a
Cancel-first OPEN confirmation when saving. Legacy repository policy can only
tighten a capability while it awaits migration; it cannot turn one on.

`ai-jail forge` keeps repository-bound credentials in a separate owner-only
store. A GitHub App token is minted for one selected repository and one launch;
normal exit attempts revocation, while token expiry is the boundary after a
crash. GitLab, Codeberg/Forgejo, and supported Gitea imports remain
`OPEN · USER-ASSERTED · PERSISTENT` whenever the provider cannot prove that the
presented token lacks authority elsewhere. The exact HTTPS repository path is
enforced independently by the Git credential helper, but that path restriction
does not reduce API-token authority. See [FORGE_AUTH.md](FORGE_AUTH.md).

Trusted wrappers use the versioned contract in
[WRAPPER_INTEGRATION.md](WRAPPER_INTEGRATION.md). `--harness` supplies identity,
while `--request-file` supplies requested authority from a guarded file outside
the checkout. Neither is a grant: exact requests must be approved in the
external project profile. Repository files cannot provide request manifests,
and non-interactive launches fail before sandbox creation when a request is
pending. `status --json` is the read-only preflight surface.

## Configuration trust boundary

The trusted store is `$XDG_CONFIG_HOME/ai-jail` (normally
`~/.config/ai-jail`). Global policy is `config.toml`; per-project documents
are under `projects/`. The store and its parents reject symlink components,
files are owner-only, and the whole store is masked from the sandbox. A project
document records its canonical path, separates grants from constraints, and
keeps migration provenance. Saved directory grants also record filesystem
identity and fail closed if the target moves, disappears, or changes identity.

Repository `.ai-jail` and `~/.ai-jail` are legacy inputs. A writable launch
copies a safe global file into the trusted store. It projects a repository file
to monotonic constraints only, so commands, maps, credential access, network
grants, and policy exceptions are not imported as authority. The destination
is durably written and parsed before the source is removed. Migration notices
are shown when ai-jail finishes, including after a later launch error. A tracked repository file remains deleted in
the Git worktree; restoring it does not override an existing external profile.

For compatibility before migration, a legacy repository file is untrusted and
may only tighten policy. The legacy global `trust_project_config` setting can
temporarily opt selected directories into the old trusted merge:

```toml
# ~/.config/ai-jail/config.toml
trust_project_config = ["~/work/repos"]
```

A project cannot confer this trust on itself. Everything beneath a listed
directory is included, including repositories cloned later, so keep the list
narrow. Legacy global symlinks are accepted for migration only when their
resolved file is user-owned, is not group- or world-writable, and lies outside
the project. Unsafe, unreadable, malformed, conflicting, or changed migration
sources fail closed and remain in place.

`project_strategy = "repo-root"` is likewise trusted global policy that a
repository cannot set. It lets a linked worktree use its main repository's
saved policy, which also shares forge bindings and credentials across its
worktrees. The worktree's repository metadata is repository-authored, so it
passes the same structural validation as other worktree metadata
(GHSA-w976-gw52-hvx2) before it can select a policy. Refused metadata or a
missing main checkout falls back to the launch directory's own policy with a
warning, and a bare repository keeps it silently. None of these widens access.

Structural validation does not mean the user authored that metadata. With
`--worktree` the jailed agent can write the repository's common git
directory, and an agent launched in a main checkout already has `.git/` inside
its writable project. Such an agent can create
`.git/worktrees/<name>/{gitdir,commondir}` and a matching `.git` gitfile in any
directory it can write. Under `repo-root`, later launches in that directory
then use this repository's saved policy and ignore the directory's own saved
policy, including any restrictions saved only there. This grants nothing
beyond what the agent already holds: it can only write where it already has
write access, and the policy it selects is one the user approved for this
repository. To keep the substitution visible, ai-jail prints one warning
whenever a resolved repository policy overrides an existing per-directory
policy document. Every checkout's automatic save merges restrictions into the
shared document rather than replacing them, so a launch in one checkout cannot
remove restrictions saved from another.

Private home is on by default. ai-jail exposes only state needed by the
invoked agent. The first-run developer preset visibly selects agent credential
state; disabling it or passing `--no-agent-state` keeps the harness logged out.
Selecting it or passing `--agent-state` mounts the harness state so it starts
pre-authenticated. `--no-agent-state` forces an isolated, logged-out run. Use
`--no-private-home` only as an explicit broad host-home exception.

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
denied without `--macos-host-ipc`. `--macos-chromium` is a much narrower
opt-in for headless Chromium: it lets the browser register and look up its own
`<bundle id>.MachPortRendezvousServer.<pid>` service and nothing else. Without
it the browser dies on the denied `mach-register`, and `--macos-host-ipc`
does not cover registration. `--macos-trustd` is similarly narrow: it grants
only the `com.apple.trustd.agent` lookup that Go and Security.framework TLS
clients (e.g. `gh`) need to verify certificates, which otherwise fail with
`OSStatus -26276`. Like the other macOS opt-ins, repository constraints cannot
enable it and `--lockdown` drops it. The default profile also grants
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

The writable project directory includes `.git/`, and host-side git trusts what
it finds there. A program named in `.git/config`, such as `core.fsmonitor` or
`core.pager`, or an executable in `.git/hooks/`, runs as you, outside the
sandbox, when the matching git operation next runs on the host. For
`core.fsmonitor` that is a plain `git status`, including one another tool runs
in the background. Unlike an edited `Makefile` or `package.json`, such a change
needs no project code to be run and does not show in `git diff`. `--lockdown`
closes it by mounting the project read-only, and `--map .git` keeps the
repository read-only in a normal run at the cost of committing from inside the
sandbox. On Linux, mapping only `.git/config` and `.git/hooks` read-only stops
an accidental write but not a process that renames `.git` and builds a new one.
If a session did something you did not expect, read `.git/config` and list
`.git/hooks` with plain file tools before running git on the host —
`git config --list` itself starts the configured pager.

`--mask` and `--deny-path` change what the sandbox sees, not the host files:
on Linux they are placeholder mounts in the sandbox's mount namespace, on
macOS seatbelt deny rules. Anything outside the sandbox that acts for the agent
still reads the real files — for example the Docker daemon under `--docker`,
or an MCP server or broker reached through a mapped socket. A tool that serves
a sandboxed agent from the host has to apply the same masks itself.

On Linux those placeholder mounts pin the file's inode, so replacing the path
on the host while the sandbox runs — `mv` of a temp file over it, which is
what `sed -i` and many editors' saves do, or delete-and-recreate — detaches
the mount and the running sandbox reads the new, unmasked file. Writing in
place keeps the mask; the jailed process cannot cause this itself (the masked
path is a mount point and renames over it fail with `EBUSY`). Keep a secret
you will edit during a session inside a masked directory, or restart the
sandbox after saving it. macOS rules match the path, not the inode, and are
not affected.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting: go to the repository's **Security** tab and choose
**Report a vulnerability**, or open
<https://github.com/akitaonrails/ai-jail/security/advisories/new> directly.
Include reproduction steps and affected versions, and allow time to coordinate
a fix and disclosure.
