# ai-jail

**[aijail.io](https://aijail.io)**

`ai-jail` runs AI coding agents in an OS sandbox: bubblewrap plus Landlock,
seccomp, and limits on Linux; `sandbox-exec` on macOS.

## What ai-jail is (and isn't)

ai-jail is **not** a lockdown or hard-security tool, and it is **not** a
boundary against malware or other hostile code — for that, use a disposable
VM. Its job is to be **developer-friendly**: it defends against a
trusted-but-fallible agent's mistakes, not against a motivated attacker
actively trying to escape.

Concretely, that means your dev tools and the invoked agent's own
credentials are available **by default** — which is explicitly not a
lockdown-secure posture — with flags to progressively turn capabilities off.
The goal is to prevent _accidents_: an LLM running a mistyped command that
deletes unrelated important files outside the project, for example. With the
project directory as the blast radius, you can confidently turn on "YOLO
mode" (auto-accept, no confirmation prompts) in an AI harness with reasonable
confidence it won't damage anything outside the project scope.

It is a useful accident-prevention layer, not a replacement for a disposable
VM when running hostile code. See [docs/SECURITY.md](docs/SECURITY.md) for
the full threat model.

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
namespace), is not world-writable, and carries the sticky bit if it is
group-writable — the standard multi-user store layout, mode `1775`. A
group-writable store without the sticky bit is refused, because a group member
could then replace the binary. A single-user store owned by the invoking user
does not qualify either.
macOS uses Apple's deprecated `/usr/bin/sandbox-exec` interface. Windows is not
supported; use WSL2 and the Linux backend inside it.

## Quick start

```bash
cd ~/Projects/my-app
ai-jail claude                 # Claude's credential state mounted, pre-authenticated
ai-jail --no-agent-state claude  # isolated, logged-out run instead
ai-jail --dry-run claude
```

The project directory is writable by default; host capabilities are not. The
first ordinary run may create `.ai-jail`; `--dry-run` never writes it. Existing
unreadable or invalid project/global configuration fails closed rather than
launching with a weakened policy. Bootstrap output is always mode `0600`.

## Secure defaults

"Secure defaults" here means defaults tuned to stop accidents, not defaults
tuned to stop attackers — see
[What ai-jail is (and isn't)](#what-ai-jail-is-and-isnt). The project
directory is where the agent is expected to work; everything else on the
host is either hidden or exposed deliberately, capability by capability.

### On by default

- **Private home** — the agent gets a fresh tmpfs `$HOME`, not your host
  home.
- **Agent/harness auth (`agent_state`)** — the invoked harness's own
  credential/state dir (for example `~/.claude`, `~/.codex`,
  `~/.kimi`, `~/.gemini`) is mounted **read-write** so it starts
  pre-authenticated instead of asking you to log in every session; its
  known API-key env var (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`/`GOOGLE_API_KEY`, `XAI_API_KEY`, `MOONSHOT_API_KEY`) is
  also copied from the host when set. This is the trade-off for being
  developer-friendly: anything running in the sandbox can use those
  credentials for the life of the launch. `--no-agent-state` opts out for
  an isolated, logged-out run.
- **Dev toolchains (`--toolchains`)** — persistent, jail-owned dependency
  caches (cargo/npm/go/maven/...), the Rust toolchain mapped read-only,
  and, when the network posture is otherwise unset, filtered egress to
  package registries so a fresh `npm install`/`cargo build`/`go get` works
  out of the box — see [Dev toolchains](#dev-toolchains).
- **mise integration** — the project's language versions are activated
  automatically when mise is on `$PATH` — see
  [mise integration](#mise-integration).
- **Project directory** — read-write by default; `/tmp` inside the sandbox
  is writable (and discarded on exit).

### Off by default

network, GPU, KVM, display (Wayland), X11, audio, host shared memory, raw
terminal passthrough, the Docker socket, Tailscale, the systemd user bus,
SSH agent/key sharing, Pictures, linked Git worktree metadata,
`--inherit-env`, the update check, macOS host IPC, and the five opt-in
credential flags (`--github`, `--aws`, `--kube`, `--gcloud`,
`--docker-config`) — see [Tool credentials](#tool-credentials). Mounting
agent state or any of these exposes that material to everything running in
the sandbox, which is exactly why each one that isn't a default-on
dev-ergonomics capability stays an explicit opt-in. Use `--no-private-home`
only when deliberately granting broad host-home access; `--map` and
`--rw-map` remain explicit, narrow alternatives.

| Flag pair                                              | Effect and security consequence                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--network` / `--no-network`                           | Enables/disables unrestricted network. `--network` permits full network exfiltration of any readable data.                                                                                                                                                                                                                                                              |
| `--gpu` / `--no-gpu`                                   | Enables/disables GPU device access.                                                                                                                                                                                                                                                                                                                                     |
| `--display` / `--no-display`                           | Enables/disables display access. Only the validated Wayland socket is mounted; ai-jail never mounts all of `XDG_RUNTIME_DIR`. X11 is separate (`--x11`).                                                                                                                                                                                                                |
| `--x11` / `--no-x11`                                   | Enables/disables X11 separately. X11 access permits keylogging and screenshots.                                                                                                                                                                                                                                                                                         |
| `--audio` / `--no-audio`                               | Enables/disables host audio (Linux only). Binds the validated PipeWire/PulseAudio sockets in `XDG_RUNTIME_DIR` plus `/dev/snd`; anything in the sandbox can record and play audio while enabled.                                                                                                                                                                        |
| `--kvm` / `--no-kvm`                                   | Enables/disables `/dev/kvm` (Linux only) for hardware-accelerated VMs; exposes the host kernel's KVM ioctl interface. No `/dev/net/tun` or vhost devices; guests get only the sandbox's network.                                                                                                                                                                        |
| `--host-shm` / `--no-host-shm`                         | Enables/disables host `/dev/shm`; enabling it opens host cross-process IPC.                                                                                                                                                                                                                                                                                             |
| `--terminal-passthrough` / `--no-terminal-passthrough` | Enables/disables raw terminal forwarding. Output is filtered through a VT parser by default; raw forwarding exposes terminal clipboard, query, and parser surface.                                                                                                                                                                                                      |
| `--agent-state` / `--no-agent-state`                   | On by default. Mounts the invoked command's credential state read-write (for example `~/.claude`, `~/.codex`) and copies its known API-key env var from the host when set, so it starts pre-authenticated. `--no-agent-state` gives an isolated, logged-out run instead; lets anything in the sandbox use those credentials while enabled; disabled under `--lockdown`. |
| `--inherit-env` / `--no-inherit-env`                   | Default is a minimal environment allowlist. `--inherit-env` passes the full parent environment, secrets included.                                                                                                                                                                                                                                                       |
| `--update-check` / `--no-update-check`                 | Enables the status bar's outbound GitHub version check, run in a background thread while the interactive status bar is active (default off; all other launches make no network requests).                                                                                                                                                                               |
| `--macos-host-ipc` / `--no-macos-host-ipc`             | Enables/disables macOS Mach, IOKit, and host IPC exposure.                                                                                                                                                                                                                                                                                                              |
| `--worktree` / `--no-worktree`                         | Enables/disables validated linked-worktree metadata. When enabled, the per-worktree git dir and the shared common dir are writable so the agent can commit; `--lockdown` keeps both read-only.                                                                                                                                                                          |
| `--private-home` / `--no-private-home`                 | Enables/disables the default private home. Disabling it is broad host-home access.                                                                                                                                                                                                                                                                                      |
| `--toolchains` / `--no-toolchains`                     | On by default (Linux only; issue #148). Persists dependency caches (cargo/npm/go/maven/...) in a jail-owned store and maps Rust's toolchain binaries read-only; when the network posture is otherwise unset, also default-allows filtered egress to package registries. `--no-toolchains` disables both; disabled under `--lockdown`; no effect on macOS.               |
| `--github` / `--no-github`                             | Shares gh configuration read-only and the active github.com token from the host. Off by default; sandboxed programs can act with that token.                                                                                                                                                                                                                            |
| `--aws` / `--no-aws`                                   | Enables/disables read-only `~/.aws`. Off by default; anything in the sandbox can then act as you on AWS.                                                                                                                                                                                                                                                                |
| `--kube` / `--no-kube`                                 | Enables/disables read-only `~/.kube`. Off by default; anything in the sandbox can then act as you against your clusters.                                                                                                                                                                                                                                                |
| `--gcloud` / `--no-gcloud`                             | Enables/disables read-only `~/.config/gcloud`. Off by default; anything in the sandbox can then act as you on GCP.                                                                                                                                                                                                                                                      |
| `--docker-config` / `--no-docker-config`               | Enables/disables read-only `~/.docker/config.json`. Off by default; anything in the sandbox can then push/pull as you against your registries.                                                                                                                                                                                                                          |

When the invoked command itself lives under `$HOME`, its path is exempted
from the private home, and symlink chains along it are preserved as symlinks
inside the sandbox (regression: prime-agent/bun crashed with ENOENT
`package.json` when the exemption flattened the launcher symlink), so
symlink-following launchers keep resolving their app root. Only the terminal
real path is bind-mounted read-only.

### Turning it down

The default posture is developer-friendly: your tools and the invoked
harness's credentials are on, the project directory is read-write, and
filtered registry egress gets dependency installs working out of the box.
From there you can turn individual knobs down, or jump straight to the
strictest mode:

- **Selective opt-outs** — `--no-agent-state` (no harness credentials
  mounted), `--no-toolchains` (no caches, no registry egress),
  `--no-network` (fully offline, overriding the toolchain default), `--mask`
  / `--deny-path` (hide or deny specific project paths), `--hide-dotdir`
  (never mount a named dotdir), `--map` / `--rw-map` (scope extra mounts
  narrowly instead of a broad grant).
- **`--no-private-home`** goes the other way: it is **more** exposure, not
  less — the agent gets your real host `$HOME` instead of a fresh tmpfs one.
  Reach for it only when you deliberately want that, and prefer `--map` /
  `--rw-map` or a `[commands.<name>]` table for anything narrower.
- **`--lockdown`** — the maximum: read-only project directory, toolchains,
  agent-state, registry egress, and most other capabilities disabled, strict
  Landlock and seccomp. It is the closest ai-jail gets to a hard-security
  posture, but it is still not a VM — see
  [Platform and threat model](#platform-and-threat-model).

`--allow-host HOST` (repeatable, or `allow_hosts = [...]` in `.ai-jail`)
enables filtered egress instead: the sandbox keeps no route off the host
except a built-in CONNECT proxy that dials exactly the listed hosts — an
entry matches the host itself and its subdomains. On Linux the fence is a
private network namespace whose only reachable endpoint is an in-sandbox
bridge; on macOS it is a seatbelt endpoint rule allowing outbound only to
the proxy's loopback port. It is TCP/CONNECT-only:
no UDP, and no working DNS inside the sandbox on Linux (on macOS the system
resolver is not fenced). It cannot combine with `--network` or `--browser`,
and a project `.ai-jail` may only shrink the list, never grow it.

### Phantom credentials: `--secret KEY=host`

With filtered egress on, `--secret ANTHROPIC_API_KEY=api.anthropic.com`
(repeatable, or `secret_hosts = { ... }` in the global config) keeps the real
value out of the sandbox: the child env carries an `AIJAIL-PHANTOM-…`
placeholder, and the egress proxy swaps in the real value only for requests
terminating at the bound host. The key must already be passed via `--env` or
`--env-from-file`. One honest caveat: CONNECT tunnels stay opaque — this only
covers clients that can speak plain HTTP to the proxy (e.g. an
`ANTHROPIC_BASE_URL=http://…` override); those requests are terminated and
re-originated over TLS by the supervisor, which therefore sees that plaintext
for secret-bound hosts. HTTPS clients that only CONNECT keep working exactly
as before, with no substitution.

`--allow-tcp-port` remains accepted for backward compatibility, but launch
fails closed because UDP cannot be securely constrained through this option —
use `--allow-host` for filtered egress instead.
Use `--network` only when unrestricted network access is explicitly desired.

`--docker` mounts an actual Unix Docker socket and is effectively host-root:
the daemon can create host-mounted containers. `DOCKER_HOST` must identify an
actual Unix socket; TCP/SSH endpoints are not mounted. `~/.docker` is not
broadly mounted. `--systemd-user` exposes only explicit user-bus sockets, but
can still ask the host user manager to run services.

### Dev toolchains

`--toolchains` / `--no-toolchains` (on by default, **Linux only** — macOS
seatbelt cannot express the alternate-destination cache mounts, issue #148)
persists dependency caches across sessions without exposing your real toolchain
state. ai-jail maps a jail-owned cache store at
`~/.local/share/ai-jail/cache/`, separate from your host caches, so a jailed
build can never poison what the host builds from:

- Rust: `~/.cargo/bin` and `~/.rustup` are mounted **read-only** so
  `cargo`/`rustc` resolve; `~/.cargo/{registry,git}` are mounted
  **read-write** to the jail store instead. Cargo's own `config.toml` and
  credentials are never mapped. `cargo install` to the global bin is
  unsupported in-jail — use `cargo install --root`.
- Other ecosystems get a jail-owned cache at their default path when the
  tool's home dir exists on the host: `~/.cache` (pip, go build cache, yarn,
  deno, coursier, crystal, zig, composer), `~/go/pkg/mod`, `~/.npm`,
  `~/.m2/repository`, `~/.gradle/caches`, `~/.bun/install/cache`, and
  `~/.local/share/pnpm/store`.

When toolchains are enabled and the network posture is otherwise unset (no
`--network`, no `--no-network`, not `--lockdown`, not a browser launch),
ai-jail also default-allows filtered egress to the package registries
dependency managers actually need — `crates.io`, `registry.npmjs.org`,
`registry.yarnpkg.com`, `pypi.org`, `files.pythonhosted.org`,
`proxy.golang.org`, `sum.golang.org`, `repo1.maven.org`,
`repo.maven.apache.org`, `repo.clojars.org`, `repo.packagist.org`,
`github.com`, `codeload.github.com`, and `objects.githubusercontent.com` — so
a fresh `npm install`/`cargo build`/`go get` works without passing
`--allow-host`. Deny-by-default still holds: nothing else is reachable, and
an explicit `--allow-host` set is unioned with this list. The default is
gated on an unprivileged network-namespace probe: where netns is unavailable
(hardened kernels, some nested containers, restricted CI) it silently stays
offline instead of breaking the launch — an explicit `--allow-host` keeps its
fail-closed guarantee regardless. `--no-network` without an explicit
`--allow-host` list keeps the sandbox fully offline; combined with
`--allow-host`, it permits only that filtered host list. `--network` gives
unrestricted access instead of filtered egress.

When Claude Code is the invoked command and no network posture or explicit
`--allow-host` list is configured, ai-jail also enables filtered egress to
`api.anthropic.com`, `statsig.anthropic.com`, and `sentry.io`, the endpoints
listed in Anthropic's [Claude Code proxy documentation](https://docs.anthropic.com/en/docs/claude-code/corporate-proxy).
This applies on macOS and Linux; on Linux it is gated on the same network
namespace probe as registry egress. Explicit `--no-network`, `--network`,
`--allow-host`, browser, and lockdown choices keep their existing behavior.
On Linux, the package-registry hosts above are also added when toolchains are
enabled; pass `--no-toolchains` to omit those registry hosts while retaining
Claude's documented endpoints.

`--no-toolchains` (or `no_toolchains = true`) disables both the cache maps
and the registry default together. The untrusted project `.ai-jail` may only
disable it, never enable it, and `--lockdown` disables it outright.

### Tool credentials

Five flags share one external tool's host credentials with the sandbox, each
off by default: `--github` (GitHub CLI configuration and active token), `--aws`
(`~/.aws`), `--kube` (`~/.kube`), `--gcloud` (`~/.config/gcloud`), and
`--docker-config` (`~/.docker/config.json`). Each is monotonic — the
untrusted project `.ai-jail` may only disable one, never enable it — and all
five are disabled under `--lockdown`.

`--github` mounts the effective GitHub CLI configuration directory read-only:
`GH_CONFIG_DIR` if set, otherwise `$XDG_CONFIG_HOME/gh` if set, otherwise
`~/.config/gh`. It also forwards the active `github.com` account's token from
the host `gh` command, including tokens kept in the system keyring. Existing
`GH_TOKEN` and `GITHUB_TOKEN` values follow the CLI's precedence, and an
explicit `--env` or `--env-from-file` token skips the host lookup. Under
`--inherit-env` an inherited `GH_TOKEN` still outranks an explicit
`GITHUB_TOKEN`; pass `--env GH_TOKEN=...` to replace it. The token is
available to programs inside the sandbox as `GH_TOKEN`. Only `github.com` and
its active account are resolved automatically; Enterprise hosts and other
accounts need explicit configuration. If the host token cannot be retrieved,
ai-jail warns and continues with the read-only configuration mount, which may
still contain usable credentials. Dry-run does not retrieve a token. Network
access is controlled separately by the network flags.

Read-only protects the file from modification, not the credential from use:
anything running inside the sandbox can authenticate to that service as you
for as long as the credential is valid. Turn these on only when the agent
genuinely needs that specific service.

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

On Linux, ai-jail passes bwrap options, including environment values, through
an anonymous file descriptor; on macOS it sets the child environment directly.
These values do not appear on the sandbox launcher's argv. A literal
`--env NAME=VALUE` is still visible on **ai-jail's own** command line before
launch. Use `--env NAME` or `--env-from-file` to avoid putting a literal secret
there. Programs inside the sandbox can read forwarded environment values. For
a secret bound to one HTTP host, `--secret KEY=host` (filtered egress) keeps the
real value outside the sandbox and substitutes it through the egress proxy.

The same thing is available from trusted config as `env_pass`, so you do not
have to repeat `--env` on every launch:

```toml
# ~/.ai-jail
env_pass = ["CI", "API_BASE=https://internal.example"]

[commands.claude]
env_pass = ["ANTHROPIC_BASE_URL"]
```

`env_pass` is a trusted-layer field: it is read from the global config and its
`[commands.<name>]` tables, and ignored in a project `.ai-jail`, since a
repository must not be able to pull variables out of your shell. It is also
never written back to disk, because `NAME=VALUE` entries can carry secrets.

### Credential hygiene: `--env-from-file`

For API keys and similar secrets, keep them out of every `.ai-jail` file:
pass them from the host environment via `--env NAME`, or from a 0600 file
via `--env-from-file PATH` (repeatable; also `env_from_file` in the global
config). Each file must be user-owned, a regular file (never a symlink),
mode 0600 or stricter, and live outside the project directory — any
violation fails the launch. The format is strict `KEY=VALUE` lines (`#`
comments and blank lines are skipped; no `export` prefix, no quote
stripping). Entries apply like `--env`, and `--env` wins on conflicts.
Validation and reading use the same opened file descriptor. Directory
aliases remain supported, but aliases into the project are refused.
File and directory permissions are never changed.
Auto-save strips them, but don't rely on it: write secrets into files or
your shell, never into config.

## Audit log

Use `--audit-log` to record launches and filtered network decisions locally in
`~/.local/share/ai-jail/history.jsonl`. `ai-jail --audit-show` prints a
readable summary of recognized record syntax; it does not verify hash-chain
integrity. Use `ai-jail --audit-verify` for that separate check. HOME is the
trusted starting directory and may itself be a symlink (including through
symlinked ancestors); after HOME is opened, no symlink is followed in
`.local/share/ai-jail/history.jsonl`. Both readers reject special files, files
owned by another user, and files with group or other permissions. For backward
compatibility, the writer accepts an existing user-owned regular log with loose
permissions and tightens that same opened file descriptor to mode 0600 before
use.

Record reads are bounded for display, verification, and append-time chain
seeding. Oversized records are treated as malformed during display and
verification rather than being buffered without limit. `--audit-show` exits 0
after a successful display (including an empty log), 1 for malformed records,
a missing/invalid HOME, or an I/O/security error, and 2 when the log does not
exist under a valid HOME. `--audit-verify` uses 0 for an intact chain, 1 for a
broken chain, missing/invalid HOME, or read/security error, and 2 when the log
does not exist under a valid HOME. Failures specific to optional audit logging,
including a missing, empty, or unusable HOME at audit-log setup, are
best-effort: logging is disabled with a warning and does not prevent launch or
override the child's exit status. Configuration and sandbox validation errors
remain fatal. No fallback audit log is written under `/tmp`.

The SHA-256 chain provides tamper-evident internal consistency, not keyed
authenticity: it does not prove who wrote the records and cannot by itself
detect wholesale replacement with a newly generated consistent log. Launch
summaries may display the command and its arguments, so avoid putting secrets
in argv. The audit file is local sensitive data; safe opening and restrictive
permissions do not remove that privacy limit.

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
X11-based browsers need `--x11` instead of `--display`. Audio (e.g. video
playback) additionally needs `--audio`, which binds the validated
PipeWire/PulseAudio sockets — `ai-jail --browser=soft --network --display
--audio chromium`.

## Configuration

Two config files plus CLI flags, in increasing authority:

1. `./.ai-jail` (project) — untrusted, monotonic policy: it may tighten the
   sandbox but can never enable capabilities, outside maps, ports,
   `claude_dir`, or exceptions. It is masked from the sandbox by default, so
   the agent sees an empty file rather than your policy. Add `.ai-jail` to
   `.gitignore` and leave it uncommitted if you would rather the agent not
   notice it at all: `git status` inside the sandbox is then completely
   clean. A _committed_ `.ai-jail` always shows as modified there, because
   masking replaces its contents — git has to report something either way.
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
`systemd_user`, `kvm`, `ssh`, `pictures`, `private_home`, `lockdown`,
`browser_profile`, `claude_dir`, `allow_tcp_ports`, `status_bar_style`.

Global config only: `env_pass` (see Environment policy above) and
`trust_project_config`, which lists directories whose project
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

`PATH` is also pruned to the directories that actually exist inside the
sandbox, so entries describing the host's layout no longer make tools look
installed when nothing is mounted behind them.

**Under the default private home, those paths are not dotdirs, so earlier
releases did not mount them** — `$HOME` is a fresh tmpfs, activation found
nothing, and every mise-managed tool (the agent executable included) vanished
from `PATH`. As of v2.4.1, when mise is enabled ai-jail maps the mise data
dir (`~/.local/share/mise`, honoring `MISE_DATA_DIR`), the mise config dir
(`~/.config/mise`, honoring `MISE_CONFIG_DIR`), and the `mise` binary's
directory **read-only automatically**, so an agent gets the project's real
toolchain out of the box. Only existing directories are mapped, so a host
without mise is unchanged, and the derived paths are never written into a
saved `.ai-jail`.

`--no-mise` (or `no_mise = true`) and `--lockdown` opt out — both already
disable mise activation, so neither maps these paths. You can still add extra
`ro_maps` from trusted global config if a tool lives elsewhere, or use
`--no-private-home` when you deliberately want the whole host home.

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

**opencode hangs at "Starting background server...".** opencode 2.x runs as a
client of a shared background service whose socket lives under
`~/.local/share/opencode`. The jail is a one-shot wrapper with a fresh tmpfs
home, so that service can neither persist nor be found across runs — a shared
daemon model does not fit the jail by design. Run opencode's own
self-contained mode instead, pinned in the config so it is not typed each
time (`command = ["opencode", "--standalone"]`). ai-jail also warns about
this at launch when the command is opencode without `--standalone`.

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
