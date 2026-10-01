# Dev-toolchain & container passthrough — design note

Status: proposal (pre-implementation). Targets: **v2.4.2** (blocking patch —
Part 0) then **v2.5.0** (feature — Parts A + B). Requires maintainer approval
before tagging. Open decision: the network default (see "Open decisions").

Two workstreams, both answering "is ai-jail friendly to the tools a developer
needs inside the jail, without leaking too much":

- **A. Toolchain cache persistence** — under the default private home, every
  dependency cache is thrown away each session, and Rust is fully broken. Fix
  both for every ecosystem, additively.
- **B. Container tooling** — make `docker` / `podman` work against the host
  daemon from inside the jail, opt-in, with the right sockets auto-discovered.

Guiding constraint: _developer-friendly with enough security_. Keep the dev's
tools working and their caches warm; leak nothing we do not have to; every new
exposure is opt-in or read-only by default.

## Release ordering (updated after in-jail verification)

Four cross-project bug reports arrived from the ai-memory ecosystem. Verified
empirically (two on the host, one inside a real jail). They split into a
**blocking patch** that must ship first and the **feature release** this note
started as:

1. **v2.4.2 (patch, blocker, ship first)** — Part 0 below:
   - Landlock `REFER`/`EXDEV` regression (blocks _all_ Rust compilation in the
     jail; confirmed in-jail).
   - `--` flag-guard bug (confirmed on host).
2. **v2.5.0 (feature, after v2.4.2 is green)** — Parts A + B below: toolchain
   cache persistence and container tooling.

The toolchain feature (A) is pointless until REFER is fixed: persisting a cargo
cache does not help if `rustc` cannot write its own output. So v2.4.2 lands and
releases first.

## Part 0 — v2.4.2 blockers

### 0.1 Landlock REFER / EXDEV — cross-directory rename denied (regression)

**Verified inside a real jail** (kernel 7.2.5, default private home,
no-network, no-lockdown):

```
mv   /tmp/x/a/g /tmp/x/b/g                       # OK  (coreutils falls back to copy+unlink on EXDEV)
python3 -c "os.rename('/tmp/x/b/g','/tmp/x/a/h')" # OSError 18 EXDEV  ← raw rename(2) fails
```

So `mv` masks the problem, but any tool doing a raw `rename(2)` across
directories fails — which is exactly `rustc` (writes a temp file then renames it
into `deps/`) and `rustup` (stages then renames into `toolchains/`). Net effect
reported and consistent with the mechanism: **no Rust project compiles in the
jail at all.** `git` (same-dir rename) and `rustfmt` (in-place) are unaffected.

**Root cause — NOT what the report guessed.** The report proposed "the RW rules
omit `AccessFs::Refer`." They do not: `apply_fs_rules` (`src/sandbox/landlock.rs`)
does `handle_access(AccessFs::from_all(ABI::V3))` and grants `rw_paths`
`from_all(V3)`, and `from_all(V3)` _includes_ `Refer` (added at ABI v2). The real
cause is **stacked-layer semantics**: a Landlock ruleset that does not handle
`REFER` implicitly forbids all cross-directory reparenting for processes it
restricts. `apply()` stacks three layers via separate `restrict_self` calls — fs
(V3, handles REFER), net (V4), and **scope (V6)**. In this mode `apply_net_rules`
is a noop, so the extra enforced layer is the **V6 scope ruleset added in
v2.4.0**, which handles only `Scope`, not `AccessFs::Refer`. That layer is the
regression: the fs layer allows the reparent, the scope layer forbids it, and the
stack denies.

**Fix direction (must be iterated against a real V6 kernel).** Ensure no enforced
Landlock layer forbids reparenting while another is meant to allow it. Candidate
approaches, to be chosen by in-jail experiment:

- Have the stacked net and scope rulesets also `handle_access(AccessFs::REFER)`
  and grant `Refer` on the same ro+rw path rules (so every fs-restricting layer
  agrees), under `CompatLevel::BestEffort`; or
- Fold fs + net + scope handled-accesses into a single ruleset/`restrict_self`
  so there is only one fs layer (best-effort downgrades on older kernels).

Whichever is chosen, it must be verified empirically, because the kernel's
exact cross-layer REFER rule is what this hinges on and my static reading already
mispredicted it once.

**Tests (adversarial + control, run in-jail):**

- control: cross-dir `rename(2)` inside `/tmp` and inside the project succeeds;
  `cargo new x && cargo build` (a zero-dep crate, offline) succeeds.
- adversarial: a `rename(2)`/`link(2)` from a read-only map _into_ the project is
  still refused; reparent out of a `--deny-path`/`--mask` tree still refused;
  reparent from a RW tree into a RO tree stays denied (no access gained).
- regression: a rustup-style stage-then-rename works.
- unit: the ruleset builder grants `REFER` on every fs-restricting enforced layer
  and never on read-only path rules.

Keep the macOS seatbelt path unaffected (verify it has no equivalent restriction).

### 0.2 Post-command flag guard ignores `--`

**Verified on host** (no sandbox): `ai-jail --dry-run --network -- /bin/true run
claude --env X=1` is rejected with "flag `--env` after command … or use --",
although `--` is already present. The guard scans the whole argv and does not stop
at the `--` separator, so no caller can forward a child flag whose name collides
with an ai-jail flag (`--env`, `--network`, `--verbose`, `--map`, …).

**Fix.** Everything after a leading `--` is the command + args, verbatim — never
scanned for sandbox flags, and `--` is not passed to the child. Keep the guard for
the no-`--` case (`ai-jail claude --network` stays ambiguous → still errors).
`--dry-run` follows the same parsing.

**Tests:** `ai-jail --dry-run --network -- /bin/true --env X=1 --network
--verbose` succeeds and the plan contains the three child flags verbatim; control
`ai-jail --dry-run /bin/true --network` (no `--`) still errors.

(ai-memory's integration test gates on the ai-jail version that honors `--`;
confirm **v2.4.2** back to the ai-memory project so it can set its skip floor.)

## Current behavior — authoritative, from `ai-jail --dry-run -- bash`

Under the default private home the only home-area mounts are:

```
--tmpfs /home/<user>
--ro-bind ~/.gitconfig ~/.gitignore            (git identity)
--ro-bind ~/Pictures                           (pictures mount)
--ro-bind ~/.local/share/mise ~/.config/mise   (mise passthrough, v2.4.1)
<project binds>
```

Nothing else from home is bound. In particular there is **no `DOTDIR_RW`
binding** of `.cargo`/`.npm`/`.cache`/… — that enumeration
(`discover_home_dotfiles`) only runs under `--no-private-home`; under the private
home it returns the tmpfs home alone. So the default jail has no host-home
credential exposure to reconcile, and two concrete gaps instead:

- **Binaries:** resolve through mise (node, python, go, ruby, bun, … all work).
  **Rust is broken** — mise installs it as a symlink into `~/.cargo/bin`, which is
  not mapped, so `cargo`/`rustc` have no real target.
- **Caches:** _none persist._ Every tool writes its cache under the ephemeral
  tmpfs `$HOME`, so it is discarded at exit and re-downloaded next session. This
  is the same problem for every ecosystem, not a per-tool quirk.

(`--no-private-home` is a separate, explicitly broad mode that binds host home
read-write via `DOTDIR_RW`; its host-cache/credential exposure is out of scope
here and unchanged.)

## Principles this design is bound by

- _Developer-friendly:_ `cargo build`/`test`, `go build` with fetches, `npm
install`, etc. work, and their caches persist across sessions. A sandbox that
  re-downloads the world every launch is not a dev sandbox.
- _Secure by default, lockdown opt-in:_ cache persistence on by default outside
  `--lockdown`; container access opt-in (`--docker`). `--lockdown` and explicit
  opt-outs disable each. Project `.ai-jail` stays monotonic — may disable, never
  enable.
- _Leak nothing extra:_ caches live in a dedicated **jail-owned** directory, never
  the host's real cache, so a jailed build can never poison what the host's own
  non-jailed builds compile from. No host credential file is ever mapped (under
  private home none is bound anyway; we keep it that way).
- _Fail closed / warn-and-skip appropriately:_ a cache that cannot be set up warns
  and is skipped (convenience, not security); nothing silently degrades a
  capability. Derived paths/env are never persisted to a saved `.ai-jail`; new
  config keys use `#[serde(default)]` and are monotonic.

---

# Part A — Toolchain cache persistence

## The cache store

One persistent, jail-owned root on the host, created `0700` before launch and
bind-mounted read-write into the sandbox (the `discover_browser_state_mount`
precedent: `create_dir_all` then a plain `Mount::Bind`):

```
~/.local/share/ai-jail/cache/
  cargo/{registry,git}
  go/{mod,build}
  xdg/            # becomes XDG_CACHE_HOME inside the jail
  npm  yarn  pnpm  bun
  maven  gradle  nuget  pub-cache  mix  hex  gem
```

It is persistent (survives sessions), **shared across all projects** (one warm
cache, not one per project), and isolated from each tool's real host cache. The
only cost is a one-time cold start: the store begins empty and re-downloads what
the host already has, once, then reuses it forever. Concurrency-safe: cargo/go/npm
take file locks on their cache dirs and are built for concurrent access (unlike an
overlayfs upper, which is why this is a plain bind, not an overlay).

## Mechanism: redirect by env var first, bind only when there is no env var

Redirecting a tool's cache with its own environment variable is robust to the
tool's internal layout and version changes, and it never touches a host path.
Bind mounts are the fallback for the few caches keyed to a fixed `$HOME` path with
no env override. Both are injected the same way the mise passthrough injects
`ro_maps` today — in `src/main.rs`, after the status/`--init`/bootstrap early
returns and the save paths, gated on `toolchains_enabled() && !lockdown`, so the
derived env/paths are never written to a saved `.ai-jail` nor shown in `status`.
A user's own `--env`/explicit map for the same key always wins (skip-if-present,
mirroring mise's guard).

### Per-ecosystem table (env var preferred; bind where noted)

| Ecosystem    | Redirect                                                                              | Store subdir           | Notes                                                                                                                                                    |
| ------------ | ------------------------------------------------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust         | **bind** `~/.cargo/registry`, `~/.cargo/git`; **ro-bind** `~/.cargo/bin`, `~/.rustup` | `cargo/{registry,git}` | `CARGO_HOME` would relocate `bin` too, so bind the two cache subdirs and ro-map the real binaries/toolchains. `credentials*`/`config.toml` never mapped. |
| Go           | `GOMODCACHE`, `GOCACHE`                                                               | `go/{mod,build}`       | Replaces today's ephemeral `~/go/pkg/mod` and `~/.cache/go-build`.                                                                                       |
| General XDG  | `XDG_CACHE_HOME`                                                                      | `xdg`                  | Covers pip, uv, deno, yarn-v1, and many others in one lever.                                                                                             |
| npm          | `npm_config_cache`                                                                    | `npm`                  | Token lives in `~/.npmrc` (a dotfile, not mapped) — unaffected.                                                                                          |
| Yarn (berry) | `YARN_CACHE_FOLDER`                                                                   | `yarn`                 |                                                                                                                                                          |
| pnpm         | `PNPM_HOME` / store-dir                                                               | `pnpm`                 | Verify the exact store-dir env against pnpm docs at implementation.                                                                                      |
| Bun          | `BUN_INSTALL_CACHE_DIR`                                                               | `bun`                  |                                                                                                                                                          |
| Maven        | `-Dmaven.repo.local` via `MAVEN_OPTS` (or **bind** `~/.m2/repository`)                | `maven`                | `settings.xml` not provided (may hold creds) — default resolution.                                                                                       |
| Gradle       | `GRADLE_USER_HOME`                                                                    | `gradle`               | `gradle.properties` not provided (may hold creds) — defaults.                                                                                            |
| .NET / NuGet | `NUGET_PACKAGES`                                                                      | `nuget`                | `NuGet.Config` not provided (may hold creds).                                                                                                            |
| Dart         | `PUB_CACHE`                                                                           | `pub-cache`            | `credentials.json` not provided.                                                                                                                         |
| Elixir       | `MIX_HOME`, `HEX_HOME`                                                                | `mix`, `hex`           | `hex.config` not provided (may hold API key).                                                                                                            |
| Ruby / gem   | `GEM_SPEC_CACHE` (+ `GEM_HOME` only if a writable gem home is wanted)                 | `gem`                  | gems install under the mise ruby (RO); default to cache only.                                                                                            |

Exact env-var names for pnpm, bun, and the elixir tools are verified against each
tool's current docs during implementation; a row whose var cannot be confirmed
falls back to a bind of its `$HOME` cache path, and if neither is safe it is
dropped from v1 with a note rather than guessed.

### Why this is low-regression

Under the private home nothing from host home is bound today, so every row above
is **purely additive**: it turns an ephemeral cache into a persistent one. No
existing mount changes, no credential file becomes newly visible (we point tools
at fresh jail dirs), and `--no-private-home` is untouched. The one behavior note:
`cargo install` to the global `~/.cargo/bin` stays unsupported in-jail because that
dir is read-only (host-`PATH` write vector) — use `cargo install --root`
(DECISION 1, maintainer-approved).

### Config + CLI surface (mirror `no_mise`)

- `pub no_toolchains: Option<bool>` + `#[serde(default)]`;
  `toolchains_enabled() = no_toolchains != Some(true)`.
- `monotonic!(no_toolchains, …)` — project may tighten (`true`), never enable.
- CLI `invert!(toolchains, no_toolchains)`; `--no-toolchains / --toolchains`.
- `display_status`: `print_auto_tristate("  Toolchains", config.no_toolchains)`.
- Backward compat: new field defaults to `None` → on by default; old `.ai-jail`
  parses unchanged. Regression test parses a config without the key.

### macOS / seatbelt

The store is a plain writable dir (no overlay), so there is no platform fetch
limitation. seatbelt needs a `file-write*` rule for the store root and
`file-read*` for the rust `bin`/`rustup` ro-binds; env redirection needs no
profile change. Validate on the `macos` CI job (the only seatbelt validator;
`ring` cannot cross-compile from Linux).

### mise auto-install noise

With the mise data dir mapped read-only, a shim for a declared-but-missing
version prints `Read-only file system (os error 30)` while attempting a doomed
install. Mapping rust (above) removes the rust case. For the rest, set
`MISE_NOT_FOUND_AUTO_INSTALL=false` in the sandbox env whenever the mise data dir
is mapped read-only, so a missing tool fails once cleanly instead of retrying.
Verify the exact variable name against current mise docs; set it only on the
mise-enabled read-only path; a user `--env` override wins.

---

# Part B — Container tooling (docker / podman / …)

## Current state

`--docker` / `no_docker` (opt-in, default off) exposes the host daemon socket:
`docker_socket()` resolves `$DOCKER_HOST` (`unix://` only; TCP/SSH refused by
design) else `/var/run/docker.sock`, requires an actual socket, binds it rw (mount
order step 4) with a Landlock rule. A podman socket via `$DOCKER_HOST` already
works (there is a test). This is a deliberate host-root trust extension and stays
opt-in; the warning stays.

## Additions (opt-in, additive, backward-compatible)

1. **Auto-discover rootless/podman sockets.** After `$DOCKER_HOST`, add, in order,
   each gated behind `--docker`, first actual socket wins:
   - `$XDG_RUNTIME_DIR/docker.sock` (rootless Docker)
   - `$XDG_RUNTIME_DIR/podman/podman.sock` and `/run/user/<uid>/podman/podman.sock`
   - `/run/podman/podman.sock` (rootful podman)
   - `/var/run/docker.sock` (unchanged, last)
     Backward compatible: `$DOCKER_HOST` still leads; the two existing socket tests
     stay green.
2. **Honor `$CONTAINER_HOST`** (podman's own var), same `unix://` parsing, ranked
   just below `$DOCKER_HOST`.
3. **Forward the resolved endpoint into the child env** as
   `DOCKER_HOST=unix:///var/run/docker.sock` (the in-jail bind path) when a
   non-default socket was chosen, overridable by an explicit user `--env`.

## Deliberately out of scope / separate follow-ups

- **Registry credentials** (`~/.docker/config.json`,
  `~/.config/containers/auth.json`). `.docker` is in `DOTDIR_DENY` for good
  reason. A separate explicit opt-in (e.g. `--docker-config`, read-only, default
  off) — filed, not built in v1. (Note: a read-only `~/.docker/config.json` is
  already mounted under `--no-private-home` + `--docker`; this follow-up is about
  the private-home default.)
- **Nested/rootless container creation _inside_ the jail** (podman/buildah
  building/running within the sandbox) needs userns, subuid/subgid, `/dev/fuse`,
  fuse-overlayfs, and fights bwrap's userns handling. Out of scope: the supported
  model is client-in-jail → host daemon over the socket. Documented so it is a
  known boundary, not a silent failure.

---

# Open decisions

- **Network default.** A request was raised to make network **on by default**
  with `--no-network` to opt into the lock. This contradicts `CLAUDE.md`
  ("Network … opt-in. Do not weaken these defaults.") and the deny-by-default
  identity of the tool, and changes behavior for every existing invocation/config.
  Recommended alternatives, in order:
  1. _Personal only:_ `network = true` in the user's global `~/.ai-jail` — zero
     code, shipped default unchanged.
  2. _Dev-friendly middle (recommended for the shipped tool):_ when toolchains are
     enabled, default to **filtered egress to the package registries**
     (crates.io, static.crates.io, registry.npmjs.org, pypi.org, files.pythonhosted.org,
     proxy.golang.org, sum.golang.org, …) via the existing `--allow-host`
     machinery — deps fetch, arbitrary exfiltration still blocked.
  3. _Flip the shipped default_ (as asked) — advised against.
     Unresolved; does not block v2.4.2. Needed before the v2.5.0 toolchain feature so
     cache fetches work out of the box.

# Regression analysis (what could break, and the guard)

- _A redirect/bind overrides a user's explicit `--env` or map_ → skip-if-present
  guard; test an explicit `--env GOMODCACHE=…` and `--rw-map …:~/.cargo/registry`
  both win.
- _Derived env/paths leak into a saved `.ai-jail` or `status`_ → injected after
  the save/init/bootstrap returns (mise precedent); test `--init` output and
  `status` omit them.
- _Rust still broken / wrong target_ → ro-bind the real `~/.cargo/bin` + `~/.rustup`
  (canonicalized to follow a symlinked `~/.cargo`); control test runs
  `cargo build`.
- _Lockdown or `--no-toolchains` still redirects_ → gate mirrors mise; test both
  emit no toolchain env/binds.
- _Project `.ai-jail` enables toolchains when global disabled_ → monotonic; test
  it can disable but not enable.
- _`--no-private-home` behavior changes_ → Part A only adds env/binds under the
  private home; assert dry-run for `--no-private-home` is unchanged.
- _Container: a new socket candidate auto-exposes the daemon without `--docker`_ →
  every candidate behind `docker_enabled()`; test discovery returns nothing when
  off.
- _`$DOCKER_HOST` precedence changes_ → stays first; existing two socket tests
  pass unchanged.
- _macOS drift_ → cross-target `cargo clippy --target aarch64-apple-darwin
--all-targets -- -D warnings` locally; seatbelt validated on the `macos` CI job.

# Test matrix (each fails before, passes after; plus legit controls)

Unit (`src/sandbox/mod.rs`, mirroring the mise tests):

- The redirect builder emits the right env/bind set from a given store root and a
  detected tool set; honors `$CARGO_HOME`/`$RUSTUP_HOME`/`$GOPATH`; canonicalizes a
  symlinked `~/.cargo`/`~/.rustup`; skips tools not present; never emits a
  credential path.
- skip-if-present leaves a user-supplied env/map untouched.
- `docker_socket()` ordering: `$DOCKER_HOST` > `$CONTAINER_HOST` > rootless/podman
  well-known > `/var/run/docker.sock`; skips non-sockets; returns the in-jail env
  mapping; returns nothing when `--docker` is off.

Integration / adversarial (`tests/`, and via `--dry-run` assertions):

- Default private-home dry-run gains the store bind + rust ro-binds + the cache
  env vars, and **no** host credential path.
- `--lockdown` and `--no-toolchains` dry-runs gain none of them.
- `--no-private-home` dry-run is byte-for-byte unchanged vs. today.
- Container discovery: nothing without `--docker`; with `--docker` picks a
  rootless/podman socket and sets in-jail `DOCKER_HOST`.

Controls (developer-friendly must actually hold):

- `cargo --version`, `rustc --version` resolve; `cargo build` fetching one dep
  succeeds (real-dir and symlinked `~/.cargo`).
- `go build` fetching one module, and `npm install` of one package, each populate
  the store.
- A second run reuses the store (assert store non-empty, no network needed).

Config regression:

- Old `.ai-jail` without `no_toolchains` parses and defaults to enabled.

# Deliverable / release (per CLAUDE.md)

Two releases, in order. Each: gate on the final committed tree (`cargo fmt`
max_width 80, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test
--locked`, cross-target macOS clippy, prettier on any `.md`); CI green on ubuntu
and macOS legs; bump `Cargo.toml`, `cargo update -p ai-jail`, add
`releases/vX.Y.Z.md`, commit `chore(release): vX.Y.Z`, GPG-signed tag, push; AUR
bump `PKGBUILD`/`PKGBUILD-bin` + `publish.sh --push`, verify via fresh AUR clone;
maintainer approval before tagging.

1. **v2.4.2** — Part 0 (REFER fix + `--` flag-guard). The REFER fix is iterated
   and verified against a real V6 kernel (run the freshly built `ai-jail` binary
   on the host against a jailed repro: cross-dir `rename(2)` and `cargo new &&
cargo build` must pass; RO→RW reparent must stay denied). Report the version
   back to the ai-memory project for its test skip-floor.
2. **v2.5.0** — Parts A + B (toolchain cache persistence + container tooling), on
   top of green v2.4.2. Resolve the network-default open decision first. Note the
   `cargo install`-to-global-bin behavior in the release notes.
