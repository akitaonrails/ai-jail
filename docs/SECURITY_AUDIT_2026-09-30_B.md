# Security audit B — 2026-09-30

Independent second audit of ai-jail v2.3.0, commit `f62d5761b18b9d9765b4c88aacc4ad77ff0db5e4`,
working tree clean. Produced without reading the findings of the same-day audit A
(`SECURITY_AUDIT_2026-09-30.md`) until after the candidate list was fixed; audit A
was then used only as a source of leads, each re-derived from source here.

Every finding below was confirmed by one of: an empirical run of the release
binary, a unit or integration test, or a direct code read with line references.
Unresolved leads carry no severity and are listed separately.

## Scope and threat model

- Assets: the host filesystem, the user's credentials, the sandbox boundary,
  the audit log's integrity, and the release channel.
- Actors: a hostile repository (project `.ai-jail`, `.git` metadata, `.envrc`),
  a compromised agent inside the sandbox, another local user, a dependency
  maintainer, a CI contributor.
- Entry points: CLI and config layers, the egress proxy (CONNECT and plain-HTTP
  termination), environment plumbing, worktree and overlay mounts, the audit
  reader and writer, release automation.
- Out of scope / untestable here: macOS seatbelt behaviour (no Mac; rests on
  CI), fuzzing of the proxy's HTTP framing, an end-to-end release run.

## Automated evidence

- `cargo audit`: clean, 70 crate dependencies.
- GitHub secret scanning, Dependabot, and CodeQL: all enabled (push protection
  on), zero open alerts, CodeQL green on this commit.
- Both workflows: least-privilege permissions, every action SHA-pinned, no
  `pull_request_target`, no event data interpolated into `run:`.
- No `build.rs`, no git/path dependencies, no lint relaxations, no Unicode bidi
  controls, no tracked binaries.
- 776+ unit tests plus 11 filtered-egress / phantom-secret integration tests.
  The integration tests were confirmed to have genuinely exercised bwrap on this
  host rather than silently skipping (they print `SKIPPED:` on early return and
  none did; `bwrap --unshare-net` works here and curl is present).

## Findings

### [High] Forged worktree metadata mounts an arbitrary host directory read-write

- Evidence: `src/sandbox/mod.rs:743-782`. Validation establishes that the
  project `.git` file points at a directory, that its `gitdir` points back, and
  that its `commondir` names an existing directory. Nothing establishes that the
  `commondir` target is the repository's real common directory. `bwrap.rs` then
  bind-mounts it read-write outside lockdown. Confirmed empirically: a repository
  whose `commondir` file names a path outside the project gets that path bound
  read-write.
- Prerequisites: the user passes `--worktree` (opt-in) on a hostile repository.
- Impact: any host directory becomes writable inside the sandbox. This is
  precisely what the untrusted-project boundary exists to prevent.
- Remediation: require `git_dir` to be `<common>/worktrees/<name>` (or
  `<common>/.git/worktrees/<name>`) with `commondir` resolving to that exact
  `<common>`, canonicalize both sides, and reject everything else.
- Regression tests: a fixture whose mutually consistent files point outside the
  repository must be refused; a genuine linked worktree must keep working.

### [High] Duplicate environment entries bypass phantom-secret isolation

- Evidence: `prepare_secrets` (`src/main.rs:115-133`) rewrites only the first
  `env_pass` entry for a bound key (`position()`), while `apply_env_pass`
  (`src/config.rs:445-466`) makes the last entry win. Confirmed empirically:
  with a bound key present twice, the child environment receives the real value
  and no placeholder at all.
- The realistic trigger is the README's own documented pattern: the secret in a
  0600 file via `--env-from-file`, plus `--env KEY` to forward it. That
  combination delivers the real host value into the sandbox.
- Impact: the credential `--secret` promises to keep out of the sandbox is
  delivered into it, silently.
- Remediation: resolve the effective value with the same last-wins precedence
  as `apply_env_pass`, then remove every entry for the key and insert exactly one
  placeholder entry.
- Regression tests: file plus CLI, duplicate CLI, bare-name resolution against
  the host environment, `--inherit-env`, both backends; assert the proxy sees the
  real value and the child sees only the placeholder.

### [Medium] Test-only escape hatches are live in the release binary via environment variables

- Evidence: `src/main.rs:139-158` and the proxy setup near `main.rs:625`.
  `AI_JAIL_TEST_PROXY_ALLOW_PRIVATE` disables the SSRF address-range guard and
  `AI_JAIL_TEST_PROXY_EXTRA_ROOTS` injects an additional TLS trust root. Neither
  is `cfg(test)`-gated; both names are present in `strings` of the shipped
  release binary. `ProxyConfig`'s own doc comment says these must never become
  settable from config or CLI; the process environment is an unclosed third
  channel.
- Prerequisites: control of the supervisor's environment, for example a
  repository `.envrc` under direnv.
- Impact: with an attacker root trusted, the TLS re-origination that carries the
  real secret can be intercepted on-path; with the range guard off, an
  allowlisted host that resolves to a private address reaches host-local
  services.
- Remediation: gate both behind a compile-time feature that the release profile
  never enables.

### [Medium] Trusted project config overrides explicit CLI restrictions

- Evidence: `merge_trusted`'s `take!` (`src/config.rs:858-864`) copies any
  `Some` project value over the baseline that already contains the CLI layer.
  README "Configuration" states that CLI flags have the highest authority.
- Impact: `ai-jail --no-network` inside a `trust_project_config` directory can
  be re-enabled by that repository's `.ai-jail`. Trust is opt-in, but an explicit
  flag being silently reversed is a precedence inversion.
- Remediation: apply the CLI layer last, or refuse to override a value the CLI
  set explicitly.

### [Medium] Overlay failures degrade to the writable original

- Evidence: `src/sandbox/bwrap.rs:3045-3081` warns and continues when an
  overlay source is missing, when destinations overlap, or when layer-storage
  creation fails. The project bind stays read-write. `CLAUDE.md` and
  `docs/SECURITY.md:63-64` state that overlay setup fails closed. It does not.
- Remediation: fail the launch when a requested overlay cannot be established.

### [Medium] Rewriting the global config drops credential policy

- Evidence: `env_pass`, `env_from_file`, and `secret_hosts` are
  `#[serde(skip_serializing)]` (`src/config.rs:258-273`); `save_global`
  (`src/config.rs:1355`) serializes the whole struct. Any global save, such as
  persisting a status-bar theme, rewrites `~/.ai-jail` without those fields.
- Remediation: patch the on-disk document instead of re-serializing the struct,
  or refuse to save while skipped fields are populated.

### [Low] The phantom placeholder is a truncated hash of the real secret

- Evidence: `src/secret.rs:26-33` derives the placeholder as
  `sha256("KEY:real")[..16]`. Confirmed: the placeholder observed in a dry run
  equals that digest exactly. `docs/SECURITY.md` says real values never reach the
  sandbox; 64 bits of their hash do.
- Impact: offline guessing is feasible only for low-entropy secrets; typical API
  keys are not practically recoverable.
- Remediation: derive the placeholder from a CSPRNG per launch. Determinism
  across dry runs buys nothing.

### [Low] `--env KEY=VALUE` on the command line is visible to other local users

- Evidence: confirmed in `/proc/<pid>/cmdline` of the supervisor, world-readable
  on this host with no `hidepid`. The sandboxed child cannot see it (own PID
  namespace). The README recommends `--env NAME` and `--env-from-file` for
  secrets but never explains why the literal form is unsafe.
- Remediation: one sentence in "Credential hygiene".

### [Low, conditional] The update check executes a bare `curl` from `PATH` in the unsandboxed supervisor

- Evidence: `src/statusbar.rs:291-304`, gated by `should_check_update`
  (`src/main.rs:755`). Opt-in only. Requires an attacker-writable directory
  ahead of curl on `PATH`.

## Documentation stale or contradicted by code

- `CLAUDE.md` and `docs/SECURITY.md`: "overlay setup fails closed" is false
  (finding above).
- `README.md` "Configuration": "CLI flags have highest authority" is false for
  trusted projects (finding above).
- `src/config.rs` comments and `docs/connect-proxy-plan.md`: an untrusted project
  `allow_hosts` "may narrow by omission". The merge at `config.rs:1281-1294` only
  drops entries that are new; it never removes baseline entries. Not a widening,
  but the claim is wrong.
- `docs/SECURITY.md`: "real values live only in supervisor memory, never in the
  sandbox" is inexact (hash finding above).
- `README.md` and `docs/SECURITY.md` still direct `--allow-tcp-port` users to
  `--network`; the README elsewhere correctly points at `--allow-host`.
- `docs/RELEASE_SECURITY.md` never mentions the attestation / `id-token` step
  the release workflow now runs.

Verified accurate: every README flag maps to a real CLI flag (the only
mismatches, `--locked`, `--release`, `--standalone`, `--system`, are cargo,
opencode, and sysctl arguments quoted in prose). Every README config key exists
as a serde field. Effective defaults match the `docs/SECURITY.md` capability
table exactly. Install instructions match `packaging/`. The claims about
`--env-from-file` validation, the audit reader and writer, the netns fence, the
socket-only bind, and the seatbelt filtered rule all match the code.

## Reviewed boundaries with no finding

- Egress proxy core: strict CONNECT parsing, 8 KiB request cap, slowloris
  timeout, 256-connection cap, DNS resolved once then dialed, SSRF classifier
  covering loopback, private, link-local, cloud metadata, CGNAT, multicast, and
  the v4-mapped and v4-compatible IPv6 forms. Substitution is scoped to the single
  binding for the destination host, and the TLS target is the bound host rather
  than anything in the request.
- Kernel fence: `--unshare-net` in filtered mode; only the socket file is bound;
  Landlock allows the bridge port connect-only and only in filtered mode; the
  seatbelt filtered rule is `network-outbound` to `localhost:<port>` only.
- `--inherit-env` with `--secret`: the placeholder `--setenv` overrides the
  inherited real value (confirmed by dry run).
- Credential files: `lstat`, symlink refused, owner equals euid, mode 0600 or
  stricter, outside the project directory.
- Audit reader and writer: re-verified; `audit_log` is in the monotonic set.
- Terminal filter: the charset-designation regression test is still present.
- Project `.ai-jail`: `secret_hosts` ignored with a warning; `allow_hosts` cannot
  extend the baseline; `inherit_env` monotonic.

## Needs validation

- Whether non-zero `0.0.0.0/8` addresses reach loopback on older kernels or
  macOS. On this kernel they do not (`0.1.2.3` times out; `0.0.0.0` itself is
  already denied). No Mac available.
- Whether Landlock marks the worktree common directory read-only while bwrap
  binds it read-write, and whether `DOCKER_HOST` is unset while a non-default
  socket is mounted. Both raised by audit A; neither traced here.

(The `monotonic!(audit_log)` question that was listed here is resolved as
confirmed under "Corrections and additions" below.)

## Corrections and additions after reading audit A

Audit A's findings were treated as leads and re-derived here from source.
Three are confirmed and were absent from this audit's own list; one of them
reverses a candidate this audit had wrongly rejected. They are recorded here so
the false negatives stay visible.

### [Medium] TIOCSTI seccomp compare uses the wrong argument width (this audit's earlier rejection was wrong)

- Evidence: `src/sandbox/seccomp.rs:326-335` compares ioctl argument 1 as a
  64-bit `Qword` equality against `TIOCSTI`. The kernel reads the ioctl request
  as a 32-bit value, so the upper word is free. Confirmed empirically inside the
  sandbox with an invalid descriptor: plain `0x5412` returns `EPERM` (the
  seccomp rule fires), while `0x5412 | (1 << 32)` returns `EBADF` — it passed the
  filter and reached the kernel, which then treats it as the same request.
- Prerequisites: a kernel that permits legacy unprivileged `TIOCSTI` and access
  to a writable controlling terminal. This host has `dev.tty.legacy_tiocsti = 0`,
  so it is not exploitable here, but the filter is still wrong.
- Correction: this audit had listed the Qword width as a rejected candidate,
  reasoning it matched the 64-bit register. That was wrong — the kernel truncates
  to 32 bits, so the high bits are an evasion channel. Audit A had it right.
- Remediation: compare the request as a 32-bit argument (`SeccompCmpArgLen::Dword`),
  and test the filter against high-word variants, not only the BPF constant.

### [Medium] Primary-screen escape filter bypassed by a doubled introducer

- Evidence: `src/pty.rs` `TerminalFilter`. Confirmed empirically: feeding
  `ESC` followed by `ESC ] 52 ; c ; … BEL` lets the OSC introducer reach the
  output — a regression test asserting the OSC never appears in the filtered
  bytes fails on the current code. `ESC [ ESC ] …` behaves the same way.
- Impact: an OSC the filter is meant to strip (clipboard write, title set, query)
  reaches the host terminal. This is the same class the charset-designation fix
  from the prior session closed, via a different reset path.
- Remediation: on `ESC` while already in an ESC or CSI state, restart the
  pending sequence rather than completing or forwarding it. Audit A found this.

### [Medium] Untrusted project can disable operator audit logging

- Evidence: `monotonic!(audit_log)` (`src/config.rs:1190-1236`). The macro takes
  the project value when the candidate is not "enabled" or the baseline already
  is; disabling makes the candidate not enabled, so the project's `false` is
  taken. A project `.ai-jail` can therefore switch off logging that the CLI or
  trusted global config turned on.
- Impact: loss of operator-requested audit evidence, chosen by the untrusted
  layer. This was in this audit's "needs validation" list; resolved here as
  confirmed. Audit A reported it directly.
- Remediation: treat audit logging as operator policy, not a sandbox capability
  subject to monotonic weakening.

## Rejected candidates

- HTTP-termination request smuggling: trailing bytes reach only the same bound
  host over a fresh `Connection: close` TLS session and carry no substitution.
  (Audit A narrows this to a Low with a caveat rather than rejecting it; see the
  comparison note.)
- `0.x.x.x` SSRF bypass: disproven on this kernel — `0.1.2.3` does not reach a
  loopback listener here; `0.0.0.0` is already denied by the classifier.
- Same-handle audit-thread corruption: the mutex covers chain state and the
  write. (The separate-process variant is a real finding — audit A's, below.)

## Residual risk

No macOS host, so every seatbelt claim rests on CI. The proxy's HTTP framing
was not fuzzed. The release workflow was not run end to end.

## Release readiness

Blocked by the two High findings. Both have small, clean fixes at their owning
boundaries.
