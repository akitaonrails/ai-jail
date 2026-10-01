# Security remediation plan — 2026-09-30

Consolidates every confirmed weakness from the two same-day audits
(`SECURITY_AUDIT_2026-09-30.md`, `..._B.md`) and the two open advisories
(`GHSA-w976-gw52-hvx2`, `GHSA-frgp-q3qc-g78p`) into one prioritized, testable
plan against v2.3.0 (`f62d576`).

Working rules for every item below:

- One coherent boundary per change, its own branch, its own regression test that
  fails before the fix and passes after, plus a legitimate control case.
- No config field removed or retyped; `#[serde(default)]` preserved
  (`CLAUDE.md` backward-compatibility invariant).
- Full gate on the final tree: `cargo fmt --check`, `cargo clippy --locked
--all-targets -- -D warnings`, `cargo test --locked`, the musl `cargo check`,
  `cargo audit`, prettier on any `.md`. macOS items also need the `macos` CI job.
- Nothing lands that weakens an existing test to go green.

## Phase 1 — release blockers (untrusted input crosses a trust boundary)

### 1.1 Worktree metadata can bind an arbitrary host directory RW

Advisory 1 #1; both audits; reproduced. `src/sandbox/mod.rs:743-782`.

- Fix: require the linked-worktree hierarchy to be genuine — `git_dir` must be
  `<common>/worktrees/<name>` (or `<common>/.git/worktrees/<name>`), the reverse
  `gitdir` must identify that exact worktree, and `commondir` must resolve to that
  `<common>`. Canonicalize every path before comparison; reject any inconsistency.
- Test: adversarial fixtures whose mutually consistent files point at an unrelated
  host directory, at a symlinked ancestor, and with swapped metadata are all
  refused; a real `git worktree add` tree still works.

### 1.2 Duplicate env entries defeat phantom-secret substitution

Both audits; reproduced. `src/main.rs:115-133` vs `src/config.rs:445-466`.

- Fix: in `prepare_secrets`, resolve each bound key with the _same_ last-wins
  precedence `apply_env_pass` uses, then remove **every** `env_pass` entry for the
  key and insert exactly one `KEY=placeholder`.
- Test: file+CLI, duplicate CLI, bare-name against host env, `--inherit-env`, both
  backends; assert the child sees only the placeholder and the proxy binding holds
  the effective real value.

### 1.3 Overlay setup falls back to the writable original

Advisory-adjacent; audit A High / B Medium. `src/sandbox/bwrap.rs:3045-3081`.

- Fix: when a requested overlay cannot be established (missing source, overlapping
  destination, storage-dir failure, bwrap overlay failure), fail the launch
  instead of continuing with the plain read-write project bind. Derive the storage
  identifier from the canonical destination so distinct destinations cannot collide
  (the current `_`-substitution can alias them).
- Test: missing source, overlap, unwritable storage, punctuation collision — each
  aborts the launch; the child never runs against the writable original.
- Doc: fix `CLAUDE.md` / `docs/SECURITY.md` "overlay fails closed" to match.

### 1.4 Project `.ai-jail` clears trusted lockdown via a browser command

Advisory 1 #3; **missed by both audits**; reproduced. `src/main.rs:72`, `:507-508`.

- Fix: `apply_browser_profile` must not set `lockdown = Some(false)` when the
  command was adopted from the project file rather than the CLI. Clearing lockdown
  for a browser the _user_ named on the CLI stays as today (keep the existing test
  at `main.rs:739`). Track command provenance (CLI vs project) through to
  `apply_browser_profile`.
- Test: project `.ai-jail` with `command = ["chromium"]` under `--lockdown` keeps
  lockdown (inner args still carry `--lockdown`, no `--browser=hard` downgrade);
  `ai-jail --lockdown chromium` on the CLI still opens the browser profile.

### 1.5 Test-only escape hatches are live in the release binary

Audit B; confirmed via `strings`. `src/main.rs:139-158`, proxy setup ~`:625`.

- Fix: gate `AI_JAIL_TEST_PROXY_ALLOW_PRIVATE` (SSRF guard off) and
  `AI_JAIL_TEST_PROXY_EXTRA_ROOTS` (extra TLS root) behind a compile-time feature
  (e.g. `dangerous-test-hooks`) that the release profile never enables; tests opt
  in. Keep the runtime env-var read only under that cfg.
- Test: the integration tests still pass with the feature on; `strings` of a
  default release build contains neither name (add a small build-level check).

## Phase 2 — sandbox-boundary hardening

### 2.1 TIOCSTI seccomp compare uses the wrong width

Advisory 1 #2; both audits; reproduced (`0x5412|(1<<32)` reaches the kernel).
`src/sandbox/seccomp.rs:326-335`.

- Fix: compare the ioctl request as a 32-bit value (`SeccompCmpArgLen::Dword`).
- Test: compile the filter and assert both the plain request and high-word
  variants are denied, using an invalid descriptor; the existing BPF-constant test
  is insufficient. (This host has legacy TIOCSTI disabled, so the deny is verified
  by the filter result, not a live injection.)

### 2.2 Landlock lacks V6 scope; the "backstop" claim is false

Advisory 2; **missed by both audits**; confirmed (no `.scope()` call).
`src/sandbox/landlock.rs`.

- Fix: add a third stacked ruleset applying
  `Scope::AbstractUnixSocket | Scope::Signal` under `CompatLevel::BestEffort`,
  mirroring the existing three-way `RulesetStatus` contract (hard-fail in lockdown,
  log-and-continue otherwise). V3–V5 kernels return `NotEnforced` and the FS
  ruleset is unaffected.
- Doc: correct the threat-model block (`landlock.rs:10-14` and `docs/SECURITY.md`)
  to state which classes the default covers vs. which need `--lockdown` — the
  pathname user bus (`/run/user/$UID/bus`) is a mount-namespace concern, not a
  Landlock one, and V6 scope covers abstract sockets only.
- Test: unit-cover the new ruleset's status handling; note the abstract-socket
  runtime check needs a V6 kernel (record as environment-gated).

### 2.3 ESC-ESC (and ESC-CSI) resets bypass the primary-screen filter

Audit A; B-confirmed (OSC introducer reaches output after a doubled ESC).
`src/pty.rs` `TerminalFilter`.

- Fix: on `ESC` while already in the `Esc` or `Csi` state, restart the pending
  sequence rather than completing or forwarding it; validate CSI grammar before
  forwarding.
- Test: `ESC ESC ]52;…BEL`, `ESC [ ESC ]…`, repeated ESC runs, every input split
  point; assert no OSC dispatch reaches the filtered output. Keep the existing
  charset-designation test.

### 2.4 Redirected stdout leaves terminal stderr unfiltered

Audit A. `src/main.rs` PTY selection; `src/sandbox/bwrap.rs:281-283`.

- Fix: classify every inherited terminal descriptor, proxy each terminal-bound
  output stream, and give the child a private or absent controlling terminal;
  apply passthrough consent consistently across stdout and stderr.
- Test: the full stdin/stdout/stderr TTY matrix with isolated PTYs, including
  `--exec`.

## Phase 3 — availability and audit integrity

### 3.1 Proxy and bridge resource limits are incomplete

Audit A. `src/proxy.rs`.

- Fix: acquire the connection slot _before_ spawning the handler; bound the bridge
  independently; add absolute deadlines for the TLS handshake, request read,
  upload, and response write (established tunnels stay idle-timeout-free by
  design); bound half-close draining.
- Test: silent clients, slow-drip headers, nonresponsive TLS, incomplete bodies,
  blocked consumers, half-close retention; assert thread and descriptor recovery.

### 3.2 vt100 parser accumulates an unterminated OSC without bound

Audit A. `src/pty.rs` around the parser feed.

- Fix: bound or reject terminal-string accumulation before every parser call,
  including drain paths, or configure a parser hard limit.
- Test: feed an oversized unterminated OSC across many chunks in a
  resource-bounded subprocess; assert bounded memory and parser recovery.

### 3.3 Audit chain corrupts across independent processes; no growth bound

Audit A. `src/audit.rs`.

- Fix: coordinate tail-validation-plus-append under an interprocess lock (flock on
  the log fd) or move to per-launch logs; after an uncertain partial write, fail
  closed rather than keep stale in-memory chain state. Add a size/rotation cap and
  collapse repeated identical verdicts. Ensure the lockdown child `FSIZE` cap does
  not apply to the supervisor's own audit writes (avoid `SIGXFSZ`).
- Test: two concurrent handles / processes then verify the chain; inject
  prefix-write-then-error; drive the log past the rotation threshold.

### 3.4 HTTP-termination framing is ambiguous

Audit A (Low). `src/proxy.rs:604-620`, `626-710`.

- Fix: split head from body at the first `\r\n\r\n` before parsing framing; reject
  conflicting or invalid `Content-Length`/`Transfer-Encoding`; forward exactly the
  accepted body length; do not let non-UTF-8 body bytes disable framing detection.
- Test: duplicate/negative/invalid `Content-Length`, chunked, surplus buffered
  bytes; assert exact forwarding and rejection of conflicts.

### 3.5 Project-config read can block or exhaust the supervisor

Audit A. `src/config.rs:720-759` (and the credential-file path `:540-593`).

- Fix: open once with `O_NOFOLLOW | O_NONBLOCK`, validate the opened descriptor
  (regular file, ownership, mode), enforce a per-file and aggregate size cap before
  `read_to_string`. Same for env-files.
- Test: a FIFO at the config path does not block; an oversized regular file is
  rejected before allocation.

### 3.6 Saving UI preferences deletes credential policy

Both audits. `src/config.rs:1355-1419`; skip-serialized fields `:258-273`.

- Fix: patch only the changed keys in the on-disk TOML document instead of
  re-serializing the whole struct (which drops `env_pass`, `env_from_file`,
  `secret_hosts`). Or refuse to save while those runtime fields are populated.
- Test: set a status-bar theme with credential fields present; assert the saved
  document still contains them.

## Phase 4 — credential-boundary correctness

### 4.1 Deterministic phantom placeholder

Both audits; confirmed the placeholder equals `sha256(key:real)[..16]`.
`src/secret.rs:26-33`.

- Fix: derive the placeholder from a CSPRNG (≥128 bits) per binding per launch;
  keep the `AIJAIL-PHANTOM-` shape.
- Test: two launches with the same inputs yield different placeholders; the value
  never contains any slice of the real secret.

### 4.2 Only the first binding per host is applied

Audit A (Low functional). `src/proxy.rs:674-709`.

- Fix: pass every binding whose host matches to `rewrite_head`; keep per-key audit
  counts.
- Test: two keys bound to the same host both substitute.

### 4.3 Untrusted project can override explicit CLI restrictions

Both audits. `src/config.rs:858-864` (`take!`) applied after the CLI layer.

- Fix: apply the CLI layer last, or refuse to let a trusted-project value override
  a value the CLI set explicitly to a _more_ restrictive setting.
- Test: `--no-network` in a `trust_project_config` dir with `network = true` in the
  project file stays no-network.

### 4.4 Untrusted project can disable operator audit logging

Audit A; B-confirmed. `src/config.rs:1190-1236` `monotonic!(audit_log)`.

- Fix: treat `audit_log` as operator policy independent of capability
  monotonicity; a project `.ai-jail` cannot switch off logging enabled by CLI or
  trusted config.
- Test: project `audit_log = false` does not disable a CLI/global `--audit-log`.

### 4.5 `allow_hosts` "shrink by omission" is documented but not implemented

Both audits. `src/config.rs:1281-1294`.

- Decision needed: either implement intersect-with-baseline for a non-empty
  project list (define empty vs. omitted, preserving old-config parsing), or
  correct the docs/plan to say project `allow_hosts` can only fail to add. Pick
  one; do not leave the claim and the code disagreeing.

## Phase 5 — macOS (requires a Mac / the `macos` CI job to validate)

From advisory 1 (#4, #5) and audit A. All in `src/sandbox/seatbelt.rs`.

- 5.1 Restrict `file-read*`/`file-write*` to the allocated PTY, not every
  `/dev/ttys[0-9]+` (advisory 1 #4).
- 5.2 Add effective mask paths to write denials, not only read denials; test
  last-match order in the generated profile (advisory 1 #5).
- 5.3 Make explicit `hide_dotdirs` win over agent-state passthrough, matching
  Linux.
- 5.4 Create the session temp dir atomically with a random name under the
  validated per-user root; validate the opened descriptor; RAII cleanup.

These are code-writable now but must not be marked done until the `macos` CI job
exercises them; several rest on Seatbelt semantics not testable on Linux.

## Phase 6 — documentation and low-severity

- 6.1 `--env KEY=VALUE` is visible in `/proc/<pid>/cmdline` — one line in
  "Credential hygiene" steering users to `--env NAME` / `--env-from-file`.
- 6.2 README "CLI flags have highest authority" — correct once 4.3 is decided.
- 6.3 `docs/SECURITY.md` "real values never reach the sandbox" — note the
  placeholder is derived from the secret (until 4.1 lands, then it is true again).
- 6.4 `docs/RELEASE_SECURITY.md` — document the attestation / `id-token` step the
  workflow runs.
- 6.5 Landlock threat-model wording (with 2.2).
- 6.6 Piped stdin with terminal stdout fails before launch (audit A Low) — enter
  raw mode only when stdin is a TTY; otherwise preserve the pipe and still proxy
  output.

## Release publication (separate track, human decision)

Audit A [High, conditional]: `cargo publish` runs with `CARGO_REGISTRY_TOKEN`
present, so a malicious build path in a tagged commit could read it. Move to
crates.io trusted publishing (OIDC, short-lived), or split secret-free packaging
and verification from the minimal token-bearing upload. This is a workflow change
with a human decision attached (`STOP` per audit policy if it needs more than
mechanical edits); keep it off the code-fix critical path.

## Suggested order

1. Phase 1 (1.1–1.5) — release-blocking; ship as one security release once green.
2. Phase 2 (2.1–2.4) and Phase 4 (4.1, 4.3, 4.4) — boundary + credential
   correctness.
3. Phase 3 — availability and audit integrity.
4. Phase 5 — macOS, gated on the `macos` CI job.
5. Phase 6 docs alongside each owning fix, not batched at the end.
6. Release-publication track in parallel, human-owned.

Do not describe any release as hardened until at least Phase 1 and the Phase 2
sandbox items are merged with their regression tests and the full gate is green
on the exact release commit.
