# Security Audit — 2026-09-30

Audit performed by LUA, a Genesys PI model developed by LUA Vision.

## Scope

- Audited commit: `f62d5761b18b9d9765b4c88aacc4ad77ff0db5e4`
- Branch: `master`
- Released `v2.3.0` implementation: `fb6e7b6e0ed0953b90b163551436f170d1f61e1f`
- The audited branch differed from the release only in AUR metadata.
- The repository was clean before and after the audit.
- The audit was read-only. No source files, tickets, branches, tags, releases, or security settings were changed.

The assessment covered Linux and macOS sandbox construction, configuration trust and precedence, filesystem exposure, terminal handling, filtered egress, phantom credentials, audit logging, process limits, CI, and release publication.

## Threat model

Protected assets include host files outside the project, credentials, terminal integrity, network isolation, audit-log integrity, release credentials, and supervisor availability.

Relevant attackers include:

- code running inside the sandbox;
- a repository controlling project files and command output;
- a process able to prepare or replace local filesystem entries;
- a configured upstream service receiving a bound credential;
- a contributor able to affect code built during publication;
- a local actor able to influence inherited environment or executable lookup.

This tool is a development sandbox, not a boundary for hostile kernel-level workloads. Kernel, driver, and underlying sandbox implementation escapes remain outside scope.

## Automated evidence

The following checks passed for the audited state:

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked`
- `cargo audit`
- release build
- working-tree diff check

The full test run reported 776 unit tests plus the integration suites, with no failures. Hosted Linux, macOS, Nix, musl, and CodeQL checks for the relevant commit were green. GitHub secret-scanning, dependency, and code-scanning dashboards had no open alerts.

These results are supporting evidence only. They do not cover the manual trust-boundary defects below.

## Findings

### [High] Forged worktree metadata can expose an arbitrary host directory

**Evidence:** `src/sandbox/mod.rs:743-782`, `src/sandbox/bwrap.rs:2869-2908`.

When `--worktree` is enabled, validation establishes that:

- the project `.git` file points to a directory;
- that directory contains a `gitdir` file pointing back to the project `.git` file;
- its `commondir` file points to an existing directory.

It does not establish that the paths belong to a genuine linked Git worktree hierarchy. Repository-controlled metadata can therefore designate an arbitrary existing directory as the common directory. Outside lockdown, both discovered paths are bind-mounted read-write.

**Prerequisites:** The user explicitly enables worktree passthrough and launches from a prepared repository tree.

**Impact:** Read-write exposure of a host directory outside the project.

**Remediation:** Resolve worktree metadata through Git or validate the full canonical hierarchy: the per-worktree directory must be under `<common>/.git/worktrees/`, the reverse link must identify the exact worktree, and the common directory must be the repository common directory rather than an arbitrary existing path. Reject all inconsistencies.

**Regression tests:** Add adversarial fixtures whose mutually consistent files point to unrelated host directories, symlinked ancestors, and swapped metadata. Confirm they are rejected while a real linked worktree remains usable.

### [High] Overlay setup can silently fall back to the real writable project

**Evidence:** `src/sandbox/bwrap.rs:1596-1608`, `1700-1705`, `3020-3021`, `3045-3081`.

Missing overlay sources, overlapping destinations, and layer-directory creation failures can produce a warning and skip the requested overlay. The normal project bind remains writable, so a user relying on copy-on-write protection may instead modify the original files.

The storage-name transformation at `src/sandbox/bwrap.rs:2989-3006` also replaces distinct punctuation characters with `_`, allowing different destinations to map to the same storage directory.

**Prerequisites:** The user requests an overlay map and setup encounters one of the skip conditions or a name collision.

**Impact:** Loss of the promised copy-on-write boundary and unintended modification of source files.

**Remediation:** Fail the launch when any requested overlay cannot be established. Derive collision-resistant storage identifiers from canonical destinations, and reject duplicate identifiers defensively.

**Regression tests:** Cover missing sources, overlaps, unwritable storage, symlink replacement, punctuation collisions, and bwrap overlay failures. Assert that the child never launches against the writable original after a requested overlay fails.

### [High] Duplicate environment entries can bypass phantom-secret isolation

**Evidence:** `src/main.rs:115-133`, `src/config.rs:519-533`.

Secret preparation rewrites only the first matching environment entry, while final child-environment construction uses the last successfully resolved value. For example:

```text
KEY=first, KEY=real
→ KEY=placeholder, KEY=real
→ child receives real
```

A credential file followed by `--env KEY` can create this condition without unusual input.

Linux lockdown avoids this exact disclosure path because it forwards the rewritten first explicit binding through a separate path, but ordinary Linux and macOS runs remain affected.

**Impact:** A real credential can enter the sandbox environment despite phantomization.

**Remediation:** Resolve each bound key using exactly the same precedence and missing-variable semantics as final child-environment construction. Remove every entry for that key and insert one placeholder entry.

**Regression tests:** Cover duplicate explicit values, credential-file plus CLI values, bare missing variables, global/command/CLI collisions, inheritance modes, and both sandbox backends. Assert that the proxy receives the effective real value and the child receives only the placeholder.

### [High, conditional] Update checking can execute an attacker-selected host binary

**Evidence:** `src/main.rs:755-756`, `src/statusbar.rs:291-304`.

The opt-in update checker executes a bare `curl` through inherited host `PATH` before sandbox construction. It does not validate or pin the executable and does not clear the host environment.

**Prerequisites:** Update checking is enabled, the interactive status bar is active, and an attacker-writable directory appears before the trusted curl location in host `PATH`.

**Impact:** Code execution with host authority outside the sandbox.

**Remediation:** Prefer a bounded in-process HTTPS implementation. Otherwise resolve and validate a trusted absolute executable, disable user curl configuration, sanitize the environment, and enforce timeout and output limits externally.

**Regression tests:** Put a synthetic executable named `curl` in a repository-local directory at the front of `PATH` and assert that it is never selected.

### [High, conditional] Release publication rebuilds while the registry token is present

**Evidence:** `.github/workflows/release.yml:310-329`.

The crates.io publication job supplies `CARGO_REGISTRY_TOKEN` to `cargo publish --locked`. Publication may verify and build package content while the credential is present. A malicious build path introduced into the tagged source could access the token.

**Prerequisites:** A malicious or compromised build path reaches a release tag and the publication environment approves it.

**Impact:** Registry credential theft and possible package publication compromise.

**Remediation:** Adopt trusted publishing with short-lived identity credentials. Separate secret-free packaging and verification from the minimal upload step. Enforce protected release environments and signed, reviewed tags.

**Regression/verification:** Validate the release workflow with no long-lived registry token and confirm that package build scripts never run in a credential-bearing job.

### [Medium] Terminal escape filtering can be bypassed

**Evidence:** `src/pty.rs:800-826`.

Repeated or nested ESC bytes can reset or prematurely complete parser states, allowing a following OSC sequence through unchanged. Confirmed examples include:

```text
ESC ESC ]52;... BEL
ESC [ ESC ]52;... BEL
```

**Prerequisites:** Child-controlled primary-screen output and a host terminal that acts on the delivered sequence. Clipboard modification additionally depends on terminal policy.

**Impact:** Delivery of terminal protocols that the default filter is intended to block. This does not by itself prove universal clipboard access or command execution.

**Remediation:** Restart or discard interrupted escape sequences when ESC appears in ESC/CSI states, and validate CSI grammar before forwarding.

**Regression tests:** Test both examples, repeated ESC runs, every input split point, and parser-level confirmation that no OSC dispatch reaches a recording terminal.

### [Medium] Redirected stdout can leave terminal stderr unfiltered

**Evidence:** `src/main.rs:383-398`, `691-720`, `839-849`; `src/sandbox/bwrap.rs:281-283`.

PTY selection and passthrough consent consider stdout. When stdout is redirected but stderr remains terminal-connected, the child inherits an unfiltered terminal output descriptor. With terminal stdin outside lockdown, the child can also retain the host controlling terminal.

**Impact:** Terminal control sequences can bypass the filter through stderr. The retained controlling terminal also combines with ioctl weaknesses.

**Remediation:** Classify all inherited terminal descriptors, proxy every terminal-bound output stream, and provide the child a private or absent controlling terminal. Apply passthrough consent consistently.

**Regression tests:** Exercise the stdin/stdout/stderr TTY matrix using isolated PTYs, including `--exec`.

### [Medium; potentially High in combination] TIOCSTI seccomp comparison uses the wrong width

**Evidence:** `src/sandbox/seccomp.rs:326-350`.

The seccomp rule compares ioctl argument 1 with a 64-bit equality test, while Linux interprets the request as a 32-bit value. A raw syscall can set upper bits to avoid the filter while preserving the effective ioctl request.

Safe verification with an invalid descriptor produced `EPERM` for ordinary `TIOCSTI` and normal syscall handling for high-bit variants.

**Prerequisites for shell-input injection:** Access to the relevant controlling terminal and a kernel that permits legacy unprivileged TIOCSTI. The audit host had legacy TIOCSTI disabled.

**Remediation:** Compare the ioctl request as a 32-bit argument.

**Regression tests:** Execute the compiled filter against zero- and nonzero-upper-word forms using an invalid descriptor. The existing BPF-constant test is insufficient.

### [Medium] Unterminated OSC data can grow supervisor memory without bound

**Evidence:** `src/pty.rs:240`, `350-351`, `435-441` and the resolved terminal parser dependency behavior.

Raw child bytes reach the terminal parser before filtering. With the enabled dependency features, an unterminated OSC string accumulates in a growing vector across reads. The 8 KiB read buffer limits individual reads, not total parser state.

**Impact:** Supervisor memory exhaustion and session denial.

**Remediation:** Bound or reject terminal string accumulation before every parser call, including drain paths, or use a parser configuration with a hard bound.

**Regression tests:** Feed an oversized unterminated OSC over many chunks in a resource-bounded subprocess and assert bounded memory plus parser recovery.

### [Low] Piped stdin with terminal stdout fails before child launch

**Evidence:** `src/main.rs:691-720`, `src/pty.rs:99-106`, `1164-1194`.

Terminal stdout selects the PTY path, which unconditionally applies `tcgetattr` to stdin. Piped or file stdin returns `ENOTTY` before spawning the workload.

**Remediation:** Enter raw mode and proxy input only when stdin is a terminal; otherwise preserve the pipe while continuing to proxy terminal output.

### [Medium] Proxy and bridge resource limits are incomplete

**Evidence:** `src/proxy.rs:111-130`, `245-263`, `351-369`, `727-777`, `790-877`.

- Handler threads are spawned before admission control.
- Bridge relays have no admission limit and create additional pump threads.
- Initial request timeout is per read rather than an absolute deadline.
- TLS handshake, upload, response write, and tunnel lifetime lack complete deadlines.
- Half-closed bridge connections can retain a blocked upload pump and its handler.

The 256 admitted-connection cap and process file-descriptor limits are real, but they do not bound all spawned threads or bridge lifetimes.

**Impact:** Session denial and host resource pressure when filtered egress is enabled.

**Remediation:** Acquire capacity before spawning, bound proxy and bridge independently, add absolute phase deadlines, and bound half-close draining.

**Regression tests:** Cover silent clients, slow-drip headers, nonresponsive TLS, incomplete bodies, blocked response consumers, half-close retention, and thread/descriptor recovery.

### [Low; smuggling impact needs validation] HTTP termination has ambiguous framing

**Evidence:** `src/proxy.rs:604-620`, `626-710`, `727-737`.

The termination path:

- examines the whole initial buffer, including body bytes, while deriving framing;
- lets non-UTF-8 body data disable framing recognition;
- uses last-value behavior for duplicate `Content-Length` headers;
- accepts invalid length values as absent;
- forwards already-buffered bytes beyond the declared body;
- leaves ambiguous framing headers on the upstream request.

Each request uses a fresh upstream TLS connection with connection closure requested, which limits the demonstrated impact. Cross-client desynchronization or allowlist bypass was not established.

**Remediation:** Split at the first header terminator before parsing, reject conflicting or invalid framing, accept only supported transfer modes, and forward exactly the accepted body length.

### [Medium] Untrusted project `allow_hosts` does not shrink the trusted baseline

**Evidence:** `src/config.rs:1281-1294`, regression test `src/config.rs:4221-4237`.

The comments and documentation state that omission or a subset in project policy narrows the allowlist. The implementation instead retains every baseline host and merely rejects new hosts. The test explicitly asserts that the complete baseline survives.

**Impact:** A repository cannot enforce the documented tighter egress policy.

**Remediation:** When an untrusted project supplies a nonempty list, intersect it with the trusted baseline. Define and test the meaning of an omitted versus explicitly empty list without breaking old config parsing.

### [Low security / Medium functional] Only one secret binding is selected per host

**Evidence:** `src/proxy.rs:674-709`.

The proxy uses the first binding matching a hostname and passes only that binding to a rewrite function that otherwise supports multiple values. With several keys bound to the same host, later placeholders are not substituted.

**Remediation:** Select every binding for the matched host and preserve per-key audit counts.

### [Informational boundary issue] Bound services can reflect real secrets

**Evidence:** `src/secret.rs:50-69`, `src/proxy.rs:744-747`, `tests/phantom_secrets.rs:199-225`.

Substitution applies to arbitrary positions in the request head, and upstream responses are returned without filtering. Existing tests intentionally demonstrate a reflected real credential reaching sandbox output.

This is not an arbitrary-host bypass: allowlisting, DNS checks, target matching, and TLS validation remain relevant. It does invalidate documentation claiming that a real value never reaches the sandbox. A transparent proxy cannot prevent a malicious bound service from encoding and returning a secret.

**Remediation:** Document bound services as trusted credential recipients. Reduce unnecessary exposure by injecting only into configured authentication fields and approved operations. Do not claim response redaction can provide a complete guarantee.

### [Medium for low-entropy secrets; Low otherwise] Deterministic placeholders leak correlation and support guessing

**Evidence:** `src/secret.rs:26-33`, determinism test `src/secret.rs:112-119`.

The placeholder is derived from a truncated hash of the key name and real value, without a random launch salt. Identical credentials produce stable identifiers across launches, projects, and hosts. A sandbox can test candidate low-entropy values offline.

This does not make arbitrary high-entropy API tokens practically recoverable.

**Remediation:** Generate a fresh, secret-independent random placeholder of at least 128 bits per binding per launch.

### [Medium] Independent audit writers can corrupt the hash chain

**Evidence:** `src/audit.rs:505-568`.

The mutex protects threads sharing one handle, but separate processes open the same file and independently seed sequence and previous-hash state. Two writers can therefore append conflicting chain records. A successful prefix write followed by an error can also leave a malformed tail while the live writer retains stale state.

**Remediation:** Coordinate tail validation and append under an interprocess lock, or use per-launch logs. Disable or explicitly recover after uncertain partial writes.

**Regression tests:** Use two simultaneously open handles and multiple processes, then verify the resulting chain. Inject prefix-write-then-error behavior.

### [Medium] Audit logging has no growth or rate bound

**Evidence:** `src/proxy.rs:291-333`, `src/sandbox/rlimits.rs:15`, `42-47`, `src/main.rs:781`.

Denied proxy requests are logged before DNS or connection work. The writer has no rotation, total-size limit, or verdict-rate budget. Under lockdown, the supervisor receives a 1 GiB file-size limit; extending an audit file past that limit can deliver `SIGXFSZ`, whose default action terminates the process.

**Remediation:** Rotate or cap logs, summarize repeated verdicts, and apply child resource limits without unintentionally constraining supervisor logging.

### [Medium policy bypass] Untrusted project config can disable audit logging

**Evidence:** `src/config.rs:1234-1236`, test `src/config.rs:4275-4300`.

The monotonic merge treats disabling audit logging as tightening policy, so a project can turn off logging enabled by trusted configuration or the CLI.

**Impact:** Loss of operator-requested audit evidence.

**Remediation:** Treat audit logging as an operator policy independent of sandbox capability monotonicity. An untrusted project must not disable an explicit trusted or CLI choice.

### [Medium] Project config can block or exhaust the supervisor before sandboxing

**Evidence:** `src/config.rs:720-759`, called at `src/main.rs:472-479`.

Project config loading rejects a final-component symlink but accepts other file types, then reopens the pathname with unbounded `read_to_string`. A pre-existing FIFO can block before sandbox construction, and a large regular file can cause excessive allocation. The metadata/open split also creates a replacement race.

Git cannot represent a FIFO directly, but a prepared working tree or another local process can. Oversized regular files need no special filesystem type.

Credential files reject static FIFOs and unsafe modes, but validation and reading use separate pathname operations and have no size cap: `src/config.rs:540-593`.

**Remediation:** Open once with descriptor-relative, no-follow and nonblocking semantics; validate the opened descriptor; enforce per-file and aggregate limits before parsing.

### [Medium] Saving UI preferences deletes credential policy

**Evidence:** credential fields at `src/config.rs:258-273`; whole-document save path at `src/config.rs:1365-1419`.

`env_pass`, `env_from_file`, and `secret_hosts` are never serialized. Saving a status-bar preference reloads the global document into typed structures and rewrites the whole document, removing those fields from the base and all command tables.

**Impact:** Subsequent authentication failure or, where credentials still arrive through another mechanism, loss of phantom-secret protection.

**Remediation:** Update only the relevant keys in the original TOML document. Do not serialize merged runtime credentials or CLI secret values.

### [Medium] Trusted project config can override explicit CLI restrictions

**Evidence:** `src/main.rs:478-498`, `src/config.rs:832-906`, `1096-1106`, `1627-1749`.

CLI settings are merged into the trusted baseline first. A project under `trust_project_config` is merged afterward using scalar replacement semantics, so it can undo an explicit CLI choice. This contradicts `README.md:272-287`, which calls CLI flags the highest authority.

A project must already be under a directory trusted by global policy, so this is not an untrusted-repository escalation. It remains a surprising and security-relevant precedence rule.

**Remediation:** Apply CLI last, or document the actual authority model and prevent trusted project policy from weakening explicit restrictive CLI flags.

### [Medium, native validation required] macOS allows direct access to every `/dev/ttys*`

**Evidence:** `src/sandbox/seatbelt.rs:522-552`.

The profile limits `file-ioctl` to the allocated child PTY, but grants read and write access to every `/dev/ttys[0-9]+`. A sandboxed process may therefore write terminal escape sequences directly to another terminal, bypassing the PTY output filter.

**Remediation:** Restrict file read/write access to the allocated PTY as well as ioctl access.

### [Medium] macOS agent-state passthrough overrides `hide_dotdirs`

**Evidence:** `src/sandbox/seatbelt.rs:285-295`, compared with the Linux override behavior and test at `src/sandbox/bwrap.rs:5829`.

When agent-state passthrough is enabled, matching state paths are removed from the generic read-deny list. A user-specified hidden state directory therefore does not win on macOS as it does on Linux.

**Remediation:** Make explicit user deny/hide policy take precedence over agent-state exposure on both platforms.

### [Medium, native validation required] macOS masks do not consistently deny writes

**Evidence:** `src/sandbox/seatbelt.rs:296-318`, `676-678`, `682-753`.

Effective mask patterns are added to read denials. Write denials are built from explicit deny paths plus read-only/overlay maps, not all mask paths. A process that cannot read a masked project file may still modify it blindly through the project write allowance.

**Remediation:** Add effective mask paths to explicit write denials and test last-match behavior in the generated profile and on a native macOS runner.

### [Medium, native validation required] macOS session temporary directories are predictable and reused

**Evidence:** `src/sandbox/seatbelt.rs:827-851`.

The session directory is named `ai-jail-<pid>`. Creation accepts an existing directory through `is_dir()`, then changes its mode by pathname. There is no production cleanup guard. PID reuse can therefore reopen stale state, and pathname replacement remains possible.

**Remediation:** Create a random directory atomically under the validated per-user root, validate the opened directory descriptor, and remove it through RAII cleanup.

## Documentation and compatibility defects

- `README.md:272-287` says CLI flags have highest authority, but a trusted project is merged afterward.
- `src/config.rs:234-235`, `1281-1294`, and `docs/connect-proxy-plan.md:31` claim project `allow_hosts` can shrink the baseline, but it cannot.
- `--x11` alone does not enable display discovery because `discover_display` is called only when `display_enabled()` is true: `src/sandbox/bwrap.rs:1525-1531`, `2555-2591`. Documentation describes X11 as a separate opt-in.
- A non-default Docker socket can be mounted while `DOCKER_HOST` is unconditionally removed from the child environment: `src/sandbox/bwrap.rs:310-330`, `2499-2525`.
- Outside lockdown, bwrap mounts both worktree paths writable while Landlock marks the common directory read-only: `src/sandbox/bwrap.rs:2880-2908`, `src/sandbox/landlock.rs:622-628`.
- `README.md:348-350` says common worktree metadata is read-only, while implementation and `docs/SECURITY.md:24` say it is writable outside lockdown.
- `docs/SECURITY.md:63-64` states overlay setup fails closed, which is not true for all per-overlay setup failures.
- The audit chain provides internal consistency, not authenticity. It cannot detect whole-log replacement, clean suffix deletion, or a final-record edit without a successor.

## Reviewed boundaries with no new finding

- `BWRAP_BIN` does not accept an arbitrary user-controlled executable. Outside Nix, the target must be a root-owned executable without group/other write permission. The Nix path has separate store and binary ownership/mode checks: `src/sandbox/bwrap.rs:676-737`.
- Same-handle concurrent audit writes are serialized by a mutex; the integrity issue is independent handles/processes.
- A static credential FIFO is rejected by regular-file validation. Remaining credential-file concerns require replacement races, writable ancestors, or oversized regular files.
- The proxy has a real 256 admitted-connection cap and process descriptor limits. The finding concerns pre-admission spawning, bridge relays, and incomplete lifetime bounds rather than literally unlimited successful proxy sessions.
- The v2.3 audit readers use descriptor-relative no-follow traversal below trusted `HOME`, reject special files and unsafe ownership/modes, bound records to 8 MiB, and preserve opened-descriptor identity across pathname replacement.
- `BWRAP_BIN`, worktree, network, GPU, display, X11, host shared memory, terminal passthrough, agent state, Docker, and update checking remain opt-in by default.

## Needs validation

The following unresolved facts are not treated as confirmed vulnerabilities:

- Native macOS execution is needed to establish the exact runtime reach of the `/dev/ttys*`, mask-write, and temporary-directory profile findings.
- Meaningful HTTP request desynchronization or cross-client impact needs a representative upstream server test; only malformed framing and surplus forwarding are confirmed.
- Full TIOCSTI exploitability depends on a kernel permitting legacy unprivileged TIOCSTI and on access to the relevant controlling terminal.
- Some Linux integration tests may skip when user namespaces, Landlock, seccomp, or other host prerequisites are unavailable. A green suite does not prove each negative boundary executed.
- musl and macOS-specific build/runtime behavior was covered by hosted checks, not reproduced locally during this audit.

## Rejected or narrowed candidates

- Same-handle audit thread corruption was disproven; the mutex covers chain state and writing.
- A static credential FIFO was disproven; validation rejects non-regular files. The separate check/use race remains.
- Arbitrary untrusted `BWRAP_BIN` selection was disproven by ownership and mode validation.
- A generic cross-client request-smuggling exploit was not established because the termination path uses a fresh upstream TLS connection and requests closure.
- Deterministic placeholders do not make arbitrary high-entropy credentials practically recoverable; the confirmed risk is correlation and offline guessing of low-entropy values.
- A reflecting bound service is not an arbitrary-host escape. It demonstrates that bound services are inside the credential trust boundary and that the stronger documentation guarantee is false.

## Recommended remediation order

1. Worktree authorization and overlay fail-closed behavior.
2. Duplicate secret handling and preservation of global credential policy.
3. Host update-check executable resolution and release publishing credentials.
4. Terminal OSC filtering, inherited terminal descriptors, parser memory bounds, and TIOCSTI comparison width.
5. Proxy admission, deadlines, half-close cleanup, and HTTP framing.
6. Audit writer coordination, log rotation/rate control, and separation of supervisor and child resource limits.
7. macOS terminal, mask, agent-state, and temporary-directory policy.
8. Config-file descriptor safety, network/config precedence, and documentation corrections.

## Release assessment

The tested release machinery and baseline defaults are substantially hardened, but the confirmed findings include host-filesystem exposure, possible original-file modification despite requested overlays, credential disclosure paths, conditional host execution, terminal filtering bypasses, and availability weaknesses. The published `v2.3.0` release should not be described as fully hardened until the highest-priority boundaries above are corrected and regression-tested.
