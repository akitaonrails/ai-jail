# Filtered egress plan: CONNECT proxy + `--allow-host`

**Date**: September 2026
**Status**: implemented in v2.0.0
**Context**: `docs/openshell-comparison.md` identified fine-grained egress as
the one OpenShell capability worth borrowing. This is the design and
implementation plan. It also covers the two small companion features from the
same research (launch audit log, `--env-from-file`) and settles the fate of
the dead `--allow-tcp-port` flag.

## The decision this reverses

`releases/v1.20.0.md` closed per-domain allowlisting (#107) as out of scope:
"a declinable proxy is not a restriction." That objection was correct against
the design it faced — a proxy the child can simply ignore changes nothing.
This plan is different because the proxy is **not** the enforcement layer.
Enforcement is kernel-level: the sandbox never gets a route off loopback
except through the proxy. The proxy only decides what an already-fenced
process may reach. Anthropic's sandbox-runtime converged on the same pattern
(and documents the same residual gaps), so the design has production
precedent, not just theory.

## Goals / non-goals

Goals:

- `ai-jail --allow-host api.anthropic.com --allow-host github.com claude`:
  the agent reaches exactly those hosts (TCP, via CONNECT), nothing else.
- Kernel-enforced on both platforms. No TLS termination, no CA, no L7
  inspection, no daemon, no new dependencies.
- Project `.ai-jail` may only _shrink_ the allowlist, never grow it.
- Default behavior with no `allow_hosts` is byte-identical to today.

Non-goals (explicitly, matching the comparison doc):

- UDP/QUIC filtering (see Residual gaps), traffic content inspection,
  per-method/path rules, operator approval flows, remote/team features.

## Threat model and residual gaps (documented, accepted)

- **Allowed host is trusted wholesale.** Allowing `github.com` permits
  pushing to any repo. We say so in the docs, as srt does.
- **Linux: DNS simply fails** inside the filtered sandbox (private netns has
  no resolver route). That is a feature — no DNS exfiltration channel — but
  it will surprise tools that pre-resolve; they degrade to proxy behavior.
- **macOS: the system resolver is not fenced.** `getaddrinfo()` works via
  mDNSResponder even when connect() is denied, so low-bandwidth DNS
  exfiltration survives. Same gap srt documents; we accept it.
- **Same-port leak does not exist in this design** — see why below.
- The proxy sees CONNECT metadata (host, port, timing), not content.

## Why not the obvious designs

**Landlock V4 port restriction (Linux).** V4 (kernel **6.7** — the comments
in `src/sandbox/landlock.rs:21,180` saying 6.5 are wrong, fix while there)
matches ports only, never addresses: "allow connect to port P" permits
`evil.com:P`. The proxy port is visible to the child in `http_proxy`, so the
random-port obscurity is zero against the agent itself. Rejected as the
primary fence. (V4 remains useful defense-in-depth, see below.)

**Private netns + proxy inside it.** With `--unshare-net` nothing inside the
namespace, proxy included, has a route out. Unprivileged veth pairs to the
host netns require privileges we don't have; slirp4netns/pasta is an external
dependency we don't want. Rejected.

**Async proxy crate.** Everything proxy-shaped on crates.io is tokio-based
(`hyper-http-proxy`, `http-mitm-proxy`, Pingora); hyper 1.x has no usable
non-tokio glue. A sync CONNECT proxy is ~300–450 auditable std-only lines;
any dep would be bigger than the feature. Rejected; `std::net` +
thread-per-connection + the already-present `nix::poll` feature.

## Design

Three new pieces, two reused patterns.

### 1. `src/proxy.rs` — the CONNECT proxy (new, ~400 lines + tests)

Runs as threads inside the **outer, unrestricted ai-jail supervisor process**
(which already stays alive to reap the child — no daemon, no lifecycle
problem; threads die with the process).

- Listener: `TcpListener` on `127.0.0.1:0` (random port) for macOS; on Linux
  additionally a Unix listener at `$TMPDIR/.ai-jail-proxy-<nonce>.sock`
  (0600, in the per-launch temp dir `SandboxGuard` already manages).
- Per connection (own thread): read the request capped at 8 KiB with a short
  read timeout (slowloris guard on the loopback listener), parse
  `CONNECT authority` (handle `[v6]:port` brackets), then:
  1. **Allowlist check** on the hostname. Semantics: an entry `example.com`
     matches `example.com` and any subdomain (`api.example.com`); entries
     are lowercase, trailing-dot-normalized; IP-literal entries match only
     themselves. Exact rules written down in README.
  2. **Resolve once, dial what you checked** (DNS pinning, srt's model):
     one `ToSocketAddrs` resolution, drop any answer in a denied range,
     `connect_timeout` to a surviving address. Never resolve twice — this
     kills DNS-rebinding TOCTOU.
  3. **SSRF guard**: refused ranges = loopback, link-local, private RFC1918,
     CGNAT 100.64/10, metadata 169.254.169.254, v6 equivalents, unspecified
     0.0.0.0. Denials name the _class_ ("loopback address") not the IP.
- Reply `HTTP/1.1 200 Connection Established\r\n\r\n`, then relay:
  `try_clone()` both streams, two pump threads, `io::copy` each direction;
  on read-EOF `shutdown(Write)` the opposite stream (half-close correctness —
  truncated uploads are the classic bug here); do not `join` one pump before
  the other finishes.
- Optional decision log: when the audit log (below) is on, each CONNECT
  appends `{ts, host, port, verdict, reason-class}` — this turns the proxy
  into the connection-level audit trail OpenShell gets from OPA, for free.
- Limits: max 256 concurrent connections, 10 s connect timeout, 8 KiB
  request cap, no idle timeout on established tunnels (agent SSE streams are
  long-lived).

### 2. Linux fence: netns + in-sandbox bridge (no Landlock net rules needed)

The trick that makes Linux strictly tighter than a Landlock-only design:

- Keep `--unshare-net` — the sandbox still gets a **private network
  namespace with no external route**. DNS, UDP, QUIC, raw egress: all dead
  by construction.
- The outer proxy's Unix socket is bind-mounted into the sandbox
  (Unix sockets are filesystem objects; connecting to one does not cross
  network namespaces).
- A second re-exec stage — `ai-jail --proxy-bridge`, spawned inside the
  sandbox by the existing `--landlock-exec` wrapper **before** it calls
  `restrict_self()` (Landlock/seccomp are inherit-on-spawn, so the bridge
  stays unrestricted; confirmed against kernel docs) — listens on
  `127.0.0.1:<proxy-port>` _inside the netns_ and pumps each accepted
  connection to the bind-mounted Unix socket. Same pump code as the proxy,
  ~100 lines, no socat dependency (this is srt's socat pattern, but the
  bridge is our own binary, already mounted read-only at
  `/tmp/.ai-jail-landlock`).
- Net result for the child: the only reachable TCP endpoint in its universe
  is the loopback bridge. No same-port leak, no UDP leak, no IP-matching
  limitation. Landlock V4 net rules stay lockdown-only; nothing about them
  changes.
- Kernel-version independence: unlike the Landlock V4 route, this works on
  every kernel bwrap already supports.

Mount-order note: the proxy socket bind is a new entry in the load-bearing
26-group mount order in `bwrap.rs` (CLAUDE.md:82-113); it lands in the
capability group region alongside display/audio and CLAUDE.md gets updated
in the same PR.

### 3. macOS fence: seatbelt endpoint rules (parity, actually stronger)

SBPL supports endpoint-scoped rules, and sandbox-runtime ships exactly this
in production: deny everything, then

```
(allow network-outbound (remote ip "localhost:<proxy-port>"))
```

`network-bind`/`network-inbound` stay unemitted (deny default). This is
_address_-scoped, tighter than anything Landlock V4 can express. Filtered
mode on macOS = `push_network_section` emits that one rule instead of the
blanket allows; no bridge process needed (no netns on macOS — the child
talks directly to the host's loopback proxy). Profile-generation unit tests
run on Linux like all existing `sbpl_profile_*` tests; live verification on
the macOS CI runner.

### Config / CLI surface

- New list key `allow_hosts = ["api.anthropic.com", "github.com"]` +
  repeatable `--allow-host HOST`. Same field pattern as
  `allow_tcp_ports` (`config.rs:229-230`): `#[serde(default,
skip_serializing_if = "Vec::is_empty")]`, plus the mandatory old-format
  regression test per CLAUDE.md:70.
- Mode resolution: `network = true` → unrestricted (unchanged);
  `allow_hosts` non-empty → **filtered**; neither → off (unchanged).
  `--network` + `--allow-host` together = launch error (contradictory),
  same fail-closed style as `--allow-tcp-port` today.
- Untrusted project merge: copy the `allow_tcp_ports` shrink-only block
  (`config.rs:1086-1100`) — project entries not in the baseline are dropped
  with a `security_warn`; the baseline survives. Trusted layers union.
- Env injection: filtered mode forces `http_proxy`/`https_proxy`/
  `all_proxy=http://127.0.0.1:<port>` (+ uppercase) via a post-`--clearenv`
  `--setenv` block (the `claude_env` pattern, `bwrap.rs:360-365`), also in
  the lockdown env branch (`bwrap.rs:285-305`); `no_proxy` is cleared.
  Project config already cannot inject env (`config.rs:1069-1074`).
- `ai-jail status` prints the filtered mode and effective allowlist; the
  v1.22.0 capability-gap warning treats filtered as "network satisfied" for
  known API clients (with a note if the agent's API host isn't in the list —
  the known-agent table knows the domains that matter, e.g. claude →
  api.anthropic.com, so we can warn precisely).

### Interaction with existing modes

- `--lockdown` + `allow_hosts`: allowed; filtered egress is strictly tighter
  than lockdown's current "no network". Lockdown's fail-closed ladder
  unchanged.
- `--browser=hard`: unchanged (browser mode forces its own network posture);
  combining `--browser` with `--allow-host` is an error for now — browsers
  need real DNS and many domains; revisit if asked.
- `--ssh`/`--docker`/`--tailscale`: these are socket/Unix-based, unaffected.

## Companion features (same release or fast-follow)

### Launch audit log — `--audit-log` / `audit_log = true`

Opt-in (default off), append-only JSONL at
`~/.local/share/ai-jail/history.jsonl` (dir 0700, file 0600, symlink
rejected — house conventions). One record per launch: timestamp, command,
effective capability set, config sources used, and at exit: exit code,
duration. When filtered egress is active, the proxy appends CONNECT
allow/deny records to the same file (supervisor-side `Mutex` append; the
sandbox never sees the file — it's outside every mount). ~150 lines. Gives
"what did I let that agent do, and where did it try to go?" without OCSF,
OTLP, or a schema framework.

### `--env-from-file PATH` — credential hygiene

Reads `KEY=VALUE` lines from a file that must be user-owned, 0600, not a
symlink, outside the project dir; entries apply exactly like `--env`
(post-allowlist, pre-forced-setenv). Never persisted by config auto-save,
never settable from project `.ai-jail` (the `env_pass` precedent).
~80 lines plus validation tests. This codifies the "secrets live in host
env or a 0600 file, never in any `.ai-jail`" pattern in README/docs.

### `--allow-tcp-port` verdict: stays dead, gets a headstone

Keep the CLI/TOML key parsing (config back-compat contract) and keep the
fail-closed error, but reword it to point at `--allow-host`. The Landlock
V4 `NetPort` machinery stays for lockdown and remains unit-tested. Do **not**
graduate port allowlists to normal mode: the proxy design is strictly
better (address-aware at the CONNECT layer, UDP-safe via netns) and shipping
both would be the "two half-hearted answers" the comparison doc warns
against. README:108-110 updated to point at the new mode.

## Implementation phases

Each phase lands green on master with its own tests; only phases 1–4 are the
proxy feature.

1. **`src/proxy.rs` core** — CONNECT parse/allowlist/SSRF/DNS-pin/relay,
   fully unit-testable on the host (bind loopback, drive it with real
   `TcpStream`s; test half-close, slowloris cap, rebinding pinning, each
   refused IP class, subdomain semantics). No sandbox involvement.
2. **Config/CLI surface** — `allow_hosts`, `--allow-host`, mode resolution,
   contradictory-flag error, shrink-only project merge, status display,
   gap-warning integration, old-format regression test.
3. **Linux wiring** — outer proxy threads + Unix socket, bind mount in the
   mount order, `--proxy-bridge` stage spawned by the landlock wrapper,
   forced env. Integration tests in `tests/` in the `sandbox_escape.rs`
   style: end-to-end `curl --proxy` through a real sandbox to a local
   fixture server, plus negative cases (direct connect refused, disallowed
   host refused, UDP dead).
4. **macOS wiring** — seatbelt endpoint rules + profile tests; CI macos job
   exercises it.
5. **Audit log** — independent, can land any time after 1.
6. **`--env-from-file`** — independent, can land any time.

Docs land with their phase: README capability section, docs/SECURITY.md
(network chapter: filtered mode, residual gaps in the honest language above),
CLAUDE.md mount order + testing conventions, releases note per release flow.

## Risks

- **Proxy correctness is security-critical** — a parse bug is a policy
  bypass. Mitigation: phase 1's test battery, request-size caps, no header
  forwarding beyond the CONNECT line, 200-then-raw-bytes only.
- **Bridge ordering bug** (bridge spawned after `restrict_self`) silently
  breaks connectivity rather than weakening policy — fails closed, the safe
  direction; covered by phase-3 integration tests.
- **Env-honoring bypass**: proxy-unaware processes ignore `http_proxy` and
  just fail (netns has no route) — annoying, not unsafe. Documented.
- **Scope creep toward L7**: the doc you're reading is the fence. If L7 is
  ever wanted, it's a separate proposal with its own justification.

## Semver

Additive, backward-compatible, default-off: **minor** (v1.23.0 when phases
1–4 land; companions can ride the same minor or a following patch).
