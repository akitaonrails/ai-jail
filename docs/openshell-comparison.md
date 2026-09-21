# OpenShell vs ai-jail

**Date**: September 2026
**Subject**: [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) — "the safe,
private runtime for autonomous AI agents", announced at GTC 2026-03-16,
Apache-2.0, pre-1.0 (`v0.0.116`, `v0.1.0-pre.5` in flight), ~8.7k stars.
**Verdict up front**: different product category. OpenShell is an agent
_runtime platform_ (daemon + containers + policy engine); ai-jail is a
_one-shot process wrapper_. We should not chase their architecture — but
their egress-filtering model exposes our weakest surface, and two of their
ideas are worth borrowing in a form that fits us.

## The fundamental difference

|                   | ai-jail                                                                     | OpenShell                                                                                                      |
| ----------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Unit of isolation | one child process in namespaces (bwrap/Landlock/seccomp; seatbelt on macOS) | a container, pod, or libkrun MicroVM per sandbox                                                               |
| Control plane     | none — the CLI _is_ the supervisor                                          | persistent **gateway** daemon (local K3s-style cluster, remote over SSH, or Kubernetes via Helm)               |
| Prereqs           | `bwrap` (~50 KB binary)                                                     | Docker Engine 28.04+ / rootless Podman / Kubernetes / KVM                                                      |
| Agent environment | your real host: project dir, toolchain (mise), dotfiles you opt in          | a bundled container image (Python 3.14, Node 22, agent CLIs baked in)                                          |
| Network policy    | on/off (private netns vs host net)                                          | deny-by-default **CONNECT proxy** + OPA policy, per-destination, optional L7 TLS inspection                    |
| Credentials       | env allowlist + opt-in `--agent-state` mounts                               | gateway-brokered providers, endpoint-bound injection, never on sandbox disk                                    |
| Auditability      | none (process exits, gone)                                                  | OCSF structured logs, per-connection allow/deny trail                                                          |
| Footprint         | ~1.7 MB binary, 37 lockfile packages, no daemon                             | gateway + cluster containers + per-sandbox image + in-sandbox proxy/supervisor                                 |
| Platforms         | Linux, macOS (native seatbelt)                                              | Linux; macOS via Docker Desktop VM (sandboxing lives in the VM, not the host); Windows via WSL2 (experimental) |
| Telemetry         | none                                                                        | anonymous, on by default, opt-out                                                                              |
| Maturity          | 1.x, weekly cadence, hard config back-compat contract                       | alpha-stage, 116 patch tags in ~7 months, 542 open issues                                                      |

## What ai-jail does better

- **Zero infrastructure.** No container daemon, no gateway, no cluster.
  `cargo install ai-jail` (or brew/AUR/nix) and you're sandboxing. OpenShell's
  first-run experience provisions a local Kubernetes-style cluster; ours is a
  single exec.
- **Host fidelity.** The agent runs against your actual project, your actual
  toolchain (mise-managed versions), your SSH agent/display/audio if you opt
  in. OpenShell's agent lives in a container image with NVIDIA's bundled
  toolchain — your host dev environment does not carry over.
- **Real macOS support.** We generate seatbelt profiles on the host. On macOS,
  OpenShell's Landlock/seccomp enforcement happens inside the Docker Desktop
  Linux VM — the macOS host itself is out of the policy loop.
- **Interactive-terminal hardening.** vt100 filter for control-sequence
  injection, TIOCSTI denial, alt-screen re-rendering, status bar, signal
  forwarding, terminal reset on exit. OpenShell SSHes you into a container;
  the terminal path is out of scope for them.
- **Unprivileged and fail-closed everywhere.** No root, no daemon socket, and
  every ambiguous state (unreadable config, symlink tricks, partial Landlock)
  is fatal or loudly warned. OpenShell's default Landlock mode is
  `best_effort` — it _degrades to no filesystem enforcement_ on pre-5.13
  kernels with only a log finding (their `hard_requirement` mode matches our
  behavior, but it's opt-in).
- **Auditability of the tool itself.** ~6k lines of dependency-light Rust you
  can read in an afternoon, vs a gateway + OPA + proxy + Helm + gRPC driver
  surface. Our threat model is inspectable by one person; theirs isn't.
- **Privacy posture.** No telemetry, no phone-home except an explicitly
  opt-in update check that only runs while the status bar is visible.
- **Config stability.** A documented contract that every new version works
  with previously generated configs, enforced by regression tests. OpenShell
  is pre-1.0 with a schema-v1 policy format still in flux.

## What OpenShell does better

- **Egress policy — their headline win, our biggest gap.** Deny-by-default
  network where even proxy-unaware processes can only reach the in-sandbox
  CONNECT proxy; rules match binary identity + host + port; optional L7
  inspection (per-method/path REST, GraphQL, MCP per-tool); SSRF guards
  against private/loopback/metadata IPs; denied endpoints surface for
  one-click operator approval. Our network is a binary switch, and
  `--allow-tcp-port` has been dead-failing since v1.18.0 because UDP can't be
  constrained. An agent with `--network` can exfiltrate to anywhere.
- **Credential brokering.** Credentials are injected gateway-side only after
  policy admits the request, never written to the sandbox filesystem, with
  rotation and SigV4 re-signing. Our model is ambient: env vars and
  `--agent-state` mounts are visible to anything running inside.
- **Audit trail.** OCSF JSONL of every connection, process, and SSH session
  with allow/deny decisions. We log nothing — after a run you cannot answer
  "what did the agent touch?"
- **Stateful sandbox lifecycle.** Stop/start with persistent workspaces,
  policy hot-reload, reconnecting sessions. We're one-shot by design.
- **Stronger isolation ceiling.** The libkrun MicroVM driver (KVM/HVF) is a
  real VM boundary for genuinely hostile workloads — the thing our README
  explicitly tells you to use a disposable VM for.
- **Multi-host and teams.** Remote gateways over SSH, Kubernetes/OpenShift,
  OIDC. Entirely out of our scope, but real value for org deployments.
- **Distribution plumbing worth noting**: OCI SBOMs, `gh attestation
verify`-able artifacts, SDKs in four languages.

## What we could borrow (and what fits)

Ranked by value-per-effort for our single-binary, no-daemon model.

### 1. A minimal local CONNECT proxy for egress allowlists — the real lesson

OpenShell proves the demand: agent users want "API + GitHub yes, everything
else no", not "all network or no network". Our dead `--allow-tcp-port` shows
we hit the same wall. A fit-for-us version, without their machinery:

- An optional built-in HTTP CONNECT forward-proxy (no TLS termination, no CA,
  no L7) bound to a loopback addr inside the net namespace; ai-jail sets
  `http_proxy`/`https_proxy` for the child and Landlock V4 (or the namespace
  itself) blocks direct egress except to the proxy.
- A `--allow-host` / `allow_hosts` config list matched at CONNECT time —
  domain allowlisting without MITM, and private/loopback ranges refused by
  default (their SSRF guard, basically free at CONNECT).
- Proxy-unaware processes still get nothing unless `--network` is fully on —
  same trade-off OpenShell accepts, at 1% of the complexity.

This is a meaningful feature (new proxy component, new tests), not a
weekend patch — but it's the only OpenShell capability our users are likely
to actually miss.

### 2. Graduate the Landlock V4 port allowlist out of lockdown

Cheaper subset of the above: `allow_tcp_ports` already exists but is only
reachable in `--lockdown`, and the CLI flag fails closed because UDP is
unconstrained. We could expose it in normal mode with honest documentation
("TCP connect only; UDP/ICMP unrestricted") — or decide the CONNECT proxy is
the one true answer and keep it closed. Don't ship both half-heartedly.

### 3. A launch audit log

Their OCSF pipeline is overkill, but the question "what did I let that agent
do?" is legitimate. Cheap version: an opt-in append-only JSONL at
`~/.local/share/ai-jail/history.jsonl` — timestamp, command, effective
capability set, config sources, exit code, duration. No connection logging
(impossible without the proxy), no schema framework, ~100 lines.

### 4. Credential hygiene documentation, not machinery

Their endpoint-bound injection needs a gateway we don't have. But the
_spirit_ — secrets never at rest in project files — we already half-implement:
`env_pass` is never persisted to disk and project `.ai-jail` can't set it.
Worth one README/docs section codifying the pattern: inject secrets via host
env + `--env NAME`, never write them into any `.ai-jail` file. Possibly an
`--env-from-file PATH` (0600, user-owned, validated) for launcher scripts.
Small, honest, done.

## What we should NOT borrow

- **Gateway/daemon/control plane** — our entire value proposition is that
  there isn't one. The moment ai-jail needs a running service, we've become a
  worse OpenShell instead of a better ai-jail.
- **L7 TLS inspection with a per-sandbox CA** — MITM-ing the agent's traffic
  is a trust and maintenance sink (cert injection into every runtime's CA
  store, GraphQL/MCP parsers) utterly disproportionate to a process wrapper.
- **Kubernetes/OIDC/multi-tenant anything** — different product.
- **TUI dashboard, SDKs, agent-operable skills** — surface area without
  sandbox value for a single-user CLI.
- **Default-on telemetry** — against the project's posture, full stop.
- **Container-image agent environments** — our host-fidelity is the feature.

## Bottom line

OpenShell is NVIDIA building the Kubernetes of agent runtimes: heavier,
richer, team-scale, alpha. ai-jail's answer to the same fear is a binary you
already trust. The one place their architecture genuinely beats ours —
fine-grained egress — doesn't actually require their architecture. If we
build anything from this research, it's the loopback CONNECT proxy with
`--allow-host`; everything else is validation that the minimal model was
right.

**Follow-up**: the design and implementation plan for that proxy now lives
in [connect-proxy-plan.md](connect-proxy-plan.md).

## Sources

- [NVIDIA/OpenShell repo](https://github.com/NVIDIA/OpenShell) and
  [docs.nvidia.com/openshell](https://docs.nvidia.com/openshell/latest/)
  ([architecture](https://docs.nvidia.com/openshell/about/architecture),
  [policy schema](https://docs.nvidia.com/openshell/reference/policy-schema),
  [compute drivers](https://docs.nvidia.com/openshell/reference/sandbox-compute-drivers),
  [support matrix](https://docs.nvidia.com/openshell/latest/reference/support-matrix.html),
  [security best practices](https://docs.nvidia.com/openshell/security/best-practices))
- [NVIDIA developer blog announcement](https://developer.nvidia.com/blog/run-autonomous-self-evolving-agents-more-safely-with-nvidia-openshell/)
- [Red Hat Developer: layered sandboxing on OpenShift](https://developers.redhat.com/articles/2026/07/16/layered-sandboxing-ai-agents-openshift-and-openshell)
- Not verified: no independent security audit of OpenShell found; no published
  performance/overhead benchmarks; no named end-user production deployments
  beyond vendor partnerships.
