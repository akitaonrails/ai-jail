# Wrapper integration contract

This interface lets a trusted host wrapper describe the harnesses it will run
and the access it needs. A request is never a grant. ai-jail remains the only
component that asks the user, stores approval, and constructs the sandbox.

The contract was added in v3.0.1. Wrappers should query it instead of scraping
human-oriented help text:

```console
$ ai-jail capabilities --json
{
  "version": "3.0.1",
  "schema_version": 1,
  "flags": ["--harness", "--request-file", "--request", "--json"],
  "request_kinds": ["private_host", "host", "env", "secret", "agent_state", "map"],
  "features": {
    "harness_flag": true,
    "request_file": true,
    "status_json": true,
    "secret_private_http": true,
    "configure_requests": true,
    "inside_marker": false
  },
  "exit_codes": {
    "cancelled": 130,
    "required_grant": 3,
    "blocked": 4,
    "backend_unavailable": 5
  }
}
```

## Security invariants

These are contract requirements, not implementation suggestions:

| Assurance                         | Enforced behavior                                                                                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requests are not grants           | Pending, changed, or denied requests cannot widen the effective configuration and stop non-interactive launch with exit 3.                                                                              |
| Identity cannot be disguised      | Explicit harness declarations override inference, but a contradiction with a known executable is refused.                                                                                               |
| Repository input is untrusted     | A request manifest must be a guarded host file outside the checkout; symlinks, hard links, foreign ownership, and group/world writes are refused.                                                       |
| Secrets stay supervisor-side      | Status, errors, profiles, manifests, argv, and the sandbox never receive the secret value. Only the approved plain-HTTP host substitution sees it.                                                      |
| OPEN authority is named OPEN      | Private hosts, unrestricted network, full SSH, full GitHub credentials, and inherited host environment are reported under `grants.open`; interactive onboarding requires the final `OPEN` confirmation. |
| Saved approval is exact           | Requester, kind, normalized value, host, port, and writable mode are compared. Any change is pending again.                                                                                             |
| Read-only means read-only         | `status --json` never prompts, migrates, or saves policy.                                                                                                                                               |
| Unsupported assurance is explicit | `features.inside_marker` remains false until every supported backend can provide the documented guarantee.                                                                                              |

`tests/wrapper_contract.rs` exercises the process-level contract, including
non-disclosure and unsafe manifest paths. Unit tests in `src/integration.rs`
pin normalization, exact approval matching, OPEN classification, hostile text
rejection, and the required documentation disclosures.

`inside_marker` is false because Linux bind mounts and macOS `sandbox-exec`
cannot provide the same unspoofable marker contract. Wrappers must not infer a
stronger guarantee from the hostname, prompt, or an environment variable.

## Declare harness identity

Pass `--harness NAME` before `--`. It is repeatable because a wrapper may run
several harnesses in one jail:

```console
ai-jail --harness claude --harness codex -- \
  ai-memory run --some-future-flag x claude
```

The declaration selects onboarding, model API destinations, login-state
mounts, and API-key names. Unknown wrapper arguments no longer affect harness
selection. ai-jail rejects unknown harness names and rejects a declaration
that contradicts a known direct executable or wrapper `--executable` value.
Without `--harness`, the legacy argv inference remains available.

## Request manifest

`--request-file PATH` accepts schema version 1 JSON. The path must be absolute,
outside the canonical project checkout, user-owned, non-hard-linked, not a
symlink, and not group/world writable. These checks prevent a repository from
turning a checked-in file into trusted host input.

```json
{
  "version": 1,
  "requester": "ai-memory",
  "requests": [
    {
      "kind": "private_host",
      "value": "192.168.0.90:49374",
      "reason": "memory server for capture and recall"
    },
    {
      "kind": "host",
      "value": "api.anthropic.com",
      "reason": "model API"
    },
    {
      "kind": "env",
      "value": "AI_MEMORY_SERVER_URL",
      "reason": "where hooks send observations"
    },
    {
      "kind": "secret",
      "value": "AI_MEMORY_AUTH_TOKEN",
      "host": "192.168.0.90",
      "reason": "memory server login"
    },
    {
      "kind": "agent_state",
      "value": true,
      "reason": "harness login survives the jail"
    },
    {
      "kind": "map",
      "value": "/home/u/Projects/sibling",
      "writable": false,
      "reason": "user-picked folder"
    }
  ]
}
```

Host requests may include a port. Approval records that exact port, while the
current filtered proxy authorizes the named host on any requested TCP port;
the final access review states that consequence. A `map` value must be an
absolute path and still passes the normal credential-root and inode-identity
checks. Environment and secret values are never placed in the manifest or
saved profile.

`--request KIND=VALUE` is a repeatable convenience for simple requests. It is
identified as requester `command-line`; structured requests should use a
manifest so they can carry a reason, secret host, writable bit, or port.

On interactive onboarding or `configure`, each request is shown with its
requester, reason, and resource in the persistent staged-request review. Every
request begins undecided and needs an explicit APPROVE or REJECT decision.
Opening or revealing a request approves nothing. OPEN authority uses an
in-TUI confirmation dialog for that request and another confirmation dialog
before the chosen final action; Cancel is focused by default in both. The trusted
external project document stores the normalized request identity and requester
alongside the resulting grant. It does not store environment values.

See the [onboarding walkthrough](USER_GUIDE.md#wrapper-staged-requests) for the
user flow and [TUI design contract](TUI_DESIGN.md) for renderer invariants.

An existing profile applies only exact requests it previously approved. A new
or changed request exits with code 3 before the sandbox starts. Review it with:

```console
ai-jail configure --harness claude --request-file /secure/path/requests.json
```

## Read-only preflight

Use `status --json` before preparing wrapper-side work:

```console
ai-jail --harness claude --request-file /secure/path/requests.json \
  status --json -- ai-memory run claude
```

The result has `version`, `schema_version`, `project`, `harnesses`, `grants`
(`restricted`, `allowed`, and `open`), `requests` (`approved` and `pending`),
and `blockers`. Stable blocker codes include `onboarding_required`,
`required_grant_not_approved`, `missing_approved_env`, `directory_drift`,
`changed_ssh_key`, and `backend_unavailable`. Status is read-only and never
prompts.

## Private HTTP secrets

A `secret` request reuses phantom credentials. The sandbox receives a
placeholder, and the host proxy substitutes the current environment value only
for an absolute-form plain-HTTP request to the approved host. This also works
when that host is approved through `private_host`. The real value is not put in
the sandbox, manifest, profile, status JSON, logs, or command line.

The corresponding host request is still required. A private host is OPEN
because it can reach a named LAN/private-address service; loopback, link-local,
metadata, multicast, and unspecified addresses remain denied.

## Exit codes and persistence

Machine-facing exits are:

- `0`: query succeeded or child succeeded.
- `3`: a required wrapper request is refused, changed, or not approved.
- `4`: a saved approval is blocked by host drift, such as a missing approved
  environment variable, replaced directory, or changed SSH key.
- `5`: the platform sandbox backend is unavailable.
- `130`: the user cancelled onboarding.

Other configuration and launch failures remain exit 1. A launched child keeps
its own exit status.

`--no-save-config` suppresses profile and project-constraint auto-save. It does
not suppress the security migration of legacy `.ai-jail` files into the
trusted external store. `--dry-run` and read-only status do not migrate.

<!-- provenance: wrapper-contract-v1; implementation=src/integration.rs,src/cli.rs,src/main.rs; tests=tests/wrapper_contract.rs -->
