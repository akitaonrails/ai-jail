# ai-jail onboarding guide

`ai-jail` reviews host access the first time a known harness runs in a
project. The saved policy lives under `~/.config/ai-jail/projects`, outside
the checkout. Repository files cannot add grants.

Repository-scoped GitHub, GitLab, Codeberg/Forgejo, and Gitea credentials use
the separate [`ai-jail forge` step-by-step guide](FORGE_AUTH.md). It includes
complete simulated prompts, provider account setup, scope/lifetime labels,
rotation, removal, and the distinction from the legacy OPEN `--github` option.

## Message contract

The following block is rendered from the same message catalog as the CLI and
checked byte-for-byte by the test suite.

```text
AJ-ONB-001 Configure a known harness for one canonical project.
AJ-CHOICE-001 Every selection is off until the user enables it.
AJ-GRANT-001 Every active grant names resource, access, process, duration, scope, limits, default, and consequence.
AJ-OPEN-001 Broad access requires typing OPEN.
AJ-SUM-001 Final output always contains RESTRICTED, ALLOWED, and OPEN.
AJ-SAVE-001 Saved policy lives outside the project.
AJ-CANCEL-001 Cancel writes no onboarding grants and starts nothing.
AJ-NONTTY-001 Non-TTY first runs save no onboarding profile.
AJ-NONTTY-002 Non-TTY configure changes nothing.
AJ-FINAL-001 Complete effective access includes every contributing policy layer.
AJ-PATH-001 Unsafe directory syntax is refused.
AJ-PATH-002 Credential roots require their dedicated access choice.
AJ-PATH-003 Saved directory grants require identity records.
AJ-PATH-004 Directory identity drift refuses access.
AJ-ENV-001 Environment approvals store names only.
AJ-ENV-002 Missing approved host variables fail closed.
AJ-SSH-001 Selected-key SSH never shares private key files or the host agent.
AJ-SSH-002 SSH destination limits are claimed only after host-key verification.
AJ-SSH-003 A moved or changed selected key refuses launch.
AJ-SSH-004 Selected-key SSH requires a separately approved Unrestricted network (OPEN) grant.
```

## Secure default

```text
$ ai-jail claude

Configure claude for this project
Project: /home/alice/src/demo

AJ-ONB-001 ai-jail stores this approval outside the project. Files in this
repository cannot add access on their own.

AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [ ] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

Press Space
AJ-GRANT-001 Enable this grant? [y/N] y

Press s

AJ-SUM-001 Final access for claude

[LOCK] RESTRICTED
  SSH       No key files, host agent socket, or SSH configuration
  GitHub    No host gh configuration or token
  Host home See the complete effective access below
  Network   Every destination except the named API/dependency hosts

[WARN] ALLOWED
  /home/alice/src/demo: read and write for claude and its child processes
  api.anthropic.com: filtered TCP access while this jail runs

[ERROR] OPEN
  None

Save and launch [s], launch once [o], back [b], cancel [q]: s
[OK] AJ-SAVE-001 Configuration saved
```

The live summary expands every `ALLOWED` entry into Resource, Access,
Process, Duration, Scope, Limits, Default, and Consequence fields. Network and
credential entries also show Remote or Authority where applicable.

The confirmation screen then shows the complete effective policy after global
settings, the proposed project grants, command-line flags, project
restrictions, and platform defaults are combined. This fixture is rendered by
the same code and checked byte-for-byte:

```text
AJ-FINAL-001 Complete effective access
Recipient: claude and every child process it starts inside this jail
Duration: While each jail runs; approval remains saved for this project
Project: /home/alice/src/demo (read and write)
Scope: global policy, proposed project grants, command-line grants, project constraints, and derived platform defaults
Effective policy (every nondefault field):
command = ["claude"]
github = false
no_mise = true
no_toolchains = true
ssh = false
allow_hosts = ["api.anthropic.com"]
agent_state = false
Built-in environment names: PATH, HOME, TERM, LANG, SHELL, TMPDIR, COLORTERM, SSL_CERT_FILE, SSL_CERT_DIR, http_proxy, https_proxy, no_proxy, HTTP_PROXY, HTTPS_PROXY, NO_PROXY; prefixes: LC_, XDG_, TERM_PROGRAM
Authority details (resource; access; scope/limits; consequence):
- [WARN] ALLOWED: private persistent jail home; read and write; this harness profile only; state persists across launches
- [WARN] ALLOWED: public hosts api.anthropic.com; filtered TCP connections; named hosts and subdomains with private/loopback resolution blocked; services can receive readable jail data
Environment names: none beyond the built-in safe allowlist
User-approved host environment names: none
Limits: mandatory masks, platform support, and monotonic project restrictions still apply
```

## Add and remove directories

```text
Press r
Directory (Tab completes; absolute path or ~/...): ~/Documents/reference
Entered:  ~/Documents/reference
Resolved: /home/alice/Documents/reference

Resource:    /home/alice/Documents/reference
Access:      Read the complete directory tree; writes are denied
Process:     claude and every child process it starts inside this jail
Duration:    This jail run; saving keeps approval for later runs, while launch once does not
Scope:       This resolved directory tree only
Limits:      Contents can be copied into the project or sent to an allowed network destination
Default:     Not shared
Consequence: The harness can inspect these host files but cannot modify them through this grant

Add this directory? [y/N] y
```

Use `w` for read/write access and `d` to remove a saved entry. Completion
reads the filesystem directly; it never invokes a shell or expands variables
or globs. Credential roots such as `~/.ssh`, host `gh` configuration, and the
ai-jail policy store are refused. The filesystem root is also refused because
the sandbox cannot enforce it as an extra map. Sharing the whole home
directory or a broad project ancestor requires typing `OPEN`.

## Environment variables

The safe baseline names shown in the complete summary are available without
extra approval. Other host variables start off. Press `e` to filter the
current host variable names. ai-jail never displays or saves their values.
It stores an approved name and reads its current value again for each launch.
Every non-baseline host variable requires `OPEN` because a harmless-looking
name can still carry sensitive authority. If a saved name is missing later, the
launch stops and tells you to restore it or remove it with `configure`.

This name-only fixture is generated from the same grant renderer:

```text
AJ-ENV-001 Environment names only. Type to filter; arrows move; Space/Enter selects for approval; q/Esc returns. Values are never shown.
  Filter: CUSTOM
  > [ ] CUSTOM_MODE

AJ-GRANT-001
Resource:    Host environment variable CUSTOM_MODE (value hidden)
Access:      Read and use the current host value; the value is never displayed or saved by ai-jail
Process:     claude and every child process it starts inside this jail
Duration:    This jail run; saving keeps approval for later runs, while launch once does not
Scope:       This exact variable name; the current value is read again for each launch
Limits:      Every jailed descendant can read and copy the value; allowed network access can carry it outside the jail
Default:     Arbitrary host variables are not shared; the documented safe baseline remains available
Consequence: The harness and every child process can use or disclose the current value
Authority:   The authority of an arbitrary host value cannot be verified from its name

AJ-OPEN-001 Host variable CUSTOM_MODE has unverifiable authority. Type OPEN to approve its name: OPEN
```

## Broad legacy access

```text
Press 5

AJ-OPEN-001 OPEN access removes an important boundary.

Resource:    The effective host gh configuration and active github.com token
Access:      Read configuration and use the token for GitHub API and Git HTTPS operations
Process:     claude and every child process it starts inside this jail
Duration:    This jail run; saving keeps approval for later runs, while launch once does not
Scope:       Every repository and organization allowed by the active host token
Limits:      Read-only configuration does not restrict use or copying of the token
Default:     Not shared
Consequence: Jailed processes can act with the host token's complete GitHub authority
Authority:   Every permission granted to the active github.com token

Type OPEN to enable this exact grant: OPEN
```

Full SSH, the full host GitHub token, and unrestricted network are legacy
compatibility modes. They are always listed under `OPEN`.

## Selected-key SSH

Press `k` to add or remove file-backed identities. ai-jail discovers only
regular, non-symlinked key pairs. It displays and saves the public SHA-256
fingerprint, comment, path, and file identity. It never saves or mounts private
key contents.

```text
AJ-SSH-TRANSCRIPT-BEGIN selected-key SSH interaction
AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: a
Available file-backed identities:
  1. /home/alice/.ssh/id_ed25519.pub  SHA256:EXAMPLE  alice@example
Key number, private-key path, or .pub path: 1

AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Selected identities:
  1. /home/alice/.ssh/id_ed25519.pub  SHA256:EXAMPLE  alice@example
Lifetime: 3600 seconds; destinations: not configured (launch and save are refused)
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: h
Required destinations, comma-separated: git@github.com

Resource:    Fresh SSH agent containing only SHA256:EXAMPLE
Access:      Request signatures; private key files and the ambient agent stay outside the jail
Duration:    Agent lives for this jail; loaded keys expire after 3600 seconds
Scope:       AJ-SSH-002 Only verified destination constraints: git@github.com
Limits:      Destination constraints depend on OpenSSH support and verified known_hosts entries; unrestricted network is separately OPEN; failure refuses launch
```

Choose `h` to add destination constraints. ai-jail copies only verified public
host-key lines into a generated `known_hosts` file and uses OpenSSH's
destination constraints. At least one destination is required. If `ssh-add`
lacks destination constraints or a destination has no matching verified host
key, launch and save stop. Host-key checking is always strict. ai-jail does not
describe `known_hosts` as a limit on raw agent signing authority; the enforced
boundary is OpenSSH's `ssh-add -h/-H` destination constraint.

Native SSH does not travel through ai-jail's HTTP(S) filtered-egress proxy.
Select `6 Unrestricted network` and type `OPEN` to use selected-key SSH. This
opens network reachability, not extra key authority; the fresh agent still
contains only the selected identities. Without this separate approval, launch
stops with `AJ-SSH-004`.

Git is forced to use the generated SSH config. For a direct command, use the
two launch-scoped variables exactly:

```sh
"$AI_JAIL_SSH" -F "$AI_JAIL_SSH_CONFIG" git@github.com
```

Running plain `ssh` does not promise these restrictions. The temporary agent is
killed and its generated public files are removed on normal exit or launch
failure. SIGINT, SIGTERM, and SIGHUP set launch cancellation before forwarding
to the supervised child; startup observes cancellation, reaps the temporary
agent, removes its runtime directory, and does not start the sandbox command.
Ambient `SSH_AUTH_SOCK`, `GIT_SSH`, and
`GIT_SSH_COMMAND` values are removed.
Identities that exist only in the ambient agent cannot be copied selectively;
use a file-backed key or choose the legacy full SSH mode with `OPEN`.

The following normalized PTY transcript is the executable onboarding fixture.
Only the temporary root and generated policy filename are replaced.

```text
AJ-SSH-TRANSCRIPT-BEGIN selected-key SSH interaction

AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: Available file-backed identities:
  1. <ROOT>/home/.ssh/id_test.pub  SHA256:EXAMPLE  alice@example
Key number, private-key path, or .pub path: AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [x] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Selected identities:
  1. <ROOT>/home/.ssh/id_test.pub  SHA256:EXAMPLE  alice@example
Lifetime: 3600 seconds; destinations: not configured (launch and save are refused)
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: Key number to remove: AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [ ] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: Available file-backed identities:
  1. <ROOT>/home/.ssh/id_test.pub  SHA256:EXAMPLE  alice@example
Key number, private-key path, or .pub path: AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [x] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-SSH-001 Selected-key SSH uses a fresh agent for this jail. Private key files and the host agent are not shared.
Selected identities:
  1. <ROOT>/home/.ssh/id_test.pub  SHA256:EXAMPLE  alice@example
Lifetime: 3600 seconds; destinations: not configured (launch and save are refused)
Add key [a], remove key [r], destinations [h], disable [d], back [Enter]: Required destinations, comma-separated: AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [x] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-OPEN-001 OPEN access removes an important boundary.

AJ-GRANT-001
Resource:    The host's reachable network
Access:      Connect using any protocol and destination permitted by the host
Process:     claude and every child process it starts inside this jail
Duration:    This jail run; saving keeps approval for later runs, while launch once does not
Scope:       Public, private, local-network, and other host-reachable services
Limits:      Hostname filtering and destination audit enforcement no longer apply
Default:     Filtered to explicitly allowed hosts
Consequence: Any readable jail data can be sent to any reachable service
Remote:      Any reachable service

AJ-OPEN-001 Type OPEN to enable this exact grant: AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [x] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [x] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-SUM-001 Final access for claude

[LOCK] RESTRICTED
  GitHub    No host gh configuration or token
  Host home See the complete effective access below
  Network   All destinations are blocked

[WARN] ALLOWED
AJ-GRANT-001
Resource:    <ROOT>/project
Access:      Read and write the complete directory tree
Process:     claude and every child process it starts inside this jail
Duration:    While each jail runs; approval remains saved for this project
Scope:       This canonical project path only
Limits:      Readable project data can be sent to an allowed network destination
Default:     Allowed because this is the working project
Consequence: The harness can inspect, create, modify, rename, and delete project files


AJ-GRANT-001
Resource:    Fresh SSH agent containing only SHA256:EXAMPLE
Access:      Request signatures; private key files and the ambient agent stay outside the jail
Process:     claude and every child process it starts inside this jail
Duration:    Agent lives for this jail; loaded keys expire after 3600 seconds; While each jail runs; approval remains saved for this project
Scope:       AJ-SSH-002 Only verified destination constraints: git@github.com
Limits:      Destination constraints depend on OpenSSH support and verified known_hosts entries; unrestricted network is separately OPEN; failure refuses launch
Default:     Disabled until keys are selected in trusted configuration
Consequence: The harness can authenticate as accounts accepted by the selected keys during this jail run
Remote:      git@github.com
Authority:   Only accounts accepted by the selected fingerprints


[ERROR] OPEN

AJ-GRANT-001
Resource:    The host's reachable network
Access:      Connect using any protocol and destination permitted by the host
Process:     claude and every child process it starts inside this jail
Duration:    While each jail runs; approval remains saved for this project
Scope:       Public, private, local-network, and other host-reachable services
Limits:      Hostname filtering and destination audit enforcement no longer apply
Default:     Filtered to explicitly allowed hosts
Consequence: Any readable jail data can be sent to any reachable service
Remote:      Any reachable service


AJ-FINAL-001 Complete effective access
Recipient: claude and every child process it starts inside this jail
Duration: This jail run; saving keeps approval for later runs, while launch once does not
Project: <ROOT>/project (read and write)
Scope: global policy, proposed project grants, command-line grants, project constraints, and derived platform defaults
Effective policy (every nondefault field):
command = ["claude"]
rw_maps = ["<SSH-RUNTIME>/agent.sock:/tmp/ai-jail-ssh-agent.sock"]
ro_maps = ["<SSH-RUNTIME>/public:/tmp/ai-jail-ssh-public"]
github = false
network = true
no_mise = true
no_toolchains = true
ssh = false
agent_state = false
Built-in environment names: PATH, HOME, TERM, LANG, SHELL, TMPDIR, COLORTERM, SSL_CERT_FILE, SSL_CERT_DIR, http_proxy, https_proxy, no_proxy, HTTP_PROXY, HTTPS_PROXY, NO_PROXY; prefixes: LC_, XDG_, TERM_PROGRAM
Authority details (resource; access; scope/limits; consequence):
- [ERROR] OPEN: host network; unrestricted connections; every host-reachable destination and protocol; readable jail data can reach any service
- [WARN] ALLOWED: launch-scoped selected-key SSH agent; request signatures without reading private keys or the ambient agent; selected identities and saved destination constraints; accepted accounts can be used during this jail run
- [WARN] ALLOWED: private persistent jail home; read and write; this harness profile only; state persists across launches
- [WARN] ALLOWED: read-only map <SSH-RUNTIME>/public:/tmp/ai-jail-ssh-public; mapped tree access; exact encoded source/destination; readable data can leave through allowed network access
- [WARN] ALLOWED: read/write map <SSH-RUNTIME>/agent.sock:/tmp/ai-jail-ssh-agent.sock; mapped tree access; exact encoded source/destination; readable data can leave through allowed network access
Environment names: AI_JAIL_SSH, AI_JAIL_SSH_CONFIG, GIT_SSH_COMMAND, SSH_AUTH_SOCK
- [WARN] ALLOWED: generated launch-scoped SSH variable AI_JAIL_SSH; points only to the dedicated agent or generated strict SSH configuration; jailed descendants can use the selected-key authority
- [WARN] ALLOWED: generated launch-scoped SSH variable AI_JAIL_SSH_CONFIG; points only to the dedicated agent or generated strict SSH configuration; jailed descendants can use the selected-key authority
- [WARN] ALLOWED: generated launch-scoped SSH variable GIT_SSH_COMMAND; points only to the dedicated agent or generated strict SSH configuration; jailed descendants can use the selected-key authority
- [WARN] ALLOWED: generated launch-scoped SSH variable SSH_AUTH_SOCK; points only to the dedicated agent or generated strict SSH configuration; jailed descendants can use the selected-key authority
User-approved host environment names: none
Limits: mandatory masks, platform support, and monotonic project restrictions still apply
AJ-OPEN-001 Complete effective access contains OPEN authority. Type OPEN to continue: AJ-SAVE-001 Save this project profile? [y/N/b] [OK] AJ-SAVE-001 Configuration saved
  Project policy: <ROOT>/xdg/ai-jail/projects/<POLICY>.toml
  The project cannot edit or enable this policy from inside the jail.
AJ-SSH-TRANSCRIPT-END selected-key SSH interaction
```

## Migration and reapproval

```text
✓ AJ-MIG-002 IMPORTED RESTRICTIONS to ~/.config/ai-jail/projects/PROJECT.toml.
⚠ AJ-MIG-003 REAPPROVAL REQUIRED; these access requests were NOT IMPORTED:
full host SSH access, full host GitHub credentials, read/write host paths.

AJ-CHOICE-001 Access choices
  4 [ ] Full host SSH access                 OPEN
  k [ ] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
```

Migration imports repository restrictions, not grants. A migrated broad
request remains off until it is selected and confirmed again. After the child
exits, ai-jail reports the external policy path and whether the legacy file
was removed. If the old file was tracked, review `git status`; restoring it
does not grant access.

## Automation and non-interactive runs

```text
$ ai-jail claude </dev/null
[WARN] AJ-NONTTY-001 Interactive setup skipped because no terminal is attached.
  Running once with restricted defaults; no profile was saved.
  Use `ai-jail configure claude` in a terminal to review or save access.

$ ai-jail configure claude </dev/null
[ERROR] AJ-NONTTY-002 `ai-jail configure claude` needs an interactive terminal.
  No configuration was changed.
```

Automation should pass every intended grant or restriction explicitly on each
launch. A non-interactive first run never imports pending grants, prompts, or
saves a profile.

## Verified keyboard transcript

The PTY integration test produces this normalized transcript and compares it
byte-for-byte before the guide can pass CI.

```text
1y
sy

Configure claude for this project

Project: <ROOT>/project

AJ-ONB-001 ai-jail stores this approval outside the project. Files in this repository cannot add access on their own.

AJ-CHOICE-001 Access choices
  1 [ ] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [ ] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-GRANT-001
Resource:    TCP connections to api.anthropic.com and their subdomains
Access:      Connect to any requested TCP port through the filtered proxy
Process:     claude and every child process it starts inside this jail
Duration:    This jail run; saving keeps approval for later runs, while launch once does not
Scope:       Public addresses for this hostname; private and loopback addresses stay blocked
Limits:      TLS contents are opaque; allowed endpoints can receive readable jail data
Default:     Allowed as the harness's functional API destination
Consequence: The harness can send prompts and readable data to this API
Remote:      Services operating under api.anthropic.com

AJ-GRANT-001 Enable this grant? [y/N] AJ-CHOICE-001 Access choices
  1 [x] Filtered model API access
  2 [ ] Host harness login/state
  3 [ ] Dependency tools and download hosts
  4 [ ] Full host SSH access                 OPEN
  k [ ] Selected SSH keys (fresh agent)
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  7 [ ] All host loopback services          OPEN (macOS)
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Repository-scoped forge access is configured separately.

[OK] Arrow keys move. Space or Enter selects. q cancels. Esc goes back.
[OK] Selected: filtered model API

AJ-SUM-001 Final access for claude

[LOCK] RESTRICTED
  SSH       No key files, host agent socket, or SSH configuration
  GitHub    No host gh configuration or token
  Host home See the complete effective access below
  Network   Every destination except the named API/dependency hosts

[WARN] ALLOWED
AJ-GRANT-001
Resource:    <ROOT>/project
Access:      Read and write the complete directory tree
Process:     claude and every child process it starts inside this jail
Duration:    While each jail runs; approval remains saved for this project
Scope:       This canonical project path only
Limits:      Readable project data can be sent to an allowed network destination
Default:     Allowed because this is the working project
Consequence: The harness can inspect, create, modify, rename, and delete project files


AJ-GRANT-001
Resource:    TCP connections to api.anthropic.com and their subdomains
Access:      Connect to any requested TCP port through the filtered proxy
Process:     claude and every child process it starts inside this jail
Duration:    While each jail runs; approval remains saved for this project
Scope:       Public addresses for this hostname; private and loopback addresses stay blocked
Limits:      TLS contents are opaque; allowed endpoints can receive readable jail data
Default:     Allowed as the harness's functional API destination
Consequence: The harness can send prompts and readable data to this API
Remote:      Services operating under api.anthropic.com


[ERROR] OPEN
  None

AJ-FINAL-001 Complete effective access
Recipient: claude and every child process it starts inside this jail
Duration: This jail run; saving keeps approval for later runs, while launch once does not
Project: <ROOT>/project (read and write)
Scope: global policy, proposed project grants, command-line grants, project constraints, and derived platform defaults
Effective policy (every nondefault field):
command = ["claude"]
github = false
no_mise = true
no_toolchains = true
ssh = false
allow_hosts = ["api.anthropic.com"]
agent_state = false
Built-in environment names: PATH, HOME, TERM, LANG, SHELL, TMPDIR, COLORTERM, SSL_CERT_FILE, SSL_CERT_DIR, http_proxy, https_proxy, no_proxy, HTTP_PROXY, HTTPS_PROXY, NO_PROXY; prefixes: LC_, XDG_, TERM_PROGRAM
Authority details (resource; access; scope/limits; consequence):
- [WARN] ALLOWED: private persistent jail home; read and write; this harness profile only; state persists across launches
- [WARN] ALLOWED: public hosts api.anthropic.com; filtered TCP connections; named hosts and subdomains with private/loopback resolution blocked; services can receive readable jail data
Environment names: none beyond the built-in safe allowlist
User-approved host environment names: none
Limits: mandatory masks, platform support, and monotonic project restrictions still apply
AJ-SAVE-001 Save this project profile? [y/N/b] [OK] AJ-SAVE-001 Configuration saved
  Project policy: <ROOT>/xdg/ai-jail/projects/<POLICY>.toml
  The project cannot edit or enable this policy from inside the jail.
```
# Dynamic localhost services on macOS

<!-- provenance: src/onboarding.rs open_grant("loopback-connect"), render_menu; src/sandbox/seatbelt.rs push_network_section -->

Use a fixed `--forward-port PORT` whenever you know the port. If a macOS tool
uses unpredictable localhost ports, interactive setup offers:

```text
  7 [ ] All host loopback services          OPEN (macOS)
```

Selecting it shows that **ALL host loopback services on every port** become
reachable. To enable and save it, type the exact word `OPEN`; `open`, `yes`,
or pressing Enter leaves it disabled. The final access review labels the grant
OPEN again before saving. `--lockdown` disables it. On Linux the setting is
accepted for shared configuration but has no effect.
