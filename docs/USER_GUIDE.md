# ai-jail onboarding guide

`ai-jail` reviews host access the first time a known harness runs in a
project. The saved policy lives under `~/.config/ai-jail/projects`, outside
the checkout. Repository files cannot add grants.

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
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
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
compatibility modes. They are always listed under `OPEN`. Restricted SSH and
repository-scoped GitHub App choices appear only after their enforcement is
available; the current editor does not claim they exist.

## Migration and reapproval

```text
✓ AJ-MIG-002 IMPORTED RESTRICTIONS to ~/.config/ai-jail/projects/PROJECT.toml.
⚠ AJ-MIG-003 REAPPROVAL REQUIRED; these access requests were NOT IMPORTED:
full host SSH access, full host GitHub credentials, read/write host paths.

AJ-CHOICE-001 Access choices
  4 [ ] Full host SSH access                 OPEN
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
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Scoped SSH and repository GitHub access are not available yet.

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
  5 [ ] Full host GitHub token              OPEN
  6 [ ] Unrestricted network                OPEN
  r Add read-only directory   w Add read/write directory
  e Environment variables (names only; values stay hidden)
  d Remove directory          s Review summary   q Cancel
  Scoped SSH and repository GitHub access are not available yet.

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
