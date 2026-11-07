# ai-jail onboarding guide

The first run of a known harness opens one persistent terminal application for
reviewing project access. It stays on the alternate screen while you inspect
capabilities, choose directories and environment variables, configure selected
SSH keys, and decide wrapper requests. It does not interleave full-screen pages
with printed prompts.

The saved policy lives under `$XDG_CONFIG_HOME/ai-jail/projects` (normally
`~/.config/ai-jail/projects`), outside the checkout. The implementation
contract and minimum terminal behavior are in
[TUI_DESIGN.md](TUI_DESIGN.md).

The examples below preserve the labels, states, and action keys checked by the
renderer tests. Their line wrapping changes with terminal width.

Repository-scoped GitHub, GitLab, Codeberg/Forgejo, and Gitea credentials use
the separate [`ai-jail forge` guide](FORGE_AUTH.md). They are not configured by
the onboarding capability list.

## What the screen shows

The main screen has six parts:

- The header shows a bold `AI-JAIL` title, a compact project path, and the exact
  external profile path.
- The primary pane contains the capability list or editor. Checkboxes always
  show state in text, so color is never the only signal.
- The `Always enforced` pane lists protections that cannot be disabled here,
  including the platform sandbox. Focus it to read each guarantee in the
  context pane.
- The context pane describes the focused item: resource, access, process,
  duration, scope, limits, default, consequence, and, where applicable, remote
  service or authority.
- The read-only `CLI from defaults` pane shows the shortest shell-safe command
  for the current choices relative to ai-jail's built-in defaults. Press `y`
  anywhere on the main screen to copy it through the platform clipboard helper.
- The footer lists only keys that work on the current screen. Confirmation and
  validation messages appear there without leaving the application.

## Access presets

The first incomplete onboarding starts with `For developers` applied. It
enables the common access most developers need: the known harness's filtered
model API destination, host harness login/state, filtered dependency tooling,
and the active host GitHub token. Harness state also passes any detected,
well-known API-key variable for that harness; the details name the variable,
and its value is never displayed or saved. GitHub is explicitly marked OPEN:
the jail gets every permission carried by the active `gh` token, not only
access to the current repository. This preset does not enable unrestricted
network, SSH, loopback, arbitrary environment variables, or extra directories.
Saving this first-run preset opens a short Cancel-first dialog for the OPEN
GitHub grant. It names the token's full authority; confirming it saves directly
without adding a separate review page.

The top row provides three starting points:

- `Fully closed` removes every optional grant, including granular selections
  and wrapper approvals.
- `For developers` applies the first-run baseline described above. Its full
  GitHub-token grant is visibly marked OPEN in the access list.
- `Mostly open` enables unrestricted network, the full host GitHub token, the
  ambient SSH agent, and host loopback access. It is red, carries a warning,
  and requires an explicit in-TUI confirmation with Cancel focused by default.
  Its unrestricted network already reaches the model API, so no filtered host
  is saved alongside it.

`Tab` and `Shift-Tab` move focus between the access list, `Always enforced`
pane, and preset row. They skip the read-only CLI preview and never change a setting or start a
preview. In the preset row, Left/Right selects a preset and changes the
checklist to a clearly labeled `PREVIEW — not applied`. Press `Enter` or
`Space` to apply it; press `Tab`, `Down`, or `Esc` to leave without applying
it. Changing any granular option makes the active label `Custom`. Arbitrary
environment variables and extra directories are never guessed by a preset.
The sole environment exception is a detected, well-known harness API key
bundled with the explicitly visible harness-state grant.

Reopening a completed profile starts from its saved choices and does not
reapply the developer baseline. Noninteractive execution also remains
restricted; these presets are an interactive onboarding convenience.

At 96 columns or wider, the access list and its details sit side by side:

```text
AI-JAIL
Project  ../src/demo
Config   ~/.config/ai-jail/projects/demo.toml

┌ Presets • ←/→ preview • Enter/Space apply ───────────────┐
│   Fully closed    ✓ ⚠ For developers    ⚠ Mostly open   │
└──────────────────────────────────────────────────────────┘
┌ Access choices ───────────────────────────┐┌ Details — Filtered model API access ─┐
│▶ 1 ✓ Filtered model API access            ││Allows                                 │
│  2 ✓ Host harness login/state             ││claude and its children can connect    │
│  3 ✓ Dependency tools and download hosts  ││only to api.anthropic.com.              │
│  4 ○ Full host SSH access       ✓ CLOSED  ││                                       │
│  k ○ Selected SSH keys (fresh agent)      ││Still blocked                          │
│  5 ✓ Full host GitHub token       ! OPEN  ││Other hosts, private IPs, and localhost│
│  c ○ Host container engine      ✓ CLOSED  ││Risk: API can receive readable data.   │
│  6 ○ Network: unrestricted      ✓ CLOSED  ││                                       │
│  a • Additional capabilities              ││                                       │
├ Always enforced • Tab to inspect ─────────┤│                                       │
│  ◆ Bubblewrap sandbox                     ││                                       │
│  ◆ Approvals stored outside project       ││                                       │
└───────────────────────────────────────────┘└───────────────────────────────────────┘
↑/↓ move  •  Space/Enter select  •  Tab next panel  •  Esc/q exit

┌ CLI from defaults • y copy anywhere • 2 lines ─────────┐
│ai-jail --github --env GH_TOKEN claude                  │
│Config file (advanced): ~/.config/ai-jail/projects/...  │
└────────────────────────────────────────────────────────┘
```

On a narrower supported terminal, the same information is stacked. Nothing is
removed; the detail pane moves below the list and becomes scrollable.

```text
┌ Access choices ──────────────────────────────────────────┐
│▶ 1 [✓] Filtered model API access                         │
│  2 [✓] Host harness login/state                          │
│  3 [✓] Dependency tools and download hosts               │
└──────────────────────────────────────────────────────────┘
┌ Details — Filtered model API access • lines 1–6/9 ───────┐
│Allows                                                     │
│claude and its child processes can connect only to        │
│api.anthropic.com and subdomains.                         │
│Still blocked: other hosts, private IPs, and localhost.   │
└──────────────────────────────────────────────────────────┘
```

The minimum TUI size is 64 columns by 30 rows. Below that size, ai-jail asks
you to resize and retains working Back and Cancel actions. `NO_COLOR` removes
color while preserving text labels, borders, focus, and checkbox state.

## Capability review

Arrow keys move the highlighted row. `Home`, `End`, `PageUp`, and `PageDown`
navigate long lists and disclosures. `Space` or `Enter` opens the focused
choice. An `ALLOWED` grant toggles immediately after its disclosure is visible.
A disabled broad grant says `CLOSED`; selecting it opens a confirmation dialog
with Cancel focused by default. No TUI action asks you to type `OPEN` or answer
y/n.

Main-screen details summarize every add/remove editor without opening it.
`Environment variables` lists approved names without reading or displaying
values. `Directory access` lists extra directories as `READ-ONLY` or
`READ/WRITE`. Selected-key SSH lists keys, destinations, and lifetime.
`Additional capabilities` lists each enabled item as `ALLOWED` or `OPEN`. You
open those editors only when you want to add, remove, or change an entry.
Every configurable detail also includes `Use when`, with a concrete example of
why the authority may be needed. For example, Wayland display access is useful
when GUI applications must open so the harness can run, instrument, or debug
them. `Always enforced` details use `Why it matters` instead.

The CLI panel updates as choices change and is skipped by Tab navigation. It
omits options already equal to built-in defaults. Press `y` anywhere on the
main screen to copy it using `wl-copy`, `xclip`, or `xsel` on Linux and
`pbcopy` on macOS. It copies environment names, never their values. Existing
global or project policy can still affect the copied command. A note identifies
profile-only choices, such as selected-key SSH, that cannot be recreated
faithfully with launch flags. The full config path appears there as `Config
file (advanced)` for users who intentionally want to edit TOML directly;
`ai-jail configure HARNESS` remains the safer editor.

The broad compatibility choices remain clearly OPEN:

- Full host SSH shares `~/.ssh` and the ambient agent.
- Full host GitHub access shares the active host `gh` token.
- Host container-engine access controls the selected Docker or Podman daemon.
  It can mount host paths and is effectively the daemon owner's full authority.
- Unrestricted network removes hostname filtering and destination audit
  enforcement. Closing it does not necessarily mean offline: filtered model
  APIs, dependency registries, and manually approved hosts can remain
  reachable. `Fully closed` blocks every destination.
- On macOS, all-host-loopback access reaches every service and port on host
  loopback. Prefer `--forward-port PORT` when the port is known.

Opening a detail page never enables a capability. Disabling an existing choice
updates the checkbox immediately. `Esc` returns one level; `q` cancels setup
when focus is not inside a text field.

`Additional capabilities` keeps uncommon choices off the main checklist. It
contains broad host-home access, lockdown, host services and devices, cloud and
registry credential stores, full environment inheritance, worktree metadata,
Pictures, local audit logging, and platform-specific compatibility grants.
Only controls relevant to the current operating system are shown. No preset
enables anything on this screen; every OPEN item uses the same confirmation
dialog and remains visibly marked OPEN in the access summary.

Pressing `Space` or `Enter` toggles an ALLOWED choice immediately. An OPEN
choice uses the same dialog everywhere:

```text
┌ Open this boundary? ─────────────────────────────────────┐
│ This removes an important isolation boundary.           │
│                                                         │
│  [ Cancel ]       [ Enable OPEN access ]                 │
│                                                         │
│ ←/→ or Tab choose  •  Enter select  •  Esc cancel       │
└─────────────────────────────────────────────────────────┘
```

The list then changes from green `✓ CLOSED` to red `! OPEN`. Color reinforces
the meaning; the symbol and text remain authoritative in monochrome terminals.

## Directory browser

Choose `r` for read-only access or `w` for read/write access. The browser
starts at the canonical project parent (or the last directory visited), not at
a credential directory.

```text
Directory access  READ-ONLY
Location: /home/alice/Documents
Filter: ref  •  hidden: hidden

┌ Directories ───────────────────────┐┌ Security preview ───────────────────┐
│> dir  reference                    ││Selected path                        │
│  dir  reports                      ││/home/alice/Documents/reference      │
│  dir  research                     ││                                    │
│                                    ││Space reviews it for READ-ONLY access│
└────────────────────────────────────┘└─────────────────────────────────────┘
↑/↓ browse  •  Enter open  •  Space review  •  / filter  •  ↓ results
Type to refine  •  g go to path  •  . hidden  •  m mode  •  Esc back
```

On a narrow terminal, the directory list appears above the same scrollable
security preview:

```text
┌ Directories ─────────────────────────────────────────────┐
│> dir  reference                                         │
└──────────────────────────────────────────────────────────┘
┌ Security preview • lines 1–5/12 • PgUp/PgDn ─────────────┐
│Selected path                                             │
│/home/alice/Documents/reference                           │
└──────────────────────────────────────────────────────────┘
```

`m` changes the proposed mode before approval. The preview shows both the path
as entered and its resolved canonical destination. Press `Space` to add the
highlighted directory. Ordinary narrow grants need no additional y/n prompt.
A broad home or project-ancestor grant still requires reviewing the complete
disclosure and selecting the OPEN action in the shared dialog.

While filtering, press `Down` to move directly into the matching directories;
the first match is highlighted. If you start typing again while browsing those
results, focus returns to the filter and the new text is appended. `Enter` is
only needed to open the highlighted directory, not to leave the filter.

After the first selection, a `Selected directories` pane appears below the
browser. Press `Tab` to move between panes. In the lower pane, highlight a
grant and press `Space` to remove it immediately; when the final grant is
removed, the pane closes and focus returns to the browser. Press `m` on a
selected grant to toggle it between read-only and read/write. Expanding a broad
grant to read/write still requires the explicit OPEN dialog choice.

The chooser refuses filesystem root, credential roots such as `~/.ssh`, host
`gh` configuration, and the ai-jail policy store. It also refuses unsafe
symlinks, invalid UTF-8, and overlapping grants. Saved grants record filesystem
identity, so a moved, replaced, or missing target fails closed on the next
launch.

## Environment variables

The environment editor is a searchable multi-select list of names. Values are
never loaded for rendering, displayed, logged, or written to the project
profile.

```text
Environment variables
Names only; values are hidden and never saved.
Search: CUSTOM█

┌ Variable names ───────────────────┐┌ Security details ────────────────────┐
│> ○ CUSTOM_MODE                    ││CUSTOM_MODE                           │
│  ✓ CUSTOM_CACHE                   ││Every jailed descendant can read and │
│                                   ││copy the current host value.          │
└───────────────────────────────────┘└──────────────────────────────────────┘
↑/↓ move  •  Space/Enter review or remove  •  / search  •  ↓ results
Esc clears search or returns  •  values never appear in this screen
```

Press `Down` from the search field to focus the matching names immediately.
Typing again while the results are focused returns to the search field and
continues the current query; `Enter` is not required to switch focus.

At narrow widths, the variable list is stacked above `Security details`. The
checked names and the complete scroll position remain visible; values still do
not enter the display model.

```text
┌ Variable names ──────────────────────────────────────────┐
│> ○ CUSTOM_MODE                                           │
│  ✓ CUSTOM_CACHE                                          │
└──────────────────────────────────────────────────────────┘
┌ Security details • lines 1–4/8 • PgUp/PgDn ──────────────┐
│CUSTOM_MODE                                               │
│Every jailed descendant can read and copy an approved     │
│value.                                                     │
└──────────────────────────────────────────────────────────┘
```

Approving a new non-baseline name shows its complete disclosure, then the
shared dialog because a variable's authority cannot be established from its
name. Existing approvals are checked;
pressing `Space` or `Enter` on one removes it from the draft. ai-jail stores
only an approved name and reads its current host value for each launch. If the
name is missing later, launch fails closed until you restore it or remove the
approval with `configure`.

## Selected-key SSH

Choose `k` to configure selected-key SSH. This uses a fresh agent for each
launch and does not share private key files or the ambient host agent. ai-jail
discovers regular, non-symlinked file-backed identities and displays only safe
metadata: public path, SHA-256 fingerprint, and comment.

Wide terminals use separate identity, selection, destination, and security
panes. Narrow terminals stack the same panes vertically.

```text
Selected SSH keys — fresh agent
READY — selected-key SSH is destination constrained

┌ Available public identities ─────┐┌ Selected • lifetime 3600s (+/-) ─────┐
│> [x] ~/.ssh/id_ed25519.pub        ││ [x] SHA256:EXAMPLE  alice@example     │
│    SHA256:EXAMPLE alice@example   │└───────────────────────────────────────┘
└───────────────────────────────────┘┌ Required destinations ────────────────┐
                                    │> git@github.com                       │
                                    └───────────────────────────────────────┘
┌ Security detail • lines 1–8/10 ───────────────────────────────────────────┐
│Private-key boundary: private keys never enter the jail                    │
│Destinations: enforced and host-key verified                              │
│Network prerequisite: unrestricted network is separately OPEN             │
└───────────────────────────────────────────────────────────────────────────┘
Tab changes pane  •  arrows move  •  Space selects/removes
p path  •  a add destination  •  e edit  •  Del remove  •  +/- lifetime
```

The narrow layout keeps the same four zones in order: available identities,
selected identities, required destinations, and security detail. `Tab` moves
between the first three panes; `PageUp` and `PageDown` scroll the disclosure.

```text
INCOMPLETE — launch and save are blocked

┌ Available public identities ─────────────────────────────┐
│> [ ] ~/.ssh/id_ed25519.pub                               │
│    SHA256:EXAMPLE  alice@example                         │
└──────────────────────────────────────────────────────────┘
┌ Selected • lifetime 3600s (+/-) ─────────────────────────┐
│                                                          │
└──────────────────────────────────────────────────────────┘
┌ Required destinations ───────────────────────────────────┐
│                                                          │
└──────────────────────────────────────────────────────────┘
┌ Security detail • lines 1–4/10 • PgUp/PgDn ──────────────┐
│Selected-key SSH access (ALLOWED)                          │
└──────────────────────────────────────────────────────────┘
```

`Space` selects or removes an identity immediately; there is no second y/n
prompt. Its authority remains visible in the security-detail pane. Destination
edits are validated in place. Save and launch remain unavailable
until at least one identity and one enforced destination are present. ai-jail
accepts a destination limit only when OpenSSH supports `ssh-add -h/-H` and a
matching verified host key exists. Missing support, a missing host key, an
unconstrained policy, or identity drift refuses the launch.

Native SSH does not pass through ai-jail's HTTP CONNECT proxy. Selected-key SSH
therefore also requires a separately reviewed Unrestricted network grant,
classified OPEN. This opens reachability without adding identities to the fresh
agent. Git uses the generated strict configuration. For direct SSH on Linux or
macOS, use the launch-scoped variables:

```sh
"$AI_JAIL_SSH" -F "$AI_JAIL_SSH_CONFIG" git@github.com
```

Plain `ssh` does not promise the selected-key restrictions. The temporary agent
is killed and its generated public files are removed on normal exit, launch
failure, and handled termination. `SIGKILL` cannot guarantee immediate
cleanup; the configured `ssh-add` lifetime bounds use of keys left in a
surviving temporary agent.

## Wrapper-staged requests

Wrappers such as ai-memory can stage access through the
[wrapper integration contract](WRAPPER_INTEGRATION.md). Wrapper requests enter
a separate review before the normal capability list. They are proposals, not
authority.

```text
Wrapper-staged access requests
APPROVE proposes the fully disclosed access; REJECT keeps it absent.

┌ Requests ───────────────────────────┐┌ Complete disclosure ───────────────┐
│>[UNDECIDED] host memory.example     ││Requested by: ai-memory             │
│ [REJECT   ] env AI_MEMORY_SERVER_URL││Resource: host memory.example       │
│ [APPROVE  ] agent_state true        ││Reason: memory capture and recall   │
└─────────────────────────────────────┘└────────────────────────────────────┘
a validate/approve  •  r reject  •  ↑/↓ move  •  PgUp/PgDn disclosure
```

At narrow widths, `Requests` is stacked above `Complete disclosure`. The
decision label remains attached to every request, and the disclosure title
keeps its visible line range.

Every request needs an explicit APPROVE or REJECT decision. Approval first
loads the complete disclosure. Both `ALLOWED` and `OPEN` approval use the
shared dialog, with Cancel focused by default. Previously approved wrapper-derived access is
removed from the draft and reviewed again when requested. Revealing a
disclosure or opening this screen approves nothing. If any request remains
undecided, Enter does not continue.

## Saving and leaving

Select `Save configuration` or press `s` to save the choices shown in the
access screen. During first-run onboarding, saving continues into the harness.
`ai-jail configure HARNESS` saves and exits without launching it. After the TUI
closes, ai-jail prints a short confirmation with the exact external config path
for later inspection.

### Leaving with unsaved changes

On the access overview, `Esc` and `q` both request exit. If the draft still
matches the loaded profile, setup closes without writing anything. If choices
changed—or a first-run preset has not been saved—a dialog keeps the consequence
explicit:

```text
┌ Unsaved changes ───────────────────────────────────────────────────────┐
│ Your access changes have not been saved.                              │
│ Save them, discard them, or keep editing.                             │
│                                                                       │
│ [ Keep editing ]  [ Discard & quit ]  [ Save changes ]                │
└───────────────────────────────────────────────────────────────────────┘
```

`Keep editing` is selected by default, and `Esc` in this dialog also keeps the
draft open. `Discard & quit` is the only choice that intentionally throws the
draft away. `Save changes` persists the profile directly and does not launch a
jail. While editing a nested picker, `Esc` first closes input or returns to the
access overview; it does not mistake ordinary navigation for an exit request.

## Plain-terminal and noninteractive behavior

`TERM=dumb` uses a sequential text fallback instead of the alternate-screen
TUI. It covers the same decisions and security disclosures, and prints no
internal provenance identifiers. The fallback is intended for real terminals
that cannot support cursor addressing; it is not mixed into a Ratatui session.

When no terminal is attached, a first run starts once with restricted defaults
and saves no profile. Noninteractive `ai-jail configure HARNESS` exits without
changing configuration. Automation should pass every intended grant and
restriction explicitly on each launch. Pending required wrapper requests fail
with their distinct noninteractive exit code instead of becoming authority.

## Linked worktrees

By default the saved policy is keyed by the canonical path of the directory
where you launch, so every linked Git worktree of one repository is onboarded
separately. The trusted global setting `project_strategy = "repo-root"` makes a
linked worktree use its main repository's saved policy instead:

```toml
# ~/.config/ai-jail/config.toml
project_strategy = "repo-root"
```

When the setting applies, the header of the configure screen and of the
plain-terminal fallback adds a `Policy` line that names the shared root and
says it is shared with its linked worktrees. The line is absent when the policy
belongs to the launch directory itself. The mounted project stays the launch
directory; only the saved approval, identity, onboarding state, forge bindings,
and directory grants are shared.

- Only the root of a linked worktree resolves to the main repository.
  Subdirectories of a worktree or of the main checkout keep their own policy.
- ai-jail validates the worktree's repository metadata structurally. Metadata
  it refuses falls back to the launch directory's own policy with a warning.
- A main checkout that is missing on disk also falls back to the launch
  directory's own policy with a warning.
- A worktree of a bare repository keeps the launch directory's own policy
  silently, because that is a normal layout and prints no warning. No fallback
  widens access: each uses a policy that already belonged to that directory.
- A store that sits inside the launch directory or the main checkout is
  refused.
- When a launch directory also has a saved policy of its own, the one the
  default strategy would use, ai-jail prints one warning each time it runs
  there:
  `project_strategy = repo-root: using the policy of <root>; the saved policy
  for <launch dir> is ignored`. Restrictions saved only in that per-directory
  policy no longer apply there.
- Every checkout adds to the shared document's restrictions. The automatic
  save at launch and `--init` merge the restrictions they capture into the
  document instead of replacing them, so a launch in one checkout cannot drop
  a restriction saved from another. The trade-off: under `repo-root`,
  re-running `--init` cannot remove a saved restriction. To remove one, edit
  the shared document under `$XDG_CONFIG_HOME/ai-jail/projects/`, or delete
  it and onboard again.
- Absolute paths in a restriction stay as saved and name the checkout they
  were saved from. A map such as `ro_maps = ["/src/repo/vendor"]` applies only
  in the launch directory that contains it; other checkouts skip it with a
  warning. Relative entries, such as masks and maps imported from a legacy
  file, resolve against each launch directory.
- A legacy repository `.ai-jail` found in a worktree contributes restrictions
  to the shared document. Its relative paths stay relative and resolve against
  each launch directory; only its absolute paths are tied to one checkout.
- Forge bindings and credentials are shared by every worktree of the
  repository, so authorizing one worktree authorizes all of them.
- Forge entries saved for a single worktree before you enable `repo-root` are
  no longer reachable from that worktree. Remove them with
  `ai-jail forge remove` in that worktree before you enable the setting, or
  delete them from the store.
- `status --json` reports the policy location as `project.policy_path`.

The setting is global only. A repository file cannot enable it.

## Migration and reapproval

Legacy repository `.ai-jail` files contribute restrictions only. Commands,
outside maps, SSH, GitHub credentials, network access, and other grants are not
imported. A migrated broad request remains disabled until it is selected and
approved again. A legacy `~/.ai-jail` is migrated separately to
`$XDG_CONFIG_HOME/ai-jail/config.toml` after the external copy is written,
parsed, and verified.

When ai-jail finishes, its migration notices name the external destination and
list requests that need reapproval. If the source was tracked, its deletion
appears in `git status`; ai-jail does not edit the Git index. Restoring the
repository file does not override an existing external project profile.

## Documentation drift controls

The screen sketches above are curated walkthroughs, not byte-for-byte terminal
captures. Raw Ratatui output contains cursor movement, resize-dependent
wrapping, and redraw sequences that are unsuitable as user documentation.
Internal provenance IDs remain in
[`onboarding-provenance.toml`](onboarding-provenance.toml), where each security
claim maps to implementation and executable tests. Renderer tests cover wide,
narrow, `NO_COLOR`, minimum-size, disclosure-scroll, and terminal-restoration
behavior.
