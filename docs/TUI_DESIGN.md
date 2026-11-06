# Onboarding TUI design contract

<!-- provenance: onboarding-tui-v1; implementation=src/onboarding.rs,src/onboarding/tui/; tests=tests/onboarding.rs -->

The onboarding interface is one persistent terminal application. It must not
alternate between a full-screen list and printed prompts. Every capability,
explanation, editor, confirmation, and final review is a screen or overlay
inside the same terminal session.

## Interaction model

- A preset bar sits above the capability list. `Tab`/`Shift-Tab` or left/right
  moves between `Fully closed`, `For developers`, and `Mostly open`. Moving
  focus previews the resulting checklist without mutating the draft; the UI
  must say `PREVIEW — not applied`. `Enter` or `Space` applies the focused
  preset. `Down` or `Esc` leaves preview without changes.
- `For developers` is applied only for incomplete first-run onboarding. It
  enables the known harness's filtered model API, harness state, and dependency
  tooling, plus the full active host GitHub token. GitHub must be visibly
  marked OPEN and the preset must carry a warning; the final OPEN dialog remains
  mandatory. Harness state explicitly includes any detected well-known API-key
  variable for that harness; its name must appear in the disclosure and its
  value must never render or persist. The preset never enables unrestricted
  network, arbitrary environment variables, extra directories, SSH, or
  loopback. Completed profiles retain their saved choices when reopened.
- `Fully closed` clears all optional and granular grants. `Mostly open` opens
  unrestricted network, the full GitHub token, ambient SSH, and loopback, and
  clears granular grants. It requires the shared dialog with Cancel focused and
  names every opened boundary. Presets never guess directories or arbitrary
  environment variables; the known harness-key exception belongs to the
  disclosed harness-state grant. Any non-preset combination is visibly labeled
  `Custom`.
- Arrow keys move the visible highlighted row. `Home`, `End`, `PageUp`, and
  `PageDown` work in scrollable lists.
- `Space` toggles a checkbox or begins approval for the highlighted item.
  `Enter` opens the highlighted item or accepts a focused action.
- `Esc` closes the current overlay or returns one level. It never silently
  accepts a grant. `q` cancels only when focus is not inside a text field.
- The current focus is always visible. Instructions describe only keys that
  work in the current context.
- An ALLOWED toggle applies on `Space` or `Enter`. An `OPEN` grant opens a
  two-button dialog. Cancel is focused by default; `Tab` or left/right moves
  to the explicit enable action, and `Enter` selects it. Typed passphrases and
  y/n prompts are not used in the TUI.
- Toggling access is immediate and visibly updates the checklist. Complete
  consequences remain visible in the adjacent security-detail pane.

## Visual hierarchy

The interface is dense, restrained, and optimized for careful review.

- Header: harness, canonical project, and progress/location breadcrumb.
- Primary pane: the current list or editor. Checkbox state is never inferred
  from color alone.
- Context pane: full resource, access, process, duration, scope, limits,
  default, consequence, remote, and authority facts for the focused item, but
  expressed as short, plain-language `Allows`, `Still blocked`, `Scope`, and
  `Risk` statements. Do not expose the internal data-model field list in the
  normal capability detail pane. Complete field-by-field disclosure remains in
  approval dialogs and the final review.
- Footer: current keys on the first line; confirmation, validation error, or
  concise status on the second line.
- Wide terminals use list/detail split panes. Narrow terminals stack the
  detail pane below the list. Very small terminals show a clear minimum-size
  message without losing cancellation or terminal restoration.
- Color is semantic: cyan marks focus/navigation, green marks a preserved
  boundary such as `CLOSED`, amber marks constrained granted access, and red
  is reserved for enabled `OPEN` authority. `○`, `✓`, `CLOSED`, and `OPEN`
  keep every state understandable without color. `NO_COLOR` preserves weight,
  reverse video, text, borders, and state symbols.
- Internal provenance identifiers such as `AJ-CHOICE-001` never appear in the
  human interface.
- ALLOWED capability rows toggle immediately with `Space` or `Enter`; there is
  no redundant confirmation. Disabled broad rows say `CLOSED`; enabled broad
  rows say `OPEN`. Opening authority uses the shared confirmation dialog.
- Docker/Podman daemon control is a first-page OPEN capability and is closed by
  every preset. The row and detail state that daemon control can mount host
  paths and bypass filesystem isolation.
- The network row names only unrestricted access. Its detail distinguishes the
  three effective states: offline, selected hosts through filtered egress, and
  unrestricted. A closed unrestricted row must never imply that selected-host
  access is also closed.
- Less common human-facing grants live in one `Additional capabilities`
  screen. It shows only platform-relevant entries, never changes a preset, and
  uses the same immediate ALLOWED toggles and explicit OPEN dialogs as the main
  checklist.

## Directory chooser

- Starts from the canonical project parent or the last browsed directory,
  never an implicit credential directory.
- Shows a breadcrumb, an explicit current-directory row, a child-directory
  list, live filter, and the canonical destination preview.
- Arrow keys browse; `Enter` descends into a child; `Backspace` goes to the
  parent; `/` focuses the filter; `Space` adds the highlighted directory.
- Read-only/read-write mode is explicit in the header and can be changed before
  approval. The context pane explains the exact resulting authority.
- The first grant opens a lower `Selected directories` pane. `Tab` moves focus
  between browser and selections. `Space` removes the focused grant without a
  second confirmation; removing the last grant closes the pane and returns
  focus to the browser.
- In the selected pane, `m` toggles the focused grant between read-only and
  read/write without leaving the pane. Authority-reducing changes apply
  immediately; broad authority expansion uses the shared confirmation dialog.
- Narrow ALLOWED grants use the first `Space` as the approval action. Broad
  OPEN grants retain complete disclosure and the explicit dialog choice.
- Symlinks, credential roots, filesystem root, overlapping grants, invalid
  UTF-8, identity drift, and broad scopes retain existing fail-closed checks.
  A broad scope still requires an explicit OPEN dialog choice.

## Environment selector

- Searchable multi-select list of variable names. Values are never loaded for
  rendering, displayed, logged, or persisted.
- Existing approvals are checked. Space stages add/remove; the context pane
  explains that every jailed descendant can read and disclose an approved
  value.
- Every newly approved host variable shows complete disclosure followed by
  the shared confirmation dialog, because authority cannot be verified from
  its name. Cancel is focused by default. Apply/Back actions are explicit.

## Selected-key SSH editor

- Lists discovered public identities by safe path, fingerprint, and comment.
  Private-key contents and the ambient agent are never displayed or shared.
- Selected identities and required destinations are separate panes. A
  destination editor validates entries inline and shows verification failures
  without leaving the TUI.
- The final context panel states key lifetime, verified destinations, network
  prerequisite, private-key boundary, and signature authority. Save and launch
  remain refused until at least one key and enforced destination exist.

## Final review

- Scrollable complete effective access grouped as `RESTRICTED`, `ALLOWED`, and
  `OPEN`, followed by the exact effective policy and authority details.
- The action bar always distinguishes `Save and launch`, `Launch once`, `Save
profile`, `Back`, and `Cancel` according to invocation mode.
- If any OPEN authority remains, the final action opens the shared dialog and
  names the exact persistence and launch consequence. Cancel is the default.
- Cancellation writes no onboarding grants and starts no harness. Terminal
  state is restored on success, cancellation, validation failure, and panic.

## Plain-terminal fallback

`TERM=dumb` keeps the sequential text interface. Noninteractive execution
continues to fail closed or use restricted one-run defaults as documented. The
fallback is a compatibility path, not a partial TUI mixed with raw prompts.
