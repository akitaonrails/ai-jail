# Release security administration

Before enabling a release, repository administrators must:

1. Protect `master` and require reviewed, passing changes.
2. Add a `v*` tag ruleset that restricts tag creation and mutation.
3. Require signed annotated release tags and make tags/releases immutable.
4. Create separate `release-signing` and `release-publish` environments and
   restrict both to a `v*` tag deployment branch policy, so no branch or
   other ref can reach their secrets. Keep Apple credentials only in
   `release-signing`; keep publishing credentials only in `release-publish`.
   Required reviewers are deliberately **not** used: this project has a
   single owner and maintainer, so an approval gate could only ever be
   self-approved, adding a manual pause to every release for no security
   gain. Add reviewers (and `prevent_self_review`) only if a second trusted
   maintainer ever exists.
5. Restrict GitHub Actions to an allowlist, review action SHA updates, and keep
   workflow permissions minimal.
6. Configure automated cryptographic tag verification: place ASCII-armored
   release public keys (`*.asc` or `*.gpg`) and a `fingerprints.txt` listing
   the pinned 40-hex primary-key fingerprints (one per line, `#` comments
   allowed) in `.github/release-keyring/`. CI then imports the keys into an
   ephemeral `GNUPGHOME`, runs `git verify-tag`, and requires the signer's
   primary fingerprint to be pinned. Without a keyring the workflow emits an
   explicit "tag signature NOT cryptographically verified" warning — it never
   silently skips — and signature verification remains an administrator duty.
7. Migrate crates.io publication to trusted publishing/OIDC when the registry
   configuration is available; until then protect `CARGO_REGISTRY_TOKEN` in
   `release-publish` and rotate it regularly.
8. Require curated release notes: every `vX.Y.Z` tag must ship a
   `releases/vX.Y.Z.md` in the repository at that tag. The publish job uses
   that file as the release body and strips in-repo "unreleased" marker lines
   at publish time; a missing file fails the release.

The release workflow only accepts pushed `vX.Y.Z` tags. It verifies the tag is
annotated, matches `Cargo.toml`, and points to a commit reachable from
`origin/master`. macOS artifacts are signed and notarized with `notarytool`;
`stapler` is intentionally not run because it cannot staple the raw Mach-O
binary — it applies only if a `.app` bundle or pkg installer is ever shipped.
Signatures must be verified by release administration until a trusted CI
keyring is configured.

## Current status (as of v1.18.0)

Configured:

- **Item 4 (structure).** `release-signing` and `release-publish` exist, with
  no approval gate and a `v*` tag deployment branch policy, so only `v*` tag
  runs can reach them.
- **Item 5.** Actions are restricted to an allowlist: GitHub-owned actions
  (which also covers CodeQL default setup) plus `dtolnay/rust-toolchain@*`.
  Every `uses:` in this repository is SHA-pinned. Default workflow
  permissions are read-only.
- **Item 6.** A pinned release key lives in `.github/release-keyring/`
  (`ai-jail-release.asc` plus its 40-hex fingerprint in `fingerprints.txt`),
  and `tag.gpgsign` is enabled for this repository, so CI cryptographically
  verifies each `v*` tag against that key. First verified release: v1.18.1.
  The key expires 2028-08-15 — rotate before then by adding the replacement
  fingerprint to `fingerprints.txt` alongside the old one.
- **Item 8.** Enforced by the publish job.
- Tag-only release triggers, a pinned toolchain, and `--locked` builds.

Deliberately skipped for a single-maintainer project:

- **Item 1, requiring reviewed pull requests on `master`.** Releases commit
  directly to `master`; a self-approved PR gate adds friction without
  changing who can push.
- **A `v*` tag mutation ruleset.** The owner would hold bypass, so it would
  not constrain the only actor who can push tags, while blocking the
  legitimate re-tagging a failed release run requires.

Revisit both if a second maintainer or an untrusted CI identity is ever
added.

Outstanding, in the order worth doing:

1. **Scope the secrets (finishes item 4).** All eight secrets are still
   repository-level, so every job in every workflow can read them; the
   environments gate _deployment_, not secret visibility. This is the
   highest-value remaining step. Secret values cannot be copied by tooling —
   they are write-only — so re-enter them at environment scope and delete the
   repository copies:
   `gh secret set APPLE_CERTIFICATE --env release-signing` (and
   `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
   `APPLE_PASSWORD`, `APPLE_TEAM_ID`), then `CARGO_REGISTRY_TOKEN` and
   `HOMEBREW_TAP_TOKEN` with `--env release-publish`, then
   `gh secret delete <NAME>` for each repository-level copy.
2. **A `v*` ruleset requiring signed tags.** Now that signing is in place
   this is worth adding even with one maintainer, because it turns the
   signing convention into an enforced invariant rather than a habit. Add it
   once the current release flow has settled, since it also blocks the
   re-tagging a failed release run needs.
3. **Item 3, immutable releases.** Not settable through the REST API on this
   repository; enable it in Settings if and when GitHub exposes it here.
4. **Item 7, crates.io trusted publishing.** Migrate to OIDC and drop
   `CARGO_REGISTRY_TOKEN` entirely; until then rotate it.
