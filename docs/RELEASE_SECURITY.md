# Release security administration

Before enabling a release, repository administrators must:

1. Protect `master` and require reviewed, passing changes.
2. Add a `v*` tag ruleset that restricts tag creation and mutation.
3. Require signed annotated release tags and make tags/releases immutable.
4. Create protected `release-signing` and `release-publish` environments with
   required reviewers. Keep Apple credentials only in `release-signing`; keep
   publishing credentials only in `release-publish`. Restrict both to a `v*`
   tag deployment branch policy so no other ref can reach those secrets.
   `prevent_self_review` requires a reviewer who is not the actor, so it is
   only usable once a second trusted maintainer exists; with a single
   maintainer the approval gate is still valuable (it stops an automated or
   compromised push from publishing unattended) but cannot be self-review
   free.
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

Done:

- Item 4, partially: both environments exist with a required reviewer and a
  `v*` tag deployment branch policy, so only `v*` tag runs can reach them.
- Item 8: enforced by the publish job.
- Tag-only triggers, SHA-pinned actions, pinned toolchain, and `--locked`
  builds are in the workflows.

Outstanding, in the order worth doing:

1. **Scope the secrets (finishes item 4).** All eight secrets are still
   repository-level, so every job in every workflow can read them; the
   environments gate *deployment*, not secret visibility. Secret values
   cannot be copied by tooling — they are write-only — so re-enter them at
   environment scope and delete the repository copies:
   `gh secret set APPLE_CERTIFICATE --env release-signing` (and
   `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
   `APPLE_PASSWORD`, `APPLE_TEAM_ID`), then `CARGO_REGISTRY_TOKEN` and
   `HOMEBREW_TAP_TOKEN` with `--env release-publish`, then
   `gh secret delete <NAME>` for each repository-level copy.
2. **Item 6, the release keyring.** Until it exists every release logs
   "tag signature NOT cryptographically verified". Generate or choose a
   signing key, `git config user.signingkey` and `tag.gpgsign true`, export
   the public key to `.github/release-keyring/<name>.asc`, and list the
   40-hex primary fingerprint in `.github/release-keyring/fingerprints.txt`.
   Releases before this are unsigned, including v1.18.0.
3. **Items 1-3, branch and tag rulesets.** Note that releases currently
   commit straight to `master`, so requiring pull requests changes that
   workflow; a ruleset restricting `v*` tag creation and mutation, plus
   immutable releases, is the higher-value half and does not disrupt it.
4. **Item 5, Actions allowlist.** Restrict to the SHA-pinned actions already
   in use.
5. **Item 7, crates.io trusted publishing.** Migrate to OIDC and drop
   `CARGO_REGISTRY_TOKEN` entirely; until then rotate it.
