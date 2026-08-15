# Release security administration

Before enabling a release, repository administrators must:

1. Protect `master` and require reviewed, passing changes.
2. Add a `v*` tag ruleset that restricts tag creation and mutation.
3. Require signed annotated release tags and make tags/releases immutable.
4. Create protected `release-signing` and `release-publish` environments with
   required reviewers and no self-review. Keep Apple credentials only in
   `release-signing`; keep publishing credentials only in `release-publish`.
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
