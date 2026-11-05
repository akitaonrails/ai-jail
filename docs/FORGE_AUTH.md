# Repository-scoped forge access

`ai-jail forge` keeps forge credentials in the trusted user configuration tree,
never in the repository or its project policy. The remote URL is not trusted as
configuration: setup requires an explicit origin and repository, verifies the
server's numeric repository ID, and repeats that check before every launch.

The feature does not replace the legacy `--github` switch. That switch still
shares the active host `gh` credential and is accurately reported as **OPEN**.

## Security labels

- **SCOPED · SHORT-LIVED:** a GitHub App installation token, narrowed to the
  selected repository and minted for each launch. ai-jail attempts revocation on
  normal exit. Expiry remains the reliable boundary after crashes or `SIGKILL`.
- **OPEN · USER-ASSERTED · PERSISTENT:** you selected the repository and scopes
  in the forge UI, but its API cannot prove that the supplied token lacks other
  authority. Setup requires typing `OPEN`, and every launch/status summary keeps
  the OPEN label. The token remains valid until its displayed expiry or
  server-side revocation.
- **OPEN:** account-wide OAuth, classic PATs, and the legacy `--github` path.
  This setup flow does not import those tokens as scoped credentials.

The jail receives a launch-only token, the provider CLI variable (`GH_TOKEN`,
`GITLAB_TOKEN`, or `GITEA_TOKEN`), and a Git credential helper limited to the
approved HTTPS host and `OWNER/REPO` path. Host CLI configuration is not mounted.
The stored GitHub App private key is never placed in the jail.

## GitHub App: one-time account setup

GitHub requires the repository owner to create an App; ai-jail cannot silently
create one with broader account authority. In GitHub, open **Settings → Developer
settings → GitHub Apps → New GitHub App**:

1. Give the App no webhook and no callback URL. It does not use browser OAuth.
2. Select only the repository permissions needed. The setup prompts separately
   select Contents read or write, Issues write, and Pull requests write. The App
   must allow the selected permissions, but does not need the unselected ones.
3. Set installation access to **Only on this account**, create the App, install
   it for **Only select repositories**, and select this repository.
4. Generate a private key and protect the downloaded PEM with mode `0600`.
5. Copy the App ID and installation ID from GitHub.

After setup copies the key into the owner-only credential store, securely remove
the downloaded original if you do not need a separate backup.

Run from the repository:

```console
$ ai-jail forge setup github-app https://api.github.com owner/repo
AJ-FORGE-001: GitHub App access for https://api.github.com / owner/repo
Create and install a GitHub App for only this repository. ...
GitHub App ID: 123456
Installation ID: 7654321
Downloaded GitHub App private-key PEM path: /home/me/Downloads/app.pem
Select only the GitHub permissions this jail needs.
Repository contents: read-only [1] or read/write [2]: 2
Issues read/write [y/N]: n
Pull requests read/write [y/N]: y
✓ AJ-FORGE-SAVE-001 Forge access saved outside the checkout
  /home/me/.config/ai-jail/forges/<project-id>.toml
  Repository ID: 123456789
  Token class: SCOPED · SHORT-LIVED
```

On launch, ai-jail signs a short-lived App JWT on the host, requests a
one-repository installation token from the fixed `api.github.com` endpoint,
checks the numeric ID, and gives only the installation token to the jail. Git
credentials are independently restricted to `https://github.com/owner/repo`.

## GitLab project access token

Create a **project access token** in the selected project's settings. Choose an
expiry and only required scopes; do not paste a personal access token. Then:

The complete transcript below is executed in a PTY test. The token values are
entered only after terminal echo is disabled, so they do not appear.

```text
AJ-FORGE-TRANSCRIPT-BEGIN actual CLI workflow
AJ-FORGE-001: GitLab project token access for https://gitlab.example / owner/repo
Create a repository-specific token in the forge UI, limited to this repository and the operations you need. The value is hidden and stored outside the project. It remains valid until its server expiry or revocation.
Token scopes shown by the forge (comma-separated): read_repository
Token expiry shown by the forge (YYYY-MM-DD or `never`): 2027-01-31
Repository token: 
✗ AJ-FORGE-OPEN-001 OPEN: ai-jail cannot prove that this persistent token lacks access outside owner/repo. Type OPEN to save this authority:
OPEN
✓ AJ-FORGE-SAVE-001 Forge access saved outside the checkout
  <ROOT>/xdg/ai-jail/forges/<PROJECT>.toml
  Repository ID: 42
  Token class: OPEN · USER-ASSERTED · PERSISTENT
AJ-FORGE-STATUS-001 GitLab project token for https://gitlab.example / owner/repo (repository ID 42)
Token class: OPEN · USER-ASSERTED · PERSISTENT
Scopes: read_repository
Lifetime: 2027-01-31
Rotate: run `ai-jail forge setup ...` again; disable with `ai-jail forge remove`
AJ-FORGE-001: GitLab project token access for https://gitlab.example / owner/repo
Create a repository-specific token in the forge UI, limited to this repository and the operations you need. The value is hidden and stored outside the project. It remains valid until its server expiry or revocation.
Token scopes shown by the forge (comma-separated): read_repository,write_repository
Token expiry shown by the forge (YYYY-MM-DD or `never`): 2027-06-30
Repository token: 
✗ AJ-FORGE-OPEN-001 OPEN: ai-jail cannot prove that this persistent token lacks access outside owner/repo. Type OPEN to save this authority:
OPEN
✓ AJ-FORGE-SAVE-001 Forge access saved outside the checkout
  <ROOT>/xdg/ai-jail/forges/<PROJECT>.toml
  Repository ID: 42
  Token class: OPEN · USER-ASSERTED · PERSISTENT
✓ AJ-FORGE-REMOVE-001 Forge access removed for this project
AJ-FORGE-TRANSCRIPT-END actual CLI workflow
```

GitLab does not expose a portable negative-authority proof for a presented
project token, so the user assertion is preserved in every summary.

## Codeberg/Forgejo and Gitea Enterprise

Create a repository-selected token in the server UI. ai-jail downloads the
trusted origin's OpenAPI document at runtime and recognizes repository scoping
only when the access-token schema contains an explicit repository selector. A
version string alone is never accepted as proof. Enter the scopes and expiry
exactly as shown by the forge:

```console
$ ai-jail forge setup codeberg https://codeberg.org owner/repo
$ ai-jail forge setup gitea https://git.example owner/repo
```

OpenAPI capability detection does not prove the pasted token's negative
authority. These credentials remain **OPEN · USER-ASSERTED · PERSISTENT**.
Password-based token creation APIs are not used.

Private-network self-hosted origins are refused by default. If the server is
intentionally private, add `--allow-private` and type the exact word `OPEN`.
Loopback, link-local, multicast, unspecified, and cloud-metadata addresses stay
blocked. Redirects are refused; rerun setup with the canonical HTTPS origin.

## Inspect, rotate, and remove

```console
$ ai-jail forge status
AJ-FORGE-STATUS-001 GitLab project token for https://gitlab.example / owner/repo (repository ID 42)
Token class: OPEN · USER-ASSERTED · PERSISTENT
Scopes: read_repository, api
Lifetime: 2027-01-31
Rotate: run `ai-jail forge setup ...` again; disable with `ai-jail forge remove`

$ ai-jail forge remove
✓ AJ-FORGE-REMOVE-001 Forge access removed for this project
```

Rotation repeats setup and atomically replaces the stored credential. Removal
deletes both the project binding and its separate credential file. Persistent
tokens must also be revoked in the forge UI if immediate server-side revocation
is required.

## Provenance and drift controls

The executable behavior is in `src/forge_auth.rs`; CLI parsing is in
`src/cli.rs`; launch integration is in `src/main.rs`. Tests require structural
OpenAPI detection, fixed Git credential paths, secret-free binding files,
numeric IDs, strict origin parsing, and token-redacted summaries.

Security claims were derived from these provider sources (checked 2026-11-05):

- [GitHub App authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app)
- [GitHub installation access tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)
- [GitHub installation repository selection](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app)
- [GitLab project access tokens](https://docs.gitlab.com/user/project/settings/project_access_tokens/)
- [Forgejo API usage and token scopes](https://forgejo.org/docs/latest/user/api-usage/)
- [Gitea API usage](https://docs.gitea.com/development/api-usage)

When any linked provider contract or the named source modules change, update
this guide and its simulated output in the same change.
