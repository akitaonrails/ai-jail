//! Repository-bound forge credentials kept outside the checkout.
//!
//! Git remotes are hints only. Setup requires an explicit HTTPS origin and
//! repository path, resolves the forge's immutable repository ID on the host,
//! and stores secrets in the trusted ai-jail configuration tree. The jail
//! receives only a launch credential whose server-side scope is disclosed.

use crate::cli::ForgeCommand;
use crate::config::Config;
use crate::config_store::StorePaths;
use ring::{rand::SystemRandom, signature};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SCHEMA_VERSION: u32 = 1;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
const GITHUB_API_ORIGIN: &str = "https://api.github.com";
const GITHUB_GIT_ORIGIN: &str = "https://github.com";
const SETUP_ID: &str = "AJ-FORGE-001";
const OPEN_ID: &str = "AJ-FORGE-OPEN-001";
const SAVE_ID: &str = "AJ-FORGE-SAVE-001";
const STATUS_ID: &str = "AJ-FORGE-STATUS-001";
const REMOVE_ID: &str = "AJ-FORGE-REMOVE-001";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provider {
    GithubApp,
    GitlabProject,
    ForgejoRepository,
    GiteaFineGrained,
}

impl Provider {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "github-app" | "github" => Ok(Self::GithubApp),
            "gitlab" | "gitlab-project" => Ok(Self::GitlabProject),
            "codeberg" | "forgejo" => Ok(Self::ForgejoRepository),
            "gitea" => Ok(Self::GiteaFineGrained),
            _ => Err(format!(
                "Unsupported forge provider {value:?}; use github-app, gitlab, codeberg, forgejo, or gitea"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::GithubApp => "GitHub App",
            Self::GitlabProject => "GitLab project token",
            Self::ForgejoRepository => "Forgejo/Codeberg repository token",
            Self::GiteaFineGrained => "Gitea fine-grained token",
        }
    }

    fn persistent(self) -> bool {
        self != Self::GithubApp
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    schema_version: u32,
    provider: Provider,
    origin: Origin,
    repository_id: u64,
    repository: String,
    credential_id: String,
    allow_private: bool,
    scope_verified: bool,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    open_approved: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    schema_version: u32,
    provider: Provider,
    secret: SecretMaterial,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SecretMaterial {
    PersistentToken {
        token: SecretString,
    },
    GithubApp {
        app_id: u64,
        installation_id: u64,
        private_key_pkcs1_pem: SecretString,
    },
}

struct SecretString(Zeroizing<String>);

impl SecretString {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Origin {
    host: String,
    port: u16,
    #[serde(default)]
    test_http: bool,
}

impl Origin {
    fn parse(value: &str) -> Result<Self, String> {
        let (scheme, rest) = value
            .split_once("://")
            .ok_or_else(|| "Forge origin must include https://".to_string())?;
        let test_http = scheme == "http" && cfg!(feature = "test-hooks");
        if scheme != "https" && !test_http {
            return Err("Forge origin must use HTTPS".into());
        }
        if rest.is_empty()
            || rest.contains(['/', '?', '#', '@'])
            || rest.bytes().any(|b| b.is_ascii_control())
        {
            return Err(
                "Forge origin must contain only a host and optional port"
                    .into(),
            );
        }
        let (host, port) = if let Some((host, port)) = rest.rsplit_once(':') {
            if host.contains(':') {
                return Err("IPv6 forge origins are not supported yet".into());
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| "Forge origin has an invalid port".to_string())?;
            (host, port)
        } else {
            (rest, if test_http { 80 } else { 443 })
        };
        validate_dns_name(host)?;
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            test_http,
        })
    }

    fn display(&self) -> String {
        let scheme = if self.test_http { "http" } else { "https" };
        let default = (!self.test_http && self.port == 443)
            || (self.test_http && self.port == 80);
        if default {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    fn https_display(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }
}

pub(crate) struct Runtime {
    binding: Binding,
    token: TokenGuard,
}

struct TokenGuard {
    token: Zeroizing<String>,
    revoke: Option<(Origin, bool)>,
}

impl TokenGuard {
    fn persistent(token: Zeroizing<String>) -> Self {
        Self {
            token,
            revoke: None,
        }
    }

    fn github(token: Zeroizing<String>, binding: &Binding) -> Self {
        Self {
            token,
            revoke: Some((binding.origin.clone(), binding.allow_private)),
        }
    }

    fn expose(&self) -> &str {
        self.token.as_str()
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        if let Some((origin, allow_private)) = &self.revoke {
            let _ = request(
                origin,
                *allow_private,
                "DELETE",
                "/installation/token",
                Some(self.token.as_str()),
                None,
            );
        }
    }
}

impl Runtime {
    pub(crate) fn apply(&self, config: &mut Config) {
        if config.lockdown_enabled() {
            return;
        }
        strip_runtime(config);
        config
            .env_pass
            .push(format!("AI_JAIL_FORGE_TOKEN={}", self.token.expose()));
        let token_name = match self.binding.provider {
            Provider::GithubApp => "GH_TOKEN",
            Provider::GitlabProject => "GITLAB_TOKEN",
            Provider::ForgejoRepository | Provider::GiteaFineGrained => {
                "GITEA_TOKEN"
            }
        };
        config
            .env_pass
            .push(format!("{token_name}={}", self.token.expose()));
        config
            .env_pass
            .push(format!("AI_JAIL_FORGE_ORIGIN={}", self.git_origin()));
        config.env_pass.push(format!(
            "AI_JAIL_FORGE_REPOSITORY={}",
            self.binding.repository
        ));
        config.env_pass.push(format!(
            "AI_JAIL_FORGE_AUTHORITY={}",
            if self.binding.scope_verified {
                "SCOPED"
            } else {
                "OPEN"
            }
        ));
        // Git's credential machinery is path-aware only when useHttpPath is
        // enabled. The helper reads the launch-only token from the environment;
        // the server-side repository token remains the security boundary.
        config.env_pass.push("GIT_CONFIG_COUNT=3".into());
        config
            .env_pass
            .push("GIT_CONFIG_KEY_0=credential.helper".into());
        config.env_pass.push("GIT_CONFIG_VALUE_0=".into());
        config
            .env_pass
            .push("GIT_CONFIG_KEY_1=credential.useHttpPath".into());
        config.env_pass.push("GIT_CONFIG_VALUE_1=true".into());
        config.env_pass.push(format!(
            "GIT_CONFIG_KEY_2=credential.{}.helper",
            self.git_origin()
        ));
        let git_host = self
            .git_origin()
            .strip_prefix("https://")
            .expect("validated forge Git origin is HTTPS")
            .to_string();
        config.env_pass.push(format!(
            "GIT_CONFIG_VALUE_2={}",
            git_credential_helper(&git_host, &self.binding.repository)
        ));
    }

    fn git_origin(&self) -> String {
        if self.binding.provider == Provider::GithubApp {
            GITHUB_GIT_ORIGIN.into()
        } else {
            self.binding.origin.https_display()
        }
    }

    pub(crate) fn summary(&self) -> String {
        let persistence = if !self.binding.scope_verified {
            "OPEN · USER-ASSERTED · PERSISTENT"
        } else if self.binding.provider.persistent() {
            "SCOPED · PERSISTENT"
        } else {
            "SCOPED · SHORT-LIVED"
        };
        let proof = if self.binding.scope_verified {
            "server capability verified"
        } else {
            "scope selected by the user; ai-jail cannot prove negative access"
        };
        format!(
            "{}: {persistence}; {} / {}; repository ID {}; scopes {}; lifetime {}; {proof}",
            self.binding.provider.label(),
            self.binding.origin.display(),
            self.binding.repository,
            self.binding.repository_id,
            self.binding.scopes.join(", "),
            self.binding
                .expires_at
                .as_deref()
                .unwrap_or("until revoked")
        )
    }

    pub(crate) fn summary_line(&self) -> String {
        if self.binding.scope_verified {
            format!("- [WARN] ALLOWED: {}", self.summary())
        } else {
            format!("- [ERROR] OPEN: {}", self.summary())
        }
    }
}

fn git_credential_helper(host: &str, repository: &str) -> String {
    format!(
        "!f() {{ test \"$1\" = get || exit 0; protocol= host= path=; while IFS='=' read -r key value; do case \"$key\" in protocol) protocol=$value;; host) host=$value;; path) path=$value;; esac; done; test \"$protocol\" = https || exit 0; test \"$host\" = '{host}' || exit 0; case \"$path\" in '{repository}'|'{repository}.git') ;; *) exit 0;; esac; printf 'username=ai-jail\\npassword=%s\\n' \"$AI_JAIL_FORGE_TOKEN\"; }}; f"
    )
}

pub(crate) fn is_runtime_env(entry: &str) -> bool {
    [
        "AI_JAIL_FORGE_TOKEN",
        "AI_JAIL_FORGE_ORIGIN",
        "AI_JAIL_FORGE_REPOSITORY",
        "AI_JAIL_FORGE_AUTHORITY",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "GITEA_TOKEN",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_KEY_1",
        "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_VALUE_2",
    ]
    .iter()
    .any(|name| entry == *name || entry.starts_with(&format!("{name}=")))
}

pub(crate) fn strip_runtime(config: &mut Config) {
    config.env_pass.retain(|entry| !is_runtime_env(entry));
}

pub(crate) fn run_command(
    command: &ForgeCommand,
    paths: &StorePaths,
) -> Result<i32, String> {
    match command {
        ForgeCommand::Status => {
            let binding = load_binding(paths)?;
            if let Some(active) = &binding {
                load_credential(paths, &active.credential_id)?;
            }
            cleanup_orphan_credentials(
                paths,
                binding.as_ref().map(|active| active.credential_id.as_str()),
            )?;
            match binding {
                Some(binding) => println!(
                    "{STATUS_ID} {} for {} / {} (repository ID {})\nToken class: {}\nScopes: {}\nLifetime: {}\nRotate: run `ai-jail forge setup ...` again; disable with `ai-jail forge remove`",
                    binding.provider.label(),
                    binding.origin.display(),
                    binding.repository,
                    binding.repository_id,
                    if !binding.scope_verified {
                        "OPEN · USER-ASSERTED · PERSISTENT"
                    } else if binding.provider.persistent() {
                        "SCOPED · PERSISTENT"
                    } else {
                        "SCOPED · SHORT-LIVED"
                    },
                    binding.scopes.join(", "),
                    binding.expires_at.as_deref().unwrap_or("until revoked")
                ),
                None => println!("{STATUS_ID} Forge access is not configured"),
            }
            Ok(0)
        }
        ForgeCommand::Remove => {
            remove(paths)?;
            crate::output::ok(&format!(
                "{REMOVE_ID} Forge access removed for this project"
            ));
            Ok(0)
        }
        ForgeCommand::Setup {
            provider,
            origin,
            repository,
            allow_private,
        } => {
            if !crate::onboarding::is_interactive() {
                return Err(
                    "forge setup needs an interactive terminal; no credential was read"
                        .into(),
                );
            }
            let origin = Origin::parse(origin)?;
            validate_provider_origin(Provider::parse(provider)?, &origin)?;
            setup(
                paths,
                Provider::parse(provider)?,
                origin,
                repository,
                *allow_private,
            )?;
            Ok(0)
        }
    }
}

pub(crate) fn prepare(paths: &StorePaths) -> Result<Option<Runtime>, String> {
    #[cfg(feature = "test-hooks")]
    if let Some(marker) = std::env::var_os("AI_JAIL_TEST_FORGE_PREPARE_MARKER")
    {
        let marker = PathBuf::from(marker);
        if marker.is_absolute() {
            fs::write(marker, b"prepare\n")
                .map_err(|e| format!("Cannot write forge test marker: {e}"))?;
        }
    }
    let Some(binding) = load_binding(paths)? else {
        return Ok(None);
    };
    let credential = load_credential(paths, &binding.credential_id)?;
    if credential.provider != binding.provider {
        return Err(
            "Forge credential provider does not match project binding".into()
        );
    }
    if !binding.scope_verified && !binding.open_approved {
        return Err("Unverified persistent forge authority lacks explicit OPEN approval; run `ai-jail forge setup` again".into());
    }
    let token = match credential.secret {
        SecretMaterial::PersistentToken { token } => {
            TokenGuard::persistent(token.into_zeroizing())
        }
        SecretMaterial::GithubApp {
            app_id,
            installation_id,
            private_key_pkcs1_pem,
        } => {
            let minted = mint_github_token(
                &binding,
                app_id,
                installation_id,
                private_key_pkcs1_pem.expose(),
            );
            minted?
        }
    };
    let actual_id = fetch_repository_id(&binding, token.expose())?;
    verify_repository_identity(binding.repository_id, actual_id)?;
    Ok(Some(Runtime { binding, token }))
}

fn verify_repository_identity(
    expected: u64,
    actual: u64,
) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "Forge repository identity changed: expected {expected}, received {actual}. Run `ai-jail forge setup` to reassociate explicitly."
        ));
    }
    Ok(())
}

fn setup(
    paths: &StorePaths,
    provider: Provider,
    origin: Origin,
    repository: &str,
    allow_private: bool,
) -> Result<(), String> {
    validate_repository(repository)?;
    validate_provider_origin(provider, &origin)?;
    if allow_private {
        crate::output::error(&format!(
            "{OPEN_ID} OPEN: this forge origin may resolve to private network services. Type OPEN to continue:"
        ));
        if read_visible_line()?.trim() != "OPEN" {
            return Err("Private forge access was not approved".into());
        }
    }
    crate::output::status_header(
        SETUP_ID,
        &format!(
            "{} access for {} / {}",
            provider.label(),
            origin.display(),
            repository
        ),
    );
    let persistent_metadata: Option<(Vec<String>, Option<String>)>;
    let (secret, probe_token, scope_verified) = match provider {
        Provider::GithubApp => {
            eprintln!(
                "Create and install a GitHub App for only this repository. Its repository permissions must include the choices below. ai-jail stores its private key outside the project and mints a one-hour repository token for each launch."
            );
            eprint!("GitHub App ID: ");
            io::stderr().flush().ok();
            let app_id = read_visible_line()?
                .trim()
                .parse::<u64>()
                .map_err(|_| "Invalid GitHub App ID".to_string())?;
            eprint!("Installation ID: ");
            io::stderr().flush().ok();
            let installation_id = read_visible_line()?
                .trim()
                .parse::<u64>()
                .map_err(|_| "Invalid GitHub installation ID".to_string())?;
            eprint!("Downloaded GitHub App private-key PEM path: ");
            io::stderr().flush().ok();
            let path = PathBuf::from(read_visible_line()?.trim());
            let pem = read_secret_file(&path)?;
            validate_github_key(&pem)?;
            eprintln!("Select only the GitHub permissions this jail needs.");
            eprint!("Repository contents: read-only [1] or read/write [2]: ");
            io::stderr().flush().ok();
            let contents = match read_visible_line()?.trim() {
                "1" => "contents:read",
                "2" => "contents:write",
                _ => return Err("Choose 1 or 2 for repository contents".into()),
            };
            let mut scopes = vec![contents.to_string()];
            if confirm("Issues read/write [y/N]: ")? {
                scopes.push("issues:write".into());
            }
            if confirm("Pull requests read/write [y/N]: ")? {
                scopes.push("pull_requests:write".into());
            }
            persistent_metadata =
                Some((scopes.clone(), Some("one hour from launch".into())));
            let provisional = Binding {
                schema_version: SCHEMA_VERSION,
                provider,
                origin: origin.clone(),
                repository_id: 0,
                repository: repository.to_string(),
                credential_id: String::new(),
                allow_private,
                scope_verified: true,
                scopes,
                expires_at: Some("one hour from launch".into()),
                open_approved: false,
            };
            let token =
                mint_github_token(&provisional, app_id, installation_id, &pem)?;
            (
                SecretMaterial::GithubApp {
                    app_id,
                    installation_id,
                    private_key_pkcs1_pem: SecretString(pem),
                },
                token,
                true,
            )
        }
        _ => {
            eprintln!(
                "Create a repository-specific token in the forge UI, limited to this repository and the operations you need. The value is hidden and stored outside the project. It remains valid until its server expiry or revocation."
            );
            eprint!("Token scopes shown by the forge (comma-separated): ");
            io::stderr().flush().ok();
            let scopes = parse_scopes(&read_visible_line()?)?;
            eprint!(
                "Token expiry shown by the forge (YYYY-MM-DD or `never`): "
            );
            io::stderr().flush().ok();
            let expires_at = parse_expiry(&read_visible_line()?)?;
            let token = read_secret("Repository token:")?;
            if token.is_empty() || token.len() > 8192 {
                return Err("Forge token is empty or too large".into());
            }
            // Community GitLab/Gitea APIs do not provide a portable endpoint
            // proving that a presented token has no access elsewhere.
            // Capability discovery can prove repository-token support, while
            // the final scope choice remains user-asserted.
            let capability = discover_scoped_token_capability(
                provider,
                &origin,
                allow_private,
            )?;
            if matches!(
                provider,
                Provider::ForgejoRepository | Provider::GiteaFineGrained
            ) && !capability
            {
                return Err("This server's OpenAPI schema does not advertise repository-selected access tokens; no credential was saved".into());
            }
            let secret = (
                SecretMaterial::PersistentToken {
                    token: SecretString(token.clone()),
                },
                TokenGuard::persistent(token),
                false,
            );
            persistent_metadata = Some((scopes, expires_at));
            secret
        }
    };
    let provisional = Binding {
        schema_version: SCHEMA_VERSION,
        provider,
        origin,
        repository_id: 0,
        repository: repository.to_string(),
        credential_id: credential_id(paths)?,
        allow_private,
        scope_verified,
        scopes: persistent_metadata
            .as_ref()
            .map(|value| value.0.clone())
            .unwrap_or_else(|| {
                vec![
                    "contents:write".into(),
                    "issues:write".into(),
                    "pull_requests:write".into(),
                ]
            }),
        expires_at: persistent_metadata.and_then(|value| value.1).or_else(
            || (!provider.persistent()).then(|| "one hour from launch".into()),
        ),
        open_approved: false,
    };
    let repository_id =
        fetch_repository_id(&provisional, probe_token.expose())?;
    let mut binding = Binding {
        repository_id,
        ..provisional
    };
    if !binding.scope_verified {
        crate::output::error(&format!(
            "{OPEN_ID} OPEN: ai-jail cannot prove that this persistent token lacks access outside {}. Type OPEN to save this authority:",
            binding.repository
        ));
        if read_visible_line()?.trim() != "OPEN" {
            return Err("Unverified forge authority was not approved; no credential was saved".into());
        }
        binding.open_approved = true;
    }
    let credential = Credential {
        schema_version: SCHEMA_VERSION,
        provider,
        secret,
    };
    save(paths, &binding, &credential)?;
    crate::output::ok(&format!(
        "{SAVE_ID} Forge access saved outside the checkout"
    ));
    eprintln!("  {}", binding_path(paths).display());
    eprintln!("  Repository ID: {repository_id}");
    eprintln!(
        "  Token class: {}",
        if provider.persistent() {
            if scope_verified {
                "SCOPED · PERSISTENT"
            } else {
                "OPEN · USER-ASSERTED · PERSISTENT"
            }
        } else {
            "SCOPED · SHORT-LIVED"
        }
    );
    Ok(())
}

fn parse_scopes(value: &str) -> Result<Vec<String>, String> {
    let scopes = value
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if scopes.is_empty()
        || scopes.len() > 32
        || scopes.iter().any(|scope| {
            scope.len() > 80
                || !scope.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/')
                })
        })
    {
        return Err(
            "Enter the exact non-empty scope names shown by the forge".into()
        );
    }
    Ok(scopes)
}

fn parse_expiry(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value == "never" {
        return Ok(None);
    }
    let valid = value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        });
    valid
        .then(|| Some(value.to_string()))
        .ok_or_else(|| "Expiry must be YYYY-MM-DD or `never`".into())
}

fn validate_provider_origin(
    provider: Provider,
    origin: &Origin,
) -> Result<(), String> {
    if provider == Provider::GithubApp
        && !origin.test_http
        && origin.display() != GITHUB_API_ORIGIN
    {
        return Err(format!(
            "GitHub App setup requires the fixed API origin {GITHUB_API_ORIGIN}; Git credentials remain bound to {GITHUB_GIT_ORIGIN}"
        ));
    }
    Ok(())
}

fn discover_scoped_token_capability(
    provider: Provider,
    origin: &Origin,
    allow_private: bool,
) -> Result<bool, String> {
    match provider {
        Provider::GitlabProject => {
            // GitLab project tokens are a documented server capability, but
            // `/personal_access_tokens/self` does not expose their project
            // binding. Keep the result user-asserted.
            Ok(false)
        }
        Provider::ForgejoRepository => {
            let response = request(
                origin,
                allow_private,
                "GET",
                "/swagger.v1.json",
                None,
                None,
            )?;
            if response.status != 200 {
                return Err("Forgejo capability discovery failed".into());
            }
            let document: serde_json::Value =
                serde_json::from_slice(&response.body).map_err(|_| {
                    "Forgejo returned invalid OpenAPI JSON".to_string()
                })?;
            Ok(openapi_token_schema_has_repository_selector(&document))
        }
        Provider::GiteaFineGrained => {
            let response = request(
                origin,
                allow_private,
                "GET",
                "/swagger.v1.json",
                None,
                None,
            )?;
            if response.status != 200 {
                return Err("Gitea capability discovery failed".into());
            }
            let document: serde_json::Value =
                serde_json::from_slice(&response.body).map_err(|_| {
                    "Gitea returned invalid OpenAPI JSON".to_string()
                })?;
            Ok(openapi_token_schema_has_repository_selector(&document))
        }
        Provider::GithubApp => Ok(true),
    }
}

fn openapi_token_schema_has_repository_selector(
    document: &serde_json::Value,
) -> bool {
    let definitions = document
        .pointer("/definitions/CreateAccessTokenOption/properties")
        .or_else(|| {
            document.pointer(
                "/components/schemas/CreateAccessTokenOption/properties",
            )
        });
    definitions.is_some_and(|properties| {
        properties.get("repositories").is_some()
            || properties.get("repository_ids").is_some()
    })
}

fn fetch_repository_id(binding: &Binding, token: &str) -> Result<u64, String> {
    let path = match binding.provider {
        Provider::GithubApp => format!("/repos/{}", binding.repository),
        Provider::GitlabProject => {
            format!("/api/v4/projects/{}", percent_encode(&binding.repository))
        }
        Provider::ForgejoRepository | Provider::GiteaFineGrained => {
            format!("/api/v1/repos/{}", binding.repository)
        }
    };
    let response = request_provider(
        binding.provider,
        &binding.origin,
        binding.allow_private,
        "GET",
        &path,
        token,
        None,
    )?;
    if response.status != 200 {
        return Err(format!(
            "Forge refused repository verification (HTTP {})",
            response.status
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|_| "Forge returned invalid repository JSON".to_string())?;
    value
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "Forge repository response has no numeric ID".into())
}

fn mint_github_token(
    binding: &Binding,
    app_id: u64,
    installation_id: u64,
    pem: &str,
) -> Result<TokenGuard, String> {
    let jwt = github_jwt(app_id, pem)?;
    let mut permissions = serde_json::Map::new();
    for scope in &binding.scopes {
        let (name, access) = scope.split_once(':').ok_or_else(|| {
            "Invalid stored GitHub App permission".to_string()
        })?;
        if !matches!(name, "contents" | "issues" | "pull_requests")
            || !matches!(access, "read" | "write")
        {
            return Err("Invalid stored GitHub App permission".into());
        }
        permissions.insert(name.into(), access.into());
    }
    let body = serde_json::json!({
        "repositories": [binding.repository],
        "permissions": permissions
    });
    let authorization = Zeroizing::new(format!("Bearer {}", jwt.as_str()));
    let body = Zeroizing::new(body.to_string());
    let response = request_with_authorization(
        &binding.origin,
        binding.allow_private,
        "POST",
        &format!("/app/installations/{installation_id}/access_tokens"),
        &authorization,
        Some(body.as_bytes()),
    )?;
    if response.status != 201 {
        return Err(format!(
            "GitHub App token creation failed (HTTP {})",
            response.status
        ));
    }
    #[derive(Deserialize)]
    struct TokenResponse {
        token: SecretString,
    }
    let value: TokenResponse = serde_json::from_slice(&response.body)
        .map_err(|_| "GitHub returned invalid token JSON".to_string())?;
    if value.token.expose().is_empty() {
        return Err("GitHub token response has no token".into());
    }
    Ok(TokenGuard::github(value.token.into_zeroizing(), binding))
}

fn github_jwt(app_id: u64, pem: &str) -> Result<Zeroizing<String>, String> {
    let key = github_rsa_key(pem)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is before 1970".to_string())?
        .as_secs();
    let header = base64_url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = base64_url(
        format!(
            "{{\"iat\":{},\"exp\":{},\"iss\":{app_id}}}",
            now.saturating_sub(60),
            now + 540
        )
        .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let mut signature_bytes =
        Zeroizing::new(vec![0; key.public().modulus_len()]);
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature_bytes,
    )
    .map_err(|_| "Cannot sign GitHub App JWT".to_string())?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        base64_url(&signature_bytes)
    )))
}

fn binding_path(paths: &StorePaths) -> PathBuf {
    paths
        .root
        .join("forges")
        .join(format!("{}.toml", paths.identity().key))
}

fn credential_prefix(paths: &StorePaths) -> String {
    let mut hash = Sha256::new();
    hash.update(paths.canonical_project.as_os_str().as_encoded_bytes());
    hex(&hash.finalize()[..12])
}

fn credential_id(paths: &StorePaths) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut nonce = [0_u8; 12];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        "Cannot generate forge credential identifier".to_string()
    })?;
    Ok(format!("{}-{}", credential_prefix(paths), hex(&nonce)))
}

fn credential_path(paths: &StorePaths, id: &str) -> Result<PathBuf, String> {
    if id.len() != 49
        || id.as_bytes().get(24) != Some(&b'-')
        || !id
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 24 || byte.is_ascii_hexdigit())
    {
        return Err("Forge credential identifier is invalid".into());
    }
    Ok(paths.root.join("credentials").join(format!("{id}.toml")))
}

fn save(
    paths: &StorePaths,
    binding: &Binding,
    credential: &Credential,
) -> Result<(), String> {
    save_with(paths, binding, credential, atomic_private_write, |path| {
        durable_remove(path)
            .map_err(|e| format!("Cannot remove old forge credential: {e}"))
    })
}

fn save_with(
    paths: &StorePaths,
    binding: &Binding,
    credential: &Credential,
    install_binding: impl FnOnce(&Path, &[u8]) -> Result<(), InstallError>,
    remove_credential: impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let _lock = paths.prepare()?;
    secure_subdir(&paths.root.join("forges"))?;
    secure_subdir(&paths.root.join("credentials"))?;
    let credential_text = Zeroizing::new(
        toml::to_string(credential)
            .map_err(|e| format!("Cannot encode forge credential: {e}"))?,
    );
    let binding_text = toml::to_string(binding)
        .map_err(|e| format!("Cannot encode forge binding: {e}"))?;
    let previous = load_binding(paths)?;
    let new_credential = credential_path(paths, &binding.credential_id)?;
    atomic_private_write(&new_credential, credential_text.as_bytes())
        .map_err(InstallError::message)?;
    match install_binding(&binding_path(paths), binding_text.as_bytes()) {
        Ok(()) => {}
        Err(InstallError::NotInstalled(error)) => {
            remove_credential(&new_credential).map_err(|cleanup| {
                format!("{error}; replacement credential cleanup also failed: {cleanup}")
            })?;
            return Err(error);
        }
        Err(InstallError::InstalledButSyncFailed(error)) => {
            return Err(format!(
                "{error}; the new binding and credential remain installed and valid, but directory durability could not be confirmed"
            ));
        }
    }
    if let Some(previous) = previous
        && previous.credential_id != binding.credential_id
        && let Ok(old) = credential_path(paths, &previous.credential_id)
    {
        remove_credential(&old).map_err(|error| {
            format!(
                "Forge credential rotation completed, but old credential cleanup failed: {error}. The new binding remains valid; run forge status or remove to retry cleanup"
            )
        })?;
    }
    cleanup_orphan_credentials_unlocked(
        paths,
        Some(&binding.credential_id),
        &remove_credential,
    )?;
    Ok(())
}

fn load_binding(paths: &StorePaths) -> Result<Option<Binding>, String> {
    let path = binding_path(paths);
    if !path.exists() {
        return Ok(None);
    }
    let text = read_private(&path)?;
    let binding: Binding = toml::from_str(&text)
        .map_err(|e| format!("Cannot parse forge binding: {e}"))?;
    if binding.schema_version != SCHEMA_VERSION {
        return Err("Unsupported forge binding schema".into());
    }
    validate_repository(&binding.repository)?;
    validate_dns_name(&binding.origin.host)?;
    validate_provider_origin(binding.provider, &binding.origin)?;
    if binding.repository_id == 0
        || binding.scopes.is_empty()
        || binding
            .scopes
            .iter()
            .any(|scope| parse_scopes(scope).is_err())
    {
        return Err("Forge binding metadata is invalid".into());
    }
    if binding.origin.test_http && !cfg!(feature = "test-hooks") {
        return Err("Plain-HTTP forge binding is test-only".into());
    }
    Ok(Some(binding))
}

fn load_credential(paths: &StorePaths, id: &str) -> Result<Credential, String> {
    let text = read_private(&credential_path(paths, id)?)?;
    let credential: Credential = toml::from_str(&text)
        .map_err(|e| format!("Cannot parse forge credential: {e}"))?;
    if credential.schema_version != SCHEMA_VERSION {
        return Err("Unsupported forge credential schema".into());
    }
    Ok(credential)
}

fn remove(paths: &StorePaths) -> Result<(), String> {
    let _lock = paths.prepare()?;
    let binding = binding_path(paths);
    if binding.exists() {
        fs::remove_file(&binding)
            .map_err(|e| format!("Cannot remove {}: {e}", binding.display()))?;
    }
    let prefix = format!("{}-", credential_prefix(paths));
    let credentials = paths.root.join("credentials");
    if credentials.is_dir() {
        for entry in fs::read_dir(&credentials).map_err(|e| {
            format!("Cannot inspect {}: {e}", credentials.display())
        })? {
            let entry = entry
                .map_err(|e| format!("Cannot inspect forge credential: {e}"))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".toml") {
                fs::remove_file(entry.path()).map_err(|e| {
                    format!("Cannot remove {}: {e}", entry.path().display())
                })?;
            }
        }
    }
    Ok(())
}

fn cleanup_orphan_credentials(
    paths: &StorePaths,
    active_id: Option<&str>,
) -> Result<(), String> {
    let _lock = paths.prepare()?;
    cleanup_orphan_credentials_unlocked(paths, active_id, &|path| {
        durable_remove(path)
            .map_err(|e| format!("Cannot clean up {}: {e}", path.display()))
    })
}

fn cleanup_orphan_credentials_unlocked(
    paths: &StorePaths,
    active_id: Option<&str>,
    remove_credential: &impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let prefix = format!("{}-", credential_prefix(paths));
    let credentials = paths.root.join("credentials");
    if !credentials.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&credentials)
        .map_err(|e| format!("Cannot inspect {}: {e}", credentials.display()))?
    {
        let entry = entry
            .map_err(|e| format!("Cannot inspect forge credential: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_active =
            active_id.is_some_and(|id| name.as_ref() == format!("{id}.toml"));
        if !is_active && name.starts_with(&prefix) && name.ends_with(".toml") {
            remove_credential(&entry.path())?;
        }
    }
    Ok(())
}

fn secure_subdir(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot protect {}: {e}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|e| {
                format!("Cannot inspect {}: {e}", path.display())
            })?;
            let uid = unsafe { nix::libc::geteuid() };
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != uid
                || metadata.mode() & 0o077 != 0
            {
                return Err(format!(
                    "Unsafe forge store directory {}",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) => Err(format!("Cannot create {}: {error}", path.display())),
    }
}

#[derive(Debug)]
enum InstallError {
    NotInstalled(String),
    InstalledButSyncFailed(String),
}

fn durable_remove(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("credential path has no parent"))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(parent)?;
    fs::remove_file(path)?;
    let rc = unsafe { nix::libc::fsync(dir.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl InstallError {
    fn message(self) -> String {
        match self {
            Self::NotInstalled(message)
            | Self::InstalledButSyncFailed(message) => message,
        }
    }
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let parent = path.parent().ok_or_else(|| {
        InstallError::NotInstalled("Forge store path has no parent".to_string())
    })?;
    let temp = parent.join(format!(
        ".forge-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
            .open(parent)
            .map_err(|e| {
                InstallError::NotInstalled(format!(
                    "Cannot open forge store directory: {e}"
                ))
            })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|e| {
                InstallError::NotInstalled(format!(
                    "Cannot create forge store temporary file: {e}"
                ))
            })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| {
                InstallError::NotInstalled(format!(
                    "Cannot persist forge store file: {e}"
                ))
            })?;
        fs::rename(&temp, path).map_err(|e| {
            InstallError::NotInstalled(format!(
                "Cannot install forge store file: {e}"
            ))
        })?;
        let rc = unsafe { nix::libc::fsync(dir.as_raw_fd()) };
        if rc != 0 {
            return Err(InstallError::InstalledButSyncFailed(format!(
                "Cannot sync forge store directory: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    })();
    if matches!(result, Err(InstallError::NotInstalled(_))) {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_private(path: &Path) -> Result<Zeroizing<String>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Cannot inspect {}: {e}", path.display()))?;
    let uid = unsafe { nix::libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(format!("Unsafe forge store file {}", path.display()));
    }
    let mut text = String::new();
    file.take(256 * 1024)
        .read_to_string(&mut text)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    Ok(Zeroizing::new(text))
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot inspect private-key file: {e}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(
            "Private-key file must be a non-linked owner-only regular file"
                .into(),
        );
    }
    read_private(path)
}

struct Response {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}

fn request(
    origin: &Origin,
    allow_private: bool,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let authorization = token
        .map(|token| Zeroizing::new(format!("Bearer {token}")))
        .unwrap_or_else(|| Zeroizing::new(String::new()));
    request_with_authorization(
        origin,
        allow_private,
        method,
        path,
        authorization.as_str(),
        body,
    )
}

fn request_provider(
    provider: Provider,
    origin: &Origin,
    allow_private: bool,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let scheme = match provider {
        Provider::ForgejoRepository | Provider::GiteaFineGrained => "token",
        Provider::GithubApp | Provider::GitlabProject => "Bearer",
    };
    let authorization = Zeroizing::new(format!("{scheme} {token}"));
    request_with_authorization(
        origin,
        allow_private,
        method,
        path,
        authorization.as_str(),
        body,
    )
}

fn request_with_authorization(
    origin: &Origin,
    allow_private: bool,
    method: &str,
    path: &str,
    authorization: &str,
    body: Option<&[u8]>,
) -> Result<Response, String> {
    if !path.starts_with('/')
        || path.contains(['\r', '\n'])
        || !matches!(method, "GET" | "POST" | "DELETE")
    {
        return Err("Invalid forge request".into());
    }
    let addresses = resolve_addresses(origin, allow_private)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(TIMEOUT)).ok();
                stream.set_write_timeout(Some(TIMEOUT)).ok();
                if origin.test_http {
                    return exchange_http(
                        stream,
                        origin,
                        method,
                        path,
                        authorization,
                        body,
                    );
                }
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                let tls = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let name = rustls::pki_types::ServerName::try_from(
                    origin.host.clone(),
                )
                .map_err(|_| "Invalid forge TLS server name".to_string())?;
                let connection =
                    rustls::ClientConnection::new(Arc::new(tls), name)
                        .map_err(|e| {
                            format!("Cannot create forge TLS client: {e}")
                        })?;
                return exchange_http(
                    rustls::StreamOwned::new(connection, stream),
                    origin,
                    method,
                    path,
                    authorization,
                    body,
                );
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "Cannot connect to forge: {}",
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no approved address".into())
    ))
}

fn exchange_http(
    mut stream: impl Read + Write,
    origin: &Origin,
    method: &str,
    path: &str,
    authorization: &str,
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let body = body.unwrap_or_default();
    let mut request = Zeroizing::new(format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ai-jail/{}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
        if origin.port == 443 || (origin.test_http && origin.port == 80) {
            origin.host.clone()
        } else {
            format!("{}:{}", origin.host, origin.port)
        },
        env!("CARGO_PKG_VERSION"),
        body.len()
    ));
    if !authorization.is_empty() {
        request.push_str("Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("X-GitHub-Api-Version: 2022-11-28\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("Cannot write forge request: {e}"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    stream
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read forge response: {e}"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err("Forge response exceeds size limit".into());
    }
    let head_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Forge returned malformed HTTP".to_string())?;
    let (status, chunked) = {
        let head = std::str::from_utf8(&bytes[..head_end])
            .map_err(|_| "Forge returned non-UTF-8 HTTP headers".to_string())?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| "Forge returned invalid HTTP status".to_string())?;
        let chunked = head.lines().any(|line| {
            line.eq_ignore_ascii_case("transfer-encoding: chunked")
        });
        (status, chunked)
    };
    if (300..400).contains(&status) {
        return Err("Forge redirects are refused; approve the canonical origin explicitly".into());
    }
    let body = Zeroizing::new(bytes.split_off(head_end + 4));
    if chunked {
        return Ok(Response {
            status,
            body: decode_chunked(&body)?,
        });
    }
    Ok(Response { status, body })
}

fn decode_chunked(mut input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut result = Zeroizing::new(Vec::new());
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "Malformed chunked forge response".to_string())?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| "Invalid chunk size".to_string())?;
        let size = usize::from_str_radix(
            size_text.split(';').next().unwrap_or_default(),
            16,
        )
        .map_err(|_| "Invalid chunk size".to_string())?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(result);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err("Truncated chunked forge response".into());
        }
        result.extend_from_slice(&input[..size]);
        if result.len() > MAX_RESPONSE {
            return Err("Forge response exceeds size limit".into());
        }
        input = &input[size + 2..];
    }
}

fn resolve_addresses(
    origin: &Origin,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, String> {
    let addresses = (origin.host.as_str(), origin.port)
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve forge origin: {e}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("Forge origin resolved to no addresses".into());
    }
    for address in &addresses {
        if !(origin.test_http && cfg!(feature = "test-hooks"))
            && forbidden_address(address.ip(), allow_private)
        {
            return Err(format!(
                "Forge origin resolved to refused address {}",
                address.ip()
            ));
        }
    }
    Ok(addresses)
}

fn validate_dns_name(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("Forge origin has an invalid DNS name".into());
    }
    Ok(())
}

fn validate_repository(repository: &str) -> Result<(), String> {
    let parts = repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || part.len() > 100
                || !part.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
                })
        })
    {
        return Err("Repository must be OWNER/REPO with safe characters".into());
    }
    Ok(())
}

fn percent_encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn read_visible_line() -> Result<String, String> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("Cannot read terminal input: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn confirm(prompt: &str) -> Result<bool, String> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    Ok(matches!(read_visible_line()?.trim(), "y" | "Y"))
}

struct EchoGuard {
    fd: i32,
    original: nix::libc::termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            nix::libc::tcsetattr(self.fd, nix::libc::TCSAFLUSH, &self.original);
        }
        eprintln!();
    }
}

fn read_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let fd = io::stdin().as_raw_fd();
    let mut original = unsafe { std::mem::zeroed::<nix::libc::termios>() };
    if unsafe { nix::libc::tcgetattr(fd, &mut original) } != 0 {
        return Err("Secret input requires a terminal".into());
    }
    let mut hidden = original;
    hidden.c_lflag &= !(nix::libc::ECHO
        | nix::libc::ECHONL
        | nix::libc::ICANON
        | nix::libc::ISIG);
    hidden.c_cc[nix::libc::VMIN] = 1;
    hidden.c_cc[nix::libc::VTIME] = 0;
    if unsafe { nix::libc::tcsetattr(fd, nix::libc::TCSAFLUSH, &hidden) } != 0 {
        return Err("Cannot disable terminal echo".into());
    }
    let _guard = EchoGuard { fd, original };
    let mut bytes = Zeroizing::new(Vec::new());
    let mut input = io::stdin().lock();
    loop {
        let mut byte = [0_u8; 1];
        input
            .read_exact(&mut byte)
            .map_err(|e| format!("Cannot read secret input: {e}"))?;
        match byte[0] {
            b'\n' | b'\r' => break,
            3 | 4 | 27 => return Err("Secret input cancelled".into()),
            8 | 127 => {
                bytes.pop();
            }
            value if !value.is_ascii_control() => {
                if bytes.len() >= 8192 {
                    return Err("Forge token is too large".into());
                }
                bytes.push(value);
            }
            _ => {}
        }
    }
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| "Secret input must be UTF-8".into())
}

fn validate_github_key(pem: &str) -> Result<(), String> {
    github_rsa_key(pem).map(|_| ())
}

fn github_rsa_key(pem: &str) -> Result<signature::RsaKeyPair, String> {
    if let Ok(der) = decode_pem(pem, "RSA PRIVATE KEY")
        && let Ok(key) = signature::RsaKeyPair::from_der(&der)
    {
        return Ok(key);
    }
    if let Ok(der) = decode_pem(pem, "PRIVATE KEY")
        && let Ok(key) = signature::RsaKeyPair::from_pkcs8(&der)
    {
        return Ok(key);
    }
    Err("GitHub App key must be an unencrypted RSA private-key PEM".into())
}

fn decode_pem(pem: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or_else(|| format!("Missing {begin}"))?
        + begin.len();
    let finish = pem[start..]
        .find(&end)
        .map(|offset| start + offset)
        .ok_or_else(|| format!("Missing {end}"))?;
    let encoded = pem[start..finish]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    base64_decode(&encoded).map(Zeroizing::new)
}

fn base64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return Err("Invalid PEM base64".into());
    }
    let mut output = Vec::new();
    for chunk in input.chunks(4) {
        let a =
            value(chunk[0]).ok_or_else(|| "Invalid PEM base64".to_string())?;
        let b =
            value(chunk[1]).ok_or_else(|| "Invalid PEM base64".to_string())?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            value(chunk[2]).ok_or_else(|| "Invalid PEM base64".to_string())?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            value(chunk[3]).ok_or_else(|| "Invalid PEM base64".to_string())?
        };
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(c & 63) as usize] as char);
        }
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn forbidden_address(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => forbidden_ipv4(ip, allow_private),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return forbidden_ipv4(mapped, allow_private);
            }
            ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip
                    == "fd00:ec2::254"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("constant IPv6 address")
                || (!allow_private && (ip.segments()[0] & 0xfe00 == 0xfc00))
        }
    }
}

fn forbidden_ipv4(ip: std::net::Ipv4Addr, allow_private: bool) -> bool {
    let octets = ip.octets();
    let cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
    ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || matches!(
            octets,
            [100, 100, 100, 200]
                | [192, 0, 0, 170]
                | [192, 0, 0, 171]
                | [192, 0, 0, 192]
        )
        || (!allow_private && (ip.is_private() || cgnat))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(name: &str) -> (PathBuf, StorePaths) {
        let base =
            fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "ai-jail-forge-{name}-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("store");
        let paths = StorePaths {
            available: true,
            root: root.clone(),
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root.join("projects/project.toml"),
            legacy_global: base.join("legacy-global"),
            legacy_project: project.join(".ai-jail"),
            canonical_project: fs::canonicalize(project).unwrap(),
        };
        (base, paths)
    }

    #[cfg(feature = "test-hooks")]
    fn fake_http(response: Vec<u8>) -> Origin {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(&response).unwrap();
        });
        Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()
    }

    #[cfg(feature = "test-hooks")]
    fn fake_http_capture() -> (Origin, std::sync::mpsc::Receiver<String>) {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (send, receive) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let count = stream.read(&mut request).unwrap();
            send.send(String::from_utf8_lossy(&request[..count]).into_owned())
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        (
            Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
            receive,
        )
    }

    fn binding(provider: Provider) -> Binding {
        Binding {
            schema_version: SCHEMA_VERSION,
            provider,
            origin: Origin::parse("https://forge.example").unwrap(),
            repository_id: 42,
            repository: "owner/repo".into(),
            credential_id: "0123456789abcdef01234567".into(),
            allow_private: false,
            scope_verified: provider == Provider::GithubApp,
            scopes: vec!["repository:write".into()],
            expires_at: provider.persistent().then(|| "2099-01-01".into()),
            open_approved: provider != Provider::GithubApp,
        }
    }

    #[test]
    fn origin_rejects_credentials_paths_and_plain_http() {
        for value in [
            "https://user@forge.example",
            "https://forge.example/path",
            "https://forge.example?query",
            "https://-forge.example",
        ] {
            assert!(Origin::parse(value).is_err(), "accepted {value}");
        }
        if !cfg!(feature = "test-hooks") {
            assert!(Origin::parse("http://forge.example").is_err());
        }
        assert_eq!(
            Origin::parse("https://FORGE.example:8443")
                .unwrap()
                .display(),
            "https://forge.example:8443"
        );
    }

    #[test]
    fn network_guard_refuses_local_metadata_and_private_by_default() {
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "100.64.0.1",
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert!(forbidden_address(ip, false), "accepted {ip}");
        }
        assert!(!forbidden_address("10.0.0.1".parse().unwrap(), true));
        assert!(forbidden_address("100.100.100.200".parse().unwrap(), true));
        assert!(forbidden_address("127.0.0.1".parse().unwrap(), true));
        assert!(!forbidden_address("100.64.0.1".parse().unwrap(), true));
        assert!(forbidden_address("::ffff:127.0.0.1".parse().unwrap(), true));
    }

    #[test]
    fn binding_never_serializes_token_material() {
        let binding = binding(Provider::GitlabProject);
        let credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: Provider::GitlabProject,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("glpat-test-secret".into()),
            },
        };
        let binding_text = toml::to_string(&binding).unwrap();
        let credential_text = toml::to_string(&credential).unwrap();
        assert!(!binding_text.contains("glpat-test-secret"));
        assert!(credential_text.contains("glpat-test-secret"));
        assert_eq!(toml::from_str::<Binding>(&binding_text).unwrap(), binding);
    }

    #[test]
    fn runtime_injects_exact_path_helper_and_lockdown_strips_it() {
        let runtime = Runtime {
            binding: binding(Provider::GitlabProject),
            token: TokenGuard::persistent(Zeroizing::new(
                "synthetic-token".into(),
            )),
        };
        let mut config = Config::default();
        runtime.apply(&mut config);
        assert!(
            config
                .env_pass
                .iter()
                .any(|entry| entry == "GITLAB_TOKEN=synthetic-token")
        );
        assert!(config.env_pass.iter().any(|entry| {
            entry == "GIT_CONFIG_KEY_2=credential.https://forge.example.helper"
        }));
        let helper = config
            .env_pass
            .iter()
            .find(|entry| entry.starts_with("GIT_CONFIG_VALUE_2="))
            .unwrap();
        assert!(helper.contains("test \"$host\" = 'forge.example'"));
        assert!(helper.contains("'owner/repo'|'owner/repo.git'"));
        assert!(config.env_pass.iter().all(|entry| is_runtime_env(entry)));
        strip_runtime(&mut config);
        assert!(config.env_pass.is_empty());
    }

    #[test]
    fn git_helper_accepts_only_exact_repository_paths() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let helper = git_credential_helper("forge.example", "owner/repo");
        for (host, path, accepted) in [
            ("forge.example", "owner/repo", true),
            ("forge.example", "owner/repo.git", true),
            ("forge.example", "owner/repo2", false),
            ("forge.example", "owner/repo/nested", false),
            ("forge.example", "owner/repo?ref=main", false),
            ("evil.example", "owner/repo", false),
        ] {
            let mut child = Command::new("git")
                .args([
                    "-c",
                    "credential.helper=",
                    "-c",
                    "credential.useHttpPath=true",
                    "-c",
                    &format!(
                        "credential.https://forge.example.helper={helper}"
                    ),
                    "credential",
                    "fill",
                ])
                .env("AI_JAIL_FORGE_TOKEN", "synthetic-token")
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            write!(
                child.stdin.take().unwrap(),
                "protocol=https\nhost={host}\npath={path}\n\n"
            )
            .unwrap();
            let output = child.wait_with_output().unwrap();
            if accepted {
                assert!(output.status.success(), "{host}/{path}: {output:?}");
                let stdout = String::from_utf8(output.stdout).unwrap();
                assert!(stdout.contains("username=ai-jail\n"));
                assert!(stdout.contains("password=synthetic-token\n"));
                assert!(stdout.contains(&format!("path={path}\n")));
            } else {
                assert!(!output.status.success(), "{host}/{path}: {output:?}");
                assert!(
                    !String::from_utf8_lossy(&output.stdout)
                        .contains("synthetic-token")
                );
            }
        }
    }

    #[test]
    fn chunked_decoder_is_bounded_and_exact() {
        assert_eq!(
            decode_chunked(b"4\r\ntest\r\n3\r\n123\r\n0\r\n\r\n")
                .unwrap()
                .as_slice(),
            b"test123"
        );
        assert!(decode_chunked(b"4\r\nno").is_err());
    }

    #[test]
    fn repository_and_percent_encoding_are_strict() {
        assert!(validate_repository("owner/repo").is_ok());
        for value in ["owner", "owner/repo/extra", "../repo", "owner/re po"] {
            assert!(validate_repository(value).is_err());
        }
        assert_eq!(percent_encode("group/project"), "group%2Fproject");
        assert!(verify_repository_identity(42, 42).is_ok());
        let swapped = verify_repository_identity(42, 43).unwrap_err();
        assert!(swapped.contains("identity changed"));
    }

    #[test]
    fn runtime_debug_surfaces_do_not_contain_token() {
        let credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: Provider::ForgejoRepository,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("never-print-this".into()),
            },
        };
        // Credential deliberately has no Debug implementation. Binding and
        // runtime summaries carry metadata only.
        let runtime = Runtime {
            binding: binding(Provider::ForgejoRepository),
            token: TokenGuard::persistent(match credential.secret {
                SecretMaterial::PersistentToken { token } => {
                    token.into_zeroizing()
                }
                _ => unreachable!(),
            }),
        };
        assert!(!runtime.summary().contains("never-print-this"));
    }

    #[test]
    fn persistent_metadata_is_strict_and_openapi_detection_is_structural() {
        assert_eq!(
            parse_scopes("read_repository, issues:write").unwrap(),
            ["read_repository", "issues:write"]
        );
        assert!(parse_scopes(" ").is_err());
        assert_eq!(parse_expiry("never").unwrap(), None);
        assert!(parse_expiry("tomorrow").is_err());

        let supported = serde_json::json!({
            "definitions": {
                "CreateAccessTokenOption": {
                    "properties": { "repositories": { "type": "array" } }
                }
            }
        });
        let misleading = serde_json::json!({"description": "repositories"});
        assert!(openapi_token_schema_has_repository_selector(&supported));
        assert!(!openapi_token_schema_has_repository_selector(&misleading));
    }

    #[test]
    fn github_jwt_accepts_github_pkcs8_download_shape() {
        let pem = include_str!("../tests/fixtures/test-only-key.pem");
        validate_github_key(pem).unwrap();
        assert_eq!(github_jwt(123, pem).unwrap().split('.').count(), 3);
    }

    #[test]
    fn forge_documentation_and_provenance_do_not_drift() {
        let guide = include_str!("../docs/FORGE_AUTH.md");
        let fixture = include_str!("../tests/fixtures/forge/workflow.txt");
        assert!(guide.contains(fixture.trim()));
        let provenance = include_str!("../docs/forge-provenance.toml");
        for id in [SETUP_ID, OPEN_ID, SAVE_ID, STATUS_ID, REMOVE_ID] {
            assert!(guide.contains(id), "guide missing {id}");
            assert!(provenance.contains(id), "provenance missing {id}");
        }
        toml::from_str::<toml::Value>(provenance).unwrap();
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn fake_endpoint_verifies_numeric_id_and_refuses_redirects() {
        let body = br#"{"id":4242}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let mut binding = binding(Provider::GitlabProject);
        binding.origin = fake_http(response.into_bytes());
        binding.allow_private = true;
        assert_eq!(fetch_repository_id(&binding, "synthetic-token"), Ok(4242));

        let origin = fake_http(b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n".to_vec());
        let result = request_provider(
            Provider::GitlabProject,
            &origin,
            true,
            "GET",
            "/api/v4/projects/owner%2Frepo",
            "synthetic-token",
            None,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("redirect was accepted"),
        };
        assert!(error.contains("redirects are refused"));
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn github_runtime_attempts_normal_exit_revocation() {
        let (origin, request) = fake_http_capture();
        let mut bound = binding(Provider::GithubApp);
        bound.origin = origin;
        let token = TokenGuard::github(
            Zeroizing::new("synthetic-installation-token".into()),
            &bound,
        );
        drop(Runtime {
            binding: bound,
            token,
        });
        let request = request.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.starts_with("DELETE /installation/token HTTP/1.1\r\n"));
        assert!(request.contains(
            "\r\nAuthorization: Bearer synthetic-installation-token\r\n"
        ));
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn github_token_revokes_on_verification_failure_and_ignores_revoke_failure()
    {
        let (origin, request) = fake_http_capture();
        let mut bound = binding(Provider::GithubApp);
        bound.origin = origin;
        let guard = TokenGuard::github(
            Zeroizing::new("failed-verification-token".into()),
            &bound,
        );
        assert!(verify_repository_identity(1, 2).is_err());
        drop(guard);
        assert!(
            request
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .starts_with("DELETE /installation/token")
        );

        bound.origin = Origin::parse("http://127.0.0.1:9").unwrap();
        let guard = TokenGuard::github(
            Zeroizing::new("unreachable-revoke-token".into()),
            &bound,
        );
        drop(guard);
    }

    #[test]
    fn concurrent_store_writes_remain_private_and_parseable() {
        let (base, paths) = test_store("concurrent");
        let mut left_binding = binding(Provider::GitlabProject);
        left_binding.credential_id = credential_id(&paths).unwrap();
        let mut right_binding = binding(Provider::ForgejoRepository);
        right_binding.credential_id = credential_id(&paths).unwrap();
        let first = Credential {
            schema_version: SCHEMA_VERSION,
            provider: left_binding.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("first-synthetic-token".into()),
            },
        };
        let second = Credential {
            schema_version: SCHEMA_VERSION,
            provider: right_binding.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("second-synthetic-token".into()),
            },
        };
        let left_paths = paths.clone();
        let saved_left = left_binding.clone();
        let left = std::thread::spawn(move || {
            save(&left_paths, &saved_left, &first).unwrap()
        });
        let right_paths = paths.clone();
        let saved_right = right_binding.clone();
        let right = std::thread::spawn(move || {
            save(&right_paths, &saved_right, &second).unwrap()
        });
        left.join().unwrap();
        right.join().unwrap();

        let active = load_binding(&paths).unwrap().unwrap();
        assert!(active == left_binding || active == right_binding);
        let credential =
            load_credential(&paths, &active.credential_id).unwrap();
        assert_eq!(credential.provider, active.provider);
        for path in [
            binding_path(&paths),
            credential_path(&paths, &active.credential_id).unwrap(),
        ] {
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
        }
        let files = fs::read_dir(paths.root.join("credentials"))
            .unwrap()
            .count();
        assert_eq!(files, 1);
        let orphan_id = credential_id(&paths).unwrap();
        atomic_private_write(
            &credential_path(&paths, &orphan_id).unwrap(),
            b"orphan",
        )
        .unwrap();
        remove(&paths).unwrap();
        assert!(!binding_path(&paths).exists());
        assert_eq!(
            fs::read_dir(paths.root.join("credentials"))
                .unwrap()
                .count(),
            0
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn failed_rotation_preserves_prior_binding_and_credential() {
        let (base, paths) = test_store("failed-rotation");
        let mut prior = binding(Provider::GitlabProject);
        prior.credential_id = credential_id(&paths).unwrap();
        let prior_credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: prior.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("prior-token".into()),
            },
        };
        save(&paths, &prior, &prior_credential).unwrap();

        let mut replacement = binding(Provider::ForgejoRepository);
        replacement.credential_id = credential_id(&paths).unwrap();
        let replacement_credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: replacement.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("replacement-token".into()),
            },
        };
        assert!(
            save_with(
                &paths,
                &replacement,
                &replacement_credential,
                |_, _| {
                    Err(InstallError::NotInstalled(
                        "injected binding install failure".into(),
                    ))
                },
                |path| {
                    fs::remove_file(path).map_err(|error| error.to_string())
                },
            )
            .is_err()
        );
        assert_eq!(load_binding(&paths).unwrap(), Some(prior.clone()));
        assert!(
            credential_path(&paths, &prior.credential_id)
                .unwrap()
                .is_file()
        );
        assert!(
            !credential_path(&paths, &replacement.credential_id)
                .unwrap()
                .exists()
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn post_rename_sync_failure_keeps_installed_binding_credential_pair() {
        let (base, paths) = test_store("post-rename-sync");
        let mut replacement = binding(Provider::ForgejoRepository);
        replacement.credential_id = credential_id(&paths).unwrap();
        let replacement_credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: replacement.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("replacement-token".into()),
            },
        };
        let error = save_with(
            &paths,
            &replacement,
            &replacement_credential,
            |path, bytes| {
                atomic_private_write(path, bytes).unwrap();
                Err(InstallError::InstalledButSyncFailed(
                    "injected post-rename directory sync failure".into(),
                ))
            },
            |path| fs::remove_file(path).map_err(|error| error.to_string()),
        )
        .unwrap_err();
        assert!(error.contains("remain installed and valid"));
        assert_eq!(load_binding(&paths).unwrap(), Some(replacement.clone()));
        assert!(load_credential(&paths, &replacement.credential_id).is_ok());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn old_credential_deletion_failure_leaves_valid_new_pair_for_cleanup() {
        let (base, paths) = test_store("old-delete-failure");
        let mut prior = binding(Provider::GitlabProject);
        prior.credential_id = credential_id(&paths).unwrap();
        let prior_credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: prior.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("prior-token".into()),
            },
        };
        save(&paths, &prior, &prior_credential).unwrap();

        let mut replacement = binding(Provider::ForgejoRepository);
        replacement.credential_id = credential_id(&paths).unwrap();
        let replacement_credential = Credential {
            schema_version: SCHEMA_VERSION,
            provider: replacement.provider,
            secret: SecretMaterial::PersistentToken {
                token: SecretString::new("replacement-token".into()),
            },
        };
        let error = save_with(
            &paths,
            &replacement,
            &replacement_credential,
            atomic_private_write,
            |_| Err("injected deletion refusal".into()),
        )
        .unwrap_err();
        assert!(error.contains("new binding remains valid"));
        assert_eq!(load_binding(&paths).unwrap(), Some(replacement.clone()));
        assert!(load_credential(&paths, &replacement.credential_id).is_ok());
        assert!(
            credential_path(&paths, &prior.credential_id)
                .unwrap()
                .is_file()
        );

        cleanup_orphan_credentials(&paths, Some(&replacement.credential_id))
            .unwrap();
        assert!(
            !credential_path(&paths, &prior.credential_id)
                .unwrap()
                .exists()
        );
        assert!(load_credential(&paths, &replacement.credential_id).is_ok());
        fs::remove_dir_all(base).unwrap();
    }
}
