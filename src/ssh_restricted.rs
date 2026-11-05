//! Selected-key SSH forwarding through a fresh, launch-scoped agent.
//!
//! Private keys stay on the host. The jail receives only a dedicated agent
//! socket and generated public SSH configuration.

use crate::config::Config;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{
    FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(crate) const JAIL_AGENT_SOCKET: &str = "/tmp/ai-jail-ssh-agent.sock";
pub(crate) const JAIL_PUBLIC_DIR: &str = "/tmp/ai-jail-ssh-public";
pub(crate) const DEFAULT_LIFETIME_SECONDS: u32 = 3600;
static PLAN_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn is_runtime_env(entry: &str) -> bool {
    entry == format!("SSH_AUTH_SOCK={JAIL_AGENT_SOCKET}")
        || (entry.starts_with("SSH_AUTH_SOCK=/tmp/ai-jail-ssh-")
            && entry.ends_with("/agent.sock"))
        || (entry.starts_with("GIT_SSH_COMMAND=/")
            && entry.contains("/ssh -F /tmp/ai-jail-ssh-"))
        || (entry.starts_with("GIT_SSH_COMMAND=/")
            && entry.ends_with(" -F /tmp/ai-jail-ssh-public/config"))
        || entry.starts_with("AI_JAIL_SSH=/")
        || entry.starts_with("AI_JAIL_SSH_CONFIG=/tmp/ai-jail-ssh-")
        || entry == format!("AI_JAIL_SSH_CONFIG={JAIL_PUBLIC_DIR}/config")
}

pub(crate) fn is_runtime_map(config: &Config, encoded: &Path) -> bool {
    if !config.env_pass.iter().any(|entry| is_runtime_env(entry)) {
        return false;
    }
    let Ok(candidate) = crate::config::MapSpec::parse(encoded) else {
        return false;
    };
    let base = config
        .rw_maps
        .iter()
        .filter_map(|entry| crate::config::MapSpec::parse(entry).ok())
        .find_map(|entry| {
            let destination_matches = entry.destination
                == Path::new(JAIL_AGENT_SOCKET)
                || entry.source.ends_with("agent.sock");
            destination_matches
                .then(|| entry.source.parent().map(Path::to_path_buf))
                .flatten()
        });
    base.is_some_and(|base| {
        candidate.source == base.join("agent.sock")
            || candidate.source == base.join("public")
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyIdentity {
    pub(crate) private_path: PathBuf,
    pub(crate) public_path: PathBuf,
    pub(crate) fingerprint: String,
    #[serde(default)]
    pub(crate) comment: String,
    pub(crate) private_dev: u64,
    pub(crate) private_ino: u64,
    pub(crate) public_dev: u64,
    pub(crate) public_ino: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub(crate) keys: Vec<KeyIdentity>,
    #[serde(default = "default_lifetime")]
    pub(crate) lifetime_seconds: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) destinations: Vec<String>,
}

fn default_lifetime() -> u32 {
    DEFAULT_LIFETIME_SECONDS
}

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    policy: Policy,
    base: PathBuf,
    public_dir: PathBuf,
    socket: PathBuf,
    known_hosts: String,
    tools: Toolset,
}

#[derive(Clone, Debug)]
struct Toolset {
    keygen: TrustedTool,
    agent: TrustedTool,
    add: TrustedTool,
    ssh: TrustedTool,
}

#[derive(Clone, Debug)]
struct TrustedTool {
    path: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    digest: [u8; 32],
    #[cfg(test)]
    test_fixture: bool,
    #[cfg(feature = "test-hooks")]
    test_hook: bool,
}

impl TrustedTool {
    fn verify(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|e| format!("Trusted SSH tool disappeared: {e}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || metadata.uid() != self.uid
            || metadata.mode() != self.mode
            || tool_digest(&self.path)? != self.digest
        {
            return Err("Trusted SSH tool changed after validation".into());
        }
        #[cfg(test)]
        if self.test_fixture {
            return Ok(());
        }
        #[cfg(feature = "test-hooks")]
        if self.test_hook {
            return Ok(());
        }
        validate_trusted_chain(&self.path)
    }

    #[cfg(test)]
    fn fixture(path: PathBuf) -> Self {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let digest = tool_digest(&path).unwrap();
        Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            digest,
            test_fixture: true,
            #[cfg(feature = "test-hooks")]
            test_hook: false,
        }
    }
}

pub(crate) struct Runtime {
    child: Child,
    base: PathBuf,
}

struct StagingCleanup {
    base: PathBuf,
    armed: bool,
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        crate::signals::clear_child_pid_if(self.child.id() as i32);
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Toolset {
    fn resolve() -> Result<Self, String> {
        Ok(Self {
            keygen: resolve_tool("ssh-keygen")?,
            agent: resolve_tool("ssh-agent")?,
            add: resolve_tool("ssh-add")?,
            ssh: resolve_tool("ssh")?,
        })
    }
}

fn resolve_tool(name: &str) -> Result<TrustedTool, String> {
    #[cfg(feature = "test-hooks")]
    if let Some(directory) = std::env::var_os("AI_JAIL_TEST_SSH_TOOL_DIR") {
        let path = PathBuf::from(directory).join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Cannot inspect test SSH tool: {e}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.mode() & 0o111 == 0
        {
            return Err(
                "Test SSH tool must be a regular executable file".into()
            );
        }
        return Ok(TrustedTool {
            path: path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            digest: tool_digest(&path)?,
            #[cfg(test)]
            test_fixture: false,
            test_hook: true,
        });
    }
    const PREFIXES: &[&str] =
        &["/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"];
    for prefix in PREFIXES {
        let presented = Path::new(prefix).join(name);
        let Ok(path) = fs::canonicalize(&presented) else {
            continue;
        };
        if validate_trusted_chain(&path).is_err() {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o022 != 0
        {
            continue;
        }
        let euid = unsafe { nix::libc::geteuid() };
        if metadata.uid() != 0 && metadata.uid() != euid {
            continue;
        }
        let digest = tool_digest(&path)?;
        return Ok(TrustedTool {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            digest,
            #[cfg(test)]
            test_fixture: false,
            #[cfg(feature = "test-hooks")]
            test_hook: false,
        });
    }
    Err(format!(
        "No trusted {name} found in standard Linux/macOS/Homebrew locations"
    ))
}

fn tool_digest(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Cannot read trusted SSH tool: {e}"))?;
    Ok(Sha256::digest(bytes).into())
}

fn validate_trusted_chain(path: &Path) -> Result<(), String> {
    let euid = unsafe { nix::libc::geteuid() };
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|e| format!("Cannot inspect SSH tool directory: {e}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.mode() & 0o022 != 0
            || (metadata.uid() != 0 && metadata.uid() != euid)
        {
            return Err(
                "SSH tool has an untrusted writable parent directory".into()
            );
        }
        parent = directory.parent();
    }
    Ok(())
}

pub(crate) fn capture_key(path: &Path) -> Result<KeyIdentity, String> {
    let keygen = resolve_tool("ssh-keygen")?;
    capture_key_with(path, |public| {
        keygen.verify()?;
        let output = Command::new(&keygen.path)
            .args(["-l", "-E", "sha256", "-f"])
            .arg(public)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Cannot run ssh-keygen: {e}"))?;
        if !output.status.success() {
            return Err("ssh-keygen could not read the public key".into());
        }
        String::from_utf8(output.stdout)
            .map_err(|_| "ssh-keygen returned non-UTF-8 output".to_string())
    })
}

fn capture_key_with(
    path: &Path,
    fingerprint: impl FnOnce(&Path) -> Result<String, String>,
) -> Result<KeyIdentity, String> {
    let (private_path, public_path) =
        if path.extension().is_some_and(|x| x == "pub") {
            (path.with_extension(""), path.to_path_buf())
        } else {
            (
                path.to_path_buf(),
                PathBuf::from(format!("{}.pub", path.display())),
            )
        };
    validate_presented_key(&private_path, "private")?;
    validate_presented_key(&public_path, "public")?;
    let private_path = fs::canonicalize(&private_path)
        .map_err(|e| format!("SSH private key is unavailable: {e}"))?;
    let public_path = fs::canonicalize(&public_path)
        .map_err(|e| format!("SSH public key is unavailable: {e}"))?;
    let private = fs::symlink_metadata(&private_path)
        .map_err(|e| format!("Cannot inspect SSH private key: {e}"))?;
    let public = fs::symlink_metadata(&public_path)
        .map_err(|e| format!("Cannot inspect SSH public key: {e}"))?;
    if !private.is_file()
        || private.file_type().is_symlink()
        || private.nlink() != 1
    {
        return Err("SSH private key must be a regular, non-linked file".into());
    }
    if !public.is_file()
        || public.file_type().is_symlink()
        || public.nlink() != 1
    {
        return Err("SSH public key must be a regular, non-linked file".into());
    }
    let output = fingerprint(&public_path)?;
    let parts: Vec<_> = output.split_whitespace().collect();
    let fingerprint_index = parts
        .iter()
        .position(|part| part.starts_with("SHA256:"))
        .ok_or_else(|| {
            "ssh-keygen did not return a SHA256 fingerprint".to_string()
        })?;
    let fingerprint = parts[fingerprint_index].to_string();
    let comment = parts
        .iter()
        .skip(fingerprint_index + 1)
        .take_while(|part| !part.starts_with('('))
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    Ok(KeyIdentity {
        private_path,
        public_path,
        fingerprint,
        comment,
        private_dev: private.dev(),
        private_ino: private.ino(),
        public_dev: public.dev(),
        public_ino: public.ino(),
    })
}

fn validate_presented_key(path: &Path, kind: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("SSH {kind} key is unavailable: {e}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
    {
        return Err(format!(
            "SSH {kind} key must be a regular, non-linked file"
        ));
    }
    Ok(())
}

pub(crate) fn validate_policy(policy: &Policy) -> Result<(), String> {
    if policy.keys.is_empty() {
        return Err("Restricted SSH has no selected key".into());
    }
    if !(60..=86_400).contains(&policy.lifetime_seconds) {
        return Err(
            "Restricted SSH lifetime must be between 60 and 86400 seconds"
                .into(),
        );
    }
    if policy.destinations.is_empty() {
        return Err("Selected-key SSH requires at least one verified destination; unconstrained agent authority is not an ALLOWED grant".into());
    }
    for key in &policy.keys {
        let current = capture_key(&key.private_path)?;
        if &current != key {
            return Err(format!(
                "{} Selected SSH key {} moved or changed; access was refused",
                crate::onboarding::messages::SSH_DRIFT_ID,
                crate::onboarding::safe_path(&key.public_path)
                    .unwrap_or_else(|_| "[unsafe path]".into())
            ));
        }
    }
    for destination in &policy.destinations {
        validate_destination(destination)?;
    }
    Ok(())
}

fn validate_destination(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'-' | b'_' | b'@' | b'>')
        })
    {
        return Err("SSH destination contains unsupported characters".into());
    }
    Ok(())
}

pub(crate) fn destination_host(value: &str) -> &str {
    let endpoint = value.rsplit('>').next().unwrap_or(value);
    endpoint.rsplit('@').next().unwrap_or(endpoint)
}

pub(crate) fn plan(
    policy: Policy,
    config: &mut Config,
    home: &Path,
) -> Result<Plan, String> {
    validate_policy(&policy)?;
    plan_validated(policy, config, home)
}

fn plan_validated(
    policy: Policy,
    config: &mut Config,
    home: &Path,
) -> Result<Plan, String> {
    let tools = Toolset::resolve()?;
    let id = PLAN_ID.fetch_add(1, Ordering::Relaxed);
    let base = Path::new("/tmp")
        .join(format!("ai-jail-ssh-{}-{id}", std::process::id()));
    let public_dir = base.join("public");
    let socket = base.join("agent.sock");
    let known_hosts =
        collect_known_hosts(&policy.destinations, home, &tools.keygen)?;
    config.ssh = Some(false);
    config.env_pass.retain(|entry| {
        entry != "SSH_AUTH_SOCK"
            && !entry.starts_with("SSH_AUTH_SOCK=")
            && entry != "GIT_SSH"
            && !entry.starts_with("GIT_SSH=")
            && entry != "GIT_SSH_COMMAND"
            && !entry.starts_with("GIT_SSH_COMMAND=")
            && entry != "AI_JAIL_SSH"
            && !entry.starts_with("AI_JAIL_SSH=")
            && entry != "AI_JAIL_SSH_CONFIG"
            && !entry.starts_with("AI_JAIL_SSH_CONFIG=")
    });
    #[cfg(target_os = "linux")]
    {
        config
            .env_pass
            .push(format!("SSH_AUTH_SOCK={JAIL_AGENT_SOCKET}"));
        config.rw_maps.push(PathBuf::from(format!(
            "{}:{JAIL_AGENT_SOCKET}",
            socket.display()
        )));
        config.ro_maps.push(PathBuf::from(format!(
            "{}:{JAIL_PUBLIC_DIR}",
            public_dir.display()
        )));
        config.env_pass.push(format!(
            "GIT_SSH_COMMAND={} -F {JAIL_PUBLIC_DIR}/config",
            tools.ssh.path.display()
        ));
        config
            .env_pass
            .push(format!("AI_JAIL_SSH={}", tools.ssh.path.display()));
        config
            .env_pass
            .push(format!("AI_JAIL_SSH_CONFIG={JAIL_PUBLIC_DIR}/config"));
    }
    #[cfg(target_os = "macos")]
    {
        let socket_text = socket.to_str().ok_or_else(|| {
            "Restricted SSH socket path is not UTF-8".to_string()
        })?;
        let config_path = public_dir.join("config");
        let config_text = config_path.to_str().ok_or_else(|| {
            "Restricted SSH config path is not UTF-8".to_string()
        })?;
        config.env_pass.push(format!("SSH_AUTH_SOCK={socket_text}"));
        config.env_pass.push(format!(
            "GIT_SSH_COMMAND={} -F {config_text}",
            tools.ssh.path.display()
        ));
        config
            .env_pass
            .push(format!("AI_JAIL_SSH={}", tools.ssh.path.display()));
        config
            .env_pass
            .push(format!("AI_JAIL_SSH_CONFIG={config_text}"));
        config.rw_maps.push(socket.clone());
        config.ro_maps.push(public_dir.clone());
    }
    Ok(Plan {
        policy,
        base,
        public_dir,
        socket,
        known_hosts,
        tools,
    })
}

fn collect_known_hosts(
    destinations: &[String],
    home: &Path,
    keygen: &TrustedTool,
) -> Result<String, String> {
    let source = home.join(".ssh/known_hosts");
    let bytes = read_known_hosts_safely(&source)?;
    if destinations.is_empty() {
        if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
            return Err("Any-host restricted SSH requires a non-empty known_hosts under 8 MiB".into());
        }
        return String::from_utf8(bytes)
            .map_err(|_| "known_hosts is not UTF-8".into());
    }
    keygen.verify()?;
    let snapshot = Path::new("/tmp").join(format!(
        "ai-jail-known-hosts-{}-{}",
        std::process::id(),
        PLAN_ID.fetch_add(1, Ordering::Relaxed)
    ));
    write_private(&snapshot, &bytes)?;
    let result =
        collect_known_hosts_with(destinations, &keygen.path, &snapshot);
    let _ = fs::remove_file(snapshot);
    result
}

fn read_known_hosts_safely(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("Cannot open known_hosts safely: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Cannot inspect known_hosts: {e}"))?;
    let euid = unsafe { nix::libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != euid
        || metadata.mode() & 0o022 != 0
    {
        return Err("known_hosts must be a user-owned, non-linked, non-writable-by-others regular file".into());
    }
    if metadata.len() > 8 * 1024 * 1024 {
        return Err("known_hosts exceeds the 8 MiB safety limit".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read trusted known_hosts: {e}"))?;
    Ok(bytes)
}

fn collect_known_hosts_with(
    destinations: &[String],
    ssh_keygen: &Path,
    source: &Path,
) -> Result<String, String> {
    let mut result = String::new();
    for destination in destinations {
        let host = destination_host(destination);
        let output = Command::new(ssh_keygen)
            .args(["-F", host, "-f"])
            .arg(source)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| {
                format!("Cannot verify SSH destination {host}: {e}")
            })?;
        if !output.status.success() {
            return Err(format!(
                "No verified known_hosts entry for SSH destination {host}"
            ));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| {
            "known_hosts lookup returned non-UTF-8 output".to_string()
        })?;
        let lines: Vec<_> = text
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect();
        if lines.is_empty() {
            return Err(format!(
                "No verified known_hosts entry for SSH destination {host}"
            ));
        }
        for line in lines {
            result.push_str(line);
            result.push('\n');
        }
    }
    Ok(result)
}

impl Plan {
    pub(crate) fn start(&self) -> Result<Runtime, String> {
        validate_policy(&self.policy)?;
        self.start_validated()
    }

    fn start_validated(&self) -> Result<Runtime, String> {
        crate::signals::abort_if_cancelled()?;
        self.tools.agent.verify()?;
        self.tools.add.verify()?;
        self.tools.ssh.verify()?;
        if self.base.exists() {
            return Err("Restricted SSH runtime path already exists".into());
        }
        let mut staging = StagingCleanup {
            base: self.base.clone(),
            armed: true,
        };
        fs::create_dir(&self.base).map_err(|e| {
            format!("Cannot create restricted SSH runtime: {e}")
        })?;
        fs::set_permissions(&self.base, fs::Permissions::from_mode(0o700))
            .map_err(|e| {
                format!("Cannot protect restricted SSH runtime: {e}")
            })?;
        fs::create_dir(&self.public_dir)
            .map_err(|e| format!("Cannot create public SSH directory: {e}"))?;
        fs::set_permissions(
            &self.public_dir,
            fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| format!("Cannot protect public SSH directory: {e}"))?;
        write_private(
            &self.public_dir.join("known_hosts"),
            self.known_hosts.as_bytes(),
        )?;
        write_private(&self.public_dir.join("global_known_hosts"), b"")?;
        #[cfg(target_os = "linux")]
        let identity_agent = JAIL_AGENT_SOCKET.to_string();
        #[cfg(target_os = "macos")]
        let identity_agent = self.socket.to_string_lossy().into_owned();
        #[cfg(target_os = "linux")]
        let config_root = JAIL_PUBLIC_DIR.to_string();
        #[cfg(target_os = "macos")]
        let config_root = self.public_dir.to_string_lossy().into_owned();
        write_private(
            &self.public_dir.join("config"),
            render_config(&identity_agent, &config_root).as_bytes(),
        )?;
        crate::signals::abort_if_cancelled()?;
        let child = Command::new(&self.tools.agent.path)
            .env_clear()
            .args(["-D", "-a"])
            .arg(&self.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Cannot start restricted ssh-agent: {e}"))?;
        crate::signals::set_child_pid(child.id() as i32);
        let mut runtime = Runtime {
            child,
            base: self.base.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.socket.exists() {
            crate::signals::abort_if_cancelled()?;
            if runtime
                .child
                .try_wait()
                .map_err(|e| {
                    format!("Cannot supervise restricted ssh-agent: {e}")
                })?
                .is_some()
            {
                return Err(
                    "Restricted ssh-agent exited before creating its socket"
                        .into(),
                );
            }
            if Instant::now() >= deadline {
                return Err(
                    "Restricted ssh-agent did not create its socket".into()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        crate::signals::abort_if_cancelled()?;
        if !fs::symlink_metadata(&self.socket)
            .map_err(|e| {
                format!("Cannot inspect restricted agent socket: {e}")
            })?
            .file_type()
            .is_socket()
        {
            return Err("Restricted ssh-agent path is not a Unix socket".into());
        }
        self.load_keys()?;
        crate::signals::abort_if_cancelled()?;
        staging.armed = false;
        Ok(runtime)
    }

    fn load_keys(&self) -> Result<(), String> {
        self.tools.add.verify()?;
        let constrained = !self.policy.destinations.is_empty();
        if constrained
            && !ssh_add_supports_destination_constraints(&self.tools.add.path)?
        {
            return Err("This ssh-add does not support destination constraints; restricted SSH was not opened".into());
        }
        for key in &self.policy.keys {
            self.tools.add.verify()?;
            let mut command = Command::new(&self.tools.add.path);
            command
                .env_clear()
                .env("SSH_AUTH_SOCK", &self.socket)
                .env("SSH_ASKPASS_REQUIRE", "never")
                .args(["-t", &self.policy.lifetime_seconds.to_string()]);
            if constrained {
                command
                    .args(["-H"])
                    .arg(self.public_dir.join("known_hosts"));
                for destination in &self.policy.destinations {
                    command.args(["-h", destination]);
                }
            }
            let status = command
                .arg(&key.private_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("Cannot run ssh-add: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "ssh-add refused selected key {}",
                    crate::onboarding::safe_path(&key.public_path)
                        .unwrap_or_else(|_| "[unsafe path]".into())
                ));
            }
        }
        self.tools.add.verify()?;
        let output = Command::new(&self.tools.add.path)
            .env_clear()
            .env("SSH_AUTH_SOCK", &self.socket)
            .arg("-l")
            .output()
            .map_err(|e| format!("Cannot verify restricted ssh-agent: {e}"))?;
        if !output.status.success() {
            return Err(
                "Cannot verify keys loaded into restricted ssh-agent".into()
            );
        }
        let listing = String::from_utf8_lossy(&output.stdout);
        let loaded: Vec<_> = listing
            .split_whitespace()
            .filter(|part| part.starts_with("SHA256:"))
            .collect();
        if loaded.len() != self.policy.keys.len()
            || self
                .policy
                .keys
                .iter()
                .any(|key| !loaded.contains(&key.fingerprint.as_str()))
        {
            return Err(
                "Restricted ssh-agent loaded an unexpected identity".into()
            );
        }
        Ok(())
    }
}

fn render_config(identity_agent: &str, config_root: &str) -> String {
    format!(
        "Host *\n  IdentityAgent {identity_agent}\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {config_root}/known_hosts\n  GlobalKnownHostsFile {config_root}/global_known_hosts\n"
    )
}

fn ssh_add_supports_destination_constraints(
    executable: &Path,
) -> Result<bool, String> {
    let output = Command::new(executable)
        .arg("-?")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("Cannot inspect ssh-add capabilities: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(text.contains("-h destination_constraint")
        && text.contains("-H hostkey_file"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn add_known_hosts(home: &Path) {
        fs::create_dir_all(home.join(".ssh")).unwrap();
        let path = home.join(".ssh/known_hosts");
        fs::write(&path, "example.test ssh-ed25519 AAAATEST\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn capture_refuses_linked_private_key_and_parses_fingerprint() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-ssh-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let private = root.join("id_test");
        let public = root.join("id_test.pub");
        fs::write(&private, "private-test-fixture").unwrap();
        fs::write(&public, "ssh-ed25519 AAAATEST fixture").unwrap();
        let captured = capture_key_with(&public, |_| {
            Ok("256 SHA256:fixture fingerprint (ED25519)\n".into())
        })
        .unwrap();
        assert_eq!(captured.fingerprint, "SHA256:fixture");
        let link = root.join("linked");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        let error = capture_key_with(&link, |_| Ok("256 SHA256:x x".into()))
            .unwrap_err();
        assert!(
            error.contains("public key is unavailable")
                || error.contains("non-linked")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_disables_ambient_ssh_and_maps_only_generated_resources() {
        let _env_lock = crate::test_utils::ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir()
            .join(format!("ai-jail-ssh-plan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let private = root.join("id_test");
        let public = root.join("id_test.pub");
        fs::write(&private, "private-test-fixture").unwrap();
        fs::write(&public, "public-test-fixture").unwrap();
        add_known_hosts(&root);
        let hostile_tmp = root.join("hostile tmp\ncontrol");
        let _tmpdir =
            crate::test_utils::EnvVarGuard::set("TMPDIR", &hostile_tmp);
        let key =
            capture_key_with(&private, |_| Ok("256 SHA256:fixture x".into()))
                .unwrap();
        let mut config = Config {
            ssh: Some(true),
            env_pass: vec![
                "SSH_AUTH_SOCK=/ambient".into(),
                "GIT_SSH=/project/ssh".into(),
                "GIT_SSH_COMMAND=ssh -o StrictHostKeyChecking=no".into(),
                "AI_JAIL_SSH=/project/ssh".into(),
            ],
            ..Config::default()
        };
        let policy = Policy {
            keys: vec![key],
            lifetime_seconds: 600,
            destinations: vec![],
        };
        let planned = plan_validated(policy, &mut config, &root).unwrap();
        assert_eq!(config.ssh, Some(false));
        assert!(config.env_pass.iter().any(|v| is_runtime_env(v)));
        assert!(!config.env_pass.iter().any(|v| v.contains("/ambient")));
        assert!(!config.env_pass.iter().any(|v| v.contains("/project/ssh")));
        assert_eq!(planned.base.parent(), Some(Path::new("/tmp")));
        #[cfg(target_os = "linux")]
        assert!(
            config
                .rw_maps
                .iter()
                .any(|v| v.to_string_lossy().contains(JAIL_AGENT_SOCKET))
        );
        assert!(!config.ro_maps.iter().any(|v| v == &private));
        assert_eq!(planned.policy.lifetime_seconds, 600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fake_ssh_add_receives_only_selected_key_lifetime_and_constraints() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-add-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let log = root.join("args.log");
        let script = root.join("ssh-add");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = '-?' ]; then echo 'usage: -h destination_constraint -H hostkey_file' >&2; exit 1; fi\nif [ \"$1\" = '-l' ]; then echo '256 SHA256:fixture selected (ED25519)'; fi\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .unwrap();
        let private = root.join("id_selected");
        let public = root.join("id_selected.pub");
        fs::write(&private, "private fixture never read by ai-jail").unwrap();
        fs::write(&public, "public fixture").unwrap();
        add_known_hosts(&root);
        let key = capture_key_with(&private, |_| {
            Ok("256 SHA256:fixture selected (ED25519)".into())
        })
        .unwrap();
        let mut config = Config::default();
        let mut plan = plan_validated(
            Policy {
                keys: vec![key],
                lifetime_seconds: 600,
                destinations: vec![],
            },
            &mut config,
            &root,
        )
        .unwrap();
        plan.policy.destinations = vec!["git@example.test".into()];
        plan.tools.add = TrustedTool::fixture(script);
        plan.public_dir = root.join("public");
        fs::create_dir(&plan.public_dir).unwrap();
        fs::write(plan.public_dir.join("known_hosts"), "host key fixture\n")
            .unwrap();
        plan.load_keys().unwrap();
        let args = fs::read_to_string(log).unwrap();
        assert!(args.contains("-t 600"));
        assert!(args.contains("-H"));
        assert!(args.contains("-h git@example.test"));
        assert!(args.contains(private.to_str().unwrap()));
        assert!(!args.contains("-c"));
        assert!(!args.contains("SSH_AUTH_SOCK"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_fake_agent_start_removes_runtime_directory() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-agent-fail-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let private = root.join("id_selected");
        let public = root.join("id_selected.pub");
        fs::write(&private, "private fixture").unwrap();
        fs::write(&public, "public fixture").unwrap();
        add_known_hosts(&root);
        let key = capture_key_with(&private, |_| {
            Ok("256 SHA256:fixture selected (ED25519)".into())
        })
        .unwrap();
        let mut config = Config::default();
        let mut plan = plan_validated(
            Policy {
                keys: vec![key],
                lifetime_seconds: 600,
                destinations: vec![],
            },
            &mut config,
            &root,
        )
        .unwrap();
        let script = root.join("ssh-agent-fake");
        fs::write(&script, "#!/bin/sh\nexit 7\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .unwrap();
        plan.tools.agent = TrustedTool::fixture(script);
        let base = plan.base.clone();
        assert!(plan.start_validated().is_err());
        assert!(!base.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fake_keygen_limits_known_hosts_copy_to_approved_destination() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-keygen-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let script = root.join("ssh-keygen");
        let log = root.join("args.log");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nprintf '# Host example.test found: line 1\\nexample.test ssh-ed25519 AAAATEST\\n'\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .unwrap();
        let source = root.join("known_hosts");
        fs::write(&source, "host fixture").unwrap();
        let copied = collect_known_hosts_with(
            &["git@example.test".into()],
            &script,
            &source,
        )
        .unwrap();
        assert_eq!(copied, "example.test ssh-ed25519 AAAATEST\n");
        let args = fs::read_to_string(log).unwrap();
        assert!(args.contains("-F example.test -f"));
        assert!(args.contains(source.to_str().unwrap()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trusted_tool_resolution_ignores_a_path_lookalike() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-path-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let marker = root.join("executed");
        let lookalike = root.join("ssh-keygen");
        fs::write(
            &lookalike,
            format!("#!/bin/sh\ntouch '{}'\nexit 99\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&lookalike, fs::Permissions::from_mode(0o700))
            .unwrap();
        let tool = resolve_tool("ssh-keygen").unwrap();
        assert!(tool.path.is_absolute());
        assert!(!tool.path.starts_with(&root));
        tool.verify().unwrap();
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trusted_tool_revalidation_refuses_identity_drift_and_symlink_swap() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-tool-drift-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ssh-add");
        fs::write(&path, "fixture one").unwrap();
        let tool = TrustedTool::fixture(path.clone());
        fs::remove_file(&path).unwrap();
        fs::write(&path, "fixture two").unwrap();
        assert!(tool.verify().is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("target", &path).unwrap();
        assert!(tool.verify().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn presented_private_and_public_symlinks_are_refused_before_canonicalize() {
        let root = std::env::temp_dir().join(format!(
            "ai-jail-ssh-symlinks-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let real_private = root.join("real");
        let real_public = root.join("real.pub");
        fs::write(&real_private, "private").unwrap();
        fs::write(&real_public, "public").unwrap();
        let linked_private = root.join("linked");
        let linked_public = root.join("linked.pub");
        std::os::unix::fs::symlink(&real_private, &linked_private).unwrap();
        fs::write(&linked_public, "public").unwrap();
        assert!(
            capture_key_with(&linked_private, |_| Ok("256 SHA256:x x".into()))
                .unwrap_err()
                .contains("private key must")
        );
        fs::remove_file(&linked_private).unwrap();
        fs::write(&linked_private, "private").unwrap();
        fs::remove_file(&linked_public).unwrap();
        std::os::unix::fs::symlink(&real_public, &linked_public).unwrap();
        assert!(
            capture_key_with(&linked_private, |_| Ok("256 SHA256:x x".into()))
                .unwrap_err()
                .contains("public key must")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_config_always_uses_strict_host_key_files() {
        let rendered = render_config(JAIL_AGENT_SOCKET, JAIL_PUBLIC_DIR);
        assert!(rendered.contains("StrictHostKeyChecking yes"));
        assert!(rendered.contains(
            "UserKnownHostsFile /tmp/ai-jail-ssh-public/known_hosts"
        ));
        assert!(!rendered.contains("StrictHostKeyChecking no"));
        assert!(!rendered.contains("/dev/null"));
    }

    #[test]
    fn unconstrained_selected_key_policy_is_refused() {
        let policy = Policy {
            keys: vec![KeyIdentity {
                private_path: "/unused/private".into(),
                public_path: "/unused/public".into(),
                fingerprint: "SHA256:unused".into(),
                comment: String::new(),
                private_dev: 0,
                private_ino: 0,
                public_dev: 0,
                public_ino: 0,
            }],
            lifetime_seconds: 600,
            destinations: Vec::new(),
        };
        let error = validate_policy(&policy).unwrap_err();
        assert!(error.contains("at least one verified destination"));
        assert!(error.contains("not an ALLOWED grant"));
    }

    #[test]
    fn runtime_drop_kills_child_and_removes_private_directory() {
        let base = std::env::temp_dir().join(format!(
            "ai-jail-ssh-runtime-drop-{}-{}",
            std::process::id(),
            PLAN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        crate::signals::set_child_pid(pid);
        drop(Runtime {
            child,
            base: base.clone(),
        });
        assert!(!base.exists());
    }
}
