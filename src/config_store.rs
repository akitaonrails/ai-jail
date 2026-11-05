//! Trusted external configuration store and legacy `.ai-jail` migration.

use crate::config::{self, Config, GlobalConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
    DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Path, PathBuf};

pub(crate) const MIGRATION_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub(crate) struct StorePaths {
    pub(crate) available: bool,
    pub(crate) root: PathBuf,
    pub(crate) global: PathBuf,
    pub(crate) global_provenance: PathBuf,
    pub(crate) project: PathBuf,
    pub(crate) legacy_global: PathBuf,
    pub(crate) legacy_project: PathBuf,
    pub(crate) canonical_project: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectIdentity {
    pub(crate) canonical_path: PathBuf,
    pub(crate) key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceTrust {
    UntrustedRepository,
    TrustedUserGlobal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationProvenance {
    pub(crate) migration_version: u32,
    pub(crate) source_kind: String,
    pub(crate) source_path: PathBuf,
    pub(crate) source_digest: String,
    pub(crate) trust: SourceTrust,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectPolicyDocument {
    pub(crate) schema_version: u32,
    pub(crate) project: ProjectIdentity,
    #[serde(default)]
    pub(crate) grants: Config,
    #[serde(default)]
    pub(crate) constraints: Config,
    #[serde(default)]
    pub(crate) onboarding_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) directory_grants: Vec<DirectoryGrantIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) approved_env_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restricted_ssh: Option<crate::ssh_restricted::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) migration: Option<MigrationProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryGrantIdentity {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) open_scope: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MigrationNotice {
    pub(crate) id: &'static str,
    pub(crate) text: String,
    pub(crate) warning: bool,
}

#[derive(Debug, Default)]
pub(crate) struct LoadedProject {
    pub(crate) grants: Config,
    pub(crate) constraints: Config,
    pub(crate) present: bool,
    pub(crate) onboarding_complete: bool,
    pub(crate) approved_env_names: Vec<String>,
    pub(crate) restricted_ssh: Option<crate::ssh_restricted::Policy>,
}

pub(crate) struct StoreLock(File);

pub(crate) struct LegacyMaskPlaceholder {
    path: Option<PathBuf>,
    dev: u64,
    ino: u64,
}

struct LegacyFile {
    bytes: Vec<u8>,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        unsafe {
            nix::libc::flock(self.0.as_raw_fd(), nix::libc::LOCK_UN);
        }
    }
}

impl LegacyMaskPlaceholder {
    pub(crate) fn prepare(paths: &StorePaths) -> Result<Self, String> {
        let path = paths.canonical_project.join(".ai-jail");
        if !paths.project.is_file() || path.exists() {
            return Ok(Self {
                path: None,
                dev: 0,
                ino: 0,
            });
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| {
                format!(
                    "Cannot create secure legacy config mask {}: {e}",
                    path.display()
                )
            })?;
        let meta = file
            .metadata()
            .map_err(|e| format!("Cannot verify {}: {e}", path.display()))?;
        Ok(Self {
            path: Some(path),
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

impl Drop for LegacyMaskPlaceholder {
    fn drop(&mut self) {
        let Some(path) = &self.path else { return };
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        if meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.dev() == self.dev
            && meta.ino() == self.ino
            && meta.len() == 0
        {
            let _ = fs::remove_file(path);
        }
    }
}

pub(crate) fn xdg_config_home() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME")
        && !value.is_empty()
    {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("XDG_CONFIG_HOME must be an absolute path".into());
        }
        return Ok(path);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    if !home.is_absolute() {
        return Err("HOME must be an absolute path".into());
    }
    Ok(home.join(".config"))
}

pub(crate) fn trusted_store_root() -> Option<PathBuf> {
    xdg_config_home().ok().map(|p| p.join("ai-jail"))
}

fn validate_no_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if let std::path::Component::Normal(part) = component {
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(format!(
                        "Trusted config path has symlink component {}",
                        current.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    break;
                }
                Err(error) => {
                    return Err(format!(
                        "Cannot validate {}: {error}",
                        current.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn project_has_external_policy(project_dir: &Path) -> bool {
    StorePaths::discover(project_dir)
        .is_ok_and(|paths| paths.available && paths.project.is_file())
}

fn canonical_or_absolute(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        fs::canonicalize(path)
            .map_err(|e| format!("Cannot resolve {}: {e}", path.display()))
    } else if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| format!("Cannot resolve {}: {e}", path.display()))
    }
}

#[cfg(test)]
fn reject_overlap(
    kind: &str,
    source: &Path,
    root: &Path,
) -> Result<(), String> {
    let source = canonical_or_absolute(source)?;
    if source == root || source.starts_with(root) || root.starts_with(&source) {
        return Err(format!(
            "Refusing {kind} source {} because it overlaps trusted config store {}",
            source.display(),
            root.display()
        ));
    }
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn validate_resolved_exposures<'a>(
    exposures: impl IntoIterator<Item = (&'a Path, &'a Path)>,
    later_denies: impl IntoIterator<Item = &'a Path>,
) -> Result<(), String> {
    let Some(root) = trusted_store_root() else {
        return Ok(());
    };
    let root = canonical_or_absolute(&root)?;
    let denied = later_denies
        .into_iter()
        .any(|path| canonical_or_absolute(path).is_ok_and(|path| path == root));
    for (source, destination) in exposures {
        let source = canonical_or_absolute(source)?;
        let destination = canonical_or_absolute(destination)?;
        if source == root || source.starts_with(&root) {
            return Err(format!(
                "Refusing resolved host exposure source {} because it is trusted config store {} or a child",
                source.display(),
                root.display()
            ));
        }
        if root.starts_with(&source) && !(source == destination && denied) {
            return Err(format!(
                "Refusing resolved host exposure {} -> {} because it contains trusted config store {} without a later mandatory deny",
                source.display(),
                destination.display(),
                root.display()
            ));
        }
    }
    Ok(())
}

impl StorePaths {
    pub(crate) fn discover(cwd: &Path) -> Result<Self, String> {
        let canonical_project = fs::canonicalize(cwd).map_err(|e| {
            format!("Cannot resolve project directory {}: {e}", cwd.display())
        })?;
        let (root, available) = match xdg_config_home() {
            Ok(base) => (base.join("ai-jail"), true),
            Err(_)
                if std::env::var_os("XDG_CONFIG_HOME")
                    .is_none_or(|value| value.is_empty())
                    && std::env::var_os("HOME").is_none() =>
            {
                (PathBuf::from("/__ai-jail-config-unavailable__"), false)
            }
            Err(error) => return Err(error),
        };
        if root == canonical_project || root.starts_with(&canonical_project) {
            return Err(format!(
                "Refusing trusted config store inside project: {}",
                root.display()
            ));
        }
        let identity = project_identity(&canonical_project);
        let legacy_global = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".ai-jail"))
            .unwrap_or_default();
        Ok(Self {
            available,
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root
                .join("projects")
                .join(format!("{}.toml", identity.key)),
            legacy_global,
            legacy_project: PathBuf::from(".ai-jail"),
            canonical_project,
            root,
        })
    }

    pub(crate) fn identity(&self) -> ProjectIdentity {
        project_identity(&self.canonical_project)
    }

    pub(crate) fn prepare(&self) -> Result<StoreLock, String> {
        if !self.available {
            return Err(
                "Config store is unavailable because HOME is not set".into()
            );
        }
        validate_no_symlink_components(&self.root)?;
        secure_dir(&self.root)?;
        let canonical_root = fs::canonicalize(&self.root).map_err(|e| {
            format!("Cannot resolve config store {}: {e}", self.root.display())
        })?;
        if canonical_root == self.canonical_project
            || canonical_root.starts_with(&self.canonical_project)
        {
            return Err(format!(
                "Refusing trusted config store inside project: {}",
                canonical_root.display()
            ));
        }
        secure_dir(&self.root.join("projects"))?;
        let lock_path = self.root.join(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&lock_path)
            .map_err(|e| {
                format!(
                    "Cannot open migration lock {}: {e}",
                    lock_path.display()
                )
            })?;
        let lock_meta = lock
            .metadata()
            .map_err(|e| format!("Cannot stat migration lock: {e}"))?;
        let uid = unsafe { nix::libc::geteuid() };
        if !lock_meta.is_file()
            || lock_meta.uid() != uid
            || lock_meta.mode() & 0o777 != 0o600
            || lock_meta.nlink() != 1
        {
            return Err("Unsafe migration lock file".into());
        }
        let rc =
            unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX) };
        if rc != 0 {
            return Err(format!(
                "Cannot lock config store: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(StoreLock(lock))
    }
}

fn validate_store_for_read(paths: &StorePaths) -> Result<bool, String> {
    if !paths.available {
        return Ok(false);
    }
    match fs::symlink_metadata(&paths.root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(format!(
                "Cannot stat trusted config store {}: {error}",
                paths.root.display()
            ));
        }
        Ok(_) => {}
    }
    validate_no_symlink_components(&paths.root)?;
    secure_existing_dir(&paths.root)?;
    let canonical = fs::canonicalize(&paths.root).map_err(|error| {
        format!("Cannot resolve {}: {error}", paths.root.display())
    })?;
    if canonical == paths.canonical_project
        || canonical.starts_with(&paths.canonical_project)
    {
        return Err(format!(
            "Refusing trusted config store inside project: {}",
            canonical.display()
        ));
    }
    let projects = paths.root.join("projects");
    if projects.exists() {
        secure_existing_dir(&projects)?;
    }
    Ok(true)
}

fn secure_existing_dir(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot stat {}: {error}", path.display()))?;
    let uid = unsafe { nix::libc::geteuid() };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o777 != 0o700
    {
        return Err(format!(
            "Trusted config directory {} must be owner-owned mode 0700 with no symlink",
            path.display()
        ));
    }
    Ok(())
}

fn secure_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot secure {}: {e}", path.display()))?;
    }
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    let uid = unsafe { nix::libc::geteuid() };
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
        return Err(format!("Unsafe config directory {}", path.display()));
    }
    if meta.mode() & 0o777 != 0o700 {
        return Err(format!(
            "Config directory {} must have mode 0700",
            path.display()
        ));
    }
    Ok(())
}

fn project_identity(canonical: &Path) -> ProjectIdentity {
    let digest = hex_digest(canonical.as_os_str().as_bytes());
    let base = canonical
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("project")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    ProjectIdentity {
        canonical_path: canonical.to_path_buf(),
        key: format!("{}-{}", base, &digest[..20]),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_legacy_regular(path: &Path) -> Result<Option<LegacyFile>, String> {
    if let Err(error) = fs::symlink_metadata(path) {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!("Cannot stat {}: {error}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| format!("Invalid legacy path {}", path.display()))?;
    let dir = File::open(parent)
        .map_err(|e| format!("Cannot open {}: {e}", parent.display()))?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| "Legacy filename contains NUL".to_string())?;
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            nix::libc::O_RDONLY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!("Refusing to read {}: {error}", path.display()));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    Ok(Some(LegacyFile {
        bytes,
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        mode: meta.mode(),
        nlink: meta.nlink(),
    }))
}

fn read_trusted_regular(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let Some(source) = read_legacy_regular(path)? else {
        return Ok(None);
    };
    let uid = unsafe { nix::libc::geteuid() };
    if source.uid != uid || source.mode & 0o777 != 0o600 || source.nlink != 1 {
        return Err(format!(
            "Trusted config {} must be owner-only (0600), owned by uid {}, and not hard-linked",
            path.display(),
            uid
        ));
    }
    Ok(Some(source.bytes))
}

fn read_project(
    path: &Path,
    identity: &ProjectIdentity,
) -> Result<LoadedProject, String> {
    let Some(raw) = read_trusted_regular(path)? else {
        return Ok(LoadedProject::default());
    };
    let text = std::str::from_utf8(&raw)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    let doc: ProjectPolicyDocument = toml::from_str(text)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    if doc.schema_version != MIGRATION_VERSION {
        return Err(format!(
            "Unsupported project policy schema {} in {}",
            doc.schema_version,
            path.display()
        ));
    }
    if &doc.project != identity {
        return Err(format!(
            "Project identity mismatch in {} (expected {})",
            path.display(),
            identity.canonical_path.display()
        ));
    }
    let mut grants = doc.grants;
    validate_directory_grants(
        &mut grants,
        &doc.directory_grants,
        &identity.canonical_path,
    )?;
    Ok(LoadedProject {
        grants,
        constraints: doc.constraints,
        present: true,
        onboarding_complete: doc.onboarding_complete,
        approved_env_names: doc.approved_env_names,
        restricted_ssh: doc.restricted_ssh,
    })
}

pub(crate) fn load_project(
    paths: &StorePaths,
) -> Result<LoadedProject, String> {
    if !validate_store_for_read(paths)? {
        return Ok(LoadedProject::default());
    }
    read_project(&paths.project, &paths.identity())
}

pub(crate) fn load_global(paths: &StorePaths) -> Result<GlobalConfig, String> {
    if !validate_store_for_read(paths)? {
        return Ok(GlobalConfig::default());
    }
    let Some(raw) = read_trusted_regular(&paths.global)? else {
        return Ok(GlobalConfig::default());
    };
    let text = std::str::from_utf8(&raw).map_err(|e| {
        format!("Failed to parse {}: {e}", paths.global.display())
    })?;
    config::parse_global_toml(text)
        .map_err(|e| format!("Failed to parse {}: {e}", paths.global.display()))
}

pub(crate) fn migrate(
    paths: &StorePaths,
    include_project: bool,
    notices: &mut Vec<MigrationNotice>,
) -> Result<(), String> {
    if fs::canonicalize(
        paths
            .legacy_global
            .parent()
            .unwrap_or_else(|| Path::new(".")),
    )
    .ok()
        == Some(paths.canonical_project.clone())
        && paths.legacy_global.exists()
    {
        return Err(format!(
            "Legacy global/project config collision at {}; move it before migration",
            paths.legacy_global.display()
        ));
    }
    let _lock = paths.prepare()?;
    migrate_global(paths, notices)?;
    if include_project {
        migrate_project(paths, notices)?;
    }
    Ok(())
}

fn migrate_global(
    paths: &StorePaths,
    notices: &mut Vec<MigrationNotice>,
) -> Result<(), String> {
    if paths.legacy_global.as_os_str().is_empty() {
        return Ok(());
    }
    let (raw, link_target, file_identity) =
        match fs::symlink_metadata(&paths.legacy_global) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "Cannot stat {}: {e}",
                    paths.legacy_global.display()
                ));
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                let link =
                    fs::read_link(&paths.legacy_global).map_err(|e| {
                        format!(
                            "Cannot read {}: {e}",
                            paths.legacy_global.display()
                        )
                    })?;
                let target =
                    fs::canonicalize(&paths.legacy_global).map_err(|e| {
                        format!(
                            "Refusing legacy global symlink {}: {e}",
                            paths.legacy_global.display()
                        )
                    })?;
                let source =
                    read_legacy_regular(&target)?.ok_or_else(|| {
                        "Legacy global target disappeared".to_string()
                    })?;
                let uid = unsafe { nix::libc::geteuid() };
                if source.uid != uid
                    || source.mode & 0o022 != 0
                    || target.starts_with(&paths.canonical_project)
                {
                    return Err(format!(
                        "Refusing unsafe legacy global symlink {}",
                        paths.legacy_global.display()
                    ));
                }
                (source.bytes, Some(link), None)
            }
            Ok(meta) if meta.is_file() => {
                let source = read_legacy_regular(&paths.legacy_global)?
                    .ok_or_else(|| "Legacy global disappeared".to_string())?;
                let uid = unsafe { nix::libc::geteuid() };
                if source.uid != uid || source.mode & 0o022 != 0 {
                    return Err(format!(
                        "Refusing unsafe legacy global config {}",
                        paths.legacy_global.display()
                    ));
                }
                (source.bytes, None, Some((source.dev, source.ino)))
            }
            Ok(_) => {
                return Err(format!(
                    "{} is not a regular file",
                    paths.legacy_global.display()
                ));
            }
        };
    let text = std::str::from_utf8(&raw).map_err(|e| {
        format!("Failed to parse {}: {e}", paths.legacy_global.display())
    })?;
    let parsed = config::parse_global_toml(text).map_err(|e| {
        format!("Failed to parse {}: {e}", paths.legacy_global.display())
    })?;
    let digest = hex_digest(&raw);
    let prior_digest_matches =
        read_global_provenance(&paths.global_provenance)?
            .is_some_and(|provenance| provenance.source_digest == digest);
    if paths.global.exists() {
        let existing =
            read_trusted_regular(&paths.global)?.ok_or_else(|| {
                "Global config disappeared during migration".to_string()
            })?;
        if existing != raw && !prior_digest_matches {
            return Err(format!(
                "Conflicting global configs at {} and {}; neither was removed",
                paths.legacy_global.display(),
                paths.global.display()
            ));
        }
        let existing_text = std::str::from_utf8(&existing).map_err(|e| {
            format!("Failed to parse {}: {e}", paths.global.display())
        })?;
        config::parse_global_toml(existing_text).map_err(|e| {
            format!("Failed to parse {}: {e}", paths.global.display())
        })?;
    } else {
        durable_write(&paths.global, &raw)?;
    }
    let installed = load_global(paths)?;
    if !prior_digest_matches && installed != parsed {
        return Err(format!(
            "Global migration verification failed at {}; legacy source retained at {}",
            paths.global.display(),
            paths.legacy_global.display()
        ));
    }
    let provenance = MigrationProvenance {
        migration_version: MIGRATION_VERSION,
        source_kind: if link_target.is_some() {
            "global_legacy_symlink".into()
        } else {
            "global_legacy_file".into()
        },
        source_path: paths.legacy_global.clone(),
        source_digest: digest,
        trust: SourceTrust::TrustedUserGlobal,
    };
    let provenance_body = toml::to_string_pretty(&provenance)
        .map_err(|e| format!("Cannot serialize global provenance: {e}"))?;
    durable_write(&paths.global_provenance, provenance_body.as_bytes())?;
    if let Some(link) = link_target {
        quarantine_remove_symlink(&paths.legacy_global, &link)?;
    } else {
        let (dev, ino) = file_identity
            .ok_or_else(|| "Missing legacy global identity".to_string())?;
        quarantine_remove(
            &paths.legacy_global,
            &LegacyFile {
                bytes: raw,
                dev,
                ino,
                uid: unsafe { nix::libc::geteuid() },
                mode: 0,
                nlink: 1,
            },
        )?;
    }
    notices.push(MigrationNotice {
        id: "AJ-MIG-001",
        text: format!(
            "Global config moved to {}. The legacy file was removed.",
            paths.global.display()
        ),
        warning: false,
    });
    Ok(())
}

fn read_global_provenance(
    path: &Path,
) -> Result<Option<MigrationProvenance>, String> {
    let Some(raw) = read_trusted_regular(path)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&raw)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    let provenance: MigrationProvenance = toml::from_str(text)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    if provenance.migration_version != MIGRATION_VERSION {
        return Err(format!(
            "Unsupported migration provenance version in {}",
            path.display()
        ));
    }
    Ok(Some(provenance))
}

fn quarantine_remove_symlink(
    path: &Path,
    expected: &Path,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| "Missing source name".to_string())?;
    let dir = File::open(parent)
        .map_err(|e| format!("Cannot open {}: {e}", parent.display()))?;
    let source =
        CString::new(name.as_bytes()).map_err(|_| "NUL in path".to_string())?;
    let quarantine_name = format!(
        ".ai-jail.quarantine.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let quarantine = CString::new(quarantine_name.clone()).unwrap();
    if unsafe {
        nix::libc::renameat(
            dir.as_raw_fd(),
            source.as_ptr(),
            dir.as_raw_fd(),
            quarantine.as_ptr(),
        )
    } != 0
    {
        return Err(format!("Cannot quarantine {}", path.display()));
    }
    let quarantined_path = parent.join(&quarantine_name);
    sync_file(&dir).map_err(|e| recovery_error(e, &quarantined_path))?;
    if fs::read_link(&quarantined_path).ok().as_deref() != Some(expected) {
        if entry_absent(&dir, &source) {
            let _ = unsafe {
                nix::libc::renameat(
                    dir.as_raw_fd(),
                    quarantine.as_ptr(),
                    dir.as_raw_fd(),
                    source.as_ptr(),
                )
            };
            sync_file(&dir).map_err(|e| recovery_error(e, path))?;
        }
        let recovery = if path.exists() {
            path
        } else {
            &quarantined_path
        };
        return Err(recovery_error(
            "Legacy global symlink changed during migration",
            recovery,
        ));
    }
    if unsafe { nix::libc::unlinkat(dir.as_raw_fd(), quarantine.as_ptr(), 0) }
        != 0
    {
        return Err(format!(
            "Migration committed; symlink remains recoverable at {}",
            quarantined_path.display()
        ));
    }
    sync_file(&dir).map_err(|e| {
        format!("Migration destination committed and source unlinked; source-removal durability is uncertain: {e}")
    })
}

fn migrate_project(
    paths: &StorePaths,
    notices: &mut Vec<MigrationNotice>,
) -> Result<(), String> {
    let Some(source) = read_legacy_regular(&paths.legacy_project)? else {
        return Ok(());
    };
    let raw = &source.bytes;
    let text = std::str::from_utf8(raw).map_err(|e| {
        format!("Failed to parse {}: {e}", paths.legacy_project.display())
    })?;
    let legacy = config::parse_toml(text).map_err(|e| {
        format!("Failed to parse {}: {e}", paths.legacy_project.display())
    })?;
    let selector = crate::cli::CliArgs {
        command: legacy.command.clone(),
        ..crate::cli::CliArgs::default()
    };
    let baseline = config::global_config_for_command(
        load_global(paths)?,
        &selector,
        &Config::default(),
    );
    let dropped = dropped_capability_requests(
        &legacy,
        &baseline,
        &paths.canonical_project,
    );
    let projected = config::monotonic_project_constraints(
        &legacy,
        &paths.canonical_project,
    );
    let identity = paths.identity();
    let digest = hex_digest(raw);
    let mut doc = if paths.project.exists() {
        let existing = read_project_document(&paths.project, &identity)?;
        if existing
            .migration
            .as_ref()
            .is_some_and(|m| m.source_digest == digest)
        {
            quarantine_remove(&paths.legacy_project, &source)?;
            notices.push(project_notice(paths));
            push_reapproval_notice(notices, &dropped);
            return Ok(());
        }
        existing
    } else {
        ProjectPolicyDocument {
            schema_version: MIGRATION_VERSION,
            project: identity,
            grants: Config::default(),
            constraints: Config::default(),
            onboarding_complete: false,
            directory_grants: Vec::new(),
            approved_env_names: Vec::new(),
            restricted_ssh: None,
            migration: None,
        }
    };
    doc.constraints = config::merge_with_global_report(
        doc.constraints,
        projected,
        &paths.canonical_project,
    )
    .0;
    doc.migration = Some(MigrationProvenance {
        migration_version: MIGRATION_VERSION,
        source_kind: "project_legacy_file".into(),
        source_path: paths.legacy_project.clone(),
        source_digest: digest,
        trust: SourceTrust::UntrustedRepository,
    });
    write_project_document(&paths.project, &doc)?;
    quarantine_remove(&paths.legacy_project, &source)?;
    notices.push(project_notice(paths));
    push_reapproval_notice(notices, &dropped);
    Ok(())
}

pub(crate) fn save_project_grants(
    paths: &StorePaths,
    mut grants: Config,
    mut approved_env_names: Vec<String>,
    approved_directory_grants: &[DirectoryGrantIdentity],
    restricted_ssh: Option<crate::ssh_restricted::Policy>,
) -> Result<(), String> {
    let _lock = paths.prepare()?;
    validate_directory_grants(
        &mut grants,
        approved_directory_grants,
        &paths.canonical_project,
    )?;
    let identity = paths.identity();
    let mut doc = if paths.project.exists() {
        read_project_document(&paths.project, &identity)?
    } else {
        ProjectPolicyDocument {
            schema_version: MIGRATION_VERSION,
            project: identity,
            grants: Config::default(),
            constraints: Config::default(),
            onboarding_complete: false,
            directory_grants: Vec::new(),
            approved_env_names: Vec::new(),
            restricted_ssh: None,
            migration: None,
        }
    };
    for name in &approved_env_names {
        crate::onboarding::validate_env_name(name)?;
    }
    approved_env_names.sort();
    approved_env_names.dedup();
    // Environment approvals are persisted as names in the dedicated trusted
    // field. Config.env_pass may contain literal assignments, so it must never
    // be serialized as part of the project grants.
    grants.env_pass.clear();
    doc.directory_grants = approved_directory_grants.to_vec();
    doc.grants = grants;
    doc.approved_env_names = approved_env_names;
    if let Some(policy) = &restricted_ssh {
        crate::ssh_restricted::validate_policy(policy)?;
    }
    doc.restricted_ssh = restricted_ssh;
    doc.onboarding_complete = true;
    write_project_document(&paths.project, &doc)
}

pub(crate) fn capture_directory_grants(
    grants: &Config,
    project: &Path,
) -> Result<Vec<DirectoryGrantIdentity>, String> {
    let mut identities = Vec::new();
    for (writable, paths) in [(false, &grants.ro_maps), (true, &grants.rw_maps)]
    {
        for encoded in paths {
            let spec = config::MapSpec::parse(encoded)?;
            spec.validate()?;
            if spec.is_alternate() {
                return Err("Onboarding directory grants cannot change the destination path".into());
            }
            let path = fs::canonicalize(&spec.source).map_err(|e| {
                format!(
                    "Directory grant {} is unavailable: {e}",
                    spec.source.display()
                )
            })?;
            if path.as_os_str().as_bytes().contains(&b':')
                || path.to_str().is_none()
            {
                return Err("Directory grant paths must be UTF-8 and cannot contain ':'".into());
            }
            let metadata = fs::metadata(&path).map_err(|e| {
                format!(
                    "Cannot inspect directory grant {}: {e}",
                    path.display()
                )
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "Directory grant {} is not a directory",
                    path.display()
                ));
            }
            reject_onboarding_credential_path(&path)?;
            let open_scope = onboarding_path_is_broad(&path, project);
            identities.push(DirectoryGrantIdentity {
                path,
                writable,
                dev: metadata.dev(),
                ino: metadata.ino(),
                open_scope,
            });
        }
    }
    Ok(identities)
}

pub(crate) fn validate_directory_grants(
    grants: &mut Config,
    identities: &[DirectoryGrantIdentity],
    project: &Path,
) -> Result<(), String> {
    if grants.ro_maps.is_empty() && grants.rw_maps.is_empty() {
        return Ok(());
    }
    if identities.len() != grants.ro_maps.len() + grants.rw_maps.len() {
        return Err(format!(
            "{} Saved directory grants lack identity records; run `ai-jail configure HARNESS` again",
            crate::onboarding::messages::PATH_IDENTITY_ID
        ));
    }
    let expected =
        capture_directory_grants(grants, project).map_err(|error| {
            format!("{} {error}", crate::onboarding::messages::PATH_DRIFT_ID)
        })?;
    if expected != identities {
        return Err(format!(
            "{} A saved directory grant moved, disappeared, or changed identity; access was refused",
            crate::onboarding::messages::PATH_DRIFT_ID
        ));
    }
    grants.ro_maps = identities
        .iter()
        .filter(|item| !item.writable)
        .map(|item| item.path.clone())
        .collect();
    grants.rw_maps = identities
        .iter()
        .filter(|item| item.writable)
        .map(|item| item.path.clone())
        .collect();
    Ok(())
}

fn onboarding_path_is_broad(path: &Path, project: &Path) -> bool {
    let home_is_path = std::env::var_os("HOME").is_some_and(|home| {
        let configured = PathBuf::from(home);
        let canonical = fs::canonicalize(&configured).unwrap_or(configured);
        path == canonical
    });
    home_is_path || (project.starts_with(path) && path != project)
}

fn reject_onboarding_credential_path(path: &Path) -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "AJ-PATH-002 Cannot validate credential roots because HOME is not set".to_string())?;
    if crate::authority_inventory::is_protected(path, &home)? {
        return Err("AJ-PATH-002 A saved directory now resolves inside a credential root; access was refused".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DirectionalAuthority {
    Gpu,
    Docker,
    Tailscale,
    Display,
    Audio,
    Github,
    Aws,
    Kube,
    Gcloud,
    DockerConfig,
    Kvm,
    PromptHosts,
    Network,
    MacosHostIpc,
    MacosChromium,
    MacosTrustd,
    AllowPty,
    LoopbackListen,
    LoopbackConnect,
    X11,
    HostShm,
    Terminal,
    HideConfig,
    Ssh,
    Pictures,
    PrivateHome,
    Lockdown,
    Landlock,
    Seccomp,
    Rlimits,
    Systemd,
    InheritEnv,
    Worktree,
    Mise,
    Toolchains,
    AgentState,
    BrowserProfile,
    UpdateCheck,
    AuditLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticPolicyClass {
    Authority,
    Restriction,
    Preference,
    SensitiveAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticRenderer {
    Command,
    RwMaps,
    RoMaps,
    OverlayMaps,
    MaskExceptions,
    DenyExceptions,
    TcpPorts,
    Hosts,
    PrivateHosts,
    ForwardPorts,
    PublishPorts,
    ClaudeDir,
    EnvPass,
    EnvFiles,
    SecretHosts,
    TrustedProjects,
}

#[derive(Clone, Copy)]
enum ConfigFieldPolicy {
    Static {
        field: &'static str,
        class: StaticPolicyClass,
        renderer: Option<StaticRenderer>,
    },
    Directional {
        field: &'static str,
        rule: DirectionalAuthority,
        renderer: &'static str,
    },
}

macro_rules! static_policy {
    ($field:literal, $class:ident, $renderer:ident) => {
        ConfigFieldPolicy::Static {
            field: $field,
            class: StaticPolicyClass::$class,
            renderer: Some(StaticRenderer::$renderer),
        }
    };
}
macro_rules! excluded_policy {
    ($field:literal, $class:ident) => {
        ConfigFieldPolicy::Static {
            field: $field,
            class: StaticPolicyClass::$class,
            renderer: None,
        }
    };
}
macro_rules! directional_policy {
    ($field:literal, $rule:ident, $renderer:literal) => {
        ConfigFieldPolicy::Directional {
            field: $field,
            rule: DirectionalAuthority::$rule,
            renderer: $renderer,
        }
    };
}

const CONFIG_FIELD_POLICY: &[ConfigFieldPolicy] = &[
    static_policy!("command", Authority, Command),
    static_policy!("rw_maps", Authority, RwMaps),
    static_policy!("ro_maps", Authority, RoMaps),
    static_policy!("overlay_maps", Authority, OverlayMaps),
    excluded_policy!("hide_dotdirs", Restriction),
    excluded_policy!("mask", Restriction),
    excluded_policy!("deny_paths", Restriction),
    static_policy!("mask_exceptions", Authority, MaskExceptions),
    static_policy!("deny_path_exceptions", Authority, DenyExceptions),
    directional_policy!("no_gpu", Gpu, "gpu"),
    directional_policy!("no_docker", Docker, "docker-socket"),
    directional_policy!("tailscale", Tailscale, "tailscale-socket"),
    directional_policy!("no_display", Display, "display"),
    directional_policy!("audio", Audio, "audio"),
    directional_policy!("github", Github, "github-credentials"),
    directional_policy!("aws", Aws, "aws-credentials"),
    directional_policy!("kube", Kube, "kube-credentials"),
    directional_policy!("gcloud", Gcloud, "gcloud-credentials"),
    directional_policy!("docker_config", DockerConfig, "docker-credentials"),
    directional_policy!("kvm", Kvm, "kvm"),
    directional_policy!("prompt_hosts", PromptHosts, "interactive-host-prompt"),
    directional_policy!("network", Network, "unrestricted-network"),
    directional_policy!("macos_host_ipc", MacosHostIpc, "macos-host-ipc"),
    directional_policy!("macos_chromium", MacosChromium, "macos-chromium-ipc"),
    directional_policy!("macos_trustd", MacosTrustd, "macos-trustd"),
    directional_policy!("allow_pty", AllowPty, "host-pty"),
    directional_policy!(
        "allow_loopback_listen",
        LoopbackListen,
        "loopback-listen"
    ),
    directional_policy!(
        "allow_loopback_connect",
        LoopbackConnect,
        "loopback-connect"
    ),
    directional_policy!("x11", X11, "x11"),
    directional_policy!("host_shm", HostShm, "host-shm"),
    directional_policy!(
        "terminal_passthrough",
        Terminal,
        "terminal-passthrough"
    ),
    directional_policy!("no_worktree", Worktree, "worktree-metadata"),
    directional_policy!("no_mise", Mise, "mise-state"),
    directional_policy!("no_toolchains", Toolchains, "toolchain-state"),
    excluded_policy!("no_save_config", Preference),
    directional_policy!("no_hide_config", HideConfig, "visible-legacy-config"),
    directional_policy!("ssh", Ssh, "ssh"),
    directional_policy!("pictures", Pictures, "pictures"),
    directional_policy!("browser_profile", BrowserProfile, "browser-profile"),
    directional_policy!("private_home", PrivateHome, "host-home"),
    directional_policy!("lockdown", Lockdown, "disable-lockdown"),
    directional_policy!("no_landlock", Landlock, "disable-landlock"),
    excluded_policy!("no_status_bar", Preference),
    excluded_policy!("status_bar_style", Preference),
    excluded_policy!("resize_redraw_key", Preference),
    directional_policy!("no_seccomp", Seccomp, "disable-seccomp"),
    directional_policy!("no_rlimits", Rlimits, "disable-resource-limits"),
    directional_policy!("systemd_user", Systemd, "systemd-user"),
    static_policy!("allow_tcp_ports", Authority, TcpPorts),
    static_policy!("allow_hosts", Authority, Hosts),
    static_policy!("allow_private_hosts", Authority, PrivateHosts),
    static_policy!("forward_ports", Authority, ForwardPorts),
    static_policy!("publish_ports", Authority, PublishPorts),
    static_policy!("claude_dir", Authority, ClaudeDir),
    directional_policy!("agent_state", AgentState, "agent-state"),
    directional_policy!("inherit_env", InheritEnv, "inherit-host-environment"),
    static_policy!("env_pass", SensitiveAuthority, EnvPass),
    static_policy!("env_from_file", SensitiveAuthority, EnvFiles),
    static_policy!("secret_hosts", SensitiveAuthority, SecretHosts),
    static_policy!("trust_project_config", Authority, TrustedProjects),
    directional_policy!("update_check", UpdateCheck, "update-check-network"),
    directional_policy!("audit_log", AuditLog, "audit-log-host-write"),
];
impl DirectionalAuthority {
    fn widens(self, c: &Config, b: &Config) -> bool {
        match self {
            Self::Gpu => c.no_gpu == Some(false) && b.no_gpu != Some(false),
            Self::Docker => {
                c.no_docker == Some(false) && b.no_docker != Some(false)
            }
            Self::Tailscale => {
                c.tailscale == Some(true) && b.tailscale != Some(true)
            }
            Self::Display => {
                c.no_display == Some(false) && b.no_display != Some(false)
            }
            Self::Audio => c.audio == Some(true) && b.audio != Some(true),
            Self::Github => c.github == Some(true) && b.github != Some(true),
            Self::Aws => c.aws == Some(true) && b.aws != Some(true),
            Self::Kube => c.kube == Some(true) && b.kube != Some(true),
            Self::Gcloud => c.gcloud == Some(true) && b.gcloud != Some(true),
            Self::DockerConfig => {
                c.docker_config == Some(true) && b.docker_config != Some(true)
            }
            Self::Kvm => c.kvm == Some(true) && b.kvm != Some(true),
            Self::PromptHosts => {
                c.prompt_hosts == Some(true) && b.prompt_hosts != Some(true)
            }
            Self::Network => c.network == Some(true) && b.network != Some(true),
            Self::MacosHostIpc => {
                c.macos_host_ipc == Some(true) && b.macos_host_ipc != Some(true)
            }
            Self::MacosChromium => {
                c.macos_chromium == Some(true) && b.macos_chromium != Some(true)
            }
            Self::MacosTrustd => {
                c.macos_trustd == Some(true) && b.macos_trustd != Some(true)
            }
            Self::AllowPty => {
                c.allow_pty == Some(true) && b.allow_pty != Some(true)
            }
            Self::LoopbackListen => {
                c.allow_loopback_listen == Some(true)
                    && b.allow_loopback_listen != Some(true)
            }
            Self::LoopbackConnect => {
                c.allow_loopback_connect == Some(true)
                    && b.allow_loopback_connect != Some(true)
            }
            Self::X11 => c.x11 == Some(true) && b.x11 != Some(true),
            Self::HostShm => {
                c.host_shm == Some(true) && b.host_shm != Some(true)
            }
            Self::Terminal => {
                c.terminal_passthrough == Some(true)
                    && b.terminal_passthrough != Some(true)
            }
            Self::HideConfig => {
                c.no_hide_config == Some(true) && b.no_hide_config != Some(true)
            }
            Self::Ssh => c.ssh == Some(true) && b.ssh != Some(true),
            Self::Pictures => {
                c.pictures == Some(true) && b.pictures != Some(true)
            }
            Self::PrivateHome => {
                c.private_home == Some(false) && b.private_home != Some(false)
            }
            Self::Lockdown => {
                c.lockdown == Some(false) && b.lockdown == Some(true)
            }
            Self::Landlock => {
                c.no_landlock == Some(true) && b.no_landlock != Some(true)
            }
            Self::Seccomp => {
                c.no_seccomp == Some(true) && b.no_seccomp != Some(true)
            }
            Self::Rlimits => {
                c.no_rlimits == Some(true) && b.no_rlimits != Some(true)
            }
            Self::Systemd => {
                c.systemd_user == Some(true) && b.systemd_user != Some(true)
            }
            Self::InheritEnv => {
                c.inherit_env == Some(true) && b.inherit_env != Some(true)
            }
            Self::Worktree => {
                c.no_worktree == Some(false) && b.no_worktree == Some(true)
            }
            Self::Mise => c.no_mise == Some(false) && b.no_mise == Some(true),
            Self::Toolchains => {
                c.no_toolchains == Some(false) && b.no_toolchains == Some(true)
            }
            Self::AgentState => {
                c.agent_state == Some(true) && b.agent_state == Some(false)
            }
            Self::BrowserProfile => {
                matches!(
                    c.browser_profile.as_deref(),
                    Some(
                        "off"
                            | "none"
                            | "disabled"
                            | "soft"
                            | "persistent"
                            | "survivable"
                    )
                ) && matches!(
                    b.browser_profile.as_deref(),
                    Some("hard" | "isolated" | "ephemeral")
                )
            }
            Self::UpdateCheck => {
                c.update_check == Some(true) && b.update_check != Some(true)
            }
            Self::AuditLog => {
                c.audit_log == Some(true) && b.audit_log != Some(true)
            }
        }
    }
}

fn render_static_authority(
    renderer: StaticRenderer,
    config: &Config,
    baseline: &Config,
    project: &Path,
) -> Vec<String> {
    let added_paths =
        |paths: &[PathBuf], baseline_paths: &[PathBuf], label: &str| {
            paths
                .iter()
                .filter(|path| !baseline_paths.contains(path))
                .map(|path| format!("{label} {}", path.display()))
                .collect()
        };
    let added_maps =
        |paths: &[PathBuf], baseline_paths: &[PathBuf], label: &str| {
            paths
                .iter()
                .filter(|path| !baseline_paths.contains(path))
                .filter_map(|encoded| {
                    let spec = config::MapSpec::parse(encoded).ok()?;
                    (!config::resolves_inside_project(&spec.source, project))
                        .then(|| format!("{label} {}", spec.source.display()))
                })
                .collect()
        };
    match renderer {
        StaticRenderer::Command => config
            .command
            .first()
            .filter(|_| config.command != baseline.command)
            .map(|program| {
                vec![format!("command {}", Path::new(program).display())]
            })
            .unwrap_or_default(),
        StaticRenderer::RwMaps => {
            added_maps(&config.rw_maps, &baseline.rw_maps, "rw-map")
        }
        StaticRenderer::RoMaps => {
            added_maps(&config.ro_maps, &baseline.ro_maps, "ro-map")
        }
        StaticRenderer::OverlayMaps => added_maps(
            &config.overlay_maps,
            &baseline.overlay_maps,
            "overlay-map",
        ),
        StaticRenderer::MaskExceptions => added_paths(
            &config.mask_exceptions,
            &baseline.mask_exceptions,
            "mask-exception",
        ),
        StaticRenderer::DenyExceptions => added_paths(
            &config.deny_path_exceptions,
            &baseline.deny_path_exceptions,
            "deny-path-exception",
        ),
        StaticRenderer::TcpPorts => config
            .allow_tcp_ports
            .iter()
            .filter(|p| !baseline.allow_tcp_ports.contains(p))
            .map(|p| format!("tcp-port {p}"))
            .collect(),
        StaticRenderer::Hosts => config
            .allow_hosts
            .iter()
            .filter(|h| !baseline.allow_hosts.contains(h))
            .map(|h| format!("host {h}"))
            .collect(),
        StaticRenderer::PrivateHosts => config
            .allow_private_hosts
            .iter()
            .filter(|h| !baseline.allow_private_hosts.contains(h))
            .map(|h| format!("private-host {h}"))
            .collect(),
        StaticRenderer::ForwardPorts => config
            .forward_ports
            .iter()
            .filter(|p| !baseline.forward_ports.contains(p))
            .map(|p| format!("forward-port {p}"))
            .collect(),
        StaticRenderer::PublishPorts => config
            .publish_ports
            .iter()
            .filter(|p| !baseline.publish_ports.contains(p))
            .map(|p| format!("publish-port {p}"))
            .collect(),
        StaticRenderer::ClaudeDir => config
            .claude_dir
            .as_ref()
            .filter(|p| baseline.claude_dir.as_ref() != Some(*p))
            .map(|p| vec![format!("claude-dir {}", p.display())])
            .unwrap_or_default(),
        StaticRenderer::EnvPass => config
            .env_pass
            .iter()
            .filter(|entry| !baseline.env_pass.contains(entry))
            .map(|entry| {
                entry
                    .split_once('=')
                    .map_or(entry.as_str(), |(name, _)| name)
            })
            .map(|name| format!("environment-variable {name}"))
            .collect(),
        StaticRenderer::EnvFiles => added_paths(
            &config.env_from_file,
            &baseline.env_from_file,
            "environment-file",
        ),
        StaticRenderer::SecretHosts => config
            .secret_hosts
            .iter()
            .filter(|(name, host)| {
                baseline.secret_hosts.get(*name) != Some(*host)
            })
            .map(|(name, host)| {
                format!("secret-variable {name} for host {host}")
            })
            .collect(),
        StaticRenderer::TrustedProjects => added_paths(
            &config.trust_project_config,
            &baseline.trust_project_config,
            "trusted-project",
        ),
    }
}

fn dropped_capability_requests(
    config: &Config,
    baseline: &Config,
    project: &Path,
) -> Vec<String> {
    let mut dropped = Vec::new();
    for item in CONFIG_FIELD_POLICY {
        match item {
            ConfigFieldPolicy::Static {
                field,
                class,
                renderer,
            } => {
                debug_assert!(!field.is_empty());
                match (class, renderer) {
                    (
                        StaticPolicyClass::Authority
                        | StaticPolicyClass::SensitiveAuthority,
                        Some(renderer),
                    ) => {
                        dropped.extend(render_static_authority(
                            *renderer, config, baseline, project,
                        ));
                    }
                    (
                        StaticPolicyClass::Restriction
                        | StaticPolicyClass::Preference,
                        None,
                    ) => {}
                    _ => unreachable!(
                        "CONFIG_FIELD_POLICY category/renderer mismatch"
                    ),
                }
            }
            ConfigFieldPolicy::Directional {
                field,
                rule,
                renderer,
            } if rule.widens(config, baseline) => {
                debug_assert!(!field.is_empty());
                dropped.push(
                    if matches!(rule, DirectionalAuthority::BrowserProfile) {
                        format!(
                            "{renderer} {}",
                            config
                                .browser_profile
                                .as_deref()
                                .unwrap_or_default()
                        )
                    } else {
                        (*renderer).into()
                    },
                );
            }
            ConfigFieldPolicy::Directional { field, .. } => {
                debug_assert!(!field.is_empty());
            }
        }
    }
    dropped.sort();
    dropped.dedup();
    dropped
}
fn push_reapproval_notice(
    notices: &mut Vec<MigrationNotice>,
    dropped: &[String],
) {
    if dropped.is_empty() {
        return;
    }
    notices.push(MigrationNotice {
        id: "AJ-MIG-003",
        text: format!(
            "REAPPROVAL REQUIRED; these access requests were NOT IMPORTED: {}.",
            dropped.join(", ")
        ),
        warning: true,
    });
}

fn project_notice(paths: &StorePaths) -> MigrationNotice {
    MigrationNotice {
        id: "AJ-MIG-002",
        text: format!(
            "IMPORTED RESTRICTIONS to {}. The legacy file was removed.",
            paths.project.display()
        ),
        warning: false,
    }
}

fn read_project_document(
    path: &Path,
    identity: &ProjectIdentity,
) -> Result<ProjectPolicyDocument, String> {
    let raw = read_trusted_regular(path)?
        .ok_or_else(|| format!("Config disappeared: {}", path.display()))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    let doc: ProjectPolicyDocument = toml::from_str(text)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    if doc.schema_version != MIGRATION_VERSION || &doc.project != identity {
        return Err(format!(
            "Project identity/schema mismatch in {}",
            path.display()
        ));
    }
    Ok(doc)
}

fn write_project_document(
    path: &Path,
    doc: &ProjectPolicyDocument,
) -> Result<(), String> {
    let body = toml::to_string_pretty(doc)
        .map_err(|e| format!("Cannot serialize project policy: {e}"))?;
    durable_write(path, body.as_bytes())?;
    let identity = &doc.project;
    let checked = read_project_document(path, identity)?;
    if checked != *doc {
        return Err(format!("Failed to verify {}", path.display()));
    }
    Ok(())
}

pub(crate) fn save_project_constraints(
    paths: &StorePaths,
    constraints: Config,
) -> Result<(), String> {
    let _lock = paths.prepare()?;
    let identity = paths.identity();
    let mut doc = if paths.project.exists() {
        read_project_document(&paths.project, &identity)?
    } else {
        ProjectPolicyDocument {
            schema_version: MIGRATION_VERSION,
            project: identity,
            grants: Config::default(),
            constraints: Config::default(),
            onboarding_complete: false,
            directory_grants: Vec::new(),
            approved_env_names: Vec::new(),
            restricted_ssh: None,
            migration: None,
        }
    };
    doc.constraints = config::monotonic_project_constraints(
        &constraints,
        &paths.canonical_project,
    );
    write_project_document(&paths.project, &doc)
}

pub(crate) fn save_global_document(
    paths: &StorePaths,
    global: &GlobalConfig,
) -> Result<(), String> {
    let _lock = paths.prepare()?;
    let body = toml::to_string_pretty(global)
        .map_err(|e| format!("Cannot serialize global config: {e}"))?;
    durable_write(&paths.global, body.as_bytes())?;
    let checked = load_global(paths)?;
    if checked != *global {
        return Err(format!("Failed to verify {}", paths.global.display()));
    }
    Ok(())
}

fn durable_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        let uid = unsafe { nix::libc::geteuid() };
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != uid
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(format!(
                "Refusing unsafe config target {}",
                path.display()
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| "Missing parent directory".to_string())?;
    let stem = path.file_name().unwrap_or_else(|| OsStr::new("config"));
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        stem.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(|e| format!("Cannot create {}: {e}", tmp.display()))?;
    file.write_all(contents).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(&tmp, path)
        .map_err(|e| format!("Cannot install {}: {e}", path.display()))?;
    sync_dir(parent)?;
    Ok(())
}

fn quarantine_remove(path: &Path, expected: &LegacyFile) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| "Missing source name".to_string())?;
    let dir = File::open(parent)
        .map_err(|e| format!("Cannot open {}: {e}", parent.display()))?;
    let source_name = CString::new(name.as_bytes())
        .map_err(|_| "Legacy filename contains NUL".to_string())?;
    let quarantine_name = format!(
        ".ai-jail.quarantine.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let quarantine = CString::new(quarantine_name.clone()).unwrap();
    let rc = unsafe {
        nix::libc::renameat(
            dir.as_raw_fd(),
            source_name.as_ptr(),
            dir.as_raw_fd(),
            quarantine.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(format!(
            "Cannot quarantine {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let quarantined_path = parent.join(&quarantine_name);
    sync_file(&dir).map_err(|e| recovery_error(e, &quarantined_path))?;
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            quarantine.as_ptr(),
            nix::libc::O_RDONLY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Migration source is recoverable at {}",
            quarantined_path.display()
        ));
    }
    let mut quarantined = unsafe { File::from_raw_fd(fd) };
    let metadata = quarantined.metadata().map_err(|e| {
        recovery_error(
            format!("Cannot verify quarantine: {e}"),
            &quarantined_path,
        )
    })?;
    let mut bytes = Vec::new();
    quarantined
        .read_to_end(&mut bytes)
        .map_err(|e| recovery_error(e.to_string(), &quarantined_path))?;
    if bytes != expected.bytes
        || metadata.dev() != expected.dev
        || metadata.ino() != expected.ino
    {
        drop(quarantined);
        let mut restored = false;
        if entry_absent(&dir, &source_name) {
            let restore_rc = unsafe {
                nix::libc::renameat(
                    dir.as_raw_fd(),
                    quarantine.as_ptr(),
                    dir.as_raw_fd(),
                    source_name.as_ptr(),
                )
            };
            if restore_rc == 0 {
                sync_file(&dir).map_err(|e| recovery_error(e, path))?;
                restored = true;
            }
        }
        let recovery = if restored { path } else { &quarantined_path };
        return Err(recovery_error(
            "Legacy config changed during migration; it was not deleted",
            recovery,
        ));
    }
    drop(quarantined);
    let rc =
        unsafe { nix::libc::unlinkat(dir.as_raw_fd(), quarantine.as_ptr(), 0) };
    if rc != 0 {
        return Err(format!(
            "Migration committed; source remains recoverable at {}",
            quarantined_path.display()
        ));
    }
    sync_file(&dir).map_err(|e| {
        format!("Migration destination committed and source unlinked; source-removal durability is uncertain: {e}")
    })
}

fn recovery_error(reason: impl std::fmt::Display, path: &Path) -> String {
    format!("{reason}; recoverable config: {}", path.display())
}

fn sync_dir(path: &Path) -> Result<(), String> {
    let dir = File::open(path)
        .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    sync_file(&dir)
}

fn entry_absent(dir: &File, name: &CString) -> bool {
    let mut stat = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
    let rc = unsafe {
        nix::libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            nix::libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    rc != 0
        && std::io::Error::last_os_error().kind()
            == std::io::ErrorKind::NotFound
}

fn sync_file(file: &File) -> Result<(), String> {
    file.sync_all().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_temp_dir() -> PathBuf {
        fs::canonicalize(std::env::temp_dir()).unwrap()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ExpectedStaticPolicy {
        field: &'static str,
        class: StaticPolicyClass,
        renderer: Option<StaticRenderer>,
        output: &'static [&'static str],
    }

    macro_rules! expected_authority {
        ($field:literal, $class:ident, $renderer:ident, [$($output:literal),+ $(,)?]) => {
            ExpectedStaticPolicy {
                field: $field,
                class: StaticPolicyClass::$class,
                renderer: Some(StaticRenderer::$renderer),
                output: &[$($output),+],
            }
        };
    }

    macro_rules! expected_excluded {
        ($field:literal, $class:ident) => {
            ExpectedStaticPolicy {
                field: $field,
                class: StaticPolicyClass::$class,
                renderer: None,
                output: &[],
            }
        };
    }

    const EXPECTED_STATIC_POLICY: &[ExpectedStaticPolicy] = &[
        expected_authority!("command", Authority, Command, ["command claude"]),
        expected_authority!(
            "rw_maps",
            Authority,
            RwMaps,
            ["rw-map /outside/rw"]
        ),
        expected_authority!(
            "ro_maps",
            Authority,
            RoMaps,
            ["ro-map /outside/ro"]
        ),
        expected_authority!(
            "overlay_maps",
            Authority,
            OverlayMaps,
            ["overlay-map /outside/overlay"]
        ),
        expected_excluded!("hide_dotdirs", Restriction),
        expected_excluded!("mask", Restriction),
        expected_excluded!("deny_paths", Restriction),
        expected_authority!(
            "mask_exceptions",
            Authority,
            MaskExceptions,
            ["mask-exception /outside/mask"]
        ),
        expected_authority!(
            "deny_path_exceptions",
            Authority,
            DenyExceptions,
            ["deny-path-exception /outside/deny"]
        ),
        expected_excluded!("no_save_config", Preference),
        expected_excluded!("no_status_bar", Preference),
        expected_excluded!("status_bar_style", Preference),
        expected_excluded!("resize_redraw_key", Preference),
        expected_authority!(
            "allow_tcp_ports",
            Authority,
            TcpPorts,
            ["tcp-port 443"]
        ),
        expected_authority!(
            "allow_hosts",
            Authority,
            Hosts,
            ["host api.example.com"]
        ),
        expected_authority!(
            "allow_private_hosts",
            Authority,
            PrivateHosts,
            ["private-host db.internal"]
        ),
        expected_authority!(
            "forward_ports",
            Authority,
            ForwardPorts,
            ["forward-port 8080"]
        ),
        expected_authority!(
            "publish_ports",
            Authority,
            PublishPorts,
            ["publish-port 9090"]
        ),
        expected_authority!(
            "claude_dir",
            Authority,
            ClaudeDir,
            ["claude-dir /outside/claude"]
        ),
        expected_authority!(
            "env_pass",
            SensitiveAuthority,
            EnvPass,
            ["environment-variable TOKEN"]
        ),
        expected_authority!(
            "env_from_file",
            SensitiveAuthority,
            EnvFiles,
            ["environment-file /outside/secrets.env"]
        ),
        expected_authority!(
            "secret_hosts",
            SensitiveAuthority,
            SecretHosts,
            ["secret-variable API_TOKEN for host api.example.com"]
        ),
        expected_authority!(
            "trust_project_config",
            Authority,
            TrustedProjects,
            ["trusted-project /outside/trusted"]
        ),
    ];

    fn config_with_only_static_field(field: &str) -> Config {
        let mut config = Config::default();
        match field {
            "command" => {
                config.command =
                    vec!["claude".into(), "--token=top-secret".into()];
            }
            "rw_maps" => {
                config.rw_maps = vec!["/outside/rw:/sandbox/rw".into()];
            }
            "ro_maps" => {
                config.ro_maps = vec!["/outside/ro:/sandbox/ro".into()];
            }
            "overlay_maps" => {
                config.overlay_maps =
                    vec!["/outside/overlay:/sandbox/overlay".into()];
            }
            "hide_dotdirs" => config.hide_dotdirs = vec![".secret".into()],
            "mask" => config.mask = vec!["/secret".into()],
            "deny_paths" => config.deny_paths = vec!["/denied".into()],
            "mask_exceptions" => {
                config.mask_exceptions = vec!["/outside/mask".into()];
            }
            "deny_path_exceptions" => {
                config.deny_path_exceptions = vec!["/outside/deny".into()];
            }
            "no_save_config" => config.no_save_config = Some(true),
            "no_status_bar" => config.no_status_bar = Some(true),
            "status_bar_style" => config.status_bar_style = Some("dark".into()),
            "resize_redraw_key" => {
                config.resize_redraw_key = Some("top-secret".into());
            }
            "allow_tcp_ports" => config.allow_tcp_ports = vec![443],
            "allow_hosts" => {
                config.allow_hosts = vec!["api.example.com".into()]
            }
            "allow_private_hosts" => {
                config.allow_private_hosts = vec!["db.internal".into()];
            }
            "forward_ports" => config.forward_ports = vec![8080],
            "publish_ports" => config.publish_ports = vec![9090],
            "claude_dir" => config.claude_dir = Some("/outside/claude".into()),
            "env_pass" => config.env_pass = vec!["TOKEN=top-secret".into()],
            "env_from_file" => {
                config.env_from_file = vec!["/outside/secrets.env".into()];
            }
            "secret_hosts" => {
                config
                    .secret_hosts
                    .insert("API_TOKEN".into(), "api.example.com".into());
            }
            "trust_project_config" => {
                config.trust_project_config = vec!["/outside/trusted".into()];
            }
            _ => panic!("missing independent static-field sample for {field}"),
        }
        config
    }

    #[test]
    fn every_config_field_has_an_explicit_authority_classification() {
        let source = include_str!("config.rs");
        let body = source
            .split("pub struct Config {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        let mut fields = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub "))
            .filter_map(|line| line.split_once(':').map(|(name, _)| name))
            .collect::<Vec<_>>();
        fields.sort_unstable();
        let mut classified = CONFIG_FIELD_POLICY
            .iter()
            .map(|item| match item {
                ConfigFieldPolicy::Static { field, .. }
                | ConfigFieldPolicy::Directional { field, .. } => *field,
            })
            .collect::<Vec<_>>();
        classified.sort_unstable();
        assert_eq!(
            fields, classified,
            "Config field added/removed without authority classification"
        );
    }

    #[test]
    fn authority_inventory_is_direction_sensitive_and_redacts_values() {
        let project = Path::new("/project");
        let restrictive = Config {
            no_gpu: Some(true),
            network: Some(false),
            private_home: Some(true),
            mask: vec!["/secret".into()],
            no_status_bar: Some(true),
            ..Config::default()
        };
        assert!(
            dropped_capability_requests(
                &restrictive,
                &Config::default(),
                project
            )
            .is_empty()
        );
        let authority = Config {
            no_gpu: Some(false),
            network: Some(true),
            private_home: Some(false),
            env_pass: vec!["TOKEN=super-secret".into()],
            allow_hosts: vec!["api.example.com".into()],
            ..Config::default()
        };
        let items = dropped_capability_requests(
            &authority,
            &Config::default(),
            project,
        )
        .join("|");
        for expected in [
            "gpu",
            "unrestricted-network",
            "host-home",
            "environment-variable TOKEN",
            "host api.example.com",
        ] {
            assert!(items.contains(expected), "{items}");
        }
        assert!(!items.contains("super-secret"));
    }

    #[test]
    fn every_directional_inventory_item_widens_a_restrictive_baseline() {
        let baseline = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            tailscale: Some(false),
            no_display: Some(true),
            audio: Some(false),
            github: Some(false),
            aws: Some(false),
            kube: Some(false),
            gcloud: Some(false),
            docker_config: Some(false),
            kvm: Some(false),
            prompt_hosts: Some(false),
            network: Some(false),
            macos_host_ipc: Some(false),
            macos_chromium: Some(false),
            macos_trustd: Some(false),
            allow_pty: Some(false),
            allow_loopback_listen: Some(false),
            allow_loopback_connect: Some(false),
            x11: Some(false),
            host_shm: Some(false),
            terminal_passthrough: Some(false),
            no_hide_config: Some(false),
            ssh: Some(false),
            pictures: Some(false),
            private_home: Some(true),
            lockdown: Some(true),
            no_landlock: Some(false),
            no_seccomp: Some(false),
            no_rlimits: Some(false),
            systemd_user: Some(false),
            inherit_env: Some(false),
            no_worktree: Some(true),
            no_mise: Some(true),
            no_toolchains: Some(true),
            agent_state: Some(false),
            browser_profile: Some("hard".into()),
            update_check: Some(false),
            audit_log: Some(false),
            ..Config::default()
        };
        let widening = Config {
            no_gpu: Some(false),
            no_docker: Some(false),
            tailscale: Some(true),
            no_display: Some(false),
            audio: Some(true),
            github: Some(true),
            aws: Some(true),
            kube: Some(true),
            gcloud: Some(true),
            docker_config: Some(true),
            kvm: Some(true),
            prompt_hosts: Some(true),
            network: Some(true),
            macos_host_ipc: Some(true),
            macos_chromium: Some(true),
            macos_trustd: Some(true),
            allow_pty: Some(true),
            allow_loopback_listen: Some(true),
            allow_loopback_connect: Some(true),
            x11: Some(true),
            host_shm: Some(true),
            terminal_passthrough: Some(true),
            no_hide_config: Some(true),
            ssh: Some(true),
            pictures: Some(true),
            private_home: Some(false),
            lockdown: Some(false),
            no_landlock: Some(true),
            no_seccomp: Some(true),
            no_rlimits: Some(true),
            systemd_user: Some(true),
            inherit_env: Some(true),
            no_worktree: Some(false),
            no_mise: Some(false),
            no_toolchains: Some(false),
            agent_state: Some(true),
            browser_profile: Some("soft".into()),
            update_check: Some(true),
            audit_log: Some(true),
            ..Config::default()
        };
        let rendered = dropped_capability_requests(
            &widening,
            &baseline,
            Path::new("/project"),
        );
        for item in CONFIG_FIELD_POLICY {
            let ConfigFieldPolicy::Directional {
                rule,
                renderer: label,
                ..
            } = item
            else {
                continue;
            };
            assert!(
                rule.widens(&widening, &baseline),
                "polarity missing for {label}"
            );
            assert!(
                !rule.widens(&baseline, &baseline),
                "restrictive/opposite value widened for {label}"
            );
            assert!(
                rendered.iter().any(|item| item == label
                    || item.starts_with(&format!("{label} "))),
                "renderer missing for {label}: {rendered:?}"
            );
        }
    }

    #[test]
    fn independent_static_policy_fixture_pins_class_renderer_and_output() {
        let mut actual = CONFIG_FIELD_POLICY
            .iter()
            .filter_map(|item| match item {
                ConfigFieldPolicy::Static {
                    field,
                    class,
                    renderer,
                } => Some((*field, *class, *renderer)),
                ConfigFieldPolicy::Directional { .. } => None,
            })
            .collect::<Vec<_>>();
        let mut expected = EXPECTED_STATIC_POLICY
            .iter()
            .map(|item| (item.field, item.class, item.renderer))
            .collect::<Vec<_>>();
        actual.sort_by_key(|(field, _, _)| *field);
        expected.sort_by_key(|(field, _, _)| *field);
        assert_eq!(
            actual, expected,
            "static field class or renderer changed without independent policy approval"
        );

        for expected in EXPECTED_STATIC_POLICY {
            let config = config_with_only_static_field(expected.field);
            assert_ne!(
                config,
                Config::default(),
                "sample must populate only {}",
                expected.field
            );
            let rendered = dropped_capability_requests(
                &config,
                &Config::default(),
                Path::new("/project"),
            );
            let exact = expected
                .output
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                rendered, exact,
                "unexpected sanitized output for {}",
                expected.field
            );
            assert!(
                !rendered.join("|").contains("top-secret"),
                "sensitive value leaked for {}",
                expected.field
            );
            assert!(
                dropped_capability_requests(
                    &config,
                    &config,
                    Path::new("/project")
                )
                .is_empty(),
                "unchanged {} sample must be negative",
                expected.field
            );
        }
    }

    #[test]
    fn changed_sensitive_authority_is_detected_but_safely_rendered() {
        let mut baseline_secrets = std::collections::BTreeMap::new();
        baseline_secrets.insert("TOKEN".into(), "old.example.com".into());
        let baseline = Config {
            command: vec!["claude".into(), "--token=old-secret".into()],
            env_pass: vec!["API_KEY=old-secret".into()],
            env_from_file: vec!["/outside/old.env".into()],
            secret_hosts: baseline_secrets,
            ..Config::default()
        };
        let mut changed_secrets = std::collections::BTreeMap::new();
        changed_secrets.insert("TOKEN".into(), "new.example.com".into());
        let changed = Config {
            command: vec!["claude".into(), "--token=new-secret".into()],
            env_pass: vec!["API_KEY=new-secret".into()],
            env_from_file: vec!["/outside/new.env".into()],
            secret_hosts: changed_secrets,
            ..Config::default()
        };
        let rendered = dropped_capability_requests(
            &changed,
            &baseline,
            Path::new("/project"),
        )
        .join("|");
        for safe in [
            "command claude",
            "environment-variable API_KEY",
            "environment-file /outside/new.env",
            "secret-variable TOKEN for host new.example.com",
        ] {
            assert!(rendered.contains(safe), "missing {safe}: {rendered}");
        }
        for secret in ["old-secret", "new-secret", "--token"] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
    }

    #[test]
    fn precedence_is_global_then_grants_then_cli_then_constraints() {
        let project = Path::new("/project");
        let global = Config {
            github: Some(false),
            no_gpu: Some(false),
            ..Config::default()
        };
        let grants = Config {
            github: Some(true),
            ..Config::default()
        };
        let trusted = config::merge_trusted_project(global, grants);
        let cli = crate::cli::CliArgs {
            github: Some(false),
            audio: Some(true),
            ..crate::cli::CliArgs::default()
        };
        let baseline = config::merge(&cli, trusted);
        let constraints = Config {
            no_gpu: Some(true),
            audio: Some(false),
            ..Config::default()
        };
        let effective =
            config::merge_with_global_report(baseline, constraints, project).0;
        assert_eq!(
            effective.github,
            Some(false),
            "CLI must override grants/global"
        );
        assert_eq!(
            effective.no_gpu,
            Some(true),
            "constraints must override global grant"
        );
        assert_eq!(
            effective.audio,
            Some(false),
            "constraints must override CLI grant"
        );
    }

    #[test]
    fn identity_uses_canonical_checkout() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-store-{}", std::process::id()));
        let real = root.join("real");
        let alias = root.join("alias");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(
            project_identity(&fs::canonicalize(&real).unwrap()),
            project_identity(&fs::canonicalize(&alias).unwrap())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn strict_envelope_rejects_unknown_fields() {
        let text = "schema_version=1\nunknown=true\n[project]\ncanonical_path='/tmp/p'\nkey='p-x'\n";
        assert!(toml::from_str::<ProjectPolicyDocument>(text).is_err());
    }

    #[test]
    fn monotonic_migration_drops_command_and_grants() {
        let project = Path::new("/tmp/project");
        let source = Config {
            command: vec!["sh".into()],
            github: Some(true),
            no_gpu: Some(true),
            ..Config::default()
        };
        let projected = config::monotonic_project_constraints(&source, project);
        assert!(projected.command.is_empty());
        assert_ne!(projected.github, Some(true));
        assert_eq!(projected.no_gpu, Some(true));
    }

    #[test]
    fn quarantine_refuses_replaced_inode_and_restores_replacement() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-quarantine-race-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(".ai-jail");
        fs::write(&path, "no_gpu=true\n").unwrap();
        let expected = read_legacy_regular(&path).unwrap().unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, "network=false\n").unwrap();

        let error = quarantine_remove(&path, &expected).unwrap_err();
        assert!(error.contains(&path.display().to_string()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "network=false\n");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn overlap_rejects_canonical_and_symlink_aliases() {
        let root = canonical_temp_dir()
            .join(format!("ai-jail-overlap-{}", std::process::id()));
        let store = root.join("store");
        let alias = root.join("alias");
        fs::create_dir_all(&store).unwrap();
        std::os::unix::fs::symlink(&store, &alias).unwrap();
        assert!(reject_overlap("map", &store, &store).is_err());
        assert!(reject_overlap("map", &alias, &store).is_err());
        assert!(reject_overlap("map", &root, &store).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn placeholder_cleanup_is_identity_checked() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-placeholder-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(".ai-jail");
        fs::write(&path, "replacement").unwrap();
        let meta = fs::metadata(&path).unwrap();
        drop(LegacyMaskPlaceholder {
            path: Some(path.clone()),
            dev: meta.dev(),
            ino: meta.ino() + 1,
        });
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn project_document_round_trip_marks_onboarding_complete() {
        let base = canonical_temp_dir()
            .join(format!("ai-jail-onboarding-store-{}", std::process::id()));
        let project = base.join("project");
        let root = base.join("config/ai-jail");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&project).unwrap();
        let canonical_project = fs::canonicalize(&project).unwrap();
        let identity = project_identity(&canonical_project);
        let paths = StorePaths {
            available: true,
            root: root.clone(),
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root
                .join("projects")
                .join(format!("{}.toml", identity.key)),
            legacy_global: base.join("home/.ai-jail"),
            legacy_project: project.join(".ai-jail"),
            canonical_project,
        };
        let grants = Config {
            agent_state: Some(false),
            github: Some(true),
            ..Config::default()
        };

        save_project_grants(
            &paths,
            grants.clone(),
            vec!["CUSTOM_MODE".into()],
            &[],
            None,
        )
        .unwrap();
        let loaded = load_project(&paths).unwrap();

        assert!(loaded.present);
        assert!(loaded.onboarding_complete);
        assert_eq!(loaded.grants, grants);
        assert_eq!(loaded.approved_env_names, vec!["CUSTOM_MODE"]);
        let serialized = fs::read_to_string(&paths.project).unwrap();
        assert!(serialized.contains("CUSTOM_MODE"));
        assert!(!serialized.contains("secret-value"));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn saving_onboarding_grants_preserves_existing_constraints() {
        let base = canonical_temp_dir().join(format!(
            "ai-jail-save-grants-preserves-constraints-{}",
            std::process::id()
        ));
        let project = base.join("project");
        let root = base.join("config/ai-jail");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&project).unwrap();
        let canonical_project = fs::canonicalize(&project).unwrap();
        let identity = project_identity(&canonical_project);
        let paths = StorePaths {
            available: true,
            root: root.clone(),
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root
                .join("projects")
                .join(format!("{}.toml", identity.key)),
            legacy_global: base.join("home/.ai-jail"),
            legacy_project: project.join(".ai-jail"),
            canonical_project,
        };
        let constraints = Config {
            lockdown: Some(true),
            mask: vec!["/host/private".into()],
            ..Config::default()
        };
        save_project_constraints(&paths, constraints.clone()).unwrap();
        save_project_grants(
            &paths,
            Config {
                agent_state: Some(false),
                ..Config::default()
            },
            Vec::new(),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(load_project(&paths).unwrap().constraints, constraints);
        let before = fs::read(&paths.project).unwrap();
        let projects = paths.project.parent().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(projects, fs::Permissions::from_mode(0o500))
            .unwrap();
        let failed = save_project_grants(
            &paths,
            Config {
                github: Some(true),
                ..Config::default()
            },
            Vec::new(),
            &[],
            None,
        );
        fs::set_permissions(projects, fs::Permissions::from_mode(0o700))
            .unwrap();
        assert!(failed.is_err());
        assert_eq!(fs::read(&paths.project).unwrap(), before);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn directory_grant_identity_refuses_symlink_swap_and_disappearance() {
        use std::os::unix::fs::symlink;

        let base = canonical_temp_dir().join(format!(
            "ai-jail-onboarding-identity-{}",
            std::process::id()
        ));
        let project = base.join("project");
        let first = base.join("first");
        let second = base.join("second");
        let link = base.join("shared");
        let root = base.join("config/ai-jail");
        let _ = fs::remove_dir_all(&base);
        for path in [&project, &first, &second] {
            fs::create_dir_all(path).unwrap();
        }
        symlink(&first, &link).unwrap();
        let canonical_project = fs::canonicalize(&project).unwrap();
        let identity = project_identity(&canonical_project);
        let paths = StorePaths {
            available: true,
            root: root.clone(),
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root
                .join("projects")
                .join(format!("{}.toml", identity.key)),
            legacy_global: base.join("home/.ai-jail"),
            legacy_project: project.join(".ai-jail"),
            canonical_project,
        };
        let grants = Config {
            ro_maps: vec![link.clone()],
            ..Config::default()
        };
        let approved =
            capture_directory_grants(&grants, &paths.canonical_project)
                .unwrap();
        save_project_grants(&paths, grants, Vec::new(), &approved, None)
            .unwrap();
        fs::remove_dir(&first).unwrap();
        fs::rename(&second, &first).unwrap();
        assert!(load_project(&paths).unwrap_err().contains("AJ-PATH-004"));

        fs::remove_dir(&first).unwrap();
        assert!(load_project(&paths).unwrap_err().contains("unavailable"));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn launch_once_directory_identity_is_reverified_before_execution() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "ai-jail-launch-once-directory-identity-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let project = base.join("project");
        let approved = base.join("approved");
        let replacement = base.join("replacement");
        let link = base.join("shared");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&approved).unwrap();
        fs::create_dir_all(&replacement).unwrap();
        symlink(&approved, &link).unwrap();
        let mut grants = Config {
            ro_maps: vec![fs::canonicalize(&link).unwrap()],
            ..Config::default()
        };
        let identities = capture_directory_grants(&grants, &project).unwrap();

        fs::remove_dir(&approved).unwrap();
        fs::rename(&replacement, &approved).unwrap();
        let error =
            validate_directory_grants(&mut grants, &identities, &project)
                .unwrap_err();
        assert!(error.contains(crate::onboarding::messages::PATH_DRIFT_ID));

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn save_refuses_directory_swapped_after_preview_and_preserves_policy() {
        let base = canonical_temp_dir().join(format!(
            "ai-jail-save-directory-race-{}",
            std::process::id()
        ));
        let project = base.join("project");
        let approved = base.join("approved");
        let replacement = base.join("replacement");
        let root = base.join("config/ai-jail");
        let _ = fs::remove_dir_all(&base);
        for path in [&project, &approved, &replacement] {
            fs::create_dir_all(path).unwrap();
        }
        let canonical_project = fs::canonicalize(&project).unwrap();
        let identity = project_identity(&canonical_project);
        let paths = StorePaths {
            available: true,
            root: root.clone(),
            global: root.join("config.toml"),
            global_provenance: root.join("global-migration.toml"),
            project: root
                .join("projects")
                .join(format!("{}.toml", identity.key)),
            legacy_global: base.join("home/.ai-jail"),
            legacy_project: project.join(".ai-jail"),
            canonical_project,
        };
        save_project_grants(&paths, Config::default(), Vec::new(), &[], None)
            .unwrap();
        let before = fs::read(&paths.project).unwrap();
        let grants = Config {
            ro_maps: vec![approved.clone()],
            ..Config::default()
        };
        let preview_identities =
            capture_directory_grants(&grants, &project).unwrap();
        fs::remove_dir(&approved).unwrap();
        fs::rename(&replacement, &approved).unwrap();

        let error = save_project_grants(
            &paths,
            grants,
            Vec::new(),
            &preview_identities,
            None,
        )
        .unwrap_err();
        assert!(error.contains(crate::onboarding::messages::PATH_DRIFT_ID));
        assert_eq!(fs::read(&paths.project).unwrap(), before);
        assert!(load_project(&paths).unwrap().grants.ro_maps.is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn directory_grant_identity_rejects_colon_and_non_utf8_paths() {
        #[cfg(target_os = "linux")]
        use std::os::unix::ffi::OsStringExt;

        let base = canonical_temp_dir()
            .join(format!("ai-jail-onboarding-path-{}", std::process::id()));
        let colon = base.join("bad:name");
        fs::create_dir_all(&colon).unwrap();
        let error = capture_directory_grants(
            &Config {
                ro_maps: vec![colon],
                ..Config::default()
            },
            &base.join("project"),
        )
        .unwrap_err();
        assert!(
            error.contains("cannot change") || error.contains("cannot contain")
        );

        #[cfg(target_os = "linux")]
        {
            let invalid = base.join(std::ffi::OsString::from_vec(vec![0xff]));
            fs::create_dir_all(&invalid).unwrap();
            let error = capture_directory_grants(
                &Config {
                    ro_maps: vec![invalid],
                    ..Config::default()
                },
                &base.join("project"),
            )
            .unwrap_err();
            assert!(error.contains("UTF-8"));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn restricted_ssh_policy_serializes_names_and_identity_not_key_material() {
        let doc = ProjectPolicyDocument {
            schema_version: MIGRATION_VERSION,
            project: ProjectIdentity {
                canonical_path: "/work/project".into(),
                key: "project-fixture".into(),
            },
            grants: Config::default(),
            constraints: Config::default(),
            onboarding_complete: true,
            directory_grants: Vec::new(),
            approved_env_names: Vec::new(),
            restricted_ssh: Some(crate::ssh_restricted::Policy {
                keys: vec![crate::ssh_restricted::KeyIdentity {
                    private_path: "/home/test/.ssh/id_test".into(),
                    public_path: "/home/test/.ssh/id_test.pub".into(),
                    fingerprint: "SHA256:fixture".into(),
                    comment: "fixture@example".into(),
                    private_dev: 1,
                    private_ino: 2,
                    public_dev: 1,
                    public_ino: 3,
                }],
                lifetime_seconds: 600,
                destinations: vec!["git@example.test".into()],
            }),
            migration: None,
        };
        let text = toml::to_string_pretty(&doc).unwrap();
        assert!(text.contains("SHA256:fixture"));
        assert!(!text.contains("PRIVATE KEY"));
        assert_eq!(
            toml::from_str::<ProjectPolicyDocument>(&text).unwrap(),
            doc
        );
    }
}
