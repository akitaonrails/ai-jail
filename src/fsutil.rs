use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn ensure_regular_file_or_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(format!("{} is a symlink", path.display()));
            }
            if !ft.is_file() {
                return Err(format!(
                    "{} exists but is not a regular file",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Cannot stat {}: {e}", path.display())),
    }
}

/// Reject existing symlink components before a bootstrap write. This narrows
/// path redirection attacks but cannot eliminate TOCTOU races without openat2.
pub(crate) fn ensure_no_symlink_parents(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut current = if parent.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in parent.components() {
        use std::path::Component;
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => current.push(component.as_os_str()),
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(format!(
                            "{} has a symlink parent ({})",
                            path.display(),
                            current.display()
                        ));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => {
                        return Err(format!(
                            "Cannot stat {}: {e}",
                            current.display()
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn write_atomic(
    path: &Path,
    contents: &str,
    create_parent_dirs: bool,
    fallback_stem: &str,
) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if create_parent_dirs {
        fs::create_dir_all(parent).map_err(|e| {
            format!("Cannot create directory {}: {e}", parent.display())
        })?;
    }
    let existing_mode = fs::symlink_metadata(path)
        .ok()
        .filter(|meta| {
            !meta.file_type().is_symlink() && meta.file_type().is_file()
        })
        .map(|meta| meta.permissions().mode());

    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback_stem);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_path =
        parent.join(format!(".{stem}.tmp.{}.{}", std::process::id(), nonce));
    let mut tmp_guard = TempGuard::new(tmp_path.clone());

    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| {
            format!("Failed to create temp file {}: {e}", tmp_path.display())
        })?;

    f.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);

    fs::rename(&tmp_path, path).map_err(|e| {
        format!("Failed to rename temp file to {}: {e}", path.display())
    })?;
    tmp_guard.disarm();
    if let Some(mode) = existing_mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(
            |e| {
                format!(
                    "Failed to restore permissions on {}: {e}",
                    path.display()
                )
            },
        )?;
    }
    // Best effort: persist the rename itself where the platform supports it.
    if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub(crate) fn backup_file(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    ensure_regular_file_or_absent(path)?;
    let mut bak = path.as_os_str().to_owned();
    bak.push(".bak");
    let bak_path = PathBuf::from(bak);
    ensure_regular_file_or_absent(&bak_path)?;
    fs::copy(path, &bak_path)
        .map_err(|e| format!("Failed to backup {}: {e}", path.display()))?;
    fs::set_permissions(&bak_path, fs::Permissions::from_mode(0o600)).map_err(
        |e| format!("Failed to secure backup {}: {e}", bak_path.display()),
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_preserves_existing_mode() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-fsutil-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("secret");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_atomic(&path, "new", false, "secret").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(dir);
    }
}
