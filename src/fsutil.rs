use std::fs::{self, OpenOptions};
use std::io::Write;
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

    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback_stem);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_path =
        parent.join(format!(".{stem}.tmp.{}.{}", std::process::id(), nonce));

    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|e| {
            format!("Failed to create temp file {}: {e}", tmp_path.display())
        })?;

    if let Err(e) = f.write_all(contents.as_bytes()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    if let Err(e) = f.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    drop(f);

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to rename temp file to {}: {e}", path.display())
    })
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
    Ok(true)
}
