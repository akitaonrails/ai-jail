//! Real Linux bind mounts must preserve explicitly restored host content
//! beneath an alternate-source map. All files and HOME are synthetic.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, assert_ok};

struct MapFixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    base: PathBuf,
    nested: PathBuf,
    replacement: PathBuf,
    leaf: PathBuf,
}

impl MapFixture {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("map-precedence-{name}-{}", std::process::id()));
        let home = root.join("home");
        let project = root.join("project");
        // Keep the maps outside the project so its own bind cannot restore
        // the original contents and accidentally hide the regression.
        let base = root.join("base");
        let nested = base.join("nested");
        let replacement = root.join("replacement");
        let leaf = nested.join("settings");
        for path in [&home, &project, &nested, &replacement] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(&leaf, "ORIGINAL\n").unwrap();
        std::fs::write(replacement.join("settings"), "REPLACEMENT\n").unwrap();
        Self {
            root,
            home,
            project,
            base,
            nested,
            replacement,
            leaf,
        }
    }

    fn read_with_restore(&self, restore: &Path) -> Output {
        let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
        Command::new(ai_jail())
            .args([
                "--clean",
                "--no-mise",
                "--no-toolchains",
                "--no-agent-state",
                "--no-network",
                "--no-save-config",
                "--no-status-bar",
                "--exec",
            ])
            .arg("--map")
            .arg(&self.base)
            .arg("--map")
            .arg(format!(
                "{}:{}",
                self.replacement.display(),
                self.nested.display()
            ))
            .arg("--map")
            .arg(restore)
            .arg("/bin/cat")
            .arg(&self.leaf)
            .current_dir(&self.project)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("failed to run ai-jail with synthetic read-only maps")
    }
}

impl Drop for MapFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn cat_available() -> bool {
    if Path::new("/bin/cat").is_file() {
        return true;
    }
    eprintln!("SKIPPED: /bin/cat unavailable on this non-FHS system");
    false
}

#[test]
fn same_path_leaf_overrides_an_alternate_source_ancestor() {
    require_bwrap!();
    if !cat_available() {
        return;
    }
    let fixture = MapFixture::new("leaf");
    let output = fixture.read_with_restore(&fixture.leaf);
    assert_eq!(
        assert_ok(&output),
        "ORIGINAL\n",
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn same_path_map_restores_a_previously_remapped_destination() {
    require_bwrap!();
    if !cat_available() {
        return;
    }
    let fixture = MapFixture::new("same-destination");
    let output = fixture.read_with_restore(&fixture.nested);
    assert_eq!(
        assert_ok(&output),
        "ORIGINAL\n",
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
