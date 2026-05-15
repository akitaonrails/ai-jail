//! Shared test helpers for the `sandbox` module tree.
//!
//! Only compiled under `#[cfg(test)]`; not part of the production
//! binary. Lives here (instead of being duplicated in each test
//! module) so a fixture only has to be updated in one place.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A real on-disk linked-git-worktree layout, valid against
/// `validate_linked_git_worktree`.
///
/// ```text
/// root/
/// ├── project/
/// │   └── .git              (gitfile pointing at ../common/.git/worktrees/wt1)
/// └── common/
///     └── .git/
///         └── worktrees/wt1/
///             ├── gitdir    (../../../../project/.git)
///             └── commondir (../..)
/// ```
///
/// Cleaned up on drop via `remove_dir_all(root)`.
pub(crate) struct LinkedWorktreeFixture {
    pub root: PathBuf,
    pub project_dir: PathBuf,
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
}

impl Drop for LinkedWorktreeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Build a [`LinkedWorktreeFixture`] under `$TMPDIR`. `prefix` is
/// embedded in the temp dir name to keep concurrent test runs from
/// the same module from colliding.
pub(crate) fn linked_worktree_fixture(prefix: &str) -> LinkedWorktreeFixture {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir()
        .join(format!("ai-jail-{prefix}-{}-{nonce}", std::process::id()));
    let project_dir = root.join("project");
    let common_dir = root.join("common/.git");
    let git_dir = common_dir.join("worktrees/wt1");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(
        project_dir.join(".git"),
        "gitdir: ../common/.git/worktrees/wt1\n",
    )
    .unwrap();
    std::fs::write(git_dir.join("gitdir"), "../../../../project/.git\n")
        .unwrap();
    std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();

    LinkedWorktreeFixture {
        root,
        project_dir,
        git_dir,
        common_dir,
    }
}
