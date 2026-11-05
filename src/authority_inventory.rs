//! Single source of truth for host credential and harness-state authority.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocationBasis {
    Home,
    XdgConfig,
    XdgData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Macos,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedStatePath {
    pub(crate) authority: &'static AuthorityPath,
    pub(crate) path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExposureMode {
    ProtectedOnly,
    HarnessState {
        harness: &'static str,
        linux: bool,
        macos: bool,
        kind: StateKind,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityPath {
    pub(crate) provider: &'static str,
    pub(crate) basis: LocationBasis,
    pub(crate) relative: &'static str,
    pub(crate) exposure: ExposureMode,
}

macro_rules! protected {
    ($provider:literal, $basis:ident, $path:literal) => {
        AuthorityPath {
            provider: $provider,
            basis: LocationBasis::$basis,
            relative: $path,
            exposure: ExposureMode::ProtectedOnly,
        }
    };
}

macro_rules! state {
    ($provider:literal, $basis:ident, $path:literal, $harness:literal, $linux:literal, $macos:literal, $kind:ident) => {
        AuthorityPath {
            provider: $provider,
            basis: LocationBasis::$basis,
            relative: $path,
            exposure: ExposureMode::HarnessState {
                harness: $harness,
                linux: $linux,
                macos: $macos,
                kind: StateKind::$kind,
            },
        }
    };
}

/// Complete authority inventory. Every onboarding credential boundary and
/// every command-specific sandbox state exposure is selected from this table.
pub(crate) const AUTHORITY_PATHS: &[AuthorityPath] = &[
    protected!("ssh", Home, ".ssh"),
    protected!("gpg", Home, ".gnupg"),
    protected!("aws", Home, ".aws"),
    protected!("kubernetes", Home, ".kube"),
    protected!("docker", Home, ".docker"),
    protected!("azure", Home, ".azure"),
    protected!("github", Home, ".config/gh"),
    protected!("google-cloud", Home, ".config/gcloud"),
    protected!("ai-jail", Home, ".config/ai-jail"),
    state!("claude", Home, ".claude", "claude", true, true, Directory),
    state!("claude", Home, ".claude.json", "claude", true, true, File),
    state!("codex", Home, ".codex", "codex", true, true, Directory),
    state!("gemini", Home, ".gemini", "gemini", true, true, Directory),
    state!(
        "gemini",
        Home,
        ".gemini",
        "antigravity",
        true,
        true,
        Directory
    ),
    state!(
        "opencode",
        Home,
        ".config/opencode",
        "opencode",
        true,
        true,
        Directory
    ),
    state!(
        "opencode",
        Home,
        ".local/share/opencode",
        "opencode",
        true,
        true,
        Directory
    ),
    state!("crush", Home, ".crush", "crush", true, true, Directory),
    state!(
        "crush",
        Home,
        ".config/crush",
        "crush",
        true,
        true,
        Directory
    ),
    state!(
        "crush",
        Home,
        ".local/share/crush",
        "crush",
        true,
        true,
        Directory
    ),
    state!("grok", Home, ".grok", "grok", true, true, Directory),
    state!("kimi", Home, ".kimi", "kimi*", true, true, Directory),
    state!("kimi", Home, ".kimi-code", "kimi*", true, true, Directory),
    state!("jcode", Home, ".jcode", "jcode", true, true, Directory),
    state!(
        "jcode",
        Home,
        ".config/jcode",
        "jcode",
        true,
        true,
        Directory
    ),
    state!("pi", Home, ".pi", "pi", true, true, Directory),
    state!("pi", Home, ".pi-lens", "pi", true, true, Directory),
    state!("aider", Home, ".aider", "aider", true, true, Directory),
    state!(
        "soulforge",
        Home,
        ".soulforge",
        "soulforge",
        true,
        true,
        Directory
    ),
    state!("omp", Home, ".omp", "omp", true, true, Directory),
    state!("kiro", Home, ".kiro", "kiro-cli", true, true, Directory),
    state!(
        "kiro",
        Home,
        ".local/share/kiro-cli",
        "kiro-cli",
        true,
        false,
        Directory
    ),
    state!(
        "prime",
        Home,
        ".prime/agent",
        "prime-agent",
        true,
        true,
        Directory
    ),
    protected!("devin", Home, ".local/share/devin"),
    protected!("devin", Home, ".config/devin"),
    protected!("github", XdgConfig, "gh"),
    protected!("google-cloud", XdgConfig, "gcloud"),
    protected!("ai-jail", XdgConfig, "ai-jail"),
    protected!("opencode", XdgConfig, "opencode"),
    protected!("crush", XdgConfig, "crush"),
    protected!("jcode", XdgConfig, "jcode"),
    state!("devin", XdgConfig, "devin", "devin", true, true, Directory),
    protected!("opencode", XdgData, "opencode"),
    protected!("crush", XdgData, "crush"),
    state!(
        "kiro", XdgData, "kiro-cli", "kiro-cli", false, true, Directory
    ),
    state!("devin", XdgData, "devin", "devin", true, true, Directory),
];

pub(crate) fn harness_state_paths(
    harness: &str,
    basis: LocationBasis,
    linux: bool,
) -> impl Iterator<Item = &'static AuthorityPath> {
    AUTHORITY_PATHS.iter().filter(move |entry| {
        if entry.basis != basis {
            return false;
        }
        let ExposureMode::HarnessState {
            harness: expected,
            linux: on_linux,
            macos: on_macos,
            ..
        } = entry.exposure
        else {
            return false;
        };
        let matches = expected
            .strip_suffix('*')
            .map_or(harness == expected, |prefix| harness.starts_with(prefix));
        matches && if linux { on_linux } else { on_macos }
    })
}

/// Resolve the inventory entries for one harness and location basis. Backends
/// provide the already validated HOME/XDG root, while the inventory remains
/// the sole selector for paths and file-vs-directory permissions.
pub(crate) fn resolve_harness_state(
    harness: &str,
    basis: LocationBasis,
    platform: Platform,
    root: &Path,
) -> Vec<ResolvedStatePath> {
    harness_state_paths(harness, basis, platform == Platform::Linux)
        .map(|authority| ResolvedStatePath {
            authority,
            path: root.join(authority.relative),
        })
        .collect()
}

pub(crate) fn state_hide_scope(authority: &AuthorityPath) -> &str {
    match authority.exposure {
        ExposureMode::HarnessState {
            kind: StateKind::File,
            ..
        } => Path::new(authority.relative)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(authority.relative),
        _ => authority.relative,
    }
}

pub(crate) struct ProtectedRoots {
    pub(crate) home: PathBuf,
    pub(crate) xdg_config: Option<PathBuf>,
    pub(crate) xdg_data: Option<PathBuf>,
}

fn canonical_required(path: &Path, label: &str) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|error| {
        format!(
            "Cannot establish {label} identity {}: {error}",
            path.display()
        )
    })
}

fn configured_path(
    entry: &AuthorityPath,
    roots: &ProtectedRoots,
) -> Option<PathBuf> {
    let root = match entry.basis {
        LocationBasis::Home => Some(&roots.home),
        LocationBasis::XdgConfig => roots.xdg_config.as_ref(),
        LocationBasis::XdgData => roots.xdg_data.as_ref(),
    }?;
    Some(root.join(entry.relative))
}

pub(crate) fn is_protected(path: &Path, home: &Path) -> Result<bool, String> {
    is_protected_with(
        path,
        &ProtectedRoots {
            home: home.to_path_buf(),
            xdg_config: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            xdg_data: std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        },
    )
}

pub(crate) fn is_protected_with(
    path: &Path,
    roots: &ProtectedRoots,
) -> Result<bool, String> {
    let path = canonical_required(path, "directory grant")?;
    let normalized = ProtectedRoots {
        home: if roots.home.exists() {
            canonical_required(&roots.home, "HOME")?
        } else {
            roots.home.clone()
        },
        xdg_config: roots.xdg_config.clone(),
        xdg_data: roots.xdg_data.clone(),
    };
    for entry in AUTHORITY_PATHS {
        let Some(configured) = configured_path(entry, &normalized) else {
            continue;
        };
        let root = if configured.exists() {
            canonical_required(&configured, "credential root")?
        } else {
            configured
        };
        if path == root || path.starts_with(&root) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn map_is_protected(encoded: &Path) -> Result<bool, String> {
    let source = crate::config::MapSpec::parse(encoded)?.source;
    let home =
        std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            "Cannot classify credential paths because HOME is not set"
                .to_string()
        })?;
    is_protected(&source, &home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn inventory_fixture_drives_classification_and_sandbox_exposure() {
        let expected = include_str!(
            "../tests/fixtures/onboarding/authority-inventory.txt"
        );
        let actual = AUTHORITY_PATHS
            .iter()
            .map(|entry| {
                let exposure = match entry.exposure {
                    ExposureMode::ProtectedOnly => "protected".to_string(),
                    ExposureMode::HarnessState {
                        harness,
                        linux,
                        macos,
                        kind,
                    } => format!(
                        "state:{harness}:linux={linux}:macos={macos}:kind={}",
                        if kind == StateKind::File {
                            "file"
                        } else {
                            "dir"
                        }
                    ),
                };
                format!(
                    "{}|{:?}|{}|{exposure}",
                    entry.provider, entry.basis, entry.relative
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(actual, expected);

        let root = std::env::temp_dir().join(format!(
            "ai-jail-authority-inventory-{}",
            std::process::id()
        ));
        let home = root.join("home");
        let config = root.join("xdg-config");
        let data = root.join("xdg-data");
        let home_alias = root.join("home-alias");
        let config_alias = root.join("config-alias");
        let data_alias = root.join("data-alias");
        let _ = std::fs::remove_dir_all(&root);
        for path in [&home, &config, &data] {
            std::fs::create_dir_all(path).unwrap();
        }
        symlink(&home, &home_alias).unwrap();
        symlink(&config, &config_alias).unwrap();
        symlink(&data, &data_alias).unwrap();
        for entry in AUTHORITY_PATHS {
            let base = match entry.basis {
                LocationBasis::Home => &home,
                LocationBasis::XdgConfig => &config,
                LocationBasis::XdgData => &data,
            };
            let path = base.join(entry.relative);
            if matches!(
                entry.exposure,
                ExposureMode::HarnessState {
                    harness: "claude",
                    linux: true,
                    macos: true,
                    kind: StateKind::File
                }
            ) {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, b"{}").unwrap();
            } else {
                std::fs::create_dir_all(&path).unwrap();
            }
        }
        let direct = ProtectedRoots {
            home: home.clone(),
            xdg_config: Some(config.clone()),
            xdg_data: Some(data.clone()),
        };
        let aliases = ProtectedRoots {
            home: home_alias.clone(),
            xdg_config: Some(config_alias.clone()),
            xdg_data: Some(data_alias.clone()),
        };
        for entry in AUTHORITY_PATHS {
            let (base, alias) = match entry.basis {
                LocationBasis::Home => (&home, &home_alias),
                LocationBasis::XdgConfig => (&config, &config_alias),
                LocationBasis::XdgData => (&data, &data_alias),
            };
            assert!(
                is_protected_with(&base.join(entry.relative), &direct).unwrap(),
                "direct {entry:?}"
            );
            assert!(
                is_protected_with(&alias.join(entry.relative), &aliases)
                    .unwrap(),
                "alias {entry:?}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_drives_linux_and_macos_resolved_state_permissions() {
        let home = Path::new("/fixture/home");
        let xdg_config = Path::new("/fixture/config");
        let xdg_data = Path::new("/fixture/data");

        let linux_claude = resolve_harness_state(
            "claude",
            LocationBasis::Home,
            Platform::Linux,
            home,
        );
        assert_eq!(
            linux_claude
                .iter()
                .map(|state| (state.path.as_path(), state.authority.exposure))
                .collect::<Vec<_>>(),
            vec![
                (
                    Path::new("/fixture/home/.claude"),
                    ExposureMode::HarnessState {
                        harness: "claude",
                        linux: true,
                        macos: true,
                        kind: StateKind::Directory,
                    },
                ),
                (
                    Path::new("/fixture/home/.claude.json"),
                    ExposureMode::HarnessState {
                        harness: "claude",
                        linux: true,
                        macos: true,
                        kind: StateKind::File,
                    },
                ),
            ]
        );
        let mac_kiro = resolve_harness_state(
            "kiro-cli",
            LocationBasis::XdgData,
            Platform::Macos,
            Path::new("/fixture/Library/Application Support"),
        );
        assert_eq!(
            mac_kiro
                .iter()
                .map(|state| state.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("/fixture/Library/Application Support/kiro-cli")]
        );
        for (basis, root) in [
            (LocationBasis::XdgData, xdg_data),
            (LocationBasis::XdgConfig, xdg_config),
        ] {
            for platform in [Platform::Linux, Platform::Macos] {
                let devin =
                    resolve_harness_state("devin", basis, platform, root);
                assert_eq!(devin.len(), 1);
                assert_eq!(devin[0].path, root.join("devin"));
                assert!(matches!(
                    devin[0].authority.exposure,
                    ExposureMode::HarnessState {
                        kind: StateKind::Directory,
                        ..
                    }
                ));
            }
        }
    }
}
