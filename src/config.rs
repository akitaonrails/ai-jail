use crate::cli::CliArgs;
use crate::output;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = ".ai-jail";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub rw_maps: Vec<PathBuf>,
    #[serde(default)]
    pub ro_maps: Vec<PathBuf>,
    #[serde(default)]
    pub hide_dotdirs: Vec<String>,
    #[serde(default)]
    pub mask: Vec<PathBuf>,
    #[serde(default)]
    pub no_gpu: Option<bool>,
    #[serde(default)]
    pub no_docker: Option<bool>,
    #[serde(default)]
    pub no_display: Option<bool>,
    #[serde(default)]
    pub no_worktree: Option<bool>,
    #[serde(default)]
    pub no_mise: Option<bool>,
    #[serde(default)]
    pub no_save_config: Option<bool>,
    #[serde(default)]
    pub ssh: Option<bool>,
    #[serde(default)]
    pub pictures: Option<bool>,
    #[serde(default)]
    pub lockdown: Option<bool>,
    #[serde(default)]
    pub no_landlock: Option<bool>,
    #[serde(default)]
    pub no_status_bar: Option<bool>,
    #[serde(default)]
    pub status_bar_style: Option<String>,
    #[serde(default)]
    pub resize_redraw_key: Option<String>,
    #[serde(default)]
    pub no_seccomp: Option<bool>,
    #[serde(default)]
    pub no_rlimits: Option<bool>,
    #[serde(default)]
    pub allow_tcp_ports: Vec<u16>,
}

impl Config {
    pub fn gpu_enabled(&self) -> bool {
        self.no_gpu != Some(true)
    }
    pub fn docker_enabled(&self) -> bool {
        self.no_docker != Some(true)
    }
    pub fn display_enabled(&self) -> bool {
        self.no_display != Some(true)
    }
    pub fn mise_enabled(&self) -> bool {
        self.no_mise != Some(true)
    }
    pub fn worktree_enabled(&self) -> bool {
        self.no_worktree != Some(true)
    }
    pub fn lockdown_enabled(&self) -> bool {
        self.lockdown == Some(true)
    }
    pub fn save_config_enabled(&self) -> bool {
        self.no_save_config != Some(true)
    }
    pub fn ssh_enabled(&self) -> bool {
        self.ssh == Some(true)
    }
    pub fn pictures_enabled(&self) -> bool {
        self.pictures == Some(true)
    }
    pub fn landlock_enabled(&self) -> bool {
        self.no_landlock != Some(true)
    }
    pub fn status_bar_enabled(&self) -> bool {
        self.no_status_bar != Some(true)
    }
    pub fn status_bar_style(&self) -> &str {
        match self.status_bar_style.as_deref() {
            Some("light") => "light",
            Some("dark") => "dark",
            _ => "pastel",
        }
    }
    pub fn seccomp_enabled(&self) -> bool {
        self.no_seccomp != Some(true)
    }
    pub fn rlimits_enabled(&self) -> bool {
        self.no_rlimits != Some(true)
    }
    pub fn allow_tcp_ports(&self) -> &[u16] {
        &self.allow_tcp_ports
    }
}

fn config_path() -> PathBuf {
    Path::new(CONFIG_FILE).to_path_buf()
}

fn global_config_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(CONFIG_FILE))
}

pub fn parse_toml(contents: &str) -> Result<Config, String> {
    toml::from_str(contents).map_err(|e| e.to_string())
}

fn load_from_path(path: &Path) -> Config {
    if !path.exists() {
        return Config::default();
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => match parse_toml(&contents) {
            Ok(cfg) => cfg,
            Err(e) => {
                output::warn(&format!(
                    "Failed to parse {}: {e}",
                    path.display()
                ));
                Config::default()
            }
        },
        Err(e) => {
            output::warn(&format!("Failed to read {}: {e}", path.display()));
            Config::default()
        }
    }
}

/// Load project-level config from `.ai-jail` in the current dir.
pub fn load() -> Config {
    load_from_path(&config_path())
}

/// Load global user config from `$HOME/.ai-jail`.
pub fn load_global() -> Config {
    match global_config_path() {
        Some(p) => load_from_path(&p),
        None => Config::default(),
    }
}

/// Merge global (user-level) and local (project-level) configs.
/// Local overrides global for project settings; global provides
/// user-level defaults (status bar + resize redraw preferences).
pub fn merge_with_global(global: Config, local: Config) -> Config {
    let mut c = global;
    if !local.command.is_empty() {
        c.command = local.command;
    }
    c.rw_maps.extend(local.rw_maps);
    dedup_paths(&mut c.rw_maps);
    c.ro_maps.extend(local.ro_maps);
    dedup_paths(&mut c.ro_maps);
    c.hide_dotdirs.extend(local.hide_dotdirs);
    dedup_strings(&mut c.hide_dotdirs);
    c.mask.extend(local.mask);
    dedup_paths(&mut c.mask);
    if local.no_gpu.is_some() {
        c.no_gpu = local.no_gpu;
    }
    if local.no_docker.is_some() {
        c.no_docker = local.no_docker;
    }
    if local.no_display.is_some() {
        c.no_display = local.no_display;
    }
    if local.no_mise.is_some() {
        c.no_mise = local.no_mise;
    }
    if local.no_worktree.is_some() {
        c.no_worktree = local.no_worktree;
    }
    if local.no_save_config.is_some() {
        c.no_save_config = local.no_save_config;
    }
    if local.ssh.is_some() {
        c.ssh = local.ssh;
    }
    if local.pictures.is_some() {
        c.pictures = local.pictures;
    }
    if local.lockdown.is_some() {
        c.lockdown = local.lockdown;
    }
    if local.no_landlock.is_some() {
        c.no_landlock = local.no_landlock;
    }
    if local.no_seccomp.is_some() {
        c.no_seccomp = local.no_seccomp;
    }
    if local.no_rlimits.is_some() {
        c.no_rlimits = local.no_rlimits;
    }
    c.allow_tcp_ports.extend(local.allow_tcp_ports);
    c.allow_tcp_ports.sort_unstable();
    c.allow_tcp_ports.dedup();
    // Status bar + resize redraw key stay from global — local should
    // not override user-level preferences.
    c
}

/// Save project-level config to `.ai-jail` in the current dir.
/// User-level fields (status bar + resize redraw key) are excluded —
/// they belong in the global `$HOME/.ai-jail`.
pub fn save(config: &Config) {
    let mut local = config.clone();
    // Strip user-level fields from project config
    local.no_status_bar = None;
    local.status_bar_style = None;
    local.resize_redraw_key = None;

    save_to_path(&config_path(), &local);
}

/// Persist user-level preferences (status bar) to `$HOME/.ai-jail`.
/// Loads the existing global config first so other fields are kept.
pub fn save_global(config: &Config) {
    if config.no_status_bar.is_none() && config.status_bar_style.is_none() {
        return;
    }
    let Some(path) = global_config_path() else {
        return;
    };
    let mut global = load_from_path(&path);
    if config.no_status_bar.is_some() {
        global.no_status_bar = config.no_status_bar;
    }
    if config.status_bar_style.is_some() {
        global.status_bar_style = config.status_bar_style.clone();
    }
    save_to_path(&path, &global);
}

fn save_to_path(path: &Path, config: &Config) {
    let header = "# ai-jail sandbox configuration\n\
                  # https://github.com/akitaonrails/ai-jail\n\
                  # Edit freely. Regenerate with: \
                  ai-jail --clean --init\n\n";
    if let Err(e) = ensure_regular_target_or_absent(path) {
        output::warn(&format!("Refusing to write {}: {e}", path.display()));
        return;
    }
    match toml::to_string_pretty(config) {
        Ok(body) => {
            let contents = format!("{header}{body}");
            if let Err(e) = write_atomic(path, &contents) {
                output::warn(&format!(
                    "Failed to write {}: {e}",
                    path.display()
                ));
            }
        }
        Err(e) => {
            output::warn(&format!("Failed to serialize config: {e}"));
        }
    }
}

fn ensure_regular_target_or_absent(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err("target is a symlink".into());
            }
            if !ft.is_file() {
                return Err("target exists but is not a regular file".into());
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ai-jail");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path =
        parent.join(format!(".{stem}.tmp.{}.{}", std::process::id(), nonce));

    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|e| e.to_string())?;

    if let Err(e) = f.write_all(contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    if let Err(e) = f.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    drop(f);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        e.to_string()
    })
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
}

fn dedup_strings(strings: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    strings.retain(|s| seen.insert(s.clone()));
}

pub fn merge(cli: &CliArgs, existing: Config) -> Config {
    let mut config = existing;

    // command: CLI replaces config
    if !cli.command.is_empty() {
        config.command = cli.command.clone();
    }

    // rw_maps/ro_maps: CLI values appended, deduplicated
    config.rw_maps.extend(cli.rw_maps.iter().cloned());
    dedup_paths(&mut config.rw_maps);

    config.ro_maps.extend(cli.ro_maps.iter().cloned());
    dedup_paths(&mut config.ro_maps);

    // hide_dotdirs: CLI values appended, deduplicated
    config.hide_dotdirs.extend(cli.hide_dotdirs.iter().cloned());
    dedup_strings(&mut config.hide_dotdirs);

    config.mask.extend(cli.mask.iter().cloned());
    dedup_paths(&mut config.mask);

    // Boolean flags: CLI overrides config (--no-gpu => no_gpu=Some(true), --gpu => no_gpu=Some(false))
    if let Some(v) = cli.gpu {
        config.no_gpu = Some(!v);
    }
    if let Some(v) = cli.docker {
        config.no_docker = Some(!v);
    }
    if let Some(v) = cli.display {
        config.no_display = Some(!v);
    }
    if let Some(v) = cli.mise {
        config.no_mise = Some(!v);
    }
    if let Some(v) = cli.save_config {
        config.no_save_config = Some(!v);
    }
    if let Some(v) = cli.ssh {
        config.ssh = Some(v);
    }
    if let Some(v) = cli.pictures {
        config.pictures = Some(v);
    }
    if let Some(v) = cli.worktree {
        config.no_worktree = Some(!v);
    }
    if let Some(v) = cli.lockdown {
        config.lockdown = Some(v);
    }
    if let Some(v) = cli.landlock {
        config.no_landlock = Some(!v);
    }
    if let Some(v) = cli.seccomp {
        config.no_seccomp = Some(!v);
    }
    if let Some(v) = cli.rlimits {
        config.no_rlimits = Some(!v);
    }
    if let Some(v) = cli.status_bar {
        config.no_status_bar = Some(!v);
    }
    if let Some(ref style) = cli.status_bar_style {
        config.status_bar_style = Some(style.clone());
    }

    config
        .allow_tcp_ports
        .extend(cli.allow_tcp_ports.iter().copied());
    config.allow_tcp_ports.sort_unstable();
    config.allow_tcp_ports.dedup();

    config
}

pub fn display_status(config: &Config) {
    let path = config_path();
    if !path.exists() {
        output::info("No .ai-jail config file found in current directory.");
        return;
    }

    output::info(&format!("Config: {}", path.display()));

    if config.command.is_empty() {
        output::status_header("  Command", "(default: bash)");
    } else {
        output::status_header("  Command", &config.command.join(" "));
    }

    if !config.rw_maps.is_empty() {
        output::status_header(
            "  RW maps",
            &config
                .rw_maps
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !config.ro_maps.is_empty() {
        output::status_header(
            "  RO maps",
            &config
                .ro_maps
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !config.hide_dotdirs.is_empty() {
        output::status_header(
            "  Hide dotdirs",
            &config.hide_dotdirs.join(", "),
        );
    }
    if !config.mask.is_empty() {
        output::status_header(
            "  Masked files",
            &config
                .mask
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    let bool_opt = |name: &str, val: Option<bool>| match val {
        Some(true) => output::status_header(&format!("  {name}"), "disabled"),
        Some(false) => output::status_header(&format!("  {name}"), "enabled"),
        None => output::status_header(&format!("  {name}"), "auto"),
    };

    bool_opt("GPU", config.no_gpu);
    bool_opt("Docker", config.no_docker);
    bool_opt("Display", config.no_display);
    bool_opt("Git worktree", config.no_worktree);
    bool_opt("Mise", config.no_mise);
    match config.no_save_config {
        Some(true) => output::status_header("  Save config", "disabled"),
        Some(false) => output::status_header("  Save config", "enabled"),
        None => output::status_header("  Save config", "enabled (default)"),
    }
    match config.ssh {
        Some(true) => output::status_header("  SSH keys", "shared (read-only)"),
        _ => output::status_header("  SSH keys", "hidden"),
    }
    match config.pictures {
        Some(true) => output::status_header("  Pictures", "shared (read-only)"),
        _ => output::status_header("  Pictures", "hidden"),
    }
    bool_opt("Landlock", config.no_landlock);
    bool_opt("Seccomp", config.no_seccomp);
    bool_opt("Rlimits", config.no_rlimits);
    bool_opt("Lockdown", config.lockdown.map(|v| !v));
    if !config.allow_tcp_ports.is_empty() {
        let ports: Vec<String> = config
            .allow_tcp_ports
            .iter()
            .map(|p| p.to_string())
            .collect();
        let note = if config.lockdown_enabled() {
            ""
        } else {
            " (only effective in lockdown mode)"
        };
        output::status_header(
            "  Allow TCP ports",
            &format!("{}{note}", ports.join(", ")),
        );
    }
    match config.no_status_bar {
        Some(true) => output::status_header("  Status bar", "disabled"),
        Some(false) => output::status_header("  Status bar", "enabled"),
        None => output::status_header("  Status bar", "enabled (default)"),
    }
    if config.status_bar_enabled() {
        output::status_header("  Style", config.status_bar_style());
    }
    if let Some(key) = config.resize_redraw_key.as_deref() {
        output::status_header("  Resize redraw", key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliArgs;

    // Tests that call set_current_dir must hold this lock to avoid
    // racing each other (cwd is process-global).
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Tests that mutate env vars must hold this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serialize_config(config: &Config) -> Result<String, String> {
        toml::to_string_pretty(config).map_err(|e| e.to_string())
    }

    // ── Parsing tests ──────────────────────────────────────────

    #[test]
    fn parse_minimal_config() {
        let cfg = parse_toml("").unwrap();
        assert!(cfg.command.is_empty());
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
        assert_eq!(cfg.no_save_config, None);
        assert_eq!(cfg.lockdown, None);
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/test"]
ro_maps = ["/opt/data"]
no_gpu = true
no_docker = false
no_display = true
no_mise = false
no_save_config = true
lockdown = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/test")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("/opt/data")]);
        assert_eq!(cfg.no_gpu, Some(true));
        assert_eq!(cfg.no_docker, Some(false));
        assert_eq!(cfg.no_display, Some(true));
        assert_eq!(cfg.no_worktree, None);
        assert_eq!(cfg.no_mise, Some(false));
        assert_eq!(cfg.no_save_config, Some(true));
        assert_eq!(cfg.lockdown, Some(true));
    }

    #[test]
    fn parse_command_only() {
        let toml = r#"command = ["bash"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["bash"]);
        assert!(cfg.rw_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
    }

    #[test]
    fn parse_no_save_config_false() {
        let cfg = parse_toml("no_save_config = false").unwrap();
        assert_eq!(cfg.no_save_config, Some(false));
    }

    #[test]
    fn parse_no_save_config_true() {
        let cfg = parse_toml("no_save_config = true").unwrap();
        assert_eq!(cfg.no_save_config, Some(true));
    }

    #[test]
    fn parse_multi_word_command() {
        let toml = r#"command = ["claude", "--verbose", "--model", "opus"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude", "--verbose", "--model", "opus"]);
    }

    // ── Backward compatibility regression tests ────────────────
    // NEVER DELETE THESE. Add new ones when the format changes.

    #[test]
    fn regression_v0_1_0_config_format() {
        // This is the exact format generated by v0.1.0.
        // It must always parse successfully.
        let toml = r#"
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = []
ro_maps = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
    }

    #[test]
    fn regression_v0_1_0_config_with_maps() {
        let toml = r#"
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = ["/tmp/test"]
ro_maps = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/test")]);
    }

    #[test]
    fn regression_unknown_fields_are_ignored() {
        // A future version might remove a field. Old config files with that
        // field must still parse without error.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
some_future_field = "hello"
another_removed_field = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["claude"]);
    }

    #[test]
    fn regression_missing_optional_fields() {
        // A config from a newer version that only has command.
        // All other fields should default.
        let toml = r#"command = ["bash"]"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.command, vec!["bash"]);
        assert!(cfg.rw_maps.is_empty());
        assert!(cfg.ro_maps.is_empty());
        assert_eq!(cfg.no_gpu, None);
        assert_eq!(cfg.no_docker, None);
        assert_eq!(cfg.no_display, None);
        assert_eq!(cfg.no_worktree, None);
        assert_eq!(cfg.no_mise, None);
        assert_eq!(cfg.no_save_config, None);
        assert_eq!(cfg.lockdown, None);
        assert_eq!(cfg.no_landlock, None);
        assert_eq!(cfg.no_status_bar, None);
        assert_eq!(cfg.resize_redraw_key, None);
        assert_eq!(cfg.no_seccomp, None);
        assert_eq!(cfg.no_rlimits, None);
        assert!(cfg.allow_tcp_ports.is_empty());
    }

    #[test]
    fn regression_v0_3_0_config_without_no_landlock() {
        // v0.3.0 configs don't have no_landlock field.
        // They must still parse and default to landlock enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_landlock, None);
        assert!(cfg.landlock_enabled());
    }

    #[test]
    fn regression_v0_4_5_config_without_no_status_bar() {
        // v0.4.5 configs don't have no_status_bar field.
        // They must still parse and default to status bar enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_status_bar, None);
        assert!(cfg.status_bar_enabled());
    }

    #[test]
    fn regression_v0_5_3_config_without_seccomp_rlimits() {
        // v0.5.3 configs don't have no_seccomp or no_rlimits fields.
        // They must still parse and default to both enabled.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_seccomp, None);
        assert_eq!(cfg.no_rlimits, None);
        assert!(cfg.seccomp_enabled());
        assert!(cfg.rlimits_enabled());
    }

    #[test]
    fn regression_v0_6_0_config_without_allow_tcp_ports() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = true
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.allow_tcp_ports.is_empty());
        assert_eq!(cfg.lockdown, Some(true));
    }

    #[test]
    fn regression_v0_6_0_config_without_hide_dotdirs() {
        // v0.6.0 configs don't have hide_dotdirs field.
        // They must still parse and default to empty.
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
no_gpu = false
no_docker = false
lockdown = false
no_landlock = false
no_status_bar = false
no_seccomp = false
no_rlimits = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.hide_dotdirs.is_empty());
    }

    #[test]
    fn regression_v0_8_0_config_without_no_worktree() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
hide_dotdirs = []
no_gpu = false
no_docker = false
no_display = false
no_mise = false
lockdown = false
no_landlock = false
no_status_bar = false
status_bar_style = "dark"
no_seccomp = false
no_rlimits = false
allow_tcp_ports = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_worktree, None);
        assert!(cfg.worktree_enabled());
    }

    #[test]
    fn regression_empty_config_file() {
        // An empty .ai-jail file must not crash
        let cfg = parse_toml("").unwrap();
        assert!(cfg.command.is_empty());
    }

    #[test]
    fn regression_comment_only_config() {
        let toml = "# just a comment\n# another comment\n";
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.command.is_empty());
    }

    // ── Roundtrip tests ────────────────────────────────────────

    #[test]
    fn roundtrip_serialize_deserialize() {
        let config = Config {
            command: vec!["claude".into()],
            rw_maps: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            ro_maps: vec![PathBuf::from("/opt/data")],
            hide_dotdirs: vec![".my_secrets".into(), ".proton".into()],
            mask: vec![PathBuf::from(".env")],
            no_gpu: Some(true),
            no_docker: None,
            no_display: Some(false),
            no_worktree: Some(false),
            no_mise: None,
            no_save_config: Some(true),
            ssh: Some(true),
            pictures: None,
            lockdown: Some(true),
            no_landlock: Some(false),
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            allow_tcp_ports: vec![32000, 8080],
        };
        let serialized = serialize_config(&config).unwrap();
        let deserialized = parse_toml(&serialized).unwrap();
        assert_eq!(deserialized.command, config.command);
        assert_eq!(deserialized.rw_maps, config.rw_maps);
        assert_eq!(deserialized.ro_maps, config.ro_maps);
        assert_eq!(deserialized.hide_dotdirs, config.hide_dotdirs);
        assert_eq!(deserialized.no_gpu, config.no_gpu);
        assert_eq!(deserialized.no_docker, config.no_docker);
        assert_eq!(deserialized.no_display, config.no_display);
        assert_eq!(deserialized.no_worktree, config.no_worktree);
        assert_eq!(deserialized.no_mise, config.no_mise);
        assert_eq!(deserialized.no_save_config, config.no_save_config);
        assert_eq!(deserialized.lockdown, config.lockdown);
        assert_eq!(deserialized.no_landlock, config.no_landlock);
        assert_eq!(deserialized.resize_redraw_key, config.resize_redraw_key);
        assert_eq!(deserialized.no_seccomp, config.no_seccomp);
        assert_eq!(deserialized.no_rlimits, config.no_rlimits);
        assert_eq!(deserialized.allow_tcp_ports, config.allow_tcp_ports);
    }

    // ── Merge tests ────────────────────────────────────────────

    #[test]
    fn merge_cli_command_replaces_config() {
        let existing = Config {
            command: vec!["bash".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.command, vec!["claude"]);
    }

    #[test]
    fn merge_empty_cli_preserves_config_command() {
        let existing = Config {
            command: vec!["claude".into()],
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(merged.command, vec!["claude"]);
    }

    #[test]
    fn merge_rw_maps_appended_and_deduplicated() {
        let existing = Config {
            rw_maps: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            ..Config::default()
        };
        let cli = CliArgs {
            rw_maps: vec![PathBuf::from("/tmp/b"), PathBuf::from("/tmp/c")],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/tmp/a"),
                PathBuf::from("/tmp/b"),
                PathBuf::from("/tmp/c"),
            ]
        );
    }

    #[test]
    fn merge_ro_maps_appended_and_deduplicated() {
        let existing = Config {
            ro_maps: vec![PathBuf::from("/opt/x")],
            ..Config::default()
        };
        let cli = CliArgs {
            ro_maps: vec![PathBuf::from("/opt/x"), PathBuf::from("/opt/y")],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.ro_maps,
            vec![PathBuf::from("/opt/x"), PathBuf::from("/opt/y")]
        );
    }

    #[test]
    fn merge_hide_dotdirs_appended_and_deduplicated() {
        let existing = Config {
            hide_dotdirs: vec![".my_secrets".into(), ".proton".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            hide_dotdirs: vec![".proton".into(), ".password-store".into()],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.hide_dotdirs,
            vec![".my_secrets", ".proton", ".password-store"]
        );
    }

    #[test]
    fn parse_config_with_no_worktree() {
        let toml = r#"
command = ["claude"]
no_worktree = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.no_worktree, Some(true));
        assert!(!cfg.worktree_enabled());
    }

    #[test]
    fn parse_hide_dotdirs() {
        let toml = r#"
command = ["claude"]
hide_dotdirs = [".my_secrets", ".proton", ".password-store"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.hide_dotdirs,
            vec![".my_secrets", ".proton", ".password-store"]
        );
    }

    #[test]
    fn merge_gpu_flag_overrides() {
        let existing = Config {
            no_gpu: Some(true),
            ..Config::default()
        };

        // --gpu sets no_gpu to false
        let cli = CliArgs {
            gpu: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_gpu, Some(false));

        // --no-gpu sets no_gpu to true
        let cli = CliArgs {
            gpu: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
    }

    #[test]
    fn merge_no_cli_flags_preserves_config_booleans() {
        let existing = Config {
            no_gpu: Some(true),
            no_docker: Some(false),
            no_display: None,
            no_worktree: Some(true),
            no_mise: Some(true),
            no_save_config: Some(true),
            lockdown: Some(true),
            no_landlock: Some(true),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.no_docker, Some(false));
        assert_eq!(merged.no_display, None);
        assert_eq!(merged.no_worktree, Some(true));
        assert_eq!(merged.no_mise, Some(true));
        assert_eq!(merged.no_save_config, Some(true));
        assert_eq!(merged.lockdown, Some(true));
        assert_eq!(merged.no_landlock, Some(true));
    }

    #[test]
    fn merge_all_boolean_flags() {
        let existing = Config::default();
        let cli = CliArgs {
            gpu: Some(false),         // --no-gpu
            docker: Some(false),      // --no-docker
            display: Some(true),      // --display
            worktree: Some(false),    // --no-worktree
            mise: Some(true),         // --mise
            save_config: Some(false), // --no-save-config
            lockdown: Some(true),     // --lockdown
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.no_docker, Some(true));
        assert_eq!(merged.no_display, Some(false));
        assert_eq!(merged.no_worktree, Some(true));
        assert_eq!(merged.no_mise, Some(false));
        assert_eq!(merged.no_save_config, Some(true));
        assert_eq!(merged.lockdown, Some(true));
    }

    #[test]
    fn merge_landlock_flag_overrides() {
        let existing = Config {
            no_landlock: None,
            ..Config::default()
        };

        // --landlock sets no_landlock to false
        let cli = CliArgs {
            landlock: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_landlock, Some(false));

        // --no-landlock sets no_landlock to true
        let cli = CliArgs {
            landlock: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_landlock, Some(true));
    }

    #[test]
    fn merge_worktree_flag_overrides() {
        let existing = Config {
            no_worktree: None,
            ..Config::default()
        };

        let cli = CliArgs {
            worktree: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_worktree, Some(false));

        let cli = CliArgs {
            worktree: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_worktree, Some(true));
    }

    #[test]
    fn merge_allow_tcp_ports_from_cli() {
        let existing = Config {
            allow_tcp_ports: vec![32000],
            ..Config::default()
        };
        let cli = CliArgs {
            allow_tcp_ports: vec![8080, 32000],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.allow_tcp_ports, vec![8080, 32000]);
    }

    #[test]
    fn merge_allow_tcp_ports_with_global() {
        let global = Config {
            allow_tcp_ports: vec![443],
            ..Config::default()
        };
        let local = Config {
            allow_tcp_ports: vec![32000, 443],
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.allow_tcp_ports, vec![443, 32000]);
    }

    #[test]
    fn allow_tcp_ports_accessor() {
        let cfg = Config {
            allow_tcp_ports: vec![32000, 8080],
            ..Config::default()
        };
        assert_eq!(cfg.allow_tcp_ports(), &[32000, 8080]);
        assert_eq!(Config::default().allow_tcp_ports(), &[] as &[u16]);
    }

    #[test]
    fn parse_config_with_allow_tcp_ports() {
        let toml = r#"
command = ["opencode"]
lockdown = true
allow_tcp_ports = [32000, 8080]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.allow_tcp_ports, vec![32000, 8080]);
    }

    #[test]
    fn merge_lockdown_flag_overrides() {
        let existing = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            lockdown: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.lockdown, Some(false));
    }

    #[test]
    fn merge_with_global_local_no_save_config_wins_false() {
        let global = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let local = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_save_config, Some(false));
    }

    #[test]
    fn merge_with_global_local_no_save_config_wins_true() {
        let global = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let local = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_save_config, Some(true));
    }

    #[test]
    fn merge_cli_save_config_overrides_config() {
        let existing = Config {
            no_save_config: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            save_config: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_save_config, Some(false));
    }

    #[test]
    fn merge_cli_no_save_config_overrides_config() {
        let existing = Config {
            no_save_config: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            save_config: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_save_config, Some(true));
    }

    // ── Dedup tests ────────────────────────────────────────────

    #[test]
    fn dedup_paths_removes_duplicates_preserves_order() {
        let mut paths = vec![
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            PathBuf::from("/a"),
            PathBuf::from("/c"),
            PathBuf::from("/b"),
        ];
        dedup_paths(&mut paths);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ]
        );
    }

    #[test]
    fn dedup_paths_empty() {
        let mut paths: Vec<PathBuf> = vec![];
        dedup_paths(&mut paths);
        assert!(paths.is_empty());
    }

    #[test]
    fn dedup_strings_removes_duplicates_preserves_order() {
        let mut strings = vec![
            ".my_secrets".into(),
            ".proton".into(),
            ".my_secrets".into(),
            ".aws".into(),
            ".proton".into(),
        ];
        dedup_strings(&mut strings);
        assert_eq!(strings, vec![".my_secrets", ".proton", ".aws"]);
    }

    #[test]
    fn dedup_strings_empty() {
        let mut strings: Vec<String> = vec![];
        dedup_strings(&mut strings);
        assert!(strings.is_empty());
    }

    // ── Accessor method tests ─────────────────────────────────

    #[test]
    fn gpu_enabled_accessor() {
        assert!(
            Config {
                no_gpu: None,
                ..Config::default()
            }
            .gpu_enabled()
        );
        assert!(
            !Config {
                no_gpu: Some(true),
                ..Config::default()
            }
            .gpu_enabled()
        );
        assert!(
            Config {
                no_gpu: Some(false),
                ..Config::default()
            }
            .gpu_enabled()
        );
    }

    #[test]
    fn docker_enabled_accessor() {
        assert!(
            Config {
                no_docker: None,
                ..Config::default()
            }
            .docker_enabled()
        );
        assert!(
            !Config {
                no_docker: Some(true),
                ..Config::default()
            }
            .docker_enabled()
        );
        assert!(
            Config {
                no_docker: Some(false),
                ..Config::default()
            }
            .docker_enabled()
        );
    }

    #[test]
    fn display_enabled_accessor() {
        assert!(
            Config {
                no_display: None,
                ..Config::default()
            }
            .display_enabled()
        );
        assert!(
            !Config {
                no_display: Some(true),
                ..Config::default()
            }
            .display_enabled()
        );
        assert!(
            Config {
                no_display: Some(false),
                ..Config::default()
            }
            .display_enabled()
        );
    }

    #[test]
    fn worktree_enabled_accessor() {
        assert!(
            Config {
                no_worktree: None,
                ..Config::default()
            }
            .worktree_enabled()
        );
        assert!(
            !Config {
                no_worktree: Some(true),
                ..Config::default()
            }
            .worktree_enabled()
        );
        assert!(
            Config {
                no_worktree: Some(false),
                ..Config::default()
            }
            .worktree_enabled()
        );
    }

    #[test]
    fn mise_enabled_accessor() {
        assert!(
            Config {
                no_mise: None,
                ..Config::default()
            }
            .mise_enabled()
        );
        assert!(
            !Config {
                no_mise: Some(true),
                ..Config::default()
            }
            .mise_enabled()
        );
        assert!(
            Config {
                no_mise: Some(false),
                ..Config::default()
            }
            .mise_enabled()
        );
    }

    #[test]
    fn save_config_enabled_accessor() {
        assert!(
            Config {
                no_save_config: None,
                ..Config::default()
            }
            .save_config_enabled()
        );
        assert!(
            !Config {
                no_save_config: Some(true),
                ..Config::default()
            }
            .save_config_enabled()
        );
        assert!(
            Config {
                no_save_config: Some(false),
                ..Config::default()
            }
            .save_config_enabled()
        );
    }

    #[test]
    fn landlock_enabled_accessor() {
        assert!(
            Config {
                no_landlock: None,
                ..Config::default()
            }
            .landlock_enabled()
        );
        assert!(
            !Config {
                no_landlock: Some(true),
                ..Config::default()
            }
            .landlock_enabled()
        );
        assert!(
            Config {
                no_landlock: Some(false),
                ..Config::default()
            }
            .landlock_enabled()
        );
    }

    #[test]
    fn lockdown_enabled_accessor() {
        assert!(
            !Config {
                lockdown: None,
                ..Config::default()
            }
            .lockdown_enabled()
        );
        assert!(
            Config {
                lockdown: Some(true),
                ..Config::default()
            }
            .lockdown_enabled()
        );
        assert!(
            !Config {
                lockdown: Some(false),
                ..Config::default()
            }
            .lockdown_enabled()
        );
    }

    #[test]
    fn status_bar_enabled_accessor() {
        // Default ON: None means enabled
        assert!(
            Config {
                no_status_bar: None,
                ..Config::default()
            }
            .status_bar_enabled()
        );
        // Explicitly disabled
        assert!(
            !Config {
                no_status_bar: Some(true),
                ..Config::default()
            }
            .status_bar_enabled()
        );
        // Explicitly enabled
        assert!(
            Config {
                no_status_bar: Some(false),
                ..Config::default()
            }
            .status_bar_enabled()
        );
    }

    #[test]
    fn merge_status_bar_flag_overrides() {
        let existing = Config {
            no_status_bar: None,
            ..Config::default()
        };

        // --status-bar only changes style
        let cli = CliArgs {
            status_bar_style: Some("light".into()),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing.clone());
        assert_eq!(merged.no_status_bar, None);
        assert!(merged.status_bar_enabled());
        assert_eq!(merged.status_bar_style.as_deref(), Some("light"));

        // --no-status-bar sets no_status_bar to true (disabled)
        let cli = CliArgs {
            status_bar: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_status_bar, Some(true));
        assert!(!merged.status_bar_enabled());
    }

    // ── File I/O tests (using temp dirs) ───────────────────────

    #[test]
    fn save_global_status_bar_theme_persists() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-home-global-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        unsafe { std::env::set_var("HOME", &home) };

        let cfg = Config {
            no_status_bar: None,
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global(&cfg);

        let global = load_global();
        assert_eq!(global.no_status_bar, None);
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        unsafe { std::env::remove_var("HOME") };
        let _ = std::fs::remove_file(home.join(".ai-jail"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn save_global_theme_does_not_reenable_disabled_status_bar() {
        let _env = ENV_LOCK.lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-home-global-preserve-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&home);
        unsafe { std::env::set_var("HOME", &home) };

        let path = home.join(".ai-jail");
        let existing = Config {
            no_status_bar: Some(true),
            status_bar_style: Some("light".into()),
            ..Config::default()
        };
        save_to_path(&path, &existing);

        let cfg = Config {
            no_status_bar: None,
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global(&cfg);

        let global = load_global();
        assert_eq!(global.no_status_bar, Some(true));
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        unsafe { std::env::remove_var("HOME") };
        let _ = std::fs::remove_file(home.join(".ai-jail"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn merge_with_global_keeps_status_bar_preferences_from_global() {
        let global = Config {
            no_status_bar: Some(false),
            status_bar_style: Some("light".into()),
            resize_redraw_key: Some("ctrl-l".into()),
            ..Config::default()
        };
        let local = Config {
            no_status_bar: Some(true),
            status_bar_style: Some("dark".into()),
            resize_redraw_key: Some("disabled".into()),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.no_status_bar, Some(false));
        assert_eq!(merged.status_bar_style.as_deref(), Some("light"));
        assert_eq!(merged.resize_redraw_key.as_deref(), Some("ctrl-l"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let _cwd = CWD_LOCK.lock().unwrap();
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original_dir = std::env::current_dir().unwrap();

        // Change to temp dir so save/load use the right path
        std::env::set_current_dir(&dir).unwrap();

        let config = Config {
            command: vec!["codex".into()],
            rw_maps: vec![PathBuf::from("/tmp/shared")],
            ro_maps: vec![],
            hide_dotdirs: vec![],
            mask: vec![],
            no_gpu: Some(true),
            no_docker: None,
            no_display: None,
            no_worktree: None,
            no_mise: None,
            no_save_config: Some(true),
            ssh: None,
            pictures: Some(true),
            lockdown: Some(false),
            no_landlock: None,
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            allow_tcp_ports: vec![32000],
        };
        save(&config);

        let loaded = load();
        assert_eq!(loaded.command, vec!["codex"]);
        assert_eq!(loaded.rw_maps, vec![PathBuf::from("/tmp/shared")]);
        assert_eq!(loaded.no_gpu, Some(true));
        assert_eq!(loaded.lockdown, Some(false));
        assert_eq!(loaded.allow_tcp_ports, vec![32000]);
        assert_eq!(loaded.resize_redraw_key, None);

        // Cleanup
        std::env::set_current_dir(&original_dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_rejects_symlink_target() {
        let _cwd = CWD_LOCK.lock().unwrap();
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-test-{}-symlink", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original_dir = std::env::current_dir().unwrap();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "KEEP").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".ai-jail")).unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let config = Config {
            command: vec!["bash".into()],
            ..Default::default()
        };
        save(&config);

        let victim_after = std::fs::read_to_string(&victim).unwrap();
        assert_eq!(victim_after, "KEEP");

        std::env::set_current_dir(&original_dir).unwrap();
        let _ = std::fs::remove_file(dir.join(".ai-jail"));
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
