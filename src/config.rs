use crate::cli::CliArgs;
use crate::output;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = ".ai-jail";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Hard,
    Soft,
}

impl BrowserProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserProfile::Hard => "hard",
            BrowserProfile::Soft => "soft",
        }
    }
}

pub fn parse_browser_profile_spec(value: &str) -> Option<BrowserProfile> {
    match value {
        "hard" | "isolated" | "ephemeral" => Some(BrowserProfile::Hard),
        "soft" | "persistent" | "survivable" => Some(BrowserProfile::Soft),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSpec {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl MapSpec {
    pub fn parse(value: &Path) -> Result<Self, String> {
        let bytes = value.as_os_str().as_bytes();
        let Some(separator) = bytes.iter().position(|byte| *byte == b':')
        else {
            if bytes.is_empty() {
                return Err("map has empty source and destination".into());
            }
            return Ok(Self {
                source: value.to_path_buf(),
                destination: value.to_path_buf(),
            });
        };

        let source = &bytes[..separator];
        let destination = &bytes[separator + 1..];
        if source.is_empty() {
            return Err("map has empty source".into());
        }
        if destination.is_empty() {
            return Err("map has empty destination".into());
        }

        Ok(Self {
            source: PathBuf::from(OsString::from_vec(source.to_vec())),
            destination: PathBuf::from(OsString::from_vec(
                destination.to_vec(),
            )),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.source.as_os_str().is_empty() {
            return Err("map has empty source".into());
        }
        if self.destination.as_os_str().is_empty() {
            return Err("map has empty destination".into());
        }
        if self.source.to_str().is_none() {
            return Err("map source must be valid UTF-8".into());
        }
        if self.destination.to_str().is_none() {
            return Err("map destination must be valid UTF-8".into());
        }
        if self.source == Path::new("/") {
            return Err("map cannot use root source".into());
        }
        if self.destination == Path::new("/") {
            return Err("map cannot use root destination".into());
        }
        Ok(())
    }

    pub fn is_alternate(&self) -> bool {
        self.source != self.destination
    }

    /// Parse and validate an encoded map entry, warning and returning
    /// `None` on malformed input (warn-and-skip convention). `label`
    /// names the map kind in the warning, e.g. "read-only".
    pub fn parse_validated(encoded: &Path, label: &str) -> Option<Self> {
        let parsed = Self::parse(encoded).and_then(|spec| {
            spec.validate()?;
            Ok(spec)
        });
        match parsed {
            Ok(spec) => Some(spec),
            Err(reason) => {
                output::warn(&format!(
                    "Invalid {label} map {}: {reason}; skipping.",
                    encoded.display()
                ));
                None
            }
        }
    }

    pub fn encode(&self) -> PathBuf {
        if !self.is_alternate() {
            return self.source.clone();
        }

        let mut encoded = self.source.as_os_str().as_bytes().to_vec();
        encoded.push(b':');
        encoded.extend_from_slice(self.destination.as_os_str().as_bytes());
        PathBuf::from(OsString::from_vec(encoded))
    }
}

fn transform_map_specs(
    paths: &mut [PathBuf],
    mut transform: impl FnMut(PathBuf) -> PathBuf,
) {
    for path in paths {
        let Ok(spec) = MapSpec::parse(path) else {
            continue;
        };
        *path = MapSpec {
            source: transform(spec.source),
            destination: transform(spec.destination),
        }
        .encode();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rw_maps: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ro_maps: Vec<PathBuf>,
    /// Copy-on-write overlay mounts: PATH is visible read-write inside
    /// the sandbox, but writes land on a side layer under
    /// `<project>/.ai-jail-overlays/` while the original stays
    /// untouched (Linux/bwrap only; read-only fallback on macOS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlay_maps: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hide_dotdirs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask_exceptions: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_path_exceptions: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_gpu: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_docker: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_display: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_worktree: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_mise: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_save_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_hide_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pictures: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_home: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockdown: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_landlock: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_status_bar: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_bar_style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resize_redraw_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_seccomp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_rlimits: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemd_user: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_tcp_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GlobalConfig {
    #[serde(flatten)]
    base: Config,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    commands: BTreeMap<String, Config>,
}

impl Config {
    pub fn gpu_enabled(&self) -> bool {
        self.no_gpu != Some(true)
    }
    pub fn docker_enabled(&self) -> bool {
        self.no_docker != Some(true)
    }
    pub fn tailscale_enabled(&self) -> bool {
        self.tailscale == Some(true)
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
    /// Whether to automatically mask the project's `.ai-jail` file
    /// from the sandbox (default on). Opt-out via `--no-hide-config`
    /// or `no_hide_config = true` in the config file.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn hide_config_enabled(&self) -> bool {
        self.no_hide_config != Some(true)
    }
    pub fn ssh_enabled(&self) -> bool {
        self.ssh == Some(true)
    }
    pub fn pictures_enabled(&self) -> bool {
        self.pictures == Some(true)
    }
    pub fn browser_profile(&self) -> Option<BrowserProfile> {
        self.browser_profile
            .as_deref()
            .and_then(parse_browser_profile_spec)
    }
    pub fn browser_profile_disabled(&self) -> bool {
        matches!(
            self.browser_profile.as_deref(),
            Some("off" | "none" | "disabled")
        )
    }
    pub fn private_home_enabled(&self) -> bool {
        self.private_home == Some(true)
    }
    #[cfg_attr(target_os = "macos", allow(dead_code))]
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
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn seccomp_enabled(&self) -> bool {
        self.no_seccomp != Some(true)
    }
    pub fn rlimits_enabled(&self) -> bool {
        self.no_rlimits != Some(true)
    }
    pub fn systemd_user_enabled(&self) -> bool {
        self.systemd_user == Some(true)
    }
    pub fn allow_tcp_ports(&self) -> &[u16] {
        &self.allow_tcp_ports
    }
}

fn config_path() -> PathBuf {
    Path::new(CONFIG_FILE).to_path_buf()
}

fn global_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(CONFIG_FILE))
}

pub fn parse_toml(contents: &str) -> Result<Config, String> {
    toml::from_str(contents).map_err(|e| e.to_string())
}

fn parse_global_toml(contents: &str) -> Result<GlobalConfig, String> {
    toml::from_str(contents).map_err(|e| e.to_string())
}

fn load_toml_from_path<T: Default>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse(&contents)
            .map_err(|e| format!("Failed to parse {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("Failed to read {}: {e}", path.display())),
    }
}

fn load_from_path(path: &Path) -> Result<Config, String> {
    load_toml_from_path(path, parse_toml)
}

fn load_global_from_path(path: &Path) -> Result<GlobalConfig, String> {
    load_toml_from_path(path, parse_global_toml)
}

/// Load project-level config from `.ai-jail` in the current dir.
pub fn load() -> Result<Config, String> {
    load_from_path(&config_path())
}

/// Load global user config from `$HOME/.ai-jail`, applying a matching
/// `[commands.<name>]` table when present. The selection key is based on the
/// effective command before global command tables are merged: CLI command,
/// then project command, then global base command.
pub fn load_global_for_command(
    cli: &CliArgs,
    project: &Config,
) -> Result<Config, String> {
    match global_config_path() {
        Some(p) => load_global_for_command_from_path(&p, cli, project),
        None => Ok(Config::default()),
    }
}

fn load_global_for_command_from_path(
    path: &Path,
    cli: &CliArgs,
    project: &Config,
) -> Result<Config, String> {
    let global = load_global_from_path(path)?;
    Ok(global_config_for_command(global, cli, project))
}

fn global_config_for_command(
    global: GlobalConfig,
    cli: &CliArgs,
    project: &Config,
) -> Config {
    let command_name = cli
        .command
        .first()
        .or_else(|| project.command.first())
        .or_else(|| global.base.command.first())
        .cloned();

    let mut base = global.base;
    if let Some(name) = command_name
        && let Some(command_config) = global.commands.get(&name)
    {
        base = merge_with_global(base, command_config.clone());
    }
    base
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
    c.overlay_maps.extend(local.overlay_maps);
    dedup_paths(&mut c.overlay_maps);
    c.hide_dotdirs.extend(local.hide_dotdirs);
    dedup_strings(&mut c.hide_dotdirs);
    c.mask.extend(local.mask);
    dedup_paths(&mut c.mask);
    c.deny_paths.extend(local.deny_paths);
    dedup_paths(&mut c.deny_paths);
    c.mask_exceptions.extend(local.mask_exceptions);
    dedup_paths(&mut c.mask_exceptions);
    c.deny_path_exceptions.extend(local.deny_path_exceptions);
    dedup_paths(&mut c.deny_path_exceptions);
    // Each Option-typed field follows the same pattern: local
    // overrides global iff local explicitly set it. The macro is
    // local to the function so it stays scoped to this single use.
    macro_rules! take {
        ($field:ident) => {
            if local.$field.is_some() {
                c.$field = local.$field;
            }
        };
    }
    take!(no_gpu);
    take!(no_docker);
    take!(tailscale);
    take!(no_display);
    take!(no_mise);
    take!(no_worktree);
    take!(no_save_config);
    take!(no_hide_config);
    take!(ssh);
    take!(pictures);
    take!(browser_profile);
    take!(private_home);
    take!(lockdown);
    take!(no_landlock);
    take!(no_seccomp);
    take!(no_rlimits);
    take!(systemd_user);
    c.allow_tcp_ports.extend(local.allow_tcp_ports);
    c.allow_tcp_ports.sort_unstable();
    c.allow_tcp_ports.dedup();
    take!(claude_dir);
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
pub fn save_global(config: &Config) -> Result<(), String> {
    if config.no_status_bar.is_none() && config.status_bar_style.is_none() {
        return Ok(());
    }
    let Some(path) = global_config_path() else {
        return Ok(());
    };
    save_global_to_path(&path, config)
}

fn save_global_to_path(path: &Path, config: &Config) -> Result<(), String> {
    let mut global = load_global_from_path(path)?;
    if config.no_status_bar.is_some() {
        global.base.no_status_bar = config.no_status_bar;
    }
    if config.status_bar_style.is_some() {
        global.base.status_bar_style = config.status_bar_style.clone();
    }
    save_global_doc_to_path(path, &global);
    Ok(())
}

/// Comment block written at the top of every saved `.ai-jail` file
/// (project and global).
const CONFIG_FILE_HEADER: &str = "# ai-jail sandbox configuration\n\
                  # https://github.com/akitaonrails/ai-jail\n\
                  # Edit freely. Regenerate with: \
                  ai-jail --clean --init\n\n";

fn save_global_doc_to_path(path: &Path, global: &GlobalConfig) {
    let header = CONFIG_FILE_HEADER;
    if let Err(e) = ensure_regular_target_or_absent(path) {
        output::warn(&format!("Refusing to write {}: {e}", path.display()));
        return;
    }
    let mut on_disk = global.clone();
    collapse_tilde_config(&mut on_disk.base);
    for command_config in on_disk.commands.values_mut() {
        collapse_tilde_config(command_config);
    }
    match toml::to_string_pretty(&on_disk) {
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

fn save_to_path(path: &Path, config: &Config) {
    let header = CONFIG_FILE_HEADER;
    if let Err(e) = ensure_regular_target_or_absent(path) {
        output::warn(&format!("Refusing to write {}: {e}", path.display()));
        return;
    }
    // Re-collapse `$HOME/...` prefixes back to `~/...` so the on-disk
    // file stays portable across machines and stable across runs.
    // Issue #52: configs typed with `~/.claude` were rewritten to
    // absolute paths and lost their shareability.
    let mut on_disk = config.clone();
    collapse_tilde_config(&mut on_disk);
    match toml::to_string_pretty(&on_disk) {
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

fn collapse_tilde_config(config: &mut Config) {
    transform_map_specs(&mut config.rw_maps, |path| collapse_tilde(&path));
    transform_map_specs(&mut config.ro_maps, |path| collapse_tilde(&path));
    collapse_tilde_vec(&mut config.overlay_maps);
    collapse_tilde_vec(&mut config.mask);
    collapse_tilde_vec(&mut config.deny_paths);
    collapse_tilde_vec(&mut config.mask_exceptions);
    collapse_tilde_vec(&mut config.deny_path_exceptions);
    if let Some(p) = config.claude_dir.take() {
        config.claude_dir = Some(collapse_tilde(&p));
    }
}

fn ensure_regular_target_or_absent(path: &Path) -> Result<(), String> {
    crate::fsutil::ensure_regular_file_or_absent(path)
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    crate::fsutil::write_atomic(path, contents, false, "ai-jail")
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
}

fn dedup_strings(strings: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    strings.retain(|s| seen.insert(s.clone()));
}

/// Expand a leading `~` or `~/` in a path using `$HOME`.
/// Returns the path unchanged if `$HOME` is unset or the path
/// does not start with `~`. Only leading-tilde forms are
/// rewritten; `~user` (other-user home) is left alone.
pub fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = match path.to_str() {
        Some(s) => s,
        None => return path,
    };
    if s == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
        return path;
    }
    if let Some(rest) = s.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path
}

fn expand_tilde_vec(paths: &mut [PathBuf]) {
    for p in paths.iter_mut() {
        *p = expand_tilde(std::mem::take(p));
    }
}

/// Lexically normalize a path: collapse `.` and `..` components without
/// touching the filesystem. Symbolic links are NOT resolved — we use
/// this for user-supplied paths that may not exist at config time and
/// don't want surprising symlink-following semantics.
///
/// `..` that would escape the root is dropped (so `/..` stays `/`),
/// matching the behaviour of `cd /..` in a shell.
pub fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                // Pop the last Normal component; otherwise we're at a
                // root or about to escape it, so drop the `..`.
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else if !matches!(
                    out.last(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    // Relative path with leading `..` and nothing to pop:
                    // preserve the `..` literally.
                    out.push(comp);
                }
            }
            other => out.push(other),
        }
    }
    let mut result = PathBuf::new();
    for c in out {
        result.push(c.as_os_str());
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Resolve a user-supplied path to an absolute, lexically-normalized
/// form. Relative paths are joined with `base` (typically the user's
/// invocation cwd / project dir) before normalization. Absolute paths
/// are normalized in place.
pub fn to_absolute(path: PathBuf, base: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    normalize_path(&joined)
}

fn absolutize_vec(paths: &mut [PathBuf], base: &Path) {
    for p in paths.iter_mut() {
        *p = to_absolute(std::mem::take(p), base);
    }
}

/// Resolve relative paths in user-supplied fields against `cwd` so
/// downstream sandbox code (bwrap, landlock, seatbelt) sees absolute
/// paths consistently. Called once after [`merge`] in `main`.
///
/// Without this, `ai-jail --map ../sister-project` would hand bwrap
/// a relative path which it silently rejects, leaving the mount
/// invisible inside the sandbox (issue #54).
pub fn absolutize_user_paths(config: &mut Config, cwd: &Path) {
    transform_map_specs(&mut config.rw_maps, |path| to_absolute(path, cwd));
    transform_map_specs(&mut config.ro_maps, |path| to_absolute(path, cwd));
    absolutize_vec(&mut config.overlay_maps, cwd);
}

/// Inverse of `expand_tilde`: if `path` starts with `$HOME`, rewrite
/// that prefix to `~`. Used at save time so `.ai-jail` keeps its
/// `~/...` notation across runs and stays portable across machines.
/// Returns the path unchanged if `$HOME` is unset or the path is not
/// a `$HOME` descendant.
pub fn collapse_tilde(path: &Path) -> PathBuf {
    let Ok(home) = std::env::var("HOME") else {
        return path.to_path_buf();
    };
    if home.is_empty() {
        return path.to_path_buf();
    }
    let home_path = PathBuf::from(&home);
    if path == home_path {
        return PathBuf::from("~");
    }
    if let Ok(rest) = path.strip_prefix(&home_path) {
        // Preserve `~/` form even when the rest is empty (unreachable
        // in practice — covered by the path==home branch above — but
        // cheap to handle for safety).
        if rest.as_os_str().is_empty() {
            return PathBuf::from("~");
        }
        return PathBuf::from("~").join(rest);
    }
    path.to_path_buf()
}

fn collapse_tilde_vec(paths: &mut [PathBuf]) {
    for p in paths.iter_mut() {
        *p = collapse_tilde(p);
    }
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

    config.overlay_maps.extend(cli.overlay_maps.iter().cloned());
    dedup_paths(&mut config.overlay_maps);

    // hide_dotdirs: CLI values appended, deduplicated
    config.hide_dotdirs.extend(cli.hide_dotdirs.iter().cloned());
    dedup_strings(&mut config.hide_dotdirs);

    config.mask.extend(cli.mask.iter().cloned());
    dedup_paths(&mut config.mask);

    config.deny_paths.extend(cli.deny_paths.iter().cloned());
    dedup_paths(&mut config.deny_paths);
    config
        .mask_exceptions
        .extend(cli.mask_exceptions.iter().cloned());
    dedup_paths(&mut config.mask_exceptions);
    config
        .deny_path_exceptions
        .extend(cli.deny_path_exceptions.iter().cloned());
    dedup_paths(&mut config.deny_path_exceptions);

    // Boolean flags: CLI overrides config (--no-gpu => no_gpu=Some(true), --gpu => no_gpu=Some(false))
    // Three macros for the three patterns the CLI uses:
    //  invert!: CLI positive flag flips a `no_*` config field
    //           (e.g. `--no-gpu` sets `cli.gpu=Some(false)` → `no_gpu=Some(true)`)
    //  direct!: CLI flag maps straight onto a same-named config field
    //  clone_into!: same as direct! but for non-Copy types (String, PathBuf)
    macro_rules! invert {
        ($cli_field:ident, $config_field:ident) => {
            if let Some(v) = cli.$cli_field {
                config.$config_field = Some(!v);
            }
        };
    }
    macro_rules! direct {
        ($field:ident) => {
            if let Some(v) = cli.$field {
                config.$field = Some(v);
            }
        };
    }
    macro_rules! clone_into {
        ($field:ident) => {
            if let Some(ref v) = cli.$field {
                config.$field = Some(v.clone());
            }
        };
    }

    invert!(gpu, no_gpu);
    invert!(docker, no_docker);
    direct!(tailscale);
    invert!(display, no_display);
    invert!(mise, no_mise);
    invert!(save_config, no_save_config);
    invert!(hide_config, no_hide_config);
    direct!(ssh);
    direct!(pictures);
    clone_into!(browser_profile);
    direct!(private_home);
    invert!(worktree, no_worktree);
    direct!(lockdown);
    direct!(systemd_user);
    invert!(landlock, no_landlock);
    invert!(seccomp, no_seccomp);
    invert!(rlimits, no_rlimits);
    invert!(status_bar, no_status_bar);
    clone_into!(status_bar_style);

    config
        .allow_tcp_ports
        .extend(cli.allow_tcp_ports.iter().copied());
    config.allow_tcp_ports.sort_unstable();
    config.allow_tcp_ports.dedup();

    if let Some(p) = cli.claude_dir.clone() {
        config.claude_dir = Some(p);
    }

    // Expand ~ / ~/ in every user-provided path field in one pass.
    // Config files are TOML (no shell expansion); CLI args are
    // shell-expanded already but harmless to re-run. Only leading
    // tilde is recognized; `~user` is left alone.
    transform_map_specs(&mut config.rw_maps, expand_tilde);
    transform_map_specs(&mut config.ro_maps, expand_tilde);
    expand_tilde_vec(&mut config.overlay_maps);
    expand_tilde_vec(&mut config.mask);
    expand_tilde_vec(&mut config.deny_paths);
    expand_tilde_vec(&mut config.mask_exceptions);
    expand_tilde_vec(&mut config.deny_path_exceptions);
    if let Some(p) = config.claude_dir.take() {
        config.claude_dir = Some(expand_tilde(p));
    }

    config
}

/// Build the project-local config to write during automatic saves.
///
/// Runtime config may include values inherited from `$HOME/.ai-jail` via
/// [`merge_with_global`]. Auto-save must not copy those inherited values into
/// the project `.ai-jail`; it should persist only the existing project config
/// plus CLI-persistable changes from this invocation.
pub fn project_config_for_auto_save(
    cli: &CliArgs,
    project: Config,
    invocation_cwd: &Path,
) -> Config {
    let stored_project_command = project.command.clone();
    let mut to_save = merge(cli, project);

    // A CLI-passed command is transient when the project already has a stored
    // command. Preserve that project default instead of flipping it between
    // agents on ordinary runs; `--init` remains the explicit way to change it.
    if !stored_project_command.is_empty() && !cli.command.is_empty() {
        to_save.command = stored_project_command;
    }

    absolutize_user_paths(&mut to_save, invocation_cwd);
    to_save
}

pub fn display_status(config: &Config) {
    let path = config_path();
    if !path.exists() {
        output::info("No .ai-jail config file found in current directory.");
        return;
    }
    output::info(&format!("Config: {}", path.display()));

    print_command(config);
    print_path_list("  RW maps", &config.rw_maps);
    print_path_list("  RO maps", &config.ro_maps);
    print_path_list("  Overlay maps", &config.overlay_maps);
    print_string_list("  Hide dotdirs", &config.hide_dotdirs);
    print_path_list("  Masked files", &config.mask);
    print_path_list("  Denied paths", &config.deny_paths);
    print_path_list("  Mask exceptions", &config.mask_exceptions);
    print_path_list("  Deny exceptions", &config.deny_path_exceptions);

    print_auto_tristate("  GPU", config.no_gpu);
    print_auto_tristate("  Docker", config.no_docker);
    print_shared_or_hidden("  Tailscale", config.tailscale);
    print_auto_tristate("  Display", config.no_display);
    print_auto_tristate("  Git worktree", config.no_worktree);
    print_auto_tristate("  Mise", config.no_mise);
    print_default_on_tristate("  Save config", config.no_save_config);
    print_default_on_tristate("  Hide .ai-jail", config.no_hide_config);
    print_shared_or_hidden("  SSH keys", config.ssh);
    print_shared_or_hidden("  Pictures", config.pictures);
    print_browser_profile(config.browser_profile.as_deref());
    print_private_home(config.private_home);
    print_auto_tristate("  Landlock", config.no_landlock);
    print_auto_tristate("  Seccomp", config.no_seccomp);
    print_auto_tristate("  Rlimits", config.no_rlimits);
    print_shared_or_hidden("  systemd --user", config.systemd_user);
    print_auto_tristate("  Lockdown", config.lockdown.map(|v| !v));
    print_allow_tcp_ports(&config.allow_tcp_ports, config.lockdown_enabled());
    print_default_on_tristate("  Status bar", config.no_status_bar);
    if config.status_bar_enabled() {
        output::status_header("  Style", config.status_bar_style());
    }
    if let Some(key) = config.resize_redraw_key.as_deref() {
        output::status_header("  Resize redraw", key);
    }
    if let Some(dir) = &config.claude_dir {
        output::status_header("  Claude dir", &dir.display().to_string());
    }
}

fn print_command(config: &Config) {
    if config.command.is_empty() {
        output::status_header("  Command", "(default: bash)");
    } else {
        output::status_header("  Command", &config.command.join(" "));
    }
}

fn print_path_list(label: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let joined = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    output::status_header(label, &joined);
}

fn print_string_list(label: &str, strings: &[String]) {
    if strings.is_empty() {
        return;
    }
    output::status_header(label, &strings.join(", "));
}

/// Render a `no_*` field with the default-off convention:
/// Some(true) → "disabled", Some(false) → "enabled", None → "auto".
fn print_auto_tristate(label: &str, val: Option<bool>) {
    let v = match val {
        Some(true) => "disabled",
        Some(false) => "enabled",
        None => "auto",
    };
    output::status_header(label, v);
}

/// Render a `no_*` field with the default-on convention:
/// Some(true) → "disabled", Some(false) → "enabled", None → "enabled (default)".
fn print_default_on_tristate(label: &str, val: Option<bool>) {
    let v = match val {
        Some(true) => "disabled",
        Some(false) => "enabled",
        None => "enabled (default)",
    };
    output::status_header(label, v);
}

/// For ssh/pictures: explicit-on shares the dir, anything else hides it.
fn print_shared_or_hidden(label: &str, val: Option<bool>) {
    let v = if val == Some(true) {
        "shared (read-only)"
    } else {
        "hidden"
    };
    output::status_header(label, v);
}

fn print_browser_profile(profile: Option<&str>) {
    let v = match profile {
        Some("off" | "none" | "disabled") => "disabled",
        Some(value) => value,
        None => "auto",
    };
    output::status_header("  Browser profile", v);
}

fn print_private_home(val: Option<bool>) {
    let v = match val {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "auto",
    };
    output::status_header("  Private home", v);
}

fn print_allow_tcp_ports(ports: &[u16], lockdown: bool) {
    if ports.is_empty() {
        return;
    }
    let joined = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let note = if lockdown {
        ""
    } else {
        " (only effective in lockdown mode)"
    };
    output::status_header("  Allow TCP ports", &format!("{joined}{note}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliArgs;
    use crate::test_utils::{ENV_LOCK, EnvVarGuard};

    // Tests that call set_current_dir must hold this lock to avoid
    // racing each other (cwd is process-global).
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serialize_config(config: &Config) -> Result<String, String> {
        toml::to_string_pretty(config).map_err(|e| e.to_string())
    }

    // ── Parsing tests ──────────────────────────────────────────

    #[test]
    fn map_spec_parses_same_path_and_alternate_destination() {
        let same = MapSpec::parse(Path::new("/opt/data")).unwrap();
        assert_eq!(same.source, PathBuf::from("/opt/data"));
        assert_eq!(same.destination, PathBuf::from("/opt/data"));
        assert!(!same.is_alternate());

        let alternate =
            MapSpec::parse(Path::new("/host/data:/jail/data:copy")).unwrap();
        assert_eq!(alternate.source, PathBuf::from("/host/data"));
        assert_eq!(alternate.destination, PathBuf::from("/jail/data:copy"));
        assert!(alternate.is_alternate());
    }

    #[test]
    fn map_spec_rejects_empty_components_and_root() {
        let error = MapSpec::parse(Path::new(":/jail")).unwrap_err();
        assert!(error.contains("empty source"));

        let error = MapSpec::parse(Path::new("/host:")).unwrap_err();
        assert!(error.contains("empty destination"));

        let root_source = MapSpec::parse(Path::new("/:/jail")).unwrap();
        let error = root_source.validate().unwrap_err();
        assert!(error.contains("root source"));

        let root_destination = MapSpec::parse(Path::new("/host:/")).unwrap();
        let error = root_destination.validate().unwrap_err();
        assert!(error.contains("root destination"));
    }

    #[test]
    fn map_spec_validate_rejects_empty_components() {
        let empty_source = MapSpec {
            source: PathBuf::new(),
            destination: PathBuf::from("/jail"),
        };
        let error = empty_source.validate().unwrap_err();
        assert!(error.contains("empty source"));

        let empty_destination = MapSpec {
            source: PathBuf::from("/host"),
            destination: PathBuf::new(),
        };
        let error = empty_destination.validate().unwrap_err();
        assert!(error.contains("empty destination"));
    }

    #[test]
    fn map_spec_encoding_keeps_legacy_shape() {
        let same = MapSpec {
            source: PathBuf::from("/opt/data"),
            destination: PathBuf::from("/opt/data"),
        };
        assert_eq!(same.encode(), PathBuf::from("/opt/data"));

        let alternate = MapSpec {
            source: PathBuf::from("/host/data"),
            destination: PathBuf::from("/jail/data"),
        };
        assert_eq!(alternate.encode(), PathBuf::from("/host/data:/jail/data"));
    }

    #[test]
    fn map_spec_preserves_but_rejects_non_utf8_bytes() {
        fn assert_rejected(
            encoded_bytes: &[u8],
            source: &[u8],
            destination: &[u8],
            component: &str,
        ) {
            let encoded =
                PathBuf::from(OsString::from_vec(encoded_bytes.to_vec()));
            let map = MapSpec::parse(&encoded).unwrap();

            assert_eq!(map.source.as_os_str().as_bytes(), source);
            assert_eq!(map.destination.as_os_str().as_bytes(), destination);
            assert_eq!(map.encode().as_os_str().as_bytes(), encoded_bytes);

            let error = map.validate().unwrap_err();
            assert!(error.contains(component), "unexpected error: {error}");
            assert!(error.contains("UTF-8"), "unexpected error: {error}");
        }

        assert_rejected(
            b"/host/\xff/data:/jail/data",
            b"/host/\xff/data",
            b"/jail/data",
            "source",
        );
        assert_rejected(
            b"/host/data:/jail/\xfe/data:copy",
            b"/host/data",
            b"/jail/\xfe/data:copy",
            "destination",
        );
    }

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
browser_profile = "soft"
private_home = true
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
        assert_eq!(cfg.browser_profile.as_deref(), Some("soft"));
        assert_eq!(cfg.browser_profile(), Some(BrowserProfile::Soft));
        assert_eq!(cfg.private_home, Some(true));
        assert!(cfg.private_home_enabled());
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
    fn regression_pre_alternate_destination_map_format() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/shared"]
ro_maps = ["~/.ssh"]
"#;
        let cfg = parse_toml(toml).unwrap();

        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/shared")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("~/.ssh")]);
    }

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
        assert_eq!(cfg.browser_profile, None);
        assert_eq!(cfg.private_home, None);
        assert_eq!(cfg.no_seccomp, None);
        assert_eq!(cfg.no_rlimits, None);
        assert!(cfg.allow_tcp_ports.is_empty());
        assert_eq!(cfg.claude_dir, None);
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
    fn regression_v0_10_0_config_without_private_home() {
        let toml = r#"
command = ["claude"]
rw_maps = []
ro_maps = []
hide_dotdirs = []
mask = []
no_gpu = false
no_docker = false
no_display = false
no_worktree = false
no_mise = false
no_save_config = false
browser_profile = "off"
lockdown = false
no_landlock = false
no_status_bar = false
status_bar_style = "pastel"
resize_redraw_key = "ctrl-shift-l"
no_seccomp = false
no_rlimits = false
allow_tcp_ports = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.private_home, None);
        assert!(!cfg.private_home_enabled());
    }

    #[test]
    fn regression_v1_7_0_config_without_overlay_maps() {
        // Configs written before overlay_maps existed must still parse,
        // defaulting the new field to an empty list.
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
ro_maps = ["/opt/ro"]
hide_dotdirs = []
mask = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/tmp/rw")]);
        assert_eq!(cfg.ro_maps, vec![PathBuf::from("/opt/ro")]);
        assert!(cfg.overlay_maps.is_empty());
    }

    #[test]
    fn regression_old_config_without_deny_paths() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
mask = [".env"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.deny_paths.is_empty());
        assert!(cfg.mask_exceptions.is_empty());
        assert!(cfg.deny_path_exceptions.is_empty());
    }

    #[test]
    fn regression_old_config_without_systemd_user() {
        let toml = r#"
command = ["claude"]
rw_maps = ["/tmp/rw"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.systemd_user, None);
        assert!(!cfg.systemd_user_enabled());
    }

    #[test]
    fn parse_config_with_overlay_maps() {
        let toml = r#"
command = ["claude"]
overlay_maps = ["/home/u/.claude", "/home/u/.config/foo"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.overlay_maps,
            vec![
                PathBuf::from("/home/u/.claude"),
                PathBuf::from("/home/u/.config/foo"),
            ]
        );
    }

    #[test]
    fn parse_deny_paths() {
        let toml = r#"
command = ["claude"]
deny_paths = [".env", "secrets/*.json"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.deny_paths,
            vec![PathBuf::from(".env"), PathBuf::from("secrets/*.json")]
        );
    }

    #[test]
    fn parse_mask_and_deny_path_exceptions() {
        let cfg = parse_toml(
            "mask_exceptions = [\"**/target/**\"]\ndeny_path_exceptions = [\"public.key\"]",
        )
        .unwrap();
        assert_eq!(cfg.mask_exceptions, vec![PathBuf::from("**/target/**")]);
        assert_eq!(cfg.deny_path_exceptions, vec![PathBuf::from("public.key")]);
    }

    #[test]
    fn parse_systemd_user() {
        let cfg = parse_toml("systemd_user = true\n").unwrap();
        assert_eq!(cfg.systemd_user, Some(true));
        assert!(cfg.systemd_user_enabled());
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

    #[test]
    fn regression_old_config_without_tailscale_parses() {
        let toml = r#"
command = ["claude"]
no_docker = false
no_gpu = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.tailscale, None);
        assert!(!cfg.tailscale_enabled());
    }

    // ── Roundtrip tests ────────────────────────────────────────

    #[test]
    fn roundtrip_serialize_deserialize() {
        let config = Config {
            command: vec!["claude".into()],
            rw_maps: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            ro_maps: vec![PathBuf::from("/opt/data")],
            overlay_maps: vec![PathBuf::from("/home/u/.claude")],
            hide_dotdirs: vec![".my_secrets".into(), ".proton".into()],
            mask: vec![PathBuf::from(".env")],
            deny_paths: vec![PathBuf::from("secrets.json")],
            mask_exceptions: vec![PathBuf::from("target")],
            deny_path_exceptions: vec![PathBuf::from("public.json")],
            no_gpu: Some(true),
            no_docker: None,
            tailscale: Some(true),
            no_display: Some(false),
            no_worktree: Some(false),
            no_mise: None,
            no_save_config: Some(true),
            no_hide_config: Some(false),
            ssh: Some(true),
            pictures: None,
            browser_profile: Some("soft".into()),
            private_home: Some(true),
            lockdown: Some(true),
            no_landlock: Some(false),
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            systemd_user: Some(true),
            allow_tcp_ports: vec![32000, 8080],
            claude_dir: None,
        };
        let serialized = serialize_config(&config).unwrap();
        let deserialized = parse_toml(&serialized).unwrap();
        assert_eq!(deserialized.command, config.command);
        assert_eq!(deserialized.rw_maps, config.rw_maps);
        assert_eq!(deserialized.ro_maps, config.ro_maps);
        assert_eq!(deserialized.hide_dotdirs, config.hide_dotdirs);
        assert_eq!(deserialized.deny_paths, config.deny_paths);
        assert_eq!(deserialized.mask_exceptions, config.mask_exceptions);
        assert_eq!(
            deserialized.deny_path_exceptions,
            config.deny_path_exceptions
        );
        assert_eq!(deserialized.no_gpu, config.no_gpu);
        assert_eq!(deserialized.no_docker, config.no_docker);
        assert_eq!(deserialized.tailscale, config.tailscale);
        assert_eq!(deserialized.no_display, config.no_display);
        assert_eq!(deserialized.no_worktree, config.no_worktree);
        assert_eq!(deserialized.no_mise, config.no_mise);
        assert_eq!(deserialized.no_save_config, config.no_save_config);
        assert_eq!(deserialized.browser_profile, config.browser_profile);
        assert_eq!(deserialized.private_home, config.private_home);
        assert_eq!(deserialized.lockdown, config.lockdown);
        assert_eq!(deserialized.no_landlock, config.no_landlock);
        assert_eq!(deserialized.resize_redraw_key, config.resize_redraw_key);
        assert_eq!(deserialized.no_seccomp, config.no_seccomp);
        assert_eq!(deserialized.no_rlimits, config.no_rlimits);
        assert_eq!(deserialized.systemd_user, config.systemd_user);
        assert_eq!(deserialized.allow_tcp_ports, config.allow_tcp_ports);
        assert_eq!(deserialized.claude_dir, config.claude_dir);
    }

    #[test]
    fn serialize_default_omits_empty_defaults() {
        let serialized = serialize_config(&Config::default()).unwrap();
        assert!(
            serialized.trim().is_empty(),
            "default config should not write empty/default fields: {serialized:?}"
        );
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
    fn merge_deduplicates_complete_map_specifications() {
        let existing = Config {
            rw_maps: vec![PathBuf::from("/host/data:/jail/one")],
            ..Config::default()
        };
        let cli = CliArgs {
            rw_maps: vec![
                PathBuf::from("/host/data:/jail/one"),
                PathBuf::from("/host/data:/jail/two"),
            ],
            ..CliArgs::default()
        };

        let merged = merge(&cli, existing);

        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/host/data:/jail/one"),
                PathBuf::from("/host/data:/jail/two"),
            ]
        );
    }

    #[test]
    fn merge_deny_paths_appended_and_deduplicated() {
        let existing = Config {
            deny_paths: vec![PathBuf::from(".env")],
            ..Config::default()
        };
        let cli = CliArgs {
            deny_paths: vec![
                PathBuf::from(".env"),
                PathBuf::from("secrets/*.json"),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.deny_paths,
            vec![PathBuf::from(".env"), PathBuf::from("secrets/*.json")]
        );
    }

    #[test]
    fn merge_exceptions_appended_and_deduplicated() {
        let existing = Config {
            mask_exceptions: vec![PathBuf::from("target")],
            deny_path_exceptions: vec![PathBuf::from("public")],
            ..Config::default()
        };
        let cli = CliArgs {
            mask_exceptions: vec![
                PathBuf::from("target"),
                PathBuf::from("build"),
            ],
            deny_path_exceptions: vec![
                PathBuf::from("public"),
                PathBuf::from("docs"),
            ],
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.mask_exceptions,
            vec![PathBuf::from("target"), PathBuf::from("build")]
        );
        assert_eq!(
            merged.deny_path_exceptions,
            vec![PathBuf::from("public"), PathBuf::from("docs")]
        );
    }

    #[test]
    fn merge_systemd_user_from_cli() {
        let existing = Config {
            systemd_user: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            systemd_user: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.systemd_user, Some(true));
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
    fn parse_tailscale_config() {
        let toml = r#"
command = ["claude"]
tailscale = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.tailscale, Some(true));
        assert!(cfg.tailscale_enabled());
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
            tailscale: Some(true),
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
        assert_eq!(merged.tailscale, Some(true));
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
            tailscale: Some(true),    // --tailscale
            display: Some(true),      // --display
            worktree: Some(false),    // --no-worktree
            mise: Some(true),         // --mise
            save_config: Some(false), // --no-save-config
            private_home: Some(true), // --private-home
            lockdown: Some(true),     // --lockdown
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.no_docker, Some(true));
        assert_eq!(merged.tailscale, Some(true));
        assert_eq!(merged.no_display, Some(false));
        assert_eq!(merged.no_worktree, Some(true));
        assert_eq!(merged.no_mise, Some(false));
        assert_eq!(merged.no_save_config, Some(true));
        assert_eq!(merged.private_home, Some(true));
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
    fn merge_browser_profile_from_cli() {
        let existing = Config::default();
        let cli = CliArgs {
            browser_profile: Some("soft".into()),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.browser_profile.as_deref(), Some("soft"));
        assert_eq!(merged.browser_profile(), Some(BrowserProfile::Soft));
    }

    #[test]
    fn merge_private_home_from_cli() {
        let existing = Config {
            private_home: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            private_home: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.private_home, Some(true));
        assert!(merged.private_home_enabled());
    }

    #[test]
    fn merge_with_global_local_private_home_wins() {
        let global = Config {
            private_home: Some(true),
            ..Config::default()
        };
        let local = Config {
            private_home: Some(false),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.private_home, Some(false));
    }

    #[test]
    fn merge_with_global_local_tailscale_wins() {
        let global = Config {
            tailscale: Some(false),
            ..Config::default()
        };
        let local = Config {
            tailscale: Some(true),
            ..Config::default()
        };
        let merged = merge_with_global(global, local);
        assert_eq!(merged.tailscale, Some(true));
    }

    #[test]
    fn auto_save_project_config_does_not_copy_global_only_scalars() {
        let global = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            tailscale: Some(true),
            private_home: Some(true),
            claude_dir: Some(PathBuf::from("/home/u/.claude-global")),
            ..Config::default()
        };
        let project = Config::default();
        let runtime = merge_with_global(global, project.clone());
        assert_eq!(runtime.no_gpu, Some(true));
        assert_eq!(
            runtime.claude_dir,
            Some(PathBuf::from("/home/u/.claude-global"))
        );

        let to_save = project_config_for_auto_save(
            &CliArgs::default(),
            project,
            Path::new("/project"),
        );
        assert_eq!(to_save.no_gpu, None);
        assert_eq!(to_save.no_docker, None);
        assert_eq!(to_save.tailscale, None);
        assert_eq!(to_save.private_home, None);
        assert_eq!(to_save.claude_dir, None);
    }

    #[test]
    fn auto_save_project_config_keeps_project_and_cli_vectors_not_global() {
        let global = Config {
            rw_maps: vec![PathBuf::from("/global/rw")],
            ro_maps: vec![PathBuf::from("/global/ro")],
            overlay_maps: vec![PathBuf::from("/global/overlay")],
            hide_dotdirs: vec![".global".into()],
            mask: vec![PathBuf::from("/global/mask")],
            allow_tcp_ports: vec![1111],
            ..Config::default()
        };
        let project = Config {
            rw_maps: vec![PathBuf::from("/project/rw")],
            ro_maps: vec![PathBuf::from("/project/ro")],
            overlay_maps: vec![PathBuf::from("/project/overlay")],
            hide_dotdirs: vec![".project".into()],
            mask: vec![PathBuf::from("/project/mask")],
            allow_tcp_ports: vec![2222],
            ..Config::default()
        };
        let runtime = merge_with_global(global, project.clone());
        assert!(runtime.rw_maps.contains(&PathBuf::from("/global/rw")));

        let cli = CliArgs {
            rw_maps: vec![PathBuf::from("cli-rw")],
            ro_maps: vec![PathBuf::from("cli-ro")],
            overlay_maps: vec![PathBuf::from("cli-overlay")],
            hide_dotdirs: vec![".cli".into()],
            mask: vec![PathBuf::from("/cli/mask")],
            allow_tcp_ports: vec![3333],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));

        assert_eq!(
            to_save.rw_maps,
            vec![
                PathBuf::from("/project/rw"),
                PathBuf::from("/project/cli-rw")
            ]
        );
        assert_eq!(
            to_save.ro_maps,
            vec![
                PathBuf::from("/project/ro"),
                PathBuf::from("/project/cli-ro")
            ]
        );
        assert_eq!(
            to_save.overlay_maps,
            vec![
                PathBuf::from("/project/overlay"),
                PathBuf::from("/project/cli-overlay"),
            ]
        );
        assert_eq!(to_save.hide_dotdirs, vec![".project", ".cli"]);
        assert_eq!(
            to_save.mask,
            vec![PathBuf::from("/project/mask"), PathBuf::from("/cli/mask")]
        );
        assert_eq!(to_save.allow_tcp_ports, vec![2222, 3333]);
    }

    #[test]
    fn auto_save_persists_cli_command_when_only_global_command_exists() {
        let global = Config {
            command: vec!["global-agent".into()],
            ..Config::default()
        };
        let project = Config::default();
        let runtime = merge_with_global(global, project.clone());
        assert_eq!(runtime.command, vec!["global-agent"]);

        let cli = CliArgs {
            command: vec!["claude".into()],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));
        assert_eq!(to_save.command, vec!["claude"]);
    }

    #[test]
    fn auto_save_project_config_preserves_existing_project_command() {
        let project = Config {
            command: vec!["claude".into()],
            ..Config::default()
        };
        let cli = CliArgs {
            command: vec!["codex".into()],
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));
        assert_eq!(to_save.command, vec!["claude"]);
    }

    #[test]
    fn auto_save_project_config_persists_cli_boolean_overrides() {
        let project = Config {
            no_gpu: Some(false),
            no_docker: Some(true),
            tailscale: Some(false),
            no_seccomp: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            gpu: Some(false),
            docker: Some(true),
            tailscale: Some(true),
            seccomp: Some(false),
            ..CliArgs::default()
        };
        let to_save =
            project_config_for_auto_save(&cli, project, Path::new("/project"));

        assert_eq!(to_save.no_gpu, Some(true));
        assert_eq!(to_save.no_docker, Some(false));
        assert_eq!(to_save.tailscale, Some(true));
        assert_eq!(to_save.no_seccomp, Some(true));
    }

    #[test]
    fn command_scoped_global_applies_for_cli_command() {
        let global = parse_global_toml(
            r#"
rw_maps = ["~/common"]
no_gpu = true

[commands.pi]
rw_maps = ["~/.pi", "~/.pi-lens"]
tailscale = true

[commands.claude]
rw_maps = ["~/.claude"]
tailscale = false
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["pi".into()],
            ..CliArgs::default()
        };

        let selected =
            global_config_for_command(global, &cli, &Config::default());

        assert_eq!(
            selected.rw_maps,
            vec![
                PathBuf::from("~/common"),
                PathBuf::from("~/.pi"),
                PathBuf::from("~/.pi-lens"),
            ]
        );
        assert_eq!(selected.no_gpu, Some(true));
        assert_eq!(selected.tailscale, Some(true));
        assert!(!selected.rw_maps.contains(&PathBuf::from("~/.claude")));
    }

    #[test]
    fn command_scoped_global_uses_project_command_when_cli_absent() {
        let global = parse_global_toml(
            r#"
rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi"]
tailscale = true
"#,
        )
        .unwrap();
        let project = Config {
            command: vec!["pi".into()],
            ..Config::default()
        };

        let selected =
            global_config_for_command(global, &CliArgs::default(), &project);

        assert_eq!(
            selected.rw_maps,
            vec![PathBuf::from("~/common"), PathBuf::from("~/.pi")]
        );
        assert_eq!(selected.tailscale, Some(true));
    }

    #[test]
    fn command_scoped_global_uses_base_command_as_fallback() {
        let global = parse_global_toml(
            r#"
command = ["pi"]
rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi"]
tailscale = true
"#,
        )
        .unwrap();

        let selected = global_config_for_command(
            global,
            &CliArgs::default(),
            &Config::default(),
        );

        assert_eq!(selected.command, vec!["pi"]);
        assert_eq!(
            selected.rw_maps,
            vec![PathBuf::from("~/common"), PathBuf::from("~/.pi")]
        );
        assert_eq!(selected.tailscale, Some(true));
    }

    #[test]
    fn project_config_overrides_command_scoped_global() {
        let global = parse_global_toml(
            r#"
no_gpu = true
rw_maps = ["~/common"]

[commands.pi]
tailscale = true
no_docker = true
rw_maps = ["~/.pi"]
"#,
        )
        .unwrap();
        let cli = CliArgs {
            command: vec!["pi".into()],
            ..CliArgs::default()
        };
        let project = Config {
            tailscale: Some(false),
            no_docker: Some(false),
            rw_maps: vec![PathBuf::from("/project/rw")],
            ..Config::default()
        };

        let selected = global_config_for_command(global, &cli, &project);
        let merged = merge_with_global(selected, project);

        assert_eq!(merged.no_gpu, Some(true));
        assert_eq!(merged.tailscale, Some(false));
        assert_eq!(merged.no_docker, Some(false));
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("~/common"),
                PathBuf::from("~/.pi"),
                PathBuf::from("/project/rw"),
            ]
        );
    }

    #[test]
    fn project_parse_toml_ignores_commands_table() {
        let cfg = parse_toml(
            r#"
rw_maps = ["/project"]

[commands.pi]
rw_maps = ["/global-pi"]
tailscale = true
"#,
        )
        .unwrap();

        assert_eq!(cfg.rw_maps, vec![PathBuf::from("/project")]);
        assert_eq!(cfg.tailscale, None);
    }

    #[test]
    fn browser_profile_disabled_accessor() {
        assert!(
            !Config {
                browser_profile: Some("hard".into()),
                ..Config::default()
            }
            .browser_profile_disabled()
        );
        assert!(
            Config {
                browser_profile: Some("off".into()),
                ..Config::default()
            }
            .browser_profile_disabled()
        );
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
    fn tailscale_enabled_accessor() {
        assert!(!Config::default().tailscale_enabled());
        assert!(
            Config {
                tailscale: Some(true),
                ..Config::default()
            }
            .tailscale_enabled()
        );
        assert!(
            !Config {
                tailscale: Some(false),
                ..Config::default()
            }
            .tailscale_enabled()
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
    fn hide_config_enabled_accessor() {
        // Default: hidden
        assert!(Config::default().hide_config_enabled());
        // Explicit on
        assert!(
            Config {
                no_hide_config: Some(false),
                ..Config::default()
            }
            .hide_config_enabled()
        );
        // Opt-out
        assert!(
            !Config {
                no_hide_config: Some(true),
                ..Config::default()
            }
            .hide_config_enabled()
        );
    }

    #[test]
    fn merge_cli_no_hide_config_overrides_config() {
        let existing = Config {
            no_hide_config: Some(false),
            ..Config::default()
        };
        let cli = CliArgs {
            hide_config: Some(false),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_hide_config, Some(true));
        assert!(!merged.hide_config_enabled());
    }

    #[test]
    fn merge_cli_hide_config_overrides_config() {
        let existing = Config {
            no_hide_config: Some(true),
            ..Config::default()
        };
        let cli = CliArgs {
            hide_config: Some(true),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(merged.no_hide_config, Some(false));
        assert!(merged.hide_config_enabled());
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
    fn missing_config_file_uses_defaults() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-missing-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let config = load_from_path(&dir.join(".ai-jail")).unwrap();

        assert!(config.command.is_empty());
        assert!(config.rw_maps.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_config_file_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-malformed-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        std::fs::write(&path, "command = [\"bash\"\n").unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to parse {}", path.display())));
        assert!(error.contains("TOML parse error"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_config_path_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-unreadable-config-{}", std::process::id()));
        let path = dir.join(".ai-jail");
        std::fs::create_dir_all(&path).unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to read {}", path.display())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_utf8_config_file_is_fatal() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-non-utf8-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        std::fs::write(&path, [0xff]).unwrap();

        let error = load_from_path(&path).unwrap_err();

        assert!(error.contains(&format!("Failed to read {}", path.display())));
        assert_eq!(std::fs::read(&path).unwrap(), [0xff]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_preference_save_preserves_malformed_file() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-malformed-global-config-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".ai-jail");
        let original = "no_gpu = tru\n";
        std::fs::write(&path, original).unwrap();
        let config = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };

        let error = save_global_to_path(&path, &config).unwrap_err();

        assert!(error.contains(&format!("Failed to parse {}", path.display())));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_global_status_bar_theme_persists() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-home-global-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");

        let cfg = Config {
            no_status_bar: None,
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_from_path(&path).unwrap();
        assert_eq!(global.no_status_bar, None);
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_global_theme_does_not_reenable_disabled_status_bar() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-home-global-preserve-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);

        let path = dir.join(".ai-jail");
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
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_from_path(&path).unwrap();
        assert_eq!(global.no_status_bar, Some(true));
        assert_eq!(global.status_bar_style.as_deref(), Some("dark"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_global_preserves_command_scoped_tables() {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-home-global-commands-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");
        std::fs::write(
            &path,
            r#"rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi", "~/.pi-lens"]
tailscale = true

[commands.claude]
rw_maps = ["~/.claude"]
"#,
        )
        .unwrap();

        let cfg = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_global_from_path(&path).unwrap();
        assert_eq!(global.base.status_bar_style.as_deref(), Some("dark"));
        assert_eq!(global.base.rw_maps, vec![PathBuf::from("~/common")]);
        assert_eq!(global.commands.len(), 2);
        assert_eq!(
            global.commands["pi"].rw_maps,
            vec![PathBuf::from("~/.pi"), PathBuf::from("~/.pi-lens")]
        );
        assert_eq!(global.commands["pi"].tailscale, Some(true));
        assert_eq!(
            global.commands["claude"].rw_maps,
            vec![PathBuf::from("~/.claude")]
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regression_old_plain_global_roundtrips_through_save() {
        // A global .ai-jail written before [commands.*] tables existed
        // (plain Config fields only) must survive a save cycle: the
        // serde(flatten) load/save path must not drop or reshape any
        // base field, and must not invent a [commands] table.
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-old-plain-global-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".ai-jail");
        std::fs::write(
            &path,
            r#"command = ["claude"]
rw_maps = ["~/shared"]
no_gpu = true
hide_dotdirs = [".my_secrets"]
"#,
        )
        .unwrap();

        let cfg = Config {
            status_bar_style: Some("dark".into()),
            ..Config::default()
        };
        save_global_to_path(&path, &cfg).unwrap();

        let global = load_global_from_path(&path).unwrap();
        assert_eq!(global.base.command, vec!["claude"]);
        assert_eq!(global.base.rw_maps, vec![PathBuf::from("~/shared")]);
        assert_eq!(global.base.no_gpu, Some(true));
        assert_eq!(global.base.hide_dotdirs, vec![".my_secrets"]);
        assert_eq!(global.base.status_bar_style.as_deref(), Some("dark"));
        assert!(global.commands.is_empty());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("[commands"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&dir);
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
            overlay_maps: vec![],
            hide_dotdirs: vec![],
            mask: vec![],
            deny_paths: vec![PathBuf::from("secrets.json")],
            mask_exceptions: vec![],
            deny_path_exceptions: vec![],
            no_gpu: Some(true),
            no_docker: None,
            tailscale: Some(true),
            no_display: None,
            no_worktree: None,
            no_mise: None,
            no_save_config: Some(true),
            no_hide_config: None,
            ssh: None,
            pictures: Some(true),
            browser_profile: Some("hard".into()),
            private_home: Some(true),
            lockdown: Some(false),
            no_landlock: None,
            no_status_bar: None,
            status_bar_style: None,
            resize_redraw_key: Some("ctrl-shift-l".into()),
            no_seccomp: None,
            no_rlimits: None,
            systemd_user: Some(true),
            allow_tcp_ports: vec![32000],
            claude_dir: None,
        };
        save(&config);

        let loaded = load().unwrap();
        assert_eq!(loaded.command, vec!["codex"]);
        assert_eq!(loaded.rw_maps, vec![PathBuf::from("/tmp/shared")]);
        assert_eq!(loaded.no_gpu, Some(true));
        assert_eq!(loaded.lockdown, Some(false));
        assert_eq!(loaded.allow_tcp_ports, vec![32000]);
        assert_eq!(loaded.systemd_user, Some(true));
        assert_eq!(loaded.deny_paths, vec![PathBuf::from("secrets.json")]);
        assert_eq!(loaded.resize_redraw_key, None);
        assert_eq!(loaded.browser_profile.as_deref(), Some("hard"));
        assert_eq!(loaded.claude_dir, None);

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

    // ── Tilde expansion tests ─────────────────────────────────

    #[test]
    fn expand_tilde_with_slash() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/example");
        let out = expand_tilde(PathBuf::from("~/projects/x"));
        assert_eq!(out, PathBuf::from("/home/example/projects/x"));
    }

    #[test]
    fn expand_tilde_bare() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/bare");
        assert_eq!(
            expand_tilde(PathBuf::from("~")),
            PathBuf::from("/home/bare")
        );
    }

    #[test]
    fn expand_tilde_leaves_other_user_home_alone() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/me");
        // ~otheruser should not be rewritten
        let p = PathBuf::from("~otheruser/file");
        assert_eq!(expand_tilde(p.clone()), p);
    }

    #[test]
    fn expand_tilde_passes_through_absolute_paths() {
        let _env = ENV_LOCK.lock().unwrap();
        let p = PathBuf::from("/tmp/abs");
        assert_eq!(expand_tilde(p.clone()), p);
    }

    #[test]
    fn merge_expands_tilde_in_ro_and_rw_maps_and_mask() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");

        let existing = Config {
            ro_maps: vec![
                PathBuf::from("~/.bashrc"),
                PathBuf::from("/absolute/path"),
            ],
            rw_maps: vec![PathBuf::from("~/work")],
            mask: vec![PathBuf::from("~/secret.env")],
            ..Config::default()
        };
        let merged = merge(&CliArgs::default(), existing);

        assert_eq!(
            merged.ro_maps,
            vec![
                PathBuf::from("/home/user/.bashrc"),
                PathBuf::from("/absolute/path"),
            ]
        );
        assert_eq!(merged.rw_maps, vec![PathBuf::from("/home/user/work")]);
        assert_eq!(merged.mask, vec![PathBuf::from("/home/user/secret.env")]);
    }

    #[test]
    fn merge_expands_tilde_on_both_map_sides() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let existing = Config {
            ro_maps: vec![PathBuf::from("~/.ssh/ai-jail:~/.ssh")],
            ..Config::default()
        };

        let merged = merge(&CliArgs::default(), existing);

        assert_eq!(
            merged.ro_maps,
            vec![PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh")]
        );
    }

    // ── Relative-path resolution tests (issue #54) ────────────

    #[test]
    fn normalize_path_collapses_parent_and_current() {
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(normalize_path(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(
            normalize_path(Path::new("/a/b/c/..")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn normalize_path_drops_dotdot_above_root() {
        // /.. is /, /../foo is /foo. Matches `cd /..` shell behaviour.
        assert_eq!(normalize_path(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(normalize_path(Path::new("/../foo")), PathBuf::from("/foo"));
        assert_eq!(
            normalize_path(Path::new("/a/../../b")),
            PathBuf::from("/b")
        );
    }

    #[test]
    fn normalize_path_preserves_leading_dotdot_when_relative() {
        // Relative input with no base to resolve against: keep `..`.
        // (In practice we always call this on absolute paths via
        // to_absolute, but the helper itself should be sane.)
        assert_eq!(
            normalize_path(Path::new("../foo")),
            PathBuf::from("../foo")
        );
    }

    #[test]
    fn normalize_path_empty_becomes_dot() {
        assert_eq!(normalize_path(Path::new("./.")), PathBuf::from("."));
    }

    #[test]
    fn to_absolute_resolves_parent_relative_against_base() {
        // Core repro for #54: `--map ../sister-project` from
        // /home/user/Projects/myproject must yield the absolute
        // sibling, not be passed through to bwrap as `../sister-project`.
        let cwd = Path::new("/home/user/Projects/myproject");
        assert_eq!(
            to_absolute(PathBuf::from("../sister-project"), cwd),
            PathBuf::from("/home/user/Projects/sister-project")
        );
    }

    #[test]
    fn to_absolute_leaves_absolute_paths_alone_modulo_normalization() {
        let cwd = Path::new("/home/user");
        assert_eq!(
            to_absolute(PathBuf::from("/opt/data"), cwd),
            PathBuf::from("/opt/data")
        );
        // Absolute path with `..` still gets normalized.
        assert_eq!(
            to_absolute(PathBuf::from("/opt/foo/../data"), cwd),
            PathBuf::from("/opt/data")
        );
    }

    #[test]
    fn to_absolute_resolves_bare_relative() {
        let cwd = Path::new("/home/user/project");
        assert_eq!(
            to_absolute(PathBuf::from("subdir"), cwd),
            PathBuf::from("/home/user/project/subdir")
        );
        assert_eq!(
            to_absolute(PathBuf::from("./subdir"), cwd),
            PathBuf::from("/home/user/project/subdir")
        );
    }

    #[test]
    fn absolutize_user_paths_handles_rw_and_ro_maps() {
        let mut config = Config {
            rw_maps: vec![
                PathBuf::from("../sister"),
                PathBuf::from("/opt/abs"),
            ],
            ro_maps: vec![PathBuf::from("./sub")],
            // mask is intentionally NOT touched by absolutize; its
            // existing "relative-to-project-dir at mount time" semantic
            // (see build_mask_mounts) is left alone.
            mask: vec![PathBuf::from("secret.env")],
            ..Config::default()
        };
        absolutize_user_paths(
            &mut config,
            Path::new("/home/user/Projects/myproject"),
        );
        assert_eq!(
            config.rw_maps,
            vec![
                PathBuf::from("/home/user/Projects/sister"),
                PathBuf::from("/opt/abs"),
            ]
        );
        assert_eq!(
            config.ro_maps,
            vec![PathBuf::from("/home/user/Projects/myproject/sub")]
        );
        assert_eq!(config.mask, vec![PathBuf::from("secret.env")]);
    }

    #[test]
    fn absolutize_user_paths_is_idempotent() {
        // The landlock-exec re-entry calls absolutize again; absolute
        // paths must not be mangled.
        let mut config = Config {
            rw_maps: vec![PathBuf::from("/home/user/work")],
            ro_maps: vec![PathBuf::from("/opt/data")],
            ..Config::default()
        };
        absolutize_user_paths(&mut config, Path::new("/somewhere/else"));
        absolutize_user_paths(&mut config, Path::new("/elsewhere"));
        assert_eq!(config.rw_maps, vec![PathBuf::from("/home/user/work")]);
        assert_eq!(config.ro_maps, vec![PathBuf::from("/opt/data")]);
    }

    #[test]
    fn absolutize_user_paths_resolves_both_map_sides() {
        let mut config = Config {
            rw_maps: vec![PathBuf::from("../shared:vendor/shared")],
            ..Config::default()
        };

        absolutize_user_paths(&mut config, Path::new("/work/project"));

        assert_eq!(
            config.rw_maps,
            vec![PathBuf::from("/work/shared:/work/project/vendor/shared")]
        );
    }

    #[test]
    fn alternate_map_absolutization_is_idempotent() {
        let mut config = Config {
            rw_maps: vec![PathBuf::from("/host/data:/jail/data")],
            ..Config::default()
        };

        absolutize_user_paths(&mut config, Path::new("/first"));
        absolutize_user_paths(&mut config, Path::new("/second"));

        assert_eq!(
            config.rw_maps,
            vec![PathBuf::from("/host/data:/jail/data")]
        );
    }

    // ── Tilde collapse tests (issue #52) ──────────────────────

    #[test]
    fn collapse_tilde_rewrites_home_prefix() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        assert_eq!(
            collapse_tilde(Path::new("/home/user/.claude")),
            PathBuf::from("~/.claude")
        );
    }

    #[test]
    fn collapse_tilde_rewrites_bare_home() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        assert_eq!(collapse_tilde(Path::new("/home/user")), PathBuf::from("~"));
    }

    #[test]
    fn collapse_tilde_leaves_unrelated_paths_alone() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let p = Path::new("/opt/data");
        assert_eq!(collapse_tilde(p), PathBuf::from("/opt/data"));
    }

    #[test]
    fn collapse_tilde_does_not_match_sibling_directories() {
        // /home/user2/foo must NOT collapse just because $HOME is /home/user.
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");
        let p = Path::new("/home/user2/foo");
        assert_eq!(collapse_tilde(p), PathBuf::from("/home/user2/foo"));
    }

    #[test]
    fn collapse_tilde_returns_input_when_home_unset() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::remove("HOME");
        let p = Path::new("/home/user/.claude");
        assert_eq!(collapse_tilde(p), PathBuf::from("/home/user/.claude"));
    }

    #[test]
    fn save_round_trip_preserves_tilde_notation() {
        // Round-trip: write a config with `~/.claude` paths, run
        // through save_to_path, parse the resulting TOML back, and
        // confirm the on-disk file kept the `~/` form.
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/user");

        let tmp_dir = std::env::temp_dir().join(format!(
            "ai-jail-collapse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let path = tmp_dir.join(".ai-jail");

        let cfg = Config {
            command: vec!["claude".into()],
            // These are expanded as if they had passed through merge().
            rw_maps: vec![
                PathBuf::from("/home/user/.claude"),
                PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh"),
            ],
            ro_maps: vec![PathBuf::from("/home/user/.bashrc")],
            mask: vec![PathBuf::from("/home/user/secret.env")],
            claude_dir: Some(PathBuf::from("/home/user/.claude-work")),
            ..Config::default()
        };
        save_to_path(&path, &cfg);

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("\"~/.claude\""),
            "expected ~/.claude in TOML, got:\n{written}"
        );
        assert!(
            written.contains("\"~/.ssh/ai-jail:~/.ssh\""),
            "alternate map not collapsed: {written}"
        );
        assert!(written.contains("\"~/.bashrc\""), "rw_maps not collapsed");
        assert!(written.contains("\"~/secret.env\""), "mask not collapsed");
        assert!(
            written.contains("\"~/.claude-work\""),
            "claude_dir not collapsed"
        );
        // And the round-trip: parse it back and re-expand via merge
        // should yield the same absolute paths we started with.
        let parsed = parse_toml(&written).unwrap();
        let merged = merge(&CliArgs::default(), parsed);
        assert_eq!(
            merged.rw_maps,
            vec![
                PathBuf::from("/home/user/.claude"),
                PathBuf::from("/home/user/.ssh/ai-jail:/home/user/.ssh"),
            ]
        );
        assert_eq!(merged.ro_maps, vec![PathBuf::from("/home/user/.bashrc")]);
        assert_eq!(merged.mask, vec![PathBuf::from("/home/user/secret.env")]);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-work"))
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ── claude_dir tests ──────────────────────────────────────

    #[test]
    fn regression_v0_9_0_config_without_claude_dir() {
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
        assert_eq!(cfg.claude_dir, None);
    }

    #[test]
    fn parse_claude_dir_from_toml() {
        let toml = r#"
command = ["claude"]
claude_dir = "/home/user/.claude-example"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_claude_dir_from_cli() {
        let existing = Config::default();
        let cli = CliArgs {
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_claude_dir_expands_tilde() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/testuser");

        let existing = Config::default();
        let cli = CliArgs {
            claude_dir: Some(PathBuf::from("~/.claude-example")),
            ..CliArgs::default()
        };
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/testuser/.claude-example"))
        );
    }

    #[test]
    fn merge_cli_no_claude_dir_preserves_config_claude_dir() {
        let existing = Config {
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/user/.claude-example"))
        );
    }

    #[test]
    fn merge_expands_tilde_from_config_file() {
        let _env = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/home/testuser");

        let existing = Config {
            claude_dir: Some(PathBuf::from("~/.claude-example")),
            ..Config::default()
        };
        let cli = CliArgs::default();
        let merged = merge(&cli, existing);
        assert_eq!(
            merged.claude_dir,
            Some(PathBuf::from("/home/testuser/.claude-example"))
        );
    }

    #[test]
    fn roundtrip_claude_dir() {
        let config = Config {
            command: vec!["claude".into()],
            claude_dir: Some(PathBuf::from("/home/user/.claude-example")),
            ..Config::default()
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized = parse_toml(&serialized).unwrap();
        assert_eq!(deserialized.claude_dir, config.claude_dir);
    }

    #[test]
    fn roundtrip_claude_dir_none_not_written() {
        let config = Config {
            command: vec!["claude".into()],
            claude_dir: None,
            ..Config::default()
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        assert!(!serialized.contains("claude_dir"));
    }
}
