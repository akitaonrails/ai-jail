use crate::output;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

// ── Permission lists (shared philosophy) ─────────────────────────

const ALLOW: &[&str] = &[
    // Git read
    "Bash(git status *)",
    "Bash(git diff *)",
    "Bash(git log *)",
    "Bash(git show *)",
    "Bash(git fetch *)",
    "Bash(git pull *)",
    "Bash(git branch *)",
    "Bash(git rev-parse *)",
    "Bash(git ls-files *)",
    "Bash(git remote -v*)",
    // Git local-write
    "Bash(git add *)",
    "Bash(git commit *)",
    "Bash(git stash *)",
    "Bash(git merge *)",
    "Bash(git checkout *)",
    "Bash(git switch *)",
    "Bash(git tag *)",
    // File read
    "Bash(ls *)",
    "Bash(find *)",
    "Bash(grep *)",
    "Bash(rg *)",
    "Bash(cat *)",
    "Bash(head *)",
    "Bash(tail *)",
    "Bash(file *)",
    "Bash(which *)",
    "Bash(wc *)",
    "Bash(stat *)",
    "Bash(du *)",
    "Bash(df *)",
    // File write non-destructive
    "Bash(mkdir *)",
    "Bash(cp *)",
    "Bash(mv *)",
    "Bash(touch *)",
    // System probing
    "Bash(ps *)",
    "Bash(lsof *)",
    "Bash(env *)",
    "Bash(printenv *)",
    "Bash(pwd)",
    "Bash(echo *)",
    "Bash(whoami)",
    "Bash(uname *)",
    "Bash(id *)",
    "Bash(date *)",
    // Text processing
    "Bash(sed *)",
    "Bash(awk *)",
    "Bash(sort *)",
    "Bash(uniq *)",
    "Bash(diff *)",
    "Bash(jq *)",
    "Bash(tee *)",
    "Bash(xargs *)",
    // Mise-managed toolchains
    "Bash(cargo *)",
    "Bash(rustc *)",
    "Bash(npm *)",
    "Bash(npx *)",
    "Bash(yarn *)",
    "Bash(pnpm *)",
    "Bash(bun *)",
    "Bash(node *)",
    "Bash(ruby *)",
    "Bash(bundle *)",
    "Bash(rails *)",
    "Bash(rake *)",
    "Bash(gem *)",
    "Bash(go *)",
    "Bash(python *)",
    "Bash(pip *)",
    "Bash(mix *)",
    "Bash(elixir *)",
    "Bash(iex *)",
    "Bash(erl *)",
    "Bash(zig *)",
    "Bash(mise *)",
    // Build tools
    "Bash(make *)",
    "Bash(cmake *)",
    "Bash(docker compose *)",
    "Bash(docker ps *)",
    "Bash(docker logs *)",
    "Bash(docker images *)",
    // CLI tools
    "Bash(gh *)",
    "Bash(curl *)",
    // Version/help probing
    "Bash(* --version)",
    "Bash(* --help)",
    // Web research
    "WebSearch",
    "WebFetch",
];

const DENY: &[&str] = &[
    "Bash(sudo *)",
    "Bash(chmod 777 *)",
    "Bash(git reset --hard *)",
    "Bash(git clean *)",
    "Bash(git push --force *)",
    "Bash(git push -f *)",
    "Bash(docker rm *)",
    "Bash(docker rmi *)",
    "Bash(docker system prune *)",
];

const ASK: &[&str] = &[
    "Bash(git push *)",
    "Bash(git rebase *)",
    "Bash(git branch -D *)",
    "Bash(git branch -d *)",
    "Bash(rm *)",
    "Bash(kamal *)",
    "Bash(docker run *)",
    "Bash(docker exec *)",
    "Bash(docker stop *)",
];

// ── Public entry point ───────────────────────────────────────────

pub fn run(verbose: bool, claude_dir: Option<&Path>) -> Result<(), String> {
    output::info("Bootstrapping AI tool configs...");

    bootstrap_gemini(verbose)?;
    bootstrap_claude(verbose, claude_dir)?;
    bootstrap_codex(verbose)?;
    bootstrap_opencode(verbose)?;
    bootstrap_crush(verbose)?;

    output::ok("Bootstrap complete");
    Ok(())
}

// ── Safe file helpers ─────────────────────────────────────────────

fn ensure_regular_file_or_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(format!(
                    "{} is a symlink — refusing to write",
                    path.display()
                ));
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

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = fs::create_dir_all(parent) {
        return Err(format!(
            "Cannot create directory {}: {e}",
            parent.display()
        ));
    }

    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bootstrap");
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

fn backup_file(path: &Path) -> Result<bool, String> {
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

// ── Gemini ───────────────────────────────────────────────────────

fn gemini_policy_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".gemini")
        .join("policies")
        .join("ai-jail.toml")
}

fn toml_basic_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn gemini_command_prefix(source: &str) -> Option<String> {
    let inner = source.strip_prefix("Bash(")?.strip_suffix(')')?;
    if inner.starts_with('*') {
        return None;
    }
    let prefix = inner
        .strip_suffix(" *")
        .or_else(|| inner.strip_suffix('*'))
        .unwrap_or(inner)
        .trim_end();
    if prefix.is_empty() {
        None
    } else {
        Some(prefix.to_string())
    }
}

fn gemini_command_prefixes(list: &[&str]) -> Vec<String> {
    list.iter()
        .filter_map(|entry| gemini_command_prefix(entry))
        .collect()
}

fn push_gemini_tool_rule(toml: &mut String, tool_name: &str, decision: &str) {
    toml.push_str("[[rule]]\n");
    toml.push_str(&format!("toolName = {}\n", toml_basic_string(tool_name)));
    toml.push_str(&format!("decision = {}\n", toml_basic_string(decision)));
    toml.push_str("priority = 100\n\n");
}

fn push_gemini_shell_rule(
    toml: &mut String,
    decision: &str,
    priority: u16,
    prefixes: &[String],
) {
    if prefixes.is_empty() {
        return;
    }
    toml.push_str("[[rule]]\n");
    toml.push_str("toolName = \"run_shell_command\"\n");
    toml.push_str(&format!("decision = {}\n", toml_basic_string(decision)));
    toml.push_str(&format!("priority = {priority}\n"));
    toml.push_str("commandPrefix = [\n");
    for prefix in prefixes {
        toml.push_str("    ");
        toml.push_str(&toml_basic_string(prefix));
        toml.push_str(",\n");
    }
    toml.push_str("]\n\n");
}

fn build_gemini_policy() -> String {
    let mut toml =
        String::from("# ai-jail bootstrap policy for Gemini CLI\n\n");

    push_gemini_tool_rule(&mut toml, "google_web_search", "allow");
    push_gemini_tool_rule(&mut toml, "web_fetch", "allow");

    for tool in [
        "list_directory",
        "read_file",
        "grep_search",
        "glob",
        "codebase_investigator",
        "write_file",
        "replace",
    ] {
        push_gemini_tool_rule(&mut toml, tool, "allow");
    }

    push_gemini_shell_rule(
        &mut toml,
        "allow",
        110,
        &gemini_command_prefixes(ALLOW),
    );
    push_gemini_shell_rule(
        &mut toml,
        "ask_user",
        120,
        &gemini_command_prefixes(ASK),
    );
    push_gemini_shell_rule(
        &mut toml,
        "deny",
        900,
        &gemini_command_prefixes(DENY),
    );

    toml
}

fn bootstrap_gemini(verbose: bool) -> Result<(), String> {
    let path = gemini_policy_path();
    ensure_regular_file_or_absent(&path)?;

    if backup_file(&path)? && verbose {
        output::verbose(&format!("Backed up {}", path.display()));
    }

    let content = build_gemini_policy();
    write_atomic(&path, &content)?;

    output::ok(&format!("Gemini: {}", path.display()));
    Ok(())
}

// ── Claude ───────────────────────────────────────────────────────

fn claude_config_path(claude_dir: Option<&Path>) -> PathBuf {
    match claude_dir {
        Some(dir) => dir.join("settings.json"),
        None => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".claude").join("settings.json")
        }
    }
}

fn build_claude_permissions() -> serde_json::Value {
    let allow: Vec<serde_json::Value> = ALLOW
        .iter()
        .map(|s| serde_json::Value::String(s.to_string()))
        .collect();
    let deny: Vec<serde_json::Value> = DENY
        .iter()
        .map(|s| serde_json::Value::String(s.to_string()))
        .collect();
    let ask: Vec<serde_json::Value> = ASK
        .iter()
        .map(|s| serde_json::Value::String(s.to_string()))
        .collect();

    serde_json::json!({
        "allow": allow,
        "deny": deny,
        "ask": ask,
        "defaultMode": "acceptEdits"
    })
}

fn bootstrap_claude(
    verbose: bool,
    claude_dir: Option<&Path>,
) -> Result<(), String> {
    let path = claude_config_path(claude_dir);
    ensure_regular_file_or_absent(&path)?;

    let mut root = if path.exists() {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&content)
            .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?
    } else {
        serde_json::json!({})
    };

    if backup_file(&path)? && verbose {
        output::verbose(&format!("Backed up {}", path.display()));
    }

    let obj = root
        .as_object_mut()
        .ok_or("Claude config is not a JSON object")?;
    obj.insert("permissions".to_string(), build_claude_permissions());

    let pretty = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize Claude config: {e}"))?;
    write_atomic(&path, &pretty)?;

    output::ok(&format!("Claude: {}", path.display()));
    Ok(())
}

// ── Codex ────────────────────────────────────────────────────────

fn codex_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".codex").join("config.toml")
}

fn bootstrap_codex(verbose: bool) -> Result<(), String> {
    let path = codex_config_path();
    ensure_regular_file_or_absent(&path)?;

    let mut root = if path.exists() {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        content
            .parse::<toml::Value>()
            .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    if backup_file(&path)? && verbose {
        output::verbose(&format!("Backed up {}", path.display()));
    }

    let table = root
        .as_table_mut()
        .ok_or("Codex config is not a TOML table")?;
    table.insert(
        "approval_policy".to_string(),
        toml::Value::String("on-request".to_string()),
    );

    let content = toml::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize Codex config: {e}"))?;
    write_atomic(&path, &content)?;

    output::ok(&format!("Codex: {}", path.display()));
    Ok(())
}

// ── OpenCode ─────────────────────────────────────────────────────

fn opencode_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("opencode")
        .join("opencode.json")
}

fn build_opencode_permissions() -> serde_json::Value {
    serde_json::json!({
        "bash": "allow",
        "edit": "allow",
        "write": "allow"
    })
}

fn bootstrap_opencode(verbose: bool) -> Result<(), String> {
    let path = opencode_config_path();
    ensure_regular_file_or_absent(&path)?;

    let mut root = if path.exists() {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&content)
            .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?
    } else {
        serde_json::json!({})
    };

    if backup_file(&path)? && verbose {
        output::verbose(&format!("Backed up {}", path.display()));
    }

    let obj = root
        .as_object_mut()
        .ok_or("OpenCode config is not a JSON object")?;
    obj.insert("permission".to_string(), build_opencode_permissions());

    let pretty = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize OpenCode config: {e}"))?;
    write_atomic(&path, &pretty)?;

    output::ok(&format!("OpenCode: {}", path.display()));
    Ok(())
}

// ── Crush ────────────────────────────────────────────────────────

fn crush_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("crush")
        .join("crush.json")
}

fn bootstrap_crush(verbose: bool) -> Result<(), String> {
    let path = crush_config_path();

    if path.exists() {
        ensure_regular_file_or_absent(&path)?;
        if backup_file(&path)? && verbose {
            output::verbose(&format!("Backed up {}", path.display()));
        }
        output::info(&format!(
            "Crush: no per-command permissions — ai-jail's sandbox is the security layer ({})",
            path.display()
        ));
    } else {
        output::info(
            "Crush: no config found, skipping (ai-jail's sandbox is the security layer)",
        );
    }

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Gemini TOML policy generation ─────────────────────────

    #[test]
    fn gemini_policy_generation() {
        let policy = build_gemini_policy();
        let parsed: toml::Value = policy.parse().unwrap();
        let rules = parsed
            .get("rule")
            .and_then(|value| value.as_array())
            .expect("Gemini policy should contain rule array");

        assert!(rules.iter().any(|rule| {
            rule.get("toolName").and_then(|value| value.as_str())
                == Some("google_web_search")
                && rule.get("decision").and_then(|value| value.as_str())
                    == Some("allow")
        }));
        assert!(rules.iter().any(|rule| {
            rule.get("toolName").and_then(|value| value.as_str())
                == Some("web_fetch")
                && rule.get("decision").and_then(|value| value.as_str())
                    == Some("allow")
        }));
        assert!(rules.iter().any(|rule| {
            rule.get("toolName").and_then(|value| value.as_str())
                == Some("run_shell_command")
                && rule.get("decision").and_then(|value| value.as_str())
                    == Some("ask_user")
        }));
    }

    #[test]
    fn gemini_command_prefixes_skip_leading_wildcards() {
        assert_eq!(
            gemini_command_prefix("Bash(git status *)").as_deref(),
            Some("git status")
        );
        assert_eq!(
            gemini_command_prefix("Bash(git remote -v*)").as_deref(),
            Some("git remote -v")
        );
        assert_eq!(gemini_command_prefix("Bash(pwd)").as_deref(), Some("pwd"));
        assert_eq!(gemini_command_prefix("Bash(* --version)"), None);
        assert_eq!(gemini_command_prefix("WebSearch"), None);
    }

    #[test]
    fn gemini_policy_does_not_emit_glob_prefixes() {
        let policy = build_gemini_policy();
        assert!(policy.contains("\"git status\""));
        assert!(policy.contains("\"git remote -v\""));
        assert!(policy.contains("\"sudo\""));
        assert!(!policy.contains("\"* --version\""));
        assert!(!policy.contains("\"git remote -v*\""));
    }
    use std::env;
    use std::fs;

    use std::sync::atomic::{AtomicU32, Ordering};
    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "ai-jail-bootstrap-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    // ── Permission list sanity ──────────────────────────────────

    #[test]
    fn deny_does_not_overlap_allow() {
        for d in DENY {
            assert!(
                !ALLOW.contains(d),
                "deny entry {d:?} also appears in allow list"
            );
        }
    }

    #[test]
    fn ask_does_not_overlap_deny() {
        for a in ASK {
            assert!(
                !DENY.contains(a),
                "ask entry {a:?} also appears in deny list"
            );
        }
    }

    #[test]
    fn ask_does_not_overlap_allow() {
        for a in ASK {
            assert!(
                !ALLOW.contains(a),
                "ask entry {a:?} also appears in allow list"
            );
        }
    }

    // ── Symlink rejection ────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() {
        let dir = test_dir();
        let victim = dir.join("victim.json");
        fs::write(&victim, "KEEP").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = ensure_regular_file_or_absent(&link);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("symlink"));

        // victim must be untouched
        assert_eq!(fs::read_to_string(&victim).unwrap(), "KEEP");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_symlink_source() {
        let dir = test_dir();
        let real = dir.join("real.json");
        fs::write(&real, "data").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = backup_file(&link);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("symlink"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_symlink_bak_target() {
        let dir = test_dir();
        let file = dir.join("config.json");
        fs::write(&file, "data").unwrap();
        let victim = dir.join("victim.txt");
        fs::write(&victim, "KEEP").unwrap();
        let bak = dir.join("config.json.bak");
        std::os::unix::fs::symlink(&victim, &bak).unwrap();

        let err = backup_file(&file);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("symlink"));

        // victim must be untouched
        assert_eq!(fs::read_to_string(&victim).unwrap(), "KEEP");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Atomic writes ───────────────────────────────────────────

    #[test]
    fn write_atomic_creates_file() {
        let dir = test_dir();
        let path = dir.join("new.json");
        write_atomic(&path, "content").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "content");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_creates_parent_dirs() {
        let dir = test_dir();
        let path = dir.join("sub").join("dir").join("file.json");
        write_atomic(&path, "nested").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nested");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_rejects_symlink_destination() {
        let dir = test_dir();
        let victim = dir.join("victim.txt");
        fs::write(&victim, "KEEP").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        // ensure_regular_file_or_absent catches this before write_atomic is called
        let err = ensure_regular_file_or_absent(&link);
        assert!(err.is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "KEEP");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Backup ──────────────────────────────────────────────────

    #[test]
    fn backup_creates_bak_file() {
        let dir = test_dir();
        let file = dir.join("test.json");
        fs::write(&file, b"original").unwrap();

        let backed_up = backup_file(&file).unwrap();
        assert!(backed_up);

        let bak = dir.join("test.json.bak");
        assert!(bak.exists());
        assert_eq!(fs::read_to_string(&bak).unwrap(), "original");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_overwrites_existing_bak() {
        let dir = test_dir();
        let file = dir.join("test.json");
        let bak = dir.join("test.json.bak");

        fs::write(&file, b"v1").unwrap();
        fs::write(&bak, b"old-backup").unwrap();

        backup_file(&file).unwrap();
        assert_eq!(fs::read_to_string(&bak).unwrap(), "v1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_returns_false_for_missing_file() {
        let dir = test_dir();
        let file = dir.join("nonexistent.json");
        let backed_up = backup_file(&file).unwrap();
        assert!(!backed_up);

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Claude permissions JSON ─────────────────────────────────

    #[test]
    fn claude_permissions_roundtrip() {
        let perms = build_claude_permissions();
        let obj = perms.as_object().unwrap();

        assert!(obj.contains_key("allow"));
        assert!(obj.contains_key("deny"));
        assert!(obj.contains_key("ask"));
        assert_eq!(obj["defaultMode"], "acceptEdits");

        let allow = obj["allow"].as_array().unwrap();
        assert!(allow.iter().any(|v| v == "Bash(git status *)"));
        assert!(allow.iter().any(|v| v == "Bash(rg *)"));
        assert!(allow.iter().any(|v| v == "WebSearch"));

        let deny = obj["deny"].as_array().unwrap();
        assert!(deny.iter().any(|v| v == "Bash(sudo *)"));

        let ask = obj["ask"].as_array().unwrap();
        assert!(ask.iter().any(|v| v == "Bash(git push *)"));
        assert!(ask.iter().any(|v| v == "Bash(rm *)"));
    }

    #[test]
    fn claude_merge_preserves_existing_keys() {
        let dir = test_dir();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let path = claude_dir.join("settings.json");

        // Write existing config with enabledPlugins
        let existing = serde_json::json!({
            "enabledPlugins": {
                "rust-analyzer-lsp@claude-plugins-official": true
            },
            "alwaysThinkingEnabled": true,
            "permissions": {
                "allow": ["Bash(echo old)"],
                "deny": [],
                "ask": []
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&existing).unwrap())
            .unwrap();

        // Simulate merge
        let content = fs::read_to_string(&path).unwrap();
        let mut root: serde_json::Value =
            serde_json::from_str(&content).unwrap();
        root.as_object_mut()
            .unwrap()
            .insert("permissions".to_string(), build_claude_permissions());

        let result = root.as_object().unwrap();

        // Permissions replaced
        let allow = result["permissions"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|v| v == "Bash(git status *)"));
        assert!(!allow.iter().any(|v| v == "Bash(echo old)"));

        // Other keys preserved
        assert!(result.contains_key("enabledPlugins"));
        assert_eq!(result["alwaysThinkingEnabled"], true);
        assert_eq!(
            result["enabledPlugins"]["rust-analyzer-lsp@claude-plugins-official"],
            true
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Codex TOML merge ────────────────────────────────────────

    #[test]
    fn codex_merge_preserves_existing_keys() {
        let dir = test_dir();
        let codex_dir = dir.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();
        let path = codex_dir.join("config.toml");

        let existing = r#"
model = "o3"
model_reasoning_effort = "high"

[projects.my-app]
sandbox_mode = "full"
"#;
        fs::write(&path, existing).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let mut root: toml::Value = content.parse().unwrap();
        root.as_table_mut().unwrap().insert(
            "approval_policy".to_string(),
            toml::Value::String("on-request".to_string()),
        );

        let table = root.as_table().unwrap();
        assert_eq!(table["approval_policy"].as_str().unwrap(), "on-request");
        assert_eq!(table["model"].as_str().unwrap(), "o3");
        assert_eq!(table["model_reasoning_effort"].as_str().unwrap(), "high");
        assert!(table.contains_key("projects"));
        assert!(table["projects"].as_table().unwrap().contains_key("my-app"));

        let _ = fs::remove_dir_all(&dir);
    }

    // ── OpenCode JSON merge ─────────────────────────────────────

    #[test]
    fn opencode_merge_preserves_existing_keys() {
        let dir = test_dir();
        let oc_dir = dir.join(".config").join("opencode");
        fs::create_dir_all(&oc_dir).unwrap();
        let path = oc_dir.join("opencode.json");

        let existing = serde_json::json!({
            "provider": "anthropic",
            "theme": "dark",
            "mcpServers": {
                "local": { "command": "mcp-server" }
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&existing).unwrap())
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let mut root: serde_json::Value =
            serde_json::from_str(&content).unwrap();
        root.as_object_mut()
            .unwrap()
            .insert("permission".to_string(), build_opencode_permissions());

        let result = root.as_object().unwrap();

        // Permission added
        assert_eq!(result["permission"]["bash"], "allow");
        assert_eq!(result["permission"]["edit"], "allow");
        assert_eq!(result["permission"]["write"], "allow");

        // Other keys preserved
        assert_eq!(result["provider"], "anthropic");
        assert_eq!(result["theme"], "dark");
        assert!(result.contains_key("mcpServers"));

        let _ = fs::remove_dir_all(&dir);
    }

    // ── claude_config_path with custom dir ─────────────────────

    #[test]
    fn claude_config_path_uses_custom_dir() {
        let custom = PathBuf::from("/home/user/.claude-example");
        let path = claude_config_path(Some(&custom));
        assert_eq!(
            path,
            PathBuf::from("/home/user/.claude-example/settings.json")
        );
    }

    #[test]
    fn claude_config_path_defaults_to_dot_claude() {
        let _env = ENV_LOCK.lock().unwrap();
        unsafe { env::set_var("HOME", "/home/testuser") };
        let path = claude_config_path(None);
        assert_eq!(path, PathBuf::from("/home/testuser/.claude/settings.json"));
        unsafe { env::remove_var("HOME") };
    }
}
