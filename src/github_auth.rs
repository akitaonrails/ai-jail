//! Launch-only GitHub CLI authentication for the active github.com account.

use crate::config::{self, Config};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TOKEN_BYTES: u64 = 4096;
const LOOKUP_WARNING: &str = "GitHub token unavailable from host gh; mounted configuration may still authenticate";

pub struct GitHubSetup {
    pub config_dir: Option<PathBuf>,
    pub warning: Option<&'static str>,
}

pub fn prepare(config: &mut Config, cwd: &Path, dry_run: bool) -> GitHubSetup {
    let host_env: Vec<(String, String)> = std::env::vars().collect();
    prepare_with(config, cwd, dry_run, &host_env, gh_auth_token)
}

fn env_value<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn has_env_entry(config: &Config, name: &str) -> bool {
    config.env_pass.iter().any(|entry| {
        config::parse_env_entry(entry)
            .is_ok_and(|(entry_name, _)| entry_name == name)
    })
}

fn effective_env(
    config: &Config,
    host_env: &[(String, String)],
) -> Vec<(String, String)> {
    if config.inherit_env_enabled() {
        let mut env = host_env.to_vec();
        config::apply_env_pass(&mut env, &config.env_pass, host_env);
        env
    } else {
        config::filtered_child_env(&config.env_pass, host_env)
    }
}

fn prepare_with(
    config: &mut Config,
    cwd: &Path,
    dry_run: bool,
    host_env: &[(String, String)],
    resolve: impl FnOnce(&Path) -> Result<String, ()>,
) -> GitHubSetup {
    if !config.github_enabled() || config.lockdown_enabled() {
        return GitHubSetup {
            config_dir: None,
            warning: None,
        };
    }

    // GH_CONFIG_DIR is not in the default child allowlist. Forward the host
    // setting unless the user explicitly chose a different one for the jail.
    if !has_env_entry(config, "GH_CONFIG_DIR")
        && env_value(host_env, "GH_CONFIG_DIR").is_some_and(|v| !v.is_empty())
    {
        config.env_pass.push("GH_CONFIG_DIR".into());
    }
    let child_env = effective_env(config, host_env);
    let home = env_value(host_env, "HOME").unwrap_or("/tmp");
    let dir = if let Some(value) =
        env_value(&child_env, "GH_CONFIG_DIR").filter(|v| !v.is_empty())
    {
        PathBuf::from(value)
    } else if let Some(value) =
        env_value(&child_env, "XDG_CONFIG_HOME").filter(|v| !v.is_empty())
    {
        PathBuf::from(value).join("gh")
    } else {
        PathBuf::from(home).join(".config/gh")
    };
    let dir = if dir.is_absolute() {
        dir
    } else {
        cwd.join(dir)
    };
    // Make the host lookup and the jailed gh use the same exact directory,
    // including when a relative override was provided by the user.
    let Some(dir_str) = dir.to_str() else {
        return GitHubSetup {
            config_dir: None,
            warning: Some("GitHub config path is not valid UTF-8"),
        };
    };
    config.env_pass.push(format!("GH_CONFIG_DIR={dir_str}"));

    // An explicit launch credential skips the host lookup, including an
    // explicitly empty value. Precedence between the two names is left to
    // gh: under --inherit-env an inherited GH_TOKEN still outranks an
    // explicit GITHUB_TOKEN.
    if has_env_entry(config, "GH_TOKEN")
        || has_env_entry(config, "GITHUB_TOKEN")
    {
        return GitHubSetup {
            config_dir: Some(dir),
            warning: None,
        };
    }
    if dry_run {
        return GitHubSetup {
            config_dir: Some(dir),
            warning: None,
        };
    }
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if env_value(host_env, name).is_some_and(|value| !value.is_empty()) {
            if !config.inherit_env_enabled() {
                config.env_pass.push(name.to_string());
            }
            return GitHubSetup {
                config_dir: Some(dir),
                warning: None,
            };
        }
    }
    match resolve(&dir).and_then(valid_token) {
        Ok(token) => {
            config.env_pass.push(format!("GH_TOKEN={token}"));
            GitHubSetup {
                config_dir: Some(dir),
                warning: None,
            }
        }
        Err(()) => GitHubSetup {
            config_dir: Some(dir),
            warning: Some(LOOKUP_WARNING),
        },
    }
}

fn valid_token(output: String) -> Result<String, ()> {
    let token = output.trim_end_matches(['\r', '\n']);
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES as usize
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(());
    }
    Ok(token.to_string())
}

fn gh_auth_token(config_dir: &Path) -> Result<String, ()> {
    gh_auth_token_from(Path::new("gh"), config_dir, GH_TIMEOUT)
}

fn gh_auth_token_from(
    executable: &Path,
    config_dir: &Path,
    timeout: Duration,
) -> Result<String, ()> {
    let mut child = Command::new(executable)
        .args(["auth", "token", "--hostname", "github.com"])
        .env("GH_CONFIG_DIR", config_dir)
        .env("GH_PROMPT_DISABLED", "1")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| ())?;

    let mut stdout = child.stdout.take().ok_or(())?;
    // Drain while waiting: a full pipe can prevent gh from exiting, and a
    // helper retaining stdout must not extend the lookup past the deadline.
    let fd = stdout.as_raw_fd();
    // SAFETY: fd is the live pipe owned by stdout; fcntl only changes its
    // blocking flag in this parent process.
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
    if flags < 0
        || unsafe {
            nix::libc::fcntl(
                fd,
                nix::libc::F_SETFL,
                flags | nix::libc::O_NONBLOCK,
            )
        } < 0
    {
        stop_child(&mut child);
        return Err(());
    }

    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut status = None;
    let mut eof = false;
    loop {
        if !eof {
            let mut chunk = [0_u8; 1024];
            match stdout.read(&mut chunk) {
                Ok(0) => eof = true,
                Ok(n) => {
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.len() > MAX_TOKEN_BYTES as usize + 2 {
                        stop_child(&mut child);
                        return Err(());
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Err(_) => {
                    stop_child(&mut child);
                    return Err(());
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(result) => status = result,
                Err(_) => {
                    stop_child(&mut child);
                    return Err(());
                }
            }
        }
        if status.is_some_and(|status| !status.success()) {
            return Err(());
        }
        if status.is_some() && eof {
            return String::from_utf8(bytes).map_err(|_| ());
        }
        if start.elapsed() >= timeout {
            if status.is_none() {
                stop_child(&mut child);
            }
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::{Path, PathBuf};

    #[test]
    fn keyring_token_reaches_the_child_when_github_is_enabled() {
        let mut config = Config {
            github: Some(true),
            ..Config::default()
        };
        let host_env = vec![("HOME".to_string(), "/home/test".to_string())];

        let setup = prepare_with(
            &mut config,
            Path::new("/work"),
            false,
            &host_env,
            |_| Ok("ghp_synthetic_token".to_string()),
        );
        let child_env =
            crate::config::filtered_child_env(&config.env_pass, &host_env);

        assert_eq!(
            setup.config_dir,
            Some(PathBuf::from("/home/test/.config/gh"))
        );
        assert_eq!(setup.warning, None);
        assert!(child_env.iter().any(|(name, value)| {
            name == "GH_TOKEN" && value == "ghp_synthetic_token"
        }));
    }

    #[test]
    fn dry_run_never_forwards_a_host_github_token() {
        let mut config = Config {
            github: Some(true),
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".to_string(), "/home/test".to_string()),
            ("GH_TOKEN".to_string(), "ghp_synthetic_token".to_string()),
        ];

        let setup = prepare_with(
            &mut config,
            Path::new("/work"),
            true,
            &host_env,
            |_| panic!("dry-run must not look up a token"),
        );

        assert_eq!(setup.warning, None);
        assert!(!config.env_pass.iter().any(|entry| entry == "GH_TOKEN"));
        assert!(
            !config
                .env_pass
                .iter()
                .any(|entry| entry.contains("ghp_synthetic_token"))
        );
    }

    #[test]
    fn explicit_github_token_keeps_gh_precedence_under_inherit_env() {
        let mut config = Config {
            github: Some(true),
            inherit_env: Some(true),
            env_pass: vec!["GITHUB_TOKEN=explicit_token".into()],
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".to_string(), "/home/test".to_string()),
            ("GH_TOKEN".to_string(), "host_token".to_string()),
        ];

        prepare_with(&mut config, Path::new("/work"), false, &host_env, |_| {
            panic!("explicit token must skip gh lookup")
        });
        let child_env = effective_env(&config, &host_env);

        assert_eq!(env_value(&child_env, "GH_TOKEN"), Some("host_token"));
        assert_eq!(
            env_value(&child_env, "GITHUB_TOKEN"),
            Some("explicit_token")
        );
        assert!(
            !config
                .env_pass
                .iter()
                .any(|entry| entry.starts_with("GH_TOKEN="))
        );
    }

    #[test]
    fn secret_bound_github_token_is_not_copied_under_another_name() {
        let mut config = Config {
            github: Some(true),
            inherit_env: Some(true),
            env_pass: vec!["GITHUB_TOKEN=bound_secret".into()],
            secret_hosts: [("GITHUB_TOKEN".into(), "api.github.com".into())]
                .into_iter()
                .collect(),
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".into(), "/home/test".into()),
            ("GH_TOKEN".into(), "different_host_token".into()),
        ];

        prepare_with(&mut config, Path::new("/work"), false, &host_env, |_| {
            panic!("explicit token must skip gh lookup")
        });

        assert!(
            !config
                .env_pass
                .iter()
                .any(|entry| entry == "GH_TOKEN=bound_secret")
        );
    }

    #[test]
    fn disabled_and_lockdown_never_read_or_forward_github_credentials() {
        for config in [
            Config::default(),
            Config {
                github: Some(false),
                ..Config::default()
            },
            Config {
                github: Some(true),
                lockdown: Some(true),
                ..Config::default()
            },
        ] {
            let mut config = config;
            let setup = prepare_with(
                &mut config,
                Path::new("/work"),
                false,
                &[("GH_TOKEN".into(), "host_token".into())],
                |_| panic!("disabled sharing must not invoke gh"),
            );
            assert!(setup.config_dir.is_none());
            assert!(config.env_pass.is_empty());
        }
    }

    #[test]
    fn host_token_precedence_follows_gh_and_skips_keyring_lookup() {
        let mut config = Config {
            github: Some(true),
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".into(), "/home/test".into()),
            ("GITHUB_TOKEN".into(), "second_choice".into()),
            ("GH_TOKEN".into(), "first_choice".into()),
        ];
        prepare_with(&mut config, Path::new("/work"), false, &host_env, |_| {
            panic!("host token must skip gh lookup")
        });
        let child_env = effective_env(&config, &host_env);
        assert_eq!(env_value(&child_env, "GH_TOKEN"), Some("first_choice"));
        assert_eq!(env_value(&child_env, "GITHUB_TOKEN"), None);
    }

    #[test]
    fn github_config_dir_overrides_xdg_and_is_forwarded() {
        let mut config = Config {
            github: Some(true),
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".into(), "/home/test".into()),
            ("XDG_CONFIG_HOME".into(), "/xdg".into()),
            ("GH_CONFIG_DIR".into(), "/custom/gh".into()),
        ];
        let setup = prepare_with(
            &mut config,
            Path::new("/work"),
            true,
            &host_env,
            |_| panic!("dry-run must not invoke gh"),
        );
        assert_eq!(setup.config_dir, Some(PathBuf::from("/custom/gh")));
        let child_env = effective_env(&config, &host_env);
        assert_eq!(env_value(&child_env, "GH_CONFIG_DIR"), Some("/custom/gh"));
    }

    #[test]
    fn xdg_config_home_selects_gh_subdirectory() {
        let mut config = Config {
            github: Some(true),
            ..Config::default()
        };
        let host_env = vec![
            ("HOME".into(), "/home/test".into()),
            ("XDG_CONFIG_HOME".into(), "/xdg".into()),
        ];
        let setup = prepare_with(
            &mut config,
            Path::new("/work"),
            true,
            &host_env,
            |_| panic!("dry-run must not invoke gh"),
        );
        assert_eq!(setup.config_dir, Some(PathBuf::from("/xdg/gh")));
    }

    #[test]
    fn failed_or_invalid_lookup_reports_only_a_sanitized_warning() {
        for result in [
            Err(()),
            Ok(String::new()),
            Ok("token with space".into()),
            Ok("token\nsecond_line".into()),
            Ok("x".repeat(4097)),
        ] {
            let mut config = Config {
                github: Some(true),
                ..Config::default()
            };
            let setup = prepare_with(
                &mut config,
                Path::new("/work"),
                false,
                &[("HOME".into(), "/home/test".into())],
                |_| result,
            );
            assert_eq!(setup.warning, Some(LOOKUP_WARNING));
            assert!(
                !config
                    .env_pass
                    .iter()
                    .any(|entry| entry.starts_with("GH_TOKEN="))
            );
            assert!(!LOOKUP_WARNING.contains("token with space"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn host_gh_lookup_has_a_bounded_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let script = std::env::temp_dir().join(format!(
            "ai-jail-gh-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&script, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let started = Instant::now();

        let result = gh_auth_token_from(
            &script,
            Path::new("/tmp/gh-config"),
            Duration::from_millis(100),
        );

        std::fs::remove_file(&script).unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn host_gh_lookup_selects_only_active_github_com_token() {
        use std::os::unix::fs::PermissionsExt;

        let script = std::env::temp_dir().join(format!(
            "ai-jail-gh-args-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &script,
            r#"#!/bin/sh
[ "$#" = 4 ] && [ "$1" = auth ] && [ "$2" = token ] &&
    [ "$3" = --hostname ] && [ "$4" = github.com ] &&
    [ "$GH_CONFIG_DIR" = /tmp/gh-config ] || exit 9
printf 'ghp_synthetic_token\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let result = gh_auth_token_from(
            &script,
            Path::new("/tmp/gh-config"),
            Duration::from_secs(1),
        );

        std::fs::remove_file(&script).unwrap();
        assert_eq!(result, Ok("ghp_synthetic_token\n".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn host_gh_lookup_timeout_covers_stdout_after_process_exit() {
        use std::os::unix::fs::PermissionsExt;

        let script = std::env::temp_dir().join(format!(
            "ai-jail-gh-pipe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &script,
            "#!/bin/sh\nsleep 1 &\nprintf 'ghp_synthetic_token\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let started = Instant::now();

        let result = gh_auth_token_from(
            &script,
            Path::new("/tmp/gh-config"),
            Duration::from_millis(100),
        );

        std::fs::remove_file(&script).unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
