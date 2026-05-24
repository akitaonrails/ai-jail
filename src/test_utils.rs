use std::ffi::{OsStr, OsString};
use std::sync::Mutex;

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct EnvVarGuard {
    key: &'static str,
    saved: Option<OsString>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let saved = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, saved }
    }

    pub(crate) fn remove(key: &'static str) -> Self {
        let saved = std::env::var_os(key);
        unsafe { std::env::remove_var(key) };
        Self { key, saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(value) = self.saved.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}
