//! Phantom credential injection (Part 2 of the filtered-egress plan,
//! issue #135).
//!
//! The sandbox environment holds a *placeholder* for each bound secret;
//! the real value exists only in supervisor memory. The egress proxy
//! substitutes placeholder -> real only inside the request head of
//! absolute-form plain-HTTP requests that terminate at the binding's
//! allowlisted host. CONNECT tunnels stay opaque and untouched.
//!
//! A placeholder is `AIJAIL-PHANTOM-<16 hex>`: deterministic per launch
//! inputs, shaped so it can never collide with a real token, and
//! harmless when printed by dry-run or `ai-jail status`. It is not a
//! credential -- knowing it authorizes nothing.

/// One bound secret: the env var `key`, the `placeholder` the sandbox
/// sees, the `real` value that never leaves the supervisor, and the
/// allowlisted `host` whose terminated requests may carry it.
pub(crate) struct SecretBinding {
    pub key: String,
    pub placeholder: String,
    pub real: String,
    pub host: String,
}

impl SecretBinding {
    pub(crate) fn new(key: &str, real: &str, host: &str) -> Self {
        let digest =
            crate::audit::sha256_hex(format!("{key}:{real}").as_bytes());
        SecretBinding {
            key: key.to_string(),
            placeholder: format!("AIJAIL-PHANTOM-{}", &digest[..16]),
            real: real.to_string(),
            host: host.to_string(),
        }
    }
}

// The real value never appears in debug output either.
impl std::fmt::Debug for SecretBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBinding")
            .field("key", &self.key)
            .field("placeholder", &self.placeholder)
            .field("real", &"[redacted]")
            .field("host", &self.host)
            .finish()
    }
}

/// Byte-replace every placeholder occurrence in `head` (the request
/// line and headers only -- never the body) with the real value,
/// returning the rewritten bytes and the substitution count for
/// auditing. Multiple bindings stack; a placeholder that never appears
/// costs nothing.
pub(crate) fn rewrite_head(
    head: &[u8],
    bindings: &[SecretBinding],
) -> (Vec<u8>, usize) {
    let mut out = head.to_vec();
    let mut substitutions = 0;
    for binding in bindings {
        let (rewritten, count) = replace_all(
            &out,
            binding.placeholder.as_bytes(),
            binding.real.as_bytes(),
        );
        out = rewritten;
        substitutions += count;
    }
    (out, substitutions)
}

/// Replace every non-overlapping occurrence of `needle` in `haystack`
/// with `replacement`.
fn replace_all(
    haystack: &[u8],
    needle: &[u8],
    replacement: &[u8],
) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(haystack.len());
    let mut count = 0;
    let mut pos = 0;
    while let Some(at) = find_subslice(&haystack[pos..], needle) {
        out.extend_from_slice(&haystack[pos..pos + at]);
        out.extend_from_slice(replacement);
        pos += at + needle.len();
        count += 1;
    }
    out.extend_from_slice(&haystack[pos..]);
    (out, count)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SecretBinding {
        SecretBinding::new(
            "ANTHROPIC_API_KEY",
            "sk-ant-real",
            "api.anthropic.com",
        )
    }

    #[test]
    fn placeholder_is_deterministic_and_shaped() {
        let a = SecretBinding::new("KEY", "real-value", "example.com");
        let b = SecretBinding::new("KEY", "real-value", "example.com");
        let c = SecretBinding::new("KEY", "other-value", "example.com");
        assert_eq!(a.placeholder, b.placeholder);
        assert_ne!(a.placeholder, c.placeholder);
        assert!(a.placeholder.starts_with("AIJAIL-PHANTOM-"));
        assert_eq!(a.placeholder.len(), "AIJAIL-PHANTOM-".len() + 16);
        // Never leaks the real value's prefix or length.
        assert!(!a.placeholder.contains("real"));
        assert!(!a.placeholder.contains("-value"));
    }

    #[test]
    fn rewrite_head_substitutes_every_occurrence() {
        let b = binding();
        let head = format!(
            "POST /v1/messages HTTP/1.1\r\n\
             x-api-key: {}\r\n\
             authorization: Bearer {}\r\n\
             host: api.anthropic.com\r\n\
             \r\n",
            b.placeholder, b.placeholder
        );
        let (out, count) = rewrite_head(head.as_bytes(), &[binding()]);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(count, 2);
        assert!(!out.contains(&b.placeholder));
        assert_eq!(out.matches("sk-ant-real").count(), 2);
    }

    #[test]
    fn rewrite_head_noop_without_placeholder() {
        let head = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        let (out, count) = rewrite_head(head, &[binding()]);
        assert_eq!(count, 0);
        assert_eq!(out, head);
    }

    #[test]
    fn rewrite_head_treats_head_as_bytes() {
        // A placeholder straddling a multibyte boundary still matches;
        // non-UTF-8 bytes elsewhere pass through untouched.
        let b = binding();
        let mut head = b"GET / HTTP/1.1\r\nx-k: ".to_vec();
        head.extend_from_slice(&[0xff, 0xfe]);
        head.extend_from_slice(b.placeholder.as_bytes());
        head.extend_from_slice(b"\r\n\r\n");
        let (out, count) = rewrite_head(&head, &[binding()]);
        assert_eq!(count, 1);
        assert!(out.windows(2).any(|w| w == [0xff, 0xfe]));
        assert!(String::from_utf8_lossy(&out).contains("sk-ant-real"));
    }
}
