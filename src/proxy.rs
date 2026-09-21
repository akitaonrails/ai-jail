//! HTTP CONNECT forward-proxy core for filtered egress (phase 1 of
//! docs/connect-proxy-plan.md).
//!
//! The proxy runs as threads inside the outer, unrestricted ai-jail
//! supervisor process. Kernel fencing (private netns on Linux, seatbelt
//! endpoint rules on macOS) leaves the sandbox no route off loopback
//! except this proxy; the proxy only decides which CONNECT targets an
//! already-fenced process may reach. Phases 2-3 wire the CLI/config
//! surface and the sandbox mounts; this module is the self-contained,
//! std-only core.
//!
//! Lifecycle: accept loops run on dedicated threads that block in
//! `accept()` forever. There is deliberately no graceful shutdown -- the
//! supervisor outlives the child and then exits, and process exit reaps
//! the threads, the same lifecycle the supervisor already has for
//! reaping. `Proxy`'s Drop only unlinks the Unix socket file.

// The Unix-socket listener, in-sandbox bridge, and related constants are
// only consumed on Linux; on macOS they are unused, so the module keeps a
// dead_code allowance for that target.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs,
};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Hard cap on the CONNECT request (request line plus headers).
const REQUEST_CAP: usize = 8 * 1024;

const REPLY_OK: &str = "HTTP/1.1 200 Connection Established\r\n\r\n";

/// Proxy configuration. Phase 2 builds this from the effective config.
pub(crate) struct ProxyConfig {
    /// Allowed CONNECT targets. An entry `example.com` matches
    /// `example.com` and any subdomain of it; IP-literal entries match
    /// only themselves. Matching is case-insensitive and trailing-dot
    /// normalized (see [`allowlist_matches`]).
    pub allowlist: Vec<String>,
    /// Maximum simultaneous connections; excess is refused with 503.
    pub max_connections: usize,
    /// Timeout for dialing the CONNECT target.
    pub connect_timeout: Duration,
    /// Read timeout on the client while waiting for the request
    /// (slowloris guard). Established tunnels have no idle timeout.
    pub read_timeout: Duration,
    /// Test-only escape hatch: skip the SSRF address-range check so
    /// tests can CONNECT to loopback fixture servers. Must never become
    /// settable from config or CLI in later phases.
    pub danger_allow_private: bool,
    /// Shared audit-log handle (phase 5): when the launch audit log is
    /// on, each CONNECT appends a verdict record. The file is
    /// supervisor-side; the sandbox never sees it.
    pub audit: Option<Arc<crate::audit::AuditLog>>,
}

impl ProxyConfig {
    pub(crate) fn new(allowlist: Vec<String>) -> Self {
        ProxyConfig {
            allowlist,
            max_connections: 256,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(10),
            danger_allow_private: false,
            audit: None,
        }
    }
}

/// Running proxy handle. Reports where the listeners are; see the
/// module docs for the (process-exit) lifecycle.
pub(crate) struct Proxy {
    port: u16,
    unix_path: Option<PathBuf>,
}

impl Proxy {
    /// Bind a TCP listener on 127.0.0.1:0 (random port) and, when
    /// `unix_socket_path` is given, a Unix listener at that path
    /// (mode 0600), serving both on dedicated accept threads.
    pub(crate) fn start(
        config: ProxyConfig,
        unix_socket_path: Option<&Path>,
    ) -> io::Result<Proxy> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Shared {
            config,
            active: AtomicUsize::new(0),
        });

        let tcp_shared = Arc::clone(&shared);
        thread::spawn(move || {
            for stream in listener.incoming().map_while(Result::ok) {
                let shared = Arc::clone(&tcp_shared);
                thread::spawn(move || handle_conn(stream, shared));
            }
        });

        let unix_path = if let Some(path) = unix_socket_path {
            // A stale socket from a previous launch would fail the bind.
            let _ = std::fs::remove_file(path);
            let unix_listener = UnixListener::bind(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o600),
            )?;
            let unix_shared = Arc::clone(&shared);
            thread::spawn(move || {
                for stream in unix_listener.incoming().map_while(Result::ok) {
                    let shared = Arc::clone(&unix_shared);
                    thread::spawn(move || handle_conn(stream, shared));
                }
            });
            Some(path.to_path_buf())
        } else {
            None
        };

        Ok(Proxy { port, unix_path })
    }

    /// Loopback TCP port the proxy listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Unix socket path, when one was bound.
    pub(crate) fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(path) = &self.unix_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct Shared {
    config: ProxyConfig,
    active: AtomicUsize,
}

/// Decrements the active-connection count when the handler returns.
struct ActiveGuard(Arc<Shared>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A duplex byte stream the proxy or bridge can relay: `TcpStream` from
/// the loopback listeners, `UnixStream` from the Unix listener and the
/// bridge's upstream side.
pub(crate) trait ClientStream: Read + Write + Send + 'static {
    fn try_clone_stream(&self) -> io::Result<Self>
    where
        Self: Sized;
    fn shutdown_write(&self) -> io::Result<()>;
    fn shutdown_both(&self) -> io::Result<()>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

impl ClientStream for TcpStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
}

impl ClientStream for UnixStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }
}

/// Rejection reasons, mapped to minimal HTTP error replies. Replies are
/// header-only and name the class of the problem, never the resolved IP.
#[derive(Debug)]
enum Reject {
    BadRequest,
    MethodNotAllowed,
    TooLarge,
    ForbiddenHost,
    ForbiddenRange,
    BadGateway,
    Unavailable,
}

impl Reject {
    fn status(&self) -> (u16, &'static str) {
        match self {
            Reject::BadRequest => (400, "Bad Request"),
            Reject::MethodNotAllowed => (405, "Method Not Allowed"),
            Reject::TooLarge => (431, "Request Header Fields Too Large"),
            Reject::ForbiddenHost => (403, "Forbidden"),
            Reject::ForbiddenRange => (403, "Forbidden address range"),
            Reject::BadGateway => (502, "Bad Gateway"),
            Reject::Unavailable => (503, "Service Unavailable"),
        }
    }
}

fn handle_conn<S: ClientStream>(mut client: S, shared: Arc<Shared>) {
    let active = shared.active.fetch_add(1, Ordering::SeqCst) + 1;
    let _guard = ActiveGuard(Arc::clone(&shared));
    if active > shared.config.max_connections {
        reject(&mut client, &Reject::Unavailable);
        return;
    }

    let _ = client.set_read_timeout(Some(shared.config.read_timeout));
    let request = match read_request(&mut client, REQUEST_CAP) {
        Ok(request) => request,
        Err(ReadFail::TooLarge) => {
            reject(&mut client, &Reject::TooLarge);
            return;
        }
        // Slowloris timeout or a reset peer: close without a reply.
        Err(ReadFail::Io) => return,
    };
    let _ = client.set_read_timeout(None);

    let (host, port) = match parse_request(&request) {
        Ok(target) => target,
        Err(why) => {
            reject(&mut client, &why);
            return;
        }
    };

    if !allowlist_matches(&shared.config.allowlist, &host) {
        audit_verdict(&shared, &host, port, "deny", "not-in-allowlist");
        reject(&mut client, &Reject::ForbiddenHost);
        return;
    }

    let upstream = match connect_upstream(&host, port, &shared.config) {
        Ok(stream) => stream,
        Err(why) => {
            // Only policy refusals are verdicts; a failed resolution or
            // dial is an upstream error, not a deny.
            if matches!(why, Reject::ForbiddenRange) {
                audit_verdict(
                    &shared,
                    &host,
                    port,
                    "deny",
                    "forbidden-address-range",
                );
            }
            reject(&mut client, &why);
            return;
        }
    };
    audit_verdict(&shared, &host, port, "allow", "in-allowlist");

    if client.write_all(REPLY_OK.as_bytes()).is_err() {
        return;
    }
    relay(client, upstream);
}

/// Append a CONNECT verdict record when the launch audit log is on.
fn audit_verdict(
    shared: &Shared,
    host: &str,
    port: u16,
    verdict: &str,
    reason: &str,
) {
    if let Some(log) = &shared.config.audit {
        log.record(crate::audit::connect_record(host, port, verdict, reason));
    }
}

fn reject<S: ClientStream>(stream: &mut S, why: &Reject) {
    let (code, reason) = why.status();
    let reply = format!("HTTP/1.1 {code} {reason}\r\n\r\n");
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.shutdown_both();
}

enum ReadFail {
    TooLarge,
    Io,
}

/// Read one CONNECT request through its `\r\n\r\n` terminator, capped
/// at `cap` bytes. Headers after the request line are consumed but
/// ignored -- nothing beyond the CONNECT line is ever forwarded.
fn read_request<S: ClientStream>(
    stream: &mut S,
    cap: usize,
) -> Result<Vec<u8>, ReadFail> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let n = stream.read(&mut chunk).map_err(|_| ReadFail::Io)?;
        if n == 0 {
            return Err(ReadFail::Io);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > cap {
            return Err(ReadFail::TooLarge);
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

/// Parse `CONNECT authority HTTP/1.x` strictly: exactly three
/// space-separated tokens, an HTTP/1.x version token, and a well-formed
/// authority. Anything else is a 400; a well-formed line with another
/// method is a 405.
fn parse_request(buf: &[u8]) -> Result<(String, u16), Reject> {
    let end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Reject::BadRequest)?;
    let head = &buf[..end];
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| Reject::BadRequest)?;

    let mut parts = line.split(' ');
    let method = parts.next().ok_or(Reject::BadRequest)?;
    let authority = parts.next().ok_or(Reject::BadRequest)?;
    let version = parts.next().ok_or(Reject::BadRequest)?;
    if parts.next().is_some() || authority.is_empty() {
        return Err(Reject::BadRequest);
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Reject::BadRequest);
    }
    if method != "CONNECT" {
        return Err(Reject::MethodNotAllowed);
    }
    parse_authority(authority)
}

/// Split an authority into (host, port). CONNECT authorities always
/// carry a port: a missing, zero, or non-numeric port is malformed.
/// IPv6 literals must use the bracket form (`[::1]:443`); a bare
/// IPv6 literal is ambiguous with the port separator and is rejected.
fn parse_authority(authority: &str) -> Result<(String, u16), Reject> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(Reject::BadRequest)?;
        let host = &rest[..close];
        let port = rest[close + 1..]
            .strip_prefix(':')
            .ok_or(Reject::BadRequest)?;
        // Brackets are only meaningful around an IPv6 literal.
        host.parse::<Ipv6Addr>().map_err(|_| Reject::BadRequest)?;
        let port = parse_port(port)?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = authority.rsplit_once(':').ok_or(Reject::BadRequest)?;
    if host.is_empty() || host.contains(':') {
        return Err(Reject::BadRequest);
    }
    Ok((host.to_string(), parse_port(port)?))
}

fn parse_port(port: &str) -> Result<u16, Reject> {
    let port: u16 = port.parse().map_err(|_| Reject::BadRequest)?;
    if port == 0 {
        return Err(Reject::BadRequest);
    }
    Ok(port)
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_lowercase()
}

/// Allowlist semantics: an entry `example.com` matches `example.com`
/// itself and any subdomain (`api.example.com`), so `notexample.com`
/// and `example.com.evil.com` never match it. Entries that are IP
/// literals match only that exact IP -- no suffix rule for addresses.
/// Matching is case-insensitive and trailing-dot normalized on both
/// sides.
pub(crate) fn allowlist_matches(allowlist: &[String], host: &str) -> bool {
    let host = normalize_host(host);
    allowlist.iter().any(|entry| {
        let entry = normalize_host(entry);
        if let Ok(entry_ip) = entry.parse::<IpAddr>() {
            return host.parse::<IpAddr>().is_ok_and(|ip| ip == entry_ip);
        }
        if host == entry {
            return true;
        }
        host.len() > entry.len()
            && host.ends_with(&entry)
            && host.as_bytes()[host.len() - entry.len() - 1] == b'.'
    })
}

/// SSRF guard: the refused class of an address, or None if dialable.
/// The class names a range, never the specific address, so it is safe
/// to surface and to log.
fn denied_class(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => denied_class_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 answers inherit the v4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return denied_class_v4(&mapped);
            }
            if v6.is_unspecified() {
                Some("unspecified address")
            } else if v6.is_loopback() {
                Some("loopback address")
            } else if v6.is_multicast() {
                Some("multicast address")
            } else if v6.is_unicast_link_local() {
                Some("link-local address")
            } else if v6.is_unique_local() {
                Some("private address range")
            } else if v6.to_ipv4().is_some() {
                // Deprecated v4-compatible ::/96 (e.g. ::10.0.0.1);
                // :: and ::1 are already handled above.
                Some("v4-compatible address")
            } else {
                None
            }
        }
    }
}

fn denied_class_v4(ip: &Ipv4Addr) -> Option<&'static str> {
    if ip.is_unspecified() {
        Some("unspecified address")
    } else if ip.is_loopback() {
        Some("loopback address")
    } else if *ip == Ipv4Addr::new(169, 254, 169, 254) {
        // Cloud instance metadata; also inside link-local, but worth
        // its own class name.
        Some("cloud metadata address")
    } else if ip.is_link_local() {
        Some("link-local address")
    } else if ip.is_private() {
        Some("private address range")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64 {
        Some("carrier-grade NAT address range")
    } else {
        None
    }
}

/// DNS pinning: resolve once, filter the answer set through the SSRF
/// guard, then `connect_timeout` to a surviving address. Never resolve
/// twice -- checking one answer set and dialing another is the DNS
/// rebinding TOCTOU this design exists to kill. IP literals skip DNS
/// (ToSocketAddrs parses them directly) but still get the range check.
fn connect_upstream(
    host: &str,
    port: u16,
    config: &ProxyConfig,
) -> Result<TcpStream, Reject> {
    let addrs = match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return Err(Reject::BadGateway),
    };
    let mut dialable = false;
    for addr in addrs {
        if !config.danger_allow_private
            && let Some(class) = denied_class(&addr.ip())
        {
            // The caller records one deny verdict for the request; the
            // per-answer class detail stays internal to this filter.
            let _ = class;
            continue;
        }
        dialable = true;
        if let Ok(stream) =
            TcpStream::connect_timeout(&addr, config.connect_timeout)
        {
            return Ok(stream);
        }
    }
    // Every answer filtered out is a policy refusal; answers that
    // refused or timed out the dial are upstream failures.
    Err(if dialable {
        Reject::BadGateway
    } else {
        Reject::ForbiddenRange
    })
}

/// Relay bytes both ways until both directions end. On read-EOF the
/// opposite stream gets shutdown(Write) so a half-close propagates
/// (truncated uploads are the classic CONNECT bug). Both pumps are
/// joined -- joining only the first would leak the other thread.
/// Established tunnels have no idle timeout: agent SSE streams are
/// long-lived.
///
/// Shared with the in-sandbox bridge (phase 3): the proxy relays
/// client<->TCP-target, the bridge relays client<->Unix-socket.
pub(crate) fn relay<C: ClientStream, U: ClientStream>(client: C, upstream: U) {
    let (mut client_reader, mut upstream_reader) =
        match (client.try_clone_stream(), upstream.try_clone_stream()) {
            (Ok(reader), Ok(upstream)) => (reader, upstream),
            _ => return,
        };
    let mut client_writer = client;
    let mut upstream_writer = upstream;

    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown_write();
    });
    let down = thread::spawn(move || {
        let _ = io::copy(&mut upstream_reader, &mut client_writer);
        let _ = client_writer.shutdown_write();
    });
    let _ = up.join();
    let _ = down.join();
}

/// Fixed loopback port the in-sandbox bridge listens on (Linux,
/// filtered egress). The port lives inside the private netns, so it
/// cannot collide with anything on the host, and the proxy's own TCP
/// port is irrelevant in there -- the bridge is the only endpoint the
/// child can reach.
pub(crate) const BRIDGE_PORT: u16 = 15919;

/// Fixed path inside the sandbox where the outer proxy's Unix socket is
/// bind-mounted (Linux, filtered egress). Lives under /tmp, which is
/// always a fresh tmpfs in the sandbox.
pub(crate) const IN_SANDBOX_SOCK_PATH: &str = "/tmp/.ai-jail-proxy.sock";

/// Host-side nonce path for the proxy's Unix socket of this launch.
pub(crate) fn default_socket_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "ai-jail-proxy.{}.{}.sock",
        std::process::id(),
        nonce
    ))
}

/// The forced proxy environment for a filtered-egress sandbox
/// (post-`--clearenv`, so nothing else can precede it). `no_proxy` is
/// emptied explicitly: an inherited exclusion would route around the
/// proxy straight into the netns wall.
pub(crate) fn env_vars(port: u16) -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{port}");
    let mut vars: Vec<(String, String)> = [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ]
    .iter()
    .map(|key| ((*key).to_string(), url.clone()))
    .collect();
    vars.push(("no_proxy".to_string(), String::new()));
    vars.push(("NO_PROXY".to_string(), String::new()));
    vars
}

/// The in-sandbox bridge end of filtered egress (Linux, phase 3 of
/// docs/connect-proxy-plan.md): listen on 127.0.0.1:<port> inside the
/// private netns and pump each accepted connection to the outer proxy's
/// bind-mounted Unix socket. Connecting to a Unix socket is a
/// filesystem operation, so it does not cross network namespaces.
///
/// Runs unrestricted by design: the landlock wrapper spawns this mode
/// before apply_landlock/apply_seccomp, and those only restrict the
/// caller and its future children.
pub(crate) fn run_bridge(port: u16, socket: &Path) -> Result<(), String> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
            format!("proxy bridge cannot bind 127.0.0.1:{port}: {e}")
        })?;
    for client in listener.incoming().map_while(Result::ok) {
        let socket = socket.to_path_buf();
        thread::spawn(move || {
            if let Ok(upstream) = UnixStream::connect(&socket) {
                relay(client, upstream);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn allowlist_exact_subdomain_and_lookalikes() {
        let allowlist = entries(&["example.com"]);
        assert!(allowlist_matches(&allowlist, "example.com"));
        assert!(allowlist_matches(&allowlist, "api.example.com"));
        assert!(allowlist_matches(&allowlist, "deep.api.example.com"));
        // Suffix lookalikes must never match.
        assert!(!allowlist_matches(&allowlist, "notexample.com"));
        assert!(!allowlist_matches(&allowlist, "evil-example.com"));
        assert!(!allowlist_matches(&allowlist, "example.com.evil.com"));
        // A trailing dot on the host is the FQDN form; it normalizes.
        assert!(allowlist_matches(&allowlist, "example.com."));
    }

    #[test]
    fn allowlist_case_and_trailing_dot_normalized() {
        let allowlist = entries(&["Example.COM."]);
        assert!(allowlist_matches(&allowlist, "example.com"));
        assert!(allowlist_matches(&allowlist, "API.EXAMPLE.COM"));
        assert!(allowlist_matches(&allowlist, "api.example.com."));
        assert!(allowlist_matches(&allowlist, "EXAMPLE.COM."));
    }

    #[test]
    fn allowlist_ip_literals_match_only_themselves() {
        let allowlist = entries(&["93.184.216.34", "2606:4700:4700::1111"]);
        assert!(allowlist_matches(&allowlist, "93.184.216.34"));
        assert!(allowlist_matches(&allowlist, "2606:4700:4700::1111"));
        // No suffix rule for addresses, and no cross-family match.
        assert!(!allowlist_matches(&allowlist, "1.93.184.216.34"));
        assert!(!allowlist_matches(&allowlist, "foo.93.184.216.34"));
        assert!(!allowlist_matches(&allowlist, "93.184.216.35"));
        assert!(!allowlist_matches(&allowlist, "2606:4700:4700::1112"));
        // A domain entry never covers an IP, nor vice versa.
        assert!(!allowlist_matches(&entries(&["example.com"]), "1.2.3.4"));
    }

    #[test]
    fn ssrf_classifier_refuses_each_denied_range() {
        for (addr, class) in [
            ("0.0.0.0", "unspecified address"),
            ("127.0.0.1", "loopback address"),
            ("127.53.0.9", "loopback address"),
            ("10.0.0.1", "private address range"),
            ("10.255.255.255", "private address range"),
            ("172.16.0.1", "private address range"),
            ("172.31.255.255", "private address range"),
            ("192.168.0.1", "private address range"),
            ("100.64.0.0", "carrier-grade NAT address range"),
            ("100.127.255.255", "carrier-grade NAT address range"),
            ("169.254.169.254", "cloud metadata address"),
            ("169.254.0.1", "link-local address"),
            ("224.0.0.1", "multicast address"),
            ("239.255.255.255", "multicast address"),
            ("::", "unspecified address"),
            ("::1", "loopback address"),
            ("ff00::1", "multicast address"),
            ("ff02::1", "multicast address"),
            ("fe80::1", "link-local address"),
            ("febf::ffff", "link-local address"),
            ("fc00::1", "private address range"),
            ("fdff::ffff", "private address range"),
            // v4-mapped forms inherit the v4 classes.
            ("::ffff:0.0.0.0", "unspecified address"),
            ("::ffff:127.0.0.1", "loopback address"),
            ("::ffff:10.1.2.3", "private address range"),
            ("::ffff:169.254.169.254", "cloud metadata address"),
            ("::ffff:224.0.0.1", "multicast address"),
            // Deprecated v4-compatible ::/96 is refused outright.
            ("::10.0.0.1", "v4-compatible address"),
            ("::8.8.8.8", "v4-compatible address"),
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(denied_class(&ip), Some(class), "{addr}");
        }
    }

    #[test]
    fn ssrf_classifier_allows_public_addresses() {
        for addr in [
            "8.8.8.8",
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "192.0.2.1",
            "223.255.255.255",
            "240.0.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(denied_class(&ip), None, "{addr}");
        }
    }

    #[test]
    fn parse_authority_accepts_host_port_and_bracketed_v6() {
        assert_eq!(
            parse_authority("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn parse_authority_rejects_malformed() {
        for authority in [
            "example.com",       // CONNECT authorities always carry a port
            "example.com:",      // empty port
            "example.com:0",     // port zero
            "example.com:65536", // out of range
            "example.com:abc",   // non-numeric port
            ":443",              // empty host
            "::1:443",           // bare IPv6 is ambiguous
            "example.com:443:2",
            "[::1]",           // bracketed without port
            "[::1]x:443",      // garbage after the bracket
            "[not-an-ip]:443", // brackets are for IPv6 literals only
        ] {
            assert!(parse_authority(authority).is_err(), "{authority}");
        }
    }

    #[test]
    fn parse_request_accepts_connect_and_consumes_headers() {
        let (host, port) = parse_request(
            b"CONNECT example.com:443 HTTP/1.1\r\n\
              Host: example.com:443\r\n\
              User-Agent: curl/8.0\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n",
        )
        .unwrap();
        assert_eq!((host.as_str(), port), ("example.com", 443));
        // HTTP/1.0 is accepted too.
        assert!(
            parse_request(b"CONNECT example.com:443 HTTP/1.0\r\n\r\n").is_ok()
        );
    }

    #[test]
    fn parse_request_rejects_non_connect_with_405() {
        assert!(matches!(
            parse_request(b"GET http://example.com/ HTTP/1.1\r\n\r\n"),
            Err(Reject::MethodNotAllowed)
        ));
        assert!(matches!(
            parse_request(b"POST / HTTP/1.1\r\n\r\n"),
            Err(Reject::MethodNotAllowed)
        ));
    }

    #[test]
    fn parse_request_rejects_garbage_with_400() {
        for request in [
            &b"garbage\r\n\r\n"[..],
            b"CONNECT example.com:443\r\n\r\n", // no version
            b"CONNECT example.com:443 HTTP/2\r\n\r\n", // not HTTP/1.x
            b"CONNECT  example.com:443 HTTP/1.1\r\n\r\n", // doubled space
            b"CONNECT example.com HTTP/1.1\r\n\r\n", // no port
            b"CONNECT example.com:443 HTTP/1.1 extra\r\n\r\n",
        ] {
            assert!(
                matches!(parse_request(request), Err(Reject::BadRequest)),
                "{}",
                String::from_utf8_lossy(request)
            );
        }
    }

    // --- end-to-end, over real loopback streams ---

    /// Echo fixture: writes back whatever it reads until the peer
    /// half-closes, then drops the socket.
    fn echo_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut stream in listener.incoming().map_while(Result::ok) {
                thread::spawn(move || {
                    let mut buf = [0_u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    /// Half-close fixture: reads until EOF, then still sends a reply.
    fn eof_then_send_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
            let _ = stream.write_all(b"bye");
        });
        port
    }

    fn test_config(allowlist: &[&str]) -> ProxyConfig {
        let mut config = ProxyConfig::new(entries(allowlist));
        // Tests CONNECT to loopback fixture servers, which the real
        // SSRF guard would refuse; this knob is test-only.
        config.danger_allow_private = true;
        config
    }

    fn connect_and_send(port: u16, request: &[u8]) -> TcpStream {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (&stream).write_all(request).unwrap();
        stream
    }

    fn connect_request(host_port: &str) -> Vec<u8> {
        format!("CONNECT {host_port} HTTP/1.1\r\n\r\n").into_bytes()
    }

    fn read_reply_head(stream: &TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 512];
        loop {
            let n = (&mut &*stream).read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn e2e_connect_then_bidirectional_echo() {
        let echo = echo_server();
        let proxy = Proxy::start(test_config(&["127.0.0.1"]), None).unwrap();
        let request = connect_request(&format!("127.0.0.1:{echo}"));
        let stream = connect_and_send(proxy.port(), &request);
        assert_eq!(read_reply_head(&stream), REPLY_OK);

        // Client -> upstream.
        (&stream).write_all(b"hello").unwrap();
        let mut buf = [0_u8; 5];
        (&mut &stream).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        // And again, both directions stay up.
        (&stream).write_all(b"world").unwrap();
        (&mut &stream).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn e2e_half_close_propagates() {
        // Client half-closes; the fixture must still be able to answer.
        let fixture = eof_then_send_server();
        let proxy = Proxy::start(test_config(&["127.0.0.1"]), None).unwrap();
        let request = connect_request(&format!("127.0.0.1:{fixture}"));
        let stream = connect_and_send(proxy.port(), &request);
        assert_eq!(read_reply_head(&stream), REPLY_OK);

        (&stream).write_all(b"data").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        (&mut &stream).read_to_end(&mut received).unwrap();
        assert_eq!(received, b"bye");
    }

    #[test]
    fn e2e_disallowed_host_is_403() {
        let proxy = Proxy::start(test_config(&["example.com"]), None).unwrap();
        let stream =
            connect_and_send(proxy.port(), &connect_request("127.0.0.1:443"));
        assert_eq!(read_reply_head(&stream), "HTTP/1.1 403 Forbidden\r\n\r\n");
    }

    #[test]
    fn e2e_ssrf_range_is_403_even_when_allowlisted() {
        // No danger_allow_private here: the allowlist alone must never
        // open a forbidden range.
        let proxy =
            Proxy::start(ProxyConfig::new(entries(&["127.0.0.1"])), None)
                .unwrap();
        let stream =
            connect_and_send(proxy.port(), &connect_request("127.0.0.1:80"));
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 403 Forbidden address range\r\n\r\n"
        );
    }

    #[test]
    fn e2e_non_connect_is_405() {
        let proxy = Proxy::start(test_config(&[]), None).unwrap();
        let stream = connect_and_send(proxy.port(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
        );
    }

    #[test]
    fn e2e_oversized_request_is_rejected() {
        let proxy = Proxy::start(test_config(&[]), None).unwrap();
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
        request.extend(std::iter::repeat_n(b'A', REQUEST_CAP));
        let stream = connect_and_send(proxy.port(), &request);
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"
        );
    }

    #[test]
    fn e2e_malformed_authority_is_400() {
        let proxy = Proxy::start(test_config(&[]), None).unwrap();
        let stream = connect_and_send(
            proxy.port(),
            b"CONNECT example.com HTTP/1.1\r\n\r\n",
        );
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 400 Bad Request\r\n\r\n"
        );
    }

    #[test]
    fn e2e_audit_records_connect_verdicts() {
        // Phase 5: with an audit handle attached, each CONNECT appends
        // a verdict record -- deny for a non-allowlisted host, allow
        // for a tunneled one.
        let echo = echo_server();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-proxy-audit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let log = crate::audit::AuditLog::open(&home).unwrap();

        let mut config = test_config(&["127.0.0.1"]);
        config.audit = Some(log);
        let proxy = Proxy::start(config, None).unwrap();

        let denied =
            connect_and_send(proxy.port(), &connect_request("example.com:443"));
        assert_eq!(read_reply_head(&denied), "HTTP/1.1 403 Forbidden\r\n\r\n");

        let allowed = connect_and_send(
            proxy.port(),
            &connect_request(&format!("127.0.0.1:{echo}")),
        );
        assert_eq!(read_reply_head(&allowed), REPLY_OK);
        drop(allowed);
        drop(proxy);

        let content = std::fs::read_to_string(
            home.join(".local/share/ai-jail/history.jsonl"),
        )
        .unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["type"], "connect");
        assert_eq!(records[0]["host"], "example.com");
        assert_eq!(records[0]["verdict"], "deny");
        assert_eq!(records[0]["reason"], "not-in-allowlist");
        assert_eq!(records[1]["host"], "127.0.0.1");
        assert_eq!(records[1]["verdict"], "allow");
        assert_eq!(records[1]["reason"], "in-allowlist");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn e2e_slowloris_times_out_silently() {
        let mut config = test_config(&[]);
        config.read_timeout = Duration::from_millis(300);
        let proxy = Proxy::start(config, None).unwrap();
        let stream = connect_and_send(proxy.port(), b"CONNECT example.co");
        // No terminator: the read timeout closes the connection without
        // a reply, well inside the client-side 5 s test timeout.
        let n = (&mut &stream).read(&mut [0_u8; 64]).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn e2e_connection_limit_is_503() {
        let echo = echo_server();
        let mut config = test_config(&["127.0.0.1"]);
        config.max_connections = 1;
        let proxy = Proxy::start(config, None).unwrap();

        // Hold one tunnel open so the second connection exceeds the cap.
        let request = connect_request(&format!("127.0.0.1:{echo}"));
        let _held = connect_and_send(proxy.port(), &request);
        assert_eq!(read_reply_head(&_held), REPLY_OK);

        let second =
            connect_and_send(proxy.port(), &connect_request("127.0.0.1:443"));
        assert_eq!(
            read_reply_head(&second),
            "HTTP/1.1 503 Service Unavailable\r\n\r\n"
        );
    }

    #[test]
    fn e2e_unix_listener_serves_connect() {
        let echo = echo_server();
        let path = std::env::temp_dir()
            .join(format!("ai-jail-proxy-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let proxy =
            Proxy::start(test_config(&["127.0.0.1"]), Some(&path)).unwrap();
        assert_eq!(proxy.unix_path(), Some(path.as_path()));
        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let stream = UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = connect_request(&format!("127.0.0.1:{echo}"));
        (&stream).write_all(&request).unwrap();
        let mut head = Vec::new();
        let mut chunk = [0_u8; 64];
        while !head.ends_with(b"\r\n\r\n") {
            let n = (&mut &stream).read(&mut chunk).unwrap();
            assert!(n > 0, "proxy closed before replying");
            head.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(head, REPLY_OK.as_bytes());
        (&stream).write_all(b"ping").unwrap();
        let mut buf = [0_u8; 4];
        (&mut &stream).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        // Dropping the handle unlinks the socket file.
        drop(proxy);
        assert!(!path.exists());
    }

    #[test]
    fn e2e_bridge_pumps_between_loopback_and_unix_socket() {
        // The phase-3 data path, without the sandbox: bridge on
        // loopback <-> proxy's Unix socket <-> allowlisted fixture.
        let echo = echo_server();
        let path = std::env::temp_dir()
            .join(format!("ai-jail-bridge-test-{}.sock", std::process::id()));
        let proxy =
            Proxy::start(test_config(&["127.0.0.1"]), Some(&path)).unwrap();

        let bridge_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bridge_port = bridge_listener.local_addr().unwrap().port();
        let bridge_socket = path.clone();
        let bridge = thread::spawn(move || {
            for client in bridge_listener.incoming().map_while(Result::ok) {
                let socket = bridge_socket.clone();
                thread::spawn(move || {
                    if let Ok(upstream) = UnixStream::connect(&socket) {
                        relay(client, upstream);
                    }
                });
            }
        });

        let stream =
            TcpStream::connect((Ipv4Addr::LOCALHOST, bridge_port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = connect_request(&format!("127.0.0.1:{echo}"));
        (&stream).write_all(&request).unwrap();
        assert_eq!(read_reply_head(&stream), REPLY_OK);
        (&stream).write_all(b"through").unwrap();
        let mut buf = [0_u8; 7];
        (&mut &stream).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"through");

        // A non-allowlisted target through the same bridge is refused
        // by the proxy's own allowlist.
        let refused =
            TcpStream::connect((Ipv4Addr::LOCALHOST, bridge_port)).unwrap();
        refused
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (&refused)
            .write_all(&connect_request("10.0.0.1:443"))
            .unwrap();
        assert_eq!(read_reply_head(&refused), "HTTP/1.1 403 Forbidden\r\n\r\n");

        drop(bridge);
        drop(proxy);
    }
}
