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

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream,
    ToSocketAddrs,
};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::egress_log::{ConnRecord, CountingReader, Verdict};

/// Hard cap on the CONNECT request (request line plus headers).
const REQUEST_CAP: usize = 8 * 1024;

const REPLY_OK: &str = "HTTP/1.1 200 Connection Established\r\n\r\n";
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

fn accept_next<S>(
    label: &str,
    accept: &mut impl FnMut() -> io::Result<S>,
) -> S {
    let mut warned = false;
    loop {
        match accept() {
            Ok(stream) => return stream,
            Err(error) => {
                if !warned {
                    crate::output::warn(&format!(
                        "{label} accept failed: {error}; retrying"
                    ));
                    warned = true;
                }
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
        }
    }
}

/// Proxy configuration. Phase 2 builds this from the effective config.
pub(crate) struct ProxyConfig {
    /// Allowed CONNECT targets. An entry `example.com` matches
    /// `example.com` and any subdomain of it; IP-literal entries match
    /// only themselves. Matching is case-insensitive and trailing-dot
    /// normalized (see [`allowlist_matches`]).
    pub allowlist: Vec<String>,
    /// Trusted hosts allowed to resolve to private/CGNAT addresses. These
    /// entries are also present in `allowlist`; this second list only grants
    /// the narrow address-range exception.
    pub allow_private_hosts: Vec<String>,
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
    /// Phantom credential bindings (issue #135): absolute-form
    /// plain-HTTP requests to a binding's host are terminated, their
    /// placeholders rewritten to the real values, and re-originated
    /// over TLS.
    pub secrets: Vec<crate::secret::SecretBinding>,
    /// Test-only escape hatch: extra TLS trust roots for the
    /// self-signed fixture in tests/. Same rule as
    /// `danger_allow_private`: never config- or CLI-exposable.
    pub danger_extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Interactive host prompt (`--prompt-hosts`): a CONNECT to a host
    /// outside `allowlist` asks the user once per session instead of
    /// being refused outright. The SSRF address-range guard still
    /// applies to approved hosts.
    pub prompt: Option<Arc<dyn HostPrompt>>,
    /// The `--egress-log` file: one line per accepted
    /// connection. `None` writes nothing, but `stats` still counts.
    pub egress: Option<Arc<crate::egress_log::EgressLog>>,
    /// Run-wide connection and byte counters, kept with or without a log.
    pub stats: Arc<crate::egress_log::EgressStats>,
    /// Whether the run shuts the tunnels still open when the command
    /// exits ([`Proxy::drain`]). Only a run that records its egress needs
    /// that; any other run ends its proxy as before, when it exits.
    pub drain_on_exit: bool,
    /// Test seam: delay before a connection's handler starts, to widen
    /// the accept-to-handler window the drain must cover.
    #[cfg(test)]
    pub(crate) test_handler_delay: Duration,
    /// Test seam: the accept threads never accept, so connections stay in
    /// the kernel backlog for the drain to find.
    #[cfg(test)]
    pub(crate) test_accept_paused: bool,
}

impl ProxyConfig {
    pub(crate) fn new(allowlist: Vec<String>) -> Self {
        ProxyConfig {
            allowlist,
            allow_private_hosts: Vec::new(),
            max_connections: 256,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(10),
            danger_allow_private: false,
            audit: None,
            secrets: Vec::new(),
            danger_extra_roots: Vec::new(),
            prompt: None,
            egress: None,
            stats: Arc::new(crate::egress_log::EgressStats::default()),
            drain_on_exit: false,
            #[cfg(test)]
            test_handler_delay: Duration::ZERO,
            #[cfg(test)]
            test_accept_paused: false,
        }
    }
}

/// Asks the user whether a host outside the allowlist may be reached.
/// Runs on the connection's own thread, which blocks until it returns.
pub(crate) trait HostPrompt: Send + Sync {
    /// `internal` lists the host's private/CGNAT addresses (empty for a
    /// public host): approving opens them for the rest of the session.
    fn ask(&self, host: &str, port: u16, internal: &[IpAddr]) -> PromptAnswer;
}

/// The user's answer. Only `Allow` and `Deny` are remembered for the
/// session; `NoAnswer` refuses the waiting connection(s) and the next
/// connection to that host asks again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PromptAnswer {
    Allow,
    Deny,
    NoAnswer,
}

/// Desktop-notification prompt (Linux): `notify-send --wait` with
/// Allow/Deny actions. A dismissal, a missing or failing `notify-send`,
/// or no answer within `timeout` are all `NoAnswer`.
pub(crate) struct NotifySendPrompt {
    /// Absolute path of a trusted `notify-send`.
    pub program: PathBuf,
    /// Command name shown in the notification title.
    pub label: String,
    pub timeout: Duration,
}

const NOTIFY_POLL: Duration = Duration::from_millis(100);
/// How long a prompted `notify-send` gets to close its notification after
/// SIGINT before it is killed outright.
const NOTIFY_CLOSE_GRACE: Duration = Duration::from_millis(300);

/// `notify-send` processes currently waiting for an answer.
///
/// SIGINT makes libnotify close its notification through its own daemon
/// connection ("Wait cancelled, closing notification"); SIGKILL does not,
/// which is why an unanswered critical prompt otherwise stays in the
/// notification list until it is dismissed by hand.
static PENDING_PROMPTS: std::sync::Mutex<Vec<nix::unistd::Pid>> =
    std::sync::Mutex::new(Vec::new());

fn register_prompt(pid: nix::unistd::Pid) {
    if let Ok(mut pending) = PENDING_PROMPTS.lock() {
        pending.push(pid);
    }
}

fn unregister_prompt(pid: nix::unistd::Pid) {
    if let Ok(mut pending) = PENDING_PROMPTS.lock() {
        pending.retain(|candidate| *candidate != pid);
    }
}

/// Close the notifications of prompts still waiting when ai-jail exits, so
/// no dead prompt is left behind for the session's operator.
pub(crate) fn close_pending_prompts() {
    let Ok(mut pending) = PENDING_PROMPTS.lock() else {
        return;
    };
    for pid in pending.drain(..) {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT);
    }
}

/// Ask a prompted process to close its notification, then wait out the grace
/// period before killing it.
fn interrupt_then_kill(child: &mut std::process::Child) {
    let pid =
        nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT);
    let deadline = Instant::now() + NOTIFY_CLOSE_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(NOTIFY_POLL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl HostPrompt for NotifySendPrompt {
    fn ask(&self, host: &str, port: u16, internal: &[IpAddr]) -> PromptAnswer {
        let (summary, body) = notify_text(&self.label, host, port, internal);
        // Outlive ai-jail's own deadline: the daemon must not expire the
        // prompt before the connection it belongs to is decided.
        let expire = self.timeout.saturating_add(NOTIFY_CLOSE_GRACE * 10);
        let spawned = Command::new(&self.program)
            .arg("--app-name=ai-jail")
            .arg("--urgency=critical")
            .arg(format!("--expire-time={}", expire.as_millis()))
            .arg("--wait")
            .arg("--action=allow=Allow")
            .arg("--action=deny=Deny")
            .arg(summary)
            .arg(body)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = spawned else {
            return PromptAnswer::NoAnswer;
        };
        let pid =
            nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));
        register_prompt(pid);
        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(NOTIFY_POLL);
                }
                _ => {
                    interrupt_then_kill(&mut child);
                    unregister_prompt(pid);
                    return PromptAnswer::NoAnswer;
                }
            }
        }
        unregister_prompt(pid);
        let mut reply = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut reply);
        }
        notify_reply(&reply)
    }
}

/// Notification summary and body. An internal host is called out in the
/// summary and its addresses are listed, since approving it opens part of
/// the local network to the sandbox.
fn notify_text(
    label: &str,
    host: &str,
    port: u16,
    internal: &[IpAddr],
) -> (String, String) {
    // A project config may choose the command name. Keep that untrusted text
    // from adding markup or extra lines to an authorization prompt.
    let label = if !label.is_empty()
        && label.len() <= 80
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        label
    } else {
        "the sandboxed command"
    };
    if internal.is_empty() {
        return (
            format!("ai-jail: {label} wants to reach a new host"),
            format!("{host}:{port}"),
        );
    }
    let addresses: Vec<String> =
        internal.iter().map(ToString::to_string).collect();
    (
        format!("ai-jail: {label} wants to reach an INTERNAL host"),
        format!("{host}:{port}\nInternal address: {}", addresses.join(", ")),
    )
}

/// `notify-send --wait` prints the invoked action's name, or nothing
/// when the notification is dismissed or expires.
fn notify_reply(reply: &str) -> PromptAnswer {
    match reply.trim_end() {
        "allow" => PromptAnswer::Allow,
        "deny" => PromptAnswer::Deny,
        _ => PromptAnswer::NoAnswer,
    }
}

/// Running proxy handle. Reports where the listeners are; see the
/// module docs for the (process-exit) lifecycle.
pub(crate) struct Proxy {
    port: Option<u16>,
    unix_path: Option<PathBuf>,
    shared: Arc<Shared>,
    drain_on_exit: bool,
}

impl Proxy {
    /// Bind exactly one listener: a Unix socket (mode 0600) when a path is
    /// supplied, otherwise a TCP listener on 127.0.0.1:0. Linux uses the Unix
    /// endpoint across its private network namespace; macOS uses loopback.
    pub(crate) fn start(
        config: ProxyConfig,
        unix_socket_path: Option<&Path>,
    ) -> io::Result<Proxy> {
        let drain_on_exit = config.drain_on_exit;
        let shared = Arc::new(Shared::new(config));

        let port = if unix_socket_path.is_none() {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            shared.keep_listener(listener.try_clone().map(DrainListener::Tcp));
            let tcp_shared = Arc::clone(&shared);
            thread::spawn(move || {
                loop {
                    #[cfg(test)]
                    if tcp_shared.config.test_accept_paused {
                        park_forever();
                    }
                    let stream = accept_next("proxy TCP listener", &mut || {
                        let accepted =
                            listener.accept().map(|(stream, _)| stream);
                        tcp_shared.stop_accepting_if_draining(&accepted);
                        accepted
                    });
                    spawn_handler(stream, &tcp_shared);
                }
            });
            Some(port)
        } else {
            None
        };

        let unix_path = if let Some(path) = unix_socket_path {
            // A stale socket from a previous launch would fail the bind.
            let _ = std::fs::remove_file(path);
            let unix_listener = UnixListener::bind(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o600),
            )?;
            shared.keep_listener(
                unix_listener.try_clone().map(DrainListener::Unix),
            );
            let unix_shared = Arc::clone(&shared);
            thread::spawn(move || {
                loop {
                    let stream =
                        accept_next("proxy Unix listener", &mut || {
                            let accepted = unix_listener
                                .accept()
                                .map(|(stream, _)| stream);
                            unix_shared.stop_accepting_if_draining(&accepted);
                            accepted
                        });
                    spawn_handler(stream, &unix_shared);
                }
            });
            Some(path.to_path_buf())
        } else {
            None
        };

        Ok(Proxy {
            port,
            unix_path,
            shared,
            drain_on_exit,
        })
    }

    /// Whether the run asked for its open tunnels to be drained at exit.
    pub(crate) fn drain_on_exit(&self) -> bool {
        self.drain_on_exit
    }

    /// Loopback TCP port the proxy listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port.expect("proxy does not have a TCP listener")
    }

    /// Loopback TCP port, when one was bound.
    pub(crate) fn tcp_port(&self) -> Option<u16> {
        self.port
    }

    /// Unix socket path, when one was bound.
    pub(crate) fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    /// End every live connection before the egress log is closed:
    /// refuse new ones, shut every registered socket so both
    /// relay pumps return, and wait up to `grace` for the handlers to
    /// finish. A handler writes its egress line before it leaves `active`,
    /// so once this sees 0 every line and every byte is counted.
    pub(crate) fn drain(&self, grace: Duration) {
        let shared = &self.shared;
        shared.draining.store(true, Ordering::SeqCst);
        // Connections waiting on another connection's prompt give up now.
        shared.decided.notify_all();
        // The sandbox has exited, so nothing new arrives; what is still in
        // the kernel backlog is accepted here and refused with its line, so
        // the log and the totals cover the same connections.
        shared.take_backlog();
        for entry in shared.live_conns().values() {
            entry.shut();
        }
        let deadline = Instant::now() + grace;
        while shared.active.load(Ordering::SeqCst) > 0 {
            if Instant::now() >= deadline {
                let open = shared.active.load(Ordering::SeqCst);
                let undrainable = shared
                    .live_conns()
                    .values()
                    .filter(|entry| entry.undrainable)
                    .count();
                // A handler still resolving, dialing or awaiting a prompt
                // holds a registered socket too, so the open count is not
                // split by phase: it would claim a precision it lacks.
                crate::output::security_warn(&format!(
                    "egress proxy: {open} connection(s) still open after a \
                     {} ms drain ({undrainable} could not be shut); their \
                     egress lines are missing from the log",
                    grace.as_millis()
                ));
                return;
            }
            thread::sleep(DRAIN_POLL);
        }
    }
}

/// How often `Proxy::drain` checks whether the handlers have finished.
const DRAIN_POLL: Duration = Duration::from_millis(10);

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
    /// Session verdicts of the host prompt, keyed by normalized host.
    /// Kept in memory only: a new session asks again.
    decisions: Mutex<HashMap<String, Decision>>,
    /// Wakes connections waiting on a `Pending` host.
    decided: Condvar,
    /// Set by `Proxy::drain`: new connections are refused, and a socket
    /// registered after the drain began is shut at once.
    draining: AtomicBool,
    /// Shutdown handles of every live connection, keyed by `next_conn`.
    conns: Mutex<HashMap<u64, DrainEntry>>,
    next_conn: AtomicU64,
    /// `try_clone`s of the listeners, for the drain's backlog sweep.
    listeners: Mutex<Vec<DrainListener>>,
}

/// A listener clone the drain accepts the remaining backlog from.
enum DrainListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

/// Spawn the handler of a connection the accept loop just returned. It is
/// admitted (counted in `active`) here, before the thread exists, so a
/// drain can never miss a connection whose handler has not started yet.
fn spawn_handler<S: ClientStream + Send + 'static>(
    stream: S,
    shared: &Arc<Shared>,
) {
    let admission = Shared::admit(shared);
    let shared = Arc::clone(shared);
    thread::spawn(move || {
        #[cfg(test)]
        thread::sleep(shared.config.test_handler_delay);
        handle_conn(stream, shared, admission)
    });
}

/// Never returns: an accept thread that saw the drain begin stops here,
/// leaving the backlog to the drain's own sweep.
fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

impl Shared {
    fn new(config: ProxyConfig) -> Self {
        Shared {
            config,
            active: AtomicUsize::new(0),
            decisions: Mutex::new(HashMap::new()),
            decided: Condvar::new(),
            draining: AtomicBool::new(false),
            conns: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(0),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Count a connection the moment it is accepted.
    fn admit(shared: &Arc<Shared>) -> Admission {
        let active = shared.active.fetch_add(1, Ordering::SeqCst) + 1;
        let id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
        Admission {
            slot: ConnSlot {
                shared: Arc::clone(shared),
                id,
            },
            active,
        }
    }

    #[cfg(test)]
    fn listeners_kept(&self) -> usize {
        self.listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Keep a listener clone for the drain. A failed clone only means the
    /// drain cannot sweep that listener's backlog.
    fn keep_listener(&self, listener: io::Result<DrainListener>) {
        if !self.config.drain_on_exit {
            return;
        }
        if let Ok(listener) = listener {
            self.listeners
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(listener);
        }
    }

    /// An accept thread stops for good once a drain has begun and its
    /// accept did not yield a connection (the drain set the listener
    /// non-blocking): the drain owns the backlog from then on.
    fn stop_accepting_if_draining<T>(&self, accepted: &io::Result<T>) {
        if accepted.is_err() && self.draining.load(Ordering::SeqCst) {
            park_forever();
        }
    }

    /// Accept, without blocking, every connection still queued on a
    /// listener, and run each through the handler, which refuses it as
    /// `connection-cap` and writes its line. Runs on the drain's thread.
    fn take_backlog(self: &Arc<Self>) {
        let listeners =
            self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        for listener in listeners.iter() {
            match listener {
                DrainListener::Tcp(l) => {
                    if l.set_nonblocking(true).is_ok() {
                        while let Ok((stream, _)) = l.accept() {
                            let _ = stream.set_nonblocking(false);
                            let admission = Shared::admit(self);
                            handle_conn(stream, Arc::clone(self), admission);
                        }
                    }
                }
                DrainListener::Unix(l) => {
                    if l.set_nonblocking(true).is_ok() {
                        while let Ok((stream, _)) = l.accept() {
                            let _ = stream.set_nonblocking(false);
                            let admission = Shared::admit(self);
                            handle_conn(stream, Arc::clone(self), admission);
                        }
                    }
                }
            }
        }
    }

    /// A poisoned registry only means a handler panicked while holding
    /// it; the handles inside are still valid.
    fn live_conns(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u64, DrainEntry>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a `try_clone` handle for connection `id`. A failed clone
    /// leaves the connection undrainable (counted, never a panic). Under
    /// the registry lock, a drain already under way is seen here, so a
    /// socket can never slip in after the drain's sweep.
    fn register(&self, id: u64, handle: io::Result<ShutHandle>) {
        let mut conns = self.live_conns();
        let entry = conns.entry(id).or_default();
        match handle {
            Ok(handle) => {
                if self.draining.load(Ordering::SeqCst) {
                    handle();
                }
                entry.handles.push(handle);
            }
            Err(_) => entry.undrainable = true,
        }
    }
}

/// Shuts one socket both ways. Its error (ENOTCONN once the peer is
/// gone) is ignored: the socket is closing either way.
type ShutHandle = Box<dyn Fn() + Send>;

fn shut_handle<S: ClientStream>(stream: &S) -> io::Result<ShutHandle> {
    let clone = stream.try_clone_stream()?;
    Ok(Box::new(move || {
        let _ = clone.shutdown_both();
    }))
}

fn shut_tcp_handle(stream: &TcpStream) -> io::Result<ShutHandle> {
    let clone = stream.try_clone()?;
    Ok(Box::new(move || {
        let _ = clone.shutdown(Shutdown::Both);
    }))
}

/// The drainable sockets of one live connection: the client, then the
/// upstream once it is dialed.
#[derive(Default)]
struct DrainEntry {
    handles: Vec<ShutHandle>,
    undrainable: bool,
}

impl DrainEntry {
    fn shut(&self) {
        for handle in &self.handles {
            handle();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Pending,
    /// `internal`: the approval covered private/CGNAT answers too.
    Allow {
        internal: bool,
    },
    Deny,
    /// Outcome of an unanswered prompt; never stored, so the host is
    /// asked again on its next connection.
    NoAnswer,
}

/// One accepted connection: its egress record and its place in the
/// proxy's bookkeeping. Fields drop in declaration order, so the record
/// bumps the stats and writes its line before the slot leaves the drain
/// registry and the active count: a drain that sees `active == 0` sees
/// every line and every byte.
struct Conn {
    record: ConnRecord,
    slot: ConnSlot,
}

impl Conn {
    /// Returns the connection and the active count including it.
    fn begin(shared: &Arc<Shared>, admission: Admission) -> (Conn, usize) {
        let record = ConnRecord::begin(
            shared.config.egress.clone(),
            Arc::clone(&shared.config.stats),
        );
        let Admission { slot, active } = admission;
        (Conn { record, slot }, active)
    }

    // Only a proxy that will be drained keeps socket clones: any other
    // holds the same descriptors per tunnel as before.
    fn register<S: ClientStream>(&self, stream: &S) {
        if self.slot.shared.config.drain_on_exit {
            self.slot.shared.register(self.slot.id, shut_handle(stream));
        }
    }

    fn register_tcp(&self, stream: &TcpStream) {
        if self.slot.shared.config.drain_on_exit {
            self.slot
                .shared
                .register(self.slot.id, shut_tcp_handle(stream));
        }
    }
}

/// A connection counted in `active` at accept time, not yet handled.
struct Admission {
    slot: ConnSlot,
    active: usize,
}

/// Leaves the drain registry (under its lock), then the active count.
struct ConnSlot {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.shared.live_conns().remove(&self.id);
        self.shared.active.fetch_sub(1, Ordering::SeqCst);
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
    NotImplemented,
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
            Reject::NotImplemented => (501, "Not Implemented"),
        }
    }
}

/// Every connection is one `Conn`, made first, so each `return` below
/// drops it and writes exactly one egress line. The verdict
/// is set next to the reply that carries it; `audit_verdict` is left as it
/// was.
fn handle_conn<S: ClientStream>(
    mut client: S,
    shared: Arc<Shared>,
    admission: Admission,
) {
    let (mut conn, active) = Conn::begin(&shared, admission);
    if active > shared.config.max_connections
        || shared.draining.load(Ordering::SeqCst)
    {
        conn.record.verdict(Verdict::Error, "connection-cap");
        reject(&mut client, &Reject::Unavailable);
        return;
    }
    conn.register(&client);

    let _ = client.set_read_timeout(Some(shared.config.read_timeout));
    let request = match read_request(&mut client, REQUEST_CAP) {
        Ok(request) => request,
        Err(ReadFail::TooLarge) => {
            conn.record.verdict(Verdict::Error, "request-too-large");
            reject(&mut client, &Reject::TooLarge);
            return;
        }
        // Slowloris timeout or a reset peer: close without a reply.
        Err(ReadFail::Io) => {
            conn.record.verdict(Verdict::Error, "client-read-failed");
            return;
        }
    };
    let _ = client.set_read_timeout(None);

    let (host, port) = match parse_request(&request) {
        Ok(target) => target,
        Err(Reject::MethodNotAllowed) => {
            // Phantom credentials (issue #135): a non-CONNECT method is
            // still a 405 unless it is an absolute-form plain-HTTP
            // request to a secret-bound allowlisted host, which the
            // proxy terminates, rewrites, and re-originates over TLS.
            // Anything else keeps today's 405 -- this proxy does not
            // become a general HTTP relay.
            match parse_absolute_form(&request) {
                Some(target) => {
                    // A target was parsed, so the line names it even when
                    // the request is refused (null only without one).
                    conn.record.target(&target.0, target.1);
                    // The method was refused unless termination takes it.
                    conn.record.verdict(Verdict::Error, "method-not-allowed");
                    handle_http_termination(
                        client, target, request, &shared, &mut conn,
                    );
                    return;
                }
                None => {
                    conn.record.verdict(Verdict::Error, "method-not-allowed");
                    reject(&mut client, &Reject::MethodNotAllowed);
                    return;
                }
            }
        }
        Err(why) => {
            conn.record.verdict(Verdict::Error, "malformed-request");
            reject(&mut client, &why);
            return;
        }
    };
    // Only the parsed host and port reach the record, never the request
    // bytes.
    conn.record.target(&host, port);

    let allowlisted = allowlist_matches(&shared.config.allowlist, &host);
    let prompting = !allowlisted
        && shared.config.prompt.is_some()
        && promptable_host(&host);
    if !allowlisted && !prompting {
        audit_verdict(&shared, &host, port, "deny", "not-in-allowlist");
        conn.record.verdict(Verdict::Deny, "not-in-allowlist");
        reject(&mut client, &Reject::ForbiddenHost);
        return;
    }

    // One resolution serves both the prompt and the dial (DNS pinning):
    // the addresses the user approves are the ones dialed.
    let addrs = match resolve(&host, port) {
        Ok(addrs) => addrs,
        Err(why) => {
            // No audit verdict here: a failed lookup is an upstream
            // error, not a policy refusal.
            conn.record.verdict(Verdict::Error, "upstream-unreachable");
            reject(&mut client, &why);
            return;
        }
    };
    let mut allow_reason = "in-allowlist";
    let mut internal_ok = false;
    if prompting {
        match prompt_verdict(&shared, &host, port, &addrs) {
            Some(Decision::Allow { internal }) => {
                allow_reason = "prompt-allow";
                internal_ok = internal;
            }
            Some(Decision::NoAnswer) => {
                audit_verdict(&shared, &host, port, "deny", "prompt-no-answer");
                conn.record.verdict(Verdict::Deny, "prompt-no-answer");
                reject(&mut client, &Reject::ForbiddenHost);
                return;
            }
            Some(_) => {
                audit_verdict(&shared, &host, port, "deny", "prompt-deny");
                conn.record.verdict(Verdict::Deny, "prompt-deny");
                reject(&mut client, &Reject::ForbiddenHost);
                return;
            }
            None => {
                conn.record
                    .verdict(Verdict::Deny, "forbidden-address-range");
                audit_verdict(
                    &shared,
                    &host,
                    port,
                    "deny",
                    "forbidden-address-range",
                );
                reject(&mut client, &Reject::ForbiddenRange);
                return;
            }
        }
    }

    let upstream =
        match dial_resolved(&host, &addrs, &shared.config, internal_ok) {
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
                let (verdict, reason) = dial_failure_verdict(&why);
                conn.record.verdict(verdict, reason);
                reject(&mut client, &why);
                return;
            }
        };
    audit_verdict(&shared, &host, port, "allow", allow_reason);
    conn.register_tcp(&upstream);

    if client.write_all(REPLY_OK.as_bytes()).is_err() {
        conn.record.verdict(Verdict::Error, "client-write-failed");
        return;
    }
    conn.record.verdict(Verdict::Allow, allow_reason);
    let (up, down) = conn.record.counters();
    relay(client, upstream, Some((up, down)));
}

/// Egress verdict of a failed dial: every answer filtered out by the SSRF
/// guard is a policy refusal, anything else an upstream error.
fn dial_failure_verdict(why: &Reject) -> (Verdict, &'static str) {
    if matches!(why, Reject::ForbiddenRange) {
        (Verdict::Deny, "forbidden-address-range")
    } else {
        (Verdict::Error, "upstream-unreachable")
    }
}

/// Verdict for a promptable host outside the allowlist, given its resolved
/// `addrs`. `None` when no answer could ever be dialed (loopback,
/// link-local, metadata, ...), so the user is never asked. Answers in
/// private/CGNAT ranges are shown to the user, and an approval then opens
/// those ranges for the host. An `Allow` or `Deny` holds for the session,
/// so each host is answered at most once; `NoAnswer` is not remembered and
/// the next connection asks again. Concurrent connections to a host being
/// asked about wait for that one outcome.
fn prompt_verdict(
    shared: &Shared,
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
) -> Option<Decision> {
    let prompt = shared.config.prompt.as_ref()?;
    let mut internal: Vec<IpAddr> = Vec::new();
    let mut offerable = false;
    for ip in addrs.iter().map(SocketAddr::ip) {
        if address_is_allowed(host, &ip, &shared.config) {
            offerable = true;
        } else if is_internal_class(&ip) {
            offerable = true;
            if !internal.contains(&ip) {
                internal.push(ip);
            }
        }
    }
    if !offerable {
        return None;
    }

    let key = normalize_host(host);
    let lock = || shared.decisions.lock().unwrap_or_else(|e| e.into_inner());
    let mut decisions = lock();
    let mut waited = false;
    loop {
        match decisions.get(&key).copied() {
            Some(Decision::Pending) => {
                waited = true;
                decisions = shared
                    .decided
                    .wait(decisions)
                    .unwrap_or_else(|e| e.into_inner());
                // Woken by Proxy::drain: the run is over, stop waiting.
                if shared.draining.load(Ordering::SeqCst) {
                    return Some(Decision::NoAnswer);
                }
            }
            Some(decided) => return Some(decided),
            // The prompt this connection waited on went unanswered: it
            // shares that outcome instead of asking again at once.
            None if waited => return Some(Decision::NoAnswer),
            None => break,
        }
    }
    decisions.insert(key.clone(), Decision::Pending);
    drop(decisions);

    let decision = match prompt.ask(&key, port, &internal) {
        PromptAnswer::Allow => Decision::Allow {
            internal: !internal.is_empty(),
        },
        PromptAnswer::Deny => Decision::Deny,
        PromptAnswer::NoAnswer => Decision::NoAnswer,
    };
    let mut decisions = lock();
    if decision == Decision::NoAnswer {
        decisions.remove(&key);
    } else {
        decisions.insert(key, decision);
    }
    drop(decisions);
    shared.decided.notify_all();
    Some(decision)
}

/// Only plain DNS names and IP literals reach the user: the host comes
/// from the sandbox, and anything else (spaces, markup) could make the
/// notification misleading.
fn promptable_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)))
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
    dial_resolved(host, &resolve(host, port)?, config, false)
}

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Reject> {
    (host, port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .map_err(|_| Reject::BadGateway)
}

/// Dial the first answer of an already-resolved set that passes the SSRF
/// guard. `internal_ok` is a session approval of an internal host through
/// the prompt: it relaxes the same private/CGNAT classes as
/// `allow_private_hosts`, nothing more.
fn dial_resolved(
    host: &str,
    addrs: &[SocketAddr],
    config: &ProxyConfig,
    internal_ok: bool,
) -> Result<TcpStream, Reject> {
    let mut any_dialable = false;
    for addr in addrs {
        if !dialable(host, &addr.ip(), config, internal_ok) {
            // The caller records one deny verdict for the request; the
            // per-answer class detail stays internal to this filter.
            continue;
        }
        any_dialable = true;
        if let Ok(stream) =
            TcpStream::connect_timeout(addr, config.connect_timeout)
        {
            return Ok(stream);
        }
    }
    // Every answer filtered out is a policy refusal; answers that
    // refused or timed out the dial are upstream failures.
    Err(if any_dialable {
        Reject::BadGateway
    } else {
        Reject::ForbiddenRange
    })
}

fn dialable(
    host: &str,
    ip: &IpAddr,
    config: &ProxyConfig,
    internal_ok: bool,
) -> bool {
    address_is_allowed(host, ip, config)
        || (internal_ok && is_internal_class(ip))
}

/// Private and carrier-grade NAT ranges: the only classes a trusted grant
/// (`allow_private_hosts` or an approved prompt) may open. Loopback,
/// link-local, metadata, multicast, and unspecified never qualify.
fn is_internal_class(ip: &IpAddr) -> bool {
    matches!(
        denied_class(ip),
        Some("private address range" | "carrier-grade NAT address range")
    )
}

fn address_is_allowed(host: &str, ip: &IpAddr, config: &ProxyConfig) -> bool {
    if denied_class(ip).is_none() || config.danger_allow_private {
        return true;
    }
    is_internal_class(ip)
        && allowlist_matches(&config.allow_private_hosts, host)
}

/// Parse an absolute-form request line (`METHOD http://host[:port]/...
/// HTTP/1.x`), returning (host, port). The port defaults to 443: the
/// proxy re-originates over TLS, so the scheme's port 80 never applies.
/// Origin-form requests and non-HTTP/1.x versions are not this path.
fn parse_absolute_form(buf: &[u8]) -> Option<(String, u16)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &buf[..end];
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let _method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || (version != "HTTP/1.0" && version != "HTTP/1.1")
    {
        return None;
    }
    let rest = uri.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    if let Some(v6) = authority.strip_prefix('[') {
        let close = v6.find(']')?;
        let host = &v6[..close];
        host.parse::<Ipv6Addr>().ok()?;
        let port = match v6[close + 1..].strip_prefix(':') {
            Some(port) => port.parse().ok().filter(|p| *p > 0)?,
            None => 443,
        };
        return Some((host.to_string(), port));
    }
    match authority.split_once(':') {
        Some((host, port)) => {
            if host.is_empty() {
                return None;
            }
            let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
            Some((host.to_string(), port))
        }
        None if !authority.is_empty() => Some((authority.to_string(), 443)),
        None => None,
    }
}

/// One header field parsed from a request head: whether the request
/// body is chunked, and the Content-Length when present.
fn head_body_framing(head: &[u8]) -> (bool, Option<u64>) {
    let mut chunked = false;
    let mut content_length = None;
    // read_request may include body bytes from the same socket read. They
    // can be binary or look like headers, but cannot define HTTP framing.
    let end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(head.len());
    let head = &head[..end];
    let Ok(text) = std::str::from_utf8(head) else {
        return (chunked, content_length);
    };
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
        } else if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        }
    }
    (chunked, content_length)
}

/// Strip any client `Connection:` header and pin `Connection: close`:
/// no keep-alive in the termination path (v1), so upstream EOF marks
/// the end of the response.
fn force_connection_close(head: &[u8]) -> Vec<u8> {
    let terminator = b"\r\n\r\n";
    let Some(end) =
        head.windows(terminator.len()).position(|w| w == terminator)
    else {
        return head.to_vec();
    };
    let mut out = Vec::with_capacity(head.len() + 19);
    let mut rest = &head[..end];
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());
        let line = &rest[..line_end];
        let is_connection = line
            .iter()
            .position(|b| *b == b':')
            .is_some_and(|at| line[..at].eq_ignore_ascii_case(b"connection"));
        if !is_connection {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        if line_end == rest.len() {
            break;
        }
        rest = &rest[line_end + 2..];
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

/// Terminate an absolute-form plain-HTTP request: only a host that is
/// both allowlisted and secret-bound takes this path (everything else
/// keeps today's 405). The head is placeholder-rewritten, pinned to
/// `Connection: close`, and re-originated over TLS; exactly
/// Content-Length body bytes are forwarded and the response streams
/// back until upstream EOF. No keep-alive in v1.
fn handle_http_termination<S: ClientStream>(
    mut client: S,
    target: (String, u16),
    request: Vec<u8>,
    shared: &Shared,
    conn: &mut Conn,
) {
    let (host, port) = target;
    // Secret-bound allowlisted hosts only: the allowlist check is the
    // same one CONNECT targets get, and the binding is what makes this
    // a termination request rather than a 405.
    let binding = shared
        .config
        .secrets
        .iter()
        .find(|b| b.host.eq_ignore_ascii_case(&host));
    if !allowlist_matches(&shared.config.allowlist, &host) || binding.is_none()
    {
        reject(&mut client, &Reject::MethodNotAllowed);
        return;
    }
    let binding = binding.expect("binding checked above");

    let (chunked, content_length) = head_body_framing(&request);
    if chunked {
        // Unsupported framing: the request is refused before any dial.
        conn.record.verdict(Verdict::Error, "malformed-request");
        // API clients send Content-Length; chunked bodies are out of
        // scope for v1 rather than silently mishandled.
        reject(&mut client, &Reject::NotImplemented);
        return;
    }

    // Split head from any body bytes already read (read_request reads
    // in 1 KiB chunks and can overshoot into the body).
    let head_end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(request.len());
    let (head, body_so_far) = request.split_at(head_end);

    // Only the binding for THIS host may substitute: the host check
    // above decides whether this is a termination request; which
    // credentials may appear in it is scoped the same way, or a
    // sandboxed process could exfiltrate KEY_A's real value by sending
    // its placeholder to secret-bound host B.
    let (rewritten, substitutions) =
        crate::secret::rewrite_head(head, std::slice::from_ref(binding));
    let rewritten = force_connection_close(&rewritten);
    if let Some(log) = &shared.config.audit {
        log.record(crate::audit::secret_inject_record(
            &host,
            &binding.key,
            substitutions,
        ));
    }

    conn.record.upstream(&binding.host, port);
    let mut upstream = match tls_connect(&binding.host, port, &shared.config) {
        Ok(stream) => stream,
        Err(why) => {
            let (verdict, reason) = dial_failure_verdict(&why);
            conn.record.verdict(verdict, reason);
            reject(&mut client, &why);
            return;
        }
    };
    conn.register_tcp(&upstream.sock);
    conn.record.verdict(Verdict::Allow, "secret-termination");
    let (up, down) = conn.record.counters();

    // The forwarded head, body bytes already read and the rest of the
    // body all go through one counting reader: the record gets a byte
    // count, never the bytes.
    let body_len = content_length.unwrap_or(0) as usize;
    let write_result = (|| -> io::Result<()> {
        let rest = body_len.saturating_sub(body_so_far.len()) as u64;
        let body_rest: Box<dyn Read> = if rest > 0 {
            Box::new(client.try_clone_stream()?.take(rest))
        } else {
            Box::new(io::empty())
        };
        let mut forwarded = CountingReader::new(
            rewritten.as_slice().chain(body_so_far).chain(body_rest),
            up,
        );
        io::copy(&mut forwarded, &mut upstream)?;
        upstream.flush()?;
        Ok(())
    })();
    if write_result.is_err() {
        return;
    }

    // Upstream closes at the end of the response (Connection: close),
    // which ends this copy and the connection.
    let mut client_writer = client;
    let _ = io::copy(
        &mut CountingReader::new(&mut upstream, down),
        &mut client_writer,
    );
    let _ = client_writer.shutdown_both();
}

/// TLS to the checked upstream: DNS pinning and the SSRF guard are
/// inherited from connect_upstream (resolve once, dial the checked
/// address); the original host name is the TLS SNI/ServerName. Roots
/// are webpki-roots plus the test-only danger_extra_roots knob.
fn tls_connect(
    host: &str,
    port: u16,
    config: &ProxyConfig,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Reject> {
    let tcp = connect_upstream(host, port, config)?;
    let mut roots = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    for der in &config.danger_extra_roots {
        roots.add(der.clone()).map_err(|_| Reject::BadGateway)?;
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| Reject::BadGateway)?;
    let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|_| Reject::BadGateway)?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    // Force the handshake now so a TLS failure is a 502, not a half-
    // written request.
    stream.flush().map_err(|_| Reject::BadGateway)?;
    Ok(stream)
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
pub(crate) fn relay<C: ClientStream, U: ClientStream>(
    client: C,
    upstream: U,
    counters: Option<(Arc<AtomicU64>, Arc<AtomicU64>)>,
) {
    let (client_reader, upstream_reader) =
        match (client.try_clone_stream(), upstream.try_clone_stream()) {
            (Ok(reader), Ok(upstream)) => (reader, upstream),
            _ => return,
        };
    let (up_count, down_count) = counters.unzip();
    let mut client_writer = client;
    let mut upstream_writer = upstream;

    let up = thread::spawn(move || {
        pump(client_reader, &mut upstream_writer, up_count);
        let _ = upstream_writer.shutdown_write();
    });
    let down = thread::spawn(move || {
        pump(upstream_reader, &mut client_writer, down_count);
        let _ = client_writer.shutdown_write();
    });
    let _ = up.join();
    let _ = down.join();
}

/// One direction of [`relay`]. With a counter, every read is counted as
/// it happens, so a reset tunnel keeps the bytes that crossed before it
/// (`io::copy` returns no count on error).
fn pump<R: Read, W: Write>(
    mut reader: R,
    writer: &mut W,
    count: Option<Arc<AtomicU64>>,
) {
    let _ = match count {
        Some(count) => {
            io::copy(&mut CountingReader::new(reader, count), writer)
        }
        None => io::copy(&mut reader, writer),
    };
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
/// emptied explicitly unless loopback is isolated from the host or a
/// `--forward-port` deliberately exposes it. An inherited exclusion must not
/// route around the proxy on macOS, where the host network stack is shared.
pub(crate) fn env_vars(
    port: u16,
    forward_ports: &[u16],
    loopback_is_isolated: bool,
) -> Vec<(String, String)> {
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
    let no_proxy = if loopback_is_isolated || !forward_ports.is_empty() {
        LOOPBACK_NO_PROXY.to_string()
    } else {
        String::new()
    };
    vars.push(("no_proxy".to_string(), no_proxy.clone()));
    vars.push(("NO_PROXY".to_string(), no_proxy));
    vars
}

/// Loopback names exempted when the host cannot be reached through them, or
/// when a named port is deliberately forwarded.
const LOOPBACK_NO_PROXY: &str = "127.0.0.1,localhost,::1";

/// Env var asking the bridge to print `ready` on stdout once bound.
pub(crate) const BRIDGE_READY_ENV: &str = "AI_JAIL_BRIDGE_READY";

/// The in-sandbox bridge end of filtered egress (Linux, phase 3 of
/// docs/connect-proxy-plan.md): listen on 127.0.0.1:<port> inside the
/// private netns and pump each accepted connection to the outer proxy's
/// bind-mounted Unix socket. Connecting to a Unix socket is a
/// filesystem operation, so it does not cross network namespaces.
///
/// Test-only hatch (tests/port_forward.rs), compiled in ONLY under the
/// `test-hooks` feature: hold the bind back so a spawner that does not wait
/// for readiness loses the race every time. Called only for bridges whose
/// spawner waits for them (a `--forward-port` bridge), so it can only delay
/// the launch, never leave the proxy bridge unbound while the agent runs.
#[cfg(feature = "test-hooks")]
fn test_bridge_delay() {
    if let Some(ms) = std::env::var("AI_JAIL_TEST_BRIDGE_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        thread::sleep(Duration::from_millis(ms.min(5_000)));
    }
}

#[cfg(not(feature = "test-hooks"))]
fn test_bridge_delay() {}

/// Runs unrestricted by design: the landlock wrapper spawns this mode
/// before apply_landlock/apply_seccomp, and those only restrict the
/// caller and its future children.
pub(crate) fn run_bridge(port: u16, socket: &Path) -> Result<(), String> {
    let wait_ready = std::env::var_os(BRIDGE_READY_ENV).is_some();
    if wait_ready {
        test_bridge_delay();
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|e| format!("bridge cannot bind 127.0.0.1:{port}: {e}"))?;
    // A spawner that waits for the port (a `--forward-port` bridge) sets
    // this and pipes stdout; the proxy bridge inherits the agent's stdout
    // and must never write to it.
    if wait_ready {
        let mut out = io::stdout();
        out.write_all(b"ready\n")
            .and_then(|()| out.flush())
            .map_err(|e| format!("bridge cannot report readiness: {e}"))?;
    }
    loop {
        let client = accept_next("proxy bridge listener", &mut || {
            listener.accept().map(|(stream, _)| stream)
        });
        let socket = socket.to_path_buf();
        thread::spawn(move || {
            if let Ok(upstream) = UnixStream::connect(&socket) {
                relay(client, upstream, None);
            }
        });
    }
}

/// Fixed path inside the sandbox where the host-side Unix socket of a
/// `--forward-port` is bind-mounted (Linux). One per port, under the
/// same fresh /tmp tmpfs as the proxy socket.
#[cfg(target_os = "linux")]
pub(crate) fn forward_in_sandbox_path(port: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/.ai-jail-forward.{port}.sock"))
}

/// Simultaneous relays one `--forward-port` or `--publish-port` serves;
/// the same bound the egress proxy applies to its tunnels.
#[cfg(target_os = "linux")]
pub(crate) const MAX_FORWARD_CONNECTIONS: usize = 256;

/// Dial loopback on `port`: IPv4 first, then IPv6. A service that binds
/// `localhost` may listen on `::1` only (Node >= 17 dev servers do); the
/// other end of a forward or publish always listens on 127.0.0.1.
#[cfg(target_os = "linux")]
fn connect_loopback(port: u16) -> io::Result<TcpStream> {
    TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .or_else(|_| TcpStream::connect((Ipv6Addr::LOCALHOST, port)))
}

/// Host-side end of a `--forward-port` (Linux): a Unix listener whose
/// every connection is relayed to the host's 127.0.0.1:<port>. Inside
/// the sandbox the same `run_bridge` that serves the proxy listens on
/// 127.0.0.1:<port> and pumps into this socket, so the private netns
/// stays up and only the named port crosses it -- no allowlist, no
/// SSRF guard: forwarding a port is the explicit decision to trust the
/// service behind it.
#[cfg(target_os = "linux")]
pub(crate) struct PortForward {
    port: u16,
    unix_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl PortForward {
    /// Bind the Unix listener (mode 0600) at a per-launch nonce path and
    /// serve it on a dedicated accept thread. A host service that is
    /// down only fails the connection that needed it, as on the host.
    ///
    /// Bounded like the egress proxy: at most [`MAX_FORWARD_CONNECTIONS`]
    /// relays at once (each costs host threads and fds, and the sandbox
    /// decides how many it opens); excess connections are closed. Accept
    /// errors (EMFILE, ECONNABORTED) back off and retry instead of ending
    /// the forward for the rest of the launch.
    pub(crate) fn start(port: u16, verbose: bool) -> io::Result<PortForward> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "ai-jail-forward.{}.{}.{port}.sock",
            std::process::id(),
            nonce
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        )?;
        let active = Arc::new(AtomicUsize::new(0));
        thread::spawn(move || {
            loop {
                let client = accept_next("forward listener", &mut || {
                    listener.accept().map(|(stream, _)| stream)
                });
                if active.fetch_add(1, Ordering::SeqCst)
                    >= MAX_FORWARD_CONNECTIONS
                {
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(client);
                    continue;
                }
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    match connect_loopback(port) {
                        Ok(upstream) => relay(client, upstream, None),
                        Err(e) if verbose => crate::output::verbose(&format!(
                            "forward {port}: host service unreachable: {e}"
                        )),
                        Err(_) => {}
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(PortForward {
            port,
            unix_path: path,
        })
    }

    /// Host loopback port this forward reaches.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Host-side Unix socket path.
    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }
}

#[cfg(target_os = "linux")]
impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.unix_path);
    }
}

/// Fixed path inside the sandbox where the host-side Unix socket of a
/// `--publish-port` is bind-mounted (Linux). One per port, next to the
/// forward sockets on the fresh /tmp tmpfs.
#[cfg(target_os = "linux")]
pub(crate) fn publish_in_sandbox_path(port: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/.ai-jail-publish.{port}.sock"))
}

/// Host-side end of a `--publish-port` (Linux), the mirror of
/// [`PortForward`]: a TCP listener on the host's 127.0.0.1:<port> and a
/// Unix listener the sandbox sees at [`publish_in_sandbox_path`]. The
/// in-sandbox publish bridge connects to the Unix socket once, before
/// the agent runs; every host connection is then handed to it as a file
/// descriptor (SCM_RIGHTS) and relayed to the sandbox's own
/// 127.0.0.1:<port>. The sandbox gains no outbound path: what it
/// receives are streams a host client already opened to it.
#[cfg(target_os = "linux")]
pub(crate) struct PortPublish {
    port: u16,
    unix_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl PortPublish {
    /// Bind 127.0.0.1:<port> on the host (never 0.0.0.0; fails when the
    /// port is taken) and the Unix listener (mode 0600) at a per-launch
    /// nonce path, then hand connections over on a dedicated thread.
    pub(crate) fn start(port: u16, verbose: bool) -> io::Result<PortPublish> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "ai-jail-publish.{}.{}.{port}.sock",
            std::process::id(),
            nonce
        ));
        let _ = std::fs::remove_file(&path);
        let unix = UnixListener::bind(&path)?;
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        )?;
        thread::spawn(move || hand_off_published(tcp, unix, port, verbose));
        Ok(PortPublish {
            port,
            unix_path: path,
        })
    }

    /// Host loopback port this publish listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Host-side Unix socket path.
    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }
}

#[cfg(target_os = "linux")]
impl Drop for PortPublish {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.unix_path);
    }
}

/// Supervisor loop of a `--publish-port`. The first Unix connection from
/// our own uid is the bridge's: the landlock wrapper makes it before it
/// execs the agent. The listener is closed right after, so nothing else
/// in the sandbox can claim the stream later. Host connections that
/// arrive before the bridge wait in the TCP backlog. When the bridge is
/// gone the TCP listener closes and later host connections are refused.
#[cfg(target_os = "linux")]
fn hand_off_published(
    tcp: TcpListener,
    unix: UnixListener,
    port: u16,
    verbose: bool,
) {
    // The socket briefly had umask permissions before its chmod: a peer
    // of another uid that slipped in is dropped, never made the bridge.
    let bridge = loop {
        let peer = accept_next("publish bridge listener", &mut || {
            unix.accept().map(|(stream, _)| stream)
        });
        if peer_uid(&peer).is_ok_and(|uid| uid == nix::unistd::getuid()) {
            break peer;
        }
    };
    drop(unix);
    loop {
        let client = accept_next("publish listener", &mut || {
            tcp.accept().map(|(stream, _)| stream)
        });
        // The supervisor's copy closes when `client` drops; the bridge
        // holds its own. Only a dead bridge ends the publish; any other
        // failure costs just this connection.
        match send_fd(&bridge, &client) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                if verbose {
                    crate::output::verbose(&format!(
                        "publish {port}: the in-sandbox bridge is gone: {e}"
                    ));
                }
                return;
            }
            Err(e) if verbose => crate::output::verbose(&format!(
                "publish {port}: connection dropped: {e}"
            )),
            Err(_) => {}
        }
    }
}

/// Uid of the process at the other end of `stream` (SO_PEERCRED).
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<nix::unistd::Uid> {
    use nix::libc;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, a
    // properly sized and aligned ucred.
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(nix::unistd::Uid::from_raw(cred.uid))
    }
}

/// The in-sandbox end of a `--publish-port` (Linux): connect once to the
/// supervisor's Unix socket mounted at `socket`, then relay every host
/// connection it hands over to 127.0.0.1:<port> in here. Spawned and
/// left unrestricted by the landlock wrapper, like [`run_bridge`]; it
/// only ever dials the sandbox's own loopback.
///
/// Unlike the other bridges it holds sockets of the host's network
/// namespace, which a TCP socket can be disconnected and reconnected
/// from. So it makes itself non-dumpable first: the agent, its parent,
/// has no CAP_SYS_PTRACE in the sandbox's user namespace, and cannot
/// then ptrace it or open its /proc/<pid>/mem, even without Landlock.
#[cfg(target_os = "linux")]
pub(crate) fn run_publish_bridge(
    port: u16,
    socket: &Path,
) -> Result<(), String> {
    // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(format!(
            "publish bridge cannot make itself non-dumpable: {}",
            io::Error::last_os_error()
        ));
    }
    let wait_ready = std::env::var_os(BRIDGE_READY_ENV).is_some();
    if wait_ready {
        test_bridge_delay();
    }
    let control = UnixStream::connect(socket).map_err(|e| {
        format!("publish bridge cannot reach {}: {e}", socket.display())
    })?;
    if wait_ready {
        let mut out = io::stdout();
        out.write_all(b"ready\n")
            .and_then(|()| out.flush())
            .map_err(|e| format!("bridge cannot report readiness: {e}"))?;
    }
    serve_published(&control, port);
    Ok(())
}

/// Relay each descriptor received on `control` to 127.0.0.1:<port>,
/// until the supervisor hangs up. Bounded like the forward path: at most
/// [`MAX_FORWARD_CONNECTIONS`] relays at once, excess connections are
/// closed.
#[cfg(target_os = "linux")]
fn serve_published(control: &UnixStream, port: u16) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let client = match recv_fd(control) {
            Ok(Some(fd)) => TcpStream::from(fd),
            Ok(None) => return,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::InvalidData
                ) =>
            {
                continue;
            }
            Err(_) => return,
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_FORWARD_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(client);
            continue;
        }
        let active = Arc::clone(&active);
        thread::spawn(move || {
            if let Ok(upstream) = connect_loopback(port) {
                relay(client, upstream, None);
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Send one byte carrying `fd` as SCM_RIGHTS ancillary data. std has no
/// stable API for it, and nix's would pull in its `socket` feature.
#[cfg(target_os = "linux")]
fn send_fd(stream: &UnixStream, fd: &impl AsRawFd) -> io::Result<()> {
    use nix::libc;
    let byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    };
    // u64 storage keeps the cmsghdr aligned; 32 bytes hold one fd.
    let mut control = [0_u64; 4];
    let fd_len = std::mem::size_of::<RawFd>() as libc::c_uint;
    loop {
        // SAFETY: `msg` points at `iov` and `control`, both alive for
        // the call; CMSG_SPACE(fd_len) fits in `control`, so the first
        // header and its data are in bounds. sendmsg only reads them.
        let sent = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(fd_len) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_len) as _;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(cmsg).cast::<RawFd>(),
                fd.as_raw_fd(),
            );
            libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL)
        };
        if sent >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receive one byte and the descriptor [`send_fd`] attached to it.
/// `Ok(None)` at end of stream; `InvalidData` for a byte that carried no
/// descriptor. Extra descriptors in one message are closed.
#[cfg(target_os = "linux")]
fn recv_fd(stream: &UnixStream) -> io::Result<Option<OwnedFd>> {
    use nix::libc;
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = [0_u64; 4];
    let mut received = None;
    // SAFETY: `msg` points at `iov` and `control`, both alive for the
    // call. The kernel fills at most `msg_controllen` bytes and the CMSG_*
    // walk stays within what it reports; each SCM_RIGHTS entry is a fresh
    // descriptor this process now owns, so wrapping it in OwnedFd is sound.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let read =
            libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Ok(None);
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET
                && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            {
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                let count = ((*cmsg).cmsg_len as usize
                    - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        data.add(i),
                    ));
                    if received.is_none() {
                        received = Some(fd);
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    received.map(Some).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "no descriptor attached")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_log::{EgressLog, EgressStats};
    use std::sync::mpsc;

    fn entries(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn accept_retries_after_transient_errors() {
        let mut attempts = [
            Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
            Err(io::Error::from(io::ErrorKind::Other)),
            Ok(42_u8),
        ]
        .into_iter();

        let accepted =
            accept_next("test listener", &mut || attempts.next().unwrap());

        assert_eq!(accepted, 42);
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
    fn private_host_grant_is_narrow_and_keeps_sensitive_ranges_denied() {
        let mut config = ProxyConfig::new(entries(&["gitlab.example.com"]));
        config.allow_private_hosts = entries(&["gitlab.example.com"]);

        for addr in ["10.1.2.3", "192.168.1.4", "100.64.1.2", "fd00::1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(address_is_allowed("gitlab.example.com", &ip, &config));
            assert!(address_is_allowed("ci.gitlab.example.com", &ip, &config));
            assert!(!address_is_allowed("other.example.com", &ip, &config));
        }
        for addr in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.169.254",
            "169.254.1.2",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!address_is_allowed("gitlab.example.com", &ip, &config));
        }
        assert!(address_is_allowed(
            "gitlab.example.com",
            &"93.184.216.34".parse().unwrap(),
            &config
        ));
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

    /// Fake host prompt: gives `answer`, counts calls, records the
    /// internal addresses each call was shown, and holds each answer for
    /// `delay` so concurrent connections overlap.
    struct FakePrompt {
        answer: PromptAnswer,
        delay: Duration,
        calls: AtomicUsize,
        internal_seen: Mutex<Vec<Vec<IpAddr>>>,
    }

    impl FakePrompt {
        fn new(answer: PromptAnswer, delay: Duration) -> Arc<FakePrompt> {
            Arc::new(FakePrompt {
                answer,
                delay,
                calls: AtomicUsize::new(0),
                internal_seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl HostPrompt for FakePrompt {
        fn ask(
            &self,
            _host: &str,
            _port: u16,
            internal: &[IpAddr],
        ) -> PromptAnswer {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.internal_seen.lock().unwrap().push(internal.to_vec());
            thread::sleep(self.delay);
            self.answer
        }
    }

    fn prompted_proxy(
        answer: PromptAnswer,
        delay: Duration,
    ) -> (Proxy, Arc<FakePrompt>) {
        let prompt = FakePrompt::new(answer, delay);
        let mut config = test_config(&["example.com"]);
        config.prompt = Some(Arc::clone(&prompt) as Arc<dyn HostPrompt>);
        (Proxy::start(config, None).unwrap(), prompt)
    }

    #[test]
    fn e2e_prompt_no_answer_denies_but_asks_again() {
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::NoAnswer, Duration::ZERO);
        for _ in 0..2 {
            let stream = connect_and_send(
                proxy.port(),
                &connect_request("203.0.113.5:443"),
            );
            assert_eq!(
                read_reply_head(&stream),
                "HTTP/1.1 403 Forbidden\r\n\r\n"
            );
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn e2e_concurrent_connections_share_one_unanswered_prompt() {
        // Connections waiting on a prompt that goes unanswered are denied
        // with it rather than each re-asking at once.
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::NoAnswer, Duration::from_millis(300));
        let port = proxy.port();
        let clients: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(move || {
                    let stream = connect_and_send(
                        port,
                        &connect_request("203.0.113.5:443"),
                    );
                    read_reply_head(&stream)
                })
            })
            .collect();
        for client in clients {
            assert_eq!(
                client.join().unwrap(),
                "HTTP/1.1 403 Forbidden\r\n\r\n"
            );
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);
    }

    /// Like [`prompted_proxy`] but with the real SSRF guard, so private
    /// and loopback answers are classified as they are in production.
    fn guarded_prompted_proxy(
        answer: PromptAnswer,
    ) -> (Proxy, Arc<FakePrompt>) {
        let prompt = FakePrompt::new(answer, Duration::ZERO);
        let mut config = ProxyConfig::new(Vec::new());
        config.connect_timeout = Duration::from_millis(200);
        config.prompt = Some(Arc::clone(&prompt) as Arc<dyn HostPrompt>);
        (Proxy::start(config, None).unwrap(), prompt)
    }

    #[test]
    fn e2e_prompt_shows_internal_addresses() {
        let (proxy, prompt) = guarded_prompted_proxy(PromptAnswer::Deny);
        let stream =
            connect_and_send(proxy.port(), &connect_request("10.1.2.3:443"));
        assert_eq!(read_reply_head(&stream), "HTTP/1.1 403 Forbidden\r\n\r\n");
        let seen = prompt.internal_seen.lock().unwrap();
        assert_eq!(*seen, vec![vec!["10.1.2.3".parse::<IpAddr>().unwrap()]]);
    }

    #[test]
    fn e2e_prompt_shows_no_internal_address_for_public_hosts() {
        let (proxy, prompt) = guarded_prompted_proxy(PromptAnswer::Deny);
        let stream =
            connect_and_send(proxy.port(), &connect_request("203.0.113.5:443"));
        assert_eq!(read_reply_head(&stream), "HTTP/1.1 403 Forbidden\r\n\r\n");
        let seen = prompt.internal_seen.lock().unwrap();
        assert_eq!(*seen, vec![Vec::<IpAddr>::new()]);
    }

    #[test]
    fn e2e_prompt_never_offers_loopback_or_metadata() {
        let (proxy, prompt) = guarded_prompted_proxy(PromptAnswer::Allow);
        for target in ["127.0.0.1:80", "169.254.169.254:80", "[::1]:80"] {
            let stream =
                connect_and_send(proxy.port(), &connect_request(target));
            assert_eq!(
                read_reply_head(&stream),
                "HTTP/1.1 403 Forbidden address range\r\n\r\n",
                "{target}"
            );
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn e2e_prompt_unresolvable_host_is_not_asked() {
        let (proxy, prompt) = guarded_prompted_proxy(PromptAnswer::Allow);
        let stream = connect_and_send(
            proxy.port(),
            &connect_request("ai-jail-no-such-host.invalid:443"),
        );
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 502 Bad Gateway\r\n\r\n"
        );
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn approved_internal_host_dials_only_grantable_ranges() {
        let config = ProxyConfig::new(Vec::new());
        let private: IpAddr = "10.1.2.3".parse().unwrap();
        let cgnat: IpAddr = "100.64.0.1".parse().unwrap();
        let public: IpAddr = "203.0.113.5".parse().unwrap();
        for ip in [private, cgnat, public] {
            assert!(dialable("h.test", &ip, &config, true), "{ip}");
        }
        assert!(!dialable("h.test", &private, &config, false));
        assert!(!dialable("h.test", &cgnat, &config, false));
        assert!(dialable("h.test", &public, &config, false));
        for never in
            ["127.0.0.1", "169.254.169.254", "::1", "fe80::1", "0.0.0.0"]
        {
            let ip: IpAddr = never.parse().unwrap();
            assert!(!dialable("h.test", &ip, &config, true), "{never}");
        }
    }

    #[test]
    fn e2e_prompt_allow_tunnels_and_is_remembered() {
        let echo = echo_server();
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::Allow, Duration::ZERO);
        let request = connect_request(&format!("127.0.0.1:{echo}"));
        for _ in 0..2 {
            let stream = connect_and_send(proxy.port(), &request);
            assert_eq!(read_reply_head(&stream), REPLY_OK);
            (&stream).write_all(b"ping").unwrap();
            let mut buf = [0_u8; 4];
            (&mut &stream).read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn e2e_prompt_deny_is_403_and_never_asked_again() {
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::Deny, Duration::ZERO);
        for _ in 0..2 {
            let stream = connect_and_send(
                proxy.port(),
                &connect_request("203.0.113.5:443"),
            );
            assert_eq!(
                read_reply_head(&stream),
                "HTTP/1.1 403 Forbidden\r\n\r\n"
            );
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn e2e_prompt_decision_is_per_host_case_insensitive() {
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::Deny, Duration::ZERO);
        // Names that resolve offline: /etc/hosts maps localhost.
        for host in ["LocalHost:443", "localhost:80", "203.0.113.5:443"] {
            let stream = connect_and_send(proxy.port(), &connect_request(host));
            read_reply_head(&stream);
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn e2e_concurrent_connections_share_one_prompt() {
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::Deny, Duration::from_millis(300));
        let port = proxy.port();
        let clients: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(move || {
                    let stream = connect_and_send(
                        port,
                        &connect_request("203.0.113.5:443"),
                    );
                    read_reply_head(&stream)
                })
            })
            .collect();
        for client in clients {
            assert_eq!(
                client.join().unwrap(),
                "HTTP/1.1 403 Forbidden\r\n\r\n"
            );
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn e2e_prompt_skips_hosts_with_unexpected_characters() {
        let (proxy, prompt) =
            prompted_proxy(PromptAnswer::Allow, Duration::ZERO);
        for host in ["<b>evil</b>:443", "a b.test:443", "x&y.test:443"] {
            let stream = connect_and_send(proxy.port(), &connect_request(host));
            read_reply_head(&stream);
        }
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn e2e_prompt_is_not_asked_for_allowlisted_hosts() {
        let echo = echo_server();
        let prompt = FakePrompt::new(PromptAnswer::Deny, Duration::ZERO);
        let mut config = test_config(&["127.0.0.1"]);
        config.prompt = Some(Arc::clone(&prompt) as Arc<dyn HostPrompt>);
        let proxy = Proxy::start(config, None).unwrap();
        let stream = connect_and_send(
            proxy.port(),
            &connect_request(&format!("127.0.0.1:{echo}")),
        );
        assert_eq!(read_reply_head(&stream), REPLY_OK);
        assert_eq!(prompt.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn notify_text_calls_out_internal_hosts_with_their_addresses() {
        let (summary, body) = notify_text("claude", "example.com", 443, &[]);
        assert_eq!(summary, "ai-jail: claude wants to reach a new host");
        assert_eq!(body, "example.com:443");

        let (summary, _) =
            notify_text("<b>trusted agent</b>\nAllow", "example.com", 443, &[]);
        assert_eq!(
            summary,
            "ai-jail: the sandboxed command wants to reach a new host"
        );

        let internal: Vec<IpAddr> =
            vec!["10.0.0.5".parse().unwrap(), "fd00::5".parse().unwrap()];
        let (summary, body) =
            notify_text("claude", "gitlab.lan", 443, &internal);
        assert!(summary.contains("INTERNAL"));
        assert_eq!(body, "gitlab.lan:443\nInternal address: 10.0.0.5, fd00::5");
    }

    fn fake_notify_trapping_int(
        tag: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir()
            .join(format!("ai-jail-notify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let script = root.join("notify-send");
        let closed = root.join("closed");
        let ready = root.join("ready");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntrap 'printf closed > \"{}\" ; exit 3' INT\nprintf ready > \"{}\"\nwhile :; do sleep 0.05; done\n",
                closed.display(),
                ready.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        (script, closed, ready)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unanswered_prompt_is_closed_with_sigint_not_killed() {
        let (script, closed, _ready) = fake_notify_trapping_int("deadline");
        let prompt = NotifySendPrompt {
            program: script,
            label: "claude".into(),
            timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let answer = prompt.ask("example.test", 443, &[]);
        assert_eq!(answer, PromptAnswer::NoAnswer);
        assert!(started.elapsed() < Duration::from_secs(5));
        // libnotify closes its notification on SIGINT; SIGKILL would not,
        // so the trap firing is the assertion that matters.
        assert!(closed.is_file(), "notify-send did not receive SIGINT");
        let _ = std::fs::remove_dir_all(closed.parent().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exit_closes_notifications_still_waiting() {
        use std::os::unix::fs::PermissionsExt;
        let (script, closed, ready) = fake_notify_trapping_int("shutdown");
        let mut child = Command::new(&script).spawn().unwrap();
        // Wait for the trap to be installed: a SIGINT that arrives first
        // kills the shell by default action and writes nothing.
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() && Instant::now() < ready_deadline {
            thread::sleep(NOTIFY_POLL);
        }
        assert!(ready.is_file(), "fake notify-send did not start");
        register_prompt(nix::unistd::Pid::from_raw(child.id() as i32));
        close_pending_prompts();
        let deadline = Instant::now() + Duration::from_secs(5);
        let exited = loop {
            if let Ok(Some(_)) = child.try_wait() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(NOTIFY_POLL);
        };
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o700),
        );
        assert!(exited, "pending notify-send was not interrupted on exit");
        assert!(closed.is_file(), "notification was not closed on exit");
        let _ = std::fs::remove_dir_all(closed.parent().unwrap());
    }

    #[test]
    fn notify_reply_maps_actions_and_treats_the_rest_as_no_answer() {
        assert_eq!(notify_reply("allow\n"), PromptAnswer::Allow);
        assert_eq!(notify_reply("allow"), PromptAnswer::Allow);
        assert_eq!(notify_reply("deny\n"), PromptAnswer::Deny);
        // Dismissed or expired: notify-send prints nothing.
        assert_eq!(notify_reply(""), PromptAnswer::NoAnswer);
        assert_eq!(notify_reply("allowed\n"), PromptAnswer::NoAnswer);
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
    fn e2e_audit_records_prompt_verdicts() {
        let echo = echo_server();
        let home = std::env::temp_dir().join(format!(
            "ai-jail-proxy-prompt-audit-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let log = crate::audit::AuditLog::open(&home).unwrap();

        let mut config = test_config(&[]);
        config.audit = Some(log);
        config.prompt =
            Some(FakePrompt::new(PromptAnswer::Allow, Duration::ZERO));
        let proxy = Proxy::start(config, None).unwrap();
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
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(record["verdict"], "allow");
        assert_eq!(record["reason"], "prompt-allow");
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
        assert_eq!(proxy.tcp_port(), None);
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
    fn parse_absolute_form_table() {
        assert_eq!(
            parse_absolute_form(b"GET http://example.com/x HTTP/1.1\r\n\r\n"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_absolute_form(
                b"POST http://127.0.0.1:8080/v1 HTTP/1.1\r\n\r\n"
            ),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            parse_absolute_form(b"GET http://[::1]:8443/ HTTP/1.0\r\n\r\n"),
            Some(("::1".to_string(), 8443))
        );
        for buf in [
            &b"GET /origin-form HTTP/1.1\r\n\r\n"[..],
            b"GET https://example.com/ HTTP/1.1\r\n\r\n",
            b"GET http://example.com HTTP/2\r\n\r\n",
            b"GET http://:8080/ HTTP/1.1\r\n\r\n",
            b"GET http://example.com:0/ HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_absolute_form(buf).is_none(), "{buf:?}");
        }
    }

    #[test]
    fn head_body_framing_parses_content_length_and_chunked() {
        let (chunked, len) =
            head_body_framing(b"POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n");
        assert!(!chunked);
        assert_eq!(len, Some(42));
        let (chunked, len) = head_body_framing(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert!(chunked);
        assert_eq!(len, None);
        let (chunked, len) = head_body_framing(b"GET / HTTP/1.1\r\n\r\n");
        assert!(!chunked);
        assert_eq!(len, None);
    }

    #[test]
    fn head_body_framing_ignores_bytes_after_the_header_terminator() {
        for body in [
            b"\xff\x00\xfe".as_slice(),
            b"Transfer-Encoding: chunked\r\n".as_slice(),
            b"Content-Length: 99999\r\n".as_slice(),
        ] {
            let mut request = format!(
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(body);
            assert_eq!(
                head_body_framing(&request),
                (false, Some(body.len() as u64))
            );
        }
    }

    #[test]
    fn force_connection_close_rewrites_and_appends() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let out = force_connection_close(head);
        assert_eq!(
            out,
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let head = b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
        let out = force_connection_close(head);
        assert_eq!(out, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert_eq!(out.windows(4).filter(|w| *w == b"\r\n\r\n").count(), 1);
    }

    /// TLS fixture: the test-only self-signed cert from
    /// tests/fixtures, serving the received x-test-key header back in
    /// the response body.
    fn tls_fixture() -> u16 {
        use rustls::pki_types::pem::PemObject;
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let cert = rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(format!("{dir}/test-only-cert.pem")).unwrap(),
        )
        .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            &std::fs::read(format!("{dir}/test-only-key.pem")).unwrap(),
        )
        .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming().map_while(Result::ok) {
                let config = Arc::clone(&config);
                thread::spawn(move || {
                    let Ok(server_conn) = rustls::ServerConnection::new(config)
                    else {
                        return;
                    };
                    let mut tls = rustls::StreamOwned::new(server_conn, conn);
                    let mut buf = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    loop {
                        match tls.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let value = head
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, v)| {
                                name.trim()
                                    .eq_ignore_ascii_case("x-test-key")
                                    .then(|| v.trim().to_string())
                            })
                        })
                        .unwrap_or_default();
                    let body = format!("key={value}");
                    let _ = tls.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                             Connection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        port
    }

    fn fixture_root() -> rustls::pki_types::CertificateDer<'static> {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/test-only-cert.pem"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn e2e_http_termination_substitutes_secret_over_tls() {
        let fixture = tls_fixture();
        let binding = crate::secret::SecretBinding::new(
            "X_KEY",
            "real-secret",
            "127.0.0.1",
        );
        let placeholder = binding.placeholder.clone();
        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding];
        config.danger_extra_roots = vec![fixture_root()];
        let proxy = Proxy::start(config, None).unwrap();

        let request = format!(
            "GET http://127.0.0.1:{fixture}/v1/test HTTP/1.1\r\n\
             Host: 127.0.0.1:{fixture}\r\n\
             x-test-key: {placeholder}\r\n\
             \r\n"
        );
        let stream = connect_and_send(proxy.port(), request.as_bytes());
        let mut response = Vec::new();
        (&mut &stream).read_to_end(&mut response).unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        // The real value reached the fixture; the placeholder did not.
        assert!(response.contains("key=real-secret"), "{response}");
        assert!(!response.contains(&placeholder), "{response}");
    }

    #[test]
    fn e2e_http_termination_substitutes_only_the_matched_host_binding() {
        // Two bindings, KEY_A -> host A (the fixture) and KEY_B ->
        // host B. A request to host A carrying KEY_B's placeholder must
        // pass it through untouched: substitution is host-scoped, or a
        // sandboxed process could exfiltrate A's credential by sending
        // its placeholder to secret-bound host B.
        let fixture = tls_fixture();
        let binding_a =
            crate::secret::SecretBinding::new("KEY_A", "real-a", "127.0.0.1");
        let placeholder_a = binding_a.placeholder.clone();
        let binding_b =
            crate::secret::SecretBinding::new("KEY_B", "real-b", "127.0.0.2");
        let placeholder_b = binding_b.placeholder.clone();

        let home = std::env::temp_dir()
            .join(format!("ai-jail-proxy-scope-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let log = crate::audit::AuditLog::open(&home).unwrap();

        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding_a, binding_b];
        config.danger_extra_roots = vec![fixture_root()];
        config.audit = Some(log);
        let proxy = Proxy::start(config, None).unwrap();

        let request = format!(
            "GET http://127.0.0.1:{fixture}/ HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             x-test-key: {placeholder_b}\r\n\
             x-test-key-a: {placeholder_a}\r\n\
             \r\n"
        );
        let stream = connect_and_send(proxy.port(), request.as_bytes());
        let mut response = Vec::new();
        (&mut &stream).read_to_end(&mut response).unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        // KEY_B's placeholder reached host A untouched; its real value
        // is nowhere in the exchange.
        assert!(
            response.contains(&format!("key={placeholder_b}")),
            "{response}"
        );
        assert!(!response.contains("real-b"), "{response}");
        drop(proxy);

        // The audit record shows exactly one substitution -- KEY_A's
        // placeholder in x-test-key-a -- not two.
        let content = std::fs::read_to_string(
            home.join(".local/share/ai-jail/history.jsonl"),
        )
        .unwrap();
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(record["type"], "secret_inject");
        assert_eq!(record["key"], "KEY_A");
        assert_eq!(record["substitutions"], 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn egress_line_names_both_ends_of_a_secret_termination_and_no_secret() {
        let fixture = tls_fixture();
        let binding = crate::secret::SecretBinding::new(
            "X_KEY",
            "real-secret",
            "127.0.0.1",
        );
        let placeholder = binding.placeholder.clone();
        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding];
        config.danger_extra_roots = vec![fixture_root()];
        let h = harness("secret-ends", config);

        let request = format!(
            "GET http://127.0.0.1:{fixture}/v1/test HTTP/1.1\r\n\
             Host: 127.0.0.1:{fixture}\r\n\
             x-test-key: {placeholder}\r\n\
             \r\n"
        );
        let stream = connect_and_send(h.proxy.port(), request.as_bytes());
        let mut response = Vec::new();
        (&mut &stream).read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));

        let got = wait_lines(&h.path, 1);
        let line = &got[0];
        assert_eq!(line["reason"], "secret-termination", "{line}");
        assert_eq!(line["host"], "127.0.0.1", "{line}");
        assert_eq!(line["port"], fixture, "{line}");
        assert_eq!(line["upstream_host"], "127.0.0.1", "{line}");
        assert_eq!(line["upstream_port"], fixture, "{line}");
        let raw = std::fs::read_to_string(&h.path).unwrap();
        for leaked in ["real-secret", placeholder.as_str(), "X_KEY", "/v1/test"]
        {
            assert!(!raw.contains(leaked), "{leaked} in {raw}");
        }
    }

    #[test]
    fn e2e_http_absolute_form_non_secret_host_is_405() {
        // Allowlisted but not secret-bound: no termination, today's 405.
        let proxy = Proxy::start(test_config(&["127.0.0.1"]), None).unwrap();
        let stream = connect_and_send(
            proxy.port(),
            b"GET http://127.0.0.1:1/ HTTP/1.1\r\n\r\n",
        );
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
        );
        // Origin-form stays 405 even for a secret-bound host.
        let binding =
            crate::secret::SecretBinding::new("X_KEY", "real", "127.0.0.1");
        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding];
        let proxy = Proxy::start(config, None).unwrap();
        let stream = connect_and_send(proxy.port(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
        );
    }

    #[test]
    fn e2e_http_termination_rejects_chunked_with_501() {
        let fixture = tls_fixture();
        let binding =
            crate::secret::SecretBinding::new("X_KEY", "real", "127.0.0.1");
        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding];
        config.danger_extra_roots = vec![fixture_root()];
        let proxy = Proxy::start(config, None).unwrap();
        let request = format!(
            "POST http://127.0.0.1:{fixture}/ HTTP/1.1\r\n\
             Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        );
        let stream = connect_and_send(proxy.port(), request.as_bytes());
        assert_eq!(
            read_reply_head(&stream),
            "HTTP/1.1 501 Not Implemented\r\n\r\n"
        );
    }

    #[test]
    fn http_termination_accepts_header_like_text_in_the_body() {
        let fixture = tls_fixture();
        let binding = crate::secret::SecretBinding::new(
            "X_KEY",
            "synthetic",
            "127.0.0.1",
        );
        let placeholder = binding.placeholder.clone();
        let mut config = test_config(&["127.0.0.1"]);
        config.secrets = vec![binding];
        config.danger_extra_roots = vec![fixture_root()];
        let shared = Arc::new(Shared::new(config));
        let body = "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n";
        // Supply the read-ahead bytes explicitly so the regression does not
        // depend on whether TCP delivers headers and body in the same read.
        let request = format!(
            "POST http://127.0.0.1:{fixture}/upload HTTP/1.1\r\n\
             Host: 127.0.0.1:{fixture}\r\n\
             x-test-key: {placeholder}\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let handler = thread::spawn(move || {
            let (mut conn, _) = Conn::begin(&shared, Shared::admit(&shared));
            handle_http_termination(
                server,
                ("127.0.0.1".into(), fixture),
                request,
                &shared,
                &mut conn,
            );
        });
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        handler.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("key=synthetic"), "{response}");
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
        assert_eq!(proxy.tcp_port(), None);

        let bridge_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bridge_port = bridge_listener.local_addr().unwrap().port();
        let bridge_socket = path.clone();
        let bridge = thread::spawn(move || {
            for client in bridge_listener.incoming().map_while(Result::ok) {
                let socket = bridge_socket.clone();
                thread::spawn(move || {
                    if let Ok(upstream) = UnixStream::connect(&socket) {
                        relay(client, upstream, None);
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

    #[cfg(target_os = "linux")]
    fn free_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publish_hands_host_connections_to_the_bridge() {
        // The jailed service: greets and hangs up.
        let service = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let service_port = service.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut conn in service.incoming().map_while(Result::ok) {
                let _ = conn.write_all(b"hello");
            }
        });
        let host_port = free_loopback_port();
        let publish = PortPublish::start(host_port, false).unwrap();
        let control = UnixStream::connect(publish.unix_path()).unwrap();
        thread::spawn(move || serve_published(&control, service_port));

        for _ in 0..3 {
            let mut client =
                TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).unwrap();
            assert_eq!(reply, "hello");
        }
        // Only the bridge's own connection was ever accepted.
        assert!(UnixStream::connect(publish.unix_path()).is_err());
        let path = publish.unix_path().to_path_buf();
        drop(publish);
        assert!(!path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publish_refuses_host_connections_once_the_bridge_is_gone() {
        let host_port = free_loopback_port();
        let publish = PortPublish::start(host_port, false).unwrap();
        drop(UnixStream::connect(publish.unix_path()).unwrap());
        let refused = (0..100).any(|_| {
            if TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).is_err() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
            false
        });
        assert!(refused, "host port still accepting without a bridge");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publish_refuses_a_taken_host_port() {
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        assert!(PortPublish::start(port, false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recv_fd_rejects_a_byte_without_descriptor() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"x").unwrap();
        let error = recv_fd(&receiver).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(sender);
        assert!(recv_fd(&receiver).unwrap().is_none());
    }

    // ── egress log ──────────────────────────────
    // Egress-log wiring: one line per accepted connection with the verdict
    // and its reason, and the drain on exit only when a log was asked for
    // (`ProxyConfig::egress`, `ProxyConfig::stats`).

    struct Harness {
        proxy: Proxy,
        path: PathBuf,
        dir: PathBuf,
        stats: Arc<EgressStats>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn harness(name: &str, mut config: ProxyConfig) -> Harness {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-proxy-egress-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress.jsonl");
        let log = EgressLog::open(&path, &crate::egress_log::run_id().unwrap())
            .unwrap();
        let stats = Arc::new(EgressStats::default());
        config.egress = Some(Arc::new(log));
        config.stats = Arc::clone(&stats);
        // Setup: a proxy with an egress log is one the run drains.
        config.drain_on_exit = true;
        let proxy = Proxy::start(config, None).unwrap();
        Harness {
            proxy,
            path,
            dir,
            stats,
        }
    }

    fn private_config(allowlist: &[&str]) -> ProxyConfig {
        let mut config =
            ProxyConfig::new(allowlist.iter().map(|s| s.to_string()).collect());
        config.danger_allow_private = true;
        config
    }

    fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("line is JSON"))
            .collect()
    }

    /// Wait until the log holds `n` lines, then make sure no extra line
    /// follows (exactly one line per connection).
    fn wait_lines(path: &std::path::Path, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let got = lines(path);
            if got.len() >= n {
                std::thread::sleep(Duration::from_millis(150));
                let got = lines(path);
                assert_eq!(got.len(), n, "exactly {n} line(s): {got:?}");
                return got;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {n} lines",
                got.len()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send(port: u16, request: &[u8]) -> TcpStream {
        let s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (&s).write_all(request).unwrap();
        s
    }

    fn read_head(s: &TcpStream) -> String {
        let mut buf = Vec::new();
        let mut c = [0_u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            match (&mut &*s).read(&mut c) {
                Ok(0) | Err(_) => break,
                Ok(_) => buf.push(c[0]),
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn free_port() -> u16 {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        l.local_addr().unwrap().port()
    }

    fn assert_error(line: &serde_json::Value, reason: &str, host_null: bool) {
        assert_eq!(line["verdict"], "error", "{line}");
        assert_eq!(line["reason"], reason, "{line}");
        assert_eq!(line["host"].is_null(), host_null, "{line}");
        assert_eq!(line["bytes_up"], 0, "{line}");
        assert_eq!(line["bytes_down"], 0, "{line}");
    }

    #[test]
    fn every_early_exit_writes_exactly_one_error_line() {
        let h = harness("early", private_config(&["127.0.0.1"]));
        let port = h.proxy.port();

        // malformed request (no port): no target parsed -> host null
        let s = send(port, b"CONNECT example.com HTTP/1.1\r\n\r\n");
        assert!(read_head(&s).contains("400"));
        let got = wait_lines(&h.path, 1);
        assert_error(&got[0], "malformed-request", true);

        // method not allowed
        let s = send(port, b"GET / HTTP/1.1\r\n\r\n");
        assert!(read_head(&s).contains("405"));
        let got = wait_lines(&h.path, 2);
        assert_error(&got[1], "method-not-allowed", true);

        // request too large
        let mut big = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'A', REQUEST_CAP));
        let s = send(port, &big);
        assert!(read_head(&s).contains("431"));
        let got = wait_lines(&h.path, 3);
        assert_error(&got[2], "request-too-large", true);

        // client read failure: connect and close without a request
        let s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        s.shutdown(Shutdown::Both).unwrap();
        drop(s);
        let got = wait_lines(&h.path, 4);
        assert_error(&got[3], "client-read-failed", true);

        // upstream unreachable: the target WAS parsed, so the host stays
        let dead = free_port();
        let s = send(
            port,
            format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert!(read_head(&s).contains("502"));
        let got = wait_lines(&h.path, 5);
        assert_error(&got[4], "upstream-unreachable", false);
        assert_eq!(got[4]["host"], "127.0.0.1");
        assert_eq!(got[4]["port"], dead);

        assert_eq!(h.stats.snapshot().errored, 5);
    }

    #[test]
    fn connection_cap_is_an_error_line() {
        let mut config = private_config(&["127.0.0.1"]);
        config.max_connections = 0;
        let h = harness("cap", config);
        let s = send(h.proxy.port(), b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&s).contains("503"));
        let got = wait_lines(&h.path, 1);
        assert_error(&got[0], "connection-cap", true);
    }

    #[test]
    fn policy_refusals_are_deny_lines_written_at_refusal_time() {
        // Two hostile shapes of "deny": not allowlisted, and allowlisted but
        // in a forbidden range (SSRF guard on: no danger_allow_private).
        let h =
            harness("deny", ProxyConfig::new(vec!["127.0.0.1".to_string()]));
        let port = h.proxy.port();
        let held_a = send(port, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&held_a).contains("403"));
        // The client still holds its socket: the line exists already.
        let got = wait_lines(&h.path, 1);
        assert_eq!(got[0]["verdict"], "deny");
        assert_eq!(got[0]["reason"], "not-in-allowlist");
        assert_eq!(got[0]["host"], "evil.example");
        assert_eq!(got[0]["port"], 443);
        assert_eq!(got[0]["bytes_up"], 0);
        assert_eq!(got[0]["bytes_down"], 0);

        let held_b = send(port, b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n");
        assert!(read_head(&held_b).contains("403"));
        let got = wait_lines(&h.path, 2);
        assert_eq!(got[1]["verdict"], "deny");
        assert_eq!(got[1]["reason"], "forbidden-address-range");
        assert_eq!(got[1]["host"], "127.0.0.1");
        let t = h.stats.snapshot();
        assert_eq!((t.allowed, t.denied, t.errored), (0, 2, 0));
        drop((held_a, held_b));
    }

    #[test]
    fn allowed_tunnel_counts_only_tunneled_bytes() {
        // Neither the CONNECT request nor REPLY_OK may be
        // counted as upstream traffic.
        let echo = echo_server();
        let h = harness("allow", private_config(&["127.0.0.1"]));
        let s = send(
            h.proxy.port(),
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&s), REPLY_OK);
        (&s).write_all(b"hello").unwrap();
        let mut buf = [0_u8; 5];
        (&mut &s).read_exact(&mut buf).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        let _ = (&mut &s).read_to_end(&mut rest);
        drop(s);
        let got = wait_lines(&h.path, 1);
        assert_eq!(got[0]["verdict"], "allow");
        assert_eq!(got[0]["reason"], "in-allowlist");
        assert_eq!(got[0]["host"], "127.0.0.1");
        assert_eq!(got[0]["port"], echo);
        assert_eq!(got[0]["bytes_up"], 5);
        assert_eq!(got[0]["bytes_down"], 5);
        let t = h.stats.snapshot();
        assert_eq!((t.allowed, t.bytes_up, t.bytes_down), (1, 5, 5));
    }

    #[test]
    fn bytes_survive_an_upstream_reset() {
        // io::copy returns Err with no count on a reset: the counting reader
        // must still report what crossed before it.
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let up_port = l.local_addr().unwrap().port();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut ping = [0_u8; 4];
            s.read_exact(&mut ping).unwrap();
            s.write_all(&[b'x'; 1000]).unwrap();
            let _ = go_rx.recv_timeout(Duration::from_secs(5));
            // SO_LINGER 0 turns close into a RST.
            let linger = nix::libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: `s` is an open socket this thread owns, and `linger`
            // outlives the call that copies it.
            let rc = unsafe {
                nix::libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&s),
                    nix::libc::SOL_SOCKET,
                    nix::libc::SO_LINGER,
                    (&linger as *const nix::libc::linger).cast(),
                    std::mem::size_of::<nix::libc::linger>()
                        as nix::libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "SO_LINGER must hold, or the close is no reset");
            drop(s);
        });
        let h = harness("reset", private_config(&["127.0.0.1"]));
        let s = send(
            h.proxy.port(),
            format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&s), REPLY_OK);
        (&s).write_all(b"ping").unwrap();
        let mut got = vec![0_u8; 1000];
        (&mut &s).read_exact(&mut got).unwrap();
        go_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        drop(s);
        let lines = wait_lines(&h.path, 1);
        assert_eq!(lines[0]["bytes_up"], 4, "{}", lines[0]);
        assert_eq!(lines[0]["bytes_down"], 1000, "{}", lines[0]);
    }

    #[test]
    fn no_request_content_reaches_the_line() {
        let echo = echo_server();
        let h = harness("content", private_config(&["127.0.0.1"]));
        let port = h.proxy.port();
        // 405 path with a path, query and a credential header.
        let s = send(
            port,
            b"GET http://127.0.0.1:1/secret/path?token=hunter2 HTTP/1.1\r\n\
          Authorization: Bearer hunter2\r\n\r\n",
        );
        let _ = read_head(&s);
        // malformed path carrying content
        let s2 = send(
            port,
            b"BREW /leak?q=hunter2 HTCPCP/9\r\nX-Key: hunter2\r\n\r\n",
        );
        let _ = read_head(&s2);
        // allowed tunnel with proxy headers and tunneled payload
        let s3 = send(
            port,
            format!(
                "CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n\
             Proxy-Authorization: Basic aHVudGVyMg==\r\n\r\n"
            )
            .as_bytes(),
        );
        assert_eq!(read_head(&s3), REPLY_OK);
        (&s3)
            .write_all(b"GET /tunnel?token=hunter2 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut b = [0_u8; 8];
        let _ = (&mut &s3).read(&mut b);
        drop((s, s2, s3));
        wait_lines(&h.path, 3);
        let raw = std::fs::read_to_string(&h.path).unwrap();
        for needle in [
            "hunter2",
            "aHVudGVyMg",
            "secret",
            "token",
            "leak",
            "Bearer",
            "/",
        ] {
            assert!(!raw.contains(needle), "{needle:?} leaked: {raw}");
        }
    }

    #[test]
    fn without_an_egress_log_audit_records_are_unchanged_and_stats_still_count()
    {
        // no egress line, and the audit `connect` records keep their
        // exact shape; the run-wide counters still count.
        let echo = echo_server();
        let home = std::env::temp_dir()
            .join(format!("ai-jail-proxy-egress-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let audit = crate::audit::AuditLog::open(&home).unwrap();
        let stats = Arc::new(EgressStats::default());
        let mut config = private_config(&["127.0.0.1"]);
        config.audit = Some(audit);
        config.stats = Arc::clone(&stats);
        assert!(config.egress.is_none(), "no egress log unless asked");
        let proxy = Proxy::start(config, None).unwrap();
        let d = send(proxy.port(), b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&d).contains("403"));
        let a = send(
            proxy.port(),
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&a), REPLY_OK);
        drop((a, d));
        let deadline = Instant::now() + Duration::from_secs(10);
        while stats.snapshot().allowed + stats.snapshot().denied < 2 {
            assert!(Instant::now() < deadline, "stats never counted");
            std::thread::sleep(Duration::from_millis(20));
        }
        let content = std::fs::read_to_string(
            home.join(".local/share/ai-jail/history.jsonl"),
        )
        .unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|v: &serde_json::Value| v["type"] == "connect")
            .collect();
        assert_eq!(records.len(), 2);
        for r in &records {
            for key in ["bytes_up", "bytes_down", "duration_ms", "run_id", "v"]
            {
                assert!(r.get(key).is_none(), "audit record grew {key}: {r}");
            }
        }
        assert_eq!(records[0]["verdict"], "deny");
        assert_eq!(records[1]["verdict"], "allow");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn drain_closes_a_live_tunnel_and_writes_its_line() {
        // An upstream that never closes and a client that never closes: only
        // drain can end this tunnel, and its line must exist when drain
        // returns (the totals are read right after).
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let up_port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut ping = [0_u8; 4];
            let _ = s.read_exact(&mut ping);
            let _ = s.write_all(b"pong!!");
            // Hold the socket open, reading until the proxy shuts it.
            let mut sink = [0_u8; 64];
            while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
            std::thread::sleep(Duration::from_secs(30));
        });
        let h = harness("drain", private_config(&["127.0.0.1"]));
        let s = send(
            h.proxy.port(),
            format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&s), REPLY_OK);
        (&s).write_all(b"ping").unwrap();
        let mut pong = [0_u8; 6];
        (&mut &s).read_exact(&mut pong).unwrap();
        assert!(lines(&h.path).is_empty(), "the tunnel is still open");

        let grace = Duration::from_millis(2000);
        let started = Instant::now();
        h.proxy.drain(grace);
        let took = started.elapsed();
        assert!(took <= grace + Duration::from_millis(250), "{took:?}");
        assert!(
            took < Duration::from_millis(1500),
            "closed sockets end the handlers; drain must not sleep the whole \
         grace: {took:?}"
        );

        // No polling: the line is there as soon as drain returns.
        let got = lines(&h.path);
        assert_eq!(got.len(), 1, "exactly one line: {got:?}");
        assert_eq!(got[0]["verdict"], "allow");
        assert_eq!(got[0]["bytes_up"], 4);
        assert_eq!(got[0]["bytes_down"], 6);
        let t = h.stats.snapshot();
        assert_eq!((t.allowed, t.bytes_up, t.bytes_down), (1, 4, 6));

        // The client side was shut down too.
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut b = [0_u8; 8];
        let closed = match (&mut &s).read(&mut b) {
            Ok(0) => true,
            Ok(_) => false,
            // A read timeout means the socket is still open.
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        };
        assert!(closed, "the client socket is still open after drain");
    }

    // ── prompt verdicts ─────────────────────────

    /// Stands in for the `--prompt-hosts` desktop prompt through the
    /// proxy's own `HostPrompt` seam: answers per host from a script and
    /// records every host it was asked about.
    struct ScriptedHostPrompt {
        answers: Vec<(String, PromptAnswer)>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl HostPrompt for ScriptedHostPrompt {
        fn ask(
            &self,
            host: &str,
            _port: u16,
            _internal: &[std::net::IpAddr],
        ) -> PromptAnswer {
            self.asked.lock().unwrap().push(host.to_string());
            self.answers
                .iter()
                .find(|(h, _)| h == host)
                .map(|(_, a)| *a)
                .unwrap_or(PromptAnswer::Deny)
        }
    }

    fn scripted_prompt(
        answers: &[(&str, PromptAnswer)],
    ) -> Arc<ScriptedHostPrompt> {
        Arc::new(ScriptedHostPrompt {
            answers: answers.iter().map(|(h, a)| (h.to_string(), *a)).collect(),
            asked: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn assert_verdict(line: &serde_json::Value, verdict: &str, reason: &str) {
        assert_eq!(line["verdict"], verdict, "{line}");
        assert_eq!(line["reason"], reason, "{line}");
    }

    #[test]
    fn prompt_verdicts_are_egress_lines() {
        let echo = echo_server();
        let prompt = scripted_prompt(&[
            ("203.0.113.5", PromptAnswer::Deny),
            ("203.0.113.6", PromptAnswer::NoAnswer),
            ("127.0.0.1", PromptAnswer::Allow),
        ]);
        // The allowlist names an unrelated host, so every target prompts.
        let mut config = private_config(&["example.com"]);
        config.prompt = Some(Arc::clone(&prompt) as Arc<dyn HostPrompt>);
        let h = harness("prompt", config);
        let port = h.proxy.port();

        // Two refusals share the verdict `deny`, and the line must still tell a
        // refusal from no answer.
        let deny = send(port, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&deny).contains("403"));
        let got = wait_lines(&h.path, 1);
        assert_verdict(&got[0], "deny", "prompt-deny");
        assert_eq!(got[0]["host"], "203.0.113.5");
        assert_eq!(got[0]["port"], 443);
        assert_eq!(got[0]["bytes_up"], 0);
        assert_eq!(got[0]["bytes_down"], 0);

        let silent = send(port, b"CONNECT 203.0.113.6:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&silent).contains("403"));
        let got = wait_lines(&h.path, 2);
        assert_verdict(&got[1], "deny", "prompt-no-answer");
        assert_eq!(got[1]["host"], "203.0.113.6");

        // A refusal remembered for the session is still the
        // prompt's verdict, not `not-in-allowlist`, though nobody is asked.
        let again = send(port, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&again).contains("403"));
        let got = wait_lines(&h.path, 3);
        assert_verdict(&got[2], "deny", "prompt-deny");

        // An approved tunnel is an allow line with its own reason.
        let a = send(
            port,
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&a), REPLY_OK);
        (&a).write_all(b"hi").unwrap();
        let mut buf = [0_u8; 2];
        (&mut &a).read_exact(&mut buf).unwrap();
        a.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        let _ = (&mut &a).read_to_end(&mut rest);
        drop(a);
        let got = wait_lines(&h.path, 4);
        assert_verdict(&got[3], "allow", "prompt-allow");
        assert_eq!(got[3]["host"], "127.0.0.1");
        assert_eq!(got[3]["port"], echo);
        assert_eq!(got[3]["bytes_up"], 2);
        assert_eq!(got[3]["bytes_down"], 2);
        assert_eq!(
            *prompt.asked.lock().unwrap(),
            ["203.0.113.5", "203.0.113.6", "127.0.0.1"],
            "the remembered refusal is not asked again"
        );
        let t = h.stats.snapshot();
        assert_eq!((t.allowed, t.denied, t.errored), (1, 3, 0));
        drop((deny, silent, again));

        // With a prompt configured, an allowlisted host is never
        // relabelled `prompt-allow`.
        let listed_prompt =
            scripted_prompt(&[("127.0.0.1", PromptAnswer::Allow)]);
        let mut config = private_config(&["127.0.0.1"]);
        config.prompt = Some(Arc::clone(&listed_prompt) as Arc<dyn HostPrompt>);
        let listed = harness("prompt-listed", config);
        let s = send(
            listed.proxy.port(),
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(read_head(&s), REPLY_OK);
        s.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        let _ = (&mut &s).read_to_end(&mut rest);
        drop(s);
        let got = wait_lines(&listed.path, 1);
        assert_verdict(&got[0], "allow", "in-allowlist");
        assert!(listed_prompt.asked.lock().unwrap().is_empty());

        // The prompt's own address-class refusal (SSRF guard on): loopback is
        // never offered, and the line says why.
        let guarded_prompt =
            scripted_prompt(&[("127.0.0.1", PromptAnswer::Allow)]);
        let mut config = ProxyConfig::new(vec!["example.com".to_string()]);
        config.prompt =
            Some(Arc::clone(&guarded_prompt) as Arc<dyn HostPrompt>);
        let guarded = harness("prompt-guarded", config);
        let s = send(
            guarded.proxy.port(),
            b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n",
        );
        assert!(read_head(&s).contains("403"));
        let got = wait_lines(&guarded.path, 1);
        assert_verdict(&got[0], "deny", "forbidden-address-range");
        assert_eq!(got[0]["host"], "127.0.0.1");
        assert!(guarded_prompt.asked.lock().unwrap().is_empty());
        drop(s);
    }

    // ── drain only on request ───────────────────

    #[test]
    fn drain_is_off_unless_requested() {
        // A launch that asked for no egress log builds its proxy from the
        // plain constructor, and its proxy must end as it did before the
        // flag existed: no drain. `drain` itself stays unconditional (the
        // tests above call it directly); the run decides whether to call it.
        let plain = ProxyConfig::new(vec!["127.0.0.1".to_string()]);
        assert!(!plain.drain_on_exit, "the drain is opt-in");

        // The setting is the run's request, not something the
        // proxy infers. A config that carries the run-wide counters and an
        // audit handle (both present on every filtered launch) is still not
        // asked to drain.
        let home = std::env::temp_dir()
            .join(format!("ai-jail-proxy-drain-flag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut counted = private_config(&["127.0.0.1"]);
        counted.audit = Some(crate::audit::AuditLog::open(&home).unwrap());
        counted.stats = Arc::new(EgressStats::default());
        assert!(
            !counted.drain_on_exit,
            "counters alone do not ask for a drain"
        );

        // The run's request is a plain setting it can make, and a
        // proxy started with it still serves connections.
        let mut asked = private_config(&["127.0.0.1"]);
        asked.drain_on_exit = true;
        let proxy = Proxy::start(asked, None).unwrap();
        let s = send(proxy.port(), b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        assert!(read_head(&s).contains("403"), "the proxy still serves");
        let _ = std::fs::remove_dir_all(&home);
    }

    // ── drain coverage ──────────────────────────
    // Drain coverage (connections accepted before their handler runs, the
    // listen backlog) and absolute-form targets.

    fn start(mut config: ProxyConfig) -> (Proxy, Arc<EgressStats>) {
        let stats = Arc::new(EgressStats::default());
        config.stats = Arc::clone(&stats);
        config.drain_on_exit = true;
        (Proxy::start(config, None).unwrap(), stats)
    }

    #[test]
    fn the_proxy_reports_whether_the_run_asked_for_a_drain() {
        let plain = Proxy::start(ProxyConfig::new(Vec::new()), None).unwrap();
        assert!(!plain.drain_on_exit());
        assert_eq!(plain.shared.listeners_kept(), 0, "no clone kept");
        let mut asked = ProxyConfig::new(Vec::new());
        asked.drain_on_exit = true;
        let asked = Proxy::start(asked, None).unwrap();
        assert!(asked.drain_on_exit());
        assert_eq!(asked.shared.listeners_kept(), 1);
    }

    #[test]
    fn drain_waits_for_a_connection_accepted_before_its_handler_runs() {
        let mut config = ProxyConfig::new(vec!["example.com".into()]);
        config.test_handler_delay = Duration::from_millis(300);
        let (proxy, stats) = start(config);
        let _client =
            std::net::TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        // Accepted, handler not started yet (it sleeps 300 ms).
        thread::sleep(Duration::from_millis(50));
        proxy.drain(Duration::from_secs(2));
        let t = stats.snapshot();
        assert_eq!(
            t.allowed + t.denied + t.errored,
            1,
            "the accepted connection must be counted before drain returns"
        );
    }

    #[test]
    fn drain_takes_the_listen_backlog() {
        let mut config = ProxyConfig::new(vec!["example.com".into()]);
        config.test_accept_paused = true;
        let (proxy, stats) = start(config);
        let mut client =
            std::net::TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        thread::sleep(Duration::from_millis(50));
        proxy.drain(Duration::from_secs(1));
        assert_eq!(stats.snapshot().errored, 1, "backlog refused as an error");
        let mut reply = String::new();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _ = client.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 503"), "{reply:?}");
    }

    #[test]
    fn a_refused_absolute_form_request_keeps_its_target() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-abs-target-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress.jsonl");
        let mut config = ProxyConfig::new(vec!["example.com".into()]);
        config.egress = Some(Arc::new(EgressLog::open(&path, "r1").unwrap()));
        let (proxy, _stats) = start(config);
        let mut client =
            std::net::TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        client
            .write_all(
                b"GET http://example.com/x HTTP/1.1\r\n\
                  Host: example.com\r\n\r\n",
            )
            .unwrap();
        let mut reply = String::new();
        let _ = client.read_to_string(&mut reply);
        proxy.drain(Duration::from_secs(1));
        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["reason"], "method-not-allowed");
        assert_eq!(line["host"], "example.com", "{line}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
