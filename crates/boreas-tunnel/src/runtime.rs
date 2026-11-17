//! Blocking link runtime: TCP -> WebSocket (h1) -> inner TLS -> authorized session.
//!
//! This is the callable vertical path of the hop transport. It is deliberately
//! synchronous and thread-per-connection: one `LinkClient::connect` or
//! `LinkServer::accept` call owns one connection end to end. HTTP/2 Extended
//! CONNECT, connection pooling, async task scheduling and the full Phase 1
//! data plane are **not** implemented here.
//!
//! The TLS handshake is delegated to an [`InnerTlsConnector`] /
//! [`InnerTlsAcceptor`]. The default build has no backend and therefore cannot
//! complete a real link; the `openssl-inner-tls` feature wires the reviewed
//! `boreas-crypto` OpenSSL backend. Tests use a `#[cfg(test)]` plaintext
//! transport that performs no TLS and is not security evidence.
//!
//! Every handshake entry point arms an owner-clone shutdown guard for its
//! absolute deadline. Socket read/write timeouts alone are per-syscall hints and
//! cannot bound an outer-TLS backend that loops inside one call.

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::error::TunnelError;
use crate::resource::{
    Admission, AuthenticatedPeer, ByteCredit, ConnectionCredit, HandshakeCredit,
};
use crate::session::{self, EstablishedSession, SessionPolicy};
use crate::stream::{DeadlineIo, Duplex};
use crate::tls::{InnerTlsAcceptor, InnerTlsConnector, OuterTlsConnector};
use crate::ws::{self, MAX_WS_FRAME_PAYLOAD};

/// Application-buffer reservation per accepted connection: the WebSocket frame
/// buffer plus the session read chunk. This covers **application buffers only**;
/// outer TLS, inner TLS, HTTP parser and kernel socket memory are separate and
/// are not claimed to be bounded by this reservation (plan section 8.2 requires
/// the three memory classes to be reported separately).
pub const CONNECTION_BUFFER_BUDGET: usize = 2 * (MAX_WS_FRAME_PAYLOAD + 8 * 1024);

/// Opt-in stage-timing diagnostics for controlled experiment runs. Only the
/// exact value `1` enables output; an absent value or any other value is silent.
pub(crate) const DIAGNOSTIC_TIMING_ENV: &str = "BOREAS_DIAGNOSTIC_TIMING";

fn diagnostic_timing_enabled_value(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

pub(crate) fn diagnostic_timing_enabled() -> bool {
    diagnostic_timing_enabled_value(std::env::var_os(DIAGNOSTIC_TIMING_ENV).as_deref())
}

/// Observation-only, opt-in monotonic timer for one handshake stage.
///
/// It emits one fixed-format line when the stage ends, including when the `?`
/// operator returns early, so a failed stage still reports. Nothing is written
/// and no clock is read unless the opt-in value is active. The write locks
/// stderr and may briefly block while another writer holds that lock. This is
/// instrumentation for controlled experiment runs, not a security or latency
/// guarantee: it does not gate, retry, or rewrite the handshake or its errors.
/// Only the static phase label and integer microseconds are emitted; target
/// addresses, host names, keys, nonces, paths, and wire bodies never reach it.
pub(crate) struct DiagnosticTimer {
    phase: &'static str,
    started: Option<Instant>,
}

impl DiagnosticTimer {
    pub(crate) fn start(phase: &'static str, enabled: bool) -> Self {
        Self {
            phase,
            // The default path must not even read the monotonic clock.
            started: enabled.then(Instant::now),
        }
    }
}

impl Drop for DiagnosticTimer {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let line = diagnostic_timing_line(self.phase, started.elapsed().as_micros());
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "{line}");
    }
}

fn diagnostic_timing_line(phase: &'static str, elapsed_us: u128) -> String {
    format!("boreas-diagnostic-timing phase={phase} elapsed_us={elapsed_us}")
}

/// Static build capabilities. These describe what this binary can do; they are
/// not evidence that any Phase 0-5 gate is complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapabilities {
    /// HTTP/1.1 WebSocket baseline is compiled in.
    pub hop_websocket_h1: bool,
    /// A reviewed inner-TLS backend is linked (`openssl-inner-tls`).
    pub hop_inner_tls_backend: bool,
    /// The same backend can run E2E TLS over a circuit stream.
    pub e2e_tls: bool,
    /// Bounded circuit open/accept/forwarding exists.
    pub circuit_forwarding: bool,
    /// No control socket exists in this crate.
    pub control_socket: bool,
    /// No DNS-over-TCP capability is advertised.
    pub dns_tcp: bool,
    /// No daemon process exists in this crate.
    pub daemon: bool,
}

pub const fn runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities {
        hop_websocket_h1: true,
        hop_inner_tls_backend: cfg!(feature = "openssl-inner-tls"),
        e2e_tls: cfg!(feature = "openssl-inner-tls"),
        circuit_forwarding: true,
        control_socket: false,
        dns_tcp: false,
        daemon: false,
    }
}

/// Where a client connects and which names it presents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTarget {
    pub address: SocketAddr,
    /// `Host` header / outer WebSocket authority. May include a `:port`, which
    /// is correct for HTTP but must **not** be used as the TLS server name.
    pub ws_host: String,
    /// Pure DNS host used for outer TLS SNI and certificate verification (no
    /// port, no brackets around a bare host name).
    pub tls_server_name: String,
    pub path: String,
}

/// Absolute cutoff for one handshake, backed by a duplicated socket handle.
///
/// [`DeadlineIo`] can refuse to start another transport operation once the
/// deadline has passed, but it cannot interrupt a backend already blocked in a
/// syscall or looping inside one of its own calls. The outer-TLS backend is the
/// critical case because it receives the raw `TcpStream`. This guard gives a
/// duplicated handle to a watchdog thread that waits for one absolute
/// `Instant` and then calls `shutdown(Both)` on the shared socket.
///
/// The descriptor is always owned by this guard or by the watchdog thread,
/// never represented as a bare integer. Every path either disarms the guard or
/// drops it; both join the thread, so no watchdog can outlive the handshake and
/// later shut down a recycled descriptor. The guard does not install a timeout
/// on the original socket; it is an independent cancellation path.
#[must_use = "dropping the guard disarms it; ignoring it removes the absolute timeout"]
struct HandshakeGuard {
    state: std::sync::Arc<GuardState>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct GuardState {
    cancelled: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
    fired: std::sync::atomic::AtomicBool,
}

impl HandshakeGuard {
    fn arm(tcp: &TcpStream, deadline: Instant) -> io::Result<Self> {
        let socket = tcp.try_clone()?;
        let state = std::sync::Arc::new(GuardState {
            cancelled: std::sync::Mutex::new(false),
            wake: std::sync::Condvar::new(),
            fired: std::sync::atomic::AtomicBool::new(false),
        });
        let thread_state = std::sync::Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name("boreas-handshake-deadline".to_owned())
            .spawn(move || handshake_guard_watch(socket, deadline, thread_state))?;
        Ok(Self {
            state,
            thread: Some(thread),
        })
    }

    fn fired(&self) -> bool {
        self.state
            .fired
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stop the watchdog and wait for it. Always joins; safe to call twice.
    fn disarm(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        {
            let mut cancelled = self
                .state
                .cancelled
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *cancelled = true;
            self.state.wake.notify_all();
        }
        let _ = thread.join();
    }

    /// Disarm, then report a guard-fired shutdown as a handshake timeout.
    fn finish<T>(&mut self, result: Result<T, TunnelError>) -> Result<T, TunnelError> {
        self.disarm();
        if self.fired() {
            return Err(TunnelError::Timeout);
        }
        result
    }
}

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        self.disarm();
    }
}

fn handshake_guard_watch(
    socket: TcpStream,
    deadline: Instant,
    state: std::sync::Arc<GuardState>,
) {
    let cancelled = state
        .cancelled
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let wait = deadline.saturating_duration_since(Instant::now());
    let (cancelled, _) = state
        .wake
        .wait_timeout_while(cancelled, wait, |cancelled| !*cancelled)
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *cancelled {
        return;
    }
    state
        .fired
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = socket.shutdown(std::net::Shutdown::Both);
}

pub struct LinkClient {
    outer: Box<dyn OuterTlsConnector>,
    inner: Box<dyn InnerTlsConnector>,
}

impl LinkClient {
    /// `outer` terminates the public HTTPS/WSS TLS layer (web PKI); `inner` runs
    /// the strict pq768 hop session inside the WebSocket byte stream.
    pub fn new(outer: Box<dyn OuterTlsConnector>, inner: Box<dyn InnerTlsConnector>) -> Self {
        Self { outer, inner }
    }

    /// Connect, run outer TLS, upgrade to WebSocket inside it, run the hop inner
    /// TLS handshake, then the `SessionHello`/`SessionAccept` authorization.
    ///
    /// `io_timeout` bounds the exchange from before the TCP dial. The deadline
    /// is absolute: a guard thread shuts down a duplicated socket handle when it
    /// expires, so a trickling outer-TLS backend cannot run the handshake
    /// indefinitely. The outer-TLS backend still receives the remaining budget
    /// as per-read/per-write socket timeouts; that is a transport hint, not the
    /// mechanism that makes the deadline absolute.
    pub fn connect(
        &self,
        target: &ClientTarget,
        policy: SessionPolicy,
        io_timeout: Duration,
    ) -> Result<EstablishedSession, TunnelError> {
        let deadline = Instant::now()
            .checked_add(io_timeout)
            .ok_or_else(handshake_budget_overflow)?;
        self.connect_until(target, policy, deadline)
    }

    /// Explicit absolute-deadline client handshake.
    ///
    /// The TCP dial is bounded by the time left until `deadline`; the rest of
    /// the exchange runs under the same instant. Use this when the caller has
    /// already spent part of a larger budget and must not hand the transport a
    /// fresh allowance.
    pub fn connect_until(
        &self,
        target: &ClientTarget,
        policy: SessionPolicy,
        deadline: Instant,
    ) -> Result<EstablishedSession, TunnelError> {
        let tcp = self.connect_tcp_until(target, deadline)?;
        self.connect_preconnected_until(tcp, target, policy, deadline)
    }

    /// Establish only the TCP transport. Errors returned here are strictly
    /// pre-TLS and pre-authentication; callers may safely classify dial failures.
    ///
    /// The budget that remains after the dial is carried on the socket so that a
    /// subsequent [`Self::connect_preconnected`] call, whose reviewed signature
    /// has no timeout argument, starts from approximately the caller's original
    /// deadline instead of a fresh full budget. Time spent between the two calls
    /// is not deducted, because a `TcpStream` cannot carry an `Instant`.
    pub fn connect_tcp(
        &self,
        target: &ClientTarget,
        io_timeout: Duration,
    ) -> io::Result<TcpStream> {
        let deadline = Instant::now()
            .checked_add(io_timeout)
            .ok_or_else(handshake_budget_overflow)?;
        self.connect_tcp_until(target, deadline)
    }

    fn connect_tcp_until(
        &self,
        target: &ClientTarget,
        deadline: Instant,
    ) -> io::Result<TcpStream> {
        let dial_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the handshake deadline expired before the TCP dial",
                )
            })?;
        let tcp = TcpStream::connect_timeout(&target.address, dial_timeout)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP dial consumed the handshake budget",
                )
            })?;
        // A per-read socket timeout from the remaining budget, not an absolute
        // deadline. The preconnected path re-derives its deadline from it.
        configure(&tcp, Some(remaining))?;
        Ok(tcp)
    }

    /// Complete TLS/WSS/session negotiation on a TCP stream already connected
    /// to `target.address`. The stream is consumed, ensuring callers can classify
    /// TCP dial failures separately without probing one socket and reconnecting.
    ///
    /// The budget is taken from the socket policy installed by
    /// [`Self::connect_tcp`], or from a bounded default when the socket was
    /// dialed directly. It becomes a fresh absolute deadline when this call
    /// starts; the residual gap between dial and call is documented on
    /// [`Self::connect_tcp`]. It is replaced by the exact remaining budget
    /// before the first blocking handshake operation.
    pub fn connect_preconnected(
        &self,
        tcp: TcpStream,
        target: &ClientTarget,
        policy: SessionPolicy,
    ) -> Result<EstablishedSession, TunnelError> {
        let budget = carried_handshake_budget(&tcp);
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(handshake_budget_overflow)?;
        self.connect_preconnected_until(tcp, target, policy, deadline)
    }

    /// Handshake on a preconnected socket under one absolute deadline.
    ///
    /// The owner-clone handshake guard owns a duplicated socket handle and
    /// shuts it down when the deadline expires. That is what makes the deadline
    /// absolute: the outer-TLS backend takes the raw `TcpStream` and may block
    /// in, or loop over, several transport calls inside `connect`, so a per-read
    /// socket timeout alone cannot bound it. The guard covers outer TLS, the
    /// WebSocket upgrade, inner TLS, and the session exchange. It is disarmed
    /// and joined only after the session handshake returns.
    ///
    /// The operation-boundary deadline wrapper is still installed after outer
    /// TLS. It recomputes the remaining budget before each operation and gives a
    /// stable timeout error, while the guard interrupts any already-blocked
    /// syscall.
    pub fn connect_preconnected_until(
        &self,
        tcp: TcpStream,
        target: &ClientTarget,
        policy: SessionPolicy,
        deadline: Instant,
    ) -> Result<EstablishedSession, TunnelError> {
        if tcp.peer_addr()? != target.address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "preconnected TCP peer does not match client target",
            )
            .into());
        }
        let diagnostics = diagnostic_timing_enabled();
        configure(&tcp, Some(remaining_handshake_budget(deadline)?))?;
        let mut guard = HandshakeGuard::arm(&tcp, deadline)?;
        let result = self.finish_client_handshake(tcp, target, policy, deadline, diagnostics);
        guard.finish(result)
    }

    fn finish_client_handshake(
        &self,
        tcp: TcpStream,
        target: &ClientTarget,
        policy: SessionPolicy,
        deadline: Instant,
        diagnostics: bool,
    ) -> Result<EstablishedSession, TunnelError> {
        let outer = {
            let _timer = DiagnosticTimer::start("outer_tls", diagnostics);
            self.outer.connect(tcp, &target.tls_server_name)?
        };
        // The guard is the absolute bound; this check keeps an overrun from
        // being mistaken for a fresh allowance if the backend returns just
        // before the shutdown lands.
        remaining_handshake_budget(deadline)?;
        let transport = DeadlineIo::new(outer, deadline);
        let websocket = {
            let _timer = DiagnosticTimer::start("ws_handshake", diagnostics);
            ws::client_handshake_until(transport, &target.ws_host, &target.path, deadline)?
        };
        let inner = {
            let _timer = DiagnosticTimer::start("inner_tls", diagnostics);
            self.inner.connect(Box::new(websocket))?
        };
        let (stream, tls) = inner.into_parts();
        let _timer = DiagnosticTimer::start("session_handshake", diagnostics);
        session::client_handshake(stream, &tls, policy)
    }
}

fn handshake_budget_overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "handshake budget overflows the deadline",
    )
}

/// Bounded fallback for a directly dialed preconnected socket. Callers that use
/// [`LinkClient::connect_tcp`] carry their own value on the socket instead.
const DEFAULT_PRECONNECTED_HANDSHAKE_BUDGET: Duration = Duration::from_secs(20);

fn carried_handshake_budget(tcp: &TcpStream) -> Duration {
    tcp.read_timeout()
        .ok()
        .flatten()
        .or_else(|| tcp.write_timeout().ok().flatten())
        .filter(|budget| !budget.is_zero())
        .unwrap_or(DEFAULT_PRECONNECTED_HANDSHAKE_BUDGET)
}

fn remaining_handshake_budget(deadline: Instant) -> Result<Duration, TunnelError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(TunnelError::Timeout)
}

pub struct LinkServer {
    tls: Box<dyn InnerTlsAcceptor>,
}

/// An accepted hop session plus its admission credits. Dropping the value
/// releases the authenticated connection slot and the buffer reservation.
pub struct AcceptedSession {
    pub session: EstablishedSession,
    pub credit: ConnectionCredit,
    pub buffer_credit: ByteCredit,
}

impl LinkServer {
    pub fn new(tls: Box<dyn InnerTlsAcceptor>) -> Self {
        Self { tls }
    }

    /// Production accept path: reserve admission **before** the outer TLS
    /// handshake, so an attacker cannot make the process perform expensive TLS
    /// work without consuming a global pre-authentication slot. The slot is
    /// converted to an authenticated per-peer slot only after the session is
    /// authorized; the buffer reservation is charged for the connection's
    /// lifetime.
    pub fn accept_tls(
        &self,
        listener: &TcpListener,
        outer: &dyn crate::tls::OuterTlsAcceptor,
        policy: SessionPolicy,
        io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let (tcp, _peer_address) = listener.accept()?;
        self.accept_tls_stream(tcp, outer, policy, io_timeout, admission)
    }

    /// Complete the authenticated WSS server path for a TCP stream already
    /// accepted by the caller. This seam lets listeners apply an absolute
    /// handshake deadline without changing listener-wide blocking mode.
    /// Admission is still reserved before outer TLS work.
    ///
    /// `io_timeout` bounds the exchange, starting when this call begins. The
    /// owner-clone handshake guard shuts down a duplicated socket handle when
    /// the deadline expires, so it is an absolute bound across outer TLS, the
    /// WebSocket upgrade, inner TLS, and the session exchange. The outer-TLS
    /// backend also receives the remaining budget as per-read/per-write socket
    /// timeouts, but that hint is not what makes the deadline absolute.
    pub fn accept_tls_stream(
        &self,
        tcp: TcpStream,
        outer: &dyn crate::tls::OuterTlsAcceptor,
        policy: SessionPolicy,
        io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let deadline = Instant::now()
            .checked_add(io_timeout)
            .ok_or_else(handshake_budget_overflow)?;
        self.accept_tls_stream_until(tcp, outer, policy, deadline, admission)
    }

    /// Explicit absolute-deadline server handshake on an already-accepted
    /// stream. The deadline is monotonic and shared by every TLS and session
    /// stage; it is not a fresh per-stage allowance.
    pub fn accept_tls_stream_until(
        &self,
        tcp: TcpStream,
        outer: &dyn crate::tls::OuterTlsAcceptor,
        policy: SessionPolicy,
        deadline: Instant,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let handshake = admission.reserve_handshake()?;
        let buffer_credit = admission.reserve_bytes(CONNECTION_BUFFER_BUDGET)?;
        configure(&tcp, Some(remaining_handshake_budget(deadline)?))?;
        let mut guard = HandshakeGuard::arm(&tcp, deadline)?;
        let result = outer
            .accept(tcp)
            .and_then(|outer| {
                self.accept_outer_complete(outer, handshake, buffer_credit, policy, deadline)
            });
        guard.finish(result)
    }

    /// Explicitly insecure development path: TCP straight into the WebSocket
    /// upgrade with **no outer TLS**. It exists only under `#[cfg(test)]`, so a
    /// production build cannot serve plaintext WSS origins through this crate.
    #[cfg(test)]
    pub fn accept_plaintext_for_tests(
        &self,
        listener: &TcpListener,
        policy: SessionPolicy,
        io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let (tcp, _peer_address) = listener.accept()?;
        let deadline = Instant::now()
            .checked_add(io_timeout)
            .ok_or_else(handshake_budget_overflow)?;
        let handshake = admission.reserve_handshake()?;
        let buffer_credit = admission.reserve_bytes(CONNECTION_BUFFER_BUDGET)?;
        configure(&tcp, Some(remaining_handshake_budget(deadline)?))?;
        let mut guard = HandshakeGuard::arm(&tcp, deadline)?;
        let outer: Box<dyn Duplex> = Box::new(tcp);
        let result =
            self.accept_outer_complete(outer, handshake, buffer_credit, policy, deadline);
        guard.finish(result)
    }

    fn accept_outer_complete(
        &self,
        outer: Box<dyn Duplex>,
        handshake: HandshakeCredit,
        buffer_credit: ByteCredit,
        policy: SessionPolicy,
        deadline: Instant,
    ) -> Result<AcceptedSession, TunnelError> {
        // The guard is the absolute bound; this check keeps an overrun from
        // being mistaken for a fresh allowance if the backend returns just
        // before the shutdown lands.
        remaining_handshake_budget(deadline)?;
        let transport = DeadlineIo::new(outer, deadline);
        self.accept_established(transport, handshake, buffer_credit, policy, deadline)
    }

    /// Test-only shorthand: plaintext transport, no outer TLS. Never exists in a
    /// production build.
    #[cfg(test)]
    pub fn accept(
        &self,
        listener: &TcpListener,
        policy: SessionPolicy,
        io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        self.accept_plaintext_for_tests(listener, policy, io_timeout, admission)
    }

    /// Private: reached only through a path that already reserved admission and
    /// terminated the outer TLS layer (or, in tests, deliberately skipped it).
    /// Keeping this private prevents an arbitrary stream from bypassing the
    /// outer TLS seam.
    fn accept_established<T: Duplex + 'static>(
        &self,
        transport: T,
        handshake: HandshakeCredit,
        buffer_credit: ByteCredit,
        policy: SessionPolicy,
        deadline: Instant,
    ) -> Result<AcceptedSession, TunnelError> {
        let websocket = ws::server_handshake_until(transport, deadline)?;
        let inner = self.tls.accept(Box::new(websocket))?;
        let (stream, tls) = inner.into_parts();
        let session = session::server_handshake(stream, &tls, policy)?;
        let authenticated = AuthenticatedPeer::from_verified_identity(session.peer());
        let credit = handshake.authenticate(&authenticated)?;
        Ok(AcceptedSession {
            session,
            credit,
            buffer_credit,
        })
    }
}

/// Configure the socket for a bounded handshake.
///
/// The timeout installed here is a per-read/per-write socket timeout, not an
/// absolute deadline: the OS applies it afresh to every blocking syscall, and a
/// backend such as outer TLS may perform several calls inside one handshake.
/// Callers must not describe this as an absolute handshake deadline. The
/// absolute cutoff comes from [`HandshakeGuard`], which shuts down a duplicated
/// socket handle when the deadline expires. The runtime also installs the
/// *remaining* budget before a backend call, re-checks the deadline after that
/// call, and from the WebSocket upgrade onward [`DeadlineIo`] recomputes the
/// remaining budget for each later operation.
///
/// A sub-millisecond remainder is rounded up to one millisecond: some platforms
/// interpret a zero `SO_RCVTIMEO`/`SO_SNDTIMEO` as "wait forever", which would
/// remove the bound instead of tightening it.
const MIN_SOCKET_TIMEOUT: Duration = Duration::from_millis(1);

fn configure(tcp: &TcpStream, timeout: Option<Duration>) -> io::Result<()> {
    let timeout = timeout.map(|timeout| timeout.max(MIN_SOCKET_TIMEOUT));
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(timeout)?;
    tcp.set_write_timeout(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Limits;
    use crate::tls::PeerIdentity;
    use crate::tls::{TestOnlyPlaintextOuter, TestOnlyPlaintextTls};
    use boreas_crypto::NodeRole;
    use boreas_proto::messages::{PathRole, Suite as MessageSuite};
    use boreas_proto::{ControlType, Kind, SecurityMode};
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn identity(node_id: u16, role: NodeRole) -> PeerIdentity {
        PeerIdentity::legacy_default([7; 16], node_id, 1, role)
    }

    fn policy(local: PeerIdentity, peer: PeerIdentity) -> SessionPolicy {
        SessionPolicy {
            local,
            expected_peer: peer,
            path_role: PathRole::Cdn,
            security_mode: SecurityMode::E2eRequired,
            suite: MessageSuite::Pq768,
            mtu_cap: 1400,
            identity_registered: true,
            allow_pq1024: false,
            allow_hop_only: false,
            allowed_peer_roles: vec![peer.role],
        }
    }

    fn admission() -> Admission {
        Admission::new(Limits {
            handshakes_global: 8,
            authenticated_global: 8,
            authenticated_per_peer: 4,
            bytes_global: 1024 * 1024,
        })
    }

    fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local addr");
        (listener, address)
    }

    fn target(address: SocketAddr) -> ClientTarget {
        ClientTarget {
            address,
            ws_host: "hub.boreas.test:443".to_owned(),
            tls_server_name: "hub.boreas.test".to_owned(),
            path: "/tunnel".to_owned(),
        }
    }

    #[test]
    fn loopback_session_roundtrip() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let mut session = server
                    .accept(&listener, policy, TIMEOUT, &admission)
                    .expect("session")
                    .session;
                let frame = session.recv_frame().expect("probe");
                assert_eq!(frame.header.kind, Kind::Control);
                assert_eq!(frame.body, [ControlType::Probe as u8, 0xAA]);
                session
                    .send_control(ControlType::Probe, &[ControlType::Probe as u8, 0xBB])
                    .expect("probe reply");
                session.peer()
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let mut session = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("client session");
        assert_eq!(session.peer(), b);
        assert_eq!(session.mtu_cap(), 1400);
        session
            .send_control(ControlType::Probe, &[ControlType::Probe as u8, 0xAA])
            .expect("probe");
        let reply = session.recv_frame().expect("reply");
        assert_eq!(reply.body, [ControlType::Probe as u8, 0xBB]);
        assert_eq!(server.join().expect("server thread"), a);
    }

    #[test]
    fn connect_tcp_reports_refusal_before_any_handshake() {
        let (listener, address) = listener();
        drop(listener);
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls {
                peer: identity(0x0201, NodeRole::Core),
            }),
        );
        let error = match client.connect_tcp(&target(address), TIMEOUT) {
            Err(error) => error,
            Ok(_) => panic!("closed listener must fail during TCP dial"),
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn preconnected_api_reuses_the_supplied_tcp_stream() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                server
                    .accept(&listener, policy, TIMEOUT, &admission)
                    .expect("session");
            })
        };
        let tcp = TcpStream::connect(address).expect("dial once");
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let session = client
            .connect_preconnected(tcp, &target(address), policy(a, b))
            .expect("session over supplied stream");
        assert_eq!(session.peer(), b);
        server.join().expect("server thread");
    }

    #[test]
    fn preconnected_api_rejects_a_socket_for_another_target() {
        let (listener_a, address_a) = listener();
        let (_listener_b, address_b) = listener();
        let accept = thread::spawn(move || listener_a.accept().expect("accept socket A"));
        let tcp = TcpStream::connect(address_a).expect("connect socket A");
        let (_server_socket, _) = accept.join().expect("server thread");
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls {
                peer: identity(0x0201, NodeRole::Core),
            }),
        );
        let error = match client.connect_preconnected(
            tcp,
            &target(address_b),
            policy(
                identity(0x0101, NodeRole::Edge),
                identity(0x0201, NodeRole::Core),
            ),
        ) {
            Err(error) => error,
            Ok(_) => panic!("wrong-target socket must be rejected before handshake"),
        };
        assert!(matches!(
            error,
            TunnelError::Io(io::ErrorKind::InvalidInput)
        ));
    }

    #[test]
    fn configure_installs_and_clears_the_handshake_timeout() {
        let (listener, address) = listener();
        let accept = thread::spawn(move || listener.accept().expect("accept"));
        let tcp = TcpStream::connect(address).expect("connect");
        configure(&tcp, Some(Duration::from_millis(250))).expect("configure");
        assert_eq!(
            tcp.read_timeout().expect("read timeout"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            tcp.write_timeout().expect("write timeout"),
            Some(Duration::from_millis(250))
        );
        configure(&tcp, None).expect("clear");
        assert_eq!(tcp.read_timeout().expect("read timeout"), None);
        assert_eq!(tcp.write_timeout().expect("write timeout"), None);
        drop(tcp);
        let (_socket, _) = accept.join().expect("server thread");
    }

    #[test]
    fn preconnected_budget_is_carried_on_the_tcp_socket() {
        let (listener, address) = listener();
        let accept = thread::spawn(move || listener.accept().expect("accept"));
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls {
                peer: identity(0x0201, NodeRole::Core),
            }),
        );
        let tcp = client
            .connect_tcp(&target(address), Duration::from_secs(3))
            .expect("dial");
        let carried = carried_handshake_budget(&tcp);
        assert!(carried <= Duration::from_secs(3));
        assert!(carried > Duration::ZERO);
        drop(tcp);
        let (_socket, _) = accept.join().expect("server thread");
    }

    #[test]
    fn explicit_deadline_api_fails_closed_before_dial_when_already_spent() {
        let (listener, address) = listener();
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls {
                peer: identity(0x0201, NodeRole::Core),
            }),
        );
        let error = match client.connect_until(
            &target(address),
            policy(
                identity(0x0101, NodeRole::Edge),
                identity(0x0201, NodeRole::Core),
            ),
            Instant::now(),
        ) {
            Ok(_) => panic!("an expired explicit deadline must not dial"),
            Err(error) => error,
        };
        assert_eq!(error, TunnelError::Timeout);
        drop(listener);
    }

    #[test]
    fn handshake_guard_shuts_down_a_blocked_socket_at_the_deadline() {
        let (listener, address) = listener();
        let accept = thread::spawn(move || listener.accept().expect("accept"));
        let mut tcp = TcpStream::connect(address).expect("connect");
        let (_server, _) = accept.join().expect("server thread");
        let deadline = Instant::now() + Duration::from_millis(100);
        let guard = HandshakeGuard::arm(&tcp, deadline).expect("arm guard");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");

        let started = Instant::now();
        let mut byte = [0u8; 1];
        let result = tcp.read(&mut byte);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the guard must interrupt the blocked read, not wait for the socket timeout"
        );
        if let Ok(read) = result {
            assert_eq!(read, 0, "shutdown must not deliver application bytes");
        }
        drop(guard);
    }

    #[test]
    fn handshake_guard_disarm_joins_without_shutting_down_the_socket() {
        let (listener, address) = listener();
        let accept = thread::spawn(move || listener.accept().expect("accept"));
        let mut tcp = TcpStream::connect(address).expect("connect");
        let (_server, _) = accept.join().expect("server thread");
        let mut guard = HandshakeGuard::arm(&tcp, Instant::now() + Duration::from_secs(10))
            .expect("arm guard");
        let started = Instant::now();
        guard.disarm();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "disarm must wake and join the watchdog instead of waiting for the deadline"
        );
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");

        let mut byte = [0u8; 1];
        let error = tcp
            .read(&mut byte)
            .expect_err("a disarmed guard must leave the socket open");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }

    struct TimeoutProbeOuter;

    impl crate::tls::OuterTlsAcceptor for TimeoutProbeOuter {
        fn accept(&self, tcp: TcpStream) -> Result<Box<dyn Duplex>, TunnelError> {
            let timeout = tcp
                .read_timeout()
                .expect("query timeout")
                .expect("handshake timeout installed before outer TLS");
            assert!(timeout <= TIMEOUT);
            assert!(timeout > Duration::ZERO);
            Ok(Box::new(tcp))
        }
    }

    #[test]
    fn accept_tls_stream_applies_the_budget_before_outer_tls() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
            let admission = admission();
            server
                .accept_tls_stream(
                    tcp,
                    &TimeoutProbeOuter,
                    policy(b, a),
                    TIMEOUT,
                    &admission,
                )
                .expect("server session");
        });
        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let session = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("client session");
        assert_eq!(session.peer(), b);
        server.join().expect("server thread");
    }

    /// Models the failure the positive test guards against: a wrapper that
    /// forwards the handshake timeout while it is armed but silently drops the
    /// clear. Authorization still succeeds; the stale socket timeout would then
    /// fail a later idle read.
    struct ClearDropping<T>(T);

    impl<T: Read> Read for ClearDropping<T> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.0.read(out)
        }
    }

    impl<T: Write> Write for ClearDropping<T> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl<T: Duplex> Duplex for ClearDropping<T> {
        fn has_buffered_input(&self) -> bool {
            self.0.has_buffered_input()
        }

        fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            match timeout {
                // Arming is forwarded so the handshake itself is bounded.
                Some(timeout) => self.0.set_io_timeout(Some(timeout)),
                // This fixture models a wrapper that forgets to forward the clear.
                None => Ok(()),
            }
        }

        fn clear_handshake_deadline(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ClearDroppingOuter;

    impl crate::tls::OuterTlsConnector for ClearDroppingOuter {
        fn connect(
            &self,
            tcp: TcpStream,
            _server_name: &str,
        ) -> Result<Box<dyn Duplex>, TunnelError> {
            Ok(Box::new(ClearDropping(Box::new(tcp))))
        }
    }

    #[test]
    fn session_handshake_clears_the_socket_timeout_through_every_layer() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let (tcp, _) = listener.accept().expect("accept");
                let observer = tcp.try_clone().expect("clone");
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let session = server
                    .accept_tls_stream(
                        tcp,
                        &TestOnlyPlaintextOuter,
                        policy,
                        TIMEOUT,
                        &admission,
                    )
                    .expect("server session");
                assert_eq!(observer.read_timeout().expect("read timeout"), None);
                assert_eq!(observer.write_timeout().expect("write timeout"), None);
                drop(session);
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let tcp = client
            .connect_tcp(&target(address), TIMEOUT)
            .expect("dial");
        let observer = tcp.try_clone().expect("clone");
        assert!(
            observer.read_timeout().expect("read timeout").is_some(),
            "the per-read handshake timeout is installed before outer TLS"
        );
        let session = client
            .connect_preconnected(tcp, &target(address), policy(a, b))
            .expect("client session");
        assert_eq!(observer.read_timeout().expect("read timeout"), None);
        assert_eq!(observer.write_timeout().expect("write timeout"), None);
        drop(session);
        server.join().expect("server thread");
    }

    #[test]
    fn a_layer_that_drops_the_clear_leaves_the_socket_timeout_armed() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let _session = server
                    .accept(&listener, policy, TIMEOUT, &admission)
                    .expect("server session");
            })
        };

        let client = LinkClient::new(
            Box::new(ClearDroppingOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let tcp = client
            .connect_tcp(&target(address), TIMEOUT)
            .expect("dial");
        let observer = tcp.try_clone().expect("clone");
        let session = client
            .connect_preconnected(tcp, &target(address), policy(a, b))
            .expect("client session");
        assert!(
            observer.read_timeout().expect("read timeout").is_some(),
            "a no-op clear must leave the stale handshake timeout visible; \
             otherwise the positive test proves nothing"
        );
        drop(session);
        server.join().expect("server thread");
    }

    #[test]
    fn authorized_session_is_not_timed_out_by_an_expired_handshake_deadline() {
        // Keep a wide margin between the handshake budget and the idle sleep so
        // a loaded CI runner cannot turn scheduling delay into a flaky failure.
        const BUDGET: Duration = Duration::from_secs(1);
        const IDLE: Duration = Duration::from_millis(1_500);
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let mut session = server
                    .accept(&listener, policy, BUDGET, &admission)
                    .expect("server session")
                    .session;
                thread::sleep(IDLE);
                let frame = session.recv_frame().expect("probe after idle");
                assert_eq!(frame.body, [ControlType::Probe as u8, 0xAA]);
                session
                    .send_control(ControlType::Probe, &[ControlType::Probe as u8, 0xBB])
                    .expect("reply after idle");
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let mut session = client
            .connect(&target(address), policy(a, b), BUDGET)
            .expect("client session");
        thread::sleep(IDLE);
        session
            .send_control(ControlType::Probe, &[ControlType::Probe as u8, 0xAA])
            .expect("probe after idle");
        let reply = session.recv_frame().expect("reply after idle");
        assert_eq!(reply.body, [ControlType::Probe as u8, 0xBB]);
        server.join().expect("server thread");
    }

    struct SlowOuterConnector {
        reads: usize,
        budget: Duration,
        completed: Arc<AtomicBool>,
    }

    impl crate::tls::OuterTlsConnector for SlowOuterConnector {
        fn connect(
            &self,
            mut tcp: TcpStream,
            _server_name: &str,
        ) -> Result<Box<dyn Duplex>, TunnelError> {
            let installed = tcp
                .read_timeout()
                .expect("query timeout")
                .expect("per-read timeout installed before outer TLS");
            assert!(installed > Duration::ZERO);
            assert!(installed <= self.budget);
            let mut byte = [0u8; 1];
            for _ in 0..self.reads {
                tcp.read_exact(&mut byte)?;
            }
            self.completed.store(true, Ordering::SeqCst);
            Ok(Box::new(tcp))
        }
    }

    #[test]
    fn outer_tls_overrun_is_rejected_before_the_websocket_upgrade() {
        const BUDGET: Duration = Duration::from_millis(400);
        const GAP: Duration = Duration::from_millis(200);
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let server = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().expect("accept");
            for _ in 0..4 {
                thread::sleep(GAP);
                if tcp.write_all(&[0u8; 1]).is_err() {
                    return;
                }
            }
        });

        let completed = Arc::new(AtomicBool::new(false));
        let client = LinkClient::new(
            Box::new(SlowOuterConnector {
                reads: 4,
                budget: BUDGET,
                completed: Arc::clone(&completed),
            }),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let error = match client.connect(&target(address), policy(a, b), BUDGET) {
            Ok(_) => panic!("an outer TLS call that outlives the budget must fail"),
            Err(error) => error,
        };
        assert_eq!(error, TunnelError::Timeout);
        assert!(
            !completed.load(Ordering::SeqCst),
            "the guard must interrupt outer TLS before the backend can finish all reads"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn admission_charges_only_authenticated_peers() {
        let (listener, address) = listener();
        let a = identity(0x0101, NodeRole::Edge);
        let b = identity(0x0201, NodeRole::Core);
        let admission = Admission::new(Limits {
            handshakes_global: 4,
            authenticated_global: 4,
            authenticated_per_peer: 1,
            bytes_global: 1024 * 1024,
        });
        let server_admission = admission.clone();
        let server = {
            let policy = policy(b, a);
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let first = server
                    .accept(&listener, policy.clone(), TIMEOUT, &server_admission)
                    .expect("first session");
                let second = server.accept(&listener, policy, TIMEOUT, &server_admission);
                drop(first);
                assert!(matches!(
                    second,
                    Err(TunnelError::Admission(
                        crate::resource::AdmissionError::PeerLimit
                    ))
                ));
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let _first = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("first client session");
        // The second handshake completes, then the server refuses to charge a
        // second authenticated slot to the same peer and drops it.
        let _second = client.connect(&target(address), policy(a, b), TIMEOUT);
        server.join().expect("server thread");
        assert_eq!(admission.snapshot().expect("snapshot").authenticated, 0);
        assert_eq!(admission.snapshot().expect("snapshot").bytes, 0);
    }

    #[test]
    fn capabilities_are_honest_about_missing_backend() {
        let capabilities = runtime_capabilities();
        assert!(capabilities.hop_websocket_h1);
        assert!(capabilities.circuit_forwarding);
        assert!(!capabilities.control_socket);
        assert!(!capabilities.daemon);
        assert!(!capabilities.dns_tcp);
        assert_eq!(
            capabilities.hop_inner_tls_backend,
            cfg!(feature = "openssl-inner-tls")
        );
    }

    #[test]
    fn diagnostic_timing_requires_the_exact_opt_in_value() {
        // Pass the value in directly: tests must not mutate process env, which
        // is unsafe and racy across parallel tests.
        assert!(diagnostic_timing_enabled_value(Some(std::ffi::OsStr::new(
            "1"
        ))));
        for disabled in [
            None,
            Some(std::ffi::OsStr::new("0")),
            Some(std::ffi::OsStr::new("true")),
            Some(std::ffi::OsStr::new(" 1")),
            Some(std::ffi::OsStr::new("1 ")),
        ] {
            assert!(!diagnostic_timing_enabled_value(disabled));
        }
    }

    #[test]
    fn diagnostic_timing_line_has_a_fixed_non_secret_format() {
        assert_eq!(
            diagnostic_timing_line("outer_tls", 42),
            "boreas-diagnostic-timing phase=outer_tls elapsed_us=42"
        );
        assert_eq!(
            diagnostic_timing_line("session_handshake", 0),
            "boreas-diagnostic-timing phase=session_handshake elapsed_us=0"
        );
    }

    #[test]
    fn disabled_diagnostic_timer_does_not_start_a_clock() {
        let timer = DiagnosticTimer::start("outer_tls", false);
        assert!(timer.started.is_none());
    }
}
