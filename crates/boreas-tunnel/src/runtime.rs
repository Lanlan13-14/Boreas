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

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::error::TunnelError;
use crate::resource::{
    Admission, AuthenticatedPeer, ByteCredit, ConnectionCredit, HandshakeCredit,
};
use crate::session::{self, EstablishedSession, SessionPolicy};
use crate::stream::Duplex;
use crate::tls::{InnerTlsAcceptor, InnerTlsConnector, OuterTlsConnector};
use crate::ws::{self, MAX_WS_FRAME_PAYLOAD};

/// Application-buffer reservation per accepted connection: the WebSocket frame
/// buffer plus the session read chunk. This covers **application buffers only**;
/// outer TLS, inner TLS, HTTP parser and kernel socket memory are separate and
/// are not claimed to be bounded by this reservation (plan section 8.2 requires
/// the three memory classes to be reported separately).
pub const CONNECTION_BUFFER_BUDGET: usize = 2 * (MAX_WS_FRAME_PAYLOAD + 8 * 1024);

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
    pub fn connect(
        &self,
        target: &ClientTarget,
        policy: SessionPolicy,
        io_timeout: Duration,
    ) -> Result<EstablishedSession, TunnelError> {
        let tcp = self.connect_tcp(target, io_timeout)?;
        self.connect_preconnected(tcp, target, policy)
    }

    /// Establish only the TCP transport. Errors returned here are strictly
    /// pre-TLS and pre-authentication; callers may safely classify dial failures.
    pub fn connect_tcp(
        &self,
        target: &ClientTarget,
        io_timeout: Duration,
    ) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&target.address, io_timeout)
    }

    /// Complete TLS/WSS/session negotiation on a TCP stream already connected
    /// to `target.address`. The stream is consumed, ensuring callers can classify
    /// TCP dial failures separately without probing one socket and reconnecting.
    pub fn connect_preconnected(
        &self,
        tcp: TcpStream,
        target: &ClientTarget,
        policy: SessionPolicy,
    ) -> Result<EstablishedSession, TunnelError> {
        if tcp.peer_addr()? != target.address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "preconnected TCP peer does not match client target",
            )
            .into());
        }
        // The handshake budget belongs to the whole exchange, not to each
        // socket read. A public path can split one TLS record across several
        // RTTs; a per-read deadline makes that look like a handshake failure.
        configure(&tcp)?;
        let outer = self.outer.connect(tcp, &target.tls_server_name)?;
        let websocket = ws::client_handshake(outer, &target.ws_host, &target.path)?;
        let inner = self.inner.connect(Box::new(websocket))?;
        let (stream, tls) = inner.into_parts();
        session::client_handshake(stream, &tls, policy)
    }
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
    /// accept deadline without changing listener-wide blocking mode. Admission
    /// is still reserved immediately after TCP accept and before outer TLS work.
    pub fn accept_tls_stream(
        &self,
        tcp: TcpStream,
        outer: &dyn crate::tls::OuterTlsAcceptor,
        policy: SessionPolicy,
        _io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let handshake = admission.reserve_handshake()?;
        let buffer_credit = admission.reserve_bytes(CONNECTION_BUFFER_BUDGET)?;
        configure(&tcp)?;
        let transport = outer.accept(tcp)?;
        self.accept_established(transport, handshake, buffer_credit, policy)
    }

    /// Explicitly insecure development path: TCP straight into the WebSocket
    /// upgrade with **no outer TLS**. It exists only under `#[cfg(test)]`, so a
    /// production build cannot serve plaintext WSS origins through this crate.
    #[cfg(test)]
    pub fn accept_plaintext_for_tests(
        &self,
        listener: &TcpListener,
        policy: SessionPolicy,
        _io_timeout: Duration,
        admission: &Admission,
    ) -> Result<AcceptedSession, TunnelError> {
        let (tcp, _peer_address) = listener.accept()?;
        let handshake = admission.reserve_handshake()?;
        let buffer_credit = admission.reserve_bytes(CONNECTION_BUFFER_BUDGET)?;
        configure(&tcp)?;
        self.accept_established(tcp, handshake, buffer_credit, policy)
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
    ) -> Result<AcceptedSession, TunnelError> {
        let websocket = ws::server_handshake(transport)?;
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

fn configure(tcp: &TcpStream) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    // Handshake reads stay blocking. A per-read timeout is not a handshake
    // deadline: public paths split one record across multiple reads.
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)
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
    use std::net::TcpListener;
    use std::thread;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn identity(node_id: u16, role: NodeRole) -> PeerIdentity {
        PeerIdentity {
            net_id: [7; 16],
            node_id,
            identity_generation: 1,
            role,
        }
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
}
