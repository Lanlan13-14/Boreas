//! Hop session authorization and bounded application framing.
//!
//! After the inner TLS handshake both peers exchange `SessionHello` /
//! `SessionAccept` inside the TLS application data stream. A completed TLS
//! handshake alone is **not** authorization: this module binds the authenticated
//! peer identity (network, node, identity generation, role) to the advertised
//! session parameters, enforces local policy, and only then exposes a session
//! that may carry control or circuit frames.
//!
//! Every frame is an [`AppHeader`](boreas_proto::AppHeader) plus a bounded body.
//! Frame-level state transitions (which control subtype is legal when, MTU,
//! mode, hop-only prohibition for circuits) come from
//! [`boreas_proto::validate_frame_policy`]; this module adds the identity,
//! network, path-role, suite and role checks that the protocol crate cannot make.
//!
//! Wire schemas are the candidate `boreas-proto` definitions; they are not a
//! frozen protocol. `SessionHello` is the only accepted first frame.


use boreas_crypto::{NodeRole, Policy};
use boreas_proto::messages::{
    self, LocalIdentity, PathRole, SessionAccept, SessionHello, SessionParams,
    Suite as MessageSuite,
};
use boreas_proto::{
    AppHeader, ControlType, Frame, FrameDecoder, HEADER_LEN, Kind, MAX_BODY_LEN, PROTO_MAJOR,
    PeerRole, SecurityMode, SessionContext,
};

use crate::csprng;
use crate::error::{SessionReject, TunnelError};
use crate::stream::Duplex;
use crate::tls::{InnerTlsSession, PeerIdentity, check_inner_tls, crypto_suite};

/// Decoder limit: one maximal application frame. A feed that would retain more
/// than this is rejected by `FrameDecoder`.
pub const FRAME_BUFFER_LIMIT: usize = HEADER_LEN + MAX_BODY_LEN as usize;
const READ_CHUNK: usize = 8 * 1024;
/// Decoded frames queued by one read before the caller consumes them. An 8 KiB
/// read can contain more than a thousand minimal 8-byte headers, so metadata is
/// bounded separately from `FrameDecoder`'s byte limit.
pub const MAX_PENDING_FRAMES: usize = 64;
/// Total body bytes queued by one read.
pub const MAX_PENDING_BYTES: usize = 128 * 1024;

/// Local authorization policy for one hop session.
///
/// The expected peer is an already-authorized value from configuration or the
/// directory trust layer, never a peer-supplied claim. `allowed_peer_roles`
/// must be explicit: an empty list authorizes nobody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub local: PeerIdentity,
    pub expected_peer: PeerIdentity,
    pub path_role: PathRole,
    pub security_mode: SecurityMode,
    pub suite: MessageSuite,
    pub mtu_cap: u16,
    /// Whether the authenticated peer identity is already registered (and thus
    /// allowed to carry non-enrollment traffic). Enrollment-only connections
    /// are a separate path and are rejected here.
    pub identity_registered: bool,
    /// Enables the `pq1024` suite only after its separate Phase 0 PoC exists.
    pub allow_pq1024: bool,
    /// Explicit opt-in for `HopOnly`. The CLI is responsible for the interactive
    /// `HOP-ONLY` confirmation before this flag is set.
    pub allow_hop_only: bool,
    pub allowed_peer_roles: Vec<NodeRole>,
}

impl SessionPolicy {
    /// pq768 / `e2e-required` uplink to a Core, ported from the configuration
    /// candidate in the master plan (§5.5).
    pub fn default_pq768(local: PeerIdentity, expected_peer: PeerIdentity) -> Self {
        Self {
            local,
            expected_peer,
            path_role: PathRole::Cdn,
            security_mode: SecurityMode::E2eRequired,
            suite: MessageSuite::Pq768,
            mtu_cap: 1500,
            identity_registered: true,
            allow_pq1024: false,
            allow_hop_only: false,
            allowed_peer_roles: vec![NodeRole::Core],
        }
    }

    /// Local-only consistency checks. Runs before any network write.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.local.net_id == [0u8; 16] || self.local.net_id != self.expected_peer.net_id {
            return Err(SessionReject::NetworkMismatch.into());
        }
        if self.local.identity_generation == 0
            || self.expected_peer.identity_generation == 0
            || self.local.node_id == 0
            || self.expected_peer.node_id == 0
        {
            return Err(SessionReject::InvalidLocalIdentity.into());
        }
        if !(messages::MIN_MTU_CAP..=messages::MAX_MTU_CAP).contains(&self.mtu_cap) {
            return Err(SessionReject::InvalidMtu.into());
        }
        if self.path_role == PathRole::Dir && self.local.role != NodeRole::Core {
            return Err(SessionReject::DirRequiresCore.into());
        }
        if self.security_mode == SecurityMode::HopOnly && !self.allow_hop_only {
            return Err(SessionReject::HopOnlyNotPermitted.into());
        }
        if self.suite == MessageSuite::Pq1024 && !self.allow_pq1024 {
            return Err(SessionReject::Pq1024NotEnabled.into());
        }
        if self.local.role == NodeRole::EnrollmentService {
            return Err(SessionReject::LocalRoleNotAllowed.into());
        }
        if !self.allowed_peer_roles.contains(&self.expected_peer.role) {
            return Err(SessionReject::PeerRoleNotAllowed.into());
        }
        Ok(())
    }

    /// Full authorization of a peer's `SessionHello` (or of the mirrored
    /// `SessionAccept` parameters, which carry the same binding with source and
    /// destination swapped).
    pub fn authorize_hello(
        &self,
        tls: &InnerTlsSession,
        hello: &SessionParams,
    ) -> Result<AuthorizedSession, TunnelError> {
        self.validate()?;
        check_inner_tls(tls, self.suite, self.allow_pq1024)?;

        // Exact peer binding through the reviewed policy gate: network, node id,
        // identity generation and role, with zero generations rejected.
        let policy = Policy {
            suite: crypto_suite(self.suite),
            allow_pq1024: self.allow_pq1024,
        };
        policy.validate_peer(
            self.expected_peer.crypto_expected(),
            tls.peer().crypto_presented(),
        )?;

        if hello.net_id != self.local.net_id {
            return Err(SessionReject::NetworkMismatch.into());
        }
        if hello.connection_instance == [0u8; 16] {
            return Err(SessionReject::ZeroConnectionInstance.into());
        }
        if hello.source_node_id != tls.peer().node_id
            || hello.source_identity_generation != tls.peer().identity_generation
        {
            return Err(SessionReject::HelloSourceMismatch.into());
        }
        if hello.source_role != peer_role(self.expected_peer.role) {
            return Err(SessionReject::PeerIdentityMismatch.into());
        }
        if hello.destination_node_id != self.local.node_id
            || hello.destination_identity_generation != self.local.identity_generation
        {
            return Err(SessionReject::HelloDestinationMismatch.into());
        }
        if hello.path_role != self.path_role {
            return Err(SessionReject::PathRoleMismatch.into());
        }
        if hello.security_mode != self.security_mode {
            return Err(SessionReject::SecurityModeMismatch.into());
        }
        if hello.suite != self.suite {
            return Err(SessionReject::SuiteMismatch.into());
        }
        if hello.mtu_cap > self.mtu_cap {
            return Err(SessionReject::MtuExceedsLocal.into());
        }
        if hello.capabilities != messages::ALLOWED_CAPABILITIES {
            return Err(SessionReject::CapabilitiesNotSupported.into());
        }

        Ok(AuthorizedSession {
            peer: tls.peer(),
            connection_instance: hello.connection_instance,
            mtu_cap: hello.mtu_cap.min(self.mtu_cap),
            security_mode: self.security_mode,
        })
    }
}

/// Result of a successful `SessionHello` authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedSession {
    pub peer: PeerIdentity,
    pub connection_instance: [u8; 16],
    pub mtu_cap: u16,
    pub security_mode: SecurityMode,
}

/// Bounded application-frame I/O over the inner TLS stream.
///
/// A partial write (header accepted, body failed) or any decode/read error
/// poisons the object permanently: the byte stream can no longer be
/// resynchronised, so later calls fail instead of emitting a torn frame.
struct FrameIo {
    stream: Box<dyn Duplex>,
    decoder: FrameDecoder,
    buffer: Vec<u8>,
    write_buf: Vec<u8>,
    // Store each decoded batch in reverse so pop() delivers it in wire order.
    pending: Vec<Frame>,
    failed: bool,
}

impl FrameIo {
    fn new(stream: Box<dyn Duplex>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::new(FRAME_BUFFER_LIMIT),
            buffer: vec![0u8; READ_CHUNK],
            write_buf: Vec::new(),
            pending: Vec::new(),
            failed: false,
        }
    }

    /// Return ownership only after the circuit consumed the last byte. Pending
    /// Frames remain exclusive owners; capacity, not logical length, is charged
    /// against the existing receive quota. There is no second spare slot.
    fn recycle_relay_body(&mut self, body: Vec<u8>) -> bool {
        let used = self.pending.iter().fold(self.decoder.body_capacity(), |used, frame| {
            used.saturating_add(frame.body.capacity())
        });
        self.decoder.recycle_empty_body(body, MAX_PENDING_BYTES.saturating_sub(used))
    }

    fn poison(&mut self) {
        self.failed = true;
        self.pending = Vec::new();
        // Drop all retained receive storage, including a recycled empty body.
        self.decoder = FrameDecoder::new(FRAME_BUFFER_LIMIT);
    }

    fn has_buffered_input(&self) -> bool {
        !self.pending.is_empty()
            || self.decoder.buffered_len() > 0
            || self.stream.has_buffered_input()
    }

    /// Disarm the bounded handshake transport deadline now that authorization
    /// is complete.
    ///
    /// The runtime arms one absolute deadline across outer TLS, the WebSocket
    /// upgrade, the inner TLS handshake and this session exchange. Leaving that
    /// deadline armed would make a legitimately idle data-plane read fail with
    /// `TimedOut`, so it is explicitly removed before the session is returned.
    ///
    /// The call is forwarded by every wrapper down to the raw transport. Every
    /// real transport layer overrides the timeout installer and the clear, so a
    /// missing forward cannot leave the socket timeout armed.
    fn end_handshake(&mut self) -> Result<(), TunnelError> {
        self.stream.clear_handshake_deadline()?;
        Ok(())
    }

    fn prepare_frame(&mut self, kind: Kind, body: &[u8]) -> Result<(), TunnelError> {
        let header = AppHeader {
            proto_major: PROTO_MAJOR,
            kind,
            flags: 0,
            body_len: u32::try_from(body.len()).map_err(|_| TunnelError::FrameTooLarge)?,
        };
        let encoded = header.encode()?;
        self.write_buf.clear();
        self.write_buf.reserve(encoded.len() + body.len());
        self.write_buf.extend_from_slice(&encoded);
        self.write_buf.extend_from_slice(body);
        Ok(())
    }

    fn send(&mut self, kind: Kind, body: &[u8]) -> Result<(), TunnelError> {
        if self.failed {
            return Err(TunnelError::Poisoned);
        }
        if let Err(error) = self.prepare_frame(kind, body) {
            self.poison();
            return Err(error);
        }
        self.send_buffered()
    }

    fn send_buffered(&mut self) -> Result<(), TunnelError> {
        if self.failed {
            return Err(TunnelError::Poisoned);
        }
        // Offer TLS the whole frame, not separate header and body writes.
        // Short writes are retried; any write or flush error is terminal.
        let result = self
            .stream
            .write_all(&self.write_buf)
            .and_then(|()| self.stream.flush());
        if result.is_err() {
            self.poison();
        }
        #[cfg(any(test, feature = "record-diagnostics"))]
        if result.is_ok() {
            crate::record_diagnostics::observe(crate::record_diagnostics::Layer::Frame, &self.write_buf);
        }
        result.map_err(TunnelError::from)
    }

    fn recv(&mut self) -> Result<Frame, TunnelError> {
        if self.failed {
            return Err(TunnelError::Poisoned);
        }
        loop {
            if let Some(frame) = self.pending.pop() {
                return Ok(frame);
            }
            let read = match self.stream.read(&mut self.buffer) {
                Ok(read) => read,
                Err(error) => {
                    self.poison();
                    return Err(error.into());
                }
            };
            if read == 0 {
                self.poison();
                return Err(TunnelError::Closed);
            }
            if let Err(error) = self.decoder.feed_into(&self.buffer[..read], &mut self.pending) {
                self.poison();
                return Err(error.into());
            }
            // Check the full batch before publishing any frame. The decoder's
            // byte limit alone does not bound queued frame metadata.
            if self.pending.len() > MAX_PENDING_FRAMES
                || self.pending.iter().map(|frame| frame.body.len()).sum::<usize>() > MAX_PENDING_BYTES
                || self.pending.iter().fold(self.decoder.body_capacity(), |used, frame| {
                    used.saturating_add(frame.body.capacity())
                }) > MAX_PENDING_BYTES
            {
                self.poison();
                return Err(TunnelError::FrameQuota);
            }
            self.pending.reverse();
        }
    }
}

/// An authorized hop session.
///
/// The type has no public constructor: only [`client_handshake`] and
/// [`server_handshake`] produce it, after TLS facts were re-checked and the
/// peer identity bound to the hello. It is not `Sync`; a single thread drives
/// it (the baseline runtime uses one thread per connection).
pub struct EstablishedSession {
    io: FrameIo,
    ctx: SessionContext,
    policy: SessionPolicy,
    authorized: AuthorizedSession,
}

impl EstablishedSession {
    pub fn peer(&self) -> PeerIdentity {
        self.authorized.peer
    }

    pub fn local(&self) -> PeerIdentity {
        self.policy.local
    }

    pub fn connection_instance(&self) -> [u8; 16] {
        self.authorized.connection_instance
    }

    pub fn mtu_cap(&self) -> u16 {
        self.authorized.mtu_cap
    }

    pub fn security_mode(&self) -> SecurityMode {
        self.authorized.security_mode
    }

    pub fn peer_role(&self) -> NodeRole {
        self.authorized.peer.role
    }

    /// Network suite negotiated for this hop. The E2E layer reuses the same
    /// policy so a downgrade cannot be introduced per circuit.
    pub fn security_suite(&self) -> MessageSuite {
        self.policy.suite
    }

    /// Whether `pq1024` was explicitly enabled for this link.
    pub fn pq1024_enabled(&self) -> bool {
        self.policy.allow_pq1024
    }

    /// Whether decoded frames or lower-layer bytes remain buffered locally.
    pub fn has_buffered_input(&self) -> bool {
        self.io.has_buffered_input()
    }

    /// Send one application frame. Frame-level state transitions are validated
    /// with the same state machine used on receive, so a control message that
    /// is illegal in the current state never reaches the wire.
    pub fn send_frame(&mut self, kind: Kind, body: &[u8]) -> Result<(), TunnelError> {
        if body.len() > MAX_BODY_LEN as usize {
            return Err(TunnelError::FrameTooLarge);
        }
        let header = AppHeader {
            proto_major: PROTO_MAJOR,
            kind,
            flags: 0,
            body_len: u32::try_from(body.len()).map_err(|_| TunnelError::FrameTooLarge)?,
        };
        if let Err(error) = boreas_proto::validate_frame_policy_parts(&header, body, &mut self.ctx)
        {
            // A state-machine violation ends the session; do not leave a
            // half-valid context that a later frame could exploit.
            self.io.poison();
            return Err(error.into());
        }
        self.io.send(kind, body)
    }

    /// Assemble a local circuit fragment directly in the session write buffer,
    /// keeping it contiguous for TLS without an intermediate payload copy.
    pub(crate) fn send_relay_fragment(
        &mut self,
        circuit_id: [u8; 16],
        direction: u8,
        byte_offset: u64,
        hops_remaining: u8,
        payload: &[u8],
    ) -> Result<(), TunnelError> {
        let fragment_header = messages::RelayFragment::encode_header(
            circuit_id,
            direction,
            byte_offset,
            hops_remaining,
            payload.len(),
        )?;
        let body_len = fragment_header.len() + payload.len();
        let header = AppHeader {
            proto_major: PROTO_MAJOR,
            kind: Kind::RelayCircuit,
            flags: 0,
            body_len: u32::try_from(body_len).map_err(|_| TunnelError::FrameTooLarge)?,
        };
        if self.io.failed {
            return Err(TunnelError::Poisoned);
        }
        let encoded = header.encode()?;
        let wire = &mut self.io.write_buf;
        wire.clear();
        wire.reserve(HEADER_LEN + body_len);
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&fragment_header);
        wire.extend_from_slice(payload);
        if let Err(error) =
            boreas_proto::validate_frame_policy_parts(&header, &wire[HEADER_LEN..], &mut self.ctx)
        {
            self.io.poison();
            return Err(error.into());
        }
        self.io.send_buffered()
    }

    pub(crate) fn recycle_relay_body(&mut self, body: Vec<u8>) -> bool {
        if self.io.failed { return false; }
        self.io.recycle_relay_body(body)
    }

    /// Receive one application frame and apply the frame-level state machine.
    pub fn recv_frame(&mut self) -> Result<Frame, TunnelError> {
        let frame = self.io.recv()?;
        if let Err(error) = boreas_proto::validate_frame_policy(&frame, &mut self.ctx) {
            self.io.poison();
            return Err(error.into());
        }
        Ok(frame)
    }

    /// Send a control body that must begin with the declared subtype byte.
    pub fn send_control(&mut self, control: ControlType, body: &[u8]) -> Result<(), TunnelError> {
        if body.first().copied() != Some(control as u8) {
            return Err(SessionReject::ControlSubtypeMismatch.into());
        }
        self.send_frame(Kind::Control, body)
    }
}

fn accepted_context(policy: &SessionPolicy, authorized: &AuthorizedSession) -> SessionContext {
    SessionContext {
        hello_received: true,
        accepted: true,
        identity_registered: policy.identity_registered,
        peer_role: peer_role(authorized.peer.role),
        enrollment_service: false,
        circuit_opening: false,
        circuit_established: false,
        mode: authorized.security_mode,
        net_id: policy.local.net_id,
    }
}

// --- Candidate `boreas-proto` call sites -------------------------------------
// Kept behind these two functions so a schema change in `messages.rs` has one
// place to adapt instead of touching the session state machine.

fn decode_session_hello(body: &[u8]) -> Result<SessionParams, TunnelError> {
    Ok(SessionHello::decode(body)?.params)
}

/// Parse a `SessionAccept` and require it to be the exact mirror of `hello`
/// built from the locally authenticated identity.
fn decode_session_accept(
    body: &[u8],
    hello: SessionParams,
    local: LocalIdentity,
) -> Result<SessionParams, TunnelError> {
    Ok(SessionAccept::decode_for_hello(body, &hello, local)?.params)
}

fn local_identity(peer: PeerIdentity) -> LocalIdentity {
    LocalIdentity {
        node_id: peer.node_id,
        identity_generation: peer.identity_generation,
        role: peer_role(peer.role),
    }
}

fn peer_role(role: NodeRole) -> PeerRole {
    match role {
        NodeRole::Edge => PeerRole::Edge,
        NodeRole::Core => PeerRole::Core,
        NodeRole::EnrollmentService => PeerRole::EnrollmentService,
    }
}

fn encode_session_hello(params: SessionParams) -> Result<Vec<u8>, TunnelError> {
    Ok(SessionHello { params }.encode()?.to_vec())
}

fn encode_session_accept(params: SessionParams) -> Result<Vec<u8>, TunnelError> {
    Ok(SessionAccept { params }.encode()?.to_vec())
}

/// Connector side: send `SessionHello`, require a mirroring `SessionAccept`,
/// then re-authorize the accepted parameters through the same checks.
///
/// `transport` is expected to carry the runtime's bounded handshake deadline.
/// This function does not invent one; it disarms that deadline after the peer is
/// authorized so the data plane does not inherit a handshake timeout.
pub fn client_handshake(
    transport: Box<dyn Duplex>,
    tls: &InnerTlsSession,
    policy: SessionPolicy,
) -> Result<EstablishedSession, TunnelError> {
    policy.validate()?;
    check_inner_tls(tls, policy.suite, policy.allow_pq1024)?;

    // The connector already knows which node it dialed; enforce the exact
    // binding before any application byte is written.
    let gate = Policy {
        suite: crypto_suite(policy.suite),
        allow_pq1024: policy.allow_pq1024,
    };
    gate.validate_peer(
        policy.expected_peer.crypto_expected(),
        tls.peer().crypto_presented(),
    )?;

    let instance: [u8; 16] = csprng::random_array()?;
    if instance == [0u8; 16] {
        return Err(TunnelError::Entropy);
    }
    let hello = SessionParams {
        proto_major: PROTO_MAJOR,
        net_id: policy.local.net_id,
        source_node_id: policy.local.node_id,
        destination_node_id: policy.expected_peer.node_id,
        source_identity_generation: policy.local.identity_generation,
        destination_identity_generation: policy.expected_peer.identity_generation,
        connection_instance: instance,
        source_role: peer_role(policy.local.role),
        path_role: policy.path_role,
        security_mode: policy.security_mode,
        mtu_cap: policy.mtu_cap,
        suite: policy.suite,
        capabilities: 0,
    };

    let mut io = FrameIo::new(transport);
    io.send(Kind::Control, &encode_session_hello(hello)?)?;
    let frame = io.recv()?;
    if frame.header.kind != Kind::Control {
        return Err(SessionReject::FirstFrameNotHello.into());
    }
    if frame.body.first().copied() != Some(ControlType::SessionAccept as u8) {
        return Err(SessionReject::FirstFrameNotHello.into());
    }
    let accept = decode_session_accept(&frame.body, hello, local_identity(policy.expected_peer))?;
    let authorized = policy.authorize_hello(tls, &accept)?;
    io.end_handshake()?;
    let ctx = accepted_context(&policy, &authorized);
    Ok(EstablishedSession {
        io,
        ctx,
        policy,
        authorized,
    })
}

/// Acceptor side: require `SessionHello` as the first frame, authorize it, then
/// send the mirroring `SessionAccept`.
///
/// `transport` is expected to carry the runtime's bounded handshake deadline;
/// this function disarms it after sending the accept.
pub fn server_handshake(
    transport: Box<dyn Duplex>,
    tls: &InnerTlsSession,
    policy: SessionPolicy,
) -> Result<EstablishedSession, TunnelError> {
    policy.validate()?;
    check_inner_tls(tls, policy.suite, policy.allow_pq1024)?;

    let mut io = FrameIo::new(transport);
    let frame = io.recv()?;
    if frame.header.kind != Kind::Control {
        return Err(SessionReject::FirstFrameNotHello.into());
    }
    if frame.body.first().copied() != Some(ControlType::SessionHello as u8) {
        return Err(SessionReject::FirstFrameNotHello.into());
    }
    let hello = decode_session_hello(&frame.body)?;
    let authorized = policy.authorize_hello(tls, &hello)?;

    // The proto layer builds the exact Accept tuple from the received Hello and
    // the locally authenticated identity (source/destination and generations
    // swapped, all shared fields echoed) and validates the destination binding.
    let accept = SessionParams::accept_for(&hello, local_identity(policy.local))?;
    io.send(Kind::Control, &encode_session_accept(accept)?)?;
    io.end_handshake()?;

    let ctx = accepted_context(&policy, &authorized);
    Ok(EstablishedSession {
        io,
        ctx,
        policy,
        authorized,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::strict_test_negotiated;
    use boreas_crypto::PolicyError;
    use boreas_proto::messages::Suite as TestSuite;
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordedIo {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
    }

    struct RecordingStream {
        record: Arc<Mutex<RecordedIo>>,
        write_limit: Option<usize>,
        fail_flush: bool,
    }

    impl Read for RecordingStream {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut record = self.record.lock().unwrap();
            record.writes += 1;
            let n = self.write_limit.map_or(buf.len(), |limit| {
                buf.len().min(limit.saturating_sub(record.bytes.len()))
            });
            if n == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            record.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.record.lock().unwrap().flushes += 1;
            if self.fail_flush {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            Ok(())
        }
    }

    impl Duplex for RecordingStream {
        fn has_buffered_input(&self) -> bool {
            false
        }
    }

    fn recording_session(
        circuit_established: bool,
        write_limit: Option<usize>,
        fail_flush: bool,
    ) -> (EstablishedSession, Arc<Mutex<RecordedIo>>) {
        let policy = policy();
        let authorized = AuthorizedSession {
            peer: policy.expected_peer,
            connection_instance: [1; 16],
            mtu_cap: policy.mtu_cap,
            security_mode: policy.security_mode,
        };
        let mut ctx = accepted_context(&policy, &authorized);
        ctx.circuit_established = circuit_established;
        let record = Arc::new(Mutex::new(RecordedIo::default()));
        let io = FrameIo::new(Box::new(RecordingStream {
            record: Arc::clone(&record),
            write_limit,
            fail_flush,
        }));
        (
            EstablishedSession {
                io,
                ctx,
                policy,
                authorized,
            },
            record,
        )
    }

    #[test]
    fn receive_reuses_one_batch_and_preserves_fifo() {
        let mut batch = Vec::new();
        for value in [1, 2, 3] {
            let header = AppHeader {
                proto_major: PROTO_MAJOR, kind: Kind::Control, flags: 0, body_len: 1,
            };
            batch.extend_from_slice(&header.encode().unwrap());
            batch.push(value);
        }
        let mut io = FrameIo::new(Box::new(std::io::Cursor::new(batch.clone())));
        for value in [1, 2, 3] {
            assert_eq!(io.recv().unwrap().body, [value]);
        }
        assert!(!io.has_buffered_input());
        let mut io = FrameIo::new(Box::new(std::io::Cursor::new(batch.repeat(MAX_PENDING_FRAMES))));
        assert!(matches!(io.recv(), Err(TunnelError::FrameQuota)));
        assert!(!io.has_buffered_input());
        assert!(matches!(io.recv(), Err(TunnelError::Poisoned)));
    }

    #[test]
    fn recycled_slot_charges_real_capacity_and_preserves_pending_owners() {
        let mut io = FrameIo::new(Box::new(std::io::Cursor::new(Vec::new())));
        let pending = Frame {
            header: AppHeader { proto_major: PROTO_MAJOR, kind: Kind::RelayCircuit,
                flags: 0, body_len: 1 },
            body: { let mut body = Vec::with_capacity(MAX_PENDING_BYTES - 16384);
                body.push(0xa5); body },
        };
        let ptr = pending.body.as_ptr();
        io.pending.push(pending);
        assert!(!io.recycle_relay_body(Vec::with_capacity(16385)));
        assert_eq!(io.decoder.body_capacity(), 0);
        assert!(io.recycle_relay_body(Vec::with_capacity(16384)));
        assert_eq!(io.pending[0].body.as_ptr(), ptr);
        assert_eq!(io.pending[0].body, [0xa5]);
        assert_eq!(io.pending[0].body.capacity() + io.decoder.body_capacity(), MAX_PENDING_BYTES);
        assert!(!io.recycle_relay_body(Vec::with_capacity(1)));
        io.poison();
        assert!(io.pending.is_empty());
        assert_eq!(io.decoder.body_capacity(), 0);
        assert!(matches!(io.recv(), Err(TunnelError::Poisoned)));
    }

    #[test]
    fn relay_write_keeps_wire_format_and_one_write_per_frame() {
        let (mut session, record) = recording_session(true, None, false);
        let max_payload = vec![0xa5; messages::MAX_RELAY_PAYLOAD];
        let id = [0x2a; 16];
        let next_offset = max_payload.len() as u64;
        session
            .send_relay_fragment(id, 1, 0, 2, &max_payload)
            .unwrap();
        session
            .send_relay_fragment(id, 1, next_offset, 2, b"tail")
            .unwrap();

        let record = record.lock().unwrap();
        assert_eq!((record.writes, record.flushes), (2, 2));
        let mut remaining = record.bytes.as_slice();
        for (offset, payload) in [(0, max_payload.as_slice()), (next_offset, b"tail")] {
            let header = AppHeader::parse(remaining[..HEADER_LEN].try_into().unwrap()).unwrap();
            assert_eq!(header.kind, Kind::RelayCircuit);
            assert_eq!(header.flags, 0);
            let frame_len = HEADER_LEN + header.body_len as usize;
            let body = &remaining[HEADER_LEN..frame_len];
            let fragment = messages::RelayFragment::decode_ref(body).unwrap();
            assert_eq!(fragment.circuit_id, id);
            assert_eq!(fragment.direction, 1);
            assert_eq!(fragment.byte_offset, offset);
            assert_eq!(fragment.hops_remaining, 2);
            assert_eq!(fragment.payload, payload);
            remaining = &remaining[frame_len..];
        }
        assert!(remaining.is_empty());
    }

    #[test]
    fn relay_write_preserves_bounds_and_session_policy() {
        let id = [0x2a; 16];
        let (mut session, record) = recording_session(false, None, false);
        let oversized = vec![0; messages::MAX_RELAY_PAYLOAD + 1];
        for (direction, offset, hops, payload, error) in [
            (
                2,
                0,
                1,
                b"x".as_slice(),
                messages::MessageError::InvalidDirection(2),
            ),
            (
                0,
                0,
                0,
                b"x".as_slice(),
                messages::MessageError::InvalidHopCount(0),
            ),
            (
                0,
                u64::MAX,
                1,
                b"x".as_slice(),
                messages::MessageError::OffsetOverflow,
            ),
            (
                0,
                0,
                1,
                oversized.as_slice(),
                messages::MessageError::PayloadTooLarge(oversized.len()),
            ),
        ] {
            assert_eq!(
                session.send_relay_fragment(id, direction, offset, hops, payload),
                Err(TunnelError::Message(error)),
            );
        }
        assert_eq!(
            session.send_relay_fragment(id, 0, 0, 1, b"x"),
            Err(TunnelError::Frame(boreas_proto::Error::IllegalState)),
        );
        assert_eq!(
            session.send_relay_fragment(id, 0, 0, 1, b"x"),
            Err(TunnelError::Poisoned),
        );
        let record = record.lock().unwrap();
        assert_eq!((record.writes, record.flushes), (0, 0));
    }

    #[test]
    fn relay_partial_write_or_flush_failure_poisons_all_writes() {
        let id = [0x2a; 16];
        for (limit, fail_flush, calls) in [(Some(3), false, (2, 0)), (None, true, (1, 1))] {
            let (mut session, record) = recording_session(true, limit, fail_flush);
            assert_eq!(
                session.send_relay_fragment(id, 0, 0, 1, b"payload"),
                Err(TunnelError::Io(io::ErrorKind::BrokenPipe)),
            );
            assert_eq!(
                session.send_relay_fragment(id, 0, 0, 1, b"retry"),
                Err(TunnelError::Poisoned),
            );
            assert_eq!(
                session.send_control(ControlType::Probe, &[ControlType::Probe as u8]),
                Err(TunnelError::Poisoned),
            );
            let record = record.lock().unwrap();
            assert_eq!((record.writes, record.flushes), calls);
        }
    }

    fn identity(node_id: u16, generation: u64, role: NodeRole) -> PeerIdentity {
        PeerIdentity::legacy_default([7; 16], node_id, generation, role)
    }

    fn policy() -> SessionPolicy {
        SessionPolicy {
            local: identity(0x0101, 4, NodeRole::Edge),
            expected_peer: identity(0x0102, 9, NodeRole::Core),
            path_role: PathRole::Cdn,
            security_mode: SecurityMode::E2eRequired,
            suite: TestSuite::Pq768,
            mtu_cap: 1400,
            identity_registered: true,
            allow_pq1024: false,
            allow_hop_only: false,
            allowed_peer_roles: vec![NodeRole::Core],
        }
    }

    fn tls(peer: PeerIdentity) -> InnerTlsSession {
        InnerTlsSession::test_only(peer, strict_test_negotiated())
    }

    fn hello(policy: &SessionPolicy) -> SessionParams {
        SessionParams {
            proto_major: PROTO_MAJOR,
            net_id: policy.local.net_id,
            source_node_id: policy.expected_peer.node_id,
            destination_node_id: policy.local.node_id,
            source_identity_generation: policy.expected_peer.identity_generation,
            destination_identity_generation: policy.local.identity_generation,
            connection_instance: [3; 16],
            source_role: peer_role(policy.expected_peer.role),
            path_role: policy.path_role,
            security_mode: policy.security_mode,
            mtu_cap: 1200,
            suite: policy.suite,
            capabilities: 0,
        }
    }

    #[test]
    fn authorizes_exact_peer_and_bounds_mtu() {
        let policy = policy();
        let authorized = policy
            .authorize_hello(&tls(policy.expected_peer), &hello(&policy))
            .expect("authorized");
        assert_eq!(authorized.mtu_cap, 1200);
        assert_eq!(authorized.connection_instance, [3; 16]);
        assert_eq!(authorized.peer, policy.expected_peer);
    }

    #[test]
    fn rejects_wrong_network_identity() {
        let policy = policy();
        let mut presented = policy.expected_peer;
        presented.net_id = [8; 16];
        assert_eq!(
            policy.authorize_hello(&tls(presented), &hello(&policy)),
            Err(TunnelError::Policy(PolicyError::PeerMismatch))
        );
    }

    #[test]
    fn rejects_source_and_destination_mismatch() {
        let policy = policy();
        let mut wrong_source = hello(&policy);
        wrong_source.source_identity_generation = 8;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &wrong_source),
            Err(TunnelError::Session(SessionReject::HelloSourceMismatch))
        );

        let mut wrong_destination = hello(&policy);
        wrong_destination.destination_node_id = 0x0103;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &wrong_destination),
            Err(TunnelError::Session(
                SessionReject::HelloDestinationMismatch
            ))
        );
    }

    #[test]
    fn rejects_zero_instance_and_capabilities() {
        let policy = policy();
        let mut zero_instance = hello(&policy);
        zero_instance.connection_instance = [0; 16];
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &zero_instance),
            Err(TunnelError::Session(SessionReject::ZeroConnectionInstance))
        );

        let mut capabilities = hello(&policy);
        capabilities.capabilities = 1;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &capabilities),
            Err(TunnelError::Session(
                SessionReject::CapabilitiesNotSupported
            ))
        );
    }

    #[test]
    fn hop_only_and_pq1024_need_explicit_enablement() {
        let mut hop_only = policy();
        hop_only.security_mode = SecurityMode::HopOnly;
        assert_eq!(
            hop_only.validate(),
            Err(TunnelError::Session(SessionReject::HopOnlyNotPermitted))
        );
        hop_only.allow_hop_only = true;
        assert_eq!(hop_only.validate(), Ok(()));

        let mut pq1024 = policy();
        pq1024.suite = TestSuite::Pq1024;
        assert_eq!(
            pq1024.validate(),
            Err(TunnelError::Session(SessionReject::Pq1024NotEnabled))
        );
    }

    #[test]
    fn dir_listener_requires_core_role() {
        let mut policy = policy();
        policy.path_role = PathRole::Dir;
        assert_eq!(
            policy.validate(),
            Err(TunnelError::Session(SessionReject::DirRequiresCore))
        );
        policy.local.role = NodeRole::Core;
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn peer_role_must_be_explicitly_allowed() {
        let mut policy = policy();
        policy.allowed_peer_roles = vec![NodeRole::Edge];
        assert_eq!(
            policy.validate(),
            Err(TunnelError::Session(SessionReject::PeerRoleNotAllowed))
        );
    }

    #[test]
    fn suite_and_mode_must_match_local_policy() {
        let policy = policy();
        let mut hop_only_hello = hello(&policy);
        hop_only_hello.security_mode = SecurityMode::HopOnly;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &hop_only_hello),
            Err(TunnelError::Session(SessionReject::SecurityModeMismatch))
        );

        let mut pq768_dir = hello(&policy);
        pq768_dir.path_role = PathRole::Dir;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &pq768_dir),
            Err(TunnelError::Session(SessionReject::PathRoleMismatch))
        );
    }

    #[test]
    fn mtu_above_local_cap_is_rejected() {
        let policy = policy();
        let mut hello = hello(&policy);
        hello.mtu_cap = 1500;
        assert_eq!(
            policy.authorize_hello(&tls(policy.expected_peer), &hello),
            Err(TunnelError::Session(SessionReject::MtuExceedsLocal))
        );
    }
}
