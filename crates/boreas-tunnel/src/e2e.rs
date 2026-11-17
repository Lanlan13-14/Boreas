//! End-to-end virtual circuits over an authorized hop session.
//!
//! A circuit is a reliable ordered byte stream carried in `RelayCircuit`
//! fragments (`kind = 3`). It is not a security layer by itself: fragments are
//! protected by the hop TLS session and the payload is protected by the E2E TLS
//! session that runs on top of this byte stream. Core relays only forward
//! bounded fragments and never hold E2E secrets.
//!
//! # Circuit control bodies (candidate, owned by `boreas-proto`)
//!
//! The 28/18/17/17-byte layouts below are the agreed candidate schema with
//! `boreas-proto`: `CircuitOpen` = subtype + `circuit_id[16]` + destination
//! node id (BE u16) + destination identity generation (BE u64) + `path_hops`;
//! `CircuitAccept` = subtype + id + `path_hops`; `CircuitReset` / `CircuitClose`
//! = subtype + id. `boreas-proto` will publish `messages::CircuitOpen` etc.
//! The `codec` section is the **only** place that touches these bytes; when the
//! typed proto API lands, those six functions are replaced one-for-one. Do not
//! add a second wire format.
//!
//! `path_hops` is the circuit length in hop links (`1..=MAX_RELAY_HOPS`). Every
//! fragment carries a `hops_remaining` budget that starts at `path_hops` and is
//! decremented by each relay; endpoints accept only `1..=path_hops`, and a relay
//! refuses to forward when the budget is 1.
//!
//! # TLS role is not the circuit role
//!
//! The plan fixes the **lower `NodeID`** endpoint as the E2E TLS client,
//! independent of which side opened the circuit (RFC-style "client" is a TLS
//! role, not an authorization to carry business traffic). [`e2e_tls_role`]
//! derives it from node identities only.
//!
//! # Bounds
//!
//! One circuit per hop session: the `boreas-proto` application state machine
//! tracks a single `circuit_opening`/`circuit_established` pair. Multiple
//! circuits per node pair need a per-circuit table and are a later slice.
//! Fragment payloads are bounded by `messages::MAX_RELAY_PAYLOAD`; offsets must
//! be exactly contiguous per direction.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::time::Instant;

use boreas_crypto::NodeRole;
use boreas_proto::messages::{
    self, CircuitAccept as ProtoCircuitAccept, CircuitClose as ProtoCircuitClose,
    CircuitOpen as ProtoCircuitOpen, CircuitReset as ProtoCircuitReset, RelayFragment,
    Suite as MessageSuite,
};
use boreas_proto::{ControlType, Kind, SecurityMode};

use crate::csprng;
use crate::error::{CircuitReject, SessionReject, TunnelError};
use crate::relay::{
    CircuitId, Direction, HopSessionToken, MAX_RELAY_HOPS, NodeRef, RelayTable, Segment,
    VerifiedE2eSession,
};
use crate::resource::Admission;
use crate::runtime::{DiagnosticTimer, diagnostic_timing_enabled};
use crate::session::EstablishedSession;
use crate::stream::Duplex;
use crate::tls::{InnerTlsSession, PeerIdentity};

const CIRCUIT_ID_LEN: usize = 16;
/// Encoded `CircuitOpen` body length, including the subtype byte.
pub const CIRCUIT_OPEN_BODY_LEN: usize = 1 + CIRCUIT_ID_LEN + 2 + 8 + 1;
/// Encoded `CircuitAccept` body length, including the subtype byte.
pub const CIRCUIT_ACCEPT_BODY_LEN: usize = 1 + CIRCUIT_ID_LEN + 1;
/// Encoded `CircuitReset` / `CircuitClose` body length.
pub const CIRCUIT_ID_BODY_LEN: usize = 1 + CIRCUIT_ID_LEN;
/// Largest payload one fragment can carry.
pub const MAX_FRAGMENT_PAYLOAD: usize = messages::MAX_RELAY_PAYLOAD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitRole {
    /// Opened the circuit; writes `direction = 0`.
    Initiator,
    /// Accepted the circuit; writes `direction = 1`.
    Acceptor,
}

impl CircuitRole {
    fn outbound(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Acceptor => 1,
        }
    }

    fn inbound(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Acceptor => 0,
        }
    }
}

/// Which side of the **E2E TLS** handshake a node takes.
///
/// This is not the circuit role and not an authorization: it only decides who
/// sends the TLS ClientHello. The lower `NodeID` is always the client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitTlsRole {
    Client,
    Server,
}

/// Lower `NodeID` is the TLS client, independent of who opened the circuit.
pub fn e2e_tls_role(local_node_id: u16, peer_node_id: u16) -> CircuitTlsRole {
    if local_node_id < peer_node_id {
        CircuitTlsRole::Client
    } else {
        CircuitTlsRole::Server
    }
}

/// Circuit identity plus its declared path length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitInfo {
    pub circuit_id: [u8; CIRCUIT_ID_LEN],
    pub path_hops: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CircuitBinding {
    circuit_id: [u8; CIRCUIT_ID_LEN],
    destination: NodeRef,
    path_hops: u8,
}

// --- codec: delegates to `boreas-proto` typed circuit bodies ------------------

fn encode_open(binding: &CircuitBinding) -> Result<Vec<u8>, TunnelError> {
    Ok(ProtoCircuitOpen {
        circuit_id: binding.circuit_id,
        destination_node_id: binding.destination.node_id,
        destination_identity_generation: binding.destination.identity_generation,
        path_hops: binding.path_hops,
    }
    .encode()?)
}

fn decode_open(body: &[u8]) -> Result<CircuitBinding, TunnelError> {
    let open = ProtoCircuitOpen::decode(body)?;
    Ok(CircuitBinding {
        circuit_id: open.circuit_id,
        destination: NodeRef {
            node_id: open.destination_node_id,
            identity_generation: open.destination_identity_generation,
        },
        path_hops: open.path_hops,
    })
}

fn encode_accept(circuit_id: [u8; CIRCUIT_ID_LEN], path_hops: u8) -> Result<Vec<u8>, TunnelError> {
    Ok(ProtoCircuitAccept {
        circuit_id,
        path_hops,
    }
    .encode()?)
}

fn decode_accept(body: &[u8], expected: [u8; CIRCUIT_ID_LEN]) -> Result<u8, TunnelError> {
    let accept = ProtoCircuitAccept::decode(body)?;
    if accept.circuit_id != expected {
        return Err(CircuitReject::UnknownCircuit.into());
    }
    Ok(accept.path_hops)
}

fn encode_reset(circuit_id: [u8; CIRCUIT_ID_LEN]) -> Result<Vec<u8>, TunnelError> {
    Ok(ProtoCircuitReset { circuit_id }.encode()?)
}

fn encode_close(circuit_id: [u8; CIRCUIT_ID_LEN]) -> Result<Vec<u8>, TunnelError> {
    Ok(ProtoCircuitClose { circuit_id }.encode()?)
}

fn decode_control_id(
    body: &[u8],
    subtype: ControlType,
) -> Result<[u8; CIRCUIT_ID_LEN], TunnelError> {
    match subtype {
        ControlType::CircuitReset => Ok(ProtoCircuitReset::decode(body)?.circuit_id),
        ControlType::CircuitClose => Ok(ProtoCircuitClose::decode(body)?.circuit_id),
        _ => Err(CircuitReject::BadBody.into()),
    }
}

// --- circuit byte stream -----------------------------------------------------

/// A circuit exposed as a byte stream.
///
/// Implements [`Read`]/[`Write`] so it can be handed directly to the reviewed
/// E2E TLS backend as its transport; no extra socket is opened. One `write`
/// call emits one fragment of at most [`MAX_FRAGMENT_PAYLOAD`] bytes.
pub struct CircuitStream<'a> {
    session: &'a mut EstablishedSession,
    circuit_id: [u8; CIRCUIT_ID_LEN],
    role: CircuitRole,
    path_hops: u8,
    send_offset: u64,
    recv_offset: u64,
    inbound: VecDeque<u8>,
    closed: bool,
}

impl<'a> CircuitStream<'a> {
    fn new(
        session: &'a mut EstablishedSession,
        circuit_id: [u8; CIRCUIT_ID_LEN],
        role: CircuitRole,
        path_hops: u8,
    ) -> Self {
        Self {
            session,
            circuit_id,
            role,
            path_hops,
            send_offset: 0,
            recv_offset: 0,
            inbound: VecDeque::new(),
            closed: false,
        }
    }

    pub fn circuit_id(&self) -> [u8; CIRCUIT_ID_LEN] {
        self.circuit_id
    }

    pub fn role(&self) -> CircuitRole {
        self.role
    }

    pub fn path_hops(&self) -> u8 {
        self.path_hops
    }

    /// Whether a previous read left bytes above the raw hop socket.
    pub fn has_buffered_input(&self) -> bool {
        !self.inbound.is_empty() || self.session.has_buffered_input()
    }

    /// Send up to [`MAX_FRAGMENT_PAYLOAD`] bytes as one fragment.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<usize, TunnelError> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Err(CircuitReject::Closed.into());
        }
        let take = data.len().min(MAX_FRAGMENT_PAYLOAD);
        let fragment = RelayFragment {
            circuit_id: self.circuit_id,
            direction: self.role.outbound(),
            byte_offset: self.send_offset,
            hops_remaining: self.path_hops,
            payload: data[..take].to_vec(),
        };
        self.session
            .send_frame(Kind::RelayCircuit, &fragment.encode()?)?;
        let advance =
            u64::try_from(take).map_err(|_| TunnelError::Circuit(CircuitReject::BadBody))?;
        self.send_offset = self
            .send_offset
            .checked_add(advance)
            .ok_or(TunnelError::Circuit(CircuitReject::OffsetMismatch))?;
        Ok(take)
    }

    /// Read bytes delivered for this circuit; `Ok(0)` means the peer closed it.
    pub fn read_bytes(&mut self, out: &mut [u8]) -> Result<usize, TunnelError> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.inbound.is_empty() {
                let take = self.inbound.len().min(out.len());
                for slot in out.iter_mut().take(take) {
                    *slot = self.inbound.pop_front().expect("length checked");
                }
                return Ok(take);
            }
            if self.closed {
                return Ok(0);
            }
            self.fill_inbound()?;
        }
    }

    fn fill_inbound(&mut self) -> Result<(), TunnelError> {
        let frame = self.session.recv_frame()?;
        match frame.header.kind {
            Kind::RelayCircuit => {
                let fragment = RelayFragment::decode(&frame.body)?;
                if fragment.circuit_id != self.circuit_id {
                    return Err(CircuitReject::UnknownCircuit.into());
                }
                if fragment.direction != self.role.inbound() {
                    return Err(CircuitReject::DirectionMismatch.into());
                }
                if fragment.hops_remaining == 0 || fragment.hops_remaining > self.path_hops {
                    return Err(CircuitReject::HopsMismatch.into());
                }
                if fragment.payload.is_empty() {
                    return Err(CircuitReject::BadBody.into());
                }
                if fragment.byte_offset != self.recv_offset {
                    self.reset_best_effort();
                    return Err(CircuitReject::OffsetMismatch.into());
                }
                let advance = u64::try_from(fragment.payload.len())
                    .map_err(|_| TunnelError::Circuit(CircuitReject::OffsetMismatch))?;
                self.recv_offset = self
                    .recv_offset
                    .checked_add(advance)
                    .ok_or(TunnelError::Circuit(CircuitReject::OffsetMismatch))?;
                self.inbound.extend(fragment.payload);
                Ok(())
            }
            Kind::Control => {
                let subtype = frame.body.first().copied().ok_or(CircuitReject::BadBody)?;
                if subtype == ControlType::CircuitReset as u8 {
                    // The subtype is not enough: a reset for a different
                    // circuit must never tear this stream down.
                    let circuit_id = decode_control_id(&frame.body, ControlType::CircuitReset)?;
                    if circuit_id != self.circuit_id {
                        self.closed = true;
                        return Err(CircuitReject::UnknownCircuit.into());
                    }
                    self.closed = true;
                    return Err(CircuitReject::ResetReceived.into());
                }
                if subtype == ControlType::CircuitClose as u8 {
                    let circuit_id = decode_control_id(&frame.body, ControlType::CircuitClose)?;
                    if circuit_id != self.circuit_id {
                        self.closed = true;
                        return Err(CircuitReject::UnknownCircuit.into());
                    }
                    self.closed = true;
                    return Ok(());
                }
                Err(CircuitReject::UnexpectedFrame.into())
            }
            Kind::HopIpBatch => Err(CircuitReject::UnexpectedFrame.into()),
        }
    }

    fn reset_best_effort(&mut self) {
        let Ok(body) = encode_reset(self.circuit_id) else {
            return;
        };
        let _ = self.session.send_control(ControlType::CircuitReset, &body);
        self.closed = true;
    }

    /// Close the circuit and give the hop session borrow back.
    pub fn finish(mut self) -> Result<(), TunnelError> {
        let body = encode_close(self.circuit_id)?;
        let result = self.session.send_control(ControlType::CircuitClose, &body);
        self.closed = true;
        result
    }
}

impl Drop for CircuitStream<'_> {
    fn drop(&mut self) {
        // A TLS/backend/confirmation error destroys the underlying byte stream.
        // Tear down the circuit as well; never reinterpret this as hop-only.
        if !self.closed {
            self.reset_best_effort();
        }
    }
}

impl Read for CircuitStream<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_bytes(out)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl Write for CircuitStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_bytes(buf)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Open a circuit to `destination` through the current hop. Blocks until the
/// peer's `CircuitAccept` arrives.
pub fn open_circuit<'a>(
    session: &'a mut EstablishedSession,
    destination: NodeRef,
    path_hops: u8,
) -> Result<(CircuitStream<'a>, CircuitInfo), TunnelError> {
    if session.security_mode() != SecurityMode::E2eRequired {
        return Err(CircuitReject::NotE2eRequired.into());
    }
    if path_hops == 0 || path_hops > MAX_RELAY_HOPS {
        return Err(CircuitReject::BadBody.into());
    }
    if destination.node_id == 0
        || destination.identity_generation == 0
        || destination.node_id == session.local().node_id
    {
        return Err(CircuitReject::WrongDestination.into());
    }
    let circuit_id: [u8; CIRCUIT_ID_LEN] = csprng::random_array()?;
    if circuit_id == [0u8; CIRCUIT_ID_LEN] {
        return Err(TunnelError::Entropy);
    }
    let binding = CircuitBinding {
        circuit_id,
        destination,
        path_hops,
    };
    session.send_control(ControlType::CircuitOpen, &encode_open(&binding)?)?;
    let frame = session.recv_frame()?;
    if frame.header.kind != Kind::Control {
        return Err(CircuitReject::UnexpectedFrame.into());
    }
    let echoed = decode_accept(&frame.body, circuit_id)?;
    if echoed != path_hops {
        return Err(CircuitReject::HopsMismatch.into());
    }
    let info = CircuitInfo {
        circuit_id,
        path_hops,
    };
    Ok((
        CircuitStream::new(session, circuit_id, CircuitRole::Initiator, path_hops),
        info,
    ))
}

/// Accept a circuit opened by the current hop peer.
pub fn accept_circuit<'a>(
    session: &'a mut EstablishedSession,
) -> Result<(CircuitStream<'a>, CircuitInfo), TunnelError> {
    if session.security_mode() != SecurityMode::E2eRequired {
        return Err(CircuitReject::NotE2eRequired.into());
    }
    let frame = session.recv_frame()?;
    if frame.header.kind != Kind::Control {
        return Err(CircuitReject::UnexpectedFrame.into());
    }
    let binding = decode_open(&frame.body)?;
    let local = session.local();
    if binding.destination.node_id != local.node_id
        || binding.destination.identity_generation != local.identity_generation
    {
        return Err(CircuitReject::WrongDestination.into());
    }
    let circuit_id = binding.circuit_id;
    session.send_control(
        ControlType::CircuitAccept,
        &encode_accept(circuit_id, binding.path_hops)?,
    )?;
    let info = CircuitInfo {
        circuit_id,
        path_hops: binding.path_hops,
    };
    Ok((
        CircuitStream::new(
            session,
            circuit_id,
            CircuitRole::Acceptor,
            binding.path_hops,
        ),
        info,
    ))
}

// --- E2E TLS seam ------------------------------------------------------------

/// E2E byte stream with a protocol-specific planned-stop notification.
///
/// Kept separate from `Duplex` so its blanket implementation does not hide
/// TLS shutdown behind a no-op implementation.
pub trait E2eStream: Duplex {
    fn close_stream(&mut self) -> io::Result<()>;
}

/// E2E TLS session established over a circuit byte stream.
///
/// Fields are private: only the in-tree E2E backend adapter pairs a stream with
/// its verified facts.
pub struct E2eEstablished<'a> {
    stream: Box<dyn E2eStream + 'a>,
    session: InnerTlsSession,
}

impl<'a> E2eEstablished<'a> {
    #[cfg(any(feature = "openssl-inner-tls", test))]
    pub(crate) fn new(stream: Box<dyn E2eStream + 'a>, session: InnerTlsSession) -> Self {
        Self { stream, session }
    }

    pub fn session(&self) -> &InnerTlsSession {
        &self.session
    }

    pub fn into_parts(self) -> (Box<dyn E2eStream + 'a>, InnerTlsSession) {
        (self.stream, self.session)
    }

    /// End the E2E TLS record layer with `close_notify` before the circuit is
    /// torn down. Raw test streams implement this as a no-op.
    pub fn close_tls(&mut self) -> io::Result<()> {
        self.stream.close_stream()
    }
}

/// Runs the E2E TLS handshake over a circuit in either role.
///
/// The same reviewed backend used for the hop session implements this trait.
/// Implementations must not choose the role from who opened the circuit.
pub trait E2eTlsBackend: Send + Sync {
    fn connect<'a>(&self, transport: CircuitStream<'a>) -> Result<E2eEstablished<'a>, TunnelError>;
    fn accept<'a>(&self, transport: CircuitStream<'a>) -> Result<E2eEstablished<'a>, TunnelError>;
}

/// An established, policy-checked E2E circuit.
///
/// It owns the E2E TLS stream and the [`VerifiedE2eSession`] token created from
/// the handshake facts. The token cannot be minted from network parameters: the
/// constructor re-checks the strict pq768 policy and the exact expected peer.
///
/// The authenticated **local** identity is captured here from the hop session at
/// establishment time. It is deliberately not part of [`E2eInfo`], which carries
/// peer facts only, and it is not derived from any caller-declared value: a
/// consumer that binds this circuit to a packet endpoint must read it through
/// [`E2eCircuit::local`] instead of being trusted with its own declaration.
///
/// `mtu_cap` is the hop session's negotiated MTU ceiling, captured at the same
/// time. A packet adapter must not use a link MTU above it.
pub struct E2eCircuit<'a> {
    stream: Box<dyn E2eStream + 'a>,
    token: VerifiedE2eSession,
    info: E2eInfo,
    local: PeerIdentity,
    mtu_cap: u16,
}

/// Candidate confirmation body inside E2E TLS. Not a cryptographic handshake.
/// Field order/version is documented in docs/protocol/e2e-confirmation-candidate-v1.md.
const E2E_CONFIRM_MAGIC: [u8; 4] = *b"BE2E";
const E2E_CONFIRM_VERSION: u8 = 1;
const E2E_CONFIRM_OFFER: u8 = 1;
const E2E_CONFIRM_ACK: u8 = 2;
const E2E_CONFIRM_BODY_LEN: usize = 73;
const E2E_CONFIRM_CAPABILITIES: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct E2eConfirmation {
    net_id: [u8; 16],
    initiator_node_id: u16,
    initiator_generation: u64,
    initiator_role: NodeRole,
    acceptor_node_id: u16,
    acceptor_generation: u64,
    acceptor_role: NodeRole,
    circuit_id: [u8; CIRCUIT_ID_LEN],
    suite: MessageSuite,
    opener_node_id: u16,
    path_hops: u8,
}

impl E2eConfirmation {
    fn encode(self, message_type: u8) -> [u8; E2E_CONFIRM_BODY_LEN] {
        let mut bytes = [0u8; E2E_CONFIRM_BODY_LEN];
        let mut cursor = 0;
        bytes[cursor..cursor + 4].copy_from_slice(&E2E_CONFIRM_MAGIC);
        cursor += 4;
        bytes[cursor] = E2E_CONFIRM_VERSION;
        cursor += 1;
        bytes[cursor] = message_type;
        cursor += 1;
        bytes[cursor..cursor + 16].copy_from_slice(&self.net_id);
        cursor += 16;
        bytes[cursor..cursor + 2].copy_from_slice(&self.initiator_node_id.to_be_bytes());
        cursor += 2;
        bytes[cursor..cursor + 8].copy_from_slice(&self.initiator_generation.to_be_bytes());
        cursor += 8;
        bytes[cursor] = node_role_byte(self.initiator_role);
        cursor += 1;
        bytes[cursor..cursor + 2].copy_from_slice(&self.acceptor_node_id.to_be_bytes());
        cursor += 2;
        bytes[cursor..cursor + 8].copy_from_slice(&self.acceptor_generation.to_be_bytes());
        cursor += 8;
        bytes[cursor] = node_role_byte(self.acceptor_role);
        cursor += 1;
        bytes[cursor..cursor + CIRCUIT_ID_LEN].copy_from_slice(&self.circuit_id);
        cursor += CIRCUIT_ID_LEN;
        // Security-mode byte: 1 is the existing E2E-required enum value.
        bytes[cursor] = 1;
        cursor += 1;
        bytes[cursor] = self.suite as u8;
        cursor += 1;
        bytes[cursor..cursor + 2].copy_from_slice(&self.opener_node_id.to_be_bytes());
        cursor += 2;
        bytes[cursor] = self.path_hops;
        cursor += 1;
        bytes[cursor..cursor + 8].copy_from_slice(&E2E_CONFIRM_CAPABILITIES.to_be_bytes());
        debug_assert_eq!(cursor + 8, E2E_CONFIRM_BODY_LEN);
        bytes
    }
}

fn node_role_byte(role: NodeRole) -> u8 {
    match role {
        NodeRole::Edge => 1,
        NodeRole::Core => 2,
        NodeRole::EnrollmentService => 3,
    }
}

fn write_confirmation(
    stream: &mut dyn Duplex,
    message_type: u8,
    confirmation: E2eConfirmation,
) -> Result<(), TunnelError> {
    let record = confirmation.encode(message_type);
    let length = u16::try_from(record.len()).map_err(|_| TunnelError::FrameTooLarge)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&record)?;
    stream.flush()?;
    Ok(())
}

fn read_confirmation(stream: &mut dyn Duplex) -> Result<[u8; E2E_CONFIRM_BODY_LEN], TunnelError> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length != E2E_CONFIRM_BODY_LEN {
        return Err(CircuitReject::BadBody.into());
    }
    let mut record = [0u8; E2E_CONFIRM_BODY_LEN];
    stream.read_exact(&mut record)?;
    Ok(record)
}

fn confirm_e2e_application(
    stream: &mut dyn Duplex,
    info: E2eInfo,
    local: PeerIdentity,
    peer: PeerIdentity,
    suite: MessageSuite,
) -> Result<(), TunnelError> {
    if local.net_id != peer.net_id
        || local.net_id == [0; 16]
        || info.peer != peer
        || info.circuit_id == [0; CIRCUIT_ID_LEN]
        || local.node_id == 0
        || peer.node_id == 0
        || local.node_id == peer.node_id
        || local.identity_generation == 0
        || peer.identity_generation == 0
        || info.path_hops == 0
        || info.path_hops > MAX_RELAY_HOPS
        || suite != MessageSuite::Pq768
    {
        return Err(SessionReject::PeerIdentityMismatch.into());
    }
    let (initiator, acceptor) = if local.node_id < peer.node_id {
        (local, peer)
    } else {
        (peer, local)
    };
    let opener_node_id = match info.role {
        CircuitRole::Initiator => local.node_id,
        CircuitRole::Acceptor => peer.node_id,
    };
    let expected = E2eConfirmation {
        net_id: local.net_id,
        initiator_node_id: initiator.node_id,
        initiator_generation: initiator.identity_generation,
        initiator_role: initiator.role,
        acceptor_node_id: acceptor.node_id,
        acceptor_generation: acceptor.identity_generation,
        acceptor_role: acceptor.role,
        circuit_id: info.circuit_id,
        suite,
        opener_node_id,
        path_hops: info.path_hops,
    };
    let (outgoing, incoming) = if info.tls_role == CircuitTlsRole::Client {
        (E2E_CONFIRM_OFFER, E2E_CONFIRM_ACK)
    } else {
        (E2E_CONFIRM_ACK, E2E_CONFIRM_OFFER)
    };
    if outgoing == E2E_CONFIRM_OFFER {
        write_confirmation(stream, E2E_CONFIRM_OFFER, expected)?;
    }
    let received = read_confirmation(stream)?;
    let expected_bytes = expected.encode(incoming);
    if !constant_time_record_eq(&received, &expected_bytes) {
        return Err(SessionReject::PeerIdentityMismatch.into());
    }
    if outgoing == E2E_CONFIRM_ACK {
        write_confirmation(stream, E2E_CONFIRM_ACK, expected)?;
    }
    Ok(())
}

fn constant_time_record_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eInfo {
    pub circuit_id: [u8; CIRCUIT_ID_LEN],
    pub path_hops: u8,
    pub role: CircuitRole,
    pub tls_role: CircuitTlsRole,
    pub peer: PeerIdentity,
}

impl<'a> E2eCircuit<'a> {
    pub fn token(&self) -> &VerifiedE2eSession {
        &self.token
    }

    /// Whether E2E TLS or a lower layer already holds inbound bytes.
    pub fn has_buffered_input(&self) -> bool {
        self.stream.has_buffered_input()
    }

    pub fn info(&self) -> E2eInfo {
        self.info
    }

    /// The authenticated local identity of the hop session this circuit runs on.
    ///
    /// Captured from [`EstablishedSession::local`] when the circuit was
    /// completed, so it cannot be supplied or overridden by a later consumer.
    pub fn local(&self) -> PeerIdentity {
        self.local
    }

    /// The hop session's negotiated MTU ceiling, captured when the circuit was
    /// completed. A packet adapter must not exceed it.
    pub fn mtu_cap(&self) -> u16 {
        self.mtu_cap
    }

    pub fn circuit_id(&self) -> [u8; CIRCUIT_ID_LEN] {
        self.info.circuit_id
    }

    /// End the E2E TLS record layer with `close_notify` before the circuit is
    /// torn down.
    ///
    /// The circuit's own `CircuitClose` frame cannot be sent from here: this
    /// circuit holds the E2E byte stream, and the `CircuitStream` underneath it
    /// is no longer reachable. `close_notify` is what the peer's reader
    /// observes — it turns the next read into a clean end of stream (`Ok(0)`)
    /// instead of a truncated TLS record. The `CircuitStream` drop that follows
    /// still sends its best-effort `CircuitReset`, exactly as any other drop of
    /// this circuit does.
    ///
    /// Best-effort by design. A planned stop must not turn a peer that already
    /// went away into a local failure.
    pub fn close_gracefully(&mut self) {
        let _ = self.stream.close_stream();
    }
}

impl Read for E2eCircuit<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.read(out)
    }
}

impl Write for E2eCircuit<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Authenticated local hop facts captured when a circuit is completed.
///
/// Grouped so the completion helper stays under the argument-count lint without
/// suppressing it. This is not part of [`E2eInfo`], which carries peer facts only.
struct E2ePolicy {
    local: PeerIdentity,
    suite: MessageSuite,
    allow_pq1024: bool,
    /// Hop-local negotiated MTU ceiling, not a full end-to-end PMTU.
    mtu_cap: u16,
}

fn finish_e2e<'a>(
    established: E2eEstablished<'a>,
    info: E2eInfo,
    expected_peer: PeerIdentity,
    policy: E2ePolicy,
    diagnostics: bool,
) -> Result<E2eCircuit<'a>, TunnelError> {
    let E2ePolicy {
        local,
        suite,
        allow_pq1024,
        mtu_cap,
    } = policy;
    let (mut stream, tls) = established.into_parts();
    if tls.peer() != expected_peer {
        return Err(SessionReject::PeerIdentityMismatch.into());
    }
    // Require the registered, strict TLS profile before exchanging even this
    // encrypted application-layer binding. Confirmation never replaces TLS auth.
    crate::tls::check_inner_tls(&tls, suite, allow_pq1024)?;
    {
        let _timer = DiagnosticTimer::start("confirmation", diagnostics);
        confirm_e2e_application(&mut *stream, info, local, expected_peer, suite)?;
    }
    let token =
        VerifiedE2eSession::from_verified_e2e_tls(&tls, expected_peer, suite, allow_pq1024)?;
    Ok(E2eCircuit {
        stream,
        token,
        info,
        local,
        mtu_cap,
    })
}

fn run_e2e<'a>(
    circuit: CircuitStream<'a>,
    backend: &dyn E2eTlsBackend,
    tls_role: CircuitTlsRole,
) -> Result<E2eEstablished<'a>, TunnelError> {
    match tls_role {
        CircuitTlsRole::Client => backend.connect(circuit),
        CircuitTlsRole::Server => backend.accept(circuit),
    }
}

/// Open a circuit and run the E2E TLS handshake over it in the identity-derived
/// role.
///
/// `expected_peer` comes from the authorized directory / configuration, never
/// from the wire. A failed handshake, policy gate, or identity binding leaves
/// no circuit to reuse.
pub fn open_e2e<'a>(
    session: &'a mut EstablishedSession,
    backend: &dyn E2eTlsBackend,
    expected_peer: PeerIdentity,
    path_hops: u8,
) -> Result<E2eCircuit<'a>, TunnelError> {
    let suite = session.security_suite();
    let allow_pq1024 = session.pq1024_enabled();
    let local = session.local();
    let mtu_cap = session.mtu_cap();
    let diagnostics = diagnostic_timing_enabled();
    let tls_role = e2e_tls_role(local.node_id, expected_peer.node_id);
    let destination = NodeRef {
        node_id: expected_peer.node_id,
        identity_generation: expected_peer.identity_generation,
    };
    let (circuit, circuit_info) = {
        let _timer = DiagnosticTimer::start("circuit_open", diagnostics);
        open_circuit(session, destination, path_hops)?
    };
    let established = {
        let _timer = DiagnosticTimer::start("e2e_tls", diagnostics);
        run_e2e(circuit, backend, tls_role)?
    };
    let info = E2eInfo {
        circuit_id: circuit_info.circuit_id,
        path_hops: circuit_info.path_hops,
        role: CircuitRole::Initiator,
        tls_role,
        peer: expected_peer,
    };
    finish_e2e(
        established,
        info,
        expected_peer,
        E2ePolicy {
            local,
            suite,
            allow_pq1024,
            mtu_cap,
        },
        diagnostics,
    )
}

/// Accept a circuit and run the E2E TLS handshake over it in the
/// identity-derived role.
pub fn accept_e2e<'a>(
    session: &'a mut EstablishedSession,
    backend: &dyn E2eTlsBackend,
    expected_peer: PeerIdentity,
) -> Result<E2eCircuit<'a>, TunnelError> {
    let suite = session.security_suite();
    let allow_pq1024 = session.pq1024_enabled();
    let local = session.local();
    let mtu_cap = session.mtu_cap();
    let diagnostics = diagnostic_timing_enabled();
    let tls_role = e2e_tls_role(local.node_id, expected_peer.node_id);
    let (circuit, circuit_info) = {
        let _timer = DiagnosticTimer::start("circuit_accept", diagnostics);
        accept_circuit(session)?
    };
    let established = {
        let _timer = DiagnosticTimer::start("e2e_tls_accept", diagnostics);
        run_e2e(circuit, backend, tls_role)?
    };
    let info = E2eInfo {
        circuit_id: circuit_info.circuit_id,
        path_hops: circuit_info.path_hops,
        role: CircuitRole::Acceptor,
        tls_role,
        peer: expected_peer,
    };
    finish_e2e(
        established,
        info,
        expected_peer,
        E2ePolicy {
            local,
            suite,
            allow_pq1024,
            mtu_cap,
        },
        diagnostics,
    )
}

// --- relay forwarding --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayProgress {
    Continue,
    CircuitClosed,
}

#[derive(Clone, Copy)]
struct CircuitRoute {
    opener: NodeRef,
    destination: NodeRef,
}

/// Bounded blind relay for circuits arriving on one hop session and leaving on
/// another.
///
/// The relay never runs E2E TLS and holds no E2E secrets. It enforces circuit
/// admission and per-direction offset continuity through [`RelayTable`], binds
/// every segment to the authenticated upstream hop ([`HopSessionToken`]), and
/// decrements the per-fragment hop budget by one.
pub struct RelayHop {
    table: RelayTable,
    local: PeerIdentity,
    routes: HashMap<CircuitId, CircuitRoute>,
}

impl RelayHop {
    pub fn new(
        admission: Admission,
        max_circuits: usize,
        local: PeerIdentity,
    ) -> Result<Self, TunnelError> {
        Ok(Self {
            table: RelayTable::new(admission, max_circuits),
            local,
            routes: HashMap::new(),
        })
    }

    pub fn active_circuits(&self) -> usize {
        self.table.len()
    }

    /// Read exactly one frame from `upstream` and act on it.
    pub fn relay_once(
        &mut self,
        upstream: &mut EstablishedSession,
        downstream: &mut EstablishedSession,
        now: Instant,
    ) -> Result<RelayProgress, TunnelError> {
        let frame = upstream.recv_frame()?;
        match frame.header.kind {
            Kind::Control => {
                let subtype = frame.body.first().copied().ok_or(CircuitReject::BadBody)?;
                let control = ControlType::try_from(subtype)?;
                match control {
                    ControlType::CircuitOpen => {
                        let binding = decode_open(&frame.body)?;
                        let result = self.forward_open(upstream, downstream, binding, now);
                        if result.is_err() {
                            self.drop_circuit(binding.circuit_id);
                        }
                        result?;
                        Ok(RelayProgress::Continue)
                    }
                    ControlType::CircuitReset | ControlType::CircuitClose => {
                        let circuit_id = decode_control_id(&frame.body, control)?;
                        // Only tear down a circuit this relay actually carries;
                        // a reset/close for an unknown id is not forwarded.
                        if !self.routes.contains_key(&CircuitId(circuit_id)) {
                            return Err(CircuitReject::UnknownCircuit.into());
                        }
                        self.drop_circuit(circuit_id);
                        downstream.send_control(control, &frame.body)?;
                        Ok(if control == ControlType::CircuitClose {
                            RelayProgress::CircuitClosed
                        } else {
                            RelayProgress::Continue
                        })
                    }
                    _ => Err(CircuitReject::UnexpectedFrame.into()),
                }
            }
            Kind::RelayCircuit => {
                let fragment = RelayFragment::decode(&frame.body)?;
                if fragment.hops_remaining <= 1 {
                    return Err(CircuitReject::HopsMismatch.into());
                }
                let id = CircuitId(fragment.circuit_id);
                let route = *self.routes.get(&id).ok_or(CircuitReject::UnknownCircuit)?;
                let hop = HopSessionToken::from_established_session(upstream);
                let direction = match fragment.direction {
                    0 => Direction::SourceToDestination,
                    1 => Direction::DestinationToSource,
                    _ => return Err(CircuitReject::DirectionMismatch.into()),
                };
                let segment = Segment {
                    direction,
                    offset: fragment.byte_offset,
                    source: route.opener,
                    destination: route.destination,
                    bytes: &fragment.payload,
                    now,
                };
                if let Err(error) = self.table.accept_segment(id, &hop, segment) {
                    if let Ok(reset) = encode_reset(fragment.circuit_id) {
                        let _ = downstream.send_control(ControlType::CircuitReset, &reset);
                    }
                    self.drop_circuit(fragment.circuit_id);
                    return Err(error.into());
                }
                let forwarded = RelayFragment {
                    hops_remaining: fragment.hops_remaining - 1,
                    ..fragment
                };
                downstream.send_frame(Kind::RelayCircuit, &forwarded.encode()?)?;
                Ok(RelayProgress::Continue)
            }
            Kind::HopIpBatch => Err(CircuitReject::UnexpectedFrame.into()),
        }
    }

    fn forward_open(
        &mut self,
        upstream: &mut EstablishedSession,
        downstream: &mut EstablishedSession,
        binding: CircuitBinding,
        now: Instant,
    ) -> Result<(), TunnelError> {
        if binding.destination.node_id == self.local.node_id {
            return Err(CircuitReject::WrongDestination.into());
        }
        let peer = upstream.peer();
        let opener = NodeRef {
            node_id: peer.node_id,
            identity_generation: peer.identity_generation,
        };
        if opener.node_id == binding.destination.node_id {
            return Err(CircuitReject::WrongDestination.into());
        }
        let id = CircuitId(binding.circuit_id);
        self.table
            .open(id, opener, binding.destination, binding.path_hops, now)?;
        self.routes.insert(
            id,
            CircuitRoute {
                opener,
                destination: binding.destination,
            },
        );
        downstream.send_control(ControlType::CircuitOpen, &encode_open(&binding)?)?;
        let accept = downstream.recv_frame()?;
        if accept.header.kind != Kind::Control {
            return Err(CircuitReject::UnexpectedFrame.into());
        }
        let path_hops = decode_accept(&accept.body, binding.circuit_id)?;
        if path_hops != binding.path_hops {
            return Err(CircuitReject::HopsMismatch.into());
        }
        self.table.mark_established(id, now)?;
        upstream.send_control(ControlType::CircuitAccept, &accept.body)?;
        Ok(())
    }

    fn drop_circuit(&mut self, circuit_id: [u8; CIRCUIT_ID_LEN]) {
        self.routes.remove(&CircuitId(circuit_id));
        let _ = self.table.reset(CircuitId(circuit_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::MAX_PREOPEN_BYTES;
    use crate::resource::Limits;
    use crate::runtime::{ClientTarget, LinkClient, LinkServer};
    use crate::session::SessionPolicy;
    use crate::tls::{
        InnerTlsSession, TestOnlyPlaintextOuter, TestOnlyPlaintextTls, strict_test_negotiated,
    };
    use boreas_crypto::NodeRole;
    use boreas_proto::messages::PathRole;
    use std::net::{SocketAddr, TcpListener};
    use std::thread;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// No TLS is performed here. This is only an in-memory/test-socket seam for
    /// exercising confirmation ordering; it is not production crypto evidence.
    struct TestE2eBackend {
        peer: PeerIdentity,
    }

    // Confirmation tests use a plaintext circuit seam, with no TLS record
    // layer to notify. Production adapters must provide their own close.
    impl E2eStream for CircuitStream<'_> {
        fn close_stream(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl E2eTlsBackend for TestE2eBackend {
        fn connect<'a>(
            &self,
            transport: CircuitStream<'a>,
        ) -> Result<E2eEstablished<'a>, TunnelError> {
            Ok(E2eEstablished::new(
                Box::new(transport),
                InnerTlsSession::test_only(self.peer, strict_test_negotiated()),
            ))
        }

        fn accept<'a>(
            &self,
            transport: CircuitStream<'a>,
        ) -> Result<E2eEstablished<'a>, TunnelError> {
            self.connect(transport)
        }
    }

    fn identity(node_id: u16, generation: u64, role: NodeRole) -> PeerIdentity {
        PeerIdentity::legacy_default([7; 16], node_id, generation, role)
    }

    fn policy(local: PeerIdentity, peer: PeerIdentity) -> SessionPolicy {
        SessionPolicy {
            local,
            expected_peer: peer,
            path_role: PathRole::Cdn,
            security_mode: SecurityMode::E2eRequired,
            suite: MessageSuite::Pq768,
            mtu_cap: 1500,
            identity_registered: true,
            allow_pq1024: false,
            allow_hop_only: false,
            allowed_peer_roles: vec![peer.role],
        }
    }

    fn admission() -> Admission {
        Admission::new(Limits {
            handshakes_global: 16,
            authenticated_global: 16,
            authenticated_per_peer: 8,
            bytes_global: MAX_PREOPEN_BYTES * 8,
        })
    }

    fn target(address: SocketAddr) -> ClientTarget {
        ClientTarget {
            address,
            ws_host: "hub.boreas.test:443".to_owned(),
            tls_server_name: "hub.boreas.test".to_owned(),
            path: "/tunnel".to_owned(),
        }
    }

    fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local addr");
        (listener, address)
    }

    #[test]
    fn circuit_bodies_roundtrip_and_role_is_identity_derived() {
        let binding = CircuitBinding {
            circuit_id: [9; 16],
            destination: NodeRef {
                node_id: 0x0301,
                identity_generation: 4,
            },
            path_hops: 2,
        };
        let encoded = encode_open(&binding).expect("encode");
        assert_eq!(encoded.len(), CIRCUIT_OPEN_BODY_LEN);
        assert_eq!(decode_open(&encoded), Ok(binding));

        let accept = encode_accept(binding.circuit_id, binding.path_hops).expect("encode");
        assert_eq!(accept.len(), CIRCUIT_ACCEPT_BODY_LEN);
        assert_eq!(decode_accept(&accept, binding.circuit_id), Ok(2));
        assert_eq!(
            decode_accept(&accept, [8; 16]),
            Err(TunnelError::Circuit(CircuitReject::UnknownCircuit))
        );

        let reset = encode_reset(binding.circuit_id).expect("encode");
        assert_eq!(
            decode_control_id(&reset, ControlType::CircuitReset),
            Ok(binding.circuit_id)
        );
        // A reset body must not parse as a close body (subtype is checked by
        // the proto decoder before any field is trusted).
        assert!(matches!(
            decode_control_id(&reset, ControlType::CircuitClose),
            Err(TunnelError::Message(_))
        ));

        // Lower node id is the TLS client regardless of circuit direction.
        assert_eq!(e2e_tls_role(0x0101, 0x0201), CircuitTlsRole::Client);
        assert_eq!(e2e_tls_role(0x0201, 0x0101), CircuitTlsRole::Server);
    }

    #[test]
    fn confirmation_record_is_fixed_length_and_binds_all_candidate_fields() {
        let local = identity(0x0101, 4, NodeRole::Edge);
        let peer = identity(0x0201, 9, NodeRole::Core);
        let info = E2eInfo {
            circuit_id: [0x5a; CIRCUIT_ID_LEN],
            path_hops: 3,
            role: CircuitRole::Initiator,
            tls_role: CircuitTlsRole::Client,
            peer,
        };
        let (initiator, acceptor) = (local, peer);
        let confirmation = E2eConfirmation {
            net_id: local.net_id,
            initiator_node_id: initiator.node_id,
            initiator_generation: initiator.identity_generation,
            initiator_role: initiator.role,
            acceptor_node_id: acceptor.node_id,
            acceptor_generation: acceptor.identity_generation,
            acceptor_role: acceptor.role,
            circuit_id: info.circuit_id,
            suite: MessageSuite::Pq768,
            opener_node_id: local.node_id,
            path_hops: info.path_hops,
        };
        let encoded = confirmation.encode(E2E_CONFIRM_OFFER);
        assert_eq!(encoded.len(), E2E_CONFIRM_BODY_LEN);
        assert_eq!(&encoded[..4], b"BE2E");
        assert_eq!(encoded[4], E2E_CONFIRM_VERSION);
        assert_eq!(encoded[5], E2E_CONFIRM_OFFER);
        assert_eq!(&encoded[6..22], &[7; 16]);
        assert_eq!(&encoded[22..24], &0x0101u16.to_be_bytes());
        assert_eq!(&encoded[24..32], &4u64.to_be_bytes());
        assert_eq!(encoded[32], 1);
        assert_eq!(&encoded[33..35], &0x0201u16.to_be_bytes());
        assert_eq!(&encoded[35..43], &9u64.to_be_bytes());
        assert_eq!(encoded[43], 2);
        assert_eq!(&encoded[44..60], &[0x5a; 16]);
        assert_eq!(encoded[60], 1);
        assert_eq!(encoded[61], MessageSuite::Pq768 as u8);
        assert_eq!(&encoded[62..64], &0x0101u16.to_be_bytes());
        assert_eq!(encoded[64], 3);
        assert_eq!(&encoded[65..73], &[0; 8]);
        let mut altered = encoded;
        altered[61] = MessageSuite::Pq1024 as u8;
        assert!(!constant_time_record_eq(&encoded, &altered));
        altered[61] = MessageSuite::Pq768 as u8;
        altered[65] = 1; // Unknown/nonzero capabilities are not accepted.
        assert!(!constant_time_record_eq(&encoded, &altered));
        altered[65] = 0;
        altered[4] = 2; // unknown confirmation version
        assert!(!constant_time_record_eq(&encoded, &altered));
    }

    #[test]
    fn confirmation_rejects_tampered_fields_from_peer() {
        let local = identity(0x0101, 4, NodeRole::Edge);
        let peer = identity(0x0201, 9, NodeRole::Core);
        let info = E2eInfo {
            circuit_id: [0x5a; CIRCUIT_ID_LEN],
            path_hops: 3,
            role: CircuitRole::Initiator,
            tls_role: CircuitTlsRole::Client,
            peer,
        };
        let base = E2eConfirmation {
            net_id: local.net_id,
            initiator_node_id: local.node_id,
            initiator_generation: local.identity_generation,
            initiator_role: local.role,
            acceptor_node_id: peer.node_id,
            acceptor_generation: peer.identity_generation,
            acceptor_role: peer.role,
            circuit_id: info.circuit_id,
            suite: MessageSuite::Pq768,
            opener_node_id: local.node_id,
            path_hops: info.path_hops,
        };
        // Header, version, type, network, both endpoint IDs/generations/roles,
        // circuit, mode, suite, opener, path length, and capabilities are all
        // compared against the certificate/configuration-derived expected tuple.
        for offset in [
            0usize, 4, 5, 6, 22, 24, 32, 33, 35, 43, 44, 60, 61, 62, 64, 65,
        ] {
            let (listener, address) = listener();
            let responder = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let _offer = read_confirmation(&mut stream).expect("offer");
                let mut ack = base.encode(E2E_CONFIRM_ACK);
                ack[offset] ^= 1;
                stream
                    .write_all(&(E2E_CONFIRM_BODY_LEN as u16).to_be_bytes())
                    .expect("length");
                stream.write_all(&ack).expect("tampered ack");
            });
            let mut stream = std::net::TcpStream::connect(address).expect("connect");
            stream
                .set_read_timeout(Some(TIMEOUT))
                .expect("read timeout");
            stream
                .set_write_timeout(Some(TIMEOUT))
                .expect("write timeout");
            assert!(
                confirm_e2e_application(&mut stream, info, local, peer, MessageSuite::Pq768)
                    .is_err(),
                "mutation at byte offset {offset} must reject"
            );
            responder.join().expect("responder");
        }

        let mut other_network = peer;
        other_network.net_id = [8; 16];
        let mut stream = std::io::Cursor::new(Vec::<u8>::new());
        assert!(
            confirm_e2e_application(&mut stream, info, local, other_network, MessageSuite::Pq768)
                .is_err()
        );
    }

    #[test]
    fn confirmation_read_rejects_short_length_and_truncation() {
        let mut short = std::io::Cursor::new(72u16.to_be_bytes().to_vec());
        assert_eq!(
            read_confirmation(&mut short),
            Err(TunnelError::Circuit(CircuitReject::BadBody))
        );
        let mut oversized = std::io::Cursor::new(74u16.to_be_bytes().to_vec());
        assert_eq!(
            read_confirmation(&mut oversized),
            Err(TunnelError::Circuit(CircuitReject::BadBody))
        );
        let mut truncated = std::io::Cursor::new(73u16.to_be_bytes().to_vec());
        assert_eq!(read_confirmation(&mut truncated), Err(TunnelError::Closed));
    }

    #[test]
    fn confirmation_read_timeout_fails_closed() {
        let (listener, address) = listener();
        let responder = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept");
            // Keep the peer socket open but silent: the local I/O timeout, not
            // an invented confirmation-level deadline, must terminate the read.
            thread::sleep(Duration::from_millis(100));
        });
        let mut stream = std::net::TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(TIMEOUT))
            .expect("write timeout");
        let local = identity(0x0101, 1, NodeRole::Edge);
        let peer = identity(0x0201, 1, NodeRole::Core);
        let info = E2eInfo {
            circuit_id: [0x33; CIRCUIT_ID_LEN],
            path_hops: 1,
            role: CircuitRole::Initiator,
            tls_role: CircuitTlsRole::Client,
            peer,
        };
        assert_eq!(
            confirm_e2e_application(&mut stream, info, local, peer, MessageSuite::Pq768),
            Err(TunnelError::Timeout)
        );
        responder.join().expect("responder");
    }

    #[test]
    fn circuit_stream_carries_bytes_between_two_nodes() {
        let (listener, address) = listener();
        let a = identity(0x0101, 1, NodeRole::Edge);
        let b = identity(0x0201, 1, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let mut session = server
                    .accept(&listener, policy, TIMEOUT, &admission)
                    .expect("session")
                    .session;
                let (mut circuit, info) = accept_circuit(&mut session).expect("circuit");
                assert_eq!(info.path_hops, 1);
                let mut buffer = vec![0u8; 200_000];
                let mut total = 0usize;
                while total < buffer.len() {
                    let read = circuit.read_bytes(&mut buffer[total..]).expect("read");
                    if read == 0 {
                        break;
                    }
                    total += read;
                }
                buffer.truncate(total);
                buffer
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let mut session = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("client session");
        let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
        {
            let (mut circuit, info) = open_circuit(
                &mut session,
                NodeRef {
                    node_id: b.node_id,
                    identity_generation: b.identity_generation,
                },
                1,
            )
            .expect("open");
            assert_eq!(info.path_hops, 1);
            let mut written = 0usize;
            while written < payload.len() {
                written += circuit.write_bytes(&payload[written..]).expect("write");
            }
            circuit.finish().expect("close");
        }
        let received = server.join().expect("server thread");
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }

    #[test]
    fn e2e_confirmation_gates_business_stream_when_higher_node_opens() {
        let (listener, address) = listener();
        let lower = identity(0x0101, 4, NodeRole::Edge);
        let higher = identity(0x0201, 9, NodeRole::Core);
        let server = {
            let hop_policy = policy(lower, higher);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: higher }));
                let mut hop = server
                    .accept(&listener, hop_policy, TIMEOUT, &admission)
                    .expect("authorized hop")
                    .session;
                let backend = TestE2eBackend { peer: higher };
                let mut e2e = accept_e2e(&mut hop, &backend, higher).expect("confirmed E2E");
                let mut received = [0u8; 5];
                e2e.read_exact(&mut received).expect("read business bytes");
                assert_eq!(&received, b"hello");
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: lower }),
        );
        let mut hop = client
            .connect(&target(address), policy(higher, lower), TIMEOUT)
            .expect("authorized hop");
        let backend = TestE2eBackend { peer: lower };
        // The higher NodeID opens; the lower NodeID is nevertheless the E2E TLS
        // client. Opener identity is not confused with TLS client/server role.
        let mut e2e = open_e2e(&mut hop, &backend, lower, 1).expect("confirmed E2E");
        assert_eq!(e2e.info().tls_role, CircuitTlsRole::Server);
        assert_eq!(e2e.info().role, CircuitRole::Initiator);
        e2e.write_all(b"hello").expect("write business bytes");
        drop(e2e);
        server.join().expect("server thread");
    }

    #[test]
    fn duplicate_offset_resets_the_circuit() {
        let (listener, address) = listener();
        let a = identity(0x0101, 1, NodeRole::Edge);
        let b = identity(0x0201, 1, NodeRole::Core);
        let server = {
            let policy = policy(b, a);
            let admission = admission();
            thread::spawn(move || {
                let server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let mut session = server
                    .accept(&listener, policy, TIMEOUT, &admission)
                    .expect("session")
                    .session;
                let (mut circuit, _) = accept_circuit(&mut session).expect("circuit");
                let mut buffer = [0u8; 3];
                let read = circuit.read_bytes(&mut buffer).expect("first fragment");
                assert_eq!(read, 3);
                assert_eq!(
                    circuit.read_bytes(&mut buffer),
                    Err(TunnelError::Circuit(CircuitReject::OffsetMismatch))
                );
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let mut session = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("client session");
        let (circuit, info) = open_circuit(
            &mut session,
            NodeRef {
                node_id: b.node_id,
                identity_generation: b.identity_generation,
            },
            1,
        )
        .expect("open");
        let fragment = RelayFragment {
            circuit_id: info.circuit_id,
            direction: 0,
            byte_offset: 0,
            hops_remaining: 1,
            payload: b"abc".to_vec(),
        };
        // Keep CircuitStream alive while injecting the malformed duplicate;
        // its Drop must not reset the circuit before these frames are sent.
        circuit
            .session
            .send_frame(Kind::RelayCircuit, &fragment.encode().expect("encode"))
            .expect("first send");
        circuit
            .session
            .send_frame(Kind::RelayCircuit, &fragment.encode().expect("encode"))
            .expect("duplicate send");
        drop(circuit);
        server.join().expect("server thread");
    }

    #[test]
    fn relay_forwards_across_three_nodes() {
        let (listener, address) = listener();
        let a = identity(0x0101, 1, NodeRole::Edge);
        let b = identity(0x0201, 1, NodeRole::Core);
        let c = identity(0x0301, 2, NodeRole::Core);
        let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 241) as u8).collect();
        let payload_len = payload.len();

        // A connects before C starts, so the relay's accept order is fixed.
        let relay_thread = {
            let policy_upstream = policy(b, a);
            let policy_downstream = policy(b, c);
            let relay_admission = admission();
            thread::spawn(move || {
                let upstream_server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: a }));
                let mut upstream = upstream_server
                    .accept(&listener, policy_upstream, TIMEOUT, &relay_admission)
                    .expect("upstream session")
                    .session;
                let downstream_server = LinkServer::new(Box::new(TestOnlyPlaintextTls { peer: c }));
                let mut downstream = downstream_server
                    .accept(&listener, policy_downstream, TIMEOUT, &relay_admission)
                    .expect("downstream session")
                    .session;
                let mut hop = RelayHop::new(admission(), 8, b).expect("relay");
                for _ in 0..32 {
                    match hop.relay_once(&mut upstream, &mut downstream, Instant::now()) {
                        Ok(RelayProgress::Continue) => {}
                        Ok(RelayProgress::CircuitClosed) => break,
                        Err(_) => break,
                    }
                }
            })
        };

        let client = LinkClient::new(
            Box::new(TestOnlyPlaintextOuter),
            Box::new(TestOnlyPlaintextTls { peer: b }),
        );
        let mut session = client
            .connect(&target(address), policy(a, b), TIMEOUT)
            .expect("client session");

        let endpoint_thread = {
            let policy = policy(c, b);
            thread::spawn(move || {
                let client = LinkClient::new(
                    Box::new(TestOnlyPlaintextOuter),
                    Box::new(TestOnlyPlaintextTls { peer: b }),
                );
                let mut session = client
                    .connect(&target(address), policy, TIMEOUT)
                    .expect("session");
                let (mut circuit, info) = accept_circuit(&mut session).expect("circuit");
                assert_eq!(info.path_hops, 2);
                let mut buffer = vec![0u8; payload_len];
                let mut total = 0usize;
                while total < buffer.len() {
                    let read = circuit.read_bytes(&mut buffer[total..]).expect("read");
                    if read == 0 {
                        break;
                    }
                    total += read;
                }
                buffer.truncate(total);
                buffer
            })
        };

        {
            let (mut circuit, info) = open_circuit(
                &mut session,
                NodeRef {
                    node_id: c.node_id,
                    identity_generation: c.identity_generation,
                },
                2,
            )
            .expect("open");
            assert_eq!(info.path_hops, 2);
            let mut written = 0usize;
            while written < payload.len() {
                written += circuit.write_bytes(&payload[written..]).expect("write");
            }
            circuit.finish().expect("close");
        }
        let received = endpoint_thread.join().expect("endpoint thread");
        relay_thread.join().expect("relay thread");
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }
}
