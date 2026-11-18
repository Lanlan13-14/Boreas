//! RelayCircuit lifecycle and bounded pre-establishment queues only. This is
//! NOT TLS, key agreement, authentication, or an E2E-active token. Callers must
//! hold a genuine verified TLS session token before passing application traffic.
//!
//! Two distinct capabilities gate this module:
//!
//! * [`HopSessionToken`] proves a segment arrived on an already-authorized hop
//!   session. A blind relay uses it: it never holds E2E secrets.
//! * [`VerifiedE2eSession`] records a completed, policy-checked **E2E** TLS
//!   handshake peer. Only an endpoint may create it, through
//!   [`VerifiedE2eSession::from_verified_e2e_tls`], and it gates plaintext
//!   injection for pre-open queues. It stores only the peer [`NodeRef`], not
//!   `net_id`, circuit id or freshness; consumers must add those checks.
use crate::error::{SessionReject, TunnelError};
use crate::resource::{Admission, AdmissionError, ByteCredit};
use crate::tls::{InnerTlsSession, PeerIdentity, check_inner_tls};
use boreas_proto::messages::Suite as MessageSuite;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_RELAY_HOPS: u8 = 8;
pub const DEFAULT_MAX_CIRCUITS_PER_PAIR: usize = 1;
pub const HARD_MAX_CIRCUITS_PER_PAIR: usize = 4;
pub const MAX_PREOPEN_BYTES: usize = 64 * 1024;
pub const MAX_PREOPEN_ITEMS: usize = 128;
pub const PREOPEN_TTL: Duration = Duration::from_secs(2);
pub const CIRCUIT_LIFETIME: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CircuitId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeRef {
    pub node_id: u16,
    pub identity_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Pair {
    first: u16,
    second: u16,
}
fn pair_key(src: NodeRef, dst: NodeRef) -> Pair {
    if src.node_id <= dst.node_id {
        Pair {
            first: src.node_id,
            second: dst.node_id,
        }
    } else {
        Pair {
            first: dst.node_id,
            second: src.node_id,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    InvalidId,
    InvalidEndpoints,
    TooManyHops,
    DuplicateCircuit,
    PairLimit,
    GlobalLimit,
    PreopenLimit,
    PreopenExpired,
    EmptySegment,
    InvalidDirection,
    OffsetMismatch,
    WrongDestination,
    WrongSourceGeneration,
    WrongDestinationGeneration,
    /// The segment did not arrive from the hop peer that opened the circuit.
    WrongHop,
    /// The E2E session token does not belong to either endpoint of this circuit.
    WrongSession,
    NotEstablished,
    Expired,
    Admission(AdmissionError),
}
impl From<AdmissionError> for RelayError {
    fn from(e: AdmissionError) -> Self {
        Self::Admission(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    SourceToDestination,
    DestinationToSource,
}

/// One already-authenticated segment descriptor. Payload is borrowed and is not
/// parsed or decrypted by the relay lifecycle state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment<'a> {
    pub direction: Direction,
    pub offset: u64,
    pub source: NodeRef,
    pub destination: NodeRef,
    pub bytes: &'a [u8],
    pub now: Instant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    Opening,
    Established,
    Reset,
}
struct Queued {
    bytes: Vec<u8>,
    credit: ByteCredit,
    expires: Instant,
}

/// Opaque capability minted only from a completed, policy-checked E2E TLS
/// handshake. It is not constructible from network parameters or booleans; the
/// only production constructor is
/// [`VerifiedE2eSession::from_verified_e2e_tls`].
///
/// # Binding boundary
///
/// The token stores only the authenticated E2E peer [`NodeRef`] (NodeID and
/// identity generation). It does **not** carry `net_id`, a `circuit_id`,
/// session freshness, or a per-circuit nonce, and it is not a full circuit
/// binding. A token must not be used across networks or across circuits, even
/// when both circuits have the same peer. A real consumer must additionally
/// require the expected `net_id`, the exact circuit id, and fresh
/// E2E/lease/status state. [`RelayTable::consume_preopen`] performs only the
/// endpoint-peer check described on that method; it does not replace those
/// consumer checks.
pub struct VerifiedE2eSession {
    /// Authenticated E2E peer. This is not a net/circuit binding; see the
    /// type-level boundary.
    peer: NodeRef,
    _private: (),
}
impl VerifiedE2eSession {
    /// The only production constructor.
    ///
    /// It accepts facts reported by a **completed E2E inner-TLS handshake** and
    /// re-runs the strict policy gate plus an exact peer-identity comparison.
    /// Network-supplied identifiers, booleans and configuration flags never
    /// reach this constructor, so a relay cannot mint an E2E token and an
    /// endpoint cannot mint one before the E2E TLS session exists. It records
    /// only the peer [`NodeRef`]; `net_id`, circuit id and freshness remain
    /// consumer-side checks (see the type-level binding boundary).
    pub fn from_verified_e2e_tls(
        session: &InnerTlsSession,
        expected_peer: PeerIdentity,
        suite: MessageSuite,
        allow_pq1024: bool,
    ) -> Result<Self, TunnelError> {
        check_inner_tls(session, suite, allow_pq1024)?;
        let peer = session.peer();
        if peer != expected_peer {
            return Err(SessionReject::PeerIdentityMismatch.into());
        }
        Ok(Self {
            peer: NodeRef {
                node_id: peer.node_id,
                identity_generation: peer.identity_generation,
            },
            _private: (),
        })
    }
}
#[cfg(test)]
impl VerifiedE2eSession {
    fn test_only(peer: NodeRef) -> Self {
        Self { peer, _private: () }
    }
}

/// Proof that a segment was read from an already-authorized hop session.
///
/// This is what a blind relay can hold: the relay authenticated its upstream
/// peer's hop TLS session, but it does not have (and must not have) the E2E TLS
/// session that protects the payload. It is deliberately weaker than
/// [`VerifiedE2eSession`].
pub struct HopSessionToken {
    peer: NodeRef,
    _private: (),
}
impl HopSessionToken {
    /// Created by the runtime from an authorized hop session. The peer values
    /// come from the verified certificate identity, not from the wire.
    pub(crate) fn from_established_session(session: &crate::session::EstablishedSession) -> Self {
        let peer = session.peer();
        Self {
            peer: NodeRef {
                node_id: peer.node_id,
                identity_generation: peer.identity_generation,
            },
            _private: (),
        }
    }
    #[cfg(test)]
    fn test_only(peer: NodeRef) -> Self {
        Self { peer, _private: () }
    }
    pub fn peer(&self) -> NodeRef {
        self.peer
    }
}

/// Owns payload bytes and their global admission credit together. The credit is
/// released only when the consumed payload itself is dropped.
pub struct PreopenPayload {
    bytes: Vec<u8>,
    _credit: ByteCredit,
}
impl PreopenPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
struct Circuit {
    src: NodeRef,
    dst: NodeRef,
    hops_left: u8,
    state: CircuitState,
    created: Instant,
    expires: Instant,
    queued: VecDeque<Queued>,
    queued_bytes: usize,
    next_offset: [u64; 2],
}
#[derive(Default)]
struct PairUsage {
    circuits: usize,
    queued_bytes: usize,
    queued_items: usize,
}

/// Pure bounded state. Caller supplies CSPRNG-created circuit IDs; this crate
/// does not generate IDs or authenticate them.
pub struct RelayTable {
    admission: Admission,
    max_circuits: usize,
    max_per_pair: usize,
    circuits: HashMap<CircuitId, Circuit>,
    pairs: HashMap<Pair, PairUsage>,
}
impl RelayTable {
    pub fn new(admission: Admission, max_circuits_global: usize) -> Self {
        Self::with_pair_limit(
            admission,
            max_circuits_global,
            DEFAULT_MAX_CIRCUITS_PER_PAIR,
        )
        .expect("default pair limit valid")
    }
    pub fn with_pair_limit(
        admission: Admission,
        max_circuits_global: usize,
        max_per_pair: usize,
    ) -> Result<Self, RelayError> {
        if max_per_pair == 0 || max_per_pair > HARD_MAX_CIRCUITS_PER_PAIR {
            return Err(RelayError::PairLimit);
        }
        Ok(Self {
            admission,
            max_circuits: max_circuits_global,
            max_per_pair,
            circuits: HashMap::new(),
            pairs: HashMap::new(),
        })
    }
    pub fn len(&self) -> usize {
        self.circuits.len()
    }
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    pub fn open(
        &mut self,
        id: CircuitId,
        src: NodeRef,
        dst: NodeRef,
        hops: u8,
        now: Instant,
    ) -> Result<(), RelayError> {
        if id.0.iter().all(|b| *b == 0) {
            return Err(RelayError::InvalidId);
        }
        if src.node_id == dst.node_id
            || src.identity_generation == 0
            || dst.identity_generation == 0
        {
            return Err(RelayError::InvalidEndpoints);
        }
        if hops == 0 || hops > MAX_RELAY_HOPS {
            return Err(RelayError::TooManyHops);
        }
        if self.circuits.contains_key(&id) {
            return Err(RelayError::DuplicateCircuit);
        }
        if self.circuits.len() >= self.max_circuits {
            return Err(RelayError::GlobalLimit);
        }
        let pair = pair_key(src, dst);
        if self.pairs.get(&pair).map_or(0, |u| u.circuits) >= self.max_per_pair {
            return Err(RelayError::PairLimit);
        }
        self.pairs.entry(pair).or_default().circuits += 1;
        self.circuits.insert(
            id,
            Circuit {
                src,
                dst,
                hops_left: hops,
                state: CircuitState::Opening,
                created: now,
                expires: now + CIRCUIT_LIFETIME,
                queued: VecDeque::new(),
                queued_bytes: 0,
                next_offset: [0, 0],
            },
        );
        Ok(())
    }

    /// Keep opening traffic globally and pair-charged until its payload is
    /// consumed/dropped or reset. Empty payloads are rejected to bound metadata.
    pub fn queue_preopen(
        &mut self,
        id: CircuitId,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<(), RelayError> {
        let (src, dst, created, queued_bytes, state) = {
            let c = self.circuits.get(&id).ok_or(RelayError::NotEstablished)?;
            (c.src, c.dst, c.created, c.queued_bytes, c.state)
        };
        if state != CircuitState::Opening {
            return Err(RelayError::NotEstablished);
        }
        if now >= created + PREOPEN_TTL {
            self.circuits.get_mut(&id).expect("circuit checked").state = CircuitState::Reset;
            return Err(RelayError::PreopenExpired);
        }
        if bytes.is_empty() {
            return Err(RelayError::PreopenLimit);
        }
        let pair = pair_key(src, dst);
        let pair_usage = self.pairs.get(&pair).ok_or(RelayError::NotEstablished)?;
        if queued_bytes
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_PREOPEN_BYTES)
            || pair_usage
                .queued_bytes
                .checked_add(bytes.len())
                .is_none_or(|n| n > MAX_PREOPEN_BYTES)
            || pair_usage.queued_items >= MAX_PREOPEN_ITEMS
        {
            return Err(RelayError::PreopenLimit);
        }
        let expires = created + PREOPEN_TTL;
        let credit = self.admission.reserve_bytes(bytes.len())?;
        let c = self.circuits.get_mut(&id).expect("circuit checked");
        c.queued_bytes += bytes.len();
        c.queued.push_back(Queued {
            bytes,
            credit,
            expires,
        });
        let usage = self.pairs.get_mut(&pair).expect("pair exists");
        usage.queued_bytes += c.queued.back().expect("queued").bytes.len();
        usage.queued_items += 1;
        Ok(())
    }

    /// Lifecycle transition only, not evidence TLS was negotiated. Establishment
    /// must occur before the two-second pre-open deadline.
    pub fn mark_established(&mut self, id: CircuitId, now: Instant) -> Result<usize, RelayError> {
        let c = self
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::NotEstablished)?;
        if now >= c.expires {
            c.state = CircuitState::Reset;
            return Err(RelayError::Expired);
        }
        if c.state != CircuitState::Opening {
            return Err(RelayError::NotEstablished);
        }
        if now >= c.created + PREOPEN_TTL || c.queued.iter().any(|q| now >= q.expires) {
            c.state = CircuitState::Reset;
            return Err(RelayError::PreopenExpired);
        }
        c.state = CircuitState::Established;
        Ok(c.queued.len())
    }
    pub fn preopen_queue_len(&self, id: CircuitId) -> Result<usize, RelayError> {
        Ok(self
            .circuits
            .get(&id)
            .ok_or(RelayError::NotEstablished)?
            .queued
            .len())
    }

    /// Payload and credit leave the queue together. Credit remains held in each
    /// returned `PreopenPayload` for as long as those bytes remain live.
    ///
    /// The token must name one of the circuit's authenticated endpoint
    /// [`NodeRef`]s; a token for another peer is refused with
    /// [`RelayError::WrongSession`]. This check is deliberately narrow: the
    /// token has no `net_id` or circuit id, so it does **not** prove that the
    /// token came from the same network, that it belongs to this exact circuit
    /// rather than another circuit to the same peer, or that it is fresh. A
    /// real consumer must enforce those conditions separately before treating
    /// the returned plaintext as authorized.
    pub fn consume_preopen(
        &mut self,
        id: CircuitId,
        session: &VerifiedE2eSession,
        now: Instant,
    ) -> Result<Vec<PreopenPayload>, RelayError> {
        let c = self
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::NotEstablished)?;
        if session.peer != c.src && session.peer != c.dst {
            return Err(RelayError::WrongSession);
        }
        if c.state != CircuitState::Established {
            return Err(RelayError::NotEstablished);
        }
        if now >= c.expires {
            c.state = CircuitState::Reset;
            return Err(RelayError::Expired);
        }
        if c.queued.iter().any(|q| now >= q.expires) {
            c.state = CircuitState::Reset;
            return Err(RelayError::PreopenExpired);
        }
        let pair = pair_key(c.src, c.dst);
        let count = c.queued.len();
        let bytes = c.queued_bytes;
        let result = c
            .queued
            .drain(..)
            .map(|q| PreopenPayload {
                bytes: q.bytes,
                _credit: q.credit,
            })
            .collect();
        c.queued_bytes = 0;
        if let Some(usage) = self.pairs.get_mut(&pair) {
            usage.queued_items = usage.queued_items.saturating_sub(count);
            usage.queued_bytes = usage.queued_bytes.saturating_sub(bytes);
        }
        Ok(result)
    }

    /// Any binding, generation, direction, expiry, or offset error locks the
    /// circuit in Reset so a later frame cannot continue the corrupted stream.
    ///
    /// The `hop` token binds the segment to the authenticated upstream peer:
    /// a relay accepts only frames that arrived on the session which opened
    /// the circuit. It carries no E2E state, because a blind relay must not
    /// hold any.
    pub fn accept_segment(
        &mut self,
        id: CircuitId,
        hop: &HopSessionToken,
        segment: Segment<'_>,
    ) -> Result<u64, RelayError> {
        let Segment {
            direction,
            offset,
            source: claimed_source,
            destination: claimed_destination,
            bytes,
            now,
        } = segment;
        let c = self
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::NotEstablished)?;
        if now >= c.expires {
            c.state = CircuitState::Reset;
            return Err(RelayError::Expired);
        }
        if c.state != CircuitState::Established {
            return Err(RelayError::NotEstablished);
        }
        let (src, dst, index) = match direction {
            Direction::SourceToDestination => (c.src, c.dst, 0),
            Direction::DestinationToSource => (c.dst, c.src, 1),
        };
        let error = if hop.peer != src {
            Some(RelayError::WrongHop)
        } else if claimed_source.node_id != src.node_id {
            Some(RelayError::InvalidDirection)
        } else if claimed_source.identity_generation != src.identity_generation {
            Some(RelayError::WrongSourceGeneration)
        } else if claimed_destination.node_id != dst.node_id {
            Some(RelayError::WrongDestination)
        } else if claimed_destination.identity_generation != dst.identity_generation {
            Some(RelayError::WrongDestinationGeneration)
        } else if offset != c.next_offset[index] {
            Some(RelayError::OffsetMismatch)
        } else {
            None
        };
        if let Some(error) = error {
            c.state = CircuitState::Reset;
            return Err(error);
        }
        if bytes.is_empty() {
            c.state = CircuitState::Reset;
            return Err(RelayError::EmptySegment);
        }
        let len = match u64::try_from(bytes.len()) {
            Ok(n) => n,
            Err(_) => {
                c.state = CircuitState::Reset;
                return Err(RelayError::OffsetMismatch);
            }
        };
        let next = match c.next_offset[index].checked_add(len) {
            Some(n) => n,
            None => {
                c.state = CircuitState::Reset;
                return Err(RelayError::OffsetMismatch);
            }
        };
        c.next_offset[index] = next;
        Ok(next)
    }
    pub fn decrement_hop(&mut self, id: CircuitId) -> Result<u8, RelayError> {
        let c = self
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::NotEstablished)?;
        if c.hops_left <= 1 {
            c.state = CircuitState::Reset;
            return Err(RelayError::TooManyHops);
        }
        c.hops_left -= 1;
        Ok(c.hops_left)
    }

    /// Reset releases queue and pair credits. Returned payloads are for disposal,
    /// and retain their byte credits until dropped by the caller.
    pub fn reset(&mut self, id: CircuitId) -> Result<Vec<PreopenPayload>, RelayError> {
        let mut c = self
            .circuits
            .remove(&id)
            .ok_or(RelayError::NotEstablished)?;
        c.state = CircuitState::Reset;
        let pair = pair_key(c.src, c.dst);
        let count = c.queued.len();
        let bytes = c.queued_bytes;
        if let Some(u) = self.pairs.get_mut(&pair) {
            u.circuits = u.circuits.saturating_sub(1);
            u.queued_items = u.queued_items.saturating_sub(count);
            u.queued_bytes = u.queued_bytes.saturating_sub(bytes);
            if u.circuits == 0 {
                self.pairs.remove(&pair);
            }
        }
        Ok(c.queued
            .drain(..)
            .map(|q| PreopenPayload {
                bytes: q.bytes,
                _credit: q.credit,
            })
            .collect())
    }
    pub fn reap_expired(&mut self, now: Instant) -> Vec<CircuitId> {
        let ids: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(id, c)| {
                (c.state == CircuitState::Reset
                    || now >= c.expires
                    || (c.state == CircuitState::Opening && now >= c.created + PREOPEN_TTL))
                    .then_some(*id)
            })
            .collect();
        for id in &ids {
            let _ = self.reset(*id);
        }
        ids
    }
}

// --- bounded Core topology: dial ownership, dedup, fixed hop chains ----------
//
// §3.1 bounds the mesh to 16 Cores with all-pairs links, a default of `M = 5`
// flows per Core pair (four carrying plus one probe on the other path), a
// smallest-id primary dialer with a bounded reverse-dial fallback, and a
// deduplication rule that may only drain a redundant dial once BOTH connections
// completed inner TLS and `SessionAccept` and a healthy probe. §7 binds every
// circuit to one fixed forwarding chain and a relay hop budget of at most 8.
//
// This is a pure model: it opens no socket, performs no handshake and never
// authenticates anything. Every `authorized`/`probe_ok` bit is a caller report
// from the real session layer, and `dial_role` is a policy answer, not an
// authorization to skip any check. Pairs are not routeable until the caller
// explicitly reports them up; there is no implicit all-connected default.

/// Cores in the mesh, including this one (§3.1: `core_id = 1..=16`).
pub const MAX_MESH_CORES: usize = 16;

/// Carrying flows per Core pair (§3.1 default `M = 5`, i.e. four plus a probe).
pub const ACTIVE_FLOWS_PER_CORE_PAIR: u8 = 4;

/// One extra probe flow on the other path (`DIR`/`CDN`), §3.1.
pub const PROBE_FLOWS_PER_CORE_PAIR: u8 = 1;

/// Total flows a Core pair maintains by default (§3.1 `M`).
pub const FLOWS_PER_CORE_PAIR: u8 = ACTIVE_FLOWS_PER_CORE_PAIR + PROBE_FLOWS_PER_CORE_PAIR;

const _: () = assert!(FLOWS_PER_CORE_PAIR == 5);
const _: () = assert!(MAX_MESH_PATH_HOPS == MAX_RELAY_HOPS);

/// §3.1: the larger Core may reverse-dial only after the smaller one has failed
/// to connect for this long. A plan default, not a measured bound.
pub const REVERSE_DIAL_AFTER: Duration = Duration::from_secs(6);

/// Longest Core path the relay header can express (§7, [`MAX_RELAY_HOPS`]).
pub const MAX_MESH_PATH_HOPS: u8 = MAX_RELAY_HOPS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeshError {
    /// `core_id` is outside `1..=16`, or equals this Core.
    InvalidCore,
    /// The Core is not known to this view.
    UnknownCore,
    /// The Core is already in this view.
    DuplicateCore,
    /// No link carries that `connection_instance`.
    UnknownLink,
    /// The mesh already holds [`MAX_MESH_CORES`] Cores.
    MeshFull,
    /// A zero `connection_instance` cannot identify a connection (§3.1).
    ZeroInstance,
    /// `conn_slot` is outside `0..FLOWS_PER_CORE_PAIR`; it is only a local slot.
    InvalidSlot,
    /// The reported flow count exceeds [`FLOWS_PER_CORE_PAIR`].
    FlowLimit,
    /// No explicitly up pair connects the endpoints inside the hop budget, or
    /// a pair on the path is marked down.
    NoPath,
}

/// Which side of a Core pair is expected to dial (§3.1 smallest-id rule).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialRole {
    /// Our id is smaller: we are the primary dialer for this pair.
    Primary,
    /// The peer's id is smaller: it dials and we accept. We may reverse-dial
    /// only after [`REVERSE_DIAL_AFTER`] without an authorized inbound link.
    Accept,
}

/// Which direction one transport connection takes on a pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkDirection {
    Outbound,
    Inbound,
}

/// One transport connection on one Core pair.
///
/// This is a caller report, not a capability. `authorized` and `probe_ok` are
/// plain booleans: constructing a link with `true` authenticates nothing, and
/// neither bit authorizes a route. The runtime must derive them from its
/// authenticated session layer, and [`MeshTopology::path`] must never be used
/// as a runtime route grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeshLink {
    /// 128-bit CSPRNG `connection_instance` from `SessionHello`. It identifies a
    /// connection only; §3.1 forbids using it as a session key or replay key.
    pub connection_instance: [u8; 16],
    /// Local striping slot. §3.1 decouples it from `connection_instance`.
    pub conn_slot: u8,
    pub direction: LinkDirection,
    /// Caller report: inner TLS completed **and** `SessionAccept` authorized
    /// the peer. Not a session or routing capability.
    pub authorized: bool,
    /// Caller report: a probe challenge matched on this link. §3.1 requires
    /// this before a redundant dial may be drained.
    pub probe_ok: bool,
}

impl MeshLink {
    fn usable(self) -> bool {
        self.authorized && self.probe_ok
    }
}

/// §3.1 duplicate-link decision for one pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupDecision {
    /// Fewer than two links, or at least one is not yet authorized and probed.
    /// Nothing may be drained: the healthy link might be the only one.
    KeepBoth,
    /// Both links are authorized and probed. Drain the redundant reverse-dial
    /// link; the primary dialer's link survives.
    Drain { keep: [u8; 16], drain: [u8; 16] },
}

#[derive(Clone, Debug)]
struct PeerLinks {
    created_at: Instant,
    outbound: Option<MeshLink>,
    inbound: Option<MeshLink>,
    flows: u8,
}

impl PeerLinks {
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            outbound: None,
            inbound: None,
            flows: 0,
        }
    }

    fn slot(&mut self, direction: LinkDirection) -> &mut Option<MeshLink> {
        match direction {
            LinkDirection::Outbound => &mut self.outbound,
            LinkDirection::Inbound => &mut self.inbound,
        }
    }

    fn link(&self, direction: LinkDirection) -> Option<MeshLink> {
        match direction {
            LinkDirection::Outbound => self.outbound,
            LinkDirection::Inbound => self.inbound,
        }
    }
}

/// Bounded planning view of the Core mesh as seen from one Core.
///
/// This is a pure model over caller reports. It opens no socket, authenticates
/// no peer and authorizes no traffic. `add_core` records knowledge of a Core,
/// not connectivity: a pair is routeable only after the caller explicitly
/// reports it up with [`Self::mark_pair_up`]. [`Self::path`] is a planning aid,
/// never a runtime route or permission to skip TLS/`SessionAccept` on a hop.
#[derive(Clone, Debug)]
pub struct MeshTopology {
    local_core: u8,
    peers: BTreeMap<u8, PeerLinks>,
    /// Pairs explicitly reported usable by the caller. Absence means "no
    /// reported path", never "assume up".
    up_pairs: BTreeSet<(u8, u8)>,
    down_pairs: BTreeSet<(u8, u8)>,
}

impl MeshTopology {
    pub fn new(local_core: u8, _now: Instant) -> Result<Self, MeshError> {
        if local_core == 0 || usize::from(local_core) > MAX_MESH_CORES {
            return Err(MeshError::InvalidCore);
        }
        Ok(Self {
            local_core,
            peers: BTreeMap::new(),
            up_pairs: BTreeSet::new(),
            down_pairs: BTreeSet::new(),
        })
    }

    pub fn local_core(&self) -> u8 {
        self.local_core
    }

    /// Cores in this view, including the local one.
    pub fn core_count(&self) -> usize {
        self.peers.len() + 1
    }

    pub fn cores(&self) -> impl Iterator<Item = u8> {
        std::iter::once(self.local_core).chain(self.peers.keys().copied())
    }

    pub fn add_core(&mut self, core_id: u8, now: Instant) -> Result<(), MeshError> {
        if core_id == 0 || usize::from(core_id) > MAX_MESH_CORES || core_id == self.local_core {
            return Err(MeshError::InvalidCore);
        }
        if self.peers.contains_key(&core_id) {
            return Err(MeshError::DuplicateCore);
        }
        if self.core_count() >= MAX_MESH_CORES {
            return Err(MeshError::MeshFull);
        }
        self.peers.insert(core_id, PeerLinks::new(now));
        Ok(())
    }

    pub fn remove_core(&mut self, core_id: u8) -> Result<(), MeshError> {
        if self.peers.remove(&core_id).is_none() {
            return Err(MeshError::UnknownCore);
        }
        self.up_pairs
            .retain(|(a, b)| *a != core_id && *b != core_id);
        self.down_pairs
            .retain(|(a, b)| *a != core_id && *b != core_id);
        Ok(())
    }

    fn peer(&self, core_id: u8) -> Result<&PeerLinks, MeshError> {
        if core_id == 0 || usize::from(core_id) > MAX_MESH_CORES {
            return Err(MeshError::InvalidCore);
        }
        self.peers.get(&core_id).ok_or(MeshError::UnknownCore)
    }

    fn peer_mut(&mut self, core_id: u8) -> Result<&mut PeerLinks, MeshError> {
        if core_id == 0 || usize::from(core_id) > MAX_MESH_CORES {
            return Err(MeshError::InvalidCore);
        }
        self.peers.get_mut(&core_id).ok_or(MeshError::UnknownCore)
    }

    /// §3.1 dial ownership for one pair. Equal ids are rejected.
    pub fn dial_role(&self, core_id: u8) -> Result<DialRole, MeshError> {
        if core_id == self.local_core {
            return Err(MeshError::InvalidCore);
        }
        self.peer(core_id)?;
        Ok(if self.local_core < core_id {
            DialRole::Primary
        } else {
            DialRole::Accept
        })
    }

    /// Whether this Core may reverse-dial now: only for the `Accept` role, only
    /// when no authorized inbound link exists, and only after the fallback
    /// deadline. A genuine duplicate is resolved by [`Self::dedup`], not here.
    pub fn reverse_dial_allowed(&self, core_id: u8, now: Instant) -> Result<bool, MeshError> {
        let role = self.dial_role(core_id)?;
        if role != DialRole::Accept {
            return Ok(false);
        }
        let peer = self.peer(core_id)?;
        let inbound_ok = peer.inbound.is_some_and(|link| link.authorized);
        let outbound = peer.outbound.is_some();
        let deadline = peer
            .created_at
            .checked_add(REVERSE_DIAL_AFTER)
            .unwrap_or(peer.created_at);
        Ok(!inbound_ok && !outbound && now >= deadline)
    }

    /// Record or refresh one connection on a pair. A `connection_instance` is
    /// unique per connection, so replacing a link with a different instance is a
    /// new connection (drain/rebuild), not an authentication claim. Recording a
    /// link does not make the pair routeable: the caller must separately report
    /// it up after its own verification.
    pub fn note_link(&mut self, core_id: u8, link: MeshLink) -> Result<(), MeshError> {
        if link.connection_instance == [0u8; 16] {
            return Err(MeshError::ZeroInstance);
        }
        if usize::from(link.conn_slot) >= usize::from(FLOWS_PER_CORE_PAIR) {
            return Err(MeshError::InvalidSlot);
        }
        let peer = self.peer_mut(core_id)?;
        *peer.slot(link.direction) = Some(link);
        Ok(())
    }

    /// Report one probe outcome for an existing link (§8.5 matched challenge).
    pub fn note_probe(
        &mut self,
        core_id: u8,
        connection_instance: [u8; 16],
        ok: bool,
    ) -> Result<(), MeshError> {
        let peer = self.peer_mut(core_id)?;
        for direction in [LinkDirection::Outbound, LinkDirection::Inbound] {
            if let Some(link) = peer.slot(direction)
                && link.connection_instance == connection_instance
            {
                link.probe_ok = ok;
                return Ok(());
            }
        }
        Err(MeshError::UnknownLink)
    }

    /// Report the pair's current authenticated flow count, bounded by `M`.
    pub fn set_flows(&mut self, core_id: u8, flows: u8) -> Result<(), MeshError> {
        if flows > FLOWS_PER_CORE_PAIR {
            return Err(MeshError::FlowLimit);
        }
        self.peer_mut(core_id)?.flows = flows;
        Ok(())
    }

    pub fn flows(&self, core_id: u8) -> Result<u8, MeshError> {
        Ok(self.peer(core_id)?.flows)
    }

    pub fn link(&self, core_id: u8, direction: LinkDirection) -> Option<MeshLink> {
        self.peers
            .get(&core_id)
            .and_then(|peer| peer.link(direction))
    }

    /// §3.1 deduplication: drain a redundant dial only when BOTH directions are
    /// authorized and probed. The primary dialer's link always survives.
    pub fn dedup(&self, core_id: u8) -> Result<DedupDecision, MeshError> {
        let peer = self.peer(core_id)?;
        let (Some(outbound), Some(inbound)) = (peer.outbound, peer.inbound) else {
            return Ok(DedupDecision::KeepBoth);
        };
        if !outbound.usable() || !inbound.usable() {
            return Ok(DedupDecision::KeepBoth);
        }
        if outbound.connection_instance == inbound.connection_instance {
            return Ok(DedupDecision::KeepBoth);
        }
        let (keep, drain) = if self.local_core < core_id {
            (outbound, inbound)
        } else {
            (inbound, outbound)
        };
        Ok(DedupDecision::Drain {
            keep: keep.connection_instance,
            drain: drain.connection_instance,
        })
    }

    fn pair(a: u8, b: u8) -> (u8, u8) {
        if a <= b { (a, b) } else { (b, a) }
    }

    /// Report a failed Core pair (§8.5 path failure / partition) and drop any
    /// prior up report.
    pub fn mark_pair_down(&mut self, a: u8, b: u8) -> Result<(), MeshError> {
        self.check_pair(a, b)?;
        let pair = Self::pair(a, b);
        self.up_pairs.remove(&pair);
        self.down_pairs.insert(pair);
        Ok(())
    }

    /// Report that this pair is currently usable. This is a caller report, not
    /// a capability or authorization: the caller must establish the link (or
    /// consume a trusted LSA) before marking it up. No pair is up by default.
    pub fn mark_pair_up(&mut self, a: u8, b: u8) -> Result<(), MeshError> {
        self.check_pair(a, b)?;
        let pair = Self::pair(a, b);
        self.down_pairs.remove(&pair);
        self.up_pairs.insert(pair);
        Ok(())
    }

    pub fn pair_is_down(&self, a: u8, b: u8) -> bool {
        self.down_pairs.contains(&Self::pair(a, b))
    }

    fn check_pair(&self, a: u8, b: u8) -> Result<(), MeshError> {
        if a == b {
            return Err(MeshError::InvalidCore);
        }
        for core in [a, b] {
            if core != self.local_core {
                self.peer(core)?;
            }
        }
        Ok(())
    }

    fn linked(&self, a: u8, b: u8) -> bool {
        let pair = Self::pair(a, b);
        self.up_pairs.contains(&pair) && !self.down_pairs.contains(&pair)
    }

    /// Planning-only deterministic shortest Core path. Breadth-first with
    /// ascending Core order breaks ties, so two Cores holding the same view
    /// compute the same chain. A pair is traversable only when explicitly
    /// reported up; there is no implicit all-connected default. The returned
    /// path is bounded by [`MAX_MESH_PATH_HOPS`] once expressed as relay hops.
    ///
    /// This does not authenticate or authorize any hop. A caller that forwards
    /// traffic must independently establish each session and re-check policy;
    /// the path is not a route capability.
    pub fn path(&self, source: u8, destination: u8) -> Result<CorePath, MeshError> {
        for core in [source, destination] {
            if core != self.local_core {
                self.peer(core)?;
            }
        }
        if source == destination {
            return Ok(CorePath {
                cores: vec![source],
            });
        }
        // Longest usable Core chain: `relay_hops = cores + 1 <= 8`.
        let max_cores = usize::from(MAX_MESH_PATH_HOPS).saturating_sub(1);
        let mut previous: BTreeMap<u8, u8> = BTreeMap::new();
        let mut visited: BTreeSet<u8> = BTreeSet::new();
        let mut queue: VecDeque<(u8, usize)> = VecDeque::new();
        visited.insert(source);
        queue.push_back((source, 1));
        while let Some((current, depth)) = queue.pop_front() {
            if current == destination {
                break;
            }
            if depth >= max_cores {
                continue;
            }
            for next in self.cores() {
                if next == current || visited.contains(&next) || !self.linked(current, next) {
                    continue;
                }
                visited.insert(next);
                previous.insert(next, current);
                queue.push_back((next, depth + 1));
            }
        }
        if !visited.contains(&destination) {
            return Err(MeshError::NoPath);
        }
        let mut cores = vec![destination];
        let mut cursor = destination;
        while cursor != source {
            cursor = *previous.get(&cursor).ok_or(MeshError::NoPath)?;
            cores.push(cursor);
        }
        cores.reverse();
        Ok(CorePath { cores })
    }
}

/// One fixed forwarding chain (§7): the Cores a circuit traverses, inclusive.
///
/// Planning data only. It is not a route capability or a session token, and it
/// must not be used to skip authentication or authorization on any hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePath {
    cores: Vec<u8>,
}

impl CorePath {
    pub fn cores(&self) -> &[u8] {
        &self.cores
    }

    pub fn len(&self) -> usize {
        self.cores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cores.is_empty()
    }

    /// Relay hop budget for an edge behind the first Core towards an edge behind
    /// the last: one hop into the mesh, one per Core link, one hop out. This is
    /// the value `CircuitOpen.path_hops` carries, and each relay decrements it.
    pub fn relay_hops(&self) -> Result<u8, MeshError> {
        if self.cores.is_empty() {
            return Err(MeshError::NoPath);
        }
        let hops = u8::try_from(self.cores.len())
            .ok()
            .and_then(|cores| cores.checked_add(1))
            .ok_or(MeshError::NoPath)?;
        if hops < 2 || hops > MAX_MESH_PATH_HOPS {
            return Err(MeshError::NoPath);
        }
        Ok(hops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Limits;
    fn table() -> RelayTable {
        RelayTable::new(
            Admission::new(Limits {
                handshakes_global: 4,
                authenticated_global: 8,
                authenticated_per_peer: 4,
                bytes_global: MAX_PREOPEN_BYTES,
            }),
            8,
        )
    }
    fn node(id: u16, generation: u64) -> NodeRef {
        NodeRef {
            node_id: id,
            identity_generation: generation,
        }
    }
    fn id(n: u8) -> CircuitId {
        let mut b = [0; 16];
        b[15] = n;
        CircuitId(b)
    }
    fn test_session(peer: NodeRef) -> VerifiedE2eSession {
        VerifiedE2eSession::test_only(peer)
    }
    #[test]
    fn pair_limit_and_pair_queue_byte_credit() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        assert_eq!(
            t.open(id(2), node(2, 1), node(1, 1), 8, now),
            Err(RelayError::PairLimit)
        );
        let payload = t.queue_preopen(id(1), vec![7; MAX_PREOPEN_BYTES], now);
        assert!(payload.is_ok());
        let duplicate = t.queue_preopen(id(1), vec![1], now);
        assert_eq!(duplicate, Err(RelayError::PreopenLimit));
        assert_eq!(
            t.open(id(3), node(1, 2), node(1, 3), 8, now),
            Err(RelayError::InvalidEndpoints)
        );
        assert_eq!(
            RelayTable::with_pair_limit(
                Admission::new(Limits {
                    handshakes_global: 1,
                    authenticated_global: 1,
                    authenticated_per_peer: 1,
                    bytes_global: 1
                }),
                8,
                5
            )
            .err(),
            Some(RelayError::PairLimit)
        );
        assert_eq!(
            RelayTable::with_pair_limit(
                Admission::new(Limits {
                    handshakes_global: 1,
                    authenticated_global: 1,
                    authenticated_per_peer: 1,
                    bytes_global: 1
                }),
                8,
                0
            )
            .err(),
            Some(RelayError::PairLimit)
        );
    }
    #[test]
    fn pair_queue_budget_aggregates_across_circuits_and_rejects_empty() {
        let admission = Admission::new(Limits {
            handshakes_global: 4,
            authenticated_global: 8,
            authenticated_per_peer: 4,
            bytes_global: 2 * MAX_PREOPEN_BYTES,
        });
        let mut t = RelayTable::with_pair_limit(admission, 8, 2).unwrap();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        t.open(id(2), node(1, 1), node(2, 1), 8, now).unwrap();
        assert_eq!(
            t.queue_preopen(id(1), Vec::new(), now),
            Err(RelayError::PreopenLimit)
        );
        t.queue_preopen(id(1), vec![1; MAX_PREOPEN_BYTES / 2], now)
            .unwrap();
        assert_eq!(
            t.queue_preopen(id(2), vec![2; MAX_PREOPEN_BYTES / 2 + 1], now),
            Err(RelayError::PreopenLimit)
        );
        t.queue_preopen(id(2), vec![2; MAX_PREOPEN_BYTES / 2], now)
            .unwrap();
    }
    #[test]
    fn generation_or_offset_error_locks_circuit() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 2), node(2, 3), 8, now).unwrap();
        t.mark_established(id(1), now).unwrap();
        let hop = HopSessionToken::test_only(node(1, 2));
        assert_eq!(
            t.accept_segment(
                id(1),
                &hop,
                Segment {
                    direction: Direction::SourceToDestination,
                    offset: 0,
                    source: node(1, 1),
                    destination: node(2, 3),
                    bytes: b"x",
                    now
                },
            ),
            Err(RelayError::WrongSourceGeneration)
        );
        assert_eq!(
            t.accept_segment(
                id(1),
                &hop,
                Segment {
                    direction: Direction::SourceToDestination,
                    offset: 0,
                    source: node(1, 2),
                    destination: node(2, 3),
                    bytes: b"x",
                    now
                },
            ),
            Err(RelayError::NotEstablished)
        );
    }
    #[test]
    fn expiry_and_hop_bounds() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        assert_eq!(
            t.mark_established(id(1), now + PREOPEN_TTL),
            Err(RelayError::PreopenExpired)
        );
        assert_eq!(t.decrement_hop(id(1)).unwrap(), 7);
        assert_eq!(t.reap_expired(now + PREOPEN_TTL), vec![id(1)]);
    }
    #[test]
    fn foreign_hop_cannot_feed_a_circuit() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        t.mark_established(id(1), now).unwrap();
        let foreign = HopSessionToken::test_only(node(9, 1));
        assert_eq!(
            t.accept_segment(
                id(1),
                &foreign,
                Segment {
                    direction: Direction::SourceToDestination,
                    offset: 0,
                    source: node(1, 1),
                    destination: node(2, 1),
                    bytes: b"x",
                    now
                },
            ),
            Err(RelayError::WrongHop)
        );
    }

    #[test]
    fn e2e_token_requires_strict_tls_and_exact_peer() {
        use crate::tls::{InnerTlsSession, PeerIdentity, strict_test_negotiated};
        use boreas_crypto::NodeRole;
        use boreas_proto::messages::Suite as MessageSuite;

        let peer = PeerIdentity::legacy_default([7; 16], 2, 1, NodeRole::Core);
        let strict = InnerTlsSession::test_only(peer, strict_test_negotiated());
        assert!(
            VerifiedE2eSession::from_verified_e2e_tls(&strict, peer, MessageSuite::Pq768, false)
                .is_ok()
        );

        let mut wrong_peer = peer;
        wrong_peer.identity_generation = 2;
        assert_eq!(
            VerifiedE2eSession::from_verified_e2e_tls(
                &strict,
                wrong_peer,
                MessageSuite::Pq768,
                false
            )
            .err(),
            Some(TunnelError::Session(SessionReject::PeerIdentityMismatch))
        );

        let mut downgraded = strict_test_negotiated();
        downgraded.group = boreas_crypto::HybridGroup::ClassicalOnly;
        let classical = InnerTlsSession::test_only(peer, downgraded);
        assert!(matches!(
            VerifiedE2eSession::from_verified_e2e_tls(&classical, peer, MessageSuite::Pq768, false),
            Err(TunnelError::Policy(
                boreas_crypto::PolicyError::HybridGroupRequired
            ))
        ));
    }

    #[test]
    fn preopen_consumption_requires_the_circuits_e2e_peer() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        t.queue_preopen(id(1), vec![1, 2, 3], now).unwrap();
        t.mark_established(id(1), now).unwrap();

        // A valid token for another peer cannot drain this circuit's queue.
        assert_eq!(
            t.consume_preopen(id(1), &test_session(node(9, 1)), now)
                .err(),
            Some(RelayError::WrongSession)
        );
        let payload = t
            .consume_preopen(id(1), &test_session(node(2, 1)), now)
            .unwrap();
        assert_eq!(payload[0].as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn returned_payload_holds_global_credit_until_payload_drop() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        t.queue_preopen(id(1), vec![1, 2, 3], now).unwrap();
        t.mark_established(id(1), now).unwrap();
        let session = test_session(node(2, 1));
        let payload = t.consume_preopen(id(1), &session, now).unwrap();
        assert_eq!(payload[0].as_bytes(), [1, 2, 3]);
        assert_eq!(t.admission.snapshot().unwrap().bytes, 3);
        drop(payload);
        assert_eq!(t.admission.snapshot().unwrap().bytes, 0);
    }
}

#[cfg(test)]
mod mesh_tests {
    use super::*;

    fn link(instance: u8, direction: LinkDirection, authorized: bool, probe_ok: bool) -> MeshLink {
        MeshLink {
            connection_instance: [instance; 16],
            conn_slot: 0,
            direction,
            authorized,
            probe_ok,
        }
    }

    fn pair_view(local: u8, peer: u8) -> (MeshTopology, Instant) {
        let now = Instant::now();
        let mut topology = MeshTopology::new(local, now).expect("local core");
        topology.add_core(peer, now).expect("peer core");
        (topology, now)
    }

    fn report_up(topology: &mut MeshTopology, pairs: &[(u8, u8)]) {
        for &(a, b) in pairs {
            topology.mark_pair_up(a, b).expect("reported pair up");
        }
    }

    #[test]
    fn dial_ownership_follows_the_smaller_core_id() {
        let (topology, _now) = pair_view(2, 3);
        assert_eq!(topology.core_count(), 2);
        assert_eq!(topology.dial_role(3), Ok(DialRole::Primary));
        let (larger, _now) = pair_view(3, 2);
        assert_eq!(larger.dial_role(2), Ok(DialRole::Accept));
        assert_eq!(larger.dial_role(3), Err(MeshError::InvalidCore));
        assert_eq!(larger.dial_role(9), Err(MeshError::UnknownCore));
    }

    #[test]
    fn reverse_dial_waits_for_the_fallback_deadline() {
        let (mut topology, now) = pair_view(3, 2);
        // Still inside the 6 s window: no reverse dial.
        assert_eq!(topology.reverse_dial_allowed(2, now), Ok(false));
        // Past the deadline but an authorized inbound link exists: the pair is
        // already up, so a reverse dial would only create a duplicate.
        topology
            .note_link(2, link(0x21, LinkDirection::Inbound, true, true))
            .expect("inbound link");
        assert_eq!(
            topology.reverse_dial_allowed(2, now + REVERSE_DIAL_AFTER * 2),
            Ok(false)
        );
        // A fresh view with no inbound link may reverse-dial after the deadline.
        let (fresh, now) = pair_view(3, 2);
        assert_eq!(
            fresh.reverse_dial_allowed(2, now + REVERSE_DIAL_AFTER),
            Ok(true)
        );
        // The primary dialer never reverse-dials against its own rule.
        let (primary, now) = pair_view(2, 3);
        assert_eq!(
            primary.reverse_dial_allowed(3, now + REVERSE_DIAL_AFTER),
            Ok(false)
        );
    }

    #[test]
    fn dedup_needs_both_ends_authorized_and_probed() {
        let (mut topology, _now) = pair_view(2, 3);
        topology
            .note_link(3, link(0x11, LinkDirection::Outbound, true, false))
            .expect("outbound");
        topology
            .note_link(3, link(0x22, LinkDirection::Inbound, true, true))
            .expect("inbound");
        // The primary dialer's link has not passed a probe yet: keep both, and
        // never drop the only healthy link.
        assert_eq!(topology.dedup(3), Ok(DedupDecision::KeepBoth));
        topology.note_probe(3, [0x11; 16], true).expect("probe");
        assert_eq!(
            topology.dedup(3),
            Ok(DedupDecision::Drain {
                keep: [0x11; 16],
                drain: [0x22; 16],
            })
        );

        // From the larger Core's view the survivor is its inbound link.
        let (mut larger, _now) = pair_view(3, 2);
        larger
            .note_link(2, link(0x33, LinkDirection::Outbound, true, true))
            .expect("reverse dial");
        larger
            .note_link(2, link(0x44, LinkDirection::Inbound, true, true))
            .expect("primary dial");
        assert_eq!(
            larger.dedup(2),
            Ok(DedupDecision::Drain {
                keep: [0x44; 16],
                drain: [0x33; 16],
            })
        );

        // An unauthorized link is never drained on the strength of the other.
        let (mut pending, _now) = pair_view(2, 3);
        pending
            .note_link(3, link(0x55, LinkDirection::Outbound, true, true))
            .expect("outbound");
        pending
            .note_link(3, link(0x66, LinkDirection::Inbound, false, true))
            .expect("inbound");
        assert_eq!(pending.dedup(3), Ok(DedupDecision::KeepBoth));
    }

    #[test]
    fn flows_slots_and_link_identity_are_bounded() {
        let (mut topology, _now) = pair_view(2, 3);
        assert_eq!(topology.flows(3), Ok(0));
        assert_eq!(
            topology.set_flows(3, FLOWS_PER_CORE_PAIR + 1),
            Err(MeshError::FlowLimit)
        );
        assert_eq!(topology.set_flows(3, FLOWS_PER_CORE_PAIR), Ok(()));
        assert_eq!(topology.flows(3), Ok(FLOWS_PER_CORE_PAIR));

        let mut bad_slot = link(0x07, LinkDirection::Outbound, true, true);
        bad_slot.conn_slot = FLOWS_PER_CORE_PAIR;
        assert_eq!(topology.note_link(3, bad_slot), Err(MeshError::InvalidSlot));

        let mut zero = link(0x00, LinkDirection::Outbound, true, true);
        zero.connection_instance = [0u8; 16];
        assert_eq!(topology.note_link(3, zero), Err(MeshError::ZeroInstance));

        assert_eq!(
            topology.note_probe(3, [0x99; 16], true),
            Err(MeshError::UnknownLink)
        );
        assert_eq!(topology.link(3, LinkDirection::Outbound), None);
    }

    #[test]
    fn path_is_deterministic_and_respects_the_hop_budget() {
        let now = Instant::now();
        let mut topology = MeshTopology::new(2, now).expect("core 2");
        for core in [3u8, 4, 5] {
            topology.add_core(core, now).expect("peer core");
        }
        // Knowing a Core is not a link: without an explicit report there is no
        // route, even though the pair is not marked down.
        assert_eq!(topology.path(2, 5), Err(MeshError::NoPath));
        // No implicit all-connected default: every pair the planner may use is
        // explicitly reported up by the caller.
        report_up(
            &mut topology,
            &[(2, 3), (2, 4), (2, 5), (3, 4), (3, 5), (4, 5)],
        );
        // Direct link wins, and a Core route costs one hop in, one per link and
        // one out.
        assert_eq!(topology.path(2, 5).expect("path").cores(), &[2u8, 5][..]);
        assert_eq!(topology.path(2, 5).expect("path").relay_hops(), Ok(3));
        assert_eq!(topology.path(2, 2).expect("self").cores(), &[2u8][..]);
        assert_eq!(topology.path(2, 2).expect("self").relay_hops(), Ok(2));

        // A failed direct pair forces the ascending alternative.
        topology.mark_pair_down(2, 5).expect("pair down");
        assert_eq!(
            topology.path(2, 5).expect("detour").cores(),
            &[2u8, 3, 5][..]
        );
        assert_eq!(topology.path(2, 5).expect("detour").relay_hops(), Ok(4));

        // Cut every link leaving Core 2: no path remains.
        topology.mark_pair_down(2, 3).expect("pair down");
        topology.mark_pair_down(2, 4).expect("pair down");
        assert_eq!(topology.path(2, 5), Err(MeshError::NoPath));
        topology.mark_pair_up(2, 5).expect("pair up");
        assert_eq!(
            topology.path(2, 5).expect("restored").cores(),
            &[2u8, 5][..]
        );
    }

    #[test]
    fn chain_longer_than_the_relay_budget_is_refused() {
        let now = Instant::now();
        let mut topology = MeshTopology::new(2, now).expect("core 2");
        for core in 3..=9u8 {
            topology.add_core(core, now).expect("peer core");
        }
        // Only explicitly reported links are usable. Leave the chain
        // 2-3-4-5-6-7-8-9 up and mark every non-adjacent pair down.
        for a in 2..=8u8 {
            topology.mark_pair_up(a, a + 1).expect("chain pair up");
        }
        for a in 2..=9u8 {
            for b in (a + 1)..=9u8 {
                if b != a + 1 {
                    topology.mark_pair_down(a, b).expect("pair down");
                }
            }
        }
        // Seven Cores between the edges is the longest expressible chain.
        assert_eq!(
            topology.path(2, 8).expect("chain").cores(),
            &[2u8, 3, 4, 5, 6, 7, 8][..]
        );
        assert_eq!(topology.path(2, 8).expect("chain").relay_hops(), Ok(8));
        // Eight Cores would need nine relay hops, above the §7 ceiling.
        assert_eq!(topology.path(2, 9), Err(MeshError::NoPath));
    }

    #[test]
    fn mesh_core_count_is_bounded() {
        let now = Instant::now();
        let mut topology = MeshTopology::new(1, now).expect("core 1");
        for core in 2..=16u8 {
            topology.add_core(core, now).expect("peer core");
        }
        // Cores are `1..=16`, so a 16-Core view is complete and a duplicate is
        // rejected rather than growing the map. An out-of-range id is refused
        // even when the view is not full.
        assert_eq!(topology.core_count(), MAX_MESH_CORES);
        assert_eq!(topology.add_core(0, now), Err(MeshError::InvalidCore));
        assert_eq!(topology.add_core(17, now), Err(MeshError::InvalidCore));
        assert_eq!(topology.add_core(2, now), Err(MeshError::DuplicateCore));
        assert_eq!(topology.remove_core(99), Err(MeshError::UnknownCore));
        assert_eq!(topology.remove_core(16), Ok(()));
        assert_eq!(topology.core_count(), MAX_MESH_CORES - 1);
        assert_eq!(topology.add_core(0, now), Err(MeshError::InvalidCore));
        assert_eq!(topology.add_core(17, now), Err(MeshError::InvalidCore));
        assert_eq!(topology.mark_pair_down(3, 3), Err(MeshError::InvalidCore));
        // Core 16 was just removed from this view.
        assert_eq!(topology.mark_pair_down(3, 16), Err(MeshError::UnknownCore));
    }
}
