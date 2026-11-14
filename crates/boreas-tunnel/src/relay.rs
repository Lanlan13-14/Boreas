//! RelayCircuit lifecycle and bounded pre-establishment queues only. This is
//! NOT TLS, key agreement, authentication, or an E2E-active token. Callers must
//! hold a genuine verified TLS session token before passing application traffic.
use crate::resource::{Admission, AdmissionError, ByteCredit};
use std::collections::{HashMap, VecDeque};
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

/// Opaque capability reserved for a future TLS integration. No constructor is
/// available in production until a real E2E TLS backend has been reviewed.
pub struct VerifiedE2eSession {
    _private: (),
}
#[cfg(test)]
impl VerifiedE2eSession {
    fn test_only() -> Self {
        Self { _private: () }
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
    pub fn consume_preopen(
        &mut self,
        id: CircuitId,
        _session: &VerifiedE2eSession,
        now: Instant,
    ) -> Result<Vec<PreopenPayload>, RelayError> {
        let c = self
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::NotEstablished)?;
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
    pub fn accept_segment(
        &mut self,
        id: CircuitId,
        _session: &VerifiedE2eSession,
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
        let error = if claimed_source.node_id != src.node_id {
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
    fn test_session() -> VerifiedE2eSession {
        VerifiedE2eSession::test_only()
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
        let session = test_session();
        assert_eq!(
            t.accept_segment(
                id(1),
                &session,
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
                &session,
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
    fn returned_payload_holds_global_credit_until_payload_drop() {
        let mut t = table();
        let now = Instant::now();
        t.open(id(1), node(1, 1), node(2, 1), 8, now).unwrap();
        t.queue_preopen(id(1), vec![1, 2, 3], now).unwrap();
        t.mark_established(id(1), now).unwrap();
        let session = test_session();
        let payload = t.consume_preopen(id(1), &session, now).unwrap();
        assert_eq!(payload[0].as_bytes(), [1, 2, 3]);
        assert_eq!(t.admission.snapshot().unwrap().bytes, 3);
        drop(payload);
        assert_eq!(t.admission.snapshot().unwrap().bytes, 0);
    }
}
