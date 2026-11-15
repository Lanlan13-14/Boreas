//! Pure relay-circuit byte stream: hop budget, ordered offsets, ciphertext
//! backpressure, and pre-establishment plaintext admission.
//!
//! This is not TLS, not a core, and not a grant ledger. Identity generations,
//! the 900 s lifetime, global admission, and [`crate::relay::RelayTable`]
//! pre-open credit stay in `relay`. That table already rejects a non-contiguous
//! segment once a caller holds [`crate::relay::VerifiedE2eSession`]; the session
//! type has no production constructor, so the cursor, the ciphertext cap, and
//! the pending-drop rule live here where they can be checked without one.
//!
//! `relay_hops_left` is not an IP TTL. This module has no function that reads
//! or writes an IP header. Nothing here decrypts, and nothing tries another key
//! after `Reset`. Passing these tests does not pass `G-E2E`.

#![forbid(unsafe_code)]

use std::fmt;

pub use crate::relay::CircuitId;
pub use crate::relay::DEFAULT_MAX_CIRCUITS_PER_PAIR as DEFAULT_PAIR_CAP;
pub use crate::relay::HARD_MAX_CIRCUITS_PER_PAIR as HARD_PAIR_CAP;
/// Per-direction cap on ciphertext that has not been released.
///
/// Same 64 KiB figure as the relay pre-open byte cap. It is not that ledger:
/// [`RelayCircuit::push`] accounts for it locally and never takes a
/// [`crate::resource::ByteCredit`].
pub use crate::relay::MAX_PREOPEN_BYTES as CIPHERTEXT_QUEUE_CAP;
pub use crate::relay::MAX_RELAY_HOPS as RELAY_HOPS_MAX;

/// Plaintext queued before a circuit is up, per peer pair. Same 64 KiB figure.
pub const PENDING_PLAINTEXT_CAP: usize = CIPHERTEXT_QUEUE_CAP;

/// Longest wait for that plaintext. Same two seconds as [`crate::relay::PREOPEN_TTL`].
pub const PENDING_WAIT_MS: u64 = 2_000;

const _: () = {
    assert!(RELAY_HOPS_MAX == 8);
    assert!(DEFAULT_PAIR_CAP == 1);
    assert!(HARD_PAIR_CAP == 4);
    assert!(CIPHERTEXT_QUEUE_CAP == 64 * 1024);
    assert!(PENDING_PLAINTEXT_CAP == 64 * 1024);
    assert!(PENDING_WAIT_MS == 2_000);
    assert!(crate::relay::PREOPEN_TTL.as_secs() == 2);
};

/// Why a pure circuit operation stopped. None of these mean "send hop-only".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitError {
    /// The two node ids are the same, so there is no low TLS client.
    EqualNodes,
    /// Pair cap was not in `1..=4`.
    InvalidCap,
    /// Circuit id, hop start, or duplicate id cannot open a stream.
    InvalidOpen,
    /// Zero-length fragment. The cursor and the queue are unchanged.
    Empty,
    /// This direction was poisoned, or the circuit was reset. Not a key trial.
    Reset,
    /// The new ciphertext does not fit in the 64 KiB not-yet-released queue.
    Backpressure,
    /// This peer pair already holds its cap of circuits.
    TooMany,
    /// The new pre-up plaintext datagram was dropped. Previously queued bytes stay.
    PendingDrop,
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EqualNodes => "circuit endpoints have the same node id",
            Self::InvalidCap => "circuit cap must be from 1 to 4",
            Self::InvalidOpen => "circuit id or hop budget cannot open",
            Self::Empty => "empty circuit fragment",
            Self::Reset => "circuit was reset",
            Self::Backpressure => "ciphertext queue is at the 64 KiB cap",
            Self::TooMany => "peer pair circuit cap is exhausted",
            Self::PendingDrop => "pending plaintext datagram was dropped",
        })
    }
}

impl std::error::Error for CircuitError {}

/// One direction of the virtual byte stream. `A` and `B` are the caller's
/// endpoint arguments, not a canonical low/high rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    AtoB,
    BtoA,
}

/// `true` when `a < b`. Equal ids are `false`; opening them is [`CircuitError::EqualNodes`].
pub const fn client_is_low(a: u16, b: u16) -> bool {
    a < b
}

/// A business trigger never authorizes `CircuitOpen`, including a trigger from
/// the high node. There is no open path that takes a trigger.
pub const fn trigger_authorizes_open() -> bool {
    false
}

/// Decrement the relay hop budget. `0` is [`CircuitError::Reset`] and does not wrap.
///
/// This is the circuit header counter. It does not read an IP header.
pub const fn forward(hops_left: u8) -> Result<u8, CircuitError> {
    match hops_left.checked_sub(1) {
        Some(next) => Ok(next),
        None => Err(CircuitError::Reset),
    }
}

/// Admit one plaintext datagram while the circuit is not up.
///
/// `Err(PendingDrop)` drops that new datagram only. It is not a hop-only send.
pub const fn admit_pending(queued: usize, add: usize, waited_ms: u64) -> Result<(), CircuitError> {
    let over_bytes = match queued.checked_add(add) {
        Some(total) => total > PENDING_PLAINTEXT_CAP,
        None => true,
    };
    if over_bytes || waited_ms >= PENDING_WAIT_MS {
        Err(CircuitError::PendingDrop)
    } else {
        Ok(())
    }
}

/// Counts datagrams [`admit_pending`] refused. The queued total does not shrink.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingPlaintext {
    queued: usize,
    drops: u64,
}

impl PendingPlaintext {
    pub const fn new() -> Self {
        Self {
            queued: 0,
            drops: 0,
        }
    }

    pub const fn queued(self) -> usize {
        self.queued
    }

    pub const fn drops(self) -> u64 {
        self.drops
    }

    /// On refusal, increments the drop count and leaves `queued` untouched.
    pub fn admit(&mut self, add: usize, waited_ms: u64) -> Result<(), CircuitError> {
        match admit_pending(self.queued, add, waited_ms) {
            Ok(()) => {
                self.queued += add;
                Ok(())
            }
            Err(error) => {
                self.drops = self.drops.saturating_add(1);
                Err(error)
            }
        }
    }
}

struct DirectionStream {
    next_expected: u64,
    send_offset: u64,
    poisoned: bool,
    queue: Vec<Vec<u8>>,
    queued: usize,
}

impl DirectionStream {
    const fn new() -> Self {
        Self {
            next_expected: 0,
            send_offset: 0,
            poisoned: false,
            queue: Vec::new(),
            queued: 0,
        }
    }
}

/// One circuit's hop counter and two directional byte cursors.
///
/// Built only by [`CircuitPair::open`]. Fields stay private so a caller cannot
/// clear the poison bit or delete one ciphertext chunk and keep going.
pub struct RelayCircuit {
    id: CircuitId,
    endpoint_a: u16,
    endpoint_b: u16,
    relay_hops_left: u8,
    atob: DirectionStream,
    btoa: DirectionStream,
    reset: bool,
}

impl RelayCircuit {
    fn new(id: CircuitId, endpoint_a: u16, endpoint_b: u16, relay_hops_left: u8) -> Self {
        debug_assert!(endpoint_a != endpoint_b);
        debug_assert!((1..=RELAY_HOPS_MAX).contains(&relay_hops_left));
        Self {
            id,
            endpoint_a,
            endpoint_b,
            relay_hops_left,
            atob: DirectionStream::new(),
            btoa: DirectionStream::new(),
            reset: false,
        }
    }

    pub const fn id(&self) -> CircuitId {
        self.id
    }

    pub const fn endpoint_a(&self) -> u16 {
        self.endpoint_a
    }

    pub const fn endpoint_b(&self) -> u16 {
        self.endpoint_b
    }

    /// Lower node id. Argument order does not matter, and this does not open.
    pub const fn tls_client(&self) -> u16 {
        if client_is_low(self.endpoint_a, self.endpoint_b) {
            self.endpoint_a
        } else {
            self.endpoint_b
        }
    }

    pub const fn relay_hops_left(&self) -> u8 {
        self.relay_hops_left
    }

    pub const fn is_reset(&self) -> bool {
        self.reset
    }

    pub const fn is_poisoned(&self, direction: Direction) -> bool {
        self.stream(direction).poisoned
    }

    pub const fn next_expected(&self, direction: Direction) -> u64 {
        self.stream(direction).next_expected
    }

    pub const fn send_offset(&self, direction: Direction) -> u64 {
        self.stream(direction).send_offset
    }

    pub const fn ciphertext_bytes(&self, direction: Direction) -> usize {
        self.stream(direction).queued
    }

    pub fn ciphertext_chunks(&self, direction: Direction) -> usize {
        self.stream(direction).queue.len()
    }

    pub fn ciphertext_head(&self, direction: Direction) -> Option<&[u8]> {
        self.stream(direction).queue.first().map(Vec::as_slice)
    }

    /// Apply [`forward`] and store it. `Ok(0)` is the exhausted budget.
    /// The next call resets the circuit and does not wrap.
    pub fn forward_hop(&mut self) -> Result<u8, CircuitError> {
        if self.reset {
            return Err(CircuitError::Reset);
        }
        match forward(self.relay_hops_left) {
            Ok(next) => {
                self.relay_hops_left = next;
                Ok(next)
            }
            Err(error) => {
                self.fail_circuit();
                Err(error)
            }
        }
    }

    /// Accept `bytes` only when `offset == next_expected` for this direction.
    ///
    /// A hole, a reorder, an overlap, or a duplicate range returns [`CircuitError::Reset`]
    /// and poisons the direction. The duplicate is not dropped and forgotten.
    /// This does not decrypt.
    pub fn accept(
        &mut self,
        direction: Direction,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u64, CircuitError> {
        if self.reset {
            return Err(CircuitError::Reset);
        }
        if bytes.is_empty() {
            return Err(CircuitError::Empty);
        }
        let expected = self.stream(direction).next_expected;
        if self.stream(direction).poisoned || offset != expected {
            self.fail(direction);
            return Err(CircuitError::Reset);
        }
        let Ok(len) = u64::try_from(bytes.len()) else {
            self.fail(direction);
            return Err(CircuitError::Reset);
        };
        let Some(next) = expected.checked_add(len) else {
            self.fail(direction);
            return Err(CircuitError::Reset);
        };
        self.stream_mut(direction).next_expected = next;
        Ok(next)
    }

    /// Queue ciphertext that has not been released. Over the cap, the previous
    /// chunks stay and the send cursor does not move.
    ///
    /// There is no method that drops one chunk and continues. [`Self::reset_circuit`]
    /// is the only way off a stuck cap.
    pub fn push(&mut self, direction: Direction, bytes: &[u8]) -> Result<(), CircuitError> {
        if self.reset {
            return Err(CircuitError::Reset);
        }
        if bytes.is_empty() {
            return Err(CircuitError::Empty);
        }
        let queued = self.stream(direction).queued;
        let send_offset = self.stream(direction).send_offset;
        if queued
            .checked_add(bytes.len())
            .is_none_or(|total| total > CIPHERTEXT_QUEUE_CAP)
        {
            return Err(CircuitError::Backpressure);
        }
        let Ok(len) = u64::try_from(bytes.len()) else {
            self.fail_circuit();
            return Err(CircuitError::Reset);
        };
        let Some(next_offset) = send_offset.checked_add(len) else {
            self.fail_circuit();
            return Err(CircuitError::Reset);
        };
        let stream = self.stream_mut(direction);
        stream.queued += bytes.len();
        stream.send_offset = next_offset;
        stream.queue.push(bytes.to_vec());
        Ok(())
    }

    /// Discard both ciphertext queues. Further `push` and `accept` fail.
    pub fn reset_circuit(&mut self) {
        self.fail_circuit();
    }

    const fn stream(&self, direction: Direction) -> &DirectionStream {
        match direction {
            Direction::AtoB => &self.atob,
            Direction::BtoA => &self.btoa,
        }
    }

    fn stream_mut(&mut self, direction: Direction) -> &mut DirectionStream {
        match direction {
            Direction::AtoB => &mut self.atob,
            Direction::BtoA => &mut self.btoa,
        }
    }

    fn discard_ciphertext(&mut self) {
        self.atob.queue.clear();
        self.atob.queued = 0;
        self.btoa.queue.clear();
        self.btoa.queued = 0;
    }

    fn fail(&mut self, direction: Direction) {
        self.reset = true;
        self.stream_mut(direction).poisoned = true;
        self.discard_ciphertext();
    }

    fn fail_circuit(&mut self) {
        self.reset = true;
        self.atob.poisoned = true;
        self.btoa.poisoned = true;
        self.discard_ciphertext();
    }
}

/// Circuits for one peer pair. One object is one unordered pair; a swapped
/// `(b, a)` must not be a second object with its own cap.
pub struct CircuitPair {
    endpoint_a: u16,
    endpoint_b: u16,
    cap: usize,
    circuits: Vec<RelayCircuit>,
}

impl CircuitPair {
    /// `cap` must be `1..=4`. Equal node ids are refused.
    pub fn new(endpoint_a: u16, endpoint_b: u16, cap: usize) -> Result<Self, CircuitError> {
        if endpoint_a == endpoint_b {
            return Err(CircuitError::EqualNodes);
        }
        if !(1..=HARD_PAIR_CAP).contains(&cap) {
            return Err(CircuitError::InvalidCap);
        }
        Ok(Self {
            endpoint_a,
            endpoint_b,
            cap,
            circuits: Vec::new(),
        })
    }

    pub fn with_default_cap(endpoint_a: u16, endpoint_b: u16) -> Result<Self, CircuitError> {
        Self::new(endpoint_a, endpoint_b, DEFAULT_PAIR_CAP)
    }

    /// Lower node id. Does not open a circuit and does not read a trigger.
    pub const fn tls_client(endpoint_a: u16, endpoint_b: u16) -> Result<u16, CircuitError> {
        if endpoint_a == endpoint_b {
            Err(CircuitError::EqualNodes)
        } else if client_is_low(endpoint_a, endpoint_b) {
            Ok(endpoint_a)
        } else {
            Ok(endpoint_b)
        }
    }

    pub const fn endpoint_a(&self) -> u16 {
        self.endpoint_a
    }

    pub const fn endpoint_b(&self) -> u16 {
        self.endpoint_b
    }

    pub const fn cap(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Open one circuit. A trigger is not an argument and cannot authorize this.
    pub fn open(&mut self, id: CircuitId, relay_hops_left: u8) -> Result<(), CircuitError> {
        if id.0 == [0; 16] || !(1..=RELAY_HOPS_MAX).contains(&relay_hops_left) {
            return Err(CircuitError::InvalidOpen);
        }
        if self.circuits.iter().any(|circuit| circuit.id == id) {
            return Err(CircuitError::InvalidOpen);
        }
        if self.circuits.len() >= self.cap {
            return Err(CircuitError::TooMany);
        }
        self.circuits.push(RelayCircuit::new(
            id,
            self.endpoint_a,
            self.endpoint_b,
            relay_hops_left,
        ));
        Ok(())
    }

    pub fn get(&self, id: CircuitId) -> Option<&RelayCircuit> {
        self.circuits.iter().find(|circuit| circuit.id == id)
    }

    pub fn get_mut(&mut self, id: CircuitId) -> Option<&mut RelayCircuit> {
        self.circuits.iter_mut().find(|circuit| circuit.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> CircuitId {
        let mut bytes = [0; 16];
        bytes[15] = n;
        CircuitId(bytes)
    }

    #[test]
    fn low_node_is_tls_client_and_trigger_does_not_open() {
        assert_eq!(std::mem::size_of::<CircuitId>(), 16);
        assert!(client_is_low(4, 9));
        assert!(!client_is_low(9, 4));
        assert!(!client_is_low(9, 9));
        assert_eq!(
            CircuitPair::new(9, 9, 1).err(),
            Some(CircuitError::EqualNodes)
        );
        assert_eq!(CircuitPair::tls_client(9, 9), Err(CircuitError::EqualNodes));
        assert_eq!(CircuitPair::tls_client(9, 4).unwrap(), 4);
        assert_eq!(CircuitPair::tls_client(4, 9).unwrap(), 4);
        let authorized = trigger_authorizes_open();
        assert!(!authorized);
        let mut pair = CircuitPair::new(9, 4, 1).unwrap();
        assert_eq!(pair.len(), 0);
        assert_eq!(pair.endpoint_a(), 9);
        assert_eq!(pair.endpoint_b(), 4);
        pair.open(cid(1), 8).unwrap();
        let circuit = pair.get(cid(1)).unwrap();
        assert_eq!(circuit.endpoint_a(), 9);
        assert_eq!(circuit.endpoint_b(), 4);
        assert_eq!(circuit.tls_client(), 4);
        assert_eq!(circuit.relay_hops_left(), 8);
    }

    #[test]
    fn forward_one_to_zero_does_not_wrap() {
        assert_eq!(forward(8), Ok(7));
        assert_eq!(forward(1), Ok(0));
        assert_eq!(forward(0), Err(CircuitError::Reset));
        assert_ne!(forward(0).ok(), Some(255));
        let mut pair = CircuitPair::new(1, 2, 2).unwrap();
        assert_eq!(pair.open(cid(1), 0), Err(CircuitError::InvalidOpen));
        assert_eq!(pair.open(cid(1), 9), Err(CircuitError::InvalidOpen));
        assert!(pair.is_empty());
        pair.open(cid(1), 1).unwrap();
        pair.open(cid(2), 8).unwrap();
        {
            let circuit = pair.get_mut(cid(1)).unwrap();
            assert_eq!(circuit.relay_hops_left(), 1);
            assert_eq!(circuit.forward_hop(), Ok(0));
            assert_eq!(circuit.relay_hops_left(), 0);
            assert!(!circuit.is_reset());
            assert_eq!(circuit.forward_hop(), Err(CircuitError::Reset));
            assert!(circuit.is_reset());
            assert_eq!(circuit.forward_hop(), Err(CircuitError::Reset));
            assert_eq!(circuit.relay_hops_left(), 0);
        }
        let circuit = pair.get_mut(cid(2)).unwrap();
        let mut left = 8u8;
        for _ in 0..8 {
            left = circuit.forward_hop().unwrap();
        }
        assert_eq!(left, 0);
        assert_eq!(circuit.forward_hop(), Err(CircuitError::Reset));
    }

    #[test]
    fn offset_hole_reorder_overlap_and_duplicate_poison() {
        let mut pair = CircuitPair::new(1, 2, 4).unwrap();
        for n in 1..=4 {
            pair.open(cid(n), 8).unwrap();
        }
        {
            let circuit = pair.get_mut(cid(1)).unwrap();
            assert_eq!(circuit.accept(Direction::AtoB, 0, &[1, 2, 3, 4]), Ok(4));
            assert_eq!(circuit.accept(Direction::BtoA, 0, &[9]), Ok(1));
            circuit.push(Direction::AtoB, &[5, 5, 5]).unwrap();
            assert_eq!(
                circuit.accept(Direction::AtoB, 8, &[1]),
                Err(CircuitError::Reset)
            );
            assert!(circuit.is_poisoned(Direction::AtoB));
            assert!(!circuit.is_poisoned(Direction::BtoA));
            assert!(circuit.is_reset());
            assert_eq!(circuit.next_expected(Direction::AtoB), 4);
            assert_eq!(circuit.ciphertext_bytes(Direction::AtoB), 0);
            assert_eq!(
                circuit.accept(Direction::AtoB, 4, &[1]),
                Err(CircuitError::Reset)
            );
            assert_eq!(
                circuit.accept(Direction::BtoA, 1, &[1]),
                Err(CircuitError::Reset)
            );
            assert_eq!(
                circuit.push(Direction::AtoB, &[1]),
                Err(CircuitError::Reset)
            );
        }
        {
            let circuit = pair.get_mut(cid(2)).unwrap();
            assert_eq!(
                circuit.accept(Direction::AtoB, 5, b"abc"),
                Err(CircuitError::Reset)
            );
            assert_eq!(circuit.next_expected(Direction::AtoB), 0);
            assert_eq!(
                circuit.accept(Direction::AtoB, 0, b"abc"),
                Err(CircuitError::Reset)
            );
        }
        {
            let circuit = pair.get_mut(cid(3)).unwrap();
            assert_eq!(circuit.accept(Direction::AtoB, 0, &[0; 10]), Ok(10));
            assert_eq!(
                circuit.accept(Direction::AtoB, 6, &[1, 2, 3, 4]),
                Err(CircuitError::Reset)
            );
            assert_eq!(circuit.next_expected(Direction::AtoB), 10);
            assert_eq!(
                circuit.accept(Direction::AtoB, 10, &[1]),
                Err(CircuitError::Reset)
            );
        }
        {
            let circuit = pair.get_mut(cid(4)).unwrap();
            assert_eq!(circuit.accept(Direction::AtoB, 0, b"0123456789"), Ok(10));
            assert_eq!(
                circuit.accept(Direction::AtoB, 0, b"0123456789"),
                Err(CircuitError::Reset)
            );
            assert_eq!(
                circuit.accept(Direction::AtoB, 10, b"x"),
                Err(CircuitError::Reset)
            );
        }
    }

    #[test]
    fn ciphertext_backpressure_keeps_bytes_until_reset() {
        let mut pair = CircuitPair::new(1, 2, 1).unwrap();
        pair.open(cid(1), 8).unwrap();
        let circuit = pair.get_mut(cid(1)).unwrap();
        let full = vec![0xABu8; CIPHERTEXT_QUEUE_CAP];
        circuit.push(Direction::AtoB, &full).unwrap();
        let extra = [0xFFu8];
        assert_eq!(
            circuit.push(Direction::AtoB, &extra),
            Err(CircuitError::Backpressure)
        );
        assert_eq!(extra, [0xFF]);
        assert!(!circuit.is_reset());
        assert_eq!(
            circuit.ciphertext_bytes(Direction::AtoB),
            CIPHERTEXT_QUEUE_CAP
        );
        assert_eq!(circuit.ciphertext_chunks(Direction::AtoB), 1);
        assert_eq!(
            circuit
                .ciphertext_head(Direction::AtoB)
                .map(|chunk| chunk[0]),
            Some(0xAB)
        );
        assert_eq!(
            circuit.send_offset(Direction::AtoB),
            u64::try_from(CIPHERTEXT_QUEUE_CAP).unwrap()
        );
        let almost = vec![0x09u8; CIPHERTEXT_QUEUE_CAP - 1];
        circuit.push(Direction::BtoA, &almost).unwrap();
        assert_eq!(
            circuit.push(Direction::BtoA, &[1, 2]),
            Err(CircuitError::Backpressure)
        );
        assert_eq!(
            circuit.ciphertext_bytes(Direction::BtoA),
            CIPHERTEXT_QUEUE_CAP - 1
        );
        assert_eq!(
            circuit.send_offset(Direction::BtoA),
            u64::try_from(CIPHERTEXT_QUEUE_CAP - 1).unwrap()
        );
        circuit.push(Direction::BtoA, &[1]).unwrap();
        assert_eq!(
            circuit.push(Direction::BtoA, &[3]),
            Err(CircuitError::Backpressure)
        );
        assert_eq!(circuit.ciphertext_chunks(Direction::BtoA), 2);
        assert_eq!(circuit.push(Direction::BtoA, &[]), Err(CircuitError::Empty));
        assert_eq!(circuit.ciphertext_chunks(Direction::BtoA), 2);
        circuit.reset_circuit();
        assert!(circuit.is_reset());
        assert_eq!(circuit.ciphertext_bytes(Direction::AtoB), 0);
        assert_eq!(circuit.ciphertext_bytes(Direction::BtoA), 0);
        assert!(circuit.ciphertext_head(Direction::AtoB).is_none());
        assert_eq!(
            circuit.send_offset(Direction::AtoB),
            u64::try_from(CIPHERTEXT_QUEUE_CAP).unwrap()
        );
        assert_eq!(
            circuit.push(Direction::AtoB, &[1]),
            Err(CircuitError::Reset)
        );
        assert_eq!(
            circuit.push(Direction::BtoA, &[1]),
            Err(CircuitError::Reset)
        );
    }

    #[test]
    fn fifth_circuit_refused_and_default_cap_is_one() {
        assert_eq!(DEFAULT_PAIR_CAP, 1);
        assert_eq!(HARD_PAIR_CAP, 4);
        assert_eq!(
            CircuitPair::new(1, 2, 0).err(),
            Some(CircuitError::InvalidCap)
        );
        assert_eq!(
            CircuitPair::new(1, 2, 5).err(),
            Some(CircuitError::InvalidCap)
        );
        let mut one = CircuitPair::with_default_cap(2, 1).unwrap();
        assert_eq!(one.cap(), 1);
        one.open(cid(1), 8).unwrap();
        assert_eq!(one.open(cid(1), 8), Err(CircuitError::InvalidOpen));
        assert!(!one.get(cid(1)).unwrap().is_reset());
        assert_eq!(one.open(cid(2), 8), Err(CircuitError::TooMany));
        assert_eq!(one.len(), 1);
        let mut four = CircuitPair::new(3, 8, HARD_PAIR_CAP).unwrap();
        for n in 1..=4 {
            four.open(cid(n), 8).unwrap();
        }
        assert_eq!(four.open(cid(5), 8), Err(CircuitError::TooMany));
        assert_eq!(four.len(), 4);
        assert!(four.get(cid(1)).is_some());
        assert!(four.get(cid(5)).is_none());
        assert_eq!(four.open(cid(0), 8), Err(CircuitError::InvalidOpen));
    }

    #[test]
    fn pending_timeout_drops_new_datagram_without_hop_only() {
        assert_eq!(admit_pending(0, PENDING_PLAINTEXT_CAP, 0), Ok(()));
        assert_eq!(
            admit_pending(0, PENDING_PLAINTEXT_CAP + 1, 0),
            Err(CircuitError::PendingDrop)
        );
        assert_eq!(
            admit_pending(PENDING_PLAINTEXT_CAP, 1, 0),
            Err(CircuitError::PendingDrop)
        );
        assert_eq!(
            admit_pending(1, PENDING_PLAINTEXT_CAP, 0),
            Err(CircuitError::PendingDrop)
        );
        assert_eq!(admit_pending(PENDING_PLAINTEXT_CAP, 0, 1_999), Ok(()));
        assert_eq!(admit_pending(0, 1, 1_999), Ok(()));
        assert_eq!(admit_pending(0, 1, 2_000), Err(CircuitError::PendingDrop));
        assert_eq!(admit_pending(0, 1, 2_001), Err(CircuitError::PendingDrop));
        assert_eq!(
            admit_pending(usize::MAX, 1, 0),
            Err(CircuitError::PendingDrop)
        );
        let mut pending = PendingPlaintext::new();
        pending.admit(1_000, 0).unwrap();
        assert_eq!(
            pending.admit(PENDING_PLAINTEXT_CAP, 10),
            Err(CircuitError::PendingDrop)
        );
        assert_eq!(pending.queued(), 1_000);
        assert_eq!(pending.drops(), 1);
        assert_eq!(pending.admit(1, 2_000), Err(CircuitError::PendingDrop));
        assert_eq!(pending.queued(), 1_000);
        assert_eq!(pending.drops(), 2);
        let decision = admit_pending(0, 1, 2_000);
        match decision {
            Err(CircuitError::PendingDrop) => {}
            Ok(()) => panic!("timeout must not admit or fall back to hop-only"),
            Err(
                CircuitError::Reset
                | CircuitError::Backpressure
                | CircuitError::TooMany
                | CircuitError::EqualNodes
                | CircuitError::InvalidCap
                | CircuitError::InvalidOpen
                | CircuitError::Empty,
            ) => panic!("pending refusal must not change mode"),
        }
    }
}
