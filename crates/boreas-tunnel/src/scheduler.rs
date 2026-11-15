//! Bounded byte-quantum DRR plus FIFO age shedding. This is not RFC 8290
//! FQ-CoDel: it has no hash-based flow classifier, CoDel control law, ECN, or
//! packet scheduler integration. Ciphertext is never silently dropped here;
//! queue-age/size failures ask the caller to reset the logical flow/circuit.
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub max_flows: usize,
    pub max_packets: usize,
    pub max_bytes: usize,
    pub quantum_bytes: usize,
    pub max_queue_age: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueError {
    TooManyFlows,
    PacketTooLarge,
    QueueFull,
    QueueAgeExceeded,
    EmptyItem,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerConfigError {
    ZeroFlowLimit,
    ZeroPacketLimit,
    ZeroByteLimit,
    ZeroQuantum,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DequeueError {
    QueueAgeExceeded { flow_id: usize },
}
#[derive(Debug, Eq, PartialEq)]
pub enum DequeueResult<T> {
    Empty,
    PendingCredit,
    Item(T),
}
struct Item<T> {
    value: T,
    bytes: usize,
    enqueued: Instant,
}
struct Flow<T> {
    queue: VecDeque<Item<T>>,
    deficit: usize,
}
/// FIFO within each flow, deficit round-robin across flows. `PendingCredit`
/// means backlog remains but no head item had enough deficit during this bounded
/// pass; the caller MUST reschedule dequeue (without waiting for new arrivals).
pub struct DrrScheduler<T> {
    config: SchedulerConfig,
    flows: HashMap<usize, Flow<T>>,
    active: VecDeque<usize>,
    packet_count: usize,
    byte_count: usize,
}
impl<T> DrrScheduler<T> {
    pub fn new(config: SchedulerConfig) -> Result<Self, SchedulerConfigError> {
        if config.max_flows == 0 {
            return Err(SchedulerConfigError::ZeroFlowLimit);
        }
        if config.max_packets == 0 {
            return Err(SchedulerConfigError::ZeroPacketLimit);
        }
        if config.max_bytes == 0 {
            return Err(SchedulerConfigError::ZeroByteLimit);
        }
        if config.quantum_bytes == 0 {
            return Err(SchedulerConfigError::ZeroQuantum);
        }
        Ok(Self {
            config,
            flows: HashMap::new(),
            active: VecDeque::new(),
            packet_count: 0,
            byte_count: 0,
        })
    }
    pub fn queued_packets(&self) -> usize {
        self.packet_count
    }
    pub fn queued_bytes(&self) -> usize {
        self.byte_count
    }

    pub fn enqueue(
        &mut self,
        flow_id: usize,
        value: T,
        bytes: usize,
        now: Instant,
    ) -> Result<(), EnqueueError> {
        if bytes == 0 {
            return Err(EnqueueError::EmptyItem);
        }
        if bytes > self.config.max_bytes {
            return Err(EnqueueError::PacketTooLarge);
        }
        if self.packet_count >= self.config.max_packets
            || self
                .byte_count
                .checked_add(bytes)
                .is_none_or(|n| n > self.config.max_bytes)
        {
            return Err(EnqueueError::QueueFull);
        }
        if flow_id >= self.config.max_flows {
            return Err(EnqueueError::TooManyFlows);
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = self.flows.entry(flow_id) {
            entry.insert(Flow {
                queue: VecDeque::new(),
                deficit: 0,
            });
            self.active.push_back(flow_id);
        }
        let flow = self.flows.get_mut(&flow_id).expect("flow inserted");
        if flow.queue.front().is_some_and(|item| {
            now.saturating_duration_since(item.enqueued) > self.config.max_queue_age
        }) {
            return Err(EnqueueError::QueueAgeExceeded);
        }
        flow.queue.push_back(Item {
            value,
            bytes,
            enqueued: now,
        });
        self.packet_count += 1;
        self.byte_count += bytes;
        Ok(())
    }

    /// Returns an expired flow ID instead of discarding its ciphertext. The
    /// caller must reset/close that flow and then explicitly purge its queue.
    pub fn dequeue(&mut self, now: Instant) -> Result<DequeueResult<(usize, T)>, DequeueError> {
        let mut rounds = self.active.len();
        let mut pending_credit = false;
        while rounds > 0 {
            rounds -= 1;
            let Some(flow_id) = self.active.pop_front() else {
                break;
            };
            let flow = self.flows.get_mut(&flow_id).expect("active flow exists");
            if flow.queue.front().is_some_and(|item| {
                now.saturating_duration_since(item.enqueued) > self.config.max_queue_age
            }) {
                self.active.push_front(flow_id);
                return Err(DequeueError::QueueAgeExceeded { flow_id });
            }
            flow.deficit = flow.deficit.saturating_add(self.config.quantum_bytes);
            if let Some(item) = flow.queue.pop_front_if(|item| item.bytes <= flow.deficit) {
                flow.deficit -= item.bytes;
                self.packet_count -= 1;
                self.byte_count -= item.bytes;
                let flow_is_empty = flow.queue.is_empty();
                if flow_is_empty {
                    self.flows.remove(&flow_id);
                } else {
                    self.active.push_back(flow_id);
                }
                return Ok(DequeueResult::Item((flow_id, item.value)));
            }
            pending_credit = true;
            self.active.push_back(flow_id);
        }
        Ok(if pending_credit {
            DequeueResult::PendingCredit
        } else {
            DequeueResult::Empty
        })
    }

    /// Explicit reset cleanup. Call only after the transport owner has selected
    /// a reset policy; returned items are not treated as successful deliveries.
    pub fn purge_flow(&mut self, flow_id: usize) -> Vec<T> {
        let Some(flow) = self.flows.remove(&flow_id) else {
            return Vec::new();
        };
        self.active.retain(|id| *id != flow_id);
        self.packet_count -= flow.queue.len();
        self.byte_count -= flow.queue.iter().map(|i| i.bytes).sum::<usize>();
        flow.queue.into_iter().map(|i| i.value).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> SchedulerConfig {
        SchedulerConfig {
            max_flows: 8,
            max_packets: 10,
            max_bytes: 100,
            quantum_bytes: 10,
            max_queue_age: Duration::from_secs(2),
        }
    }
    #[test]
    fn drr_serves_flows_and_preserves_per_flow_fifo() {
        let mut s = DrrScheduler::new(config()).unwrap();
        let t = Instant::now();
        s.enqueue(0, "a", 10, t).unwrap();
        s.enqueue(0, "b", 10, t).unwrap();
        s.enqueue(1, "c", 10, t).unwrap();
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::Item((0, "a")));
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::Item((1, "c")));
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::Item((0, "b")));
    }
    #[test]
    fn pending_credit_is_distinct_from_empty_and_requires_reschedule() {
        let mut cfg = config();
        cfg.quantum_bytes = 5;
        let mut s = DrrScheduler::new(cfg).unwrap();
        let t = Instant::now();
        s.enqueue(0, "large", 12, t).unwrap();
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::PendingCredit);
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::PendingCredit);
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::Item((0, "large")));
        assert_eq!(s.dequeue(t).unwrap(), DequeueResult::Empty);
    }
    #[test]
    fn rejects_invalid_zero_quantum() {
        let mut cfg = config();
        cfg.quantum_bytes = 0;
        assert_eq!(
            DrrScheduler::<()>::new(cfg).err(),
            Some(SchedulerConfigError::ZeroQuantum)
        );
    }
    #[test]
    fn rejects_zero_byte_metadata_entries() {
        let mut s = DrrScheduler::<()>::new(config()).unwrap();
        assert_eq!(
            s.enqueue(0, (), 0, Instant::now()),
            Err(EnqueueError::EmptyItem)
        );
        assert_eq!(s.queued_packets(), 0);
    }
    #[test]
    fn aged_ciphertext_requires_explicit_purge() {
        let mut s = DrrScheduler::new(config()).unwrap();
        let t = Instant::now();
        s.enqueue(3, vec![1, 2, 3], 3, t).unwrap();
        assert_eq!(
            s.dequeue(t + Duration::from_secs(3)),
            Err(DequeueError::QueueAgeExceeded { flow_id: 3 })
        );
        assert_eq!(s.purge_flow(3), vec![vec![1, 2, 3]]);
        assert_eq!(s.queued_bytes(), 0);
    }
}

/// Admission failure for [`ClassBudget`], [`chunk_limit`], and [`serialization_us`].
///
/// These helpers are local integer rules. They are not an RFC 8290 FQ-CoDel
/// implementation and they are not a `G-PERF` measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedError {
    /// Packet cap or byte cap was zero.
    ZeroCap,
    /// Control packet counter is already at the pps cap.
    PacketCap,
    /// Adding this packet would pass the Control byte cap.
    ByteCap,
    /// A zero-length Control admission is rejected and consumes nothing.
    Empty,
    /// A rate argument was zero.
    ZeroRate,
    /// `chunk_limit`'s `target_ms` was zero.
    ZeroTarget,
    /// The product does not fit in `u64`. This is not a chunk of `u64::MAX`.
    Overflow,
}

/// Independent packet and byte counters for the Control class only.
///
/// Data-class traffic does not call [`Self::admit_control`] and is not limited
/// by either counter. A port-priority queue (Control before Data, or a queue
/// keyed only by port) is not RFC 8290 FQ-CoDel: that RFC hashes flows and runs
/// a CoDel control law on each queue. This type is only a dual cap.
///
/// Counting these admissions is not a `G-PERF` latency result.
#[derive(Debug)]
pub struct ClassBudget {
    pps_cap: u64,
    byte_cap: u64,
    packets: u64,
    bytes_used: u64,
}

impl ClassBudget {
    /// `pps_cap` and `byte_cap` must each be at least 1.
    pub fn new(pps_cap: u64, byte_cap: u64) -> Result<Self, SchedError> {
        if pps_cap == 0 || byte_cap == 0 {
            return Err(SchedError::ZeroCap);
        }
        Ok(Self {
            pps_cap,
            byte_cap,
            packets: 0,
            bytes_used: 0,
        })
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    /// Admit one Control packet.
    ///
    /// Rejects when the packet counter is already at the pps cap, or when
    /// `bytes` would make the byte counter exceed the byte cap. A rejection
    /// increments neither counter.
    pub fn admit_control(&mut self, bytes: usize) -> Result<(), SchedError> {
        if self.packets >= self.pps_cap {
            return Err(SchedError::PacketCap);
        }
        if bytes == 0 {
            return Err(SchedError::Empty);
        }
        let add = bytes as u64;
        let Some(next) = self.bytes_used.checked_add(add) else {
            return Err(SchedError::Overflow);
        };
        if next > self.byte_cap {
            return Err(SchedError::ByteCap);
        }
        self.packets += 1;
        self.bytes_used = next;
        Ok(())
    }
}

/// What to do with a ciphertext stream after an unrecoverable queue loss.
///
/// [`CipherAction::Keep`] is not a legal response to that loss. This module
/// has no function that discards one ciphertext chunk and returns `Keep`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherAction {
    Keep,
    ResetStream,
}

/// What to do with one plaintext L3 datagram that does not fit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L3Action {
    DropDatagram,
}

/// Ciphertext loss rebuilds the security stream. It does not drop one record
/// and continue. Not FQ-CoDel, and not a `G-PERF` result.
pub fn on_ciphertext_loss() -> CipherAction {
    CipherAction::ResetStream
}

/// Plaintext L3 overflow drops that datagram so congestion can propagate.
/// The return type is not [`CipherAction`]; callers cannot mix the two policies.
pub fn on_plaintext_overflow() -> L3Action {
    L3Action::DropDatagram
}

/// Chunk size in bytes: `rate_bytes_per_sec * target_ms / 1000`.
///
/// A product that overflows `u64` returns [`SchedError::Overflow`]. It does not
/// saturate to `u64::MAX` and present that value as a chunk. Integer division
/// truncates. This is planning arithmetic, not `G-PERF`.
pub fn chunk_limit(rate_bytes_per_sec: u64, target_ms: u64) -> Result<u64, SchedError> {
    if rate_bytes_per_sec == 0 {
        return Err(SchedError::ZeroRate);
    }
    if target_ms == 0 {
        return Err(SchedError::ZeroTarget);
    }
    let product = rate_bytes_per_sec
        .checked_mul(target_ms)
        .ok_or(SchedError::Overflow)?;
    Ok(product / 1000)
}

/// Serialization delay in microseconds: `bytes * 8 * 1_000_000 / bits_per_sec`.
///
/// Integer division truncates a fractional microsecond toward zero. It does not
/// round to nearest. 65536 bytes is 524288 bits; at `1_000_000_000` bits/s that
/// is 524.288 µs, so the result is 524, not 525. Not a `G-PERF` measurement.
pub fn serialization_us(bytes: u64, bits_per_sec: u64) -> Result<u64, SchedError> {
    if bits_per_sec == 0 {
        return Err(SchedError::ZeroRate);
    }
    let bit_microseconds = bytes.checked_mul(8_000_000).ok_or(SchedError::Overflow)?;
    Ok(bit_microseconds / bits_per_sec)
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    #[test]
    fn control_packet_cap_reached_while_byte_cap_remains() {
        let mut budget = ClassBudget::new(1, 10_000).unwrap();
        budget.admit_control(100).unwrap();
        assert_eq!(budget.admit_control(100), Err(SchedError::PacketCap));
        assert_eq!(budget.packets(), 1);
        assert_eq!(budget.bytes_used(), 100);
        assert!(budget.bytes_used() < 10_000);
    }

    #[test]
    fn control_byte_cap_reached_while_packet_cap_remains() {
        let mut budget = ClassBudget::new(100, 50).unwrap();
        budget.admit_control(40).unwrap();
        assert_eq!(budget.admit_control(20), Err(SchedError::ByteCap));
        assert_eq!(budget.packets(), 1);
        assert_eq!(budget.bytes_used(), 40);
        assert!(budget.packets() < 100);
    }

    #[test]
    fn reject_does_not_consume_either_counter() {
        let mut budget = ClassBudget::new(2, 30).unwrap();
        assert_eq!(budget.admit_control(31), Err(SchedError::ByteCap));
        assert_eq!(budget.packets(), 0);
        assert_eq!(budget.bytes_used(), 0);
        budget.admit_control(30).unwrap();
        assert_eq!(budget.admit_control(1), Err(SchedError::ByteCap));
        assert_eq!(budget.packets(), 1);
        assert_eq!(budget.bytes_used(), 30);
        assert_eq!(budget.admit_control(0), Err(SchedError::Empty));
        assert_eq!(budget.packets(), 1);
        assert_eq!(budget.bytes_used(), 30);
    }

    #[test]
    fn ciphertext_loss_resets_stream_and_plaintext_overflow_drops() {
        fn cipher_only(action: CipherAction) -> CipherAction {
            action
        }
        fn l3_only(action: L3Action) -> L3Action {
            action
        }
        assert_eq!(cipher_only(on_ciphertext_loss()), CipherAction::ResetStream);
        assert_ne!(on_ciphertext_loss(), CipherAction::Keep);
        assert_eq!(l3_only(on_plaintext_overflow()), L3Action::DropDatagram);
    }

    #[test]
    fn ten_megabit_one_millisecond_chunk_is_1250_bytes() {
        // 10_000_000 bits/s = 1_250_000 bytes/s; a 1 ms target yields 1250 bytes.
        let rate_bytes_per_sec = 10_000_000 / 8;
        assert_eq!(rate_bytes_per_sec, 1_250_000);
        assert_eq!(chunk_limit(rate_bytes_per_sec, 1).unwrap(), 1250);
    }

    #[test]
    fn sixty_four_kib_at_one_gigabit_truncates_to_524_us() {
        // 65536 bytes = 524288 bits. 524288 / 1e9 s = 524.288 us.
        // Integer microseconds truncate toward zero: 524, not 525.
        assert_eq!(serialization_us(65_536, 1_000_000_000).unwrap(), 524);
        assert_ne!(serialization_us(65_536, 1_000_000_000).unwrap(), 525);
    }

    #[test]
    fn zero_rate_rejected() {
        assert_eq!(chunk_limit(0, 1), Err(SchedError::ZeroRate));
        assert_eq!(chunk_limit(1_250_000, 0), Err(SchedError::ZeroTarget));
        assert_eq!(serialization_us(65_536, 0), Err(SchedError::ZeroRate));
        assert_eq!(chunk_limit(u64::MAX, 1_000), Err(SchedError::Overflow));
        assert_ne!(chunk_limit(u64::MAX, 1_000), Ok(u64::MAX));
    }

    #[test]
    fn caps_must_be_at_least_one() {
        assert_eq!(ClassBudget::new(0, 1).err(), Some(SchedError::ZeroCap));
        assert_eq!(ClassBudget::new(1, 0).err(), Some(SchedError::ZeroCap));
    }
}
