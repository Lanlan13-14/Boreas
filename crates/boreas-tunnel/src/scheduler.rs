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
