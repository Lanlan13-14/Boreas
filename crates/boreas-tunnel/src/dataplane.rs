//! In-process hop data plane between two logical VirtualTun-shaped endpoints.
//!
//! Packets move from an ingress [`HopTun`] to an egress [`HopTun`] across a
//! bounded set of logical flows. Loss, reset, and reorder are counted, and
//! delivered payloads are hashed. This is **not** TLS, **not** an L3
//! authorization check, and **not** evidence that `G-DATA`, `G-FRAME`, or
//! `G-CRYPTO` passed.
//!
//! [`HopTun`] is a pure in-memory FIFO with the same fail-closed shape as
//! `boreas_tun::VirtualTun` (empty, oversized, full). It is **not** that type
//! and does **not** call it: linking `boreas-tun` would change the default
//! workspace build. This module does **not** open a real TUN device, does
//! **not** call `LinuxTun`, and does **not** fall back to a plaintext network
//! path. A length check is not an IP parse and is not an authorization decision.
//!
//! Fail closed: empty, oversized, over-budget, unknown, closed, reset, and
//! out-of-order deliveries are rejected. Reset discards queued bytes and those
//! bytes are excluded from the delivered payload hash.

use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Logical flow identifier. Uniqueness is enforced by [`DataPlane::open_flow`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowId(pub u64);

/// Recoverable data-plane rejection. None of these variants authorize a
/// plaintext fallback or a retry that skips the failed check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataError {
    Empty,
    TooLarge,
    QueueFull,
    FlowLimit,
    Closed,
    Reset,
    Reorder,
    HashMismatch,
    Budget,
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty packet",
            Self::TooLarge => "packet exceeds max_packet",
            Self::QueueFull => "per-flow queue is full",
            Self::FlowLimit => "flow table is full or the flow id is already open",
            Self::Closed => "flow is closed",
            Self::Reset => "flow was reset",
            Self::Reorder => "delivery offset is not the next expected offset",
            Self::HashMismatch => "delivered payload hash does not match",
            Self::Budget => "configuration or byte budget is invalid or exhausted",
        })
    }
}

impl std::error::Error for DataError {}

/// Hard bounds for one single-owner data plane.
///
/// `max_flows * queue_packets * max_packet` must not overflow `usize`.
/// `max_packet` is capped at the IPv4/IPv6 maximum datagram length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneConfig {
    pub max_flows: usize,
    pub max_packet: usize,
    pub queue_packets: usize,
    pub max_bytes: usize,
}

impl DataPlaneConfig {
    pub fn validate(self) -> Result<Self, DataError> {
        if self.max_flows == 0
            || self.max_packet == 0
            || self.queue_packets == 0
            || self.max_bytes == 0
            || self.max_packet > 65_535
        {
            return Err(DataError::Budget);
        }
        // The queue-dimension product must be representable. `max_bytes` is an
        // independent finite cap and may be smaller than that product.
        self.queue_packets
            .checked_mul(self.max_packet)
            .and_then(|per_flow| self.max_flows.checked_mul(per_flow))
            .ok_or(DataError::Budget)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowState {
    Open,
    /// New enqueue is refused; already queued packets may still be delivered.
    Closed,
    /// Queue was discarded. Later enqueue and deliver are refused.
    Reset,
}

struct Flow {
    state: FlowState,
    queue: VecDeque<Vec<u8>>,
    /// Next delivery offset. Starts at 0 and advances by 1 per delivered packet.
    next_offset: u64,
}

/// Counters for one data plane. Resets are losses, not deliveries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPlaneStats {
    pub enqueued_packets: u64,
    pub delivered_packets: u64,
    pub dropped_resets: u64,
    pub reorders: u64,
    pub bytes_enqueued: u64,
    pub bytes_delivered: u64,
}

struct HopPacket {
    flow: FlowId,
    bytes: Vec<u8>,
}

/// In-process stand-in for one direction of a `boreas_tun::VirtualTun` pair.
///
/// The queue is a bounded FIFO. A full endpoint returns [`DataError::QueueFull`]
/// and never silently drops or opens another path. There is no device fd.
struct HopTun {
    queue: VecDeque<HopPacket>,
    max_packet: usize,
    capacity: usize,
}

impl HopTun {
    fn new(max_packet: usize, capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_packet,
            capacity,
        }
    }

    fn push(&mut self, flow: FlowId, packet: &[u8]) -> Result<(), DataError> {
        if packet.is_empty() {
            return Err(DataError::Empty);
        }
        if packet.len() > self.max_packet {
            return Err(DataError::TooLarge);
        }
        if self.queue.len() >= self.capacity {
            return Err(DataError::QueueFull);
        }
        self.queue.push_back(HopPacket {
            flow,
            bytes: packet.to_vec(),
        });
        Ok(())
    }

    fn pop(&mut self) -> Option<HopPacket> {
        self.queue.pop_front()
    }

    /// Pop the oldest packet that belongs to `flow`, leaving other flows in order.
    fn pop_flow(&mut self, flow: FlowId) -> Option<HopPacket> {
        let index = self.queue.iter().position(|packet| packet.flow == flow)?;
        self.queue.remove(index)
    }

    /// Drop every still-queued hop packet for `flow`. Other flows stay in order.
    fn discard_flow(&mut self, flow: FlowId) -> usize {
        let before = self.queue.len();
        self.queue.retain(|packet| packet.flow != flow);
        before - self.queue.len()
    }
}

/// Single-owner hop plane. Callers share it by `&mut self`; there is no lock.
///
/// Ingress and egress are a [`HopTun`] pair standing in for two VirtualTun
/// endpoints. Crossing them is the hop. Per-flow FIFOs bound how many packets
/// may wait between the two ends.
pub struct DataPlane {
    config: DataPlaneConfig,
    flows: HashMap<FlowId, Flow>,
    stats: DataPlaneStats,
    /// SHA-256 over delivered packet bytes in delivery order.
    hash: Sha256,
    ingress: HopTun,
    egress: HopTun,
    /// Bytes currently sitting in per-flow queues (not yet delivered or reset).
    queued_bytes: usize,
}

impl DataPlane {
    pub fn new(config: DataPlaneConfig) -> Result<Self, DataError> {
        let config = config.validate()?;
        // One in-flight packet per budgeted byte is the smallest packet that
        // can still be charged. These are not Linux TUN devices.
        let slots = config.max_bytes;
        Ok(Self {
            ingress: HopTun::new(config.max_packet, slots),
            egress: HopTun::new(config.max_packet, slots),
            config,
            flows: HashMap::new(),
            stats: DataPlaneStats::default(),
            hash: Sha256::new(),
            queued_bytes: 0,
        })
    }

    pub fn snapshot(&self) -> DataPlaneStats {
        self.stats
    }

    /// SHA-256 of the concatenation of delivered packet payloads, in order.
    /// Reset (discarded) bytes are not included.
    pub fn delivered_hash(&self) -> [u8; 32] {
        self.hash.clone().finalize()
    }

    pub fn open_flow(&mut self, id: FlowId) -> Result<(), DataError> {
        if self.flows.contains_key(&id) {
            return Err(DataError::FlowLimit);
        }
        if self.flows.len() >= self.config.max_flows {
            return Err(DataError::FlowLimit);
        }
        self.flows.insert(
            id,
            Flow {
                state: FlowState::Open,
                queue: VecDeque::new(),
                next_offset: 0,
            },
        );
        Ok(())
    }

    /// Enqueue one opaque packet on an open flow.
    ///
    /// The only structural check is non-empty and `len <= max_packet`. This
    /// does **not** parse an IP header and does **not** authorize the packet.
    pub fn enqueue(&mut self, id: FlowId, packet: &[u8]) -> Result<(), DataError> {
        if packet.is_empty() {
            return Err(DataError::Empty);
        }
        if packet.len() > self.config.max_packet {
            return Err(DataError::TooLarge);
        }
        let flow = self.flows.get(&id).ok_or(DataError::Closed)?;
        match flow.state {
            FlowState::Closed => return Err(DataError::Closed),
            FlowState::Reset => return Err(DataError::Reset),
            FlowState::Open => {}
        }
        if flow.queue.len() >= self.config.queue_packets {
            return Err(DataError::QueueFull);
        }
        let next_queued = self
            .queued_bytes
            .checked_add(packet.len())
            .ok_or(DataError::Budget)?;
        if next_queued > self.config.max_bytes {
            return Err(DataError::Budget);
        }
        // Move the bytes ingress then egress before admitting them to the
        // per-flow FIFO. A failed push leaves accounting unchanged. This is a
        // length-bounded copy, not an IP parse and not an L3 authorization.
        self.ingress.push(id, packet)?;
        let Some(hopped) = self.ingress.pop() else {
            return Err(DataError::Budget);
        };
        if hopped.flow != id || hopped.bytes.as_slice() != packet {
            return Err(DataError::HashMismatch);
        }
        self.egress.push(hopped.flow, &hopped.bytes)?;
        let flow = self.flows.get_mut(&id).ok_or(DataError::Closed)?;
        flow.queue.push_back(hopped.bytes);
        self.queued_bytes = next_queued;
        self.stats.enqueued_packets = self.stats.enqueued_packets.saturating_add(1);
        self.stats.bytes_enqueued = self
            .stats
            .bytes_enqueued
            .saturating_add(u64::try_from(packet.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Stop new enqueue. Already queued packets remain deliverable.
    pub fn close_flow(&mut self, id: FlowId) -> Result<(), DataError> {
        let flow = self.flows.get_mut(&id).ok_or(DataError::Closed)?;
        match flow.state {
            FlowState::Reset => Err(DataError::Reset),
            FlowState::Closed | FlowState::Open => {
                flow.state = FlowState::Closed;
                Ok(())
            }
        }
    }

    /// Discard every queued packet on `id` and refuse later enqueue.
    /// Discarded packets increment `dropped_resets` and never enter the hash.
    pub fn reset_flow(&mut self, id: FlowId) -> Result<(), DataError> {
        let flow = self.flows.get_mut(&id).ok_or(DataError::Closed)?;
        if flow.state == FlowState::Reset {
            return Err(DataError::Reset);
        }
        let dropped = flow.queue.len();
        let dropped_bytes: usize = flow.queue.iter().map(Vec::len).sum();
        flow.queue.clear();
        flow.state = FlowState::Reset;
        // The same packets sit on the egress endpoint. Remove only this flow
        // so a surviving flow cannot observe the reset bytes.
        let hopped = self.egress.discard_flow(id);
        if hopped != dropped {
            return Err(DataError::HashMismatch);
        }
        self.queued_bytes = self.queued_bytes.saturating_sub(dropped_bytes);
        self.stats.dropped_resets = self
            .stats
            .dropped_resets
            .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Deliver the next FIFO packet, using the flow's next expected offset.
    pub fn deliver(&mut self, id: FlowId) -> Result<Option<Vec<u8>>, DataError> {
        let next = self.flows.get(&id).ok_or(DataError::Closed)?.next_offset;
        self.deliver_at(id, next)
    }

    /// Deliver only when `offset` is the next expected index (starts at 0).
    /// A mismatch returns [`DataError::Reorder`] and neither delivers nor skips.
    pub fn deliver_at(&mut self, id: FlowId, offset: u64) -> Result<Option<Vec<u8>>, DataError> {
        let flow = self.flows.get_mut(&id).ok_or(DataError::Closed)?;
        if flow.state == FlowState::Reset {
            return Err(DataError::Reset);
        }
        if offset != flow.next_offset {
            self.stats.reorders = self.stats.reorders.saturating_add(1);
            return Err(DataError::Reorder);
        }
        if flow.queue.is_empty() {
            return Ok(None);
        }
        // Reserve the next offset before the packet leaves the queue so a
        // budget overflow cannot both pop and refuse.
        let next = flow.next_offset.checked_add(1).ok_or(DataError::Budget)?;
        let packet = flow.queue.pop_front().ok_or(DataError::Budget)?;
        flow.next_offset = next;
        // The matching buffer has been on the egress endpoint since enqueue.
        // Popping it completes the hop. A mismatch fails closed and is not hashed.
        let Some(out) = self.egress.pop_flow(id) else {
            return Err(DataError::Budget);
        };
        if out.flow != id || out.bytes.as_slice() != packet.as_slice() {
            return Err(DataError::HashMismatch);
        }
        let out = out.bytes;
        self.queued_bytes = self.queued_bytes.saturating_sub(out.len());
        self.hash.update(&out);
        self.stats.delivered_packets = self.stats.delivered_packets.saturating_add(1);
        self.stats.bytes_delivered = self
            .stats
            .bytes_delivered
            .saturating_add(u64::try_from(out.len()).unwrap_or(u64::MAX));
        Ok(Some(out))
    }
}

/// Counts and the SHA-256 of surviving delivered bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReport {
    pub stats: DataPlaneStats,
    pub delivered_hash: [u8; 32],
    pub delivered: Vec<Vec<u8>>,
}

/// Split `src_packets` round-robin across `flows`, reset the listed flow
/// indexes after enqueue and before deliver, then deliver survivors in flow
/// order (flow 0 fully, then flow 1, ...).
///
/// Reset flows contribute neither packets nor bytes to `delivered_hash`.
/// This helper is an in-process unit surface only. It does not transfer 1 GiB,
/// does not open `LinuxTun`, and does not satisfy `G-DATA`.
pub fn transfer_all(
    src_packets: &[Vec<u8>],
    flows: usize,
    drop_flow_indexes: &[usize],
) -> Result<TransferReport, DataError> {
    if flows == 0 || drop_flow_indexes.iter().any(|index| *index >= flows) {
        return Err(DataError::Budget);
    }
    let max_packet = src_packets
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(1)
        .clamp(1, 65_535);
    let queue_packets = src_packets.len().max(1);
    let max_bytes = src_packets
        .iter()
        .map(Vec::len)
        .try_fold(0usize, |acc, n| acc.checked_add(n))
        .ok_or(DataError::Budget)?
        .max(1);
    let plane_cfg = DataPlaneConfig {
        max_flows: flows,
        max_packet,
        queue_packets,
        max_bytes,
    };
    let mut plane = DataPlane::new(plane_cfg)?;
    for index in 0..flows {
        plane.open_flow(FlowId(u64::try_from(index).map_err(|_| DataError::Budget)?))?;
    }
    for (index, packet) in src_packets.iter().enumerate() {
        let flow = index % flows;
        plane.enqueue(
            FlowId(u64::try_from(flow).map_err(|_| DataError::Budget)?),
            packet,
        )?;
    }
    for index in drop_flow_indexes {
        plane.reset_flow(FlowId(
            u64::try_from(*index).map_err(|_| DataError::Budget)?,
        ))?;
    }
    let mut delivered = Vec::new();
    for index in 0..flows {
        if drop_flow_indexes.contains(&index) {
            continue;
        }
        let id = FlowId(u64::try_from(index).map_err(|_| DataError::Budget)?);
        while let Some(packet) = plane.deliver(id)? {
            delivered.push(packet);
        }
    }
    Ok(TransferReport {
        stats: plane.snapshot(),
        delivered_hash: plane.delivered_hash(),
        delivered,
    })
}

/// SHA-256 (FIPS 180-4) of `bytes`. This is a compact, dependency-free digest
/// for payload accounting. It is not a MAC and not a substitute for TLS.
pub fn payload_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    /// Total message bytes, not including padding.
    bits_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H0,
            buffer: [0; 64],
            buffered: 0,
            bits_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.bits_len = self
            .bits_len
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .expect("sha256 length fits in u64 for in-process payloads");
        self.absorb(data);
    }

    /// Feed bytes into the compression function without changing `bits_len`.
    fn absorb(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let need = 64 - self.buffered;
            if data.len() < need {
                self.buffer[self.buffered..self.buffered + data.len()].copy_from_slice(data);
                self.buffered += data.len();
                return;
            }
            self.buffer[self.buffered..].copy_from_slice(&data[..need]);
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffered = 0;
            data = &data[need..];
        }
        while data.len() >= 64 {
            let block = &data[..64];
            compress(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.bits_len.saturating_mul(8);
        let mut tail = [0u8; 128];
        tail[0] = 0x80;
        let pad_len = if self.buffered < 56 {
            56 - self.buffered
        } else {
            64 + 56 - self.buffered
        };
        tail[pad_len..pad_len + 8].copy_from_slice(&bit_len.to_be_bytes());
        self.absorb(&tail[..pad_len + 8]);
        let mut out = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            let start = index * 4;
            out[start..start + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut schedule = [0u32; 64];
    for (index, word) in schedule.iter_mut().enumerate().take(16) {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_flows: usize, queue_packets: usize, max_bytes: usize) -> DataPlaneConfig {
        DataPlaneConfig {
            max_flows,
            max_packet: 64,
            queue_packets,
            max_bytes,
        }
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha256_empty_and_abc() {
        let empty = payload_hash(b"");
        assert_eq!(
            hex32(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = payload_hash(b"abc");
        assert_eq!(
            hex32(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = payload_hash(&[0x61u8; 70]);
        let mut split = Sha256::new();
        split.update(&[0x61u8; 40]);
        split.update(&[0x61u8; 30]);
        assert_eq!(split.finalize(), long);
    }

    #[test]
    fn rejects_empty_oversized_queue_full_and_flow_limit() {
        let mut plane = DataPlane::new(cfg(1, 1, 64)).unwrap();
        assert_eq!(plane.open_flow(FlowId(1)), Ok(()));
        assert_eq!(plane.open_flow(FlowId(1)), Err(DataError::FlowLimit));
        assert_eq!(plane.open_flow(FlowId(2)), Err(DataError::FlowLimit));
        assert_eq!(plane.enqueue(FlowId(1), b""), Err(DataError::Empty));
        assert_eq!(
            plane.enqueue(FlowId(1), &[0u8; 65]),
            Err(DataError::TooLarge)
        );
        plane.enqueue(FlowId(1), b"ab").unwrap();
        assert_eq!(plane.enqueue(FlowId(1), b"cd"), Err(DataError::QueueFull));
        assert_eq!(plane.snapshot().enqueued_packets, 1);

        let mut tight = DataPlane::new(cfg(1, 4, 3)).unwrap();
        tight.open_flow(FlowId(7)).unwrap();
        tight.enqueue(FlowId(7), b"ab").unwrap();
        assert_eq!(tight.enqueue(FlowId(7), b"cd"), Err(DataError::Budget));
    }

    #[test]
    fn reorder_does_not_deliver_or_skip() {
        let mut plane = DataPlane::new(cfg(1, 4, 64)).unwrap();
        plane.open_flow(FlowId(0)).unwrap();
        plane.enqueue(FlowId(0), b"one").unwrap();
        plane.enqueue(FlowId(0), b"two").unwrap();
        assert_eq!(plane.deliver_at(FlowId(0), 1), Err(DataError::Reorder));
        assert_eq!(plane.snapshot().reorders, 1);
        assert_eq!(plane.snapshot().delivered_packets, 0);
        assert_eq!(plane.deliver_at(FlowId(0), 0).unwrap().unwrap(), b"one");
        assert_eq!(plane.deliver(FlowId(0)).unwrap().unwrap(), b"two");
        assert_eq!(plane.deliver(FlowId(0)).unwrap(), None);
        assert_eq!(plane.snapshot().delivered_packets, 2);
    }

    #[test]
    fn reset_bytes_are_excluded_from_delivered_hash() {
        let mut plane = DataPlane::new(cfg(2, 4, 256)).unwrap();
        plane.open_flow(FlowId(0)).unwrap();
        plane.open_flow(FlowId(1)).unwrap();
        plane.enqueue(FlowId(0), b"keep").unwrap();
        plane.enqueue(FlowId(1), b"drop-me").unwrap();
        plane.enqueue(FlowId(1), b"also").unwrap();
        plane.reset_flow(FlowId(1)).unwrap();
        assert_eq!(plane.enqueue(FlowId(1), b"nope"), Err(DataError::Reset));
        assert_eq!(plane.deliver(FlowId(1)), Err(DataError::Reset));
        let kept = plane.deliver(FlowId(0)).unwrap().unwrap();
        assert_eq!(kept, b"keep");
        assert_eq!(plane.snapshot().dropped_resets, 2);
        assert_eq!(plane.delivered_hash(), payload_hash(b"keep"));
        assert_ne!(plane.delivered_hash(), payload_hash(b"keepdrop-mealso"));
    }

    #[test]
    fn close_stops_enqueue_but_drains() {
        let mut plane = DataPlane::new(cfg(1, 4, 64)).unwrap();
        plane.open_flow(FlowId(3)).unwrap();
        plane.enqueue(FlowId(3), b"zz").unwrap();
        plane.close_flow(FlowId(3)).unwrap();
        assert_eq!(plane.enqueue(FlowId(3), b"yy"), Err(DataError::Closed));
        assert_eq!(plane.deliver(FlowId(3)).unwrap().unwrap(), b"zz");
        assert_eq!(plane.deliver(FlowId(3)).unwrap(), None);
    }

    #[test]
    fn multi_flow_transfer_resets_two_and_hashes_survivors() {
        let mut packets = Vec::new();
        for index in 0..400u16 {
            let mut packet = vec![0x45, 0x00];
            packet.extend_from_slice(&index.to_be_bytes());
            packet.extend_from_slice(b"pkt");
            packets.push(packet);
        }
        let report = transfer_all(&packets, 4, &[1, 3]).unwrap();
        let mut expected = Vec::new();
        for flow in [0usize, 2] {
            for (index, packet) in packets.iter().enumerate() {
                if index % 4 == flow {
                    expected.extend_from_slice(packet);
                }
            }
        }
        assert_eq!(report.delivered_hash, payload_hash(&expected));
        assert_eq!(report.stats.delivered_packets, 200);
        assert_eq!(report.stats.dropped_resets, 200);
        assert_eq!(report.stats.enqueued_packets, 400);
        assert_eq!(report.delivered.len(), 200);
        let mut flat = Vec::new();
        for packet in &report.delivered {
            flat.extend_from_slice(packet);
        }
        assert_eq!(payload_hash(&flat), report.delivered_hash);
        assert_eq!(report.stats.reorders, 0);
    }

    #[test]
    fn config_rejects_zero_and_overflowing_products() {
        assert!(
            DataPlane::new(DataPlaneConfig {
                max_flows: 0,
                max_packet: 1,
                queue_packets: 1,
                max_bytes: 1,
            })
            .is_err()
        );
        assert!(
            DataPlane::new(DataPlaneConfig {
                max_flows: usize::MAX,
                max_packet: usize::MAX,
                queue_packets: usize::MAX,
                max_bytes: 1,
            })
            .is_err()
        );
        assert!(
            DataPlaneConfig {
                max_flows: 1,
                max_packet: 65_536,
                queue_packets: 1,
                max_bytes: 1,
            }
            .validate()
            .is_err()
        );
    }
}
