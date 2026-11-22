//! Endpoint-side §7.2 policy for one authenticated permanent IPv4 VIP pair.
//!
//! This module does not open circuits or authorize identities. The caller owns
//! TLS, serialized packet I/O and global admission. Use one pool per node pair
//! across concurrent openings, rotations and teardowns. Both directions must
//! use the pinned lane's FIFO packet path. Use the authenticated VIPs and MTU,
//! and reserve lanes only for this exact pair and identity epoch. Never replace
//! the pool while old lanes or packets can enter the new pool.

mod tcp_close;

use self::tcp_close::{Close, Finish, Segment, close_retry, tcp_checksum};
use crate::circuit::{CircuitId, DEFAULT_PAIR_CAP, HARD_PAIR_CAP};
use crate::packet_path::{PacketDeny, PacketPathError, PointToPoint};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// Hard cap on active/failed flows per pair. At most twice the configured
/// flow limit is retained in total (active/failed plus closed tuple guards).
pub const MAX_TRACKED_FLOWS: usize = 4096;

// TIME-WAIT-style guard, not a wire TTL. The ordered authenticated lane and
// the runtime's bounded queues/deadlines are also required; a finite guard
// cannot reject arbitrary replay forever. Never evict a guard early for room.
const CLOSE_GUARD: Duration = Duration::from_secs(120);

type GuardKey = (Instant, FlowKey);

#[derive(Debug)]
enum Flow {
    Pinned(CircuitId, Close),
    Failed,
    Closed {
        lane: CircuitId,
        fins: [Finish; 2],
        charged: bool,
    },
}

/// An IPv4/TCP tuple in canonical endpoint order, independent of direction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowKey(SocketAddrV4, SocketAddrV4);

impl FlowKey {
    pub const fn endpoints(self) -> (SocketAddrV4, SocketAddrV4) {
        (self.0, self.1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneState {
    Pending,
    Ready,
    Draining,
    /// Unusable immediately, but still charged until teardown completes.
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowBinding {
    Pinned(CircuitId),
    /// The lane was invalidated. Do not replay/rebind this tuple automatically.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError {
    InvalidEndpoints(PacketPathError),
    InvalidLaneLimit,
    InvalidFlowLimit,
    InvalidCircuitId,
    DuplicateCircuit,
    LaneLimit,
    UnknownLane,
    InvalidLaneState,
    Revoked,
    PacketDenied(PacketDeny),
    NotTcp,
    Fragmented,
    InvalidTcpHeader,
    UnknownFlow,
    FlowLimit,
    NoReadyLane,
    WrongLane,
    FlowFailed,
}

#[derive(Clone, Copy, Debug)]
struct Lane {
    id: CircuitId,
    state: LaneState,
}

/// Reusable bounded admission and flow-affinity state. No packet or TLS bytes
/// are retained. Methods whose decisions are needed for IO must be serialized
/// with the corresponding lane and flow lifecycle operations by the caller.
#[derive(Debug)]
pub struct CircuitPool {
    endpoints: PointToPoint,
    lane_limit: usize,
    lanes: [Option<Lane>; HARD_PAIR_CAP],
    next_slot: usize,
    flow_limit: usize,
    flows: BTreeMap<FlowKey, Flow>,
    charged: usize,
    guards: BTreeSet<GuardKey>,
    revoked: bool,
}

impl CircuitPool {
    /// Validate two distinct permanent VIPs on the same private overlay /16
    /// and the negotiated MTU using the existing point-to-point policy.
    pub fn new(
        local: Ipv4Addr,
        peer: Ipv4Addr,
        mtu: usize,
        lane_limit: usize,
        flow_limit: usize,
    ) -> Result<Self, PoolError> {
        if !(1..=HARD_PAIR_CAP).contains(&lane_limit) {
            return Err(PoolError::InvalidLaneLimit);
        }
        if !(1..=MAX_TRACKED_FLOWS).contains(&flow_limit) {
            return Err(PoolError::InvalidFlowLimit);
        }
        Ok(Self {
            endpoints: PointToPoint::try_new(local, peer, mtu)
                .map_err(PoolError::InvalidEndpoints)?,
            lane_limit,
            lanes: [None; HARD_PAIR_CAP],
            next_slot: 0,
            flow_limit,
            flows: BTreeMap::new(),
            charged: 0,
            guards: BTreeSet::new(),
            revoked: false,
        })
    }

    /// Use the §7.2 default of one admitted circuit per pair.
    pub fn with_default_lane_limit(
        local: Ipv4Addr,
        peer: Ipv4Addr,
        mtu: usize,
        flow_limit: usize,
    ) -> Result<Self, PoolError> {
        Self::new(local, peer, mtu, DEFAULT_PAIR_CAP, flow_limit)
    }

    pub fn lane_count(&self) -> usize {
        self.lanes.iter().flatten().count()
    }

    pub fn lane_state(&self, id: CircuitId) -> Option<LaneState> {
        self.lane_slot(id)
            .map(|slot| self.lanes[slot].expect("occupied slot").state)
    }

    /// Charged bindings, including guarded closes that could not free a slot.
    pub fn flow_count(&self) -> usize {
        self.charged
    }

    pub fn binding(&self, key: FlowKey) -> Option<FlowBinding> {
        match self.flows.get(&key)? {
            Flow::Pinned(id, _) => Some(FlowBinding::Pinned(*id)),
            Flow::Failed => Some(FlowBinding::Failed),
            Flow::Closed { .. } => None,
        }
    }

    pub fn pinned_count(&self, id: CircuitId) -> usize {
        self.flows
            .values()
            .filter(|flow| matches!(flow, Flow::Pinned(bound, _) if *bound == id))
            .count()
    }

    /// Charge a Pending slot before starting an opening attempt. The caller
    /// supplies a fresh nonzero circuit ID and must not reuse it after release.
    pub fn reserve_lane(&mut self, id: CircuitId) -> Result<(), PoolError> {
        if self.revoked {
            return Err(PoolError::Revoked);
        }
        if id.0 == [0; 16] {
            return Err(PoolError::InvalidCircuitId);
        }
        if self.lane_slot(id).is_some() {
            return Err(PoolError::DuplicateCircuit);
        }
        let slot = self.lanes[..self.lane_limit]
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(PoolError::LaneLimit)?;
        *slot = Some(Lane {
            id,
            state: LaneState::Pending,
        });
        Ok(())
    }

    /// Call only after the complete E2E handshake and authenticated binding
    /// to this pool's pair. Pending circuits never carry affinity traffic.
    pub fn mark_ready(&mut self, id: CircuitId) -> Result<(), PoolError> {
        self.transition(id, LaneState::Pending, LaneState::Ready)
    }

    /// Existing flows keep using the lane; new tuples cannot bind to it.
    pub fn begin_drain(&mut self, id: CircuitId) -> Result<(), PoolError> {
        self.transition(id, LaneState::Ready, LaneState::Draining)
    }

    /// Stop using this lane (failed handshake, failed transport, or end of
    /// drain). Return the number of live bindings explicitly marked Failed.
    /// The lane remains charged; call `release_lane` after actual teardown.
    pub fn invalidate_lane(&mut self, id: CircuitId) -> Result<usize, PoolError> {
        self.lane_mut(id)?.state = LaneState::Closing;
        let mut failed = 0;
        for flow in self.flows.values_mut() {
            if matches!(flow, Flow::Pinned(bound, _) if *bound == id) {
                *flow = Flow::Failed;
                failed += 1;
            }
        }
        Ok(failed)
    }

    /// Release a Closing slot only once the attempt/transport and its
    /// outstanding work have stopped. Never use this to bypass drain quota.
    pub fn release_lane(&mut self, id: CircuitId) -> Result<(), PoolError> {
        let slot = self.lane_slot(id).ok_or(PoolError::UnknownLane)?;
        if self.lanes[slot].expect("occupied slot").state != LaneState::Closing {
            return Err(PoolError::InvalidLaneState);
        }
        self.lanes[slot] = None;
        Ok(())
    }

    /// Irreversibly deny traffic and new reservations for this pool. Clear all
    /// flow state and make all lanes Closing; the caller still tears them down
    /// and releases their slots. Returns the count of cleared flow entries.
    pub fn revoke(&mut self) -> usize {
        self.revoked = true;
        for lane in self.lanes.iter_mut().flatten() {
            lane.state = LaneState::Closing;
        }
        let cleared = self.flows.len();
        self.flows.clear();
        self.guards.clear();
        self.charged = 0;
        cleared
    }

    /// Explicitly override a live or failed binding only with external proof
    /// that its socket and outstanding traffic are gone. This cannot bypass
    /// the guard for an automatically closed flow. No idle or RST-based expiry
    /// exists for incomplete or failed bindings.
    pub fn retire_flow(&mut self, key: FlowKey) -> Option<FlowBinding> {
        let binding = self.binding(key)?;
        self.flows.remove(&key);
        self.charged -= 1;
        Some(binding)
    }

    /// Route local IPv4/TCP. A previously unseen tuple may bind only on an
    /// opening SYN. New flows are distributed round-robin over Ready lanes;
    /// existing flows remain pinned even when lane membership changes.
    pub fn route_outbound(&mut self, packet: &[u8]) -> Result<(FlowKey, CircuitId), PoolError> {
        self.route_at(packet, Instant::now())
    }

    fn route_at(&mut self, packet: &[u8], now: Instant) -> Result<(FlowKey, CircuitId), PoolError> {
        let (key, segment) = self.inspect(packet, true)?;
        self.expire_guards(now);
        if let Some(id) = self.existing_flow(key, segment, None, now)? {
            return Ok((key, id));
        }
        self.check_new_flow(segment.opening())?;
        let (slot, id) = (0..self.lane_limit)
            .map(|offset| (self.next_slot + offset) % self.lane_limit)
            .find_map(|slot| match self.lanes[slot] {
                Some(lane) if lane.state == LaneState::Ready => Some((slot, lane.id)),
                _ => None,
            })
            .ok_or(PoolError::NoReadyLane)?;
        self.pin(key, id, segment);
        self.next_slot = (slot + 1) % self.lane_limit;
        Ok((key, id))
    }

    /// Accept data received on an authenticated E2E lane. A peer-initiated
    /// flow is learned on its actual lane, on an opening SYN on a Ready lane.
    /// Thereafter both directions must use that lane. Conflicting opens (also
    /// possible with simultaneous TCP open) fail closed, never re-pin.
    pub fn accept_inbound(&mut self, id: CircuitId, packet: &[u8]) -> Result<FlowKey, PoolError> {
        self.accept_at(id, packet, Instant::now())
    }

    fn accept_at(
        &mut self,
        id: CircuitId,
        packet: &[u8],
        now: Instant,
    ) -> Result<FlowKey, PoolError> {
        let (key, segment) = self.inspect(packet, false)?;
        self.expire_guards(now);
        if self.existing_flow(key, segment, Some(id), now)?.is_some() {
            return Ok(key);
        }
        if self.lane_state(id).ok_or(PoolError::UnknownLane)? != LaneState::Ready {
            return Err(PoolError::InvalidLaneState);
        }
        self.check_new_flow(segment.opening())?;
        self.pin(key, id, segment);
        Ok(key)
    }

    fn pin(&mut self, key: FlowKey, id: CircuitId, segment: Segment) {
        self.flows
            .insert(key, Flow::Pinned(id, Close::new(segment)));
        self.charged += 1;
    }

    fn existing_flow(
        &mut self,
        key: FlowKey,
        segment: Segment,
        inbound: Option<CircuitId>,
        now: Instant,
    ) -> Result<Option<CircuitId>, PoolError> {
        let Some(flow) = self.flows.get_mut(&key) else {
            return Ok(None);
        };
        match flow {
            Flow::Failed => Err(PoolError::FlowFailed),
            Flow::Closed { lane, fins, .. } => {
                // This is a packet drop, not a lane/protocol failure. A queued
                // old packet must not tear down healthy unrelated lanes.
                let id = *lane;
                if inbound.is_some_and(|lane| lane != id)
                    || !close_retry(segment, *fins)
                    || !matches!(
                        self.lane_state(id),
                        Some(LaneState::Ready | LaneState::Draining)
                    )
                {
                    return Err(PoolError::UnknownFlow);
                }
                Ok(Some(id))
            }
            Flow::Pinned(id, close) => {
                let id = *id;
                if inbound.is_some_and(|lane| lane != id) {
                    return Err(PoolError::WrongLane);
                }
                if let Some(fins) = close.observe(segment)
                    && let Some(until) = now.checked_add(CLOSE_GUARD)
                {
                    let charged = self.guards.len() >= self.flow_limit;
                    *flow = Flow::Closed {
                        lane: id,
                        fins,
                        charged,
                    };
                    self.guards.insert((until, key));
                    if !charged {
                        self.charged -= 1;
                    }
                }
                Ok(Some(id))
            }
        }
    }

    fn expire_guards(&mut self, now: Instant) {
        while let Some(&(until, key)) = self.guards.first() {
            if until > now {
                break;
            }
            self.guards.pop_first();
            match self.flows.remove(&key) {
                Some(Flow::Closed { charged: true, .. }) => self.charged -= 1,
                Some(Flow::Closed { charged: false, .. }) => {}
                _ => unreachable!("guard index must name a closed tuple"),
            }
        }
    }

    fn lane_slot(&self, id: CircuitId) -> Option<usize> {
        self.lanes
            .iter()
            .position(|lane| lane.is_some_and(|lane| lane.id == id))
    }

    fn lane_mut(&mut self, id: CircuitId) -> Result<&mut Lane, PoolError> {
        let slot = self.lane_slot(id).ok_or(PoolError::UnknownLane)?;
        self.lanes[slot].as_mut().ok_or(PoolError::UnknownLane)
    }

    fn transition(
        &mut self,
        id: CircuitId,
        from: LaneState,
        to: LaneState,
    ) -> Result<(), PoolError> {
        if self.revoked {
            return Err(PoolError::Revoked);
        }
        let lane = self.lane_mut(id)?;
        if lane.state != from {
            return Err(PoolError::InvalidLaneState);
        }
        lane.state = to;
        Ok(())
    }

    fn check_new_flow(&self, opening: bool) -> Result<(), PoolError> {
        if !opening {
            return Err(PoolError::UnknownFlow);
        }
        if self.charged >= self.flow_limit {
            return Err(PoolError::FlowLimit);
        }
        Ok(())
    }

    fn inspect(&self, packet: &[u8], outbound: bool) -> Result<(FlowKey, Segment), PoolError> {
        if self.revoked {
            return Err(PoolError::Revoked);
        }
        let info = if outbound {
            self.endpoints.authorize_outbound(packet)
        } else {
            self.endpoints.authorize_inbound(packet)
        }
        .map_err(PoolError::PacketDenied)?;
        if info.protocol != 6 {
            return Err(PoolError::NotTcp);
        }
        if info.fragment.is_some() {
            return Err(PoolError::Fragmented);
        }
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (info.source, info.destination) else {
            return Err(PoolError::PacketDenied(PacketDeny::Ipv6NotNegotiated));
        };
        let tcp = &packet[info.header_len..];
        if tcp.len() < 20 {
            return Err(PoolError::InvalidTcpHeader);
        }
        let tcp_header = usize::from(tcp[12] >> 4) * 4;
        if !(20..=tcp.len()).contains(&tcp_header) {
            return Err(PoolError::InvalidTcpHeader);
        }
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        if src_port == 0 || dst_port == 0 {
            return Err(PoolError::InvalidTcpHeader);
        }
        let a = SocketAddrV4::new(src, src_port);
        let b = SocketAddrV4::new(dst, dst_port);
        let key = if a < b { FlowKey(a, b) } else { FlowKey(b, a) };
        // Checksums only qualify lifecycle evidence; they are not a
        // substitute for TCP input validation by the destination host.
        Ok((key, Segment {
            seq: u32::from_be_bytes(tcp[4..8].try_into().expect("TCP fixed header")),
            ack: u32::from_be_bytes(tcp[8..12].try_into().expect("TCP fixed header")),
            data: (tcp.len() - tcp_header) as u32,
            flags: tcp[13],
            outbound,
            checksum_ok: tcp_checksum(&packet[12..20], tcp) == 0,
        }))
    }
}

#[cfg(test)]
mod retirement_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 20, 16, 251);
    const A: CircuitId = CircuitId([1; 16]);
    const B: CircuitId = CircuitId([2; 16]);
    const C: CircuitId = CircuitId([3; 16]);
    const D: CircuitId = CircuitId([4; 16]);
    const E: CircuitId = CircuitId([5; 16]);
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const MTU: usize = 1500;

    pub(super) fn ip_checksum(bytes: &mut [u8]) {
        bytes[10..12].fill(0);
        let header_len = usize::from(bytes[0] & 15) * 4;
        let (words, tail) = bytes[..header_len].as_chunks::<2>();
        assert!(tail.is_empty());
        let mut sum: u32 = words
            .iter()
            .map(|&word| u32::from(u16::from_be_bytes(word)))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        bytes[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    pub(super) fn packet(reverse: bool, client_port: u16, flags: u8) -> [u8; 40] {
        let (src, dst, sport, dport) = if reverse {
            (PEER, LOCAL, 443u16, client_port)
        } else {
            (LOCAL, PEER, client_port, 443u16)
        };
        let mut p = [0; 40];
        p[0] = 0x45;
        p[3] = 40;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        ip_checksum(&mut p);
        p
    }

    fn ready(pool: &mut CircuitPool, id: CircuitId) {
        pool.reserve_lane(id).unwrap();
        pool.mark_ready(id).unwrap();
    }

    #[test]
    fn validates_configuration_boundaries() {
        for bad in [
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 17, 1),
            Ipv4Addr::new(10, 20, 1, 0),
            Ipv4Addr::new(10, 20, 1, 252),
            Ipv4Addr::new(10, 21, 1, 1),
            Ipv4Addr::new(8, 8, 1, 1),
        ] {
            assert!(matches!(
                CircuitPool::new(LOCAL, bad, MTU, 1, 1),
                Err(PoolError::InvalidEndpoints(_))
            ));
        }
        assert!(matches!(
            CircuitPool::new(LOCAL, LOCAL, MTU, 1, 1),
            Err(PoolError::InvalidEndpoints(PacketPathError::SelfPair))
        ));
        for mtu in [575, 1501] {
            assert!(matches!(
                CircuitPool::new(LOCAL, PEER, mtu, 1, 1),
                Err(PoolError::InvalidEndpoints(PacketPathError::MtuOutOfRange))
            ));
        }
        for limit in [0, HARD_PAIR_CAP + 1] {
            assert!(matches!(
                CircuitPool::new(LOCAL, PEER, MTU, limit, 1),
                Err(PoolError::InvalidLaneLimit)
            ));
        }
        for limit in [0, MAX_TRACKED_FLOWS + 1] {
            assert!(matches!(
                CircuitPool::new(LOCAL, PEER, MTU, 1, limit),
                Err(PoolError::InvalidFlowLimit)
            ));
        }
        assert!(CircuitPool::new(LOCAL, PEER, 576, 4, MAX_TRACKED_FLOWS).is_ok());
        let mut default = CircuitPool::with_default_lane_limit(LOCAL, PEER, MTU, 1).unwrap();
        assert_eq!(default.reserve_lane(A), Ok(()));
        assert_eq!(default.reserve_lane(B), Err(PoolError::LaneLimit));
    }

    #[test]
    fn all_lane_states_charge_quota_until_teardown() {
        let mut pool = CircuitPool::new(LOCAL, PEER, MTU, 4, 1).unwrap();
        assert_eq!(
            pool.reserve_lane(CircuitId([0; 16])),
            Err(PoolError::InvalidCircuitId)
        );
        assert_eq!(pool.mark_ready(A), Err(PoolError::UnknownLane));
        pool.reserve_lane(A).unwrap();
        assert_eq!(pool.reserve_lane(A), Err(PoolError::DuplicateCircuit));
        assert_eq!(pool.begin_drain(A), Err(PoolError::InvalidLaneState));
        assert_eq!(
            pool.route_outbound(&packet(false, 1, SYN)),
            Err(PoolError::NoReadyLane)
        );
        assert_eq!(
            pool.accept_inbound(A, &packet(true, 1, SYN)),
            Err(PoolError::InvalidLaneState)
        );
        ready(&mut pool, B);
        ready(&mut pool, C);
        pool.begin_drain(C).unwrap();
        assert_eq!(pool.mark_ready(C), Err(PoolError::InvalidLaneState));
        assert_eq!(pool.release_lane(C), Err(PoolError::InvalidLaneState));
        pool.reserve_lane(D).unwrap();
        assert_eq!(pool.invalidate_lane(D), Ok(0));
        assert_eq!(pool.lane_state(A), Some(LaneState::Pending));
        assert_eq!(pool.lane_state(B), Some(LaneState::Ready));
        assert_eq!(pool.lane_state(C), Some(LaneState::Draining));
        assert_eq!(pool.lane_state(D), Some(LaneState::Closing));
        assert_eq!(pool.mark_ready(D), Err(PoolError::InvalidLaneState));
        assert_eq!(pool.lane_count(), 4);
        assert_eq!(pool.reserve_lane(E), Err(PoolError::LaneLimit));
        pool.release_lane(D).unwrap();
        assert_eq!(pool.release_lane(D), Err(PoolError::UnknownLane));
        assert_eq!(pool.reserve_lane(E), Ok(()));
    }

    #[test]
    fn two_endpoints_agree_on_lanes_in_both_directions() {
        let mut local = CircuitPool::new(LOCAL, PEER, MTU, 3, 8).unwrap();
        let mut peer = CircuitPool::new(PEER, LOCAL, MTU, 3, 8).unwrap();
        ready(&mut local, A);
        ready(&mut local, B);
        // Receiver independently admits and orders the lanes differently.
        ready(&mut peer, B);
        ready(&mut peer, A);
        for (port, lane, other) in [(1, A, B), (65535, B, A)] {
            let syn = packet(false, port, SYN);
            let ack = packet(true, port, SYN | ACK);
            let (key, selected) = local.route_outbound(&syn).unwrap();
            assert_eq!(selected, lane);
            assert_eq!(peer.accept_inbound(lane, &syn), Ok(key));
            assert_eq!(peer.route_outbound(&ack), Ok((key, lane)));
            assert_eq!(local.accept_inbound(other, &ack), Err(PoolError::WrongLane));
            assert_eq!(local.accept_inbound(lane, &ack), Ok(key));
            assert_eq!(
                key.endpoints(),
                (SocketAddrV4::new(LOCAL, port), SocketAddrV4::new(PEER, 443))
            );
        }
        ready(&mut local, C);
        local.begin_drain(A).unwrap();
        assert_eq!(local.route_outbound(&packet(false, 1, ACK)).unwrap().1, A);
        assert!(local.accept_inbound(A, &packet(true, 1, ACK)).is_ok());
        assert_eq!(
            local.accept_inbound(A, &packet(true, 3, SYN)),
            Err(PoolError::InvalidLaneState)
        );
        assert_eq!(local.route_outbound(&packet(false, 3, SYN)).unwrap().1, C);
        let (key, lane) = peer.route_outbound(&packet(true, 4, SYN)).unwrap();
        assert_eq!(lane, B);
        assert_eq!(local.accept_inbound(lane, &packet(true, 4, SYN)), Ok(key));
        assert_eq!(
            local.route_outbound(&packet(false, 4, SYN | ACK)),
            Ok((key, lane))
        );
    }

    #[test]
    fn failed_flows_remain_blocked_and_revoke_clears_state() {
        let mut pool = CircuitPool::new(LOCAL, PEER, MTU, 2, 2).unwrap();
        ready(&mut pool, A);
        ready(&mut pool, B);
        let syn = packet(false, 80, SYN);
        let (key, _) = pool.route_outbound(&syn).unwrap();
        let (other, _) = pool.route_outbound(&packet(false, 81, SYN)).unwrap();
        assert_eq!(pool.invalidate_lane(A), Ok(1));
        assert_eq!(pool.invalidate_lane(A), Ok(0));
        assert_eq!(pool.pinned_count(A), 0);
        assert_eq!(pool.binding(key), Some(FlowBinding::Failed));
        assert_eq!(pool.binding(other), Some(FlowBinding::Pinned(B)));
        assert_eq!(pool.route_outbound(&syn), Err(PoolError::FlowFailed));
        assert_eq!(
            pool.accept_inbound(B, &packet(true, 80, ACK)),
            Err(PoolError::FlowFailed)
        );
        assert_eq!(pool.reserve_lane(C), Err(PoolError::LaneLimit));
        pool.release_lane(A).unwrap();
        ready(&mut pool, C);
        assert_eq!(pool.route_outbound(&syn), Err(PoolError::FlowFailed));
        assert_eq!(
            pool.route_outbound(&packet(false, 82, SYN)),
            Err(PoolError::FlowLimit)
        );
        assert_eq!(
            pool.accept_inbound(C, &packet(true, 83, SYN)),
            Err(PoolError::FlowLimit)
        );
        assert_eq!(pool.retire_flow(key), Some(FlowBinding::Failed));
        assert_eq!(
            pool.route_outbound(&packet(false, 80, ACK)),
            Err(PoolError::UnknownFlow)
        );
        assert!(pool.route_outbound(&syn).is_ok());
        assert_eq!(pool.revoke(), 2);
        assert_eq!(pool.revoke(), 0);
        assert_eq!(pool.flow_count(), 0);
        assert_eq!(pool.lane_count(), 2);
        assert_eq!(pool.lane_state(B), Some(LaneState::Closing));
        assert_eq!(pool.route_outbound(&syn), Err(PoolError::Revoked));
        assert_eq!(
            pool.accept_inbound(B, &packet(true, 80, SYN)),
            Err(PoolError::Revoked)
        );
        pool.release_lane(B).unwrap();
        pool.release_lane(C).unwrap();
        assert_eq!(pool.reserve_lane(D), Err(PoolError::Revoked));
    }

    #[test]
    fn denies_wrong_direction_and_malformed_or_unsupported_packets() {
        let mut pool = CircuitPool::new(LOCAL, PEER, MTU, 1, 1).unwrap();
        ready(&mut pool, A);
        assert_eq!(
            pool.route_outbound(&packet(true, 80, SYN)),
            Err(PoolError::PacketDenied(PacketDeny::SourceNotLocal))
        );
        assert_eq!(
            pool.accept_inbound(A, &packet(false, 80, SYN)),
            Err(PoolError::PacketDenied(PacketDeny::SourceNotPeer))
        );
        for flags in [0, ACK, SYN | ACK, SYN | 1, SYN | 4] {
            assert_eq!(
                pool.route_outbound(&packet(false, 80, flags)),
                Err(PoolError::UnknownFlow)
            );
        }
        assert_eq!(
            pool.route_outbound(&packet(false, 0, SYN)),
            Err(PoolError::InvalidTcpHeader)
        );
        let mut p = packet(false, 80, SYN);
        assert!(matches!(
            pool.route_outbound(&p[..39]),
            Err(PoolError::PacketDenied(_))
        ));
        for offset in [0x40, 0x60] {
            p[32] = offset;
            assert_eq!(pool.route_outbound(&p), Err(PoolError::InvalidTcpHeader));
        }
        p[32] = 0x50;
        p[22..24].fill(0);
        assert_eq!(pool.route_outbound(&p), Err(PoolError::InvalidTcpHeader));
        p[9] = 17;
        ip_checksum(&mut p);
        assert_eq!(pool.route_outbound(&p), Err(PoolError::NotTcp));
        p[9] = 6;
        p[7] = 1;
        ip_checksum(&mut p);
        assert_eq!(pool.route_outbound(&p), Err(PoolError::Fragmented));
        let mut first = p.to_vec();
        first.resize(44, 0);
        first[3] = 44;
        first[6] = 0x20;
        first[7] = 0;
        ip_checksum(&mut first);
        assert_eq!(pool.route_outbound(&first), Err(PoolError::Fragmented));
        assert_eq!(pool.flow_count(), 0);
    }

    #[test]
    fn honors_ipv4_and_tcp_header_lengths() {
        let mut pool = CircuitPool::new(LOCAL, PEER, MTU, 1, 1).unwrap();
        ready(&mut pool, A);
        let base = packet(false, 80, SYN);
        let mut p = [0; 48];
        p[..20].copy_from_slice(&base[..20]);
        p[0] = 0x46;
        p[3] = 48;
        p[24..44].copy_from_slice(&base[20..]);
        p[36] = 0x60;
        ip_checksum(&mut p);
        let (key, lane) = pool.route_outbound(&p).unwrap();
        assert_eq!(lane, A);
        assert_eq!(
            pool.accept_inbound(A, &packet(true, 80, SYN | ACK)),
            Ok(key)
        );
    }
}
