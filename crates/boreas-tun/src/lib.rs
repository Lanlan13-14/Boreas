//! Bounded packet I/O, L3 validation, and native Linux/Windows/macOS adapters.
//! Native adapters manage only their own device and MTU; they install no routes
//! and make no production VPN, performance, or security-certification claim.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod icmp;
pub mod queue;
pub mod route_audit;
pub mod virtio;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const MAX_IP_PACKET: usize = 65_535;
pub const MAX_IPV6_EXT_HEADERS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPacket,
    Truncated,
    InvalidVersion,
    InvalidHeader,
    InvalidLength,
    InvalidChecksum,
    UnsupportedExtension,
    TooManyExtensions,
    FragmentMalformed,
    FragmentOverlap,
    FragmentLimit,
    FragmentTimeout,
    PacketTooLarge { mtu: usize },
    TtlExpired,
    QueueFull,
    QueueClosed,
    InvalidConfiguration,
    VirtioHeaderTruncated,
    VirtioUnsupportedGso,
    VirtioUnsupportedOffload,
    VirtioInvalid,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketInfo {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub header_len: usize,
    pub packet_len: usize,
    pub fragment: Option<FragmentInfo>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentInfo {
    pub identification: u32,
    pub offset: u32,
    pub more: bool,
    pub payload_len: usize,
}

/// Strictly validate an entire IPv4/IPv6 packet. IPv6 extension chains are capped at four headers.
pub fn inspect_packet(packet: &[u8]) -> Result<PacketInfo, Error> {
    let first = *packet.first().ok_or(Error::EmptyPacket)?;
    match first >> 4 {
        4 => inspect_v4(packet),
        6 => inspect_v6(packet),
        _ => Err(Error::InvalidVersion),
    }
}
fn checksum_valid(h: &[u8]) -> bool {
    checksum(h) == 0
}
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u64;
    for chunk in data.chunks(2) {
        sum += if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u64
        } else {
            (chunk[0] as u64) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn inspect_v4(p: &[u8]) -> Result<PacketInfo, Error> {
    if p.len() < 20 {
        return Err(Error::Truncated);
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > p.len() {
        return Err(Error::InvalidHeader);
    }
    let n = u16::from_be_bytes([p[2], p[3]]) as usize;
    if n < ihl || n != p.len() {
        return Err(Error::InvalidLength);
    }
    if !checksum_valid(&p[..ihl]) {
        return Err(Error::InvalidChecksum);
    }
    let frag = u16::from_be_bytes([p[6], p[7]]);
    if frag & 0x8000 != 0 || (frag & 0x4000 != 0 && frag & 0x3fff != 0) {
        return Err(Error::InvalidHeader);
    }
    let off = ((frag & 0x1fff) as u32) * 8;
    let more = frag & 0x2000 != 0;
    let plen = n - ihl;
    if (more && (plen == 0 || !plen.is_multiple_of(8))) || off as usize + plen > 65_535 - ihl {
        return Err(Error::FragmentMalformed);
    }
    let fragmented = more || off != 0;
    Ok(PacketInfo {
        version: IpVersion::V4,
        source: IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
        destination: IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
        protocol: p[9],
        header_len: ihl,
        packet_len: n,
        fragment: fragmented.then_some(FragmentInfo {
            identification: u16::from_be_bytes([p[4], p[5]]) as u32,
            offset: off,
            more,
            payload_len: plen,
        }),
    })
}
fn inspect_v6(p: &[u8]) -> Result<PacketInfo, Error> {
    if p.len() < 40 {
        return Err(Error::Truncated);
    }
    let n = 40usize
        .checked_add(u16::from_be_bytes([p[4], p[5]]) as usize)
        .ok_or(Error::InvalidLength)?;
    if n != p.len() {
        return Err(Error::InvalidLength);
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
    let mut next = p[6];
    let mut pos = 40;
    let mut count = 0;
    let mut frag = None;
    loop {
        if !matches!(next, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
            break;
        }
        if count == MAX_IPV6_EXT_HEADERS {
            return Err(Error::TooManyExtensions);
        }
        count += 1;
        match next {
            44 => {
                if pos + 8 > n {
                    return Err(Error::Truncated);
                }
                let following = p[pos];
                let bits = u16::from_be_bytes([p[pos + 2], p[pos + 3]]);
                if bits & 0x0006 != 0 || frag.is_some() {
                    return Err(Error::FragmentMalformed);
                }
                let off = (bits & 0xfff8) as u32;
                if off != 0 && matches!(following, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
                    return Err(Error::UnsupportedExtension);
                }
                let more = bits & 1 != 0;
                let plen = n - (pos + 8);
                if (more && (plen == 0 || !plen.is_multiple_of(8))) || off as usize + plen > 65_535
                {
                    return Err(Error::FragmentMalformed);
                }
                frag = Some(FragmentInfo {
                    identification: u32::from_be_bytes(p[pos + 4..pos + 8].try_into().unwrap()),
                    offset: off,
                    more,
                    payload_len: plen,
                });
                next = following;
                pos += 8;
            }
            51 => {
                if pos + 2 > n {
                    return Err(Error::Truncated);
                }
                let l = (p[pos + 1] as usize + 2) * 4;
                if l < 12 || pos + l > n {
                    return Err(Error::InvalidLength);
                }
                next = p[pos];
                pos += l;
            }
            _ => {
                if pos + 2 > n {
                    return Err(Error::Truncated);
                }
                let l = (p[pos + 1] as usize + 1) * 8;
                if pos + l > n {
                    return Err(Error::InvalidLength);
                }
                next = p[pos];
                pos += l;
            }
        }
    }
    if next == 59 && pos != n {
        return Err(Error::InvalidLength);
    }
    Ok(PacketInfo {
        version: IpVersion::V6,
        source: IpAddr::V6(src),
        destination: IpAddr::V6(dst),
        protocol: next,
        header_len: pos,
        packet_len: n,
        fragment: frag,
    })
}

/// Decrement the forwarding hop field. TTL/hop-limit expiry returns an error; caller emits ICMP.
pub fn decrement_hop(packet: &mut [u8]) -> Result<(), Error> {
    let info = inspect_packet(packet)?;
    match info.version {
        IpVersion::V4 => {
            if packet[8] <= 1 {
                return Err(Error::TtlExpired);
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let c = checksum(&packet[..info.header_len]).to_be_bytes();
            packet[10] = c[0];
            packet[11] = c[1];
        }
        IpVersion::V6 => {
            if packet[7] <= 1 {
                return Err(Error::TtlExpired);
            }
            packet[7] -= 1;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtuAction {
    Forward,
    Ipv4Fragment,
    Ipv4FragmentationNeeded,
    Ipv6PacketTooBig,
}
/// Decide PMTU behavior, without mutating or fragmenting the packet.
pub fn pmtu_action(packet: &[u8], mtu: usize) -> Result<MtuAction, Error> {
    let i = inspect_packet(packet)?;
    if mtu < 68 || (i.version == IpVersion::V6 && mtu < 1280) {
        return Err(Error::InvalidLength);
    }
    if packet.len() <= mtu {
        return Ok(MtuAction::Forward);
    }
    Ok(match i.version {
        IpVersion::V6 => MtuAction::Ipv6PacketTooBig,
        IpVersion::V4 => {
            let f = u16::from_be_bytes([packet[6], packet[7]]);
            if f & 0x4000 != 0 {
                MtuAction::Ipv4FragmentationNeeded
            } else {
                MtuAction::Ipv4Fragment
            }
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OffloadCaps {
    pub checksum: bool,
    pub tso4: bool,
    pub tso6: bool,
    pub uso4: bool,
    pub uso6: bool,
}
impl OffloadCaps {
    pub fn intersection(self, peer: Self) -> Self {
        Self {
            checksum: self.checksum && peer.checksum,
            tso4: self.tso4 && peer.tso4,
            tso6: self.tso6 && peer.tso6,
            uso4: self.uso4 && peer.uso4,
            uso6: self.uso6 && peer.uso6,
        }
    }
}
pub const VNET_HDR_LEN: usize = 10;
/// Parse little-endian virtio_net_hdr (10-byte base header). GSO is rejected unless explicitly supported;
/// this implementation does not claim software segmentation, so never forwards a super-packet.
pub fn parse_virtio_frame(
    frame: &[u8],
    caps: OffloadCaps,
) -> Result<(VirtioNetHeader, &[u8]), Error> {
    if frame.len() < VNET_HDR_LEN {
        return Err(Error::VirtioHeaderTruncated);
    }
    let h = VirtioNetHeader {
        flags: frame[0],
        gso_type: frame[1],
        hdr_len: u16::from_le_bytes([frame[2], frame[3]]),
        gso_size: u16::from_le_bytes([frame[4], frame[5]]),
        csum_start: u16::from_le_bytes([frame[6], frame[7]]),
        csum_offset: u16::from_le_bytes([frame[8], frame[9]]),
    };
    if h.flags & !3 != 0 || !matches!(h.gso_type & !0x80, 0 | 1 | 3 | 4 | 5 | 6) {
        return Err(Error::VirtioInvalid);
    }
    if h.flags & 2 != 0 {
        return Err(Error::VirtioUnsupportedOffload);
    }
    let data = &frame[VNET_HDR_LEN..];
    if data.is_empty() {
        return Err(Error::VirtioInvalid);
    }
    if h.flags & 1 != 0 && !caps.checksum {
        return Err(Error::VirtioUnsupportedOffload);
    }
    if h.flags & 1 != 0 {
        let end = (h.csum_start as usize)
            .checked_add(h.csum_offset as usize)
            .and_then(|x| x.checked_add(2))
            .ok_or(Error::VirtioInvalid)?;
        if end > data.len() {
            return Err(Error::VirtioInvalid);
        }
        return Err(Error::VirtioUnsupportedOffload);
    }
    if h.gso_type == 0x80 {
        return Err(Error::VirtioInvalid);
    }
    let g = h.gso_type & !0x80;
    if g == 0 && (h.hdr_len != 0 || h.gso_size != 0) {
        return Err(Error::VirtioInvalid);
    }
    if h.flags & 1 == 0 && (h.csum_start != 0 || h.csum_offset != 0) {
        return Err(Error::VirtioInvalid);
    }
    if g != 0 {
        let supported = match g {
            1 => caps.tso4,
            4 => caps.tso6,
            3 => caps.uso4,
            5 => caps.uso6,
            _ => false,
        };
        if h.gso_type & 0x80 != 0
            || !supported
            || h.gso_size == 0
            || h.hdr_len as usize > data.len()
        {
            return Err(Error::VirtioUnsupportedGso);
        }
        // Metadata accepted only for an implementation that handles it; this implementation does not.
        return Err(Error::VirtioUnsupportedGso);
    }
    let _ = caps;
    let i = inspect_packet(data).map_err(|_| Error::VirtioInvalid)?;
    if h.hdr_len as usize > i.packet_len {
        return Err(Error::VirtioInvalid);
    }
    if h.flags & 1 != 0 && h.csum_start as usize >= i.packet_len {
        return Err(Error::VirtioInvalid);
    }
    Ok((h, data))
}

/// A bounded in-memory packet endpoint. Each direction is a finite FIFO; full queues fail closed.
#[derive(Clone)]
pub struct VirtualTun {
    inner: Arc<Mutex<Queues>>,
    side: usize,
    max_packet: usize,
}
struct Queues {
    rx: [VecDeque<Vec<u8>>; 2],
    cap: [usize; 2],
    closed: bool,
}
pub trait PacketIo {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error>;
    fn write_packet(&self, packet: &[u8]) -> Result<(), Error>;
}
impl VirtualTun {
    /// Create connected in-memory endpoints; capacities bound each receive direction independently.
    pub fn try_pair(
        a_capacity: usize,
        b_capacity: usize,
        max_packet: usize,
    ) -> Result<(Self, Self), Error> {
        if max_packet == 0
            || max_packet > MAX_IP_PACKET
            || a_capacity.checked_mul(max_packet).is_none()
            || b_capacity.checked_mul(max_packet).is_none()
        {
            return Err(Error::InvalidConfiguration);
        }
        let q = Arc::new(Mutex::new(Queues {
            rx: [VecDeque::new(), VecDeque::new()],
            cap: [a_capacity, b_capacity],
            closed: false,
        }));
        Ok((
            Self {
                inner: q.clone(),
                side: 0,
                max_packet,
            },
            Self {
                inner: q,
                side: 1,
                max_packet,
            },
        ))
    }
    pub fn pair(a_capacity: usize, b_capacity: usize, max_packet: usize) -> (Self, Self) {
        Self::try_pair(a_capacity, b_capacity, max_packet)
            .expect("VirtualTun::pair requires bounded valid capacities")
    }
    /// Inject a packet as if received from the host on this endpoint.
    pub fn inject(&self, packet: &[u8]) -> Result<(), Error> {
        if packet.len() > self.max_packet {
            return Err(Error::PacketTooLarge {
                mtu: self.max_packet,
            });
        }
        inspect_packet(packet)?;
        let mut q = self.inner.lock().map_err(|_| Error::QueueClosed)?;
        if q.closed {
            return Err(Error::QueueClosed);
        }
        if q.rx[self.side].len() >= q.cap[self.side] {
            return Err(Error::QueueFull);
        }
        q.rx[self.side].push_back(packet.to_vec());
        Ok(())
    }
    pub fn close(&self) {
        if let Ok(mut q) = self.inner.lock() {
            q.closed = true
        }
    }
}
impl PacketIo for VirtualTun {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error> {
        let mut q = self.inner.lock().map_err(|_| Error::QueueClosed)?;
        Ok(q.rx[self.side].pop_front())
    }
    fn write_packet(&self, p: &[u8]) -> Result<(), Error> {
        if p.len() > self.max_packet {
            return Err(Error::PacketTooLarge {
                mtu: self.max_packet,
            });
        }
        inspect_packet(p)?;
        let mut q = self.inner.lock().map_err(|_| Error::QueueClosed)?;
        if q.closed {
            return Err(Error::QueueClosed);
        }
        let peer = 1 - self.side;
        if q.rx[peer].len() >= q.cap[peer] {
            return Err(Error::QueueFull);
        }
        q.rx[peer].push_back(p.to_vec());
        Ok(())
    }
}

/// Four-dimensional bounded fragment reassembly.
///
/// L3 source check does not need reassembly; this tracker exists only for a
/// destination-node L4 ACL after decrypt. A forwarding core must not call it.
/// There is no API that says "core_may_reassemble".
///
/// This tracker does not parse IPv6 extension headers and does not look at
/// ports. [`FragmentTracker::try_for_role`] selects the cap: `1` is Edge
/// (512 sets, 4 MiB) and `2` is Core (2048 sets, 16 MiB). Role `0` is rejected.
/// A new set past the concurrency cap is rejected and no existing set is evicted.
///
/// One set holds at most 65,535 bytes. A fragment that would push it over drops
/// the whole set and counts the drop. A fragment that would push the global
/// buffer over the role cap is rejected and does not enter any set. A set whose
/// age is at least 5,000 monotonic milliseconds is dropped whole on the next
/// [`FragmentTracker::insert`] or [`FragmentTracker::poll`], counted as expired,
/// and cannot be completed later.
///
/// Overlapping ranges drop the whole set. A duplicate exact fragment (same
/// offset and same bytes) is an overlap in this slice, not a harmless
/// retransmit.
///
/// Reassembly returns the payload only when the fragment that clears
/// more-fragments has defined the datagram end and the accepted ranges cover
/// `0..end` with no holes. The set is then freed and its bytes leave the
/// global counter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FragmentKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub identification: u32,
}
/// Destination-node role. This is not a forwarding permission.
///
/// Discriminant `0` is not a role. [`FragmentTracker::try_for_role`] rejects it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FragmentRole {
    /// 512 concurrent sets and a 4 MiB global buffer.
    Edge = 1,
    /// 2048 concurrent sets and a 16 MiB global buffer.
    Core = 2,
}
#[derive(Clone, Copy, Debug)]
pub struct FragmentLimits {
    pub streams: usize,
    pub per_stream_bytes: usize,
    pub global_bytes: usize,
    pub timeout: Duration,
}
impl FragmentLimits {
    pub const EDGE: Self = Self {
        streams: 512,
        per_stream_bytes: 65_535,
        global_bytes: 4 * 1024 * 1024,
        timeout: Duration::from_secs(5),
    };
    pub const CORE: Self = Self {
        streams: 2048,
        per_stream_bytes: 65_535,
        global_bytes: 16 * 1024 * 1024,
        timeout: Duration::from_secs(5),
    };
}
struct Chunk {
    offset: u32,
    end: u32,
    data: Vec<u8>,
}
struct Flow {
    chunks: Vec<Chunk>,
    bytes: usize,
    created_ms: u64,
    final_end: Option<u32>,
}
pub struct FragmentTracker {
    limits: FragmentLimits,
    flows: HashMap<FragmentKey, Flow>,
    tombstones: HashMap<FragmentKey, u64>,
    bytes: usize,
    dropped: u64,
    expired: u64,
    instant_origin: Option<Instant>,
}
/// `true` when `global_used + add` fits in `cap` without wrapping.
fn try_reserve(global_used: usize, cap: usize, add: usize) -> bool {
    global_used.checked_add(add).is_some_and(|sum| sum <= cap)
}
impl FragmentTracker {
    /// Hardcoded production caps. `1` is Edge (4 MiB, 512 sets). `2` is Core
    /// (16 MiB, 2048 sets). `0` and any other discriminant are rejected.
    pub fn try_for_role(role: u8) -> Result<Self, Error> {
        let limits = match role {
            1 => FragmentLimits::EDGE,
            2 => FragmentLimits::CORE,
            _ => return Err(Error::InvalidConfiguration),
        };
        Ok(Self::from_limits(limits))
    }
    /// Compatibility constructor. The public fields cannot exceed the production
    /// ceilings, and `0` is rejected. Prefer [`Self::try_for_role`].
    pub fn try_new(limits: FragmentLimits) -> Result<Self, Error> {
        if limits.streams == 0
            || limits.streams > 2048
            || limits.per_stream_bytes == 0
            || limits.per_stream_bytes > 65_535
            || limits.global_bytes == 0
            || limits.global_bytes > 16 * 1024 * 1024
            || limits.timeout.is_zero()
            || limits.timeout > Duration::from_secs(5)
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self::from_limits(limits))
    }
    pub fn new(limits: FragmentLimits) -> Self {
        Self::try_new(limits).expect("FragmentTracker requires protocol-bounded limits")
    }
    fn from_limits(limits: FragmentLimits) -> Self {
        Self {
            limits,
            flows: HashMap::new(),
            tombstones: HashMap::new(),
            bytes: 0,
            dropped: 0,
            expired: 0,
            instant_origin: None,
        }
    }
    pub fn tracked_streams(&self) -> usize {
        self.flows.len()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }
    /// Whole sets discarded because a fragment overlapped or exceeded 65,535 bytes.
    pub fn dropped_sets(&self) -> u64 {
        self.dropped
    }
    /// Whole sets discarded because their age reached 5,000 monotonic milliseconds.
    pub fn expired_sets(&self) -> u64 {
        self.expired
    }
    fn tombstone(&mut self, key: FragmentKey, until_ms: u64) {
        let cap = self.limits.streams.saturating_mul(2).max(1);
        if self.tombstones.len() >= cap
            && !self.tombstones.contains_key(&key)
            && let Some(old) = self
                .tombstones
                .iter()
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| *k)
        {
            self.tombstones.remove(&old);
        }
        self.tombstones.insert(key, until_ms);
    }
    fn drop_set(&mut self, key: FragmentKey, now_ms: u64) {
        if let Some(f) = self.flows.remove(&key) {
            self.bytes -= f.bytes;
        }
        self.dropped += 1;
        self.tombstone(
            key,
            now_ms.saturating_add(self.limits.timeout.as_millis() as u64),
        );
    }
    fn sweep_expired(&mut self, now_ms: u64) -> usize {
        let lifetime = self.limits.timeout.as_millis() as u64;
        let old: Vec<_> = self
            .flows
            .iter()
            .filter_map(|(k, v)| (now_ms.saturating_sub(v.created_ms) >= lifetime).then_some(*k))
            .collect();
        for k in &old {
            if let Some(f) = self.flows.remove(k) {
                self.bytes -= f.bytes;
            }
            self.expired += 1;
            self.tombstone(*k, now_ms.saturating_add(lifetime));
        }
        self.tombstones.retain(|_, until| *until > now_ms);
        old.len()
    }
    fn now_ms(&mut self, now: Instant) -> u64 {
        match self.instant_origin {
            Some(origin) => now.saturating_duration_since(origin).as_millis() as u64,
            None => {
                self.instant_origin = Some(now);
                0
            }
        }
    }
    /// Observe one fragment and return the reassembled payload once, if this
    /// fragment completed `0..end`. `now` is an injectable monotonic instant.
    pub fn observe(
        &mut self,
        key: FragmentKey,
        offset: u32,
        payload: &[u8],
        more: bool,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, Error> {
        let now_ms = self.now_ms(now);
        self.insert(key, offset, payload, more, now_ms)
    }
    /// Drop sets whose age is at least the lifetime. Returns how many were expired.
    pub fn expire(&mut self, now: Instant) -> usize {
        let now_ms = self.now_ms(now);
        self.sweep_expired(now_ms)
    }
    /// Insert one fragment. `now_ms` is caller-supplied monotonic milliseconds.
    ///
    /// The returned bytes are the payload only, and only when the fragment that
    /// cleared more-fragments has defined the end and the ranges cover `0..end`
    /// with no holes. The set is freed before the return, so its bytes leave
    /// the global counter.
    pub fn insert(
        &mut self,
        key: FragmentKey,
        offset: u32,
        payload: &[u8],
        more: bool,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.sweep_expired(now_ms);
        if self.tombstones.contains_key(&key) {
            return Err(Error::FragmentTimeout);
        }
        let len = payload.len();
        let len_u32 = u32::try_from(len).map_err(|_| Error::FragmentMalformed)?;
        let Some(end) = offset.checked_add(len_u32) else {
            self.drop_set(key, now_ms);
            return Err(Error::FragmentLimit);
        };
        if len == 0
            || (offset != 0 && !offset.is_multiple_of(8))
            || (more && !len.is_multiple_of(8))
        {
            return Err(Error::FragmentMalformed);
        }
        if end > 65_535 {
            self.drop_set(key, now_ms);
            return Err(Error::FragmentLimit);
        }
        if !self.flows.contains_key(&key) && self.flows.len() >= self.limits.streams {
            return Err(Error::FragmentLimit);
        }
        let current = self.flows.get(&key);
        let old_bytes = current.map_or(0, |f| f.bytes);
        let total = old_bytes.checked_add(len).ok_or(Error::FragmentLimit)?;
        if total > self.limits.per_stream_bytes {
            self.drop_set(key, now_ms);
            return Err(Error::FragmentLimit);
        }
        let used_without = self.bytes - old_bytes;
        if !try_reserve(used_without, self.limits.global_bytes, total) {
            return Err(Error::FragmentLimit);
        }
        if let Some(f) = self.flows.get(&key)
            && (f.chunks.iter().any(|c| offset < c.end && c.offset < end)
                || f.final_end
                    .is_some_and(|x| end > x || (!more && end != x) || (more && end >= x))
                || (!more && f.chunks.iter().any(|c| c.end > end)))
        {
            self.drop_set(key, now_ms);
            return Err(Error::FragmentOverlap);
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            chunks: Vec::new(),
            bytes: 0,
            created_ms: now_ms,
            final_end: None,
        });
        flow.chunks.push(Chunk {
            offset,
            end,
            data: payload.to_vec(),
        });
        flow.bytes += len;
        if !more {
            flow.final_end = Some(end);
        }
        self.bytes += len;
        if !Self::is_complete(self.flows.get(&key).expect("flow just inserted")) {
            return Ok(None);
        }
        let flow = self.flows.remove(&key).expect("complete flow exists");
        self.bytes -= flow.bytes;
        self.tombstone(
            key,
            now_ms.saturating_add(self.limits.timeout.as_millis() as u64),
        );
        Ok(Some(Self::assemble(flow)))
    }
    /// Drop expired sets and return how many expired. Does not complete a set.
    pub fn poll(&mut self, now_ms: u64) -> usize {
        self.sweep_expired(now_ms)
    }
    fn is_complete(flow: &Flow) -> bool {
        let Some(final_end) = flow.final_end else {
            return false;
        };
        let mut ranges: Vec<(u32, u32)> = flow.chunks.iter().map(|c| (c.offset, c.end)).collect();
        ranges.sort_unstable();
        let mut cursor = 0u32;
        for (start, end) in ranges {
            if start != cursor {
                return false;
            }
            cursor = end;
        }
        cursor == final_end
    }
    fn assemble(flow: Flow) -> Vec<u8> {
        let end = flow.final_end.expect("complete flow has an end");
        let mut out = vec![0u8; end as usize];
        let mut chunks = flow.chunks;
        chunks.sort_by_key(|c| c.offset);
        for chunk in chunks {
            let start = chunk.offset as usize;
            out[start..start + chunk.data.len()].copy_from_slice(&chunk.data);
        }
        out
    }
}

#[cfg(test)]
mod fragment_bounds {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(id: u32) -> FragmentKey {
        FragmentKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 20, 1, 1)),
            protocol: 17,
            identification: id,
        }
    }

    fn fill_edge(tracker: &mut FragmentTracker, n: usize) {
        let payload = [0u8; 8];
        for id in 0..n {
            assert_eq!(
                tracker.insert(key(id as u32), 0, &payload, true, 0),
                Ok(None)
            );
        }
    }

    #[test]
    fn role_zero_is_rejected_and_caps_are_hardcoded() {
        assert!(matches!(
            FragmentTracker::try_for_role(0),
            Err(Error::InvalidConfiguration)
        ));
        let edge = FragmentTracker::try_for_role(1).unwrap();
        assert_eq!(edge.limits.streams, 512);
        assert_eq!(edge.limits.global_bytes, 4 * 1024 * 1024);
        let core = FragmentTracker::try_for_role(2).unwrap();
        assert_eq!(core.limits.streams, 2048);
        assert_eq!(core.limits.global_bytes, 16 * 1024 * 1024);
        assert!(FragmentTracker::try_for_role(3).is_err());
    }

    #[test]
    fn edge_accepts_512_and_rejects_513_without_evicting() {
        let mut tracker = FragmentTracker::try_for_role(1).unwrap();
        fill_edge(&mut tracker, 512);
        assert_eq!(tracker.tracked_streams(), 512);
        assert_eq!(
            tracker.insert(key(512), 0, &[0u8; 8], true, 0),
            Err(Error::FragmentLimit)
        );
        assert_eq!(tracker.tracked_streams(), 512);
        assert_eq!(tracker.buffered_bytes(), 512 * 8);
        let tail = [1u8; 8];
        let done = tracker.insert(key(0), 8, &tail, false, 1).unwrap();
        assert_eq!(done, Some(vec![0u8; 8].into_iter().chain(tail).collect()));
        assert_eq!(tracker.tracked_streams(), 511);
        assert_eq!(tracker.buffered_bytes(), 511 * 8);
    }

    #[test]
    fn core_accepts_2048_and_rejects_2049() {
        let mut tracker = FragmentTracker::try_for_role(2).unwrap();
        let payload = [0u8; 8];
        for id in 0..2048u32 {
            tracker.insert(key(id), 0, &payload, true, 0).unwrap();
        }
        assert_eq!(tracker.tracked_streams(), 2048);
        assert_eq!(
            tracker.insert(key(2048), 0, &payload, true, 0),
            Err(Error::FragmentLimit)
        );
        assert_eq!(tracker.tracked_streams(), 2048);
        assert_eq!(tracker.buffered_bytes(), 2048 * 8);
    }

    #[test]
    fn overlap_drops_the_set_and_a_later_fragment_does_not_resurrect_it() {
        let mut tracker = FragmentTracker::try_for_role(1).unwrap();
        tracker.insert(key(1), 0, &[1u8; 8], true, 0).unwrap();
        assert_eq!(
            tracker.insert(key(1), 0, &[2u8; 8], true, 1),
            Err(Error::FragmentOverlap)
        );
        assert_eq!(tracker.tracked_streams(), 0);
        assert_eq!(tracker.buffered_bytes(), 0);
        assert_eq!(tracker.dropped_sets(), 1);
        assert_eq!(
            tracker.insert(key(1), 8, &[3u8; 8], false, 2),
            Err(Error::FragmentTimeout)
        );
        assert_eq!(tracker.tracked_streams(), 0);
        assert_eq!(tracker.buffered_bytes(), 0);
    }

    #[test]
    fn exact_duplicate_is_an_overlap() {
        let mut tracker = FragmentTracker::try_for_role(1).unwrap();
        let payload = [9u8; 8];
        tracker.insert(key(1), 0, &payload, true, 0).unwrap();
        assert_eq!(
            tracker.insert(key(1), 0, &payload, true, 1),
            Err(Error::FragmentOverlap)
        );
        assert_eq!(tracker.dropped_sets(), 1);
        assert_eq!(tracker.tracked_streams(), 0);
    }

    #[test]
    fn byte_65536_drops_the_whole_set() {
        let mut tracker = FragmentTracker::try_for_role(1).unwrap();
        tracker.insert(key(1), 0, &[0u8; 8], true, 0).unwrap();
        assert_eq!(
            tracker.insert(key(1), 65528, &[0u8; 8], true, 1),
            Err(Error::FragmentLimit)
        );
        assert_eq!(tracker.tracked_streams(), 0);
        assert_eq!(tracker.buffered_bytes(), 0);
        assert_eq!(tracker.dropped_sets(), 1);
        assert_eq!(
            tracker.insert(key(1), 8, &[0u8; 8], false, 3),
            Err(Error::FragmentTimeout)
        );
    }

    #[test]
    fn global_reserve_boundary_and_real_insert_reject() {
        assert!(!try_reserve(4 * 1024 * 1024 - 1, 4 * 1024 * 1024, 2));
        assert!(try_reserve(16 * 1024 * 1024, 16 * 1024 * 1024, 0));
        assert!(try_reserve(16 * 1024 * 1024 - 8, 16 * 1024 * 1024, 8));
        assert!(!try_reserve(16 * 1024 * 1024 - 8, 16 * 1024 * 1024, 9));
        assert!(!try_reserve(usize::MAX, 16 * 1024 * 1024, 1));

        let mut tracker = FragmentTracker::try_new(FragmentLimits {
            streams: 4,
            per_stream_bytes: 65_535,
            global_bytes: 24,
            timeout: Duration::from_secs(5),
        })
        .unwrap();
        tracker.insert(key(1), 0, &[1u8; 16], true, 0).unwrap();
        assert_eq!(tracker.buffered_bytes(), 16);
        assert_eq!(
            tracker.insert(key(2), 0, &[2u8; 16], true, 1),
            Err(Error::FragmentLimit)
        );
        assert_eq!(tracker.tracked_streams(), 1);
        assert_eq!(tracker.buffered_bytes(), 16);
        assert_eq!(tracker.dropped_sets(), 0);
        tracker.insert(key(2), 0, &[2u8; 8], true, 2).unwrap();
        assert_eq!(tracker.buffered_bytes(), 24);
        assert_eq!(tracker.tracked_streams(), 2);
    }

    #[test]
    fn expiry_at_5000_drops_and_4999_still_completes() {
        let mut dead = FragmentTracker::try_for_role(1).unwrap();
        dead.insert(key(1), 0, &[7u8; 8], true, 0).unwrap();
        assert_eq!(dead.poll(4999), 0);
        assert_eq!(dead.tracked_streams(), 1);
        assert_eq!(dead.poll(5000), 1);
        assert_eq!(dead.expired_sets(), 1);
        assert_eq!(dead.tracked_streams(), 0);
        assert_eq!(dead.buffered_bytes(), 0);
        assert_eq!(
            dead.insert(key(1), 8, &[8u8; 8], false, 5001),
            Err(Error::FragmentTimeout)
        );

        let mut live = FragmentTracker::try_for_role(1).unwrap();
        live.insert(key(2), 0, &[4u8; 8], true, 10).unwrap();
        let done = live.insert(key(2), 8, &[5u8; 8], false, 10 + 4999).unwrap();
        assert_eq!(
            done.unwrap(),
            vec![4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5]
        );
        assert_eq!(live.tracked_streams(), 0);
        assert_eq!(live.buffered_bytes(), 0);
        assert_eq!(live.expired_sets(), 0);
    }

    #[test]
    fn holes_wait_and_completion_frees_the_global_counter() {
        let mut tracker = FragmentTracker::try_for_role(1).unwrap();
        assert_eq!(tracker.insert(key(9), 8, &[2u8; 8], false, 0), Ok(None));
        assert_eq!(
            tracker.insert(key(9), 0, &[1u8; 8], true, 1),
            Ok(Some(vec![1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]))
        );
        assert_eq!(tracker.buffered_bytes(), 0);
        assert_eq!(tracker.tracked_streams(), 0);
    }
}
