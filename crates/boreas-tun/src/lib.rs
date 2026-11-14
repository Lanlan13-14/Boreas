//! Bounded, platform-neutral packet I/O and L3 validation primitives.
//! This crate deliberately does not claim to implement or validate a real Linux TUN device.
#![forbid(unsafe_code)]

pub mod icmp;
#[cfg(target_os = "linux")]
pub mod linux;

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

/// Four-dimensional fragment accounting. This tracker observes ranges only: L3 authorization must
/// independently validate src/dst on every fragment and does not require reassembly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FragmentKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub identification: u32,
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
struct Flow {
    ranges: Vec<(u32, u32)>,
    bytes: usize,
    created: Instant,
    final_end: Option<u32>,
}
pub struct FragmentTracker {
    limits: FragmentLimits,
    flows: HashMap<FragmentKey, Flow>,
    tombstones: HashMap<FragmentKey, Instant>,
    bytes: usize,
}
impl FragmentTracker {
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
        Ok(Self {
            limits,
            flows: HashMap::new(),
            tombstones: HashMap::new(),
            bytes: 0,
        })
    }
    pub fn new(limits: FragmentLimits) -> Self {
        Self::try_new(limits).expect("FragmentTracker requires protocol-bounded limits")
    }
    pub fn tracked_streams(&self) -> usize {
        self.flows.len()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }
    fn tombstone(&mut self, key: FragmentKey, until: Instant) {
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
        self.tombstones.insert(key, until);
    }
    fn discard(&mut self, key: FragmentKey, now: Instant) {
        if let Some(f) = self.flows.remove(&key) {
            self.bytes -= f.bytes
        }
        self.tombstone(key, now + self.limits.timeout);
    }
    pub fn expire(&mut self, now: Instant) -> usize {
        let old: Vec<_> = self
            .flows
            .iter()
            .filter_map(|(k, v)| {
                (now.saturating_duration_since(v.created) >= self.limits.timeout).then_some(*k)
            })
            .collect();
        for k in &old {
            self.discard(*k, now)
        }
        self.tombstones.retain(|_, until| *until > now);
        old.len()
    }
    /// Observe one IP fragment and reject overlaps. `now` is injectable for deterministic timeout tests.
    pub fn observe(
        &mut self,
        key: FragmentKey,
        offset: u32,
        len: usize,
        more: bool,
        now: Instant,
    ) -> Result<(), Error> {
        self.expire(now);
        if self.tombstones.contains_key(&key) {
            return Err(Error::FragmentTimeout);
        }
        let end = offset
            .checked_add(u32::try_from(len).map_err(|_| Error::FragmentMalformed)?)
            .ok_or(Error::FragmentMalformed)?;
        if len == 0
            || end > 65_535
            || (offset != 0 && !offset.is_multiple_of(8))
            || (more && !len.is_multiple_of(8))
        {
            return Err(Error::FragmentMalformed);
        }
        if !self.flows.contains_key(&key) && self.flows.len() >= self.limits.streams {
            return Err(Error::FragmentLimit);
        }
        let current = self.flows.get(&key);
        let oldbytes = current.map_or(0, |f| f.bytes);
        let total = oldbytes.checked_add(len).ok_or(Error::FragmentLimit)?;
        if total > self.limits.per_stream_bytes
            || self.bytes - oldbytes + total > self.limits.global_bytes
        {
            self.discard(key, now);
            return Err(Error::FragmentLimit);
        }
        if let Some(f) = self.flows.get(&key)
            && (f.ranges.iter().any(|(a, b)| offset < *b && *a < end)
                || f.final_end
                    .is_some_and(|x| end > x || (!more && end != x) || (more && end >= x))
                || (!more && f.ranges.iter().any(|(_, b)| *b > end)))
        {
            self.discard(key, now);
            return Err(Error::FragmentOverlap);
        }
        let f = self.flows.entry(key).or_insert_with(|| Flow {
            ranges: Vec::new(),
            bytes: 0,
            created: now,
            final_end: None,
        });
        f.ranges.push((offset, end));
        f.bytes += len;
        if !more {
            f.final_end = Some(end)
        }
        self.bytes += len;
        let _ = f;
        let complete = if let Some(flow) = self.flows.get(&key) {
            if let Some(final_end) = flow.final_end {
                let mut ranges = flow.ranges.clone();
                ranges.sort_unstable();
                let mut cursor = 0;
                let mut contiguous = true;
                for (a, b) in ranges {
                    if a != cursor {
                        contiguous = false;
                        break;
                    }
                    cursor = b
                }
                contiguous && cursor == final_end
            } else {
                false
            }
        } else {
            false
        };
        if complete {
            self.flows.remove(&key);
            self.bytes -= total;
            self.tombstones.insert(key, now + self.limits.timeout);
        }
        Ok(())
    }
}
