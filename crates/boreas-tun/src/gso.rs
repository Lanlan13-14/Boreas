//! Bounded software segmentation of a strict subset of Linux TUN TCPv4 GSO.
//!
//! Linux's `virtio_net_hdr_from_skb` can emit a linear-head-length hint, not
//! the exact header size. This API deliberately requires an exact match and
//! derives the split point from the packet, never from that hint. This module
//! does not configure TUN, authorize offload, or negotiate a wire feature.

use std::{fmt, slice::Chunks};

use crate::{
    MAX_IP_PACKET, checksum,
    virtio::{GSO_TCPV4, VIRTIO_HDR_LEN},
};

/// Maximum L3 superpacket length, excluding the 10-byte virtio header.
pub const MAX_SUPERPACKET: usize = 64_000;
/// Hard limit on output packets per call.
pub const MAX_SEGMENTS: usize = 64;
/// Hard limit on aggregate L3 output bytes, including replicated headers.
/// This is a scratch-space budget, not a tunnel body limit.
pub const MAX_OUTPUT_BYTES: usize = 67_200;

const IPV4_LEN: usize = 20;
const TCP_MIN_LEN: usize = 20;
const TCP_PROTOCOL: u8 = 6;
const TCP_CHECK_OFFSET: usize = 16;
const TCP_CHECK: usize = IPV4_LEN + TCP_CHECK_OFFSET;
const NEEDS_CSUM: u8 = 1;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GsoError {
    TruncatedVirtio,
    UnsupportedVirtio,
    InvalidMetadata,
    SuperpacketTooLarge,
    InvalidIpv4,
    InvalidTcp,
    InvalidChecksum,
    NotSuperpacket,
    InvalidMtu,
    SegmentExceedsMtu,
    SegmentLimit,
    OutputLimit,
    ScratchTooSmall { needed: usize },
}

impl fmt::Display for GsoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GsoError {}

/// Split a 10-byte little-endian virtio header followed by exactly one L3
/// superpacket (no PI, Ethernet, or extended virtio header). Only bare TCPv4
/// with `NEEDS_CSUM`, exact offsets, and at least two data segments is accepted.
/// IPv4 options, fragments, TCP ECN/control flags other than ACK/PSH/FIN,
/// and TCP options other than padding and one Timestamp are not supported.
/// The input IPv4 checksum and standard partial TCP pseudo-header seed must
/// match; neither validates the input TCP payload. Both output checksums
/// are recomputed, without using the input seed.
///
/// `mtu` is the caller's L3 egress ceiling (68..=65535); an MSS that would
/// exceed it is rejected, not rewritten. The result borrows contiguous caller
/// scratch and yields complete bare IPv4 packets in order. No allocation is
/// performed. On error scratch is untouched; on success only the exact used
/// prefix is written. No packet may be forwarded on error.
pub fn segment_tcpv4<'out>(
    frame: &[u8],
    mtu: usize,
    scratch: &'out mut [u8],
) -> Result<Chunks<'out, u8>, GsoError> {
    let (meta, packet) = frame
        .split_at_checked(VIRTIO_HDR_LEN)
        .ok_or(GsoError::TruncatedVirtio)?;
    if packet.len() > MAX_SUPERPACKET {
        return Err(GsoError::SuperpacketTooLarge);
    }
    if meta[0] != NEEDS_CSUM || meta[1] != GSO_TCPV4 {
        return Err(GsoError::UnsupportedVirtio);
    }
    let mss = usize::from(read_le16(meta, 4));
    if mss == 0
        || usize::from(read_le16(meta, 6)) != IPV4_LEN
        || usize::from(read_le16(meta, 8)) != TCP_CHECK_OFFSET
    {
        return Err(GsoError::InvalidMetadata);
    }
    if packet.len() < IPV4_LEN
        || packet[0] != 0x45
        || packet[9] != TCP_PROTOCOL
        || usize::from(read_be16(packet, 2)) != packet.len()
        || read_be16(packet, 6) & !0x4000 != 0
    {
        return Err(GsoError::InvalidIpv4);
    }
    let tcp = &packet[IPV4_LEN..];
    if tcp.len() < TCP_MIN_LEN {
        return Err(GsoError::InvalidTcp);
    }
    let tcp_len = usize::from(tcp[12] >> 4) * 4;
    let flags = tcp[13];
    if !(TCP_MIN_LEN..=tcp.len()).contains(&tcp_len)
        || read_be16(tcp, 0) == 0
        || read_be16(tcp, 2) == 0
        || tcp[12] & 0x0f != 0
        || flags & ACK == 0
        || flags & !(ACK | PSH | FIN) != 0
        || read_be16(tcp, 18) != 0
    {
        return Err(GsoError::InvalidTcp);
    }
    let hdr_len = IPV4_LEN + tcp_len;
    if usize::from(read_le16(meta, 2)) != hdr_len {
        return Err(GsoError::InvalidMetadata);
    }
    let (header, payload) = packet.split_at(hdr_len);
    if !tcp_options_supported(&tcp[TCP_MIN_LEN..tcp_len]) {
        return Err(GsoError::InvalidTcp);
    }
    if checksum(&packet[..IPV4_LEN]) != 0 || read_be16(packet, TCP_CHECK) != pseudo_sum(packet) {
        return Err(GsoError::InvalidChecksum);
    }
    if payload.len() <= mss {
        return Err(GsoError::NotSuperpacket);
    }
    if !(68..=MAX_IP_PACKET).contains(&mtu) {
        return Err(GsoError::InvalidMtu);
    }
    let stride = hdr_len + mss;
    if stride > mtu {
        return Err(GsoError::SegmentExceedsMtu);
    }
    let segments = payload.len().div_ceil(mss);
    if segments > MAX_SEGMENTS {
        return Err(GsoError::SegmentLimit);
    }
    // hdr_len <= 80, segments <= MAX_SEGMENTS, payload.len() <= MAX_SUPERPACKET.
    let needed = hdr_len * segments + payload.len();
    if needed > MAX_OUTPUT_BYTES {
        return Err(GsoError::OutputLimit);
    }
    let out = scratch
        .get_mut(..needed)
        .ok_or(GsoError::ScratchTooSmall { needed })?;

    let id = read_be16(packet, 4);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    // Both iterators have `segments` chunks. The last output chunk has
    // exactly one header plus the remaining payload, even on an exact MSS multiple.
    for (i, (segment, data)) in out.chunks_mut(stride).zip(payload.chunks(mss)).enumerate() {
        segment[..hdr_len].copy_from_slice(header);
        segment[hdr_len..].copy_from_slice(data);
        let len = segment.len() as u16;
        segment[2..4].copy_from_slice(&len.to_be_bytes());
        // The base virtio header carries no fixed-ID mode. Use the default
        // sequential IDs; preserve DF, which also makes IDs immaterial for
        // atomic datagrams.
        segment[4..6].copy_from_slice(&id.wrapping_add(i as u16).to_be_bytes());
        let seq = seq.wrapping_add((i * mss) as u32);
        segment[24..28].copy_from_slice(&seq.to_be_bytes());
        if i + 1 != segments {
            segment[33] &= !(PSH | FIN);
        }
        segment[10..12].fill(0);
        let ip_check = checksum(&segment[..IPV4_LEN]);
        segment[10..12].copy_from_slice(&ip_check.to_be_bytes());
        segment[TCP_CHECK..TCP_CHECK + 2].fill(0);
        let tcp_check = tcp_checksum(segment);
        segment[TCP_CHECK..TCP_CHECK + 2].copy_from_slice(&tcp_check.to_be_bytes());
    }
    Ok(out.chunks(stride))
}

fn read_le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn tcp_options_supported(mut options: &[u8]) -> bool {
    let mut timestamp = false;
    while let Some((&kind, rest)) = options.split_first() {
        match kind {
            0 => return rest.iter().all(|&byte| byte == 0),
            1 => options = rest,
            8 if !timestamp && rest.first() == Some(&10) => {
                let Some(next) = options.get(10..) else {
                    return false;
                };
                timestamp = true;
                options = next;
            }
            _ => return false,
        }
    }
    true
}

fn pseudo_sum(packet: &[u8]) -> u16 {
    let mut pseudo = [0; 12];
    pseudo[..8].copy_from_slice(&packet[12..20]);
    pseudo[9] = TCP_PROTOCOL;
    pseudo[10..].copy_from_slice(&((packet.len() - IPV4_LEN) as u16).to_be_bytes());
    !checksum(&pseudo)
}

fn tcp_checksum(packet: &[u8]) -> u16 {
    // Start with the folded pseudo-header sum; the TCP checksum field is zero.
    // At most 64,000 input bytes, so even an unfolded sum fits in u32.
    let mut sum = u32::from(pseudo_sum(packet));
    let (words, remainder) = packet[IPV4_LEN..].as_chunks::<2>();
    if let [tail] = remainder {
        sum += u32::from(*tail) << 8;
    }
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests;
