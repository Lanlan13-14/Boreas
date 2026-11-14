//! Fail-closed IPv4/IPv6 UDP packet path for the DNS wire authority.
//!
//! This module deliberately has no socket or bind operation. The caller passes
//! complete packets from its TUN/user-space data path plus a source address
//! already bound to an authenticated Overlay peer. This is not TCP DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::AuthoritativeDns;

pub const DNS_PORT: u16 = 53;
pub const MIN_PACKET_MTU: usize = 1280;
pub const MAX_PACKET_MTU: usize = 65_535;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    Truncated,
    InvalidVersion,
    InvalidLength,
    InvalidHeaderChecksum,
    InvalidUdpChecksum,
    UnsupportedProtocol,
    Fragmented,
    UnsupportedExtension,
    InvalidAddress,
    UnauthorizedSource,
    InvalidPort,
    ResponseTooLarge,
}

/// Values copied from a validated, trusted genesis object and its DNS VIP
/// assignment. The constructor validates family and membership; signature,
/// epoch, and revocation validation remain the trust layer's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedDnsGenesis {
    ipv4_network: (Ipv4Addr, u8),
    ipv6_ula48: Ipv6Addr,
    dns_v4: Ipv4Addr,
    dns_v6: Ipv6Addr,
}

impl TrustedDnsGenesis {
    pub fn new(ipv4_network: (Ipv4Addr, u8), ipv6_ula48: Ipv6Addr, dns_v4: Ipv4Addr, dns_v6: Ipv6Addr) -> Result<Self, PacketError> {
            let (network, prefix) = ipv4_network;
        let expected_network = Ipv4Addr::new(10, 20, 0, 0);
        let expected_v6 = u128::from(ipv6_ula48).checked_add(0x53).ok_or(PacketError::InvalidAddress)?;
        if network != expected_network || prefix != 16 ||
            ipv4_value(dns_v4) != ipv4_value(expected_network) + 53 ||
            ipv6_ula48 != Ipv6Addr::new(
                ipv6_ula48.segments()[0], ipv6_ula48.segments()[1], ipv6_ula48.segments()[2], 0, 0, 0, 0, 0,
            ) || !is_ula48(ipv6_ula48) || u128::from(dns_v6) != expected_v6 {
            return Err(PacketError::InvalidAddress);
        }
        Ok(Self { ipv4_network, ipv6_ula48, dns_v4, dns_v6 })
    }

    pub const fn ipv4_network(self) -> (Ipv4Addr, u8) { self.ipv4_network }
    pub const fn ipv6_ula48(self) -> Ipv6Addr { self.ipv6_ula48 }
    pub const fn dns_v4(self) -> Ipv4Addr { self.dns_v4 }
    pub const fn dns_v6(self) -> Ipv6Addr { self.dns_v6 }
}

/// Explicit authenticated-peer binding supplied by the packet ingress owner.
/// It must be created only after the overlay has authenticated and authorized
/// the peer; an IP source field alone is not identity proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeerSource(IpAddr);

impl AuthenticatedPeerSource {
    /// Bind the source address from authenticated overlay peer state, not from
    /// the untrusted packet's source address.
    pub fn from_authenticated_overlay_peer(source: IpAddr) -> Result<Self, PacketError> {
        if source.is_unspecified() || source.is_multicast() || matches!(source, IpAddr::V4(a) if a == Ipv4Addr::BROADCAST) { return Err(PacketError::InvalidAddress); }
        Ok(Self(source))
    }

    pub const fn address(self) -> IpAddr { self.0 }
}

#[derive(Clone, Copy, Debug)]
pub struct PacketConfig {
    genesis: TrustedDnsGenesis,
    max_packet_bytes: usize,
}

impl PacketConfig {
    pub fn new(genesis: TrustedDnsGenesis, max_packet_bytes: usize) -> Result<Self, PacketError> {
        if !(MIN_PACKET_MTU..=MAX_PACKET_MTU).contains(&max_packet_bytes) { return Err(PacketError::InvalidLength); }
        Ok(Self { genesis, max_packet_bytes })
    }

    pub const fn dns_v4(self) -> Ipv4Addr { self.genesis.dns_v4 }
    pub const fn dns_v6(self) -> Ipv6Addr { self.genesis.dns_v6 }
}

/// Process one complete IPv4 or IPv6 packet. Returns a complete response IP
/// packet, or `None` when the DNS authority silently declines the message (for
/// example an unauthorized peer). IP fragments and IPv6 extension headers are
/// explicitly rejected, not reassembled or guessed at. There is no socket bind.
pub fn respond_packet(
    dns: &AuthoritativeDns,
    config: PacketConfig,
    authenticated_source: AuthenticatedPeerSource,
    packet: &[u8],
) -> Result<Option<Vec<u8>>, PacketError> {
    if packet.is_empty() { return Err(PacketError::Truncated); }
    if packet.len() > config.max_packet_bytes { return Err(PacketError::InvalidLength); }
    match packet[0] >> 4 {
        4 => respond_v4(dns, config, authenticated_source, packet),
        6 => respond_v6(dns, config, authenticated_source, packet),
        _ => Err(PacketError::InvalidVersion),
    }
}

fn respond_v4(dns: &AuthoritativeDns, cfg: PacketConfig, peer: AuthenticatedPeerSource, p: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    if p.len() < IPV4_HEADER_LEN { return Err(PacketError::Truncated); }
    if p[0] >> 4 != 4 { return Err(PacketError::InvalidVersion); }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl != IPV4_HEADER_LEN { return Err(PacketError::UnsupportedExtension); }
    let total = usize::from(be16(p, 2)?);
    if total != p.len() || total < ihl + UDP_HEADER_LEN { return Err(PacketError::InvalidLength); }
    if checksum(&p[..ihl]) != 0 { return Err(PacketError::InvalidHeaderChecksum); }
    if p[8] == 0 { return Err(PacketError::InvalidLength); }
    let frag = be16(p, 6)?;
    if frag & 0xbfff != 0 { return Err(PacketError::Fragmented); }
    if p[9] != 17 { return Err(PacketError::UnsupportedProtocol); }
    let src4 = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let src = IpAddr::V4(src4);
    let dst4 = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    if peer.0 != src { return Err(PacketError::UnauthorizedSource); }
    if dst4 != cfg.genesis.dns_v4 { return Err(PacketError::InvalidAddress); }
    let udp = &p[ihl..total];
    let (src_port, dst_port, dns_bytes) = validate_udp4(udp, src, dst4)?;
    if dst_port != DNS_PORT || src_port == 0 { return Err(PacketError::InvalidPort); }
    let response = match dns.respond_udp(src, dns_bytes).map_err(|_| PacketError::InvalidLength)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let out = build_v4(dst4, src4, dst_port, src_port, &response)?;
    if out.len() > cfg.max_packet_bytes { return Err(PacketError::ResponseTooLarge); }
    Ok(Some(out))
}

fn respond_v6(dns: &AuthoritativeDns, cfg: PacketConfig, peer: AuthenticatedPeerSource, p: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    if p.len() < IPV6_HEADER_LEN { return Err(PacketError::Truncated); }
    if p[0] >> 4 != 6 { return Err(PacketError::InvalidVersion); }
    let payload_len = usize::from(be16(p, 4)?);
    if payload_len == 0 || IPV6_HEADER_LEN + payload_len != p.len() || p[7] == 0 { return Err(PacketError::InvalidLength); }
    // Only direct UDP is supported. Fragment, routing, hop-by-hop, destination,
    // AH and all other extension chains are rejected by this exact match.
    if p[6] != 17 { return Err(if matches!(p[6], 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140) { PacketError::UnsupportedExtension } else { PacketError::UnsupportedProtocol }); }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).map_err(|_| PacketError::Truncated)?));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).map_err(|_| PacketError::Truncated)?);
    if peer.0 != src { return Err(PacketError::UnauthorizedSource); }
    if dst != cfg.genesis.dns_v6 { return Err(PacketError::InvalidAddress); }
    let udp = &p[IPV6_HEADER_LEN..];
    let (src_port, dst_port, dns_bytes) = validate_udp6(udp, match src { IpAddr::V6(a) => a, _ => unreachable!() }, dst)?;
    if dst_port != DNS_PORT || src_port == 0 { return Err(PacketError::InvalidPort); }
    let response = match dns.respond_udp(src, dns_bytes).map_err(|_| PacketError::InvalidLength)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let src6 = match src { IpAddr::V6(a) => a, _ => unreachable!() };
    let out = build_v6(dst, src6, dst_port, src_port, &response)?;
    if out.len() > cfg.max_packet_bytes { return Err(PacketError::ResponseTooLarge); }
    Ok(Some(out))
}

fn validate_udp4(udp: &[u8], src: IpAddr, dst: Ipv4Addr) -> Result<(u16, u16, &[u8]), PacketError> {
    if udp.len() < UDP_HEADER_LEN { return Err(PacketError::Truncated); }
    let len = usize::from(be16(udp, 4)?);
    if len != udp.len() || len < UDP_HEADER_LEN + 12 { return Err(PacketError::InvalidLength); }
    let check = be16(udp, 6)?;
    if check != 0 && udp_checksum_v4(src, IpAddr::V4(dst), udp) != 0 { return Err(PacketError::InvalidUdpChecksum); }
    Ok((be16(udp, 0)?, be16(udp, 2)?, &udp[UDP_HEADER_LEN..]))
}

fn validate_udp6(udp: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<(u16, u16, &[u8]), PacketError> {
    if udp.len() < UDP_HEADER_LEN { return Err(PacketError::Truncated); }
    let len = usize::from(be16(udp, 4)?);
    if len != udp.len() || len < UDP_HEADER_LEN + 12 { return Err(PacketError::InvalidLength); }
    if be16(udp, 6)? == 0 || udp_checksum_v6(src, dst, udp) != 0 { return Err(PacketError::InvalidUdpChecksum); }
    Ok((be16(udp, 0)?, be16(udp, 2)?, &udp[UDP_HEADER_LEN..]))
}

fn build_v4(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, dns: &[u8]) -> Result<Vec<u8>, PacketError> {
    let udp_len = UDP_HEADER_LEN.checked_add(dns.len()).ok_or(PacketError::ResponseTooLarge)?;
    let total = IPV4_HEADER_LEN.checked_add(udp_len).ok_or(PacketError::ResponseTooLarge)?;
    if udp_len > u16::MAX as usize || total > u16::MAX as usize { return Err(PacketError::ResponseTooLarge); }
    let mut out = vec![0u8; total];
    out[0] = 0x45; out[2..4].copy_from_slice(&(total as u16).to_be_bytes()); out[8] = 64; out[9] = 17;
    out[12..16].copy_from_slice(&src.octets()); out[16..20].copy_from_slice(&dst.octets());
    let hcheck = checksum(&out[..IPV4_HEADER_LEN]); out[10..12].copy_from_slice(&hcheck.to_be_bytes());
    out[20..22].copy_from_slice(&src_port.to_be_bytes()); out[22..24].copy_from_slice(&dst_port.to_be_bytes()); out[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[28..].copy_from_slice(dns);
    let check = udp_checksum_v4(IpAddr::V4(src), IpAddr::V4(dst), &out[20..]);
    // IPv4 UDP zero means checksum omitted; encode a computed zero as all ones.
    out[26..28].copy_from_slice(&(if check == 0 { 0xffff } else { check }).to_be_bytes());
    Ok(out)
}

fn build_v6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, dns: &[u8]) -> Result<Vec<u8>, PacketError> {
    let udp_len = UDP_HEADER_LEN.checked_add(dns.len()).ok_or(PacketError::ResponseTooLarge)?;
    if udp_len > u16::MAX as usize { return Err(PacketError::ResponseTooLarge); }
    let total = IPV6_HEADER_LEN.checked_add(udp_len).ok_or(PacketError::ResponseTooLarge)?;
    let mut out = vec![0u8; total];
    out[0] = 0x60; out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); out[6] = 17; out[7] = 64;
    out[8..24].copy_from_slice(&src.octets()); out[24..40].copy_from_slice(&dst.octets());
    out[40..42].copy_from_slice(&src_port.to_be_bytes()); out[42..44].copy_from_slice(&dst_port.to_be_bytes()); out[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[48..].copy_from_slice(dns);
    let check = udp_checksum_v6(src, dst, &out[40..]);
    out[46..48].copy_from_slice(&(if check == 0 { 0xffff } else { check }).to_be_bytes());
    Ok(out)
}

fn ipv4_value(a: Ipv4Addr) -> u32 { u32::from(a) }
fn is_ula48(a: Ipv6Addr) -> bool { let n = u128::from(a); (n >> 120) == 0xfd && n & ((1u128 << 80) - 1) == 0 }
fn be16(p: &[u8], at: usize) -> Result<u16, PacketError> { let b = p.get(at..at.checked_add(2).ok_or(PacketError::InvalidLength)?).ok_or(PacketError::Truncated)?; Ok(u16::from_be_bytes([b[0], b[1]])) }

fn checksum(data: &[u8]) -> u16 { let mut sum = 0u32; let mut chunks = data.chunks_exact(2); for c in &mut chunks { sum += u32::from(u16::from_be_bytes([c[0], c[1]])); } if let Some(&b) = chunks.remainder().first() { sum += u32::from(b) << 8; } fold(sum) }
fn checksum_add(mut sum: u32, data: &[u8]) -> u32 { let mut chunks = data.chunks_exact(2); for c in &mut chunks { sum += u32::from(u16::from_be_bytes([c[0], c[1]])); } if let Some(&b) = chunks.remainder().first() { sum += u32::from(b) << 8; } sum }
fn fold(mut sum: u32) -> u16 { while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); } !(sum as u16) }
fn udp_checksum_v4(src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 { let (a,b) = match (src,dst) { (IpAddr::V4(a),IpAddr::V4(b)) => (a.octets(),b.octets()), _ => return 0 }; let mut sum=0; sum=checksum_add(sum,&a);sum=checksum_add(sum,&b);sum=checksum_add(sum,&[0,17]);sum=checksum_add(sum,&(udp.len() as u16).to_be_bytes());fold(checksum_add(sum,udp)) }
fn udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 { let mut sum=0;sum=checksum_add(sum,&src.octets());sum=checksum_add(sum,&dst.octets());sum=checksum_add(sum,&(udp.len() as u32).to_be_bytes());sum=checksum_add(sum,&[0,0,0,17]);fold(checksum_add(sum,udp)) }
