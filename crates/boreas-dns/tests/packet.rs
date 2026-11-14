use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use boreas_dns::packet::{
    AuthenticatedPeerSource, PacketConfig, PacketError, TrustedDnsGenesis, respond_packet,
};
use boreas_dns::{AuthoritativeDns, SourceAuthorization, Zone};

const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const DNS4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 53);
const DNS6_PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 0);
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 2);
const DNS6: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 0x53);

fn setup() -> (AuthoritativeDns, PacketConfig) {
    let genesis =
        TrustedDnsGenesis::new((Ipv4Addr::new(10, 20, 0, 0), 16), DNS6_PREFIX, DNS4, DNS6).unwrap();
    let config = PacketConfig::new(genesis, 1500).unwrap();
    let mut zone = Zone::new("corp.example").unwrap();
    zone.add_address(
        "host.corp.example",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
    )
    .unwrap();
    let dns = AuthoritativeDns::new(
        zone,
        SourceAuthorization::new([IpAddr::V4(CLIENT4), IpAddr::V6(CLIENT6)]),
        1232,
    )
    .unwrap();
    (dns, config)
}

fn peer(addr: IpAddr) -> AuthenticatedPeerSource {
    AuthenticatedPeerSource::from_authenticated_overlay_peer(addr).unwrap()
}
fn query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(&[
        4, b'h', b'o', b's', b't', 4, b'c', b'o', b'r', b'p', 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 0, 0, 1, 0, 1,
    ]);
    q
}
fn ip_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn pseudo_udp_v4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut data = Vec::new();
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(&[0, 17]);
    data.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    data.extend_from_slice(udp);
    if data.len() % 2 != 0 {
        data.push(0);
    }
    ip_checksum(&data)
}
fn pseudo_udp_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut data = Vec::new();
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, 17]);
    data.extend_from_slice(udp);
    if data.len() % 2 != 0 {
        data.push(0);
    }
    ip_checksum(&data)
}
fn packet4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, dns: &[u8]) -> Vec<u8> {
    let ulen = 8 + dns.len();
    let mut p = vec![0u8; 20 + ulen];
    let total = p.len() as u16;
    p[0] = 0x45;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let hc = ip_checksum(&p[..20]);
    p[10..12].copy_from_slice(&hc.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&(ulen as u16).to_be_bytes());
    p[28..].copy_from_slice(dns);
    let c = pseudo_udp_v4(src, dst, &p[20..]);
    p[26..28].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    p
}
fn packet6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, dns: &[u8]) -> Vec<u8> {
    let ulen = 8 + dns.len();
    let mut p = vec![0u8; 40 + ulen];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(ulen as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..42].copy_from_slice(&sport.to_be_bytes());
    p[42..44].copy_from_slice(&dport.to_be_bytes());
    p[44..46].copy_from_slice(&(ulen as u16).to_be_bytes());
    p[48..].copy_from_slice(dns);
    let c = pseudo_udp_v6(src, dst, &p[40..]);
    p[46..48].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    p
}

#[test]
fn ipv4_reply_reverses_tuple_and_checksums() {
    let (dns, cfg) = setup();
    let request = packet4(CLIENT4, DNS4, 53001, 53, &query());
    let reply = respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &request)
        .unwrap()
        .unwrap();
    assert_eq!(&reply[12..16], &DNS4.octets());
    assert_eq!(&reply[16..20], &CLIENT4.octets());
    assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 53);
    assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 53001);
    assert_eq!(ip_checksum(&reply[..20]), 0);
    assert_eq!(pseudo_udp_v4(DNS4, CLIENT4, &reply[20..]), 0);
    assert_eq!(reply[9], 17);
    assert_eq!(reply[8], 64);
}

#[test]
fn ipv6_reply_reverses_tuple_and_checksum_is_mandatory() {
    let (dns, cfg) = setup();
    let request = packet6(CLIENT6, DNS6, 53002, 53, &query());
    let reply = respond_packet(&dns, cfg, peer(IpAddr::V6(CLIENT6)), &request)
        .unwrap()
        .unwrap();
    assert_eq!(&reply[8..24], &DNS6.octets());
    assert_eq!(&reply[24..40], &CLIENT6.octets());
    assert_eq!(u16::from_be_bytes([reply[40], reply[41]]), 53);
    assert_eq!(u16::from_be_bytes([reply[42], reply[43]]), 53002);
    assert_eq!(pseudo_udp_v6(DNS6, CLIENT6, &reply[40..]), 0);
    let mut bad = request;
    bad[46] = 0;
    bad[47] = 0;
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V6(CLIENT6)), &bad),
        Err(PacketError::InvalidUdpChecksum)
    );
}

#[test]
fn ipv4_accepts_omitted_udp_checksum_but_rejects_bad_nonzero_checksum() {
    let (dns, cfg) = setup();
    let mut request = packet4(CLIENT4, DNS4, 53003, 53, &query());
    request[26] = 0;
    request[27] = 0;
    assert!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &request)
            .unwrap()
            .is_some()
    );
    request[26] = 0xff;
    request[27] = 0xff;
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &request),
        Err(PacketError::InvalidUdpChecksum)
    );
}

#[test]
fn drops_fragmented_or_extended_packets_and_bad_lengths() {
    let (dns, cfg) = setup();
    let mut v4 = packet4(CLIENT4, DNS4, 53004, 53, &query());
    v4[6] = 0x20;
    v4[7] = 0;
    v4[10] = 0;
    v4[11] = 0;
    let hc = ip_checksum(&v4[..20]);
    v4[10..12].copy_from_slice(&hc.to_be_bytes());
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &v4),
        Err(PacketError::Fragmented)
    );
    let mut v6 = packet6(CLIENT6, DNS6, 53004, 53, &query());
    v6[6] = 44;
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V6(CLIENT6)), &v6),
        Err(PacketError::UnsupportedExtension)
    );
    let mut v6 = packet6(CLIENT6, DNS6, 53004, 53, &query());
    v6[5] ^= 1;
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V6(CLIENT6)), &v6),
        Err(PacketError::InvalidLength)
    );
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &[]),
        Err(PacketError::Truncated)
    );
}

#[test]
fn authentic_peer_binding_vip_port_and_authority_all_gate_synthesis() {
    let (dns, cfg) = setup();
    let p = packet4(CLIENT4, DNS4, 53005, 53, &query());
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 3))), &p),
        Err(PacketError::UnauthorizedSource)
    );
    let p = packet4(CLIENT4, Ipv4Addr::new(10, 20, 0, 54), 53005, 53, &query());
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &p),
        Err(PacketError::InvalidAddress)
    );
    let p = packet4(CLIENT4, DNS4, 53005, 5353, &query());
    assert_eq!(
        respond_packet(&dns, cfg, peer(IpAddr::V4(CLIENT4)), &p),
        Err(PacketError::InvalidPort)
    );
    assert_eq!(
        AuthenticatedPeerSource::from_authenticated_overlay_peer(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Err(PacketError::InvalidAddress)
    );
}

#[test]
fn rejects_invalid_genesis_vips_and_mtu() {
    assert_eq!(
        TrustedDnsGenesis::new((Ipv4Addr::new(10, 20, 1, 0), 16), DNS6_PREFIX, DNS4, DNS6),
        Err(PacketError::InvalidAddress)
    );
    assert!(
        PacketConfig::new(
            TrustedDnsGenesis::new((Ipv4Addr::new(10, 20, 0, 0), 16), DNS6_PREFIX, DNS4, DNS6)
                .unwrap(),
            575
        )
        .is_err()
    );
}
