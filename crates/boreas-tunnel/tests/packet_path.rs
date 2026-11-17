//! Integration coverage for the E2E packet-stream adapter's public surface.
//!
//! These tests use the real `boreas_tun::VirtualTun` endpoints and real,
//! checksummed IP packets. They exercise the pure point-to-point model, the
//! candidate framing and both `PacketIo` directions.
//!
//! They do **not** exercise the token-gated `PacketPath` constructor: reaching it
//! requires a completed E2E TLS handshake plus the encrypted application
//! confirmation, which needs the `openssl-inner-tls` backend and a real
//! certificate fixture. The in-crate `packet_path` tests drive that constructor's
//! pump over the same real `VirtualTun` API. Nothing here is production,
//! `G-DATA`, `G-E2E` or 1 GiB acceptance evidence.

use std::net::Ipv4Addr;

use boreas_tun::{Error as TunError, IpVersion, PacketIo, VirtualTun, inspect_packet};
use boreas_tunnel::packet_path::{
    DEFAULT_MTU, FRAME_PREFIX_LEN, MAX_FRAME_BYTES, MAX_MTU, MIN_MTU, PacketDeny, PacketPathError,
    PointToPoint, decode_packet_frame, encode_packet_frame,
};

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 20, 3, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 20, 3, 9);

fn checksum_value(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += if chunk.len() == 2 {
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u32::from(chunk[0]) << 8
        };
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4/UDP packet with a correct header checksum.
fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total).expect("bounded").to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..].copy_from_slice(payload);
    let checksum = checksum_value(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Rewrite the header checksum after the caller changed a header field.
fn repair_checksum(packet: &mut [u8]) {
    packet[10] = 0;
    packet[11] = 0;
    let checksum = checksum_value(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// One IPv6 packet: 40-byte header, no payload, no next header.
fn ipv6(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src);
    packet[24..40].copy_from_slice(&dst);
    packet
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn policy() -> PointToPoint {
    PointToPoint::try_new(LOCAL, PEER, DEFAULT_MTU).expect("canonical permanent pair")
}

#[test]
fn point_to_point_model_refuses_anything_but_two_permanent_vips() {
    let policy = policy();
    assert_eq!(policy.local_vip(), LOCAL);
    assert_eq!(policy.peer_vip(), PEER);
    assert_eq!(policy.mtu(), DEFAULT_MTU);
    assert_eq!(policy.max_frame(), FRAME_PREFIX_LEN + DEFAULT_MTU);
    assert_eq!(MAX_FRAME_BYTES, FRAME_PREFIX_LEN + MAX_MTU);

    for address in [
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(10, 20, 3, 0),
        Ipv4Addr::new(10, 20, 3, 255),
        Ipv4Addr::new(10, 20, 17, 1),
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 21, 3, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert_eq!(
            PointToPoint::try_new(address, PEER, DEFAULT_MTU),
            Err(PacketPathError::InvalidEndpointVip),
            "{address}"
        );
        assert_eq!(
            PointToPoint::try_new(LOCAL, address, DEFAULT_MTU),
            Err(PacketPathError::InvalidEndpointVip),
            "{address}"
        );
    }
    assert_eq!(
        PointToPoint::try_new(LOCAL, LOCAL, DEFAULT_MTU),
        Err(PacketPathError::SelfPair)
    );
    for mtu in [MIN_MTU - 1, 0, MAX_MTU + 1] {
        assert_eq!(
            PointToPoint::try_new(LOCAL, PEER, mtu),
            Err(PacketPathError::MtuOutOfRange),
            "{mtu}"
        );
    }
    assert!(PointToPoint::try_new(LOCAL, PEER, MIN_MTU).is_ok());
    assert!(PointToPoint::try_new(LOCAL, PEER, MAX_MTU).is_ok());
}

#[test]
fn pure_policy_supports_shared_private_prefixes_but_rejects_public_or_mixed_pairs() {
    // This constructs only a pure model; the production path still requires
    // an authenticated E2E circuit and matching signed-policy digests.
    for (a, b) in [(10, 21), (172, 19), (192, 168)] {
        let local = Ipv4Addr::new(a, b, 3, 1);
        let peer = Ipv4Addr::new(a, b, 3, 9);
        let model = PointToPoint::try_new(local, peer, DEFAULT_MTU).unwrap();
        assert_eq!(model.local_vip(), local);
        assert_eq!(model.peer_vip(), peer);
        let packet = ipv4(local.octets(), peer.octets(), b"private-policy");
        assert!(model.authorize_outbound(&packet).is_ok());
    }
    for (local, peer) in [
        (Ipv4Addr::new(1, 1, 1, 1), PEER),
        (LOCAL, Ipv4Addr::new(8, 8, 3, 9)),
        (LOCAL, Ipv4Addr::new(10, 21, 3, 9)),
        (Ipv4Addr::new(100, 64, 3, 1), Ipv4Addr::new(100, 64, 3, 9)),
    ] {
        assert_eq!(
            PointToPoint::try_new(local, peer, DEFAULT_MTU),
            Err(PacketPathError::InvalidEndpointVip)
        );
    }
}

#[test]
fn real_virtual_tun_transports_one_authorized_packet_with_valid_checksum() {
    let mtu = DEFAULT_MTU;
    let policy = policy();
    // `device` is the tunnel-side endpoint. `inject` feeds its reader with a
    // packet the local host stack emitted; `write_packet` on it lands in the peer
    // endpoint's queue, which is where the host stack consumes delivery.
    let (device, host) = VirtualTun::try_pair(4, 4, mtu).expect("bounded pair");

    let outbound = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"outbound-payload");
    let inbound = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"inbound-payload");
    for packet in [&outbound, &inbound] {
        let info = inspect_packet(packet).expect("strictly valid packet");
        assert_eq!(info.version, IpVersion::V4);
        assert_eq!(info.packet_len, packet.len());
        assert_eq!(info.header_len, 20);
    }

    // Host stack -> wire.
    device.inject(&outbound).expect("valid host packet");
    let host_packet = device
        .read_packet()
        .expect("host endpoint readable")
        .expect("one packet was injected");
    assert_eq!(host_packet, outbound);
    assert_eq!(
        policy
            .authorize_outbound(&host_packet)
            .map(|info| info.packet_len),
        Ok(outbound.len())
    );
    let frame = encode_packet_frame(&host_packet, mtu).expect("one frame");
    assert_eq!(frame.len(), FRAME_PREFIX_LEN + outbound.len());
    let wire = decode_packet_frame(&frame, mtu).expect("one packet per frame");
    assert_eq!(wire, outbound.as_slice());
    assert_eq!(fnv1a_64(wire), fnv1a_64(&outbound));

    // Wire -> host stack.
    assert_eq!(
        policy
            .authorize_inbound(&inbound)
            .map(|info| info.packet_len),
        Ok(inbound.len())
    );
    let frame = encode_packet_frame(&inbound, mtu).expect("one frame");
    let received = decode_packet_frame(&frame, mtu).expect("one packet per frame");
    device.write_packet(received).expect("host queue has room");
    let delivered = host
        .read_packet()
        .expect("host readable")
        .expect("one packet");
    assert_eq!(delivered, inbound);
    assert_eq!(fnv1a_64(&delivered), fnv1a_64(&inbound));
    assert_eq!(
        inspect_packet(&delivered).map(|info| info.destination),
        Ok(std::net::IpAddr::V4(LOCAL))
    );
    assert_eq!(host.read_packet(), Ok(None), "exactly one packet per call");
}

#[test]
fn spoofed_source_destination_and_third_party_addresses_are_denied() {
    let policy = policy();

    let third_party = ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"spoofed-source");
    assert_eq!(
        policy.authorize_outbound(&third_party),
        Err(PacketDeny::SourceNotLocal)
    );
    let to_third_party = ipv4([10, 20, 3, 1], [10, 20, 3, 7], b"third-party");
    assert_eq!(
        policy.authorize_outbound(&to_third_party),
        Err(PacketDeny::DestinationNotPeer)
    );
    // Default route, subnet broadcast and multicast are not third parties either.
    for destination in [
        [0, 0, 0, 0],
        [10, 20, 3, 255],
        [10, 20, 3, 0],
        [224, 0, 0, 1],
        [10, 21, 3, 9],
    ] {
        let packet = ipv4([10, 20, 3, 1], destination, b"not-peer");
        assert_eq!(
            policy.authorize_outbound(&packet),
            Err(PacketDeny::DestinationNotPeer),
            "{destination:?}"
        );
    }
    // Inbound traffic must come from the peer and be addressed to the local VIP.
    let wrong_source = ipv4([10, 20, 3, 7], [10, 20, 3, 1], b"wrong-source");
    assert_eq!(
        policy.authorize_inbound(&wrong_source),
        Err(PacketDeny::SourceNotPeer)
    );
    let wrong_destination = ipv4([10, 20, 3, 9], [10, 20, 3, 7], b"wrong-destination");
    assert_eq!(
        policy.authorize_inbound(&wrong_destination),
        Err(PacketDeny::DestinationNotLocal)
    );
    // The same packet is not authorized in both directions.
    let peer_packet = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"peer");
    assert_eq!(
        policy.authorize_outbound(&peer_packet),
        Err(PacketDeny::SourceNotLocal)
    );
    assert!(policy.authorize_inbound(&peer_packet).is_ok());
}

#[test]
fn oversize_truncated_corrupt_and_unknown_version_are_denied() {
    let mtu = DEFAULT_MTU;
    let policy = policy();
    let (device, _host) = VirtualTun::try_pair(2, 2, mtu).expect("bounded pair");

    // 1600 bytes: structurally valid, over the negotiated MTU.
    let oversize = ipv4([10, 20, 3, 1], [10, 20, 3, 9], &[0u8; 1580]);
    assert_eq!(oversize.len(), 1600);
    assert!(inspect_packet(&oversize).is_ok());
    assert_eq!(
        policy.authorize_outbound(&oversize),
        Err(PacketDeny::MtuExceeded)
    );
    assert!(matches!(
        device.inject(&oversize),
        Err(TunError::PacketTooLarge { mtu: 1500 })
    ));
    assert_eq!(
        encode_packet_frame(&oversize, mtu),
        Err(PacketPathError::Denied(PacketDeny::MtuExceeded))
    );

    // Declared length disagrees with the slice.
    let mut truncated = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"truncate-me");
    truncated.truncate(truncated.len() - 3);
    assert_eq!(
        policy.authorize_outbound(&truncated),
        Err(PacketDeny::BadLength)
    );
    assert!(device.inject(&truncated).is_err());

    // Header cut off inside the minimum IPv4 header.
    let short = vec![0x45u8; 12];
    assert_eq!(
        policy.authorize_outbound(&short),
        Err(PacketDeny::Truncated)
    );
    assert!(device.inject(&short).is_err());

    // Bad header checksum.
    let mut corrupt = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"corrupt");
    corrupt[10] ^= 0xff;
    assert_eq!(
        policy.authorize_outbound(&corrupt),
        Err(PacketDeny::BadChecksum)
    );
    assert_eq!(device.inject(&corrupt), Err(TunError::InvalidChecksum));

    // Unknown IP version, with an otherwise consistent header checksum.
    let mut unknown = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"version");
    unknown[0] = 0x75;
    repair_checksum(&mut unknown);
    assert_eq!(
        policy.authorize_outbound(&unknown),
        Err(PacketDeny::UnknownVersion)
    );
    assert_eq!(device.inject(&unknown), Err(TunError::InvalidVersion));

    // Empty slice.
    assert_eq!(policy.authorize_outbound(&[]), Err(PacketDeny::EmptyPacket));
}

#[test]
fn ipv6_is_refused_rather_than_forwarded() {
    let policy = policy();
    let (device, _host) = VirtualTun::try_pair(2, 2, DEFAULT_MTU).expect("bounded pair");

    let v6 = ipv6(
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 9],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1],
    );
    let info = inspect_packet(&v6).expect("structurally valid IPv6");
    assert_eq!(info.version, IpVersion::V6);
    device
        .inject(&v6)
        .expect("VirtualTun accepts it structurally");
    let from_host = device.read_packet().expect("readable").expect("one packet");
    assert_eq!(
        policy.authorize_outbound(&from_host),
        Err(PacketDeny::Ipv6NotNegotiated)
    );
    assert_eq!(
        policy.authorize_inbound(&v6),
        Err(PacketDeny::Ipv6NotNegotiated)
    );
}

#[test]
fn frame_codec_is_single_packet_and_bounded() {
    let mtu = MAX_MTU;
    let packet = ipv4([10, 20, 3, 1], [10, 20, 3, 9], &[0u8; 1480]);
    assert_eq!(packet.len(), mtu);
    let frame = encode_packet_frame(&packet, mtu).expect("full-mtu frame");
    assert_eq!(frame.len(), MAX_FRAME_BYTES);
    assert_eq!(decode_packet_frame(&frame, mtu), Ok(packet.as_slice()));

    // Empty frame and empty packet are refused at both ends.
    assert_eq!(
        encode_packet_frame(&[], mtu),
        Err(PacketPathError::Denied(PacketDeny::EmptyPacket))
    );
    assert_eq!(
        decode_packet_frame(&[0, 0], mtu),
        Err(PacketPathError::EmptyFrame)
    );
    // A prefix that never completes.
    assert_eq!(
        decode_packet_frame(&[0x00], mtu),
        Err(PacketPathError::TruncatedFrame)
    );
    assert_eq!(
        decode_packet_frame(&[], mtu),
        Err(PacketPathError::TruncatedFrame)
    );
    // Declared length above the MTU.
    assert_eq!(
        decode_packet_frame(&[0x05, 0xdd], mtu),
        Err(PacketPathError::FrameTooLarge)
    );
    // Declared length disagrees with the bytes present, both short and long.
    assert_eq!(
        decode_packet_frame(&[0x00, 0x05, 1, 2, 3], mtu),
        Err(PacketPathError::FrameLengthMismatch)
    );
    assert_eq!(
        decode_packet_frame(&[0x00, 0x03, 1, 2, 3, 4], mtu),
        Err(PacketPathError::FrameLengthMismatch)
    );
    // A packet larger than the link MTU cannot be framed.
    assert_eq!(
        encode_packet_frame(&packet, mtu - 1),
        Err(PacketPathError::Denied(PacketDeny::MtuExceeded))
    );
}
