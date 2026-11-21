//! Test-only Linux ABI wiring. Never enables offloads on a Boreas production fd.
//! Reference mechanisms: sing-tun at 4486c14ba472 checks VNET separately from
//! offload support and distinguishes the Linux hdr_len hint from header geometry.
//! This test instead drives a real TCP socket and observes kernel-generated data.

use super::{ip, ipv4_checksum, rerun_in_netns, root, unique_name};
use boreas_tun::gso::{MAX_OUTPUT_BYTES, MAX_SUPERPACKET, segment_tcpv4};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    path::PathBuf,
    time::{Duration, Instant},
};

// Linux UAPI: if_tun.h and virtio_net.h, Ubuntu x86_64 ioctl encoding.
const GET_FEATURES: u32 = 0x800454cf;
const SET_IFF: u32 = 0x400454ca;
const GET_IFF: u32 = 0x800454d2;
const GET_HDR_SIZE: u32 = 0x800454d7;
const SET_VNET_LE: u32 = 0x400454dc;
const GET_VNET_LE: u32 = 0x800454dd;
const SET_OFFLOAD: u32 = 0x400454d0;
const TUN_NO_PI_VNET: libc::c_short = 0x5001;
const EXCL: libc::c_short = 0x8000u16.cast_signed();
const CSUM_TSO4: libc::c_ulong = 0x01 | 0x02;
const VNET: usize = 10;
const MTU: usize = 1200;
const MSS: usize = MTU - 40;
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PEER_SEQ: u32 = 0x1357_0000;
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const TIMEOUT: Duration = Duration::from_secs(5);

// Keep pointer ioctls distinct from TUNSETOFFLOAD's scalar argument.
macro_rules! tun_ptr {
    ($fd:expr, $cmd:ident, $obj:expr) => {{
        let (fd, request, arg) = ($fd, $cmd as libc::Ioctl, std::ptr::from_mut($obj));
        // SAFETY: callers supply the initialized, writable UAPI object for this ioctl.
        let rc = unsafe { libc::ioctl(fd, request, arg) };
        assert!(
            rc >= 0,
            "{}: {}",
            stringify!($cmd),
            io::Error::last_os_error()
        );
    }};
}

fn create(name: &str) -> File {
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")
        .expect("open real Linux TUN character device");
    assert!(tun.metadata().unwrap().file_type().is_char_device());
    let fd = tun.as_raw_fd();
    let mut features = 0u32;
    tun_ptr!(fd, GET_FEATURES, &mut features);
    let required = u32::try_from(TUN_NO_PI_VNET).unwrap();
    assert_eq!(features & required, required, "TUNGETFEATURES IFF flags");

    // SAFETY: the C ifreq contains only integer, pointer and byte-array fields;
    // all-zero is valid and initializes the full ioctl storage.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, &src) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = src.cast_signed() as libc::c_char;
    }
    let expected_name = req.ifr_name;
    req.ifr_ifru.ifru_flags = TUN_NO_PI_VNET | EXCL;
    tun_ptr!(fd, SET_IFF, &mut req);
    tun_ptr!(fd, GET_IFF, &mut req);
    assert_eq!(req.ifr_name, expected_name);
    // SAFETY: TUNGETIFF writes the union's flags member.
    assert_eq!(unsafe { req.ifr_ifru.ifru_flags }, TUN_NO_PI_VNET);
    let mut size: libc::c_int = 0;
    tun_ptr!(fd, GET_HDR_SIZE, &mut size);
    assert_eq!(usize::try_from(size).unwrap(), VNET);
    let mut le: libc::c_int = 1;
    tun_ptr!(fd, SET_VNET_LE, &mut le);
    le = 0;
    tun_ptr!(fd, GET_VNET_LE, &mut le);
    assert_eq!(le, 1);
    eprintln!("TUN ABI: features={features:#x} vnet_header_bytes={size} little_endian={le}");
    tun
}

fn set_offload(tun: &File, mask: libc::c_ulong) {
    // SAFETY: TUNSETOFFLOAD gets an unsigned long value, not a user pointer.
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), SET_OFFLOAD as libc::Ioctl, mask) };
    assert!(
        rc >= 0,
        "TUNSETOFFLOAD({mask:#x}): {}",
        io::Error::last_os_error()
    );
}

fn readable(fd: libc::c_int, deadline: Instant) {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        assert!(ms > 0, "TCPv4 probe deadline expired");
        // SAFETY: poll points to one initialized writable pollfd; timeout is bounded.
        let rc = unsafe { libc::poll(&mut poll, 1, libc::c_int::try_from(ms).unwrap()) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll: {error}");
        }
        assert_eq!(
            poll.revents,
            libc::POLLIN,
            "probe timeout or fd error (poll={rc})"
        );
        return;
    }
}

fn be16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap())
}
fn be32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())
}
fn le16(buf: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes(
        buf[offset..offset + 2].try_into().unwrap(),
    ))
}

// A checksum oracle independent of the segmenter. IPv4 TCP pseudo-header is
// even-length, so it can be concatenated to either the full TCP bytes or none.
fn tcp_sum(packet: &[u8], seed_only: bool) -> u16 {
    let mut bytes = Vec::from(&packet[12..20]);
    bytes.extend([0, 6]);
    bytes.extend(u16::try_from(packet.len() - 20).unwrap().to_be_bytes());
    if !seed_only {
        bytes.extend(&packet[20..]);
    }
    ipv4_checksum(&bytes)
}

// Only the in-namespace fixture peer's ordinary SYN and ACK enter the TUN.
// All data packets, including the superpacket, originate from the TCP socket.
fn peer_handshake(tun: &mut File, dst: u16, src: u16, syn: bool, ack: u32) {
    let tcp_len = if syn { 24 } else { 20 };
    let len = 20 + tcp_len;
    let mut frame = vec![0; VNET + len]; // GSO_NONE; complete checksum, no PI
    let packet = &mut frame[VNET..];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&PEER.octets());
    packet[16..20].copy_from_slice(&LOCAL.octets());
    let tcp = &mut packet[20..];
    tcp[..2].copy_from_slice(&src.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.to_be_bytes());
    tcp[4..8].copy_from_slice(&(PEER_SEQ + u32::from(!syn)).to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = u8::try_from(tcp_len / 4).unwrap() << 4;
    tcp[13] = if syn { SYN } else { ACK };
    tcp[14..16].copy_from_slice(&32_768u16.to_be_bytes());
    if syn {
        tcp[20..22].copy_from_slice(&[2, 4]); // MSS; no timestamps, ECN or other options
        tcp[22..24].copy_from_slice(&u16::try_from(MSS).unwrap().to_be_bytes());
    }
    let tcp_check = tcp_sum(packet, false);
    packet[36..38].copy_from_slice(&tcp_check.to_be_bytes());
    let ip_check = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_check.to_be_bytes());
    assert_eq!(
        tun.write(&frame).expect("inject valid test peer handshake"),
        frame.len()
    );
}

fn capture(tun: &mut File, ports: (u16, u16), deadline: Instant) -> Vec<u8> {
    let mut frame = vec![0; VNET + usize::from(u16::MAX) + 1];
    loop {
        readable(tun.as_raw_fd(), deadline);
        let n = tun.read(&mut frame).expect("read real TUN queue");
        let p = frame
            .get(VNET..n)
            .expect("kernel frame must contain the virtio header");
        if p.len() >= 40
            && p[0] == 0x45
            && p[9] == 6
            && p[12..16] == LOCAL.octets()
            && p[16..20] == PEER.octets()
            && (be16(p, 20), be16(p, 22)) == ports
        {
            frame.truncate(n);
            return frame;
        }
    }
}

fn check_ipv4(packet: &[u8]) {
    assert_eq!(usize::from(be16(packet, 2)), packet.len());
    assert_eq!(be16(packet, 6) & !0x4000, 0, "unfragmented IPv4");
    assert_eq!(ipv4_checksum(&packet[..20]), 0, "IPv4 header checksum");
}

fn check_segment(segment: &[u8], seq: u32, flags: u8, payload: &[u8], ports: (u16, u16)) {
    assert_eq!(segment.len(), 40 + payload.len());
    assert!(segment.len() <= MTU);
    assert_eq!(segment[0], 0x45);
    assert_eq!(segment[9], 6);
    assert_eq!(segment[12..16], LOCAL.octets());
    assert_eq!(segment[16..20], PEER.octets());
    check_ipv4(segment);
    assert_eq!((be16(segment, 20), be16(segment, 22)), ports);
    assert_eq!(be32(segment, 24), seq);
    assert_eq!(be32(segment, 28), PEER_SEQ + 1);
    assert_eq!(segment[32], 0x50, "no TCP options on established data");
    assert_eq!(segment[33], flags);
    assert_eq!(&segment[40..], payload);
}

fn observe(tun: &mut File, offload: bool, peer_port: u16) -> usize {
    let listener = TcpListener::bind(SocketAddrV4::new(LOCAL, 0)).expect("namespace TCP listener");
    let ports = (listener.local_addr().unwrap().port(), peer_port);
    let deadline = Instant::now() + TIMEOUT;
    peer_handshake(tun, ports.0, ports.1, true, 0);
    let syn_ack = capture(tun, ports, deadline);
    let syn_ack = &syn_ack[VNET..];
    check_ipv4(syn_ack);
    assert_eq!(syn_ack[33], SYN | ACK);
    assert_eq!(be32(syn_ack, 28), PEER_SEQ + 1);
    let first = be32(syn_ack, 24).wrapping_add(1);
    peer_handshake(tun, ports.0, ports.1, false, first);
    readable(listener.as_raw_fd(), deadline);
    let (mut stream, peer) = listener
        .accept()
        .expect("kernel completed valid TCP handshake");
    assert_eq!(peer, SocketAddr::V4(SocketAddrV4::new(PEER, peer_port)));
    stream.set_nodelay(true).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();

    let payload: Vec<_> = (0..2 * MSS + 137)
        .map(|i| ((i * 17 + i / 251) % 251) as u8)
        .collect();
    stream
        .write_all(&payload)
        .expect("normal TCP send through TUN");
    let mut seen = 0;
    let mut ordinary = 0;
    let mut aggregates = 0;
    let mut scratch = vec![0; MAX_OUTPUT_BYTES];
    while seen < payload.len() {
        let frame = capture(tun, ports, deadline);
        let (hdr, p) = frame.split_at(VNET);
        let seq = be32(p, 24);
        let flags = p[33];
        if flags == SYN | ACK && seq.wrapping_add(1) == first {
            continue; // A duplicate SYN-ACK may already be queued.
        }
        let offset = usize::try_from(seq.wrapping_sub(first)).unwrap();
        assert!(offset < payload.len(), "unexpected TCP data sequence");
        assert_eq!(flags & !PSH, ACK);
        let data = &p[40..];
        assert!(!data.is_empty());
        let end = offset + data.len();
        assert_eq!(data, &payload[offset..end]);
        // Validate retransmissions too, but don't count them as new evidence.
        let is_new = end > seen;
        if is_new {
            assert_eq!(
                offset, seen,
                "TCP data must be contiguous and non-overlapping"
            );
        }
        if hdr[1] == 0 {
            ordinary += usize::from(is_new);
            check_segment(p, seq, flags, data, ports);
            if offload && hdr[0] == 1 {
                assert_eq!((le16(hdr, 2), le16(hdr, 4)), (0, 0));
                assert_eq!((le16(hdr, 6), le16(hdr, 8)), (20, 16));
                assert_eq!(be16(p, 36), !tcp_sum(p, true), "ordinary partial TCP seed");
            } else {
                assert_eq!(hdr, &[0; VNET], "ordinary data without offload");
                assert_eq!(tcp_sum(p, false), 0, "kernel completed TCP checksum");
            }
        } else {
            assert!(offload, "GSO after TUNSETOFFLOAD(0)");
            assert_eq!(&hdr[..2], &[1, 1], "NEEDS_CSUM | TCPv4 GSO");
            assert_eq!(
                le16(hdr, 2),
                40,
                "linear head hint must match this direct TCP path; no rewriting"
            );
            assert_eq!((le16(hdr, 4), le16(hdr, 6), le16(hdr, 8)), (MSS, 20, 16));
            assert!(p.len() > MTU && p.len() <= MAX_SUPERPACKET);
            assert_eq!(p[32], 0x50);
            assert_eq!(be32(p, 28), PEER_SEQ + 1);
            check_ipv4(p);
            assert_eq!(be16(p, 36), !tcp_sum(p, true), "kernel partial TCP seed");
            let segments =
                segment_tcpv4(&frame, MTU, &mut scratch).expect("segment unmodified kernel frame");
            assert_eq!(segments.len(), data.len().div_ceil(MSS));
            assert!(segments.len() >= 2);
            let count = segments.len();
            for (i, (segment, bytes)) in segments.zip(data.chunks(MSS)).enumerate() {
                let seq = seq.wrapping_add(u32::try_from(i * MSS).unwrap());
                check_segment(
                    segment,
                    seq,
                    if i + 1 == count { flags } else { ACK },
                    bytes,
                    ports,
                );
                assert_eq!(
                    tcp_sum(segment, false),
                    0,
                    "software completed TCP checksum"
                );
                assert_eq!(
                    be16(segment, 4),
                    be16(p, 4).wrapping_add(u16::try_from(i).unwrap())
                );
                assert_eq!(be16(segment, 6), be16(p, 6), "preserve DF state");
            }
            eprintln!(
                "TUN TCPv4 GSO: ip_len={} hdr_len={} gso_size={} csum_start={} csum_offset={} segments={count}",
                p.len(),
                le16(hdr, 2),
                le16(hdr, 4),
                le16(hdr, 6),
                le16(hdr, 8),
            );
            aggregates += usize::from(is_new);
        }
        seen = seen.max(end);
    }
    eprintln!(
        "TUN TCPv4: offload={offload} payload_bytes={seen} ordinary={ordinary} gso={aggregates}"
    );
    aggregates
}

// This covers direct local TCP egress only. Other paths (notably forwarded
// GRO) can yield a different Linux hdr_len hint; that is not normalized here.
// No GSO is injected into the kernel, and these fds never enter the daemon.
#[test]
fn real_tcpv4_gso_kernel_segmentation() {
    if std::env::var_os("BOREAS_IN_NETNS").is_none() {
        rerun_in_netns(concat!(
            "tun_gso::",
            stringify!(real_tcpv4_gso_kernel_segmentation)
        ));
        return;
    }
    assert!(root(), "real TUN test requires root");
    let parent =
        PathBuf::from(std::env::var_os("BOREAS_PARENT_NETNS").expect("namespace harness parent"));
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        parent,
        "must unshare network before IP setup"
    );
    let name = unique_name();
    let mut tun = create(&name);
    set_offload(&tun, CSUM_TSO4);
    ip(&["link", "set", "dev", &name, "mtu", &MTU.to_string(), "up"]);
    ip(&["-4", "addr", "add", "192.0.2.1/30", "dev", &name]);
    let aggregates = observe(&mut tun, true, 40901);
    assert!(
        aggregates > 0,
        "enabled TCPv4 offload did not produce a kernel GSO frame"
    );
    set_offload(&tun, 0);
    assert_eq!(observe(&mut tun, false, 40902), 0);
    drop(tun);
    assert!(
        !PathBuf::from(format!("/sys/class/net/{name}")).exists(),
        "non-persistent TUN disappeared on final close"
    );
    println!(
        "\nBOREAS_DEVICE_EVIDENCE platform=linux driver=tun vnet=ok tcpv4_gso=kernel segmented=ok offload_disabled=ok cleanup=ok"
    );
}
