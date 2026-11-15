#![cfg(target_os = "macos")]

use boreas_tun::{
    IpVersion,
    macos::{UtunConfig, UtunDevice},
};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    process::Command,
    time::{Duration, Instant},
};

fn require_tun() -> bool {
    env::var_os("BOREAS_REQUIRE_TUN").is_some()
}

fn root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

fn ifconfig(arguments: &[&str]) -> std::process::Output {
    let output = Command::new("/sbin/ifconfig")
        .args(arguments)
        .output()
        .expect("/sbin/ifconfig must be available on macOS");
    assert!(
        output.status.success(),
        "ifconfig {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn interface_absent(name: &str) -> bool {
    for _ in 0..30 {
        let status = Command::new("/sbin/ifconfig")
            .arg(name)
            .output()
            .expect("/sbin/ifconfig");
        if !status.status.success() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn socket_addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    assert!(total <= 65_535);
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn is_expected_udp(
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_source_port: u16,
    expected_destination: Ipv4Addr,
    expected_destination_port: u16,
    expected_payload: &[u8],
) -> bool {
    let Ok(info) = boreas_tun::inspect_packet(packet) else {
        return false;
    };
    if info.version != IpVersion::V4
        || info.protocol != 17
        || info.source != std::net::IpAddr::V4(expected_source)
        || info.destination != std::net::IpAddr::V4(expected_destination)
    {
        return false;
    }
    let start = info.header_len;
    if packet.len() < start + 8 {
        return false;
    }
    let udp_length = u16::from_be_bytes([packet[start + 4], packet[start + 5]]) as usize;
    if udp_length < 8 || start + udp_length > packet.len() {
        return false;
    }
    let udp = &packet[start..start + udp_length];
    u16::from_be_bytes([udp[0], udp[1]]) == expected_source_port
        && u16::from_be_bytes([udp[2], udp[3]]) == expected_destination_port
        && &udp[8..] == expected_payload
}

#[test]
fn real_utun_packet_round_trip() {
    if !root() {
        if require_tun() {
            panic!("real utun test requires root (BOREAS_REQUIRE_TUN is set)");
        }
        eprintln!("skipping real utun test: utun creation requires root");
        return;
    }
    // Let the kernel assign an unused utun unit; the library reads it back.
    let device = UtunDevice::create(UtunConfig {
        name: None,
        mtu: 1400,
    })
    .unwrap_or_else(|error| panic!("create real utun interface: {error}"));
    let name = device.name().to_owned();
    assert!(name.starts_with("utun"), "kernel-assigned name: {name}");
    assert_eq!(device.mtu(), 1400);
    device.verify().expect("verify utun name and MTU");
    assert!(
        device.write_packet(&[0u8; 20]).is_err(),
        "invalid L3 packet must be rejected before reaching utun"
    );
    let oversized_payload = [0u8; 1401 - 28];
    let oversized = udp_packet(
        Ipv4Addr::new(198, 18, 0, 2),
        12_345,
        Ipv4Addr::new(198, 18, 0, 1),
        54_321,
        &oversized_payload,
    );
    assert!(
        device.write_packet(&oversized).is_err(),
        "packet larger than the configured MTU must be rejected"
    );

    let name_argument: &str = &name;
    ifconfig(&[name_argument, "inet", "198.18.0.1", "198.18.0.2", "up"]);
    let configuration_output = ifconfig(&[name_argument]);
    let configuration = String::from_utf8_lossy(&configuration_output.stdout);
    assert!(
        configuration.contains("mtu 1400"),
        "ifconfig should report the applied MTU: {configuration}"
    );
    assert!(
        configuration.contains("198.18.0.1"),
        "ifconfig should report the assigned address: {configuration}"
    );
    device
        .verify()
        .expect("utun name and MTU remain valid after address configuration");

    let bind_deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match UdpSocket::bind((Ipv4Addr::new(198, 18, 0, 1), 0)) {
            Ok(socket) => break socket,
            Err(error) => {
                if Instant::now() >= bind_deadline {
                    panic!("bind UDP oracle to the utun address: {error}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("socket timeout");
    let oracle_port = socket.local_addr().expect("oracle local address").port();
    let request = udp_packet(
        Ipv4Addr::new(198, 18, 0, 2),
        12_345,
        Ipv4Addr::new(198, 18, 0, 1),
        oracle_port,
        b"boreas-utun",
    );
    device
        .write_packet(&request)
        .expect("write UDP/IP packet into utun");

    let mut buffer = [0u8; 256];
    let (length, source) = socket
        .recv_from(&mut buffer)
        .expect("macOS IP stack should deliver the injected packet through utun");
    assert_eq!(&buffer[..length], &b"boreas-utun"[..]);
    assert_eq!(
        source,
        socket_addr(Ipv4Addr::new(198, 18, 0, 2), 12_345)
    );

    socket
        .send_to(
            b"boreas-reply",
            socket_addr(Ipv4Addr::new(198, 18, 0, 2), 12_345),
        )
        .expect("send UDP reply through the utun interface");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reply = None;
    let mut ignored = 0usize;
    while Instant::now() < deadline {
        match device.read_packet_timeout(Duration::from_millis(100)) {
            Ok(Some(packet)) => {
                if is_expected_udp(
                    &packet,
                    Ipv4Addr::new(198, 18, 0, 1),
                    oracle_port,
                    Ipv4Addr::new(198, 18, 0, 2),
                    12_345,
                    b"boreas-reply",
                ) {
                    reply = Some(packet);
                    break;
                }
                ignored += 1;
                eprintln!(
                    "ignoring non-matching utun packet: version={} protocol={} length={}",
                    packet[0] >> 4,
                    packet.get(9).copied().unwrap_or(0),
                    packet.len()
                );
            }
            Ok(None) => {}
            Err(error) => panic!("utun read returned unexpected result: {error}"),
        }
    }
    assert!(
        reply.is_some(),
        "UDP reply from the macOS stack should be readable from utun (ignored {ignored} other packets)"
    );

    drop(socket);
    drop(device);
    assert!(
        interface_absent(&name),
        "closing the utun control socket should destroy the non-persistent interface"
    );
    println!(
        "BOREAS_DEVICE_EVIDENCE platform=macos driver=utun adapter=created packet_roundtrip=ok cleanup=ok"
    );
}
