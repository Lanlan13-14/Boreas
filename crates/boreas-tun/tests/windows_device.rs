#![cfg(target_os = "windows")]

use boreas_tun::{
    IpVersion,
    windows::{WintunConfig, WintunDevice},
};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

fn require_tun() -> bool {
    env::var_os("BOREAS_REQUIRE_TUN").is_some()
}

fn parse_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn driver() -> Option<(PathBuf, [u8; 32])> {
    let path = env::var_os("BOREAS_WINTUN_DLL").map(PathBuf::from);
    let digest = env::var("BOREAS_WINTUN_SHA256").ok();
    match (path, digest) {
        (Some(path), Some(digest)) => match parse_digest(&digest) {
            Some(digest) => Some((path, digest)),
            None => panic!("BOREAS_WINTUN_SHA256 must be 64 hexadecimal characters"),
        },
        (None, None) if !require_tun() => {
            eprintln!("skipping real Wintun test: BOREAS_WINTUN_DLL/SHA256 are not set");
            None
        }
        _ => panic!(
            "BOREAS_WINTUN_DLL and BOREAS_WINTUN_SHA256 must both be set for the real Wintun test"
        ),
    }
}

fn unique_name() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "BoreasTun{}{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn netsh(arguments: &[&str]) {
    let output = Command::new("netsh")
        .args(arguments)
        .output()
        .expect("netsh must be available on Windows");
    assert!(
        output.status.success(),
        "netsh {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct FirewallRule {
    name: String,
}

impl FirewallRule {
    fn allow_udp_port(port: u16) -> Self {
        let name = format!("BoreasTunTest-{}-{port}", std::process::id());
        let executable = std::env::current_exe().expect("test executable path");
        let name_argument = format!("name={name}");
        let port_argument = format!("localport={port}");
        let program_argument = format!("program={}", executable.display());
        netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            name_argument.as_str(),
            "dir=in",
            "action=allow",
            "protocol=UDP",
            port_argument.as_str(),
            program_argument.as_str(),
            "enable=yes",
            "profile=any",
        ]);
        Self { name }
    }
}

impl Drop for FirewallRule {
    fn drop(&mut self) {
        let name_argument = format!("name={}", self.name);
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                name_argument.as_str(),
            ])
            .status();
    }
}

fn adapter_absent(name: &str) -> bool {
    let name_argument = format!("name={name}");
    for _ in 0..30 {
        let output = Command::new("netsh")
            .args(["interface", "show", "interface", name_argument.as_str()])
            .output()
            .expect("netsh");
        if !output.status.success() {
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
fn real_wintun_device_packet_round_trip() {
    let Some((driver_path, digest)) = driver() else {
        return;
    };
    let name = unique_name();
    let device = WintunDevice::create(WintunConfig {
        name: name.clone(),
        tunnel_type: "BoreasTest".to_owned(),
        mtu: 1400,
        ring_capacity: 0x0004_0000,
        dll_path: driver_path,
        dll_sha256: digest,
    })
    .unwrap_or_else(|error| {
        panic!("create real Wintun adapter (requires elevation and official wintun.dll): {error}")
    });
    assert_eq!(device.name(), name);
    assert_eq!(device.mtu(), 1400);
    assert_ne!(device.luid(), 0, "Wintun adapter must have a real LUID");
    device
        .verify()
        .expect("verify adapter alias and IPv4/IPv6 MTU");
    assert!(
        device.write_packet(&[0u8; 20]).is_err(),
        "invalid L3 packet must be rejected before reaching Wintun"
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

    let name_argument = format!("name={name}");
    netsh(&[
        "interface",
        "ipv4",
        "set",
        "address",
        name_argument.as_str(),
        "static",
        "198.18.0.1",
        "255.255.255.0",
    ]);
    netsh(&[
        "interface",
        "set",
        "interface",
        name_argument.as_str(),
        "admin=enable",
    ]);
    device
        .verify()
        .expect("adapter alias and MTU remain valid after address configuration");

    let bind_deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match UdpSocket::bind((Ipv4Addr::new(198, 18, 0, 1), 0)) {
            Ok(socket) => break socket,
            Err(error) => {
                if Instant::now() >= bind_deadline {
                    panic!("bind UDP oracle to the Wintun address: {error}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("socket timeout");
    let oracle_port = socket.local_addr().expect("oracle local address").port();
    let firewall = FirewallRule::allow_udp_port(oracle_port);
    let request = udp_packet(
        Ipv4Addr::new(198, 18, 0, 2),
        12_345,
        Ipv4Addr::new(198, 18, 0, 1),
        oracle_port,
        b"boreas-wintun",
    );
    device
        .write_packet(&request)
        .expect("write UDP/IP packet into Wintun send ring");

    let mut buffer = [0u8; 256];
    let (length, source) = socket
        .recv_from(&mut buffer)
        .expect("Windows IP stack should deliver the injected packet through Wintun");
    assert_eq!(&buffer[..length], &b"boreas-wintun"[..]);
    assert_eq!(source, socket_addr(Ipv4Addr::new(198, 18, 0, 2), 12_345));

    socket
        .send_to(
            b"boreas-reply",
            socket_addr(Ipv4Addr::new(198, 18, 0, 2), 12_345),
        )
        .expect("send UDP reply through the Wintun interface");

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
                    "ignoring non-matching Wintun packet: version={} protocol={} length={}",
                    packet[0] >> 4,
                    packet.get(9).copied().unwrap_or(0),
                    packet.len()
                );
            }
            Ok(None) => {}
            Err(error) => panic!("Wintun read returned unexpected result: {error}"),
        }
    }
    assert!(
        reply.is_some(),
        "UDP reply from the Windows stack should be readable from Wintun (ignored {ignored} other packets)"
    );

    drop(firewall);
    drop(socket);
    drop(device);
    assert!(
        adapter_absent(&name),
        "WintunCloseAdapter should remove the adapter created by WintunCreateAdapter"
    );
    println!(
        "BOREAS_DEVICE_EVIDENCE platform=windows driver=wintun adapter=created packet_roundtrip=ok cleanup=ok"
    );
}
