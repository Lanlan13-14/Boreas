use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use boreas_dns::tcp::{DNS_TCP_PORT, TcpDnsConfig, TcpDnsServer, TcpSourceAuthorizer};
use boreas_dns::{AuthoritativeDns, SourceAuthorization, Zone};
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::SocketBuffer,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint},
};

const SERVER4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 53);
const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 2);
const SERVER6: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 0x53);

#[derive(Clone, Default)]
struct AllowPeers;
impl TcpSourceAuthorizer for AllowPeers {
    fn is_authorized_authenticated_peer(&self, source: IpAddr) -> bool {
        source == IpAddr::V4(CLIENT4) || source == IpAddr::V6(CLIENT6)
    }
}

#[derive(Clone)]
struct Link {
    inbound: std::sync::Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    outbound: std::sync::Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
}
impl Link {
    fn pair() -> (Self, Self) {
        let a = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::new()));
        (
            Self {
                inbound: a.clone(),
                outbound: b.clone(),
            },
            Self {
                inbound: b,
                outbound: a,
            },
        )
    }
}
struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
struct Tx {
    queue: std::sync::Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
}
impl TxToken for Tx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = vec![0; len];
        let r = f(&mut b);
        self.queue.lock().unwrap().push_back(b);
        r
    }
}
impl Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx)> {
        let p = self.inbound.lock().unwrap().pop_front()?;
        Some((
            Rx(p),
            Tx {
                queue: self.outbound.clone(),
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx> {
        Some(Tx {
            queue: self.outbound.clone(),
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }
}

struct Side {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: Link,
}
fn side(ip: IpAddress, device: Link, seed: u64) -> Side {
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = seed;
    let mut device = device;
    let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(match ip {
                IpAddress::Ipv4(a) => IpCidr::new(IpAddress::Ipv4(a), 24),
                IpAddress::Ipv6(a) => IpCidr::new(IpAddress::Ipv6(a), 64),
            })
            .unwrap()
    });
    // Both addresses are directly connected; no default route is configured.
    Side {
        iface,
        sockets: SocketSet::new(Vec::<SocketStorage<'static>>::new()),
        device,
    }
}
fn dns() -> AuthoritativeDns {
    let mut z = Zone::new("corp.example").unwrap();
    z.add_address(
        "host.corp.example",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
    )
    .unwrap();
    AuthoritativeDns::new(
        z,
        SourceAuthorization::new([IpAddr::V4(CLIENT4), IpAddr::V6(CLIENT6)]),
        1232,
    )
    .unwrap()
}
fn query(id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'h', b'o', b's', b't', 4, b'c', b'o', b'r', b'p', 7,
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
    ]);
    q
}
fn framed(q: &[u8]) -> Vec<u8> {
    let mut b = (q.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(q);
    b
}
fn poll(side: &mut Side, now: i64) {
    let t = Instant::from_millis(now);
    let _ = side.iface.poll(t, &mut side.device, &mut side.sockets);
}
fn pump(
    server: &mut Side,
    client: &mut Side,
    now: i64,
    server_dns: &AuthoritativeDns,
    endpoint: &mut TcpDnsServer,
) -> usize {
    poll(client, now);
    poll(server, now);
    let done = endpoint.process(
        &mut server.sockets,
        server_dns,
        &AllowPeers,
        Instant::from_millis(now),
    );
    poll(server, now);
    poll(client, now);
    done
}

fn setup_v4() -> (Side, Side, TcpDnsServer) {
    let (cdev, sdev) = Link::pair();
    let client = side(IpAddress::Ipv4(CLIENT4), cdev, 11);
    let mut server = side(IpAddress::Ipv4(SERVER4), sdev, 12);
    let mut listener = SocketSet::new(Vec::<SocketStorage<'static>>::new());
    let endpoint = IpListenEndpoint {
        addr: Some(IpAddress::Ipv4(SERVER4)),
        port: DNS_TCP_PORT,
    };
    let tcp = TcpDnsServer::new(TcpDnsConfig::default(), endpoint, &mut listener).unwrap();
    server.sockets = listener;
    (client, server, tcp)
}
fn setup_v6() -> (Side, Side, TcpDnsServer) {
    let (cdev, sdev) = Link::pair();
    let client = side(IpAddress::Ipv6(CLIENT6), cdev, 21);
    let mut server = side(IpAddress::Ipv6(SERVER6), sdev, 22);
    let mut listener = SocketSet::new(Vec::<SocketStorage<'static>>::new());
    let endpoint = IpListenEndpoint {
        addr: Some(IpAddress::Ipv6(SERVER6)),
        port: DNS_TCP_PORT,
    };
    let tcp = TcpDnsServer::new(TcpDnsConfig::default(), endpoint, &mut listener).unwrap();
    server.sockets = listener;
    (client, server, tcp)
}

fn connect(
    client: &mut Side,
    server: &mut Side,
    now: i64,
    remote: IpAddress,
    local_port: u16,
) -> smoltcp::iface::SocketHandle {
    use smoltcp::socket::tcp;
    let h = client.sockets.add(tcp::Socket::new(
        SocketBuffer::new(vec![0u8; 8192]),
        SocketBuffer::new(vec![0u8; 8192]),
    ));
    client
        .sockets
        .get_mut::<tcp::Socket>(h)
        .connect(client.iface.context(), (remote, DNS_TCP_PORT), local_port)
        .unwrap();
    for n in 0..8 {
        poll(client, now + n * 10);
        poll(server, now + n * 10);
    }
    h
}
fn receive_tcp(
    sockets: &mut SocketSet<'static>,
    h: smoltcp::iface::SocketHandle,
    out: &mut Vec<u8>,
) -> bool {
    use smoltcp::socket::tcp;
    let s = sockets.get_mut::<tcp::Socket>(h);
    while s.can_recv() {
        let mut b = [0; 1024];
        match s.recv_slice(&mut b) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&b[..n]),
            Err(_) => break,
        }
    }
    !out.is_empty()
}

#[test]
fn real_smoltcp_v4_handshake_dns_frame_and_reply() {
    use smoltcp::socket::tcp;
    let (mut c, mut s, mut endpoint) = setup_v4();
    let dh = dns();
    let ch = connect(&mut c, &mut s, 0, IpAddress::Ipv4(SERVER4), 53000);
    let mut got = Vec::new();
    for n in 0..12 {
        let q = query(0x1234);
        if n == 0 {
            c.sockets
                .get_mut::<tcp::Socket>(ch)
                .send_slice(&framed(&q))
                .unwrap();
        }
        let _ = pump(&mut s, &mut c, 100 + n * 10, &dh, &mut endpoint);
        let _ = receive_tcp(&mut c.sockets, ch, &mut got);
        if got.len() >= 2 {
            let len = u16::from_be_bytes([got[0], got[1]]) as usize;
            if got.len() >= len + 2 {
                assert_eq!(&got[2..4], &[0x12, 0x34]);
                assert_eq!(u16::from_be_bytes([got[8], got[9]]), 1);
                return;
            }
        }
    }
    panic!("TCP DNS response missing");
}

#[test]
fn tcp_framing_survives_split_prefix_body_and_coalesced_queries() {
    use smoltcp::socket::tcp;
    let (mut c, mut s, mut endpoint) = setup_v4();
    let dh = dns();
    let ch = connect(&mut c, &mut s, 0, IpAddress::Ipv4(SERVER4), 53001);
    let q1 = framed(&query(1));
    let q2 = framed(&query(2));
    let split = q1.len() / 2;
    c.sockets
        .get_mut::<tcp::Socket>(ch)
        .send_slice(&q1[..split])
        .unwrap();
    let _ = pump(&mut s, &mut c, 100, &dh, &mut endpoint);
    c.sockets
        .get_mut::<tcp::Socket>(ch)
        .send_slice(&q1[split..])
        .unwrap();
    let mut together = q2.clone();
    together.extend_from_slice(&framed(&query(3)));
    c.sockets
        .get_mut::<tcp::Socket>(ch)
        .send_slice(&together)
        .unwrap();
    let mut got = Vec::new();
    for n in 0..20 {
        let _ = pump(&mut s, &mut c, 200 + n * 10, &dh, &mut endpoint);
        let _ = receive_tcp(&mut c.sockets, ch, &mut got);
    }
    let mut ids = Vec::new();
    let mut p = 0;
    while got.len().saturating_sub(p) >= 2 {
        let len = u16::from_be_bytes([got[p], got[p + 1]]) as usize;
        if got.len() - p < len + 2 {
            break;
        }
        ids.push(u16::from_be_bytes([got[p + 2], got[p + 3]]));
        p += len + 2;
    }
    assert_eq!(ids, vec![1, 2, 3]);
}

#[test]
fn v6_tcp_and_invalid_frame_close() {
    use smoltcp::socket::tcp;
    let (mut c, mut s, mut endpoint) = setup_v6();
    let dh = dns();
    let ch = connect(&mut c, &mut s, 0, IpAddress::Ipv6(SERVER6), 53002);
    c.sockets
        .get_mut::<tcp::Socket>(ch)
        .send_slice(&framed(&query(0xbeef)))
        .unwrap();
    let mut got = Vec::new();
    for n in 0..12 {
        let _ = pump(&mut s, &mut c, 100 + n * 10, &dh, &mut endpoint);
        let _ = receive_tcp(&mut c.sockets, ch, &mut got);
    }
    assert!(got.len() > 2);
    let ch2 = connect(&mut c, &mut s, 500, IpAddress::Ipv6(SERVER6), 53003);
    c.sockets
        .get_mut::<tcp::Socket>(ch2)
        .send_slice(&[0, 0])
        .unwrap();
    for n in 0..5 {
        let _ = pump(&mut s, &mut c, 600 + n * 10, &dh, &mut endpoint);
    }
    assert!(!c.sockets.get::<tcp::Socket>(ch2).is_active());
}

#[test]
fn config_rejects_unbounded_resources() {
    let cfg = TcpDnsConfig {
        max_connections: 0,
        ..Default::default()
    };
    let mut set = SocketSet::new(Vec::<SocketStorage<'static>>::new());
    assert!(
        TcpDnsServer::new(
            cfg,
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(SERVER4)),
                port: DNS_TCP_PORT
            },
            &mut set
        )
        .is_err()
    );
    let cfg = TcpDnsConfig {
        idle_timeout: Duration::ZERO,
        ..TcpDnsConfig::default()
    };
    assert!(
        TcpDnsServer::new(
            cfg,
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(SERVER4)),
                port: DNS_TCP_PORT
            },
            &mut set
        )
        .is_err()
    );
}
