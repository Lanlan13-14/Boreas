//! Test-only B tier: real authenticated WSS/hop/E2E with production PacketPath.
//! The source/sink replaces only host I/O. No production plaintext seam exists.
use super::*;
use boreas_tun::{Error as TunError, PacketIo};
use boreas_tunnel::packet_path::PacketPath;
use std::{borrow::Cow, cell::Cell};

const MTU: usize = 1360;
const IP_TCP: usize = 40;

fn pin(cpu: usize) {
    // SAFETY: CPU index comes from sched_getaffinity; the set has ABI size.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set),
            0
        );
    }
}
fn allowed_cpus() -> Vec<usize> {
    // SAFETY: valid initialized output with the expected cpu_set_t size.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set),
            0
        );
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| libc::CPU_ISSET(cpu, &set))
            .collect()
    }
}
fn cpu_seconds() -> f64 {
    // SAFETY: clock_gettime writes the provided timespec, no pointers retained.
    unsafe {
        let mut time: libc::timespec = std::mem::zeroed();
        assert_eq!(
            libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time),
            0
        );
        time.tv_sec as f64 + time.tv_nsec as f64 / 1e9
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(local: [u8; 4], peer: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0x5a; MTU];
    bytes[..IP_TCP].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(MTU as u16).to_be_bytes());
    // IP_HDRINCL fills a zero ID in raw-socket sends. Specify a nonzero
    // fixture ID so the kernel does not mutate the expected exact bytes.
    bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&local);
    bytes[16..20].copy_from_slice(&peer);
    bytes[20..22].copy_from_slice(&18080u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&18081u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x18;
    bytes[34..36].copy_from_slice(&65535u16.to_be_bytes());
    let ip_sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let mut pseudo = Vec::with_capacity(MTU);
    pseudo.extend_from_slice(&bytes[12..20]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((MTU - 20) as u16).to_be_bytes());
    pseudo.extend_from_slice(&bytes[20..]);
    let tcp_sum = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    bytes
}
// RFC1624 incremental replacement of the TCP sequence number. The body stays
// deterministic. Sequence checking detects drops, duplication and reordering.
fn sequenced(bytes: &mut [u8], sequence: u32) {
    let old = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
    let old_sum = u16::from_be_bytes(bytes[36..38].try_into().unwrap());
    let mut sum = u32::from(!old_sum)
        + u32::from(!(old >> 16) as u16)
        + u32::from(!old as u16)
        + (sequence >> 16)
        + (sequence & 65535);
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
    bytes[36..38].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}
struct SourceSink {
    template: Vec<u8>,
    next: Cell<u32>,
    received: Cell<u32>,
    total: u32,
}
impl SourceSink {
    fn new(template: Vec<u8>, total: u32) -> Self {
        Self {
            template,
            next: Cell::new(0),
            received: Cell::new(0),
            total,
        }
    }
}
impl PacketIo for SourceSink {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
        panic!("benchmark must use bounded caller scratch")
    }
    fn read_packet_with_scratch<'b>(
        &self,
        scratch: &'b mut [u8],
    ) -> Result<Option<Cow<'b, [u8]>>, TunError> {
        assert!(scratch.len() > MTU);
        let next = self.next.get();
        if next == self.total {
            return Ok(None);
        }
        scratch[..MTU].copy_from_slice(&self.template);
        sequenced(&mut scratch[..MTU], next);
        self.next.set(next + 1);
        Ok(Some(Cow::Borrowed(&scratch[..MTU])))
    }
    fn write_packet(&self, bytes: &[u8]) -> Result<(), TunError> {
        assert_eq!(bytes.len(), MTU);
        let next = self.received.get();
        assert!(next < self.total);
        assert_eq!(&bytes[..24], &self.template[..24]);
        assert_eq!(u32::from_be_bytes(bytes[24..28].try_into().unwrap()), next);
        assert_eq!(&bytes[28..36], &self.template[28..36]);
        assert_eq!(&bytes[38..], &self.template[38..]);
        let mut pseudo = [0u8; MTU - 8];
        pseudo[..8].copy_from_slice(&bytes[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&((MTU - 20) as u16).to_be_bytes());
        pseudo[12..].copy_from_slice(&bytes[20..]);
        assert_eq!(
            checksum(&pseudo),
            0,
            "TCP checksum including ordered sequence"
        );
        self.received.set(next + 1);
        Ok(())
    }
}
fn run_path(
    circuit: boreas_tunnel::e2e::E2eCircuit<'_>,
    io: &SourceSink,
    send: bool,
    batch: usize,
    label: &str,
) {
    let mut path = PacketPath::try_new_over_e2e(io, circuit, MTU).unwrap();
    let scope = boreas_tunnel::record_diagnostics::Scope::begin();
    let cpu = cpu_seconds();
    let wall = Instant::now();
    let mut delivered = 0usize;
    while delivered < io.total as usize {
        if send {
            let count = path.step_outbound_batch(batch, 16_288 - (MTU + 1)).unwrap();
            assert!(count > 0);
            delivered += count;
        } else {
            assert_eq!(path.step_inbound().unwrap(), Some(MTU));
            delivered += 1;
        }
    }
    let elapsed = wall.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu;
    let stats = scope.snapshot();
    drop(scope);
    let payload = delivered * (MTU - IP_TCP);
    println!(
        "record_chain role={label} send={send} batch={batch} packets={delivered} l3_bytes={} effective_bytes={payload} wall_seconds={elapsed:.9} thread_cpu_seconds={cpu:.9} cpu_seconds_per_gib={:.6} effective_mbps={:.3} counters={stats:?}",
        delivered * MTU,
        cpu * 1073741824.0 / payload as f64,
        payload as f64 * 8.0 / elapsed / 1e6
    );
    if send {
        assert!(stats.e2e_records.complete());
        assert!(stats.hop_records.complete());
        assert!(stats.e2e_records.records > 0 && stats.hop_records.records > 0);
    }
    // Fixed byte count, ordered checksum validation; not steady-state or a gate.
    path.close_gracefully();
}

#[test]
#[ignore = "opt-in release-profile record-chain diagnostic, not an acceptance gate"]
fn authenticated_record_chain_capacity() {
    let cpus = allowed_cpus();
    assert!(cpus.len() >= 2, "requires two independently allowed CPUs");
    let total: u32 = std::env::var("BOREAS_RECORD_PACKETS")
        .unwrap_or_else(|_| "16384".into())
        .parse()
        .unwrap();
    assert!((16..=1_000_000).contains(&total));
    let t = Temp::new();
    setup(&t);
    for batch in [1, 4, 8, 11] {
        for client_send in [true, false] {
            let (client_side, server_side) = sides(&t);
            let edge = [10, 20, 1, 2];
            let core = [10, 20, 1, 1];
            let template = if client_send {
                packet(edge, core)
            } else {
                packet(core, edge)
            };
            let server_template = template.clone();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server_cpu = cpus[1];
            let client_cpu = cpus[0];
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let server_barrier = barrier.clone();
            let server = thread::spawn(move || {
                pin(server_cpu);
                let (mut accepted, backend, peer) = accept_session(&listener, server_side).unwrap();
                let circuit = accept_e2e(&mut accepted.session, &backend, peer).unwrap();
                let io = SourceSink::new(server_template, total);
                server_barrier.wait();
                run_path(circuit, &io, !client_send, batch, "server");
            });
            let client = thread::spawn(move || {
                pin(client_cpu);
                let link = LinkClient::new(Box::new(client_side.outer), client_side.hop);
                let mut hop = link
                    .connect(
                        &target(address, "wss.boreas.test"),
                        policy(client_side.local, client_side.peer),
                        IO_TIMEOUT,
                    )
                    .unwrap();
                let circuit = open_e2e(&mut hop, &client_side.e2e, client_side.peer, 1).unwrap();
                let io = SourceSink::new(template, total);
                barrier.wait();
                run_path(circuit, &io, client_send, batch, "client");
            });
            client.join().unwrap();
            server.join().unwrap();
        }
    }
}

#[test]
fn source_sequence_and_tcp_checksums_are_exact() {
    let template = packet([10, 20, 1, 2], [10, 20, 1, 1]);
    let source = SourceSink::new(template.clone(), 32);
    let sink = SourceSink::new(template, 32);
    let mut scratch = [0; MTU + 1];
    for _ in 0..32 {
        let bytes = source
            .read_packet_with_scratch(&mut scratch)
            .unwrap()
            .unwrap();
        sink.write_packet(&bytes).unwrap();
    }
    assert!(
        source
            .read_packet_with_scratch(&mut scratch)
            .unwrap()
            .is_none()
    );
}

/// A tier: ordinary kernel TUN, raw-IP generator/packet-socket sink. The
/// generator has a separate CPU and fixed 32-packet credits, not a hidden
/// production helper. Kernel and generator costs are reported separately.
#[test]
#[ignore = "requires CAP_NET_ADMIN, private net+mount namespace and release profile"]
fn ordinary_tun_packet_capacity() {
    use boreas_tun::{
        InspectedPacket,
        linux::{LinuxTunDevice, TunConfig},
    };
    use boreas_tunnel::packet_path::PointToPoint;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let cpus = allowed_cpus();
    assert!(cpus.len() >= 2);
    let total: u32 = std::env::var("BOREAS_RECORD_PACKETS")
        .unwrap_or_else(|_| "16384".into())
        .parse()
        .unwrap();
    assert!((32..=1_000_000).contains(&total) && total.is_multiple_of(32));
    for size in [1360usize, 128] {
        for receive in [true, false] {
            let name = "diag0";
            let (device, queue) = LinuxTunDevice::create(TunConfig {
                name: Some(name.into()),
                mtu: MTU,
                multi_queue: false,
                vnet_header: false,
            })
            .unwrap();
            queue.set_nonblocking(true).unwrap();
            let configure = Command::new("ip")
                .args(["address", "add", "10.20.1.1/24", "dev", name])
                .status()
                .unwrap();
            assert!(configure.success());
            assert!(
                Command::new("ip")
                    .args(["link", "set", name, "up"])
                    .status()
                    .unwrap()
                    .success()
            );
            let (local, peer) = ([10, 20, 1, 1], [10, 20, 1, 2]);
            let mut template = if receive {
                packet(local, peer)
            } else {
                packet(peer, local)
            };
            template.truncate(size);
            template[2..4].copy_from_slice(&(size as u16).to_be_bytes());
            template[10..12].fill(0);
            let sum = checksum(&template[..20]);
            template[10..12].copy_from_slice(&sum.to_be_bytes());
            template[36..38].fill(0);
            let mut pseudo = template[12..20].to_vec();
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((size - 20) as u16).to_be_bytes());
            pseudo.extend_from_slice(&template[20..]);
            let sum = checksum(&pseudo);
            template[36..38].copy_from_slice(&sum.to_be_bytes());
            let expected = template.clone();
            let (to_main, from_generator) = std::sync::mpsc::sync_channel::<()>(1);
            let (to_generator, from_main) = std::sync::mpsc::sync_channel::<()>(1);
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);
            let generator_cpu = cpus[1];
            let generator = thread::spawn(move || {
                pin(generator_cpu);
                // SAFETY: owned socket fd, ABI-correct structures, bounded slices.
                unsafe {
                    let domain = if receive {
                        libc::AF_INET
                    } else {
                        libc::AF_PACKET
                    };
                    let protocol = if receive {
                        libc::IPPROTO_RAW
                    } else {
                        i32::from((libc::ETH_P_IP as u16).to_be())
                    };
                    let raw = libc::socket(domain, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol);
                    assert!(raw >= 0);
                    let fd = OwnedFd::from_raw_fd(raw);
                    let timeout = libc::timeval {
                        tv_sec: 10,
                        tv_usec: 0,
                    };
                    assert_eq!(
                        libc::setsockopt(
                            raw,
                            libc::SOL_SOCKET,
                            libc::SO_RCVTIMEO,
                            (&timeout as *const libc::timeval).cast(),
                            std::mem::size_of_val(&timeout) as _
                        ),
                        0
                    );
                    if !receive {
                        let ignore_outgoing: libc::c_int = 1;
                        assert_eq!(
                            libc::setsockopt(
                                raw,
                                libc::SOL_PACKET,
                                23,
                                (&ignore_outgoing as *const libc::c_int).cast(),
                                std::mem::size_of_val(&ignore_outgoing) as _
                            ),
                            0
                        );
                        let interface = std::ffi::CString::new(name).unwrap();
                        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
                        addr.sll_family = libc::AF_PACKET as u16;
                        addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
                        addr.sll_ifindex = libc::if_nametoindex(interface.as_ptr()) as i32;
                        assert!(addr.sll_ifindex > 0);
                        assert_eq!(
                            libc::bind(
                                raw,
                                (&addr as *const libc::sockaddr_ll).cast(),
                                std::mem::size_of_val(&addr) as _
                            ),
                            0
                        );
                    }
                    ready_tx.send(()).unwrap();
                    let start = cpu_seconds();
                    let wall = Instant::now();
                    let mut addr: libc::sockaddr_in = std::mem::zeroed();
                    addr.sin_family = libc::AF_INET as u16;
                    addr.sin_addr.s_addr = u32::from_ne_bytes(peer);
                    let mut buffer = [0u8; MTU + 1];
                    for n in 0..total {
                        if receive {
                            sequenced(&mut template, n);
                            let sent = libc::sendto(
                                raw,
                                template.as_ptr().cast(),
                                template.len(),
                                0,
                                (&addr as *const libc::sockaddr_in).cast(),
                                std::mem::size_of_val(&addr) as _,
                            );
                            assert_eq!(sent, size as isize);
                            if n % 32 == 31 {
                                from_main.recv_timeout(Duration::from_secs(10)).unwrap();
                            }
                        } else {
                            if n % 32 == 0 {
                                to_main.send(()).unwrap();
                            }
                            let got = libc::recv(
                                fd.as_raw_fd(),
                                buffer.as_mut_ptr().cast(),
                                buffer.len(),
                                0,
                            );
                            assert_eq!(got, size as isize);
                            let mut check = template.clone();
                            sequenced(&mut check, n);
                            assert_eq!(&buffer[..size], check);
                        }
                    }
                    println!(
                        "ordinary_tun generator_receive={receive} size={size} packets={total} generator_cpu_seconds={:.9} generator_wall_seconds={:.9}",
                        cpu_seconds() - start,
                        wall.elapsed().as_secs_f64()
                    );
                }
            });
            ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            pin(cpus[0]);
            let policy = PointToPoint::try_new(local.into(), peer.into(), MTU).unwrap();
            let wall = Instant::now();
            let cpu = cpu_seconds();
            let mut calls = 0u64;
            let mut scratch = [0; MTU + 1];
            let mut next = expected;
            for n in 0..total {
                if receive {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    loop {
                        calls += 1;
                        if let Some(packet) = queue.try_read_inspected_into(&mut scratch).unwrap() {
                            policy.authorize_outbound(packet.bytes()).unwrap();
                            sequenced(&mut next, n);
                            assert_eq!(packet.bytes(), next);
                            break;
                        }
                        assert!(Instant::now() < deadline, "TUN read deadline");
                        thread::yield_now();
                    }
                    if n % 32 == 31 {
                        to_generator.send(()).unwrap();
                    }
                } else {
                    if n % 32 == 0 {
                        from_generator
                            .recv_timeout(Duration::from_secs(10))
                            .unwrap();
                    }
                    scratch[..size].copy_from_slice(&next);
                    sequenced(&mut scratch[..size], n);
                    policy.authorize_inbound(&scratch[..size]).unwrap();
                    let inspected = InspectedPacket::new(&scratch[..size]).unwrap();
                    queue.write_inspected_packet(inspected).unwrap();
                    calls += 1;
                }
            }
            let cpu = cpu_seconds() - cpu;
            let elapsed = wall.elapsed().as_secs_f64();
            println!(
                "ordinary_tun receive={receive} size={size} packets={total} packet_api_calls={calls} thread_cpu_seconds={cpu:.9} wall_seconds={elapsed:.9} packets_per_second={:.3} cpu_seconds_per_million_packets={:.6} cycles=unavailable syscall_count=unmeasured",
                f64::from(total) / elapsed,
                cpu * 1e6 / f64::from(total)
            );
            generator.join().unwrap();
            drop(queue);
            drop(device);
        }
    }
}
