//! Test-only bounded short-I/O seam ABOVE verified outer TLS. No plaintext or
//! alternate authentication entry point exists in production.
use super::*;
use boreas_tun::{PacketIo, VirtualTun};
use boreas_tunnel::{
    packet_path::PacketPath,
    stream::Duplex,
    tls::{OuterTlsAcceptor, OuterTlsConnector},
};

struct ShortDuplex {
    inner: Box<dyn Duplex>,
    chunk: usize,
}
impl Read for ShortDuplex {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.chunk);
        self.inner.read(&mut out[..n])
    }
}
impl Write for ShortDuplex {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write(&bytes[..bytes.len().min(self.chunk)])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
impl Duplex for ShortDuplex {
    fn has_buffered_input(&self) -> bool {
        self.inner.has_buffered_input()
    }
    fn set_io_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_io_timeout(t)
    }
    fn clear_handshake_deadline(&self) -> std::io::Result<()> {
        self.inner.clear_handshake_deadline()
    }
}
struct ShortConnector {
    inner: OpenSslOuterTlsConnector,
    chunk: usize,
}
impl OuterTlsConnector for ShortConnector {
    fn connect(
        &self,
        tcp: TcpStream,
        name: &str,
    ) -> Result<Box<dyn Duplex>, boreas_tunnel::TunnelError> {
        Ok(Box::new(ShortDuplex {
            inner: self.inner.connect(tcp, name)?,
            chunk: self.chunk,
        }))
    }
}
struct ShortAcceptor {
    inner: OpenSslOuterTlsAcceptor,
    chunk: usize,
}
impl OuterTlsAcceptor for ShortAcceptor {
    fn accept(&self, tcp: TcpStream) -> Result<Box<dyn Duplex>, boreas_tunnel::TunnelError> {
        Ok(Box::new(ShortDuplex {
            inner: self.inner.accept(tcp)?,
            chunk: self.chunk,
        }))
    }
}
fn l3(src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + body.len()];
    p[0] = 0x45;
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[4..6].copy_from_slice(&1u16.to_be_bytes());
    p[8] = 64;
    p[9] = 253;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..].copy_from_slice(body);
    let mut sum: u32 = p[..20]
        .chunks_exact(2)
        .map(|x| u32::from(u16::from_be_bytes([x[0], x[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p
}
#[test]
fn optimized_packets_cross_real_wss_pq768_with_bounded_short_io_both_directions() {
    let t = Temp::new();
    setup(&t);
    for chunk in [257, 4096] {
        let (client_side, server_side) = sides(&t);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let server_ready = ready.clone();
        let server = thread::spawn(move || {
            let tcp = bounded_accept(&listener).unwrap();
            let mut accepted = LinkServer::new(server_side.hop)
                .accept_tls_stream(
                    tcp,
                    &ShortAcceptor {
                        inner: server_side.outer,
                        chunk,
                    },
                    policy(server_side.local, server_side.peer),
                    IO_TIMEOUT,
                    &admission(),
                )
                .unwrap();
            let mut circuit =
                accept_e2e(&mut accepted.session, &server_side.e2e, server_side.peer).unwrap();
            circuit.enable_direct_read_ahead();
            let (device, host) = VirtualTun::try_pair(32, 32, 1360).unwrap();
            let mut path = PacketPath::try_new_over_e2e(&device, circuit, 1360).unwrap();
            server_ready.wait();
            for i in 0..24u8 {
                assert_eq!(path.step_inbound_prefetched().unwrap(), Some(21));
                assert_eq!(
                    host.read_packet().unwrap().unwrap(),
                    l3([10, 20, 1, 2], [10, 20, 1, 1], &[i])
                );
            }
            for i in 0..24u8 {
                device
                    .inject(&l3([10, 20, 1, 1], [10, 20, 1, 2], &[i]))
                    .unwrap();
            }
            assert_eq!(path.step_outbound_batch(24, 14800).unwrap(), 24);
            // Every packet is still one delivery boundary, even when the
            // remaining 23 are already in the same authenticated TLS record.
            assert_eq!(path.step_inbound_prefetched().unwrap(), None);
        });
        let link = LinkClient::new(
            Box::new(ShortConnector {
                inner: client_side.outer,
                chunk,
            }),
            client_side.hop,
        );
        let mut hop = link
            .connect(
                &target(address, "wss.boreas.test"),
                policy(client_side.local, client_side.peer),
                IO_TIMEOUT,
            )
            .unwrap();
        let mut circuit = open_e2e(&mut hop, &client_side.e2e, client_side.peer, 1).unwrap();
        circuit.enable_direct_read_ahead();
        let (device, host) = VirtualTun::try_pair(32, 32, 1360).unwrap();
        let mut path = PacketPath::try_new_over_e2e(&device, circuit, 1360).unwrap();
        ready.wait();
        for i in 0..24u8 {
            device
                .inject(&l3([10, 20, 1, 2], [10, 20, 1, 1], &[i]))
                .unwrap();
        }
        assert_eq!(path.step_outbound_batch(24, 14800).unwrap(), 24);
        for i in 0..24u8 {
            assert_eq!(path.step_inbound_prefetched().unwrap(), Some(21));
            assert_eq!(
                host.read_packet().unwrap().unwrap(),
                l3([10, 20, 1, 1], [10, 20, 1, 2], &[i])
            );
        }
        path.close_gracefully();
        server.join().unwrap();
    }
}
