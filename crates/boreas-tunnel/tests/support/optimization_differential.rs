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
    fn enable_progress(&mut self) -> io::Result<bool> { self.inner.enable_progress() }
    fn progress_io(&mut self) -> io::Result<boreas_tunnel::stream::ProgressIo> { self.inner.progress_io() }
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
        .as_chunks::<2>().0.iter()
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

/// Real three-layer TLS proof for the L3 completion boundary only. The peer
/// withholds a whole later E2E record containing the L3 tail until it receives
/// our independently originated packet. This does not cover partial TLS/WS.
#[test]
fn partial_l3_record_allows_reverse_packet_before_tail_over_real_wss_pq768() {
    real_partial_l3_progress(false);
}
#[test]
fn queued_three_layer_tls_preserves_reverse_progress_and_releases_credits() {
    real_partial_l3_progress(true);
}
fn real_partial_l3_progress(queued: bool) {
    use boreas_tunnel::{e2e::E2eCircuit, packet_path::{InboundProgress, encode_packet_frame}};
    use std::sync::{Mutex, mpsc};
    struct Trace {
        events: Arc<Mutex<Vec<&'static str>>>,
        prefix: mpsc::Sender<()>,
    }
    fn sender(mut circuit: E2eCircuit<'_>, local: [u8;4], peer: [u8;4], split: usize, trace: Trace) {
        let packet = l3(local,peer,b"withheld-tail");
        let wire = encode_packet_frame(&packet,1360).unwrap();
        circuit.write_all(&wire[..split]).unwrap();
        circuit.flush().unwrap();
        trace.events.lock().unwrap().push("prefix_sent");
        trace.prefix.send(()).unwrap();
        // A true circular wait in the old code: do not send tail until the
        // reverse packet is completely received and byte-exact.
        let mut prefix=[0;2]; circuit.read_exact(&mut prefix).unwrap();
        let mut reverse=vec![0;usize::from(u16::from_be_bytes(prefix))];
        assert!(reverse.len()<=1360);
        circuit.read_exact(&mut reverse).unwrap();
        assert_eq!(reverse,l3(peer,local,b"reverse"));
        trace.events.lock().unwrap().push("reverse_received");
        circuit.write_all(&wire[split..]).unwrap();
        circuit.flush().unwrap();
        trace.events.lock().unwrap().push("tail_sent");
        let mut end=[0;1];
        assert_eq!(circuit.read(&mut end).unwrap(),0);
    }
    fn receiver(mut circuit: E2eCircuit<'_>, local: [u8;4], peer: [u8;4],
        prefix: mpsc::Receiver<()>, events: Arc<Mutex<Vec<&'static str>>>, queued: bool) {
        circuit.enable_direct_read_ahead();
        let (device,host)=VirtualTun::try_pair(8,8,1360).unwrap();
        let mut path=PacketPath::try_new_over_e2e(&device,circuit,1360).unwrap();
        let ledger=boreas_tunnel::resource::Admission::new(boreas_tunnel::resource::Limits {
            handshakes_global:1,authenticated_global:1,authenticated_per_peer:1,bytes_global:128*1024,
        });
        if queued {assert!(path.configure_queued_progress(&ledger).unwrap());}
        prefix.recv_timeout(IO_TIMEOUT).unwrap();
        let until=Instant::now()+IO_TIMEOUT;
        path.progress_transport().unwrap();
        assert_eq!(path.step_inbound_progress(IO_TIMEOUT).unwrap(),InboundProgress::Pending);
        events.lock().unwrap().push("partial_returned");
        device.inject(&l3(local,peer,b"reverse")).unwrap();
        let mut sent=0;
        while sent==0 {
            path.progress_transport().unwrap();
            sent=path.step_outbound_batch(1,14000).unwrap();
            assert!(Instant::now()<until,"queued outbound stalled");
        }
        assert_eq!(sent,1);
        events.lock().unwrap().push("reverse_committed");
        loop {
            path.progress_transport().unwrap();
            match path.step_inbound_progress(IO_TIMEOUT).unwrap() {
                InboundProgress::Pending=>assert!(Instant::now()<until,"queued inbound stalled"),
                InboundProgress::Packet(n)=>{assert_eq!(n,l3(peer,local,b"withheld-tail").len());break;},
                InboundProgress::Closed=>panic!("premature close"),
            }
        }
        assert_eq!(host.read_packet().unwrap().unwrap(),l3(peer,local,b"withheld-tail"));
        events.lock().unwrap().push("packet_delivered");
        assert_eq!(path.stats().inbound_packets,1);
        assert_eq!(path.stats().outbound_packets,1);
        path.close_gracefully();
        assert_eq!(ledger.snapshot().unwrap().bytes,0);
    }
    let t=Temp::new(); setup(&t);
    for paused_server in [false,true] {
        for split in [1,2,34] {
            let (client_side,server_side)=sides(&t);
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();
            let address=listener.local_addr().unwrap();
            let events=Arc::new(Mutex::new(vec![]));
            let server_events=events.clone();
            let (prefix_tx,prefix_rx)=mpsc::channel();
            let (server_tx,client_rx)=mpsc::channel();
            let server=thread::spawn(move || {
                let tcp=bounded_accept(&listener).unwrap();
                let mut accepted=LinkServer::new(server_side.hop).accept_tls_stream(tcp,
                    &ShortAcceptor{inner:server_side.outer,chunk:257},
                    policy(server_side.local,server_side.peer),IO_TIMEOUT,&admission()).unwrap();
                let circuit=accept_e2e(&mut accepted.session,&server_side.e2e,server_side.peer).unwrap();
                if paused_server { receiver(circuit,[10,20,1,1],[10,20,1,2],prefix_rx,server_events,queued); }
                else { sender(circuit,[10,20,1,1],[10,20,1,2],split,Trace{events:server_events,prefix:server_tx}); }
            });
            let link=LinkClient::new(Box::new(ShortConnector{inner:client_side.outer,chunk:257}),client_side.hop);
            let mut hop=link.connect(&target(address,"wss.boreas.test"),
                policy(client_side.local,client_side.peer),IO_TIMEOUT).unwrap();
            let circuit=open_e2e(&mut hop,&client_side.e2e,client_side.peer,1).unwrap();
            if paused_server { sender(circuit,[10,20,1,2],[10,20,1,1],split,Trace{events:events.clone(),prefix:prefix_tx}); }
            else { receiver(circuit,[10,20,1,2],[10,20,1,1],client_rx,events.clone(),queued); }
            server.join().unwrap();
            let events=events.lock().unwrap();
            let at=|event| events.iter().position(|e| *e==event).unwrap();
            assert!(at("prefix_sent")<at("partial_returned"));
            assert!(at("partial_returned")<at("reverse_received"));
            assert!(at("reverse_received")<at("tail_sent"));
            assert_eq!(events.iter().filter(|e| **e=="packet_delivered").count(),1);
        }
    }
}
