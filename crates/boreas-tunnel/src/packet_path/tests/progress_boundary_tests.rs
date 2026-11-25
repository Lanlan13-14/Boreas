//! Event-order evidence for pre.7's synchronous boundary. These tests expose
//! the stall; they are NOT acceptance tests claiming the stall is repaired.
use super::*;
use std::sync::{Arc, Mutex, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event { PartialRead, TunReady, TailReleased, OutboundBytes }
struct PausedRead {
    bytes: io::Cursor<Vec<u8>>,
    split: usize,
    waiting: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    events: Arc<Mutex<Vec<Event>>>,
}
impl Read for PausedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let position = self.bytes.position() as usize;
        if position >= self.split && let Some(waiting) = self.waiting.take() {
            self.events.lock().unwrap().push(Event::PartialRead);
            waiting.send(()).unwrap();
            self.release.recv().unwrap();
        }
        let available = if position < self.split { self.split - position } else { out.len() };
        let count = out.len().min(available);
        self.bytes.read(&mut out[..count])
    }
}
impl Write for PausedRead {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.events.lock().unwrap().push(Event::OutboundBytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl crate::stream::Duplex for PausedRead {
    fn has_buffered_input(&self) -> bool { true }
}
impl crate::e2e::E2eStream for PausedRead {
    fn close_stream(&mut self) -> io::Result<()> { Ok(()) }
}
#[test]
fn synchronous_l3_partial_prefix_and_body_prevent_next_outbound_turn() {
    for reversed in [false, true] {
        let (local, peer) = if reversed {
            (identity(0x0209, NodeRole::Edge), identity(0x0201, NodeRole::Core))
        } else { (identity(0x0201, NodeRole::Core), identity(0x0209, NodeRole::Edge)) };
        let facts = endpoints(local, peer);
        let incoming = ipv4(facts.peer.vip.octets(), facts.local.vip.octets(), b"inbound");
        let outgoing = ipv4(facts.local.vip.octets(), facts.peer.vip.octets(), b"outbound");
        let wire = encode_packet_frame(&incoming, DEFAULT_MTU).unwrap();
        for (split, optimized) in [1, 2, wire.len()-1].into_iter()
            .flat_map(|split| [(split, false), (split, true)]) {
            let (waiting, wait) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let events = Arc::new(Mutex::new(Vec::new()));
            let driver_events = events.clone();
            let (device, host) = boreas_tun::VirtualTun::try_pair(4,4,DEFAULT_MTU).unwrap();
            let bytes = wire.clone();
            let incoming_len = incoming.len();
            let endpoints = endpoints(local, peer);
            let thread = std::thread::spawn(move || {
                let circuit = PausedRead { bytes: io::Cursor::new(bytes), split,
                    waiting: Some(waiting), release: released, events: driver_events };
                if optimized {
                    let mut circuit = crate::e2e::test_plaintext_circuit(
                        Box::new(circuit), local, peer,
                    );
                    circuit.enable_direct_read_ahead();
                    let mut path = PacketPath::try_new(&device, circuit, endpoints, DEFAULT_MTU).unwrap();
                    assert_eq!(path.step_inbound_prefetched().unwrap(), Some(incoming_len));
                    assert_eq!(path.step_outbound_batch(1,16000).unwrap(), 1);
                } else {
                    let mut path = PacketPath::try_new(&device, circuit, endpoints, DEFAULT_MTU).unwrap();
                    assert_eq!(path.step_inbound().unwrap(), Some(incoming_len));
                    assert_eq!(path.step_outbound_batch(1,16000).unwrap(), 1);
                }
            });
            wait.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            host.write_packet(&outgoing).unwrap();
            events.lock().unwrap().push(Event::TunReady);
            // The driver itself has announced that its next operation is the
            // tail wait. No sleep or throughput threshold infers this order.
            assert_eq!(*events.lock().unwrap(), [Event::PartialRead, Event::TunReady]);
            events.lock().unwrap().push(Event::TailReleased);
            release.send(()).unwrap();
            thread.join().unwrap();
            let events = events.lock().unwrap();
            assert_eq!(&events[..3], [Event::PartialRead, Event::TunReady, Event::TailReleased]);
            assert!(events[3..].iter().all(|event| *event == Event::OutboundBytes));
            assert!(events.len() > 3);
        }
    }
}
