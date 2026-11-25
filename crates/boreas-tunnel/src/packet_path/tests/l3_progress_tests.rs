use super::*;
use std::{sync::{Arc, Mutex}, time::Duration};

struct SplitPlaintext {
    bytes: io::Cursor<Vec<u8>>,
    split: usize,
    first: bool,
    events: Arc<Mutex<Vec<&'static str>>>,
    writes: Arc<Mutex<Vec<u8>>>,
}
impl Read for SplitPlaintext {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = if self.first { self.first = false; self.split.min(out.len()) }
            else { out.len() };
        let read = self.bytes.read(&mut out[..count])?;
        self.events.lock().unwrap().push(if self.bytes.position() as usize <= self.split {
            "partial" } else { "tail" });
        Ok(read)
    }
}
impl Write for SplitPlaintext {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.events.lock().unwrap().push("outbound");
        self.writes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl crate::stream::Duplex for SplitPlaintext {}
impl crate::e2e::E2eStream for SplitPlaintext {
    fn close_stream(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn partial_l3_returns_pending_and_sends_before_tail_on_both_roles() {
    for (local, peer) in [(identity(0x0201,NodeRole::Core),identity(0x0209,NodeRole::Edge)),
        (identity(0x0209,NodeRole::Edge),identity(0x0201,NodeRole::Core))] {
        let facts = endpoints(local,peer);
        let incoming = ipv4(facts.peer.vip.octets(), facts.local.vip.octets(), b"incoming");
        let outgoing = ipv4(facts.local.vip.octets(), facts.peer.vip.octets(), b"outgoing");
        let wire = encode_packet_frame(&incoming,DEFAULT_MTU).unwrap();
        for split in [1,2,wire.len()-1] {
            let events = Arc::new(Mutex::new(vec![]));
            let writes = Arc::new(Mutex::new(vec![]));
            let source = SplitPlaintext { bytes: io::Cursor::new(wire.clone()), split,
                first: true, events: events.clone(), writes: writes.clone() };
            let mut circuit = crate::e2e::test_plaintext_circuit(Box::new(source),local,peer);
            circuit.enable_direct_read_ahead();
            let io = MatrixIo::new(vec![ReadEvent::Packet(outgoing.clone())],0);
            let mut path = PacketPath::try_new(&io,circuit,endpoints(local,peer),DEFAULT_MTU).unwrap();
            path.inbound_scratch = vec![0xa5;MAX_MTU];
            assert_eq!(path.step_inbound_progress(Duration::from_secs(30)),Ok(InboundProgress::Pending));
            assert!(path.is_open());
            assert_eq!(path.stats().inbound_packets,0);
            assert!(!path.has_progress_input()); // retained partial alone isn't readiness
            events.lock().unwrap().push("tun_ready");
            assert_eq!(path.step_outbound_batch(1,16000),Ok(1));
            assert_eq!(*writes.lock().unwrap(),encode_packet_frame(&outgoing,DEFAULT_MTU).unwrap());
            assert_eq!(path.step_inbound_progress(Duration::from_secs(30)),Ok(InboundProgress::Packet(incoming.len())));
            assert_eq!(*events.lock().unwrap(),["partial","tun_ready","outbound","tail"]);
            assert_eq!(io.writes.borrow().as_slice(),std::slice::from_ref(&incoming));
            assert!(path.inbound_scratch.iter().all(|byte| *byte==0xa5));
        }
    }
}

#[test]
fn partial_l3_absolute_deadline_is_not_renewed_and_poisons_both_directions() {
    let local=identity(0x0201,NodeRole::Core); let peer=identity(0x0209,NodeRole::Edge);
    let source=SplitPlaintext {bytes:io::Cursor::new(vec![0,40,0x45]),split:1,first:true,
        events:Arc::new(Mutex::new(vec![])),writes:Arc::new(Mutex::new(vec![]))};
    let mut circuit=crate::e2e::test_plaintext_circuit(Box::new(source),local,peer);
    circuit.enable_direct_read_ahead();
    let io=MatrixIo::new(vec![],0);
    let mut path=PacketPath::try_new(&io,circuit,endpoints(local,peer),DEFAULT_MTU).unwrap();
    assert_eq!(path.step_inbound_progress(Duration::ZERO),Ok(InboundProgress::Pending));
    assert_eq!(path.check_inbound_progress_deadline(),Err(PacketPathError::CircuitIo(io::ErrorKind::TimedOut)));
    assert!(path.circuit.is_none());
    assert_eq!(path.step_outbound_batch(1,16000),Err(PacketPathError::Poisoned));
}
