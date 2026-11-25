use super::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct Source {
    bytes: io::Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    chunk: usize,
    interrupted: bool,
}
impl Read for Source {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.interrupted { return Err(io::ErrorKind::Interrupted.into()); }
        let n = out.len().min(self.chunk);
        self.bytes.read(&mut out[..n])
    }
}
impl Write for Source {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl crate::stream::Duplex for Source {
    fn has_buffered_input(&self) -> bool {
        self.bytes.position() < self.bytes.get_ref().len() as u64
    }
}
impl crate::e2e::E2eStream for Source {
    fn close_stream(&mut self) -> io::Result<()> { Ok(()) }
}
fn path<'a>(io: &'a MatrixIo, bytes: Vec<u8>, chunk: usize, interrupted: bool)
    -> (PacketPath<'a, E2eCircuit<'a>, MatrixIo>, Arc<AtomicUsize>)
{
    let endpoints = endpoints(identity(0x0201, NodeRole::Core), identity(0x0209, NodeRole::Edge));
    let reads = Arc::new(AtomicUsize::new(0));
    let mut circuit = crate::e2e::test_plaintext_circuit(
        Box::new(Source { bytes: io::Cursor::new(bytes), reads: reads.clone(), chunk, interrupted }),
        PeerIdentity::policy_bound(NET, 0x0201, GENERATION, NodeRole::Core, test_policy_context(NET)).unwrap(),
        PeerIdentity::policy_bound(NET, 0x0209, GENERATION, NodeRole::Edge, test_policy_context(NET)).unwrap(),
    );
    circuit.enable_direct_read_ahead();
    (PacketPath::try_new(io, circuit, endpoints, DEFAULT_MTU).unwrap(), reads)
}
#[test]
fn empty_refill_first_and_second_packet_borrow_without_scratch_copy() {
    let packet = ipv4([10,20,3,9], [10,20,3,1], b"first and second");
    let wire = encode_packet_frame(&packet, DEFAULT_MTU).unwrap().repeat(2);
    let io = MatrixIo::new(vec![], 0);
    let (mut path, reads) = path(&io, wire, usize::MAX, false);
    path.inbound_scratch = vec![0xa5; 37];
    for count in 1..=2 {
        assert_eq!(path.step_inbound_prefetched(), Ok(Some(packet.len())));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(path.inbound_scratch, vec![0xa5; 37]);
        assert_eq!(path.stats().inbound_packets, count);
        assert_eq!(io.writes.borrow().len(), count as usize);
    }
    assert_eq!(path.step_inbound_prefetched(), Ok(None));
    assert!(!path.is_open());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}
#[test]
fn refill_error_and_every_truncation_match_legacy_terminal_semantics() {
    let packet = ipv4([10,20,3,9], [10,20,3,1], b"payload");
    let frame = encode_packet_frame(&packet, DEFAULT_MTU).unwrap();
    let mut inputs: Vec<_> = (0..=frame.len()).map(|n| frame[..n].to_vec()).collect();
    inputs.extend([vec![0,0], vec![255,255]]);
    for wire in inputs {
        for chunk in [1, 3, usize::MAX] {
            for fail_write in [false, true] {
                let mut a = MatrixIo::new(vec![], 0); a.fail_write = fail_write;
                let mut b = MatrixIo::new(vec![], 0); b.fail_write = fail_write;
                let (mut fast, _) = path(&a, wire.clone(), chunk, false);
                let (mut slow, _) = path(&b, wire.clone(), chunk, false);
                assert_eq!(fast.step_inbound_prefetched(), slow.step_inbound());
                assert_eq!(fast.stats(), slow.stats());
                assert_eq!(fast.first_error(), slow.first_error());
                assert_eq!(*a.writes.borrow(), *b.writes.borrow());
                if !fast.is_open() {
                    let before = a.writes.borrow().len();
                    assert!(fast.step_inbound_prefetched().is_err());
                    assert_eq!(a.writes.borrow().len(), before);
                    assert!(fast.circuit.is_none());
                } else {
                    assert_eq!(fast.circuit.as_ref().unwrap().prefetched_plaintext(),
                        slow.circuit.as_ref().unwrap().prefetched_plaintext());
                }
            }
        }
    }
    let a = MatrixIo::new(vec![], 0);
    let (mut fast, reads) = path(&a, vec![], 1, true);
    assert_eq!(fast.step_inbound_prefetched(), Err(PacketPathError::CircuitIo(io::ErrorKind::Interrupted)));
    assert_eq!(reads.load(Ordering::SeqCst), usize::from(MAX_INTERRUPT_RETRIES));
    assert!(fast.circuit.is_none());
}
