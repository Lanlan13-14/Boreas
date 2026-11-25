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

#[test]
fn mixed_dns_borrows_ordinary_packet_and_preserves_special_cursor() {
    let ordinary = ipv4([10,20,3,9], [10,20,3,1], b"ordinary");
    let dns = ipv4([10,20,0,53], [10,20,3,1], b"not a valid DNS response");
    let mut wire = encode_packet_frame(&ordinary, DEFAULT_MTU).unwrap();
    wire.extend(encode_packet_frame(&dns, DEFAULT_MTU).unwrap());
    let io = MatrixIo::new(vec![], 0);
    let (mut path, reads) = path(&io, wire, usize::MAX, false);
    path.edge_dns = Some(EdgeDns {
        vip: [10,20,0,53].into(), zone: "private.example",
        public: false, current: Box::new(|| true), pending: Default::default(), tcp: None,
    });
    path.inbound_scratch = vec![0xa5; 37];
    assert_eq!(path.step_inbound_prefetched(), Ok(Some(ordinary.len())));
    assert_eq!(path.inbound_scratch, vec![0xa5; 37]);
    assert_eq!(io.writes.borrow().as_slice(), &[ordinary]);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    // DNS bytes are not consumed by classification. The original responder
    // reparses once and rejects malformed content rather than forwarding it.
    let pending = path.circuit.as_ref().unwrap().prefetched_plaintext().unwrap();
    let policy = path.policy;
    assert!(deliver_prefetched_classified(&io, &policy, pending,
        None, Some([10,20,0,53].into()), false).is_none());
    assert!(path.step_inbound_prefetched().is_err());
    assert_eq!(path.stats().inbound_packets, 1);
    assert_eq!(io.writes.borrow().len(), 1);
    assert!(path.circuit.is_none());
}

#[test]
fn classification_priority_and_replica_isolation_match_both_entry_points() {
    let policy = PointToPoint::try_new([10,20,3,1].into(), [10,20,3,9].into(), DEFAULT_MTU).unwrap();
    for (src, dst, replica, expected) in [
        ([10,20,3,9], [10,20,3,1], false, Ok(InboundClass::Host)),
        ([10,20,3,9], [10,20,0,53], true, Ok(InboundClass::CoreDns)),
        ([10,20,3,7], [10,20,0,53], false, Err(PacketPathError::Denied(PacketDeny::SourceNotPeer))),
        ([10,20,0,53], [10,20,3,1], true, Ok(InboundClass::EdgeDns)),
        ([10,20,0,53], [10,20,3,7], false, Err(PacketPathError::Denied(PacketDeny::DestinationNotLocal))),
        ([10,20,3,9], [10,20,3,1], true, Err(PacketPathError::Denied(PacketDeny::NotDnsTraffic))),
    ] {
        let packet = ipv4(src, dst, b"classification");
        let inspected = policy.inspect_bytes(&packet).unwrap();
        assert_eq!(classify_inbound(&policy, inspected,
            Some([10,20,0,53].into()), Some([10,20,0,53].into()), replica), expected);
    }
}

#[test]
fn daemon_configuration_entry_uses_lease_final_policy_and_releases_credit() {
    use crate::resource::{Admission, Limits};
    for (real_tun, replica, dedicated, want) in [
        (true,false,false,true), (false,false,false,false),
        (true,true,false,false), (true,false,true,false),
    ] {
        let io = MatrixIo::new(vec![], 0);
        let (mut path, _) = path(&io, vec![], usize::MAX, false);
        // Clear the fixture-only optimization to test production admission.
        path.circuit.as_mut().unwrap().disable_read_ahead_for_test();
        path.dns_replica_only = dedicated;
        let admission = Admission::new(Limits {
            handshakes_global: 1, authenticated_global: 1,
            authenticated_per_peer: 1, bytes_global: 16384,
        });
        assert_eq!(path.configure_direct_read_ahead(real_tun, replica, &admission), want);
        assert_eq!(admission.snapshot().unwrap().bytes, if want { 16384 } else { 0 });
        path.close();
        assert_eq!(admission.snapshot().unwrap().bytes, 0);
    }
    let io = MatrixIo::new(vec![], 0);
    let (mut path, _) = path(&io, vec![], usize::MAX, false);
    path.circuit.as_mut().unwrap().disable_read_ahead_for_test();
    let admission = Admission::new(Limits {
        handshakes_global: 1, authenticated_global: 1,
        authenticated_per_peer: 1, bytes_global: 16383,
    });
    assert!(!path.configure_direct_read_ahead(true, false, &admission));
    assert!(path.is_open());
    assert_eq!(path.step_inbound_prefetched(), Ok(None));
    assert_eq!(admission.snapshot().unwrap().bytes, 0);
}

#[test]
fn prefetched_dns_checks_current_lease_and_matching_transaction_at_delivery() {
    use crate::dns_runtime::tests::{dns_query, udp_datagram};
    use std::sync::atomic::AtomicBool;
    let local = identity(0x0209, NodeRole::Edge);
    let peer = identity(0x0201, NodeRole::Core);
    let vip = [10,20,0,53];
    let query = dns_query("host.private.example", 1);
    let mut answer = query.clone();
    answer[2] |= 0x84;
    let valid = udp_datagram(vip, [10,20,3,9], 53, 40_001, &answer, true);
    let wrong = udp_datagram(vip, [10,20,3,9], 53, 40_002, &answer, true);
    for expired in [false, true] {
        for optimized in [false, true] {
            let io = MatrixIo::new(vec![], 0);
            let reads = Arc::new(AtomicUsize::new(0));
            let live = Arc::new(AtomicBool::new(true));
            let mut bytes = encode_packet_frame(&wrong, DEFAULT_MTU).unwrap();
            bytes.extend(encode_packet_frame(&valid, DEFAULT_MTU).unwrap());
            bytes.extend(encode_packet_frame(&valid, DEFAULT_MTU).unwrap());
            let mut circuit = crate::e2e::test_plaintext_circuit(Box::new(Source {
                bytes: io::Cursor::new(bytes), reads, chunk: usize::MAX, interrupted: false,
            }), local, peer);
            circuit.enable_direct_read_ahead();
            let mut path = PacketPath::try_new(&io, circuit, endpoints(local,peer), DEFAULT_MTU).unwrap();
            let current = live.clone();
            let mut dns = EdgeDns {
                vip: vip.into(), zone: "private.example", public: false,
                current: Box::new(move || current.load(Ordering::SeqCst)),
                pending: Default::default(), tcp: None,
            };
            let request = udp_datagram([10,20,3,9], vip, 40_001, 53, &query, true);
            let request = PacketRead::Inspected(InspectedPacket::new(&request).unwrap());
            assert!(authorize_outbound_read(&path.policy, &request, Some(&mut dns), false).is_ok());
            path.edge_dns = Some(dns);
            assert!(matches!(path.circuit.as_mut().unwrap().fill_prefetched_plaintext(),
                crate::e2e::PrefetchFill::HasBytes));
            // Revoke after bytes arrived but before the dispatcher can publish.
            live.store(!expired, Ordering::SeqCst);
            let step = |path: &mut PacketPath<'_, E2eCircuit<'_>, MatrixIo>| {
                if optimized { path.step_inbound_prefetched() } else { path.step_inbound() }
            };
            if expired {
                assert_eq!(step(&mut path), Err(PacketPathError::DnsAuthorizationLost));
                assert!(io.writes.borrow().is_empty());
                assert!(path.circuit.is_none());
            } else {
                assert_eq!(step(&mut path), Ok(Some(wrong.len())));
                assert!(io.writes.borrow().is_empty());
                assert_eq!(step(&mut path), Ok(Some(valid.len())));
                assert_eq!(io.writes.borrow().as_slice(), std::slice::from_ref(&valid));
                assert_eq!(step(&mut path), Ok(Some(valid.len())));
                assert_eq!(io.writes.borrow().len(), 1); // replay not published twice
            }
        }
    }
}
