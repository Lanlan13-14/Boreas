use super::*;
use std::{borrow::Cow, collections::VecDeque};

#[derive(Clone)]
enum ReadEvent {
    Packet(Vec<u8>),
    Empty,
    Error(TunError),
}
struct MatrixIo {
    reads: RefCell<VecDeque<ReadEvent>>,
    style: u8,
    writes: RefCell<Vec<Vec<u8>>>,
    addresses: RefCell<Vec<usize>>,
    fail_write: bool,
}
impl MatrixIo {
    fn new(events: Vec<ReadEvent>, style: u8) -> Self {
        Self {
            reads: RefCell::new(events.into()),
            style,
            writes: RefCell::new(Vec::new()),
            addresses: RefCell::new(Vec::new()),
            fail_write: false,
        }
    }
}
impl PacketIo for MatrixIo {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
        unreachable!()
    }
    fn read_for_forwarding<'a>(
        &self,
        scratch: &'a mut [u8],
    ) -> Result<Option<PacketRead<'a>>, TunError> {
        assert_eq!(scratch.len(), MAX_MTU + 1);
        self.addresses.borrow_mut().push(scratch.as_ptr() as usize);
        match self
            .reads
            .borrow_mut()
            .pop_front()
            .unwrap_or(ReadEvent::Empty)
        {
            ReadEvent::Empty => Ok(None),
            ReadEvent::Error(error) => Err(error),
            ReadEvent::Packet(bytes) => {
                if self.style == 0 {
                    return Ok(Some(PacketRead::Bytes(Cow::Owned(bytes))));
                }
                scratch[..bytes.len()].copy_from_slice(&bytes);
                let bytes = &scratch[..bytes.len()];
                if self.style == 1 {
                    Ok(Some(PacketRead::Bytes(Cow::Borrowed(bytes))))
                } else {
                    InspectedPacket::new(bytes).map(|p| Some(PacketRead::Inspected(p)))
                }
            }
        }
    }
    fn write_packet(&self, bytes: &[u8]) -> Result<(), TunError> {
        if self.fail_write {
            return Err(TunError::QueueFull);
        }
        self.writes.borrow_mut().push(bytes.to_vec());
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    Zero,
    Timeout,
    Interrupts,
    Flush,
}
struct MatrixStream {
    bytes: Rc<RefCell<Vec<u8>>>,
    calls: Rc<Cell<usize>>,
    fault: Fault,
}
impl Read for MatrixStream {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for MatrixStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let calls = self.calls.get();
        self.calls.set(calls + 1);
        match self.fault {
            Fault::Zero => return Ok(0),
            Fault::Interrupts => return Err(io::ErrorKind::Interrupted.into()),
            Fault::Timeout if calls > 0 => return Err(io::ErrorKind::TimedOut.into()),
            _ => {}
        }
        let n = bytes.len().min(3);
        self.bytes.borrow_mut().extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if matches!(self.fault, Fault::Flush) {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}
type BatchResult = (
    Result<usize, PacketPathError>,
    PacketStats,
    Option<PacketPathError>,
    Vec<u8>,
    usize,
    usize,
);
fn batch_result(
    events: Vec<ReadEvent>,
    style: u8,
    fault: Fault,
    fast: bool,
    packets: usize,
    threshold: usize,
) -> BatchResult {
    let io = MatrixIo::new(events, style);
    let bytes = Rc::new(RefCell::new(Vec::new()));
    let calls = Rc::new(Cell::new(0));
    let stream = MatrixStream {
        bytes: bytes.clone(),
        calls: calls.clone(),
        fault,
    };
    let mut path = PacketPath::try_new(
        &io,
        stream,
        endpoints(
            identity(0x0201, NodeRole::Core),
            identity(0x0209, NodeRole::Edge),
        ),
        DEFAULT_MTU,
    )
    .unwrap();
    let result = if fast {
        path.step_outbound_batch(packets, threshold)
    } else {
        path.step_outbound_batch_legacy(packets, threshold)
    };
    let remaining = io.reads.borrow().len();
    let summary = (
        result,
        path.stats(),
        path.first_error(),
        bytes.borrow().clone(),
        calls.get(),
        remaining,
    );
    if result.is_err() {
        assert!(path.circuit.is_none());
        assert_eq!(
            path.step_outbound_batch(16, 16000),
            Err(PacketPathError::Poisoned)
        );
        assert_eq!(path.step_inbound(), Err(PacketPathError::Poisoned));
    }
    summary
}
#[test]
fn outbound_inline_matches_legacy_owned_borrowed_and_inspected_fault_matrix() {
    let p = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"payload");
    let small = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"x");
    let spoof = ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"discard");
    let mut corrupt = p.clone();
    corrupt[10] ^= 1;
    let scenarios = vec![
        vec![],
        vec![
            ReadEvent::Packet(p.clone()),
            ReadEvent::Packet(small.clone()),
            ReadEvent::Empty,
        ],
        vec![
            ReadEvent::Packet(spoof.clone()),
            ReadEvent::Packet(p.clone()),
        ],
        vec![ReadEvent::Packet(p.clone()), ReadEvent::Packet(corrupt)],
        vec![
            ReadEvent::Packet(p.clone()),
            ReadEvent::Error(TunError::QueueClosed),
        ],
        vec![ReadEvent::Packet(spoof); 40],
    ];
    for style in 0..3 {
        for events in &scenarios {
            for fault in [
                Fault::None,
                Fault::Zero,
                Fault::Timeout,
                Fault::Interrupts,
                Fault::Flush,
            ] {
                for (packets, threshold) in [
                    (0, 16000),
                    (16, 0),
                    (1, 1),
                    (16, 1),
                    (16, 16000),
                    (usize::MAX, INLINE_BATCH_THRESHOLD),
                ] {
                    let a = batch_result(events.clone(), style, fault, true, packets, threshold);
                    let b = batch_result(events.clone(), style, fault, false, packets, threshold);
                    assert_eq!(
                        a, b,
                        "style={style} packets={packets} threshold={threshold}"
                    );
                }
            }
        }
    }
}
#[test]
fn inline_storage_reuses_high_water_and_never_sends_guard_or_stale_tail() {
    let large = ipv4([10, 20, 3, 1], [10, 20, 3, 9], &[0x9a; 1400]);
    let small = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"short");
    let io = MatrixIo::new(
        vec![
            ReadEvent::Packet(large.clone()),
            ReadEvent::Empty,
            ReadEvent::Packet(small.clone()),
            ReadEvent::Empty,
        ],
        2,
    );
    let (sink, bytes) = OutboundSink::new();
    let mut path = PacketPath::try_new(
        &io,
        sink,
        endpoints(
            identity(0x0201, NodeRole::Core),
            identity(0x0209, NodeRole::Edge),
        ),
        DEFAULT_MTU,
    )
    .unwrap();
    assert_eq!(path.step_outbound_batch(16, 16000), Ok(1));
    let base = path.outbound_inline.as_ptr() as usize;
    assert_eq!(io.addresses.borrow()[0], base + 2);
    assert_eq!(path.step_outbound_batch(16, 16000), Ok(1));
    assert_eq!(path.outbound_inline.as_ptr() as usize, base);
    assert_eq!(path.outbound_inline.len(), INLINE_BATCH_STORAGE);
    let mut expected = encode_packet_frame(&large, DEFAULT_MTU).unwrap();
    expected.extend(encode_packet_frame(&small, DEFAULT_MTU).unwrap());
    assert_eq!(*bytes.borrow(), expected);
    path.close();
    assert_eq!(
        path.step_outbound_batch(16, 16000),
        Err(PacketPathError::Closed)
    );
}
#[test]
fn prefetched_and_copied_delivery_match_under_short_reads_and_malformed_frames() {
    let policy =
        PointToPoint::try_new([10, 20, 3, 1].into(), [10, 20, 3, 9].into(), DEFAULT_MTU).unwrap();
    let valid = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"verified");
    let spoof = ipv4([10, 20, 3, 7], [10, 20, 3, 1], b"spoof");
    let mut corrupt = valid.clone();
    corrupt[10] ^= 1;
    for packet in [valid.clone(), spoof, corrupt] {
        let frame = encode_packet_frame(&packet, DEFAULT_MTU).unwrap();
        for fail_write in [false, true] {
            let mut borrowed = MatrixIo::new(vec![], 0);
            borrowed.fail_write = fail_write;
            let mut copied = MatrixIo::new(vec![], 0);
            copied.fail_write = fail_write;
            let fast = deliver_prefetched(&borrowed, &policy, &frame)
                .unwrap()
                .map(|(_, n)| n);
            let mut source = io::Cursor::new(frame.clone());
            let mut scratch = Vec::new();
            let slow = inbound_once(
                &copied,
                &mut source,
                &policy,
                &mut scratch,
                None,
                None,
                false,
            )
            .map(|v| v.unwrap().length);
            assert_eq!(fast, slow);
            assert_eq!(*borrowed.writes.borrow(), *copied.writes.borrow());
        }
        for length in 0..frame.len() {
            assert!(
                deliver_prefetched(&MatrixIo::new(vec![], 0), &policy, &frame[..length]).is_none()
            );
        }
    }
    assert_eq!(
        deliver_prefetched(&MatrixIo::new(vec![], 0), &policy, &[0, 0]),
        Some(Err(PacketPathError::EmptyFrame))
    );
    assert_eq!(
        deliver_prefetched(&MatrixIo::new(vec![], 0), &policy, &[255, 255]),
        Some(Err(PacketPathError::FrameTooLarge))
    );
}
