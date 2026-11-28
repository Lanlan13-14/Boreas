use super::*;

fn wire(len: usize, byte: u8) -> Vec<u8> {
    let mut wire = AppHeader {
        proto_major: PROTO_MAJOR, kind: Kind::RelayCircuit, flags: 0, body_len: len as u32,
    }.encode().unwrap().to_vec();
    wire.resize(HEADER_LEN + len, byte);
    wire
}
#[test]
fn one_owner_reuses_capacity_for_split_and_contiguous_frames() {
    for chunk in [8192, usize::MAX] {
        let wire = wire(16384, 0xa5);
        let mut decoder = FrameDecoder::new(HEADER_LEN + 65536);
        let mut previous = None;
        for _ in 0..8 {
            let mut frames = Vec::new();
            for bytes in wire.chunks(chunk) {
                decoder.feed_into(bytes, &mut frames).unwrap();
            }
            assert_eq!(frames.len(), 1);
            let mut body = frames.pop().unwrap().body;
            assert_eq!(body, vec![0xa5;16384]);
            if let Some((ptr, capacity)) = previous {
                assert_eq!((body.as_ptr() as usize, body.capacity()), (ptr, capacity));
            }
            previous = Some((body.as_ptr() as usize, body.capacity()));
            body.clear();
            assert!(decoder.recycle_empty_body(body, 16384));
            assert_eq!(decoder.body_capacity(), 16384);
        }
    }
}
#[test]
fn recycle_refuses_live_oversize_or_second_owner_and_batch_errors_publish_nothing() {
    let mut decoder = FrameDecoder::new(65544);
    assert!(!decoder.recycle_empty_body(vec![1], 65536));
    assert!(!decoder.recycle_empty_body(Vec::with_capacity(8193), 8192));
    let spare = Vec::with_capacity(16384);
    let pointer = spare.as_ptr() as usize;
    assert!(decoder.recycle_empty_body(spare, 16384));
    assert!(!decoder.recycle_empty_body(Vec::with_capacity(10), 16384));
    let mut batch = wire(3, 7);
    batch.extend(wire(5, 8));
    let frames = decoder.feed(&batch).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].body.as_ptr() as usize, pointer);
    assert_ne!(frames[1].body.as_ptr(), frames[0].body.as_ptr());
    assert_eq!(frames[0].body, vec![7;3]);
    assert_eq!(frames[1].body, vec![8;5]);
    let mut bad = wire(3, 7);
    bad.extend_from_slice(&[0xff; HEADER_LEN]);
    let mut out = frames;
    assert_eq!(decoder.feed_into(&bad, &mut out), Err(Error::BadVersion(0xff)));
    assert!(out.is_empty());
    assert!(decoder.is_failed());
    assert_eq!(decoder.body_capacity(), 0);
    assert!(!decoder.recycle_empty_body(Vec::with_capacity(10), 16384));
    assert_eq!(decoder.feed(&wire(3, 7)), Err(Error::Poisoned));
}
#[test]
fn recycled_capacity_does_not_accept_unarrived_bytes_or_weaken_feed_quota() {
    let mut decoder = FrameDecoder::new(32);
    assert!(decoder.recycle_empty_body(Vec::with_capacity(64), 64));
    let wire = wire(24, 1);
    assert!(decoder.feed(&wire[..9]).unwrap().is_empty());
    assert_eq!(decoder.buffered_len(), 9);
    let mut tail = wire[9..].to_vec();
    tail.extend_from_slice(&wire);
    let mut out = Vec::new();
    assert_eq!(decoder.feed_into(&tail, &mut out), Err(Error::BufferLimit));
    assert!(out.is_empty());
    assert_eq!(decoder.body_capacity(), 0);
}
