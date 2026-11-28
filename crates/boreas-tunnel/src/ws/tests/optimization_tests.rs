use super::*;

struct ShortIo {
    inner: MemoryIo,
    max: usize,
}
impl Read for ShortIo {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.max);
        self.inner.read(&mut out[..n])
    }
}
impl Write for ShortIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(&bytes[..bytes.len().min(self.max)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn encoded(masked: bool, opcode: OpCode, bytes: &[u8]) -> Vec<u8> {
    encode_frame_into(masked, true, opcode, bytes, &mut Vec::new())
        .unwrap()
        .to_vec()
}
#[test]
fn receive_payload_allocation_reused_with_short_io_and_control_frames() {
    for masked in [false, true] {
        for short in [1, 7, 65536] {
            let role = if masked {
                WsRole::Server
            } else {
                WsRole::Client
            };
            let payloads = [vec![0xa5; 16384], vec![0xb6; 31], vec![0xc7; 8192]];
            let mut wire = Vec::new();
            for bytes in &payloads {
                wire.extend(encoded(masked, OpCode::Ping, b"ping"));
                wire.extend(encoded(masked, OpCode::Binary, bytes));
            }
            wire.extend(encoded(masked, OpCode::Close, &[3, 232]));
            let mut stream = WsStream::new(
                ShortIo {
                    inner: memory(&wire),
                    max: short,
                },
                role,
                WsLimits::default(),
            );
            let mut first = None;
            for bytes in &payloads {
                let mut got = vec![0; bytes.len()];
                stream.read_exact(&mut got).unwrap();
                assert_eq!(got, *bytes);
                let ptr = stream.pending.as_ptr();
                if let Some(first) = first {
                    assert_eq!(ptr, first);
                } else {
                    first = Some(ptr);
                }
                assert!(stream.pending.capacity() >= 16384);
                assert_eq!(stream.pending.len(), 16384, "initialized high-water retained");
                assert_eq!(stream.pending_len, bytes.len());
            }
            let mut guard = [0x9a; 16];
            assert_eq!(stream.read(&mut guard).unwrap(), 0);
            assert_eq!(guard, [0x9a; 16]);
            assert_eq!(
                stream.read(&mut guard).unwrap(),
                0,
                "close payload must stay private"
            );
        }
    }
}
#[test]
fn truncated_reused_payload_never_exposes_old_or_partial_bytes_and_poison_is_terminal() {
    for masked in [false, true] {
        let good = encoded(masked, OpCode::Binary, &[0xab; 4096]);
        let next = encoded(masked, OpCode::Binary, &[0xcd; 17]);
        for cut in 1..next.len() {
            let mut wire = good.clone();
            wire.extend_from_slice(&next[..cut]);
            let mut stream = WsStream::new(
                ShortIo {
                    inner: memory(&wire),
                    max: 3,
                },
                if masked { WsRole::Server } else { WsRole::Client },
                WsLimits::default(),
            );
            let mut initial = [0; 4096];
            stream.read_exact(&mut initial).unwrap();
            assert_eq!(initial, [0xab; 4096]);
            let mut out = [0x75; 19];
            assert!(stream.read(&mut out).is_err());
            assert_eq!(out, [0x75; 19]);
            assert!(stream.read(&mut out).is_err());
            assert!(stream.write(b"stop").is_err());
        }
    }
}

#[test]
fn reused_storage_exposes_only_current_data_and_control_prefixes() {
    for masked in [false, true] {
        let role = if masked { WsRole::Server } else { WsRole::Client };
        let peer_role = if masked { WsRole::Client } else { WsRole::Server };
        let mut wire = encoded(masked, OpCode::Binary, &[0xa7; 4096]);
        wire.extend(encoded(masked, OpCode::Ping, b"p"));
        wire.extend(encoded(masked, OpCode::Binary, b""));
        wire.extend(encoded(masked, OpCode::Binary, b"xy"));
        wire.extend(encoded(masked, OpCode::Binary, &[0x31; 3000]));
        wire.extend(encoded(masked, OpCode::Close, &[3, 232]));
        let mut stream = WsStream::new(
            ShortIo { inner: memory(&wire), max: 7 },
            role,
            WsLimits::default(),
        );
        let mut out = [0xcc; 5000];
        assert_eq!(stream.read(&mut out).unwrap(), 4096);
        assert_eq!(&out[..4096], &[0xa7; 4096]);
        assert_eq!(out[4096], 0xcc);
        out.fill(0xcc);
        assert_eq!(stream.read(&mut out).unwrap(), 2);
        assert_eq!(&out[..2], b"xy");
        assert!(out[2..].iter().all(|&b| b == 0xcc));
        assert_eq!(stream.pending.len(), 4096);
        assert_eq!(stream.pending_len, 2);
        assert_eq!(stream.read(&mut out).unwrap(), 3000);
        assert_eq!(&out[..3000], &[0x31; 3000]);
        assert_eq!(stream.read(&mut out).unwrap(), 0);
        let mut replies = Cursor::new(stream.io.inner.output.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        let pong = read_frame(&mut replies, peer_role, &WsLimits::default(), deadline).unwrap();
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(pong.payload(), b"p");
        let close = read_frame(&mut replies, peer_role, &WsLimits::default(), deadline).unwrap();
        assert_eq!(close.opcode, OpCode::Close);
        assert_eq!(close.payload(), &[3, 232]);
        assert_eq!(replies.position() as usize, replies.get_ref().len());
    }
}

#[test]
fn shorter_fragment_is_checked_against_logical_message_length() {
    for masked in [false, true] {
        let role = if masked { WsRole::Server } else { WsRole::Client };
        let mut wire = encoded(masked, OpCode::Binary, &[0x55; 32]);
        wire.extend(encode_frame(masked, false, OpCode::Binary, b"a").unwrap());
        wire.extend(encode_frame(masked, true, OpCode::Continuation, b"bc").unwrap());
        let limits = WsLimits { max_message_bytes: 32, ..WsLimits::default() };
        let mut stream = WsStream::new(memory(&wire), role, limits);
        let mut out = [0; 32];
        assert_eq!(stream.read(&mut out).unwrap(), 32);
        assert_eq!(stream.read(&mut out).unwrap(), 1);
        assert_eq!(out[0], b'a');
        assert_eq!(stream.read(&mut out).unwrap(), 2);
        assert_eq!(&out[..2], b"bc");
    }
}

#[test]
fn short_caller_reads_stop_at_validated_boundary() {
    for masked in [false, true] {
        let role = if masked { WsRole::Server } else { WsRole::Client };
        let mut wire = encoded(masked, OpCode::Binary, &[0x91; 64]);
        wire.extend(encoded(masked, OpCode::Binary, b"abc"));
        wire.extend(encoded(masked, OpCode::Binary, b"z"));
        let mut stream = WsStream::new(memory(&wire), role, WsLimits::default());
        let mut large = [0; 64];
        stream.read_exact(&mut large).unwrap();
        let mut two = [0; 2];
        assert_eq!(stream.read(&mut two).unwrap(), 2);
        assert_eq!(&two, b"ab");
        two.fill(0xee);
        assert_eq!(stream.read(&mut two).unwrap(), 1);
        assert_eq!(two, [b'c', 0xee]);
        assert_eq!(stream.read(&mut two).unwrap(), 1);
        assert_eq!(two[0], b'z');
    }
}

#[test]
fn fragmented_message_limit_still_fails_closed_after_large_frame() {
    for masked in [false, true] {
        let role = if masked { WsRole::Server } else { WsRole::Client };
        let mut wire = encoded(masked, OpCode::Binary, &[0x66; 8]);
        wire.extend(encode_frame(masked, false, OpCode::Binary, b"12345").unwrap());
        wire.extend(encode_frame(masked, true, OpCode::Continuation, b"6789").unwrap());
        let limits = WsLimits { max_message_bytes: 8, ..WsLimits::default() };
        let mut stream = WsStream::new(memory(&wire), role, limits);
        let mut out = [0; 16];
        assert_eq!(stream.read(&mut out).unwrap(), 8);
        assert_eq!(stream.read(&mut out).unwrap(), 5);
        out.fill(0xe1);
        assert!(stream.read(&mut out).is_err());
        assert_eq!(out, [0xe1; 16]);
        assert!(stream.read(&mut out).is_err());
    }
}

// A partial frame keeps its cursor on WouldBlock and never exposes old
// high-water storage. Reverse-direction writes remain independently usable.
struct BlockAfterInput {
    input: Cursor<Vec<u8>>,
}
impl Read for BlockAfterInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.input.read(out)?;
        if n == 0 { Err(io::ErrorKind::WouldBlock.into()) } else { Ok(n) }
    }
}
impl Write for BlockAfterInput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn partial_frame_then_would_block_resumes_without_leaking_storage() {
    for masked in [false, true] {
        let role = if masked { WsRole::Server } else { WsRole::Client };
        let mut wire = encoded(masked, OpCode::Binary, &[0x5a; 64]);
        let partial = encoded(masked, OpCode::Binary, b"abcdef");
        wire.extend_from_slice(&partial[..partial.len() - 1]);
        let mut stream = WsStream::new(
            BlockAfterInput { input: Cursor::new(wire) },
            role,
            WsLimits::default(),
        );
        let mut out = [0; 64];
        assert_eq!(stream.read(&mut out).unwrap(), 64);
        out.fill(0xd2);
        assert_eq!(stream.read(&mut out).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(out, [0xd2; 64]);
        assert_eq!(stream.read(&mut out).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(stream.write(b"later").unwrap(), 5);
        stream.io.input.get_mut().push(*partial.last().unwrap());
        assert_eq!(stream.read(&mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"abcdef");
    }
}
