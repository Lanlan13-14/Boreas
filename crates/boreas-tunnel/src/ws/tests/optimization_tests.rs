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
    let good = encoded(false, OpCode::Binary, &[0xab; 4096]);
    let next = encoded(false, OpCode::Binary, &[0xcd; 17]);
    for cut in 1..next.len() {
        let mut wire = good.clone();
        wire.extend_from_slice(&next[..cut]);
        let mut stream = WsStream::new(
            ShortIo {
                inner: memory(&wire),
                max: 3,
            },
            WsRole::Client,
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
