//! Opt-in, thread-local record-chain diagnostics. No payloads are retained.
//! A scope never changes I/O sizes, deadlines, authorization or TLS policy.
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    Circuit,
    Frame,
    WebSocket,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Writes {
    pub calls: u64,
    pub bytes: u64,
    /// <=128, <=512, <=2048, <=8192, <=16384, larger.
    pub sizes: [u64; 6],
}
impl Writes {
    fn observe(&mut self, bytes: usize) {
        self.calls += 1;
        self.bytes += bytes as u64;
        let index = [128, 512, 2048, 8192, 16384]
            .iter()
            .position(|&bound| bytes <= bound)
            .unwrap_or(5);
        self.sizes[index] += 1;
    }
}

/// Streaming TLS wire-header counter; handles headers split across writes.
/// Counts ciphertext records, NOT SSL_write calls or flushes. A scope must
/// begin between complete records (the benchmark starts after confirmation).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Records {
    pub records: u64,
    pub ciphertext_bytes: u64,
    pub invalid_header: bool,
    header: [u8; 5],
    header_used: usize,
    remaining: usize,
}
impl Records {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && !self.invalid_header {
            if self.remaining != 0 {
                let take = self.remaining.min(bytes.len());
                self.remaining -= take;
                bytes = &bytes[take..];
                continue;
            }
            let take = (5 - self.header_used).min(bytes.len());
            self.header[self.header_used..self.header_used + take].copy_from_slice(&bytes[..take]);
            self.header_used += take;
            bytes = &bytes[take..];
            if self.header_used == 5 {
                if !(20..=23).contains(&self.header[0])
                    || self.header[1] != 3
                    || self.header[2] != 3
                {
                    self.invalid_header = true;
                    break;
                }
                self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.records += 1;
                self.ciphertext_bytes += (5 + self.remaining) as u64;
                self.header_used = 0;
            }
        }
    }
    pub fn complete(&self) -> bool {
        !self.invalid_header && self.header_used == 0 && self.remaining == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchExit {
    Empty,
    PacketBudget,
    ByteBudget,
    DiscardBudget,
    Fatal,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Batches {
    pub exits: [u64; 5],
    pub packets: u64,
    pub effective_bytes: u64,
    pub framed_bytes: u64,
}
pub(crate) fn observe_batch(exit: BatchExit, packets: usize, effective: u64, framed: usize) {
    ACTIVE.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            let batches = &mut state.batches;
            batches.exits[exit as usize] += 1;
            batches.packets += packets as u64;
            batches.effective_bytes += effective;
            batches.framed_bytes += framed as u64;
        }
    });
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub batches: Batches,
    pub circuit: Writes,
    pub frame: Writes,
    pub websocket: Writes,
    pub e2e_records: Records,
    pub hop_records: Records,
    pub socket_reads: Writes,
    pub socket_writes: Writes,
    pub socket_write_attempts: u64,
    pub outer_records: Records,
}
thread_local! {
    static ACTIVE: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
}
/// Deliberately !Send: a scope belongs to exactly one data-plane thread.
pub struct Scope {
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Scope {
    pub fn begin() -> Self {
        ACTIVE.with(|slot| {
            assert!(slot.borrow().is_none(), "nested record diagnostic scope");
            *slot.borrow_mut() = Some(Snapshot::default());
        });
        Self {
            _thread: std::marker::PhantomData,
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        ACTIVE.with(|slot| slot.borrow().expect("active diagnostic scope"))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(crate) fn observe(layer: Layer, bytes: &[u8]) {
    ACTIVE.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            match layer {
                Layer::Circuit => {
                    state.circuit.observe(bytes.len());
                    state.e2e_records.feed(bytes);
                }
                Layer::Frame => state.frame.observe(bytes.len()),
                Layer::WebSocket => {
                    state.websocket.observe(bytes.len());
                    state.hop_records.feed(bytes);
                }
            }
        }
    });
}

/// Wraps only the real TCP transport below OpenSSL; never retains bytes.
#[cfg(all(feature = "record-diagnostics", feature = "openssl-inner-tls"))]
pub(crate) struct Socket(pub std::net::TcpStream);
#[cfg(all(feature = "record-diagnostics", feature = "openssl-inner-tls"))]
impl std::io::Read for Socket {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let result = std::io::Read::read(&mut self.0, out);
        ACTIVE.with(|slot| {
            if let Some(s) = slot.borrow_mut().as_mut() {
                s.socket_reads
                    .observe(result.as_ref().copied().unwrap_or(0));
            }
        });
        result
    }
}
#[cfg(all(feature = "record-diagnostics", feature = "openssl-inner-tls"))]
impl std::io::Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = std::io::Write::write(&mut self.0, bytes);
        ACTIVE.with(|slot| {
            if let Some(s) = slot.borrow_mut().as_mut() {
                s.socket_write_attempts += 1;
                if let Ok(n) = result.as_ref() {
                    s.socket_writes.observe(*n);
                    s.outer_records.feed(&bytes[..*n]);
                }
            }
        });
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)
    }
}
#[cfg(all(feature = "record-diagnostics", feature = "openssl-inner-tls"))]
impl crate::stream::Duplex for Socket {
    fn enable_progress(&mut self) -> std::io::Result<bool> {
        crate::stream::Duplex::enable_progress(&mut self.0)
    }
    fn progress_io(&mut self) -> std::io::Result<crate::stream::ProgressIo> {
        crate::stream::Duplex::progress_io(&mut self.0)
    }
    fn is_raw_socket(&self) -> bool { true }
    fn wait_progress(&self, timeout: std::time::Duration, write: bool) -> std::io::Result<()> {
        crate::stream::Duplex::wait_progress(&self.0, timeout, write)
    }
    fn has_buffered_input(&self) -> bool {
        false
    }
    fn set_io_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(timeout)?;
        self.0.set_write_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_and_payloads_can_be_split_at_every_byte() {
        let wire = [23, 3, 3, 0, 3, 8, 9, 10, 23, 3, 3, 0, 1, 11];
        for split in 0..=wire.len() {
            let mut records = Records::default();
            records.feed(&wire[..split]);
            records.feed(&wire[split..]);
            assert_eq!(records.records, 2);
            assert_eq!(records.ciphertext_bytes, 14);
            assert!(records.complete());
        }
        let mut records = Records::default();
        for byte in wire {
            records.feed(&[byte]);
        }
        assert!(records.complete());
        assert_eq!(records.records, 2);
    }
    #[test]
    fn partial_invalid_and_empty_are_not_reported_as_complete_records() {
        let mut records = Records::default();
        records.feed(&[23, 3]);
        assert!(!records.complete());
        let mut records = Records::default();
        records.feed(&[23, 3, 3, 0, 4, 1]);
        assert!(!records.complete());
        let mut records = Records::default();
        records.feed(&[0, 0, 0, 0, 0]);
        assert!(records.invalid_header);
        assert_eq!(records.records, 0);
        assert!(Records::default().complete());
    }
    #[test]
    fn scopes_reset_and_cannot_leak_between_threads() {
        let scope = Scope::begin();
        observe(Layer::Frame, &[1; 129]);
        std::thread::spawn(|| {
            let child = Scope::begin();
            assert_eq!(child.snapshot(), Snapshot::default());
        })
        .join()
        .unwrap();
        assert_eq!(scope.snapshot().frame.sizes, [0, 1, 0, 0, 0, 0]);
        drop(scope);
        observe(Layer::Frame, &[2]);
        let next = Scope::begin();
        assert_eq!(next.snapshot(), Snapshot::default());
    }
}
