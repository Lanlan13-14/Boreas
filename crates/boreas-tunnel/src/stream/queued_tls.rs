//! TLS application-phase byte queues. Handshakes remain synchronous and use
//! the existing verified backend. Activation is explicit and after E2E bind.
use super::{Duplex, ProgressIo};
use openssl::ssl::{ErrorCode, SslStream};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub(crate) const QUEUE_BYTES: usize = 8192;
pub(crate) const TLS_PROGRESS_BYTES: usize = 4 * QUEUE_BYTES;

pub(crate) struct QueueIo<S> {
    inner: S,
    buffers: Option<Queues>,
}
struct Queues {
    input: Box<[u8; QUEUE_BYTES]>,
    input_pos: usize,
    input_len: usize,
    output: Box<[u8; QUEUE_BYTES]>,
    output_pos: usize,
    output_len: usize,
    eof: bool,
    output_attempt_end: Option<usize>,
    output_deadline: Option<Instant>,
}
impl<S> QueueIo<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            buffers: None,
        }
    }
    fn active(&self) -> bool {
        self.buffers.is_some()
    }
    fn input_ready(&self) -> bool {
        self.buffers
            .as_ref()
            .is_some_and(|q| q.input_pos < q.input_len || q.eof)
    }
    fn output_pending(&self) -> bool {
        self.buffers
            .as_ref()
            .is_some_and(|q| q.output_pos < q.output_len)
    }
}
impl<S: Read> Read for QueueIo<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Some(q) = &mut self.buffers else {
            return self.inner.read(out);
        };
        if out.is_empty() {
            return Ok(0);
        }
        let n = out.len().min(q.input_len - q.input_pos);
        if n == 0 {
            return if q.eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        out[..n].copy_from_slice(&q.input[q.input_pos..q.input_pos + n]);
        q.input_pos += n;
        Ok(n)
    }
}
impl<S: Write> Write for QueueIo<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(q) = &mut self.buffers else {
            return self.inner.write(bytes);
        };
        if bytes.is_empty() {
            return Ok(0);
        }
        if q.output_pos == q.output_len {
            q.output_pos = 0;
            q.output_len = 0;
            q.output_deadline = None;
        }
        q.output_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
        let n = bytes.len().min(QUEUE_BYTES - q.output_len);
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        q.output[q.output_len..q.output_len + n].copy_from_slice(&bytes[..n]);
        q.output_len += n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.active() {
            Ok(())
        } else {
            self.inner.flush()
        }
    }
}
impl<S: Duplex> QueueIo<S> {
    fn activate(&mut self) -> io::Result<()> {
        if self.active() {
            return Ok(());
        }
        if !self.inner.enable_progress()? {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.buffers = Some(Queues {
            input: Box::new([0; QUEUE_BYTES]),
            input_pos: 0,
            input_len: 0,
            output: Box::new([0; QUEUE_BYTES]),
            output_pos: 0,
            output_len: 0,
            eof: false,
            output_attempt_end: None,
            output_deadline: None,
        });
        Ok(())
    }
    fn pump(&mut self) -> io::Result<ProgressIo> {
        let mut result = self.inner.progress_io()?;
        let Some(q) = &mut self.buffers else {
            return Ok(result);
        };
        if q.output_deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if q.output_pos < q.output_len {
            let end = *q.output_attempt_end.get_or_insert(q.output_len);
            match self.inner.write(&q.output[q.output_pos..end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    q.output_pos += n;
                    q.output_attempt_end = None;
                    result.advanced = true;
                    if q.output_pos == q.output_len {
                        q.output_deadline = None;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if q.input_pos == q.input_len {
            q.input_pos = 0;
            q.input_len = 0;
        }
        if !q.eof && q.input_len < QUEUE_BYTES {
            match self.inner.read(&mut q.input[q.input_len..]) {
                Ok(0) => {
                    q.eof = true;
                    result.advanced = true;
                }
                Ok(n) => {
                    q.input_len += n;
                    result.advanced = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if self.inner.is_raw_socket() {
            result.write |= q.output_pos < q.output_len;
        }
        Ok(result)
    }
}

/// A pending write is retried only with this object's fixed buffer, length,
/// and bytes. Completion is acknowledged once to the original writer, even if
/// progress_io completed the SSL operation before that writer was called again.
#[derive(Clone, Copy)]
enum WriteState {
    Empty,
    Waiting(usize),
    Complete(usize),
}
struct Plain {
    read: Box<[u8; QUEUE_BYTES]>,
    read_pos: usize,
    read_len: usize,
    read_waiting: bool,
    read_closed: bool,
    authenticated_eof: bool,
    read_want_output: bool,
    write: Box<[u8; QUEUE_BYTES]>,
    write_state: WriteState,
    deadline: Option<Instant>,
    read_deadline: Option<Instant>,
}
pub(crate) struct QueuedTls<S> {
    ssl: SslStream<QueueIo<S>>,
    plain: Option<Plain>,
    failed: bool,
}
impl<S> QueuedTls<S> {
    pub(crate) fn new(ssl: SslStream<QueueIo<S>>) -> Self {
        Self {
            ssl,
            plain: None,
            failed: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn transport_mut(&mut self) -> &mut S {
        &mut self.ssl.get_mut().inner
    }
}
fn pending_error() -> io::Error {
    io::ErrorKind::WouldBlock.into()
}
fn tls_error(error: openssl::ssl::Error) -> io::Error {
    if matches!(error.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) {
        pending_error()
    } else {
        error.into_io_error().unwrap_or_else(io::Error::other)
    }
}
impl<S: Duplex> QueuedTls<S> {
    fn ensure_live(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if self.plain.as_ref().is_some_and(|p| {
            p.deadline.is_some_and(|d| Instant::now() >= d)
                || p.read_deadline.is_some_and(|d| Instant::now() >= d)
        }) {
            self.failed = true;
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
    fn resume_write(&mut self) -> io::Result<()> {
        self.ensure_live()?;
        let Some(p) = &mut self.plain else {
            return Ok(());
        };
        let WriteState::Waiting(n) = p.write_state else {
            return Ok(());
        };
        match self.ssl.ssl_write(&p.write[..n]) {
            Ok(done) if done > 0 => {
                p.write_state = WriteState::Complete(done);
                p.deadline = None;
                Ok(())
            }
            Ok(_) => {
                self.failed = true;
                Err(io::ErrorKind::WriteZero.into())
            }
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {
                Err(pending_error())
            }
            Err(e) => {
                self.failed = true;
                Err(tls_error(e))
            }
        }
    }
    fn resume_read(&mut self) -> io::Result<()> {
        self.ensure_live()?;
        let has_ciphertext = self
            .ssl
            .get_ref()
            .buffers
            .as_ref()
            .is_some_and(|q| q.input_pos < q.input_len)
            || self.ssl.ssl().pending() > 0;
        let Some(p) = &mut self.plain else {
            return Ok(());
        };
        if p.read_pos < p.read_len || p.read_closed {
            return Ok(());
        }
        if has_ciphertext {
            p.read_deadline
                .get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
        }
        if matches!(p.write_state, WriteState::Waiting(_)) {
            return Err(pending_error());
        }
        p.read_waiting = true;
        match self.ssl.ssl_read(&mut p.read[..]) {
            Ok(n) => {
                p.read_pos = 0;
                p.read_len = n;
                p.read_waiting = false;
                p.read_want_output = false;
                p.read_deadline = None;
                Ok(())
            }
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                p.read_closed = true;
                p.authenticated_eof = true;
                p.read_waiting = false;
                p.read_deadline = None;
                Ok(())
            }
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {
                p.read_want_output = e.code() == ErrorCode::WANT_WRITE;
                Err(pending_error())
            }
            Err(e) => {
                self.failed = true;
                Err(tls_error(e))
            }
        }
    }
}
impl<S: Duplex> Read for QueuedTls<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.plain.is_none() {
            return self.ssl.read(out);
        }
        self.ensure_live()?;
        if out.is_empty() {
            return Ok(0);
        }
        self.resume_read()?;
        let p = self.plain.as_mut().expect("active");
        let n = out.len().min(p.read_len - p.read_pos);
        out[..n].copy_from_slice(&p.read[p.read_pos..p.read_pos + n]);
        p.read_pos += n;

        Ok(n)
    }
}
impl<S: Duplex> Write for QueuedTls<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.plain.is_none() {
            return self.ssl.write(bytes);
        }
        self.ensure_live()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let p = self.plain.as_mut().expect("active");
        if p.read_waiting && p.read_want_output {
            return Err(pending_error());
        }
        if matches!(p.write_state, WriteState::Empty) {
            let n = bytes.len().min(QUEUE_BYTES);
            p.write[..n].copy_from_slice(&bytes[..n]);
            p.write_state = WriteState::Waiting(n);
            p.deadline
                .get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
        }
        self.resume_write()?;
        let p = self.plain.as_mut().expect("active");
        if let WriteState::Complete(n) = p.write_state {
            if bytes.len() < n || bytes[..n] != p.write[..n] {
                self.failed = true;
                return Err(io::ErrorKind::InvalidInput.into());
            }
            p.write_state = WriteState::Empty;
            Ok(n)
        } else {
            Err(pending_error())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.plain.is_none() {
            return self.ssl.flush();
        }
        self.progress_io()?;
        if self.ssl.get_ref().output_pending() {
            Err(pending_error())
        } else {
            Ok(())
        }
    }
}
impl<S: Duplex> Duplex for QueueIo<S> {
    fn has_pending_output(&self) -> bool {
        self.output_pending() || self.inner.has_pending_output()
    }
    fn wait_progress(&self, timeout: Duration, write: bool) -> io::Result<()> {
        self.inner.wait_progress(timeout, write)
    }

    fn has_buffered_input(&self) -> bool {
        self.input_ready() || self.inner.has_buffered_input()
    }
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_io_timeout(timeout)
    }
    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.inner.clear_handshake_deadline()
    }
    fn enable_progress(&mut self) -> io::Result<bool> {
        self.activate()?;
        Ok(true)
    }
    fn progress_io(&mut self) -> io::Result<ProgressIo> {
        self.pump()
    }
}
impl<S: Duplex> Duplex for QueuedTls<S> {
    fn has_pending_output(&self) -> bool {
        self.plain
            .as_ref()
            .is_some_and(|p| matches!(p.write_state, WriteState::Waiting(_)))
            || self.ssl.get_ref().has_pending_output()
    }
    fn wait_progress(&self, timeout: Duration, write: bool) -> io::Result<()> {
        self.ssl.get_ref().wait_progress(timeout, write)
    }

    fn has_buffered_input(&self) -> bool {
        self.plain
            .as_ref()
            .is_some_and(|p| p.read_pos < p.read_len || p.read_closed)
            || self.ssl.ssl().pending() > 0
            || self.ssl.get_ref().has_buffered_input()
    }
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.ssl.get_ref().set_io_timeout(timeout)
    }
    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.ssl.get_ref().clear_handshake_deadline()
    }
    fn enable_progress(&mut self) -> io::Result<bool> {
        if self.plain.is_some() {
            return Ok(true);
        }
        self.ssl.get_mut().activate()?;
        self.plain = Some(Plain {
            read: Box::new([0; QUEUE_BYTES]),
            read_pos: 0,
            read_len: 0,
            read_waiting: false,
            read_closed: false,
            authenticated_eof: false,
            read_want_output: false,
            write: Box::new([0; QUEUE_BYTES]),
            write_state: WriteState::Empty,
            deadline: None,
            read_deadline: None,
        });
        Ok(true)
    }
    fn progress_io(&mut self) -> io::Result<ProgressIo> {
        self.ensure_live()?;
        let mut result = self.ssl.get_mut().pump()?;
        let pending_write = self
            .plain
            .as_ref()
            .is_some_and(|p| matches!(p.write_state, WriteState::Waiting(_)));
        if pending_write {
            match self.resume_write() {
                Ok(()) => result.advanced = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        let pending_read = self.plain.as_ref().is_some_and(|p| p.read_waiting);
        if pending_read
            && !self
                .plain
                .as_ref()
                .is_some_and(|p| matches!(p.write_state, WriteState::Waiting(_)))
        {
            match self.resume_read() {
                Ok(()) => result.advanced = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        // Each lower layer's result carries actual socket interest. This TLS
        // layer's application queue alone is not a raw socket writable event.
        Ok(result)
    }
}

#[cfg(test)]
#[path = "queued_tls_tests.rs"]
mod tests;
