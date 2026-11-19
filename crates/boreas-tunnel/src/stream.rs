//! Blocking bidirectional byte-stream seam.
//!
//! The reviewed inner-TLS backend accepts such a stream instead of a
//! `TcpStream`, because the hop TLS session runs inside WebSocket binary
//! payloads and the E2E TLS session runs inside circuit fragments. WebSocket
//! message and TLS record boundaries are independent; callers must never rely
//! on one message containing exactly one record.

use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "openssl-inner-tls")]
use boreas_crypto::backend::EstablishedStream;

use crate::e2e::CircuitStream;
use crate::ws::WsStream;

/// A bidirectional, sendable byte stream with conservative buffered-readiness
/// reporting for the daemon's event loop.
///
/// `has_buffered_input` covers bytes above the raw socket: TLS records already
/// decrypted by OpenSSL, WebSocket payloads, decoded application frames, and
/// circuit fragments. Polling only the TCP fd misses all of those cases. It is
/// deliberately conservative for a partial frame: just like socket readiness,
/// it permits a read attempt but does not promise that a whole frame is ready.
pub trait Duplex: Read + Write + Send {
    fn has_buffered_input(&self) -> bool;

    /// Install a per-operation transport timeout for a bounded handshake.
    ///
    /// This is a transport hint, not a deadline model of its own: the socket
    /// timeout only bounds one blocking syscall. The runtime's deadline wrapper
    /// recomputes the remaining budget before every read and write it starts,
    /// so the wrapper never grants a fresh per-operation timeout after the
    /// handshake deadline has passed.
    ///
    /// The default is a no-op only for in-memory and test streams that have no
    /// socket. Every wrapper around a real transport in this module overrides
    /// it, and `clear_handshake_deadline` is forwarded explicitly through those
    /// wrappers as well; a silent no-op around a real socket can leave a
    /// pre-outer-TLS timeout armed and turn an idle data-plane read into a
    /// failure.
    fn set_io_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    /// Stop enforcing a handshake deadline and return to ordinary blocking I/O.
    ///
    /// The runtime arms a deadline only for the handshake. Leaving it armed for
    /// the data plane would turn a legitimately idle link into a `TimedOut`
    /// failure, so the session layer disarms it after authorization.
    ///
    /// Wrappers in this module override this to forward the clear to the
    /// transport they wrap, rather than relying on an implicit
    /// `set_io_timeout(None)`. The default remains for streams that have no
    /// transport below them.
    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.set_io_timeout(None)
    }
}

impl Duplex for TcpStream {
    fn has_buffered_input(&self) -> bool {
        false
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.set_io_timeout(None)
    }
}

impl<T: Duplex + ?Sized> Duplex for Box<T> {
    fn has_buffered_input(&self) -> bool {
        (**self).has_buffered_input()
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_io_timeout(timeout)
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        (**self).clear_handshake_deadline()
    }
}

impl Duplex for Cursor<Vec<u8>> {
    fn has_buffered_input(&self) -> bool {
        self.position() < self.get_ref().len() as u64
    }

    fn set_io_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        // In-memory stream: there is no blocking transport call to bound.
        Ok(())
    }
}

impl<T: Duplex> Duplex for WsStream<T> {
    fn has_buffered_input(&self) -> bool {
        self.has_buffered_input()
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_transport_timeout(timeout)
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.clear_transport_deadline()
    }
}

#[cfg(feature = "openssl-inner-tls")]
impl<S: Duplex> Duplex for EstablishedStream<S> {
    fn has_buffered_input(&self) -> bool {
        self.ssl_pending() > 0 || self.get_ref().has_buffered_input()
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.get_ref().set_io_timeout(timeout)
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.get_ref().clear_handshake_deadline()
    }
}

impl Duplex for CircuitStream<'_> {
    fn has_buffered_input(&self) -> bool {
        self.has_buffered_input()
    }

    fn set_io_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        // A circuit stream carries application data over an already-authorized
        // session. Its hop handshake deadline was cleared before the session was
        // returned, and a circuit-level budget must not arm the shared hop
        // socket, so there is no transport timeout to install here.
        Ok(())
    }
}

#[cfg(feature = "openssl-inner-tls")]
impl Duplex for openssl::ssl::SslStream<TcpStream> {
    fn has_buffered_input(&self) -> bool {
        self.ssl().pending() > 0
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.get_ref().set_read_timeout(timeout)?;
        self.get_ref().set_write_timeout(timeout)
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        self.get_ref().set_read_timeout(None)?;
        self.get_ref().set_write_timeout(None)
    }
}

/// Never ask the OS for a zero-duration timeout: on multiple platforms zero
/// means "wait forever", which would disable the very bound being installed.
const MIN_IO_TIMEOUT: Duration = Duration::from_millis(1);

/// A transport wrapper that enforces one absolute deadline at operation
/// boundaries during a handshake.
///
/// A plain socket read timeout is not enough. It is reset on every syscall, so
/// a peer can send one byte just before each timeout and keep the exchange
/// alive indefinitely. Before each operation this wrapper recomputes the
/// remaining budget, installs exactly that budget on the underlying transport,
/// and refuses to start another operation after the deadline. A stalled
/// transport call is therefore bounded by the remaining budget, and the wrapper
/// itself never grants a fresh budget.
///
/// The inner backend may perform several transport reads inside one of its own
/// calls. This wrapper cannot split those, so it does not claim a hard
/// wall-clock cutoff against a peer that trickles bytes through that backend;
/// the socket timeout only guarantees that no single transport read waits
/// forever. This is an explicit residual, not a performance or security pass.
///
/// The deadline is armed only for handshake I/O. [`Duplex::clear_handshake_deadline`]
/// disarms it (and removes the socket timeout) before the session starts
/// carrying application data.
pub(crate) struct DeadlineIo<T> {
    inner: T,
    deadline: Instant,
    armed: AtomicBool,
}

impl<T: Duplex> DeadlineIo<T> {
    pub(crate) fn new(inner: T, deadline: Instant) -> Self {
        Self {
            inner,
            deadline,
            armed: AtomicBool::new(true),
        }
    }

    /// Remaining budget, or `TimedOut` once the deadline has passed.
    fn remaining(&self) -> io::Result<Option<Duration>> {
        if !self.armed.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) else {
            return Err(deadline_exceeded());
        };
        if remaining.is_zero() {
            return Err(deadline_exceeded());
        }
        Ok(Some(remaining.max(MIN_IO_TIMEOUT)))
    }

    /// Install the current remaining budget before one blocking operation.
    fn prepare(&self) -> io::Result<()> {
        match self.remaining()? {
            Some(remaining) => self.inner.set_io_timeout(Some(remaining)),
            None => Ok(()),
        }
    }

    /// Map a timeout to a deadline failure only while the wrapper is armed.
    /// Once disarmed, this type is a transparent passthrough so an unrelated
    /// nonblocking error is not misreported as a handshake timeout.
    fn map_error(&self, error: io::Error) -> io::Error {
        if self.armed.load(Ordering::Relaxed) {
            map_deadline_error(error)
        } else {
            error
        }
    }
}

fn deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "handshake deadline exceeded")
}

/// A transport timeout is a deadline failure, not a protocol error and not a
/// clean close. Keep the kind stable so the session layer maps it to
/// `TunnelError::Timeout`.
fn map_deadline_error(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => deadline_exceeded(),
        _ => error,
    }
}

impl<T: Duplex> Read for DeadlineIo<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.prepare()?;
        match self.inner.read(out) {
            Ok(read) => Ok(read),
            Err(error) => Err(self.map_error(error)),
        }
    }
}

impl<T: Duplex> Write for DeadlineIo<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.prepare()?;
        match self.inner.write(buf) {
            Ok(written) => Ok(written),
            Err(error) => Err(self.map_error(error)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.prepare()?;
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(error) => Err(self.map_error(error)),
        }
    }
}

impl<T: Duplex> Duplex for DeadlineIo<T> {
    fn has_buffered_input(&self) -> bool {
        self.inner.has_buffered_input()
    }

    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match timeout {
            // Installing a budget does not re-arm a wrapper that was already
            // cleared; only an armed handshake uses this path.
            Some(timeout) => self.inner.set_io_timeout(Some(timeout)),
            None => self.clear_handshake_deadline(),
        }
    }

    fn clear_handshake_deadline(&self) -> io::Result<()> {
        let was_armed = self.armed.swap(false, Ordering::Relaxed);
        // A handshake that consumed its entire budget is not successful
        // merely because the last CPU-only step finished. Fail closed
        // before the session can carry application data.
        if was_armed && Instant::now() >= self.deadline {
            return Err(deadline_exceeded());
        }
        self.inner.clear_handshake_deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Probe {
        state: Arc<ProbeState>,
    }

    #[derive(Default)]
    struct ProbeState {
        reads: AtomicUsize,
        clears: AtomicUsize,
        timeout: Mutex<Option<Duration>>,
    }

    impl Probe {
        fn reads(&self) -> usize {
            self.state.reads.load(Ordering::Relaxed)
        }

        fn clears(&self) -> usize {
            self.state.clears.load(Ordering::Relaxed)
        }

        fn timeout(&self) -> Option<Duration> {
            *self.state.timeout.lock().expect("probe lock")
        }
    }

    impl Read for Probe {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            self.state.reads.fetch_add(1, Ordering::Relaxed);
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for Probe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Duplex for Probe {
        fn has_buffered_input(&self) -> bool {
            false
        }

        fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.state.timeout.lock().expect("probe lock") = timeout;
            Ok(())
        }

        fn clear_handshake_deadline(&self) -> io::Result<()> {
            self.state.clears.fetch_add(1, Ordering::Relaxed);
            self.set_io_timeout(None)
        }
    }

    #[test]
    fn armed_deadline_installs_the_remaining_budget_before_io() {
        let probe = Probe::default();
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("future deadline");
        let mut io = DeadlineIo::new(probe, deadline);

        let error = io
            .read(&mut [0u8; 1])
            .expect_err("WouldBlock is a deadline failure");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let installed = io.inner.timeout().expect("timeout was installed");
        assert!(installed > Duration::ZERO);
        assert!(installed <= Duration::from_secs(10));
        assert_eq!(io.inner.reads(), 1);
    }

    #[test]
    fn expired_deadline_fails_before_touching_the_transport() {
        let probe = Probe::default();
        let mut io = DeadlineIo::new(probe, Instant::now());

        let error = io
            .read(&mut [0u8; 1])
            .expect_err("deadline is already spent");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(io.inner.reads(), 0);
    }

    #[test]
    fn clearing_the_deadline_restores_transparent_blocking_io() {
        let probe = Probe::default();
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("future deadline");
        let mut io = DeadlineIo::new(probe, deadline);

        io.clear_handshake_deadline().expect("clear deadline");
        assert_eq!(io.inner.timeout(), None);
        assert_eq!(io.inner.clears(), 1);

        let error = io
            .read(&mut [0u8; 1])
            .expect_err("probe returns WouldBlock");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(io.inner.reads(), 1);
    }

    #[derive(Clone, Default)]
    struct ClearOnly {
        state: Arc<ClearOnlyState>,
    }

    #[derive(Default)]
    struct ClearOnlyState {
        clears: AtomicUsize,
        timeout: Mutex<Option<Duration>>,
    }

    impl ClearOnly {
        fn clears(&self) -> usize {
            self.state.clears.load(Ordering::Relaxed)
        }

        fn timeout(&self) -> Option<Duration> {
            *self.state.timeout.lock().expect("clear-only lock")
        }
    }

    impl Read for ClearOnly {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for ClearOnly {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Duplex for ClearOnly {
        fn has_buffered_input(&self) -> bool {
            false
        }

        fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.state.timeout.lock().expect("clear-only lock") = timeout;
            Ok(())
        }

        fn clear_handshake_deadline(&self) -> io::Result<()> {
            self.state.clears.fetch_add(1, Ordering::Relaxed);
            self.set_io_timeout(None)
        }
    }

    #[test]
    fn clear_is_forwarded_through_box_and_websocket_layers() {
        use crate::ws::{WsLimits, WsRole};

        let inner = ClearOnly::default();
        let observer = inner.clone();
        let websocket = WsStream::new(inner, WsRole::Client, WsLimits::default());
        let stream: Box<dyn Duplex> = Box::new(websocket);

        stream
            .clear_handshake_deadline()
            .expect("clear through boxed websocket layers");

        // Default `clear_handshake_deadline` would call `set_io_timeout(None)`
        // and leave this counter at zero. Only a real layer-by-layer clear
        // reaches the inner stream's clear.
        assert_eq!(observer.clears(), 1);
        assert_eq!(observer.timeout(), None);
    }
}
