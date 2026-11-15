//! Ordered byte-stream adapter for TLS records carried in WebSocket binary messages.
//!
//! The adapter deliberately does not parse HTTP, WebSocket frames, control
//! messages, or compression.  The outer transport must accept only binary data
//! frames for this path, concatenate their payloads in wire order, and feed
//! them through [`WsByteStream::feed_ciphertext`].  TLS record boundaries never
//! coincide with WebSocket message boundaries: the stream is the only framing
//! that the TLS engine sees.
//!
//! Both queues are bounded.  An empty-but-open inbound queue returns
//! [`std::io::ErrorKind::WouldBlock`] so a TLS driver can return to its event
//! loop instead of blocking a WebSocket reader; a full outbound queue applies
//! backpressure the same way.  Bytes are never dropped, reordered, or
//! coalesced into a different queue entry: callers must honour the returned
//! counts on short reads and writes.
//!
//! The per-stream bounds below are **not** an aggregate transport quota.  The
//! outer WebSocket transport must account for every live stream and enforce a
//! global bound of its own (Phase 1 `G-RESOURCE`); this type only refuses
//! absurd per-stream allocations.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

/// Default bound for each direction of the ciphertext queues.
///
/// This is an implementation default, not a negotiated or measured memory
/// budget.  The transport layer may choose a smaller bound with
/// [`WsByteStream::with_capacity`] after the Phase 0/1 resource work assigns
/// one.
pub const DEFAULT_QUEUE_CAPACITY: usize = 256 * 1024;

/// Hard per-stream ceiling accepted by [`WsByteStream::with_capacity`].
///
/// This is a safety valve against an accidental or attacker-influenced
/// allocation request, not a transport-wide budget: many 1 MiB streams would
/// still exceed the master-plan memory model, so the WebSocket transport must
/// allocate per-stream capacities from a global quota.
pub const MAX_QUEUE_CAPACITY: usize = 1024 * 1024;

/// Bounded, ordered TLS ciphertext byte stream for one WebSocket payload path.
#[derive(Debug)]
pub struct WsByteStream {
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    capacity: usize,
    inbound_closed: bool,
}

impl Default for WsByteStream {
    fn default() -> Self {
        Self::new()
    }
}

impl WsByteStream {
    /// Create a stream with [`DEFAULT_QUEUE_CAPACITY`] bytes per direction.
    pub fn new() -> Self {
        Self::from_validated_capacity(DEFAULT_QUEUE_CAPACITY)
    }

    /// Create a stream with an explicit per-direction bound.
    ///
    /// `capacity` must be non-zero and no larger than [`MAX_QUEUE_CAPACITY`].
    /// A zero-sized queue cannot make progress and an unbounded request is a
    /// local allocation denial-of-service.  The bound is per stream, not
    /// transport-wide.
    pub fn with_capacity(capacity: usize) -> io::Result<Self> {
        if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("WsByteStream capacity {capacity} outside 1..={MAX_QUEUE_CAPACITY}"),
            ));
        }
        Ok(Self::from_validated_capacity(capacity))
    }

    fn from_validated_capacity(capacity: usize) -> Self {
        Self {
            inbound: VecDeque::with_capacity(capacity),
            outbound: VecDeque::with_capacity(capacity),
            capacity,
            inbound_closed: false,
        }
    }

    /// Per-direction queue bound in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Queue received WebSocket binary payload bytes in order.
    ///
    /// Returns the number of bytes accepted, which may be less than
    /// `bytes.len()` when the queue is nearly full.  The caller keeps the
    /// remainder and retries after draining TLS output.  A full queue returns
    /// [`std::io::ErrorKind::WouldBlock`]; feeding after
    /// [`Self::close_inbound`] returns [`std::io::ErrorKind::BrokenPipe`].
    pub fn feed_ciphertext(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.inbound_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS byte stream is closed for inbound data",
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let room = self.capacity.saturating_sub(self.inbound.len());
        if room == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let accepted = room.min(bytes.len());
        self.inbound.extend(bytes[..accepted].iter().copied());
        Ok(accepted)
    }

    /// Remove up to `out.len()` encrypted bytes for the next WebSocket data frame.
    ///
    /// A short drain is normal.  The next frame must carry exactly the bytes
    /// drained here, in order.
    pub fn drain_ciphertext(&mut self, out: &mut [u8]) -> usize {
        let drained = out.len().min(self.outbound.len());
        for slot in &mut out[..drained] {
            *slot = self
                .outbound
                .pop_front()
                .expect("length checked before draining outbound bytes");
        }
        drained
    }

    /// Close the inbound direction after the transport has delivered the final
    /// byte of a clean peer close.  Reads then return EOF once the queued bytes
    /// are consumed.  A truncated transport must not call this: it is reserved
    /// for a peer-signalled end of stream, and the TLS engine still decides
    /// whether the record layer ended cleanly.
    pub fn close_inbound(&mut self) {
        self.inbound_closed = true;
    }

    /// Number of received ciphertext bytes waiting for the TLS engine.
    pub fn inbound_len(&self) -> usize {
        self.inbound.len()
    }

    /// Number of produced ciphertext bytes waiting for the WebSocket sender.
    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
    }
}

impl Read for WsByteStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.inbound.is_empty() {
            return if self.inbound_closed {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let read = out.len().min(self.inbound.len());
        for slot in &mut out[..read] {
            *slot = self
                .inbound
                .pop_front()
                .expect("length checked before reading inbound bytes");
        }
        Ok(read)
    }
}

impl Write for WsByteStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let room = self.capacity.saturating_sub(self.outbound.len());
        if room == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let written = room.min(bytes.len());
        self.outbound.extend(bytes[..written].iter().copied());
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // The WebSocket sender drains the queue; flushing the adapter itself
        // has no transport to wait on.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queues_preserve_order_and_report_short_transfers() {
        let mut stream = WsByteStream::with_capacity(4).expect("bounded capacity");
        assert_eq!(stream.feed_ciphertext(b"abc").expect("feed abc"), 3);
        assert_eq!(stream.feed_ciphertext(b"def").expect("feed partial"), 1);
        assert!(matches!(
            stream.feed_ciphertext(b"g"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        let mut read = [0u8; 8];
        assert_eq!(stream.read(&mut read).expect("read inbound"), 4);
        assert_eq!(&read[..4], b"abcd");
        // The queue is empty again, so all three remaining bytes fit.
        assert_eq!(stream.feed_ciphertext(b"efg").expect("feed remainder"), 3);

        assert_eq!(stream.write(b"wxyz").expect("write outbound"), 4);
        assert!(matches!(
            stream.write(b"!"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        let mut drain = [0u8; 2];
        assert_eq!(stream.drain_ciphertext(&mut drain), 2);
        assert_eq!(&drain, b"wx");
        assert_eq!(stream.drain_ciphertext(&mut drain), 2);
        assert_eq!(&drain, b"yz");
    }

    #[test]
    fn capacity_requests_are_bounded_and_reject_zero() {
        assert!(WsByteStream::with_capacity(0).is_err());
        assert!(WsByteStream::with_capacity(MAX_QUEUE_CAPACITY + 1).is_err());
        assert!(WsByteStream::with_capacity(MAX_QUEUE_CAPACITY).is_ok());
    }

    #[test]
    fn open_empty_stream_is_would_block_and_close_is_eof() {
        let mut stream = WsByteStream::with_capacity(8).expect("bounded capacity");
        let mut read = [0u8; 1];
        assert!(matches!(
            stream.read(&mut read),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        stream.close_inbound();
        assert_eq!(stream.read(&mut read).expect("clean EOF"), 0);
        assert!(matches!(
            stream.feed_ciphertext(b"late"),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }
}
