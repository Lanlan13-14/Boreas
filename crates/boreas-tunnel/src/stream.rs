//! Blocking bidirectional byte-stream seam.
//!
//! The reviewed inner-TLS backend accepts such a stream instead of a
//! `TcpStream`, because the hop TLS session runs inside WebSocket binary
//! payloads and the E2E TLS session runs inside circuit fragments. WebSocket
//! message and TLS record boundaries are independent; callers must never rely
//! on one message containing exactly one record.

use std::io::{self, Read, Write};

/// Any blocking, bidirectional, sendable byte stream.
///
/// The blanket implementation keeps the adapter surface small: a
/// `TcpStream`, a [`crate::ws::WsStream`], an OpenSSL `SslStream`, or an E2E
/// [`crate::e2e::CircuitStream`] all satisfy it without extra code.
///
/// `close_stream` exists so an owner that sits on top of this stream (the
/// packet path) can ask the stream to end itself the way its protocol
/// requires — a TLS record layer must emit `close_notify`, a raw test stream
/// has nothing to do — before the owner drops it. Dropping a TLS stream
/// without `close_notify` makes the peer read a truncated record and fail
/// closed, which is correct for an error path and wrong for a planned stop.
pub trait Duplex: Read + Write + Send {
    fn close_stream(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<T: Read + Write + Send> Duplex for T {}
