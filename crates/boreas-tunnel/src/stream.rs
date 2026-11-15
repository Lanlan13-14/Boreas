//! Blocking bidirectional byte-stream seam.
//!
//! The reviewed inner-TLS backend accepts such a stream instead of a
//! `TcpStream`, because the hop TLS session runs inside WebSocket binary
//! payloads and the E2E TLS session runs inside circuit fragments. WebSocket
//! message and TLS record boundaries are independent; callers must never rely
//! on one message containing exactly one record.

use std::io::{Cursor, Read, Write};
use std::net::TcpStream;

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
}

impl Duplex for TcpStream {
    fn has_buffered_input(&self) -> bool {
        false
    }
}

impl Duplex for Cursor<Vec<u8>> {
    fn has_buffered_input(&self) -> bool {
        self.position() < self.get_ref().len() as u64
    }
}

impl<T: Duplex> Duplex for WsStream<T> {
    fn has_buffered_input(&self) -> bool {
        self.has_buffered_input()
    }
}

impl<S: Duplex> Duplex for EstablishedStream<S> {
    fn has_buffered_input(&self) -> bool {
        self.ssl_pending() > 0 || self.get_ref().has_buffered_input()
    }
}

impl Duplex for CircuitStream<'_> {
    fn has_buffered_input(&self) -> bool {
        self.has_buffered_input()
    }
}

#[cfg(feature = "openssl-inner-tls")]
impl Duplex for openssl::ssl::SslStream<TcpStream> {
    fn has_buffered_input(&self) -> bool {
        self.ssl().pending() > 0
    }
}
