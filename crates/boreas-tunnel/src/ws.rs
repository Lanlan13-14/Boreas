//! RFC 6455 WebSocket over HTTP/1.1 (`h1`) baseline.
//!
//! The hop transport upgrades a TCP connection with a standard `Upgrade:
//! websocket` handshake and then concatenates binary message payloads into a
//! reliable ordered byte stream for the inner TLS engine. Boundaries:
//!
//! * Only binary data messages are accepted; text frames are a protocol error.
//! * `Ping`, `Pong` and `Close` are handled here and never enter the TLS byte
//!   stream. A `Ping` is answered with a `Pong` carrying the same payload.
//! * No extension is offered or accepted: `permessage-deflate` is rejected on
//!   both sides, as are reserved bits.
//! * Every client frame is masked with a fresh CSPRNG mask; an unmasked client
//!   frame is rejected by the server, a masked server frame by the client.
//! * HTTP head bytes, header count, frame payload, message size, fragment count
//!   and control-frame payloads are all bounded.
//!
//! The reader consumes one byte at a time while parsing the HTTP head so that
//! no payload byte can be swallowed by an over-read. That is a baseline
//! trade-off: it is correct and bounded, not tuned for handshake throughput.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::csprng;
use crate::sha1;

/// RFC 6455 handshake GUID used to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Maximum accepted HTTP head size, including the terminating CRLFCRLF.
pub const MAX_HTTP_HEAD_BYTES: usize = 8 * 1024;
/// Maximum number of HTTP header fields in a handshake.
pub const MAX_HTTP_HEADERS: usize = 32;
/// Maximum payload of one WebSocket frame.
pub const MAX_WS_FRAME_PAYLOAD: usize = 64 * 1024;
/// Maximum reassembled size of one binary message.
pub const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum number of fragments in one binary message.
pub const MAX_WS_FRAGMENTS: usize = 64;
/// Absolute wall-clock budget for one `Read` call to obtain payload after it
/// begins. It is an overall budget for all fragments and TLS records consumed
/// by that call, not a per-record or per-RTT allowance. A peer dripping one
/// byte per read cannot extend it: the deadline is re-checked before and after
/// every blocking read. A completely silent peer is bounded only when the
/// surrounding runtime installs a transport timeout; the generic `Read` seam
/// cannot interrupt a blocked syscall by itself, and the data plane deliberately
/// runs without a per-read timeout once the handshake deadline is disarmed.
pub const MAX_WS_FRAME_DEADLINE: Duration = Duration::from_secs(30);
/// Absolute budget for the whole HTTP/1.1 upgrade handshake.
pub const MAX_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Maximum control frames handled during one data read. A peer cannot flood
/// Ping/Pong frames to keep a single read call busy without bound.
pub const MAX_CONTROL_FRAMES_PER_READ: usize = 16;
/// Maximum control-frame bytes handled during one data read.
pub const MAX_CONTROL_BYTES_PER_READ: usize = 4096;
/// Maximum frames of any kind consumed during one `Read` call. This bounds both
/// control floods and empty binary frames: an empty frame makes no progress and
/// must not restart the per-frame deadline.
pub const MAX_FRAMES_PER_READ: usize = 32;
/// Hard ceiling for `WsLimits::max_frame_payload`.
pub const HARD_MAX_WS_FRAME_PAYLOAD: usize = 64 * 1024;
/// Hard ceiling for `WsLimits::max_message_bytes`.
pub const HARD_MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;
/// Hard ceiling for `WsLimits::max_fragments`.
pub const HARD_MAX_WS_FRAGMENTS: usize = 64;
/// Hard ceiling for one read's absolute deadline budget.
pub const HARD_MAX_MESSAGE_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsRole {
    /// Masks outgoing frames and requires unmasked incoming frames.
    Client,
    /// Sends unmasked frames and requires masked incoming frames.
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsError {
    /// Transport I/O failed.
    Io(io::ErrorKind),
    /// A socket operation exceeded its configured timeout.
    Timeout,
    /// EOF before the operation completed.
    Closed,
    /// The OS CSPRNG was unavailable.
    Entropy,
    /// HTTP head exceeded [`MAX_HTTP_HEAD_BYTES`].
    HeadTooLarge,
    /// HTTP head syntax was invalid (bare LF, bad line, control bytes).
    HeadMalformed,
    /// A required header appeared more than once.
    DuplicateHeader,
    /// Status line was not `HTTP/1.1 101`.
    BadStatus,
    /// `Upgrade` header missing or not `websocket`.
    BadUpgrade,
    /// `Connection` header missing the `Upgrade` token.
    BadConnectionHeader,
    /// `Sec-WebSocket-Version` was not `13`.
    BadVersion,
    /// `Sec-WebSocket-Key` missing, not base64, or not 16 bytes.
    BadKey,
    /// `Sec-WebSocket-Accept` missing or not the expected digest.
    BadAcceptKey,
    /// An extension (for example `permessage-deflate`) was offered.
    ExtensionOffered,
    /// A subprotocol was selected although none was offered.
    UnexpectedSubprotocol,
    /// A request carried a body.
    RequestBody,
    /// The request method was not `GET`.
    BadMethod,
    /// Host or request-target characters could break the HTTP head.
    InvalidTarget,
    /// A reserved bit was set without a negotiated extension.
    ReservedBits,
    /// Unknown or unsupported opcode.
    UnknownOpcode,
    /// A text frame was received; this transport is binary-only.
    TextFrame,
    /// A control frame had `FIN = 0`.
    ControlFragmented,
    /// A control frame payload exceeded 125 bytes.
    ControlTooLarge,
    /// A client-to-server frame was not masked.
    UnmaskedClientFrame,
    /// A server-to-client frame was masked.
    MaskedServerFrame,
    /// A 16/64-bit length was used although a shorter encoding applies.
    NonCanonicalLength,
    /// Frame payload exceeded the configured cap.
    MessageTooLarge,
    /// Fragment count exceeded [`MAX_WS_FRAGMENTS`].
    TooManyFragments,
    /// A continuation frame arrived without an open message.
    UnexpectedContinuation,
    /// A new data frame arrived while a fragmented message was open.
    InterleavedMessage,
    /// Close payload had a reserved status code or invalid UTF-8 reason.
    BadCloseFrame,
    /// Too many control frames arrived while one data read was pending.
    ControlFlood,
    /// Too many frames (including empty binary frames) were consumed by one
    /// `Read` call without making progress.
    FrameFlood,
    /// A previous framing error poisoned the stream; no resynchronisation.
    Poisoned,
}

impl std::fmt::Display for WsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for WsError {}

fn map_io(error: io::Error) -> WsError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => WsError::Timeout,
        io::ErrorKind::UnexpectedEof => WsError::Closed,
        kind => WsError::Io(kind),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WsLimits {
    pub max_frame_payload: usize,
    pub max_message_bytes: usize,
    pub max_fragments: usize,
    pub message_deadline: Duration,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            max_frame_payload: MAX_WS_FRAME_PAYLOAD,
            max_message_bytes: MAX_WS_MESSAGE_BYTES,
            max_fragments: MAX_WS_FRAGMENTS,
            message_deadline: MAX_WS_FRAME_DEADLINE,
        }
    }
}

impl WsLimits {
    /// Clamp caller-supplied limits to the compiled hard ceilings. Public limits
    /// are a tuning surface, not a way to disable the protocol bounds.
    pub fn bounded(self) -> Self {
        Self {
            max_frame_payload: self.max_frame_payload.clamp(1, HARD_MAX_WS_FRAME_PAYLOAD),
            max_message_bytes: self.max_message_bytes.clamp(1, HARD_MAX_WS_MESSAGE_BYTES),
            max_fragments: self.max_fragments.clamp(1, HARD_MAX_WS_FRAGMENTS),
            message_deadline: self
                .message_deadline
                .clamp(Duration::from_secs(1), HARD_MAX_MESSAGE_DEADLINE),
        }
    }
}

/// Bounded per-stream read buffer for WebSocket frame parsing so `read_frame`
/// does not issue 3–4 tiny TLS/socket reads per frame.
const WS_READ_BUFFER_BYTES: usize = 32 * 1024;
const MAX_INTERRUPT_RETRIES: u8 = 8;

enum WsIoError {
    WouldBlock,
    Fatal(WsError),
}

/// A WebSocket connection exposed as a byte stream.
///
/// `Read` yields payload bytes of binary messages only. `Write` emits one
/// binary message per call, splitting into frames at
/// `limits.max_frame_payload`.
pub struct WsStream<T> {
    io: T,
    role: WsRole,
    limits: WsLimits,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    needs_flush: bool,
    pending_pong: Option<Vec<u8>>,
    pending: Vec<u8>,
    pending_pos: usize,
    message: MessageState,
    close_sent: bool,
    close_received: bool,
    failed: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MessageState {
    in_progress: bool,
    bytes: usize,
    fragments: usize,
}

impl<T: Read + Write> WsStream<T> {
    pub fn new(io: T, role: WsRole, limits: WsLimits) -> Self {
        Self {
            io,
            role,
            limits: limits.bounded(),
            read_buf: Vec::new(),
            read_pos: 0,
            read_len: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
            pending_pong: None,
            pending: Vec::new(),
            pending_pos: 0,
            message: MessageState::default(),
            close_sent: false,
            close_received: false,
            failed: false,
        }
    }

    fn flush_write_buf(&mut self) -> Result<(), WsIoError> {
        loop {
            let mut interrupts = 0u8;
            while self.write_pos < self.write_buf.len() {
                match self.io.write(&self.write_buf[self.write_pos..]) {
                    Ok(0) => return Err(WsIoError::Fatal(WsError::Io(io::ErrorKind::WriteZero))),
                    Ok(n) => {
                        self.write_pos += n;
                        interrupts = 0;
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                        interrupts = interrupts.saturating_add(1);
                        if interrupts >= MAX_INTERRUPT_RETRIES {
                            return Err(WsIoError::Fatal(WsError::Io(io::ErrorKind::Interrupted)));
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        return Err(WsIoError::WouldBlock);
                    }
                    Err(err) => return Err(WsIoError::Fatal(map_io(err))),
                }
            }
            self.write_buf.clear();
            self.write_pos = 0;
            if let Some(pong) = self.pending_pong.take() {
                encode_frame_into(
                    self.role == WsRole::Client,
                    true,
                    OpCode::Pong,
                    &pong,
                    &mut self.write_buf,
                )
                .map_err(WsIoError::Fatal)?;
                self.needs_flush = true;
                continue;
            }
            break;
        }
        if self.needs_flush {
            match self.io.flush() {
                Ok(()) => self.needs_flush = false,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    return Err(WsIoError::WouldBlock);
                }
                Err(err) => return Err(WsIoError::Fatal(map_io(err))),
            }
        }
        Ok(())
    }

    fn send_frame(&mut self, opcode: OpCode, payload: &[u8]) -> Result<(), WsIoError> {
        if self.write_pos < self.write_buf.len() {
            self.flush_write_buf()?;
        }
        encode_frame_into(
            self.role == WsRole::Client,
            true,
            opcode,
            payload,
            &mut self.write_buf,
        )
        .map_err(WsIoError::Fatal)?;
        self.write_pos = 0;
        self.needs_flush = true;
        self.flush_write_buf()
    }

    fn queue_pong(&mut self, payload: &[u8]) -> Result<(), WsIoError> {
        if self.write_pos < self.write_buf.len() {
            match self.flush_write_buf() {
                Ok(()) => {}
                Err(WsIoError::WouldBlock) => {
                    if self.pending_pong.is_some() {
                        return Err(WsIoError::Fatal(WsError::ControlFlood));
                    }
                    self.pending_pong = Some(payload.to_vec());
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }
        match self.send_frame(OpCode::Pong, payload) {
            Ok(()) | Err(WsIoError::WouldBlock) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn respond_close(&mut self, payload: &[u8]) -> Result<(), WsIoError> {
        if self.close_sent {
            return Ok(());
        }
        if !close_payload_valid(payload) {
            return Err(WsIoError::Fatal(WsError::BadCloseFrame));
        }
        self.close_sent = true;
        let echo: &[u8] = if payload.len() >= 2 {
            &payload[..2]
        } else {
            &[]
        };
        match self.send_frame(OpCode::Close, echo) {
            Ok(()) | Err(WsIoError::WouldBlock) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn pull_read_buf(&mut self, needed: usize, deadline: Instant) -> Result<(), WsIoError> {
        if Instant::now() >= deadline {
            return Err(WsIoError::Fatal(WsError::Timeout));
        }
        if self.read_pos > 0 {
            self.read_buf.copy_within(self.read_pos..self.read_len, 0);
            self.read_len -= self.read_pos;
            self.read_pos = 0;
        }
        let target_len = WS_READ_BUFFER_BYTES.max(needed);
        if self.read_buf.len() < target_len {
            self.read_buf.resize(target_len, 0);
        }
        let mut interrupts = 0u8;
        loop {
            match self.io.read(&mut self.read_buf[self.read_len..]) {
                Ok(0) => return Err(WsIoError::Fatal(WsError::Closed)),
                Ok(n) => {
                    self.read_len += n;
                    if Instant::now() >= deadline {
                        return Err(WsIoError::Fatal(WsError::Timeout));
                    }
                    return Ok(());
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    interrupts = interrupts.saturating_add(1);
                    if interrupts >= MAX_INTERRUPT_RETRIES {
                        return Err(WsIoError::Fatal(WsError::Io(io::ErrorKind::Interrupted)));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    return Err(WsIoError::WouldBlock);
                }
                Err(err) => return Err(WsIoError::Fatal(map_io(err))),
            }
        }
    }

    fn read_frame_buffered(&mut self, deadline: Instant) -> Result<RawFrame, WsIoError> {
        loop {
            let avail = self.read_len - self.read_pos;
            if avail < 2 {
                self.pull_read_buf(2, deadline)?;
                continue;
            }
            let head = &self.read_buf[self.read_pos..self.read_pos + 2];
            let fin = head[0] & 0x80 != 0;
            if head[0] & 0x70 != 0 {
                return Err(WsIoError::Fatal(WsError::ReservedBits));
            }
            let opcode = OpCode::from_bits(head[0] & 0x0f).map_err(WsIoError::Fatal)?;
            let masked = head[1] & 0x80 != 0;
            match self.role {
                WsRole::Server if !masked => {
                    return Err(WsIoError::Fatal(WsError::UnmaskedClientFrame));
                }
                WsRole::Client if masked => {
                    return Err(WsIoError::Fatal(WsError::MaskedServerFrame));
                }
                _ => {}
            }
            let length_code = head[1] & 0x7f;
            let ext_len = match length_code {
                126 => 2usize,
                127 => 8usize,
                _ => 0usize,
            };
            let mask_len = if masked { 4usize } else { 0usize };
            let header_len = 2 + ext_len + mask_len;
            if avail < header_len {
                self.pull_read_buf(header_len, deadline)?;
                continue;
            }
            let payload_len = match length_code {
                126 => {
                    let b = &self.read_buf[self.read_pos + 2..self.read_pos + 4];
                    let length = usize::from(u16::from_be_bytes([b[0], b[1]]));
                    if length < 126 {
                        return Err(WsIoError::Fatal(WsError::NonCanonicalLength));
                    }
                    length
                }
                127 => {
                    let b = &self.read_buf[self.read_pos + 2..self.read_pos + 10];
                    let length =
                        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    if length < 65_536 {
                        return Err(WsIoError::Fatal(WsError::NonCanonicalLength));
                    }
                    usize::try_from(length)
                        .map_err(|_| WsIoError::Fatal(WsError::MessageTooLarge))?
                }
                other => usize::from(other),
            };
            if opcode.is_control() {
                if !fin {
                    return Err(WsIoError::Fatal(WsError::ControlFragmented));
                }
                if payload_len > 125 {
                    return Err(WsIoError::Fatal(WsError::ControlTooLarge));
                }
            }
            if payload_len > self.limits.max_frame_payload {
                return Err(WsIoError::Fatal(WsError::MessageTooLarge));
            }
            let total_len = header_len + payload_len;
            if avail < total_len {
                self.pull_read_buf(total_len, deadline)?;
                continue;
            }
            let payload_start = self.read_pos + header_len;
            let mut payload = self.read_buf[payload_start..payload_start + payload_len].to_vec();
            if masked {
                let mask_start = self.read_pos + 2 + ext_len;
                let mask = [
                    self.read_buf[mask_start],
                    self.read_buf[mask_start + 1],
                    self.read_buf[mask_start + 2],
                    self.read_buf[mask_start + 3],
                ];
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[index % 4];
                }
            }
            self.read_pos += total_len;
            if self.read_pos == self.read_len {
                self.read_pos = 0;
                self.read_len = 0;
            }
            return Ok(RawFrame {
                fin,
                opcode,
                payload,
            });
        }
    }

    fn track_message(&mut self, opcode: OpCode, fin: bool, len: usize) -> Result<(), WsError> {
        match opcode {
            OpCode::Binary => {
                if self.message.in_progress {
                    return Err(WsError::InterleavedMessage);
                }
                self.message = MessageState {
                    in_progress: !fin,
                    bytes: len,
                    fragments: 1,
                };
            }
            OpCode::Continuation => {
                if !self.message.in_progress {
                    return Err(WsError::UnexpectedContinuation);
                }
                self.message.fragments += 1;
                self.message.bytes = self.message.bytes.saturating_add(len);
                if fin {
                    self.message.in_progress = false;
                }
            }
            OpCode::Text | OpCode::Close | OpCode::Ping | OpCode::Pong => {}
        }
        if self.message.bytes > self.limits.max_message_bytes {
            return Err(WsError::MessageTooLarge);
        }
        if self.message.fragments > self.limits.max_fragments {
            return Err(WsError::TooManyFragments);
        }
        Ok(())
    }

    /// Read frames until a payload byte is available. Control frames are fully
    /// handled here; `Ok(None)` means the peer closed the connection.
    ///
    /// One absolute deadline covers the whole call, and a frame budget bounds
    /// both control floods and empty binary frames. An empty data frame makes no
    /// progress, so it must not restart the deadline or loop forever.
    fn next_data_payload(&mut self) -> Result<Option<Vec<u8>>, WsIoError> {
        let deadline = Instant::now() + self.limits.message_deadline;
        let mut frames = 0usize;
        let mut control_frames = 0usize;
        let mut control_bytes = 0usize;
        loop {
            frames += 1;
            if frames > MAX_FRAMES_PER_READ {
                return Err(WsIoError::Fatal(WsError::FrameFlood));
            }
            let frame = self.read_frame_buffered(deadline)?;
            match frame.opcode {
                OpCode::Ping | OpCode::Pong | OpCode::Close => {
                    control_frames += 1;
                    control_bytes = control_bytes.saturating_add(frame.payload.len());
                    if control_frames > MAX_CONTROL_FRAMES_PER_READ
                        || control_bytes > MAX_CONTROL_BYTES_PER_READ
                    {
                        return Err(WsIoError::Fatal(WsError::ControlFlood));
                    }
                    match frame.opcode {
                        OpCode::Ping => self.queue_pong(&frame.payload)?,
                        OpCode::Close => {
                            self.close_received = true;
                            self.respond_close(&frame.payload)?;
                            return Ok(None);
                        }
                        _ => {}
                    }
                }
                OpCode::Binary | OpCode::Continuation => {
                    self.track_message(frame.opcode, frame.fin, frame.payload.len())
                        .map_err(WsIoError::Fatal)?;
                    if frame.payload.is_empty() {
                        continue;
                    }
                    return Ok(Some(frame.payload));
                }
                OpCode::Text => return Err(WsIoError::Fatal(WsError::TextFrame)),
            }
        }
    }
}

impl<T: crate::stream::Duplex> WsStream<T> {
    /// Whether payload bytes are buffered above the underlying transport.
    /// A partial WebSocket frame is included conservatively; the event-loop
    /// owner still applies the normal bounded read and protocol checks.
    pub fn has_buffered_input(&self) -> bool {
        self.read_pos < self.read_len
            || self.pending_pos < self.pending.len()
            || self.io.has_buffered_input()
    }

    /// Whether an outbound frame or Pong remains buffered waiting on `POLLOUT`.
    pub fn has_pending_write(&self) -> bool {
        self.write_pos < self.write_buf.len()
            || self.needs_flush
            || self.pending_pong.is_some()
            || self.io.has_pending_write()
    }

    /// Forward a transport timeout to the wrapped byte stream.
    ///
    /// The runtime's handshake deadline wrapper lives below this type, so the
    /// `Duplex` forwarding impl in `stream.rs` cannot touch the private `io`
    /// field directly. This is crate-internal plumbing; it does not alter
    /// WebSocket framing or the frame budget.
    pub(crate) fn set_transport_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io.set_io_timeout(timeout)
    }

    /// Forward a handshake-deadline clear to the wrapped byte stream.
    ///
    /// Clearing is a distinct operation from installing `None`: the runtime's
    /// deadline wrapper must also disarm its own absolute deadline state.
    /// Forwarding through this private field keeps every layer's clear explicit
    /// instead of relying on a blanket `set_io_timeout(None)` translation.
    pub(crate) fn clear_transport_deadline(&self) -> io::Result<()> {
        self.io.clear_handshake_deadline()
    }
}

fn poisoned() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, WsError::Poisoned)
}

impl<T: Read + Write> Read for WsStream<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(poisoned());
        }
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending.len() {
                let take = (self.pending.len() - self.pending_pos).min(out.len());
                out[..take]
                    .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + take]);
                self.pending_pos += take;
                return Ok(take);
            }
            self.pending.clear();
            self.pending_pos = 0;
            if self.close_received {
                return Ok(0);
            }
            match self.next_data_payload() {
                Ok(Some(payload)) => self.pending = payload,
                Ok(None) => return Ok(0),
                Err(WsIoError::WouldBlock) => {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Err(WsIoError::Fatal(error)) => {
                    // Any framing/protocol error is fatal: bytes may already be
                    // partially consumed, so a later read must never try to
                    // resynchronise on the same stream.
                    self.failed = true;
                    self.pending.clear();
                    self.pending_pos = 0;
                    self.read_buf.clear();
                    self.read_pos = 0;
                    self.read_len = 0;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            }
        }
    }
}

impl<T: Read + Write> Write for WsStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(poisoned());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.close_sent {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket already closed",
            ));
        }
        if self.write_pos < self.write_buf.len() {
            match self.flush_write_buf() {
                Ok(()) => {}
                Err(WsIoError::WouldBlock) => {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Err(WsIoError::Fatal(error)) => {
                    self.failed = true;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            }
        }
        let take = buf.len().min(self.limits.max_frame_payload);
        if let Err(error) = encode_frame_into(
            self.role == WsRole::Client,
            true,
            OpCode::Binary,
            &buf[..take],
            &mut self.write_buf,
        ) {
            self.failed = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
        self.write_pos = 0;
        self.needs_flush = true;
        match self.flush_write_buf() {
            Ok(()) | Err(WsIoError::WouldBlock) => Ok(take),
            Err(WsIoError::Fatal(error)) => {
                self.failed = true;
                self.write_buf.clear();
                self.write_pos = 0;
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(poisoned());
        }
        match self.flush_write_buf() {
            Ok(()) => Ok(()),
            Err(WsIoError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(WsIoError::Fatal(error)) => {
                self.failed = true;
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    fn from_bits(bits: u8) -> Result<Self, WsError> {
        match bits {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(WsError::UnknownOpcode),
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawFrame {
    fin: bool,
    opcode: OpCode,
    payload: Vec<u8>,
}

/// Fill `buf`, re-checking an absolute deadline before and after every blocking
/// read. The socket read timeout alone would let a peer drip one byte per
/// timeout, and a busy loop alone cannot interrupt a blocked syscall. During the
/// handshake the runtime supplies that transport timeout; the data plane
/// deliberately has none, so this check bounds progress between reads there.
#[cfg(test)]
fn read_exact<T: Read>(io: &mut T, buf: &mut [u8], deadline: Instant) -> Result<(), WsError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(WsError::Timeout);
        }
        let read = io.read(&mut buf[filled..]).map_err(map_io)?;
        if read == 0 {
            return Err(WsError::Closed);
        }
        filled += read;
        // A single blocking read can return after the budget has expired. Do
        // not accept that byte just because it completed the buffer: the
        // deadline is absolute, not an idle timeout between reads.
        if Instant::now() >= deadline {
            return Err(WsError::Timeout);
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_frame<T: Read>(
    io: &mut T,
    role: WsRole,
    limits: &WsLimits,
    deadline: Instant,
) -> Result<RawFrame, WsError> {
    let mut head = [0u8; 2];
    read_exact(io, &mut head, deadline)?;
    let fin = head[0] & 0x80 != 0;
    if head[0] & 0x70 != 0 {
        return Err(WsError::ReservedBits);
    }
    let opcode = OpCode::from_bits(head[0] & 0x0f)?;
    let masked = head[1] & 0x80 != 0;
    match role {
        WsRole::Server if !masked => return Err(WsError::UnmaskedClientFrame),
        WsRole::Client if masked => return Err(WsError::MaskedServerFrame),
        _ => {}
    }

    let length_code = head[1] & 0x7f;
    let payload_len = match length_code {
        126 => {
            let mut bytes = [0u8; 2];
            read_exact(io, &mut bytes, deadline)?;
            let length = usize::from(u16::from_be_bytes(bytes));
            if length < 126 {
                return Err(WsError::NonCanonicalLength);
            }
            length
        }
        127 => {
            let mut bytes = [0u8; 8];
            read_exact(io, &mut bytes, deadline)?;
            let length = u64::from_be_bytes(bytes);
            if length < 65_536 {
                return Err(WsError::NonCanonicalLength);
            }
            usize::try_from(length).map_err(|_| WsError::MessageTooLarge)?
        }
        other => usize::from(other),
    };

    if opcode.is_control() {
        if !fin {
            return Err(WsError::ControlFragmented);
        }
        if payload_len > 125 {
            return Err(WsError::ControlTooLarge);
        }
    }
    if payload_len > limits.max_frame_payload {
        return Err(WsError::MessageTooLarge);
    }

    let mask = if masked {
        let mut mask = [0u8; 4];
        read_exact(io, &mut mask, deadline)?;
        Some(mask)
    } else {
        None
    };
    let mut payload = vec![0u8; payload_len];
    read_exact(io, &mut payload, deadline)?;
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(RawFrame {
        fin,
        opcode,
        payload,
    })
}

/// Encode one frame into reusable storage. Client frames are masked with a fresh CSPRNG mask.
fn encode_frame_into(
    masked: bool,
    fin: bool,
    opcode: OpCode,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), WsError> {
    out.clear();
    let first = if fin { 0x80 } else { 0x00 } | opcode.bits();
    let mask_bit: u8 = if masked { 0x80 } else { 0x00 };
    out.reserve(payload.len() + 14);
    out.push(first);
    match payload.len() {
        length @ 0..=125 => out.push(mask_bit | (length as u8)),
        length @ 126..=65_535 => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    if masked {
        let mask: [u8; 4] = csprng::random_array().map_err(|_| WsError::Entropy)?;
        out.extend_from_slice(&mask);
        let start = out.len();
        out.extend_from_slice(payload);
        let (chunks, rem) = out[start..].as_chunks_mut::<4>();
        for chunk in chunks {
            chunk[0] ^= mask[0];
            chunk[1] ^= mask[1];
            chunk[2] ^= mask[2];
            chunk[3] ^= mask[3];
        }
        for (idx, byte) in rem.iter_mut().enumerate() {
            *byte ^= mask[idx];
        }
    } else {
        out.extend_from_slice(payload);
    }
    Ok(())
}

#[cfg(test)]
fn encode_frame(
    masked: bool,
    fin: bool,
    opcode: OpCode,
    payload: &[u8],
) -> Result<Vec<u8>, WsError> {
    let mut out = Vec::new();
    encode_frame_into(masked, fin, opcode, payload, &mut out)?;
    Ok(out)
}

fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn close_payload_valid(payload: &[u8]) -> bool {
    match payload.len() {
        0 => true,
        1 => false,
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            valid_close_code(code) && std::str::from_utf8(&payload[2..]).is_ok()
        }
    }
}

fn is_token_byte(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

struct HttpHead {
    start_line: String,
    fields: Vec<(String, String)>,
}

impl HttpHead {
    fn start_line(&self) -> &str {
        &self.start_line
    }

    /// Look up a header, rejecting duplicates of the same name.
    fn field(&self, name: &str) -> Result<Option<&str>, WsError> {
        let mut found = None;
        for (key, value) in &self.fields {
            if key.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return Err(WsError::DuplicateHeader);
                }
                found = Some(value.as_str());
            }
        }
        Ok(found)
    }
}

fn header_has_token(value: &str, token: &str) -> bool {
    value.split(',').any(|part| {
        part.trim_matches(|c| c == ' ' || c == '\t')
            .eq_ignore_ascii_case(token)
    })
}

fn read_http_head<T: Read>(io: &mut T, deadline: Instant) -> Result<HttpHead, WsError> {
    let mut raw: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(WsError::Timeout);
        }
        let read = io.read(&mut byte).map_err(map_io)?;
        if read == 0 {
            return Err(WsError::Closed);
        }
        // Check after the read as well: a blocking read may return exactly the
        // terminating byte after the budget expired. The whole upgrade, not
        // just the time spent waiting before each read, must fit the deadline.
        if Instant::now() >= deadline {
            return Err(WsError::Timeout);
        }
        if byte[0] == b'\n' && raw.last().is_none_or(|last| *last != b'\r') {
            return Err(WsError::HeadMalformed);
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw.len() >= MAX_HTTP_HEAD_BYTES {
            return Err(WsError::HeadTooLarge);
        }
    }
    let text = std::str::from_utf8(&raw[..raw.len() - 4]).map_err(|_| WsError::HeadMalformed)?;
    parse_head(text)
}

fn parse_head(text: &str) -> Result<HttpHead, WsError> {
    let mut lines = text.split("\r\n");
    let start_line = lines.next().ok_or(WsError::HeadMalformed)?.to_owned();
    if start_line.is_empty() {
        return Err(WsError::HeadMalformed);
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            return Err(WsError::HeadMalformed);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(WsError::HeadMalformed);
        }
        let (name, value) = line.split_once(':').ok_or(WsError::HeadMalformed)?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(WsError::HeadMalformed);
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value
            .bytes()
            .any(|byte| byte == 0 || (byte < 0x20 && byte != 0x09) || byte == 0x7f)
        {
            return Err(WsError::HeadMalformed);
        }
        if fields.len() >= MAX_HTTP_HEADERS {
            return Err(WsError::HeadTooLarge);
        }
        fields.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(HttpHead { start_line, fields })
}

fn parse_status_line(line: &str) -> Result<u16, WsError> {
    let mut parts = line.split(' ');
    let version = parts.next().ok_or(WsError::HeadMalformed)?;
    if version != "HTTP/1.1" {
        return Err(WsError::HeadMalformed);
    }
    let code = parts.next().ok_or(WsError::HeadMalformed)?;
    if code.len() != 3 {
        return Err(WsError::HeadMalformed);
    }
    code.parse::<u16>().map_err(|_| WsError::HeadMalformed)
}

fn parse_request_line(line: &str) -> Result<(&str, &str), WsError> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(WsError::HeadMalformed)?;
    let target = parts.next().ok_or(WsError::HeadMalformed)?;
    let version = parts.next().ok_or(WsError::HeadMalformed)?;
    if version != "HTTP/1.1" || parts.next().is_some() {
        return Err(WsError::HeadMalformed);
    }
    Ok((method, target))
}

fn validate_host(host: &str) -> Result<(), WsError> {
    if host.is_empty() || host.len() > 255 {
        return Err(WsError::InvalidTarget);
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']' | b'_')
    }) {
        return Err(WsError::InvalidTarget);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), WsError> {
    if path.is_empty() || path.len() > 1024 || !path.starts_with('/') {
        return Err(WsError::InvalidTarget);
    }
    if !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(WsError::InvalidTarget);
    }
    Ok(())
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
        out.push(char::from(ALPHABET[((value >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((value >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[((value >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(value & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    // RFC 4648 encodes the empty octet string as the empty string. This is
    // distinct from malformed input; handshake keys are separately required
    // to decode to exactly 16 bytes.
    if text.is_empty() {
        return Some(Vec::new());
    }
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let chunks = text.len() / 4;
    let mut out = Vec::with_capacity(chunks * 3);
    for (index, chunk) in text.as_bytes().chunks(4).enumerate() {
        let last = index + 1 == chunks;
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (slot, byte) in values.iter_mut().zip(chunk) {
            if *byte == b'=' {
                padding += 1;
                *slot = 0;
            } else {
                if padding > 0 {
                    return None;
                }
                *slot = base64_value(*byte)?;
            }
        }
        if padding > 2 || (!last && padding > 0) {
            return None;
        }
        // Padding is only valid in the final quantum and only at its tail;
        // RFC 4648 also requires unused pad bits to be zero.
        if (padding == 2 && (chunk[0] == b'=' || chunk[1] == b'=' || values[1] & 0x0f != 0))
            || (padding == 1
                && (chunk[0] == b'='
                    || chunk[1] == b'='
                    || chunk[2] == b'='
                    || values[2] & 0x03 != 0))
            || (padding == 0 && chunk.contains(&b'='))
        {
            return None;
        }
        let value = (u32::from(values[0]) << 18)
            | (u32::from(values[1]) << 12)
            | (u32::from(values[2]) << 6)
            | u32::from(values[3]);
        out.push((value >> 16) as u8);
        if padding < 2 {
            out.push((value >> 8) as u8);
        }
        if padding < 1 {
            out.push(value as u8);
        }
    }
    Some(out)
}

fn expected_accept_key(key: &str) -> String {
    let mut material = Vec::with_capacity(key.len() + WS_GUID.len());
    material.extend_from_slice(key.as_bytes());
    material.extend_from_slice(WS_GUID.as_bytes());
    base64_encode(&sha1::sha1(&material))
}

/// Clamp a caller's absolute handshake deadline to the protocol's upgrade
/// budget. A tighter end-to-end budget is never widened here; a longer caller
/// budget still cannot make the HTTP upgrade exceed [`MAX_HANDSHAKE_DEADLINE`].
fn handshake_deadline(caller: Instant) -> Instant {
    caller.min(Instant::now() + MAX_HANDSHAKE_DEADLINE)
}

/// Write one handshake message under a single absolute deadline.
///
/// A bare `write_all` would reset any per-syscall timeout on every partial
/// write. The runtime transport also installs a per-operation timeout, but this
/// loop keeps the bound explicit for every `Write` implementation, including
/// in-memory ones used by tests.
fn write_all_until<T: Write>(io: &mut T, buf: &[u8], deadline: Instant) -> Result<(), WsError> {
    let mut written = 0usize;
    while written < buf.len() {
        if Instant::now() >= deadline {
            return Err(WsError::Timeout);
        }
        match io.write(&buf[written..]) {
            Ok(0) => return Err(WsError::Io(io::ErrorKind::WriteZero)),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    if Instant::now() >= deadline {
        return Err(WsError::Timeout);
    }
    io.flush().map_err(map_io)
}

/// Perform the client side of the RFC 6455 handshake over an established
/// transport (normally a fresh `TcpStream`).
pub fn client_handshake<T: Read + Write>(
    io: T,
    host: &str,
    path: &str,
) -> Result<WsStream<T>, WsError> {
    client_handshake_until(io, host, path, Instant::now() + MAX_HANDSHAKE_DEADLINE)
}

/// Client handshake under a caller-supplied absolute deadline.
///
/// The runtime passes the overall hop-handshake deadline here, so the WebSocket
/// upgrade cannot silently receive a fresh ten-second allowance after outer TLS
/// has already consumed most of the caller's budget.
pub(crate) fn client_handshake_until<T: Read + Write>(
    mut io: T,
    host: &str,
    path: &str,
    deadline: Instant,
) -> Result<WsStream<T>, WsError> {
    let deadline = handshake_deadline(deadline);
    validate_host(host)?;
    validate_path(path)?;
    let key_bytes: [u8; 16] = csprng::random_array().map_err(|_| WsError::Entropy)?;
    let key = base64_encode(&key_bytes);

    let mut request = String::with_capacity(256);
    request.push_str("GET ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(host);
    request.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    request.push_str(&key);
    request.push_str("\r\nSec-WebSocket-Version: 13\r\n\r\n");
    write_all_until(&mut io, request.as_bytes(), deadline)?;

    let head = read_http_head(&mut io, deadline)?;
    if parse_status_line(head.start_line())? != 101 {
        return Err(WsError::BadStatus);
    }
    let upgrade = head.field("upgrade")?.ok_or(WsError::BadUpgrade)?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(WsError::BadUpgrade);
    }
    let connection = head
        .field("connection")?
        .ok_or(WsError::BadConnectionHeader)?;
    if !header_has_token(connection, "upgrade") {
        return Err(WsError::BadConnectionHeader);
    }
    // Extensions are never offered, so any accepted extension is a downgrade
    // attempt (permessage-deflate enables compression side channels).
    if head.field("sec-websocket-extensions")?.is_some() {
        return Err(WsError::ExtensionOffered);
    }
    if head.field("sec-websocket-protocol")?.is_some() {
        return Err(WsError::UnexpectedSubprotocol);
    }
    let accept = head
        .field("sec-websocket-accept")?
        .ok_or(WsError::BadAcceptKey)?;
    if accept != expected_accept_key(&key) {
        return Err(WsError::BadAcceptKey);
    }

    Ok(WsStream::new(io, WsRole::Client, WsLimits::default()))
}

/// Perform the server side of the RFC 6455 handshake over an accepted
/// transport.
pub fn server_handshake<T: Read + Write>(io: T) -> Result<WsStream<T>, WsError> {
    server_handshake_until(io, Instant::now() + MAX_HANDSHAKE_DEADLINE)
}

/// Server handshake under a caller-supplied absolute deadline.
pub(crate) fn server_handshake_until<T: Read + Write>(
    mut io: T,
    deadline: Instant,
) -> Result<WsStream<T>, WsError> {
    let deadline = handshake_deadline(deadline);
    let head = read_http_head(&mut io, deadline)?;
    let (method, target) = parse_request_line(head.start_line())?;
    if method != "GET" {
        return Err(WsError::BadMethod);
    }
    if !target.starts_with('/') || target.len() > 1024 {
        return Err(WsError::HeadMalformed);
    }
    match head.field("sec-websocket-version")? {
        Some("13") => {}
        _ => return Err(WsError::BadVersion),
    }
    let upgrade = head.field("upgrade")?.ok_or(WsError::BadUpgrade)?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(WsError::BadUpgrade);
    }
    let connection = head
        .field("connection")?
        .ok_or(WsError::BadConnectionHeader)?;
    if !header_has_token(connection, "upgrade") {
        return Err(WsError::BadConnectionHeader);
    }
    if head.field("sec-websocket-extensions")?.is_some() {
        return Err(WsError::ExtensionOffered);
    }
    if head.field("content-length")?.is_some() {
        return Err(WsError::RequestBody);
    }
    let key = head.field("sec-websocket-key")?.ok_or(WsError::BadKey)?;
    let decoded = base64_decode(key).ok_or(WsError::BadKey)?;
    if decoded.len() != 16 {
        return Err(WsError::BadKey);
    }

    let accept = expected_accept_key(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    write_all_until(&mut io, response.as_bytes(), deadline)?;
    Ok(WsStream::new(io, WsRole::Server, WsLimits::default()))
}

/// Convenience for tests and adapters that already own a `TcpStream`.
pub fn client_handshake_tcp(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Result<WsStream<TcpStream>, WsError> {
    client_handshake(stream, host, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    struct MemoryIo {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for MemoryIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for MemoryIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn memory(input: &[u8]) -> MemoryIo {
        MemoryIo {
            input: Cursor::new(input.to_vec()),
            output: Vec::new(),
        }
    }

    fn inbound_frame(bytes: &[u8]) -> RawFrame {
        read_frame(
            &mut Cursor::new(bytes.to_vec()),
            WsRole::Server,
            &WsLimits::default(),
            Instant::now() + WsLimits::default().bounded().message_deadline,
        )
        .expect("valid client frame")
    }

    #[test]
    fn accept_key_matches_rfc6455_example() {
        assert_eq!(
            expected_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_roundtrip() {
        for length in 0..40usize {
            let data: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let encoded = base64_encode(&data);
            assert_eq!(base64_decode(&encoded).as_deref(), Some(data.as_slice()));
        }
        assert_eq!(base64_decode("abc"), None);
        assert_eq!(base64_decode("===="), None);
        assert_eq!(base64_decode("AA=A"), None);
        assert_eq!(base64_decode("AB=="), None); // non-zero unused pad bits
        assert_eq!(base64_decode("AAB="), None); // non-zero unused pad bits
        assert_eq!(base64_decode("AA==").as_deref(), Some(&[0][..]));
        assert_eq!(base64_decode("AAA=").as_deref(), Some(&[0, 0][..]));
        assert_eq!(base64_decode("=AAA"), None);
    }

    #[test]
    fn client_rejects_bad_accept_key() {
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
        assert_eq!(
            client_handshake(memory(response.as_bytes()), "hub.example.net", "/tunnel").err(),
            Some(WsError::BadAcceptKey)
        );
    }

    #[test]
    fn client_rejects_extension_offer() {
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
        assert_eq!(
            client_handshake(memory(response.as_bytes()), "hub.example.net", "/tunnel").err(),
            Some(WsError::ExtensionOffered)
        );
    }

    #[test]
    fn server_rejects_extension_and_missing_key() {
        let with_extension = "GET /tunnel HTTP/1.1\r\nHost: hub\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
        assert_eq!(
            server_handshake(memory(with_extension.as_bytes())).err(),
            Some(WsError::ExtensionOffered)
        );
        let missing_key = "GET /tunnel HTTP/1.1\r\nHost: hub\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            server_handshake(memory(missing_key.as_bytes())).err(),
            Some(WsError::BadKey)
        );
        let wrong_version = "GET /tunnel HTTP/1.1\r\nHost: hub\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n";
        assert_eq!(
            server_handshake(memory(wrong_version.as_bytes())).err(),
            Some(WsError::BadVersion)
        );
    }

    #[test]
    fn server_answers_with_expected_accept() {
        let request = "GET /tunnel HTTP/1.1\r\nHost: hub\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let stream = server_handshake(memory(request.as_bytes())).expect("handshake");
        let output = String::from_utf8(stream.io.output.clone()).expect("ascii response");
        assert!(output.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(output.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }

    #[test]
    fn loopback_handshake_and_binary_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            tcp.set_write_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut stream = server_handshake(tcp).expect("server handshake");
            let mut received = vec![0u8; 4096];
            let mut total = 0usize;
            while total < received.len() {
                let read = stream.read(&mut received[total..]).expect("read");
                if read == 0 {
                    break;
                }
                total += read;
            }
            stream.write_all(b"pong").expect("write");
            stream.flush().expect("flush");
            (total, received)
        });

        let tcp = TcpStream::connect(address).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut client =
            client_handshake(tcp, "hub.example.net", "/tunnel").expect("client handshake");
        let payload = vec![7u8; 4096];
        client.write_all(&payload).expect("write");
        client.flush().expect("flush");
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).expect("read reply");
        assert_eq!(&reply, b"pong");

        let (total, received) = server.join().expect("server thread");
        assert_eq!(total, 4096);
        assert_eq!(received, payload);
    }

    #[test]
    fn control_frames_do_not_enter_the_byte_stream() {
        let mut input = Vec::new();
        input.extend_from_slice(&encode_frame(false, true, OpCode::Ping, b"hi").expect("ping"));
        input.extend_from_slice(&encode_frame(false, true, OpCode::Binary, b"data").expect("data"));
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 4];
        stream.read_exact(&mut out).expect("data");
        assert_eq!(&out, b"data");

        // The pong was written by the client stream, therefore masked.
        let pong = read_frame(
            &mut Cursor::new(stream.io.output.clone()),
            WsRole::Server,
            &WsLimits::default(),
            Instant::now() + WsLimits::default().message_deadline,
        )
        .expect("valid masked pong frame");
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(pong.payload, b"hi");
    }

    #[test]
    fn close_frame_is_echoed_and_read_returns_eof() {
        let input = encode_frame(false, true, OpCode::Close, &[0x03, 0xe8]).expect("close");
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 8];
        assert_eq!(stream.read(&mut out).expect("eof"), 0);
        let echoed = inbound_frame(&stream.io.output);
        assert_eq!(echoed.opcode, OpCode::Close);
        assert_eq!(echoed.payload, [0x03, 0xe8]);
    }

    #[test]
    fn framing_violations_are_rejected() {
        let mut cursor = Cursor::new(encode_frame(false, true, OpCode::Binary, b"x").unwrap());
        assert_eq!(
            read_frame(
                &mut cursor,
                WsRole::Server,
                &WsLimits::default(),
                Instant::now() + Duration::from_secs(5),
            )
            .err(),
            Some(WsError::UnmaskedClientFrame)
        );

        let mut cursor = Cursor::new(encode_frame(true, true, OpCode::Binary, b"x").unwrap());
        assert_eq!(
            read_frame(
                &mut cursor,
                WsRole::Client,
                &WsLimits::default(),
                Instant::now() + Duration::from_secs(5),
            )
            .err(),
            Some(WsError::MaskedServerFrame)
        );

        let mut reserved = encode_frame(false, true, OpCode::Binary, b"x").unwrap();
        reserved[0] |= 0x40;
        let mut cursor = Cursor::new(reserved);
        assert_eq!(
            read_frame(
                &mut cursor,
                WsRole::Client,
                &WsLimits::default(),
                Instant::now() + Duration::from_secs(5),
            )
            .err(),
            Some(WsError::ReservedBits)
        );

        let mut text = encode_frame(false, true, OpCode::Text, b"x").unwrap();
        text[0] = 0x81;
        let mut stream = WsStream::new(memory(&text), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 1];
        assert!(stream.read(&mut out).is_err());
    }

    #[test]
    fn protocol_error_poisons_the_stream() {
        // A masked server frame is a protocol error for a client stream.
        let input = encode_frame(true, true, OpCode::Binary, b"x").expect("masked frame");
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 1];
        assert!(stream.read(&mut out).is_err());
        // The stream must stay dead: no resynchronisation on partially consumed
        // bytes and no further writes.
        assert!(stream.read(&mut out).is_err());
        assert!(stream.write(b"y").is_err());
    }

    #[test]
    fn control_flood_is_bounded() {
        let mut input = Vec::new();
        for _ in 0..=MAX_CONTROL_FRAMES_PER_READ {
            input.extend_from_slice(&encode_frame(false, true, OpCode::Ping, b"p").expect("ping"));
        }
        input.extend_from_slice(&encode_frame(false, true, OpCode::Binary, b"data").expect("data"));
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 4];
        assert!(stream.read(&mut out).is_err());
    }

    #[test]
    fn fragmented_message_is_reassembled_and_bounded() {
        let mut input = Vec::new();
        input.extend_from_slice(&encode_frame(false, false, OpCode::Binary, b"ab").unwrap());
        input.extend_from_slice(&encode_frame(false, false, OpCode::Continuation, b"cd").unwrap());
        input.extend_from_slice(&encode_frame(false, true, OpCode::Continuation, b"ef").unwrap());
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 6];
        stream.read_exact(&mut out).expect("reassembled");
        assert_eq!(&out, b"abcdef");

        let limits = WsLimits {
            max_fragments: 1,
            ..WsLimits::default()
        };
        let mut input = Vec::new();
        input.extend_from_slice(&encode_frame(false, false, OpCode::Binary, b"a").unwrap());
        input.extend_from_slice(&encode_frame(false, true, OpCode::Continuation, b"b").unwrap());
        let mut stream = WsStream::new(memory(&input), WsRole::Client, limits);
        let mut out = [0u8; 1];
        // Read returns already-available payload immediately; the fragment cap
        // is enforced when the next frame is consumed on the following read.
        assert_eq!(stream.read(&mut out).expect("first fragment"), 1);
        assert!(stream.read(&mut out).is_err());
    }

    #[test]
    fn oversized_frame_and_head_are_rejected() {
        let limits = WsLimits {
            max_frame_payload: 16,
            ..WsLimits::default()
        };
        // Client-side parser: an oversized server frame must be unmasked so
        // that the size limit, not the mask-role check, is the first failure.
        let mut bytes = vec![0x82, 0x7e, 0x00, 0x7e];
        bytes.extend(std::iter::repeat_n(0u8, 126));
        assert_eq!(
            read_frame(
                &mut Cursor::new(bytes),
                WsRole::Client,
                &limits,
                Instant::now() + Duration::from_secs(5),
            )
            .err(),
            Some(WsError::MessageTooLarge)
        );

        let mut head = b"HTTP/1.1 101 Switching Protocols\r\n".to_vec();
        head.extend(std::iter::repeat_n(b'x', MAX_HTTP_HEAD_BYTES));
        assert_eq!(
            client_handshake(memory(&head), "hub.example.net", "/tunnel").err(),
            Some(WsError::HeadTooLarge)
        );
    }

    #[test]
    fn close_payload_validation() {
        assert!(close_payload_valid(&[]));
        assert!(!close_payload_valid(&[0x03]));
        assert!(close_payload_valid(&[0x03, 0xe8]));
        assert!(!close_payload_valid(&[0x03, 0xe8, 0xff]));
        assert!(!close_payload_valid(&[0x03, 0xed]));
        assert!(close_payload_valid(&[0x0f, 0xa0]));
    }

    struct SlowFirstRead {
        slept: bool,
    }

    impl Read for SlowFirstRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.slept {
                self.slept = true;
                thread::sleep(Duration::from_millis(50));
            }
            buf[0] = 0x82;
            Ok(1)
        }
    }

    #[test]
    fn frame_deadline_is_not_restarted_after_each_read() {
        // The first byte arrives only after the budget has expired. The next
        // loop check must fail instead of granting a fresh deadline for the
        // remaining header/payload bytes or for a TLS record split.
        let mut io = SlowFirstRead { slept: false };
        let error = read_frame(
            &mut io,
            WsRole::Client,
            &WsLimits::default(),
            Instant::now() + Duration::from_millis(20),
        )
        .err();
        assert_eq!(error, Some(WsError::Timeout));
    }

    #[test]
    fn handshake_until_honors_a_caller_deadline_that_already_expired() {
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
        assert_eq!(
            client_handshake_until(
                memory(response.as_bytes()),
                "hub.example.net",
                "/tunnel",
                Instant::now(),
            )
            .err(),
            Some(WsError::Timeout)
        );
    }

    #[test]
    fn buffered_reader_tracks_coalesced_frames_across_reads() {
        let mut input = Vec::new();
        input.extend_from_slice(&encode_frame(false, true, OpCode::Binary, b"alpha").unwrap());
        input.extend_from_slice(&encode_frame(false, true, OpCode::Binary, b"beta").unwrap());

        let mut stream = WsStream::new(Cursor::new(input), WsRole::Client, WsLimits::default());
        assert!(stream.has_buffered_input());
        let mut first = [0u8; 5];
        stream.read_exact(&mut first).expect("first frame");
        assert_eq!(&first, b"alpha");
        // Second frame was already pulled into WsStream's read_buf during the first read.
        assert!(stream.read_pos < stream.read_len);
        assert!(stream.has_buffered_input());
        let mut second = [0u8; 4];
        stream.read_exact(&mut second).expect("second frame");
        assert_eq!(&second, b"beta");
        assert!(!stream.has_buffered_input());
    }

    #[test]
    fn nonblocking_would_block_preserves_partial_frame_and_write_buffer() {
        struct FragmentedIo {
            chunks: Vec<Vec<u8>>,
            idx: usize,
            write_calls: usize,
            written: Vec<u8>,
        }
        impl Read for FragmentedIo {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.idx >= self.chunks.len() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let chunk = &self.chunks[self.idx];
                self.idx += 1;
                if chunk.is_empty() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let take = chunk.len().min(out.len());
                out[..take].copy_from_slice(&chunk[..take]);
                Ok(take)
            }
        }
        impl Write for FragmentedIo {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.write_calls += 1;
                if self.write_calls == 1 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let take = buf.len().min(3);
                self.written.extend_from_slice(&buf[..take]);
                Ok(take)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let frame = encode_frame(false, true, OpCode::Binary, b"hello-nb").unwrap();
        let split = 4;
        let io = FragmentedIo {
            chunks: vec![frame[..split].to_vec(), Vec::new(), frame[split..].to_vec()],
            idx: 0,
            write_calls: 0,
            written: Vec::new(),
        };
        let mut ws = WsStream::new(io, WsRole::Client, WsLimits::default());
        let mut out = [0u8; 16];
        let err = ws.read(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let n = ws.read(&mut out).expect("second read completes frame");
        assert_eq!(&out[..n], b"hello-nb");

        assert_eq!(ws.write(b"abc").unwrap(), 3);
        assert!(ws.write_pos < ws.write_buf.len());
        assert_eq!(
            ws.write(b"def").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        ws.flush().expect("flush completes buffered frame");
        assert_eq!(ws.write_pos, ws.write_buf.len());
        let parsed = inbound_frame(&ws.io.written);
        assert_eq!(parsed.payload, b"abc");
    }
}
