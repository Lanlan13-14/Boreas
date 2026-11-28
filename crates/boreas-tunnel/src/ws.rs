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
        #[cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
        io::ErrorKind::Other if crate::error::tls_transport_eof(&error) => WsError::Closed,
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

/// A WebSocket connection exposed as a byte stream.
///
/// `Read` yields payload bytes of binary messages only. `Write` emits one
/// binary message per call, splitting into frames at
/// `limits.max_frame_payload`.
mod incremental;
#[cfg(test)]
mod resume_tests;
use incremental::{Incoming, ReceiveTurn};

pub struct WsStream<T> {
    io: T,
    role: WsRole,
    limits: WsLimits,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
    write_buf: Vec<u8>,
    pending: Vec<u8>,
    // `pending` keeps initialized high-water storage for reuse. Only this
    // validated prefix belongs to the current frame and may be exposed.
    pending_len: usize,
    pending_pos: usize,
    receive_turn: Option<ReceiveTurn>,
    write_pos: usize,
    write_active: bool,
    write_deadline: Option<Instant>,
    write_payload_len: usize,
    write_opcode: OpCode,
    progress_enabled: bool,
    control_reply: Option<(OpCode,Vec<u8>)>,
    message: MessageState,
    close_sent: bool,
    close_received: bool,
    failed: bool,
}

struct BufferedReader<'a, T> {
    io: &'a mut T,
    buf: &'a mut Vec<u8>,
    pos: &'a mut usize,
    len: &'a mut usize,
}

impl<T: Read> Read for BufferedReader<'_, T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if *pos_or_reset(self.pos, self.len) < *self.len {
            let avail = *self.len - *self.pos;
            let take = avail.min(out.len());
            out[..take].copy_from_slice(&self.buf[*self.pos..*self.pos + take]);
            *self.pos += take;
            if *self.pos == *self.len {
                *self.pos = 0;
                *self.len = 0;
            }
            return Ok(take);
        }
        if out.len() >= WS_READ_BUFFER_BYTES {
            return self.io.read(out);
        }
        if self.buf.len() < WS_READ_BUFFER_BYTES {
            self.buf.resize(WS_READ_BUFFER_BYTES, 0);
        }
        let n = self.io.read(self.buf)?;
        if n == 0 {
            return Ok(0);
        }
        let take = n.min(out.len());
        out[..take].copy_from_slice(&self.buf[..take]);
        if take < n {
            *self.pos = take;
            *self.len = n;
        } else {
            *self.pos = 0;
            *self.len = 0;
        }
        Ok(take)
    }
}

fn pos_or_reset<'a>(pos: &'a mut usize, len: &mut usize) -> &'a mut usize {
    if *pos >= *len {
        *pos = 0;
        *len = 0;
    }
    pos
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
            pending: Vec::new(),
            pending_len: 0,
            pending_pos: 0,
            receive_turn: None,
            write_pos:0, write_active:false, write_deadline:None, write_payload_len:0,
            write_opcode:OpCode::Binary, progress_enabled:false, control_reply:None,
            message: MessageState::default(),
            close_sent: false,
            close_received: false,
            failed: false,
        }
    }

    fn send_frame(&mut self, opcode: OpCode, payload: &[u8]) -> Result<(), WsError> {
        if !self.write_active {
            let frame_len=encode_frame_into(self.role == WsRole::Client, true, opcode, payload, &mut self.write_buf)?.len();
            self.write_buf.truncate(frame_len);
            self.write_active=true;
            self.write_pos=0;
            self.write_payload_len=payload.len();
            self.write_opcode=opcode;
            self.write_deadline=Some(Instant::now()+self.limits.message_deadline);
        } else if self.write_opcode!=opcode || self.write_payload_len!=payload.len() {
            return Err(WsError::Poisoned);
        } else {
            let header_len = self.write_buf.len().saturating_sub(payload.len());
            let same = if self.role == WsRole::Client {
                if header_len < 4 { false } else {
                    let mask = &self.write_buf[header_len - 4..header_len];
                    self.write_buf[header_len..].iter().zip(payload)
                        .enumerate().all(|(i, (wire, plain))| *wire ^ mask[i % 4] == *plain)
                }
            } else {
                self.write_buf[header_len..] == *payload
            };
            if !same { return Err(WsError::Poisoned); }
        }
        self.pump_wire_frame()?;
        self.write_active=false;
        self.write_pos=0;
        self.write_deadline=None;
        #[cfg(any(test, feature = "record-diagnostics"))]
        if opcode==OpCode::Binary {
            crate::record_diagnostics::observe(crate::record_diagnostics::Layer::WebSocket,payload);
        }
        Ok(())
    }

    // Progress the original encoded frame without acknowledging a different
    // caller. In particular a queued Pong cannot replace a pending Binary.
    fn pump_wire_frame(&mut self)->Result<(),WsError> {
        if self.write_deadline.is_some_and(|d|Instant::now()>=d) {return Err(WsError::Timeout);}
        while self.write_pos<self.write_buf.len() {
            match self.io.write(&self.write_buf[self.write_pos..]) {
                Ok(0)=>return Err(WsError::Io(io::ErrorKind::WriteZero)),
                Ok(n)=>self.write_pos+=n,
                Err(e) if e.kind()==io::ErrorKind::WouldBlock=>return Err(WsError::Io(io::ErrorKind::WouldBlock)),
                Err(e)=>return Err(map_io(e)),
            }
        }
        self.io.flush().map_err(|e|if e.kind()==io::ErrorKind::WouldBlock {
            WsError::Io(io::ErrorKind::WouldBlock)
        } else {map_io(e)})?;
        if self.write_deadline.is_some_and(|d|Instant::now()>=d) {return Err(WsError::Timeout);}
        Ok(())
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
    fn next_data_payload(&mut self) -> Result<bool, WsError> {
        self.receive_turn.get_or_insert_with(|| ReceiveTurn::new(self.limits.message_deadline));
        let mut payload = std::mem::take(&mut self.pending);
        loop {
            if let Some((opcode,body))=&self.control_reply {
                if self.write_active && self.write_opcode==OpCode::Binary {
                    return Err(WsError::Io(io::ErrorKind::WouldBlock));
                }
                let (opcode,body)=(*opcode,body.clone());
                self.send_frame(opcode,&body)?;
                self.control_reply=None;
                if opcode==OpCode::Close {
                    self.close_sent=true;self.close_received=true;
                    self.receive_turn=None;return Ok(false);
                }
            }
            let turn = self.receive_turn.as_mut().expect("receive turn installed");
            if turn.incoming.is_none() {
                turn.frames += 1;
                if turn.frames > MAX_FRAMES_PER_READ { return Err(WsError::FrameFlood); }
                turn.incoming = Some(Incoming::new(payload));
            }
            let frame = {
                let mut reader = BufferedReader {
                    io: &mut self.io,
                    buf: &mut self.read_buf,
                    pos: &mut self.read_pos,
                    len: &mut self.read_len,
                };
                turn.incoming.as_mut().expect("incoming installed")
                    .receive(&mut reader, self.role, &self.limits, turn.deadline)?
            };
            turn.incoming = None;
            match frame.opcode {
                OpCode::Ping | OpCode::Pong | OpCode::Close => {
                    turn.controls += 1;
                    turn.control_bytes = turn.control_bytes.saturating_add(frame.len);
                    if turn.controls > MAX_CONTROL_FRAMES_PER_READ
                        || turn.control_bytes > MAX_CONTROL_BYTES_PER_READ
                    {
                        return Err(WsError::ControlFlood);
                    }
                    match frame.opcode {
                        OpCode::Ping => {
                            self.control_reply = Some((OpCode::Pong, frame.payload().to_vec()));
                        }
                        OpCode::Close => {
                            if !close_payload_valid(frame.payload()) { return Err(WsError::BadCloseFrame); }
                            if self.close_sent {
                                self.close_received = true;
                                self.receive_turn = None;
                                return Ok(false);
                            }
                            let echo = if frame.len >= 2 { frame.payload()[..2].to_vec() } else { Vec::new() };
                            self.control_reply = Some((OpCode::Close, echo));
                        }
                        _ => {}
                    }
                    payload = frame.payload;
                }
                OpCode::Binary | OpCode::Continuation => {
                    self.track_message(frame.opcode, frame.fin, frame.len)?;
                    if frame.len == 0 {
                        payload = frame.payload;
                        continue;
                    }
                    self.pending_len = frame.len;
                    self.pending = frame.payload;
                    self.receive_turn = None;
                    return Ok(true);
                }
                OpCode::Text => return Err(WsError::TextFrame),
            }
        }
    }
}

impl<T: crate::stream::Duplex> WsStream<T> {
    /// Whether payload bytes are buffered above the underlying transport.
    /// A partial WebSocket frame is included conservatively; the event-loop
    /// owner still applies the normal bounded read and protocol checks.
    pub(crate) fn enable_transport_progress(&mut self) -> io::Result<bool> {
        self.progress_enabled=self.io.enable_progress()?;
        Ok(self.progress_enabled)
    }
    pub(crate) fn transport_output_pending(&self)->bool {
        self.write_active || self.control_reply.is_some() || self.io.has_pending_output()
    }
    pub(crate) fn wait_transport_progress(&self,timeout:Duration,write:bool)->io::Result<()> {
        self.io.wait_progress(timeout,write)
    }
    pub(crate) fn progress_transport_io(&mut self) -> io::Result<crate::stream::ProgressIo> {
        if self.failed {return Err(poisoned());}
        let mut result=self.io.progress_io()?;
        let before=self.write_pos;
        let operation=if self.write_active && self.write_opcode==OpCode::Binary {
            self.pump_wire_frame()
        } else if let Some((opcode,body))=&self.control_reply {
            let (opcode,body)=(*opcode,body.clone());
            self.send_frame(opcode,&body).map(|()| {
                self.control_reply=None;
                if opcode==OpCode::Close {
                    self.close_sent=true;self.close_received=true;self.receive_turn=None;
                }
            })
        } else {Ok(())};
        match operation {
            Ok(())=>{},
            Err(WsError::Io(io::ErrorKind::WouldBlock))=>{},
            Err(error)=>{self.failed=true;return Err(io::Error::new(io::ErrorKind::InvalidData,error));},
        }
        result.advanced|=self.write_pos!=before;
        Ok(result)
    }

    pub fn has_buffered_input(&self) -> bool {
        self.read_pos < self.read_len
            || self.pending_pos < self.pending_len
            || self.io.has_buffered_input()
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
            if self.pending_pos < self.pending_len {
                let take = (self.pending_len - self.pending_pos).min(out.len());
                out[..take]
                    .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + take]);
                self.pending_pos += take;
                return Ok(take);
            }
            // Retain the initialized high-water storage but expose no bytes
            // until the next frame has been completely read and validated.
            self.pending_len = 0;
            self.pending_pos = 0;
            if self.close_received {
                return Ok(0);
            }
            match self.next_data_payload() {
                Ok(true) => {}
                Ok(false) => return Ok(0),
                Err(WsError::Io(io::ErrorKind::WouldBlock)) => {
                    // Starting an empty nonblocking read is not the beginning
                    // of a peer frame. Do not expire genuinely idle links.
                    let idle=self.receive_turn.as_ref().is_some_and(|turn|
                        turn.frames==1 && turn.controls==0
                            && turn.incoming.as_ref().is_some_and(|incoming|!incoming.started()));
                    if idle && let Some(turn)=self.receive_turn.take()
                        && let Some(incoming)=turn.incoming {
                        self.pending=incoming.into_storage();
                    }
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Err(error) => {
                    self.receive_turn = None;
                    // Any framing/protocol error is fatal: bytes may already be
                    // partially consumed, so a later read must never try to
                    // resynchronise on the same stream.
                    self.failed = true;
                    self.pending.clear();
                    self.pending_len = 0;
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
        if self.control_reply.is_some() && !(self.write_active && self.write_opcode==OpCode::Binary) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let take = buf.len().min(self.limits.max_frame_payload);
        if let Err(error) = self.send_frame(OpCode::Binary, &buf[..take]) {
            if error==WsError::Io(io::ErrorKind::WouldBlock) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.failed = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
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
    // Storage may retain a larger initialized high-water mark. Bytes past len
    // are never part of this frame and must not reach the caller or control IO.
    payload: Vec<u8>,
    len: usize,
}

impl RawFrame {
    fn payload(&self) -> &[u8] {
        &self.payload[..self.len]
    }
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
    read_frame_into(io, role, limits, deadline, Vec::new())
}

#[cfg(test)]
fn read_frame_into<T: Read>(
    io: &mut T,
    role: WsRole,
    limits: &WsLimits,
    deadline: Instant,
    mut payload: Vec<u8>,
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
    // Shrinking a frame must not discard the initialized high-water mark:
    // otherwise every large/small alternation zero-fills that storage again.
    // The exact validated prefix is filled before it is ever made observable.
    if payload.len() < payload_len {
        payload.resize(payload_len, 0);
    }
    let current = &mut payload[..payload_len];
    read_exact(io, current, deadline)?;
    if let Some(mask) = mask {
        unmask_payload(current, mask);
    }
    Ok(RawFrame {
        fin,
        opcode,
        payload,
        len: payload_len,
    })
}

/// Encode one frame into reusable storage. Only the returned prefix is on the wire.
fn encode_frame_into<'a>(
    masked: bool,
    fin: bool,
    opcode: OpCode,
    payload: &[u8],
    out: &'a mut Vec<u8>,
) -> Result<&'a [u8], WsError> {
    let mut header = [0u8; 14];
    header[0] = if fin { 0x80 } else { 0x00 } | opcode.bits();
    let mask_bit: u8 = if masked { 0x80 } else { 0x00 };
    let header_len = match payload.len() {
        length @ 0..=125 => {
            header[1] = mask_bit | length as u8;
            2
        }
        length @ 126..=65_535 => {
            header[1] = mask_bit | 126;
            header[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            4
        }
        length => {
            header[1] = mask_bit | 127;
            header[2..10].copy_from_slice(&(length as u64).to_be_bytes());
            10
        }
    };
    if !masked {
        out.clear();
        out.reserve(header_len + payload.len());
        out.extend_from_slice(&header[..header_len]);
        out.extend_from_slice(payload);
        return Ok(out);
    }

    let mask: [u8; 4] = csprng::random_array().map_err(|_| WsError::Entropy)?;
    let masked_header_len = header_len + mask.len();
    header[header_len..masked_header_len].copy_from_slice(&mask);
    let frame_len = masked_header_len + payload.len();
    // Initialize only when the frame grows past the high-water mark. For
    // reused space, copy and mask in one pass without clearing or zero-filling.
    if out.len() < frame_len {
        out.resize(frame_len, 0);
    }
    let frame = &mut out[..frame_len];
    let (out_header, out_payload) = frame.split_at_mut(masked_header_len);
    out_header.copy_from_slice(&header[..masked_header_len]);
    copy_masked_payload(payload, out_payload, mask);
    Ok(frame)
}

fn copy_masked_payload(src: &[u8], dst: &mut [u8], mask: [u8; 4]) {
    // Native byte conversions preserve mask byte order on either endian.
    // Each word and the trailing bytes start at mask index zero.
    let word_mask = u64::from(u32::from_ne_bytes(mask));
    let word_mask = word_mask | (word_mask << 32);
    let (src_words, src_tail) = src.as_chunks::<8>();
    let (dst_words, dst_tail) = dst.as_chunks_mut::<8>();
    for (src, dst) in src_words.iter().zip(dst_words.iter_mut()) {
        *dst = (u64::from_ne_bytes(*src) ^ word_mask).to_ne_bytes();
    }
    for (index, (src, dst)) in src_tail.iter().zip(dst_tail.iter_mut()).enumerate() {
        *dst = *src ^ mask[index % 4];
    }
}

fn unmask_payload(payload: &mut [u8], mask: [u8; 4]) {
    // An eight-byte word is two full mask cycles on either endian. No
    // alignment assumptions, unsafe loads, or access outside the payload.
    let mask_word = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let (words, tail) = payload.as_chunks_mut::<8>();
    for word in words {
        *word = (u64::from_ne_bytes(*word) ^ mask_word).to_ne_bytes();
    }
    for (index, byte) in tail.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
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
    mod optimization_tests;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    struct MemoryIo {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        flushes: usize,
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
            self.flushes += 1;
            Ok(())
        }
    }

    fn memory(input: &[u8]) -> MemoryIo {
        MemoryIo {
            input: Cursor::new(input.to_vec()),
            output: Vec::new(),
            flushes: 0,
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
    fn unmask_matches_wire_bytes_for_unaligned_frames_and_all_tail_lengths() {
        for length in (0..=42).chain([125, 126, 16_384, 65_535, MAX_WS_FRAME_PAYLOAD]) {
            let mut actual = vec![0x5a; length + 2];
            let mask = [0x11, 0x23, 0x45, 0x87];
            let payload = &mut actual[1..1 + length];
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte = (i % 251) as u8;
            }
            let expected: Vec<_> = payload.iter().zip(mask.into_iter().cycle())
                .map(|(&byte, key)| byte ^ key).collect();
            unmask_payload(payload, mask);
            assert_eq!(payload, expected.as_slice(), "length {length}");
            assert_eq!(actual[0], 0x5a);
            assert_eq!(actual[length + 1], 0x5a);
        }
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
    fn reusable_frame_buffer_preserves_wire_bytes() {
        for role in [WsRole::Server, WsRole::Client] {
            let mut stream = WsStream::new(memory(&[]), role, WsLimits::default());
            let masked = role == WsRole::Client;
            // Grow to the long header, then reuse the buffer for shorter frames,
            // including every tail length of an eight-byte masking word.
            let lengths = [125usize, 126, 65_535, 65_536, 127]
                .into_iter()
                .chain(0..16);
            for (index, len) in lengths.enumerate() {
                let payload: Vec<u8> = (0..len).map(|i| (i ^ (i >> 3)) as u8).collect();
                let start = stream.io.output.len();
                stream
                    .send_frame(OpCode::Binary, &payload)
                    .expect("send frame");
                assert_eq!(stream.io.flushes, index + 1);
                let frame = &stream.io.output[start..];
                assert_eq!(frame[0], 0x82);
                assert_eq!(frame[1] & 0x80 != 0, masked);
                let mask_start = match len {
                    0..=125 => {
                        assert_eq!(frame[1] & 0x7f, len as u8);
                        2
                    }
                    126..=65_535 => {
                        assert_eq!(frame[1] & 0x7f, 126);
                        assert_eq!(&frame[2..4], &(len as u16).to_be_bytes());
                        4
                    }
                    _ => {
                        assert_eq!(frame[1] & 0x7f, 127);
                        assert_eq!(&frame[2..10], &(len as u64).to_be_bytes());
                        10
                    }
                };
                let payload_start = if masked { mask_start + 4 } else { mask_start };
                assert_eq!(frame.len(), payload_start + len);
                if masked {
                    // Compare against RFC 6455's byte-wise rule, not the reader.
                    // Equal masks on two frames are possible, so don't assert
                    // anything about the relationship between sampled masks.
                    for (i, &byte) in payload.iter().enumerate() {
                        assert_eq!(frame[payload_start + i], byte ^ frame[mask_start + i % 4]);
                    }
                } else {
                    assert_eq!(&frame[payload_start..], payload.as_slice());
                }
            }
        }
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
        assert_eq!(pong.payload(), b"hi");
    }

    #[test]
    fn close_frame_is_echoed_and_read_returns_eof() {
        let input = encode_frame(false, true, OpCode::Close, &[0x03, 0xe8]).expect("close");
        let mut stream = WsStream::new(memory(&input), WsRole::Client, WsLimits::default());
        let mut out = [0u8; 8];
        assert_eq!(stream.read(&mut out).expect("eof"), 0);
        let echoed = inbound_frame(&stream.io.output);
        assert_eq!(echoed.opcode, OpCode::Close);
        assert_eq!(echoed.payload(), [0x03, 0xe8]);
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
}
