//! Bounded RFC 6455 binary-frame codec for the h1 WebSocket framing baseline.
//!
//! This module frames and deframes WebSocket binary data messages and the
//! Close / Ping / Pong control frames.  It does not speak HTTP, does not check
//! `SETTINGS_ENABLE_CONNECT_PROTOCOL`, does not prove CDN behavior, and does
//! not pass any gate.  HTTP Upgrade, HTTP/2 Extended CONNECT, certificates,
//! the CSPRNG that must supply each client mask, and any CDN probe stay
//! outside this type.
//!
//! `permessage-deflate` and every other extension are forbidden: any RSV bit
//! fails the frame.  Text opcode `0x1` is rejected because Boreas inner bytes
//! are binary only.  Masking uses the RFC 6455 rotating XOR; the caller
//! injects the 4-byte client mask so this codec never draws from a CSPRNG.

use std::fmt;

/// Default payload cap: one binary message, including a reassembled
/// continuation, may not exceed 32 KiB.
pub const DEFAULT_MAX_PAYLOAD: usize = 32 * 1024;

/// Hard ceiling a caller may request.  Larger caps are refused at construction.
pub const HARD_MAX_PAYLOAD: usize = 1024 * 1024;

/// Longest legal frame header: 2 base bytes + 8 length bytes + 4 mask bytes.
const MAX_HEADER_LEN: usize = 14;

/// RFC 6455 control-frame payload limit, also the largest 7-bit length.
const CONTROL_PAYLOAD_LIMIT: usize = 125;

/// Close reason may occupy at most 123 bytes after the 2-byte status.
const CLOSE_REASON_LIMIT: usize = 123;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Which side this decoder is reading, and which side the encoder writes as.
///
/// A client masks every frame it sends and rejects masked frames it receives.
/// A server does the opposite.  The direction is fixed for the life of the
/// codec; it is not inferred from the mask bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Frames this side writes are masked; frames it reads must be unmasked.
    Client,
    /// Frames this side writes are unmasked; frames it reads must be masked.
    Server,
}

/// One decoded WebSocket frame after unmasking.
///
/// Data continuations are not surfaced: they are accumulated until `FIN` and
/// then returned as one [`Frame::Binary`].  Control frames are returned as
/// they arrive and do not disturb an in-progress data message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// One complete binary message.  The payload may be empty.
    Binary(Vec<u8>),
    /// A Close control frame.  `None` is an empty close body.
    Close(Option<CloseBody>),
    /// A Ping control frame.  Payload is at most 125 bytes.
    Ping(Vec<u8>),
    /// A Pong control frame.  Payload is at most 125 bytes.
    Pong(Vec<u8>),
}

/// Status code and optional UTF-8 reason from a Close payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseBody {
    pub status: u16,
    pub reason: String,
}

/// Why a frame or message was rejected.
///
/// After any error the decoder is poisoned: further feeds return the same
/// class of failure and never yield another frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// An RSV bit was set.  Extensions, including permessage-deflate, are forbidden.
    RsvBitSet,
    /// Opcode is not continuation, binary, close, ping, or pong.
    /// Text (`0x1`) is explicitly included: this path is binary only.
    UnknownOpcode,
    /// A control frame had `FIN = 0` or a payload longer than 125 bytes.
    BadControlFrame,
    /// A 16-bit or 64-bit length was used where the shorter form was enough.
    NonMinimalLength,
    /// The 64-bit length had its most significant bit set (RFC 6455 §5.2).
    LengthMsbSet,
    /// Role and mask bit disagree: client received a mask, or server did not.
    MaskDirection,
    /// Payload, or the concatenated continuation, exceeds the configured cap.
    PayloadTooLarge,
    /// Continuation without a binary start, a new data opcode mid-message,
    /// or a second binary start before `FIN`.
    BadFragmentation,
    /// Close body was one byte, or the reason was not valid UTF-8.
    BadClosePayload,
    /// Close status is below 1000 and not in the small RFC-allowed set.
    BadCloseStatus,
    /// `feed` was called after a previous hard error.
    Poisoned,
    /// Caller asked for a cap of zero or above [`HARD_MAX_PAYLOAD`].
    CapOutOfRange,
    /// Encoder was given a control payload above 125 bytes, or a close
    /// reason above 123 bytes.
    EncodeTooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FrameError {}

/// Outcome of feeding bytes into the decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Feed {
    /// Not enough bytes for the next frame.  They stay buffered.
    NeedMore,
    /// Exactly one frame.  Any leftover bytes stay buffered.
    Frame(Frame),
}

/// Streaming RFC 6455 decoder/encoder bound to one [`Role`].
///
/// `feed` accepts an arbitrary split or merge of the byte stream.  One call
/// returns at most one frame.  Incomplete input returns [`Feed::NeedMore`].
/// The buffer never grows past `cap + 14` bytes: a frame whose header is
/// already known to exceed the cap is rejected before the body is stored.
#[derive(Debug)]
pub struct WsFrameCodec {
    role: Role,
    max_payload: usize,
    buffer: Vec<u8>,
    /// Reassembled binary payload waiting for `FIN`.  `None` means idle.
    partial: Option<Vec<u8>>,
    /// A Close frame has been decoded.  This is a record, not a state machine:
    /// later data frames are still parsed.
    close_seen: bool,
    poisoned: Option<FrameError>,
}

impl WsFrameCodec {
    /// Codec with the default 32 KiB message cap.
    pub fn new(role: Role) -> Self {
        Self::with_max_payload(role, DEFAULT_MAX_PAYLOAD)
            .expect("default payload cap is inside the hard range")
    }

    /// Codec with an explicit message cap, `1..=HARD_MAX_PAYLOAD`.
    pub fn with_max_payload(role: Role, max_payload: usize) -> Result<Self, FrameError> {
        if max_payload == 0 || max_payload > HARD_MAX_PAYLOAD {
            return Err(FrameError::CapOutOfRange);
        }
        Ok(Self {
            role,
            max_payload,
            buffer: Vec::new(),
            partial: None,
            close_seen: false,
            poisoned: None,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// True after a Close frame has been successfully decoded.
    pub fn close_seen(&self) -> bool {
        self.close_seen
    }

    /// True after a hard framing error.  The decoder no longer yields frames.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Bytes held back because they do not yet form a complete frame.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Accept the next slice of the WebSocket byte stream.
    ///
    /// At most one frame is returned.  Bytes beyond that frame remain buffered
    /// and are consumed by later calls, including a call with an empty slice.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Feed, FrameError> {
        if let Some(error) = self.poisoned {
            return Err(error);
        }
        if self.buffer.len().saturating_add(bytes.len()) > self.buffer_limit() {
            // A legal frame fits in cap+14.  Anything beyond that is either a
            // length that already failed the cap check or an oversize header
            // we refuse to accumulate.
            return self.poison(FrameError::PayloadTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        self.pull_frame()
    }

    /// Encode one binary data frame (opcode `0x2`, `FIN = 1`).
    ///
    /// `mask` is required for [`Role::Client`] and must be `None` for
    /// [`Role::Server`].  An empty payload is legal.
    pub fn encode_binary(
        &self,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        if payload.len() > self.max_payload {
            return Err(FrameError::PayloadTooLarge);
        }
        self.encode(true, OP_BINARY, payload, mask)
    }

    /// Encode a Close control frame.
    ///
    /// `None` writes an empty body.  A reason longer than 123 bytes is rejected.
    pub fn encode_close(
        &self,
        body: Option<&CloseBody>,
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        let payload = match body {
            None => Vec::new(),
            Some(close) => encode_close_body(close)?,
        };
        self.encode(true, OP_CLOSE, &payload, mask)
    }

    /// Encode a Ping control frame.  Payload must be at most 125 bytes.
    pub fn encode_ping(
        &self,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        self.encode_control(OP_PING, payload, mask)
    }

    /// Encode a Pong control frame.  Payload must be at most 125 bytes.
    pub fn encode_pong(
        &self,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        self.encode_control(OP_PONG, payload, mask)
    }

    fn encode_control(
        &self,
        opcode: u8,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        if payload.len() > CONTROL_PAYLOAD_LIMIT {
            return Err(FrameError::EncodeTooLarge);
        }
        self.encode(true, opcode, payload, mask)
    }

    fn encode(
        &self,
        fin: bool,
        opcode: u8,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Result<Vec<u8>, FrameError> {
        let masked = match (self.role, mask) {
            (Role::Client, Some(mask)) => Some(mask),
            (Role::Server, None) => None,
            _ => return Err(FrameError::MaskDirection),
        };
        Ok(write_frame(fin, opcode, payload, masked))
    }

    fn buffer_limit(&self) -> usize {
        self.max_payload.saturating_add(MAX_HEADER_LEN)
    }

    fn poison<T>(&mut self, error: FrameError) -> Result<T, FrameError> {
        self.poisoned = Some(error);
        self.buffer.clear();
        self.partial = None;
        Err(error)
    }

    fn pull_frame(&mut self) -> Result<Feed, FrameError> {
        loop {
            if self.poisoned.is_some() {
                return Err(self.poisoned.unwrap_or(FrameError::Poisoned));
            }
            let Some(header) = parse_header(&self.buffer)? else {
                return Ok(Feed::NeedMore);
            };
            if let Err(error) = self.validate_header(&header) {
                return self.poison(error);
            }
            let total = header.header_len.saturating_add(header.payload_len);
            if self.buffer.len() < total {
                // Header is complete but the body is not.  Reject before
                // buffering a body the cap already forbids; otherwise wait.
                if header.payload_len > self.max_payload {
                    return self.poison(FrameError::PayloadTooLarge);
                }
                return Ok(Feed::NeedMore);
            }
            let mut payload = self.buffer[header.header_len..total].to_vec();
            self.buffer.drain(..total);
            if let Some(mask) = header.mask {
                apply_mask(&mut payload, mask);
            }
            match self.accept(header, payload) {
                Ok(Some(frame)) => return Ok(Feed::Frame(frame)),
                Ok(None) => continue,
                Err(error) => return self.poison(error),
            }
        }
    }

    fn validate_header(&self, header: &Header) -> Result<(), FrameError> {
        if header.rsv != 0 {
            return Err(FrameError::RsvBitSet);
        }
        if !opcode_known(header.opcode) {
            return Err(FrameError::UnknownOpcode);
        }
        let masked = header.mask.is_some();
        let expect_masked = matches!(self.role, Role::Server);
        if masked != expect_masked {
            return Err(FrameError::MaskDirection);
        }
        if is_control(header.opcode) && (!header.fin || header.payload_len > CONTROL_PAYLOAD_LIMIT)
        {
            return Err(FrameError::BadControlFrame);
        }
        if header.payload_len > self.max_payload {
            return Err(FrameError::PayloadTooLarge);
        }
        Ok(())
    }

    /// `Ok(None)` consumes a non-final data fragment and keeps parsing.
    fn accept(&mut self, header: Header, payload: Vec<u8>) -> Result<Option<Frame>, FrameError> {
        if is_control(header.opcode) {
            return self.accept_control(header.opcode, payload).map(Some);
        }
        match (header.opcode, header.fin, self.partial.is_some()) {
            (OP_BINARY, true, false) => Ok(Some(Frame::Binary(payload))),
            (OP_BINARY, false, false) => {
                self.partial = Some(payload);
                Ok(None)
            }
            (OP_CONTINUATION, false, true) => self.append_partial(payload).map(|()| None),
            (OP_CONTINUATION, true, true) => {
                self.append_partial(payload)?;
                Ok(Some(Frame::Binary(self.partial.take().unwrap_or_default())))
            }
            (OP_CONTINUATION, _, false) | (OP_BINARY, _, true) => Err(FrameError::BadFragmentation),
            _ => Err(FrameError::UnknownOpcode),
        }
    }

    fn append_partial(&mut self, payload: Vec<u8>) -> Result<(), FrameError> {
        let partial = self.partial.as_mut().ok_or(FrameError::BadFragmentation)?;
        let next = partial.len().saturating_add(payload.len());
        if next > self.max_payload {
            return Err(FrameError::PayloadTooLarge);
        }
        partial.extend_from_slice(&payload);
        Ok(())
    }

    fn accept_control(&mut self, opcode: u8, payload: Vec<u8>) -> Result<Frame, FrameError> {
        match opcode {
            OP_CLOSE => {
                let body = decode_close(&payload)?;
                self.close_seen = true;
                Ok(Frame::Close(body))
            }
            OP_PING => Ok(Frame::Ping(payload)),
            OP_PONG => Ok(Frame::Pong(payload)),
            _ => Err(FrameError::UnknownOpcode),
        }
    }
}

struct Header {
    fin: bool,
    rsv: u8,
    opcode: u8,
    payload_len: usize,
    mask: Option<[u8; 4]>,
    header_len: usize,
}

/// Parse a header when the buffer contains one.  `Ok(None)` means the header
/// itself is incomplete.  Structural header errors are returned immediately.
fn parse_header(buffer: &[u8]) -> Result<Option<Header>, FrameError> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let b0 = buffer[0];
    let b1 = buffer[1];
    let fin = b0 & 0x80 != 0;
    let rsv = (b0 >> 4) & 0x07;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7F) as usize;

    let (payload_len, length_field) = if len7 < 126 {
        (len7, 0usize)
    } else if len7 == 126 {
        if buffer.len() < 4 {
            return Ok(None);
        }
        let value = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        if value < 126 {
            return Err(FrameError::NonMinimalLength);
        }
        (value, 2usize)
    } else {
        if buffer.len() < 10 {
            return Ok(None);
        }
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&buffer[2..10]);
        if wide[0] & 0x80 != 0 {
            return Err(FrameError::LengthMsbSet);
        }
        let value = u64::from_be_bytes(wide);
        if value < 65536 {
            return Err(FrameError::NonMinimalLength);
        }
        if value > usize::MAX as u64 {
            return Err(FrameError::PayloadTooLarge);
        }
        (value as usize, 8usize)
    };

    let header_len = 2 + length_field + if masked { 4 } else { 0 };
    if buffer.len() < header_len {
        return Ok(None);
    }
    let mask = if masked {
        let start = 2 + length_field;
        let mut key = [0u8; 4];
        key.copy_from_slice(&buffer[start..start + 4]);
        Some(key)
    } else {
        None
    };
    Ok(Some(Header {
        fin,
        rsv,
        opcode,
        payload_len,
        mask,
        header_len,
    }))
}

fn opcode_known(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    )
}

fn is_control(opcode: u8) -> bool {
    opcode & 0x08 != 0
}

/// RFC 6455 §5.3: octet `i` is XORed with `mask[i mod 4]`.
fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

fn write_frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let masked = mask.is_some();
    let mut out = Vec::with_capacity(MAX_HEADER_LEN + payload.len());
    let mut b0 = opcode & 0x0F;
    if fin {
        b0 |= 0x80;
    }
    out.push(b0);
    let len_marker: u8 = if payload.len() < 126 {
        payload.len() as u8
    } else if payload.len() <= u16::MAX as usize {
        126
    } else {
        127
    };
    out.push(len_marker | if masked { 0x80 } else { 0 });
    if payload.len() >= 126 && payload.len() <= u16::MAX as usize {
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else if payload.len() > u16::MAX as usize {
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if let Some(mask) = mask {
        out.extend_from_slice(&mask);
    }
    let body_start = out.len();
    out.extend_from_slice(payload);
    if let Some(mask) = mask {
        apply_mask(&mut out[body_start..], mask);
    }
    out
}

fn encode_close_body(close: &CloseBody) -> Result<Vec<u8>, FrameError> {
    if close.reason.len() > CLOSE_REASON_LIMIT {
        return Err(FrameError::EncodeTooLarge);
    }
    if !close_status_allowed(close.status) {
        return Err(FrameError::BadCloseStatus);
    }
    let mut payload = Vec::with_capacity(2 + close.reason.len());
    payload.extend_from_slice(&close.status.to_be_bytes());
    payload.extend_from_slice(close.reason.as_bytes());
    Ok(payload)
}

fn decode_close(payload: &[u8]) -> Result<Option<CloseBody>, FrameError> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() < 2 || payload.len() > CONTROL_PAYLOAD_LIMIT {
        return Err(FrameError::BadClosePayload);
    }
    let status = u16::from_be_bytes([payload[0], payload[1]]);
    if !close_status_allowed(status) {
        return Err(FrameError::BadCloseStatus);
    }
    let reason = std::str::from_utf8(&payload[2..]).map_err(|_| FrameError::BadClosePayload)?;
    Ok(Some(CloseBody {
        status,
        reason: reason.to_owned(),
    }))
}

/// Status codes this path accepts.
///
/// Empty bodies are handled separately.  Codes below 1000 are rejected except
/// the RFC 6455 private-use and registered values that are legal on the wire:
/// none of 0..=999 are legal.  1004, 1005, 1006 and 1015 must not appear in a
/// Close payload (RFC 6455 §7.4.1).  Everything else in 1000..=4999 is accepted.
fn close_status_allowed(status: u16) -> bool {
    matches!(status, 1000..=4999) && !matches!(status, 1004 | 1005 | 1006 | 1015)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    fn server() -> WsFrameCodec {
        WsFrameCodec::new(Role::Server)
    }

    fn client() -> WsFrameCodec {
        WsFrameCodec::new(Role::Client)
    }

    fn client_binary(payload: &[u8]) -> Vec<u8> {
        WsFrameCodec::new(Role::Client)
            .encode_binary(payload, Some(MASK))
            .expect("client binary")
    }

    fn feed_all(codec: &mut WsFrameCodec, bytes: &[u8]) -> Frame {
        match codec.feed(bytes).expect("frame") {
            Feed::Frame(frame) => frame,
            Feed::NeedMore => panic!("expected a complete frame"),
        }
    }

    #[test]
    fn byte_at_a_time_and_every_split_round_trip() {
        let payload = b"boreas-binary-frame";
        let wire = client_binary(payload);
        assert!(wire.len() > payload.len());

        let mut codec = server();
        for (index, byte) in wire.iter().enumerate() {
            let feed = codec.feed(&[*byte]).expect("incremental");
            if index + 1 < wire.len() {
                assert_eq!(feed, Feed::NeedMore);
            } else {
                assert_eq!(feed, Feed::Frame(Frame::Binary(payload.to_vec())));
            }
        }
        assert_eq!(codec.buffered_len(), 0);

        for split in 0..=wire.len() {
            let mut codec = server();
            assert_eq!(
                codec.feed(&wire[..split]).expect("prefix"),
                if split == wire.len() {
                    Feed::Frame(Frame::Binary(payload.to_vec()))
                } else {
                    Feed::NeedMore
                }
            );
            if split < wire.len() {
                assert_eq!(
                    codec.feed(&wire[split..]).expect("suffix"),
                    Feed::Frame(Frame::Binary(payload.to_vec()))
                );
            }
            assert_eq!(codec.buffered_len(), 0);
        }
    }

    #[test]
    fn merged_frames_return_the_first_and_keep_the_second() {
        let first = client_binary(b"one");
        let second = client_binary(b"two");
        let mut merged = first.clone();
        merged.extend_from_slice(&second);
        let mut codec = server();
        assert_eq!(
            codec.feed(&merged).expect("first of two"),
            Feed::Frame(Frame::Binary(b"one".to_vec()))
        );
        assert_eq!(codec.buffered_len(), second.len());
        assert_eq!(
            codec.feed(&[]).expect("buffered second"),
            Feed::Frame(Frame::Binary(b"two".to_vec()))
        );
        assert_eq!(codec.buffered_len(), 0);
    }

    #[test]
    fn rsv_text_direction_length_oversize_and_control_fragment_fail() {
        let mut rsv = client_binary(b"x");
        rsv[0] |= 0x40;
        assert_eq!(server().feed(&rsv), Err(FrameError::RsvBitSet));

        let text = write_frame(true, OP_TEXT, b"hi", Some(MASK));
        assert_eq!(server().feed(&text), Err(FrameError::UnknownOpcode));

        let unmasked = write_frame(true, OP_BINARY, b"hi", None);
        assert_eq!(server().feed(&unmasked), Err(FrameError::MaskDirection));

        let masked_for_client = client_binary(b"hi");
        assert_eq!(
            client().feed(&masked_for_client),
            Err(FrameError::MaskDirection)
        );

        // 16-bit length used for a 1-byte payload.
        let mut non_minimal = vec![0x82, 0xFE, 0x00, 0x01];
        non_minimal.extend_from_slice(&MASK);
        non_minimal.push(0x00);
        assert_eq!(
            server().feed(&non_minimal),
            Err(FrameError::NonMinimalLength)
        );

        let mut wide = vec![0x82, 0xFF];
        wide.extend_from_slice(&1u64.to_be_bytes());
        wide.extend_from_slice(&MASK);
        wide.push(0x00);
        assert_eq!(server().feed(&wide), Err(FrameError::NonMinimalLength));

        let mut capped = WsFrameCodec::with_max_payload(Role::Server, 4).expect("cap");
        let oversize = client_binary(b"12345");
        assert_eq!(capped.feed(&oversize), Err(FrameError::PayloadTooLarge));
        assert!(capped.is_poisoned());

        let fragmented_ping = write_frame(false, OP_PING, b"p", Some(MASK));
        assert_eq!(
            server().feed(&fragmented_ping),
            Err(FrameError::BadControlFrame)
        );
        let mut huge_control = vec![0x89, 0xFE, 0x00, 126];
        huge_control.extend_from_slice(&MASK);
        huge_control.extend(std::iter::repeat_n(0u8, 126));
        assert_eq!(
            server().feed(&huge_control),
            Err(FrameError::BadControlFrame)
        );

        let unknown = write_frame(true, 0x3, b"x", Some(MASK));
        assert_eq!(server().feed(&unknown), Err(FrameError::UnknownOpcode));
        assert!(WsFrameCodec::with_max_payload(Role::Client, 0).is_err());
        assert!(WsFrameCodec::with_max_payload(Role::Client, HARD_MAX_PAYLOAD + 1).is_err());
    }

    #[test]
    fn continuation_assembles_and_mid_message_binary_poisons() {
        let start = write_frame(false, OP_BINARY, b"ab", Some(MASK));
        let middle = write_frame(false, OP_CONTINUATION, b"cd", Some(MASK));
        let end = write_frame(true, OP_CONTINUATION, b"ef", Some(MASK));
        let mut codec = server();
        assert_eq!(codec.feed(&start).expect("start"), Feed::NeedMore);
        assert_eq!(codec.feed(&middle).expect("middle"), Feed::NeedMore);
        assert_eq!(
            codec.feed(&end).expect("end"),
            Feed::Frame(Frame::Binary(b"abcdef".to_vec()))
        );

        let ping = WsFrameCodec::new(Role::Client)
            .encode_ping(b"ping", Some(MASK))
            .expect("ping");
        let mut codec = server();
        assert_eq!(codec.feed(&start).expect("restart"), Feed::NeedMore);
        assert_eq!(
            codec.feed(&ping).expect("control between fragments"),
            Feed::Frame(Frame::Ping(b"ping".to_vec()))
        );
        assert_eq!(
            codec.feed(&end).expect("finish after ping"),
            Feed::Frame(Frame::Binary(b"abef".to_vec()))
        );

        let orphan = write_frame(true, OP_CONTINUATION, b"zz", Some(MASK));
        assert_eq!(server().feed(&orphan), Err(FrameError::BadFragmentation));

        let mut codec = server();
        assert_eq!(codec.feed(&start).expect("open"), Feed::NeedMore);
        let second = client_binary(b"nope");
        assert_eq!(codec.feed(&second), Err(FrameError::BadFragmentation));
        assert!(codec.is_poisoned());
        assert_eq!(codec.feed(&end), Err(FrameError::BadFragmentation));

        let mut tiny = WsFrameCodec::with_max_payload(Role::Server, 3).expect("cap");
        assert_eq!(tiny.feed(&start).expect("fits"), Feed::NeedMore);
        assert_eq!(tiny.feed(&middle), Err(FrameError::PayloadTooLarge));
    }

    #[test]
    fn mask_changes_wire_image_but_not_payload() {
        let payload = b"mask-me";
        let one = WsFrameCodec::new(Role::Client)
            .encode_binary(payload, Some([1, 2, 3, 4]))
            .expect("mask one");
        let two = WsFrameCodec::new(Role::Client)
            .encode_binary(payload, Some([9, 8, 7, 6]))
            .expect("mask two");
        assert_ne!(one, two);
        assert_ne!(&one[6..], payload);
        assert_eq!(
            feed_all(&mut server(), &one),
            Frame::Binary(payload.to_vec())
        );
        assert_eq!(
            feed_all(&mut server(), &two),
            Frame::Binary(payload.to_vec())
        );

        let unmasked = WsFrameCodec::new(Role::Server)
            .encode_binary(payload, None)
            .expect("server unmasked");
        assert_eq!(&unmasked[2..], payload);
        assert_eq!(
            feed_all(&mut client(), &unmasked),
            Frame::Binary(payload.to_vec())
        );
        assert!(
            WsFrameCodec::new(Role::Client)
                .encode_binary(payload, None)
                .is_err()
        );
        assert!(
            WsFrameCodec::new(Role::Server)
                .encode_binary(payload, Some(MASK))
                .is_err()
        );
        assert_eq!(
            feed_all(&mut server(), &client_binary(b"")),
            Frame::Binary(Vec::new())
        );
    }

    #[test]
    fn close_ping_pong_and_close_payload_rules() {
        let close = CloseBody {
            status: 1000,
            reason: "done".to_owned(),
        };
        let wire = WsFrameCodec::new(Role::Client)
            .encode_close(Some(&close), Some(MASK))
            .expect("close");
        let mut codec = server();
        assert_eq!(
            codec.feed(&wire).expect("decode close"),
            Feed::Frame(Frame::Close(Some(close.clone())))
        );
        assert!(codec.close_seen());

        let empty = WsFrameCodec::new(Role::Server)
            .encode_close(None, None)
            .expect("empty close");
        let mut peer = client();
        assert_eq!(
            peer.feed(&empty).expect("empty"),
            Feed::Frame(Frame::Close(None))
        );

        let bad_utf8 = write_frame(true, OP_CLOSE, &[0x03, 0xE8, 0xFF], Some(MASK));
        assert_eq!(server().feed(&bad_utf8), Err(FrameError::BadClosePayload));
        let one_byte = write_frame(true, OP_CLOSE, &[0x03], Some(MASK));
        assert_eq!(server().feed(&one_byte), Err(FrameError::BadClosePayload));
        let reserved = write_frame(true, OP_CLOSE, &1005u16.to_be_bytes(), Some(MASK));
        assert_eq!(server().feed(&reserved), Err(FrameError::BadCloseStatus));
        let below = write_frame(true, OP_CLOSE, &999u16.to_be_bytes(), Some(MASK));
        assert_eq!(server().feed(&below), Err(FrameError::BadCloseStatus));

        let ping = WsFrameCodec::new(Role::Client)
            .encode_ping(b"abc", Some(MASK))
            .expect("ping");
        let pong = WsFrameCodec::new(Role::Server)
            .encode_pong(b"abc", None)
            .expect("pong");
        assert_eq!(feed_all(&mut server(), &ping), Frame::Ping(b"abc".to_vec()));
        assert_eq!(feed_all(&mut client(), &pong), Frame::Pong(b"abc".to_vec()));
        assert!(
            WsFrameCodec::new(Role::Client)
                .encode_ping(&[0u8; 126], Some(MASK))
                .is_err()
        );
        let long_reason = "r".repeat(CLOSE_REASON_LIMIT + 1);
        assert!(
            WsFrameCodec::new(Role::Server)
                .encode_close(
                    Some(&CloseBody {
                        status: 1000,
                        reason: long_reason,
                    }),
                    None,
                )
                .is_err()
        );
    }

    #[test]
    fn buffer_stays_within_cap_plus_header() {
        let mut codec = WsFrameCodec::with_max_payload(Role::Server, 8).expect("cap");
        let mut huge = vec![0x82, 0x7E, 0x01, 0x00];
        huge.extend_from_slice(&MASK);
        huge.extend(std::iter::repeat_n(0u8, 32));
        assert_eq!(codec.feed(&huge), Err(FrameError::PayloadTooLarge));
        assert!(codec.buffered_len() <= 8 + MAX_HEADER_LEN);
    }
}
