//! HTTP/1.1 WebSocket upgrade bytes and HTTP/2 frame headers.
//!
//! Pure codecs for master-plan §6.1 and §6.3. This file writes and checks the
//! HTTP/1.1 opening handshake in front of the RFC 6455 binary frames that
//! `boreas_crypto::ws_frame` already encodes. It does not mask those frames,
//! and it does not open a socket.
//!
//! The HTTP/2 half parses and writes DATA, HEADERS, SETTINGS, and
//! WINDOW_UPDATE only. It is not a connection loop, not HPACK, and not flow
//! control. One `WINDOW_UPDATE` is checked as arithmetic; a credit ledger is
//! not implemented here.
//!
//! This is not a CDN test, not an h2 flow-control memory proof, and not any
//! gate. RFC 8441 Extended CONNECT waits for `SETTINGS_ENABLE_CONNECT_PROTOCOL`
//! on an HTTP/2 connection. [`h1_upgrade_on_negotiated_h2`] is false: this file
//! does not send an HTTP/1.1 Upgrade on a connection that already negotiated h2.

use std::fmt;

/// RFC 6455 GUID concatenated after the base64 key before SHA-1.
const WS_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Key` is the standard base64 of exactly 16 bytes.
pub const WS_KEY_LEN: usize = 16;

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// RFC 9113 default `SETTINGS_MAX_FRAME_SIZE`.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// Largest `SETTINGS_MAX_FRAME_SIZE` this codec will record (2^20).
pub const HARD_MAX_FRAME_SIZE: u32 = 1_048_576;

/// Initial connection flow-control window (RFC 9113 §6.9.2).
pub const INITIAL_CONNECTION_WINDOW: i32 = 65_535;

/// Largest `SETTINGS_INITIAL_WINDOW_SIZE` this plan allows.
///
/// An unconditional 64 MiB grant is forbidden. Values above 65535 are rejected.
pub const MAX_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// Highest legal flow-control window (`2^31 - 1`).
pub const MAX_WINDOW: i32 = i32::MAX;

const FRAME_HEADER_LEN: usize = 9;

const FT_DATA: u8 = 0x0;
const FT_HEADERS: u8 = 0x1;
const FT_SETTINGS: u8 = 0x4;
const FT_WINDOW_UPDATE: u8 = 0x8;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_PADDED: u8 = 0x8;

const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

/// HTTP/2 must not be selected by the HTTP/1.1 upgrade path.
///
/// RFC 8441: Extended CONNECT is used only after
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`. If that setting is absent, the
/// caller opens a new HTTP/1.1 connection. An HTTP/1.1 `Upgrade` is not sent
/// on a connection that already negotiated HTTP/2.
pub const fn h1_upgrade_on_negotiated_h2() -> bool {
    false
}

/// Why an upgrade message or an HTTP/2 frame was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Host was empty.
    EmptyHost,
    /// Path did not start with `/`.
    BadPath,
    /// A field contained CR or LF.
    CrLfInField,
    /// Input ended before a complete message or frame.
    Truncated,
    /// The status line was not `HTTP/1.1 101`.
    NotSwitchingProtocols,
    /// A required upgrade header was missing.
    MissingHeader,
    /// `Upgrade` was not `websocket`.
    BadUpgrade,
    /// `Connection` did not contain the `Upgrade` token.
    BadConnection,
    /// `Sec-WebSocket-Accept` was missing or not the RFC 6455 digest.
    BadAccept,
    /// `permessage-deflate` was offered or accepted.
    PermessageDeflate,
    /// Frame type is not DATA, HEADERS, SETTINGS, or WINDOW_UPDATE.
    Unsupported,
    /// Payload length is above the recorded maximum frame size.
    FrameTooLarge,
    /// A length that must be exact was not.
    BadLength,
    /// PADDED is rejected; padding is not implemented.
    Padded,
    /// DATA arrived on stream 0.
    DataOnStreamZero,
    /// SETTINGS acknowledgement carried a payload.
    SettingsAckPayload,
    /// A SETTINGS value is outside the range this codec accepts.
    BadSettings,
    /// `WINDOW_UPDATE` increment was 0.
    WindowUpdateZero,
    /// Applying the increment would pass `2^31 - 1`.
    WindowOverflow,
    /// Stream id reserved bit was set, or a frame forbade stream 0.
    BadStreamId,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Client opening handshake, ready to write on a fresh HTTP/1.1 connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRequest {
    /// Wire bytes, including the blank line. Not an HTTP/2 preface.
    pub bytes: Vec<u8>,
    /// The 16-byte key, so the caller can check `Sec-WebSocket-Accept` later.
    pub key: [u8; WS_KEY_LEN],
}

/// What a 101 response asserted. Frames are not consumed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAccept {
    /// HTTP header bytes consumed, including the blank line.
    pub header_len: usize,
}

/// Build `GET` with `Upgrade: websocket` and `Sec-WebSocket-Version: 13`.
///
/// `key` is 16 caller-supplied bytes. It is standard-base64 encoded into
/// `Sec-WebSocket-Key`. Empty `host`, a `path` that does not start with `/`,
/// or CR/LF in any field is rejected. `permessage-deflate` is not offered.
pub fn build_upgrade_request(
    host: &str,
    path: &str,
    key: [u8; WS_KEY_LEN],
) -> Result<UpgradeRequest, Error> {
    reject_request_fields(host, path)?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"GET ");
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");
    bytes.extend_from_slice(b"Host: ");
    bytes.extend_from_slice(host.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(b"Upgrade: websocket\r\n");
    bytes.extend_from_slice(b"Connection: Upgrade\r\n");
    bytes.extend_from_slice(b"Sec-WebSocket-Key: ");
    push_base64(&mut bytes, &key);
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n\r\n");
    debug_assert!(
        !contains_permessage_deflate(&bytes),
        "client must not offer permessage-deflate"
    );
    Ok(UpgradeRequest { bytes, key })
}

/// Parse a 101 response. Failure means the caller must not read frames.
///
/// Requires status 101, `Upgrade: websocket`, a `Connection` header that
/// contains the `Upgrade` token, and `Sec-WebSocket-Accept` equal to
/// base64(SHA-1(base64(key) + GUID)). A 200, a missing accept, or a wrong
/// accept is an error. `permessage-deflate` on either side is an error.
pub fn parse_upgrade_response(
    input: &[u8],
    key: &[u8; WS_KEY_LEN],
) -> Result<UpgradeAccept, Error> {
    let header_end = find_header_end(input)?;
    let header = &input[..header_end];
    if contains_permessage_deflate(header) {
        return Err(Error::PermessageDeflate);
    }
    let (status_line, rest) = split_first_line(header)?;
    if !status_is_101(status_line) {
        return Err(Error::NotSwitchingProtocols);
    }
    let mut upgrade = None;
    let mut connection = None;
    let mut accept = None;
    for line in split_lines(rest) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = split_header(line) else {
            return Err(Error::MissingHeader);
        };
        if name_eq(name, b"upgrade") {
            upgrade = Some(trim_ows(value));
        } else if name_eq(name, b"connection") {
            connection = Some(trim_ows(value));
        } else if name_eq(name, b"sec-websocket-accept") {
            accept = Some(trim_ows(value));
        } else if name_eq(name, b"sec-websocket-extensions") {
            return Err(Error::PermessageDeflate);
        }
    }
    match upgrade {
        Some(v) if token_eq_ignore_ascii_case(v, b"websocket") => {}
        Some(_) => return Err(Error::BadUpgrade),
        None => return Err(Error::MissingHeader),
    }
    match connection {
        Some(v) if connection_has_upgrade(v) => {}
        Some(_) => return Err(Error::BadConnection),
        None => return Err(Error::MissingHeader),
    }
    let expected = websocket_accept(key);
    match accept {
        Some(v) if v == expected.as_slice() => {}
        _ => return Err(Error::BadAccept),
    }
    Ok(UpgradeAccept {
        header_len: header_end,
    })
}

/// base64(SHA-1(base64(key) + GUID)), the `Sec-WebSocket-Accept` value.
pub fn websocket_accept(key: &[u8; WS_KEY_LEN]) -> [u8; 28] {
    let mut material = [0u8; 24 + 36];
    let key_b64 = base64_16(key);
    material[..24].copy_from_slice(&key_b64);
    material[24..].copy_from_slice(WS_ACCEPT_GUID);
    let digest = sha1(&material);
    base64_20(&digest)
}

/// HTTP/2 frame types this codec will read and write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameType {
    /// DATA (`0x0`). Payload is opaque octets, not HPACK.
    Data = FT_DATA as isize,
    /// HEADERS (`0x1`). Payload is an opaque header block, not decoded.
    Headers = FT_HEADERS as isize,
    /// SETTINGS (`0x4`).
    Settings = FT_SETTINGS as isize,
    /// WINDOW_UPDATE (`0x8`).
    WindowUpdate = FT_WINDOW_UPDATE as isize,
}

impl FrameType {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            FT_DATA => Ok(Self::Data),
            FT_HEADERS => Ok(Self::Headers),
            FT_SETTINGS => Ok(Self::Settings),
            FT_WINDOW_UPDATE => Ok(Self::WindowUpdate),
            _ => Err(Error::Unsupported),
        }
    }
}

/// 9-byte HTTP/2 frame header (RFC 9113 §4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    /// Payload length. Not part of the 9-byte header size.
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    /// 31-bit stream identifier. The reserved bit is not stored.
    pub stream_id: u32,
}

impl FrameHeader {
    /// Encode length, type, flags, and stream id. The reserved bit is written 0.
    pub fn write(self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.length > 0x00FF_FFFF {
            return Err(Error::FrameTooLarge);
        }
        if self.stream_id > 0x7FFF_FFFF {
            return Err(Error::BadStreamId);
        }
        let len = self.length.to_be_bytes();
        out.extend_from_slice(&len[1..4]);
        out.push(self.frame_type as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        Ok(())
    }
}

/// One decoded frame. Header-block and DATA octets are not interpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// DATA. `end_stream` is flag `0x1`. Padding is never present.
    Data {
        stream_id: u32,
        end_stream: bool,
        payload: Vec<u8>,
    },
    /// HEADERS. The payload is not HPACK-decoded.
    Headers {
        stream_id: u32,
        flags: u8,
        payload: Vec<u8>,
    },
    /// SETTINGS. `ack` is set only when the payload was empty.
    Settings { ack: bool, settings: Vec<Setting> },
    /// WINDOW_UPDATE. `increment` is already checked against zero and overflow.
    WindowUpdate { stream_id: u32, increment: u32 },
}

/// One SETTINGS parameter after the value checks in [`parse_settings_payload`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

/// Limits remembered from SETTINGS. This is not a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSettings {
    /// `SETTINGS_MAX_FRAME_SIZE`, default 16384, never above 1 MiB here.
    pub max_frame_size: u32,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`. `None` means the peer has not sent it.
    pub enable_connect_protocol: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` if the peer sent one within the cap.
    pub initial_window_size: Option<u32>,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            enable_connect_protocol: None,
            initial_window_size: None,
        }
    }
}

impl PeerSettings {
    /// Apply one SETTINGS payload. An ack is not applied here.
    pub fn apply(&mut self, settings: &[Setting]) -> Result<(), Error> {
        for setting in settings {
            match setting.id {
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(DEFAULT_MAX_FRAME_SIZE..=HARD_MAX_FRAME_SIZE).contains(&setting.value) {
                        return Err(Error::BadSettings);
                    }
                    self.max_frame_size = setting.value;
                }
                SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                    if setting.value > 1 {
                        return Err(Error::BadSettings);
                    }
                    self.enable_connect_protocol = Some(setting.value);
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if setting.value > MAX_INITIAL_WINDOW_SIZE {
                        return Err(Error::BadSettings);
                    }
                    self.initial_window_size = Some(setting.value);
                }
                SETTINGS_HEADER_TABLE_SIZE
                | SETTINGS_ENABLE_PUSH
                | SETTINGS_MAX_CONCURRENT_STREAMS
                | SETTINGS_MAX_HEADER_LIST_SIZE => {}
                _ => {}
            }
        }
        Ok(())
    }
}

/// Parse one frame. `max_frame_size` is the peer's `SETTINGS_MAX_FRAME_SIZE`.
///
/// The default is [`DEFAULT_MAX_FRAME_SIZE`]. A length above that is an error
/// unless the caller passes a recorded maximum no higher than 1 MiB. Other
/// frame types return [`Error::Unsupported`] and are not guessed. PADDED is
/// rejected. DATA on stream 0 is an error.
pub fn parse_frame(input: &[u8], max_frame_size: u32) -> Result<(Frame, usize), Error> {
    let max_frame_size = checked_max_frame_size(max_frame_size)?;
    if input.len() < FRAME_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let length = u32::from_be_bytes([0, input[0], input[1], input[2]]);
    if length > max_frame_size {
        return Err(Error::FrameTooLarge);
    }
    let type_byte = input[3];
    let flags = input[4];
    let stream_word = u32::from_be_bytes([input[5], input[6], input[7], input[8]]);
    if stream_word & 0x8000_0000 != 0 {
        return Err(Error::BadStreamId);
    }
    let stream_id = stream_word & 0x7FFF_FFFF;
    let total = FRAME_HEADER_LEN + length as usize;
    if input.len() < total {
        return Err(Error::Truncated);
    }
    let payload = &input[FRAME_HEADER_LEN..total];
    let frame_type = FrameType::from_u8(type_byte)?;
    if flags & FLAG_PADDED != 0
        && matches!(frame_type, FrameType::Data | FrameType::Headers)
    {
        return Err(Error::Padded);
    }
    let frame = match frame_type {
        FrameType::Data => {
            if stream_id == 0 {
                return Err(Error::DataOnStreamZero);
            }
            Frame::Data {
                stream_id,
                end_stream: flags & FLAG_END_STREAM != 0,
                payload: payload.to_vec(),
            }
        }
        FrameType::Headers => {
            if stream_id == 0 {
                return Err(Error::BadStreamId);
            }
            Frame::Headers {
                stream_id,
                flags,
                payload: payload.to_vec(),
            }
        }
        FrameType::Settings => {
            if stream_id != 0 {
                return Err(Error::BadStreamId);
            }
            let ack = flags & FLAG_ACK != 0;
            if ack {
                if !payload.is_empty() {
                    return Err(Error::SettingsAckPayload);
                }
                Frame::Settings {
                    ack: true,
                    settings: Vec::new(),
                }
            } else {
                Frame::Settings {
                    ack: false,
                    settings: parse_settings_payload(payload)?,
                }
            }
        }
        FrameType::WindowUpdate => parse_window_update(stream_id, payload)?,
    };
    Ok((frame, total))
}

/// Write one frame. The same checks as [`parse_frame`] apply on the way out.
pub fn write_frame(frame: &Frame, max_frame_size: u32) -> Result<Vec<u8>, Error> {
    let max_frame_size = checked_max_frame_size(max_frame_size)?;
    let mut out = Vec::new();
    match frame {
        Frame::Data {
            stream_id,
            end_stream,
            payload,
        } => {
            if *stream_id == 0 || *stream_id > 0x7FFF_FFFF {
                return Err(Error::BadStreamId);
            }
            check_len(payload.len(), max_frame_size)?;
            FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data,
                flags: if *end_stream { FLAG_END_STREAM } else { 0 },
                stream_id: *stream_id,
            }
            .write(&mut out)?;
            out.extend_from_slice(payload);
        }
        Frame::Headers {
            stream_id,
            flags,
            payload,
        } => {
            if *stream_id == 0 || *stream_id > 0x7FFF_FFFF {
                return Err(Error::BadStreamId);
            }
            if flags & FLAG_PADDED != 0 {
                return Err(Error::Padded);
            }
            check_len(payload.len(), max_frame_size)?;
            FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Headers,
                flags: *flags,
                stream_id: *stream_id,
            }
            .write(&mut out)?;
            out.extend_from_slice(payload);
        }
        Frame::Settings { ack, settings } => {
            if *ack {
                if !settings.is_empty() {
                    return Err(Error::SettingsAckPayload);
                }
                FrameHeader {
                    length: 0,
                    frame_type: FrameType::Settings,
                    flags: FLAG_ACK,
                    stream_id: 0,
                }
                .write(&mut out)?;
            } else {
                let payload = write_settings_payload(settings)?;
                check_len(payload.len(), max_frame_size)?;
                FrameHeader {
                    length: payload.len() as u32,
                    frame_type: FrameType::Settings,
                    flags: 0,
                    stream_id: 0,
                }
                .write(&mut out)?;
                out.extend_from_slice(&payload);
            }
        }
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => {
            if *stream_id > 0x7FFF_FFFF {
                return Err(Error::BadStreamId);
            }
            if *increment == 0 || *increment > 0x7FFF_FFFF {
                return Err(if *increment == 0 {
                    Error::WindowUpdateZero
                } else {
                    Error::WindowOverflow
                });
            }
            FrameHeader {
                length: 4,
                frame_type: FrameType::WindowUpdate,
                flags: 0,
                stream_id: *stream_id,
            }
            .write(&mut out)?;
            out.extend_from_slice(&increment.to_be_bytes());
        }
    }
    Ok(out)
}

/// Parse a SETTINGS payload. Does not apply it.
///
/// `SETTINGS_INITIAL_WINDOW_SIZE` above [`MAX_INITIAL_WINDOW_SIZE`] is
/// rejected. `SETTINGS_ENABLE_CONNECT_PROTOCOL` other than 0 or 1 is rejected.
/// A non-multiple of 6 is rejected.
pub fn parse_settings_payload(payload: &[u8]) -> Result<Vec<Setting>, Error> {
    if payload.len() % 6 != 0 {
        return Err(Error::BadLength);
    }
    let mut settings = Vec::with_capacity(payload.len() / 6);
    for chunk in payload.chunks(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        validate_setting(id, value)?;
        settings.push(Setting { id, value });
    }
    Ok(settings)
}

/// Check one WINDOW_UPDATE against the current window.
///
/// Increment 0 is a connection error. An increment that would move `current`
/// above `2^31 - 1` is an error. This is the arithmetic of one update only.
pub fn check_window_update(current: i32, increment: u32) -> Result<i32, Error> {
    if increment == 0 {
        return Err(Error::WindowUpdateZero);
    }
    if current < 0 {
        return Err(Error::WindowOverflow);
    }
    let next = (current as i64) + (increment as i64);
    if next > MAX_WINDOW as i64 {
        return Err(Error::WindowOverflow);
    }
    Ok(next as i32)
}

fn validate_setting(id: u16, value: u32) -> Result<(), Error> {
    match id {
        SETTINGS_INITIAL_WINDOW_SIZE if value > MAX_INITIAL_WINDOW_SIZE => Err(Error::BadSettings),
        SETTINGS_MAX_FRAME_SIZE
            if !(DEFAULT_MAX_FRAME_SIZE..=HARD_MAX_FRAME_SIZE).contains(&value) =>
        {
            Err(Error::BadSettings)
        }
        SETTINGS_ENABLE_PUSH | SETTINGS_ENABLE_CONNECT_PROTOCOL if value > 1 => {
            Err(Error::BadSettings)
        }
        _ => Ok(()),
    }
}

fn write_settings_payload(settings: &[Setting]) -> Result<Vec<u8>, Error> {
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for setting in settings {
        validate_setting(setting.id, setting.value)?;
        payload.extend_from_slice(&setting.id.to_be_bytes());
        payload.extend_from_slice(&setting.value.to_be_bytes());
    }
    Ok(payload)
}

fn parse_window_update(stream_id: u32, payload: &[u8]) -> Result<Frame, Error> {
    if payload.len() != 4 {
        return Err(Error::BadLength);
    }
    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if raw & 0x8000_0000 != 0 {
        return Err(Error::WindowOverflow);
    }
    let increment = raw & 0x7FFF_FFFF;
    // No current window is known here, so the ceiling check is against a
    // zero window: any in-range increment still fits. Callers that hold a
    // window use [`check_window_update`].
    let _ = check_window_update(0, increment)?;
    Ok(Frame::WindowUpdate {
        stream_id,
        increment,
    })
}

fn checked_max_frame_size(max_frame_size: u32) -> Result<u32, Error> {
    if !(DEFAULT_MAX_FRAME_SIZE..=HARD_MAX_FRAME_SIZE).contains(&max_frame_size) {
        Err(Error::BadSettings)
    } else {
        Ok(max_frame_size)
    }
}

fn check_len(len: usize, max_frame_size: u32) -> Result<(), Error> {
    if len > max_frame_size as usize {
        Err(Error::FrameTooLarge)
    } else {
        Ok(())
    }
}

fn reject_request_fields(host: &str, path: &str) -> Result<(), Error> {
    if host.is_empty() {
        return Err(Error::EmptyHost);
    }
    if !path.starts_with('/') {
        return Err(Error::BadPath);
    }
    if has_crlf(host) || has_crlf(path) {
        return Err(Error::CrLfInField);
    }
    Ok(())
}

fn has_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn find_header_end(input: &[u8]) -> Result<usize, Error> {
    input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or(Error::Truncated)
}

fn split_first_line(header: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let Some(i) = header.windows(2).position(|w| w == b"\r\n") else {
        return Err(Error::Truncated);
    };
    Ok((&header[..i], &header[i + 2..]))
}

fn split_lines(rest: &[u8]) -> impl Iterator<Item = &[u8]> {
    rest.split(|&b| b == b'\n').map(|line| {
        if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        }
    })
}

fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = line.iter().position(|b| *b == b':')?;
    Some((&line[..i], &line[i + 1..]))
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &v[start..end]
}

fn name_eq(name: &[u8], lower: &[u8]) -> bool {
    if name.len() != lower.len() {
        return false;
    }
    name.iter()
        .zip(lower.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn token_eq_ignore_ascii_case(value: &[u8], token: &[u8]) -> bool {
    value.len() == token.len()
        && value
            .iter()
            .zip(token.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn connection_has_upgrade(value: &[u8]) -> bool {
    value.split(|&b| b == b',').any(|part| {
        token_eq_ignore_ascii_case(trim_ows(part), b"upgrade")
    })
}

fn status_is_101(line: &[u8]) -> bool {
    // `HTTP/1.1 101` plus the required space before the reason phrase.
    // `HTTP/1.1 1011 ...` and a bare `HTTP/1.0 101` are not switching.
    let Some(rest) = line.strip_prefix(b"HTTP/1.1 ") else {
        return false;
    };
    rest.starts_with(b"101 ") || rest == b"101"
}

fn contains_permessage_deflate(bytes: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"permessage-deflate";
    bytes.windows(NEEDLE.len()).any(|w| {
        w.iter()
            .zip(NEEDLE.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

fn push_base64(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&base64_encode(data));
}

fn base64_16(data: &[u8; 16]) -> [u8; 24] {
    let encoded = base64_encode(data);
    let mut out = [0u8; 24];
    out.copy_from_slice(&encoded);
    out
}

fn base64_20(data: &[u8; 20]) -> [u8; 28] {
    let encoded = base64_encode(data);
    let mut out = [0u8; 28];
    out.copy_from_slice(&encoded);
    out
}

/// Standard base64 with `=` padding. No line breaks.
fn base64_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize]);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize]);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize]);
        out.push(BASE64_ALPHABET[(n & 0x3F) as usize]);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize]);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize]);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize]);
            out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    out
}

/// SHA-1 (FIPS 180-4). Used only for `Sec-WebSocket-Accept`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).saturating_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A82_7999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY: [u8; 16] = *b"the sample nonce";

    #[test]
    fn rfc6455_accept_vector() {
        let accept = websocket_accept(&SAMPLE_KEY);
        assert_eq!(&accept, b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(
            base64_encode(&SAMPLE_KEY),
            b"dGhlIHNhbXBsZSBub25jZQ=="
        );
    }

    #[test]
    fn sha1_known_answers() {
        assert_eq!(
            sha1(b""),
            hex20(b"da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(sha1(b"abc"), hex20(b"a9993e364706816aba3e25717850c26c9cd0d89d"));
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex20(b"84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    #[test]
    fn upgrade_request_shape_and_rejects() {
        let req = build_upgrade_request("example.com", "/boreas", SAMPLE_KEY).unwrap();
        let text = std::str::from_utf8(&req.bytes).unwrap();
        assert!(text.starts_with("GET /boreas HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(!text.to_ascii_lowercase().contains("permessage-deflate"));
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(req.key, SAMPLE_KEY);
        assert!(build_upgrade_request("", "/x", SAMPLE_KEY).is_err());
        assert!(build_upgrade_request("h", "x", SAMPLE_KEY).is_err());
        assert!(build_upgrade_request("h\r\nX: y", "/x", SAMPLE_KEY).is_err());
        assert!(build_upgrade_request("h", "/x\n", SAMPLE_KEY).is_err());
        assert!(!h1_upgrade_on_negotiated_h2());
    }

    #[test]
    fn switching_response_checks_accept() {
        let body = response_with_accept(&websocket_accept(&SAMPLE_KEY));
        let ok = parse_upgrade_response(&body, &SAMPLE_KEY).unwrap();
        assert_eq!(ok.header_len, body.len());
        let mut bad = websocket_accept(&SAMPLE_KEY);
        bad[0] ^= 1;
        assert_eq!(
            parse_upgrade_response(&response_with_accept(&bad), &SAMPLE_KEY),
            Err(Error::BadAccept)
        );
        let ok_200 = b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(
            parse_upgrade_response(ok_200, &SAMPLE_KEY),
            Err(Error::NotSwitchingProtocols)
        );
        let missing = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(
            parse_upgrade_response(missing, &SAMPLE_KEY),
            Err(Error::BadAccept)
        );
    }

    #[test]
    fn deflate_on_either_side_is_rejected() {
        let mut offered = build_upgrade_request("h", "/x", SAMPLE_KEY)
            .unwrap()
            .bytes;
        // The builder never emits the token. Injecting it into a response must fail.
        let _ = &mut offered;
        let bad = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert_eq!(
            parse_upgrade_response(bad, &SAMPLE_KEY),
            Err(Error::PermessageDeflate)
        );
    }

    #[test]
    fn frame_header_roundtrip_and_limits() {
        let frame = Frame::Data {
            stream_id: 1,
            end_stream: true,
            payload: b"hi".to_vec(),
        };
        let bytes = write_frame(&frame, DEFAULT_MAX_FRAME_SIZE).unwrap();
        assert_eq!(bytes.len(), 11);
        assert_eq!(&bytes[..3], &[0, 0, 2]);
        assert_eq!(bytes[3], FT_DATA);
        assert_eq!(bytes[4], FLAG_END_STREAM);
        let (parsed, n) = parse_frame(&bytes, DEFAULT_MAX_FRAME_SIZE).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed, frame);

        let mut big = write_frame(
            &Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: vec![0; DEFAULT_MAX_FRAME_SIZE as usize + 1],
            },
            HARD_MAX_FRAME_SIZE,
        )
        .unwrap();
        assert_eq!(
            parse_frame(&big, DEFAULT_MAX_FRAME_SIZE),
            Err(Error::FrameTooLarge)
        );
        let (parsed, _) = parse_frame(&big, HARD_MAX_FRAME_SIZE).unwrap();
        match parsed {
            Frame::Data { payload, .. } => {
                assert_eq!(payload.len(), DEFAULT_MAX_FRAME_SIZE as usize + 1)
            }
            _ => panic!("data"),
        }
        big[3] = 0x7;
        assert_eq!(parse_frame(&big, HARD_MAX_FRAME_SIZE), Err(Error::Unsupported));
        assert!(parse_frame(&[0, 0, 1], DEFAULT_MAX_FRAME_SIZE).is_err());
    }

    #[test]
    fn settings_window_and_padding() {
        let settings = vec![
            Setting {
                id: SETTINGS_INITIAL_WINDOW_SIZE,
                value: 65_535,
            },
            Setting {
                id: SETTINGS_ENABLE_CONNECT_PROTOCOL,
                value: 1,
            },
            Setting {
                id: SETTINGS_MAX_FRAME_SIZE,
                value: 32_768,
            },
        ];
        let bytes = write_frame(
            &Frame::Settings {
                ack: false,
                settings: settings.clone(),
            },
            DEFAULT_MAX_FRAME_SIZE,
        )
        .unwrap();
        let (parsed, _) = parse_frame(&bytes, DEFAULT_MAX_FRAME_SIZE).unwrap();
        let Frame::Settings {
            ack: false,
            settings: got,
        } = parsed
        else {
            panic!("settings");
        };
        assert_eq!(got, settings);
        let mut peer = PeerSettings::default();
        peer.apply(&got).unwrap();
        assert_eq!(peer.enable_connect_protocol, Some(1));
        assert_eq!(peer.max_frame_size, 32_768);
        assert_eq!(peer.initial_window_size, Some(65_535));

        assert_eq!(
            write_frame(
                &Frame::Settings {
                    ack: false,
                    settings: vec![Setting {
                        id: SETTINGS_INITIAL_WINDOW_SIZE,
                        value: 65_536,
                    }],
                },
                DEFAULT_MAX_FRAME_SIZE,
            ),
            Err(Error::BadSettings)
        );
        let ack = write_frame(
            &Frame::Settings {
                ack: true,
                settings: Vec::new(),
            },
            DEFAULT_MAX_FRAME_SIZE,
        )
        .unwrap();
        assert_eq!(ack.len(), 9);
        let mut dirty_ack = ack.clone();
        dirty_ack[2] = 6;
        dirty_ack.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
        assert_eq!(
            parse_frame(&dirty_ack, DEFAULT_MAX_FRAME_SIZE),
            Err(Error::SettingsAckPayload)
        );

        assert_eq!(check_window_update(0, 0), Err(Error::WindowUpdateZero));
        assert_eq!(
            check_window_update(MAX_WINDOW, 1),
            Err(Error::WindowOverflow)
        );
        assert_eq!(check_window_update(65_535, 1).unwrap(), 65_536);
        let zero = write_frame(
            &Frame::WindowUpdate {
                stream_id: 0,
                increment: 1,
            },
            DEFAULT_MAX_FRAME_SIZE,
        )
        .unwrap();
        let mut zero_inc = zero;
        zero_inc[9] = 0;
        zero_inc[10] = 0;
        zero_inc[11] = 0;
        zero_inc[12] = 0;
        assert_eq!(
            parse_frame(&zero_inc, DEFAULT_MAX_FRAME_SIZE),
            Err(Error::WindowUpdateZero)
        );

        let mut padded = write_frame(
            &Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: b"x".to_vec(),
            },
            DEFAULT_MAX_FRAME_SIZE,
        )
        .unwrap();
        padded[4] |= FLAG_PADDED;
        assert_eq!(
            parse_frame(&padded, DEFAULT_MAX_FRAME_SIZE),
            Err(Error::Padded)
        );
        let mut stream0 = write_frame(
            &Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: Vec::new(),
            },
            DEFAULT_MAX_FRAME_SIZE,
        )
        .unwrap();
        stream0[5] = 0;
        stream0[6] = 0;
        stream0[7] = 0;
        stream0[8] = 0;
        assert_eq!(
            parse_frame(&stream0, DEFAULT_MAX_FRAME_SIZE),
            Err(Error::DataOnStreamZero)
        );
    }

    fn response_with_accept(accept: &[u8]) -> Vec<u8> {
        let mut v = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: ".to_vec();
        v.extend_from_slice(accept);
        v.extend_from_slice(b"\r\n\r\n");
        v
    }

    fn hex20(s: &[u8]) -> [u8; 20] {
        let mut out = [0u8; 20];
        for i in 0..20 {
            out[i] = u8::from_str_radix(std::str::from_utf8(&s[i * 2..i * 2 + 2]).unwrap(), 16)
                .unwrap();
        }
        out
    }
}
