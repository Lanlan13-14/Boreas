//! Candidate Boreas wire primitives; not a frozen protocol or cryptographic implementation.
#![forbid(unsafe_code)]

use std::fmt;

pub const PROTO_MAJOR: u8 = 3;
pub const HEADER_LEN: usize = 8;
pub const MAX_BODY_LEN: u32 = 65_536;
pub const MAX_CBOR_DEPTH: usize = 32;
pub const ALLOWED_FLAGS: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Control = 1,
    HopIpBatch = 2,
    RelayCircuit = 3,
}
impl TryFrom<u8> for Kind {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Control),
            2 => Ok(Self::HopIpBatch),
            3 => Ok(Self::RelayCircuit),
            _ => Err(Error::UnknownKind(v)),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppHeader {
    pub proto_major: u8,
    pub kind: Kind,
    pub flags: u16,
    pub body_len: u32,
}
impl AppHeader {
    pub fn parse(b: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        let proto_major = b[0];
        if proto_major != PROTO_MAJOR {
            return Err(Error::BadVersion(proto_major));
        }
        let kind = Kind::try_from(b[1])?;
        let flags = u16::from_be_bytes([b[2], b[3]]);
        if flags & !ALLOWED_FLAGS != 0 {
            return Err(Error::BadFlags(flags));
        }
        let body_len = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        if body_len > MAX_BODY_LEN {
            return Err(Error::BodyTooLarge(body_len));
        }
        if kind == Kind::Control && body_len == 0 {
            return Err(Error::EmptyControl);
        }
        Ok(Self {
            proto_major,
            kind,
            flags,
            body_len,
        })
    }
    pub fn encode(self) -> Result<[u8; HEADER_LEN], Error> {
        if self.proto_major != PROTO_MAJOR {
            return Err(Error::BadVersion(self.proto_major));
        }
        if self.flags & !ALLOWED_FLAGS != 0 {
            return Err(Error::BadFlags(self.flags));
        }
        if self.body_len > MAX_BODY_LEN {
            return Err(Error::BodyTooLarge(self.body_len));
        }
        if self.kind == Kind::Control && self.body_len == 0 {
            return Err(Error::EmptyControl);
        }
        let mut b = [0; HEADER_LEN];
        b[0] = self.proto_major;
        b[1] = self.kind as u8;
        b[2..4].copy_from_slice(&self.flags.to_be_bytes());
        b[4..8].copy_from_slice(&self.body_len.to_be_bytes());
        Ok(b)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadVersion(u8),
    UnknownKind(u8),
    BadFlags(u16),
    BodyTooLarge(u32),
    EmptyControl,
    InvalidFrameBody,
    BufferLimit,
    Poisoned,
    Truncated,
    UnknownControl(u8),
    IllegalState,
    HopIpBatchForbidden,
    InvalidCbor(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub header: AppHeader,
    pub body: Vec<u8>,
}
/// Limit applies per feed to retained incomplete bytes plus returned frame wire bytes.
/// It does not bound caller-held frames, global memory, transport buffers or allocator overhead.
pub struct FrameDecoder {
    buf: Vec<u8>,
    limit: usize,
    failed: bool,
}
impl FrameDecoder {
    pub fn new(per_connection_limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit: per_connection_limit,
            failed: false,
        }
    }
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.failed = true;
        self.buf.clear();
        Err(e)
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<Frame>, Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        let mut out = Vec::new();
        let mut emitted = 0usize;
        for byte in input {
            if self
                .buf
                .len()
                .checked_add(emitted)
                .and_then(|n| n.checked_add(1))
                .filter(|n| *n <= self.limit)
                .is_none()
            {
                return self.fail(Error::BufferLimit);
            }
            self.buf.push(*byte);
            if self.buf.len() == HEADER_LEN {
                let raw: [u8; HEADER_LEN] = self.buf[..].try_into().expect("header length checked");
                if let Err(e) = AppHeader::parse(&raw) {
                    return self.fail(e);
                }
            }
            if self.buf.len() >= HEADER_LEN {
                let raw: [u8; HEADER_LEN] = self.buf[..HEADER_LEN]
                    .try_into()
                    .expect("header length checked");
                let h = match AppHeader::parse(&raw) {
                    Ok(v) => v,
                    Err(e) => return self.fail(e),
                };
                let n = HEADER_LEN + h.body_len as usize;
                if n > self.limit {
                    return self.fail(Error::BufferLimit);
                }
                if self.buf.len() == n {
                    let mut complete = std::mem::take(&mut self.buf);
                    let body = complete.split_off(HEADER_LEN);
                    emitted += n;
                    out.push(Frame { header: h, body });
                }
            }
        }
        Ok(out)
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        if self.buf.is_empty() {
            Ok(())
        } else {
            self.fail(Error::Truncated)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityMode {
    E2eRequired,
    HopOnly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Edge,
    Core,
    EnrollmentService,
}
/// Orthogonal facts about a session; circuit facts are per this context and must be scoped per circuit by callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionContext {
    pub hello_received: bool,
    pub accepted: bool,
    pub identity_registered: bool,
    pub peer_role: PeerRole,
    pub enrollment_service: bool,
    pub circuit_opening: bool,
    pub circuit_established: bool,
    pub mode: SecurityMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlType {
    SessionHello = 1,
    SessionAccept = 2,
    Enrollment = 3,
    DirectoryPage = 4,
    Lease = 5,
    Lsa = 6,
    Grant = 7,
    Revoke = 8,
    Probe = 9,
    Drain = 10,
    CircuitOpen = 16,
    CircuitAccept = 17,
    CircuitReset = 18,
    CircuitClose = 19,
}
impl TryFrom<u8> for ControlType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::SessionHello),
            2 => Ok(Self::SessionAccept),
            3 => Ok(Self::Enrollment),
            4 => Ok(Self::DirectoryPage),
            5 => Ok(Self::Lease),
            6 => Ok(Self::Lsa),
            7 => Ok(Self::Grant),
            8 => Ok(Self::Revoke),
            9 => Ok(Self::Probe),
            10 => Ok(Self::Drain),
            16 => Ok(Self::CircuitOpen),
            17 => Ok(Self::CircuitAccept),
            18 => Ok(Self::CircuitReset),
            19 => Ok(Self::CircuitClose),
            _ => Err(Error::UnknownControl(v)),
        }
    }
}
impl ControlType {
    pub fn body_cap(self) -> usize {
        match self {
            Self::SessionHello
            | Self::SessionAccept
            | Self::Lease
            | Self::CircuitOpen
            | Self::CircuitAccept => 4096,
            Self::Enrollment | Self::DirectoryPage | Self::Revoke => 16384,
            Self::Lsa | Self::Grant => 8192,
            Self::Probe | Self::Drain | Self::CircuitReset | Self::CircuitClose => 256,
        }
    }
}
pub fn validate_frame_policy(frame: &Frame, ctx: &mut SessionContext) -> Result<(), Error> {
    frame.header.encode()?;
    if frame.header.body_len as usize != frame.body.len() {
        return Err(Error::InvalidFrameBody);
    }
    match frame.header.kind {
        Kind::Control => {
            let Some(&subtype) = frame.body.first() else {
                return Err(Error::EmptyControl);
            };
            let t = ControlType::try_from(subtype)?;
            if frame.body.len() > t.body_cap() {
                return Err(Error::BodyTooLarge(frame.body.len() as u32));
            }
            match t {
                ControlType::SessionHello
                    if !ctx.accepted && !ctx.hello_received && !ctx.enrollment_service =>
                {
                    ctx.hello_received = true
                }
                ControlType::SessionAccept
                    if !ctx.accepted && ctx.hello_received && !ctx.enrollment_service =>
                {
                    ctx.accepted = true
                }
                ControlType::Enrollment
                    if ctx.enrollment_service
                        && ctx.peer_role == PeerRole::EnrollmentService
                        && !ctx.accepted =>
                {
                    ()
                }
                ControlType::DirectoryPage
                | ControlType::Grant
                | ControlType::Revoke
                | ControlType::Probe
                | ControlType::Drain
                    if ctx.accepted =>
                {
                    ()
                }
                ControlType::Lease if ctx.accepted && ctx.identity_registered => (),
                ControlType::Lsa if ctx.accepted && ctx.peer_role == PeerRole::Core => (),
                ControlType::CircuitOpen
                    if ctx.accepted
                        && ctx.mode == SecurityMode::E2eRequired
                        && !ctx.circuit_opening
                        && !ctx.circuit_established =>
                {
                    ctx.circuit_opening = true
                }
                ControlType::CircuitAccept if ctx.circuit_opening => {
                    ctx.circuit_opening = false;
                    ctx.circuit_established = true;
                }
                ControlType::CircuitReset if ctx.circuit_opening || ctx.circuit_established => {
                    ctx.circuit_opening = false;
                    ctx.circuit_established = false;
                }
                ControlType::CircuitClose if ctx.circuit_established => {
                    ctx.circuit_established = false
                }
                _ => return Err(Error::IllegalState),
            }
        }
        Kind::HopIpBatch => {
            if !ctx.accepted {
                return Err(Error::IllegalState);
            }
            if ctx.mode != SecurityMode::HopOnly {
                return Err(Error::HopIpBatchForbidden);
            }
        }
        Kind::RelayCircuit => {
            if !ctx.accepted || ctx.mode != SecurityMode::E2eRequired || !ctx.circuit_established {
                return Err(Error::IllegalState);
            }
        }
    }
    Ok(())
}

/// Validate one canonical CBOR item; accepts integers, byte/text strings, arrays and maps only.
pub fn validate_deterministic_cbor(
    data: &[u8],
    max_depth: usize,
    max_len: usize,
) -> Result<(), Error> {
    if max_depth > MAX_CBOR_DEPTH {
        return Err(Error::InvalidCbor("depth limit exceeds hard cap"));
    }
    if data.len() > max_len {
        return Err(Error::InvalidCbor("length limit"));
    }
    let mut p = Parser {
        d: data,
        i: 0,
        max_depth,
    };
    p.item(0)?;
    if p.i != data.len() {
        return Err(Error::InvalidCbor("trailing bytes"));
    }
    Ok(())
}
struct Parser<'a> {
    d: &'a [u8],
    i: usize,
    max_depth: usize,
}
impl<'a> Parser<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.d.get(self.i).ok_or(Error::InvalidCbor("truncated"))?;
        self.i += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let e = self
            .i
            .checked_add(n)
            .ok_or(Error::InvalidCbor("length overflow"))?;
        let s = self
            .d
            .get(self.i..e)
            .ok_or(Error::InvalidCbor("truncated"))?;
        self.i = e;
        Ok(s)
    }
    fn arg(&mut self, a: u8) -> Result<u64, Error> {
        Ok(match a {
            0..=23 => a as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(Error::InvalidCbor("non_shortest"));
                }
                v
            }
            25 => {
                let x = self.take(2)?;
                let v = u16::from_be_bytes([x[0], x[1]]) as u64;
                if v <= 255 {
                    return Err(Error::InvalidCbor("non_shortest"));
                }
                v
            }
            26 => {
                let x = self.take(4)?;
                let v = u32::from_be_bytes(x.try_into().unwrap()) as u64;
                if v <= 65535 {
                    return Err(Error::InvalidCbor("non_shortest"));
                }
                v
            }
            27 => {
                let x = self.take(8)?;
                let v = u64::from_be_bytes(x.try_into().unwrap());
                if v <= u32::MAX as u64 {
                    return Err(Error::InvalidCbor("non_shortest"));
                }
                v
            }
            31 => return Err(Error::InvalidCbor("unsupported_indefinite")),
            _ => return Err(Error::InvalidCbor("unsupported_reserved")),
        })
    }
    fn item(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.max_depth {
            return Err(Error::InvalidCbor("depth_limit"));
        }
        let h = self.byte()?;
        let major = h >> 5;
        let ai = h & 31;
        match major {
            0 | 1 => {
                self.arg(ai)?;
            }
            2 | 3 => {
                let n = usize::try_from(self.arg(ai)?)
                    .map_err(|_| Error::InvalidCbor("length overflow"))?;
                let b = self.take(n)?;
                if major == 3 && std::str::from_utf8(b).is_err() {
                    return Err(Error::InvalidCbor("invalid_utf8"));
                }
            }
            4 => {
                let n = self.arg(ai)?;
                for _ in 0..n {
                    self.item(depth + 1)?
                }
            }
            5 => {
                let n = self.arg(ai)?;
                let mut prev: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let start = self.i;
                    self.item(depth + 1)?;
                    let key = self.d[start..self.i].to_vec();
                    if let Some(p) = &prev {
                        if canonical_cmp(p, &key) != std::cmp::Ordering::Less {
                            return Err(Error::InvalidCbor("duplicate_or_key_order"));
                        }
                    }
                    prev = Some(key);
                    self.item(depth + 1)?
                }
            }
            _ => return Err(Error::InvalidCbor("unsupported_float_simple_tag")),
        }
        Ok(())
    }
}
fn canonical_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hdr(k: u8, n: u32) -> [u8; 8] {
        [
            3,
            k,
            0,
            0,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]
    }
    #[test]
    fn header_vectors() {
        assert_eq!(
            AppHeader::parse(&hdr(3, 0)).unwrap().encode().unwrap(),
            hdr(3, 0)
        );
        assert_eq!(AppHeader::parse(&hdr(2, 65536)).unwrap().body_len, 65536);
        assert!(AppHeader::parse(&[0; 8]).is_err());
        assert!(AppHeader::parse(&hdr(9, 1)).is_err());
        assert!(AppHeader::parse(&[3, 3, 0, 1, 0, 0, 0, 0]).is_err());
        assert!(AppHeader::parse(&hdr(3, 65537)).is_err());
    }
    #[test]
    fn every_split_and_merged_frames() {
        let mut wire = hdr(3, 3).to_vec();
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&hdr(2, 0));
        for split in 0..=wire.len() {
            let mut d = FrameDecoder::new(100);
            let mut got = d.feed(&wire[..split]).unwrap();
            got.extend(d.feed(&wire[split..]).unwrap());
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].body, b"abc");
            d.finish().unwrap();
        }
    }
    #[test]
    fn failure_locks_decoder() {
        let mut d = FrameDecoder::new(64);
        assert!(d.feed(&[3, 9, 0, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(d.feed(&hdr(3, 0)), Err(Error::Poisoned));
        let mut d = FrameDecoder::new(64);
        assert!(d.feed(&hdr(3, 65)).is_err());
        assert!(d.is_failed());
        let mut d = FrameDecoder::new(64);
        assert!(d.feed(&hdr(3, 0)[..4]).unwrap().is_empty());
        assert_eq!(d.finish(), Err(Error::Truncated));
    }
    #[test]
    fn cbor_candidate_vectors() {
        for x in [
            &[0x00][..],
            &[0x18, 0x18][..],
            &[0xa2, 1, 0, 2, 0][..],
            &[0x61, 0x61][..],
        ] {
            validate_deterministic_cbor(x, 8, 64).unwrap();
        }
        for x in [
            &[0x18, 1][..],
            &[0xa2, 1, 0, 1, 1][..],
            &[0xa2, 2, 0, 1, 0][..],
            &[0x9f, 0xff][..],
            &[0xf9, 0, 0][..],
            &[0xc0, 0][..],
            &[0x61, 0xff][..],
            &[0, 0][..],
            &[0x18][..],
        ] {
            assert!(validate_deterministic_cbor(x, 8, 64).is_err());
        }
        assert!(validate_deterministic_cbor(&[0], usize::MAX, 1).is_err());
    }
    #[test]
    fn policy_checks_empty_frame_and_mode() {
        let mut ctx = SessionContext {
            hello_received: false,
            accepted: true,
            identity_registered: false,
            peer_role: PeerRole::Edge,
            enrollment_service: false,
            circuit_opening: false,
            circuit_established: false,
            mode: SecurityMode::E2eRequired,
        };
        let empty = Frame {
            header: AppHeader {
                proto_major: 3,
                kind: Kind::Control,
                flags: 0,
                body_len: 0,
            },
            body: vec![],
        };
        assert_eq!(
            validate_frame_policy(&empty, &mut ctx),
            Err(Error::EmptyControl)
        );
        let data = Frame {
            header: AppHeader {
                proto_major: 3,
                kind: Kind::HopIpBatch,
                flags: 0,
                body_len: 0,
            },
            body: vec![],
        };
        assert_eq!(
            validate_frame_policy(&data, &mut ctx),
            Err(Error::HopIpBatchForbidden)
        );
        ctx.mode = SecurityMode::HopOnly;
        ctx.accepted = false;
        assert_eq!(
            validate_frame_policy(&data, &mut ctx),
            Err(Error::IllegalState)
        );
    }
}
