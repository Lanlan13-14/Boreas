//! Candidate Boreas wire primitives; not a frozen protocol or cryptographic implementation.
#![forbid(unsafe_code)]

pub mod authority_revocation;
pub mod batch;
pub mod dns_authority;
pub mod dns_service_policy;
pub mod h1h2;
pub mod messages;
pub mod network_policy;
pub mod objects;
pub mod revocation;
pub mod session_auth;
#[cfg(test)]
mod recycle_tests;

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
    header_bytes: [u8; HEADER_LEN],
    header_len: usize,
    // Some only after the full header is validated; until then body is empty.
    header: Option<AppHeader>,
    body: Vec<u8>,
    limit: usize,
    failed: bool,
}
impl FrameDecoder {
    pub fn new(per_connection_limit: usize) -> Self {
        Self {
            header_bytes: [0; HEADER_LEN],
            header_len: 0,
            header: None,
            body: Vec::new(),
            limit: per_connection_limit,
            failed: false,
        }
    }
    pub fn buffered_len(&self) -> usize {
        self.header_len + self.body.len()
    }
    /// Capacity retained by the incomplete body or the single recycled slot.
    /// Caller-held Frames are intentionally not counted here.
    pub fn body_capacity(&self) -> usize { self.body.capacity() }

    /// Internal transport ownership seam. Only an empty, fully consumed body
    /// is accepted, within the caller's remaining capacity budget. This cannot
    /// decode/publish a Frame or replace bytes that still have an owner.
    #[doc(hidden)]
    pub fn recycle_empty_body(&mut self, body: Vec<u8>, available_capacity: usize) -> bool {
        if self.failed || !body.is_empty() || self.body.capacity() != 0
            || body.capacity() > available_capacity
        { return false; }
        self.body = body;
        true
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }
    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.failed = true;
        self.header_len = 0;
        self.header = None;
        self.body = Vec::new();
        Err(e)
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<Frame>, Error> {
        let mut out = Vec::new();
        self.feed_into(input, &mut out)?;
        Ok(out)
    }

    /// Decode one input chunk, reusing caller-owned frame metadata storage.
    /// The destination is replaced, and is empty on error (even if a valid
    /// frame preceded the error in the same chunk).
    pub fn feed_into(&mut self, input: &[u8], out: &mut Vec<Frame>) -> Result<(), Error> {
        out.clear();
        let result = self.decode_chunk(input, out);
        if result.is_err() {
            out.clear();
        }
        result
    }

    fn decode_chunk(&mut self, mut input: &[u8], out: &mut Vec<Frame>) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        let mut emitted = 0usize;
        while !input.is_empty() {
            let header = if let Some(header) = self.header {
                header
            } else {
                let take = input.len().min(HEADER_LEN - self.header_len);
                if take > self.limit - emitted - self.header_len {
                    return self.fail(Error::BufferLimit);
                }
                self.header_bytes[self.header_len..self.header_len + take]
                    .copy_from_slice(&input[..take]);
                self.header_len += take;
                input = &input[take..];
                if self.header_len < HEADER_LEN {
                    break;
                }
                // Validate immediately when the header is complete, before
                // charging or accepting any body bytes.
                let header = match AppHeader::parse(&self.header_bytes) {
                    Ok(header) => header,
                    Err(error) => return self.fail(error),
                };
                self.header = Some(header);
                header
            };
            let body_len = header.body_len as usize;
            let wire_len = HEADER_LEN + body_len;
            let take = input.len().min(body_len - self.body.len());
            if wire_len > self.limit || take > self.limit - emitted - self.buffered_len() {
                return self.fail(Error::BufferLimit);
            }
            let body = if self.body.is_empty() && take == body_len {
                // Copy once into the unique recycled allocation if available.
                // A contiguous input is not claimed to be zero-copy.
                self.body.extend_from_slice(&input[..take]);
                std::mem::take(&mut self.body)
            } else {
                let received = self.body.len() + take;
                if received > self.body.capacity() {
                    // Grow only as bytes arrive. Cap geometric growth at the
                    // checked body length, since the frame will own this Vec.
                    let capacity = self
                        .body
                        .capacity()
                        .saturating_mul(2)
                        .max(received)
                        .min(body_len);
                    self.body.reserve_exact(capacity - self.body.len());
                }
                self.body.extend_from_slice(&input[..take]);
                if received < body_len {
                    break;
                }
                // For split bodies, transfer the accumulated allocation instead
                // of allocating and copying the entire body again at completion.
                std::mem::take(&mut self.body)
            };
            self.header_len = 0;
            self.header = None;
            out.push(Frame { header, body });
            emitted += wire_len;
            input = &input[take..];
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        if self.buffered_len() == 0 {
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
    /// Local 128-bit network id; session payloads must match it exactly.
    pub net_id: [u8; 16],
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
    IdentityRevocation = 20,
    MeshPath = 21,
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
            20 => Ok(Self::IdentityRevocation),
            21 => Ok(Self::MeshPath),
            _ => Err(Error::UnknownControl(v)),
        }
    }
}
impl ControlType {
    /// Candidate body cap including the subtype byte, shared by the payload
    /// registry in [`messages`] so framing and payload codecs cannot drift.
    pub const fn body_cap(self) -> usize {
        match self {
            Self::SessionHello | Self::SessionAccept | Self::CircuitOpen | Self::CircuitAccept => {
                4096
            }
            // A dual-signed AttachmentLease envelope needs ~9.5 KiB with
            // ML-DSA-87 signatures plus TBS, so the plan's 4 KiB row is not
            // implementable; 16 KiB is the candidate replacement pending plan
            // review.
            Self::Enrollment | Self::DirectoryPage | Self::Lease | Self::Revoke => 16384,
            Self::Lsa | Self::Grant => 8192,
            Self::IdentityRevocation => 2 + authority_revocation::MAX_IDENTITY_REVOCATION_BYTES,
            Self::MeshPath => 2 + messages::MAX_MESH_PATH_CORES,
            Self::Probe | Self::Drain | Self::CircuitReset | Self::CircuitClose => 256,
        }
    }
}
/// Validate one frame against the candidate registry, per-subtype body cap and
/// session state gates. Payload schemas are intentionally separate: call
/// [`messages::parse_control_body`] before applying state transitions so a
/// structurally malformed `SessionHello` cannot advance the handshake.
pub fn validate_frame_policy(frame: &Frame, ctx: &mut SessionContext) -> Result<(), Error> {
    validate_frame_policy_parts(&frame.header, &frame.body, ctx)
}

/// Apply the identical frame policy to a borrowed body before serialization.
pub fn validate_frame_policy_parts(
    header: &AppHeader,
    body: &[u8],
    ctx: &mut SessionContext,
) -> Result<(), Error> {
    header.encode()?;
    if header.body_len as usize != body.len() {
        return Err(Error::InvalidFrameBody);
    }
    match header.kind {
        Kind::Control => {
            let Some(&subtype) = body.first() else {
                return Err(Error::EmptyControl);
            };
            let t = ControlType::try_from(subtype)?;
            if body.len() > t.body_cap() {
                return Err(Error::BodyTooLarge(body.len() as u32));
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
                        && !ctx.accepted => {}
                ControlType::DirectoryPage
                | ControlType::Grant
                | ControlType::Revoke
                | ControlType::Probe
                | ControlType::Drain
                    if ctx.accepted => {}
                ControlType::Lease if ctx.accepted && ctx.identity_registered => (),
                ControlType::Lsa if ctx.accepted && ctx.peer_role == PeerRole::Core => (),
                ControlType::IdentityRevocation | ControlType::MeshPath
                    if ctx.accepted
                        && ctx.peer_role == PeerRole::Core
                        && ctx.mode == SecurityMode::E2eRequired
                        && !ctx.circuit_opening
                        && !ctx.circuit_established => {}
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
        return Err(Error::InvalidCbor("length_limit"));
    }
    let mut p = Parser {
        d: data,
        i: 0,
        max_depth,
    };
    p.item(0)?;
    if p.i != data.len() {
        return Err(Error::InvalidCbor("trailing_bytes"));
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
                    if let Some(p) = &prev
                        && canonical_cmp(p, &key) != std::cmp::Ordering::Less
                    {
                        return Err(Error::InvalidCbor("duplicate_or_key_order"));
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
    // ------------------------------------------------------------------
    // G-FRAME adversarial coverage (master plan v1.11.0 SS6.2/Phase 1
    // G-FRAME; task brief items 1-4). Helpers stay inside this test
    // module on purpose: no test-only re-implementation is exported.
    // ------------------------------------------------------------------

    /// Fixed-seed xorshift64* -- deterministic pseudo-random cut points
    /// without an external `rand` dependency (adding one is forbidden).
    fn prng_step(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *s = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Wire image of one valid frame (8-byte header + body).
    fn wire(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = hdr(kind, body.len() as u32).to_vec();
        v.extend_from_slice(body);
        v
    }

    /// Feed `input` in fixed-seed pseudo-random chunk sizes (1..=16 B);
    /// on success also requires a clean `finish()`.
    fn feed_prng_chunks(
        d: &mut FrameDecoder,
        input: &[u8],
        seed: u64,
    ) -> Result<Vec<Frame>, Error> {
        let mut frames = Vec::new();
        let mut state = seed;
        let mut offset = 0;
        while offset < input.len() {
            let step = 1 + (prng_step(&mut state) % 16) as usize;
            let end = (offset + step).min(input.len());
            frames.extend(d.feed(&input[offset..end])?);
            offset = end;
        }
        d.finish()?;
        Ok(frames)
    }

    /// Header + body of one control frame with 0xA5 filler bytes.
    fn control_wire(subtype: u8, body_len: usize) -> Vec<u8> {
        assert!(body_len >= 1);
        let mut body = vec![0xA5; body_len];
        body[0] = subtype;
        wire(1, &body)
    }

    fn test_ctx() -> SessionContext {
        SessionContext {
            hello_received: false,
            accepted: false,
            identity_registered: false,
            peer_role: PeerRole::Edge,
            enrollment_service: false,
            circuit_opening: false,
            circuit_established: false,
            mode: SecurityMode::E2eRequired,
            net_id: [0x5A; 16],
        }
    }

    fn frame(kind: Kind, body: Vec<u8>) -> Frame {
        let body_len = body.len() as u32;
        Frame {
            header: AppHeader {
                proto_major: PROTO_MAJOR,
                kind,
                flags: 0,
                body_len,
            },
            body,
        }
    }

    fn control_body(subtype: u8, total_len: usize) -> Vec<u8> {
        assert!(total_len >= 1);
        let mut body = vec![0xA5; total_len];
        body[0] = subtype;
        body
    }

    /// Legal frame set shared by the split/merge tests; wire-level only
    /// (policy order is tested separately, not by the decoder).
    fn legal_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&wire(1, b"\x01hello")); // Control body > 0
        s.extend_from_slice(&wire(1, &[0x02])); // Control body == 1 (subtype only)
        s.extend_from_slice(&wire(2, &[0u8; 64]));
        s.extend_from_slice(&wire(3, &[]));
        s.extend_from_slice(&wire(3, &[0x5A; 300]));
        s.extend_from_slice(&wire(2, &vec![0xC3; 4096]));
        s
    }

    #[test]
    fn split_merge_byte_at_a_time_matches_bulk_reference() {
        let stream = legal_stream();
        let mut bulk = FrameDecoder::new(1024 * 1024);
        let reference = bulk.feed(&stream).unwrap();
        bulk.finish().unwrap();
        assert_eq!(reference.len(), 6);
        let mut drip = FrameDecoder::new(1024 * 1024);
        let mut got = Vec::new();
        for byte in &stream {
            got.extend(drip.feed(&[*byte]).unwrap());
        }
        drip.finish().unwrap();
        assert_eq!(
            got, reference,
            "byte-at-a-time result differs from bulk feed"
        );
    }

    #[test]
    fn split_merge_fixed_seed_prng_matches_bulk_reference() {
        let stream = legal_stream();
        let mut bulk = FrameDecoder::new(1024 * 1024);
        let reference = bulk.feed(&stream).unwrap();
        bulk.finish().unwrap();
        assert_eq!(reference.len(), 6);
        for seed in [
            1u64,
            0x1234_5678,
            0xDEAD_BEEF_CAFE,
            u64::MAX,
            0x9E37_79B9_7F4A_7C15,
        ] {
            let mut d = FrameDecoder::new(1024 * 1024);
            let got = feed_prng_chunks(&mut d, &stream, seed).unwrap();
            assert_eq!(got, reference, "fixed-seed PRNG cut error, seed={seed:#x}");
        }
    }

    #[test]
    fn split_merge_all_two_way_splits_match() {
        // Extends the pre-existing every_split test to a 4-frame stream:
        // every bisection point must reproduce the same frame set.
        let mut stream = Vec::new();
        stream.extend_from_slice(&wire(1, b"\x01hi"));
        stream.extend_from_slice(&wire(2, &[7u8; 33]));
        stream.extend_from_slice(&wire(3, &[]));
        stream.extend_from_slice(&wire(1, &[0x09]));
        let mut bulk = FrameDecoder::new(1024 * 1024);
        let reference = bulk.feed(&stream).unwrap();
        bulk.finish().unwrap();
        assert_eq!(reference.len(), 4);
        for split in 0..=stream.len() {
            let mut d = FrameDecoder::new(1024 * 1024);
            let mut got = d.feed(&stream[..split]).unwrap();
            got.extend(d.feed(&stream[split..]).unwrap());
            d.finish().unwrap();
            assert_eq!(got, reference, "split at {split} diverges");
        }
    }

    #[test]
    fn caller_owned_decode_output_reuses_capacity_and_discards_failed_chunk() {
        let wire = legal_stream();
        let mut reference = FrameDecoder::new(1024 * 1024);
        let mut decoder = FrameDecoder::new(1024 * 1024);
        let mut reuse = Vec::with_capacity(16);
        let capacity = reuse.capacity();
        for chunk in wire.chunks(7) {
            decoder.feed_into(chunk, &mut reuse).unwrap();
            assert_eq!(reuse, reference.feed(chunk).unwrap());
            assert_eq!(reuse.capacity(), capacity);
        }
        decoder.finish().unwrap();
        let mut bad = wire;
        bad.extend_from_slice(&[3, 9, 0, 0, 0, 0, 0, 0]);
        assert!(decoder.feed_into(&bad, &mut reuse).is_err());
        assert!(reuse.is_empty());
        assert_eq!(decoder.feed_into(&[], &mut reuse), Err(Error::Poisoned));
    }

    #[test]
    fn feeding_empty_input_is_a_noop() {
        // Current documented contract: feed(&[]) succeeds and yields no
        // frames, including after successful/failed history.
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&[]).unwrap().is_empty());
        assert_eq!(d.feed(&wire(3, &[])).unwrap().len(), 1);
        assert!(d.feed(&[]).unwrap().is_empty());
        d.finish().unwrap();
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&[3, 9, 0, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(
            d.feed(&[]),
            Err(Error::Poisoned),
            "poisoned before processing even empty input"
        );
    }

    #[test]
    fn max_body_frame_decodes_byte_at_a_time_and_prng() {
        let stream = wire(2, &vec![0x5A; MAX_BODY_LEN as usize]);
        let mut d = FrameDecoder::new(1024 * 1024);
        let mut got = Vec::new();
        for byte in &stream {
            got.extend(d.feed(&[*byte]).unwrap());
        }
        d.finish().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body.len(), MAX_BODY_LEN as usize);
        let mut d = FrameDecoder::new(1024 * 1024);
        let got = feed_prng_chunks(&mut d, &stream, 42).unwrap();
        assert_eq!(got[0].body.len(), MAX_BODY_LEN as usize);
    }

    #[test]
    fn first_byte_proto_major_all_byte_values() {
        // SS6.2: proto_major == 3 only; every other value is BadVersion(v).
        for v in 0u16..=255 {
            let v = v as u8;
            let mut h = hdr(2, 0);
            h[0] = v;
            if v == PROTO_MAJOR {
                assert!(
                    AppHeader::parse(&h).is_ok(),
                    "first byte {v:#04x} must be accepted"
                );
            } else {
                assert_eq!(
                    AppHeader::parse(&h),
                    Err(Error::BadVersion(v)),
                    "first byte {v:#04x}"
                );
            }
        }
    }

    #[test]
    fn kind_byte_classifies_all_256() {
        for v in 0u16..=255 {
            let v = v as u8;
            match v {
                1 => assert_eq!(Kind::try_from(v), Ok(Kind::Control)),
                2 => assert_eq!(Kind::try_from(v), Ok(Kind::HopIpBatch)),
                3 => assert_eq!(Kind::try_from(v), Ok(Kind::RelayCircuit)),
                _ => assert_eq!(
                    Kind::try_from(v),
                    Err(Error::UnknownKind(v)),
                    "kind byte {v:#04x}"
                ),
            }
        }
        // Old v1.10 leftover byte 0x22 must be rejected like any unknown
        // kind (SS6.2: the 0x22 collision path is deleted, never guessed).
        assert_eq!(Kind::try_from(0x22), Err(Error::UnknownKind(0x22)));
    }

    #[test]
    fn control_subtype_classifies_all_256() {
        // Candidate registry including the mesh extensions: 16 subtypes. Reserved
        // ranges 0x00, 0x0B..=0x0F and 0x16..=0xFF -> UnknownControl(v).
        for (v, expected) in [
            (1u8, Ok(ControlType::SessionHello)),
            (2, Ok(ControlType::SessionAccept)),
            (3, Ok(ControlType::Enrollment)),
            (4, Ok(ControlType::DirectoryPage)),
            (5, Ok(ControlType::Lease)),
            (6, Ok(ControlType::Lsa)),
            (7, Ok(ControlType::Grant)),
            (8, Ok(ControlType::Revoke)),
            (9, Ok(ControlType::Probe)),
            (10, Ok(ControlType::Drain)),
            (16, Ok(ControlType::CircuitOpen)),
            (17, Ok(ControlType::CircuitAccept)),
            (18, Ok(ControlType::CircuitReset)),
            (19, Ok(ControlType::CircuitClose)),
            (20, Ok(ControlType::IdentityRevocation)),
            (21, Ok(ControlType::MeshPath)),
        ] {
            assert_eq!(ControlType::try_from(v), expected);
        }
        for v in 0u16..=255 {
            let v = v as u8;
            if matches!(v, 1..=10 | 16..=21) {
                continue;
            }
            assert_eq!(
                ControlType::try_from(v),
                Err(Error::UnknownControl(v)),
                "control byte {v:#04x} must reject deterministically"
            );
        }
        // Discrimination: 0x0B and 0x16 are the first reserved bytes after
        // the two allocated runs; 0x00 is never allocated.
        assert_eq!(
            ControlType::try_from(0x0B),
            Err(Error::UnknownControl(0x0B))
        );
        assert_eq!(
            ControlType::try_from(0x16),
            Err(Error::UnknownControl(0x16))
        );
        assert_eq!(
            ControlType::try_from(0x00),
            Err(Error::UnknownControl(0x00))
        );
    }

    #[test]
    fn flags_every_single_bit_and_all_bits_rejected() {
        // SS6.2 "undefined flag bits must reject" + zero allocated flags:
        // every nonzero u16 is bad. The 16 single-bit patterns are pinned
        // individually so a future ALLOWED_FLAGS change cannot pass
        // silently; ALLOWED_FLAGS == 0 itself is pinned below.
        assert_eq!(
            ALLOWED_FLAGS, 0,
            "no flags allocated in candidate v0.1; a change here must update plan SS6.2/registry first"
        );
        for bit in 0..16u32 {
            let flags = 1u16 << bit;
            let mut h = hdr(2, 0);
            h[2..4].copy_from_slice(&flags.to_be_bytes());
            assert_eq!(
                AppHeader::parse(&h),
                Err(Error::BadFlags(flags)),
                "flags bit {bit}"
            );
            assert_eq!(
                (AppHeader {
                    proto_major: PROTO_MAJOR,
                    kind: Kind::HopIpBatch,
                    flags,
                    body_len: 0
                })
                .encode(),
                Err(Error::BadFlags(flags)),
                "encode must reject flags bit {bit} too"
            );
        }
        let mut h = hdr(2, 0);
        h[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(AppHeader::parse(&h), Err(Error::BadFlags(0xFFFF)));
        assert!(AppHeader::parse(&hdr(2, 0)).is_ok(), "flags == 0 accepted");
    }

    #[test]
    fn body_len_zero_max_and_over_max_per_kind() {
        // body_len == 0
        assert_eq!(
            AppHeader::parse(&hdr(1, 0)),
            Err(Error::EmptyControl),
            "Control/0: first body byte selects subtype, empty is illegal"
        );
        assert!(
            AppHeader::parse(&hdr(2, 0)).is_ok(),
            "HopIpBatch/0 accepted at header level"
        );
        assert!(
            AppHeader::parse(&hdr(3, 0)).is_ok(),
            "RelayCircuit/0 matches relay-zero-body vector"
        );
        // body_len == MAX_BODY_LEN (65536)
        assert!(
            AppHeader::parse(&hdr(1, MAX_BODY_LEN)).is_ok(),
            "Control/max ok at header level; per-subtype caps apply in policy"
        );
        assert!(AppHeader::parse(&hdr(2, MAX_BODY_LEN)).is_ok());
        assert!(AppHeader::parse(&hdr(3, MAX_BODY_LEN)).is_ok());
        assert_eq!(MAX_BODY_LEN, 65_536, "SS6.2 freezes body_len at 0..=65536");
        // body_len == MAX + 1, and the u32 extremes
        for kind in [1u8, 2, 3] {
            assert_eq!(
                AppHeader::parse(&hdr(kind, MAX_BODY_LEN + 1)),
                Err(Error::BodyTooLarge(MAX_BODY_LEN + 1))
            );
            assert_eq!(
                AppHeader::parse(&hdr(kind, u32::MAX)),
                Err(Error::BodyTooLarge(u32::MAX))
            );
        }
        // Encode mirrors parse at the same bounds.
        assert_eq!(
            (AppHeader {
                proto_major: 3,
                kind: Kind::Control,
                flags: 0,
                body_len: 0
            })
            .encode(),
            Err(Error::EmptyControl)
        );
        assert_eq!(
            (AppHeader {
                proto_major: 3,
                kind: Kind::RelayCircuit,
                flags: 0,
                body_len: 65537
            })
            .encode(),
            Err(Error::BodyTooLarge(65537))
        );
        assert_eq!(
            (AppHeader {
                proto_major: 2,
                kind: Kind::Control,
                flags: 0,
                body_len: 1
            })
            .encode(),
            Err(Error::BadVersion(2))
        );
        // Round-trip at the extremes.
        for h in [hdr(2, 0), hdr(2, 65536), hdr(3, 1), hdr(1, 4096)] {
            assert_eq!(AppHeader::parse(&h).unwrap().encode().unwrap(), h);
        }
        // Big-endian layout: byte 7 is the low body_len byte, byte 4 the high one.
        let mut le = [3, 2, 0, 0, 0x10, 0, 0, 0];
        assert_eq!(
            AppHeader::parse(&le),
            Err(Error::BodyTooLarge(0x1000_0000)),
            "little-endian-written length must be a huge BE length, not accepted as 16"
        );
        le = [3, 2, 0, 0, 0, 0, 0x01, 0x00];
        assert_eq!(AppHeader::parse(&le).unwrap().body_len, 256);
    }

    #[test]
    fn truncated_header_every_prefix_then_finish_fails() {
        let full = wire(2, b"payload");
        for n in 1..HEADER_LEN {
            let mut d = FrameDecoder::new(1024);
            assert!(
                d.feed(&full[..n]).unwrap().is_empty(),
                "partial header ({n} B) must wait, not fail"
            );
            assert_eq!(d.buffered_len(), n);
            assert!(!d.is_failed(), "truncation alone does not poison yet");
            assert_eq!(
                d.finish(),
                Err(Error::Truncated),
                "finish on {n} header bytes"
            );
            assert!(d.is_failed(), "finish on truncation locks the decoder");
            assert_eq!(
                d.feed(&full),
                Err(Error::Poisoned),
                "a truncated decoder can never resync"
            );
        }
        // A partial header completed by the next feed decodes normally.
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&full[..HEADER_LEN - 1]).unwrap().is_empty());
        assert_eq!(d.feed(&full[HEADER_LEN - 1..]).unwrap().len(), 1);
        d.finish().unwrap();
    }

    #[test]
    fn truncated_body_at_every_offset_then_finish_fails() {
        let full = wire(3, &[9u8; 100]);
        for n in HEADER_LEN..full.len() {
            let mut d = FrameDecoder::new(1024);
            assert!(
                d.feed(&full[..n]).unwrap().is_empty(),
                "{n} of {} bytes: frame not yet complete",
                full.len()
            );
            assert_eq!(d.finish(), Err(Error::Truncated));
        }
        let mut d = FrameDecoder::new(1024);
        let got = d.feed(&full).unwrap();
        assert_eq!(got.len(), 1);
        d.finish().unwrap();
        // Declared length greater than bytes actually fed: feeding a valid
        // *later* frame only completes the first one (documented stream
        // semantics); the merged case must stay consistent.
        let mut d = FrameDecoder::new(1024);
        let mut stream = wire(3, &[1u8; 10]);
        stream.extend_from_slice(&wire(2, &[]));
        let first_pass = d.feed(&stream[..15]).unwrap(); // 8 hdr + 7 body
        assert!(first_pass.is_empty());
        let rest = d.feed(&stream[15..]).unwrap();
        assert_eq!(
            rest.len(),
            2,
            "later bytes complete frame 1, then frame 2 decodes"
        );
        d.finish().unwrap();
    }

    #[test]
    fn finish_is_idempotent_on_clean_boundary() {
        // Succinct contract: finish() on empty buffer is Ok and repeatable;
        // the decoder remains usable (finish is EOF-check, not shutdown).
        let mut d = FrameDecoder::new(1024);
        assert_eq!(d.finish(), Ok(()));
        assert_eq!(d.finish(), Ok(()));
        assert_eq!(d.feed(&wire(3, &[])).unwrap().len(), 1);
        assert_eq!(d.finish(), Ok(()));
        assert!(!d.is_failed());
        // A failed decoder answers Poisoned from finish() as well.
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&[3, 9, 0, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(d.finish(), Err(Error::Poisoned));
    }

    #[test]
    fn chunked_feed_preserves_quota_and_header_error_order() {
        let first = wire(3, b"1234");
        let mut stream = first.clone();
        stream.extend_from_slice(&wire(3, b"5678"));
        let mut exact = FrameDecoder::new(stream.len());
        assert_eq!(exact.feed(&stream).unwrap().len(), 2);
        assert_eq!(exact.finish(), Ok(()));
        let mut short = FrameDecoder::new(stream.len() - 1);
        assert_eq!(short.feed(&stream), Err(Error::BufferLimit));
        assert_eq!(short.buffered_len(), 0);
        assert_eq!(short.feed(&first), Err(Error::Poisoned));

        let mut invalid = first.clone();
        invalid.extend_from_slice(&[0; HEADER_LEN]);
        invalid.extend_from_slice(&[0; 128]);
        let mut header_fits = FrameDecoder::new(first.len() + HEADER_LEN);
        assert_eq!(header_fits.feed(&invalid), Err(Error::BadVersion(0)));
        let mut header_does_not_fit = FrameDecoder::new(first.len() + HEADER_LEN - 1);
        assert_eq!(header_does_not_fit.feed(&invalid), Err(Error::BufferLimit));

        for split in 0..=stream.len() {
            let mut decoder = FrameDecoder::new(stream.len());
            let mut frames = decoder.feed(&stream[..split]).unwrap();
            frames.extend(decoder.feed(&stream[split..]).unwrap());
            assert_eq!(frames.len(), 2, "split at {split}");
            assert_eq!(frames[0].body, b"1234");
            assert_eq!(frames[1].body, b"5678");
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn split_relay_body_preserves_wire_accounting_and_tail_errors() {
        // Match the session's 8 KiB read granularity. The first read leaves
        // both a verified header and part of the relay body buffered.
        const CHUNK: usize = 8 * 1024;
        let body = (0..16_000).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let first = wire(3, &body);
        let second = wire(3, b"next");
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let mut exact = FrameDecoder::new(stream.len());
        assert!(exact.feed(&stream[..CHUNK]).unwrap().is_empty());
        assert_eq!(exact.buffered_len(), CHUNK);
        assert!(exact.feed(&[]).unwrap().is_empty());
        assert_eq!(exact.buffered_len(), CHUNK);
        // A short second read grows the accumulator without finishing the
        // frame. The final read must transfer that allocation unchanged.
        let split = CHUNK + 32;
        assert!(exact.feed(&stream[CHUNK..split]).unwrap().is_empty());
        assert_eq!(exact.buffered_len(), split);
        assert!(exact.body.capacity() >= body.len());
        let allocation = exact.body.as_ptr();
        let frames = exact.feed(&stream[split..]).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].body, body);
        assert_eq!(frames[0].body.as_ptr(), allocation);
        assert_eq!(frames[1].body, b"next");
        assert_eq!(exact.buffered_len(), 0);
        assert_eq!(exact.finish(), Ok(()));

        let mut short = FrameDecoder::new(stream.len() - 1);
        assert!(short.feed(&stream[..CHUNK]).unwrap().is_empty());
        assert_eq!(short.feed(&stream[CHUNK..]), Err(Error::BufferLimit));
        assert_eq!(short.buffered_len(), 0);
        assert_eq!(short.feed(&first), Err(Error::Poisoned));

        stream.truncate(first.len());
        stream.extend_from_slice(&[0; HEADER_LEN]);
        let mut invalid = FrameDecoder::new(stream.len());
        assert!(invalid.feed(&stream[..CHUNK]).unwrap().is_empty());
        assert_eq!(invalid.feed(&stream[CHUNK..]), Err(Error::BadVersion(0)));
        assert_eq!(invalid.buffered_len(), 0);
        assert_eq!(invalid.finish(), Err(Error::Poisoned));
    }

    #[test]
    fn garbage_after_valid_frame_poisons_and_locks() {
        // One valid frame followed by garbage bytes: the decoder must never
        // resync (SS6.2 fail-closed). Note the contract: feed() returns
        // only Err in this case, so the already-parsed frame is dropped
        // with the error -- callers must treat the whole connection as dead.
        let mut stream = wire(3, b"ok!");
        stream.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // version 0
        let mut d = FrameDecoder::new(1024);
        assert_eq!(d.feed(&stream), Err(Error::BadVersion(0)));
        assert!(d.is_failed());
        assert_eq!(
            d.feed(&wire(3, &[])),
            Err(Error::Poisoned),
            "no resync after garbage"
        );
        // Split feed: valid frame is returned first, garbage fails next, and
        // every subsequent call is Poisoned (not the original error again).
        let mut d = FrameDecoder::new(1024);
        assert_eq!(d.feed(&wire(3, b"ok!")).unwrap().len(), 1);
        assert_eq!(
            d.feed(&[3, 0x22, 0, 0, 0, 0, 0, 0]),
            Err(Error::UnknownKind(0x22)),
            "legacy 0x22 byte must kill the stream, never be guessed as relay"
        );
        assert_eq!(d.feed(&wire(2, &[])), Err(Error::Poisoned));
        assert_eq!(d.finish(), Err(Error::Poisoned));
    }

    #[test]
    fn every_error_class_poisons_permanently() {
        // Each distinct failure must lock: BufferLimit, header rejects and
        // Truncated (via finish). After locking, only Poisoned comes back.
        let cases: &[(&str, Vec<u8>, usize)] = &[
            ("bad version", vec![2, 2, 0, 0, 0, 0, 0, 0], 1024),
            ("unknown kind", vec![3, 4, 0, 0, 0, 0, 0, 0], 1024),
            ("bad flags", vec![3, 2, 0, 1, 0, 0, 0, 0], 1024),
            ("oversize body", hdr(2, 65537).to_vec(), 1024 * 1024),
            ("empty control", hdr(1, 0).to_vec(), 1024),
            ("over per-feed quota", wire(2, &[0u8; 64]), 16),
        ];
        for (name, input, limit) in cases {
            let mut d = FrameDecoder::new(*limit);
            let first = d.feed(input).unwrap_err();
            assert_ne!(
                first,
                Error::Poisoned,
                "{name}: first failure is the real error"
            );
            assert!(d.is_failed(), "{name}");
            assert_eq!(d.feed(&wire(3, &[])), Err(Error::Poisoned), "{name}");
            assert_eq!(d.feed(&[]), Err(Error::Poisoned), "{name}");
            assert_eq!(d.finish(), Err(Error::Poisoned), "{name}");
            assert_eq!(d.buffered_len(), 0, "{name}: buffer is cleared on failure");
        }
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&[3]).unwrap().is_empty());
        assert_eq!(d.finish(), Err(Error::Truncated));
        assert_eq!(d.feed(&[3]), Err(Error::Poisoned));
        assert_eq!(d.finish(), Err(Error::Poisoned));
    }

    #[test]
    fn slow_oversize_header_rejected_exactly_at_byte_8() {
        // Slow-drip attack: one header byte at a time. Bytes 1..7 cannot be
        // judged yet (must not fail, must not allocate for the body); the
        // reject must land exactly when byte 8 completes the header.
        for (name, header, expected) in [
            ("huge body", hdr(2, u32::MAX), Error::BodyTooLarge(u32::MAX)),
            (
                "over-limit body",
                hdr(2, 65_537),
                Error::BodyTooLarge(65_537),
            ),
            ("unknown kind", hdr(9, 0), Error::UnknownKind(9)),
            (
                "bad version",
                [4, 2, 0, 0, 0, 0, 0, 0],
                Error::BadVersion(4),
            ),
        ] {
            let mut d = FrameDecoder::new(1 << 30);
            for (i, byte) in header.iter().enumerate() {
                let r = d.feed(&[*byte]);
                if i + 1 < HEADER_LEN {
                    assert!(
                        r.unwrap().is_empty(),
                        "{name}: byte {} must wait for a full header",
                        i + 1
                    );
                    assert_eq!(
                        d.buffered_len(),
                        i + 1,
                        "{name}: no body allocation before header validation"
                    );
                } else {
                    assert_eq!(r, Err(expected.clone()), "{name}: reject at byte 8");
                }
            }
            assert!(d.is_failed(), "{name}");
        }
        // Declared frame that fits MAX_BODY_LEN but not the per-feed quota:
        // rejected at header completion, before any body byte is accepted.
        let mut d = FrameDecoder::new(100);
        assert_eq!(
            d.feed(&hdr(3, 512)),
            Err(Error::BufferLimit),
            "declared 512 > quota 100: rejected from the header alone"
        );
        // Slow-drip *body*: header accepted, buffered bytes grow 1:1 with
        // fed bytes (no speculative body allocation observable via the API)
        // and the frame only emerges when complete.
        let stream = wire(3, &vec![0x77; 1000]);
        let mut d = FrameDecoder::new(1024 * 1024);
        for (i, byte) in stream.iter().enumerate() {
            let got = d.feed(&[*byte]).unwrap();
            if i + 1 < stream.len() {
                assert!(got.is_empty(), "body byte {} must not emit early", i + 1);
                assert_eq!(d.buffered_len(), i + 1);
            } else {
                assert_eq!(got.len(), 1);
                assert_eq!(d.buffered_len(), 0);
            }
        }
    }

    #[test]
    fn per_feed_quota_bounds_are_exact_and_fail_closed() {
        let wire3 = wire(3, &[0u8; 24]); // 32 bytes on the wire
        // limit == exact wire size: ok; limit == size-1: reject.
        assert_eq!(FrameDecoder::new(32).feed(&wire3).unwrap().len(), 1);
        let mut d = FrameDecoder::new(31);
        assert_eq!(d.feed(&wire3), Err(Error::BufferLimit));
        assert_eq!(
            d.feed(&wire3),
            Err(Error::Poisoned),
            "quota failure also poisons"
        );
        // Split feeding may not bypass the quota: buffered bytes count.
        let mut d = FrameDecoder::new(31);
        assert!(
            d.feed(&wire3[..20]).is_err(),
            "declared 32-byte frame exceeds 31-byte quota even fed in pieces"
        );
        // Emitted frames count against the same feed: 3 frames x 8 B need 24.
        let three = [wire(3, &[]), wire(3, &[]), wire(3, &[])].concat();
        assert_eq!(
            FrameDecoder::new(24).feed(&three).unwrap().len(),
            3,
            "exactly at quota: all three frames"
        );
        let mut d = FrameDecoder::new(23);
        assert_eq!(
            d.feed(&three),
            Err(Error::BufferLimit),
            "one byte under: whole feed rejected (frames already parsed are dropped)"
        );
        assert!(d.is_failed());
        // A completed frame returned by an earlier feed no longer counts:
        // same total split across feeds under the same limit succeeds.
        let mut d = FrameDecoder::new(16);
        assert_eq!(d.feed(&wire(3, &[])).unwrap().len(), 1);
        assert_eq!(d.feed(&wire(3, &[])).unwrap().len(), 1);
        assert_eq!(
            d.feed(&[wire(3, &[]), wire(3, &[])].concat())
                .unwrap()
                .len(),
            2
        );
        // Degenerate limits: 0 rejects any byte; 7 cannot hold a header.
        let mut d = FrameDecoder::new(0);
        assert!(
            d.feed(&[]).unwrap().is_empty(),
            "empty feed under zero quota is still a no-op"
        );
        let mut d = FrameDecoder::new(0);
        assert_eq!(d.feed(&[3]), Err(Error::BufferLimit));
        let mut d = FrameDecoder::new(HEADER_LEN - 1);
        assert_eq!(
            d.feed(&wire(3, &[])),
            Err(Error::BufferLimit),
            "quota below header size can never accept a frame"
        );
        // Accounting ceiling, not bytes seen: an incomplete frame buffered
        // from a previous feed plus this feed's bytes still must fit.
        let mut d = FrameDecoder::new(20);
        assert!(
            d.feed(&wire3[..20]).is_err(),
            "quota is checked against the declared frame size up front"
        );
    }

    // ------------------------------------------------------------------
    // G-FRAME / SS5.3 deterministic-CBOR adversarial coverage.
    // ------------------------------------------------------------------

    /// Shorthand: assert rejection with exactly this error category.
    fn invalid_cbor(data: &[u8], depth: usize, len: usize, why: &'static str) {
        assert_eq!(
            validate_deterministic_cbor(data, depth, len),
            Err(Error::InvalidCbor(why)),
            "input {data:02x?}"
        );
    }

    #[test]
    fn cbor_shortest_integer_boundaries_all_widths() {
        // Value boundaries across the 5 additional-info widths: the last
        // value of each width in the *next* width is non-shortest.
        // Unsigned (major 0). Inline 23 ok / 23 in 1-byte form rejects.
        validate_deterministic_cbor(&[23], 8, 64).unwrap();
        invalid_cbor(&[0x18, 23], 8, 64, "non_shortest");
        // 24 ok with ai=24; 255 ok; 255 in 2-byte form rejects.
        validate_deterministic_cbor(&[0x18, 24], 8, 64).unwrap();
        validate_deterministic_cbor(&[0x18, 255], 8, 64).unwrap();
        invalid_cbor(&[0x19, 0x00, 0xFF], 8, 64, "non_shortest");
        invalid_cbor(&[0x19, 0x00, 0x18], 8, 64, "non_shortest");
        // 256 / 65535 ok; 65535 in 4-byte form rejects.
        validate_deterministic_cbor(&[0x19, 0x01, 0x00], 8, 64).unwrap();
        validate_deterministic_cbor(&[0x19, 0xFF, 0xFF], 8, 64).unwrap();
        invalid_cbor(&[0x1A, 0, 0, 0xFF, 0xFF], 8, 64, "non_shortest");
        // 65536 / u32::MAX ok; u32::MAX in 8-byte form rejects.
        validate_deterministic_cbor(&[0x1A, 0, 1, 0, 0], 8, 64).unwrap();
        validate_deterministic_cbor(&[0x1A, 0xFF, 0xFF, 0xFF, 0xFF], 8, 64).unwrap();
        invalid_cbor(
            &[0x1B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF],
            8,
            64,
            "non_shortest",
        );
        validate_deterministic_cbor(&[0x1B, 0, 0, 0, 1, 0, 0, 0, 0], 8, 64).unwrap();
        // u64::MAX via unsigned; -1-2^64 window via negative major.
        validate_deterministic_cbor(
            &[0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            8,
            64,
        )
        .unwrap();
        validate_deterministic_cbor(&[0x20], 8, 64).unwrap(); // -1
        validate_deterministic_cbor(&[0x37], 8, 64).unwrap(); // -24
        invalid_cbor(&[0x38, 23], 8, 64, "non_shortest");
        validate_deterministic_cbor(&[0x38, 24], 8, 64).unwrap(); // -25
        invalid_cbor(&[0x39, 0x00, 0xFF], 8, 64, "non_shortest");
        validate_deterministic_cbor(
            &[0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            8,
            64,
        )
        .unwrap();
        // Non-shortest *length* heads (string/array/map counts) also reject.
        invalid_cbor(&[0x58, 0x03, 0, 0, 0], 8, 64, "non_shortest"); // bstr len 3
        invalid_cbor(&[0x98, 0x02, 0, 0], 8, 64, "non_shortest"); // array of 2
        invalid_cbor(&[0x99, 0x00, 0x01, 0], 8, 64, "non_shortest"); // array of 1, 2-byte len
        invalid_cbor(&[0x7A, 0, 0, 0, 1, 0x61], 8, 64, "non_shortest"); // text len 1, 4-byte len
    }

    #[test]
    fn cbor_reserved_and_indefinite_and_unsupported_majors() {
        // ai 28/29/30 reserved on every supported major type.
        for (head, _) in [
            (0x1Cu8, "uint"),
            (0x3C, "nint"),
            (0x5C, "bstr"),
            (0x7C, "tstr"),
            (0x9C, "array"),
            (0xBC, "map"),
        ] {
            invalid_cbor(&[head], 8, 64, "unsupported_reserved");
            invalid_cbor(&[head + 1], 8, 64, "unsupported_reserved");
            invalid_cbor(&[head + 2], 8, 64, "unsupported_reserved");
        }
        // ai 31 indefinite length on every major where CBOR allows it.
        for head in [0x5Fu8, 0x7F, 0x9F, 0xBF] {
            invalid_cbor(&[head, 0xFF], 8, 64, "unsupported_indefinite");
        }
        // Indefinite byte string with chunks, tag wrapping a valid item,
        // simple/float values, break as item: all outside the subset.
        invalid_cbor(&[0x5F, 0x42, 1, 2, 0xFF], 8, 64, "unsupported_indefinite");
        invalid_cbor(&[0xC1, 0x00], 8, 64, "unsupported_float_simple_tag"); // tag(1)
        invalid_cbor(&[0xD8, 0x20, 0x00], 8, 64, "unsupported_float_simple_tag"); // tag(32)
        invalid_cbor(&[0xF4], 8, 64, "unsupported_float_simple_tag"); // false
        invalid_cbor(&[0xF5], 8, 64, "unsupported_float_simple_tag"); // true
        invalid_cbor(&[0xF6], 8, 64, "unsupported_float_simple_tag"); // null
        invalid_cbor(&[0xF7], 8, 64, "unsupported_float_simple_tag"); // undefined
        invalid_cbor(&[0xF9, 0x3C, 0x00], 8, 64, "unsupported_float_simple_tag"); // f16 1.0
        invalid_cbor(
            &[0xFA, 0x3F, 0x80, 0, 0],
            8,
            64,
            "unsupported_float_simple_tag",
        ); // f32 1.0
        invalid_cbor(
            &[0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0],
            8,
            64,
            "unsupported_float_simple_tag",
        ); // f64 1.0
        invalid_cbor(&[0xFF], 8, 64, "unsupported_float_simple_tag"); // break
        // Unsupported item nested inside an array must also reject.
        invalid_cbor(&[0x82, 0x00, 0xF6], 8, 64, "unsupported_float_simple_tag");
    }

    #[test]
    fn cbor_map_key_order_canonical_length_then_lex() {
        // Deterministic ordering: encoded-key *length* first, then bytes
        // -- NOT numeric value order. Keys: 1 (01), 24 (1818) is ordered.
        validate_deterministic_cbor(&[0xA2, 0x01, 0x00, 0x18, 0x18, 0x00], 8, 64).unwrap();
        // Same pair reversed rejects even though values are "sorted" numerically.
        invalid_cbor(
            &[0xA2, 0x18, 0x18, 0x00, 0x01, 0x00],
            8,
            64,
            "duplicate_or_key_order",
        );
        // Cross-type: 10 (0A, 1 B) < -1 (20, 1 B) < "" (60, 1 B) < h'' (40? no--bytes) .
        // Encoded order by (len, bytes): 0A < 20 < 40 < 60; use 0A,20,40,60.
        validate_deterministic_cbor(&[0xA4, 0x0A, 0, 0x20, 0, 0x40, 0, 0x60, 0], 8, 64).unwrap();
        // Swapping two keys in the middle rejects.
        invalid_cbor(
            &[0xA4, 0x0A, 0, 0x40, 0, 0x20, 0, 0x60, 0],
            8,
            64,
            "duplicate_or_key_order",
        );
        // Duplicates: same key twice with different values; same key/value.
        invalid_cbor(
            &[0xA2, 0x01, 0x00, 0x01, 0x01],
            8,
            64,
            "duplicate_or_key_order",
        );
        invalid_cbor(
            &[0xA2, 0x61, b'a', 0x00, 0x61, b'a', 0x00],
            8,
            64,
            "duplicate_or_key_order",
        );
        // Non-adjacent duplicate (third key repeats the first).
        invalid_cbor(
            &[0xA3, 0x01, 0, 0x02, 0, 0x01, 0],
            8,
            64,
            "duplicate_or_key_order",
        );
        // A map as a key and an array as a key are still ordered by encoding:
        // 81 00 ([0]) vs A0 ({}): lengths 2 vs 1, so {} sorts first.
        validate_deterministic_cbor(&[0xA2, 0xA0, 0, 0x81, 0x00, 0], 8, 64).unwrap();
        invalid_cbor(
            &[0xA2, 0x81, 0x00, 0, 0xA0, 0],
            8,
            64,
            "duplicate_or_key_order",
        );
        // Empty map and single-entry map of any key type pass trivially.
        validate_deterministic_cbor(&[0xA0], 8, 64).unwrap();
        validate_deterministic_cbor(&[0xA1, 0x81, 0x01, 0x00], 8, 64).unwrap();
        // Non-canonical *key encoding* rejects even with correct intended order.
        invalid_cbor(&[0xA1, 0x18, 0x01, 0x00], 8, 64, "non_shortest");
    }

    /// Encoded `[[[...[0]...]]]` with `wraps` array-of-1 wrappers.
    fn nest(wraps: usize) -> Vec<u8> {
        let mut v = vec![0x81; wraps];
        v.push(0);
        v
    }

    #[test]
    fn cbor_depth_exact_boundary_and_hard_cap() {
        // item(depth) rejects when depth > max_depth; root is depth 0 and
        // each array wrapper adds 1, so max_depth N accepts exactly N wraps.
        validate_deterministic_cbor(&nest(0), 0, 64).unwrap();
        invalid_cbor(&nest(1), 0, 64, "depth_limit");
        validate_deterministic_cbor(&nest(8), 8, 4096).unwrap();
        invalid_cbor(&nest(9), 8, 4096, "depth_limit");
        validate_deterministic_cbor(&nest(32), MAX_CBOR_DEPTH, 4096).unwrap();
        invalid_cbor(&nest(33), MAX_CBOR_DEPTH, 4096, "depth_limit");
        // Maps count both key and value one level deeper.
        validate_deterministic_cbor(&[0xA1, 0x00, 0x81, 0x00], 2, 64).unwrap();
        invalid_cbor(&[0xA1, 0x00, 0x81, 0x00], 1, 64, "depth_limit");
        // A scalar at the boundary is fine; one more wrapper is not,
        // regardless of how large max_len is.
        invalid_cbor(&nest(200), MAX_CBOR_DEPTH, usize::MAX, "depth_limit");
        // max_depth above the hard cap rejects up front (fail-closed),
        // even when the input itself is tiny and valid.
        assert_eq!(MAX_CBOR_DEPTH, 32, "SS5.3/hard cap candidate value");
        invalid_cbor(&[0], MAX_CBOR_DEPTH + 1, 64, "depth limit exceeds hard cap");
        invalid_cbor(&[0], usize::MAX, 64, "depth limit exceeds hard cap");
        // Depth counting is per nesting, not per sibling: 100 sibling
        // scalars in one array stay within depth 2.
        let mut wide = vec![0x98, 100];
        wide.extend(std::iter::repeat_n(0u8, 100));
        validate_deterministic_cbor(&wide, 2, 4096).unwrap();
    }

    #[test]
    fn cbor_truncation_trailing_and_length_limits() {
        // Every proper prefix of a compound item must reject (truncation
        // or a length complaint), never panic or accept.
        let full = [0xA2, 0x01, 0x82, 0x02, 0x03, 0x61, b'a', 0x44, 1, 2, 3, 4];
        validate_deterministic_cbor(&full, 8, 64).unwrap();
        for n in 0..full.len() {
            assert!(
                validate_deterministic_cbor(&full[..n], 8, 64).is_err(),
                "prefix of {n} bytes must reject"
            );
        }
        // Trailing garbage after one complete item: exact category from the
        // frozen candidate vector set (trailing_bytes).
        invalid_cbor(&[0x00, 0x00], 8, 64, "trailing_bytes");
        invalid_cbor(&[0x80, 0x00], 8, 64, "trailing_bytes");
        invalid_cbor(&[0x41, 0xAA, 0x00], 8, 64, "trailing_bytes");
        // Empty input is truncated, not "vacuously one item".
        invalid_cbor(&[], 8, 64, "truncated");
        // max_len: exact fit ok, one byte over rejects with length_limit.
        validate_deterministic_cbor(&[0x00], 8, 1).unwrap();
        invalid_cbor(&[0x41, 0x00], 8, 1, "length_limit");
        invalid_cbor(&full, 8, full.len() - 1, "length_limit");
        validate_deterministic_cbor(&full, 8, full.len()).unwrap();
        // max_len == 0 rejects even a single byte.
        invalid_cbor(&[0x00], 8, 0, "length_limit");
        // Declared string length far beyond input rejects without allocation
        // from the counter (truncated), for both byte and text strings.
        invalid_cbor(
            &[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            8,
            4096,
            "length overflow",
        );
        invalid_cbor(&[0x7A, 0x7F, 0xFF, 0xFF, 0xFF, 0x61], 8, 4096, "truncated");
        // Declared array/map counts beyond input run out of items, fast.
        invalid_cbor(
            &[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            8,
            4096,
            "truncated",
        );
        invalid_cbor(
            &[
                0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
            ],
            8,
            4096,
            "truncated",
        );
        // Map key present, value missing.
        invalid_cbor(&[0xA1, 0x01], 8, 64, "truncated");
    }

    #[test]
    fn cbor_text_utf8_strictness() {
        validate_deterministic_cbor(&[0x60], 8, 64).unwrap(); // ""
        validate_deterministic_cbor(&[0x62, 0xC3, 0xA9], 8, 64).unwrap(); // "e-acute" (2-byte)
        validate_deterministic_cbor(&[0x63, 0xE2, 0x82, 0xAC], 8, 64).unwrap(); // euro sign (3-byte)
        validate_deterministic_cbor(&[0x64, 0xF0, 0x9F, 0x98, 0x80], 8, 64).unwrap(); // emoji (4-byte)
        // Invalid: lone continuation, overlong forms, surrogate, truncated seq.
        invalid_cbor(&[0x61, 0x80], 8, 64, "invalid_utf8");
        invalid_cbor(&[0x62, 0xC0, 0x80], 8, 64, "invalid_utf8"); // overlong NUL
        invalid_cbor(&[0x62, 0xC1, 0xBF], 8, 64, "invalid_utf8"); // overlong
        invalid_cbor(&[0x63, 0xED, 0xA0, 0x80], 8, 64, "invalid_utf8"); // U+D800 surrogate
        invalid_cbor(&[0x62, 0xE2, 0x82], 8, 64, "invalid_utf8"); // seq cut by declared end
        invalid_cbor(&[0x61, 0xFF], 8, 64, "invalid_utf8");
        // The same bytes in a *byte* string are fine: major 2 is opaque.
        validate_deterministic_cbor(&[0x42, 0xFF, 0x80], 8, 64).unwrap();
        validate_deterministic_cbor(&[0x40], 8, 64).unwrap(); // h''
        // Invalid UTF-8 as a map key rejects too.
        invalid_cbor(&[0xA1, 0x61, 0xFF, 0x00], 8, 64, "invalid_utf8");
    }

    /// Every byte value 0x00..=0xFF as a frame's first wire byte: the only
    /// one that can start a valid frame is PROTO_MAJOR (0x03); the others
    /// must fail deterministically as BadVersion once a full header lands.
    #[test]
    fn decoder_first_byte_exhaustive_over_256() {
        for v in 0u16..=255 {
            let v = v as u8;
            let mut start = [v, 2, 0, 0, 0, 0, 0, 0]; // zero-length HopIpBatch shape
            let mut d = FrameDecoder::new(1024);
            let r = d.feed(&start);
            if v == PROTO_MAJOR {
                assert_eq!(
                    r.unwrap().len(),
                    1,
                    "proto_major={v:#04x} completes the frame"
                );
                d.finish().unwrap();
            } else {
                assert_eq!(
                    r,
                    Err(Error::BadVersion(v)),
                    "first byte {v:#04x} must never be accepted or panic"
                );
                assert!(d.is_failed());
            }
            // Feeding the first byte alone must never panic or emit a frame.
            let mut d = FrameDecoder::new(1024);
            start = [v, 0, 0, 0, 0, 0, 0, 0];
            assert!(
                d.feed(&start[..1]).unwrap().is_empty(),
                "single first byte {v:#04x}"
            );
        }
    }

    #[test]
    fn kind_byte_exhaustive_through_decoder() {
        // Byte 1 sweep through the *decoder*: 1/2/3 accept (with the right
        // zero-body rule), everything else fails as UnknownKind, no panic.
        for v in 0u16..=255 {
            let v = v as u8;
            let mut d = FrameDecoder::new(1024);
            let r = d.feed(&hdr(v, 0));
            match v {
                1 => assert_eq!(r, Err(Error::EmptyControl), "Control with body 0"),
                2 | 3 => assert_eq!(r.unwrap().len(), 1, "valid kinds emit"),
                _ => assert_eq!(r, Err(Error::UnknownKind(v))),
            }
        }
    }

    #[test]
    fn declared_vs_actual_and_merged_boundary_cases() {
        // Two complete frames merged in one feed, then finish: fine.
        let mut d = FrameDecoder::new(1024);
        let merged = [wire(2, b"a"), wire(3, b"bc")].concat();
        assert_eq!(d.feed(&merged).unwrap().len(), 2);
        d.finish().unwrap();
        // A feed that ends exactly on a frame boundary, next feed starts
        // the next frame's header: fine (no off-by-one in state).
        let mut d = FrameDecoder::new(1024);
        let w1 = wire(3, &[1, 2, 3]);
        assert_eq!(d.feed(&w1).unwrap().len(), 1);
        let w2 = wire(3, &[4]);
        assert!(
            d.feed(&w2[..HEADER_LEN]).unwrap().is_empty(),
            "bare header of frame 2 emits nothing"
        );
        assert_eq!(d.feed(&w2[HEADER_LEN..]).unwrap().len(), 1);
        d.finish().unwrap();
        // Declared Control length 1 with an unregistered subtype byte: the
        // *decoder* accepts (subtype registry is policy, not framing) --
        // pin that split of duties so nobody hides policy in the decoder.
        let mut d = FrameDecoder::new(1024);
        let got = d.feed(&control_wire(0x0B, 1)).unwrap();
        assert_eq!(
            got.len(),
            1,
            "framing accepts; validate_frame_policy rejects (tested below)"
        );
    }

    // ------------------------------------------------------------------
    // Session state machine (SS5.2 + SS5.4 registry). Only rules that are
    // explicit in the plan/registry are asserted; direction, duplicate
    // Hello-after-accept semantics beyond the current code, etc. are
    // noted in the report as pending freeze rather than invented here.
    // ------------------------------------------------------------------

    #[test]
    fn policy_happy_path_hello_accept_then_registered_traffic() {
        let mut ctx = test_ctx();
        validate_frame_policy(&frame(Kind::Control, control_body(1, 4)), &mut ctx).unwrap();
        assert!(ctx.hello_received && !ctx.accepted);
        validate_frame_policy(&frame(Kind::Control, control_body(2, 4)), &mut ctx).unwrap();
        assert!(ctx.accepted);
        // Accepted-session subtypes from the registry table.
        for subtype in [4u8, 7, 8, 9, 10] {
            validate_frame_policy(&frame(Kind::Control, control_body(subtype, 4)), &mut ctx)
                .unwrap();
        }
        // Lease additionally needs a registered identity.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(5, 4)), &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.identity_registered = true;
        validate_frame_policy(&frame(Kind::Control, control_body(5, 4)), &mut ctx).unwrap();
        // Lsa needs an accepted Core peer (Core-Core only): Edge rejects.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(6, 4)), &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.peer_role = PeerRole::Core;
        validate_frame_policy(&frame(Kind::Control, control_body(6, 4)), &mut ctx).unwrap();
    }

    #[test]
    fn policy_order_violations_before_hello_and_before_accept() {
        // SessionAccept before any SessionHello.
        let mut ctx = test_ctx();
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(2, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert!(!ctx.accepted, "rejected Accept must not mutate state");
        // Every established-session subtype and both data kinds reject
        // before acceptance.
        for subtype in [4u8, 5, 6, 7, 8, 9, 10, 16] {
            assert_eq!(
                validate_frame_policy(&frame(Kind::Control, control_body(subtype, 1)), &mut ctx),
                Err(Error::IllegalState),
                "subtype {subtype:#04x} before Hello"
            );
        }
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState),
            "relay before accept"
        );
        let mut hop = test_ctx();
        hop.mode = SecurityMode::HopOnly;
        assert_eq!(
            validate_frame_policy(&frame(Kind::HopIpBatch, vec![0]), &mut hop),
            Err(Error::IllegalState),
            "hop data before accept"
        );
        // After Hello but before Accept, data still rejects.
        let mut ctx = test_ctx();
        validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx).unwrap();
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(9, 1)), &mut ctx),
            Err(Error::IllegalState),
            "Probe between Hello and Accept"
        );
        // Duplicate SessionHello before acceptance: current explicit rule
        // requires !hello_received, so it rejects and state is untouched.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert!(ctx.hello_received && !ctx.accepted);
        // SessionAccept may only be consumed once.
        validate_frame_policy(&frame(Kind::Control, control_body(2, 1)), &mut ctx).unwrap();
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(2, 1)), &mut ctx),
            Err(Error::IllegalState),
            "second Accept"
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx),
            Err(Error::IllegalState),
            "Hello after accept"
        );
        // Permissive contexts (every flag pre-set) still reject Hello/Accept.
        let mut ctx = test_ctx();
        ctx.accepted = true;
        ctx.hello_received = true;
        ctx.identity_registered = true;
        ctx.peer_role = PeerRole::Core;
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(2, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn policy_enrollment_only_on_enrollment_context() {
        // SS5.2: registration-incomplete connections may only use
        // Enrollment, on an enrollment-service connection. The code
        // requires BOTH markers; each one alone must reject.
        let mut ctx = test_ctx(); // neither marker
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(3, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        let mut ctx = test_ctx();
        ctx.enrollment_service = true; // peer role still Edge
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(3, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        let mut ctx = test_ctx();
        ctx.peer_role = PeerRole::EnrollmentService; // connection marker unset
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(3, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        let mut ctx = test_ctx();
        ctx.enrollment_service = true;
        ctx.peer_role = PeerRole::EnrollmentService;
        validate_frame_policy(&frame(Kind::Control, control_body(3, 1)), &mut ctx).unwrap();
        // On that context, session/data frames are NOT substitutes:
        // Hello/Accept are excluded by !enrollment_service, data by !accepted.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx),
            Err(Error::IllegalState),
            "Hello on enrollment connection"
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState),
            "no IP forwarding before registration completes (SS5.2)"
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(4, 1)), &mut ctx),
            Err(Error::IllegalState),
            "no directory enumeration before registration completes (SS5.2)"
        );
        // Enrollment on an already-accepted session rejects.
        ctx.accepted = true;
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(3, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn policy_circuit_lifecycle_gates_relay_data() {
        let mut ctx = test_ctx();
        validate_frame_policy(&frame(Kind::Control, control_body(1, 1)), &mut ctx).unwrap();
        validate_frame_policy(&frame(Kind::Control, control_body(2, 1)), &mut ctx).unwrap();
        // Relay data with no circuit at all.
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState)
        );
        // CircuitAccept/Reset/Close with nothing opening or established.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(17, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(18, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(19, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut ctx).unwrap();
        assert!(ctx.circuit_opening);
        // Opening is not established: relay data must still reject, and a
        // second CircuitOpen must not stack openings.
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut ctx),
            Err(Error::IllegalState),
            "CircuitOpen while opening"
        );
        validate_frame_policy(&frame(Kind::Control, control_body(17, 1)), &mut ctx).unwrap();
        assert!(ctx.circuit_established && !ctx.circuit_opening);
        validate_frame_policy(&frame(Kind::RelayCircuit, vec![0, 1, 2]), &mut ctx).unwrap();
        // CircuitOpen while established rejects; duplicate Accept too.
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(17, 1)), &mut ctx),
            Err(Error::IllegalState)
        );
        validate_frame_policy(&frame(Kind::Control, control_body(19, 1)), &mut ctx).unwrap();
        assert!(!ctx.circuit_established, "Close clears established state");
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut ctx),
            Err(Error::IllegalState),
            "no relay after Close"
        );
        // Reset from the opening state clears it.
        validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut ctx).unwrap();
        validate_frame_policy(&frame(Kind::Control, control_body(18, 1)), &mut ctx).unwrap();
        assert!(!ctx.circuit_opening && !ctx.circuit_established);
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(17, 1)), &mut ctx),
            Err(Error::IllegalState),
            "Accept after Reset"
        );
        // Reset from established also clears.
        validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut ctx).unwrap();
        validate_frame_policy(&frame(Kind::Control, control_body(17, 1)), &mut ctx).unwrap();
        validate_frame_policy(&frame(Kind::Control, control_body(18, 1)), &mut ctx).unwrap();
        assert!(!ctx.circuit_established);
        // Circuit opening in hop-only mode rejects (SS5.4: e2e-required).
        let mut hop = test_ctx();
        hop.mode = SecurityMode::HopOnly;
        hop.accepted = true;
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(16, 1)), &mut hop),
            Err(Error::IllegalState)
        );
        // Relay data in hop-only mode rejects even with everything else set.
        let mut hop = test_ctx();
        hop.mode = SecurityMode::HopOnly;
        hop.accepted = true;
        hop.circuit_established = true;
        assert_eq!(
            validate_frame_policy(&frame(Kind::RelayCircuit, vec![0]), &mut hop),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn policy_hop_only_and_e2e_modes_are_mutually_exclusive() {
        // SS6.2: HopIpBatch only in explicitly-selected hop-only mode;
        // e2e-required business traffic only via RelayCircuit.
        let mut e2e = test_ctx();
        e2e.accepted = true;
        assert_eq!(
            validate_frame_policy(&frame(Kind::HopIpBatch, vec![0]), &mut e2e),
            Err(Error::HopIpBatchForbidden)
        );
        assert_eq!(
            validate_frame_policy(&frame(Kind::HopIpBatch, vec![]), &mut e2e),
            Err(Error::HopIpBatchForbidden)
        );
        let mut hop = test_ctx();
        hop.mode = SecurityMode::HopOnly;
        assert_eq!(
            validate_frame_policy(&frame(Kind::HopIpBatch, vec![0]), &mut hop),
            Err(Error::IllegalState),
            "checked before mode: not accepted yet"
        );
        hop.accepted = true;
        validate_frame_policy(&frame(Kind::HopIpBatch, vec![0]), &mut hop).unwrap();
        validate_frame_policy(&frame(Kind::HopIpBatch, vec![]), &mut hop).unwrap();
        // Order pinning (current implementation detail; the plan does not
        // freeze which error wins): !accepted is checked first.
        let mut ctx = test_ctx(); // E2eRequired + not accepted
        assert_eq!(
            validate_frame_policy(&frame(Kind::HopIpBatch, vec![0]), &mut ctx),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn policy_rejects_unknown_subtypes_even_when_fully_accepted() {
        let mut ctx = test_ctx();
        ctx.hello_received = true;
        ctx.accepted = true;
        ctx.identity_registered = true;
        ctx.peer_role = PeerRole::Core;
        // Reserved bytes must reject with UnknownControl, not IllegalState:
        // they are not "a known message at the wrong time".
        for subtype in [0x00u8, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x16, 0x7F, 0x80, 0xFF] {
            assert_eq!(
                validate_frame_policy(&frame(Kind::Control, control_body(subtype, 1)), &mut ctx),
                Err(Error::UnknownControl(subtype)),
                "subtype {subtype:#04x}"
            );
        }
        // Unknown subtype also wins before any state check (try_from runs first).
        let mut fresh = test_ctx();
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(0x0B, 1)), &mut fresh),
            Err(Error::UnknownControl(0x0B))
        );
    }

    #[test]
    fn policy_control_body_caps_match_registry_table_exactly() {
        // Candidate caps including the subtype byte. The Lease row is 16 KiB,
        // not the plan's 4 KiB: a dual-signed AttachmentLease envelope cannot
        // fit 4 KiB once Ed25519 + ML-DSA signatures and the TBS are counted.
        // That deviation is a reported plan/registry conflict, not a silent
        // protocol change.
        let table = [
            (ControlType::SessionHello, 4096usize),
            (ControlType::SessionAccept, 4096),
            (ControlType::Enrollment, 16384),
            (ControlType::DirectoryPage, 16384),
            (ControlType::Lease, 16384),
            (ControlType::Lsa, 8192),
            (ControlType::Grant, 8192),
            (ControlType::Revoke, 16384),
            (ControlType::Probe, 256),
            (ControlType::Drain, 256),
            (ControlType::IdentityRevocation, 19767),
            (ControlType::MeshPath, 6),
            (ControlType::CircuitOpen, 4096),
            (ControlType::CircuitAccept, 4096),
            (ControlType::CircuitReset, 256),
            (ControlType::CircuitClose, 256),
        ];
        assert_eq!(table.len(), 16);
        for (t, cap) in table {
            assert_eq!(t.body_cap(), cap, "{t:?}");
        }
    }

    /// Context in which every subtype state gate is already satisfied, so
    /// cap-boundary assertions exercise the cap and not the state machine.
    fn permissive_ctx(subtype: u8) -> SessionContext {
        let mut ctx = test_ctx();
        match subtype {
            1 => {} // needs !hello_received && !accepted
            2 => ctx.hello_received = true,
            3 => {
                ctx.enrollment_service = true;
                ctx.peer_role = PeerRole::EnrollmentService;
            }
            4 | 7 | 8 | 9 | 10 => ctx.accepted = true,
            5 => {
                ctx.accepted = true;
                ctx.identity_registered = true;
            }
            6 | 20 | 21 => {
                ctx.accepted = true;
                ctx.peer_role = PeerRole::Core;
            }
            16 => ctx.accepted = true,
            17 | 18 => {
                ctx.accepted = true;
                ctx.circuit_opening = true;
            }
            19 => {
                ctx.accepted = true;
                ctx.circuit_established = true;
            }
            _ => unreachable!(),
        }
        ctx
    }

    #[test]
    fn identity_revocation_requires_accepted_core_control_phase() {
        let frame = frame(Kind::Control, vec![
            ControlType::IdentityRevocation as u8,
            0,
        ]);
        let mut ctx = test_ctx();
        assert_eq!(
            validate_frame_policy(&frame, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.accepted = true;
        assert_eq!(
            validate_frame_policy(&frame, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.peer_role = PeerRole::Core;
        assert_eq!(validate_frame_policy(&frame, &mut ctx), Ok(()));
        ctx.circuit_opening = true;
        assert_eq!(
            validate_frame_policy(&frame, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.circuit_opening = false;
        ctx.circuit_established = true;
        assert_eq!(
            validate_frame_policy(&frame, &mut ctx),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn mesh_path_requires_accepted_core_e2e_before_circuit() {
        let proposal = frame(Kind::Control, vec![ControlType::MeshPath as u8, 2, 1, 4]);
        let mut ctx = test_ctx();
        assert_eq!(
            validate_frame_policy(&proposal, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.accepted = true;
        assert_eq!(
            validate_frame_policy(&proposal, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.peer_role = PeerRole::Core;
        ctx.mode = SecurityMode::HopOnly;
        assert_eq!(
            validate_frame_policy(&proposal, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.mode = SecurityMode::E2eRequired;
        let before = ctx;
        assert_eq!(validate_frame_policy(&proposal, &mut ctx), Ok(()));
        assert_eq!(ctx, before); // Proposal never opens a circuit.
        ctx.circuit_opening = true;
        assert_eq!(
            validate_frame_policy(&proposal, &mut ctx),
            Err(Error::IllegalState)
        );
        ctx.circuit_opening = false;
        ctx.circuit_established = true;
        assert_eq!(
            validate_frame_policy(&proposal, &mut ctx),
            Err(Error::IllegalState)
        );
    }

    #[test]
    fn policy_control_cap_boundary_exact_and_one_over() {
        let caps: [(u8, usize); 16] = [
            (1, 4096),
            (2, 4096),
            (3, 16384),
            (4, 16384),
            (5, 16384),
            (6, 8192),
            (7, 8192),
            (8, 16384),
            (9, 256),
            (10, 256),
            (16, 4096),
            (17, 4096),
            (18, 256),
            (19, 256),
            (20, 19767),
            (21, 6),
        ];
        for (subtype, cap) in caps {
            // Minimal legal body (subtype byte only).
            let mut ctx = permissive_ctx(subtype);
            validate_frame_policy(&frame(Kind::Control, control_body(subtype, 1)), &mut ctx)
                .unwrap_or_else(|e| panic!("subtype {subtype} minimal body: {e:?}"));
            // Exactly at cap.
            let mut ctx = permissive_ctx(subtype);
            validate_frame_policy(&frame(Kind::Control, control_body(subtype, cap)), &mut ctx)
                .unwrap_or_else(|e| panic!("subtype {subtype} at cap {cap}: {e:?}"));
            // One byte over: BodyTooLarge(cap+1), and no state mutation.
            let mut ctx = permissive_ctx(subtype);
            let before = ctx;
            assert_eq!(
                validate_frame_policy(
                    &frame(Kind::Control, control_body(subtype, cap + 1)),
                    &mut ctx
                ),
                Err(Error::BodyTooLarge((cap + 1) as u32)),
                "subtype {subtype} one over cap"
            );
            assert_eq!(
                ctx, before,
                "subtype {subtype}: oversize frame must not mutate context"
            );
        }
        // Cap check precedes state check: over-cap Hello on accepted session
        // reports size, not state (current order; plan does not freeze it).
        let mut ctx = test_ctx();
        ctx.accepted = true;
        assert_eq!(
            validate_frame_policy(&frame(Kind::Control, control_body(1, 4097)), &mut ctx),
            Err(Error::BodyTooLarge(4097))
        );
    }

    #[test]
    fn policy_frame_self_consistency_rejects_doctored_frames() {
        let mut ctx = test_ctx();
        // header.body_len != actual body length.
        let mut f = frame(Kind::RelayCircuit, vec![0; 4]);
        f.header.body_len = 3;
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::InvalidFrameBody)
        );
        let mut f = frame(Kind::RelayCircuit, vec![0; 4]);
        f.header.body_len = 5;
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::InvalidFrameBody)
        );
        // Header fields are re-encoded before the length compare: version
        // and flags tampering surface as the header errors.
        let mut f = frame(Kind::RelayCircuit, vec![]);
        f.header.proto_major = 2;
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::BadVersion(2))
        );
        let mut f = frame(Kind::RelayCircuit, vec![]);
        f.header.flags = 0x8000;
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::BadFlags(0x8000))
        );
        let mut f = frame(Kind::RelayCircuit, vec![]);
        f.header.body_len = MAX_BODY_LEN + 1;
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::BodyTooLarge(MAX_BODY_LEN + 1))
        );
        // Control with body reassigned to empty behind a len=0 header.
        let f = frame(Kind::Control, vec![]);
        assert_eq!(
            validate_frame_policy(&f, &mut ctx),
            Err(Error::EmptyControl)
        );
        // A rejected frame never partially advances handshake state:
        // tampered Hello then a clean Hello must still succeed exactly once.
        let mut ctx = test_ctx();
        let mut bad = frame(Kind::Control, control_body(1, 2));
        bad.header.body_len = 7;
        assert_eq!(
            validate_frame_policy(&bad, &mut ctx),
            Err(Error::InvalidFrameBody)
        );
        validate_frame_policy(&frame(Kind::Control, control_body(1, 2)), &mut ctx).unwrap();
    }

    #[test]
    fn policy_rejections_do_not_mutate_context() {
        // Fuzz-like sweep: for a handful of contexts and every control
        // subtype byte 0..=255 + both data kinds, Err must leave ctx
        // bitwise unchanged (no half-applied transitions).
        let seeds = [
            test_ctx(),
            SessionContext {
                hello_received: true,
                ..test_ctx()
            },
            SessionContext {
                hello_received: true,
                accepted: true,
                ..test_ctx()
            },
            SessionContext {
                enrollment_service: true,
                peer_role: PeerRole::EnrollmentService,
                ..test_ctx()
            },
            SessionContext {
                accepted: true,
                circuit_opening: true,
                ..test_ctx()
            },
            SessionContext {
                accepted: true,
                circuit_established: true,
                ..test_ctx()
            },
        ];
        for seed in seeds {
            for subtype in 0u16..=255 {
                let mut ctx = seed;
                let f = frame(Kind::Control, control_body(subtype as u8, 2));
                if validate_frame_policy(&f, &mut ctx).is_err() {
                    assert_eq!(ctx, seed, "control {subtype:#04x} mutated context on error");
                }
            }
            for kind in [Kind::HopIpBatch, Kind::RelayCircuit] {
                let mut ctx = seed;
                if validate_frame_policy(&frame(kind, vec![0, 1]), &mut ctx).is_err() {
                    assert_eq!(ctx, seed, "{kind:?} mutated context on error");
                }
            }
        }
    }

    #[test]
    fn end_to_end_decoder_into_policy_happy_and_hostile_paths() {
        // Wire -> FrameDecoder -> validate_frame_policy, byte-at-a-time.
        let mut stream = Vec::new();
        stream.extend_from_slice(&control_wire(1, 8));
        stream.extend_from_slice(&control_wire(2, 8));
        stream.extend_from_slice(&control_wire(9, 2));
        stream.extend_from_slice(&control_wire(16, 4));
        stream.extend_from_slice(&control_wire(17, 4));
        stream.extend_from_slice(&wire(3, b"ciphertext-bytes"));
        let mut d = FrameDecoder::new(1024 * 1024);
        let mut frames = Vec::new();
        for byte in &stream {
            frames.extend(d.feed(&[*byte]).unwrap());
        }
        d.finish().unwrap();
        assert_eq!(frames.len(), 6);
        let mut ctx = test_ctx();
        for f in &frames {
            validate_frame_policy(f, &mut ctx).unwrap();
        }
        assert!(ctx.accepted && ctx.circuit_established);
        // Hostile: data frame first, then Hello -- policy rejects the data
        // and the same context can still complete a clean handshake.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&wire(3, b"premature"));
        hostile.extend_from_slice(&control_wire(1, 4));
        hostile.extend_from_slice(&control_wire(2, 4));
        let mut d = FrameDecoder::new(1024 * 1024);
        let frames = feed_prng_chunks(&mut d, &hostile, 7).unwrap();
        let mut ctx = test_ctx();
        assert_eq!(
            validate_frame_policy(&frames[0], &mut ctx),
            Err(Error::IllegalState)
        );
        validate_frame_policy(&frames[1], &mut ctx).unwrap();
        validate_frame_policy(&frames[2], &mut ctx).unwrap();
    }

    #[test]
    fn candidate_vector_headers_match_parser() {
        // docs/protocol/vectors/candidate-vectors-v1.json app_header set,
        // hard-coded here so the vectors and this crate cannot drift apart
        // silently (the Python verifier checks the file independently).
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let h8 = |s: &str| -> [u8; 8] { hex(s).as_slice().try_into().unwrap() };
        assert_eq!(
            AppHeader::parse(&h8("0301000000000000")),
            Err(Error::EmptyControl)
        ); // control-empty-invalid
        let ok = AppHeader::parse(&h8("0303000000000000")).unwrap(); // relay-zero-body
        assert_eq!((ok.kind, ok.flags, ok.body_len), (Kind::RelayCircuit, 0, 0));
        let ok = AppHeader::parse(&h8("0302000000010000")).unwrap(); // hop-max-body
        assert_eq!((ok.kind, ok.body_len), (Kind::HopIpBatch, 65536));
        assert_eq!(
            AppHeader::parse(&h8("0303000000010001")),
            Err(Error::BodyTooLarge(65537))
        ); // relay-over-cap
        assert_eq!(
            AppHeader::parse(&h8("0304000000000000")),
            Err(Error::UnknownKind(4))
        ); // unknown-kind
        assert_eq!(
            AppHeader::parse(&h8("0303000100000000")),
            Err(Error::BadFlags(1))
        ); // undefined-flag
        assert_eq!(
            AppHeader::parse(&h8("0203000000000000")),
            Err(Error::BadVersion(2))
        ); // wrong-major
        // header-wrong-length (7 bytes 03030000000000): through the decoder
        // this is an incomplete header -- finish() must say Truncated.
        let mut d = FrameDecoder::new(1024);
        assert!(d.feed(&hex("03030000000000")).unwrap().is_empty());
        assert_eq!(d.finish(), Err(Error::Truncated));
        // CBOR vector spot-exacts (error categories, incl. the limits block).
        validate_deterministic_cbor(&hex("a201000200"), 32, 16384).unwrap(); // ordered-map
        invalid_cbor(&hex("1801"), 32, 16384, "non_shortest");
        invalid_cbor(&hex("a201000101"), 32, 16384, "duplicate_or_key_order");
        invalid_cbor(&hex("9fff"), 32, 16384, "unsupported_indefinite");
        invalid_cbor(&hex("0000"), 32, 16384, "trailing_bytes");
        invalid_cbor(&hex("1c"), 32, 16384, "unsupported_reserved");
        invalid_cbor(&hex("8100"), 0, 16384, "depth_limit"); // limits.max_depth = 0
        invalid_cbor(&hex("4100"), 32, 1, "length_limit"); // limits.max_len = 1
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
            net_id: [0x5A; 16],
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
