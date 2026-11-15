//! Candidate bounded control-message payload codecs; not frozen and not cryptographic.
//!
//! This module owns the typed payloads carried by `AppHeader.kind = 1`
//! (`Control`) and the relay fragment carried by `kind = 3` (`RelayCircuit`).
//! It validates registration, exact lengths, field ranges, signature-envelope
//! shape and candidate caps only. It does not perform TLS, signature
//! verification, key selection, authorization or certificate parsing; callers
//! must bind every field to an already authenticated peer and to local policy.
//!
//! Every registered control subtype has a typed schema. Management-object
//! payloads carry a [`SignedObject`] envelope with the exact raw TBS bytes,
//! explicit Ed25519/ML-DSA parameter sets and both signatures (plus the
//! AttachmentLease Core co-signature), so an Edge can verify the signed bytes
//! independently. The envelope parser never re-encodes or repairs TBS bytes.

use std::fmt;

use crate::objects::{self, MldsaParameterSet, ObjectBody, ObjectType, valid_node_id};
use crate::{ControlType, MAX_BODY_LEN, PROTO_MAJOR, PeerRole, SecurityMode, SessionContext};

/// Fixed wire length of a `SessionHello`/`SessionAccept` control body,
/// including the leading subtype byte.
pub const SESSION_MESSAGE_LEN: usize = 1 + SESSION_PARAM_FIELDS_LEN;
const SESSION_PARAM_FIELDS_LEN: usize = 1 + 16 + 2 + 2 + 8 + 8 + 16 + 1 + 1 + 1 + 2 + 1 + 8;
const _: () = assert!(SESSION_MESSAGE_LEN == 68);

/// Length of the `net_id` field.
pub const NET_ID_LEN: usize = 16;
/// Length of the `connection_instance` field.
pub const CONNECTION_INSTANCE_LEN: usize = 16;
/// Fixed relay-fragment prefix before the opaque payload.
pub const RELAY_FRAGMENT_FIXED_LEN: usize = 16 + 1 + 8 + 4 + 1;
/// Largest relay payload that still fits one `AppHeader` body.
pub const MAX_RELAY_PAYLOAD: usize = MAX_BODY_LEN as usize - RELAY_FRAGMENT_FIXED_LEN;
/// Candidate maximum `hops_remaining` budget.
pub const MAX_CIRCUIT_HOPS: u8 = 8;
/// Candidate minimum MTU cap.
pub const MIN_MTU_CAP: u16 = 576;
/// Candidate maximum MTU cap.
pub const MAX_MTU_CAP: u16 = 9_000;
/// No capability bits are allocated in this candidate revision.
pub const ALLOWED_CAPABILITIES: u64 = 0;

/// Candidate maximum DER blob carried by an Enrollment payload.
pub const MAX_ENROLLMENT_DER: usize = 8 * 1024;
/// Candidate maximum number of signed objects in one DirectoryPage.
pub const MAX_DIRECTORY_OBJECTS: usize = 16;
/// Candidate maximum size of one signed-object envelope.
pub const MAX_SIGNED_OBJECT_LEN: usize = 16 * 1024;
/// Candidate signed-object envelope version.
pub const SIGNED_OBJECT_VERSION: u8 = 1;
/// Candidate management-object schema version carried in the envelope.
pub const SIGNED_OBJECT_SCHEMA_VERSION: u16 = 1;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// FIPS 204 ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// FIPS 204 ML-DSA-87 signature length.
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;
/// Candidate Enrollment request version.
pub const ENROLLMENT_VERSION: u16 = 1;
/// Candidate maximum Drain retry hint.
pub const MAX_DRAIN_RETRY_SECONDS: u16 = 3600;
/// Fixed Probe body length.
pub const PROBE_BODY_LEN: usize = 1 + 1 + 16 + 8 + 8;
/// Fixed Drain body length.
pub const DRAIN_BODY_LEN: usize = 1 + 1 + 8 + 2;
/// Fixed CircuitOpen body length (transport-compatible candidate).
pub const CIRCUIT_OPEN_BODY_LEN: usize = 1 + 16 + 2 + 8 + 1;
/// Fixed CircuitAccept body length (transport-compatible candidate).
pub const CIRCUIT_ACCEPT_BODY_LEN: usize = 1 + 16 + 1;
/// Fixed CircuitReset/CircuitClose body length (subtype + circuit id).
pub const CIRCUIT_ID_BODY_LEN: usize = 1 + 16;

/// Candidate `path_role` field values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PathRole {
    Cdn = 1,
    Dir = 2,
}

impl TryFrom<u8> for PathRole {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Cdn),
            2 => Ok(Self::Dir),
            _ => Err(MessageError::BadPathRole(value)),
        }
    }
}

/// Candidate cryptographic-suite identifier; no key length may be inferred from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Suite {
    Pq768 = 1,
    Pq1024 = 2,
}

impl TryFrom<u8> for Suite {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pq768),
            2 => Ok(Self::Pq1024),
            _ => Err(MessageError::BadSuite(value)),
        }
    }
}

/// Role of one signer in a [`SignedObject`] envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SignerRole {
    Primary = 1,
    CoSign = 2,
}

impl TryFrom<u8> for SignerRole {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Primary),
            2 => Ok(Self::CoSign),
            _ => Err(MessageError::InvalidField("signer role")),
        }
    }
}

/// Structural payload error. It never implies that a peer was authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageError {
    /// A control body had no subtype byte.
    EmptyBody,
    /// The subtype byte is not in the candidate registry.
    UnknownSubtype(u8),
    /// A fixed-length message had a different length, including trailing bytes.
    WrongLength,
    /// The subtype byte did not match the expected message type.
    BadSubtype(u8),
    /// `proto_major` was not `PROTO_MAJOR`.
    BadProtocolVersion(u8),
    /// `net_id` was all zero or did not match the local network.
    BadNetId,
    /// A `node_id` was outside the candidate home-core/octet mapping.
    BadNodeId,
    /// Source and destination `node_id` values were equal.
    IdenticalNodeIds,
    /// An identity generation was zero.
    BadIdentityGeneration,
    /// The role byte was not a registered role.
    BadRole(u8),
    /// The path-role byte was not `CDN` or `DIR`.
    BadPathRole(u8),
    /// The security-mode byte was not e2e-required or hop-only.
    BadSecurityMode(u8),
    /// The suite byte was not a registered candidate suite.
    BadSuite(u8),
    /// `mtu_cap` was outside the candidate range.
    InvalidMtu(u16),
    /// A capability bit outside `ALLOWED_CAPABILITIES` was set.
    UnknownCapability(u64),
    /// A control body exceeded its registered per-subtype cap.
    BodyTooLarge(usize),
    /// A relay payload exceeded `MAX_RELAY_PAYLOAD`.
    PayloadTooLarge(usize),
    /// The declared relay payload length did not match the actual bytes.
    LengthMismatch { declared: usize, actual: usize },
    /// `byte_offset + payload_len` overflowed `u64`.
    OffsetOverflow,
    /// Relay direction was not `0` or `1`.
    InvalidDirection(u8),
    /// `hops_remaining` was outside `1..=MAX_CIRCUIT_HOPS`.
    InvalidHopCount(u8),
    /// An Accept did not match the Hello and local identity it is bound to.
    SessionMismatch,
    /// The message is not legal for this candidate session state.
    IllegalState,
    /// A candidate field rule was violated.
    InvalidField(&'static str),
    /// The object-type byte was not a registered management object type.
    BadObjectType,
    /// The embedded raw TBS bytes were not a valid management object.
    BadManagementObject,
    /// The signed-object envelope header or signer list was malformed.
    BadSignedObject,
    /// The ML-DSA parameter set was not registered.
    BadSignatureAlgorithm,
    /// A signature length did not match its explicit algorithm.
    WrongSignatureLength,
    /// An AttachmentLease envelope lacked its Core co-signature.
    MissingCoSignature,
    /// A single-signer object carried an unexpected co-signature.
    UnexpectedCoSignature,
    /// A signed-object envelope exceeded its candidate size bound.
    SignedObjectTooLarge(usize),
}

impl MessageError {
    /// Stable category names used by candidate vectors and logs.
    pub fn category(self) -> &'static str {
        match self {
            Self::EmptyBody => "empty_body",
            Self::UnknownSubtype(_) => "unknown_subtype",
            Self::WrongLength => "wrong_length",
            Self::BadSubtype(_) => "bad_subtype",
            Self::BadProtocolVersion(_) => "bad_protocol_version",
            Self::BadNetId => "bad_net_id",
            Self::BadNodeId => "bad_node_id",
            Self::IdenticalNodeIds => "identical_node_ids",
            Self::BadIdentityGeneration => "bad_identity_generation",
            Self::BadRole(_) => "bad_role",
            Self::BadPathRole(_) => "bad_path_role",
            Self::BadSecurityMode(_) => "bad_security_mode",
            Self::BadSuite(_) => "bad_suite",
            Self::InvalidMtu(_) => "invalid_mtu",
            Self::UnknownCapability(_) => "unknown_capability",
            Self::BodyTooLarge(_) => "body_too_large",
            Self::PayloadTooLarge(_) => "payload_too_large",
            Self::LengthMismatch { .. } => "length_mismatch",
            Self::OffsetOverflow => "offset_overflow",
            Self::InvalidDirection(_) => "invalid_direction",
            Self::InvalidHopCount(_) => "invalid_hop_count",
            Self::SessionMismatch => "session_mismatch",
            Self::IllegalState => "illegal_state",
            Self::InvalidField(_) => "invalid_field",
            Self::BadObjectType => "bad_object_type",
            Self::BadManagementObject => "bad_management_object",
            Self::BadSignedObject => "bad_signed_object",
            Self::BadSignatureAlgorithm => "bad_signature_algorithm",
            Self::WrongSignatureLength => "wrong_signature_length",
            Self::MissingCoSignature => "missing_cosignature",
            Self::UnexpectedCoSignature => "unexpected_cosignature",
            Self::SignedObjectTooLarge(_) => "signed_object_too_large",
        }
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for MessageError {}

/// Payload shape registered for a control subtype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadSchema {
    /// Fixed 68-byte `SessionHello`/`SessionAccept` body.
    SessionParams,
    /// Typed Enrollment request/response.
    Enrollment,
    /// Paginated list of signed management objects.
    DirectoryPage,
    /// One [`SignedObject`] envelope.
    SignedObject,
    /// Typed Probe ping/pong.
    Probe,
    /// Typed Drain notice.
    Drain,
    /// Typed CircuitOpen.
    CircuitOpen,
    /// Typed CircuitAccept.
    CircuitAccept,
    /// Typed CircuitReset.
    CircuitReset,
    /// Typed CircuitClose.
    CircuitClose,
}

/// One row of the candidate control-subtype registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlSchema {
    pub subtype: ControlType,
    pub name: &'static str,
    /// Body cap including the subtype byte; the value comes from
    /// [`ControlType::body_cap`] so framing and payload views cannot drift.
    pub body_cap: usize,
    pub payload: PayloadSchema,
}

/// Candidate control registry in the order documented in
/// `docs/protocol/control-messages-v1.md`.
pub const CONTROL_SCHEMAS: [ControlSchema; 14] = [
    ControlSchema {
        subtype: ControlType::SessionHello,
        name: "SessionHello",
        body_cap: ControlType::SessionHello.body_cap(),
        payload: PayloadSchema::SessionParams,
    },
    ControlSchema {
        subtype: ControlType::SessionAccept,
        name: "SessionAccept",
        body_cap: ControlType::SessionAccept.body_cap(),
        payload: PayloadSchema::SessionParams,
    },
    ControlSchema {
        subtype: ControlType::Enrollment,
        name: "Enrollment",
        body_cap: ControlType::Enrollment.body_cap(),
        payload: PayloadSchema::Enrollment,
    },
    ControlSchema {
        subtype: ControlType::DirectoryPage,
        name: "DirectoryPage",
        body_cap: ControlType::DirectoryPage.body_cap(),
        payload: PayloadSchema::DirectoryPage,
    },
    ControlSchema {
        subtype: ControlType::Lease,
        name: "Lease",
        body_cap: ControlType::Lease.body_cap(),
        payload: PayloadSchema::SignedObject,
    },
    ControlSchema {
        subtype: ControlType::Lsa,
        name: "Lsa",
        body_cap: ControlType::Lsa.body_cap(),
        payload: PayloadSchema::SignedObject,
    },
    ControlSchema {
        subtype: ControlType::Grant,
        name: "Grant",
        body_cap: ControlType::Grant.body_cap(),
        payload: PayloadSchema::SignedObject,
    },
    ControlSchema {
        subtype: ControlType::Revoke,
        name: "Revoke",
        body_cap: ControlType::Revoke.body_cap(),
        payload: PayloadSchema::SignedObject,
    },
    ControlSchema {
        subtype: ControlType::Probe,
        name: "Probe",
        body_cap: ControlType::Probe.body_cap(),
        payload: PayloadSchema::Probe,
    },
    ControlSchema {
        subtype: ControlType::Drain,
        name: "Drain",
        body_cap: ControlType::Drain.body_cap(),
        payload: PayloadSchema::Drain,
    },
    ControlSchema {
        subtype: ControlType::CircuitOpen,
        name: "CircuitOpen",
        body_cap: ControlType::CircuitOpen.body_cap(),
        payload: PayloadSchema::CircuitOpen,
    },
    ControlSchema {
        subtype: ControlType::CircuitAccept,
        name: "CircuitAccept",
        body_cap: ControlType::CircuitAccept.body_cap(),
        payload: PayloadSchema::CircuitAccept,
    },
    ControlSchema {
        subtype: ControlType::CircuitReset,
        name: "CircuitReset",
        body_cap: ControlType::CircuitReset.body_cap(),
        payload: PayloadSchema::CircuitReset,
    },
    ControlSchema {
        subtype: ControlType::CircuitClose,
        name: "CircuitClose",
        body_cap: ControlType::CircuitClose.body_cap(),
        payload: PayloadSchema::CircuitClose,
    },
];

const fn schema_index(subtype: ControlType) -> usize {
    match subtype {
        ControlType::SessionHello => 0,
        ControlType::SessionAccept => 1,
        ControlType::Enrollment => 2,
        ControlType::DirectoryPage => 3,
        ControlType::Lease => 4,
        ControlType::Lsa => 5,
        ControlType::Grant => 6,
        ControlType::Revoke => 7,
        ControlType::Probe => 8,
        ControlType::Drain => 9,
        ControlType::CircuitOpen => 10,
        ControlType::CircuitAccept => 11,
        ControlType::CircuitReset => 12,
        ControlType::CircuitClose => 13,
    }
}

/// Registry row for a known subtype.
pub fn control_schema(subtype: ControlType) -> &'static ControlSchema {
    &CONTROL_SCHEMAS[schema_index(subtype)]
}

/// Registry lookup for a wire subtype byte; unknown bytes reject deterministically.
pub fn control_schema_for_byte(byte: u8) -> Result<&'static ControlSchema, MessageError> {
    let subtype = ControlType::try_from(byte).map_err(|_| MessageError::UnknownSubtype(byte))?;
    Ok(control_schema(subtype))
}

/// The sending endpoint's identity triple. The caller must source it from the
/// authenticated local identity, never from peer input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalIdentity {
    pub node_id: u16,
    pub identity_generation: u64,
    pub role: PeerRole,
}

/// Candidate `SessionHello`/`SessionAccept` parameter tuple.
///
/// `source_*` describes the sender of this message; `destination_*` describes
/// the peer the sender expects. `connection_instance` is a correlation value,
/// not a secret, nonce, MAC or cryptographic binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionParams {
    pub proto_major: u8,
    pub net_id: [u8; NET_ID_LEN],
    pub source_node_id: u16,
    pub destination_node_id: u16,
    pub source_identity_generation: u64,
    pub destination_identity_generation: u64,
    pub connection_instance: [u8; CONNECTION_INSTANCE_LEN],
    pub source_role: PeerRole,
    pub path_role: PathRole,
    pub security_mode: SecurityMode,
    pub mtu_cap: u16,
    pub suite: Suite,
    pub capabilities: u64,
}

impl SessionParams {
    /// Validate candidate structural rules. This is not authentication: the
    /// caller must still compare identities and generations with TLS/policy.
    pub fn validate(self) -> Result<(), MessageError> {
        if self.proto_major != PROTO_MAJOR {
            return Err(MessageError::BadProtocolVersion(self.proto_major));
        }
        if self.net_id == [0; NET_ID_LEN] {
            return Err(MessageError::BadNetId);
        }
        if !valid_node_id(self.source_node_id) || !valid_node_id(self.destination_node_id) {
            return Err(MessageError::BadNodeId);
        }
        if self.source_node_id == self.destination_node_id {
            return Err(MessageError::IdenticalNodeIds);
        }
        if self.source_identity_generation == 0 || self.destination_identity_generation == 0 {
            return Err(MessageError::BadIdentityGeneration);
        }
        if !(MIN_MTU_CAP..=MAX_MTU_CAP).contains(&self.mtu_cap) {
            return Err(MessageError::InvalidMtu(self.mtu_cap));
        }
        if self.capabilities & !ALLOWED_CAPABILITIES != 0 {
            return Err(MessageError::UnknownCapability(self.capabilities));
        }
        Ok(())
    }

    /// Build the exact Accept tuple expected from a peer that received `hello`,
    /// given this endpoint's authenticated local identity.
    ///
    /// All shared fields are echoed; the source identity triple becomes local;
    /// source/destination node ids and generations are swapped. The peer must
    /// have addressed `hello` to the local node and generation.
    pub fn accept_for(hello: &SessionParams, local: LocalIdentity) -> Result<Self, MessageError> {
        hello.validate()?;
        if hello.destination_node_id != local.node_id
            || hello.destination_identity_generation != local.identity_generation
        {
            return Err(MessageError::SessionMismatch);
        }
        let expected = Self {
            proto_major: hello.proto_major,
            net_id: hello.net_id,
            source_node_id: local.node_id,
            destination_node_id: hello.source_node_id,
            source_identity_generation: local.identity_generation,
            destination_identity_generation: hello.source_identity_generation,
            connection_instance: hello.connection_instance,
            source_role: local.role,
            path_role: hello.path_role,
            security_mode: hello.security_mode,
            mtu_cap: hello.mtu_cap,
            suite: hello.suite,
            capabilities: hello.capabilities,
        };
        expected.validate()?;
        Ok(expected)
    }

    fn encode(self, subtype: ControlType) -> Result<[u8; SESSION_MESSAGE_LEN], MessageError> {
        if !matches!(
            subtype,
            ControlType::SessionHello | ControlType::SessionAccept
        ) {
            return Err(MessageError::BadSubtype(subtype as u8));
        }
        self.validate()?;
        let mut writer = Writer::new();
        writer.byte(subtype as u8)?;
        writer.byte(self.proto_major)?;
        writer.put(&self.net_id)?;
        writer.be_u16(self.source_node_id)?;
        writer.be_u16(self.destination_node_id)?;
        writer.be_u64(self.source_identity_generation)?;
        writer.be_u64(self.destination_identity_generation)?;
        writer.put(&self.connection_instance)?;
        writer.byte(role_byte(self.source_role))?;
        writer.byte(self.path_role as u8)?;
        writer.byte(mode_byte(self.security_mode))?;
        writer.be_u16(self.mtu_cap)?;
        writer.byte(self.suite as u8)?;
        writer.be_u64(self.capabilities)?;
        Ok(writer.finish())
    }

    fn decode(data: &[u8], expected: ControlType) -> Result<Self, MessageError> {
        if data.len() != SESSION_MESSAGE_LEN {
            return Err(MessageError::WrongLength);
        }
        if data[0] != expected as u8
            || !matches!(
                expected,
                ControlType::SessionHello | ControlType::SessionAccept
            )
        {
            return Err(MessageError::BadSubtype(data[0]));
        }
        let mut reader = Reader::new(&data[1..]);
        let params = Self {
            proto_major: reader.byte()?,
            net_id: reader.array16()?,
            source_node_id: reader.be_u16()?,
            destination_node_id: reader.be_u16()?,
            source_identity_generation: reader.be_u64()?,
            destination_identity_generation: reader.be_u64()?,
            connection_instance: reader.array16()?,
            source_role: parse_role(reader.byte()?)?,
            path_role: PathRole::try_from(reader.byte()?)?,
            security_mode: parse_mode(reader.byte()?)?,
            mtu_cap: reader.be_u16()?,
            suite: Suite::try_from(reader.byte()?)?,
            capabilities: reader.be_u64()?,
        };
        if !reader.is_empty() {
            return Err(MessageError::WrongLength);
        }
        params.validate()?;
        Ok(params)
    }
}

/// Candidate fixed-wire `SessionHello` body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionHello {
    pub params: SessionParams,
}

impl SessionHello {
    pub fn encode(self) -> Result<[u8; SESSION_MESSAGE_LEN], MessageError> {
        self.params.encode(ControlType::SessionHello)
    }

    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            params: SessionParams::decode(data, ControlType::SessionHello)?,
        })
    }
}

/// Candidate fixed-wire `SessionAccept` body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAccept {
    pub params: SessionParams,
}

impl SessionAccept {
    pub fn encode(self) -> Result<[u8; SESSION_MESSAGE_LEN], MessageError> {
        self.params.encode(ControlType::SessionAccept)
    }

    /// Structural decode only. Session code must call [`Self::decode_bound`]
    /// (or compare the tuple with [`SessionParams::accept_for`]) before it
    /// treats the Accept as agreeing to a Hello.
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            params: SessionParams::decode(data, ControlType::SessionAccept)?,
        })
    }

    /// Decode and require exact equality with the expected Accept tuple built
    /// by [`SessionParams::accept_for`].
    pub fn decode_bound(data: &[u8], expected: SessionParams) -> Result<Self, MessageError> {
        let accept = Self::decode(data)?;
        if accept.params != expected {
            return Err(MessageError::SessionMismatch);
        }
        Ok(accept)
    }

    /// Compatibility entry for session layers that hold the received Hello and
    /// their own authenticated identity. Equivalent to
    /// `accept_for(hello, local)` followed by `decode_bound(data, expected)`.
    pub fn decode_for_hello(
        data: &[u8],
        hello: &SessionParams,
        local: LocalIdentity,
    ) -> Result<Self, MessageError> {
        let expected = SessionParams::accept_for(hello, local)?;
        Self::decode_bound(data, expected)
    }
}

/// Check a received session payload against local network, peer role, mode and
/// the candidate handshake state gates. Callers must first parse the wire
/// payload and bind Accept tuples with [`SessionAccept::decode_bound`].
pub fn validate_session_payload(
    ctx: &SessionContext,
    params: SessionParams,
    subtype: ControlType,
) -> Result<(), MessageError> {
    params.validate()?;
    if params.net_id != ctx.net_id {
        return Err(MessageError::BadNetId);
    }
    if params.source_role != ctx.peer_role {
        return Err(MessageError::SessionMismatch);
    }
    if params.security_mode != ctx.mode {
        return Err(MessageError::IllegalState);
    }
    if ctx.enrollment_service {
        return Err(MessageError::IllegalState);
    }
    match subtype {
        ControlType::SessionHello if !ctx.hello_received && !ctx.accepted => Ok(()),
        ControlType::SessionAccept if ctx.hello_received && !ctx.accepted => Ok(()),
        _ => Err(MessageError::IllegalState),
    }
}

/// Candidate Enrollment request. `invite_secret` is a bearer secret and is
/// redacted from `Debug`; callers must not log it.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrollmentRequest {
    pub request_version: u16,
    pub enrollment_id: [u8; 16],
    pub invite_id: [u8; 16],
    pub csr_hash: [u8; 32],
    pub invite_secret: [u8; 32],
    pub csr_der: Vec<u8>,
}

impl fmt::Debug for EnrollmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentRequest")
            .field("request_version", &self.request_version)
            .field("enrollment_id", &self.enrollment_id)
            .field("invite_id", &self.invite_id)
            .field("csr_hash", &self.csr_hash)
            .field("invite_secret", &"[REDACTED]")
            .field("csr_der_len", &self.csr_der.len())
            .finish()
    }
}

/// Candidate Enrollment response status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnrollmentStatus {
    Issued = 1,
    Pending = 2,
    Rejected = 3,
}

impl TryFrom<u8> for EnrollmentStatus {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Issued),
            2 => Ok(Self::Pending),
            3 => Ok(Self::Rejected),
            _ => Err(MessageError::InvalidField("enrollment status")),
        }
    }
}

/// Candidate Enrollment response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentResponse {
    pub status: EnrollmentStatus,
    pub enrollment_id: [u8; 16],
    pub csr_hash: [u8; 32],
    pub node_id: u16,
    pub identity_generation: u64,
    pub net_id: [u8; NET_ID_LEN],
    /// Exact `SignedObject` envelope bytes carrying the issued NodeIdentity.
    pub signed_identity: Vec<u8>,
}

/// Typed Enrollment control payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Enrollment {
    Request(EnrollmentRequest),
    Response(EnrollmentResponse),
}

impl Enrollment {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = VecWriter::new();
        writer.byte(ControlType::Enrollment as u8);
        match self {
            Self::Request(request) => {
                request.validate()?;
                writer.byte(1);
                writer.be_u16(request.request_version);
                writer.put(&request.enrollment_id);
                writer.put(&request.invite_id);
                writer.put(&request.csr_hash);
                writer.put(&request.invite_secret);
                writer.be_u16(
                    u16::try_from(request.csr_der.len())
                        .map_err(|_| MessageError::InvalidField("csr_der length"))?,
                );
                writer.put(&request.csr_der);
            }
            Self::Response(response) => {
                response.validate()?;
                writer.byte(2);
                writer.byte(response.status as u8);
                writer.put(&response.enrollment_id);
                writer.put(&response.csr_hash);
                writer.be_u16(response.node_id);
                writer.be_u64(response.identity_generation);
                writer.put(&response.net_id);
                writer.be_u16(
                    u16::try_from(response.signed_identity.len())
                        .map_err(|_| MessageError::InvalidField("signed_identity length"))?,
                );
                writer.put(&response.signed_identity);
            }
        }
        let out = writer.finish();
        if out.len() > ControlType::Enrollment.body_cap() {
            return Err(MessageError::BodyTooLarge(out.len()));
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        let (&subtype, payload) = body.split_first().ok_or(MessageError::EmptyBody)?;
        if subtype != ControlType::Enrollment as u8 {
            return Err(MessageError::BadSubtype(subtype));
        }
        if body.len() > ControlType::Enrollment.body_cap() {
            return Err(MessageError::BodyTooLarge(body.len()));
        }
        let mut reader = Reader::new(payload);
        let value = match reader.byte()? {
            1 => {
                let request_version = reader.be_u16()?;
                let enrollment_id = reader.array16()?;
                let invite_id = reader.array16()?;
                let csr_hash = reader.array32()?;
                let invite_secret = reader.array32()?;
                let csr_len = usize::from(reader.be_u16()?);
                let csr_der = reader.take(csr_len)?.to_vec();
                let request = EnrollmentRequest {
                    request_version,
                    enrollment_id,
                    invite_id,
                    csr_hash,
                    invite_secret,
                    csr_der,
                };
                request.validate()?;
                Self::Request(request)
            }
            2 => {
                let status = EnrollmentStatus::try_from(reader.byte()?)?;
                let enrollment_id = reader.array16()?;
                let csr_hash = reader.array32()?;
                let node_id = reader.be_u16()?;
                let identity_generation = reader.be_u64()?;
                let net_id = reader.array16()?;
                let signed_len = usize::from(reader.be_u16()?);
                let signed_identity = reader.take(signed_len)?.to_vec();
                let response = EnrollmentResponse {
                    status,
                    enrollment_id,
                    csr_hash,
                    node_id,
                    identity_generation,
                    net_id,
                    signed_identity,
                };
                response.validate()?;
                Self::Response(response)
            }
            _ => return Err(MessageError::InvalidField("enrollment kind")),
        };
        if !reader.is_empty() {
            return Err(MessageError::WrongLength);
        }
        Ok(value)
    }
}

impl EnrollmentRequest {
    fn validate(&self) -> Result<(), MessageError> {
        if self.request_version != ENROLLMENT_VERSION {
            return Err(MessageError::InvalidField("enrollment request version"));
        }
        if is_zero(&self.enrollment_id)
            || is_zero(&self.invite_id)
            || is_zero(&self.csr_hash)
            || is_zero(&self.invite_secret)
        {
            return Err(MessageError::InvalidField("enrollment zero id or secret"));
        }
        if self.csr_der.is_empty() || self.csr_der.len() > MAX_ENROLLMENT_DER {
            return Err(MessageError::InvalidField("csr_der length"));
        }
        Ok(())
    }
}

impl EnrollmentResponse {
    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.enrollment_id) || is_zero(&self.csr_hash) {
            return Err(MessageError::InvalidField("enrollment zero id or hash"));
        }
        if !valid_node_id(self.node_id)
            || self.identity_generation == 0
            || self.net_id == [0; NET_ID_LEN]
        {
            return Err(MessageError::InvalidField("enrollment identity"));
        }
        if self.signed_identity.len() > MAX_SIGNED_OBJECT_LEN {
            return Err(MessageError::InvalidField("signed_identity length"));
        }
        match self.status {
            EnrollmentStatus::Issued if self.signed_identity.is_empty() => Err(
                MessageError::InvalidField("issued response needs signed identity"),
            ),
            EnrollmentStatus::Pending | EnrollmentStatus::Rejected
                if !self.signed_identity.is_empty() =>
            {
                Err(MessageError::InvalidField(
                    "non-issued response carries signed identity",
                ))
            }
            EnrollmentStatus::Issued => {
                let object = SignedObject::decode(&self.signed_identity)?;
                if object.object_type != ObjectType::NodeIdentity {
                    return Err(MessageError::BadObjectType);
                }
                let identity = objects::decode_tbs(&object.raw_tbs)
                    .map_err(|_| MessageError::BadManagementObject)?;
                let ObjectBody::NodeIdentity(node) = identity.body else {
                    return Err(MessageError::BadObjectType);
                };
                if node.node_id != self.node_id
                    || node.identity_generation != self.identity_generation
                    || node.net_id != self.net_id
                {
                    return Err(MessageError::InvalidField(
                        "enrollment identity does not match signed object",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// One signer's Ed25519 + ML-DSA signature pair over the same raw TBS bytes.
/// Both signatures are mandatory; the envelope never silently drops Ed25519.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerSignatures {
    pub role: SignerRole,
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    pub mldsa_parameter_set: MldsaParameterSet,
    pub mldsa: Vec<u8>,
}

/// Signed management-object envelope. `raw_tbs` is kept byte-for-byte; the
/// verifier must pass exactly those bytes to
/// [`objects::signature_input`](crate::objects::signature_input).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedObject {
    pub object_type: ObjectType,
    pub raw_tbs: Vec<u8>,
    pub signers: Vec<SignerSignatures>,
}

impl SignedObject {
    pub fn validate(&self) -> Result<(), MessageError> {
        if self.raw_tbs.is_empty() || self.raw_tbs.len() > objects::MAX_OBJECT_LEN {
            return Err(MessageError::BadSignedObject);
        }
        let object =
            objects::decode_tbs(&self.raw_tbs).map_err(|_| MessageError::BadManagementObject)?;
        if object.body.object_type() != self.object_type {
            return Err(MessageError::BadObjectType);
        }
        let expected = expected_signer_count(self.object_type);
        if self.signers.len() != expected {
            return Err(if expected == 2 {
                MessageError::MissingCoSignature
            } else {
                MessageError::UnexpectedCoSignature
            });
        }
        if self.signers[0].role != SignerRole::Primary {
            return Err(MessageError::InvalidField("primary signer role"));
        }
        if expected == 2 && self.signers[1].role != SignerRole::CoSign {
            return Err(MessageError::InvalidField("co-signer role"));
        }
        for signer in &self.signers {
            validate_signer(signer)?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(SIGNED_OBJECT_VERSION);
        writer.byte(self.object_type as u8);
        writer.be_u16(SIGNED_OBJECT_SCHEMA_VERSION);
        writer.byte(u8::try_from(self.signers.len()).map_err(|_| MessageError::BadSignedObject)?);
        for signer in &self.signers {
            writer.byte(signer.role as u8);
            writer.put(&signer.ed25519);
            writer.byte(signer.mldsa_parameter_set as u8);
            writer.be_u16(
                u16::try_from(signer.mldsa.len())
                    .map_err(|_| MessageError::WrongSignatureLength)?,
            );
            writer.put(&signer.mldsa);
        }
        writer
            .be_u32(u32::try_from(self.raw_tbs.len()).map_err(|_| MessageError::BadSignedObject)?);
        writer.put(&self.raw_tbs);
        let out = writer.finish();
        if out.len() > MAX_SIGNED_OBJECT_LEN {
            return Err(MessageError::SignedObjectTooLarge(out.len()));
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() > MAX_SIGNED_OBJECT_LEN {
            return Err(MessageError::SignedObjectTooLarge(data.len()));
        }
        let mut reader = Reader::new(data);
        if reader.byte()? != SIGNED_OBJECT_VERSION {
            return Err(MessageError::BadSignedObject);
        }
        let object_type = ObjectType::try_from(u64::from(reader.byte()?))
            .map_err(|_| MessageError::BadObjectType)?;
        if reader.be_u16()? != SIGNED_OBJECT_SCHEMA_VERSION {
            return Err(MessageError::BadSignedObject);
        }
        let signer_count = reader.byte()?;
        if !(1..=2).contains(&signer_count) {
            return Err(MessageError::BadSignedObject);
        }
        let mut signers = Vec::new();
        for _ in 0..signer_count {
            let role = SignerRole::try_from(reader.byte()?)?;
            let ed25519 = reader.array64()?;
            let mldsa_parameter_set = MldsaParameterSet::try_from(u64::from(reader.byte()?))
                .map_err(|_| MessageError::BadSignatureAlgorithm)?;
            let signature_len = usize::from(reader.be_u16()?);
            if signature_len != mldsa_signature_len(mldsa_parameter_set) {
                return Err(MessageError::WrongSignatureLength);
            }
            let mldsa = reader.take(signature_len)?.to_vec();
            signers.push(SignerSignatures {
                role,
                ed25519,
                mldsa_parameter_set,
                mldsa,
            });
        }
        let tbs_len =
            usize::try_from(reader.be_u32()?).map_err(|_| MessageError::BadSignedObject)?;
        let raw_tbs = reader.take(tbs_len)?.to_vec();
        if !reader.is_empty() {
            return Err(MessageError::WrongLength);
        }
        let object = Self {
            object_type,
            raw_tbs,
            signers,
        };
        object.validate()?;
        Ok(object)
    }
}

/// Signed AttachmentLease payload (node primary signature + Core co-signature).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub object: SignedObject,
}

/// Signed CoreLsa payload (Core operational key).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lsa {
    pub object: SignedObject,
}

/// Signed RouteGrant or DirectGrant payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub object: SignedObject,
}

/// Signed StatusSnapshot payload carrying revocation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revoke {
    pub object: SignedObject,
}

/// Paginated signed-object page used for directory distribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryPage {
    pub page_seq: u64,
    pub objects: Vec<SignedObject>,
}

impl DirectoryPage {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if self.objects.is_empty() || self.objects.len() > MAX_DIRECTORY_OBJECTS {
            return Err(MessageError::InvalidField("directory page count"));
        }
        let mut writer = VecWriter::new();
        writer.byte(ControlType::DirectoryPage as u8);
        writer.be_u64(self.page_seq);
        writer.byte(
            u8::try_from(self.objects.len())
                .map_err(|_| MessageError::InvalidField("directory page count"))?,
        );
        for object in &self.objects {
            let encoded = object.encode()?;
            if writer.data.len() + encoded.len() > ControlType::DirectoryPage.body_cap() {
                return Err(MessageError::BodyTooLarge(
                    writer.data.len() + encoded.len(),
                ));
            }
            writer.be_u16(
                u16::try_from(encoded.len())
                    .map_err(|_| MessageError::SignedObjectTooLarge(encoded.len()))?,
            );
            writer.put(&encoded);
        }
        let out = writer.finish();
        if out.len() > ControlType::DirectoryPage.body_cap() {
            return Err(MessageError::BodyTooLarge(out.len()));
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        let (&subtype, payload) = body.split_first().ok_or(MessageError::EmptyBody)?;
        if subtype != ControlType::DirectoryPage as u8 {
            return Err(MessageError::BadSubtype(subtype));
        }
        if body.len() > ControlType::DirectoryPage.body_cap() {
            return Err(MessageError::BodyTooLarge(body.len()));
        }
        let mut reader = Reader::new(payload);
        let page_seq = reader.be_u64()?;
        let count = reader.byte()?;
        if !(1..=MAX_DIRECTORY_OBJECTS as u8).contains(&count) {
            return Err(MessageError::InvalidField("directory page count"));
        }
        let mut objects = Vec::new();
        for _ in 0..count {
            let object_len = usize::from(reader.be_u16()?);
            let encoded = reader.take(object_len)?;
            objects.push(SignedObject::decode(encoded)?);
        }
        if !reader.is_empty() {
            return Err(MessageError::WrongLength);
        }
        Ok(Self { page_seq, objects })
    }
}

/// Typed Probe kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProbeKind {
    Ping = 1,
    Pong = 2,
}

impl TryFrom<u8> for ProbeKind {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Pong),
            _ => Err(MessageError::InvalidField("probe kind")),
        }
    }
}

/// Candidate Probe ping/pong payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe {
    pub kind: ProbeKind,
    pub challenge: [u8; 16],
    pub sent_monotonic_us: u64,
    pub echo_monotonic_us: u64,
}

/// Candidate Drain reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DrainReason {
    Maintenance = 1,
    Shutdown = 2,
    Overload = 3,
}

impl TryFrom<u8> for DrainReason {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Maintenance),
            2 => Ok(Self::Shutdown),
            3 => Ok(Self::Overload),
            _ => Err(MessageError::InvalidField("drain reason")),
        }
    }
}

/// Candidate Drain notice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Drain {
    pub reason: DrainReason,
    pub deadline_unix_us: u64,
    pub retry_after_seconds: u16,
}

/// Candidate CircuitOpen payload, matching transport's 28-byte body:
/// subtype + circuit id + destination identity + path-hop budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitOpen {
    pub circuit_id: [u8; 16],
    pub destination_node_id: u16,
    pub destination_identity_generation: u64,
    pub path_hops: u8,
}

/// Candidate CircuitAccept payload, matching transport's 18-byte body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitAccept {
    pub circuit_id: [u8; 16],
    pub path_hops: u8,
}

/// Candidate CircuitReset payload, matching transport's 17-byte body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitReset {
    pub circuit_id: [u8; 16],
}

/// Candidate CircuitClose payload, matching transport's 17-byte body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitClose {
    pub circuit_id: [u8; 16],
}

/// Parsed control body. Every registered subtype is typed; there is no opaque
/// fallback that could smuggle capabilities, GSO or MTU state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlBody {
    SessionHello(SessionHello),
    SessionAccept(SessionAccept),
    Enrollment(Enrollment),
    DirectoryPage(DirectoryPage),
    Lease(Lease),
    Lsa(Lsa),
    Grant(Grant),
    Revoke(Revoke),
    Probe(Probe),
    Drain(Drain),
    CircuitOpen(CircuitOpen),
    CircuitAccept(CircuitAccept),
    CircuitReset(CircuitReset),
    CircuitClose(CircuitClose),
}

impl ControlBody {
    pub fn subtype(&self) -> ControlType {
        match self {
            Self::SessionHello(_) => ControlType::SessionHello,
            Self::SessionAccept(_) => ControlType::SessionAccept,
            Self::Enrollment(_) => ControlType::Enrollment,
            Self::DirectoryPage(_) => ControlType::DirectoryPage,
            Self::Lease(_) => ControlType::Lease,
            Self::Lsa(_) => ControlType::Lsa,
            Self::Grant(_) => ControlType::Grant,
            Self::Revoke(_) => ControlType::Revoke,
            Self::Probe(_) => ControlType::Probe,
            Self::Drain(_) => ControlType::Drain,
            Self::CircuitOpen(_) => ControlType::CircuitOpen,
            Self::CircuitAccept(_) => ControlType::CircuitAccept,
            Self::CircuitReset(_) => ControlType::CircuitReset,
            Self::CircuitClose(_) => ControlType::CircuitClose,
        }
    }
}

/// Strict control-body parse: non-empty, registered subtype, registered cap,
/// then the typed schema for that subtype.
pub fn parse_control_body(body: &[u8]) -> Result<ControlBody, MessageError> {
    let (&subtype_byte, _) = body.split_first().ok_or(MessageError::EmptyBody)?;
    let schema = control_schema_for_byte(subtype_byte)?;
    if body.len() > schema.body_cap {
        return Err(MessageError::BodyTooLarge(body.len()));
    }
    match schema.subtype {
        ControlType::SessionHello => Ok(ControlBody::SessionHello(SessionHello::decode(body)?)),
        ControlType::SessionAccept => Ok(ControlBody::SessionAccept(SessionAccept::decode(body)?)),
        ControlType::Enrollment => Ok(ControlBody::Enrollment(Enrollment::decode(body)?)),
        ControlType::DirectoryPage => Ok(ControlBody::DirectoryPage(DirectoryPage::decode(body)?)),
        ControlType::Lease => Ok(ControlBody::Lease(Lease {
            object: decode_signed_control(
                body,
                ControlType::Lease,
                &[ObjectType::AttachmentLease],
            )?,
        })),
        ControlType::Lsa => Ok(ControlBody::Lsa(Lsa {
            object: decode_signed_control(body, ControlType::Lsa, &[ObjectType::CoreLsa])?,
        })),
        ControlType::Grant => Ok(ControlBody::Grant(Grant {
            object: decode_signed_control(
                body,
                ControlType::Grant,
                &[ObjectType::RouteGrant, ObjectType::DirectGrant],
            )?,
        })),
        ControlType::Revoke => Ok(ControlBody::Revoke(Revoke {
            object: decode_signed_control(
                body,
                ControlType::Revoke,
                &[ObjectType::StatusSnapshot],
            )?,
        })),
        ControlType::Probe => Ok(ControlBody::Probe(Probe::decode(body)?)),
        ControlType::Drain => Ok(ControlBody::Drain(Drain::decode(body)?)),
        ControlType::CircuitOpen => Ok(ControlBody::CircuitOpen(CircuitOpen::decode(body)?)),
        ControlType::CircuitAccept => Ok(ControlBody::CircuitAccept(CircuitAccept::decode(body)?)),
        ControlType::CircuitReset => Ok(ControlBody::CircuitReset(CircuitReset::decode(body)?)),
        ControlType::CircuitClose => Ok(ControlBody::CircuitClose(CircuitClose::decode(body)?)),
    }
}

impl Lease {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        encode_signed_control(
            ControlType::Lease,
            &self.object,
            &[ObjectType::AttachmentLease],
        )
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            object: decode_signed_control(
                body,
                ControlType::Lease,
                &[ObjectType::AttachmentLease],
            )?,
        })
    }
}

impl Lsa {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        encode_signed_control(ControlType::Lsa, &self.object, &[ObjectType::CoreLsa])
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            object: decode_signed_control(body, ControlType::Lsa, &[ObjectType::CoreLsa])?,
        })
    }
}

impl Grant {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        encode_signed_control(
            ControlType::Grant,
            &self.object,
            &[ObjectType::RouteGrant, ObjectType::DirectGrant],
        )
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            object: decode_signed_control(
                body,
                ControlType::Grant,
                &[ObjectType::RouteGrant, ObjectType::DirectGrant],
            )?,
        })
    }
}

impl Revoke {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        encode_signed_control(
            ControlType::Revoke,
            &self.object,
            &[ObjectType::StatusSnapshot],
        )
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        Ok(Self {
            object: decode_signed_control(
                body,
                ControlType::Revoke,
                &[ObjectType::StatusSnapshot],
            )?,
        })
    }
}

impl Probe {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::Probe as u8);
        writer.byte(self.kind as u8);
        writer.put(&self.challenge);
        writer.be_u64(self.sent_monotonic_us);
        writer.be_u64(self.echo_monotonic_us);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != PROBE_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::Probe as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            kind: ProbeKind::try_from(reader.byte()?)?,
            challenge: reader.array16()?,
            sent_monotonic_us: reader.be_u64()?,
            echo_monotonic_us: reader.be_u64()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.challenge) {
            return Err(MessageError::InvalidField("probe challenge"));
        }
        if self.kind == ProbeKind::Ping && self.echo_monotonic_us != 0 {
            return Err(MessageError::InvalidField("ping echo time"));
        }
        Ok(())
    }
}

impl Drain {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::Drain as u8);
        writer.byte(self.reason as u8);
        writer.be_u64(self.deadline_unix_us);
        writer.be_u16(self.retry_after_seconds);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != DRAIN_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::Drain as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            reason: DrainReason::try_from(reader.byte()?)?,
            deadline_unix_us: reader.be_u64()?,
            retry_after_seconds: reader.be_u16()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if self.retry_after_seconds > MAX_DRAIN_RETRY_SECONDS {
            return Err(MessageError::InvalidField("drain retry"));
        }
        Ok(())
    }
}

impl CircuitOpen {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::CircuitOpen as u8);
        writer.put(&self.circuit_id);
        writer.be_u16(self.destination_node_id);
        writer.be_u64(self.destination_identity_generation);
        writer.byte(self.path_hops);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != CIRCUIT_OPEN_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::CircuitOpen as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            circuit_id: reader.array16()?,
            destination_node_id: reader.be_u16()?,
            destination_identity_generation: reader.be_u64()?,
            path_hops: reader.byte()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.circuit_id) {
            return Err(MessageError::InvalidField("circuit id"));
        }
        if !valid_node_id(self.destination_node_id) {
            return Err(MessageError::BadNodeId);
        }
        if self.destination_identity_generation == 0 {
            return Err(MessageError::BadIdentityGeneration);
        }
        if !(1..=MAX_CIRCUIT_HOPS).contains(&self.path_hops) {
            return Err(MessageError::InvalidHopCount(self.path_hops));
        }
        Ok(())
    }
}

impl CircuitAccept {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::CircuitAccept as u8);
        writer.put(&self.circuit_id);
        writer.byte(self.path_hops);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != CIRCUIT_ACCEPT_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::CircuitAccept as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            circuit_id: reader.array16()?,
            path_hops: reader.byte()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.circuit_id) {
            return Err(MessageError::InvalidField("circuit id"));
        }
        if !(1..=MAX_CIRCUIT_HOPS).contains(&self.path_hops) {
            return Err(MessageError::InvalidHopCount(self.path_hops));
        }
        Ok(())
    }
}

impl CircuitReset {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::CircuitReset as u8);
        writer.put(&self.circuit_id);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != CIRCUIT_ID_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::CircuitReset as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            circuit_id: reader.array16()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.circuit_id) {
            return Err(MessageError::InvalidField("circuit id"));
        }
        Ok(())
    }
}

impl CircuitClose {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.validate()?;
        let mut writer = VecWriter::new();
        writer.byte(ControlType::CircuitClose as u8);
        writer.put(&self.circuit_id);
        Ok(writer.finish())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != CIRCUIT_ID_BODY_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(body);
        if reader.byte()? != ControlType::CircuitClose as u8 {
            return Err(MessageError::BadSubtype(body[0]));
        }
        let value = Self {
            circuit_id: reader.array16()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MessageError> {
        if is_zero(&self.circuit_id) {
            return Err(MessageError::InvalidField("circuit id"));
        }
        Ok(())
    }
}

/// Candidate `RelayCircuit` fragment payload. The payload is opaque to this
/// codec; ordering, direction ownership and circuit binding are circuit-state
/// checks outside this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayFragment {
    pub circuit_id: [u8; 16],
    pub direction: u8,
    pub byte_offset: u64,
    pub hops_remaining: u8,
    pub payload: Vec<u8>,
}

impl RelayFragment {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if self.direction > 1 {
            return Err(MessageError::InvalidDirection(self.direction));
        }
        if !(1..=MAX_CIRCUIT_HOPS).contains(&self.hops_remaining) {
            return Err(MessageError::InvalidHopCount(self.hops_remaining));
        }
        if self.payload.len() > MAX_RELAY_PAYLOAD {
            return Err(MessageError::PayloadTooLarge(self.payload.len()));
        }
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| MessageError::PayloadTooLarge(self.payload.len()))?;
        self.byte_offset
            .checked_add(u64::from(payload_len))
            .ok_or(MessageError::OffsetOverflow)?;
        let mut out = Vec::with_capacity(RELAY_FRAGMENT_FIXED_LEN + self.payload.len());
        out.extend_from_slice(&self.circuit_id);
        out.push(self.direction);
        out.extend_from_slice(&self.byte_offset.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.push(self.hops_remaining);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < RELAY_FRAGMENT_FIXED_LEN {
            return Err(MessageError::WrongLength);
        }
        let mut reader = Reader::new(data);
        let circuit_id = reader.array16()?;
        let direction = reader.byte()?;
        if direction > 1 {
            return Err(MessageError::InvalidDirection(direction));
        }
        let byte_offset = reader.be_u64()?;
        let declared = reader.be_u32()? as usize;
        let hops_remaining = reader.byte()?;
        if !(1..=MAX_CIRCUIT_HOPS).contains(&hops_remaining) {
            return Err(MessageError::InvalidHopCount(hops_remaining));
        }
        if declared > MAX_RELAY_PAYLOAD {
            return Err(MessageError::PayloadTooLarge(declared));
        }
        let actual = data.len() - RELAY_FRAGMENT_FIXED_LEN;
        if declared != actual {
            return Err(MessageError::LengthMismatch { declared, actual });
        }
        byte_offset
            .checked_add(u64::try_from(declared).map_err(|_| MessageError::OffsetOverflow)?)
            .ok_or(MessageError::OffsetOverflow)?;
        Ok(Self {
            circuit_id,
            direction,
            byte_offset,
            hops_remaining,
            payload: data[RELAY_FRAGMENT_FIXED_LEN..].to_vec(),
        })
    }
}

fn expected_signer_count(object_type: ObjectType) -> usize {
    match object_type {
        ObjectType::AttachmentLease => 2,
        _ => 1,
    }
}

fn validate_signer(signer: &SignerSignatures) -> Result<(), MessageError> {
    if signer.mldsa.len() != mldsa_signature_len(signer.mldsa_parameter_set) {
        return Err(MessageError::WrongSignatureLength);
    }
    Ok(())
}

fn mldsa_signature_len(parameter_set: MldsaParameterSet) -> usize {
    match parameter_set {
        MldsaParameterSet::Mldsa65 => ML_DSA_65_SIGNATURE_LEN,
        MldsaParameterSet::Mldsa87 => ML_DSA_87_SIGNATURE_LEN,
    }
}

fn encode_signed_control(
    subtype: ControlType,
    object: &SignedObject,
    allowed: &[ObjectType],
) -> Result<Vec<u8>, MessageError> {
    if !allowed.contains(&object.object_type) {
        return Err(MessageError::BadObjectType);
    }
    let mut out = vec![subtype as u8];
    out.extend_from_slice(&object.encode()?);
    if out.len() > subtype.body_cap() {
        return Err(MessageError::BodyTooLarge(out.len()));
    }
    Ok(out)
}

fn decode_signed_control(
    body: &[u8],
    subtype: ControlType,
    allowed: &[ObjectType],
) -> Result<SignedObject, MessageError> {
    let (&subtype_byte, payload) = body.split_first().ok_or(MessageError::WrongLength)?;
    if subtype_byte != subtype as u8 {
        return Err(MessageError::BadSubtype(subtype_byte));
    }
    if body.len() > subtype.body_cap() {
        return Err(MessageError::BodyTooLarge(body.len()));
    }
    let object = SignedObject::decode(payload)?;
    if !allowed.contains(&object.object_type) {
        return Err(MessageError::BadObjectType);
    }
    Ok(object)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn role_byte(role: PeerRole) -> u8 {
    match role {
        PeerRole::Edge => 1,
        PeerRole::Core => 2,
        PeerRole::EnrollmentService => 3,
    }
}

fn parse_role(value: u8) -> Result<PeerRole, MessageError> {
    match value {
        1 => Ok(PeerRole::Edge),
        2 => Ok(PeerRole::Core),
        3 => Ok(PeerRole::EnrollmentService),
        _ => Err(MessageError::BadRole(value)),
    }
}

fn mode_byte(mode: SecurityMode) -> u8 {
    match mode {
        SecurityMode::E2eRequired => 1,
        SecurityMode::HopOnly => 2,
    }
}

fn parse_mode(value: u8) -> Result<SecurityMode, MessageError> {
    match value {
        1 => Ok(SecurityMode::E2eRequired),
        2 => Ok(SecurityMode::HopOnly),
        _ => Err(MessageError::BadSecurityMode(value)),
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.data.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], MessageError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MessageError::WrongLength)?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or(MessageError::WrongLength)?;
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, MessageError> {
        Ok(self.take(1)?[0])
    }

    fn be_u16(&mut self) -> Result<u16, MessageError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn be_u32(&mut self) -> Result<u32, MessageError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().map_err(|_| MessageError::WrongLength)?,
        ))
    }

    fn be_u64(&mut self) -> Result<u64, MessageError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| MessageError::WrongLength)?,
        ))
    }

    fn array16(&mut self) -> Result<[u8; 16], MessageError> {
        self.take(16)?
            .try_into()
            .map_err(|_| MessageError::WrongLength)
    }

    fn array32(&mut self) -> Result<[u8; 32], MessageError> {
        self.take(32)?
            .try_into()
            .map_err(|_| MessageError::WrongLength)
    }

    fn array64(&mut self) -> Result<[u8; 64], MessageError> {
        self.take(64)?
            .try_into()
            .map_err(|_| MessageError::WrongLength)
    }
}

struct Writer {
    data: [u8; SESSION_MESSAGE_LEN],
    offset: usize,
}

impl Writer {
    fn new() -> Self {
        Self {
            data: [0; SESSION_MESSAGE_LEN],
            offset: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), MessageError> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(MessageError::WrongLength)?;
        let target = self
            .data
            .get_mut(self.offset..end)
            .ok_or(MessageError::WrongLength)?;
        target.copy_from_slice(bytes);
        self.offset = end;
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), MessageError> {
        self.put(&[value])
    }

    fn be_u16(&mut self, value: u16) -> Result<(), MessageError> {
        self.put(&value.to_be_bytes())
    }

    fn be_u64(&mut self, value: u64) -> Result<(), MessageError> {
        self.put(&value.to_be_bytes())
    }

    fn finish(self) -> [u8; SESSION_MESSAGE_LEN] {
        debug_assert_eq!(self.offset, SESSION_MESSAGE_LEN);
        self.data
    }
}

struct VecWriter {
    data: Vec<u8>,
}

impl VecWriter {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn put(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    fn byte(&mut self, value: u8) {
        self.data.push(value);
    }

    fn be_u16(&mut self, value: u16) {
        self.put(&value.to_be_bytes());
    }

    fn be_u32(&mut self, value: u32) {
        self.put(&value.to_be_bytes());
    }

    fn be_u64(&mut self, value: u64) {
        self.put(&value.to_be_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::objects::{
        AttachmentLease, CoreLsa, DirectGrant, Endpoint, ManagementObject, NodeIdentity, NodeRole,
        RouteGrant, StatusSnapshot, SubjectIdentity,
    };
    use crate::{ControlType, PROTO_MAJOR, PeerRole, SecurityMode, SessionContext};

    const TEST_NET_ID: [u8; NET_ID_LEN] = [1; NET_ID_LEN];
    const TEST_INSTANCE: [u8; CONNECTION_INSTANCE_LEN] = [2; CONNECTION_INSTANCE_LEN];

    fn sample_params() -> SessionParams {
        SessionParams {
            proto_major: PROTO_MAJOR,
            net_id: TEST_NET_ID,
            source_node_id: 0x0101,
            destination_node_id: 0x0202,
            source_identity_generation: 1,
            destination_identity_generation: 2,
            connection_instance: TEST_INSTANCE,
            source_role: PeerRole::Edge,
            path_role: PathRole::Cdn,
            security_mode: SecurityMode::E2eRequired,
            mtu_cap: 1500,
            suite: Suite::Pq768,
            capabilities: 0,
        }
    }

    fn sample_hello() -> SessionHello {
        SessionHello {
            params: sample_params(),
        }
    }

    fn sample_local_identity() -> LocalIdentity {
        LocalIdentity {
            node_id: 0x0202,
            identity_generation: 2,
            role: PeerRole::Core,
        }
    }

    fn sample_accept() -> SessionAccept {
        SessionAccept {
            params: SessionParams::accept_for(&sample_params(), sample_local_identity()).unwrap(),
        }
    }

    fn sample_relay() -> RelayFragment {
        RelayFragment {
            circuit_id: [3; 16],
            direction: 0,
            byte_offset: 0,
            hops_remaining: 8,
            payload: b"abc".to_vec(),
        }
    }

    fn node_identity_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(0x0101),
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::NodeIdentity(NodeIdentity {
                net_id: TEST_NET_ID,
                node_id: 0x0101,
                home_core_id: 2,
                vip: [10, 20, 2, 1],
                vip6: [0; 16],
                role: NodeRole::Core,
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                identity_pub_mldsa: vec![1; 32],
                identity_pub_ed25519: [0x55; 32],
                identity_generation: 1,
                not_before: 10,
                expires: 20,
                scope: vec![],
            }),
        }
    }

    fn attachment_lease_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(0x0202),
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::AttachmentLease(AttachmentLease {
                node_id: 0x0202,
                identity_generation: 1,
                attach_generation: 1,
                target_core_id: 3,
                not_before: 10,
                expires: 20,
            }),
        }
    }

    fn core_lsa_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Core(3),
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::CoreLsa(CoreLsa {
                core_id: 3,
                core_generation: 1,
                seq: 1,
                neighbors: vec![],
            }),
        }
    }

    fn route_grant_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(0x0102),
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::RouteGrant(RouteGrant {
                subject_node_id: 0x0102,
                prefix: vec![10, 20, 2, 0],
                prefix_len: 24,
                metric: 1,
                ha_group: vec![],
                seq: 1,
                expires: 20,
            }),
        }
    }

    fn direct_grant_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(0x0102),
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::DirectGrant(DirectGrant {
                subject_node_id: 0x0102,
                endpoint: Endpoint::Hostname(b"example.com".to_vec()),
                port: 443,
                sni: b"example.com".to_vec(),
                expires: 20,
            }),
        }
    }

    fn status_snapshot_object() -> ManagementObject {
        ManagementObject {
            net_id: TEST_NET_ID,
            issuer_key_id: vec![1],
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Network,
            seq: 1,
            issued_at: 10,
            expires: 20,
            extensions: vec![],
            body: ObjectBody::StatusSnapshot(StatusSnapshot {
                issued_at: 10,
                next_update: 20,
                sequence: 1,
                revocations: vec![],
            }),
        }
    }

    fn mldsa_len(parameter_set: MldsaParameterSet) -> usize {
        match parameter_set {
            MldsaParameterSet::Mldsa65 => ML_DSA_65_SIGNATURE_LEN,
            MldsaParameterSet::Mldsa87 => ML_DSA_87_SIGNATURE_LEN,
        }
    }

    fn signer(role: SignerRole, parameter_set: MldsaParameterSet) -> SignerSignatures {
        SignerSignatures {
            role,
            ed25519: [0x11; ED25519_SIGNATURE_LEN],
            mldsa_parameter_set: parameter_set,
            mldsa: vec![0x22; mldsa_len(parameter_set)],
        }
    }

    fn signed(object: &ManagementObject, signers: Vec<SignerSignatures>) -> SignedObject {
        SignedObject {
            object_type: object.body.object_type(),
            raw_tbs: objects::encode_tbs(object).unwrap(),
            signers,
        }
    }

    fn single_signed(object: &ManagementObject) -> SignedObject {
        signed(
            object,
            vec![signer(SignerRole::Primary, MldsaParameterSet::Mldsa65)],
        )
    }

    fn lease_signed(object: &ManagementObject) -> SignedObject {
        signed(
            object,
            vec![
                signer(SignerRole::Primary, MldsaParameterSet::Mldsa87),
                signer(SignerRole::CoSign, MldsaParameterSet::Mldsa87),
            ],
        )
    }

    #[test]
    fn session_roundtrip_layout_and_field_rejections() {
        let hello = sample_hello();
        let bytes = hello.encode().unwrap();
        assert_eq!(bytes.len(), SESSION_MESSAGE_LEN);
        assert_eq!(SessionHello::decode(&bytes).unwrap(), hello);
        assert_eq!(bytes[1], PROTO_MAJOR);

        let mut bad = bytes;
        bad[1] = 2;
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::BadProtocolVersion(2))
        );
        let mut bad = bytes;
        bad[2..18].fill(0);
        assert_eq!(SessionHello::decode(&bad), Err(MessageError::BadNetId));
        let mut bad = bytes;
        bad[18..20].copy_from_slice(&[0, 0]);
        assert_eq!(SessionHello::decode(&bad), Err(MessageError::BadNodeId));
        let mut bad = bytes;
        bad[20..22].copy_from_slice(&[0x01, 0x01]);
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::IdenticalNodeIds)
        );
        let mut bad = bytes;
        bad[22..30].copy_from_slice(&[0; 8]);
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::BadIdentityGeneration)
        );
        let mut bad = bytes;
        bad[54] = 4;
        assert_eq!(SessionHello::decode(&bad), Err(MessageError::BadRole(4)));
        let mut bad = bytes;
        bad[55] = 3;
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::BadPathRole(3))
        );
        let mut bad = bytes;
        bad[56] = 3;
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::BadSecurityMode(3))
        );
        let mut bad = bytes;
        bad[57..59].copy_from_slice(&575u16.to_be_bytes());
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::InvalidMtu(575))
        );
        let mut bad = bytes;
        bad[59] = 3;
        assert_eq!(SessionHello::decode(&bad), Err(MessageError::BadSuite(3)));
        let mut bad = bytes;
        bad[67] = 1;
        assert_eq!(
            SessionHello::decode(&bad),
            Err(MessageError::UnknownCapability(1))
        );
        assert_eq!(
            SessionHello::decode(&bytes[..SESSION_MESSAGE_LEN - 1]),
            Err(MessageError::WrongLength)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            SessionHello::decode(&trailing),
            Err(MessageError::WrongLength)
        );
    }

    #[test]
    fn accept_binding_and_hello_entry() {
        let hello = sample_params();
        let accept = sample_accept();
        let bytes = accept.encode().unwrap();
        let expected = SessionParams::accept_for(&hello, sample_local_identity()).unwrap();
        assert_eq!(
            SessionAccept::decode_bound(&bytes, expected).unwrap(),
            accept
        );
        assert_eq!(
            SessionAccept::decode_for_hello(&bytes, &hello, sample_local_identity()).unwrap(),
            accept
        );
        let mut wrong = bytes;
        wrong[38] ^= 0xFF;
        assert_eq!(
            SessionAccept::decode_bound(&wrong, expected),
            Err(MessageError::SessionMismatch)
        );
        assert_eq!(
            SessionParams::accept_for(
                &hello,
                LocalIdentity {
                    node_id: 0x0303,
                    ..sample_local_identity()
                }
            ),
            Err(MessageError::SessionMismatch)
        );
    }

    #[test]
    fn relay_roundtrip_and_bounds() {
        let relay = sample_relay();
        let bytes = relay.encode().unwrap();
        assert_eq!(bytes.len(), RELAY_FRAGMENT_FIXED_LEN + 3);
        assert_eq!(RelayFragment::decode(&bytes).unwrap(), relay);

        let max = RelayFragment {
            payload: vec![0xA5; MAX_RELAY_PAYLOAD],
            ..sample_relay()
        };
        let max_bytes = max.encode().unwrap();
        assert_eq!(max_bytes.len(), MAX_BODY_LEN as usize);
        assert_eq!(RelayFragment::decode(&max_bytes).unwrap(), max);

        let mut bad = bytes.clone();
        bad[16] = 2;
        assert_eq!(
            RelayFragment::decode(&bad),
            Err(MessageError::InvalidDirection(2))
        );
        let mut bad = bytes.clone();
        bad[29] = 0;
        assert_eq!(
            RelayFragment::decode(&bad),
            Err(MessageError::InvalidHopCount(0))
        );
        let mut bad = bytes.clone();
        bad[25..29].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            RelayFragment::decode(&bad),
            Err(MessageError::LengthMismatch {
                declared: 4,
                actual: 3
            })
        );
        let mut overflow = bytes;
        overflow[17..25].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            RelayFragment::decode(&overflow),
            Err(MessageError::OffsetOverflow)
        );
        assert_eq!(
            RelayFragment {
                payload: vec![0; MAX_RELAY_PAYLOAD + 1],
                ..sample_relay()
            }
            .encode(),
            Err(MessageError::PayloadTooLarge(MAX_RELAY_PAYLOAD + 1))
        );
    }

    #[test]
    fn registry_caps_and_all_subtype_bytes() {
        let caps: [(ControlType, usize); 14] = [
            (ControlType::SessionHello, 4096),
            (ControlType::SessionAccept, 4096),
            (ControlType::Enrollment, 16384),
            (ControlType::DirectoryPage, 16384),
            (ControlType::Lease, 16384),
            (ControlType::Lsa, 8192),
            (ControlType::Grant, 8192),
            (ControlType::Revoke, 16384),
            (ControlType::Probe, 256),
            (ControlType::Drain, 256),
            (ControlType::CircuitOpen, 4096),
            (ControlType::CircuitAccept, 4096),
            (ControlType::CircuitReset, 256),
            (ControlType::CircuitClose, 256),
        ];
        assert_eq!(CONTROL_SCHEMAS.len(), caps.len());
        for (schema, (subtype, cap)) in CONTROL_SCHEMAS.iter().zip(caps) {
            assert_eq!(schema.subtype, subtype);
            assert_eq!(schema.body_cap, cap);
            assert_eq!(schema.body_cap, subtype.body_cap());
        }
        let names: BTreeSet<&str> = CONTROL_SCHEMAS.iter().map(|schema| schema.name).collect();
        assert_eq!(names.len(), CONTROL_SCHEMAS.len());

        for value in 0u16..=255 {
            let value = value as u8;
            let body = [value];
            match ControlType::try_from(value) {
                Ok(_) => assert_eq!(
                    parse_control_body(&body),
                    Err(MessageError::WrongLength),
                    "subtype {value:#04x}"
                ),
                Err(_) => assert_eq!(
                    parse_control_body(&body),
                    Err(MessageError::UnknownSubtype(value)),
                    "subtype {value:#04x}"
                ),
            }
        }
        assert_eq!(parse_control_body(&[]), Err(MessageError::EmptyBody));
    }

    #[test]
    fn signed_object_roundtrip_and_signer_rules() {
        let object = node_identity_object();
        let signed_object = single_signed(&object);
        let bytes = signed_object.encode().unwrap();
        assert_eq!(SignedObject::decode(&bytes).unwrap(), signed_object);
        assert_eq!(signed_object.raw_tbs, objects::encode_tbs(&object).unwrap());
        assert_eq!(
            signed_object.signers[0].ed25519.len(),
            ED25519_SIGNATURE_LEN
        );

        let lease = lease_signed(&attachment_lease_object());
        let lease_bytes = lease.encode().unwrap();
        assert_eq!(SignedObject::decode(&lease_bytes).unwrap(), lease);
        assert_eq!(lease.signers.len(), 2);
        assert_eq!(lease.signers[1].role, SignerRole::CoSign);

        let missing = single_signed(&attachment_lease_object());
        assert_eq!(missing.validate(), Err(MessageError::MissingCoSignature));

        let mut unexpected = single_signed(&object);
        unexpected
            .signers
            .push(signer(SignerRole::CoSign, MldsaParameterSet::Mldsa65));
        assert_eq!(
            unexpected.validate(),
            Err(MessageError::UnexpectedCoSignature)
        );

        let mut wrong_length = single_signed(&object);
        wrong_length.signers[0].mldsa.truncate(1);
        assert_eq!(
            wrong_length.validate(),
            Err(MessageError::WrongSignatureLength)
        );

        let mut wrong_type = single_signed(&object);
        wrong_type.object_type = ObjectType::CoreLsa;
        assert_eq!(wrong_type.validate(), Err(MessageError::BadObjectType));
    }

    #[test]
    fn management_control_payloads_and_directory_page() {
        let lease = Lease {
            object: lease_signed(&attachment_lease_object()),
        };
        let bytes = lease.encode().unwrap();
        assert!(bytes.len() <= ControlType::Lease.body_cap());
        assert_eq!(Lease::decode(&bytes).unwrap(), lease);

        let lsa = Lsa {
            object: single_signed(&core_lsa_object()),
        };
        assert_eq!(Lsa::decode(&lsa.encode().unwrap()).unwrap(), lsa);

        let grant = Grant {
            object: single_signed(&route_grant_object()),
        };
        assert_eq!(Grant::decode(&grant.encode().unwrap()).unwrap(), grant);
        let direct = Grant {
            object: single_signed(&direct_grant_object()),
        };
        assert_eq!(Grant::decode(&direct.encode().unwrap()).unwrap(), direct);

        let revoke = Revoke {
            object: single_signed(&status_snapshot_object()),
        };
        assert_eq!(Revoke::decode(&revoke.encode().unwrap()).unwrap(), revoke);

        let wrong_type = Lease {
            object: single_signed(&core_lsa_object()),
        };
        assert_eq!(wrong_type.encode(), Err(MessageError::BadObjectType));

        let page = DirectoryPage {
            page_seq: 7,
            objects: vec![
                single_signed(&node_identity_object()),
                lease_signed(&attachment_lease_object()),
            ],
        };
        let page_bytes = page.encode().unwrap();
        assert_eq!(DirectoryPage::decode(&page_bytes).unwrap(), page);
        assert_eq!(
            DirectoryPage {
                page_seq: 1,
                objects: vec![]
            }
            .encode(),
            Err(MessageError::InvalidField("directory page count"))
        );

        let control = parse_control_body(&bytes).unwrap();
        assert_eq!(control.subtype(), ControlType::Lease);
        assert!(matches!(control, ControlBody::Lease(_)));
    }

    #[test]
    fn enrollment_request_secret_is_redacted_and_response_binds_identity() {
        let request = EnrollmentRequest {
            request_version: ENROLLMENT_VERSION,
            enrollment_id: [1; 16],
            invite_id: [2; 16],
            csr_hash: [3; 32],
            invite_secret: [4; 32],
            csr_der: vec![0x30; 64],
        };
        let encoded = Enrollment::Request(request.clone()).encode().unwrap();
        assert_eq!(
            Enrollment::decode(&encoded).unwrap(),
            Enrollment::Request(request.clone())
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("invite_secret: [4"));

        let signed_identity = single_signed(&node_identity_object()).encode().unwrap();
        let response = EnrollmentResponse {
            status: EnrollmentStatus::Issued,
            enrollment_id: [1; 16],
            csr_hash: [3; 32],
            node_id: 0x0101,
            identity_generation: 1,
            net_id: TEST_NET_ID,
            signed_identity,
        };
        let encoded = Enrollment::Response(response.clone()).encode().unwrap();
        assert_eq!(
            Enrollment::decode(&encoded).unwrap(),
            Enrollment::Response(response.clone())
        );

        let mut empty_issued = response.clone();
        empty_issued.signed_identity.clear();
        assert_eq!(
            Enrollment::Response(empty_issued).encode(),
            Err(MessageError::InvalidField(
                "issued response needs signed identity"
            ))
        );
        let mut pending_with_identity = response;
        pending_with_identity.status = EnrollmentStatus::Pending;
        assert_eq!(
            Enrollment::Response(pending_with_identity).encode(),
            Err(MessageError::InvalidField(
                "non-issued response carries signed identity"
            ))
        );
    }

    #[test]
    fn probe_drain_circuit_roundtrips_and_bounds() {
        let probe = Probe {
            kind: ProbeKind::Ping,
            challenge: [9; 16],
            sent_monotonic_us: 10,
            echo_monotonic_us: 0,
        };
        let bytes = probe.encode().unwrap();
        assert_eq!(bytes.len(), PROBE_BODY_LEN);
        assert_eq!(Probe::decode(&bytes).unwrap(), probe);
        assert_eq!(
            Probe {
                echo_monotonic_us: 1,
                ..probe
            }
            .encode(),
            Err(MessageError::InvalidField("ping echo time"))
        );

        let drain = Drain {
            reason: DrainReason::Maintenance,
            deadline_unix_us: 100,
            retry_after_seconds: 30,
        };
        let bytes = drain.encode().unwrap();
        assert_eq!(bytes.len(), DRAIN_BODY_LEN);
        assert_eq!(Drain::decode(&bytes).unwrap(), drain);
        assert_eq!(
            Drain {
                retry_after_seconds: MAX_DRAIN_RETRY_SECONDS + 1,
                ..drain
            }
            .encode(),
            Err(MessageError::InvalidField("drain retry"))
        );

        let open = CircuitOpen {
            circuit_id: [5; 16],
            destination_node_id: 0x0102,
            destination_identity_generation: 4,
            path_hops: 4,
        };
        let bytes = open.encode().unwrap();
        assert_eq!(bytes.len(), CIRCUIT_OPEN_BODY_LEN);
        assert_eq!(CircuitOpen::decode(&bytes).unwrap(), open);
        assert_eq!(
            CircuitOpen {
                path_hops: 0,
                ..open
            }
            .encode(),
            Err(MessageError::InvalidHopCount(0))
        );

        let accept = CircuitAccept {
            circuit_id: [5; 16],
            path_hops: 4,
        };
        let bytes = accept.encode().unwrap();
        assert_eq!(bytes.len(), CIRCUIT_ACCEPT_BODY_LEN);
        assert_eq!(CircuitAccept::decode(&bytes).unwrap(), accept);

        for (subtype, encoded) in [
            (
                ControlType::CircuitReset,
                CircuitReset {
                    circuit_id: [5; 16],
                }
                .encode()
                .unwrap(),
            ),
            (
                ControlType::CircuitClose,
                CircuitClose {
                    circuit_id: [5; 16],
                }
                .encode()
                .unwrap(),
            ),
        ] {
            assert_eq!(encoded.len(), CIRCUIT_ID_BODY_LEN);
            assert_eq!(encoded[0], subtype as u8);
            assert_eq!(parse_control_body(&encoded).unwrap().subtype(), subtype);
        }

        assert_eq!(
            CircuitReset {
                circuit_id: [0; 16]
            }
            .encode(),
            Err(MessageError::InvalidField("circuit id"))
        );
    }

    #[test]
    fn session_payload_context_binding() {
        let hello = sample_params();
        let mut ctx = SessionContext {
            hello_received: false,
            accepted: false,
            identity_registered: false,
            peer_role: PeerRole::Edge,
            enrollment_service: false,
            circuit_opening: false,
            circuit_established: false,
            mode: SecurityMode::E2eRequired,
            net_id: TEST_NET_ID,
        };
        assert_eq!(
            validate_session_payload(&ctx, hello, ControlType::SessionHello),
            Ok(())
        );
        let mut wrong_net = hello;
        wrong_net.net_id = [0; NET_ID_LEN];
        assert_eq!(
            validate_session_payload(&ctx, wrong_net, ControlType::SessionHello),
            Err(MessageError::BadNetId)
        );
        let mut wrong_mode = hello;
        wrong_mode.security_mode = SecurityMode::HopOnly;
        assert_eq!(
            validate_session_payload(&ctx, wrong_mode, ControlType::SessionHello),
            Err(MessageError::IllegalState)
        );
        ctx.hello_received = true;
        ctx.peer_role = PeerRole::Core;
        let accept = sample_accept().params;
        assert_eq!(
            validate_session_payload(&ctx, accept, ControlType::SessionAccept),
            Ok(())
        );
        ctx.accepted = true;
        assert_eq!(
            validate_session_payload(&ctx, accept, ControlType::SessionAccept),
            Err(MessageError::IllegalState)
        );
    }

    const VECTORS: &str =
        include_str!("../../../docs/protocol/vectors/control-messages-candidate-v1.json");

    fn vector_document() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("control vector JSON")
    }

    fn vector_array(document: &serde_json::Value) -> &[serde_json::Value] {
        document
            .get("vectors")
            .and_then(|value| value.as_array())
            .map(|values| values.as_slice())
            .expect("control vectors array")
    }

    fn vector_by_id<'a>(
        document: &'a serde_json::Value,
        id: &str,
    ) -> &'a serde_json::Value {
        let matches: Vec<&serde_json::Value> = vector_array(document)
            .iter()
            .filter(|candidate| {
                candidate
                    .get("id")
                    .and_then(|value| value.as_str())
                    == Some(id)
            })
            .collect();
        assert_eq!(matches.len(), 1, "control vector id {id} must be unique");
        matches[0]
    }

    fn vector_ids(document: &serde_json::Value) -> Vec<String> {
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, vector) in vector_array(document).iter().enumerate() {
            let id = vector
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| panic!("control vector[{index}] has no string id"));
            assert!(!id.is_empty(), "control vector[{index}] has an empty id");
            assert!(
                seen.insert(id.to_owned()),
                "duplicate control vector id {id}"
            );
            ids.push(id.to_owned());
        }
        ids
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "odd-length hex");
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("non-lowercase hex digit"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn string_field<'a>(vector: &'a serde_json::Value, field: &str) -> &'a str {
        vector
            .get(field)
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("control vector field {field} must be a string"))
    }

    fn bool_field(vector: &serde_json::Value, field: &str) -> bool {
        vector
            .get(field)
            .and_then(|value| value.as_bool())
            .unwrap_or_else(|| panic!("control vector field {field} must be a boolean"))
    }

    fn message_for_subtype(subtype: u8) -> Option<&'static str> {
        match subtype {
            1 => Some("SessionHello"),
            2 => Some("SessionAccept"),
            3 => Some("Enrollment"),
            4 => Some("DirectoryPage"),
            5 => Some("Lease"),
            6 => Some("Lsa"),
            7 => Some("Grant"),
            8 => Some("Revoke"),
            9 => Some("Probe"),
            10 => Some("Drain"),
            16 => Some("CircuitOpen"),
            17 => Some("CircuitAccept"),
            18 => Some("CircuitReset"),
            19 => Some("CircuitClose"),
            _ => None,
        }
    }

    fn checked_message<'a>(vector: &'a serde_json::Value, data: &[u8]) -> &'a str {
        let kind = string_field(vector, "kind");
        let message = string_field(vector, "message");
        match kind {
            "control" => {
                if message != "ControlBody" {
                    let subtype = data.first().copied().unwrap_or_else(|| {
                        panic!("control vector {message} has an empty body")
                    });
                    let expected = message_for_subtype(subtype).unwrap_or_else(|| {
                        panic!("control vector {message} uses unregistered subtype {subtype}")
                    });
                    assert_eq!(
                        message, expected,
                        "control vector message/subtype mismatch"
                    );
                }
            }
            "relay" => assert_eq!(message, "RelayFragment", "relay vector message"),
            "signed_object" => {
                assert_eq!(message, "SignedObject", "signed-object vector message")
            }
            other => panic!("unknown control vector kind {other}"),
        }
        message
    }

    fn decode_vector(message: &str, data: &[u8]) -> Result<(), MessageError> {
        match message {
            "SessionHello" => {
                SessionHello::decode(data)?;
            }
            "SessionAccept" => {
                SessionAccept::decode_bound(data, sample_accept().params)?;
            }
            "Enrollment" => {
                Enrollment::decode(data)?;
            }
            "DirectoryPage" => {
                DirectoryPage::decode(data)?;
            }
            "SignedObject" => {
                SignedObject::decode(data)?;
            }
            "ControlBody" => {
                parse_control_body(data)?;
            }
            "RelayFragment" => {
                RelayFragment::decode(data)?;
            }
            "Probe" => {
                Probe::decode(data)?;
            }
            "Drain" => {
                Drain::decode(data)?;
            }
            "CircuitOpen" => {
                CircuitOpen::decode(data)?;
            }
            "CircuitAccept" => {
                CircuitAccept::decode(data)?;
            }
            "CircuitReset" => {
                CircuitReset::decode(data)?;
            }
            "CircuitClose" => {
                CircuitClose::decode(data)?;
            }
            other => panic!("unknown vector message {other}"),
        }
        Ok(())
    }

    fn encode_vector(message: &str, data: &[u8]) -> Result<Vec<u8>, MessageError> {
        match message {
            "SessionHello" => Ok(SessionHello::decode(data)?.encode()?.to_vec()),
            "SessionAccept" => {
                Ok(SessionAccept::decode_bound(data, sample_accept().params)?
                    .encode()?
                    .to_vec())
            }
            "Enrollment" => Ok(Enrollment::decode(data)?.encode()?),
            "DirectoryPage" => Ok(DirectoryPage::decode(data)?.encode()?),
            "SignedObject" => Ok(SignedObject::decode(data)?.encode()?),
            "RelayFragment" => Ok(RelayFragment::decode(data)?.encode()?),
            "Probe" => Ok(Probe::decode(data)?.encode()?),
            "Drain" => Ok(Drain::decode(data)?.encode()?),
            "CircuitOpen" => Ok(CircuitOpen::decode(data)?.encode()?),
            "CircuitAccept" => Ok(CircuitAccept::decode(data)?.encode()?),
            "CircuitReset" => Ok(CircuitReset::decode(data)?.encode()?),
            "CircuitClose" => Ok(CircuitClose::decode(data)?.encode()?),
            "ControlBody" => panic!("ControlBody vectors are not re-encodable"),
            other => panic!("unknown vector message {other}"),
        }
    }

    #[test]
    fn fixed_vectors_decode_or_reject_with_expected_categories() {
        let document = vector_document();
        assert_eq!(
            vector_array(&document).len(),
            48,
            "control vector count changed; update this assertion"
        );
        assert_eq!(
            document
                .get("session_pairs")
                .and_then(|value| value.as_array())
                .map(|pairs| pairs.len()),
            Some(4),
            "session_pairs count changed; update this assertion"
        );
        for id in vector_ids(&document) {
            let vector = vector_by_id(&document, &id);
            let valid = bool_field(vector, "valid");
            let data = decode_hex(if valid {
                string_field(vector, "expected_hex")
            } else {
                string_field(vector, "input_hex")
            });
            let message = checked_message(vector, &data);
            if valid {
                decode_vector(message, &data)
                    .unwrap_or_else(|error| panic!("{id}: valid vector rejected as {error:?}"));
                let encoded = encode_vector(message, &data)
                    .unwrap_or_else(|error| panic!("{id}: valid vector re-encode failed as {error:?}"));
                assert_eq!(encoded, data, "{id}: decode/encode is not byte-exact");
            } else {
                let error = match decode_vector(message, &data) {
                    Ok(()) => panic!("{id}: invalid vector accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.category(),
                    string_field(vector, "expected_error"),
                    "{id}"
                );
            }
        }
    }

    #[test]
    fn vector_parsing_ignores_json_whitespace_and_key_order() {
        let document = vector_document();
        let compact = serde_json::to_string(&document).unwrap();
        let pretty = serde_json::to_string_pretty(&document).unwrap();
        for text in [&compact, &pretty] {
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
            assert_eq!(vector_array(&parsed).len(), 48);
            assert_eq!(vector_ids(&parsed).len(), 48);
        }

        // Same Probe vector with fields in a different textual order. This
        // must not depend on the hand-written `\"field\": \"` spacing that
        // broke the previous extractor.
        let reordered: serde_json::Value = serde_json::from_str(
            r#"{
                "vectors": [
                    {
                        "valid": true,
                        "expected_hex": "090109090909090909090909090909090909000000000000000a0000000000000000",
                        "message": "Probe",
                        "kind": "control",
                        "id": "reordered-probe"
                    }
                ],
                "session_pairs": []
            }"#,
        )
        .unwrap();
        assert_eq!(vector_ids(&reordered), vec!["reordered-probe".to_owned()]);
        let vector = vector_by_id(&reordered, "reordered-probe");
        let data = decode_hex(string_field(vector, "expected_hex"));
        let message = checked_message(vector, &data);
        decode_vector(message, &data).unwrap();
        assert_eq!(encode_vector(message, &data).unwrap(), data);
    }

    #[test]
    fn minimal_vectors_pin_exact_sample_bytes() {
        let document = vector_document();
        let expected = |id: &str| {
            decode_hex(string_field(vector_by_id(&document, id), "expected_hex"))
        };
        assert_eq!(
            sample_hello().encode().unwrap().to_vec(),
            expected("session-hello-minimal")
        );
        assert_eq!(
            sample_accept().encode().unwrap().to_vec(),
            expected("session-accept-minimal")
        );
        assert_eq!(
            sample_relay().encode().unwrap(),
            expected("relay-fragment-minimal")
        );
        assert_eq!(
            Probe {
                kind: ProbeKind::Ping,
                challenge: [9; 16],
                sent_monotonic_us: 10,
                echo_monotonic_us: 0,
            }
            .encode()
            .unwrap(),
            expected("probe-ping-minimal")
        );
        assert_eq!(
            Drain {
                reason: DrainReason::Maintenance,
                deadline_unix_us: 100,
                retry_after_seconds: 30,
            }
            .encode()
            .unwrap(),
            expected("drain-minimal")
        );
        assert_eq!(
            CircuitOpen {
                circuit_id: [5; 16],
                destination_node_id: 0x0102,
                destination_identity_generation: 4,
                path_hops: 4,
            }
            .encode()
            .unwrap(),
            expected("circuit-open-minimal")
        );
    }
}
