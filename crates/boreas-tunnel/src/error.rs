//! Coarse transport error shared by the runtime modules.
//!
//! Errors cross a network trust boundary, so they carry only static reason
//! strings or protocol identifiers that a peer already knows. Certificate
//! bytes, private keys, TLS traffic secrets and peer-supplied text are never
//! copied into them. Detailed diagnosis belongs in a local-only debug facility
//! supplied by the daemon layer.

use std::fmt;
use std::io;

use boreas_crypto::PolicyError;
use boreas_proto::messages::MessageError;

use crate::relay::RelayError;
use crate::resource::AdmissionError;
use crate::ws::WsError;

/// Why a `SessionHello` / `SessionAccept` was rejected. The variants are the
/// authorization decisions themselves, so callers and tests can assert on the
/// exact rule that fired without parsing text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionReject {
    /// Local and expected peer `net_id` differ, or `net_id` is all zero.
    NetworkMismatch,
    /// Local identity is unusable (zero generation / zero node id).
    InvalidLocalIdentity,
    /// The `SessionHello` source does not match the authenticated TLS peer.
    HelloSourceMismatch,
    /// The `SessionHello` destination does not match this node.
    HelloDestinationMismatch,
    /// Peer identity facts differ from the expected, already-authorized peer.
    PeerIdentityMismatch,
    /// `path_role` differs from local policy (`CDN` vs `DIR`).
    PathRoleMismatch,
    /// `security_mode` differs from local policy.
    SecurityModeMismatch,
    /// `suite` differs from local policy.
    SuiteMismatch,
    /// `HopOnly` was requested without an explicit local opt-in.
    HopOnlyNotPermitted,
    /// `pq1024` was requested without separate PoC enablement.
    Pq1024NotEnabled,
    /// Peer MTU cap exceeds the locally configured cap.
    MtuExceedsLocal,
    /// MTU cap outside the protocol range.
    InvalidMtu,
    /// Authenticated peer role is not in the explicitly allowed role list.
    PeerRoleNotAllowed,
    /// Enrollment-service listeners are handled by a separate enrollment path.
    LocalRoleNotAllowed,
    /// A `DIR` listener exists only on Core nodes.
    DirRequiresCore,
    /// `connection_instance` was all zero and cannot bind a session.
    ZeroConnectionInstance,
    /// The first application frame was not a `SessionHello`.
    FirstFrameNotHello,
    /// Capability bits were set although none are registered.
    CapabilitiesNotSupported,
    /// A control body does not start with the declared subtype byte.
    ControlSubtypeMismatch,
}

/// Why an E2E circuit operation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitReject {
    /// The hop session is not in `e2e-required` mode.
    NotE2eRequired,
    /// The circuit is unknown, closed, or never opened.
    NotEstablished,
    /// Circuit-bound destination/generation differs from this node.
    WrongDestination,
    /// Fragment arrived on a different circuit id.
    UnknownCircuit,
    /// Fragment direction byte does not belong to this endpoint.
    DirectionMismatch,
    /// Fragment hop budget is zero, above the circuit length, or too small to
    /// forward through another relay.
    HopsMismatch,
    /// Fragment offset was not the exact next byte boundary (gap or duplicate).
    OffsetMismatch,
    /// The peer sent `CircuitReset`.
    ResetReceived,
    /// Control/`RelayCircuit` frame arrived where the circuit state forbids it.
    UnexpectedFrame,
    /// A circuit control body had the wrong length or subtype byte.
    BadBody,
    /// A write was attempted after the circuit closed.
    Closed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TunnelError {
    /// Transport I/O failed. Only the kind is retained.
    Io(io::ErrorKind),
    /// A socket read/write exceeded its configured timeout.
    Timeout,
    /// The peer closed the connection (clean WebSocket close or EOF).
    Closed,
    /// The OS CSPRNG was unavailable or a request was impossible to satisfy.
    Entropy,
    /// WebSocket handshake or framing violation.
    Ws(WsError),
    /// Bounded HTTP request/response head was malformed.
    Http(&'static str),
    /// Application framing header/body violation.
    Frame(boreas_proto::Error),
    /// `SessionHello`/`SessionAccept`/`RelayFragment` wire-schema violation.
    Message(MessageError),
    /// Strict TLS policy gate rejected the negotiated facts or the peer.
    Policy(PolicyError),
    /// The inner-TLS seam failed or reported facts this crate cannot trust.
    InnerTls(&'static str),
    /// Session authorization rejected the peer.
    Session(SessionReject),
    /// E2E circuit operation rejected.
    Circuit(CircuitReject),
    /// Bounded connection/byte admission rejected.
    Admission(AdmissionError),
    /// Circuit lifecycle bookkeeping rejected.
    Relay(RelayError),
    /// A body length cannot be expressed in `AppHeader`.
    FrameTooLarge,
    /// Too many decoded frames or too many bytes are queued for delivery.
    FrameQuota,
    /// A previous partial write or framing error poisoned the session; the
    /// frame stream cannot be resynchronised.
    Poisoned,
    /// The requested operation is not implemented by this build.
    Unsupported(&'static str),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TunnelError {}

impl From<io::Error> for TunnelError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::UnexpectedEof => Self::Closed,
            kind => Self::Io(kind),
        }
    }
}

impl From<WsError> for TunnelError {
    fn from(error: WsError) -> Self {
        Self::Ws(error)
    }
}

impl From<boreas_proto::Error> for TunnelError {
    fn from(error: boreas_proto::Error) -> Self {
        Self::Frame(error)
    }
}

impl From<MessageError> for TunnelError {
    fn from(error: MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<PolicyError> for TunnelError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<SessionReject> for TunnelError {
    fn from(reject: SessionReject) -> Self {
        Self::Session(reject)
    }
}

impl From<CircuitReject> for TunnelError {
    fn from(reject: CircuitReject) -> Self {
        Self::Circuit(reject)
    }
}

impl From<AdmissionError> for TunnelError {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}

impl From<RelayError> for TunnelError {
    fn from(error: RelayError) -> Self {
        Self::Relay(error)
    }
}

impl From<crate::csprng::EntropyError> for TunnelError {
    fn from(_: crate::csprng::EntropyError) -> Self {
        Self::Entropy
    }
}
