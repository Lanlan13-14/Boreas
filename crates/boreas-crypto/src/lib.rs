//! Boreas TLS security policy gate, not a TLS implementation.
//!
//! No handshake, key exchange, signature, certificate parser, or AEAD is implemented here.
//! In particular, no production session can be created until a reviewed backend is wired in.

#![forbid(unsafe_code)]

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Edge,
    Core,
    EnrollmentService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    /// RFC 10024 X25519MLKEM768 + ML-DSA-65 profile.
    Pq768,
    /// RFC 10024 SecP384r1MLKEM1024 + ML-DSA-87; disabled until separate PoC evidence.
    Pq1024,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridGroup {
    X25519MlKem768,
    SecP384r1MlKem1024,
    ClassicalOnly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySignature {
    MlDsa65,
    MlDsa87,
    Ed25519,
    Rsa,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Aead {
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsVersion {
    Tls13,
    Tls12,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedParameters {
    pub version: TlsVersion,
    pub group: HybridGroup,
    pub peer_signature: IdentitySignature,
    pub aead: Aead,
    pub resumed: bool,
    pub zero_rtt: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedPeer {
    pub net_id: [u8; 16],
    pub node_id: u16,
    pub identity_generation: u64,
    pub role: NodeRole,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentedPeer {
    pub net_id: [u8; 16],
    pub node_id: u16,
    pub identity_generation: u64,
    pub role: NodeRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Pq1024NotEnabled,
    WrongTlsVersion,
    HybridGroupRequired,
    WrongMlDsaAlgorithm,
    AeadNotAllowed,
    ResumptionForbidden,
    ZeroRttForbidden,
    PeerMismatch,
    BackendUnavailable,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    pub suite: Suite,
    pub allow_pq1024: bool,
}
impl Policy {
    pub const fn production_default() -> Self {
        Self {
            suite: Suite::Pq768,
            allow_pq1024: false,
        }
    }

    /// Verify policy-relevant facts from a backend's completed handshake.
    /// Caller must additionally rely on backend certificate-chain and CertificateVerify checks.
    pub fn validate_negotiated(&self, negotiated: NegotiatedParameters) -> Result<(), PolicyError> {
        if negotiated.version != TlsVersion::Tls13 {
            return Err(PolicyError::WrongTlsVersion);
        }
        let (group, signature) = match self.suite {
            Suite::Pq768 => (HybridGroup::X25519MlKem768, IdentitySignature::MlDsa65),
            Suite::Pq1024 if self.allow_pq1024 => {
                (HybridGroup::SecP384r1MlKem1024, IdentitySignature::MlDsa87)
            }
            Suite::Pq1024 => return Err(PolicyError::Pq1024NotEnabled),
        };
        if negotiated.group != group {
            return Err(PolicyError::HybridGroupRequired);
        }
        if negotiated.peer_signature != signature {
            return Err(PolicyError::WrongMlDsaAlgorithm);
        }
        if !matches!(
            negotiated.aead,
            Aead::Aes256GcmSha384 | Aead::ChaCha20Poly1305Sha256
        ) {
            return Err(PolicyError::AeadNotAllowed);
        }
        if negotiated.resumed {
            return Err(PolicyError::ResumptionForbidden);
        }
        if negotiated.zero_rtt {
            return Err(PolicyError::ZeroRttForbidden);
        }
        Ok(())
    }

    pub fn validate_peer(
        &self,
        expected: ExpectedPeer,
        presented: PresentedPeer,
    ) -> Result<(), PolicyError> {
        if expected.net_id != presented.net_id
            || expected.node_id != presented.node_id
            || expected.identity_generation == 0
            || expected.identity_generation != presented.identity_generation
            || expected.role != presented.role
        {
            return Err(PolicyError::PeerMismatch);
        }
        Ok(())
    }

    /// Fail closed unless caller supplies an actual external TLS backend integration.
    /// This crate intentionally ships with no backend implementation.
    pub fn establish<'a>(
        &self,
        _backend: Option<&'a dyn TlsBackend>,
        _expected: ExpectedPeer,
    ) -> Result<ProductionSession<'a>, PolicyError> {
        Err(PolicyError::BackendUnavailable)
    }
}

/// Marker interface to make the integration boundary explicit. A backend implementer must
/// perform standard TLS 1.3 and authenticated certificate validation; it cannot be replaced
/// by a fake authenticator. The trait has no default implementation.
pub trait TlsBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;
}

/// A token representing a session that has actually passed backend and policy validation.
/// No public constructor is provided in this policy-only crate.
pub struct ProductionSession<'a> {
    _backend: &'a dyn TlsBackend,
    _private: (),
}

/// Descriptive policy result only; it is not an authorization token or proof of TLS/E2E.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E2eMode {
    Required,
    HopOnlyExplicit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficDecision {
    PolicyWouldPermit,
    Reject,
}
/// Static policy simulation for tests/config validation. Production data paths must require
/// a verified `ProductionSession` plus separate E2E peer/circuit binding; this boolean proves neither.
pub fn policy_simulation_decision(
    mode: E2eMode,
    hypothetical_session_established: bool,
) -> TrafficDecision {
    match (mode, hypothetical_session_established) {
        (E2eMode::Required, true) | (E2eMode::HopOnlyExplicit, true) => {
            TrafficDecision::PolicyWouldPermit
        }
        _ => TrafficDecision::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn negotiated() -> NegotiatedParameters {
        NegotiatedParameters {
            version: TlsVersion::Tls13,
            group: HybridGroup::X25519MlKem768,
            peer_signature: IdentitySignature::MlDsa65,
            aead: Aead::ChaCha20Poly1305Sha256,
            resumed: false,
            zero_rtt: false,
        }
    }
    #[test]
    fn accepts_only_required_pq768_profile() {
        let policy = Policy::production_default();
        assert_eq!(policy.validate_negotiated(negotiated()), Ok(()));
        let mut n = negotiated();
        n.group = HybridGroup::ClassicalOnly;
        assert_eq!(
            policy.validate_negotiated(n),
            Err(PolicyError::HybridGroupRequired)
        );
        let mut n = negotiated();
        n.peer_signature = IdentitySignature::Ed25519;
        assert_eq!(
            policy.validate_negotiated(n),
            Err(PolicyError::WrongMlDsaAlgorithm)
        );
        let mut n = negotiated();
        n.aead = Aead::Other;
        assert_eq!(
            policy.validate_negotiated(n),
            Err(PolicyError::AeadNotAllowed)
        );
    }
    #[test]
    fn tls_version_resumption_and_0rtt_fail_closed() {
        let p = Policy::production_default();
        let mut n = negotiated();
        n.version = TlsVersion::Tls12;
        assert_eq!(p.validate_negotiated(n), Err(PolicyError::WrongTlsVersion));
        let mut n = negotiated();
        n.resumed = true;
        assert_eq!(
            p.validate_negotiated(n),
            Err(PolicyError::ResumptionForbidden)
        );
        let mut n = negotiated();
        n.zero_rtt = true;
        assert_eq!(p.validate_negotiated(n), Err(PolicyError::ZeroRttForbidden));
    }
    #[test]
    fn pq1024_requires_explicit_enablement_and_correct_algorithms() {
        let disabled = Policy {
            suite: Suite::Pq1024,
            allow_pq1024: false,
        };
        let mut n = negotiated();
        n.group = HybridGroup::SecP384r1MlKem1024;
        n.peer_signature = IdentitySignature::MlDsa87;
        assert_eq!(
            disabled.validate_negotiated(n),
            Err(PolicyError::Pq1024NotEnabled)
        );
        let enabled = Policy {
            suite: Suite::Pq1024,
            allow_pq1024: true,
        };
        assert_eq!(enabled.validate_negotiated(n), Ok(()));
    }
    #[test]
    fn exact_peer_binding_includes_generation_and_network() {
        let p = Policy::production_default();
        let expected = ExpectedPeer {
            net_id: [4; 16],
            node_id: 0x102,
            identity_generation: 7,
            role: NodeRole::Edge,
        };
        let shown = PresentedPeer {
            net_id: [4; 16],
            node_id: 0x102,
            identity_generation: 7,
            role: NodeRole::Edge,
        };
        assert_eq!(p.validate_peer(expected, shown), Ok(()));
        assert_eq!(
            p.validate_peer(
                expected,
                PresentedPeer {
                    identity_generation: 6,
                    ..shown
                }
            ),
            Err(PolicyError::PeerMismatch)
        );
        assert_eq!(
            p.validate_peer(
                expected,
                PresentedPeer {
                    node_id: 0x103,
                    ..shown
                }
            ),
            Err(PolicyError::PeerMismatch)
        );
        assert_eq!(
            p.validate_peer(
                expected,
                PresentedPeer {
                    role: NodeRole::Core,
                    ..shown
                }
            ),
            Err(PolicyError::PeerMismatch)
        );
        assert_eq!(
            p.validate_peer(
                expected,
                PresentedPeer {
                    net_id: [5; 16],
                    ..shown
                }
            ),
            Err(PolicyError::PeerMismatch)
        );
        assert_eq!(
            p.validate_peer(
                ExpectedPeer {
                    identity_generation: 0,
                    ..expected
                },
                shown
            ),
            Err(PolicyError::PeerMismatch)
        );
    }
    #[test]
    fn absent_backend_never_establishes_and_e2e_fails_closed() {
        let p = Policy::production_default();
        let peer = ExpectedPeer {
            net_id: [0; 16],
            node_id: 1,
            identity_generation: 1,
            role: NodeRole::Core,
        };
        assert!(matches!(
            p.establish(None, peer),
            Err(PolicyError::BackendUnavailable)
        ));
        assert_eq!(
            policy_simulation_decision(E2eMode::Required, false),
            TrafficDecision::Reject
        );
        assert_eq!(
            policy_simulation_decision(E2eMode::Required, true),
            TrafficDecision::PolicyWouldPermit
        );
    }
}
