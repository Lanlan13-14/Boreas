//! Inner-TLS seam and the policy gate re-checked by the runtime.
//!
//! The hop TLS session is a standard TLS 1.3 session carried inside WebSocket
//! binary payloads. This crate does not implement TLS: a backend implements
//! [`InnerTlsConnector`] / [`InnerTlsAcceptor`] and must
//!
//! * require TLS 1.3 with the reviewed hybrid group (`X25519MLKEM768`) and
//!   ML-DSA-65 certificate authentication, no resumption and no 0-RTT,
//! * verify the peer certificate chain and `CertificateVerify`, and
//! * report the authenticated peer identity plus negotiated parameters.
//!
//! [`check_inner_tls`] re-runs `boreas-crypto`'s strict policy gate over the
//! reported facts, and [`crate::session`] binds the authenticated identity to
//! the `SessionHello`. A backend that lies about these facts defeats the
//! design, so only the reviewed in-tree adapter may be used in production.
//! `boreas-crypto`'s OpenSSL backend is wired by the `openssl-inner-tls`
//! feature; the default build has no backend at all and fails closed.

use boreas_crypto::{
    ExpectedPeer, NegotiatedParameters, NodeRole, Policy, PresentedPeer, Suite as CryptoSuite,
};
#[cfg(feature = "openssl-inner-tls")]
use boreas_pki::VerifiedNetworkContext;
use boreas_proto::messages::Suite as MessageSuite;

use crate::error::{SessionReject, TunnelError};
use crate::stream::Duplex;

/// Authenticated peer facts. Values come from the verified certificate chain
/// (via the PKI layer) and never from a peer-supplied message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub net_id: [u8; 16],
    pub node_id: u16,
    pub identity_generation: u64,
    pub role: NodeRole,
    #[cfg(feature = "openssl-inner-tls")]
    policy: Option<VerifiedNetworkContext>,
}

impl PeerIdentity {
    /// Construct the policy-bound identity used by the runtime packet path.
    /// Callers cannot supply a raw digest or prefix; they must hold the opaque
    /// context produced by successful NetworkRoot-pinned verification.
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn policy_bound(
        net_id: [u8; 16],
        node_id: u16,
        identity_generation: u64,
        role: NodeRole,
        policy: VerifiedNetworkContext,
    ) -> Option<Self> {
        if net_id != policy.net_id() {
            return None;
        }
        Some(Self {
            net_id,
            node_id,
            identity_generation,
            role,
            policy: Some(policy),
        })
    }

    /// Explicit compatibility identity for old non-packet session/control paths.
    /// It is not evidence of signed policy and packet path rejects it.
    pub(crate) fn legacy_default(
        net_id: [u8; 16],
        node_id: u16,
        identity_generation: u64,
        role: NodeRole,
    ) -> Self {
        Self {
            net_id,
            node_id,
            identity_generation,
            role,
            #[cfg(feature = "openssl-inner-tls")]
            policy: None,
        }
    }

    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn policy(&self) -> Option<VerifiedNetworkContext> {
        self.policy
    }
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn policy_digest(&self) -> Option<[u8; 32]> {
        self.policy.map(|policy| policy.policy_digest())
    }
    pub(crate) fn crypto_expected(self) -> ExpectedPeer {
        ExpectedPeer {
            net_id: self.net_id,
            node_id: self.node_id,
            identity_generation: self.identity_generation,
            role: self.role,
        }
    }

    pub(crate) fn crypto_presented(self) -> PresentedPeer {
        PresentedPeer {
            net_id: self.net_id,
            node_id: self.node_id,
            identity_generation: self.identity_generation,
            role: self.role,
        }
    }
}

/// A completed inner-TLS session: the authenticated peer plus the negotiated
/// parameters that the policy gate re-checks.
///
/// The fields are private on purpose. A value of this type can only be built by
/// the reviewed in-tree backend adapter, from a certificate chain that the TLS
/// backend already verified and a `PeerIdentity` the PKI layer mapped from that
/// verified leaf. A public struct literal would be a self-reported claim, not an
/// authorization result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerTlsSession {
    peer: PeerIdentity,
    negotiated: NegotiatedParameters,
}

impl InnerTlsSession {
    /// Constructor for the in-tree backend adapters only.
    ///
    /// Callers must pass a certificate-derived [`PeerIdentity`]; the adapter is
    /// the only code path that holds a verified leaf certificate. Test code uses
    /// a `#[cfg(test)]` constructor instead.
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn from_verified_certificate(
        peer: PeerIdentity,
        negotiated: NegotiatedParameters,
    ) -> Self {
        Self { peer, negotiated }
    }

    pub fn peer(&self) -> PeerIdentity {
        self.peer
    }

    pub fn negotiated(&self) -> NegotiatedParameters {
        self.negotiated
    }

    #[cfg(test)]
    pub(crate) fn test_only(peer: PeerIdentity, negotiated: NegotiatedParameters) -> Self {
        Self { peer, negotiated }
    }
}

/// A TLS-protected byte stream together with its session facts.
///
/// Fields are private: only the in-tree backend adapter can pair a stream with
/// a session, so safe code outside this crate cannot combine an arbitrary
/// plaintext stream with a cloned set of "verified" facts.
pub struct EstablishedInner {
    stream: Box<dyn Duplex>,
    session: InnerTlsSession,
}

impl EstablishedInner {
    /// Constructor for the in-tree backend adapters only.
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn new(stream: Box<dyn Duplex>, session: InnerTlsSession) -> Self {
        Self { stream, session }
    }

    pub fn session(&self) -> &InnerTlsSession {
        &self.session
    }

    /// Hand the protected stream and its facts to the session layer.
    pub fn into_parts(self) -> (Box<dyn Duplex>, InnerTlsSession) {
        (self.stream, self.session)
    }
}

/// Maps a **verified** peer leaf certificate to Boreas identity claims.
///
/// The TLS backend has already validated the chain and `CertificateVerify` when
/// this is called; the implementation still must validate `net_id`, role, node
/// id, generation and issuer scope from the certificate and return `None` on any
/// mismatch. There is deliberately no default implementation: without a real
/// PKI mapping the in-tree adapter cannot be constructed.
pub trait PeerIdentityExtractor: Send + Sync {
    fn extract(&self, certificate_der: &[u8]) -> Option<PeerIdentity>;
}

/// Client side of the outer HTTPS/WSS TLS layer.
///
/// Outer TLS faces the CDN or the origin's public certificate; it is verified
/// against the **web PKI**, unlike the Boreas identity CA used by the inner
/// session. The plan allows the CDN to terminate outer TLS with classical
/// parameters, so this layer does not enforce the pq768 profile; the inner
/// session always does. Implementations must verify the certificate chain and
/// the server name and must not disable verification to get connectivity.
///
/// `server_name` is a pure DNS host (no port); callers must not pass the
/// `Host` header value when it contains a port.
pub trait OuterTlsConnector: Send + Sync {
    fn connect(
        &self,
        tcp: std::net::TcpStream,
        server_name: &str,
    ) -> Result<Box<dyn Duplex>, TunnelError>;
}

/// Server side of the outer TLS layer (origin leg or local terminator).
///
/// Implementations present the origin certificate and must keep TLS 1.3 as the
/// floor. Authenticating the CDN/origin peer (mTLS, signed token, allowlist) is
/// a separate origin-auth concern; this trait only terminates the channel.
pub trait OuterTlsAcceptor: Send + Sync {
    fn accept(&self, tcp: std::net::TcpStream) -> Result<Box<dyn Duplex>, TunnelError>;
}

/// Test-only outer transport: returns the plain TCP stream unchanged.
///
/// Performs **no outer TLS**. It exists only under `#[cfg(test)]` so the framing
/// and session state machines can run over real sockets; it is not evidence
/// that WSS works.
#[cfg(test)]
pub(crate) struct TestOnlyPlaintextOuter;

#[cfg(test)]
impl OuterTlsConnector for TestOnlyPlaintextOuter {
    fn connect(
        &self,
        tcp: std::net::TcpStream,
        _server_name: &str,
    ) -> Result<Box<dyn Duplex>, TunnelError> {
        Ok(Box::new(tcp))
    }
}

#[cfg(test)]
impl OuterTlsAcceptor for TestOnlyPlaintextOuter {
    fn accept(&self, tcp: std::net::TcpStream) -> Result<Box<dyn Duplex>, TunnelError> {
        Ok(Box::new(tcp))
    }
}

/// Client (connector) side of the hop inner TLS handshake.
pub trait InnerTlsConnector: Send + Sync {
    fn connect(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError>;
}

/// Server (acceptor) side of the hop inner TLS handshake.
pub trait InnerTlsAcceptor: Send + Sync {
    fn accept(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError>;
}

pub(crate) fn crypto_suite(suite: MessageSuite) -> CryptoSuite {
    match suite {
        MessageSuite::Pq768 => CryptoSuite::Pq768,
        MessageSuite::Pq1024 => CryptoSuite::Pq1024,
    }
}

/// Re-check the strict TLS policy over facts reported by the backend.
///
/// `pq1024` is rejected unless separately enabled; `boreas-crypto` has no
/// reviewed pq1024 profile, so enabling the flag here would still require the
/// Phase 0 PoC and an independent backend.
pub fn check_inner_tls(
    session: &InnerTlsSession,
    suite: MessageSuite,
    allow_pq1024: bool,
) -> Result<(), TunnelError> {
    if suite == MessageSuite::Pq1024 && !allow_pq1024 {
        return Err(SessionReject::Pq1024NotEnabled.into());
    }
    let policy = Policy {
        suite: crypto_suite(suite),
        allow_pq1024,
    };
    policy.validate_negotiated(session.negotiated())?;
    Ok(())
}

/// Test-only transport used to exercise framing and authorization state
/// machines over real sockets.
///
/// It performs **no TLS**, no certificate validation and fabricates the
/// negotiated facts. It exists only under `#[cfg(test)]`; it is never compiled
/// into a production build and its output is not security evidence.
#[cfg(test)]
pub(crate) struct TestOnlyPlaintextTls {
    pub peer: PeerIdentity,
}

#[cfg(test)]
impl TestOnlyPlaintextTls {
    fn establish(&self, stream: Box<dyn Duplex>) -> EstablishedInner {
        EstablishedInner {
            stream,
            session: InnerTlsSession::test_only(self.peer, strict_test_negotiated()),
        }
    }
}

#[cfg(test)]
impl InnerTlsConnector for TestOnlyPlaintextTls {
    fn connect(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        Ok(self.establish(transport))
    }
}

#[cfg(test)]
impl InnerTlsAcceptor for TestOnlyPlaintextTls {
    fn accept(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        Ok(self.establish(transport))
    }
}

/// Facts a strict pq768 handshake must report. Test-only.
#[cfg(test)]
pub(crate) fn strict_test_negotiated() -> NegotiatedParameters {
    use boreas_crypto::{Aead, HybridGroup, IdentitySignature, TlsVersion};

    NegotiatedParameters {
        version: TlsVersion::Tls13,
        group: HybridGroup::X25519MlKem768,
        peer_signature: IdentitySignature::MlDsa65,
        aead: Aead::ChaCha20Poly1305Sha256,
        resumed: false,
        zero_rtt: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreas_crypto::PolicyError;

    fn peer() -> PeerIdentity {
        PeerIdentity::legacy_default([7; 16], 0x0102, 3, NodeRole::Core)
    }

    fn session(peer: PeerIdentity) -> InnerTlsSession {
        InnerTlsSession::test_only(peer, strict_test_negotiated())
    }

    #[test]
    fn strict_facts_pass_and_classical_downgrade_is_rejected() {
        assert_eq!(
            check_inner_tls(&session(peer()), MessageSuite::Pq768, false),
            Ok(())
        );

        let mut facts = strict_test_negotiated();
        facts.group = boreas_crypto::HybridGroup::ClassicalOnly;
        let downgraded = InnerTlsSession::test_only(peer(), facts);
        assert_eq!(
            check_inner_tls(&downgraded, MessageSuite::Pq768, false),
            Err(TunnelError::Policy(PolicyError::HybridGroupRequired))
        );
    }

    #[test]
    fn resumption_zero_rtt_and_pq1024_fail_closed() {
        let mut facts = strict_test_negotiated();
        facts.resumed = true;
        let resumed = InnerTlsSession::test_only(peer(), facts);
        assert_eq!(
            check_inner_tls(&resumed, MessageSuite::Pq768, false),
            Err(TunnelError::Policy(PolicyError::ResumptionForbidden))
        );

        let mut facts = strict_test_negotiated();
        facts.zero_rtt = true;
        let early = InnerTlsSession::test_only(peer(), facts);
        assert_eq!(
            check_inner_tls(&early, MessageSuite::Pq768, false),
            Err(TunnelError::Policy(PolicyError::ZeroRttForbidden))
        );

        assert_eq!(
            check_inner_tls(&session(peer()), MessageSuite::Pq1024, false),
            Err(TunnelError::Session(SessionReject::Pq1024NotEnabled))
        );
    }
}
