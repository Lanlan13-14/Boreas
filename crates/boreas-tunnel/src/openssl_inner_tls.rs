//! In-tree adapter from the reviewed `boreas-crypto` OpenSSL pq768 backend to
//! the hop and E2E transport seams.
//!
//! Enabled by the `openssl-inner-tls` feature. The adapter deliberately cannot
//! invent peer identity: the certificate is read from the backend **after**
//! chain verification, and a [`PeerIdentityExtractor`] supplied by the PKI layer
//! must map the verified leaf to `net_id` / node id / generation / role. If the
//! extractor returns `None`, the handshake is rejected.
//!
//! The separate diagnostic helpers ([`connect_inner`], [`accept_inner`],
//! [`exchange`], [`loopback_echo`]) retain the backend-only seam API. They do not
//! run outer WSS TLS, map Boreas identities, authorize application traffic, or
//! create runtime session/E2E tokens. A successful echo is not a gate pass.
//!
//! This module is compiled only with the feature and needs OpenSSL 3.6+ with
//! ML-DSA support (the same build the `rust-tls.yml` workflow produces). It is
//! not exerciseable by the default workspace CI job; the OpenSSL CI job must run
//! `cargo test -p boreas-tunnel --features openssl-inner-tls` before any claim
//! about real inner TLS behaviour.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boreas_crypto::backend::{BackendError, EstablishedStream, OpenSslAcceptor, OpenSslConnector};
use boreas_crypto::pq_wg::{
    PqWgAcceptor, PqWgConnector, PqWgIdentity, PqWgLayer, PqWgPeerResolver, PqWgStream,
};
use boreas_crypto::{NodeRole, Policy, PolicyError, Suite};
use boreas_pki::management::VerifiedObject;
use boreas_proto::objects::{MldsaParameterSet, NodeRole as ObjectRole, ObjectBody};
use openssl::sha::sha256;
use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;

use crate::e2e::{CircuitStream, E2eEstablished, E2eStream, E2eTlsBackend};
use crate::error::TunnelError;
use crate::stream::Duplex;
use crate::tls::{
    EstablishedInner, InnerTlsAcceptor, InnerTlsConnector, InnerTlsSession, OuterTlsAcceptor,
    OuterTlsConnector, PeerIdentity, PeerIdentityExtractor,
};

struct ExtractorResolver {
    extractor: Arc<dyn PeerIdentityExtractor>,
}

impl PqWgPeerResolver for ExtractorResolver {
    fn resolve_spki_hash(&self, spki_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.extractor
            .resolve_spki_hash(spki_hash)
            .map(|(spki, _)| spki)
    }
}

fn peer_identity_from_spki(
    extractor: &Arc<dyn PeerIdentityExtractor>,
    spki_der: &[u8],
) -> Result<PeerIdentity, TunnelError> {
    let hash = sha256(spki_der);
    let (trusted_spki, peer) = extractor
        .resolve_spki_hash(&hash)
        .ok_or(TunnelError::InnerTls("peer identity mapping"))?;
    if trusted_spki != spki_der {
        return Err(TunnelError::InnerTls("peer identity mapping"));
    }
    Ok(peer)
}

/// Client side of the WireGuard-style TLS-less PQ hop handshake.
pub struct PqWgInnerConnector {
    connector: PqWgConnector,
    extractor: Arc<dyn PeerIdentityExtractor>,
}

impl PqWgInnerConnector {
    pub fn new(
        identity: PqWgIdentity,
        policy: Policy,
        extractor: Arc<dyn PeerIdentityExtractor>,
    ) -> Result<Self, TunnelError> {
        let resolver = Arc::new(ExtractorResolver {
            extractor: Arc::clone(&extractor),
        });
        let connector = PqWgConnector::new(identity, resolver, policy, PqWgLayer::Hop)
            .map_err(|_| TunnelError::InnerTls("pq-wg connector setup"))?;
        Ok(Self {
            connector,
            extractor,
        })
    }

    fn establish(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        let established = self
            .connector
            .connect(transport)
            .map_err(|_| TunnelError::InnerTls("pq-wg handshake"))?;
        let negotiated = established.negotiated();
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_pq_wg layer=hop negotiated={negotiated:?}");
        let peer = peer_identity_from_spki(&self.extractor, established.peer_spki())?;
        Ok(EstablishedInner::new(
            Box::new(established),
            InnerTlsSession::from_verified_pq_wg(peer, negotiated),
        ))
    }
}

impl InnerTlsConnector for PqWgInnerConnector {
    fn connect(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        self.establish(transport)
    }
}

/// Server side of the WireGuard-style TLS-less PQ hop handshake.
pub struct PqWgInnerAcceptor {
    acceptor: PqWgAcceptor,
    extractor: Arc<dyn PeerIdentityExtractor>,
}

impl PqWgInnerAcceptor {
    pub fn new(
        identity: PqWgIdentity,
        policy: Policy,
        extractor: Arc<dyn PeerIdentityExtractor>,
    ) -> Result<Self, TunnelError> {
        let resolver = Arc::new(ExtractorResolver {
            extractor: Arc::clone(&extractor),
        });
        let acceptor = PqWgAcceptor::new(identity, resolver, policy, PqWgLayer::Hop)
            .map_err(|_| TunnelError::InnerTls("pq-wg acceptor setup"))?;
        Ok(Self {
            acceptor,
            extractor,
        })
    }

    fn establish(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        let established = self
            .acceptor
            .accept(transport)
            .map_err(|_| TunnelError::InnerTls("pq-wg handshake"))?;
        let negotiated = established.negotiated();
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_pq_wg layer=hop negotiated={negotiated:?}");
        let peer = peer_identity_from_spki(&self.extractor, established.peer_spki())?;
        Ok(EstablishedInner::new(
            Box::new(established),
            InnerTlsSession::from_verified_pq_wg(peer, negotiated),
        ))
    }
}

impl InnerTlsAcceptor for PqWgInnerAcceptor {
    fn accept(&self, transport: Box<dyn Duplex>) -> Result<EstablishedInner, TunnelError> {
        self.establish(transport)
    }
}

/// E2E WireGuard-style TLS-less PQ encryption over a circuit byte stream.
pub struct PqWgE2eBackend {
    connector: Arc<PqWgConnector>,
    acceptor: Arc<PqWgAcceptor>,
    extractor: Arc<dyn PeerIdentityExtractor>,
}

impl PqWgE2eBackend {
    pub fn new(
        identity: PqWgIdentity,
        policy: Policy,
        extractor: Arc<dyn PeerIdentityExtractor>,
    ) -> Result<Self, TunnelError> {
        let resolver: Arc<dyn PqWgPeerResolver> = Arc::new(ExtractorResolver {
            extractor: Arc::clone(&extractor),
        });
        let connector = PqWgConnector::new(identity.clone(), Arc::clone(&resolver), policy, PqWgLayer::E2e)
            .map_err(|_| TunnelError::InnerTls("pq-wg e2e connector setup"))?;
        let acceptor = PqWgAcceptor::new(identity, resolver, policy, PqWgLayer::E2e)
            .map_err(|_| TunnelError::InnerTls("pq-wg e2e acceptor setup"))?;
        Ok(Self {
            connector: Arc::new(connector),
            acceptor: Arc::new(acceptor),
            extractor,
        })
    }
}

impl E2eStream for PqWgStream<CircuitStream<'_>> {
    fn close_stream(&mut self) -> io::Result<()> {
        let until = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match self.close_notify() {
                Ok(()) => break,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(error) => return Err(error),
            }
            let progress = self.progress_io()?;
            let remaining = until.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
            if !progress.advanced { self.wait_progress(remaining, progress.write)?; }
        }
        while self.has_pending_output() {
            let progress = self.progress_io()?;
            let remaining = until.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
            if !progress.advanced && self.has_pending_output() {
                self.wait_progress(remaining, progress.write)?;
            }
        }
        self.get_mut().send_close_until(until)
    }

    fn read_with_authenticated_eof(&mut self, out: &mut [u8]) -> io::Result<usize> {
        PqWgStream::read_with_authenticated_eof(self, out)
    }

    #[cfg(target_os = "linux")]
    fn finish_dedicated(&mut self) -> Result<(), TunnelError> {
        self.close_notify()?;
        self.get_mut().send_close()
    }

    #[cfg(target_os = "linux")]
    fn wait_dedicated_close(&mut self) -> Result<(), TunnelError> {
        let mut byte = [0u8; 1];
        match self.read_with_authenticated_eof(&mut byte) {
            Ok(0) => self.get_mut().wait_close(),
            Ok(_) => Err(crate::CircuitReject::UnexpectedFrame.into()),
            Err(error) => Err(error.into()),
        }
    }
}

impl E2eTlsBackend for PqWgE2eBackend {
    fn connect<'a>(&self, transport: CircuitStream<'a>) -> Result<E2eEstablished<'a>, TunnelError> {
        let established = self
            .connector
            .connect(transport)
            .map_err(|_| TunnelError::InnerTls("pq-wg e2e handshake"))?;
        let negotiated = established.negotiated();
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_pq_wg layer=e2e negotiated={negotiated:?}");
        let peer = peer_identity_from_spki(&self.extractor, established.peer_spki())?;
        Ok(E2eEstablished::new(
            Box::new(established),
            InnerTlsSession::from_verified_pq_wg(peer, negotiated),
        ))
    }

    fn accept<'a>(&self, transport: CircuitStream<'a>) -> Result<E2eEstablished<'a>, TunnelError> {
        let established = self
            .acceptor
            .accept(transport)
            .map_err(|_| TunnelError::InnerTls("pq-wg e2e handshake"))?;
        let negotiated = established.negotiated();
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_pq_wg layer=e2e negotiated={negotiated:?}");
        let peer = peer_identity_from_spki(&self.extractor, established.peer_spki())?;
        Ok(E2eEstablished::new(
            Box::new(established),
            InnerTlsSession::from_verified_pq_wg(peer, negotiated),
        ))
    }
}

// --- PKI identity extraction -------------------------------------------------

/// A node identity derived from a `NodeIdentity` management object that
/// `boreas-pki`'s `ManagementTrust` already verified.
///
/// There is deliberately no unchecked constructor: [`Self::from_verified_object`]
/// accepts only a [`VerifiedObject`] plus a [`boreas_pki::VerifiedNetworkContext`], rejects any other object body, and derives
/// the expected SubjectPublicKeyInfo from the object's ML-DSA public key. An
/// arbitrary `key + role` pair cannot be labelled "verified" through this API.
///
/// `not_before` / `expires` are exposed for the caller: validity, generation and
/// revocation must be re-checked with a trusted clock for each business action
/// and recovery, not only once at handshake time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNodeIdentity {
    net_id: [u8; 16],
    node_id: u16,
    identity_generation: u64,
    role: NodeRole,
    home_core_id: u8,
    vip: [u8; 4],
    policy: Option<boreas_pki::VerifiedNetworkContext>,
    not_before: u64,
    expires: u64,
    public_key_spki: Vec<u8>,
}

impl VerifiedNodeIdentity {
    pub fn from_verified_object(
        object: &VerifiedObject,
        policy: &boreas_pki::VerifiedNetworkContext,
    ) -> Result<Self, TunnelError> {
        let body = verified_node_body(object, Some(policy))?;
        if body.net_id != policy.net_id() {
            return Err(TunnelError::Unsupported("identity network mismatch"));
        }
        let overlay = boreas_pki::OverlayPrefix::new(policy.overlay_base(), 16)
            .map_err(|_| TunnelError::Unsupported("non-private runtime network prefix"))?;
        Self::from_validated_body(body, Some(*policy), overlay)
    }

    /// Explicitly unbound compatibility path for hop-only diagnostics. The
    /// resulting identity cannot authorize an E2E packet path.
    pub fn from_verified_object_legacy_for_hop_only(
        object: &VerifiedObject,
    ) -> Result<Self, TunnelError> {
        let body = verified_node_body(object, None)?;
        Self::from_validated_body(body, None, boreas_pki::OverlayPrefix::DEFAULT)
    }

    fn from_validated_body(
        body: &boreas_proto::objects::NodeIdentity,
        policy: Option<boreas_pki::VerifiedNetworkContext>,
        overlay: boreas_pki::OverlayPrefix,
    ) -> Result<Self, TunnelError> {
        let expected_vip = overlay
            .vip(
                body.home_core_id,
                body.vip[3],
                match body.role {
                    boreas_proto::objects::NodeRole::Edge => boreas_pki::NodeRole::Edge,
                    boreas_proto::objects::NodeRole::Core => boreas_pki::NodeRole::Core,
                    boreas_proto::objects::NodeRole::EnrollmentService => {
                        boreas_pki::NodeRole::EnrollmentService
                    }
                },
            )
            .map_err(|_| TunnelError::Unsupported("invalid identity VIP"))?;
        if body.vip != expected_vip {
            return Err(TunnelError::Unsupported("identity VIP mismatch"));
        }
        let expected_node_id = boreas_pki::node_id(
            body.home_core_id,
            body.vip[3],
            match body.role {
                boreas_proto::objects::NodeRole::Edge => boreas_pki::NodeRole::Edge,
                boreas_proto::objects::NodeRole::Core => boreas_pki::NodeRole::Core,
                boreas_proto::objects::NodeRole::EnrollmentService => {
                    boreas_pki::NodeRole::EnrollmentService
                }
            },
        )
        .map_err(|_| TunnelError::Unsupported("invalid identity node mapping"))?;
        if body.node_id != expected_node_id {
            return Err(TunnelError::Unsupported("identity node mapping mismatch"));
        }
        if body.node_id == 0 || body.identity_generation == 0 {
            return Err(TunnelError::Unsupported("invalid identity fields"));
        }
        if body.identity_pub_mldsa.is_empty() {
            return Err(TunnelError::Unsupported("missing identity key"));
        }
        let oid = match body.mldsa_parameter_set {
            MldsaParameterSet::Mldsa65 => ML_DSA_65_OID,
            MldsaParameterSet::Mldsa87 => ML_DSA_87_OID,
        };
        Ok(Self {
            net_id: body.net_id,
            node_id: body.node_id,
            identity_generation: body.identity_generation,
            role: map_object_role(body.role),
            home_core_id: body.home_core_id,
            vip: body.vip,
            policy,
            not_before: body.not_before,
            expires: body.expires,
            public_key_spki: ml_dsa_spki(oid, &body.identity_pub_mldsa),
        })
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn node_id(&self) -> u16 {
        self.node_id
    }

    pub fn identity_generation(&self) -> u64 {
        self.identity_generation
    }

    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// IPv4 VIP authenticated by the verified signed NodeIdentity body.
    pub fn vip(&self) -> [u8; 4] {
        self.vip
    }

    pub fn peer_identity(&self) -> PeerIdentity {
        match self.policy {
            Some(policy) => PeerIdentity::policy_bound(
                self.net_id,
                self.node_id,
                self.identity_generation,
                self.role,
                policy,
            )
            .expect("validated identity and policy share network id"),
            None => PeerIdentity::legacy_default(
                self.net_id,
                self.node_id,
                self.identity_generation,
                self.role,
            ),
        }
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn expires(&self) -> u64 {
        self.expires
    }
}

fn verified_node_body<'a>(
    object: &'a VerifiedObject,
    policy: Option<&boreas_pki::VerifiedNetworkContext>,
) -> Result<&'a boreas_proto::objects::NodeIdentity, TunnelError> {
    let management = object.object();
    let ObjectBody::NodeIdentity(body) = &management.body else {
        return Err(TunnelError::Unsupported("not a NodeIdentity object"));
    };
    if management.net_id != body.net_id || body.net_id == [0; 16] {
        return Err(TunnelError::Unsupported("identity network mismatch"));
    }
    let role = match body.role {
        ObjectRole::Edge => boreas_pki::NodeRole::Edge,
        ObjectRole::Core => boreas_pki::NodeRole::Core,
        ObjectRole::EnrollmentService => boreas_pki::NodeRole::EnrollmentService,
    };
    if let Some(policy) = policy
        && policy.overlay_base() != boreas_pki::OverlayPrefix::DEFAULT.base()
        && !matches!(management.extensions.as_slice(), [evidence]
            if evidence.id == boreas_proto::objects::OFFLINE_IPV4_POOL_MIGRATION_EXTENSION
                && evidence.critical
                && evidence.value.len() == 64
                && evidence.value[..32] == policy.policy_digest())
    {
        return Err(TunnelError::Unsupported("identity pool migration policy mismatch"));
    }
    let overlay = match policy {
        Some(policy) => boreas_pki::OverlayPrefix::new(policy.overlay_base(), 16)
            .map_err(|_| TunnelError::Unsupported("invalid verified policy prefix"))?,
        None => boreas_pki::OverlayPrefix::DEFAULT,
    };
    let vip = overlay
        .vip(body.home_core_id, body.vip[3], role)
        .map_err(|_| TunnelError::Unsupported("invalid identity VIP"))?;
    if body.vip != vip {
        return Err(TunnelError::Unsupported("identity VIP mismatch"));
    }
    let node_id = boreas_pki::node_id(body.home_core_id, body.vip[3], role)
        .map_err(|_| TunnelError::Unsupported("invalid identity node mapping"))?;
    if body.node_id != node_id || body.node_id == 0 || body.identity_generation == 0 {
        return Err(TunnelError::Unsupported("identity node mapping mismatch"));
    }
    if body.identity_pub_mldsa.is_empty() {
        return Err(TunnelError::Unsupported("missing identity key"));
    }
    Ok(body)
}

/// RFC 9881 id-ml-dsa-65 OID content (2.16.840.1.101.3.4.3.18).
const ML_DSA_65_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
/// RFC 9881 id-ml-dsa-87 OID content (2.16.840.1.101.3.4.3.19).
const ML_DSA_87_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

fn map_object_role(role: ObjectRole) -> NodeRole {
    match role {
        ObjectRole::Edge => NodeRole::Edge,
        ObjectRole::Core => NodeRole::Core,
        ObjectRole::EnrollmentService => NodeRole::EnrollmentService,
    }
}

fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    let mut out = Vec::with_capacity(1 + significant.len());
    out.push(0x80 | (significant.len() as u8));
    out.extend_from_slice(significant);
    out
}

/// Build the DER SubjectPublicKeyInfo for a raw ML-DSA public key.
///
/// SPKI = SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING { 0x00 || key } }.
/// The certificate must carry exactly this key; comparing the whole SPKI binds
/// the certificate to the management object's identity key.
fn ml_dsa_spki(oid: &[u8], raw_key: &[u8]) -> Vec<u8> {
    let mut algorithm = Vec::with_capacity(oid.len() + 2);
    algorithm.push(0x30);
    algorithm.extend(der_length(oid.len() + 2));
    algorithm.push(0x06);
    algorithm.extend(der_length(oid.len()));
    algorithm.extend_from_slice(oid);

    let mut key = Vec::with_capacity(raw_key.len() + 2);
    key.push(0x03);
    key.extend(der_length(raw_key.len() + 1));
    key.push(0x00);
    key.extend_from_slice(raw_key);

    let mut spki = Vec::with_capacity(algorithm.len() + key.len() + 2);
    spki.push(0x30);
    spki.extend(der_length(algorithm.len() + key.len()));
    spki.extend(algorithm);
    spki.extend(key);
    spki
}

/// Extracts peer identity by exact SubjectPublicKeyInfo binding against a trust
/// store of already-validated [`VerifiedNodeIdentity`] values.
///
/// The TLS backend has verified the certificate chain to the Boreas identity CA
/// before this runs. This extractor does not trust a fingerprint: it decodes
/// the leaf, compares its SPKI byte-for-byte with the identity key recorded in
/// the management object, and returns the corresponding claims. Zero or more
/// than one match is rejected. Certificate parsing must not panic on hostile
/// DER; failures return `None`.
pub struct PkiIdentityExtractor {
    trusted: Vec<VerifiedNodeIdentity>,
}

impl PkiIdentityExtractor {
    pub fn new(trusted: Vec<VerifiedNodeIdentity>) -> Result<Self, TunnelError> {
        if trusted.is_empty() {
            return Err(TunnelError::Unsupported("empty trust store"));
        }
        for (index, identity) in trusted.iter().enumerate() {
            if identity.public_key_spki.is_empty()
                || identity.net_id == [0u8; 16]
                || identity.node_id == 0
                || identity.identity_generation == 0
            {
                return Err(TunnelError::Unsupported("invalid trusted identity"));
            }
            for other in &trusted[index + 1..] {
                if other.public_key_spki == identity.public_key_spki {
                    return Err(TunnelError::Unsupported("duplicate identity key"));
                }
            }
        }
        Ok(Self { trusted })
    }

    /// Return the signed VIP only when `certificate_der` is the exact-SPKI
    /// certificate owner of the supplied peer identity. This trust-store lookup
    /// is not a fresh authorization decision: callers must independently enforce
    /// current fresh status (including validity, generation and revocation)
    /// before using the result for an action.
    pub fn signed_vip_for_verified_peer(
        &self,
        peer: PeerIdentity,
        certificate_der: &[u8],
    ) -> Option<[u8; 4]> {
        let extracted = self.extract(certificate_der)?;
        if extracted != peer {
            return None;
        }
        let mut matched = None;
        for identity in &self.trusted {
            if identity.net_id == peer.net_id
                && identity.node_id == peer.node_id
                && identity.identity_generation == peer.identity_generation
                && identity.role == peer.role
            {
                if matched.is_some() {
                    return None;
                }
                matched = Some(identity.vip);
            }
        }
        matched
    }
}

fn validated_peer_identity(identity: &VerifiedNodeIdentity) -> Option<PeerIdentity> {
    // Recheck the address under the same authenticated policy used to
    // construct this identity, not under the legacy fixed overlay.
    let overlay = match identity.policy {
        Some(policy) => boreas_pki::OverlayPrefix::new(policy.overlay_base(), 16).ok()?,
        None => boreas_pki::OverlayPrefix::DEFAULT,
    };
    let expected_vip = overlay
        .vip(
            identity.home_core_id,
            identity.vip[3],
            match identity.role {
                NodeRole::Edge => boreas_pki::NodeRole::Edge,
                NodeRole::Core => boreas_pki::NodeRole::Core,
                NodeRole::EnrollmentService => boreas_pki::NodeRole::EnrollmentService,
            },
        )
        .ok()?;
    if identity.vip != expected_vip {
        return None;
    }
    Some(identity.peer_identity())
}

impl PeerIdentityExtractor for PkiIdentityExtractor {
    fn extract(&self, certificate_der: &[u8]) -> Option<PeerIdentity> {
        let certificate = X509::from_der(certificate_der).ok()?;
        let spki = certificate.public_key().ok()?.public_key_to_der().ok()?;
        let mut matched = None;
        for identity in &self.trusted {
            if identity.public_key_spki == spki {
                if matched.is_some() {
                    return None;
                }
                matched = Some(identity);
            }
        }
        validated_peer_identity(matched?)
    }

    fn resolve_spki_hash(&self, spki_hash: &[u8; 32]) -> Option<(Vec<u8>, PeerIdentity)> {
        let mut matched = None;
        for identity in &self.trusted {
            if &sha256(&identity.public_key_spki) == spki_hash {
                if matched.is_some() {
                    return None;
                }
                matched = Some(identity);
            }
        }
        let identity = matched?;
        let peer = validated_peer_identity(identity)?;
        Some((identity.public_key_spki.clone(), peer))
    }
}

// --- outer HTTPS/WSS TLS -----------------------------------------------------

/// Outer TLS client using the platform web-PKI trust store.
///
/// Requires TLS 1.3 (both floor and ceiling) and verifies the chain and server
/// name. It never offers the Boreas identity CA and never disables verification.
pub struct OpenSslOuterTlsConnector {
    connector: SslConnector,
}

impl OpenSslOuterTlsConnector {
    pub fn web_pki() -> Result<Self, TunnelError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|_| TunnelError::InnerTls("outer tls context"))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_default_verify_paths()
            .map_err(|_| TunnelError::InnerTls("web pki roots"))?;
        Ok(Self {
            connector: builder.build(),
        })
    }

    /// Test/private-CA constructor: trusts exactly the supplied PEM roots.
    pub fn with_root_certificates(root_pem: &[u8]) -> Result<Self, TunnelError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|_| TunnelError::InnerTls("outer tls context"))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder.set_verify(SslVerifyMode::PEER);
        let roots = X509::stack_from_pem(root_pem)
            .map_err(|_| TunnelError::InnerTls("root certificate"))?;
        if roots.is_empty() {
            return Err(TunnelError::InnerTls("root certificate"));
        }
        for root in roots {
            builder
                .cert_store_mut()
                .add_cert(root)
                .map_err(|_| TunnelError::InnerTls("trust root"))?;
        }
        Ok(Self {
            connector: builder.build(),
        })
    }

    /// Trusts the platform web-PKI roots AND the supplied private PEM roots.
    ///
    /// Allows a WSS client to verify certificates issued by a publicly trusted
    /// CA without requiring manual CA distribution on both ends, while still
    /// accepting an explicitly provisioned private `outer-ca.pem`.
    pub fn with_web_pki_and_roots(root_pem: &[u8]) -> Result<Self, TunnelError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|_| TunnelError::InnerTls("outer tls context"))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_default_verify_paths()
            .map_err(|_| TunnelError::InnerTls("web pki roots"))?;
        let roots = X509::stack_from_pem(root_pem)
            .map_err(|_| TunnelError::InnerTls("root certificate"))?;
        if roots.is_empty() {
            return Err(TunnelError::InnerTls("root certificate"));
        }
        for root in roots {
            builder
                .cert_store_mut()
                .add_cert(root)
                .map_err(|_| TunnelError::InnerTls("trust root"))?;
        }
        Ok(Self {
            connector: builder.build(),
        })
    }
}

impl OuterTlsConnector for OpenSslOuterTlsConnector {
    fn connect(&self, tcp: TcpStream, server_name: &str) -> Result<Box<dyn Duplex>, TunnelError> {
        #[cfg(feature = "record-diagnostics")]
        let tcp = crate::record_diagnostics::Socket(tcp);
        let stream = self
            .connector
            .connect(server_name, crate::stream::queued_tls::QueueIo::new(tcp))
            .map_err(|error| TunnelError::InnerTls(outer_tls_reason("outer handshake", &error)))?;
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_tls layer=outer version={} cipher={}", stream.ssl().version_str(), stream.ssl().current_cipher().map_or("unavailable", |cipher| cipher.name()));
        Ok(Box::new(crate::stream::queued_tls::QueuedTls::new(stream)))
    }
}

/// Outer TLS server for the origin leg. Presents the configured certificate and
/// requires TLS 1.3. Peer (CDN/origin) authentication is a separate concern and
/// is **not** provided by this channel alone.
pub struct OpenSslOuterTlsAcceptor {
    acceptor: SslAcceptor,
}

impl OpenSslOuterTlsAcceptor {
    pub fn from_pem_files(
        certificate_chain: impl AsRef<Path>,
        private_key: impl AsRef<Path>,
    ) -> Result<Self, TunnelError> {
        let mut builder = Self::builder()?;
        builder
            .set_certificate_chain_file(certificate_chain)
            .map_err(|_| TunnelError::InnerTls("outer certificate"))?;
        builder
            .set_private_key_file(private_key, SslFiletype::PEM)
            .map_err(|_| TunnelError::InnerTls("outer private key"))?;
        builder
            .check_private_key()
            .map_err(|_| TunnelError::InnerTls("outer key mismatch"))?;
        Ok(Self {
            acceptor: builder.build(),
        })
    }

    /// Use caller-validated, bounded file contents without reopening paths.
    pub fn from_pem(certificate_chain: &[u8], private_key: &[u8]) -> Result<Self, TunnelError> {
        let mut builder = Self::builder()?;
        let mut chain = X509::stack_from_pem(certificate_chain)
            .map_err(|_| TunnelError::InnerTls("outer certificate"))?
            .into_iter();
        let leaf = chain.next().ok_or(TunnelError::InnerTls("outer certificate"))?;
        builder.set_certificate(&leaf)
            .map_err(|_| TunnelError::InnerTls("outer certificate"))?;
        for certificate in chain {
            builder.add_extra_chain_cert(certificate)
                .map_err(|_| TunnelError::InnerTls("outer certificate chain"))?;
        }
        let key = openssl::pkey::PKey::private_key_from_pem(private_key)
            .map_err(|_| TunnelError::InnerTls("outer private key"))?;
        builder.set_private_key(&key)
            .map_err(|_| TunnelError::InnerTls("outer private key"))?;
        builder.check_private_key()
            .map_err(|_| TunnelError::InnerTls("outer key mismatch"))?;
        Ok(Self { acceptor: builder.build() })
    }

    fn builder() -> Result<openssl::ssl::SslAcceptorBuilder, TunnelError> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(|_| TunnelError::InnerTls("outer tls context"))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| TunnelError::InnerTls("outer tls version"))?;
        Ok(builder)
    }
}

impl OuterTlsAcceptor for OpenSslOuterTlsAcceptor {
    fn accept(&self, tcp: TcpStream) -> Result<Box<dyn Duplex>, TunnelError> {
        #[cfg(feature = "record-diagnostics")]
        let tcp = crate::record_diagnostics::Socket(tcp);
        let stream = self
            .acceptor
            .accept(crate::stream::queued_tls::QueueIo::new(tcp))
            .map_err(|error| TunnelError::InnerTls(outer_tls_reason("outer accept", &error)))?;
        #[cfg(feature = "record-diagnostics")]
        eprintln!("record_chain_tls layer=outer version={} cipher={}", stream.ssl().version_str(), stream.ssl().current_cipher().map_or("unavailable", |cipher| cipher.name()));
        Ok(Box::new(crate::stream::queued_tls::QueuedTls::new(stream)))
    }
}

fn outer_tls_reason<S>(
    stage: &'static str,
    error: &openssl::ssl::HandshakeError<S>,
) -> &'static str {
    let io_error = match error {
        openssl::ssl::HandshakeError::SetupFailure(_) => return "outer tls setup",
        openssl::ssl::HandshakeError::Failure(stream)
        | openssl::ssl::HandshakeError::WouldBlock(stream) => stream.error(),
    };
    let kind = io_error.io_error().map(io::Error::kind);
    match (stage, kind) {
        (_, Some(io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)) => "outer tls timeout",
        (
            "outer handshake",
            Some(io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof),
        ) => "outer handshake reset",
        ("outer accept", Some(io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof)) => {
            "outer accept reset"
        }
        ("outer handshake", _) => "outer handshake",
        _ => "outer accept",
    }
}

// --- diagnostic inner-TLS seam ----------------------------------------------
//
// These helpers retain the strict backend-only exchange API. Unlike the runtime
// adapters above, they do not extract a Boreas identity or authorize a session.
// A successful exchange is not WSS, E2E authorization, or a `G-CRYPTO` gate pass.
// Certificate files are supplied by the caller; this crate never generates keys.

/// Bound for one seam exchange. Production framing stays in `boreas-proto`.
pub const MAX_SEAM_PAYLOAD: usize = 16 * 1024;
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum SeamError {
    Policy(PolicyError),
    Backend(BackendError),
    Io(std::io::ErrorKind),
    PayloadTooLarge,
    PeerClosed,
}

impl From<PolicyError> for SeamError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<BackendError> for SeamError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

/// The only policy this seam will hand to the backend.
pub fn required_policy() -> Policy {
    Policy::production_default()
}

fn require_pq768(policy: Policy) -> Result<Policy, SeamError> {
    if policy.suite != Suite::Pq768 || policy.allow_pq1024 {
        return Err(SeamError::Policy(PolicyError::Pq1024NotEnabled));
    }
    Ok(policy)
}

/// Loopback connector against an already-listening strict acceptor.
pub fn connect_inner(
    address: std::net::SocketAddr,
    certificate: &Path,
    private_key: &Path,
    trust_anchor: &Path,
) -> Result<EstablishedStream<TcpStream>, SeamError> {
    let policy = require_pq768(required_policy())?;
    let connector =
        OpenSslConnector::from_pem_files(certificate, private_key, trust_anchor, policy)?;
    let stream = TcpStream::connect_timeout(&address, HANDSHAKE_WAIT)
        .map_err(|error| SeamError::Io(error.kind()))?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_WAIT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_WAIT));
    Ok(connector.connect(stream)?)
}

/// Accept one loopback inner-TLS connection on an already-bound listener.
pub fn accept_inner(
    listener: &TcpListener,
    certificate: &Path,
    private_key: &Path,
    trust_anchor: &Path,
) -> Result<EstablishedStream<TcpStream>, SeamError> {
    let policy = require_pq768(required_policy())?;
    let acceptor = OpenSslAcceptor::from_pem_files(certificate, private_key, trust_anchor, policy)?;
    let (stream, _) = listener
        .accept()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_WAIT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_WAIT));
    Ok(acceptor.accept(stream)?)
}

/// Write one bounded payload and read the same number of bytes back.
pub fn exchange(
    stream: &mut EstablishedStream<TcpStream>,
    payload: &[u8],
) -> Result<Vec<u8>, SeamError> {
    if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
        return Err(SeamError::PayloadTooLarge);
    }
    stream
        .write_all(payload)
        .map_err(|error| SeamError::Io(error.kind()))?;
    stream
        .flush()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let mut received = vec![0; payload.len()];
    stream
        .read_exact(&mut received)
        .map_err(|error| SeamError::Io(error.kind()))?;
    Ok(received)
}

/// Run the acceptor on a background thread and connect to it.
///
/// The caller owns both identities. A successful return only means the strict
/// backend completed a handshake and echoed `payload`; it does not authorize a
/// node, open a relay circuit, or pass `G-CRYPTO`.
pub fn loopback_echo(
    server_certificate: &Path,
    server_key: &Path,
    client_certificate: &Path,
    client_key: &Path,
    trust_anchor: &Path,
    payload: &[u8],
) -> Result<Vec<u8>, SeamError> {
    if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
        return Err(SeamError::PayloadTooLarge);
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| SeamError::Io(error.kind()))?;
    let address = listener
        .local_addr()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let server_certificate = server_certificate.to_path_buf();
    let server_key = server_key.to_path_buf();
    let trust = trust_anchor.to_path_buf();
    let expected = payload.to_vec();
    let server = thread::spawn(move || -> Result<(), SeamError> {
        let mut accepted = accept_inner(&listener, &server_certificate, &server_key, &trust)?;
        let echoed = exchange(&mut accepted, &expected)?;
        if echoed != expected {
            return Err(SeamError::PeerClosed);
        }
        Ok(())
    });
    let mut client = connect_inner(address, client_certificate, client_key, trust_anchor)?;
    let echoed = exchange(&mut client, payload)?;
    match server.join() {
        Ok(Ok(())) => Ok(echoed),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(SeamError::PeerClosed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seam_refuses_anything_but_the_pq768_policy() {
        let policy = required_policy();
        assert_eq!(policy.suite, Suite::Pq768);
        assert!(!policy.allow_pq1024);
        assert!(require_pq768(policy).is_ok());
        assert!(payload_bound_rejects_empty());
    }

    fn payload_bound_rejects_empty() -> bool {
        matches!(
            exchange_without_socket(&[]),
            Err(SeamError::PayloadTooLarge)
        )
    }

    fn exchange_without_socket(payload: &[u8]) -> Result<(), SeamError> {
        if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
            Err(SeamError::PayloadTooLarge)
        } else {
            Ok(())
        }
    }

    #[test]
    fn oversized_seam_payload_is_rejected_before_io() {
        let payload = vec![0u8; MAX_SEAM_PAYLOAD + 1];
        assert!(matches!(
            exchange_without_socket(&payload),
            Err(SeamError::PayloadTooLarge)
        ));
    }
}
