//! OpenSSL-backed Boreas inner-TLS connector and acceptor.
//!
//! This module intentionally exposes only the reviewed pq768 profile.  It is
//! not a general purpose TLS configuration surface: callers cannot widen the
//! group, signature-algorithm, TLS-version, or cipher-suite set.  Application
//! identity extraction and authorization remain deliberately separate; this
//! backend returns the verified peer certificate so the application layer can
//! perform the exact `net_id` / role / NodeID / generation checks required by
//! the plan.  A completed handshake alone is not application authorization.

use std::io::{self, Read, Write};
use std::path::Path;

use foreign_types_shared::ForeignTypeRef;
use openssl::asn1::Asn1Object;
use openssl::error::ErrorStack;
use openssl::pkey::{KeyType, PKey, Private};
use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslRef,
    SslSessionCacheMode, SslStream, SslVerifyMode, SslVersion,
};
use openssl::x509::{X509, X509Ref, X509VerifyResult};

use crate::{
    Aead, HybridGroup, IdentitySignature, NegotiatedParameters, Policy, PolicyError, Suite,
};

/// The sole network-wide, non-secret SNI value used by Boreas inner TLS.
///
/// It deliberately contains no node identifier, invitation secret, or stable
/// user identifier, as required by §4.2 of the master plan.
pub const INNER_SNI: &str = "net.boreas.internal";

const HYBRID_GROUP_NAME: &str = "X25519MLKEM768";
const SIGNATURE_ALGORITHM_NAME: &str = "mldsa65";
const CIPHERSUITES: &str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
const BACKEND_NAME: &str = "OpenSSL (rust-openssl) strict pq768 mTLS";

/// Master-plan §5 budget for a certificate or trust-anchor PEM file/object.
pub const MAX_CERTIFICATE_PEM_BYTES: u64 = 64 * 1024;
/// Local private-key bound; a ML-DSA-65 PKCS#8 key is only a few KiB.
pub const MAX_PRIVATE_KEY_PEM_BYTES: u64 = 16 * 1024;
/// OpenSSL `SSL_CTX_set_verify_depth` upper bound.
///
/// OpenSSL counts *intermediate CA certificates* here, not total chain
/// certificates, so this parameter is **not** the master-plan depth-four
/// bound. The explicit `MAX_CHAIN_CERTIFICATES` total-certificate check in
/// `require_ml_dsa65_verified_chain` is authoritative; this value only keeps
/// OpenSSL's own chain builder from following an unreasonably long path.
pub const MAX_VERIFY_DEPTH: u32 = 4;
/// Master-plan §5 total certificate-chain bound (leaf through trust anchor).
pub const MAX_CHAIN_CERTIFICATES: usize = 4;

/// PEM-encoded local identity and trust-anchor material.
///
/// The certificate and private key must belong together.  The trust anchor is
/// installed in both the certificate store and the separate verify store used
/// by OpenSSL; using only one can leave an implicit host trust path or an
/// unexpectedly empty peer-verification store.  No system roots are loaded.
///
/// `Debug` is custom: it reports byte lengths and redacts all PEM bytes,
/// especially the private key.
#[derive(Clone, Eq, PartialEq)]
pub struct PemIdentity {
    /// PEM bytes for the local ML-DSA-65 leaf certificate.
    pub certificate_pem: Vec<u8>,
    /// PEM bytes for the local ML-DSA-65 private key.
    pub private_key_pem: Vec<u8>,
    /// PEM bytes for the Boreas identity trust anchor certificate.
    pub trust_anchor_pem: Vec<u8>,
}

impl core::fmt::Debug for PemIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PemIdentity")
            .field("certificate_pem_len", &self.certificate_pem.len())
            .field("private_key_pem", &"<redacted>")
            .field("trust_anchor_pem_len", &self.trust_anchor_pem.len())
            .finish()
    }
}

impl PemIdentity {
    /// Load the three required PEM files.
    ///
    /// Each file is read with a hard byte bound before parsing: 64 KiB for the
    /// certificate and trust anchor, 16 KiB for the private key (master plan
    /// §5).  File ownership and permission enforcement belong to the process
    /// bootstrap and key-store layers; this constructor still validates that
    /// the PEM content parses, that both local keys are ML-DSA-65, and that the
    /// certificate's public key equals the private key's public component
    /// before exposing a usable identity to the TLS builders.
    pub fn from_pem_files(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        trust_anchor_path: impl AsRef<Path>,
    ) -> Result<Self, BackendError> {
        let identity = Self {
            certificate_pem: read_bounded_pem(
                certificate_path,
                MAX_CERTIFICATE_PEM_BYTES,
                "certificate",
            )?,
            private_key_pem: read_bounded_pem(
                private_key_path,
                MAX_PRIVATE_KEY_PEM_BYTES,
                "private key",
            )?,
            trust_anchor_pem: read_bounded_pem(
                trust_anchor_path,
                MAX_CERTIFICATE_PEM_BYTES,
                "trust anchor",
            )?,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Parse and validate the local identity material.
    ///
    /// Checks, in order: per-field size bounds (also for in-memory callers),
    /// ML-DSA-65 leaf certificate and key types, and equality of the
    /// certificate SPKI with the private key's public component.  The last
    /// check makes the `from_pem_files` "certificate/key match" contract true
    /// in this module instead of relying only on the later
    /// `SslContextBuilder::check_private_key` defense-in-depth call.
    fn validate(&self) -> Result<ValidatedIdentity, BackendError> {
        if self.certificate_pem.len() as u64 > MAX_CERTIFICATE_PEM_BYTES {
            return Err(BackendError::IdentityTooLarge {
                kind: "certificate",
                limit: MAX_CERTIFICATE_PEM_BYTES,
            });
        }
        if self.private_key_pem.len() as u64 > MAX_PRIVATE_KEY_PEM_BYTES {
            return Err(BackendError::IdentityTooLarge {
                kind: "private key",
                limit: MAX_PRIVATE_KEY_PEM_BYTES,
            });
        }
        if self.trust_anchor_pem.len() as u64 > MAX_CERTIFICATE_PEM_BYTES {
            return Err(BackendError::IdentityTooLarge {
                kind: "trust anchor",
                limit: MAX_CERTIFICATE_PEM_BYTES,
            });
        }

        let certificate =
            X509::from_pem(&self.certificate_pem).map_err(BackendError::from_stack)?;
        let trust_anchor =
            X509::from_pem(&self.trust_anchor_pem).map_err(BackendError::from_stack)?;
        let private_key =
            PKey::private_key_from_pem(&self.private_key_pem).map_err(BackendError::from_stack)?;

        require_ml_dsa65_certificate(&certificate)?;
        if !private_key.is_a(KeyType::ML_DSA_65) {
            return Err(BackendError::WrongLocalKeyType);
        }

        let certificate_public_key = certificate.public_key().map_err(BackendError::from_stack)?;
        let certificate_public_der = certificate_public_key
            .public_key_to_der()
            .map_err(BackendError::from_stack)?;
        let private_public_der = private_key
            .public_key_to_der()
            .map_err(BackendError::from_stack)?;
        if certificate_public_der != private_public_der {
            return Err(BackendError::LocalIdentityMismatch);
        }

        Ok(ValidatedIdentity {
            certificate,
            private_key,
            trust_anchor,
        })
    }
}

/// Read a PEM file with a hard bound and reject anything larger before parsing.
fn read_bounded_pem(
    path: impl AsRef<Path>,
    limit: u64,
    kind: &'static str,
) -> Result<Vec<u8>, BackendError> {
    let file =
        std::fs::File::open(path).map_err(|error| BackendError::IdentityIo(error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BackendError::IdentityIo(error.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(BackendError::IdentityTooLarge { kind, limit });
    }
    Ok(bytes)
}

struct ValidatedIdentity {
    certificate: X509,
    private_key: PKey<Private>,
    trust_anchor: X509,
}

/// Backend failures that are deliberately coarse.
///
/// Certificate/private-key byte strings and OpenSSL's full diagnostic stack
/// are never copied into error strings that a data plane might log across a
/// trust boundary.  Human operators can diagnose configuration failures from
/// the phase and OpenSSL reason code in a local-only debug facility added by
/// the daemon layer; network peers observe only a TLS alert/disconnect.
pub enum BackendError {
    /// The requested suite is not the reviewed pq768 profile.
    UnsupportedSuite,
    /// pq1024 remains disabled (the caller tried to enable it here).
    Pq1024NotEnabled,
    /// A PEM file could not be read.
    IdentityIo(String),
    /// A local PEM input exceeded the master-plan size bound.
    IdentityTooLarge { kind: &'static str, limit: u64 },
    /// A local certificate did not contain an ML-DSA-65 public key.
    WrongLocalCertificateKey,
    /// The local private key was not ML-DSA-65.
    WrongLocalKeyType,
    /// The local certificate's public key does not match the private key.
    LocalIdentityMismatch,
    /// OpenSSL refused a configuration or identity operation.
    OpenSslConfiguration,
    /// The handshake did not complete.
    Handshake,
    /// OpenSSL completed the handshake but certificate verification failed.
    PeerCertificateVerification,
    /// The peer presented a verified certificate with the wrong key type.
    WrongPeerKeyType,
    /// A certificate in the verified chain was not signed with ML-DSA-65.
    WrongChainSignatureAlgorithm,
    /// OpenSSL exposed negotiated facts inconsistent with the strict policy.
    NegotiatedMismatch,
}

impl BackendError {
    fn from_stack(_: ErrorStack) -> Self {
        Self::OpenSslConfiguration
    }
}

impl core::fmt::Debug for BackendError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSuite => write!(formatter, "UnsupportedSuite"),
            Self::Pq1024NotEnabled => write!(formatter, "Pq1024NotEnabled"),
            Self::IdentityIo(_) => write!(formatter, "IdentityIo(<redacted>)"),
            Self::IdentityTooLarge { kind, limit } => {
                write!(formatter, "IdentityTooLarge({kind}, {limit})")
            }
            Self::WrongLocalCertificateKey => write!(formatter, "WrongLocalCertificateKey"),
            Self::WrongLocalKeyType => write!(formatter, "WrongLocalKeyType"),
            Self::LocalIdentityMismatch => write!(formatter, "LocalIdentityMismatch"),
            Self::OpenSslConfiguration => write!(formatter, "OpenSslConfiguration"),
            Self::Handshake => write!(formatter, "Handshake"),
            Self::PeerCertificateVerification => {
                write!(formatter, "PeerCertificateVerification")
            }
            Self::WrongPeerKeyType => write!(formatter, "WrongPeerKeyType"),
            Self::WrongChainSignatureAlgorithm => {
                write!(formatter, "WrongChainSignatureAlgorithm")
            }
            Self::NegotiatedMismatch => write!(formatter, "NegotiatedMismatch"),
        }
    }
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BackendError {}

/// Strict pq768 client endpoint (the connector side of a Boreas link).
pub struct OpenSslConnector {
    context: SslContext,
    policy: Policy,
}

/// Strict pq768 server endpoint (the acceptor side of a Boreas link).
pub struct OpenSslAcceptor {
    context: SslContext,
    policy: Policy,
}

/// A completed strict OpenSSL session plus the facts Boreas independently
/// checked after the standard TLS handshake.
///
/// `peer_certificate` is an owned OpenSSL object.  It is returned rather than
/// inventing a Boreas-specific certificate representation or extracting
/// identity claims from an application-undefined certificate field.
pub struct EstablishedStream<S> {
    stream: SslStream<S>,
    negotiated: NegotiatedParameters,
    peer_certificate: X509,
}

impl<S> EstablishedStream<S> {
    /// Facts checked against `Policy::validate_negotiated` before return.
    pub fn negotiated(&self) -> NegotiatedParameters {
        self.negotiated
    }

    /// The verified peer leaf certificate.
    pub fn peer_certificate(&self) -> &X509 {
        &self.peer_certificate
    }

    /// Access the wrapped transport stream without giving up the TLS stream.
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Application bytes already decrypted and buffered inside OpenSSL.
    ///
    /// This is separate from transport readiness: raw socket polling cannot
    /// observe these bytes after a previous TLS read consumed a larger record.
    pub fn ssl_pending(&self) -> usize {
        self.stream.ssl().pending()
    }

    /// Mutably access the wrapped transport stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Replace ownership of the TLS stream after application authorization.
    ///
    /// The negotiated facts and peer certificate are exposed separately so
    /// the caller can retain them while moving the I/O stream into a session.
    pub fn into_parts(self) -> (SslStream<S>, NegotiatedParameters, X509) {
        (self.stream, self.negotiated, self.peer_certificate)
    }
}

impl<S: Read + Write> EstablishedStream<S> {
    /// Read decrypted application bytes from a non-blocking transport.
    ///
    /// Unlike [`Read::read`], this keeps the distinction between "no
    /// ciphertext is queued yet" and a fatal record-layer error: the former is
    /// [`io::ErrorKind::WouldBlock`] and the caller must drain/fill its
    /// WebSocket queues and retry.  A clean peer `close_notify` is
    /// [`io::ErrorKind::UnexpectedEof`].
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.ssl_read(buf).map_err(map_tls_io_error)
    }

    /// Write application bytes to a non-blocking transport.
    ///
    /// [`io::ErrorKind::WouldBlock`] means OpenSSL needs transport write
    /// readiness (the outbound ciphertext queue is full). Drain
    /// `get_mut().drain_ciphertext(..)` and call this method again with the
    /// **exact same slice** (same pointer, length, and contents). OpenSSL may
    /// have retained a partially consumed write; advancing by an assumed byte
    /// count or changing the slice can corrupt the record stream. Only after
    /// `Ok(n)` is returned may the caller advance by `n` bytes. This method
    /// never silently drops plaintext.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.ssl_write(buf).map_err(map_tls_io_error)
    }

    /// Attempt to send TLS `close_notify` while retaining stream ownership.
    ///
    /// One shutdown call sends our notification; it need not wait for the peer's
    /// reply. Non-blocking callers must retry on `WouldBlock` after driving the
    /// transport. Error paths may still drop the stream without a notification.
    pub fn close_notify(&mut self) -> io::Result<()> {
        self.stream.shutdown().map(|_| ()).map_err(map_tls_io_error)
    }
}

fn map_tls_io_error(error: openssl::ssl::Error) -> io::Error {
    let code = error.code();
    if code == ErrorCode::WANT_READ || code == ErrorCode::WANT_WRITE {
        io::ErrorKind::WouldBlock.into()
    } else if code == ErrorCode::ZERO_RETURN {
        io::ErrorKind::UnexpectedEof.into()
    } else {
        io::Error::other("TLS record I/O failed")
    }
}

impl<S: Read + Write> Read for EstablishedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<S: Read + Write> Write for EstablishedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Progress of a non-blocking TLS handshake driven over a byte-queue transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveState {
    /// The engine consumed/produced what it could and needs more transport I/O.
    Incomplete,
    /// The TLS handshake finished locally; call [`HandshakeDriver::finish`] to
    /// run the same certificate/negotiation checks as the blocking API.
    Complete,
}

/// Non-blocking handshake driver for a WebSocket payload byte stream.
///
/// The outer WebSocket state machine owns framing and control messages.  For
/// every event it feeds binary payload bytes through
/// [`Self::transport_mut`]'s `WsByteStream`, calls [`Self::drive_handshake`]
/// until `Incomplete`, then drains produced ciphertext for binary frames.
/// `WouldBlock`/`WANT_READ`/`WANT_WRITE` is normal control flow; any other
/// OpenSSL failure is reported as [`BackendError::Handshake`].
///
/// `Complete` is not authorization: [`Self::finish`] still verifies the peer
/// chain, ML-DSA-65 key/signature algorithms, and the policy gate before an
/// [`EstablishedStream`] exists.
pub struct HandshakeDriver<S> {
    stream: SslStream<S>,
    policy: Policy,
}

impl<S: Read + Write> HandshakeDriver<S> {
    /// Advance the handshake without blocking for transport readiness.
    pub fn drive_handshake(&mut self) -> Result<DriveState, BackendError> {
        match self.stream.do_handshake() {
            Ok(()) => Ok(DriveState::Complete),
            Err(error) => {
                let code = error.code();
                if code == ErrorCode::WANT_READ || code == ErrorCode::WANT_WRITE {
                    Ok(DriveState::Incomplete)
                } else {
                    Err(BackendError::Handshake)
                }
            }
        }
    }

    /// The underlying transport, for inspection only.
    pub fn transport(&self) -> &S {
        self.stream.get_ref()
    }

    /// The underlying transport, used to feed received ciphertext and drain
    /// produced ciphertext between handshake drives.
    pub fn transport_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Validate the completed handshake and convert it into an established
    /// stream.  Calling this before `Complete` fails closed because no verified
    /// peer certificate exists yet.
    pub fn finish(self) -> Result<EstablishedStream<S>, BackendError> {
        finish_established(self.stream, self.policy)
    }
}

/// The backend marker used by the policy layer's explicit integration seam.
///
/// This is not, by itself, an authorization result: the connector/acceptor's
/// completed handshakes remain the only path that creates I/O sessions.
pub struct OpenSslBackend;

impl crate::TlsBackend for OpenSslBackend {
    fn backend_name(&self) -> &'static str {
        BACKEND_NAME
    }
}

fn require_pq768_policy(policy: Policy) -> Result<Policy, BackendError> {
    match policy.suite {
        Suite::Pq768 if !policy.allow_pq1024 => Ok(policy),
        Suite::Pq768 => Err(BackendError::UnsupportedSuite),
        Suite::Pq1024 => Err(BackendError::Pq1024NotEnabled),
    }
}

fn configure_strict_context(
    builder: &mut SslContextBuilder,
    identity: &ValidatedIdentity,
    server_side: bool,
) -> Result<(), BackendError> {
    // TLS 1.3 is a hard floor and a hard ceiling for this profile.  Setting
    // both prevents a future OpenSSL default from silently admitting an
    // unreviewed version above 1.3.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(BackendError::from_stack)?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(BackendError::from_stack)?;

    // One hybrid group only.  The safe rust-openssl 0.10.82 API has no
    // negotiated-group getter.  Because this context offers no other group
    // and TLS 1.3 key shares use the intersection, a completed handshake can
    // only have selected this group.  This is a constrained-context proof,
    // not a claim based on a peer-controlled string.
    builder
        .set_groups_list(HYBRID_GROUP_NAME)
        .map_err(BackendError::from_stack)?;
    builder
        .set_sigalgs_list(SIGNATURE_ALGORITHM_NAME)
        .map_err(BackendError::from_stack)?;
    builder
        .set_ciphersuites(CIPHERSUITES)
        .map_err(BackendError::from_stack)?;

    // First release: no resumption tickets, no session cache.  `NO_TICKET`
    // plus `set_num_tickets(0)` closes both the TLS 1.2-era ticket switch and
    // TLS 1.3 post-handshake ticket issuance.  A resumed session observed
    // after the handshake is still rejected defensively below.
    let options = builder.set_options(SslOptions::NO_TICKET);
    if !options.contains(SslOptions::NO_TICKET) {
        return Err(BackendError::OpenSslConfiguration);
    }
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    builder
        .set_num_tickets(0)
        .map_err(BackendError::from_stack)?;
    // rust-openssl has no boolean "disable 0-RTT" switch.  A zero
    // max_early_data is OpenSSL's standard disable, and this backend never
    // exposes its early-data read/write APIs.
    builder
        .set_max_early_data(0)
        .map_err(BackendError::from_stack)?;

    // Anchors are explicit Boreas trust material, never host roots.  OpenSSL
    // has a context certificate store and a distinct verify store; populate
    // both with the same trust anchor so chain building and TLS peer
    // verification cannot diverge.
    builder
        .cert_store_mut()
        .add_cert(identity.trust_anchor.clone())
        .map_err(BackendError::from_stack)?;

    let mut verify_store =
        openssl::x509::store::X509StoreBuilder::new().map_err(BackendError::from_stack)?;
    verify_store
        .add_cert(identity.trust_anchor.clone())
        .map_err(BackendError::from_stack)?;
    builder
        .set_verify_cert_store(verify_store.build())
        .map_err(BackendError::from_stack)?;

    let verify_mode = if server_side {
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
    } else {
        SslVerifyMode::PEER
    };
    builder.set_verify(verify_mode);
    // Master plan §5: certificate chain depth is bounded to 4.  Without this,
    // OpenSSL's default depth (100) leaves peer-controlled chain length as an
    // unnecessary handshake resource.
    builder.set_verify_depth(MAX_VERIFY_DEPTH);

    builder
        .set_certificate(&identity.certificate)
        .map_err(BackendError::from_stack)?;
    builder
        .set_private_key(&identity.private_key)
        .map_err(BackendError::from_stack)?;
    builder
        .check_private_key()
        .map_err(BackendError::from_stack)?;

    Ok(())
}

fn require_ml_dsa65_certificate(certificate: &X509Ref) -> Result<(), BackendError> {
    let public_key = certificate.public_key().map_err(BackendError::from_stack)?;
    if public_key.is_a(KeyType::ML_DSA_65) {
        Ok(())
    } else {
        Err(BackendError::WrongLocalCertificateKey)
    }
}

fn require_ml_dsa65_peer(certificate: &X509Ref) -> Result<(), BackendError> {
    let public_key = certificate.public_key().map_err(BackendError::from_stack)?;
    if public_key.is_a(KeyType::ML_DSA_65) {
        Ok(())
    } else {
        Err(BackendError::WrongPeerKeyType)
    }
}

fn chain_within_limit(chain_len: usize) -> bool {
    chain_len <= MAX_CHAIN_CERTIFICATES
}

fn require_ml_dsa65_verified_chain(ssl: &SslRef) -> Result<(), BackendError> {
    // `set_sigalgs_list("mldsa65")` constrains CertificateVerify selection
    // but rust-openssl 0.10.82 exposes no `signature_algorithms_cert`
    // setter.  Close that gap in depth: every certificate in OpenSSL's
    // verified chain must carry an ML-DSA-65 subject public key and an
    // ML-DSA-65 signature algorithm.  RFC 9881 assigns id-ml-dsa-65 the OID
    // 2.16.840.1.101.3.4.3.18.  Constructing an `Asn1Object` from the
    // dotted OID and comparing numeric NIDs avoids a localized display
    // name and avoids hard-coding an OpenSSL build-specific NID value.
    let ml_dsa_65 =
        Asn1Object::from_str("2.16.840.1.101.3.4.3.18").map_err(BackendError::from_stack)?;
    let ml_dsa_65_nid = ml_dsa_65.nid();

    let chain = ssl
        .verified_chain()
        .ok_or(BackendError::PeerCertificateVerification)?;
    if chain.is_empty() {
        return Err(BackendError::PeerCertificateVerification);
    }
    // `set_verify_depth` is expressed in intermediates, so enforce the
    // master-plan total-certificate bound explicitly as well.
    if !chain_within_limit(chain.len()) {
        return Err(BackendError::PeerCertificateVerification);
    }
    for certificate in chain {
        require_ml_dsa65_peer(certificate)?;
        if certificate.signature_algorithm().object().nid() != ml_dsa_65_nid {
            return Err(BackendError::WrongChainSignatureAlgorithm);
        }
    }
    Ok(())
}

impl OpenSslConnector {
    /// Build a strict connector from an in-memory PEM identity.
    pub fn from_pem_identity(identity: &PemIdentity, policy: Policy) -> Result<Self, BackendError> {
        let policy = require_pq768_policy(policy)?;
        let identity = identity.validate()?;
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(BackendError::from_stack)?;
        configure_strict_context(&mut builder, &identity, false)?;
        Ok(Self {
            context: builder.build(),
            policy,
        })
    }

    /// Build a strict connector from three PEM files.
    pub fn from_pem_files(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        trust_anchor_path: impl AsRef<Path>,
        policy: Policy,
    ) -> Result<Self, BackendError> {
        Self::from_pem_identity(
            &PemIdentity::from_pem_files(certificate_path, private_key_path, trust_anchor_path)?,
            policy,
        )
    }

    /// Establish an inner-TLS client session over an arbitrary byte stream.
    ///
    /// The argument is intentionally named `transport`, not "TCP stream":
    /// the plan carries this session in a WebSocket binary payload stream,
    /// and this API must not depend on WebSocket message boundaries.
    pub fn connect<S: Read + Write>(
        &self,
        transport: S,
    ) -> Result<EstablishedStream<S>, BackendError> {
        let stream = self
            .new_ssl()?
            .connect(transport)
            .map_err(|_| BackendError::Handshake)?;
        finish_established(stream, self.policy)
    }

    /// Begin a non-blocking client handshake over a WebSocket byte stream.
    ///
    /// This is the client half of the pump described on [`HandshakeDriver`].
    /// The blocking [`Self::connect`] remains the simpler path for tests and
    /// for transports that already provide a blocking `Read + Write`.
    pub fn start_connect<S: Read + Write>(
        &self,
        transport: S,
    ) -> Result<HandshakeDriver<S>, BackendError> {
        let stream =
            SslStream::new(self.new_ssl()?, transport).map_err(BackendError::from_stack)?;
        Ok(HandshakeDriver {
            stream,
            policy: self.policy,
        })
    }

    fn new_ssl(&self) -> Result<Ssl, BackendError> {
        let mut ssl = Ssl::new(&self.context).map_err(BackendError::from_stack)?;
        ssl.set_connect_state();
        // SNI is a network-scoped routing hint only.  Hostname verification
        // is intentionally not enabled: peer authorization is exact Boreas
        // identity validation by the application layer, not a DNS name match.
        ssl.set_hostname(INNER_SNI)
            .map_err(BackendError::from_stack)?;
        Ok(ssl)
    }
}

impl OpenSslAcceptor {
    /// Build a strict acceptor from an in-memory PEM identity.
    pub fn from_pem_identity(identity: &PemIdentity, policy: Policy) -> Result<Self, BackendError> {
        let policy = require_pq768_policy(policy)?;
        let identity = identity.validate()?;

        // Do not start from Mozilla profile helpers: they contain additional
        // settings that would then need to be overridden one by one.  A plain
        // context makes the strict Boreas settings auditable in one place.
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(BackendError::from_stack)?;
        configure_strict_context(&mut builder, &identity, true)?;
        Ok(Self {
            context: builder.build(),
            policy,
        })
    }

    /// Build a strict acceptor from three PEM files.
    pub fn from_pem_files(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        trust_anchor_path: impl AsRef<Path>,
        policy: Policy,
    ) -> Result<Self, BackendError> {
        Self::from_pem_identity(
            &PemIdentity::from_pem_files(certificate_path, private_key_path, trust_anchor_path)?,
            policy,
        )
    }

    /// Accept an inner-TLS server session over an arbitrary byte stream.
    pub fn accept<S: Read + Write>(
        &self,
        transport: S,
    ) -> Result<EstablishedStream<S>, BackendError> {
        let stream = self
            .new_ssl()?
            .accept(transport)
            .map_err(|_| BackendError::Handshake)?;
        finish_established(stream, self.policy)
    }

    /// Begin a non-blocking server handshake over a WebSocket byte stream.
    ///
    /// This is the acceptor half of the pump described on
    /// [`HandshakeDriver`].  The blocking [`Self::accept`] remains available
    /// for transports that already provide a blocking `Read + Write`.
    pub fn start_accept<S: Read + Write>(
        &self,
        transport: S,
    ) -> Result<HandshakeDriver<S>, BackendError> {
        let stream =
            SslStream::new(self.new_ssl()?, transport).map_err(BackendError::from_stack)?;
        Ok(HandshakeDriver {
            stream,
            policy: self.policy,
        })
    }

    fn new_ssl(&self) -> Result<Ssl, BackendError> {
        let mut ssl = Ssl::new(&self.context).map_err(BackendError::from_stack)?;
        ssl.set_accept_state();
        Ok(ssl)
    }
}

fn finish_established<S: Read + Write>(
    stream: SslStream<S>,
    policy: Policy,
) -> Result<EstablishedStream<S>, BackendError> {
    let ssl = stream.ssl();

    // A peer certificate can exist and `verify_result` can be OK before the
    // Finished flight has been processed (notably on a TLS 1.3 server that has
    // received Certificate/CertificateVerify but not the client Finished).
    // `EstablishedStream` may only be created from a fully completed handshake.
    if !ssl.is_init_finished() {
        return Err(BackendError::Handshake);
    }
    if ssl.verify_result() != X509VerifyResult::OK {
        return Err(BackendError::PeerCertificateVerification);
    }

    let peer_certificate = ssl
        .peer_certificate()
        .ok_or(BackendError::PeerCertificateVerification)?;
    require_ml_dsa65_peer(&peer_certificate)?;
    require_ml_dsa65_verified_chain(ssl)?;

    let negotiated = negotiated_parameters(ssl)?;

    // Run the crate's pure policy gate as an independent final check.  The
    // backend does not reach application authorization here; it returns the
    // verified leaf for the SessionHello / application checks to bind exact
    // net_id, role, NodeID, and identity generation.
    policy
        .validate_negotiated(negotiated)
        .map_err(|_| BackendError::NegotiatedMismatch)?;

    Ok(EstablishedStream {
        stream,
        negotiated,
        peer_certificate,
    })
}

fn negotiated_parameters(ssl: &SslRef) -> Result<NegotiatedParameters, BackendError> {
    // `version2()` returns an SslVersion; compare it to OpenSSL's TLS1_3
    // constant.  The textual API is not used because localized/format changes
    // should not become part of a security decision.
    if ssl.version2() != Some(SslVersion::TLS1_3) {
        return Err(BackendError::NegotiatedMismatch);
    }
    if ssl.max_early_data() != 0 {
        return Err(BackendError::NegotiatedMismatch);
    }

    let aead = match ssl.current_cipher().map(|cipher| cipher.name()) {
        Some("TLS_AES_256_GCM_SHA384") => Aead::Aes256GcmSha384,
        Some("TLS_CHACHA20_POLY1305_SHA256") => Aead::ChaCha20Poly1305Sha256,
        _ => return Err(BackendError::NegotiatedMismatch),
    };

    Ok(NegotiatedParameters {
        version: crate::TlsVersion::Tls13,
        group: HybridGroup::X25519MlKem768,
        peer_signature: IdentitySignature::MlDsa65,
        aead,
        resumed: session_reused(ssl),
        // TLS 1.3 early data is never enabled by this backend. `SslStream`
        // is returned only after a full blocking handshake, and no early-data
        // read/write APIs are exposed.  The policy gate type requires an
        // explicit value rather than silently omitting this fact.
        zero_rtt: false,
    })
}

fn session_reused(ssl: &SslRef) -> bool {
    // rust-openssl 0.10.82's safe `SslRef` does not expose a public
    // `session_reused()` getter, but openssl-sys 0.9.118 binds
    // `SSL_session_reused`.  `ForeignTypeRef::as_ptr` returns the borrowed
    // SSL object without transferring ownership.  The OpenSSL call is a
    // state query that does not mutate or free the object; a non-zero result
    // is surfaced and the pure policy gate rejects it before this backend
    // returns an I/O stream.
    //
    // The `ForeignTypeRef` import must stay on the foreign-types-shared copy
    // that openssl 0.10.82 links (0.1.1 through foreign-types 0.3.2); bumping
    // the direct pin to 0.3.x adds a second copy of the trait and this call
    // stops compiling.  See tools/dependencies/crates-review.json.
    unsafe { openssl_sys::SSL_session_reused(ssl.as_ptr()) != 0 }
}

impl From<PolicyError> for BackendError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::Pq1024NotEnabled => Self::Pq1024NotEnabled,
            PolicyError::WrongTlsVersion
            | PolicyError::HybridGroupRequired
            | PolicyError::WrongMlDsaAlgorithm
            | PolicyError::AeadNotAllowed
            | PolicyError::ResumptionForbidden
            | PolicyError::ZeroRttForbidden
            | PolicyError::PeerMismatch => Self::NegotiatedMismatch,
            PolicyError::BackendUnavailable => Self::UnsupportedSuite,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn pem_identity_debug_redacts_every_pem_byte() {
        let identity = PemIdentity {
            certificate_pem: b"CERT-SENTINEL".to_vec(),
            private_key_pem: b"PRIVATE-KEY-SENTINEL".to_vec(),
            trust_anchor_pem: b"ANCHOR-SENTINEL".to_vec(),
        };
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("PemIdentity"));
        assert!(rendered.contains("<redacted>"));
        for sentinel in ["CERT-SENTINEL", "PRIVATE-KEY-SENTINEL", "ANCHOR-SENTINEL"] {
            assert!(
                !rendered.contains(sentinel),
                "PemIdentity Debug leaked {sentinel}: {rendered}"
            );
        }
    }

    #[test]
    fn pem_inputs_are_size_bounded_before_parsing() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "boreas-pem-bound-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temporary PEM directory");
        let certificate = dir.join("certificate.pem");
        std::fs::write(
            &certificate,
            vec![b'A'; MAX_CERTIFICATE_PEM_BYTES as usize + 1],
        )
        .expect("write oversized certificate placeholder");
        let placeholder = dir.join("placeholder.pem");
        std::fs::write(&placeholder, b"not parsed").expect("write placeholder");

        let from_files = PemIdentity::from_pem_files(&certificate, &placeholder, &placeholder);
        let _ = std::fs::remove_dir_all(&dir);
        match from_files {
            Err(BackendError::IdentityTooLarge { kind, limit }) => {
                assert_eq!(kind, "certificate");
                assert_eq!(limit, MAX_CERTIFICATE_PEM_BYTES);
            }
            other => panic!("expected IdentityTooLarge from oversized file, got {other:?}"),
        }

        let in_memory = PemIdentity {
            certificate_pem: vec![0; MAX_CERTIFICATE_PEM_BYTES as usize + 1],
            private_key_pem: Vec::new(),
            trust_anchor_pem: Vec::new(),
        };
        match OpenSslConnector::from_pem_identity(&in_memory, Policy::production_default()) {
            Err(BackendError::IdentityTooLarge { kind, limit }) => {
                assert_eq!(kind, "certificate");
                assert_eq!(limit, MAX_CERTIFICATE_PEM_BYTES);
            }
            Err(other) => {
                panic!("expected IdentityTooLarge before OpenSSL parsing, got {other:?}")
            }
            Ok(_) => panic!("expected IdentityTooLarge before OpenSSL parsing, got a connector"),
        }
    }

    #[test]
    fn chain_limit_is_four_total_certificates_not_four_intermediates() {
        assert_eq!(MAX_CHAIN_CERTIFICATES, 4);
        assert!(chain_within_limit(1));
        assert!(chain_within_limit(MAX_CHAIN_CERTIFICATES));
        assert!(!chain_within_limit(MAX_CHAIN_CERTIFICATES + 1));
        // Four intermediates + leaf + trust anchor is six certificates, which
        // the master-plan total bound must reject even though an OpenSSL
        // verify-depth value of 4 would express only the intermediates.
        assert!(!chain_within_limit(6));
    }

    #[test]
    fn sni_is_network_scoped_and_non_identifying() {
        assert_eq!(INNER_SNI, "net.boreas.internal");
        assert!(!INNER_SNI.contains("node"));
        assert!(!INNER_SNI.contains("invite"));
    }

    #[test]
    fn backend_rejects_every_attempt_to_enable_pq1024() {
        assert!(matches!(
            require_pq768_policy(Policy {
                suite: Suite::Pq1024,
                allow_pq1024: true,
            }),
            Err(BackendError::Pq1024NotEnabled)
        ));
        assert!(matches!(
            require_pq768_policy(Policy {
                suite: Suite::Pq768,
                allow_pq1024: true,
            }),
            Err(BackendError::UnsupportedSuite)
        ));
    }

    #[test]
    fn strict_constants_are_the_single_reviewed_profile() {
        assert_eq!(HYBRID_GROUP_NAME, "X25519MLKEM768");
        assert_eq!(SIGNATURE_ALGORITHM_NAME, "mldsa65");
        assert_eq!(
            CIPHERSUITES,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        );
    }
}
