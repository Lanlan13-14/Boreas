//! Strict parser, policy and verification boundary for release metadata
//! (master plan §10.1–§10.2, `G-SUPPLY`).
//!
//! # What this module does and does not do
//!
//! * [`parse_unsigned`] bounds the input, then parses a *strict* JSON subset:
//!   duplicate keys, unknown fields, non-integer numbers, trailing data,
//!   invalid UTF-8, excessive nesting and oversized collections are all
//!   rejected. The result is [`UnsignedManifest`] — **structure only**.
//! * [`ReleasePolicy`] applies deployment policy (freshness, maximum lifetime,
//!   minimum sequence, architecture selection) to such a structure. It is
//!   diagnostics/preflight, never authorization.
//! * [`verify_release`] is the *only* route to [`VerifiedManifest`], the only
//!   type that may be staged. It follows the mandated order — bound the size,
//!   verify Ed25519 **and** ML-DSA-65 over the exact raw bytes, then parse
//!   those same bytes — and re-parses after verification so a caller can never
//!   verify one byte string and hand over another.
//!
//! # Signature provider
//!
//! With the `openssl-backend` feature, [`verify_dual_signatures`] delegates to
//! [`crate::release_crypto`], which performs real Ed25519 **and** ML-DSA-65
//! verification over the exact bytes with OpenSSL 3.5+ (SPKI DER key parsing
//! plus `KeyType` checks, never a raw-bytes shortcut). Without that feature the
//! default build has no crypto at all and [`verify_release`] fails closed with
//! [`ManifestError::VerificationUnavailable`].
//!
//! Either way there is no `bool` "already verified" parameter, no
//! caller-implementable verifier trait, and no conversion from
//! [`UnsignedManifest`] to [`VerifiedManifest`]: a release is installable only
//! after both signatures verify and the verified bytes are re-parsed.
//!
//! Also deliberately absent: TUF role separation and threshold/root rotation,
//! revocation lists, SBOM/provenance, downloader redirect policy, artifact
//! hash computation, and durable anti-rollback (the [`SequenceLedger`] below is
//! explicitly in-memory). None of them may be claimed on the strength of this
//! module.

use std::collections::BTreeMap;
use std::fmt;

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_ASSETS: usize = 256;
pub const MAX_ASSET_NAME_BYTES: usize = 128;
pub const MAX_ARCH_BYTES: usize = 64;
pub const MAX_SIGNING_KEY_ID_BYTES: usize = 128;
pub const MAX_VERSION_BYTES: usize = 128;
pub const MAX_URL_BYTES: usize = 2048;
/// Ed25519 SPKI DER ceiling (a 32-byte raw key encodes to 44 bytes; 64 leaves
/// room for the standard algorithm-parameter variants).
pub const MAX_ED25519_PUBLIC_KEY_DER_BYTES: usize = 64;
/// ML-DSA-65 SPKI DER ceiling, as agreed with the crypto backend.
pub const MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES: usize = 4096;
pub const MAX_LEDGER_ENTRIES: usize = 1024;
pub const MAX_METADATA_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
/// FIPS 204 ML-DSA-65 public key length.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    TooLarge,
    InvalidJson,
    DuplicateKey,
    Invalid(&'static str),
    Expired,
    ClockBeforeEpoch,
    Equivocation {
        sequence: u64,
    },
    SequenceRollback {
        previous: u64,
        candidate: u64,
    },
    /// The envelope names a key that is not a configured release root.
    UntrustedKey,
    /// Both signatures are required, but this build contains no Ed25519 or
    /// ML-DSA-65 implementation to check them against `raw`. Fail closed.
    VerificationUnavailable,
}
impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("manifest exceeds the configured byte limit"),
            Self::InvalidJson => f.write_str("manifest is not valid strict JSON"),
            Self::DuplicateKey => f.write_str("manifest contains a duplicate JSON object key"),
            Self::Invalid(reason) => write!(f, "invalid manifest: {reason}"),
            Self::Expired => f.write_str("manifest is expired"),
            Self::ClockBeforeEpoch => f.write_str("clock is before Unix epoch"),
            Self::Equivocation { sequence } => {
                write!(f, "different manifest bytes reuse sequence {sequence}")
            }
            Self::SequenceRollback {
                previous,
                candidate,
            } => {
                write!(f, "manifest sequence rollback: {candidate} < {previous}")
            }
            Self::UntrustedKey => f.write_str("manifest was signed by an untrusted key id"),
            Self::VerificationUnavailable => f.write_str(
                "no Ed25519/ML-DSA-65 verifier is compiled in; the release cannot be authenticated",
            ),
        }
    }
}
impl std::error::Error for ManifestError {}

/// A structurally valid but **unverified** manifest.
///
/// Every field is private and there is no mutating accessor: a caller can read
/// the parsed values or the exact original bytes, but cannot patch `assets`
/// after signatures were checked over `raw` (the TOCTOU shape this type is
/// designed to make impossible). It has no conversion to [`VerifiedManifest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedManifest {
    product: String,
    manifest_version: u64,
    sequence: u64,
    published_at: String,
    issued_at: String,
    expires: String,
    min_compatible_state: String,
    signing_key_id: String,
    assets: Vec<UnsignedAsset>,
    /// Exact bounded input bytes. Signatures are checked over these bytes.
    raw: Vec<u8>,
}
impl UnsignedManifest {
    pub fn product(&self) -> &str {
        &self.product
    }
    pub fn manifest_version(&self) -> u64 {
        self.manifest_version
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn published_at(&self) -> &str {
        &self.published_at
    }
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }
    pub fn expires(&self) -> &str {
        &self.expires
    }
    pub fn min_compatible_state(&self) -> &str {
        &self.min_compatible_state
    }
    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }
    pub fn assets(&self) -> &[UnsignedAsset] {
        &self.assets
    }
    /// The exact bytes that a verifier must authenticate.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn expires_unix_seconds(&self) -> u64 {
        parse_timestamp(&self.expires).expect("validated timestamp")
    }
    pub fn issued_unix_seconds(&self) -> u64 {
        parse_timestamp(&self.issued_at).expect("validated timestamp")
    }
    /// Reject an expired manifest against caller-supplied trusted UTC seconds.
    /// This cannot prove the caller's clock is trustworthy, nor that the
    /// publisher did not ship a stale-but-unexpired manifest (freeze attack).
    pub fn check_expiry(&self, trusted_now_unix_seconds: u64) -> Result<(), ManifestError> {
        if trusted_now_unix_seconds >= self.expires_unix_seconds() {
            Err(ManifestError::Expired)
        } else {
            Ok(())
        }
    }
}

/// One artifact of an unverified manifest. The hash is a *claim*: it is only
/// meaningful once the manifest is authenticated and the downloaded bytes are
/// hashed by a future downloader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedAsset {
    name: String,
    arch: String,
    size: u64,
    sha256: String,
    url: String,
}
impl UnsignedAsset {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn arch(&self) -> &str {
        &self.arch
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Canonical lowercase 64-digit SHA-256 text, exactly as claimed by the
    /// manifest. Never computed or verified in this module.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Parse one bounded manifest as unsigned structure only.
///
/// Order matters and is fixed: size bound first, then a strict JSON parse of
/// every byte. Signature verification is *not* performed here and success must
/// never be treated as authorization to stage anything.
pub fn parse_unsigned(bytes: &[u8]) -> Result<UnsignedManifest, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let mut parser = JsonParser {
        text: std::str::from_utf8(bytes).map_err(|_| ManifestError::InvalidJson)?,
        pos: 0,
    };
    parser.skip_whitespace();
    let root = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.text.len() {
        return Err(ManifestError::InvalidJson);
    }

    let mut fields = as_object(root, "top-level value must be an object")?;
    let product = take_string(&mut fields, "product")?;
    if product != "boreas" {
        return Err(ManifestError::Invalid("product must be boreas"));
    }
    let manifest_version = take_u64(&mut fields, "manifest_version")?;
    if manifest_version != 1 {
        return Err(ManifestError::Invalid("unsupported manifest_version"));
    }
    let sequence = take_u64(&mut fields, "sequence")?;
    if sequence == 0 {
        return Err(ManifestError::Invalid("sequence must be positive"));
    }
    let published_at = take_string(&mut fields, "published_at")?;
    let issued_at = take_string(&mut fields, "issued_at")?;
    let expires = take_string(&mut fields, "expires")?;
    let published = parse_timestamp(&published_at).ok_or(ManifestError::Invalid(
        "published_at must be RFC3339 with an explicit UTC offset",
    ))?;
    let issued = parse_timestamp(&issued_at).ok_or(ManifestError::Invalid(
        "issued_at must be RFC3339 with an explicit UTC offset",
    ))?;
    let expiry = parse_timestamp(&expires).ok_or(ManifestError::Invalid(
        "expires must be RFC3339 with an explicit UTC offset",
    ))?;
    if published > issued || issued >= expiry {
        return Err(ManifestError::Invalid(
            "published_at <= issued_at < expires is required",
        ));
    }
    let min_compatible_state = take_string(&mut fields, "min_compatible_state")?;
    validate_identifier(
        &min_compatible_state,
        MAX_VERSION_BYTES,
        "min_compatible_state",
    )?;
    let signing_key_id = take_string(&mut fields, "signing_key_id")?;
    validate_identifier(&signing_key_id, MAX_SIGNING_KEY_ID_BYTES, "signing_key_id")?;
    let assets_value = fields
        .remove("assets")
        .ok_or(ManifestError::Invalid("missing assets"))?;
    if !fields.is_empty() {
        return Err(ManifestError::Invalid(
            "unknown top-level fields are not accepted",
        ));
    }
    let assets = parse_assets(assets_value)?;
    Ok(UnsignedManifest {
        product,
        manifest_version,
        sequence,
        published_at,
        issued_at,
        expires,
        min_compatible_state,
        signing_key_id,
        assets,
        raw: bytes.to_vec(),
    })
}

/// [`parse_unsigned`] plus an expiry check against caller-supplied trusted UTC
/// seconds. Still structure + freshness only: no signature is verified.
pub fn parse_unsigned_at(
    bytes: &[u8],
    trusted_now_unix_seconds: u64,
) -> Result<UnsignedManifest, ManifestError> {
    let manifest = parse_unsigned(bytes)?;
    manifest.check_expiry(trusted_now_unix_seconds)?;
    Ok(manifest)
}

/// A configured release root: the trust anchor a signature must chain to.
///
/// Both keys are **SPKI DER**, so the crypto backend can prove each one is the
/// algorithm it is supposed to be (`KeyType::ED25519` / `KeyType::ML_DSA_65`)
/// instead of trusting a bare byte blob. Constructed through
/// [`ReleaseRoot::new`], which bounds the material; the algorithm check itself
/// happens before any signature is accepted. This is *input* to verification,
/// not proof of anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRoot {
    key_id: String,
    ed25519_public_key_der: Vec<u8>,
    ml_dsa_65_public_key_der: Vec<u8>,
}
impl ReleaseRoot {
    pub fn new(
        key_id: impl Into<String>,
        ed25519_public_key_der: Vec<u8>,
        ml_dsa_65_public_key_der: Vec<u8>,
    ) -> Result<Self, ManifestError> {
        let key_id = key_id.into();
        validate_identifier(&key_id, MAX_SIGNING_KEY_ID_BYTES, "root key_id")?;
        if ed25519_public_key_der.is_empty()
            || ed25519_public_key_der.len() > MAX_ED25519_PUBLIC_KEY_DER_BYTES
        {
            return Err(ManifestError::Invalid("release root Ed25519 DER length"));
        }
        if ml_dsa_65_public_key_der.is_empty()
            || ml_dsa_65_public_key_der.len() > MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES
        {
            return Err(ManifestError::Invalid("release root ML-DSA-65 DER length"));
        }
        Ok(Self {
            key_id,
            ed25519_public_key_der,
            ml_dsa_65_public_key_der,
        })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn ed25519_public_key_der(&self) -> &[u8] {
        &self.ed25519_public_key_der
    }
    pub fn ml_dsa_65_public_key_der(&self) -> &[u8] {
        &self.ml_dsa_65_public_key_der
    }
}

/// The detached dual signature over one manifest's exact raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEnvelope {
    key_id: String,
    ed25519: [u8; 64],
    ml_dsa_65: Vec<u8>,
}
impl SignatureEnvelope {
    pub fn new(
        key_id: impl Into<String>,
        ed25519: [u8; 64],
        ml_dsa_65: Vec<u8>,
    ) -> Result<Self, ManifestError> {
        let key_id = key_id.into();
        validate_identifier(&key_id, MAX_SIGNING_KEY_ID_BYTES, "envelope key_id")?;
        if ml_dsa_65.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(ManifestError::Invalid(
                "envelope ML-DSA-65 signature length",
            ));
        }
        Ok(Self {
            key_id,
            ed25519,
            ml_dsa_65,
        })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn ed25519(&self) -> &[u8; 64] {
        &self.ed25519
    }
    pub fn ml_dsa_65(&self) -> &[u8] {
        &self.ml_dsa_65
    }
}

/// An asset **looked up inside** a verified manifest.
///
/// The field is private and the only producer is
/// [`VerifiedManifest::asset`], so a `VerifiedAsset` can never be built from an
/// unrelated `parse_unsigned` result. That is the membership rule this type
/// exists to enforce: the earlier API took an arbitrary `&UnsignedAsset`, which
/// let an attacker authenticate one manifest and then pass an asset from a
/// different, unsigned one.
#[derive(Clone, Debug)]
pub struct VerifiedAsset<'a> {
    asset: &'a UnsignedAsset,
}
impl<'a> VerifiedAsset<'a> {
    pub fn name(&self) -> &str {
        self.asset.name()
    }
    pub fn arch(&self) -> &str {
        self.asset.arch()
    }
    pub fn size(&self) -> u64 {
        self.asset.size()
    }
    pub fn sha256(&self) -> &str {
        self.asset.sha256()
    }
    pub fn url(&self) -> &str {
        self.asset.url()
    }
    /// Check received artifact bytes against **this** asset's authenticated
    /// size and SHA-256.
    pub fn verify_bytes(&self, downloaded: &[u8]) -> Result<(), ManifestError> {
        verify_asset_bytes_against(self.asset, downloaded)
    }
}

/// Size + hash check against one authenticated asset claim.
fn verify_asset_bytes_against(
    asset: &UnsignedAsset,
    downloaded: &[u8],
) -> Result<(), ManifestError> {
    #[cfg(feature = "openssl-backend")]
    {
        crate::release_crypto::verify_asset_bytes(downloaded, asset.size(), asset.sha256())
            .map_err(ManifestError::Invalid)
    }
    #[cfg(not(feature = "openssl-backend"))]
    {
        if downloaded.len() as u64 != asset.size() {
            return Err(ManifestError::Invalid(
                "artifact size does not match the authenticated manifest",
            ));
        }
        Err(ManifestError::VerificationUnavailable)
    }
}

/// A manifest whose dual signature has been verified over exactly the bytes it
/// was parsed from.
///
/// The field is private and there is no public constructor: the only producer
/// is [`verify_release`], which re-parses `bytes` *after* the signatures check
/// out. Holding one means "these exact bytes were signed by a configured root
/// and were parsed afterwards". It is deliberately **not** stage-able on its
/// own: deployment policy must be applied through
/// [`VerifiedManifest::into_candidate`] first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    manifest: UnsignedManifest,
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &UnsignedManifest {
        &self.manifest
    }
    /// The exact bytes the signatures were checked over.
    pub fn raw_bytes(&self) -> &[u8] {
        self.manifest.raw_bytes()
    }

    /// Look up one asset by exact name inside *this* verified manifest.
    ///
    /// Returning `VerifiedAsset` (rather than handing out `&UnsignedAsset`)
    /// keeps every later size/hash check bound to authenticated bytes.
    pub fn asset(&self, name: &str) -> Result<VerifiedAsset<'_>, ManifestError> {
        let asset = self
            .manifest
            .assets()
            .iter()
            .find(|asset| asset.name() == name)
            .ok_or(ManifestError::Invalid(
                "asset name is not present in the verified manifest",
            ))?;
        Ok(VerifiedAsset { asset })
    }

    /// Apply deployment policy (freshness, lifetime, sequence floor, allowed
    /// architecture) and select the single target asset.
    ///
    /// This is the **only** way to reach [`VerifiedCandidate`], the stage-able
    /// type: a successful `verify_release` proves *who signed it*, not that it
    /// is fresh, not rolled back, or built for this machine.
    pub fn into_candidate(
        self,
        policy: &ReleasePolicy,
        arch: &str,
        trusted_now_unix_seconds: u64,
    ) -> Result<VerifiedCandidate, ManifestError> {
        policy.check(self.manifest(), trusted_now_unix_seconds)?;
        let asset = policy.select_asset(self.manifest(), arch)?;
        Ok(VerifiedCandidate {
            asset_name: asset.name().to_owned(),
            arch: arch.to_owned(),
            manifest: self,
        })
    }
}

/// A verified manifest that has also passed deployment policy and has exactly
/// one selected asset for the target architecture.
///
/// Private fields, no public constructor: produced only by
/// [`VerifiedManifest::into_candidate`]. This is the only type from which a
/// future installer may derive a [`crate::Candidate`] and stage bytes.
#[derive(Clone, Debug)]
pub struct VerifiedCandidate {
    manifest: VerifiedManifest,
    asset_name: String,
    arch: String,
}
impl VerifiedCandidate {
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
    pub fn arch(&self) -> &str {
        &self.arch
    }
    pub fn sequence(&self) -> u64 {
        self.manifest.manifest().sequence()
    }
    /// The selected asset, re-resolved inside the verified manifest by name.
    pub fn asset(&self) -> Result<VerifiedAsset<'_>, ManifestError> {
        self.manifest.asset(&self.asset_name)
    }
    /// Check received bytes against the selected, authenticated asset.
    pub fn verify_bytes(&self, downloaded: &[u8]) -> Result<(), ManifestError> {
        self.asset()?.verify_bytes(downloaded)
    }
}

/// The only route from untrusted bytes to [`VerifiedManifest`].
///
/// Fixed order (master plan §10.2): bound the size → resolve the signing key id
/// against the configured roots → verify Ed25519 **and** ML-DSA-65 over the raw
/// bytes → parse strictly. The parse in step four reads the same slice that was
/// verified, never a caller-supplied structure, so there is no window in which
/// `assets` could be swapped after verification.
///
/// With the `openssl-backend` feature the signatures are checked for real by
/// [`crate::release_crypto`]. Without it there is no provider at all and the
/// call fails closed with [`ManifestError::VerificationUnavailable`].
pub fn verify_release(
    bytes: &[u8],
    envelope: &SignatureEnvelope,
    roots: &[ReleaseRoot],
) -> Result<VerifiedManifest, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let root = roots
        .iter()
        .find(|root| root.key_id == envelope.key_id)
        .ok_or(ManifestError::UntrustedKey)?;
    verify_dual_signatures(bytes, envelope, root)?;
    let manifest = parse_unsigned(bytes)?;
    if manifest.signing_key_id != envelope.key_id {
        return Err(ManifestError::Invalid(
            "manifest signing_key_id does not match the verified envelope",
        ));
    }
    Ok(VerifiedManifest { manifest })
}

/// Ed25519 AND ML-DSA-65 over `raw`, both required.
///
/// This is the single choke point: an OR here would silently downgrade the
/// dual-signature requirement of §10.2, so the backend must verify both halves
/// and report any length/DER/backend problem as an error.
#[cfg(feature = "openssl-backend")]
fn verify_dual_signatures(
    raw: &[u8],
    envelope: &SignatureEnvelope,
    root: &ReleaseRoot,
) -> Result<(), ManifestError> {
    crate::release_crypto::verify_dual(
        raw,
        root.ed25519_public_key_der(),
        root.ml_dsa_65_public_key_der(),
        envelope.ed25519(),
        envelope.ml_dsa_65(),
    )
    .map_err(ManifestError::Invalid)
}

/// Without the crypto feature nothing can be authenticated; fail closed.
#[cfg(not(feature = "openssl-backend"))]
fn verify_dual_signatures(
    _raw: &[u8],
    _envelope: &SignatureEnvelope,
    _root: &ReleaseRoot,
) -> Result<(), ManifestError> {
    Err(ManifestError::VerificationUnavailable)
}

/// Deployment policy applied to metadata before a download is even attempted.
///
/// This is preflight, not authorization: it can only reject. It must be run on
/// a [`VerifiedManifest`] in production; running it on an [`UnsignedManifest`]
/// is useful for diagnostics and says nothing about authenticity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePolicy {
    allowed_arches: Vec<String>,
    max_lifetime_seconds: u64,
    min_sequence: u64,
}
impl ReleasePolicy {
    pub fn new(
        allowed_arches: Vec<String>,
        max_lifetime_seconds: u64,
        min_sequence: u64,
    ) -> Result<Self, ManifestError> {
        if allowed_arches.is_empty() {
            return Err(ManifestError::Invalid(
                "at least one allowed architecture is required",
            ));
        }
        for arch in &allowed_arches {
            validate_arch(arch)?;
        }
        if max_lifetime_seconds == 0 || max_lifetime_seconds > MAX_METADATA_LIFETIME_SECONDS {
            return Err(ManifestError::Invalid(
                "max_lifetime_seconds must be within (0, 90 days]",
            ));
        }
        Ok(Self {
            allowed_arches,
            max_lifetime_seconds,
            min_sequence,
        })
    }
    pub fn allowed_arches(&self) -> &[String] {
        &self.allowed_arches
    }
    pub fn max_lifetime_seconds(&self) -> u64 {
        self.max_lifetime_seconds
    }
    pub fn min_sequence(&self) -> u64 {
        self.min_sequence
    }

    /// Freshness, lifetime and anti-rollback checks.
    pub fn check(
        &self,
        manifest: &UnsignedManifest,
        trusted_now: u64,
    ) -> Result<(), ManifestError> {
        manifest.check_expiry(trusted_now)?;
        let lifetime = manifest
            .expires_unix_seconds()
            .saturating_sub(manifest.issued_unix_seconds());
        if lifetime > self.max_lifetime_seconds {
            return Err(ManifestError::Invalid(
                "manifest lifetime exceeds the configured maximum",
            ));
        }
        if manifest.sequence() < self.min_sequence {
            return Err(ManifestError::SequenceRollback {
                previous: self.min_sequence,
                candidate: manifest.sequence(),
            });
        }
        Ok(())
    }

    /// The single asset for `arch`. Zero or several matches are both errors:
    /// letting an installer pick "the first of many" is how a downgrade or an
    /// unintended artifact slips through.
    pub fn select_asset<'a>(
        &self,
        manifest: &'a UnsignedManifest,
        arch: &str,
    ) -> Result<&'a UnsignedAsset, ManifestError> {
        validate_arch(arch)?;
        if !self.allowed_arches.iter().any(|allowed| allowed == arch) {
            return Err(ManifestError::Invalid(
                "architecture is not allowed by this deployment's release policy",
            ));
        }
        let mut matches = manifest.assets().iter().filter(|asset| asset.arch == arch);
        let first = matches.next().ok_or(ManifestError::Invalid(
            "manifest has no asset for this architecture",
        ))?;
        if matches.next().is_some() {
            return Err(ManifestError::Invalid(
                "manifest has more than one asset for this architecture",
            ));
        }
        Ok(first)
    }
}

/// In-memory equivocation/rollback guard for one product.
///
/// It accepts only [`VerifiedManifest`], so it cannot be fed attacker-chosen
/// bytes by accident. Persistence, atomic storage, root rotation and crash
/// recovery are intentionally **not** implemented: this is not durable
/// anti-rollback state, and the master plan's "persist the content hash" item
/// remains open.
#[derive(Clone, Debug, Default)]
pub struct SequenceLedger {
    highest: u64,
    by_sequence: BTreeMap<u64, Vec<u8>>,
}
impl SequenceLedger {
    pub fn highest_sequence(&self) -> Option<u64> {
        if self.highest == 0 {
            None
        } else {
            Some(self.highest)
        }
    }

    /// Record one verified manifest. Identical bytes for the same sequence are
    /// idempotent; different bytes are equivocation, and a lower sequence is a
    /// rollback attempt.
    pub fn observe(&mut self, manifest: &VerifiedManifest) -> Result<(), ManifestError> {
        let sequence = manifest.manifest().sequence();
        if let Some(existing) = self.by_sequence.get(&sequence) {
            if existing.as_slice() != manifest.raw_bytes() {
                return Err(ManifestError::Equivocation { sequence });
            }
            return Ok(());
        }
        if sequence < self.highest {
            return Err(ManifestError::SequenceRollback {
                previous: self.highest,
                candidate: sequence,
            });
        }
        if self.by_sequence.len() >= MAX_LEDGER_ENTRIES {
            return Err(ManifestError::Invalid(
                "volatile equivocation ledger is at capacity",
            ));
        }
        self.by_sequence
            .insert(sequence, manifest.raw_bytes().to_vec());
        self.highest = self.highest.max(sequence);
        Ok(())
    }
}

fn parse_assets(value: JsonValue) -> Result<Vec<UnsignedAsset>, ManifestError> {
    let JsonValue::Array(values) = value else {
        return Err(ManifestError::Invalid("assets must be an array"));
    };
    if values.is_empty() || values.len() > MAX_ASSETS {
        return Err(ManifestError::Invalid("assets count must be 1..=256"));
    }
    let mut seen = BTreeMap::<String, ()>::new();
    let mut assets = Vec::with_capacity(values.len());
    for value in values {
        let mut fields = as_object(value, "asset must be an object")?;
        let name = take_string(&mut fields, "name")?;
        validate_asset_name(&name)?;
        if seen.insert(name.clone(), ()).is_some() {
            return Err(ManifestError::Invalid("duplicate asset name"));
        }
        let arch = take_string(&mut fields, "arch")?;
        validate_arch(&arch)?;
        let size = take_u64(&mut fields, "size")?;
        if size == 0 {
            return Err(ManifestError::Invalid("asset size must be positive"));
        }
        let sha256 = take_string(&mut fields, "sha256")?;
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ManifestError::Invalid(
                "sha256 must be 64 lowercase hexadecimal digits",
            ));
        }
        let url = take_string(&mut fields, "url")?;
        validate_https_url(&url)?;
        if !fields.is_empty() {
            return Err(ManifestError::Invalid(
                "unknown asset fields are not accepted",
            ));
        }
        assets.push(UnsignedAsset {
            name,
            arch,
            size,
            sha256,
            url,
        });
    }
    Ok(assets)
}

fn validate_asset_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty()
        || name.len() > MAX_ASSET_NAME_BYTES
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return Err(ManifestError::Invalid(
            "asset name must be a safe filename without traversal",
        ));
    }
    Ok(())
}

fn validate_arch(arch: &str) -> Result<(), ManifestError> {
    if arch.is_empty()
        || arch.len() > MAX_ARCH_BYTES
        || !arch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ManifestError::Invalid(
            "arch must be a bounded ASCII architecture token",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, max: usize, field: &'static str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > max
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return Err(ManifestError::Invalid(field));
    }
    Ok(())
}

/// Strict subset of an HTTPS URL, checked without a general-purpose URL parser.
///
/// ```text
/// url     = "https://" authority [ path ]
/// authority = label *( "." label ) [ ":" port ]
/// label   = 1*63( ALPHA / DIGIT / "-" ), no leading or trailing "-"
/// port    = 1*5 DIGIT, value 1..=65535
/// path    = "/" *( unreserved )          ; unreserved = ALPHA / DIGIT / "-._~"
/// ```
///
/// Everything outside that grammar is rejected, which is what makes the check
/// reviewable: there is no userinfo (`@`), no query (`?`), no fragment (`#`),
/// no percent-encoding, no backslash, no whitespace/control byte, no bracketed
/// IPv6 literal, and no dot segment. `https://host?x@evil` therefore fails at
/// the authority label check rather than being silently mis-split, and
/// `https://host:0/`, `https://host:99999/` and `https:///p` are all rejected.
fn validate_https_url(url: &str) -> Result<(), ManifestError> {
    if url.len() > MAX_URL_BYTES {
        return Err(ManifestError::Invalid(
            "asset URL exceeds the configured limit",
        ));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ManifestError::Invalid(
            "asset URL must be printable ASCII without spaces or controls",
        ));
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ManifestError::Invalid("asset URL must use https://"));
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], Some(&rest[index..])),
        None => (rest, None),
    };
    validate_authority(authority)?;
    if let Some(path) = path {
        validate_path(path)?;
    }
    Ok(())
}

fn validate_authority(authority: &str) -> Result<(), ManifestError> {
    if authority.is_empty() || authority.len() > 253 {
        return Err(ManifestError::Invalid(
            "asset URL host is empty or too long",
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(ManifestError::Invalid("asset URL host is empty"));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ManifestError::Invalid("asset URL host label is invalid"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ManifestError::Invalid(
                "asset URL host label starts or ends with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ManifestError::Invalid(
                "asset URL host may contain only letters, digits, dots and hyphens",
            ));
        }
    }
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ManifestError::Invalid(
                "asset URL port is not a decimal number",
            ));
        }
        let value: u32 = port
            .parse()
            .map_err(|_| ManifestError::Invalid("asset URL port is not a decimal number"))?;
        if value == 0 || value > 65535 {
            return Err(ManifestError::Invalid("asset URL port is out of range"));
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ManifestError> {
    if !path.starts_with('/') {
        return Err(ManifestError::Invalid("asset URL path must start with /"));
    }
    for segment in path.split('/') {
        if segment == "." || segment == ".." {
            return Err(ManifestError::Invalid("asset URL path contains traversal"));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(ManifestError::Invalid(
                "asset URL path may contain only unreserved characters",
            ));
        }
    }
    Ok(())
}

fn take_string(
    fields: &mut BTreeMap<String, JsonValue>,
    key: &'static str,
) -> Result<String, ManifestError> {
    match fields.remove(key) {
        Some(JsonValue::String(s)) if !s.is_empty() => Ok(s),
        Some(_) => Err(ManifestError::Invalid(key)),
        None => Err(ManifestError::Invalid("missing required field")),
    }
}

fn take_u64(
    fields: &mut BTreeMap<String, JsonValue>,
    key: &'static str,
) -> Result<u64, ManifestError> {
    match fields.remove(key) {
        Some(JsonValue::U64(n)) => Ok(n),
        Some(JsonValue::I64(n)) if n >= 0 => Ok(n as u64),
        _ => Err(ManifestError::Invalid(key)),
    }
}

fn as_object(
    value: JsonValue,
    error: &'static str,
) -> Result<BTreeMap<String, JsonValue>, ManifestError> {
    match value {
        JsonValue::Object(map) => Ok(map),
        _ => Err(ManifestError::Invalid(error)),
    }
}

/// Strict RFC3339 subset parser: full seconds and explicit `Z` or ±HH:MM
/// offset, optional 1–9 digit fractional seconds. Rejects invalid calendar
/// fields/leap-second labels, normalizes offset, and returns Unix whole seconds.
fn parse_timestamp(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let year = digits(b, 0, 4)? as i64;
    let month = digits(b, 5, 2)?;
    let day = digits(b, 8, 2)?;
    let hour = digits(b, 11, 2)?;
    let minute = digits(b, 14, 2)?;
    let second = digits(b, 17, 2)?;
    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut pos = 19;
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        let start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start || pos - start > 9 {
            return None;
        }
    }
    let offset = match b.get(pos) {
        Some(b'Z') if pos + 1 == b.len() => 0i64,
        Some(sign @ (b'+' | b'-')) if pos + 6 == b.len() && b.get(pos + 3) == Some(&b':') => {
            let oh = digits(b, pos + 1, 2)? as i64;
            let om = digits(b, pos + 4, 2)? as i64;
            if oh > 23 || om > 59 {
                return None;
            }
            let n = oh * 3600 + om * 60;
            if *sign == b'+' { n } else { -n }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let utc = days.checked_mul(86400)? + i64::from(hour * 3600 + minute * 60 + second) - offset;
    u64::try_from(utc).ok()
}

fn digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let slice = bytes.get(start..start + len)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    slice.iter().try_fold(0u32, |n, d| {
        n.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from(month) + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[derive(Debug)]
enum JsonValue {
    Null,
    Bool,
    I64(i64),
    U64(u64),
    Float,
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

/// Minimal strict JSON reader (RFC 8259 subset).
///
/// Written by hand because this crate deliberately has no third-party
/// dependencies, and because a strict reader is easier to audit than a
/// configuration of a general one: every byte is consumed exactly once, the
/// nesting depth and collection sizes are bounded before allocation, duplicate
/// object keys are rejected at every depth, and any trailing byte after the
/// top-level value is an error.
struct JsonParser<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ManifestError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ManifestError::Invalid(
                "manifest JSON nesting exceeds the limit",
            ));
        }
        match self.peek().ok_or(ManifestError::InvalidJson)? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => self.parse_string().map(JsonValue::String),
            b't' => {
                self.expect_literal("true")?;
                Ok(JsonValue::Bool)
            }
            b'f' => {
                self.expect_literal("false")?;
                Ok(JsonValue::Bool)
            }
            b'n' => {
                self.expect_literal("null")?;
                Ok(JsonValue::Null)
            }
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(ManifestError::InvalidJson),
        }
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), ManifestError> {
        if self.text[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(ManifestError::InvalidJson)
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ManifestError> {
        self.pos += 1; // '{'
        let mut fields = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(ManifestError::InvalidJson);
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(ManifestError::InvalidJson);
            }
            self.pos += 1;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            if fields.len() >= MAX_JSON_FIELDS {
                return Err(ManifestError::Invalid(
                    "manifest object exceeds the field-count limit",
                ));
            }
            if fields.insert(key, value).is_some() {
                return Err(ManifestError::DuplicateKey);
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(fields));
                }
                _ => return Err(ManifestError::InvalidJson),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ManifestError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            if items.len() >= MAX_ASSETS {
                return Err(ManifestError::Invalid(
                    "manifest array exceeds the item-count limit",
                ));
            }
            items.push(value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(ManifestError::InvalidJson),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ManifestError> {
        self.pos += 1; // '"'
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(ManifestError::InvalidJson)?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = self.peek().ok_or(ManifestError::InvalidJson)?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let ch = self.parse_unicode_escape()?;
                            out.push(ch);
                        }
                        _ => return Err(ManifestError::InvalidJson),
                    }
                }
                0x00..=0x1f => return Err(ManifestError::InvalidJson),
                _ => {
                    let ch = self.text[self.pos..]
                        .chars()
                        .next()
                        .ok_or(ManifestError::InvalidJson)?;
                    self.pos += ch.len_utf8();
                    out.push(ch);
                }
            }
        }
    }

    /// `\uXXXX`, including the surrogate-pair form. Lone surrogates are not
    /// valid Unicode scalar values, so they are rejected rather than replaced.
    fn parse_unicode_escape(&mut self) -> Result<char, ManifestError> {
        let high = self.parse_hex4()?;
        let scalar = if (0xD800..=0xDBFF).contains(&high) {
            if self.peek() != Some(b'\\') {
                return Err(ManifestError::InvalidJson);
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(ManifestError::InvalidJson);
            }
            self.pos += 1;
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(ManifestError::InvalidJson);
            }
            0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&high) {
            return Err(ManifestError::InvalidJson);
        } else {
            high
        };
        char::from_u32(scalar).ok_or(ManifestError::InvalidJson)
    }

    fn parse_hex4(&mut self) -> Result<u32, ManifestError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self.peek().ok_or(ManifestError::InvalidJson)?;
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(ManifestError::InvalidJson),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonValue, ManifestError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(ManifestError::InvalidJson),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ManifestError::InvalidJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ManifestError::InvalidJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = &self.text[start..self.pos];
        if is_float {
            return Ok(JsonValue::Float);
        }
        if text.starts_with('-') {
            text.parse::<i64>()
                .map(JsonValue::I64)
                .map_err(|_| ManifestError::Invalid("manifest integer is out of range"))
        } else {
            text.parse::<u64>()
                .map(JsonValue::U64)
                .map_err(|_| ManifestError::Invalid("manifest integer is out of range"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::useless_vec)]
    use super::*;

    const GOOD: &str = r#"{"product":"boreas","manifest_version":1,"sequence":4,"published_at":"2026-01-01T00:00:00Z","issued_at":"2026-01-01T00:00:01Z","expires":"2026-02-01T00:00:00Z","min_compatible_state":"state-v1","signing_key_id":"root-1","assets":[{"name":"boreas-linux-x86_64","arch":"x86_64-unknown-linux-gnu","size":42,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"https://releases.example.test/boreas"}]}"#;

    fn parse(s: &str) -> Result<UnsignedManifest, ManifestError> {
        parse_unsigned(s.as_bytes())
    }

    fn root() -> ReleaseRoot {
        // Bounded placeholder SPKI-shaped material: `ReleaseRoot::new` checks
        // only bounds/algorithm-independent length; the DER algorithm check
        // happens inside the crypto backend before any signature is accepted.
        ReleaseRoot::new(
            "root-1",
            vec![7u8; 44],
            vec![9u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        )
        .expect("valid root")
    }

    fn envelope() -> SignatureEnvelope {
        SignatureEnvelope::new("root-1", [1u8; 64], vec![2u8; ML_DSA_65_SIGNATURE_BYTES])
            .expect("valid envelope")
    }

    /// Test-only: the production constructor is `verify_release`, which has no
    /// provider. Child modules can see private fields, parent modules cannot.
    fn verified(bytes: &[u8]) -> VerifiedManifest {
        VerifiedManifest {
            manifest: parse_unsigned(bytes).unwrap(),
        }
    }

    #[test]
    fn valid_unsigned_manifest_is_bounded_and_retains_original_bytes() {
        let m = parse(GOOD).unwrap();
        assert_eq!(m.sequence(), 4);
        assert_eq!(m.product(), "boreas");
        assert_eq!(m.assets().len(), 1);
        assert_eq!(m.assets()[0].arch(), "x86_64-unknown-linux-gnu");
        assert_eq!(m.raw_bytes(), GOOD.as_bytes());
    }

    #[test]
    fn parsed_fields_are_read_only() {
        // Compile-time property made explicit: no `&mut` accessor exists, so a
        // caller cannot edit `assets` after a verifier hashed `raw_bytes()`.
        let m = parse(GOOD).unwrap();
        let assets: &[UnsignedAsset] = m.assets();
        assert_eq!(assets.len(), 1);
        assert_eq!(m.signing_key_id(), "root-1");
        assert_eq!(m.min_compatible_state(), "state-v1");
    }

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        let s = GOOD.replace(
            "\"product\":\"boreas\",",
            "\"product\":\"boreas\",\"product\":\"boreas\",",
        );
        assert_eq!(parse(&s), Err(ManifestError::DuplicateKey));
        let s = GOOD.replace(
            "\"name\":\"boreas-linux-x86_64\",",
            "\"name\":\"boreas-linux-x86_64\",\"name\":\"boreas-linux-x86_64\",",
        );
        assert_eq!(parse(&s), Err(ManifestError::DuplicateKey));
    }

    #[test]
    fn rejects_unknown_fields_and_non_integer_numbers() {
        assert!(parse(&GOOD.replace("\"sequence\":4", "\"sequence\":4.0")).is_err());
        assert!(parse(&GOOD.replace("\"sequence\":4", "\"sequence\":4e0")).is_err());
        assert!(parse(&GOOD.replace("\"sequence\":4", "\"sequence\":-4")).is_err());
        assert!(
            parse(&GOOD.replace(
                "\"product\":\"boreas\",",
                "\"product\":\"boreas\",\"future\":true,"
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_trailing_data_bom_and_invalid_utf8() {
        assert_eq!(
            parse(&format!("{GOOD} {{}}")),
            Err(ManifestError::InvalidJson)
        );
        // Trailing whitespace is legal JSON and is retained verbatim in `raw`.
        // Semantic fields must match the compact fixture; the bytes must not.
        let padded = format!("{GOOD}\n\n");
        let padded_manifest = parse(&padded).expect("trailing whitespace is valid JSON");
        let compact = parse(GOOD).unwrap();
        assert_eq!(padded_manifest.sequence(), compact.sequence());
        assert_eq!(padded_manifest.product(), compact.product());
        assert_eq!(padded_manifest.assets(), compact.assets());
        assert_eq!(padded_manifest.raw_bytes(), padded.as_bytes());
        assert_ne!(padded_manifest.raw_bytes(), compact.raw_bytes());
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(GOOD.as_bytes());
        assert!(parse_unsigned(&bom).is_err());
        let bad_utf8 = [b'{', 0xFF, b'}'];
        assert_eq!(parse_unsigned(&bad_utf8), Err(ManifestError::InvalidJson));
    }

    #[test]
    fn rejects_path_traversal_and_bad_assets() {
        for name in ["../evil", "a/../../b", "%2e%2e", "..", "a\\b"] {
            let s = GOOD.replace("boreas-linux-x86_64", name);
            assert!(parse(&s).is_err(), "{name}");
        }
        let s = GOOD.replace(
            "\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"sha256\":\"AAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        );
        assert!(parse(&s).is_err());
        let s = GOOD.replace("\"size\":42", "\"size\":0");
        assert!(parse(&s).is_err());
    }

    #[test]
    fn url_must_be_the_strict_https_subset() {
        for url in [
            "http://example.test/a",
            "https://u@example.test/a",
            "https://example.test/a/../b",
            "https://example.test/%2e%2e/x",
            "https://example.test/a#frag",
            "https://example.test/a?x=1",
            // The authority/query confusion case: `?x@` must not be read as
            // userinfo and must not be accepted.
            "https://example.test?x@evil.test/a",
            // Empty host, empty port, zero port, out-of-range port.
            "https:///path",
            "https://:443/path",
            "https://example.test:/a",
            "https://example.test:0/a",
            "https://example.test:99999/a",
            "https://-leading.test/a",
            "https://trailing-.test/a",
            "https://exa mple.test/a",
            "https://example.test/a b",
            "https://example.test\\a",
        ] {
            let s = GOOD.replace("https://releases.example.test/boreas", url);
            assert!(parse(&s).is_err(), "{url}");
        }
        for url in [
            "https://example.test",
            "https://example.test/",
            "https://example.test:8443/a/b-c_d.e~f",
            "https://sub.domain.example.test/a",
        ] {
            let s = GOOD.replace("https://releases.example.test/boreas", url);
            assert!(parse(&s).is_ok(), "{url}");
        }
    }

    #[test]
    fn expiry_and_date_ordering_are_checked() {
        let m = parse(GOOD).unwrap();
        assert!(m.check_expiry(m.expires_unix_seconds()).is_err());
        assert!(m.check_expiry(m.expires_unix_seconds() - 1).is_ok());
        assert!(parse(&GOOD.replace("2026-01-01T00:00:01Z", "2026-02-01T00:00:00Z")).is_err());
        assert!(parse(&GOOD.replace("2026-02-01T00:00:00Z", "2026-02-30T00:00:00Z")).is_err());
        assert!(parse(&GOOD.replace("2026-02-01T00:00:00Z", "2026-02-01T00:00:00")).is_err());
    }

    #[test]
    fn json_nesting_is_bounded() {
        let deep = format!(
            "{{\"product\":{}{}}}",
            "[".repeat(MAX_JSON_DEPTH + 2),
            "]".repeat(MAX_JSON_DEPTH + 2)
        );
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn rejects_oversize_before_parsing() {
        assert_eq!(
            parse_unsigned(&vec![b' '; MAX_MANIFEST_BYTES + 1]),
            Err(ManifestError::TooLarge)
        );
        assert_eq!(parse_unsigned(&[]), Err(ManifestError::TooLarge));
    }

    #[test]
    fn release_policy_enforces_freshness_lifetime_and_sequence() {
        let m = parse(GOOD).unwrap();
        let now = m.issued_unix_seconds();
        // GOOD's 31-day lifetime is inside the 90-day ceiling but outside a
        // 7-day policy.
        let strict =
            ReleasePolicy::new(vec!["x86_64-unknown-linux-gnu".into()], 7 * 24 * 60 * 60, 1)
                .unwrap();
        assert!(strict.check(&m, now).is_err());
        let loose = ReleasePolicy::new(
            vec!["x86_64-unknown-linux-gnu".into()],
            MAX_METADATA_LIFETIME_SECONDS,
            1,
        )
        .unwrap();
        assert!(loose.check(&m, now).is_ok());
        // Expired by the caller's trusted clock.
        assert_eq!(
            loose.check(&m, m.expires_unix_seconds()),
            Err(ManifestError::Expired)
        );
        // Rollback below the configured floor.
        let floored = ReleasePolicy::new(
            vec!["x86_64-unknown-linux-gnu".into()],
            MAX_METADATA_LIFETIME_SECONDS,
            5,
        )
        .unwrap();
        assert_eq!(
            floored.check(&m, now),
            Err(ManifestError::SequenceRollback {
                previous: 5,
                candidate: 4
            })
        );
    }

    #[test]
    fn policy_selects_exactly_one_asset_for_the_target_arch() {
        let m = parse(GOOD).unwrap();
        let policy = ReleasePolicy::new(
            vec![
                "x86_64-unknown-linux-gnu".into(),
                "aarch64-unknown-linux-gnu".into(),
            ],
            MAX_METADATA_LIFETIME_SECONDS,
            1,
        )
        .unwrap();
        let asset = policy.select_asset(&m, "x86_64-unknown-linux-gnu").unwrap();
        assert_eq!(asset.name(), "boreas-linux-x86_64");
        assert_eq!(asset.size(), 42);
        assert!(
            policy
                .select_asset(&m, "aarch64-unknown-linux-gnu")
                .is_err()
        );
        assert!(
            policy
                .select_asset(&m, "riscv64-unknown-linux-gnu")
                .is_err()
        );

        // Two distinct assets for the same architecture are ambiguous and are
        // refused rather than resolved by position.
        let single = r#"{"name":"boreas-linux-x86_64","arch":"x86_64-unknown-linux-gnu","size":42,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"https://releases.example.test/boreas"}"#;
        assert!(GOOD.contains(single));
        let second = single.replace("boreas-linux-x86_64", "boreas-linux-x86_64-alt");
        let ambiguous = GOOD.replace(single, &format!("{single},{second}"));
        let m = parse(&ambiguous).unwrap();
        assert_eq!(m.assets().len(), 2);
        assert!(policy.select_asset(&m, "x86_64-unknown-linux-gnu").is_err());
    }

    #[test]
    fn verify_release_rejects_untrusted_and_oversized_inputs_before_crypto() {
        let roots = [root()];
        // Unknown key id: refused before any signature is looked at.
        let other =
            SignatureEnvelope::new("root-2", [1u8; 64], vec![2u8; ML_DSA_65_SIGNATURE_BYTES])
                .unwrap();
        assert_eq!(
            verify_release(GOOD.as_bytes(), &other, &roots),
            Err(ManifestError::UntrustedKey)
        );
        // Size bound is checked before the key lookup.
        assert_eq!(
            verify_release(&[], &envelope(), &roots),
            Err(ManifestError::TooLarge)
        );
        assert_eq!(
            verify_release(&vec![b' '; MAX_MANIFEST_BYTES + 1], &envelope(), &roots),
            Err(ManifestError::TooLarge)
        );
        // Bounded, non-empty DER only.
        assert!(ReleaseRoot::new("root-1", Vec::new(), vec![9u8; 1952]).is_err());
        assert!(ReleaseRoot::new("root-1", vec![7u8; 65], vec![9u8; 1952]).is_err());
        assert!(ReleaseRoot::new("root-1", vec![7u8; 44], Vec::new()).is_err());
        assert!(ReleaseRoot::new("root-1", vec![7u8; 44], vec![9u8; 4097]).is_err());
        // Envelope signature lengths are structural (the Ed25519 half is a
        // fixed-size array at the type level; the ML-DSA half is checked).
        assert!(SignatureEnvelope::new("root-1", [0u8; 64], vec![0u8; 3]).is_err());
        assert!(
            SignatureEnvelope::new("root-1", [0u8; 64], vec![2u8; ML_DSA_65_SIGNATURE_BYTES])
                .is_ok()
        );
    }

    #[cfg(not(feature = "openssl-backend"))]
    #[test]
    fn verify_release_without_a_crypto_backend_fails_closed() {
        assert_eq!(
            verify_release(GOOD.as_bytes(), &envelope(), &[root()]),
            Err(ManifestError::VerificationUnavailable)
        );
        // The asset size claim is still checked; the hash cannot be.
        let verified = verified(GOOD.as_bytes());
        let asset = verified.asset("boreas-linux-x86_64").expect("member asset");
        assert_eq!(
            asset.verify_bytes(&vec![0u8; 41]),
            Err(ManifestError::Invalid(
                "artifact size does not match the authenticated manifest"
            ))
        );
        assert_eq!(
            asset.verify_bytes(&vec![0u8; 42]),
            Err(ManifestError::VerificationUnavailable)
        );
        // Membership: a name that is not in the verified bytes is refused, so
        // an asset parsed from some other (unsigned) manifest cannot borrow
        // this manifest's authentication.
        assert!(verified.asset("not-in-this-manifest").is_err());
    }

    #[cfg(feature = "openssl-backend")]
    #[test]
    fn verify_release_accepts_only_dual_signed_bytes() {
        use openssl::pkey::{KeyType, PKey, Private};
        use openssl::sign::Signer;

        fn sign(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
            let mut signer = Signer::new_without_digest(key).expect("signer");
            signer.sign_oneshot_to_vec(message).expect("sign")
        }
        fn anchor(key_id: &str, ed_der: Vec<u8>, mldsa_der: Vec<u8>) -> ReleaseRoot {
            ReleaseRoot::new(key_id, ed_der, mldsa_der).expect("valid anchor")
        }

        let ed25519 = PKey::generate_ed25519().expect("ed25519 key");
        let mldsa = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[7u8; 32])
            .expect("ml-dsa-65 key");
        let mldsa_der = mldsa.public_key_to_der().expect("ml-dsa der");
        let roots = [anchor(
            "root-1",
            ed25519.public_key_to_der().expect("ed der"),
            mldsa_der.clone(),
        )];
        let message = GOOD.as_bytes();
        let envelope = SignatureEnvelope::new(
            "root-1",
            sign(&ed25519, message)
                .try_into()
                .expect("64-byte ed25519 signature"),
            sign(&mldsa, message),
        )
        .expect("envelope");

        // Both signatures over the exact bytes: authenticated, and only now is
        // the same slice parsed into a private VerifiedManifest.
        let verified = verify_release(message, &envelope, &roots).expect("authenticated");
        assert_eq!(verified.raw_bytes(), message);
        assert_eq!(verified.manifest().sequence(), 4);
        assert_eq!(verified.manifest().signing_key_id(), "root-1");

        // One changed byte invalidates the pair.
        let mut tampered = message.to_vec();
        tampered[10] ^= 0x01;
        assert!(verify_release(&tampered, &envelope, &roots).is_err());

        // A different Ed25519 anchor must not verify this envelope.
        let other_ed = PKey::generate_ed25519().expect("other ed25519 key");
        let other_roots = [anchor(
            "root-1",
            other_ed.public_key_to_der().expect("other der"),
            mldsa_der,
        )];
        assert!(verify_release(message, &envelope, &other_roots).is_err());

        // The asset hash is checked against the authenticated bytes, and the
        // asset must be looked up *inside* this manifest.
        let verified = verify_release(message, &envelope, &roots).expect("authenticated");
        let expired_at = verified.manifest().expires_unix_seconds();
        let asset = verified.asset("boreas-linux-x86_64").expect("member asset");
        assert!(
            asset
                .verify_bytes(&vec![0u8; asset.size() as usize])
                .is_err(),
            "wrong content with the right size must not verify"
        );
        assert!(asset.verify_bytes(&vec![0u8; 41]).is_err());
        assert!(verified.asset("not-in-this-manifest").is_err());

        // Staging needs the policy layer, not just signatures.
        let policy = ReleasePolicy::new(
            vec!["x86_64-unknown-linux-gnu".into()],
            MAX_METADATA_LIFETIME_SECONDS,
            1,
        )
        .expect("policy");
        let now = verified.manifest().issued_unix_seconds();
        let candidate = verified
            .clone()
            .into_candidate(&policy, "x86_64-unknown-linux-gnu", now)
            .expect("policy satisfied");
        assert_eq!(
            candidate.asset().expect("selected asset").name(),
            "boreas-linux-x86_64"
        );
        assert_eq!(candidate.sequence(), 4);
        assert!(candidate.verify_bytes(&vec![0u8; 42]).is_err());

        // A sequence floor above the manifest, a foreign architecture and an
        // expired clock are all refused, and each refusal happens before any
        // staging could occur.
        let floored = ReleasePolicy::new(
            vec!["x86_64-unknown-linux-gnu".into()],
            MAX_METADATA_LIFETIME_SECONDS,
            5,
        )
        .expect("policy");
        assert!(
            verified
                .clone()
                .into_candidate(&floored, "x86_64-unknown-linux-gnu", now)
                .is_err()
        );
        assert!(
            verified
                .clone()
                .into_candidate(&policy, "aarch64-unknown-linux-gnu", now)
                .is_err()
        );
        assert!(
            verified
                .into_candidate(&policy, "x86_64-unknown-linux-gnu", expired_at)
                .is_err()
        );
    }

    #[test]
    fn sequence_ledger_accepts_only_verified_manifests() {
        let a = verified(GOOD.as_bytes());
        let b = verified(GOOD.replace("\"sequence\":4", "\"sequence\":5").as_bytes());
        let equiv = verified(GOOD.replace("\"size\":42", "\"size\":43").as_bytes());
        // A genuinely *new*, lower-numbered manifest, for the rollback case.
        let older = verified(
            GOOD.replace("\"sequence\":4", "\"sequence\":3")
                .replace("\"size\":42", "\"size\":43")
                .as_bytes(),
        );
        let mut ledger = SequenceLedger::default();
        ledger.observe(&a).unwrap();
        // Re-observing the same bytes is idempotent, not a rollback.
        ledger.observe(&a).unwrap();
        assert_eq!(
            ledger.observe(&equiv),
            Err(ManifestError::Equivocation { sequence: 4 })
        );
        ledger.observe(&b).unwrap();
        assert_eq!(ledger.highest_sequence(), Some(5));
        // Sequence 4 is still retained, so a different body at that sequence is
        // equivocation. A lower sequence that was never observed is a rollback.
        let older = verified(GOOD.replace("\"sequence\":4", "\"sequence\":3").as_bytes());
        assert_eq!(
            ledger.observe(&older),
            Err(ManifestError::SequenceRollback {
                previous: 5,
                candidate: 3
            })
        );
        // The already-recorded manifest is still just a duplicate.
        assert_eq!(ledger.observe(&a), Ok(()));
    }

    /// Parse one JSON string literal through the real reader, so escape and
    /// surrogate handling can be tested without a schema field that accepts
    /// arbitrary text (every manifest field is validated).
    fn json_string(literal: &str) -> Result<String, ManifestError> {
        let mut parser = JsonParser {
            text: literal,
            pos: 0,
        };
        let value = parser.parse_value(0)?;
        parser.skip_whitespace();
        assert_eq!(
            parser.pos,
            parser.text.len(),
            "reader must consume the input"
        );
        match value {
            JsonValue::String(s) => Ok(s),
            other => panic!("expected a string, got {other:?}"),
        }
    }

    #[test]
    fn unicode_escapes_are_decoded_and_lone_surrogates_rejected() {
        assert_eq!(json_string(r#""state\u002dv1""#).unwrap(), "state-v1");
        assert_eq!(json_string(r#""\uD83D\uDE00""#).unwrap(), "😀");
        assert_eq!(
            json_string(r#""quote:\" backslash:\\ tab:\t""#).unwrap(),
            "quote:\" backslash:\\ tab:\t"
        );
        for bad in [
            r#""\uD83D""#,
            r#""\uDE00""#,
            r#""\uD83Dx""#,
            r#""\u""#,
            r#""\q""#,
        ] {
            assert!(json_string(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn control_characters_must_be_escaped() {
        let raw = GOOD.replace("state-v1", "state\u{1}v1");
        assert!(parse(&raw).is_err());
        // The escaped form of the same byte parses (and is then rejected by
        // the identifier rule, not by the reader).
        let escaped = GOOD.replace("state-v1", r"state\u0001v1");
        assert!(parse(&escaped).is_err());
    }

    #[test]
    fn utf8_validation_happens_before_parsing() {
        // A lone continuation byte inside a string is not valid UTF-8; the
        // parser reports InvalidJson instead of slicing on a char boundary.
        let index = GOOD.find("state-v1").expect("marker present") + 2;
        let mut bytes = GOOD.as_bytes().to_vec();
        bytes[index] = 0x80;
        assert_eq!(parse_unsigned(&bytes), Err(ManifestError::InvalidJson));
    }
}
