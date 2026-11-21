//! Real dual-signature management-object verification and issuer authorization.
//!
//! This module is compiled only with the `openssl-backend` feature because it performs
//! actual Ed25519 and ML-DSA signature verification through OpenSSL 3.5+. Verification
//! and authorization are deliberately separate: a cryptographically valid signature is
//! never sufficient unless the issuer, generation, object type, target core, scope,
//! network and freshness checks also pass.
//!
//! The envelope is `boreas_proto::messages::SignedObject`, whose total cap is 16 KiB.
//! Both Ed25519 and ML-DSA signatures are mandatory for every signer; there is no
//! ML-DSA-only acceptance path. Signatures cover the exact original TBS bytes via
//! [`boreas_proto::objects::signature_input`]. The parser re-encodes the decoded TBS and
//! requires byte-for-byte equality, so it never verifies a re-encoded substitute.
//!
//! Trust boundary: [`IssuerRecord`] values are out-of-band provisioned trust anchors. This
//! module checks object authority, scope and signature possession; it does **not** parse or
//! validate an X.509 certificate chain, and it does not replace the NetworkRoot/
//! RootAuthorization PKI. A caller that treats arbitrary issuer records as a chain has
//! widened the trust boundary incorrectly.
//!
//! Durability boundary: the `ManagementTrust` replay table is process-local. It detects
//! equivocation during one process lifetime and keeps the exact conflicting inputs, but a
//! directory must persist accepted object IDs/watermarks (and both evidence sides) before
//! acting or before restart. This is not yet a durable global replay database.
//!
//! `AttachmentLease` uses two mandatory signers: the Primary signature must verify with
//! the node Ed25519 + ML-DSA public keys in an already verified `NodeIdentity`, and the
//! CoSign signature must verify with the target Core's `CoreOperationalKey`. The two
//! signatures cover the same exact TBS. A node Ed25519 key is accepted only through the
//! IdentityAuthority-bound NodeIdentity object; a forwarding Core cannot add it.
//!
//! The NodeIdentity schema revision is still a candidate. Online enrollment Ed binding
//! remains gated on a controlled CSR proof-of-possession design and a formally assigned
//! extension OID; offline/controlled provisioning is the only claimed path until then.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;

use boreas_proto::messages::{MAX_SIGNED_OBJECT_LEN, SignedObject, SignerRole, SignerSignatures};
use boreas_proto::objects::{
    self, ManagementObject, MldsaParameterSet, NodeIdentity, NodeRole as ObjectNodeRole,
    ObjectBody, ObjectType, SubjectIdentity,
};
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{Id, KeyType, PKey, Private};
use openssl::sign::{Signer, Verifier};

use crate::{Authority, NodeRole, root_authorization::VerifiedIssuerAuthorization};

/// Candidate management-object schema version used by `boreas-proto`.
pub const MANAGEMENT_SCHEMA_VERSION: u16 = 1;
/// Total signed-object container cap from the master plan and the 16 KiB
/// `DirectoryPage` single-object cap. The TBS budget is this total minus the
/// actual signature envelope and container headers; layers must not each add 16 KiB.
pub const MAX_SIGNED_OBJECT_BYTES: usize = MAX_SIGNED_OBJECT_LEN;
/// Bounded provisioned issuer list, to keep a malicious-but-authorized issuer
/// provisioning stream from growing trust memory without limit.
pub const MAX_TRUSTED_ISSUERS: usize = 256;
/// Bounded replay/equivocation slot table. Route grants can address many prefixes,
/// so the table needs its own cap rather than assuming one entry per issuer.
pub const MAX_REPLAY_SLOTS: usize = 16_384;
/// Maximum verified NodeIdentity records retained for Lease two-party verification.
pub const MAX_NODE_IDENTITIES: usize = 4_096;
const MAX_SCOPE_ROLES: usize = 3;
const MAX_SCOPE_CORES: usize = 16;
const MAX_SCOPE_PREFIXES: usize = 256;

const ED25519_SIGNATURE_LEN: usize = 64;
const MLDSA65_SIGNATURE_LEN: usize = 3309;
const MLDSA87_SIGNATURE_LEN: usize = 4627;
const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
const MAX_ISSUER_KEY_ID_LEN: usize = 64;
const MAX_PUBLIC_KEY_DER_LEN: usize = 4096;
const MAX_SCOPE_LEN: usize = 1024;
const MAX_PREFIX_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ObjectTooLarge,
    MalformedObject,
    NonCanonicalObject,
    WrongNetwork,
    NotYetValid,
    Expired,
    UnknownIssuer,
    UnknownNodeIdentity,
    StaleNodeIdentity,
    IssuerGenerationMismatch,
    IssuerNotValid,
    UnauthorizedObjectType,
    OutOfScope,
    InvalidIdentityKey,
    InvalidIssuerKey,
    MalformedSignedObject,
    ImproperSignerRole,
    MlDsaParameterMismatch,
    InvalidEd25519Signature,
    InvalidMlDsaSignature,
    SignatureBackend,
    StaleSequence,
    IssuedAtRegression,
    Equivocation,
    UnsupportedTwoPartyObject,
    DuplicateIssuer,
    TrustFull,
    ReplayFull,
    InvalidIssuerRecord,
    InvalidPrefix,
    InvalidTemplate,
    InvalidValidity,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// A canonical prefix pool entry for a RouteAuthority scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedPrefix {
    bytes: Vec<u8>,
    prefix_len: u8,
}
impl AllowedPrefix {
    pub fn new(bytes: Vec<u8>, prefix_len: u8) -> Result<Self, Error> {
        if !matches!(bytes.len(), 4 | 16) || usize::from(prefix_len) > MAX_PREFIX_LEN {
            return Err(Error::InvalidPrefix);
        }
        if usize::from(prefix_len) > bytes.len() * 8 {
            return Err(Error::InvalidPrefix);
        }
        // Route prefixes in the plan are at least /8 (IPv4) and /48 (IPv6); reject
        // overly broad scopes rather than silently authorizing most of the address space.
        let minimum = if bytes.len() == 4 { 8 } else { 48 };
        if prefix_len < minimum || !host_bits_zero(&bytes, prefix_len) {
            return Err(Error::InvalidPrefix);
        }
        Ok(Self { bytes, prefix_len })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
    fn contains(&self, candidate: &Self) -> bool {
        self.bytes.len() == candidate.bytes.len()
            && candidate.prefix_len >= self.prefix_len
            && prefix_matches(&self.bytes, &candidate.bytes, self.prefix_len)
    }
}

/// Explicit issuer authority scope. Empty role/core/prefix sets authorize nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssuerScope {
    pub allowed_roles: Vec<NodeRole>,
    pub allowed_home_cores: Vec<u8>,
    pub allowed_prefixes: Vec<AllowedPrefix>,
}
impl IssuerScope {
    pub fn for_identity(roles: Vec<NodeRole>, home_cores: Vec<u8>) -> Result<Self, Error> {
        if roles.len() > MAX_SCOPE_ROLES
            || home_cores.len() > MAX_SCOPE_CORES
            || home_cores.iter().any(|core| !(1..=16).contains(core))
        {
            return Err(Error::InvalidIssuerRecord);
        }
        Ok(Self {
            allowed_roles: roles,
            allowed_home_cores: home_cores,
            allowed_prefixes: Vec::new(),
        })
    }
    pub fn for_route(prefixes: Vec<AllowedPrefix>) -> Result<Self, Error> {
        if prefixes.len() > MAX_SCOPE_PREFIXES {
            return Err(Error::InvalidIssuerRecord);
        }
        Ok(Self {
            allowed_roles: Vec::new(),
            allowed_home_cores: Vec::new(),
            allowed_prefixes: prefixes,
        })
    }
}

/// Provisioned issuer trust record. The public keys are DER SubjectPublicKeyInfo values
/// imported and type-checked by `add_issuer`; they are never raw attacker-supplied blobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub issuer_key_id: Vec<u8>,
    pub issuer_generation: u64,
    pub authority: Authority,
    pub ed25519_public_key_der: Vec<u8>,
    pub mldsa_parameter_set: MldsaParameterSet,
    pub mldsa_public_key_der: Vec<u8>,
    pub scope: IssuerScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedObject {
    /// SHA-256 of the exact TBS bytes; also the candidate `object_id` rule.
    object_id: [u8; 32],
    object: ManagementObject,
    /// Exact original TBS bytes; never a re-encoded substitute.
    raw_tbs: Vec<u8>,
    /// Parsed proto `SignedObject` carrying the exact raw TBS and every signer.
    signed_object: SignedObject,
    /// Exact original envelope bytes, retained so a directory can persist the full
    /// object and preserve both sides of an equivocation instead of only the TBS.
    raw_signed_object: Vec<u8>,
    /// True when the exact same `(logical slot, seq, TBS)` was already accepted.
    duplicate: bool,
    /// Exclusive UTC cutoff: the earlier of object and issuer delegation expiry.
    valid_until: u64,
}
impl VerifiedObject {
    pub fn object_id(&self) -> [u8; 32] {
        self.object_id
    }
    pub fn object(&self) -> &ManagementObject {
        &self.object
    }
    pub fn raw_tbs(&self) -> &[u8] {
        &self.raw_tbs
    }
    pub fn signed_object(&self) -> &SignedObject {
        &self.signed_object
    }
    pub fn raw_signed_object(&self) -> &[u8] {
        &self.raw_signed_object
    }
    /// Exclusive UTC cutoff for this object, including any root delegation.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn is_duplicate(&self) -> bool {
        self.duplicate
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum ReplayKey {
    NodeIdentity(u16),
    CoreLsa(u8),
    RouteGrant {
        issuer_key_id: Vec<u8>,
        subject_node_id: u16,
        prefix: Vec<u8>,
        prefix_len: u8,
    },
    DirectGrant {
        issuer_key_id: Vec<u8>,
        subject_node_id: u16,
    },
    Lease {
        node_id: u16,
        target_core_id: u8,
    },
    StatusSnapshot,
}
#[derive(Clone, Copy, Debug)]
struct ReplayState {
    seq: u64,
    issued_at: u64,
    object_id: [u8; 32],
    conflicted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedIssuer {
    record: IssuerRecord,
    /// `None` is reserved for explicitly provisioned out-of-band anchors.
    validity: Option<(u64, u64)>,
}

/// Stateful verifier with provisioned issuer records and per-logical-slot replay watermarks.
///
/// The replay state is process-local in this module. A production directory must persist
/// accepted object IDs/watermarks in its own durable store before acting on them.
#[derive(Debug)]
pub struct ManagementTrust {
    net_id: [u8; 16],
    issuers: BTreeMap<Vec<u8>, TrustedIssuer>,
    /// Only NodeIdentity records accepted through this verifier; a Lease Primary key is
    /// never taken from an unsigned caller-supplied map.
    node_identities: BTreeMap<u16, NodeIdentity>,
    replay: BTreeMap<ReplayKey, ReplayState>,
    /// Last conflicting envelope bytes, retained for evidence. Bounded to one object;
    /// a durable directory must copy it to its own append-only evidence store.
    conflict_evidence: Option<Vec<u8>>,
}
impl ManagementTrust {
    pub fn new(net_id: [u8; 16]) -> Self {
        Self {
            net_id,
            issuers: BTreeMap::new(),
            node_identities: BTreeMap::new(),
            replay: BTreeMap::new(),
            conflict_evidence: None,
        }
    }
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }
    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }
    pub(crate) fn same_issuers(&self, expected: &Self) -> bool {
        self.net_id == expected.net_id && self.issuers == expected.issuers
    }
    /// Full envelope bytes of the most recent equivocation, if any.
    pub fn conflict_evidence(&self) -> Option<&[u8]> {
        self.conflict_evidence.as_deref()
    }
    /// Verified NodeIdentity used for the Lease Primary signer, if already accepted.
    pub fn node_identity(&self, node_id: u16) -> Option<&NodeIdentity> {
        self.node_identities.get(&node_id)
    }

    /// Provision an out-of-band trust anchor with no root-delegation window.
    /// Use [`Self::add_verified_issuer`] for root-delegated trust instead.
    pub fn add_issuer(&mut self, issuer: IssuerRecord) -> Result<(), Error> {
        self.insert_issuer(issuer, None)
    }

    /// Install a verifier-produced root authorization, retaining its exclusive validity window.
    pub fn add_verified_issuer(
        &mut self,
        authorization: &VerifiedIssuerAuthorization,
    ) -> Result<(), Error> {
        if authorization.net_id() != self.net_id {
            return Err(Error::WrongNetwork);
        }
        self.insert_issuer(authorization.issuer_record(), Some(authorization.validity()))
    }

    fn insert_issuer(
        &mut self,
        issuer: IssuerRecord,
        validity: Option<(u64, u64)>,
    ) -> Result<(), Error> {
        if issuer.issuer_key_id.is_empty()
            || issuer.issuer_key_id.len() > MAX_ISSUER_KEY_ID_LEN
            || issuer.issuer_generation == 0
            || issuer.ed25519_public_key_der.is_empty()
            || issuer.ed25519_public_key_der.len() > MAX_PUBLIC_KEY_DER_LEN
            || issuer.mldsa_public_key_der.is_empty()
            || issuer.mldsa_public_key_der.len() > MAX_PUBLIC_KEY_DER_LEN
        {
            return Err(Error::InvalidIssuerRecord);
        }
        if issuer.scope.allowed_roles.len() > MAX_SCOPE_ROLES
            || issuer.scope.allowed_home_cores.len() > MAX_SCOPE_CORES
            || issuer.scope.allowed_prefixes.len() > MAX_SCOPE_PREFIXES
            || issuer
                .scope
                .allowed_home_cores
                .iter()
                .any(|core| !(1..=16).contains(core))
        {
            return Err(Error::InvalidIssuerRecord);
        }
        if self.issuers.contains_key(&issuer.issuer_key_id) {
            return Err(Error::DuplicateIssuer);
        }
        if self.issuers.len() >= MAX_TRUSTED_ISSUERS {
            return Err(Error::TrustFull);
        }
        if let Authority::CoreOperationalKey { core_id } = issuer.authority
            && !(1..=16).contains(&core_id)
        {
            return Err(Error::InvalidIssuerRecord);
        }
        if !key_matches(&issuer.ed25519_public_key_der, KeyType::ED25519) {
            return Err(Error::InvalidIssuerKey);
        }
        if !key_matches(
            &issuer.mldsa_public_key_der,
            mldsa_key_type(issuer.mldsa_parameter_set),
        ) {
            return Err(Error::InvalidIssuerKey);
        }
        self.issuers.insert(
            issuer.issuer_key_id.clone(),
            TrustedIssuer {
                record: issuer,
                validity,
            },
        );
        Ok(())
    }

    /// Verify both signatures over the exact TBS and apply issuer/object/scope/replay policy.
    ///
    /// `now_us` is trusted UTC microseconds supplied by the caller; it is not a local
    /// monotonic clock and it is not silently clamped.
    pub fn verify_and_authorize(
        &mut self,
        raw_signed_object: &[u8],
        now_us: u64,
    ) -> Result<VerifiedObject, Error> {
        self.verify_with_issuer_time(raw_signed_object, now_us, now_us)
    }

    /// The status store can authenticate evidence at its signed time while still
    /// checking delegation expiry against a separate, conservative UTC bound.
    pub(crate) fn verify_with_issuer_time(
        &mut self,
        raw_signed_object: &[u8],
        object_now_us: u64,
        issuer_now_us: u64,
    ) -> Result<VerifiedObject, Error> {
        if raw_signed_object.is_empty() || raw_signed_object.len() > MAX_SIGNED_OBJECT_BYTES {
            return Err(Error::ObjectTooLarge);
        }
        let signed =
            SignedObject::decode(raw_signed_object).map_err(|_| Error::MalformedSignedObject)?;
        let raw_tbs = signed.raw_tbs.clone();
        let object = objects::decode_tbs(&raw_tbs).map_err(|_| Error::MalformedObject)?;
        let canonical = objects::encode_tbs(&object).map_err(|_| Error::MalformedObject)?;
        if canonical != raw_tbs {
            return Err(Error::NonCanonicalObject);
        }
        if object.net_id != self.net_id {
            return Err(Error::WrongNetwork);
        }
        if object_now_us < object.issued_at {
            return Err(Error::NotYetValid);
        }
        if object_now_us >= object.expires {
            return Err(Error::Expired);
        }
        let issuer = self
            .issuers
            .get(&object.issuer_key_id)
            .cloned()
            .ok_or(Error::UnknownIssuer)?;
        let valid_until = if let Some((not_before, expires)) = issuer.validity {
            // For StatusSnapshot, the signed issued_at also anchors historical
            // verification on reopen; do not accept a pre-delegation snapshot.
            let not_before_check = if matches!(&object.body, ObjectBody::StatusSnapshot(_)) {
                object.issued_at
            } else {
                object_now_us
            };
            if not_before_check < not_before || issuer_now_us.max(object_now_us) >= expires {
                return Err(Error::IssuerNotValid);
            }
            object.expires.min(expires)
        } else {
            object.expires
        };
        let issuer = issuer.record;
        if object.issuer_generation != issuer.issuer_generation {
            return Err(Error::IssuerGenerationMismatch);
        }
        let kind = object_kind(&object.body)?;
        let is_lease = matches!(&object.body, ObjectBody::AttachmentLease(_));
        let expected_signers = if is_lease { 2 } else { 1 };
        if signed.signers.len() != expected_signers {
            return Err(Error::ImproperSignerRole);
        }
        let target_core_id = target_core_id(issuer.authority, &object.body);
        if !crate::may_issue_for_core(issuer.authority, kind, target_core_id) {
            return Err(Error::UnauthorizedObjectType);
        }
        authorize_scope(&issuer, &object)?;
        if let ObjectBody::NodeIdentity(node) = &object.body
            && !self.node_identities.contains_key(&node.node_id)
            && self.node_identities.len() >= MAX_NODE_IDENTITIES
        {
            return Err(Error::ReplayFull);
        }
        let message = objects::signature_input(
            &raw_tbs,
            object.body.object_type(),
            MANAGEMENT_SCHEMA_VERSION,
        )
        .map_err(|_| Error::MalformedObject)?;
        if is_lease {
            self.verify_lease(&object, &issuer, &signed, &message)?;
        } else {
            verify_signer_signatures(&issuer, &message, &signed.signers[0], SignerRole::Primary)?;
        }
        let object_id = sha256(&raw_tbs)?;
        let duplicate = match self.record_replay(
            replay_key(&object)?,
            object.seq,
            object.issued_at,
            object_id,
        ) {
            Ok(duplicate) => duplicate,
            Err(Error::Equivocation) => {
                self.conflict_evidence = Some(raw_signed_object.to_vec());
                return Err(Error::Equivocation);
            }
            Err(error) => return Err(error),
        };
        if let ObjectBody::NodeIdentity(node) = &object.body {
            self.node_identities.insert(node.node_id, node.clone());
        }
        Ok(VerifiedObject {
            object_id,
            object,
            raw_tbs,
            signed_object: signed,
            raw_signed_object: raw_signed_object.to_vec(),
            duplicate,
            valid_until,
        })
    }

    /// True two-party AttachmentLease authorization: the Primary signer must be the
    /// already-verified NodeIdentity's Ed25519 + ML-DSA keys, and the CoSign signer must
    /// be the target CoreOperationalKey. Both signatures cover the same TBS.
    fn verify_lease(
        &self,
        object: &ManagementObject,
        issuer: &IssuerRecord,
        signed: &SignedObject,
        message: &[u8],
    ) -> Result<(), Error> {
        let ObjectBody::AttachmentLease(body) = &object.body else {
            return Err(Error::UnsupportedTwoPartyObject);
        };
        if signed.signers.len() != 2 {
            return Err(Error::ImproperSignerRole);
        }
        let primary = &signed.signers[0];
        let co_sign = &signed.signers[1];
        if primary.role != SignerRole::Primary || co_sign.role != SignerRole::CoSign {
            return Err(Error::ImproperSignerRole);
        }
        let node = self
            .node_identities
            .get(&body.node_id)
            .ok_or(Error::UnknownNodeIdentity)?;
        if node.identity_generation != body.identity_generation {
            return Err(Error::StaleNodeIdentity);
        }
        verify_node_signatures(node, message, primary)?;
        verify_signer_signatures(issuer, message, co_sign, SignerRole::CoSign)?;
        Ok(())
    }

    /// Test convenience that binds the separately supplied TBS to the envelope's exact
    /// `raw_tbs` before verification. Negative tests that intend to change signed bytes
    /// must mutate the envelope's raw TBS and re-encode it; a mismatched argument fails.
    #[cfg(test)]
    fn verify_test(
        &mut self,
        raw_tbs: &[u8],
        raw_signed: &[u8],
        now_us: u64,
    ) -> Result<VerifiedObject, Error> {
        let signed = SignedObject::decode(raw_signed).map_err(|_| Error::MalformedSignedObject)?;
        if signed.raw_tbs.as_slice() != raw_tbs {
            return Err(Error::NonCanonicalObject);
        }
        self.verify_and_authorize(raw_signed, now_us)
    }

    fn record_replay(
        &mut self,
        key: ReplayKey,
        seq: u64,
        issued_at: u64,
        object_id: [u8; 32],
    ) -> Result<bool, Error> {
        let replay_full = self.replay.len() >= MAX_REPLAY_SLOTS;
        match self.replay.entry(key) {
            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                if state.conflicted {
                    return Err(Error::Equivocation);
                }
                if seq < state.seq {
                    return Err(Error::StaleSequence);
                }
                if seq == state.seq {
                    if state.object_id == object_id {
                        return Ok(true);
                    }
                    // Same logical writer/key slot and same seq with different TBS bytes:
                    // freeze this slot permanently instead of choosing a winner.
                    state.conflicted = true;
                    return Err(Error::Equivocation);
                }
                if issued_at < state.issued_at {
                    return Err(Error::IssuedAtRegression);
                }
                state.seq = seq;
                state.issued_at = issued_at;
                state.object_id = object_id;
                Ok(false)
            }
            Entry::Vacant(entry) => {
                if replay_full {
                    return Err(Error::ReplayFull);
                }
                entry.insert(ReplayState {
                    seq,
                    issued_at,
                    object_id,
                    conflicted: false,
                });
                Ok(false)
            }
        }
    }
}

/// Verify a persisted proto `SignedObject` against a trust store containing the
/// signing authority. The exact envelope bytes are decoded by the proto parser and
/// retained in [`VerifiedObject::raw_signed_object`].
pub fn verify_signed_identity(
    trust: &mut ManagementTrust,
    raw_signed: &[u8],
    now_us: u64,
) -> Result<VerifiedObject, Error> {
    trust.verify_and_authorize(raw_signed, now_us)
}

/// Inputs controlled by the enrollment transaction, not by an untrusted CSR subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityTemplate {
    pub node_id: u16,
    pub home_core_id: u8,
    pub vip_octet: u8,
    pub role: NodeRole,
    pub identity_generation: u64,
    /// Node management-signing Ed25519 public key, bound by the IdentityAuthority.
    /// It is distinct from the ML-DSA TLS identity key and must be supplied by the node.
    pub identity_pub_ed25519: [u8; 32],
    pub not_before_us: u64,
    pub expires_us: u64,
    pub scope: Vec<u8>,
}

/// Offline IdentityAuthority signing boundary.
///
/// Private keys are loaded from PKCS#8 DER and type-checked. There is no public constructor
/// that accepts a caller-supplied "already signed" blob, and no unchecked test bypass in
/// non-test builds. Signing produces a dual-signed NodeIdentity object; it does not issue a
/// TLS certificate, which remains a separate certificate-profile integration step.
pub struct IdentityAuthority {
    net_id: [u8; 16],
    issuer_key_id: Vec<u8>,
    issuer_generation: u64,
    ed25519: PKey<Private>,
    mldsa: PKey<Private>,
}
impl IdentityAuthority {
    pub fn from_pkcs8_der(
        net_id: [u8; 16],
        issuer_key_id: Vec<u8>,
        issuer_generation: u64,
        ed25519_pkcs8_der: &[u8],
        mldsa_pkcs8_der: &[u8],
    ) -> Result<Self, Error> {
        if issuer_key_id.is_empty()
            || issuer_key_id.len() > MAX_ISSUER_KEY_ID_LEN
            || issuer_generation == 0
        {
            return Err(Error::InvalidIssuerRecord);
        }
        let ed25519 =
            PKey::private_key_from_der(ed25519_pkcs8_der).map_err(|_| Error::InvalidIssuerKey)?;
        if !ed25519.is_a(KeyType::ED25519) {
            return Err(Error::InvalidIssuerKey);
        }
        let mldsa =
            PKey::private_key_from_der(mldsa_pkcs8_der).map_err(|_| Error::InvalidIssuerKey)?;
        if !mldsa.is_a(KeyType::ML_DSA_65) {
            return Err(Error::InvalidIssuerKey);
        }
        Ok(Self {
            net_id,
            issuer_key_id,
            issuer_generation,
            ed25519,
            mldsa,
        })
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }
    pub fn issuer_key_id(&self) -> &[u8] {
        &self.issuer_key_id
    }
    pub fn issuer_generation(&self) -> u64 {
        self.issuer_generation
    }

    pub fn issuer_record(&self, scope: IssuerScope) -> Result<IssuerRecord, Error> {
        Ok(IssuerRecord {
            issuer_key_id: self.issuer_key_id.clone(),
            issuer_generation: self.issuer_generation,
            authority: Authority::IdentityAuthority,
            ed25519_public_key_der: self
                .ed25519
                .public_key_to_der()
                .map_err(|_| Error::SignatureBackend)?,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: self
                .mldsa
                .public_key_to_der()
                .map_err(|_| Error::SignatureBackend)?,
            scope,
        })
    }

    /// Build the NodeIdentity body from the exact CSR read back from the journal.
    /// The CSR's PKCS#10 proof is verified again here before its public key is used.
    pub fn node_identity_from_csr(
        &self,
        template: IdentityTemplate,
        csr_der: &[u8],
    ) -> Result<NodeIdentity, Error> {
        if template.scope.len() > MAX_SCOPE_LEN
            || template.identity_generation == 0
            || template.not_before_us >= template.expires_us
            || template.identity_pub_ed25519 == [0; 32]
        {
            return Err(Error::InvalidTemplate);
        }
        let ed_key = PKey::public_key_from_raw_bytes(&template.identity_pub_ed25519, Id::ED25519)
            .map_err(|_| Error::InvalidTemplate)?;
        if !ed_key.is_a(KeyType::ED25519) {
            return Err(Error::InvalidTemplate);
        }
        let expected_node_id =
            crate::node_id(template.home_core_id, template.vip_octet, template.role)
                .map_err(|_| Error::InvalidTemplate)?;
        if expected_node_id != template.node_id {
            return Err(Error::InvalidTemplate);
        }
        let vip = crate::expected_vip(template.home_core_id, template.vip_octet, template.role)
            .map_err(|_| Error::InvalidTemplate)?;
        let request =
            openssl::x509::X509Req::from_der(csr_der).map_err(|_| Error::InvalidIdentityKey)?;
        let public_key = request
            .public_key()
            .map_err(|_| Error::InvalidIdentityKey)?;
        if !public_key.is_a(KeyType::ML_DSA_65) {
            return Err(Error::InvalidIdentityKey);
        }
        if !request
            .verify(&public_key)
            .map_err(|_| Error::InvalidIdentityKey)?
        {
            return Err(Error::InvalidIdentityKey);
        }
        let raw_public_key = public_key
            .raw_public_key()
            .map_err(|_| Error::InvalidIdentityKey)?;
        if raw_public_key.len() != MLDSA65_PUBLIC_KEY_LEN {
            return Err(Error::InvalidIdentityKey);
        }
        let role = match template.role {
            NodeRole::Edge => ObjectNodeRole::Edge,
            NodeRole::Core => ObjectNodeRole::Core,
            NodeRole::EnrollmentService => ObjectNodeRole::EnrollmentService,
        };
        Ok(NodeIdentity {
            net_id: self.net_id,
            node_id: template.node_id,
            home_core_id: template.home_core_id,
            vip,
            vip6: [0u8; 16],
            role,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            identity_pub_mldsa: raw_public_key,
            identity_pub_ed25519: template.identity_pub_ed25519,
            identity_generation: template.identity_generation,
            not_before: template.not_before_us,
            expires: template.expires_us,
            scope: template.scope,
        })
    }

    pub fn sign_node_identity(&self, body: NodeIdentity) -> Result<SignedObject, Error> {
        if body.net_id != self.net_id
            || body.identity_generation == 0
            || body.not_before >= body.expires
            || body.scope.len() > MAX_SCOPE_LEN
        {
            return Err(Error::InvalidTemplate);
        }
        let envelope = ManagementObject {
            net_id: self.net_id,
            issuer_key_id: self.issuer_key_id.clone(),
            issuer_generation: self.issuer_generation,
            subject_identity: SubjectIdentity::Node(body.node_id),
            seq: body.identity_generation,
            issued_at: body.not_before,
            expires: body.expires,
            extensions: Vec::new(),
            body: ObjectBody::NodeIdentity(body),
        };
        let raw_tbs = objects::encode_tbs(&envelope).map_err(|_| Error::MalformedObject)?;
        let message = objects::signature_input(
            &raw_tbs,
            envelope.body.object_type(),
            MANAGEMENT_SCHEMA_VERSION,
        )
        .map_err(|_| Error::MalformedObject)?;
        let (ed25519, mldsa) = self.sign_message(&message)?;
        let signed = SignedObject {
            object_type: ObjectType::NodeIdentity,
            raw_tbs,
            signers: vec![SignerSignatures {
                role: SignerRole::Primary,
                ed25519,
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa,
            }],
        };
        signed.encode().map_err(|_| Error::MalformedSignedObject)?;
        Ok(signed)
    }

    fn sign_message(
        &self,
        message: &[u8],
    ) -> Result<([u8; ED25519_SIGNATURE_LEN], Vec<u8>), Error> {
        let mut ed_signer =
            Signer::new_without_digest(&self.ed25519).map_err(|_| Error::SignatureBackend)?;
        let ed_signature = ed_signer
            .sign_oneshot_to_vec(message)
            .map_err(|_| Error::SignatureBackend)?;
        let ed25519: [u8; ED25519_SIGNATURE_LEN] = ed_signature
            .try_into()
            .map_err(|_| Error::SignatureBackend)?;
        let mut mldsa_signer =
            Signer::new_without_digest(&self.mldsa).map_err(|_| Error::SignatureBackend)?;
        let mldsa = mldsa_signer
            .sign_oneshot_to_vec(message)
            .map_err(|_| Error::SignatureBackend)?;
        if mldsa.len() != MLDSA65_SIGNATURE_LEN {
            return Err(Error::SignatureBackend);
        }
        Ok((ed25519, mldsa))
    }
}

fn object_kind(body: &ObjectBody) -> Result<crate::ObjectKind, Error> {
    Ok(match body {
        ObjectBody::NodeIdentity(_) => crate::ObjectKind::Identity,
        ObjectBody::CoreLsa(_) => crate::ObjectKind::CoreLsa,
        ObjectBody::AttachmentLease(_) => crate::ObjectKind::AttachmentLeaseConfirmation,
        ObjectBody::RouteGrant(_) => crate::ObjectKind::RouteGrant,
        ObjectBody::DirectGrant(_) => crate::ObjectKind::OwnDirectGrant,
        ObjectBody::StatusSnapshot(_) => crate::ObjectKind::StatusSnapshot,
    })
}

fn target_core_id(authority: Authority, body: &ObjectBody) -> u8 {
    match body {
        ObjectBody::NodeIdentity(body) => body.home_core_id,
        ObjectBody::CoreLsa(body) => body.core_id,
        ObjectBody::AttachmentLease(body) => body.target_core_id,
        ObjectBody::RouteGrant(body) => ((body.subject_node_id >> 8) as u8).saturating_add(1),
        ObjectBody::DirectGrant(_) => match authority {
            Authority::CoreOperationalKey { core_id } => core_id,
            _ => 0,
        },
        ObjectBody::StatusSnapshot(_) => 0,
    }
}

fn authorize_scope(issuer: &IssuerRecord, object: &ManagementObject) -> Result<(), Error> {
    match &object.body {
        ObjectBody::NodeIdentity(body) => {
            let role = match body.role {
                ObjectNodeRole::Edge => NodeRole::Edge,
                ObjectNodeRole::Core => NodeRole::Core,
                ObjectNodeRole::EnrollmentService => NodeRole::EnrollmentService,
            };
            if !issuer.scope.allowed_roles.contains(&role)
                || !issuer.scope.allowed_home_cores.contains(&body.home_core_id)
            {
                return Err(Error::OutOfScope);
            }
            validate_identity_public_key(body)?;
        }
        ObjectBody::RouteGrant(body) => {
            let candidate = AllowedPrefix::new(body.prefix.clone(), body.prefix_len)?;
            if !issuer
                .scope
                .allowed_prefixes
                .iter()
                .any(|prefix| prefix.contains(&candidate))
            {
                return Err(Error::OutOfScope);
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_identity_public_key(body: &NodeIdentity) -> Result<(), Error> {
    if body.identity_pub_ed25519 == [0; 32] {
        return Err(Error::InvalidIdentityKey);
    }
    let ed_key = PKey::public_key_from_raw_bytes(&body.identity_pub_ed25519, Id::ED25519)
        .map_err(|_| Error::InvalidIdentityKey)?;
    if !ed_key.is_a(KeyType::ED25519) {
        return Err(Error::InvalidIdentityKey);
    }
    let expected_length = match body.mldsa_parameter_set {
        MldsaParameterSet::Mldsa65 => MLDSA65_PUBLIC_KEY_LEN,
        MldsaParameterSet::Mldsa87 => MLDSA87_PUBLIC_KEY_LEN,
    };
    if body.identity_pub_mldsa.len() != expected_length {
        return Err(Error::InvalidIdentityKey);
    }
    let key_type = mldsa_key_type(body.mldsa_parameter_set);
    let key = PKey::public_key_from_raw_bytes_ex(None, key_type, None, &body.identity_pub_mldsa)
        .map_err(|_| Error::InvalidIdentityKey)?;
    if !key.is_a(key_type) {
        return Err(Error::InvalidIdentityKey);
    }
    Ok(())
}

fn verify_node_signatures(
    node: &NodeIdentity,
    message: &[u8],
    signer: &SignerSignatures,
) -> Result<(), Error> {
    if signer.role != SignerRole::Primary {
        return Err(Error::ImproperSignerRole);
    }
    if signer.mldsa_parameter_set != node.mldsa_parameter_set {
        return Err(Error::MlDsaParameterMismatch);
    }
    let expected_mldsa_len = match node.mldsa_parameter_set {
        MldsaParameterSet::Mldsa65 => MLDSA65_SIGNATURE_LEN,
        MldsaParameterSet::Mldsa87 => MLDSA87_SIGNATURE_LEN,
    };
    if signer.mldsa.len() != expected_mldsa_len || node.identity_pub_ed25519 == [0; 32] {
        return Err(Error::InvalidMlDsaSignature);
    }
    let ed_key = PKey::public_key_from_raw_bytes(&node.identity_pub_ed25519, Id::ED25519)
        .map_err(|_| Error::InvalidIdentityKey)?;
    if !ed_key.is_a(KeyType::ED25519) {
        return Err(Error::InvalidIdentityKey);
    }
    let mut ed_verifier =
        Verifier::new_without_digest(&ed_key).map_err(|_| Error::SignatureBackend)?;
    if !ed_verifier
        .verify_oneshot(&signer.ed25519, message)
        .map_err(|_| Error::SignatureBackend)?
    {
        return Err(Error::InvalidEd25519Signature);
    }
    let key_type = mldsa_key_type(node.mldsa_parameter_set);
    let mldsa_key =
        PKey::public_key_from_raw_bytes_ex(None, key_type, None, &node.identity_pub_mldsa)
            .map_err(|_| Error::InvalidIdentityKey)?;
    if !mldsa_key.is_a(key_type) {
        return Err(Error::InvalidIdentityKey);
    }
    let mut mldsa_verifier =
        Verifier::new_without_digest(&mldsa_key).map_err(|_| Error::SignatureBackend)?;
    if !mldsa_verifier
        .verify_oneshot(&signer.mldsa, message)
        .map_err(|_| Error::SignatureBackend)?
    {
        return Err(Error::InvalidMlDsaSignature);
    }
    Ok(())
}

fn verify_signer_signatures(
    issuer: &IssuerRecord,
    message: &[u8],
    signer: &SignerSignatures,
    expected_role: SignerRole,
) -> Result<(), Error> {
    if signer.role != expected_role {
        return Err(Error::ImproperSignerRole);
    }
    if signer.mldsa_parameter_set != issuer.mldsa_parameter_set {
        return Err(Error::MlDsaParameterMismatch);
    }
    let ed25519 = &signer.ed25519;
    let expected_mldsa_len = match issuer.mldsa_parameter_set {
        MldsaParameterSet::Mldsa65 => MLDSA65_SIGNATURE_LEN,
        MldsaParameterSet::Mldsa87 => MLDSA87_SIGNATURE_LEN,
    };
    if signer.mldsa.len() != expected_mldsa_len {
        return Err(Error::InvalidMlDsaSignature);
    }
    let ed_key = PKey::public_key_from_der(&issuer.ed25519_public_key_der)
        .map_err(|_| Error::InvalidIssuerKey)?;
    if !ed_key.is_a(KeyType::ED25519) {
        return Err(Error::InvalidIssuerKey);
    }
    let mut ed_verifier =
        Verifier::new_without_digest(&ed_key).map_err(|_| Error::SignatureBackend)?;
    if !ed_verifier
        .verify_oneshot(ed25519, message)
        .map_err(|_| Error::SignatureBackend)?
    {
        return Err(Error::InvalidEd25519Signature);
    }
    let key_type = mldsa_key_type(issuer.mldsa_parameter_set);
    let mldsa_key = PKey::public_key_from_der(&issuer.mldsa_public_key_der)
        .map_err(|_| Error::InvalidIssuerKey)?;
    if !mldsa_key.is_a(key_type) {
        return Err(Error::InvalidIssuerKey);
    }
    let mut mldsa_verifier =
        Verifier::new_without_digest(&mldsa_key).map_err(|_| Error::SignatureBackend)?;
    if !mldsa_verifier
        .verify_oneshot(&signer.mldsa, message)
        .map_err(|_| Error::SignatureBackend)?
    {
        return Err(Error::InvalidMlDsaSignature);
    }
    Ok(())
}

fn replay_key(object: &ManagementObject) -> Result<ReplayKey, Error> {
    Ok(match &object.body {
        ObjectBody::NodeIdentity(body) => ReplayKey::NodeIdentity(body.node_id),
        ObjectBody::CoreLsa(body) => ReplayKey::CoreLsa(body.core_id),
        ObjectBody::RouteGrant(body) => ReplayKey::RouteGrant {
            issuer_key_id: object.issuer_key_id.clone(),
            subject_node_id: body.subject_node_id,
            prefix: body.prefix.clone(),
            prefix_len: body.prefix_len,
        },
        ObjectBody::DirectGrant(body) => ReplayKey::DirectGrant {
            issuer_key_id: object.issuer_key_id.clone(),
            subject_node_id: body.subject_node_id,
        },
        ObjectBody::StatusSnapshot(_) => ReplayKey::StatusSnapshot,
        ObjectBody::AttachmentLease(body) => ReplayKey::Lease {
            node_id: body.node_id,
            target_core_id: body.target_core_id,
        },
    })
}

fn mldsa_key_type(parameter_set: MldsaParameterSet) -> KeyType {
    match parameter_set {
        MldsaParameterSet::Mldsa65 => KeyType::ML_DSA_65,
        MldsaParameterSet::Mldsa87 => KeyType::ML_DSA_87,
    }
}

fn key_matches(der: &[u8], expected: KeyType) -> bool {
    PKey::public_key_from_der(der).is_ok_and(|key| key.is_a(expected))
}

fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    let digest = hash(MessageDigest::sha256(), data).map_err(|_| Error::SignatureBackend)?;
    let bytes: &[u8] = digest.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn host_bits_zero(bytes: &[u8], prefix_len: u8) -> bool {
    let full = usize::from(prefix_len) / 8;
    let remainder = usize::from(prefix_len) % 8;
    if remainder != 0 {
        let Some(byte) = bytes.get(full) else {
            return false;
        };
        if byte & ((1u8 << (8 - remainder)) - 1) != 0 {
            return false;
        }
    }
    let start = full + usize::from(remainder != 0);
    bytes
        .get(start..)
        .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
}

fn prefix_matches(left: &[u8], right: &[u8], prefix_len: u8) -> bool {
    let full = usize::from(prefix_len) / 8;
    let remainder = usize::from(prefix_len) % 8;
    if left.get(..full) != right.get(..full) {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    left.get(full)
        .zip(right.get(full))
        .is_some_and(|(left, right)| (left & mask) == (right & mask))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreas_proto::messages::{
        MAX_SIGNED_OBJECT_LEN, SignedObject, SignerRole, SignerSignatures,
    };
    use boreas_proto::objects::{
        AttachmentLease, CoreLsa, DirectGrant, Endpoint, NodeIdentity, NodeRole as ObjectNodeRole,
        ObjectType, RouteGrant, StatusSnapshot,
    };
    use openssl::pkey::{Id, KeyType, PKey, Private};
    use openssl::sign::Signer;

    const NET: [u8; 16] = [0x42; 16];

    struct TestSigner {
        key_id: Vec<u8>,
        ed25519: PKey<Private>,
        mldsa: PKey<Private>,
        authority: Authority,
        scope: IssuerScope,
    }
    impl TestSigner {
        fn new(key_id: u8, authority: Authority, scope: IssuerScope) -> Self {
            let ed25519 = PKey::generate_ed25519().unwrap();
            let mldsa =
                PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[key_id; 32]).unwrap();
            Self {
                key_id: vec![key_id],
                ed25519,
                mldsa,
                authority,
                scope,
            }
        }
        fn record(&self) -> IssuerRecord {
            IssuerRecord {
                issuer_key_id: self.key_id.clone(),
                issuer_generation: 1,
                authority: self.authority,
                ed25519_public_key_der: self.ed25519.public_key_to_der().unwrap(),
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa_public_key_der: self.mldsa.public_key_to_der().unwrap(),
                scope: self.scope.clone(),
            }
        }
        fn sign(&self, object: &ManagementObject) -> Vec<u8> {
            let raw_tbs = objects::encode_tbs(object).unwrap();
            let message = objects::signature_input(
                &raw_tbs,
                object.body.object_type(),
                MANAGEMENT_SCHEMA_VERSION,
            )
            .unwrap();
            let mut ed_signer = Signer::new_without_digest(&self.ed25519).unwrap();
            let ed25519: [u8; ED25519_SIGNATURE_LEN] = ed_signer
                .sign_oneshot_to_vec(&message)
                .unwrap()
                .try_into()
                .unwrap();
            let mut mldsa_signer = Signer::new_without_digest(&self.mldsa).unwrap();
            let mldsa = mldsa_signer.sign_oneshot_to_vec(&message).unwrap();
            let primary = SignerSignatures {
                role: SignerRole::Primary,
                ed25519,
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa,
            };
            let signers = if object.body.object_type() == ObjectType::AttachmentLease {
                // The proto schema requires two signers for a Lease. This test signer is
                // only exercising the disabled-policy branch, not a real node/core pair.
                let co_sign = SignerSignatures {
                    role: SignerRole::CoSign,
                    ..primary.clone()
                };
                vec![primary, co_sign]
            } else {
                vec![primary]
            };
            SignedObject {
                object_type: object.body.object_type(),
                raw_tbs,
                signers,
            }
            .encode()
            .unwrap()
        }
    }
    fn sign_bytes(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new_without_digest(key).unwrap();
        signer.sign_oneshot_to_vec(message).unwrap()
    }
    fn sign_lease(
        object: &ManagementObject,
        node_ed25519: &PKey<Private>,
        node_mldsa: &PKey<Private>,
        core: &TestSigner,
    ) -> Vec<u8> {
        let raw_tbs = objects::encode_tbs(object).unwrap();
        let message = objects::signature_input(
            &raw_tbs,
            object.body.object_type(),
            MANAGEMENT_SCHEMA_VERSION,
        )
        .unwrap();
        let node_ed: [u8; ED25519_SIGNATURE_LEN] =
            sign_bytes(node_ed25519, &message).try_into().unwrap();
        let node_ml = sign_bytes(node_mldsa, &message);
        let core_ed: [u8; ED25519_SIGNATURE_LEN] =
            sign_bytes(&core.ed25519, &message).try_into().unwrap();
        let core_ml = sign_bytes(&core.mldsa, &message);
        SignedObject {
            object_type: object.body.object_type(),
            raw_tbs,
            signers: vec![
                SignerSignatures {
                    role: SignerRole::Primary,
                    ed25519: node_ed,
                    mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                    mldsa: node_ml,
                },
                SignerSignatures {
                    role: SignerRole::CoSign,
                    ed25519: core_ed,
                    mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                    mldsa: core_ml,
                },
            ],
        }
        .encode()
        .unwrap()
    }
    fn trust_with(signers: &[&TestSigner]) -> ManagementTrust {
        let mut trust = ManagementTrust::new(NET);
        for signer in signers {
            trust.add_issuer(signer.record()).unwrap();
        }
        trust
    }
    fn ml_identity_key(seed: u8) -> PKey<Private> {
        PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap()
    }
    fn node_ed_key() -> PKey<Private> {
        PKey::private_key_from_raw_bytes(&[0x77; 32], Id::ED25519).unwrap()
    }
    fn node_ed_public() -> [u8; 32] {
        node_ed_key().raw_public_key().unwrap().try_into().unwrap()
    }
    fn node_identity_object(
        signer: &TestSigner,
        role: ObjectNodeRole,
        home_core_id: u8,
        vip_octet: u8,
        generation: u64,
        identity_public_key: &[u8],
    ) -> ManagementObject {
        let node_id = ((u16::from(home_core_id) - 1) << 8) | u16::from(vip_octet);
        ManagementObject {
            net_id: NET,
            issuer_key_id: signer.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(node_id),
            seq: generation,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::NodeIdentity(NodeIdentity {
                net_id: NET,
                node_id,
                home_core_id,
                vip: [10, 20, home_core_id, vip_octet],
                vip6: [0; 16],
                role,
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                identity_pub_mldsa: identity_public_key.to_vec(),
                identity_pub_ed25519: node_ed_public(),
                identity_generation: generation,
                not_before: 100,
                expires: 1_000,
                scope: Vec::new(),
            }),
        }
    }
    fn route_grant_object(
        signer: &TestSigner,
        prefix: Vec<u8>,
        prefix_len: u8,
    ) -> ManagementObject {
        ManagementObject {
            net_id: NET,
            issuer_key_id: signer.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(2),
            seq: 1,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::RouteGrant(RouteGrant {
                subject_node_id: 2,
                prefix,
                prefix_len,
                metric: 10,
                ha_group: Vec::new(),
                seq: 1,
                expires: 1_000,
            }),
        }
    }
    fn core_lsa_object(signer: &TestSigner, core_id: u8) -> ManagementObject {
        ManagementObject {
            net_id: NET,
            issuer_key_id: signer.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Core(core_id),
            seq: 1,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::CoreLsa(CoreLsa {
                core_id,
                core_generation: 1,
                seq: 1,
                neighbors: Vec::new(),
            }),
        }
    }
    fn direct_grant_object(signer: &TestSigner) -> ManagementObject {
        ManagementObject {
            net_id: NET,
            issuer_key_id: signer.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(2),
            seq: 1,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::DirectGrant(DirectGrant {
                subject_node_id: 2,
                endpoint: Endpoint::Ip(vec![10, 0, 0, 1]),
                port: 443,
                sni: b"example.boreas".to_vec(),
                expires: 1_000,
            }),
        }
    }
    fn status_snapshot_object(signer: &TestSigner) -> ManagementObject {
        ManagementObject {
            net_id: NET,
            issuer_key_id: signer.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Network,
            seq: 1,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::StatusSnapshot(StatusSnapshot {
                issued_at: 100,
                next_update: 1_000,
                sequence: 1,
                revocations: Vec::new(),
            }),
        }
    }

    #[test]
    fn node_identity_requires_both_real_signatures_and_retains_evidence() {
        let signer = TestSigner::new(
            1,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        let identity_key = ml_identity_key(21);
        let identity_public = identity_key.raw_public_key().unwrap();
        let object = node_identity_object(&signer, ObjectNodeRole::Edge, 1, 2, 1, &identity_public);
        let raw_tbs = objects::encode_tbs(&object).unwrap();
        let signatures = signer.sign(&object);
        let mut trust = trust_with(&[&signer]);
        let verified = trust.verify_test(&raw_tbs, &signatures, 200).unwrap();
        assert_eq!(verified.object_id(), sha256(&raw_tbs).unwrap());
        assert_eq!(verified.raw_tbs(), raw_tbs.as_slice());
        assert_eq!(verified.raw_signed_object(), signatures.as_slice());
        assert!(!verified.is_duplicate());
        let duplicate = trust.verify_test(&raw_tbs, &signatures, 200).unwrap();
        assert!(duplicate.duplicate);
        let mut mismatched_tbs = raw_tbs.clone();
        mismatched_tbs[0] ^= 1;
        assert_eq!(
            trust.verify_test(&mismatched_tbs, &signatures, 200),
            Err(Error::NonCanonicalObject)
        );

        let mut bad_ed = SignedObject::decode(&signatures).unwrap();
        bad_ed.signers[0].ed25519[0] ^= 1;
        assert_eq!(
            trust.verify_test(&raw_tbs, &bad_ed.encode().unwrap(), 200),
            Err(Error::InvalidEd25519Signature)
        );
        let mut bad_mldsa = SignedObject::decode(&signatures).unwrap();
        bad_mldsa.signers[0].mldsa[0] ^= 1;
        assert_eq!(
            trust.verify_test(&raw_tbs, &bad_mldsa.encode().unwrap(), 200),
            Err(Error::InvalidMlDsaSignature)
        );
        // The proto envelope has no optional Ed25519 flag: a truncated signature stream
        // must fail decoding rather than becoming an ML-DSA-only acceptance.
        let truncated = &signatures[..signatures.len() - 1];
        assert!(SignedObject::decode(truncated).is_err());
    }

    #[test]
    fn core_cannot_sign_identity_and_scope_blocks_role_or_home_escalation() {
        let identity_signer = TestSigner::new(
            2,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        let identity_key = ml_identity_key(22);
        let identity_public = identity_key.raw_public_key().unwrap();
        let core_signer = TestSigner::new(
            3,
            Authority::CoreOperationalKey { core_id: 1 },
            IssuerScope::default(),
        );
        let core_identity = node_identity_object(
            &core_signer,
            ObjectNodeRole::Edge,
            1,
            2,
            1,
            &identity_public,
        );
        let raw = objects::encode_tbs(&core_identity).unwrap();
        let signatures = core_signer.sign(&core_identity);
        let mut trust = trust_with(&[&identity_signer, &core_signer]);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::UnauthorizedObjectType)
        );

        let core_role = node_identity_object(
            &identity_signer,
            ObjectNodeRole::Core,
            1,
            1,
            1,
            &identity_public,
        );
        let raw = objects::encode_tbs(&core_role).unwrap();
        let signatures = identity_signer.sign(&core_role);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::OutOfScope)
        );
        let other_home = node_identity_object(
            &identity_signer,
            ObjectNodeRole::Edge,
            2,
            2,
            1,
            &identity_public,
        );
        let raw = objects::encode_tbs(&other_home).unwrap();
        let signatures = identity_signer.sign(&other_home);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::OutOfScope)
        );
    }

    #[test]
    fn route_grant_scope_and_core_lsa_target_are_enforced() {
        let route_signer = TestSigner::new(
            4,
            Authority::RouteAuthority,
            IssuerScope::for_route(vec![AllowedPrefix::new(vec![192, 168, 0, 0], 16).unwrap()])
                .unwrap(),
        );
        let in_scope = route_grant_object(&route_signer, vec![192, 168, 10, 0], 24);
        let raw = objects::encode_tbs(&in_scope).unwrap();
        let signatures = route_signer.sign(&in_scope);
        let mut trust = trust_with(&[&route_signer]);
        assert!(trust.verify_test(&raw, &signatures, 200).is_ok());
        let out_of_scope = route_grant_object(&route_signer, vec![192, 169, 10, 0], 24);
        let raw = objects::encode_tbs(&out_of_scope).unwrap();
        let signatures = route_signer.sign(&out_of_scope);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::OutOfScope)
        );

        let core_one = TestSigner::new(
            5,
            Authority::CoreOperationalKey { core_id: 1 },
            IssuerScope::default(),
        );
        trust.add_issuer(core_one.record()).unwrap();
        let own_lsa = core_lsa_object(&core_one, 1);
        let raw = objects::encode_tbs(&own_lsa).unwrap();
        let signatures = core_one.sign(&own_lsa);
        assert!(trust.verify_test(&raw, &signatures, 200).is_ok());
        let other_lsa = core_lsa_object(&core_one, 2);
        let raw = objects::encode_tbs(&other_lsa).unwrap();
        let signatures = core_one.sign(&other_lsa);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::UnauthorizedObjectType)
        );
    }

    #[test]
    fn same_sequence_equivocation_stale_generation_and_regression_are_rejected() {
        let signer = TestSigner::new(
            6,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        let identity_key = ml_identity_key(26);
        let identity_public = identity_key.raw_public_key().unwrap();
        let first = node_identity_object(&signer, ObjectNodeRole::Edge, 1, 2, 2, &identity_public);
        let raw_first = objects::encode_tbs(&first).unwrap();
        let signatures = signer.sign(&first);
        let mut trust = trust_with(&[&signer]);
        assert!(trust.verify_test(&raw_first, &signatures, 200).is_ok());

        let mut higher = first.clone();
        if let ObjectBody::NodeIdentity(body) = &mut higher.body {
            body.identity_generation = 3;
            body.not_before = 110;
            body.expires = 1_000;
        }
        higher.seq = 3;
        higher.issued_at = 110;
        let raw_higher = objects::encode_tbs(&higher).unwrap();
        let signatures = signer.sign(&higher);
        assert!(trust.verify_test(&raw_higher, &signatures, 200).is_ok());

        let stale = first.clone();
        let raw_stale = objects::encode_tbs(&stale).unwrap();
        let signatures = signer.sign(&stale);
        assert_eq!(
            trust.verify_test(&raw_stale, &signatures, 200),
            Err(Error::StaleSequence)
        );

        let mut regressed = first.clone();
        if let ObjectBody::NodeIdentity(body) = &mut regressed.body {
            body.identity_generation = 4;
            body.not_before = 105;
            body.expires = 1_000;
        }
        regressed.seq = 4;
        regressed.issued_at = 105;
        let raw_regressed = objects::encode_tbs(&regressed).unwrap();
        let signatures = signer.sign(&regressed);
        assert_eq!(
            trust.verify_test(&raw_regressed, &signatures, 200),
            Err(Error::IssuedAtRegression)
        );

        // Same logical slot and seq as the accepted generation 3, different TBS bytes:
        // accepted objects remain usable, but this writer slot then latches as conflicted.
        let mut conflicted = higher.clone();
        if let ObjectBody::NodeIdentity(body) = &mut conflicted.body {
            body.scope = vec![9];
        }
        let raw_conflicted = objects::encode_tbs(&conflicted).unwrap();
        let signatures = signer.sign(&conflicted);
        assert_eq!(
            trust.verify_test(&raw_conflicted, &signatures, 200),
            Err(Error::Equivocation)
        );
        assert_eq!(trust.conflict_evidence(), Some(signatures.as_slice()));
    }

    #[test]
    fn cross_network_freshness_and_forged_signer_fail_closed() {
        let signer = TestSigner::new(
            7,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        let identity_key = ml_identity_key(27);
        let identity_public = identity_key.raw_public_key().unwrap();
        let mut object =
            node_identity_object(&signer, ObjectNodeRole::Edge, 1, 2, 1, &identity_public);
        object.net_id = [0x41; 16];
        if let ObjectBody::NodeIdentity(body) = &mut object.body {
            body.net_id = object.net_id;
        }
        let raw = objects::encode_tbs(&object).unwrap();
        let signatures = signer.sign(&object);
        let mut trust = trust_with(&[&signer]);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::WrongNetwork)
        );
        let valid = node_identity_object(&signer, ObjectNodeRole::Edge, 1, 2, 1, &identity_public);
        let raw = objects::encode_tbs(&valid).unwrap();
        let signatures = signer.sign(&valid);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 99),
            Err(Error::NotYetValid)
        );
        assert_eq!(
            trust.verify_test(&raw, &signatures, 1_000),
            Err(Error::Expired)
        );

        let attacker = TestSigner::new(
            8,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        let mut forged = valid;
        forged.issuer_key_id = signer.key_id.clone();
        let raw = objects::encode_tbs(&forged).unwrap();
        let signatures = attacker.sign(&forged);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::InvalidEd25519Signature)
        );
    }

    #[test]
    fn direct_grant_status_snapshot_and_real_two_party_lease() {
        let core = TestSigner::new(
            9,
            Authority::CoreOperationalKey { core_id: 1 },
            IssuerScope::default(),
        );
        let grant = direct_grant_object(&core);
        let raw = objects::encode_tbs(&grant).unwrap();
        let signatures = core.sign(&grant);
        let mut trust = trust_with(&[&core]);
        assert!(trust.verify_test(&raw, &signatures, 200).is_ok());

        let status = TestSigner::new(10, Authority::StatusSigner, IssuerScope::default());
        let snapshot = status_snapshot_object(&status);
        let raw = objects::encode_tbs(&snapshot).unwrap();
        let signatures = status.sign(&snapshot);
        trust.add_issuer(status.record()).unwrap();
        assert!(trust.verify_test(&raw, &signatures, 200).is_ok());

        let identity_authority = TestSigner::new(
            11,
            Authority::IdentityAuthority,
            IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        );
        trust.add_issuer(identity_authority.record()).unwrap();
        let node_ml = ml_identity_key(31);
        let node_ml_public = node_ml.raw_public_key().unwrap();
        let identity = node_identity_object(
            &identity_authority,
            ObjectNodeRole::Edge,
            1,
            2,
            1,
            &node_ml_public,
        );
        let raw_identity = objects::encode_tbs(&identity).unwrap();
        let identity_signatures = identity_authority.sign(&identity);
        assert!(
            trust
                .verify_test(&raw_identity, &identity_signatures, 200)
                .is_ok()
        );

        let lease = ManagementObject {
            net_id: NET,
            issuer_key_id: core.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Node(2),
            seq: 1,
            issued_at: 100,
            expires: 1_000,
            extensions: Vec::new(),
            body: ObjectBody::AttachmentLease(AttachmentLease {
                node_id: 2,
                identity_generation: 1,
                attach_generation: 1,
                target_core_id: 1,
                not_before: 100,
                expires: 1_000,
            }),
        };
        let raw = objects::encode_tbs(&lease).unwrap();
        let node_ed = node_ed_key();
        let lease_signatures = sign_lease(&lease, &node_ed, &node_ml, &core);
        assert!(trust.verify_test(&raw, &lease_signatures, 200).is_ok());

        // A different Ed25519 key cannot take the Primary slot for the verified node.
        let attacker_ed = PKey::generate_ed25519().unwrap();
        let signatures = sign_lease(&lease, &attacker_ed, &node_ml, &core);
        assert_eq!(
            trust.verify_test(&raw, &signatures, 200),
            Err(Error::InvalidEd25519Signature)
        );
        // A stale node generation is not accepted even with a valid counter-signature.
        let mut stale = lease.clone();
        if let ObjectBody::AttachmentLease(body) = &mut stale.body {
            body.identity_generation = 2;
        }
        let raw_stale = objects::encode_tbs(&stale).unwrap();
        let signatures = sign_lease(&stale, &node_ed, &node_ml, &core);
        assert_eq!(
            trust.verify_test(&raw_stale, &signatures, 200),
            Err(Error::StaleNodeIdentity)
        );
        // Without an already verified NodeIdentity, Lease Primary is unknown.
        let mut bare_trust = trust_with(&[&core]);
        assert_eq!(
            bare_trust.verify_test(&raw, &lease_signatures, 200),
            Err(Error::UnknownNodeIdentity)
        );
    }

    #[test]
    fn signed_object_total_cap_is_sixteen_kibibytes() {
        assert_eq!(MAX_SIGNED_OBJECT_BYTES, MAX_SIGNED_OBJECT_LEN);
        let too_large = vec![0; MAX_SIGNED_OBJECT_BYTES + 1];
        assert!(SignedObject::decode(&too_large).is_err());
    }
}
