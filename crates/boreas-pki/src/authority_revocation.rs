//! Authority-specific revocation verification with opaque tokens.
//!
//! This module verifies the independent
//! [`boreas_proto::authority_revocation::AuthorityRevocation`] object. It does not
//! reuse `StatusSnapshot.revocations` or extend `objects::ObjectType`. The
//! Linux daemon uses it through the separate identity extension of `StatusStore`.
//!
//! # Authority separation
//!
//! The signed object names its class. This slice fully enables only `Identity`:
//!
//! * `Identity` must be signed by an `IdentityAuthority` record whose
//!   `IssuerScope` authorizes the subject's home Core and role. This is the
//!   complete reference slice; both Ed25519 and ML-DSA-65 signatures must verify
//!   over the exact domain-separated TBS.
//! * `Core` (NetworkRoot), `Route` (RouteAuthority, one prefix) and `Direct`
//!   (the CoreOperationalKey of the issuing Core, never inferred from the
//!   subject's home Core) remain schema-reserved. `verify` returns
//!   [`Error::UnsupportedClass`] for them in this slice; no partial token exists.
//!
//! Only the Identity slice is enabled. It requires a provisioned IdentityAuthority
//! record, both signatures, the exact scope evidence and a still-valid
//! root-authorization grant window. There is no "missing evidence means accept"
//! path.
//!
//! There is no caller boolean that selects an authority. The authority comes from
//! the provisioned [`IssuerRecord`] and is re-checked with the existing
//! [`crate::may_issue`] mapping.
//!
//! # Trust provisioning
//!
//! [`AuthorityRevocationTrust::add_issuer`] copies the record into this verifier
//! only after the existing [`ManagementTrust::add_issuer`] has parsed and
//! type-checked the Ed25519 and ML-DSA public keys, and it retains the issuer
//! grant's `not_before`/`expires` window. [`AuthorityRevocationTrust::add_verified_issuer`]
//! accepts a [`VerifiedIssuerAuthorization`] from `root_authorization` and keeps
//! that token's validity instead of discarding it during `IssuerRecord`
//! conversion. The grant window is re-checked on every verification and is part
//! of the token's freshness intersection. Records are still out-of-band trust
//! anchors; this module does not parse X.509 chains.
//!
//! # What the token does not prove
//!
//! [`VerifiedAuthorityRevocation`] proves only that the exact object bytes and
//! both signatures verified against a provisioned authority and that both the
//! object and its issuer-grant validity intervals contain the caller-supplied
//! `now`. It does not provide a durable sequence watermark, anti-replay storage,
//! clock trust or resource cleanup. The status store owns replay and persistence;
//! the daemon owns the authenticated session handles. This verifier has no
//! independent trusted-clock service.
//!
//! No public constructor exists for [`VerifiedAuthorityRevocation`]; only
//! [`AuthorityRevocationTrust::verify`] creates one. The token fields are private,
//! and `Clone` is not a signing capability.

#![cfg(feature = "openssl-backend")]

use std::{collections::BTreeMap, fmt};

use openssl::{
    hash::{MessageDigest, hash},
    pkey::{KeyType, PKey},
    sign::Verifier,
};

use boreas_proto::{
    authority_revocation::{AuthorityRevocation, RevocationClass, RevocationScope},
    objects::MldsaParameterSet,
};

use crate::{
    Authority, NodeRole, ObjectKind,
    management::{self, IssuerRecord, ManagementTrust},
    root_authorization::VerifiedIssuerAuthorization,
};

/// Ed25519 signature length accepted for this profile.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 signature length accepted for this profile.
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    InvalidCandidate,
    WrongNetwork,
    InvalidTime,
    UnknownIssuer,
    IssuerGenerationMismatch,
    /// The provisioned authority cannot issue this object class.
    WrongAuthority,
    /// Only the Identity slice is enabled; Core/Route/Direct fail closed.
    UnsupportedClass,
    /// The root-authorization grant that made this issuer trustworthy has
    /// expired or is not yet valid.
    IssuerNotValid,
    /// The subject is outside the IdentityAuthority's configured role/home-Core scope.
    OutOfScope,
    InvalidIssuerRecord,
    InvalidSignatureLength,
    InvalidEdSignature,
    InvalidMlDsaSignature,
    Backend,
    /// The existing `ManagementTrust::add_issuer` rejected the record.
    IssuerRejected(management::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Provisioned authority records accepted by this verifier.
///
/// The record's authority is out-of-band trust input, exactly like
/// `ManagementTrust`; `add_issuer` does not discover or validate a certificate
/// chain. This slice accepts only `IdentityAuthority` records; the other
/// authorities remain schema-reserved and fail closed.
pub struct AuthorityRevocationTrust {
    net_id: [u8; 16],
    issuers: BTreeMap<Vec<u8>, TrustedIssuer>,
    /// Existing verifier used only to reuse its real issuer key parsing/type
    /// checks and duplicate-key rejection. It records no revocation state.
    validation: ManagementTrust,
}

/// An issuer record plus the root-authorization grant window that made it
/// trustworthy. `IssuerRecord` has no validity fields of its own, so this bound
/// must be retained here instead of being dropped during conversion.
struct TrustedIssuer {
    record: IssuerRecord,
    not_before: u64,
    expires: u64,
}

impl AuthorityRevocationTrust {
    pub fn new(net_id: [u8; 16]) -> Self {
        Self {
            net_id,
            issuers: BTreeMap::new(),
            validation: ManagementTrust::new(net_id),
        }
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }

    /// Provision one IdentityAuthority record after the existing issuer checks.
    ///
    /// `not_before` / `expires` are the root-authorization grant window the record
    /// came from. They are retained and checked on every `verify`, because
    /// `IssuerRecord` itself has no validity fields and an expired grant must not
    /// keep authorizing new revocations. The record must carry an identity scope
    /// with at least one role and one home Core and no route prefixes.
    pub fn add_issuer(
        &mut self,
        record: IssuerRecord,
        not_before: u64,
        expires: u64,
    ) -> Result<(), Error> {
        if record.authority != Authority::IdentityAuthority {
            return Err(Error::UnsupportedClass);
        }
        if record.mldsa_parameter_set != MldsaParameterSet::Mldsa65 {
            return Err(Error::InvalidIssuerRecord);
        }
        if record.scope.allowed_roles.is_empty()
            || record.scope.allowed_home_cores.is_empty()
            || !record.scope.allowed_prefixes.is_empty()
            || not_before >= expires
        {
            return Err(Error::InvalidIssuerRecord);
        }
        self.insert_issuer(record, not_before, expires)
    }

    /// Add an IdentityAuthority record produced by the existing root-authorization
    /// verifier. The grant's validity window is retained and re-checked at every
    /// verification; it is not discarded during the `IssuerRecord` conversion.
    pub fn add_verified_issuer(
        &mut self,
        verified: VerifiedIssuerAuthorization,
    ) -> Result<(), Error> {
        if verified.net_id() != self.net_id {
            return Err(Error::WrongNetwork);
        }
        let (not_before, expires) = verified.validity();
        self.add_issuer(verified.issuer_record(), not_before, expires)
    }

    fn insert_issuer(
        &mut self,
        record: IssuerRecord,
        not_before: u64,
        expires: u64,
    ) -> Result<(), Error> {
        // Reuse the real Ed25519/ML-DSA key parsing, algorithm checks and
        // duplicate-key rejection instead of accepting raw caller bytes.
        self.validation
            .add_issuer(record.clone())
            .map_err(Error::IssuerRejected)?;
        self.issuers.insert(
            record.issuer_key_id.clone(),
            TrustedIssuer {
                record,
                not_before,
                expires,
            },
        );
        Ok(())
    }

    /// Verify one exact Identity TBS and both authority signatures, then mint an
    /// opaque token. A missing record, expired issuer grant, bad signature, bad
    /// time window or out-of-scope subject yields no token. Non-Identity classes
    /// fail closed with [`Error::UnsupportedClass`].
    pub fn verify(
        &self,
        raw_tbs: &[u8],
        ed25519_signature: &[u8],
        mldsa_signature: &[u8],
        now: u64,
    ) -> Result<VerifiedAuthorityRevocation, Error> {
        let object =
            AuthorityRevocation::decode_tbs(raw_tbs).map_err(|_| Error::InvalidCandidate)?;
        if object.class != RevocationClass::Identity {
            return Err(Error::UnsupportedClass);
        }
        if object.net_id != self.net_id {
            return Err(Error::WrongNetwork);
        }
        if now < object.issued_at || now >= object.next_update {
            return Err(Error::InvalidTime);
        }
        if ed25519_signature.len() != ED25519_SIGNATURE_LEN
            || mldsa_signature.len() != MLDSA65_SIGNATURE_LEN
        {
            return Err(Error::InvalidSignatureLength);
        }
        let trusted = self
            .issuers
            .get(&object.issuer_key_id)
            .ok_or(Error::UnknownIssuer)?;
        // The root-authorization grant validity is not part of `IssuerRecord`.
        // Check it on every verify, not only when the record was provisioned.
        if now < trusted.not_before || now >= trusted.expires {
            return Err(Error::IssuerNotValid);
        }
        let issuer = &trusted.record;
        if object.issuer_generation != issuer.issuer_generation {
            return Err(Error::IssuerGenerationMismatch);
        }
        if !crate::may_issue(issuer.authority, ObjectKind::IdentityRevocation) {
            return Err(Error::WrongAuthority);
        }
        let (home_core, role) = identity_subject_slot(object.subject_node_id)?;
        if issuer.scope.allowed_home_cores.is_empty()
            || !issuer.scope.allowed_home_cores.contains(&home_core)
            || issuer.scope.allowed_roles.is_empty()
            || !issuer.scope.allowed_roles.contains(&role)
        {
            return Err(Error::OutOfScope);
        }
        let message =
            AuthorityRevocation::signature_input(raw_tbs).map_err(|_| Error::InvalidCandidate)?;
        let ed_key = PKey::public_key_from_der(&issuer.ed25519_public_key_der)
            .map_err(|_| Error::IssuerRejected(management::Error::InvalidIssuerKey))?;
        let pq_key = PKey::public_key_from_der(&issuer.mldsa_public_key_der)
            .map_err(|_| Error::IssuerRejected(management::Error::InvalidIssuerKey))?;
        verify_both(
            &ed_key,
            &pq_key,
            &message,
            ed25519_signature,
            mldsa_signature,
        )?;
        Ok(VerifiedAuthorityRevocation {
            net_id: object.net_id,
            class: object.class,
            subject_node_id: object.subject_node_id,
            identity_generation: object.identity_generation,
            issuer_key_id: object.issuer_key_id,
            issuer_generation: object.issuer_generation,
            authority: issuer.authority,
            scope: object.scope,
            sequence: object.seq,
            issued_at: object.issued_at,
            next_update: object.next_update,
            issuer_not_before: trusted.not_before,
            issuer_expires: trusted.expires,
            object_digest: sha256(raw_tbs)?,
        })
    }
}

/// Opaque proof that one Identity revocation object verified. Private fields and
/// no public constructor: only [`AuthorityRevocationTrust::verify`] can create it.
#[derive(Clone, Debug)]
pub struct VerifiedAuthorityRevocation {
    net_id: [u8; 16],
    class: RevocationClass,
    subject_node_id: u16,
    identity_generation: u64,
    issuer_key_id: Vec<u8>,
    issuer_generation: u64,
    authority: Authority,
    scope: RevocationScope,
    sequence: u64,
    issued_at: u64,
    next_update: u64,
    issuer_not_before: u64,
    issuer_expires: u64,
    object_digest: [u8; 32],
}

impl VerifiedAuthorityRevocation {
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn class(&self) -> RevocationClass {
        self.class
    }

    pub fn subject_node_id(&self) -> u16 {
        self.subject_node_id
    }

    pub fn identity_generation(&self) -> u64 {
        self.identity_generation
    }

    pub fn issuer_key_id(&self) -> &[u8] {
        &self.issuer_key_id
    }

    pub fn issuer_generation(&self) -> u64 {
        self.issuer_generation
    }

    /// The provisioned authority that signed this object.
    pub fn issuer_authority(&self) -> Authority {
        self.authority
    }

    /// Verified class scope bytes. For the enabled `Identity` class this is the
    /// canonical empty scope.
    pub fn scope(&self) -> &RevocationScope {
        &self.scope
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The revocation object's own half-open signed interval. This is not the
    /// whole freshness bound; use [`Self::freshness`]/[`Self::is_fresh_at`].
    pub fn validity(&self) -> (u64, u64) {
        (self.issued_at, self.next_update)
    }

    /// Validity of the root-authorization grant that made the issuer record
    /// trustworthy. The issuer record itself carries no validity fields, so this
    /// bound is stored on the token explicitly.
    pub fn issuer_validity(&self) -> (u64, u64) {
        (self.issuer_not_before, self.issuer_expires)
    }

    /// Intersection of the revocation object window and the issuer grant window.
    /// Every freshness decision must use this, not `validity()` alone.
    pub fn freshness(&self) -> (u64, u64) {
        (
            self.issued_at.max(self.issuer_not_before),
            self.next_update.min(self.issuer_expires),
        )
    }

    /// Fail-closed freshness check for a kept token. It is true only while both
    /// the object and the root-authorization grant are inside their half-open
    /// intervals. This is not durable replay protection or a trusted clock.
    pub fn is_fresh_at(&self, now: u64) -> bool {
        let (from, until) = self.freshness();
        now >= from && now < until
    }

    /// SHA-256 of the exact TBS bytes, for audit and durable correlation only.
    pub fn object_digest(&self) -> [u8; 32] {
        self.object_digest
    }
}

fn identity_subject_slot(node_id: u16) -> Result<(u8, NodeRole), Error> {
    let home_core = (node_id >> 8) + 1;
    if !(1..=16).contains(&home_core) {
        return Err(Error::InvalidCandidate);
    }
    let octet = (node_id & 0xff) as u8;
    let role = match octet {
        1 => NodeRole::Core,
        2..=251 => NodeRole::Edge,
        _ => return Err(Error::InvalidCandidate),
    };
    Ok((
        u8::try_from(home_core).map_err(|_| Error::InvalidCandidate)?,
        role,
    ))
}

fn verify_both(
    ed_key: &PKey<openssl::pkey::Public>,
    pq_key: &PKey<openssl::pkey::Public>,
    message: &[u8],
    ed25519_signature: &[u8],
    mldsa_signature: &[u8],
) -> Result<(), Error> {
    if !ed_key.is_a(KeyType::ED25519) || !pq_key.is_a(KeyType::ML_DSA_65) {
        return Err(Error::InvalidIssuerRecord);
    }
    let mut verifier = Verifier::new_without_digest(ed_key).map_err(|_| Error::Backend)?;
    if !verifier
        .verify_oneshot(ed25519_signature, message)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidEdSignature);
    }
    let mut verifier = Verifier::new_without_digest(pq_key).map_err(|_| Error::Backend)?;
    if !verifier
        .verify_oneshot(mldsa_signature, message)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidMlDsaSignature);
    }
    Ok(())
}

fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    let digest = hash(MessageDigest::sha256(), data).map_err(|_| Error::Backend)?;
    digest.as_ref().try_into().map_err(|_| Error::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        management::IssuerScope,
        root_authorization::{
            NetworkRootPin, Purpose, RootAuthorizationCandidate, Scope,
            VerifiedIssuerAuthorization, verify as verify_root,
        },
    };
    use boreas_proto::authority_revocation::RevocationScope;
    use openssl::{
        pkey::{PKey, Private},
        sign::Signer,
    };

    const NET: [u8; 16] = [7; 16];

    fn keys(seed: u8) -> (PKey<Private>, PKey<Private>) {
        (
            PKey::generate_ed25519().unwrap(),
            PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
        )
    }

    fn sign(ed: &PKey<Private>, pq: &PKey<Private>, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut signer = Signer::new_without_digest(ed).unwrap();
        let ed_signature = signer.sign_oneshot_to_vec(message).unwrap();
        let mut signer = Signer::new_without_digest(pq).unwrap();
        (ed_signature, signer.sign_oneshot_to_vec(message).unwrap())
    }

    fn record(ed: &PKey<Private>, pq: &PKey<Private>) -> IssuerRecord {
        IssuerRecord {
            issuer_key_id: b"identity-authority-v1".to_vec(),
            issuer_generation: 1,
            authority: Authority::IdentityAuthority,
            ed25519_public_key_der: ed.public_key_to_der().unwrap(),
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: pq.public_key_to_der().unwrap(),
            scope: IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
        }
    }

    /// Build a real root-authorized IdentityAuthority token, including the
    /// grant validity window, so `add_verified_issuer` is tested against the same
    /// path that previously dropped `not_before`/`expires`.
    fn verified_grant(
        issuer_ed: &PKey<Private>,
        issuer_pq: &PKey<Private>,
        root_ed: &PKey<Private>,
        root_pq: &PKey<Private>,
        not_before: u64,
        expires: u64,
    ) -> VerifiedIssuerAuthorization {
        let candidate = RootAuthorizationCandidate {
            net_id: NET,
            issuer_key_id: b"identity-authority-v1".to_vec(),
            issuer_generation: 1,
            purpose: Purpose::Identity,
            ed25519_public_key_der: issuer_ed.public_key_to_der().unwrap(),
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: issuer_pq.public_key_to_der().unwrap(),
            scope: Scope::Identity {
                roles: vec![NodeRole::Edge],
                home_cores: vec![1],
            },
            not_before,
            expires,
            chain_depth: 1,
            may_delegate: false,
        };
        let raw = candidate.encode_candidate().unwrap();
        let mut message = b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0".to_vec();
        message.extend_from_slice(&raw);
        let (root_ed_signature, root_pq_signature) = sign(root_ed, root_pq, &message);
        let pin = NetworkRootPin::provisioned(
            NET,
            root_ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        verify_root(
            &candidate,
            &raw,
            &root_ed_signature,
            &root_pq_signature,
            &pin,
            NET,
            not_before,
        )
        .unwrap()
    }

    fn object() -> AuthorityRevocation {
        AuthorityRevocation {
            net_id: NET,
            class: RevocationClass::Identity,
            subject_node_id: 0x0007,
            identity_generation: 2,
            issuer_key_id: b"identity-authority-v1".to_vec(),
            issuer_generation: 1,
            scope: RevocationScope::default(),
            seq: 1,
            issued_at: 1_000,
            next_update: 2_000,
        }
    }

    fn signed(
        object: &AuthorityRevocation,
        ed: &PKey<Private>,
        pq: &PKey<Private>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let raw = object.encode_tbs().unwrap();
        let message = AuthorityRevocation::signature_input(&raw).unwrap();
        let (ed_signature, pq_signature) = sign(ed, pq, &message);
        (raw, ed_signature, pq_signature)
    }

    #[test]
    fn identity_token_requires_real_dual_signature_and_scope() {
        let (ed, pq) = keys(11);
        let mut trust = AuthorityRevocationTrust::new(NET);
        trust.add_issuer(record(&ed, &pq), 1_000, 3_000).unwrap();
        let (raw, ed_signature, pq_signature) = signed(&object(), &ed, &pq);
        let token = trust
            .verify(&raw, &ed_signature, &pq_signature, 1_500)
            .unwrap();
        assert_eq!(token.class(), RevocationClass::Identity);
        assert_eq!(token.subject_node_id(), 0x0007);
        assert_eq!(token.identity_generation(), 2);
        assert_eq!(token.issuer_key_id(), b"identity-authority-v1");
        assert_eq!(token.issuer_generation(), 1);
        assert_eq!(token.sequence(), 1);
        assert_eq!(token.validity(), (1_000, 2_000));
        assert_eq!(token.issuer_validity(), (1_000, 3_000));
        assert_eq!(token.freshness(), (1_000, 2_000));
        assert!(token.is_fresh_at(1_999));
        assert!(!token.is_fresh_at(2_000));
    }

    #[test]
    fn issuer_grant_validity_bounds_each_verification_and_the_token() {
        let (ed, pq) = keys(19);
        let mut trust = AuthorityRevocationTrust::new(NET);
        // The issuer grant ends before the revocation object does. Verification
        // at 1_900 would pass the object's own window, but must fail because the
        // root-authorization grant has expired.
        trust.add_issuer(record(&ed, &pq), 1_000, 1_800).unwrap();
        let (raw, ed_signature, pq_signature) = signed(&object(), &ed, &pq);
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 1_900)
                .unwrap_err(),
            Error::IssuerNotValid
        );
        let token = trust
            .verify(&raw, &ed_signature, &pq_signature, 1_500)
            .unwrap();
        assert_eq!(token.validity(), (1_000, 2_000));
        assert_eq!(token.issuer_validity(), (1_000, 1_800));
        assert_eq!(token.freshness(), (1_000, 1_800));
        assert!(token.is_fresh_at(1_799));
        assert!(!token.is_fresh_at(1_800));
    }

    #[test]
    fn verified_root_grant_retains_its_validity_for_later_checks() {
        let (issuer_ed, issuer_pq) = keys(20);
        let (root_ed, root_pq) = keys(21);
        let grant = verified_grant(&issuer_ed, &issuer_pq, &root_ed, &root_pq, 1_000, 1_800);
        let mut trust = AuthorityRevocationTrust::new(NET);
        assert_eq!(grant.validity(), (1_000, 1_800));
        trust.add_verified_issuer(grant).unwrap();
        let (raw, ed_signature, pq_signature) = signed(&object(), &issuer_ed, &issuer_pq);
        // The revocation object is still valid at 1_900, but its authorizing
        // grant is not. The converted IssuerRecord must not erase that bound.
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 1_900)
                .unwrap_err(),
            Error::IssuerNotValid
        );
    }

    #[test]
    fn both_signatures_and_time_are_enforced() {
        let (ed, pq) = keys(12);
        let mut trust = AuthorityRevocationTrust::new(NET);
        trust.add_issuer(record(&ed, &pq), 1_000, 3_000).unwrap();
        let (raw, ed_signature, pq_signature) = signed(&object(), &ed, &pq);

        let mut bad_ed = ed_signature.clone();
        bad_ed[0] ^= 1;
        assert_eq!(
            trust
                .verify(&raw, &bad_ed, &pq_signature, 1_500)
                .unwrap_err(),
            Error::InvalidEdSignature
        );
        let mut bad_pq = pq_signature.clone();
        bad_pq[0] ^= 1;
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &bad_pq, 1_500)
                .unwrap_err(),
            Error::InvalidMlDsaSignature
        );
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 2_000)
                .unwrap_err(),
            Error::InvalidTime
        );
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 999)
                .unwrap_err(),
            Error::InvalidTime
        );
    }

    #[test]
    fn wrong_network_issuer_and_scope_fail_closed() {
        let (ed, pq) = keys(13);
        let mut trust = AuthorityRevocationTrust::new(NET);
        trust.add_issuer(record(&ed, &pq), 1_000, 3_000).unwrap();

        let mut wrong_net = object();
        wrong_net.net_id = [8; 16];
        let (raw, ed_signature, pq_signature) = signed(&wrong_net, &ed, &pq);
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 1_500)
                .unwrap_err(),
            Error::WrongNetwork
        );

        let mut wrong_gen = object();
        wrong_gen.issuer_generation = 2;
        let (raw, ed_signature, pq_signature) = signed(&wrong_gen, &ed, &pq);
        assert_eq!(
            trust
                .verify(&raw, &ed_signature, &pq_signature, 1_500)
                .unwrap_err(),
            Error::IssuerGenerationMismatch
        );

        // The subject is in home Core 1; this record authorizes only Core 2.
        let mut other = record(&ed, &pq);
        other.issuer_key_id = b"identity-authority-2".to_vec();
        other.scope = IssuerScope::for_identity(vec![NodeRole::Edge], vec![2]).unwrap();
        let (ed2, pq2) = keys(14);
        other.ed25519_public_key_der = ed2.public_key_to_der().unwrap();
        other.mldsa_public_key_der = pq2.public_key_to_der().unwrap();
        let mut scoped = AuthorityRevocationTrust::new(NET);
        scoped.add_issuer(other, 1_000, 3_000).unwrap();
        let mut out_of_scope = object();
        out_of_scope.issuer_key_id = b"identity-authority-2".to_vec();
        let (raw, ed_signature, pq_signature) = signed(&out_of_scope, &ed2, &pq2);
        assert_eq!(
            scoped
                .verify(&raw, &ed_signature, &pq_signature, 1_500)
                .unwrap_err(),
            Error::OutOfScope
        );
    }

    #[test]
    fn unsupported_authority_and_non_identity_class_fail_closed() {
        let (ed, pq) = keys(15);
        let mut wrong_authority = record(&ed, &pq);
        wrong_authority.authority = Authority::StatusSigner;
        let mut trust = AuthorityRevocationTrust::new(NET);
        assert_eq!(
            trust.add_issuer(wrong_authority, 1_000, 3_000).unwrap_err(),
            Error::UnsupportedClass
        );

        // Only Identity is enabled in this slice. A correctly signed Core
        // object is still refused, not silently routed to another authority.
        let mut identity = AuthorityRevocationTrust::new(NET);
        identity.add_issuer(record(&ed, &pq), 1_000, 3_000).unwrap();
        let mut core = object();
        core.class = RevocationClass::Core;
        core.subject_node_id = 0x0101;
        let (raw, ed_signature, pq_signature) = signed(&core, &ed, &pq);
        assert_eq!(
            identity
                .verify(&raw, &ed_signature, &pq_signature, 1_500)
                .unwrap_err(),
            Error::UnsupportedClass
        );
    }
}
