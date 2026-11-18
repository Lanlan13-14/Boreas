//! NetworkRoot-authorized, independently dual-signed DNS authority verification.
//!
//! # Separation of duties
//!
//! Two *different* key pairs are involved and neither is the identity authority:
//!
//! 1. The NetworkRoot key pair that already signs the `NetworkPolicy` candidate
//!    authorizes one DNS signer key pair through a [`boreas_proto::dns_authority::DnsSignerGrant`].
//!    The grant's purpose byte and key id are fixed by the candidate profile, so an
//!    identity, route, status or core-operational authorization cannot be replayed
//!    as a DNS issuer.
//! 2. That separate DNS signer then dual-signs a
//!    [`boreas_proto::dns_authority::DnsAuthority`] describing the zone, the
//!    permanent VIP claims and the authoritative records.
//!
//! The verifier proves that the root authorized the signer; it does not compare
//! the two public keys, so provisioning genuinely distinct root and DNS-signer
//! key pairs remains an operational requirement of this separation.
//!
//! Both token types have private fields and no public constructor: they exist only
//! after the corresponding dual signatures verified against the pinned keys, the
//! verified `NetworkPolicy` digest and the caller-supplied UTC clock. A missing
//! or failed check yields no token at all, so callers cannot fail open.
//!
//! # What these tokens do not prove
//!
//! * They are static: `issued_at` / `expires` are checked against a caller-supplied
//!   UTC `now`, but no durable anti-replay watermark, revocation feed or
//!   rollback protection is implemented here. A UTC rollback can revive an
//!   expired token; this is not a trusted-clock service. The durable stores are
//!   separate gates. A [`VerifiedDnsAuthority`] records the intersection of the
//!   authority, DNS signer grant and `NetworkPolicy` validity windows, so a token
//!   kept past any of the three stops being fresh.
//! * The profile is IPv4-only. `NetworkPolicy` carries one IPv4 overlay prefix and
//!   no ULA, so a signed IPv6 VIP or `AAAA` record cannot be bound to this
//!   network. Such an authority is refused here rather than advertised.
//! * Signer rotation is disabled in this slice. The authority TBS does not carry
//!   `signer_generation` or the signer grant digest, so accepting a later grant
//!   could otherwise re-authorize an authority body whose signer was replaced.
//!   [`DnsSignerPin::verify_grant`] therefore accepts only
//!   `signer_generation == 1`. Enabling rotation requires binding the grant
//!   digest into the authority signature domain/body and new fixed vectors; that
//!   is a separate profile change, not implemented here.
//! * They do not prove the pin's provenance; the pin must be provisioned
//!   independently, exactly as for `NetworkPolicy`.
//! * They do not enable the DNS service. Building the runtime, enforcement of the
//!   scope and `TCP DNS` enablement remain explicit caller decisions.

#![cfg(feature = "openssl-backend")]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use openssl::{
    hash::{MessageDigest, hash},
    pkey::{KeyType, PKey},
    sign::Verifier,
};

use boreas_proto::dns_authority::{DnsAuthority, DnsSignerGrant, MAX_TBS_LEN, TYPE_AAAA};

use crate::VerifiedNetworkContext;
use crate::root_authorization::NetworkRootPin;

/// Ed25519 signature length accepted for every dual-signed object here.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 signature length; ML-DSA-87 is not accepted by this profile.
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;
/// This slice accepts only the initial signer generation. Rotation is disabled
/// because the authority body does not bind the signer generation/grant digest.
const INITIAL_SIGNER_GENERATION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    InvalidCandidate,
    WrongNetwork,
    /// The object is not bound to the exact verified policy digest presented.
    PolicyMismatch,
    WrongRootKey,
    InvalidTime,
    InvalidSignatureLength,
    InvalidEdSignature,
    InvalidMlDsaSignature,
    /// The grant was authorized for another purpose than the DNS signer.
    WrongPurpose,
    /// The grant names a key id this profile does not accept as a DNS signer.
    WrongSignerKey,
    /// This slice does not bind the authority to a signer generation or grant
    /// digest, so only the initial `signer_generation == 1` is accepted and
    /// signer rotation is explicitly disabled.
    RotationUnsupported,
    /// The authority was not signed by the pinned DNS signer.
    SignerMismatch,
    /// A claimed VIP is not the canonical permanent slot of its node id inside
    /// the verified policy's overlay prefix.
    VipSlotMismatch,
    /// The profile's policy has an IPv4 overlay prefix only; an IPv6 VIP or AAAA
    /// record cannot be proven to belong to this network.
    UnsupportedIpv6,
    Backend,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Root-authorized DNS signer keys. Private fields and no public constructor: the
/// only source is [`DnsSignerPin::verify_grant`] with a pinned NetworkRoot. Only
/// the two public keys, the grant digest and the validity window are retained;
/// no private key, seed or signing capability is copied into this token.
#[derive(Clone, Debug)]
pub struct DnsSignerPin {
    net_id: [u8; 16],
    policy_digest: [u8; 32],
    generation: u64,
    not_before: u64,
    expires: u64,
    ed25519_public_key_der: Vec<u8>,
    mldsa_public_key_der: Vec<u8>,
    /// SHA-256 of the exact grant TBS whose two root signatures verified.
    grant_digest: [u8; 32],
}

impl DnsSignerPin {
    /// Verify a NetworkRoot dual signature over a DNS signer grant.
    ///
    /// The grant must name this network, the *exact* verified policy digest, the
    /// fixed DNS signer key id and the ML-DSA-65 parameter set, and `now` must be
    /// inside both the policy and the grant validity intervals. A token derived
    /// from this pin is fresh only while the policy, the grant and the authority
    /// are all fresh. Only `signer_generation == 1` is accepted: this slice does
    /// not bind the grant digest into the authority, so signer rotation is
    /// explicitly disabled rather than silently reusing an old authority.
    pub fn verify_grant(
        raw_tbs: &[u8],
        ed25519_signature: &[u8],
        mldsa_signature: &[u8],
        root: &NetworkRootPin,
        policy: &VerifiedNetworkContext,
        now: u64,
    ) -> Result<Self, Error> {
        let grant = decode_grant(raw_tbs)?;
        if ed25519_signature.len() != ED25519_SIGNATURE_LEN
            || mldsa_signature.len() != MLDSA65_SIGNATURE_LEN
        {
            return Err(Error::InvalidSignatureLength);
        }
        if root.net_id() != policy.net_id() || grant.net_id != policy.net_id() {
            return Err(Error::WrongNetwork);
        }
        // Binding to the exact signed policy TBS: a grant minted for another
        // policy version, network prefix or overlay base cannot be replayed.
        if grant.policy_digest != policy.policy_digest() {
            return Err(Error::PolicyMismatch);
        }
        if root.fingerprint().map_err(|_| Error::WrongRootKey)? != policy.root_key_fingerprint() {
            return Err(Error::WrongRootKey);
        }
        // The grant fixes ML-DSA-65; a pin for another set cannot verify it even
        // if its signature bytes happened to be the right length.
        if root.mldsa_parameter_set() != boreas_proto::objects::MldsaParameterSet::Mldsa65 {
            return Err(Error::WrongRootKey);
        }
        // No authority-body binding to signer_generation/grant_digest exists in
        // this profile. Refuse every generation but the initial one so a later
        // grant cannot re-authorize an old authority after a signer switch.
        if grant.signer_generation != INITIAL_SIGNER_GENERATION {
            return Err(Error::RotationUnsupported);
        }
        let (policy_not_before, policy_expires) = policy.validity();
        if now < policy_not_before || now >= policy_expires {
            return Err(Error::InvalidTime);
        }
        if now < grant.not_before || now >= grant.expires {
            return Err(Error::InvalidTime);
        }
        let ed_root = PKey::public_key_from_der(root.ed25519_public_key_der())
            .map_err(|_| Error::WrongRootKey)?;
        let pq_root = PKey::public_key_from_der(root.mldsa_public_key_der())
            .map_err(|_| Error::WrongRootKey)?;
        verify_both(
            &ed_root,
            &pq_root,
            &DnsSignerGrant::signature_input(raw_tbs).map_err(|_| Error::InvalidCandidate)?,
            ed25519_signature,
            mldsa_signature,
        )?;
        Ok(Self {
            net_id: grant.net_id,
            policy_digest: grant.policy_digest,
            generation: grant.signer_generation,
            not_before: grant.not_before,
            expires: grant.expires,
            ed25519_public_key_der: grant.ed25519_public_key_der,
            mldsa_public_key_der: grant.mldsa_public_key_der,
            grant_digest: sha256(raw_tbs)?,
        })
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn validity(&self) -> (u64, u64) {
        (self.not_before, self.expires)
    }

    /// Digest of the verified grant TBS, for correlation and audit only.
    pub fn grant_digest(&self) -> [u8; 32] {
        self.grant_digest
    }
}

/// One verified permanent VIP claim. `ipv6` is always `None` in this profile:
/// the signed policy has no ULA, so no IPv6 address can be network-authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedVipClaim {
    pub node_id: u16,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

/// One verified authoritative record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecord {
    pub owner: String,
    pub record_type: u16,
    pub address: Vec<u8>,
}

/// DnsSigner-authorized zone/VIP/record authority.
///
/// Private fields and no public constructor: only
/// [`VerifiedDnsAuthority::verify`] produces one, and only from a pinned
/// [`DnsSignerPin`] bound to the same verified policy digest. It holds public
/// authorization data only; no private key or signing capability.
#[derive(Clone, Debug)]
pub struct VerifiedDnsAuthority {
    net_id: [u8; 16],
    policy_digest: [u8; 32],
    sequence: u64,
    issued_at: u64,
    expires: u64,
    zone: String,
    vips: Vec<VerifiedVipClaim>,
    records: Vec<VerifiedRecord>,
    signer_grant_digest: [u8; 32],
    signer_generation: u64,
    signer_not_before: u64,
    signer_expires: u64,
    policy_not_before: u64,
    policy_expires: u64,
}

impl VerifiedDnsAuthority {
    /// Verify the DnsSigner dual signature over one authority object.
    ///
    /// The authority, the signer grant and the verified policy must agree on the
    /// network and on the exact policy digest, and `now` must be inside all three
    /// validity intervals. An IPv6 VIP claim or `AAAA` record is refused because
    /// the policy carries no ULA against which it could be verified.
    pub fn verify(
        raw_tbs: &[u8],
        ed25519_signature: &[u8],
        mldsa_signature: &[u8],
        signer: &DnsSignerPin,
        policy: &VerifiedNetworkContext,
        now: u64,
    ) -> Result<Self, Error> {
        let authority = decode_authority(raw_tbs)?;
        if ed25519_signature.len() != ED25519_SIGNATURE_LEN
            || mldsa_signature.len() != MLDSA65_SIGNATURE_LEN
        {
            return Err(Error::InvalidSignatureLength);
        }
        if signer.net_id != policy.net_id()
            || signer.policy_digest != policy.policy_digest()
            || authority.net_id != policy.net_id()
        {
            return Err(Error::SignerMismatch);
        }
        if authority.policy_digest != policy.policy_digest() {
            return Err(Error::PolicyMismatch);
        }
        let (policy_not_before, policy_expires) = policy.validity();
        let (signer_not_before, signer_expires) = signer.validity();
        if now < policy_not_before
            || now >= policy_expires
            || now < signer_not_before
            || now >= signer_expires
            || now < authority.issued_at
            || now >= authority.expires
        {
            return Err(Error::InvalidTime);
        }
        let ed_signer = PKey::public_key_from_der(&signer.ed25519_public_key_der)
            .map_err(|_| Error::WrongSignerKey)?;
        let pq_signer = PKey::public_key_from_der(&signer.mldsa_public_key_der)
            .map_err(|_| Error::WrongSignerKey)?;
        verify_both(
            &ed_signer,
            &pq_signer,
            &DnsAuthority::signature_input(raw_tbs).map_err(|_| Error::InvalidCandidate)?,
            ed25519_signature,
            mldsa_signature,
        )?;
        let zone = String::from_utf8(authority.zone).map_err(|_| Error::InvalidCandidate)?;
        let base = policy.overlay_base();
        let mut vips = Vec::with_capacity(authority.vips.len());
        for claim in authority.vips {
            // The DNS object is signed, but a signer must not be able to claim
            // an address the policy never reserved for that node. The permanent
            // slot rule is re-derived here from the *verified* prefix; the
            // object's own bytes are never used to pick the prefix.
            //
            // The profile's policy holds one IPv4 prefix and no ULA, so there is
            // no signed value an IPv6 claim could be checked against. Refuse it
            // instead of treating "fd00::/8" as network authorization.
            if claim.ipv6 != [0; 16] {
                return Err(Error::UnsupportedIpv6);
            }
            let home_core = u8::try_from(claim.node_id >> 8)
                .ok()
                .and_then(|high| high.checked_add(1))
                .filter(|home| *home <= 16)
                .ok_or(Error::VipSlotMismatch)?;
            let vip_octet =
                u8::try_from(claim.node_id & 0xff).map_err(|_| Error::VipSlotMismatch)?;
            let slot_valid = vip_octet == 1 || (2..=251).contains(&vip_octet);
            if !slot_valid || claim.ipv4 != [base[0], base[1], home_core, vip_octet] {
                return Err(Error::VipSlotMismatch);
            }
            vips.push(VerifiedVipClaim {
                node_id: claim.node_id,
                ipv4: Ipv4Addr::from(claim.ipv4),
                ipv6: None,
            });
        }
        let mut records = Vec::with_capacity(authority.records.len());
        for record in authority.records {
            // Defence in depth: an AAAA record always implies a nonzero IPv6
            // claim, which was already refused above.
            if record.record_type == TYPE_AAAA {
                return Err(Error::UnsupportedIpv6);
            }
            records.push(VerifiedRecord {
                owner: String::from_utf8(record.owner).map_err(|_| Error::InvalidCandidate)?,
                record_type: record.record_type,
                address: record.address,
            });
        }
        Ok(Self {
            net_id: authority.net_id,
            policy_digest: authority.policy_digest,
            sequence: authority.sequence,
            issued_at: authority.issued_at,
            expires: authority.expires,
            zone,
            vips,
            records,
            signer_grant_digest: signer.grant_digest,
            signer_generation: signer.generation,
            signer_not_before,
            signer_expires,
            policy_not_before,
            policy_expires,
        })
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    /// The exact `NetworkPolicy` TBS digest this authority is bound to.
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Raw validity of the authority object alone. Enforcement must use
    /// [`Self::freshness`] or [`Self::is_fresh_at`], which also bound the signer
    /// grant and the policy.
    pub fn validity(&self) -> (u64, u64) {
        (self.issued_at, self.expires)
    }

    /// Zone origin, lowercase ASCII without a trailing dot.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn vips(&self) -> &[VerifiedVipClaim] {
        &self.vips
    }

    pub fn records(&self) -> &[VerifiedRecord] {
        &self.records
    }

    /// Digest of the verified signer grant; audit correlation only.
    pub fn signer_grant_digest(&self) -> [u8; 32] {
        self.signer_grant_digest
    }

    pub fn signer_generation(&self) -> u64 {
        self.signer_generation
    }

    /// Validity of the root-authorized signer grant this authority was verified
    /// under. The grant can expire before the authority object itself.
    pub fn signer_validity(&self) -> (u64, u64) {
        (self.signer_not_before, self.signer_expires)
    }

    /// Validity of the exact `NetworkPolicy` this authority is bound to.
    pub fn policy_validity(&self) -> (u64, u64) {
        (self.policy_not_before, self.policy_expires)
    }

    /// Intersection of the authority, signer grant and policy validity windows.
    /// Every operation must use this window, not `validity()` alone.
    pub fn freshness(&self) -> (u64, u64) {
        (
            self.issued_at
                .max(self.signer_not_before)
                .max(self.policy_not_before),
            self.expires
                .min(self.signer_expires)
                .min(self.policy_expires),
        )
    }

    /// Fail-closed freshness check for callers that keep this token past `now`.
    /// The token is fresh only while the authority, the DNS signer grant and the
    /// verified policy are all inside their half-open validity intervals. This is
    /// not durable replay protection and does not prevent a UTC rollback from
    /// reviving an expired token; there is no trusted-clock service here.
    pub fn is_fresh_at(&self, now: u64) -> bool {
        let (from, until) = self.freshness();
        now >= from && now < until
    }
}

fn decode_grant(raw_tbs: &[u8]) -> Result<DnsSignerGrant, Error> {
    if raw_tbs.is_empty() || raw_tbs.len() > MAX_TBS_LEN {
        return Err(Error::InvalidCandidate);
    }
    let grant = DnsSignerGrant::decode_tbs(raw_tbs).map_err(|_| Error::InvalidCandidate)?;
    // `decode_tbs` already pinned the purpose byte and key id; re-stating them
    // here keeps the separation visible at the trust boundary that matters.
    if grant.mldsa_parameter_set != boreas_proto::dns_authority::MLDSA_PARAMETER_SET_65 {
        return Err(Error::WrongSignerKey);
    }
    Ok(grant)
}

fn decode_authority(raw_tbs: &[u8]) -> Result<DnsAuthority, Error> {
    if raw_tbs.is_empty() || raw_tbs.len() > MAX_TBS_LEN {
        return Err(Error::InvalidCandidate);
    }
    DnsAuthority::decode_tbs(raw_tbs).map_err(|_| Error::InvalidCandidate)
}

fn verify_both(
    ed_key: &PKey<openssl::pkey::Public>,
    pq_key: &PKey<openssl::pkey::Public>,
    message: &[u8],
    ed25519_signature: &[u8],
    mldsa_signature: &[u8],
) -> Result<(), Error> {
    if !ed_key.is_a(KeyType::ED25519) || !pq_key.is_a(KeyType::ML_DSA_65) {
        return Err(Error::WrongSignerKey);
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
    use crate::verify_network_policy;
    use boreas_proto::{
        dns_authority::{
            DNS_SIGNER_KEY_ID, DnsAuthority, DnsRecordEntry, DnsSignerGrant, DnsVipClaim,
            MLDSA_PARAMETER_SET_65, TYPE_A, TYPE_AAAA,
        },
        network_policy::NetworkPolicyCandidate,
        objects::MldsaParameterSet,
    };
    use openssl::{
        pkey::{KeyType, PKey, Private},
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
        (
            ed_signature,
            signer.sign_oneshot_to_vec(message).unwrap(),
        )
    }

    struct Fixture {
        root: NetworkRootPin,
        policy: VerifiedNetworkContext,
        grant_raw: Vec<u8>,
        grant_ed: Vec<u8>,
        grant_pq: Vec<u8>,
        signer: DnsSignerPin,
        authority_raw: Vec<u8>,
        authority_ed: Vec<u8>,
        authority_pq: Vec<u8>,
        signer_ed: PKey<Private>,
        signer_pq: PKey<Private>,
        root_ed: PKey<Private>,
        root_pq: PKey<Private>,
    }

    fn fixture() -> Fixture {
        fixture_with(2_000, 2_000, 2_000)
    }

    /// Same real trust chain with caller-chosen policy, signer-grant and
    /// authority expiries, so freshness intersection can be tested without
    /// bypassing any signature or policy check.
    fn fixture_with(
        policy_expires: u64,
        grant_expires: u64,
        authority_expires: u64,
    ) -> Fixture {
        let (root_ed, root_pq) = keys(11);
        // The root pin is the independently provisioned anchor. The policy,
        // the signer grant and the authority are each verified from real bytes.
        let root = NetworkRootPin::provisioned(
            NET,
            root_ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        let candidate = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: root.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 1_000,
            expires: policy_expires,
        };
        let raw = candidate.encode_tbs().unwrap();
        let message = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&root_ed, &root_pq, &message);
        let policy = verify_network_policy(&raw, &ed, &pq, &root, NET, 1_500)
            .unwrap()
            .require_default_runtime()
            .unwrap();

        let (signer_ed, signer_pq) = keys(12);
        let grant = DnsSignerGrant {
            net_id: NET,
            policy_digest: policy.policy_digest(),
            signer_generation: 1,
            sequence: 1,
            not_before: 1_000,
            expires: grant_expires,
            ed25519_public_key_der: signer_ed.public_key_to_der().unwrap(),
            mldsa_parameter_set: MLDSA_PARAMETER_SET_65,
            mldsa_public_key_der: signer_pq.public_key_to_der().unwrap(),
        };
        let grant_raw = grant.encode_tbs().unwrap();
        let message = DnsSignerGrant::signature_input(&grant_raw).unwrap();
        let (grant_ed, grant_pq) = sign(&root_ed, &root_pq, &message);
        let signer =
            DnsSignerPin::verify_grant(&grant_raw, &grant_ed, &grant_pq, &root, &policy, 1_500)
                .unwrap();

        let authority = DnsAuthority {
            net_id: NET,
            policy_digest: policy.policy_digest(),
            sequence: 1,
            issued_at: 1_000,
            expires: authority_expires,
            zone: b"b.example".to_vec(),
            vips: vec![DnsVipClaim {
                node_id: 0x0001,
                ipv4: [10, 20, 1, 1],
                ipv6: [0; 16],
            }],
            records: vec![DnsRecordEntry {
                owner: b"host.b.example".to_vec(),
                record_type: TYPE_A,
                address: vec![10, 20, 1, 1],
            }],
        };
        let authority_raw = authority.encode_tbs().unwrap();
        let message = DnsAuthority::signature_input(&authority_raw).unwrap();
        let (authority_ed, authority_pq) = sign(&signer_ed, &signer_pq, &message);
        Fixture {
            root,
            policy,
            grant_raw,
            grant_ed,
            grant_pq,
            signer,
            authority_raw,
            authority_ed,
            authority_pq,
            signer_ed,
            signer_pq,
            root_ed,
            root_pq,
        }
    }

    #[test]
    fn real_dual_signatures_verify_for_grant_and_authority() {
        let f = fixture();
        let signer = DnsSignerPin::verify_grant(
            &f.grant_raw,
            &f.grant_ed,
            &f.grant_pq,
            &f.root,
            &f.policy,
            1_500,
        )
        .unwrap();
        let authority = VerifiedDnsAuthority::verify(
            &f.authority_raw,
            &f.authority_ed,
            &f.authority_pq,
            &signer,
            &f.policy,
            1_500,
        )
        .unwrap();
        assert_eq!(authority.net_id(), NET);
        assert_eq!(authority.policy_digest(), f.policy.policy_digest());
        assert_eq!(authority.zone(), "b.example");
        assert_eq!(authority.sequence(), 1);
        assert_eq!(authority.validity(), (1_000, 2_000));
        assert_eq!(authority.vips().len(), 1);
        assert_eq!(authority.vips()[0].node_id, 1);
        assert_eq!(authority.vips()[0].ipv4, Ipv4Addr::new(10, 20, 1, 1));
        assert_eq!(authority.records()[0].owner, "host.b.example");
        assert_eq!(authority.signer_generation(), 1);
        assert_eq!(authority.signer_grant_digest(), signer.grant_digest());
        assert_eq!(authority.signer_validity(), (1_000, 2_000));
        assert_eq!(authority.policy_validity(), (1_000, 2_000));
        assert_eq!(authority.freshness(), (1_000, 2_000));
        assert_eq!(authority.vips()[0].ipv6, None);
        assert!(authority.is_fresh_at(1_500));
        assert!(!authority.is_fresh_at(2_000));
    }

    #[test]
    fn freshness_intersects_authority_signer_grant_and_policy() {
        // The authority object outlives its signer grant by 100 seconds. A token
        // must still expire with the grant, not with authority.expires.
        let f = fixture_with(2_000, 1_800, 1_900);
        let authority = VerifiedDnsAuthority::verify(
            &f.authority_raw,
            &f.authority_ed,
            &f.authority_pq,
            &f.signer,
            &f.policy,
            1_500,
        )
        .unwrap();
        assert_eq!(authority.validity(), (1_000, 1_900));
        assert_eq!(authority.signer_validity(), (1_000, 1_800));
        assert_eq!(authority.policy_validity(), (1_000, 2_000));
        assert_eq!(authority.freshness(), (1_000, 1_800));
        assert!(authority.is_fresh_at(1_799));
        assert!(!authority.is_fresh_at(1_800));
        assert!(!authority.is_fresh_at(1_850));
        // Verification at 1_850 also fails closed: the grant has expired even
        // though the authority object has not.
        assert_eq!(
            VerifiedDnsAuthority::verify(
                &f.authority_raw,
                &f.authority_ed,
                &f.authority_pq,
                &f.signer,
                &f.policy,
                1_850,
            )
            .unwrap_err(),
            Error::InvalidTime
        );

        // A policy that ends before the authority and grant also bounds the
        // token; the token cannot outlive the policy it is bound to.
        let p = fixture_with(1_700, 2_000, 1_900);
        let policy_bound = VerifiedDnsAuthority::verify(
            &p.authority_raw,
            &p.authority_ed,
            &p.authority_pq,
            &p.signer,
            &p.policy,
            1_500,
        )
        .unwrap();
        assert_eq!(policy_bound.validity(), (1_000, 1_900));
        assert_eq!(policy_bound.policy_validity(), (1_000, 1_700));
        assert_eq!(policy_bound.freshness(), (1_000, 1_700));
        assert!(policy_bound.is_fresh_at(1_699));
        assert!(!policy_bound.is_fresh_at(1_700));
    }

    #[test]
    fn ipv6_claims_and_aaaa_records_are_refused_without_a_policy_ula() {
        let f = fixture();
        let v6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // A well-formed fd00::/8 claim is still not network-authorized: the
        // verified policy has no ULA value to compare it with.
        let mut claim_only = DnsAuthority::decode_tbs(&f.authority_raw).unwrap();
        claim_only.vips[0].ipv6 = v6;
        assert_eq!(
            verify_resigned_authority(&f, &claim_only).unwrap_err(),
            Error::UnsupportedIpv6
        );

        // An AAAA record always implies such a claim; both are refused.
        let mut aaaa = DnsAuthority::decode_tbs(&f.authority_raw).unwrap();
        aaaa.vips[0].ipv6 = v6;
        aaaa.records[0].record_type = TYPE_AAAA;
        aaaa.records[0].address = v6.to_vec();
        assert_eq!(
            verify_resigned_authority(&f, &aaaa).unwrap_err(),
            Error::UnsupportedIpv6
        );
    }

    #[test]
    fn both_signatures_are_independent_for_both_objects() {
        let f = fixture();
        let mut ed = f.grant_ed.clone();
        ed[0] ^= 1;
        assert_eq!(
            DnsSignerPin::verify_grant(&f.grant_raw, &ed, &f.grant_pq, &f.root, &f.policy, 1_500)
                .unwrap_err(),
            Error::InvalidEdSignature
        );
        let mut pq = f.grant_pq.clone();
        pq[0] ^= 1;
        assert_eq!(
            DnsSignerPin::verify_grant(
                &f.grant_raw,
                &f.grant_ed,
                &pq,
                &f.root,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidMlDsaSignature
        );
        let mut ed = f.authority_ed.clone();
        ed[0] ^= 1;
        assert_eq!(
            VerifiedDnsAuthority::verify(
                &f.authority_raw,
                &ed,
                &f.authority_pq,
                &f.signer,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidEdSignature
        );
        let mut pq = f.authority_pq.clone();
        pq[0] ^= 1;
        assert_eq!(
            VerifiedDnsAuthority::verify(
                &f.authority_raw,
                &f.authority_ed,
                &pq,
                &f.signer,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidMlDsaSignature
        );
    }

    #[test]
    fn signature_lengths_and_time_windows_are_fixed() {
        let f = fixture();
        assert_eq!(
            DnsSignerPin::verify_grant(
                &f.grant_raw,
                &f.grant_ed[..ED25519_SIGNATURE_LEN - 1],
                &f.grant_pq,
                &f.root,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidSignatureLength
        );
        assert_eq!(
            DnsSignerPin::verify_grant(
                &f.grant_raw,
                &f.grant_ed,
                &f.grant_pq[..MLDSA65_SIGNATURE_LEN - 1],
                &f.root,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidSignatureLength
        );
        for now in [999, 2_000] {
            assert_eq!(
                DnsSignerPin::verify_grant(
                    &f.grant_raw,
                    &f.grant_ed,
                    &f.grant_pq,
                    &f.root,
                    &f.policy,
                    now
                )
                .unwrap_err(),
                Error::InvalidTime
            );
            assert_eq!(
                VerifiedDnsAuthority::verify(
                    &f.authority_raw,
                    &f.authority_ed,
                    &f.authority_pq,
                    &f.signer,
                    &f.policy,
                    now
                )
                .unwrap_err(),
                Error::InvalidTime
            );
        }
    }

    #[test]
    fn grant_is_bound_to_network_policy_and_root_pin() {
        let f = fixture();
        let mut wrong_net = DnsSignerGrant::decode_tbs(&f.grant_raw).unwrap();
        wrong_net.net_id = [8; 16];
        assert_eq!(
            verify_resigned_grant(&f, &wrong_net).unwrap_err(),
            Error::WrongNetwork
        );

        let mut wrong_policy = DnsSignerGrant::decode_tbs(&f.grant_raw).unwrap();
        wrong_policy.policy_digest = [9; 32];
        assert_eq!(
            verify_resigned_grant(&f, &wrong_policy).unwrap_err(),
            Error::PolicyMismatch
        );

        let (other_ed, other_pq) = keys(21);
        let other = NetworkRootPin::provisioned(
            NET,
            other_ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            other_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(
            DnsSignerPin::verify_grant(
                &f.grant_raw,
                &f.grant_ed,
                &f.grant_pq,
                &other,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::WrongRootKey
        );
    }

    #[test]
    fn signer_rotation_is_explicitly_disabled() {
        let f = fixture();
        let mut rotated = DnsSignerGrant::decode_tbs(&f.grant_raw).unwrap();
        rotated.signer_generation = 2;
        assert_eq!(
            verify_resigned_grant(&f, &rotated).unwrap_err(),
            Error::RotationUnsupported
        );
    }

    /// Re-sign a modified grant with the fixture root keys. Used to prove that a
    /// *correctly signed* object is still refused when a binding is wrong.
    fn verify_resigned_grant(f: &Fixture, grant: &DnsSignerGrant) -> Result<DnsSignerPin, Error> {
        let raw = grant.encode_tbs().unwrap();
        let message = DnsSignerGrant::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&f.root_ed, &f.root_pq, &message);
        DnsSignerPin::verify_grant(&raw, &ed, &pq, &f.root, &f.policy, 1_500)
    }

    fn verify_resigned_authority(
        f: &Fixture,
        authority: &DnsAuthority,
    ) -> Result<VerifiedDnsAuthority, Error> {
        let raw = authority.encode_tbs().unwrap();
        let message = DnsAuthority::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&f.signer_ed, &f.signer_pq, &message);
        VerifiedDnsAuthority::verify(&raw, &ed, &pq, &f.signer, &f.policy, 1_500)
    }

    #[test]
    fn authority_is_bound_to_signer_policy_and_exact_slot() {
        let f = fixture();
        // A correctly formed authority signed by a key the grant did not
        // authorize must not verify.
        let message = DnsAuthority::signature_input(&f.authority_raw).unwrap();
        let (other_ed, other_pq) = keys(31);
        let (ed, pq) = sign(&other_ed, &other_pq, &message);
        assert_eq!(
            VerifiedDnsAuthority::verify(
                &f.authority_raw,
                &ed,
                &pq,
                &f.signer,
                &f.policy,
                1_500
            )
            .unwrap_err(),
            Error::InvalidEdSignature
        );

        let mut other_policy = DnsAuthority::decode_tbs(&f.authority_raw).unwrap();
        other_policy.policy_digest = [9; 32];
        assert_eq!(
            verify_resigned_authority(&f, &other_policy).unwrap_err(),
            Error::PolicyMismatch
        );

        let mut outside_prefix = DnsAuthority::decode_tbs(&f.authority_raw).unwrap();
        outside_prefix.vips[0].ipv4 = [10, 21, 1, 1];
        outside_prefix.records[0].address = vec![10, 21, 1, 1];
        assert_eq!(
            verify_resigned_authority(&f, &outside_prefix).unwrap_err(),
            Error::VipSlotMismatch
        );

        let mut wrong_slot = DnsAuthority::decode_tbs(&f.authority_raw).unwrap();
        wrong_slot.vips[0].node_id = 0x0002;
        assert_eq!(
            verify_resigned_authority(&f, &wrong_slot).unwrap_err(),
            Error::VipSlotMismatch
        );
    }

    #[test]
    fn tampered_key_id_is_refused_even_with_a_valid_signature() {
        let f = fixture();
        let mut raw = f.authority_raw.clone();
        // Locate the fixed 16-byte signer key id itself, not a 2-byte prefix
        // that could also occur inside random digest bytes.
        let at = raw
            .windows(DNS_SIGNER_KEY_ID.len())
            .position(|w| w == DNS_SIGNER_KEY_ID)
            .expect("authority signer key id");
        raw[at] = b'x';
        let message = DnsAuthority::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&f.signer_ed, &f.signer_pq, &message);
        assert_eq!(
            VerifiedDnsAuthority::verify(&raw, &ed, &pq, &f.signer, &f.policy, 1_500)
                .unwrap_err(),
            Error::InvalidCandidate
        );
    }
}
