//! Verification of NetworkPolicy candidates against a separately provisioned pin.
//! Runtime conversion currently permits only the existing default private prefix;
//! non-default prefixes remain unavailable. A static context is not a live
//! freshness proof: renewal, trusted time and revocation remain separate gates.
#![cfg(feature = "openssl-backend")]

use crate::root_authorization::{self, NetworkRootPin};
use boreas_proto::network_policy::NetworkPolicyCandidate;
use std::fmt;

/// Static tokens prove signature and stated-time validity only; they are not durable fresh permission.
#[derive(Clone, Debug)]
pub struct VerifiedNetworkPolicy {
    net_id: [u8; 16],
    root_key_fingerprint: [u8; 32],
    overlay_base: [u8; 4],
    version: u64,
    seq: u64,
    issued_at: u64,
    expires: u64,
    /// Digest of the exact signed TBS, present on every platform so downstream
    /// identities can bind to this verified policy without retaining raw bytes.
    policy_digest: [u8; 32],
    #[cfg(target_os = "linux")]
    object_hash: [u8; 32],
}
impl VerifiedNetworkPolicy {
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }
    pub fn root_key_fingerprint(&self) -> [u8; 32] {
        self.root_key_fingerprint
    }
    pub fn overlay_base(&self) -> [u8; 4] {
        self.overlay_base
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn validity(&self) -> (u64, u64) {
        (self.issued_at, self.expires)
    }

    /// Stable digest of the exact TBS candidate whose dual signatures were
    /// verified. This is a binding identifier, not standalone authorization.
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Convert verified policy to the only runtime context currently supported.
    /// Non-default signed prefixes remain verifiable/recordable but cannot reach
    /// identity or packet authorization.
    pub fn require_default_runtime(&self) -> Result<VerifiedNetworkContext, NetworkPolicyError> {
        if self.overlay_base != [10, 20, 0, 0] {
            return Err(NetworkPolicyError::UnsupportedRuntimePrefix);
        }
        Ok(VerifiedNetworkContext {
            net_id: self.net_id,
            root_key_fingerprint: self.root_key_fingerprint,
            overlay_base: self.overlay_base,
            policy_digest: self.policy_digest,
            version: self.version,
            seq: self.seq,
            issued_at: self.issued_at,
            expires: self.expires,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn matches_raw(&self, raw_tbs: &[u8]) -> bool {
        use openssl::hash::{MessageDigest, hash};
        hash(MessageDigest::sha256(), raw_tbs)
            .ok()
            .and_then(|digest| <[u8; 32]>::try_from(digest.as_ref()).ok())
            .is_some_and(|digest| digest == self.object_hash)
    }
}

/// Runtime-safe subset of a cryptographically verified policy. Private fields and
/// no public constructor make the binding originate only from verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNetworkContext {
    net_id: [u8; 16],
    root_key_fingerprint: [u8; 32],
    overlay_base: [u8; 4],
    policy_digest: [u8; 32],
    version: u64,
    seq: u64,
    issued_at: u64,
    expires: u64,
}
impl VerifiedNetworkContext {
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }
    pub fn root_key_fingerprint(&self) -> [u8; 32] {
        self.root_key_fingerprint
    }
    pub fn overlay_base(&self) -> [u8; 4] {
        self.overlay_base
    }
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn validity(&self) -> (u64, u64) {
        (self.issued_at, self.expires)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicyError {
    InvalidCandidate,
    WrongNetwork,
    WrongRootFingerprint,
    InvalidTime,
    InvalidRootOrSignature,
    UnsupportedRuntimePrefix,
}
impl fmt::Display for NetworkPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NetworkPolicyError {}

/// Verify the exact raw TBS candidate and both root signatures against an independent pin.
/// Validity is the half-open interval [issued_at, expires); callers supply their trusted now.
pub fn verify_network_policy(
    raw_tbs: &[u8],
    ed25519_signature: &[u8],
    mldsa65_signature: &[u8],
    pin: &NetworkRootPin,
    expected_net_id: [u8; 16],
    now: u64,
) -> Result<VerifiedNetworkPolicy, NetworkPolicyError> {
    if raw_tbs.is_empty()
        || raw_tbs.len() > boreas_proto::network_policy::MAX_TBS_LEN
        || ed25519_signature.len() != 64
        || mldsa65_signature.len() != 3309
    {
        return Err(NetworkPolicyError::InvalidCandidate);
    }
    let candidate = NetworkPolicyCandidate::decode_tbs(raw_tbs)
        .map_err(|_| NetworkPolicyError::InvalidCandidate)?;
    if candidate.net_id != expected_net_id || pin.net_id() != expected_net_id {
        return Err(NetworkPolicyError::WrongNetwork);
    }
    let fingerprint = pin
        .fingerprint()
        .map_err(|_| NetworkPolicyError::InvalidRootOrSignature)?;
    if candidate.root_key_fingerprint != fingerprint {
        return Err(NetworkPolicyError::WrongRootFingerprint);
    }
    if now < candidate.issued_at || now >= candidate.expires {
        return Err(NetworkPolicyError::InvalidTime);
    }
    root_authorization::verify_network_policy_message(
        raw_tbs,
        ed25519_signature,
        mldsa65_signature,
        pin,
        expected_net_id,
        fingerprint,
    )
    .map_err(|e| match e {
        root_authorization::Error::WrongNetwork => NetworkPolicyError::WrongNetwork,
        root_authorization::Error::InvalidCandidate | root_authorization::Error::TooLarge => {
            NetworkPolicyError::InvalidCandidate
        }
        _ => NetworkPolicyError::InvalidRootOrSignature,
    })?;
    let policy_digest: [u8; 32] =
        openssl::hash::hash(openssl::hash::MessageDigest::sha256(), raw_tbs)
            .map_err(|_| NetworkPolicyError::InvalidCandidate)?
            .as_ref()
            .try_into()
            .map_err(|_| NetworkPolicyError::InvalidCandidate)?;
    Ok(VerifiedNetworkPolicy {
        net_id: candidate.net_id,
        root_key_fingerprint: candidate.root_key_fingerprint,
        overlay_base: candidate.overlay_base,
        version: candidate.version,
        seq: candidate.seq,
        issued_at: candidate.issued_at,
        expires: candidate.expires,
        policy_digest,
        #[cfg(target_os = "linux")]
        object_hash: policy_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreas_proto::{network_policy::NetworkPolicyCandidate, objects::MldsaParameterSet};
    use openssl::{
        pkey::{KeyType, PKey, Private},
        sign::Signer,
    };

    fn keys(seed: u8) -> (PKey<Private>, PKey<Private>) {
        (
            PKey::generate_ed25519().unwrap(),
            PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
        )
    }
    fn make_pin(ed: &PKey<Private>, pq: &PKey<Private>) -> NetworkRootPin {
        NetworkRootPin::provisioned(
            [3; 16],
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().unwrap(),
        )
        .unwrap()
    }
    fn sign(ed: &PKey<Private>, pq: &PKey<Private>, raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let msg = NetworkPolicyCandidate::signature_input(raw).unwrap();
        let mut signer = Signer::new_without_digest(ed).unwrap();
        let es = signer.sign_oneshot_to_vec(&msg).unwrap();
        let mut signer = Signer::new_without_digest(pq).unwrap();
        (es, signer.sign_oneshot_to_vec(&msg).unwrap())
    }
    fn fixture() -> (NetworkRootPin, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (ed, pq) = keys(7);
        let pin = make_pin(&ed, &pq);
        let candidate = NetworkPolicyCandidate {
            net_id: [3; 16],
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 4,
            issued_at: 10,
            expires: 20,
        };
        let raw = candidate.encode_tbs().unwrap();
        let (es, ps) = sign(&ed, &pq, &raw);
        (pin, raw, es, ps)
    }
    #[test]
    fn rejects_mldsa87_pin_even_with_valid_mldsa87_signature() {
        let ed = PKey::generate_ed25519().unwrap();
        let pq87 = PKey::private_key_from_seed(None, KeyType::ML_DSA_87, None, &[9; 32]).unwrap();
        let pin = NetworkRootPin::provisioned(
            [3; 16],
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa87,
            pq87.public_key_to_der().unwrap(),
        )
        .unwrap();
        let candidate = NetworkPolicyCandidate {
            net_id: [3; 16],
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 10,
            expires: 20,
        };
        let raw = candidate.encode_tbs().unwrap();
        let msg = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let mut signer = Signer::new_without_digest(&ed).unwrap();
        let es = signer.sign_oneshot_to_vec(&msg).unwrap();
        let mut signer = Signer::new_without_digest(&pq87).unwrap();
        let ps = signer.sign_oneshot_to_vec(&msg).unwrap();
        assert!(verify_network_policy(&raw, &es, &ps, &pin, [3; 16], 10).is_err());
    }

    #[test]
    fn verifies_real_dual_signatures_and_fails_closed() {
        let (pin, raw, es, ps) = fixture();
        let ok = verify_network_policy(&raw, &es, &ps, &pin, [3; 16], 10).unwrap();
        assert_eq!(ok.seq(), 4);
        assert_eq!(ok.validity(), (10, 20));
        assert_eq!(ok.policy_digest(), openssl::sha::sha256(&raw).unwrap());
        let context = ok.require_default_runtime().unwrap();
        assert_eq!(context.net_id(), [3; 16]);
        assert_eq!(context.overlay_base(), [10, 20, 0, 0]);
        assert_eq!(context.policy_digest(), ok.policy_digest());
        assert_eq!(context.validity(), ok.validity());
        let mut bad = es.clone();
        bad[0] ^= 1;
        assert!(verify_network_policy(&raw, &bad, &ps, &pin, [3; 16], 10).is_err());
        let mut bad = ps.clone();
        bad[0] ^= 1;
        assert!(verify_network_policy(&raw, &es, &bad, &pin, [3; 16], 10).is_err());
        let (wrong_ed, wrong_pq) = keys(8);
        let wrong = make_pin(&wrong_ed, &wrong_pq);
        assert!(verify_network_policy(&raw, &es, &ps, &wrong, [3; 16], 10).is_err());
        assert!(verify_network_policy(&raw, &es, &ps, &pin, [4; 16], 10).is_err());
        assert!(verify_network_policy(&raw, &es, &ps, &pin, [3; 16], 9).is_err());
        assert!(verify_network_policy(&raw, &es, &ps, &pin, [3; 16], 20).is_err());
        let mut parsed = NetworkPolicyCandidate::decode_tbs(&raw).unwrap();
        parsed.seq = 5;
        let changed = parsed.encode_tbs().unwrap();
        assert_ne!(changed, raw);
        assert!(verify_network_policy(&changed, &es, &ps, &pin, [3; 16], 10).is_err());
    }

    #[test]
    fn signed_non_default_prefix_is_verifiable_but_not_runtime_supported() {
        let (ed, pq) = keys(11);
        let pin = make_pin(&ed, &pq);
        let candidate = NetworkPolicyCandidate {
            net_id: [3; 16],
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 21, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 10,
            expires: 20,
        };
        let raw = candidate.encode_tbs().unwrap();
        let (es, ps) = sign(&ed, &pq, &raw);
        let verified = verify_network_policy(&raw, &es, &ps, &pin, [3; 16], 10).unwrap();
        assert_eq!(
            verified.require_default_runtime().unwrap_err(),
            NetworkPolicyError::UnsupportedRuntimePrefix
        );
    }
}
