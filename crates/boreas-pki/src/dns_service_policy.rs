//! Static DNS service policy verification, not live DNS authorization.

use std::fmt;

use boreas_proto::{
    dns_service_policy::{Capability, DnsServicePolicy, DnsSubject},
    objects::MldsaParameterSet,
};
use openssl::pkey::PKey;

use crate::{
    NetworkRootPin, VerifiedNetworkPolicy,
    dns_authority::{self, ED25519_SIGNATURE_LEN, MLDSA65_SIGNATURE_LEN, verify_both},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCandidate,
    WrongNetwork,
    PolicyMismatch,
    WrongRootKey,
    InvalidTime,
    InvalidSignatureLength,
    InvalidEdSignature,
    InvalidMlDsaSignature,
    Backend,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Opaque proof of canonical bytes, exact NetworkPolicy binding and both root
/// signatures. This snapshot does not select the current policy or authenticate a peer.
#[derive(Clone, Debug)]
pub struct VerifiedDnsServicePolicy {
    body: DnsServicePolicy,
}

impl VerifiedDnsServicePolicy {
    /// The signed interval must lie wholly inside the verified NetworkPolicy's
    /// interval. `now` is caller-supplied UTC Unix microseconds; end is exclusive.
    pub fn verify(
        raw_tbs: &[u8],
        ed25519_signature: &[u8],
        mldsa_signature: &[u8],
        root: &NetworkRootPin,
        policy: &VerifiedNetworkPolicy,
        now: u64,
    ) -> Result<Self, Error> {
        if ed25519_signature.len() != ED25519_SIGNATURE_LEN
            || mldsa_signature.len() != MLDSA65_SIGNATURE_LEN
        {
            return Err(Error::InvalidSignatureLength);
        }
        let body = DnsServicePolicy::decode_tbs(raw_tbs).map_err(|_| Error::InvalidCandidate)?;
        if body.net_id != policy.net_id() || root.net_id() != policy.net_id() {
            return Err(Error::WrongNetwork);
        }
        if body.policy_digest != policy.policy_digest() {
            return Err(Error::PolicyMismatch);
        }
        if root.mldsa_parameter_set() != MldsaParameterSet::Mldsa65
            || root.fingerprint().map_err(|_| Error::Backend)? != policy.root_key_fingerprint()
        {
            return Err(Error::WrongRootKey);
        }
        let (from, until) = policy.validity();
        if body.issued_at < from
            || body.expires > until
            || now < body.issued_at
            || now >= body.expires
        {
            return Err(Error::InvalidTime);
        }
        let message =
            DnsServicePolicy::signature_input(raw_tbs).map_err(|_| Error::InvalidCandidate)?;
        let ed_root = PKey::public_key_from_der(root.ed25519_public_key_der())
            .map_err(|_| Error::WrongRootKey)?;
        let pq_root = PKey::public_key_from_der(root.mldsa_public_key_der())
            .map_err(|_| Error::WrongRootKey)?;
        verify_both(
            &ed_root,
            &pq_root,
            &message,
            ed25519_signature,
            mldsa_signature,
        )
        .map_err(|error| match error {
            dns_authority::Error::InvalidEdSignature => Error::InvalidEdSignature,
            dns_authority::Error::InvalidMlDsaSignature => Error::InvalidMlDsaSignature,
            dns_authority::Error::WrongSignerKey => Error::WrongRootKey,
            _ => Error::Backend,
        })?;
        Ok(Self { body })
    }

    /// Signed metadata only; this API does not maintain a sequence watermark.
    pub fn sequence(&self) -> u64 {
        self.body.sequence
    }

    /// Checks only the explicit grant for the supplied authenticated subject facts.
    /// Caller must supply its currently selected verified NetworkPolicy and obtain
    /// subject facts from authenticated identity, not from an advertisement or
    /// request. A match says nothing about revocation, role, endpoint or name.
    pub fn has_grant_at(
        &self,
        policy: &VerifiedNetworkPolicy,
        subject_net_id: [u8; 16],
        subject: DnsSubject,
        capability: Capability,
        now: u64,
    ) -> bool {
        if now < self.body.issued_at
            || now >= self.body.expires
            || subject_net_id != self.body.net_id
            || policy.net_id() != self.body.net_id
            || policy.policy_digest() != self.body.policy_digest
        {
            return false;
        }
        self.body
            .grants
            .binary_search_by_key(&subject.node_id, |grant| grant.subject.node_id)
            .ok()
            .is_some_and(|index| {
                let grant = &self.body.grants[index];
                grant.subject == subject && grant.capabilities.contains(capability)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreas_proto::{
        dns_service_policy::{Capabilities, DnsServiceGrant},
        network_policy::NetworkPolicyCandidate,
    };
    use openssl::{
        pkey::{KeyType, Private},
        sign::Signer,
    };

    const NET: [u8; 16] = [7; 16];
    const CORE: DnsSubject = DnsSubject {
        node_id: 1,
        identity_generation: 9,
    };
    const EDGE: DnsSubject = DnsSubject {
        node_id: 2,
        identity_generation: 5,
    };

    struct Fixture {
        ed: PKey<Private>,
        pq: PKey<Private>,
        pin: NetworkRootPin,
        network: VerifiedNetworkPolicy,
        body: DnsServicePolicy,
    }

    impl Fixture {
        fn new() -> Self {
            let ed = PKey::generate_ed25519().unwrap();
            let pq =
                PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[42; 32]).unwrap();
            let pin = NetworkRootPin::provisioned(
                NET,
                ed.public_key_to_der().unwrap(),
                MldsaParameterSet::Mldsa65,
                pq.public_key_to_der().unwrap(),
            )
            .unwrap();
            let network = network(&ed, &pq, &pin, 1);
            let body = DnsServicePolicy {
                net_id: NET,
                policy_digest: network.policy_digest(),
                sequence: 2,
                issued_at: 20,
                expires: 80,
                grants: vec![
                    DnsServiceGrant {
                        subject: CORE,
                        capabilities: Capabilities::default().with(Capability::Advertise),
                    },
                    DnsServiceGrant {
                        subject: EDGE,
                        capabilities: Capabilities::default().with(Capability::Register),
                    },
                ],
            };
            Self {
                ed,
                pq,
                pin,
                network,
                body,
            }
        }

        fn sign(&self, body: &DnsServicePolicy) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let raw = body.encode_tbs().unwrap();
            let message = DnsServicePolicy::signature_input(&raw).unwrap();
            let (ed, pq) = sign(&self.ed, &self.pq, &message);
            (raw, ed, pq)
        }
    }

    fn sign(ed: &PKey<Private>, pq: &PKey<Private>, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let one = |key: &PKey<Private>| {
            Signer::new_without_digest(key)
                .unwrap()
                .sign_oneshot_to_vec(message)
                .unwrap()
        };
        (one(ed), one(pq))
    }

    fn network(
        ed: &PKey<Private>,
        pq: &PKey<Private>,
        pin: &NetworkRootPin,
        seq: u64,
    ) -> VerifiedNetworkPolicy {
        let raw = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq,
            issued_at: 10,
            expires: 100,
        }
        .encode_tbs()
        .unwrap();
        let (ed, pq) = sign(
            ed,
            pq,
            &NetworkPolicyCandidate::signature_input(&raw).unwrap(),
        );
        crate::verify_network_policy(&raw, &ed, &pq, pin, NET, 50).unwrap()
    }

    #[test]
    fn matches_exact_live_network_binding_and_separate_grants() {
        let f = Fixture::new();
        let (raw, ed, pq) = f.sign(&f.body);
        let token =
            VerifiedDnsServicePolicy::verify(&raw, &ed, &pq, &f.pin, &f.network, 20).unwrap();
        assert_eq!(token.sequence(), 2);
        let matches = |subject, capability, now| {
            token.has_grant_at(&f.network, NET, subject, capability, now)
        };
        assert!(matches(CORE, Capability::Advertise, 20));
        assert!(matches(EDGE, Capability::Register, 79));
        for capability in [
            Capability::PublicForward,
            Capability::Replica,
            Capability::Register,
        ] {
            assert!(!matches(CORE, capability, 50));
        }
        assert!(!matches(EDGE, Capability::Advertise, 50));
        assert!(!matches(
            DnsSubject {
                identity_generation: 10,
                ..CORE
            },
            Capability::Advertise,
            50
        ));
        assert!(!matches(
            DnsSubject {
                node_id: 0x0101,
                ..CORE
            },
            Capability::Advertise,
            50
        ));
        assert!(!token.has_grant_at(&f.network, [8; 16], CORE, Capability::Advertise, 50));
        let replacement = network(&f.ed, &f.pq, &f.pin, 2);
        assert!(!token.has_grant_at(&replacement, NET, CORE, Capability::Advertise, 50));
        assert_eq!(
            VerifiedDnsServicePolicy::verify(&raw, &ed, &pq, &f.pin, &replacement, 50).unwrap_err(),
            Error::PolicyMismatch
        );
        for now in [19, 80, 100] {
            assert!(!matches(CORE, Capability::Advertise, now));
            assert_eq!(
                VerifiedDnsServicePolicy::verify(&raw, &ed, &pq, &f.pin, &f.network, now)
                    .unwrap_err(),
                Error::InvalidTime
            );
        }
    }

    #[test]
    fn refuses_root_signed_object_outside_its_network_or_parent_window() {
        let f = Fixture::new();
        for (body, expected) in [
            (
                DnsServicePolicy {
                    net_id: [8; 16],
                    ..f.body.clone()
                },
                Error::WrongNetwork,
            ),
            (
                DnsServicePolicy {
                    issued_at: 9,
                    ..f.body.clone()
                },
                Error::InvalidTime,
            ),
            (
                DnsServicePolicy {
                    expires: 101,
                    ..f.body.clone()
                },
                Error::InvalidTime,
            ),
        ] {
            let (raw, ed, pq) = f.sign(&body);
            assert_eq!(
                VerifiedDnsServicePolicy::verify(&raw, &ed, &pq, &f.pin, &f.network, 50)
                    .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn requires_both_root_signatures_in_the_service_policy_domain() {
        let f = Fixture::new();
        let (raw, ed, pq) = f.sign(&f.body);
        let wrong_domain = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let (wrong_ed, wrong_pq) = sign(&f.ed, &f.pq, &wrong_domain);
        let other = Fixture::new();
        for (ed, pq, root, expected) in [
            (
                wrong_ed.as_slice(),
                pq.as_slice(),
                &f.pin,
                Error::InvalidEdSignature,
            ),
            (
                ed.as_slice(),
                wrong_pq.as_slice(),
                &f.pin,
                Error::InvalidMlDsaSignature,
            ),
            (
                ed.as_slice(),
                pq.as_slice(),
                &other.pin,
                Error::WrongRootKey,
            ),
            (
                &ed[..63],
                pq.as_slice(),
                &f.pin,
                Error::InvalidSignatureLength,
            ),
            (
                ed.as_slice(),
                &pq[..3308],
                &f.pin,
                Error::InvalidSignatureLength,
            ),
        ] {
            assert_eq!(
                VerifiedDnsServicePolicy::verify(&raw, ed, pq, root, &f.network, 50).unwrap_err(),
                expected
            );
        }
    }
}
