use super::*;
use crate::{
    NetworkPolicyError, NetworkRootPin,
    management::IssuerScope,
    root_authorization::{self, Purpose, RootAuthorizationCandidate, Scope},
    verify_network_policy,
};
use boreas_proto::{
    messages::SignedObject,
    network_policy::NetworkPolicyCandidate,
    objects::{self, MldsaParameterSet},
};
use openssl::{
    pkey::{KeyType, PKey, Private},
    sign::Signer,
};

const NET: [u8; 16] = [0x42; 16];
const BASE: [u8; 4] = [172, 19, 0, 0];
const NOW: u64 = 400;

struct Fixture {
    root_ed: PKey<Private>,
    root_pq: PKey<Private>,
    pin: NetworkRootPin,
    signer: IdentityAuthority,
    issuer: VerifiedIssuerAuthorization,
    source: NodeIdentity,
}

fn pq(seed: u8) -> PKey<Private> {
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap()
}

fn sign(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
    Signer::new_without_digest(key)
        .unwrap()
        .sign_oneshot_to_vec(message)
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let root_ed = PKey::generate_ed25519().unwrap();
        let root_pq = pq(1);
        let pin = NetworkRootPin::provisioned(
            NET,
            root_ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        let signer = IdentityAuthority::from_pkcs8_der(
            NET,
            b"migration-ia".to_vec(),
            1,
            &PKey::generate_ed25519()
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap(),
            &pq(2).private_key_to_pkcs8().unwrap(),
        )
        .unwrap();
        let roles = vec![NodeRole::Edge, NodeRole::Core];
        let homes = vec![1, 16];
        let ia = signer
            .issuer_record(IssuerScope::for_identity(roles.clone(), homes.clone()).unwrap())
            .unwrap();
        let authorization = RootAuthorizationCandidate {
            net_id: NET,
            issuer_key_id: ia.issuer_key_id,
            issuer_generation: ia.issuer_generation,
            purpose: Purpose::Identity,
            ed25519_public_key_der: ia.ed25519_public_key_der,
            mldsa_parameter_set: ia.mldsa_parameter_set,
            mldsa_public_key_der: ia.mldsa_public_key_der,
            scope: Scope::Identity {
                roles,
                home_cores: homes,
            },
            not_before: 120,
            expires: 600,
            chain_depth: root_authorization::MAX_CHAIN_DEPTH,
            may_delegate: false,
        };
        let raw = authorization.encode_candidate().unwrap();
        let msg = [b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0".as_slice(), &raw].concat();
        let issuer = root_authorization::verify_raw(
            &raw,
            &sign(&root_ed, &msg),
            &sign(&root_pq, &msg),
            &pin,
            NET,
            NOW,
        )
        .unwrap();
        let source = NodeIdentity {
            net_id: NET,
            node_id: 0x0ffb,
            home_core_id: 16,
            vip: [10, 20, 16, 251],
            vip6: [0; 16],
            role: ObjectNodeRole::Edge,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            identity_pub_mldsa: pq(3).raw_public_key().unwrap(),
            identity_pub_ed25519: PKey::generate_ed25519()
                .unwrap()
                .raw_public_key()
                .unwrap()
                .try_into()
                .unwrap(),
            identity_generation: 7,
            not_before: 100,
            expires: 800,
            scope: b"retain scope".to_vec(),
        };
        Self {
            root_ed,
            root_pq,
            pin,
            signer,
            issuer,
            source,
        }
    }

    fn policy(&self, overlay_base: [u8; 4], seq: u64) -> VerifiedNetworkPolicy {
        let candidate = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: self.pin.fingerprint().unwrap(),
            overlay_base,
            version: 1,
            seq,
            issued_at: 200,
            expires: 700,
        };
        let raw = candidate.encode_tbs().unwrap();
        let msg = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        verify_network_policy(
            &raw,
            &sign(&self.root_ed, &msg),
            &sign(&self.root_pq, &msg),
            &self.pin,
            NET,
            NOW,
        )
        .unwrap()
    }

    fn legacy(&self, body: NodeIdentity) -> Vec<u8> {
        self.signer
            .sign_node_identity(body)
            .unwrap()
            .encode()
            .unwrap()
    }
}

#[test]
fn stages_verifiable_edge_and_core_but_does_not_activate_custom_policy() {
    let f = Fixture::new();
    let policy = f.policy(BASE, 3);
    assert_eq!(
        policy.require_default_runtime(),
        Err(NetworkPolicyError::UnsupportedRuntimePrefix)
    );
    let mut core = f.source.clone();
    core.role = ObjectNodeRole::Core;
    core.home_core_id = 1;
    core.node_id = 1;
    core.vip = [10, 20, 1, 1];
    for source in [f.source.clone(), core] {
        let legacy = f.legacy(source.clone());
        let staged = f
            .signer
            .stage_ipv4_pool_migration(&legacy, &policy, &f.issuer, NOW)
            .unwrap();
        let verified =
            verify_ipv4_pool_migration(&legacy, &staged, &policy, &f.issuer, NOW + 1).unwrap();
        let mut expected = source;
        expected.vip[..2].copy_from_slice(&BASE[..2]);
        expected.identity_generation += 1;
        expected.not_before = 200;
        expected.expires = 600; // Earlier than either source or policy expiry.
        assert_eq!(verified, expected);

        let signed = SignedObject::decode_for_overlay(&staged, BASE).unwrap();
        let retried = f
            .signer
            .stage_ipv4_pool_migration(&legacy, &policy, &f.issuer, NOW + 1)
            .unwrap();
        assert_eq!(
            SignedObject::decode_for_overlay(&retried, BASE)
                .unwrap()
                .raw_tbs,
            signed.raw_tbs
        );
        assert_eq!(signed.encode_for_overlay(BASE).unwrap(), staged);
        assert!(SignedObject::decode(&staged).is_err());
        assert!(SignedObject::decode_for_overlay(&staged, [10, 21, 0, 0]).is_err());
        let mut live = ManagementTrust::new(NET);
        live.add_verified_issuer(&f.issuer).unwrap();
        assert!(live.verify_and_authorize(&staged, NOW).is_err());
        assert!(live.verify_and_authorize(&legacy, NOW).is_ok());
    }
}

#[test]
fn rejects_each_invalid_signature_and_policy_or_source_substitution() {
    let f = Fixture::new();
    let policy = f.policy(BASE, 3);
    let legacy = f.legacy(f.source.clone());
    let staged = f
        .signer
        .stage_ipv4_pool_migration(&legacy, &policy, &f.issuer, NOW)
        .unwrap();
    for tamper_ed in [true, false] {
        let mut signed = SignedObject::decode_for_overlay(&staged, BASE).unwrap();
        if tamper_ed {
            signed.signers[0].ed25519[0] ^= 1;
        } else {
            signed.signers[0].mldsa.fill(0);
        }
        let changed = signed.encode_for_overlay(BASE).unwrap();
        assert!(verify_ipv4_pool_migration(&legacy, &changed, &policy, &f.issuer, NOW).is_err());
    }
    let mut changed = SignedObject::decode_for_overlay(&staged, BASE).unwrap();
    let mut changed_object = objects::decode_tbs_for_overlay(&changed.raw_tbs, BASE).unwrap();
    changed_object.extensions[0].value[0] ^= 1;
    changed.raw_tbs = objects::encode_tbs_for_overlay(&changed_object, BASE).unwrap();
    assert_eq!(
        verify_ipv4_pool_migration(&legacy, &changed.encode_for_overlay(BASE).unwrap(), &policy, &f.issuer, NOW),
        Err(Error::InvalidEd25519Signature)
    );
    changed_object.extensions.clear();
    assert!(objects::encode_tbs_for_overlay(&changed_object, BASE).is_err());

    let mut invalid_source = SignedObject::decode(&legacy).unwrap();
    invalid_source.signers[0].ed25519[0] ^= 1;
    assert!(
        f.signer
            .stage_ipv4_pool_migration(&invalid_source.encode().unwrap(), &policy, &f.issuer, NOW)
            .is_err()
    );
    assert_eq!(
        verify_ipv4_pool_migration(&legacy, &staged, &f.policy(BASE, 4), &f.issuer, NOW),
        Err(Error::InvalidPoolMigration)
    );
    let wrong_root_policy = Fixture::new().policy(BASE, 3);
    assert_eq!(
        verify_ipv4_pool_migration(&legacy, &staged, &wrong_root_policy, &f.issuer, NOW),
        Err(Error::InvalidPoolMigration)
    );

    let mut alternate_source = f.source.clone();
    alternate_source.expires += 1; // Same transformed body, but different exact TBS.
    assert_eq!(
        verify_ipv4_pool_migration(
            &f.legacy(alternate_source),
            &staged,
            &policy,
            &f.issuer,
            NOW
        ),
        Err(Error::InvalidPoolMigration)
    );
    assert!(verify_ipv4_pool_migration(&legacy, &staged, &policy, &f.issuer, 600).is_err());
}

#[test]
fn refuses_out_of_scope_sources_unsupported_slots_and_generation_wrap() {
    let f = Fixture::new();
    let policy = f.policy(BASE, 3);
    let mut source = f.source.clone();
    source.identity_generation = u64::MAX;
    assert_eq!(
        f.signer
            .stage_ipv4_pool_migration(&f.legacy(source), &policy, &f.issuer, NOW),
        Err(Error::InvalidPoolMigration)
    );
    let mut source = f.source.clone();
    source.vip6[0] = 0xfd;
    assert_eq!(
        f.signer
            .stage_ipv4_pool_migration(&f.legacy(source), &policy, &f.issuer, NOW),
        Err(Error::InvalidPoolMigration)
    );
    let mut source = f.source.clone();
    source.node_id = 0x01fb;
    source.home_core_id = 2;
    source.vip[2] = 2;
    assert_eq!(
        f.signer
            .stage_ipv4_pool_migration(&f.legacy(source), &policy, &f.issuer, NOW),
        Err(Error::OutOfScope)
    );
    let mut source = f.source.clone();
    source.node_id = 0x0ffc;
    source.vip[3] = 252;
    assert!(f.signer.sign_node_identity(source).is_err());

    let legacy = f.legacy(f.source.clone());
    assert_eq!(
        f.signer
            .stage_ipv4_pool_migration(&legacy, &f.policy([10, 20, 0, 0], 1), &f.issuer, NOW),
        Err(Error::InvalidPoolMigration)
    );
    assert_eq!(
        f.signer
            .stage_ipv4_pool_migration(&legacy, &policy, &f.issuer, 199),
        Err(Error::InvalidPoolMigration)
    );
}
