//! Runtime revocation: a real dual-signed StatusSnapshot changes who may forward.
//!
//! The production `StatusStore` refuses every non-empty revocation payload, so this
//! exercises [`boreas_cli::daemon_revoke`] through the same verifier the store uses
//! and the same poll decision the business loop calls before forwarding.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]

use boreas_pki::Authority;
use boreas_pki::management::{
    IssuerRecord, IssuerScope, MANAGEMENT_SCHEMA_VERSION, ManagementTrust,
};
use boreas_pki::revoke_cleanup::CleanupTable;
use boreas_proto::messages::{ED25519_SIGNATURE_LEN, SignedObject, SignerRole, SignerSignatures};
use boreas_proto::objects::{
    ManagementObject, MldsaParameterSet, ObjectType, StatusSnapshot, SubjectIdentity,
};
use boreas_proto::revocation::{IssuerClass, RevocationEntry, RevocationPayload};
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::Signer;

const NET: [u8; 16] = [0x42; 16];
const REVOKED_NODE: u16 = 2;
const REVOKED_GENERATION: u64 = 1;
const OTHER_NODE: u16 = 3;

struct StatusSigner {
    key_id: Vec<u8>,
    ed25519: PKey<Private>,
    mldsa: PKey<Private>,
}

impl StatusSigner {
    fn generate() -> Self {
        Self {
            key_id: vec![7],
            ed25519: PKey::generate_ed25519().unwrap(),
            mldsa: PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[7; 32]).unwrap(),
        }
    }

    fn record(&self) -> IssuerRecord {
        IssuerRecord {
            issuer_key_id: self.key_id.clone(),
            issuer_generation: 1,
            authority: Authority::StatusSigner,
            ed25519_public_key_der: self.ed25519.public_key_to_der().unwrap(),
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: self.mldsa.public_key_to_der().unwrap(),
            scope: IssuerScope::default(),
        }
    }

    fn sign(&self, issued_at: u64, next_update: u64, sequence: u64, revocations: &[u8]) -> Vec<u8> {
        let object = ManagementObject {
            net_id: NET,
            issuer_key_id: self.key_id.clone(),
            issuer_generation: 1,
            subject_identity: SubjectIdentity::Network,
            seq: sequence,
            issued_at,
            expires: next_update,
            extensions: Vec::new(),
            body: boreas_proto::objects::ObjectBody::StatusSnapshot(StatusSnapshot {
                issued_at,
                next_update,
                sequence,
                revocations: revocations.to_vec(),
            }),
        };
        let raw_tbs = boreas_proto::objects::encode_tbs(&object).unwrap();
        let message = boreas_proto::objects::signature_input(
            &raw_tbs,
            ObjectType::StatusSnapshot,
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
        SignedObject {
            object_type: ObjectType::StatusSnapshot,
            raw_tbs,
            signers: vec![SignerSignatures {
                role: SignerRole::Primary,
                ed25519,
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa,
            }],
        }
        .encode()
        .unwrap()
    }
}

fn trust_for(signer: &StatusSigner) -> ManagementTrust {
    let mut trust = ManagementTrust::new(NET);
    trust.add_issuer(signer.record()).unwrap();
    trust
}

fn identity_revocation() -> Vec<u8> {
    let entry = RevocationEntry::new(
        IssuerClass::Identity,
        0,
        REVOKED_NODE,
        REVOKED_GENERATION,
        0,
        1,
        1,
    )
    .unwrap();
    RevocationPayload::new(vec![entry])
        .unwrap()
        .encode()
        .unwrap()
}

#[test]
fn revocation_stops_only_the_named_peer() {
    use boreas_cli::daemon_revoke::{
        ForwardPoll, RevocationSet, apply_signed_status, poll_peer_forward,
    };

    let signer = StatusSigner::generate();
    let mut trust = trust_for(&signer);
    let mut set = RevocationSet::new();
    let mut cleanup = CleanupTable::default();
    let mut forwarded = 0u64;
    let mut failures = 0u64;

    assert_eq!(
        poll_peer_forward(
            &set,
            REVOKED_NODE,
            REVOKED_GENERATION,
            &mut forwarded,
            &mut failures
        ),
        ForwardPoll::Forward
    );
    assert_eq!(forwarded, 1);
    assert_eq!(failures, 0);

    let raw = signer.sign(100, 1_000, 1, &identity_revocation());
    let applied = apply_signed_status(&mut trust, &raw, 200, &mut set, &mut cleanup).unwrap();
    assert_eq!(applied.sequence, 1);
    assert!(set.contains(REVOKED_NODE, REVOKED_GENERATION));

    assert_eq!(
        poll_peer_forward(
            &set,
            REVOKED_NODE,
            REVOKED_GENERATION,
            &mut forwarded,
            &mut failures
        ),
        ForwardPoll::Revoked
    );
    assert_eq!(forwarded, 1, "a revoked peer must not be forwarded again");
    assert_eq!(failures, 1, "revocation counts one failed forward");

    assert_eq!(
        poll_peer_forward(
            &set,
            OTHER_NODE,
            REVOKED_GENERATION,
            &mut forwarded,
            &mut failures
        ),
        ForwardPoll::Forward
    );
    assert_eq!(forwarded, 2);
    assert!(!set.contains(OTHER_NODE, REVOKED_GENERATION));
    assert!(
        !set.contains(REVOKED_NODE, 2),
        "a later generation of the same node is not revoked"
    );
}

#[test]
fn expired_or_mis_signed_snapshot_does_not_change_the_set() {
    use boreas_cli::daemon_revoke::{RevocationSet, RevokeApplyError, apply_signed_status};

    let signer = StatusSigner::generate();
    let mut trust = trust_for(&signer);
    let mut set = RevocationSet::new();
    let mut cleanup = CleanupTable::default();
    let raw = signer.sign(100, 1_000, 1, &identity_revocation());

    let expired = apply_signed_status(&mut trust, &raw, 1_000, &mut set, &mut cleanup);
    assert_eq!(expired, Err(RevokeApplyError::SnapshotRejected));
    assert!(set.is_empty());
    assert!(cleanup.lookup(REVOKED_NODE, REVOKED_GENERATION).is_none());

    let mut forged = raw.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let rejected = apply_signed_status(&mut trust, &forged, 200, &mut set, &mut cleanup);
    assert_eq!(rejected, Err(RevokeApplyError::SnapshotRejected));
    assert!(set.is_empty(), "a bad signature must not revoke anyone");

    let accepted = apply_signed_status(&mut trust, &raw, 200, &mut set, &mut cleanup).unwrap();
    assert_eq!(accepted.revoked_peers, 1);
    assert!(set.contains(REVOKED_NODE, REVOKED_GENERATION));
}
