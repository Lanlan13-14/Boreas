//! Production must not derive an identity denial from a dual-signed status snapshot.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]

use boreas_pki::Authority;
use boreas_pki::management::{
    IssuerRecord, IssuerScope, MANAGEMENT_SCHEMA_VERSION, ManagementTrust,
};
use boreas_pki::status_store::{AuthenticatedPeer, Error, StatusStore};
use boreas_proto::messages::{ED25519_SIGNATURE_LEN, SignedObject, SignerRole, SignerSignatures};
use boreas_proto::objects::{
    ManagementObject, MldsaParameterSet, ObjectType, StatusSnapshot, SubjectIdentity,
};
use boreas_proto::revocation::{IssuerClass, RevocationEntry, RevocationPayload};
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::Signer;
use std::{fs, os::unix::fs::{MetadataExt, PermissionsExt}, time::Instant};

const NET: [u8; 16] = [0x42; 16];
const REVOKED_NODE: u16 = 2;
const REVOKED_GENERATION: u64 = 1;

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
fn dual_signed_status_cannot_revoke_an_identity_or_advance_the_status_sequence() {
    use boreas_pki::authority_revocation::AuthorityRevocationTrust;

    let dir = std::env::temp_dir().join(format!("boreas-status-no-relay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let signer = StatusSigner::generate();
    let mut store = StatusStore::open_with_identity_revocations(
        dir.join("status.state"),
        NET,
        fs::metadata(&dir).unwrap().uid(),
        trust_for(&signer),
        [1; 32],
        AuthorityRevocationTrust::new(NET),
    )
    .unwrap();
    let peer = AuthenticatedPeer::new(NET, REVOKED_NODE, REVOKED_GENERATION).unwrap();
    let now = Instant::now();
    let raw = signer.sign(100, 1_000, 2, &identity_revocation());
    assert!(matches!(store.accept_signed_snapshot(&raw, 200, now), Err(Error::RevocationPermission)));
    assert_eq!(store.sequence(), None);
    assert!(!store.identity_revoked(&peer).unwrap());
    let clean = signer.sign(100, 1_000, 1, &[]);
    store.accept_signed_snapshot(&clean, 200, now).unwrap();
    assert_eq!(store.sequence(), Some(1));
    assert!(!store.identity_revoked(&peer).unwrap());
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}
