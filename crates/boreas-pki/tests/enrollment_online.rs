//! Online enrollment from candidate control bytes through dual-signed identity.
//!
//! Requires `openssl-backend`. Without it this file is an empty test target so the
//! default workspace build still compiles.

#![cfg(feature = "openssl-backend")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use boreas_pki::NodeRole as PolicyRole;
use boreas_pki::enrollment::{
    CsrPolicy, EXPERIMENTAL_ED25519_CSR_POP_OID, EnrollmentError, EnrollmentPhase, EnrollmentStore,
    InviteSpec, NodeRole, Slot, WriterFence,
};
use boreas_pki::management::{
    IdentityAuthority, IssuerScope, ManagementTrust, verify_signed_identity,
};
use boreas_proto::messages::{ENROLLMENT_VERSION, Enrollment, EnrollmentRequest};
use boreas_proto::objects::ObjectBody;
use openssl::asn1::{Asn1Object, Asn1OctetString};
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::Signer;
use openssl::stack::Stack;
use openssl::x509::{X509Extension, X509NameBuilder, X509ReqBuilder};

const NET: [u8; 16] = [0x42; 16];
const POP_DOMAIN: &[u8] = b"BOREAS-NODE-ED25519-POP-v1\0";
const NOW_US: u64 = 1_000_000;

fn private_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "boreas-enroll-online-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn ml_dsa(seed: u8) -> PKey<Private> {
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap()
}

fn csr_with_pop(ml_key: &PKey<Private>, ed_key: &PKey<Private>, oid: &str) -> Vec<u8> {
    let ml_public = ml_key.raw_public_key().unwrap();
    let ed_public = ed_key.raw_public_key().unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(POP_DOMAIN);
    message.extend_from_slice(&ed_public);
    message.extend_from_slice(&ml_public);
    let mut signer = Signer::new_without_digest(ed_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&message).unwrap();
    let mut payload = vec![1u8];
    payload.extend_from_slice(&ed_public);
    payload.extend_from_slice(&signature);
    let extension = X509Extension::new_from_der(
        Asn1Object::from_str(oid).unwrap().as_ref(),
        true,
        Asn1OctetString::new_from_bytes(&payload).unwrap().as_ref(),
    )
    .unwrap();
    let mut extensions = Stack::new().unwrap();
    extensions.push(extension).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "boreas-online-enrollment")
        .unwrap();
    let name = name.build();
    let mut builder = X509ReqBuilder::new().unwrap();
    builder.set_version(0).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(ml_key).unwrap();
    builder.add_extensions(&extensions).unwrap();
    builder.sign(ml_key, MessageDigest::null()).unwrap();
    builder.build().to_der().unwrap()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = hash(MessageDigest::sha256(), bytes).unwrap();
    digest.as_ref().try_into().unwrap()
}

fn request_bytes(
    enrollment_id: [u8; 16],
    invite_id: [u8; 16],
    secret: [u8; 32],
    csr: &[u8],
) -> Vec<u8> {
    Enrollment::Request(EnrollmentRequest {
        request_version: ENROLLMENT_VERSION,
        enrollment_id,
        invite_id,
        csr_hash: sha256(csr),
        invite_secret: secret,
        csr_der: csr.to_vec(),
    })
    .encode()
    .unwrap()
}

fn invite(secret: [u8; 32]) -> InviteSpec {
    InviteSpec {
        invite_id: [1u8; 16],
        expires_at_us: NOW_US + 60_000_000,
        role: NodeRole::Edge,
        home_core_id: 1,
        bearer_secret: secret,
    }
}

fn edge_slot() -> Slot {
    Slot {
        home_core_id: 1,
        vip_octet: 2,
        role: NodeRole::Edge,
    }
}

fn open_store(path: &Path, secret: [u8; 32]) -> EnrollmentStore {
    let policy = CsrPolicy::with_ed25519_pop_oid(EXPERIMENTAL_ED25519_CSR_POP_OID).unwrap();
    EnrollmentStore::open_with_csr_policy(
        path.join("journal"),
        WriterFence::from_external_authority(1),
        vec![invite(secret)],
        vec![edge_slot()],
        policy,
    )
    .unwrap()
}

fn authority() -> IdentityAuthority {
    let ed = PKey::generate_ed25519().unwrap();
    IdentityAuthority::from_pkcs8_der(
        NET,
        vec![9],
        1,
        &ed.private_key_to_pkcs8().unwrap(),
        &ml_dsa(12).private_key_to_pkcs8().unwrap(),
    )
    .unwrap()
}

fn validity() -> boreas_pki::enrollment::IdentityValidity {
    boreas_pki::enrollment::IdentityValidity {
        not_before_us: NOW_US - 1,
        expires_us: NOW_US + 60_000_000,
        scope: vec![1, 2, 3],
    }
}

#[test]
fn online_request_is_verified_and_issued_from_network_bytes() {
    let dir = private_dir("issue");
    let secret = [7u8; 32];
    let enrollment_id = [9u8; 16];
    let ml_key = ml_dsa(11);
    let ed_key = PKey::generate_ed25519().unwrap();
    let ed_public: [u8; 32] = ed_key.raw_public_key().unwrap().try_into().unwrap();
    let csr = csr_with_pop(&ml_key, &ed_key, EXPERIMENTAL_ED25519_CSR_POP_OID);
    let raw = request_bytes(enrollment_id, [1u8; 16], secret, &csr);
    let signer = authority();
    let signed = {
        let mut store = open_store(&dir, secret);
        let prepared = store.claim_from_request(&raw, NOW_US).unwrap();
        assert_eq!(prepared.phase, EnrollmentPhase::Prepared);
        assert_eq!(prepared.node_id, 2);
        assert!(prepared.signed_identity.is_none());
        store
            .issue(&signer, enrollment_id, NOW_US, validity())
            .unwrap()
    };
    let mut trust = ManagementTrust::new(NET);
    trust
        .add_issuer(
            signer
                .issuer_record(IssuerScope::for_identity(vec![PolicyRole::Edge], vec![1]).unwrap())
                .unwrap(),
        )
        .unwrap();
    let verified = verify_signed_identity(&mut trust, &signed, NOW_US).unwrap();
    match &verified.object().body {
        ObjectBody::NodeIdentity(body) => {
            assert_eq!(body.node_id, 2);
            assert_eq!(body.identity_generation, 1);
            assert_eq!(body.identity_pub_ed25519, ed_public);
            assert_eq!(body.identity_pub_mldsa, ml_key.raw_public_key().unwrap());
        }
        other => panic!("expected NodeIdentity, got {other:?}"),
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn second_claim_of_the_same_invite_allocates_nothing() {
    let dir = private_dir("rebind");
    let secret = [7u8; 32];
    let ml_key = ml_dsa(11);
    let ed_key = PKey::generate_ed25519().unwrap();
    let first_csr = csr_with_pop(&ml_key, &ed_key, EXPERIMENTAL_ED25519_CSR_POP_OID);
    let mut store = open_store(&dir, secret);
    let first = request_bytes([9u8; 16], [1u8; 16], secret, &first_csr);
    assert_eq!(store.claim_from_request(&first, NOW_US).unwrap().node_id, 2);
    let other_csr = csr_with_pop(
        &ml_dsa(21),
        &PKey::generate_ed25519().unwrap(),
        EXPERIMENTAL_ED25519_CSR_POP_OID,
    );
    let second = request_bytes([8u8; 16], [1u8; 16], secret, &other_csr);
    assert!(matches!(
        store.claim_from_request(&second, NOW_US),
        Err(EnrollmentError::InviteBoundToDifferentRequest)
    ));
    assert_eq!(store.allocation_watermark(1).unwrap(), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_bearer_is_rejected_without_a_slot() {
    let dir = private_dir("bearer");
    let ml_key = ml_dsa(11);
    let ed_key = PKey::generate_ed25519().unwrap();
    let csr = csr_with_pop(&ml_key, &ed_key, EXPERIMENTAL_ED25519_CSR_POP_OID);
    let mut store = open_store(&dir, [7u8; 32]);
    let raw = request_bytes([9u8; 16], [1u8; 16], [8u8; 32], &csr);
    assert!(matches!(
        store.claim_from_request(&raw, NOW_US),
        Err(EnrollmentError::InvalidBearerSecret)
    ));
    assert_eq!(store.allocation_watermark(1).unwrap(), 0);
    let honest = request_bytes([9u8; 16], [1u8; 16], [7u8; 32], &csr);
    assert_eq!(
        store.claim_from_request(&honest, NOW_US).unwrap().node_id,
        2
    );
    assert_eq!(store.allocation_watermark(1).unwrap(), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn issued_node_id_survives_journal_recovery() {
    let dir = private_dir("recover");
    let secret = [7u8; 32];
    let enrollment_id = [9u8; 16];
    let csr = csr_with_pop(
        &ml_dsa(11),
        &PKey::generate_ed25519().unwrap(),
        EXPERIMENTAL_ED25519_CSR_POP_OID,
    );
    let raw = request_bytes(enrollment_id, [1u8; 16], secret, &csr);
    let signer = authority();
    let (node_id, signed) = {
        let mut store = open_store(&dir, secret);
        store.claim_from_request(&raw, NOW_US).unwrap();
        let signed = store
            .issue(&signer, enrollment_id, NOW_US, validity())
            .unwrap();
        (2u16, signed)
    };
    let mut recovered = open_store(&dir, secret);
    let again = recovered.claim_from_request(&raw, NOW_US + 1).unwrap();
    assert_eq!(again.node_id, node_id);
    assert_eq!(again.phase, EnrollmentPhase::Issued);
    assert_eq!(again.signed_identity.as_deref(), Some(signed.as_slice()));
    let repeated = recovered
        .issue(&signer, enrollment_id, NOW_US + 1, validity())
        .unwrap();
    assert_eq!(repeated, signed);
    assert_eq!(recovered.allocation_watermark(1).unwrap(), 1);
    let _ = fs::remove_dir_all(&dir);
}
