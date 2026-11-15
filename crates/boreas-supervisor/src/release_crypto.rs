//! Real Ed25519 + ML-DSA-65 verification and SHA-256 for release artifacts,
//! backed by the maintained `openssl` crate (`=0.10.82`, OpenSSL 3.5+ provider).
//!
//! Compiled only with the `openssl-backend` feature. The default build has no
//! provider and `manifest::verify_release` must keep failing closed with
//! `ManifestError::VerificationUnavailable`.
//!
//! # Trust and key selection
//!
//! This module has no notion of a key id. The caller must first select exactly
//! one provisioned `ReleaseRoot` by exact `key_id` match and only then pass its
//! **SPKI DER** public keys here. Both keys are parsed with
//! `PKey::public_key_from_der` and checked with `PKey::is_a(KeyType)`; a raw
//! key blob, a key of the wrong algorithm, malformed DER, or an over-limit DER
//! is a verification failure, never a "skip this half" condition. The parsed
//! key is re-encoded and compared byte-for-byte with the input, because
//! OpenSSL's DER parser can tolerate trailing bytes; this rejects non-canonical
//! or trailing data instead of silently ignoring it.
//!
//! Ed25519 and ML-DSA-65 signatures are both checked over the exact same
//! message bytes with `Verifier::new_without_digest` + `verify_oneshot`. This is
//! an AND: either half failing, including a backend error, rejects the release.
//! No TLS, X.509 chain, or network identity key is involved here.
//!
//! Error strings are static and deliberately contain no key, signature, path,
//! or manifest bytes, so a caller may map them to a coarse
//! `ManifestError::Invalid(reason)` without leaking material.
//!
//! [`sha256`] and [`verify_asset_bytes`] operate on an already-bounded
//! in-memory slice. They must not be used as a license to `read_to_end` an
//! untrusted artifact: the supervisor's file path must stream the digest with
//! an explicit byte counter and refuse input above the staging bound.

use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{KeyType, PKey, Public};
use openssl::sign::Verifier;

use crate::manifest::{
    MAX_ED25519_PUBLIC_KEY_DER_BYTES, MAX_MANIFEST_BYTES, MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
};

/// Raw Ed25519 signature length.
pub(crate) const ED25519_SIGNATURE_BYTES: usize = 64;
/// Release manifest message bound, matching the parser's own bound.
pub(crate) const MAX_RELEASE_MESSAGE_BYTES: usize = MAX_MANIFEST_BYTES;
/// Staging bound for one release artifact; this mirrors the supervisor's
/// existing 2 GiB artifact limit and is not a claim that 2 GiB is safe to hold
/// in memory.
pub(crate) const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Parse and type-check both provisioned public keys.
///
/// `ed25519_der` and `ml_dsa_65_der` must be SubjectPublicKeyInfo DER, not raw
/// key bytes. The length checks run before `public_key_from_der` so a
/// caller-supplied oversized blob cannot force an unbounded DER parse.
fn parse_release_keys(
    ed25519_der: &[u8],
    ml_dsa_65_der: &[u8],
) -> Result<(PKey<Public>, PKey<Public>), &'static str> {
    if ed25519_der.len() > MAX_ED25519_PUBLIC_KEY_DER_BYTES {
        return Err("release root Ed25519 SPKI DER exceeds the length limit");
    }
    if ml_dsa_65_der.len() > MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES {
        return Err("release root ML-DSA-65 SPKI DER exceeds the length limit");
    }

    let ed25519_key = PKey::public_key_from_der(ed25519_der)
        .map_err(|_| "release root Ed25519 public key is not valid SPKI DER")?;
    if !ed25519_key.is_a(KeyType::ED25519) {
        return Err("release root key is not an Ed25519 public key");
    }
    let ed25519_canonical = ed25519_key
        .public_key_to_der()
        .map_err(|_| "release root Ed25519 public key re-encode failed")?;
    if ed25519_canonical.as_slice() != ed25519_der {
        return Err("release root Ed25519 SPKI DER is non-canonical or has trailing bytes");
    }

    let ml_dsa_65_key = PKey::public_key_from_der(ml_dsa_65_der)
        .map_err(|_| "release root ML-DSA-65 public key is not valid SPKI DER")?;
    if !ml_dsa_65_key.is_a(KeyType::ML_DSA_65) {
        return Err("release root key is not an ML-DSA-65 public key");
    }
    let ml_dsa_65_canonical = ml_dsa_65_key
        .public_key_to_der()
        .map_err(|_| "release root ML-DSA-65 public key re-encode failed")?;
    if ml_dsa_65_canonical.as_slice() != ml_dsa_65_der {
        return Err("release root ML-DSA-65 SPKI DER is non-canonical or has trailing bytes");
    }

    Ok((ed25519_key, ml_dsa_65_key))
}

/// Validate both provisioned trust-anchor keys without verifying a signature.
///
/// This is suitable for provisioning/startup preflight. It does not prove that
/// either private key is held by the release signer, and it does not replace
/// [`verify_dual`] on the exact manifest bytes.
#[allow(dead_code)] // provisioning preflight; verify_dual repeats the check per handshake
pub(crate) fn check_key_types(
    ed25519_der: &[u8],
    ml_dsa_65_der: &[u8],
) -> Result<(), &'static str> {
    parse_release_keys(ed25519_der, ml_dsa_65_der).map(|_| ())
}

/// Verify **both** signatures over the same message bytes.
///
/// The caller must already have selected the root by exact `key_id`; this
/// function intentionally has no key-id parameter and performs no key lookup.
/// Ed25519 is verified first, then ML-DSA-65, and both must return `true`.
/// Any malformed DER, wrong algorithm, wrong signature length, or OpenSSL error
/// is an error; there is no mode in which one successful half authorizes the
/// release.
pub(crate) fn verify_dual(
    message: &[u8],
    ed25519_public_key_der: &[u8],
    ml_dsa_65_public_key_der: &[u8],
    ed25519_signature: &[u8],
    ml_dsa_65_signature: &[u8],
) -> Result<(), &'static str> {
    if message.len() > MAX_RELEASE_MESSAGE_BYTES {
        return Err("release message exceeds the configured byte limit");
    }
    if ed25519_signature.len() != ED25519_SIGNATURE_BYTES {
        return Err("Ed25519 signature length is not 64 bytes");
    }
    if ml_dsa_65_signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err("ML-DSA-65 signature length is not 3309 bytes");
    }

    let (ed25519_key, ml_dsa_65_key) =
        parse_release_keys(ed25519_public_key_der, ml_dsa_65_public_key_der)?;

    let mut ed25519_verifier =
        Verifier::new_without_digest(&ed25519_key).map_err(|_| "Ed25519 verifier unavailable")?;
    let ed25519_valid = ed25519_verifier
        .verify_oneshot(ed25519_signature, message)
        .map_err(|_| "Ed25519 verification backend error")?;
    if !ed25519_valid {
        return Err("Ed25519 signature does not match the release bytes");
    }

    let mut ml_dsa_65_verifier =
        Verifier::new_without_digest(&ml_dsa_65_key).map_err(|_| "ML-DSA-65 verifier unavailable")?;
    let ml_dsa_65_valid = ml_dsa_65_verifier
        .verify_oneshot(ml_dsa_65_signature, message)
        .map_err(|_| "ML-DSA-65 verification backend error")?;
    if !ml_dsa_65_valid {
        return Err("ML-DSA-65 signature does not match the release bytes");
    }

    Ok(())
}

/// SHA-256 of an already-bounded byte slice, for comparison with the
/// authenticated manifest claim. OpenSSL computes the digest; this module does
/// not implement SHA-256 itself.
///
/// For a real artifact file, the supervisor must hash a bounded reader in
/// chunks while counting bytes and abort above the staging limit. Passing a
/// whole untrusted file in one slice is not an acceptable production path.
pub(crate) fn sha256(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    if bytes.len() as u64 > MAX_ASSET_BYTES {
        return Err("SHA-256 input exceeds the artifact staging limit");
    }
    let digest = hash(MessageDigest::sha256(), bytes).map_err(|_| "SHA-256 backend error")?;
    let mut out = [0u8; 32];
    if digest.len() != out.len() {
        return Err("SHA-256 backend returned an unexpected length");
    }
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Verify one already-bounded downloaded artifact slice against the
/// authenticated manifest `size` and canonical lowercase `sha256` fields.
///
/// Size is checked before hashing so an oversized download cannot force a
/// needless digest. The hex comparison is exact: uppercase or truncated claims
/// are rejected rather than normalized. This helper is for bounded in-memory
/// test/data-plane slices; a file-backed download must be streamed by the
/// supervisor, not read unbounded into one `Vec`.
pub(crate) fn verify_asset_bytes(
    downloaded: &[u8],
    expected_size: u64,
    expected_sha256_hex: &str,
) -> Result<(), &'static str> {
    if expected_size > MAX_ASSET_BYTES {
        return Err("authenticated asset size exceeds the staging limit");
    }
    if downloaded.len() as u64 != expected_size {
        return Err("asset size does not match the authenticated manifest");
    }
    let digest = sha256(downloaded)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut actual = [0u8; 64];
    for (index, byte) in digest.iter().enumerate() {
        actual[index * 2] = HEX[(byte >> 4) as usize];
        actual[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    if expected_sha256_hex.as_bytes() != &actual[..] {
        return Err("asset SHA-256 does not match the authenticated manifest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;

    fn sign(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new_without_digest(key).expect("signer");
        signer
            .sign_oneshot_to_vec(message)
            .expect("one-shot signature")
    }

    fn keypair() -> (PKey<Private>, PKey<Private>) {
        let ed25519 = PKey::generate_ed25519().expect("ed25519 key");
        let ml_dsa_65 = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[7u8; 32])
            .expect("ml-dsa-65 key");
        (ed25519, ml_dsa_65)
    }

    fn public_der(key: &PKey<Private>) -> Vec<u8> {
        key.public_key_to_der().expect("SPKI DER")
    }

    #[test]
    fn dual_signature_round_trip_requires_both_halves() {
        let (ed25519, ml_dsa_65) = keypair();
        let ed_der = public_der(&ed25519);
        let mldsa_der = public_der(&ml_dsa_65);
        let message = b"exact release manifest bytes";
        let ed_sig = sign(&ed25519, message);
        let mldsa_sig = sign(&ml_dsa_65, message);

        verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &mldsa_sig).expect("both valid");

        // A valid Ed25519 half plus an invalid ML-DSA-65 half must fail.
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &vec![0u8; 3309]).is_err()
        );
        // A valid ML-DSA-65 half plus an invalid Ed25519 half must also fail.
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &vec![0u8; 64], &mldsa_sig).is_err()
        );
        // A correct-length ML-DSA-65 signature from a different key must fail
        // against the configured root key (not merely fail a length check).
        let other_mldsa = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[9u8; 32])
            .expect("other ml-dsa-65 key");
        let other_mldsa_sig = sign(&other_mldsa, message);
        assert_eq!(other_mldsa_sig.len(), ML_DSA_65_SIGNATURE_BYTES);
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &other_mldsa_sig).is_err()
        );
        // A bit-flipped but correctly sized ML-DSA-65 signature must fail.
        let mut tampered_mldsa = mldsa_sig.clone();
        tampered_mldsa[0] ^= 0x01;
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &tampered_mldsa).is_err()
        );
        // Any mutation of the signed message invalidates both halves.
        assert!(
            verify_dual(
                b"exact release manifest bytez",
                &ed_der,
                &mldsa_der,
                &ed_sig,
                &mldsa_sig
            )
            .is_err()
        );
        // Swapped anchors fail the algorithm check.
        assert!(verify_dual(message, &mldsa_der, &ed_der, &ed_sig, &mldsa_sig).is_err());
        // A different Ed25519 key cannot validate the recorded signature.
        let other_ed = PKey::generate_ed25519().expect("other ed25519");
        assert!(
            verify_dual(
                message,
                &public_der(&other_ed),
                &mldsa_der,
                &ed_sig,
                &mldsa_sig
            )
            .is_err()
        );
        // A correct-length Ed25519 signature from another key also fails
        // against the configured root key.
        let other_ed_sig = sign(&other_ed, message);
        assert_eq!(other_ed_sig.len(), ED25519_SIGNATURE_BYTES);
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &other_ed_sig, &mldsa_sig).is_err()
        );
        // A bit-flipped but correctly sized Ed25519 signature must fail.
        let mut tampered_ed = ed_sig.clone();
        tampered_ed[0] ^= 0x01;
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &tampered_ed, &mldsa_sig).is_err()
        );
    }

    #[test]
    fn real_manifest_bytes_are_verified_before_strict_parsing() {
        // Same shape as the strict manifest tests: signatures cover these exact
        // bytes, and only after `verify_dual` succeeds may the parser inspect
        // them.
        let manifest = br#"{"product":"boreas","manifest_version":1,"sequence":4,"published_at":"2026-01-01T00:00:00Z","issued_at":"2026-01-01T00:00:01Z","expires":"2026-02-01T00:00:00Z","min_compatible_state":"state-v1","signing_key_id":"root-1","assets":[{"name":"boreas-linux-x86_64","arch":"x86_64-unknown-linux-gnu","size":42,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"https://releases.example.test/boreas"}]}"#;
        let (ed25519, ml_dsa_65) = keypair();
        let ed_der = public_der(&ed25519);
        let mldsa_der = public_der(&ml_dsa_65);
        let ed_sig = sign(&ed25519, manifest);
        let mldsa_sig = sign(&ml_dsa_65, manifest);

        verify_dual(manifest, &ed_der, &mldsa_der, &ed_sig, &mldsa_sig)
            .expect("manifest dual signature");
        let parsed = crate::manifest::parse_unsigned(manifest).expect("strict parse after verify");
        assert_eq!(parsed.signing_key_id(), "root-1");
        assert_eq!(parsed.assets().len(), 1);
        assert_eq!(parsed.assets()[0].size(), 42);
        assert_eq!(
            parsed.assets()[0].sha256(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        // A one-byte mutation after signing is rejected before the parser.
        let mut modified = manifest.to_vec();
        modified[0] ^= 0x01;
        assert!(verify_dual(&modified, &ed_der, &mldsa_der, &ed_sig, &mldsa_sig).is_err());
    }

    #[test]
    fn signature_and_key_lengths_are_bounded() {
        let (ed25519, ml_dsa_65) = keypair();
        let ed_der = public_der(&ed25519);
        let mldsa_der = public_der(&ml_dsa_65);
        let message = b"length checks";
        let ed_sig = sign(&ed25519, message);
        let mldsa_sig = sign(&ml_dsa_65, message);

        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig[..63], &mldsa_sig).is_err()
        );
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &mldsa_sig[..3308]).is_err()
        );
        let oversized_ed_sig = vec![0u8; ED25519_SIGNATURE_BYTES + 1];
        let oversized_mldsa_sig = vec![0u8; ML_DSA_65_SIGNATURE_BYTES + 1];
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &oversized_ed_sig, &mldsa_sig).is_err()
        );
        assert!(
            verify_dual(message, &ed_der, &mldsa_der, &ed_sig, &oversized_mldsa_sig).is_err()
        );

        let oversized_ed = vec![0u8; MAX_ED25519_PUBLIC_KEY_DER_BYTES + 1];
        let oversized_mldsa = vec![0u8; MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES + 1];
        assert!(verify_dual(message, &oversized_ed, &mldsa_der, &ed_sig, &mldsa_sig).is_err());
        assert!(verify_dual(message, &ed_der, &oversized_mldsa, &ed_sig, &mldsa_sig).is_err());
        assert!(verify_dual(message, &[], &mldsa_der, &ed_sig, &mldsa_sig).is_err());
        assert!(verify_dual(message, &ed_der, &[], &ed_sig, &mldsa_sig).is_err());

        // Raw key bytes (not SPKI DER) are rejected even at the correct raw
        // lengths, so provisioning cannot silently pass raw material.
        let raw_ed = vec![7u8; 32];
        let raw_mldsa = vec![7u8; crate::manifest::ML_DSA_65_PUBLIC_KEY_BYTES];
        assert!(check_key_types(&raw_ed, &mldsa_der).is_err());
        assert!(check_key_types(&ed_der, &raw_mldsa).is_err());
    }

    #[test]
    fn check_key_types_rejects_wrong_algorithms_and_garbage_der() {
        let (ed25519, ml_dsa_65) = keypair();
        let ed_der = public_der(&ed25519);
        let mldsa_der = public_der(&ml_dsa_65);
        check_key_types(&ed_der, &mldsa_der).expect("matching key types");
        assert!(check_key_types(&mldsa_der, &ed_der).is_err());
        assert!(check_key_types(&[0u8; 44], &mldsa_der).is_err());
        assert!(check_key_types(&ed_der, &[0u8; 44]).is_err());
        assert!(
            check_key_types(&vec![0u8; MAX_ED25519_PUBLIC_KEY_DER_BYTES + 1], &mldsa_der)
                .is_err()
        );
        assert!(
            check_key_types(&ed_der, &vec![0u8; MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn spki_der_must_be_canonical_and_fully_consumed() {
        let (ed25519, ml_dsa_65) = keypair();
        let ed_der = public_der(&ed25519);
        let mldsa_der = public_der(&ml_dsa_65);
        let message = b"strict DER";
        let ed_sig = sign(&ed25519, message);
        let mldsa_sig = sign(&ml_dsa_65, message);

        let mut trailing_ed = ed_der.clone();
        trailing_ed.push(0);
        let mut trailing_mldsa = mldsa_der.clone();
        trailing_mldsa.push(0);

        assert!(check_key_types(&trailing_ed, &mldsa_der).is_err());
        assert!(check_key_types(&ed_der, &trailing_mldsa).is_err());
        assert!(
            verify_dual(message, &trailing_ed, &mldsa_der, &ed_sig, &mldsa_sig).is_err()
        );
        assert!(
            verify_dual(message, &ed_der, &trailing_mldsa, &ed_sig, &mldsa_sig).is_err()
        );
        // The corresponding canonical DER still passes, so the trailing-byte
        // check did not reject valid provisioned material.
        check_key_types(&ed_der, &mldsa_der).expect("canonical keys");
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        let digest = sha256(b"abc").expect("sha256");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let empty = sha256(b"").expect("sha256 empty");
        let hex: String = empty.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn asset_size_and_canonical_hex_are_enforced() {
        let digest = sha256(b"asset").expect("sha256");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

        verify_asset_bytes(b"asset", 5, &hex).expect("size and hash match");
        assert!(verify_asset_bytes(b"asset", 6, &hex).is_err());
        assert!(verify_asset_bytes(b"asset!", 6, &hex).is_err());
        assert!(verify_asset_bytes(b"asset", 5, &hex.to_ascii_uppercase()).is_err());
        assert!(verify_asset_bytes(b"asset", 5, &hex[..62]).is_err());
        assert!(verify_asset_bytes(b"", MAX_ASSET_BYTES + 1, &hex).is_err());
    }

    #[test]
    fn message_size_limit_is_enforced_before_crypto() {
        assert_eq!(MAX_RELEASE_MESSAGE_BYTES, 1024 * 1024);
        assert_eq!(MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES, 4096);
        assert_eq!(MAX_ED25519_PUBLIC_KEY_DER_BYTES, 64);

        let (ed25519, ml_dsa_65) = keypair();
        let oversized = vec![0u8; MAX_RELEASE_MESSAGE_BYTES + 1];
        assert!(
            verify_dual(
                &oversized,
                &public_der(&ed25519),
                &public_der(&ml_dsa_65),
                &[0u8; 64],
                &[0u8; ML_DSA_65_SIGNATURE_BYTES],
            )
            .is_err()
        );
    }
}
