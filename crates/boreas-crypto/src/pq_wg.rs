//! WireGuard-style TLS-less Post-Quantum Authenticated Key Exchange and AEAD transport.
//!
//! Replaces TLS 1.3 on Boreas Hop and E2E links with a lightweight, 1-RTT
//! Noise-style PQ handshake (`X25519 + ML-KEM-768` hybrid ephemeral key
//! agreement, mutual `ML-DSA-65` identity authentication, HKDF-SHA256 key
//! schedule, explicit AEAD key confirmation) followed by stateless counter-nonce
//! `AES-256-GCM` encrypted framing.
//!
//! No X.509 certificate chains are exchanged on the wire, and no TLS state
//! machine or resumption/0-RTT is permitted. Plaintext writes are split into
//! bounded authenticated records.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{Ordering, compiler_fence};

use foreign_types_shared::ForeignTypeRef;
use openssl::derive::Deriver;
use openssl::kdf::{HkdfMode, hkdf};
use openssl::md::Md;
use openssl::pkey::{Id, KeyType, PKey, Private};
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::X509;

use crate::backend::PemIdentity;
use crate::{Aead, HybridGroup, IdentitySignature, Policy, PolicyError, PqWgParameters, Suite};

/// Maximum accepted PEM private-key file size (16 KiB).
pub const MAX_PRIVATE_KEY_PEM_BYTES: u64 = 16 * 1024;
/// Maximum accepted peer SPKI DER size (8 KiB).
pub const MAX_SPKI_DER_BYTES: usize = 8 * 1024;
/// Maximum handshake frame size on the wire (16 KiB).
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 16 * 1024;
/// Maximum plaintext bytes carried in a single AEAD record (16 KiB).
pub const MAX_RECORD_PAYLOAD: usize = 16 * 1024;

const ML_KEM_768_EK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;
const SHARED_SECRET_LEN: usize = 32;
const NONCE_BYTES_LEN: usize = 32;
const SPKI_HASH_LEN: usize = 32;
const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;

const FRAME_MAGIC: &[u8; 4] = b"BWG3";
const MSG_INIT: u8 = 1;
const MSG_RESP: u8 = 2;

// Type byte + big-endian payload length. The record counter is NOT on the
// wire: both peers track it locally and it is the AEAD nonce, so a reordered,
// dropped or replayed record fails authentication instead of being accepted.
const RECORD_HEADER_LEN: usize = 1 + 4;
const RECORD_DATA: u8 = 0x01;
const RECORD_CLOSE: u8 = 0x02;
const RECORD_UPDATE: u8 = 0x03;
// Per-direction, per-epoch GCM limits. Every data record reserves one
// empty authenticated control record (two blocks) for either update or close.
// The quadratic GCM term is approximately 2^-74 per key, not a formal
// multi-user or whole-session bound. Authentication failure poisons the stream.
const MAX_RECORDS_PER_KEY: u64 = 1 << 20;
const MAX_PLAINTEXT_BYTES_PER_KEY: u64 = 1 << 30;
const MAX_AUTH_BLOCKS_PER_KEY: u64 = 1 << 27;
// Limit aggregate exposure as well as individual key use. A stream may use
// at most this many epochs in each direction; reaching it requires a new
// handshake. The sum of per-key estimates is still not a formal proof.
const MAX_EPOCHS_PER_DIRECTION: u64 = 1 << 20;

// BWG3 changes both the marker and authenticated transcript: no fallback to
// BWG1/BWG2. Each direction's keys are independently advanced by an empty,
// old-key-authenticated UPDATE. This deterministic symmetric ratchet supplies
// no post-compromise recovery or new forward secrecy.
const PROTOCOL_NAME: &[u8] = b"BOREAS-PQ-WG-v3-X25519-MLKEM768-MLDSA65-AES256GCM";

/// Domain-separation tag so a Hop handshake can never cross-protocol replay into E2E.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqWgLayer {
    Hop,
    E2e,
}

impl PqWgLayer {
    fn domain_tag(self) -> &'static [u8] {
        match self {
            Self::Hop => b"BOREAS-PQ-WG-LAYER-HOP-v1\0",
            Self::E2e => b"BOREAS-PQ-WG-LAYER-E2E-v1\0",
        }
    }
}

/// Coarse, secret-free errors from the WireGuard-style PQ transport.
#[derive(Debug)]
pub enum PqWgError {
    UnsupportedSuite,
    Pq1024NotEnabled,
    IdentityIo(String),
    IdentityTooLarge { kind: &'static str, limit: u64 },
    WrongLocalKeyType,
    LocalIdentityMismatch,
    OpenSslError,
    UnknownPeer,
    WrongPeerKeyType,
    SignatureVerification,
    Handshake,
    KeyConfirmation,
    NegotiatedMismatch,
}

impl core::fmt::Display for PqWgError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSuite => write!(formatter, "UnsupportedSuite"),
            Self::Pq1024NotEnabled => write!(formatter, "Pq1024NotEnabled"),
            Self::IdentityIo(_) => write!(formatter, "IdentityIo(<redacted>)"),
            Self::IdentityTooLarge { kind, limit } => {
                write!(formatter, "IdentityTooLarge({kind}, {limit})")
            }
            Self::WrongLocalKeyType => write!(formatter, "WrongLocalKeyType"),
            Self::LocalIdentityMismatch => write!(formatter, "LocalIdentityMismatch"),
            Self::OpenSslError => write!(formatter, "OpenSslError"),
            Self::UnknownPeer => write!(formatter, "UnknownPeer"),
            Self::WrongPeerKeyType => write!(formatter, "WrongPeerKeyType"),
            Self::SignatureVerification => write!(formatter, "SignatureVerification"),
            Self::Handshake => write!(formatter, "Handshake"),
            Self::KeyConfirmation => write!(formatter, "KeyConfirmation"),
            Self::NegotiatedMismatch => write!(formatter, "NegotiatedMismatch"),
        }
    }
}

impl std::error::Error for PqWgError {}

impl From<PolicyError> for PqWgError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::Pq1024NotEnabled => Self::Pq1024NotEnabled,
            PolicyError::BackendUnavailable => Self::UnsupportedSuite,
            _ => Self::NegotiatedMismatch,
        }
    }
}

fn require_pq768_policy(policy: Policy) -> Result<Policy, PqWgError> {
    match policy.suite {
        Suite::Pq768 if !policy.allow_pq1024 => Ok(policy),
        Suite::Pq768 => Err(PqWgError::UnsupportedSuite),
        Suite::Pq1024 => Err(PqWgError::Pq1024NotEnabled),
    }
}

fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned mutable reference to a single u8.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn sha256_all(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finish()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
            == 0
}

fn nonzero_u32() -> Result<u32, PqWgError> {
    let mut bytes = [0u8; 4];
    for _ in 0..8 {
        rand_bytes(&mut bytes).map_err(|_| PqWgError::OpenSslError)?;
        let value = u32::from_be_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
    Err(PqWgError::OpenSslError)
}

fn random_32() -> Result<[u8; 32], PqWgError> {
    let mut bytes = [0u8; 32];
    rand_bytes(&mut bytes).map_err(|_| PqWgError::OpenSslError)?;
    Ok(bytes)
}

struct IdentityInner {
    private_key: PKey<Private>,
    public_spki: Vec<u8>,
    spki_hash: [u8; SPKI_HASH_LEN],
}

/// Local ML-DSA-65 identity used for WireGuard-style PQ handshakes.
///
/// Requires only the local ML-DSA-65 private key (`identity.key`); no X.509
/// certificate chain is needed or sent over the wire.
#[derive(Clone)]
pub struct PqWgIdentity {
    inner: Arc<IdentityInner>,
}

impl core::fmt::Debug for PqWgIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PqWgIdentity")
            .field("public_spki_len", &self.inner.public_spki.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl PqWgIdentity {
    /// Load from a local ML-DSA-65 PKCS#8 PEM buffer.
    pub fn from_private_key_pem(private_key_pem: &[u8]) -> Result<Self, PqWgError> {
        if private_key_pem.len() as u64 > MAX_PRIVATE_KEY_PEM_BYTES {
            return Err(PqWgError::IdentityTooLarge {
                kind: "private key",
                limit: MAX_PRIVATE_KEY_PEM_BYTES,
            });
        }
        let private_key =
            PKey::private_key_from_pem(private_key_pem).map_err(|_| PqWgError::WrongLocalKeyType)?;
        if !private_key.is_a(KeyType::ML_DSA_65) {
            return Err(PqWgError::WrongLocalKeyType);
        }
        let public_spki = private_key
            .public_key_to_der()
            .map_err(|_| PqWgError::OpenSslError)?;
        if public_spki.len() > MAX_SPKI_DER_BYTES {
            return Err(PqWgError::LocalIdentityMismatch);
        }
        let spki_hash = sha256_all(&[&public_spki]);
        Ok(Self {
            inner: Arc::new(IdentityInner {
                private_key,
                public_spki,
                spki_hash,
            }),
        })
    }

    /// Load from an ML-DSA-65 PKCS#8 PEM file with a 16 KiB read cap.
    pub fn from_private_key_file(path: impl AsRef<Path>) -> Result<Self, PqWgError> {
        let file =
            std::fs::File::open(path).map_err(|err| PqWgError::IdentityIo(err.to_string()))?;
        let mut bytes = Vec::new();
        file.take(MAX_PRIVATE_KEY_PEM_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| PqWgError::IdentityIo(err.to_string()))?;
        let identity = Self::from_private_key_pem(&bytes);
        zeroize(&mut bytes);
        identity
    }

    /// Construct from an existing `PemIdentity`, checking certificate/key match.
    pub fn from_pem_identity(pem: &PemIdentity) -> Result<Self, PqWgError> {
        let cert = X509::from_pem(&pem.certificate_pem).map_err(|_| PqWgError::OpenSslError)?;
        let cert_spki = cert
            .public_key()
            .map_err(|_| PqWgError::OpenSslError)?
            .public_key_to_der()
            .map_err(|_| PqWgError::OpenSslError)?;
        let identity = Self::from_private_key_pem(&pem.private_key_pem)?;
        if identity.inner.public_spki != cert_spki {
            return Err(PqWgError::LocalIdentityMismatch);
        }
        Ok(identity)
    }

    pub fn public_spki(&self) -> &[u8] {
        &self.inner.public_spki
    }

    pub fn spki_hash(&self) -> &[u8; SPKI_HASH_LEN] {
        &self.inner.spki_hash
    }
}

/// Resolves a peer's 32-byte `SHA256(SPKI)` hint to its trusted DER SPKI bytes.
///
/// The trust store must only return SPKIs from already-verified identities
/// (e.g. `VerifiedNodeIdentity` from dual-signed `NodeIdentity` objects).
pub trait PqWgPeerResolver: Send + Sync {
    fn resolve_spki_hash(&self, spki_hash: &[u8; SPKI_HASH_LEN]) -> Option<Vec<u8>>;
}

/// Simple in-memory SPKI trust store for unit tests and standalone callers.
#[derive(Clone, Default)]
pub struct StaticSpkiResolver {
    spkis: Vec<(Vec<u8>, [u8; SPKI_HASH_LEN])>,
}

impl StaticSpkiResolver {
    pub fn from_spkis(spkis: Vec<Vec<u8>>) -> Self {
        let entries = spkis
            .into_iter()
            .map(|spki| {
                let hash = sha256_all(&[&spki]);
                (spki, hash)
            })
            .collect();
        Self { spkis: entries }
    }
}

impl PqWgPeerResolver for StaticSpkiResolver {
    fn resolve_spki_hash(&self, spki_hash: &[u8; SPKI_HASH_LEN]) -> Option<Vec<u8>> {
        self.spkis
            .iter()
            .find(|(_, hash)| constant_time_eq(hash, spki_hash))
            .map(|(spki, _)| spki.clone())
    }
}

// --- OpenSSL EVP ML-KEM-768 RAII helpers -------------------------------------

struct EvpPkey(*mut openssl_sys::EVP_PKEY);

impl Drop for EvpPkey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an owned EVP_PKEY allocated by OpenSSL.
            unsafe { openssl_sys::EVP_PKEY_free(self.0) };
        }
    }
}

struct EvpPkeyCtx(*mut openssl_sys::EVP_PKEY_CTX);

impl EvpPkeyCtx {
    fn from_name(name: &core::ffi::CStr) -> Result<Self, PqWgError> {
        // SAFETY: `name` is a static NUL-terminated C string.
        let ctx = unsafe {
            openssl_sys::EVP_PKEY_CTX_new_from_name(
                std::ptr::null_mut(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        if ctx.is_null() {
            return Err(PqWgError::OpenSslError);
        }
        Ok(Self(ctx))
    }

    fn from_pkey(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Self, PqWgError> {
        if pkey.is_null() {
            return Err(PqWgError::OpenSslError);
        }
        // SAFETY: `pkey` is a valid EVP_PKEY pointer borrowed for this ctx.
        let ctx = unsafe { openssl_sys::EVP_PKEY_CTX_new(pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(PqWgError::OpenSslError);
        }
        Ok(Self(ctx))
    }
}

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an owned EVP_PKEY_CTX allocated by OpenSSL.
            unsafe { openssl_sys::EVP_PKEY_CTX_free(self.0) };
        }
    }
}

fn mlkem768_keygen() -> Result<(EvpPkey, Vec<u8>), PqWgError> {
    let ctx = EvpPkeyCtx::from_name(c"ML-KEM-768")?;
    // SAFETY: `ctx.0` is a valid keygen-capable EVP_PKEY_CTX.
    if unsafe { openssl_sys::EVP_PKEY_keygen_init(ctx.0) } <= 0 {
        return Err(PqWgError::OpenSslError);
    }
    let mut raw: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
    // SAFETY: `raw` receives a newly allocated EVP_PKEY owned by `EvpPkey`.
    if unsafe { openssl_sys::EVP_PKEY_keygen(ctx.0, &mut raw) } <= 0 || raw.is_null() {
        return Err(PqWgError::OpenSslError);
    }
    let key = EvpPkey(raw);
    let mut ek = vec![0u8; ML_KEM_768_EK_LEN];
    let mut ek_len = ek.len();
    // SAFETY: `key.0` is valid and `ek` has capacity `ML_KEM_768_EK_LEN`.
    if unsafe { openssl_sys::EVP_PKEY_get_raw_public_key(key.0, ek.as_mut_ptr(), &mut ek_len) }
        <= 0
        || ek_len != ML_KEM_768_EK_LEN
    {
        return Err(PqWgError::OpenSslError);
    }
    Ok((key, ek))
}

fn mlkem768_encapsulate(peer_ek: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), PqWgError> {
    if peer_ek.len() != ML_KEM_768_EK_LEN {
        return Err(PqWgError::Handshake);
    }
    let peer_pub = PKey::public_key_from_raw_bytes_ex(None, KeyType::ML_KEM_768, None, peer_ek)
        .map_err(|_| PqWgError::Handshake)?;
    let ctx = EvpPkeyCtx::from_pkey(peer_pub.as_ptr())?;
    // SAFETY: `ctx.0` wraps a valid ML-KEM-768 public key.
    if unsafe { openssl_sys::EVP_PKEY_encapsulate_init(ctx.0, std::ptr::null()) } <= 0 {
        return Err(PqWgError::OpenSslError);
    }
    let mut ct = vec![0u8; ML_KEM_768_CT_LEN];
    let mut ct_len = ct.len();
    let mut ss = [0u8; SHARED_SECRET_LEN];
    let mut ss_len = ss.len();
    // SAFETY: buffers are sized to the fixed ML-KEM-768 ciphertext and shared-secret lengths.
    if unsafe {
        openssl_sys::EVP_PKEY_encapsulate(
            ctx.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            ss.as_mut_ptr(),
            &mut ss_len,
        )
    } <= 0
        || ct_len != ML_KEM_768_CT_LEN
        || ss_len != SHARED_SECRET_LEN
    {
        zeroize(&mut ss);
        return Err(PqWgError::Handshake);
    }
    Ok((ct, ss))
}

fn mlkem768_decapsulate(
    priv_key: &EvpPkey,
    ct: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], PqWgError> {
    if ct.len() != ML_KEM_768_CT_LEN {
        return Err(PqWgError::Handshake);
    }
    let ctx = EvpPkeyCtx::from_pkey(priv_key.0)?;
    // SAFETY: `ctx.0` wraps a valid ML-KEM-768 private key.
    if unsafe { openssl_sys::EVP_PKEY_decapsulate_init(ctx.0, std::ptr::null()) } <= 0 {
        return Err(PqWgError::OpenSslError);
    }
    let mut ss = [0u8; SHARED_SECRET_LEN];
    let mut ss_len = ss.len();
    // SAFETY: `ss` has capacity `SHARED_SECRET_LEN` and `ct` has `ML_KEM_768_CT_LEN` bytes.
    if unsafe {
        openssl_sys::EVP_PKEY_decapsulate(
            ctx.0,
            ss.as_mut_ptr(),
            &mut ss_len,
            ct.as_ptr(),
            ct.len(),
        )
    } <= 0
        || ss_len != SHARED_SECRET_LEN
    {
        zeroize(&mut ss);
        return Err(PqWgError::Handshake);
    }
    Ok(ss)
}

fn x25519_shared_secret(
    local_priv: &PKey<Private>,
    peer_pub_raw: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], PqWgError> {
    if peer_pub_raw.len() != X25519_PUB_LEN {
        return Err(PqWgError::Handshake);
    }
    let peer_pub =
        PKey::public_key_from_raw_bytes(peer_pub_raw, Id::X25519).map_err(|_| PqWgError::Handshake)?;
    let mut deriver = Deriver::new(local_priv).map_err(|_| PqWgError::OpenSslError)?;
    deriver
        .set_peer(&peer_pub)
        .map_err(|_| PqWgError::Handshake)?;
    let mut ss = [0u8; SHARED_SECRET_LEN];
    let len = deriver.derive(&mut ss).map_err(|_| PqWgError::Handshake)?;
    if len != SHARED_SECRET_LEN || ss.iter().fold(0u8, |acc, &b| acc | b) == 0 {
        zeroize(&mut ss);
        return Err(PqWgError::Handshake);
    }
    Ok(ss)
}

type SessionKeys = ([u8; AEAD_KEY_LEN], [u8; AEAD_KEY_LEN], [u8; AEAD_KEY_LEN]);

fn derive_session_keys(
    ck: &[u8; 32],
    h: &[u8; 32],
    ss_ecdh: &[u8; SHARED_SECRET_LEN],
    ss_pq: &[u8; SHARED_SECRET_LEN],
) -> Result<SessionKeys, PqWgError> {
    let mut ikm = [0u8; SHARED_SECRET_LEN * 2];
    ikm[..SHARED_SECRET_LEN].copy_from_slice(ss_ecdh);
    ikm[SHARED_SECRET_LEN..].copy_from_slice(ss_pq);

    let mut info = [0u8; 22 + 32];
    info[..22].copy_from_slice(b"BOREAS-PQ-WG-KEYS-v1\0\0");
    info[22..].copy_from_slice(h);

    let mut out = [0u8; AEAD_KEY_LEN * 3];
    let res = hkdf(
        Md::sha256(),
        &ikm,
        Some(ck),
        Some(&info),
        HkdfMode::ExtractAndExpand,
        None,
        &mut out,
    );
    zeroize(&mut ikm);
    if res.is_err() {
        zeroize(&mut out);
        return Err(PqWgError::OpenSslError);
    }

    let mut k_i_to_r = [0u8; AEAD_KEY_LEN];
    let mut k_r_to_i = [0u8; AEAD_KEY_LEN];
    let mut k_confirm = [0u8; AEAD_KEY_LEN];
    k_i_to_r.copy_from_slice(&out[..32]);
    k_r_to_i.copy_from_slice(&out[32..64]);
    k_confirm.copy_from_slice(&out[64..96]);
    zeroize(&mut out);
    Ok((k_i_to_r, k_r_to_i, k_confirm))
}

fn make_nonce(counter: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn aead_seal_into(
    key: &[u8; AEAD_KEY_LEN],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
    out_ct_and_tag: &mut [u8],
) -> Result<usize, PqWgError> {
    if out_ct_and_tag.len() < plaintext.len() + AEAD_TAG_LEN {
        return Err(PqWgError::OpenSslError);
    }
    let nonce = make_nonce(counter);
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(&nonce))
        .map_err(|_| PqWgError::OpenSslError)?;
    crypter
        .aad_update(aad)
        .map_err(|_| PqWgError::OpenSslError)?;
    let mut n = crypter
        .update(plaintext, out_ct_and_tag)
        .map_err(|_| PqWgError::OpenSslError)?;
    n += crypter
        .finalize(&mut out_ct_and_tag[n..])
        .map_err(|_| PqWgError::OpenSslError)?;
    if n != plaintext.len() {
        return Err(PqWgError::OpenSslError);
    }
    crypter
        .get_tag(&mut out_ct_and_tag[n..n + AEAD_TAG_LEN])
        .map_err(|_| PqWgError::OpenSslError)?;
    Ok(n + AEAD_TAG_LEN)
}

fn aead_open_into(
    key: &[u8; AEAD_KEY_LEN],
    counter: u64,
    aad: &[u8],
    ct_and_tag: &[u8],
    out_plaintext: &mut [u8],
) -> Result<usize, PqWgError> {
    if ct_and_tag.len() < AEAD_TAG_LEN {
        return Err(PqWgError::KeyConfirmation);
    }
    let ct_len = ct_and_tag.len() - AEAD_TAG_LEN;
    if out_plaintext.len() < ct_len + 1 {
        return Err(PqWgError::OpenSslError);
    }
    let (ct, tag) = ct_and_tag.split_at(ct_len);
    let nonce = make_nonce(counter);
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(&nonce))
        .map_err(|_| PqWgError::OpenSslError)?;
    crypter
        .aad_update(aad)
        .map_err(|_| PqWgError::OpenSslError)?;
    let mut n = match crypter.update(ct, out_plaintext) {
        Ok(n) => n,
        Err(_) => {
            zeroize(out_plaintext);
            return Err(PqWgError::KeyConfirmation);
        }
    };
    if crypter.set_tag(tag).is_err() {
        zeroize(out_plaintext);
        return Err(PqWgError::KeyConfirmation);
    }
    match crypter.finalize(&mut out_plaintext[n..]) {
        Ok(final_len) => n += final_len,
        Err(_) => {
            // OpenSSL may have written unauthenticated plaintext during update.
            zeroize(out_plaintext);
            return Err(PqWgError::KeyConfirmation);
        }
    }
    Ok(n)
}

fn sign_mldsa65(key: &PKey<Private>, domain: &[u8], transcript: &[u8; 32]) -> Result<Vec<u8>, PqWgError> {
    let mut msg = Vec::with_capacity(domain.len() + transcript.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(transcript);
    let mut signer = Signer::new_without_digest(key).map_err(|_| PqWgError::OpenSslError)?;
    signer
        .sign_oneshot_to_vec(&msg)
        .map_err(|_| PqWgError::OpenSslError)
}

fn verify_mldsa65(
    spki_der: &[u8],
    domain: &[u8],
    transcript: &[u8; 32],
    signature: &[u8],
) -> Result<(), PqWgError> {
    let peer_pub = PKey::public_key_from_der(spki_der).map_err(|_| PqWgError::WrongPeerKeyType)?;
    if !peer_pub.is_a(KeyType::ML_DSA_65) {
        return Err(PqWgError::WrongPeerKeyType);
    }
    let mut msg = Vec::with_capacity(domain.len() + transcript.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(transcript);
    let mut verifier =
        Verifier::new_without_digest(&peer_pub).map_err(|_| PqWgError::OpenSslError)?;
    if verifier
        .verify_oneshot(signature, &msg)
        .map_err(|_| PqWgError::SignatureVerification)?
    {
        Ok(())
    } else {
        Err(PqWgError::SignatureVerification)
    }
}

fn write_handshake_frame<S: Write>(stream: &mut S, body: &[u8]) -> Result<(), PqWgError> {
    let len = u32::try_from(body.len()).map_err(|_| PqWgError::Handshake)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|_| PqWgError::Handshake)
}

fn read_handshake_frame<S: Read>(stream: &mut S) -> Result<Vec<u8>, PqWgError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|_| PqWgError::Handshake)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(PqWgError::Handshake);
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|_| PqWgError::Handshake)?;
    Ok(body)
}

fn confirm_seal(
    k_confirm: &[u8; AEAD_KEY_LEN],
    counter: u64,
    label: &[u8],
    h: &[u8; 32],
) -> Result<[u8; AEAD_TAG_LEN], PqWgError> {
    let mut aad = Vec::with_capacity(label.len() + 32);
    aad.extend_from_slice(label);
    aad.extend_from_slice(h);
    let mut tag = [0u8; AEAD_TAG_LEN];
    let written = aead_seal_into(k_confirm, counter, &aad, &[], &mut tag)?;
    if written != AEAD_TAG_LEN {
        return Err(PqWgError::OpenSslError);
    }
    Ok(tag)
}

fn confirm_verify(
    k_confirm: &[u8; AEAD_KEY_LEN],
    counter: u64,
    label: &[u8],
    h: &[u8; 32],
    tag: &[u8],
) -> Result<(), PqWgError> {
    let mut aad = Vec::with_capacity(label.len() + 32);
    aad.extend_from_slice(label);
    aad.extend_from_slice(h);
    let mut dummy = [0u8; 16];
    let n = aead_open_into(k_confirm, counter, &aad, tag, &mut dummy)?;
    if n != 0 {
        return Err(PqWgError::KeyConfirmation);
    }
    Ok(())
}

/// WireGuard-style TLS-less PQ client connector.
pub struct PqWgConnector {
    identity: PqWgIdentity,
    resolver: Arc<dyn PqWgPeerResolver>,
    policy: Policy,
    layer: PqWgLayer,
}

impl PqWgConnector {
    pub fn new(
        identity: PqWgIdentity,
        resolver: Arc<dyn PqWgPeerResolver>,
        policy: Policy,
        layer: PqWgLayer,
    ) -> Result<Self, PqWgError> {
        let policy = require_pq768_policy(policy)?;
        Ok(Self {
            identity,
            resolver,
            policy,
            layer,
        })
    }

    pub fn connect<S: Read + Write>(
        &self,
        mut transport: S,
    ) -> Result<PqWgStream<S>, PqWgError> {
        let ck = sha256_all(&[PROTOCOL_NAME]);
        let mut h = sha256_all(&[&ck, self.layer.domain_tag()]);

        let e_i_priv = PKey::generate_x25519().map_err(|_| PqWgError::OpenSslError)?;
        let e_i_pub = e_i_priv
            .raw_public_key()
            .map_err(|_| PqWgError::OpenSslError)?;
        if e_i_pub.len() != X25519_PUB_LEN {
            return Err(PqWgError::OpenSslError);
        }
        let (pq_i_priv, pq_i_ek) = mlkem768_keygen()?;
        let sender_index = nonzero_u32()?;
        let nonce_i = random_32()?;

        // msg1_body = BWG3 | 1 | sender_index(4) | nonce_i(32) | e_i_pub(32) | ek_len(2) | ek(1184) | init_spki_hash(32)
        let mut msg1_body = Vec::with_capacity(
            4 + 1 + 4 + NONCE_BYTES_LEN + X25519_PUB_LEN + 2 + ML_KEM_768_EK_LEN + SPKI_HASH_LEN,
        );
        msg1_body.extend_from_slice(FRAME_MAGIC);
        msg1_body.push(MSG_INIT);
        msg1_body.extend_from_slice(&sender_index.to_be_bytes());
        msg1_body.extend_from_slice(&nonce_i);
        msg1_body.extend_from_slice(&e_i_pub);
        msg1_body.extend_from_slice(&(ML_KEM_768_EK_LEN as u16).to_be_bytes());
        msg1_body.extend_from_slice(&pq_i_ek);
        msg1_body.extend_from_slice(self.identity.spki_hash());

        h = sha256_all(&[&h, &msg1_body]);
        let sig_i = sign_mldsa65(
            &self.identity.inner.private_key,
            b"BOREAS-PQ-WG-INIT-SIG-v1\0",
            &h,
        )?;
        let sig_i_len = u16::try_from(sig_i.len()).map_err(|_| PqWgError::Handshake)?;
        h = sha256_all(&[&h, &sig_i_len.to_be_bytes(), &sig_i]);

        let mut msg1 = Vec::with_capacity(msg1_body.len() + 2 + sig_i.len());
        msg1.extend_from_slice(&msg1_body);
        msg1.extend_from_slice(&sig_i_len.to_be_bytes());
        msg1.extend_from_slice(&sig_i);
        write_handshake_frame(&mut transport, &msg1)?;

        // Read Message 2:
        // msg2_body = BWG3(4) | 2(1) | receiver_index(4) | sender_index(4) | nonce_r(32) | e_r_pub(32) | ct_len(2) | ct(1088) | resp_spki_hash(32)
        let msg2 = read_handshake_frame(&mut transport)?;
        let msg2_body_len = 4
            + 1
            + 4
            + 4
            + NONCE_BYTES_LEN
            + X25519_PUB_LEN
            + 2
            + ML_KEM_768_CT_LEN
            + SPKI_HASH_LEN;
        if msg2.len() < msg2_body_len + 2 + AEAD_TAG_LEN {
            return Err(PqWgError::Handshake);
        }
        let (msg2_body, rest) = msg2.split_at(msg2_body_len);
        if &msg2_body[..4] != FRAME_MAGIC || msg2_body[4] != MSG_RESP {
            return Err(PqWgError::Handshake);
        }
        let receiver_index = u32::from_be_bytes(
            msg2_body[5..9]
                .try_into()
                .map_err(|_| PqWgError::Handshake)?,
        );
        let echoed_sender = u32::from_be_bytes(
            msg2_body[9..13]
                .try_into()
                .map_err(|_| PqWgError::Handshake)?,
        );
        if receiver_index == 0 || echoed_sender != sender_index {
            return Err(PqWgError::Handshake);
        }
        let e_r_pub = &msg2_body[13 + NONCE_BYTES_LEN..13 + NONCE_BYTES_LEN + X25519_PUB_LEN];
        let ct_len_offset = 13 + NONCE_BYTES_LEN + X25519_PUB_LEN;
        let ct_len = u16::from_be_bytes([msg2_body[ct_len_offset], msg2_body[ct_len_offset + 1]]) as usize;
        if ct_len != ML_KEM_768_CT_LEN {
            return Err(PqWgError::Handshake);
        }
        let pq_ct = &msg2_body[ct_len_offset + 2..ct_len_offset + 2 + ML_KEM_768_CT_LEN];
        let resp_spki_hash: [u8; SPKI_HASH_LEN] = msg2_body[ct_len_offset + 2 + ML_KEM_768_CT_LEN..]
            .try_into()
            .map_err(|_| PqWgError::Handshake)?;

        let sig_r_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() != 2 + sig_r_len + AEAD_TAG_LEN {
            return Err(PqWgError::Handshake);
        }
        let sig_r = &rest[2..2 + sig_r_len];
        let resp_confirm_tag = &rest[2 + sig_r_len..];

        let peer_spki = self
            .resolver
            .resolve_spki_hash(&resp_spki_hash)
            .ok_or(PqWgError::UnknownPeer)?;
        if !constant_time_eq(&sha256_all(&[&peer_spki]), &resp_spki_hash) {
            return Err(PqWgError::UnknownPeer);
        }

        h = sha256_all(&[&h, msg2_body]);
        verify_mldsa65(&peer_spki, b"BOREAS-PQ-WG-RESP-SIG-v1\0", &h, sig_r)?;
        h = sha256_all(&[&h, &(sig_r_len as u16).to_be_bytes(), sig_r]);

        let mut ss_ecdh = x25519_shared_secret(&e_i_priv, e_r_pub)?;
        let mut ss_pq = match mlkem768_decapsulate(&pq_i_priv, pq_ct) {
            Ok(ss) => ss,
            Err(err) => {
                zeroize(&mut ss_ecdh);
                return Err(err);
            }
        };
        let keys_res = derive_session_keys(&ck, &h, &ss_ecdh, &ss_pq);
        zeroize(&mut ss_ecdh);
        zeroize(&mut ss_pq);
        let (mut k_i_to_r, mut k_r_to_i, mut k_confirm) = keys_res?;

        if let Err(err) = confirm_verify(
            &k_confirm,
            1,
            b"BOREAS-PQ-WG-RESP-CONFIRM\0",
            &h,
            resp_confirm_tag,
        ) {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            zeroize(&mut k_confirm);
            return Err(err);
        }

        let init_confirm_tag = confirm_seal(&k_confirm, 2, b"BOREAS-PQ-WG-INIT-CONFIRM\0", &h);
        zeroize(&mut k_confirm);
        let init_confirm_tag = match init_confirm_tag {
            Ok(tag) => tag,
            Err(err) => {
                zeroize(&mut k_i_to_r);
                zeroize(&mut k_r_to_i);
                return Err(err);
            }
        };
        if transport
            .write_all(&init_confirm_tag)
            .and_then(|()| transport.flush())
            .is_err()
        {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            return Err(PqWgError::Handshake);
        }

        let negotiated = PqWgParameters {
            group: HybridGroup::X25519MlKem768,
            peer_signature: IdentitySignature::MlDsa65,
            aead: Aead::Aes256GcmSha384,
            resumed: false,
            zero_rtt: false,
            tls_free: true,
        };
        if let Err(err) = self.policy.validate_pq_wg(negotiated) {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            return Err(err.into());
        }

        Ok(PqWgStream::new(
            transport, k_i_to_r, k_r_to_i, peer_spki, negotiated, true,
        ))
    }
}

/// WireGuard-style TLS-less PQ server acceptor.
pub struct PqWgAcceptor {
    identity: PqWgIdentity,
    resolver: Arc<dyn PqWgPeerResolver>,
    policy: Policy,
    layer: PqWgLayer,
}

impl PqWgAcceptor {
    pub fn new(
        identity: PqWgIdentity,
        resolver: Arc<dyn PqWgPeerResolver>,
        policy: Policy,
        layer: PqWgLayer,
    ) -> Result<Self, PqWgError> {
        let policy = require_pq768_policy(policy)?;
        Ok(Self {
            identity,
            resolver,
            policy,
            layer,
        })
    }

    pub fn accept<S: Read + Write>(
        &self,
        mut transport: S,
    ) -> Result<PqWgStream<S>, PqWgError> {
        let ck = sha256_all(&[PROTOCOL_NAME]);
        let mut h = sha256_all(&[&ck, self.layer.domain_tag()]);

        let msg1 = read_handshake_frame(&mut transport)?;
        let msg1_body_len = 4 + 1 + 4 + NONCE_BYTES_LEN + X25519_PUB_LEN + 2 + ML_KEM_768_EK_LEN + SPKI_HASH_LEN;
        if msg1.len() < msg1_body_len + 2 {
            return Err(PqWgError::Handshake);
        }
        let (msg1_body, rest) = msg1.split_at(msg1_body_len);
        if &msg1_body[..4] != FRAME_MAGIC || msg1_body[4] != MSG_INIT {
            return Err(PqWgError::Handshake);
        }
        let sender_index = u32::from_be_bytes(
            msg1_body[5..9]
                .try_into()
                .map_err(|_| PqWgError::Handshake)?,
        );
        if sender_index == 0 {
            return Err(PqWgError::Handshake);
        }
        let e_i_pub = &msg1_body[9 + NONCE_BYTES_LEN..9 + NONCE_BYTES_LEN + X25519_PUB_LEN];
        let ek_len_offset = 9 + NONCE_BYTES_LEN + X25519_PUB_LEN;
        let ek_len = u16::from_be_bytes([msg1_body[ek_len_offset], msg1_body[ek_len_offset + 1]]) as usize;
        if ek_len != ML_KEM_768_EK_LEN {
            return Err(PqWgError::Handshake);
        }
        let pq_i_ek = &msg1_body[ek_len_offset + 2..ek_len_offset + 2 + ML_KEM_768_EK_LEN];
        let init_spki_hash: [u8; SPKI_HASH_LEN] = msg1_body[ek_len_offset + 2 + ML_KEM_768_EK_LEN..]
            .try_into()
            .map_err(|_| PqWgError::Handshake)?;

        let sig_i_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() != 2 + sig_i_len {
            return Err(PqWgError::Handshake);
        }
        let sig_i = &rest[2..];

        let peer_spki = self
            .resolver
            .resolve_spki_hash(&init_spki_hash)
            .ok_or(PqWgError::UnknownPeer)?;
        if !constant_time_eq(&sha256_all(&[&peer_spki]), &init_spki_hash) {
            return Err(PqWgError::UnknownPeer);
        }

        h = sha256_all(&[&h, msg1_body]);
        verify_mldsa65(&peer_spki, b"BOREAS-PQ-WG-INIT-SIG-v1\0", &h, sig_i)?;
        h = sha256_all(&[&h, &(sig_i_len as u16).to_be_bytes(), sig_i]);

        let e_r_priv = PKey::generate_x25519().map_err(|_| PqWgError::OpenSslError)?;
        let e_r_pub = e_r_priv
            .raw_public_key()
            .map_err(|_| PqWgError::OpenSslError)?;
        if e_r_pub.len() != X25519_PUB_LEN {
            return Err(PqWgError::OpenSslError);
        }

        let mut ss_ecdh = x25519_shared_secret(&e_r_priv, e_i_pub)?;
        let (pq_ct, mut ss_pq) = match mlkem768_encapsulate(pq_i_ek) {
            Ok(pair) => pair,
            Err(err) => {
                zeroize(&mut ss_ecdh);
                return Err(err);
            }
        };

        let receiver_index = match nonzero_u32() {
            Ok(idx) => idx,
            Err(err) => {
                zeroize(&mut ss_ecdh);
                zeroize(&mut ss_pq);
                return Err(err);
            }
        };
        let nonce_r = match random_32() {
            Ok(n) => n,
            Err(err) => {
                zeroize(&mut ss_ecdh);
                zeroize(&mut ss_pq);
                return Err(err);
            }
        };

        let mut msg2_body =
            Vec::with_capacity(4 + 1 + 4 + 4 + NONCE_BYTES_LEN + X25519_PUB_LEN + 2 + ML_KEM_768_CT_LEN + SPKI_HASH_LEN);
        msg2_body.extend_from_slice(FRAME_MAGIC);
        msg2_body.push(MSG_RESP);
        msg2_body.extend_from_slice(&receiver_index.to_be_bytes());
        msg2_body.extend_from_slice(&sender_index.to_be_bytes());
        msg2_body.extend_from_slice(&nonce_r);
        msg2_body.extend_from_slice(&e_r_pub);
        msg2_body.extend_from_slice(&(ML_KEM_768_CT_LEN as u16).to_be_bytes());
        msg2_body.extend_from_slice(&pq_ct);
        msg2_body.extend_from_slice(self.identity.spki_hash());

        h = sha256_all(&[&h, &msg2_body]);
        let sig_r = match sign_mldsa65(
            &self.identity.inner.private_key,
            b"BOREAS-PQ-WG-RESP-SIG-v1\0",
            &h,
        ) {
            Ok(sig) => sig,
            Err(err) => {
                zeroize(&mut ss_ecdh);
                zeroize(&mut ss_pq);
                return Err(err);
            }
        };
        let sig_r_len = u16::try_from(sig_r.len()).map_err(|_| PqWgError::Handshake)?;
        h = sha256_all(&[&h, &sig_r_len.to_be_bytes(), &sig_r]);

        let keys_res = derive_session_keys(&ck, &h, &ss_ecdh, &ss_pq);
        zeroize(&mut ss_ecdh);
        zeroize(&mut ss_pq);
        let (mut k_i_to_r, mut k_r_to_i, mut k_confirm) = keys_res?;

        let resp_confirm_tag = match confirm_seal(&k_confirm, 1, b"BOREAS-PQ-WG-RESP-CONFIRM\0", &h) {
            Ok(tag) => tag,
            Err(err) => {
                zeroize(&mut k_i_to_r);
                zeroize(&mut k_r_to_i);
                zeroize(&mut k_confirm);
                return Err(err);
            }
        };

        let mut msg2 = Vec::with_capacity(msg2_body.len() + 2 + sig_r.len() + AEAD_TAG_LEN);
        msg2.extend_from_slice(&msg2_body);
        msg2.extend_from_slice(&sig_r_len.to_be_bytes());
        msg2.extend_from_slice(&sig_r);
        msg2.extend_from_slice(&resp_confirm_tag);
        if write_handshake_frame(&mut transport, &msg2).is_err() {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            zeroize(&mut k_confirm);
            return Err(PqWgError::Handshake);
        }

        let mut init_confirm_tag = [0u8; AEAD_TAG_LEN];
        if transport.read_exact(&mut init_confirm_tag).is_err() {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            zeroize(&mut k_confirm);
            return Err(PqWgError::Handshake);
        }
        let verified = confirm_verify(
            &k_confirm,
            2,
            b"BOREAS-PQ-WG-INIT-CONFIRM\0",
            &h,
            &init_confirm_tag,
        );
        zeroize(&mut k_confirm);
        if let Err(err) = verified {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            return Err(err);
        }

        let negotiated = PqWgParameters {
            group: HybridGroup::X25519MlKem768,
            peer_signature: IdentitySignature::MlDsa65,
            aead: Aead::Aes256GcmSha384,
            resumed: false,
            zero_rtt: false,
            tls_free: true,
        };
        if let Err(err) = self.policy.validate_pq_wg(negotiated) {
            zeroize(&mut k_i_to_r);
            zeroize(&mut k_r_to_i);
            return Err(err.into());
        }

        Ok(PqWgStream::new(
            transport, k_r_to_i, k_i_to_r, peer_spki, negotiated, false,
        ))
    }
}

#[derive(Clone, Copy)]
struct KeyLimits {
    records: u64,
    bytes: u64,
    blocks: u64,
}

impl Default for KeyLimits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS_PER_KEY,
            bytes: MAX_PLAINTEXT_BYTES_PER_KEY,
            blocks: MAX_AUTH_BLOCKS_PER_KEY,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct KeyUsage {
    records: u64,
    bytes: u64,
    blocks: u64,
}

impl KeyUsage {
    // Header AAD occupies one block, plus padded ciphertext and a length block.
    // Data must leave room for one empty control record. Calculate on a copy so
    // a failed capacity check never consumes a nonce or changes the state.
    fn charge(&mut self, payload_len: usize, is_data: bool, limits: KeyLimits) -> io::Result<u64> {
        let bytes = u64::try_from(payload_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pq-wg key usage exceeded"))?;
        let blocks = bytes.div_ceil(16).checked_add(2);
        let next_records = self.records.checked_add(1);
        let next_bytes = self.bytes.checked_add(bytes);
        let next_blocks = blocks.and_then(|n| self.blocks.checked_add(n));
        let reserve = u64::from(is_data);
        match (
            next_records,
            next_bytes,
            next_blocks,
            limits.records.checked_sub(reserve),
            limits.blocks.checked_sub(2 * reserve),
        ) {
            (
                Some(records),
                Some(total_bytes),
                Some(total_blocks),
                Some(max_records),
                Some(max_blocks),
            ) if records <= max_records
                && total_bytes <= limits.bytes
                && total_blocks <= max_blocks =>
            {
                self.records = records;
                self.bytes = total_bytes;
                self.blocks = total_blocks;
                Ok(records)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pq-wg key usage exceeded",
            )),
        }
    }
}

// Role-specific labels bind the ratchet to the wire direction, including in
// the unlikely event that the two handshake traffic keys happen to coincide.
fn advance_key(key: &mut [u8; AEAD_KEY_LEN], direction: u8, epoch: &mut u64) -> io::Result<()> {
    let next = epoch
        .checked_add(1)
        .filter(|&next| next < MAX_EPOCHS_PER_DIRECTION)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pq-wg epoch exhausted"))?;
    let mut info = Vec::with_capacity(48);
    info.extend_from_slice(b"BOREAS-PQ-WG-v3-TRAFFIC-UPDATE\0");
    info.push(direction);
    info.extend_from_slice(&next.to_be_bytes());
    let mut new_key = [0u8; AEAD_KEY_LEN];
    let result = hkdf(
        Md::sha256(),
        key,
        None,
        Some(&info),
        HkdfMode::ExtractAndExpand,
        None,
        &mut new_key,
    );
    if result.is_err() {
        zeroize(&mut new_key);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pq-wg key update failed",
        ));
    }
    zeroize(key);
    key.copy_from_slice(&new_key);
    zeroize(&mut new_key);
    *epoch = next;
    Ok(())
}

/// Authenticated WireGuard-style AES-256-GCM encrypted byte stream.
pub struct PqWgStream<S> {
    inner: S,
    send_key: [u8; AEAD_KEY_LEN],
    recv_key: [u8; AEAD_KEY_LEN],
    send_usage: KeyUsage,
    recv_usage: KeyUsage,
    limits: KeyLimits,
    send_epoch: u64,
    recv_epoch: u64,
    send_direction: u8,
    recv_direction: u8,
    peer_spki: Vec<u8>,
    negotiated: PqWgParameters,
    // Reusable buffers to avoid per-packet heap allocations on the hot path.
    tx_buf: Vec<u8>,
    tx_pos: usize,
    tx_len: usize,
    rx_raw: Vec<u8>,
    rx_raw_len: usize,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
    rx_plain_len: usize,
    peer_closed: bool,
    close_started: bool,
    local_closed: bool,
    failed: bool,
}

impl<S> Drop for PqWgStream<S> {
    fn drop(&mut self) {
        zeroize(&mut self.send_key);
        zeroize(&mut self.recv_key);
        zeroize(&mut self.rx_plain);
    }
}

impl<S> PqWgStream<S> {
    fn new(
        inner: S,
        send_key: [u8; AEAD_KEY_LEN],
        recv_key: [u8; AEAD_KEY_LEN],
        peer_spki: Vec<u8>,
        negotiated: PqWgParameters,
        is_initiator: bool,
    ) -> Self {
        Self {
            inner,
            send_key,
            recv_key,
            send_usage: KeyUsage::default(),
            recv_usage: KeyUsage::default(),
            limits: KeyLimits::default(),
            send_epoch: 0,
            recv_epoch: 0,
            send_direction: if is_initiator { 0 } else { 1 },
            recv_direction: if is_initiator { 1 } else { 0 },
            peer_spki,
            negotiated,
            tx_buf: vec![0u8; RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD + AEAD_TAG_LEN],
            tx_pos: 0,
            tx_len: 0,
            rx_raw: vec![0u8; RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD + AEAD_TAG_LEN],
            rx_raw_len: 0,
            rx_plain: vec![0u8; MAX_RECORD_PAYLOAD + 16],
            rx_plain_pos: 0,
            rx_plain_len: 0,
            peer_closed: false,
            close_started: false,
            local_closed: false,
            failed: false,
        }
    }

    pub fn negotiated(&self) -> PqWgParameters {
        self.negotiated
    }

    pub fn peer_spki(&self) -> &[u8] {
        &self.peer_spki
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Whether an encrypted frame still needs transport write readiness/flush.
    /// A successful `write` can leave such a frame queued after WouldBlock.
    pub fn has_pending_output(&self) -> bool {
        self.tx_pos < self.tx_len
    }

    pub fn has_buffered_input(&self) -> bool {
        self.rx_plain_pos < self.rx_plain_len || self.peer_closed
    }
}

impl<S: Read + Write> PqWgStream<S> {
    /// Attempt to send any buffered record; retry on WouldBlock or TimedOut.
    pub fn flush_pending_output(&mut self) -> io::Result<()> {
        self.flush()
    }

    fn drain_tx(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pq-wg stream poisoned"));
        }
        while self.tx_pos < self.tx_len {
            match self.inner.write(&self.tx_buf[self.tx_pos..self.tx_len]) {
                Ok(0) => {
                    self.failed = true;
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "pq-wg transport write zero"));
                }
                Ok(n) => self.tx_pos += n,
                Err(err) => {
                    if !matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) {
                        self.failed = true;
                    }
                    return Err(err);
                }
            }
        }
        self.tx_pos = 0;
        self.tx_len = 0;
        Ok(())
    }

    fn send_record(&mut self, record_type: u8, payload: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pq-wg stream poisoned",
            ));
        }
        self.drain_tx()?;
        // Reserve the nonce and budget before encryption or any transport write.
        let counter =
            self.send_usage
                .charge(payload.len(), record_type == RECORD_DATA, self.limits)?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;
        self.tx_buf[0] = record_type;
        self.tx_buf[1..RECORD_HEADER_LEN].copy_from_slice(&payload_len.to_be_bytes());
        let (aad, rest) = self.tx_buf.split_at_mut(RECORD_HEADER_LEN);
        let written =
            aead_seal_into(&self.send_key, counter, aad, payload, rest).map_err(|_| {
                self.failed = true;
                io::Error::new(io::ErrorKind::InvalidData, "pq-wg encrypt failed")
            })?;
        self.tx_len = RECORD_HEADER_LEN + written;
        Ok(())
    }

    // If data will not fit with the reserved control slot, queue UPDATE under
    // the old key and install the new key exactly once. The queued ciphertext
    // must drain before any new-key data can be queued, even after WouldBlock.
    fn prepare_data(&mut self, len: usize) -> io::Result<()> {
        let mut candidate = self.send_usage;
        if candidate.charge(len, true, self.limits).is_ok() {
            return Ok(());
        }
        // Do not emit an update if this record cannot fit even in a fresh epoch.
        KeyUsage::default().charge(len, true, self.limits)?;
        if self.send_epoch >= MAX_EPOCHS_PER_DIRECTION - 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pq-wg epoch exhausted",
            ));
        }
        self.send_record(RECORD_UPDATE, &[])?;
        if let Err(err) = advance_key(
            &mut self.send_key,
            self.send_direction,
            &mut self.send_epoch,
        ) {
            self.failed = true;
            return Err(err);
        }
        self.send_usage = KeyUsage::default();
        Ok(())
    }

    /// Send an authenticated close frame so the peer distinguishes planned
    /// closure from bare transport EOF or reset. Once called, further writes
    /// are rejected, even if pending output makes close return a retryable error.
    pub fn close_notify(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pq-wg stream poisoned"));
        }
        self.close_started = true;
        if !self.local_closed {
            self.send_record(RECORD_CLOSE, &[])?;
            self.local_closed = true;
        }
        self.flush()
    }

    /// Read plaintext, returning `Ok(0)` only after an authenticated close frame.
    pub fn read_with_authenticated_eof(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_inner(out)
    }

    fn read_inner(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pq-wg stream poisoned",
            ));
        }
        // Bound work for a peer sending many authenticated updates in a row.
        // Interrupted is retryable and lets the caller yield between batches.
        let mut updates = 0;
        loop {
            if self.rx_plain_pos < self.rx_plain_len {
                let avail = self.rx_plain_len - self.rx_plain_pos;
                let take = avail.min(out.len());
                out[..take].copy_from_slice(&self.rx_plain[self.rx_plain_pos..self.rx_plain_pos + take]);
                self.rx_plain_pos += take;
                if self.rx_plain_pos == self.rx_plain_len {
                    self.rx_plain_pos = 0;
                    self.rx_plain_len = 0;
                }
                return Ok(take);
            }
            if self.peer_closed {
                return Ok(0);
            }
            let old_epoch = self.recv_epoch;
            self.read_next_record()?;
            if self.recv_epoch != old_epoch {
                updates += 1;
                if updates == 16 {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
            }
        }
    }

    fn read_next_record(&mut self) -> io::Result<()> {
        while self.rx_raw_len < RECORD_HEADER_LEN {
            match self.inner.read(&mut self.rx_raw[self.rx_raw_len..RECORD_HEADER_LEN]) {
                Ok(0) => {
                    self.failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "transport closed without authenticated close",
                    ));
                }
                Ok(n) => self.rx_raw_len += n,
                Err(err) => {
                    if !matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) {
                        self.failed = true;
                    }
                    return Err(err);
                }
            }
        }

        let record_type = self.rx_raw[0];
        let payload_len = u32::from_be_bytes(
            self.rx_raw[1..RECORD_HEADER_LEN]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad header"))?,
        ) as usize;
        let valid_header = match record_type {
            RECORD_DATA => payload_len > 0 && payload_len <= MAX_RECORD_PAYLOAD,
            RECORD_CLOSE | RECORD_UPDATE => payload_len == 0,
            _ => false,
        };
        if !valid_header {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pq-wg record header",
            ));
        }
        // Reserve budget before decrypting. Transient I/O errors may resume the
        // same buffered record, so charge only once after it is fully read.
        let total_len = RECORD_HEADER_LEN + payload_len + AEAD_TAG_LEN;
        while self.rx_raw_len < total_len {
            match self.inner.read(&mut self.rx_raw[self.rx_raw_len..total_len]) {
                Ok(0) => {
                    self.failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated pq-wg record",
                    ));
                }
                Ok(n) => self.rx_raw_len += n,
                Err(err) => {
                    if !matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) {
                        self.failed = true;
                    }
                    return Err(err);
                }
            }
        }

        // Empty epochs carry no data and can never be generated by an honest
        // sender. Reject them to prevent cheap authenticated update floods.
        if record_type == RECORD_UPDATE && self.recv_usage.records == 0 {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty pq-wg epoch",
            ));
        }
        let counter = self
            .recv_usage
            .charge(payload_len, record_type == RECORD_DATA, self.limits)
            .inspect_err(|_| {
                self.failed = true;
            })?;
        let (aad, ct_and_tag) = self.rx_raw[..total_len].split_at(RECORD_HEADER_LEN);
        let plain_len = aead_open_into(
            &self.recv_key,
            counter,
            aad,
            ct_and_tag,
            &mut self.rx_plain,
        )
        .map_err(|_| {
            self.failed = true;
            io::Error::new(io::ErrorKind::InvalidData, "pq-wg record authentication failed")
        })?;
        self.rx_raw_len = 0;

        if plain_len != payload_len {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pq-wg plaintext length mismatch",
            ));
        }
        if record_type == RECORD_CLOSE {
            self.peer_closed = true;
            return Ok(());
        }
        if record_type == RECORD_UPDATE {
            if let Err(err) = advance_key(
                &mut self.recv_key,
                self.recv_direction,
                &mut self.recv_epoch,
            ) {
                self.failed = true;
                return Err(err);
            }
            self.recv_usage = KeyUsage::default();
            return Ok(());
        }
        self.rx_plain_pos = 0;
        self.rx_plain_len = plain_len;
        Ok(())
    }
}

impl<S: Read + Write> Read for PqWgStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_inner(buf)
    }
}

impl<S: Read + Write> Write for PqWgStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.close_started {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pq-wg stream locally closed",
            ));
        }
        let take = buf.len().min(MAX_RECORD_PAYLOAD);
        self.prepare_data(take)?;
        self.send_record(RECORD_DATA, &buf[..take])?;
        // Once accepted, report plaintext progress even if the underlying write
        // would block: the encrypted frame remains buffered for flush/next write.
        let _ = self.drain_tx();
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pq-wg stream poisoned",
            ));
        }
        self.drain_tx()?;
        match self.inner.flush() {
            Err(err) if !matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {
                self.failed = true;
                Err(err)
            }
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn test_identity(seed: u8) -> PqWgIdentity {
        let key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32])
            .expect("mldsa65 key");
        let pem = key.private_key_to_pem_pkcs8().expect("pem");
        PqWgIdentity::from_private_key_pem(&pem).expect("identity")
    }

    #[test]
    fn aes_256_gcm_known_answer_and_negative_authentication() {
        // NIST AES-256-GCM zero key, zero 96-bit IV, empty AAD and one zero block.
        let key = [0u8; AEAD_KEY_LEN];
        let mut sealed = [0u8; 32];
        assert_eq!(aead_seal_into(&key, 0, &[], &[0; 16], &mut sealed).unwrap(), 32);
        assert_eq!(sealed, [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
            0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
            0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
        ]);
        let mut plain = [0x55; 32];
        assert_eq!(aead_open_into(&key, 0, &[], &sealed, &mut plain).unwrap(), 16);
        assert_eq!(&plain[..16], &[0; 16]);
        for (wrong_key, counter, aad, index) in [
            (true, 0, &b""[..], None),
            (false, 1, &b""[..], None),
            (false, 0, &b"x"[..], None),
            (false, 0, &b""[..], Some(0)),
            (false, 0, &b""[..], Some(31)),
        ] {
            let mut candidate = sealed;
            if let Some(i) = index { candidate[i] ^= 1; }
            let candidate_key = if wrong_key { [1; 32] } else { key };
            plain.fill(0x55);
            assert!(aead_open_into(&candidate_key, counter, aad, &candidate, &mut plain).is_err());
            assert_eq!(plain, [0; 32]);
        }
        let mut tag = [0; AEAD_TAG_LEN];
        assert_eq!(aead_seal_into(&key, 0, &[], &[], &mut tag).unwrap(), AEAD_TAG_LEN);
        assert_eq!(tag, [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        ]);
    }

    #[test]
    fn legacy_cipher_and_protocol_version_are_rejected() {
        let key = [0x42; AEAD_KEY_LEN];
        let aad = b"record header";
        let plaintext = b"legacy record";
        let nonce = make_nonce(1);
        let mut old = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, &key, Some(&nonce)).unwrap();
        old.aad_update(aad).unwrap();
        let mut wire = vec![0; plaintext.len() + AEAD_TAG_LEN];
        let mut n = old.update(plaintext, &mut wire).unwrap();
        n += old.finalize(&mut wire[n..]).unwrap();
        old.get_tag(&mut wire[n..n + AEAD_TAG_LEN]).unwrap();
        let mut out = vec![0; plaintext.len() + AEAD_TAG_LEN];
        assert!(aead_open_into(&key, 1, aad, &wire, &mut out).is_err());

        // Both algorithm and version feed the transcript before the first signature.
        let identity = test_identity(0xa1);
        let body = b"same handshake message";
        let transcript = |name: &[u8]| {
            let ck = sha256_all(&[name]);
            let h = sha256_all(&[&ck, PqWgLayer::Hop.domain_tag()]);
            sha256_all(&[&h, body])
        };
        let current = transcript(PROTOCOL_NAME);
        let sig = sign_mldsa65(&identity.inner.private_key, b"BOREAS-PQ-WG-INIT-SIG-v1\0", &current).unwrap();
        assert!(verify_mldsa65(identity.public_spki(), b"BOREAS-PQ-WG-INIT-SIG-v1\0", &current, &sig).is_ok());
        for name in [
            &b"BOREAS-PQ-WG-v1-X25519-MLKEM768-MLDSA65-CHACHA20POLY1305"[..],
            &b"BOREAS-PQ-WG-v1-X25519-MLKEM768-MLDSA65-AES256GCM"[..],
            &b"BOREAS-PQ-WG-v2-X25519-MLKEM768-MLDSA65-AES256GCM"[..],
        ] {
            assert!(
                verify_mldsa65(
                    identity.public_spki(),
                    b"BOREAS-PQ-WG-INIT-SIG-v1\0",
                    &transcript(name),
                    &sig
                )
                .is_err()
            );
        }
    }

    #[derive(Default)]
    struct MemoryWire {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for MemoryWire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.input.read(buf) }
    }
    impl Write for MemoryWire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    fn test_stream(wire: MemoryWire, send: [u8; 32], recv: [u8; 32]) -> PqWgStream<MemoryWire> {
        PqWgStream::new(
            wire,
            send,
            recv,
            Vec::new(),
            PqWgParameters {
                group: HybridGroup::X25519MlKem768,
                peer_signature: IdentitySignature::MlDsa65,
                aead: Aead::Aes256GcmSha384,
                resumed: false,
                zero_rtt: false,
                tls_free: true,
            },
            true,
        )
    }
    fn reader_for(data: Vec<u8>, key: [u8; 32]) -> PqWgStream<MemoryWire> {
        let mut reader = test_stream(
            MemoryWire {
                input: std::io::Cursor::new(data),
                output: Vec::new(),
            },
            [3; 32],
            key,
        );
        reader.recv_direction = 0;
        reader.send_direction = 1;
        reader
    }

    #[test]
    fn record_tampering_wrong_key_replay_and_poisoning() {
        let key = [9; 32];
        let mut sender = test_stream(MemoryWire::default(), key, [3; 32]);
        sender.write_all(b"record").unwrap();
        sender.close_notify().unwrap();
        let record_len = RECORD_HEADER_LEN + b"record".len() + AEAD_TAG_LEN;
        let record = sender.get_ref().output[..record_len].to_vec();
        let full_wire = sender.get_ref().output.clone();
        for (wire, recv_key) in [
            ({ let mut r = full_wire.clone(); r[0] ^= 0x80; r }, key),
            ({ let mut r = full_wire; r[4] = 7; r }, key),
            ({ let mut r = record.clone(); r[RECORD_HEADER_LEN] ^= 1; r }, key),
            ({ let mut r = record.clone(); let i = r.len() - 1; r[i] ^= 1; r }, key),
            (record.clone(), [8; 32]),
        ] {
            let mut reader = reader_for(wire, recv_key);
            assert!(reader.read(&mut [0; 32]).is_err());
            assert_eq!(reader.read(&mut [0; 32]).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        }
        let mut replayed = record.clone();
        replayed.extend_from_slice(&record);
        let mut reader = reader_for(replayed, key);
        let mut out = [0; 6];
        reader.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"record");
        assert_eq!(reader.read(&mut out).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rekey_long_stream_limits_and_directional_independence() {
        let key = [7; 32];
        // Each case isolates one limit: two 4-byte records fit per epoch.
        for limits in [
            KeyLimits {
                records: 3,
                bytes: 100,
                blocks: 100,
            },
            KeyLimits {
                records: 100,
                bytes: 8,
                blocks: 100,
            },
            KeyLimits {
                records: 100,
                bytes: 100,
                blocks: 8,
            },
        ] {
            let mut sender = test_stream(MemoryWire::default(), key, [8; 32]);
            sender.limits = limits;
            for _ in 0..21 {
                sender.write_all(b"test").unwrap();
            }
            assert_eq!(sender.send_epoch, 10);
            assert_eq!(sender.recv_epoch, 0);
            sender.close_notify().unwrap();
            assert!(sender.write(b"x").is_err());
            let mut reader = reader_for(sender.get_ref().output.clone(), key);
            reader.limits = limits;
            let mut plain = Vec::new();
            reader.read_to_end(&mut plain).unwrap();
            assert_eq!(plain, b"test".repeat(21));
            assert_eq!(reader.recv_epoch, 10);
            assert_eq!(reader.send_epoch, 0);
        }
        // Reverse direction uses the responder label and does not update the
        // opposite traffic key even when both starting traffic keys are equal.
        let limits = KeyLimits {
            records: 2,
            bytes: 100,
            blocks: 100,
        };
        let mut responder = reader_for(Vec::new(), key);
        responder.send_key = key;
        responder.limits = limits;
        responder.write_all(b"a").unwrap();
        responder.write_all(b"b").unwrap();
        responder.close_notify().unwrap();
        assert_eq!((responder.send_epoch, responder.recv_epoch), (1, 0));
        let mut initiator = test_stream(
            MemoryWire {
                input: std::io::Cursor::new(responder.get_ref().output.clone()),
                output: Vec::new(),
            },
            key,
            key,
        );
        initiator.limits = limits;
        let mut plain = Vec::new();
        initiator.read_to_end(&mut plain).unwrap();
        assert_eq!(plain, b"ab");
        assert_eq!((initiator.send_epoch, initiator.recv_epoch), (0, 1));

        // Exact production limits: a data record leaves one close/update slot.
        let limits = KeyLimits::default();
        for mut usage in [
            KeyUsage {
                records: limits.records - 2,
                bytes: 0,
                blocks: 0,
            },
            KeyUsage {
                records: 0,
                bytes: limits.bytes - 1,
                blocks: 0,
            },
            KeyUsage {
                records: 0,
                bytes: 0,
                blocks: limits.blocks - 5,
            },
        ] {
            usage.charge(1, true, limits).unwrap();
            assert!(usage.charge(1, true, limits).is_err());
            usage.charge(0, false, limits).unwrap();
        }
        // Direction labels prevent ratchet collisions even with identical input keys.
        let (mut a, mut b, mut c) = (key, key, key);
        let (mut ea, mut eb, mut ec) = (0, 0, 0);
        advance_key(&mut a, 0, &mut ea).unwrap();
        advance_key(&mut b, 1, &mut eb).unwrap();
        advance_key(&mut c, 0, &mut ec).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, c);
        advance_key(&mut c, 0, &mut ec).unwrap();
        assert_ne!(a, c);
        zeroize(&mut a);
        zeroize(&mut b);
        zeroize(&mut c);
    }

    #[test]
    fn update_tamper_reorder_replay_truncation_and_exhaustion() {
        let key = [9; 32];
        let limits = KeyLimits {
            records: 2,
            bytes: 100,
            blocks: 100,
        };
        let mut sender = test_stream(MemoryWire::default(), key, [3; 32]);
        sender.limits = limits;
        sender.write_all(b"a").unwrap();
        sender.write_all(b"b").unwrap();
        sender.close_notify().unwrap();
        let wire = &sender.get_ref().output;
        let d = RECORD_HEADER_LEN + 1 + AEAD_TAG_LEN;
        let u = RECORD_HEADER_LEN + AEAD_TAG_LEN;
        let first = &wire[..d];
        let update = &wire[d..d + u];
        let rest = &wire[d + u..];
        assert_eq!(update[0], RECORD_UPDATE);
        let mut tampered = update.to_vec();
        tampered[u - 1] ^= 1;
        let mut bad_len = update.to_vec();
        bad_len[4] = 1;
        let mut wrong_type = update.to_vec();
        wrong_type[0] = RECORD_CLOSE;
        for bad in [
            [first, &tampered, rest].concat(),
            [first, &bad_len, rest].concat(),
            [first, &wrong_type, rest].concat(),
            [first, &update[..u - 1]].concat(),
            [first, rest, update].concat(),
            [first, update, update, rest].concat(),
            [first, rest].concat(),
        ] {
            let mut reader = reader_for(bad, key);
            reader.limits = limits;
            let mut output = [0; 1];
            assert_eq!(reader.read(&mut output).unwrap(), 1);
            assert!(reader.read(&mut output).is_err());
            assert_eq!(
                reader.read(&mut output).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        // Epoch exhaustion refuses a further update but leaves the reserved
        // control record available for an authenticated close.
        let mut exhausted = test_stream(MemoryWire::default(), key, [3; 32]);
        exhausted.limits = limits;
        exhausted.send_epoch = MAX_EPOCHS_PER_DIRECTION - 1;
        exhausted.write_all(b"a").unwrap();
        let before = exhausted.get_ref().output.len();
        assert!(exhausted.write_all(b"b").is_err());
        assert_eq!(exhausted.get_ref().output.len(), before);
        exhausted.close_notify().unwrap();
        let mut receiver = reader_for(exhausted.get_ref().output.clone(), key);
        receiver.limits = limits;
        let mut plain = Vec::new();
        receiver.read_to_end(&mut plain).unwrap();
        assert_eq!(plain, b"a");

        // Even an authenticated peer cannot use control-only epochs to force
        // unbounded ratchet work in a single read.
        let mut update = vec![0; RECORD_HEADER_LEN + AEAD_TAG_LEN];
        update[0] = RECORD_UPDATE;
        let (aad, tag) = update.split_at_mut(RECORD_HEADER_LEN);
        aead_seal_into(&key, 1, aad, &[], tag).unwrap();
        let mut empty_epoch = reader_for(update, key);
        assert!(empty_epoch.read(&mut [0; 1]).is_err());
        assert_eq!(empty_epoch.read(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::BrokenPipe);

        // A malicious authenticated update cannot exceed the receive epoch cap.
        let mut reader = reader_for(wire.clone(), key);
        reader.limits = limits;
        reader.recv_epoch = MAX_EPOCHS_PER_DIRECTION - 1;
        reader.read_exact(&mut [0; 1]).unwrap();
        assert!(reader.read(&mut [0; 1]).is_err());
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn old_frame_magic_is_rejected_before_peer_lookup() {
        let identity = test_identity(0xb1);
        let acceptor = PqWgAcceptor::new(
            identity,
            Arc::new(StaticSpkiResolver::default()),
            Policy::production_default(),
            PqWgLayer::Hop,
        )
        .unwrap();
        let body_len =
            4 + 1 + 4 + NONCE_BYTES_LEN + X25519_PUB_LEN + 2 + ML_KEM_768_EK_LEN + SPKI_HASH_LEN;
        let mut body = vec![0; body_len + 2];
        body[4] = MSG_INIT;
        for magic in [b"BWG1", b"BWG2"] {
            body[..4].copy_from_slice(magic);
            let mut input = (body.len() as u32).to_be_bytes().to_vec();
            input.extend_from_slice(&body);
            let wire = MemoryWire {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
            };
            assert!(matches!(acceptor.accept(wire), Err(PqWgError::Handshake)));
        }
    }

    #[test]
    fn partial_nonblocking_writes_are_resumed_without_reencrypting() {
        struct ShortWriter { wire: MemoryWire, blocked: bool }
        impl Read for ShortWriter {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.wire.read(buf) }
        }
        impl Write for ShortWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.blocked { return Err(io::ErrorKind::WouldBlock.into()); }
                let n = buf.len().min(3);
                self.wire.write_all(&buf[..n])?;
                self.blocked = true;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let key = [0x12; 32];
        let params = test_stream(MemoryWire::default(), key, key).negotiated();
        let wire = ShortWriter {
            wire: MemoryWire::default(),
            blocked: false,
        };
        let mut sender = PqWgStream::new(wire, key, key, Vec::new(), params, true);
        let limits = KeyLimits {
            records: 2,
            bytes: 100,
            blocks: 100,
        };
        sender.limits = limits;
        assert_eq!(sender.write(b"first").unwrap(), 5);
        assert!(sender.has_pending_output());
        assert_eq!(sender.write(b"second").unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(sender.send_usage.records, 1);
        loop {
            sender.get_mut().blocked = false;
            match sender.flush_pending_output() {
                Ok(()) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(err) => panic!("unexpected flush error: {err}"),
            }
        }
        assert!(!sender.has_pending_output());
        // UPDATE itself is partially written and never re-encrypted on retry.
        loop {
            sender.get_mut().blocked = false;
            match sender.write(b"second") {
                Ok(6) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                other => panic!("unexpected write result: {other:?}"),
            }
        }
        assert_eq!(sender.send_epoch, 1);
        assert_eq!(sender.close_notify().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(sender.write(b"late").unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        loop {
            sender.get_mut().blocked = false;
            match sender.close_notify() {
                Ok(()) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(err) => panic!("unexpected close error: {err}"),
            }
        }
        assert_eq!(sender.send_usage.records, 2);
        let mut reader = reader_for(sender.get_ref().wire.output.clone(), key);
        reader.limits = limits;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"firstsecond");
    }

    #[test]
    fn partial_ciphertext_is_not_reported_ready_and_failure_reaches_close() {
        struct FragmentThenBlock { byte: Option<u8> }
        impl Read for FragmentThenBlock {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                match self.byte.take() {
                    Some(byte) => { out[0] = byte; Ok(1) },
                    None => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }
        impl Write for FragmentThenBlock {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> { Ok(buf.len()) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let key = [0x12; 32];
        let params = test_stream(MemoryWire::default(), key, key).negotiated();
        let mut stream = PqWgStream::new(
            FragmentThenBlock {
                byte: Some(RECORD_DATA),
            },
            key,
            key,
            Vec::new(),
            params,
            true,
        );
        let received = stream.read(&mut [0; 1]).unwrap_err();
        assert_eq!(received.kind(), io::ErrorKind::WouldBlock);
        assert!(!stream.has_buffered_input());
        stream.failed = true;
        assert_eq!(stream.close_notify().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn pq_wg_roundtrip_hop_and_e2e_and_authenticated_close() {
        for layer in [PqWgLayer::Hop, PqWgLayer::E2e] {
        let client_id = test_identity(0x11);
        let server_id = test_identity(0x22);
        let resolver = Arc::new(StaticSpkiResolver::from_spkis(vec![
            client_id.public_spki().to_vec(),
            server_id.public_spki().to_vec(),
        ]));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_id = server_id.clone();
        let expected_client_spki = client_id.public_spki().to_vec();
        let srv_res = Arc::clone(&resolver);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let acceptor =
                PqWgAcceptor::new(srv_id, srv_res, Policy::production_default(), layer)
                    .unwrap();
            let mut stream = acceptor.accept(tcp).unwrap();
            assert_eq!(stream.peer_spki(), expected_client_spki);
            assert_eq!(stream.negotiated().aead, Aead::Aes256GcmSha384);
            assert!(stream.negotiated().tls_free);
            let mut buf = vec![0u8; 40_000];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(&buf).unwrap();
            stream.close_notify().unwrap();
            let mut eof = [0u8; 1];
            assert_eq!(stream.read_with_authenticated_eof(&mut eof).unwrap(), 0);
        });

        let tcp = TcpStream::connect(addr).unwrap();
        let connector = PqWgConnector::new(
            client_id,
            Arc::new(StaticSpkiResolver::from_spkis(vec![
                server_id.public_spki().to_vec(),
            ])),
            Policy::production_default(),
            layer,
        )
        .unwrap();
        let mut stream = connector.connect(tcp).unwrap();
        assert_eq!(stream.negotiated().aead, Aead::Aes256GcmSha384);
        assert_eq!(stream.peer_spki(), server_id.public_spki());
        let payload = vec![0x5Au8; 40_000];
        stream.write_all(&payload).unwrap();
        stream.flush().unwrap();
        let mut echoed = vec![0u8; 40_000];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, payload);
        let mut eof = [0u8; 1];
        assert_eq!(stream.read_with_authenticated_eof(&mut eof).unwrap(), 0);
        stream.close_notify().unwrap();
        server.join().unwrap();
        }
    }

    #[test]
    fn pq_wg_rejects_cross_layer_replay() {
        let client_id = test_identity(0x31);
        let server_id = test_identity(0x42);
        let resolver = Arc::new(StaticSpkiResolver::from_spkis(vec![
            client_id.public_spki().to_vec(),
            server_id.public_spki().to_vec(),
        ]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_res = Arc::clone(&resolver);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let acceptor =
                PqWgAcceptor::new(server_id, srv_res, Policy::production_default(), PqWgLayer::E2e)
                    .unwrap();
            acceptor.accept(tcp).is_err()
        });

        let tcp = TcpStream::connect(addr).unwrap();
        let connector = PqWgConnector::new(
            client_id,
            resolver,
            Policy::production_default(),
            PqWgLayer::Hop,
        )
        .unwrap();
        assert!(connector.connect(tcp).is_err());
        assert!(server.join().unwrap());
    }

    #[test]
    fn pq_wg_rejects_unauthenticated_eof() {
        let client_id = test_identity(0x51);
        let server_id = test_identity(0x62);
        let resolver = Arc::new(StaticSpkiResolver::from_spkis(vec![
            client_id.public_spki().to_vec(),
            server_id.public_spki().to_vec(),
        ]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_res = Arc::clone(&resolver);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let acceptor =
                PqWgAcceptor::new(server_id, srv_res, Policy::production_default(), PqWgLayer::E2e)
                    .unwrap();
            let mut stream = acceptor.accept(tcp).unwrap();
            stream.write_all(b"secret").unwrap();
            stream.flush().unwrap();
            // Drop without close_notify -> client must observe UnexpectedEof, not Ok(0).
        });

        let tcp = TcpStream::connect(addr).unwrap();
        let connector = PqWgConnector::new(
            client_id,
            resolver,
            Policy::production_default(),
            PqWgLayer::E2e,
        )
        .unwrap();
        let mut stream = connector.connect(tcp).unwrap();
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"secret");
        let err = stream.read_with_authenticated_eof(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        server.join().unwrap();
    }

    #[test]
    fn pq_wg_handles_one_byte_fragmented_reads() {
        let client_id = test_identity(0x71);
        let server_id = test_identity(0x82);
        let resolver = Arc::new(StaticSpkiResolver::from_spkis(vec![
            client_id.public_spki().to_vec(),
            server_id.public_spki().to_vec(),
        ]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_res = Arc::clone(&resolver);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let acceptor =
                PqWgAcceptor::new(server_id, srv_res, Policy::production_default(), PqWgLayer::Hop)
                    .unwrap();
            let mut stream = acceptor.accept(tcp).unwrap();
            stream.write_all(b"hello-frag").unwrap();
            stream.close_notify().unwrap();
        });

        struct OneByteStream(TcpStream);
        impl Read for OneByteStream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let cap = buf.len().min(1);
                self.0.read(&mut buf[..cap])
            }
        }
        impl Write for OneByteStream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let cap = buf.len().min(1);
                self.0.write(&buf[..cap])
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }

        let tcp = OneByteStream(TcpStream::connect(addr).unwrap());
        let connector = PqWgConnector::new(
            client_id,
            resolver,
            Policy::production_default(),
            PqWgLayer::Hop,
        )
        .unwrap();
        let mut stream = connector.connect(tcp).unwrap();
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read_with_authenticated_eof(&mut byte).unwrap() {
                0 => break,
                n => out.extend_from_slice(&byte[..n]),
            }
        }
        assert_eq!(out, b"hello-frag");
        server.join().unwrap();
    }
}
