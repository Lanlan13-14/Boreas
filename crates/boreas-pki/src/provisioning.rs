//! Offline PKI provisioning and bundle verification (master plan §1.1, §2.2, §2.4, §3.4, §5.3).
//!
//! This module implements the first-release recommended offline provisioning path:
//! - `NetworkRoot` signs `RootAuthorizationCandidate` records for separated
//!   `IdentityAuthority` (`Purpose::Identity`) and `StatusSigner` (`Purpose::Status`)
//!   into a deterministic `roots.cbor`-compatible `RootsBundle`.
//! - `IdentityAuthority` signs node ML-DSA-65 X.509 v3 leaf certificates (under its
//!   ML-DSA-65 X.509 CA) and dual-signs (`Ed25519 + ML-DSA-65` AND) canonical
//!   `NodeIdentity` management objects bound to the exact same ML-DSA-65 public key.
//! - `StatusSigner` dual-signs (`Ed25519 + ML-DSA-65` AND) bounded `StatusSnapshot`
//!   objects (`next_update - issued_at <= 24 h`).
//! - Node material directories never receive `NetworkRoot`, `IdentityAuthority`, or
//!   `StatusSigner` private keys.
#![cfg(feature = "openssl-backend")]

#[cfg(target_os = "linux")]
pub mod core_mesh;

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use boreas_crypto::Policy;
use boreas_crypto::backend::{OpenSslAcceptor, PemIdentity};
use boreas_proto::messages::{SignedObject, SignerRole, SignerSignatures};
use boreas_proto::network_policy::NetworkPolicyCandidate;
use boreas_proto::objects::{
    self, ManagementObject, MldsaParameterSet, ObjectBody, ObjectType, StatusSnapshot,
    SubjectIdentity,
};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{KeyType, PKey, Private};
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder, X509Ref, X509ReqBuilder};

use crate::management::{
    IdentityAuthority, IdentityTemplate, MANAGEMENT_SCHEMA_VERSION, ManagementTrust, VerifiedObject,
};
use crate::root_authorization::{
    self, MAX_CHAIN_DEPTH, NetworkRootPin, Purpose, RootAuthorizationCandidate, Scope,
    VerifiedIssuerAuthorization,
};
use crate::{Authority, NodeRole, STATUS_MAX_AGE_US, expected_vip, node_id};

const ROOTS_BUNDLE_MAGIC: &[u8; 8] = b"BRRB0001";
const ROOT_AUTH_DOMAIN: &[u8] = b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0";
const MAX_ROOTS_BUNDLE_BYTES: usize = 128 * 1024;
// Sixteen operational scopes plus distinct IdentityAuthority and StatusSigner.
const MAX_BUNDLE_AUTH_RECORDS: usize = 18;
const MAX_MATERIAL_FILE_BYTES: usize = 64 * 1024;
const MLDSA65_SIG_LEN: usize = 3309;
const IA_KEY_ID: &[u8] = b"identity-authority-v1";
const STATUS_KEY_ID: &[u8] = b"status-signer-v1";

#[derive(Debug)]
pub enum ProvisionError {
    Io(&'static str),
    FileTooLarge,
    AlreadyExists,
    InvalidParameter(&'static str),
    OpenSsl(&'static str),
    RootAuth(root_authorization::Error),
    Management(crate::management::Error),
    CryptoIdentity,
    SpkiMismatch,
    WrongNetwork,
    StatusExpired,
    StatusWindowInvalid,
    MissingAuthority(&'static str),
    MalformedRootsBundle,
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(ctx) => write!(f, "provisioning I/O failed: {ctx}"),
            Self::FileTooLarge => write!(f, "provisioning file exceeds maximum bounded size"),
            Self::AlreadyExists => write!(f, "refusing to overwrite existing key or CA directory"),
            Self::InvalidParameter(msg) => write!(f, "invalid provisioning parameter: {msg}"),
            Self::OpenSsl(ctx) => write!(f, "OpenSSL operation failed: {ctx}"),
            Self::RootAuth(err) => write!(f, "root authorization failed: {err}"),
            Self::Management(err) => write!(f, "management verification failed: {err}"),
            Self::CryptoIdentity => write!(f, "TLS PEM identity validation failed"),
            Self::SpkiMismatch => {
                write!(f, "TLS leaf ML-DSA key does not match signed NodeIdentity")
            }
            Self::WrongNetwork => write!(f, "bundle network identifier mismatch"),
            Self::StatusExpired => write!(f, "StatusSnapshot is not fresh at current UTC"),
            Self::StatusWindowInvalid => write!(f, "StatusSnapshot validity window exceeds 24h"),
            Self::MissingAuthority(which) => write!(f, "missing authorized issuer: {which}"),
            Self::MalformedRootsBundle => write!(f, "malformed roots bundle"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<root_authorization::Error> for ProvisionError {
    fn from(value: root_authorization::Error) -> Self {
        Self::RootAuth(value)
    }
}

impl From<crate::management::Error> for ProvisionError {
    fn from(value: crate::management::Error) -> Self {
        Self::Management(value)
    }
}

impl From<std::io::Error> for ProvisionError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Self::AlreadyExists
        } else {
            Self::Io("filesystem I/O")
        }
    }
}

/// One signed `RootAuthorizationCandidate` inside `roots.cbor`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRootAuthorization {
    pub raw_candidate: Vec<u8>,
    pub ed25519_signature: Vec<u8>,
    pub mldsa_signature: Vec<u8>,
}

/// Deterministic `roots.cbor` container binding `NetworkRoot` public keys and
/// its dual-signed `RootAuthorizationCandidate` delegations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootsBundle {
    pub net_id: [u8; 16],
    pub root_ed25519_pub_der: Vec<u8>,
    pub root_mldsa65_pub_der: Vec<u8>,
    pub authorizations: Vec<SignedRootAuthorization>,
}

impl RootsBundle {
    pub fn encode(&self) -> Result<Vec<u8>, ProvisionError> {
        if self.net_id == [0u8; 16]
            || self.root_ed25519_pub_der.is_empty()
            || self.root_mldsa65_pub_der.is_empty()
            || self.authorizations.is_empty()
            || self.authorizations.len() > MAX_BUNDLE_AUTH_RECORDS
        {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        let mut out = Vec::new();
        out.extend_from_slice(ROOTS_BUNDLE_MAGIC);
        out.extend_from_slice(&self.net_id);
        push_len_bytes(&mut out, &self.root_ed25519_pub_der)?;
        push_len_bytes(&mut out, &self.root_mldsa65_pub_der)?;
        let count = u16::try_from(self.authorizations.len())
            .map_err(|_| ProvisionError::MalformedRootsBundle)?;
        out.extend_from_slice(&count.to_be_bytes());
        for auth in &self.authorizations {
            push_len_bytes(&mut out, &auth.raw_candidate)?;
            push_len_bytes(&mut out, &auth.ed25519_signature)?;
            push_len_bytes(&mut out, &auth.mldsa_signature)?;
        }
        if out.len() > MAX_ROOTS_BUNDLE_BYTES {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisionError> {
        if bytes.len() < 8 + 16 + 4 || bytes.len() > MAX_ROOTS_BUNDLE_BYTES {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        if &bytes[..8] != ROOTS_BUNDLE_MAGIC {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        let mut cursor = 8usize;
        let net_id: [u8; 16] = bytes[cursor..cursor + 16]
            .try_into()
            .map_err(|_| ProvisionError::MalformedRootsBundle)?;
        cursor += 16;
        if net_id == [0u8; 16] {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        let root_ed25519_pub_der = read_len_bytes(bytes, &mut cursor)?;
        let root_mldsa65_pub_der = read_len_bytes(bytes, &mut cursor)?;
        if cursor + 2 > bytes.len() {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        let count = usize::from(u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]));
        cursor += 2;
        if count == 0 || count > MAX_BUNDLE_AUTH_RECORDS {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        let mut authorizations = Vec::with_capacity(count);
        for _ in 0..count {
            let raw_candidate = read_len_bytes(bytes, &mut cursor)?;
            let ed25519_signature = read_len_bytes(bytes, &mut cursor)?;
            let mldsa_signature = read_len_bytes(bytes, &mut cursor)?;
            authorizations.push(SignedRootAuthorization {
                raw_candidate,
                ed25519_signature,
                mldsa_signature,
            });
        }
        if cursor != bytes.len() {
            return Err(ProvisionError::MalformedRootsBundle);
        }
        Ok(Self {
            net_id,
            root_ed25519_pub_der,
            root_mldsa65_pub_der,
            authorizations,
        })
    }

    /// Parse the exact public NetworkRoot keys; callers must still bind the
    /// resulting fingerprint to their independently verified network context.
    pub fn network_root_pin(&self) -> Result<NetworkRootPin, ProvisionError> {
        Ok(NetworkRootPin::provisioned(
            self.net_id,
            self.root_ed25519_pub_der.clone(),
            MldsaParameterSet::Mldsa65,
            self.root_mldsa65_pub_der.clone(),
        )?)
    }

    /// Verify the `NetworkRoot` pin and every delegated `RootAuthorizationCandidate` at `now_us`.
    pub fn verify_all(
        &self,
        expected_net_id: [u8; 16],
        now_us: u64,
    ) -> Result<([u8; 32], Vec<VerifiedIssuerAuthorization>), ProvisionError> {
        if self.net_id != expected_net_id {
            return Err(ProvisionError::WrongNetwork);
        }
        let pin = self.network_root_pin()?;
        let root_fp = pin.fingerprint()?;
        let mut verified = Vec::with_capacity(self.authorizations.len());
        for entry in &self.authorizations {
            let auth = root_authorization::verify_raw(
                &entry.raw_candidate,
                &entry.ed25519_signature,
                &entry.mldsa_signature,
                &pin,
                expected_net_id,
                now_us,
            )?;
            verified.push(auth);
        }
        Ok((root_fp, verified))
    }
}

fn push_len_bytes(out: &mut Vec<u8>, slice: &[u8]) -> Result<(), ProvisionError> {
    let len = u32::try_from(slice.len()).map_err(|_| ProvisionError::MalformedRootsBundle)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(slice);
    Ok(())
}

fn read_len_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ProvisionError> {
    if *cursor + 4 > bytes.len() {
        return Err(ProvisionError::MalformedRootsBundle);
    }
    let len = usize::try_from(u32::from_be_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]))
    .map_err(|_| ProvisionError::MalformedRootsBundle)?;
    *cursor += 4;
    if len == 0 || len > MAX_ROOTS_BUNDLE_BYTES || *cursor + len > bytes.len() {
        return Err(ProvisionError::MalformedRootsBundle);
    }
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct CaInitParams {
    pub net_id: [u8; 16],
    pub issuer_generation: u64,
    pub now_us: u64,
    pub validity_days: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaInitSummary {
    pub net_id_hex: String,
    pub root_fingerprint_hex: String,
    pub issuer_generation: u64,
    pub expires_us: u64,
}

#[derive(Clone, Debug)]
pub struct NodeIssueParams {
    pub role: NodeRole,
    pub home_core_id: u8,
    pub vip_octet: u8,
    pub identity_generation: u64,
    pub now_us: u64,
    pub validity_hours: u32,
    pub outer_san_dns: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIssueSummary {
    pub net_id_hex: String,
    pub node_id: u16,
    pub role: NodeRole,
    pub home_core_id: u8,
    pub vip: [u8; 4],
    pub identity_generation: u64,
    pub expires_us: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshotSummary {
    pub net_id_hex: String,
    pub sequence: u64,
    pub issued_at_us: u64,
    pub next_update_us: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicySummary {
    pub net_id_hex: String,
    pub root_fingerprint_hex: String,
    pub sequence: u64,
    pub issued_at_us: u64,
    pub expires_us: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    pub net_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub local: VerifiedObject,
    pub peer: Option<VerifiedObject>,
    pub status_sequence: u64,
    pub status_issued_at_us: u64,
    /// The snapshot's signed `next_update`, not an authorization deadline.
    pub status_next_update_us: u64,
    /// Exclusive freshness cutoff, including the verified StatusSigner grant.
    pub status_valid_until_us: u64,
}

/// Initialize a separated offline CA hierarchy (`NetworkRoot`, `IdentityAuthority`,
/// `StatusSigner`, plus optional private outer-TLS origin CA) and emit `roots.cbor`.
pub fn init_ca_dir(ca_dir: &Path, params: &CaInitParams) -> Result<CaInitSummary, ProvisionError> {
    if params.net_id == [0u8; 16] {
        return Err(ProvisionError::InvalidParameter(
            "net_id cannot be all-zero",
        ));
    }
    if params.issuer_generation == 0 {
        return Err(ProvisionError::InvalidParameter(
            "issuer_generation must be non-zero",
        ));
    }
    if params.validity_days == 0 || params.validity_days > 3650 {
        return Err(ProvisionError::InvalidParameter(
            "validity_days must be in 1..=3650",
        ));
    }
    ensure_private_dir(ca_dir)?;
    if ca_dir.join("root.ed25519.key").exists() || ca_dir.join("roots.cbor").exists() {
        return Err(ProvisionError::AlreadyExists);
    }

    let span_us = u64::from(params.validity_days) * 86_400 * 1_000_000;
    let not_before_us = params.now_us.saturating_sub(60_000_000);
    let expires_us = params
        .now_us
        .checked_add(span_us)
        .ok_or(ProvisionError::InvalidParameter("validity_days overflow"))?;

    // 1. Offline NetworkRoot (Ed25519 + ML-DSA-65).
    let root_ed = generate_ed25519()?;
    let root_ml = generate_mldsa65()?;
    let root_ed_pub = root_ed
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("root ed25519 pub der"))?;
    let root_ml_pub = root_ml
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("root mldsa65 pub der"))?;

    // 2. Separated IdentityAuthority (Ed25519 + ML-DSA-65 + ML-DSA-65 X.509 CA).
    let ia_ed = generate_ed25519()?;
    let ia_ml = generate_mldsa65()?;
    let ia_ed_pub = ia_ed
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("ia ed25519 pub der"))?;
    let ia_ml_pub = ia_ml
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("ia mldsa65 pub der"))?;
    let ia_ca_cert = build_mldsa65_ca_cert(
        &ia_ml,
        "Boreas Identity Authority CA",
        params.now_us,
        expires_us,
    )?;

    // 3. Separated StatusSigner (Ed25519 + ML-DSA-65).
    let status_ed = generate_ed25519()?;
    let status_ml = generate_mldsa65()?;
    let status_ed_pub = status_ed
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("status ed25519 pub der"))?;
    let status_ml_pub = status_ml
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("status mldsa65 pub der"))?;

    // 4. Dev/private-origin Outer TLS CA (EC P-256).
    let outer_ca_key = generate_p256()?;
    let outer_ca_cert = build_p256_ca_cert(
        &outer_ca_key,
        "Boreas Private Origin TLS CA",
        params.now_us,
        expires_us,
    )?;

    // 5. Sign RootAuthorizationCandidate delegations under NetworkRoot.
    let ia_candidate = RootAuthorizationCandidate {
        net_id: params.net_id,
        issuer_key_id: IA_KEY_ID.to_vec(),
        issuer_generation: params.issuer_generation,
        purpose: Purpose::Identity,
        ed25519_public_key_der: ia_ed_pub.clone(),
        mldsa_parameter_set: MldsaParameterSet::Mldsa65,
        mldsa_public_key_der: ia_ml_pub.clone(),
        scope: Scope::Identity {
            roles: vec![NodeRole::Edge, NodeRole::Core],
            home_cores: (1u8..=16).collect(),
        },
        not_before: not_before_us,
        expires: expires_us,
        chain_depth: MAX_CHAIN_DEPTH,
        may_delegate: false,
    };
    let status_candidate = RootAuthorizationCandidate {
        net_id: params.net_id,
        issuer_key_id: STATUS_KEY_ID.to_vec(),
        issuer_generation: params.issuer_generation,
        purpose: Purpose::Status,
        ed25519_public_key_der: status_ed_pub.clone(),
        mldsa_parameter_set: MldsaParameterSet::Mldsa65,
        mldsa_public_key_der: status_ml_pub.clone(),
        scope: Scope::Status,
        not_before: not_before_us,
        expires: expires_us,
        chain_depth: MAX_CHAIN_DEPTH,
        may_delegate: false,
    };
    let signed_ia = sign_root_auth(&ia_candidate, &root_ed, &root_ml)?;
    let signed_status = sign_root_auth(&status_candidate, &root_ed, &root_ml)?;

    let bundle = RootsBundle {
        net_id: params.net_id,
        root_ed25519_pub_der: root_ed_pub,
        root_mldsa65_pub_der: root_ml_pub,
        authorizations: vec![signed_ia, signed_status],
    };
    let (root_fp, _) = bundle.verify_all(params.net_id, params.now_us)?;
    let roots_bytes = bundle.encode()?;

    // Persist private keys (0600, create_new) and public metadata.
    write_secret_new(
        &ca_dir.join("root.ed25519.key"),
        &root_ed
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("root ed pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("root.mldsa65.key"),
        &root_ml
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("root ml pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("ia.ed25519.key"),
        &ia_ed
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("ia ed pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("ia.mldsa65.key"),
        &ia_ml
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("ia ml pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("status.ed25519.key"),
        &status_ed
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("status ed pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("status.mldsa65.key"),
        &status_ml
            .private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("status ml pkcs8"))?,
    )?;
    write_secret_new(
        &ca_dir.join("outer-ca.key"),
        &outer_ca_key
            .private_key_to_pem_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("outer ca key pem"))?,
    )?;

    write_public_atomic(
        &ca_dir.join("net_id.hex"),
        hex_encode(&params.net_id).as_bytes(),
    )?;
    write_public_atomic(
        &ca_dir.join("issuer.generation"),
        params.issuer_generation.to_string().as_bytes(),
    )?;
    write_public_atomic(&ca_dir.join("ia.ed25519.pub.der"), &ia_ed_pub)?;
    write_public_atomic(&ca_dir.join("ia.mldsa65.pub.der"), &ia_ml_pub)?;
    write_public_atomic(&ca_dir.join("status.ed25519.pub.der"), &status_ed_pub)?;
    write_public_atomic(&ca_dir.join("status.mldsa65.pub.der"), &status_ml_pub)?;
    write_public_atomic(
        &ca_dir.join("identity-ca.pem"),
        &ia_ca_cert
            .to_pem()
            .map_err(|_| ProvisionError::OpenSsl("ia ca pem"))?,
    )?;
    write_public_atomic(
        &ca_dir.join("outer-ca.pem"),
        &outer_ca_cert
            .to_pem()
            .map_err(|_| ProvisionError::OpenSsl("outer ca pem"))?,
    )?;
    write_public_atomic(&ca_dir.join("roots.cbor"), &roots_bytes)?;

    Ok(CaInitSummary {
        net_id_hex: hex_encode(&params.net_id),
        root_fingerprint_hex: hex_encode(&root_fp),
        issuer_generation: params.issuer_generation,
        expires_us,
    })
}

/// Issue an offline node material bundle (`Core` or `Edge`) without copying any CA secret.
pub fn issue_node_dir(
    ca_dir: &Path,
    out_dir: &Path,
    params: &NodeIssueParams,
) -> Result<NodeIssueSummary, ProvisionError> {
    if params.identity_generation == 0 {
        return Err(ProvisionError::InvalidParameter(
            "identity_generation must be non-zero",
        ));
    }
    if params.validity_hours == 0 || params.validity_hours > 24 * 3650 {
        return Err(ProvisionError::InvalidParameter(
            "validity_hours must be in 1..=87600",
        ));
    }
    if params.role == NodeRole::EnrollmentService {
        return Err(ProvisionError::InvalidParameter(
            "offline node issuance supports Core or Edge only",
        ));
    }
    let computed_node_id =
        node_id(params.home_core_id, params.vip_octet, params.role).map_err(|_| {
            ProvisionError::InvalidParameter("invalid home_core_id or vip_octet for role")
        })?;
    let vip = expected_vip(params.home_core_id, params.vip_octet, params.role)
        .map_err(|_| ProvisionError::InvalidParameter("invalid permanent VIP slot"))?;

    if let Some(san) = &params.outer_san_dns
        && !valid_dns_san(san)
    {
        return Err(ProvisionError::InvalidParameter(
            "outer_san_dns must be a valid ASCII DNS hostname",
        ));
    }

    ensure_private_dir(out_dir)?;
    if out_dir.join("identity.key").exists() || out_dir.join("local.signed").exists() {
        return Err(ProvisionError::AlreadyExists);
    }

    let net_id = read_net_id_hex(&ca_dir.join("net_id.hex"))?;
    let issuer_generation = read_u64_ascii(&ca_dir.join("issuer.generation"))?;
    let ia_ed_pkcs8 = read_bounded(&ca_dir.join("ia.ed25519.key"))?;
    let ia_ml_pkcs8 = read_bounded(&ca_dir.join("ia.mldsa65.key"))?;
    let ia_ca_pem = read_bounded(&ca_dir.join("identity-ca.pem"))?;
    let outer_ca_pem = read_bounded(&ca_dir.join("outer-ca.pem"))?;
    let roots_cbor = read_bounded(&ca_dir.join("roots.cbor"))?;
    let ia_ed_pub = read_bounded(&ca_dir.join("ia.ed25519.pub.der"))?;
    let ia_ml_pub = read_bounded(&ca_dir.join("ia.mldsa65.pub.der"))?;

    let ia_ca_cert =
        X509::from_pem(&ia_ca_pem).map_err(|_| ProvisionError::OpenSsl("parse identity-ca.pem"))?;
    let ia_ml_key = PKey::private_key_from_der(&ia_ml_pkcs8)
        .map_err(|_| ProvisionError::OpenSsl("parse ia mldsa key"))?;
    let authority = IdentityAuthority::from_pkcs8_der(
        net_id,
        IA_KEY_ID.to_vec(),
        issuer_generation,
        &ia_ed_pkcs8,
        &ia_ml_pkcs8,
    )?;

    let not_before_us = params.now_us.saturating_sub(60_000_000);
    let expires_us = params
        .now_us
        .checked_add(u64::from(params.validity_hours) * 3_600 * 1_000_000)
        .ok_or(ProvisionError::InvalidParameter("validity_hours overflow"))?;

    // Local node keys (unique per node, never shared).
    let node_ml_key = generate_mldsa65()?;
    let node_ed_key = generate_ed25519()?;
    let node_ed_pub: [u8; 32] = node_ed_key
        .raw_public_key()
        .map_err(|_| ProvisionError::OpenSsl("node ed25519 raw pub"))?
        .try_into()
        .map_err(|_| ProvisionError::OpenSsl("node ed25519 pub len"))?;

    let cn = format!("node-{computed_node_id}.boreas.internal");
    let csr_der = build_mldsa65_csr(&node_ml_key, &cn)?;
    let leaf_cert = build_mldsa65_leaf_cert(
        &node_ml_key,
        &ia_ca_cert,
        &ia_ml_key,
        &cn,
        params.now_us,
        expires_us,
    )?;
    let leaf_pem = leaf_cert
        .to_pem()
        .map_err(|_| ProvisionError::OpenSsl("leaf cert pem"))?;
    let node_ml_pem = node_ml_key
        .private_key_to_pem_pkcs8()
        .map_err(|_| ProvisionError::OpenSsl("node mldsa pem"))?;

    // Cross-check with boreas-crypto's strict PemIdentity validator immediately.
    let pem_id = PemIdentity {
        certificate_pem: leaf_pem.clone(),
        private_key_pem: node_ml_pem.clone(),
        trust_anchor_pem: ia_ca_pem.clone(),
    };
    let _ = OpenSslAcceptor::from_pem_identity(&pem_id, Policy::production_default())
        .map_err(|_| ProvisionError::CryptoIdentity)?;

    let body = authority.node_identity_from_csr(
        IdentityTemplate {
            node_id: computed_node_id,
            home_core_id: params.home_core_id,
            vip_octet: params.vip_octet,
            role: params.role,
            identity_generation: params.identity_generation,
            identity_pub_ed25519: node_ed_pub,
            not_before_us,
            expires_us,
            scope: Vec::new(),
        },
        &csr_der,
    )?;
    let signed_identity = authority.sign_node_identity(body)?;
    let signed_identity_bytes = signed_identity
        .encode()
        .map_err(|_| ProvisionError::OpenSsl("encode signed NodeIdentity"))?;

    // Write node secrets and public verification files.
    write_secret_new(&out_dir.join("identity.key"), &node_ml_pem)?;
    write_secret_new(
        &out_dir.join("identity.ed25519.key"),
        &node_ed_key
            .private_key_to_pem_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("node ed25519 pem"))?,
    )?;
    write_public_atomic(&out_dir.join("identity.pem"), &leaf_pem)?;
    write_public_atomic(&out_dir.join("identity-ca.pem"), &ia_ca_pem)?;
    write_public_atomic(&out_dir.join("outer-ca.pem"), &outer_ca_pem)?;
    write_public_atomic(&out_dir.join("roots.cbor"), &roots_cbor)?;
    write_public_atomic(&out_dir.join("local.signed"), &signed_identity_bytes)?;
    // Legacy compatibility files for `node serve`/`node connect` one-hop tests:
    write_public_atomic(&out_dir.join("issuer.key-id"), IA_KEY_ID)?;
    write_public_atomic(
        &out_dir.join("issuer.generation"),
        issuer_generation.to_string().as_bytes(),
    )?;
    write_public_atomic(&out_dir.join("issuer.ed25519.der"), &ia_ed_pub)?;
    write_public_atomic(&out_dir.join("issuer.mldsa.der"), &ia_ml_pub)?;

    if params.role == NodeRole::Core
        && let Some(san_dns) = &params.outer_san_dns
    {
        let outer_ca_cert = X509::from_pem(&outer_ca_pem)
            .map_err(|_| ProvisionError::OpenSsl("parse outer-ca.pem"))?;
        let outer_ca_key_pem = read_bounded(&ca_dir.join("outer-ca.key"))?;
        let outer_ca_key = PKey::private_key_from_pem(&outer_ca_key_pem)
            .map_err(|_| ProvisionError::OpenSsl("parse outer-ca.key"))?;
        let outer_leaf_key = generate_p256()?;
        let outer_leaf_cert = build_p256_leaf_cert(
            &outer_leaf_key,
            &outer_ca_cert,
            &outer_ca_key,
            san_dns,
            params.now_us,
            expires_us,
        )?;
        write_secret_new(
            &out_dir.join("outer.key"),
            &outer_leaf_key
                .private_key_to_pem_pkcs8()
                .map_err(|_| ProvisionError::OpenSsl("outer leaf key pem"))?,
        )?;
        write_public_atomic(
            &out_dir.join("outer.pem"),
            &outer_leaf_cert
                .to_pem()
                .map_err(|_| ProvisionError::OpenSsl("outer leaf cert pem"))?,
        )?;
    }

    // Issue an initial fresh StatusSnapshot (default 1 hour, strictly <= 24h per §3.4).
    let status_ttl_secs = (u64::from(params.validity_hours) * 3600).min(3600);
    sign_status_file(
        ca_dir,
        &out_dir.join("status.signed"),
        1,
        params.now_us,
        status_ttl_secs,
    )?;

    Ok(NodeIssueSummary {
        net_id_hex: hex_encode(&net_id),
        node_id: computed_node_id,
        role: params.role,
        home_core_id: params.home_core_id,
        vip,
        identity_generation: params.identity_generation,
        expires_us,
    })
}

/// Sign a canonical `StatusSnapshot` (`Ed25519 + ML-DSA-65` AND) with `StatusSigner`.
/// Enforces §3.4: `next_update - issued_at <= 24 h` (`86_400 s`).
pub fn sign_status_file(
    ca_dir: &Path,
    out_file: &Path,
    sequence: u64,
    now_us: u64,
    ttl_seconds: u64,
) -> Result<StatusSnapshotSummary, ProvisionError> {
    if sequence == 0 {
        return Err(ProvisionError::InvalidParameter(
            "status sequence must be non-zero",
        ));
    }
    if ttl_seconds == 0 || ttl_seconds > 86_400 {
        return Err(ProvisionError::StatusWindowInvalid);
    }
    let span_us = ttl_seconds
        .checked_mul(1_000_000)
        .ok_or(ProvisionError::StatusWindowInvalid)?;
    if span_us > STATUS_MAX_AGE_US {
        return Err(ProvisionError::StatusWindowInvalid);
    }
    let next_update_us = now_us
        .checked_add(span_us)
        .ok_or(ProvisionError::StatusWindowInvalid)?;

    let net_id = read_net_id_hex(&ca_dir.join("net_id.hex"))?;
    let issuer_generation = read_u64_ascii(&ca_dir.join("issuer.generation"))?;
    let status_ed_pkcs8 = read_bounded(&ca_dir.join("status.ed25519.key"))?;
    let status_ml_pkcs8 = read_bounded(&ca_dir.join("status.mldsa65.key"))?;
    let status_ed = PKey::private_key_from_der(&status_ed_pkcs8)
        .map_err(|_| ProvisionError::OpenSsl("parse status ed key"))?;
    let status_ml = PKey::private_key_from_der(&status_ml_pkcs8)
        .map_err(|_| ProvisionError::OpenSsl("parse status ml key"))?;
    if !status_ed.is_a(KeyType::ED25519) || !status_ml.is_a(KeyType::ML_DSA_65) {
        return Err(ProvisionError::OpenSsl("status signer key type mismatch"));
    }

    let envelope = ManagementObject {
        net_id,
        issuer_key_id: STATUS_KEY_ID.to_vec(),
        issuer_generation,
        subject_identity: SubjectIdentity::Network,
        seq: sequence,
        issued_at: now_us,
        expires: next_update_us,
        extensions: Vec::new(),
        body: ObjectBody::StatusSnapshot(StatusSnapshot {
            issued_at: now_us,
            next_update: next_update_us,
            sequence,
            revocations: Vec::new(),
        }),
    };
    let raw_tbs =
        objects::encode_tbs(&envelope).map_err(|_| ProvisionError::OpenSsl("encode status tbs"))?;
    let sig_msg = objects::signature_input(
        &raw_tbs,
        ObjectType::StatusSnapshot,
        MANAGEMENT_SCHEMA_VERSION,
    )
    .map_err(|_| ProvisionError::OpenSsl("status sig input"))?;
    let (ed_sig, ml_sig) = dual_sign(&sig_msg, &status_ed, &status_ml)?;
    let signed = SignedObject {
        object_type: ObjectType::StatusSnapshot,
        raw_tbs,
        signers: vec![SignerSignatures {
            role: SignerRole::Primary,
            ed25519: ed_sig,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa: ml_sig,
        }],
    };
    let encoded = signed
        .encode()
        .map_err(|_| ProvisionError::OpenSsl("encode signed StatusSnapshot"))?;
    write_public_atomic(out_file, &encoded)?;

    Ok(StatusSnapshotSummary {
        net_id_hex: hex_encode(&net_id),
        sequence,
        issued_at_us: now_us,
        next_update_us,
    })
}

/// Sign a canonical `NetworkPolicyCandidate` (`Ed25519 + ML-DSA-65` AND) under the
/// offline `NetworkRoot` keys in `ca_dir` and write the five public verification
/// artifacts (`tbs.cbor`, `ed25519.sig`, `mldsa65.sig`, `root-ed25519.der`,
/// `root-mldsa65.der`) into `out_dir`. Private keys never leave `ca_dir`.
pub fn sign_network_policy_dir(
    ca_dir: &Path,
    out_dir: &Path,
    sequence: u64,
    now_us: u64,
    ttl_seconds: u64,
) -> Result<NetworkPolicySummary, ProvisionError> {
    sign_network_policy_dir_for_overlay(
        ca_dir,
        out_dir,
        sequence,
        now_us,
        ttl_seconds,
        crate::OverlayPrefix::DEFAULT,
    )
}

/// Sign a policy candidate for an explicit offline overlay. This does not
/// install it, change an existing policy watermark, or authorize runtime use.
pub fn sign_network_policy_dir_for_overlay(
    ca_dir: &Path,
    out_dir: &Path,
    sequence: u64,
    now_us: u64,
    ttl_seconds: u64,
    overlay: crate::OverlayPrefix,
) -> Result<NetworkPolicySummary, ProvisionError> {
    if sequence == 0 {
        return Err(ProvisionError::InvalidParameter(
            "network policy sequence must be non-zero",
        ));
    }
    if ttl_seconds == 0 || ttl_seconds > 3650 * 86_400 {
        return Err(ProvisionError::InvalidParameter(
            "network policy ttl_seconds must be in 1..=315360000",
        ));
    }
    let span_us = ttl_seconds
        .checked_mul(1_000_000)
        .ok_or(ProvisionError::InvalidParameter("ttl_seconds overflow"))?;
    let issued_at_us = now_us.saturating_sub(1_000_000);
    let expires_us = now_us
        .checked_add(span_us)
        .ok_or(ProvisionError::InvalidParameter("expires_us overflow"))?;

    let net_id = read_net_id_hex(&ca_dir.join("net_id.hex"))?;
    let root_ed_pkcs8 = read_bounded(&ca_dir.join("root.ed25519.key"))?;
    let root_ml_pkcs8 = read_bounded(&ca_dir.join("root.mldsa65.key"))?;
    let root_ed = PKey::private_key_from_der(&root_ed_pkcs8)
        .map_err(|_| ProvisionError::OpenSsl("parse root ed25519 key"))?;
    let root_ml = PKey::private_key_from_der(&root_ml_pkcs8)
        .map_err(|_| ProvisionError::OpenSsl("parse root mldsa65 key"))?;
    if !root_ed.is_a(KeyType::ED25519) || !root_ml.is_a(KeyType::ML_DSA_65) {
        return Err(ProvisionError::OpenSsl("root key type mismatch"));
    }
    let root_ed_pub = root_ed
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("root ed25519 pub der"))?;
    let root_ml_pub = root_ml
        .public_key_to_der()
        .map_err(|_| ProvisionError::OpenSsl("root mldsa65 pub der"))?;
    let pin = NetworkRootPin::provisioned(
        net_id,
        root_ed_pub.clone(),
        MldsaParameterSet::Mldsa65,
        root_ml_pub.clone(),
    )?;
    let root_fp = pin.fingerprint()?;

    let candidate = NetworkPolicyCandidate {
        net_id,
        root_key_fingerprint: root_fp,
        overlay_base: overlay.base(),
        version: 1,
        seq: sequence,
        issued_at: issued_at_us,
        expires: expires_us,
    };
    let raw_tbs = candidate
        .encode_tbs()
        .map_err(|_| ProvisionError::OpenSsl("encode network policy tbs"))?;
    let sig_msg = NetworkPolicyCandidate::signature_input(&raw_tbs)
        .map_err(|_| ProvisionError::OpenSsl("network policy sig input"))?;
    let (ed_sig, ml_sig) = dual_sign(&sig_msg, &root_ed, &root_ml)?;

    // Self-verify against the constructed root pin before publishing to out_dir.
    crate::verify_network_policy(&raw_tbs, &ed_sig, &ml_sig, &pin, net_id, now_us)
        .map_err(|_| ProvisionError::OpenSsl("verify generated network policy"))?;

    if overlay == crate::OverlayPrefix::DEFAULT {
        ensure_private_dir(out_dir)?;
    } else {
        // A migration candidate must never replace installed policy inputs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(out_dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(out_dir)?;
    }
    write_public_atomic(&out_dir.join("tbs.cbor"), &raw_tbs)?;
    write_public_atomic(&out_dir.join("ed25519.sig"), &ed_sig)?;
    write_public_atomic(&out_dir.join("mldsa65.sig"), &ml_sig)?;
    write_public_atomic(&out_dir.join("root-ed25519.der"), &root_ed_pub)?;
    write_public_atomic(&out_dir.join("root-mldsa65.der"), &root_ml_pub)?;

    Ok(NetworkPolicySummary {
        net_id_hex: hex_encode(&net_id),
        root_fingerprint_hex: hex_encode(&root_fp),
        sequence,
        issued_at_us,
        expires_us,
    })
}

/// Verify a node material directory end-to-end from `roots_path` (`roots.cbor`):
/// `NetworkRoot` -> `RootAuthorization` -> (`IdentityAuthority` + `StatusSigner`) ->
/// (`local.signed` + optional `peer.signed` + `status.signed`) -> ML-DSA-65 TLS leaf SPKI match.
pub fn verify_material_dir_with_roots(
    material_dir: &Path,
    roots_path: &Path,
    expected_net_id: Option<[u8; 16]>,
    now_us: u64,
    require_peer: bool,
) -> Result<VerifiedBundle, ProvisionError> {
    let roots_raw = read_bounded(roots_path)?;
    let roots_bundle = RootsBundle::decode(&roots_raw)?;
    let net_id = match expected_net_id {
        Some(expected) if expected != roots_bundle.net_id => {
            return Err(ProvisionError::WrongNetwork);
        }
        Some(expected) => expected,
        None => roots_bundle.net_id,
    };
    let (root_fingerprint, authorizations) = roots_bundle.verify_all(net_id, now_us)?;

    let mut has_ia = false;
    let mut has_status = false;
    let mut trust = ManagementTrust::new(net_id);
    for auth in authorizations {
        match auth.authority() {
            Authority::IdentityAuthority => has_ia = true,
            Authority::StatusSigner => has_status = true,
            _ => {}
        }
        trust.add_verified_issuer(&auth)?;
    }
    if !has_ia {
        return Err(ProvisionError::MissingAuthority("IdentityAuthority"));
    }
    if !has_status {
        return Err(ProvisionError::MissingAuthority("StatusSigner"));
    }

    // Verify local TLS PEM identity and extract leaf raw ML-DSA-65 public key.
    let pem = PemIdentity::from_pem_files(
        material_dir.join("identity.pem"),
        material_dir.join("identity.key"),
        material_dir.join("identity-ca.pem"),
    )
    .map_err(|_| ProvisionError::CryptoIdentity)?;
    let leaf_cert =
        X509::from_pem(&pem.certificate_pem).map_err(|_| ProvisionError::CryptoIdentity)?;
    let leaf_mldsa_raw = leaf_cert
        .public_key()
        .map_err(|_| ProvisionError::CryptoIdentity)?
        .raw_public_key()
        .map_err(|_| ProvisionError::CryptoIdentity)?;

    let local_raw = read_bounded(&material_dir.join("local.signed"))?;
    let local = trust.verify_and_authorize(&local_raw, now_us)?;
    let ObjectBody::NodeIdentity(local_body) = &local.object().body else {
        return Err(ProvisionError::InvalidParameter(
            "local.signed is not a NodeIdentity",
        ));
    };
    if local_body.identity_pub_mldsa != leaf_mldsa_raw {
        return Err(ProvisionError::SpkiMismatch);
    }

    let peer_path = material_dir.join("peer.signed");
    let peer = if peer_path.exists() || require_peer {
        let peer_raw = read_bounded(&peer_path)?;
        let verified_peer = trust.verify_and_authorize(&peer_raw, now_us)?;
        let ObjectBody::NodeIdentity(peer_body) = &verified_peer.object().body else {
            return Err(ProvisionError::InvalidParameter(
                "peer.signed is not a NodeIdentity",
            ));
        };
        if peer_body.node_id == local_body.node_id {
            return Err(ProvisionError::InvalidParameter(
                "peer.signed has the same node_id as local.signed",
            ));
        }
        Some(verified_peer)
    } else {
        None
    };

    let status =
        verify_status_file_against_trust(&mut trust, &material_dir.join("status.signed"), now_us)?;

    Ok(VerifiedBundle {
        net_id,
        root_fingerprint,
        local,
        peer,
        status_sequence: status.sequence,
        status_issued_at_us: status.issued_at,
        status_next_update_us: status.next_update,
        status_valid_until_us: status.valid_until,
    })
}

/// Convenience wrapper verifying `material_dir/roots.cbor`.
pub fn verify_material_dir(
    material_dir: &Path,
    now_us: u64,
    require_peer: bool,
) -> Result<VerifiedBundle, ProvisionError> {
    verify_material_dir_with_roots(
        material_dir,
        &material_dir.join("roots.cbor"),
        None,
        now_us,
        require_peer,
    )
}

/// Build the status-signing `ManagementTrust` from `roots_path` at `now_us`.
///
/// This is the single roots-to-trust construction used by both the one-shot
/// status verifier and the durable `StatusStore` owner. It requires an
/// authorized `StatusSigner` and retains its verified grant window; it does
/// not read or grant freshness for any status file.
pub fn status_trust_from_roots(
    roots_path: &Path,
    expected_net_id: [u8; 16],
    now_us: u64,
) -> Result<ManagementTrust, ProvisionError> {
    let roots_raw = read_bounded(roots_path)?;
    let roots_bundle = RootsBundle::decode(&roots_raw)?;
    let (_, authorizations) = roots_bundle.verify_all(expected_net_id, now_us)?;
    let mut trust = ManagementTrust::new(expected_net_id);
    let mut has_status = false;
    for auth in authorizations {
        if auth.authority() == Authority::StatusSigner {
            has_status = true;
        }
        trust.add_verified_issuer(&auth)?;
    }
    if !has_status {
        return Err(ProvisionError::MissingAuthority("StatusSigner"));
    }
    Ok(trust)
}

/// Read `status.signed` with the same bounded reader used by provisioning.
///
/// The caller must still verify these exact bytes; this helper exists so the
/// daemon's durable status owner does not add an unbounded `fs::read`.
pub fn read_status_snapshot_raw(status_path: &Path) -> Result<Vec<u8>, ProvisionError> {
    read_bounded(status_path)
}

/// Re-verify `status.signed` from `roots_path` at `now_us`.
/// Returns `(sequence, issued_at, valid_until)` in which the exclusive UTC
/// cutoff is the earlier of signed `next_update` and the verified grant expiry.
pub fn verify_status_freshness_from_roots(
    roots_path: &Path,
    status_path: &Path,
    expected_net_id: [u8; 16],
    now_us: u64,
) -> Result<(u64, u64, u64), ProvisionError> {
    let mut trust = status_trust_from_roots(roots_path, expected_net_id, now_us)?;
    let status = verify_status_file_against_trust(&mut trust, status_path, now_us)?;
    Ok((status.sequence, status.issued_at, status.valid_until))
}

struct VerifiedStatusWindow {
    sequence: u64,
    issued_at: u64,
    next_update: u64,
    valid_until: u64,
}

fn verify_status_file_against_trust(
    trust: &mut ManagementTrust,
    status_path: &Path,
    now_us: u64,
) -> Result<VerifiedStatusWindow, ProvisionError> {
    let status_raw = read_bounded(status_path)?;
    let verified = trust.verify_and_authorize(&status_raw, now_us)?;
    let obj = verified.object();
    if obj.subject_identity != SubjectIdentity::Network {
        return Err(ProvisionError::InvalidParameter(
            "StatusSnapshot subject must be Network",
        ));
    }
    let ObjectBody::StatusSnapshot(body) = &obj.body else {
        return Err(ProvisionError::InvalidParameter(
            "status.signed is not a StatusSnapshot",
        ));
    };
    if obj.seq != body.sequence
        || obj.issued_at != body.issued_at
        || obj.expires != body.next_update
    {
        return Err(ProvisionError::InvalidParameter(
            "StatusSnapshot envelope/body mismatch",
        ));
    }
    if body.issued_at >= body.next_update || body.next_update - body.issued_at > STATUS_MAX_AGE_US {
        return Err(ProvisionError::StatusWindowInvalid);
    }
    let valid_until = verified.valid_until();
    if now_us < body.issued_at || now_us >= valid_until {
        return Err(ProvisionError::StatusExpired);
    }
    Ok(VerifiedStatusWindow {
        sequence: body.sequence,
        issued_at: body.issued_at,
        next_update: body.next_update,
        valid_until,
    })
}

// --- Cryptographic & X.509 helpers -------------------------------------------

fn generate_ed25519() -> Result<PKey<Private>, ProvisionError> {
    PKey::generate_ed25519().map_err(|_| ProvisionError::OpenSsl("generate Ed25519"))
}

fn generate_mldsa65() -> Result<PKey<Private>, ProvisionError> {
    let mut seed = [0u8; 32];
    rand_bytes(&mut seed).map_err(|_| ProvisionError::OpenSsl("CSPRNG for ML-DSA-65 seed"))?;
    if seed == [0u8; 32] {
        return Err(ProvisionError::OpenSsl("degenerate zero seed"));
    }
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &seed)
        .map_err(|_| ProvisionError::OpenSsl("generate ML-DSA-65 from CSPRNG seed"))
}

fn generate_p256() -> Result<PKey<Private>, ProvisionError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|_| ProvisionError::OpenSsl("P-256 group"))?;
    let ec = EcKey::generate(&group).map_err(|_| ProvisionError::OpenSsl("generate P-256"))?;
    PKey::from_ec_key(ec).map_err(|_| ProvisionError::OpenSsl("wrap P-256 PKey"))
}

fn random_serial() -> Result<Asn1Integer, ProvisionError> {
    let mut raw = [0u8; 16];
    rand_bytes(&mut raw).map_err(|_| ProvisionError::OpenSsl("serial CSPRNG"))?;
    raw[0] &= 0x7f;
    raw[0] |= 0x01;
    let bn = BigNum::from_slice(&raw).map_err(|_| ProvisionError::OpenSsl("serial BigNum"))?;
    bn.to_asn1_integer()
        .map_err(|_| ProvisionError::OpenSsl("serial Asn1Integer"))
}

fn asn1_time_from_us(us: u64) -> Result<Asn1Time, ProvisionError> {
    let secs = i64::try_from(us / 1_000_000)
        .map_err(|_| ProvisionError::InvalidParameter("timestamp out of i64 range"))?;
    Asn1Time::from_unix(secs).map_err(|_| ProvisionError::OpenSsl("Asn1Time::from_unix"))
}

fn build_mldsa65_csr(key: &PKey<Private>, cn: &str) -> Result<Vec<u8>, ProvisionError> {
    let mut name = X509NameBuilder::new().map_err(|_| ProvisionError::OpenSsl("X509Name"))?;
    name.append_entry_by_text("CN", cn)
        .map_err(|_| ProvisionError::OpenSsl("CSR CN"))?;
    let name = name.build();
    let mut req = X509ReqBuilder::new().map_err(|_| ProvisionError::OpenSsl("X509ReqBuilder"))?;
    req.set_version(0)
        .map_err(|_| ProvisionError::OpenSsl("CSR version"))?;
    req.set_subject_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("CSR subject"))?;
    req.set_pubkey(key)
        .map_err(|_| ProvisionError::OpenSsl("CSR pubkey"))?;
    req.sign(key, MessageDigest::null())
        .map_err(|_| ProvisionError::OpenSsl("CSR ML-DSA-65 sign"))?;
    req.build()
        .to_der()
        .map_err(|_| ProvisionError::OpenSsl("CSR DER"))
}

fn build_mldsa65_ca_cert(
    ca_key: &PKey<Private>,
    cn: &str,
    now_us: u64,
    expires_us: u64,
) -> Result<X509, ProvisionError> {
    let mut name = X509NameBuilder::new().map_err(|_| ProvisionError::OpenSsl("CA X509Name"))?;
    name.append_entry_by_text("CN", cn)
        .map_err(|_| ProvisionError::OpenSsl("CA CN"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|_| ProvisionError::OpenSsl("CA X509Builder"))?;
    builder
        .set_version(2)
        .map_err(|_| ProvisionError::OpenSsl("CA v3"))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|_| ProvisionError::OpenSsl("CA serial"))?;
    builder
        .set_subject_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("CA subject"))?;
    builder
        .set_issuer_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("CA issuer"))?;
    builder
        .set_pubkey(ca_key)
        .map_err(|_| ProvisionError::OpenSsl("CA pubkey"))?;
    let nb = asn1_time_from_us(now_us.saturating_sub(300_000_000))?;
    let na = asn1_time_from_us(expires_us)?;
    builder
        .set_not_before(&nb)
        .map_err(|_| ProvisionError::OpenSsl("CA not_before"))?;
    builder
        .set_not_after(&na)
        .map_err(|_| ProvisionError::OpenSsl("CA not_after"))?;

    let bc = BasicConstraints::new()
        .critical()
        .ca()
        .pathlen(0)
        .build()
        .map_err(|_| ProvisionError::OpenSsl("CA BasicConstraints"))?;
    builder
        .append_extension(bc)
        .map_err(|_| ProvisionError::OpenSsl("append CA BasicConstraints"))?;
    let ku = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("CA KeyUsage"))?;
    builder
        .append_extension(ku)
        .map_err(|_| ProvisionError::OpenSsl("append CA KeyUsage"))?;
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(|_| ProvisionError::OpenSsl("CA SKI"))?;
    builder
        .append_extension(ski)
        .map_err(|_| ProvisionError::OpenSsl("append CA SKI"))?;

    builder
        .sign(ca_key, MessageDigest::null())
        .map_err(|_| ProvisionError::OpenSsl("sign ML-DSA-65 CA"))?;
    Ok(builder.build())
}

fn build_mldsa65_leaf_cert(
    leaf_key: &PKey<Private>,
    ca_cert: &X509Ref,
    ca_key: &PKey<Private>,
    cn: &str,
    now_us: u64,
    expires_us: u64,
) -> Result<X509, ProvisionError> {
    let mut name = X509NameBuilder::new().map_err(|_| ProvisionError::OpenSsl("leaf X509Name"))?;
    name.append_entry_by_text("CN", cn)
        .map_err(|_| ProvisionError::OpenSsl("leaf CN"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|_| ProvisionError::OpenSsl("leaf X509Builder"))?;
    builder
        .set_version(2)
        .map_err(|_| ProvisionError::OpenSsl("leaf v3"))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|_| ProvisionError::OpenSsl("leaf serial"))?;
    builder
        .set_subject_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("leaf subject"))?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(|_| ProvisionError::OpenSsl("leaf issuer"))?;
    builder
        .set_pubkey(leaf_key)
        .map_err(|_| ProvisionError::OpenSsl("leaf pubkey"))?;
    let nb = asn1_time_from_us(now_us.saturating_sub(300_000_000))?;
    let na = asn1_time_from_us(expires_us)?;
    builder
        .set_not_before(&nb)
        .map_err(|_| ProvisionError::OpenSsl("leaf not_before"))?;
    builder
        .set_not_after(&na)
        .map_err(|_| ProvisionError::OpenSsl("leaf not_after"))?;

    let bc = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("leaf BasicConstraints"))?;
    builder
        .append_extension(bc)
        .map_err(|_| ProvisionError::OpenSsl("append leaf BasicConstraints"))?;
    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("leaf KeyUsage"))?;
    builder
        .append_extension(ku)
        .map_err(|_| ProvisionError::OpenSsl("append leaf KeyUsage"))?;
    let eku = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("leaf EKU"))?;
    builder
        .append_extension(eku)
        .map_err(|_| ProvisionError::OpenSsl("append leaf EKU"))?;
    let san = SubjectAlternativeName::new()
        .dns(cn)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|_| ProvisionError::OpenSsl("leaf SAN"))?;
    builder
        .append_extension(san)
        .map_err(|_| ProvisionError::OpenSsl("append leaf SAN"))?;
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|_| ProvisionError::OpenSsl("leaf SKI"))?;
    builder
        .append_extension(ski)
        .map_err(|_| ProvisionError::OpenSsl("append leaf SKI"))?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|_| ProvisionError::OpenSsl("leaf AKI"))?;
    builder
        .append_extension(aki)
        .map_err(|_| ProvisionError::OpenSsl("append leaf AKI"))?;

    builder
        .sign(ca_key, MessageDigest::null())
        .map_err(|_| ProvisionError::OpenSsl("sign ML-DSA-65 leaf"))?;
    Ok(builder.build())
}

fn build_p256_ca_cert(
    ca_key: &PKey<Private>,
    cn: &str,
    now_us: u64,
    expires_us: u64,
) -> Result<X509, ProvisionError> {
    let mut name = X509NameBuilder::new().map_err(|_| ProvisionError::OpenSsl("outer CA name"))?;
    name.append_entry_by_text("CN", cn)
        .map_err(|_| ProvisionError::OpenSsl("outer CA CN"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|_| ProvisionError::OpenSsl("outer CA builder"))?;
    builder
        .set_version(2)
        .map_err(|_| ProvisionError::OpenSsl("outer CA v3"))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|_| ProvisionError::OpenSsl("outer CA serial"))?;
    builder
        .set_subject_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("outer CA subject"))?;
    builder
        .set_issuer_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("outer CA issuer"))?;
    builder
        .set_pubkey(ca_key)
        .map_err(|_| ProvisionError::OpenSsl("outer CA pubkey"))?;
    let nb = asn1_time_from_us(now_us.saturating_sub(300_000_000))?;
    let na = asn1_time_from_us(expires_us)?;
    builder
        .set_not_before(&nb)
        .map_err(|_| ProvisionError::OpenSsl("outer CA not_before"))?;
    builder
        .set_not_after(&na)
        .map_err(|_| ProvisionError::OpenSsl("outer CA not_after"))?;

    let bc = BasicConstraints::new()
        .critical()
        .ca()
        .pathlen(0)
        .build()
        .map_err(|_| ProvisionError::OpenSsl("outer CA BC"))?;
    builder
        .append_extension(bc)
        .map_err(|_| ProvisionError::OpenSsl("append outer CA BC"))?;
    let ku = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("outer CA KU"))?;
    builder
        .append_extension(ku)
        .map_err(|_| ProvisionError::OpenSsl("append outer CA KU"))?;
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(|_| ProvisionError::OpenSsl("outer CA SKI"))?;
    builder
        .append_extension(ski)
        .map_err(|_| ProvisionError::OpenSsl("append outer CA SKI"))?;

    builder
        .sign(ca_key, MessageDigest::sha256())
        .map_err(|_| ProvisionError::OpenSsl("sign outer CA"))?;
    Ok(builder.build())
}

fn build_p256_leaf_cert(
    leaf_key: &PKey<Private>,
    ca_cert: &X509Ref,
    ca_key: &PKey<Private>,
    san_dns: &str,
    now_us: u64,
    expires_us: u64,
) -> Result<X509, ProvisionError> {
    let mut name =
        X509NameBuilder::new().map_err(|_| ProvisionError::OpenSsl("outer leaf name"))?;
    name.append_entry_by_text("CN", san_dns)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf CN"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|_| ProvisionError::OpenSsl("outer leaf builder"))?;
    builder
        .set_version(2)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf v3"))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf serial"))?;
    builder
        .set_subject_name(&name)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf subject"))?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(|_| ProvisionError::OpenSsl("outer leaf issuer"))?;
    builder
        .set_pubkey(leaf_key)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf pubkey"))?;
    let nb = asn1_time_from_us(now_us.saturating_sub(300_000_000))?;
    let na = asn1_time_from_us(expires_us)?;
    builder
        .set_not_before(&nb)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf not_before"))?;
    builder
        .set_not_after(&na)
        .map_err(|_| ProvisionError::OpenSsl("outer leaf not_after"))?;

    let bc = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("outer leaf BC"))?;
    builder
        .append_extension(bc)
        .map_err(|_| ProvisionError::OpenSsl("append outer leaf BC"))?;
    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("outer leaf KU"))?;
    builder
        .append_extension(ku)
        .map_err(|_| ProvisionError::OpenSsl("append outer leaf KU"))?;
    let eku = ExtendedKeyUsage::new()
        .server_auth()
        .build()
        .map_err(|_| ProvisionError::OpenSsl("outer leaf EKU"))?;
    builder
        .append_extension(eku)
        .map_err(|_| ProvisionError::OpenSsl("append outer leaf EKU"))?;
    let san = SubjectAlternativeName::new()
        .dns(san_dns)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|_| ProvisionError::OpenSsl("outer leaf SAN"))?;
    builder
        .append_extension(san)
        .map_err(|_| ProvisionError::OpenSsl("append outer leaf SAN"))?;

    builder
        .sign(ca_key, MessageDigest::sha256())
        .map_err(|_| ProvisionError::OpenSsl("sign outer leaf"))?;
    Ok(builder.build())
}

fn sign_root_auth(
    candidate: &RootAuthorizationCandidate,
    root_ed: &PKey<Private>,
    root_ml: &PKey<Private>,
) -> Result<SignedRootAuthorization, ProvisionError> {
    let raw_candidate = candidate.encode_candidate()?;
    let mut msg = Vec::with_capacity(ROOT_AUTH_DOMAIN.len() + raw_candidate.len());
    msg.extend_from_slice(ROOT_AUTH_DOMAIN);
    msg.extend_from_slice(&raw_candidate);
    let (ed_sig, ml_sig) = dual_sign(&msg, root_ed, root_ml)?;
    Ok(SignedRootAuthorization {
        raw_candidate,
        ed25519_signature: ed_sig.to_vec(),
        mldsa_signature: ml_sig,
    })
}

fn dual_sign(
    message: &[u8],
    ed_key: &PKey<Private>,
    ml_key: &PKey<Private>,
) -> Result<([u8; 64], Vec<u8>), ProvisionError> {
    let mut ed_signer = Signer::new_without_digest(ed_key)
        .map_err(|_| ProvisionError::OpenSsl("Ed25519 signer"))?;
    let ed_vec = ed_signer
        .sign_oneshot_to_vec(message)
        .map_err(|_| ProvisionError::OpenSsl("Ed25519 sign"))?;
    let ed_sig: [u8; 64] = ed_vec
        .try_into()
        .map_err(|_| ProvisionError::OpenSsl("Ed25519 sig len"))?;

    let mut ml_signer =
        Signer::new_without_digest(ml_key).map_err(|_| ProvisionError::OpenSsl("ML-DSA signer"))?;
    let ml_sig = ml_signer
        .sign_oneshot_to_vec(message)
        .map_err(|_| ProvisionError::OpenSsl("ML-DSA sign"))?;
    if ml_sig.len() != MLDSA65_SIG_LEN {
        return Err(ProvisionError::OpenSsl("ML-DSA-65 sig len"));
    }
    Ok((ed_sig, ml_sig))
}

// --- Safe bounded filesystem & encoding helpers ------------------------------

fn ensure_private_dir(dir: &Path) -> Result<(), ProvisionError> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<(), ProvisionError> {
    if path.exists() {
        return Err(ProvisionError::AlreadyExists);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}

fn write_public_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp.boreas");
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ProvisionError> {
    let mut f = File::open(path)?;
    let meta = f.metadata()?;
    if meta.len() > u64::try_from(MAX_MATERIAL_FILE_BYTES).unwrap_or(u64::MAX) {
        return Err(ProvisionError::FileTooLarge);
    }
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    let mut chunk = [0u8; 8192];
    loop {
        let n = f.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > MAX_MATERIAL_FILE_BYTES {
            return Err(ProvisionError::FileTooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn read_net_id_hex(path: &Path) -> Result<[u8; 16], ProvisionError> {
    let raw = read_bounded(path)?;
    let text = core::str::from_utf8(&raw)
        .map_err(|_| ProvisionError::InvalidParameter("net_id.hex is not UTF-8"))?
        .trim();
    parse_net_id_hex(text)
}

pub fn parse_net_id_hex(text: &str) -> Result<[u8; 16], ProvisionError> {
    let cleaned = text.strip_prefix("0x").unwrap_or(text);
    if cleaned.len() != 32 {
        return Err(ProvisionError::InvalidParameter(
            "net_id hex must be exactly 32 hex digits",
        ));
    }
    let mut out = [0u8; 16];
    for (idx, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(cleaned.as_bytes()[idx * 2])?;
        let lo = hex_nibble(cleaned.as_bytes()[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    if out == [0u8; 16] {
        return Err(ProvisionError::InvalidParameter(
            "net_id cannot be all-zero",
        ));
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ProvisionError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ProvisionError::InvalidParameter("invalid hex character")),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn read_u64_ascii(path: &Path) -> Result<u64, ProvisionError> {
    let raw = read_bounded(path)?;
    let text = core::str::from_utf8(&raw)
        .map_err(|_| ProvisionError::InvalidParameter("number file is not UTF-8"))?
        .trim();
    text.parse::<u64>()
        .map_err(|_| ProvisionError::InvalidParameter("invalid u64 file"))
}

fn valid_dns_san(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreas_crypto::backend::OpenSslConnector;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "boreas-pki-prov-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn full_offline_pki_flow_roots_to_leaf_and_strict_mtls() {
        let ca = TempDir::new("ca");
        let core_dir = TempDir::new("core");
        let edge_dir = TempDir::new("edge");
        let now_us = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap();
        let net_id = [0x42; 16];

        let ca_summary = init_ca_dir(
            &ca.0,
            &CaInitParams {
                net_id,
                issuer_generation: 1,
                now_us,
                validity_days: 30,
            },
        )
        .expect("init offline CA");
        assert_eq!(ca_summary.net_id_hex.len(), 32);

        let core_summary = issue_node_dir(
            &ca.0,
            &core_dir.0,
            &NodeIssueParams {
                role: NodeRole::Core,
                home_core_id: 1,
                vip_octet: 1,
                identity_generation: 1,
                now_us,
                validity_hours: 48,
                outer_san_dns: Some("wss.boreas.test".to_string()),
            },
        )
        .expect("issue core bundle");
        assert_eq!(core_summary.node_id, 1);
        assert_eq!(core_summary.vip, [10, 20, 1, 1]);

        let edge_summary = issue_node_dir(
            &ca.0,
            &edge_dir.0,
            &NodeIssueParams {
                role: NodeRole::Edge,
                home_core_id: 1,
                vip_octet: 2,
                identity_generation: 1,
                now_us,
                validity_hours: 48,
                outer_san_dns: None,
            },
        )
        .expect("issue edge bundle");
        assert_eq!(edge_summary.node_id, 2);
        assert_eq!(edge_summary.vip, [10, 20, 1, 2]);

        // Cross-copy peer.signed (public management identities).
        fs::copy(
            core_dir.0.join("local.signed"),
            edge_dir.0.join("peer.signed"),
        )
        .unwrap();
        fs::copy(
            edge_dir.0.join("local.signed"),
            core_dir.0.join("peer.signed"),
        )
        .unwrap();

        // Neither node bundle contains CA private keys.
        assert!(!core_dir.0.join("root.ed25519.key").exists());
        assert!(!core_dir.0.join("ia.mldsa65.key").exists());
        assert!(!edge_dir.0.join("status.mldsa65.key").exists());

        // Verify both bundles strictly through roots.cbor.
        let verified_core = verify_material_dir(&core_dir.0, now_us + 1_000_000, true)
            .expect("core bundle verifies against roots.cbor");
        let verified_edge = verify_material_dir(&edge_dir.0, now_us + 1_000_000, true)
            .expect("edge bundle verifies against roots.cbor");
        assert_eq!(
            verified_core.root_fingerprint,
            verified_edge.root_fingerprint
        );
        assert_eq!(verified_core.status_sequence, 1);

        // Fail-closed when status snapshot expires (> 1h here).
        let expired_err = verify_material_dir(&edge_dir.0, now_us + 7_200 * 1_000_000, true)
            .expect_err("expired StatusSnapshot must fail closed");
        assert!(matches!(
            expired_err,
            ProvisionError::StatusExpired | ProvisionError::Management(_)
        ));

        // Fail-closed if roots.cbor belongs to a different CA.
        let rogue_ca = TempDir::new("rogue-ca");
        init_ca_dir(
            &rogue_ca.0,
            &CaInitParams {
                net_id,
                issuer_generation: 1,
                now_us,
                validity_days: 30,
            },
        )
        .unwrap();
        assert!(
            verify_material_dir_with_roots(
                &edge_dir.0,
                &rogue_ca.0.join("roots.cbor"),
                Some(net_id),
                now_us + 1_000_000,
                true,
            )
            .is_err(),
            "rogue roots.cbor must reject leaf/local.signed"
        );

        // Verify the issued pure-Rust ML-DSA-65 X.509 certificates actually complete
        // strict pq768 OpenSslConnector <-> OpenSslAcceptor mTLS over UnixStream!
        #[cfg(unix)]
        {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;
            let connector = OpenSslConnector::from_pem_files(
                edge_dir.0.join("identity.pem"),
                edge_dir.0.join("identity.key"),
                edge_dir.0.join("identity-ca.pem"),
                Policy::production_default(),
            )
            .expect("strict pq768 connector accepts pure-Rust ML-DSA-65 cert");
            let acceptor = OpenSslAcceptor::from_pem_files(
                core_dir.0.join("identity.pem"),
                core_dir.0.join("identity.key"),
                core_dir.0.join("identity-ca.pem"),
                Policy::production_default(),
            )
            .expect("strict pq768 acceptor accepts pure-Rust ML-DSA-65 cert");

            let (c_sock, s_sock) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let mut s = acceptor.accept(s_sock).expect("server mTLS accept");
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, b"ping");
                s.write_all(b"pong").unwrap();
                s.flush().unwrap();
            });
            let mut c = connector.connect(c_sock).expect("client mTLS connect");
            c.write_all(b"ping").unwrap();
            c.flush().unwrap();
            let mut reply = [0u8; 4];
            c.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"pong");
            server.join().unwrap();
        }
    }

    #[test]
    fn sign_network_policy_dir_produces_verifiable_public_bundle_without_private_keys() {
        let ca = TempDir::new("policy-ca");
        let out = TempDir::new("policy-out");
        let net_id = [0x42u8; 16];
        let now_us = 1_795_000_000_000_000u64;
        init_ca_dir(
            &ca.0,
            &CaInitParams {
                net_id,
                issuer_generation: 1,
                now_us,
                validity_days: 30,
            },
        )
        .unwrap();

        assert!(sign_network_policy_dir(&ca.0, &out.0, 0, now_us, 3600).is_err());
        assert!(sign_network_policy_dir(&ca.0, &out.0, 1, now_us, 0).is_err());

        let summary = sign_network_policy_dir(&ca.0, &out.0, 7, now_us, 3600).unwrap();
        assert_eq!(summary.sequence, 7);
        assert_eq!(summary.net_id_hex, hex_encode(&net_id));

        assert!(!out.0.join("root.ed25519.key").exists());
        assert!(!out.0.join("root.mldsa65.key").exists());

        let tbs = fs::read(out.0.join("tbs.cbor")).unwrap();
        let ed_sig = fs::read(out.0.join("ed25519.sig")).unwrap();
        let ml_sig = fs::read(out.0.join("mldsa65.sig")).unwrap();
        let ed_der = fs::read(out.0.join("root-ed25519.der")).unwrap();
        let ml_der = fs::read(out.0.join("root-mldsa65.der")).unwrap();
        let pin = NetworkRootPin::provisioned(net_id, ed_der, MldsaParameterSet::Mldsa65, ml_der)
            .unwrap();
        let verified =
            crate::verify_network_policy(&tbs, &ed_sig, &ml_sig, &pin, net_id, now_us).unwrap();
        assert_eq!(verified.seq(), 7);
        assert_eq!(verified.overlay_base(), [10, 20, 0, 0]);
    }
}
