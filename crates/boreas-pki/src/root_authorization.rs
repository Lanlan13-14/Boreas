//! Bounded NetworkRoot authorization-candidate verification.
//!
//! This is intentionally a candidate wire format, not a frozen PKI profile. It is
//! compiled only with `openssl-backend`; no caller-supplied verifier can mint trust.
#![cfg(feature = "openssl-backend")]

use std::fmt;

use openssl::{
    hash::{MessageDigest, hash},
    pkey::{KeyType, PKey},
    sign::Verifier,
};

use crate::{
    Authority, NodeRole,
    management::{AllowedPrefix, IssuerRecord, IssuerScope},
};

pub const MAX_CANDIDATE_BYTES: usize = 16 * 1024;
pub const MAX_ISSUER_ID: usize = 64;
pub const MAX_KEY_DER: usize = 4096;
pub const MAX_PREFIXES: usize = 256;
pub const MAX_CHAIN_DEPTH: u8 = 1;
const DOMAIN: &[u8] = b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0";
const ED_SIG_LEN: usize = 64;
const MLDSA65_SIG_LEN: usize = 3309;
const MLDSA87_SIG_LEN: usize = 4627;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Purpose {
    Identity = 1,
    Route = 2,
    Status = 3,
    CoreOperational = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Identity {
        roles: Vec<NodeRole>,
        home_cores: Vec<u8>,
    },
    Route {
        prefixes: Vec<AllowedPrefix>,
    },
    Status,
    CoreOperational {
        core_id: u8,
    },
}

/// Decoded candidate fields. This is untrusted input; only `verify` yields a trust token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootAuthorizationCandidate {
    pub net_id: [u8; 16],
    pub issuer_key_id: Vec<u8>,
    pub issuer_generation: u64,
    pub purpose: Purpose,
    pub ed25519_public_key_der: Vec<u8>,
    pub mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet,
    pub mldsa_public_key_der: Vec<u8>,
    pub scope: Scope,
    pub not_before: u64,
    pub expires: u64,
    /// Root authorization chains are deliberately unsupported; no implicit delegation.
    pub chain_depth: u8,
    pub may_delegate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    InvalidCandidate,
    WrongNetwork,
    InvalidTime,
    InvalidRootKey,
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

/// Separately provisioned NetworkRoot public keys; ReleaseRoot is not accepted by this API.
/// DER SubjectPublicKeyInfo bytes are parsed and algorithm checked on each verification.
#[derive(Clone, Debug)]
pub struct NetworkRootPin {
    net_id: [u8; 16],
    ed25519_public_key_der: Vec<u8>,
    mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet,
    mldsa_public_key_der: Vec<u8>,
}
impl NetworkRootPin {
    /// SHA-256 identifier for correlating the externally provisioned pin. This fingerprints
    /// public configuration only; it does not establish the pin's provenance or trustworthiness.
    pub fn fingerprint(&self) -> Result<[u8; 32], Error> {
        let mut input = b"BOREAS-NETWORK-ROOT-PIN-FINGERPRINT\0".to_vec();
        input.extend_from_slice(&(self.net_id.len() as u32).to_be_bytes());
        input.extend_from_slice(&self.net_id);
        input.push(1); // Ed25519 SPKI DER
        input.extend_from_slice(&(self.ed25519_public_key_der.len() as u32).to_be_bytes());
        input.extend_from_slice(&self.ed25519_public_key_der);
        input.push(match self.mldsa_parameter_set {
            boreas_proto::objects::MldsaParameterSet::Mldsa65 => 65,
            boreas_proto::objects::MldsaParameterSet::Mldsa87 => 87,
        });
        input.extend_from_slice(&(self.mldsa_public_key_der.len() as u32).to_be_bytes());
        input.extend_from_slice(&self.mldsa_public_key_der);
        let digest = hash(MessageDigest::sha256(), &input).map_err(|_| Error::Backend)?;
        digest.as_ref().try_into().map_err(|_| Error::Backend)
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    /// The pinned Ed25519 SubjectPublicKeyInfo DER, for in-crate verifiers that
    /// must build an OpenSSL key. This is not a trust decision on its own: the
    /// caller still verifies against this pin's fingerprint.
    pub(crate) fn ed25519_public_key_der(&self) -> &[u8] {
        &self.ed25519_public_key_der
    }

    /// The pinned ML-DSA SubjectPublicKeyInfo DER.
    pub(crate) fn mldsa_public_key_der(&self) -> &[u8] {
        &self.mldsa_public_key_der
    }

    /// The pinned ML-DSA parameter set; callers must refuse a set they do not
    /// actually verify.
    pub(crate) fn mldsa_parameter_set(&self) -> boreas_proto::objects::MldsaParameterSet {
        self.mldsa_parameter_set
    }

    /// Construct a network-purpose pin from independently provisioned public key DER.
    /// The type prevents accidental API substitution but cannot cryptographically distinguish
    /// copied ReleaseRoot DER; independent provenance is required.
    pub fn provisioned(
        net_id: [u8; 16],
        ed25519_public_key_der: Vec<u8>,
        mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet,
        mldsa_public_key_der: Vec<u8>,
    ) -> Result<Self, Error> {
        if ed25519_public_key_der.is_empty()
            || ed25519_public_key_der.len() > MAX_KEY_DER
            || mldsa_public_key_der.is_empty()
            || mldsa_public_key_der.len() > MAX_KEY_DER
        {
            return Err(Error::InvalidRootKey);
        }
        let ed = PKey::public_key_from_der(&ed25519_public_key_der)
            .map_err(|_| Error::InvalidRootKey)?;
        let pq =
            PKey::public_key_from_der(&mldsa_public_key_der).map_err(|_| Error::InvalidRootKey)?;
        if !ed.is_a(KeyType::ED25519)
            || !pq.is_a(match mldsa_parameter_set {
                boreas_proto::objects::MldsaParameterSet::Mldsa65 => KeyType::ML_DSA_65,
                boreas_proto::objects::MldsaParameterSet::Mldsa87 => KeyType::ML_DSA_87,
            })
        {
            return Err(Error::InvalidRootKey);
        }
        Ok(Self {
            net_id,
            ed25519_public_key_der,
            mldsa_parameter_set,
            mldsa_public_key_der,
        })
    }
}

/// Verify the fixed NetworkPolicy candidate against a separately provisioned root pin.
/// This is crate-private and deliberately cannot authorize any root-authorization purpose.
pub(crate) fn verify_network_policy_message(
    raw_tbs: &[u8],
    ed25519_signature: &[u8],
    mldsa_signature: &[u8],
    root: &NetworkRootPin,
    expected_net_id: [u8; 16],
    expected_fingerprint: [u8; 32],
) -> Result<(), Error> {
    if raw_tbs.len() > boreas_proto::network_policy::MAX_TBS_LEN {
        return Err(Error::TooLarge);
    }
    let candidate = boreas_proto::network_policy::NetworkPolicyCandidate::decode_tbs(raw_tbs)
        .map_err(|_| Error::InvalidCandidate)?;
    if root.net_id != expected_net_id || candidate.net_id != expected_net_id {
        return Err(Error::WrongNetwork);
    }
    if root.fingerprint()? != expected_fingerprint
        || candidate.root_key_fingerprint != expected_fingerprint
    {
        return Err(Error::InvalidRootKey);
    }
    if root.mldsa_parameter_set != boreas_proto::objects::MldsaParameterSet::Mldsa65 {
        return Err(Error::InvalidRootKey);
    }
    if ed25519_signature.len() != ED_SIG_LEN || mldsa_signature.len() != MLDSA65_SIG_LEN {
        return Err(Error::InvalidSignatureLength);
    }
    let ed_root = PKey::public_key_from_der(&root.ed25519_public_key_der)
        .map_err(|_| Error::InvalidRootKey)?;
    let pq_root =
        PKey::public_key_from_der(&root.mldsa_public_key_der).map_err(|_| Error::InvalidRootKey)?;
    if !ed_root.is_a(KeyType::ED25519) || !pq_root.is_a(KeyType::ML_DSA_65) {
        return Err(Error::InvalidRootKey);
    }
    let msg = boreas_proto::network_policy::NetworkPolicyCandidate::signature_input(raw_tbs)
        .map_err(|_| Error::InvalidCandidate)?;
    let mut ev = Verifier::new_without_digest(&ed_root).map_err(|_| Error::Backend)?;
    if !ev
        .verify_oneshot(ed25519_signature, &msg)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidEdSignature);
    }
    let mut pv = Verifier::new_without_digest(&pq_root).map_err(|_| Error::Backend)?;
    if !pv
        .verify_oneshot(mldsa_signature, &msg)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidMlDsaSignature);
    }
    Ok(())
}

/// Private-field proof. The only constructor is successful verification against a root pin.
#[derive(Clone, Debug)]
pub struct VerifiedIssuerAuthorization {
    record: IssuerRecord,
    net_id: [u8; 16],
    not_before: u64,
    expires: u64,
}
impl VerifiedIssuerAuthorization {
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }
    pub fn validity(&self) -> (u64, u64) {
        (self.not_before, self.expires)
    }
    /// Copy out a record for the existing ManagementTrust path; caller must still scope this
    /// record to the same network/context. Durable storage and rollback protection are external.
    pub fn issuer_record(&self) -> IssuerRecord {
        self.record.clone()
    }
}

impl RootAuthorizationCandidate {
    /// Decode canonical candidate CBOR. Re-encoding equality prevents alternate signed forms.
    pub fn decode_candidate(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_CANDIDATE_BYTES {
            return Err(Error::TooLarge);
        }
        let (v, used) = read_value(raw, 0)?;
        if used != raw.len() {
            return Err(Error::InvalidCandidate);
        }
        let Value::Map(fields) = v else {
            return Err(Error::InvalidCandidate);
        };
        if fields.len() != 14 || fields.iter().enumerate().any(|(i, (k, _))| *k != i as u64) {
            return Err(Error::InvalidCandidate);
        }
        let get = |key: u64| {
            fields
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v)
                .ok_or(Error::InvalidCandidate)
        };
        let version = value_uint(get(0)?)?;
        if version != 1 {
            return Err(Error::InvalidCandidate);
        }
        let net_id = value_bytes(get(1)?)?
            .try_into()
            .map_err(|_| Error::InvalidCandidate)?;
        let issuer_key_id = value_bytes(get(2)?)?.to_vec();
        let issuer_generation = value_uint(get(3)?)?;
        let purpose = match value_uint(get(4)?)? {
            1 => Purpose::Identity,
            2 => Purpose::Route,
            3 => Purpose::Status,
            4 => Purpose::CoreOperational,
            _ => return Err(Error::InvalidCandidate),
        };
        let ed25519_public_key_der = value_bytes(get(5)?)?.to_vec();
        let mldsa_parameter_set = match value_uint(get(6)?)? {
            1 => boreas_proto::objects::MldsaParameterSet::Mldsa65,
            2 => boreas_proto::objects::MldsaParameterSet::Mldsa87,
            _ => return Err(Error::InvalidCandidate),
        };
        let mldsa_public_key_der = value_bytes(get(7)?)?.to_vec();
        let scope_raw = value_bytes(get(8)?)?;
        let scope = decode_scope(purpose, scope_raw)?;
        let not_before = value_uint(get(9)?)?;
        let expires = value_uint(get(10)?)?;
        let chain_depth =
            u8::try_from(value_uint(get(11)?)?).map_err(|_| Error::InvalidCandidate)?;
        let may_delegate = match get(12)? {
            Value::Bool(value) => *value,
            _ => return Err(Error::InvalidCandidate),
        };
        if !matches!(get(13)?, Value::Array(xs) if xs.is_empty()) {
            return Err(Error::InvalidCandidate);
        }
        let candidate = Self {
            net_id,
            issuer_key_id,
            issuer_generation,
            purpose,
            ed25519_public_key_der,
            mldsa_parameter_set,
            mldsa_public_key_der,
            scope,
            not_before,
            expires,
            chain_depth,
            may_delegate,
        };
        candidate.validate()?;
        if candidate.encode_candidate()?.as_slice() != raw {
            return Err(Error::InvalidCandidate);
        }
        Ok(candidate)
    }
    /// Canonical candidate bytes signed verbatim (not parsed/re-encoded substitute bytes).
    pub fn encode_candidate(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let (purpose, scope_bytes) = encode_scope(&self.scope)?;
        let mut o = Vec::new();
        map(14, &mut o);
        uint(0, &mut o);
        uint(1, &mut o); // schema version
        uint(1, &mut o);
        bytes(&self.net_id, &mut o);
        uint(2, &mut o);
        bytes(&self.issuer_key_id, &mut o);
        uint(3, &mut o);
        uint(self.issuer_generation, &mut o);
        uint(4, &mut o);
        uint(purpose as u64, &mut o);
        uint(5, &mut o);
        bytes(&self.ed25519_public_key_der, &mut o);
        uint(6, &mut o);
        uint(self.mldsa_parameter_set as u64, &mut o);
        uint(7, &mut o);
        bytes(&self.mldsa_public_key_der, &mut o);
        uint(8, &mut o);
        bytes(&scope_bytes, &mut o);
        uint(9, &mut o);
        uint(self.not_before, &mut o);
        uint(10, &mut o);
        uint(self.expires, &mut o);
        uint(11, &mut o);
        uint(self.chain_depth as u64, &mut o);
        uint(12, &mut o);
        cbor_bool(self.may_delegate, &mut o);
        // Key 13 is reserved for candidate extensions and is currently an empty array.
        uint(13, &mut o);
        array(0, &mut o);
        if o.len() > MAX_CANDIDATE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(o)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.issuer_key_id.is_empty()
            || self.issuer_key_id.len() > MAX_ISSUER_ID
            || self.issuer_generation == 0
            || self.ed25519_public_key_der.is_empty()
            || self.ed25519_public_key_der.len() > MAX_KEY_DER
            || self.mldsa_public_key_der.is_empty()
            || self.mldsa_public_key_der.len() > MAX_KEY_DER
            || self.not_before >= self.expires
            || self.chain_depth != MAX_CHAIN_DEPTH
            || self.may_delegate
        {
            return Err(Error::InvalidCandidate);
        }
        let purpose_ok = matches!(
            (&self.purpose, &self.scope),
            (Purpose::Identity, Scope::Identity { .. })
                | (Purpose::Route, Scope::Route { .. })
                | (Purpose::Status, Scope::Status)
                | (Purpose::CoreOperational, Scope::CoreOperational { .. })
        );
        if !purpose_ok {
            return Err(Error::InvalidCandidate);
        }
        match &self.scope {
            Scope::Identity { roles, home_cores }
                if roles.is_empty()
                    || roles.len() > 3
                    || home_cores.is_empty()
                    || home_cores.len() > 16
                    || home_cores.iter().any(|x| !(1..=16).contains(x))
                    || { roles.windows(2).any(|w| (w[0] as u8) >= (w[1] as u8)) }
                    || { home_cores.windows(2).any(|w| w[0] >= w[1]) } =>
            {
                Err(Error::InvalidCandidate)
            }
            Scope::Route { prefixes }
                if prefixes.is_empty() || prefixes.len() > MAX_PREFIXES || {
                    prefixes.windows(2).any(|w| {
                        (w[0].bytes(), w[0].prefix_len()) >= (w[1].bytes(), w[1].prefix_len())
                    })
                } =>
            {
                Err(Error::InvalidCandidate)
            }
            Scope::CoreOperational { core_id } if !(1..=16).contains(core_id) => {
                Err(Error::InvalidCandidate)
            }
            _ => Ok(()),
        }
    }
}

/// Parse and verify the exact raw candidate bytes; prefer this entry point for untrusted input.
pub fn verify_raw(
    raw_candidate: &[u8],
    ed25519_signature: &[u8],
    mldsa_signature: &[u8],
    root: &NetworkRootPin,
    expected_net_id: [u8; 16],
    now_us: u64,
) -> Result<VerifiedIssuerAuthorization, Error> {
    let candidate = RootAuthorizationCandidate::decode_candidate(raw_candidate)?;
    verify(
        &candidate,
        raw_candidate,
        ed25519_signature,
        mldsa_signature,
        root,
        expected_net_id,
        now_us,
    )
}

/// Verify pin network, policy bindings, then both signatures over exact raw candidate bytes.
pub fn verify(
    candidate: &RootAuthorizationCandidate,
    raw_candidate: &[u8],
    ed25519_signature: &[u8],
    mldsa_signature: &[u8],
    root: &NetworkRootPin,
    expected_net_id: [u8; 16],
    now_us: u64,
) -> Result<VerifiedIssuerAuthorization, Error> {
    if raw_candidate.len() > MAX_CANDIDATE_BYTES {
        return Err(Error::TooLarge);
    }
    candidate.validate()?;
    if root.net_id != expected_net_id || candidate.net_id != expected_net_id {
        return Err(Error::WrongNetwork);
    }
    if now_us < candidate.not_before || now_us >= candidate.expires {
        return Err(Error::InvalidTime);
    }
    if candidate.encode_candidate()?.as_slice() != raw_candidate {
        return Err(Error::InvalidCandidate);
    }
    let expected_mldsa_sig_len = match root.mldsa_parameter_set {
        boreas_proto::objects::MldsaParameterSet::Mldsa65 => MLDSA65_SIG_LEN,
        boreas_proto::objects::MldsaParameterSet::Mldsa87 => MLDSA87_SIG_LEN,
    };
    if ed25519_signature.len() != ED_SIG_LEN || mldsa_signature.len() != expected_mldsa_sig_len {
        return Err(Error::InvalidSignatureLength);
    }
    let ed_issuer = PKey::public_key_from_der(&candidate.ed25519_public_key_der)
        .map_err(|_| Error::InvalidCandidate)?;
    let pq_issuer = PKey::public_key_from_der(&candidate.mldsa_public_key_der)
        .map_err(|_| Error::InvalidCandidate)?;
    if !ed_issuer.is_a(KeyType::ED25519)
        || !pq_issuer.is_a(match candidate.mldsa_parameter_set {
            boreas_proto::objects::MldsaParameterSet::Mldsa65 => KeyType::ML_DSA_65,
            boreas_proto::objects::MldsaParameterSet::Mldsa87 => KeyType::ML_DSA_87,
        })
    {
        return Err(Error::InvalidCandidate);
    }
    let ed_root = PKey::public_key_from_der(&root.ed25519_public_key_der)
        .map_err(|_| Error::InvalidRootKey)?;
    let pq_root =
        PKey::public_key_from_der(&root.mldsa_public_key_der).map_err(|_| Error::InvalidRootKey)?;
    if !ed_root.is_a(KeyType::ED25519)
        || !pq_root.is_a(match root.mldsa_parameter_set {
            boreas_proto::objects::MldsaParameterSet::Mldsa65 => KeyType::ML_DSA_65,
            boreas_proto::objects::MldsaParameterSet::Mldsa87 => KeyType::ML_DSA_87,
        })
    {
        return Err(Error::InvalidRootKey);
    }
    let mut msg = Vec::with_capacity(DOMAIN.len() + raw_candidate.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(raw_candidate);
    let mut ev = Verifier::new_without_digest(&ed_root).map_err(|_| Error::Backend)?;
    if !ev
        .verify_oneshot(ed25519_signature, &msg)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidEdSignature);
    }
    let mut pv = Verifier::new_without_digest(&pq_root).map_err(|_| Error::Backend)?;
    if !pv
        .verify_oneshot(mldsa_signature, &msg)
        .map_err(|_| Error::Backend)?
    {
        return Err(Error::InvalidMlDsaSignature);
    }
    let (authority, scope) = match &candidate.scope {
        Scope::Identity { roles, home_cores } => (
            Authority::IdentityAuthority,
            IssuerScope::for_identity(roles.clone(), home_cores.clone())
                .map_err(|_| Error::InvalidCandidate)?,
        ),
        Scope::Route { prefixes } => (
            Authority::RouteAuthority,
            IssuerScope::for_route(prefixes.clone()).map_err(|_| Error::InvalidCandidate)?,
        ),
        Scope::Status => (Authority::StatusSigner, IssuerScope::default()),
        Scope::CoreOperational { core_id } => (
            Authority::CoreOperationalKey { core_id: *core_id },
            IssuerScope::default(),
        ),
    };
    Ok(VerifiedIssuerAuthorization {
        record: IssuerRecord {
            issuer_key_id: candidate.issuer_key_id.clone(),
            issuer_generation: candidate.issuer_generation,
            authority,
            ed25519_public_key_der: candidate.ed25519_public_key_der.clone(),
            mldsa_parameter_set: candidate.mldsa_parameter_set,
            mldsa_public_key_der: candidate.mldsa_public_key_der.clone(),
            scope,
        },
        net_id: candidate.net_id,
        not_before: candidate.not_before,
        expires: candidate.expires,
    })
}

#[derive(Debug)]
enum Value<'a> {
    UInt(u64),
    Bool(bool),
    Bytes(&'a [u8]),
    Array(Vec<Value<'a>>),
    Map(Vec<(u64, Value<'a>)>),
}
fn read_value(data: &[u8], depth: usize) -> Result<(Value<'_>, usize), Error> {
    if depth > 8 || data.is_empty() {
        return Err(Error::InvalidCandidate);
    }
    let major = data[0] >> 5;
    let ai = data[0] & 31;
    let mut pos = 1usize;
    if major == 7 {
        return match ai {
            20 => Ok((Value::Bool(false), pos)),
            21 => Ok((Value::Bool(true), pos)),
            _ => Err(Error::InvalidCandidate),
        };
    }
    let n = match ai {
        0..=23 => ai as u64,
        24 => {
            let x = *data.get(pos).ok_or(Error::InvalidCandidate)? as u64;
            pos += 1;
            if x < 24 {
                return Err(Error::InvalidCandidate);
            }
            x
        }
        25 => {
            let x = data.get(pos..pos + 2).ok_or(Error::InvalidCandidate)?;
            pos += 2;
            let n = u16::from_be_bytes([x[0], x[1]]) as u64;
            if n <= 255 {
                return Err(Error::InvalidCandidate);
            }
            n
        }
        26 => {
            let x = data.get(pos..pos + 4).ok_or(Error::InvalidCandidate)?;
            pos += 4;
            let n = u32::from_be_bytes(x.try_into().map_err(|_| Error::InvalidCandidate)?) as u64;
            if n <= 65535 {
                return Err(Error::InvalidCandidate);
            }
            n
        }
        27 => {
            let x = data.get(pos..pos + 8).ok_or(Error::InvalidCandidate)?;
            pos += 8;
            let n = u64::from_be_bytes(x.try_into().map_err(|_| Error::InvalidCandidate)?);
            if n <= u32::MAX as u64 {
                return Err(Error::InvalidCandidate);
            }
            n
        }
        _ => return Err(Error::InvalidCandidate),
    };
    let val = match major {
        0 => Value::UInt(n),
        2 => {
            let len = usize::try_from(n).map_err(|_| Error::InvalidCandidate)?;
            let end = pos.checked_add(len).ok_or(Error::InvalidCandidate)?;
            let b = data.get(pos..end).ok_or(Error::InvalidCandidate)?;
            pos = end;
            Value::Bytes(b)
        }
        4 => {
            if n > 256 {
                return Err(Error::TooLarge);
            }
            let mut xs = Vec::new();
            for _ in 0..n {
                let (v, used) = read_value(&data[pos..], depth + 1)?;
                pos += used;
                xs.push(v);
            }
            Value::Array(xs)
        }
        5 => {
            if n > 16 {
                return Err(Error::TooLarge);
            }
            let mut xs = Vec::new();
            let mut last = None;
            for _ in 0..n {
                let (k, used) = read_value(&data[pos..], depth + 1)?;
                pos += used;
                let Value::UInt(k) = k else {
                    return Err(Error::InvalidCandidate);
                };
                if last.is_some_and(|x| x >= k) {
                    return Err(Error::InvalidCandidate);
                }
                last = Some(k);
                let (v, used) = read_value(&data[pos..], depth + 1)?;
                pos += used;
                xs.push((k, v));
            }
            Value::Map(xs)
        }
        _ => return Err(Error::InvalidCandidate),
    };
    Ok((val, pos))
}
fn value_uint(v: &Value<'_>) -> Result<u64, Error> {
    if let Value::UInt(n) = v {
        Ok(*n)
    } else {
        Err(Error::InvalidCandidate)
    }
}
fn value_bytes<'a>(v: &Value<'a>) -> Result<&'a [u8], Error> {
    if let Value::Bytes(b) = v {
        Ok(b)
    } else {
        Err(Error::InvalidCandidate)
    }
}
fn decode_scope(purpose: Purpose, raw: &[u8]) -> Result<Scope, Error> {
    let (v, used) = read_value(raw, 0)?;
    if used != raw.len() {
        return Err(Error::InvalidCandidate);
    }
    match (purpose, v) {
        (Purpose::Identity, Value::Map(m)) if m.len() == 2 && m[0].0 == 0 && m[1].0 == 1 => {
            let Value::Array(rs) = &m[0].1 else {
                return Err(Error::InvalidCandidate);
            };
            let Value::Array(cs) = &m[1].1 else {
                return Err(Error::InvalidCandidate);
            };
            let mut roles = Vec::new();
            for r in rs {
                roles.push(match value_uint(r)? {
                    1 => NodeRole::Edge,
                    2 => NodeRole::Core,
                    3 => NodeRole::EnrollmentService,
                    _ => return Err(Error::InvalidCandidate),
                });
            }
            let mut home_cores = Vec::new();
            for c in cs {
                home_cores.push(u8::try_from(value_uint(c)?).map_err(|_| Error::InvalidCandidate)?);
            }
            Ok(Scope::Identity { roles, home_cores })
        }
        (Purpose::Route, Value::Array(items)) => {
            let mut prefixes = Vec::new();
            for item in items {
                let Value::Array(pair) = item else {
                    return Err(Error::InvalidCandidate);
                };
                if pair.len() != 2 {
                    return Err(Error::InvalidCandidate);
                };
                let b = value_bytes(&pair[0])?.to_vec();
                let p = u8::try_from(value_uint(&pair[1])?).map_err(|_| Error::InvalidCandidate)?;
                prefixes.push(AllowedPrefix::new(b, p).map_err(|_| Error::InvalidCandidate)?);
            }
            Ok(Scope::Route { prefixes })
        }
        (Purpose::Status, Value::Map(m)) if m.is_empty() => Ok(Scope::Status),
        (Purpose::CoreOperational, v) => Ok(Scope::CoreOperational {
            core_id: u8::try_from(value_uint(&v)?).map_err(|_| Error::InvalidCandidate)?,
        }),
        _ => Err(Error::InvalidCandidate),
    }
}

fn encode_scope(s: &Scope) -> Result<(Purpose, Vec<u8>), Error> {
    let mut o = Vec::new();
    match s {
        Scope::Identity { roles, home_cores } => {
            map(2, &mut o);
            uint(0, &mut o);
            array(roles.len(), &mut o);
            for r in roles {
                uint(
                    match r {
                        NodeRole::Edge => 1,
                        NodeRole::Core => 2,
                        NodeRole::EnrollmentService => 3,
                    },
                    &mut o,
                );
            }
            uint(1, &mut o);
            array(home_cores.len(), &mut o);
            for c in home_cores {
                uint(*c as u64, &mut o);
            }
            Ok((Purpose::Identity, o))
        }
        Scope::Route { prefixes } => {
            array(prefixes.len(), &mut o);
            for p in prefixes {
                array(2, &mut o);
                bytes(p.bytes(), &mut o);
                uint(p.prefix_len() as u64, &mut o);
            }
            Ok((Purpose::Route, o))
        }
        Scope::Status => {
            map(0, &mut o);
            Ok((Purpose::Status, o))
        }
        Scope::CoreOperational { core_id } => {
            uint(*core_id as u64, &mut o);
            Ok((Purpose::CoreOperational, o))
        }
    }
}
fn head(major: u8, n: usize, o: &mut Vec<u8>) {
    let n = n as u64;
    let m = major << 5;
    if n < 24 {
        o.push(m | n as u8)
    } else if n <= 255 {
        o.extend([m | 24, n as u8])
    } else {
        o.extend([m | 25]);
        o.extend((n as u16).to_be_bytes())
    }
}
fn cbor_bool(value: bool, o: &mut Vec<u8>) {
    o.push(if value { 0xf5 } else { 0xf4 });
}
fn uint(n: u64, o: &mut Vec<u8>) {
    let m = 0;
    if n < 24 {
        o.push((m << 5) | n as u8)
    } else if n <= 255 {
        o.extend([24, n as u8])
    } else if n <= 65535 {
        o.push(25);
        o.extend((n as u16).to_be_bytes())
    } else if n <= u32::MAX as u64 {
        o.push(26);
        o.extend((n as u32).to_be_bytes())
    } else {
        o.push(27);
        o.extend(n.to_be_bytes())
    }
}
fn map(n: usize, o: &mut Vec<u8>) {
    head(5, n, o)
}
fn array(n: usize, o: &mut Vec<u8>) {
    head(4, n, o)
}
fn bytes(b: &[u8], o: &mut Vec<u8>) {
    head(2, b.len(), o);
    o.extend_from_slice(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        pkey::{KeyType, PKey, Private},
        sign::Signer,
    };

    fn pair(seed: u8) -> (PKey<Private>, PKey<Private>) {
        (
            PKey::generate_ed25519().unwrap(),
            PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
        )
    }
    fn signed(key_ed: &PKey<Private>, key_pq: &PKey<Private>, raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(raw);
        let mut s = Signer::new_without_digest(key_ed).unwrap();
        let ed = s.sign_oneshot_to_vec(&msg).unwrap();
        let mut s = Signer::new_without_digest(key_pq).unwrap();
        (ed, s.sign_oneshot_to_vec(&msg).unwrap())
    }
    fn candidate(ed: &PKey<Private>, pq: &PKey<Private>) -> RootAuthorizationCandidate {
        RootAuthorizationCandidate {
            net_id: [3; 16],
            issuer_key_id: vec![1],
            issuer_generation: 4,
            purpose: Purpose::Identity,
            ed25519_public_key_der: ed.public_key_to_der().unwrap(),
            mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: pq.public_key_to_der().unwrap(),
            scope: Scope::Identity {
                roles: vec![NodeRole::Edge],
                home_cores: vec![2],
            },
            not_before: 10,
            expires: 20,
            chain_depth: 1,
            may_delegate: false,
        }
    }
    fn hex(raw: &str) -> Vec<u8> {
        let compact: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
        let (pairs, remainder) = compact.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "odd-length fixture hex");
        pairs
            .iter()
            .map(|pair| {
                let byte = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(byte, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn independent_python_root_structure_vector_and_bool_encoding() {
        // tools/candidate_bindings.py / security-bindings-candidate-v1.json uses synthetic
        // non-DER keys: structural decoding only, deliberately no signature verification.
        let valid = hex(
            "ae 0001 0150 03030303030303030303030303030303 024101 0304 0401 054101 0601 074102 0847 a2008101018102 090a 0a14 0b01 0cf4 0d80",
        );
        let parsed = RootAuthorizationCandidate::decode_candidate(&valid).unwrap();
        assert_eq!(parsed.purpose, Purpose::Identity);
        assert!(!parsed.may_delegate);
        assert_eq!(parsed.encode_candidate().unwrap(), valid);
        let uint_false = hex(
            "ae 0001 0150 03030303030303030303030303030303 024101 0304 0401 054101 0601 074102 0847 a2008101018102 090a 0a14 0b01 0c00 0d80",
        );
        assert!(RootAuthorizationCandidate::decode_candidate(&uint_false).is_err());
        let true_delegate = hex(
            "ae 0001 0150 03030303030303030303030303030303 024101 0304 0401 054101 0601 074102 0847 a2008101018102 090a 0a14 0b01 0cf5 0d80",
        );
        assert!(RootAuthorizationCandidate::decode_candidate(&true_delegate).is_err());
    }

    #[test]
    fn verified_token_requires_pinned_root_and_both_signatures() {
        let (root_ed, root_pq) = pair(9);
        let (issuer_ed, issuer_pq) = pair(10);
        let c = candidate(&issuer_ed, &issuer_pq);
        let raw = c.encode_candidate().unwrap();
        let (sig_ed, sig_pq) = signed(&root_ed, &root_pq, &raw);
        let pin = NetworkRootPin::provisioned(
            [3; 16],
            root_ed.public_key_to_der().unwrap(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(pin.fingerprint().unwrap(), pin.fingerprint().unwrap());
        let other_network = NetworkRootPin::provisioned(
            [4; 16],
            root_ed.public_key_to_der().unwrap(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        assert_ne!(
            pin.fingerprint().unwrap(),
            other_network.fingerprint().unwrap()
        );
        let (other_root_ed, other_root_pq) = pair(12);
        let other_keys = NetworkRootPin::provisioned(
            [3; 16],
            other_root_ed.public_key_to_der().unwrap(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            other_root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        assert_ne!(
            pin.fingerprint().unwrap(),
            other_keys.fingerprint().unwrap()
        );
        assert_eq!(
            RootAuthorizationCandidate::decode_candidate(&raw).unwrap(),
            c
        );
        assert!(verify(&c, &raw, &sig_ed, &sig_pq, &pin, [3; 16], 10).is_ok());
        assert!(matches!(
            verify(
                &c,
                &raw,
                &sig_ed,
                &sig_pq[..sig_pq.len() - 1],
                &pin,
                [3; 16],
                10
            ),
            Err(Error::InvalidSignatureLength)
        ));
        let mut bad_ed = sig_ed.clone();
        bad_ed[0] ^= 1;
        assert!(matches!(
            verify(&c, &raw, &bad_ed, &sig_pq, &pin, [3; 16], 10),
            Err(Error::InvalidEdSignature)
        ));
        let mut bad_pq = sig_pq.clone();
        bad_pq[0] ^= 1;
        assert!(matches!(
            verify(&c, &raw, &sig_ed, &bad_pq, &pin, [3; 16], 10),
            Err(Error::InvalidMlDsaSignature)
        ));
        assert!(matches!(
            verify(&c, &raw, &sig_ed, &sig_pq, &pin, [4; 16], 10),
            Err(Error::WrongNetwork)
        ));
        assert!(matches!(
            verify(&c, &raw, &sig_ed, &sig_pq, &pin, [3; 16], 9),
            Err(Error::InvalidTime)
        ));
        assert!(matches!(
            verify(&c, &raw, &sig_ed, &sig_pq, &pin, [3; 16], 20),
            Err(Error::InvalidTime)
        ));
        let mut changed = raw.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify(&c, &changed, &sig_ed, &sig_pq, &pin, [3; 16], 10),
            Err(Error::InvalidCandidate)
        ));
        let (other_ed, other_pq) = pair(11);
        let wrong = NetworkRootPin::provisioned(
            [3; 16],
            other_ed.public_key_to_der().unwrap(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            other_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify(&c, &raw, &sig_ed, &sig_pq, &wrong, [3; 16], 10),
            Err(Error::InvalidEdSignature) | Err(Error::InvalidMlDsaSignature)
        ));
        // Canonical decoder rejects a re-encoded alternate/non-shortest candidate and oversize input.
        let mut noncanonical = raw.clone();
        noncanonical[0] = 0xb8;
        noncanonical.insert(1, 14);
        assert!(RootAuthorizationCandidate::decode_candidate(&noncanonical).is_err());
        assert!(matches!(
            RootAuthorizationCandidate::decode_candidate(&vec![0; MAX_CANDIDATE_BYTES + 1]),
            Err(Error::TooLarge)
        ));
        let mut delegate = c.clone();
        delegate.may_delegate = true;
        assert!(matches!(
            delegate.encode_candidate(),
            Err(Error::InvalidCandidate)
        ));
        let mut confused = c.clone();
        confused.purpose = Purpose::CoreOperational;
        assert!(matches!(
            confused.encode_candidate(),
            Err(Error::InvalidCandidate)
        ));
        let mut bad_gen = c.clone();
        bad_gen.issuer_generation = 0;
        assert!(matches!(
            bad_gen.encode_candidate(),
            Err(Error::InvalidCandidate)
        ));
        let mut bad_scope = c.clone();
        bad_scope.scope = Scope::Identity {
            roles: vec![NodeRole::Core, NodeRole::Edge],
            home_cores: vec![2],
        };
        assert!(matches!(
            bad_scope.encode_candidate(),
            Err(Error::InvalidCandidate)
        ));
        let mut bad_id = c.clone();
        bad_id.issuer_key_id = vec![9; MAX_ISSUER_ID + 1];
        assert!(matches!(
            bad_id.encode_candidate(),
            Err(Error::InvalidCandidate)
        ));
        let rec = verify_raw(&raw, &sig_ed, &sig_pq, &pin, [3; 16], 10)
            .unwrap()
            .issuer_record();
        assert_eq!(rec.authority, Authority::IdentityAuthority);
        assert_eq!(rec.issuer_generation, 4);
    }
}
