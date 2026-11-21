//! Operator-only Core mesh provisioning. Never put these directories in a
//! runtime material tree. Only public requests cross the NetworkRoot boundary.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use boreas_proto::{
    messages::PathRole,
    objects::{CoreLsa, Neighbor},
};

use super::{
    Authority, File, KeyType, MANAGEMENT_SCHEMA_VERSION, MAX_CHAIN_DEPTH, ManagementObject,
    ManagementTrust, MldsaParameterSet, ObjectBody, ObjectType, OpenOptions, PKey, Path, Private,
    ProvisionError, Purpose, Read, RootAuthorizationCandidate, RootsBundle, Scope, SignedObject,
    SignerRole, SignerSignatures, SubjectIdentity, Write, dual_sign, fs, generate_ed25519,
    generate_mldsa65, objects, sign_root_auth, write_secret_new,
};

const MAX_INPUT: usize = 128 * 1024;
const MAX_LSA_TTL: u32 = 3600;
// Same Linux flag values as the durable status store.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
const NOFOLLOW: i32 = 0o400_000;

type Result<T> = std::result::Result<T, ProvisionError>;

fn invalid(label: &'static str) -> ProvisionError {
    ProvisionError::InvalidParameter(label)
}

fn read(path: &Path, secret: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | 0x800 | 0x80000) // NOFOLLOW, NONBLOCK, CLOEXEC.
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() == 0
        || meta.len() > MAX_INPUT as u64
        || meta.mode() & if secret { 0o077 } else { 0o022 } != 0
    {
        return Err(invalid("unsafe Core mesh input"));
    }
    let mut raw = Vec::new();
    file.take(MAX_INPUT as u64 + 1).read_to_end(&mut raw)?;
    if raw.is_empty() || raw.len() > MAX_INPUT {
        return Err(ProvisionError::FileTooLarge);
    }
    Ok(raw)
}

fn key(path: &Path, expected: KeyType) -> Result<PKey<Private>> {
    let key = PKey::private_key_from_der(&read(path, true)?)
        .map_err(|_| ProvisionError::OpenSsl("Core mesh private key"))?;
    if !key.is_a(expected) {
        return Err(invalid("Core mesh private key type"));
    }
    Ok(key)
}

fn output(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Generate a scoped public request and local keys. All three files are in a
/// newly-created private directory; send *only* `core.request` to the root.
#[allow(clippy::too_many_arguments)]
pub fn init_core_request(
    out: &Path,
    net: [u8; 16],
    core: u8,
    issuer_generation: u64,
    now: u64,
    ttl: u32,
) -> Result<()> {
    if !(1..=16).contains(&core) || !(1..=3650).contains(&ttl) {
        return Err(invalid("Core slot or authorization validity days"));
    }
    let expires = now
        .checked_add(u64::from(ttl) * 86_400_000_000)
        .ok_or_else(|| invalid("Core grant time overflow"))?;
    let ed = generate_ed25519()?;
    let pq = generate_mldsa65()?;
    let request = RootAuthorizationCandidate {
        net_id: net,
        issuer_key_id: format!("mesh-core-{core}-g{issuer_generation}").into_bytes(),
        issuer_generation,
        purpose: Purpose::CoreOperational,
        ed25519_public_key_der: ed
            .public_key_to_der()
            .map_err(|_| ProvisionError::OpenSsl("Core Ed25519 public key"))?,
        mldsa_parameter_set: MldsaParameterSet::Mldsa65,
        mldsa_public_key_der: pq
            .public_key_to_der()
            .map_err(|_| ProvisionError::OpenSsl("Core ML-DSA public key"))?,
        scope: Scope::CoreOperational { core_id: core },
        not_before: now.saturating_sub(60_000_000),
        expires,
        chain_depth: MAX_CHAIN_DEPTH,
        may_delegate: false,
    }
    .encode_candidate()?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(out)?;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700))?;
    write_secret_new(
        &out.join("core.ed25519.key"),
        &ed.private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("Core Ed25519 private key"))?,
    )?;
    write_secret_new(
        &out.join("core.mldsa65.key"),
        &pq.private_key_to_pkcs8()
            .map_err(|_| ProvisionError::OpenSsl("Core ML-DSA private key"))?,
    )?;
    output(&out.join("core.request"), &request)
}

/// Offline NetworkRoot authorization. Does not read Core private keys or
/// overwrite the input bundle; the caller reviews the public request first.
/// Use the output as the input bundle for the next distinct Core slot.
pub fn authorize_core(
    ca: &Path,
    roots: &Path,
    request: &Path,
    out: &Path,
    expected_core: u8,
    now: u64,
) -> Result<()> {
    let mut bundle = RootsBundle::decode(&read(roots, false)?)?;
    let raw = read(request, false)?;
    let candidate = RootAuthorizationCandidate::decode_candidate(&raw)?;
    let Scope::CoreOperational { core_id } = &candidate.scope else {
        return Err(invalid("not a CoreOperational request"));
    };
    if *core_id != expected_core
        || candidate.purpose != Purpose::CoreOperational
        || candidate.may_delegate
        || candidate.net_id != bundle.net_id
        || candidate.encode_candidate()? != raw
    {
        return Err(invalid("invalid CoreOperational request"));
    }
    let (_, grants) = bundle.verify_all(bundle.net_id, now)?;
    if grants.iter().any(|grant| {
        let record = grant.issuer_record();
        record.authority == (Authority::CoreOperationalKey { core_id: *core_id })
            || record.issuer_key_id == candidate.issuer_key_id
    }) {
        return Err(invalid("Core slot or issuer already authorized"));
    }
    let ed = key(&ca.join("root.ed25519.key"), KeyType::ED25519)?;
    let pq = key(&ca.join("root.mldsa65.key"), KeyType::ML_DSA_65)?;
    bundle
        .authorizations
        .push(sign_root_auth(&candidate, &ed, &pq)?);
    // With a wrong offline root or an unusable request the new bundle cannot verify.
    let (_, grants) = bundle.verify_all(bundle.net_id, now)?;
    let mut trust = ManagementTrust::new(bundle.net_id);
    for grant in grants {
        trust.add_verified_issuer(&grant)?;
    }
    output(out, &bundle.encode()?)
}

/// Signed publication stays out of the data-plane process. Trust is checked
/// again against the final roots, including the scoped operational key.
pub struct LsaParams<'a> {
    pub now: u64,
    pub core_generation: u64,
    pub sequence: u64,
    pub ttl_seconds: u32,
    pub neighbors: &'a [(u8, u16, u32)],
}

pub fn sign_lsa(keys: &Path, roots: &Path, out: &Path, p: &LsaParams<'_>) -> Result<()> {
    if !(1..=MAX_LSA_TTL).contains(&p.ttl_seconds) || p.neighbors.len() > 15 {
        return Err(invalid("LSA validity seconds or neighbor count"));
    }
    let bundle = RootsBundle::decode(&read(roots, false)?)?;
    let request =
        RootAuthorizationCandidate::decode_candidate(&read(&keys.join("core.request"), false)?)?;
    let Scope::CoreOperational { core_id } = request.scope else {
        return Err(invalid("not a CoreOperational request"));
    };
    if request.net_id != bundle.net_id || request.purpose != Purpose::CoreOperational {
        return Err(invalid("invalid CoreOperational request"));
    }
    let expires = p
        .now
        .checked_add(u64::from(p.ttl_seconds) * 1_000_000)
        .ok_or_else(|| invalid("LSA time overflow"))?;
    let (_, grants) = bundle.verify_all(bundle.net_id, p.now)?;
    let mut trust = ManagementTrust::new(bundle.net_id);
    for grant in grants {
        trust.add_verified_issuer(&grant)?;
    }
    let mut neighbors: Vec<_> = p
        .neighbors
        .iter()
        .map(|&(id, rtt, loss)| Neighbor {
            peer_core_id: id,
            rtt_p50_ms: rtt,
            loss_ppm: loss,
            path_type: PathRole::Cdn as u8,
        })
        .collect();
    neighbors.sort_unstable_by_key(|n| n.peer_core_id);
    let obj = ManagementObject {
        net_id: bundle.net_id,
        issuer_key_id: request.issuer_key_id,
        issuer_generation: request.issuer_generation,
        subject_identity: SubjectIdentity::Core(core_id),
        seq: p.sequence,
        issued_at: p.now,
        expires,
        extensions: Vec::new(),
        body: ObjectBody::CoreLsa(CoreLsa {
            core_id,
            core_generation: p.core_generation,
            seq: p.sequence,
            neighbors,
        }),
    };
    let raw_tbs = objects::encode_tbs(&obj).map_err(|_| invalid("invalid CoreLsa fields"))?;
    let msg = objects::signature_input(&raw_tbs, ObjectType::CoreLsa, MANAGEMENT_SCHEMA_VERSION)
        .map_err(|_| invalid("invalid CoreLsa TBS"))?;
    let ed = key(&keys.join("core.ed25519.key"), KeyType::ED25519)?;
    let pq = key(&keys.join("core.mldsa65.key"), KeyType::ML_DSA_65)?;
    let (ed25519, mldsa) = dual_sign(&msg, &ed, &pq)?;
    let bytes = SignedObject {
        object_type: ObjectType::CoreLsa,
        raw_tbs,
        signers: vec![SignerSignatures {
            role: SignerRole::Primary,
            ed25519,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa,
        }],
    }
    .encode()
    .map_err(|_| invalid("invalid CoreLsa envelope"))?;
    if trust.verify_and_authorize(&bytes, p.now)?.valid_until() < expires {
        return Err(invalid("CoreLsa exceeds operational grant window"));
    }
    output(out, &bytes)
}
