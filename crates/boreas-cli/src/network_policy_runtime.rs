//! Daemon-facing explicit policy verifier/recorder. No policy is discovered implicitly.
//! Installer/operator must pre-place all five raw inputs directly inside the configured
//! state directory; this layout is explicit operator input, not candidate-derived provenance.
//! Wall-clock validity uses the local clock; this is not a trusted-time service.

#[cfg(all(not(unix), feature = "openssl-inner-tls"))]
use std::fs::File;
#[cfg(feature = "openssl-inner-tls")]
use std::{fmt, io::Read, path::Path};

#[cfg(feature = "openssl-inner-tls")]
#[derive(Debug)]
pub enum PolicyRuntimeError {
    Input(&'static str),
    Pin(String),
    Verify(String),
    Store(String),
    UnsupportedPrefix,
    Clock,
}
#[cfg(feature = "openssl-inner-tls")]
impl fmt::Display for PolicyRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(label) => write!(f, "policy input rejected: {label}"),
            Self::Pin(reason) => write!(f, "policy root pin rejected: {reason}"),
            Self::Verify(reason) => write!(f, "policy verification failed: {reason}"),
            Self::Store(reason) => write!(f, "policy store rejected: {reason}"),
            Self::UnsupportedPrefix => {
                f.write_str("policy prefix is not the default runtime prefix")
            }
            Self::Clock => f.write_str("policy wall clock is unavailable"),
        }
    }
}
#[cfg(feature = "openssl-inner-tls")]
impl std::error::Error for PolicyRuntimeError {}

/// The five explicit raw policy inputs, all required directly inside the configured
/// state directory. Paths are borrowed for the duration of verification only.
#[cfg(feature = "openssl-inner-tls")]
pub struct PolicyInputPaths<'a> {
    pub tbs: &'a Path,
    pub ed25519_signature: &'a Path,
    pub mldsa65_signature: &'a Path,
    pub root_ed25519_der: &'a Path,
    pub root_mldsa65_der: &'a Path,
}

#[cfg(feature = "openssl-inner-tls")]
fn read_bounded_regular(
    path: &Path,
    max: usize,
    label: &'static str,
) -> Result<Vec<u8>, PolicyRuntimeError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| PolicyRuntimeError::Input(label))?;
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.len() == 0
        || meta.len() > max as u64
    {
        return Err(PolicyRuntimeError::Input(label));
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| PolicyRuntimeError::Input(label))?
    };
    #[cfg(not(unix))]
    let mut file = {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        opts.open(path)
            .map_err(|_| PolicyRuntimeError::Input(label))?
    };
    let opened = file
        .metadata()
        .map_err(|_| PolicyRuntimeError::Input(label))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > max as u64 {
        return Err(PolicyRuntimeError::Input(label));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyRuntimeError::Input(label))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(PolicyRuntimeError::Input(label));
    }
    Ok(bytes)
}

/// Verify and durably record explicitly supplied raw policy and independent root keys.
/// `expected_net_id` is from active daemon configuration. The installer/operator must
/// pre-place each candidate/signature/key file directly within `configured_state_dir`;
/// this is deployment layout, not provenance inferred from the signed candidate. The independently
/// provisioned DER pair must match the verified identity/status root fingerprint before opening
/// the watermark. Returns the signed private-prefix context only after fresh verification and
/// successful anti-replay commit.
#[cfg(feature = "openssl-inner-tls")]
pub fn verify_and_record_default_policy(
    inputs: PolicyInputPaths<'_>,
    state_path: &Path,
    configured_state_dir: &Path,
    expected_net_id: [u8; 16],
    expected_root_fingerprint: [u8; 32],
    trusted_owner_uid: u32,
) -> Result<boreas_pki::VerifiedNetworkContext, PolicyRuntimeError> {
    use boreas_pki::{
        NetworkRootPin, network_policy_store::NetworkPolicyStore, verify_network_policy,
    };
    use boreas_proto::objects::MldsaParameterSet;

    let PolicyInputPaths {
        tbs: tbs_path,
        ed25519_signature: ed25519_signature_path,
        mldsa65_signature: mldsa65_signature_path,
        root_ed25519_der: root_ed25519_der_path,
        root_mldsa65_der: root_mldsa65_der_path,
    } = inputs;

    let canonical_state_dir = configured_state_dir
        .canonicalize()
        .map_err(|_| PolicyRuntimeError::Input("configured state directory unavailable"))?;
    if !canonical_state_dir.is_dir() {
        return Err(PolicyRuntimeError::Input(
            "configured state path is not a directory",
        ));
    }
    if !state_path.is_absolute() {
        return Err(PolicyRuntimeError::Input("state path must be absolute"));
    }
    let state_parent = state_path
        .parent()
        .ok_or(PolicyRuntimeError::Input("state path has no parent"))?
        .canonicalize()
        .map_err(|_| PolicyRuntimeError::Input("state parent directory unavailable"))?;
    if state_parent != canonical_state_dir {
        return Err(PolicyRuntimeError::Input(
            "state path must be directly inside configured state directory",
        ));
    }
    let state_name = state_path
        .file_name()
        .ok_or(PolicyRuntimeError::Input("state path has no filename"))?;
    let canonical_state_path = canonical_state_dir.join(state_name);
    let input_paths = [
        tbs_path,
        ed25519_signature_path,
        mldsa65_signature_path,
        root_ed25519_der_path,
        root_mldsa65_der_path,
    ];
    for path in input_paths {
        let parent = path
            .parent()
            .ok_or(PolicyRuntimeError::Input("input path has no parent"))?
            .canonicalize()
            .map_err(|_| PolicyRuntimeError::Input("input parent directory unavailable"))?;
        if parent != canonical_state_dir {
            return Err(PolicyRuntimeError::Input(
                "policy inputs must be directly inside configured state directory",
            ));
        }
    }
    let mut canonical_inputs = Vec::with_capacity(input_paths.len());
    for path in input_paths {
        let canonical = path
            .canonicalize()
            .map_err(|_| PolicyRuntimeError::Input("policy input unavailable"))?;
        if canonical == canonical_state_path {
            return Err(PolicyRuntimeError::Input(
                "policy inputs and state file must be distinct",
            ));
        }
        if canonical_inputs.contains(&canonical) {
            return Err(PolicyRuntimeError::Input(
                "candidate, signatures, and root keys must be distinct files",
            ));
        }
        canonical_inputs.push(canonical);
    }

    let tbs = read_bounded_regular(tbs_path, 16 * 1024, "invalid TBS file")?;
    let ed_sig =
        read_bounded_regular(ed25519_signature_path, 64, "invalid Ed25519 signature file")?;
    let pq_sig = read_bounded_regular(
        mldsa65_signature_path,
        3309,
        "invalid ML-DSA-65 signature file",
    )?;
    if ed_sig.len() != 64 || pq_sig.len() != 3309 {
        return Err(PolicyRuntimeError::Input("invalid signature length"));
    }
    let ed_der =
        read_bounded_regular(root_ed25519_der_path, 4096, "invalid Ed25519 root key file")?;
    let pq_der = read_bounded_regular(
        root_mldsa65_der_path,
        4096,
        "invalid ML-DSA-65 root key file",
    )?;
    let pin =
        NetworkRootPin::provisioned(expected_net_id, ed_der, MldsaParameterSet::Mldsa65, pq_der)
            .map_err(|e| PolicyRuntimeError::Pin(e.to_string()))?;
    let fingerprint = pin
        .fingerprint()
        .map_err(|e| PolicyRuntimeError::Pin(e.to_string()))?;
    if fingerprint != expected_root_fingerprint {
        return Err(PolicyRuntimeError::Pin(
            "does not match the daemon identity/status NetworkRoot fingerprint".to_string(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PolicyRuntimeError::Clock)?
        .as_micros();
    let now = u64::try_from(now).map_err(|_| PolicyRuntimeError::Clock)?;
    let token = verify_network_policy(&tbs, &ed_sig, &pq_sig, &pin, expected_net_id, now)
        .map_err(|e| PolicyRuntimeError::Verify(e.to_string()))?;
    let context = token
        .require_default_runtime()
        .map_err(|_| PolicyRuntimeError::UnsupportedPrefix)?;
    let mut store =
        NetworkPolicyStore::open(state_path, expected_net_id, fingerprint, trusted_owner_uid)
            .map_err(|e| PolicyRuntimeError::Store(e.to_string()))?;
    store
        .commit(&token, &tbs)
        .map_err(|e| PolicyRuntimeError::Store(e.to_string()))?;
    Ok(context)
}

#[cfg(all(test, feature = "openssl-inner-tls"))]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "boreas-policy-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
    #[test]
    fn helper_requires_dual_signatures_default_prefix_pin_and_durable_state() {
        use boreas_pki::NetworkRootPin;
        use boreas_proto::{network_policy::NetworkPolicyCandidate, objects::MldsaParameterSet};
        use openssl::{
            pkey::{KeyType, PKey, Private},
            sign::Signer,
        };
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fn keys() -> (PKey<Private>, PKey<Private>) {
            (
                PKey::generate_ed25519().unwrap(),
                PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[43; 32]).unwrap(),
            )
        }
        fn setup(
            root: &Path,
            ed: &PKey<Private>,
            pq: &PKey<Private>,
            net: [u8; 16],
            prefix: [u8; 4],
            seq: u64,
            window: (u64, u64),
        ) -> Vec<PathBuf> {
            let (issued, expires) = window;
            let pin = NetworkRootPin::provisioned(
                net,
                ed.public_key_to_der().unwrap(),
                MldsaParameterSet::Mldsa65,
                pq.public_key_to_der().unwrap(),
            )
            .unwrap();
            let c = NetworkPolicyCandidate {
                net_id: net,
                root_key_fingerprint: pin.fingerprint().unwrap(),
                overlay_base: prefix,
                version: 1,
                seq,
                issued_at: issued,
                expires,
            };
            let raw = c.encode_tbs().unwrap();
            let msg = NetworkPolicyCandidate::signature_input(&raw).unwrap();
            let mut signer = Signer::new_without_digest(ed).unwrap();
            let es = signer.sign_oneshot_to_vec(&msg).unwrap();
            let mut signer = Signer::new_without_digest(pq).unwrap();
            let ps = signer.sign_oneshot_to_vec(&msg).unwrap();
            let paths = ["tbs", "ed.sig", "pq.sig", "ed.der", "pq.der"].map(|s| root.join(s));
            for (path, bytes) in paths.iter().zip([
                raw,
                es,
                ps,
                ed.public_key_to_der().unwrap(),
                pq.public_key_to_der().unwrap(),
            ]) {
                fs::write(path, bytes).unwrap();
            }
            paths.into_iter().collect()
        }
        fn invoke(
            paths: &[PathBuf],
            state: &Path,
            state_dir: &Path,
            net: [u8; 16],
            fingerprint: [u8; 32],
            uid: u32,
        ) -> Result<boreas_pki::VerifiedNetworkContext, PolicyRuntimeError> {
            let inputs = PolicyInputPaths {
                tbs: paths[0].as_path(),
                ed25519_signature: paths[1].as_path(),
                mldsa65_signature: paths[2].as_path(),
                root_ed25519_der: paths[3].as_path(),
                root_mldsa65_der: paths[4].as_path(),
            };
            verify_and_record_default_policy(inputs, state, state_dir, net, fingerprint, uid)
        }
        let root = dir();
        let state_dir = root.join("state");
        fs::create_dir(&state_dir).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let state = state_dir.join("policy.state");
        let net = [8; 16];
        let (ed, pq) = keys();
        let uid = fs::metadata(&state_dir).unwrap().uid();
        let fingerprint = NetworkRootPin::provisioned(
            net,
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().unwrap(),
        )
        .unwrap()
        .fingerprint()
        .unwrap();
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let t0 = now_micros.saturating_sub(1_000_000);
        let validity = 3_600_000_000;
        let paths = setup(
            &state_dir,
            &ed,
            &pq,
            net,
            [10, 20, 0, 0],
            2,
            (t0, t0 + validity),
        );
        assert!(invoke(&paths, &state, &state_dir, [9; 16], fingerprint, uid).is_err());
        assert!(invoke(&paths, &state, &root, net, fingerprint, uid).is_err());
        let mut mismatched_fingerprint = fingerprint;
        mismatched_fingerprint[0] ^= 1;
        assert!(matches!(
            invoke(&paths, &state, &state_dir, net, mismatched_fingerprint, uid),
            Err(PolicyRuntimeError::Pin(_))
        ));
        assert!(!state.exists());
        assert!(!state_dir.join("policy.state.lock").exists());
        assert_eq!(
            invoke(&paths, &state, &state_dir, net, fingerprint, uid).unwrap().seq(),
            2
        );
        let anchor = {
            let store = boreas_pki::network_policy_store::NetworkPolicyStore::open(
                &state,
                net,
                fingerprint,
                uid,
            )
            .unwrap();
            (
                store.sequence().unwrap(),
                store.current_object_hash().unwrap(),
            )
        };
        let rollback = setup(
            &state_dir,
            &ed,
            &pq,
            net,
            [10, 20, 0, 0],
            1,
            (t0, t0 + validity),
        );
        assert!(matches!(
            invoke(&rollback, &state, &state_dir, net, fingerprint, uid),
            Err(PolicyRuntimeError::Store(reason)) if reason.contains("SequenceRollback")
        ));
        // Same sequence, same valid issue time, different expiry: a real
        // equivocation rather than a future-dated policy that fails verification.
        let equivocation = setup(
            &state_dir,
            &ed,
            &pq,
            net,
            [10, 20, 0, 0],
            2,
            (t0, t0 + validity + 1_000_000),
        );
        assert!(matches!(
            invoke(&equivocation, &state, &state_dir, net, fingerprint, uid),
            Err(PolicyRuntimeError::Store(reason)) if reason.contains("Equivocation")
        ));
        // This helper has no external anchor: a missing state file is
        // indistinguishable from first use and is accepted. Deletion detection
        // requires the independent expected anchor below; this is not a claim of
        // whole-disk rollback detection.
        let fresh = state_dir.join("fresh");
        assert!(invoke(&equivocation, &fresh, &state_dir, net, fingerprint, uid).is_ok());
        let deleted = state_dir.join("deleted");
        assert!(matches!(
            boreas_pki::network_policy_store::NetworkPolicyStore::open_with_expected(
                &deleted,
                net,
                fingerprint,
                uid,
                Some(anchor),
            ),
            Err(boreas_pki::network_policy_store::Error::Corrupt)
        ));
        let (wrong_ed, _) = keys();
        fs::write(&paths[3], wrong_ed.public_key_to_der().unwrap()).unwrap();
        assert!(
            invoke(
                &paths,
                &state_dir.join("wrong-pin.state"),
                &state_dir,
                net,
                fingerprint,
                uid
            )
            .is_err()
        );
        fs::write(&paths[3], ed.public_key_to_der().unwrap()).unwrap();
        let private = setup(
            &state_dir,
            &ed,
            &pq,
            net,
            [172, 19, 0, 0],
            3,
            (t0, t0 + validity),
        );
        assert_eq!(
            invoke(
                &private,
                &state_dir.join("private.state"),
                &state_dir,
                net,
                fingerprint,
                uid
            )
            .unwrap()
            .overlay_base(),
            [172, 19, 0, 0]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_reader_rejects_empty_oversize_and_symlink() {
        let root = dir();
        let empty = root.join("empty");
        fs::write(&empty, []).unwrap();
        assert!(matches!(
            read_bounded_regular(&empty, 8, "input"),
            Err(PolicyRuntimeError::Input(_))
        ));
        let big = root.join("big");
        fs::write(&big, [0u8; 9]).unwrap();
        assert!(matches!(
            read_bounded_regular(&big, 8, "input"),
            Err(PolicyRuntimeError::Input(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = root.join("link");
            symlink(&big, &link).unwrap();
            assert!(matches!(
                read_bounded_regular(&link, 16, "input"),
                Err(PolicyRuntimeError::Input(_))
            ));
        }
        let _ = fs::remove_dir_all(root);
    }
}
