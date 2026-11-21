use std::ffi::OsString;

use crate::{CliOutcome, err_out};

pub fn stage_command(args: &[OsString], verify_only: bool) -> CliOutcome {
    #[cfg(all(target_os = "linux", feature = "openssl-backend"))]
    {
        let command = if verify_only { "verify-stage" } else { "stage" };
        match admission(args, verify_only) {
            Ok(message) => crate::done(0, format!("{message}\n"), String::new()),
            Err(e) => err_out(&format!("{command}: {e}")),
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "openssl-backend")))]
    {
        let _ = (args, verify_only);
        err_out("release admission requires Linux and an openssl-backend supervisor (OpenSSL 3.5+)")
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-backend"))]
fn admission(args: &[OsString], verify_only: bool) -> Result<String, Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::io;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use boreas_supervisor::manifest::{
        MAX_ED25519_PUBLIC_KEY_DER_BYTES, MAX_MANIFEST_BYTES, MAX_METADATA_LIFETIME_SECONDS,
        MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES, ML_DSA_65_SIGNATURE_BYTES, ReleasePolicy, ReleaseRoot,
        SignatureEnvelope, verify_release,
    };
    use boreas_supervisor::preflight::MAX_ELF_BYTES;
    use boreas_supervisor::verified_stage::{native_asset, preflight, read_input, stage_approved};

    let flags = [
        "--store",
        "--manifest",
        "--artifact",
        "--root-key-id",
        "--root-ed25519-der",
        "--root-mldsa65-der",
        "--ed25519-signature",
        "--mldsa65-signature",
        "--min-sequence",
    ];
    const APPROVAL: &str = "--confirm-manifest-sha256";
    if args.len() != 2 * flags.len() && args.len() != 2 * (flags.len() + 1) {
        return Err(io::Error::other("expected all stage options exactly once (see --help)").into());
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid stage flag"))?;
        if (!flags.contains(&key) && key != APPROVAL) || values.insert(key, &pair[1]).is_some() {
            return Err(io::Error::other("unknown or duplicated stage flag").into());
        }
    }
    if flags.iter().any(|flag| !values.contains_key(*flag)) {
        return Err(io::Error::other("missing required stage option").into());
    }
    let expected = values
        .get(APPROVAL)
        .map(|value| {
            value
                .to_str()
                .filter(|hash| {
                    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                })
                .ok_or_else(|| io::Error::other("approval must be a lowercase SHA-256"))
        })
        .transpose()?;
    let file = |flag: &str, max| read_input(Path::new(values[flag]), max);
    let id = values["--root-key-id"]
        .to_str()
        .ok_or_else(|| io::Error::other("invalid root key id"))?;
    let min_sequence = values["--min-sequence"]
        .to_str()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::other("--min-sequence must be a positive integer"))?;
    let root = ReleaseRoot::new(
        id,
        file(
            "--root-ed25519-der",
            MAX_ED25519_PUBLIC_KEY_DER_BYTES as u64,
        )?,
        file(
            "--root-mldsa65-der",
            MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES as u64,
        )?,
    )?;
    let envelope = SignatureEnvelope::new(
        id,
        file("--ed25519-signature", 64)?
            .try_into()
            .map_err(|_| io::Error::other("invalid Ed25519 signature length"))?,
        file("--mldsa65-signature", ML_DSA_65_SIGNATURE_BYTES as u64)?,
    )?;
    let manifest = file("--manifest", MAX_MANIFEST_BYTES as u64)?;
    let (arch, _) = native_asset()?;
    let policy = ReleasePolicy::new(
        vec![arch.into()],
        MAX_METADATA_LIFETIME_SECONDS,
        min_sequence,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let candidate =
        verify_release(&manifest, &envelope, &[root])?.into_candidate(&policy, arch, now)?;
    let artifact = file("--artifact", candidate.asset()?.size().min(MAX_ELF_BYTES))?;
    policy.check(
        candidate.manifest().manifest(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let store = Path::new(values["--store"]);
    if verify_only {
        let (version, hash) = preflight(store, &candidate, &artifact, expected)?;
        Ok(format!("verified {version} {hash}"))
    } else {
        let version = stage_approved(store, &candidate, &artifact, expected)?;
        Ok(format!("staged {version}"))
    }
}
