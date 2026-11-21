use std::ffi::OsString;

use crate::{CliOutcome, err_out};

pub fn stage_command(args: &[OsString]) -> CliOutcome {
    #[cfg(all(target_os = "linux", feature = "openssl-backend"))]
    {
        match stage(args) {
            Ok(version) => crate::done(0, format!("staged {version}\n"), String::new()),
            Err(e) => err_out(&format!("stage: {e}")),
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "openssl-backend")))]
    {
        let _ = args;
        err_out("stage requires Linux and an openssl-backend supervisor (OpenSSL 3.5+)")
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-backend"))]
fn stage(args: &[OsString]) -> Result<String, Box<dyn std::error::Error>> {
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
    use boreas_supervisor::verified_stage::{native_asset, read_input, stage};

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
    if args.len() != 2 * flags.len() {
        return Err(
            io::Error::other("expected all stage options exactly once (see --help)").into(),
        );
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid stage flag"))?;
        if !flags.contains(&key) || values.insert(key, &pair[1]).is_some() {
            return Err(io::Error::other("unknown or duplicated stage flag").into());
        }
    }
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
    stage(Path::new(values["--store"]), &candidate, &artifact)
}
