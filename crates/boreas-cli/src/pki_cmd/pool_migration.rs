use std::{collections::HashMap, fs::OpenOptions, io::Write, path::Path};

use boreas_pki::{
    NetworkRootPin, VerifiedNetworkPolicy,
    management::{IdentityAuthority, MAX_SIGNED_OBJECT_BYTES, verify_ipv4_pool_migration},
    provisioning::{RootsBundle, hex_encode},
    root_authorization::VerifiedIssuerAuthorization,
    verify_network_policy,
};
use boreas_proto::{
    messages::SignedObject,
    network_policy::MAX_TBS_LEN,
    objects::{self, MldsaParameterSet},
};

use crate::network_policy_runtime::read_bounded_regular;

pub(super) fn run(command: &str, args: &[String]) -> Result<(), String> {
    let stage = command == "stage-pool-migration";
    let common = [
        "--legacy-identity",
        "--roots",
        "--expected-root-fingerprint",
        "--tbs-file",
        "--ed25519-signature-file",
        "--mldsa65-signature-file",
    ];
    let specific: &[&str] = if stage {
        &["--ca-dir", "--out"]
    } else {
        &["--staged-identity"]
    };
    let options = common
        .into_iter()
        .chain(specific.iter().copied())
        .collect::<Vec<_>>();
    let mut parsed = HashMap::new();
    let (pairs, tail) = args.as_chunks::<2>();
    for pair in pairs {
        let flag = pair[0].as_str();
        let value = pair[1].as_str();
        if !options.contains(&flag)
            || value.is_empty()
            || value.starts_with("--")
            || parsed.insert(flag, value).is_some()
        {
            return Err(format!(
                "pki {command}: invalid or duplicate argument `{flag}`"
            ));
        }
    }
    if !tail.is_empty() {
        return Err(format!("pki {command}: missing argument value"));
    }
    for flag in options {
        if !parsed.contains_key(flag) {
            return Err(format!("pki {command}: `{flag}` is required"));
        }
    }
    let result = run_with_inputs(stage, &parsed);
    result.map_err(|error| format!("pki {command}: {error}"))
}

fn read(path: &str, max: usize, label: &'static str) -> Result<Vec<u8>, String> {
    read_bounded_regular(Path::new(path), max, label).map_err(|e| e.to_string())
}

fn run_with_inputs(stage: bool, options: &HashMap<&str, &str>) -> Result<(), String> {
    let now = super::now_utc_us()?;
    let legacy = read(
        options["--legacy-identity"],
        MAX_SIGNED_OBJECT_BYTES,
        "invalid legacy identity file",
    )?;
    let (policy, issuer) = trust_inputs(options, &legacy, now)?;
    let staged = if stage {
        let ca = Path::new(options["--ca-dir"]);
        let record = issuer.issuer_record();
        let ed = read_bounded_regular(
            &ca.join("ia.ed25519.key"),
            16 * 1024,
            "invalid IdentityAuthority Ed25519 key file",
        )
        .map_err(|e| e.to_string())?;
        let pq = read_bounded_regular(
            &ca.join("ia.mldsa65.key"),
            16 * 1024,
            "invalid IdentityAuthority ML-DSA-65 key file",
        )
        .map_err(|e| e.to_string())?;
        let signer = IdentityAuthority::from_pkcs8_der(
            policy.net_id(),
            record.issuer_key_id,
            record.issuer_generation,
            &ed,
            &pq,
        )
        .map_err(|e| e.to_string())?;
        signer
            .stage_ipv4_pool_migration(&legacy, &policy, &issuer, now)
            .map_err(|e| e.to_string())?
    } else {
        read(
            options["--staged-identity"],
            MAX_SIGNED_OBJECT_BYTES,
            "invalid staged identity file",
        )?
    };
    let body = verify_ipv4_pool_migration(&legacy, &staged, &policy, &issuer, now)
        .map_err(|e| e.to_string())?;
    if stage {
        // Never overwrite an identity, including via a symlink or preexisting
        // hardlink. Use a new file in an operator-controlled staging directory.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(options["--out"])
            .map_err(|_| "cannot create a new staging output")?;
        file.write_all(&staged)
            .and_then(|()| file.sync_all())
            .map_err(|_| "cannot complete staging output; do not use any partial file")?;
    }
    println!(
        "{{\"status\":\"{}\",\"prefix_active\":false,\"policy_digest\":\"{}\",\"node_id\":{},\"vip\":\"{}\",\"identity_generation\":{}}}",
        if stage { "staged" } else { "verified" },
        hex_encode(&policy.policy_digest()),
        body.node_id,
        std::net::Ipv4Addr::from(body.vip),
        body.identity_generation,
    );
    Ok(())
}

fn trust_inputs(
    options: &HashMap<&str, &str>,
    legacy: &[u8],
    now: u64,
) -> Result<(VerifiedNetworkPolicy, VerifiedIssuerAuthorization), String> {
    let expected = options["--expected-root-fingerprint"];
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid independently pinned root fingerprint".into());
    }
    let roots = read(options["--roots"], 128 * 1024, "invalid roots bundle file")?;
    let roots = RootsBundle::decode(&roots).map_err(|e| e.to_string())?;
    let pin = NetworkRootPin::provisioned(
        roots.net_id,
        roots.root_ed25519_pub_der.clone(),
        MldsaParameterSet::Mldsa65,
        roots.root_mldsa65_pub_der.clone(),
    )
    .map_err(|e| e.to_string())?;
    if !hex_encode(&pin.fingerprint().map_err(|e| e.to_string())?).eq_ignore_ascii_case(expected) {
        return Err("roots bundle does not match independently pinned root fingerprint".into());
    }
    let tbs = read(
        options["--tbs-file"],
        MAX_TBS_LEN,
        "invalid policy TBS file",
    )?;
    let ed = read(
        options["--ed25519-signature-file"],
        64,
        "invalid Ed25519 signature file",
    )?;
    let pq = read(
        options["--mldsa65-signature-file"],
        3309,
        "invalid ML-DSA-65 signature file",
    )?;
    let policy = verify_network_policy(&tbs, &ed, &pq, &pin, roots.net_id, now)
        .map_err(|e| e.to_string())?;
    let envelope = SignedObject::decode(legacy).map_err(|_| "invalid legacy identity envelope")?;
    let source =
        objects::decode_tbs(&envelope.raw_tbs).map_err(|_| "invalid legacy identity TBS")?;
    let (_, authorizations) = roots
        .verify_all(roots.net_id, now)
        .map_err(|e| e.to_string())?;
    let mut matching = authorizations
        .into_iter()
        .filter(|candidate| candidate.issuer_record().issuer_key_id == source.issuer_key_id);
    let issuer = matching
        .next()
        .ok_or("missing source issuer authorization")?;
    if matching.next().is_some() {
        return Err("ambiguous source issuer authorization".into());
    }
    Ok((policy, issuer))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    #[test]
    fn offline_pool_migration_cli_roundtrip_with_pinned_root_and_no_overwrite() {
        use boreas_pki::{
            NodeRole,
            provisioning::{CaInitParams, NodeIssueParams, init_ca_dir, issue_node_dir},
        };
        let temp =
            std::env::temp_dir().join(format!("boreas-pool-migration-{}", std::process::id()));
        fs::create_dir(&temp).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(temp.clone());
        let ca = temp.join("ca");
        let source = temp.join("source");
        let policy = temp.join("policy");
        let staged = temp.join("staged.signed");
        let now = super::super::now_utc_us().unwrap();
        let ca_summary = init_ca_dir(&ca, &CaInitParams {
            net_id: [19; 16],
            issuer_generation: 1,
            now_us: now,
            validity_days: 30,
        })
        .unwrap();
        issue_node_dir(&ca, &source, &NodeIssueParams {
            role: NodeRole::Edge,
            home_core_id: 1,
            vip_octet: 2,
            identity_generation: 1,
            now_us: now,
            validity_hours: 48,
            outer_san_dns: None,
        })
        .unwrap();

        let invoke = |argv: &[&str]| {
            super::super::run_pki_command(
                &argv.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
            )
        };
        invoke(&[
            "sign-policy",
            "--ca-dir",
            ca.to_str().unwrap(),
            "--out-dir",
            policy.to_str().unwrap(),
            "--sequence",
            "3",
            "--overlay-prefix",
            "172.19.0.0/16",
        ])
        .unwrap();
        let path = |base: &std::path::Path, name| base.join(name).to_str().unwrap().to_owned();
        let legacy = path(&source, "local.signed");
        let roots = path(&ca, "roots.cbor");
        let tbs = path(&policy, "tbs.cbor");
        let ed = path(&policy, "ed25519.sig");
        let pq = path(&policy, "mldsa65.sig");
        let common = [
            "--legacy-identity",
            &legacy,
            "--roots",
            &roots,
            "--tbs-file",
            &tbs,
            "--ed25519-signature-file",
            &ed,
            "--mldsa65-signature-file",
            &pq,
            "--expected-root-fingerprint",
        ];
        let mut stage = vec![
            "stage-pool-migration",
            "--ca-dir",
            ca.to_str().unwrap(),
            "--out",
            staged.to_str().unwrap(),
        ];
        stage.extend(common);
        let wrong_fingerprint = "0".repeat(64);
        stage.push(&wrong_fingerprint);
        assert!(invoke(&stage).unwrap_err().contains("independently pinned"));
        assert!(!staged.exists());
        stage.pop();
        stage.push(&ca_summary.root_fingerprint_hex);
        invoke(&stage).unwrap();
        let original = fs::read(&staged).unwrap();
        assert!(invoke(&stage).unwrap_err().contains("new staging output"));
        assert_eq!(fs::read(&staged).unwrap(), original);

        let mut verify = vec![
            "verify-pool-migration",
            "--staged-identity",
            staged.to_str().unwrap(),
        ];
        verify.extend(common);
        verify.push(&ca_summary.root_fingerprint_hex);
        fs::remove_file(ca.join("ia.ed25519.key")).unwrap();
        fs::remove_file(ca.join("ia.mldsa65.key")).unwrap();
        invoke(&verify).unwrap();
    }
}
