//! Offline PKI management subcommands (`boreas pki ...`, master plan §2.2 / §10.4).
//!
//! Default builds have no OpenSSL 3.6+ ML-DSA backend and fail closed (`exit 2`).
//! With `openssl-inner-tls`, this provides:
//! - `boreas pki init-ca --ca-dir <DIR> [--net-id <32HEX>] [--validity-days <N>]`
//! - `boreas pki issue-node --ca-dir <DIR> --out-dir <DIR> --role core|edge --home-core <1..16> --vip-octet <1|2..251> [--generation <N>] [--validity-hours <N>] [--outer-san <DNS>]`
//! - `boreas pki sign-status --ca-dir <DIR> --out <FILE> --sequence <N> [--ttl-seconds <1..86400>]`
//! - `boreas pki sign-policy --ca-dir <DIR> --out-dir <DIR> --sequence <N> [--ttl-seconds <1..315360000>]`
//! - `boreas pki verify-bundle --material-dir <DIR> [--roots <FILE>] [--require-peer]`
//! - `boreas pki verify-policy --tbs-file <FILE> --ed25519-signature-file <FILE> --mldsa65-signature-file <FILE> --net-id <32HEX> --root-ed25519-der <FILE> --root-mldsa65-der <FILE>`

#[cfg(not(feature = "openssl-inner-tls"))]
pub fn run_pki_command(args: &[String]) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("{}", pki_usage());
        return Ok(());
    }
    Err("pki: offline ML-DSA-65 PKI commands require a binary built with `--features openssl-inner-tls` (OpenSSL 3.6+)".to_string())
}

pub fn pki_usage() -> &'static str {
    "Usage:
  boreas pki init-ca --ca-dir <DIR> [--net-id <32HEX>] [--generation <N>] [--validity-days <1..3650>]
  boreas pki issue-node --ca-dir <DIR> --out-dir <DIR> --role <core|edge> --home-core <1..16> --vip-octet <1..251> [--generation <N>] [--validity-hours <N>] [--outer-san <DNS>]
  boreas pki sign-status --ca-dir <DIR> --out <FILE> --sequence <N> [--ttl-seconds <1..86400>]
  boreas pki sign-policy --ca-dir <DIR> --out-dir <DIR> --sequence <N> [--ttl-seconds <1..315360000>]
  boreas pki verify-bundle --material-dir <DIR> [--roots <FILE>] [--require-peer]
  boreas pki verify-policy --tbs-file <FILE> --ed25519-signature-file <FILE> --mldsa65-signature-file <FILE> --net-id <32HEX> --root-ed25519-der <FILE> --root-mldsa65-der <FILE> [--record-state --state-file <ABSOLUTE> (--expect-first-use | --expect-seq <N> --expect-hash <64HEX>)]"
}

#[cfg(feature = "openssl-inner-tls")]
pub fn run_pki_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help"))
    {
        println!("{}", pki_usage());
        return Ok(());
    }
    match args[0].as_str() {
        "init-ca" => cmd_init_ca(&args[1..]),
        "issue-node" => cmd_issue_node(&args[1..]),
        "sign-status" => cmd_sign_status(&args[1..]),
        "sign-policy" => cmd_sign_policy(&args[1..]),
        "verify-bundle" => cmd_verify_bundle(&args[1..]),
        "verify-policy" => cmd_verify_policy(&args[1..]),
        _ => Err("pki: unknown subcommand (run `boreas pki --help`)".to_string()),
    }
}

#[cfg(feature = "openssl-inner-tls")]
fn now_utc_us() -> Result<u64, String> {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before UNIX_EPOCH".to_string())?;
    u64::try_from(dur.as_micros()).map_err(|_| "system clock overflow".to_string())
}

#[cfg(feature = "openssl-inner-tls")]
fn random_net_id() -> Result<[u8; 16], String> {
    let raw = boreas_tunnel::csprng::random_array::<16>()
        .map_err(|_| "OS CSPRNG unavailable for net_id".to_string())?;
    if raw == [0u8; 16] {
        return Err("degenerate zero net_id".to_string());
    }
    Ok(raw)
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_init_ca(args: &[String]) -> Result<(), String> {
    use boreas_pki::provisioning::{CaInitParams, init_ca_dir, parse_net_id_hex};
    use std::path::PathBuf;

    let mut ca_dir: Option<PathBuf> = None;
    let mut net_id_opt: Option<[u8; 16]> = None;
    let mut generation: u64 = 1;
    let mut validity_days: u32 = 365;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("pki init-ca: missing value for `{flag}`"))?;
        match flag {
            "--ca-dir" => ca_dir = Some(PathBuf::from(val)),
            "--net-id" => {
                net_id_opt = Some(parse_net_id_hex(val).map_err(|e| format!("pki init-ca: {e}"))?)
            }
            "--generation" => {
                generation = val
                    .parse::<u64>()
                    .map_err(|_| "pki init-ca: invalid --generation".to_string())?
            }
            "--validity-days" => {
                validity_days = val
                    .parse::<u32>()
                    .map_err(|_| "pki init-ca: invalid --validity-days".to_string())?
            }
            _ => return Err("pki init-ca: unknown argument".to_string()),
        }
        i += 2;
    }

    let ca_dir = ca_dir.ok_or_else(|| "pki init-ca: `--ca-dir` is required".to_string())?;
    let net_id = match net_id_opt {
        Some(id) => id,
        None => random_net_id()?,
    };
    let summary = init_ca_dir(
        &ca_dir,
        &CaInitParams {
            net_id,
            issuer_generation: generation,
            now_us: now_utc_us()?,
            validity_days,
        },
    )
    .map_err(|e| format!("pki init-ca failed: {e}"))?;

    println!(
        "{{\"command\":\"pki.init-ca\",\"status\":\"ok\",\"net_id\":\"{}\",\"root_fingerprint\":\"{}\",\"issuer_generation\":{},\"expires_us\":{}}}",
        summary.net_id_hex,
        summary.root_fingerprint_hex,
        summary.issuer_generation,
        summary.expires_us
    );
    Ok(())
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_issue_node(args: &[String]) -> Result<(), String> {
    use boreas_pki::{
        NodeRole,
        provisioning::{NodeIssueParams, issue_node_dir},
    };
    use std::path::PathBuf;

    let mut ca_dir: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut role: Option<NodeRole> = None;
    let mut home_core_id: Option<u8> = None;
    let mut vip_octet: Option<u8> = None;
    let mut generation: u64 = 1;
    let mut validity_hours: u32 = 24 * 30;
    let mut outer_san_dns: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("pki issue-node: missing value for `{flag}`"))?;
        match flag {
            "--ca-dir" => ca_dir = Some(PathBuf::from(val)),
            "--out-dir" => out_dir = Some(PathBuf::from(val)),
            "--role" => {
                role = Some(match val.as_str() {
                    "core" => NodeRole::Core,
                    "edge" => NodeRole::Edge,
                    _ => return Err("pki issue-node: --role must be `core` or `edge`".to_string()),
                })
            }
            "--home-core" => {
                home_core_id = Some(
                    val.parse::<u8>()
                        .map_err(|_| "pki issue-node: invalid --home-core".to_string())?,
                )
            }
            "--vip-octet" => {
                vip_octet = Some(
                    val.parse::<u8>()
                        .map_err(|_| "pki issue-node: invalid --vip-octet".to_string())?,
                )
            }
            "--generation" => {
                generation = val
                    .parse::<u64>()
                    .map_err(|_| "pki issue-node: invalid --generation".to_string())?
            }
            "--validity-hours" => {
                validity_hours = val
                    .parse::<u32>()
                    .map_err(|_| "pki issue-node: invalid --validity-hours".to_string())?
            }
            "--outer-san" => outer_san_dns = Some(val.clone()),
            _ => return Err("pki issue-node: unknown argument".to_string()),
        }
        i += 2;
    }

    let ca_dir = ca_dir.ok_or_else(|| "pki issue-node: `--ca-dir` is required".to_string())?;
    let out_dir = out_dir.ok_or_else(|| "pki issue-node: `--out-dir` is required".to_string())?;
    let role = role.ok_or_else(|| "pki issue-node: `--role` is required".to_string())?;
    let home_core_id =
        home_core_id.ok_or_else(|| "pki issue-node: `--home-core` is required".to_string())?;
    let vip_octet =
        vip_octet.ok_or_else(|| "pki issue-node: `--vip-octet` is required".to_string())?;

    let summary = issue_node_dir(
        &ca_dir,
        &out_dir,
        &NodeIssueParams {
            role,
            home_core_id,
            vip_octet,
            identity_generation: generation,
            now_us: now_utc_us()?,
            validity_hours,
            outer_san_dns,
        },
    )
    .map_err(|e| format!("pki issue-node failed: {e}"))?;

    let role_str = match summary.role {
        NodeRole::Core => "core",
        NodeRole::Edge => "edge",
        NodeRole::EnrollmentService => "enrollment",
    };
    println!(
        "{{\"command\":\"pki.issue-node\",\"status\":\"ok\",\"net_id\":\"{}\",\"role\":\"{}\",\"node_id\":{},\"home_core_id\":{},\"vip\":\"{}.{}.{}.{}\",\"identity_generation\":{},\"expires_us\":{}}}",
        summary.net_id_hex,
        role_str,
        summary.node_id,
        summary.home_core_id,
        summary.vip[0],
        summary.vip[1],
        summary.vip[2],
        summary.vip[3],
        summary.identity_generation,
        summary.expires_us
    );
    Ok(())
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_sign_status(args: &[String]) -> Result<(), String> {
    use boreas_pki::provisioning::sign_status_file;
    use std::path::PathBuf;

    let mut ca_dir: Option<PathBuf> = None;
    let mut out_file: Option<PathBuf> = None;
    let mut sequence: Option<u64> = None;
    let mut ttl_seconds: u64 = 3600;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("pki sign-status: missing value for `{flag}`"))?;
        match flag {
            "--ca-dir" => ca_dir = Some(PathBuf::from(val)),
            "--out" => out_file = Some(PathBuf::from(val)),
            "--sequence" => {
                sequence = Some(
                    val.parse::<u64>()
                        .map_err(|_| "pki sign-status: invalid --sequence".to_string())?,
                )
            }
            "--ttl-seconds" => {
                ttl_seconds = val
                    .parse::<u64>()
                    .map_err(|_| "pki sign-status: invalid --ttl-seconds".to_string())?
            }
            _ => return Err("pki sign-status: unknown argument".to_string()),
        }
        i += 2;
    }

    let ca_dir = ca_dir.ok_or_else(|| "pki sign-status: `--ca-dir` is required".to_string())?;
    let out_file = out_file.ok_or_else(|| "pki sign-status: `--out` is required".to_string())?;
    let sequence =
        sequence.ok_or_else(|| "pki sign-status: `--sequence` is required".to_string())?;

    let summary = sign_status_file(&ca_dir, &out_file, sequence, now_utc_us()?, ttl_seconds)
        .map_err(|e| format!("pki sign-status failed: {e}"))?;

    println!(
        "{{\"command\":\"pki.sign-status\",\"status\":\"ok\",\"net_id\":\"{}\",\"sequence\":{},\"issued_at_us\":{},\"next_update_us\":{}}}",
        summary.net_id_hex, summary.sequence, summary.issued_at_us, summary.next_update_us
    );
    Ok(())
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_sign_policy(args: &[String]) -> Result<(), String> {
    use boreas_pki::provisioning::sign_network_policy_dir;
    use std::path::PathBuf;

    let mut ca_dir: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut sequence: Option<u64> = None;
    let mut ttl_seconds: u64 = 3600;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("pki sign-policy: missing value for `{flag}`"))?;
        match flag {
            "--ca-dir" => ca_dir = Some(PathBuf::from(val)),
            "--out-dir" => out_dir = Some(PathBuf::from(val)),
            "--sequence" => {
                sequence = Some(
                    val.parse::<u64>()
                        .map_err(|_| "pki sign-policy: invalid --sequence".to_string())?,
                )
            }
            "--ttl-seconds" => {
                ttl_seconds = val
                    .parse::<u64>()
                    .map_err(|_| "pki sign-policy: invalid --ttl-seconds".to_string())?
            }
            _ => return Err("pki sign-policy: unknown argument".to_string()),
        }
        i += 2;
    }

    let ca_dir = ca_dir.ok_or_else(|| "pki sign-policy: `--ca-dir` is required".to_string())?;
    let out_dir = out_dir.ok_or_else(|| "pki sign-policy: `--out-dir` is required".to_string())?;
    let sequence =
        sequence.ok_or_else(|| "pki sign-policy: `--sequence` is required".to_string())?;

    let summary = sign_network_policy_dir(&ca_dir, &out_dir, sequence, now_utc_us()?, ttl_seconds)
        .map_err(|e| format!("pki sign-policy failed: {e}"))?;

    println!(
        "{{\"command\":\"pki.sign-policy\",\"status\":\"ok\",\"net_id\":\"{}\",\"root_fingerprint\":\"{}\",\"sequence\":{},\"issued_at_us\":{},\"expires_us\":{}}}",
        summary.net_id_hex,
        summary.root_fingerprint_hex,
        summary.sequence,
        summary.issued_at_us,
        summary.expires_us
    );
    Ok(())
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_verify_policy(args: &[String]) -> Result<(), String> {
    use boreas_pki::provisioning::{hex_encode, parse_net_id_hex};
    use boreas_pki::{root_authorization::NetworkRootPin, verify_network_policy};
    use boreas_proto::objects::MldsaParameterSet;
    use std::{
        collections::HashMap,
        io::Read,
        path::{Path, PathBuf},
    };

    fn read_input(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>, String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| format!("pki verify-policy: cannot inspect {label}"))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > limit as u64
        {
            return Err(format!("pki verify-policy: invalid or oversized {label}"));
        }
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| format!("pki verify-policy: cannot safely open {label}"))?
        };
        #[cfg(not(unix))]
        let mut file = {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
            }
            options
                .open(path)
                .map_err(|_| format!("pki verify-policy: cannot safely open {label}"))?
        };
        let opened_meta = file
            .metadata()
            .map_err(|_| format!("pki verify-policy: cannot inspect {label}"))?;
        if !opened_meta.file_type().is_file() || opened_meta.len() > limit as u64 {
            return Err(format!("pki verify-policy: invalid or oversized {label}"));
        }
        let mut bytes = Vec::with_capacity(opened_meta.len() as usize);
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| format!("pki verify-policy: cannot read {label}"))?;
        if bytes.is_empty() || bytes.len() > limit {
            return Err(format!("pki verify-policy: empty or oversized {label}"));
        }
        Ok(bytes)
    }

    let required = [
        "--tbs-file",
        "--ed25519-signature-file",
        "--mldsa65-signature-file",
        "--net-id",
        "--root-ed25519-der",
        "--root-mldsa65-der",
    ];
    let record_flags = [
        "--record-state",
        "--state-file",
        "--expect-first-use",
        "--expect-seq",
        "--expect-hash",
    ];
    let mut values = HashMap::new();
    let mut record_state = false;
    let mut first_use = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--record-state" || flag == "--expect-first-use" {
            if (flag == "--record-state" && record_state)
                || (flag == "--expect-first-use" && first_use)
            {
                return Err(format!("pki verify-policy: duplicate argument `{flag}`"));
            }
            if flag == "--record-state" {
                record_state = true;
            } else {
                first_use = true;
            }
            i += 1;
            continue;
        }
        if !required.contains(&flag) && !record_flags.contains(&flag) {
            return Err(format!("pki verify-policy: unknown argument `{flag}`"));
        }
        if values.contains_key(flag) {
            return Err(format!("pki verify-policy: duplicate argument `{flag}`"));
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("pki verify-policy: missing value for `{flag}`"))?;
        if value.starts_with("--") {
            return Err(format!("pki verify-policy: missing value for `{flag}`"));
        }
        values.insert(flag, value);
        i += 2;
    }
    for flag in required {
        if !values.contains_key(flag) {
            return Err(format!("pki verify-policy: `{flag}` is required"));
        }
    }
    let state_path = values.get("--state-file").map(|s| PathBuf::from(*s));
    let seq_text = values.get("--expect-seq");
    let hash_text = values.get("--expect-hash");
    let has_any_record = record_state
        || first_use
        || state_path.is_some()
        || seq_text.is_some()
        || hash_text.is_some();
    if has_any_record && !record_state {
        return Err("pki verify-policy: record options require --record-state".into());
    }
    let expected = if record_state {
        let path = state_path
            .as_ref()
            .ok_or("pki verify-policy: --state-file is required")?;
        if !path.is_absolute() {
            return Err("pki verify-policy: --state-file must be absolute".into());
        }
        if first_use {
            if seq_text.is_some() || hash_text.is_some() {
                return Err(
                    "pki verify-policy: --expect-first-use cannot mix with seq/hash".into(),
                );
            }
            None
        } else {
            let seq = seq_text
                .ok_or("pki verify-policy: expected watermark required")?
                .parse::<u64>()
                .map_err(|_| "pki verify-policy: invalid --expect-seq")?;
            let hash = hash_text.ok_or("pki verify-policy: expected watermark required")?;
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("pki verify-policy: invalid --expect-hash".into());
            }
            let mut bytes = [0u8; 32];
            for (i, pair) in hash.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                    .map_err(|_| "pki verify-policy: invalid --expect-hash")?;
            }
            Some((seq, bytes))
        }
    } else {
        None
    };
    let net_id = parse_net_id_hex(values["--net-id"])
        .map_err(|e| format!("pki verify-policy: invalid --net-id: {e}"))?;
    let tbs = read_input(Path::new(values["--tbs-file"]), 16 * 1024, "TBS")?;
    let ed_sig = read_input(
        Path::new(values["--ed25519-signature-file"]),
        64,
        "Ed25519 signature",
    )?;
    let pq_sig = read_input(
        Path::new(values["--mldsa65-signature-file"]),
        3309,
        "ML-DSA-65 signature",
    )?;
    if ed_sig.len() != 64 || pq_sig.len() != 3309 {
        return Err("pki verify-policy: signature has invalid length".to_string());
    }
    let ed_der = read_input(
        Path::new(values["--root-ed25519-der"]),
        4096,
        "Ed25519 root key",
    )?;
    let pq_der = read_input(
        Path::new(values["--root-mldsa65-der"]),
        4096,
        "ML-DSA-65 root key",
    )?;
    let pin = NetworkRootPin::provisioned(net_id, ed_der, MldsaParameterSet::Mldsa65, pq_der)
        .map_err(|e| format!("pki verify-policy: invalid root pin: {e}"))?;
    let now = now_utc_us()?;
    let verified = verify_network_policy(&tbs, &ed_sig, &pq_sig, &pin, net_id, now)
        .map_err(|e| format!("pki verify-policy failed: {e}"))?;
    let overlay = verified.overlay_base();
    let (issued, expires) = verified.validity();
    let durable: Option<(&str, u64, String)> = if record_state {
        #[cfg(target_os = "linux")]
        {
            let owner = unsafe { libc::geteuid() };
            if !state_path.as_ref().unwrap().is_absolute() {
                return Err("pki verify-policy: state path must be absolute".into());
            }
            let mut store =
                boreas_pki::network_policy_store::NetworkPolicyStore::open_with_expected(
                    state_path.as_ref().unwrap(),
                    net_id,
                    verified.root_key_fingerprint(),
                    owner,
                    expected,
                )
                .map_err(|e| format!("pki verify-policy: state open failed: {e}"))?;
            let result = store
                .commit(&verified, &tbs)
                .map_err(|e| format!("pki verify-policy: state commit failed: {e}"))?;
            let status = match result {
                boreas_pki::network_policy_store::CommitResult::Committed => "recorded",
                boreas_pki::network_policy_store::CommitResult::Duplicate => "duplicate",
            };
            let seq = store.sequence().unwrap_or(verified.seq());
            let hash = hex_encode(
                &store
                    .current_object_hash()
                    .ok_or("pki verify-policy: committed state has no hash")?,
            );
            Some((status, seq, hash))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, state_path);
            return Err("pki verify-policy: durable recording unsupported on this platform".into());
        }
    } else {
        None
    };
    let durable_json = durable.map(|(status, seq, hash)| format!(",\"durable_record\":\"{status}\",\"durable_sequence\":{seq},\"object_hash\":\"{hash}\",\"prefix_active\":false")).unwrap_or_default();
    println!(
        "{{\"command\":\"pki.verify-policy\",\"status\":\"ok\",\"net_id\":\"{}\",\"root_fingerprint\":\"{}\",\"overlay_base\":\"{}.{}.{}.{}\",\"version\":{},\"sequence\":{},\"issued_at_us\":{},\"expires_us\":{},\"clock\":\"local-untrusted\",\"pin_provenance\":\"operator-supplied; verify independently\"{}}}",
        hex_encode(&verified.net_id()),
        hex_encode(&verified.root_key_fingerprint()),
        overlay[0],
        overlay[1],
        overlay[2],
        overlay[3],
        verified.version(),
        verified.seq(),
        issued,
        expires,
        durable_json
    );
    Ok(())
}

#[cfg(all(test, feature = "openssl-inner-tls"))]
mod verify_policy_cli_tests {
    use super::*;
    use boreas_proto::network_policy::NetworkPolicyCandidate;
    use std::process::Command;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "boreas-policy-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }
    fn run(args: &[&str]) -> Result<(), String> {
        run_pki_command(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }
    fn baseline(dir: &std::path::Path) -> Vec<String> {
        let mut args = Vec::new();
        for (flag, file, bytes) in [
            ("--tbs-file", "tbs", vec![1]),
            ("--ed25519-signature-file", "ed", vec![0; 64]),
            ("--mldsa65-signature-file", "pq", vec![0; 3309]),
            ("--root-ed25519-der", "ed.der", vec![1]),
            ("--root-mldsa65-der", "pq.der", vec![1]),
        ] {
            fs::write(dir.join(file), bytes).unwrap();
            args.extend([
                flag.to_string(),
                dir.join(file).to_string_lossy().into_owned(),
            ]);
        }
        args.extend([
            "--net-id".to_string(),
            "03030303030303030303030303030303".to_string(),
        ]);
        args
    }
    fn openssl_bin() -> std::ffi::OsString {
        std::env::var_os("BOREAS_OPENSSL_BIN").expect(
            "BOREAS_OPENSSL_BIN is required for verify-policy CLI E2E tests (pinned OpenSSL with ML-DSA-65); refusing to skip",
        )
    }

    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new(openssl_bin())
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run pinned BOREAS_OPENSSL_BIN");
        assert!(
            output.status.success(),
            "openssl {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn keys(dir: &Path, suffix: &str) -> (PathBuf, PathBuf, Vec<u8>, Vec<u8>) {
        let ed_key = dir.join(format!("{suffix}.ed.key"));
        let pq_key = dir.join(format!("{suffix}.pq.key"));
        let ed_pub = dir.join(format!("{suffix}.ed.der"));
        let pq_pub = dir.join(format!("{suffix}.pq.der"));
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                ed_key.to_str().unwrap(),
            ],
        );
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "ML-DSA-65",
                "-out",
                pq_key.to_str().unwrap(),
            ],
        );
        openssl(
            dir,
            &[
                "pkey",
                "-in",
                ed_key.to_str().unwrap(),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                ed_pub.to_str().unwrap(),
            ],
        );
        openssl(
            dir,
            &[
                "pkey",
                "-in",
                pq_key.to_str().unwrap(),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                pq_pub.to_str().unwrap(),
            ],
        );
        (
            ed_key,
            pq_key,
            fs::read(ed_pub).unwrap(),
            fs::read(pq_pub).unwrap(),
        )
    }

    fn sign(
        dir: &Path,
        keys: &(PathBuf, PathBuf, Vec<u8>, Vec<u8>),
        tbs: &[u8],
        suffix: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let input = NetworkPolicyCandidate::signature_input(tbs).unwrap();
        let input_path = dir.join(format!("{suffix}.input"));
        let ed_sig_path = dir.join(format!("{suffix}.ed.sig"));
        let pq_sig_path = dir.join(format!("{suffix}.pq.sig"));
        fs::write(&input_path, input).unwrap();
        for (key, sig) in [(&keys.0, &ed_sig_path), (&keys.1, &pq_sig_path)] {
            openssl(
                dir,
                &[
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    key.to_str().unwrap(),
                    "-in",
                    input_path.to_str().unwrap(),
                    "-out",
                    sig.to_str().unwrap(),
                ],
            );
        }
        (
            fs::read(ed_sig_path).unwrap(),
            fs::read(pq_sig_path).unwrap(),
        )
    }

    fn policy(now: u64, fingerprint: [u8; 32]) -> Vec<u8> {
        NetworkPolicyCandidate {
            net_id: [3; 16],
            root_key_fingerprint: fingerprint,
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 4,
            issued_at: now.saturating_sub(60_000_000),
            expires: now.saturating_add(60_000_000),
        }
        .encode_tbs()
        .unwrap()
    }

    fn write_material(
        dir: &Path,
        tbs: &[u8],
        ed_sig: &[u8],
        pq_sig: &[u8],
        ed_der: &[u8],
        pq_der: &[u8],
    ) -> Vec<String> {
        let mut args = Vec::new();
        for (flag, name, bytes) in [
            ("--tbs-file", "tbs", tbs),
            ("--ed25519-signature-file", "ed.sig", ed_sig),
            ("--mldsa65-signature-file", "pq.sig", pq_sig),
            ("--root-ed25519-der", "ed.der", ed_der),
            ("--root-mldsa65-der", "pq.der", pq_der),
        ] {
            fs::write(dir.join(name), bytes).unwrap();
            args.extend([
                flag.to_string(),
                dir.join(name).to_string_lossy().into_owned(),
            ]);
        }
        args.extend([
            "--net-id".to_string(),
            "03030303030303030303030303030303".to_string(),
        ]);
        args
    }

    fn invoke(args: &[String]) -> Result<(), String> {
        let argv = std::iter::once("verify-policy".to_string())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>();
        run_pki_command(&argv)
    }

    #[test]
    fn verify_policy_cli_accepts_real_dual_signed_candidate_and_rejects_tampering() {
        let dir = temp_dir();
        let root = keys(&dir, "root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            [3; 16],
            root.2.clone(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            root.3.clone(),
        )
        .unwrap();
        let tbs = policy(now_utc_us().unwrap(), pin.fingerprint().unwrap());
        let (ed_sig, pq_sig) = sign(&dir, &root, &tbs, "valid");
        let mut args = write_material(&dir, &tbs, &ed_sig, &pq_sig, &root.2, &root.3);
        let original = ["tbs", "ed.sig", "pq.sig", "ed.der", "pq.der"]
            .map(|name| fs::read(dir.join(name)).unwrap());
        assert!(
            invoke(&args).is_ok(),
            "valid signatures and current local time window should pass"
        );
        for (name, expected) in ["tbs", "ed.sig", "pq.sig", "ed.der", "pq.der"]
            .into_iter()
            .zip(&original)
        {
            assert_eq!(
                fs::read(dir.join(name)).unwrap(),
                *expected,
                "verifier must not mutate local input files"
            );
        }

        let mut bad_ed = ed_sig.clone();
        bad_ed[0] ^= 1;
        fs::write(dir.join("ed.sig"), &bad_ed).unwrap();
        assert!(invoke(&args).is_err());
        fs::write(dir.join("ed.sig"), &ed_sig).unwrap();
        let mut bad_pq = pq_sig.clone();
        bad_pq[0] ^= 1;
        fs::write(dir.join("pq.sig"), &bad_pq).unwrap();
        assert!(invoke(&args).is_err());
        fs::write(dir.join("pq.sig"), &pq_sig).unwrap();

        let wrong_root = keys(&dir, "wrong");
        fs::write(dir.join("ed.der"), &wrong_root.2).unwrap();
        fs::write(dir.join("pq.der"), &wrong_root.3).unwrap();
        assert!(invoke(&args).is_err(), "a pin for the wrong root must fail");
        fs::write(dir.join("ed.der"), &root.2).unwrap();
        fs::write(dir.join("pq.der"), &root.3).unwrap();

        let expired = NetworkPolicyCandidate {
            net_id: [3; 16],
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 5,
            issued_at: 1,
            expires: 2,
        }
        .encode_tbs()
        .unwrap();
        let (expired_ed, expired_pq) = sign(&dir, &root, &expired, "expired");
        args = write_material(&dir, &expired, &expired_ed, &expired_pq, &root.2, &root.3);

        let expired_snapshot = ["tbs", "ed.sig", "pq.sig", "ed.der", "pq.der"]
            .map(|name| fs::read(dir.join(name)).unwrap());
        assert!(
            invoke(&args).is_err(),
            "a correctly signed expired candidate must fail"
        );
        for (name, expected) in ["tbs", "ed.sig", "pq.sig", "ed.der", "pq.der"]
            .into_iter()
            .zip(expired_snapshot)
        {
            assert_eq!(
                fs::read(dir.join(name)).unwrap(),
                expected,
                "verifier must not mutate local input files on failure",
            );
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_policy_cli_persists_equivocation_freeze_and_rejects_stale_state() {
        use boreas_pki::network_policy_store::NetworkPolicyStore;

        let dir = temp_dir();
        let state = dir.join("policy.state");
        let root = keys(&dir, "equiv-root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            [3; 16],
            root.2.clone(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            root.3.clone(),
        )
        .unwrap();
        let fingerprint = pin.fingerprint().unwrap();
        let now = now_utc_us().unwrap();
        let candidate = |seq, expires| {
            NetworkPolicyCandidate {
                net_id: [3; 16],
                root_key_fingerprint: fingerprint,
                overlay_base: [10, 20, 0, 0],
                version: 1,
                seq,
                issued_at: now.saturating_sub(60_000_000),
                expires,
            }
            .encode_tbs()
            .unwrap()
        };
        let run_candidate = |raw: &[u8], suffix: &str, extra: &[&str]| -> Result<(), String> {
            let (ed, pq) = sign(&dir, &root, raw, suffix);
            let mut args = write_material(&dir, raw, &ed, &pq, &root.2, &root.3);
            args.extend([
                "--record-state".into(),
                "--state-file".into(),
                state.to_string_lossy().into_owned(),
            ]);
            args.extend(extra.iter().map(|s| (*s).to_string()));
            invoke(&args)
        };

        let first = candidate(7, now.saturating_add(60_000_000));
        let (first_ed, first_pq) = sign(&dir, &root, &first, "equiv-first-readonly");
        let readonly_args = write_material(&dir, &first, &first_ed, &first_pq, &root.2, &root.3);
        assert!(
            invoke(&readonly_args).is_ok(),
            "default verification remains read-only"
        );
        assert!(
            !state.exists(),
            "default verification must not create durable state"
        );
        assert!(run_candidate(&first, "equiv-first", &["--expect-first-use"]).is_ok());
        let hash =
            NetworkPolicyStore::open(&state, [3; 16], fingerprint, unsafe { libc::geteuid() })
                .unwrap()
                .current_object_hash()
                .unwrap();
        let hash_hex = boreas_pki::provisioning::hex_encode(&hash);

        // Same sequence and prefix, but a different valid expiry produces a distinct signed TBS.
        let conflicting = candidate(7, now.saturating_add(90_000_000));
        assert!(
            run_candidate(
                &conflicting,
                "equiv-second",
                &["--expect-seq", "7", "--expect-hash", &hash_hex]
            )
            .unwrap_err()
            .contains("Equivocation")
        );
        let frozen =
            NetworkPolicyStore::open(&state, [3; 16], fingerprint, unsafe { libc::geteuid() })
                .unwrap();
        assert!(
            frozen.is_frozen(),
            "equivocation freeze must survive reopen"
        );
        drop(frozen);
        let higher = candidate(8, now.saturating_add(120_000_000));
        assert!(
            run_candidate(
                &higher,
                "equiv-higher",
                &["--expect-seq", "7", "--expect-hash", &hash_hex]
            )
            .is_err(),
            "a higher sequence must not clear the persisted freeze"
        );

        // A stale expected watermark must not initialize a deleted state file.
        fs::remove_file(&state).unwrap();
        assert!(
            run_candidate(
                &first,
                "equiv-deleted-state",
                &["--expect-seq", "7", "--expect-hash", &hash_hex]
            )
            .is_err()
        );
        assert!(
            !state.exists(),
            "failed expected-watermark open must not recreate state"
        );

        // Missing expectation flags are rejected before any durable state is created.
        assert!(run_candidate(&first, "equiv-no-expectation", &[]).is_err());
        assert!(
            !state.exists(),
            "missing expectation must fail without writing state"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_policy_cli_records_only_verified_candidates_against_expected_watermark() {
        use boreas_pki::network_policy_store::NetworkPolicyStore;
        let dir = temp_dir();
        let state = dir.join("policy.state");
        let root = keys(&dir, "record-root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            [3; 16],
            root.2.clone(),
            boreas_proto::objects::MldsaParameterSet::Mldsa65,
            root.3.clone(),
        )
        .unwrap();
        let now = now_utc_us().unwrap();
        let candidate = |seq, issued, prefix, version| {
            NetworkPolicyCandidate {
                net_id: [3; 16],
                root_key_fingerprint: pin.fingerprint().unwrap(),
                overlay_base: prefix,
                version,
                seq,
                issued_at: issued,
                expires: now + 60_000_000,
            }
            .encode_tbs()
            .unwrap()
        };
        let run_candidate = |raw: &[u8], suffix: &str, expected: &[&str]| -> Result<(), String> {
            let (ed, pq) = sign(&dir, &root, raw, suffix);
            let mut args = write_material(&dir, raw, &ed, &pq, &root.2, &root.3);
            args.extend([
                "--record-state".into(),
                "--state-file".into(),
                state.to_string_lossy().into_owned(),
            ]);
            args.extend(expected.iter().map(|x| (*x).to_string()));
            invoke(&args)
        };
        let first = candidate(4, now.saturating_sub(60_000_000), [10, 20, 0, 0], 1);
        assert!(run_candidate(&first, "record-first", &["--expect-first-use"]).is_ok());
        let fingerprint = pin.fingerprint().unwrap();
        let store =
            NetworkPolicyStore::open(&state, [3; 16], fingerprint, unsafe { libc::geteuid() })
                .unwrap();
        let hash = store.current_object_hash().unwrap();
        assert_ne!(
            hash, [0u8; 32],
            "committed state exposes a nonzero object hash"
        );
        assert_eq!(store.sequence(), Some(4));
        drop(store);
        let hash_hex = boreas_pki::provisioning::hex_encode(&hash);
        assert!(
            run_candidate(
                &first,
                "record-duplicate",
                &["--expect-seq", "4", "--expect-hash", &hash_hex]
            )
            .is_ok()
        );
        let higher = candidate(5, now.saturating_sub(30_000_000), [10, 20, 0, 0], 1);
        assert!(
            run_candidate(
                &higher,
                "record-higher",
                &["--expect-seq", "4", "--expect-hash", &hash_hex]
            )
            .is_ok()
        );
        let higher_hash = boreas_pki::provisioning::hex_encode(
            &NetworkPolicyStore::open(&state, [3; 16], fingerprint, unsafe { libc::geteuid() })
                .unwrap()
                .current_object_hash()
                .unwrap(),
        );
        let lower = candidate(3, now.saturating_sub(20_000_000), [10, 20, 0, 0], 1);
        assert!(
            run_candidate(
                &lower,
                "record-lower",
                &["--expect-seq", "5", "--expect-hash", &higher_hash]
            )
            .is_err()
        );
        let conflict = candidate(6, now.saturating_sub(10_000_000), [10, 21, 0, 0], 1);
        assert!(
            run_candidate(
                &conflict,
                "record-conflict",
                &["--expect-seq", "5", "--expect-hash", &higher_hash]
            )
            .is_err()
        );
        assert!(run_candidate(&higher, "record-missing-expect", &[]).is_err());
        let final_store =
            NetworkPolicyStore::open(&state, [3; 16], fingerprint, unsafe { libc::geteuid() })
                .unwrap();
        assert_eq!(
            final_store.sequence(),
            Some(5),
            "refusals must not advance durable state"
        );
        drop(final_store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_policy_rejects_unknown_duplicate_and_missing_flags() {
        assert!(
            run(&["verify-policy", "--unknown", "x"])
                .unwrap_err()
                .contains("unknown")
        );
        let dir = temp_dir();
        let args = baseline(&dir);
        let mut duplicate = args.clone();
        duplicate.extend(["--net-id".into(), "03030303030303030303030303030303".into()]);
        let duplicate_args = std::iter::once("verify-policy".to_string())
            .chain(duplicate)
            .collect::<Vec<_>>();
        assert!(
            run(&duplicate_args
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>())
            .unwrap_err()
            .contains("duplicate")
        );
        assert!(
            run(&["verify-policy", "--tbs-file", "x"])
                .unwrap_err()
                .contains("required")
        );
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn verify_policy_rejects_oversized_and_symlink_inputs() {
        let dir = temp_dir();
        let args = baseline(&dir);
        let tbs = dir.join("tbs");
        fs::write(&tbs, vec![0; 16 * 1024 + 1]).unwrap();
        let mut argv = vec!["verify-policy".to_string()];
        argv.extend(args.clone());
        let result = run(&argv.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(result.unwrap_err().contains("oversized"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.join("tbs-link");
            symlink(dir.join("ed"), &link).unwrap();
            let mut linked = args;
            let index = linked.iter().position(|s| s == "--tbs-file").unwrap() + 1;
            linked[index] = link.to_string_lossy().into_owned();
            let mut argv = vec!["verify-policy".to_string()];
            argv.extend(linked);
            assert!(
                run(&argv.iter().map(String::as_str).collect::<Vec<_>>())
                    .unwrap_err()
                    .contains("invalid or oversized TBS")
            );
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sign_policy_cli_round_trips_into_verify_policy() {
        let dir = temp_dir();
        let ca_dir = dir.join("ca");
        let out_dir = dir.join("out");
        let ca_str = ca_dir.to_string_lossy().into_owned();
        let out_str = out_dir.to_string_lossy().into_owned();
        let net_hex = "03030303030303030303030303030303";
        run(&[
            "init-ca",
            "--ca-dir",
            &ca_str,
            "--net-id",
            net_hex,
            "--validity-days",
            "30",
        ])
        .expect("init-ca");
        run(&[
            "sign-policy",
            "--ca-dir",
            &ca_str,
            "--out-dir",
            &out_str,
            "--sequence",
            "9",
            "--ttl-seconds",
            "3600",
        ])
        .expect("sign-policy");
        let tbs = out_dir.join("tbs.cbor").to_string_lossy().into_owned();
        let ed_sig = out_dir.join("ed25519.sig").to_string_lossy().into_owned();
        let pq_sig = out_dir.join("mldsa65.sig").to_string_lossy().into_owned();
        let ed_der = out_dir
            .join("root-ed25519.der")
            .to_string_lossy()
            .into_owned();
        let pq_der = out_dir
            .join("root-mldsa65.der")
            .to_string_lossy()
            .into_owned();
        run(&[
            "verify-policy",
            "--tbs-file",
            &tbs,
            "--ed25519-signature-file",
            &ed_sig,
            "--mldsa65-signature-file",
            &pq_sig,
            "--net-id",
            net_hex,
            "--root-ed25519-der",
            &ed_der,
            "--root-mldsa65-der",
            &pq_der,
        ])
        .expect("verify-policy");
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(feature = "openssl-inner-tls")]
fn cmd_verify_bundle(args: &[String]) -> Result<(), String> {
    use boreas_pki::provisioning::{hex_encode, verify_material_dir_with_roots};
    use boreas_proto::objects::ObjectBody;
    use std::path::PathBuf;

    let mut material_dir: Option<PathBuf> = None;
    let mut roots_path: Option<PathBuf> = None;
    let mut require_peer = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--require-peer" => {
                require_peer = true;
                i += 1;
            }
            flag => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("pki verify-bundle: missing value for `{flag}`"))?;
                match flag {
                    "--material-dir" => material_dir = Some(PathBuf::from(val)),
                    "--roots" => roots_path = Some(PathBuf::from(val)),
                    _ => return Err("pki verify-bundle: unknown argument".to_string()),
                }
                i += 2;
            }
        }
    }

    let material_dir = material_dir
        .ok_or_else(|| "pki verify-bundle: `--material-dir` is required".to_string())?;
    let roots = roots_path.unwrap_or_else(|| material_dir.join("roots.cbor"));

    let verified =
        verify_material_dir_with_roots(&material_dir, &roots, None, now_utc_us()?, require_peer)
            .map_err(|e| format!("pki verify-bundle failed: {e}"))?;
    let ObjectBody::NodeIdentity(local) = &verified.local.object().body else {
        return Err("pki verify-bundle: local object is not NodeIdentity".to_string());
    };
    let peer_node_json = match &verified.peer {
        Some(p) => match &p.object().body {
            ObjectBody::NodeIdentity(pb) => pb.node_id.to_string(),
            _ => "null".to_string(),
        },
        None => "null".to_string(),
    };

    println!(
        "{{\"command\":\"pki.verify-bundle\",\"status\":\"ok\",\"net_id\":\"{}\",\"root_fingerprint\":\"{}\",\"local_node_id\":{},\"peer_node_id\":{},\"status_sequence\":{},\"status_next_update_us\":{}}}",
        hex_encode(&verified.net_id),
        hex_encode(&verified.root_fingerprint),
        local.node_id,
        peer_node_json,
        verified.status_sequence,
        verified.status_next_update_us
    );
    Ok(())
}
