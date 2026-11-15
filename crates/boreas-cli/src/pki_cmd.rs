//! Offline PKI management subcommands (`boreas pki ...`, master plan §2.2 / §10.4).
//!
//! Default builds have no OpenSSL 3.6+ ML-DSA backend and fail closed (`exit 2`).
//! With `openssl-inner-tls`, this provides:
//! - `boreas pki init-ca --ca-dir <DIR> [--net-id <32HEX>] [--validity-days <N>]`
//! - `boreas pki issue-node --ca-dir <DIR> --out-dir <DIR> --role core|edge --home-core <1..16> --vip-octet <1|2..251> [--generation <N>] [--validity-hours <N>] [--outer-san <DNS>]`
//! - `boreas pki sign-status --ca-dir <DIR> --out <FILE> --sequence <N> [--ttl-seconds <1..86400>]`
//! - `boreas pki verify-bundle --material-dir <DIR> [--roots <FILE>] [--require-peer]`

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
  boreas pki verify-bundle --material-dir <DIR> [--roots <FILE>] [--require-peer]"
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
        "verify-bundle" => cmd_verify_bundle(&args[1..]),
        _ => Err(format!("pki: unknown subcommand (run `boreas pki --help`)")),
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
