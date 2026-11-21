//! End-to-end integration tests for `boreas pki`, `boreas daemon` (`--virtual-tun`),
//! and `boreas ctl` / `boreas status --socket` when built with `openssl-inner-tls`.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use boreas_pki::provisioning::sign_network_policy_dir;
use openssl::pkey::PKey;

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "boreas-cli-e2e-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_boreas")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn owner_uid(path: &Path) -> String {
    fs::metadata(path).unwrap().uid().to_string()
}

fn policy_fixture(ca_dir: &Path, state_dir: &Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    // The same offline CA signs both the identity/status grants and this policy.
    sign_network_policy_dir(ca_dir, state_dir, 1, now, 3600).unwrap();
}

fn policy_args(state_dir: &Path) -> Vec<String> {
    let mut args = Vec::new();
    for (flag, file) in [
        ("--network-policy-tbs", "tbs.cbor"),
        ("--network-policy-ed25519-signature", "ed25519.sig"),
        ("--network-policy-mldsa65-signature", "mldsa65.sig"),
        ("--network-root-ed25519-der", "root-ed25519.der"),
        ("--network-root-mldsa65-der", "root-mldsa65.der"),
        ("--network-policy-state-file", "policy.state"),
    ] {
        args.push(flag.to_string());
        args.push(state_dir.join(file).to_string_lossy().into_owned());
    }
    args.push("--network-policy-state-owner-uid".into());
    args.push(owner_uid(state_dir));
    args
}

fn write_config(
    path: &Path,
    role: &str,
    vip_octet: u8,
    node_id: u16,
    mat_dir: &Path,
    state_dir: &Path,
    primary: &str,
) {
    write_config_with_uplinks(
        path, role, 1, vip_octet, node_id, mat_dir, state_dir, primary, None,
    );
}

/// Full config writer: the failover tests need a second Core's home id and a
/// `[uplink].backup` endpoint, which the single-uplink helper above cannot express.
#[allow(clippy::too_many_arguments)]
fn write_config_with_uplinks(
    path: &Path,
    role: &str,
    home_core_id: u8,
    vip_octet: u8,
    node_id: u16,
    mat_dir: &Path,
    state_dir: &Path,
    primary: &str,
    backup: Option<&str>,
) {
    let backup_line = backup
        .map(|endpoint| format!("backup = \"{endpoint}\"\n"))
        .unwrap_or_default();
    let body = format!(
        r#"version = 2

[node]
net_id = "03030303030303030303030303030303"
role = "{role}"
home_core_id = {home_core_id}
vip_octet = {vip_octet}
node_id = {node_id}
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"

[paths]
identity_key = "{id_key}"
roots = ["{roots}"]
state_dir = "{state}"

[uplink]
primary = "{primary}"
{backup_line}paths = 4
probe_paths = 1
"#,
        id_key = mat_dir.join("identity.key").display(),
        roots = mat_dir.join("roots.cbor").display(),
        state = state_dir.display(),
    );
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// One offline CA plus the mounted material for a single Core and one Edge.
///
/// `daemon connect` only ever authorizes the one peer identity in
/// `peer.signed`; there is no multi-Core directory, so this fixture is also the
/// boundary for the "another Core is not trusted because config named it" test.
struct Pair {
    root: TempDir,
    ca_dir: PathBuf,
    core_mat: PathBuf,
    edge_mat: PathBuf,
}

impl Pair {
    fn provision(label: &str) -> Self {
        let root = TempDir::new(label);
        let ca_dir = root.0.join("ca");
        let core_mat = root.0.join("core-mat");
        let edge_mat = root.0.join("edge-mat");
        let init = Command::new(bin())
            .args([
                "pki",
                "init-ca",
                "--ca-dir",
                ca_dir.to_str().unwrap(),
                "--net-id",
                "03030303030303030303030303030303",
                "--validity-days",
                "30",
            ])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "init-ca stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        for (out_dir, role, home, octet, outer_san) in [
            (&core_mat, "core", "1", "1", Some("wss.boreas.test")),
            (&edge_mat, "edge", "1", "2", None),
        ] {
            let mut args: Vec<String> = vec![
                "pki".into(),
                "issue-node".into(),
                "--ca-dir".into(),
                ca_dir.to_string_lossy().into_owned(),
                "--out-dir".into(),
                out_dir.to_string_lossy().into_owned(),
                "--role".into(),
                role.into(),
                "--home-core".into(),
                home.into(),
                "--vip-octet".into(),
                octet.into(),
            ];
            if let Some(san) = outer_san {
                args.push("--outer-san".into());
                args.push(san.into());
            }
            let issued = Command::new(bin()).args(&args).output().unwrap();
            assert!(
                issued.status.success(),
                "issue-node {role} stderr: {}",
                String::from_utf8_lossy(&issued.stderr)
            );
        }
        fs::copy(core_mat.join("local.signed"), edge_mat.join("peer.signed")).unwrap();
        fs::copy(edge_mat.join("local.signed"), core_mat.join("peer.signed")).unwrap();
        Self {
            root,
            ca_dir,
            core_mat,
            edge_mat,
        }
    }

    /// One daemon's private state directory with its own dual-signed policy.
    ///
    /// Two Core listeners of the same identity must not share a durable status
    /// store: the second `StatusStore::open` on one path is `Busy`.
    fn new_state(&self, label: &str) -> PathBuf {
        let dir = self.root.0.join(format!("state-{label}"));
        policy_fixture(&self.ca_dir, &dir);
        dir
    }

    /// Replace the issue-time snapshot with one that comfortably outlives the
    /// test, so a failover cannot be confused with a status expiry.
    fn long_lived_status(&self, mat_dir: &Path) {
        let out = Command::new(bin())
            .args([
                "pki",
                "sign-status",
                "--ca-dir",
                self.ca_dir.to_str().unwrap(),
                "--out",
                mat_dir.join("status.signed").to_str().unwrap(),
                "--sequence",
                "2",
                "--ttl-seconds",
                "3600",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "sign-status stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn identity_revocation_fixture(ca_dir: &Path, subject_generation: u64, sequence: u64) -> Vec<u8> {
    use boreas_pki::status_store::IDENTITY_REVOCATION_MAGIC;
    use boreas_proto::authority_revocation::{AuthorityRevocation, RevocationClass, RevocationScope};
    use openssl::sign::Signer;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let issuer_generation = fs::read_to_string(ca_dir.join("issuer.generation"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let tbs = AuthorityRevocation {
        net_id: [3; 16],
        class: RevocationClass::Identity,
        subject_node_id: 2,
        identity_generation: subject_generation,
        issuer_key_id: b"identity-authority-v1".to_vec(),
        issuer_generation,
        scope: RevocationScope::default(),
        seq: sequence,
        issued_at: now,
        next_update: now + 60_000_000,
    }
    .encode_tbs()
    .unwrap();
    let message = AuthorityRevocation::signature_input(&tbs).unwrap();
    let mut raw = IDENTITY_REVOCATION_MAGIC.to_vec();
    for name in ["ia.ed25519.key", "ia.mldsa65.key"] {
        let key = PKey::private_key_from_der(&fs::read(ca_dir.join(name)).unwrap()).unwrap();
        let signature = Signer::new_without_digest(&key)
            .unwrap()
            .sign_oneshot_to_vec(&message)
            .unwrap();
        raw.extend_from_slice(&signature);
    }
    raw.extend_from_slice(&tbs);
    raw
}

fn publish_identity_revocation(material: &Path, raw: &[u8]) -> PathBuf {
    let stage = material.join("identity-revocation.stage");
    let mailbox = material.join("identity-revocation.signed");
    fs::write(&stage, raw).unwrap();
    fs::rename(stage, &mailbox).unwrap();
    mailbox
}

#[test]
fn live_identity_revocation_closes_the_authenticated_circuit_and_survives_restart() {
    let pair = Pair::provision("identity-revoke");
    let core_state = pair.new_state("core");
    let edge_state = pair.new_state("edge");
    pair.long_lived_status(&pair.core_mat);
    pair.long_lived_status(&pair.edge_mat);
    let listen = format!("127.0.0.1:{}", free_port());
    let core_cfg = pair.root.0.join("core.toml");
    let edge_cfg = pair.root.0.join("edge.toml");
    write_config(&core_cfg, "core", 1, 1, &pair.core_mat, &core_state, &listen);
    write_config(&edge_cfg, "edge", 2, 2, &pair.edge_mat, &edge_state, &listen);

    let mut core = spawn_serve(&core_cfg, &pair.core_mat, &core_state, &listen, "15");
    let core_socket = core_state.join("control.sock");
    assert!(wait_for_status(&core_socket, "\"status_fresh\":true", Duration::from_secs(10)));
    thread::sleep(Duration::from_millis(200));
    let mut edge = spawn_connect(&edge_cfg, &pair.edge_mat, &edge_state, "wss.boreas.test", "15");
    assert!(wait_for_status(&core_socket, "\"daemon_connected\":true", Duration::from_secs(10)));

    // First commit a correctly signed denial for another generation of this slot.
    let other = identity_revocation_fixture(&pair.ca_dir, 2, 1);
    publish_identity_revocation(&pair.core_mat, &other);
    let status_state = core_state.join("status.state");
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if fs::read(&status_state).unwrap().starts_with(b"BRSS\0\0\0\x02") {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(fs::read(&status_state).unwrap().starts_with(b"BRSS\0\0\0\x02"));
    assert!(ctl_status(&core_socket).unwrap().contains("\"daemon_connected\":true"));

    let exact = identity_revocation_fixture(&pair.ca_dir, 1, 2);
    let mailbox = publish_identity_revocation(&pair.core_mat, &exact);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && core.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(core.try_wait().unwrap().is_some(), "revoked Core circuit did not stop promptly");
    let closed = core.wait_with_output().unwrap();
    let _ = edge.kill();
    let _ = edge.wait();
    assert!(!closed.status.success());
    assert!(String::from_utf8_lossy(&closed.stderr).contains("identity node 2 generation 1 revoked"));

    // The mailbox is not the state; even after removal the exact generation
    // is refused before accepting a connection on the restarted daemon.
    fs::remove_file(mailbox).unwrap();
    let mut restarted = spawn_serve(&core_cfg, &pair.core_mat, &core_state, &listen, "15");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && restarted.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(restarted.try_wait().unwrap().is_some(), "durable denial was not reapplied at startup");
    let output = restarted.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("identity node 2 generation 1 revoked"));
}

fn ctl_status(socket: &Path) -> Option<String> {
    let out = Command::new(bin())
        .args(["ctl", "status", "--socket", socket.to_str().unwrap()])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Read one unsigned integer field out of the live control-socket JSON.
fn u64_field(raw: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = raw.find(&needle)? + needle.len();
    let digits: String = raw[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Poll the live control socket until it reports `needle`.
fn wait_for_status(socket: &Path, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(text) = ctl_status(socket)
            && text.contains(needle)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn spawn_serve(
    config: &Path,
    mat_dir: &Path,
    state_dir: &Path,
    listen: &str,
    max_seconds: &str,
) -> std::process::Child {
    let owner = owner_uid(state_dir);
    Command::new(bin())
        .args([
            "daemon",
            "serve",
            "--config",
            config.to_str().unwrap(),
            "--material-dir",
            mat_dir.to_str().unwrap(),
            "--status-state-file",
            state_dir.join("status.state").to_str().unwrap(),
            "--status-state-owner-uid",
            &owner,
            "--listen",
            listen,
            "--virtual-tun",
            "--max-seconds",
            max_seconds,
        ])
        .args(policy_args(state_dir))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Connect using the configured `[uplink]` primary/backup pair (no `--connect`,
/// which would disable the standby path).
fn spawn_connect(
    config: &Path,
    mat_dir: &Path,
    state_dir: &Path,
    tls_name: &str,
    max_seconds: &str,
) -> std::process::Child {
    let owner = owner_uid(state_dir);
    Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            config.to_str().unwrap(),
            "--material-dir",
            mat_dir.to_str().unwrap(),
            "--status-state-file",
            state_dir.join("status.state").to_str().unwrap(),
            "--status-state-owner-uid",
            &owner,
            "--tls-name",
            tls_name,
            "--virtual-tun",
            "--max-seconds",
            max_seconds,
        ])
        .args(policy_args(state_dir))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Real two-node, same-Core mid-run path failover.
///
/// Both listeners speak for the *same* Core identity (`10.20.1.1`), which is the
/// only authority the Edge holds. The Edge keeps a fully authenticated standby
/// hop session on the backup ingress, and when the primary ingress dies it must
/// rebuild the E2E circuit on the standby with both VIPs unchanged.
#[test]
fn same_core_standby_path_takes_over_after_the_primary_ingress_dies() {
    let pair = Pair::provision("failover");
    let core_state_a = pair.new_state("core-a");
    let core_state_b = pair.new_state("core-b");
    let edge_state = pair.new_state("edge");
    pair.long_lived_status(&pair.core_mat);
    pair.long_lived_status(&pair.edge_mat);

    let port_a = free_port();
    let port_b = free_port();
    let listen_a = format!("127.0.0.1:{port_a}");
    let listen_b = format!("127.0.0.1:{port_b}");

    let core_cfg_a = pair.root.0.join("core-a.toml");
    let core_cfg_b = pair.root.0.join("core-b.toml");
    write_config(
        &core_cfg_a,
        "core",
        1,
        1,
        &pair.core_mat,
        &core_state_a,
        "wss.boreas.test:443",
    );
    write_config(
        &core_cfg_b,
        "core",
        1,
        1,
        &pair.core_mat,
        &core_state_b,
        "wss.boreas.test:443",
    );
    let edge_cfg = pair.root.0.join("edge.toml");
    write_config_with_uplinks(
        &edge_cfg,
        "edge",
        1,
        2,
        2,
        &pair.edge_mat,
        &edge_state,
        &listen_a,
        Some(&listen_b),
    );

    let mut serve_a = spawn_serve(&core_cfg_a, &pair.core_mat, &core_state_a, &listen_a, "30");
    let serve_b = spawn_serve(&core_cfg_b, &pair.core_mat, &core_state_b, &listen_b, "20");
    let sock_a = core_state_a.join("control.sock");
    let sock_b = core_state_b.join("control.sock");
    let bind_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < bind_deadline && !(sock_a.exists() && sock_b.exists()) {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        sock_a.exists() && sock_b.exists(),
        "both Core listeners must bind before the edge dials"
    );
    // `control.sock` is published just before the listener binds, so a refused
    // initial dial must not be mistaken for the failover path.
    thread::sleep(Duration::from_millis(200));

    let edge_sock = edge_state.join("control.sock");
    let edge = spawn_connect(
        &edge_cfg,
        &pair.edge_mat,
        &edge_state,
        "wss.boreas.test",
        "20",
    );
    assert!(
        wait_for_status(
            &edge_sock,
            "\"daemon_connected\":true",
            Duration::from_secs(10)
        ),
        "edge never started business on the primary ingress"
    );
    assert!(
        wait_for_status(
            &edge_sock,
            "\"standby_ready\":true",
            Duration::from_secs(10)
        ),
        "the authenticated standby session was never established on the backup ingress"
    );
    assert!(
        wait_for_status(
            &edge_sock,
            "\"active_path\":\"primary\"",
            Duration::from_secs(5)
        ),
        "business must start on the primary ingress"
    );

    // Kill only the primary ingress.
    serve_a.kill().unwrap();
    let _ = serve_a.wait();

    assert!(
        wait_for_status(&edge_sock, "\"failover_events\":1", Duration::from_secs(10)),
        "edge did not complete a failover to the backup ingress"
    );
    assert!(
        wait_for_status(&edge_sock, "\"path_epoch\":2", Duration::from_secs(10)),
        "the backup epoch never started"
    );
    let live = ctl_status(&edge_sock).expect("edge control socket during the backup epoch");
    assert!(
        live.contains("\"active_path\":\"backup\""),
        "business must continue on the backup ingress: {live}"
    );
    assert!(
        live.contains("\"standby_ready\":false"),
        "the promoted session is no longer a standby: {live}"
    );
    // The Core side of the backup ingress must actually be carrying the circuit,
    // not merely have been dialled: it reports its own live business state.
    assert!(
        wait_for_status(
            &sock_b,
            "\"daemon_connected\":true",
            Duration::from_secs(10)
        ),
        "the backup ingress never accepted the rebuilt E2E circuit"
    );
    // Cleanup contract: promotion closes the standby manager, so its dial and
    // poll sequences must stop moving instead of quietly reconnecting from a
    // detached thread.
    let first = ctl_status(&edge_sock).expect("edge status after promotion");
    thread::sleep(Duration::from_millis(600));
    let second = ctl_status(&edge_sock).expect("edge status 600 ms later");
    assert_eq!(
        u64_field(&first, "standby_attempts"),
        u64_field(&second, "standby_attempts"),
        "the standby manager must stop dialling once the backup carries business"
    );
    assert_eq!(
        u64_field(&first, "standby_polls"),
        u64_field(&second, "standby_polls"),
        "the standby manager must stop polling once it is closed"
    );

    let edge_out = edge.wait_with_output().unwrap();
    let serve_b_out = serve_b.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&edge_out.stdout);
    assert!(
        edge_out.status.success(),
        "edge failed after failover: {}",
        String::from_utf8_lossy(&edge_out.stderr)
    );
    assert!(
        serve_b_out.status.success(),
        "the backup ingress failed after taking over: {}",
        String::from_utf8_lossy(&serve_b_out.stderr)
    );
    assert!(
        stdout.contains("\"local_vip\":\"10.20.1.2\""),
        "the edge VIP must not change across a failover: {stdout}"
    );
    assert!(
        stdout.contains("\"peer_vip\":\"10.20.1.1\""),
        "the Core VIP must not change across a failover: {stdout}"
    );
    assert!(
        stdout.contains("\"failover_events\":1") && stdout.contains("\"path_epoch\":2"),
        "expected exactly one same-Core failover: {stdout}"
    );
}

/// The initial endpoint fallback is allowed to select the backup once, but the
/// now-active backup must not also become the standby endpoint.
///
/// Opening a standby to the only ingress already carrying business would leave no
/// second path and would let a later loss "promote" onto the same endpoint. The
/// standby dialler must stay absent (`standby_attempts == 0`) and a later loss of
/// that active backup must fail closed.
#[test]
fn initial_primary_refusal_falls_back_once_without_dialling_the_active_backup_as_standby() {
    let pair = Pair::provision("initial-fallback");
    let core_state = pair.new_state("core");
    let edge_state = pair.new_state("edge");
    pair.long_lived_status(&pair.core_mat);
    pair.long_lived_status(&pair.edge_mat);

    let refused_port = free_port();
    let refused = format!("127.0.0.1:{refused_port}");
    let backup_port = loop {
        let candidate = free_port();
        if candidate != refused_port {
            break candidate;
        }
    };
    let backup = format!("127.0.0.1:{backup_port}");

    let core_cfg = pair.root.0.join("core.toml");
    write_config(
        &core_cfg,
        "core",
        1,
        1,
        &pair.core_mat,
        &core_state,
        "wss.boreas.test:443",
    );
    let edge_cfg = pair.root.0.join("edge.toml");
    write_config_with_uplinks(
        &edge_cfg,
        "edge",
        1,
        2,
        2,
        &pair.edge_mat,
        &edge_state,
        &refused,
        Some(&backup),
    );

    let mut serve = spawn_serve(&core_cfg, &pair.core_mat, &core_state, &backup, "30");
    let sock = core_state.join("control.sock");
    let bind_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < bind_deadline && !sock.exists() {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        sock.exists(),
        "the backup listener must bind before the edge dials"
    );
    thread::sleep(Duration::from_millis(200));

    let edge_sock = edge_state.join("control.sock");
    let edge = spawn_connect(
        &edge_cfg,
        &pair.edge_mat,
        &edge_state,
        "wss.boreas.test",
        "20",
    );
    assert!(
        wait_for_status(
            &edge_sock,
            "\"daemon_connected\":true",
            Duration::from_secs(10)
        ),
        "edge never started business on the backup after the primary refusal"
    );
    let live = ctl_status(&edge_sock).expect("edge status on the initial fallback");
    assert!(
        live.contains("\"active_path\":\"backup\""),
        "the initial fallback must report the backup as active: {live}"
    );
    assert_eq!(
        u64_field(&live, "standby_attempts"),
        Some(0),
        "the active backup must not be dialled again as a standby: {live}"
    );
    assert_eq!(
        u64_field(&live, "standby_polls"),
        Some(0),
        "there is no standby link to poll on the active backup: {live}"
    );
    assert!(
        live.contains("\"standby_state\":\"idle\"") && live.contains("\"standby_rejected\":false"),
        "the absent standby must stay idle, not look ready: {live}"
    );
    assert!(
        live.contains("\"failover_events\":0") && live.contains("\"path_epoch\":1"),
        "the initial fallback is not a promotion: {live}"
    );

    serve.kill().unwrap();
    let _ = serve.wait();

    let edge_out = edge.wait_with_output().unwrap();
    assert!(
        !edge_out.status.success(),
        "losing the only active ingress must fail closed, not succeed silently"
    );
    let stderr = String::from_utf8_lossy(&edge_out.stderr);
    assert!(
        stderr.contains("no authenticated standby path is ready"),
        "unexpected fail-closed reason: {stderr}"
    );
}

/// A reachable, correctly signed *second* Core at `[uplink].backup` must never be
/// trusted just because configuration named it.
///
/// There is no multi-Core directory in this tree, so the Edge's only authority is
/// `peer.signed` (pinned to `10.20.1.1`). The second Core completes outer TLS but
/// cannot pass the inner pq768 SPKI binding, so no standby ever becomes ready and
/// losing the primary is fail-closed rather than a hijack to `10.20.2.1`.
#[test]
fn a_second_core_at_the_backup_endpoint_is_never_trusted_from_config() {
    let pair = Pair::provision("second-core");
    let core2_mat = pair.root.0.join("core2-mat");
    let issued = Command::new(bin())
        .args([
            "pki",
            "issue-node",
            "--ca-dir",
            pair.ca_dir.to_str().unwrap(),
            "--out-dir",
            core2_mat.to_str().unwrap(),
            "--role",
            "core",
            "--home-core",
            "2",
            "--vip-octet",
            "1",
            "--outer-san",
            "wss.boreas.test",
        ])
        .output()
        .unwrap();
    assert!(
        issued.status.success(),
        "issue second core stderr: {}",
        String::from_utf8_lossy(&issued.stderr)
    );
    fs::copy(
        pair.edge_mat.join("local.signed"),
        core2_mat.join("peer.signed"),
    )
    .unwrap();

    let core_state_a = pair.new_state("core-a");
    let core2_state = pair.new_state("core2");
    let edge_state = pair.new_state("edge");
    pair.long_lived_status(&pair.core_mat);
    pair.long_lived_status(&pair.edge_mat);
    pair.long_lived_status(&core2_mat);

    let port_a = free_port();
    let port_c = free_port();
    let listen_a = format!("127.0.0.1:{port_a}");
    let listen_c = format!("127.0.0.1:{port_c}");

    let core_cfg_a = pair.root.0.join("core-a.toml");
    let core2_cfg = pair.root.0.join("core2.toml");
    write_config(
        &core_cfg_a,
        "core",
        1,
        1,
        &pair.core_mat,
        &core_state_a,
        "wss.boreas.test:443",
    );
    write_config_with_uplinks(
        &core2_cfg,
        "core",
        2,
        1,
        257,
        &core2_mat,
        &core2_state,
        "wss.boreas.test:443",
        None,
    );
    let edge_cfg = pair.root.0.join("edge.toml");
    write_config_with_uplinks(
        &edge_cfg,
        "edge",
        1,
        2,
        2,
        &pair.edge_mat,
        &edge_state,
        &listen_a,
        Some(&listen_c),
    );

    let mut serve_a = spawn_serve(&core_cfg_a, &pair.core_mat, &core_state_a, &listen_a, "30");
    let mut serve_c = spawn_serve(&core2_cfg, &core2_mat, &core2_state, &listen_c, "30");
    let sock_a = core_state_a.join("control.sock");
    let sock_c = core2_state.join("control.sock");
    let bind_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < bind_deadline && !(sock_a.exists() && sock_c.exists()) {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        sock_a.exists() && sock_c.exists(),
        "both Core listeners must bind before the edge dials"
    );
    thread::sleep(Duration::from_millis(200));

    let edge_sock = edge_state.join("control.sock");
    let edge = spawn_connect(
        &edge_cfg,
        &pair.edge_mat,
        &edge_state,
        "wss.boreas.test",
        "20",
    );
    assert!(
        wait_for_status(
            &edge_sock,
            "\"daemon_connected\":true",
            Duration::from_secs(10)
        ),
        "edge never started business on the primary ingress"
    );
    // An inner-TLS identity rejection is terminal for this standby path: it must
    // not be retried as an ordinary transport miss, and it must never count as a
    // failover event.
    assert!(
        wait_for_status(
            &edge_sock,
            "\"standby_state\":\"rejected\"",
            Duration::from_secs(10)
        ),
        "the unauthorized second Core must be reported as a rejected standby path"
    );
    let rejected = ctl_status(&edge_sock).expect("edge status while the standby is rejected");
    assert!(
        rejected.contains("\"standby_ready\":false"),
        "an unauthorized Core must never become a ready standby: {rejected}"
    );
    assert!(
        rejected.contains("\"failover_events\":0") && rejected.contains("\"path_epoch\":1"),
        "an identity rejection must not be treated as a failover trigger: {rejected}"
    );
    let attempts = u64_field(&rejected, "standby_attempts").expect("standby_attempts");
    assert_eq!(
        attempts, 1,
        "a rejected identity must not be retried: {rejected}"
    );
    thread::sleep(Duration::from_millis(600));
    let still_rejected = ctl_status(&edge_sock).expect("edge status after the rejection");
    assert_eq!(
        u64_field(&still_rejected, "standby_attempts"),
        Some(attempts),
        "a protocol/identity rejection must stop the standby dialler: {still_rejected}"
    );

    serve_a.kill().unwrap();
    let _ = serve_a.wait();

    let edge_out = edge.wait_with_output().unwrap();
    serve_c.kill().unwrap();
    let _ = serve_c.wait();
    assert!(
        !edge_out.status.success(),
        "edge must fail closed when the only authorized path is gone"
    );
    let stderr = String::from_utf8_lossy(&edge_out.stderr);
    assert!(
        stderr.contains("no authenticated standby path is ready"),
        "unexpected fail-closed reason: {stderr}"
    );
    assert!(
        stderr.contains("rejected"),
        "the terminal identity rejection must be reported: {stderr}"
    );
}

#[test]
fn business_modes_require_explicit_durable_status_binding() {
    for mode in ["serve", "connect"] {
        let out = Command::new(bin()).args(["daemon", mode]).output().unwrap();
        assert!(
            !out.status.success(),
            "{mode} must refuse without status binding"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("--status-state-file"),
            "{mode} stderr must name the required state file: {err}"
        );
        assert!(
            err.contains("--status-state-owner-uid"),
            "{mode} stderr must name the required owner UID: {err}"
        );
    }

    let relative = Command::new(bin())
        .args([
            "daemon",
            "serve",
            "--status-state-file",
            "relative-status.state",
            "--status-state-owner-uid",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!relative.status.success());
    assert!(
        String::from_utf8_lossy(&relative.stderr).contains("absolute"),
        "relative state path must fail closed"
    );
}

#[test]
fn cli_offline_pki_to_live_pq768_e2e_daemon_and_status_expiry_fail_closed() {
    let root = TempDir::new("full");
    let ca_dir = root.0.join("ca");
    let core_mat = root.0.join("core-mat");
    let edge_mat = root.0.join("edge-mat");
    let core_state = root.0.join("core-state");
    let edge_state = root.0.join("edge-state");
    let core_status_state = core_state.join("status.state");
    let edge_status_state = edge_state.join("status.state");

    // 1. Offline CA init (`boreas pki init-ca`).
    let init_out = Command::new(bin())
        .args([
            "pki",
            "init-ca",
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--net-id",
            "03030303030303030303030303030303",
            "--validity-days",
            "30",
        ])
        .output()
        .unwrap();
    assert!(
        init_out.status.success(),
        "init-ca stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    assert!(String::from_utf8_lossy(&init_out.stdout).contains("\"status\":\"ok\""));
    policy_fixture(&ca_dir, &core_state);
    policy_fixture(&ca_dir, &edge_state);
    // Each daemon status store is independently bound to its state directory owner.
    let core_state_owner = owner_uid(&core_state);
    let edge_state_owner = owner_uid(&edge_state);

    // 2. Issue Core (10.20.1.1, node_id=1) with outer SAN `wss.boreas.test`.
    let core_issue = Command::new(bin())
        .args([
            "pki",
            "issue-node",
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--out-dir",
            core_mat.to_str().unwrap(),
            "--role",
            "core",
            "--home-core",
            "1",
            "--vip-octet",
            "1",
            "--outer-san",
            "wss.boreas.test",
        ])
        .output()
        .unwrap();
    assert!(
        core_issue.status.success(),
        "issue core stderr: {}",
        String::from_utf8_lossy(&core_issue.stderr)
    );

    // 3. Issue Edge (10.20.1.2, node_id=2).
    let edge_issue = Command::new(bin())
        .args([
            "pki",
            "issue-node",
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--out-dir",
            edge_mat.to_str().unwrap(),
            "--role",
            "edge",
            "--home-core",
            "1",
            "--vip-octet",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        edge_issue.status.success(),
        "issue edge stderr: {}",
        String::from_utf8_lossy(&edge_issue.stderr)
    );

    // Cross-mount public peer NodeIdentity records (`peer.signed`).
    fs::copy(core_mat.join("local.signed"), edge_mat.join("peer.signed")).unwrap();
    fs::copy(edge_mat.join("local.signed"), core_mat.join("peer.signed")).unwrap();

    // 4. Verify both bundles via `boreas pki verify-bundle --require-peer`.
    for dir in [&core_mat, &edge_mat] {
        let ver = Command::new(bin())
            .args([
                "pki",
                "verify-bundle",
                "--material-dir",
                dir.to_str().unwrap(),
                "--require-peer",
            ])
            .output()
            .unwrap();
        assert!(
            ver.status.success(),
            "verify-bundle stderr: {}",
            String::from_utf8_lossy(&ver.stderr)
        );
    }

    // 5. Run real two-process `daemon serve` + `daemon connect` (`--virtual-tun`)
    //    and query live `control.sock` via `boreas ctl status` and `boreas status --socket`.
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let core_cfg = root.0.join("core.toml");
    let edge_cfg = root.0.join("edge.toml");
    write_config(
        &core_cfg,
        "core",
        1,
        1,
        &core_mat,
        &core_state,
        "wss.boreas.test:443",
    );
    write_config(
        &edge_cfg,
        "edge",
        2,
        2,
        &edge_mat,
        &edge_state,
        &format!("wss.boreas.test:{port}"),
    );

    // Both missing trust pins and a malformed dual-signature input are rejected
    // before a daemon process can start forwarding.
    let complete_policy_args = policy_args(&edge_state);
    let mut incomplete_policy_args = Vec::new();
    for pair in complete_policy_args.as_chunks::<2>().0 {
        if pair[0] != "--network-root-mldsa65-der" {
            incomplete_policy_args.extend_from_slice(pair);
        }
    }
    let missing = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--status-state-file",
            edge_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &edge_state_owner,
        ])
        .args(incomplete_policy_args)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--network-root-mldsa65-der"));

    // A mistaken independently supplied pin must fail before opening the policy
    // watermark. Keep all identity, status and signed policy bytes unchanged.
    let ed_pin_path = edge_state.join("root-ed25519.der");
    let valid_ed_pin = fs::read(&ed_pin_path).unwrap();
    let unrelated_public_key = PKey::generate_ed25519().unwrap().public_key_to_der().unwrap();
    fs::write(&ed_pin_path, unrelated_public_key).unwrap();
    let mismatched_pin = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--status-state-file",
            edge_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &edge_state_owner,
        ])
        .args(&complete_policy_args)
        .output()
        .unwrap();
    fs::write(ed_pin_path, valid_ed_pin).unwrap();
    assert!(!mismatched_pin.status.success());
    let details = String::from_utf8_lossy(&mismatched_pin.stderr);
    assert!(details.contains("does not match the daemon identity/status NetworkRoot fingerprint"), "{details}");
    for name in ["policy.state", "policy.state.lock", "status.state", "control.sock"] {
        assert!(!edge_state.join(name).exists(), "unexpected {name}");
    }

    let ml_sig_path = edge_state.join("mldsa65.sig");
    let valid_ml_sig = fs::read(&ml_sig_path).unwrap();
    fs::write(&ml_sig_path, [0u8; 3309]).unwrap();
    let bad_signature = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--status-state-file",
            edge_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &edge_state_owner,
        ])
        .args(policy_args(&edge_state))
        .output()
        .unwrap();
    fs::write(&ml_sig_path, valid_ml_sig).unwrap();
    assert!(!bad_signature.status.success());
    assert!(String::from_utf8_lossy(&bad_signature.stderr).contains("network policy rejected"));

    let srv = Command::new(bin())
        .args([
            "daemon",
            "serve",
            "--config",
            core_cfg.to_str().unwrap(),
            "--material-dir",
            core_mat.to_str().unwrap(),
            "--status-state-file",
            core_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &core_state_owner,
            "--listen",
            &listen,
            "--virtual-tun",
            "--max-seconds",
            "3",
        ])
        .args(policy_args(&core_state))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for `core_state/control.sock` to appear before dialing.
    let core_sock = core_state.join("control.sock");
    let wait_sock = Instant::now();
    while !core_sock.exists() && wait_sock.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(core_sock.exists(), "core control.sock did not start");

    let cli = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--status-state-file",
            edge_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &edge_state_owner,
            "--connect",
            &listen,
            "--tls-name",
            "wss.boreas.test",
            "--virtual-tun",
            "--max-seconds",
            "2",
        ])
        .args(policy_args(&edge_state))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait until `boreas ctl status` sees `daemon_connected:true`.
    let mut saw_connected = false;
    let poll_start = Instant::now();
    while poll_start.elapsed() < Duration::from_secs(5) {
        let ctl_out = Command::new(bin())
            .args(["ctl", "status", "--socket", core_sock.to_str().unwrap()])
            .output()
            .unwrap();
        if ctl_out.status.success() {
            let s = String::from_utf8_lossy(&ctl_out.stdout);
            if s.contains("\"daemon_connected\":true") {
                saw_connected = true;
                // Also verify `boreas status --json --socket` reports `"daemon":"connected"`.
                let st_out = Command::new(bin())
                    .args(["status", "--json", "--socket", core_sock.to_str().unwrap()])
                    .output()
                    .unwrap();
                assert!(st_out.status.success());
                assert!(
                    String::from_utf8_lossy(&st_out.stdout).contains("\"daemon\":\"connected\"")
                );
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw_connected,
        "never observed live connected daemon over control.sock"
    );

    let cli_res = cli.wait_with_output().unwrap();
    let srv_res = srv.wait_with_output().unwrap();
    assert!(
        cli_res.status.success(),
        "edge daemon failed: {}",
        String::from_utf8_lossy(&cli_res.stderr)
    );
    assert!(
        srv_res.status.success(),
        "core daemon failed: {}",
        String::from_utf8_lossy(&srv_res.stderr)
    );
    assert!(String::from_utf8_lossy(&cli_res.stdout).contains("\"local_vip\":\"10.20.1.2\""));
    assert!(String::from_utf8_lossy(&srv_res.stdout).contains("\"local_vip\":\"10.20.1.1\""));

    // 6. Test §3.4 fail-closed StatusSnapshot expiry: sign a 1-second snapshot on edge,
    //    start a 4-second session, and verify edge terminates fail-closed on status expiry!
    let short_status = Command::new(bin())
        .args([
            "pki",
            "sign-status",
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--out",
            edge_mat.join("status.signed").to_str().unwrap(),
            "--sequence",
            "2",
            "--ttl-seconds",
            "1",
        ])
        .output()
        .unwrap();
    assert!(short_status.status.success());

    let port2 = free_port();
    let listen2 = format!("127.0.0.1:{port2}");
    let srv2 = Command::new(bin())
        .args([
            "daemon",
            "serve",
            "--config",
            core_cfg.to_str().unwrap(),
            "--material-dir",
            core_mat.to_str().unwrap(),
            "--status-state-file",
            core_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &core_state_owner,
            "--listen",
            &listen2,
            "--virtual-tun",
            "--max-seconds",
            "4",
        ])
        .args(policy_args(&core_state))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(150));

    let cli2 = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--status-state-file",
            edge_status_state.to_str().unwrap(),
            "--status-state-owner-uid",
            &edge_state_owner,
            "--connect",
            &listen2,
            "--tls-name",
            "wss.boreas.test",
            "--virtual-tun",
            "--max-seconds",
            "4",
        ])
        .args(policy_args(&edge_state))
        .output()
        .unwrap();
    let _ = srv2.wait_with_output();

    assert!(
        !cli2.status.success(),
        "edge daemon MUST fail closed once status.signed expires"
    );
    let err_txt = String::from_utf8_lossy(&cli2.stderr);
    assert!(
        err_txt.contains("StatusSnapshot")
            || err_txt.contains("status.signed")
            || err_txt.contains("expired"),
        "unexpected stderr on status expiry: {err_txt}"
    );
}
