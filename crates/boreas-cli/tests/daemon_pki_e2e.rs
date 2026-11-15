//! End-to-end integration tests for `boreas pki`, `boreas daemon` (`--virtual-tun`),
//! and `boreas ctl` / `boreas status --socket` when built with `openssl-inner-tls`.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

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

fn write_config(path: &Path, role: &str, vip_octet: u8, node_id: u16, mat_dir: &Path, state_dir: &Path, primary: &str) {
    let body = format!(
        r#"version = 2

[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "{role}"
home_core_id = 1
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
paths = 4
probe_paths = 1
"#,
        id_key = mat_dir.join("identity.key").display(),
        roots = mat_dir.join("roots.cbor").display(),
        state = state_dir.display(),
    );
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn cli_offline_pki_to_live_pq768_e2e_daemon_and_status_expiry_fail_closed() {
    let root = TempDir::new("full");
    let ca_dir = root.0.join("ca");
    let core_mat = root.0.join("core-mat");
    let edge_mat = root.0.join("edge-mat");
    let core_state = root.0.join("core-state");
    let edge_state = root.0.join("edge-state");

    // 1. Offline CA init (`boreas pki init-ca`).
    let init_out = Command::new(bin())
        .args([
            "pki",
            "init-ca",
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--net-id",
            "0123456789abcdef0123456789abcdef",
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
    write_config(&core_cfg, "core", 1, 1, &core_mat, &core_state, "wss.boreas.test:443");
    write_config(&edge_cfg, "edge", 2, 2, &edge_mat, &edge_state, &format!("wss.boreas.test:{port}"));

    let mut srv = Command::new(bin())
        .args([
            "daemon",
            "serve",
            "--config",
            core_cfg.to_str().unwrap(),
            "--material-dir",
            core_mat.to_str().unwrap(),
            "--listen",
            &listen,
            "--virtual-tun",
            "--max-seconds",
            "3",
        ])
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

    let mut cli = Command::new(bin())
        .args([
            "daemon",
            "connect",
            "--config",
            edge_cfg.to_str().unwrap(),
            "--material-dir",
            edge_mat.to_str().unwrap(),
            "--connect",
            &listen,
            "--tls-name",
            "wss.boreas.test",
            "--virtual-tun",
            "--max-seconds",
            "2",
        ])
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
    assert!(saw_connected, "never observed live connected daemon over control.sock");

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
            "--listen",
            &listen2,
            "--virtual-tun",
            "--max-seconds",
            "4",
        ])
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
            "--connect",
            &listen2,
            "--tls-name",
            "wss.boreas.test",
            "--virtual-tun",
            "--max-seconds",
            "4",
        ])
        .output()
        .unwrap();
    let _ = srv2.wait_with_output();

    assert!(
        !cli2.status.success(),
        "edge daemon MUST fail closed once status.signed expires"
    );
    let err_txt = String::from_utf8_lossy(&cli2.stderr);
    assert!(
        err_txt.contains("StatusSnapshot") || err_txt.contains("status.signed") || err_txt.contains("expired"),
        "unexpected stderr on status expiry: {err_txt}"
    );
}
