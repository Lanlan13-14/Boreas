//! Cross-check the public library client against the binary's real server state machine.
#![cfg(target_os = "linux")]

use boreas_supervisor::ready_client::{report_ready, TunStatus};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("boreas-client-e2e-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    (root.clone(), root.join("ready.sock"))
}

fn fake_server(challenge: String) -> (std::path::PathBuf, std::path::PathBuf, std::thread::JoinHandle<()>) {
    let (root, socket) = fixture();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let thread = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => std::thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("fake server accept failed: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
        stream.write_all(challenge.as_bytes()).unwrap();
        let mut response = [0u8; 1024];
        let _ = stream.read(&mut response);
    });
    (root, socket, thread)
}

#[test]
fn rejects_wrong_nonce_challenge() {
    let (root, socket, server) = fake_server(format!("BOREAS-READY-1 {}\n", "g".repeat(64)));
    assert!(report_ready(&socket, "state-v1", 1, TunStatus::Ready).is_err());
    server.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_oversize_challenge() {
    let (root, socket, server) = fake_server(format!("{}\n", "x".repeat(513)));
    assert!(report_ready(&socket, "state-v1", 1, TunStatus::Ready).is_err());
    server.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_socket_with_wrong_mode() {
    let (root, socket) = fixture();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(report_ready(&socket, "state-v1", 1, TunStatus::Ready).is_err());
    drop(listener);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_invalid_schema_before_connecting() {
    let (root, absent_socket) = fixture();
    let result = report_ready(&absent_socket, "../invalid", 1, TunStatus::Ready);
    std::fs::remove_dir_all(root).unwrap();
    assert!(matches!(result, Err(boreas_supervisor::ready_client::ReadyClientError::Protocol(_))));
}

#[test]
fn library_client_completes_real_server_handshake_same_pid() {
    let (root, socket) = fixture();
    let listener = crate::readiness::bind(&socket).unwrap();
    let client_socket = socket.clone();
    let client = std::thread::spawn(move || report_ready(&client_socket, "state-v1", 2, TunStatus::Ready));
    let policy = crate::readiness::ReadinessPolicy { expected_schema: "state-v1".into(), require_tun: true, min_workers: 1 };
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut pending = None;
    let report = loop {
        if let Some(report) = crate::readiness::probe_once(&listener, std::process::id(), &policy, &mut pending, deadline).unwrap() { break report; }
        assert!(Instant::now() < deadline, "real server handshake deadline");
        std::thread::sleep(Duration::from_millis(1));
    };
    client.join().unwrap().unwrap();
    assert_eq!(report.workers, 2);
    crate::readiness::cleanup(&socket);
    std::fs::remove_dir_all(root).unwrap();
}

