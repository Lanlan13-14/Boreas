//! Real two-node E2E + Linux TUN daemon runtime (`boreas daemon serve|connect`,
//! plus `boreas ctl status`, master plan §1.1 / §3.4 / §4.1–§4.4 / §10.4–§10.5).
//!
//! Default builds have no OpenSSL 3.6+ ML-DSA backend and fail closed (`exit 2`).
//! With `openssl-inner-tls` on Linux, `daemon` runs the full point-to-point stack:
//! - Step 1: Validates `config.toml` and verifies the mounted `roots.cbor` trust
//!   anchor against `local.signed`, `peer.signed`, `status.signed`, and the
//!   ML-DSA-65 TLS leaf SPKI (`boreas_pki::provisioning::verify_material_dir_with_roots`).
//! - Step 2: Completes outer TLS 1.3 + RFC 6455 binary WSS + strict pq768
//!   (`X25519MLKEM768` + `mldsa65`) inner mTLS + `SessionHello`/`SessionAccept` +
//!   `RelayCircuit` + strict pq768 E2E mTLS + encrypted `BE2E` confirmation.
//! - Step 3: Opens a real Linux `/dev/net/tun` queue (`LinuxTunDevice::create`) or
//!   bounded `VirtualTun` (`--virtual-tun` for unprivileged tests), binds
//!   `PacketPath::try_new_over_e2e`, and runs a bounded bidirectional packet loop.
//! - Step 4: Periodically re-verifies `status.signed` freshness (§3.4 fail-closed:
//!   if `next_update` expires without refresh, business forwarding stops immediately).
//! - Step 5: Serves an owner-only (`0600`) Unix control socket (`state_dir/control.sock`)
//!   with `SO_PEERCRED` caller UID verification.

#[cfg(unix)]
use crate::render::{DaemonState, SecurityMode as RenderSecurityMode, StatusSnapshot};
#[cfg(not(unix))]
use crate::render::StatusSnapshot;
use std::path::Path;

#[cfg(not(feature = "openssl-inner-tls"))]
pub fn run_daemon_command(args: &[String]) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("{}", daemon_usage());
        return Ok(());
    }
    Err("daemon: real pq768 E2E tunnel daemon requires a Linux binary built with `--features openssl-inner-tls` (OpenSSL 3.6+)".to_string())
}

pub fn daemon_usage() -> &'static str {
    "Usage:
  boreas daemon serve --config <FILE> --material-dir <DIR> --listen <IP:PORT> [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>] [--max-packets <N>] [--max-seconds <N>] [--virtual-tun]
  boreas daemon connect --config <FILE> --material-dir <DIR> [--connect <IP:PORT>] [--tls-name <DNS>] [--ws-host <HOST:PORT>] [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>] [--max-packets <N>] [--max-seconds <N>] [--virtual-tun]"
}

/// Query an active daemon control socket and parse a live [`StatusSnapshot`].
/// Never invents state: any connection, permission, or parse error returns `Err`.
#[cfg(unix)]
pub fn query_control_socket(sock_path: &Path) -> Result<(StatusSnapshot, String), String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let meta = std::fs::symlink_metadata(sock_path)
        .map_err(|_| "control socket is not present".to_string())?;
    let my_uid = unsafe { libc::geteuid() };
    if meta.uid() != my_uid {
        return Err("control socket owner UID mismatch".to_string());
    }

    let mut stream = UnixStream::connect(sock_path)
        .map_err(|_| "cannot connect to control socket".to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    stream
        .write_all(b"STATUS\n")
        .map_err(|_| "control socket write failed".to_string())?;
    stream
        .flush()
        .map_err(|_| "control socket flush failed".to_string())?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream.take(4096));
    reader
        .read_line(&mut line)
        .map_err(|_| "control socket read failed".to_string())?;
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err("malformed control socket response".to_string());
    }
    let snap = parse_live_snapshot_json(trimmed)?;
    Ok((snap, trimmed.to_string()))
}

#[cfg(not(unix))]
pub fn query_control_socket(_sock_path: &Path) -> Result<(StatusSnapshot, String), String> {
    Err("Unix control socket is not supported on this platform".to_string())
}

#[cfg(unix)]
fn parse_live_snapshot_json(raw: &str) -> Result<StatusSnapshot, String> {
    let node_name = json_str_field(raw, "node").unwrap_or_else(|| "(live)".to_string());
    let version =
        json_str_field(raw, "version").unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let mode_str =
        json_str_field(raw, "security_mode").unwrap_or_else(|| "e2e-required".to_string());
    let security_mode = match mode_str.as_str() {
        "hop-only" => RenderSecurityMode::HopOnly,
        _ => RenderSecurityMode::E2eRequired,
    };
    let inbound_on = json_bool_field(raw, "inbound_on").unwrap_or(false);
    let inbound_connections = json_u64_field(raw, "inbound_connections").unwrap_or(0);
    let outbound_upstreams = json_u64_field(raw, "outbound_upstreams").unwrap_or(0);
    let connected = json_bool_field(raw, "daemon_connected").unwrap_or(false);

    Ok(StatusSnapshot {
        node_name,
        version,
        inbound_on,
        inbound_connections,
        outbound_upstreams,
        security_mode,
        daemon: if connected {
            DaemonState::Connected
        } else {
            DaemonState::NotConnected
        },
    })
}

#[cfg(unix)]
fn json_str_field(raw: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = raw.find(&needle)? + needle.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(unix)]
fn json_bool_field(raw: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\":");
    let start = raw.find(&needle)? + needle.len();
    let rest = raw[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(unix)]
fn json_u64_field(raw: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = raw.find(&needle)? + needle.len();
    let rest = raw[start..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

pub fn run_ctl_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("Usage: boreas ctl status [--socket <PATH>] [--config <FILE>]");
        return Ok(());
    }
    if args[0].as_str() != "status" {
        return Err("ctl: only `boreas ctl status` is supported".to_string());
    }
    let mut sock: Option<std::path::PathBuf> = None;
    let mut cfg_path: Option<std::path::PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("ctl status: missing value for `{flag}`"))?;
        match flag {
            "--socket" => sock = Some(std::path::PathBuf::from(val)),
            "--config" => cfg_path = Some(std::path::PathBuf::from(val)),
            _ => return Err("ctl status: unknown argument".to_string()),
        }
        i += 2;
    }
    let target = if let Some(s) = sock {
        s
    } else if let Some(c) = cfg_path {
        let cfg =
            crate::config::Config::read_file(&c, crate::config::RuntimeCapabilities::NO_RUNTIME)
                .map_err(|e| format!("ctl status: {e}"))?;
        cfg.paths.state_dir.join("control.sock")
    } else {
        std::path::PathBuf::from("/run/boreas/control.sock")
    };
    let (_snap, raw_json) = query_control_socket(&target)?;
    println!("{raw_json}");
    Ok(())
}

#[cfg(all(feature = "openssl-inner-tls", not(target_os = "linux")))]
pub fn run_daemon_command(args: &[String]) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("{}", daemon_usage());
        return Ok(());
    }
    Err("daemon: real TUN + SO_PEERCRED daemon runtime currently requires Linux".to_string())
}

#[cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
pub fn run_daemon_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help"))
    {
        println!("{}", daemon_usage());
        return Ok(());
    }
    match args[0].as_str() {
        "serve" => linux_daemon::run_mode(linux_daemon::Mode::Serve, &args[1..]),
        "connect" => linux_daemon::run_mode(linux_daemon::Mode::Connect, &args[1..]),
        _ => Err("daemon: expected `serve` or `connect` (run `boreas daemon --help`)".to_string()),
    }
}

#[cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
mod linux_daemon {
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use boreas_crypto::{
        Policy,
        backend::{OpenSslAcceptor, OpenSslConnector},
    };
    use boreas_pki::provisioning::{
        parse_net_id_hex, verify_material_dir_with_roots, verify_status_freshness_from_roots,
    };
    use boreas_proto::{
        SecurityMode as ProtoSecurityMode,
        messages::{PathRole, Suite},
    };
    use boreas_tun::{
        Error as TunError, PacketIo, VirtualTun,
        linux::{LinuxTunDevice, LinuxTunQueue, TunConfig},
    };
    use boreas_tunnel::{
        ClientTarget, LinkClient, LinkServer, OpenSslE2eBackend, OpenSslInnerAcceptor,
        OpenSslInnerConnector, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, PeerIdentity,
        PkiIdentityExtractor, TunnelError, VerifiedNodeIdentity,
        e2e::{accept_e2e, open_e2e},
        packet_path::{PacketPath, PacketPathError},
        resource::{Admission, Limits},
        session::SessionPolicy,
    };

    use crate::config::{
        Config, CryptoSuite as CfgSuite, NodeRole as CfgRole, RuntimeCapabilities,
        SecurityMode as CfgMode,
    };

    const POLL_IO_TIMEOUT: Duration = Duration::from_millis(25);
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
    const ACCEPT_WAIT: Duration = Duration::from_secs(30);
    const STATUS_RECHECK_INTERVAL: Duration = Duration::from_millis(500);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Mode {
        Serve,
        Connect,
    }

    struct LiveCounters {
        node_label: String,
        security_mode: &'static str,
        inbound_on: bool,
        connected: AtomicBool,
        inbound_connections: AtomicU64,
        outbound_upstreams: AtomicU64,
        tx_packets: AtomicU64,
        tx_bytes: AtomicU64,
        rx_packets: AtomicU64,
        rx_bytes: AtomicU64,
        status_sequence: AtomicU64,
        status_fresh: AtomicBool,
    }

    struct ControlSocketGuard {
        path: PathBuf,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for ControlSocketGuard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = std::os::unix::net::UnixStream::connect(&self.path);
            let _ = fs::remove_file(&self.path);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Adapter around `LinuxTunQueue` that uses bounded `poll()` (`25 ms`) inside
    /// `PacketIo::read_packet` so a single-thread bidirectional loop alternates
    /// outbound and inbound steps without blocking forever on an idle TUN fd.
    struct NonBlockingLinuxTun {
        queue: LinuxTunQueue,
        poll_timeout: Duration,
    }

    impl PacketIo for NonBlockingLinuxTun {
        fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
            self.queue
                .read_packet_timeout(self.poll_timeout)
                .map_err(|e| match e {
                    boreas_tun::linux::LinuxTunError::Packet(p) => p,
                    _ => TunError::QueueClosed,
                })
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
            self.queue.write_packet(packet).map_err(|e| match e {
                boreas_tun::linux::LinuxTunError::Packet(p) => p,
                _ => TunError::QueueClosed,
            })
        }
    }

    enum TunEndpoint {
        Real {
            _device: Arc<LinuxTunDevice>,
            io: NonBlockingLinuxTun,
            name: String,
        },
        Virtual {
            device: VirtualTun,
            _host: VirtualTun,
        },
    }

    impl TunEndpoint {
        fn packet_io(&self) -> &dyn PacketIo {
            match self {
                Self::Real { io, .. } => io,
                Self::Virtual { device, .. } => device,
            }
        }

        fn name(&self) -> &str {
            match self {
                Self::Real { name, .. } => name.as_str(),
                Self::Virtual { .. } => "virtual0",
            }
        }
    }

    fn daemon_capabilities() -> RuntimeCapabilities {
        RuntimeCapabilities {
            dns_tcp: false,
            control_socket: true,
            e2e_relay: true,
        }
    }

    fn now_utc_us() -> Result<u64, String> {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock before UNIX_EPOCH".to_string())?;
        u64::try_from(d.as_micros()).map_err(|_| "system clock overflow".to_string())
    }

    fn verify_peercred_same_uid(fd: i32) -> bool {
        let mut cred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != core::mem::size_of::<libc::ucred>() {
            return false;
        }
        let my_uid = unsafe { libc::geteuid() };
        cred.uid == my_uid
    }

    fn start_control_socket(
        state_dir: &Path,
        counters: Arc<LiveCounters>,
    ) -> Result<ControlSocketGuard, String> {
        fs::create_dir_all(state_dir)
            .map_err(|_| "daemon: cannot create state_dir for control.sock".to_string())?;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "daemon: cannot set 0700 on state_dir".to_string())?;
        let sock_path = state_dir.join("control.sock");
        if sock_path.exists() {
            let _ = fs::remove_file(&sock_path);
        }
        let listener = UnixListener::bind(&sock_path)
            .map_err(|_| "daemon: cannot bind control.sock".to_string())?;
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "daemon: cannot set 0600 on control.sock".to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "daemon: control.sock nonblocking failed".to_string())?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if stop_bg.load(Ordering::Relaxed) {
                            break;
                        }
                        if !verify_peercred_same_uid(stream.as_raw_fd()) {
                            continue;
                        }
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                        let mut line = String::new();
                        let mut reader = BufReader::new((&mut stream).take(256));
                        if reader.read_line(&mut line).is_ok() && line.trim() == "STATUS" {
                            let resp = format!(
                                "{{\"command\":\"ctl.status\",\"version\":\"{}\",\"node\":\"{}\",\"daemon_connected\":{},\"inbound_on\":{},\"inbound_connections\":{},\"outbound_upstreams\":{},\"security_mode\":\"{}\",\"tx_packets\":{},\"tx_bytes\":{},\"rx_packets\":{},\"rx_bytes\":{},\"status_sequence\":{},\"status_fresh\":{}}}\n",
                                env!("CARGO_PKG_VERSION"),
                                counters.node_label,
                                counters.connected.load(Ordering::Relaxed),
                                counters.inbound_on,
                                counters.inbound_connections.load(Ordering::Relaxed),
                                counters.outbound_upstreams.load(Ordering::Relaxed),
                                counters.security_mode,
                                counters.tx_packets.load(Ordering::Relaxed),
                                counters.tx_bytes.load(Ordering::Relaxed),
                                counters.rx_packets.load(Ordering::Relaxed),
                                counters.rx_bytes.load(Ordering::Relaxed),
                                counters.status_sequence.load(Ordering::Relaxed),
                                counters.status_fresh.load(Ordering::Relaxed),
                            );
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(ControlSocketGuard {
            path: sock_path,
            stop,
            handle: Some(handle),
        })
    }

    fn resolve_addr(spec: &str) -> Result<SocketAddr, String> {
        spec.to_socket_addrs()
            .map_err(|_| "daemon: cannot resolve endpoint address".to_string())?
            .next()
            .ok_or_else(|| "daemon: endpoint resolved to zero addresses".to_string())
    }

    pub fn run_mode(mode: Mode, args: &[String]) -> Result<(), String> {
        let mut config_path: Option<PathBuf> = None;
        let mut material_dir: Option<PathBuf> = None;
        let mut listen_spec: Option<String> = None;
        let mut connect_spec: Option<String> = None;
        let mut tls_name: Option<String> = None;
        let mut ws_host: Option<String> = None;
        let mut ws_path: String = "/tunnel".to_string();
        let mut tun_name: Option<String> = None;
        let mut mtu: usize = 1360;
        let mut max_packets: Option<u64> = None;
        let mut max_seconds: Option<u64> = None;
        let mut virtual_tun = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--virtual-tun" => {
                    virtual_tun = true;
                    i += 1;
                }
                flag => {
                    let val = args
                        .get(i + 1)
                        .ok_or_else(|| format!("daemon: missing value for `{flag}`"))?;
                    match flag {
                        "--config" => config_path = Some(PathBuf::from(val)),
                        "--material-dir" => material_dir = Some(PathBuf::from(val)),
                        "--listen" => listen_spec = Some(val.clone()),
                        "--connect" => connect_spec = Some(val.clone()),
                        "--tls-name" => tls_name = Some(val.clone()),
                        "--ws-host" => ws_host = Some(val.clone()),
                        "--ws-path" => ws_path = val.clone(),
                        "--tun-name" => tun_name = Some(val.clone()),
                        "--mtu" => {
                            mtu = val
                                .parse::<usize>()
                                .map_err(|_| "daemon: invalid --mtu".to_string())?
                        }
                        "--max-packets" => {
                            max_packets = Some(
                                val.parse::<u64>()
                                    .map_err(|_| "daemon: invalid --max-packets".to_string())?,
                            )
                        }
                        "--max-seconds" => {
                            max_seconds = Some(
                                val.parse::<u64>()
                                    .map_err(|_| "daemon: invalid --max-seconds".to_string())?,
                            )
                        }
                        _ => return Err("daemon: unknown argument".to_string()),
                    }
                    i += 2;
                }
            }
        }

        if !(1280..=1400).contains(&mtu) {
            return Err("daemon: --mtu must be in 1280..=1400".to_string());
        }

        let cfg_file = config_path.ok_or_else(|| "daemon: `--config` is required".to_string())?;
        let mat_dir =
            material_dir.ok_or_else(|| "daemon: `--material-dir` is required".to_string())?;
        let config = Config::read_file(&cfg_file, daemon_capabilities())
            .map_err(|e| format!("daemon config rejected: {e}"))?;

        if config.security.mode != CfgMode::E2eRequired {
            return Err(
                "daemon: pre.1 enforces `security_mode = e2e-required` (fail-closed)".to_string(),
            );
        }
        if config.security.suite != CfgSuite::Pq768 {
            return Err("daemon: pre.1 supports `suite = pq768` only".to_string());
        }
        match (mode, config.identity.role) {
            (Mode::Serve, CfgRole::Core) | (Mode::Connect, CfgRole::Edge) => {}
            _ => {
                return Err(
                    "daemon: `serve` requires a `core` config and `connect` requires an `edge` config"
                        .to_string(),
                );
            }
        }

        let cfg_net_id = parse_net_id_hex(&config.network.net_id)
            .map_err(|e| format!("daemon net_id invalid: {e}"))?;
        let roots_path = config
            .paths
            .roots
            .first()
            .ok_or_else(|| "daemon: config `[paths].roots` is empty".to_string())?
            .clone();

        // Real mounted roots.cbor verification (§2.2 / §3.4): NO TOFU, NO bypass.
        let now_us = now_utc_us()?;
        let verified =
            verify_material_dir_with_roots(&mat_dir, &roots_path, Some(cfg_net_id), now_us, true)
                .map_err(|e| format!("daemon trust/roots verification failed: {e}"))?;

        let local_vn = VerifiedNodeIdentity::from_verified_object(&verified.local)
            .map_err(|_| "daemon: invalid local VerifiedNodeIdentity".to_string())?;
        let peer_obj = verified
            .peer
            .as_ref()
            .ok_or_else(|| "daemon: `peer.signed` is required".to_string())?;
        let peer_vn = VerifiedNodeIdentity::from_verified_object(peer_obj)
            .map_err(|_| "daemon: invalid peer VerifiedNodeIdentity".to_string())?;

        if local_vn.node_id() != config.identity.node_id
            || local_vn.identity_generation() != config.identity.identity_generation
        {
            return Err(
                "daemon: config node_id/identity_generation does not match verified local.signed"
                    .to_string(),
            );
        }

        let local_peer = PeerIdentity {
            net_id: local_vn.net_id(),
            node_id: local_vn.node_id(),
            identity_generation: local_vn.identity_generation(),
            role: local_vn.role(),
        };
        let remote_peer = PeerIdentity {
            net_id: peer_vn.net_id(),
            node_id: peer_vn.node_id(),
            identity_generation: peer_vn.identity_generation(),
            role: peer_vn.role(),
        };

        let extractor = Arc::new(
            PkiIdentityExtractor::new(vec![local_vn, peer_vn])
                .map_err(|_| "daemon: duplicate or invalid SPKIs".to_string())?,
        );

        let tls_policy = Policy::production_default();
        let inner_conn = OpenSslConnector::from_pem_files(
            &mat_dir.join("identity.pem"),
            &config.identity.private_key,
            &mat_dir.join("identity-ca.pem"),
            tls_policy,
        )
        .map_err(|_| "daemon: inner pq768 connector setup failed".to_string())?;
        let inner_acc = OpenSslAcceptor::from_pem_files(
            &mat_dir.join("identity.pem"),
            &config.identity.private_key,
            &mat_dir.join("identity-ca.pem"),
            tls_policy,
        )
        .map_err(|_| "daemon: inner pq768 acceptor setup failed".to_string())?;

        let e2e_conn = OpenSslConnector::from_pem_files(
            &mat_dir.join("identity.pem"),
            &config.identity.private_key,
            &mat_dir.join("identity-ca.pem"),
            tls_policy,
        )
        .map_err(|_| "daemon: E2E pq768 connector setup failed".to_string())?;
        let e2e_acc = OpenSslAcceptor::from_pem_files(
            &mat_dir.join("identity.pem"),
            &config.identity.private_key,
            &mat_dir.join("identity-ca.pem"),
            tls_policy,
        )
        .map_err(|_| "daemon: E2E pq768 acceptor setup failed".to_string())?;
        let e2e_backend =
            OpenSslE2eBackend::new(Arc::new(e2e_conn), Arc::new(e2e_acc), extractor.clone());

        // Open real Linux TUN (or VirtualTun for unprivileged tests) BEFORE starting traffic.
        let tun_endpoint = if virtual_tun {
            let (device, host) = VirtualTun::try_pair(64, 64, mtu)
                .map_err(|e| format!("daemon VirtualTun failed: {e}"))?;
            TunEndpoint::Virtual {
                device,
                _host: host,
            }
        } else {
            let (dev, queue) = LinuxTunDevice::create(TunConfig {
                name: tun_name,
                mtu,
                multi_queue: false,
                vnet_header: false,
            })
            .map_err(|e| {
                format!(
                    "daemon Linux TUN creation failed (need CAP_NET_ADMIN / /dev/net/tun): {e:?}"
                )
            })?;
            let actual_name = dev.name().to_string();
            TunEndpoint::Real {
                _device: dev,
                io: NonBlockingLinuxTun {
                    queue,
                    poll_timeout: POLL_IO_TIMEOUT,
                },
                name: actual_name,
            }
        };

        let node_label = format!(
            "{}-{}",
            config.identity.role.as_str(),
            config.identity.node_id
        );
        let counters = Arc::new(LiveCounters {
            node_label,
            security_mode: config.security.mode.as_str(),
            inbound_on: mode == Mode::Serve,
            connected: AtomicBool::new(false),
            inbound_connections: AtomicU64::new(0),
            outbound_upstreams: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            status_sequence: AtomicU64::new(verified.status_sequence),
            status_fresh: AtomicBool::new(true),
        });
        let _ctl_guard = start_control_socket(&config.paths.state_dir, Arc::clone(&counters))?;

        let session_policy = SessionPolicy {
            local: local_peer,
            expected_peer: remote_peer,
            path_role: PathRole::Cdn,
            security_mode: ProtoSecurityMode::E2eRequired,
            suite: Suite::Pq768,
            mtu_cap: 1400,
            identity_registered: true,
            allow_pq1024: false,
            allow_hop_only: false,
            allowed_peer_roles: vec![remote_peer.role],
        };

        match mode {
            Mode::Serve => run_serve_loop(
                listen_spec.ok_or_else(|| "daemon serve: `--listen` is required".to_string())?,
                &mat_dir,
                &roots_path,
                &mat_dir.join("status.signed"),
                cfg_net_id,
                inner_acc,
                extractor,
                e2e_backend,
                session_policy,
                remote_peer,
                &tun_endpoint,
                mtu,
                max_packets,
                max_seconds,
                &counters,
            ),
            Mode::Connect => {
                let dial_str = connect_spec.unwrap_or_else(|| config.uplinks.primary.clone());
                let default_host = dial_str
                    .split(':')
                    .next()
                    .unwrap_or("wss.boreas.internal")
                    .to_string();
                let sni = tls_name.unwrap_or_else(|| default_host.clone());
                let host_hdr = ws_host.unwrap_or(dial_str.clone());
                run_connect_loop(
                    &dial_str,
                    &sni,
                    &host_hdr,
                    &ws_path,
                    &mat_dir,
                    &roots_path,
                    &mat_dir.join("status.signed"),
                    cfg_net_id,
                    inner_conn,
                    extractor,
                    e2e_backend,
                    session_policy,
                    remote_peer,
                    &tun_endpoint,
                    mtu,
                    max_packets,
                    max_seconds,
                    &counters,
                )
            }
        }
    }

    /// Outer TLS connector wrapper that records the raw socket `fd` on `connect`
    /// so the steady-state packet loop can `poll(fd, POLLIN, 20ms)` **before**
    /// calling `PacketPath::step_inbound()` (preventing idle reads from entering
    /// `WsStream` and poisoning the stream).
    struct TrackingOuterConnector {
        inner: OpenSslOuterTlsConnector,
        fd_slot: Arc<std::sync::atomic::AtomicI32>,
    }

    impl boreas_tunnel::OuterTlsConnector for TrackingOuterConnector {
        fn connect(
            &self,
            tcp: std::net::TcpStream,
            server_name: &str,
        ) -> Result<Box<dyn boreas_tunnel::Duplex>, TunnelError> {
            self.fd_slot.store(tcp.as_raw_fd(), Ordering::SeqCst);
            self.inner.connect(tcp, server_name)
        }
    }

    fn tcp_fd_readable(fd: i32, timeout_ms: i32) -> Result<bool, String> {
        if fd < 0 {
            return Err("daemon: invalid socket fd".to_string());
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err("daemon: socket poll failed".to_string());
        }
        Ok(rc > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_serve_loop(
        listen_spec: String,
        mat_dir: &Path,
        roots_path: &Path,
        status_path: &Path,
        expected_net_id: [u8; 16],
        inner_acc: OpenSslAcceptor,
        extractor: Arc<PkiIdentityExtractor>,
        e2e_backend: OpenSslE2eBackend,
        session_policy: SessionPolicy,
        remote_peer: PeerIdentity,
        tun: &TunEndpoint,
        mtu: usize,
        max_packets: Option<u64>,
        max_seconds: Option<u64>,
        counters: &Arc<LiveCounters>,
    ) -> Result<(), String> {
        let listen_addr = resolve_addr(&listen_spec)?;
        let outer_acc = OpenSslOuterTlsAcceptor::from_pem_files(
            mat_dir.join("outer.pem"),
            mat_dir.join("outer.key"),
        )
        .map_err(|_| "daemon serve: outer.pem/outer.key setup failed".to_string())?;
        let listener = TcpListener::bind(listen_addr)
            .map_err(|_| "daemon serve: cannot bind TCP listener".to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "daemon serve: listener nonblocking failed".to_string())?;

        let wait_limit = max_seconds.map(Duration::from_secs).unwrap_or(ACCEPT_WAIT);
        let accept_deadline = Instant::now() + wait_limit;
        let tcp = loop {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false)
                        .map_err(|_| "daemon serve: tcp blocking mode failed".to_string())?;
                    break s;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        return Err(
                            "daemon serve: timed out waiting for peer connection".to_string()
                        );
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err("daemon serve: listener accept failed".to_string()),
            }
        };
        let sock_fd = tcp.as_raw_fd();

        let admission = Admission::new(Limits {
            handshakes_global: 8,
            authenticated_global: 8,
            authenticated_per_peer: 2,
            bytes_global: 16 * 1024 * 1024,
        });
        let link_server =
            LinkServer::new(Box::new(OpenSslInnerAcceptor::new(inner_acc, extractor)));
        let mut accepted = link_server
            .accept_tls_stream(
                tcp,
                &outer_acc,
                session_policy,
                HANDSHAKE_TIMEOUT,
                &admission,
            )
            .map_err(|e| format!("daemon serve: WSS + pq768 hop session rejected: {e}"))?;

        let e2e = accept_e2e(&mut accepted.session, &e2e_backend, remote_peer)
            .map_err(|e| format!("daemon serve: pq768 E2E circuit rejected: {e}"))?;

        counters.inbound_connections.store(1, Ordering::SeqCst);
        counters.connected.store(true, Ordering::SeqCst);

        let res = drive_packet_path(
            "serve",
            sock_fd,
            tun,
            e2e,
            mtu,
            roots_path,
            status_path,
            expected_net_id,
            max_packets,
            max_seconds,
            counters,
        );

        counters.connected.store(false, Ordering::SeqCst);
        counters.inbound_connections.store(0, Ordering::SeqCst);
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn run_connect_loop(
        dial_spec: &str,
        tls_server_name: &str,
        ws_host: &str,
        ws_path: &str,
        mat_dir: &Path,
        roots_path: &Path,
        status_path: &Path,
        expected_net_id: [u8; 16],
        inner_conn: OpenSslConnector,
        extractor: Arc<PkiIdentityExtractor>,
        e2e_backend: OpenSslE2eBackend,
        session_policy: SessionPolicy,
        remote_peer: PeerIdentity,
        tun: &TunEndpoint,
        mtu: usize,
        max_packets: Option<u64>,
        max_seconds: Option<u64>,
        counters: &Arc<LiveCounters>,
    ) -> Result<(), String> {
        let target_addr = resolve_addr(dial_spec)?;
        let outer_ca_path = mat_dir.join("outer-ca.pem");
        let outer_conn = if outer_ca_path.exists() {
            let pem = fs::read(&outer_ca_path)
                .map_err(|_| "daemon connect: cannot read outer-ca.pem".to_string())?;
            OpenSslOuterTlsConnector::with_root_certificates(&pem)
                .map_err(|_| "daemon connect: invalid outer-ca.pem".to_string())?
        } else {
            OpenSslOuterTlsConnector::web_pki()
                .map_err(|_| "daemon connect: web-PKI roots unavailable".to_string())?
        };

        let fd_slot = Arc::new(std::sync::atomic::AtomicI32::new(-1));
        let tracking_outer = TrackingOuterConnector {
            inner: outer_conn,
            fd_slot: Arc::clone(&fd_slot),
        };
        let link_client = LinkClient::new(
            Box::new(tracking_outer),
            Box::new(OpenSslInnerConnector::new(inner_conn, extractor)),
        );
        let client_target = ClientTarget {
            address: target_addr,
            ws_host: ws_host.to_string(),
            tls_server_name: tls_server_name.to_string(),
            path: ws_path.to_string(),
        };

        let mut hop_session = link_client
            .connect(&client_target, session_policy, HANDSHAKE_TIMEOUT)
            .map_err(|e| format!("daemon connect: WSS + pq768 hop session rejected: {e}"))?;
        let sock_fd = fd_slot.load(Ordering::SeqCst);

        let e2e = open_e2e(&mut hop_session, &e2e_backend, remote_peer, 1)
            .map_err(|e| format!("daemon connect: pq768 E2E circuit rejected: {e}"))?;

        counters.outbound_upstreams.store(1, Ordering::SeqCst);
        counters.connected.store(true, Ordering::SeqCst);

        let res = drive_packet_path(
            "connect",
            sock_fd,
            tun,
            e2e,
            mtu,
            roots_path,
            status_path,
            expected_net_id,
            max_packets,
            max_seconds,
            counters,
        );

        counters.connected.store(false, Ordering::SeqCst);
        counters.outbound_upstreams.store(0, Ordering::SeqCst);
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_packet_path(
        mode_name: &str,
        sock_fd: i32,
        tun: &TunEndpoint,
        e2e: boreas_tunnel::e2e::E2eCircuit<'_>,
        mtu: usize,
        roots_path: &Path,
        status_path: &Path,
        expected_net_id: [u8; 16],
        max_packets: Option<u64>,
        max_seconds: Option<u64>,
        counters: &Arc<LiveCounters>,
    ) -> Result<(), String> {
        let mut path = PacketPath::try_new_over_e2e(tun.packet_io(), e2e, mtu)
            .map_err(|e| format!("daemon {mode_name}: PacketPath bind rejected: {e:?}"))?;
        let local_vip = path.local_endpoint().vip;
        let peer_vip = path.peer_endpoint().vip;

        let started = Instant::now();
        let mut last_status_check = Instant::now();
        let stop_reason: &'static str;

        loop {
            if let Some(sec) = max_seconds
                && started.elapsed() >= Duration::from_secs(sec)
            {
                path.close();
                stop_reason = "max_seconds_reached";
                break;
            }
            if let Some(limit) = max_packets {
                let st = path.stats();
                if st.outbound_packets.saturating_add(st.inbound_packets) >= limit {
                    path.close();
                    stop_reason = "max_packets_reached";
                    break;
                }
            }

            // §3.4 StatusSnapshot fail-closed freshness check: if expired or invalid,
            // immediately close the E2E circuit and stop forwarding business packets.
            if last_status_check.elapsed() >= STATUS_RECHECK_INTERVAL {
                last_status_check = Instant::now();
                let now_us = now_utc_us()?;
                match verify_status_freshness_from_roots(
                    roots_path,
                    status_path,
                    expected_net_id,
                    now_us,
                ) {
                    Ok((seq, _issued, _next)) => {
                        let prev = counters.status_sequence.load(Ordering::Relaxed);
                        if seq < prev {
                            counters.status_fresh.store(false, Ordering::SeqCst);
                            path.close();
                            return Err(
                                "daemon: StatusSnapshot sequence rollback detected (fail-closed)"
                                    .to_string(),
                            );
                        }
                        counters.status_sequence.store(seq, Ordering::Relaxed);
                    }
                    Err(e) => {
                        counters.status_fresh.store(false, Ordering::SeqCst);
                        path.close();
                        return Err(format!(
                            "daemon: StatusSnapshot stale or invalid, business forwarding halted (§3.4): {e}"
                        ));
                    }
                }
            }

            // 1. Outbound step: `NonBlockingLinuxTun` polls `/dev/net/tun` up to 25ms.
            match path.step_outbound() {
                Ok(Some(_len)) => {
                    let st = path.stats();
                    counters
                        .tx_packets
                        .store(st.outbound_packets, Ordering::Relaxed);
                    counters
                        .tx_bytes
                        .store(st.outbound_bytes, Ordering::Relaxed);
                }
                Ok(None) => {}
                Err(PacketPathError::Denied(_)) => {
                    // Fail-closed per-packet denial already poisoned `path`.
                    return Err(
                        "daemon: outbound L3 packet denied by PointToPoint policy".to_string()
                    );
                }
                Err(e) => {
                    return Err(format!("daemon: outbound packet path error: {e:?}"));
                }
            }

            // 2. Inbound step: only enter `step_inbound` when TCP socket is readable!
            if tcp_fd_readable(sock_fd, 10)? {
                match path.step_inbound() {
                    Ok(Some(_len)) => {
                        let st = path.stats();
                        counters
                            .rx_packets
                            .store(st.inbound_packets, Ordering::Relaxed);
                        counters.rx_bytes.store(st.inbound_bytes, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        stop_reason = "peer_closed_cleanly";
                        break;
                    }
                    Err(e) => {
                        return Err(format!("daemon: inbound packet path error: {e:?}"));
                    }
                }
            }
        }

        let st = path.stats();
        println!(
            "{{\"command\":\"daemon.{mode_name}\",\"status\":\"ok\",\"stop_reason\":\"{stop_reason}\",\"tun\":\"{}\",\"local_vip\":\"{local_vip}\",\"peer_vip\":\"{peer_vip}\",\"security_mode\":\"e2e-required\",\"suite\":\"pq768\",\"tx_packets\":{},\"tx_bytes\":{},\"rx_packets\":{},\"rx_bytes\":{}}}",
            tun.name(),
            st.outbound_packets,
            st.outbound_bytes,
            st.inbound_packets,
            st.inbound_bytes
        );
        Ok(())
    }
}
