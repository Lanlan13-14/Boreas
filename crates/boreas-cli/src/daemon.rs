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

#[cfg(not(unix))]
use crate::render::StatusSnapshot;
#[cfg(unix)]
use crate::render::{DaemonState, SecurityMode as RenderSecurityMode, StatusSnapshot};
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
        Arc, Condvar, Mutex,
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

    const IDLE_POLL_TIMEOUT: Duration = Duration::from_millis(10);
    const VIRTUAL_IDLE_WAIT: Duration = Duration::from_millis(1);
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

    /// Linux TUN adapter whose reads never introduce a polling delay. The daemon
    /// waits on the TUN and outer TCP descriptors together when idle, then drains
    /// ready work without a per-packet sleep.
    struct NonBlockingLinuxTun {
        queue: LinuxTunQueue,
    }

    impl NonBlockingLinuxTun {
        fn raw_fd(&self) -> i32 {
            self.queue.as_raw_fd()
        }
    }

    impl PacketIo for NonBlockingLinuxTun {
        fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
            self.queue
                .read_packet_timeout(Duration::ZERO)
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

        fn raw_fd(&self) -> Option<i32> {
            match self {
                Self::Real { io, .. } => Some(io.raw_fd()),
                Self::Virtual { .. } => None,
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

    fn connect_endpoints<'a>(primary: &'a str, backup: Option<&'a str>) -> Vec<&'a str> {
        match backup.filter(|backup| *backup != primary) {
            Some(backup) => vec![primary, backup],
            None => vec![primary],
        }
    }

    fn attempt_endpoint<T, E>(
        index: usize,
        endpoint_count: usize,
        dial: impl FnOnce() -> Result<T, E>,
        is_retryable_tcp_error: impl FnOnce(&E) -> bool,
    ) -> Result<T, EndpointAttemptError<E>> {
        match dial() {
            Ok(value) => Ok(value),
            Err(error) if index == 0 && endpoint_count == 2 && is_retryable_tcp_error(&error) => {
                Err(EndpointAttemptError::TryBackup(error))
            }
            Err(error) => Err(EndpointAttemptError::Stop(error)),
        }
    }

    enum EndpointAttemptError<E> {
        TryBackup(E),
        Stop(E),
    }

    fn may_try_backup(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
        )
    }

    fn endpoint_tls_name(endpoint: &str) -> Result<&str, String> {
        if endpoint.starts_with('[') {
            return Err("daemon: IPv6 endpoint TLS names are unsupported".to_string());
        }
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| "daemon: endpoint must be host:port".to_string())?;
        if host.is_empty() || host.starts_with('[') || host.contains(':') || port.is_empty() {
            return Err("daemon: endpoint host/port is invalid".to_string());
        }
        Ok(host)
    }

    fn client_target(
        endpoint: &str,
        tls_override: Option<&str>,
        ws_override: Option<&str>,
        path: &str,
    ) -> Result<ClientTarget, String> {
        Ok(ClientTarget {
            address: resolve_addr(endpoint)?,
            ws_host: ws_override.unwrap_or(endpoint).to_string(),
            tls_server_name: tls_override
                .map(str::to_string)
                .unwrap_or(endpoint_tls_name(endpoint)?.to_string()),
            path: path.to_string(),
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

        let id_pem = mat_dir.join("identity.pem");
        let id_ca_pem = mat_dir.join("identity-ca.pem");
        let tls_policy = Policy::production_default();
        let inner_conn = OpenSslConnector::from_pem_files(
            &id_pem,
            &config.identity.private_key,
            &id_ca_pem,
            tls_policy,
        )
        .map_err(|_| "daemon: inner pq768 connector setup failed".to_string())?;
        let inner_acc = OpenSslAcceptor::from_pem_files(
            &id_pem,
            &config.identity.private_key,
            &id_ca_pem,
            tls_policy,
        )
        .map_err(|_| "daemon: inner pq768 acceptor setup failed".to_string())?;

        let e2e_conn = OpenSslConnector::from_pem_files(
            &id_pem,
            &config.identity.private_key,
            &id_ca_pem,
            tls_policy,
        )
        .map_err(|_| "daemon: E2E pq768 connector setup failed".to_string())?;
        let e2e_acc = OpenSslAcceptor::from_pem_files(
            &id_pem,
            &config.identity.private_key,
            &id_ca_pem,
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
                io: NonBlockingLinuxTun { queue },
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
                let explicit_connect = connect_spec.is_some();
                let primary = connect_spec.unwrap_or_else(|| config.uplinks.primary.clone());
                let backup = if explicit_connect {
                    None
                } else {
                    config.uplinks.backup.as_deref()
                };
                run_connect_loop(
                    &primary,
                    backup,
                    tls_name.as_deref(),
                    ws_host.as_deref(),
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

    /// Bounded readiness wait on the outer socket and, when the endpoint is a real
    /// device, the TUN descriptor as one event set.
    ///
    /// Socket readiness is only one input: OpenSSL, WebSocket, `FrameIo` and
    /// `CircuitStream` can all retain bytes after an earlier read, so the packet
    /// loop also consults `PacketPath::has_buffered_input()`. A zero duration is
    /// a nonblocking probe; an idle iteration uses a short bounded wait so the
    /// loop always returns to the status/budget checks.
    ///
    /// A terminal TUN event (`POLLERR` / `POLLHUP`) is fail-closed: a dead host
    /// packet interface is not a recoverable condition and must stop business
    /// forwarding instead of idling on a descriptor that never fills. The outer
    /// socket's `POLLHUP`/`POLLERR` stays readable on purpose, because it is how
    /// a clean peer close (and the watchdog's `shutdown`) surfaces.
    fn poll_io(
        sock_fd: i32,
        tun_fd: Option<i32>,
        timeout: Duration,
    ) -> Result<(bool, bool), String> {
        if sock_fd < 0 || tun_fd.is_some_and(|fd| fd < 0) {
            return Err("daemon: invalid poll fd".to_string());
        }
        let mut fds = [
            libc::pollfd {
                fd: sock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tun_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = if tun_fd.is_some() { 2 } else { 1 };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `fds` is a valid array of `count` initialized `pollfd` values;
        // `poll` only writes `revents`.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok((false, false));
            }
            return Err("daemon: socket/TUN poll failed".to_string());
        }
        if fds.iter().any(|pfd| pfd.revents & libc::POLLNVAL != 0) {
            return Err("daemon: poll reported an invalid fd".to_string());
        }
        if count == 2 && fds[1].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return Err(
                "daemon: TUN device reported a terminal poll event (HUP/ERR); business forwarding halted"
                    .to_string(),
            );
        }
        let ready =
            |pfd: &libc::pollfd| pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        Ok((
            ready(&fds[0]),
            count == 2 && fds[1].revents & libc::POLLIN != 0,
        ))
    }

    /// Whether one loop iteration did work.
    ///
    /// A packet the host emitted for another address is consumed and dropped by
    /// the adapter. That is still work: treating it as idle would sleep in front
    /// of a TUN queue that is ready, so it keeps the loop hot without pretending
    /// that anything crossed the circuit.
    fn iteration_progress(delivered: bool, dropped_before: u64, dropped_after: u64) -> bool {
        delivered || dropped_after > dropped_before
    }

    /// §3.4 `StatusSnapshot` freshness watchdog.
    ///
    /// The 500 ms re-check reads `roots.cbor` + `status.signed` and verifies
    /// signatures, so it cannot live on the packet loop: a blocking socket read
    /// would stall it past the deadline. This thread runs the same
    /// [`verify_status_freshness_from_roots`] check, publishes the first failure
    /// as an owned string, and interrupts any in-flight blocking I/O with
    /// `shutdown(SHUT_RDWR)` on the outer socket.
    ///
    /// It never tears the circuit down and never falls back to hop-only: the
    /// packet loop owns the fail-closed teardown and reports the published
    /// reason. `Drop` stops and joins the thread, so every exit path — including
    /// a panic-free early return — leaves no live checker behind.
    struct StatusWatchdog {
        /// Guards the wakeup predicate. The predicate itself is the atomic
        /// below so a stopped checker never needs the lock to observe `stop`,
        /// and no lock is ever held across `shutdown()` or a status check.
        stop: Arc<(Mutex<()>, Condvar)>,
        stopped: Arc<AtomicBool>,
        fault: Arc<Mutex<Option<String>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl StatusWatchdog {
        fn start(
            roots_path: PathBuf,
            status_path: PathBuf,
            expected_net_id: [u8; 16],
            sock_fd: i32,
            counters: Arc<LiveCounters>,
            interval: Duration,
        ) -> Self {
            let stop = Arc::new((Mutex::new(()), Condvar::new()));
            let stopped = Arc::new(AtomicBool::new(false));
            let fault: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let stop_bg = Arc::clone(&stop);
            let stopped_bg = Arc::clone(&stopped);
            let fault_bg = Arc::clone(&fault);
            let handle = thread::spawn(move || {
                loop {
                    // Monotonic deadline per check: verification work must not
                    // stretch the cadence, and stop/join must stay prompt.
                    let deadline = Instant::now() + interval;
                    let mut guard = match stop_bg.0.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    while !stopped_bg.load(Ordering::Acquire) {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        guard = match stop_bg.1.wait_timeout(guard, deadline - now) {
                            Ok((guard, _timeout)) => guard,
                            Err(poisoned) => poisoned.into_inner().0,
                        };
                    }
                    let stopping = stopped_bg.load(Ordering::Acquire);
                    drop(guard);
                    if stopping {
                        return;
                    }

                    let failure = match now_utc_us() {
                        Err(_) => Some(
                            "daemon: StatusSnapshot clock unavailable (system clock before UNIX_EPOCH)"
                                .to_string(),
                        ),
                        Ok(now_us) => match verify_status_freshness_from_roots(
                            &roots_path,
                            &status_path,
                            expected_net_id,
                            now_us,
                        ) {
                            Ok((seq, _issued, _next)) => {
                                let prev = counters.status_sequence.load(Ordering::Relaxed);
                                if seq < prev {
                                    Some(format!(
                                        "daemon: StatusSnapshot sequence rollback detected (fail-closed): {seq} < {prev}"
                                    ))
                                } else {
                                    counters.status_sequence.store(seq, Ordering::Relaxed);
                                    None
                                }
                            }
                            Err(error) => Some(format!(
                                "daemon: StatusSnapshot stale or invalid, business forwarding halted (§3.4): {error}"
                            )),
                        },
                    };
                    let Some(message) = failure else { continue };
                    // Ordering: flag first (observable through `ctl status`), then the
                    // owned reason, then the syscall that unblocks the packet loop.
                    counters.status_fresh.store(false, Ordering::SeqCst);
                    {
                        let mut slot = match fault_bg.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if slot.is_none() {
                            *slot = Some(message);
                        }
                    }
                    if sock_fd >= 0 {
                        // SAFETY: `sock_fd` is the connected outer TCP socket, kept
                        // open for the whole lifetime of `drive_packet_path`; this
                        // watchdog is stopped and joined before that stream drops.
                        unsafe { libc::shutdown(sock_fd, libc::SHUT_RDWR) };
                    }
                    return;
                }
            });
            Self {
                stop,
                stopped,
                fault,
                handle: Some(handle),
            }
        }

        /// Owned first-failure reason, if the watchdog halted forwarding.
        fn fault(&self) -> Option<String> {
            match self.fault.lock() {
                Ok(slot) => (*slot).clone(),
                Err(poisoned) => (*poisoned.into_inner()).clone(),
            }
        }
    }

    impl Drop for StatusWatchdog {
        fn drop(&mut self) {
            {
                // Store the stop flag under the lock so a notify cannot be lost
                // between the checker's predicate test and its wait.
                let _guard = match self.stop.0.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                self.stopped.store(true, Ordering::Release);
            }
            self.stop.1.notify_all();
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
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
        primary_spec: &str,
        backup_spec: Option<&str>,
        tls_name_override: Option<&str>,
        ws_host_override: Option<&str>,
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
        let endpoints = connect_endpoints(primary_spec, backup_spec);
        let mut connected: Option<(boreas_tunnel::EstablishedSession, i32)> = None;
        for (index, endpoint) in endpoints.iter().enumerate() {
            let now_us = now_utc_us()?;
            verify_status_freshness_from_roots(roots_path, status_path, expected_net_id, now_us)
                .map_err(|e| format!("daemon connect: StatusSnapshot stale or invalid: {e}"))?;
            let target = client_target(endpoint, tls_name_override, ws_host_override, ws_path)?;
            match attempt_endpoint(
                index,
                endpoints.len(),
                || link_client.connect_tcp(&target, HANDSHAKE_TIMEOUT),
                may_try_backup,
            ) {
                Ok(tcp) => {
                    let now_us = now_utc_us()?;
                    verify_status_freshness_from_roots(
                        roots_path,
                        status_path,
                        expected_net_id,
                        now_us,
                    )
                    .map_err(|e| format!("daemon connect: StatusSnapshot stale or invalid: {e}"))?;
                    let session = link_client
                        .connect_preconnected(tcp, &target, session_policy.clone())
                        .map_err(|e| {
                            format!("daemon connect: WSS + pq768 hop session rejected: {e}")
                        })?;
                    connected = Some((session, fd_slot.load(Ordering::SeqCst)));
                    break;
                }
                Err(EndpointAttemptError::TryBackup(_error)) => continue,
                Err(EndpointAttemptError::Stop(error)) => {
                    return Err(format!("daemon connect: TCP connect failed: {error}"));
                }
            }
        }
        let (mut hop_session, sock_fd) =
            connected.ok_or_else(|| "daemon connect: no endpoint connected".to_string())?;

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
        let local_vip = path.local_endpoint().vip();
        let peer_vip = path.peer_endpoint().vip();

        // Declared after `path` on purpose: the watchdog is stopped and joined
        // before the E2E stream (and its socket) is dropped, so `shutdown()`
        // can never target a recycled descriptor.
        let watchdog = StatusWatchdog::start(
            roots_path.to_path_buf(),
            status_path.to_path_buf(),
            expected_net_id,
            sock_fd,
            Arc::clone(counters),
            STATUS_RECHECK_INTERVAL,
        );

        let started = Instant::now();
        let mut last_dropped = 0u64;
        let stop_reason: &'static str;

        loop {
            // Status first: once the watchdog published a failure, business I/O
            // is forbidden and that reason must win over every later symptom.
            if let Some(reason) = watchdog.fault() {
                path.close();
                return Err(reason);
            }

            if let Some(sec) = max_seconds
                && started.elapsed() >= Duration::from_secs(sec)
            {
                path.close_gracefully();
                stop_reason = "max_seconds_reached";
                break;
            }
            if let Some(limit) = max_packets {
                let st = path.stats();
                if st.outbound_packets.saturating_add(st.inbound_packets) >= limit {
                    path.close_gracefully();
                    stop_reason = "max_packets_reached";
                    break;
                }
            }

            // Both packet sources are nonblocking here: TUN reads are zero-time
            // readiness queries and idle waiting happens once per iteration.
            // Status freshness is no longer checked inline — the watchdog owns
            // it, so a blocking read can never stall the §3.4 deadline.
            let mut made_progress = false;
            match path.step_outbound() {
                Ok(Some(_len)) => {
                    made_progress = true;
                    let st = path.stats();
                    counters
                        .tx_packets
                        .store(st.outbound_packets, Ordering::Relaxed);
                    counters
                        .tx_bytes
                        .store(st.outbound_bytes, Ordering::Relaxed);
                }
                Ok(None) => {
                    // `Ok(None)` covers both "no host packet" and "a valid host
                    // packet the adapter discarded locally". The latter consumed
                    // a packet, so it counts as work: sleeping in front of a
                    // still-ready TUN queue would leak latency for no reason.
                    let dropped = path.stats().dropped_outbound;
                    made_progress = iteration_progress(made_progress, last_dropped, dropped);
                    last_dropped = dropped;
                }
                Err(PacketPathError::Denied(_)) => {
                    // `step_outbound` discards ordinary local traffic itself.
                    // Reaching here means the packet was malformed or the host
                    // packet interface failed; that remains fatal.
                    if let Some(reason) = watchdog.fault() {
                        path.close();
                        return Err(reason);
                    }
                    return Err(
                        "daemon: outbound packet path rejected a malformed host packet".to_string(),
                    );
                }
                Err(e) => {
                    // A watchdog `shutdown()` surfaces here as an I/O error; the
                    // status reason must win over the symptom it caused.
                    if let Some(reason) = watchdog.fault() {
                        path.close();
                        return Err(reason);
                    }
                    return Err(format!("daemon: outbound packet path error: {e:?}"));
                }
            }

            // Raw TCP readiness alone is insufficient: OpenSSL, WebSocket,
            // FrameIo and CircuitStream can all hold bytes after an earlier
            // read. Drain whenever any layer reports buffered input as well.
            let buffered = path.has_buffered_input();
            let socket_ready = if buffered {
                // Buffered work is already known to be readable; skip the probe.
                false
            } else {
                poll_io(sock_fd, None, Duration::ZERO)?.0
            };
            if buffered || socket_ready {
                match path.step_inbound() {
                    Ok(Some(_len)) => {
                        made_progress = true;
                        let st = path.stats();
                        counters
                            .rx_packets
                            .store(st.inbound_packets, Ordering::Relaxed);
                        counters.rx_bytes.store(st.inbound_bytes, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        // The watchdog's `shutdown()` also surfaces as a clean
                        // end of stream; the status reason must win.
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        stop_reason = "peer_closed_cleanly";
                        break;
                    }
                    Err(e) => {
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        return Err(format!("daemon: inbound packet path error: {e:?}"));
                    }
                }
            }

            if !made_progress && !buffered {
                if tun.raw_fd().is_none() && !socket_ready {
                    // In-memory endpoint: nothing to wait on, so yield briefly
                    // rather than spin at 100% CPU.
                    thread::sleep(VIRTUAL_IDLE_WAIT);
                } else {
                    // One wait on both sources: an outbound packet arriving on
                    // the TUN wakes the loop immediately, and a TUN HUP/ERR is
                    // fail-closed inside `poll_io` instead of idling forever.
                    poll_io(sock_fd, tun.raw_fd(), IDLE_POLL_TIMEOUT)?;
                }
            }
        }

        // A failure that raced in during a graceful budget stop must still be
        // reported: never print `"status":"ok"` for a halted §3.4 condition.
        if let Some(reason) = watchdog.fault() {
            return Err(reason);
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

    #[cfg(test)]
    mod watchdog_tests {
        use super::*;

        #[test]
        fn endpoint_selection_used_by_connect_loop_and_names_honor_overrides() {
            assert_eq!(
                connect_endpoints("primary:443", Some("backup:443")),
                vec!["primary:443", "backup:443"]
            );
            assert_eq!(connect_endpoints("cli:9443", None), vec!["cli:9443"]);
            assert_eq!(
                endpoint_tls_name("backup.example:8443").unwrap(),
                "backup.example"
            );
            assert!(endpoint_tls_name("[::1]:443").is_err());
            let target = client_target(
                "127.0.0.1:443",
                Some("override.example"),
                Some("override-host:8443"),
                "/x",
            )
            .unwrap();
            assert_eq!(target.ws_host, "override-host:8443");
            assert_eq!(target.tls_server_name, "override.example");
        }

        #[test]
        fn backup_gate_rejects_non_transport_errors_and_handshake_failures_stop() {
            let mut calls = 0;
            let result: Result<(), EndpointAttemptError<std::io::Error>> = attempt_endpoint(
                0,
                2,
                || {
                    calls += 1;
                    Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                },
                may_try_backup,
            );
            assert!(matches!(result, Err(EndpointAttemptError::TryBackup(_))));
            assert_eq!(calls, 1);

            let result: Result<(), _> = attempt_endpoint(0, 2, || Err("TLS rejected"), |_| false);
            assert!(matches!(
                result,
                Err(EndpointAttemptError::Stop("TLS rejected"))
            ));

            for kind in [
                std::io::ErrorKind::ConnectionReset,
                std::io::ErrorKind::PermissionDenied,
                std::io::ErrorKind::InvalidInput,
            ] {
                let error = std::io::Error::from(kind);
                assert!(matches!(
                    attempt_endpoint::<(), _>(0, 2, || Err(error), may_try_backup),
                    Err(EndpointAttemptError::Stop(_))
                ));
            }
        }

        fn counters() -> Arc<LiveCounters> {
            Arc::new(LiveCounters {
                node_label: "test".to_string(),
                security_mode: "e2e-required",
                inbound_on: false,
                connected: AtomicBool::new(true),
                inbound_connections: AtomicU64::new(0),
                outbound_upstreams: AtomicU64::new(0),
                tx_packets: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                rx_packets: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
                status_sequence: AtomicU64::new(7),
                status_fresh: AtomicBool::new(true),
            })
        }

        /// An unusable status file must halt forwarding: the first failure is
        /// published as an owned string and `status_fresh` flips immediately,
        /// without requiring a live socket.
        #[test]
        fn watchdog_publishes_status_failure_and_marks_stale() {
            let counters = counters();
            let watchdog = StatusWatchdog::start(
                PathBuf::from("/nonexistent-boreas-roots.cbor"),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                [0x2a; 16],
                -1,
                Arc::clone(&counters),
                Duration::from_millis(10),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut reason = None;
            while Instant::now() < deadline {
                if let Some(published) = watchdog.fault() {
                    reason = Some(published);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let reason = reason.expect("watchdog must publish a status failure");
            assert!(
                reason.contains("StatusSnapshot"),
                "unexpected reason: {reason}"
            );
            assert!(!counters.status_fresh.load(Ordering::SeqCst));
        }

        /// `Drop` stops and joins promptly even while the checker is parked.
        #[test]
        fn watchdog_drop_joins_promptly_without_fault() {
            let counters = counters();
            let watchdog = StatusWatchdog::start(
                PathBuf::from("/nonexistent-boreas-roots.cbor"),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                [0x2a; 16],
                -1,
                Arc::clone(&counters),
                Duration::from_secs(3600),
            );
            let started = Instant::now();
            drop(watchdog);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "watchdog drop must not block: {:?}",
                started.elapsed()
            );
            assert!(counters.status_fresh.load(Ordering::SeqCst));
        }

        /// `shutdown(SHUT_RDWR)` is the mechanism that unblocks a stalled read;
        /// without it the 500 ms re-check could never interrupt the packet loop.
        #[test]
        fn shutdown_interrupts_a_blocking_read() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let address = listener.local_addr().expect("local addr");
            let client = std::net::TcpStream::connect(address).expect("connect");
            let (_server, _) = listener.accept().expect("accept");
            let fd = client.as_raw_fd();
            let (tx, rx) = std::sync::mpsc::channel();
            let reader = thread::spawn(move || {
                let mut client = client;
                let mut byte = [0u8; 1];
                let _ = tx.send(client.read(&mut byte));
            });
            thread::sleep(Duration::from_millis(50));
            // SAFETY: `fd` belongs to `client`, owned by the reader thread for
            // the whole call; `shutdown` does not close the descriptor.
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
            let outcome = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("blocking read must be interrupted by shutdown");
            assert_eq!(outcome.expect("read returns after shutdown"), 0);
            reader.join().expect("reader thread");
        }

        /// A terminal TUN poll event is fail-closed, while the outer socket's
        /// HUP stays readable because that is how a normal peer close surfaces.
        #[test]
        fn terminal_tun_poll_event_is_fail_closed() {
            let mut sock = [0i32; 2];
            let mut tun = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(sock.as_mut_ptr()) }, 0);
            assert_eq!(unsafe { libc::pipe(tun.as_mut_ptr()) }, 0);
            // Closing the write end makes the TUN read end report POLLHUP.
            unsafe { libc::close(tun[1]) };
            let result = poll_io(sock[0], Some(tun[0]), Duration::ZERO);
            unsafe {
                libc::close(sock[0]);
                libc::close(sock[1]);
                libc::close(tun[0]);
            }
            let error = result.expect_err("a dead TUN must fail closed");
            assert!(error.contains("TUN"), "unexpected error: {error}");
        }

        /// Local discards keep the loop hot but never count as delivery.
        #[test]
        fn local_discards_count_as_progress_without_faking_delivery() {
            assert!(!iteration_progress(false, 3, 3));
            assert!(iteration_progress(false, 3, 4));
            assert!(iteration_progress(true, 0, 0));
        }
    }
}
