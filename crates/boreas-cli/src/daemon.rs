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
//! - Step 6 (`connect` only): while the primary path carries business traffic, one
//!   bounded background dial keeps a standby hop link to the configured backup
//!   endpoint authenticated. The link is checked with a transport-level poll only
//!   (no challenge and no Pong, so this is **not** `ProbePing`), and a primary
//!   path failure promotes it by rebuilding the E2E circuit on it. The promotion
//!   re-asserts the same verified peer identity and both permanent VIPs, so the
//!   overlay binding cannot change underneath the host stack. With no
//!   multi-Core directory there is no authority for a second Core: a backup
//!   endpoint owned by any other identity cannot pass the pinned-SPKI inner
//!   handshake, so this slice deliberately fails closed instead of trusting
//!   `[uplink].backup` for a cross-Core "BackupCdn".

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
  boreas daemon serve --config <FILE> --material-dir <DIR> --listen <IP:PORT> --status-state-file <ABS> --status-state-owner-uid <UID> --network-policy-tbs <FILE> --network-policy-ed25519-signature <FILE> --network-policy-mldsa65-signature <FILE> --network-root-ed25519-der <FILE> --network-root-mldsa65-der <FILE> --network-policy-state-file <ABS> --network-policy-state-owner-uid <UID> [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>] [--max-packets <N>] [--max-seconds <N>] [--virtual-tun]
  boreas daemon connect --config <FILE> --material-dir <DIR> --status-state-file <ABS> --status-state-owner-uid <UID> --network-policy-tbs <FILE> --network-policy-ed25519-signature <FILE> --network-policy-mldsa65-signature <FILE> --network-root-ed25519-der <FILE> --network-root-mldsa65-der <FILE> --network-policy-state-file <ABS> --network-policy-state-owner-uid <UID> [--connect <IP:PORT>] [--tls-name <DNS>] [--ws-host <HOST:PORT>] [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>] [--max-packets <N>] [--max-seconds <N>] [--virtual-tun]"
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
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    };
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use boreas_crypto::{
        Policy,
        backend::{OpenSslAcceptor, OpenSslConnector},
    };
    use boreas_pki::{
        Authority,
        management::ManagementTrust,
        provisioning::{
            RootsBundle, parse_net_id_hex, read_status_snapshot_raw, verify_material_dir_with_roots,
        },
        status_store::StatusStore,
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
        PeerIdentityExtractor, PkiIdentityExtractor, TunnelError, VerifiedNodeIdentity,
        e2e::{E2eCircuit, accept_e2e, open_e2e},
        failover,
        packet_path::{PacketPath, PacketPathError, PacketStats},
        resource::{Admission, Limits},
        session::{EstablishedSession, SessionPolicy},
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

    /// Absolute bound on one blocking read/write of the business socket.
    ///
    /// The packet loop starts a read only after readiness, so idle time is never
    /// spent here. This bound covers the two states readiness cannot: a peer
    /// stalled in the middle of a frame and a send window that never reopens.
    /// Both used to park the loop with no escape except a status fault, because
    /// the only thing that could interrupt the blocking call was the watchdog's
    /// `shutdown`. Expiry is an ordinary socket error that the path already
    /// refuses, i.e. a failure deadline, not a tuned wait or a retry budget.
    const PATH_IO_TIMEOUT: Duration = Duration::from_secs(30);

    /// Hard ceiling on live upstream sockets in one `connect` process: one
    /// business connection plus at most one standby dial. Every dial must hold a
    /// permit and the permit travels inside the link value, so a connection can
    /// never outlive its reservation.
    const MAX_LIVE_CONNECTIONS: u8 = 2;

    /// Standby-link cadence and failure counting.
    ///
    /// These reuse the plan's initial §8.5 cadence values (`failover::{PROBE_INTERVAL,
    /// FAIL_THRESHOLD, BACKOFF_MAX}`) unchanged: they are not tuned here, not
    /// tightened to manufacture a result, and not treated as a latency promise.
    ///
    /// The standby check itself is only a `poll(2)` for FIN/RST/unexpected bytes
    /// on an authenticated link that carries no circuit. It sends no challenge
    /// and consumes no Pong, so the counters below are liveness polls, **not**
    /// `ProbePing` samples, RTT measurements or packet-loss statistics.
    const STANDBY_POLL_INTERVAL: Duration = Duration::from_millis(failover::PROBE_INTERVAL);
    const STANDBY_FAIL_THRESHOLD: u64 = failover::FAIL_THRESHOLD as u64;
    const STANDBY_DIAL_BACKOFF: Duration = Duration::from_millis(failover::BACKOFF_MAX);
    /// Bounded wait for an in-flight standby dial before a failover verdict.
    const STANDBY_READY_WAIT: Duration = Duration::from_millis(failover::PROBE_INTERVAL);

    /// `LiveCounters::active_path` values.
    const PATH_PRIMARY: u8 = 0;
    const PATH_BACKUP: u8 = 1;

    fn active_path_label(value: u8) -> &'static str {
        if value == PATH_BACKUP {
            "backup"
        } else {
            "primary"
        }
    }

    /// Published standby verdict: a protocol/identity rejection is terminal for
    /// this path, otherwise a verified link is held, or the consecutive failure
    /// count has reached the plan's threshold, or a dial is still being
    /// established. This reports state; it never relaxes a gate.
    fn standby_state_label(counters: &LiveCounters) -> &'static str {
        if counters.standby_rejected.load(Ordering::SeqCst) {
            "rejected"
        } else if counters.standby_ready.load(Ordering::SeqCst) {
            "ready"
        } else if counters.standby_failures.load(Ordering::SeqCst) >= STANDBY_FAIL_THRESHOLD {
            "down"
        } else {
            "idle"
        }
    }

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
        /// A verified standby hop link to the same Core is currently held.
        standby_ready: AtomicBool,
        /// The standby endpoint was rejected for a protocol/identity reason, so
        /// this manager must never dial it again.
        standby_rejected: AtomicBool,
        /// Monotonic count of standby dial attempts (never rewinds).
        standby_attempts: AtomicU64,
        /// Monotonic count of transport liveness polls (never rewinds). This is
        /// not a `ProbePing` counter: no challenge is sent and no Pong matched.
        standby_polls: AtomicU64,
        /// Consecutive standby failures, reset by a verified session.
        standby_failures: AtomicU64,
        /// Completed primary -> backup promotions.
        failover_events: AtomicU64,
        /// 1-based business-path epoch; incremented per promotion.
        path_epoch: AtomicU64,
        /// Which endpoint currently carries business traffic.
        active_path: AtomicU8,
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
            self.queue.try_read_packet().map_err(|e| match e {
                boreas_tun::linux::LinuxTunError::Packet(p) => p,
                _ => TunError::QueueClosed,
            })
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
            self.queue.write_packet(packet).map_err(|e| match e {
                boreas_tun::linux::LinuxTunError::Packet(p) => p,
                boreas_tun::linux::LinuxTunError::Io(io_err)
                    if io_err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    TunError::QueueFull
                }
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

    /// Fixed signed-policy window captured once after startup verification.
    ///
    /// The signed UTC `expires` is the authority; the paired monotonic deadline
    /// prevents a wall-clock rollback from widening it. This value is never
    /// refreshed or recalculated from a later clock reading, so a new policy
    /// window cannot be silently invented at runtime.
    #[derive(Clone, Copy)]
    struct PolicyWindow {
        expires_utc_us: u64,
        deadline: Instant,
    }

    impl PolicyWindow {
        fn new(expires_utc_us: u64) -> Result<Self, String> {
            let now_us = now_utc_us()?;
            if now_us >= expires_utc_us {
                return Err("daemon: signed network policy is already expired".to_string());
            }
            let remaining_us = expires_utc_us
                .checked_sub(now_us)
                .ok_or_else(|| "daemon: signed network policy window underflow".to_string())?;
            let deadline = Instant::now()
                .checked_add(Duration::from_micros(remaining_us))
                .ok_or_else(|| "daemon: signed network policy deadline overflow".to_string())?;
            Ok(Self {
                expires_utc_us,
                deadline,
            })
        }

        fn deadline(&self) -> Instant {
            self.deadline
        }

        /// Fail closed if either the signed UTC window or its monotonic shadow
        /// has ended. The two checks are independent on purpose.
        fn check(&self) -> Result<(), String> {
            let now_us = now_utc_us()?;
            if now_us >= self.expires_utc_us {
                return Err(
                    "daemon: signed network policy expired, business forwarding halted".to_string(),
                );
            }
            if Instant::now() >= self.deadline {
                return Err(
                    "daemon: signed network policy monotonic window expired, business forwarding halted"
                        .to_string(),
                );
            }
            Ok(())
        }
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
                                "{{\"command\":\"ctl.status\",\"version\":\"{}\",\"node\":\"{}\",\"daemon_connected\":{},\"inbound_on\":{},\"inbound_connections\":{},\"outbound_upstreams\":{},\"security_mode\":\"{}\",\"tx_packets\":{},\"tx_bytes\":{},\"rx_packets\":{},\"rx_bytes\":{},\"status_sequence\":{},\"status_fresh\":{},\"standby_ready\":{},\"standby_rejected\":{},\"standby_state\":\"{}\",\"standby_attempts\":{},\"standby_polls\":{},\"standby_failures\":{},\"failover_events\":{},\"path_epoch\":{},\"active_path\":\"{}\"}}\n",
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
                                counters.standby_ready.load(Ordering::SeqCst),
                                counters.standby_rejected.load(Ordering::SeqCst),
                                standby_state_label(&counters),
                                counters.standby_attempts.load(Ordering::SeqCst),
                                counters.standby_polls.load(Ordering::SeqCst),
                                counters.standby_failures.load(Ordering::Relaxed),
                                counters.failover_events.load(Ordering::Relaxed),
                                counters.path_epoch.load(Ordering::Relaxed),
                                active_path_label(counters.active_path.load(Ordering::Relaxed)),
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

    fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// One status gate against the process-wide durable store.
    ///
    /// The store is a process-wide singleton: a second `StatusStore::open` on the
    /// same path returns `Busy`. Every boundary — each dial, each handshake, and
    /// each failover epoch — therefore re-verifies the exact current
    /// `status.signed` through that one instance instead of reopening it.
    fn lock_gate(store: &Mutex<StatusStore>, status_path: &Path) -> Result<(u64, Instant), String> {
        let mut guard = lock_mutex(store);
        status_gate(&mut guard, status_path, now_utc_us()?, Instant::now())
    }

    // --- bounded upstream connection management ----------------------------

    /// Hard ceiling on live upstream sockets in one `connect` process.
    ///
    /// The permit is carried inside the link value rather than in a side table,
    /// so a connection cannot outlive its reservation and a failed dial releases
    /// its slot immediately. This is a local concurrency bound; it does not
    /// replace the peer's global unauthenticated/authenticated admission limits.
    struct ConnectionBudget {
        live: Arc<AtomicU8>,
    }

    impl ConnectionBudget {
        fn new() -> Self {
            Self {
                live: Arc::new(AtomicU8::new(0)),
            }
        }

        fn try_acquire(&self) -> Option<ConnectionPermit> {
            let mut observed = self.live.load(Ordering::SeqCst);
            loop {
                if observed >= MAX_LIVE_CONNECTIONS {
                    return None;
                }
                match self.live.compare_exchange(
                    observed,
                    observed + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        return Some(ConnectionPermit {
                            live: Arc::clone(&self.live),
                        });
                    }
                    Err(current) => observed = current,
                }
            }
        }

        fn live(&self) -> u8 {
            self.live.load(Ordering::SeqCst)
        }
    }

    struct ConnectionPermit {
        live: Arc<AtomicU8>,
    }

    impl Drop for ConnectionPermit {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// One established, authenticated hop link plus its socket descriptor.
    ///
    /// Replacing the value on failover drops the previous session and releases
    /// its permit, so the live-connection bound holds across every epoch.
    struct HopLink {
        session: EstablishedSession,
        fd: i32,
        _permit: ConnectionPermit,
    }

    // Handshake deadlines belong to exactly one layer: the transport crate.
    //
    // `LinkClient::connect_preconnected` and `LinkServer::accept_tls_stream`
    // derive one absolute `Instant` from the budget passed here, install it on the
    // socket for outer TLS and then carry it through `DeadlineIo` for every later
    // handshake operation. The daemon therefore passes `HANDSHAKE_TIMEOUT` and
    // must never install a second, competing deadline on the same socket: two
    // mechanisms would race, and whichever fired second could mask a correctly
    // authenticated handshake or leave a timeout behind.
    //
    // The daemon owns exactly two other socket-policy decisions, both at explicit
    // boundaries:
    // - `bound_path_io` installs the steady-state business I/O bound *after* the
    //   handshake and before the first packet, deliberately replacing the
    //   handshake-shaped socket timeout the crate left behind.
    // - The status watchdog's `shutdown()` on a fault, which is an interruption,
    //   not a deadline.

    /// Transport-level health of one socket, without consuming any bytes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SocketHealth {
        /// Open, with no pending event.
        Alive,
        /// Bytes arrived that no layer of this connection is expecting.
        Unread,
        /// The peer closed (FIN) or the socket is shut down.
        PeerClosed,
        /// `POLLERR`/`POLLNVAL` or a pending `SO_ERROR`, i.e. a reset.
        Failed,
    }

    fn pending_socket_error(fd: i32) -> bool {
        if fd < 0 {
            return true;
        }
        let mut error: libc::c_int = 0;
        let mut length = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `error` and `length` are valid for one `c_int`; `SO_ERROR`
        // reads and clears the pending socket error.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        rc == 0 && error != 0
    }

    /// Classify one socket without reading from it.
    ///
    /// The standby path carries no circuit and no packets, so a byte arriving
    /// there is a protocol violation and a reset or close means the standby is
    /// gone. This never blocks and never consumes data the business path owns.
    fn socket_health(fd: i32) -> SocketHealth {
        if fd < 0 {
            return SocketHealth::Failed;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is one initialized `pollfd`; `poll` only writes `revents`.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
        if rc < 0 {
            return SocketHealth::Failed;
        }
        if pfd.revents & libc::POLLNVAL != 0 || pfd.revents & libc::POLLERR != 0 {
            return SocketHealth::Failed;
        }
        if pfd.revents & libc::POLLHUP != 0 {
            return SocketHealth::PeerClosed;
        }
        if pfd.revents & libc::POLLIN != 0 {
            if pending_socket_error(fd) {
                return SocketHealth::Failed;
            }
            return SocketHealth::Unread;
        }
        SocketHealth::Alive
    }

    /// Bound blocking reads and writes on the business socket.
    ///
    /// See [`PATH_IO_TIMEOUT`]: this is what turns "the peer stalled mid-frame"
    /// from an unbounded park into a bounded, fail-closed I/O error.
    fn bound_path_io(fd: i32) -> Result<(), String> {
        if fd < 0 {
            return Err("daemon: cannot bound I/O on an invalid socket".to_string());
        }
        let timeout = libc::timeval {
            tv_sec: PATH_IO_TIMEOUT.as_secs() as _,
            tv_usec: 0,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: `timeout` is a valid `timeval` and the length matches the
            // documented `SO_RCVTIMEO`/`SO_SNDTIMEO` argument size.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    core::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err("daemon: cannot bound business socket I/O timeouts".to_string());
            }
        }
        Ok(())
    }

    /// The authenticated facts a failover must reproduce exactly.
    ///
    /// The permanent VIP is a function of the signed identity, so an unchanged
    /// identity implies an unchanged VIP. Comparing both makes the invariant
    /// explicit and refuses any circuit whose verified endpoints differ from the
    /// pre-failure binding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BusinessIdentity {
        local_vip: std::net::Ipv4Addr,
        peer_vip: std::net::Ipv4Addr,
        peer_node_id: u16,
        peer_generation: u64,
        path_hops: u8,
        mtu_cap: u16,
    }

    fn business_identity<C: std::io::Read + std::io::Write, P: PacketIo + ?Sized>(
        path: &PacketPath<'_, C, P>,
    ) -> BusinessIdentity {
        let local = path.local_endpoint();
        let peer = path.peer_endpoint();
        BusinessIdentity {
            local_vip: local.vip(),
            peer_vip: peer.vip(),
            peer_node_id: peer.node_id(),
            peer_generation: peer.identity_generation(),
            path_hops: path.path_hops(),
            mtu_cap: path.mtu_cap(),
        }
    }

    /// Whether a path error is the host-side adapter failing rather than the
    /// authenticated circuit. Host failures never justify moving to another
    /// path: the same host adapter would refuse the packets there too.
    fn host_side_failure(error: &PacketPathError) -> bool {
        matches!(
            error,
            PacketPathError::HostQueueFull
                | PacketPathError::HostQueueClosed
                | PacketPathError::HostRejected(_)
        )
    }

    /// Whether a circuit failure may justify moving to an alternate ingress.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PathFailureKind {
        /// The byte stream failed (reset or timeout). A transport failure is the
        /// only kind that may use a verified standby path.
        Transport,
        /// Framing, policy or identity violation. These stay terminal rather than
        /// being treated as an ordinary failover trigger.
        Protocol,
    }

    /// Classify one `PacketPathError`.
    ///
    /// Only a circuit I/O failure is transport loss. A truncated frame, length
    /// disagreement, policy or identity error is a protocol failure and must
    /// never be auto-promoted as ordinary failover.
    fn path_failure_kind(error: &PacketPathError) -> PathFailureKind {
        match error {
            PacketPathError::CircuitIo(_) => PathFailureKind::Transport,
            _ => PathFailureKind::Protocol,
        }
    }

    /// Why one business path stopped.
    enum PathStop {
        /// The owner's own budget ran out: a planned stop, not a failure.
        Budget(&'static str),
        /// The peer closed the circuit between frames.
        PeerClosed,
        /// The circuit failed. The caller decides whether this kind may promote.
        Failed {
            kind: PathFailureKind,
            reason: String,
        },
    }

    struct PathReport {
        stop: PathStop,
        identity: BusinessIdentity,
        stats: PacketStats,
        local_vip: std::net::Ipv4Addr,
        peer_vip: std::net::Ipv4Addr,
    }

    fn print_path_summary(
        mode_name: &str,
        tun: &TunEndpoint,
        report: &PathReport,
        stop_reason: &str,
        failover_events: u64,
        path_epoch: u64,
    ) {
        let stats = report.stats;
        println!(
            "{{\"command\":\"daemon.{mode_name}\",\"status\":\"ok\",\"stop_reason\":\"{stop_reason}\",\"tun\":\"{}\",\"local_vip\":\"{}\",\"peer_vip\":\"{}\",\"security_mode\":\"e2e-required\",\"suite\":\"pq768\",\"tx_packets\":{},\"tx_bytes\":{},\"rx_packets\":{},\"rx_bytes\":{},\"failover_events\":{},\"path_epoch\":{}}}",
            tun.name(),
            report.local_vip,
            report.peer_vip,
            stats.outbound_packets,
            stats.outbound_bytes,
            stats.inbound_packets,
            stats.inbound_bytes,
            failover_events,
            path_epoch
        );
    }

    // --- standby path (same Core, alternate ingress) ------------------------

    /// Everything the standby dial thread needs. Immutable, so it is shared by
    /// reference instead of rebuilt per attempt.
    #[derive(Clone)]
    struct StandbyConfig {
        /// Configured endpoint spelling, used only in diagnostics.
        endpoint: String,
        /// Fully resolved target. Resolution happens on the manager-owning thread
        /// before the worker starts: a blocking resolver must never sit between
        /// `close()`/`Drop` and its bounded join.
        target: ClientTarget,
        mat_dir: PathBuf,
        key_path: PathBuf,
        policy: SessionPolicy,
        expected_peer: PeerIdentity,
        extractor: Arc<PkiIdentityExtractor>,
        /// Fixed signed-policy window captured at startup.
        policy_window: PolicyWindow,
        /// The process-wide durable store is shared, never reopened, so every
        /// standby dial and every promotion is gated through the same instance.
        status_store: Arc<Mutex<StatusStore>>,
        status_path: PathBuf,
    }

    struct StandbyShared {
        config: StandbyConfig,
        budget: Arc<ConnectionBudget>,
        counters: Arc<LiveCounters>,
        slot: Arc<Mutex<Option<HopLink>>>,
        /// Single-flight: at most one standby dial in flight at any moment.
        dialing: Arc<AtomicBool>,
        /// Set once by `StandbyManager::close`; no dial may start afterwards.
        stop: Arc<AtomicBool>,
        /// Interrupt handle for the *in-flight* dial only.
        ///
        /// It is a duplicate descriptor of the socket being handshaked, so
        /// shutdown can reach that socket without ever naming a closed or
        /// recycled raw fd, and the duplicate keeps the fd number alive for as
        /// long as the handle is held. The dial thread retires the handle before
        /// a session can be published, so a published standby is never
        /// interrupted by cleanup.
        interrupt: Arc<Mutex<Option<std::net::TcpStream>>>,
        /// Monotonic attempt sequence; never rewinds.
        attempts: Arc<AtomicU64>,
        /// Consecutive failures (transport dial failures plus lost sessions).
        misses: Arc<AtomicU64>,
        /// Monotonic transport-liveness poll sequence; never rewinds.
        polls: Arc<AtomicU64>,
        /// Set once on a protocol/identity rejection. Such a rejection is not an
        /// ordinary transport miss: the endpoint is never dialled again and can
        /// never be promoted.
        rejected: Arc<AtomicBool>,
        /// First terminal rejection reason, for the fail-closed error path.
        fatal: Arc<Mutex<Option<String>>>,
    }

    /// Whether the standby path should start a new authenticated dial.
    ///
    /// Kept as one predicate so "stopped" and "already dialling" can never be
    /// forgotten by a caller, and so the rule is testable without a socket.
    fn should_dial(
        now: Instant,
        next_attempt: Instant,
        ready: bool,
        dialing: bool,
        stopped: bool,
    ) -> bool {
        !stopped && !dialing && !ready && now >= next_attempt
    }

    /// Publish a verified standby link at most once.
    ///
    /// The slot and the published flag are updated under the same lock, so a
    /// concurrent [`take_standby_slot`] can never leave `ready == true` with an
    /// empty slot (the previous publisher race). A session that is already held
    /// is never replaced: the new link is returned to the caller and dropped.
    fn publish_standby_slot<T>(slot: &Mutex<Option<T>>, ready: &AtomicBool, value: T) -> Option<T> {
        let mut guard = lock_mutex(slot);
        if guard.is_some() {
            return Some(value);
        }
        *guard = Some(value);
        ready.store(true, Ordering::SeqCst);
        None
    }

    /// Take a held standby link and clear its published flag atomically.
    fn take_standby_slot<T>(slot: &Mutex<Option<T>>, ready: &AtomicBool) -> Option<T> {
        let mut guard = lock_mutex(slot);
        let taken = guard.take();
        if taken.is_some() {
            ready.store(false, Ordering::SeqCst);
        }
        taken
    }

    /// Drop any held link and always clear the published flag.
    fn clear_standby_slot<T>(slot: &Mutex<Option<T>>, ready: &AtomicBool) {
        let mut guard = lock_mutex(slot);
        let _ = guard.take();
        ready.store(false, Ordering::SeqCst);
    }

    /// Mark this standby endpoint terminally rejected.
    ///
    /// Protocol, policy and identity failures are not interchangeable with a
    /// transport miss: retrying them would treat an authentication failure as an
    /// ordinary failover candidate. The active business path is left alone, but
    /// this standby can never become ready or be promoted.
    fn reject_standby(shared: &StandbyShared, reason: String) {
        shared.rejected.store(true, Ordering::SeqCst);
        shared
            .counters
            .standby_rejected
            .store(true, Ordering::SeqCst);
        clear_standby_slot(&shared.slot, &shared.counters.standby_ready);
        let mut fatal = lock_mutex(&shared.fatal);
        if fatal.is_none() {
            *fatal = Some(reason);
        }
    }

    /// Retires the in-flight interrupt handle on every exit path of a dial.
    ///
    /// Declared after the socket handle so the guard runs *before* the socket it
    /// duplicates is dropped: cleanup can therefore never shut down a raw fd that
    /// has already been closed, and the duplicate descriptor keeps the fd number
    /// reserved until this guard releases it.
    struct InterruptGuard<'a> {
        shared: &'a StandbyShared,
    }

    impl Drop for InterruptGuard<'_> {
        fn drop(&mut self) {
            drop(lock_mutex(&self.shared.interrupt).take());
        }
    }

    /// One standby-dial failure, split by trust meaning.
    enum StandbyDialFailure {
        /// Pre-authentication transport failure. A later bounded retry is allowed.
        Transport,
        /// Protocol, policy or identity rejection. Retrying it would treat an
        /// authentication failure as an ordinary failover candidate.
        Protocol(String),
        /// The manager stopped the dial; nothing may be counted or published.
        Stopped,
    }

    /// Classify a hop-handshake error without ever looking at the peer identity.
    ///
    /// Only raw I/O, timeout and clean-transport-close errors are retryable
    /// transport failures. WSS framing, HTTP, session authorization, inner-TLS
    /// policy and identity mapping errors are terminal for this standby path.
    fn classify_tunnel_failure(error: TunnelError) -> StandbyDialFailure {
        match error {
            TunnelError::Io(_)
            | TunnelError::Timeout
            | TunnelError::Closed
            | TunnelError::Ws(boreas_tunnel::ws::WsError::Io(_))
            | TunnelError::Ws(boreas_tunnel::ws::WsError::Timeout)
            | TunnelError::Ws(boreas_tunnel::ws::WsError::Closed) => StandbyDialFailure::Transport,
            other => StandbyDialFailure::Protocol(format!(
                "standby: hop protocol/identity rejected: {other:?}"
            )),
        }
    }

    /// One bounded standby dial: TCP, outer TLS, WSS, inner pq768 hop session and
    /// the peer identity binding. The result is a fully authenticated link to the
    /// same Core over the alternate ingress.
    ///
    /// Every dial is gated through the process-wide durable status store before
    /// the TCP connect and again after the handshake. The target is already
    /// resolved, so neither this worker nor `close()`'s join can wait on DNS.
    fn dial_standby_link(
        shared: &StandbyShared,
        permit: ConnectionPermit,
    ) -> Result<HopLink, StandbyDialFailure> {
        let config = &shared.config;
        if shared.stop.load(Ordering::SeqCst) {
            return Err(StandbyDialFailure::Stopped);
        }
        config.policy_window.check().map_err(|e| {
            StandbyDialFailure::Protocol(format!(
                "standby {}: policy window failed before dial: {e}",
                config.endpoint
            ))
        })?;
        lock_gate(&config.status_store, &config.status_path).map_err(|e| {
            StandbyDialFailure::Protocol(format!(
                "standby {}: durable status gate failed before dial: {e}",
                config.endpoint
            ))
        })?;

        let outer_ca_path = config.mat_dir.join("outer-ca.pem");
        let outer = if outer_ca_path.exists() {
            let pem = fs::read(&outer_ca_path).map_err(|_| {
                StandbyDialFailure::Protocol("standby: cannot read outer-ca.pem".to_string())
            })?;
            OpenSslOuterTlsConnector::with_root_certificates(&pem).map_err(|_| {
                StandbyDialFailure::Protocol("standby: invalid outer-ca.pem".to_string())
            })?
        } else {
            OpenSslOuterTlsConnector::web_pki().map_err(|_| {
                StandbyDialFailure::Protocol("standby: web-PKI roots unavailable".to_string())
            })?
        };
        let inner = OpenSslConnector::from_pem_files(
            config.mat_dir.join("identity.pem"),
            &config.key_path,
            config.mat_dir.join("identity-ca.pem"),
            Policy::production_default(),
        )
        .map_err(|_| {
            StandbyDialFailure::Protocol("standby: pq768 inner connector setup failed".to_string())
        })?;
        let link = LinkClient::new(
            Box::new(outer),
            Box::new(OpenSslInnerConnector::new(
                inner,
                Arc::clone(&config.extractor) as Arc<dyn PeerIdentityExtractor>,
            )),
        );
        let tcp = link
            .connect_tcp(&config.target, HANDSHAKE_TIMEOUT)
            .map_err(|_| StandbyDialFailure::Transport)?;
        config.policy_window.check().map_err(|e| {
            StandbyDialFailure::Protocol(format!(
                "standby {}: policy window failed after TCP connect: {e}",
                config.endpoint
            ))
        })?;
        let fd = tcp.as_raw_fd();
        // The handshake budget is the crate's single deadline. This handle exists
        // only so `close()` can interrupt it; it is not a second deadline. It is a
        // duplicated descriptor, so shutdown can never name the dial's reused fd.
        let interrupt = tcp.try_clone().map_err(|_| StandbyDialFailure::Transport)?;
        *lock_mutex(&shared.interrupt) = Some(interrupt);
        let _interrupt = InterruptGuard { shared };
        if shared.stop.load(Ordering::SeqCst) {
            // `close()` may have raced this install: interrupt our own dial here
            // so the join it is already waiting on returns promptly.
            if let Some(stream) = lock_mutex(&shared.interrupt).take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            return Err(StandbyDialFailure::Stopped);
        }
        let session = link
            .connect_preconnected(tcp, &config.target, config.policy.clone())
            .map_err(classify_tunnel_failure)?;
        config.policy_window.check().map_err(|e| {
            StandbyDialFailure::Protocol(format!(
                "standby {}: policy window failed after hop handshake: {e}",
                config.endpoint
            ))
        })?;
        lock_gate(&config.status_store, &config.status_path).map_err(|e| {
            StandbyDialFailure::Protocol(format!(
                "standby: durable status gate failed after hop handshake: {e}"
            ))
        })?;
        // This session owns its socket from here on, so the interruptible window
        // is closed *before* the caller can publish it.
        drop(lock_mutex(&shared.interrupt).take());
        if shared.stop.load(Ordering::SeqCst) {
            return Err(StandbyDialFailure::Stopped);
        }
        // Defense in depth: the session policy already pins this identity, and a
        // second Core cannot present a certificate whose SPKI is in the pinned
        // trust store. Refuse rather than trust the configured endpoint.
        if session.peer() != config.expected_peer {
            return Err(StandbyDialFailure::Protocol(
                "standby: authenticated peer is not the configured Core".to_string(),
            ));
        }
        Ok(HopLink {
            session,
            fd,
            _permit: permit,
        })
    }

    fn standby_dial(shared: Arc<StandbyShared>) {
        /// Clears the single-flight flag on every exit path, including a panic.
        struct DialGuard(Arc<AtomicBool>);
        impl Drop for DialGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = DialGuard(Arc::clone(&shared.dialing));
        if shared.stop.load(Ordering::SeqCst) || shared.rejected.load(Ordering::SeqCst) {
            return;
        }
        let attempt = shared.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        shared
            .counters
            .standby_attempts
            .store(attempt, Ordering::SeqCst);
        let Some(permit) = shared.budget.try_acquire() else {
            shared.misses.fetch_add(1, Ordering::SeqCst);
            return;
        };
        let link = match dial_standby_link(&shared, permit) {
            Ok(link) => link,
            Err(StandbyDialFailure::Stopped) => return,
            Err(StandbyDialFailure::Transport) => {
                let misses = shared.misses.fetch_add(1, Ordering::SeqCst) + 1;
                shared
                    .counters
                    .standby_failures
                    .store(misses, Ordering::SeqCst);
                shared.counters.standby_ready.store(false, Ordering::SeqCst);
                return;
            }
            Err(StandbyDialFailure::Protocol(reason)) => {
                let misses = shared.misses.fetch_add(1, Ordering::SeqCst) + 1;
                shared
                    .counters
                    .standby_failures
                    .store(misses, Ordering::SeqCst);
                reject_standby(&shared, reason);
                return;
            }
        };
        if shared.stop.load(Ordering::SeqCst) || shared.rejected.load(Ordering::SeqCst) {
            return;
        }
        let published = publish_standby_slot(&shared.slot, &shared.counters.standby_ready, link);
        if published.is_some() {
            // A verified session was already held; keep it and drop this one.
            return;
        }
        shared.misses.store(0, Ordering::SeqCst);
        shared.counters.standby_failures.store(0, Ordering::SeqCst);
    }

    /// Owner-side handle for the standby path of one `connect` process.
    ///
    /// The session is owned by the dial thread until it is published, then by
    /// this handle. Promotion takes it out of the slot, so no thread ever polls a
    /// descriptor that another owner has already dropped.
    ///
    /// The dial worker is **owned, never detached**: exactly one handle is kept
    /// here, a finished one is reaped before the next spawn, and [`Self::close`]
    /// interrupts the in-flight handshake and joins before the manager can go
    /// away. That is the whole reason no socket can be created after
    /// `run_connect_loop` returns.
    struct StandbyManager {
        shared: Arc<StandbyShared>,
        worker: Option<thread::JoinHandle<()>>,
        next_attempt: Instant,
        last_poll: Instant,
    }

    impl StandbyManager {
        fn new(
            config: StandbyConfig,
            budget: Arc<ConnectionBudget>,
            counters: Arc<LiveCounters>,
        ) -> Self {
            Self {
                shared: Arc::new(StandbyShared {
                    config,
                    budget,
                    counters,
                    slot: Arc::new(Mutex::new(None)),
                    dialing: Arc::new(AtomicBool::new(false)),
                    stop: Arc::new(AtomicBool::new(false)),
                    interrupt: Arc::new(Mutex::new(None)),
                    attempts: Arc::new(AtomicU64::new(0)),
                    misses: Arc::new(AtomicU64::new(0)),
                    polls: Arc::new(AtomicU64::new(0)),
                    rejected: Arc::new(AtomicBool::new(false)),
                    fatal: Arc::new(Mutex::new(None)),
                }),
                worker: None,
                next_attempt: Instant::now(),
                last_poll: Instant::now(),
            }
        }

        /// Rejoin the previous dial worker before starting a new one.
        ///
        /// The single-flight flag is cleared by a guard that runs only when the
        /// worker body has returned, so a clear `dialing` flag means this join
        /// cannot block on network work. It exists so a `JoinHandle` is never
        /// dropped while still detached: at most one worker is ever alive, and
        /// `close` joins the last one.
        fn join_previous_worker(&mut self) {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }

        /// Stop dialling, interrupt an in-flight handshake, and wait for the
        /// worker to exit.
        ///
        /// Idempotent. After it returns, no thread of this manager can still run,
        /// so no socket or descriptor is created or held on its behalf. The wait
        /// is bounded by the dial's own single budget (`HANDSHAKE_TIMEOUT`): the
        /// duplicated descriptor covers the whole handshake, and the only step
        /// with no interruptible descriptor yet is the TCP connect itself. DNS
        /// resolution happened before this manager was created, so the join never
        /// sits in a resolver.
        fn close(&mut self) {
            self.shared.stop.store(true, Ordering::SeqCst);
            // The duplicate descriptor keeps the dial socket alive, so this
            // shutdown can never name a closed or recycled raw fd.
            if let Some(stream) = lock_mutex(&self.shared.interrupt).take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            clear_standby_slot(&self.shared.slot, &self.shared.counters.standby_ready);
        }

        /// Whether a verified standby session is currently held.
        fn is_ready(&self) -> bool {
            lock_mutex(&self.shared.slot).is_some()
        }

        /// First terminal protocol/identity rejection, if any.
        fn rejection(&self) -> Option<String> {
            let fatal = lock_mutex(&self.shared.fatal);
            (*fatal).clone()
        }

        /// Take the held standby session for promotion.
        fn take(&mut self) -> Option<HopLink> {
            take_standby_slot(&self.shared.slot, &self.shared.counters.standby_ready)
        }

        /// One bounded, non-blocking maintenance step.
        ///
        /// A held session gets exactly one transport-liveness poll per
        /// `STANDBY_POLL_INTERVAL`; the poll counter is strictly increasing and
        /// never rewinds. A lost transport is replaced by a fresh authenticated
        /// dial after `STANDBY_DIAL_BACKOFF`; consecutive transport failures
        /// beyond `STANDBY_FAIL_THRESHOLD` stay visible through `ctl status`.
        fn maintain(&mut self, now: Instant) {
            if self.shared.rejected.load(Ordering::SeqCst) {
                self.shared
                    .counters
                    .standby_ready
                    .store(false, Ordering::SeqCst);
                return;
            }
            match self.poll_health(now) {
                Some(SocketHealth::Alive) => {
                    self.shared.misses.store(0, Ordering::SeqCst);
                    self.shared
                        .counters
                        .standby_failures
                        .store(0, Ordering::SeqCst);
                    self.shared
                        .counters
                        .standby_ready
                        .store(true, Ordering::SeqCst);
                }
                Some(SocketHealth::Unread) => {
                    // An authenticated path that carries no circuit must not
                    // produce bytes. Treat that as a protocol violation, not as an
                    // ordinary transport miss that may be retried into failover.
                    drop(self.take());
                    reject_standby(
                        &self.shared,
                        "standby: unexpected bytes on an idle standby link (protocol violation)"
                            .to_string(),
                    );
                }
                Some(_) => {
                    // FIN/RST/POLLERR at the transport layer: drop the link and
                    // re-authenticate after the bounded backoff.
                    drop(self.take());
                    let misses = self.shared.misses.fetch_add(1, Ordering::SeqCst) + 1;
                    self.shared
                        .counters
                        .standby_failures
                        .store(misses, Ordering::SeqCst);
                    self.shared
                        .counters
                        .standby_ready
                        .store(false, Ordering::SeqCst);
                    self.next_attempt = now + STANDBY_DIAL_BACKOFF;
                }
                None => {}
            }
            if should_dial(
                now,
                self.next_attempt,
                self.is_ready(),
                self.shared.dialing.load(Ordering::SeqCst),
                self.shared.stop.load(Ordering::SeqCst),
            ) && !self.shared.dialing.swap(true, Ordering::SeqCst)
            {
                self.join_previous_worker();
                let shared = Arc::clone(&self.shared);
                // Stored, never detached: `close` joins it.
                self.worker = Some(thread::spawn(move || standby_dial(shared)));
            }
        }

        /// One monotonic transport-liveness poll, at most once per interval.
        ///
        /// This is `poll(2)` readiness only. It is not a `ProbePing`: it sends no
        /// random challenge and never matches a `Pong`.
        fn poll_health(&mut self, now: Instant) -> Option<SocketHealth> {
            if now.saturating_duration_since(self.last_poll) < STANDBY_POLL_INTERVAL {
                return None;
            }
            let fd = {
                let slot = lock_mutex(&self.shared.slot);
                slot.as_ref().map(|link| link.fd)
            }?;
            self.last_poll = now;
            let polls = self.shared.polls.fetch_add(1, Ordering::SeqCst) + 1;
            self.shared
                .counters
                .standby_polls
                .store(polls, Ordering::SeqCst);
            Some(socket_health(fd))
        }

        /// Bounded wait for a standby session before a failover verdict.
        ///
        /// It waits only while a dial is actually in flight: with no dial
        /// outstanding nothing can become ready, so answering immediately is the
        /// honest result rather than a sleep that pretends to recover.
        fn wait_ready(&mut self, budget: Duration) -> bool {
            if self.shared.rejected.load(Ordering::SeqCst) {
                return false;
            }
            let deadline = Instant::now() + budget;
            loop {
                if self.is_ready() {
                    return true;
                }
                if self.shared.rejected.load(Ordering::SeqCst)
                    || !self.shared.dialing.load(Ordering::SeqCst)
                    || Instant::now() >= deadline
                {
                    return false;
                }
                thread::sleep(Duration::from_millis(5));
                self.maintain(Instant::now());
            }
        }
    }

    impl Drop for StandbyManager {
        fn drop(&mut self) {
            // Every exit path, including a panic, waits for the worker instead of
            // leaving a detached thread that could still dial and own sockets.
            self.close();
        }
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

    /// Bind the exact root bundle used to construct the durable status verifier
    /// to the fingerprint from identity verification. The path was read once
    /// for identity; checking that earlier fingerprint alone would not bind
    /// a second read used to build status trust.
    fn bound_status_trust(
        roots_path: &Path,
        net_id: [u8; 16],
        expected_root_fingerprint: [u8; 32],
        now_us: u64,
    ) -> Result<ManagementTrust, String> {
        // The provisioning material reader caps roots.cbor at 64 KiB.
        const MAX_ROOTS_FILE_BYTES: usize = 64 * 1024;
        let mut raw = Vec::new();
        fs::File::open(roots_path)
            .and_then(|file| file.take(MAX_ROOTS_FILE_BYTES as u64 + 1).read_to_end(&mut raw))
            .map_err(|_| "daemon: cannot read status trust root bundle".to_string())?;
        if raw.len() > MAX_ROOTS_FILE_BYTES {
            return Err("daemon: status trust root bundle exceeds size limit".to_string());
        }
        let (fingerprint, authorizations) = RootsBundle::decode(&raw)
            .and_then(|bundle| bundle.verify_all(net_id, now_us))
            .map_err(|e| format!("daemon: status trust from roots failed: {e}"))?;
        if fingerprint != expected_root_fingerprint {
            return Err("daemon: status NetworkRoot fingerprint does not match identity".to_string());
        }
        let mut trust = ManagementTrust::new(net_id);
        let mut has_status = false;
        for authorization in authorizations {
            has_status |= authorization.issuer_record().authority == Authority::StatusSigner;
            trust
                .add_verified_issuer(&authorization)
                .map_err(|e| format!("daemon: status trust issuer rejected: {e}"))?;
        }
        if !has_status {
            return Err("daemon: status trust missing authorized StatusSigner".to_string());
        }
        Ok(trust)
    }

    /// One fail-closed status decision at a business admission boundary.
    ///
    /// Every gate reads and verifies the exact current `status.signed` bytes
    /// through the durable store. A lower sequence is a hard
    /// `SequenceNotIncreasing` error, never a reason to silently keep using the
    /// persisted snapshot. A duplicate at the same sequence returns
    /// `DuplicateNotRenewed`; the store keeps the original monotonic deadline.
    /// Non-empty revocation bytes are rejected by the store until a real
    /// decoder and handle-cleanup path exist.
    fn status_gate(
        store: &mut StatusStore,
        status_path: &Path,
        trusted_utc_us: u64,
        mono_now: Instant,
    ) -> Result<(u64, Instant), String> {
        let raw = read_status_snapshot_raw(status_path)
            .map_err(|e| format!("status file read failed: {e}"))?;
        store
            .accept_signed_snapshot(&raw, trusted_utc_us, mono_now)
            .map_err(|e| format!("status snapshot rejected: {e:?}"))?;
        let fresh = store
            .current_fresh(trusted_utc_us, mono_now)
            .map_err(|e| format!("status not fresh: {e:?}"))?;
        fresh
            .check(trusted_utc_us, mono_now)
            .map_err(|e| format!("status check failed: {e:?}"))?;
        Ok((fresh.sequence(), fresh.deadline()))
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
        let mut status_state_file: Option<PathBuf> = None;
        let mut status_state_owner_uid: Option<u32> = None;
        let mut policy_tbs: Option<PathBuf> = None;
        let mut policy_ed_sig: Option<PathBuf> = None;
        let mut policy_pq_sig: Option<PathBuf> = None;
        let mut policy_root_ed: Option<PathBuf> = None;
        let mut policy_root_pq: Option<PathBuf> = None;
        let mut policy_state_file: Option<PathBuf> = None;
        let mut policy_state_owner_uid: Option<u32> = None;

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
                        "--status-state-file" => {
                            status_state_file = Some(PathBuf::from(val));
                        }
                        "--status-state-owner-uid" => {
                            status_state_owner_uid = Some(val.parse::<u32>().map_err(|_| {
                                "daemon: invalid --status-state-owner-uid".to_string()
                            })?);
                        }
                        "--network-policy-tbs" => policy_tbs = Some(PathBuf::from(val)),
                        "--network-policy-ed25519-signature" => {
                            policy_ed_sig = Some(PathBuf::from(val));
                        }
                        "--network-policy-mldsa65-signature" => {
                            policy_pq_sig = Some(PathBuf::from(val));
                        }
                        "--network-root-ed25519-der" => {
                            policy_root_ed = Some(PathBuf::from(val));
                        }
                        "--network-root-mldsa65-der" => {
                            policy_root_pq = Some(PathBuf::from(val));
                        }
                        "--network-policy-state-file" => {
                            policy_state_file = Some(PathBuf::from(val));
                        }
                        "--network-policy-state-owner-uid" => {
                            policy_state_owner_uid = Some(val.parse::<u32>().map_err(|_| {
                                "daemon: invalid --network-policy-state-owner-uid".to_string()
                            })?);
                        }
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

        // Business forwarding is never allowed without an explicit durable
        // status binding. There is no flag combination that silently falls
        // back to the old path-only watchdog.
        let (status_state_file, status_state_owner_uid) = match (
            status_state_file,
            status_state_owner_uid,
        ) {
            (Some(file), Some(owner)) => (file, owner),
            _ => {
                return Err(
                        "daemon: `--status-state-file <ABS>` and `--status-state-owner-uid <UID>` are required for durable, fail-closed status"
                            .to_string(),
                    );
            }
        };
        if !status_state_file.is_absolute() || status_state_file.file_name().is_none() {
            return Err("daemon: `--status-state-file` must be an absolute file path".to_string());
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
        let status_trust = bound_status_trust(
            &roots_path,
            cfg_net_id,
            verified.root_fingerprint,
            now_utc_us()?,
        )?;

        // The default overlay now also requires a separately pinned, dual-signed
        // policy plus durable anti-rollback state. This helper accepts no raw
        // caller prefix and currently returns only the default runtime prefix.
        // Missing inputs fail closed rather than selecting legacy/unbound data.
        fn required_policy_input(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
            value.ok_or_else(|| format!("daemon: `{flag}` is required for policy-bound runtime"))
        }
        let policy_tbs_path = required_policy_input(policy_tbs, "--network-policy-tbs")?;
        let policy_ed_sig_path =
            required_policy_input(policy_ed_sig, "--network-policy-ed25519-signature")?;
        let policy_pq_sig_path =
            required_policy_input(policy_pq_sig, "--network-policy-mldsa65-signature")?;
        let policy_root_ed_path =
            required_policy_input(policy_root_ed, "--network-root-ed25519-der")?;
        let policy_root_pq_path =
            required_policy_input(policy_root_pq, "--network-root-mldsa65-der")?;
        let policy_state_path =
            required_policy_input(policy_state_file, "--network-policy-state-file")?;
        let policy_inputs = crate::network_policy_runtime::PolicyInputPaths {
            tbs: &policy_tbs_path,
            ed25519_signature: &policy_ed_sig_path,
            mldsa65_signature: &policy_pq_sig_path,
            root_ed25519_der: &policy_root_ed_path,
            root_mldsa65_der: &policy_root_pq_path,
        };
        let network_context = crate::network_policy_runtime::verify_and_record_default_policy(
            policy_inputs,
            &policy_state_path,
            &config.paths.state_dir,
            cfg_net_id,
            verified.root_fingerprint,
            policy_state_owner_uid.ok_or_else(|| {
                "daemon: `--network-policy-state-owner-uid` is required".to_string()
            })?,
        )
        .map_err(|error| format!("daemon network policy rejected: {error}"))?;

        // The signed policy is the sole address authority. A config prefix that
        // does not equal the verified context would let a node derive/use an
        // unintended overlay, so reject it before any identity or TUN is created.
        if network_context.net_id() != cfg_net_id {
            return Err(
                "daemon: verified network policy belongs to a different net_id".to_string(),
            );
        }
        let config_prefix = config.network.overlay_prefix.base();
        let signed_prefix = network_context.overlay_base();
        if config_prefix != signed_prefix {
            return Err(format!(
                "daemon: configured overlay_prefix {}.{}.0.0/16 does not match signed policy prefix {}.{}.0.0/16",
                config_prefix[0], config_prefix[1], signed_prefix[0], signed_prefix[1]
            ));
        }
        // Capture the signed window exactly once. It is checked at every dial,
        // handshake, promotion and packet-loop iteration; it is never widened by
        // a later verification or clock observation.
        let policy_window = PolicyWindow::new(network_context.validity().1)?;

        let local_vn =
            VerifiedNodeIdentity::from_verified_object(&verified.local, &network_context)
                .map_err(|_| "daemon: invalid local VerifiedNodeIdentity".to_string())?;
        let peer_obj = verified
            .peer
            .as_ref()
            .ok_or_else(|| "daemon: `peer.signed` is required".to_string())?;
        let peer_vn = VerifiedNodeIdentity::from_verified_object(peer_obj, &network_context)
            .map_err(|_| "daemon: invalid peer VerifiedNodeIdentity".to_string())?;

        if local_vn.node_id() != config.identity.node_id
            || local_vn.identity_generation() != config.identity.identity_generation
        {
            return Err(
                "daemon: config node_id/identity_generation does not match verified local.signed"
                    .to_string(),
            );
        }

        let local_peer = local_vn.peer_identity();
        let remote_peer = peer_vn.peer_identity();

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
            queue
                .set_nonblocking(true)
                .map_err(|e| format!("daemon Linux TUN O_NONBLOCK failed: {e:?}"))?;
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
            standby_ready: AtomicBool::new(false),
            standby_rejected: AtomicBool::new(false),
            standby_attempts: AtomicU64::new(0),
            standby_polls: AtomicU64::new(0),
            standby_failures: AtomicU64::new(0),
            failover_events: AtomicU64::new(0),
            path_epoch: AtomicU64::new(0),
            active_path: AtomicU8::new(PATH_PRIMARY),
        });
        let _ctl_guard = start_control_socket(&config.paths.state_dir, Arc::clone(&counters))?;

        // The durable status store is a process-wide singleton: open it once,
        // before any accept/connect handshake, and keep it until the watchdog
        // thread exits. A second StatusStore::open on the same path would
        // return Busy from the adjacent .lock.
        let canonical_state_dir = fs::canonicalize(&config.paths.state_dir)
            .map_err(|_| "daemon: cannot canonicalize state_dir for status store".to_string())?;
        let status_parent = status_state_file
            .parent()
            .ok_or_else(|| "daemon: --status-state-file has no parent".to_string())?;
        let canonical_status_parent = fs::canonicalize(status_parent)
            .map_err(|_| "daemon: status state parent does not exist".to_string())?;
        if canonical_status_parent != canonical_state_dir {
            return Err(
                "daemon: --status-state-file must be directly under the configured state_dir"
                    .to_string(),
            );
        }
        let mut status_store = StatusStore::open(
            &status_state_file,
            cfg_net_id,
            status_state_owner_uid,
            status_trust,
        )
        .map_err(|e| format!("daemon: durable status store open failed: {e:?}"))?;
        let status_path = mat_dir.join("status.signed");
        let (gate_seq, _gate_deadline) = status_gate(
            &mut status_store,
            &status_path,
            now_utc_us()?,
            Instant::now(),
        )
        .map_err(|e| format!("daemon: durable status gate failed before business: {e}"))?;
        counters.status_sequence.store(gate_seq, Ordering::SeqCst);
        // One process-wide store instance for every later boundary, including
        // each failover epoch: reopening on the same path would return `Busy`.
        let status_store = Arc::new(Mutex::new(status_store));

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
                &status_path,
                policy_window,
                status_store,
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
                    &config.identity.private_key,
                    extractor,
                    &status_path,
                    policy_window,
                    status_store,
                    inner_conn,
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

    /// Duplicate the connected socket for the watchdog's shutdown handle.
    ///
    /// The duplicate owns its own descriptor and keeps the underlying socket
    /// alive even after the packet path drops the original stream. The watchdog
    /// therefore never calls `shutdown(2)` on a raw number whose original owner
    /// has already closed it (and whose number could have been reused). A
    /// close-on-exec duplicate is used so the descriptor cannot leak into a
    /// future exec.
    fn duplicate_shutdown_fd(fd: i32) -> Option<OwnedFd> {
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is an open socket owned by the caller; `F_DUPFD_CLOEXEC`
        // returns a new owned descriptor or -1. `OwnedFd::from_raw_fd` then takes
        // ownership of that new descriptor exactly once.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return None;
        }
        Some(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    /// §3.4 `StatusSnapshot` freshness watchdog plus signed-policy expiry guard.
    ///
    /// The 500 ms re-check checks the fixed signed-policy window and reads and
    /// verifies `status.signed` through the process-wide durable store, so it
    /// cannot live on the packet loop: a blocking read/verification would stall
    /// it past the deadline. This thread runs [`status_gate`], publishes the
    /// first failure as an owned string, and interrupts any in-flight blocking
    /// I/O with `shutdown(SHUT_RDWR)` through an owned duplicate of the outer
    /// socket, so a concurrently closed original descriptor cannot be reused
    /// underneath the shutdown.
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
            store: Arc<Mutex<StatusStore>>,
            status_path: PathBuf,
            policy_window: PolicyWindow,
            sock_fd: i32,
            counters: Arc<LiveCounters>,
            interval: Duration,
            revocations: Arc<Mutex<crate::daemon_revoke::RevocationSet>>,
        ) -> Self {
            let stop = Arc::new((Mutex::new(()), Condvar::new()));
            let stopped = Arc::new(AtomicBool::new(false));
            let fault: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let stop_bg = Arc::clone(&stop);
            let stopped_bg = Arc::clone(&stopped);
            let fault_bg = Arc::clone(&fault);
            // Capture an owned duplicate now, while the caller's session is
            // still alive. The worker uses only this duplicate, never `sock_fd`.
            let shutdown_fd = duplicate_shutdown_fd(sock_fd);
            let handle = thread::spawn(move || {
                // First check is immediate: business may already have started
                // when this watchdog is constructed; a 500 ms grace period
                // would be an unprotected forwarding window.
                let mut deadline = Instant::now();
                loop {
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

                    let failure = if let Err(reason) = policy_window.check() {
                        Some(reason)
                    } else {
                        match now_utc_us() {
                        Err(_) => Some(
                            "daemon: StatusSnapshot clock unavailable (system clock before UNIX_EPOCH)"
                                .to_string(),
                        ),
                        Ok(now_us) => {
                            // The store lock is held only for the verification;
                            // business boundaries that also gate on it are on the
                            // same thread as the loop this watchdog interrupts.
                            let mut store_guard = lock_mutex(&store);
                            match status_gate(
                                &mut store_guard,
                                &status_path,
                                now_us,
                                Instant::now(),
                            ) {
                                Ok((seq, status_deadline)) => {
                                    let prev = counters.status_sequence.load(Ordering::Relaxed);
                                    if seq < prev {
                                        Some(format!(
                                            "daemon: StatusSnapshot sequence rollback detected (fail-closed): {seq} < {prev}"
                                        ))
                                    } else {
                                        counters.status_sequence.store(seq, Ordering::Relaxed);
                                        // Publish only scopes from the snapshot the store
                                        // just verified. A rejected snapshot never reaches
                                        // here, so it cannot change the revocation set.
                                        let scopes = store_guard.revocation_scopes();
                                        lock_mutex(&revocations).sync_verified_scopes(&scopes);
                                        // Do not sleep past the captured freshness
                                        // deadline; the normal 500 ms cadence must
                                        // never become a post-expiry forwarding window.
                                        deadline = (Instant::now() + interval)
                                            .min(status_deadline)
                                            .min(policy_window.deadline());
                                        None
                                    }
                                }
                                Err(error) => Some(format!(
                                    "daemon: StatusSnapshot stale or invalid, business forwarding halted (§3.4): {error}"
                                )),
                            }
                        }
                    }
                    };
                    let Some(message) = failure else {
                        // `status_gate` already set the next deadline to
                        // min(now + interval, captured freshness deadline).
                        continue;
                    };
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
                    if let Some(fd) = shutdown_fd.as_ref() {
                        // SAFETY: `fd` is an owned duplicate of the connected
                        // outer socket. It keeps the socket alive even if the
                        // packet path has already dropped the original stream, so
                        // this can never target a closed/reused descriptor.
                        unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
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
        status_path: &Path,
        policy_window: PolicyWindow,
        status_store: Arc<Mutex<StatusStore>>,
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

        // Status and the signed policy window must still be fresh at the last
        // boundary before an untrusted peer is accepted.
        policy_window
            .check()
            .map_err(|e| format!("daemon serve: policy window failed before accept: {e}"))?;
        lock_gate(&status_store, status_path)
            .map_err(|e| format!("daemon serve: durable status gate failed before accept: {e}"))?;

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
                    policy_window.check().map_err(|e| {
                        format!("daemon serve: policy window failed while waiting for peer: {e}")
                    })?;
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
        policy_window
            .check()
            .map_err(|e| format!("daemon serve: policy window failed after accept: {e}"))?;

        let admission = Admission::new(Limits {
            handshakes_global: 8,
            authenticated_global: 8,
            authenticated_per_peer: 2,
            bytes_global: 16 * 1024 * 1024,
        });
        let link_server =
            LinkServer::new(Box::new(OpenSslInnerAcceptor::new(inner_acc, extractor)));
        // `HANDSHAKE_TIMEOUT` is the crate's one absolute budget for this
        // exchange; the daemon installs no second deadline on the same socket.
        let mut accepted = link_server
            .accept_tls_stream(
                tcp,
                &outer_acc,
                session_policy,
                HANDSHAKE_TIMEOUT,
                &admission,
            )
            .map_err(|e| format!("daemon serve: WSS + pq768 hop session rejected: {e}"))?;

        // The peer authenticated, but status or the signed policy may have
        // expired during the blocking handshake. Recheck before running the E2E
        // handshake.
        policy_window
            .check()
            .map_err(|e| format!("daemon serve: policy window failed after hop handshake: {e}"))?;
        lock_gate(&status_store, status_path).map_err(|e| {
            format!("daemon serve: durable status gate failed after hop handshake: {e}")
        })?;

        let e2e = accept_e2e(&mut accepted.session, &e2e_backend, remote_peer)
            .map_err(|e| format!("daemon serve: pq768 E2E circuit rejected: {e}"))?;

        // Last business-admission boundary: a status or policy that expired
        // during E2E handshake must stop before any packet is forwarded.
        policy_window
            .check()
            .map_err(|e| format!("daemon serve: policy window failed before business: {e}"))?;
        lock_gate(&status_store, status_path).map_err(|e| {
            format!("daemon serve: durable status gate failed before business: {e}")
        })?;

        bound_path_io(sock_fd)?;

        counters.inbound_connections.store(1, Ordering::SeqCst);
        counters.path_epoch.store(1, Ordering::SeqCst);
        counters.connected.store(true, Ordering::SeqCst);

        let res = drive_business_path(
            "serve",
            sock_fd,
            tun,
            e2e,
            mtu,
            status_path,
            policy_window,
            Arc::clone(&status_store),
            max_packets,
            0,
            max_seconds.map(|seconds| Instant::now() + Duration::from_secs(seconds)),
            None,
            None,
            counters,
        );

        counters.connected.store(false, Ordering::SeqCst);
        counters.inbound_connections.store(0, Ordering::SeqCst);
        // `serve` has exactly one authenticated peer and no standby path, so a
        // transport failure is terminal here.
        let report = res?;
        let stop_reason = match &report.stop {
            PathStop::Budget(reason) => *reason,
            PathStop::PeerClosed => "peer_closed_cleanly",
            PathStop::Failed { reason, .. } => {
                return Err(format!(
                    "daemon serve: inbound circuit failed (fail-closed): {reason}"
                ));
            }
        };
        print_path_summary("serve", tun, &report, stop_reason, 0, 1);
        Ok(())
    }

    /// Connect, then keep business on one authenticated circuit at a time.
    ///
    /// The initial dial keeps the pre-authorization fallback: only a transport
    /// refusal or timeout on the primary may advance to the backup endpoint, and
    /// a policy or handshake rejection still stops everything. Once business is
    /// running on the primary, the same backup endpoint becomes a *standby path*:
    /// one bounded background dial keeps a fully authenticated session to the same
    /// Core on it, and a transport failure promotes that session by rebuilding the
    /// E2E circuit on it. If the initial dial already fell back to the backup, no
    /// standby is opened to that active endpoint: there is no second ingress, and
    /// its loss is fail-closed.
    ///
    /// What is deliberately not here: a second Core. There is no multi-Core
    /// directory in this tree, so the only authority for a peer identity is the
    /// mounted `peer.signed`, which is pinned into the inner pq768 trust store. A
    /// backup endpoint owned by any other identity cannot complete the handshake,
    /// so the standby never becomes ready and the failure is closed instead of
    /// being "trusted" because configuration named the endpoint.
    ///
    /// Exactly one promotion is allowed: the two configured endpoints are the
    /// whole path set, so after the backup carries business a further loss is
    /// fail-closed rather than a re-dial of the endpoint already in use.
    #[allow(clippy::too_many_arguments)]
    fn run_connect_loop(
        primary_spec: &str,
        backup_spec: Option<&str>,
        tls_name_override: Option<&str>,
        ws_host_override: Option<&str>,
        ws_path: &str,
        mat_dir: &Path,
        key_path: &Path,
        extractor: Arc<PkiIdentityExtractor>,
        status_path: &Path,
        policy_window: PolicyWindow,
        status_store: Arc<Mutex<StatusStore>>,
        inner_conn: OpenSslConnector,
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

        let budget = Arc::new(ConnectionBudget::new());
        let link_client = LinkClient::new(
            Box::new(outer_conn),
            Box::new(OpenSslInnerConnector::new(
                inner_conn,
                Arc::clone(&extractor) as Arc<dyn PeerIdentityExtractor>,
            )),
        );
        let endpoints = connect_endpoints(primary_spec, backup_spec);
        let mut link: Option<(usize, HopLink)> = None;
        for (index, endpoint) in endpoints.iter().enumerate() {
            policy_window
                .check()
                .map_err(|e| format!("daemon connect: policy window failed before dial: {e}"))?;
            lock_gate(&status_store, status_path).map_err(|e| {
                format!("daemon connect: durable status gate failed before dial: {e}")
            })?;
            let target = client_target(endpoint, tls_name_override, ws_host_override, ws_path)?;
            let Some(permit) = budget.try_acquire() else {
                return Err(format!(
                    "daemon connect: bounded live-connection budget exhausted before dial (live={}/{MAX_LIVE_CONNECTIONS})",
                    budget.live()
                ));
            };
            match attempt_endpoint(
                index,
                endpoints.len(),
                || link_client.connect_tcp(&target, HANDSHAKE_TIMEOUT),
                may_try_backup,
            ) {
                Ok(tcp) => {
                    // TCP connect can take time; recheck before spending the
                    // blocking WSS/hop handshake on a stale status or policy.
                    policy_window.check().map_err(|e| {
                        format!("daemon connect: policy window failed after TCP connect: {e}")
                    })?;
                    lock_gate(&status_store, status_path).map_err(|e| {
                        format!("daemon connect: durable status gate failed after TCP connect: {e}")
                    })?;
                    let fd = tcp.as_raw_fd();
                    // One deadline, owned by the transport crate (see the note
                    // above `SocketHealth`): the daemon only supplies the budget.
                    let session = link_client
                        .connect_preconnected(tcp, &target, session_policy.clone())
                        .map_err(|e| {
                            format!("daemon connect: WSS + pq768 hop session rejected: {e}")
                        })?;
                    // Status or policy may have expired during the blocking
                    // handshake.
                    policy_window.check().map_err(|e| {
                        format!("daemon connect: policy window failed after hop handshake: {e}")
                    })?;
                    lock_gate(&status_store, status_path).map_err(|e| {
                        format!(
                            "daemon connect: durable status gate failed after hop handshake: {e}"
                        )
                    })?;
                    counters.active_path.store(
                        if index == 0 {
                            PATH_PRIMARY
                        } else {
                            PATH_BACKUP
                        },
                        Ordering::SeqCst,
                    );
                    link = Some((
                        index,
                        HopLink {
                            session,
                            fd,
                            _permit: permit,
                        },
                    ));
                    break;
                }
                Err(EndpointAttemptError::TryBackup(_error)) => continue,
                Err(EndpointAttemptError::Stop(error)) => {
                    return Err(format!("daemon connect: TCP connect failed: {error}"));
                }
            }
        }
        let (active_index, mut link) =
            link.ok_or_else(|| "daemon connect: no endpoint connected".to_string())?;
        let backup_configured = endpoints.len() > 1;

        // Only a distinct configured backup endpoint gets a standby path, and only
        // while the primary carries business. If the initial dial already fell back
        // to the backup, that endpoint is the active path: opening a standby to it
        // would leave no other ingress and invite a second "promotion" onto the
        // same endpoint.
        let mut standby = if active_index == 0 && backup_configured {
            let endpoint = endpoints[1];
            // Resolve here, on the manager-owning thread. The worker and `close()`
            // join must never block on a resolver with no bound.
            let target = client_target(endpoint, tls_name_override, ws_host_override, ws_path)?;
            Some(StandbyManager::new(
                StandbyConfig {
                    endpoint: endpoint.to_string(),
                    target,
                    mat_dir: mat_dir.to_path_buf(),
                    key_path: key_path.to_path_buf(),
                    policy: session_policy.clone(),
                    expected_peer: remote_peer,
                    extractor: Arc::clone(&extractor),
                    policy_window,
                    status_store: Arc::clone(&status_store),
                    status_path: status_path.to_path_buf(),
                },
                Arc::clone(&budget),
                Arc::clone(counters),
            ))
        } else {
            None
        };

        let business_started = Instant::now();
        let deadline = max_seconds.map(|seconds| business_started + Duration::from_secs(seconds));
        let mut packets_before = 0u64;
        let mut identity: Option<BusinessIdentity> = None;
        let mut failover_events = 0u64;
        let mut epoch = 0u64;

        loop {
            epoch = epoch.saturating_add(1);
            // Re-apply the bound per epoch: a promoted session is a different
            // socket, and it must never run unbounded either.
            bound_path_io(link.fd)?;

            let attempt = {
                // Gate before spending an E2E handshake on this epoch. A promoted
                // session is not exempt: it was admitted only for the status and
                // policy window that were current when its standby dial
                // authenticated.
                policy_window.check().map_err(|e| {
                    format!("daemon connect: policy window failed before E2E circuit: {e}")
                })?;
                lock_gate(&status_store, status_path).map_err(|e| {
                    format!("daemon connect: durable status gate failed before E2E circuit: {e}")
                })?;
                // The circuit borrows this session for the whole epoch, so the
                // standby is a distinct object that this loop only polls.
                let e2e = open_e2e(&mut link.session, &e2e_backend, remote_peer, 1)
                    .map_err(|e| format!("daemon connect: pq768 E2E circuit rejected: {e}"))?;
                // Last business-admission boundary before the packet loop starts.
                lock_gate(&status_store, status_path).map_err(|e| {
                    format!("daemon connect: durable status gate failed before business: {e}")
                })?;
                if epoch > 1 {
                    // The rebuilt circuit has passed the final status/policy
                    // boundary and the E2E handshake. Count it only now, after
                    // the promotion actually reached a business epoch.
                    failover_events = failover_events.saturating_add(1);
                    counters
                        .failover_events
                        .store(failover_events, Ordering::SeqCst);
                    counters.active_path.store(PATH_BACKUP, Ordering::SeqCst);
                }
                counters.path_epoch.store(epoch, Ordering::SeqCst);
                counters.outbound_upstreams.store(1, Ordering::SeqCst);
                counters.connected.store(true, Ordering::SeqCst);
                let result = drive_business_path(
                    "connect",
                    link.fd,
                    tun,
                    e2e,
                    mtu,
                    status_path,
                    policy_window,
                    Arc::clone(&status_store),
                    max_packets,
                    packets_before,
                    deadline,
                    identity,
                    standby.as_mut(),
                    counters,
                );
                counters.connected.store(false, Ordering::SeqCst);
                counters.outbound_upstreams.store(0, Ordering::SeqCst);
                result
            };
            let report = attempt?;
            packets_before = packets_before
                .saturating_add(report.stats.outbound_packets)
                .saturating_add(report.stats.inbound_packets);
            identity = Some(report.identity);
            if let PathStop::Budget(reason) = &report.stop {
                print_path_summary("connect", tun, &report, reason, failover_events, epoch);
                return Ok(());
            }

            // Every promotion boundary is gated through the same durable store
            // instance and the fixed signed-policy window. A status or policy
            // that expired while the packet loop was stopping must not be able to
            // reach a new E2E circuit.
            policy_window.check().map_err(|e| {
                format!("daemon connect: policy window failed before promotion: {e}")
            })?;
            lock_gate(&status_store, status_path).map_err(|e| {
                format!("daemon connect: durable status gate failed before promotion: {e}")
            })?;

            let reason = match &report.stop {
                PathStop::Failed { reason, .. } => reason.clone(),
                _ => "the peer closed the authenticated circuit".to_string(),
            };

            match &report.stop {
                PathStop::PeerClosed
                | PathStop::Failed {
                    kind: PathFailureKind::Transport,
                    ..
                } => {}
                PathStop::Failed {
                    kind: PathFailureKind::Protocol,
                    ..
                } => {
                    return Err(format!(
                        "daemon connect: non-transport protocol/identity failure is terminal, not an ordinary failover trigger (fail-closed): {reason}"
                    ));
                }
                PathStop::Budget(reason) => {
                    print_path_summary("connect", tun, &report, reason, failover_events, epoch);
                    return Ok(());
                }
            }

            // A standby path exists precisely to keep business running when the
            // active ingress goes away, so a clean close is also a promotion
            // trigger. Without a verified standby the close stays terminal, and a
            // hard failure with no standby is fail-closed with its real reason.
            let promoted = {
                let ready = match standby.as_mut() {
                    Some(manager) => manager.wait_ready(STANDBY_READY_WAIT),
                    None => false,
                };
                if ready {
                    // The bounded wait can itself outlive the status/policy
                    // boundary that admitted it. Recheck immediately before
                    // consuming the standby, so a stale admission can never
                    // increment the promotion counter.
                    policy_window.check().map_err(|e| {
                        format!("daemon connect: policy window failed during standby wait: {e}")
                    })?;
                    lock_gate(&status_store, status_path).map_err(|e| {
                        format!(
                            "daemon connect: durable status gate failed during standby wait: {e}"
                        )
                    })?;
                    standby.as_mut().and_then(StandbyManager::take)
                } else {
                    None
                }
            };
            let Some(next) = promoted else {
                // A clean close is a planned stop only when no backup endpoint
                // was configured at all. With one configured, losing the active
                // path while no verified standby is ready is exactly the
                // condition that must be reported, not hidden behind
                // `peer_closed_cleanly`. This also covers an initial fallback
                // that is already on the backup: there is no second ingress left.
                if !backup_configured && matches!(&report.stop, PathStop::PeerClosed) {
                    print_path_summary(
                        "connect",
                        tun,
                        &report,
                        "peer_closed_cleanly",
                        failover_events,
                        epoch,
                    );
                    return Ok(());
                }
                let rejected = standby
                    .as_ref()
                    .and_then(StandbyManager::rejection)
                    .map(|reason| format!("; standby rejected: {reason}"))
                    .unwrap_or_default();
                return Err(format!(
                    "daemon connect: active path failed and no authenticated standby path is ready (fail-closed): {reason}{rejected}"
                ));
            };
            // Replaces (and drops) the failed link, releasing its permit.
            link = next;
            // There is exactly one alternate ingress. Once it carries business
            // there is no third path to keep warm, so a further loss is
            // fail-closed instead of re-dialling the endpoint already in use.
            // Cleanup happens here, at a defined point: stop, interrupt, join.
            if let Some(mut manager) = standby.take() {
                manager.close();
            }
        }
    }

    #[derive(Default)]
    struct PathIoTiming {
        max_outbound_us: u128,
        max_inbound_us: u128,
        outbound_over_1ms: u64,
        inbound_over_1ms: u64,
    }

    impl PathIoTiming {
        fn observe(&mut self, outbound: bool, elapsed: Duration) {
            let us = elapsed.as_micros();
            let (max, stalls) = if outbound {
                (&mut self.max_outbound_us, &mut self.outbound_over_1ms)
            } else {
                (&mut self.max_inbound_us, &mut self.inbound_over_1ms)
            };
            *max = (*max).max(us);
            if us >= 1_000 {
                *stalls = stalls.saturating_add(1);
            }
        }
    }

    impl Drop for PathIoTiming {
        fn drop(&mut self) {
            eprintln!(
                "boreas-io-timing max_outbound_us={} max_inbound_us={} outbound_ge_1ms={} inbound_ge_1ms={}",
                self.max_outbound_us,
                self.max_inbound_us,
                self.outbound_over_1ms,
                self.inbound_over_1ms,
            );
        }
    }

    /// Run the packet loop for one established business path.
    ///
    /// Returns *why* the path stopped, or a terminal failure. A transport
    /// failure is reported rather than retried: only the caller knows whether an
    /// authenticated standby path exists. The path is bound to the circuit it was
    /// given and can never deliver a packet on another one, so one circuit still
    /// carries one FIFO.
    #[allow(clippy::too_many_arguments)]
    fn drive_business_path(
        mode_name: &str,
        sock_fd: i32,
        tun: &TunEndpoint,
        e2e: E2eCircuit<'_>,
        mtu: usize,
        status_path: &Path,
        policy_window: PolicyWindow,
        status_store: Arc<Mutex<StatusStore>>,
        max_packets: Option<u64>,
        packets_before: u64,
        deadline: Option<Instant>,
        expected: Option<BusinessIdentity>,
        mut standby: Option<&mut StandbyManager>,
        counters: &Arc<LiveCounters>,
    ) -> Result<PathReport, String> {
        let mut path = PacketPath::try_new_over_e2e(tun.packet_io(), e2e, mtu)
            .map_err(|e| format!("daemon {mode_name}: PacketPath bind rejected: {e:?}"))?;
        let identity = business_identity(&path);
        if let Some(expected) = expected
            && expected != identity
        {
            path.close();
            return Err(format!(
                "daemon {mode_name}: fail-closed: a standby path must keep the verified peer identity and VIP binding (expected {expected:?}, observed {identity:?})"
            ));
        }
        let local_vip = path.local_endpoint().vip();
        let peer_vip = path.peer_endpoint().vip();

        // Declared after `path` on purpose: the watchdog is stopped and joined
        // before the E2E stream (and its socket) is dropped, so `shutdown()` can
        // never target a recycled descriptor.
        let revocations = Arc::new(Mutex::new(crate::daemon_revoke::RevocationSet::new()));
        let mut revoke_forwarded = 0u64;
        let mut revoke_failures = 0u64;
        let watchdog = StatusWatchdog::start(
            status_store,
            status_path.to_path_buf(),
            policy_window,
            sock_fd,
            Arc::clone(counters),
            STATUS_RECHECK_INTERVAL,
            Arc::clone(&revocations),
        );

        let mut io_timing = (std::env::var_os("BOREAS_DIAGNOSTIC_TIMING").as_deref()
            == Some(std::ffi::OsStr::new("1")))
        .then(PathIoTiming::default);
        let mut last_dropped = 0u64;
        let stop = 'outer: loop {
            // Policy first: an expired signed policy window is a hard stop even
            // when the status snapshot is still fresh.
            if let Err(reason) = policy_window.check() {
                path.close();
                return Err(format!(
                    "daemon {mode_name}: policy window failed during business: {reason}"
                ));
            }
            // Status next: once the watchdog published a failure, business I/O
            // is forbidden and that reason must win over every later symptom.
            if let Some(reason) = watchdog.fault() {
                path.close();
                return Err(reason);
            }

            if let Some(deadline) = deadline
                && Instant::now() >= deadline
            {
                path.close_gracefully();
                break PathStop::Budget("max_seconds_reached");
            }
            if let Some(limit) = max_packets {
                let stats = path.stats();
                let total = packets_before
                    .saturating_add(stats.outbound_packets)
                    .saturating_add(stats.inbound_packets);
                if total >= limit {
                    path.close_gracefully();
                    break PathStop::Budget("max_packets_reached");
                }
            }

            // Standby maintenance is one non-blocking transport poll plus, at
            // most, one background dial. It never blocks this loop and never
            // touches the active circuit; it is not a ProbePing exchange.
            if let Some(manager) = standby.as_deref_mut() {
                manager.maintain(Instant::now());
            }

            // Revocation is checked before either direction forwards. The set is
            // whatever the watchdog published from the last verified snapshot; this
            // lookup does not itself verify a signature.
            let peer_revoked = {
                let set = lock_mutex(&revocations);
                crate::daemon_revoke::poll_peer_forward(
                    &set,
                    identity.peer_node_id,
                    identity.peer_generation,
                    &mut revoke_forwarded,
                    &mut revoke_failures,
                ) == crate::daemon_revoke::ForwardPoll::Revoked
            };
            if peer_revoked {
                path.close();
                break 'outer PathStop::Failed {
                    kind: PathFailureKind::Protocol,
                    reason: format!(
                        "peer node {} generation {} revoked; business path closed before forward",
                        identity.peer_node_id, identity.peer_generation
                    ),
                };
            }

            // Both packet sources are nonblocking here: TUN reads are single-syscall
            // non-blocking reads and idle waiting happens once per iteration.
            // Drain currently ready packets in a single contiguous TLS/WS write
            // (bounded per turn, §6.4: never wait on a coalescing timer) so
            // burst TCP traffic fills full MSS segments instead of splitting
            // 1613 B single-packet records into 1448 + 165 B tail segments.
            // Keep each blocking write and inbound drain small so the opposite
            // direction and the next policy check can run between bursts.
            const MAX_OUTBOUND_BATCH_PACKETS: usize = 16;
            const MAX_OUTBOUND_BATCH_BYTES: usize = 16_000;
            const MAX_INBOUND_BATCH_PACKETS: usize = 32;
            let mut made_progress = false;
            let remaining_budget = max_packets
                .map(|limit| {
                    let stats = path.stats();
                    let total = packets_before
                        .saturating_add(stats.outbound_packets)
                        .saturating_add(stats.inbound_packets);
                    usize::try_from(limit.saturating_sub(total)).unwrap_or(usize::MAX)
                })
                .unwrap_or(MAX_OUTBOUND_BATCH_PACKETS);
            let out_limit = remaining_budget.min(MAX_OUTBOUND_BATCH_PACKETS);
            if out_limit > 0 {
                let started = io_timing.as_ref().map(|_| Instant::now());
                let result = path.step_outbound_batch(out_limit, MAX_OUTBOUND_BATCH_BYTES);
                if let (Some(timing), Some(started)) = (&mut io_timing, started) {
                    timing.observe(true, started.elapsed());
                }
                match result {
                    Ok(drained) if drained > 0 => {
                        made_progress = true;
                        let stats = path.stats();
                        counters
                            .tx_packets
                            .store(stats.outbound_packets, Ordering::Relaxed);
                        counters
                            .tx_bytes
                            .store(stats.outbound_bytes, Ordering::Relaxed);
                    }
                    Ok(_) => {
                        let dropped = path.stats().dropped_outbound;
                        if iteration_progress(false, last_dropped, dropped) {
                            made_progress = true;
                        }
                        last_dropped = dropped;
                    }
                    Err(PacketPathError::Denied(_)) => {
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        return Err(
                            "daemon: outbound packet path rejected a malformed host packet"
                                .to_string(),
                        );
                    }
                    Err(error) => {
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        if host_side_failure(&error) {
                            return Err(format!("daemon: outbound packet path error: {error:?}"));
                        }
                        break 'outer PathStop::Failed {
                            kind: path_failure_kind(&error),
                            reason: format!("outbound circuit error: {error:?}"),
                        };
                    }
                }
            }

            // Raw TCP readiness alone is insufficient: OpenSSL, WebSocket,
            // FrameIo and CircuitStream can all hold bytes after an earlier read.
            // Drain up to MAX_INBOUND_BATCH_PACKETS buffered/ready frames per turn.
            let mut buffered = path.has_buffered_input();
            let mut socket_ready = if buffered {
                false
            } else {
                poll_io(sock_fd, None, Duration::ZERO)?.0
            };
            for step in 0..MAX_INBOUND_BATCH_PACKETS {
                if let Some(reason) = watchdog.fault() {
                    path.close();
                    return Err(reason);
                }
                if let Some(limit) = max_packets {
                    let stats = path.stats();
                    let total = packets_before
                        .saturating_add(stats.outbound_packets)
                        .saturating_add(stats.inbound_packets);
                    if total >= limit {
                        break;
                    }
                }
                if step > 0 {
                    buffered = path.has_buffered_input();
                    socket_ready = if buffered {
                        false
                    } else {
                        poll_io(sock_fd, None, Duration::ZERO)?.0
                    };
                    if !buffered && !socket_ready {
                        break;
                    }
                } else if !buffered && !socket_ready {
                    break;
                }
                let started = io_timing.as_ref().map(|_| Instant::now());
                let result = path.step_inbound();
                if let (Some(timing), Some(started)) = (&mut io_timing, started) {
                    timing.observe(false, started.elapsed());
                }
                match result {
                    Ok(Some(_len)) => {
                        made_progress = true;
                        let stats = path.stats();
                        counters
                            .rx_packets
                            .store(stats.inbound_packets, Ordering::Relaxed);
                        counters
                            .rx_bytes
                            .store(stats.inbound_bytes, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        break 'outer PathStop::PeerClosed;
                    }
                    Err(error) => {
                        if let Some(reason) = watchdog.fault() {
                            path.close();
                            return Err(reason);
                        }
                        if host_side_failure(&error) {
                            return Err(format!("daemon: inbound packet path error: {error:?}"));
                        }
                        break 'outer PathStop::Failed {
                            kind: path_failure_kind(&error),
                            reason: format!("inbound circuit error: {error:?}"),
                        };
                    }
                }
            }
            buffered = path.has_buffered_input();

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
        };

        // A failure that raced in during a graceful budget stop must still be
        // reported: never print `"status":"ok"` for a halted section 3.4 condition.
        if let Some(reason) = watchdog.fault() {
            return Err(reason);
        }

        Ok(PathReport {
            stop,
            identity,
            stats: path.stats(),
            local_vip,
            peer_vip,
        })
    }
    #[cfg(test)]
    mod watchdog_tests {
        use super::*;
        use boreas_pki::{management::ManagementTrust, status_store::StatusStore};
        use std::os::unix::fs::PermissionsExt;

        /// Real Linux durable-store fixture for watchdog tests. The caller owns
        /// the returned directory and removes it after dropping the watchdog.
        fn store_fixture(label: &str) -> (PathBuf, StatusStore) {
            let dir = std::env::temp_dir()
                .join(format!("boreas-watchdog-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create watchdog store dir");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("watchdog store dir 0700");
            let uid = unsafe { libc::geteuid() };
            let store = StatusStore::open(
                dir.join("status.state"),
                [0x2a; 16],
                uid,
                ManagementTrust::new([0x2a; 16]),
            )
            .expect("open watchdog status store");
            (dir, store)
        }

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

        fn policy_window() -> PolicyWindow {
            PolicyWindow::new(now_utc_us().unwrap() + 3_600_000_000).expect("future policy window")
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
                standby_ready: AtomicBool::new(false),
                standby_rejected: AtomicBool::new(false),
                standby_attempts: AtomicU64::new(0),
                standby_polls: AtomicU64::new(0),
                standby_failures: AtomicU64::new(0),
                failover_events: AtomicU64::new(0),
                path_epoch: AtomicU64::new(1),
                active_path: AtomicU8::new(PATH_PRIMARY),
            })
        }

        /// An unusable status file must halt forwarding: the first failure is
        /// published as an owned string and `status_fresh` flips immediately,
        /// without requiring a live socket.
        #[test]
        fn watchdog_publishes_status_failure_and_marks_stale() {
            let counters = counters();
            let (dir, store) = store_fixture("publishes");
            let watchdog = StatusWatchdog::start(
                Arc::new(Mutex::new(store)),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                policy_window(),
                -1,
                Arc::clone(&counters),
                Duration::from_millis(10),
                Arc::new(Mutex::new(crate::daemon_revoke::RevocationSet::new())),
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
            drop(watchdog);
            let _ = fs::remove_dir_all(dir);
        }

        /// The watchdog must hold its own socket descriptor, not a raw number
        /// that the packet path can close and the kernel can reuse.
        #[test]
        fn watchdog_shutdown_duplicate_survives_the_original_stream() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let address = listener.local_addr().expect("local addr");
            let client = std::net::TcpStream::connect(address).expect("connect");
            let (_server, _) = listener.accept().expect("accept");
            let original = client.as_raw_fd();
            let duplicate = duplicate_shutdown_fd(original).expect("duplicate the socket");
            assert_ne!(duplicate.as_raw_fd(), original);
            drop(client);
            // SAFETY: `duplicate` is an owned descriptor; `F_GETFD` only reads
            // its flags and does not close or replace it.
            let flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) };
            assert!(
                flags >= 0,
                "the watchdog duplicate must remain open after the original drops"
            );
            assert!(duplicate_shutdown_fd(-1).is_none());
        }

        /// The signed UTC expiry and its monotonic shadow are independent halt
        /// conditions; neither can widen the other.
        #[test]
        fn policy_window_checks_signed_utc_and_monotonic_independently() {
            let utc_expired = PolicyWindow {
                expires_utc_us: 1,
                deadline: Instant::now() + Duration::from_secs(60),
            };
            assert!(
                utc_expired.check().is_err(),
                "an elapsed signed UTC window must fail closed"
            );
            let mono_expired = PolicyWindow {
                expires_utc_us: now_utc_us().unwrap() + 60_000_000,
                deadline: Instant::now(),
            };
            assert!(
                mono_expired.check().is_err(),
                "an elapsed monotonic window must fail closed"
            );
            assert!(policy_window().check().is_ok());
        }

        /// The signed policy window is a second, independent halt condition: a
        /// still-fresh status snapshot must not keep business alive past it.
        #[test]
        fn watchdog_halts_when_the_signed_policy_window_expires() {
            let counters = counters();
            let (dir, store) = store_fixture("policy-expiry");
            let window = PolicyWindow {
                expires_utc_us: 1,
                deadline: Instant::now(),
            };
            let watchdog = StatusWatchdog::start(
                Arc::new(Mutex::new(store)),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                window,
                -1,
                Arc::clone(&counters),
                Duration::from_secs(3600),
                Arc::new(Mutex::new(crate::daemon_revoke::RevocationSet::new())),
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
            let reason = reason.expect("watchdog must publish policy expiry");
            assert!(
                reason.contains("network policy") || reason.contains("policy window"),
                "unexpected policy reason: {reason}"
            );
            drop(watchdog);
            let _ = fs::remove_dir_all(dir);
        }

        /// `Drop` stops and joins promptly even when the immediate first check
        /// has already published a fault.
        #[test]
        fn watchdog_drop_joins_promptly_without_fault() {
            let counters = counters();
            let (dir, store) = store_fixture("drop");
            let watchdog = StatusWatchdog::start(
                Arc::new(Mutex::new(store)),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                policy_window(),
                -1,
                Arc::clone(&counters),
                Duration::from_secs(3600),
                Arc::new(Mutex::new(crate::daemon_revoke::RevocationSet::new())),
            );
            let started = Instant::now();
            drop(watchdog);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "watchdog drop must not block: {:?}",
                started.elapsed()
            );
            let _ = fs::remove_dir_all(dir);
        }

        /// A second store on the same path is Busy; the watchdog must never
        /// reopen per tick or retry through the lock.
        #[test]
        fn second_store_open_is_busy_and_never_retried() {
            let (dir, store) = store_fixture("busy");
            let uid = unsafe { libc::geteuid() };
            let second = StatusStore::open(
                dir.join("status.state"),
                [0x2a; 16],
                uid,
                ManagementTrust::new([0x2a; 16]),
            );
            assert!(matches!(second, Err(boreas_pki::status_store::Error::Busy)));
            drop(store);
            let _ = fs::remove_dir_all(dir);
        }

        /// The first check must not wait for `interval`: an old implementation
        /// parked for 500 ms (or 1 h in this test) after business started.
        #[test]
        fn watchdog_first_check_is_immediate() {
            let counters = counters();
            let (dir, store) = store_fixture("immediate");
            let watchdog = StatusWatchdog::start(
                Arc::new(Mutex::new(store)),
                PathBuf::from("/nonexistent-boreas-status.signed"),
                policy_window(),
                -1,
                Arc::clone(&counters),
                Duration::from_secs(3600),
                Arc::new(Mutex::new(crate::daemon_revoke::RevocationSet::new())),
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if watchdog.fault().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                watchdog.fault().is_some(),
                "watchdog first check must be immediate"
            );
            assert!(!counters.status_fresh.load(Ordering::SeqCst));
            drop(watchdog);
            let _ = fs::remove_dir_all(dir);
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

        /// Concurrent upstream sockets are bounded: one business connection plus
        /// at most one standby, and a released permit is immediately reusable.
        #[test]
        fn live_connection_budget_bounds_both_slots_and_releases_on_drop() {
            let budget = ConnectionBudget::new();
            assert_eq!(budget.live(), 0);
            let business = budget.try_acquire().expect("business slot");
            let standby = budget.try_acquire().expect("standby slot");
            assert_eq!(budget.live(), MAX_LIVE_CONNECTIONS);
            assert!(
                budget.try_acquire().is_none(),
                "a third live upstream socket must be refused, not queued"
            );
            drop(business);
            assert_eq!(budget.live(), 1);
            let replacement = budget.try_acquire().expect("released slot is reusable");
            drop(replacement);
            drop(standby);
            assert_eq!(budget.live(), 0);
        }

        /// The daemon installs exactly one steady-state socket bound, and only at
        /// the post-handshake boundary. Handshake deadlines belong to the
        /// transport crate; this asserts the daemon does not silently leave a
        /// handshake-shaped timeout (or no timeout at all) on the business socket.
        #[test]
        fn steady_state_io_bound_is_installed_after_the_handshake() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let address = listener.local_addr().expect("local addr");
            let client = std::net::TcpStream::connect(address).expect("connect");
            let (_server, _) = listener.accept().expect("accept");
            let fd = client.as_raw_fd();
            bound_path_io(fd).expect("the business bound must install");
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                let mut value = libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                let mut length = core::mem::size_of::<libc::timeval>() as libc::socklen_t;
                // SAFETY: `value` and `length` are valid for one `timeval`.
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        option,
                        (&mut value as *mut libc::timeval).cast(),
                        &mut length,
                    )
                };
                assert_eq!(rc, 0, "bound must be readable back");
                assert_eq!(
                    u64::try_from(value.tv_sec).unwrap(),
                    PATH_IO_TIMEOUT.as_secs()
                );
                assert_eq!(value.tv_usec, 0);
            }
            assert!(
                bound_path_io(-1).is_err(),
                "an invalid descriptor must be refused, not silently unbound"
            );
        }

        /// The cleanup path interrupts a blocked dial through a *duplicate*
        /// descriptor, then joins. Without this, `Drop` would leave a detached
        /// thread that keeps dialling and owning sockets after the daemon stops.
        #[test]
        fn interrupt_clone_ends_a_blocked_dial_and_join_waits() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let address = listener.local_addr().expect("local addr");
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let peer = thread::spawn(move || {
                let (_peer, _) = listener.accept().expect("accept");
                // Silent peer: exactly the state an outer-TLS handshake waits in.
                let _ = release_rx.recv_timeout(Duration::from_secs(10));
            });
            let dial = std::net::TcpStream::connect(address).expect("connect");
            let interrupt = dial.try_clone().expect("duplicate the dial socket");
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                let mut dial = dial;
                let mut byte = [0u8; 1];
                let _ = done_tx.send(dial.read(&mut byte));
            });
            thread::sleep(Duration::from_millis(30));
            interrupt
                .shutdown(std::net::Shutdown::Both)
                .expect("the duplicate descriptor must reach the dial socket");
            let read = done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("cleanup must end the blocked dial instead of leaking it");
            assert_eq!(read.expect("read returns after shutdown"), 0);
            let started = Instant::now();
            worker.join().expect("worker join");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "joining a stopped dial must be prompt: {:?}",
                started.elapsed()
            );
            let _ = release_tx.send(());
            peer.join().expect("peer thread");
        }

        /// A stopped manager can never start another dial, whatever the clock or
        /// the backoff state says.
        #[test]
        fn stopped_manager_never_starts_another_dial() {
            let now = Instant::now();
            assert!(should_dial(now, now, false, false, false));
            assert!(!should_dial(now, now, false, false, true), "stopped");
            assert!(
                !should_dial(now, now, false, true, false),
                "already dialling"
            );
            assert!(!should_dial(now, now, true, false, false), "standby held");
            assert!(
                !should_dial(now, now + Duration::from_secs(1), false, false, false),
                "backoff not elapsed"
            );
        }

        #[test]
        fn socket_health_never_reports_a_dead_peer_as_alive() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let address = listener.local_addr().expect("local addr");
            let client = std::net::TcpStream::connect(address).expect("connect");
            let (server, _) = listener.accept().expect("accept");
            let fd = client.as_raw_fd();
            assert_eq!(socket_health(fd), SocketHealth::Alive);
            drop(server);
            // A closed peer surfaces as a reset (Failed) or as readable EOF
            // (Unread/PeerClosed); all of them mean "unusable standby".
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut health = SocketHealth::Alive;
            while Instant::now() < deadline {
                health = socket_health(fd);
                if health != SocketHealth::Alive {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            assert_ne!(
                health,
                SocketHealth::Alive,
                "a closed peer must never look alive"
            );
            assert_eq!(socket_health(-1), SocketHealth::Failed);
        }

        /// The standby verdict uses the plan's initial threshold: below it the
        /// path is still "idle", at it the path is reported "down", a held
        /// verified session wins, and a protocol/identity rejection always wins
        /// because it can never be promoted.
        #[test]
        fn standby_state_uses_the_plan_threshold_without_relaxing_it() {
            let counters = counters();
            assert_eq!(standby_state_label(&counters), "idle");
            counters
                .standby_failures
                .store(STANDBY_FAIL_THRESHOLD - 1, Ordering::SeqCst);
            assert_eq!(standby_state_label(&counters), "idle");
            counters
                .standby_failures
                .store(STANDBY_FAIL_THRESHOLD, Ordering::SeqCst);
            assert_eq!(standby_state_label(&counters), "down");
            counters.standby_ready.store(true, Ordering::SeqCst);
            assert_eq!(standby_state_label(&counters), "ready");
            counters.standby_rejected.store(true, Ordering::SeqCst);
            assert_eq!(standby_state_label(&counters), "rejected");
            // Cadence, threshold and backoff are the plan's initial §8.5 values.
            // The interval names a transport poll, not a ProbePing sample.
            assert_eq!(STANDBY_POLL_INTERVAL, Duration::from_millis(2_000));
            assert_eq!(STANDBY_FAIL_THRESHOLD, 3);
            assert_eq!(STANDBY_DIAL_BACKOFF, Duration::from_millis(1_000));
        }

        /// A published flag and its slot must never disagree, even when a
        /// publisher and a taker run at the same time.
        #[test]
        fn standby_publisher_and_taker_keep_ready_in_sync_with_the_slot() {
            let slot = Arc::new(Mutex::new(None::<()>));
            let ready = Arc::new(AtomicBool::new(false));
            let done = Arc::new(AtomicBool::new(false));

            let publisher = {
                let slot = Arc::clone(&slot);
                let ready = Arc::clone(&ready);
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    for _ in 0..20_000 {
                        if done.load(Ordering::SeqCst) {
                            break;
                        }
                        let _ = publish_standby_slot(&slot, &ready, ());
                        thread::yield_now();
                    }
                })
            };
            let taker = {
                let slot = Arc::clone(&slot);
                let ready = Arc::clone(&ready);
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    for _ in 0..20_000 {
                        if done.load(Ordering::SeqCst) {
                            break;
                        }
                        let _ = take_standby_slot(&slot, &ready);
                        thread::yield_now();
                    }
                })
            };
            let monitor = {
                let slot = Arc::clone(&slot);
                let ready = Arc::clone(&ready);
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        let guard = lock_mutex(&slot);
                        assert_eq!(
                            guard.is_some(),
                            ready.load(Ordering::SeqCst),
                            "published flag disagrees with the held slot"
                        );
                        drop(guard);
                        thread::yield_now();
                    }
                })
            };

            publisher.join().expect("publisher");
            taker.join().expect("taker");
            done.store(true, Ordering::SeqCst);
            monitor.join().expect("monitor");
            assert_eq!(
                ready.load(Ordering::SeqCst),
                lock_mutex(&slot).is_some(),
                "final published flag must match the final slot"
            );
        }

        /// Only pre-authentication transport errors are retryable. Inner-TLS
        /// policy/identity failures are terminal for the standby path and must
        /// never become an ordinary failover candidate.
        #[test]
        fn standby_protocol_and_identity_failures_are_not_transport_misses() {
            assert!(matches!(
                classify_tunnel_failure(TunnelError::Io(std::io::ErrorKind::ConnectionReset)),
                StandbyDialFailure::Transport
            ));
            assert!(matches!(
                classify_tunnel_failure(TunnelError::Closed),
                StandbyDialFailure::Transport
            ));
            assert!(matches!(
                classify_tunnel_failure(TunnelError::Ws(boreas_tunnel::ws::WsError::Io(
                    std::io::ErrorKind::ConnectionReset
                ))),
                StandbyDialFailure::Transport
            ));
            for error in [
                TunnelError::InnerTls("handshake"),
                TunnelError::InnerTls("peer identity mapping"),
                TunnelError::Ws(boreas_tunnel::ws::WsError::BadAcceptKey),
            ] {
                assert!(
                    matches!(
                        classify_tunnel_failure(error),
                        StandbyDialFailure::Protocol(_)
                    ),
                    "a protocol/identity error must not be a transport miss"
                );
            }
        }

        /// A protocol or identity failure on the business path is terminal, not a
        /// failover candidate; only a byte-stream failure may promote.
        #[test]
        fn protocol_path_failures_are_not_failover_candidates() {
            assert_eq!(
                path_failure_kind(&PacketPathError::CircuitIo(
                    std::io::ErrorKind::ConnectionReset
                )),
                PathFailureKind::Transport,
                "a circuit I/O failure is transport loss"
            );
            for error in [
                PacketPathError::TruncatedFrame,
                PacketPathError::EmptyFrame,
                PacketPathError::FrameTooLarge,
                PacketPathError::FrameLengthMismatch,
                PacketPathError::PolicyMismatch,
                PacketPathError::IdentityMismatch,
                PacketPathError::Closed,
                PacketPathError::Poisoned,
            ] {
                assert_eq!(
                    path_failure_kind(&error),
                    PathFailureKind::Protocol,
                    "{error:?} must not be promoted as ordinary failover"
                );
            }
        }

        fn identity_fixture() -> BusinessIdentity {
            BusinessIdentity {
                local_vip: std::net::Ipv4Addr::new(10, 20, 1, 2),
                peer_vip: std::net::Ipv4Addr::new(10, 20, 1, 1),
                peer_node_id: 1,
                peer_generation: 1,
                path_hops: 1,
                mtu_cap: 1400,
            }
        }

        /// A failover may change the circuit and its ingress, never the verified
        /// peer identity or either permanent VIP.
        #[test]
        fn failover_identity_must_match_the_pre_failure_binding() {
            let baseline = identity_fixture();
            assert_eq!(baseline, identity_fixture());
            for changed in [
                BusinessIdentity {
                    local_vip: std::net::Ipv4Addr::new(10, 20, 2, 2),
                    ..identity_fixture()
                },
                BusinessIdentity {
                    peer_vip: std::net::Ipv4Addr::new(10, 20, 2, 1),
                    ..identity_fixture()
                },
                BusinessIdentity {
                    peer_node_id: 0x0101,
                    ..identity_fixture()
                },
                BusinessIdentity {
                    peer_generation: 2,
                    ..identity_fixture()
                },
                BusinessIdentity {
                    path_hops: 2,
                    ..identity_fixture()
                },
                BusinessIdentity {
                    mtu_cap: 1280,
                    ..identity_fixture()
                },
            ] {
                assert_ne!(
                    baseline, changed,
                    "a different verified binding must be refused, not promoted"
                );
            }
        }

        /// Host-side failures are terminal: another path would fail identically,
        /// so they must never be classified as a failover trigger.
        #[test]
        fn host_side_failures_are_terminal_not_failover_candidates() {
            for error in [
                PacketPathError::HostQueueFull,
                PacketPathError::HostQueueClosed,
            ] {
                assert!(host_side_failure(&error), "{error:?} is host-side");
            }
            for error in [
                PacketPathError::CircuitIo(std::io::ErrorKind::ConnectionReset),
                PacketPathError::TruncatedFrame,
                PacketPathError::Closed,
                PacketPathError::Poisoned,
            ] {
                assert!(
                    !host_side_failure(&error),
                    "{error:?} is a circuit failure, not host-side"
                );
            }
        }
    }
}
