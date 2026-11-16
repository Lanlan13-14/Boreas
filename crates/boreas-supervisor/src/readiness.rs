//! Authorized `AF_UNIX` readiness handshake for trial launches.
//!
//! A trial candidate is **not** ready because it is still alive. The supervisor
//! binds a private socket (`<store>/ready.sock`, mode `0600`), exports its path
//! to the child as [`SOCKET_ENV`], and then requires the child to connect and
//! answer a fresh, per-run random challenge with its state schema, ready worker
//! count and TUN status. Only a response that echoes *this run's* nonce, reports
//! the schema this deployment expects and satisfies the worker/TUN policy
//! confirms the upgrade.
//!
//! The exchange is a **non-blocking state machine** ([`Handshake`]) with a fixed
//! 512-byte line budget and one absolute deadline:
//!
//! * the accepted socket is never switched back to blocking mode;
//! * bytes are read into a fixed buffer, so a peer cannot make the supervisor
//!   allocate an unbounded line before the length check;
//! * a slow-drip peer cannot extend the exchange, because the deadline is
//!   absolute rather than a per-read timeout that each read resets;
//! * between polls the caller keeps observing child exit and stop signals.
//!
//! Peer credentials bind the connection to the supervisor's own OS user, and on
//! Linux additionally to the exact child pid, so another local process cannot
//! answer on the candidate's behalf.
//!
//! Deliberate limits, stated rather than implied:
//!
//! * The nonce is not yet bound to the candidate artifact SHA-256 because the
//!   `verify_release` → `prepare` path is not wired; the schema binding is the
//!   part that exists today.
//! * There is no Boreas daemon in this workspace yet, so this module is
//!   exercised against the `__ready-stub` candidate in tests. It is **not**
//!   claimed to be integrated in production.
//! * Windows has no `AF_UNIX` in `std` and no peer-credential API here, so the
//!   module is Unix-only and the store stays fail-closed there.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Instant;

use crate::readiness_protocol::{
    CHALLENGE_MAGIC, MAX_LINE_BYTES, MAX_SCHEMA_BYTES, MAX_WORKERS, RESPONSE_MAGIC,
};

/// Environment variable carrying the readiness socket path to the candidate.
pub const SOCKET_ENV: &str = "BOREAS_READY_SOCKET";

#[derive(Debug)]
pub enum ReadinessError {
    Io(io::Error),
    /// The policy-relevant part of the answer was missing or wrong.
    NotReady(&'static str),
    /// The peer was not the process we launched.
    UnauthorizedPeer(String),
    /// Framing/format problem: the peer is not speaking this protocol.
    Protocol(&'static str),
}
impl fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "readiness I/O error: {e}"),
            Self::NotReady(reason) => write!(f, "candidate is not ready: {reason}"),
            Self::UnauthorizedPeer(reason) => {
                write!(f, "readiness peer is not the launched candidate: {reason}")
            }
            Self::Protocol(reason) => write!(f, "readiness protocol error: {reason}"),
        }
    }
}
impl std::error::Error for ReadinessError {}
impl From<io::Error> for ReadinessError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// What the deployment requires before an upgrade may be committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessPolicy {
    /// The exact state schema the candidate must report. This is bound to the
    /// target release's compatible schema, so any *other* well-formed schema is
    /// refused instead of silently accepted.
    pub expected_schema: String,
    /// Require a ready TUN device (a report of `absent` then fails the trial).
    pub require_tun: bool,
    /// Minimum number of workers the candidate must report as ready.
    pub min_workers: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunStatus {
    Ready,
    Absent,
}

/// A validated readiness answer from the launched candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyReport {
    pub schema: String,
    pub workers: u32,
    pub tun: TunStatus,
}

/// One pending handshake, owned by the supervisor's poll loop.
///
/// Holds the accepted socket and the partially read line. Nothing here blocks:
/// [`Handshake::poll`] returns `Pending` when no complete line is available yet.
pub struct Handshake {
    stream: UnixStream,
    nonce_hex: String,
    policy: ReadinessPolicy,
    buffer: [u8; MAX_LINE_BYTES + 1],
    used: usize,
}

/// Result of one non-blocking poll.
pub enum Progress {
    Pending,
    Ready(ReadyReport),
}

/// Create the private readiness socket.
///
/// A leftover socket from a previous run is removed; any other kind of object
/// at that path is refused (the store root is trusted, but this keeps a
/// surprise file from being silently unlinked).
pub fn bind(socket_path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(socket_path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "readiness socket path exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Best-effort cleanup; called on every exit path of a trial.
pub fn cleanup(socket_path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(socket_path)
        && meta.file_type().is_socket()
    {
        let _ = std::fs::remove_file(socket_path);
    }
}

/// Accept one connection and send the challenge, without blocking.
///
/// Returns `Ok(None)` when nobody has connected yet; the socket stays
/// non-blocking from here on, so the returned [`Handshake`] can be polled from
/// the supervisor's loop.
pub fn accept(
    listener: &UnixListener,
    child_pid: u32,
    policy: &ReadinessPolicy,
) -> Result<Option<Handshake>, ReadinessError> {
    let mut stream = match listener.accept() {
        Ok((stream, _addr)) => stream,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(e) => return Err(ReadinessError::Io(e)),
    };
    authorize_peer(&stream, child_pid)?;
    stream.set_nonblocking(true)?;
    let nonce = random_challenge()?;
    let nonce_hex = hex_encode(&nonce);
    let challenge = format!("{CHALLENGE_MAGIC} {nonce_hex}\n");
    // One write of ~71 bytes into an empty send buffer. A peer that cannot take
    // it is not going to complete the handshake anyway, so this is a refusal
    // rather than something to wait on.
    match stream.write(challenge.as_bytes()) {
        Ok(written) if written == challenge.len() => {}
        Ok(_) => {
            return Err(ReadinessError::Protocol(
                "challenge was only partially written",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            return Err(ReadinessError::NotReady(
                "candidate is not reading the readiness challenge",
            ));
        }
        Err(e) => return Err(ReadinessError::Io(e)),
    }
    Ok(Some(Handshake {
        stream,
        nonce_hex,
        policy: policy.clone(),
        buffer: [0u8; MAX_LINE_BYTES + 1],
        used: 0,
    }))
}

/// Advance at most one non-blocking step of the readiness exchange.
///
/// The caller retains `pending` between supervisor iterations so accepting a
/// client and receiving its response may span multiple polls without losing the
/// authorized peer. The absolute deadline is shared with the supervisor loop.
pub fn probe_once(
    listener: &UnixListener,
    child_pid: u32,
    policy: &ReadinessPolicy,
    pending: &mut Option<Handshake>,
    deadline: Instant,
) -> Result<Option<ReadyReport>, ReadinessError> {
    if pending.is_none() {
        *pending = accept(listener, child_pid, policy)?;
    }
    let Some(handshake) = pending.as_mut() else {
        return Ok(None);
    };
    match handshake.poll(deadline)? {
        Progress::Pending => Ok(None),
        Progress::Ready(report) => {
            *pending = None;
            Ok(Some(report))
        }
    }
}

impl Handshake {
    /// Read whatever is available without blocking.
    ///
    /// `deadline` is absolute: a peer trickling one byte per poll still fails
    /// once it passes, because the deadline is never extended.
    pub fn poll(&mut self, deadline: Instant) -> Result<Progress, ReadinessError> {
        if Instant::now() >= deadline {
            return Err(ReadinessError::NotReady(
                "candidate did not answer the readiness challenge in time",
            ));
        }
        loop {
            if let Some(position) = self.buffer[..self.used].iter().position(|b| *b == b'\n') {
                let line = std::str::from_utf8(&self.buffer[..position])
                    .map_err(|_| ReadinessError::Protocol("readiness answer is not UTF-8"))?;
                let report =
                    parse_response(line.trim_end_matches('\r'), &self.nonce_hex, &self.policy)?;
                return Ok(Progress::Ready(report));
            }
            if self.used >= MAX_LINE_BYTES {
                return Err(ReadinessError::Protocol(
                    "readiness answer exceeds the line limit",
                ));
            }
            match self.stream.read(&mut self.buffer[self.used..]) {
                Ok(0) => {
                    return Err(ReadinessError::Protocol(
                        "candidate closed the readiness socket without answering",
                    ));
                }
                Ok(read) => self.used += read,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(Progress::Pending);
                }
                Err(e) => return Err(ReadinessError::Io(e)),
            }
        }
    }
}

fn parse_response(
    line: &str,
    nonce_hex: &str,
    policy: &ReadinessPolicy,
) -> Result<ReadyReport, ReadinessError> {
    let mut fields = line.split(' ');
    if fields.next() != Some(RESPONSE_MAGIC) {
        return Err(ReadinessError::Protocol(
            "unexpected readiness answer magic",
        ));
    }
    let echo = fields
        .next()
        .ok_or(ReadinessError::Protocol("missing challenge echo"))?;
    if echo != nonce_hex {
        return Err(ReadinessError::Protocol(
            "challenge echo does not match this run",
        ));
    }
    let schema = fields
        .next()
        .ok_or(ReadinessError::Protocol("missing state schema"))?;
    if !valid_schema(schema) {
        return Err(ReadinessError::Protocol(
            "state schema identifier is invalid",
        ));
    }
    if schema != policy.expected_schema {
        return Err(ReadinessError::NotReady(
            "candidate reported a state schema this deployment does not expect",
        ));
    }
    let workers: u32 = fields
        .next()
        .ok_or(ReadinessError::Protocol("missing worker count"))?
        .parse()
        .map_err(|_| ReadinessError::Protocol("worker count is not a number"))?;
    if workers == 0 || workers > MAX_WORKERS {
        return Err(ReadinessError::Protocol("worker count is out of range"));
    }
    let tun = match fields
        .next()
        .ok_or(ReadinessError::Protocol("missing TUN status"))?
    {
        "ready" => TunStatus::Ready,
        "absent" => TunStatus::Absent,
        _ => {
            return Err(ReadinessError::Protocol(
                "TUN status is neither ready nor absent",
            ));
        }
    };
    if fields.next().is_some() {
        return Err(ReadinessError::Protocol(
            "trailing fields in readiness answer",
        ));
    }
    if workers < policy.min_workers {
        return Err(ReadinessError::NotReady(
            "fewer ready workers than the policy requires",
        ));
    }
    if policy.require_tun && tun == TunStatus::Absent {
        return Err(ReadinessError::NotReady(
            "no ready TUN device, which this deployment requires",
        ));
    }
    Ok(ReadyReport {
        schema: schema.to_owned(),
        workers,
        tun,
    })
}

fn valid_schema(schema: &str) -> bool {
    !schema.is_empty()
        && schema.len() <= MAX_SCHEMA_BYTES
        && !schema.starts_with('.')
        && schema
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

/// Linux: `SO_PEERCRED` gives uid **and** pid, so the answer must come from the
/// exact process the supervisor spawned.
#[cfg(target_os = "linux")]
fn authorize_peer(stream: &UnixStream, child_pid: u32) -> Result<(), ReadinessError> {
    use std::os::fd::AsRawFd;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into the live `cred`
    // value, and the descriptor is owned by `stream` for the whole call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(ReadinessError::UnauthorizedPeer(
            io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if cred.uid != euid {
        return Err(ReadinessError::UnauthorizedPeer(
            "peer runs as a different uid".to_string(),
        ));
    }
    if cred.pid != child_pid as libc::pid_t {
        return Err(ReadinessError::UnauthorizedPeer(format!(
            "peer pid {} is not the launched child pid {child_pid}",
            cred.pid
        )));
    }
    Ok(())
}

/// macOS: `getpeereid` gives uid/gid only. The pid is not available through a
/// stable binding here, so the check is "same user" plus the private `0600`
/// socket; this is documented rather than silently implied.
#[cfg(target_os = "macos")]
fn authorize_peer(stream: &UnixStream, _child_pid: u32) -> Result<(), ReadinessError> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: both out-parameters are live locals for the call.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(ReadinessError::UnauthorizedPeer(
            io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if uid != euid {
        return Err(ReadinessError::UnauthorizedPeer(
            "peer runs as a different uid".to_string(),
        ));
    }
    Ok(())
}

/// Other Unixes: no reviewed peer-credential binding is implemented, so the
/// handshake refuses rather than running unauthenticated.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn authorize_peer(_stream: &UnixStream, _child_pid: u32) -> Result<(), ReadinessError> {
    Err(ReadinessError::UnauthorizedPeer(
        "peer credentials are not implemented on this platform".to_string(),
    ))
}

fn random_challenge() -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    // `/dev/urandom` is available on every Unix this module compiles for; a
    // short read is an error, never a zero nonce.
    let mut source = std::fs::File::open("/dev/urandom")?;
    source.read_exact(&mut buf)?;
    Ok(buf)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Candidate side of the handshake, used by the `__ready-stub` test command.
///
/// Connects, reads the challenge and answers with the configured state. This is
/// a real client for the real protocol, so integration tests exercise both
/// halves instead of mocking one.
pub fn serve_once(
    socket_path: &Path,
    schema: &str,
    workers: u32,
    tun: TunStatus,
) -> io::Result<()> {
    if !valid_schema(schema) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stub schema is not a valid identifier",
        ));
    }
    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let nonce = trimmed
        .strip_prefix(CHALLENGE_MAGIC)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unexpected readiness challenge")
        })?;
    if nonce.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "challenge nonce is not 32 bytes of hex",
        ));
    }
    let tun = match tun {
        TunStatus::Ready => "ready",
        TunStatus::Absent => "absent",
    };
    writeln!(writer, "{RESPONSE_MAGIC} {nonce} {schema} {workers} {tun}")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static TEMP_SEQ: AtomicUsize = AtomicUsize::new(0);

    fn short_test_dir() -> PathBuf {
        let base = Path::new("/tmp").canonicalize().expect("canonical /tmp");
        // Keep the socket pathname short enough for macOS sockaddr_un.sun_path.
        // Include process-local sequence and OS randomness; create_dir is
        // exclusive, so collisions never reuse another test's directory.
        let uid = unsafe { libc::geteuid() };
        for _ in 0..32 {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let mut random = [0u8; 8];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut source| source.read_exact(&mut random))
                .expect("read fixture randomness");
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = base.join(format!("br-{}-{seq}-{suffix}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&root) {
                Ok(()) => {
                    let metadata = std::fs::symlink_metadata(&root).expect("fixture metadata");
                    assert!(
                        metadata.file_type().is_dir(),
                        "fixture root must be a directory"
                    );
                    assert_eq!(
                        metadata.uid(),
                        uid,
                        "fixture root must be owned by this user"
                    );
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                        .expect("restrict fixture root permissions");
                    return root.canonicalize().expect("canonical fixture root");
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create short fixture root: {error}"),
            }
        }
        panic!("could not allocate unique short fixture root")
    }

    const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn policy() -> ReadinessPolicy {
        ReadinessPolicy {
            expected_schema: "state-v1".to_string(),
            require_tun: true,
            min_workers: 1,
        }
    }

    #[test]
    fn accepts_a_well_formed_answer() {
        let report = parse_response(
            &format!("{RESPONSE_MAGIC} {NONCE} state-v1 4 ready"),
            NONCE,
            &policy(),
        )
        .expect("valid");
        assert_eq!(report.schema, "state-v1");
        assert_eq!(report.workers, 4);
        assert_eq!(report.tun, TunStatus::Ready);
    }

    #[test]
    fn rejects_a_replayed_or_foreign_nonce() {
        let answer = format!("{RESPONSE_MAGIC} {} state-v1 4 ready", "bb".repeat(32));
        assert!(matches!(
            parse_response(&answer, NONCE, &policy()),
            Err(ReadinessError::Protocol(_))
        ));
    }

    #[test]
    fn rejects_a_valid_but_unexpected_schema() {
        // Length/format alone must not be enough: the schema is bound to the
        // deployment's expected value.
        let answer = format!("{RESPONSE_MAGIC} {NONCE} state-v2 4 ready");
        assert!(matches!(
            parse_response(&answer, NONCE, &policy()),
            Err(ReadinessError::NotReady(_))
        ));
        let different = ReadinessPolicy {
            expected_schema: "state-v2".to_string(),
            ..policy()
        };
        assert!(parse_response(&answer, NONCE, &different).is_ok());
    }

    #[test]
    fn enforces_tun_worker_and_framing_policy() {
        // No TUN device, but the deployment requires one.
        assert!(matches!(
            parse_response(
                &format!("{RESPONSE_MAGIC} {NONCE} state-v1 4 absent"),
                NONCE,
                &policy()
            ),
            Err(ReadinessError::NotReady(_))
        ));
        assert!(
            parse_response(
                &format!("{RESPONSE_MAGIC} {NONCE} state-v1 4 absent"),
                NONCE,
                &ReadinessPolicy {
                    expected_schema: "state-v1".to_string(),
                    require_tun: false,
                    min_workers: 1
                }
            )
            .is_ok()
        );
        // Too few workers for the policy.
        let strict = ReadinessPolicy {
            expected_schema: "state-v1".to_string(),
            require_tun: true,
            min_workers: 3,
        };
        assert!(matches!(
            parse_response(
                &format!("{RESPONSE_MAGIC} {NONCE} state-v1 2 ready"),
                NONCE,
                &strict
            ),
            Err(ReadinessError::NotReady(_))
        ));
        // Framing: wrong magic, missing fields, trailing fields, bad counts.
        for bad in [
            format!("BOREAS-READY {NONCE} state-v1 1 ready"),
            format!("{RESPONSE_MAGIC} {NONCE} state-v1 1"),
            format!("{RESPONSE_MAGIC} {NONCE} state-v1 1 ready extra"),
            format!("{RESPONSE_MAGIC} {NONCE} state-v1 zero ready"),
            format!("{RESPONSE_MAGIC} {NONCE} state-v1 0 ready"),
            format!("{RESPONSE_MAGIC} {NONCE} ../bad 1 ready"),
        ] {
            assert!(parse_response(&bad, NONCE, &policy()).is_err(), "{bad}");
        }
    }

    #[test]
    fn end_to_end_handshake_is_bounded_and_non_blocking() {
        let dir = short_test_dir();
        let socket = dir.join("ready.sock");
        let listener = bind(&socket).expect("bind");
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "readiness socket must be private");
        assert!(
            accept(&listener, std::process::id(), &policy())
                .expect("accept poll")
                .is_none(),
            "no peer yet must be a non-blocking Pending, not an error"
        );

        let path = socket.clone();
        let client = std::thread::spawn(move || {
            for _ in 0..500 {
                if serve_once(&path, "state-v1", 2, TunStatus::Ready).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("stub could not complete the handshake");
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut pending = None;
        let report = loop {
            match probe_once(
                &listener,
                std::process::id(),
                &policy(),
                &mut pending,
                deadline,
            )
            .expect("readiness poll")
            {
                Some(report) => break report,
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        client.join().expect("client thread");
        assert_eq!(report.schema, "state-v1");
        assert_eq!(report.workers, 2);
        cleanup(&socket);
        assert!(!socket.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_slow_drip_peer_cannot_extend_the_absolute_deadline() {
        let dir = short_test_dir();
        let socket = dir.join("ready.sock");
        let listener = bind(&socket).expect("bind");

        let path = socket.clone();
        let client = std::thread::spawn(move || {
            // Connect and read the challenge, then send one byte at a time.
            let mut stream = UnixStream::connect(&path).expect("connect");
            let mut challenge = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).expect("read") == 1 && byte[0] != b'\n' {
                challenge.push(byte[0]);
            }
            for _ in 0..200 {
                if stream.write_all(b"B").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let deadline = Instant::now() + Duration::from_millis(150);
        let mut handshake = loop {
            if let Some(handshake) =
                accept(&listener, std::process::id(), &policy()).expect("accept")
            {
                break handshake;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut outcome = Ok(Progress::Pending);
        while Instant::now() < deadline + Duration::from_secs(2) {
            outcome = handshake.poll(deadline);
            if !matches!(outcome, Ok(Progress::Pending)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            matches!(outcome, Err(ReadinessError::NotReady(_))),
            "a slow-drip peer must hit the absolute deadline, got {:?}",
            outcome.map(|_| "pending/ready")
        );
        let _ = client.join();
        cleanup(&socket);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
