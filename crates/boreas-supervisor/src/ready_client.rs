//! Bounded client for the supervisor's trial-readiness challenge.
//!
//! This reports caller-supplied runtime facts to the supervisor; it does not
//! attest artifact identity or prove those facts. In particular, the challenge
//! is not bound to a signed release hash.

use std::fmt;
use std::io;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::readiness_protocol::{
    CHALLENGE_MAGIC, MAX_LINE_BYTES, MAX_SCHEMA_BYTES, MAX_WORKERS, RESPONSE_MAGIC,
};

#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunStatus {
    Ready,
    Absent,
}

#[derive(Debug)]
pub enum ReadyClientError {
    Io(io::Error),
    Protocol(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for ReadyClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "readiness client I/O error: {e}"),
            Self::Protocol(reason) => write!(f, "readiness client protocol error: {reason}"),
            Self::Unsupported(reason) => write!(f, "readiness client unsupported: {reason}"),
        }
    }
}
impl std::error::Error for ReadyClientError {}
impl From<io::Error> for ReadyClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Connect to `socket_path`, verify the supervisor peer, answer one challenge,
/// and return only after the bounded response has been written.
///
/// `schema`, `workers`, and `tun` are assertions supplied by the caller, not
/// artifact-bound or cryptographically attested readiness evidence. The
/// supervisor remains responsible for policy validation of its response.
#[cfg(target_os = "linux")]
pub fn report_ready(
    socket_path: &Path,
    schema: &str,
    workers: u32,
    tun: TunStatus,
) -> Result<(), ReadyClientError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    validate_report(schema, workers)?;
    let meta = std::fs::symlink_metadata(socket_path)?;
    if !meta.file_type().is_socket() || meta.mode() & 0o777 != 0o600 {
        return Err(ReadyClientError::Protocol(
            "readiness path is not a mode-0600 socket",
        ));
    }
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(ReadyClientError::Protocol(
            "readiness socket owner UID mismatch",
        ));
    }

    let deadline = Instant::now() + IO_TIMEOUT;
    // std UnixStream::connect is blocking and has no portable timeout knob.
    // Once connected, all exchange I/O is bounded by this shared deadline and
    // per-operation socket timeouts; connect itself is not claimed to be bounded.
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut cred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt fills the live credential value for this owned stream.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut cred_len,
        )
    };
    if rc != 0 || cred_len as usize != std::mem::size_of::<libc::ucred>() || cred.uid != uid {
        return Err(ReadyClientError::Protocol(
            "readiness server credentials rejected",
        ));
    }

    let line = read_bounded_line(&mut stream, deadline)?;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 2 || fields[0] != CHALLENGE_MAGIC || !valid_nonce(fields[1]) {
        return Err(ReadyClientError::Protocol("invalid readiness challenge"));
    }
    let tun = match tun {
        TunStatus::Ready => "ready",
        TunStatus::Absent => "absent",
    };
    let response = format!("{RESPONSE_MAGIC} {} {schema} {workers} {tun}\n", fields[1]);
    if response.len() > MAX_LINE_BYTES {
        return Err(ReadyClientError::Protocol(
            "readiness response exceeds line limit",
        ));
    }
    if Instant::now() >= deadline {
        return Err(ReadyClientError::Protocol("readiness exchange timed out"));
    }
    write_deadline(&mut stream, response.as_bytes(), deadline)?;
    stream.flush()?;
    Ok(())
}

/// AF_UNIX readiness client peer credentials are only implemented on Linux.
#[cfg(not(target_os = "linux"))]
pub fn report_ready(
    _socket_path: &Path,
    _schema: &str,
    _workers: u32,
    _tun: TunStatus,
) -> Result<(), ReadyClientError> {
    Err(ReadyClientError::Unsupported(
        "server peer credential verification is implemented only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn validate_report(schema: &str, workers: u32) -> Result<(), ReadyClientError> {
    if schema.is_empty()
        || schema.len() > MAX_SCHEMA_BYTES
        || schema.starts_with('.')
        || !schema
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return Err(ReadyClientError::Protocol(
            "invalid state schema identifier",
        ));
    }
    if workers == 0 || workers > MAX_WORKERS {
        return Err(ReadyClientError::Protocol("worker count out of range"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_line(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
) -> Result<String, ReadyClientError> {
    let mut bytes = Vec::with_capacity(96);
    loop {
        if Instant::now() >= deadline {
            return Err(ReadyClientError::Protocol("readiness exchange timed out"));
        }
        stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return Err(ReadyClientError::Protocol("server closed before challenge")),
            Ok(_) if byte[0] == b'\n' => {
                if bytes.last() == Some(&b'\r') {
                    bytes.pop();
                }
                return String::from_utf8(bytes)
                    .map_err(|_| ReadyClientError::Protocol("challenge is not UTF-8"));
            }
            Ok(_) => {
                if bytes.len() >= MAX_LINE_BYTES {
                    return Err(ReadyClientError::Protocol("challenge exceeds line limit"));
                }
                bytes.push(byte[0]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ReadyClientError::Protocol("readiness challenge timed out"));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(target_os = "linux")]
fn write_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), ReadyClientError> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadyClientError::Protocol("readiness exchange timed out"));
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err(ReadyClientError::Protocol("server closed during response")),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ReadyClientError::Protocol("readiness response timed out"));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 64
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
