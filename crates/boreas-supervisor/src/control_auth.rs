//! Control-socket peer authorization (master plan §10.5, last bullet).
//!
//! # What this module is
//!
//! [`authorize`] decides whether a caller-supplied peer uid may use the
//! console control socket. The socket path is exactly
//! [`CONTROL_SOCKET_PATH`] (`/run/boreas/control.sock`) and the mode is
//! exactly [`CONTROL_SOCKET_MODE`] (`0o600`). The peer uid must equal the
//! daemon uid **after privilege drop**.
//!
//! # What this module is not
//!
//! This function does **not** call `SO_PEERCRED`, `getsockopt`, `stat`, or
//! `connect`. The caller passes the path, the mode, and the uid it already
//! observed. There is no log-parsing API: the console must not recover a
//! snapshot by reading daemon log text.
//!
//! uid `0` is not a special allow. [`daemon_uid_may_be_root`] is `false`, so
//! a root daemon is rejected, and a peer uid of `0` returns
//! [`Decision::RefusedRoot`] even when the daemon uid is also `0`.
//!
//! A matching path, mode, and uid is [`Decision::Allowed`]. That is not
//! `G-UI` (three languages, narrow terminal, non-TTY, `NO_COLOR`, DSR,
//! confirmation, log/terminal injection, diagnostic redaction). It is not
//! `G-UPGRADE` and not `G-RESOURCE`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

/// Absolute path of the console control socket. No other path is accepted.
pub const CONTROL_SOCKET_PATH: &str = "/run/boreas/control.sock";

/// Required mode: owner read/write only. Type bits and any other permission
/// bit fail. `0o600` is not "at most 0o600" and not "0o600 plus extras".
pub const CONTROL_SOCKET_MODE: u32 = 0o600;

/// This policy never permits a daemon uid of 0.
///
/// The §10.5 check is "peer uid equals the post-drop daemon user", not
/// "peer is root". A daemon that is still uid 0 has not dropped privileges,
/// so it is not an acceptable control-socket identity.
pub const fn daemon_uid_may_be_root() -> bool {
    false
}

/// Outcome of [`authorize`]. Only [`Decision::Allowed`] may take a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Path, mode, and post-drop uid all matched. Root was not involved.
    Allowed,
    /// Path was not exactly [`CONTROL_SOCKET_PATH`].
    RefusedPath,
    /// Mode was not exactly [`CONTROL_SOCKET_MODE`] (`0o600`).
    RefusedMode,
    /// Peer uid is 0. Root is refused even if the daemon uid is also 0.
    RefusedRoot,
    /// Daemon uid is 0 and [`daemon_uid_may_be_root`] is false.
    RefusedDaemonRoot,
    /// Peer uid is not the post-drop daemon uid.
    RefusedUid,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => f.write_str("control socket peer allowed"),
            Self::RefusedPath => f.write_str("control socket path is not /run/boreas/control.sock"),
            Self::RefusedMode => f.write_str("control socket mode is not 0o600"),
            Self::RefusedRoot => f.write_str("control socket peer uid 0 is refused"),
            Self::RefusedDaemonRoot => {
                f.write_str("control socket daemon uid 0 is refused by policy")
            }
            Self::RefusedUid => f.write_str("control socket peer uid does not match daemon uid"),
        }
    }
}

/// Why [`authorize`] refused. [`Decision::Allowed`] is not an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthError {
    decision: Decision,
}

impl AuthError {
    pub fn decision(self) -> Decision {
        self.decision
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.decision.fmt(f)
    }
}

impl Error for AuthError {}

/// Authorize one observed peer against the fixed control socket.
///
/// `path` must be exactly `/run/boreas/control.sock` (byte-for-byte, no
/// trailing slash, no `.` or `..` components, no alternate prefix).
/// `mode` must be exactly `0o600`. File-type bits (`S_IFSOCK` and friends)
/// are not stripped: the caller passes the permission mode alone.
///
/// `daemon_uid` is the uid the daemon holds **after** it drops privileges.
/// `peer_uid` is the uid the caller already read (for example from
/// `SO_PEERCRED`). This function does not perform that read.
///
/// Check order, first failure wins: path, mode, peer uid 0
/// ([`Decision::RefusedRoot`]), daemon uid 0 while
/// [`daemon_uid_may_be_root`] is false, then uid equality.
pub fn authorize(path: &str, mode: u32, daemon_uid: u32, peer_uid: u32) -> Result<Decision, AuthError> {
    if path != CONTROL_SOCKET_PATH {
        return Err(AuthError {
            decision: Decision::RefusedPath,
        });
    }
    if mode != CONTROL_SOCKET_MODE {
        return Err(AuthError {
            decision: Decision::RefusedMode,
        });
    }
    // uid 0 is never an allow, including the case where the daemon uid is
    // also 0. That case is the one a "root may talk to a root daemon" rule
    // would have accepted; this policy rejects it.
    if peer_uid == 0 {
        return Err(AuthError {
            decision: Decision::RefusedRoot,
        });
    }
    if daemon_uid == 0 && !daemon_uid_may_be_root() {
        return Err(AuthError {
            decision: Decision::RefusedDaemonRoot,
        });
    }
    if peer_uid != daemon_uid {
        return Err(AuthError {
            decision: Decision::RefusedUid,
        });
    }
    Ok(Decision::Allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAEMON: u32 = 1000;

    #[test]
    fn policy_rejects_a_root_daemon_identity() {
        assert!(!daemon_uid_may_be_root());
    }

    #[test]
    fn matching_path_mode_and_uid_is_allowed() {
        let decision = authorize(CONTROL_SOCKET_PATH, CONTROL_SOCKET_MODE, DAEMON, DAEMON)
            .expect("matching uid");
        assert_eq!(decision, Decision::Allowed);
        assert_eq!(CONTROL_SOCKET_PATH, "/run/boreas/control.sock");
        assert_eq!(CONTROL_SOCKET_MODE, 0o600);
    }

    #[test]
    fn other_modes_fail() {
        for mode in [0o000, 0o400, 0o200, 0o640, 0o660, 0o700, 0o755, 0o777, 0o1600, 0o100600] {
            let err = authorize(CONTROL_SOCKET_PATH, mode, DAEMON, DAEMON).unwrap_err();
            assert_eq!(err.decision(), Decision::RefusedMode, "mode {mode:#o}");
        }
    }

    #[test]
    fn other_paths_fail() {
        for path in [
            "",
            "run/boreas/control.sock",
            "/run/boreas/control.sock/",
            "/run/boreas/control.sock\0",
            "/run/boreas//control.sock",
            "/run/boreas/./control.sock",
            "/run/boreas/control.sock/../control.sock",
            "/tmp/boreas/control.sock",
            "/run/boreas/control.sock.bak",
            "/run/Boreas/control.sock",
            "/run/boreas/control.SOCK",
        ] {
            let err = authorize(path, CONTROL_SOCKET_MODE, DAEMON, DAEMON).unwrap_err();
            assert_eq!(err.decision(), Decision::RefusedPath, "path {path:?}");
        }
    }

    #[test]
    fn peer_uid_zero_is_refused_root_even_when_daemon_uid_is_zero() {
        let err = authorize(CONTROL_SOCKET_PATH, CONTROL_SOCKET_MODE, 0, 0).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedRoot);

        let err = authorize(CONTROL_SOCKET_PATH, CONTROL_SOCKET_MODE, DAEMON, 0).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedRoot);
    }

    #[test]
    fn root_daemon_with_nonzero_peer_is_refused() {
        let err = authorize(CONTROL_SOCKET_PATH, CONTROL_SOCKET_MODE, 0, DAEMON).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedDaemonRoot);
    }

    #[test]
    fn mismatched_nonzero_uid_is_refused() {
        let err = authorize(CONTROL_SOCKET_PATH, CONTROL_SOCKET_MODE, DAEMON, DAEMON + 1).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedUid);
    }

    #[test]
    fn path_is_checked_before_mode_and_root() {
        let err = authorize("/tmp/control.sock", 0o777, 0, 0).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedPath);
        let err = authorize(CONTROL_SOCKET_PATH, 0o777, 0, 0).unwrap_err();
        assert_eq!(err.decision(), Decision::RefusedMode);
    }
}
