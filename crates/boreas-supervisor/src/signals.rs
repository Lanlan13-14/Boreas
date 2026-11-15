//! Signal forwarding and controlled stop.
//!
//! The supervisor installs async-signal-safe handlers for `SIGTERM`, `SIGINT`
//! and `SIGHUP`. The handler only stores the signal number in an atomic; the
//! wait loops poll it, forward the signal to the child, and escalate to
//! `SIGKILL` after a grace period. That turns "the child receives group-directed
//! stops if the service manager happens to signal the whole cgroup" into an
//! explicit contract for stops that target only the supervisor.
//!
//! Windows has no POSIX signal disposition: the functions compile to no-ops and
//! the documented contract there stays console/JOB-object based.

use std::sync::atomic::{AtomicI32, Ordering};

static PENDING: AtomicI32 = AtomicI32::new(0);

/// Install the handlers. Idempotent enough for one supervisor process: calling
/// it twice just reinstalls the same function.
#[cfg(unix)]
pub fn install() -> std::io::Result<()> {
    extern "C" fn handler(signal: libc::c_int) {
        // Async-signal-safe: one relaxed store into a static, nothing else.
        PENDING.store(signal, Ordering::Relaxed);
    }
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: `handler` has the C signal-handler signature, performs only an
        // atomic store, and is never uninstalled, so the pointer stays valid.
        let previous = unsafe { libc::signal(signal, handler as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn install() -> std::io::Result<()> {
    Ok(())
}

/// Take the last delivered stop signal, if any.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn take() -> Option<i32> {
    match PENDING.swap(0, Ordering::Relaxed) {
        0 => None,
        signal => Some(signal),
    }
}

/// Forward `signal` to `pid`. Returns a diagnostic on failure; never panics.
#[cfg(unix)]
pub fn forward(pid: u32, signal: i32) -> Option<String> {    // SAFETY: kill(2) on a pid we spawned; no memory is touched.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal as libc::c_int) };
    if rc == 0 {
        None
    } else {
        Some(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub fn forward(_pid: u32, _signal: i32) -> Option<String> {
    Some("signal forwarding is not implemented on this platform".to_string())
}

/// Shell-convention exit code for "terminated by `signal`".
#[cfg_attr(not(unix), allow(dead_code))]
pub fn exit_code(signal: i32) -> u8 {
    u8::try_from(128i32.saturating_add(signal)).unwrap_or(1)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn pending_signal_is_taken_once() {
        // Directly set the static to avoid delivering a real signal in tests.
        PENDING.store(libc::SIGTERM, Ordering::Relaxed);
        assert_eq!(take(), Some(libc::SIGTERM));
        assert_eq!(take(), None, "taking a signal clears it");
    }

    #[test]
    fn exit_codes_follow_the_shell_convention() {
        assert_eq!(exit_code(libc::SIGTERM), 143);
        assert_eq!(exit_code(libc::SIGKILL), 137);
    }
}
