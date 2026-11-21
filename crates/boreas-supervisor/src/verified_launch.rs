use std::{ffi::OsString, path::Path};

use boreas_supervisor::{Activation, UpgradeStore, verified_stage};

pub fn is_enabled(store: &str) -> Result<bool, String> {
    let path = Path::new(store);
    let enabled = verified_stage::is_verified_store(path).map_err(|e| e.to_string())?;
    if !enabled {
        return Ok(false);
    }
    #[cfg(all(target_os = "linux", feature = "openssl-backend"))]
    {
        verified_stage::validate_store_path(path).map_err(|e| e.to_string())?;
        Ok(true)
    }
    #[cfg(not(all(target_os = "linux", feature = "openssl-backend")))]
    Err("verified release store requires the OpenSSL-enabled Linux supervisor".into())
}

/// After a verified trial fails, the next supervisor boots the retained release
/// (not the failed candidate) until the operator resets or stages newer bytes.
/// Check for crashes after reservation but before the journal reached Activated.
pub fn select_recovered(store: &UpgradeStore) -> Result<Option<Activation>, String> {
    let result = || -> boreas_supervisor::Result<Option<Activation>> {
        let Some(journal) = store.journal()? else {
            return Ok(None);
        };
        if journal.phase == boreas_supervisor::Phase::Prepared
            && store.trial_state()?.is_some_and(|t| t.version == journal.new_version)
        {
            if let boreas_supervisor::Recovery::RolledBack { active } = store.recover()? {
                return Ok(Some(Activation::RolledBack { active, candidate: journal.new_version }));
            }
            return Err(boreas_supervisor::UpgradeError::WrongState);
        }
        Ok(None)
    };
    result().map_err(|e| e.to_string())
}

pub fn validate_arguments(argv: &[OsString], schema: &str) -> Result<(), String> {
    if argv.first().is_none_or(|arg| arg != "{version}/boreas")
        || argv.get(1).is_none_or(|arg| arg != "daemon")
        || argv.get(2).is_none_or(|arg| arg != "serve" && arg != "connect")
        || schema != verified_stage::DAEMON_STATE_SCHEMA
    {
        return Err(format!(
            "verified launch requires --ready-expected-schema {} and -- '{{version}}/boreas' daemon serve|connect ...",
            verified_stage::DAEMON_STATE_SCHEMA
        ));
    }
    Ok(())
}

pub fn argv(store: &UpgradeStore, child_argv: &[OsString], expected_active: Option<&str>) -> Result<Vec<OsString>, String> {
    #[cfg(all(target_os = "linux", feature = "openssl-backend"))]
    {
        let active = store.active_version().map_err(|e| e.to_string())?;
        let active = active.as_deref().ok_or("no retained verified release to launch")?;
        if Some(active) != expected_active {
            return Err("verified active pointer disagrees with recovery".into());
        }
        let bin = verified_stage::validate_binary(store, active).map_err(|e| e.to_string())?;
        let mut argv = child_argv.to_vec();
        argv[0] = bin.into_os_string();
        Ok(argv)
    }
    #[cfg(not(all(target_os = "linux", feature = "openssl-backend")))]
    {
        let _ = (store, child_argv, expected_active);
        Err("verified launch is unavailable".into())
    }
}

/// Verified Linux children receive only stdio and the readiness socket path.
/// The supervisor listener and own fds already use CLOEXEC; mark any other
/// inherited fds too, leaving the stdlib's exec error pipe usable until exec.
/// If the kernel cannot establish this boundary, the child never executes.
#[cfg(target_os = "linux")]
pub fn protect_child(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: this pre-exec hook does only raw Linux syscalls and returns errno.
    // CLOSE_RANGE_CLOEXEC doesn't close the stdlib error-report pipe pre-exec.
    unsafe {
        let parent = libc::getpid();
        command.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Close the fork-to-prctl race if the supervisor already died.
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}
