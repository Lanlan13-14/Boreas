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
            && store
                .trial_state()?
                .is_some_and(|t| t.version == journal.new_version)
        {
            if let boreas_supervisor::Recovery::RolledBack { active } = store.recover()? {
                return Ok(Some(Activation::RolledBack {
                    active,
                    candidate: journal.new_version,
                }));
            }
            return Err(boreas_supervisor::UpgradeError::WrongState);
        }
        Ok(None)
    };
    result().map_err(|e| e.to_string())
}

pub fn validate_arguments(argv: &[OsString], schema: &str) -> Result<(), String> {
    if argv
        .iter()
        .any(|arg| arg == "--virtual-tun" || arg == "--max-packets" || arg == "--max-seconds")
        || argv.first().is_none_or(|arg| arg != "{version}/boreas")
        || argv.get(1).is_none_or(|arg| arg != "daemon")
        || argv
            .get(2)
            .is_none_or(|arg| arg != "serve" && arg != "connect")
        || schema != verified_stage::DAEMON_STATE_SCHEMA
    {
        return Err(format!(
            "verified launch requires --ready-expected-schema {} and -- '{{version}}/boreas' daemon serve|connect ...",
            verified_stage::DAEMON_STATE_SCHEMA
        ));
    }
    Ok(())
}

pub struct Image {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
}

impl Image {
    #[cfg(target_os = "linux")]
    pub fn program(&self) -> OsString {
        use std::os::fd::AsRawFd;
        format!("/proc/self/fd/{}", self.file.as_raw_fd()).into()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn program(&self) -> OsString {
        unreachable!("verified images only exist on Linux")
    }

    #[cfg(unix)]
    pub fn matches_process(&self, pid: u32) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let expected = self.file.metadata()?;
            let actual = std::fs::metadata(format!("/proc/{pid}/exe"))?;
            if (actual.dev(), actual.ino()) == (expected.dev(), expected.ino()) {
                return Ok(());
            }
        }
        let _ = pid;
        Err(std::io::Error::other(
            "readiness peer is not executing the sealed release image",
        ))
    }
}

pub fn image(
    store: &UpgradeStore,
    expected_active: Option<&str>,
    min_run_sequence: u64,
) -> Result<Image, String> {
    #[cfg(all(target_os = "linux", feature = "openssl-backend"))]
    {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::PermissionsExt;

        let active = store.active_version().map_err(|e| e.to_string())?;
        let active = active
            .as_deref()
            .ok_or("no retained verified release to launch")?;
        if Some(active) != expected_active {
            return Err("verified active pointer disagrees with recovery".into());
        }
        if verified_stage::sequence(active).map_err(|e| e.to_string())? < min_run_sequence {
            return Err(
                "verified release is below the operator's minimum runnable sequence".into(),
            );
        }
        let (_, bytes) =
            verified_stage::checked_binary(store, active).map_err(|e| e.to_string())?;
        // Execute an immutable copy of exactly the bytes hashed above. An open
        // file alone would pin the inode, but not prevent its contents changing.
        // MFD_EXEC is explicit on kernels with memfd execution policy (6.3+).
        let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
        // SAFETY: constant NUL-terminated name and scalar flags.
        let mut fd = unsafe { libc::memfd_create(c"boreas-verified".as_ptr(), flags | 0x0010) };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            // SAFETY: same constant name, legacy scalar flags.
            fd = unsafe { libc::memfd_create(c"boreas-verified".as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: memfd_create returned a fresh owned descriptor.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.set_permissions(std::fs::Permissions::from_mode(0o500))
            .map_err(|e| e.to_string())?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        // SAFETY: fcntl takes this live owned fd and a scalar seal mask.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Image { file })
    }
    #[cfg(not(all(target_os = "linux", feature = "openssl-backend")))]
    {
        let _ = (store, expected_active, min_run_sequence);
        Err("verified launch is unavailable".into())
    }
}

/// Only the supervisor sends systemd readiness. The candidate never inherits
/// NOTIFY_SOCKET; on manual launches there is no systemd notification to send.
#[cfg(unix)]
pub fn notify_ready() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(raw) = std::env::var_os("NOTIFY_SOCKET") {
        use std::os::{
            linux::net::SocketAddrExt,
            unix::{
                ffi::OsStrExt,
                net::{SocketAddr, UnixDatagram},
            },
        };
        let bytes = raw.as_bytes();
        let addr = match bytes.first() {
            Some(b'@') => SocketAddr::from_abstract_name(&bytes[1..])?,
            Some(b'/') => SocketAddr::from_pathname(Path::new(&raw))?,
            _ => return Err(std::io::Error::other("invalid NOTIFY_SOCKET")),
        };
        UnixDatagram::unbound()?.send_to_addr(b"READY=1", &addr)?;
    }
    Ok(())
}

/// Verified Linux children receive only stdio and the readiness socket path.
/// The supervisor listener and own fds already use CLOEXEC; mark any other
/// inherited fds too, leaving the stdlib's exec error pipe usable until exec.
/// If the kernel cannot establish this boundary, the child never executes.
#[cfg(target_os = "linux")]
pub fn protect_child(command: &mut std::process::Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;

    for fd in 0..=2 {
        // Stdio may be a journal socket or pipe; never accept an inherited
        // Internet socket in one of the conventional descriptor slots.
        let mut family = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        // SAFETY: getsockopt only writes to live output variables.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut family as *mut i32).cast(),
                &mut len,
            )
        };
        if rc == 0 && family != libc::AF_UNIX {
            return Err(std::io::Error::other(
                "verified service refuses inherited non-Unix sockets on stdio",
            ));
        }
        if rc != 0
            && !matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTSOCK) | Some(libc::EBADF)
            )
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    // SAFETY: there are no arguments; these calls read process credentials.
    if unsafe { libc::geteuid() == 0 || libc::getuid() == 0 } {
        return Err(std::io::Error::other(
            "verified child must run unprivileged, not as root",
        ));
    }
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
    Ok(())
}
