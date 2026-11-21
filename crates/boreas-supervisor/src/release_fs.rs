//! The authenticated daemon must not be able to rewrite its release journal,
//! image or watermark even though it shares the dedicated service UID.
//! Restrict writes before exec; all inherited descriptors except stdio close.

use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const WRITE_FILE: u64 = 1 << 1;
const TRUNCATE: u64 = 1 << 14;
// REMOVE_DIR through REFER; no device, socket, FIFO or symlink creation needed
// outside the daemon's own state area. Unix filesystem sockets are created
// there by bind; LANDLOCK_ACCESS_FS_MAKE_SOCK also covers mknod().
const STATE_WRITE: u64 = WRITE_FILE | TRUNCATE | 0x3ff0;

#[repr(C, packed)]
struct PathRule {
    allowed_access: u64,
    parent_fd: i32,
}

pub struct ReleaseFs {
    state: PathBuf,
}

impl ReleaseFs {
    pub fn new(root: &Path, state: &Path) -> io::Result<Self> {
        boreas_supervisor::verified_stage::validate_store_path(state)?;
        let state = fs::canonicalize(state)?;
        let root = fs::canonicalize(root)?;
        if root.starts_with(&state) || state.starts_with(&root) {
            return Err(io::Error::other(
                "release store and daemon writable state must be disjoint",
            ));
        }
        Ok(Self { state })
    }

    pub fn configure(&self, command: &mut Command, daemon: bool) -> io::Result<()> {
        let handled = STATE_WRITE;
        // SAFETY: the version probe uses only null/scalar arguments.
        let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) };
        if abi < 3 {
            return Err(io::Error::other(
                "Landlock ABI 3 or newer is required for release-store isolation",
            ));
        }
        // SAFETY: the live, eight-byte ruleset attribute is copied by the kernel.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &handled,
                size_of::<u64>(),
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel returned an owned FD.
        let ruleset = unsafe { File::from_raw_fd(fd as i32) };
        if daemon {
            add_path(&ruleset, &self.state, STATE_WRITE)?;
            add_path(&ruleset, Path::new("/dev/net/tun"), WRITE_FILE)?;
        }
        // SAFETY: the capture owns the ruleset. NNP is installed by the
        // earlier pre-exec hook. This closure performs one syscall only.
        unsafe {
            command.pre_exec(move || {
                if libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

fn add_path(ruleset: &File, path: &Path, rights: u64) -> io::Result<()> {
    let path_fd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = path_fd.metadata()?;
    if rights == WRITE_FILE {
        // The TUN device node is Linux misc major 10, minor 200.
        if !meta.file_type().is_char_device()
            || libc::major(meta.rdev()) != 10
            || libc::minor(meta.rdev()) != 200
        {
            return Err(io::Error::other("/dev/net/tun is not the expected device"));
        }
    } else if !meta.is_dir() {
        return Err(io::Error::other("invalid writable state directory"));
    }
    let rule = PathRule {
        allowed_access: rights,
        parent_fd: path_fd.as_raw_fd(),
    };
    // SAFETY: rule is a live Linux landlock_path_beneath_attr (packed).
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1,
            &rule,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
