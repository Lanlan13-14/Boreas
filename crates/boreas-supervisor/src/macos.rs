//! macOS durability primitives used by the transaction backend in `lib.rs`.
//!
//! Bindings come from the target-specific `libc = "=0.2.191"` dependency; no
//! handwritten C ABI declarations or constants are used here. Both functions
//! are wired into `UpgradeStore`, and the transaction test suite runs on the
//! macOS CI targets, which is what makes this a tested backend rather than a
//! draft adapter.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

/// Ask macOS to flush a regular file through the filesystem and device cache.
/// F_FULLFSYNC is stronger than fsync on supported hardware, but cannot force
/// hardware that ignores cache-flush commands to honor them. A failure is
/// returned to the caller and is never downgraded to a plain `fsync`.
pub(crate) fn flush_file(file: &File) -> io::Result<()> {
    // SAFETY: file is a live descriptor owned by `File`; F_FULLFSYNC takes no
    // variadic argument per the macOS fcntl(2) contract.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sync a directory entry namespace. `fsync` on a directory is required for
/// rename durability ordering but is not a universal power-loss guarantee.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    let dir = File::open(path)?;
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_fullfsync_failure_is_reported_without_downgrading_to_fsync() {
        let file = File::open("/dev/null").expect("macOS /dev/null exists");
        // Character devices do not support this operation. In particular this
        // test ensures the implementation reports errors rather than claiming
        // fsync fallback has the F_FULLFSYNC semantics.
        assert!(flush_file(&file).is_err());
    }
}
