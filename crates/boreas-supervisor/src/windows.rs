//! Windows filesystem primitives (intentionally not exported by `lib.rs` yet).
//!
//! The APIs below use the generated `windows-sys = 0.61.2` bindings, not
//! handwritten ABI declarations. File data flush and namespace replacement are
//! exposed as distinct operations. Windows currently has no portable,
//! documented equivalent of POSIX parent-directory fsync for this crate's
//! transaction contract; therefore this module cannot claim durable directory
//! entries or power-loss-safe journal transitions. Integrators must keep the
//! Windows backend fail-closed until that boundary is resolved and tested.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FlushFileBuffers, GetFileInformationByHandle,
    MoveFileExW, ReplaceFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
};

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    if path.as_os_str().encode_wide().any(|c| c == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"));
    }
    Ok(path.as_os_str().encode_wide().chain(Some(0)).collect())
}

/// Flush buffered file data with the documented Win32 `FlushFileBuffers` API.
/// The `File` must have been opened with write access. Success does not prove
/// storage hardware honored a volatile-cache flush.
pub(crate) fn flush_file(file: &File) -> io::Result<()> {
    // SAFETY: the raw handle is borrowed from a live `File` for the call.
    let ok = unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Replace one regular file using the OS replacement primitive. Existing
/// destinations use `ReplaceFileW` (same-volume by contract); a first install
/// uses `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` or `COPY_ALLOWED` so
/// an existing destination and cross-volume move fail rather than overwrite or
/// copy-delete. Caller flushes the staged file first. This is namespace
/// replacement, NOT a claim of directory-entry power-loss durability.
pub(crate) fn replace_file_namespace(staged: &Path, destination: &Path) -> io::Result<()> {
    validate_single_link_file(staged)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path has no parent")
    })?;
    if !same_volume(staged, destination_parent)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staged file and destination directory are on different volumes",
        ));
    }
    let staged_w = wide(staged)?;
    let destination_w = wide(destination)?;
    let destination_exists = match std::fs::symlink_metadata(destination) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "replacement destination must be a regular non-symlink file",
                ));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };

    let ok = if destination_exists {
        // REPLACEFILE_WRITE_THROUGH is documented as unsupported; pass zero.
        // SAFETY: both NUL-terminated UTF-16 strings live through the call;
        // optional pointers are null as permitted by ReplaceFileW.
        unsafe {
            ReplaceFileW(
                destination_w.as_ptr(),
                staged_w.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        // MOVEFILE_WRITE_THROUGH is used, but Microsoft documents its flush
        // guarantee for copy/delete moves; COPY_ALLOWED is deliberately absent.
        // Thus same-volume metadata persistence is not upgraded to a claim here.
        unsafe { MoveFileExW(staged_w.as_ptr(), destination_w.as_ptr(), MOVEFILE_WRITE_THROUGH) }
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Query a path without following a final reparse point and reject reparse
/// points/symlinks. This does not replace trusted-root/ACL and race controls;
/// handle-relative traversal is needed for hostile concurrent writers.
pub(crate) fn reject_reparse_leaf(path: &Path, directory: bool) -> io::Result<()> {
    let path_w = wide(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
    // SAFETY: path pointer remains valid; null security/template pointers are
    // permitted. Sharing is broad to avoid spuriously failing inspection.
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a live handle; close it exactly once.
    let file = unsafe { File::from_raw_handle(handle as _) };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is writable and handle remains live for the call.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse point is not accepted",
        ));
    }
    drop(file);
    Ok(())
}

/// Reject multiply-linked files using metadata from the same no-follow handle
/// that was checked for the reparse-point attribute.
pub(crate) fn validate_single_link_file(path: &Path) -> io::Result<()> {
    let path_w = wide(path)?;
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle as _) };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse point is not accepted",
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected regular file, found directory",
        ));
    }
    if info.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hard-linked files are not accepted",
        ));
    }
    drop(file);
    Ok(())
}

/// Compare volume serials using open handles. Rejecting reparse points on both
/// paths remains the caller's responsibility; same-volume does not establish
/// that a path is beneath a trusted root.
pub(crate) fn same_volume(left: &Path, right: &Path) -> io::Result<bool> {
    fn volume(path: &Path) -> io::Result<u32> {
        let path_w = wide(path)?;
        let handle = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle as _) };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "reparse point is not accepted"));
        }
        let serial = info.dwVolumeSerialNumber;
        drop(file);
        Ok(serial)
    }
    Ok(volume(left)? == volume(right)?)
}

/// Deliberately fail closed until the service's exact security principal is
/// known and a restrictive DACL is created/verified with reviewed Windows ACL
/// APIs. The default inherited ACL is not accepted as an implicit private-store
/// policy.
pub(crate) fn ensure_private_store_acl(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "explicit Windows store DACL creation/verification is not implemented",
    ))
}

/// Deliberately fail closed: FlushFileBuffers documents file-handle flushing,
/// not the directory-entry durability contract required for the journal.
pub(crate) fn sync_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows parent-directory durability is not implemented; transaction backend must remain disabled",
    ))
}
