//! Operating-system CSPRNG access.
//!
//! Every helper fails closed: callers must never substitute timestamps,
//! counters, `NodeID`s, or other predictable values when entropy is
//! unavailable. On Unix the source is `/dev/urandom`; on Windows it is
//! `BCryptGenRandom` with the system-preferred RNG. Other targets report
//! [`EntropyError::Unavailable`] instead of falling back to a weaker source.
//!
//! This module contains the crate's only `unsafe` code (the Windows FFI
//! declaration). The rest of the runtime is safe Rust.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyError {
    /// The OS random source could not be opened, read, or called.
    Unavailable,
}

/// Fill `dst` with cryptographically secure random bytes.
pub fn fill(dst: &mut [u8]) -> Result<(), EntropyError> {
    if dst.is_empty() {
        return Ok(());
    }
    fill_os(dst)
}

/// Return a fresh random array. Used for WebSocket masking keys (4 bytes),
/// `connection_instance` / `circuit_id` (16 bytes) and keys (16/32 bytes).
pub fn random_array<const N: usize>() -> Result<[u8; N], EntropyError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(windows)]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut core::ffi::c_void,
        buffer: *mut u8,
        length: u32,
        flags: u32,
    ) -> i32;
}

#[cfg(windows)]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[cfg(windows)]
fn fill_os(dst: &mut [u8]) -> Result<(), EntropyError> {
    let length = u32::try_from(dst.len()).map_err(|_| EntropyError::Unavailable)?;
    // SAFETY: `dst` is a live writable buffer of exactly `length` bytes. A null
    // algorithm handle combined with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` is the
    // documented way to ask for the system-preferred RNG. The call writes only
    // inside that buffer and returns a status code.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            dst.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(EntropyError::Unavailable)
    }
}

#[cfg(unix)]
fn fill_os(dst: &mut [u8]) -> Result<(), EntropyError> {
    use std::fs::File;
    use std::io::Read as _;
    use std::sync::{Mutex, OnceLock};

    // One handle per process; the kernel device never needs reopening. A
    // poisoned mutex fails closed rather than reusing a partially read state.
    static SOURCE: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    let source = SOURCE.get_or_init(|| File::open("/dev/urandom").ok().map(Mutex::new));
    let Some(source) = source else {
        return Err(EntropyError::Unavailable);
    };
    let mut file = source.lock().map_err(|_| EntropyError::Unavailable)?;
    file.read_exact(dst).map_err(|_| EntropyError::Unavailable)
}

#[cfg(not(any(unix, windows)))]
fn fill_os(_dst: &mut [u8]) -> Result<(), EntropyError> {
    Err(EntropyError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_is_available_and_varies() {
        let first: [u8; 32] = random_array().expect("OS CSPRNG");
        let second: [u8; 32] = random_array().expect("OS CSPRNG");
        assert_ne!(first, second);
        assert!(first.iter().any(|byte| *byte != 0));
        fill(&mut []).expect("empty request is a no-op");
    }

    #[test]
    fn four_byte_mask_request_succeeds() {
        // A fresh mask is sampled per frame. Do **not** assert that two 32-bit
        // samples differ: a collision is legal with probability 2^-32, and the
        // assertion would be flaky across large CI runs.
        let mut mask = [0u8; 4];
        fill(&mut mask).expect("OS CSPRNG");
    }
}
