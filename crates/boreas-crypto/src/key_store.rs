//! On-disk key policy from master plan §4.4.
//!
//! Pure policy: this module does not call `mlock`, does not draw from the OS
//! CSPRNG, does not generate key bytes, and does not write a secret to disk.
//! [`may_persist`] returning true is a permission, not a save path. There is no
//! `save` method. No type here can hold or serialize a TLS traffic secret or a
//! key-and-counter pair.
//!
//! Satisfying these checks does not pass `G-CRYPTO`.

#![forbid(unsafe_code)]

use core::fmt;

/// Class of secret the storage rules keep apart.
///
/// Master plan §4.4 separates the node identity private key, management
/// signing keys, TLS traffic secrets, and the release signing key. Ephemeral
/// KEM/DH private keys are a fifth class with the same persistence ban as
/// traffic secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretClass {
    /// Long-term node identity private key.
    IdentityPrivate,
    /// Management-object signing key.
    ManagementSigning,
    /// TLS traffic secret. Must not be stored or resumed.
    TlsTraffic,
    /// Release-manifest signing key. Not the network identity root.
    ReleaseSigning,
    /// Ephemeral KEM or DH private key, including a one-time `key_share`.
    EphemeralKex,
}

/// Whether a secret of this class may reside on disk at all.
///
/// `true` means the class is not forbidden from persistence. It does not write
/// a key. Traffic secrets and ephemeral KEM/DH private keys must not be stored.
pub const fn may_persist(class: SecretClass) -> bool {
    match class {
        SecretClass::IdentityPrivate
        | SecretClass::ManagementSigning
        | SecretClass::ReleaseSigning => true,
        SecretClass::TlsTraffic | SecretClass::EphemeralKex => false,
    }
}

/// Whether a forwarding core may hold this class as an Edge–Edge E2E secret.
///
/// Master plan §4.4: a forwarding core never holds an Edge–Edge end-to-end
/// session secret. The answer is false for every [`SecretClass`]. The match is
/// exhaustive so a new class cannot become allowed by omission.
pub const fn core_may_hold_edge_e2e(class: SecretClass) -> bool {
    match class {
        SecretClass::IdentityPrivate
        | SecretClass::ManagementSigning
        | SecretClass::TlsTraffic
        | SecretClass::ReleaseSigning
        | SecretClass::EphemeralKex => false,
    }
}

/// File permission bits required for a persisted private key (`0600`).
pub const FILE_MODE: u32 = 0o600;

/// Directory permission bits required for a key directory (`0700`).
pub const DIRECTORY_MODE: u32 = 0o700;

const PERMISSION_MASK: u32 = 0o777;

/// Which inode shape [`accept_mode`] is judging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeKind {
    /// A regular key file. Permission bits must be exactly [`FILE_MODE`].
    File,
    /// A key directory. Permission bits must be exactly [`DIRECTORY_MODE`].
    Directory,
}

/// Accept only an exact permission mode.
///
/// Keeps the low 9 bits (`mode & 0o777`) and requires equality with [`FILE_MODE`]
/// or [`DIRECTORY_MODE`]. `0o640`, `0o644`, `0o666`, and `0o700` are rejected
/// for a file. `0o755` is rejected for a directory. File-type and set-id bits
/// sit above this mask and are not accepted or rejected here.
pub const fn accept_mode(kind: ModeKind, mode: u32) -> bool {
    let bits = mode & PERMISSION_MASK;
    match kind {
        ModeKind::File => bits == FILE_MODE,
        ModeKind::Directory => bits == DIRECTORY_MODE,
    }
}

/// Accept a key inode only when it has exactly one directory entry.
///
/// `nlink == 2` is a hard link and is rejected. `nlink == 0` is not a live name.
pub const fn accept_link_count(nlink: u64) -> bool {
    nlink == 1
}

/// Symbolic links are never an acceptable key file or key directory.
pub const fn accept_symlink() -> bool {
    false
}

/// Key-file replacement must stay on one filesystem so `rename` can be atomic.
///
/// This is only the requirement. This module does not create, rename, or
/// `fsync` a file.
pub const fn same_filesystem_required() -> bool {
    true
}

/// Traffic keys and their counters are not resumed after a restart.
///
/// Master plan §4.4 forbids persisting a traffic key, an ephemeral KEM/DH
/// private key, or a recoverable TLS session snapshot. §10.3 forbids
/// serializing a TLS traffic key in order to continue a counter. Restart
/// rebuilds the channel. This module has no type that can store either value.
pub const fn resume_traffic_keys_after_restart() -> bool {
    false
}

/// Whether every backend-internal copy of a private key is known to be locked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Coverage {
    /// Not proved. Master plan §4.4 records this gap as `[待证]`.
    Unproven,
    /// The claim §4.4 forbids: that every private key is never swapped out.
    /// This module never returns it.
    Proven,
}

/// Report whether `mlock` on a Rust wrapper covers the backend's own copies.
///
/// Returns [`Coverage::Unproven`]. Quoting the plan: mlocking a Rust wrapper
/// does not prove the backend's internal copies are locked, and mlock is not
/// disk encryption and does not stop root.
///
/// An opaque backend's internal copies still have to be checked before anyone
/// claims they are locked or zeroed. When that coverage cannot be proved,
/// record `[待证]` and do not claim that every private key is never swapped
/// out. This function does not call `mlock`.
pub const fn mlock_covers_backend_copies() -> Coverage {
    Coverage::Unproven
}

/// A storage-policy failure. The only variant carries no key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// A timestamp or node id was offered as a seed. No key bytes were produced.
    SeedForbidden,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

/// Refuse a timestamp or node id as a key seed.
///
/// Master plan §4.4 forbids using a timestamp or `NodeID` as a random seed.
/// Both arguments are discarded. They are not copied into the error and are
/// not mixed into any 32-byte value. This function does not read a CSPRNG and
/// does not generate a key.
pub const fn seed_from_time_or_node_id(_time: u64, _node: u16) -> Result<[u8; 32], StoreError> {
    Err(StoreError::SeedForbidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn may_persist_rejects_traffic_and_ephemeral() {
        let allowed = [
            SecretClass::IdentityPrivate,
            SecretClass::ManagementSigning,
            SecretClass::ReleaseSigning,
        ];
        for class in allowed {
            let persist = may_persist(class);
            assert!(persist, "{class:?}");
        }
        let forbidden = [SecretClass::TlsTraffic, SecretClass::EphemeralKex];
        for class in forbidden {
            let persist = may_persist(class);
            assert!(!persist, "{class:?}");
        }
    }

    #[test]
    fn forwarding_core_never_holds_edge_e2e() {
        let classes = [
            SecretClass::IdentityPrivate,
            SecretClass::ManagementSigning,
            SecretClass::TlsTraffic,
            SecretClass::ReleaseSigning,
            SecretClass::EphemeralKex,
        ];
        for class in classes {
            let held = core_may_hold_edge_e2e(class);
            assert!(!held, "{class:?}");
        }
    }

    #[test]
    fn persisted_file_mode_is_exactly_0600() {
        assert_eq!(FILE_MODE, 0o600);
        let accepted_modes = [0o600_u32, 0o100_000 | 0o600, 0o600 | 0o1000];
        for mode in accepted_modes {
            let accepted = accept_mode(ModeKind::File, mode);
            assert!(accepted, "{mode:#o}");
        }
        let rejected_modes = [
            0o640_u32,
            0o644,
            0o666,
            0o700,
            0o400,
            0o000,
            0o601,
            0o620,
            0o755,
            0o777,
            u32::MAX,
        ];
        for mode in rejected_modes {
            let accepted = accept_mode(ModeKind::File, mode);
            assert!(!accepted, "{mode:#o}");
        }
    }

    #[test]
    fn persisted_directory_mode_is_exactly_0700() {
        assert_eq!(DIRECTORY_MODE, 0o700);
        let accepted_modes = [0o700_u32, 0o040_000 | 0o700, 0o700 | 0o1000];
        for mode in accepted_modes {
            let accepted = accept_mode(ModeKind::Directory, mode);
            assert!(accepted, "{mode:#o}");
        }
        let rejected_modes = [
            0o755_u32,
            0o600,
            0o640,
            0o644,
            0o666,
            0o701,
            0o000,
            0o777,
            u32::MAX,
        ];
        for mode in rejected_modes {
            let accepted = accept_mode(ModeKind::Directory, mode);
            assert!(!accepted, "{mode:#o}");
        }
    }

    #[test]
    fn hard_link_count_above_one_is_rejected() {
        let single = accept_link_count(1);
        assert!(single);
        for nlink in 0..9_u64 {
            let accepted = accept_link_count(nlink);
            let only_one = nlink == 1;
            assert_eq!(accepted, only_one, "nlink {nlink}");
        }
        let doubled = accept_link_count(2);
        assert!(!doubled);
        let unlinked = accept_link_count(0);
        assert!(!unlinked);
        let saturated = accept_link_count(u64::MAX);
        assert!(!saturated);
    }

    #[test]
    fn symlink_is_rejected() {
        let accepted = accept_symlink();
        assert!(!accepted);
    }

    #[test]
    fn same_filesystem_is_required() {
        let required = same_filesystem_required();
        assert!(required);
    }

    #[test]
    fn traffic_keys_are_not_resumed_after_restart() {
        let resume = resume_traffic_keys_after_restart();
        assert!(!resume);
    }

    #[test]
    fn mlock_coverage_stays_unproven() {
        let coverage = mlock_covers_backend_copies();
        assert_eq!(coverage, Coverage::Unproven);
        assert_ne!(coverage, Coverage::Proven);
    }

    #[test]
    fn seed_inputs_never_become_key_material() {
        let time_a: u64 = 0x0123_4567_89AB_CDEF;
        let node_a: u16 = 0x0F1E;
        let time_b: u64 = 0xFEDC_BA98_7654_3210;
        let node_b: u16 = 0xA5A5;
        let times_differ = time_a != time_b;
        let nodes_differ = node_a != node_b;
        assert!(times_differ);
        assert!(nodes_differ);

        let first = seed_from_time_or_node_id(time_a, node_a);
        let second = seed_from_time_or_node_id(time_b, node_b);
        assert_eq!(first, second);
        assert_eq!(first, Err(StoreError::SeedForbidden));
        let error_size = core::mem::size_of::<StoreError>();
        assert_eq!(error_size, 0);

        let rendered = match first {
            Ok(_bytes) => panic!("seed ban returned key material"),
            Err(err) => format!("{err:?} {err}"),
        };
        assert!(rendered.chars().all(|ch| !ch.is_ascii_digit()));
        let tokens = [
            time_a.to_string(),
            time_b.to_string(),
            node_a.to_string(),
            node_b.to_string(),
            format!("{time_a:x}"),
            format!("{time_a:X}"),
            format!("{time_b:x}"),
            format!("{time_b:X}"),
            format!("{node_a:x}"),
            format!("{node_a:X}"),
            format!("{node_b:x}"),
            format!("{node_b:X}"),
        ];
        for token in tokens {
            assert!(
                !rendered.contains(token.as_str()),
                "{token} leaked into {rendered}"
            );
        }
    }
}
