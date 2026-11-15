//! First-install trust boundary (master plan §10.5).
//!
//! # What this module is
//!
//! A pure decision. [`install_outcome`] records which stop the caller has
//! already reached: a pre-trusted external verifier plus a static-ELF check
//! and `self-check`, an explicit weak-HTTPS acceptance, or a refusal.
//! [`UnitExample`] holds the §10.5 unit numbers and says they are examples.
//! [`restart_on_failure_is_rollback`] says relaunching a crashed process is
//! not an upgrade rollback.
//!
//! # What this module is not
//!
//! No installer script is written. Nothing is downloaded, staged, renamed, or
//! executed. This function does not verify ML-DSA, Ed25519, a manifest hash,
//! a size, duplicate JSON keys, expiry, `sequence`, root rotation, an artifact
//! path, or an upgrade journal. [`SCRIPT_VERIFIES_ML_DSA`] is `false`.
//! `G-SUPPLY` is not passed. A candidate `self-check` is not the trust root.

#![forbid(unsafe_code)]

use std::fmt;

/// Example `MemoryHigh=512M` from master plan §10.5. Not a budget.
pub const EXAMPLE_MEMORY_HIGH_BYTES: u64 = 512 * 1024 * 1024;
/// Example `MemoryMax=1G` from master plan §10.5. Not a budget.
///
/// A host whose RAM is 1 GiB cannot run this example: the cgroup ceiling is
/// the whole machine, and `MemoryMax` can still end in an OOM kill.
pub const EXAMPLE_MEMORY_MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// Example `LimitMEMLOCK=8M` from master plan §10.5.
///
/// Locked pages for the long-term identity key and signing key only. Traffic
/// keys and ephemeral KEM private keys are outside this example.
pub const EXAMPLE_MEMLOCK_BYTES: u64 = 8 * 1024 * 1024;

/// 1 GiB, the host size §10.5 says cannot run [`EXAMPLE_MEMORY_MAX_BYTES`].
pub const ONE_GIBIBYTE: u64 = 1024 * 1024 * 1024;

/// Who already verified the release, if anyone.
///
/// Fetching a script and a hash from the same unauthenticated source is not
/// [`Verifier::PreTrustedExternal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verifier {
    /// An external checker the administrator trusted before this install.
    /// Manifest dual-signature and artifact-hash checks belong to that
    /// checker. This module does not perform them and does not verify ML-DSA.
    PreTrustedExternal,
    /// HTTPS (or HTTP) fetch with no pre-trusted checker.
    HttpsOnly,
    /// No verifier and no transport claim.
    None,
}

/// §10.5 systemd example values. Documented as examples, not a budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnitExample {
    /// `MemoryHigh`, in bytes.
    pub memory_high: u64,
    /// `MemoryMax`, in bytes.
    pub memory_max: u64,
    /// `LimitMEMLOCK`, in bytes.
    pub memlock: u64,
}

/// Stop recorded by [`install_outcome`].
///
/// No variant formats as `后量子可信安装完成`. This function did not verify
/// ML-DSA on any path, including [`Outcome::ReadyToExec`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The external verifier did the signature check. This function did not
    /// verify ML-DSA. ELF static check and `self-check` were recorded as
    /// passed by the caller. Still not a post-quantum install: `G-SUPPLY`
    /// is not passed.
    ReadyToExec,
    /// No pre-trusted verifier. The administrator explicitly accepted the
    /// weaker HTTPS bootstrap. Stop here. This is not a post-quantum install.
    WeakHttpsAccepted,
    /// A required check failed, weak HTTPS was not explicitly accepted, or
    /// there is no verifier. Nothing may be activated.
    Refused(&'static str),
}

/// The §10.5 example unit. Not a measured budget.
#[must_use]
pub const fn unit_example() -> UnitExample {
    UnitExample {
        memory_high: EXAMPLE_MEMORY_HIGH_BYTES,
        memory_max: EXAMPLE_MEMORY_MAX_BYTES,
        memlock: EXAMPLE_MEMLOCK_BYTES,
    }
}

/// `false`: `MemoryHigh` / `MemoryMax` / `LimitMEMLOCK` above are examples.
#[must_use]
pub const fn example_is_a_budget() -> bool {
    false
}

/// Whether `example` can run on a 1 GiB machine.
///
/// `false` when `memory_max` is at least 1 GiB. The §10.5 example has
/// `memory_max` of 1 GiB, so that example does not fit. Do not lower the
/// example to make this return `true`.
#[must_use]
pub const fn fits_one_gib_machine(example: &UnitExample) -> bool {
    example.memory_max < ONE_GIBIBYTE
}

/// `false`. The POSIX `sh` installer does not verify ML-DSA (§10.5).
/// Dual-signature verification belongs to a pre-trusted external verifier.
pub const SCRIPT_VERIFIES_ML_DSA: bool = false;

/// `false`. See [`SCRIPT_VERIFIES_ML_DSA`].
#[must_use]
pub const fn script_verifies_mldsa() -> bool {
    false
}

/// Decide the §10.5 first-install stop.
///
/// `admin_accepts_weak_https` is read only on [`Verifier::HttpsOnly`]. It does
/// not promote a missing verifier, and it does not replace a failed ELF or
/// `self-check` on the pre-trusted path.
#[must_use]
pub const fn install_outcome(
    verifier: Verifier,
    admin_accepts_weak_https: bool,
    elf_static_ok: bool,
    self_check_ok: bool,
) -> Outcome {
    match verifier {
        Verifier::PreTrustedExternal => {
            if !elf_static_ok {
                return Outcome::Refused("ELF architecture/static-interpreter check did not pass");
            }
            if !self_check_ok {
                return Outcome::Refused("candidate self-check did not pass");
            }
            Outcome::ReadyToExec
        }
        Verifier::HttpsOnly => {
            if admin_accepts_weak_https {
                Outcome::WeakHttpsAccepted
            } else {
                Outcome::Refused(
                    "no pre-trusted verifier; weak HTTPS bootstrap was not explicitly accepted",
                )
            }
        }
        Verifier::None => Outcome::Refused(
            "no verifier; a binary checking itself is not the trust root",
        ),
    }
}

/// `false` for every variant. No outcome is a post-quantum install.
#[must_use]
pub const fn claims_post_quantum_install(outcome: Outcome) -> bool {
    match outcome {
        Outcome::ReadyToExec | Outcome::WeakHttpsAccepted | Outcome::Refused(_) => false,
    }
}

/// `Restart=on-failure` relaunches the same binary. That is not rollback.
///
/// Rollback is the supervisor changing the active version pointer, then
/// starting that version. Starting the broken version again is not it.
#[must_use]
pub const fn restart_on_failure_is_rollback() -> bool {
    false
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadyToExec => f.write_str(
                "external verifier, static ELF check, and self-check were recorded; \
                 the installer script did not verify ML-DSA",
            ),
            Self::WeakHttpsAccepted => f.write_str(
                "stopped at weak HTTPS bootstrap after explicit administrator acceptance; \
                 signature was not verified",
            ),
            Self::Refused(reason) => write!(f, "install refused: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forbidden(outcome: Outcome) -> bool {
        outcome.to_string().contains("后量子可信安装完成")
    }

    #[test]
    fn pretrusted_static_elf_and_self_check_records_ready() {
        let outcome = install_outcome(Verifier::PreTrustedExternal, false, true, true);
        assert_eq!(outcome, Outcome::ReadyToExec);
        assert!(!script_verifies_mldsa());
        assert_eq!(script_verifies_mldsa(), SCRIPT_VERIFIES_ML_DSA);
        assert!(!claims_post_quantum_install(outcome));
        assert!(!forbidden(outcome));
        assert!(outcome.to_string().contains("did not verify ML-DSA"));
    }

    #[test]
    fn pretrusted_accept_flag_does_not_change_a_passing_record() {
        let outcome = install_outcome(Verifier::PreTrustedExternal, true, true, true);
        assert_eq!(outcome, Outcome::ReadyToExec);
        assert!(!claims_post_quantum_install(outcome));
    }

    #[test]
    fn pretrusted_failed_elf_or_self_check_is_refused() {
        let elf = install_outcome(Verifier::PreTrustedExternal, true, false, true);
        let check = install_outcome(Verifier::PreTrustedExternal, false, true, false);
        assert!(matches!(elf, Outcome::Refused(_)));
        assert!(matches!(check, Outcome::Refused(_)));
        assert_ne!(elf, Outcome::ReadyToExec);
        assert_ne!(check, Outcome::WeakHttpsAccepted);
        assert!(!claims_post_quantum_install(elf));
        assert!(!claims_post_quantum_install(check));
        assert!(!forbidden(elf));
        assert!(!forbidden(check));
    }

    #[test]
    fn https_only_without_acceptance_is_refused() {
        let outcome = install_outcome(Verifier::HttpsOnly, false, true, true);
        assert!(matches!(outcome, Outcome::Refused(_)));
        assert_ne!(outcome, Outcome::ReadyToExec);
        assert_ne!(outcome, Outcome::WeakHttpsAccepted);
        assert!(!claims_post_quantum_install(outcome));
        assert!(!forbidden(outcome));
    }

    #[test]
    fn https_only_with_explicit_acceptance_stops_at_weak_bootstrap() {
        let outcome = install_outcome(Verifier::HttpsOnly, true, true, true);
        assert_eq!(outcome, Outcome::WeakHttpsAccepted);
        assert_ne!(outcome, Outcome::ReadyToExec);
        assert!(!claims_post_quantum_install(outcome));
        assert!(!forbidden(outcome));
        assert!(outcome.to_string().contains("HTTPS"));
    }

    #[test]
    fn no_verifier_is_refused_even_when_self_check_passes() {
        let outcome = install_outcome(Verifier::None, true, true, true);
        assert!(matches!(outcome, Outcome::Refused(_)));
        assert_ne!(outcome, Outcome::ReadyToExec);
        assert_ne!(outcome, Outcome::WeakHttpsAccepted);
        assert!(!claims_post_quantum_install(outcome));
        assert!(!forbidden(outcome));
        let quiet = install_outcome(Verifier::None, false, false, false);
        assert!(matches!(quiet, Outcome::Refused(_)));
    }

    #[test]
    fn no_outcome_claims_a_post_quantum_install() {
        let samples = [
            Outcome::ReadyToExec,
            Outcome::WeakHttpsAccepted,
            Outcome::Refused("no pre-trusted verifier"),
        ];
        for outcome in samples {
            assert!(!claims_post_quantum_install(outcome));
            assert!(!forbidden(outcome));
        }
    }

    #[test]
    fn example_unit_is_not_a_budget_and_misses_a_one_gib_machine() {
        let example = unit_example();
        assert_eq!(example.memory_high, 512 * 1024 * 1024);
        assert_eq!(example.memory_max, 1024 * 1024 * 1024);
        assert_eq!(example.memlock, 8 * 1024 * 1024);
        assert_eq!(example.memory_max, ONE_GIBIBYTE);
        assert!(example.memory_high < example.memory_max);
        assert!(!example_is_a_budget());
        assert!(!fits_one_gib_machine(&example));
        assert!(!fits_one_gib_machine(&UnitExample {
            memory_high: example.memory_high,
            memory_max: ONE_GIBIBYTE,
            memlock: example.memlock,
        }));
    }

    #[test]
    fn restart_on_failure_does_not_roll_back() {
        assert!(!restart_on_failure_is_rollback());
    }
}
