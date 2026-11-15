//! Staggered drain overlap reservation (master plan §6.4, last bullet).
//!
//! # What this module is
//!
//! Steady capacity is `N` connections. A drain may hold the old set and one
//! new connection at once, so the first reservation may be `N + 1`.
//! [`reserve`] accepts `want` only when `already + want <= steady_n + 1`.
//! The returned count is that sum. It is allowed to be `steady_n + 1` and
//! is **not** reported as if steady `N` already covered the overlap.
//!
//! [`switch_before_authenticated`] is `false`. The new connection must be
//! authenticated before the caller switches. [`reserve`] only records the
//! reservation; a successful reserve is not permission to switch.
//!
//! # What this module is not
//!
//! This is not a connection scheduler, a CDN-limit client, or a global quota
//! enforcer. It does not open sockets, authenticate peers, or move traffic.
//! `G-RESOURCE`, `G-UPGRADE`, and `G-UI` are not passed.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

/// The new connection must be authenticated before any switch.
///
/// This is a policy constant, not a connection state. Callers must not treat
/// a [`reserve`] success as authentication or as a completed switch.
pub const fn switch_before_authenticated() -> bool {
    false
}

/// Why a drain reservation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainError {
    /// Steady capacity `N` must be at least 1. Zero is not "reserve the +1".
    ZeroSteady,
    /// A reservation of nothing is not a drain slot.
    ZeroWant,
    /// `already + want` or `steady_n + 1` does not fit in `u32`.
    Overflow,
    /// `already + want` is above `steady_n + 1`. The overlap is one extra
    /// connection, not a second full copy of steady `N`.
    ExceedsTransient {
        steady_n: u32,
        already: u32,
        want: u32,
        limit: u32,
    },
}

impl fmt::Display for DrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSteady => f.write_str("drain steady capacity N must be non-zero"),
            Self::ZeroWant => f.write_str("drain reservation want must be non-zero"),
            Self::Overflow => f.write_str("drain reservation count overflowed u32"),
            Self::ExceedsTransient {
                steady_n,
                already,
                want,
                limit,
            } => write!(
                f,
                "drain reservation {already}+{want} exceeds transient limit {limit} (steady N={steady_n} plus one)"
            ),
        }
    }
}

impl Error for DrainError {}

/// Reserve `want` additional drain slots against steady capacity `steady_n`.
///
/// Accepts only when `already + want <= steady_n + 1`. Rejects `want == 0`
/// and `steady_n == 0`. On success returns `already + want`, which may be
/// `steady_n + 1`. That return value is the overlap count; it does not mean
/// steady `N` covers the overlap, and it does not authorize a switch
/// ([`switch_before_authenticated`] stays false).
pub fn reserve(steady_n: u32, already: u32, want: u32) -> Result<u32, DrainError> {
    if steady_n == 0 {
        return Err(DrainError::ZeroSteady);
    }
    if want == 0 {
        return Err(DrainError::ZeroWant);
    }
    let Some(limit) = steady_n.checked_add(1) else {
        return Err(DrainError::Overflow);
    };
    let Some(sum) = already.checked_add(want) else {
        return Err(DrainError::Overflow);
    };
    if sum > limit {
        return Err(DrainError::ExceedsTransient {
            steady_n,
            already,
            want,
            limit,
        });
    }
    debug_assert!(sum == already + want);
    debug_assert!(sum <= steady_n + 1);
    // Do not clamp to steady_n. The +1 is the reservation, not hidden capacity.
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_requires_authentication_first() {
        assert!(!switch_before_authenticated());
    }

    #[test]
    fn first_reservation_may_be_n_plus_one() {
        let steady_n = 4u32;
        let held = reserve(steady_n, 0, steady_n + 1).expect("N+1 first");
        assert_eq!(held, steady_n + 1);
        assert_ne!(
            held, steady_n,
            "steady N must not be reported as covering the overlap"
        );
    }

    #[test]
    fn filling_steady_then_one_extra_is_the_same_cap() {
        let steady_n = 3u32;
        let held = reserve(steady_n, 0, steady_n).expect("steady fill");
        assert_eq!(held, steady_n);
        let held = reserve(steady_n, held, 1).expect("one extra");
        assert_eq!(held, steady_n + 1);
        assert!(!switch_before_authenticated());
    }

    #[test]
    fn second_extra_is_rejected() {
        let steady_n = 3u32;
        let err = reserve(steady_n, steady_n + 1, 1).unwrap_err();
        assert_eq!(
            err,
            DrainError::ExceedsTransient {
                steady_n,
                already: steady_n + 1,
                want: 1,
                limit: steady_n + 1,
            }
        );
    }

    #[test]
    fn want_above_n_plus_one_from_empty_is_rejected() {
        let err = reserve(2, 0, 4).unwrap_err();
        assert_eq!(
            err,
            DrainError::ExceedsTransient {
                steady_n: 2,
                already: 0,
                want: 4,
                limit: 3,
            }
        );
    }

    #[test]
    fn zero_want_and_zero_steady_are_rejected() {
        assert_eq!(reserve(4, 0, 0), Err(DrainError::ZeroWant));
        assert_eq!(reserve(4, 2, 0), Err(DrainError::ZeroWant));
        assert_eq!(reserve(0, 0, 1), Err(DrainError::ZeroSteady));
        // steady 0 wins over want 0 so "N = 0, reserve nothing" cannot pass.
        assert_eq!(reserve(0, 0, 0), Err(DrainError::ZeroSteady));
    }

    #[test]
    fn overflow_is_not_wrapped_into_an_accept() {
        assert_eq!(reserve(u32::MAX, 0, 1), Err(DrainError::Overflow));
        assert_eq!(reserve(1, u32::MAX, 1), Err(DrainError::Overflow));
        assert_eq!(reserve(1, u32::MAX - 1, 2), Err(DrainError::Overflow));
    }

    #[test]
    fn exact_limit_from_a_partial_hold_is_accepted() {
        assert_eq!(reserve(8, 7, 2).expect("7+2 = 9 = N+1"), 9);
        assert_eq!(reserve(1, 0, 1).expect("steady one"), 1);
        assert_eq!(reserve(1, 0, 2).expect("the single extra"), 2);
        assert!(reserve(1, 1, 2).is_err());
    }
}
