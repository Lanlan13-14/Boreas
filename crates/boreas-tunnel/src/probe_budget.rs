//! Detection budget from §8.5. A computed sum is not a measured failover.
//!
//! G-FAILOVER is not passed. This module does not send probes.

pub const PROBE_INTERVAL_MS: u64 = 2_000;
pub const FAIL_THRESHOLD: u32 = 3;
pub const BACKOFF_MAX_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Components {
    pub detect_ms: u64,
    pub backoff_ms: u64,
    pub handshake_rtt_ms: u64,
    pub handshake_trips: u32,
    pub authorize_ms: u64,
    pub rebuild_ms: u64,
    pub first_success_rtt_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Budget {
    /// The sum is only a lower bound. It is not a P99.
    Floor { sum_ms: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    Zero,
    Overflow,
    BackoffAboveMax,
    MissingComponent,
}

/// Loopback handshake time is not a term in this sum.
pub const fn loopback_counts_as_proof() -> bool {
    false
}

/// TCP probe misses are not a public-network loss percentage.
pub const fn probe_miss_is_path_loss() -> bool {
    false
}

pub fn recovery_floor(c: Components) -> Result<Budget, BudgetError> {
    if c.detect_ms == 0
        || c.handshake_rtt_ms == 0
        || c.handshake_trips == 0
        || c.first_success_rtt_ms == 0
    {
        return Err(BudgetError::MissingComponent);
    }
    if c.backoff_ms > BACKOFF_MAX_MS {
        return Err(BudgetError::BackoffAboveMax);
    }
    let trips = u64::from(c.handshake_trips);
    let handshake = c
        .handshake_rtt_ms
        .checked_mul(trips)
        .ok_or(BudgetError::Overflow)?;
    let sum = c
        .detect_ms
        .checked_add(c.backoff_ms)
        .and_then(|v| v.checked_add(handshake))
        .and_then(|v| v.checked_add(c.authorize_ms))
        .and_then(|v| v.checked_add(c.rebuild_ms))
        .and_then(|v| v.checked_add(c.first_success_rtt_ms))
        .ok_or(BudgetError::Overflow)?;
    Ok(Budget::Floor { sum_ms: sum })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_misses_are_only_the_detect_term() {
        assert!(!loopback_counts_as_proof());
        assert!(!probe_miss_is_path_loss());
        assert_eq!(PROBE_INTERVAL_MS * u64::from(FAIL_THRESHOLD), 6_000);
        let floor = recovery_floor(Components {
            detect_ms: 6_000,
            backoff_ms: 1_000,
            handshake_rtt_ms: 200,
            handshake_trips: 4,
            authorize_ms: 100,
            rebuild_ms: 100,
            first_success_rtt_ms: 200,
        })
        .unwrap();
        assert_eq!(floor, Budget::Floor { sum_ms: 8_200 });
        assert!(
            recovery_floor(Components {
                detect_ms: 6_000,
                backoff_ms: 1_001,
                handshake_rtt_ms: 1,
                handshake_trips: 1,
                authorize_ms: 0,
                rebuild_ms: 0,
                first_success_rtt_ms: 1,
            })
            .is_err()
        );
    }
}
