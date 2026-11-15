//! Pure admission and growth classifier. No threads and no clock sleeps.
//!
//! G-RESOURCE requires a real run of at least 30 minutes with RSS/PSS, cgroup,
//! sockstat, queue/credit, and handshake peaks. [`observe_sample`] only
//! classifies a series the caller already collected. It does not prove that
//! run, and a [`GrowthVerdict::Stable`] result is not a gate pass.

/// Configured flow and handshake ceilings used by the simulator.
///
/// `balanced_flows` is the even-spread budget (195 in the plan).
/// `concentrated_backup_flows` is the hot-backup budget (291 in the plan) and
/// is also the hard ceiling for the balanced count. `unauthenticated_handshakes`
/// is the global pre-auth cap. `max_rss_mib` is recorded for the caller; this
/// type does not measure a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    pub balanced_flows: usize,
    pub concentrated_backup_flows: usize,
    pub unauthenticated_handshakes: usize,
    pub max_rss_mib: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// A count was zero, `balanced_flows` exceeded 291, or any count exceeded 4096.
    Rejected,
}

const MAX_CONCENTRATED: usize = 291;
const MAX_COUNT: usize = 4096;

impl ResourceBudget {
    pub fn new(
        balanced_flows: usize,
        concentrated_backup_flows: usize,
        unauthenticated_handshakes: usize,
        max_rss_mib: usize,
    ) -> Result<Self, BudgetError> {
        let counts = [
            balanced_flows,
            concentrated_backup_flows,
            unauthenticated_handshakes,
            max_rss_mib,
        ];
        if counts.iter().any(|n| *n == 0 || *n > MAX_COUNT) || balanced_flows > MAX_CONCENTRATED {
            return Err(BudgetError::Rejected);
        }
        Ok(Self {
            balanced_flows,
            concentrated_backup_flows,
            unauthenticated_handshakes,
            max_rss_mib,
        })
    }
}

/// How many unauthenticated handshakes a plan would grant.
///
/// `refused` is the remainder past the global pre-auth cap. Pre-auth identity
/// is not trusted (G-DOS): a claimed `key_id` is not an argument and cannot
/// spend another peer's authenticated budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionPlan {
    pub granted: usize,
    pub refused: usize,
}

/// Grant `min(unauthenticated, cap)` and refuse the rest.
///
/// Pre-auth identity is not trusted (G-DOS). This function takes a count only.
/// A claimed key_id string is intentionally not an argument, so it cannot be
/// charged against an authenticated peer.
pub fn plan_attack(unauthenticated: usize, cap: usize) -> AdmissionPlan {
    let granted = unauthenticated.min(cap);
    AdmissionPlan {
        granted,
        refused: unauthenticated - granted,
    }
}

/// Classification of a caller-supplied `(rss_mib, sockstat_bytes)` series.
///
/// G-RESOURCE requires a real artifact of at least 30 minutes. This enum only
/// describes the samples passed to [`observe_sample`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrowthVerdict {
    Stable,
    Grew { from: usize, to: usize },
}

/// Classify `samples` of `(rss_mib, sockstat_bytes)`.
///
/// Returns [`GrowthVerdict::Grew`] only when the series is strictly increasing
/// in both columns and the last `rss_mib` is more than 10% above the first.
/// Anything else, including a noisy series that merely ends high, is
/// [`GrowthVerdict::Stable`]. An empty or single-sample series is Stable.
///
/// G-RESOURCE requires a real >=30 min artifact. This function only classifies
/// a supplied series; it does not sample a process and does not prove that run.
pub fn observe_sample(samples: &[(usize, usize)]) -> GrowthVerdict {
    let Some((&(first_rss, first_sock), rest)) = samples.split_first() else {
        return GrowthVerdict::Stable;
    };
    if rest.is_empty() {
        return GrowthVerdict::Stable;
    }
    let mut prev_rss = first_rss;
    let mut prev_sock = first_sock;
    for &(rss, sock) in rest {
        if rss <= prev_rss || sock <= prev_sock {
            return GrowthVerdict::Stable;
        }
        prev_rss = rss;
        prev_sock = sock;
    }
    let last_rss = prev_rss;
    let limit = first_rss.saturating_mul(110);
    if last_rss.saturating_mul(100) > limit {
        GrowthVerdict::Grew {
            from: first_rss,
            to: last_rss,
        }
    } else {
        GrowthVerdict::Stable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_counts_are_accepted_only_inside_the_documented_caps() {
        let balanced = ResourceBudget::new(195, 291, 32, 256).unwrap();
        assert_eq!(balanced.balanced_flows, 195);
        let concentrated = ResourceBudget::new(291, 291, 32, 256).unwrap();
        assert_eq!(concentrated.concentrated_backup_flows, 291);
        assert_eq!(
            ResourceBudget::new(292, 291, 32, 256),
            Err(BudgetError::Rejected)
        );
        assert_eq!(
            ResourceBudget::new(0, 291, 32, 256),
            Err(BudgetError::Rejected)
        );
        assert_eq!(
            ResourceBudget::new(195, 4097, 32, 256),
            Err(BudgetError::Rejected)
        );
    }

    #[test]
    fn unauthenticated_flood_is_capped_without_a_claimed_key() {
        let plan = plan_attack(1000, 32);
        assert_eq!(plan.granted, 32);
        assert_eq!(plan.refused, 968);
    }

    #[test]
    fn growth_requires_a_strict_series_above_ten_percent() {
        assert_eq!(
            observe_sample(&[(100, 10), (100, 10), (100, 10)]),
            GrowthVerdict::Stable
        );
        assert_eq!(
            observe_sample(&[(100, 10), (105, 11), (112, 12)]),
            GrowthVerdict::Grew { from: 100, to: 112 }
        );
        // Ends high, but the middle sample drops, so this is not a growth claim.
        assert_eq!(
            observe_sample(&[(100, 10), (90, 9), (140, 20)]),
            GrowthVerdict::Stable
        );
    }
}
