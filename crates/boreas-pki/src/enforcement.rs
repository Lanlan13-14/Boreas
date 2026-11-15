//! Fail-closed business forwarding when a status snapshot is stale or the
//! trusted UTC clock cannot be used.
//!
//! Freshness is only the signed `next_update` compared with a caller-supplied
//! trusted UTC. Receiving the same snapshot again does not extend life: this
//! module has no `last_received_at` and never consults a local receive clock.
//!
//! This is not revocation application. Nothing here verifies a revocation
//! signature or tears down a TLS session, so gate `G-REVOKE` is not passed.

use crate::CLOCK_ROLLBACK_TOLERANCE_US;

/// What a daemon must stop doing. There is no variant and no boolean that
/// keeps existing flows up: stale means stop existing business packets too.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Snapshot `next_update` is strictly after trusted UTC, and observed UTC
    /// is not more than 60 seconds behind the persisted trusted floor.
    Forward,
    /// Snapshot is not strictly fresh, or trusted UTC is missing. Control
    /// plane may continue; business forwarding, including packets already in
    /// flight, must stop.
    StopBusiness,
    /// Observed UTC stepped back by more than 60 seconds. Business forwarding
    /// stops, but the cause is clock repair rather than a stale snapshot.
    ClockHold,
}

/// `trusted_now_us == None` means the clock is unusable.
/// `observed_utc_us + 60s < last_trusted_utc_us` is the rollback hold.
/// A re-delivered snapshot cannot appear here; only these signed timestamps
/// decide freshness.
pub fn forwarding_decision(
    snapshot_next_update_us: u64,
    trusted_now_us: Option<u64>,
    last_trusted_utc_us: u64,
    observed_utc_us: u64,
) -> Decision {
    // Rollback is checked first so a far-future next_update cannot hide it.
    if observed_utc_us.saturating_add(CLOCK_ROLLBACK_TOLERANCE_US) < last_trusted_utc_us {
        return Decision::ClockHold;
    }
    match trusted_now_us {
        Some(now) if snapshot_next_update_us > now => Decision::Forward,
        Some(_) | None => Decision::StopBusiness,
    }
}

/// Control-plane sync and management recovery stay open in every decision.
/// Keeping the daemon alive is not permission to forward user traffic.
pub fn control_plane_allowed(decision: Decision) -> bool {
    matches!(
        decision,
        Decision::StopBusiness | Decision::ClockHold | Decision::Forward
    )
}

/// Business packets, new sessions and existing flows, move only while fresh.
pub fn business_forwarding_allowed(decision: Decision) -> bool {
    matches!(decision, Decision::Forward)
}

/// An unverified revocation is not a reason to disconnect someone else.
/// A verified revocation is applied by the trust layer, which this module
/// does not implement.
pub fn forged_revocation_disconnects() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000_000;

    #[test]
    fn one_microsecond_of_life_still_forwards() {
        let d = forwarding_decision(NOW + 1, Some(NOW), NOW, NOW);
        assert_eq!(d, Decision::Forward);
        assert!(business_forwarding_allowed(d));
        assert!(control_plane_allowed(d));
    }

    #[test]
    fn next_update_equal_to_now_stops_business_and_keeps_control() {
        let d = forwarding_decision(NOW, Some(NOW), NOW, NOW);
        assert_eq!(d, Decision::StopBusiness);
        assert!(!business_forwarding_allowed(d));
        assert!(control_plane_allowed(d));
    }

    #[test]
    fn missing_trusted_clock_stops_business() {
        let d = forwarding_decision(NOW + 1_000_000, None, NOW, NOW);
        assert_eq!(d, Decision::StopBusiness);
        assert!(!business_forwarding_allowed(d));
        assert!(control_plane_allowed(d));
    }

    #[test]
    fn exactly_sixty_seconds_behind_still_forwards_when_snapshot_is_fresh() {
        let observed = NOW - CLOCK_ROLLBACK_TOLERANCE_US;
        let d = forwarding_decision(NOW + 1, Some(NOW), NOW, observed);
        assert_eq!(d, Decision::Forward);
        assert!(business_forwarding_allowed(d));
    }

    #[test]
    fn one_microsecond_past_sixty_seconds_holds_the_clock() {
        let observed = NOW - CLOCK_ROLLBACK_TOLERANCE_US - 1;
        let d = forwarding_decision(NOW + 1, Some(NOW), NOW, observed);
        assert_eq!(d, Decision::ClockHold);
        assert!(!business_forwarding_allowed(d));
        assert!(control_plane_allowed(d));
    }

    #[test]
    fn clock_hold_wins_even_when_next_update_is_far_ahead() {
        let observed = NOW - 60_000_000 - 1;
        let d = forwarding_decision(u64::MAX, Some(NOW), NOW, observed);
        assert_eq!(d, Decision::ClockHold);
        assert!(!business_forwarding_allowed(d));
        assert!(control_plane_allowed(d));
    }

    #[test]
    fn forged_revocation_does_not_disconnect() {
        assert!(!forged_revocation_disconnects());
    }
}
