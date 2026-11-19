//! Staged admission limits for unauthenticated handshakes, byte budgets, and
//! the pure growth classifier.
//!
//! `HandshakeCredit::authenticate` takes `&AuthenticatedPeer`, and that type has
//! no public constructor (`from_verified_identity` is `pub(crate)`). An
//! integration test therefore cannot move a handshake into the authenticated
//! ledger. The public substitute is: a failed `reserve_handshake` leaves the
//! handshake counter unchanged, and `reserve_bytes` is a separate counter that
//! a handshake rejection does not charge.
//!
//! `HandshakeCredit` and `ByteCredit` do not implement `Debug`, so the
//! reservations are matched on instead of unwrapped.
//!
//! Nothing here is a `G-DOS` or `G-RESOURCE` pass. `observe_sample` classifies a
//! caller-supplied series; it does not sample a process.

use boreas_tunnel::budget::{AdmissionPlan, GrowthVerdict, ResourceBudget, observe_sample, plan_attack};
use boreas_tunnel::resource::{Admission, AdmissionError, ByteCredit, HandshakeCredit, Limits};

fn limits() -> Limits {
    Limits {
        handshakes_global: 2,
        authenticated_global: 4,
        authenticated_per_peer: 1,
        bytes_global: 64,
    }
}

fn must_reserve_handshake(admission: &Admission) -> HandshakeCredit {
    match admission.reserve_handshake() {
        Ok(credit) => credit,
        Err(_) => panic!("handshake reservation refused below the cap"),
    }
}

fn must_reserve_bytes(admission: &Admission, amount: u64) -> ByteCredit {
    match admission.reserve_bytes(amount) {
        Ok(credit) => credit,
        Err(_) => panic!("byte reservation of {amount} refused under the budget"),
    }
}

#[test]
fn unauthenticated_handshakes_stop_at_the_global_cap_without_charging_bytes() {
    let admission = Admission::new(limits());
    let first = must_reserve_handshake(&admission);
    let second = must_reserve_handshake(&admission);
    assert!(matches!(
        admission.reserve_handshake(),
        Err(AdmissionError::HandshakeLimit)
    ));
    let after_reject = admission.snapshot().unwrap();
    assert_eq!(after_reject.handshakes, 2);
    assert_eq!(after_reject.authenticated, 0);
    assert_eq!(after_reject.bytes, 0);

    // The rejected attempt did not stick, and dropping one credit frees a slot
    // without ever having touched the authenticated counter.
    drop(first);
    let released = admission.snapshot().unwrap();
    assert_eq!(released.handshakes, 1);
    assert_eq!(released.authenticated, 0);
    let third = must_reserve_handshake(&admission);
    assert_eq!(admission.snapshot().unwrap().handshakes, 2);
    drop(second);
    drop(third);
    assert_eq!(admission.snapshot().unwrap().handshakes, 0);
    assert_eq!(admission.snapshot().unwrap().authenticated, 0);
}

#[test]
fn reserve_bytes_fails_closed_at_the_global_budget() {
    let admission = Admission::new(limits());
    let held = must_reserve_bytes(&admission, 40);
    assert_eq!(held.bytes(), 40);
    assert!(matches!(
        admission.reserve_bytes(25),
        Err(AdmissionError::ByteLimit)
    ));
    assert_eq!(admission.snapshot().unwrap().bytes, 40);
    assert_eq!(admission.snapshot().unwrap().authenticated, 0);

    let rest = must_reserve_bytes(&admission, 24);
    assert_eq!(admission.snapshot().unwrap().bytes, 64);
    assert!(matches!(
        admission.reserve_bytes(1),
        Err(AdmissionError::ByteLimit)
    ));
    drop(rest);
    assert_eq!(admission.snapshot().unwrap().bytes, 40);
    drop(held);
    assert_eq!(admission.snapshot().unwrap().bytes, 0);
}

#[test]
fn monotonic_growth_is_reported_and_a_fallback_is_not() {
    let budget = ResourceBudget::new(195, 291, 32, 256).unwrap();
    assert_eq!(budget.unauthenticated_handshakes, 32);

    assert_eq!(
        observe_sample(&[(100, 10), (111, 12), (130, 14)]),
        GrowthVerdict::Grew { from: 100, to: 130 }
    );
    // Strictly increasing but not more than 10% above the first sample.
    assert_eq!(
        observe_sample(&[(100, 10), (105, 11), (110, 12)]),
        GrowthVerdict::Stable
    );
    // Ends higher, but the middle sample falls back, so this is not growth.
    assert_eq!(
        observe_sample(&[(100, 10), (80, 8), (140, 20)]),
        GrowthVerdict::Stable
    );
    assert_eq!(observe_sample(&[(100, 10)]), GrowthVerdict::Stable);
}

#[test]
fn plan_attack_never_grants_more_unauthenticated_handshakes_than_the_cap() {
    let budget = ResourceBudget::new(195, 291, 32, 256).unwrap();
    let plan = plan_attack(1_000, budget.unauthenticated_handshakes);
    assert_eq!(
        plan,
        AdmissionPlan {
            granted: 32,
            refused: 968,
        }
    );
    assert!(plan.granted <= budget.unauthenticated_handshakes);

    let under = plan_attack(7, budget.unauthenticated_handshakes);
    assert_eq!(under.granted, 7);
    assert_eq!(under.refused, 0);
}
