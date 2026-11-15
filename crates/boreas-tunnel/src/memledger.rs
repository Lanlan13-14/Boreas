//! Three-class memory ledger from master plan §8.2.
//!
//! [`Ledger`] records charges the caller reports. It does not measure a
//! process: it does not read RSS, PSS, cgroup memory, sockstat, or any
//! allocator. It is not `G-RESOURCE`. A unit test of this module is not a
//! pass of that gate.
//!
//! The 64 MiB Edge and 144 MiB Core figures are exploratory targets from
//! §8.2, not an acceptance limit and not a pass line.
//! [`Ledger::exploratory_target_is_acceptance_limit`] is false. The three
//! class counters are design charges, not a process memory limit.
//! [`Ledger::total_is_process_limit`] is false.

#![forbid(unsafe_code)]

/// One mebibyte, 1024 × 1024 bytes.
const MIB: u64 = 1024 * 1024;

/// 1000-byte payload used by the shared-versus-copied charge rule.
const PAYLOAD_BYTES: u64 = 1000;

/// Node role that selects the §8.2 application quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Edge,
    Core,
}

/// One of the three counters §8.2 requires to be reported separately.
///
/// They are not one process limit. [`Ledger::total_is_process_limit`] is
/// false, and the only sum this API offers is [`Ledger::sum_for_display`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// RSS / PSS application buffers the caller asked this ledger to count.
    /// Charging this class does not sample process RSS.
    RssClass,
    /// Kernel socket, skbuff, TUN, route, and conntrack units the caller
    /// chose to record. This ledger does not read the kernel.
    KernelClass,
    /// Credit already promised: in-flight buffers, temporary crypto,
    /// allocator fragmentation, reconnect peaks, and a full directory sync.
    CommittedCredit,
}

/// Application bucket inside one [`Class`].
///
/// Byte buckets are bytes. Handshake and circuit buckets are counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bucket {
    /// Payload slab pool.
    Slab,
    /// Payload bytes referenced by the L3 transmit queue.
    L3Tx,
    /// Application receive and parse cache.
    Parse,
    /// Enrollment request cache.
    Enrollment,
    /// Concurrent full inner handshakes.
    Handshakes,
    /// Active end-to-end circuits.
    Circuits,
}

/// Why [`Ledger::charge`] refused. The counters are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// `current + n` would pass that bucket's role quota.
    QuotaExceeded,
    /// `current + n` does not fit in `u64`.
    Overflow,
}

const CLASS_COUNT: usize = 3;
const BUCKET_COUNT: usize = 6;

/// Pure charge table for one role.
///
/// Counters move only when [`Ledger::charge`] accepts. There is no release
/// API and no path that replaces a refused charge with an unbounded `Vec`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ledger {
    role: Role,
    charged: [[u64; BUCKET_COUNT]; CLASS_COUNT],
}

impl Ledger {
    /// Empty ledger. The role is fixed; quotas do not change later.
    pub const fn new(role: Role) -> Self {
        Self {
            role,
            charged: [[0; BUCKET_COUNT]; CLASS_COUNT],
        }
    }

    pub const fn role(self) -> Role {
        self.role
    }

    /// Units currently charged to one class and bucket.
    pub const fn charged(self, class: Class, bucket: Bucket) -> u64 {
        self.charged[class_index(class)][bucket_index(bucket)]
    }

    /// Design quota for one role and bucket.
    ///
    /// `None` means this function does not define a numeric cap. That is the
    /// Core circuit bucket: deployment-specific, not invented here.
    pub const fn quota(role: Role, bucket: Bucket) -> Option<u64> {
        match (role, bucket) {
            (Role::Edge, Bucket::Slab) => Some(8 * MIB),
            (Role::Edge, Bucket::L3Tx) => Some(8 * MIB),
            (Role::Edge, Bucket::Parse) => Some(8 * MIB),
            (Role::Edge, Bucket::Enrollment) => Some(2 * MIB),
            (Role::Edge, Bucket::Handshakes) => Some(8),
            (Role::Edge, Bucket::Circuits) => Some(128),
            (Role::Core, Bucket::Slab) => Some(32 * MIB),
            (Role::Core, Bucket::L3Tx) => Some(24 * MIB),
            (Role::Core, Bucket::Parse) => Some(32 * MIB),
            (Role::Core, Bucket::Enrollment) => Some(8 * MIB),
            (Role::Core, Bucket::Handshakes) => Some(32),
            (Role::Core, Bucket::Circuits) => core_circuit_quota(),
        }
    }

    /// Core E2E circuit cap. Deployment-specific, not invented here.
    pub const fn core_circuit_cap() -> Option<u32> {
        None
    }

    /// False. The three counters are not one process limit.
    pub const fn total_is_process_limit() -> bool {
        false
    }

    /// False. A refused charge stays refused.
    ///
    /// Nothing in this API switches that refusal into an unbounded allocation.
    pub const fn unbounded_on_refusal() -> bool {
        false
    }

    /// Exploratory RSS-class tracking figure from §8.2.
    ///
    /// Edge is 64 MiB. Core is 144 MiB. This is not an acceptance limit and
    /// not a pass line. [`Self::charge`] does not consult it.
    pub const fn exploratory_target(role: Role) -> u64 {
        match role {
            Role::Edge => 64 * MIB,
            Role::Core => 144 * MIB,
        }
    }

    /// False. Missing the exploratory target is not a ledger error, and
    /// staying under it does not waive a bucket quota.
    pub const fn exploratory_target_is_acceptance_limit() -> bool {
        false
    }

    /// Charge for one 1000-byte payload named by two queues.
    ///
    /// Returns 1000 when `copied` is false (both queues name the same bytes)
    /// and 2000 when `copied` is true (each queue holds its own copy). This
    /// is a pure function of the flag, not an allocator.
    ///
    /// The caller has to pass the truth; this function cannot see the allocator.
    pub const fn same_payload_charged_twice(copied: bool) -> u64 {
        if copied { PAYLOAD_BYTES * 2 } else { PAYLOAD_BYTES }
    }

    /// Adds the three class counters so a display can show one number.
    ///
    /// The sum is not a budget and not an RSS measurement. It is not a
    /// process limit. Addition saturates at `u64::MAX` instead of panicking;
    /// saturation is still only a display clamp.
    pub const fn sum_for_display(self) -> u64 {
        let mut total = 0u64;
        let mut class_i = 0;
        while class_i < CLASS_COUNT {
            let mut bucket_i = 0;
            while bucket_i < BUCKET_COUNT {
                total = total.saturating_add(self.charged[class_i][bucket_i]);
                bucket_i += 1;
            }
            class_i += 1;
        }
        total
    }

    /// Charge `n` units to one class's bucket.
    ///
    /// Refuses when that bucket would pass its role quota. A refusal leaves
    /// every counter unchanged. There is no fallback that turns the refusal
    /// into an unbounded allocation.
    ///
    /// The exploratory target is not consulted. A charge inside the bucket
    /// quota is `Ok` even when [`Self::sum_for_display`] would then pass
    /// [`Self::exploratory_target`]. A charge past the bucket quota is an
    /// error even when the sum would stay under that target.
    ///
    /// A bucket whose [`Self::quota`] is `None` has no numeric cap in this
    /// function. It still refuses on `u64` overflow, and it still does not
    /// allocate.
    pub fn charge(&mut self, class: Class, bucket: Bucket, n: u64) -> Result<(), LedgerError> {
        let cell = &mut self.charged[class_index(class)][bucket_index(bucket)];
        let next = cell.checked_add(n).ok_or(LedgerError::Overflow)?;
        if let Some(cap) = Self::quota(self.role, bucket)
            && next > cap
        {
            return Err(LedgerError::QuotaExceeded);
        }
        *cell = next;
        Ok(())
    }
}

const fn core_circuit_quota() -> Option<u64> {
    match Ledger::core_circuit_cap() {
        Some(cap) => Some(cap as u64),
        None => None,
    }
}

const fn class_index(class: Class) -> usize {
    match class {
        Class::RssClass => 0,
        Class::KernelClass => 1,
        Class::CommittedCredit => 2,
    }
}

const fn bucket_index(bucket: Bucket) -> usize {
    match bucket {
        Bucket::Slab => 0,
        Bucket::L3Tx => 1,
        Bucket::Parse => 2,
        Bucket::Enrollment => 3,
        Bucket::Handshakes => 4,
        Bucket::Circuits => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_unchanged(before: Ledger, after: Ledger) {
        assert_eq!(after, before);
        assert_eq!(after.sum_for_display(), before.sum_for_display());
    }

    #[test]
    fn flags_are_const_false_and_targets_are_not_a_pass_line() {
        assert!(!Ledger::total_is_process_limit());
        assert!(!Ledger::unbounded_on_refusal());
        assert!(!Ledger::exploratory_target_is_acceptance_limit());
        assert_eq!(Ledger::exploratory_target(Role::Edge), 64 * MIB);
        assert_eq!(Ledger::exploratory_target(Role::Core), 144 * MIB);
        assert_eq!(Ledger::core_circuit_cap(), None);
    }

    #[test]
    fn edge_quotas_match_section_8_2() {
        assert_eq!(Ledger::quota(Role::Edge, Bucket::Slab), Some(8 * MIB));
        assert_eq!(Ledger::quota(Role::Edge, Bucket::L3Tx), Some(8 * MIB));
        assert_eq!(Ledger::quota(Role::Edge, Bucket::Parse), Some(8 * MIB));
        assert_eq!(Ledger::quota(Role::Edge, Bucket::Enrollment), Some(2 * MIB));
        assert_eq!(Ledger::quota(Role::Edge, Bucket::Handshakes), Some(8));
        assert_eq!(Ledger::quota(Role::Edge, Bucket::Circuits), Some(128));
    }

    #[test]
    fn core_quotas_match_section_8_2_and_circuits_are_uncapped_here() {
        assert_eq!(Ledger::quota(Role::Core, Bucket::Slab), Some(32 * MIB));
        assert_eq!(Ledger::quota(Role::Core, Bucket::L3Tx), Some(24 * MIB));
        assert_eq!(Ledger::quota(Role::Core, Bucket::Parse), Some(32 * MIB));
        assert_eq!(Ledger::quota(Role::Core, Bucket::Enrollment), Some(8 * MIB));
        assert_eq!(Ledger::quota(Role::Core, Bucket::Handshakes), Some(32));
        assert_eq!(Ledger::quota(Role::Core, Bucket::Circuits), None);
        assert_eq!(Ledger::core_circuit_cap(), None);
    }

    #[test]
    fn capped_buckets_accept_the_quota_and_refuse_one_past_it() {
        let cases = [
            (Role::Edge, Bucket::Slab, 8 * MIB),
            (Role::Edge, Bucket::L3Tx, 8 * MIB),
            (Role::Edge, Bucket::Parse, 8 * MIB),
            (Role::Edge, Bucket::Enrollment, 2 * MIB),
            (Role::Edge, Bucket::Handshakes, 8),
            (Role::Edge, Bucket::Circuits, 128),
            (Role::Core, Bucket::Slab, 32 * MIB),
            (Role::Core, Bucket::L3Tx, 24 * MIB),
            (Role::Core, Bucket::Parse, 32 * MIB),
            (Role::Core, Bucket::Enrollment, 8 * MIB),
            (Role::Core, Bucket::Handshakes, 32),
        ];
        for (role, bucket, cap) in cases {
            assert_eq!(Ledger::quota(role, bucket), Some(cap));
            for class in [Class::RssClass, Class::KernelClass, Class::CommittedCredit] {
                let mut ledger = Ledger::new(role);
                assert_eq!(ledger.charge(class, bucket, cap), Ok(()));
                assert_eq!(ledger.charged(class, bucket), cap);
                let before = ledger;
                assert_eq!(
                    ledger.charge(class, bucket, 1),
                    Err(LedgerError::QuotaExceeded)
                );
                assert_unchanged(before, ledger);
                assert_eq!(ledger.charge(class, bucket, 0), Ok(()));
                assert_eq!(ledger.charged(class, bucket), cap);
            }
        }
    }

    #[test]
    fn partial_fill_that_would_cross_the_quota_does_not_move() {
        let mut ledger = Ledger::new(Role::Edge);
        let cap = 8 * MIB;
        assert_eq!(ledger.charge(Class::RssClass, Bucket::Slab, cap - 1), Ok(()));
        let before = ledger;
        assert_eq!(
            ledger.charge(Class::RssClass, Bucket::Slab, 2),
            Err(LedgerError::QuotaExceeded)
        );
        assert_unchanged(before, ledger);
        assert_eq!(ledger.charged(Class::RssClass, Bucket::Slab), cap - 1);
        assert_eq!(ledger.charged(Class::KernelClass, Bucket::Slab), 0);
        assert_eq!(ledger.charged(Class::CommittedCredit, Bucket::Slab), 0);
    }

    #[test]
    fn one_shot_overshoot_from_zero_leaves_every_counter_at_zero() {
        let mut ledger = Ledger::new(Role::Core);
        let before = ledger;
        assert_eq!(
            ledger.charge(Class::KernelClass, Bucket::Parse, 32 * MIB + 1),
            Err(LedgerError::QuotaExceeded)
        );
        assert_unchanged(before, ledger);
        assert_eq!(ledger.sum_for_display(), 0);
        assert!(!Ledger::unbounded_on_refusal());
    }

    #[test]
    fn overflow_refusal_does_not_wrap_the_counter() {
        let mut ledger = Ledger::new(Role::Core);
        assert_eq!(
            ledger.charge(Class::CommittedCredit, Bucket::Circuits, u64::MAX),
            Ok(())
        );
        let before = ledger;
        assert_eq!(
            ledger.charge(Class::CommittedCredit, Bucket::Circuits, 1),
            Err(LedgerError::Overflow)
        );
        assert_unchanged(before, ledger);
        assert_eq!(ledger.charged(Class::CommittedCredit, Bucket::Circuits), u64::MAX);
    }

    #[test]
    fn core_circuits_have_no_numeric_cap_including_1024() {
        assert_eq!(Ledger::core_circuit_cap(), None);
        let mut ledger = Ledger::new(Role::Core);
        assert_eq!(ledger.charge(Class::RssClass, Bucket::Circuits, 1024), Ok(()));
        assert_eq!(ledger.charge(Class::RssClass, Bucket::Circuits, 1), Ok(()));
        assert_eq!(ledger.charged(Class::RssClass, Bucket::Circuits), 1025);
        assert_eq!(
            ledger.charge(Class::KernelClass, Bucket::Circuits, 10_000),
            Ok(())
        );
        assert_eq!(ledger.charged(Class::KernelClass, Bucket::Circuits), 10_000);
    }

    #[test]
    fn classes_do_not_share_one_bucket_quota() {
        let mut ledger = Ledger::new(Role::Edge);
        let slab = 8 * MIB;
        for class in [Class::RssClass, Class::KernelClass, Class::CommittedCredit] {
            assert_eq!(ledger.charge(class, Bucket::Slab, slab), Ok(()));
            assert_eq!(ledger.charged(class, Bucket::Slab), slab);
        }
        assert_eq!(ledger.sum_for_display(), slab * 3);
        let before = ledger;
        assert_eq!(
            ledger.charge(Class::RssClass, Bucket::Slab, 1),
            Err(LedgerError::QuotaExceeded)
        );
        assert_unchanged(before, ledger);
        assert!(!Ledger::total_is_process_limit());
    }

    #[test]
    fn charging_past_the_exploratory_target_inside_a_quota_is_ok() {
        for role in [Role::Edge, Role::Core] {
            let target = Ledger::exploratory_target(role);
            let mut ledger = Ledger::new(role);
            let buckets = [
                Bucket::Slab,
                Bucket::L3Tx,
                Bucket::Parse,
                Bucket::Enrollment,
            ];
            let mut crossed = false;
            for class in [Class::RssClass, Class::KernelClass, Class::CommittedCredit] {
                for bucket in buckets {
                    let cap = Ledger::quota(role, bucket).expect("byte buckets are capped");
                    let before_sum = ledger.sum_for_display();
                    assert_eq!(ledger.charge(class, bucket, cap), Ok(()));
                    let after_sum = ledger.sum_for_display();
                    assert_eq!(after_sum, before_sum + cap);
                    if before_sum <= target && after_sum > target {
                        crossed = true;
                    }
                }
            }
            assert!(crossed);
            assert!(ledger.sum_for_display() > target);
            assert!(!Ledger::exploratory_target_is_acceptance_limit());
        }
    }

    #[test]
    fn over_bucket_quota_errors_while_the_sum_stays_under_the_target() {
        for role in [Role::Edge, Role::Core] {
            let mut ledger = Ledger::new(role);
            let target = Ledger::exploratory_target(role);
            let enrollment = Ledger::quota(role, Bucket::Enrollment).expect("capped");
            assert_eq!(
                ledger.charge(Class::RssClass, Bucket::Enrollment, enrollment),
                Ok(())
            );
            let slab = Ledger::quota(role, Bucket::Slab).expect("capped");
            assert!(ledger.sum_for_display() + slab + 1 < target);
            let before = ledger;
            assert_eq!(
                ledger.charge(Class::RssClass, Bucket::Slab, slab + 1),
                Err(LedgerError::QuotaExceeded)
            );
            assert_unchanged(before, ledger);
            assert!(ledger.sum_for_display() < target);
        }
    }

    #[test]
    fn same_payload_charges_once_unless_the_caller_says_it_was_copied() {
        assert_eq!(Ledger::same_payload_charged_twice(false), 1000);
        assert_eq!(Ledger::same_payload_charged_twice(true), 2000);
        let mut ledger = Ledger::new(Role::Edge);
        let shared = Ledger::same_payload_charged_twice(false);
        let copied = Ledger::same_payload_charged_twice(true);
        assert_eq!(ledger.charge(Class::RssClass, Bucket::L3Tx, shared), Ok(()));
        assert_eq!(ledger.charged(Class::RssClass, Bucket::L3Tx), 1000);
        assert_eq!(ledger.charge(Class::KernelClass, Bucket::L3Tx, copied), Ok(()));
        assert_eq!(ledger.charged(Class::KernelClass, Bucket::L3Tx), 2000);
        assert_eq!(ledger.sum_for_display(), 3000);
    }
}
