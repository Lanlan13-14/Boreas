//! Honest bounds for `TCP_NODELAY`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`,
//! and `TCP_INFO`.
//!
//! Every value here is a description of what a socket option would and would
//! not mean. Nothing in this module opens a socket or calls `setsockopt`.
//! A unit test is not a throughput measurement and does not pass `G-PERF`.
//!
//! `TCP_USER_TIMEOUT` is not the business timeout. On Linux a configured `0`
//! means "use the system default"; this plan does not allow that as an
//! implicit value, so `0` is rejected rather than stored. The option applies
//! only while data is unacknowledged or the send window is blocked. It is not
//! an idle keepalive, and it says nothing about the CDN's other TCP leg.
//!
//! `TCP_NOTSENT_LOWAT` is not the congestion window and not a hard cap on
//! bytes a caller may write. The sweep below is the plan's list, including a
//! disabled point. Picking a sweep value does not prove throughput. The
//! line-rate arithmetic for 64 KiB at 1 Gbit/s lives with the scheduler and is
//! not re-measured here.
//!
//! `TCP_INFO` on one outer socket is that socket's own TCP leg. It does not
//! yield the Core application RTT across a CDN.

#![forbid(unsafe_code)]

use std::fmt;

/// Plan default: Nagle disabled (`TCP_NODELAY = 1`). Not a live socket flag.
pub const TCP_NODELAY_DEFAULT: bool = true;

/// Initial `TCP_USER_TIMEOUT`, in milliseconds.
pub const TCP_USER_TIMEOUT_DEFAULT_MS: u32 = 6_000;

/// Lowest accepted `TCP_USER_TIMEOUT`, in milliseconds. Inclusive.
pub const TCP_USER_TIMEOUT_MIN_MS: u32 = 1_000;

/// Highest accepted `TCP_USER_TIMEOUT`, in milliseconds. Inclusive.
pub const TCP_USER_TIMEOUT_MAX_MS: u32 = 120_000;

const _: () = {
    assert!(TCP_NODELAY_DEFAULT);
    assert!(TCP_USER_TIMEOUT_DEFAULT_MS == 6_000);
    assert!(TCP_USER_TIMEOUT_MIN_MS == 1_000);
    assert!(TCP_USER_TIMEOUT_MAX_MS == 120_000);
    assert!(TCP_USER_TIMEOUT_MIN_MS <= TCP_USER_TIMEOUT_DEFAULT_MS);
    assert!(TCP_USER_TIMEOUT_DEFAULT_MS <= TCP_USER_TIMEOUT_MAX_MS);
    assert!(!notsent_lowat_is_cwnd());
    assert!(!notsent_lowat_is_hard_cap());
    assert!(!same_tls_record_may_be_cloned_to_second_session());
};

/// Why a user-timeout policy value was refused. Refusal does not touch a socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpOptError {
    /// `0` would mean "system default" on Linux. This plan does not allow that.
    UserTimeoutZero,
    /// Value is `1..=999` milliseconds.
    UserTimeoutBelowMin,
    /// Value is above `120_000` milliseconds.
    UserTimeoutAboveMax,
}

impl fmt::Display for TcpOptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UserTimeoutZero => {
                "TCP_USER_TIMEOUT 0 is rejected; it is not an implicit system default"
            }
            Self::UserTimeoutBelowMin => "TCP_USER_TIMEOUT is below 1000 ms",
            Self::UserTimeoutAboveMax => "TCP_USER_TIMEOUT is above 120000 ms",
        })
    }
}

impl std::error::Error for TcpOptError {}

/// Recorded defaults for the two options this plan names. Not applied anywhere.
///
/// `user_timeout_ms` is only the TCP user timeout. There is no business-timeout
/// field, and constructing this value does not keep an idle connection alive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpOptionPolicy {
    nodelay: bool,
    user_timeout_ms: u32,
}

impl TcpOptionPolicy {
    /// `TCP_NODELAY` on, `TCP_USER_TIMEOUT` 6000 ms.
    pub const fn defaults() -> Self {
        Self {
            nodelay: TCP_NODELAY_DEFAULT,
            user_timeout_ms: TCP_USER_TIMEOUT_DEFAULT_MS,
        }
    }

    /// Plan default for `TCP_NODELAY`. `true` means the default is on.
    pub const fn nodelay(self) -> bool {
        self.nodelay
    }

    /// Configured `TCP_USER_TIMEOUT` in milliseconds. Not a business timeout.
    pub const fn user_timeout_ms(self) -> u32 {
        self.user_timeout_ms
    }

    /// Replace the user timeout with `ms`.
    ///
    /// A policy may move the value anywhere in `1_000..=120_000`, including
    /// above the 6000 ms default. `0` is rejected. Values below 1000 ms and
    /// above 120000 ms are rejected. This does not call `setsockopt`.
    pub const fn with_user_timeout_ms(self, ms: u32) -> Result<Self, TcpOptError> {
        match checked_user_timeout_ms(ms) {
            Ok(user_timeout_ms) => Ok(Self {
                nodelay: self.nodelay,
                user_timeout_ms,
            }),
            Err(err) => Err(err),
        }
    }
}

/// Accept `ms` only inside `1_000..=120_000`. `0` is its own error.
pub const fn checked_user_timeout_ms(ms: u32) -> Result<u32, TcpOptError> {
    if ms == 0 {
        return Err(TcpOptError::UserTimeoutZero);
    }
    if ms < TCP_USER_TIMEOUT_MIN_MS {
        return Err(TcpOptError::UserTimeoutBelowMin);
    }
    if ms > TCP_USER_TIMEOUT_MAX_MS {
        return Err(TcpOptError::UserTimeoutAboveMax);
    }
    Ok(ms)
}

/// Send-side condition a caller might confuse with "the timeout is running".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpSendState {
    /// No unacknowledged data and the write side is not window-blocked.
    Idle,
    /// The handshake is done and nothing is outstanding.
    EstablishedNoData,
    /// Data has been sent and not yet acknowledged.
    UnackedData,
    /// The peer window blocks further transmission.
    WindowBlocked,
    /// The connection is in `TIME_WAIT`.
    TimeWait,
}

/// `true` only for [`TcpSendState::UnackedData`] and [`TcpSendState::WindowBlocked`].
///
/// A `false` result means an idle connection is not kept alive by
/// `TCP_USER_TIMEOUT`. It also says nothing about the CDN's other TCP leg.
pub const fn user_timeout_covers(state: TcpSendState) -> bool {
    matches!(
        state,
        TcpSendState::UnackedData | TcpSendState::WindowBlocked
    )
}

/// `TCP_NOTSENT_LOWAT` is not the congestion window.
pub const fn notsent_lowat_is_cwnd() -> bool {
    false
}

/// `TCP_NOTSENT_LOWAT` is not a hard cap on bytes written to the socket.
pub const fn notsent_lowat_is_hard_cap() -> bool {
    false
}

/// Sweep points in KiB. `0` means the disabled point in this list.
///
/// No other values belong in the sweep. `0` is not passed to `setsockopt` and
/// is not a claim that the kernel's default equals zero.
pub const fn lowat_sweep_kib() -> [u32; 5] {
    [32, 64, 128, 256, 0]
}

/// No low-water value, including every sweep point, proves throughput.
pub const fn lowat_proves_throughput(_kib: u32) -> bool {
    false
}

/// One local `TCP_INFO` observation. Fields are that socket's own counters.
///
/// There is no path-RTT field. [`infers_cdn_path_rtt`] does not copy
/// `local_rtt_us` into one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpInfoSample {
    pub local_rtt_us: u32,
    pub retrans: u32,
}

/// CDN path RTT cannot be inferred from one outer socket's `TCP_INFO`.
///
/// Always [`None`], for every sample. Core application RTT is an inner probe,
/// not `local_rtt_us` and not `retrans`.
pub const fn infers_cdn_path_rtt(_: &TcpInfoSample) -> Option<u32> {
    None
}

/// First version must not clone one TLS record onto a second session.
///
/// This is the plan's ban on SYN/DNS hedging that duplicates a TLS record.
/// Hedging is not implemented here.
pub const fn same_tls_record_may_be_cloned_to_second_session() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_nodelay_on_and_user_timeout_6000() {
        let policy = TcpOptionPolicy::defaults();
        assert!(policy.nodelay());
        assert_eq!(policy.user_timeout_ms(), 6_000);
        assert_eq!(checked_user_timeout_ms(6_000), Ok(6_000));
        assert_eq!(
            policy.with_user_timeout_ms(6_000).unwrap().user_timeout_ms(),
            6_000
        );
    }

    #[test]
    fn user_timeout_zero_is_not_the_system_default() {
        assert_eq!(checked_user_timeout_ms(0), Err(TcpOptError::UserTimeoutZero));
        assert_eq!(
            TcpOptionPolicy::defaults().with_user_timeout_ms(0),
            Err(TcpOptError::UserTimeoutZero)
        );
        assert_eq!(TcpOptionPolicy::defaults().user_timeout_ms(), 6_000);
    }

    #[test]
    fn user_timeout_rejects_999_and_120001() {
        assert_eq!(
            checked_user_timeout_ms(999),
            Err(TcpOptError::UserTimeoutBelowMin)
        );
        assert_eq!(
            checked_user_timeout_ms(120_001),
            Err(TcpOptError::UserTimeoutAboveMax)
        );
        let policy = TcpOptionPolicy::defaults();
        assert_eq!(
            policy.with_user_timeout_ms(999),
            Err(TcpOptError::UserTimeoutBelowMin)
        );
        assert_eq!(
            policy.with_user_timeout_ms(120_001),
            Err(TcpOptError::UserTimeoutAboveMax)
        );
        assert_eq!(policy.user_timeout_ms(), 6_000);
    }

    #[test]
    fn user_timeout_accepts_closed_bounds_and_6000() {
        assert_eq!(checked_user_timeout_ms(1_000), Ok(1_000));
        assert_eq!(checked_user_timeout_ms(6_000), Ok(6_000));
        assert_eq!(checked_user_timeout_ms(120_000), Ok(120_000));
        let raised = TcpOptionPolicy::defaults()
            .with_user_timeout_ms(120_000)
            .unwrap();
        assert_eq!(raised.user_timeout_ms(), 120_000);
        assert!(raised.nodelay());
        let lowered = raised.with_user_timeout_ms(1_000).unwrap();
        assert_eq!(lowered.user_timeout_ms(), 1_000);
    }

    #[test]
    fn idle_does_not_count_as_covered() {
        assert!(!user_timeout_covers(TcpSendState::Idle));
        assert!(!user_timeout_covers(TcpSendState::EstablishedNoData));
        assert!(!user_timeout_covers(TcpSendState::TimeWait));
    }

    #[test]
    fn unacked_and_window_blocked_are_covered() {
        assert!(user_timeout_covers(TcpSendState::UnackedData));
        assert!(user_timeout_covers(TcpSendState::WindowBlocked));
    }

    #[test]
    fn notsent_lowat_is_neither_cwnd_nor_hard_cap() {
        assert!(!notsent_lowat_is_cwnd());
        assert!(!notsent_lowat_is_hard_cap());
    }

    #[test]
    fn lowat_sweep_is_only_the_five_plan_values() {
        let sweep = lowat_sweep_kib();
        assert_eq!(sweep, [32, 64, 128, 256, 0]);
        assert_eq!(sweep.len(), 5);
        assert_eq!(sweep[4], 0);
    }

    #[test]
    fn lowat_never_proves_throughput() {
        for kib in lowat_sweep_kib() {
            assert!(!lowat_proves_throughput(kib));
        }
        for kib in [1, 31, 33, 48, 512, u32::MAX] {
            assert!(!lowat_proves_throughput(kib));
        }
    }

    #[test]
    fn tcp_info_inference_is_none_for_different_local_rtts() {
        let low = TcpInfoSample {
            local_rtt_us: 1,
            retrans: 0,
        };
        let high = TcpInfoSample {
            local_rtt_us: 80_000,
            retrans: 4,
        };
        assert_ne!(low.local_rtt_us, high.local_rtt_us);
        assert_eq!(infers_cdn_path_rtt(&low), None);
        assert_eq!(infers_cdn_path_rtt(&high), None);
        assert_ne!(infers_cdn_path_rtt(&low), Some(low.local_rtt_us));
        assert_ne!(infers_cdn_path_rtt(&high), Some(high.local_rtt_us));
    }

    #[test]
    fn same_tls_record_is_not_cloned_to_a_second_session() {
        assert!(!same_tls_record_may_be_cloned_to_second_session());
    }
}
