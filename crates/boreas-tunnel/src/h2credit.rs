//! One-direction HTTP/2 receive credit: a connection window and a separate
//! window per stream.
//!
//! This ledger does not parse HTTP/2 frames, does not read sockets, and a unit
//! test is not a 30-minute RSS measurement. Do not claim G-RESOURCE or RFC 9113
//! conformance of a stack.
//!
//! One [`CreditLedger`] is one direction. The opposite direction is another
//! ledger; changing this one does not widen the peer. Connection credit and
//! stream credit are not one shared counter. [`CreditLedger::recv_data`] spends
//! both only when each window can cover the whole DATA length. There is no API
//! that shrinks a window, and this type does not encode `WINDOW_UPDATE`.

use std::collections::BTreeMap;

/// RFC 9113 initial connection flow-control window (`2^16 - 1`).
pub const INITIAL_CONNECTION_WINDOW: u32 = 65_535;

/// Inclusive upper bound on concurrent open streams accepted by [`CreditLedger::new`].
pub const MAX_CONCURRENT_STREAMS: u32 = 256;

/// Largest HTTP/2 flow-control window value (`2^31 - 1`).
pub const MAX_WINDOW_SIZE: u32 = 2_147_483_647;

/// Positive `WINDOW_UPDATE` increments a caller may send. This is not a frame.
///
/// `connection_increment` restores the released bytes, up to the connection
/// ceiling. `stream_increment` may be smaller when the stream ceiling or the
/// global budget cannot take a full re-grant; the difference is withheld, not
/// taken back from credit already in the window. A zero increment is not a
/// negative update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "dropping WINDOW_UPDATE increments loses the only record of restored credit"]
pub struct WindowUpdate {
    pub connection_increment: u32,
    pub stream_increment: u32,
}

/// Why a credit operation was refused. Refusals leave the previous totals in place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditError {
    /// Constructor arguments were outside the documented bounds.
    InvalidConfig,
    /// `n == 0` is neither DATA nor a capacity release.
    ZeroLength,
    /// Stream id 0 is the connection, not a stream. Client/server parity is not checked.
    InvalidStreamId,
    /// No stream with this id, including ids that have finished draining.
    UnknownStream,
    /// This id is already open, or still draining after close.
    DuplicateStream,
    /// Another open stream would exceed the constructor `max_streams` cap.
    MaxStreams,
    /// The stream was closed. DATA and a second close are refused.
    StreamClosed,
    /// The connection window or the stream window has fewer than `n` bytes.
    WindowExceeded,
    /// Opening a stream or raising `SETTINGS_INITIAL_WINDOW_SIZE` would pass the budget.
    BudgetExceeded,
    /// Release asked for bytes that were not received, or for bytes already released.
    ReleaseExceedsConsumed,
    /// SETTINGS would shrink a window. Granted credit is not revoked.
    CreditRevoked,
    /// A window value above `2^31 - 1` is not representable as HTTP/2 credit.
    WindowTooLarge,
    /// Checked integer arithmetic failed. State was not updated.
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamCredit {
    window: u32,
    /// DATA accepted by `recv_data` and not yet passed to `release_capacity`.
    unreleased: u32,
    closed: bool,
}

/// Receive-side connection window plus per-stream windows for a single direction.
///
/// The connection window starts at [`INITIAL_CONNECTION_WINDOW`] and is never
/// raised above that ceiling. Each open stream starts at the constructor's
/// initial window (`1..=65_535`). A later absolute SETTINGS value may raise
/// stream windows only. The constructor value is not an unconditional 64 MiB
/// grant.
///
/// `committed = sum(open stream windows) + connection window + queued bytes`
/// stays `<= receive_budget`. Queued bytes are DATA this ledger has accepted
/// and the caller has not yet released. Early release is rejected.
///
/// Closing a stream returns its unused remaining window to the budget. It does
/// not reduce the connection window and does not emit a negative update.
/// Bytes already accepted stay queued until `release_capacity`; that later
/// call may restore connection credit only.
#[derive(Debug)]
pub struct CreditLedger {
    initial_window_size: u32,
    max_streams: usize,
    receive_budget: u64,
    connection_window: u32,
    connection_ceiling: u32,
    queued_bytes: u64,
    streams: BTreeMap<u32, StreamCredit>,
}

impl CreditLedger {
    /// `initial_window_size` is the first `SETTINGS_INITIAL_WINDOW_SIZE` and must
    /// be `1..=65_535`. `max_streams` must be `1..=256`. `receive_budget` must
    /// already cover the initial connection window.
    pub fn new(
        initial_window_size: u32,
        max_streams: u32,
        receive_budget: u64,
    ) -> Result<Self, CreditError> {
        if !(1..=INITIAL_CONNECTION_WINDOW).contains(&initial_window_size) {
            return Err(CreditError::InvalidConfig);
        }
        if !(1..=MAX_CONCURRENT_STREAMS).contains(&max_streams) {
            return Err(CreditError::InvalidConfig);
        }
        if receive_budget < u64::from(INITIAL_CONNECTION_WINDOW) {
            return Err(CreditError::InvalidConfig);
        }
        let max_streams = usize::try_from(max_streams).map_err(|_| CreditError::InvalidConfig)?;
        Ok(Self {
            initial_window_size,
            max_streams,
            receive_budget,
            connection_window: INITIAL_CONNECTION_WINDOW,
            connection_ceiling: INITIAL_CONNECTION_WINDOW,
            queued_bytes: 0,
            streams: BTreeMap::new(),
        })
    }

    /// Remaining connection credit the peer may still send on this direction.
    pub const fn connection_window(&self) -> u32 {
        self.connection_window
    }

    /// Current `SETTINGS_INITIAL_WINDOW_SIZE` and the stream-window ceiling.
    pub const fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Global receive budget supplied at construction. It is not an RSS sample.
    pub const fn receive_budget(&self) -> u64 {
        self.receive_budget
    }

    /// Bytes accepted by [`Self::recv_data`] and not yet released.
    pub const fn queued_bytes(&self) -> u64 {
        self.queued_bytes
    }

    /// Open streams. Closed streams that are still draining do not count.
    pub fn open_stream_count(&self) -> usize {
        self.streams.values().filter(|stream| !stream.closed).count()
    }

    /// Remaining window of an open stream.
    pub fn stream_window(&self, stream_id: u32) -> Result<u32, CreditError> {
        match self.streams.get(&stream_id) {
            Some(stream) if stream.closed => Err(CreditError::StreamClosed),
            Some(stream) => Ok(stream.window),
            None => Err(CreditError::UnknownStream),
        }
    }

    /// Consumed-but-not-released bytes for this stream, including a closed drain.
    pub fn unreleased_bytes(&self, stream_id: u32) -> Result<u32, CreditError> {
        self.streams
            .get(&stream_id)
            .map(|stream| stream.unreleased)
            .ok_or(CreditError::UnknownStream)
    }

    /// `sum(open stream windows) + connection window + queued bytes`.
    pub fn committed(&self) -> Result<u64, CreditError> {
        self.try_committed()
    }

    /// Promise `initial_window_size` bytes of stream credit.
    ///
    /// Call this when the stream becomes active, before DATA. The new window is
    /// deducted from the global budget up front. A stream id still draining
    /// cannot be reused. Odd/even HTTP/2 role rules are not applied here.
    pub fn open_stream(&mut self, stream_id: u32) -> Result<(), CreditError> {
        if stream_id == 0 {
            return Err(CreditError::InvalidStreamId);
        }
        if self.streams.contains_key(&stream_id) {
            return Err(CreditError::DuplicateStream);
        }
        if self.open_stream_count() >= self.max_streams {
            return Err(CreditError::MaxStreams);
        }
        let next = self
            .try_committed()?
            .checked_add(u64::from(self.initial_window_size))
            .ok_or(CreditError::Overflow)?;
        if next > self.receive_budget {
            return Err(CreditError::BudgetExceeded);
        }
        self.streams.insert(
            stream_id,
            StreamCredit {
                window: self.initial_window_size,
                unreleased: 0,
                closed: false,
            },
        );
        self.assert_within_budget();
        Ok(())
    }

    /// Accept `n` bytes of DATA on `stream_id`.
    ///
    /// Both the connection window and that stream window must cover `n`. The
    /// operation then spends `n` from each. If either is short, nothing changes.
    /// `n == 0` is an error. This does not read a socket or parse a frame.
    pub fn recv_data(&mut self, stream_id: u32, n: u32) -> Result<(), CreditError> {
        if n == 0 {
            return Err(CreditError::ZeroLength);
        }
        let stream = self.stream(stream_id)?;
        if stream.closed {
            return Err(CreditError::StreamClosed);
        }
        if self.connection_window < n || stream.window < n {
            return Err(CreditError::WindowExceeded);
        }
        let new_window = stream.window - n;
        let new_unreleased = stream
            .unreleased
            .checked_add(n)
            .ok_or(CreditError::Overflow)?;
        let new_connection = self.connection_window - n;
        let new_queued = self
            .queued_bytes
            .checked_add(u64::from(n))
            .ok_or(CreditError::Overflow)?;
        let Some(slot) = self.streams.get_mut(&stream_id) else {
            return Err(CreditError::UnknownStream);
        };
        slot.window = new_window;
        slot.unreleased = new_unreleased;
        self.connection_window = new_connection;
        self.queued_bytes = new_queued;
        self.assert_within_budget();
        Ok(())
    }

    /// Caller has actually consumed `n` previously accepted bytes.
    ///
    /// Refused when those bytes were never received or were already released.
    /// On success the returned increments are what a later `WINDOW_UPDATE`
    /// encoder may advertise. The connection increment is `n`: consumed
    /// connection credit is restored, never revoked, and never raised above
    /// 65_535. The stream increment stops at the current initial-window ceiling
    /// and at whatever still fits in the receive budget. Bytes that do not fit
    /// are withheld.
    pub fn release_capacity(
        &mut self,
        stream_id: u32,
        n: u32,
    ) -> Result<WindowUpdate, CreditError> {
        if n == 0 {
            return Err(CreditError::ZeroLength);
        }
        let stream = self.stream(stream_id)?;
        if n > stream.unreleased {
            return Err(CreditError::ReleaseExceedsConsumed);
        }
        let connection_room = self
            .connection_ceiling
            .saturating_sub(self.connection_window);
        if n > connection_room {
            // Accepted bytes always reduced this window by the same amount.
            // A shortfall means the totals are already inconsistent; do not
            // paper over that by shrinking the connection ceiling.
            return Err(CreditError::Overflow);
        }
        let stream_room = if stream.closed {
            0
        } else {
            self.initial_window_size.saturating_sub(stream.window)
        };
        let mut stream_inc = n.min(stream_room);
        let slack = self.budget_slack()?;
        if u64::from(stream_inc) > slack {
            stream_inc = u32::try_from(slack).map_err(|_| CreditError::Overflow)?;
        }
        let new_unreleased = stream.unreleased - n;
        let new_window = if stream.closed {
            0
        } else {
            stream
                .window
                .checked_add(stream_inc)
                .ok_or(CreditError::Overflow)?
        };
        if !stream.closed && new_window > self.initial_window_size {
            return Err(CreditError::Overflow);
        }
        let new_connection = self
            .connection_window
            .checked_add(n)
            .ok_or(CreditError::Overflow)?;
        if new_connection > self.connection_ceiling {
            return Err(CreditError::Overflow);
        }
        let new_queued = self
            .queued_bytes
            .checked_sub(u64::from(n))
            .ok_or(CreditError::Overflow)?;
        if stream.closed && new_unreleased == 0 {
            self.streams.remove(&stream_id);
        } else if let Some(slot) = self.streams.get_mut(&stream_id) {
            slot.window = new_window;
            slot.unreleased = new_unreleased;
        } else {
            return Err(CreditError::UnknownStream);
        }
        self.connection_window = new_connection;
        self.queued_bytes = new_queued;
        self.assert_within_budget();
        Ok(WindowUpdate {
            connection_increment: n,
            stream_increment: stream_inc,
        })
    }

    /// Drop an open stream. Unused stream credit returns to the global pool.
    ///
    /// The connection window is left unchanged: this method does not emit a
    /// negative `WINDOW_UPDATE`. Accepted bytes stay queued; release them to
    /// restore connection credit. The stream id cannot be reopened until that
    /// drain finishes.
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), CreditError> {
        let stream = self.stream(stream_id)?;
        if stream.closed {
            return Err(CreditError::StreamClosed);
        }
        if stream.unreleased == 0 {
            self.streams.remove(&stream_id);
        } else if let Some(slot) = self.streams.get_mut(&stream_id) {
            slot.closed = true;
            slot.window = 0;
        } else {
            return Err(CreditError::UnknownStream);
        }
        self.assert_within_budget();
        Ok(())
    }

    /// Apply a new absolute `SETTINGS_INITIAL_WINDOW_SIZE`.
    ///
    /// Only a raise is accepted. The delta is added to every open stream window
    /// and becomes the new stream ceiling. Closed drains are left alone. The
    /// connection window is not modified. When
    /// `committed + delta * open_streams` would exceed the receive budget, or
    /// any window would pass [`MAX_WINDOW_SIZE`], the call returns an error and
    /// does not change existing streams.
    pub fn apply_initial_window_size(&mut self, new_size: u32) -> Result<(), CreditError> {
        if new_size < self.initial_window_size {
            return Err(CreditError::CreditRevoked);
        }
        if new_size > MAX_WINDOW_SIZE {
            return Err(CreditError::WindowTooLarge);
        }
        let delta = new_size - self.initial_window_size;
        if delta == 0 {
            return Ok(());
        }
        let active = u64::try_from(self.open_stream_count()).map_err(|_| CreditError::Overflow)?;
        let extra = u64::from(delta)
            .checked_mul(active)
            .ok_or(CreditError::Overflow)?;
        let next = self
            .try_committed()?
            .checked_add(extra)
            .ok_or(CreditError::Overflow)?;
        if next > self.receive_budget {
            return Err(CreditError::BudgetExceeded);
        }
        let mut grown = Vec::new();
        for (id, stream) in &self.streams {
            if stream.closed {
                continue;
            }
            let window = stream
                .window
                .checked_add(delta)
                .ok_or(CreditError::Overflow)?;
            if window > MAX_WINDOW_SIZE {
                return Err(CreditError::WindowTooLarge);
            }
            grown.push((*id, window));
        }
        self.initial_window_size = new_size;
        for (id, window) in grown {
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.window = window;
            }
        }
        self.assert_within_budget();
        Ok(())
    }

    fn stream(&self, stream_id: u32) -> Result<StreamCredit, CreditError> {
        if stream_id == 0 {
            return Err(CreditError::InvalidStreamId);
        }
        self.streams
            .get(&stream_id)
            .copied()
            .ok_or(CreditError::UnknownStream)
    }

    fn try_committed(&self) -> Result<u64, CreditError> {
        let mut sum = u64::from(self.connection_window);
        for stream in self.streams.values() {
            if stream.closed {
                continue;
            }
            sum = sum
                .checked_add(u64::from(stream.window))
                .ok_or(CreditError::Overflow)?;
        }
        sum.checked_add(self.queued_bytes)
            .ok_or(CreditError::Overflow)
    }

    fn budget_slack(&self) -> Result<u64, CreditError> {
        let committed = self.try_committed()?;
        if committed > self.receive_budget {
            return Err(CreditError::Overflow);
        }
        Ok(self.receive_budget - committed)
    }

    fn assert_within_budget(&self) {
        debug_assert!(self.try_committed().is_ok_and(|total| total <= self.receive_budget));
        debug_assert_eq!(
            self.queued_bytes,
            self.streams
                .values()
                .map(|stream| u64::from(stream.unreleased))
                .sum::<u64>()
        );
        debug_assert!(self.connection_window <= self.connection_ceiling);
        debug_assert_eq!(
            u64::from(self.connection_window) + self.queued_bytes,
            u64::from(self.connection_ceiling)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(initial: u32, max_streams: u32, extra: u64) -> CreditLedger {
        CreditLedger::new(
            initial,
            max_streams,
            u64::from(INITIAL_CONNECTION_WINDOW) + extra,
        )
        .unwrap()
    }

    #[test]
    fn initial_connection_window_refuses_one_byte_past_65535() {
        let mut credit = ledger(INITIAL_CONNECTION_WINDOW, 1, u64::from(MAX_WINDOW_SIZE));
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        credit.open_stream(1).unwrap();
        // Stream credit is above 65_535, so the refusal is the connection window.
        credit
            .apply_initial_window_size(INITIAL_CONNECTION_WINDOW + 1)
            .unwrap();
        assert_eq!(
            credit.stream_window(1).unwrap(),
            INITIAL_CONNECTION_WINDOW + 1
        );
        let before = credit.committed().unwrap();
        assert_eq!(
            credit.recv_data(1, INITIAL_CONNECTION_WINDOW + 1),
            Err(CreditError::WindowExceeded)
        );
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(
            credit.stream_window(1).unwrap(),
            INITIAL_CONNECTION_WINDOW + 1
        );
        assert_eq!(credit.queued_bytes(), 0);
        assert_eq!(credit.committed().unwrap(), before);
    }

    #[test]
    fn stream_and_connection_windows_fail_independently() {
        let mut credit = ledger(10, 1, 10);
        credit.open_stream(1).unwrap();
        assert_eq!(credit.recv_data(1, 11), Err(CreditError::WindowExceeded));
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(credit.stream_window(1).unwrap(), 10);
        assert_eq!(credit.queued_bytes(), 0);
        credit.recv_data(1, 10).unwrap();
        assert_eq!(credit.stream_window(1).unwrap(), 0);
        assert_eq!(
            credit.connection_window(),
            INITIAL_CONNECTION_WINDOW - 10
        );
        // Connection credit remains; the empty stream window still refuses.
        assert_eq!(credit.recv_data(1, 1), Err(CreditError::WindowExceeded));
        assert_eq!(credit.stream_window(1).unwrap(), 0);
        assert_eq!(
            credit.connection_window(),
            INITIAL_CONNECTION_WINDOW - 10
        );
        assert_eq!(credit.queued_bytes(), 10);

        let mut wide = ledger(INITIAL_CONNECTION_WINDOW, 2, u64::from(INITIAL_CONNECTION_WINDOW) * 2);
        wide.open_stream(1).unwrap();
        wide.open_stream(3).unwrap();
        wide.recv_data(1, INITIAL_CONNECTION_WINDOW).unwrap();
        assert_eq!(wide.connection_window(), 0);
        assert_eq!(wide.stream_window(3).unwrap(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(
            wide.recv_data(3, 1),
            Err(CreditError::WindowExceeded)
        );
        assert_eq!(wide.connection_window(), 0);
        assert_eq!(wide.stream_window(3).unwrap(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(wide.queued_bytes(), u64::from(INITIAL_CONNECTION_WINDOW));
    }

    #[test]
    fn release_requires_a_prior_consume_and_is_not_repeatable() {
        let mut credit = ledger(100, 1, 100);
        credit.open_stream(1).unwrap();
        assert_eq!(
            credit.release_capacity(1, 1),
            Err(CreditError::ReleaseExceedsConsumed)
        );
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(credit.stream_window(1).unwrap(), 100);
        assert_eq!(credit.release_capacity(1, 0), Err(CreditError::ZeroLength));
        assert_eq!(credit.recv_data(1, 0), Err(CreditError::ZeroLength));

        credit.recv_data(1, 40).unwrap();
        assert_eq!(credit.unreleased_bytes(1).unwrap(), 40);
        let update = credit.release_capacity(1, 40).unwrap();
        assert_eq!(
            update,
            WindowUpdate {
                connection_increment: 40,
                stream_increment: 40,
            }
        );
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(credit.stream_window(1).unwrap(), 100);
        assert_eq!(credit.queued_bytes(), 0);
        assert_eq!(
            credit.release_capacity(1, 40),
            Err(CreditError::ReleaseExceedsConsumed)
        );
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(credit.stream_window(1).unwrap(), 100);
    }

    #[test]
    fn settings_raise_past_the_receive_budget_is_rejected() {
        let mut credit = ledger(1_000, 2, 2_000);
        credit.open_stream(1).unwrap();
        credit.open_stream(3).unwrap();
        assert_eq!(credit.stream_window(1).unwrap(), 1_000);
        assert_eq!(credit.stream_window(3).unwrap(), 1_000);
        assert_eq!(
            credit.apply_initial_window_size(1_001),
            Err(CreditError::BudgetExceeded)
        );
        assert_eq!(credit.initial_window_size(), 1_000);
        assert_eq!(credit.stream_window(1).unwrap(), 1_000);
        assert_eq!(credit.stream_window(3).unwrap(), 1_000);
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(
            credit.apply_initial_window_size(999),
            Err(CreditError::CreditRevoked)
        );
        assert_eq!(credit.stream_window(1).unwrap(), 1_000);
    }

    #[test]
    fn closing_a_stream_does_not_walk_the_connection_window_back() {
        let mut credit = ledger(1_000, 1, 1_000);
        credit.open_stream(1).unwrap();
        credit.recv_data(1, 100).unwrap();
        let before = credit.connection_window();
        assert_eq!(before, INITIAL_CONNECTION_WINDOW - 100);
        credit.close_stream(1).unwrap();
        assert_eq!(credit.connection_window(), before);
        assert_eq!(credit.queued_bytes(), 100);
        assert_eq!(credit.recv_data(1, 1), Err(CreditError::StreamClosed));
        assert_eq!(credit.connection_window(), before);
        let update = credit.release_capacity(1, 100).unwrap();
        assert_eq!(update.connection_increment, 100);
        assert_eq!(update.stream_increment, 0);
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
        assert_eq!(credit.stream_window(1), Err(CreditError::UnknownStream));
    }

    #[test]
    fn max_streams_is_enforced_and_a_failed_open_adds_nothing() {
        assert!(matches!(
            CreditLedger::new(0, 1, u64::from(INITIAL_CONNECTION_WINDOW)),
            Err(CreditError::InvalidConfig)
        ));
        assert!(matches!(
            CreditLedger::new(
                INITIAL_CONNECTION_WINDOW + 1,
                1,
                u64::from(INITIAL_CONNECTION_WINDOW)
            ),
            Err(CreditError::InvalidConfig)
        ));
        assert!(matches!(
            CreditLedger::new(1, 0, u64::from(INITIAL_CONNECTION_WINDOW)),
            Err(CreditError::InvalidConfig)
        ));
        assert!(matches!(
            CreditLedger::new(
                1,
                MAX_CONCURRENT_STREAMS + 1,
                u64::from(INITIAL_CONNECTION_WINDOW)
            ),
            Err(CreditError::InvalidConfig)
        ));
        let mut credit = ledger(1, 2, 2);
        credit.open_stream(1).unwrap();
        credit.open_stream(3).unwrap();
        assert_eq!(credit.open_stream(5), Err(CreditError::MaxStreams));
        assert_eq!(credit.open_stream(1), Err(CreditError::DuplicateStream));
        assert_eq!(credit.open_stream(0), Err(CreditError::InvalidStreamId));
        assert_eq!(credit.open_stream_count(), 2);
        assert_eq!(credit.stream_window(5), Err(CreditError::UnknownStream));
        assert_eq!(credit.connection_window(), INITIAL_CONNECTION_WINDOW);
    }
}
