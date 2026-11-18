# Performance status (2026-11-18)

Observation and static-correctness note only. This file changes no gate,
threshold, retry, wait, netem profile, workflow, or acceptance criterion. It
makes no root-cause or throughput-improvement claim.

## Current gate state

- `G-PERF` remains open. The 3 Mbps floor is unchanged.
- The latest paired performance run
  [44089808664](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664)
  tested source/binary
  `7be5abff064229980c99420b6ccac735de6dcf7e`: 1 MiB **2.439 / 2.305 Mbps**
  and 8 MiB **2.879 / 2.556 Mbps**. Both samples stayed below the unchanged
  floor.
- The separate handshake-stage diagnostic
  [44085204578](https://github.com/Lanlan13-14/Boreas/actions/runs/44085204578)
  observed 1 MiB **1.737 / 1.437 Mbps** (failed) and 8 MiB
  **6.015 / 6.010 Mbps** (passed) in one short window. That is a diagnostic
  observation, not steady state and not gate evidence.
- Low throughput therefore remains **red**. Nothing in this slice changes that
  result.

## Static changes in this slice

These changes are about bounded handshake I/O, not throughput tuning.

1. **The caller's handshake budget is actually applied.**
   - `LinkClient::connect` computes one absolute deadline before the TCP dial
     and carries it through the preconnected handshake path. The new
     `LinkClient::connect_until` exposes that absolute `Instant` directly.
   - `LinkClient::connect_tcp` carries the budget remaining after the dial on
     the socket, so the reviewed `connect_preconnected` signature (which has no
     timeout argument) starts from approximately the caller's original deadline
     instead of a fresh full allowance. A directly dialed socket without a
     carried value gets a bounded fallback.
   - `LinkServer::accept_tls_stream` and the test-only plaintext accept path now
     use `io_timeout` instead of discarding it as `_io_timeout`. The new
     `LinkServer::accept_tls_stream_until` exposes the absolute deadline.
   - The outer-TLS socket has read and write timeouts installed from the
     remaining budget before the backend is called. Those are **per-syscall
     socket timeouts**, not an absolute deadline: outer TLS may perform several
     transport calls inside one `connect`/`accept` call.
2. **An owner-clone shutdown guard supplies the absolute cutoff where the
   platform supports it.**
   - `HandshakeGuard::arm` duplicates the TCP handle with `try_clone`, starts a
     watchdog thread with a `Condvar` wake-up, and calls `shutdown(Both)` on the
     duplicate when the absolute `Instant` expires. The guard never carries a
     bare integer descriptor.
   - `HARD_HANDSHAKE_DEADLINE_SUPPORTED` is true on Unix and false on Windows.
     Windows CI showed that shutdown on the `try_clone` handle does not wake a
     blocked read on the original handle, and that clone socket options are not
     a reliable shared view. Production `HandshakeGuard::arm` therefore returns
     `io::ErrorKind::Unsupported` on Windows, before outer TLS; it does not
     silently run the handshake with a weaker bound. Unit tests use an explicit
     `cfg(test)` placeholder for plaintext protocol coverage only; that fixture
     is absent from non-test builds and grants no production deadline token.
   - On supported platforms the guard is armed before outer TLS and covers the
     WebSocket upgrade, inner TLS, and the session exchange. It is disarmed and
     the thread is **always joined** after the session handshake returns; every
     error path also joins through `Drop`. A fired guard is reported as
     `TunnelError::Timeout`.
   - `DeadlineIo` remains as the operation-boundary check after outer TLS. It
     recomputes the remaining budget, installs it before every read/write, and
     refuses to start an operation after the deadline. It is not the mechanism
     that interrupts an already-blocked outer-TLS syscall; the guard is, where
     the platform supports it.
   - `ws::client_handshake_until` / `ws::server_handshake_until` accept the
     caller's absolute deadline and clamp it to the protocol upgrade budget.
     They no longer grant a fresh ten-second allowance after outer TLS has
     already spent part of the caller's budget.
   - `session::client_handshake` / `session::server_handshake` disarm the
     deadline through every wrapper layer after authorization, so an idle but
     healthy data-plane link does not inherit a handshake timeout. The clear is
     forwarded explicitly by `Box`, `WsStream`, `EstablishedStream`,
     `SslStream`, and `DeadlineIo`; every hop-handshake transport layer
     overrides both the timeout installer and the clear. Tests observe the real
     wrapper/transport calls, not a duplicated socket's option snapshot.
3. **The WebSocket frame budget keeps its overall meaning.**
   - `MAX_WS_FRAME_DEADLINE` remains 30 seconds and remains one budget for the
     whole `Read` call, covering every fragment and TLS record consumed by that
     call. It is re-checked before and after every blocking read and is not
     restarted per byte, fragment, or record.
   - A blocked syscall cannot be interrupted by a generic `Read` check alone.
     The handshake guard's socket shutdown supplies that interruption during
     the handshake, with the transport timeout as the per-call hint. No new
     per-frame deadline was added to the data plane; the existing 30-second
     per-`Read` budget is unchanged.
4. **Buffered-I/O review.**
   - The HTTP upgrade head is still read one byte at a time deliberately: a
     buffered over-read would swallow WebSocket payload bytes that follow the
     response. This is handshake-only work, not the data path.
   - No `BufReader`/`BufWriter` or hidden per-byte flush was added anywhere in
     this slice.
   - Each WebSocket frame is written as one buffer and flushed once; session
     frames are also built as one header-plus-body buffer and flushed once.
   - `DeadlineIo` adds one timeout installation per handshake read/write. It is
     disarmed before application data flows; after that it performs one relaxed
     atomic check per read/write and adds no per-byte work, so it does not add
     work to the measured throughput path beyond that branch.

## Residuals and non-claims

- The outer-TLS and inner-TLS backends own their handshake loops and may perform
  several transport reads inside one of their own calls. The socket timeouts
  installed from the remaining budget bound each syscall, not the whole backend
  call. On Unix the `HandshakeGuard` shutdown is the absolute cutoff for the hop
  handshake. On Windows production handshakes fail closed with `Unsupported`
  before outer TLS because the platform cannot provide that cutoff. This is
  reported as `RuntimeCapabilities::hard_handshake_deadline = false`; there is
  no per-syscall fallback and no claim of a hard deadline on Windows.
  A CPU-bound step after the last transport operation cannot be interrupted, but
  a guard that fired rejects the result instead of returning a session.
- The E2E TLS handshake over `CircuitStream` is outside this hop runtime guard.
  It still has no equivalent absolute socket shutdown and is **not** covered by
  the claim above. Adding one requires the E2E/circuit owner, not this slice.
- No benchmark of these changes has been run in Actions yet. This file must not
  be cited as performance evidence or as a gate pass.
- The new positive/negative coverage is in `runtime.rs` and `stream.rs`: guard
  shutdown (Unix) and disarm, guard-fired timeout classification when supported,
  real-transport clear forwarding, a deliberately clear-dropping negative
  fixture, idle exchange after the budget expires, an outer-TLS overrun test, a
  silent-peer fail-closed test, and a Windows capability test that asserts
  production `arm` returns `Unsupported` while the explicit `cfg(test)` fixture
  keeps plaintext protocol tests running. Those tests have not been run locally;
  Actions must supply the result.
- There is no claim that the low-throughput failure is caused by handshake
  deadlines, frame deadlines, or buffering. Those remain unproven.
- Build, test, and format verification must come from the applicable host
  Actions workflows. No local build, test, or formatter run is evidence here.
