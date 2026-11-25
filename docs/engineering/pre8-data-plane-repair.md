# pre.8 data-plane repair — working acceptance record

Baseline: `002c80dd3ec5cbc6806c10ec8f0dc3613aa6aea0` (`main` / `v0.1.0-pre.7`).
Authoritative scope: user attachment `Boreas-pre7-complete-spec.md` (2026-11-25).
This is a working record, **not a completion or performance claim**.

## Current production changes

1. `262c426`: empty ReadAhead fills once before borrowed first-packet delivery; same-cursor partial completion, bounded interrupts, clean EOF, poison on failed delivery.
2. `8616f9e`: daemon configures after DNS/replica binding; ordinary packets in mixed DNS use the borrowed path; one classifier gives Core DNS, Edge DNS, then host order. DNS handlers keep live authority/transaction checks. ReadAhead owns its Admission byte credit, exhaustion falls back.
3. `13677ca`: CircuitStream hands back the allocation only after consuming its final byte; FrameIo and FrameDecoder have at most one recycled relay body, count actual capacities, and retain 8KiB feed/error atomicity.
4. **Not repaired yet:** established bidirectional progress. `d33c733` adds barrier evidence for synchronous partial-L3 stalling, not an acceptance success. Need TLS-midrecord, WS-across-TLS, relay-across-feed, and L3-prefix cases with role reversal and control. No unconditional declaration that blocking I/O is safe.

## Actual verification

- Actions `45625097371` @ `7dfe368`: integration **failed**. All 5 new prefetch tests passed, tunnel library 276 tests and real-WSS integration 19 tests passed. Failure was an omitted production `drive_business_path` caller in `private_dns_replica.rs` (compile E0061); `4c0d828` fixes that caller with an explicit zero optional-prefetch budget.
- Security `45625094097` / `45625108990`, real TUN `45625093577` / `45625120950`, interop `45625093511`: success on the first candidate.
- Actions `45626408835` @ `d33c733`: integration **failed** to compile newly added event-order fixture: AuthorizedEndpoints was moved across split iterations. Local source now constructs a new unique binding per split; not yet revalidated.
- Quick checks `45626415465`: strict Clippy **failed** on three test-only helpers enabled in default builds although their callers require the backend. Local cfg now matches callers; no lint suppression added. Default unit tests (including protocol recycle tests) ran separately; final exact counts must be read from logs.
- Security `45626407559` and real TUN `45626407530`: success on `d33c733`.
- `76c9500`: default Linux/Windows strict Clippy + workspace tests `45627616094`, dependency `45627605235`, real TUN `45627605146`: **success**. Protocol recycled-owner tests pass on both platforms. Integration `45627608647` base job: **success**, including tunnel/CLI/DNS/backend tests and the synchronous-L3 barrier regression (stall reproduced). All six real functional cases (public/private DNS, replicas, pool cutover, mesh, multi-active) **success**. - Final `45627608647`: **failure**, not a full-run pass. Delayed sample 3 (200ms one-way per device, 400ms effective RTT) had 0% ping loss but max 904.553ms / average 577.433ms, violating the unchanged latency bound; payload SHA256/bytes passed both directions. Samples 1/2 had max 400.650/400.578ms. Default low-RTT gigabit and separately opt-in GSO steps succeeded; that does not waive the delayed failure or prove the target single-core throughput. Raw artifacts, base/serial/failed logs live under `workspace/pre8-evidence/45627608647/`. Do not rerun unchanged code to pick a green outcome.

Full main acceptance allowlists include `fix/pre8-data-plane` (`7dfe368`), without changing thresholds, timeouts or cases. Do not treat skipped downstream netns/performance jobs after compile failure as passed.

## Still mandatory

- Finish item 4 at the first losing-progress boundary, preserving TLS same-operation retry buffers, absolute deadlines, control flood limits, authorization/cancel discard, stable pending owners, and genuine readiness waits.
- Expand real daemon assembly evidence to both roles/mixed DNS/replica/non-single-lane and live expiry / mismatched DNS response, rather than substituting only helper tests.
- Integrate all assertions and run combined Actions; inspect exact SHA, full functional matrix, serial/aggregate performance, default-platform tests and dependency gates.
- No local cargo/OpenSSL compilation, no subagents, no GSO, no lane increase, no 256KiB watermark increase, no gate weakening.
- Only after the complete specification and verification: merge reviewed candidate, revalidate main, publish official `v0.1.0-pre.8`, independently verify tag/assets/checksums/release manifest. Do not deploy. No prior performance-failure waiver carries over.
