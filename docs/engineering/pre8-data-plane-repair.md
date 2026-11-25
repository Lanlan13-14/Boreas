# pre.8 data-plane repair — working acceptance record

Baseline: `002c80dd3ec5cbc6806c10ec8f0dc3613aa6aea0` (`main` / `v0.1.0-pre.7`).
Authoritative scope: user attachment `Boreas-pre7-complete-spec.md` (2026-11-25).
This is a working record, **not a completion or performance claim**.

## Current production changes

1. `262c426`: empty ReadAhead fills once before borrowed first-packet delivery; same-cursor partial completion, bounded interrupts, clean EOF, poison on failed delivery.
2. `8616f9e`: daemon configures after DNS/replica binding; ordinary packets in mixed DNS use the borrowed path; one classifier gives Core DNS, Edge DNS, then host order. DNS handlers keep live authority/transaction checks. ReadAhead owns its Admission byte credit, exhaustion falls back.
3. `13677ca`: CircuitStream hands back the allocation only after consuming its final byte; FrameIo and FrameDecoder have at most one recycled relay body, count actual capacities, and retain 8KiB feed/error atomicity.
4. `a2f59c8` / `fa10f5e`: **partially repaired at the L3 completion boundary only.** Incomplete length prefixes/bodies stay in the original admitted 16KiB allocation; explicit Pending returns to the daemon policy/TUN turn, incomplete L3 alone is not readiness, and an absolute 30s assembly deadline stops indefinite retention. `85b3713` adds both-role real WSS/hop/E2E pq768 proof with 257-byte lower short I/O: peer withholds the tail until it receives a byte-exact reverse packet. **Still NOT implemented:** nonblocking incomplete TLS record / WS frame / relay-frame progress with stable pending WANT read/write operations. Do not call this full completion of item 4.

## Actual verification

- Actions `45625097371` @ `7dfe368`: integration **failed**. All 5 new prefetch tests passed, tunnel library 276 tests and real-WSS integration 19 tests passed. Failure was an omitted production `drive_business_path` caller in `private_dns_replica.rs` (compile E0061); `4c0d828` fixes that caller with an explicit zero optional-prefetch budget.
- Security `45625094097` / `45625108990`, real TUN `45625093577` / `45625120950`, interop `45625093511`: success on the first candidate.
- Actions `45626408835` @ `d33c733`: integration **failed** to compile newly added event-order fixture: AuthorizedEndpoints was moved across split iterations. Local source now constructs a new unique binding per split; not yet revalidated.
- Quick checks `45626415465`: strict Clippy **failed** on three test-only helpers enabled in default builds although their callers require the backend. Local cfg now matches callers; no lint suppression added. Default unit tests (including protocol recycle tests) ran separately; final exact counts must be read from logs.
- Security `45626407559` and real TUN `45626407530`: success on `d33c733`.
- `76c9500`: default Linux/Windows strict Clippy + workspace tests `45627616094`, dependency `45627605235`, real TUN `45627605146`: **success**. Protocol recycled-owner tests pass on both platforms. Integration `45627608647` base job: **success**, including tunnel/CLI/DNS/backend tests and the synchronous-L3 barrier regression (stall reproduced). All six real functional cases (public/private DNS, replicas, pool cutover, mesh, multi-active) **success**. - Final `45627608647`: **failure**, not a full-run pass. Delayed sample 3 (200ms one-way per device, 400ms effective RTT) had 0% ping loss but max 904.553ms / average 577.433ms, violating the unchanged latency bound; payload SHA256/bytes passed both directions. Samples 1/2 had max 400.650/400.578ms. Default low-RTT gigabit and separately opt-in GSO steps succeeded; that does not waive the delayed failure or prove the target single-core throughput. Raw artifacts, base/serial/failed logs live under `workspace/pre8-evidence/45627608647/`. Do not rerun unchanged code to pick a green outcome.

Full main acceptance allowlists include `fix/pre8-data-plane` (`7dfe368`), without changing thresholds, timeouts or cases. Do not treat skipped downstream netns/performance jobs after compile failure as passed.

## Release decision (latest user authorization)

The latest user clarification explicitly requires completing **TLS/WS half-record resumable progress before pre8**. Only performance measurement is waived: after the complete repair and sound build/correctness/security verification, merge and publish without waiting for performance results. **No authorization to publish partial item 4.** Keep failed performance results red and disclose actual numbers; do not alter thresholds or blame CPU without evidence. Use the official publication workflow; no deployment.

`00af3c7` integration `45632366953`: default checks `45632375848`, security `45632361369`, real TUN `45632361214`, base backend tests and all six functional cases passed. Delayed scenario passed on this run; ordinary low-RTT throughput failed the unchanged 1000Mbps-each-direction requirement (Edge→Core 925–931Mbps, Core→Edge 901–1003Mbps); byte/SHA256 checks passed. Environment was AMD EPYC 9V74, 4 visible vCPUs / 2 cores × 2 threads, not the requested 7713 1C1G. Raw evidence retained locally under `pre8-evidence/45632366953/`.

`a2f59c8` integration `45637123361` failed to compile ONLY the newly added SplitPlaintext fixture missing its required readiness method; `fa10f5e` fixes it explicitly without removing any assertion. Default strict Linux/Windows checks `45637756950`, dependency `45637743067`, real TUN `45637743143` passed on fa10f5e. Complete backend/functional run `45637747618` is in progress. `85b3713` real TLS circular-wait regression is the final additional test pending validation.

## Still required before pre8

- Complete item 4 below L3: TLS-midrecord, WS-across-TLS, relay-across-feed, stable WANT owners, and genuine socket interest-set waits.
- Retain all existing resource, authority, terminal, flood and handshake-deadline semantics.
- No local cargo/OpenSSL compilation, subagents, GSO/default changes, lane increase or 256KiB watermark increase.
- Official pre8 assets, exact tag, SHA256, embedded commit, and discovery manifest must be independently checked. No deployment.
