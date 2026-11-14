# Implementation status and evidence gates

Status snapshot: **foundation only; Phase 0 is not complete.** This document tracks the gates in the [v1.11.0 master plan](../plans/BOREAS-MASTER-PLAN-v1.11.0.md), §11. There is no production daemon, TLS implementation, protocol freeze, Linux static-TLS acceptance, or security audit in this repository snapshot.

| Plan gate / phase | Required evidence (not asserted here) | Current implementation | Follow-up |
|---|---|---|---|
| Phase 0 / `G-CRYPTO` | Hybrid TLS 1.3 and ML-DSA mTLS backend, independent interoperability, suite/RFC and draft review, supported static architectures | Pure suite/peer policy gate exists; no TLS backend or handshake | ADR-0001, select and prove a maintained backend; build/test interoperability PoC |
| Phase 0 / `pq1024` PoC | Independent PoC and acceptance evidence | Not implemented | Separate PoC; keep suite disabled until accepted |
| Phase 0 outputs | Threat model, authorization chain, schema/registry, error/state model, compatibility, resource budget and vectors | Pure policy/parser primitives and candidate framing exist; no TLS, signed-object encoding, production schema freeze or full evidence set | Produce reviewed ADRs/schema and vectors; do not call protocol frozen |
| Phase 1 / `G-FRAME` | Parser invariance, bounds, malformed/unknown inputs, DoS tests | Candidate 8-byte AppHeader stream decoder and policy exist with unit tests; no gate-level adversarial/interop evidence | Complete fragmentation/fuzz/DoS evidence against approved schema; no legacy 4-byte frame |
| Phase 1 / `G-DATA` | VirtualTun and LinuxTun transfer/hash/fault evidence | Packet validation and bounded packet-I/O primitives exist; no VirtualTun/LinuxTun device or data plane | Implement and test separately on target Linux |
| Phase 1 / `G-RESOURCE` | 195 balanced / 291 concentrated backup and attack tests, >=30 min resource evidence | No runtime | Instrument and run specified workload |
| Phase 1 / `G-PERF` | Prescribed RTT/loss/rate and topology benchmark evidence | No performance implementation or measurements | Benchmark real builds; publish commands, environment and results |
| Phase 2 / `G-ENROLL` | 16-way invitation race and crash/disk-full idempotency evidence | Protocol control kind exists; no invitation, CSR, enrollment transaction, persistence or evidence | Implement transaction journal and fault-injection tests |
| Phase 2 / `G-AUTHZ` | Scope, role, generation, equivocation, dual-signature rejection tests | Pure identity mapping, issuer-scope, snapshot freshness and clock policy; no signing, certificate/object parsing or cryptographic verification | Implement encoding/verification with reviewed object formats and complete negative tests |
| Phase 2 / `G-REVOKE` | Expiry, replay, clock rollback and cleanup evidence | Pure status snapshot sequencing/freshness and clock policy; no signed revocation objects, session cleanup or restart/partition integration | Implement signature-verified freshness and fail-closed session cleanup; test restart/partition |
| Phase 2 / `G-DOS` | Staged cost/fairness and unauthenticated flood evidence | No network listener | Add quotas and staged admission tests |
| Phase 3 / `G-TUN` | Queue/GSO/checksum/fallback evidence | Platform-neutral packet/virtio parsing and bounded queue primitives only; no real TUN integration | Linux device implementation and target-system tests |
| Phase 3 / `G-MTU` | MTU/DF/PTB/TTL/firewall evidence | Not implemented | Implement packet path and topology fault tests |
| Phase 3 / `G-DNS` | UDP and TCP DNS behavior, limits, no recursion | Bounded authoritative DNS message parser/response builder; no UDP/IP socket service, TCP DNS, SOA negatives, or production evidence | Implement transport service/TCP state machine and full protocol tests |
| Phase 3 / `G-SANDBOX` | seccomp/ABI positive and negative evidence, fd/resolver audit | Not implemented | Worker isolation and target-ABI audit |
| Phase 3 / `G-UPGRADE` | Crash/power-loss/recovery and external supervisor evidence | Local upgrade-journal and active-pointer transaction primitives exist; no artifact authenticity verifier, executable process supervisor, OS integration or accepted fault-matrix evidence | Add verified release chain, process supervisor and recovery fault matrix |
| Phase 4 / `G-CONVERGE` | Input-order/partition/equivocation convergence evidence | No directory implementation | Deterministic state machine and property tests |
| Phase 4 / `G-PREFIX` | Canonical prefix, reserved/scope/protected-range evidence | Pure canonical prefix classifier and deterministic route-election primitives with unit tests; no cross-implementation/property evidence or data-plane integration | Complete boundary/property and independent-input evidence; integrate shared policy |
| Phase 4 / `G-FAILOVER` | Four-Core tests and measured failover/acceptance limits | No topology runtime | Implement and exercise on multi-node testbed |
| Phase 4 / `G-SUPPLY` | Dual-signature artifacts, SBOM, reproducibility and update-journal evidence | No release pipeline/signing | Define supply-chain artifacts and independent verifier |
| Phase 4 / `G-UI` | Locale, narrow/non-TTY, NO_COLOR, DSR, prompt and injection evidence | CLI emits plain JSON; no full UI | Add UI and specified terminal tests when implemented |
| Phase 5 / `G-E2E` | Same/cross-Core, gateway and endpoint E2E TLS evidence | No E2E or relay implementation | Implement only after Phase 0 TLS proof |
| Phase 5 / no downgrade | Capture evidence all strict-mode failure paths never send hop-only traffic | No data plane exists; behavior not applicable | Add integration captures and failure-path tests |
| Phase 5 / external review | Independent crypto/protocol review, fuzzing, dependency audit and issue closure | No review evidence | Commission and close findings before release |
| Common production exit | Reproducible gate records, no blocking/high issues, operational drills | Not met | Do not release until every applicable gate has evidence |

## CI boundary

The repository CI runs Rust formatting, workspace check, Clippy, and unit tests on Windows and Ubuntu. It **does not** test Linux `x86_64`/`aarch64` static TLS builds, real Linux data plane behavior, CDN compatibility, production performance, multi-node interoperability, or cryptographic security. CI green is not Phase 0 acceptance.
