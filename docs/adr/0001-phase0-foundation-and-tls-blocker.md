# ADR 0001: Phase 0 foundation and TLS backend blocker

- Status: Accepted as current implementation boundary; not an architecture freeze
- Date: 2026-11-14
- Plan: [BOREAS Master Plan v1.11.0](../plans/BOREAS-MASTER-PLAN-v1.11.0.md), especially §§2, 4, 5 and 11

## Context

The master plan is a design baseline, explicitly not an implementation acceptance or frozen protocol. It requires standard TLS 1.3 hybrid KEX and ML-DSA authentication, deterministic application/object encoding, strict authorization, bounded resources and evidence-based release gates. In particular, the plan identifies unresolved backend support and requires a Phase 0 PoC and independent interoperability. Reverting to the retired custom PQ-IK/Pairwise handshake or legacy byte framing is prohibited.

## Decision

The current code boundary is only a minimal Rust workspace and CLI policy/parser foundation. The CLI doctor/self-check reports JSON and explicitly says daemon, networking, TLS, and Phase 0 completion are false. It does not start a daemon. Unrecognized commands fail with a non-zero exit status. No external crate dependencies are introduced by this foundation.

No choice of TLS provider, cryptographic suite implementation, handshake, object encoding, or production wire format is made by this ADR. It requires a later reviewed decision backed by executable evidence. Rust uses edition 2024 and the `stable` toolchain channel. The repository's current MSRV is Rust 1.100, matching the toolchain verified by the lead on 2026-11-14; this is a toolchain baseline, not evidence for TLS availability. CI checks Windows and Ubuntu source builds, but does not establish Linux dual-architecture static TLS acceptance.

## Gate register

The complete gate-by-gate ledger is [implementation-status.md](../engineering/implementation-status.md). Every listed gate remains open. In particular: Phase 0 `G-CRYPTO` and `pq1024` PoC; Phase 1 `G-FRAME`, `G-DATA`, `G-RESOURCE`, `G-PERF`; Phase 2 `G-ENROLL`, `G-AUTHZ`, `G-REVOKE`, `G-DOS`; Phase 3 `G-TUN`, `G-MTU`, `G-DNS`, `G-SANDBOX`, `G-UPGRADE`; Phase 4 `G-CONVERGE`, `G-PREFIX`, `G-FAILOVER`, `G-SUPPLY`, `G-UI`; Phase 5 `G-E2E`, strict no-downgrade evidence, cost retesting and external review; all shared production exit conditions. None is marked complete by this ADR.

## Consequences and follow-up

- The self-check is a status statement, not a validation of cryptography, networking, or operational readiness.
- The project cannot honestly advertise a working VPN, TLS backend, frozen protocol, or successful production gate.
- Next: produce dedicated Phase 0 ADRs for backend/version/signature-scheme decisions; build an independent interop PoC; finalize schema and vectors; retain explicit evidence and failed samples for each gate.
