# Boreas candidate protocol schema and registry v0.1

**Status: candidate / not frozen.** Derived from master plan v1.11.0 §§5.3–5.4 and 6.2. This document and `boreas-proto` are an implementation baseline for review, not production protocol certification. Management-object fields below remain candidates; dual independent implementation, fixed vectors, ADR review, and Phase 0 evidence remain required.

## AppHeader candidate (8 bytes, network byte order)

| Offset | Field | Candidate constraint |
|---:|---|---|
| 0 | `proto_major` | exactly `3` |
| 1 | `kind` | `1=Control`, `2=HopIpBatch`, `3=RelayCircuit`; others reject |
| 2..3 | `flags` | `u16` big-endian; currently no flags allocated, so nonzero rejects |
| 4..7 | `body_len` | `u32` big-endian, `0..=65536`; reject before body allocation |

Control body cannot be empty because its first byte selects the registered subtype. Candidate decoder takes an explicit per-connection/per-feed ceiling. It validates an 8-byte header as soon as available before accepting body bytes, rejects declared frames that cannot fit the ceiling, handles arbitrary splits/coalescing, and permanently locks failed connections. While producing a feed result the ceiling covers incomplete buffered wire bytes plus completed wire-byte size returned as frames. Current implementation copies the completed body into its returned `Vec`, so temporary allocator capacity/duplicate-copy peak may exceed this logical accounting ceiling; it is not a hard heap limit. It applies only to decoder accounting, **not** process-global memory, TLS/WS buffering, frames retained by the caller after return, allocator overhead, or total RSS.

`HopIpBatch` is rejected by default under `e2e-required`; caller must explicitly select `hop-only`. This parser does not implement payload schemas for batch or relay fragments.

## Control subtype registry

Subtype is the first body byte. The listed body caps include that byte. Every unlisted subtype rejects; `0x0b..0x0f` and `0x14..0xff` remain reserved.

| Byte | Candidate name | Candidate legal state | Max body |
|---:|---|---|---:|
| 01 | SessionHello | TLS ready, not accepted | 4096 |
| 02 | SessionAccept | legal Hello received | 4096 |
| 03 | Enrollment | enrollment service connection, enrollment incomplete | 16384 |
| 04 | DirectoryPage | accepted session | 16384 |
| 05 | Lease | accepted session and registered identity | 4096 |
| 06 | Lsa | accepted Core–Core session only | 8192 |
| 07 | Grant | accepted session | 8192 |
| 08 | Revoke | accepted session | 16384 |
| 09 | Probe | accepted session | 256 |
| 0a | Drain | accepted session | 256 |
| 10 | CircuitOpen | `e2e-required`, accepted | 4096 |
| 11 | CircuitAccept | matching CircuitOpen exists | 4096 |
| 12 | CircuitReset | circuit opening or established | 256 |
| 13 | CircuitClose | circuit established | 256 |

The crate exposes an orthogonal candidate `SessionContext`: Hello/accepted, registered identity, peer role, enrollment-service connection, security mode, and per-context circuit opening/established flags. This is a compact gate only: an integrator must bind circuit flags to a specific circuit identifier and enforce complementary peer roles/path authorization. Enrollment is allowed only when the caller marks the connection as enrollment-service; this marker must come from authenticated configuration, not peer input. Payload contents and identity claims are not authenticated by these checks.

## Candidate deterministic-CBOR accepted subset

The validator accepts exactly one complete item, no trailing bytes. Accepted major types: unsigned/negative integers, byte strings, UTF-8 text strings, arrays, maps. Integers and definite lengths must use shortest additional-information encoding. Map keys must appear in deterministic CBOR ordering (encoded length, then lexicographic bytes); equal encodings reject as duplicates. Float/simple values, tags, indefinite-length items, reserved additional information and invalid UTF-8 reject. Depth and total encoded byte limits are caller supplied. This implementation validates canonical representation, **not application schema, signature domain, authorization, or object semantics**.

## Candidate management objects

Candidate field structures are those in plan §5.4: `NodeIdentity`, `AttachmentLease`, `CoreLsa`, `RouteGrant`, `DirectGrant`, `StatusSnapshot`. They are intentionally not encoded or validated as frozen schemas here. Plan §5.3 signature-domain/Ed25519+ML-DSA verification requirements are not implemented; this crate contains no cryptography and must not invent it.

## Required gates / evidence not claimed

- Phase 0: ADR, complete schema, fixed positive/negative vectors, independent implementation cross-check, compatibility and resource review.
- G-FRAME: arbitrary stream split/coalesce, zero/max/over-cap lengths, unknown kind/flags, truncation, slow large headers and multi-fragment DoS.
- CBOR: malformed/overlong lengths, duplicate and misordered keys, UTF-8, nested depth, limits and trailing data.
- Not covered: production TLS framing/buffers, global quota, real resource telemetry, fuzzing campaign, third-party protocol/security review, cryptography, full message payload validation.
