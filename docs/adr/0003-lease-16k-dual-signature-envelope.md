# ADR 0003: Lease 16 KiB candidate cap for dual-signature envelopes

- Status: Proposed candidate deviation; pending plan/registry review. Not approved, not frozen.
- Date: 2026-11-15
- Plan: BOREAS Master Plan v1.11.0, §5.3 signature rules and §5.4 Control subnet registry
- Related: `docs/protocol/control-messages-v1.md`, `docs/protocol/management-objects-v1.md`, `crates/boreas-proto/src/messages.rs`

## Context

The master plan §5.3 requires both Ed25519 and ML-DSA signatures over the same raw management-object TBS, with AND verification. §5.4 states that `AttachmentLease` is signed by the node identity key and co-signed by the target Core. The plan's Control registry row for `Lease` (subtype `0x05`) lists a 4 KiB body cap.

`SignedObject` carries explicit Ed25519 and ML-DSA signatures. Candidate signature sizes are:

| Item | Bytes |
|---|---:|
| Ed25519 signature | 64 |
| ML-DSA-65 signature | 3309 |
| ML-DSA-87 signature | 4627 |
| Signer block (role 1 + Ed 64 + algorithm 1 + length 2 + ML-DSA) | 3377 / 4695 |
| Two signers (node Primary + Core CoSign) | 6754 / 9390 |
| Envelope fixed header (version, object type, schema version, signer count) | 5 |
| `raw_tbs_len` | 4 |
| Control subtype byte | 1 |
| Non-TBS overhead | 10 |

Therefore a `Lease` body with two ML-DSA-65 signers needs `6764 + TBS` bytes, and two ML-DSA-87 signers need `9400 + TBS`. A 4 KiB body cap is smaller than the signature material alone before any TBS bytes (4096 < 6754). Even a single ML-DSA-87 signer plus envelope overhead (4705) exceeds 4 KiB; the AttachmentLease co-signature rule forbids a single signer.

## Decision

The candidate Control registry and code use a **16 KiB** body cap for `Lease`:

- 16 KiB accommodates two ML-DSA-65 signers with at most 9620 TBS bytes, or two ML-DSA-87 signers with at most 6984 TBS bytes.
- `AttachmentLease` TBS is small (six integer/byte fields), so the practical limit is the signature envelope, not the TBS.
- Other subtype caps are unchanged. DirectoryPage/Revoke must still budget their own envelope payloads; this ADR does not raise them.
- The master plan text is not edited. This ADR records the deviation for review. If the plan insists on 4 KiB, the alternatives are to change the signer rule or move co-signatures outside the object; silently dropping Ed25519 or the co-signature is not acceptable.

## Consequences

- `boreas-proto` uses `ControlType::Lease.body_cap() == 16384`; `Lease` decode/encode rejects envelopes that exceed it.
- Management-object TBS limits remain 16 KiB; a Lease envelope cannot carry a maximum-size TBS because signature material consumes the body cap.
- Pki/transport must budget for the full envelope, not just TBS, and must not compress or infer signature lengths.
- This is candidate evidence for schema review only; it is not a protocol freeze, cryptographic validation, or production acceptance.
- Follow-up: review this ADR with the plan owner and independent vector owner, then either accept the 16 KiB candidate or revise the signer/co-signature architecture explicitly.
