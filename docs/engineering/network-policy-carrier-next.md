# Next slice: signed NetworkPolicy sidecar + CLI verifier

**Scope:** implement an offline, opt-in verification slice only. It does not enable custom prefixes, change daemon behavior, revise the default material-file policy, or make policy presence the default. Keep existing `BRRB0001`/`RootsBundle` behavior unchanged. The existing `verify_network_policy(raw_tbs, ed_sig, mldsa_sig, pin, expected_net_id, now)` already verifies the exact candidate bytes and both signatures against a supplied `NetworkRootPin`; the next work should adapt bytes to that API, not add another trust model.

## Current boundary / required constraint

- `RootsBundle` contains net ID, root public keys, and signed root-authorization records; `verify_material_dir_with_roots` decodes it and uses the bundled keys to construct the authorization trust chain. It currently does not verify a NetworkPolicy.
- `NetworkRootPin::provisioned` accepts separately supplied DER, and `verify_network_policy` requires that pin and expected net ID explicitly. A bundle-sourced pin is not independent provenance.
- The CLI currently exposes `boreas pki verify-bundle --material-dir ... [--roots ...] [--require-peer]`. Its default roots path is `<material-dir>/roots.cbor`; it does not expose policy verification. `pki_cmd.rs` is reached by `main.rs` dispatch under `pki`.
- No behavior change should be made to whatever material-directory file allowlist is reviewed/used by callers. Do **not** add `network-policy.*` to the accepted material directory as part of this slice. Require an explicit `--policy-file` outside that directory (or a separately reviewed explicit path), so the new input cannot silently broaden a material bundle.

## Minimal API and carrier

1. **Keep `RootsBundle` v1 byte-for-byte and semantically unchanged.** Do not add policy fields, infer policy from `roots.cbor`, or treat bundle keys as the independent pin. Avoid BRRB0002 in this slice; it is a separate carrier/versioning choice and would couple policy interpretation to the existing roots decoder.
2. Define one bounded sidecar encoding in the existing network-policy/proto area, with exactly the three values needed by the existing verifier: exact `raw_tbs`, Ed25519 signature bytes, and ML-DSA-65 signature bytes. Prefer a small versioned deterministic envelope with strict size/count/trailing-byte checks; do not introduce a generic carrier framework or a new policy model. Parsing must preserve `raw_tbs` verbatim and pass those exact bytes to `verify_network_policy`.
3. Add a thin public pki adapter (e.g. `verify_network_policy_sidecar(raw, pin, expected_net_id, now) -> Result<VerifiedNetworkPolicy, ...>`) that only decodes the bounded envelope then calls the existing verifier. Do not change `verify_material_dir_with_roots` signature or its success criteria. No policy file means existing verify-bundle behavior is unchanged; no implicit discovery or acceptance. A present malformed/unverifiable sidecar in the explicit verify-policy command must fail closed.
4. Pin inputs must come from outside both the sidecar and `roots.cbor`: CLI flags should require `--net-id`, `--root-ed25519-der`, and `--root-mldsa65-der` paths (or an explicitly reviewed pin-file format in a future change). Construct `NetworkRootPin::provisioned(..., Mldsa65, ...)`, use the same supplied net ID as `expected_net_id`, and never derive either from candidate/bundle then call that independent. Reject missing/duplicate inputs, empty/oversized key files, invalid DER/key algorithms, and network mismatch. State clearly that CLI flags establish explicit input, not provenance: operators must obtain/pin these values through an independent trusted channel. No config fields or env fallback in this slice.

## CLI must be reachable

Add `boreas pki verify-policy --policy-file <FILE> --net-id <32HEX> --root-ed25519-der <FILE> --root-mldsa65-der <FILE>` to `pki_usage()` and the feature-enabled dispatch in `crates/boreas-cli/src/pki_cmd.rs`; feature-disabled builds retain the existing fail-closed PKI feature message. Read each file with bounded reads, parse net ID using existing `parse_net_id_hex`, use current trusted wall-clock helper, invoke the library adapter, and emit a success JSON summary (net ID, root fingerprint, overlay base, version, sequence, validity); failures return the normal CLI error/exit 2. Do not route through `verify-bundle` or daemon startup. This ensures the feature is usable from the `boreas` binary, not merely from a library API.

## Compatibility and security tests

- Existing roots v1 fixture encodes/decodes identically; existing `verify_material_dir_with_roots` tests and default `verify-bundle` invocation remain successful with no sidecar.
- Existing CLI `verify-bundle` parsing/help remains compatible; verify-policy is additive, requires all independent pin flags, rejects absent/duplicate/unknown flags, missing files, invalid net ID, malformed DER, and wrong algorithms/network.
- Sidecar round-trip preserves exact raw TBS; reject malformed/truncated/oversized encoding, trailing bytes, invalid signature lengths, bad Ed25519 signature, bad ML-DSA-65 signature, wrong pin fingerprint, wrong network, not-yet-valid and expired policy. Keep both signatures conjunctive.
- Demonstrate non-self-proving pin: sidecar plus `roots.cbor` alone cannot invoke policy verification; a pin built from the bundle's own key bytes is not an acceptable implicit fallback. Altering the independent pin must fail even if the sidecar remains intact.
- Do not weaken any existing file/material allowlist. Explicit `--policy-file` is an opt-in separate file input; test that absent policy has no effect on old verification and that no policy is auto-loaded from a material directory.
- Confirm `Config::validate` continues rejecting every non-default overlay prefix, and do not add any daemon/config consumer of `VerifiedNetworkPolicy`.

## Exclusions / review gate

No BRRB0002, no material-dir allowlist expansion, no default policy requirement, no custom prefix acceptance, no persistent replay/rollback state, no policy-to-daemon wiring, and no claims of durable freshness. CLI verification is an inspection command: it verifies signature and stated-time validity only, using the local clock. Keep changes limited to the sidecar codec/adapter, `pki_cmd.rs` usage/dispatch and command implementation, narrowly scoped tests, and this design's eventual implementation notes. This document proposes the smallest slice; file-path policy and sidecar wire bytes still require review before implementation.
