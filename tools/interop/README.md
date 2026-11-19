# Independent protocol interop verifier

`verify.py` is a second, independent implementation of the candidate Boreas wire
codecs. It is deliberately written from the byte layouts in
`docs/protocol/` and the master plan, **not** by translating the Rust decoder,
so agreement with `boreas-proto` is evidence of two implementations rather than
one implementation checked against itself.

It uses only the Python standard library. It verifies structure, canonical
encoding and the cross-implementation agreement of fixed vectors. It performs
no cryptography and it is not a gate pass by itself: a green run shows that the
two decoders accept and reject the same bytes for the covered schemas.

What it checks:

* `AppHeader` (8 bytes): version, kind, flags, body length, and that a control
  body is never empty.
* Control payloads: `SessionHello` / `SessionAccept`, `Probe`, `Drain`,
  `CircuitOpen` / `CircuitAccept` / `CircuitReset` / `CircuitClose`,
  `Enrollment` request and response, `DirectoryPage`, and the `SignedObject`
  envelope used by `Lease`, `Lsa`, `Grant` and `Revoke`.
* Management-object CBOR: the deterministic subset (unsigned integers, byte
  strings, arrays, maps), canonical length encoding, strictly ascending map
  keys, and the registered object bodies.
* The `BE2E` end-to-end confirmation record.

Every fixed vector under `docs/protocol/vectors/` is decoded here and compared
field-for-field with the expectation recorded in the vector. Separately, a
bounded deterministic mutation pass (truncated, over-long, bad version, unknown
kind, unknown flags, non-canonical CBOR, swapped lengths) asserts that both
this verifier and the Rust decoder reject the same mutated inputs. The Rust
side of that comparison is `crates/boreas-proto` via the `proto-interop` CI job;
this script is the Python side and also runs standalone.
