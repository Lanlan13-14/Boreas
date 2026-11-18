# Multi-hop circuit binding: next design (not implemented)

**Status: design note only. Candidate protocol work, not frozen, not
approved, and not evidence for any gate.** Nothing in this document authorizes
a wire change, a multi-hop runtime claim, or a production route. The current
`G-E2E` evidence remains direct/one-relay transport plumbing; multi-hop relay
and multi-hop E2E remain unproven.

## Why this note exists

The current single-relay path is safe only because every relay sees the opener
as its own authenticated upstream peer:

- `CircuitOpen` carries the destination `NodeRef` and `path_hops`, but **no
  original opener NodeRef**.
- `RelayHop::forward_open` derives the relay table's opener from
  `upstream.peer()`.
- `RelayTable::accept_segment` requires `hop.peer == segment.source`; this is
  the **adjacent hop** authentication, not end-to-end opener proof.

At the second relay, `upstream.peer()` is the previous Core, not the original
Edge. Re-deriving the opener there is wrong. Simply copying the original opener
into `RelayTable.src` is also wrong: the second relay would then reject every
fragment because the authenticated hop peer is the previous Core, not the
original opener. The two identities serve different purposes and must not be
conflated.

## Security constraints

1. **Adjacent-hop authentication is local.** A Core can authenticate only the
   peer on the other end of its hop session. It cannot infer that a different
   NodeID is the real opener, nor that the opener owns any source prefix/VIP,
   lease, route or ACL.
2. **The upstream Core must not self-claim opener authorization for another
   NodeID.** A relay that receives `CircuitOpen` from another Core may preserve
   a wire opener, but that field is not a grant. It must not be used to skip
   source lease, route, VIP, source-address or resource-admission checks.
3. **E2E confirmation is not Core resource authorization.** E2E TLS and its
   application confirmation bind the two endpoint identities and the circuit
   facts. They do not prove that the original source is entitled to send a
   particular L3 source address through a Core. The Core's existing
   authenticated source/lease/route permission remains a separate mandatory
   check.
4. **No timeout-as-`Ok(None)` readiness.** TLS, WebSocket and `read_exact` may
   already have consumed part of a record when a read times out. Treating that
   timeout as a safe "no frame" result would corrupt or silently desynchronise
   the hop session. A real full-duplex driver needs a stateful readiness /
   `WANT_READ` contract, with a frame buffer, that preserves the transport
   state and poisons only on genuine protocol/IO failure. The current
   `EstablishedSession::recv_frame` is deliberately blocking and
   `has_buffered_input` is not readiness.
5. **No legacy acceptance.** A changed candidate body must have one exact
   length. Unknown, short, padded or old-form bodies must fail closed; do not
   add a compatibility branch that guesses which schema was intended.

## Proposed wire shape (NOT approved, NOT implemented)

The smallest candidate direction is to carry the original opener `NodeRef` in
`CircuitOpen`, while keeping the relay table bound to adjacent hop peers:

```text
CircuitOpen (candidate length 38 bytes, including subtype)
  0       subtype                     = 0x10
  1..17   circuit_id[16]              nonzero
  17..19  opener_node_id              valid NodeID
  19..27  opener_identity_generation  nonzero
  27..29  destination_node_id         valid NodeID, distinct from opener
  29..37  destination_identity_generation
  37      path_hops                   1..=8
```

This is a proposal only. It would require:

- `boreas-proto::messages::CircuitOpen` encode/decode/validate and
  `CIRCUIT_OPEN_BODY_LEN` update;
- `docs/protocol/control-messages-v1.md` field table and registry text;
- fixed vectors in `docs/protocol/vectors/control-messages-candidate-v1.json`
  and every Rust/Python checker that consumes them;
- negative vectors for old 28-byte form, truncation, trailing bytes, zero
  generation, invalid opener NodeID, opener equal to destination, and bad
  `path_hops`;
- a new candidate version/ADR if the E2E confirmation format is also extended.
  The current 73-byte confirmation carries only `opener_node_id`; generation
  is validated against the directory-derived endpoint identity before E2E, so
  changing that format is not part of the minimal proposal.

## Relay state split

The relay must keep two identities distinct:

- **`table_src` / `table_dst`**: adjacent hop peers from the authenticated
  `upstream.peer()` and `downstream.peer()`. These are what `RelayTable`
  checks, pairs and offsets against. A direction-1 segment uses
  `(table_dst, table_src)`.
- **`opener` / `destination`**: the original endpoints carried in
  `CircuitOpen`. These are route/endpoint facts used by `CircuitInfo`,
  `E2eInfo`, confirmation and upper-layer source authorization. They must not
  replace the adjacent-hop check in `RelayTable`.

At the first relay, the original opener is the authenticated upstream peer if
the open arrived directly from that endpoint. At later relays, the original
opener is only a carried fact; the previous Core is authenticated by its own
hop session. The endpoint must compare the carried opener against its own
local identity (initiator) or its directory-derived expected peer (acceptor)
before accepting the circuit.

## Full-duplex requirements (future)

`RelayHop::relay_once` is single-direction and blocking. A multi-hop
full-duplex driver cannot be built by claiming that an alternating poll over
`has_buffered_input` is nonblocking. Required before such a driver is claimed:

- a session-level readiness/`WANT_READ` operation that can return "no complete
  frame yet" without consuming or poisoning a partial TLS/WS record;
- explicit ownership of the frame buffer across readiness attempts;
- a documented shutdown/Reset path that does not abandon a partially read
  record;
- tests with two directions active concurrently, slow/partial records, and
  peer half-close/reset;
- a bounded driver API, not a timeout wrapper that turns transport errors into
  idle.

The current `mesh_runtime` relay test is therefore deliberately single-relay
and one-direction at the relay driver level. It is real TLS evidence for that
slice; it is not multi-hop or full-duplex evidence.

## Required future evidence

1. Candidate ADR/proto change with exact positive and negative vectors.
2. Two-relay test with an original Edge opener and a final Edge destination,
   asserting the second relay sees the original opener as route metadata but
   still authenticates its adjacent upstream/ downstream sessions separately.
3. A negative test where a Core attempts to claim another NodeID as opener or
   as a source prefix; the circuit/source permission must fail, not be granted
   by E2E confirmation.
4. Full-duplex driver tests only after the readiness contract exists.
5. Core resource checks: source VIP/lease/route/ACL authorization must remain
   enforced independently of `CircuitOpen` and E2E confirmation.

Until those land, do not add an opener field, do not add a 38-byte variant, and
do not describe the existing single-relay test as multi-hop security evidence.
