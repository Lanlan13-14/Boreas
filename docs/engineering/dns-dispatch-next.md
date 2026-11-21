# DNS split dispatcher — compositional candidate

This is a library component, not daemon DNS or release-gate evidence. It is an
increment after the bounded TCP upstream (`fc234cd`), informed by the sibling
`DNS-WAN-DESIGN.md` and `dns-wan-next.md` (proposal through `cd53ab8`).

- One dispatcher serves one trusted network and one complete configured private
  suffix. The routing suffix is required even when the authority is unavailable;
  an authority with a different origin is rejected. Classification uses the
  existing canonical DNS label parser, including case folding and an exact label
  boundary. An apex or descendant goes only to the private branch. An NXDOMAIN,
  NODATA, REFUSED, missing/stale authority, authorization denial, deadline, or
  response error never triggers an upstream request for that name. Local errors
  carry no DNS response; consumers must not retry them via another resolver.
- Ingress must bind the message to a live authenticated Overlay peer, verify
  source integrity, and implement per-network `ClientAuthorizer` from current
  policy. The private branch also enforces the authority's source allowlist.
  Rechecks guard egress from the dispatcher, not the caller's later delivery;
  the embedding runtime must enforce revocation and freshness through delivery.
  The caller must obtain an authorized snapshot, derive the half-open monotonic
  deadline from the effective policy/signer/snapshot validity, and retire the
  instance on policy or authority invalidation. No signatures, revocation feed,
  namespace derivation, persisted watermark, or replica selection happen here.
- With explicit trusted configuration, the public branch makes one blocking
  plaintext TCP exchange to one numeric endpoint. No system resolver, retry,
  UDP fallback, DoH, listener, or local positive/negative response cache. Upstream
  replies are validated to the existing transport's extent and delivered without
  rewriting TTLs. The upstream may cache. The dispatcher rejects public requests
  with nonempty EDNS option lists rather than relaying opaque client data; it is
  not content filtering for intentionally encoded information in public names,
  nor does it inspect aliases or opaque RDATA for private names in replies.
- The API accepts complete, prefix-free messages and uses stream response
  limits. Messages are at most 4096 bytes; authority snapshots are capped at 128
  address/refusal entries and 4096 allowlist addresses. A shared instance admits
  at most 64 in-flight queries total and eight per stable NodeID. One-second
  monotonic windows cap work at 1024 queries/4 MiB globally and 64 queries/256 KiB
  per NodeID. Charge is input size plus a worst-case response and TCP framing;
  the identity table has at most 256 entries. These are reservation limits, not
  exact on-wire shaping or ingress DoS protection. The caller owns bounded
  ingress scheduling, worker isolation and reply handling. Use separate policy
  instances for distinct networks; recreating an instance resets its budget.
- No packet, user-space TCP, or daemon paths are wired to this service. The
  shared query parser now rejects nonzero request RCODE bits on all its paths,
  matching the existing TCP upstream check. The private authority retains its
  single-address-per-type behavior and no SOA in negative answers. There is no
  trusted Core/Edge discovery or listener integration, LAN authorization,
  production DNS capability, or end-to-end leak claim.

Regression coverage includes loopback TCP wire tests with a sentinel listener
for private negative/failure/stale/authorization outcomes, lookalike public
names, an uncached repeated negative result, revocation during exchange, and
upstream cap failure; deterministic unit tests cover freshness boundaries and
admission quotas. No local build, test, or formatter was run. The existing
`.github/workflows/ci.yml` locked Clippy/workspace tests on the exact integrated
SHA are required before treating these tests as passing.
