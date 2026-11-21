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
- `PacketRuntime::new_private_dispatcher` owns a private-only dispatcher for
  IPv4 UDP packets and the existing real smoltcp TCP listener. Both transports
  charge one budget; UDP also honors its EDNS and link payload ceiling. The
  blocking public branch is unreachable from either packet transport, even if
  a lower-level caller configured an upstream. The private authority retains
  its single-address-per-type behavior and no SOA in negative answers.
- `boreas_tunnel::dns_packet_service` (OpenSSL feature) is an opt-in owner for
  one Core-to-Edge E2E binding. It takes endpoint identities and MTU from the
  established circuit, requires an exact signed network/policy binding and a
  current `Replica` grant for that Core generation, and materializes the
  signed IPv4 zone and single Edge source allowlist. It drops its state and
  queues on observed invalidation, UTC expiry/rollback, or a fixed monotonic
  expiry derived from the intersection of signed windows. It does not infer
  trust from a packet address. An embedding owner must supply a current,
  revocation-aware binding check and trusted UTC, keep ingress isolated to that
  circuit, and keep authorization current through actual reply delivery. This
  seam is not a multi-circuit admission controller; recreating it resets rate
  state. The current IPv4 packet profile accepts only MTUs 1280–1500.
- `PacketPath::try_new_over_e2e_with_private_dns` opts one real Core–Edge E2E
  path into UDP/53 only. `step_inbound` consumes a frame from the verified
  Edge permanent VIP to the reserved DNS VIP, never gives it to the host TUN,
  and writes only a runtime-produced DNS VIP:53 reply to that same Edge and
  query source port on the same circuit. The path enforces its selected MTU,
  even if the hop cap is higher. Before each partial write and flush it
  resamples UTC and checks the service's monotonic deadline and owner gate;
  observed invalidation poisons the path. The checks cannot retract bytes an
  in-progress blocking transport operation already accepted. The standard
  constructor still rejects the DNS VIP in both directions.
- The Linux daemon still uses the standard constructor. The Core hook is the
  `PacketPath::try_new_over_e2e` site in `daemon.rs::drive_business_path`, for
  the initial `serve` path only, after E2E and final status admission. Before
  switching that call, add explicit Core-only pinned DNS provisioning: retain
  the exact durable-accepted `VerifiedNetworkPolicy` and its independently
  provisioned root, verify the dual-signed service policy and signer grant and
  the signer-signed authority with that root/policy, and pin their exact
  current versions with anti-rollback and an invalidation source. Bind the
  nonblocking gate to the exact circuit and both generations, watchdog/status
  and revocation state, signed policy/business deadlines, and the pinned DNS
  versions. The session owner must bound/interrupt blocked writes at the
  effective deadline; reserve request/reply capacity if using a packet-count
  budget, and report TX stats for replies sent during inbound steps. No
  `|| true`, implicit reload, promotion to a standby, or discovery fallback.
- No Edge resolver, Edge-side DNS VIP authorization or host route, packet TCP
  DNS, discovery, advertisement, host/LAN listener, IPv6, public forwarding,
  replication, persisted DNS snapshot selection, or new revocation feed was
  added. Neither wire format nor negotiated capabilities changed. This is not
  production DNS or an end-to-end leak claim.

Regression coverage includes loopback TCP wire tests with a sentinel listener
for private negative/failure/stale/authorization outcomes, lookalike public
names, an uncached repeated negative result, revocation during exchange, and
upstream cap failure; deterministic unit tests cover freshness boundaries and
admission quotas. No local build, test, or formatter was run. The existing
`.github/workflows/ci.yml` locked Clippy/workspace tests on the exact integrated
SHA are required before treating these tests as passing.
