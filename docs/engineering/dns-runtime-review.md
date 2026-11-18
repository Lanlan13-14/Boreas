# DNS authority/runtime review — 2026-11-17

## Scope and execution boundary

This review covers the three untracked drafts:

- `crates/boreas-pki/src/dns_authority.rs` — NetworkRoot-authorized DNS signer
  grant and DnsSigner-authorized zone/VIP/record verification.
- `crates/boreas-proto/src/dns_authority.rs` — isolated canonical CBOR candidate
  bytes for those two objects.
- `crates/boreas-tunnel/src/dns_runtime.rs` — UDP responder over one `PacketIo`
  endpoint, bound to a verified authority and an authenticated local identity.

It also adds this document. It does **not** modify `Cargo.toml`, `Cargo.lock`,
any `lib.rs` module declaration, or CLI/daemon code. The existing feature and
module declarations are draft integration owned elsewhere and are only read here.

No local compilation, test, syntax check or formatter was run. Verification is
restricted to GitHub Actions. No commit or push was made; the exact-SHA Actions
run is therefore still pending and this document makes no pass claim.

**Result:** the expiry/freshness, IPv6, rate-limit and signer-rotation findings
are addressed in the drafts; the completeness wording is corrected; no
private-key copy was found. Actions verification is still required.

## Findings and disposition

### 1. Expiry was checked only at bind time (critical)

The runtime's freshness window was computed from the authority and policy
windows only; the signer-grant expiry was not carried by the token, and
`handle_packet` had no clock parameter. A service instance created before expiry
would keep answering after the authority, signer grant or policy expired.

Fix:

- `VerifiedDnsAuthority` now stores the signer-grant and policy validity bounds
  and exposes `signer_validity()`, `policy_validity()`, `freshness()` and
  `is_fresh_at()`. `freshness()` is the intersection of the authority, signer
  grant and policy half-open windows; `is_fresh_at()` is true only inside that
  intersection.
- `DnsUdpRuntime::try_new` uses the token's `freshness()` rather than
  `authority.validity()`.
- `poll_once(now, monotonic)` and `handle_packet(packet, now, monotonic)` take
  the caller-supplied UTC `now` and a separate monotonic `Instant` on **every**
  operation. Both check `is_fresh_at(now)` before parsing, answering or writing,
  count `expired`, and return `Handled::Expired`. `poll_once` checks before
  `read_packet`, so an expired service does not consume queued traffic.
- There is no public operation that can answer without an explicit UTC `now`.

Tests: `freshness_intersects_authority_signer_grant_and_policy` (PKI; an
authority that outlives its grant stops being fresh at the grant expiry) and
`expired_token_is_refused_per_operation_without_reading_or_writing` (runtime).

### 2. IPv6 could be advertised without a policy ULA (critical)

`NetworkPolicy` carries one IPv4 overlay prefix and no ULA value. The proto layer
checked only that an IPv6 VIP was inside `fd00::/8`, which is a format check, not
proof that the address belongs to this network. The runtime then copied AAAA
records into the zone and answered them with a signed-but-policy-unbound scope.

Fix:

- PKI refuses every nonzero `DnsVipClaim::ipv6` and every `AAAA` record with
  `Error::UnsupportedIpv6` before producing a `VerifiedDnsAuthority`.
- The runtime independently refuses such a token in `try_new` (defence in depth)
  and only builds A records. IPv6 packets remain ignored.
- IPv6 is off by default with no enable switch in this slice. `AAAA` queries for
  an existing IPv4 owner now get authoritative NODATA (`NOERROR`, `ANCOUNT=0`)
  from the real zone, never a synthesized or unverified address.
- Proto docs now state that `fd00::/8` is only a format check and that the PKI
  layer refuses IPv6 entirely.

Tests: `ipv6_claims_and_aaaa_records_are_refused_without_a_policy_ula` (PKI),
`AAAA outside ula` in `rejects_values_outside_the_strict_authority_scope` (proto),
and `aaaa_is_nodata_because_ipv6_is_disabled_by_default` (runtime).

### 3. “DNS service” wording overstated the slice (high)

The draft is not a daemon and not a complete DNS implementation. It has no
process, socket, port binding, service unit, TCP DNS, recursion, forwarding,
cache, negative SOA, DNSSEC or EDNS padding. No CLI/daemon path constructs
`DnsUdpRuntime`.

Fix: the module documentation now has an explicit “What this is not” section and
separates the verified-zone UDP responder from daemon/TCP/completeness claims.
TCP to the DNS VIP remains a classified refusal with no fabricated segment.

### 4. No rate limiting (medium)

A structurally valid query from the authenticated local VIP produced one answer
per packet with no upper bound on answer rate.

Fix: a fixed-size fixed-window counter (`RATE_LIMIT_MAX_PER_WINDOW = 128`
accepted queries per one-second window) is checked after packet validation and
before DNS work. The window is measured with `std::time::Instant`, not the UTC
freshness value, and the caller supplies the monotonic instant to
`poll_once(now, monotonic)` / `handle_packet(packet, now, monotonic)`; tests
inject explicit `Instant` values. State is one `Option<Instant>` and one `u32`,
with no map and no allocation. Exhaustion increments `rate_limited` and returns
`Handled::RateLimited` without writing. The limiter is a coarse local abuse bound,
not a traffic-shaping or per-client policy; it depends on the caller supplying a
monotonic clock and is not a DoS proof.

Test: `fixed_rate_limit_bounds_answers_and_recovers_next_window`.

### 5. Private-key handling (informational, no defect found)

No private key is copied into or retained by the runtime:

- `DnsSignerPin` keeps the two **public** DER keys, the grant digest and validity.
- `VerifiedDnsAuthority` keeps public authorization data (zone, claims, records,
  digests, validity) and no key material.
- `DnsUdpRuntime` has no key field and receives no signer input.
- Test-only key pairs are generated in the test process and never persisted.

The new doc comments state this explicitly.

### 6. Clock semantics (medium, documented not "trusted")

Freshness uses the caller-supplied UTC `now` and remains a static half-open
interval check. It does **not** prevent a UTC rollback from reviving an expired
token; there is no durable anti-rollback watermark and no trusted clock service.
This is now stated in the module and `try_new` docs instead of calling the value
a trusted clock. Rate limiting is deliberately separate and uses a monotonic
`Instant`, so changing UTC cannot refill the answer budget; the rate-limit test
advances UTC within the freshness window while holding the monotonic instant and
still receives `RateLimited`.

### 7. Signer rotation (high, disabled rather than half-bound)

The `DnsAuthority` body carries the policy digest but not `signer_generation` or
the signer grant digest. If a later grant reused signer key material, an old
authority body could otherwise verify under the new pin with no evidence that the
body belonged to that grant. A full fix would bind the grant digest into the
authority signature domain/body and require new fixed vectors and a domain ADR.

This review takes the explicitly allowed smaller route: signer rotation is
disabled in this slice. `DnsSignerPin::verify_grant` accepts only
`signer_generation == 1` and returns `Error::RotationUnsupported` otherwise. A
future rotation profile must bind `signer_generation`/grant digest before
generation 2 can be enabled. No authority signature-domain change is made here.
With generation fixed to 1, a different signer key fails signature verification,
a different policy fails the policy-digest check, and reusing the same key under
another generation-1 grant does not change the signing authority.

Test: `signer_rotation_is_explicitly_disabled`.

## Key-size check

`DnsSignerGrant` caps the ML-DSA-65 public key DER at `MAX_MLDSA_KEY_DER = 2048`.
An ML-DSA-65 SPKI is roughly 1952 bytes of key material plus a small DER header
(~1974 bytes), so the existing bound is sufficient and is not changed.

## Invariants now enforced by the code

1. Root pin → root-signed DNS signer grant → signer-signed authority. The grant
   is bound to the exact verified policy digest, the fixed purpose byte, the
   fixed `dns-authority-v1` key id and ML-DSA-65. The authority is bound to the
   same policy digest and is signed by the granted signer; only signer generation
   1 is accepted in this slice.
2. Every answer requires `now` inside authority ∩ signer grant ∩ policy. This is
   a UTC interval check only; rollback can revive an expired token and is not
   prevented.
3. IPv4 only. IPv6 claims/AAAA records fail closed; AAAA answers are NODATA.
4. A query is answered only when destination is the derived DNS VIP, protocol is
   UDP, the datagram is whole and the IPv4 source equals the authenticated local
   permanent VIP. The same VIP is the resolver allowlist.
5. At most one bounded response per accepted packet, at most the negotiated MTU,
   and at most the fixed per-window query budget. The budget uses a monotonic
   `Instant`, never UTC.
6. TCP is refused without a response; non-DNS traffic is consumed, not forwarded.

## Tests added or extended

| Test | Proves |
| --- | --- |
| `freshness_intersects_authority_signer_grant_and_policy` | A signer grant or policy that expires before the authority shortens the token window; verify at a time inside the authority but outside either bound fails. |
| `ipv6_claims_and_aaaa_records_are_refused_without_a_policy_ula` | A well-formed `fd00::/8` claim is still refused; AAAA implies a claim and is refused. |
| `AAAA outside ula` (proto scope test) | Proto still rejects an AAAA address outside `fd00::/8`. |
| `aaaa_is_nodata_because_ipv6_is_disabled_by_default` | Existing owner returns NOERROR/NODATA, not NXDOMAIN and not an AAAA address. |
| `signer_rotation_is_explicitly_disabled` | A correctly root-signed generation-2 grant is refused with `RotationUnsupported`. |
| `expired_token_is_refused_per_operation_without_reading_or_writing` | `poll_once` at expiry does not consume the queued packet; `handle_packet` at expiry answers nothing. |
| `fixed_rate_limit_bounds_answers_and_recovers_next_window` | Exhausted budget returns `RateLimited` even when UTC advances; only the next monotonic one-second window allows again. |

Existing dual-signature, slot, NXDOMAIN/REFUSED, source-spoof, TCP, malformed and
MTU tests are retained and updated for the explicit UTC `now` and monotonic
`Instant` arguments.

## Actions evidence required (not yet obtained)

The relevant existing jobs are in `.github/workflows/rust-tls.yml`:

- `cargo test --locked -p boreas-pki --features openssl-backend`
- `cargo test --locked -p boreas-tunnel --features openssl-inner-tls`
- `cargo clippy --locked -p boreas-pki -p boreas-tunnel -p boreas-cli --features boreas-cli/openssl-inner-tls --all-targets -- -D warnings`
- workspace `cargo test --workspace --locked` in `.github/workflows/ci.yml` and
  `.github/workflows/platforms.yml` covers `boreas-proto`.

These commands were **not** run locally. They must run on the exact commit that
contains this review; only terminal Actions results can be cited as evidence.

## Integration prerequisites and residual non-claims

- `Cargo.lock` does not yet list `boreas-dns` under `boreas-tunnel` even though
  `crates/boreas-tunnel/Cargo.toml` already has the optional dependency. Every
  `--locked` job will fail until the manifest/lock owner refreshes the lock. This
  review intentionally did not edit either file.
- The module is feature-gated (`openssl-inner-tls`) and is not constructed by the
  CLI or daemon. Enabling it there, adding a daemon capability, or exposing a
  config switch is out of scope and remains unproven.
- No durable anti-replay watermark, revocation feed, rollback protection or
  trusted clock source is implemented. Freshness `now` is caller-supplied UTC and
  a UTC rollback can revive an expired token; the rate limiter's `Instant` is
  monotonic but is supplied by the same caller. Neither is a trusted-time
  service.
- Signer rotation is disabled: only `signer_generation == 1` is accepted because
  the authority body does not bind the signer generation or grant digest. A
  later profile must bind them before rotation can be enabled.
- No TCP DNS, IPv6, recursion, forwarding, cache, negative SOA, DNSSEC, EDNS
  padding, multi-zone support or LAN-client source authorization.
- `boreas-dns` emits at most one address per owner and query type. A signed
  authority carrying several A records for one owner is not fully represented by
  this responder; that is a completeness gap, not an authorization bypass, and is
  not changed in this review.
- The code proves that the DNS signer is authorized by the pinned root; it does
  not compare the root and signer public keys. Provisioning genuinely distinct
  root and DNS-signer key pairs remains an operational requirement of the
  separation-of-duties design.
- The IPv6 wire fields remain for forward compatibility only. Enabling IPv6
  requires a signed policy ULA field, PKI verification against it, runtime
  enablement and new positive/negative tests; none of that is claimed here.
- A green unit test or a successful `cargo check` is not DNS production
  acceptance, interoperability evidence, or a security proof.
