# Rust OpenSSL backend over ordered WebSocket payload bytes — integration status

**Status (this change):** the strict pq768 backend is implemented behind the
`openssl-backend` feature in `crates/boreas-crypto/src/backend.rs`; the
in-memory `WsByteStream` payload-queue adapter and a non-blocking
`HandshakeDriver` are implemented in `ws_stream.rs` / `backend.rs`; the
GitHub Actions job is defined in `.github/workflows/rust-tls.yml`. No local
build or test was run for this change. The workflow has not been executed from
this checkout, so none of the results below is a CI-passed claim. Even after it
passes, same-implementation OpenSSL results are **not** the Phase 0 `G-CRYPTO`
gate and are not production authorization.

**Scope:** implement Boreas hop-TLS as ordinary TLS 1.3 over the ordered byte
stream carried by WebSocket binary payloads; do not implement TLS records,
extensions, hybrid composition, KEM, signatures, or certificate parsing
ourselves. The WebSocket Upgrade/framing engine remains outside this crate.

## Source observations

| Primary source | Observed capability | What it does not establish |
|---|---|---|
| [rust-openssl 0.10.82 `SslStream`](https://docs.rs/openssl/0.10.82/openssl/ssl/struct.SslStream.html) / [source](https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.82/openssl/src/ssl/mod.rs) | `SslStream<S>` wraps any `Read + Write`; `SslStream::new` performs no I/O; `do_handshake`, `ssl_read`, `ssl_write` expose `ErrorCode::{WANT_READ,WANT_WRITE}` for non-blocking drivers. The maintained BIO adapter maps `WouldBlock` to BIO retry and catches panics across FFI. | The BIO adapter does not turn the stream into a WebSocket engine: HTTP Upgrade, frame parsing, control-frame handling, compression rejection, and the transport-wide queue budget remain caller work. |
| [`SslContextBuilder`](https://docs.rs/openssl/0.10.82/openssl/ssl/struct.SslContextBuilder.html) | TLS version bounds, `set_groups_list`, `set_sigalgs_list`, `set_ciphersuites`, `set_verify_depth`, certificates, verify stores/modes, tickets/session cache, `set_max_early_data`. | Presence of a setter does not prove the pinned OpenSSL build registered the algorithm. This backend additionally checks the verified chain's SPKI/signature OIDs after every handshake. |
| [openssl-sys 0.9.118 SSL declarations](https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.82/openssl-sys/src/handwritten/ssl.rs) | `SSL_session_reused` is available for the one post-handshake resumption readout; `ForeignTypeRef::as_ptr` borrows the `SSL` object. | There is no safe negotiated-group or peer-signature-scheme getter in this binding. Those reported values remain constrained-context inference, not wire readout. |
| [OpenSSL 4.1.0 `ssl/t1_lib.c`](https://github.com/openssl/openssl/blob/openssl-4.1.0/ssl/t1_lib.c), [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html), [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html), [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), [TLS ML-DSA draft -06](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-06.txt) | OpenSSL 4.1.0 carries the hybrid group and the ML-DSA TLS/X.509 machinery used by the tests; RFC 10024 defines group `0x11EC`, RFC 9881 defines id-ml-dsa-65 OID `2.16.840.1.101.3.4.3.18`. TLS `mldsa65` is still draft-06 code point `0x0905` at this snapshot. | Source listing is not end-to-end identity authentication. The two test endpoints share the same OpenSSL codebase; no independent implementation has been interop-tested. 4.1.0 is itself affected by the reviewed advisories below, so this observation is capability evidence, never a security approval. |

The reviewed binding pins are `openssl = "=0.10.82"`, `openssl-sys =
"=0.9.118"`, `foreign-types-shared = "=0.1.1"`; this change adds no dependency
and does not modify `Cargo.lock`. `openssl-src`/`vendored` is deliberately not
used: it would select OpenSSL 3.2.0 rather than the reviewed 4.1.0 build.

## Pinned candidate and measured status (2026-11-17)

| Item | Pinned value | Status |
|---|---|---|
| `openssl` (rust-openssl) | `=0.10.82` | reviewed binding, unchanged |
| `openssl-sys` | `=0.9.118` | reviewed binding, unchanged |
| `foreign-types-shared` | `=0.1.1` | forced by the binding graph, see below |
| native OpenSSL | `4.1.0`, SHA-256 `50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd` | reduced build candidate, **security gate RED** |
| reduced options | `no-quic no-cms no-siv no-shared no-tests` | candidate surface reduction, not a waiver |
| fixed release `4.1.1` | none | not published; see below |

**Measured results for `openssl 0.10.82` + native `4.1.0`: none recorded in this
change.** No Actions run of `rust-tls.yml` or `crypto-poc.yml` was observed while
this record was written, so this document claims no build, handshake, capability
or CVE-reduction result for that pair. What is recorded is only: the release
metadata and tarball digest above (official API), the reviewed advisory ranges in
`tools/dependencies/openssl-review.json`, and the assertions the workflows are
required to produce. The native gate therefore stays red for two independent
reasons:

1. `CVE-2026-35190` (TLS 1.3 server key-share, Suite B cert flag) and
   `CVE-2026-107493` (`PEM_X509_INFO_read_bio_ex`) are not removed by
   `no-quic`/`no-cms`/`no-siv`; no whole-program or call-graph waiver is claimed.
2. OpenSSL `4.1.1` was **not released** on 2026-11-17: the official tag API
   returned HTTP 404 for `openssl-4.1.1`, while `releases/latest` still returned
   `openssl-4.1.0` with the reviewed digest. A fixed pin, checksum or migration
   cannot honestly be recorded, and none is invented here.

A green `verify-openssl-build.sh` run would only prove that the five reduced
configurations exclude the QUIC/CMS/SIV implementations they claim to exclude. It
would not close the gate.

## Dependency pin review

Recorded in `tools/dependencies/crates-review.json` and re-checked in Actions by
`tools/dependencies/check-crate-review.py`:

- **`foreign-types-shared` 0.3.1 is blocked, not pending.** `crates/boreas-crypto`
  imports `ForeignTypeRef` to pass a borrowed `SslRef` pointer to
  `openssl_sys::SSL_session_reused` without taking ownership. `openssl 0.10.82`
  links `foreign-types 0.3.2`, which requires `foreign-types-shared ^0.1`
  (resolved 0.1.1). A direct `=0.3.1` dependency would add a second copy of the
  crate, so `SslRef` would no longer implement the imported trait; the only ways
  to keep compiling would be a pointer transmute or dropping the borrow
  guarantee. 0.3.1 publishes no `rust-version` and exposes the same three public
  items (`Opaque`, `ForeignType`, `ForeignTypeRef`), but as a distinct crate major
  it is a distinct trait type: the blocker is type identity, not API shape, so no
  MSRV or changelog review can remove it. The pin stays `=0.1.1` because it is the
  same instance the binding uses.
- **`windows-sys` 0.61.2 is audited but not applied.** 0.61.2 is stable
  (published 2025-10-06) with `rust-version 1.71`, below the owning crate's 1.100;
  all seven enabled `Win32_*` features exist under the same names, and the
  `Win32_Security_Cryptography` `BCrypt*`, `IpHelper`, `Ndis` and `WinSock`
  modules the crate imports are still exported. Identical function signatures are
  expected but **not proven** without a Windows compile. The upgrade also replaces
  the `windows-targets 0.52.6` fan-out with `windows-link 0.2.1`, which rewrites
  `Cargo.lock` — owned by the Actions lock job, not by this tooling. The pin stays
  `=0.59.0` until that refresh lands together with a Windows build and the
  crypto/tun test suites.

Neither entry is a vulnerability waiver: both are reviewed decisions whose
justification is re-verified from crates.io metadata on every dependency run.

## Layering and byte flow

```text
outer TCP -> outer TLS/HTTPS -> HTTP Upgrade / WebSocket frames
                                           |
                          WsByteStream (ordered, bounded binary payload queue)
                                           |
                         SslStream<WsByteStream> / HandshakeDriver
                                           |
                      TLS 1.3 record layer, hybrid KEX, mTLS CertificateVerify
                                           |
                             encrypted inner TLS application bytes
```

- `WsByteStream` accepts only ordered binary payload bytes. It never parses
  frames or control messages; text frames, Ping/Pong/Close, HTTP headers and
  compression are rejected or consumed by the outer transport before this
  point. A WebSocket message boundary is never treated as a TLS record
  boundary.
- `feed_ciphertext`/`drain_ciphertext` use bounded queues. Empty-but-open reads
  return `WouldBlock`; a full write queue returns `WouldBlock`; bytes are never
  dropped or reordered. Per-stream capacity is hard-capped at 1 MiB (`0` and
  above-capacity requests are rejected with `InvalidInput`), but this is not a
  transport-wide quota: the WebSocket engine must allocate all live streams
  from the Phase 1 resource budget.
- `OpenSslConnector::start_connect` / `OpenSslAcceptor::start_accept` construct
  a non-blocking `HandshakeDriver`. `drive_handshake` maps `WANT_READ`/`WANT_WRITE`
  to `DriveState::Incomplete`; a completed driver still goes through
  `finish()` and the same certificate/chain/policy validation. `finish()`
  explicitly requires `SSL_is_init_finished()`, so a peer certificate that
  arrived before the Finished flight cannot create an `EstablishedStream`.
- `EstablishedStream::read_plaintext`/`write_plaintext` expose the same
  `WANT_READ`/`WANT_WRITE` distinction. On `WouldBlock`, `SSL_write` must be
  retried with the **same slice** (same bytes, length, pointer); only after
  `Ok(n)` may the caller advance by `n`. Retrying an assumed "unwritten suffix"
  would corrupt OpenSSL's retained write state.
- Keep outer WSS mTLS/HTTPS policy independent. CDN-terminated classical outer
  TLS does not satisfy inner TLS policy, and outer hybrid KEX does not satisfy
  inner authentication.

## Implemented configuration

`configure_strict_context` builds a plain, auditable OpenSSL context (not a
Mozilla profile) and enforces:

1. TLS 1.3 minimum and maximum.
2. Exactly one group, `X25519MLKEM768`, via `set_groups_list`.
3. Exactly one TLS signature algorithm, `mldsa65`, via `set_sigalgs_list`.
4. Only `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`.
5. `NO_TICKET`, session-cache OFF, `set_num_tickets(0)`, and
   `set_max_early_data(0)`; no PSK or early-data API is exposed.
6. Explicit Boreas trust anchor in both the certificate store and the separate
   verify store; no system roots. `PEER` on clients and
   `PEER | FAIL_IF_NO_PEER_CERT` on servers.
7. OpenSSL verify-depth upper bound 4 plus an explicit
   `MAX_CHAIN_CERTIFICATES = 4` total-certificate check after handshake.
   `SSL_CTX_set_verify_depth` counts intermediates, not total certificates, so
   the parameter name alone is not treated as equivalent to the master-plan
   depth-four total bound.
8. Local certificate and key must both be ML-DSA-65; their public components
   must be byte-identical (`public_key_to_der`); PEM inputs are bounded at
   64 KiB for certificate/trust anchor and 16 KiB for the private key, enforced
   both before file parsing and for in-memory callers.
9. `PemIdentity` has a custom `Debug` that prints lengths and `<redacted>`; it
   never prints certificate, key, or trust-anchor bytes.
10. Every certificate in the OpenSSL verified chain is checked for an
    ML-DSA-65 SPKI and ML-DSA-65 signature OID; the peer leaf must be ML-DSA-65.
11. After handshake: `SSL_is_init_finished`, `verify_result == OK`, TLS 1.3,
    allowed AEAD, `SSL_session_reused == 0`, and the pure
    `Policy::validate_negotiated` gate.

## Identity and authorization boundary

The backend returns the verified peer leaf certificate only. It does **not**
create a production session token and does not prove the peer's Boreas
`net_id`, role, `NodeID`, `identity_generation`, or scope. Those checks remain
application-layer work: the caller must parse the signed identity object,
verify its issuer/authority and scope, require the identity public key to match
the TLS leaf, then call `Policy::validate_peer`. `Policy::establish` still
fails closed with `BackendUnavailable`; the marker `TlsBackend` trait is not a
session factory. A completed TLS handshake alone is not authorization.

## Tests in the crate

`crates/boreas-crypto/tests/openssl_mtls_handshake.rs` runs only on Unix with
the `openssl-backend` feature and generates an ephemeral ML-DSA-65 PKI with the
pinned OpenSSL CLI. `BOREAS_REQUIRE_TLS_TESTS=1` is honoured by the CI job so a
missing/incapable CLI cannot silently turn the suite into skips;
`BOREAS_OPENSSL_BIN` pins the exact CLI under test.

Positive cases:

- Rust<->Rust concurrent mTLS over a Unix socket pair, three fresh handshakes,
  DER-identical peer leaves, strict negotiated report, ping/pong and 32 KiB
  plaintext round-trips.
- The same handshake over in-memory `WsByteStream` queues with deterministic
  chunk sizes, queue back-pressure, and the non-blocking driver/plaintext API.
  **This is a payload-queue test, not an HTTP Upgrade, RFC 6455 framing, outer
  HTTPS, WSS, or network WebSocket engine test.**
- `s_client` interop against the Boreas acceptor over loopback TCP for both
  allowed AEADs, asserting the CLI-reported group name and
  `Signature type: mldsa65`. This is the same OpenSSL implementation, not
  independent interop.

Fail-closed cases:

- Wrong trust anchor on either end, expired client certificate, missing client
  certificate, classical-only group offer, disallowed AEAD-only offer, TLS
  1.2-only client, malformed/truncated/empty ciphertext stream.
- Classical RSA leaf, pq1024 in either policy shape, mixed ML-DSA/RSA local
  identity, and a valid ML-DSA certificate paired with another ML-DSA key
  (`LocalIdentityMismatch`).
- `finish()` before any handshake and before the server has received the
  client's complete Finished flight.

Test-material discipline: per-test temporary directories (0700 on Unix),
removed on drop; no private key, PSK, traffic secret, or generated key material
is uploaded. CLI output is sanitized line-by-line before assertions.

## Honest limits (not proven by these tests)

1. **No independent implementation interop.** OpenSSL CLI and rust-openssl are
   the same codebase. GnuTLS/Go/wolfSSL interop from
   `docs/research/phase0-tls-backend-interop-2026-11-15.md` remains Phase 0
   work.
2. **No WSS/HTTP Upgrade integration.** `WsByteStream` is an in-memory ordered
   queue. There is no HTTP/1.1 `Upgrade` or HTTP/2 Extended CONNECT state
   machine, RFC 6455 frame parser, control-frame handling, compression
   rejection, network WebSocket engine, or transport-runtime integration here.
3. **Negotiated group and peer signature are inferred.** `openssl 0.10.82` has
   no safe `SSL_get_negotiated_group`/peer-signature getter. The backend's
   singleton offer plus full verified-chain ML-DSA-65 checks support the
   reported values, but are not a direct read of wire code points
   `0x11EC`/`0x0905`. The CLI test reads the group name from the same OpenSSL
   codebase, not an independent decoder.
4. **`session_reused` uses one audited FFI read.** `unsafe {
   openssl_sys::SSL_session_reused(ssl.as_ptr()) }` borrows the `SSL` object via
   `foreign-types-shared`; the safety argument needs ADR review. `zero_rtt ==
   false` is a constant backed by `set_max_early_data(0)` and the absence of an
   early-data API, not a negotiated readout.
5. **`signature_algorithms_cert` is not set by a public setter.** The
   post-handshake verified-chain loop is the enforcement point; no separate
   wire-level whitelist is proven.
6. **Chain-depth enforcement is only partially exercised.** The explicit
   total-4 check and its boundary logic are unit-tested. No CI test yet builds
   a five-certificate chain to prove OpenSSL rejects it end-to-end.
7. **No static musl/aarch64 evidence.** The workflow builds `no-shared`
   OpenSSL on `ubuntu-24.04` x86_64 only; that is not a fully static libc
   binary or an aarch64 handshake.
8. **No production session/authorization or resource evidence.** No
   `SessionHello`/`SessionAccept` binding, no production WSS transport, no
   measured per-stream/global queue budget, no 30-minute resource run, and no
   external security review.
9. **This checkout has not executed the workflow.** CI results, logs, and
   artifacts must be read from GitHub Actions after the integration push.

## CI job (defined, not executed here)

`.github/workflows/rust-tls.yml`:

1. Downloads the pinned OpenSSL 4.1.0 tarball, verifies its SHA-256, checks
   `VERSION.dat`, builds `no-quic no-cms no-siv no-shared no-tests`, installs it,
   writes a minimal default-provider-only `openssl.cnf`, and records `version -a`
   plus `readelf -d` evidence. `.github/workflows/crypto-poc.yml` builds the same
   reduced configuration and runs `tools/dependencies/verify-openssl-build.sh`.
2. Refuses a `vendored` feature in `crates/boreas-crypto`.
3. Runs `cargo fmt -p boreas-crypto -- --check`.
4. Runs policy-only tests without OpenSSL.
5. `cargo check -p boreas-crypto --features openssl-backend --all-targets`
   with `OPENSSL_DIR`/`OPENSSL_STATIC=1`/`OPENSSL_NO_VENDOR=1`.
6. Runs the full crypto feature test suite with `BOREAS_OPENSSL_BIN` and
   `BOREAS_REQUIRE_TLS_TESTS=1`, tees the log, and uploads non-secret evidence.
7. Runs `cargo test -p boreas-pki --all-features` for the real OpenSSL
   management/CSR/signing tests and `cargo test -p boreas-tunnel
   --all-features` for the inner-TLS seam with the backend feature, uploading
   their logs separately.
8. The job builds only `no-shared` OpenSSL on Ubuntu x86_64 and (for the musl
   variant) does not prove a fully static libc release or an aarch64 handshake.
   The workspace default feature set has no crypto backend at all; a default
   build must not be described as a complete TLS-capable binary, and
   platform-gates/static release work must retain that distinction.
9. `.github/workflows/dependencies.yml` runs the independent gates this document
   depends on: locked RustSec audit, registry/advisory/native-OpenSSL intelligence
   (`report.py`), the reviewed crate decisions (`check-crate-review.py
   --verify-candidates`), the action-pin audit (`check-action-pins.py
   --verify-remote`) and network-free fixtures for that tooling. Those jobs prove
   the review record still matches reality; they do not approve the 4.1.0 pin.

## Follow-up (not done)

- A published OpenSSL `4.1.1` (or a reviewed, still-supported branch) with an
  official digest; until then `CVE-2026-35190` and `CVE-2026-107493` keep the
  native gate red regardless of the reduced-build result.
- First Actions measurement of `openssl 0.10.82` + native `4.1.0`, including
  `verify-openssl-build.sh` evidence and real mTLS logs; nothing is measured in
  this change.
- `windows-sys` 0.61.2 adoption together with the Actions lock refresh and a
  Windows build, then removal of its review entry's candidate state.
- Direct negotiated group/sigalg readout (upstream getter or reviewed FFI ADR).
- Independent implementation interop matrix and code-point capture.
- HTTP Upgrade + RFC 6455/8441 framing and a real WSS transport engine, wired
  to this byte-stream adapter.
- Production identity/authorization binding on top of the verified leaf.
- x86_64/aarch64 static musl builds and native handshakes.
- Five-certificate depth negative case, queue resource measurements, and
  external review.

## Sources

- [rust-openssl v0.10.82 release](https://github.com/rust-openssl/rust-openssl/releases/tag/openssl-v0.10.82)
- [SslStream API](https://docs.rs/openssl/0.10.82/openssl/ssl/struct.SslStream.html)
- [SslContextBuilder API](https://docs.rs/openssl/0.10.82/openssl/ssl/struct.SslContextBuilder.html)
- [SslRef API](https://docs.rs/openssl/0.10.82/openssl/ssl/struct.SslRef.html)
- [Maintained binding BIO adapter source](https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.82/openssl/src/ssl/bio.rs)
- [OpenSSL binding `openssl-sys` SSL declarations](https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.82/openssl-sys/src/handwritten/ssl.rs)
- [OpenSSL 4.1.0 TLS group/signature discovery source](https://github.com/openssl/openssl/blob/openssl-4.1.0/ssl/t1_lib.c)
- [OpenSSL 4.1.0 security advisories](https://openssl-library.org/news/vulnerabilities/)
- [crates.io `foreign-types-shared`](https://crates.io/api/v1/crates/foreign-types-shared)
- [crates.io `foreign-types` 0.3.2 dependency requirement](https://crates.io/api/v1/crates/foreign-types/0.3.2/dependencies)
- [crates.io `windows-sys`](https://crates.io/api/v1/crates/windows-sys)
- [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html)
- [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)
- [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html)
- [draft-ietf-tls-mldsa-06](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-06.txt)
