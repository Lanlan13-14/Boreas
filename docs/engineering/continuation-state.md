# Full-plan execution state

## Human requirements

- Complete the entire v1.11 master plan, all Phase 0–5 implementations and applicable acceptance evidence; a skeleton or isolated subset is not completion.
- Delegate implementation primarily to `lightcode/gpt-6-luna`; lead owns decomposition, static review, integration, and evidence.
- Commit and push normal changes to `https://github.com/Lanlan13-14/Boreas`, branch `main`; never force-push.
- **All compilation and tests run in GitHub Actions, not locally.** Do not run local cargo/rustc/Python verification or formatter checks. Static reading and Git operations are allowed. CI can format and return/commit formatting changes.
- Final releases must include mainstream Linux (x86_64/aarch64 static), Windows, and macOS (Intel/Apple Silicon). Platform builds alone are not proof of real TUN/routing/security/upgrade functionality. No production release until applicable gates pass.
- No approval prompts. No invented TLS/security/performance/third-party review evidence.

## Baseline observations (2026-11-14)

- Initial tracked repository contained README and GPL license only; main/origin began at `4a51750dd1716c90cc2b423ae7bc92f5106b713d`.
- Supplied plan and existing untracked plan copy were read and have matching SHA-256 `23969614DD3F027EF8828B831F170BBBCAA3C29C99E93BEC20F5983F685086AA`.
- Stable manifest downloaded with curl into ignored `.local/rust-stable-manifest.toml`, date 2026-11-12. Local installed Rust updated from 1.97.1 to 1.100.0 (`0ef1bc386`, 2026-11-09) before the user instructed CI-only tests. This is toolchain metadata, not build evidence.
- Public GitHub Actions API is readable using curl without authentication. Initial `/repos/Lanlan13-14/Boreas/actions/runs?per_page=5` returned zero runs. Git credential manager is configured; secrets must never be printed.
- WSL has no Linux installation here. Do not install/start a replacement environment; use Actions as instructed.

## Work allocation, round 1

- `protocol`: `crates/boreas-proto/**`, `docs/protocol/**`; AppHeader, streaming parser, CBOR subset, control registry and vectors. Lead sent required fixes for panic/state confusion, header-before-body allocation, output quota, bounded depth, poisoning.
- `identity`: `crates/boreas-pki/**`, `crates/boreas-crypto/**`; addresses, authority, status/clock and TLS policy-only boundary. Lead sent required fixes for UTC microseconds, latched rollback, exact authority/own-Core, equivocation, and avoiding boolean fake authentication.
- `foundation`: root Cargo/toolchain/lock/ignore, main CI, CLI, README, ADR and status ledger. Lead requested accurate MSRV 1.100, real repository URL, substantive CLI dispatch tests, CI formatting handling, member/lock alignment.
- `crypto-research`: `docs/research/**`, then `tools/crypto-poc/**` and `.github/workflows/crypto-poc.yml`; maintained release backend PoC with actual hybrid ML-DSA mTLS and negative cases, only in Actions. Initial research is not G-CRYPTO evidence. Must correct confusion between plan hash and stable-manifest hash.
- `routing`: `crates/boreas-tunnel/**`; prefix classifier, deterministic routes and checked connection budget. Lead identified and requested fixes for range arithmetic, missing reserved IPv6 ranges, poison/equivocation arrival dependence, HA health/size, numeric NodeIDs, and SuppressedBy IDs.
- `independent-vectors`: `tools/verify_vectors.py`, `tools/tests/**`; independently written Python parser checks candidate JSON fixture; must run only in CI.
- `tun`: `crates/boreas-tun/**`; PacketIo/VirtualTun, packet/virtio parsing, PMTU, fragment bounds. Lead requested strict fragment absolute lifetime/whole-group rejection, non-first IPv6 handling, checksum/offload refusal and byte quotas.
- `dns`: `crates/boreas-dns/**`; authoritative wire DNS semantics and bounded parser. Real TCP DNS stack remains an explicit subsequent task, not a fake packet response.
- Child limit is 8 active. Reuse finished agents for upgrade supervisor, enrollment transactions, relay/transport, sandbox, UI and remaining work.

## Immediate integration sequence

1. Collect each child result; static review final files/diff. Do not compile locally.
2. Confirm workspace manifests and lock cover actual members; exclude local `.exe/.pdb` artifacts generated before CI-only instruction.
3. Push an honest initial implementation batch to main to start Actions. Inspect exact commit SHA/run URL and logs; repair failures and retrieve CI formatting output if needed.
4. Keep status/gate ledger aligned with code and actual CI. CI green unit tests do not mean G-CRYPTO/production gates pass.
5. Continue complete plan: standard TLS over real WSS memory streams; deterministic signed management schema/independent vectors; durable enrollment/IPAM/tombstones; actual data plane, resource admission/queues; LinuxTun/GSO/ICMP/true TCP DNS/seccomp; upgrade journal/supervisor/release verifier; directory/topology/failover; three-language control UI; E2E circuits and exact identity binding; attack/fault/performance matrices; independent review.
6. Some gates need external deployment/CDN/audit resources. Build/run all feasible CI infrastructure and implementations instead of stopping at these open gates, and never fabricate external review.

## Integration checkpoint (round 1, approximately 2026-11-14 22:20 +08)

- Main pushed implementation commits `61430a9`, `5d96379`, `44f9f4d`, `770bced`, `a5b5508`, `36a7501`; CI formatting commits were fast-forward integrated, latest known `ec1f7a5` before `a5b5508`. No local compilation/tests after CI-only instruction.
- Rust CI6 run `43604239086` at `36a7501`: cargo check passes Linux/Windows; Python fixed vectors and tests pass. Remaining failures: supervisor one collapsible-if lint (owner fixed locally), DNS packet tests use decimal IPv6 low word 53 instead of required hex `0x53` (owner fixing). Prior DNS wire tests now all pass. Need subsequent test runs to reach later crates (cargo stops at first failed test binary).
- Platform run `43604239094` still fails workspace tests, not runner allocation: Linux x86_64/aarch64 musl, Windows x64, macOS Intel/Apple Silicon runners and architecture checks actually work. No development artifacts accepted yet, no production releases.
- Crypto PoC2 run `43603816608`: pinned OpenSSL 3.6.1 tarball hash and source/static-library build passed. Client negotiated TLS1.3/hybrid/ML-DSA/AES and received HTTP response; script failed explicit server verification-log assertion. Server -brief log includes client Certificate and CertificateVerify but no explicit verifier output. crypto-research is fixing verbose verification/no-ticket and adding wrong-CA/EKU negative cases. Do NOT call G-CRYPTO passed.
- Crypto artifact `14117716318` contained temporary test resumption PSK in openssl -www output. Lead deleted remote artifact; GET run artifacts returned total_count 0. Ignored local copy is `.local/crypto-evidence2/crypto-poc-artifacts/`; do not publish raw session dumps. Future uploads must exclude/redact TLS secret fields and disable tickets/resumption; these are generated test keys only, no production credentials.
- CI logs in ignored `.local/ci-linux{2,3,4,5,6}.log`; crypto logs `.local/crypto{1,2}.log`. Read with read/grep tools, not shell cat. Authenticated logs/artifacts can use in-memory `git credential fill` password as Bearer header; never print secret. Public API metadata uses curl without auth.
- Working untracked next-batch modules: proto objects + management schema/vectors (protocol owner and independent-vectors checker still reviewing), pki enrollment (identity owner fixing reviewed persistence/scope/test problems), tunnel resource/scheduler/relay (foundation owner static review complete, ready to export/test), crypto backend.rs proposal (not exported, external openssl dep not added). Do not forget these files or claim unexported modules tested.
- Further checkpoint approximately 22:30 +08: main latest pushed `696a77a` (docs) after `1758470` (valid DF checksum test) and merge `25fcf0f`. CI8 run `43605086277` at `1758470` has all compiler/Clippy/Python checks passing; all unit suites now pass through TUN, with last tunnel suite 7 passed / 1 failure: `special_boundaries_and_mgmt_overlap` expects ReservedRange for fe80::/10 or ff00::/8, but the mandated prefix-width floor runs first and correctly returns TooBroad. Routing owner is fixing test expectations and adding qualifying /48 reserved subprefix cases. CI9 at `696a77a` (`43605148358`) has same source, likely same failure. Main documents have been updated with partial evidence, still no complete phase/gate.
- Latest run `43605397941` at `24c9dbc` still has exactly one tunnel test failure: IPv4 `224.0.0.0/4` also violates the /8 width floor before reserved-range classification. Routing owner fixing this and adding `{s}` assertion context plus legal /8 multicast subprefix test. All other compiled main modules and Clippy/Python now pass. Next: push this last expectation correction and reviewed crypto PoC patch when ready; monitor exact Actions SHA/results; then integrate/export next-batch modules with fresh CI. Protocol and independent-vectors have reported static-ready six-object schemas/raw fixtures/Python checker; no local tests performed, and objects.rs remains unexported. Keep compilation/test failures fixed, not papered over by allow/skip. New dependencies require lockfile generation only in Actions, returned/committed by CI. Crypto owner currently changing PoC script; lead warned `-rev` version must account for reversed echo and shutdown (cannot use -ign_eof and expect server to close indefinitely); prefer bounded reliable application exchange, explicit certificate verifier logs, no tickets, and secret-safe evidence upload.
- Git author set repository-local to Boreas Development Agent / boreas-development-agent@users.noreply.github.com (not impersonating the user). Normal push works via configured Git credential manager. One retained stash `supervisor-before-actions-format` is a backup from resolved formatting conflict; do not apply it again.

Goal remains active until the whole user objective is achieved; commits and unit-test success alone are not completion.
