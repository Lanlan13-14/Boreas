# Full-plan execution state

## Human requirements

- Complete the entire v1.11 master plan, all Phase 0–5 implementations and applicable acceptance evidence; a skeleton or isolated subset is not completion.
- Delegate implementation primarily to `lightcode/gpt-6-luna`; lead owns decomposition, static review, integration, and evidence.
- Commit and push normal changes to `https://github.com/Lanlan13-14/Boreas`, branch `main`; never force-push.
- **All compilation and tests run in GitHub Actions, not locally.** Do not run local cargo/rustc/Python verification or formatter checks. Static reading and Git operations are allowed. CI can format and return/commit formatting changes.
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

Goal remains active until the whole user objective is achieved; commits and unit-test success alone are not completion.
