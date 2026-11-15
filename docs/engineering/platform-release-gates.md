# Platform functional verification, packaging and release gates

**Status: development-only evidence. No production release is approved.** The
current `boreas` executable has no daemon, WSS/TLS transport, TUN adapter,
routing, DNS service or data plane. The workflows described here run real
native builds, execute the real CLI, verify Linux static linkage, exercise real
native TUN/Wintun/utun device tests where the crate provides them, and produce
unsigned development archives. They do **not** pass the master-plan
[Phase 0–5 gates](../plans/BOREAS-MASTER-PLAN-v1.11.0.md#十一实施路线图与发布门禁)
or the common production exit conditions.

Two statements are load-bearing:

1. `doctor` success is **not** a VPN test. It only proves that the CLI process
   starts and reports its own capabilities honestly.
2. A green platform run is **not** production acceptance. Production promotion
   remains blocked until the exact-commit gate ledger passes, an independent
   audit exists, and an offline Ed25519 + ML-DSA ReleaseRoot promotion bundle
   is verified. CI never generates the ReleaseRoot private key.

## 1. Evidence levels

| Level | Produced by | What it proves | What it does not prove |
|---|---|---|---|
| Development build | `platforms.yml` `build-test` | The workspace compiles and its tests pass on five native runners; the release CLI executes | VPN functionality, security, performance, production readiness |
| Static-link evidence | `verify_static_linux.py` on both Linux targets | The packaged executable has no `PT_INTERP` and no `DT_NEEDED`; ELF machine matches the target | TLS backend presence, runtime behaviour beyond the CLI smoke |
| Container runtime evidence | `linux-runtime-compat` | The static CLI starts and reports honestly in Ubuntu/Debian/Fedora/Alpine on x86_64 and aarch64 | Distro kernel, systemd, TUN, routing or data-plane compatibility |
| Native device evidence | `linux-system.yml`, `native-device.yml` | A real TUN/Wintun/utun adapter was created, a packet round trip was attempted, and cleanup occurred | Full VPN tunnel, routing, DNS, failover or release acceptance |
| Development bundle | `make_index.py`, `verify_bundle.py` | Five archives exist, hashes/sizes match, embedded metadata agrees | Authenticity, production signatures, gate acceptance |
| Production promotion | `tools/gates/verify.py` + `production_promotion.py` | Evidence metadata is complete for the exact commit; an independent verifier validated both manifests' Ed25519 + ML-DSA-65 signatures and all artifacts | Truth of the underlying audit/measurements; independence of the verifier is a human/contract check |

## 2. CI entry points

### 2.1 `platforms.yml` — five native targets and development bundle

Trigger: push, pull request, `workflow_dispatch`. Jobs:

- `lock-preflight` — fails with an actionable message if `Cargo.lock` is stale
  for the workspace manifests. It never edits the lock.
- `build-test` — five native matrix entries:
  - Linux x86_64 `x86_64-unknown-linux-musl` on `ubuntu-24.04`
  - Linux aarch64 `aarch64-unknown-linux-musl` on `ubuntu-24.04-arm`
  - Windows x86_64 `x86_64-pc-windows-msvc` on `windows-2025`
  - macOS Intel `x86_64-apple-darwin` on `macos-15-intel`
  - macOS Apple Silicon `aarch64-apple-darwin` on `macos-15`
- `linux-runtime-compat` — eight container jobs (two architectures × four
  distributions). Each extracts the packaged archive and runs `doctor`,
  `self-check` and an unknown-command failure check inside the container.
- `development-bundle` — downloads the five per-target artifacts, recomputes
  every archive hash, verifies each embedded `RELEASE.json`, writes
  `release-index.json`, `SHA256SUMS`, `platform-evidence-candidate.json` and
  `README-DEVELOPMENT.txt`, then re-verifies the result.

Artifacts (run-scoped, 14 days):

- `boreas-development-<target>-<run_id>` — archive, provenance, static report
  (Linux), functional smoke report and toolchain record.
- `boreas-development-release-<run_id>` — the five-target unsigned bundle.
- `container-runtime-<target>-<distro>-<run_id>` — per-container evidence.

The development bundle is deliberately **not** eligible for production
promotion. Its `platform-evidence-candidate.json` records
`functional_test: "not_run"`, `real_packet_io: false` and
`qualifies_as_production_platform_evidence: false`. `tools/gates/verify.py`
must therefore reject it as production platform evidence.

### 2.2 Native device workflows

`linux-system.yml` is the existing real Linux TUN gate. It runs the crate's
`linux_device.rs` tests as root with `BOREAS_REQUIRE_TUN=1`, requires the exact
test names `create_verify_mtu_multiqueue_and_auto_cleanup` and
`real_l3_write_and_kernel_routed_reply`, and rejects skipped/failed/ignored
tests. It is crate-level evidence, not a shipped VPN data-plane test.

`native-device.yml` is the wiring for `native-packetio`:

| Platform | Runner(s) | Test target | Required test | Marker |
|---|---|---|---|---|
| Windows | `windows-2025` | `crates/boreas-tun/tests/windows_device.rs` | `real_wintun_device_packet_round_trip` | `BOREAS_DEVICE_EVIDENCE platform=windows driver=wintun adapter=created packet_roundtrip=ok cleanup=ok` |
| macOS | `macos-15`, `macos-15-intel` | `crates/boreas-tun/tests/macos_device.rs` | `real_utun_packet_round_trip` | `BOREAS_DEVICE_EVIDENCE platform=macos driver=utun adapter=created packet_roundtrip=ok cleanup=ok` |

Both tests must panic when `BOREAS_REQUIRE_TUN=1` and prerequisites are
missing. The guard (`tools/release/native_device_guard.py`) requires at least
one passed test, zero failed, zero ignored, the exact test name and the marker.
A missing driver, an unelevated run or a skipped test fails the job.

Windows test dependency trust boundary:

- The official Wintun 0.14.1 ZIP is downloaded from
  `https://www.wintun.net/builds/wintun-0.14.1.zip`.
- The workflow pins the vendor-published ZIP SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, the
  extracted `amd64/wintun.dll` SHA-256
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`, and the
  Authenticode signer thumbprint
  `DF98E075A012ED8C86FBCF14854B8F9555CB3D45` / `CN=WireGuard LLC`.
- This is a **test-dependency integrity pin plus Windows publisher check**, not
  a Boreas ReleaseRoot, not an independent supply-chain attestation, and not a
  production artifact signature. The Wintun DLL is not vendored or shipped by
  these workflows.

Linux aarch64 real TUN device coverage is not yet present; the current
`linux-system.yml` runs on x86_64 only. That is an open unmet condition.

### 2.3 `release-promotion-gate.yml` — fail-closed promotion

Manual only. It checks the candidate commit is on `main`, runs the gate tool
unit tests, then:

```sh
python tools/gates/verify.py --ledger docs/engineering/gates.json --commit "$COMMIT"
```

With the checked-in ledger this normally fails: every gate is `open` and
`production_approved` is `false`. That is the intended state. If the ledger
passes, the workflow can download an externally produced signed promotion
bundle and run `tools/release/production_promotion.py` with an independent
verifier. It still **never publishes** a release, tag or GitHub Release.

## 3. Gate matrix

The authoritative evidence ledger is
[`gates.json`](gates.json); the verifier is [`tools/gates/verify.py`](../../tools/gates/verify.py).
The verifier checks metadata consistency only. It does not download reports,
prove an auditor is independent, or validate that a measurement is true. A
malicious writer can fabricate metadata; protected-branch review, an independent
release approver, retained reports and offline signatures remain necessary.

| Gate | Required evidence (summary) | Current status | Applicable CI path / gap |
|---|---|---|---|
| `G-CRYPTO` | Hybrid TLS 1.3 + ML-DSA mTLS on the actual Boreas Rust/WSS path; independent interoperability; static architecture support | Open | Crypto PoC is a separate OpenSSL harness, not Boreas Rust/WSS; `rust-tls.yml` is owned by the crypto agent |
| `G-FRAME` | AppHeader parser invariance, bounds, malformed/unknown/DoS cases | Open | Unit tests exist; no gate-level adversarial evidence |
| `G-DATA` | VirtualTun and real LinuxTun 1 GiB transfer, hash, disconnect/congestion/reconnect | Open | No shipped data plane; real TUN only crate-level device tests |
| `G-RESOURCE` | 195/291 connection workloads, 30 min RSS/PSS/cgroup evidence | Open | No topology runtime |
| `G-PERF` | Prescribed RTT/loss/rate/topology measurements | Open | No benchmark evidence |
| `G-ENROLL` | 16-way invitation race and crash/disk-full idempotency | Open | No transaction integration evidence |
| `G-AUTHZ` | Scope/role/generation/equivocation/dual-signature rejection | Open | PKI policy primitives only |
| `G-REVOKE` | Freshness, replay, clock rollback, partition cleanup | Open | No signed revocation integration |
| `G-DOS` | Staged cost/fairness and anonymous flood evidence | Open | No network listener |
| `G-TUN` | Queue/GSO/checksum/fallback on real devices | Open | Linux crate tests exist; Windows/macOS tests wired but not yet green; no shipped adapter integration |
| `G-MTU` | 1500→1280, 9000→1500, DF/PTB/TTL/firewall matrix | Open | Primitives only |
| `G-DNS` | UDP/TCP DNS, NODATA/NXDOMAIN/REFUSED, limits, no recursion | Open | Packet path exists; full matrix absent |
| `G-SANDBOX` | seccomp/ABI positive/negative, fd/resolver audit | Open | Fixture audit only; daemon not audited |
| `G-UPGRADE` | Crash/power-loss/disk-full/cross-FS/supervisor recovery | Open | Journal primitives and minimal supervisor; fault matrix absent |
| `G-CONVERGE` | Order/partition/equivocation convergence | Open | No directory runtime |
| `G-PREFIX` | Canonical prefix and reserved/scope/property evidence | Open | Pure classifier tests only |
| `G-FAILOVER` | Four-Core multi-Edge measured failover | Open | No topology runtime |
| `G-SUPPLY` | Dual-signature artifacts, SBOM, reproducibility, update journal | Open | Development packaging only; no production signatures/SBOM |
| `G-UI` | Three locales, narrow/non-TTY, NO_COLOR, DSR, injection/redaction | Open | Current CLI is a one-shot status/config slice; no full TUI |
| `G-E2E` | Same/cross-Core/gateway/endpoint E2E TLS identity binding | Open | Not implemented |
| `G-NO-DOWNGRADE` | Capture proof strict-mode failures never send hop-only traffic | Open | No data plane |
| `G-E2E-COST` | E2E TLS context/circuit/RSS/CPU/latency re-measurement | Open | Not measured |
| `G-EXTERNAL-REVIEW` | Independent crypto/protocol audit, fuzzing, dependency audit, findings closed | Open | No audit; must not be self-certified |
| `G-OPERATIONS` | Rollback, key revocation, backup/restore, overload drills | Open | No production operations evidence |

All five platform entries in `gates.json` also require exact-commit native
functional execution, real packet I/O and Linux static-linkage evidence. The
current development bundle intentionally fails those fields because the CLI
has no packet data plane.

## 4. Development archive contents

Each archive contains only:

- `boreas` (Linux/macOS) or `boreas.exe` (Windows);
- `LICENSE` (GPL-3.0-only);
- `SOURCE.txt` with repository URL, exact commit and license pointer;
- `RELEASE.json` with target, version, source commit, Cargo.lock SHA-256,
  build profile/rustc/runner OS, functional-smoke result and the explicit
  `production_release: false` / `signing.production_signatures: false` flags.

Archive metadata is normalized (sorted members, uid/gid 0, empty owner names,
1980-01-01 mtime, deterministic gzip header) so identical staged bytes produce
identical archives. This is not a bit-for-bit reproducible Rust build claim:
the executable depends on the toolchain and build environment, and no SBOM or
reproducible-build attestation is produced yet.

Verify a downloaded development bundle:

```sh
python tools/release/verify_bundle.py --bundle <bundle-directory>
```

It rejects path traversal, symlinks, unlisted archives, duplicate members,
declared/actual size mismatches, hash mismatches, production claims and
CLI-only bundles that claim real packet I/O.

## 5. Production promotion procedure

Production publication is **offline and human-controlled**. CI is never the
signing authority and must never contain a ReleaseRoot private key.

Preconditions:

1. Freeze a full 40-hex commit on `main`; no formatter or other bot commit may
   move the candidate afterwards.
2. `tools/gates/verify.py --ledger docs/engineering/gates.json --commit <sha>`
   must pass. That requires every gate accepted with exact-commit evidence,
   immutable Actions run URLs, report SHA-256 values, reviewer, UTC timestamp
   and an independent-review record with zero unresolved high/critical issues.
3. Build and retain the five production archives for that exact commit.
4. An offline ReleaseRoot signs the raw bytes of **both** the release manifest and
   the outer promotion manifest with Ed25519 **and** ML-DSA-65. Private keys
   remain offline; the public `release-root/roots.json` is distributed
   out-of-band with a pinned SHA-256.
5. An independently maintained verifier validates both manifests, all four
   signature halves, the ReleaseRoot hash and every artifact.
   `production_promotion.py` invokes that verifier; it does not self-certify
   cryptography.

Bundle layout (two manifests, each dual-signed over its own exact bytes):

```text
promotion-bundle/
  release-manifest.json                 # supervisor-compatible; exact signed bytes
  release-signature-envelope.json       # detached Ed25519 + ML-DSA-65 over (1)
  promotion-manifest.json               # outer binding: commit, hashes, artifacts
  promotion-signature-envelope.json     # detached Ed25519 + ML-DSA-65 over (3)
  release-root/roots.json               # public SPKI DER by key_id; no private keys
  artifacts/                            # exactly five archives named by (1)
  verification/verification.json        # written by the independent verifier
```

`release-manifest.json` is the **actual release manifest**, using the same
strict schema parsed by `boreas-supervisor` (`crates/boreas-supervisor/src/
manifest.rs`): `product: "boreas"`, `manifest_version: 1`, positive `sequence`,
`published_at <= issued_at < expires`, bounded `min_compatible_state` and
`signing_key_id`, and assets with exactly `name`, `arch`, `size`, `sha256` and
an `https://` `url`. Unknown top-level fields are rejected. The five `arch`
tokens are the platform tokens from `docs/engineering/gates.json`
(`linux-x86_64-static`, `linux-aarch64-static`, `windows-x86_64`,
`macos-x86_64`, `macos-aarch64`), so the supervisor can select one asset per
platform without ambiguity. The manifest lifetime is capped at 90 days to match
the supervisor's release policy ceiling.

`promotion-manifest.json` is the **outer promotion binding**. It records the
exact commit, `release_manifest_sha256`, `gate_ledger_sha256`,
`release_root_sha256`, `signing_key_id` and the five artifact names/sizes/
hashes. It deliberately contains **no hash of itself**; including a
`signed_sha256` of the manifest inside the manifest would be a self-referential
fixed point and cannot be generated. The detached
`*-signature-envelope.json` files live outside the signed bytes and are allowed
to record the SHA-256 of the file they sign (`manifest_sha256`) together with
the base64 Ed25519 (64-byte) and ML-DSA-65 (3309-byte) signatures. Both
envelopes must verify.

The promotion tool enforces bounded sizes, duplicate-key rejection, the exact
schemas above, RFC3339 offsets, the 90-day ceiling, five unique platform
assets, safe basenames, HTTPS-only URLs, the pinned ReleaseRoot hash, artifact
sizes/SHA-256, the exact-commit gate ledger, and an independent verifier report
covering **both manifests'** dual signatures and all five artifacts. It never
parses or accepts a manifest with a self-hash.

The independent verifier writes `verification/verification.json` with:
`schema: "boreas.production.external-verification.v1"`, `result: "pass"`,
`release_root_sha256`, `release_manifest_sha256`,
`promotion_manifest_sha256`, a `verifier` object with `name` (and optionally
`version`), a `signatures` list of
`{manifest: "release"|"promotion", algorithm: "ed25519"|"mldsa65", key_id,
valid: true}` records (all four required), and an `artifacts` list of
`{name, size, sha256}` records for all five archives. The verifier is called
with `--release-manifest`, `--release-signature-envelope`,
`--promotion-manifest`, `--promotion-signature-envelope`, `--release-root`,
`--artifacts`, `--json-out`, `--commit` and `--release-root-sha256`.

Run offline:

```sh
python tools/release/production_promotion.py \
  --commit <40-hex> \
  --bundle-dir /path/to/promotion-bundle \
  --expected-release-root-sha256 <64-hex> \
  --verifier /path/to/independent-verifier \
  --report promotion-report.json
```

Exit code `2` means refusal; the report lists every missing/invalid item.
Exit code `0` means only “this bundle is internally verified for offline
publication”; the tool sets `published: false` and does not publish. The
`release-promotion-gate.yml` workflow can perform the same check, but it never
creates a release.

What the tool cannot prove: that the external verifier is genuinely
independent, that the audit report is truthful, or that the ReleaseRoot private
key was not compromised. Those are human/contract controls backed by retained
evidence and offline key custody.

## 6. Lockfile policy and bootstrap recovery

Every build/test job uses `--locked`. Never remove `--locked` to get past a
stale lock; that would silently change the dependency graph.

`refresh-lock.yml` is the only workflow allowed to regenerate `Cargo.lock`:

- `generate` runs `cargo generate-lockfile` and always uploads
  `generated-cargo-lock-<run_id>` (lock, diff, SHA-256, metadata result,
  recovery notes), even if later validation fails.
- `validate` downloads that exact artifact, runs `cargo metadata --locked`
  followed by `cargo check --workspace --all-targets --locked`, and commits
  only on a full pass. It refuses if the dispatch commit left `main` or any
  workspace manifest changed after dispatch; it retries pushes three times
  without force.

This split is the bootstrap deadlock escape hatch: if a new manifest makes
`--locked` jobs fail before they can diagnose code, download the generated lock
artifact, merge only `Cargo.lock`, then fix compile/test failures normally. A
metadata pass is not a compile gate and must not be reported as one.

Current coordination note: `native-packetio` adds a target-only
`windows-sys = "=0.59.0"` dependency. After that manifest reaches `main`,
dispatch `Refresh Cargo.lock` on `main`, wait for `validate` to pass, then rerun
platform/native jobs. Until then, `--locked` jobs may fail on the missing lock
entry, which is the correct diagnosis.

## 7. Reproducible Actions path

To reproduce the development evidence:

1. Open **Actions → “Platform functional verification and development
   packaging”** (`platforms.yml`).
2. Select the exact `main` commit and **Run workflow**.
3. Inspect jobs `lock-preflight`, the five `build-test` entries,
   `linux-runtime-compat` and `development-bundle`.
4. Download `boreas-development-release-<run_id>` and verify it with
   `python tools/release/verify_bundle.py --bundle <dir>`.
5. Record the immutable run URL, commit SHA, artifact names and SHA-256 values
   in the gate ledger only when the corresponding gate evidence is real.

For real device evidence, run `linux-system.yml` and, once the Windows/macOS
tests and lock are ready, `native-device.yml`. A green `platforms.yml` run does
not replace them.

Do not fabricate run IDs or copy acceptance from a different commit. Evidence
must name the exact candidate commit, immutable Actions run URL, command,
environment, expected/observed result, reviewer, UTC timestamp and report
SHA-256.

## 8. Unmet conditions (current)

| Condition | Why it blocks production | Next step |
|---|---|---|
| Shipped CLI has no daemon/TLS/WSS/TUN/routing/DNS data plane | `doctor` only reports foundation state; no VPN functionality to test | Integrate the real runtime and exercise it end-to-end |
| `G-CRYPTO` open | PoC is not Boreas Rust/WSS, not independent interoperability, not static backend acceptance | Complete crypto backend integration and independent review |
| External audit absent | Cannot be self-certified by CI metadata | Commission independent crypto/protocol review; close findings |
| Gate ledger all open / `production_approved:false` | Exact-commit evidence incomplete | Record real evidence per gate after implementation |
| Windows Wintun test not yet green | Needs `windows-sys` lock refresh, real adapter, marker evidence | Merge manifest, refresh lock, run `native-device.yml` |
| macOS utun tests not yet green | Needs real root run on both macOS runners and marker evidence | Run `native-device.yml` on `macos-15` and `macos-15-intel` |
| Linux aarch64 real TUN device test absent | Only x86_64 `linux-system.yml` exists | Add an aarch64 runner device job or document unsupported |
| Development archives unsigned | No production authenticity | Offline dual-signature promotion only |
| No SBOM / reproducible-build attestation | `G-SUPPLY` cannot be accepted | Add SBOM generation and independent reproducibility evidence |
| No Windows Authenticode/macOS notarization for Boreas binaries | Platform distribution trust incomplete | Define signing/custody and verify on target OS |
| No GPL corresponding-source archive in the bundle | Binary distribution license compliance incomplete | Publish exact source archive or written offer with the artifact |
| Wintun DLL not shipped | Production Windows packaging decision/license review absent | Decide whether to bundle the signed DLL and include its license; never use the CI pin as a release root |

## 9. What a green run means

A green `platforms.yml` run means: the five native builds and workspace tests
passed; the Linux release binaries are fully static; the CLI ran and reported
capabilities consistently on all five targets and in eight minimal containers;
the development archives and index are internally consistent.

It does **not** mean: a VPN works; TLS/WSS or ML-DSA authentication works; TUN,
routing, DNS, failover or upgrade works; performance or resource targets are
met; an audit found no issues; or a production release is authorized. Those
claims require the specific gate evidence in the master plan and the exact-commit
ledger, plus the offline signed promotion bundle.
