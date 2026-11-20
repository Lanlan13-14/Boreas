# Development release tooling

These tools build and inspect **unsigned development artifacts**. They never
hold or generate a production `ReleaseRoot` private key, never sign production
metadata and never publish a release. Production promotion is the separate,
offline, signature-requiring path in `production_promotion.py`.

## Files

| File | Purpose |
|---|---|
| `common.py` | Bounded JSON/archive readers, safe bundle paths, target tables. |
| `functional_smoke.py` | Executes the built CLI and checks capability-report consistency. Not a VPN test. |
| `verify_static_linux.py` | Rejects Linux binaries with `PT_INTERP` or `DT_NEEDED`; checks ELF machine. |
| `package.py` | Creates one deterministic development archive plus provenance. |
| `make_index.py` | Assembles five targets, recomputes hashes and writes the development index. |
| `verify_bundle.py` | Offline integrity check of a downloaded development bundle. |
| `native_device_guard.py` | Rejects skipped/simulated Wintun/utun/TUN tests; requires real markers/test names. |
| `promotion_ledger.py` | Reads a fixed, separately reviewed main Git blob and applies the exact-candidate gate policy. |
| `production_promotion.py` | Fail-closed offline promotion verification; requires the gate ledger and an independent signature verifier. |
| `test_release_tools.py` | Negative/contract tests; run only in GitHub Actions. |

## CI entry points

- `.github/workflows/platforms.yml` — five native builds/tests, real CLI
  execution, static-linkage verification, eight container runtime checks and
  the five-target development bundle.
- `.github/workflows/linux-system.yml` — real Linux TUN device tests as root.
- `.github/workflows/native-device.yml` — real Windows Wintun and macOS utun
  tests. A missing driver or skipped test fails the evidence guard.
- `.github/workflows/release-promotion-gate.yml` — manual, always fail-closed
  promotion verification. It never publishes.

## Commands

All commands assume the repository root and are normally run by Actions:

```sh
python tools/release/verify_static_linux.py --binary target/x86_64-unknown-linux-musl/release/boreas --target x86_64-unknown-linux-musl --out dist/static-linkage.json
python tools/release/functional_smoke.py --binary target/x86_64-unknown-linux-musl/release/boreas --target x86_64-unknown-linux-musl --out functional-smoke.json
python tools/release/package.py --binary ... --target ... --source-sha "$GITHUB_SHA" ...
python tools/release/make_index.py --dist downloaded --out release-bundle ...
python tools/release/verify_bundle.py --bundle release-bundle
python -m unittest discover -s tools/release -p 'test_*.py' -v
```

Production promotion is **not** a CI release button. The bundle contains the
supervisor-compatible `release-manifest.json`, its detached
`release-signature-envelope.json`, the outer `promotion-manifest.json`, its
detached `promotion-signature-envelope.json`, `release-root/roots.json` and
`artifacts/`. Both manifests are dual-signed; neither contains a hash of
itself. The outer manifest binds the raw SHA-256 of the separately reviewed
ledger. Run from a clean, pinned trusted-main tooling checkout, not from the
candidate. The ledger source is a later main commit and not part of the bundle.

```sh
python tools/release/production_promotion.py \
  --commit <candidate-40-hex> \
  --ledger-commit <reviewed-main-40-hex> \
  --bundle-dir /path/to/promotion-bundle \
  --expected-release-root-sha256 <64-hex> \
  --verifier-executable /path/to/independent-verifier \
  --report promotion-report.json
```

It refuses when the gate ledger, either manifest, either signature half, the
ReleaseRoot hash, an artifact hash, the manifest schema or the external
verifier is missing. `--self-test` builds a complete synthetic test-key-only
positive fixture and negative cases; it is not production evidence. The
external verifier is a separate implementation; this script must not be
changed to self-certify cryptography. Its `--json-out` path is an absent file in
a new private temporary directory outside the bundle. A bundled legacy report
is ignored; exit zero without a newly written report is rejected. New reports
still do not establish verifier trust: independently provision the executable
and pin/review its version and digest. Synthetic self-test reports prove only
orchestration, not signature validity or independence. See
`docs/engineering/platform-release-gates.md`.
