# Platform support and CI evidence

## Current status

This repository is a **development foundation**, not a production VPN. The CLI currently implements policy/parser-facing `doctor`, `self-check`, and `help` behavior only. It has no production daemon, TLS backend, socket transport, TUN device driver, routing installation, DNS service, or verified production update path. A successful platform build proves only that the current foundation compiles/tests on that runner; it does **not** demonstrate usable VPN functionality, security, performance, or readiness for release.

All compilation and tests are run in GitHub Actions. Do not run Cargo, Rust, Python verification, or platform tests locally. Workflow artifacts are named and described as development-only; this workflow does not create GitHub Releases, publish packages, push images, sign artifacts, or treat tags as production releases. Do not create a production release/tag until all applicable Phase 0–5 evidence gates and external review in the master plan have passed. CI has no access to offline release signing keys. Real production manifests require the project’s separately controlled offline dual-signing process; CI credentials must never substitute for it.

## CI platform matrix

`.github/workflows/platforms.yml` runs the workspace test suite and builds the `boreas-cli` foundation binary on these native hosted runners:

| Target | Runner | Build/test intent | Status represented by CI |
|---|---|---|---|
| Linux x86_64 | `ubuntu-24.04` | `x86_64-unknown-linux-musl`; install musl toolchain; verify no ELF interpreter; run x86_64 binary in distribution containers | Static-musl foundation build/test only |
| Linux aarch64 | `ubuntu-24.04-arm` | `aarch64-unknown-linux-musl`; native execution, not cross-compilation | Static-musl foundation build/test only |
| Windows x86_64 | `windows-2025` | `x86_64-pc-windows-msvc` native build/test | Foundation build/test only; no Wintun integration |
| macOS Intel x86_64 | `macos-15-intel` | `x86_64-apple-darwin` native build/test | Foundation build/test only; no utun integration |
| macOS Apple Silicon aarch64 | `macos-15` | `aarch64-apple-darwin` native build/test; architecture checked at runtime | Foundation build/test only; no utun integration |

The workflow uploads short-retention, run-scoped, **development-only** CLI artifacts to Actions. These artifacts are not production binaries, signed releases, nor endorsements that networking works. Ubuntu x86_64 musl output is also run as `boreas doctor` in Ubuntu 24.04, Debian Bookworm, Fedora, and Alpine containers. This checks basic static executable/runtime compatibility and the foundation doctor response; it is not broad distro, kernel, system-service, or data-plane compatibility evidence.

The existing `.github/workflows/ci.yml` remains the general CI source for formatting, lint, and workspace checks. The platform workflow’s explicit target build/test jobs add OS/architecture coverage; CI status must be read together with the implementation-status ledger and must not be relabeled as a security gate.

## Platform-specific implementation gaps

| Area | Linux | Windows | macOS | Required before claiming production support |
|---|---|---|---|---|
| TUN/L3 device | `boreas-tun` has platform-neutral parsing/policy foundations; no accepted real Linux device/data-plane evidence yet | No Wintun adapter or driver lifecycle, installation/signing, privilege and cleanup implementation | No utun control-socket/device lifecycle, privilege and cleanup implementation | Implement OS-native adapter, privilege boundaries, lifecycle/recovery and packet transfer tests on actual target OS |
| Routing and firewall | No production route/rule manager or real host coexistence evidence | Windows route and firewall API behavior unimplemented | macOS route and packet-filter integration unimplemented | Add non-destructive apply/rollback, management-route protection, privilege, failure and reboot recovery tests per OS |
| Isolation/sandbox | Planned Linux seccomp/ABI work is not yet accepted evidence | Linux seccomp is not a Windows sandbox; choose and audit Windows-native process isolation/mitigations | Linux seccomp is not a macOS sandbox; evaluate and audit an appropriate macOS-native sandbox | Separate threat models, implementation, positive/negative tests and audit evidence for each OS; never label the Linux seccomp result cross-platform |
| Networking and crypto | No production TLS/WSS backend or completed Phase 0 hybrid ML-DSA evidence | Same; platform build does not establish crypto backend equivalence | Same; platform build does not establish crypto backend equivalence | Complete Phase 0 backend, interoperability and fail-closed tests on each supported platform/backend configuration |
| Operations and upgrades | No production service integration/evidence | No Windows service manager or accepted upgrade/recovery integration | No launchd/service integration or accepted upgrade/recovery integration | OS-specific packaging, least-privilege operations, verified upgrade/rollback, crash and recovery tests |

`Wintun`, `utun`, route APIs, packet-filter/firewall APIs, service managers, and sandbox primitives have different lifecycle and security properties. A platform-neutral Rust API or Linux-only test is not proof that these facilities work on Windows or macOS. Do not claim support for an OS capability until that platform has its own implementation and evidence.

## Release gate

Production release is **blocked** until the applicable master-plan Phase 0–5 gates, security review, attack/fault testing, platform-specific TUN/routing/sandbox and upgrade evidence, reproducible build/supply-chain evidence, and offline dual-signature verification have been completed and reviewed. CI build/test success and development artifact upload are necessary engineering feedback only; they do not pass those gates. Keep development artifacts clearly labeled, run-scoped, and unsigned by production keys. Do not trigger production publication from a version tag or workflow-dispatch input in this workflow.
