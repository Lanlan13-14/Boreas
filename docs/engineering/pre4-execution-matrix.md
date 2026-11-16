# pre.4 execution and acceptance matrix

This is an implementation work list, not evidence of completion. The normative baseline is `docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md`. A check box may be marked verified only with an exact-commit Actions URL and, where applicable, a real-device report. Development prerelease status does not close any production gate in `gates.json`.

## Current integration line

- Exact GitHub baseline before this work: `9dc1593` (`v0.1.0-pre.3` documentation).
- The existing public runtime is one Linux Core/Edge IPv4 pair. Library primitives with names similar to a feature are not runtime integration or production evidence.
- All compilation, formatting, lint, tests, benchmarks, and fault injection run in GitHub Actions. Local source inspection and `git diff --check` are not substitute test evidence.

## Required workstreams

| Area | Implementation required before the corresponding capability is claimed | Acceptance evidence required | Status |
|---|---|---|---|
| Data-plane latency and throughput | Remove per-packet polling delays; observe buffered input through outer TLS, WebSocket, hop TLS, application frames, circuit fragments, and E2E TLS; preserve single-circuit FIFO and backpressure | Real WSS + hop/E2E TLS netns ICMP latency, 8 MiB SHA-256 transfer, throughput report, fail-closed and idle/burst regressions | In CI |
| `boreas-easy` | Install the symlink; interactive trilingual menu; live control-socket state; safe config and service actions; no silent dangerous action | Reducer/unit tests, non-TTY JSON, injection tests, real daemon control-socket test, package symlink check | In progress |
| One-click deployment | Verified artifact before execution; same-filesystem staging; atomic active pointer; local-only private material; systemd/procd units; explicit start; idempotence and rollback boundaries | Shell syntax/static checks, dry-run and negative fixtures, distro/OpenWrt installation tests | In progress |
| Linux and OpenWrt targets | Reproducible static pq768 builds for x86_64 and aarch64 musl; explicit OpenWrt version/kernel/toolchain records | ELF linkage/architecture checks, native or QEMU functional tests, real TUN on both architectures | Both native architectures passed official 24.10.0 rootfs + runner-kernel TUN at `376da3d`; physical OpenWrt kernel/device unverified; native CVE gate blocked |
| Owned routing lifecycle | Transactional address/route/rule ownership, underlay endpoint and management-route protection, no global sysctl/firewall mutation, rollback | Isolated netns policy/asymmetric-route matrix, route-get assertions, failure injection, pre/post route snapshots | Not integrated |
| Multiple paths | Multiple independently authenticated connections, bounded scheduling and path probing; no TLS byte striping across unordered paths; no claim of LACP | Loss/jitter/RTT matrices, failover timing, flow integrity and resource reports | Not integrated |
| Multiple Cores and Edges | Directory/lease/LSA runtime, authenticated mesh connections, relay lifecycle, primary/backup attachment and bounded failover | Four-Core multi-Edge convergence, partition and failover tests; malicious-Core negative tests | Not integrated |
| Subnet routing and dual stack | RouteAuthority scope through verified grant to owned OS route; source/destination ACL, TTL/PMTU; IPv6 remains off by default | Prefix/HA/scope vectors, real LAN return-path and PTB tests, management-route preservation | Not integrated |
| DNS runtime | Authorized packet-level UDP and real bounded user-state TCP DNS; correct NODATA/NXDOMAIN/REFUSED semantics | Fragmented/coalesced DNS and source-authorization tests on real Overlay | Not integrated |
| Sandbox and privilege separation | Root-only setup broker, then dedicated-user/capability reduction; no-new-privileges and seccomp before threads; inherited-fd audit | Native x86_64/aarch64 syscall and negative tests, same-UID control-socket tests | Not integrated |
| Recoverable upgrade | External supervisor journal, verified artifacts, atomic pointer, TUN ownership and compatible state migration | Crash/SIGKILL/power-loss/disk-full/cross-filesystem matrix | Not integrated |
| Production gates | Independent interoperability, crypto/protocol review, fuzz/dependency audit, sustained resource and operations evidence | Every applicable gate has exact-commit reproducible evidence; no self-declared external review | Open |

## Scoped OpenWrt evidence — 2026-11-16

Exact commit `376da3d578e49e39554abd2f653a64d3c720bf5a`, [OpenWrt Actions run 43870788612](https://github.com/Lanlan13-14/Boreas/actions/runs/43870788612): both native x86_64 and aarch64 jobs passed static pq768 build, doctor, and real netns TUN traffic inside the pinned official OpenWrt 24.10.0 userland. The kernel is the GitHub runner kernel, **not the OpenWrt kernel**. Each direction transferred 8 MiB concurrently with SHA-256 integrity verification.

| Native runner architecture | ICMP RTT avg / max (ms) | Edge → Core (Mbps) | Core → Edge (Mbps) |
| --- | --- | --- | --- |
| x86_64 | 0.465 / 0.714 | 392.459 | 305.664 |
| aarch64 | 0.265 / 0.312 | 217.856 | 264.061 |

These are short isolated-CI observations, not public-network/CDN performance, resource endurance, physical-router support or an SLA. The reduced OpenSSL 4.1.0 candidate still falls in known affected version ranges; the independent dependency/security gate remains blocking. No release acceptance is implied.

## Ordering constraints

1. Keep the current point-to-point path green while establishing artifact, console, and deployment foundations.
2. Add owned routing and privilege boundaries before advertising subnet or router use.
3. Add independently authenticated multiple paths before multi-Core failover; never reorder one TLS circuit across TCP connections.
4. Integrate directory, leases, relay, and convergence before enabling multi-Core business traffic.
5. Keep `e2e-required`, hybrid inner KEX, ML-DSA authentication, exact peer binding, freshness checks, bounded resources, and fail-closed behavior unchanged throughout optimization.
6. Do not publish a stable/latest or production release from this line. `pre.4`, when created, is a development prerelease only and must list every remaining limitation truthfully.
