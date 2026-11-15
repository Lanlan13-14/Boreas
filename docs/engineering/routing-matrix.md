# Real daemon routing matrix (Linux GitHub Actions)

## Scope and evidence boundary

`tools/release/netns_routing_matrix.sh` is a fail-closed wrapper around the existing
`tools/release/netns_daemon_smoke.sh`, not another PKI or daemon implementation.
Each case provisions fresh PKI and runs the real static `boreas` Core + Edge
pair using pq768, real TUN devices, connected-state checking, ICMP, authenticated
8 MiB full-duplex overlay traffic, live control status and successful daemon exit.
There is **one Core and one Edge**, never multiple Cores. This is not failover,
public-network SLA, DNS, host default-route takeover, or a production routing
controller acceptance test. Routes are installed by the harness, not claimed to
have been installed by the daemon.

| Case | Underlay MTU | TUN MTU | Source policy / return path |
| --- | ---: | ---: | --- |
| policy-1500 | 1500 | 1360 | rule priority 100, table 100; original veth both ways |
| asymmetric-1500 | 1500 | 1360 | same rule; Core replies over second veth |
| policy-1280 | 1280 | 1280 | rule priority 100, table 100; original veth both ways |
| asymmetric-1280 | 1280 | 1280 | same rule; Core replies over second veth |

The smaller-underlay cases test TCP/WSS transport behavior at MTU 1280; they do
not assert that an encapsulated 1280-byte packet fits in a single underlay IP
packet, or test blocked-PMTUD/firewall behavior. The existing full-duplex traffic
is retained, with no reduced byte counts, throughput thresholds or failure skips.

## Topology and assertions

The original Core `192.0.2.1` and Edge `192.0.2.2` remain the daemon listen/connect
addresses. Both have a `/32` source selector to table 100 at priority 100. Policy
cases use explicit peer host routes in that table. Asymmetric cases add
`rm-core` (`192.0.3.1/30`) ↔ `rm-edge` (`192.0.3.2/30`), created directly inside the
namespaces. Core's table 100 sends `192.0.2.2` via `192.0.3.2`; Edge's table 100
sends `192.0.2.1` over the original veth. Both destination IPs are local addresses
on the receiving namespace, so no forwarding or NAT is needed. Reverse-path
filtering is disabled only in these disposable namespaces to permit asymmetry.

Management addresses `198.51.100.9/32` (Core loopback) and
`198.51.100.10/32` (Edge loopback) have explicit host routes through the original
veth. At setup, ready and verify, the hook records JSON route-get, all-table
routes, rules and link statistics. Assertions require:

- sourced peer route-get selects table 100, the expected device and next hop;
- priority-100 policy rules are present;
- management lookup selects the original veth and expected next hop, and an
  explicit host route exists;
- management lookup and explicit host-route snapshots are unchanged after TUN
  setup and after daemon completion (other new TUN routes are allowed);
- ready-stage TUN and every underlay link have the configured MTU;
- real management ICMP still succeeds after TUN setup and after daemon completion;
- asymmetric return-link Core TX and Edge RX byte deltas from ready to verify
  are each at least 8 MiB, in addition to smoke's end-to-end payload hashes.

This last check prevents route-get-only assertions from masquerading as proof
that the second veth actually carried the large daemon transfer. It is not a
packet capture or exact per-flow accounting.

## Required smoke hook integration (owned by root agent)

The wrapper requires these small additions to the existing smoke; it does not
edit it itself:

1. `BOREAS_TUN_MTU` defaults to 1360, is validated as 1280..1400, and supplies
   both daemon `--mtu` arguments.
2. Export `BOREAS_NETNS_HOOK_PROTOCOL=1`. When a hook is provided, require
   `BOREAS_NETNS_HOOK_VERSION=1` and an absolute regular-file path.
3. Invoke `bash "$BOREAS_NETNS_HOOK" PHASE "$CORE_NS" "$EDGE_NS" "$WORK"`
   without sourcing/eval and without suppressing any nonzero exit:
   - `setup`: original veth addresses and links are up, before netem/daemon start;
   - `ready`: both TUN VIPs and peer routes exist, before normal smoke traffic;
   - `verify`: both daemons have exited successfully and both output status
     checks passed, before final success and namespace cleanup.
4. Keep the existing unconditional EXIT cleanup trap. The hook adds interfaces
   only inside these same namespaces, so deleting them also removes new links.

The wrapper passes the helper path, protocol version, selected case, artifact
path and TUN MTU using `env -i` with a short explicit allowlist. It does not
inherit `BOREAS_ROOTFS`, netem, performance overrides or skip flags. Each phase
must leave its marker; an old unhooked smoke cannot accidentally pass. Existing
case output directories are rejected to avoid counting stale markers.

## GitHub Actions integration suggestion

Use the existing static-release build/download step and run the same artifact
that is to be released. Do not substitute `cargo test` or a dynamic debug binary.
Install `iproute2 util-linux iputils-ping python3 binutils` on Ubuntu 24.04 and
ensure `/dev/net/tun` is available. The wrapper also needs GNU `timeout` and
`realpath` (coreutils). Run as root on the disposable hosted Linux runner; nested
unprivileged containers generally lack the required netns/mount capabilities.

Example steps to insert **after** the static artifact is available (the owning
agent must select the actual artifact path and pinned action policy):

```yaml
- name: Real static pq768 routing matrix
  shell: bash
  run: |
    set -euo pipefail
    sudo bash tools/release/netns_routing_matrix.sh \
      "$GITHUB_WORKSPACE/dist/boreas" \
      "$GITHUB_WORKSPACE/routing-matrix-artifacts"
- name: Upload routing evidence, including failed cases
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: routing-matrix-evidence
    path: routing-matrix-artifacts/
    if-no-files-found: error
```

Do not set `continue-on-error` on the matrix. The wrapper uses `pipefail` for
smoke logging, rejects a binary containing a PT_INTERP segment, checks tools and
TUN availability, and bounds every smoke invocation to 180 seconds (TERM plus
10-second kill grace). Four cases normally retain the smoke's ~35-second daemon
lifetimes. Allow at least 15 minutes at job level including setup. Runner/job
termination remains a runner lifecycle cleanup responsibility; ordinary failures
run smoke's EXIT trap. No host-global sysctl, firewall, default route, qdisc or
forwarding configuration is changed by the matrix helper.

## What counts as evidence

Writing/reviewing these scripts is **not** successful routing-matrix evidence.
No local builds, tests, formatter, or Linux netns execution were performed during
this implementation. Actual evidence requires a GitHub Actions run of the real
static binary with all four case result files and all three phase markers per
case, successful smoke logs, JSON snapshots, management ping logs and a green
non-skipped job. The ELF header snapshot proves absence of PT_INTERP, not the
identity of every linked dependency: publish the tested binary hash/build
provenance separately. Failed logs and partial snapshots are diagnostics, not a
passing claim. Do not report multi-Core, failover or default-route protection as
implemented on the basis of this matrix.
