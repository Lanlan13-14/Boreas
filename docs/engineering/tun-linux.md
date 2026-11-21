# Linux TUN implementation scope

`boreas-tun::linux` is Linux-specific; it is not Windows Wintun or macOS utun, and it does not imply cross-platform VPN support.

## Implemented surface

- `LinuxTunDevice::create` opens `/dev/net/tun`, creates a non-persistent L3 device using `TUNSETIFF` with `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL` and optional frozen `IFF_MULTI_QUEUE`, then checks returned name and exact flags through `TUNGETIFF` before publishing the queue.
- Queue descriptors and a retained device-manager descriptor are owned by `OwnedFd`; each queue can be revalidated using `TUNGETIFF`. Additional queues attach only to an explicitly multi-queue device. Device-wide offload management is owned by the retained queue-zero descriptor.
- MTU is configured by writing only the kernel-returned interface's `/sys/class/net/<name>/mtu` entry. Offloads are zero by default. The only nonzero profile is the explicit single-queue TCPv4 GSO mode, frozen at device creation.
- Each packet is checked as a complete IPv4/IPv6 L3 packet and against the configured MTU at read/write boundaries. Reads have a bounded `poll`-based timeout API. The adapter installs no routes; its opt-in startup uses a short-lived `NETLINK_ROUTE` socket solely for its own device's aggregate limits.
- Unsafe Rust is confined to Linux libc syscall ABI wrappers with local safety comments; crate root denies unsafe by default and disallows unsafe operations in unsafe functions.

## Linux daemon fast path

The [pinned sing-tun read path](https://github.com/SagerNet/sing-tun/blob/4486c14ba472e42f62d04e9b7b661690e62c78f8/tun_linux.go#L521-L553) retains information derived at the device boundary while draining ready data. Boreas applies that principle without VNET or code reuse: an immutable `InspectedPacket` binds the structural result to the exact bytes. On outbound TUN reads the device inspects once, then the tunnel still checks negotiated MTU, IPv4 and both permanent VIPs for each packet. Inbound, once framing, structural inspection and VIP authorization are complete, the Linux write reuses the inspection, still enforces the device MTU, and writes only those bare L3 bytes. On the default raw TUN this removes one full `inspect_packet` per forwarded packet in each direction; it does not reduce TUN read/write syscall count, change order or batch limits, or skip either MTU check. Raw and other platform adapters retain their existing validation paths.

`BOREAS_DIAGNOSTIC_TIMING=1` also emits `boreas-tun-forwarding` on normal real-daemon teardown. The existing candidate-only netns smoke collects numeric counters per Core and Edge without changing thresholds or adding another run. `checked_reads` counts structurally valid reads carrying the result into the forwarding path, including later local policy discards; `empty_reads` includes EAGAIN; `reused_writes` counts successful Linux writes of pre-inspected bytes. Errors are counted separately and may occur before the syscall, so totals including errors are adapter calls, not a syscall trace. These counters cover the device lifetime, not just the application transfer; use them for path coverage, not as exact transfer-window syscall or CPU denominators. Use the same candidate's sampled daemon CPU/RSS and digest-verified full-duplex goodput for cost/throughput evidence. No metric is a gate, and a process killed before teardown may not emit counters.

## Explicit TCPv4 GSO (Linux daemon only)

Add `--tun-tcpv4-gso` to `boreas daemon serve` or `boreas daemon connect` to accelerate direct host TCPv4 traffic on a newly created, non-persistent TUN. A virtual, multi-queue or administrator-provisioned/verified-service TUN cannot opt in; the existing persistent-owner and sandbox paths are unchanged. Keep the interface and its link/offload attributes under the local operator's control. Missing kernel ABI support or failure to verify setup is a startup error, not a fallback.

The adapter follows the public Linux [`if_tun.h`](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_tun.h), [`virtio_net.h`](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/virtio_net.h) and [`if_link.h`](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_link.h) contracts. Like the previously reviewed sing-tun mechanism, it tests VNET framing independently of offload and treats `hdr_len` as a bounded linear-head hint, not as the split point. Boreas uses its own segmenter. It verifies the 10-byte LE header and kernel 48,000-byte/64-segment caps, then requests only `TUN_F_CSUM | TUN_F_TSO4`. Read scratch includes a truncation byte and the segmenter independently caps input at 64,000 L3 bytes and output at 67,200 bytes/64 segments. The daemon uses two reusable allocations totaling 131,211 bytes per opted-in queue at its supported MTUs, with no per-segment heap allocation. Pending segments drain FIFO before another TUN read and remain subject individually to device/negotiated MTU, structural validation, and existing circuit/IPv4/VIP policy and per-turn budgets. No wire framing, DNS/policy validity, watchdog or transport timeout changes.

Ordinary bare IPv4/IPv6 TCP/UDP partials are completed only after validating exact checksum positions, pseudo-header seed, and transport lengths. Unsupported partials fail closed; TCPv6 GSO, UDP GSO, ECN GSO, arbitrary forwarded GRO and extended VNET headers are not supported. The strict IPv4/TCP segmenter still rejects unsupported shapes/options and recomputes IPv4/TCP checksums. An inbound wire packet cannot supply any VNET metadata: the adapter locally adds an all-zero `GSO_NONE` header to an already authorized bare packet using one `writev`. No write syscall savings are claimed.

### Candidate-only CI recipe

On a privileged isolated Ubuntu Linux CI runner with `/dev/net/tun`, iproute2 and mount/network namespaces, run the existing raw-ABI test and the production queue test (adapt the existing native-device guard only if separately requested):

```sh
sudo -E env "PATH=$PATH" BOREAS_REQUIRE_TUN=1 \
  cargo test -p boreas-tun --locked --test linux_device tun_gso:: \
  -- --nocapture --test-threads=1
```

The production test requires a new TCP payload segment to be delivered FIFO while the actual fd-read counter does not advance, and checks ordinary SYN-ACK and data checksums independently. It emits a `gso_adapter=fifo syscall_saving=ok` marker. Then run the usual smoke with the **same candidate** CLI built by CI with `openssl-inner-tls`:

```sh
sudo -E env BOREAS_NETNS_TCPV4_GSO=1 BOREAS_DIAGNOSTIC_TIMING=1 \
  bash tools/release/netns_daemon_smoke.sh /absolute/path/to/candidate/boreas
```

Keep the existing digest, goodput and deadline assertions, including for an existing netem profile if selected. `boreas-tun-gso` reports attempted fd read syscalls (including EAGAIN), accepted GSO aggregates and segments handed to policy; `delivered_segments - aggregate_reads` is a conservative lower bound on local read syscalls avoided by GSO when positive. Incomplete draining at shutdown can reduce that difference; these lifetime counters are not per-transfer throughput evidence or an aggregate rate. No historical-binary run, threshold changes, or release claims are required.

## Privileges, cleanup, and evidence

Creation and MTU configuration require appropriate Linux privilege/capability, normally `CAP_NET_ADMIN`. The interface is not made persistent and is released by the kernel when all attached fds close. The integration tests run as root in disposable network/mount namespaces, make mount propagation private, and mount a fresh sysfs view so interfaces created in the test network namespace appear under `/sys/class/net`. They create uniquely named interfaces, verify `TUNGETIFF`, attach a second queue, inspect the MTU, inject an ICMP echo request to a local TUN address, and check for the kernel reply. Cleanup only targets the unique interface created by that test.

`.github/workflows/linux-system.yml` is intended to provide Linux-hosted compile, clippy and actual TUN device tests. No local Cargo/test execution is permitted. A green result is evidence only for that exact Actions Ubuntu/kernel path; it does not prove master-plan `G-TUN`, end-to-end performance, general GRO/offload support, all failure paths, production routing, or multi-kernel support. Windows and macOS adapters and their own privilege/cleanup/CI evidence remain unimplemented.
