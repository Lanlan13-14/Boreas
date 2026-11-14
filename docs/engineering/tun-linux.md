# Linux TUN implementation scope

`boreas-tun::linux` is Linux-specific; it is not Windows Wintun or macOS utun, and it does not imply cross-platform VPN support.

## Implemented surface

- `LinuxTunDevice::create` opens `/dev/net/tun`, creates a non-persistent L3 device using `TUNSETIFF` with `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL` and optional frozen `IFF_MULTI_QUEUE`, then checks returned name and exact flags through `TUNGETIFF` before publishing the queue.
- Queue descriptors and a retained device-manager descriptor are owned by `OwnedFd`; each queue can be revalidated using `TUNGETIFF`. Additional queues attach only to an explicitly multi-queue device. Device-wide offload management is owned by the retained queue-zero descriptor.
- MTU is configured by writing only the kernel-returned interface's `/sys/class/net/<name>/mtu` entry. TUN offloads are explicitly set to zero; nonzero offload requests are rejected. VNET header mode is explicitly rejected until framing/metadata support is complete.
- Each packet is checked as a complete IPv4/IPv6 L3 packet and against the configured MTU at read/write boundaries. Reads have a bounded `poll`-based timeout API. The adapter creates no UDP/RAW sockets and manages no routes.
- Unsafe Rust is confined to `linux.rs` libc syscall ABI wrappers with local safety comments; crate root denies unsafe by default and disallows unsafe operations in unsafe functions.

## Privileges, cleanup, and evidence

Creation and MTU configuration require appropriate Linux privilege/capability, normally `CAP_NET_ADMIN`. The interface is not made persistent and is released by the kernel when all attached fds close. The integration tests run as root in disposable network/mount namespaces, create uniquely named interfaces, verify `TUNGETIFF`, attach a second queue, inspect the MTU, inject an ICMP echo request to a local TUN address, and check for the kernel reply. Cleanup only targets the unique interface created by that test.

`.github/workflows/linux-system.yml` is intended to provide Linux-hosted compile, clippy and actual TUN device tests. No local Cargo/test execution is permitted. A green result is evidence only for that exact Actions Ubuntu/kernel path; it does not prove master-plan `G-TUN`, performance, all failure paths, offload/GSO software segmentation, production routing, or multi-kernel support. Windows and macOS adapters and their own privilege/cleanup/CI evidence remain unimplemented.
