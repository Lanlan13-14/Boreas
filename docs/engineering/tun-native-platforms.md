# Native Windows and macOS packet adapters

This note covers `boreas-tun`'s Windows Wintun and macOS utun adapters. It does not replace the
Linux record in [tun-linux.md](tun-linux.md); that file is intentionally unchanged and its closing
statement that Windows/macOS adapters are unimplemented is superseded here.

The adapters are real OS device integrations, not `cfg` placeholders. Both implement the
`PacketIo` trait (the inherent methods return the more detailed platform error type). They are
still development foundation code: no production daemon, routing installation, DNS service,
GSO/offload path, or performance/security certification is provided. No native-device Actions
result is claimed in this note unless an exact run is linked in the implementation ledger.

## Implemented surface

### Windows (`boreas-tun::windows`)

- `WintunConfig` requires an absolute path to `wintun.dll` and the SHA-256 of the exact DLL bytes.
  `WintunDevice::create` reads a bounded DLL image (16 MiB limit), hashes it with Windows CNG
  (BCrypt SHA-256), and refuses to load on mismatch. It never searches `PATH` or the current
  directory. The digest is an integrity pin supplied by the caller; it must be provisioned
  out-of-band. This crate does **not** call WinVerifyTrust and does **not** claim to have verified
  the Authenticode signature of the DLL. A caller that needs publisher authentication must perform
  it before supplying the path/digest.
- The verified bytes are copied to a uniquely named directory under the process temporary
  directory and loaded from that staged copy. This removes the source-path replacement window and
  means the loaded bytes came from the hashed byte buffer; it is not a defense against a hostile
  process running as the same user. `LoadLibraryExW` is called with only
  `LOAD_LIBRARY_SEARCH_SYSTEM32`, so dependent DLLs are resolved from System32 rather than the
  staging directory, the caller-selected directory, the application directory, or the current
  directory. The staging directory inherits the per-user temporary-directory ACL; it is not claimed
  to be an isolation boundary against a hostile process running as the same user.
- `WintunCreateAdapter`, `WintunGetAdapterLUID`, `WintunStartSession`,
  `WintunGetReadWaitEvent`, `WintunReceivePacket`/`WintunReleaseReceivePacket`, and
  `WintunAllocateSendPacket`/`WintunSendPacket` are resolved dynamically from the verified DLL.
  The adapter alias is checked through `ConvertInterfaceLuidToAlias`, both IPv4 and IPv6 interface
  rows are read back through `GetIpInterfaceEntry`, and the requested MTU is applied with
  `SetIpInterfaceEntry` and verified (IPv4 `SitePrefixLength` is zeroed as required; the IPv6
  value is preserved). Both IPv4 and IPv6 interface rows must be available; failure to apply
  either MTU is a creation error, not a silent partial configuration. Ring capacity is bounded to
  a power of two in `[128 KiB, 64 MiB]`; each
  read/write is a single validated IPv4/IPv6 L3 packet up to the configured MTU.
  `read_packet_timeout` includes single-reader lock wait in its deadline.
- Loaded driver images are cached for the process lifetime, keyed by source path and SHA-256, with
  a hard cap of four distinct images. This is deliberate: `WintunCloseAdapter` queues cleanup work
  whose callback lives in `wintun.dll`, so unloading immediately after the last adapter could
  execute an unmapped callback. The cache prevents that race and bounds module/temp-image growth;
  it is not an unbounded per-device handle leak. Each cached image is at most 16 MiB and the staged
  copy is intentionally retained with its module for the process lifetime.
- `WintunCloseAdapter` releases the adapter created by `WintunCreateAdapter`; the crate never calls
  `WintunDeleteDriver`, because the signed driver is shared with other applications on the host.
- Creating an adapter and changing MTU require elevation (normally an Administrator token). The
  adapter is non-persistent from this crate's perspective: closing the handle removes the adapter
  it created. The library installs no unicast addresses, routes, DNS settings, firewall rules, or
  sysctls; the OS may auto-configure link-local IPv6 on any newly created adapter.
  Before calling `WintunCreateAdapter`, it resolves the requested alias and fails closed if the
  alias already exists. Wintun itself is documented to suffix a colliding foreign adapter name,
  so callers must still use a namespaced unique name; the pre-check narrows but cannot eliminate
  that inherent create-race.

### macOS (`boreas-tun::macos`)

- A utun interface is created with an `AF_SYSTEM`/`SOCK_DGRAM` control socket using
  `SYSPROTO_CONTROL`, `CTLIOCGINFO`, and `connect(2)` with `sockaddr_ctl`. `sc_unit = 0` lets the
  kernel choose an unused unit; a requested `utunN` selects that unit. The resulting name is read
  with `getsockopt(UTUN_OPT_IFNAME)` and verified, and the MTU is applied with `SIOCSIFMTU` and
  read back with `SIOCGIFMTU`.
- The ifreq ioctl handle is an `AF_INET`/`SOCK_STREAM` socket, not a UDP or raw socket, so this path
  remains inside the project's 0-UDP boundary. It is unconnected and carries no packets.
- utun frames have a four-byte network-order address-family header. Reads verify the header,
  reject unknown families and family/version mismatches, enforce the MTU, and validate the complete
  L3 packet. Writes prepend the correct header and require a single full-length datagram write; a
  short write is an error and is never retried as another packet.
- The descriptor is `CLOEXEC`, owned, and non-persistent. Closing it destroys the utun interface;
  no `TUNSETPERSIST` equivalent is used. Creation requires root (or an appropriate system
  privilege). The library creates no addresses, routes, DNS entries, or firewall state. A single
  reader is serialized with a lock; `read_packet_timeout` includes lock wait in its deadline.

## Real-device tests

The test targets are:

- `crates/boreas-tun/tests/windows_device.rs`, test function
  `real_wintun_device_packet_round_trip`.
- `crates/boreas-tun/tests/macos_device.rs`, test function `real_utun_packet_round_trip`.

Both tests are fail-closed when `BOREAS_REQUIRE_TUN=1`; without that variable they skip when the
required privilege or external DLL is absent, so ordinary workspace test runs do not pretend to
have exercised a device. Successful real-device runs print exactly one machine-checkable marker:

```text
BOREAS_DEVICE_EVIDENCE platform=windows driver=wintun adapter=created packet_roundtrip=ok cleanup=ok
BOREAS_DEVICE_EVIDENCE platform=macos driver=utun adapter=created packet_roundtrip=ok cleanup=ok
```

The Windows test requires an elevated runner plus:

- `BOREAS_WINTUN_DLL`: absolute path to the official signed amd64 `wintun.dll`.
- `BOREAS_WINTUN_SHA256`: lowercase SHA-256 of that exact DLL file.

The macOS test requires root for utun. Each test creates a uniquely named adapter, verifies alias
and MTU, rejects an invalid packet, injects one IPv4/UDP/IP packet into the OS stack, receives it
through a test-only UDP oracle socket bound to the adapter address, sends a reply back through the
same address, reads and validates the reply from the adapter (source/destination addresses and
ports plus payload), then closes the adapter and checks that the interface is gone before printing
the evidence marker. On Windows the test adds one narrow inbound UDP firewall rule for the test
executable and its ephemeral oracle port, then removes that rule in a Drop guard; this is
ephemeral test-host configuration, not library behavior. The UDP socket exists only in the test
harness as a payload oracle; it is not part of the Boreas daemon data path and these tests do not
prove daemon 0-UDP sandboxing. A future data-plane test should put the traffic generator in a
separate process. The adapter library creates no UDP socket. The test address and its connected
route are ephemeral and are assigned only to the adapter the test owns and then removes. No
host-wide route is installed, replaced, or deleted.

The existing Linux real-device test was also tightened to accept only an IPv4, unfragmented
ICMP echo reply with the exact probe addresses, type 0, code 0, valid ICMP checksum, and matching
id/sequence. Other valid packets emitted by the kernel (for example IPv6 control traffic) are
logged and ignored rather than failing the probe. This does not change the Linux adapter itself.

The dedicated wiring is `.github/workflows/native-device.yml` for Windows/macOS; Linux real-device
coverage remains in `.github/workflows/linux-system.yml`. The Windows CI path must download the
official Wintun archive, verify the publisher-listed archive
SHA-256 (`wintun-0.14.1.zip`:
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`) before extraction, compute the
extracted DLL hash, and pass that hash to the test. The CI workflow additionally checks the
Authenticode signer of the extracted DLL; that check is CI policy and is not performed by this
crate. The archive hash is a CI supply-chain pin, not a production trust root, and this repository
does not vendor the DLL. The Actions wiring, runner
labels (`windows-2025`, `macos-15`, `macos-15-intel`), lockfile refresh, and test-count guard are
owned by the platform-gates workstream; the required contract is recorded here so it can be
reviewed independently.

## Privilege, cleanup, and failure boundaries

- Permission failures (missing Administrator on Windows, non-root utun creation on macOS) are
  returned as errors; they are never silently converted into a virtual or in-memory device.
- Missing/mismatched Wintun DLL, missing exports, invalid adapter names, invalid MTU/ring
  configuration, invalid L3 packets, and MTU read-back mismatches all fail closed.
- Cleanup is RAII: Wintun ends the session and closes the created adapter, and utun closes its
  owned descriptor, which destroys the non-persistent interface. A process abort can leave a
  Windows adapter until the driver's handle cleanup runs; CI runners are disposable.
- The library does not manage host routes. The tests add one address/prefix to their own disposable
  adapter so the OS can route the probe; they do not call route-replace APIs.

## Evidence limits

The tests exercise adapter creation, MTU, packet validation, both directions of an IPv4 data path,
and cleanup on the named CI runner OS versions. They do not prove:

- IPv6 data-path forwarding (IPv6 MTU is applied and verified, but the packet round-trip is IPv4);
- GSO/TSO/USO, checksum offload, or virtio-header behavior;
- routing policy, DNS, kill-switch, upgrade continuity, performance, or resource-limit behavior
  under production load;
- Wintun Authenticode/revocation verification, all Wintun versions/architectures, or non-elevated
  deployment models;
- behavior on macOS versions other than the CI runners, or under a non-root Network Extension
  entitlement;
- safety against a hostile process running as the same user (temporary staging ACL, same-user
  handles, and loaded-module integrity are outside that threat model).
