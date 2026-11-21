# Static private DNS on Linux (opt-in)

The supported slice is one real Linux Core `daemon serve` and one Edge `daemon
connect`, with the existing authenticated pq768 E2E session. No new handshake,
capability advertisement, namespace, process privileges, or socket exceptions.
The daemon neither opens nor inherits a DNS UDP socket. It carries the IP/UDP
packet inside the existing encrypted stream; the existing NO_UDP sandbox still
applies to the daemon. The host application is separate from that sandbox.

## Provision both ends

1. Provision and persist the ordinary network policy, identity material and
   status state as for the existing daemon. The DNS objects must bind to that
   exact network-policy TBS digest, not just its prefix or root. Authorize the
   configured Core's **current identity generation** with `Replica`.
2. Offline, produce three existing V1 dual-signed objects in a dedicated absolute
   directory: `service` (NetworkRoot-signed DNS service policy), `signer`
   (NetworkRoot-signed DNS signer grant), and `authority` (DnsSigner-signed
   authority). For each stem install `<stem>.tbs`, `<stem>.ed25519.sig` (64 raw
   bytes) and `<stem>.mldsa65.sig` (3309 raw bytes). Only public artifacts go on
   either node. Use distinct offline keys for root and DNS signer. The test
   fixture is not an operator signing utility.
3. Independently approve the exact three canonical TBS byte strings. Mount a
   trusted **96-byte raw pin** outside the artifact directory, in this order:
   `SHA256(service.tbs) || SHA256(signer.tbs) || SHA256(authority.tbs)`. Configure
   its path through the trusted launch configuration. Place its parent and
   ancestors under operator control (not writable by the artifact publisher or
   daemon), readable by the daemon; use a local filesystem. Pin and launch
   config are the rollback trust anchor: never regenerate the pin from files
   submitted to a node. Protect it from rollback across restarts just as other
   operator trust material. There is no autonomous DNS sequence watermark or
   defense against restoring the trusted pin/config and disk/clock together.
4. Both nodes specify `--private-dns-dir <ABS> --private-dns-pin <ABS>` and set
   `[dns].zone` to the exact lowercase signed suffix without a trailing dot.
   `[dns].listen_vip`, if set, must equal the reserved `<policy-prefix>.0.53`.
   No `dns.tcp`, virtual TUN, or Edge standby in this profile. A missing flag,
   mismatched zone or pin, invalid signatures, wrong network, or wrong Core
   generation with DNS requested is a startup error, not an unsigned fallback.
   Without either flag the original packet path is unchanged.

## Route and quarantine at the Edge

Keep the existing peer route and add **only** the DNS `/32` through the already
provisioned Edge TUN, e.g. for the fixture:

```sh
ip route replace 10.20.0.53/32 dev btun0 src 10.20.1.2
```

The virtual DNS address is not assigned on either host. Do not install a Core
host route/listener for it. A private-aware application or strict split resolver
must route the exact private apex and descendants **only** to this numeric VIP,
with **no** second server, search retry, TCP fallback, public resolution, or
system fallback for that suffix even when the tunnel is absent. Provision this
quarantine rule independently of tunnel readiness and keep it on failure; use
an Edge namespace or egress policy that prevents the DNS `/32` going out the
underlay when the TUN is down. This slice neither edits host DNS configuration
nor claims to prevent leaks by applications that bypass the operator's resolver.
For the explicit query client in the netns test there is no upstream configuration
at all. The Edge packet branch drops out-of-suffix and non-UDP/53 traffic to the
reserved VIP; the Core responder is private-only and never calls a public resolver.

## Lifetime and observability

The daemon uses the exact durable-accepted NetworkPolicy and original root pin,
then verifies all three DNS objects. After real E2E and final durable status and
identity-revocation admission it binds one lease to that circuit and to the
currently admitted status sequence. Status renewal does not extend this lease;
a new observed sequence retires it. Effective deadlines include status and its
delegation, signed network/service/grant/authority windows, both mounted identity
windows and the business time limit. A clock rollback observed by either DNS
owner loop retires the lease. The existing status/revocation watchdog is still
the source of authenticated revocation decisions; its polling interval is
unchanged. The DNS worker polls the trusted pin for exact changes/withdrawal
(nominally every 100 ms), checks expiry, and shuts down the existing outer socket
through an owned duplicate to unblock I/O. Pin changes are not hot reloads.
Neither periodic checks nor OS shutdown can retract bytes an earlier write
already accepted; pin/revocation delivery and OS scheduling are not instantaneous.

Both paths still enforce the verified endpoint source/destination and MTU. Only
Edge permanent VIP → DNS VIP:53 and DNS VIP:53 → that Edge permanent VIP are
added. The Core intercepts rather than forwards these queries to host TUN; the
Edge additionally requires one outstanding client port + DNS ID/name/type
transaction from its bounded 64-entry, five-second table before TUN delivery.
The authenticated Core is trusted for the answer RRs; the Edge does not validate
response RRs cryptographically. Normal permanent VIP packets still use the
existing checks. DNS work counts against the packet budget; the Core reserves
capacity for a reply before consuming a packet and exports actual reply TX counts.
There is no DNS-ready bit or DNS readiness claim in the supervisor handshake or
`ctl status`. A real successful Edge query proves that its DNS path answered.

## Live scenario (not a gate)

Use the exact candidate Linux binary and an OpenSSL CLI that supports ML-DSA-65,
plus root, Linux netns, `/dev/net/tun`, `ip`, and Python 3:

```sh
BOREAS_OPENSSL_BIN=/path/to/openssl-3.6 BOREAS_NETNS_PRIVATE_DNS=1 \
  bash tools/release/netns_daemon_smoke.sh /path/to/candidate/boreas
```

This optional scenario builds public DNS fixtures from ephemeral offline test
keys, installs the kernel Edge `/32`, and probes a byte-checked signed A response,
authoritative NXDOMAIN, outside-suffix and wrong-port non-delivery, and ordinary
ICMP on the same E2E circuit. It then withdraws only the Core pin and requires a
nonzero Core exit with the DNS invalidation reason. It does not replace or alter
the default performance/gate scenario. No local build/test/netns execution was
used to claim evidence for this change.

Not included: public forwarding/DoH, DNS-over-TCP, registration, discovery,
replication, signer generation rotation, DNSSEC, IPv6, LAN listening, a host
resolver manager, a new revocation feed, or live material/status renewal. DNS
TTL behavior is unchanged (existing 60-second positive TTL, no negative SOA);
lease invalidation does not flush external caches or revoke already received data.
