# Static private DNS on Linux (opt-in)

The supported slice is one real Linux Core `daemon serve` and one Edge `daemon
connect`, with the existing authenticated pq768 E2E session. No new handshake,
capability advertisement, namespace, process privileges, or socket exceptions.
The daemon uses neither a kernel DNS TCP listener nor a DNS UDP socket. It
carries complete IPv4/UDP and (when enabled) IPv4/TCP packets inside the existing
encrypted stream. The TCP endpoint is smoltcp in the Core packet owner, not a
host listener or a tunnel to a host resolver. The daemon's NO_UDP sandbox is
unchanged; host applications are separate from that sandbox.

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
   either node. Use distinct offline keys for root and DNS signer. An owner can
   have multiple A records, each pointing to a signed permanent VIP claim.
   The test fixture is not an operator signing utility.
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
   Set `[dns].tcp = true` on **both** nodes to enable the in-tunnel TCP
   endpoint and Edge route handling (default `false`: UDP-only). There is no
   peer feature negotiation; mismatched settings are unsupported. TCP cannot
   be enabled without both flags, with `--virtual-tun`, or with `--tun-tcpv4-gso`.
   Edge standby and multi-active are outside the private DNS profile. A missing
   flag, mismatched zone or pin, invalid signatures, wrong network, or wrong
   Core generation with DNS requested is a startup error, not an unsigned
   fallback. With neither flag and TCP not requested the normal path is unchanged.
   Use a direct daemon launch or an operator-controlled launch passing these
   exact arguments. Installer/one-click, console, and service templates do not
   provision this feature or install its routes. A `config-check` rejection for
   `dns.tcp` outside this daemon profile is not a launch-time DNS health check.

## Route and quarantine at the Edge

Keep the existing peer route and add **only** the DNS `/32` through the already
provisioned Edge TUN, e.g. for the fixture:

```sh
ip route replace 10.20.0.53/32 dev btun0 src 10.20.1.2
```

The virtual DNS address is not assigned on either host. Do not install a Core
host route/listener for it. A private-aware application or strict split resolver
must route the exact private apex and descendants **only** to this numeric VIP,
with **no** second server, search retry, public resolution, system fallback, or
host DNS proxy for that suffix even when the tunnel is absent. With TCP enabled
on both ends, the resolver may use explicit TCP or retry a truncated UDP query
**over TCP to the same private VIP only**. For UDP-only deployments disable TCP
retry for the suffix. Provision this
quarantine rule independently of tunnel readiness and keep it on failure; use
an Edge namespace or egress policy that prevents the DNS `/32` going out the
underlay when the TUN is down. This slice neither edits host DNS configuration
nor claims to prevent leaks by applications that bypass the operator's resolver.
For the explicit query client in the netns test there is no upstream configuration
at all. The Edge drops out-of-suffix UDP queries and non-DNS ports/protocols to
the reserved VIP. It does **not** parse TCP stream QNAMEs: arbitrary TCP payloads
to the VIP can reach the authenticated Core, where the signed suffix is checked
after stream reassembly. A malformed or out-of-suffix TCP message aborts that
DNS stream without a DNS answer. The Core never calls a public resolver.

An A query returns the complete signed RRset if it fits. The response ceiling
is the minimum of the negotiated IPv4 MTU minus 28 bytes, the resolver cap, and
512 bytes without EDNS (otherwise the advertised EDNS payload, clamped to
512–4096 bytes). If the complete response does not fit, the Core returns TC
with the whole question, no answer or authority records, and a minimal OPT
when the request used EDNS. If even that cannot fit, it sends nothing. A client
can request an explicitly larger EDNS size **at the same VIP**, if permitted by
its quarantine policy, or issue the query over TCP **at that same VIP** if both
ends opted in. TCP sends the complete signed answer independently of the UDP
and EDNS datagram ceilings, up to 4096 DNS bytes. Do not consume a partial RRset
or retry against another server or any public path. For the
current signed profile there are at most 64 distinct IPv4 claims. The largest
A response is at most 1306 bytes (12-byte header + up to 259-byte question +
64 × 16-byte records + 11-byte OPT), so EDNS 1320 with an IPv4 tunnel MTU of at
least 1334 accommodates any such UDP answer. At a lower MTU, enable same-VIP
TCP or ensure each necessary RRset fits the effective UDP ceiling.

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
TCP requires the same current authenticated binding and verified IPv4 endpoints,
ports, packet lengths and checksums. The Edge keeps at most 64 TCP client-port
entries learned only from local SYNs; the oldest is evicted at capacity and
entries expire 75 seconds after the most recent SYN. Linux and smoltcp, not the
Edge table, validate TCP sequence state. There is no Edge DNS question matching
on TCP; the application must match replies. In both transports the authenticated
Core is trusted for answer RRs; the Edge does not validate RRs cryptographically.
Normal permanent VIP packets still use the existing checks.

The Core has eight fixed TCP sockets, 8 KiB RX and 8 KiB TX buffers per socket,
bounded DNS framing/staging, a 4096-byte query/response cap, up to 16 completed
frames per poll, a 10-second receive-idle deadline and a 60-second maximum age
for active TCP slots. Closing states are handled by smoltcp. Input, device
input and output queues have 64 packets each. UDP and TCP share the same
per-binding dispatch budget. The Core polls timers independently of input on
the packet owner loop (nominal 10 ms idle wake, coarser under work or blocked
outer I/O). It emits at most 16 queued DNS packets per turn and counts actual
TX, including TCP control packets and retransmissions, against `--max-packets`.
UDP-only retains its one-reply reservation. Saturation can drop packets or
cause connection failures; this is not a throughput or fairness guarantee.
Outer TLS/WebSocket I/O is still blocking with existing timeouts; DNS timers
are not hard real-time and retransmission cannot fix an unusable outer circuit.
There is no DNS-ready bit in the supervisor handshake or `ctl status`. Only a
successful Edge query confirms the DNS path at that moment.

## Automated live acceptance

The DNS-specific step in `.github/workflows/rust-tls.yml` runs this scenario
on its selected refs, in addition to the default tunnel/performance checks. To
reproduce it, use the exact candidate Linux binary and an OpenSSL CLI that
supports ML-DSA-65, plus root, Linux netns, `/dev/net/tun`, `ip`, `ss`, and Python 3:

```sh
BOREAS_OPENSSL_BIN=/path/to/openssl-3.6 BOREAS_NETNS_PRIVATE_DNS=1 \
  bash tools/release/netns_daemon_smoke.sh /path/to/candidate/boreas
```

The scenario builds signed test fixtures with ephemeral offline keys and installs
only the Edge DNS `/32`. It byte-checks single-A, mixed-case multi-A, AAAA NODATA,
NXDOMAIN, whole-set truncation with and without EDNS 512, and a complete 32-A
answer with EDNS 1232. TCP exercises a split length prefix, pipelining, client
half-close and byte-exact responses, including a 64-A answer larger than the
fixture's advertised 600-byte TCP MSS. It probes out-of-suffix and wrong-port queries, rejects
oversized TCP framing, and checks idle timeout without inbound activity and a
successful subsequent query. It checks both namespaces for kernel UDP sockets
and TCP/53 listeners after the probe client exits, and checks ordinary ICMP over
the same circuit. Finally it holds an open DNS TCP stream, withdraws only the
Core pin, requires a nonzero Core exit with the DNS invalidation reason and no
additional DNS data on the stream. A kernel TCP client may time out instead of
seeing FIN/RST when its TUN disappears. This scenario is not proof that arbitrary
clients implement quarantine; the socket check is a snapshot, not a replacement
for the daemon's NO_UDP sandbox. No local build, test, or netns execution is claimed.

Not included: public forwarding/DoH, DNS-over-TLS, registration, discovery,
replication, signer generation rotation, DNSSEC, IPv6, LAN listening, a host
resolver manager, a new revocation feed, or live material/status renewal. DNS
TTL behavior is unchanged (existing 60-second positive TTL, no negative SOA);
lease invalidation does not flush external caches or revoke already received data.
