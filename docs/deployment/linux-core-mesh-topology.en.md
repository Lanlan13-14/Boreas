# Four-Core Mesh: Traffic Paths, Directory Discovery, and Failover

[简体中文](linux-core-mesh-topology.en.md) · [繁體中文](linux-core-mesh-topology.zh-TW.md) · English

Use this standalone Linux experimental entrypoint when you need an isolated four-Core mesh circuit: `boreas node mesh-run <node.toml> <material-dir> <runtime.toml>`. Do not use the standard Core/Edge `daemon`, `boreas-run`, or offline-signed daemon units. This mode serves only **one pair of permanent Core IPv4 VIP `/32` endpoints**; Source initiates the circuit, and once confirmed both endpoints can send and receive. The `[[routes]]` recipe below supports up to three explicit paths per instance, each traversing three or four distinct Cores. Alternatively, follow the [signed-topology `[routing]` recipe](linux-core-mesh-runtime.md#configure-signed-topology-routing-and-tun) to configure only endpoint pairs and neighbor transports without listing end-to-end paths, supporting direct links or up to two relays; both recipes require the Source slot to be lower than the Destination slot. Default deployment does not modify host DNS or default routing—it performs no arbitrary subnet (such as `/24`) routing, route export or forwarding, Edge, default routing, IPv6, or DNS forwarding.

**Select your implementation build first:** Choose among the three directory modes detailed in [Section 4](#directory). The complete walkthrough on this page requires a Linux `openssl-inner-tls` development build that includes mesh coordinator directory discovery and durable CoreLSA support; it does not apply to public release `v0.1.0-pre.3`. If your build lacks the directory discovery changes, omit the coordinator configuration and use manual seeding or static control adjacencies instead. Durable CoreLSA anti-replay and conflict handling below also apply only to builds with directory discovery and durable CoreLSA support. Verify whether an artifact includes these capabilities by inspecting the exact source revision it was built from; existing documentation or CI passes on other revisions are not evidence.

## 1. Topology and Ports

```text
业务首选： Core 1 ──> Core 2 ──> Core 3 ──> Core 4
业务备选： Core 1 ────────────> Core 3 ──> Core 4
目录控制： Core 1 / Core 2 / Core 4 ────> Core 3:18183（双向交换 LSA）
```

| Node | Slot / node_id | Role, Underlay Address (Example), and TLS Name | Listening Ports | TUN |
| --- | --- | --- | --- | --- |
| Core 1 | `1 / 1` | Source, `192.0.2.1`, `core1.example.com` | None | `btun0`, `10.20.1.1/32` |
| Core 2 | `2 / 257` | Relay, `192.0.2.2`, `core2.example.com` | TCP `18082` primary path | None |
| Core 3 | `3 / 513` | Relay + directory coordinator, `192.0.2.3`, `core3.example.com` | TCP `18082` primary path, `18083` backup path, `18183` directory | None |
| Core 4 | `4 / 769` | Destination, `192.0.2.4`, `core4.example.com` | TCP `18082` primary path, `18083` backup path | `btun0`, `10.20.4.1/32` |

Do not use the example addresses on the public internet. Preconfigure the underlay listening addresses on each target host, and enter actual numeric IP addresses and ports—never VIPs—in dial configurations. Configure firewall rules to permit TCP per the table and directed links, restricting source addresses: Core 2's primary traffic port accepts Core 1; Core 3's primary and backup ports accept Core 2 and Core 1 respectively; both of Core 4's traffic ports accept Core 3; and the coordinator port accepts pre-provisioned slots 1, 2, and 4. Underlay names are verified against the certificate DNS SAN; dialing by IP does not require public DNS resolution for those names. Before deploying, verify SSH routes, existing `10.20.*` addresses, ports, and interfaces; these examples are not CDN or generic reverse-proxy configurations.

## 2. Offline Issuance of Nodes, Policy, and Per-Core Topology Advertisements

Initialize `./ca` and generate a new `NET_ID` once using the [two-machine tutorial's offline preparation workflow](README.en.md#workflow). Ensure all steps use the same trusted pq768 build, a private working directory, and accurate UTC time. **Do not issue Edge identities, and do not cross-copy `peer.signed`**; dedicated mesh uses `core-N.signed` below. For lab reproducibility, this command sequence issues an outer TLS certificate for every Core, though in this topology only listeners need the outer server private key.

```sh
for slot in 1 2 3 4; do
  boreas pki issue-node --ca-dir ./ca --out-dir "./core-$slot" \
    --role core --home-core "$slot" --vip-octet 1 --generation 1 \
    --validity-hours 168 --outer-san "core$slot.example.com" || break
done
boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued --sequence 1 --ttl-seconds 604800
```

Confirm that all four `local.signed` files and node keys were issued successfully before continuing. In the next step, the signer is **CoreOperational authorized by NetworkRoot and scoped to a specific Core slot**, not the runtime service account. The directories and arguments below demonstrate Core 1:

```sh
# Core 1 的签发机；新的 ./operational-1 目录只保存在签发区
boreas pki core-request ./operational-1 "$NET_ID" 1 1 7
# 离线 NetworkRoot 签发机：线下核验请求人和槽位，仅转运公开 core.request
boreas pki core-authorize ./ca ./ca/roots.cbor \
  ./operational-1/core.request ./roots-1.cbor 1
```

Repeat this for slots `2`, `3`, and `4`: update the third argument of `core-request` to the target slot and do not reuse directories; each `core-authorize` command must read the **previous step's output** (for example, Core 2 reads `roots-1.cbor` and writes `roots-2.cbor`, producing `roots-4.cbor` at the end). Issue one scoped signing delegation per slot and never reuse another slot's private key. Distribute the final public `roots-4.cbor` to all signing machines and runtime nodes, replacing the initial `roots.cbor` across all runtime nodes so no intermediate version leaks onto a node. Never place private keys for NetworkRoot, IdentityAuthority, StatusSigner, the outer CA, or CoreOperational into runtime directories.

On **each** signing host, issue that slot's LSA using the final `roots-4.cbor`. The four lines below correspond to the four slots; each writes to a distinct output file, taking `core-generation`, `seq`, validity in seconds, and zero to 15 `peer_slot:RTT_ms:loss_ppm` entries:

```sh
boreas pki core-sign-lsa ./operational-1 ./roots-4.cbor ./core-1.lsa-1 1 1 1800 2:5:0 3:30:0
boreas pki core-sign-lsa ./operational-2 ./roots-4.cbor ./core-2.lsa-1 1 1 1800 1:5:0 3:5:0
boreas pki core-sign-lsa ./operational-3 ./roots-4.cbor ./core-3.lsa-1 1 1 1800 1:30:0 2:5:0 4:5:0
boreas pki core-sign-lsa ./operational-4 ./roots-4.cbor ./core-4.lsa-1 1 1 1800 3:5:0
```

The issuer tags adjacencies as CDN class; **this class is strictly a protocol attribute and does not mean the lab traverses a real CDN**. A traffic edge must appear in the signed advertisements of both endpoints; with identical packet loss values, this example uses lower total RTT to prefer `1→2→3→4`. Directory connections are not traffic adjacencies (for example, `2→3` can use two separate ports, and `1→3` directory authentication does not grant authorization for a traffic path). Maximum issuance validity is 3600 seconds—issue close to startup while leaving time for distribution. On renewal, increment `seq` without modifying already-signed content for the same generation and sequence. An empty adjacency list may be issued as a withdrawal and grants no new authorization.

## 3. Per-Host Configuration: `node.toml` First, Then `runtime.toml`

Create a dedicated unprivileged account `boreas` on each host. Every parent directory of `/etc/boreas-mesh` and `/var/lib/boreas-mesh` must be trusted and must not be a symlink. Restrict configuration, private keys, and state to the runtime UID only (`0700` for private directories, `0600` for files). Give every node and instance isolated persistent state: never start a second instance reading or writing the same state concurrently, and never run `mesh-probe` against the same directory simultaneously.

Install the required files on **each** host according to this table:

| Install Location | Source |
| --- | --- |
| `/etc/boreas-mesh/material/identity.key`, `identity.pem`, `identity-ca.pem`, `local.signed` | That slot's own `issue-node` output |
| `…/material/roots.cbor` | Final public `roots-4.cbor` |
| `…/material/status.signed`, `local-lsa.signed` | Current status snapshot and that slot's raw signed LSA file |
| `…/material/core-N.signed` | Public `local.signed` for each slot N in `peers`; three files per host in this example |
| `…/material/core-N-lsa.signed` | Remote signed LSAs; check [Section 4](#directory) to see whether required |
| `…/material/outer.pem`, `outer.key` | Local outer server material; required on Core 2, 3, and 4. Place the leaf certificate first in `outer.pem`, followed by intermediate certificates (if any) |
| `…/material/outer-ca.pem` | On dialers in this example, place the public certificate of the same private outer CA; specifying this replaces platform roots rather than appending. Always verify TLS names and trust chains |
| `/var/lib/boreas-mesh/network-policy.tbs` | `policy-issued/tbs.cbor` |
| `…/network-policy.ed25519.sig`, `…/network-policy.mldsa65.sig` | `policy-issued/ed25519.sig`, `policy-issued/mldsa65.sig` |
| `…/network-root.ed25519.der`, `…/network-root.mldsa65.der` | Independently provisioned NetworkRoot pins matching policy outputs `root-ed25519.der` and `root-mldsa65.der` |

[Pre-check the policy](README.en.md#network-policy) with a trusted verifier before deploying. Keep policy filenames separate across the three deployment paths: dedicated mesh reads `network-policy.*`, the offline dual-signed daemon reads `policy.*`, and the legacy installer wrapper prepends a release prefix. At runtime, the process creates `status.state`, `network-policy.state`, and (on builds with directory discovery and durable CoreLSA support) `core-lsa.state`; do not pre-create empty files. `outer-ca.pem` governs only the outer layer; inner pq768 mTLS still validates the SPKI (SubjectPublicKeyInfo) of the signed node certificate and cannot be satisfied by an outer TLS name or IP.

Use the following complete `node.toml` for Core 1 (`/etc/boreas-mesh/node.toml`):

```toml
version = 2

[node]
net_id = "REPLACE_WITH_NET_ID"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"

[paths]
identity_key = "/etc/boreas-mesh/material/identity.key"
roots = ["/etc/boreas-mesh/material/roots.cbor"]
state_dir = "/var/lib/boreas-mesh"

[uplink]
primary = "core2.example.com:18082"
paths = 4
probe_paths = 1

[limits]
ipv6 = false
advertise_routes = false
accept_routes = false
edge_direct = false
allow_edges = false
default_route = false
```

Substitute the actual `NET_ID`. On Core 2, 3, and 4, update `home_core_id` and `node_id` per Section 1 and keep the remainder. `[uplink]` is required by the shared schema and does not control mesh dialing; do not add `[dns]` or other optional capabilities (host DNS remains unmodified). Run `sudo -u boreas boreas config-check /etc/boreas-mesh/node.toml` as the service UID first to validate the shared configuration; `runtime.toml` is parsed by `mesh-run` and is outside the scope of `config-check`.

Write each of the four `runtime.toml` files below to `/etc/boreas-mesh/runtime.toml` on its **corresponding host**. Each `listen` must match the preceding node's `next` hop by hop, and the route `path` must be identical across all nodes along that route. Never share or reuse sockets between traffic and control. Directory blocks are omitted below—append them as instructed in Section 4.

**Core 1 — Source**

```toml
mode = "source"
peers = [2, 3, 4]
tun = "btun0"
mtu = 1400

[[routes]]
path = [1, 2, 3, 4]
next = "192.0.2.2:18082"
tls_name = "core2.example.com"

[[routes]]
path = [1, 3, 4]
next = "192.0.2.3:18083"
tls_name = "core3.example.com"
```

**Core 2 — Relay (primary path only)**

```toml
mode = "relay"
peers = [1, 3, 4]

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.2:18082"
next = "192.0.2.3:18082"
tls_name = "core3.example.com"
```

**Core 3 — Relay (both paths)**

```toml
mode = "relay"
peers = [1, 2, 4]

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.3:18082"
next = "192.0.2.4:18082"
tls_name = "core4.example.com"

[[routes]]
path = [1, 3, 4]
listen = "192.0.2.3:18083"
next = "192.0.2.4:18083"
tls_name = "core4.example.com"
```

**Core 4 — Destination**

```toml
mode = "destination"
peers = [1, 2, 3]
tun = "btun0"
mtu = 1400

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.4:18082"

[[routes]]
path = [1, 3, 4]
listen = "192.0.2.4:18083"
```

<a id="directory"></a>

## 4. Choose One Directory Mode

**A. Pre-provisioned members + one coordinator (builds with mesh coordinator directory discovery and durable CoreLSA support).** Append the following to the end of Core 3's `runtime.toml`:

```toml
[directory_discovery]
coordinator = 3
listen = "192.0.2.3:18183"
```

Core 1, 2, and 4 each append the following to their own runtime manifest:

```toml
[directory_discovery]
coordinator = 3
next = "192.0.2.3:18183"
tls_name = "core3.example.com"
```

The directory doesn't discover arbitrary new members. Pre-provision the other three `core-N.signed` identities and the same final roots on every host. TLS clients verify the coordinator's outer name and certificate chain and its signed identity. The coordinator matches the exact inner TLS SPKI to provisioned members; it never learns members or keys from TCP source addresses, DNS, SessionHello, or LSAs. It exchanges validated original signed advertisements, never signs on behalf of a Core or authorizes a business link, and does not elect a replacement coordinator.

**Cold start: seed a current Core 1 advertisement only on Core 3** as `material/core-1-lsa.signed`, so Core 2, 3, and 4 can learn it before Source starts. Learn the remaining remote LSAs through the directory; no per-peer copying is needed in this recipe. Directory exchange can start before all advertisements arrive, but business listeners and TUN attachment wait until the graph has a usable path. Disk seeds remain verification inputs. On renewal, replace them atomically, or remove an unneeded **seed file** once its replacement head has been persisted. Don't leave expired seeds in place or delete durable state.

**B. Static control adjacencies (`[[directory]]`).** Don't mix this format with coordinator discovery. Use dedicated control links: the lower slot dials the higher one. Here Core 1 dials Core 2 at `192.0.2.2:18182`:

```toml
# Core 1
[[directory]]
peer = 2
next = "192.0.2.2:18182"
tls_name = "core2.example.com"
```

```toml
# Core 2
[[directory]]
peer = 1
listen = "192.0.2.2:18182"
```

Configure both ends and a separate port for each additional link, for example `1→2→3→4`. Give each directory listener its own outer TLS server certificate and configure the dialer with its trust chain. To start downstream first, you can seed all current LSAs. A remote head learned by static synchronization doesn't also need a seed file. Don't depend on a Source process that hasn't started to supply the first signed LSA.

**C. Manual seeds only (no directory section).** For initial deployment install the `core-N-lsa.signed` files for all peers on each node, then start in order. There's no cross-hop synchronization, but an authenticated direct business neighbor can still send a newer advertisement. Builds with durable CoreLSA support can reuse valid persisted heads after restart; do not assume that on older builds without this feature.

Directory synchronization validates direct announcements, identity revocations, and third-party signed advertisements. Each page contains one original signed LSA; the runtime checks the signature, delegated scope, timestamps, and anti-replay watermark. A verified page can be committed independently. The dialer schedules its next attempt five seconds after the previous attempt finishes, sharing scheduling with other control work and business rounds. **This is not a five-second convergence guarantee.** If the coordinator is temporarily unreachable, a fully authorized business graph remains usable for its own validity window. Invalid signatures, authority, or freshness are not bypassed. The directory doesn't distribute identities, authorization grants, leases, or conflict evidence.

## 5. Pre-create the endpoint TUNs, then start all four processes

On Core 1 and Core 4, use a persistent, single-queue TUN with no packet information header, assigned to `boreas`. Check first for interface and route conflicts, then run the commands for each host. Don't use `replace` to overwrite a host route. Neither relay needs a TUN.

```sh
# 只在 Core 1
sudo ip tuntap add dev btun0 mode tun user boreas
sudo ip link set dev btun0 mtu 1400 up
sudo ip addr add 10.20.1.1/32 dev btun0
sudo ip route add 10.20.4.1/32 dev btun0 src 10.20.1.1
```

```sh
# 只在 Core 4
sudo ip tuntap add dev btun0 mode tun user boreas
sudo ip link set dev btun0 mtu 1400 up
sudo ip addr add 10.20.4.1/32 dev btun0
sudo ip route add 10.20.1.1/32 dev btun0 src 10.20.4.1
```

The endpoints carry traffic only between the two authenticated VIPs. Keep underlay IPs and the default route out of the TUN. `mesh-run` attaches to and validates the existing device; it does not create or remove it. After reboot, have the administrator or host network manager recreate the dedicated TUN and authorized peer `/32`.

Run the following foreground command on all hosts with a trusted executable available to the `boreas` user. Each host has different configuration contents. Start Core 3, then Core 4 and Core 2. Wait for all three downstream nodes to log `mesh ready node=…` and confirm their business ports with `ss -ltn` before starting Core 1. `mesh ready` confirms a usable local graph and an open listener or TUN, not an established end-to-end circuit. Don't dial before the downstream nodes are ready: a failure before authentication and confirmation is not failover evidence.

```sh
sudo -u boreas boreas node mesh-run /etc/boreas-mesh/node.toml \
  /etc/boreas-mesh/material /etc/boreas-mesh/runtime.toml
```

When running under supervision, capture stderr and stop with SIGTERM. This runtime has **no** `control.sock`; don't use the ordinary daemon's `ctl status` to decide whether the mesh is online.

## 6. Verify traffic, failover, and troubleshoot

```sh
# Core 1
ip -4 route get 10.20.4.1 from 10.20.1.1
ping -c 4 -I 10.20.1.1 10.20.4.1
# Core 4
ip -4 route get 10.20.1.1 from 10.20.4.1
ping -c 4 -I 10.20.4.1 10.20.1.1
```

1. On Source and Destination, check the same confirmed `circuit` ID and `path=[1, 2, 3, 4]`. Both endpoints should log `tx`/`rx`. Relays report ciphertext counters, not payload contents.
2. **On a disposable deployment only**, confirm the primary path is carrying traffic, then stop Core 2 (not the Core 3 coordinator). Wait until both endpoints confirm `path=[1, 3, 4]`. They should agree on the new ID, which must differ from the old one. Send fresh pings. The runtime attempts a new hop chain and new E2E TLS only with eligible link-loss evidence and a still-authorized alternative. It does not replay old packets or ciphertext. EOF/reset before confirmation, authentication or protocol errors, expiry, and revocation are not automatic failover triggers. Switchover isn't guaranteed lossless; TCP recovery belongs to the application or transport above the tunnel.
3. See [repository acceptance tests](#acceptance) for revocation scenarios. The independent `identity-revocation.signed` mailbox carries IdentityAuthority revocations, not the StatusSigner's routine snapshots. Committed revocation survives mailbox deletion and restart. The runtime polls while a circuit is active and persists the decision before closing an affected circuit. For remote revocation, original signed evidence can still travel via healthy directory neighbors. Local-generation revocation stops the process.

| Symptom | Check in this order |
| --- | --- |
| Directory is listening, but `mesh ready` never appears | Check that all three clients dial the same coordinator, TCP and certificate SAN are correct, and all provisioned `core-N.signed` identities are present. Check the Core 1 bootstrap seed and LSA expiry. Verify signed claims from both endpoints of each business link and matching manifests along the path. |
| `invalid directory discovery configuration` / `overlapping legacy links` | Verify the build supports coordinator discovery. Use only `listen` on the coordinator and only `next` plus `tls_name` on clients, apart from the shared coordinator field. Don't mix directory formats or reuse business sockets. |
| `mesh TUN attach` or no VIP traffic | Confirm that the dedicated device is persistent, assigned to `boreas`, and matches the name and MTU. Compare `ip -4 route get` and selected source VIPs at both ends; check the same confirmed circuit ID and path. |
| Live traffic stops and logs report invalid status, authority, or LSA | Check UTC, policy and status expiry, revocations, and all topology advertisements. A higher sequence doesn't override independent revocation or equivocation. Fix the cause, then coordinate a restart if needed. |
| `LsaConflict` / `LsaState` or startup refused | Stop the process. Preserve protected `core-lsa.state`, `core-lsa.state.lock`, and `core-lsa.state.staging` if present. Inspect the filesystem, permissions, previous state, and issuer. Don't delete state or switch to an empty directory to recover. |

### Durable CoreLSA conflict evidence (supported builds only)

`mesh-run` and `mesh-probe` use `state_dir/core-lsa.state`. Restrict it to the service UID. It binds to `net_id`, the NetworkRoot fingerprint, and the local slot, and keeps at most one current original signed advertisement per slot, up to 16 slots. On the first validly signed equivocation with the same `(core_generation, seq)` but different to-be-signed bytes, the runtime retains both original envelopes and stops using that authorization. The lock coordinates writes and marks an intent to initialize or write conflict state. A commit syncs the private staging file, installs it atomically, and syncs the parent directory. A failed commit, unresolved conflict marker, interrupted staging, missing initialized state, unsafe path, corruption, or verified equivocation causes startup or runtime authorization to fail closed. Raising the generation does not clear a persisted conflict.

During recovery, old seeds cannot lower existing watermarks. Verify historical envelopes against the dual signatures and delegation in force at issuance; authority to carry traffic remains subject to current policy, expiry, and revocation. Before rotating keys, ensure the delegation needed to verify historical evidence remains available. Preserve the evidence before investigating bad issuance, keys, or storage. Have an administrator review and re-provision trust if needed; there is no automatic unblocking. Do not delete `.lock`, `.staging`, or the state directory to restore service. This mechanism does not prevent a trusted UID or root from replacing the entire state directory or rolling back a storage snapshot.

<a id="acceptance"></a>

## 7. Run the acceptance tests and understand what they prove

Use a controlled Linux runner and the [TLS workflow](../../.github/workflows/rust-tls.yml) for the source revision under test. Use the same pinned OpenSSL, environment, and features. The repository has two entry points:

```sh
cargo test --locked -p boreas-tunnel --features openssl-inner-tls --test mesh_probe_live
cargo test --locked -p boreas-cli --features openssl-inner-tls --test mesh_run_netns --no-run
```

The real-device tests are ignored by default. Run the exact `mesh_run_netns` binary path printed by Cargo. Use a disposable runner with `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `ip`, `ping`, `unshare`, `mount`, and `setpriv`. Preserve the build's `OPENSSL_CONF` and `BOREAS_OPENSSL_BIN`:

```sh
sudo --preserve-env=OPENSSL_CONF,BOREAS_OPENSSL_BIN \
  /path/printed/mesh_run_netns-HASH --ignored --nocapture --test-threads=1
```

The fixed-path case starts four non-root processes and two real persistent TUNs. The coordinator alone seeds Source's LSA. The shared directory converges; the primary and backup paths each carry real traffic, with checks for a new circuit ID and ciphertext counters. Revoking an active remote member closes the circuit and reports that no path is available without exiting. Only revoking the local generation requires Source to exit with code `2`. Two further cases omit fixed paths: one checks that a unilateral advertisement can't authorize a direct path and that the entry point is reusable after link loss; the other rebuilds a direct circuit using mutual signed advertisements after a runtime revocation. Live TLS tests also cover idle-circuit revocation, cross-hop propagation, rejection of unprovisioned members, and conflict evidence across restart. These are test assertions, not a claim that your artifact passed: check the logs for its source revision. The tests do not traverse a real CDN or establish long-running public reliability, general routing, or production readiness.
