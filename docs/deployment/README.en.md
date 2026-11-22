# Boreas Deployment Guide: From Material Preparation to Two-Node Connectivity

[简体中文](README.en.md) · [繁體中文](README.zh-TW.md) · English

This guide walks you through building a Linux tunnel that connects only two IPv4 VIPs. Run this exercise on two disposable hosts while keeping out-of-band management access such as SSH and a cloud console. Success is not "the service shows running"—it is **correct tunnel routes on both ends, bidirectional `ping` succeeding, and increasing TX/RX packet counters**.

| Artifacts you have | Which section to use |
| --- | --- |
| Trusted current development build (Linux, `openssl-inner-tls`) | Follow [Prepare -> Issue -> Configure -> Install -> Verify](#workflow) on this page. The development `daemon` requires explicit policy, network root pins, and persistent watermarks; do not reuse commands from the public release package. |
| Public pre-release `v0.1.0-pre.3` x86-64 pq768 binary | See [Public Pre-Release Two-Node Walkthrough](#public-pre3). Do not use the current `install.sh` service wrapper or the offline dual-signed service. |
| Pre-provisioned software release root and dual-signed candidate | Share the issuance and configuration workflow below, and switch installation to the [Offline-Signed systemd Service](VERIFIED-SERVICE.md) as an alternative to the legacy root template. |
| Connecting multiple Cores | Go to the [Four-Core Topology Guide](linux-core-mesh-topology.en.md); it uses separate CLI commands, manifests, material filenames, and TUN ownership. |

<a id="workflow"></a>

## 1. Prepare Environments and Addresses

- **Offline issuer machine**: Use a pre-verified, trusted Boreas build with pq768 PKI support; keep the working directory private and verify that the system clock is accurate. Separate artifact downloading or transfer from private key custody, and never fetch unknown binaries from the network on the offline issuer.
- **Two Linux nodes**: Use artifacts from the same source revision and verify the CPU architecture. Development artifacts must come from a compatible revision for the `tools/deploy/` scripts you use; you can obtain candidates from the corresponding run of the [build workflow](../../.github/workflows/rust-tls.yml) without assuming a newer public release exists. If you substitute your own OpenSSL or provider, previous acceptance conclusions no longer apply.
- **Underlay network**: Core accepts TCP `8443` from Edge (check both cloud security groups and host firewalls); Edge only needs outbound reachability, and UDP is not required for this guide. This guide uses direct WSS without a CDN or reverse proxy. Choose an unused port and TUN name that avoid existing host routes, management networks, and production networks.
- **System tools**: Full `iproute2`, `ss`, and `ping`; the installer also requires `readelf`, SHA-256 tools, and related utilities. `systemd` is required only on hosts using a `systemd` service path. Default deployment does not modify global IPv6, host DNS, or the default route.

| Item | Core | Edge |
| --- | --- | --- |
| Underlay address | Listens on `0.0.0.0:8443`; example reachable address `203.0.113.10:8443` | Dials Core's real reachable address; may sit behind NAT |
| Outer TLS name | `wss.example.net` (certificate DNS SAN) | Verifies `wss.example.net`; HTTP Host may include `:8443` |
| `[node]` slot | `home_core_id=1`, `vip_octet=1`, `node_id=1` | `home_core_id=1`, `vip_octet=2`, `node_id=2` |
| Tunnel parameters | `btun0`, MTU 1360, `10.20.1.1/32` | `btun0`, MTU 1360, `10.20.1.2/32` |

`203.0.113.10` is a documentation-reserved address and must be replaced. When dialing a bare IP, the example DNS name is used only for certificate verification and the HTTP Host header—it does not need public DNS resolution. The permanent VIP is `10.20.<home_core_id>.<vip_octet>`, and the node ID is `((home_core_id - 1) << 8) | vip_octet`. Write your configuration to match the issued materials rather than picking VIPs arbitrarily.

Run read-only checks on both nodes first:

```sh
uname -m
ls -l /dev/net/tun
ip -4 addr show
ip -4 route show
ip -4 route get 203.0.113.10
ss -ltn
```

The last two checks verify the underlay route and listening port respectively (on Edge, substitute Core's real address; on Core, check your management route as well). If `/dev/net/tun` is missing, have the host administrator verify kernel support, device passthrough, and permissions; on Linux systems supporting module loading, run `sudo modprobe tun`. Having UID 0 inside a container does not guarantee TUN or network-admin capabilities. On `systemd` hosts, check time synchronization with `timedatectl status`; verify UTC on the offline machine as well.

<a id="offline-issuance"></a>

## 2. Offline Issuance (Run Only on the Issuer Machine)

Work in a newly created private working directory. Run `boreas doctor` first to verify the actual build before issuing; a basic CLI archive cannot replace a binary built with the OpenSSL backend enabled. Record the `NET_ID` below because you will write it into both nodes' configurations and installer arguments, but never transfer private keys along with it.

```sh
umask 077
mkdir -m 0700 "$HOME/boreas-pki"
cd "$HOME/boreas-pki"
NET_ID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
printf 'NET_ID=%s\n' "$NET_ID"

boreas pki init-ca --ca-dir ./ca --net-id "$NET_ID" --validity-days 30
boreas pki issue-node --ca-dir ./ca --out-dir ./core --role core \
  --home-core 1 --vip-octet 1 --generation 1 --validity-hours 168 --outer-san wss.example.net
boreas pki issue-node --ca-dir ./ca --out-dir ./edge --role edge \
  --home-core 1 --vip-octet 2 --generation 1 --validity-hours 168

boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
cp ./status.signed ./core/status.signed
cp ./status.signed ./edge/status.signed
cp ./core/local.signed ./edge/peer.signed
cp ./edge/local.signed ./core/peer.signed

boreas pki verify-bundle --material-dir ./core --require-peer
boreas pki verify-bundle --material-dir ./edge --require-peer
```

Bundle verification should report `status: ok`; local/peer IDs should be `1/2` for Core and `2/1` for Edge. The initial status snapshot generated by `issue-node` is valid for only about one hour, whereas the separately signed example snapshot is valid for 24 hours. `peer.signed` is a **public signed identity**, not the peer's certificate private key. Each machine receives only its own node bundle; never swap `identity.key` or `outer.key`. **Keep the entire `ca/` directory in offline custody**—it contains the NetworkRoot, IdentityAuthority, StatusSigner, and outer TLS CA private keys.

<a id="network-policy"></a>

### Current Development Builds: Issue Network Policy

**Skip this subsection for the public pre.3 walkthrough**; all other issuance steps remain the same. For development builds, the policy and nodes must use the same `net_id`. The following commands issue the `10.20.0.0`-base policy supported by the current CLI, then separate the three signed inputs from the two public key pins:

```sh
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued \
  --sequence 1 --ttl-seconds 604800
mkdir -m 0700 ./policy ./pins
install -m 0600 ./policy-issued/tbs.cbor ./policy/policy.tbs
install -m 0600 ./policy-issued/ed25519.sig ./policy/policy.ed25519.sig
install -m 0600 ./policy-issued/mldsa65.sig ./policy/policy.mldsa65.sig
install -m 0600 ./policy-issued/root-ed25519.der ./pins/root.ed25519.der
install -m 0600 ./policy-issued/root-mldsa65.der ./pins/root.mldsa65.der
```

Have the NetworkRoot custodian pre-provision these two public pins through an independent trusted channel; never use a root shipped inside an unverified artifact as your trust anchor. The preflight check below uses a **trusted** verifier CLI and the verified pins to validate the objects only without recording watermarks:

```sh
boreas pki verify-policy --net-id "$NET_ID" \
  --tbs-file ./policy/policy.tbs \
  --ed25519-signature-file ./policy/policy.ed25519.sig \
  --mldsa65-signature-file ./policy/policy.mldsa65.sig \
  --root-ed25519-der ./pins/root.ed25519.der \
  --root-mldsa65-der ./pins/root.mldsa65.der
```

Distribute each node's material bundle, the three policy files, and the pre-provisioned pins to private staging; verify SSH host keys or use an approved secure transfer method. Do not upload the `ca/` directory, and do not mix in backups or temporary files. Keep a protected offline copy of both node bundles and record the initial issuance sequence number and expiration time.

## 3. Configure Both Nodes

Below is the **complete Core TOML**. On each machine, create its own `node.toml` (`0600`) and replace `REPLACE_WITH_NET_ID` with the same actual value. The example `[paths]` match the manual pre.3 paths below; the development installer relocates those three entries during installation, though the source config should still point to existing files and directories in private staging. The offline dual-signed `systemd` path uses its [fixed directory layout](VERIFIED-SERVICE.md#首次安装管理员) without legacy installer relocation.

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
identity_key = "/etc/boreas/material/identity.key"
roots = ["/etc/boreas/material/roots.cbor"]
state_dir = "/var/lib/boreas"

[uplink]
primary = "wss.example.net:8443"
paths = 4
probe_paths = 1

[limits]
ipv6 = false
advertise_routes = false
accept_routes = false
edge_direct = false
allow_edges = true
default_route = false
```

**Copy this file for Edge**: change `role` to `"edge"`, `vip_octet` and `node_id` to `2`, and `allow_edges` to `false`; leave all other fields unchanged (if actual paths differ between machines, fill in each host's local paths). `identity_generation` must match `issue-node --generation`. Do not mistake `paths = 4` for opening four active connections: it is the `[uplink]` path limit, not the active circuit count in this example.

- `[node]` corresponds to the issued identity; editing the TOML does not change the identity. On Core, `allow_edges` permits acting as an access endpoint and does not replace point-to-point authorization via `peer.signed`.
- `[paths]` must use absolute paths. Private keys must be readable only by the runtime UID, and the state directory must be persistent and writable by that UID. Never share a single runtime state directory between two nodes or two processes.
- `[uplink]` is required. Use `--listen` / `BOREAS_LISTEN` to set the listen address, `--connect` / `BOREAS_CONNECT` to dial the underlay IP explicitly, `--tls-name` / `BOREAS_TLS_NAME` to match the certificate SAN, and `--ws-host` / `BOREAS_WS_HOST` for the WebSocket request Host header. Never set all three to the tunnel VIP.

Run `boreas config-check /actual/path/node.toml` using the trusted matching build. Passing indicates only that static checks succeeded; actual materials, policy, listening, peer authorization, and TUN creation are verified at runtime.

## 4. Install and Start Current Development Builds

Follow the [One-Click Installation Runbook](ONE_CLICK.en.md): prepare identical private staging layouts on both hosts, verify trusted SHA-256 digests on each machine, run `--dry-run` first, and then install with `--service systemd --accept-legacy-service`. Write the respective Core and Edge `boreas.env` files, **start Core first, and start Edge immediately after seeing Core listen on TCP**. The legacy template runs as root and is meant for isolated evaluation; do not mix it with the offline dual-signed unit. Installation succeeding and `active` switching do not mean the local process is already running or the tunnel is up. Using `--service none` installs files only without starting the daemon.

Each machine sees only its own `<prefix>/releases/<id>/config.toml` and `materials/`; both may use the same release ID, but never mix their materials. The one-click startup script configures each side's own mesh VIP on `btun0` and adds only a single `/32` route to the authorized peer IPv4 VIP—never arbitrary `/24` routing, route export, or forwarding. It does not replace existing addresses or routes, and on exit removes only the entries it added. It does not modify the default route or system DNS on either Core or Edge. Normal internet traffic and outer connections still use the host's existing routing; resolve any address conflict with local networks before starting. **Do not pre-create `btun0` on this path**; by contrast, the offline dual-signed service requires the administrator to pre-create a persistent TUN and peer route.

<a id="verify-and-maintain"></a>

## 5. Verification and Routine Maintenance

Inspect from the underlay up to the application layer. Core listening does not mean handshake success, and a TCP connection in `ss` does not mean an authenticated circuit is established.

```sh
# Core
sudo ss -ltnp 'sport = :8443'
ip -4 addr show dev btun0
ip -4 route get 10.20.1.2 from 10.20.1.1

# Edge
ip -4 addr show dev btun0
ip -4 route get 10.20.1.1 from 10.20.1.2
# 替换为真实底层 IP；此路由绝不能指向 btun0
ip -4 route get 203.0.113.10
```

Under the legacy installer's default prefix, query status using the same UID running the daemon (root here). For the offline dual-signed service, use `sudo -u boreas` and `/var/lib/boreas/state/control.sock`; for pre.3, use `/var/lib/boreas/control.sock`. If no socket exists, check logs first instead of relaxing permissions. When checking the legacy template journal, set the service name explicitly to `boreas`.

```sh
sudo boreas ctl status --socket /opt/boreas/state/control.sock
sudo boreas console --json --socket /opt/boreas/state/control.sock \
  --service boreas

# Edge：发送前后各看一次状态
ping -c 4 -I 10.20.1.2 10.20.1.1
# Core：反向验证
ping -c 4 -I 10.20.1.1 10.20.1.2
```

Expected results: the peer `/32` route selects `btun0`; `daemon_connected:true`, `security_mode:"e2e-required"`, and `status_fresh:true`; bidirectional `ping` succeeds, and `tx_packets` and `rx_packets` increase on both sides. To verify TCP throughput afterward, run `iperf3 -s -B 10.20.1.1` on Core and `iperf3 -c 10.20.1.1 -B 10.20.1.2 -t 10` on Edge; run benchmarks only after troubleshooting, and do not treat isolated test results as a public-network SLA.

### Optional: Resolve private domain names

Confirm that the bidirectional `ping` above passes first. Then follow the [Private DNS Deployment Guide](../engineering/dns-daemon-deployment.md) to sign the private zone, install the pinned files on both ends, and query the private address directly. If only dedicated applications query it directly, do not modify the system resolver. To let standard applications resolve private names automatically, have the administrator configure strict split DNS for the private suffix only, routing only that suffix to the mesh DNS while all other domains stay on the host's existing resolver. Do not replace global DNS, and do not allow the private suffix to fall back to public DNS—including when the tunnel is down; neither the daemon nor the installer provisions OS resolver rules automatically. To enable TCP queries, explicitly set `[dns].tcp = true` on both ends. This option enables private DNS inside the tunnel only—it does not install OS resolver rules or forward queries to the public internet.

### Renewal, Restart, and Decommissioning

- **Status snapshot**: Before expiration, generate a new version on the offline issuer—for example, `boreas pki sign-status --ca-dir ./ca --out ./status-2.signed --sequence 2 --ttl-seconds 86400` (use `2` only if the current sequence is indeed `1`). Distribute the same new snapshot to both ends, copy it to a temporary file inside the actual daemon materials directory with the correct ownership and `0600` permissions, and atomically rename it on the same filesystem to `status.signed`. The daemon re-verifies the snapshot; if it has already stopped due to expiration, fix the materials before starting it. Re-check `status_sequence`, `status_fresh`, and bidirectional traffic. Different content with the same sequence number, or a lower sequence number, cannot serve as a renewal.
- **Legacy development install release directories**: Renewing `status.signed` online is a runtime material update, not an unchanged original installation bundle; do not re-deploy modified inputs under the same release ID. Use a new release ID for a new installation generation. Policy or root changes require separate evaluation of expiration, root fingerprints, and watermarks, planned per [Policy and State Rules](POLICY-STATE.md), rather than overwriting historical files. Rolling back software does not re-enable old, expired, or revoked authorizations.
- **Decommissioning**: On the legacy `systemd` path, run `sudo systemctl stop boreas.service`, and if disabling autostart, run `sudo systemctl disable boreas.service`; verify that the `/32` route and TUN added by the wrapper are cleaned up. On the manual foreground path, stop the process in its **own terminal** rather than running a global `pkill`. Persistent TUNs for the offline dual-signed or mesh paths are managed by the administrator, so stopping the service does not delete the device. Keep state and necessary logs for inspection—never wipe watermarks as a retry workaround.

<a id="public-pre3"></a>

## 6. Public Pre-Release Two-Node Walkthrough (`v0.1.0-pre.3` Only)

This is an isolated **x86-64 Linux** manual path. If a target machine already has a Boreas service, TUN, routes, or config, use a separate isolated host instead of overwriting the existing installation. The `.tar.gz` base archive is not the same as the pq768 binary below.

On the **download side**, fetch both files for the exact official tag into an empty directory, chaining with `&&` so the group aborts if any download or verification fails:

```sh
BASE=https://github.com/Lanlan13-14/Boreas/releases/download/v0.1.0-pre.3
BIN=boreas-linux-x86_64-musl-pq768
curl -fLO "$BASE/$BIN" &&
  curl -fLO "$BASE/SHA256SUMS-PRE3" &&
  grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -
```

After seeing `OK` for that binary and exit code `0`, independently verify the provenance and SHA-256 digest. Both files come from the same source, so this step checks download integrity only—not dual-signed release verification; do not execute as root unless trust is established. After confirming there are no naming conflicts, install the same verified artifact on both nodes, and transfer the issuance binary securely to the offline machine:

```sh
sudo install -m 0755 "$BIN" /usr/local/bin/boreas
boreas doctor
```

Confirm that `doctor` on this build reports `daemon: true` and `tls_backend: true`. Follow Section 2 to issue and verify bundles, **skipping the network policy subsection**. Transfer each node's bundle securely to its own `/etc/boreas/material`, and write `/etc/boreas/node.toml` per Section 3, keeping the example `[paths]` layout. Create root-owned private directories (`/etc/boreas`, `/etc/boreas/material`, and `/var/lib/boreas` with `0700`), set `0600` on configs and private keys, verify ownership, and run `sudo boreas config-check /etc/boreas/node.toml`.

Prepare terminals on both hosts first. Start the foreground command on Core, and once you see it listening, start Edge within the initial connection wait window (30 seconds); if that window expires, inspect the error and restart Core.

```sh
# Core，终端 1
sudo boreas daemon serve --config /etc/boreas/node.toml \
  --material-dir /etc/boreas/material --listen 0.0.0.0:8443 \
  --tun-name btun0 --mtu 1360
```

```sh
# Edge，终端 1：换成实际底层 IP，不要用 Core VIP
sudo boreas daemon connect --config /etc/boreas/node.toml \
  --material-dir /etc/boreas/material --connect 203.0.113.10:8443 \
  --tls-name wss.example.net --ws-host wss.example.net:8443 \
  --tun-name btun0 --mtu 1360
```

In a second terminal on each host, use `ip link show dev btun0` to wait for its daemon to create the TUN. Then run only the three commands for that host. If `add` reports a conflict, stop and investigate rather than using `replace` to overwrite an existing entry.

```sh
# Core，终端 2
sudo ip link set dev btun0 up
sudo ip addr add 10.20.1.1/32 dev btun0
sudo ip route add 10.20.1.2/32 dev btun0
```

```sh
# Edge，终端 2
sudo ip link set dev btun0 up
sudo ip addr add 10.20.1.2/32 dev btun0
sudo ip route add 10.20.1.1/32 dev btun0
```

Run the bidirectional checks in [section 5](#verify-and-maintain), using `sudo boreas ctl status --socket /var/lib/boreas/control.sock`. To stop, end both foreground processes and confirm that the TUN, addresses, and routes from this exercise are gone. Do not copy these older manual commands into today's service templates. For a persistent service, choose the service path that matches your development build.

<a id="troubleshooting"></a>

## 7. Troubleshoot from the first failing layer

| Symptom | Check first | Fix or next step |
| --- | --- | --- |
| `doctor` lacks TLS or daemon support, or a flag is missing | Which executable ran; `uname -m`; whether pre.3 and development CLI commands were mixed | Use a trusted pq768 build for the correct architecture and source revision. Don't guess at release tags or filenames or copy development flags blindly. |
| Installer rejects the digest, ELF, path, or material | Independently verified digest; static ELF and architecture; ownership, permissions, symlinks, and hard links of inputs and parent directories | Rebuild the staging directory privately. Don't bypass validation. Changed inputs require a new release ID. |
| `config-check` fails, or the wrapper exits `78` | TOML mode `0600`, `version = 2`, absolute paths, `boreas.env`, conflicts with the TUN name, VIP, or peer `/32` | Correct the fields, paths, or local conflicts. Read `sudo journalctl -u boreas.service -n 100 --no-pager` before trying again; don't loop on restarts. |
| Core isn't listening, or TCP times out | `sudo ss -ltnp 'sport = :8443'`; Core's bind address; cloud security group and host firewall; Edge `ip -4 route get` for the actual Core underlay address | Fix the binding or underlay route; use console access to recover management if needed. Never point the default route or public underlay address into the TUN. |
| `outer handshake` or outer certificate error | `--tls-name` and certificate SAN, chain, validity, Edge's outer CA, then `--ws-host` | Use the correct certificate and trust chain. An identity file or arbitrary HTTP Host cannot replace a SAN. Do not disable verification. |
| Inner authentication or PKI fails | `local.signed` matches the configured slot and generation; `peer.signed` really identifies the peer; roots and certificates belong to the same network | Re-run `pki verify-bundle --require-peer` with a trusted offline CLI and check both reported IDs. Never copy node private keys from the other host. |
| Status expired, policy signature rejected, or rollback detected | UTC on both hosts, issuance sequence, expiry, policy filenames, independent pins, and actual `state_dir` | Correct clocks or prepare new signed input. Keep durable anti-rollback state. Follow a reviewed migration if root fingerprints differ. |
| Socket missing or permission denied | Is a daemon running? Which UID, `state_dir`, and socket name does it use? | Query the correct path as the daemon UID. Don't loosen permissions with `chmod`. `mesh-run` has no such socket. |
| Connected, but VIP traffic fails in one or both directions | `ip -4 route get` on both hosts, selected source VIP, `btun0` address and MTU, host ICMP filtering, and packet counts at each side | Fix only the authorized peer `/32` and pin the source with `ping -I <local-VIP>`. Working underlay connectivity doesn't prove the authenticated circuit carries the right VIP pair. |

When reporting a problem, include the artifact source and exact source revision or tag, architecture, failing stage, redacted `ctl status`, and a short log excerpt. Never include private keys, TLS key logs, SSH credentials, or the full configuration environment. The repository's [redacted diagnostics collector](../../tools/diagnostics/README.md) does not read daemon configuration, keys, or logs.

## 8. Verify without public hosts

The [TLS workflow](../../.github/workflows/rust-tls.yml) uses `tools/release/netns_daemon_smoke.sh` to exercise a development build's real TUN data plane on an isolated Linux runner. It is not a pre.3 test script. Use a disposable runner with `/dev/net/tun` and permissions for network and mount namespaces. Match the workflow's source revision, binary, and parameters. The legacy installer, offline dual-signed service, and multi-Core runtime have separate test entry points in their guides. Record the exact source revision and the steps that actually passed. Ordinary Rust tests or skipped device checks aren't evidence of real packet I/O.
