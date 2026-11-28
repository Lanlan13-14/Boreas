# Boreas One-Click Install: Dry Run First, Then Start

[简体中文](ONE_CLICK.md) · [繁體中文](ONE_CLICK.zh-TW.md) · English

**Local one-click entrypoint (experimental branch):** once the independently authenticated binary, deployment tools, network policy, pins, configuration and per-node materials below are prepared, run from the audited checkout root on each Linux host. Replace both placeholders with independently verified values; inspect the plan before applying. The root systemd template is for development only and does not start automatically.

```sh
STAGE=/root/boreas-stage
NET_ID=REPLACE_WITH_NET_ID
DIGEST=REPLACE_WITH_TRUSTED_SHA256
one_click() {
  sudo sh tools/deploy/one-click.sh --stage "$STAGE" --network-id "$NET_ID" \
    --sha256 "$DIGEST" --release local-eval-1 --service systemd \
    --accept-legacy-service "$@"
}
one_click --dry-run
# After reviewing the plan and independently authenticating all inputs:
one_click --apply
```

For no service, replace `--service systemd --accept-legacy-service` with `--service none` in the function and repeat the dry run. Follow Section 3 to configure, start, and verify the service. This entrypoint delegates to `install.sh`; it does not download, build, issue certificates, open ports, start, or join hosts. Public `v0.1.0-pre.3` is incompatible. Same-origin checksums are not signatures; never use `curl | sh`. The current experimental wrapper explicitly passes `BOREAS_TRANSPORT=wss|direct` to a matching daemon, defaulting to WSS; an older binary without this option is incompatible. The example uses private-CA WSS over direct TCP; `direct` instead omits outer TLS/WebSocket and relies on inner authenticated encryption. For public-CA WSS, provision the Core certificate chain and key independently; Edge can use the OpenSSL system trust store without `outer-ca.pem`, or provision an appropriate additional root. Certificate issuance, renewal, CDN compatibility and end-to-end validation are not automated.


`tools/deploy/install.sh` installs a static Linux binary that **has already been built and whose provenance you have verified**. It also checks configuration, stages materials, and switches the local active release—that completes the installation. It does not compile binaries, issue certificates, auto-discover peers, or open firewall rules for you. To verify connectivity between two hosts, complete [Deployment Tutorial Sections 1–3](README.en.md#workflow) first.

The `systemd` and `procd` templates covered here are opt-in legacy development templates that run as `root`. When you need a verified release manifest, non-privileged execution, and readiness-based rollback, use the [offline dual-signed systemd path](VERIFIED-SERVICE.md) instead—do not mix the two installations. This page targets **current compatible development builds**; the public `v0.1.0-pre.3` release lacks the daemon policy flags required here.

## 1. Prepare Inputs on Both Core and Edge

On each target host, create `/root/boreas-stage` (owned by `root`, mode `0700`) and set all files inside it to `root` ownership and mode `0600`; the binary input itself does not need to be executable beforehand. You may substitute your own private absolute directory path. Also prepare an audited source checkout containing `tools/deploy/install.sh` and the templates in the same directory. Run all commands below from the checkout root directory.

```text
/root/boreas-stage/
├── boreas                   # 本机架构的静态 Linux 候选
├── node.toml                # 此主机自己的配置；不是两端通用文件
├── material/                # 此主机的扁平节点包，含 local.signed / peer.signed
├── policy/                  # 仅三个文件，连备份或隐藏文件也不要放
│   ├── policy.tbs
│   ├── policy.ed25519.sig
│   └── policy.mldsa65.sig
└── pins/
    ├── root.ed25519.der
    └── root.mldsa65.der
```

- **Artifacts**: Obtain the 64-character hex SHA-256 digest (or a pre-verified trusted signed manifest) from an independent trusted channel, and verify the source revision, architecture, and static linking; `sha256sum` only computes the digest of a local file and does not prove provenance. After checking the digest and ELF binary, the installer **executes** the candidate binary's `doctor`, `config-migrate`, `config-check`, and `pki verify-bundle` commands. Complete authenticity verification before running the installer—never let a candidate binary vouch for itself.
- **Network trust**: Prepare and pre-check materials using a trusted CLI with `pki verify-policy` as described in [Offline Issuance](README.en.md#offline-issuance). Provision the two network root pins independently and do not place them inside `material/`. The script validates paths and permissions rather than dual signatures on the policy; at startup, the daemon verifies signatures against the pins, records the watermark, and refuses to carry traffic if verification fails.
- **Files and paths**: `material/` accepts only node bundle files and peer identities—it rejects offline CA private keys, unknown files, symlinks, special files, and subdirectories. Policies and pins must be non-empty regular files with a single hard link, and their parent directories must also be trusted. The install target `/opt/boreas` and default `/usr/local/bin` must not be symlinks and must not be group- or world-writable; `--bindir` must exist beforehand. Never place the install prefix under `/tmp` or reuse a system directory. See [Policy and State](POLICY-STATE.md) for the complete rules.
- **Tools**: Ensure full Linux `iproute2`, `readelf`, `sha256sum`, and standard POSIX shell utilities are present; the script does not install dependencies automatically. On a remote host, confirm that your management path does not traverse the TUN interface about to be created.

## 2. Dry Run and Install with the Same Parameters

Replace the two `REPLACE_…` placeholders below with your actual values. This shell function exists solely to reuse the install command; redefine it if you switch terminals. Always run `--dry-run` first to inspect the expected paths and service type, and run the dry run under the same UID (`root`) for `root`-owned inputs.

```sh
STAGE=/root/boreas-stage
NET_ID=REPLACE_WITH_NET_ID
DIGEST=REPLACE_WITH_TRUSTED_SHA256
RELEASE_ID=local-eval-1

install_boreas() {
  sudo sh tools/deploy/install.sh \
    --binary "$STAGE/boreas" --sha256 "$DIGEST" --release "$RELEASE_ID" \
    --materials "$STAGE/material" --config "$STAGE/node.toml" \
    --policy-dir "$STAGE/policy" --network-id "$NET_ID" \
    --network-root-ed25519-der "$STAGE/pins/root.ed25519.der" \
    --network-root-mldsa65-der "$STAGE/pins/root.mldsa65.der" \
    --prefix /opt/boreas "$@"
}

install_boreas --service systemd --accept-legacy-service --dry-run
```

Dry run is strictly read-only: it does not download files, write to the target prefix, or execute the candidate binary or service manager. It verifies only the digest, ELF properties, paths, and file provenance, and cannot prove that configuration checks or policy signature verification will succeed. `--url` is not part of this guide's workflow: the script accepts only direct HTTPS binary URLs, requires `--accept-weak-https`, and still cannot verify release signatures.

Proceed with the real installation only after the dry run and trust checks pass with no errors. If you want only the versioned layout and entrypoints without installing a service, switch to `--service none` (and use that same flag during `--dry-run`). If the host is already running `boreas.service`, schedule downtime and inspect the existing service and paths first rather than treating it as a fresh install; legacy templates must not replace an offline dual-signed service.

```sh
install_boreas --service systemd --accept-legacy-service
sudo cat /opt/boreas/active
sudo /usr/local/bin/boreas doctor
```

By default, the installer **does not start** the service. `active` should output `local-eval-1`, and `doctor` should confirm that the binary includes daemon and TLS support. `/opt/boreas` has mode `0700`, and in this example the dispatcher and runtime state are accessed as `root`. Resulting layout:

```text
/opt/boreas/
├── active                               # 当前 release id
├── boreas-dispatch / boreas-run          # 固定前缀，非调用者环境变量决定
├── releases/local-eval-1/
│   ├── boreas / config.toml / bundle.sha256
│   └── materials/ / policy-inputs/
└── state/
    ├── local-eval-1.policy.tbs           # 同代际还有两签名、两 pin
    └── status.state / policy.state       # 由 daemon 创建；安装器不预建
```

`config-migrate` generates a `version = 2` configuration without modifying the source file; the installer checks `net_id` and updates `[paths]` (`identity_key`, `roots`, `state_dir`) to point to the private key, roots, and shared state directory under the active release. Review all other configuration settings yourself. The `boreas` and `boreas-easy` entrypoints in the default `/usr/local/bin` point to the dispatcher.

## 3. Write Local Role and Startup Parameters

After confirming `/etc/boreas` is not used by another service, create it as a `root`-owned non-symlink directory (`0700`) and create `/etc/boreas/boreas.env` as a regular file with exact mode `0600`. For a new file, use the two commands below; **the second command truncates any existing file and is only for initial creation**. Then edit the file as an administrator and write only the configuration for this host's role—do not combine both blocks.

```sh
sudo install -d -m 0700 -o root -g root /etc/boreas
sudo install -m 0600 -o root -g root /dev/null /etc/boreas/boreas.env
```

Core (requires security group and firewall rules permitting the listening port):

```ini
BOREAS_ROLE=core
BOREAS_VIP=10.20.1.1
BOREAS_PEER_VIP=10.20.1.2
BOREAS_LISTEN=0.0.0.0:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

Edge (replace the underlay IP, verify the certificate SAN, and omit the tunnel VIP):

```ini
BOREAS_ROLE=edge
BOREAS_VIP=10.20.1.2
BOREAS_PEER_VIP=10.20.1.1
BOREAS_CONNECT=203.0.113.10:8443
BOREAS_TLS_NAME=wss.example.net
BOREAS_WS_HOST=wss.example.net:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

For the VIP, use the RFC1918 address from the signed identity without `/32` and without leading zeros; underlay listen/dial values use numeric IPv4 plus port; the TUN interface name must be at most 15 characters; the wrapper MTU range is `1280..1400`. Do not pre-create a matching TUN interface or peer `/32` routes—the wrapper creates its own runtime resources, refuses to start on conflict, and never overwrites existing network configuration. On stop, it attempts only to remove the addresses and routes it added; it does not flush routing tables or modify the default route, firewall, or host DNS.

Run `daemon-reload` and `start` on Core first. Wait until Core is listening on its TCP port before running those two commands on Edge. Consider running `enable` for start-on-boot only after [bidirectional verification](README.en.md#verify-and-maintain) passes.

```sh
sudo systemctl daemon-reload
sudo systemctl start boreas.service
sudo systemctl status boreas.service
sudo journalctl -u boreas.service -n 100 --no-pager
```

`Type=simple` reporting `active` does not prove that handshakes, routing, or traffic are healthy. Query the actual daemon:

```sh
sudo /usr/local/bin/boreas ctl status --socket /opt/boreas/state/control.sock
sudo /usr/local/bin/boreas-easy --socket /opt/boreas/state/control.sock --service boreas
```

When ready to enable start-on-boot, run `sudo systemctl enable boreas.service`. After an upgrade, an already-running process is not replaced automatically when `active` switches; review the update, run `sudo systemctl restart boreas.service` on schedule, and repeat bidirectional verification. You can also pass `--start` explicitly to enable and (re)start during installation, but that requires a compliant `boreas.env` prepared in advance and does not validate the data plane—this guide separates those steps deliberately so you can inspect first.

### Evaluation-Only `procd` Template

The legacy template can render `/etc/init.d/boreas` with `--service procd --accept-legacy-service`, using the same environment file. The template reads literal `KEY=VALUE` lines via an allowlist—do not include quotes, trailing comments, spaces, variable expansion, or CRLF line endings. The target host needs full `iproute2`, Linux TUN, and the other required utilities; the existence of this template does not mean BusyBox `ip` or physical OpenWrt hardware has been validated. Review paths, tools, and architecture on your target image in non-starting mode first; if you lack a validated environment, use the Linux/`systemd` path.

## 4. Install Failures, Stopping, and Rollback

- **Dry-run rejection**: Inspect the first error reported. Check every ancestor directory of the install target, the `material/` allowlist, that both pins reside outside `material/`, that the three policy files contain no extra files, and that the binary matches the static ELF and architecture checks. Never relax directory permissions or ignore a digest failure.
- **Install failure**: `<prefix>/.install.lock` serializes installer runs; investigate stale locks rather than breaking them. `active` is switched last; if an install step explicitly fails after that switch, the installer attempts to restore the previous pointer, though files from the failed release may remain on disk. `sync` is not a power-loss guarantee. Verify `active`, logs, and the running process—never treat a restored pointer as proof that the old service is running.
- **Service startup failure or crash loop**: Run `sudo systemctl stop boreas.service` first and check the logs. Exit code `78` is the legacy wrapper's configuration rejection, and the template does not restart on that exit code; ordinary errors are bounded by restart rate limits. An installed service never automatically rolls back its active version on runtime failure.
- **Upgrades and manual rollback**: Re-installing an existing release ID accepts only byte-identical inputs; use a new ID for any change, because historical generations are never overwritten. When rolling back, stop the service, verify that the older artifact, older policy, and existing persistent state remain compatible and valid, then restore the pointer following [Policy State and Rollback Semantics](POLICY-STATE.md#6-升级--start-与回滚), start the service, and re-verify. Never attempt recovery by deleting `status.state` or `policy.state` or by lowering the authorized watermark.

### Distinguishing Test Evidence

- `tools/deploy/test-install.sh` is an isolated shell regression suite (it mocks system tools, does not run as `root`, and must not run on a host with an existing Boreas service). It validates file provenance, paths, permissions, release pointers, and wrapper constraints, and does not prove real packet forwarding.
- `tools/deploy/test-real-install.sh` is executed by the [deploy workflow](../../.github/workflows/deploy.yml) on a controlled runner to verify static installation with `--service none`; it does not start a service or perform live TUN acceptance. For real data-plane verification, consult the [TLS workflow](../../.github/workflows/rust-tls.yml) and the [Two-Host Verification Checklist](README.en.md#verify-and-maintain).
