# Boreas 双机公网实战部署教程（`v0.1.0-pre.3`）

本教程面向 Linux 开发测试与受控部署评估，介绍两节点 `Core <-> Edge` IPv4 隧道的离线 PKI、配置、启动、检查与常见故障。示例使用预发布 `pq768` 构建及 `/dev/net/tun`；它们不构成生产部署认证。文末附单机双 `netns` 演练。开始前建议阅读 [当前实现状态](../engineering/implementation-status.md) 与 [安装辅助脚本边界](ONE_CLICK.md)。

> **入口导航：** 想用行式交互状态/服务菜单请看下方 [boreas-easy 控制台](#boreas-easy-行式控制台)；想审阅安装已有二进制的流程请读 [一键安装辅助脚本说明](ONE_CLICK.md)。后者和 OpenWrt procd 模板当前均处于验证中，不能据此认定 OpenWrt 产品支持。

### 当前版本边界与已知限制（部署前必读）

- **发布资产与开发主线不是一回事**：目前可下载的最新预发布仍是 **[`v0.1.0-pre.3`](https://github.com/Lanlan13-14/Boreas/releases/tag/v0.1.0-pre.3)**。仓库已有更新开发主线与下一版工作项，但在正式发布资产、校验和就绪前，请勿预设 `pre.4` 版本号、文件名或哈希。此教程中的下载命令严格对应 pre.3。发布页约 510 KB 的基础归档不含 TLS 后端；部署隧道应使用页面实际提供且经核验的 Linux `-pq768` 二进制。
- **性能证据须对应提交与环境**：精确提交 [`8cf865e`](https://github.com/Lanlan13-14/Boreas/commit/8cf865ec7bc9f974b2db623c6c60917e6af7ec08) 的隔离 netns/veth 基准报告 glibc 平均延迟 `0.228 ms`、`268.450 Mbps`，musl 平均延迟 `0.256 ms`、`194.547 Mbps`（[性能工作流 run 43722214463](https://github.com/Lanlan13-14/Boreas/actions/runs/43722214463)）。这是隔离测试结果，不是公网 SLA、跨地域延迟数据或持续负载容量保证，也不应无条件外推至其他版本/硬件。

- **拓扑与生产门禁状态**：本教程范围是 Linux 双节点（`1 Core <-> 1 Edge`）IPv4 点对点评估；跨多 Core 多跳网格、自动故障切换、生产自动化证书/状态轮换与内建 DNS 运行时未完成。[24 项正式生产门禁](../engineering/gates.json)仍开放，`production_approved: false`，请勿用于高敏生产业务。
- **安装器与平台边界**：`tools/deploy/install.sh`、procd 模板和 `boreas-easy` 正在开发验证；工作流/源文件存在不能代替目标机验证或产品支持声明。OpenWrt 需单独审查其工具链、procd、Linux TUN、网络配置及架构兼容性，参阅 [ONE_CLICK.md](ONE_CLICK.md)。

---

## `boreas-easy` 行式控制台

`boreas-easy` 是同一 CLI 二进制的行式控制台入口，不是图形界面或 curses TUI。交互终端下会按行显示状态与操作提示；非 TTY（管道、脚本）下输出一次 JSON 并退出，不会等待交互输入。当前行式 UI 含状态、service status/start/stop 等动作入口，但不代表所有服务管理后端或跨平台动作均已验收；采取操作前应阅读本机确认提示并核实配置。

```sh
# 交互模式（若安装了 boreas-easy 入口）
boreas-easy
# 或显式进入同一控制台
boreas console --config /etc/boreas/edge.toml --socket /var/lib/boreas/control.sock

# 一次性机器可读状态；适用于非 TTY
boreas-easy --json
boreas console --json --socket /var/lib/boreas/control.sock
```

默认控制 socket 在 CLI 通用入口中为 `/run/boreas/control.sock`，而守护进程可按配置放在 `state_dir/control.sock`；请以实际 socket 路径为准。通过 `--socket`、`--config` 显式指定可避免默认路径与本文示例不一致。可用 `--lang zh-CN|zh-TW|en` 切换语言；窄终端可试 `--narrow`。若显示离线状态，先检查 daemon、socket 文件、属主/权限以及当前用户 UID；控制台错误不会被自动伪装成“无守护进程”。不要因 UI 可启动就推断生产控制面审计或完整授权已通过。

---

## 0. 准备条件与角色规划

### 软硬件与网络要求

1. **两台 Linux 服务器**：
   - `x86_64` 主机可直接使用 `v0.1.0-pre.3` 官方预编译全静态二进制 `boreas-linux-x86_64-musl-pq768`（零 `glibc` / 系统 `OpenSSL` 依赖）。
   - `aarch64`（ARM64）主机目前需按 [`.github/workflows/rust-tls.yml`](../../.github/workflows/rust-tls.yml) 静态编译 OpenSSL 3.6.5 后通过 `cargo build --release -p boreas-cli --features openssl-inner-tls` 构建。
2. **权限与内核模块**：运行守护进程与配置路由需要 `root`（或 `CAP_NET_ADMIN`）权限，且 `/dev/net/tun` 字符设备可用（若不存在，执行 `sudo modprobe tun`）。
3. **防火墙放行**：Core 服务器的云安全组与主机防火墙（`ufw` / `nftables` / `iptables`）放行入站 **TCP `8443`**（或 `443` 等自定义端口），**不需要放行任何 UDP 端口**。Edge 服务器无需公网入站端口。
4. **时钟同步**：PKI 证书与状态快照强校验 UTC 时间戳，确认离线签发机与两台服务器均已开启 NTP 同步（`timedatectl status`）。
5. **无需改动宿主机系统网络配置**：**宿主机无需关闭系统 IPv6，也无需停用 `systemd-resolved` 或 NetworkManager**。当内核向新建的 TUN 接口发送 IPv6 Router Solicitation、mDNS 等本地探测包时，Boreas 出站路径会自动丢弃非对端 VIP 的普通本地杂包，不会污染或断开加密电路。

### 本文统一示例参数（操作时请替换公网 IP）

| 节点角色 | 公网/监听地址 | 外层 TLS 域名标识（SAN） | `home_core_id` / `vip_octet` | `node_id` | 隧道永久 VIP |
|---|---|---|---|---|---|
| **Core（服务端）** | `203.0.113.10:8443` | `wss.example.net` | `1` / `1` | `1` | `10.20.1.1` |
| **Edge（客户端）** | 任意出网环境（NAT 后亦可） | 校验 `wss.example.net` | `1` / `2` | `2` | `10.20.1.2` |

> **说明**：永久槽位编码公式为 `node_id = ((home_core_id - 1) << 8) | vip_octet`，永久 VIP 固定映射为 `10.20.<home_core_id>.<vip_octet>`（Core 的 `vip_octet` 固定为 `1`，Edge 取值 `2..=251`）。在裸 IP 直连场景下，`wss.example.net` 仅作为外层 TLS 证书 SAN 与 HTTP `Host` 标识，**无需真实注册域名或配置公网 DNS 解析**。

---

## 第一步：下载并校验 `boreas` 静态二进制

在**离线签发管理机**（Linux `x86_64`）以及 **Core**、**Edge** 两台服务器上分别执行以下命令下载、校验并安装二进制：

```bash
VERSION="v0.1.0-pre.3"
BIN_NAME="boreas-linux-x86_64-musl-pq768"
BASE_URL="https://github.com/Lanlan13-14/Boreas/releases/download/${VERSION}"

# 1. 下载静态二进制与 v0.1.0-pre.3 完整校验和文件
curl -fLO "${BASE_URL}/${BIN_NAME}"
curl -fLO "${BASE_URL}/SHA256SUMS-PRE3"

# 2. 校验 SHA-256（预期输出：boreas-linux-x86_64-musl-pq768: OK）
grep "  ${BIN_NAME}$" SHA256SUMS-PRE3 | sha256sum -c -

# 3. 安装至 /usr/local/bin/boreas 并验证编译特性
sudo install -m 0755 "${BIN_NAME}" /usr/local/bin/boreas
boreas doctor
```

确认 `boreas doctor` 输出包含 `"status":"pre_release_pq768_e2e"`、`"daemon":true` 和 `"tls_backend":true`。

---

## 第二步：在离线/管理端完成完整 PKI 签发流程

Boreas 严禁首次连接盲信（No TOFU），所有信任锚与节点身份必须在管理端一次性签发并离线互验通过后再分发到服务器。请在一台安全的本地/离线 Linux 管理机上完整执行以下 5 个子步骤：

```bash
umask 077
mkdir -p ~/boreas-pki && cd ~/boreas-pki
```

### 2.1 初始化离线 CA 体系（`init-ca`）

生成 32 位十六进制（16 字节，非全零）网络创世标识 `NET_ID`，并初始化四权分离的离线 CA 目录 `./ca`（含 `NetworkRoot`、`IdentityAuthority`、`StatusSigner`、私有外层 TLS CA 与公开信任包 `roots.cbor`）：

```bash
# 生成随机 32 位小写 hex 作为全网唯一 net_id（请记录输出值，第三步写配置要用）
NET_ID="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
echo "NET_ID=${NET_ID}"

boreas pki init-ca \
  --ca-dir ./ca \
  --net-id "${NET_ID}" \
  --validity-days 30
```

- `--validity-days` 合法范围为 `1..=3650`（默认值为 `365`）。短期测试可设 `30`；若希望长期联调免重签根锚，建议设为 `365`。

### 2.2 分别签发 Core 与 Edge 节点材料包（`issue-node`）

```bash
# 1) 签发 Core 节点（role=core, home_core=1, vip_octet=1 -> VIP 10.20.1.1, node_id=1）
#    必须传 --outer-san 生成外层 WSS TLS 服务端证书 outer.pem 与私钥 outer.key
boreas pki issue-node \
  --ca-dir ./ca \
  --out-dir ./core \
  --role core \
  --home-core 1 \
  --vip-octet 1 \
  --validity-hours 720 \
  --outer-san wss.example.net

# 2) 签发 Edge 节点（role=edge, home_core=1, vip_octet=2 -> VIP 10.20.1.2, node_id=2）
boreas pki issue-node \
  --ca-dir ./ca \
  --out-dir ./edge \
  --role edge \
  --home-core 1 \
  --vip-octet 2 \
  --validity-hours 720
```

- **`--validity-hours` 默认值与建议值**：默认值为 **`720`（即 30 天，`24 * 30` 小时）**，合法范围为 `1..=87600`。短期演练建议设 `168`（7 天）至 `720`（30 天）；长期测试建议将上一步 CA `--validity-days` 设为 `365`，节点 `--validity-hours` 设为 `720`（按月轮换）或 `2160`（90 天）。

### 2.3 签发 24 小时状态快照（`sign-status`）并分发到两端目录

`issue-node` 默认附带的初始 `status.signed` 有效期仅 **1 小时（`3600` 秒）**。为避免部署耗时超过 1 小时即触发过期拒连，显式签发一份最长有效期（`86400` 秒 = 24 小时）的状态快照并覆盖至两端目录：

```bash
boreas pki sign-status \
  --ca-dir ./ca \
  --out ./status.signed \
  --sequence 1 \
  --ttl-seconds 86400

cp ./status.signed ./core/status.signed
cp ./status.signed ./edge/status.signed
```

### 2.4 【关键步骤】交叉复制对端身份（`local.signed` <-> `peer.signed`）

> **关键步骤（漏做必报错）**：
> 点对点 `daemon` 启动时强制校验对端公开身份文件 `peer.signed`。必须将 `core/local.signed` 复制为 `edge/peer.signed`，并将 `edge/local.signed` 复制为 `core/peer.signed`。
> **若漏掉这一步，`boreas daemon` 启动会直接报错退出：`daemon trust/roots verification failed: provisioning I/O failed: filesystem I/O`！**
> 注意：仅交叉复制公开签名对象 `local.signed`，**严禁**将任一节点的 `identity.key` 或 `outer.key` 私钥复制到另一台机器。

```bash
cp ./core/local.signed ./edge/peer.signed
cp ./edge/local.signed ./core/peer.signed
```

### 2.5 离线验包（`verify-bundle`）并安全处置 `ca/` 私钥目录

在上传前，用 `verify-bundle` 对两个目录做全链路离线验签：

```bash
boreas pki verify-bundle --material-dir ./core --require-peer
boreas pki verify-bundle --material-dir ./edge --require-peer
```

两条命令均必须返回 `"status":"ok"`（Core 显示 `"local_node_id":1,"peer_node_id":2`，Edge 显示 `"local_node_id":2,"peer_node_id":1`）。

校验通过后，将 `./core` 与 `./edge` 分别安全传输至两台服务器的 `/etc/boreas/material`：

```bash
# 传至 Core 服务器（替换 root@203.0.113.10）
ssh root@203.0.113.10 'umask 077 && mkdir -p /etc/boreas/material /var/lib/boreas'
scp -p ./core/* root@203.0.113.10:/etc/boreas/material/

# 传至 Edge 服务器（替换 root@<EDGE_HOST>）
ssh root@<EDGE_HOST> 'umask 077 && mkdir -p /etc/boreas/material /var/lib/boreas'
scp -p ./edge/* root@<EDGE_HOST>:/etc/boreas/material/
```

> **安全红线**：`./ca` 目录内含全网最高权限的 `NetworkRoot`、`IdentityAuthority` 与 `StatusSigner` 私钥，**绝不允许上传到任何公网服务器**！分发完成后：
> - 若后续需要每日续签 `status.signed` 或增发节点，请立即将 `./ca` 移入离线加密存储介质并清空管理机临时目录；
> - 若仅为一次性短时演练且无需续期，可直接安全销毁（`rm -rf ./ca`）。

---

## 第三步：编写 Core 与 Edge 的 `config.toml`

Boreas 强制使用显式 `version = 2` TOML 格式，且**配置文件权限必须严格为 `0600`**（目录 `0700`，属主为运行进程的用户或 `root`），否则会被配置解析器直接拒绝。

请确保以下字段与第二步签发的材料包严格一致：
- `[node].net_id`：必须等于 `init-ca` 输出的 32 位十六进制 `NET_ID`。
- `[node].role` / `home_core_id` / `vip_octet` / `node_id` / `identity_generation`：必须与该节点 `local.signed` 完全一致。
- `[paths].identity_key` / `roots` / `state_dir`：必须全部使用**绝对路径**，且与材料包实际存放路径一致。

### 3.1 Core 服务器配置：`/etc/boreas/core.toml`

在 **Core 服务器**上以 `root` 执行（将 `<替换为你的32位NET_ID>` 替换为第二步生成的实际值）：

```bash
umask 077
mkdir -p /etc/boreas /var/lib/boreas
chmod 0700 /etc/boreas /etc/boreas/material /var/lib/boreas

cat > /etc/boreas/core.toml <<'EOF'
version = 2

[node]
net_id = "<替换为你的32位NET_ID>"
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
# v2 静态 schema 要求提供合法 host:port 格式；Core 实际监听地址由 daemon serve --listen 指定
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
EOF

chmod 0600 /etc/boreas/core.toml /etc/boreas/material/*.key
boreas config-check /etc/boreas/core.toml
```

### 3.2 Edge 服务器配置：`/etc/boreas/edge.toml`

在 **Edge 服务器**上以 `root` 执行（同样填入相同的 `<替换为你的32位NET_ID>`，注意 Edge 不可将 `allow_edges` 设为 `true`）：

```bash
umask 077
mkdir -p /etc/boreas /var/lib/boreas
chmod 0700 /etc/boreas /etc/boreas/material /var/lib/boreas

cat > /etc/boreas/edge.toml <<'EOF'
version = 2

[node]
net_id = "<替换为你的32位NET_ID>"
role = "edge"
home_core_id = 1
vip_octet = 2
node_id = 2
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
allow_edges = false
default_route = false
EOF

chmod 0600 /etc/boreas/edge.toml /etc/boreas/material/*.key
boreas config-check /etc/boreas/edge.toml
```

确认两台机器的 `boreas config-check` 均输出 `"valid":true` 且退出码为 `0`。

---

## 第四步：启动 Core 并配置 TUN IP 与对端路由

在 **Core 服务器**上启动 `boreas daemon serve` 监听 TCP `8443` 并创建 `btun0` 网卡，随后为其分配永久 VIP `10.20.1.1/32` 及指向 Edge VIP `10.20.1.2` 的主机路由：

```bash
sudo boreas daemon serve \
  --config /etc/boreas/core.toml \
  --material-dir /etc/boreas/material \
  --listen 0.0.0.0:8443 \
  --tun-name btun0 \
  --mtu 1360 &

# 等待 btun0 网卡就绪后绑定永久 VIP 与对端路由
for _ in $(seq 1 50); do ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done
sudo ip addr replace 10.20.1.1/32 dev btun0
sudo ip link set btun0 up
sudo ip route replace 10.20.1.2 dev btun0
```

> **提示**：`daemon serve` 启动后默认等待首个入站连接的超时窗口为 30 秒，请紧接着在 Edge 服务器执行第五步发起连接（正式常驻请使用第六步的 `systemd` 单元自动托管与重拉起）。

---

## 第五步：启动 Edge 并配置 TUN IP 与对端路由

> **重要提醒（用裸 IP 覆盖 `--connect` 时必看）**：
> 当通过公网裸 IP 指定 `--connect 203.0.113.10:8443` 时，**必须显式传入 `--tls-name wss.example.net`**（与第二步签发 Core 时传入的 `--outer-san` 完全一致），并建议同时传入 `--ws-host wss.example.net:8443`！
> 如果漏传 `--tls-name`，Edge 会默认拿 `--connect` 里的裸 IP 字符串（`203.0.113.10`）去做外层 TLS 1.3 SNI 与主机名校验，因与 Core `outer.pem` 的 DNS SAN 不匹配而直接握手失败——表现为 Edge 报错 **`outer handshake`**、Core 报错 **`outer accept`**。

在 **Edge 服务器**上执行（将 `203.0.113.10:8443` 替换为 Core 的真实公网 IP 与端口）：

```bash
sudo boreas daemon connect \
  --config /etc/boreas/edge.toml \
  --material-dir /etc/boreas/material \
  --connect 203.0.113.10:8443 \
  --tls-name wss.example.net \
  --ws-host wss.example.net:8443 \
  --tun-name btun0 \
  --mtu 1360 &

# 等待 btun0 网卡就绪后绑定永久 VIP 与对端路由
for _ in $(seq 1 50); do ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done
sudo ip addr replace 10.20.1.2/32 dev btun0
sudo ip link set btun0 up
sudo ip route replace 10.20.1.1 dev btun0
```

---

## 第六步：验证连通性、systemd 托管与排错速查

### 6.1 状态检查与连通性测试

1. **检查守护进程实时控制状态（`boreas ctl status` / `boreas status`）**：
   守护进程在 `paths.state_dir`（此处为 `/var/lib/boreas/control.sock`）提供同 UID 校验的实时状态套接字。以与守护进程相同的 `root` 身份查询：
   ```bash
   # 输出实时 JSON（包含连接状态、状态快照序号及 tx/rx 包与字节计数）
   sudo boreas ctl status --config /etc/boreas/edge.toml
   # 或直接指定 socket 路径：
   sudo boreas ctl status --socket /var/lib/boreas/control.sock

   # 渲染终端可视化状态面板
   sudo boreas status --socket /var/lib/boreas/control.sock
   ```
   确认返回 JSON 中 `"daemon_connected":true`、`"security_mode":"e2e-required"`、`"status_fresh":true`。

2. **ICMP `ping` 连通性验证**：
   在 Edge 上通过隧道 `ping` Core 的永久 VIP：
   ```bash
   ping -c 4 -I 10.20.1.2 10.20.1.1
   ```
   确认 `0% packet loss`，再次执行 `sudo boreas ctl status --config /etc/boreas/edge.toml` 可见 `tx_packets` 与 `rx_packets` 同步增长。

3. **`iperf3` 吞吐测试**：
   ```bash
   # 在 Core 服务器上绑定隧道 VIP 启动服务端
   iperf3 -s -B 10.20.1.1

   # 在 Edge 服务器上向 Core VIP 发起测试
   iperf3 -c 10.20.1.1 -B 10.20.1.2 -t 10
   ```
   性能结果请按本文开头给出的精确提交及隔离 netns/veth 环境解读；它不是这两台公网服务器之间的预期值或 SLA。实际吞吐会受公网路径、主机 CPU、虚拟化与防火墙影响。

### 6.2 `systemd` 守护进程托管示例与状态续签

手工验证无误后，先结束后台测试进程（`sudo pkill -f "boreas daemon"`），再配置 `systemd` 托管以实现开机自启、断线自动重连以及 `btun0` 路由自动挂载。

#### Core 节点：`/etc/systemd/system/boreas-core.service`

```ini
[Unit]
Description=Boreas Core pq768 E2E Tunnel Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
ExecStart=/usr/local/bin/boreas daemon serve \
  --config /etc/boreas/core.toml \
  --material-dir /etc/boreas/material \
  --listen 0.0.0.0:8443 \
  --tun-name btun0 \
  --mtu 1360
ExecStartPost=/bin/sh -ceu 'for _ in $(seq 1 50); do ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done; ip addr replace 10.20.1.1/32 dev btun0; ip link set btun0 up; ip route replace 10.20.1.2 dev btun0'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

#### Edge 节点：`/etc/systemd/system/boreas-edge.service`

```ini
[Unit]
Description=Boreas Edge pq768 E2E Tunnel Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
ExecStart=/usr/local/bin/boreas daemon connect \
  --config /etc/boreas/edge.toml \
  --material-dir /etc/boreas/material \
  --connect 203.0.113.10:8443 \
  --tls-name wss.example.net \
  --ws-host wss.example.net:8443 \
  --tun-name btun0 \
  --mtu 1360
ExecStartPost=/bin/sh -ceu 'for _ in $(seq 1 50); do ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done; ip addr replace 10.20.1.2/32 dev btun0; ip link set btun0 up; ip route replace 10.20.1.1 dev btun0'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

启用并查看日志：

```bash
# Core 上执行：
sudo systemctl daemon-reload && sudo systemctl enable --now boreas-core
sudo journalctl -u boreas-core -f

# Edge 上执行：
sudo systemctl daemon-reload && sudo systemctl enable --now boreas-edge
sudo journalctl -u boreas-edge -f
```

#### 日常运维：`status.signed` 24 小时到期前刷新（热加载）

安全策略强制 `status.signed` 的最大 TTL 不超过 **24 小时（`86400` 秒）**；一旦超时未更新，守护进程会立即关闭电路停止业务转发（fail-closed）。请在到期前于离线管理机使用**原 `./ca` 目录**递增 `--sequence` 签发新快照并覆盖上传（运行中的守护进程每 500 ms 检查一次，自动热加载更高 `sequence` 的快照，无需重启服务）：

```bash
# 每次续签必须严格递增 --sequence（如 2, 3, 4...），否则触发回滚保护拒收
boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 2 --ttl-seconds 86400
scp ./status.signed root@203.0.113.10:/etc/boreas/material/status.signed
scp ./status.signed root@<EDGE_HOST>:/etc/boreas/material/status.signed
```

### 6.3 常见报错排查速查表

| 报错现象（stderr 关键字） | 真实根因 | 解决方法 |
|---|---|---|
| `management verification failed: Expired` 或 `StatusSnapshot is not fresh at current UTC` | 1. 未执行 `sign-status` 覆盖，沿用了 `issue-node` 默认仅 **1 小时**有效期的初始 `status.signed`；<br>2. 运行超过 24 小时未刷新 `status.signed`；<br>3. 服务器系统 UTC 时钟漂移，或节点证书（`--validity-hours`）已到期。 | 1. 校对两端 NTP/UTC 时钟（`timedatectl`）；<br>2. 在管理端用原 `./ca` 执行 `boreas pki sign-status --ca-dir ./ca --out status.signed --sequence <递增序号> --ttl-seconds 86400` 并覆盖到两端 `/etc/boreas/material/status.signed`；<br>3. 若节点证书过期，重新签发节点包。 |
| `management verification failed: InvalidEd25519Signature`（或 `WrongNetwork`） | 混用了不同批次 `pki init-ca` 产出的文件。每次 `init-ca` 都会随机生成全新的根密钥与签名者密钥（即便指定相同的 `--net-id` 也不兼容）。 | 确保 `roots.cbor`、`local.signed`、`peer.signed`、`status.signed` 全部由**同一个 `./ca` 目录**签发；若原 `./ca` 已丢失，需整套重新 `init-ca` 并重签双端。 |
| `provisioning I/O failed: filesystem I/O` | `material-dir` 或 `[paths].roots` 下缺少必需文件或无读取权限。**90% 的情况是漏掉了第 2.4 步交叉复制 `peer.signed`**，或漏传了 `roots.cbor` / `status.signed`。 | 检查两端 `/etc/boreas/material/` 是否同时包含 `local.signed`、`peer.signed`、`status.signed`、`roots.cbor`、`identity.key`、`identity.pem`、`identity-ca.pem`，运行 `boreas pki verify-bundle --material-dir /etc/boreas/material --require-peer` 自检。 |
| Edge 报 `inner TLS failed: outer handshake`（或 `outer handshake reset`）<br>Core 报 `inner TLS failed: outer accept`（或 `outer accept reset`） | 1. **最常见**：Edge 用裸 IP 指定 `--connect` 时**漏传 `--tls-name`**，或 `--tls-name` 与 Core 签发时的 `--outer-san` 域名不一致，外层 TLS 1.3 主机名校验失败；<br>2. Edge 目录缺失同源 CA 生成的 `outer-ca.pem`；<br>3. 端口连错或中间防火墙/反代拦截了 TLS/WebSocket 升级。 | 1. 裸 IP 直连时 Edge 必须显式传 `--tls-name <与--outer-san一致的域名>` 和 `--ws-host <域名:端口>`；<br>2. 确认 Core 签发时带了 `--outer-san`（目录内有 `outer.pem`/`outer.key`）且 Edge 目录保留了对应的 `outer-ca.pem`。 |
| `daemon serve: outer.pem/outer.key setup failed` | 签发 Core 节点时漏传了 `--outer-san <DNS>` 参数，导致未生成外层服务端证书与私钥。 | 重新为 Core 执行 `boreas pki issue-node ... --role core --outer-san wss.example.net` 并重新交叉更新对端 `peer.signed`。 |
| `configuration rejected: ... group- or world-accessible` | `config.toml` 文件权限过宽（如 `0644`），触发 `0600` 安全门禁拒绝读取。 | 执行 `sudo chmod 0600 /etc/boreas/*.toml` 并确认父目录权限为 `0700`、属主为 `root` 或运行用户。 |
| `Linux TUN creation failed (need CAP_NET_ADMIN / /dev/net/tun)` | 非 `root` 运行且无 `CAP_NET_ADMIN` 能力，或宿主机/容器未开启 `/dev/net/tun` 设备。 | 使用 `sudo` / `root` 运行，执行 `sudo modprobe tun` 并检查 `ls -l /dev/net/tun`（容器环境需加 `--cap-add=NET_ADMIN --device /dev/net/tun`）。 |
| `daemon serve: timed out waiting for peer connection` | Core 启动后在默认连接等待窗口（30 秒）内未收到任何入站连接而正常退出。 | 手工调试时先起 Core 后立即起 Edge；长期运行请使用 6.2 节的 `systemd` 配置（`Restart=always`）自动持续监听。 |
| `control socket owner UID mismatch` 或 `cannot connect to control socket` | 运行 `boreas ctl status` 的用户 UID 与运行 `daemon` 的用户不一致（如未加 `sudo`），或守护进程未运行/未指定正确的 `--socket`。 | 以相同用户执行：`sudo boreas ctl status --config /etc/boreas/edge.toml`。 |
| `require a binary built with --features openssl-inner-tls` | 误下载了不含 TLS 后端的基础 CLI 包（约 510 KB 的 `.tar.gz`）。 | 重新下载约 9.8 MB 的 `boreas-linux-x86_64-musl-pq768` 并替换 `/usr/local/bin/boreas`。 |

---

## 附录：单机双 `netns` 本地演练（无需两台公网服务器）

如果你手头只有一台 Linux `x86_64` 主机（或虚拟机），可以使用 Linux 网络命名空间（`ip netns`）在同一台机器上隔离模拟 Core 与 Edge 双节点全流程。

### 方式一：运行仓库内置一键冒烟脚本

若已克隆本仓库且已安装 `/usr/local/bin/boreas`（`pq768` 版本），直接运行：

```bash
sudo bash tools/release/netns_daemon_smoke.sh /usr/local/bin/boreas
```

看到末尾输出 `REAL NETNS PQ768 E2E OVERLAY PING SUCCEEDED` 即代表离线 PKI、双层 `pq768` mTLS、真实 `/dev/net/tun` 与 ICMP 0% 丢包转发全部通过。

### 方式二：手工分步双 `netns` 演练

如果你未克隆仓库、手上只有单个 `boreas` 二进制，可将以下内容保存为 `/tmp/boreas-netns-demo.sh` 并以 `sudo bash /tmp/boreas-netns-demo.sh` 运行（在单机上创建 `boreas-core-ns` `192.0.2.1` 与 `boreas-edge-ns` `192.0.2.2` 两个隔离命名空间并完成跨隧道 `ping` 验证）：

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

WORK="$(mktemp -d /tmp/boreas-demo.XXXXXX)"
cleanup() {
  set +e
  if [ -f "$WORK/core.pid" ]; then kill "$(cat "$WORK/core.pid")" 2>/dev/null || true; fi
  if [ -f "$WORK/edge.pid" ]; then kill "$(cat "$WORK/edge.pid")" 2>/dev/null || true; fi
  ip netns del boreas-core-ns 2>/dev/null || true
  ip netns del boreas-edge-ns 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 1. 离线 PKI 签发、状态快照签发与交叉复制 peer.signed
NET_ID="0123456789abcdef0123456789abcdef"
boreas pki init-ca --ca-dir "$WORK/ca" --net-id "$NET_ID" --validity-days 30
boreas pki issue-node --ca-dir "$WORK/ca" --out-dir "$WORK/core" --role core --home-core 1 --vip-octet 1 --outer-san wss.boreas.test
boreas pki issue-node --ca-dir "$WORK/ca" --out-dir "$WORK/edge" --role edge --home-core 1 --vip-octet 2
boreas pki sign-status --ca-dir "$WORK/ca" --out "$WORK/status.signed" --sequence 1 --ttl-seconds 86400
cp "$WORK/status.signed" "$WORK/core/status.signed"
cp "$WORK/status.signed" "$WORK/edge/status.signed"
cp "$WORK/core/local.signed" "$WORK/edge/peer.signed"
cp "$WORK/edge/local.signed" "$WORK/core/peer.signed"
boreas pki verify-bundle --material-dir "$WORK/core" --require-peer
boreas pki verify-bundle --material-dir "$WORK/edge" --require-peer

# 2. 生成 Core 与 Edge 的 v2 配置文件（0600）
mkdir -p "$WORK/core-state" "$WORK/edge-state"
cat > "$WORK/core.toml" <<EOF
version = 2
[node]
net_id = "$NET_ID"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "$WORK/core/identity.key"
roots = ["$WORK/core/roots.cbor"]
state_dir = "$WORK/core-state"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
EOF

cat > "$WORK/edge.toml" <<EOF
version = 2
[node]
net_id = "$NET_ID"
role = "edge"
home_core_id = 1
vip_octet = 2
node_id = 2
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "$WORK/edge/identity.key"
roots = ["$WORK/edge/roots.cbor"]
state_dir = "$WORK/edge-state"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
EOF
chmod 0600 "$WORK/core.toml" "$WORK/edge.toml"

# 3. 创建双 netns 与模拟公网的 veth 链路（192.0.2.1 <-> 192.0.2.2）
ip netns add boreas-core-ns
ip netns add boreas-edge-ns
ip link add veth-core type veth peer name veth-edge
ip link set veth-core netns boreas-core-ns
ip link set veth-edge netns boreas-edge-ns
ip netns exec boreas-core-ns ip link set lo up
ip netns exec boreas-core-ns ip addr add 192.0.2.1/24 dev veth-core
ip netns exec boreas-core-ns ip link set veth-core up
ip netns exec boreas-edge-ns ip link set lo up
ip netns exec boreas-edge-ns ip addr add 192.0.2.2/24 dev veth-edge
ip netns exec boreas-edge-ns ip link set veth-edge up

# 4. 在各自 netns 内重挂私有 sysfs（供 TUN 设置 MTU）并启动 Core 与 Edge
run_in_ns() {
  local ns="$1"; shift
  ip netns exec "$ns" unshare --mount --propagation private \
    sh -ceu 'mount --make-rprivate /; umount -l /sys; mount -t sysfs sysfs /sys; exec "$@"' _ "$@"
}

run_in_ns boreas-core-ns boreas daemon serve \
  --config "$WORK/core.toml" --material-dir "$WORK/core" \
  --listen 192.0.2.1:8443 --tun-name btun0 --mtu 1360 &
echo $! > "$WORK/core.pid"

for _ in $(seq 1 50); do ip netns exec boreas-core-ns ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec boreas-core-ns ip addr add 10.20.1.1/32 dev btun0
ip netns exec boreas-core-ns ip link set btun0 up
ip netns exec boreas-core-ns ip route add 10.20.1.2 dev btun0

run_in_ns boreas-edge-ns boreas daemon connect \
  --config "$WORK/edge.toml" --material-dir "$WORK/edge" \
  --connect 192.0.2.1:8443 --tls-name wss.boreas.test --ws-host wss.boreas.test:8443 \
  --tun-name btun0 --mtu 1360 &
echo $! > "$WORK/edge.pid"

for _ in $(seq 1 50); do ip netns exec boreas-edge-ns ip link show btun0 >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec boreas-edge-ns ip addr add 10.20.1.2/32 dev btun0
ip netns exec boreas-edge-ns ip link set btun0 up
ip netns exec boreas-edge-ns ip route add 10.20.1.1 dev btun0

# 5. 等待握手就绪，验证跨隧道 ping 与实时包计数
for _ in $(seq 1 100); do
  boreas ctl status --socket "$WORK/edge-state/control.sock" 2>/dev/null | grep -q '"daemon_connected":true' && break
  sleep 0.05
done
ip netns exec boreas-edge-ns ping -c 3 -I 10.20.1.2 10.20.1.1
boreas ctl status --socket "$WORK/core-state/control.sock"
boreas ctl status --socket "$WORK/edge-state/control.sock"
```

