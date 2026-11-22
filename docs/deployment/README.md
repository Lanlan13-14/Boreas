# Boreas 部署教程：从材料准备到双机互通

本页带你搭一条只连接两个 IPv4 VIP 的 Linux 隧道。建议在两台可回收的主机上演练，保留 SSH 和云控制台等旁路管理入口。完成标志不是“服务显示运行中”，而是**两端的隧道路由正确、双向 `ping` 成功、收发计数增长**。

| 你手中的制品 | 使用哪一节 |
| --- | --- |
| 可信的当前开发构建（Linux、`openssl-inner-tls`） | 按本页走完 [准备 → 签发 → 配置 → 安装 → 互通](#workflow)。开发版 `daemon` 要求显式策略、网络根 pin 和持久水位，不能照搬公开包的命令。 |
| 公开发布的 `v0.1.0-pre.3` x86-64 pq768 二进制 | 看 [公开预发布双机演练](#public-pre3)。不使用当前 `install.sh` 的服务包装器或离线双签服务。 |
| 已独立预配软件发布根和双签候选 | 共用下面的签发、配置思路，安装接到 [离线签名 systemd 服务](VERIFIED-SERVICE.md)，与旧 root 模板二选一。 |
| 要连通多个 Core | 转到 [四 Core 拓扑教程](linux-core-mesh-topology.md)；它有独立的 CLI、清单、材料名及 TUN 所有权。 |

<a id="workflow"></a>

## 1. 准备环境与地址

- **离线签发机**：使用预先验证可信、支持 pq768 PKI 的 Boreas；保持工作目录私有，并确保系统时钟准确。下载或转运制品与托管私钥应分开，不在离线签发机联网拉取未知程序。
- **两台 Linux 节点**：使用同一源码修订的制品，核对 CPU 架构。开发制品需与所用 `tools/deploy/` 来自兼容修订；可以从[构建工作流](../../.github/workflows/rust-tls.yml)的对应运行取得候选，不假定有新的公开版本。若自行替换 OpenSSL 或 provider，不能沿用原有验收结论。
- **底层网络**：Core 接受 Edge 来源的 TCP `8443`（同时检查云安全组与主机防火墙）；Edge 能主动拨出即可，不要求为本例开 UDP。本文走直连 WSS，不配置 CDN/反代。选用未占用的端口和 TUN 名，避开宿主已有路由、管理网和业务网。
- **系统工具**：完整 `iproute2`、`ss`、`ping`；安装器还需 `readelf`、SHA-256 等工具。systemd 仅用于选用对应服务路径的主机。本例不修改全局 IPv6、DNS 或默认路由。

| 项目 | Core | Edge |
| --- | --- | --- |
| 底层地址 | `0.0.0.0:8443` 监听；示例可达地址 `203.0.113.10:8443` | 拨 Core 的真实可达地址，允许位于 NAT 后 |
| 外层 TLS 名称 | `wss.example.net`（证书 DNS SAN） | 校验 `wss.example.net`；HTTP Host 可带 `:8443` |
| `[node]` 槽位 | `home_core_id=1`、`vip_octet=1`、`node_id=1` | `home_core_id=1`、`vip_octet=2`、`node_id=2` |
| 隧道参数 | `btun0`、MTU 1360、`10.20.1.1/32` | `btun0`、MTU 1360、`10.20.1.2/32` |

`203.0.113.10` 是文档保留地址，必须替换；裸 IP 拨号时，示例 DNS 名仅用作证书校验和 HTTP Host，不必让它公开解析。永久 VIP 是 `10.20.<home_core_id>.<vip_octet>`，节点 ID 是 `((home_core_id - 1) << 8) | vip_octet`；写配置时以签发材料为准，而不是自行挑选 VIP。

两台节点先做只读检查：

```sh
uname -m
ls -l /dev/net/tun
ip -4 addr show
ip -4 route show
ip -4 route get 203.0.113.10
ss -ltn
```

最后两个检查分别用来核实底层路由和监听端口（在 Edge 上替换为 Core 实际地址；Core 上也检查自己的管理路由）。缺少 `/dev/net/tun` 时，先由管理员确认内核、设备透传和权限；支持模块加载的 Linux 可用 `sudo modprobe tun`。容器有 UID 0 不代表有 TUN 或网管能力。systemd 主机可用 `timedatectl status` 检查时间同步；离线机也要核对 UTC。

## 2. 离线签发（只在签发机执行）

在新建的私有工作目录操作。先 `boreas doctor` 检查实际构建，再签发；基础 CLI 归档不能代替启用了 OpenSSL 后端的二进制。下方 `NET_ID` 后续还要写入两台节点的配置和安装参数，可记录它，但私钥不得随之转运。

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

验包应报告 `status: ok`；Core 的本地/对端 ID 为 `1/2`，Edge 为 `2/1`。`issue-node` 自带的初始快照只有约一小时，另签的示例快照有效期为 24 小时。`peer.signed` 是**公开签名身份**，不是对端的证书私钥。每台机器只收自己的节点包，`identity.key`/`outer.key` 不互换。**整个 `ca/` 留在离线保管区**，其中含 NetworkRoot、IdentityAuthority、StatusSigner 及外层 TLS CA 私钥。

### 当前开发构建：额外签发网络策略

**公开 pre.3 演练跳过此小节**，其余签发步骤不变。对开发构建，策略与节点必须使用同一 `net_id`。以下命令签发当前 CLI 提供的 `10.20.0.0` 基址策略，然后把三个签名输入与两个公钥 pin 分开放：

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

由掌管 NetworkRoot 的人员通过独立可信途径预配这两个公开 pin；不能用待验证制品自带的根作信任锚。以下预检用**已信任**的 verifier CLI 和已核对的 pin，只验对象，不记录水位：

```sh
boreas pki verify-policy --net-id "$NET_ID" \
  --tbs-file ./policy/policy.tbs \
  --ed25519-signature-file ./policy/policy.ed25519.sig \
  --mldsa65-signature-file ./policy/policy.mldsa65.sig \
  --root-ed25519-der ./pins/root.ed25519.der \
  --root-mldsa65-der ./pins/root.mldsa65.der
```

将各自的节点材料包、策略三文件和已预配的 pin 分发到私有 staging；请核对 SSH 主机密钥或使用经批准的安全转运。不要上传 CA 目录，也不要混入备份和临时文件。两份节点包各存一份受保护的离线副本，记录初次签发的序号和失效时间。

## 3. 配置两个节点

下面是**完整的 Core TOML**。在每台机器创建自己的 `node.toml`（`0600`），把 `REPLACE_WITH_NET_ID` 换成同一个实际值。示例 `[paths]` 适合下文的 pre.3 手工路径；开发安装器在安装时会重定位这三项，建议源配置仍指向私有 staging 中真实存在的文件和目录。离线双签 systemd 路径则使用其[固定目录布局](VERIFIED-SERVICE.md#首次安装管理员)，不经旧安装器重定位。

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

**Edge 从这份文件复制**：将 `role` 改为 `"edge"`，`vip_octet` 和 `node_id` 改为 `2`，`allow_edges` 改为 `false`；其余字段不变（如果两端实际路径不同，各填本机路径）。`identity_generation` 与 `issue-node --generation` 匹配。不要把 `paths = 4` 当成开启四条活动连接：这是 `[uplink]` 配置中的路径上限，不是本示例的实测电路数。

- `[node]` 对应已签发身份；改 TOML 不会改身份。Core 的 `allow_edges` 允许担任接入端，不会替代 `peer.signed` 的点对点授权。
- `[paths]` 用绝对路径。私钥只给运行 UID，状态目录必须持久、可由该 UID 写入。不要为两台节点或两个进程共用同一个运行状态目录。
- `[uplink]` 必需。我们用 `--listen` / `BOREAS_LISTEN` 设定监听、用 `--connect` / `BOREAS_CONNECT` 显式拨底层 IP；`--tls-name` / `BOREAS_TLS_NAME` 对照证书 SAN，`--ws-host` / `BOREAS_WS_HOST` 是 WebSocket 请求的 Host。不要把三者都填成隧道 VIP。

用已受信的对应构建执行 `boreas config-check /实际路径/node.toml`。它通过只表示静态检查成功；实际材料、策略、监听、对端及 TUN 要到运行时验证。

## 4. 安装并启动当前开发构建

跟随[一键安装操作单](ONE_CLICK.md)：在两台主机准备同布局的私有 staging，逐台比对可信摘要，先 `--dry-run`，再用 `--service systemd --accept-legacy-service` 安装。分别写入 Core/Edge 的 `boreas.env`，**先启动 Core，看到 TCP 监听后立刻启动 Edge**。旧模板使用 root，适用于隔离评估；不要与离线双签单元混装。安装成功且 `active` 已切换，不代表本机进程已在运行或隧道已经连通。若用 `--service none`，只完成安装，不启动 daemon。

每台机器看到的是自己的 `<prefix>/releases/<id>/config.toml` 与 `materials/`，两台可使用同一个 release id，但不能混用材料。旧 wrapper 自动添加各自 VIP 和对端 `/32`，检查冲突并在退出时清理自己的地址和路由。**不要在这一条路径上预建 `btun0`**；反过来，离线双签服务要求管理员预建持久 TUN。

## 5. 验收与日常维护

先从底层查到应用层。Core 的监听存在不是握手成功；`ss` 里出现 TCP 连接也不表示已建立认证电路。

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

旧安装器默认前缀下，用运行 daemon 的相同 UID（此处 root）查状态。离线双签服务改为 `sudo -u boreas` 与 `/var/lib/boreas/state/control.sock`，pre.3 改为 `/var/lib/boreas/control.sock`。没有现成 socket 时，先看日志，不要放宽权限。查看旧模板的控制台时服务名显式设为 `boreas`。

```sh
sudo boreas ctl status --socket /opt/boreas/state/control.sock
sudo boreas console --json --socket /opt/boreas/state/control.sock \
  --service boreas

# Edge：发送前后各看一次状态
ping -c 4 -I 10.20.1.2 10.20.1.1
# Core：反向验证
ping -c 4 -I 10.20.1.1 10.20.1.2
```

预期：对端 `/32` 路由选中 `btun0`；`daemon_connected:true`、`security_mode:"e2e-required"`、`status_fresh:true`；双向 `ping` 成功，两侧 `tx_packets` 和 `rx_packets` 增长。若要再验证 TCP，可在 Core 用 `iperf3 -s -B 10.20.1.1`，Edge 用 `iperf3 -c 10.20.1.1 -B 10.20.1.2 -t 10`；故障排除后再做压测，隔离测试结果不是公网 SLA。

### 续签、重启和停用

- **状态快照**：过期前在离线签发机做新版本，例如 `boreas pki sign-status --ca-dir ./ca --out ./status-2.signed --sequence 2 --ttl-seconds 86400`（仅在当前序号确为 `1` 时用 `2`）。将同一份新快照分发到两端，在实际 daemon 材料目录内复制成临时文件，设正确属主/`0600`，同文件系统原子改名为 `status.signed`。daemon 会复核快照；如果已因过期停机，要先修复材料再启动。再次检查 `status_sequence`、`status_fresh` 及双向流量。同序号异内容或低序号不能当续签。
- **旧开发安装的发布目录**：续签在线 `status.signed` 是运行材料更新，不等于原安装 bundle 字节未变；不要继续用同 release id 重发已变的输入。新安装代际用新 id。策略或根变更应单独评估过期、根指纹与水位，按[策略及状态规则](POLICY-STATE.md)计划，而不是覆盖历史文件。软件回退不能让旧的、过期的或已撤销的授权重新生效。
- **停用**：旧 systemd 路径用 `sudo systemctl stop boreas.service`，如不再开机启动，再用 `sudo systemctl disable boreas.service`；确认 wrapper 所加 `/32` 和 TUN 已清理。手工前台路径在**对应终端**停止，不用全局 `pkill`。离线双签或 mesh 的持久 TUN 由管理员维护，停服务不等于删设备。保留状态与必要日志以便检查，不清空水位作为重试手段。

<a id="public-pre3"></a>

## 6. 公开预发布双机演练（仅 `v0.1.0-pre.3`）

这是独立的 **x86-64 Linux** 手工路径。若目标机器已有 Boreas 服务、TUN、路由或配置，请用另一台隔离主机，不覆盖现有安装。`.tar.gz` 基础归档与下面的 pq768 二进制不是一回事。

**下载端**在空目录取官方固定标签的两个文件，使用 `&&` 保证任一下载/校验失败就停止这一组操作：

```sh
BASE=https://github.com/Lanlan13-14/Boreas/releases/download/v0.1.0-pre.3
BIN=boreas-linux-x86_64-musl-pq768
curl -fLO "$BASE/$BIN" &&
  curl -fLO "$BASE/SHA256SUMS-PRE3" &&
  grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -
```

看到该二进制 `OK` 并退出 `0` 后，再独立核对来源/摘要。两个文件同源，这一步只检测下载完整性，不是发布双签；无法建立信任时不要以 root 执行。确认无命名冲突后，在两节点安装已验过的同一制品，离线机由可信转运取得签发工具：

```sh
sudo install -m 0755 "$BIN" /usr/local/bin/boreas
boreas doctor
```

预期该版本 `doctor` 包含 `daemon: true` 和 `tls_backend: true`。按第 2 节签发并验包，**跳过网络策略小节**。通过安全通道把各自的包送到各自的 `/etc/boreas/material`，按第 3 节写 `/etc/boreas/node.toml`；这里的 `[paths]` 保持示例布局。创建 root 所有的 `/etc/boreas`、`/etc/boreas/material` 和 `/var/lib/boreas` 私有目录（`0700`），配置和私钥用 `0600`，检查文件归属后运行 `sudo boreas config-check /etc/boreas/node.toml`。

先准备双方终端。Core 上执行前台命令，看到监听后请在首连等待窗口（30 秒）内启动 Edge；如果窗口已过，查看错误再重新启动 Core。

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

在各自第二个终端用 `ip link show dev btun0` 等到 daemon 创建 TUN，然后只在自己的主机执行对应三行。`add` 冲突时停下检查，不改成 `replace` 强行覆盖。

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

按第 5 节做双向验证，状态命令改用 `sudo boreas ctl status --socket /var/lib/boreas/control.sock`。停止时结束两边前台进程并确认本次 TUN/地址/路由已消失。这一节不把旧版手工命令写入当前服务模板；需要常驻时按目标开发构建选对应的服务路径。

<a id="troubleshooting"></a>

## 7. 按层排查：先找到第一处异常

| 现象 | 先检查 | 修复或下一步 |
| --- | --- | --- |
| `doctor` 没有 TLS/daemon，或缺少参数 | 实际调用的是哪个二进制；`uname -m`；公开 pre.3 与开发 CLI 是否混用 | 换成同架构、同修订的可信 pq768 构建。不要补造 release 标签、文件名或盲抄开发参数。 |
| 安装器拒绝摘要、ELF、路径或材料 | 摘要是否独立核对；静态 ELF/架构；输入和父目录属主、符号链接/硬链接、权限 | 在私有 staging 重新准备文件，勿绕过校验。相同 release id 下输入变动用新 id。 |
| `config-check` 拒绝、wrapper 退出 `78` | TOML 是否 `0600`、`version = 2`、绝对路径；`boreas.env` 是否正确；同名 TUN/VIP/对端 `/32` 是否已经存在 | 修正字段、路径或本机冲突；先看 `sudo journalctl -u boreas.service -n 100 --no-pager`，不要循环重启。 |
| Core 没监听，或 TCP 超时 | `sudo ss -ltnp 'sport = :8443'`；Core 绑定地址；云安全组和主机防火墙；Edge `ip -4 route get` 指向实际底层地址 | 修复监听或底层路由；从控制台恢复管理。不要把默认路由或公网底层地址指进 TUN。 |
| `outer handshake` / 外层证书错误 | `--tls-name`/SAN、证书链、有效期、Edge 的外层 CA；随后检查 `--ws-host` | 使用正确证书和信任链。SAN 不能用身份文件或任意 HTTP Host 代替；不要关闭校验。 |
| 内层认证或 PKI 失败 | `local.signed` 与配置的槽位/代次、`peer.signed` 是否真为对端、roots 与证书是否属同一网络 | 用离线可信 CLI 重跑 `pki verify-bundle --require-peer`，核对报告的本地/对端 ID。节点私钥不能从另一端复制。 |
| 状态过期、策略签名/回滚错误 | 两端 UTC 时间、签发序号、有效期、策略文件名、独立 pin 及实际 `state_dir` | 修复时钟或准备新签名输入；保留持久防回退状态。根指纹不匹配按审核过的迁移流程处理。 |
| socket 不存在或权限不符 | 进程是否已启动、运行 UID、`state_dir` 和实际 socket 名 | 以同 UID 查正确路径；不要 chmod 放开访问。mesh-run 没有此 socket。 |
| 已连接但 VIP 不通，或只通一边 | 两端 `ip -4 route get`、选定源 VIP、`btun0` 地址/MTU、宿主 ICMP 过滤，比较左右收发计数 | 只修授权对端 `/32`；源地址用 `ping -I <本端VIP>` 固定。底层可通不代表签名电路承载的 VIP 对正确。 |

求助时给出制品来源和准确提交/标签、架构、错误阶段、脱敏后的 `ctl status` 和短日志。不要分享私钥、TLS 密钥日志、SSH 凭据或整套配置环境。仓库另有[脱敏诊断采集器](../../tools/diagnostics/README.md)，它不读取 daemon 配置、密钥或日志。

## 8. 无公网机器时如何验证

仓库的 [TLS 工作流](../../.github/workflows/rust-tls.yml) 用 `tools/release/netns_daemon_smoke.sh` 在隔离 Linux runner 中验证开发构建的真实 TUN/数据面；这不是拿 pre.3 二进制运行的脚本。只在具备 `/dev/net/tun`、网络和挂载命名空间权限的可销毁 runner 上，按工作流同一提交、二进制和参数执行。旧安装器、离线双签服务与多 Core 有各自测试入口，分别见对应文档。记录准确 SHA 和实际通过的步骤，不能用普通 Rust 测试或被跳过的设备步骤代替真实包 I/O。
