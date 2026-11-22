# Boreas 部署教程：从材料准备到双机互通

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

按照本教程部署一条只连接两个 IPv4 VIP 的 Linux 点对点隧道。请在两台可回收的主机上演练，并全程保留 SSH 和云控制台等旁路管理入口。判定部署完成的唯一标准不是“服务显示运行中”，而是**两端隧道路由指向正确、双向 `ping` 成功、收发包计数持续增长**。

首先根据你手中的制品选择对应路径：

| 你手中的制品 | 选择路径与操作说明 |
| --- | --- |
| 可信的当前开发构建（Linux、`openssl-inner-tls`） | 按顺序完成本页 [准备 → 签发 → 配置 → 安装 → 互通](#workflow)。开发版 `daemon` 强制要求显式网络策略、网络根 pin 与持久防回退水位，不能照搬公开预发布包的命令。 |
| 公开发布的 `v0.1.0-pre.3` x86-64 pq768 二进制 | 直接跳至 [公开预发布双机演练](#public-pre3)。该版本不使用当前 `install.sh` 服务包装器或离线双签服务。 |
| 已独立预配软件发布根与双签候选包 | 共用第 2、3 节的签发与配置思路，安装与托管接入 [离线签名 systemd 服务](VERIFIED-SERVICE.md)，勿与旧 root 服务模板混用。 |
| 需要连通多个 Core 节点 | 转到 [四 Core 拓扑教程](linux-core-mesh-topology.md)；多 Core 组网使用独立的 CLI、拓扑清单、材料命名与 TUN 管理方式。 |

<a id="workflow"></a>

## 1. 准备环境与地址

动手前先核对环境、版本来源与网络边界，避免因架构、时间偏差或路由冲突导致后续失败：

- **离线签发机**：准备预先验证可信、支持 pq768 PKI 的 Boreas 二进制；将工作目录设为私有权限，并确保系统 UTC 时钟准确。务必将制品下载/转运与私钥保管隔离，不在离线签发机联网拉取未知程序。
- **两台 Linux 节点**：两台主机须运行同一源码修订构建的制品，并提前核对 CPU 架构。开发构建必须与所用 `tools/deploy/` 来自兼容的源码修订；可从[构建工作流](../../.github/workflows/rust-tls.yml)的对应运行获取候选制品，不要假定存在新的公开版本。如自行替换 OpenSSL 或 provider，原有验收结论不再适用。
- **底层网络**：Core 须对 Edge 放行入向 TCP `8443`（同时核查云安全组与主机防火墙）；Edge 只需能主动拨出即可，本例无需开放 UDP。链路走直连 WSS，不经过 CDN 或反向代理。端口与 TUN 网卡名须避开宿主机已有服务、管理网和业务网。
- **系统工具与默认边界**：两台主机须具备完整 `iproute2`、`ss`、`ping`；运行安装器还需 `readelf`、SHA-256 校验工具等。只有选用 systemd 服务路径时才依赖 systemd。默认部署不会改动宿主机全局 IPv6、系统 DNS 或默认路由，仅配置授权对端 IPv4 VIP 的 `/32` 路由，不启用任意 `/24` 路由、网段导出或转发。

下表定义本例的 Core 与 Edge 地址及隧道参数：

| 配置项 | Core | Edge |
| --- | --- | --- |
| 底层网络地址 | 监听 `0.0.0.0:8443`；示例公网可达地址 `203.0.113.10:8443` | 主动拨号至 Core 的真实可达地址，允许位于 NAT 后 |
| 外层 TLS 名称 | `wss.example.net`（写入证书 DNS SAN） | 校验 `wss.example.net`；HTTP `Host` 可带 `:8443` |
| `[node]` 槽位 | `home_core_id=1`、`vip_octet=1`、`node_id=1` | `home_core_id=1`、`vip_octet=2`、`node_id=2` |
| 隧道接口参数 | `btun0`、MTU 1360、`10.20.1.1/32` | `btun0`、MTU 1360、`10.20.1.2/32` |

注意：`203.0.113.10` 是文档保留地址，操作时必须替换为 Core 的真实可达 IP；直接用裸 IP 拨号时，示例域名 `wss.example.net` 仅用于外层证书 SAN 校验和 HTTP `Host` 请求头，无需配置公网 DNS 解析。永久 VIP 计算规则为 `10.20.<home_core_id>.<vip_octet>`，节点 ID 为 `((home_core_id - 1) << 8) | vip_octet`；编写配置时必须以签发出的材料为准，不要自行选定 VIP。

在两台节点先执行以下只读前置检查：

```sh
uname -m
ls -l /dev/net/tun
ip -4 addr show
ip -4 route show
ip -4 route get 203.0.113.10
ss -ltn
```

后两条命令分别用于核对底层出向路由和监听端口占用（在 Edge 上将目标地址替换为 Core 的真实底层 IP；在 Core 上也应检查自身管理连接路由，避免后续配置冲突）。若缺少 `/dev/net/tun`，由管理员排查内核支持、容器设备透传与权限；支持模块加载的 Linux 可执行 `sudo modprobe tun`。需注意，容器内拥有 UID 0 并不代表具备 TUN 设备或网络管理能力。使用 systemd 的主机可执行 `timedatectl status` 检查时钟同步状态；离线签发机也需确认 UTC 时间准确。

<a id="offline-issuance"></a>

## 2. 离线签发（只在签发机执行）

在签发机新建一个私有工作目录后开始签发。先执行 `boreas doctor` 核查实际使用的二进制构建（确认具备所需 TLS 后端等能力；基础 CLI 归档包不能替代启用了 OpenSSL 后端的二进制）。下述生成的 `NET_ID` 后续会写入两台节点的配置与安装参数，可记录并在安全范围内传递，但任何私钥严禁随其转运。

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

执行后，验包命令应返回 `status: ok`；Core 的本地/对端 ID 应报告为 `1/2`，Edge 为 `2/1`。`issue-node` 自带的初始状态快照有效期仅约 1 小时，命令中另行签发的示例快照有效期为 24 小时。`peer.signed` 是**公开签名身份文件**，不包含对端证书私钥。分发时每台主机只能收到自己的节点包，`identity.key` 与 `outer.key` 绝对不可互换。**整个 `ca/` 目录必须始终留在离线保管区**，其中包含 NetworkRoot、IdentityAuthority、StatusSigner 及外层 TLS CA 私钥。

<a id="network-policy"></a>

### 当前开发构建：额外签发网络策略

**如果走公开 `v0.1.0-pre.3` 演练，请跳过本小节**，其余签发操作保持不变。使用当前开发构建时，网络策略与节点材料必须绑定同一个 `net_id`。运行以下命令签发当前 CLI 支持的 `10.20.0.0` 基址策略，并将生成的三个签名输入文件与两个公钥 pin 分开保管：

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

这两个公开 pin 必须由掌管 NetworkRoot 的管理员通过独立、可信的带外途径预配到目标主机；绝不能把待验证制品自带的根材料当成信任锚。使用**已确认可信**的 verifier CLI 与已核对无误的 pin 执行以下预检，此步骤仅校验对象本身，不会记录防回退水位：

```sh
boreas pki verify-policy --net-id "$NET_ID" \
  --tbs-file ./policy/policy.tbs \
  --ed25519-signature-file ./policy/policy.ed25519.sig \
  --mldsa65-signature-file ./policy/policy.mldsa65.sig \
  --root-ed25519-der ./pins/root.ed25519.der \
  --root-mldsa65-der ./pins/root.mldsa65.der
```

校验通过后，将各自主机的节点材料包、策略三文件以及独立预配的 pin 分发到目标主机的私有 staging 目录；传输时务必核对 SSH 主机密钥或使用经批准的安全传输通道。切勿上传 `ca/` 目录，也不要混入编辑器备份或临时文件。请同时在离线保管区留存两份节点包的受保护副本，并记录初次签发的序号与过期时间。

## 3. 配置两个节点

以下为**完整的 Core 端 TOML 配置**。在两台主机分别创建各自的 `node.toml`（权限设为 `0600`），并将 `REPLACE_WITH_NET_ID` 替换为第 2 节记录的同一 `NET_ID` 值。示例中的 `[paths]` 对应下文 `v0.1.0-pre.3` 的手工路径布局；开发版安装器在部署时会自动重定位这三项路径，但源配置文件仍应指向私有 staging 中真实存在的文件和目录。若采用离线双签 systemd 服务路径，则需遵循其[固定目录布局](VERIFIED-SERVICE.md#首次安装管理员)，不经过旧安装器重定位。

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

**生成 Edge 配置时从此文件复制并修改以下字段**：将 `role` 改为 `"edge"`，`vip_octet` 与 `node_id` 改为 `2`，`allow_edges` 改为 `false`；其余字段保持一致（若两机本地路径不同，各自填写本机实际路径）。请确保 `identity_generation` 与 `issue-node --generation` 参数匹配。此外，配置里的 `paths = 4` 表示 `[uplink]` 的路径上限，并非本例实际建立四条活动连接。

填写配置时注意以下约束：

- **`[node]` 槽位绑定**：配置中的节点字段必须与已签发身份完全对应，修改 TOML 并不能改变证书中的身份。Core 的 `allow_edges` 仅允许其担任接入端，无法替代 `peer.signed` 的点对点显式授权。
- **`[paths]` 绝对路径与权限**：三项路径必须使用绝对路径。私钥只允许运行 daemon 的 UID 读取；状态目录必须持久存在且可由该 UID 写入。严禁让两台节点或两个进程共用同一运行状态目录。
- **`[uplink]` 运行参数**：该段不可省略。通过 `--listen` / `BOREAS_LISTEN` 设定监听地址，通过 `--connect` / `BOREAS_CONNECT` 显式拨号底层 IP；`--tls-name` / `BOREAS_TLS_NAME` 用于核对证书 SAN，`--ws-host` / `BOREAS_WS_HOST` 用于设置 WebSocket HTTP `Host` 请求头。切勿将这三项都填成隧道 VIP。

配置写好后，使用已受信的对应构建执行 `boreas config-check /实际路径/node.toml`。该检查通过只表示静态语法与字段格式有效；材料一致性、网络策略、端口监听、对端连通性及 TUN 创建均在运行时验证。

## 4. 安装并启动当前开发构建

按[一键安装操作单](ONE_CLICK.md)执行部署：在两台主机分别建立结构相同的私有 staging 目录，逐台核对可信 SHA-256 摘要，先执行 `--dry-run` 预演，确认无误后再使用 `--service systemd --accept-legacy-service` 完成安装。随后分别写入 Core 与 Edge 的 `boreas.env`，**务必先启动 Core，确认 Core 已开始 TCP 监听后立刻启动 Edge**。注意，旧服务模板以 root 运行，仅适合隔离评估环境，切勿与离线双签 systemd 单元混装在同一主机。安装脚本返回成功且 `active` 符号链接切换，并不代表本机 daemon 已成功启动或隧道已经连通。如果传入 `--service none`，安装器仅落地文件，不会启动 daemon。

安装完成后，每台主机只看到自己的 `<prefix>/releases/<id>/config.toml` 与 `materials/`；两端可以使用相同的 release id，但绝不可混用节点材料。一键部署的启动包装脚本会让两端各自把本机组网 VIP 配置到 `btun0`，并且只添加一条指向已授权对端 IPv4 VIP 的 `/32` 路由（不会进行任意 `/24` 路由、网段导出或流量转发）。脚本不会替换已有地址或路由，服务退出时也只清理自己添加的条目。此路径不修改默认路由，也不改变 Core 或 Edge 的系统 DNS 解析，普通上网流量和外层隧道连接继续走宿主机原有路由；若组网 VIP 与本地网络发生冲突，必须在启动前解决。**走一键安装路径时不要预先手动创建 `btun0`**；与之相对，离线双签服务路径则要求管理员提前创建持久 TUN 设备及对端路由。

<a id="verify-and-maintain"></a>

## 5. 验收与日常维护

排查与验收均应遵循从底层网络到应用层的顺序。需注意，Core 处于端口监听状态不代表外层握手成功；`ss` 中出现 TCP 连接也不代表已建立起完成认证的端到端电路。

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

在旧安装器的默认前缀下，需使用运行 daemon 的同一 UID（此处为 root）查询运行状态。若使用离线双签服务，请改用 `sudo -u boreas` 并指定 `/var/lib/boreas/state/control.sock`；若为 `v0.1.0-pre.3` 演练路径，则指向 `/var/lib/boreas/control.sock`。找不到控制 socket 时先查日志定位进程状态，不要通过放宽权限解决。查看旧服务模板日志时，需显式指定服务名 `boreas`。

```sh
sudo boreas ctl status --socket /opt/boreas/state/control.sock
sudo boreas console --json --socket /opt/boreas/state/control.sock \
  --service boreas

# Edge：发送前后各看一次状态
ping -c 4 -I 10.20.1.2 10.20.1.1
# Core：反向验证
ping -c 4 -I 10.20.1.1 10.20.1.2
```

验收成功时应观察到以下结果：对端 `/32` 路由选定经由 `btun0` 转发；状态输出包含 `daemon_connected:true`、`security_mode:"e2e-required"` 及 `status_fresh:true`；双向 `ping` 均通，且两端 `tx_packets` 与 `rx_packets` 计数同步增长。如需进一步验证隧道内 TCP 吞吐，可在 Core 执行 `iperf3 -s -B 10.20.1.1`，在 Edge 执行 `iperf3 -c 10.20.1.1 -B 10.20.1.2 -t 10`；建议在基础故障排除完成后再压测，且隔离环境下的测试结果不代表公网 SLA。

### 可选：让两台节点使用私有域名

使用私有 DNS 前，先确保上述双向 `ping` 验证已全部通过。随后按[私有 DNS 部署说明](../engineering/dns-daemon-deployment.md)签发私有区数据、在两端安装固定版本的区文件，并通过私有 VIP 地址直接发起 DNS 查询验证。仅使用专用应用直连隧道内解析器时，无需改动系统解析配置。若希望普通应用自动解析私有域名，须由管理员在操作系统层面手动配置严格的按域分流规则：仅将私有域名后缀转发至隧道内私有 DNS，且即使隧道断开也不得回退到公网 DNS，其余域名仍走宿主机原解析器；安装器不会自动修改系统解析器或代为配置分流规则，切勿替换全局系统 DNS。如需开启隧道内 TCP DNS 查询，两端配置必须显式设置 `[dns].tcp = true`；该开关只启用隧道内私有 DNS 的 TCP 监听，既不会安装系统解析规则，也不会将查询转发至公网。

### 续签、重启和停用

- **状态快照续签**：在当前快照过期前于离线签发机签发新序号版本，例如 `boreas pki sign-status --ca-dir ./ca --out ./status-2.signed --sequence 2 --ttl-seconds 86400`（仅当当前在线序号确为 `1` 时才使用 `2`）。将同一份新快照安全分发到两台主机，先复制到实际 daemon 材料目录内的临时文件，设置正确的属主与 `0600` 权限，再在同一文件系统内原子重命名为 `status.signed`。daemon 会自动复核新快照；若此前已因状态过期而停机，需先更新材料后再启动服务。更新完成后重新核对 `status_sequence`、`status_fresh` 及双向流量。注意，同序号不同内容或更低序号均不能作为有效续签。
- **旧开发安装的发布目录处理**：在线续签 `status.signed` 属于运行时材料更新，并不等于原始安装 bundle 字节未变；因此不要再用同一个 release id 重新发布已改变的输入，新的安装代际必须分配新的 release id。若涉及网络策略或根密钥变更，应按照[策略及状态规则](POLICY-STATE.md)单独评估过期时间、根指纹与防回退水位并规划切换，切勿直接覆盖历史文件。软件版本回退同样不能让旧的、已过期的或已撤销的授权恢复生效。
- **停用与清理**：使用旧 systemd 路径时，执行 `sudo systemctl stop boreas.service` 停止服务；如不再需要开机自启，再执行 `sudo systemctl disable boreas.service`，并确认包装脚本添加的 `/32` 路由与 `btun0` 已被清理。采用手工前台启动时，直接在**对应终端**中止进程，不要使用全局 `pkill`。对于离线双签服务或多 Core mesh 拓扑，其持久 TUN 由管理员自行维护，停止服务不会删除网卡设备。停用后请保留状态目录与必要日志以便审计排查，严禁将清空水位文件作为重试手段。

<a id="public-pre3"></a>

## 6. 公开预发布双机演练（仅 `v0.1.0-pre.3`）

本节为独立的 **x86-64 Linux** 手工演练路径。若目标机器已有其他 Boreas 服务、TUN 设备、路由或配置文件，请另选两台隔离主机演练，避免覆盖现有部署。注意，公开 `.tar.gz` 基础 CLI 归档包与下面使用的 pq768 二进制不是同一制品。

在**下载端**新建空目录获取官方固定标签下的两个文件，使用 `&&` 确保任一步下载或校验失败即中止整组命令：

```sh
BASE=https://github.com/Lanlan13-14/Boreas/releases/download/v0.1.0-pre.3
BIN=boreas-linux-x86_64-musl-pq768
curl -fLO "$BASE/$BIN" &&
  curl -fLO "$BASE/SHA256SUMS-PRE3" &&
  grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -
```

确认输出显示该二进制 `OK` 且命令以退出码 `0` 结束后，再独立核对制品来源与 SHA-256 摘要。由于这两个文件同源，这一步仅用于验证下载完整性，不构成发布双签信任；在无法建立来源信任前，不要以 root 身份执行。确认目标主机不存在命名冲突后，在两台节点安装校验通过的同一份二进制，并通过可信介质转运至离线签发机：

```sh
sudo install -m 0755 "$BIN" /usr/local/bin/boreas
boreas doctor
```

执行 `boreas doctor` 应确认输出包含 `daemon: true` 与 `tls_backend: true`。按第 2 节流程完成离线签发与验包，**跳过其中的网络策略小节**。随后通过安全通道将各自材料包送到对应主机的 `/etc/boreas/material`，并参照第 3 节编写 `/etc/boreas/node.toml`（本路径 `[paths]` 保留示例默认布局即可）。创建属主为 root、权限为 `0700` 的 `/etc/boreas`、`/etc/boreas/material` 与 `/var/lib/boreas` 私有目录，将配置文件和私钥设为 `0600`，检查文件归属无误后运行 `sudo boreas config-check /etc/boreas/node.toml`。

准备好两边终端后开始启动。先在 Core 上运行前台命令，看到监听就绪提示后，请在首连等待窗口（30 秒）内启动 Edge；若超时窗口已过，先查看报错原因再重新启动 Core：

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

分别在两台主机的第二个终端执行 `ip link show dev btun0`，确认 daemon 已创建 `btun0` 后，再各自执行对应主机的三条网络配置命令。如果 `ip ... add` 提示冲突，应立即停下排查，切勿改成 `replace` 强行覆盖：

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

配置完成后按第 5 节方法完成双向验证，查询状态时将 socket 参数改为 `sudo boreas ctl status --socket /var/lib/boreas/control.sock`。演练结束时中止两端前台进程，并确认本次创建的 TUN 设备、VIP 地址和 `/32` 路由已自动消失。不要直接将本节的旧版手工命令写入当前 systemd 服务模板；如需长期常驻运行，请根据目标开发构建选择对应的服务部署路径。

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

仓库的 [TLS 工作流](../../.github/workflows/rust-tls.yml) 用 `tools/release/netns_daemon_smoke.sh` 在隔离 Linux runner 中验证开发构建的真实 TUN/数据面；这不是拿 pre.3 二进制运行的脚本。只在具备 `/dev/net/tun`、网络和挂载命名空间权限的可销毁 runner 上，按工作流同一提交、二进制和参数执行。旧安装器、离线双签服务与多 Core 有各自测试入口，分别见对应文档。记录准确的源码修订版本 和实际通过的步骤，不能用普通 Rust 测试或被跳过的设备步骤代替真实包 I/O。
