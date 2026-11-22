# 四 Core 互通：业务路径、目录发现与故障切换

简体中文 · [繁體中文](linux-core-mesh-topology.zh-TW.md) · [English](linux-core-mesh-topology.en.md)

这是一条独立的 Linux 实验路线，使用 `boreas node mesh-run <node.toml> <material-dir> <runtime.toml>` 运行，不使用普通 Core/Edge 的 `daemon`、`boreas-run` 或离线签名 daemon 单元。

**适用边界与路由选择：** 本路线仅服务**一对 Core 永久 IPv4 `/32` VIP**；由 Source 发起电路，确认后两个端点均可收发。默认部署不修改宿主 DNS、不写入默认路由，也不提供任意 `/24` 子网路由、网段导出、通用转发、Edge、IPv6 或 DNS 转发；即便配置操作系统路由，也不会突破仅限授权对端 VIP `/32` 的限制。你可以二选一配置路径：

- **显式路径配方（本页 `[[routes]]`）**：每实例最多三条显式路径，每条经过三或四个不重复的 Core。
- **签名拓扑配方（[签名拓扑 `[routing]` 配方](linux-core-mesh-runtime.md#configure-signed-topology-routing-and-tun)）**：只配置端点对和相邻传输，不列端到端路径，支持直达或最多两个中继。

两种配方均要求 Source 槽位号小于 Destination 槽位号。

**先核对二进制能力再部署：** 三种目录同步方式在[第 4 节](#directory)区分。本页完整示例要求 Linux `openssl-inner-tls` 开发构建具备**目录发现协调器及持久 CoreLSA 防重放与冲突处置能力**；公开版本 `v0.1.0-pre.3` 不具备这些能力，不能直接套用。如果你使用的是**不含目录发现与持久 CoreLSA 改动的构建**，请删除协调器配置并改用手工种子或静态控制邻接；下文的持久 CoreLSA 防重放与冲突处置机制同样只适用于包含目录发现改动的构建。判断制品是否具备上述能力，必须核查构建所用的实际源码修订；文档存在或其他源码修订的 CI 通过均不能作为依据。

## 1. 拓扑和端口

```text
业务首选： Core 1 ──> Core 2 ──> Core 3 ──> Core 4
业务备选： Core 1 ────────────> Core 3 ──> Core 4
目录控制： Core 1 / Core 2 / Core 4 ────> Core 3:18183（双向交换 LSA）
```

| 节点 | 槽位 / node_id | 角色、底层地址（示例）与 TLS 名 | 监听端口 | TUN |
| --- | --- | --- | --- | --- |
| Core 1 | `1 / 1` | Source，`192.0.2.1`，`core1.example.com` | 无 | `btun0`，`10.20.1.1/32` |
| Core 2 | `2 / 257` | Relay，`192.0.2.2`，`core2.example.com` | TCP `18082` 主路径 | 无 |
| Core 3 | `3 / 513` | Relay + 目录协调器，`192.0.2.3`，`core3.example.com` | TCP `18082` 主路径、`18083` 备路径、`18183` 目录 | 无 |
| Core 4 | `4 / 769` | Destination，`192.0.2.4`，`core4.example.com` | TCP `18082` 主路径、`18083` 备路径 | `btun0`，`10.20.4.1/32` |

部署前必须满足以下网络与防火墙前提：

1. **预配置底层地址与拨号目标**：示例 IP 不能在公网直接使用。目标主机须事先配置好底层监听地址；拨号配置必须填写实际数字 IP 地址和端口，禁止填写 VIP。
2. **按有向链路开放防火墙 TCP 端口并限制来源**：Core 2 的主业务端口（`18082`）仅放行 Core 1；Core 3 的主路径端口（`18082`）放行 Core 2、备路径端口（`18083`）放行 Core 1；Core 4 的两个业务端口（`18082`、`18083`）均放行 Core 3；协调器端口（`18183`）仅放行预配的 Core 1、2、4。
3. **核对主机冲突与证书名**：底层名称通过证书 DNS SAN 校验，使用 IP 拨号时不要求公网 DNS 解析这些域名，且不要修改宿主 DNS。启动前先确认 SSH 管理路由、主机现有 `10.20.*` 地址、端口及网卡无冲突；本示例不是 CDN 或任意反向代理配置。

## 2. 离线签发节点、策略和每个 Core 的拓扑通告

开始签发前，确保所有签发机使用同一可信 `pq768` 构建、私有工作目录且系统 UTC 时间准确。先参照[双机教程的离线准备方法](README.md#workflow)生成新的 `NET_ID` 并初始化 `./ca`（全局只执行一次）。**不要签发 Edge，也不要交叉复制 `peer.signed`**；专用 mesh 统一使用下文的 `core-N.signed`。为便于实验复现，以下命令为每个 Core 都签发了外层 TLS 证书；在当前拓扑中，实际只有监听节点需要外层服务端私钥。

```sh
for slot in 1 2 3 4; do
  boreas pki issue-node --ca-dir ./ca --out-dir "./core-$slot" \
    --role core --home-core "$slot" --vip-octet 1 --generation 1 \
    --validity-hours 168 --outer-san "core$slot.example.com" || break
done
boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued --sequence 1 --ttl-seconds 604800
```

确认四份 `local.signed` 和节点密钥全部签发成功后再进入下一步。接下来的签名操作由**受 NetworkRoot 授权、且限于指定 Core 槽位的 CoreOperational** 完成，严禁使用运行账号私钥代替。以下目录与参数以 Core 1 为例：

```sh
# Core 1 的签发机；新的 ./operational-1 目录只保存在签发区
boreas pki core-request ./operational-1 "$NET_ID" 1 1 7
# 离线 NetworkRoot 签发机：线下核验请求人和槽位，仅转运公开 core.request
boreas pki core-authorize ./ca ./ca/roots.cbor \
  ./operational-1/core.request ./roots-1.cbor 1
```

为槽位 `2`、`3`、`4` 依次重复上述授权流程：

- 将 `core-request` 的第 3 个参数替换为对应槽位号，每个槽位使用独立目录，不得复用。
- `core-authorize` 每次必须读取**上一步的输出**——例如 Core 2 读取 `roots-1.cbor` 并输出 `roots-2.cbor`，最终产出 `roots-4.cbor`。每个槽位拥有一份受限签发授权，不得混用其他槽位私钥。
- 将最终公开的 `roots-4.cbor` 分发给所有签发机与运行节点，在所有运行节点上用它统一替换初始 `roots.cbor`，避免中间版本混入。
- NetworkRoot、IdentityAuthority、StatusSigner、外层 CA 以及 CoreOperational 的私钥均不得放入运行目录。

在**各自**签发机上，使用最终 `roots-4.cbor` 签发本槽位的拓扑通告（LSA）。下面四行命令分别对应四个槽位，输出文件名互不相同，参数依次为 `core-generation`、`seq`、有效秒数，以及 0 至 15 个 `对端槽位:RTT毫秒:丢包ppm`：

```sh
boreas pki core-sign-lsa ./operational-1 ./roots-4.cbor ./core-1.lsa-1 1 1 1800 2:5:0 3:30:0
boreas pki core-sign-lsa ./operational-2 ./roots-4.cbor ./core-2.lsa-1 1 1 1800 1:5:0 3:5:0
boreas pki core-sign-lsa ./operational-3 ./roots-4.cbor ./core-3.lsa-1 1 1 1800 1:30:0 2:5:0 4:5:0
boreas pki core-sign-lsa ./operational-4 ./roots-4.cbor ./core-4.lsa-1 1 1 1800 3:5:0
```

签发器将业务邻接标记为 CDN 类；**这里的类仅是协议属性，不代表实验流量经过真实 CDN**。一条业务边必须在两端节点的签名通告中同时出现才具备授权；本例在丢包率相同的情况下通过更低的总 RTT 让 `1→2→3→4` 成为主选路径。目录连接不属于业务邻接（例如 `2→3` 可使用两个不同端口，而 `1→3` 的目录认证不会为业务路径授予转发权）。LSA 签发有效期最长为 3600 秒，建议临近启动再签发并预留分发窗口；续签时必须递增 `seq`，不得修改同一代次和序号下已签发的内容。签发空邻接列表表示撤回通告，不会新增任何授权。

## 3. 逐台配置：先 `node.toml`，再 `runtime.toml`

每台主机须预先创建专用非特权账号 `boreas`。示例路径 `/etc/boreas-mesh` 和 `/var/lib/boreas-mesh` 的所有父级目录都必须可信且不能包含符号链接。配置文件、私钥与运行状态仅允许运行 UID 访问，建议私有目录权限设为 `0700`、文件权限设为 `0600`。每个节点与实例使用独立的持久状态目录，严禁并行启动第二个实例读写同一状态目录，也不要同时使用 `mesh-probe` 写入同一目录。

按以下清单在**每台**主机放置文件：

| 安装位置 | 来源 |
| --- | --- |
| `/etc/boreas-mesh/material/identity.key`、`identity.pem`、`identity-ca.pem`、`local.signed` | 该槽位自己的 `issue-node` 输出 |
| `…/material/roots.cbor` | 最终公开 `roots-4.cbor` |
| `…/material/status.signed`、`local-lsa.signed` | 当前状态快照、该槽位的 LSA 原始签名文件 |
| `…/material/core-N.signed` | `peers` 中每个槽位 N 的公开 `local.signed`；本例每台三份 |
| `…/material/core-N-lsa.signed` | 远端已签名 LSA；是否需要见[目录模式](#directory) |
| `…/material/outer.pem`、`outer.key` | 本机自己的外层服务端材料；Core 2、3、4 需要。`outer.pem` 叶子证书在前、后跟中间证书（如有） |
| `…/material/outer-ca.pem` | 本例在拨号者放同一私有外层 CA 的公开证书；指定后取代平台根，不是追加。始终核对 TLS 名称和信任链 |
| `/var/lib/boreas-mesh/network-policy.tbs` | `policy-issued/tbs.cbor` |
| `…/network-policy.ed25519.sig`、`…/network-policy.mldsa65.sig` | `policy-issued/ed25519.sig`、`policy-issued/mldsa65.sig` |
| `…/network-root.ed25519.der`、`…/network-root.mldsa65.der` | 独立预配的两个 NetworkRoot pin，对应策略输出 `root-ed25519.der` 与 `root-mldsa65.der` |

部署策略文件前，先用可信 verifier 完成[预检策略](README.md#network-policy)。切勿混用三条运行路线的策略文件命名：专用 mesh 读取 `network-policy.*`，离线双签 daemon 读取 `policy.*`，旧安装器 wrapper 则带有 release 前缀。`status.state`、`network-policy.state` 以及（当构建包含发现改动时）`core-lsa.state` 均由运行时自动创建，不要提前新建空文件。`outer-ca.pem` 仅校验外层 TLS；内层 `pq768` mTLS 仍严格匹配已签名节点证书的 SPKI（公钥信息），不能由外层 TLS 名称或 IP 替代。

以下是 Core 1 的完整 `/etc/boreas-mesh/node.toml`：

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

将配置中的占位符替换为实际 `NET_ID`。Core 2、3、4 对照第 1 节表格修改 `home_core_id` 和 `node_id`，其余字段可保持一致。`[uplink]` 仅用于满足通用配置 schema，不决定 mesh 的实际拨号目标；不要添加 `[dns]` 或其他可选功能（本方案保持默认不接管宿主 DNS，若需专用私有后缀 split DNS 请另行按对应指引显式启用，而专用 mesh 本身不支持 DNS 转发）。保存后，务必以服务账号预检通用配置：

`sudo -u boreas boreas config-check /etc/boreas-mesh/node.toml`

确认检查通过再继续。专用 `runtime.toml` 由 `mesh-run` 解析，不在 `config-check` 检查范围内。

将以下四份 `runtime.toml` 分别保存到**对应主机**的 `/etc/boreas-mesh/runtime.toml`。配置时必须确保本节点的 `listen` 与上一跳的 `next` 逐段对应，沿途所有节点上的路线 `path` 定义完全一致，且业务 socket 与控制 socket 不得复用端口。以下配置暂不含目录段落，需按第 4 节所选方式追加到文件末尾。

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

**Core 2 — Relay（仅主路径）**

```toml
mode = "relay"
peers = [1, 3, 4]

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.2:18082"
next = "192.0.2.3:18082"
tls_name = "core3.example.com"
```

**Core 3 — Relay（两条路径）**

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

## 4. 选择一种目录方式

根据你的目标二进制能力与运维偏好，从下列三种方式中任选一种（格式不可混用）：

**A. 预配成员 + 单一协调器（要求具备目录发现与持久 CoreLSA 能力的构建）。** Core 3 在其 `runtime.toml` 末尾追加：

```toml
[directory_discovery]
coordinator = 3
listen = "192.0.2.3:18183"
```

Core 1、2、4 分别在各自 `runtime.toml` 末尾追加同一段协调器客户端配置：

```toml
[directory_discovery]
coordinator = 3
next = "192.0.2.3:18183"
tls_name = "core3.example.com"
```

注意：协调器不发现任意未知成员。每个节点仍须预先配置其余三个槽位的 `core-N.signed` 和一致的最终 `roots.cbor`。TLS 客户端会校验协调器的外层域名、证书链与签名身份；协调器则依据内层 TLS 的精确 SPKI 匹配预配成员，绝不从 TCP 来源、DNS、SessionHello 或 LSA 中学习成员或公钥。协调器仅负责交换已验证的原始签名通告，不代签、不授予业务边，也不会自动选举备用协调器。

**冷启动与种子管理：** 仅在 Core 3 放置一份当前有效的 Core 1 通告（`material/core-1-lsa.signed`），以便 Core 2、3、4 在 Source 启动前提前获知 Core 1。其余远端 LSA 均通过目录获取，无需逐对复制。当部分通告尚未到位时，目录交换可先行工作，但业务监听与 TUN 附着会一直等待，直到拓扑图中存在可用路径。任何显式置于磁盘的种子文件都视为校验输入；续签 LSA 后，应原子替换种子文件，或在确认新头已持久化后删除不再需要的**种子文件**。严禁将过期种子留在目录中，也严禁删除持久状态文件。

**B. 静态控制邻接（`[[directory]]`）。** 此格式不得与方式 A 混用。为控制面配置专用控制边，按较低槽位拨较高槽位配置。例如，Core 1 拨 Core 2 的 `192.0.2.2:18182`：

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

其余控制边遵循同样规则，每条边须在两端成对配置并使用独立端口（例如建立 `1→2→3→4` 控制链）。为每个目录监听端配置本机外层 TLS 服务端证书，为拨号端配置可信 CA 链。为保证下游先行就绪，可在启动前预置当前有效的全部 LSA；启用静态同步后，学到的远端头无需再落盘写入新的种子文件。不要指望由尚未启动的 Source 把第一份签名 LSA 推向下游。

**C. 纯手工种子（不写任何目录段）。** 初次部署时按 `peers` 为每个节点放齐所有对端的 `core-N-lsa.signed`，再按顺序启动。此方式无跨跳同步；运行期间仍可接收来自已认证直接业务邻居的新通告。若使用具备目录发现与持久 CoreLSA 能力的构建，重启后可复用有效的持久头；若使用不含该改动的构建，则不能依赖跨重启持久化。

**同步校验与调度行为：** 目录同步会校验直接通告、身份撤权及第三方签名通告；每次同步分页对应一份原始签名 LSA，逐一验证签名、委派范围、时间戳和防重放水位，通过认证的页面会独立提交。拨号方在上一次同步尝试结束 5 秒后调度下一次尝试，并与其他控制任务及业务轮次共享调度器——**这不构成 5 秒收敛保证**。当协调器暂时不可达时，已完整授权的业务图在其有效期内仍可继续工作；任何签名、授权或新鲜度校验失败都不会降级放行。目录本身不分发身份凭据、业务授权、租约或冲突证据。

## 5. 管理员预建两端 TUN，再启动四个进程

Core 1 与 Core 4 各需一个交给 `boreas` 使用的持久、单队列、无包信息头（`no_pi`）的 TUN 设备。执行创建前先确认本机设备名与路由无冲突，再逐台配置，严禁使用 `replace` 覆盖宿主原有路由。Core 2 和 Core 3 两个 Relay 不建 TUN。

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

两端点仅允许收发这两个经认证的 `/32` VIP 流量；底层地址和宿主默认路由绝不能指向 TUN。`mesh-run` 只附着并校验已存在的设备，不负责创建或清理。主机重启后，必须由管理员或本地网络管理器重新创建该专用 TUN 与对应授权 `/32` 路由。

确认四台主机上 `boreas` 账号均可通过可信路径执行目标二进制后，在每台主机前台运行以下命令（使用各自对应的配置文件）。**启动顺序要求：** 先启动 Core 3，再启动 Core 4 和 Core 2；待三个下游节点均打印 `mesh ready node=…` 且通过 `ss -ltn` 确认对应业务端口处于监听状态后，最后启动 Core 1。`mesh ready` 仅表示本机拓扑图已有可用路径且对应监听或 TUN 已就绪，并不代表端到端电路已建通。切勿在下游未就绪时让 Source 提前试拨：认证确认前出现的失败不能作为倒换依据。

```sh
sudo -u boreas boreas node mesh-run /etc/boreas-mesh/node.toml \
  /etc/boreas-mesh/material /etc/boreas-mesh/runtime.toml
```

若以守护进程方式托管，请捕获 `stderr` 并使用 `SIGTERM` 停止进程。此运行入口**没有** `control.sock`，不要使用普通 daemon 的 `ctl status` 来判断 mesh 是否在线。

## 6. 验收、倒换和排错

进程就绪后，按以下步骤验证主路径连通性、故障倒换和撤权行为：

```sh
# Core 1
ip -4 route get 10.20.4.1 from 10.20.1.1
ping -c 4 -I 10.20.1.1 10.20.4.1
# Core 4
ip -4 route get 10.20.1.1 from 10.20.4.1
ping -c 4 -I 10.20.4.1 10.20.1.1
```

1. **核对主路径电路与流量**：在 Source 和 Destination 日志中核对相同的已确认 `circuit` ID 以及 `path=[1, 2, 3, 4]`。两端日志应出现 `tx`/`rx` 计数，Relay 仅报告密文转发计数，不记录明文业务内容。
2. **测试故障倒换（仅限可销毁测试环境）**：确认主路径正在承载流量后，停止 Core 2 进程（不要停止协调器 Core 3）。等待两端确认新路径 `path=[1, 3, 4]`，新 `circuit` ID 在两端应一致且不同于旧 ID；随后发起新的 `ping` 测试连通性。运行时仅在取得合格的失链证据、且备选路径仍处于有效授权时，才会尝试新的跳链与新的端到端 TLS 握手，绝不重放旧数据包或旧密文。电路确认前的 EOF/reset、认证或协议错误、凭据过期或撤权均不会触发自动改走备路。故障切换不提供无损承诺，TCP 等上层连接需由应用或协议栈自行恢复。
3. 进一步的撤权测试由[仓库验收](#acceptance)完成。独立身份撤权材料使用 `identity-revocation.signed` 入口；StatusSigner 的日常快照不替代 IdentityAuthority 撤权。已提交撤权不会因删除邮箱文件或重启而消失。业务电路存续时也轮询邮箱；撤权涉及路径成员时，先持久化决定再关闭电路。被撤的是远端时，仍可通过健康的目录邻接传播原始签名证据；若被撤的是本机代次，进程停止。

| 现象 | 检查顺序 |
| --- | --- |
| 目录端口在听但不出 `mesh ready` | 查三台是否拨同一协调器、TCP/证书 SAN、预配 `core-N.signed` 是否齐全，是否缺 Core 1 的引导种子或存在过期 LSA；确认业务边两端均有签名声明、清单沿途一致。 |
| `invalid directory discovery configuration` / `overlapping legacy links` | 目标二进制是否支持协调器目录发现；协调器只配 `listen`，其他节点只配 `next` 和 `tls_name`；不要混用两种目录段或占用业务地址/端口。 |
| `mesh TUN attach` / VIP 不通 | 端点专用设备是否持久、归 `boreas`、名称/MTU 匹配；比较两端 `ip -4 route get` 与选中的源 VIP；用已确认路径 ID 检查是否同一电路。 |
| 已有业务突然停，日志显示状态、授权或 LSA 失效 | 先核对 UTC、策略及状态期限、撤权和所有拓扑通告。发行更高序号不是忽略独立撤权或同版分叉的办法；修复原因后再按需协调重启。 |
| `LsaConflict` / `LsaState` 或启动拒绝 | 停止进程，保留受保护的 `core-lsa.state`、`core-lsa.state.lock` 及可能的 `core-lsa.state.staging`；查文件系统、权限、旧状态与签发方。不要删文件或换到空目录恢复。 |

### 持久 CoreLSA 冲突证据（须支持持久 CoreLSA）

`mesh-run` 和 `mesh-probe` 使用 `state_dir/core-lsa.state`。该状态仅供服务 UID 使用，绑定 `net_id`、NetworkRoot 指纹及本机槽位；保存每槽位至多一份当前原始签名通告（最多 16 个槽位）。首个同 `(core_generation, seq)`、签名有效但待签字节不同的分叉保留两份原始信封并停止使用该授权。锁协调写入并标记初始化或写冲突意图；提交会同步私有 staging、原子安装并同步父目录。提交失败、冲突标记未解决、中断 staging、已初始化状态缺失、路径不安全、损坏或验证到分叉都会拒绝启动或停止运行授权。提高代次不能清空已持久化冲突。

恢复时旧种子不能降低已有水位；历史信封的双签与委派按签发时刻复核，允许承载业务的授权仍受当前策略、有效期和撤权约束。轮换前确认能保留历史验签所需授权。先封存证据，再调查错误签发、密钥或存储问题，必要时由管理员审阅并重新预配信任；没有自动解封。不要删 `.lock`、`.staging` 或整个目录“修好”服务。它不防受信 UID/root 替换整个状态目录或回滚存储快照。

<a id="acceptance"></a>

## 7. 验收入口及证据范围

在与目标制品源码修订一致的 [TLS 工作流](../../.github/workflows/rust-tls.yml)和受控 Linux runner 上，使用工作流固定的 OpenSSL、环境与 features。仓库的两个入口：

```sh
cargo test --locked -p boreas-tunnel --features openssl-inner-tls --test mesh_probe_live
cargo test --locked -p boreas-cli --features openssl-inner-tls --test mesh_run_netns --no-run
```

真实设备测试是 ignored：只有显式运行 Cargo 打印的 `mesh_run_netns` 测试二进制才执行。用可销毁 runner，须有 `/dev/net/tun`、`CAP_NET_ADMIN`、`CAP_SYS_ADMIN`、`ip`、`ping`、`unshare`、`mount` 和 `setpriv`；沿用与构建配套的 `OPENSSL_CONF` / `BOREAS_OPENSSL_BIN`：

```sh
sudo --preserve-env=OPENSSL_CONF,BOREAS_OPENSSL_BIN \
  /path/printed/mesh_run_netns-HASH --ignored --nocapture --test-threads=1
```

固定路径用例启动四个非 root 进程、两个真实持久 TUN；只有协调器预置 Source LSA，通过共享目录收敛，主备路径分别传真实包，核对新 ID 和密文计数。撤销活跃远端后应取消电路、报告无可用路径但不退出；撤销本机代次才要求 Source 退出码 `2`。另外两个用例不配置固定路径，分别验证单边通告不能授权直达、失链后复用入口，以及运行中撤权后经双边签名的直达路径重新建环。活体 TLS 用例还覆盖空闲电路撤权、跨跳传播、未预配成员拒绝和跨重启分叉证据。这里描述的是测试断言；是否通过要读目标提交的实际日志。测试不经过真实 CDN，不验证公网长稳、通用路由或生产就绪。
