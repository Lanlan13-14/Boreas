# 四 Core 互通：业务路径、目录发现与故障切换

这是一条独立的 Linux 实验路线：`boreas node mesh-run <node.toml> <material-dir> <runtime.toml>`。不使用普通 Core/Edge 的 `daemon`、`boreas-run` 或离线签名 daemon 单元。它只服务**一对 Core 永久 IPv4 VIP**；Source 发起电路，确认后两个端点都可收发。下面的 `[[routes]]` 配方每实例最多三条显式路径，每条经过三或四个不重复的 Core。也可以用[签名拓扑 `[routing]` 配方](linux-core-mesh-runtime.md#configure-signed-topology-routing-and-tun)：只配置端点对和相邻传输，不列端到端路径，支持直达或最多两个中继；两种配方均要求 Source 槽位小于 Destination。它不做任意子网、Edge、默认路由、IPv6 或 DNS 转发。

**先选实现版本：** 三种目录方式在[第 4 节](#directory)区分。本页完整示例使用含 `4363e0e` 的 Linux `openssl-inner-tls` 开发构建；不适用于公开 `v0.1.0-pre.3`。如果只有不含发现改动的 `43b744a` 构建，删除协调器配置并选择手工种子或静态控制邻接。下文的持久 CoreLSA 防重放与冲突处置也只适用于包含发现改动的构建。判断制品是否具备这些能力，要看实际构建的源码提交；文档存在或其他提交的 CI 通过都不是证据。

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

示例地址不能在公网直接使用。目标主机必须预先配置好底层监听地址；拨号配置填写实际的数字 IP 地址和端口，不要填 VIP。防火墙按表和有向链路开放 TCP，并限制来源：Core 2 的主业务端口接 Core 1，Core 3 的主/备端口分别接 Core 2/1，Core 4 的两个业务端口都接 Core 3；协调器端口接预配的 1、2、4。底层名称以证书 DNS SAN 校验；用 IP 拨号不要求这些名称公开解析。部署前核对 SSH 路由、已有 `10.20.*` 地址、端口和接口；示例不是 CDN 或任意反代配置。

## 2. 离线签发节点、策略和每个 Core 的拓扑通告

用[双机教程的离线准备方法](README.md#workflow)生成新 `NET_ID` 并初始化 `./ca`，只做一次。本节以同一可信 pq768 构建、私有工作目录和正确 UTC 为前提。**不要签发 Edge，也不要交叉复制 `peer.signed`**；专用 mesh 使用下面的 `core-N.signed`。为了实验容易复现，这组命令为每个 Core 都签一份外层 TLS 证书；当前拓扑中仅监听者需要外层服务端私钥。

```sh
for slot in 1 2 3 4; do
  boreas pki issue-node --ca-dir ./ca --out-dir "./core-$slot" \
    --role core --home-core "$slot" --vip-octet 1 --generation 1 \
    --validity-hours 168 --outer-san "core$slot.example.com" || break
done
boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued --sequence 1 --ttl-seconds 604800
```

确认四份 `local.signed` 和节点密钥均成功签发后再继续。下一步的签名者是**受 NetworkRoot 授权、限于指定 Core 槽位的 CoreOperational**，不是运行账号。以下目录和参数用 Core 1 示范：

```sh
# Core 1 的签发机；新的 ./operational-1 目录只保存在签发区
boreas pki core-request ./operational-1 "$NET_ID" 1 1 7
# 离线 NetworkRoot 签发机：线下核验请求人和槽位，仅转运公开 core.request
boreas pki core-authorize ./ca ./ca/roots.cbor \
  ./operational-1/core.request ./roots-1.cbor 1
```

为槽位 `2`、`3`、`4` 各重复一次：`core-request` 的第 3 个参数改成该槽位，目录不要复用；`core-authorize` 每次读取**上一步输出**，例如 Core 2 读 `roots-1.cbor`、写 `roots-2.cbor`，最后得到 `roots-4.cbor`。每个槽位一份受限签发授权，不能复用别的槽位私钥。分发最终公开 `roots-4.cbor` 给所有签发机和运行节点，运行节点统一以它替代初始 `roots.cbor`。不要让中间版本混入节点。NetworkRoot、IdentityAuthority、StatusSigner、外层 CA 和 CoreOperational 的私钥都不进运行目录。

在**各自**签发机上，用最终 roots 签发各自的 LSA。下面四行分别对应四个槽位；输出文件是新名字，参数依次为 `core-generation`、`seq`、有效秒数和零至 15 个 `对端槽位:RTT毫秒:丢包ppm`：

```sh
boreas pki core-sign-lsa ./operational-1 ./roots-4.cbor ./core-1.lsa-1 1 1 1800 2:5:0 3:30:0
boreas pki core-sign-lsa ./operational-2 ./roots-4.cbor ./core-2.lsa-1 1 1 1800 1:5:0 3:5:0
boreas pki core-sign-lsa ./operational-3 ./roots-4.cbor ./core-3.lsa-1 1 1 1800 1:30:0 2:5:0 4:5:0
boreas pki core-sign-lsa ./operational-4 ./roots-4.cbor ./core-4.lsa-1 1 1 1800 3:5:0
```

签发器将邻接标为 CDN 类；**这里的类是协议属性，不代表实验经过真实 CDN**。一段业务边必须在两端的签名通告中出现；本例在丢包值相同的情况下用较低总 RTT 让 `1→2→3→4` 优先。目录连接不是业务邻接（例如 `2→3` 可以有两种不同端口，`1→3` 的目录认证不会给业务路径签授权）。签发有效期最长 3600 秒；临近启动再签，预留分发时间。续签时递增 `seq`，不能改同一代次/序号已签内容。空邻接列表可以签发为撤回；它不新增授权。

## 3. 逐台配置：先 `node.toml`，再 `runtime.toml`

每台主机预配专用非特权账号 `boreas`。示例路径 `/etc/boreas-mesh` 和 `/var/lib/boreas-mesh` 的各级父目录都必须可信且不能是符号链接。配置、私钥和状态仅限运行 UID 访问；建议私有目录用 `0700`，文件用 `0600`。节点和实例均使用独立持久状态。不要并行启动第二个实例读写同一状态，亦不要用 `mesh-probe` 同时写同一目录。

在**每台**主机按表放文件：

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

先用可信 verifier [预检策略](README.md#当前开发构建额外签发网络策略)，再部署。不要把三个路线上不同的策略命名混用：专用 mesh 读 `network-policy.*`，离线双签 daemon 读 `policy.*`，旧安装器 wrapper 则加 release 前缀。运行期的 `status.state`、`network-policy.state` 和（含发现改动时）`core-lsa.state` 由运行时建立，不预建空文件。`outer-ca.pem` 只管外层；内层 pq768 mTLS 仍匹配签名节点证书的 SPKI（公钥信息），不能用外层 TLS 名或 IP 代替。

以下为 Core 1 的完整 `node.toml`（`/etc/boreas-mesh/node.toml`）：

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

换成实际 `NET_ID`。Core 2/3/4 对照上表改 `home_core_id` 和 `node_id`；其余可沿用。`[uplink]` 为通用 schema 必填，不决定 mesh 的实际拨号；不加 `[dns]` 或其他可选能力。以服务 UID 运行 `sudo -u boreas boreas config-check /etc/boreas-mesh/node.toml`，先检查通用配置。专用的 `runtime.toml` 由 `mesh-run` 解析，不在 `config-check` 的范围内。

以下四份 `runtime.toml` 分别存到**对应主机**的 `/etc/boreas-mesh/runtime.toml`。`listen` 与前一节点的 `next` 要逐段对应；路线 `path` 必须在所有沿途节点一致。业务和控制的 socket 不可复用。下方不含目录段，按第 4 节追加。

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

**A. 预配成员 + 一个协调器（含 `4363e0e` 的构建）。** Core 3 在自己的运行清单末尾追加：

```toml
[directory_discovery]
coordinator = 3
listen = "192.0.2.3:18183"
```

Core 1、2、4 分别在各自清单末尾追加同一配置：

```toml
[directory_discovery]
coordinator = 3
next = "192.0.2.3:18183"
tls_name = "core3.example.com"
```

这不是发现任意新成员。每个节点都必须预配其他三份 `core-N.signed` 和一致的最终 roots。TLS 客户端验证协调器外层名称、链和签名身份；协调器按内层 TLS 的精确 SPKI 匹配预配成员，不从 TCP 来源、DNS、SessionHello 或 LSA 学习成员/公钥。协调器交换已验证的原始签名通告，不代签、不授予业务边，也不会自动选举替代协调器。

**冷启动：只在 Core 3 放一份当前有效的 Core 1 通告**（`material/core-1-lsa.signed`），让 Core 2、3、4 在 Source 进程启动前获知 Core 1。其余远端 LSA 在本例从目录获取，不逐对复制。缺少通告时，目录可先交换，但业务监听与 TUN 附着会等待图具备可用路径。任何显式放在磁盘的种子仍是校验输入；续签后要原子替换种子，或在确认新头已持久化后移除不再需要的**种子文件**。不能把过期种子留在目录，也不能删除持久状态文件。

**B. 静态控制邻接（`[[directory]]`）。** 两种格式不能同用。配置专用控制边，较低槽位拨较高槽位。例：Core 1 拨 Core 2 的 `192.0.2.2:18182`：

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

其他控制边沿用同样规则，每一条应有两端的配置及独立端口；例如控制链 `1→2→3→4`。给每个目录监听者配置本机外层 TLS 服务证书，拨号者配置可信链。为保证下游先就绪，可以先预置当前有效的全部 LSA；启用静态同步后，学到的远端头不要求再写一份种子。不要依赖尚未运行的 Source 把第一份签名 LSA 传到下游。

**C. 纯手工种子（不写任何目录段）。** 初次部署按 `peers` 为每节点放齐各 `core-N-lsa.signed`，再按顺序启动。没有跨跳同步；运行时仍可接收通过认证的直接业务邻居的新通告。包含 `4363e0e` 的构建可在重启复用有效的持久头；不含该改动时不能依赖跨重启保存。

目录同步校验直接通告、身份撤权及第三方签名通告；每页是一份原始签名 LSA，校验签名、委派范围、时间及回放水位，已认证页可独立提交。拨号方在上一次尝试结束五秒后安排下一次尝试，和其他控制任务、业务轮次共用调度。**这不是五秒收敛保证。**协调器暂时不可达时，已完整授权的业务图在自己的有效边界内仍可使用；签名、授权或新鲜度失败不会降级放行。目录不分发身份、授权、租约或冲突证据。

## 5. 管理员预建两端 TUN，再启动四个进程

Core 1 与 Core 4 各有一个交给 `boreas` 的持久、单队列、无包信息头的 TUN。下面先确认设备及路由没有冲突，再逐台执行。不要以 `replace` 覆盖宿主旧路由。两个 Relay 不建 TUN。

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

端点只能收发这两个经认证的 VIP；底层地址和默认路由不要指向 TUN。`mesh-run` 附着并校验现有设备，不创建或清理它。主机重启后由管理员或本机网络管理器重建专用 TUN 和授权 `/32`。

用可信路径上可由 `boreas` 执行的二进制，在每台主机前台运行同一命令（配置内容各不相同）。先 Core 3，再 Core 4 和 Core 2；等三个下游均记录 `mesh ready node=…`，并用 `ss -ltn` 核对其业务端口，再启动 Core 1。`mesh ready` 表示本机图已具备可用路径、相应监听或 TUN 已打开，不是端到端电路已就绪。不要让 Source 在下游未就绪时试拨：认证确认前的失败不是可以用来倒换的证据。

```sh
sudo -u boreas boreas node mesh-run /etc/boreas-mesh/node.toml \
  /etc/boreas-mesh/material /etc/boreas-mesh/runtime.toml
```

守护运行时捕获 stderr、用 SIGTERM 停止。此入口**没有** `control.sock`，不要用普通 daemon 的 `ctl status` 判定 mesh 离线。

## 6. 验收、倒换和排错

```sh
# Core 1
ip -4 route get 10.20.4.1 from 10.20.1.1
ping -c 4 -I 10.20.1.1 10.20.4.1
# Core 4
ip -4 route get 10.20.1.1 from 10.20.4.1
ping -c 4 -I 10.20.4.1 10.20.1.1
```

1. 在 Source 和 Destination 核对相同的已确认 `circuit` ID 及 `path=[1, 2, 3, 4]`。两端日志应看到 `tx`/`rx`，Relay 报密文计数，不记录业务内容。
2. **仅在可销毁的环境**，确认主路径在承载流量时，停止 Core 2 进程（不是停协调器 Core 3）。等待双方确认 `path=[1, 3, 4]`，新 ID 应相同且不同于旧 ID；再发新的 `ping`。运行只在有合格的失链证据、另一路径仍获授权时尝试新跳链和新 E2E TLS，不重放旧包或密文。确认前的 EOF/reset、认证/协议错误、过期或撤权不是自动改走备路的依据。没有无损切换承诺，测试 TCP 时由上层自行恢复。
3. 进一步的撤权测试由[仓库验收](#acceptance)完成。独立身份撤权材料使用 `identity-revocation.signed` 入口；StatusSigner 的日常快照不替代 IdentityAuthority 撤权。已提交撤权不会因删除邮箱文件或重启而消失。业务电路存续时也轮询邮箱；撤权涉及路径成员时，先持久化决定再关闭电路。被撤的是远端时，仍可通过健康的目录邻接传播原始签名证据；若被撤的是本机代次，进程停止。

| 现象 | 检查顺序 |
| --- | --- |
| 目录端口在听但不出 `mesh ready` | 查三台是否拨同一协调器、TCP/证书 SAN、预配 `core-N.signed` 是否齐全，是否缺 Core 1 的引导种子或存在过期 LSA；确认业务边两端均有签名声明、清单沿途一致。 |
| `invalid directory discovery configuration` / `overlapping legacy links` | 目标二进制是否含 `4363e0e`；协调器只配 `listen`，其他节点只配 `next` 和 `tls_name`；不要混用两种目录段或占用业务地址/端口。 |
| `mesh TUN attach` / VIP 不通 | 端点专用设备是否持久、归 `boreas`、名称/MTU 匹配；比较两端 `ip -4 route get` 与选中的源 VIP；用已确认路径 ID 检查是否同一电路。 |
| 已有业务突然停，日志显示状态、授权或 LSA 失效 | 先核对 UTC、策略及状态期限、撤权和所有拓扑通告。发行更高序号不是忽略独立撤权或同版分叉的办法；修复原因后再按需协调重启。 |
| `LsaConflict` / `LsaState` 或启动拒绝 | 停止进程，保留受保护的 `core-lsa.state`、`core-lsa.state.lock` 及可能的 `core-lsa.state.staging`；查文件系统、权限、旧状态与签发方。不要删文件或换到空目录恢复。 |

### 持久 CoreLSA 冲突证据（含 `4363e0e`）

`mesh-run` 和 `mesh-probe` 使用 `state_dir/core-lsa.state`。该状态仅供服务 UID 使用，绑定 `net_id`、NetworkRoot 指纹及本机槽位；保存每槽位至多一份当前原始签名通告（最多 16 个槽位）。首个同 `(core_generation, seq)`、签名有效但待签字节不同的分叉保留两份原始信封并停止使用该授权。锁协调写入并标记初始化或写冲突意图；提交会同步私有 staging、原子安装并同步父目录。提交失败、冲突标记未解决、中断 staging、已初始化状态缺失、路径不安全、损坏或验证到分叉都会拒绝启动或停止运行授权。提高代次不能清空已持久化冲突。

恢复时旧种子不能降低已有水位；历史信封的双签与委派按签发时刻复核，允许承载业务的授权仍受当前策略、有效期和撤权约束。轮换前确认能保留历史验签所需授权。先封存证据，再调查错误签发、密钥或存储问题，必要时由管理员审阅并重新预配信任；没有自动解封。不要删 `.lock`、`.staging` 或整个目录“修好”服务。它不防受信 UID/root 替换整个状态目录或回滚存储快照。

<a id="acceptance"></a>

## 7. 验收入口及证据范围

在与目标 SHA 匹配的 [TLS 工作流](../../.github/workflows/rust-tls.yml)和受控 Linux runner 上，使用工作流固定的 OpenSSL、环境与 features。仓库的两个入口：

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
