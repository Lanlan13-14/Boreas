# E2E 认证包流封装候选 v1（未冻结）

状态：候选（candidate），2026-11-15。**未冻结、未注册为 L3 capability、不是 RFC，也不是生产验收证据。** 本文描述
[`crates/boreas-tunnel/src/packet_path.rs`](../../crates/boreas-tunnel/src/packet_path.rs) 当前实现的字节格式与不变量，
供评审决定是否将其登记为正式对象。任何字段、宽度、错误码语义都可能在评审后改变；实现方不得把它当稳定 wire contract。

## 1. 范围

该适配器把一条已建立的 E2E 电路（`E2eCircuit`，`Read + Write`）与一个真实 `boreas_tun::PacketIo` 端点对接：

```text
host stack --PacketIo::read_packet--> 授权 --frame--> E2E circuit stream --+
                                                                           |
host stack <--PacketIo::write_packet-- 授权 <--frame-- E2E circuit stream <-+
```

它只做单跳点对点的 L3 封装，不做路由、不递减 TTL/HopLimit、不生成 ICMP、不做分片重组、不做 GSO/offload。
它不是 hop-only 回退路径，也没有任何"降级到明文/逐跳转发"的分支。

"单跳点对点"指该适配器只终结自己这一对端点，不指 `path_hops` 必须为 1：多跳加密电路仍然终止在同一个端点对上，
中间转发节点只盲转密文，适配器从不看到中间跳。故本适配器是 endpoint adapter，不是 forwarder。

## 2. 帧格式（候选）

一帧恰好承载一个 IP 包：

| 偏移 | 宽度 | 含义 |
| --- | --- | --- |
| 0 | 2 | 报文长度 `len`，大端无符号 |
| 2 | `len` | 一个完整的 IPv4 报文，`20 <= len <= MTU` |

约束：

- 长度前缀固定 2 字节，最大帧为 `2 + MTU`；本切片 `MTU ∈ [576, 1500]`，故最大帧 1502 字节。
  实际 `MTU` 还必须不超过电路建立时捕获的 hop 会话 `mtu_cap`；本切片只保证 **hop-local 上限**足够，
  远端出口 PMTU 探测/报文回执属于后续切片，不在本候选内。一行说明：`MTU = min(runtime 选择, circuit.mtu_cap())`。
- 一帧一包，不允许合并、不允许空帧、不允许同一帧内出现两个包。
- `len == 0` → 空帧拒绝；`len > MTU` → 帧过大拒绝；实际字节数与 `len` 不一致 → 长度不匹配拒绝。
- 前缀读到一半遇到 EOF 是"截断帧"，不是干净关闭；只有"帧边界处 EOF"才是干净关闭。
- 候选编码只在 E2E TLS 之内使用；它不替代任何逐跳控制帧，也不复用 `RelayFragment` 的 payload 语义
  （实际上单帧 1502 字节可被单个 `RelayFragment` 承载，但这是实现巧合，不是协议要求）。

## 3. 方向与授权

两个方向都要求"精确 /32"，不存在网段、默认路由或第三方地址：

| 方向 | 源地址 | 目的地址 |
| --- | --- | --- |
| host → peer（`step_outbound`） | 本端永久 VIP | 对端永久 VIP |
| peer → host（`step_inbound`） | 对端永久 VIP | 本端永久 VIP |

其它一律拒绝（`PacketDeny::SourceNotLocal` / `DestinationNotPeer` / `SourceNotPeer` / `DestinationNotLocal`）。
IPv6 未协商，一律 `Ipv6NotNegotiated`；未知版本 `UnknownVersion`；结构/长度/校验和由
`boreas_tun::inspect_packet` 校验，失败分别映射为 `Truncated` / `BadLength` / `BadChecksum` / `BadHeader`。
超过 MTU 的报文在解析之前就被 `MtuExceeded` 拒绝。

## 4. 端点来源（不可由调用者声明）

端点只能来自电路本身：

- 对端身份 = `E2eCircuit::info().peer`，其值在 E2E 握手完成时与已验证 TLS peer 做过精确相等比较；
- 本端身份 = `E2eCircuit::local()`，在电路建立时从已认证的 hop 会话 `EstablishedSession::local()` 捕获，
  为此在 `e2e.rs` 增加了私有字段与该只读访问器（`E2eInfo` 未改动）；
- 永久 IPv4 由 `(node_id, role)` 确定性推导：`10.20.<home_core>.<vip_octet>`，
  `node_id = ((home_core - 1) << 8) | vip_octet`，Core 要求 `vip_octet == 1`，Edge 要求 `2..=251`，
  EnrollmentService 无 VIP。该推导复现 `boreas-pki` 的永久槽位规则，用于在没有 PKI 依赖的构建里做 L3 绑定校验；
  **它不替代**对签名 `NodeIdentity` 的验证，运行时仍须由 PKI 层确认签名对象的 VIP 与该值一致。

因此不存在 `authenticated: bool` 入参、调用者自报的 local 身份、或可被替换的地址表。

## 5. 失败语义（fail closed）

- 任一解析、授权、写线或写入主机队列失败：路径 poisoned，**当步立即丢弃已建立的 E2E 电路流**（`circuit: Option<C>` 置 `None`），
  后续两个方向都返回 `Poisoned`；不重试、不改路、不静默丢包。
- 对端在帧边界干净关闭：视为业务终止，路径关闭并同样立即丢弃电路，不再允许任何方向的收发。
- 主机侧队列满：本切片无重试缓冲，按失败关闭处理（`HostQueueFull`），不静默丢包。
- 计数器只记录包数/字节数/拒绝数，不记录载荷。

## 6. 明确未集成

- **FreshStatus / 撤销 / 时钟 / 代次**：由独立 status-store 切片实现，本适配器不接入、不复查、不缓存；
  不得据此声称 `G-REVOKE`、`G-E2E` 或 `G-DATA`，也不得作为 1 GiB 或多流生产证据。
- 阻塞 I/O 的取消/poll 驱动：由未来 daemon owner 的单线程循环负责；本切片只提供单步 API。
- IPv6、子网路由、默认路由、多跳转发、GSO/offload、分片重组、TTL/ICMP。

## 7. 待评审问题

1. 长度前缀是否需要登记为正式 L3 capability？固定 2 字节与可变长度编码的取舍。
2. MTU 的权威来源：已实现为 `MTU = min(runtime 选择, circuit.mtu_cap())`，并校验 `[576, 1500]`；
   `mtu_cap` 来自 hop 会话协商值（hop-local 上限）。远端出口 PMTU 仍待后续切片，不在本候选内。
3. 适配器应拥有 `E2eCircuit` 还是借用（当前为拥有，失败即 drop）。
4. 主机队列满时是否需要有限重试（当前 fail closed）。
5. 状态许可接口形态：daemon owner 应在构造前取得何种不可伪造的 `FreshStatus` 能力。
6. 是否需要把每方向计数器暴露为管理面快照字段。

## 8. 固定示例

`len = 0x0014`（20 字节 IPv4 头，无载荷，`src = 10.20.3.1`，`dst = 10.20.3.9`）：

```text
frame = 00 14 45 00 00 14 00 00 00 00 40 11 <csum> 0a 14 03 01 0a 14 03 09
```

`len = 0` 的帧 `00 00` 为非法；`len = 0x05dd`（1501 > MTU 1500）为非法；`00 05 01 02 03`（声明 5 实际 3）为非法。