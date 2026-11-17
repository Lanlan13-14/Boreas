# Prefix runtime: 最小可实现纵切

## 决策

下一步**只把当前默认 prefix 从已独立验证的 policy 上下文传递到 signed identity → packet policy**；本纵切不开放 custom prefix，不配置设备，也不更改默认地址。默认 `10.20.0.0/16`（policy 表示为 `[10,20,0,0]`）保持现有行为。显式拒绝任何不匹配该默认值的已验证 policy，直到端到端可用性具备条件；不以 caller boolean、环境变量或未经签名配置表达信任。

这不是无限孤立 policy parser：落地目标是让真实的已认证 packet path 消费一个携带 prefix 的、不可伪造的上下文；本次可实现切片以默认值贯通并验证拒绝条件，后续切片才允许非默认 prefix。

## 当前证据与缺口

- `crates/boreas-pki/src/network_policy.rs` 的 `verify_network_policy(raw_tbs, ed25519_signature, mldsa65_signature, pin, expected_net_id, now)` 检查 candidate、net、独立 pin 指纹、时间和双签名，产出私字段 `VerifiedNetworkPolicy`，其中含 `overlay_base`。源码注释明确 token 本身没有 durable freshness/rollback protection。
- `crates/boreas-pki/src/network_policy_store.rs::commit` 以 token + 精确原始 TBS 记录单调 sequence/冲突状态；store 的读取不会重新构造授权 token，也不等价于当前可信授权上下文。
- `crates/boreas-cli/src/pki_cmd.rs` 的 `verify_policy` 直接从 `--root-ed25519-der`、`--root-mldsa65-der` 构建 `NetworkRootPin`（约 453–467 行），输出也标注 `pin_provenance=operator-supplied; verify independently`、`clock=local-untrusted`、`prefix_active=false`（约 509–522 行）。这是诊断/录制，不是 daemon runtime policy loader。
- `crates/boreas-tunnel/src/openssl_inner_tls.rs::VerifiedNodeIdentity::from_verified_object`（约 223–281 行）验证身份 net id、VIP 与永久 slot；当前 `boreas_pki::expected_vip(home_core_id, vip_octet, role)` 的 prefix 是固定默认值，身份解析 API 未接收 policy 上下文。
- `crates/boreas-tunnel/src/packet_path.rs::EndpointFacts::from_verified_identity`（约 304–328 行）用本地 `permanent_vip(node_id, role)` 重建地址；注释写死 `10.20.<home_core>.<vip_octet>`（约 307–313 行），`permanent_vip` 与 `is_permanent_vip` 亦为硬编码规则。`AuthorizedEndpoints::bind`（约 500–525 行）只校验 identity 相互一致与 VIP 唯一，不检查 policy prefix。
- Tunnel 的 `openssl-inner-tls` feature 才连上 `boreas-pki` 的 OpenSSL 后端（`crates/boreas-tunnel/Cargo.toml`）；无 backend 的默认 build 不能创建 TLS session。不能把 default-build 可用误报为已启用实际 VPN。

## 下一可直接实现的最小纵切（建议一个 PR）

### 1. 构造明确的 verified policy context

在 `crates/boreas-pki/src/network_policy.rs` 增加一个由 `verify_network_policy` 成功后才能构造的 opaque `VerifiedNetworkContext`（或将现有 `VerifiedNetworkPolicy` 明确作为它，避免重复类型）。至少携带 `net_id`、`root_key_fingerprint`、`overlay_base`，并保留版本/sequence/validity；不提供 public 字段构造器。它必须关联精确 raw TBS（现有 Linux `object_hash` 机制可复用，但需要跨平台的不可混淆 token→TBS 绑定策略）。

在 `crates/boreas-pki/src/lib.rs` re-export 该上下文。调用方仍必须传入 `NetworkRootPin`、期望 net id 和可信时钟；不得用“already verified”bool 或只从 store 读 prefix 来代替验证。在线 runtime 用的独立 pin 必须来自可信本地 provisioning / operator trust store，而不是与 candidate 同包、同源可替换的配置。

### 2. 先验证当前实现仅支持默认 prefix

新增 `VerifiedNetworkContext::require_runtime_prefix()`（或等效 typed conversion），仅接受 `[10,20,0,0]`，不匹配返回明确 `UnsupportedRuntimePrefix`。这把签名 policy 的有效性与 runtime 支持能力区分开：其他 prefix 可被 parser/verify 工具验证和存储，但不得进入活动身份/packet path。

### 3. 把上下文贯通身份与 packet policy

在 `crates/boreas-tunnel/src/openssl_inner_tls.rs`：

- 将 `VerifiedNodeIdentity::from_verified_object(object)` 迁移为 `from_verified_object(object, policy: &VerifiedNetworkContext)`（若保留旧签名，旧入口必须只承载 legacy default 且不能参与 runtime circuit 建立；不应出现绕过上下文的公共入口）。
- 首先检查 `object.net_id/body.net_id == policy.net_id()`；以 `policy.overlay_base()` 为 `expected_vip` 的 network/prefix 参数计算 VIP，并继续校验签名对象声明 VIP 精确相等、node id mapping/role/generation/key 等既有不变量。
- `VerifiedNodeIdentity` 内保存 policy context 身份（至少 net id + policy fingerprint/version/hash，或者可 clone 的 opaque context），避免后续路径意外混用不同 policy。

`crates/boreas-tunnel/src/packet_path.rs`：

- `EndpointFacts::from_verified_identity(identity, policy)` 由该 context 派生地址，移除/参数化 `permanent_vip`、`is_permanent_vip` 中的 `10.20` 常量；prefix 地址校验应验证 host slot 与角色规则，而非仅检查默认网段。
- `AuthorizedEndpoints::from_e2e_circuit` 将 circuit 两端身份与同一 policy context 绑定；`bind(..., policy)` 验证两端 context 相同、net id 相同，再生成 endpoints。Mismatch fail closed（例如 `PolicyMismatch`），不能接受两个各自有效但不同 prefix/net 的身份。
- 地址及包源/目的校验所用 prefix 来源只能是 endpoint facts/context，不从 packet/caller 参数另行注入。

### 4. runtime/CLI 接线边界

`crates/boreas-cli/src/daemon.rs` 是已验证管理对象转换成 tunnel identities 的候选接线点（当前约 648–655 行调用 `VerifiedNodeIdentity::from_verified_object`）。但本次不应把 policy CLI 的 operator-supplied 诊断 pin 静默接到 daemon；先新增明确的 daemon runtime policy input/provider，其值必须由独立 pin + 当前双签 policy verification 得到。若显式请求 policy-bound 模式但没有已信任的独立 pin 来源，该模式必须拒绝启动/建立 E2E circuit；现有 legacy-default 模式保持现有兼容行为并明确未绑定策略，不得被静默解释为 policy-bound。不得以未签名 `prefix` 配置放行非默认前缀。

`crates/boreas-cli/src/pki_cmd.rs::verify_policy` 保持诊断语义：默认 policy 能 verify/record 仍不代表 active。可增加明确的 `runtime_supported` / 默认前缀检查输出，但禁止把 `prefix_active` 改成 true，除非 daemon 的实际消费路径已完成。

## 测试迁移清单（测试建议，不在本交付运行）

1. 保留默认兼容：签名的 `[10,20,0,0]` policy + 匹配 `NodeIdentity`，得到与现在相同的 `10.20.<core>.<slot>` VIP；同样 node id/role 的永久 slot 和 packet allow 行为不变。
2. 拒绝 prefix mismatch：独立 pin 双签 `[10,21,0,0]` policy 验证本身可成功，但 `require_runtime_prefix`、VerifiedNodeIdentity runtime 构造和 endpoint 构造均拒绝；不能因身份仍是默认 VIP 而旁路。
3. 拒绝身份不一致：policy net id 不同、identity net id 不同、signed body VIP 对 policy 派生地址不匹配、role/node id 错配均 fail closed。
4. 拒绝 endpoint 混淆：两身份来自不同 policy hash/version/prefix（即便 net id 相同）不能绑成一个 circuit；拒绝默认/非默认混接。
5. token 来源：无 `VerifiedNetworkContext` 无法调用 runtime identity/packet 入口；伪造 caller boolean、单独配置 prefix、从 store 重建 token 均不可通过类型/API。
6. CLI 保持 `prefix_active=false`；只 verify/record 不会启动/改变 TUN。

## 最终启用 custom prefix 仍缺的工作（不可在此切片宣称已支持）

- **可信 roots/pin provisioning：** 当前 CLI pin 是 operator-supplied 原始 DER，输出要求 independent verify；当前 roots bundle 是身份与状态 issuer 授权材料，尚未证明它承载并独立固定 NetworkRoot pin。必须定义受保护、独立的 NetworkRoot pin 安装/轮换/恢复机制，及 roots bundle 与 policy signing trust 的明确绑定；否则同包替换导致 self-authentication 风险。
- **持久新鲜度/防回滚：** policy token 有声明时间，store 可 durable commit 序号/冲突，但 runtime 每次启动和续期要用可信时钟重新验证当前双签 policy、检查 durable state/sequence/freeze，并在过期或状态不可读时 fail closed；需定义离线恢复与 rotation。
- **身份签发/管理协议：** `NodeIdentity.vip` 当前签发校验由固定 `expected_vip` 约束。IdentityAuthority 模板、配置/签发入口及对象验证必须接收同一已授权 prefix policy，证明签名 identity 的 VIP 真由该 prefix 推导；不可仅在接收端重新解释旧 identity。
- **实际 TUN 地址与路由：** `crates/boreas-tun` native adapter 当前管理设备/MTU，不安装生产路由。需要为 Linux/Windows/macOS 正确配置设备地址、掩码、路由、冲突/清理、权限与崩溃恢复，并审计 host route leaks；prefix 由同一 runtime context 驱动。
- **DNS：** split DNS/域名记录、解析器绑定、搜索域、缓存失效、重绑定防护和 resolver 路由需定义。DNS policy 需与当前 network context 绑定，不可独立落后或暴露到宿主默认网卡。
- **peer negotiation：** 版本化 wire 协议须协商并认证 net id、policy sequence/hash/prefix（或更妥善只协商 policy digest），在双方不一致、旧 peer、降级/重放时拒绝；不得信任对端口头提供的 prefix。
- **跨路径验收：** daemon reload/轮换、已有 circuit 失效、权限、平台差异、升级/回滚、端到端测试和可运维诊断完成后，方能把非默认 prefix 标作 supported。

## 范围与验证说明

此文档是实施设计，不含源码改动。按要求未运行 local tests/build/syntax/formatter；未 commit/push。