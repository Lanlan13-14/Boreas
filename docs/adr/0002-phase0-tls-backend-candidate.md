# ADR 0002：Phase 0 内层 TLS 1.3 后端与套件候选（OpenSSL 3.6.1 + rust-openssl）

- **状态：Proposed（Candidate）——未 Accepted、未 Frozen。**
- 日期：2026-11-15
- 适用计划：[BOREAS Master Plan v1.11.0](../plans/BOREAS-MASTER-PLAN-v1.11.0.md)，主要为 §1.1、§2.3、§4、§6.1–§6.2、第十一节 Phase 0 与 `G-CRYPTO`
- 关系：不替代 [ADR 0001](0001-phase0-foundation-and-tls-blocker.md)。ADR 0001 确定的「无后端选型、无线格式冻结」边界在其被后续 Accepted ADR 明确替代前继续有效；本文只把候选、证据边界与接受条件写死。
- 证据依据：[2026-11-14 密码/TLS 后端能力核查](../research/phase0-crypto-backend-assessment-2026-11-14.md)、[2026-11-15 TLS 双实现后端调研](../research/phase0-tls-backend-interop-2026-11-15.md)。两文均为源码级/同实现 PoC 级观察快照，不是本 ADR 作者复跑的互操作或静态构建证据。

> **诚实性声明（强制）**：当前证据不足以「冻结」后端。本文出现的版本号、代码点与构建方式一律是**候选决定**，只有在 §7 全部接受条件以可复现产物留证后，才可另行修订为 Accepted。在此之前，任何文档、CLI/TUI、测试命名或代码注释都不得据此宣称 `G-CRYPTO` 通过、后端已冻结、双架构静态发行可行，或逐跳/E2E 内层 TLS 已在产品中可用。未验证事项在本文以 `[待证]` 标记。

## 1. 背景

主计划 §4 已裁决：自研 PQ-IK / Pairwise / `0x22 outer_mac` 退出生产规范，节点间机密性与认证改由标准 TLS 1.3（逐跳内层 + `e2e-required` 时再叠加端到端内层）承担；且已点名 v1.10 锁定的 rustls 0.23.35 默认 aws-lc provider 不含 ML-DSA 验签映射，不能当作满足 v1.11 的生产后端。Phase 0 必须：

1. 冻结 TLS 后端与版本、混合 KEX 组、ML-DSA 签名方案草案版本与代码点、AEAD 白名单；
2. 在同进程内跑通外层 HTTPS/WSS 承载之上的逐跳内层 TLS，内外层分开判定；
3. 用独立维护的第二实现互操作（同实现自测不计）；
4. 证明 Linux `x86_64` 与 `aarch64` 双架构静态构建并在本机握手；
5. `pq1024` 单独 PoC，未完成不得开启。

仓库当前候选实现位于 `boreas-crypto`（本 ADR 编写期间由他线修改中，本文只读引用调研快照，不对其正确性背书）。其 `Cargo.toml` 已声明 `openssl = "=0.10.82"`、`openssl-sys = "=0.9.118"` 的 optional feature `openssl-backend`；`tools/crypto-poc/run-openssl-mtls.sh` 与 CI 仅完成过 OpenSSL CLI 同实现 mTLS 冒烟（含一次客户端证据行、服务端断言与 depth 留证修正待重跑，见 2026-11-14 核查 §5）。这些都是候选的出发点，不是接受证据。

## 2. 一手标准状态（观察快照：2026-11-14/15，冻结前必须复核）

| 项目 | 观察到的状态 | 代码点 / 标识 | 本文用法 |
|---|---|---|---|
| TLS 1.3 | `[事实]` `RFC 9846`，2026-07 发布，取代 RFC 8446；含临时 `key_share` 不得跨连接复用、`KeyUpdate` 与 AEAD 使用上限要求 | TLS 1.3 cipher suite 见下 | 内层唯一版本基线 |
| Hybrid KEX | `[事实]` `RFC 10024`，2026-08 发布，TLS 1.3 混合密钥交换 | `X25519MLKEM768 = 0x11EC (4588)`；`SecP256r1MLKEM768 = 0x11EB (4587)`；`SecP384r1MLKEM1024 = 0x11ED (4589)` | `pq768` 只开 `0x11EC`；`0x11ED` 仅属 `pq1024` 独立候选 |
| ML-DSA X.509 | `[事实]` `RFC 9881`，2025-10 发布，定义 ML-DSA-44/65/87 在证书/CRL 中的 AlgorithmIdentifier/OID | RFC 9881 OID（由证书层校验，不由字节长度猜） | 身份证书编码与链校验基线 |
| ML-DSA in TLS | `[事实]` `draft-ietf-tls-mldsa-06` 仍是 Active Internet-Draft，IESG state `RFC Ed Queue`、RFC Editor `Awaiting First editor`（2026-11-15 datatracker 观察，过期日 2027-03-15）。**不是 RFC** | `mldsa44 = 0x0904`、`mldsa65 = 0x0905`、`mldsa87 = 0x0906`（IANA `Recommended = N`） | `pq768` 只开 `mldsa65 (0x0905)`；`0x0906` 仅属 `pq1024`；`mldsa44` 不在本项目候选内 |
| AEAD（TLS 1.3 cipher suites） | `[事实]` RFC 9846 标准套件 | `TLS_AES_256_GCM_SHA384 = 0x1302`、`TLS_CHACHA20_POLY1305_SHA256 = 0x1303` | 仅此两套，按平台配置偏好；AES 路径须同时核 GHASH 加速（`CLMUL`/`PMULL`） |
| 术语 | `[事实]` RFC 9794 | — | 本版 TLS 认证如实称为纯 PQ `ML-DSA` 认证，不冒称复合双认证（主计划 §2.3） |

来源逐项见两份 research 的一手链接表（RFC Editor / IETF datatracker / 固定 tag 源码）。**冻结动作当天**必须重新打开 datatracker 与 RFC Editor 核对草案是否已发布为 RFC、代码点/语义有无变更，并把抓取时间与页面状态写入接受记录；若正式 RFC 与 `-06` 分叉，先改 ADR 再改代码。

## 3. 候选决定（全部待 §7 接受，非冻结线）

### C-1 主后端候选：OpenSSL 3.6.1 + `openssl 0.10.82` / `openssl-sys 0.9.118`

- `[设计·候选]` 产品主实现候选为固定 tag `openssl-3.6.1`（release tarball SHA-256 `b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e`，2026-11-14 核查记录）经 Rust `openssl 0.10.82` / `openssl-sys 0.9.118` 绑定集成，策略集中在 `SslContextBuilder` 一层下发。
- `[事实·调研快照]` 2026-11-15 调研逐个核到该绑定对下列控制点的源码级入口：`set_min/max_proto_version(TLS1_3)`、`set_groups_list`、`set_sigalgs_list`、`set_ciphersuites`、证书链/私钥加载、`SslVerifyMode::PEER | FAIL_IF_NO_PEER_CERT`、`set_verify_callback`、`NO_TICKET`、`set_num_tickets(0)`、`set_session_cache_mode(OFF)`、`set_max_early_data`、`PKey::is_a(KeyType::ML_DSA_65)`（ML-DSA 无经典 `Id`，不得用 `id()` 判算法）。**API 存在不等于握手正确**：全部须以 §7 实测收口。
- `[待证]` OpenSSL 3.6.1 非 LTS 分支的支持窗口、4.x 存在下继续钉 3.6.1 的支持期与安全通告跟踪、以及每次发布的可复现输入更新流程，须在接受时按主计划 §10.2 写清；钉版是每次发布的输入锁定，不是永久锁死。

### C-2 严格内层策略（`pq768`，Fail-Closed）

逐跳内层与 Phase 5 的 E2E 内层共用同一严格策略（主计划 §4.2、§7.1）：

- 仅 TLS 1.3（`min = max = TLS1_3`）；仅组 `X25519MLKEM768 (0x11EC)`；仅签方案 `mldsa65 (0x0905)`（依 draft-06）；仅两套 AEAD `TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`。
- 双向认证：已注册节点互验 ML-DSA X.509（RFC 9881）证书与 `CertificateVerify`；握手成功仅证明通道认证，应用授权另行精确校验 `net_id`、角色、`NodeID`、`identity_generation`、`scope` 与期望对端（主计划 §5.2）。
- 首版禁用 0-RTT / PSK-only / 跨节点共享 resumption state：候选实现手段为 `NO_TICKET` + 服务端 `set_num_tickets(0)` + session cache `OFF` + 服务端 `set_max_early_data(0)` + 后端不暴露 early-data 读写与 PSK 回调。每一项都要以负测（尝试恢复/早数据须失败）取证，不能只查「没调某个 API」。`[待证]`
- 对端不支持上述任一项或协商失败即断开并计数；严禁退化 `X25519-only`、纯经典 TLS 或 `hop-only` 明文业务。
- 内层 SNI 仅非秘密网络级名称；`ClientHello` 不放 `NodeID`、邀请秘密或稳定用户标识。
- 外层 HTTPS/WSS 按主计划 §6.1 与内层解耦判定：CDN 外层经典协商不判内层失败，外层 hybrid 也不替代内层认证；两层协商参数分别记录。

### C-3 `pq1024` 只登记、不启用

`SecP384r1MLKEM1024 (0x11ED)` + `ML-DSA-87` / `mldsa87 (0x0906)` 只作为独立套件候选登记。未完成其独立双实现 PoC 前，后端配置面、CLI 与部署模板都不得可开启该套件（保持现有默认关闭），更不得自造任何 “X-Wing-1024” 组合器。`[待证]`

### C-4 禁止 `vendored`，走自建 OpenSSL 注入

- `[事实·调研快照]` 当前钉版的 `vendored` 链为 `openssl-sys 0.9.118 → openssl-src 300.2.0 (features=["legacy"])`；据 openssl-src 版本规则与 tag 命名，其内置版本是 OpenSSL **3.2.0**，且附带 legacy provider，与本文候选的 3.6.1 固定 tag、最小 provider 面均不一致（该结论基于 tag/README 级证据，接受时应直接展开该 crate 源码复核一遍后归档）。
- `[设计·候选]` 因此 `openssl-backend` 启用时**不得叠加 `vendored`**；静态构建改走：先按固定 tag + tarball 哈希自建 OpenSSL 3.6.1 `no-shared`（仅激活内建 default provider 的最小 `openssl.cnf`），再以带 target 前缀的环境变量注入 rust-openssl 的正常发现路径：`<TARGET>_OPENSSL_DIR=<prefix>`、`<TARGET>_OPENSSL_STATIC=1`，并加 `OPENSSL_NO_VENDOR=1` 双保险。CI 须加负断言：仓库 manifests 与最终构建命令中出现 `vendored` 即失败。`[待证]`（尚未在双架构 job 上执行）
- 同理禁止用系统默认 CA 路径（`set_default_verify_paths` 一类）充当内层信任根：内层只认 provisioning 写入的 Boreas 根锚（主计划 §2.4）。

### C-5 静态双架构候选要求（发行形态未证）

候选发行目标为 Linux `x86_64-unknown-linux-musl` 与 `aarch64-unknown-linux-musl` 全静态单一二进制。接受证据必须同时满足（缺一即不得称静态可行）：

1. 区分两件不同的事：OpenSSL `no-shared` 产出的 `.a` 静态库 **不等于** 全静态 libc 二进制。最终 ELF 须逐架构以 `file`/`readelf -d`（及等价 loader 检查）证明无动态解释器、无 `libssl.so`/`libcrypto.so` 及意外动态依赖，并记录 provider/配置的实际装载来源（禁止运行时再去载未审计的 provider 模块文件）。`[待证]`
2. 两架构都在**原生 runner** 上真实执行握手矩阵；交叉编译通过或 QEMU 单次成功不代替 aarch64 本机运行与内存/性能记录（主计划 Phase 0、§8）。`[待证]`
3. 记录每架构的：key_share/证书/签名尺寸、握手 CPU 与墙钟、峰值内存、GHASH 指令检测结果（`CLMUL`/`PMULL`，不得只报 AES 指令）、失败样本。`[待证]`
4. `openssl-sys` build 的环境变量一律用带 target 前缀形式，防止误链宿主机 OpenSSL；构建镜像 digest、工具链、target triple 与 `Cargo.lock` 一并归档。`[待证]`

### C-6 第二独立实现候选（只作互操作对端，不进产品）

- `[设计·候选]` 首选 GnuTLS 3.8.13（`--with-leancrypto`，leancrypto/Nettle 小版本须钉死）：调研在其固定 tag 源码核到组 `0x11EC`、TLS 签方案 `0x0905` 与 server/client `CertificateVerify` 接线，血统与维护方与 OpenSSL 独立。并跑 Go（调研观察为 go1.27.4）标准库 `crypto/tls` 小对端作低成本异栈交叉互检；wolfSSL `v5.9.4-stable` 列可选第三候选（构建闸多、ML-DSA 默认关）。以上**均为源码级判定、零实测握手**，priority string/配置逐字与证书互读（含 ML-DSA 私钥 seed/expandedKey/both 三种格式语义）皆为 `[待证]`。
- `[设计]` BoringSSL/AWS-LC 与 OpenSSL 同谱系，不单独记作「独立实现」；rustls 0.23.46 + aws-lc-rs 1.19.0 在调研中算法面源码级补齐（旧 0.23.35 的阻塞结论不得外推到该版本），仅登记为 Rust 备胎 PoC-B，与主路径二选一，未经新 ADR 不并行出厂、也不与 OpenSSL 路径同时宣称产品后端。

## 4. 明确禁止（违反任一条即判定不合格）

1. 自写 TLS 签名扩展、私有代码点、自造混合组合器，或回退 PQ-IK / Pairwise / 经典-only 握手凑上线。
2. 把同实现自测（OpenSSL `s_server`↔`s_client`、同后端两端点自连）计作独立互操作证据。
3. 把配置意图（setter 调用成功、配置字符串里写了组名/套件名）计作协商事实（见 §5 证据分级）。
4. 在内层开启 0-RTT、session tickets、session cache、PSK-only，或握手失败时降级经典组/经典签名/`hop-only` 业务。
5. 用签名/公钥字节长度推断 ML-DSA 参数集；用 `pkey.id()` 等经典 `Id` 判 ML-DSA（须 `is_a(KeyType::…)` 或等价 provider 名称判定）。
6. 启用 `vendored` 拉取与候选不一致的 OpenSSL；在日志/artifact 中保存测试私钥、原始 TLS 输出中的 Resumption PSK 或会话秘密（留证须走 allowlist 脱敏，如现有 PoC 脚本纪律）。

## 5. 协商参数证据边界（本 ADR 的核心约束）

### 5.1 已知限制：当前绑定不能直接读出全部协商结果

`[事实·调研快照]` 2026-11-15 调研对 `openssl 0.10.82` / `openssl-sys 0.9.118` 的结论（本文未独立复检源码，接受时须对最终锁定版本复检并更新本节）：

- **协商 group 无安全层 getter**：安全层只有 `set_groups_list` 等 setter，未见 `SSL_get_negotiated_group` 一类封装；sys 层手写绑定只有 `SSL_ctrl`/`SSL_CTX_ctrl` 通用入口。即后端目前**不能**用类型安全 API 直接读出「本次握手实际协商组 = `0x11EC`」。
- **对端 `CertificateVerify` 签方案（peer sigalg）同样无直接 getter**；`set_sigalgs_list` 只约束 `signature_algorithms` 的发送面，且不覆盖 `signature_algorithms_cert`（证书链签名算法面未在该绑定暴露 setter）。全链算法收窄只能靠 verify 回调逐张核证书 SPKI 与签名 AlgorithmIdentifier 补做。
- 能直接读出的仅：协商 TLS 版本（`version2()`）、生效 cipher suite（`current_cipher()`）、对端证书对象（`peer_certificate()`）。`session_reused` 在安全层的可见性以最终 tag 为准，调研与现有候选实现之间尚有出入，须在评审中二选一并留证；若走 `unsafe` FFI（如 `SSL_session_reused`），FFI 的所有权约定必须写进 unsafe 审查记录。
- 没有独立的「禁用 0-RTT」布尔开关：0-RTT 关闭靠服务端 `set_max_early_data(0)` + 不暴露 early-data API + tickets/cache 全关的组合，须逐项负测，不能以字段常量 `false` 代替协商读数。

### 5.2 证据分级：什么算「已证明」，什么只算「有据推断」

为杜绝把 config 推断写成已证明，协商参数的对外表述强制分三级，代码日志、状态文档与门禁记录必须注明级别：

| 级别 | 定义 | 例 | 可否写「已协商/已验证」 |
|---|---|---|---|
| E1 直接读数 | 握手后从本次会话对象直接读出的协商结果，或抓包解码的线格式数值 | `version2()=TLS 1.3`、`current_cipher()=0x1302`、pcap 中 `ServerHello.key_share.group=0x11EC`、`CertificateVerify.algorithm=0x0905` | 可以 |
| E2 白名单交集推断 | 本地仅提供单组/单 sigalg 且 TLS 1.3 语义保证协商结果必为交集成员、加握手成功事实推得 | 「只 offer `X25519MLKEM768` 且握手成功 ⇒ 协商组必为它」；「对端叶证书 `is_a(ML-DSA-65)` 且 `signature_algorithms` 只发 `mldsa65` ⇒ CertificateVerify 必为 `0x0905`」 | **不可以**。只能写「由 E2 推断」，且必须同时展示 offer 面与证书算法事实 |
| E3 配置意图 | setter 返回成功、配置字符串、常量字段 | `set_groups_list("X25519MLKEM768")` 调用成功、`zero_rtt: false` 常量 | 不构成任何协商证据 |

**候选实现中的既知 E2/E3 形态（须在实现评审中逐条处置，本 ADR 不预先追认）**：2026-11-15 调研 §6 记录了同期出现的候选 `backend.rs` 三处形态——(1) 协商组以「单组 offer + key_share 取交集」论证回填、peer sigalg 以对端证书算法回填；(2) `session_reused` 经 `unsafe` FFI 读取；(3) `zero_rtt` 以「未暴露 early-data API」常量表达且当时未见服务端 `set_max_early_data(0)`。这三处在逻辑上各有成立条件，但在证据分级上分别属 E2、实现形态待审、E3。**冻结本后端的接受路径只有两条，二选一并写入接受记录**：

- **路径 A（首选）**：补齐 E1 读数通道（经受控 `openssl-sys` FFI，例如 `SSL_ctrl(SSL_CTRL_GET_NEGOTIATED_GROUP)` 的可行性验证、peer sigalg 的等价可读面）或以抓包解码补 E1；FFI 须通过 unsafe 审查并对每个握手断言组=`0x11EC`、sigalg=`0x0905`、版本=1.3、套件∈白名单后才喂应用层策略校验。
- **路径 B（受限）**：若确无可行的 E1 通道，须在接受修订中把 E2 交集论证的前件逐项写成可执行断言（offer 面能被代码与配置共同证明为单元素、对端整条证书链算法逐张核完、关恢复/0-RTT 的组合开关逐项核完并负测失败关闭），并以独立实现互操作一方的 E1 日志交叉印证同一连接。E2 结论在 UI/遥测文案中必须带「inferred」限定词，不得显示成实测算法（主计划 §10.4「诚实的状态显示」）。

同理，安全等级（`set_security_level` 等）这类全局闸若与 ML-DSA 安全位数有关联，取何值须在后端评审中写明理由与正负测，不得无声写低值绕过拒绝。

### 5.3 与应用层校验的衔接

协商读数（无论 E1 或合规 E2）只是通道层事实。业务放行还须依次过：完整证书链与 RFC 9881 OID/用途校验 → `net_id`/角色/`NodeID`/`identity_generation`/`scope` 与期望对端绑定（主计划 §2.2「先验权限、后验签名」）→ `SessionHello`/`SessionAccept` 应用授权（§5.2）→ 吊销/状态快照新鲜度（§3.4）。任一步缺失，后端都不得以「握手成功」放行业务帧。

## 6. 风险与后果

| 风险 | 影响 | 缓解（候选） |
|---|---|---|
| `draft-ietf-tls-mldsa-06` 在 RFC 发布时文本/代码点生变 | 五个生态当前共用的 `0x0905` 前提同时动摇 | 冻结时钉死 `-06` 与代码点；RFC 发布日强制回归 + 新 ADR；禁止私有代码点绕开 |
| negotiated group / peer sigalg 无 E1 读数 | 「不得由 config 假设协商」（2026-11-14 核查 §1）的验收口径直接落空 | §5.2 路径 A/B 二选一收口；收口前本 ADR 保持 Proposed |
| `vendored` 误启用回落 OpenSSL 3.2.0 | 能力证据被偷换、legacy provider 扩大信任面 | `OPENSSL_NO_VENDOR=1` + CI `vendored` 负断言 |
| ML-DSA 私钥格式代际差（seed/expandedKey/both） | 跨实现互读失败（最可能的前锋失败） | 互操作矩阵对三种格式各测一轮；产品密钥格式在接受时钉一种并写明生成工具版本 |
| OpenSSL 3.6 非 LTS 支持期 | 接受后短期内被迫换版 | 接受记录写支持截止与更新流程；安全通告不受 Phase 边界限制（主计划 §1.1 同类原则） |
| 同谱系冒充独立 | `G-CRYPTO` 交叉验证可信度虚增 | 第二实现只认独立血统（GnuTLS/Go/wolfSSL）；rustls 引用时标注其 AWS-LC 底座来源 |
| 敏感材料外泄 | 测试私钥/PSK 进 artifact 污染证据包 | 沿现有 PoC 的 allowlist 脱敏与临时目录纪律；旧含 PSK 的 artifact 不得再引用 |

正面后果（若 §7 通过）：候选路径一次收敛主后端与第二实现，避免双栈分散；严格白名单与失败关闭与主计划 §4 一致。负面后果：FFI 读数与双架构真机两道硬关可能迫使候选返工——这是 Phase 0 的预定结论之一，不得以赶工为由降成 E3 自证。

## 7. 接受条件（Proposed → Accepted 的判据）

下列条目**全部**以可复现命令、版本、产物与失败样本留证后，方可开 ADR 修订把状态改 Accepted；任一未过则保持 Proposed，且不得开启 `pq1024`。每条注明对应的计划门禁口径。

1. **标准状态复核留档**：冻结当日复核 RFC 9846/10024/9881 与 `draft-ietf-tls-mldsa` 最新状态（若已成 RFC 则记录新 RFC 号与差异），写明代码点表与 RFC 发布后的升级评审触发条件。
2. **同进程双层握手**：外层 HTTPS/WSS 与 WebSocket 二进制字节流上的逐跳内层 TLS 在同一进程跑通；WS 消息任意分割/合并不影响 TLS 字节流；内外层协商参数分开记录（`G-CRYPTO` 核心）。
3. **双向 ML-DSA 认证 + 两 AEAD 矩阵**：两 AEAD 各自独立握手并传输多记录载荷；双端均呈交证书与 `CertificateVerify`；证书按 RFC 9881 编解码并核整条链 OID/用途。
4. **协商参数 E1/E2 收口**：按 §5.2 选定路径 A 或 B 并逐连接断言；日志与 UI 口径区分证据级别。
5. **负测失败关闭全集**：仅经典组、移除 ML-DSA 能力、错 OID/坏链、错角色/跨 `net_id`、缺客户端证书、AEAD 无交集、TLS 1.2/回退尝试、0-RTT/PSK/票据恢复尝试、过期证书——全部拒绝且日志含预期拒绝原因（非超时/设置错误冒充拒绝）。
6. **独立互操作矩阵**：{Rust 后端 ⇄ GnuTLS} 与 {OpenSSL CLI ⇄ Go}（或经评审的等价独立组合）双向互换 server/client × 两 AEAD × 同一 ML-DSA-65 证书链；每方独立输出组/套件/sigalg（含 E1 读数一方交叉印证）。同实现自测另列，不计分。
7. **双架构静态 + 本机握手**：`x86_64`/`aarch64` 原生 runner 上完成 C-5 的 ELF 依赖闭包证据与完整握手矩阵，归档每架构尺寸/性能/内存与 GHASH 检测。
8. **新鲜度与上限**：连续连接验证每连接新 `key_share`、无跨连接复用；`KeyUpdate` 与 AEAD 记录上限行为按 RFC 9846 观察并记录；内层会话 900 s 轮换为新完整握手（主计划 §4.3）。
9. **unsafe/FFI 审查**：所有 `unsafe`（含 §5.1 的 FFI 读数、`as_ptr` 所有权约定）逐项列出安全前提并评审通过；`security_level` 等全局闸取值有据。
10. **秘密生命周期记录**：流量秘密/临时私钥不落盘、重启建新会话；`zeroize`/`mlock`/`MADV_DONTDUMP` 对不透明后端内部副本的覆盖范围如实记录，覆盖不了处标 `[待证]`（主计划 §4.4）。
11. **`pq1024` 保持关闭**：接受 `pq768` 不推出 `pq1024` 可启用；后者另立 profile 与独立证据后再议。

## 8. 证据索引

- [phase0-crypto-backend-assessment-2026-11-14.md](../research/phase0-crypto-backend-assessment-2026-11-14.md)：标准状态、OpenSSL 3.6.1 固定 tag/tarball 哈希、CLI PoC 边界与「当前状态：未验收 / G-CRYPTO 未通过（尚未测）」的既有结论（本文延续，不推翻）。
- [phase0-tls-backend-interop-2026-11-15.md](../research/phase0-tls-backend-interop-2026-11-15.md)：rust-openssl API 逐项源码定位、协商读数缺口、`vendored` 3.2.0 判定、GnuTLS/wolfSSL/Go/rustls 源码级互操作候选、draft-06 datatracker 实测。
- [implementation-status.md](../engineering/implementation-status.md)：门禁台账；本文不改动其中任何 Phase/门禁的完成状态。
- 候选注册表复核与 Phase 0 威胁模型尚未落盘；本文不引用不存在的文件，也不把它们算作已完成产物。
