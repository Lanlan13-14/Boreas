# 主计划逐项审查与产品集成边界 — 2026-11-15

## 1. 结论、范围与版本

**结论：已有大量策略、解析器、状态机、设备适配器和部分真实密码/传输库接口，但尚不能称为可部署的 Boreas VPN 产品；Phase 0–5 均未验收，生产发布仍被阻止。** 单元测试数量、文档覆盖率、模拟流量哈希、静态 CLI 构建，均不能代替真实守护进程的安全数据路径。

本次静态审查覆盖 [v1.11.0 主计划](../plans/BOREAS-MASTER-PLAN-v1.11.0.md) 925 行、[门禁账本](gates.json)、同期工程状态文档和下列引用源码；没有运行编译、测试、格式化或验证脚本。

### 版本快照与并发合并限制

- 审查开始 HEAD：`dac120a5029bb3e6b430bd67670c4df6085fed26`，当时工作树已有修改和未跟踪实现，故**不是干净提交审计**。
- `2026-11-15T12:42:56+08:00` 再采样 HEAD：`22d268c8018d81512a396e88f2e780b0ee0ed704`；MERGE_HEAD：`8457d0637c5714c08b73163b80e5e3e371f29c00`。当时合并未完成，索引有 10 个未解决路径，涉及 PKI、协议、supervisor、原生 TUN 和 tunnel 的清单/导出/TLS 适配器。`12:46:45+08:00` 完稿检查时 HEAD 与 MERGE_HEAD 仍相同。
- 冲突标记属于**合并中的瞬时状态**，不作为已经提交的产品缺陷，也不据此推断最终代码编译失败。本报告引用的是所读取的工作树片段；合并完成后必须对最终 diff、模块导出、feature、依赖和调用方复审。
- [主计划](../plans/BOREAS-MASTER-PLAN-v1.11.0.md) SHA-256：`23969614DD3F027EF8828B831F170BBBCAA3C29C99E93BEC20F5983F685086AA`。
- [门禁账本](gates.json) SHA-256：`C0FC1C48B73ADB917C33272F7E5BC3530A96F2FE453275ABFB45D865BFC19658`。
- [CLI 入口](../../crates/boreas-cli/src/main.rs) SHA-256：`A1081A396141B787A49FE7F28923F0106DA65372B46F6448BD9AE5E222994C70`。
- [link runtime](../../crates/boreas-tunnel/src/runtime.rs) SHA-256：`860739F75EB5687E2212E4E034A92FB77BD501DE0ED0E1FC59A0F4D57BFD769B`。
- [CLI 清单](../../crates/boreas-cli/Cargo.toml) SHA-256：`E7CCCE93F654921CA3F851FC52B06929A7869C5AD6B2EE170FAF46EAD85F3511`。
- [failover 策略](../../crates/boreas-tunnel/src/failover.rs) SHA-256：`CE2D6618A8846B71FBCA99126D51956EEB1832A121C97DFA6DBE216E0191FF3F`。
- [sandbox 实现](../../crates/boreas-supervisor/src/sandbox.rs) SHA-256：`771F6F47CE3C1F7B29F67CA3599BE0175756306F40B22695F269E43E70AFEF25`。

审查对象为仓库副本；同期另行比对了外部原件 `BOREAS-MASTER-PLAN__7__1.md`，记录为同为 925 行且 SHA-256 一致。

### 证据口径

- **需求**：主计划的必须/不得以及明确的目标，不是实现事实。
- **实现**：源码存在、可见算法/系统调用或真实密码操作；静态阅读不证明编译或正确运行。
- **集成**：发行的 CLI/daemon 实际调用链和资源/生命周期归属；存在公开库 API 不等于集成。
- **测试**：本报告只引用既有文档记录和测试源码的范围，未独立重跑、未刷新最新 Actions 结果。
- **外部证据**：独立互操作、真实 CDN/多机性能、安全审计、离线签名和运维演练，不能用自写元数据替代。

[账本](gates.json#L1-L37) 当前 `release_commit:null`、`production_approved:false`，24 项 gate 全为 `open`、证据数组为空、platforms 为空。这个保守状态应保持，直到适用条件真正满足。

## 2. CLI / daemon 实际边界（当前最关键缺口）

### 2.1 发行入口不是 VPN 守护进程

[CLI 入口](../../crates/boreas-cli/src/main.rs#L142-L170) 仅派发 doctor/self-check、status、menu、confirm、config-check、config-migrate、help；未知命令返回“no daemon was started”。没有 daemon、pki、bench、probe、join、服务管理或在线升级入口。[CLI 清单](../../crates/boreas-cli/Cargo.toml#L13-L21) 只有 serde、toml 和 Unix libc，没有依赖 tunnel、crypto、pki、tun、dns 或 supervisor。

[运行能力](../../crates/boreas-cli/src/main.rs#L69-L79) 固定返回 `RuntimeCapabilities::NO_RUNTIME`；[配置能力模型](../../crates/boreas-cli/src/config.rs#L137-L165) 全为 false。status/menu 用离线模型；[危险确认](../../crates/boreas-cli/src/main.rs#L240-L260) 成功也返回 `applied:false`。因此配置能解析、确认词匹配、三语首屏能渲染，不表示有实际操作、持久审计或实时安全状态。

### 2.2 tunnel 库已有真实垂直接口，但未进入发行入口

[link runtime](../../crates/boreas-tunnel/src/runtime.rs#L79-L106) 可组合 TCP → 外层 TLS trait → h1 WebSocket → 内层 TLS trait → SessionHello/Accept；[服务端](../../crates/boreas-tunnel/src/runtime.rs#L126-L201) 在外层 TLS 前预留匿名握手/应用缓冲配额，认证后转换配额。这比纯策略模块前进一步，但仍是阻塞、每连接线程模型。

[能力报告](../../crates/boreas-tunnel/src/runtime.rs#L34-L63) 明示无 daemon、control socket、DNS TCP；默认构建无内层 TLS backend，feature 只是编译能力而非已验收能力。只有显式后端 feature 才可能建立真实加密链路。不能把测试中的 plaintext TLS mock 当 G-CRYPTO；也不能把该库 API 描述成“仓库完全没有任何网络实现”。

### 2.3 需要新增的集成责任

一个真实 daemon 必须拥有：安全 bootstrap/本地 key-store、根锚与创世状态加载、证书与管理对象验证、可信时钟/持久水位、listener/uplink 任务、认证后接纳、Session/DirectGrant、目录分页与反熵、路由和 allowed_lpm、TUN 收发/DNS 分流/PMTU、E2E 电路、全局内存信用、重连与轮换、吊销清场、管理 socket、服务 readiness 和受控退出。仅把若干函数连成 TCP echo 不能满足这些职责。

## 3. Phase 0–5 细粒度需求—实现—集成—证据矩阵

下表“已有测试”只表示源码或既有状态记录中有相关测试切片；**每行 gate 均未验收**。[主计划路线图](../plans/BOREAS-MASTER-PLAN-v1.11.0.md#L820-L875) 为统一判定标准。

### Phase 0：决策、schema 与密码能力

| ID / 需求 | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P0-01 威胁模型、四权分立、NetworkRoot/ReleaseRoot 隔离 | 主计划与 authority 策略；管理验签器接受受控 issuer records | issuer records 不等于已验证的根授权/证书链；离线根签发、用途/scope、根轮换、根锚落盘及换钥水位需 bootstrap 闭环 | 缺全权限链攻击矩阵、根轮换/灾难恢复演练 |
| P0-02 G-CRYPTO：真实外层 HTTPS/WSS 上逐跳 hybrid + ML-DSA mTLS | OpenSSL pq768 backend、WSS 字节流及 tunnel feature adapter | 默认 CLI 不链接；候选适配器合并中；需应用精确身份/scope/状态授权，不可只信 CA 或 SPKI | 缺最终 Rust/WSS exact-commit 正负矩阵、独立第二实现、双架构静态后端原生握手 |
| P0-03 suite / 标准 / 草案 / codepoint 冻结 | [ADR 0002](../adr/0002-phase0-tls-backend-candidate.md) 记录候选 OpenSSL 与证据分级 | ADR 仍 Proposed；“reviewed”代码注释不代表已 Accepted；正式状态须冻结当日复核 | 缺 accepted ADR、后端支持期限、漏洞升级路径、E1 读数或受限 E2 审批 |
| P0-04 pq1024 独立 PoC，未通过保持关闭 | 策略有 allow_pq1024 开关，现 backend 只支持 pq768 | 不得因枚举/配置可表示就开放部署 | 缺独立 PoC/互操作；当前应持续拒绝 |
| P0-05 确定性对象/Control/AppHeader/错误状态机 | 候选编码、消息类型、注册表和独立 Python decoder 已有进展 | Lease cap 与 Ed25519 身份键变更尚待正式裁决；重复 schema/state 模块需要单一来源 | 固定正负向量不等于完整签名授权互检；缺全面冻结评审、兼容/扩展/资源证明 |
| P0-06 参数事实与 intent 分离 | backend 限 TLS1.3、单组/单 sigalg、两 AEAD，返回 peer cert | 必须区分实际 negotiated 与 configured/inferred；禁止 UI 将 E2/E3 写成 E1 | 缺两 AEAD、整链 ML-DSA、恢复/0-RTT 拒绝及真实协商留证 |

### Phase 1：逐跳传输与有界数据面

| ID / gate | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P1-01 h1 基线、h2、真实 CDN | 阻塞 h1 WS/link API，另有 h1/h2 与 credit 策略模块 | h2 Extended CONNECT、SETTINGS 时序、每槽独立 TCP、driver 后台读的预算尚非完整运行路径；无真实 CDN 发行支持 | 缺 h1/h2 回源 ALPN/复用/流控实测；unknown 必须诚实记录 |
| P1-02 G-FRAME：任意拆分合并、未知/越界 fail-closed | AppHeader decoder、候选消息/状态检查、失败 poison | 所有传输边界应共用唯一 decoder/状态机；解析器逻辑限额不等于全局堆内存限额 | 缺全首字节/0/最大/越界/截断/坏 flag/压缩/慢头/多片攻击与 fuzz 活动证据 |
| P1-03 G-DATA：VirtualTun 与 LinuxTun 各 1GiB | VirtualTun、Linux 设备 API；新 dataplane 是自建 HopTun 内存 FIFO | 新模型既不调用 boreas_tun::VirtualTun，也不调用 LinuxTun，更没有 TLS/L3 授权；还需真实 TUN→受权安全流→远端 TUN | 缺真实多流、断两连接、拥塞重连、TCP 应用 SHA-256、Overlay 丢包/Reset/重排报告 |
| P1-04 G-RESOURCE：195/291 + 匿名攻击 ≥30min | RAII admission/ByteCredit、预算/内存账本/队列切片 | 必须合并进程级 ledger；外层/内层 TLS、WS/h2、证书链、线程栈、目录/E2E 与在途信用均需计账；当前 reservation 只覆盖应用缓冲 | 缺 RSS/PSS、cgroup、sockstat、队列信用/握手峰值及停读/慢读/全同步持续证据 |
| P1-05 G-PERF：RTT×loss×rate×路径×GSO | 有 DRR 和 TCP 参数策略，不是完整 RFC8290 FQ-CoDel | 无发行 bench 入口或完整带载 dataplane；Control pps/bytes 双预算、socket 参数/小 chunk 调度需落地 | 缺 50/200/400ms、0/0.1/1/3%、10/100/1000Mbit/s 全口径；稀疏流排队 P99、CPU/吞吐/NOTSENT 扫参 |
| P1-06 连接生命周期/去重/Probe/Drain | connection_instance 与探测/预算策略 | 低 CoreID 主拨、反向健康连接安全去重、A/B/D/M/U/H、认证后切换、900s 全握手轮换尚需 daemon 统一调度 | 缺 N+1 预留、重连风暴、随机 Probe 挑战、真实路径失败实验 |

### Phase 2：身份、注册、持久化、撤权

| ID / gate | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P2-01 G-ENROLL：先落盘本地 key/id/原 DER CSR，再发秘密 | 服务端 journal、锁、CSR PoP、claim_and_issue 等 feature API | 仍无 CLI/offline PKI 和独立 EnrollmentService 通道；需真实客户端持久重试、证书收据确认、受限 24h 恢复；Ed 管理键 CSR OID/PoP 仍候选 | 缺16路不同CSR竞争及每写点断电/满盘/响应丢失后客户端重启，证明同CSR/同VIP/同结果 |
| P2-02 IPAM 单写者/灾备 fencing/tombstone | journal 水位与外部 WriterFence 参数 | 本地锁只防同 store，不证明跨副本隔离；外部 epoch 来源是调用者责任；身份复用必须递增 generation 并等最大TTL/缓存耗尽 | 缺旧备份恢复、双活写者隔离、回收等待和旧证书/租约复活负测 |
| P2-03 G-AUTHZ：权限先于签名，全部字段绑定 | feature 管理对象真实 Ed25519+ML-DSA AND，NodeIdentity 键绑定、Lease 双主体验证 | ManagementTrust 的 issuer provisioned、replay process-local；需要完整 RootAuthorization、X.509/管理对象一致绑定及 durable replay | 缺合法恶意Core重签他人身份、越scope、跨网/角色、未知critical、单签失效、同seq异内容完整链负测 |
| P2-04 G-REVOKE：旧快照不保鲜、过期停新旧业务 | freshness/clock 纯策略、新 enforcement Decision、cleanup ID表 | 没有 daemon 每包/每业务 gate；ID表删除不等于关闭真实TLS/电路/lease/内核路由；可信UTC下界和防回滚 latch 要持久化 | 缺状态到期/时钟回拨/重启/分区/新撤权实际清场；需要受限控制恢复通道 |
| P2-05 G-DOS：分阶段成本、全局匿名额度与认证公平 | server 在外层TLS前 reserve_handshake，匿名不使用伪 key_id 扣他人quota | 外层TLS/HTTP/WS/Enrollment/验签分阶段资源、超时和公平性未统一；线程/后端临时分配不由byte counter自动约束 | 缺匿名洪泛、慢握手、大链、大头、昂贵签名、已认证重连受影响范围实测 |

### Phase 3：设备、主机与运维安全

| ID / gate | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P3-01 G-TUN：多队列/offload/GSO/checksum | LinuxTun、Wintun、utun adapter 及 virtio/队列验证切片 | 尚无 daemon 调用；GSO 完整能力协商/软件分段、单owner队列0阶梯降级与fd生命周期需集成 | 缺五目标发行功能证据，Linux aarch64真设备覆盖应复核；坏virtio、关卸载与各协议checksum矩阵 |
| P3-02 G-MTU：DF/PTB/TTL/出口MTU | ICMP/PTB、IPv4分片、PMTU与边界策略 | 需接入实际L3转发和E2E目的网关；不能由Core读取E2E内层TTL；限速ICMP需全局策略 | 缺1500→1280、9000→1500、DF/非DF、IPv6、LAN回程/防火墙真实矩阵 |
| P3-03 G-DNS：UDP包级 + 真TCP | UDP/IP响应及 smoltcp TcpDnsServer 均有源码 | daemon 必须拥有并poll Interface/Device/SocketSet，接入认证来源授权与DNS VIP引流；runtime/CLI仍不广告TCP能力 | 缺分段/多查询/FIN重传/超大应答/LAN源/限流/no-recursion完整集成证据；DNS模块旧“不支持TCP”注释需更新 |
| P3-04 主机路由共存与默认关闭暴露面 | prefix/route_audit与配置限制切片 | 需真实路由安装/撤销的实例所有权、禁止replace用户route、管理/外层端点保护、connect前SO_MARK；不可自动改sysctl/firewall/NAT | 缺每OS真实apply/rollback/reboot/failure证据；默认路由出口仍不属于首版 |
| P3-05 G-SANDBOX：全worker+exec后0-UDP/RAW | 参考C fixture、Rust BPF builder/install_current、控制鉴权切片 | 未被daemon调用；Rust filter当前拒绝全部INET socket且缺connect等调用，需要明确broker/预建fd模型；继承fd/io_uring/SCM_RIGHTS清理、降权未实现闭环 | 缺真实进程TSYNC/原生ABI/x32负测、resolver无UDP、升级前后strace；fixture PASS不等于生产sandbox |
| P3-06 G-UPGRADE：journal+外部supervisor确实恢复 | journal/active pointer、独立进程监督、readiness、信号/试运行预算已有切片 | 尚无daemon readiness响应、artifact hash绑定、验签→prepare→激活→真实TUNfd接管；Windows路径仍fail-closed | 缺早崩/SIGKILL/断电/满盘/跨FS/旧seccomp/CPU配额/状态迁移/坏指针全故障矩阵与真实恢复时间 |

### Phase 4：多Core、子网与供应链

| ID / gate | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P4-01 G-CONVERGE：三对象单写者确定收敛 | directory纯状态机，独立version/poison/equivocation fingerprints | WriterProof仅调用者声明；无wire分页/5s反熵、原signed bytes durable evidence、revocation/time过滤和身份/lease join | 缺乱序重复分区恢复、同集合一致、full证据落盘与告警；不能把FNV digest当密码哈希 |
| P4-02 G-PREFIX：五步分类/最高seq/HA/静态贪心 | 共享prefix分类与route选举策略 | 需管理验签→AcceptedSet→allowed_lpm→内核route三端共用；RouteAuthority的scope不是仅靠前缀字符串 | 缺边界/属性/独立向量；A-B-C链交叠、最高seq、同前缀最多2 HA与管理route保护 |
| P4-03 G-FAILOVER：4Core多Edge/VIP不变 | failover/capacity/probe等纯决策模块 | 无核心全互联运行时、Primary/Backup租约/健康维护、同Core先切路径和预算接纳；DIR被静态优先不等于实测质量选优 | 缺真实停进程/断回源/单路径/分区/集中Backup扩容及分段时延；需修正文中误固化floor |
| P4-04 G-SUPPLY：先独立双验签后执行 | manifest严格解析、可选真实release crypto、开发打包和外部verifier promotion工具 | installer模块是调用者断言的纯decision，无实际download/stage/验签安装；supervisor CLI不暴露prepare/activate；根轮换和完整受控升级链未闭合 | 缺离线ReleaseRoot双签、SBOM、独立重现构建材料、五目标功能包及GPL对应源码/平台签名策略 |
| P4-05 G-UI：三语/窄终端/非TTY/NO_COLOR等 | 离线status/menu/config与危险确认 | 无授权control socket实时快照、动作执行、持久审计、语言独立落盘、raw-mode/DSR/恢复闭环 | 缺真实daemon的注入/脱敏/危险操作/终端恢复/PeerCred矩阵；截图不是功能验收 |

### Phase 5：默认生产E2E与独立复核

| ID / gate | 已有实现 | 未闭合集成 | 测试 / 外部证据缺口 |
|---|---|---|---|
| P5-01 G-E2E：同/跨Core、LAN网关、Core终点 | circuit byte stream、opaque verified token、feature E2E TLS adapter、RelayHop | 当前单hop session仅一电路，尚无多业务/对等节点/全局runtime；E2E握手后缺显式加密应用确认双方身份/代次/circuit_id/策略/能力 | 缺完整真实拓扑，精确endpoint身份、恶意Core替换、自身Core终点仍E2E等证据 |
| P5-02 offset/FIFO/reset/900s轮换 | relay/circuit纯状态和流API有连续offset/hops等检查 | 应统一重复circuit实现/配额，真实E2eCircuit Read/Write没有自动时间和状态freshness gate；轮换与失效清场需runtime owner | 缺路径断/重复洞倒序/超额/同时重建/重启/900s及密钥销毁故障证据 |
| P5-03 G-NO-DOWNGRADE | frame策略拒绝严格模式HopIpBatch | 不可用“根本没数据面所以没回落”证明生产不降级；必须在可传业务的完整runtime触发失败 | 缺超时/过期/无hybrid/恶意降能力等逐一抓包；所有待发明文只丢弃计数不回落 |
| P5-04 G-E2E-COST | 配额/计数模型 | 无同口径端到端bench | 缺真实E2E TLS context、电路数、RSS/CPU/排队/吞吐；不能预设盲转吞吐翻倍 |
| P5-05 G-EXTERNAL-REVIEW | 候选文档和自测基础 | 外部审查不能自认证或由一份JSON生成 | 缺独立crypto/protocol组合审查、parser fuzz活动、依赖审计、高优先级清零及复核报告 |
| EXIT G-OPERATIONS / 共同退出条件 | gate工具fail-closed设计 | 需exact commit部署清单、支持范围、责任人、回滚/吊销/备份恢复/过载/事故响应流程 | 缺所有适用gate可复现材料和失败样本、无阻塞/高危、真实运维演练与发布审批 |

## 4. 已确认的关键差距与可实现修复优先级

### P0：在扩大实现前先收敛信任和接口

1. **冻结输入，而不是冻结未完成协议。** 合并后记录干净的40位SHA、工作树diff、feature矩阵和证据对应版本；重新检查冲突路径，尤其依赖与模块导出。保持gate open，不把别的提交的绿CI复制到候选提交。
2. **裁决主计划自身 Lease 大小矛盾。** [主计划Lease行](../plans/BOREAS-MASTER-PLAN-v1.11.0.md#L393-L407) 为4KiB；但两主体各Ed25519+ML-DSA要求仅签名块就6754/9390字节。[ADR0003](../adr/0003-lease-16k-dual-signature-envelope.md#L19-L43) 提议16KiB且尚未批准。应正式批准/否决并统一注册表、编码/decoder、独立向量、目录分页、接收配额、所有调用方；不得删签名凑4KiB。同时批准NodeIdentity新增Ed25519管理键的绑定与offline/CSR PoP/OID设计，不能私下扩schema后称计划已实现。
3. **完成真实信任输入→业务许可的单一链路。** [ManagementTrust](../../crates/boreas-pki/src/management.rs#L15-L34) 明确不验证根证书授权链、replay不持久；[SessionPolicy](../../crates/boreas-tunnel/src/session.rs#L47-L69) 仍依赖外部已授权expected_peer/registered等输入。建立不可伪造的verified能力类型和durable trust store，权限/scope→签名→身份代次→freshness→业务gate缺一步即拒绝，不以bool或WriterProof替代。
4. **在真实E2E交付业务前加入加密应用确认。** [finish_e2e](../../crates/boreas-tunnel/src/e2e.rs#L545-L563) 只检验TLS peer和suite后返回可Read/Write对象，没有§7.1要求的双方身份/代次、net_id、circuit ID、策略、能力交换。此确认应在E2E加密数据内、在任何L3业务之前，不用明文Control声明替代；加跨电路/跨网/代次/策略不一致负测。
5. **G-CRYPTO产品路径先行。** 后端ADR仍候选；优先让最终Rust/WSS+真实管理身份链在CI双架构跑通严格mTLS正负矩阵、精确协商留证和独立实现互操作，再将其作为后续daemon可信基础，不用OpenSSL CLI自连替代。

### P1：用最小可验收纵切替代继续堆叠纯策略

6. **实现可运行daemon骨干和单一配置入口。** 将配置归入共享可复用库，添加显式daemon入口与backend feature，安全加载本地根/key/state；实现控制socket/readiness/停止语义。第一纵切为受控预配的2节点、h1、单路径、真实VirtualTun/真实LinuxTun、默认E2E、拒绝未实现功能。该纵切也不是所有Phase完成。
7. **接入撤权而非只模拟清理。** [enforcement](../../crates/boreas-pki/src/enforcement.rs#L1-L9) 是纯Decision；[revoke_cleanup](../../crates/boreas-pki/src/revoke_cleanup.rs#L1-L12) 删除的是ID不是socket。daemon持有真实句柄索引，先持久化合法状态/水位，再立刻阻止新旧业务、关闭TLS/E2E、撤lease/owned route；保留限权恢复通道。写断电/重启/回拨/分区测试。
8. **实际TUN与DNS/RPF/PMTU接入。** [新dataplane](../../crates/boreas-tunnel/src/dataplane.rs#L1-L18) 明确不链接VirtualTun/LinuxTun且不验证IP；不能为其更名就声称G-DATA。以真实PacketIo驱动流水线，目的E2E解密后绑定NodeID→allowed_lpm/ACL，DNS分流并poll smoltcp，PMTU/TTL按真实L3终点履责。
9. **统一资源与实现所有权。** 合并重复circuit、stream、h1h2、ws frame、session auth和memledger模型，确保实际运行路径只采用一个wire schema/状态机/配额来源。挂钩真实TLS/WS/线程和全局credit；先用小拓扑证明超额背压/reset与quota lifetime，再跑195/291持续场景。
10. **纠正failover把目标变约束。** [failover策略](../../crates/boreas-tunnel/src/failover.rs#L24-L99) 将计划“可作为初始迟滞”的30s/120s视为不可降低floor；[estimate_switch_floor](../../crates/boreas-tunnel/src/failover.rs#L355-L381) 将算术和小于10s判错，但计划10s是条件P99目标，并非物理最小耗时。应返回各分项估计与unknown，不设任意10s下界；健康恢复hold应与首次接纳/紧急切换区分。路径选择应基于授权与测量，而不是一律DIR优先。补startup、仅有新健康backup、已健康backup、主路径刚down场景。
11. **明确sandbox系统架构再装filter。** [Rust filter](../../crates/boreas-supervisor/src/sandbox.rs#L35-L62) 仅允许固定AF_UNIX socket，拒INET新socket和大部分syscall；直接放入需要重连/监听的daemon会失能。选择特权broker/worker职责与fd通道白名单，先审核bootstrap/降权/TSYNC/继承fd/exec合同，再以真实程序验证。参考fixture不能给生产签收。

### P2：把运维与发行链闭合

12. 真实目录分页/5s反熵、原字节验签、完整equivocation双证据持久化；租约与身份代次read-time join；内核route所有权管理、四Core拓扑与Primary/Backup接纳/切换。
13. 真正串起独立release验证→staging→preflight→prepare→supervisor→artifact绑定readiness→确认/回退；加入OS服务、TUNfd验证继承、状态兼容、真实故障注入；Windows/macOS必须独立完成，不用Linux结果背书。
14. 完整管理socket实时UI/危险动作与持久审计、daemon来源脱敏诊断、bench/probe真实测量；更新滞后状态文档，既不夸大也不误报所有新代码均不存在。
15. 生产候选exact-commit矩阵、五平台真实功能/静态后端、SBOM与可复现材料、离线双根签名、外部安全复核和运维演练。外部资源可提前协调，但不能降低信任要求或伪造证据。

## 5. 文档状态漂移：必须区分“文档滞后”和“代码没有”

- [implementation-status](implementation-status.md#L14-L30) 旧表仍写“无enrollment/无真实TUN/无TCP DNS/无directory/E2E”等，而其后checkpoint又记录新切片。它对**未验收**的结论仍正确，但对代码存在性的表述已滞后，不能直接作为当前源码普查。
- [data-plane-design](data-plane-design.md#L1-L29) 仍描述不存在的production构造路径/无socket，而现在已有link API与认证token路径；应保留该文当时快照、追加明确替代范围，别用旧断言反证现实现。
- [DNS crate顶层](../../crates/boreas-dns/src/lib.rs#L1-L8) 声称不支持TCP/不处理IP包，但导出packet/tcp，且[TcpDnsServer](../../crates/boreas-dns/src/tcp.rs#L90-L123) 实际使用smoltcp。正确表述是“库已有真实TCP状态机切片，但无daemon轮询集成和完整验收”，不是“伪TCP”或“完整DNS服务”。
- [enrollment顶层](../../crates/boreas-pki/src/enrollment.rs#L1-L13) 的“无CSR解析/无生产构造”与[feature API](../../crates/boreas-pki/src/enrollment.rs#L696-L835) 不一致；应改成默认构建/可选backend/候选OID/服务未集成的分层说明。
- [supervisor顶层](../../crates/boreas-supervisor/src/main.rs#L4-L11) 的“signature provider未实现”与可选release crypto切片可能不一致；但[真实daemon/readiness未集成和artifact绑定缺失](../../crates/boreas-supervisor/src/main.rs#L78-L125) 是实质边界，应保留。
- [platform-support](platform-support.md#L25-L35) 的adapter不存在陈述已落后于当前源码；[platform-release-gates](platform-release-gates.md#L12-L30) 对build/device/生产证据的分层仍适用。需要按最终合并版本更新实现描述，而不是提前改变gate状态。

## 6. 生产验收的最小证据结构

每项证据至少绑定：candidate完整SHA、工具链/依赖/backend/feature、目标架构和OS、拓扑/真实CDN范围、可复现命令、输入/故障样本、预期与实测、原始脱敏artifact及SHA-256、不可变Actions run URL、UTC时间、reviewer和未解决问题。

证据分四层保存，不能互相顶替：

1. **实现/单元层**：parser/策略/事务/设备API的具体不变量与负测。
2. **产品集成层**：发行daemon的真实socket/TUN/route/DNS/E2E/撤权/升级调用链、抓包与故障清场。
3. **环境/规模层**：195/291连接≥30min、资源/队列/内核账本；规定netem矩阵；4Core及8Core升级/切换场景；真实CDN和五平台设备/服务证据。
4. **外部信任层**：独立TLS实现互操作、外部crypto/protocol审查和高危清零、独立发布校验器、离线ReleaseRoot双签、根吊销/灾备/回滚/过载演练及独立审批。

当前[账本](gates.json)尚无上述accepted记录；历史CI结果应按[状态文档的CI边界](implementation-status.md#L50-L60) 解释为对应提交的开发证据。本审查没有为任何门禁补录通过结论。

**建议下一验收里程碑：不是“补齐所有模块文件”，而是一个明确受限、默认E2E、离线预配、h1双层TLS、真实TUN、可撤权和受全局预算限制的二节点daemon纵切，并以最终提交的CI正负测试与抓包留证。随后扩展多Core、h2/CDN、完整系统/发行/外部复核。全部Phase与生产共同退出条件仍须分别完成。**
