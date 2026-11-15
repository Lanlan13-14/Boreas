# Boreas 主计划执行与验收任务书

日期：2026-11-15，Asia/Singapore。状态：执行中；不是完成报告。

## 1. 授权、基线和不可变规则

用户目标：同步 GitHub `Lanlan13-14/Boreas` 的 `main`，按指定主计划审核并修复全部缺口，完善 README、部署教程和严肃、无 Emoji 的发布机制。用户进一步要求先写详细严密计划，主要交由 GPT-6 Luna 实现，减少主代理 token 消耗。

- 指定原件：`C:\Program Files\Netease\GameViewer\Download\BOREAS-MASTER-PLAN__7__1.md`。
- 仓库基线：[v1.11.0 主计划](../plans/BOREAS-MASTER-PLAN-v1.11.0.md)。两份文件于本轮实际 SHA-256 比对一致：`23969614DD3F027EF8828B831F170BBBCAA3C29C99E93BEC20F5983F685086AA`，925 行。
- 本轮初始本地 HEAD `dac120a5029bb3e6b430bd67670c4df6085fed26`；远端同步目标 `8457d0637c5714c08b73163b80e5e3e371f29c00`。本地领先 6、落后 14 个提交，另有 staged/unstaged/untracked 工作。
- 先建立 `backup/pre-sync-20261115`，再将原工作树完整记录为 `22d268c8018d81512a396e88f2e780b0ee0ed704`，随后合并远端；不 reset、不丢弃、不 force-push。
- 所有编译、格式化、lint、Python/Rust 测试在 GitHub Actions 执行，不在本机运行；Git、静态阅读、API 状态/日志提取不算测试。
- 新实现主要委派明确路由 `lightcode/gpt-6-luna`。按用户最新指定，剩余监督器回归改由 `lightcode/deepseek-v4.1-flash` 处理；原 Luna 任务已确认无写入并停止，交接后才启动 Flash，禁止同文件并发写入。已经执行中的有界审查/修复完成后收回，不重复实现。主代理负责分工、最终 diff 审查、提交、正常推送、证据核对。
- 不请求批准，不输出凭据，不把 ReleaseRoot/NetworkRoot 私钥放入 CI，不用真实生产密钥作测试。
- 不能以政策模块、测试桩、单机回环、单元测试或绿色平台构建替代实际产品集成、真实环境测量或独立安全评审。
- 不降低 hybrid KEX/ML-DSA、双签 AND、新鲜度、资源硬限额或失败关闭要求来换取测试通过。

## 2. 完成度模型与记录要求

每条规范要求分别记录以下五列，不折叠为单一“完成”：

1. 规范/ADR：编号、主计划节号、明确的输入和安全不变量；有矛盾则记录拟议 ADR，不静默改计划。
2. 实现：实际公开 API、调用方和文件位置；未导出代码也不能标成已集成。
3. 产品集成：从实际 CLI/daemon/管理 socket 到真实资源的可达调用链；硬编码能力必须与实际构建一致。
4. 自动验证：exact commit、workflow/run/job URL、命令、环境、正负例和保留的原始结果。
5. 外部验收：独立实现、真实 CDN/多宿主机/设备/审计证据，记录负责人、日期、结论和未关闭发现。

实现状态文档可标记 implementation-present / integration-missing / verified-development / acceptance-open；不得把测试尚未运行写成通过。生产 ledger 只有在所有对应证据审查后才改为通过。

## 3. 依赖图与交付顺序

```text
P00 安全同步和编译基线
  -> P01 规范矛盾/身份边界裁决 -> P02 TLS/WSS与确定性协议
  -> P03 持久身份/注册/撤销 -> P04 可运行节点和管理面
P02 + P03 + P04 -> P05 真实数据面/资源/h2/CDN
P05 -> P06 多Core/路由/故障恢复 -> P07 E2E全路径
P04 + P05 -> P08 系统/沙箱/升级
P00 -> P09 供应链/文档（持续更新）
P05 + P06 + P07 + P08 + P09 -> P10 规模/故障/外部审计 -> 生产审批
```

一次最多交付一个可审查功能切片；分工禁止重叠写同一文件。子代理不得提交推送、不得自行改 production ledger 为 approved。共享接口需要先报告主代理再修改消费者，不能建立第二套平行架构。

## 4. 工作包与验收合同

### P00：保留现有工作并建立干净集成基线（最高优先级）

- 合并 remote main，逐个处理 PKI/proto、tunnel 后端、supervisor、native TUN 冲突，保留两侧安全修复和有效功能。
- 检查全部冲突标记、模块导出、feature forwarding、调用接口、测试 fixture 与当前候选 schema 是否一致。
- 已发现 E2E 测试中局部 `admission` 遮蔽同名函数，须修复而非屏蔽测试。
- 保留 `--locked`。通过显式 Refresh Cargo.lock Actions 生成依赖锁，核对新增 serde_json 和 tunnel/PKI 依赖图；若 compile validation 失败，取回生成锁恢复诊断，不放宽 gate。
- 默认 Rust CI、五平台构建/测试/产物、自带 OpenSSL feature CI、原生设备和 Linux TUN CI 必须对本轮 exact commit 重跑。
- 合并前 upstream `8457d06` 的成功记录仅证明 upstream，不能挪用给合并后代码：Rust `43676629770`、平台 `43676629872`、Linux TUN `43676629745`、TLS `43677030789`、原生设备 `43677035773`。
- 退出条件：无 unmerged index；正常提交和 push；锁满足实际 manifests；本轮每项失败已定位，成功/未验证状态准确。

### P01：候选规范和信任边界

- 盘点 NodeIdentity 的 net_id、永久 NodeID/VIP/VIP6、role、generation、期限、scope、ML-DSA 和 Ed25519 管理公钥的不可分割绑定。
- 普通 Core 不得签别人身份、别人 DirectGrant 或越 scope RouteGrant；验证权限链/用途/scope 后再验对象密码签名。
- AttachmentLease 双主体双签体积与主计划 4 KiB 上限矛盾，沿 ADR0003 明确提案/批准状态；未批准不能宣称严格达标或冻结。所有控制帧、单对象、目录页、内存配额、向量与文档统一裁决后的上限。
- 固定候选 schema/registry、版本兼容、未知 critical/字段和错误状态机；Python 独立解析和 Rust 对同一固定正负向量互检，禁止删除暴露 bug 的负例。
- 明确 RFC/草案和代码点状态，发布时核查一手资料，不把设计文档引用当后端能力证据。
- 退出条件：正式可审查 ADR、无互相矛盾的候选字节格式、完整负例；协议仍需外部评审才能冻结。

### P02：实际安全传输与帧解析

- actual outer TCP/TLS/WSS + WS 内逐跳 TLS，严格 hybrid/ML-DSA mTLS；外层 CDN 可经典，不得以其替代内层身份。
- 从验证证书/已验 NodeIdentity 提取 peer，禁止 caller-supplied 布尔或未认证 key_id 提升权限。
- HTTP/1 RFC6455 基线：Upgrade 校验、随机 mask、长度/压缩/控制帧/分片/截断/慢速/no-progress 有界拒绝。
- HTTP/2 RFC8441 是真实传输/driver，不仅帧策略；连接和流窗口、driver buffer 都纳入配额。
- 每次连接 fresh CSPRNG connection_instance；在 TLS 分配前预留未认证预算；超时、读停滞、失败路径释放配额。
- backend-specific feature 构建、正负证书/suite/角色/跨网/过期/重连测试、静态双架构和独立维护实现互操作分别验收。
- 退出条件：G-CRYPTO/G-FRAME 的每条证据齐全；独立互操作未获得则保持 open。

### P03：身份生命周期、Enrollment 与撤权

- 本地独立生钥、私钥锁页/零化和安全落盘；原始 DER CSR 在发请求前落盘，重试读取同字节不重签。
- invitation 16-way 不同 CSR 竞争仅一绑定；PREPARED/ISSUED/DELIVERED 事务、超时、响应丢失、重启幂等。
- 单写 IPAM、allocation_generation、fencing、墓碑隔离期、NodeID 复用 identity_generation 提升、备份回滚拒绝。
- 原始管理对象 Ed25519 AND ML-DSA 验签；双主体 Lease 绑定目标和两方身份，缓存到期/撤销/冲突时失效。
- 持久最高代次、对象独立水位、同版本异内容两份原始证据持久隔离。
- signed snapshot、issued/next_update、UTC 回拨锁定与单调寿命；重启不得重新刷新过期缓存；撤销要关闭真实 socket/电路并撤销实际 owned route，不只是删 ID 集合。
- 退出条件：G-ENROLL/G-AUTHZ/G-REVOKE，真实故障点和磁盘满注入；纯策略 Decision 不算运行时清理验收。

### P04：可运行节点、配置与管理平面

- 先统一 NodeRuntime 生命周期和可信启动材料接口，再接 CLI；不得仅增加返回成功的 `daemon` 子命令。
- Core/Edge 角色和永久身份不随漫游改变；解析配置后真正读受信根、身份和状态，执行 preflight 后启动。
- `boreas`、`boreas-easy` 共享入口；按计划提供 PKI、doctor、probe、bench 与控制台，未实现命令失败并说明，不能伪造在线能力。
- Unix 0600 control socket + 双向 peer uid 校验、固定 schema 状态快照、字段脱敏/控制字符防注入；Windows/macOS 相应 native 权限契约独立实现。
- 配置热变更：安全降级必须确认 HOP-ONLY、持久审计、全部旧会话断开后生效，不能用 UI 确认桩代替生效事务。
- 三语 77×18 标准屏、窄屏、非TTY JSON、NO_COLOR、超时 DSR、失败退出尽力恢复；危险操作实际连接管理面。
- 退出条件：真实进程启动/停止/诊断与管理鉴权测试；G-UI 全矩阵；CLI capability 由同一运行时来源给出。

### P05：真实 L3 数据面、DNS 和资源预算

- 复用 boreas_tun::PacketIo/VirtualTun/LinuxTun；自建 HopTun FIFO 的 hash 测试不算 VirtualTun 证据。
- 连通真实 TUN read -> 源授权/RPF -> PMTU/TTL -> 签名目录/路由 -> 安全传输 -> 目标 TUN write，明确 hop-only/E2E 的 IP 可见边界。
- 有界 Slab、队列/流公平调度、CoDel、控制保留带宽、全局/会话/对象/握手/电路 credit 同步记账；失败/Reset/断路释放可证明。
- Linux single/multiqueue 与 GSO 软件分段、坏 virtio/checksum 拒绝、关闭卸载回退；macOS utun/Windows Wintun 各有真实设备证据，不把 Linux 测试跨平台套用。
- DNS UDP packet 与 smoltcp TCP 真端点轮询接入实际 PacketIo，A/AAAA/NODATA/NXDOMAIN/REFUSED、分段/半关/重传/限流/无递归；DNS VIP 不绑系统网卡。
- 外层 resolver 无 UDP/循环依赖；DoT/DoH TCP 的 IP 和证书名分离，控制 name collision 与 split-DNS。
- 退出条件：VirtualTun 与 LinuxTun 各 1 GiB 多流/断两连接/拥塞/重连 hash；MTU 1500->1280/9000->1500/DF/IPv6/TTL/firewall 矩阵，G-TUN/G-MTU/G-DNS。

### P06：拓扑、目录、路由和故障恢复

- 16 Core 上限；小号主拨但仅双向都认证/健康后去重，6s 反拨不误断唯一健康连接。
- Edge Primary 4（可8）+ Backup1 + probe1，选核同时3候选；Primary/Backup/瞬态 U 分别硬限额。
- 原始签名对象有界分页、5s 反熵、增量推送、Edge 独立验签；永久身份、挂靠和 LSA 互不覆盖。
- 路由 ProtectedSet 同源、canonical/private/scope 校验、HA 有界、乱序/分区最终相同输入得到相同选择，无本机先到优先。
- 故障切换区分硬 Down 与性能 Suspect；30s/120s 为可调初值，10s 是 P99 目标不是理论下界；不自动放宽 suite/撤销/资源限制。
- 退出条件：G-CONVERGE/G-PREFIX 属性测试和四 Core 多 Edge 真进程故障拓扑；分段测检测/重连/收敛、VIP不变、集中Backup接纳预算。

### P07：E2E 全路径与绝不降级

- 同 Core、跨 Core、网关 LAN、Core 自身终点四种路径；中间 Core 不持业务 secret。
- CircuitID/两端 NodeID+代次/方向/offset/hop/目标绑定，逐跳控制认证，重排/重复/溢出/伪造/重启安全 Reset。
- E2E 内层 TLS 使用新密钥；900s 轮换、同时重建、进程重启不能复用 key/counter。
- 失败路径逐一故障注入并抓包：timeout、过期、撤销、不支持hybrid、恶意降能力、拥塞Reset从不发 hop-only 业务。
- 退出条件：G-E2E/G-NO-DOWNGRADE；真实路径资源成本与同口径 hop-only 比较，不能预设性能倍数。

### P08：宿主保护、沙箱和可恢复升级

- owned route/rule 显式属性/实例归属，冲突拒绝、不 replace 用户路由；SO_MARK connect 前设置，accept 后核验。
- 最小特权设置路径、专用用户/capability收缩；不静默改 sysctl、防火墙/NAT，已授权变更可追踪回滚。
- seccomp 先 arch/x32/compat，再 type mask 禁 INET UDP/RAW、io_uring；线程前 no_new_privs+TSYNC，继承fd/环清理。现有仅UNIX socket allowlist不能直接当可重连网络daemon策略。
- 发布验证到 staging/prepare/readiness 的链条真正接线；挑战绑定候选 artifact hash/schema/worker/TUN而非只有“存活”。
- journal+same-FS staging+文件/目录fsync+active指针、外部supervisor崩溃早于回退逻辑仍可恢复；只继承可信队列fd，不继承TLS secret。
- 故障：SIGKILL/断电/满盘/跨FS/坏指针/CPU配额变化/旧seccomp不兼容/状态schema回退；Windows持久存储未实现时保持 fail-closed。
- 退出条件：G-SANDBOX/G-UPGRADE 与真实 OS 服务恢复，不把 systemd 反复启动坏路径当回滚。

### P09：供应链、发布规范和可执行文档

- 立即修复 production_promotion 遗留报告复用：输出到 bundle 外新建私有临时目录、禁止预置文件成功、对本次输入严格绑定、补 no-op/stale/no-output/错误报告/超时负例。
- 独立 verifier 的可信版本/hash/来源需要独立 provisioning；新鲜报告不是密码验证器可信性的证明。
- 清单先限大小、原始字节双签 AND、再严格 JSON；拒重复key/未知critical/非法数/路径/重复资产/HTTPS跳转，hash+size+arch+时序/sequence/根轮换全验证。
- CI 只构建测试，离线 ReleaseRoot；生产标签/发布前所有 exact-commit gate 全通过并有独立审批。
- SBOM、许可证、漏洞审计、构建来源、固定工具链/依赖/后端、独立重建比较；不可把确定性压缩包称可复现二进制。
- 文档区分 v1.11设计版本与0.x产物，规范 SemVer、draft/prerelease、摘要/变更/安全/兼容/已知限制/部署/验证/回滚章节，不用emoji堆砌。
- README 说明真实可用命令；部署教程先完整说明当前开发CLI能做什么，生产章节按先决条件提供，不能编造 daemon/service 已可部署。
- 退出条件：G-SUPPLY 和文档所有示例与实现一致，未签开发产物不能误当独立可信安装。

### P10：规模、真实环境与独立验收

- 195均衡/291集中Backup、未认证洪泛/h2 driver/大证书链/慢读停读/目录全同步，至少30min RSS/PSS/cgroup/sockstat/队列/信用/峰值。
- RTT50/200/400ms × loss0/0.1/1/3% × rate10/100/1000Mbit，h1/h2、DIR/CDN、单多流、GSO、低水位参数扫描。完整归档环境和样本，不能用BDP推导代替实测。
- 1vCPU/1GiB 仅功能和有界性，生产Core规格按真实容量测量，性能不足调规格/接纳数量而不削弱安全。
- 外部密码/组合协议审查、fuzz、依赖审计，blocking/high全部关闭；本代理或同源子代理评审不叫外部独立审计。
- 根/身份撤销、状态备份恢复、生产回退、过载和事故演练。
- 退出条件：所有适用 gate 有原始可复现证据、审查者、exact commit、失败样本和未决项为零；否则不能生产发布。

## 5. 每个 Luna 子任务必须采用的返回格式

1. 范围：只写指定文件/目录；先阅读，列接口依赖；有范围外必要更改先报告。
2. 变更：安全不变量、真实调用路径、错误/失败/释放语义，不只列函数名。
3. 测试：新增正负例及 Actions workflow/命令；未执行明确标“待CI”。
4. 风险：仍有 TODO、不可实现/需外部资源项、兼容性/迁移/持久化影响。
5. 禁止项：本地编译测试、提交推送、忽略lint、跳过坏用例、伪造证据、改gate通过、上线真实环境。

## 6. 主代理集成与验收动作

- 收齐所需子任务结果后审查最终 diff；不在子代理仍写同文件时运行formatter/生成器。
- 按范围暂存与提交，完整读取异常退出，正常 push 不 force；远端自动格式化/锁提交先 fetch 再安全集成。
- 触发必要 Actions，记录 exact SHA/run/job；失败读日志后修根因，不用重复运行碰运气。
- 所有未完成后台任务记录ID；最终答复前收集相关结果，不将“代码已写”说成“测试已过”。
- 每轮更新本任务书的执行日志与状态，下一工作包从最早未满足依赖开始。目标只有全部实际验收完成才结束，外部证据不足继续做能实现的工作并准确列未决项。

## 7. 本轮执行日志

- 已保留原始本地工作并完成安全合并，`3d5665b` 正常推送；后续 bot rustfmt 已安全合入，无 force-push。
- 原主计划哈希已核实；逐条审计详表见 [plan-audit-2026-11-15.md](plan-audit-2026-11-15.md)。
- 发布报告复用修复、故障切换目标/迟滞修复、README/部署/发布规范和发布说明结构检查器已提交推送；代码提交不是测试通过，各自仍需 exact-commit Actions。
- Refresh-lock `43678497934` 在 `8090fd6` 生成成功，compile validation 暴露 supervisor readiness 接口错误。主代理核对 manifests 未变和 artifact 哈希后恢复锁为 `dc484f6`，不放宽 `--locked`，不将恢复视为编译验收。
- GPT6 Luna 当前分工：readiness 编译修复；E2E 加密应用绑定确认候选及实际调用；NetworkRoot 授权链验证；最小双节点真实数据面接口合同。已有审查记录只读/有限修复任务完成后不重复计算。
- 下一门槛：修复 supervisor 和本轮实际编译/测试失败，验证默认及 backend feature 的 exact commit；其后先落地根授权/持久信任输入，再接真正 E2E + PacketIo 纵切，不盲目同时写整个 workspace。
