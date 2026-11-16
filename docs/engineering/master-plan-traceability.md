# 全计划门禁追溯(Phase 0–5 × 24 gates)

本文是 **Phase 0–5 完整计划**的逐门禁追溯,不是完成报告,也不替代任何验收。规范性基线是
[BOREAS-MASTER-PLAN-v1.11.0.md](../plans/BOREAS-MASTER-PLAN-v1.11.0.md) §11(第 820–875 行)。
目的:纠正“只看最近 CI 是否绿”的追踪缺口——每个门禁必须同时回答**属于哪个 Phase、实现入口在哪、
有哪些精确到 SHA/run 的证据、还缺哪些 runtime/外部验收**。

**基线核对(本次复核)**:`C:\Program Files\Netease\GameViewer\Download\BOREAS-MASTER-PLAN__7__1.md`
与仓库副本 SHA-256 一致,均为 `23969614DD3F027EF8828B831F170BBBCAA3C29C99E93BEC20F5983F685086AA`。
范围不缩小:全部 Phase 0–5 在范围内。

**门禁状态声明**:[gates.json](gates.json) 中 24 个门禁全部 `status: open`、`evidence: []`,
`release_commit: null`、`production_approved: false`。本文**未**修改 gates.json,**不宣称任何 gate 完成**,
也不把 CI 绿等同于门禁通过。以下“证据”一律为**该精确 source 上的 scoped CI 结果**,不是生产验收。

## 证据源区分(来源 SHA 不可混用)

| 来源 SHA / 提交 | Runs | 覆盖的精确范围 | 边界(不得外推) |
|---|---|---|---|
| `376da3d`(376da3d578e49e39554abd2f653a64d3c720bf5a) | TLS 43870788773、OpenWrt 43870788612、Rust 43870788720、5 平台 43870788738(另记 TUN 43870788436、PoC 43870788395) | 真实 WSS/hop/E2E TLS 后端;官方 OpenWrt 24.10.0 userland 两架构 netns TUN 双向 8 MiB+SHA-256(x86_64 RTT 0.465/0.714 ms、392.459/305.664 Mbps;aarch64 0.265/0.312 ms、217.856/264.061 Mbps);依赖锁定/工作区构建;5 native 开发构建 | 内核是 **runner 内核,不是 OpenWrt 内核**;非物理设备、非 CDN、非多节点、非 30 min 资源;安全 job 43870788644 因 native known-affected 报告失败(策略阻塞,未豁免) |
| 工作流 `2513729`,脚本+二进制取自 TLS 43870788773 / source `376da3d` | 路由 workflow 43873049802,job 133318972806 | policy-1500 / asymmetric-1500 / policy-1280 / asymmetric-1280 **4 个 case 全过**(ICMP 0.203/0.261/0.248/0.231 ms;管理路由保全与不对称字节差断言) | 同一 workflow 的 **netem 受损矩阵 3 个 case 失败**:200 ms/0.1% 仅 2.279 Mbps<3 Mbps 下限;200 ms/3% 仅 9/10 ping、max 1111.072 ms;400 ms/1% 未进入 connected。路由由 harness 安装,**非 daemon-owned 生命周期**,单 Core 单 Edge,非多 Core/故障切换 |
| `fbdfee1`(fbdfee127ecd41e26d7f69b146ed55ca46da4cab) | TLS 43875749426、OpenWrt 43875749249、Rust 43875749581、platform 43875749284(另记 TUN 43875749268)全部成功 | 修复 45ce1d8 的 `wss_e2e_openssl.rs` E0433 编译错误后的精确 SHA;**已运行真实 daemon/TUN**(TLS job 走真实 WSS/hop/E2E 数据面;OpenWrt job 为 netns 真实 TUN + 真 daemon);验证 signed VIP 保留/默认 home-core+node 映射与 console fixture 修复 | 真实 daemon/TUN 是 scoped 运行时证据,但非多节点/topology、非 1 GiB/资源/性能矩阵、非外部审计;不构成 phase 验收 |
| `1880da2`(1880da2633f385708c9d7293d6b613834c8e31d2,已在 origin/main) | Rust 43878657701、TUN 43878657668、OpenWrt 43878657570、**TLS 43878657864 均 SUCCESS** | same-peer 初始 backup(primary 仅在 `ConnectionRefused`/`TimedOut` 后才切 backup)over **真实 E2E TUN** 的正向 smoke;最后一个 case avg RTT 0.219 ms、192.566/193.621 Mbps | 仅覆盖 **initial dial** 场景,不是 multi-Core、稳态重连、热备/故障切换或分区证据 |
| 资源采样器(已 push 为 `b6ead95`) | TLS 43879991003(审查时仍 pending,终态未复核) | 资源采样器实现(仅记录 exec PID、starttime+inode 身份、真实 sysconf 单位、100 ms/500 samples/45 s 有界、缺失即报 unmeasured) | 无已完成证据;即使该 run 通过也只是采样工具证据,非 30 min/PSS/cgroup/sockstat/195/291 负载 |

审查时(2026-11-16)本地 HEAD 为 `6799a13`,当时 origin/main 为 `4f70b04`;此后资源采样器已 push 为 `b6ead95`。所有编译/测试/格式化仅在 Actions;
本追溯**未读遍全部 source**,无法由现有状态判定的项一律标“未复核”。

## 24 门禁逐行映射

| 门禁 | Phase(计划行) | 已有实现入口(集成状态未复核) | 精确证据(来源 SHA → run) | 剩余 runtime / 外部验收 |
|---|---|---|---|---|
| `G-CRYPTO` | 0(§11 L827) | `crates/boreas-tunnel/src/tls.rs`、`openssl_inner_tls.rs`;`crates/boreas-crypto/src/backend.rs`;`tools/crypto-poc/run-openssl-mtls.sh` | `376da3d` → TLS 43870788773;PoC 43870788395(验证器已改为检查静态 libssl QUIC 符号) | 独立实现互操作;RFC/草案状态、代码点、证书链与静态双架构核实;`pq1024` 单独 PoC 仍**未实现**;外层 CDN 策略如实记录;独立密码审计 |
| `G-FRAME` | 1(L834) | `crates/boreas-proto/src/messages.rs`;`crates/boreas-tunnel/src/ws.rs`;`crates/boreas-crypto/src/ws_frame.rs`、`ws_stream.rs`(均已 glob 确认存在) | 无门禁级证据;`376da3d`/`fbdfee1` TLS 运行含真实字节流断言(细节未复核) | 任意 TCP/TLS/WS 分片/合并边界、长度 0/最大/越界、截断、未知 type/flag、压缩、慢速大头与多片 DoS;旧密文 `0x22` 路径删除核实 |
| `G-DATA` | 1(L835) | `crates/boreas-tunnel/src/{dataplane,stream,circuit,e2e,packet_path}.rs`;`crates/boreas-tun/src/lib.rs`(PacketIo/VirtualTun) | `376da3d` → OpenWrt 43870788612(每向 8 MiB + SHA-256);路由 4 case 8 MiB 全双工 | VirtualTun 与真实 LinuxTun 在多流、断 2 条连接、拥塞、重连下各传 **1 GiB** 并比对应用 hash,记录 L3 丢包/Reset/重排;多 peer / multi-Core 数据面仍不完整 |
| `G-RESOURCE` | 1(L836) | `crates/boreas-tunnel/src/{resource,budget,memledger,capacity}.rs`;`tools/release/netns_daemon_smoke.sh` | 资源采样器已 push(`b6ead95`),其 TLS run 43879991003 审查时 pending;无门禁级证据 | 195 均衡 / 291 集中 Backup / 全局未认证连接攻击;h2 后台 driver、TLS 大链、慢读/停读、目录全同步;**≥30 min** RSS/PSS、cgroup、sockstat、队列/信用与握手峰值,无未解释增长 |
| `G-PERF` | 1(L837) | `tools/release/netns_overlay_perf.py`;`.github/workflows/performance.yml` | 仅 scoped 观测:OpenWrt 43870788612 同时双向吞吐;路由 4 case RTT/吞吐 | 50/200/400 ms RTT × 0/0.1/1/3% 丢包 × 10/100/1000 Mbit/s;h1/h2、DIR/CDN、单/多流、GSO 开关、低水位扫参。**不得把 netem 理论窗口÷RTT 当实测吞吐**;现有 netem 3 失败未解决 |
| `G-ENROLL` | 2(L841) | `crates/boreas-pki/src/{enrollment,provisioning}.rs`;`crates/boreas-crypto/src/key_store.rs` | 无门禁级证据(候选向量 run 43650844858 为历史,非本 SHA) | 同邀请 16 路不同 CSR 争抢一个绑定;落盘/`PREPARED`/签发/`ISSUED`/送达/`DELIVERED` 各点断电、磁盘满、超时重试同 VIP/身份;服务已提交但响应丢失后重启须读同一 DER CSR、幂等键不变 |
| `G-AUTHZ` | 2(L842) | `crates/boreas-pki/src/{enforcement,management,root_authorization,trust_store}.rs`;`crates/boreas-proto/src/objects.rs` | `fbdfee1` → TLS 43875749426 覆盖 signed VIP 保留/默认映射断言;**daemon 启动即校验节点材料**:`crates/boreas-cli/src/daemon.rs:645` 调 `verify_material_dir_with_roots`(材料目录 + roots + net_id + 有效期) | 合法 Core 签他人身份、越 scope `RouteGrant`、跨网、角色提升、同 `seq` 异内容、旧代次、未知 `critical`、单签失效全部拒绝;**对完整合法目录的重新签伪造**也拒绝;完整授权链/持久重放与逐请求 daemon 强制仍缺 |
| `G-REVOKE` | 2(L843) | `crates/boreas-pki/src/{status_store,revoke_cleanup}.rs`;`crates/boreas-cli/src/daemon.rs` 状态新鲜度 watchdog(约 L1295–1436) | scoped 证据:`daemon.rs` 的 `StatusWatchdog` 在 `verify_status_freshness_from_roots` 失败时发布故障并**关闭 blocked 业务 IO**(fail-closed),含单测 `watchdog_publishes_status_failure_and_marks_stale` | 重复旧快照不得续新鲜度、过期停业务、墙钟回拨与重启不重置寿命、新合法吊销清理**全部会话与路由**;失联/分区场景;完整持久撤权与 daemon-owned 句柄清理仍缺 |
| `G-DOS` | 2(L844) | `crates/boreas-tunnel/src/{runtime,budget,probe_budget,hedge,capacity}.rs` | 无(路由 smoke 的有界准入是 harness 行为,非分阶段成本/公平性验收) | 分阶段 TLS/HTTP/WS/Enrollment/签名成本、全局并发、匿名与已认证公平性;**未认证前自报 `key_id` 不得占用他人配额**;承认接入洪水影响重连,不要求无限攻击 100% 成功 |
| `G-TUN` | 3(L848) | `crates/boreas-tun/src/{linux,windows,macos,queue,virtio}.rs`;`crates/boreas-tun/src/route_audit.rs` | `376da3d` → OpenWrt 43870788612(netns 真实 TUN,两架构)、TUN 43870788436;5 平台 43870788738 为 native 构建 | 单/多队列创建、队列 0 设备管理与多次降级、GSO 软件分段、坏 virtio 头、IPv4/IPv6 校验和与关闭卸载路径;真实 OpenWrt/物理设备内核未验(Windows Wintun/macOS utun 的 43677035773 属更早 SHA,未复核) |
| `G-MTU` | 3(L849) | `crates/boreas-tunnel/src/pmtu.rs`;`crates/boreas-tun/src/icmp.rs` | 路由 matrix 中 policy-1280/asymmetric-1280 仅在 MTU 1280 上跑 TCP/WSS,**不自证封装后 1280 单包可过** | 1500→1280、9000→1500、IPv4 DF/非 DF、IPv6 PTB、TTL/HopLimit 与受限 ICMP、LAN 回程与防火墙策略;blocked-PMTUD 未测 |
| `G-DNS` | 3(L850) | `crates/boreas-dns/src/{packet,tcp,bootstrap}.rs` | 无 | `A/AAAA/NODATA/NXDOMAIN/REFUSED`、UDP 包级处理、真实有界 TCP DNS 状态机、分段请求、多查询、超大应答、LAN 查询源地址、限流与无递归。当前 PacketPath 把 DNS VIP 当第三方丢弃,runtime 未接线 |
| `G-SANDBOX` | 3(L851) | `crates/boreas-supervisor/src/sandbox.rs`;`tools/sandbox-audit/*`;`.github/workflows/sandbox-diagnostics.yml` | 无(376da3d/fbdfee1 上未复核该 workflow) | 所有 worker 及升级后禁止 INET UDP/RAW/`io_uring`、清理继承 fd、`AF_UNIX` 鉴权、无系统 resolver 偷 UDP、按目标 ABI 跑 `strace` 与 seccomp 负样本;filter 当前未被 daemon 调用 |
| `G-UPGRADE` | 3(L852) | `crates/boreas-supervisor/src/{install,manifest,preflight,readiness,signals,release_crypto,drain}.rs` | 无故障矩阵证据 | 正常升级、启动早崩溃、`SIGKILL`、掉电、满盘、跨文件系统、旧 seccomp 不兼容、队列 CPU 配额变化、坏版本指针与状态迁移回退;**外部 supervisor 确实恢复可用版本** |
| `G-CONVERGE` | 4(L856) | `crates/boreas-tunnel/src/directory.rs` | 无 | 乱序、重复、分区两边各先装不同候选、恢复同集合后一致;A–B–C 链式交叠、最高 `seq` 替换、同前缀 HA、跨写者 epoch 不可比;无 multi-Core runtime |
| `G-PREFIX` | 4(L857) | `crates/boreas-tunnel/src/lib.rs:253-308`(`PrefixClass`/`classify_prefix`/`DenyReason`) | 无门禁级证据;路由 matrix 只用 `192.0.2.x` 与私有 VIP 默认值 | 合法 `192.168.10.0/24` 过分类;虚拟网超集/子集、默认路由、公网、越 scope、非规范前缀拒绝;定向边界+属性测试(不要求穷举)。**网络侧自定义前缀保持 fail-closed**,需签名网络策略(安装器 `--prefix` 不受此限,见下节) |
| `G-FAILOVER` | 4(L858) | `crates/boreas-tunnel/src/failover.rs`、`{capacity,hedge,probe_budget}.rs` | `1880da2` → TLS 43878657864 通过 initial same-peer backup over 真实 E2E TUN(avg RTT 0.219 ms,192.566/193.621 Mbps) | 4 Core 多 Edge 跨区:Primary 停进程、断回源、单路径故障/网络分区、VIP 不变;热备集中与故障扩容按预算接纳;分段报告检测/重连/收敛时间。现有证据仅 initial dial,不含 multi-Core/稳态重连/分区 |
| `G-SUPPLY` | 4(L859) | `tools/release/{verify_bundle,package,production_promotion,verify_static_linux}.py`;`crates/boreas-supervisor/src/{manifest,release_crypto}.rs` | `376da3d` → 5 平台 43870788738 为**未签名开发构建** | 独立工具先验双签、hash/size、重复 JSON key、超限、过期/回拨、`sequence`、根轮换、架构、产物路径与升级 journal;无私钥在 CI;SBOM 与可复现构建材料;离线 ReleaseRoot 双签链未验收 |
| `G-UI` | 4(L860) | `crates/boreas-cli/src/{tui,render,i18n,config}.rs`;`boreas-easy` 入口;`crates/boreas-cli/src/daemon.rs` 控制 socket(SO_PEERCRED 同 uid,约 L381–433) | **实时 control-socket 已有实际 smoke**:路由 matrix 每个 case 都做 live control status(`376da3d` 二进制);`fbdfee1`/`118a084` 修复 console STATUS EPIPE fixture | 三语、窄终端、非 TTY、`NO_COLOR`、不可用 DSR、危险操作确认、日志/终端注入与诊断脱敏;**缺高危动作执行路径、持久审计与完整终端矩阵**(不是全部实时路径缺失) |
| `G-E2E` | 5(L864) | `crates/boreas-tunnel/src/{e2e,circuit,relay,packet_path}.rs` | `fbdfee1` → TLS 43875749426 真实 WSS/hop/E2E 数据面;`1880da2` → TLS 43878657864 真实 E2E TUN + initial same-peer backup | 不同 Core 转发、同 Core、网关 LAN、Core 作为业务终点;E2E TLS 身份与严格 suite;无 Core 持有转发会话 secret;完整多 peer/multi-Core daemon 与拓扑矩阵仍缺 |
| `G-NO-DOWNGRADE` | 5(L865–866) | `crates/boreas-tunnel/src/{tls,runtime}.rs` 的 fail-closed/严格模式切片 | 无 | 路径断开、乱序/重复 offset、缓存溢出、替换 `CircuitID`/目标/身份/公钥、会话 `900 s` 轮换、同时重建与进程重启须安全 Reset 或恢复,**不用旧 key/counter、不发 `hop-only` 业务**;严格模式握手超时/证书或状态过期/对端不支持 hybrid/恶意 Core 降能力时抓包证明业务从未降级。现有点对点 fail-closed 实现不替代上述全场景抓包验收 |
| `G-E2E-COST` | 5(L867) | `tools/release/netns_overlay_perf.py`(现有 netns 探针为 **e2e-required** 口径,非 hop-only) | 无独立的 E2E 成本对照证据 | E2E TLS 上下文、电路数与双层 TLS 的 RSS/CPU/时延重测;同口径对比 `hop-only` 与 `e2e-required`,**不预设性能倍数** |
| `G-EXTERNAL-REVIEW` | 5(L868) | — | 无 | 外部密码与协议组合审查、解析器 fuzz、依赖安全审计、高优先级问题清零。**安全侧当前策略阻塞**:native OpenSSL 4.1.0 候选(摘要 `50c17ba…cc2fd`,no-quic/no-cms/no-siv)仍落在 known-affected 区间且有 `PENDING_ACTIONS_AND_HUMAN_REVIEW`(376da3d 安全 job 43870788644 失败,RustSec job 133311640300 通过);不得静默或豁免。测试报告不能替代证明 |
| `G-OPERATIONS` | 共同退出条件(L870–875) | `docs/deployment/*`、`tools/deploy/*`、`tools/diagnostics/*` | 无 | 所有适用门禁有可复现命令/版本/数据/预期与失败样本、无 TODO 被标“已完成”;产品部署清单明确记录 PQC 策略、E2E 必要性、吊销新鲜度、资源/规模与 CDN 范围;无已知阻塞/高危缺陷且有负责人与修复证据;生产回滚、根与身份密钥吊销、状态备份恢复、限流/过载与事故响应演练通过 |

## 非门禁重点与安全侧提醒(不得据此宣称完成)

- **custom / 自定义前缀**:两个不同层面,勿混为一谈。(1) **安装路径**:安装器**完整支持**自定义
  `--prefix`/`--bindir`(非 overlay 路径),prefix 被烘焙进 dispatcher、wrapper 与两个服务模板,运行期不读
  `BOREAS_PREFIX`/`BOREAS_CONFIG`/`BOREAS_MATERIAL_DIR`,全链路一致;约束是绝对路径、拒绝顶层系统目录/`..`/符号链接
  与非 root/可写祖先,见 [ONE_CLICK.md](../deployment/ONE_CLICK.md) 第 53–59 行。(2) **网络侧自定义前缀**仍
  fail-closed:缺**签名网络策略**,在 identity/session/packet/TUN/DNS 集成完成前不启用(见
  [continuation-state.md](continuation-state.md) 第 25 行;默认私有 VIP 如 `10.20.1.1/10.20.1.2` 仅为示例)。
- **`boreas-easy`**:`argv[0]` 入口 + 行式三语控制台(`crates/boreas-cli/src/{tui,render,i18n}.rs`),
  经 `/run/boreas/control.sock`(`0600`,SO_PEERCRED 同 uid)取快照。**live control-socket 已有实际 smoke**
  (路由 matrix 每 case 的 live control status,二进制 `376da3d`),另有 fixture 修复 `118a084`、`fbdfee1`;
  仍缺高危动作执行路径、持久审计与完整终端矩阵 → `G-UI` 仍 open。
- **deploy 多平台映射**:`tools/deploy/install.sh` 渲染 `boreas.service`(systemd,`@@PREFIX@@`,含
  `NoNewPrivileges`/`ProtectSystem=strict`/能力白名单/`RestartPreventExitStatus=78`)与 `boreas.openwrt`
  (procd,逐行白名单校验 env、拒绝注入、10 分钟内最多 5 次重启)。`test-install.sh` 为 Actions-only 源文件;
  `.github/workflows/deploy.yml` 只在 ubuntu-24.04 做 shellcheck + sh/dash/BusyBox 回归,**没有真实
  x86_64/aarch64 Linux 或 OpenWrt 设备安装/启停验收**,交付物为未签名开发包。
- **安全证据边界**:`376da3d`、`fbdfee1` 的绿色结果是 scoped 开发/测试证据;native 依赖安全门禁因
  known-affected/PENDING_REVIEW **故意保持阻塞**,不得当作通过。

## 未复核清单(现有状态不足以判定,不猜)

1. `1880da2` 各 job 内部用例计数与失败样本细节(终态 SUCCESS 由 lead 提供,本次未逐日志复核)。
2. `b6ead95` 资源采样器 TLS run 43879991003 的终态(审查时 pending)。
3. `376da3d` 与 `fbdfee1` 各 run 内具体 job/test 计数与失败样本细节。
4. `sandbox-diagnostics.yml` 在 376da3d/fbdfee1 上的结果。
5. 各 crate 实现与计划条目的逐条覆盖度(入口路径为静态列举,未逐文件审阅)。
6. Windows/macOS native 设备证据(43677035773 等)与当前 SHA 的对应关系。
