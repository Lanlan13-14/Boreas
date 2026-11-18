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
| `fde8d2e`(fde8d2eef78310c6fbd08c0b75ab71e4d1f5c114) / `5448df6`(5448df62bdbd23028671adbebeed521429be47ea) / `f6ad93d`(f6ad93db8149718fc2e5bd67ea164ea689b15a41) | `fde8d2e`:Rust 44112315845、rust-tls [44112316167](https://github.com/Lanlan13-14/Boreas/actions/runs/44112316167)、OpenWrt 44112316160、平台 44112315934、安全 44112316179 均失败,TUN 44112316532 成功;`5448df6` 无自身 run;`f6ad93d`:Rust [44119754093](https://github.com/Lanlan13-14/Boreas/actions/runs/44119754093)、TUN [44119753830](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753830) 成功,TLS/OpenWrt/平台/安全 23:57 时未终态 | `fde8d2e` 的 rust-tls job(名称 “OpenSSL 4.1.0 … pq768 mTLS”,非 CLI crypto PoC)在步骤 14/16 失败,日志为 E0106 与 E0425 `base_from_endpoints`/`policy`;`packet_path.rs` 两处调用但全库无定义。`5448df6` 只是该树的 rustfmt;`f6ad93d` 补回定义(+21/−5) | **`fde8d2e`/`5448df6` 不是可编译 main**;`f6ad93d` 仅在 Rust/TUN 上验证了编译修复,TLS/OpenWrt/平台/安全未终态,不构成完成;任何 gate 均未关闭 |

审查时(2026-11-16)本地 HEAD 为 `6799a13`,当时 origin/main 为 `4f70b04`;此后资源采样器已 push 为 `b6ead95`。所有编译/测试/格式化仅在 Actions;
本追溯**未读遍全部 source**,无法由现有状态判定的项一律标“未复核”。

## 后续精确证据更新（不关闭门禁）

- `13428c3`：Rust [43895908057](https://github.com/Lanlan13-14/Boreas/actions/runs/43895908057)、TLS [43895908026](https://github.com/Lanlan13-14/Boreas/actions/runs/43895908026)、OpenWrt [43895908751](https://github.com/Lanlan13-14/Boreas/actions/runs/43895908751)、TUN [43895908252](https://github.com/Lanlan13-14/Boreas/actions/runs/43895908252) 成功，覆盖修复后的候选字节解析、端点预览与签名 VIP 查询桥；平台包被取消，不算通过。原生安全门仍失败。
- 真实安装与新增权限负例：[43897688166 / job 133405608424](https://github.com/Lanlan13-14/Boreas/actions/runs/43897688166/job/133405608424) 成功。harness/installer 来源 `ac752d9`，被安装二进制来自后端 `43886308602`、source `91acf0c`。可写祖先、非 root 祖先、符号链接前缀均被拒，现有 active 与二进制保持不变。仅一次性 Ubuntu runner、`--service none`；不是 systemd/procd 真机、物理 OpenWrt 或发布验收。
- `8424b84` 的 [TLS 43897875864](https://github.com/Lanlan13-14/Boreas/actions/runs/43897875864) 成功：共享 readiness 客户端真实服务端往返及负例、候选策略双签与 ML-DSA-87 pin 拒绝已执行。客户端尚未接入 daemon，nonce 不证明工件真实性。
- `d6ddb19` 的 Rust [43969887681](https://github.com/Lanlan13-14/Boreas/actions/runs/43969887681)、TLS [43969887087](https://github.com/Lanlan13-14/Boreas/actions/runs/43969887087)、OpenWrt [43969886981](https://github.com/Lanlan13-14/Boreas/actions/runs/43969886981)、平台包 [43969886959](https://github.com/Lanlan13-14/Boreas/actions/runs/43969886959)、TUN [43969886965](https://github.com/Lanlan13-14/Boreas/actions/runs/43969886965) 成功。后端日志确认策略水位的重开／回滚／冲突冻结、原始字节绑定、截断拒绝及真实 CLI 签名文件测试执行通过。这仍不含掉电／满盘矩阵或运行时策略应用；依赖安全门未绿，自定义前缀仍拒绝。后续新增磁盘负例需要其自身精确提交验收。
- `bb6a626` 的 Rust [44090097472](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097472)、TLS [44090097760](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097760)、OpenWrt [44090097588](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097588)、五平台 [44090097520](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097520)、TUN [44090097478](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097478) 成功；控制台测试实际执行预览后精确 `SAVE` 及取消/近似确认拒绝。安全 [44090097546](https://github.com/Lanlan13-14/Boreas/actions/runs/44090097546) 失败，故不关闭任何门禁。
- 性能 [44089808664](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664)（workflow `ff076a1`）实际测试源/二进制 `7be5abf` / TLS 44088534961：1 MiB **2.439/2.305 Mbps**，8 MiB **2.879/2.556 Mbps**，两次均低于不变的 3 Mbps 门限。周期 TCP/qdisc/TUN 采样正在进入新 CI，当前没有根因证明或 G-PERF 通过。
- 正在审查的未推送纵切：daemon 使用显式双签默认策略 + durable watermark，并把 opaque policy digest 贯通 identity/E2E endpoints；显式 status state 在握手边界和立即首检 watchdog 中实际消费。任何非默认前缀及无 decoder 的非空 revocations 仍拒绝。这些未推送改动尚无 Actions 证据，不关闭 G-REVOKE/G-PREFIX/G-DATA。round 27 补充：revocation decoder 候选已存在于未提交工作树，但仍未 commit、未接线，见下节。
- 官方 [2026-11-17 OpenSSL 公告](https://openssl-library.org/news/secadv/20261117.txt) 标明修复版本计划 2026-12-01 发布；当前 4.1.1 尚无官方 release/digest，不能虚构迁移。新增的 Suite B TLS、caller-supplied PEM stack、QUIC rejected-stream 三项已保留为阻塞；全部八项已知 4.1.0 问题仍需处置，RustSec 通过不构成安全门通过。

### 2026-11-17 round 26：最新基线与修复

- GitHub `main` 的精确公开基线为 `a45fac50ed795a8e3f6eb1b4e32a903b62384ffc`。TLS [44098711189](https://github.com/Lanlan13-14/Boreas/actions/runs/44098711189)、平台 [44098711266](https://github.com/Lanlan13-14/Boreas/actions/runs/44098711266) 与依赖 [44098711317](https://github.com/Lanlan13-14/Boreas/actions/runs/44098711317) 均失败；TUN [44098711277](https://github.com/Lanlan13-14/Boreas/actions/runs/44098711277) 与 native Wintun/utun [44098711238](https://github.com/Lanlan13-14/Boreas/actions/runs/44098711238) 成功，仍只证明限定范围。
- 已下载并按 GitHub 摘要核验 TLS artifact `14334458772`（SHA-256 `10f1bde90c931beb5d0a1468f82f244ae076f43f17f73ad2c6398495fe4aeecf`）：数组 `.unwrap()` 编译错误与 packet-path 未绑定身份测试失败。平台日志证实默认测试的 CLI 无条件 dev-dependency 引入原生 OpenSSL，Linux 两架构和 Windows 无该库；不是伪装为通过的运行时测试。
- 上述具体修复与 CLI feature 限定已正常推送为 `c955be1a1b85d8bb23238621488c3811ac4d7299`，启动 exact-SHA Rust [44103089310](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089310)、TLS [44103089622](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089622)、OpenWrt [44103089300](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089300)、平台 [44103089398](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089398)、TUN [44103089453](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089453)、依赖安全 [44103089265](https://github.com/Lanlan13-14/Boreas/actions/runs/44103089265)。终态未收齐前所有 gate 保持开放，无 pre4。
- 按用户要求，实现继续现有代码且主要由 DeepSeek 并行负责；撤权、DNS、性能、主备、多Core、依赖、部署和 UI 是进行中写任务，不是完成声明。`G-EXTERNAL-REVIEW` 仍无独立外部证据。

### 2026-11-17 round 27：实际 Git 状态与未提交候选（不关闭门禁）

- 采样（23:41–23:57 +08）：本地 `main` 起始于 `fde8d2e`，`origin/main` 为 `5448df6`（bot rustfmt，仅格式，且该 bot push 没有触发自己的 run）。lead 本地提交 `9880924`（补回 `base_from_endpoints` 定义、`openssl_inner_tls` 策略 API 等，+21/−5），合并 `origin/main` 后 push `f6ad93d`；23:57 本地 `main` 与 `origin/main` 均为 `f6ad93d`。直接 schannel/curl 访问 API 失败，但 `.local/github_inspect.py` 用 bundled Python 可正常读取；不打印 token。
- `f6ad93d` 当前证据：Rust [44119754093](https://github.com/Lanlan13-14/Boreas/actions/runs/44119754093) 四个 job 全部 SUCCESS（locked 依赖 preflight、Ubuntu check/clippy/test、rustfmt patch、Windows check/clippy/test），TUN [44119753830](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753830) SUCCESS；rust-tls [44119753821](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753821) 仍在构建静态 OpenSSL，OpenWrt [44119753721](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753721) 构建中，平台 [44119753812](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753812) 排队，安全 [44119753952](https://github.com/Lanlan13-14/Boreas/actions/runs/44119753952) 进行中且 fixture/pin/native-review 三个 job 失败。因此只验证了 Rust/TUN 上的编译修复，TLS/OpenWrt/平台/安全未终态，不能称完成。
- `fde8d2e` 的 CI **失败，不是完成**：五个 push workflow 失败——Rust 44112315845、rust-tls [44112316167](https://github.com/Lanlan13-14/Boreas/actions/runs/44112316167)、OpenWrt 44112316160、平台 44112315934、安全 44112316179；只有 TUN 44112316532 成功。该 rust-tls job 名称是 “OpenSSL 4.1.0 … pq768 mTLS”，**不是 CLI crypto PoC**；它在步骤 14/16 失败，日志为 E0106 与 E0425 `base_from_endpoints`/`policy`，`packet_path.rs` 两处调用但全库无定义。`5448df6` 只是该树的格式化且无自身 run，因此不是可编译 main。24 门禁与 Phase 0–5 均未改变，`gates.json` 未改（仍 24 open），无 pre4。
- `0127a22` **不是 lock 已刷新**：它只改 `crates/boreas-cli/Cargo.toml`；API 显示 refresh-lock run [44109377920](https://github.com/Lanlan13-14/Boreas/actions/runs/44109377920) 两个 job 均 SUCCESS，但 `Cargo.lock` 无 diff（`84288e7` 在 `0127a22`/`fde8d2e`/`5448df6`/`f6ad93d`/worktree 相同，最后修改仍是 `b52ead2`），成功校验没有产生 commit。其自身 push CI 也是红的：Rust 44109366792、rust-tls 44109369248、OpenWrt 44109366797、安全 44109366832 失败，平台 44109366804 取消，TUN 44109369054 成功。更早的 refresh 44108659573 在 `dbe3c5d` 因 `dev-dependencies are not allowed to be optional: openssl` 失败且 diff 为空。
- 未提交候选 ≠ 完成：31 个已跟踪文件 **+7456/−343** 与 10 个新文件（`revocation.rs`、DNS authority×2、`dns_runtime.rs`、mesh/sandbox 测试、4 份 docs，约 5,460 行），是 DeepSeek 8 路续写现有代码的产物；没有 commit/push、没有 exact-SHA Actions，不得作为任何门禁证据。
- 四个候选的硬边界（仅静态阅读）：revocation entry **没有逐条 authority 签名**，只靠部署 `RevocationRelayPolicy` 与结构规则，`StatusStore::open` 默认不授权任何 class，清理只到标识符 → `G-REVOKE` open；DNS 只有 **IPv4/UDP over `PacketIo`**，拒绝 `TCP:53`、`dns_tcp=false`、daemon 未构造 → `G-DNS` open；mesh 是四节点 loopback **模型**、固定单向 relay、非 full runtime → `G-CONVERGE`/`G-E2E`/`G-FAILOVER` open；standby 是 **same Core, alternate ingress**，非多 Core/多 peer → `G-FAILOVER` open。
- `G-PERF` 仍 **red**：最后一次实测 run [44089808664](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664) / source `7be5abf` 为 1 MiB **2.439/2.305**、8 MiB **2.879/2.556** Mbps，均低于未变的 3 Mbps 门限；性能候选文档自述未在 Actions 跑 benchmark，不得称修复。

### 2026-11-18 round 28：精确 SHA 通过/失败（不关闭门禁）

| SHA | 精确 run 结论 | 可声称的范围 | 不可外推 |
|---|---|---|---|
| `ade6a03`(ade6a0362ab749689051e916650bd9df81a6a831) | 6 个 push workflow：TUN [44305778989](https://github.com/Lanlan13-14/Boreas/actions/runs/44305778989) SUCCESS；Rust [44305779015](https://github.com/Lanlan13-14/Boreas/actions/runs/44305779015)、rust-tls [44305778959](https://github.com/Lanlan13-14/Boreas/actions/runs/44305778959)、OpenWrt [44305778982](https://github.com/Lanlan13-14/Boreas/actions/runs/44305778982)、平台 [44305778994](https://github.com/Lanlan13-14/Boreas/actions/runs/44305778994)、安全 [44305779011](https://github.com/Lanlan13-14/Boreas/actions/runs/44305779011) FAILED | 仅 Linux netns TUN；目录草稿在 Rust/TLS/OpenWrt/平台/安全上均为红 | 不是可编译/可合入 main，不是完成；不能把 TUN 单 workflow 绿当成整体绿 |
| `86ca08c`(86ca08c0440c55a9aeaadee62801b05ffb1f5bc3) | deploy [44305617520](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617520) SUCCESS（shellcheck + sh/dash/BusyBox + deployment regressions）；TUN [44305617333](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617333) SUCCESS；Rust [44305617390](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617390) FAILED（Windows Test；Ubuntu success）；安全 [44305617405](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617405) FAILED；OpenWrt [44305617349](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617349)、平台 [44305617283](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617283)、TLS [44305618669](https://github.com/Lanlan13-14/Boreas/actions/runs/44305618669) cancelled | 仅 deploy 的 shell/回归脚本通过；真实 static candidate install job **skipped** | 不是 deploy 全链路通过；该 SHA 整体仍红，不能外推到后续 SHA |
| `fde503d`(fde503dce22d10bcb3d6e3eb8de45ee9eb264d3b) | OpenWrt [44191576084](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576084) SUCCESS（x86_64 与 aarch64 两个 job 全部步骤）；TUN [44191576285](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576285) SUCCESS；Rust [44191576087](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576087) FAILED（Windows Test；Ubuntu success）；平台 [44191576106](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576106) FAILED（仅 Windows；Linux 两架构与 macOS 两目标 success）；deploy [44191576099](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576099) FAILED；安全 [44191576292](https://github.com/Lanlan13-14/Boreas/actions/runs/44191576292) FAILED；API 无该 SHA 的 rust-tls run | OpenWrt 官方 24.10.0 userland + runner 内核 netns 的真实静态 daemon 路径；Linux TUN netns | 不是 OpenWrt 内核/物理路由器/procd 验收，不是 deploy 全链路，不是 TLS/平台全绿；不能外推到最新 main |

- `ade6a03` 的具体失败点（`44305779015`/`44305778959`/`44305778982`/`44305778994`/`44305779011`）：Rust Clippy `unnecessary_get_then_check`（`crates/boreas-tunnel/src/directory.rs:1263`）、`manual_range_contains`（`relay.rs:1067`），`boreas-tunnel` lib 198 pass/1 fail（`failover::attachment_tests::release_frees_exactly_one_slot`，`failover.rs:1264`）；TLS 步骤 14/16 与 OpenWrt 两架构均为 `E0382 use of moved value: spec`（`tests/mesh_runtime.rs:770`/`769`）；平台五个目标均失败于 “Run workspace tests on the target”；安全 job 的 `Dependency tooling fixtures`、`OpenSSL build verifier fixture`、`Locked RustSec` 成功，但 action-pin audit 因 `openwrt.yml` 66/67/70/225 未钉住而失败，native review 仍因 8 个 CVE + `PENDING_ACTIONS_AND_HUMAN_REVIEW_NOT_A_WAIVER` 阻塞。
- `fde503d` 的 deploy 失败日志为 `FAIL - dry-run executed the candidate`；`86ca08c` 的 deploy 通过只覆盖 regression job，真实 static candidate install 被 skipped，因此不能称“deploy 已完成”。
- 审查开始快照为 `ade6a03`；审查期间 `origin/main` 已变为 `ed02ab1`，本地又出现 `35d2aca`、`b486c69`。这些后续 SHA **未审计**，本文不把 `ade6a03`/`86ca08c`/`fde503d` 的结论外推给它们；`b486c69` 声称 pin openwrt actions，但没有本轮的 exact-SHA Actions 证据。
- 24 个门禁仍全部 open，`gates.json` 未改（24/24 open、evidence 为空），无 pre4；这些精确 SHA 的通过/失败不改变任何 gate 状态。

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
7. `fde8d2e` 各 job 内部失败步骤的完整日志未逐一下载(API 已确认 run 结论及 rust-tls 步骤 14/16 失败)。
8. `f6ad93d` 的 rust-tls 44119753821、OpenWrt 44119753721、平台 44119753812、安全 44119753952 在 23:57 尚未终态,日志/产物未收。
9. 全部未提交候选的编译/测试结果;`9880924` 没有独立 push run,只随 `f6ad93d` 一起被验证。
10. 四个候选缺口只做了入口/注释级静态阅读,未逐行审计;revocation 的 authority 归属仍是设计级 open issue。
11. `ade6a03` 之后出现的 `ed02ab1`、`35d2aca`、`b486c69` 未审计;不得把 round 28 的结论外推到这些 SHA。
12. `86ca08c` deploy 44305617520 的 “Real static candidate install” job 被 skipped;仅 deployment regression 脚本通过。
13. `fde503d` 无 rust-tls run;`86ca08c` 的 TLS/OpenWrt/platform runs 被 cancelled;平台失败日志只逐一下载了 Linux x86_64 代表样本,其余目标未逐日志复核。
