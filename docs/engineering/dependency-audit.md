# 依赖安全审计与 CI 失败策略

## 边界与实查时间

本次实际在线查询日期：**2026-11-15（Asia/Singapore；UTC 同日）**。先读取根/8 个 workspace Cargo manifests、完整根 lock 的依赖条目、stable 工具链和现有 CI/refresh-lock/rust-tls 工作流。没有运行本地构建、测试、formatter、Cargo resolve/audit/install；没有修改 manifests/lock、提交或推送。已有他人改动不在本任务范围。

**版本最新不等于无已知漏洞；查询零结果也不是安全证明。** 本页是有日期的情报快照，真正持续门禁由 GitHub Actions 每日刷新数据执行。

## 直接依赖快照

从 `crates/*/Cargo.toml` 收集普通、dev、build、target-specific 和 optional 依赖，排除 workspace path 包；并与根 `Cargo.lock` 对照。最新指 crates.io API 中非 yanked、非 prerelease 的最高数值 SemVer，不误把 `+spec-1.1.0` 的 build metadata 当 prerelease，也不使用可能滞后的默认版本字段。

| 依赖 | manifest 要求 / 当前锁 | 最新稳定 | 结论 / 计划 |
| --- | --- | --- | --- |
| serde | =1.0.229 / 1.0.229 | 1.0.229 | 暂不改 |
| toml | =1.2.1+spec-1.1.0 / 同 | 1.2.1+spec-1.1.0 | 暂不改 |
| libc | =0.2.191 / 0.2.191 | 0.2.191 | 暂不改 |
| openssl | =0.10.82 / 0.10.82 | 0.10.82 | Rust wrapper 暂不改；不代表原生库安全 |
| openssl-sys | =0.9.118 / 0.9.118 | 0.9.118 | 暂不改；本项目非 vendored |
| foreign-types-shared | =0.1.1 / 0.1.1 | 0.3.1 | 跨 0.x 次版本，需兼容性评估，不能单独机械升级 |
| subtle | 2.6 / 2.6.1 | 2.6.1 | 当前锁最新 |
| smoltcp | =0.14.0 / 0.14.0 | 0.14.0 | 当前锁最新 |
| serde_json（dev） | 1 / 1.0.154 | 1.0.154 | 当前锁最新 |
| windows-sys | =0.59.0 / 0.59.0 | 0.61.2 | 需单独 Windows API 兼容迁移 PR |

版本原始来源模式：[crates.io crate API](https://crates.io/api/v1/crates/openssl)，各行使用 `https://crates.io/api/v1/crates/<crate>`；CI 为每个 crate 保存完整响应。工具 `cargo-audit` 最新稳定 **0.23.0**，要求 Rust 1.88；现有 workspace 声明最高 Rust 1.100，工具链为浮动 stable，CI 记录真实 rustc 版本。

已对上述精确锁版本请求 [GitHub Global Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)（`ecosystem=rust&affects=<crate>@<locked-version>`），均返回 0；serde_json 还查询了整个包，0。这仅表示该数据源当时未匹配，不替代完整传递依赖 RustSec 扫描。

另核对 [openssl 全包历史公告](https://api.github.com/advisories?ecosystem=rust&affects=openssl&per_page=100)：例如 CVE-2026-45784（GHSA-phqj-4mhp-q6mq）范围 `>=0.10.50,<0.10.80`，修复 0.10.80；CVE-2026-44662 与 CVE-2026-42327 修复 0.10.79；CVE-2026-41676/41677/41678/41681/41898 修复 0.10.78。锁定 0.10.82 不在这些已发布范围内，**不是对其余漏洞的排除结论**。尚未在 Actions 运行 RustSec 扫描，不宣称完整 lock 已通过。

## 重要发现：原生 OpenSSL 3.6.5 已停止支持

rust-tls、crypto-poc、openwrt 工作流固定 **3.6.5**，源码 SHA-256 为 `a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98`；与 [官方 GitHub 3.6.5 release API](https://api.github.com/repos/openssl/openssl/releases/tags/openssl-3.6.5) asset digest 一致。其 2026-09-29 发布说明修复 CVE-2026-84782（High），以及 35189、35191、42772、54872、54873、54875、72897、75804、75805、75806、77696、84784（均为 CVE-2026-*）。固定旧版有修复记录不代表持续安全。

[官方 2026-11-10 安全公告](https://openssl-library.org/news/secadv/20261110.txt) 明确：**3.6 已 out of support，未被分析**。因此不能把它未出现在新 affected 表当作不受影响。

同公告披露：CVE-2026-88822（QUIC 未初始化栈数据）、88823（AES-GCM-SIV AAD 认证缺失）、95691（QUIC UAF）、95692（AES-GCM-SIV 越界读取/IV 处理）、107496（CMS EC order=1 无限循环），均 Low。4.1/4.0/3.5 分支受影响；CMS 另含 3.0 等。具体可达性需核对调用与配置，不能因项目叫 TLS 就笼统豁免。

[GitHub latest release API](https://api.github.com/repos/openssl/openssl/releases/latest) 当时仍返回 **4.1.0**（2026-10-23 发布），它就在上述已知受影响版本中。官方说明修复版 **4.1.1 / 4.0.4 / 3.5.10 计划 2026-12-01 发布**；当日查询 4.1.1、3.5.10 release tag API 均 404，不能虚构已发布的升级成果或 checksum。

**当前 CI 按实际 backend 版本 fail closed**：20261110 公告已复核并编码上述精确影响/修复范围；另查询[官方支持分支下载表](https://openssl-library.org/source/)（当前最新 4.1.0、4.0.3、3.5.9），3.6.5 因停服且未分析被阻断，不是仅因为出现公告就永远失败。迁移到受支持且不落已知 affected 范围的版本、同步 pin review 后可通过；未来未知新公告才要求补充人工范围评估。当前无已发布且修复这些公告、支持 ML-DSA 的候选，属于安全迁移阻塞，不能自动跳过。即便 RustSec 绿色，这个独立 job 仍阻止漏掉原生库风险。3.5 LTS 的[官方 ML-DSA 文档](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)明确实现 44/65/87，并说明 3.5 引入；迁移后仍须真实 TLS 集成测试而非只凭算法存在。

### 公告路径及最小化构建候选（不是已完成修复）

源码搜索未发现 `CMS_encrypt`/`openssl::cms`、QUIC client/server、AES-GCM-SIV 调用；只是缩小人工审查范围，不能证明整程序不可达，尤其 3.6 停服分支未被上游分析。逐 CVE 路径保存在 `tools/dependencies/openssl-review.json` 并写入 CI Markdown/JSON，不能直接声称这些漏洞可利用于本项目。

如迁移支持中的 4.1.0，官方源码存在编译裁剪候选：`no-quic no-cms no-siv`。**没有 `no-aesgcm-siv` 合法选项**。[4.1.0 INSTALL](https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/INSTALL.md) 明确前两项禁构建 QUIC/CMS；[Configure](https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/Configure) 列 `siv`，而 [cipher build.info](https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/providers/implementations/ciphers/build.info) 的 `!$disabled{siv}` 控制 GCM-SIV 和普通 SIV 实现；[default provider](https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/providers/defltprov.c) 用 `OPENSSL_NO_SIV` 禁止其注册，普通 AES-GCM 保留。这对应移除 QUIC 两 CVE、AES-GCM-SIV 两 CVE 和 CMS 一 CVE 路径，但不是升级成 patched 4.1.1，也不是已验证豁免。本次不修改后端构建，门禁仍对 affected 范围失败；迁移人应增加 configdata/头宏、算法不可用负例、实际静态链接证明及真实 TLS/签名测试，评审后才可对精确版本/配置建立显式豁免。

[4.1.0 provider capabilities](https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/providers/common/capabilities.c) 直接定义 `TLS_SIGALG_ENTRY("mldsa65", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1)` 且最低 TLS 1.3，并支持 X25519MLKEM768；这是 native signature/group 支持而非借草案 fallback。但 Rust FFI/API 与实际 mTLS 兼容必须通过 Actions，不能仅凭源码表宣布集成通过。

## 新 GitHub Actions 工作流

工作流：`.github/workflows/dependencies.yml`。所有 push、pull_request、每日 UTC 04:31、手动触发；不使用 pull_request_target。两个独立 job，避免 lock 过期或审计工具安装失败掩盖其他情报。

1. **Locked RustSec CVE gate**：`cargo metadata --locked --all-features --no-deps` 检查锁一致性；安装 `cargo-audit =0.23.0 --locked --registry crates-io`，使用工具发布包自带 lock。没有 curl|sh、未固定的安装脚本、自动修复或项目构建。克隆官方 RustSec advisory-db，记录实际 commit 和查询时间，用精确存在的 lock 副本执行 `cargo audit --file Cargo.lock --db ... --no-fetch --deny warnings --json`。数据库每次新拉取，不使用陈旧缓存、不加 `--stale`，无忽略 ID、无 target/feature 过滤。隔离工作目录，避免仓库 `.cargo/audit.toml` 静默降级策略。锁含 optional/其他平台包也照查。漏洞、unsound/unmaintained/yanked 等 warning、数据拉取/解析错误、安装失败、metadata 失败均阻断。
2. **Registry, GitHub advisories and native OpenSSL review gate**：stdlib Python 工具读取 manifests/lock，不解析新依赖图、不执行 Cargo。逐精确锁版本查询 GitHub advisories 并阻断 active 匹配；逐 crate 查询最新稳定，生成过时报告；扫描工作流原生 OpenSSL pins，和显式审查记录比对；抓官方漏洞页新公告日期，一旦新增必须人工复核。HTTP 失败、分页截断、格式改变、缺锁条目均失败而非当作零漏洞。此 job 只查直接 crate 的 GitHub 公告，完整传递链由 RustSec job 补充。
3. **新鲜度不是 CVE 策略**：默认旧版本只报告，不阻断（允许经批准的 API 兼容固定）；手动输入 `fail_on_outdated=true` 才升级成所有过时直接依赖失败，不允许这个开关关闭 CVE/原生公告 gate。
4. Actions 全部固定查询得到的 commit SHA（checkout/upload-artifact/setup-python/rust-toolchain）；contents 仅 read、禁用持久 checkout 凭据、不写回、不 PR 自动提交。
5. 两 job `always()` 上传证据，保留 30 天：原始 crate/GitHub JSON、原生 HTML/版本 JSON、机器/Markdown 报告；审计另有 lock hash、源码 SHA、真实 rustc、工具版本、数据库 SHA、安装/metadata/audit 日志。报告错误不吞掉 scan 退出码。`cargo audit` 本身没有 `--locked` 开关；它读取既有 lock，不调用 fix。`--locked` 用在真正支持该选项的 install/metadata，不编造无效 CLI。

局限：RustSec/GitHub/上游公告均有披露与收录延迟；原生 OpenSSL gate 是保守的新公告人工复核，不假装自动语义版本漏洞判定；HTTP 数据仅作为情报，绝不执行。若官网结构变化应修解析器，不应默许通过。没有本地运行新增脚本/测试；首次 Actions 运行仍需验证执行结果。超时/平台中断可能导致报告不完整，应视为未完成审计。需由仓库管理员把这两个 job 设为分支保护 required checks，并监控 schedule 失败；fork PR 不获得 secrets，仅只读 GitHub token。

## 精确升级与锁刷新计划（本次不执行）

- `windows-sys =0.59.0 -> =0.61.2`：单独 PR，检查 Win32 feature 名、HANDLE/socket/接口签名与链接方式；Windows 原生设备/构建/测试全通过，兼顾 macOS/Linux 不回归。由私网代理占用者协调后改 manifest；使用既有 Refresh Cargo.lock 工作流生成受审 artifact，检查 windows-targets 等传递变化与 checksum，再由 CI `--locked` 编译/测试。
- `foreign-types-shared =0.1.1 -> =0.3.1`：**候选而非可直接替换**。当前 openssl 经 foreign-types 0.3.2 使用 shared 0.1.1，直接引入 0.3.1 的 ForeignTypeRef trait 不保证与上游同一类型身份；先评估借用指针 trait 和 rust-openssl 支持范围。优先保持匹配上游的 0.1.1，记录 freshness debt；只有兼容 wrapper/trait 方案经 OpenSSL feature 测试后一起刷新锁，不能仅换数字。
- 原生 OpenSSL：立即停止把 3.6.5 当持续受支持基线。目标优先评估受支持 3.5 LTS 的 **3.5.10**（仍满足项目 ML-DSA/ML-KEM 3.5+），另列 **4.1.1** 主版本迁移候选；两者当时未发布。不能自动升到已知受影响的 latest 4.1.0。若发布前必须修复，需独立审查官方 commit 补丁集、固定来源/校验、逐项安全回归和支持政策，不在本任务擅改构建基线。发行后重新查官方 release asset/signature/hash，核对 3.5/4.x 与 rust-openssl 0.10.82/openssl-sys 0.9.118 的兼容，跑现有 Actions rust-tls、crypto-poc、openwrt 的真实 hybrid TLS、ML-DSA、静态 linkage 与跨目标测试，再原子更新所有工作流 pin/hash 和审查文件。原生换版本身不一定改变 Cargo.lock；wrapper 若需升级必须有明确版本与 lock artifact 评审。
- 其他直接依赖当日已经最新，无依据提出升级。未来任何升级依旧先 CVE 影响范围/修复版本与 MSRV/API 审查，再由专用 lock 刷新通道处理；禁止解除 `--locked`、本地顺手 `cargo update` 或覆盖私网代理正在操作的文件。
