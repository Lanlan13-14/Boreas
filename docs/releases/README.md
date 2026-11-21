# Boreas 发版规范

本文规定开发版的呈现和未来生产发布的必要流程，不批准任何当前生产版本。**当前软件为 `0.1.0` 开发基础；没有生产发布获批，所有适用门禁 open。** 当前 `boreas` 没有 `daemon`、`pki`、`bench`、`probe` 命令，默认 artifact 没有 TLS 后端。WSS/E2E 库 API 不是完整 CLI VPN，CLI smoke 不是生产功能验证。

规范依据：[安全主计划](<../plans/BOREAS-MASTER-PLAN-v1.11.0.md>) §2.4/§10/§11、[平台与发布门禁](<../engineering/platform-release-gates.md>)、[生产账本](<../engineering/gates.json>)、[发布工具说明](<../../tools/release/README.md>)。实际部署边界见[部署教程](<../deployment/README.md>)。

## 1. 版本与渠道

### 1.1 软件 SemVer 不等于架构设计版本

- 软件包采用 SemVer `MAJOR.MINOR.PATCH`，可附 `-dev.N`、`-alpha.N`、`-beta.N`、`-rc.N` 等预发布标识。当前 [CLI manifest](<../../crates/boreas-cli/Cargo.toml>)为 `0.1.0`。
- 主计划 `v1.11.0` 是**设计文档修订号**，不作为软件版本、GitHub stable Release 或协议冻结证明。不得用它给当前 `0.1.0` 二进制改名，不能在 release 标题写成“Boreas 1.11 production”。
- `0.x` 是未稳定开发期。约定兼容性破坏提升 minor（如 `0.1.x` → `0.2.0`），不破坏已声明契约的修复提升 patch；任何安全例外也必须写兼容性、迁移和回退边界。`0.x` 不代表可不告知破坏性变更。
- `1.0.0` 及以后才承诺明确的稳定软件契约，但**版本号本身不授予生产资格**；生产使用仍依赖准确 commit 的全门禁、审计、离线签名与运维批准。
- 软件版本、配置 schema `version=1/2`、状态 schema、AppHeader `proto_major`、对象 schema、release manifest version、发布 `sequence` 分别管理，不互相替代。候选线协议未独立验收冻结，不宣称跨版本网络互通。

### 1.2 draft / prerelease / production

| 阶段 | GitHub 呈现 | 允许声明 |
|---|---|---|
| Actions 开发 artifact | 无须创建 GitHub Release，run-scoped、可过期 | 精确 commit 的开发构建与实际通过范围；unsigned、non-production |
| 拟定版本 | `draft=true`，尚未对外批准 | 评审材料，不是 release 已发布 |
| 公开开发版 | 明确 `prerelease=true`，标题含 Development/开发预发布，不设置为 stable/latest | 仅开发使用；即使包内版本仍 `0.1.0` 也必须标开发渠道 |
| 未来生产版 | 仅在所有前提通过后由独立人员人工批准 | 严格按验收路径和支持矩阵陈述，不承诺无条件安全/性能 |

不得仅创建 tag 就触发 production 发布，不得让 `push tags: v*`、版本号或 workflow 绿色自动绕过批准。现有[平台打包工作流](<../../.github/workflows/platforms.yml>)只生成开发 artifacts；[promotion gate](<../../.github/workflows/release-promotion-gate.yml>)为手动核验，**不发布** GitHub Release/tag。本文没有执行发版、打 tag 或任何 Git 写操作。

### 1.3 只读更新检查

运行 `boreas --version` 查看本机 CLI 构建身份，运行 `boreas update-check`
检查稳定通道，或 `boreas update-check --channel pre` 检查预览通道。交互式
`boreas console` / `boreas-easy` 的第 7 项「检查更新」显示本机版本；`1`/`2`
选择 Stable/Pre-release，`c` 或 Enter 才发出请求。通道只保留在当前会话；选择通道、
进入页面、渲染菜单和非 TTY JSON 均不检查，且没有定时请求。

- 首选固定地址 `https://raw.githubusercontent.com/Lanlan13-14/Boreas/release/release-manifest.json`。
  本功能定义独立的发现清单格式，例如 `{"product":"boreas","schema":1,"stable":null,"prerelease":"v0.1.0-pre.3"}`。
  两通道字段都必需，值为匹配的 `v<SemVer>` 标签或 `null`；**它不是**生产双签清单。首个检查源有效时（包括 `null`）不请求 API。此提交不创建 `release` 分支、清单或发布工作流。
- 静态源不存在、不可用或内容无效时，请求 `https://api.github.com/repos/Lanlan13-14/Boreas/releases?per_page=20`，只检查首批最多 20 项，不调用 `/releases/latest`，不分页。拒绝 draft，要求 `prerelease` 标记与标签匹配，然后按 SemVer 比较，不按 API 返回顺序或字典序。预览只看预发布标签，稳定只看正式标签；`pre.9 < pre.40 <` 同基线正式版。没有匹配项表示**已检查数据**无匹配，不能证明从未发布、已安装版本最新或发布已获生产批准。
- 两个 HTTPS GET 共用 5 秒期限（静态源分配最多 1.75 秒），每个响应上限 1 MiB。依赖受信系统 curl 7.77+ 或支持等价选项的发行版兼容版本（Unix 仅 root 所有且非组/其他用户可写的 `/usr/bin/curl` 或 `/bin/curl` 及其路径；Windows 仅系统目录的 `curl.exe`）；缺失或不支持必要选项则提示不可用，不搜索 `PATH`。忽略 curl 配置及继承的代理、凭据、证书覆盖等；禁用自动客户端证书，要求 TLS 1.2+ 和系统信任验证，不跟随重定向。不发送 GitHub token、设备/服务标识或版本；服务仍可见普通网络连接元数据（如源 IP）。离线、TLS 失败或限流会明确报告，绝不显示为“已是最新”。
- 未显式标注标签的构建显示 Cargo 软件版本和 `dev`（编译时有完整 `BOREAS_BUILD_SHA` / `GITHUB_SHA` 时显示短 SHA），只报告发现的候选，不比较开发提交与发布标签。以后由获准的打包环境按实际标签提供编译期 `BOREAS_BUILD_TAG`；发现结果只能说明远端声称标签较新、SemVer 优先级相同、较旧或无法比较。CLI 退出码：`0` 检查完成（含无匹配），`1` 不可用，`2` 参数错误。
- 发现结果不具备发布签名授权；仅显示固定的 Boreas 发布页面，不采用远端任意 URL。`update-check` 和菜单不下载、安装、执行或激活。Linux/systemd 管理员可另行使用[离线验证与显式应用](../deployment/VERIFIED-SERVICE.md)；该入口不读取发现结果。自动更新保持禁用，见[升级信任边界](../upgrade/README.md#automatic-update-remains-blocked)。

## 2. 命名与不可变性

统一使用 ASCII、无 Emoji、无空格的标识；标题、正文、变更日志、附件说明及自动摘要均不得添加 Emoji、夸张安全徽章或未经证实的营销语。

- tag 规范：`v<软件SemVer>`，例如 `v0.2.0-dev.1`；这只是命名例子，不表示该版本存在。tag 指向完整已审核 commit，发布后不可移动/覆盖；错发时撤销、公告并用新版本重新发布。
- Release 标题：`Boreas <软件SemVer> — Development prerelease`；未来满足生产条件后才可省略开发限定词。
- 当前归档命名由[工具实现](<../../tools/release/package.py>)产生：`boreas-<软件版本>-<Rust target>.tar.gz`，Windows 为 `.zip`，版本字段不加额外 `v`。必须保持与 manifest/index 一致，不能仅改文件名伪造新版本。
- 同一 `0.1.0` 不同开发 commit 的归档可能同名：必须按完整 commit/run id 分目录保存，不能混放覆盖，不能用裸文件名作为唯一身份。现有 artifact 名为 `boreas-development-<target>-<run_id>` 与 `boreas-development-release-<run_id>`。
- 五 target 固定为 `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`、`x86_64-pc-windows-msvc`、`x86_64-apple-darwin`、`aarch64-apple-darwin`。生产 manifest 对应平台 token 是 `linux-x86_64-static`、`linux-aarch64-static`、`windows-x86_64`、`macos-x86_64`、`macos-aarch64`，不能混用两套命名。
- 已签清单和归档字节不可修改；任何重打包、许可证/元数据/附件变更必须重新计算 hash，并重新审核签名绑定。发布 `sequence` 单调增加，不依赖 tag 字典序或文件 mtime。

## 3. 开发版产物与证据要求

所有编译、格式化、lint、测试、基准和故障注入仍仅在 GitHub Actions 执行。不得为了“补发”在本地构建、移除 `--locked`、删负样本或跳过设备测试；锁更新只走[锁刷新工作流](<../../.github/workflows/refresh-lock.yml>)。用户对预信任下载产物运行 CLI/离线完整性核验是使用操作，不是替代 CI 的测试证据。

1. 冻结候选完整 commit，检查受保护分支评审。记录 source SHA、工作流定义、run URL/attempt、工具链、backend feature、依赖锁 hash、runner OS/CPU。
2. 收集准确 commit 的五个 native 构建/测试与 CLI smoke、Linux 两架构无 `PT_INTERP`/`DT_NEEDED` 静态报告、八项容器 CLI 检查。失败/取消/跳过的 job 如实写明，不把旧 commit 绿色结果移植过来。
3. 保留开发 archive、索引、`SHA256SUMS`、每目标 provenance、工具链和 smoke/static reports。核验索引/hash/size/嵌入元数据一致，且继续明确 `production_release:false`、`production_eligible:false`、`promotion_status:"blocked"`。
4. 以[发布工具](<../../tools/release/README.md>)定义为准；`verify_bundle.py` 退出 `0` 仅表示内部完整性，输出明确未做生产验签，失败退出 `1`。它不是独立真实性证明，不得用下载的未知二进制自证。
5. 整理变更日志和已知限制，再人工决定是否保留为 Actions artifact、draft 或公开 prerelease。没有授权不得实际发布。

当前默认内层 archive 只有主二进制、许可证、源码指针和开发元数据；最终 bundle 另含索引、校验和、provenance 和非生产平台候选。当前没有生产双签、SBOM、可复现构建 attestation、Boreas Authenticode/notarization，也没有完整安装器/supervisor 分发。确定性归档元数据只表示相同 staged bytes 可得到相同 archive，**不是 Rust 二进制位级可复现证明**。源码 URL 指针不等于 GPL 对应源码义务已经完整履行。

平台候选中的 `functional_test:"not_run"` 与 `real_packet_io:false` 必须保留；不得把 `cli_functional_smoke:"pass"` 当作五平台 VPN production evidence。真实 TUN/Wintun/utun 测试即使通过，也只是设备级证据，不自动通过 DNS、路由、E2E、升级、规模与审计门禁。

## 4. 变更日志模板

可复用的完整模板见 [Release 模板](<../../.github/RELEASE_TEMPLATE.md>)；
[GitHub 变更分类配置](<../../.github/release.yml>)仅整理合并的 PR，不发布版本，
不保证 PR 标题已净化。发布前必须人工审查最终说明。
[结构检查器](<../../tools/release/validate_release_notes.py>)提供以下接口：

```sh
python tools/release/validate_release_notes.py /path/to/release-notes.md --json
```

正常结构退出 `0`，拒绝退出 `1`，参数错误由 argparse 返回 `2`。
它检查有限的 Emoji/控制字符范围、256 KiB 输入上限、UTF-8、软件 SemVer、
唯一 source commit/channel、开发版非生产标记与必需章节；Unicode 检查不是完整
Emoji 数据库，结构通过也不证明内容真实、安全、签名或门禁通过。模板占位符须先填实。
检查器回归测试只在 Actions 执行；它不会创建 tag 或 GitHub Release。

下列是待填写模板，不代表任何字段已经完成。章节名统一，简体中文或 English 均可，禁止 Emoji。明确区分实现、实测证据、设计目标和待证项。

```markdown
# Boreas <SemVer> — Development prerelease

## Release identity
- Channel: development / draft / prerelease
- Source commit: <full 40-hex>
- Architecture baseline: v1.11.0 (design only)
- Build run URL / attempt: <immutable URL and attempt>
- Production approval: false

## Added
- <implemented change, scope, relevant review/issue>

## Changed
- <behavior change; distinguish library API from CLI capability>

## Fixed
- <defect, impact, exact fix commit and actual Actions evidence>

## Security
- Threat model and affected endpoint/trust assumptions: <...>
- Security advisory / affected versions / mitigation: <...>
- Algorithms/backend feature and actual supported path: <...>
- Findings unresolved, audit status and gate status: <...>
- No claim of PQ/E2E production acceptance from primitive/API presence.

## Compatibility and migration
- CLI / library API / wire protocol / object schema changes: <...>
- Config schema and explicit migration: <...>
- State schema, min_compatible_state and old-version readability: <...>
- Root/key/identity_generation/sequence constraints: <...>
- Downgrade and rollback restrictions: <...>

## Verification evidence
- <commit, workflow/job, environment/target/features, command>
- <expected/observed, run URL, report SHA-256, reviewer and UTC timestamp>
- <failed/cancelled/skipped/unmeasured items, not only passes>

## Artifacts and supply chain
- <five target names, exact filenames, size and SHA-256>
- <provenance/SBOM/source/license/signatures or explicitly absent>
- Development integrity is not production authenticity.

## Known limitations
- <no daemon/CLI data plane/backend in default artifact, as applicable>
- <unsupported OS/features/CDN path, pending gates and operational risks>

## Upgrade and rollback
- <staging/preflight/state compatibility/backup/canary/stop conditions>
- <last permitted version and recovery procedure; never bypass revocation>
```

开发版安全/兼容性章节即使“无变化”也需写出评审结论与范围，不留空、不写“全部安全”。`Fixed` 必须区分“代码已改”与“准确 commit 已验证”。promotion 遗留验签报告问题的修复代码已写入 `97e240d`（合并格式化后的 main 为 `aa69b7f`），回归待准确 commit 的 Actions 证据，尚未验收，不能写“已验证修复”。不泄露私钥、邀请、未披露漏洞利用细节、TLS 流量秘密或含个人数据的原始诊断包。

## 5. 未来生产准入：全部必要，当前均不视为满足

生产候选必须实现完整 daemon/数据面，并收齐[主计划](<../plans/BOREAS-MASTER-PLAN-v1.11.0.md>) Phase 0–5 的所有适用门禁：密码/独立互操作、帧、数据、资源/性能、注册/授权/撤权/DoS、设备/MTU/DNS/sandbox/升级、目录/前缀/故障切换、供应链/UI、E2E/无降级/成本、外部审查和运维演练。

每项证据必须绑定同一完整 commit，含不可变 Actions URL、命令、工具/feature/环境、预期/实际结果及负样本、报告 SHA-256、独立审核人和 UTC 时间。账本验证器只检查 metadata 一致，不证明测量或审计为真，不证明 reviewer/verifier 真正独立。独立 crypto/protocol 审计、fuzz/依赖审计以及所有阻塞/高危问题闭环不能由 CI 自证。

五平台均需真实 native functional execution 与 packet I/O，Linux 两架构还需静态生产后端证据。默认 CLI 静态报告、OpenSSL 独立 PoC、单个设备 round trip 或不同 commit 的测试都不够。必须覆盖主计划指定规模、持续资源、真实 CDN 支持边界、严格 E2E 失效无明文回落、吊销/可信时钟、新旧状态及故障回滚。

供应链至少要求：

- 精确依赖锁、工具链和 OpenSSL 等后端源码/版本/构建选项的完整 provenance，输入/输出 hash、workflow/run/runner、source commit，以及可信构建边界说明；自报 JSON 不冒称独立 attestation。
- 每个平台 SBOM（约定 SPDX 或 CycloneDX 格式并记录规范/生成器版本）、依赖漏洞/许可证审查、精确对应源码和第三方 notices；包含驱动时另审来源、签名、许可与更新责任。
- 独立重建与比较报告，明确不一致/不可复现部分，不把 archive 正常化当成编译可复现。
- 经实际平台核验的 Windows 签名/驱动和 macOS code signing/notarization 分发策略与密钥隔离。平台签名不替代 ReleaseRoot 双签，Wintun CI pin 不成为 Boreas 发布根。
- 版本/根轮换与吊销、可信 UTC、持久 anti-rollback、过期/冻结/同序号异内容检测、备份恢复及紧急安全更新策略。不把精简 manifest 称为完整 TUF。

## 6. 离线 ReleaseRoot 双签与核验

这是**未来满足准入后**的流程，不表示当前有可用生产包、生产密钥或已经验证的 promotion 修复。

1. 先冻结受保护 `main` 上完整 40-hex 候选；独立审核后，通过单独的 PR 把真实精确提交证据写入 `docs/engineering/release-evidence/gates.json`。使用该 PR 落到 `main` 第一父链上的完整 SHA 作为 `ledger_commit`，不要改动原候选，也不要用日常状态表 `docs/engineering/gates.json` 或 bundle 中的账本替代。所有适用门禁必须通过、独立审查闭环且经人批准。
2. 在 Actions 构建并保留五目标生产 archives、SBOM/provenance/source/license/报告，计算全部 hash/size。CI 只构建/测试，不生成或持有 ReleaseRoot 私钥。
3. 在离线/受控硬件签名环境，用独立于 NetworkRoot 的 ReleaseRoot 对**两份清单各自的精确原始字节**分别做 Ed25519 **和** ML-DSA-65 签名；必须 AND 验证，共四个签名半部。签名前限大小，不能解析重编码后验签。
4. ReleaseRoot 公钥通过独立带外渠道分发，预先钉住完整 SHA-256；不得从同源下载公钥和 hash 就自称建立独立信任。私钥保管、授权门限、双人复核、轮换/撤销、灾难恢复必须有独立操作规程，秘密绝不进入 CI Secrets/日志/artifact。
5. 使用已预先信任、独立维护的 verifier，核验双根隔离、两个 manifest 和所有 archive。发布脚本不能自充独立密码实现。每次调用必须基于**本次新生成**报告，拒绝复用遗留验签成功报告；相关修复代码已写入，仍待准确 commit 的 Actions 回归验收。

离线 bundle 结构及精确 schema 见[平台发布门禁](<../engineering/platform-release-gates.md#5-production-promotion-procedure>)：

```text
promotion-bundle/
  release-manifest.json
  release-signature-envelope.json
  promotion-manifest.json
  promotion-signature-envelope.json
  release-root/roots.json
  artifacts/                         # exactly five archives
```

独立 verifier 的报告**不存放在 bundle 内**：promotion 工具每次在 bundle 外创建私有临时目录，将一个初始不存在的输出路径通过 `--json-out` 传给 verifier，只接受本次调用新生成的报告。旧 bundle 内附带的验签报告一律忽略，不能作为成功依据；最终 `--report` 为 promotion 检查摘要，不是可复用的独立验签授权。

release manifest 使用 supervisor 严格 schema：`product:"boreas"`、`manifest_version:1`、正 `sequence`、`published_at <= issued_at < expires`、最长 90 天、`min_compatible_state`、`signing_key_id`、五个唯一平台资产（`name/arch/size/sha256/https url`）。outer promotion manifest 绑定完整候选 commit、release manifest/账本/ReleaseRoot hash 与五资产；其中 `gate_ledger_sha256` 必须是单独评审的账本在 Git 中的原始 blob SHA-256，可由可信 main 工具的 `--check-ledger` 模式取得，禁止重新序列化后再散列。两个 manifest **都不能含自己的 hash**；detached envelope 可含被签 manifest 的 hash、key id 和双签。解析必须有大小/深度/整数边界，拒绝重复 key、歧义平台、路径穿越、未知字段及不合格 URL。

独立 verifier 必须产生覆盖本次两个 manifest 的全部四签和五 archive hash/size 的报告，不能仅写一个 `verified:true`。人工审核 verifier 的独立性和报告真实性。以下命令从已独立确认的、固定在受保护 `main` 的干净工具 checkout 执行，而非从候选目录执行：

```sh
python tools/release/production_promotion.py \
  --commit <candidate-40-hex> \
  --ledger-commit <reviewed-main-40-hex> \
  --bundle-dir /path/to/promotion-bundle \
  --expected-release-root-sha256 <out-of-band-pinned-64-hex> \
  --verifier-executable /path/to/pretrusted-independent-verifier \
  --report promotion-report.json
```

拒绝退出 `2`；成功退出 `0` 也只代表离线 bundle 内部核验结论，`published:false`，不执行发布、不建立服务、不使生产门禁自动成立。工具的 `--self-test` 为测试密钥合成 fixture，只能由 Actions 运行，不是生产证据。遗留报告问题的修复代码已写入，回归仍待准确 commit 的 Actions，未验收；本次文档没有本地运行该工具或验证修复。正式放行前必须收集针对该缺陷、缺报告/旧报告/失败 verifier 的准确 commit 负向 CI 证据。

## 7. 人工发布与回滚

在完整准入、离线签名和独立核验后，独立 approver 检查 source SHA、账本/报告 hash、签名字节、五目标资产、变更日志与安全/兼容性章节、许可证/SBOM/provenance、平台签名和恢复包，才允许人工解除 draft 并发布对应渠道。保留所有审计记录与原始不可变 bytes；后续 metadata 不得指向可覆盖同名对象。tag 只是可追溯标记，不是发布授权。

生产上线前必须在目标 OS/文件系统演练：

- 同文件系统 staging、先外部验双签/hash/size/架构再执行自检；preflight 检查磁盘、seccomp/capability 兼容、状态 schema 和回退可读性。
- 保存最后一个仍获准的已验签版本、可信根/sequence/时间水位、权限正确的配置与状态备份；backup/restore 不能造成身份代次、分配水位或吊销状态回滚。
- expand/contract 状态迁移，在旧版不可读写前明确不可回退点；不能承诺任意 downgrade。发布序号、最低安全版本和已知漏洞/撤销限制持续生效。
- 原子活动版本指针、持久 journal 和外部 supervisor，真实 readiness 而不是进程存在/退出 0；覆盖候选早崩溃、死锁、SIGKILL、掉电、磁盘满、跨 FS、坏指针及旧 sandbox 不兼容。
- canary 后按观测放量，触发业务完整性、安全/吊销、资源、兼容或健康门槛立即停止。回滚到仍获安全批准且状态兼容的版本，不回落经典、跳验签或将严格 E2E 降成 hop-only。
- supervisor 重启坏路径、systemd `Restart=on-failure`、配置 `confirm` 返回 accepted 均不是回滚演练完成；当前 CLI 无 daemon/readiness 服务接线，不能把现有库/最小监督器写成可工作的生产单元。

误发、根/签名密钥失陷、错误 hash 或高危问题应暂停发布/更新，独立渠道告警，保留证据，按预案撤销/换根或发布新序号修订，绝不删除后悄悄覆盖。删除 GitHub Release/移动 tag 不会撤回已下载二进制，也不能替代密码学撤销或管理员重新 provisioning。
