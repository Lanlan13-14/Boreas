# 开发产物使用与未来部署边界

本教程当前可执行的范围是：获取开发归档、离线检查来源/完整性、在**预先信任产物之后**运行五平台 CLI、静态验证和迁移配置。**它不是生产 VPN 安装教程。** 当前无 `daemon`、`pki`、`bench`、`probe` 命令，没有完整 CLI 数据面，没有可工作的生产服务单元。WSS/逐跳 TLS/E2E 已有库 API 与可选后端不意味着 CLI 能连接 VPN；默认 artifact 没有 TLS 后端。

[生产账本](<../engineering/gates.json>)仍为 `production_approved:false`，所有适用门禁 open。以[主计划](<../plans/BOREAS-MASTER-PLAN-v1.11.0.md>)、[平台门禁](<../engineering/platform-release-gates.md>)和[实际 CLI](<../../crates/boreas-cli/src/main.rs>)为准。全部编译、格式化、lint、测试和基准验证仍只在 GitHub Actions 执行；下文是面向已信任下载产物的用户操作，不要求本地构建或运行测试套件。

## 1. 获取开发产物：先确定来源，再执行

### 1.1 固定 commit 与 Actions run

1. 在 [Boreas Actions](https://github.com/Lanlan13-14/Boreas/actions) 中选 **Platform functional verification and development packaging**。记录完整 40 位 source commit、run URL、run attempt、执行者及 workflow 来源；避免不可信 fork/PR 产物。
2. 检查该次运行的 `lock-preflight`、五项 `build-test`、八项 `linux-runtime-compat` 和 `development-bundle`。以实际结论为准，不用[项目说明](<../../README.md>)的历史绿色记录替代本次结果。PR 不生成最终 bundle；job 未完成、失败或产物已过期时停下，不猜测存在可下载文件。
3. 下载 run-scoped `boreas-development-release-<run_id>`，保留全部五目标归档和索引，使用可信归档工具将 Actions 外层 ZIP 展开至新的私有工作目录。产物默认保留 14 天；缺失时请维护者在 Actions 重跑准确 commit。

若已预先信任 GitHub CLI、已登录并且知道真实 run id，可在仓库之外的私有目录执行以下下载操作。将值替换为已审核运行；不要把占位符当实际 run：

```sh
RUN_ID='替换为审核过的数字run_id'
gh run view "$RUN_ID" --repo Lanlan13-14/Boreas
gh run download "$RUN_ID" --repo Lanlan13-14/Boreas \
  --name "boreas-development-release-$RUN_ID" --dir ./release-bundle
```

也可逐目标下载 `boreas-development-<target>-<run_id>`，其中含归档、provenance、功能 smoke、工具链记录以及 Linux 静态报告；目录结构与最终 bundle 不同，不可直接伪装成完整 bundle。

### 1.2 完整性不是真实性

开发 bundle 的索引、`SHA256SUMS` 和 provenance **均未生产签名**。从同一下载源拿到的二进制与哈希可能同时被替换。GitHub HTTPS、commit hash、workflow 绿色结果或自报 `production_release:false` 都不是独立 ReleaseRoot 认证。

在运行任何下载的 Boreas 二进制之前：

- 使用预先可信的本地工具、受保护且已经审核的源代码检查脚本；不要执行随未知包提供的“校验器”。
- 从独立可信渠道获得批准运行的 commit、archive SHA-256/size 及风险批准，逐项比对。组织若不接受 unsigned 开发产物，**到此停止**；当前不存在严格生产可信安装替代路径。
- 即便接受 GitHub 构建链作为较弱开发信任，也须明确记录这个前提，只在隔离、无生产密钥的开发环境使用；不能称为后量子可信安装。
- 首次未知二进制的 `doctor` / `self-check` 是执行代码，不是验签。禁止 `curl ... | sh`、关闭 TLS 校验或先运行二进制再用其自检结果建立信任。

使用预先审核的仓库副本和 Python 3.12，在该副本的仓库根目录运行**完整性检查**（不是编译/测试）：

```sh
python tools/release/verify_bundle.py --bundle /absolute/path/to/release-bundle
```

Windows 同一脚本可用 `python tools/release/verify_bundle.py --bundle C:/BoreasDev/release-bundle`。成功退出 `0`，输出应明确 `production_release:false` 和 `signature_verification:"not_performed_development_bundle"`；失败退出 `1`，拒绝继续。它核对五目标归档、哈希、大小、嵌入元数据与部分危险归档结构，不建立真实性，不验证外部审计，也不代替带外核验。不要直接在未知 bundle 中执行脚本。

手动核对带外预期 SHA-256 的工具示例：Linux `sha256sum <archive>`，macOS `shasum -a 256 <archive>`，PowerShell `Get-FileHash <archive> -Algorithm SHA256`。必须逐字比对完整值；同源 `SHA256SUMS` 仅能发现传输/混包错误。检查通过也不能把开发 bundle 改名后提升为生产 bundle。

## 2. 选择五平台产物并静态检查

实际归档名来自[打包实现](<../../tools/release/package.py>)：`boreas-<软件版本>-<target>.tar.gz`，Windows 使用 `.zip`。当前软件版本 `0.1.0`；不要把主计划 `v1.11.0` 代入软件版本。以下示例仅在下载元数据确实是 `0.1.0` 时使用；未来版本按索引调整，不能猜测 URL。

| 系统/CPU | target | 归档名（当前版本示例） | 检查 |
|---|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-musl` | `boreas-0.1.0-x86_64-unknown-linux-musl.tar.gz` | ELF x86-64，无 `PT_INTERP`/`DT_NEEDED` |
| Linux ARM64 | `aarch64-unknown-linux-musl` | `boreas-0.1.0-aarch64-unknown-linux-musl.tar.gz` | ELF AArch64，同样无动态依赖 |
| Windows x64 | `x86_64-pc-windows-msvc` | `boreas-0.1.0-x86_64-pc-windows-msvc.zip` | PE x64；不声称全静态或 Authenticode 已签 |
| macOS Intel | `x86_64-apple-darwin` | `boreas-0.1.0-x86_64-apple-darwin.tar.gz` | Mach-O x86_64；不声称 notarization |
| macOS Apple Silicon | `aarch64-apple-darwin` | `boreas-0.1.0-aarch64-apple-darwin.tar.gz` | Mach-O arm64；不依赖 Rosetta 代替原生证据 |

先检查主机架构（Unix `uname -m`，Windows `$env:PROCESSOR_ARCHITECTURE`），只展开匹配归档至新的目录。不要在系统 PATH/安装目录覆盖现有程序，不要用 root 解包。当前内层归档应只有可执行文件、许可证、源码指针与开发元数据四个普通文件；用可信归档工具先检查列表，拒绝路径穿越、额外文件、链接或特殊文件。之后再解包，例如 Linux x86_64：

```sh
mkdir ./boreas-cli
# 下列操作只针对已通过前述来源及完整性检查的归档。
tar -tzf ./release-bundle/boreas-0.1.0-x86_64-unknown-linux-musl.tar.gz
tar -xzf ./release-bundle/boreas-0.1.0-x86_64-unknown-linux-musl.tar.gz -C ./boreas-cli
file ./boreas-cli/boreas
readelf -h ./boreas-cli/boreas
readelf -l ./boreas-cli/boreas
readelf -d ./boreas-cli/boreas
```

两种 Linux 架构都必须确认 ELF machine 正确、program headers 无 `INTERP`、dynamic section 无 `NEEDED`；aarch64 替换 target 后同样检查。不要用 `ldd` 处理未知二进制。缺 `file`/`readelf` 时使用管理员预先提供的可信静态检查环境，不能跳过并宣称静态验收。静态 CLI 不等于静态生产 TLS 后端。

macOS 将归档 target 换为对应值，用 `file ./boreas-cli/boreas`、`lipo -archs ./boreas-cli/boreas`、`otool -L ./boreas-cli/boreas` 检查架构与依赖；系统依赖本身不是 Linux 静态要求违例。Gatekeeper 阻止时停止并交由管理员审查，不建议移除 quarantine 或关闭保护来假装正式签名。

Windows 用可信归档工具检查 ZIP 列表后再展开：

```powershell
Expand-Archive -LiteralPath .\release-bundle\boreas-0.1.0-x86_64-pc-windows-msvc.zip -DestinationPath .\boreas-cli
Get-AuthenticodeSignature -LiteralPath .\boreas-cli\boreas.exe
# 如已有 Visual Studio 检查工具，在其 Developer PowerShell 中使用：
dumpbin /headers .\boreas-cli\boreas.exe
dumpbin /dependents .\boreas-cli\boreas.exe
```

PE machine 应为 x64。未提供 Boreas Authenticode 签名是当前缺口，不能把 `NotSigned` 当成身份验证成功；不得安装来历不明的检查工具。Wintun 仅是独立 CI 测试依赖，当前 CLI 不需要安装驱动，也未在包中分发 Wintun DLL。

## 3. 运行已预先信任的 CLI：不是 VPN 验证

完成上述信任步骤后，五平台原生运行同一组离线命令，无须管理员权限：

```sh
./boreas-cli/boreas help
./boreas-cli/boreas doctor
./boreas-cli/boreas self-check
./boreas-cli/boreas --lang zh-CN status --json
./boreas-cli/boreas menu --json --narrow
```

Windows PowerShell 改用 `& .\boreas-cli\boreas.exe help` 等。每次调用后立即检查 `$?`（POSIX shell，`echo "$?"`）或 `$LASTEXITCODE`（PowerShell）。当前正常离线命令退出 `0`，能力必须如实为 daemon/TLS/network/control socket 未集成、`phase0_complete:false`；状态必须是 `not_connected`，菜单 `daemon:false`。输出与这些边界矛盾时停止并报告，不能继续称为预期默认产物。

`status`/`menu` 是一次渲染，不轮询、不接控制 socket、不处理菜单按键。`--json` 避免 TTY 呈现差异；非 TTY 本来就输出 JSON。没有 `--version` 子命令，用状态 JSON 和包元数据确认版本。`boreas-easy` 入口名仅映射无参数到离线状态，归档只含主二进制。

这些用户操作只演示进程启动和静态 CLI，不是本地测试套件；五目标真正的构建/测试/功能 smoke 证据仍必须来自该 commit 的 Actions。八项 Linux 容器检查不是宿主内核、TUN、systemd 或完整发行版 VPN 兼容性证明。

## 4. 配置创建与 0600 安全检查

### 4.1 Unix：Linux 与两种 macOS

在用户私有开发目录中复制[规范示例](<../config/config.example.toml>)，不要直接检查 checkout 内通常为 `0644` 的文件。下面从可信仓库根目录执行，仅创建开发配置副本，不安装服务、不创建示例引用的密钥。`CLI` 必须替换成第 2 节中已核验、已解包二进制的真实绝对路径（下载示例在仓库外，不能假设仓库内存在同名目录）：

```sh
CLI='/替换为已核验解包目录的绝对路径/boreas'
umask 077
mkdir -m 700 ./boreas-dev-config
cp ./docs/config/config.example.toml ./boreas-dev-config/config.toml
chmod 600 ./boreas-dev-config/config.toml
"$CLI" config-check ./boreas-dev-config/config.toml
```

Linux 用 `stat -c '%a %U %n' ./boreas-dev-config/config.toml`，macOS 用 `stat -f '%Lp %Su %N' ./boreas-dev-config/config.toml` 检查为 `600` 且属主是当前有效用户或 root；目录应 `700`。不要对未确认路径递归 chmod/chown。示例引用 `/etc/boreas`、`/var/lib/boreas`，不代表这些文件应存在或会被创建；仅做静态解析时保持绝对路径即可。

实现会安全打开最终文件、拒绝 group/world 位、非普通文件、最终符号链接、不合格属主和大于 64 KiB 的文件；读取检查在 fd metadata 上完成。**它不是完整路径安全审计**：中间目录符号链接仍可能被内核解析，未实现全组件 `openat2` 保障，配置硬链接不是此检查的拒绝承诺。所有父目录须可信且不可被攻击者写入。应设置明确 `0600`，不要把实现仅检查 group/world 位推断为精确模式/ACL/硬链接的全面证明。

### 4.2 Windows x64

POSIX 的 `/etc/...` 不是 Windows 绝对路径。建立当前用户私有的开发目录，复制样例并把 `[paths]` 改为 Windows 绝对路径（TOML 用正斜杠或单引号，避免反斜杠转义）：

```toml
[paths]
identity_key = "C:/BoreasDev/keys/identity.key"
roots = ["C:/BoreasDev/roots.cbor"]
state_dir = "C:/BoreasDev/state"
```

其余字段保留规范示例的 `version = 2` 和完整 `[node]`/`[uplink]` 等。`C:/BoreasDev` 是开发位置示例，不是系统安装目录；不存在的密钥/根引用仍可能通过静态检查。

```powershell
Get-Acl -LiteralPath C:\BoreasDev\config.toml | Format-List
icacls C:\BoreasDev\config.toml
& .\boreas-cli\boreas.exe config-check C:/BoreasDev/config.toml
$LASTEXITCODE
```

由管理员确认目录及文件 DACL 仅允许必要的当前用户、SYSTEM/管理员，排除广泛继承授予；不要盲目删除所有 ACL 导致锁死。CLI 不检查 NTFS ACL/所有者，`valid:true` 不代表 DACL 安全。最终 reparse point 拒绝不等于所有父组件均可信。

### 4.3 静态策略与输出的真实含义

详见[配置参考](<../config/README.md>)和[实现](<../../crates/boreas-cli/src/config.rs>)：

- 必须显式 `version = 1` 或 `2`，未知字段拒绝；v2 必须有 `[node]`、`[paths]`、`[uplink]`。
- `net_id` 为 32 hex；`home_core_id` 为 1–16，Core `vip_octet=1`，Edge 为 2–251；`node_id=((home_core_id-1)<<8)|vip_octet`，身份代次至少 1。手工改 role 不会获取真实角色授权。
- 路径必须绝对，roots 非空；uplink 为 `host:port`，不填 `wss://`、userinfo、路径、query、fragment 或 IPv6 literal；`paths` 为 1–8、`probe_paths` 为 0/1，不是容量保证。
- 默认 `e2e-required` 与 `pq768`。`pq1024`、`limits.default_route=true`、generic `enrollment` 配置会拒绝；`allow_edges` 只允许 core。`dns.tcp=true` 因 CLI 没有集成 TCP DNS runtime 能力而拒绝，不应跳过此能力门禁。
- IPv6、路由、Edge 直连等可解析字段仅表达意图，当前不会创建网络行为。

输出 `valid:true` 仅表示文档/静态策略符合要求，路径与 endpoint 脱敏。不读取身份私钥或根锚内容、不建立信任链、不检查引用文件存在/安全、不创建 state_dir、不拨号、不应用设置。`net_id` 等公共标识仍可输出；分享诊断前继续检查隐私。

## 5. 显式迁移 v1 到 v2

旧布局见[legacy 示例](<../config/config.legacy-v1.example.toml>)。`config-check` 对 v1 输出 `schema:"legacy-v1"`、`migrated:true`，但不改文件；`config-migrate` 只向 stdout 输出完整规范 v2，**不会脱敏**。迁移输出含路径/endpoint，应按敏感配置保存，不能上传公共日志。

Unix 在已受保护且可信的开发目录中使用不同的新文件名，沿用第 4.1 节指向预信任二进制的绝对路径变量 `CLI`：

```sh
umask 077
# 先保护输入，并保留私有备份；不要让重定向截断输入本身。
cp ./boreas-dev-config/legacy.toml ./boreas-dev-config/legacy.backup.toml
chmod 600 ./boreas-dev-config/legacy.toml ./boreas-dev-config/legacy.backup.toml
if "$CLI" config-migrate ./boreas-dev-config/legacy.toml > ./boreas-dev-config/config.v2.candidate.toml; then
  chmod 600 ./boreas-dev-config/config.v2.candidate.toml
  "$CLI" config-check ./boreas-dev-config/config.v2.candidate.toml
else
  printf '%s\n' '迁移失败，保留原配置，不使用候选输出' >&2
fi
```

人工比较输入/候选中的角色、永久 slot、身份代次、根锚、安全模式和 endpoint，确认 `config-check` 也成功后，才在受控配置流程中选择新文件。不要直接重定向覆盖原文件，不要因 stdout 文件存在就假定成功。

Windows 在预先限制 DACL 的目录，用 PowerShell 7 的 UTF-8 无 BOM 输出，先检查退出码：

```powershell
$migrated = & .\boreas-cli\boreas.exe config-migrate C:/BoreasDev/legacy.toml
if ($LASTEXITCODE -ne 0) { throw '迁移拒绝，保留原文件' }
$migrated | Set-Content -LiteralPath C:\BoreasDev\config.v2.candidate.toml -Encoding utf8NoBOM
& .\boreas-cli\boreas.exe config-check C:/BoreasDev/config.v2.candidate.toml
if ($LASTEXITCODE -ne 0) { throw '候选配置被拒绝' }
```

不要用可能写入 UTF-16 的旧 PowerShell 重定向当作 UTF-8 TOML。v1 的前两个 `wss://host[:port]` 变为 primary/backup（省略端口则 443），features 映射 limits，paths/probe_paths 默认 4/1。多于两个上行、非 WSS、路径/query/fragment 等需人工重写而不是丢信息。历史迁移说明可能简写拒绝所有 URL path；实际转换器仅允许空路径或单个尾随 `/`，任何业务路径均拒绝。

schema 迁移不代表网络状态迁移或在线 reload。安全模式、suite、网络/角色/slot、身份代次、key/roots 的变更是高危信任变更，未来需确认、持久审计及断开全部会话；当前 `confirm` 只返回 `applied:false`，不授权部署。

## 6. 排错与退出码

| 现象 | 含义与处理 |
|---|---|
| `doctor` 退出 0 但 daemon/TLS/network 为 false | 预期的离线开发 CLI，不是安装失败，也不是 VPN 已就绪 |
| `unknown or unavailable command ...; no daemon was started` | 命令不存在/未集成，退出 2；不要补写 systemd 服务去循环启动它 |
| 参数、语言、确认词错误 | CLI 退出 2；查 `help`，只支持 zh-CN/zh-TW/en，拒绝重复 `--lang` |
| `configuration ... group- or world-accessible` | Unix 配置过宽，核实真实路径/属主后设 0600；不要以 root 绕过 |
| `symbolic link or reparse point` / `not a regular file` / `could not be read` | 使用可信目录中的真实普通文件，核对权限、路径和最终链接；不放宽检查 |
| TOML/schema 错误、缺 version、超 64 KiB | 使用明确 schema 和 UTF-8，检查未知字段/类型；不会回显可能含秘密的原始 TOML |
| NodeID mismatch、路径非绝对、无 roots、endpoint 无效 | 按静态规则修正文档，不靠修改身份自报信息获得授权 |
| `dns.tcp` capability unavailable / `pq1024` disabled | 实现/验收缺口，不应修改 checker 或谎报能力换通过 |
| config-check 通过但连不上 | 此命令根本不会拨号；当前 CLI 无连接路径，无应当开启的监听端口 |
| `Exec format error` / `Bad CPU type` / Windows 无法运行 | target 与 OS/CPU 不符或文件损坏，回到独立来源/hash/架构检查；不要用模拟执行当原生证据 |
| Linux `not found` / permission denied | 先检查文件路径、执行位、挂载 noexec、ELF interpreter；不要假定安装动态库就能修复声称静态的错误产物 |
| bundle 核验失败 | 工具退出 1，保留原始文件/运行信息，拒绝执行，不编辑索引绕过 |
| artifact 缺失/过期或 `--locked` CI 失败 | 请维护者在 Actions 重跑或走锁刷新，不能本地重建后称同一受信产物 |

当前 CLI 正常静态命令返回 `0`；所有已实现的 CLI 参数/配置/确认拒绝返回 `2`。不要为这个 CLI 编造“网络错误 3/认证错误 4”等未实现映射。OS 启动失败/信号终止的状态由 shell/OS 决定，不在该两码契约内。[离线 promotion 工具](<../../tools/release/README.md>)使用独立退出约定：拒绝 `2`，成功 `0` 也只是 `published:false`，不是发布完成。

报错时附 OS/CPU、软件版本、完整 commit、Actions run URL/attempt、target、archive SHA-256、退出码和脱敏 stdout/stderr；不要附私钥、邀请、完整迁移输出、TLS secret 或整个配置目录。生产根、私钥和凭据不能进入 issue/CI artifact。

## 7. 未来生产部署：条件式检查表，不是当前安装步骤

只有以下前提全部满足，维护者才可以编写对应版本的生产安装命令：

1. 完整 CLI daemon 与数据面接线；发布支持矩阵记录 OS/CPU、TLS/backend feature、设备驱动、DNS、路由及限制。仅库 API 或默认无后端 artifact 不满足。
2. 主计划 Phase 0–5 的全部适用门禁、五平台真实功能和 packet I/O、Linux 两架构静态**生产 TLS**证据按同一准确 commit 验收；独立密码/协议审计、依赖审计及高/阻塞问题关闭；`production_approved:true` 的真实授权，不能只改账本布尔值。
3. 经过[发版规范](<../releases/README.md>)的离线 ReleaseRoot 双签、独立核验、SBOM/provenance、对应源码/第三方许可、平台签名与恢复材料准备完成。
4. 真实 daemon 与外部 supervisor 的 readiness、journal、状态兼容、故障回滚、权限收缩、seccomp 和服务管理器集成经过目标平台演练。当前 package 未携带完整 installer/supervisor 路径，主计划的 systemd 片段只是设计。

满足后依次实行的**条件步骤**：

- **若已存在受审查的生产版本及预置信任校验器**：通过独立渠道预置 ReleaseRoot 与 NetworkRoot，核对双根指纹；同文件系统 staging 下载，先校验两份清单双签和 hash/size、有效期/sequence/最低兼容状态，再检查架构/依赖，最后才运行新程序的自检。
- **若真实离线 PKI 命令已实现并验收**：每台节点由 OS CSPRNG 本机独立生钥并离线预配 NodeIdentity；身份、角色、永久地址和代次经 IdentityAuthority 授权。不能复制其他节点私钥/整份配置，不由普通转发 Core 代签全网身份。
- **若 daemon 与平台集成已验收**：按专用用户、0700 目录/0600 密钥与配置、可信时钟和保护性管理路由配置；逐步验证外层 HTTPS/CDN 回源与逐跳内层 TLS、E2E 的实际协商/身份/吊销新鲜度，再启用业务。默认保持 IPv6、子网、Edge DIR 关闭，首发不启用默认路由出口。
- **若服务管理器合同已实测**：使用该版本正式提供、审核过的单元/Windows 服务/launchd 配置；资源上限按 RSS 加内核 socket 记账重算，权限与 sandbox 按 ABI 实测。不能复制主计划示例后声称可工作，不能用 `Restart=on-failure` 代替 supervisor 回滚。
- **若运维/回滚演练已通过**：小范围 canary，检查业务完整性、E2E 无降级抓包、权限/吊销/时间失效拒绝、真实 DNS/路由和资源预算；放量后持续观测，失败按签名、兼容与安全策略回退，绝不退回已撤销或低于最低安全版本的二进制/状态。

目前上述生产条件未满足，必须停在开发使用边界；本教程不提供 `systemctl enable`、服务单元或虚构 `boreas daemon` 安装命令。
