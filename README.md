# Boreas

Rust L3 Overlay 互联引擎的开发仓库，面向跨云、跨洲及不可信 CDN WebSocket 承载场景。

**当前不是生产可用 VPN，没有任何生产发布获批。** 软件包版本当前为 `0.1.0`；`v1.11.0` 是安全与工程主计划的设计版本，不是已经发布的软件版本、冻结协议或安全认证。所有 Phase 0–5 与生产门禁仍未验收完成。

## 文档导航

- [开发产物获取、五平台 CLI 使用与部署边界](<docs/deployment/README.md>)：先建立信任再执行，配置权限、迁移、排错及未来生产前提。
- [发版规范](<docs/releases/README.md>)：SemVer、draft/prerelease、无 Emoji 变更日志、离线双签、门禁与回滚。
- [v1.11.0 安全与工程主计划](<docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md>)：架构设计的权威来源。
- [实现状态与证据记录](<docs/engineering/implementation-status.md>)、[机器可读门禁账本](<docs/engineering/gates.json>)、[平台与发布门禁](<docs/engineering/platform-release-gates.md>)：实现切片、CI 结果和验收之间的边界。
- [配置参考](<docs/config/README.md>)、[注册事务](<docs/enrollment/README.md>)、[升级与 supervisor](<docs/upgrade/README.md>)、[开发发布工具](<tools/release/README.md>)。

## 现在有什么，不能做什么

| 层次 | 当前范围 | 不代表什么 |
|---|---|---|
| 用户 CLI | 帮助、能力 JSON、离线状态/菜单、静态 TOML 检查与迁移、确认词演示 | 不启动 daemon，不打开网络或控制 socket，不应用配置 |
| 库 API | WSS HTTP/1.1、逐跳内层 TLS 接口、会话授权、E2E 电路及显式 OpenSSL 适配器；原生 TUN/Wintun/utun、DNS、PKI、升级事务等实现切片 | 不是已接线的 CLI VPN，不是完整生产数据面、真实 CDN 验收或独立安全审计 |
| 默认开发 artifact | 五目标 CLI 归档、未签名索引/校验和、构建 provenance；Linux 静态链接检查 | 无 TLS 后端、无 daemon；不是 production 安装包，无 ReleaseRoot 生产双签，无 SBOM/可复现构建证明 |
| CI | 编译、单元测试、CLI smoke、Linux 静态检查；独立工作流运行真实设备测试 | 平台构建通过、`doctor` 返回 0、设备测试通过均不等于生产门禁通过 |

不要将“真实 WSS/E2E 的库 API 存在”误读为“命令行已能连接 VPN”。默认 [tunnel 特性](<crates/boreas-tunnel/Cargo.toml>)不启用密码后端；[CLI 依赖](<crates/boreas-cli/Cargo.toml>)也未接入 tunnel runtime。可选后端及库路径必须在其准确 commit、feature、工具链和平台上获得单独证据，不能从默认平台构建外推。

**当前无 `daemon`、`pki`、`bench`、`probe` 命令。** 主计划中的这些名字是未来设计。没有可工作的生产安装器或服务单元；不要给当前二进制配置 `ExecStart=... daemon`，也不要将 supervisor 的存在当成完整升级安装路径。

## 快速开始：只做离线 CLI 检查

先按[部署教程的下载与信任步骤](<docs/deployment/README.md#1-获取开发产物先确定来源再执行>)获取并预先信任正确平台的产物。以下是用户在信任建立后使用已下载 CLI 的例子，不是构建/测试命令，更不是安全引导方法：

```sh
./boreas help
./boreas doctor
./boreas --lang zh-CN status --json
./boreas menu --json --narrow
```

Windows 使用 `./boreas.exe` 或 PowerShell 的 `.\boreas.exe`。不需要 root/管理员权限，不创建 TUN，不修改路由或 DNS。没有 `--version` 命令：软件版本看离线 `status --json` 输出和归档元数据。

`doctor` / `self-check`（及无参数 `boreas`）输出 `foundation_only`，应明确包含：

```json
{"daemon":false,"tls_backend":false,"networking":false,"control_socket":false,"runtime_capabilities":"not_integrated","phase0_complete":false}
```

这是完整输出中的部分字段；退出 `0` 只说明该命令正常完成，不表示 VPN、安全性或生产 readiness。未知/不可用命令退出 `2`，不会假装已启动服务。

## CLI 参考

以下以[实际 dispatch/help 源码](<crates/boreas-cli/src/main.rs>)为准，不是主计划的未来命令清单：

| 命令 | 行为 |
|---|---|
| `boreas` / `doctor` / `self-check` | 输出能力 JSON，无网络操作 |
| `help` / `--help` / `-h` | 输出真实帮助 |
| `status [--json]` | 离线状态；非 TTY 自动 JSON，daemon 为 `not_connected` |
| `menu [--json] [--narrow]` | 一次性离线九项菜单渲染，不是交互式 TUI |
| `config-check <path>` | 读取一个受限 TOML 文件，静态校验并输出脱敏 JSON |
| `config-migrate <path>` | 读取显式 schema v1/v2，向 stdout 输出规范 v2，不改原文件 |
| `confirm <action> <typed...>` | 只检查确认词；即便接受也返回 `applied:false` |

全局 `--lang <zh-CN|zh-TW|en>` 或 `--lang=<tag>` 只允许一次；选择顺序为显式参数、`BOREAS_LANG`、`LC_ALL`、`LANG`。状态/菜单支持三语，配置命令保持机器可读 JSON。`NO_COLOR` 的非空值由菜单读取；当前渲染本来就不产生 ANSI。`boreas-easy` 仅是按入口名识别的别名，无参数等价于 `status`，不是另外一个 daemon；开发包不保证包含该符号链接。

确认词示例 `confirm hop-only HOP-ONLY`、`confirm revoke:42 REVOKE 42`、`confirm uninstall UNINSTALL` 均不真正变更模式、吊销或卸载。不得以此替代持久审计与真实会话断开。

## 配置与安全边界

规范 schema 是显式 `version = 2`，样例见[配置模板](<docs/config/config.example.toml>)。旧 `version = 1` 可显式迁移；缺失版本、未知字段和不符合静态策略的输入被拒绝。

- Unix 配置应为 `0600`，目录 `0700`，属主为 root 或有效用户。读取时拒绝 group/world 权限、最终组件符号链接、非普通文件和超过 64 KiB 的配置。
- Windows 拒绝最终 reparse point，但**不检查 NTFS ACL**，操作者须单独审查 DACL。Unix 中间目录符号链接及配置硬链接不是完整拒绝保证，父目录必须可信。
- `config-check` 不读密钥/根锚内容、不检查其存在或权限、不解析域名、不认证对端、不建立 TLS；`valid:true` 只是静态输入成立。
- `e2e-required` / `pq768` 是默认策略声明，不是已建立的加密通道。`pq1024`、默认路由出口被拒绝；当前 `[dns].tcp=true` 因未集成 runtime 能力被拒绝。IPv6/子网/直连开关即便可解析也不创建功能。

完整的安全落盘、Unix/Windows 示例、迁移和错误处理见[部署教程](<docs/deployment/README.md>)。

## 安全设计摘要：不是已验收能力

[主计划](<docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md>)要求外层 TCP/WSS、WS 字节流中的逐跳标准 TLS 1.3，以及默认强制的端点间 E2E TLS。CDN 终结的 HTTPS 不是节点间保密或身份认证来源。严格内层策略要求 hybrid KEX 与 ML-DSA 认证，控制对象和发布清单要求 Ed25519 + ML-DSA 双签 AND；不使用历史 PQ-IK/Pairwise 自研握手凑上线。

网络身份 `NetworkRoot` 与软件发布 `ReleaseRoot` 必须隔离并经独立渠道预置信任。转发 Core 不能成为任意节点的身份 CA；节点私钥必须本机独立生成，不得复制另一台节点的整个配置目录。

`e2e-required` 失败必须关闭业务，不能静默回落 `hop-only`。`hop-only` 意味着转发 Core 可见业务明文，模式切换需要真实审计和断开已有会话，不能当故障恢复。系统不承诺匿名、不覆盖端点 root/内核失陷、不保证无限 DDoS 下可用；TCP-over-TCP、内存、吞吐和恢复时间都必须按真实路径测量。

这些是必须实现和验收的要求，不是本 README 对当前产物作出的安全背书。所有适用门禁仍 open，独立审计与运维演练未完成。

## 开发、验证与贡献

**所有编译、格式化、lint、测试、性能和故障注入验证仅在 GitHub Actions 运行，不在本地运行。** 本地用户在完成独立信任建立后使用 CLI 是允许描述的操作，不等于本地构建或测试证据。本次文档更新没有执行本地编译/测试。

- [Rust CI](<.github/workflows/ci.yml>)与[平台工作流](<.github/workflows/platforms.yml>)执行相应 workspace 检查、五目标 native 构建与 CLI smoke。
- 平台工作流定义 Linux 两架构 × Ubuntu/Debian/Fedora/Alpine 共八项容器 CLI 检查；这是当前工作流定义，不是断言任意新 commit 已全部通过。
- 真实设备证据来自[Linux 系统工作流](<.github/workflows/linux-system.yml>)与[原生设备工作流](<.github/workflows/native-device.yml>)，不是 `doctor`。
- 保持 `--locked`；依赖锁更新仅走[锁文件刷新工作流](<.github/workflows/refresh-lock.yml>)。失败必须如实记录，不删负样本、不跳过安全检查，不将失败 workflow 中部分通过的 job 宣称为整体验收。

提交评审应列明准确 commit、变更的安全/兼容性影响、预期 Actions job 和实际证据链接。不要把历史绿色结果复用为当前 commit 的门禁证据。验签报告遗留问题的修复代码已写入，回归仍待准确 commit 的 Actions，未验收；本 README 不声称已经验证或获准生产。

## English summary

Boreas is a development-stage Rust L3 overlay project, not a production VPN. The software currently uses `0.1.0`; `v1.11.0` identifies the architecture plan only. The CLI provides offline reports, menu rendering and static configuration checking/migration. There are no `daemon`, `pki`, `bench` or `probe` commands. Real WSS/hop-TLS/E2E implementations are library APIs behind explicit backend features, not a complete CLI VPN. Default development artifacts have no TLS backend, are unsigned, and have not passed production gates.

Download only an exact-commit Actions development artifact, establish independent trust before executing it, then follow the [deployment guide](<docs/deployment/README.md>). Hashes from the same download do not establish authenticity; `self-check` cannot authenticate its own unknown executable. All compilation and tests are GitHub Actions-only. See the [release policy](<docs/releases/README.md>) for draft/prerelease handling and the future offline dual-signed promotion requirements. A tag alone must never trigger production publication.

## 许可证

GPL-3.0-only，见 [LICENSE](<LICENSE>)。二进制分发必须满足对应源码和第三方许可义务；归档中的源码 URL 指针本身不是完整合规证明。
