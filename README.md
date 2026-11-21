# Boreas

**将 IP 流量装进经认证的加密隧道。** Boreas 是以 Rust 编写的实验性 L3 TUN 隧道项目：以 TLS 1.3 + WebSocket over TCP 建立承载，在节点间协商后量子混合密钥套件，并为业务电路提供端到端加密设计。项目面向开发者、网络工程师与安全研究人员；当前仍是开发预发布项目，不是经审计的生产 VPN。

> **先读边界：** 目前最新公开预发布资产仍为 [`v0.1.0-pre.3`](https://github.com/Lanlan13-14/Boreas/releases/tag/v0.1.0-pre.3)。仓库正在推进下一版开发主线；工作流文件、安装器或 UI 实现存在，并不等于相应功能已通过设备验收。原生依赖安全门禁仍未通过，`v0.1.0-pre.4` 尚未创建或发布；不要预设其版本号、资产名或校验和。生产审批仍为 `false`，24 项生产门禁仍开放。不要用于高敏或关键生产业务。

[双机部署教程](docs/deployment/README.md) · [一键安装器边界与流程](docs/deployment/ONE_CLICK.md) · [实现状态与 CI 证据](docs/engineering/implementation-status.md) · [配置参考](docs/config/README.md)

---

## Boreas 的设计

Boreas 的目标是让业务 IP 报文经由 TCP/WSS 承载穿过常见网络，同时保留严格的节点身份校验与端到端保护。当前代码包含以下安全层设计与实现切片：

1. **承载层：** TLS 1.3 与 RFC 6455 WebSocket 二进制帧，使用 TCP，不要求开通 UDP 端口。
2. **节点会话层：** 可选 OpenSSL 3.6+ 后端的 `X25519MLKEM768` 混合密钥交换及 `ML-DSA-65` 身份认证；离线 PKI 对身份对象签名并绑定证书公钥。
3. **业务电路层：** `e2e-required` 模式旨在让端点之间再建立加密电路，避免中继读取业务载荷。

这些是当前项目的架构与受限实现能力描述，不是独立密码学审计结论。协议互操作、部署拓扑、长稳性及生产安全仍需门禁验收。

## 当前状态：已验证什么、仍在做什么

| 范围 | 可据实陈述 | 不能据此推断 |
|---|---|---|
| Linux 双节点隧道 | `pre.3` 公开资产提供 Linux x86_64 musl pq768 二进制；项目已有 Linux TUN/CI 与隔离环境端到端验证记录 | 多节点网格、自动故障切换、通用生产 VPN 或其他平台 daemon 已支持 |
| 端点候选保存 | Linux 上 `config-save-candidate` 可将已校验的 `[uplink]` 片段写入当前用户已有安全配置根下的 `boreas/candidates`，必须精确 `--confirm SAVE`，成功返回 `applied:false`；源配置及密钥/roots 引用不变 | Windows/macOS 不支持；片段不是完整配置，不能直接替换；不安装、不应用、不重载、不连接，也不验证可达性 |
| 性能 | 精确提交 [`8cf865e`](https://github.com/Lanlan13-14/Boreas/commit/8cf865ec7bc9f974b2db623c6c60917e6af7ec08) 的隔离 netns/veth 基准中，glibc 平均延迟 `0.228 ms`、吞吐 `268.450 Mbps`；musl 平均延迟 `0.256 ms`、吞吐 `194.547 Mbps`。参见 [该提交性能工作流](https://github.com/Lanlan13-14/Boreas/actions/runs/43722214463) | 这些数字代表公网 SLA、跨地域 RTT、持续负载/攻击容量或任意版本的性能 |
| CI | 同一精确提交的 Rust、平台及 Linux TUN 工作流分别为 [43722214359](https://github.com/Lanlan13-14/Boreas/actions/runs/43722214359)、[43722214368](https://github.com/Lanlan13-14/Boreas/actions/runs/43722214368)、[43722214397](https://github.com/Lanlan13-14/Boreas/actions/runs/43722214397)，均成功 | CI 成功不等于所有生产门禁通过、独立互操作/审计通过或当前分支 tip 已覆盖 |
| `boreas-easy` | 有行式控制台入口与中文简体、繁体、英文本地化；当前适合作为控制台/状态操作入口 | 它不是图形界面，也不能据此宣称已完成生产控制面、完整服务管理或安全操作验收 |
| 一键安装 | `tools/deploy/` 含安装辅助脚本及 systemd/procd 模板；详见[安装器说明](docs/deployment/ONE_CLICK.md) | 脚本文件存在不等于已验证支持 OpenWrt、不同发行版、所有架构或生产升级回滚 |

**拓扑与生产限制：** 当前可用说明集中于 Linux 上的 `1 Core ↔ 1 Edge` IPv4 点对点场景。多 Core 多跳路由、自动故障切换、内建 DNS 运行时、生产级证书/状态轮换及完整 supervisor 在线升级闭环未完成。Windows/macOS 原生 TUN 库或基础归档不代表 daemon 已支持这些平台。24 项生产门禁（含独立审计、互操作与资源测试）仍为 `open`；参阅[门禁账本](docs/engineering/gates.json)及[状态证据](docs/engineering/implementation-status.md)。

---

## 选择适合你的入口

- **想先理解限制并手动搭建双机：** 从[双机公网部署教程](docs/deployment/README.md)开始。它涵盖离线 PKI、Core/Edge 配置、TUN 路由、状态检查、systemd 示例与排错；示例中所有 IP、域名、序号与权限都需按环境审阅。
- **想审阅安装步骤：** 看[受限一键安装指南](docs/deployment/ONE_CLICK.md)。先用 `--dry-run`；它安装已有二进制，不负责编译，也不会替你验证来源信任、生产路由或设备兼容性。
- **想看控制台：** `boreas-easy` 是行式三语入口，不是 curses/图形 TUI。交互终端下可以逐行操作；非 TTY 环境输出一次 JSON，避免脚本挂起。具体状态与可用操作以运行时探测和权限为准。
- **想开发或审阅实现：** 查看[实现状态与证据门禁](docs/engineering/implementation-status.md)、[配置字段说明](docs/config/README.md)和 [GitHub Actions 测试导航](docs/engineering/ci-workflows.md)。

### `boreas-easy` 快速入口

二进制默认提供 `boreas` 命令；安装时可创建 `boreas-easy` 入口。交互 shell 中运行：

```sh
boreas-easy
# 或
boreas console
```

默认控制套接字为 `/run/boreas/control.sock`，默认配置路径为 `/etc/boreas/config.toml`；不同部署应明确传入实际路径。查看一次 JSON 状态（适合脚本或无 TTY）：

```sh
boreas-easy --json
boreas console --json --socket /var/lib/boreas/control.sock --config /etc/boreas/edge.toml
```

终端宽度有限时可用 `--narrow`；语言可由 `--lang zh-CN|zh-TW|en` 指定。控制台不是绕过权限或信任策略的管理后门；启动服务等动作需审阅确认提示及本机服务配置。若控制套接字不可用，检查 daemon 是否运行、socket 路径与 UID/权限是否匹配。控制台目前只有端点预览，不提供保存动作；输入 `SAVE` 不会写入候选。

---

## 快速开始：获取当前公开预发布资产

下面命令**仅对应已经发布的 `v0.1.0-pre.3` 资产**，不要把下一版开发主线当作已发布版本，也不要自行套用未发布的文件名或校验和：

```sh
VERSION="v0.1.0-pre.3"
BASE_URL="https://github.com/Lanlan13-14/Boreas/releases/download/${VERSION}"
curl -fLO "${BASE_URL}/boreas-linux-x86_64-musl-pq768"
curl -fLO "${BASE_URL}/SHA256SUMS-PRE3"
grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -
sudo install -m 0755 boreas-linux-x86_64-musl-pq768 /usr/local/bin/boreas
boreas doctor
```

仅在发布页提供且本地校验通过时使用该资产。`doctor` 用于查看二进制编译能力，不会验证你的部署、网络可达性或生产安全。若要实际搭建，请先读[完整部署教程](docs/deployment/README.md)及[限制说明](docs/deployment/ONE_CLICK.md)。

---

## 常用命令

| 命令 | 用途与边界 |
|---|---|
| `boreas doctor` / `boreas self-check` | 显示此二进制的编译能力；不是健康检查或安全认证 |
| `boreas config-check <FILE>` | 校验配置格式与文件权限，输出脱敏结果 |
| `boreas config-migrate <FILE>` | 将受支持的旧版配置转换并输出至 stdout，不原地改写 |
| `boreas config-save-candidate ...` | 仅 Linux：保存端点候选片段；需精确 `--confirm SAVE`，成功返回 `applied:false`；不替换源配置；详见[配置参考](docs/config/README.md) |
| `boreas pki init-ca ...` | 初始化离线 PKI；私钥必须离线保护，切勿上传到公网节点 |
| `boreas pki issue-node ...` / `sign-status ...` | 签发节点材料或状态快照；请参考部署教程的完整参数与轮换流程 |
| `boreas pki verify-bundle --material-dir <DIR> --require-peer` | 验证本地节点材料包，不证明其分发渠道安全 |
| `boreas daemon serve ...` / `connect ...` | Linux pq768 构建上的 Core/Edge daemon 命令；需要 TUN、网络权限及正确材料 |
| `boreas ctl status [--socket <PATH>]` / `boreas status` | 查询控制套接字状态或显示终端视图 |
| `boreas-easy` / `boreas console` | 行式三语控制台；非交互场景可传 `--json` |

带有 OpenSSL 后端要求的 `pki`/`daemon` 命令，需使用包含 `openssl-inner-tls` 能力的构建。缺少后端的基础 CLI 构建会拒绝相关命令；请以 `boreas doctor` 为准。

### 端点候选保存（仅 Linux，`applied:false`）

`config-save-candidate` 只持久化 endpoint-only 候选，不安装、不合并、不替换、不应用、不重载、不连接，也不启动 daemon。Linux 上使用：

```sh
boreas config-save-candidate \
  --config /etc/boreas/config.toml \
  --primary edge.example.net:443 \
  --backup backup.example.net:443 \
  --confirm SAVE
```

`--config`、`--primary`、`--confirm SAVE` 必填，`--backup` 可选；`SAVE` 必须逐字匹配，小写、空白、前缀、缺失或重复/未知参数都会在任何写入前失败。命令不弹交互提示、不读 stdin。

路径只使用**已存在**的安全用户配置根：`XDG_CONFIG_HOME` 已设置时必须为绝对路径、已存在、属于当前有效 UID，且路径组件不是符号链接、不可被组/其他用户写入；相对或不安全的显式值会直接拒绝，**不会**回退到 `$HOME/.config`。未设置时 `$HOME/.config` 也必须已存在并通过同样检查。`boreas/` 与 `candidates/` 若缺失会在已验证根下自动创建为 `0700`；若已存在则必须是当前用户所有的 `0700` 真实目录，否则拒绝且不 chmod 修复。程序自行生成 `uplink-<pid>-<时间戳>-<nonce>.toml`，以 `0600` 独占创建，绝不覆盖已有文件。

成功输出类似：

```json
{"saved":true,"applied":false,"candidate":"uplink-1234-...-0.toml"}
```

`candidate` 只是 basename，`applied` 恒为 `false`。写入内容只有 `[uplink]` 的 primary、可选 backup、原有 paths/probe_paths 和“未应用”注释；它**不是完整 `version = 2` 配置**，不能直接替换现有配置。源配置及其中引用的密钥、roots、state_dir 均不被改写，密钥/roots 内容也不会被读取；成功不表示端点可达、配置已安装或已生效。

Windows/macOS 不支持写入候选：命令报 `candidate saving is supported only on Linux` 并非零退出，不创建文件。`boreas-easy`/`boreas console` 仍只有端点预览，没有保存动作；在控制台输入 `SAVE` 不会写入候选，需在控制台外审阅预览或使用上述显式命令。

**证据边界：** 精确提交 [`0295cf8`](https://github.com/Lanlan13-14/Boreas/commit/0295cf86b08261aa57a8fecd3c21fb17be618692) 的 Rust [43972354816](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354816) 与 TLS [43972354900](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354900) 工作流成功；这只是该 SHA 上候选保存/私有目录测试的证据，不代表后续提交或当前分支 tip 全绿，也不代表生产/安全门禁通过。原生安全门禁仍未通过，`pre.4` 尚未发布。

---

## 安全与故障排查起点

- **先验证信任材料：** 禁止把 `ca/`、根授权或状态签名私钥发到 Core/Edge。节点只接收其运行所需材料；对端身份与状态快照须由同一离线 CA 集合签发并离线验包。
- **核对权限与时间：** 配置应为 `0600`，秘密材料仅授权运行用户读取；PKI 时间校验依赖正确 UTC/NTP。状态快照过期或回滚会 fail-closed，需由离线授权者递增序号重新签发。
- **排查连接：** 裸 IP `--connect` 时确认 `--tls-name` 与 Core 证书 SAN 相符，并核实 `--ws-host`、TCP 防火墙、WSS 路径及反向代理升级设置。通常不需 UDP 端口。
- **谨慎安装与路由：** 安装器提供摘要/静态 ELF 检查，但摘要必须来自独立可信渠道；同源下载不构成独立验证。安装不会自动评估 SSH/管理路由冲突；启动前核对路由、TUN 名称和防火墙环境。
- **不要从 CI 推断生产就绪：** 仅引用对应精确提交的工作流与环境。netns/veth 基准不是公网实测 SLA；一键脚本/OpenWrt procd 模板也不等同于实机验证。

更完整的错误现象、根因和修复步骤见[部署教程排错表](docs/deployment/README.md#常见报错排查)与[一键安装说明](docs/deployment/ONE_CLICK.md)。

---

## 仓库与开发验证

主要 crate：`boreas-cli`（CLI/控制台）、`boreas-pki`（离线 PKI）、`boreas-crypto`（密码后端）、`boreas-tunnel`（传输与电路）、`boreas-tun`（TUN 适配）、`boreas-dns`（DNS 原语）、`boreas-supervisor`（升级原语）。它们的存在不表示每条产品链路已集成；详细完成度请以[实现状态文档](docs/engineering/implementation-status.md)为准。

按项目约定，CI/测试在隔离工作流中执行。基础本地开发命令示例：

```sh
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
```

带 OpenSSL 后端的构建还需准备符合项目配置的 OpenSSL 3.6+ ML-KEM/ML-DSA provider；Linux TUN 验证需有 `/dev/net/tun` 与相应权限。更具体的 CI 工作流和已验证运行号请查状态文档。本次文档更新不声称运行测试。

## 文档与许可

- **安装与部署：** [双机教程](docs/deployment/README.md) · [一键安装器说明](docs/deployment/ONE_CLICK.md)
- **配置与实现：** [配置参考](docs/config/README.md) · [实施状态](docs/engineering/implementation-status.md) · [v1.11.0 架构主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)
- **许可证：** [GPL-3.0-only](LICENSE)
