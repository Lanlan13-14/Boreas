# Boreas 单机安装辅助脚本（当前能力边界）

本页说明 `tools/deploy/install.sh` 的受限安装流程。它**不是 OpenWrt/Boreas 产品支持声明**：仅适用于有 POSIX `/bin/sh`、Linux TUN、root、iproute2、`readelf` 和 SHA-256 工具的目标。BusyBox/OpenWrt 镜像通常缺少 `readelf`、`stat -c`、`find -mindepth`、`cmp`、`sort`、`awk`，因此**安装器本身应在 Linux 主机上执行**；缺失工具会明确失败，不自动 opkg 安装、不改系统。`--dry-run` 只读地审阅输入，不执行候选程序、不下载、不写安装目录/系统、不启动服务。

**先阅读**：[双机部署和当前限制](README.md)。当前 daemon/TUN/路由、多 Core 等能力仍受实现状态与开放生产门禁约束；模板不提供生产安全性，也不应放高敏业务。

## 1. 信任模型：脚本保证什么、不保证什么

保证：

- 显式给出本地二进制或 HTTPS URL，以及由**独立可信渠道**取得的 64 位十六进制 SHA-256。安装器先复制到安装目录同文件系统的 staging，**先验 SHA-256，再验 ELF**，两步都通过后才允许运行 `doctor`、`config-migrate`、`config-check`、`pki verify-bundle`。
- ELF 必须 64 位、架构与本机 `uname -m` 一致，且无 `INTERP`/程序解释器/`DT_NEEDED`（即静态链接）。静态 ELF 无 `.dynamic` 时不同 binutils 的 `readelf -d` 退出码不一致，脚本对"no dynamic section"显式放行，其他非零退出仍然失败。
- 材料目录必须是**扁平**的普通文件集合，文件名必须命中节点材料 allowlist；`boreas pki init-ca` 产生的 CA/授权私钥真实文件名（`root.ed25519.key`、`root.mldsa65.key`、`ia.ed25519.key`、`ia.mldsa65.key`、`status.ed25519.key`、`status.mldsa65.key`、`outer-ca.key`）以及任何未知文件名、符号链接、FIFO、设备、子目录一律拒绝。这一点由安装器与 `pki verify-bundle` 双重覆盖：前者只放行节点材料，后者验证签名链。
- 配置先经 `boreas config-migrate` 规范化（打印 `version = 2`，不修改源文件），再严格识别其固定 `[paths]` 三字段布局：只重定位 `identity_key` 为 `<prefix>/releases/<release>/materials/identity.key`、`roots` 为仅含 `<prefix>/releases/<release>/materials/roots.cbor` 的数组、`state_dir` 为 `<prefix>/state`。其他规范化配置行不改，最终路径绝不指向 staging 或输入机器；布局、字段或字符串语法不符合预期时 fail-closed。使用 POSIX awk，不引入 Python/TOML 运行时依赖。最终以 `config.toml`（`0600`）安装；源文件和中间规范化副本删除。
- 每个 release 写入 `bundle.sha256`（二进制、规范化配置与每个材料文件的确定性清单）。以同一 `--release` 重跑，只有**整个 bundle 字节相同**才幂等接受；二进制、配置或材料任一不同都会被拒绝并提示换 release id。

不保证：

- 摘要本身的可信度。`--url` 模式下摘要与二进制同源时**不是**独立信任，脚本在动手前打印警告，且必须显式 `--accept-weak-https` 表示确认；成功后再次警告。当前接口只接受直接二进制 URL，不下载摘要文件，也不验签名 —— 没有任何签名门禁，"一键"不等于"可信"。
- 运行期安全。TUN 数据面、路由收敛、graceful drain、readiness 均未验收。

## 2. 先做不落盘 dry-run

在 Linux POSIX shell 环境中准备本机文件：

```sh
sha256sum ./boreas-linux-x86_64-musl-pq768
sh tools/deploy/install.sh \
  --binary "$PWD/boreas-linux-x86_64-musl-pq768" \
  --sha256 '<独立可信渠道提供的64位hex摘要>' \
  --release '0.1.0-pre.4-local1' \
  --materials "$PWD/edge-material" \
  --config "$PWD/edge.toml" \
  --prefix /opt/boreas --dry-run
```

dry-run 不需要 root，做的是与真实安装**同一套**只读检查：SHA-256、静态 ELF 与架构、`--prefix`/`--bindir` 路径策略、材料 allowlist 与 CA 私钥拒绝。它不运行候选 `boreas`，因此不会声称 `doctor`/配置/PKI 校验通过；输出的 "would …" 只是计划。若私钥按材料目录供 daemon 使用，请先确认所选二进制与节点材料可信。

## 3. 安装

`--start` 默认关闭。先检查摘要来源、节点身份、peer 文件、外层 TLS 参数、配置和后端 feature，再显式选择服务管理器：

```sh
sh tools/deploy/install.sh \
  --binary "$PWD/boreas-linux-x86_64-musl-pq768" \
  --sha256 '<同上的64位hex摘要>' \
  --release '0.1.0-pre.4-local1' \
  --materials "$PWD/edge-material" \
  --config "$PWD/edge.toml" \
  --service systemd
```

路径与权限不变量（违反即失败，没有覆盖开关）：

- `--prefix` 与 `--bindir` 必须是绝对路径，拒绝 `/`、顶层系统目录（`/etc`、`/usr`、`/usr/bin`、`/tmp`、`/opt` 本身等）、`..`/`.`/`//` 组件与超过 200 字符的路径；末尾多余斜杠会被规范化。
- 已存在的 `--prefix`/`--bindir`、每个祖先目录和 `releases`/`bin`/`state` 子目录必须**不是符号链接**、属于 root、不得 group/other 可写；即使目标还不存在，也检查其现存祖先。`--prefix` 在写入任何内容之前改成 `0700`，三个子目录以 `0700` 创建/限制。不要使用 `/tmp` 等非安全祖先，即使最终目录自身权限正确也拒绝。
- `--bindir` 必须已存在，安装器**不会**替 root 创建任意目录；`boreas` 与 `boreas-easy` 通过"`mktemp` + `ln -s` + `mv -f`"换入，不会跟随预置符号链接。
- 安装前缀被**烘焙**进 `/opt/boreas/boreas-dispatch`、`/opt/boreas/boreas-run` 与两个服务模板（`@@PREFIX@@` 占位符，由安装器替换）。运行期不再读 `BOREAS_PREFIX`、`BOREAS_CONFIG`、`BOREAS_MATERIAL_DIR`：root 服务不会从调用者可控制的环境变量里解析二进制或密钥路径。自定义 `--prefix` 因此是全链路一致的。
- 事务边界：校验、release 落地、可执行权限、dispatcher、wrapper、服务模板全部就绪后才 `mv` 原子切换 `active`。切换之后任一步失败（含 `--start`）都会把 `active` 恢复为切换前的值，并在首次安装时删除指针；新 release 目录保留以便排查。**服务运行期失败不会自动回滚版本**：人工回滚须停止服务、用已审核的旧 release 重写 `active`，并确认材料/配置兼容。

安装验证顺序（只在 SHA-256 与静态 ELF 检查之后执行）：

```text
boreas doctor
boreas config-migrate <staged config>   # 输出规范化 version = 2，不改源文件
boreas config-check <canonical config.toml>
boreas pki verify-bundle --material-dir <staged node materials> --require-peer
```

这些命令成功不等于 route、TUN 数据面或生产 gate 通过。

## 4. systemd 与 OpenWrt procd 模板

`--service systemd` 渲染 `tools/deploy/boreas.service` 到 `/etc/systemd/system/boreas.service`（`0644`），并把 wrapper 装到 `<prefix>/boreas-run`。`Type=simple` 是刻意选择：daemon 没有 `sd_notify`，不能伪装 readiness。升级时用 `systemctl enable` + **`restart`**（不是 `enable --now`），否则已运行的旧进程不会被替换。单元默认加固：`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、`PrivateTmp`、`ProtectKernel*`、`RestrictNamespaces`、`RestrictSUIDSGID`、`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`、`SystemCallFilter=@system-service`；`PrivateDevices` 保持默认（需要 `/dev/net/tun`）。安装器创建 `<prefix>/state`（`0700`），配置固定使用该状态目录；单元仅放行 `ReadWritePaths=@@PREFIX@@/state`（安装时替换前缀），release 保持只读，不要整体关闭 `ProtectSystem`。`RestartPreventExitStatus=78` + `StartLimitBurst` 防止配置错误变成热重启。

`--service procd` 渲染 `tools/deploy/boreas.openwrt` 到 `/etc/init.d/boreas`（`0755`）。该脚本**从不 source** `/etc/boreas/boreas.env`：它逐行校验 key（白名单）、值字符集（拒绝引号、空格、`$`、反引号、`;`、`|`、`&`、括号、CR 等），再把通过校验的 `KEY=VALUE` 交给 procd，因此弱权限的 env 文件无法向 root init 脚本注入 shell 代码（回归测试包含 `$(...)` 与 `;reboot` 用例并断言无副作用）。procd 没有 `RestartPreventExitStatus` 等价物，所以 `exit 78` 也会消耗重启配额，模板设为 10 分钟内最多 5 次后停止。

创建 `/etc/boreas` 与 `/etc/boreas/boreas.env`：

```sh
install -d -m 0700 -o root -g root /etc/boreas
install -m 0600 -o root -g root /dev/null /etc/boreas/boreas.env
```

权限是硬约束：`--start` 前安装器要求 `/etc/boreas` 不是符号链接、`boreas.env` 是普通文件、属主 root、权限**精确为 `0600`**（`0644` 虽非 group/other 可写，也因泄露读取权限而拒绝）；wrapper 启动时也会重复这一检查（因为 systemd 与 procd 都会读该文件）。Core 示例：

```sh
BOREAS_ROLE=core
BOREAS_VIP=10.20.1.1
BOREAS_PEER_VIP=10.20.1.2
BOREAS_LISTEN=0.0.0.0:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

Edge 示例：

```sh
BOREAS_ROLE=edge
BOREAS_VIP=10.20.1.2
BOREAS_PEER_VIP=10.20.1.1
BOREAS_CONNECT=203.0.113.10:8443
BOREAS_TLS_NAME=wss.example.net
BOREAS_WS_HOST=wss.example.net:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

### 控制台入口与服务名

`boreas-easy` 无参数或首参数为选项（例如 `--socket`）时转入 `console`，显式子命令如 `doctor`、`config-check`、`console` 原样保留。安装服务名固定为 `boreas.service`（procd 为 `boreas`），而控制台默认按角色推导 `boreas-core`/`boreas-edge`，因此管理本安装器服务时必须显式指定：

```sh
boreas-easy --socket /run/boreas/control.sock --service boreas
# 或 boreas console --socket /run/boreas/control.sock --service boreas
```

socket 路径请替换为目标 daemon 的实际控制 socket；此处不声称模板额外创建了该 socket。

## 5. 运行期所有权（`boreas-run`）

`boreas-run` 以前台子进程方式启动 daemon，最多等待 10 秒 TUN 创建；只做以下受控动作，其他一律不做：

- 配置校验：`BOREAS_ROLE` 必须 `core`/`edge`；VIP 与 peer VIP 必须是**规范化**点分十进制（拒绝前导零 —— 否则校验的字符串与 `ip` 按八进制解释的地址不是同一个），且必须落在 RFC1918（`10/8`、`172.16/12`、`192.168/16`）；CGNAT `100.64/10` 与公网均拒绝；端口 1..65535、无前导零；`BOREAS_TLS_NAME`/`BOREAS_WS_HOST` 必须是合法 DNS 名（可选 `:port`）；TUN 名 ≤ 15 字符（IFNAMSIZ）；MTU 1280..1400。
- 冲突拒启：同名接口已存在、VIP 已是本机地址、peer VIP 是本机地址、`PEER/32` 路由已存在、peer/VIP 等于 `BOREAS_CONNECT` 主机 —— 全部拒绝，并以 `78` 退出（supervisor 不应热重启）。
- 只加本实例资源：`link set up`、`addr add VIP/32 dev TUN`、`route add PEER/32 dev TUN`；每个 `add` 失败即失败退出，不覆盖既有地址/路由。
- 只删自己加的：退出时按 `dev TUN` 精确删除 route 与 addr，顺序为 route → addr；**没有** `ip route flush`、没有 `default`、没有网段路由、没有 `link del`、不改 sysctl/防火墙/IPv6/resolv.conf。
- 停止：先 `TERM`，最多等 10 秒，再 `KILL`；systemd 侧 `TimeoutStopSec=20`。

BusyBox 限制（如实）：wrapper 只用 POSIX shell 内建 + `ip`、`grep`、`stat`、`sleep`、`kill`，不依赖 `awk`/`basename`；但 `ip` 必须是**完整 iproute2**（`ip -4 -o addr show`、`ip -4 route show`、`ip addr/route add|del`）；BusyBox `ip` 子集未验证。`stat -c` 与 `sleep 1`（整数秒）是仅有的非 POSIX 内建依赖。

## 6. 测试：已覆盖与仍未验收

`tools/deploy/test-install.sh` 是 Actions-only 的 shell 回归源文件（拒绝以 root 运行，拒绝在已有 `/etc/boreas/boreas.env` 或真实 boreas 单元的主机上运行；用假 `id`/`stat`/`readelf`/`sha256sum`/`systemctl`/`ip` 在临时目录内模拟 root）。它覆盖：

- dry-run 不执行候选、不写 prefix、不触网；`--url` 弱信任确认与 HTTP 拒绝（断言 stderr 具体文案，避免"因为别的原因失败"的空断言）。
- 摘要长度/非十六进制/不匹配；`INTERP` 头、解释器请求、`DT_NEEDED`、架构不符四种 ELF 拒绝各自独立用例，且断言这些路径上**从未执行候选**。
- release id `..`/`.`/前导 `-`/超长；prefix `/`、`/etc`、`/usr`、`/opt`、`..` 穿越、相对路径；未知选项。
- 材料策略：7 个真实 CA 私钥名、未知文件名、目录内符号链接、FIFO、子目录、符号链接材料目录、符号链接配置。
- 真实安装路径：release 布局、`0700`/`0600`/`0755` 权限、规范化 `config.toml` 存在而 `config.source.toml` 不存在、`config-check` 拿到的是规范化文件、dispatcher 烘焙 prefix、两个稳定 symlink、`active` 内容、`bundle.sha256`。
- 幂等与拒绝：bundle 相同 → 幂等且只保留一个 release；配置或材料变化 → 拒绝并提示换 release id。
- prefix 非 root 属主 / group-other 可写 → 拒绝；`--start` 无 service、缺 `/etc/boreas` → 在**任何** system 写入与指针切换之前失败；`--bindir` 不存在 → 拒绝而不是创建。
- wrapper：未渲染即拒、非法 role、前导零/短 VIP、公网 VIP、VIP=peer、LISTEN 无端口/越界端口、MTU 越界、非法/超长 TUN 名、edge 缺 CONNECT、peer 等于 transport 主机、已有接口/本机地址/已有 `PEER/32` 路由 → 全部拒绝且退出码 78；正常路径断言"先 addr 后 route"、只删自己加的、无 `flush`/`default`/`link del`；route add 失败时删除刚加的 addr 且不删路由。
- 模板静态不变量：`RestartPreventExitStatus=78`、`NoNewPrivileges`、`ProtectSystem=strict`、能力白名单、`ExecStart=@@PREFIX@@/...` 且不含 `/opt/boreas` 硬编码；procd 脚本不含 `. /etc/boreas`、`eval`、`source`；procd env 解析器接受合法文件、拒绝 `$(...)`、`;`、未知 key、CRLF、非精确 `0600` 文件（包括 `0644`），并断言注入值无副作用、procd 仅一次设置完整 env argv。

仍未验收（不得据此声称完成）：

- 该测试源**本次未在本机执行**，需要在隔离 Linux runner 上接线并保存日志；由部署 CI 工作流接线并在隔离 runner 执行；必须以 CI 日志为准，不能把新增断言等同于已通过。
- 真实 x86_64/aarch64 Linux 与 OpenWrt 设备上的 TUN 数据面、配置、服务启停、管理/SSH/Core endpoint 路由保护、升级指针原子性与故障恢复（崩溃/SIGKILL/断电/磁盘满）仍需实测。
- 没有签名信任链、没有自动回滚、没有 procd 真机验证、没有 BusyBox `ip` 验证。
