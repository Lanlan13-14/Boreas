# Boreas 单机安装辅助脚本（当前能力边界）

> **本页只用于旧开发安装。** 摘要并非签名，以下 root wrapper 也不提供真实就绪或自动恢复。`--service systemd|procd` 现在需要显式 `--accept-legacy-service`。需要双签、非特权、可恢复的 Linux/systemd 路径，请参阅 [离线签名服务](VERIFIED-SERVICE.md)。


本页说明 `tools/deploy/install.sh` 的受限安装流程。它**不是 OpenWrt/Boreas 产品支持声明**：仅适用于有 POSIX `/bin/sh`、Linux TUN、root、iproute2、`readelf` 和 SHA-256 工具的目标。BusyBox/OpenWrt 镜像通常缺少 `readelf`、`stat -c`、`find -mindepth`、`cmp`、`sort`、`awk`，因此**安装器本身应在 Linux 主机上执行**；缺失工具会明确失败，不自动 opkg 安装、不改系统。`--dry-run` 只读地审阅输入，不执行候选程序、不下载、不写安装目录/系统、不启动服务。

**先阅读**：[双机部署和当前限制](README.md)。当前 daemon/TUN/路由、多 Core 等能力仍受实现状态与开放生产门禁约束；模板不提供生产安全性，也不应放高敏业务。

> **发布资产边界**：可下载的最新预发布 `v0.1.0-pre.3` 早于策略绑定运行期；本页的安装参数与 `boreas-run` 面向**当前 main 构建**。pre.3 的 daemon 不认识 `--network-policy-*` 等参数，把 pre.3 资产与本文流程混用会导致服务无法启动；双机手工教程中的 pre.3 命令见 [README.md](README.md)。

## 1. 信任模型：脚本保证什么、不保证什么

保证：

- 显式给出本地二进制或 HTTPS URL，以及由**独立可信渠道**取得的 64 位十六进制 SHA-256。安装器先复制到安装目录同文件系统的 staging，**先验 SHA-256，再验 ELF**，两步都通过后才允许运行 `doctor`、`config-migrate`、`config-check`、`pki verify-bundle`。
- ELF 必须 64 位、架构与本机 `uname -m` 一致，且无 `INTERP`/程序解释器/`DT_NEEDED`（即静态链接）。静态 ELF 无 `.dynamic` 时不同 binutils 的 `readelf -d` 退出码不一致，脚本对"no dynamic section"显式放行，其他非零退出仍然失败。
- 材料目录必须是**扁平**的普通文件集合，文件名必须命中节点材料 allowlist；`boreas pki init-ca` 产生的 CA/授权私钥真实文件名（`root.ed25519.key`、`root.mldsa65.key`、`ia.ed25519.key`、`ia.mldsa65.key`、`status.ed25519.key`、`status.mldsa65.key`、`outer-ca.key`）以及任何未知文件名、符号链接、FIFO、设备、子目录一律拒绝。这一点由安装器与 `pki verify-bundle` 双重覆盖：前者只放行节点材料，后者验证签名链。
- **策略与根信任输入是显式、独立的五件套**：`--policy-dir` 必须恰好提供 `policy.tbs`、`policy.ed25519.sig`、`policy.mldsa65.sig`；两个 NetworkRoot pin 必须另用 `--network-root-ed25519-der` 与 `--network-root-mldsa65-der` 单独给出。安装器校验普通文件、非符号链接、单硬链接、调用用户属主、无 group/other 权限、五个路径互不相同，并逐级检查输入路径：拒绝符号链接、拒绝 owner 不是 root/调用用户的祖先、拒绝非 sticky 的 group/other 可写祖先（sticky `/tmp` 下的私有目录可用）。`--network-id` 必须与规范化配置 `[node] net_id` 一致。pin 不会从二进制或 URL 同源取得；安装器**不声称**验证其密码学有效性，这是 daemon 每次启动的 fail-closed 职责（见 [POLICY-STATE.md](POLICY-STATE.md)）。
- **发布位置与运行期存储**：五个输入在 `active` 提交前逐文件原子发布为 `<prefix>/state/<release-id>.<name>`（运行期要求输入是 `state_dir` 的直接子文件）；同一 release 重跑只在字节一致时复用，内容不同即拒绝，**绝不覆盖**。提交指针前执行一次 `sync` 粗粒度屏障（不是逐文件 `fsync` 证明）。`status.state`/`policy.state` 由 daemon 首次启动自建，安装器不预建空文件，只在它们已存在时校验类型、属主、权限与非空。
- 配置先经 `boreas config-migrate` 规范化（打印 `version = 2`，不修改源文件），再严格识别其固定 `[paths]` 三字段布局：只重定位 `identity_key` 为 `<prefix>/releases/<release>/materials/identity.key`、`roots` 为仅含 `<prefix>/releases/<release>/materials/roots.cbor` 的数组、`state_dir` 为 `<prefix>/state`。其他规范化配置行不改，最终路径绝不指向 staging 或输入机器；布局、字段或字符串语法不符合预期时 fail-closed。使用 POSIX awk，不引入 Python/TOML 运行时依赖。最终以 `config.toml`（`0600`）安装；源文件和中间规范化副本删除。
- 每个 release 写入 `bundle.sha256`（二进制、规范化配置、五个策略输入与每个材料文件的确定性清单）。以同一 `--release` 重跑，只有**整个 bundle 字节相同**才幂等接受；二进制、配置、策略输入或材料任一不同都会被拒绝并提示换 release id。

不保证：

- **一键安装 ≠ 初始双签/发布签名验证，且独立验证必须先于执行**：安装器不验证 release 签名或 NetworkPolicy 的双签，并且在 SHA-256/ELF 通过后会**执行**候选（`doctor`/`config-migrate`/`config-check`/`pki verify-bundle`）。因此必须由独立 verifier（另一台机器/独立渠道）在运行安装器**之前**核对摘要，并对双签策略与独立预配 pin 做只读 `pki verify-policy` 预检；daemon 启动时的验签发生在候选已执行之后，不能替代安装前验证。
- 摘要本身的可信度。`--url` 模式下摘要与二进制同源时**不是**独立信任，脚本在动手前打印警告，且必须显式 `--accept-weak-https` 表示确认；成功后再次警告。当前接口只接受直接二进制 URL，不下载摘要文件，也不验签名 —— 没有任何签名门禁，"一键"不等于"可信"。
- 运行期安全。TUN 数据面、路由收敛、graceful drain、readiness 均未验收。
- 当前为开发阶段**部分实现**：正式生产门禁仍开放（`production_approved: false`），本页任何成功路径都不构成生产批准。

## 2. 先做不落盘 dry-run

在 Linux POSIX shell 环境中准备本机文件：

```sh
sha256sum ./boreas-linux-x86_64-musl-pq768
sh tools/deploy/install.sh \
  --binary "$PWD/boreas-linux-x86_64-musl-pq768" \
  --sha256 '<独立可信渠道提供的64位hex摘要>' \
  --release 'local-eval-1' \
  --materials "$PWD/edge-material" \
  --policy-dir "$PWD/policy" \
  --network-id '0123456789abcdef0123456789abcdef' \
  --network-root-ed25519-der "$PWD/root.ed25519.der" \
  --network-root-mldsa65-der "$PWD/root.mldsa65.der" \
  --config "$PWD/edge.toml" \
  --prefix /opt/boreas --dry-run
```

dry-run 不需要 root，做的是与真实安装**同一套**只读检查：SHA-256、静态 ELF 与架构、`--prefix`/`--bindir` 路径策略、材料 allowlist 与 CA 私钥拒绝、`--policy-dir` 的精确文件集合、pin 的类型/属主/硬链接/权限、五路互异，以及输入路径逐级的符号链接/祖先属主/可写祖先/最终目录属主检查。它不运行候选 `boreas`，因此不会声称 `doctor`/配置/PKI/策略签名校验通过；输出的 "would …" 只是计划。属主检查统一用 `id -u`，所以对真实 root 属主输入做 dry-run 也需要 `sudo`；非 root 运行会被 fail-closed 拒绝。若私钥按材料目录供 daemon 使用，请先确认所选二进制与节点材料可信。

## 3. 安装

`--start` 默认关闭。先检查摘要来源、节点身份、peer 文件、外层 TLS 参数、配置和后端 feature，再显式选择服务管理器。

真实安装以 root 运行，属主检查用 `id -u`：五个输入及其所在目录必须属主为 root、group/other 不可写（例如先把 policy 目录与两个 pin 放进 root 拥有的目录，必要时 `chown root`），否则安装器 fail-closed 拒绝。下面的 `$PWD/...` 只表示路径，不表示属主。

```sh
sh tools/deploy/install.sh \
  --binary "$PWD/boreas-linux-x86_64-musl-pq768" \
  --sha256 '<同上的64位hex摘要>' \
  --release 'local-eval-1' \
  --materials "$PWD/edge-material" \
  --policy-dir "$PWD/policy" \
  --network-id '0123456789abcdef0123456789abcdef' \
  --network-root-ed25519-der "$PWD/root.ed25519.der" \
  --network-root-mldsa65-der "$PWD/root.mldsa65.der" \
  --config "$PWD/edge.toml" \
  --service systemd
```

路径与权限不变量（违反即失败，没有覆盖开关）：

- `--prefix` 与 `--bindir` 必须是绝对路径，拒绝 `/`、顶层系统目录（`/etc`、`/usr`、`/usr/bin`、`/tmp`、`/opt` 本身等）、`..`/`.`/`//` 组件与超过 200 字符的路径；末尾多余斜杠会被规范化。
- 已存在的 `--prefix`/`--bindir`、每个祖先目录和 `releases`/`bin`/`state` 子目录必须**不是符号链接**、属于 root、不得 group/other 可写；即使目标还不存在，也检查其现存祖先。`--prefix` 在写入任何内容之前改成 `0700`，三个子目录以 `0700` 创建/限制。不要使用 `/tmp` 等非安全祖先，即使最终目录自身权限正确也拒绝。
- `--bindir` 必须已存在，安装器**不会**替 root 创建任意目录；`boreas` 与 `boreas-easy` 通过"`mktemp` + `ln -s` + `mv -f`"换入，不会跟随预置符号链接。
- 安装前缀被**烘焙**进 `/opt/boreas/boreas-dispatch`、`/opt/boreas/boreas-run` 与两个服务模板（`@@PREFIX@@` 占位符，由安装器替换）。运行期不再读 `BOREAS_PREFIX`、`BOREAS_CONFIG`、`BOREAS_MATERIAL_DIR`：root 服务不会从调用者可控制的环境变量里解析二进制或密钥路径。自定义 `--prefix` 因此是全链路一致的。
- 事务边界：校验、release 落地、可执行权限、dispatcher、wrapper、服务模板全部就绪后才 `mv` 原子切换 `active`。切换之后任一步失败（含 `--start`）都会把 `active` 恢复为切换前的值，并在首次安装时删除指针；新 release 目录保留以便排查。五个策略输入也在切换前按 release 逐文件原子发布到 `state/`；`active` 回滚只会重新选中旧代际文件，旧输入不被修改，无需重新发布，也绝不覆盖。指针切换前会执行一次 `sync` 粗粒度屏障，防止 `active` 先于 release 内容落盘；这不是逐文件 `fsync` 证明。整个会改动 prefix 的运行由 `<prefix>/.install.lock`（原子 `mkdir`，`0700`）串行化：锁忙或存在旧锁时明确失败，安装器只释放自己创建的锁。**服务运行期失败不会自动回滚版本**：人工回滚须停止服务、用已审核的旧 release 重写 `active`，并确认材料/配置兼容。

安装验证顺序（只在 SHA-256 与静态 ELF 检查之后执行）：

```text
boreas doctor
boreas config-migrate <staged config>   # 输出规范化 version = 2，不改源文件
# 安装器：awk 校验 [node] net_id == --network-id，并严格重定位 [paths] 三个字段
boreas config-check <canonical config.toml>
boreas pki verify-bundle --material-dir <staged node materials> --require-peer
```

CLI 已支持通过 `pki sign-policy` 离线签发 `NetworkPolicy`。安装器本身**不**独立验证发布或策略签名；操作员应先使用预先受信任的工具验发布清单及制品，并离线预检策略（`pki verify-policy` 示例见 [POLICY-STATE.md](POLICY-STATE.md) §1）。daemon 每次启动仍会重新验策略签名，失败时拒绝承载业务。上述安装自检不等于路由、TUN 数据面或生产门禁通过。

## 4. systemd 与 OpenWrt procd 模板

`--service systemd --accept-legacy-service` 渲染 `tools/deploy/boreas.service` 到 `/etc/systemd/system/boreas.service`（`0644`），并把 wrapper 装到 `<prefix>/boreas-run`。`Type=simple` 是刻意选择：daemon 没有 `sd_notify`，不能伪装 readiness。升级时用 `systemctl enable` + **`restart`**（不是 `enable --now`），否则已运行的旧进程不会被替换。单元默认加固：`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、`PrivateTmp`、`ProtectKernel*`、`RestrictNamespaces`、`RestrictSUIDSGID`、`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`、`SystemCallFilter=@system-service`；`PrivateDevices` 保持默认（需要 `/dev/net/tun`）。安装器创建 `<prefix>/state`（`0700`），配置固定使用该状态目录；单元仅放行 `ReadWritePaths=@@PREFIX@@/state`（安装时替换前缀），release 保持只读，不要整体关闭 `ProtectSystem`。`RestartPreventExitStatus=78` + `StartLimitBurst` 防止配置错误变成热重启。

`--service procd --accept-legacy-service` 渲染 `tools/deploy/boreas.openwrt` 到 `/etc/init.d/boreas`（`0755`）。该脚本**从不 source** `/etc/boreas/boreas.env`：它逐行校验 key（白名单）、值字符集（拒绝引号、空格、`$`、反引号、`;`、`|`、`&`、括号、CR 等），再把通过校验的 `KEY=VALUE` 交给 procd，因此弱权限的 env 文件无法向 root init 脚本注入 shell 代码（回归测试包含 `$(...)` 与 `;reboot` 用例并断言无副作用）。procd 没有 `RestartPreventExitStatus` 等价物，所以 `exit 78` 也会消耗重启配额，模板设为 10 分钟内最多 5 次后停止。

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
- 策略输入：从 `active` 读取 release id，要求 `state/<id>.policy.tbs`、两个签名文件、两个 root pin 均为 root 属主、无 group/other 权限的普通非符号链接文件；缺失或不安全以 `78` 退出。共享 `policy.state`/`status.state` 不要求预先存在，由 daemon 首次启动创建。
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
- 真实安装路径：release 布局、`0700`/`0600`/`0755` 权限、规范化 `config.toml` 存在而 `config.source.toml` 不存在、`config-check` 拿到的是规范化文件、dispatcher 烘焙 prefix、两个稳定 symlink、`active` 内容、`bundle.sha256`；五个 `state/<id>.*` 输入已发布且与已校验输入逐字节一致、进入 bundle 清单，`status.state`/`policy.state` 未被预建。
- 幂等与拒绝：bundle 相同 → 幂等且只保留一个 release；配置或材料变化 → 拒绝并提示换 release id。
- 策略输入负向：缺 policy 目录/输入、pin 缺失、pin 为符号链接、两个 pin 相同、`--policy-dir` 多余条目、policy 输入为符号链接/硬链接/group-other 可读/非调用用户所有、`--policy-dir` 或祖先 owner 不符、输入路径含符号链接祖先或非 sticky 的 group/other 可写祖先、`--network-id` 长度错误或与规范化配置 `net_id` 不一致 → 全部失败且不切换 `active`；sticky 可写祖先（模拟 `/tmp`）被接受。
- 安装锁：成功安装后无锁；预置锁 → 明确失败、`active` 不变、锁保留、未创建 staging；摘要失败路径释放本次自己的锁。
- 发布冲突与升级：同 release 已发布文件被篡改 → 拒绝且不覆盖，恢复一致后幂等重跑成功；升级到 `test.2` 后 `test.1` 逐字节不变；预置冲突的 `test.3` 半成品 → 失败、只清理本次新建文件、保留冲突文件与旧代际、`active` 仍为 `test.2`；移除冲突后升级成功，把 `active` 写回 `test.2` 即重新选中旧输入。
- prefix 非 root 属主 / group-other 可写 → 拒绝；`--start` 无 service、缺 `/etc/boreas` → 在**任何** system 写入与指针切换之前失败；`--bindir` 不存在 → 拒绝而不是创建。
- wrapper：未渲染即拒、非法 role、前导零/短 VIP、公网 VIP、VIP=peer、LISTEN 无端口/越界端口、MTU 越界、非法/超长 TUN 名、edge 缺 CONNECT、peer 等于 transport 主机、已有接口/本机地址/已有 `PEER/32` 路由 → 全部拒绝且退出码 78；缺一个活动代际策略输入或输入为符号链接 → 78 且不触碰 `ip`；正常路径断言"先 addr 后 route"、只删自己加的、无 `flush`/`default`/`link del`，并断言 daemon 收到 `state/<active>.*` 五个输入与共享 `status.state`/`policy.state` 参数；切换 `active` 后只传新代际路径；route add 失败时删除刚加的 addr 且不删路由。
- 模板静态不变量：`RestartPreventExitStatus=78`、`NoNewPrivileges`、`ProtectSystem=strict`、能力白名单、`ExecStart=@@PREFIX@@/...` 且不含 `/opt/boreas` 硬编码；procd 脚本不含 `. /etc/boreas`、`eval`、`source`；procd env 解析器接受合法文件、拒绝 `$(...)`、`;`、未知 key、CRLF、非精确 `0600` 文件（包括 `0644`），并断言注入值无副作用、procd 仅一次设置完整 env argv。

仍未验收（不得据此声称完成）：

- 该测试源已在 GitHub Actions 的 deploy 工作流通过（run [`44305617520`](https://github.com/Lanlan13-14/Boreas/actions/runs/44305617520)）；该证据只覆盖 sh/dash/BusyBox + shellcheck 的隔离 shell 断言，不代表真机 systemd/procd、TUN 数据面、真实安装或生产验收，后续仍以对应 run 日志为准。
- 真实 x86_64/aarch64 Linux 与 OpenWrt 设备上的 TUN 数据面、配置、服务启停、管理/SSH/Core endpoint 路由保护、升级指针原子性与故障恢复（崩溃/SIGKILL/断电/磁盘满）仍需实测；并发安装器虽由 `<prefix>/.install.lock` 串行化（锁忙明确失败），真机并发与断电场景同样未实测。
- 安装期没有策略签名门禁（运行期 daemon 每次启动都有，且 fail-closed）；没有自动回滚、没有 procd 真机验证、没有 BusyBox `ip` 验证。

### 真实安装 harness（`test-real-install.sh`，非生产）

**范围**：只覆盖 `.github/workflows/deploy.yml` 的 `real-static-install` 手动任务：在 GitHub 托管 `ubuntu-24.04` runner 上，从一次成功的 main 分支 `rust-tls.yml` 运行下载静态候选制品（先校验 `SHA256SUMS`），由 root 在 `/var/cache` 下新建 `0700` 临时前缀，以 `--service none` 调用真实 `install.sh` 安装一次，再执行拒绝用例。**不覆盖** systemd/procd 真机、TUN 数据面、物理 OpenWrt、真实生产主机或升级回滚。harness 使用结构合法但非机密的 policy/pin 占位符：安装器只验文件导源，策略密码学校验属于 daemon，而本 harness 以 `--service none` 不启动 daemon。

覆盖内容：

- 正向：SHA-256、静态 ELF、文本 `active` 指针、活动 release 二进制摘要、`doctor`、dispatcher 链接；五个 `state/<release-id>.*` 策略输入已发布且权限 `0600`，`status.state`/`policy.state` 未被安装器预建。
- 摘要错误、同一 release 不同 bundle：拒绝且 `active` 不变。
- 不安全 `--prefix`（只使用本次运行在 root `0700` 临时树下新建的子目录）：故意 `0777` 的可写祖先、由非 root runner 拥有的目录、指向现有安装的符号链接。三者必须分别命中生产安装器的原文错误 `--prefix must not be group/other writable`、`--prefix must be owned by root (uid 0)`、`--prefix must not be a symbolic link`；断言匹配完整错误行（含 `install: error:` 与具体路径）且区分大小写，防止更早的无关错误冒充门禁通过。
- 拒绝发生在写入前：三个用例后活动指针与活动二进制逐字节不变，两个不安全前缀下没有生成目录；测试以 `--service none` 运行，不启动服务、不写 `/etc`；非 root 用例使用新的空目录，不修改节点材料或私钥的属主/权限。

**已知结果（非生产证据）**：手动运行 [`43895104195`](https://github.com/Lanlan13-14/Boreas/actions/runs/43895104195) 的 `Real static candidate install (private sandbox, no service)` job [`133396409062`](https://github.com/Lanlan13-14/Boreas/actions/runs/43895104195/job/133396409062) 在 harness/installer `5a51a1c` 上成功；所用静态候选来自 `rust-tls.yml` 运行 [`43886308602`](https://github.com/Lanlan13-14/Boreas/actions/runs/43886308602)，源提交 `91acf0c`。这只是一次性 GitHub 托管 Ubuntu runner 的结果，不是 systemd/procd 真机、物理 OpenWrt 或生产部署验收；且该次运行早于上述新增的不安全 `--prefix` 用例与策略输入参数，新增门禁仍需新的 Actions 运行和日志确认，不能把断言本身视为已通过。
