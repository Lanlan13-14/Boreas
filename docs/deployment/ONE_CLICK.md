# Boreas 一键安装：先预演，再启动

`tools/deploy/install.sh` 安装一份**已经构建并由你核对来源**的静态 Linux 二进制。它还能检查配置、预置材料、切换本地版本，到此即完成了“安装”。它不编译、不签发证书、不自动发现对端，也不会代你放通防火墙。要试通双机，请先完成[部署教程第 1–3 节](README.md#workflow)。

这里的 `systemd`/`procd` 是显式启用的旧开发模板，以 root 运行；在需要认证发布清单、非特权运行和就绪回退时，改用[离线双签 systemd 路径](VERIFIED-SERVICE.md)，不要混装。本页面向**当前兼容开发构建**；公开 `v0.1.0-pre.3` 没有这里所需的 daemon 策略参数。

## 1. 在 Core、Edge 各准备一份输入

在目标机准备 `/root/boreas-stage`（root 所有，`0700`），把目录内文件设为 root 所有、`0600`；二进制输入本身不必预先可执行。目录可以使用自己的私有绝对路径。另备已审核的源码 checkout（包含 `tools/deploy/install.sh` 及其同目录模板）。以下操作均从 checkout 根目录执行。

```text
/root/boreas-stage/
├── boreas                   # 本机架构的静态 Linux 候选
├── node.toml                # 此主机自己的配置；不是两端通用文件
├── material/                # 此主机的扁平节点包，含 local.signed / peer.signed
├── policy/                  # 仅三个文件，连备份或隐藏文件也不要放
│   ├── policy.tbs
│   ├── policy.ed25519.sig
│   └── policy.mldsa65.sig
└── pins/
    ├── root.ed25519.der
    └── root.mldsa65.der
```

- **制品**：从独立可信渠道取得 64 位十六进制 SHA-256（或先验受信签名清单），核对源提交、架构与静态链接；`sha256sum` 只计算本地文件的摘要，不会证明来源。安装器经过摘要、ELF 检查后会**执行**候选的 `doctor`、`config-migrate`、`config-check`、`pki verify-bundle`。所以真实性检查必须在安装器执行之前完成，不能让候选替自己作证。
- **网络信任**：按[签发步骤](README.md#2-离线签发只在签发机执行)准备并用可信 CLI `pki verify-policy` 预检；两个网络根 pin 独立预配，不放进 `material/`。脚本校验路径与权限，不验证策略双签；daemon 启动时还会按 pin 验签并记录水位，失败不承载业务。
- **文件与路径**：材料只允许节点包文件和对端身份，不接受离线 CA 私钥、未知文件、符号链接、特殊文件或子目录；策略和 pin 要非空、普通文件、单硬链接，父目录也要可信。安装目标 `/opt/boreas` 与默认 `/usr/local/bin` 不能是符号链接、不能被组/其他人写入；`--bindir` 要提前存在。不要把安装前缀放在 `/tmp` 或复用系统目录。完整规则见[策略与状态](POLICY-STATE.md)。
- **工具**：完整 Linux `iproute2`、`readelf`、`sha256sum` 和通用 POSIX shell 工具；脚本不自动安装依赖。若是远程主机，先确认管理路径不经过待创建的 TUN。

## 2. 使用同一组参数预演与安装

请把下面两个 `REPLACE_…` 占位符替换为实际值。这段函数只用于复用安装命令；切换终端后需重新定义。先用 `--dry-run`，查看预期路径及服务类型；对 root 所有输入要用相同 UID 预演。

```sh
STAGE=/root/boreas-stage
NET_ID=REPLACE_WITH_NET_ID
DIGEST=REPLACE_WITH_TRUSTED_SHA256
RELEASE_ID=local-eval-1

install_boreas() {
  sudo sh tools/deploy/install.sh \
    --binary "$STAGE/boreas" --sha256 "$DIGEST" --release "$RELEASE_ID" \
    --materials "$STAGE/material" --config "$STAGE/node.toml" \
    --policy-dir "$STAGE/policy" --network-id "$NET_ID" \
    --network-root-ed25519-der "$STAGE/pins/root.ed25519.der" \
    --network-root-mldsa65-der "$STAGE/pins/root.mldsa65.der" \
    --prefix /opt/boreas "$@"
}

install_boreas --service systemd --accept-legacy-service --dry-run
```

预演只读：不下载、不写目标、不运行候选或服务管理器。它只检查摘要、ELF、路径和文件来源，不能证明配置或策略验签会通过。`--url` 不是本教程的路线：脚本只接受直接 HTTPS 二进制 URL，要求 `--accept-weak-https`，仍不能验证发布签名。

仅在预演和信任检查无误后执行正式安装。若只取版本和入口、不装服务，改选 `--service none`（预演时也应选同一模式）。若主机已在运行 `boreas.service`，先规划停机并检查现有服务及路径，不要直接按首次安装操作；旧模板不能替换离线双签服务。

```sh
install_boreas --service systemd --accept-legacy-service
sudo cat /opt/boreas/active
sudo /usr/local/bin/boreas doctor
```

安装器默认**不启动**。`active` 应输出 `local-eval-1`，`doctor` 应表明该二进制具有 daemon 和 TLS 支持。`/opt/boreas` 为 `0700`，此示例的 dispatcher 与运行状态用 root 访问。结果布局：

```text
/opt/boreas/
├── active                               # 当前 release id
├── boreas-dispatch / boreas-run          # 固定前缀，非调用者环境变量决定
├── releases/local-eval-1/
│   ├── boreas / config.toml / bundle.sha256
│   └── materials/ / policy-inputs/
└── state/
    ├── local-eval-1.policy.tbs           # 同代际还有两签名、两 pin
    └── status.state / policy.state       # 由 daemon 创建；安装器不预建
```

`config-migrate` 生成 `version = 2` 配置，不改源文件；安装器核对 `net_id`，把 `[paths]` 的 `identity_key` / `roots` / `state_dir` 改为活动版本下的私钥、roots 和共享状态目录。其他配置仍由你审核。`boreas` / `boreas-easy` 由默认 `/usr/local/bin` 的入口指向 dispatcher。

## 3. 写入本机角色与启动参数

检查 `/etc/boreas` 未被其他服务使用后，创建 root 所有的非符号链接目录（`0700`）和 `/etc/boreas/boreas.env`（普通文件，精确 `0600`）。新文件可用下面两条命令建立；**第二条会清空现有文件，仅用于首次**。随后以管理员身份编辑该文件，只写入本机对应的配置，不要把两段合在一起。

```sh
sudo install -d -m 0700 -o root -g root /etc/boreas
sudo install -m 0600 -o root -g root /dev/null /etc/boreas/boreas.env
```

Core（监听端口需要安全组及防火墙放行）：

```ini
BOREAS_ROLE=core
BOREAS_VIP=10.20.1.1
BOREAS_PEER_VIP=10.20.1.2
BOREAS_LISTEN=0.0.0.0:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

Edge（替换底层 IP，核对证书 SAN，不填隧道 VIP）：

```ini
BOREAS_ROLE=edge
BOREAS_VIP=10.20.1.2
BOREAS_PEER_VIP=10.20.1.1
BOREAS_CONNECT=203.0.113.10:8443
BOREAS_TLS_NAME=wss.example.net
BOREAS_WS_HOST=wss.example.net:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

VIP 使用签名身份中 RFC1918 的地址，不带 `/32`，不允许前导零；底层监听/拨号为数字 IPv4 加端口；TUN 名不超过 15 字符；wrapper MTU 范围 `1280..1400`。不要预建同名接口或对端 `/32`，该 wrapper 创建自己的运行资源，冲突会拒启，不覆盖现有网络。停止时仅尝试撤掉它加的地址/路由，不清空路由表，也不改默认路由、防火墙或 DNS。

先在 Core 上执行 `daemon-reload` 与 `start`，确认 Core 已开始监听 TCP 端口后，再在 Edge 执行同样两条。仅在[双向验收](README.md#5-验收与日常维护)通过后，才考虑 `enable` 设置开机启动。

```sh
sudo systemctl daemon-reload
sudo systemctl start boreas.service
sudo systemctl status boreas.service
sudo journalctl -u boreas.service -n 100 --no-pager
```

`Type=simple` 的 `active` 不等于握手、路由或流量正常。查询实际 daemon：

```sh
sudo /usr/local/bin/boreas ctl status --socket /opt/boreas/state/control.sock
sudo /usr/local/bin/boreas-easy --socket /opt/boreas/state/control.sock --service boreas
```

确认要开机启动时用 `sudo systemctl enable boreas.service`。升级后已运行进程不会随 `active` 自动替换；审核并按计划 `sudo systemctl restart boreas.service`，再做双向验收。`--start` 也可以显式选择启用并（重）启，但要求预先准备合规的 `boreas.env`，且不验证数据面，此处刻意先分步检查。

### 仅供评估的 procd 模板

旧模板可用 `--service procd --accept-legacy-service` 渲染 `/etc/init.d/boreas`；环境文件同上。模板按白名单读取字面 `KEY=VALUE`，不要加引号、行尾注释、空格、变量展开或 CRLF。目标机需要完整的 `iproute2`、Linux TUN 及其他所需工具；模板的存在不表示已验证 BusyBox `ip` 或物理 OpenWrt。先在目标镜像的不启动模式审阅路径、工具和架构；没有验证环境就走 Linux/systemd 路径。

## 4. 安装失败、停止与回退

- **预演拒绝**：看第一条错误。检查落盘路径各级祖先、材料 allowlist、两个 pin 是否在材料之外、三份策略是否有多余文件，以及静态 ELF/架构。不要加宽目录权限或忽略摘要失败。
- **安装失败**：安装锁 `<prefix>/.install.lock` 串行化运行；遗留锁先调查，不抢占。`active` 最后切换，切换后若安装步骤明确失败，安装器尝试恢复旧指针；已发布的文件可能保留。`sync` 不是断电验收。核对 `active`、日志和实际进程，不把指针恢复当成旧服务已运行。
- **服务启动失败或反复重启**：先 `sudo systemctl stop boreas.service` 并看日志。`78` 是旧 wrapper 的配置拒绝，模板不重启此退出码；普通错误有重启限额。装好的服务不会因为运行时故障自动把版本回退。
- **升级与手工回退**：同 release id 只接受字节一致的输入，任何改动用新 id；历史代际不覆盖。必要时停服务，审核旧制品、旧策略及现有持久状态仍兼容且有效，再按[策略状态和回退语义](POLICY-STATE.md#6-升级-start-与回滚)恢复指针，启动并复验。不得用删除 `status.state`/`policy.state` 或降低授权水位来恢复。

### 如何区分测试证据

- `tools/deploy/test-install.sh` 是隔离的 shell 回归（模拟系统工具，不以 root 执行、不在已有 Boreas 服务的主机运行）。它检查文件来源、路径、权限、版本指针和 wrapper 约束，不证明真实包传输。
- `tools/deploy/test-real-install.sh` 由 [deploy 工作流](../../.github/workflows/deploy.yml)在受控 runner 验证静态安装，使用 `--service none`；没有启动服务或现场 TUN 验收。真实数据面请看 [TLS 工作流](../../.github/workflows/rust-tls.yml) 和 [双机验收清单](README.md#5-验收与日常维护)。
