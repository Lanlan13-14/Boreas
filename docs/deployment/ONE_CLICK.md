# Boreas 一键安装：先预演，再启动

简体中文 · [繁體中文](ONE_CLICK.zh-TW.md) · [English](ONE_CLICK.en.md)

使用 `tools/deploy/one-click.sh` 可将一份**已经构建并由你核对来源**的静态 Linux 二进制部署到本机。它是现有 `install.sh` 的固定目录便捷入口，仍由后者执行全部安全校验、材料预置和活动版本切换——到此即完成“安装”。该脚本不下载、不编译、不签发证书、不自动发现对端、不自动启动，也不会代为放通防火墙。如需打通双机通信，请先完成[部署教程第 1–3 节](README.md#workflow)。

**不是免准备的一键组网**：当前实验分支没有可供本教程直接使用、已验证来源的公开一键安装包。先分别准备兼容同一修订的可信部署工具、二进制、逐机材料与独立可信 pin；不要运行 `curl | sh`，不要把同源 `SHA256SUMS` 当签名。流水线可能产生候选构建，是否存在对应成功运行、可访问资产及其真实性须独立核实；公开 `v0.1.0-pre.3` 与本安装路径不兼容。

**部署路径与版本范围说明**：此处提供的 `systemd`/`procd` 均为显式启用的旧开发模板，默认以 root 运行；如果你需要经认证的发布清单、非特权运行及就绪失败回退，请改用[离线双签 systemd 路径](VERIFIED-SERVICE.md)，切勿在同一主机混装两条路径。本页面向**当前兼容开发构建**；公开版本 `v0.1.0-pre.3` 尚不包含此处所需的 daemon 策略参数。

## 1. 在 Core、Edge 各准备一份输入

在每台目标机创建 `/root/boreas-stage`（root 所有，权限 `0700`），并将目录内文件设为 root 所有、权限 `0600`（候选二进制本身无需预先赋予可执行权限）。你也可以改用自己的私有绝对路径。另请准备一份已审核的源码 checkout（需包含 `tools/deploy/one-click.sh`、`install.sh` 及同目录模板），后续命令均在 checkout 根目录执行。

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

在进入预演前，请逐项核对以下前置条件：

- **制品真实性**：从独立可信渠道获取 64 位十六进制 SHA-256（或预先受信的签名清单），核对源码修订来源、目标架构与静态链接属性；注意 `sha256sum` 仅计算本地文件摘要，无法证明文件来源。安装器在校验摘要和 ELF 后，会直接**执行**候选二进制的 `doctor`、`config-migrate`、`config-check` 与 `pki verify-bundle`，因此真实性核验必须在运行安装器之前完成，绝不能让未验真的候选程序替自己作证。
- **网络信任材料**：按[签发步骤](README.md#offline-issuance)备齐材料，并用可信 CLI 执行 `pki verify-policy` 预检；两个网络根 pin 必须独立预配，严禁放入 `material/`。安装脚本只检查路径与权限，不校验证书/策略双签；daemon 启动时会按 pin 验签并记录水位，一旦失败将拒绝承载任何业务流量。
- **文件与路径约束**：`material/` 目录仅允许存放节点包文件和对端身份，不接受离线 CA 私钥、未知文件、符号链接、特殊文件或子目录；策略文件与 pin 必须是非空普通文件且仅有一个硬链接，其各级父目录也必须可信。安装目标 `/opt/boreas` 与默认 `/usr/local/bin` 均不能是符号链接，且不能对组或其他用户可写；若指定 `--bindir`，该目录须预先存在。切勿将安装前缀放在 `/tmp` 或复用系统目录。完整规则见[策略与状态](POLICY-STATE.md)。
- **系统工具与管理链路**：目标机须备齐完整的 Linux `iproute2`、`readelf`、`sha256sum` 及常规 POSIX shell 工具，脚本不会自动安装依赖。若通过远程会话操作，请先确认管理连接不经过即将创建的 TUN 接口，以免启动后失联。

## 2. 使用同一组参数预演与安装

执行前，请将下方两个 `REPLACE_…` 占位符替换为实际值。示例中的 shell 函数仅用于保证预演与正式安装使用完全一致的参数；切换终端会话后需重新定义。请先运行 `--dry-run` 核对预期落盘路径与服务类型；面对 root 所有的输入文件时，必须使用相同 UID 执行预演。

```sh
STAGE=/root/boreas-stage
NET_ID=REPLACE_WITH_NET_ID
DIGEST=REPLACE_WITH_TRUSTED_SHA256
RELEASE_ID=local-eval-1

install_boreas() {
  sudo sh tools/deploy/one-click.sh \
    --stage "$STAGE" --network-id "$NET_ID" --sha256 "$DIGEST" \
    --release "$RELEASE_ID" --service systemd --accept-legacy-service "$@"
}

install_boreas --dry-run
```

预演过程严格只读：不会下载文件、不会写入目标路径，也不会执行候选二进制或调用服务管理器。它仅校验摘要、ELF、路径与文件来源，不能证明配置校验或策略验签一定通过。此外，`--url` 不属于本教程路线：脚本仅接受直接的 HTTPS 二进制 URL 且要求附带 `--accept-weak-https`，但仍无法验证发布签名。

仅当预演输出与信任核查全部无误后，再执行正式安装。`--apply` 是明确的变更确认；它不自动启动服务。如果只需版本目录和命令入口，请在函数中把 `--service systemd --accept-legacy-service` 替换为 `--service none`，并重新预演。自定义前缀、bindir 或评估 procd 时使用底层 `install.sh --help`，不要与双签路径混装。若主机上已在运行 `boreas.service`，请先规划停机并检查现有服务及路径，不要直接套用首次安装流程；旧模板也不能用于替换离线双签服务。

```sh
install_boreas --apply
sudo cat /opt/boreas/active
sudo /usr/local/bin/boreas doctor
```

安装器默认**不会启动**服务。安装完成后，预期结果如下：`active` 应输出 `local-eval-1`，`doctor` 应确认该二进制具备 daemon 与 TLS 支持。`/opt/boreas` 权限为 `0700`，本示例中的 dispatcher 与运行状态均由 root 访问。落盘目录结构如下：

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

安装器调用 `config-migrate` 生成 `version = 2` 配置且不修改源文件；同时核对 `net_id`，并将 `[paths]` 下的 `identity_key`、`roots`、`state_dir` 改写为活动版本下的私钥、roots 与共享状态目录。其余配置项仍需由你自行审核。默认 `/usr/local/bin` 下的 `boreas` 与 `boreas-easy` 入口均指向 dispatcher。

## 3. 写入本机角色与启动参数

确认 `/etc/boreas` 未被其他服务占用后，创建 root 所有的非符号链接目录（`0700`）和 `/etc/boreas/boreas.env`（普通文件，精确权限 `0600`）。新建文件可执行下方两条命令；**注意第二条命令会清空现有文件，仅限首次建档使用**。随后以管理员身份编辑该文件，仅写入匹配本机角色的那一段配置，切勿将 Core 与 Edge 两段合并写入。

```sh
sudo install -d -m 0700 -o root -g root /etc/boreas
sudo install -m 0600 -o root -g root /dev/null /etc/boreas/boreas.env
```

Core 节点（监听端口须在云安全组及本机防火墙放行）：

```ini
BOREAS_TRANSPORT=wss
BOREAS_ROLE=core
BOREAS_VIP=10.20.1.1
BOREAS_PEER_VIP=10.20.1.2
BOREAS_LISTEN=0.0.0.0:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

Edge 节点（替换底层 IP、核对证书 SAN，不要填写隧道 VIP）：

```ini
BOREAS_TRANSPORT=wss
BOREAS_ROLE=edge
BOREAS_VIP=10.20.1.2
BOREAS_PEER_VIP=10.20.1.1
BOREAS_CONNECT=203.0.113.10:8443
BOREAS_TLS_NAME=wss.example.net
BOREAS_WS_HOST=wss.example.net:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

参数与网络边界约束如下：VIP 必须取自签名身份中的 RFC1918 地址，不带 `/32` 后缀且不允许前导零；底层监听或拨号地址为数字 IPv4 加端口；TUN 接口名不超过 15 个字符；wrapper 允许的 MTU 范围为 `1280..1400`。本例使用私有外层 CA 与直连 WSS（即 TCP 不经过反向代理，不是 direct 传输模式）。当前实验修订的 wrapper 把 `BOREAS_TRANSPORT=wss|direct` 显式传给 daemon；省略时为 `wss`，非法值拒绝，两端须相同。**仅使用已包含并通过验证的对应 daemon 构建**；旧二进制不支持该参数，不能回退为按文件猜测模式。`direct` 无外层 TLS/WebSocket，依赖内层认证加密，须先单独评估及测试，非 CDN 流量；本教程不承诺端到端验收已完成。

WSS 要求 Core 提供 `outer.pem`（服务端证书及所需中间链）和对应 `outer.key`，Edge 的 `BOREAS_TLS_NAME` 与 DNS SAN 匹配。私有 CA 由离线签发流程提供 `outer-ca.pem`；公网 CA 场景则须由管理员独立申请和安全安装证书、完整链及私钥，并按当前实现让 Edge 使用系统 OpenSSL 信任根（无需 `outer-ca.pem`）或独立配置适用信任根；选用哪一种必须核对实际二进制与目标主机信任库。**安装器不申请或续期公网证书、不配置 CDN、DNS 或 ACME**。公网 CA/CDN 必须自行核查服务器可达性、SNI/Host、WebSocket、代理超时及安全策略并完成现场验收；不要删除 CA 或关闭验证来解决错误。不要提前创建同名接口或对端 `/32` 路由——该 wrapper 会自行创建运行资源，遇到冲突会直接拒绝启动，不会覆盖现有网络。停止服务时，wrapper 仅尝试撤除自身添加的地址与路由，不会清空路由表，也不会修改默认路由、防火墙或主机 DNS（默认部署仅添加已授权对端的 IPv4 VIP `/32` 路由，不配置任意 `/24` 路由、导出或转发）。

启动顺序上，请先在 Core 执行 `daemon-reload` 与 `start`，确认 Core 已成功监听 TCP 端口后，再在 Edge 执行相同两条命令。仅当[双向验收](README.md#verify-and-maintain)全部通过后，再考虑执行 `enable` 开启开机自启。

```sh
sudo systemctl daemon-reload
sudo systemctl start boreas.service
sudo systemctl status boreas.service
sudo journalctl -u boreas.service -n 100 --no-pager
```

`Type=simple` 显示 `active` 并不代表握手、路由或实际流量已就绪。请查询实际 daemon 状态进行确认：

```sh
sudo /usr/local/bin/boreas ctl status --socket /opt/boreas/state/control.sock
sudo /usr/local/bin/boreas-easy --socket /opt/boreas/state/control.sock --service boreas
```

确认需要开机自启时，再执行 `sudo systemctl enable boreas.service`。后续升级时，已运行的进程不会随着 `active` 指针切换而自动替换；请先审核变更，再按计划执行 `sudo systemctl restart boreas.service` 并重做双向验收。虽然也可以显式传入 `--start` 来启用并（重）启服务，但这要求事先备好完全合规的 `boreas.env` 且不会校验数据面连通性，因此本指南刻意采用分步检查。

### 仅供评估的 procd 模板

使用 `--service procd --accept-legacy-service` 可基于旧模板渲染 `/etc/init.d/boreas`，环境文件规则与上文相同。该模板严格按白名单读取字面 `KEY=VALUE` 行，严禁添加引号、行尾注释、多余空格、变量展开或 CRLF 换行符。目标机必须具备完整的 `iproute2`、Linux TUN 及其他所需工具；存在此模板并不意味着已验证 BusyBox `ip` 或物理 OpenWrt 设备。请先在目标镜像上以不启动模式审阅路径、工具和架构；若缺少已验证环境，请直接选用 Linux/systemd 路径。

## 4. 安装失败、停止与回退

- **预演拒绝**：优先查看第一条报错。依次排查落盘路径的各级祖先目录、材料 allowlist、两个 pin 是否已放在 `material/` 之外、三份策略文件是否混入多余文件，以及静态 ELF 与目标架构是否匹配。切勿通过放宽目录权限或忽略摘要失败来强行继续。
- **安装失败**：安装锁 `<prefix>/.install.lock` 用于串行化执行；若发现遗留锁，应先排查原因而非直接抢占。`active` 指针在最后阶段切换；若切换后后续安装步骤明确失败，安装器会尝试恢复旧指针，但已发布的文件仍可能保留在目录中。注意 `sync` 并不等同于断电可靠性验收。恢复后务必核对 `active`、日志和实际存活进程，不要把指针回退误判为旧服务已恢复运行。
- **服务启动失败或反复重启**：立即执行 `sudo systemctl stop boreas.service` 并查看日志。退出码 `78` 代表旧 wrapper 的配置拒绝，服务模板不会对退出码 `78` 自动重启；普通运行错误则会受重启次数限额控制。已安装的服务不会因为运行时故障而自动回退版本。
- **升级与手工回退**：同一 release ID 仅接受字节完全一致的输入，任何变动都必须使用新 ID，绝不覆盖历史代际。确需回退时，先停服并审核旧制品、旧策略及现有持久状态是否仍兼容且有效，再按[策略状态和回退语义](POLICY-STATE.md#6-升级--start-与回滚)恢复指针、重启并重新验收。严禁通过删除 `status.state`/`policy.state` 或降低授权水位来恢复服务。

### 如何区分测试证据

- `tools/deploy/test-install.sh`：隔离环境下的 shell 回归测试（模拟系统工具，不以 root 执行，且不得在已有 Boreas 服务的主机上运行）。它只验证文件来源、路径、权限、版本指针与 wrapper 约束，不能证明真实数据包的转发能力。
- `tools/deploy/test-real-install.sh`：由 [deploy 工作流](../../.github/workflows/deploy.yml) 在受控 runner 上以 `--service none` 验证静态安装流程，不会启动服务或执行现场 TUN 验收。真实数据面验证请查阅 [TLS 工作流](../../.github/workflows/rust-tls.yml)与[双机验收清单](README.md#verify-and-maintain)。
