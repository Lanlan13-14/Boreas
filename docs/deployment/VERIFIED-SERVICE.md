# Linux/systemd 离线签名服务（待 Actions 验证）

这是受控 Linux 主机的严格路径；不是生产批准、完整 TUF、OpenWrt 方案或通用升级器。旧 `install.sh` 的摘要/HTTPS 路径不能替代双签，旧 root 服务模板仅保留显式开发入口。软件发布根与网络 PKI 根独立。

## 首次安装（管理员）

1. 从独立可信的离线包或核准途径预配 `boreas-supervisor`（必须启用 `openssl-backend`，OpenSSL ≥3.5）和本目录所指的部署工具。不要从待验发布包运行这些工具，也不要使用 Git commit/tag 或同源 SHA-256 当信任根。目标为 Linux x86-64/AArch64，需支持 Landlock ABI ≥3（通常 Linux 6.2+，发行版可回移植），并支持 seccomp TSYNC、memfd 执行/密封和 `close_range`。主机 UTC 必须可信；应有足够空间保留上一镜像和每次 staging，版本文件不会自动删除。
2. `sudo sh tools/deploy/install-verified-unit.sh /absolute/path/to/trusted/boreas-supervisor` 安装单位、启动器、专用 `boreas` 系统用户与空目录；不自动启动、覆写旧服务或迁移现有网络状态。失败时先检查现场，不要删除或重新初始化已有非空状态。`/etc/boreas/release-trust` 必须由 root 持有且为 `0700`；其中 `ed25519.der`、`mldsa65.der` 是通过独立途径核对的 SPKI DER 发布公钥，`key-id` 和 `min-sequence` 各为单行且以换行结束，四文件均 `root:root 0600`。生产签名私钥不能放在节点或 Actions，不能从候选包导入信任根。
3. 独立配置 `/etc/boreas/node.toml`（`0600` 且 `boreas` 可读），其中 `[paths].state_dir` 必须为 `/var/lib/boreas/state`；节点材料在 `/etc/boreas/materials`，只给该服务账号读节点密钥。离线签发并部署独立网络根和策略：把五个输入以 `0600` 放入 `/var/lib/boreas/state`，固定名称为 `policy.tbs`、`policy.ed25519.sig`、`policy.mldsa65.sig`、`network-root.ed25519.der`、`network-root.mldsa65.der`；不要预建或用旧备份覆盖 `policy.state`、`status.state`。材料与网络策略不是软件发布产物；升级或回退不修改它们。
4. `/etc/boreas/service.env` 用 `root:root 0600`。Core 用 `BOREAS_ROLE=core`、`BOREAS_LISTEN=0.0.0.0:8443`；Edge 用 `BOREAS_ROLE=edge`、`BOREAS_CONNECT=192.0.2.2:8443` 与 `BOREAS_TLS_NAME=<证书 DNS SAN>`（可加 `BOREAS_WS_HOST`）。用数字 TCP 地址，避免启动依赖系统 UDP DNS；端口应 ≥1024。设置 `BOREAS_TUN_NAME=btun0`、`BOREAS_MTU=1360`、`BOREAS_MIN_RUN_SEQUENCE=<当前允许执行的最低序号>`（默认 1，安全撤销时提高，**不要**仅为方便回退而降低）。此执行下限与独立发布接受下限用途不同。
5. 由管理员或系统网络管理器预配**专用、单队列、无包信息头**的持久 TUN、正确 VIP 与仅授权的对端路由。例如（先核实名字、签名身份里的 VIP 及现有路由，不复用已有接口）：
   ```sh
   sudo ip tuntap add dev btun0 mode tun user boreas
   sudo ip link set dev btun0 mtu 1360 up
   sudo ip addr add 10.20.1.1/32 dev btun0
   sudo ip route add 10.20.1.2/32 dev btun0
   ```
   重启后须由本机网络配置重新预配；持续设备不等于队列、路由或数据面连续性。单元不会给服务账号发放 `CAP_NET_ADMIN`、`CAP_NET_RAW`、绑定低端口或设置 SO_MARK 的能力。现有 root/procd 部署必须单独迁移、安全审核并保留防回退状态；禁止重置后伪装为迁移。
6. 将离线清单原始字节、对应本架构的静态 ELF、Ed25519（64 字节）与 ML-DSA-65（3309 字节）原始分离签名放到 `boreas` 可读的临时 spool。建议 root 所有、仅 `boreas` 组可读，路径均为绝对路径。不传入 URL、归档、发现 JSON、签名 envelope JSON 或候选自带的根。执行：
   ```sh
   sudo /usr/local/libexec/boreas/stage-verified-release verify \
     /ABS/SPOOL/manifest /ABS/SPOOL/boreas /ABS/SPOOL/ed.sig /ABS/SPOOL/ml.sig
   # 输出 verified release-N-ARTIFACT_SHA MANIFEST_SHA256；核对并批准完整清单摘要。
   sudo /usr/local/libexec/boreas/stage-verified-release apply --confirm-manifest-sha256 MANIFEST_SHA256 \
     /ABS/SPOOL/manifest /ABS/SPOOL/boreas /ABS/SPOOL/ed.sig /ABS/SPOOL/ml.sig
   ```
   已独立信任的管理 CLI 也可使用 `boreas update verify` / `boreas update apply`（同参数、同 helper，要求已获管理员权限，不调用 sudo 或请求密码）。**不得用待验 ELF 运行 `sudo boreas`**。此版本的 helper 与 supervisor 须一起从独立可信来源预配；旧四文件入口已取消，已有 verified 单元无需重建或重置存储，须由管理员显式替换受信工具。此入口不接管旧服务或含 drop-in 的定制单元。
7. `verify` 不停机、不写升级存储。`apply` 在独占运维锁内先以 `boreas` 复验，成功后才停机；停机后重新验签并检查同一个批准摘要，锁内再次检查持久防回退状态，然后启动真实的 `Type=notify` 单元。清单中的 HTTPS 字段只做语法校验，绝不取回。候选失败且旧版通过就绪时，服务恢复，命令仍非零报告**候选没有确认**。输入在停机后更换或损坏时不能换入新发行版；会尝试重新启动此前运行的服务。首次安装没有旧版时失败会保持停机。核实状态后可用 `sudo systemctl enable boreas.service`；没有自动 enable。

### 可选：管理员签名在线应用

如果已部署[兼容的签名 feed](../upgrade/README.md#administrator-approved-online-apply)，管理员可在独立审查发行版、核对**原始清单**完整 SHA-256 后使用预信任的 Linux/OpenSSL CLI：

```sh
sudo /absolute/path/to/pretrusted/boreas update apply \
  --confirm-manifest-sha256 REVIEWED_64_LOWERCASE_HEX \
  --signed-feed https://updates.example.test/candidate
```

它用本机已安装的发布根验双签，只为已批准清单下载受大小与 SHA-256 约束的原生静态 ELF，并把四个本地临时文件及同一摘要交给上面的离线 helper；不会跳过准入水位、停机前复验或回退。`update-check` 仍是只读命令，不能自动触发应用。没有兼容 feed 时继续用本地四文件操作；不能使用公开发现索引、普通 GitHub Release 下载地址或生产归档替代签名 feed。

## 验证 / 恢复

```sh
sudo systemctl status boreas.service
sudo journalctl -u boreas.service
sudo -u boreas /usr/local/libexec/boreas/boreas-supervisor status --store /var/lib/boreas/releases --json
```

- Ed25519 **与** ML-DSA-65 对同一份限定大小的原始清单验签；严格解析后检查 UTC 窗口、单一目标架构、字节数、SHA-256、静态 ELF 和 `boreas-node-state-v1`。最高接受序号与原始清单哈希先持久化；相同序号只有完全相同清单能幂等重放。旧版恢复不会降低接受下限。操作前不要用手改活动文件、删 journal、删水位、重置机器或恢复旧快照来绕过序号。
- 启动前重新核对存储镜像哈希，以只读密封 memfd 执行**同一批字节**。先运行受限且限时的 `self-check`（现为能力自述，不是就绪），随后以 `SO_PEERCRED` 的实际子 PID 和 `/proc/<pid>/exe` 的密封 FD inode 绑定随机挑战。Core 就绪只表示已绑定 TCP listener、TUN 队列及当前策略/状态门；不表示有对端。Edge 还须建立已认证 E2E 电路及包路径。报告不证明持续流量、本机路由收敛或外部邻居可达。只有 supervisor 发送 systemd `READY=1`，服务接受回退版本前也重复整个就绪验证。
- 受控重启，不继承旧 TLS/网络 fd；失败候选消耗持久尝试并恢复原活动指针。运维锁仅协调此入口的调用；应用期间不要并发直接运行 `systemctl`、手动操作存储或修改 ReleaseRoot/服务配置。崩溃恢复由 journal 处理，脚本自身不能捕获 `SIGKILL` 或断电。回退要求可读的同一状态 schema、保留的已验镜像且不低于 `BOREAS_MIN_RUN_SEQUENCE`；磁盘/状态损坏、签发策略过期或旧版不再兼容均可使服务拒绝启动。检查日志并优先提供更高序号的修复发行；确有需要时，停机后以 `boreas` 执行 `reset-trial --store /var/lib/boreas/releases --confirm <完整 release-N-SHA>`，它不降低防回退水位。
- `boreas` 是专用系统账号，不给登录、sudo 或其他服务。Landlock 限制候选 FS 写入到自身状态与 TUN；守护进程 seccomp 限制 native ABI、socket 类型、io_uring 和 ancillary FD 接收，**不是完整沙箱**；并不证明所有 AF_UNIX 路径被内核约束。软件状态与候选权限相同 UID 的其他**非服务进程**、root、宿主存储快照/物理篡改仍是明确的运维信任边界。不能依赖这一方案防受信签名人发布恶意程序；也没有 TUF 根轮换/吊销协议、TPM 防快照回退、密码学可信 UTC 或自动 expand/contract 迁移。
