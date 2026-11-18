# 策略输入、状态目录与发布/回滚语义

本页说明 `tools/deploy/install.sh` 如何发布 **NetworkPolicy + NetworkRoot** 五个输入，以及
`boreas-run` 如何按活动 release 选择它们。范围仅限部署脚本与目录布局；生产门禁、数据面
验收与真机证据见 [ONE_CLICK.md](ONE_CLICK.md) 和 [当前实现状态](../engineering/implementation-status.md)。

> 本页描述的是**开发阶段部分实现**的部署语义，不构成生产批准（`production_approved: false`）。

> **一句话**：五个输入按 `<release-id>` 命名、逐文件原子地发布到 `<prefix>/state`；
> `active` 指针是唯一的代际选择器；运行期存储由 daemon 首次启动时自建，安装器不预建；
> 升级失败或指针回滚只切回旧代际，永不覆盖旧文件。

## 1. 五个输入与信任边界

| 输入 | 来源 | 安装器检查 |
|---|---|---|
| `policy.tbs` | `--policy-dir` | 非空普通文件、非符号链接、单硬链接、属主为调用用户、无 group/other 权限 |
| `policy.ed25519.sig` | `--policy-dir` | 同上 |
| `policy.mldsa65.sig` | `--policy-dir` | 同上 |
| `root.ed25519.der` | `--network-root-ed25519-der` | 同上；且与其余四个输入路径互不相同 |
| `root.mldsa65.der` | `--network-root-mldsa65-der` | 同上 |

`--policy-dir` 必须**恰好**包含前三个文件；多余条目（包括 `.bak`、隐藏文件、子目录）一律
拒绝，避免操作员把半份或无关内容当成一次完整发布。属主检查使用 `id -u`：真实安装以 root
运行时，五个输入必须属主为 root（由 root 写入或先 `chown root`），组/其他用户可读也会被
拒绝。两个 NetworkRoot pin 必须通过**独立于二进制/URL 的渠道预配**：安装器只接受本地文件
参数，从不下载 pin，也不会从 `--url` 或 release 资产里"顺便"取得信任锚；pin 位于
`--materials` 内会被拒绝，防止把信任锚打包进它所授权的 release。

文件检查之后、复制之前存在时间窗，因此**路径**也必须可信：安装器从 `/` 逐级检查
`--policy-dir` 与每个 pin 的目录——任何符号链接、任何 owner 不是 root/调用用户的祖先、
任何非 sticky 的 group/other 可写祖先都拒绝；sticky 的 `/tmp` 可接受，但最终目录必须属主为
调用用户（root 安装即 root）且自身 group/other 不可写，否则同机他用户可以把该私有目录
改名替换。可写目录一律拒绝，操作员应先把输入放到 root 所有、非共享的目录。非 root 运行
`--dry-run` 时，root 属主的输入会被同一 `id -u` 规则拒绝；对真实输入应 `sudo` 复核。

安装器**不会自动轮换 pin**：同一 `--release` 下 pin 任一字节不同都会被当作不同 bundle
拒绝；换 pin 必须显式提供新输入并使用新的 `--release`，且仍受 `policy.state` 的根指纹
绑定约束（daemon 在指纹变化时以 `WrongRootFingerprint` fail-closed 拒绝，需要单独迁移）。

`--network-id` 必须与 `config-migrate` 生成的规范化配置中 `[node] net_id` 一致；不一致在
切换 `active` 之前失败。daemon 运行期还会用配置里的 net id 重新校验策略，不匹配即拒绝启动。

**安装器不做的**：它不验证策略签名与 pin 的密码学有效性，也不声称 pin 来源可信；这些属于
daemon 的 fail-closed 启动校验（见 §5），操作员应另外用下述命令预检：

```sh
boreas pki verify-policy \
  --net-id '<32 hex>' \
  --tbs-file policy.tbs \
  --ed25519-signature-file policy.ed25519.sig \
  --mldsa65-signature-file policy.mldsa65.sig \
  --root-ed25519-der root.ed25519.der \
  --root-mldsa65-der root.mldsa65.der
```

该命令只读（不带 `--record-state`），输出含 `pin_provenance: "operator-supplied; verify
independently"` 与 `clock: "local-untrusted"`，不能替代独立信任判断。

## 2. 目录布局

```text
<prefix>/                           # 默认 /opt/boreas，0700 root
├── active                          # 单行 release id，唯一提交点
├── boreas-run                      # 服务 wrapper（烘焙 prefix）
├── releases/<release-id>/          # 每个 release 只读
│   ├── boreas  config.toml  bundle.sha256
│   ├── materials/…
│   └── policy-inputs/              # 五个输入的 release 内副本，参与 bundle 清单
│       ├── policy.tbs
│       ├── policy.ed25519.sig
│       ├── policy.mldsa65.sig
│       ├── root.ed25519.der
│       └── root.mldsa65.der
└── state/                          # 0700 root；运行期共享
    ├── <release-id>.policy.tbs          # 活动代际的五个输入，直接位于 state/
    ├── <release-id>.policy.ed25519.sig
    ├── <release-id>.policy.mldsa65.sig
    ├── <release-id>.root.ed25519.der
    ├── <release-id>.root.mldsa65.der
    ├── status.state  status.state.lock       # daemon 首次启动时创建
    └── policy.state  policy.state.lock       # daemon 首次启动时创建
```

**为什么输入平铺在 `state/` 而不是 `state/<release-id>/`**：当前
`crates/boreas-cli/src/network_policy_runtime.rs` 的
`verify_and_record_default_policy` 会把每个输入父目录 canonicalize 后与配置的
`state_dir` 比较，要求**直接子文件**；`daemon.rs` 对 `--status-state-file` 也要求
"directly under the configured state_dir"。在不改 CLI 的前提下，唯一安全的布局就是
release 前缀文件名 + 由 `active` 选择。`boreas-run` 读取 `active` 后使用
`$STATE/$ACTIVE.<name>`，因此切换/回滚 release 不需要重新发布输入。

**建议的最小运行期变更（未实施，需 lead 决定）**：允许输入位于
`state_dir/<单个安全组件>/`（canonical parent 的 parent 为 `state_dir`，且该目录 0700、
属主为配置 UID），同时保留现有平铺布局兼容。这样安装器可改为
`state/<release-id>/{policy.tbs,…}` 并把 wrapper 路径换成
`$STATE/$ACTIVE/policy.tbs`；无需新增 CLI 参数，但属于 `crates/boreas-cli` 变更，需按
`rust-tls.yml`/`deploy.yml` 的触发规则重新跑 CI。当前交付**不**包含该变更。

## 3. 原子发布、无覆盖与冲突

安装器在 `active` 提交前完成以下步骤：

1. 把五个输入从 `--policy-dir`/pin 路径复制到同一文件系统的
   `<state>/.incoming.<release-id>.XXXXXX/`（`0700`，文件 `0600`），并对**暂存副本**重新
   做一次类型/属主/硬链接/权限检查。
2. 逐文件发布：目标为 `state/<release-id>.<name>`。
   - 目标不存在：`ln` 建立硬链接（原子、目标已存在即失败），随后删除暂存名。目标在出现
     的那一刻就是完整内容，不会暴露半写文件。
   - 目标已存在且逐字节相同：复用，不触碰（同一 release 重跑幂等）。
   - 目标已存在但内容不同：失败并要求换 `--release`，**永不覆盖**。
3. 五个文件都就绪后，才用 `mktemp` + `mv` 原子切换 `active`。切换后失败会把 `active`
   恢复为旧值；本次已发布的新代际保留，旧代际文件保持原样。
4. 切换前执行一次 POSIX `sync`：先冲刷 release、发布文件与 dispatcher/wrapper/服务模板
   的写入，避免断电后 `active` 指向只存在于页缓存的内容。这是**粗粒度屏障**，不是逐文件
   `fsync` 证明；硬件写缓存与文件系统崩溃一致性仍是假设（见 §8）。

这不是"五个文件一步 rename"：POSIX 没有多文件原子重命名。安全性来自两个不变量：
最终文件名只通过 `ln` 出现且内容完整；这些文件只有在 `active` 指向该 release 时才生效。
崩溃最多留下按 release id 可识别的未引用文件，重跑会复用或明确报告冲突，不会污染旧代际。
脚本正常失败路径会删除本次新建的文件和暂存目录（`PUBLISHED` 位图只记录本次创建的项）。

**安装串行化**：整个会改动 prefix 的运行由一个 create-only 锁 `<prefix>/.install.lock`
（原子 `mkdir`，`0700`）独占。锁在**任何 staging/publish 之前**取得，并在全部清理
（含指针回滚）之后才由 trap 释放；锁忙或存在旧锁时安装器明确失败，**不会自动删除**不是
本次运行创建的锁，需要操作员确认后手工移除（SIGKILL 留下的旧锁同理）。

## 4. 运行期存储：不要预建

`status.state` 与 `policy.state` 是跨 release 共享的持久防回滚存储，语义是：

- 文件**不存在** = 首次使用；daemon 自己创建 `.lock` 并在提交时创建/替换状态文件。
- **空文件**不是"首次使用"：它会被当作损坏状态读取并失败。
- 因此安装器**不创建**这两个文件，只在它们已存在时校验：普通文件、非符号链接、属主
  root、无 group/other 权限、非空。已存在的空文件同样被拒绝（删除后由 daemon 重建）。

对应实现：`crates/boreas-pki/src/status_store.rs` 的 `read_state` 对 `NotFound` 返回空
状态；`crates/boreas-pki/src/network_policy_store.rs` 模块文档也明确"missing state file
is indistinguishable from first use"。安装器预建空文件只会制造必然的启动失败。

## 5. 启动时的密码学校验（fail-closed）

`boreas daemon serve|connect` 每次启动都会：

1. 用显式传入的五个输入 + 配置 net id 重新验签（Ed25519 + ML-DSA-65），校验 pin
   指纹、有效期与默认前缀；
2. 在 `policy.state` 上提交防回滚水位（重放/回退/equivocation 失败即拒绝）；
3. 在 `status.state` 上通过签名状态门禁后才承载业务流量。

任一输入缺失、路径不是 `state_dir` 直接子文件、验签失败，或 `state_dir`/`policy.state`
属主与权限不符，daemon 在创建 TUN 之前退出；`status.state` 的检查在 TUN 创建之后、承载
业务流量之前完成。wrapper 还会在启动 daemon 前检查五个输入的存在性、非符号链接、
root 属主与 group/other 权限，缺失/不安全时以 `78`（EX_CONFIG）退出，避免 supervisor
热重启。

注意：安装器**不**检查策略 sequence/有效期与已有 `policy.state` 水位的兼容性。把较低
sequence 或冲突的策略装到已有水位的节点上，daemon 会按 anti-rollback/equivocation 规则
拒绝启动；这是有意的 fail-closed 行为，安装成功不等于 daemon 会接受该策略。

## 6. 升级、`--start` 与回滚

- 安装本身**从不启动服务**；只有显式 `--start` 才 `enable`/`restart`（systemd）或
  `enable`/`restart`（procd）。升级使用 `restart` 而不是 `enable --now`，否则旧进程继续
  运行。
- `--start` 失败发生在 `active` 切换之后时，安装器把 `active` 恢复为旧 release；旧代际的
  五个输入仍在 `state/` 中且从未被修改，wrapper 因此立即回到旧代际。
- 人工回滚：停服务 → 把已审核的旧 release id 写入 `<prefix>/active` → 启动服务。不要删除
  新代际文件；它们可用于再次升级或排查。回滚前仍需确认配置/材料兼容。
- 迁移注意：本次变更之前安装的 release 没有 `state/<id>.*` 输入，也没有包含策略输入的
  bundle 清单，既不能直接把 `active` 指回它们，也不能用同一 release id 原地补齐（清单不同
  会被拒绝）。请用同一二进制/材料以**新的** `--release` id 安装一次并切换；随后该新代际
  才可参与回滚。
- 服务运行期崩溃不会自动回滚版本。

## 7. 测试覆盖（Actions-only）

`tools/deploy/test-install.sh` 新增/覆盖：

- 正向：完整安装后五个 `state/<id>.*` 存在且 `0600`、单硬链接、与已校验输入逐字节一致、
  进入 `bundle.sha256`；`status.state`/`policy.state` **不存在**（由 daemon 创建）。
- 负向：缺 policy 目录/输入、pin 缺失、pin 为符号链接、两个 pin 相同、`--policy-dir` 多余
  条目、policy 输入为符号链接/硬链接/group-other 可读/非调用用户所有、`--policy-dir` 或
  pin 目录 group-other 可写/非调用用户所有、输入路径含符号链接祖先或非 sticky 的
  group/other 可写祖先、`--network-id` 长度错误或与规范化配置 `net_id` 不一致 → 全部失败
  且不切换 `active`；sticky 可写祖先（模拟 `/tmp`）被接受。
- 安装锁：成功安装后无锁；预置锁 → 明确失败、`active` 不变、锁保留、未创建 staging；
  失败路径（摘要不匹配）释放本次自己的锁。
- 冲突与无覆盖：同 release 已发布内容被篡改 → 拒绝且不覆盖；恢复一致后幂等重跑成功。
- 升级：`test.2` 发布自己的五个文件，`test.1` 逐字节不变；预置冲突的 `test.3` 半成品 →
  失败、清理本次新建文件、保留冲突文件与 `test.2`、`active` 不变；移除冲突后升级成功；
  把 `active` 写回 `test.2` 即可重新选中旧代际输入。
- wrapper：缺一个输入、输入为符号链接 → 退出码 `78` 且不触碰 `ip`；成功路径断言五个
  `state/<active>.*` 路径与共享 `status.state`/`policy.state` 参数；切换 `active` 到
  `r2` 后只传 `r2.*` 路径。

`tools/deploy/test-real-install.sh`（手动 `real-static-install`）用真实 root/stat/readelf
安装真实静态候选，并断言五个输入已发布（单硬链接、与占位输入逐字节一致），两个共享存储
未被安装器在 `state/` 中预建。该 harness 的 policy/pin 内容是明确的非机密占位符：它只验证
安装布局与文件导源，不启动 daemon，因而不构成密码学校验证据。

## 8. 仍未验收 / 需要 lead 触发的变更

- **未做**安装期策略验签（CLI 目前没有签发/导入 NetworkPolicy 的命令，真实安装 harness
  无法生成有效输入）。如需安装期 `pki verify-policy` 门禁，需要：
  1. CLI 增加离线签发/打包命令（或接受操作员提供的外部策略包）；
  2. `deploy.yml` 的 `real-static-install` 传入有效策略包/网络 id；
  3. 相应更新 `test-real-install.sh` 与本文档。以上均超出本目录授权，需 lead 统一安排。
  注意：daemon 的启动验签发生在候选已被安装器执行之后；独立 verifier 的摘要核对与
  `pki verify-policy` 预检**必须先于执行**安装器，不能由运行期验签倒推替代。
- **CI 未覆盖** `active` 切换后 `--start` 失败触发的 `restore_active` 分支：它要求可写
  `/etc/boreas` 与真实 systemd/procd，回归 harness 明确拒绝 root。该分支只有代码审查与
  真实主机演练可证。
- 真机断电/磁盘满的原子性仍需实测；并发安装器现在由 `<prefix>/.install.lock` 串行化
  （锁忙明确失败，测试用预置锁模拟），但没有真机并发/断电演练。
  `ln` 的 EEXIST 与 `active` 单点提交把风险限制为"未引用的完整文件"，并在切换前执行一次
  `sync` 粗粒度屏障；但仍没有逐文件 `fsync`、硬件写缓存或文件系统崩溃一致性的证明。
- 若采纳 §2 的 versioned 子目录运行期变更，安装器/wrapper/文档需作为同一变更集更新，
  并重新验证 `daemon_pki_e2e` 中"direct child"用例。
