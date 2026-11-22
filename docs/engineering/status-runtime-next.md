# Status runtime next — G-REVOKE 的 durable FreshStatus 最小接线

**状态：只读审计 + 设计提案。** 本轮只新增本文件；未修改任何源码，未在本机运行 build/test/formatter，
未 commit/push。文中所有行为均来自当前 checkout 的静态阅读，不能替代 Actions 或门禁证据。

**结论（一句话）：** daemon 目前只有“每 500 ms 重新读文件”的 fail-closed watchdog，
从未打开 `StatusStore`；`StatusStore` 已具备持久 `utc_floor`、`sequence`、签名窗口和回滚 latch，
但 daemon 没有接线。下一 slice 应“进程内只开一个 store、握手前后各 gate 一次、store 移交给
watchdog 并立即首检”，同时把 `revocations` 明确列为**未实现**，不得宣称全撤。

## 1. 当前实际路径与精确缺口

### 1.1 启动、握手与 watchdog 的时间线

| 阶段 | 当前实际代码 | 安全含义 |
|---|---|---|
| 启动材料校验 | `daemon.rs:643-646` 调 `verify_material_dir_with_roots`；后者在 `provisioning.rs:901-902` 调用 `verify_status_file_against_trust` | 只在启动瞬间检查一次 `status.signed` 的签名与 `issued_at <= now < next_update` |
| TUN / 控制 socket | `daemon.rs:719-766` | 与状态无关；控制 socket 在 `daemon.rs:766` 启动，`status_fresh` 在 `daemon.rs:764` 被初始化为 `true` |
| serve 等待连接 | `daemon.rs:1102-1121`，最长 `ACCEPT_WAIT = 30s`（`daemon.rs:259`） | 等待期间没有状态复检 |
| WSS / hop / E2E 握手 | `daemon.rs:1132-1143`；连接侧 `daemon.rs:1231-1249` | 这之后才在 `daemon.rs:1295-1302` 启动 watchdog |
| watchdog 首检 | `daemon.rs:967-986` 先 `wait_timeout(interval)`，再在 `daemon.rs:988-1013` 检查 | 首次检查发生在 watchdog 启动后 **一个 interval（500 ms，`daemon.rs:260`）** |
| 业务包 | `daemon.rs:1311-1314` 先看 `watchdog.fault()`，随后 `step_outbound` | fault 为空时，首个 500 ms 内业务包可以发出 |

关键点：`run_serve_loop` 在启动校验后**没有**任何状态复检，直接 `listener.accept()` 再握手；
`run_connect_loop` 只在 `daemon.rs:1213-1214` 和 `1223-1230` 检查，之后 `connect_preconnected`
（`daemon.rs:1231-1235`）、`open_e2e`（`daemon.rs:1248-1249`）都不再检查。E2E 完成到 watchdog
首检之间最多 500 ms 的业务窗口；如果握手本身拖长，`verify_material_dir_with_roots` 的“最近校验点”
可能已经过去任意长时间。

握手没有硬 deadline：`runtime.rs:244-256` 的 `accept_tls_stream` 形参是 `_io_timeout`，实际未使用；
`runtime.rs:315-320` 明确把读写超时设为 `None`；`e2e.rs:859-923` 的 `open_e2e` / `accept_e2e` 也没有
独立超时。因此精确窗口是：

```text
t_last_status_ok = 启动材料校验（serve）或最后一次 connect 检查
t_business       = E2E 握手完成、drive_packet_path 开始
t_first_check    = watchdog 启动 + 500 ms
```

serve 的 `t_first_check - t_last_status_ok` **没有上界**（30 s accept + 无超时握手 + 500 ms），
connect 的 `t_first_check - t_last_status_ok` 也至少覆盖 E2E 握手 + 500 ms。若 `next_update`
在这段时间内到达，状态已经过期但 daemon 仍可能完成握手并在首个 500 ms 内转发业务包。

### 1.2 为什么 `currentFreshStatus` / `status_fresh` 布尔值不是 proof

- `counters.status_fresh` 在 `daemon.rs:764` 初始化为 `true`，在 watchdog 失败时
  `daemon.rs:1018` 才置 `false`；控制 socket 在 `daemon.rs:456` 直接把它当状态字段输出。
- 它不是由一次“当前时刻的签名状态校验”产生的能力，也没有绑定 sequence、deadline、store 或调用边界；
  首次 watchdog 检查前它必然为 `true`。
- `verify_status_freshness_from_roots`（`provisioning.rs:932-954`）只返回 `(seq, issued, next)`，
  没有持久化、没有 `FreshStatus` 类型、没有 store lock；每次调用临时构建 `ManagementTrust`，
  无法证明“重启后没有回退”或“本进程当前仍持有有效窗口”。
- `StatusStore::current_fresh` / `FreshStatus::check`（`status_store.rs:486-524`、`712-750`）
  才是绑定 store 状态、sequence、持久 floor、latch 和 monotonic deadline 的能力；当前 daemon
  **没有任何非测试调用点**（`StatusStore` / `FreshStatus` 只出现在 `status_store.rs` 自身测试）。

因此下一 slice 的 gate 判断必须来自 `current_fresh` + `check` 的即时结果，不能读
`counters.status_fresh`，也不能把一次“启动时校验通过”缓存成布尔 proof。`status_fresh` 只能继续作为
控制面遥测输出。

### 1.3 当前 watchdog 实际做了什么、没做什么

`StatusWatchdog::start`（`daemon.rs:949-1043`）当前逻辑：

1. 每 500 ms 调 `verify_status_freshness_from_roots`（`daemon.rs:993-998`）；
2. 用 `counters.status_sequence` 比较 sequence（`daemon.rs:1000-1007`），但这个 baseline 只在本进程内存；
3. 失败时置 `status_fresh = false`、写 fault 字符串（`daemon.rs:1018-1027`）；
4. 若 `sock_fd >= 0`，调用 `libc::shutdown(sock_fd, SHUT_RDWR)`（`daemon.rs:1028-1034`）；
5. 返回；packet loop 看到 fault 后 `path.close()`（`daemon.rs:1311-1314` 等）。

它没有调用 `StatusStore::open` / `accept_signed_snapshot` / `current_fresh` / `FreshStatus::check`；
没有持久 sequence / UTC floor；没有 revocation 解析；没有 enumerated session/route cleanup；
`shutdown` 只针对当前 outer TCP fd。`Drop` 会 stop + join（`daemon.rs:1054-1069`），但不会把 store
归还给上层。

## 2. 下一 slice：单 owner store + 握手 gate + watchdog

目标不是实现完整 `BusinessGate` 或每包 `FreshStatus::check`，而是把现有 `StatusStore` 真实接入
daemon 的**握手前/后**与 **500 ms watchdog**，并保证进程内只有一个 store 实例。不新增纯模型类型。

### 2.1 进程内只开一次

在 `run_mode` 中、`start_control_socket`（`daemon.rs:766`）之后、`match mode`（`daemon.rs:781`）
之前打开一次 store；不要在每个 watchdog tick 重新 `StatusStore::open`。

```rust
// 新增于 crates/boreas-cli/src/daemon.rs（示意，不是已实现代码）
fn open_status_store(
    state_path: &Path,
    net_id: [u8; 16],
    owner_uid: u32,
    roots_path: &Path,
    now_us: u64,
) -> Result<StatusStore, String> {
    let trust = boreas_pki::provisioning::status_trust_from_roots(roots_path, net_id, now_us)
        .map_err(|e| format!("daemon: status trust from roots failed: {e}"))?;
    StatusStore::open(state_path, net_id, owner_uid, trust)
        .map_err(|e| format!("daemon: durable status store open failed: {e:?}"))
}
```

需要新增/复用的精确 pki 入口：

- **新增** `provisioning::status_trust_from_roots(
      roots_path: &Path, expected_net_id: [u8; 16], now_us: u64
  ) -> Result<ManagementTrust, ProvisionError>`：
  抽取 `verify_status_freshness_from_roots` 中 `RootsBundle::decode` → `verify_all` → 检查
  `Authority::StatusSigner` → `ManagementTrust::add_issuer` 的部分；
  `verify_status_freshness_from_roots` 改为调用它，行为不变。
- **新增** `provisioning::read_status_snapshot_raw(status_path: &Path) -> Result<Vec<u8>, ProvisionError>`：
  复用现有 `read_bounded`，保证 watchdog 读文件也有界；不要让 daemon 直接 `fs::read` 无上限。
- 现有 `StatusStore::open`（`status_store.rs:201-250`）、`accept_signed_snapshot`（`356-475`）、
  `current_fresh`（`486-524`）、`FreshStatus::check`（`722-749`）不改语义。

### 2.2 握手前与握手后各 gate 一次

用一个局部 helper，不引入新 gate 类型：

```rust
// 示意
fn status_gate(
    store: &mut StatusStore,
    raw: &[u8],
    trusted_utc_us: u64,
    mono_now: Instant,
) -> Result<u64, String> {
    match store.accept_signed_snapshot(raw, trusted_utc_us, mono_now) {
        Ok(_) => {}
        Err(e) => return Err(format!("daemon: status snapshot rejected: {e:?}")),
    }
    let fresh = store
        .current_fresh(trusted_utc_us, mono_now)
        .map_err(|e| format!("daemon: status not fresh: {e:?}"))?;
    fresh
        .check(trusted_utc_us, mono_now)
        .map_err(|e| format!("daemon: status check failed: {e:?}"))?;
    Ok(fresh.sequence())
}
```

`SnapshotResult::DuplicateNotRenewed` 是 `Ok`，随后 `current_fresh` 仍会按原始
`runtime_deadline` 拒绝；这正是“重复旧快照不续命”。`accept_signed_snapshot` 的
`SequenceNotIncreasing`、`SnapshotEquivocation`、`ClockRollback` 等都直接变成 gate 失败。

精确插入点：

- **serve**：
  - `listener.accept()` 之前（`daemon.rs:1102` 前）调用一次；
  - `accept_tls_stream` 返回后（`daemon.rs:1140` 后）、`accept_e2e`（`1142`）前再调用一次；
  - `accept_e2e` 返回后（`1143` 后）、`drive_packet_path`（`1148`）前再调用一次。
- **connect**：
  - 替换 `daemon.rs:1213-1214` 与 `1223-1230` 的 `verify_status_freshness_from_roots`；
  - `connect_preconnected` 返回后（`1231-1235` 后）再调用一次；
  - `open_e2e` 返回后（`1248-1249` 后）、`drive_packet_path` 前再调用一次。

这些检查都在同一线程、同一个 `&mut StatusStore` 上完成，token 在调用结束前 drop；不跨线程保存
`FreshStatus`。E2E 握手本身仍可能持续到状态过期，但 **业务包在最后一次 gate 通过前不会开始**；
握手进程内的状态过期由最后一次 gate 拦截。若产品还要求“握手进行中立即中止”，需要额外的
handshake deadline/cancel，这不在本 slice。

### 2.3 store 移交给 watchdog，且首检立即执行

`drive_packet_path` 增加 `store: StatusStore` 参数；`StatusWatchdog::start` 改为接收 store 所有权：

```rust
fn start(
    mut store: StatusStore,
    roots_path: PathBuf,
    status_path: PathBuf,
    expected_net_id: [u8; 16],
    sock_fd: i32,
    counters: Arc<LiveCounters>,
    interval: Duration,
) -> Self
```

watchdog 循环内建议顺序：

1. `read_status_snapshot_raw(&status_path)`（有界）；
2. 保留现有 `verify_status_freshness_from_roots(...)` 作为 roots/authority/窗口的再次校验
   （`provisioning.rs:932-954`）；它仍会读取当前 `roots.cbor`，保持现有行为；
3. 调 `store.accept_signed_snapshot(&raw, now_us, mono_now)`；
4. `store.current_fresh(now_us, mono_now)?` 后 `fresh.check(now_us, mono_now)?`；
5. 成功后才更新 `counters.status_sequence = fresh.sequence()` 并保持 `status_fresh = true`；
6. 任一步失败：`status_fresh = false`、写 fault、`shutdown(sock_fd, SHUT_RDWR)`、返回。

**首检必须在第一次 `wait_timeout` 之前执行**：当前 `daemon.rs:967-986` 先等一个 interval，导致
业务开始后 500 ms 内没有 store 检查。把首检移到等待之前，后续仍按 500 ms 周期；这样
`t_business` 到首个 store 检查的窗口为 0，而不是 500 ms。

注意：store 的 trust 在 `open` 时固定；watchdog 仍调用 `verify_status_freshness_from_roots` 可以
发现 roots 文件变化，但 store 不会自动 reload trust。若 roots/status signer 轮换，store 可能
`WrongNetwork`/`Policy` 失败，daemon 应 fail-closed；热轮换是另一个 slice，不能在本 slice 宣称。

### 2.4 单 owner 与锁的精确关系

`StatusStore::open` 会创建相邻 `.lock` 并 `try_lock()`；第二次打开同一路径返回
`Error::Busy`（`status_store.rs:218-228`）。因此：

- 一个进程只开一个 store；不要每个 500 ms `StatusStore::open`，也不要 watchdog 与握手线程各开一个；
- store 的 `&mut` 操作（`accept_signed_snapshot`、`current_fresh`、`observe_trusted_utc`）全部在
  watchdog/主线程的单一所有者上串行；`FreshStatus::check` 只读，但也只能在 token 生命周期内使用；
- 控制 socket 线程不打开 store；`boreas ctl status` 继续只读控制 socket JSON；
- store 被 move 进 watchdog 后，若 watchdog 结束，store drop 才释放锁；重连/重启要等 join 完成
  后再 `open`，不能并发重开。

## 3. 持久 lastUTC / sequence：已有 schema，缺的是接线

`status_store` 的持久状态已经包含所需字段（`status_store.rs:863-973`）：

```text
MAGIC "BRSS\0\0\0\x01" | net_id[16] | utc_floor:u64 | flags:u8
optional snapshot:
  issuer len:u16 + issuer bytes | generation:u64 | seq:u64 | object_id[32]
  | issued:u64 | next:u64 | raw_len:u32 + raw signed envelope
optional equivocation:
  second_raw_len:u32 + second raw envelope
```

- `utc_floor` 就是持久化的 last trusted UTC；`seq` 在 snapshot 内；`issued`/`next` 是签名窗口。
- `verify_loaded`（`status_store.rs:600-651`）在重启时用已持久化的 raw 在它自己的 `issued` 边界重新验签，
  只证明“这是曾经被接受的字节”，不授予当前新鲜度。
- `current_fresh` 用 `next - max(trusted_utc, utc_floor)` 计算剩余寿命，并与进程内 `Instant` deadline
  取最小；重启后若 snapshot 仍在签名窗口内，可以继续使用，但 `next_update` 不会因为重启或重复投递而延长。
- `accept_signed_snapshot` 对同 sequence/同 object_id 返回 `DuplicateNotRenewed`（`status_store.rs:436-439`），
  不更新 `runtime_deadline`；对低 sequence 返回 `SequenceNotIncreasing`（`451-453`）。
- `FreshStatus::check` 会重查 poison/frozen/rollback latch/`utc_floor`/sequence/窗口/deadline
  （`status_store.rs:722-749`）。

现有测试直接覆盖这些结论：

- `accept_duplicate_restart_and_expiry`（`status_store.rs:1348`）：重复旧快照不续命，重启后仍可用
  未过期的持久 snapshot，越过 `next_update` 后 `NotFresh`。
- `clock_latch_survives_restart_and_recovery_cannot_lower_floor`（`1494`）：回滚 latch 跨重启，
  recovery 不能降低 floor。
- `persist_failure_poisons_and_reopen_uses_last_durable_state`（`1530`）：提交失败 poison，重开使用
  最后一个持久状态。
- `fresh_capability_rechecks_clock_expiry_and_latch`（`1574`）：token 的 `check` 重查时钟/过期/latch。

**daemon 侧的实际缺口：** `counters.status_sequence` 在 `daemon.rs:763` 直接用启动文件的 seq 初始化，
没有读取持久 store；`verify_status_freshness_from_roots` 没有跨重启 memory。因此当前重启可以把
一个更旧但仍“签名有效”的 `status.signed` 当作新 baseline，持久 `seq`/`utc_floor` 完全不起作用。
把 store 接上后，低 seq/旧 floor 会被 store 拒绝，而不是被内存 counter 接受。

**不能宣称的部分：** 如果攻击者恢复整个磁盘镜像（连同 `utc_floor`、latch、raw snapshot），
store 自己也无法检测；这需要外部 monotonic anchor/remote watermark，模块文档已明确
（`status_store.rs:46-49`）。另外当前启动路径仍要求 `status.signed` 存在且在有效期内；
“重启时没有 status 文件也能靠 store 恢复”不在本 slice，不能外推。

## 4. 签名快照的 `revocations`：当前没有任何函数实际处理

### 4.1 精确现状

- `StatusSnapshot.revocations` 是 `Vec<u8>`（`crates/boreas-proto/src/objects.rs:140-145`），
  只受 `MAX_OBJECT_LEN = 16 KiB` 限制；主计划也只说“各类吊销条目的摘要，分页，单对象 <= 16 KiB”
  （`docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md:387`），仓库里**没有条目级 wire format**。
- `status_store::snapshot_from_verified`（`status_store.rs:752-790`）只检查
  `ObjectBody::StatusSnapshot(body)` 的窗口/envelope 一致性，**完全没有读 `body.revocations`**；
  `accept_signed_snapshot` 持久化的是整个 raw envelope，`FreshStatus` 也没有 revocation 方法。
- `revoke_cleanup` 只有 ID 表：`TlsSessionId`/`CircuitId`/`AttachmentLeaseId`/`RoutePrefixId`
  都是“不是 live socket/不是已安装路由”的注释（`revoke_cleanup.rs:18-32`）；
  `apply_verified` 只做 `entries.remove`（`94-97`），没有 shutdown/close/route 删除。
  这些 `record_*`/`apply_verified` 在 daemon 中也没有非测试调用点。
- 当前 watchdog 对任何失败都只做 `shutdown(sock_fd)`（`daemon.rs:1028-1034`），
  不会针对某条 revocation 选择 session/circuit，也不会删路由。

### 4.2 如果要实际 shutdown，缺什么（不能只写“无实现”）

要关闭“签名快照里的 revocation”，至少需要以下真实链路；当前只有第 3 步的底层原语：

1. **条目解码**：定义并实现有界 `revocations` 格式（subject node id、identity generation、
   object kind/scope、sequence/watermark 等）。当前不存在；不能拿任意 bytes 猜。
2. **匹配 live handle**：当前 daemon 只有一条 accepted connection（`run_serve_loop` 在
   `daemon.rs:1104-1121` 只 accept 一次），只有 `E2eCircuit::info().peer`（`e2e.rs:726`）
   可提供对端 `node_id`/`identity_generation`；没有 session/circuit/lease 注册表，无法枚举“全部会话”。
3. **实际断开当前连接**：对匹配的当前连接调用 `libc::shutdown(sock_fd, SHUT_RDWR)`，再
   `PacketPath::close()`（`packet_path.rs:837-842`）丢弃 `E2eCircuit`；后者 drop 时
   `CircuitStream` 会 best-effort 发 `CircuitReset`（`e2e.rs:366-371`）。这是强制路径；
   `E2eCircuit::close_gracefully` 只发 E2E `close_notify`（`e2e.rs:774-776`），不是撤销路径。
4. **路由**：`boreas-tun` 明确“native adapters ... install no routes”（`crates/boreas-tun/src/lib.rs:1-3`），
   `route_audit` 只分类调用者快照、不执行 `ip route`/`iptables`（`route_audit.rs:1-6`）。
   daemon 没有任何 route ownership 记录；`RoutePrefixId` 不是内核路由。删除路由前必须证明
   “本实例安装且属性完全匹配”（主计划 `648` 行），当前没有这个能力。
5. **持久 watermark/tombstone**：现有 store 只持久 raw snapshot/seq/floor；没有“revocation 已应用”
   的高水位或 tombstone 表。若要跨重启不重复/不回退，需要新的 schema 或独立 journal。

因此本 slice **不能**宣称“新合法吊销清理全部会话与路由”。可以做到的是：

- 在 `snapshot_from_verified` 中，对 `body.revocations` 非空且没有 decoder 的情况 **fail-closed**
  （例如返回 `Error::BadStatus`，fault 文案明确 `revocations unsupported`），绝不静默忽略；
- 对当前唯一连接，若将来有 decoder 且匹配 `E2eCircuit::info().peer`，才允许 `shutdown` + `path.close()`；
- 对路由一律报告 `unowned`/未执行，不调用任何删除 syscall，直到有 ownership 表；
- 控制面/诊断输出不得出现 `revoked_all`、`routes_removed` 之类未实现字段。

## 5. 必需的 CLI state binding

当前 daemon 只接受 `--config`/`--material-dir` 等（`daemon_usage()` `daemon.rs:35-39`，解析
`daemon.rs:561-603`），没有 status state 路径或 owner UID。`StatusStore::open` 需要
绝对路径 + `trusted_owner_uid`，且父目录必须由该 UID 拥有、无 group/other 权限
（`status_store.rs:201-250`、`1062-1106`）。下一 slice 必须显式绑定，不能从路径或 `geteuid()`
猜：

```text
boreas daemon serve|connect \
  --config <FILE> --material-dir <DIR> \
  --status-state-file /var/lib/boreas/status.state \
  --status-state-owner-uid 0 \
  ...
```

要求：

- `--status-state-file` 必须是绝对路径、无 `..`、父目录已存在且是 `state_dir` 的 canonical 路径；
  不自动创建父目录，不跟随 symlink；`.lock`/`.staging` 由 store 在相邻位置创建/拒绝。
- `--status-state-owner-uid` 必须显式给出；不允许“默认当前 euid”。若产品固定服务 UID，
  用部署配置/文档固定，但 CLI 仍应能显式核对。
- 在 `start_control_socket` 创建 `state_dir`（`daemon.rs:408-411`）之后、`match mode` 之前打开 store；
  若 `StatusStore::open` 返回 `Busy`/`UnsafePath`/`Unsupported`/`WrongNetwork`，daemon 直接退出，
  **不得回退到仅 `verify_status_freshness_from_roots` 的旧模式**。
- 非 Linux 的 daemon 已经拒绝；`StatusStore` 在非 Linux 返回 `Unsupported`，不要提供内存 fallback。
- `boreas ctl status` 不打开 store；否则会和 daemon 的 `.lock` 冲突（见 §6）。

## 6. Schema 兼容与已有 store lock 冲突

### 6.1 Schema

- 当前状态镜像 magic 是 `BRSS\0\0\0\x01`（`status_store.rs:77-78`），布局固定、无 TLV、无 padding；
  `decode` 拒绝未知 flags、尾部多余字节、`utc_floor < issued`（`status_store.rs:900-973`）。
- **本 slice 不需要改 schema**：`utc_floor`、`seq`、`issued`、`next`、raw envelope 都已存在；
  只需 daemon 接线。保持 v1 可读，避免给已有 `b077538` 状态镜像制造迁移问题。
- 若以后要加 revocation watermark/tombstone 字段：必须提升 magic 版本（例如 `...\x02`），
  新 decoder 显式处理 v1→v2；不能在同一 magic 下追加字段（旧 decoder 会因尾部字节/未知 flag 拒绝，
  新 decoder 也会拒绝旧布局）。这属于独立 schema slice，不应夹在本次接线中。
- 容量：`MAX_STATUS_STATE_BYTES = 64 KiB`（`status_store.rs:82`），
  `MAX_SIGNED_OBJECT_BYTES = MAX_OBJECT_LEN = 16 KiB`；两个 raw envelope + 元数据仍在 64 KiB 内。
  若未来把逐条 revocation 也持久化，需重新核算上限，不能默默截断。

### 6.2 Lock / 路径冲突

- `StatusStore::open` 对 `status.state.lock` 做 `try_lock`；失败直接 `Busy`（`status_store.rs:224-227`），
  没有等待/重试/只读模式。daemon 的 watchdog 若每 500 ms 重新 open，会立即 Busy；
  必须按 §2.1 单 owner。
- `status.state.staging` 若已存在，`reject_staging` 返回 `UnsafePath`（`status_store.rs:1108-1115`）；
  崩溃后不要自动删除，先由运维确认；daemon 应 fail-closed 而不是清理后继续。
- `checked_path` 会逐级拒绝 symlink、非目录、group/other 可写祖先、非 0700/非 owner 的 canonical
  父目录，以及 hardlink/错误 mode 的已有文件（`status_store.rs:1062-1106`、`1173-1190`）。
  `start_control_socket` 的 `create_dir_all` + `chmod 0700`（`daemon.rs:408-411`）不检查 owner/symlink；
  因此必须让 store open 做最终校验，失败即退出。
- 同一进程/同一路径不要同时开 `StatusStore` 和另一个需要该锁的组件；`network_policy_store` 等
  使用各自的相邻锁文件，文件名不同则不冲突，但不要共用同一个 state path。
- 已有 CI 记录 `b077538` 的 Ubuntu Rust job 有一个 supervisor durable-budget 测试报
  “unexpected store lock”（[Ubuntu job 132727090305](https://github.com/Lanlan13-14/Boreas/actions/runs/43686202443/job/132727090305)）；同 SHA 的 [TLS job 132727090180](https://github.com/Lanlan13-14/Boreas/actions/runs/43686202466/job/132727090180) 通过
  12 个 status-store 测试。该失败发生在 supervisor 的 store lock 生命周期，不是 `StatusStore`
  本身；但说明锁/继承类测试在 CI 上确实敏感，新增 daemon 测试不要用同一临时路径并发 open，
  也不要用 sleep/重试掩盖 `Busy`。

## 7. negativeActions tests（负向动作测试）

以下测试名是下一 slice 的建议落点；本轮不新增/不运行。能在现有模块内做的用注入的
`trusted_utc_us` + `mono_now`，不要依赖真实 sleep/系统时钟。表内“必须断言”即 negative action。

| 建议测试名（位置） | 必须断言 |
|---|---|
| `daemon::watchdog_tests::status_gate_blocks_before_accept_when_expired` | 过期 snapshot 时 gate 返回 Err；不进入 `listener.accept()`，不建立 TCP/TLS 会话 |
| `daemon::watchdog_tests::status_gate_rechecks_after_handshake_before_business` | t0 通过；握手期间推进到 `next_update` 后第二次 gate 失败；不调用 `drive_packet_path`，不发业务包 |
| `daemon::watchdog_tests::watchdog_first_check_is_immediate` | store 中 snapshot 已过期且 interval=1h；启动后 100 ms 内出现 fault / `status_fresh=false`（当前 `watchdog_drop_joins_promptly_without_fault` 证明旧实现不会首检） |
| `daemon::watchdog_tests::second_store_open_is_busy_and_never_retried` | 同一路径第二次 `StatusStore::open` 返回 `Busy`；watchdog 不重开、不 sleep 重试、不创建第二个 `.lock` |
| `daemon::watchdog_tests::duplicate_old_snapshot_does_not_extend_business` | seq 1 在原始 deadline 后重复投递仍 `DuplicateNotRenewed`，gate 失败；不刷新 `runtime_deadline` |
| `daemon::watchdog_tests::clock_rollback_latch_survives_restart_and_gate_stays_closed` | 重开 store 后 `is_clock_latched()` 仍 true；gate 返回 `ClockRollback`；没有人为 `recover` 就不得放行 |
| `daemon::watchdog_tests::nonempty_revocations_without_decoder_fail_closed` | `revocations` 非空且无 decoder 时 gate 失败/daemon 退出；控制面不出现 `revoked_all`/`routes_removed`；不静默继续业务 |
| `daemon::watchdog_tests::unowned_route_is_not_deleted` | 无 ownership 记录时结果为 `Unowned`/未执行；不调用 route delete，不把 `RoutePrefixId` 当内核路由 |
| `boreas_pki::status_store::tests::rejects_unsafe_paths_modes_sizes_and_staging`（已有，`status_store.rs:1622`） | symlink/错误 owner/mode/hardlink/`.staging` 均 `UnsafePath`，不自动修复 |
| `boreas_pki::status_store::tests::persist_failure_poisons_and_reopen_uses_last_durable_state`（已有，`1530`） | 提交失败后 poisoned，不能继续 mutate，不能报成功 |
| `revoke_cleanup::tests::unverified_revocation_is_refused_and_does_not_disconnect`（已有，`revoke_cleanup.rs:174`） | 未验证 revocation 不删除表项、不 disconnect；普通 core 不能借 revocation 断他人 |

真实 CLI/E2E 的负向场景（Actions only，不建议本机）：

- 使用真实签名 `status.signed` fixture，在握手前/后注入过期（通过可控的 `now_us` gate 单测覆盖，
  不要用 sleep 拖真实握手）；
- 启动时 `status.signed` 缺失/过期/低 seq/错误网络/坏签名，daemon 必须非零退出且不输出
  `"status":"ok"`；现有 `crates/boreas-cli/tests/daemon_pki_e2e.rs:373-378` 已断言过期 fail-closed，
  新 slice 应扩展为 store `Busy`/`UnsafePath`/低 seq 也非零退出；
- 状态文件在 watchdog 运行中被删除/截断/替换为低 seq，必须 fault 并关闭当前 socket，而不是继续转发。

## 8. 不能宣称 / 非目标

本 slice 完成后仍然**不是**完整 `G-REVOKE`：

- 不实现每包 `FreshStatus::check` 的 `BusinessGate`；packet loop 仍只看 watchdog fault；
- 不实现多会话/多电路注册表，serve 仍只 accept 一条连接（`daemon.rs:1104-1121`）；
- 不实现 `revocations` 的 wire format、解析、tombstone/水位或跨重启应用；
- 不实现 TUN route ownership/删除；`boreas-tun` 适配器不安装路由（`lib.rs:1-3`），
  `route_audit` 只读（`route_audit.rs:1-6`）；
- 不实现 roots/status signer 热轮换（store trust 在 open 时固定，轮换需重启或独立 slice）；
- 不解决整盘镜像回滚/外部 monotonic anchor；store 文档已明确该边界（`status_store.rs:46-49`）；
- 不产生任何 CI/门禁证据；所有新测试仍需在 Actions 的精确 SHA 上运行。
