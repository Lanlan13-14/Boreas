# P04/P05 双节点 NodeRuntime 纵切合同

## 实际下一 slice：接入 supervisor ready-client（CI pending）

**范围：仅 Linux `daemon serve` 首个可用 readiness 汇报；本 slice 不改 Rust。** CI 仍 pending，不能声称 API 已接入或已验证。依据：`daemon.rs` 在 `run_mode` 中已先验证 config/roots/material、创建真实 TUN（或显式 `--virtual-tun`）、启动 `state_dir/control.sock`；`run_serve_loop` 随后解析并 bind TCP listener、设为 nonblocking，再等待连接、做 TLS/WSS/hop/E2E。`ready_client::report_ready(path, schema, workers, tun)` 只把调用者提供的三个值作为断言，经 supervisor Unix socket challenge-response 写出；源码明确不证明 artifact identity/facts。API Linux 验证 supervisor 同 UID、socket UID/type/mode 0600、challenge/nonce 格式及 bounded exchange；非 Linux 返回 `Unsupported`。nonce 仅防协议重放/配对，不是 artifact proof。

### 最小可实现运行路径

1. supervisor 在启动 daemon 时传入 readiness socket 的**唯一来源**：例如专用 `--ready-socket <PATH>`（优先于环境变量，避免环境继承歧义）；若部署只支持环境，则约定 `BOREAS_READY_SOCKET`，缺失/空值视为该次受管启动配置错误。此路径仅定位 socket，不得从它推导 readiness 值。daemon 原有 `--config`、`--material-dir`、serve 必需 `--listen` 保持原样；不添加可任意指定 schema/workers/TUN status 的 CLI 参数。
2. daemon 完成既有 trust/config 检查、实际创建 TUN、成功启动 `control.sock`，并在 `run_serve_loop` 成功 `TcpListener::bind` + nonblocking 设置之后，调用一次 `report_ready`；此处是 listener 真正可接受连接的点、但尚未阻塞等待 peer。只在 `serve` 走此调用；`connect` 的 ready 时机需另行定义，不伪称本 slice 覆盖。`TunStatus::Ready` 仅在真实 `LinuxTunDevice` 成功创建时报告；显式 `--virtual-tun` 必须拒绝该 production-ready 路径（或未来使用 supervisor 明确接受的不同策略），不能把 VirtualTun 报为 Ready。control socket 只有创建、权限设置及 listener thread spawn 全成功才可继续。
3. `schema` 不来自 daemon CLI/env。由 daemon 侧编译常量/固定版本映射（与实际 state writer/schema 实现绑定），supervisor 对同一 daemon rollout 配置自己的精确 expected schema；未知版本 fail closed。现在 `daemon.rs` 的 `ctl.status` JSON 字段不是此 API 的 state-schema 证明，不能凭 JSON 临时猜 schema。若部署尚无真实 schema 常量/写入实现，则先不发 ready，或把集成保持关闭，不能用可由任意调用者选择的字符串冒充。
4. `workers` 使用代码中实际已启动且由 runtime 管理的线程数，并在 supervisor 侧按该固定运行拓扑配置 expected count；不得接受用户任意 `--workers`。当前此 readiness 点已有 control-socket accept thread；serve 的 packet loop 在主线程，StatusWatchdog 要到连接/E2E 成功进入 `drive_packet_path` 才启动。因此最小合同可把 workers 定义为“启动 readiness 时 daemon-owned background worker 数”，报告实际计数 1；若要把 watchdog 算入，必须把 readiness 点移到 watchdog 启动之后并相应改变“listenerready”时序/监督语义。不要将系统总线程数当成稳定指标。
5. supervisor 的 expected 值独立于 daemon 报告：由 supervisor 自己的受控 unit/launch 配置固定 socket path、允许的 schema 值、worker count 和所需 TUN 状态；部署 rollout 同步更新 schema allowlist。API 参数来自 daemon 的可信执行路径/已建资源状态，不是接受外部输入的“事实”。监督端仍须把响应与受信任的启动记录关联；challenge nonce 不绑定二进制、发布签名或 hash，不能称为 artifact attestation。

### 失败与平台合同

上述任何 prerequisites、socket 定位/权限/peer credential、challenge、写回、schema/worker 本地不变量、bind/listener 或 TUN/control 初始化失败：启动返回错误并退出非零；不得继续 accept/forward，也不得输出 ready。report_ready 失败是 fail-closed startup failure，而不是 warning/retry 后假 ready。`--virtual-tun` 只用于明确的非 production 测试，supervisor 不应将它接纳为 real-TUN ready。无 `openssl-inner-tls` 的现有 fail-closed 行为保留。非 Linux 的 daemon 既有 Unsupported 错误保留；ready-client 自身也返回 `ReadyClientError::Unsupported`，不降级成跳过上报或成功。当前 client connect 本身没有可移植连接超时保证，不能宣称整个交换严格有总时限。

**实现顺序建议：**先确定并由 supervisor 固定 schema + worker 语义/期望值，再将依赖接入 CLI 的 ready-client 调用放在真实 listener bind 成功之后；任何尚未能由 runtime 资源/编译身份决定的字段都暂不报告。此建议避免任意 schema CLI、假 TUN-ready 和“随机 nonce = artifact proof”。

状态：历史设计基线（保留当时规划/缺口描述；不应视为当前实现清单）。当前 `crates/boreas-cli/src/daemon.rs` 已包含 Linux daemon 的 TCP→TLS/WSS→pq768 hop session→pq768 E2E→PacketPath 纵切；本次窄增量仅在初始 TCP 阶段允许 primary 被明确拒绝/超时后尝试配置 backup。两个端点共享已验证的单一 `peer.signed` / `remote_peer`，每个 endpoint 分别派生 TLS name 与 WS Host；显式 `--connect` 禁用隐式 backup，显式 `--tls-name` / `--ws-host` 继续覆盖。握手、身份/session、E2E、状态或任何非 TCP refused/timeout 失败均不 fallback；不会重连，不支持不同 Core 身份。若 backup 指向不同 Core，同身份验证将失败并停止。该行为不是多 Core、高可用/漫游或生产可部署声明。本文后续章节的历史缺口需结合代码复核；未完成的持久信任/业务 gate/生命周期/路由/确认等生产边界仍然成立。DNS解析沿用现有阻塞实现，不承诺严格总截止时间。

## 1. 安全成功条件

1. 只有经独立可信渠道配置的 `NetworkRoot` 与独立 `ReleaseRoot` 公钥才可启动。Provisioning 包必须有版本/长度/规范编码，分别含网络 genesis/NetworkRoot trust chain 与 ReleaseRoot trust anchor；校验器/二进制来源及指纹渠道独立于包下载。ReleaseRoot 只用于软件发布，不可注入管理对象 `ManagementTrust`。
2. 本地节点身份私钥由节点本机 OS CSPRNG 独立生成、私钥不可复制；持久化 key store/CSR before request；初始最小纵切可仅接受离线签发证书/已签名 `NodeIdentity` 和 TLS leaf/key 的受控导入，但导入需校验本地公钥与签发身份绑定。不得靠配置复制克隆节点，不得 TOFU。启动时角色/永久 NodeID/VIP/generation 以签名身份为准；配置中的声明仅用于一致性校验。
3. 启动材料完整验证后才打开业务 listener/TUN：签发权用途/scope → 管理对象双签名 AND（对原始字节）→ 网络、对象类型、角色、scope、有效期、代次/单调序号/吊销/等价冲突 → TLS 证书链/ML-DSA及 leaf-SPKI 到当前签名 NodeIdentity 绑定。任何材料缺少、陈旧、回滚、冲突、未知 critical、持久化失败、feature/backend 不可用、TUN/监听失败均启动失败，不能产生“部分成功”业务能力。
4. 认证对象/会话/状态快照是 runtime 业务许可唯一来源；不接受 `registered: bool`、`verified: bool`、caller ID map、caller 的 `WriterProof` 或调用者声称已授权。业务建立与每包转发须受持久新鲜度 latch 约束。复播同一旧签名快照不得更新寿命。状态快照 `next_update` 失鲜、可信时钟不可用、观测 UTC 比持久 `last_trusted_utc_us` 回拨超过容差时，停止新旧业务、关闭已有真实业务资源；仅可保留明确限权的管理/状态恢复通道。
5. 完整应用流必须是 `Config -> validated bootstrap -> real TCP -> verified outer TLS/WSS -> verified hybrid pq768 hop TLS -> SessionHello/Accept -> authorized circuit -> E2E TLS -> encrypted application confirmation -> packet parse/source+dest policy -> PacketIo write`。中间转发节点只有盲转 E2E 密文权限。任一步失败则丢弃业务/Reset/关闭；绝不改送 HopIpBatch/hop-only。首纵切 E2E app confirmation 尚未实现，完成前不得送 IP 业务。
6. 节点拥有实际 session、E2E circuit、lease 和实例 owned route 句柄。撤权必须先持久化经过验证的水位、原始证据及状态，再阻止 admission、关闭真实 TLS/session/circuit、撤销真实 lease，并仅撤销由此 runtime 实例拥有的路由；所有失败保持业务停止并可恢复，不可先清纯 ID 集合后称撤权完成。route/lease API 未具备则该能力关闭，不以模拟对象替代。
7. 关闭时先闩锁 Draining 阻止创建，再停止 PacketIo poll/读写、业务队列与 listener admission，发送有限时间的协议 close/reset，close 所有 TLS/WSS/socket/circuit/lease/TUN/owned-route 句柄并 join worker；超时强制关闭连接资源，最后持久化 shutdown 状态并报告失败。TLS 密钥不继承升级、不序列化恢复。

## 2. 可复用现有边界和实际缺口

- `boreas-tunnel::runtime::{LinkClient,LinkServer}` 提供 blocking TCP→outer TLS→h1 WebSocket→hop inner TLS→SessionHello/Accept；Server admission 在 outer TLS 前预留握手及应用缓冲额度。预算并未覆盖 TLS/OpenSSL、证书解析、内核 socket/thread 栈。`runtime_capabilities()` 只报告编译事实，明确 daemon/control_socket=false。
- `tls::{OuterTlsConnector,InnerTlsConnector,InnerTlsAcceptor}` 与 `openssl_inner_tls::{OpenSslOuterTlsConnector, OpenSslOuterTlsAcceptor, OpenSslInnerConnector, OpenSslInnerAcceptor}` 是 TLS adapter seam。`PkiIdentityExtractor` 目前基于已验证 `VerifiedObject` 的身份公钥 SPKI 表做 exact leaf match；该输入表必须由完整可持久化信任链构造，而不是 caller 数据。外层 connector 可用 Web PKI；它不替代内层 peer 授权。
- `session::SessionPolicy` 结构含 `identity_registered: bool`，设计上要求调用者已认证身份。不能将它视作 runtime 权限凭据；需要以不可构造/不可伪造的 verified identity+status capability 代替或在唯一 runtime boundary 私有构造，且任何 session continuation 再检 status epoch。
- `e2e::{open_e2e,accept_e2e}` + `E2eTlsBackend` + feature-gated `OpenSslE2eBackend` 能在 `CircuitStream` 上运行真实 E2E TLS 和产生 `VerifiedE2eSession`；E2E adapter 目前只验证 TLS peer/suite，不完成主计划 §7 的加密应用确认。其 circuit stream 借用单个 `EstablishedSession`，当前 circuit-per-hop-session 上限为一个。
- `resource::Admission` RAII 只统计连接数及应用缓冲。`relay::RelayTable` 可共享 Admission/限制 circuit 生命周期，但目前不是全运行时所有对象的单一全局字节账本。TLS、WebSocket/h2、thread/stack、TLS临时、PacketIo queues 等仍需联合预算和真实资源测量。
- `boreas-tun::{PacketIo,VirtualTun,inspect_packet}` 可直接作真实数据面 API；Linux `LinuxTunDevice::create` 返回设备 manager 与 `LinuxTunQueue`，适配器不装路由。`dataplane::HopTun` 是单元内存模拟，不可进入纵切。P05 第一切片应直接由 PacketIo poll/read_packet/write_packet 实现；不声称 `VirtualTun` 是 LinuxTun 设备证据。
- `boreas-pki::management::ManagementTrust::verify_and_authorize(raw, now_us)` 做真实双签和权限检查，但信任 issuer records 是带外输入，不校验 NetworkRoot/RootAuthorization 链，replay table 进程内，equivocation 持久证据需 runtime 调用者落盘。`enforcement::forwarding_decision` 只给 decision，不关连接。`revoke_cleanup::CleanupTable` 仅清 ID，不会关 socket/circuit/route。
- CLI 的 `Config` parser 检查 TOML、权限/path/capability，不读 anchor/key/state，不建立 TLS/TUN。CLI 当前 `RuntimeCapabilities::NO_RUNTIME`；实际运行时 capabilities 不可从静态配置/编译 feature 假报 daemon/control socket 已有。

## 3. 纵切启动事务与接口

以下类型/API 是建议的单一后续接口合同，不代表其已存在。不要另做一套协议或 HopTun。

### 3.1 Bootstrap / 持久状态

持久化接口尚未分配实现。本阶段不新增 bootstrap/store crate；待 RootAuthorization verifier 评审后，复用并评估现有 `boreas-pki::enrollment::EnrollmentStore` 与 `boreas-crypto::key_store`，据此定义最小持久化接口。

不在本合同中先造一组泛化 store trait。后续存储任务先检查现有 `EnrollmentStore`、journal 与 `boreas-crypto::key_store`，再确定最小增量 API。无论 API 如何定：验证器必须构造私有字段能力值，不用 public fields / bool assertion；路径需拒链接、检查 owner/mode、bounded read、私有原子写+fsync file/dir；存储回滚不可检测或无法原子提交即拒业务启动。密钥由零化/安全 store 管理，错误/Debug/log 不泄露 bytes/path/PEM/private key。

验证顺序：
1. 先读受限配置并验证 config 文件 owner/mode/symlink、大小、路径绝对、网络与身份声明一致；请求能力只能关闭，不能从配置开启未实现功能。
2. 从信任 bootstrap store 解包 anchors/genesis；双根用途隔离并验证 RootAuthorization/Issuer certificate chain、撤销/根轮换、有效期、scope、算法与版本。
3. 从 OS key store 加载本地 node key handle；验证 leaf certificate 的链、用途、时间、ML-DSA、公开 key 与本地私钥 match，并和双签 NodeIdentity 的 net/role/id/vip/generation/SPKI 对齐。不要把 CSR 注册/事务期的候选实现当作 TLS certificate issuance 已集成。
4. 加载并按 issuer 权限先行，双签 AND 后验的规则逐个验身份/lease/status/revocation/必要 grant；对每对象保留 exact signed envelope，提交 replay watermarks、equivocation 双证据、trusted UTC floor、snapshot sequence 与状态于 durable transaction。时间值为签名 UTC unix_us；超期/回拨先进入 ClockHold。
5. 只有上述 commit 完成才建立不可伪造 `RuntimeTrustSnapshot`，配置 strict TLS adapters/policies，创建全局 Admission/credit ledger，再开 management endpoint/listener/PacketIo。任何后续初始化出错按 reverse-order drop，业务不可达。

### 3.2 连接、授权与 E2E

Need replace `SessionPolicy.identity_registered` injection pattern with runtime-only constructor e.g. `AuthorizedPeer::from_verified_identity_and_fresh_status(...)` whose fields are private, binding complete peer identity/generation/net/role, allowed object scope, status_epoch, verified UTC validity. LinkClient/server acceptance checks current status epoch again immediately after handshake and immediately before activating session; `PeerIdentityExtractor` should query a durable/current verified snapshot rather than a static stale vector. Server handshake admission credit + byte credit must remain alive with actual session. Cap TLS backend/parser handshake concurrency separately before allocation.

TWO-node first milestone uses one client-to-Core WSS connection. Server outer connection is actual TCP listener behind a TLS origin endpoint; Edge uses `ClientTarget`. LinkClient/server produce one authentic hop session, with strict TLS 1.3 hybrid X25519MLKEM768, ML-DSA cert, no resumption/0-RTT, role/network/gen exact match. Then origin is destination or direct transit target only in its authorized topology. To carry IP at destination: `open_e2e` / `accept_e2e`, run `OpenSslE2eBackend`, check fresh verified destination identity generation, then both sides exchange a new typed encrypted `E2eApplicationConfirmation` binding net_id, src/dst node ids+generations, actual circuit_id, security mode, required capabilities, negotiated suite/policy and freshness epoch; both must confirm before any PacketIo read/write is allowed. Current proto typed body and E2E API are missing; do not invent ad-hoc control encoding in NodeRuntime.

Missing interfaces to report before existing consumer edits:
- typed proto `E2eApplicationConfirmation` encode/decode + expected state transition; tests including peer/circuit/gen/net/mode/capability mismatch.
- secure circuit owner that multiplexes source/destination endpoints and retains both hop and E2E closures; current `E2eCircuit<'a>` borrow shape means tunnel worker needs dedicated ownership architecture. Do not hide it behind leaked/static lifetime or double session table.
- packet policy capability: authenticated source `NodeRef` -> verified current allowed_lpm/ACL and destination check. First two endpoints can limit to signed permanent VIP-to-VIP only; no subnet route until accepted `RouteGrant` + local allowlist + owned route API exist. `inspect_packet` checks structure/checksum but is not authorization.
- single runtime-wide global byte credits with RAII attached to queues, TLS/session/circuit ownership; admission before resource allocation, bounded queues and IO cancellation. Existing Admission can start the connection count portion only.
- `PacketIo` blocking/poll contract/cancellation: actual Linux queue reads can block; shutdown/revocation must interrupt owner (nonblocking/poll fd or close wakeup). `VirtualTun` does not provide a realistic async poller. Define a single-owner poll loop, deterministic backpressure and queue credits.

### 3.3 Authoritative business gate and revocation

A single `BusinessGate` owns status state + immutable/current `status_epoch` and acts at resource creation AND every packet I/O boundary. It accepts only `FreshStatus` created after durable verified commit. No caller-supplied bool, timestamp-only `FreshStatus`, or simple atomic flag disconnected from persistence. On accepted revocation: serialize with business admission, persist the signed object + replay high-water + tombstone/equivocation data first, latch new admissions off, remove/close every actual matching epoch-bound session/circuit/lease and owned route handle; route rollback errors remain reported and gate remains off. Stale status/clock rollback closes all business handles; restricted sync/management handles must be tagged `RecoveryControl` and never carry packet bytes or use ordinary peer policy. On successful validated fresh status plus durable clock recovery, explicit reviewed state transition may reopen. A corrupt journal or failed disk commit never opens the gate.

No lifecycle primitive is delivered in this slice. Design constraints for a later owner implementation: freshness reopen must require a non-forgeable durable `FreshStatus` capability and may not clear a clock hold without an explicit trusted-time recovery proof; resource and revoked-epoch tables must have hard bounds and durable revocation watermarks; rejected registration must explicitly close/consume its actual handle; stale/revocation/admission must linearize without allowing fresh re-admission to race a detached old resource close; close callbacks must not block while holding a global lock, and all close failures must be surfaced while the gate remains closed. Any later owner must be an exported, compiled module checked under Actions and include concurrency/restart/race tests. Until then, P04 implementation remains absent.

### 3.4 Management endpoint / snapshot

P04 management socket is a separate listener with OS peer credentials on both ends, strict versioned request/response schema, per-message/connection size and timeout caps, constant/allowlisted command registry, and read-only default. Unix socket file mode 0600 plus `SO_PEERCRED` (or equivalent) on accepted connection; validate expected uid on every connection, ensure socket path parent cannot be attacker-replaced, do not unlink arbitrary files at startup. Windows named pipe ACL and caller PID/SID check; macOS endpoint credential/entitlement checks separately reviewed. Non-Unix must refuse unsupported endpoint instead of silently creating unauthenticated TCP socket.

Snapshot schema must be typed/versioned and generated from runtime owner: lifecycle state, same-source capability facts, security mode, trusted status freshness/expiry/clock hold, TLS backend/negotiated facts (actual, not inferred), peer/circuit counts, packet bytes/drops/MTU, resource counters, last bounded error codes. No private key, raw identity/management material, secret config paths, endpoint secrets, packet payload or arbitrary peer-controlled strings. All displayed names/log codes reject control/newline/terminal escape and are length-limited. Secret/path fields are redacted before serialization. Danger actions carry authenticated command, explicit operator confirmation where needed, persisted audit transaction, and actual apply result; success response only after actual operation commits.

Capabilities must come from the concrete constructed runtime and be impossible to claim when no service is bound. Represent separate static backend support (linked strict backend) and runtime integration/ready facts (listeners bound, trust loaded, TUN opened, management endpoint active, actual E2E confirmation code present). Until all mandatory P04/P05 dependencies land, CLI capabilities remain NO_RUNTIME / daemon not ready; exporting this module alone does not alter product claims.

## 4. Error / cancellation / shutdown requirements

Use typed errors with stage only (Config, Provisioning, RootChain, ObjectAuthorization, Freshness, DurableCommit, OuterTls, WebSocketUpgrade, HopTls, SessionAuthorization, Circuit, E2eTls, E2eConfirmation, PacketParse, SourceAuthorization, DestinationAuthorization, PacketIo, ManagementAuth, Shutdown). Do not expose OpenSSL stack, secret paths, PEM, private keys, raw object data or arbitrary peer text to peer/UI. Remote peers receive protocol alert/reset/close, local operator gets stable error code and redacted context; audit stores exact signed bytes only in protected evidence storage.

Every started background worker has a cancellation token/wakeup, owned JoinHandle and first error slot. Errors propagate to coordinator; downstream frame/packet parse/protocol mismatch poison the stream/circuit, release credits and close resources. Partial startup unwinds reverse ownership order. Shutdown is idempotent; first close request transitions to Draining; no new business accepted; drain has monotonic deadline; always force-close on deadline, join workers, clear OS-owned route only for exact instance, close PacketIo; persist final state last and return aggregate typed errors. Do not hold global owner mutex while waiting for blocking I/O or thread join.

## 5. Implementation/dependency order (do not parallelize consumers ahead of interfaces)

1. **P00/P01 baseline:** finish merge/Actions baseline; reconcile candidate schemas/Lease limit, root/RootAuthorization byte contract, NodeIdentity Ed public-key binding/OID and trusted clock API. No daemon code can trust provisioned issuer records until root-authorized issuer input is real.
2. **L0 root-authorized issuer capability:** exact three files in §6; if no existing proto RootAuthorization definition can carry the documented candidate exactly, stop and request a separately assigned proto/schema slice. Do not implement dependent consumers in parallel.
3. **P03 durable state:** inspect existing enrollment journal/key-store APIs; narrow exact-byte RootAuthorization/replay/equivocation/root-version/trusted UTC watermark persistence and restart re-verification; then local key generation and identity/status state in separately approved slices. No new generic store crate.
4. **P02 backend/auth API:** strict outer+h1 WSS and hop TLS runtime integration, real peer extraction and full cert↔signed identity binding, no bool registration input, prove pq768 actual negotiated facts. Keep h2/CDN out of first slice.
5. **P04 NodeRuntime skeleton:** consume reviewed config parser/library; preflight/startup transaction and bounded resource ownership; strict errors/readiness/cancel/shutdown; Unix peer-credential management snapshot; actual capabilities from constructed services. Begin only after durable-trust and resource-closure APIs are agreed.
5. **P05 PAIRED endpoints:** real packet reader and safe packet parser/authorized VIP checks; typed E2E confirmation; single-hop session/circuit owner; Global Admission+credit; actual VirtualTun-to-VirtualTun packet integration over E2E encrypted stream. Only after this works implement LinuxTun one queue with actual route/device ownership (the current Linux adapter alone does not install routes); collect packet hashes/bytes and real failure/reset/drop evidence. No HopTun helper.
6. **Then broader P04/P05:** CLI daemon/config integration, service/system readiness, OS control endpoints and privileged bootstrap; DNS/smoltcp, owned route APIs, multi-queue/GSO, h2/CDN, multihop, subnet routes and scale each in separate slices. Actions exact commit after each slice; gates stay open pending genuine evidence and external review.

## 6. Historical implementation requirements, in dependency order

### L0 — RootAuthorization verifier first dependency (P01/P03)

This package is explicitly **not** a daemon/bootstrap store implementation. It closes one trust boundary for future P03/P04 consumers: externally pinned NetworkRoot public key + root-signed candidate RootAuthorization bytes → a private verified issuer-authorization capability → safe conversion to the existing `management::IssuerRecord`. It does not validate a genesis/root certificate chain (the independent NetworkRoot pin is a provisioning input), implement durable store/replay/clock state, verify node certificates, launch transport, accept sessions, validate freshness/revocation, connect TUN, or implement ReleaseRoot software verification. Never treat an arbitrary caller-created `IssuerRecord` or boolean as verified.

**Proposed code and specification boundaries:**
1. New `crates/boreas-pki/src/root_authorization.rs`: feature-gated alongside `management` (`openssl-backend`) and implement real Ed25519 + ML-DSA AND verification over the candidate's exact canonical signed bytes. The only trust origin is an explicit NetworkRoot public-key pin passed as typed input through a constructor that checks algorithm, key id, generation, and key material; the verifier must never bootstrap trust from the object being verified. Validate expected network, object type/purpose, signer identity+generation, time window from explicit trusted UTC input, sequence/version monotonicity within the supplied verified chain, child key types/lengths, child authority role and object-type allowlist, and scope no broader than its parent. Reject any ReleaseRoot-as-network-issuer and any NetworkRoot/child role confusion. Return `VerifiedIssuerAuthorization` with private fields and an accessor/consuming method that creates existing `management::IssuerRecord` only after successful verification; do not refactor or widen existing `ManagementTrust` in this task. Keep error messages coarse and never format raw key/object bytes.
2. New `docs/protocol/root-authorization-candidate-v1.md`: document the *candidate* wire shape, signed-byte domain/canonical encoding, root pin input assumptions, role/object/scope delegation table, validity/sequence and root rotation limits, exact open design questions, and fixed valid/invalid examples. Explicitly label non-frozen/proposed; do not claim RFC status or production readiness.
3. Existing `crates/boreas-pki/src/lib.rs`: only the necessary conditional module export (`#[cfg(feature="openssl-backend")] pub mod root_authorization;`) plus matching docs. No other existing files changed.

**Repository evidence and schema constraint:** inspected `crates/boreas-proto/src/objects.rs` currently defines only six ObjectType/ObjectBody variants (NodeIdentity, AttachmentLease, CoreLsa, RouteGrant, DirectGrant, StatusSnapshot); there is currently no `RootAuthorization`, `Genesis`, or RootAuthorization decoder there. This proposed verifier uses `root_authorization.rs`, `root-authorization-candidate-v1.md`, and the PKI `lib.rs` export; it must not assume that a nonexistent proto variant can be reused. Before writing, inspect `docs/protocol/management-objects-v1.md`, its schema JSON/ADR and existing `management.rs` signature input. Candidate document must make a precise proposal that is byte-testable without calling it frozen; verifier should reuse existing `boreas_proto::objects::signature_input` / `boreas_proto::messages::SignedObject` where their canonical constraints fit. Since the current proto object schema has no RootAuthorization variant, use an already-defined candidate encoding to verify exact raw bytes, or define the proto/schema separately before implementing the verifier. Do not introduce a competing production wire format. Current `ManagementTrust` explicitly treats `IssuerRecord` as out-of-band trust; its replay/equivocation table is process-local and it does not validate RootAuthorization chains.

**Verification matrix (Actions only):** valid pin+valid dual-signed IdentityAuthority child yields capability/IssuerRecord; wrong pin/network/type/key id/generation/role/use fails; ReleaseRoot cross-use fails; one invalid/missing Ed25519 or ML-DSA fails; mutated raw TBS and noncanonical/oversized object fail; expired/future window and stale sequence/root version fail; child trying to widen roles/object types/home cores/prefix scope fails; duplicate/rebound issuer keys and same slot+seq distinct valid bytes fail closed. Include exact deterministic positive/negative vectors in the candidate doc/tests. Compilation, tests and formatting belong in Actions; a design requirement is not gate evidence.

**Next after L0, not part of L0:** use only `VerifiedIssuerAuthorization` outputs as provisioned inputs to `ManagementTrust`; separately implement durable protected store for exact signed root/authorization envelopes, persistent replay/equivocation watermarks and trusted UTC floor before opening runtime. Do not create a new bootstrap/store crate or generic storage framework for this next increment: first inspect existing PKI enrollment journal/key-store abstractions and define a narrow state adapter/API within the existing PKI boundaries. Durable persistence must commit exact bytes + monotonic watermarks before consumer admission; verification capability must be constructed from the persisted verified chain on restart, not carried as an unsigned cached `IssuerRecord`.


### L1 — narrow durable trust state (P03; after RootAuthorization review)
- First inspect existing EnrollmentStore/journal/key-store APIs and report reuse boundaries; do not add a generic new crate/storage abstraction. Implement only an explicitly assigned narrow adapter persisting exact RootAuthorization/issuer bytes and verified replay/equivocation/root-version/trusted-UTC watermarks, with atomic bounded write and restart re-verification against the independently provisioned root pin. No caller bool, no ephemeral replay only.
- Inject crash/write-failure, disk-full, file/dir fsync, root-version rollback, bad signature, duplicate slot/equivocation persistence, symlink/unsafe mode/size, restart from stale backup. Windows durability stays unavailable/fail-closed until directory-entry durability is met. StatusSnapshot freshness/revocation application and local node key generation remain separately scoped work.

### L2 — actual trust to transport capability (P02/P03)
- Replace bool/static-vector caller seam with verified current trust capability; ensure all TLS sessions are certificate-extracted against current durable NodeIdentity and revocation state. Construct actual strict OpenSSL outer+hop adapters only on reviewed backend build; charge preauth/TLS budgets and owner. CLI not yet.
- Test negative roots, unregistered/mismatched peer, generation, role/scope, stale/expired/revoked, classical downgrade, resumed, 0-RTT, outer hostname, certificate SAN/chain, backend absent; capture negotiated parameters.

### L3 — NodeRuntime process/control lifecycle (P04)
- Implement an exported and compiled NodeRuntime module only after P03 bootstrap capability and actual resource-close APIs exist; compose trusted config/bootstrap/TLS/listener, fail-closed startup/unwind/stop, readiness/status source. Add Unix management socket peer uid and fixed snapshot schema; keep capability false unless actual integrated components. No fake command success.
- Add two-process start/stop, bad material prevents bind/TUN, process death/cancellation/timeouts, local credential denial, snapshot redaction/injection, worker join/resource count, shutdown order. Platform-specific native endpoint remains separate.

### L4 — two-node real packet path (P05+P07 prerequisite)
- Add typed E2E application confirmation and owned session/circuit bundle; run real two endpoint runtime with actual outer TLS/WSS, hop pq768 mTLS, E2E TLS, PacketIo VirtualTun. Gate PacketIo on durable FreshStatus and confirmation, parse packet using `boreas_tun::inspect_packet`, authorize source/dest exact VIP and generation, allow no routes by default, no hop-only path.
- Add positive packet transfer plus negative no/expired/rollback status, revocation while idle/active, wrong IP source/destination, malformed/checksum/MTU, E2E failure/no confirm/wrong circuit/gen, hop/link reset, budget saturation, close. Hash only packet payload delivered by actual PacketIo endpoints; never use `dataplane::HopTun`.

### L5 — real Linux TUN attach (P05)
- Adapt actual `LinuxTunDevice`/queue with one queue, offload disabled, instance-owned route integration only after API exists, no host route replacement, permissions/privilege ordering/reopen tests. Linux CI runner evidence; hardware/network integration remains environment evidence. Keep Windows/macOS false until their own adapters run.

## 7. Scope and evidence status

- This change adds only this design contract; no runtime source, proto schema, storage layer, CLI integration or exported implementation is delivered.
- The proposed APIs, schemas, tests and implementation steps above are historical design requirements, not verification of any current commit or change to the gate ledger.
