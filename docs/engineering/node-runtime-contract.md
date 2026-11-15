# P04/P05 双节点 NodeRuntime 纵切合同

状态：仅为设计合同；本次没有新增任何 runtime 源文件/原语，也不是 daemon 已实现/可部署声明。本文按读取时工作树制定，合并后必须复查引用和冲突。合同目标是 P04/P05 最小纵切：离线受控预配的两个真实节点、单条 HTTP/1.1 WSS 路径、逐跳 TLS 1.3、强制 E2E、真实 `boreas_tun::PacketIo`（首先 VirtualTun，再 LinuxTun）、认证/状态失鲜即关闭。暂不扩展多 Core、CDN/h2、漫游/故障切换、子网路由、DNS、系统路由、热更新或生产能力声明。

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

持久化接口尚未分配实现。本阶段不新增 bootstrap/store crate；待 RootAuthorization verifier 评审后，先盘点现有 `boreas-pki::enrollment::EnrollmentStore` 与 `boreas-crypto::key_store`，由主代理指定窄接口及文件范围。

```rust
trait ProvisioningVerifier { fn verify_package(&self, exact_bytes: &[u8], out_of_band_pin: &RootPins) -> Result<VerifiedProvisioning, BootstrapError>; }
trait DurableNodeStore {
    fn load_anchors_and_genesis(&self) -> Result<VerifiedGenesis, StoreError>;
    fn load_local_keypair(&self) -> Result<LocalKeyHandle, StoreError>;
    fn load_identity_chain_and_raw_objects(&self) -> Result<VerifiedStartupObjects, StoreError>;
    fn load_status_and_watermarks(&self) -> Result<DurableStatusState, StoreError>;
    fn commit_verified_update(&mut self, update: VerifiedDurableUpdate) -> Result<(), StoreError>;
    fn close(&mut self) -> Result<(), StoreError>;
}
```

验证器构造值，不用 public fields / bool assertion：`VerifiedGenesis`, `VerifiedProvisioning`, `VerifiedLocalIdentity`, `VerifiedStartupObjects`, `FreshStatus`, `VerifiedRevocation`, `DurableUpdate`. Constructors 应仅在根链/密码验证模块可见。统一对路径用 `O_NOFOLLOW`/Windows reparse 等平台接口拒绝链接、检查 owner/mode、bounded read、私有原子写+fsync file/dir；存储回滚不可检测或无法原子提交即拒业务启动。密钥由零化/安全 store 管理，错误/Debug/log 不泄露 bytes/path/PEM/private key。

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

1. **P00/P01 gating baseline:** finish merge/Actions baseline; reconcile candidate schemas/Lease limit, trust root/RootAuthorization wire bytes, NodeIdentity Ed public-key binding/OID and trusted clock API; freeze errors/schema vectors. No daemon code can trust provisioned issuer records until then.
2. **P02 backend/auth API:** strict outer+h1 WSS and hop TLS runtime integration, real peer extraction and full cert↔signed identity binding, no bool registration input, prove pq768 actual negotiated facts. Keep h2/CDN out of first slice.
3. **P03 bootstrap/store:** local key generation/key-store; root provisioning validator; durable signed object verification/replay watermarks/equivocation evidence; durable clock floor/status snapshot and authorization capability; tested commit/restart/rollback/expiry semantics; actual route handle close interface. Enrollment can be offline preprovision first, but exact same key/CSR transaction needed before online join.
4. **P04 NodeRuntime skeleton:** consume reviewed config parser/library; preflight/startup transaction and bounded resource ownership; strict errors/readiness/cancel/shutdown; Unix peer-credential management snapshot; actual capabilities from constructed services. Begin only after durable-trust and resource-closure APIs are agreed.
5. **P05 PAIRED endpoints:** real packet reader and safe packet parser/authorized VIP checks; typed E2E confirmation; single-hop session/circuit owner; Global Admission+credit; actual VirtualTun-to-VirtualTun packet integration over E2E encrypted stream. Only after this works implement LinuxTun one queue with actual route/device ownership (the current Linux adapter alone does not install routes); collect packet hashes/bytes and real failure/reset/drop evidence. No HopTun helper.
6. **Then broader P04/P05:** CLI daemon/config integration, service/system readiness, OS control endpoints and privileged bootstrap; DNS/smoltcp, owned route APIs, multi-queue/GSO, h2/CDN, multihop, subnet routes and scale each in separate slices. Actions exact commit after each slice; gates stay open pending genuine evidence and external review.

## 6. Luna work packages to dispatch sequentially

### L0 — RootAuthorization verifier first dependency (P01/P03; lead-assigned exact scope)

This package is explicitly **not** a daemon/bootstrap store implementation. It closes one trust boundary for future P03/P04 consumers: externally pinned NetworkRoot public key + root-signed candidate RootAuthorization bytes → a private verified issuer-authorization capability → safe conversion to the existing `management::IssuerRecord`. It does not validate a genesis/root certificate chain (the independent NetworkRoot pin is a provisioning input), implement durable store/replay/clock state, verify node certificates, launch transport, accept sessions, validate freshness/revocation, connect TUN, or implement ReleaseRoot software verification. Never treat an arbitrary caller-created `IssuerRecord` or boolean as verified.

**Exact file ownership, assigned by lead:**
1. New `crates/boreas-pki/src/root_authorization.rs`: feature-gated alongside `management` (`openssl-backend`) and implement real Ed25519 + ML-DSA AND verification over the candidate's exact canonical signed bytes. The only trust origin is an explicit NetworkRoot public-key pin passed as typed input through a constructor that checks algorithm, key id, generation, and key material; the verifier must never bootstrap trust from the object being verified. Validate expected network, object type/purpose, signer identity+generation, time window from explicit trusted UTC input, sequence/version monotonicity within the supplied verified chain, child key types/lengths, child authority role and object-type allowlist, and scope no broader than its parent. Reject any ReleaseRoot-as-network-issuer and any NetworkRoot/child role confusion. Return `VerifiedIssuerAuthorization` with private fields and an accessor/consuming method that creates existing `management::IssuerRecord` only after successful verification; do not refactor or widen existing `ManagementTrust` in this task. Keep error messages coarse and never format raw key/object bytes.
2. New `docs/protocol/root-authorization-candidate-v1.md`: document the *candidate* wire shape, signed-byte domain/canonical encoding, root pin input assumptions, role/object/scope delegation table, validity/sequence and root rotation limits, exact open design questions, and fixed valid/invalid examples. Explicitly label non-frozen/proposed; do not claim RFC status or production readiness.
3. Existing `crates/boreas-pki/src/lib.rs`: only the necessary conditional module export (`#[cfg(feature="openssl-backend")] pub mod root_authorization;`) plus matching docs. No other existing files changed.

**Repository evidence and schema constraint:** inspected `crates/boreas-proto/src/objects.rs` currently defines only six ObjectType/ObjectBody variants (NodeIdentity, AttachmentLease, CoreLsa, RouteGrant, DirectGrant, StatusSnapshot); there is currently no `RootAuthorization`, `Genesis`, or RootAuthorization decoder there. This assignment intentionally owns only `root_authorization.rs`, `root-authorization-candidate-v1.md`, and the PKI `lib.rs` export, so do not silently edit proto or pretend that a nonexistent variant can be reused. Before writing, inspect `docs/protocol/management-objects-v1.md`, its schema JSON/ADR and existing `management.rs` signature input. Candidate document must make a precise proposal that is byte-testable without calling it frozen; verifier should reuse existing `boreas_proto::objects::signature_input` / `boreas_proto::messages::SignedObject` where their canonical constraints fit. Since the current proto object schema has no RootAuthorization variant, this is a real dependency gap outside the assigned files: do not locally invent a competing production wire format. Either confirm an already-defined RootAuthorization encoding in the protocol docs and verify exact raw bytes under that candidate contract, or stop with a tightly scoped proto/schema follow-up proposal before implementation; the later proto work must be separately assigned. Current `ManagementTrust` explicitly treats `IssuerRecord` as out-of-band trust; its replay/equivocation table is process-local and it does not validate RootAuthorization chains.

**Verification matrix (Actions only):** valid pin+valid dual-signed IdentityAuthority child yields capability/IssuerRecord; wrong pin/network/type/key id/generation/role/use fails; ReleaseRoot cross-use fails; one invalid/missing Ed25519 or ML-DSA fails; mutated raw TBS and noncanonical/oversized object fail; expired/future window and stale sequence/root version fail; child trying to widen roles/object types/home cores/prefix scope fails; duplicate/rebound issuer keys and same slot+seq distinct valid bytes fail closed. Include exact deterministic positive/negative vectors in the candidate doc/tests. No local compile/test/format run; no gate/ledger update. If CI needs test files outside the permitted scope, report before expanding.

**Next after L0, not part of L0:** use only `VerifiedIssuerAuthorization` outputs as provisioned inputs to `ManagementTrust`; separately implement durable protected store for exact signed root/authorization envelopes, persistent replay/equivocation watermarks and trusted UTC floor before opening runtime. Do not create a new bootstrap/store crate or generic storage framework for this next increment: first inspect existing PKI enrollment journal/key-store abstractions and propose a narrow state adapter/API to lead, then implement in explicitly assigned existing PKI files. Durable persistence must commit exact bytes + monotonic watermarks before consumer admission; verification capability must be constructed from the persisted verified chain on restart, not carried as an unsigned cached `IssuerRecord`.


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
- No existing file was changed by the scoped implementation task; no local compile/test/format (Actions-only), no CI run, no gate or ledger changed. All proposed APIs, schema, tests and work packages above are design requirements, not verified code. The next implementation is the lead-assigned RootAuthorization verifier package in §6 L0.
