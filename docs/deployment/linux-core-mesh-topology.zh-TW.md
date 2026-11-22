# 讓四個 Core 互通：設定資料路徑、目錄與故障切換

[简体中文](linux-core-mesh-topology.zh-TW.md) · 繁體中文 · [English](linux-core-mesh-topology.en.md)

這是一條獨立的 Linux 實驗路線，使用 `boreas node mesh-run <node.toml> <material-dir> <runtime.toml>` 執行，不使用普通 Core/Edge 的 `daemon`、`boreas-run` 或離線簽名 daemon 單元。

**適用邊界與路由選擇：** 本路線僅服務**一對 Core 永久 IPv4 `/32` VIP**；由 Source 發起電路，確認後兩個端點均可收發。預設部署不修改宿主 DNS、不寫入預設路由，也不提供任意 `/24` 子網路由、網段匯出、通用轉發、Edge、IPv6 或 DNS 轉發；即便設定作業系統路由，也不會突破僅限授權對端 VIP `/32` 的限制。你可以二選一設定路徑：

- **顯式路徑配方（本頁 `[[routes]]`）**：每例項最多三條顯式路徑，每條經過三或四個不重複的 Core。
- **簽名拓撲配方（[簽名拓撲 `[routing]` 配方](linux-core-mesh-runtime.md#configure-signed-topology-routing-and-tun)）**：只設定端點對和相鄰傳輸，不列端到端路徑，支援直達或最多兩個中繼。

兩種配方均要求 Source 槽位號小於 Destination 槽位號。

**先核對二進位制能力再部署：** 三種目錄同步方式在[第 4 節](#directory)區分。本頁完整示例要求 Linux `openssl-inner-tls` 開發構建具備**目錄發現協調器及持久 CoreLSA 防重放與衝突處置能力**；公開版本 `v0.1.0-pre.3` 不具備這些能力，不能直接套用。如果你使用的是**不含目錄發現與持久 CoreLSA 改動的構建**，請刪除協調器設定並改用手工種子或靜態控制鄰接；下文的持久 CoreLSA 防重放與衝突處置機制同樣只適用於包含目錄發現改動的構建。判斷建置產物是否具備上述能力，必須核查構建所用的實際原始碼修訂；文件存在或其他原始碼修訂的 CI 透過均不能作為依據。

## 1. 拓撲和埠

```text
业务首选： Core 1 ──> Core 2 ──> Core 3 ──> Core 4
业务备选： Core 1 ────────────> Core 3 ──> Core 4
目录控制： Core 1 / Core 2 / Core 4 ────> Core 3:18183（双向交换 LSA）
```

| 節點 | 槽位 / node_id | 角色、底層地址（示例）與 TLS 名 | 監聽埠 | TUN |
| --- | --- | --- | --- | --- |
| Core 1 | `1 / 1` | Source，`192.0.2.1`，`core1.example.com` | 無 | `btun0`，`10.20.1.1/32` |
| Core 2 | `2 / 257` | Relay，`192.0.2.2`，`core2.example.com` | TCP `18082` 主路徑 | 無 |
| Core 3 | `3 / 513` | Relay + 目錄協調器，`192.0.2.3`，`core3.example.com` | TCP `18082` 主路徑、`18083` 備路徑、`18183` 目錄 | 無 |
| Core 4 | `4 / 769` | Destination，`192.0.2.4`，`core4.example.com` | TCP `18082` 主路徑、`18083` 備路徑 | `btun0`，`10.20.4.1/32` |

部署前必須滿足以下網路與防火牆前提：

1. **預先佈建置底層地址與撥號目標**：示例 IP 不能在公用網路直接使用。目標主機須事先設定好底層監聽地址；撥號設定必須填入實際數字 IP 地址和埠，禁止填入 VIP。
2. **按有向鏈路開放防火牆 TCP 埠並限制來源**：Core 2 的主資料埠（`18082`）僅放行 Core 1；Core 3 的主路徑埠（`18082`）放行 Core 2、備路徑埠（`18083`）放行 Core 1；Core 4 的兩個資料埠（`18082`、`18083`）均放行 Core 3；協調器埠（`18183`）僅放行預先佈建的 Core 1、2、4。
3. **核對主機衝突與證書名**：底層名稱透過證書 DNS SAN 校驗，使用 IP 撥號時不要求公用網路 DNS 解析這些域名，且不要修改宿主 DNS。啟動前先確認 SSH 管理路由、主機現有 `10.20.*` 地址、埠及網絡卡無衝突；本示例不是 CDN 或任意反向代理設定。

## 2. 離線簽發節點、策略和每個 Core 的拓撲通告

開始簽發前，確保所有簽發機使用同一可信 `pq768` 構建、私有工作目錄且系統 UTC 時間準確。先參照[雙機教程的離線準備方法](README.zh-TW.md#workflow)生成新的 `NET_ID` 並初始化 `./ca`（全域性只執行一次）。**不要簽發 Edge，也不要交叉複製 `peer.signed`**；專用 mesh 統一使用下文的 `core-N.signed`。為便於實驗復現，以下命令為每個 Core 都簽發了外層 TLS 證書；在當前拓撲中，實際只有監聽節點需要外層服務端私密金鑰。

```sh
for slot in 1 2 3 4; do
  boreas pki issue-node --ca-dir ./ca --out-dir "./core-$slot" \
    --role core --home-core "$slot" --vip-octet 1 --generation 1 \
    --validity-hours 168 --outer-san "core$slot.example.com" || break
done
boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued --sequence 1 --ttl-seconds 604800
```

確認四份 `local.signed` 和節點金鑰全部簽發成功後再進入下一步。接下來的簽名操作由**受 NetworkRoot 授權、且限於指定 Core 槽位的 CoreOperational** 完成，嚴禁使用執行賬號私密金鑰代替。以下目錄與引數以 Core 1 為例：

```sh
# Core 1 的签发机；新的 ./operational-1 目录只保存在签发区
boreas pki core-request ./operational-1 "$NET_ID" 1 1 7
# 离线 NetworkRoot 签发机：线下核验请求人和槽位，仅转运公开 core.request
boreas pki core-authorize ./ca ./ca/roots.cbor \
  ./operational-1/core.request ./roots-1.cbor 1
```

為槽位 `2`、`3`、`4` 依次重複上述授權流程：

- 將 `core-request` 的第 3 個引數替換為對應槽位號，每個槽位使用獨立目錄，不得複用。
- `core-authorize` 每次必須讀取**上一步的輸出**——例如 Core 2 讀取 `roots-1.cbor` 並輸出 `roots-2.cbor`，最終產出 `roots-4.cbor`。每個槽位擁有一份受限簽發授權，不得混用其他槽位私密金鑰。
- 將最終公開的 `roots-4.cbor` 分發給所有簽發機與執行節點，在所有執行節點上用它統一替換初始 `roots.cbor`，避免中間版本混入。
- NetworkRoot、IdentityAuthority、StatusSigner、外層 CA 以及 CoreOperational 的私密金鑰均不得放入執行目錄。

在**各自**簽發機上，使用最終 `roots-4.cbor` 簽發本槽位的拓撲通告（LSA）。下面四行命令分別對應四個槽位，輸出檔名互不相同，引數依次為 `core-generation`、`seq`、有效秒數，以及 0 至 15 個 `对端槽位:RTT毫秒:丢包ppm`：

```sh
boreas pki core-sign-lsa ./operational-1 ./roots-4.cbor ./core-1.lsa-1 1 1 1800 2:5:0 3:30:0
boreas pki core-sign-lsa ./operational-2 ./roots-4.cbor ./core-2.lsa-1 1 1 1800 1:5:0 3:5:0
boreas pki core-sign-lsa ./operational-3 ./roots-4.cbor ./core-3.lsa-1 1 1 1800 1:30:0 2:5:0 4:5:0
boreas pki core-sign-lsa ./operational-4 ./roots-4.cbor ./core-4.lsa-1 1 1 1800 3:5:0
```

簽發器將資料鄰接標記為 CDN 類；**這裡的類僅是協議屬性，不代表實驗流量經過真實 CDN**。一條資料邊必須在兩端節點的簽名通告中同時出現才具備授權；本例在丟包率相同的情況下透過更低的總 RTT 讓 `1→2→3→4` 成為主選路徑。目錄連線不屬於資料鄰接（例如 `2→3` 可使用兩個不同埠，而 `1→3` 的目錄認證不會為資料路徑授予轉發權）。LSA 簽發有效期最長為 3600 秒，建議臨近啟動再簽發並預留分發視窗；續簽時必須遞增 `seq`，不得修改同一代次和序號下已簽發的內容。簽發空鄰接列表表示撤回通告，不會新增任何授權。

## 3. 逐臺設定：先 `node.toml`，再 `runtime.toml`

每臺主機須預先建立專用非特權賬號 `boreas`。示例路徑 `/etc/boreas-mesh` 和 `/var/lib/boreas-mesh` 的所有父級目錄都必須可信且不能包含符號連結。設定檔案、私密金鑰與執行狀態僅允許執行 UID 訪問，建議私有目錄許可權設為 `0700`、檔案許可權設為 `0600`。每個節點與例項使用獨立的持久狀態目錄，嚴禁並行啟動第二個例項讀寫同一狀態目錄，也不要同時使用 `mesh-probe` 寫入同一目錄。

按以下清單在**每臺**主機放置檔案：

| 安裝位置 | 來源 |
| --- | --- |
| `/etc/boreas-mesh/material/identity.key`、`identity.pem`、`identity-ca.pem`、`local.signed` | 該槽位自己的 `issue-node` 輸出 |
| `…/material/roots.cbor` | 最終公開 `roots-4.cbor` |
| `…/material/status.signed`、`local-lsa.signed` | 當前狀態快照、該槽位的 LSA 原始簽名檔案 |
| `…/material/core-N.signed` | `peers` 中每個槽位 N 的公開 `local.signed`；本例每臺三份 |
| `…/material/core-N-lsa.signed` | 遠端已簽名 LSA；是否需要見[目錄模式](#directory) |
| `…/material/outer.pem`、`outer.key` | 本機自己的外層服務端材料；Core 2、3、4 需要。`outer.pem` 葉子證書在前、後跟中間證書（如有） |
| `…/material/outer-ca.pem` | 本例在撥號者放同一私有外層 CA 的公開證書；指定後取代平臺根，不是追加。始終核對 TLS 名稱和信任鏈 |
| `/var/lib/boreas-mesh/network-policy.tbs` | `policy-issued/tbs.cbor` |
| `…/network-policy.ed25519.sig`、`…/network-policy.mldsa65.sig` | `policy-issued/ed25519.sig`、`policy-issued/mldsa65.sig` |
| `…/network-root.ed25519.der`、`…/network-root.mldsa65.der` | 獨立預先佈建的兩個 NetworkRoot pin，對應策略輸出 `root-ed25519.der` 與 `root-mldsa65.der` |

部署策略檔案前，先用可信 verifier 完成[預檢策略](README.zh-TW.md#network-policy)。切勿混用三條執行路線的策略檔案命名：專用 mesh 讀取 `network-policy.*`，離線雙籤 daemon 讀取 `policy.*`，舊安裝器 wrapper 則帶有 release 字首。`status.state`、`network-policy.state` 以及（當構建包含發現改動時）`core-lsa.state` 均由執行期間自動建立，不要提前新建空檔案。`outer-ca.pem` 僅校驗外層 TLS；內層 `pq768` mTLS 仍嚴格匹配已簽名節點證書的 SPKI（公開金鑰資訊），不能由外層 TLS 名稱或 IP 替代。

以下是 Core 1 的完整 `/etc/boreas-mesh/node.toml`：

```toml
version = 2

[node]
net_id = "REPLACE_WITH_NET_ID"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"

[paths]
identity_key = "/etc/boreas-mesh/material/identity.key"
roots = ["/etc/boreas-mesh/material/roots.cbor"]
state_dir = "/var/lib/boreas-mesh"

[uplink]
primary = "core2.example.com:18082"
paths = 4
probe_paths = 1

[limits]
ipv6 = false
advertise_routes = false
accept_routes = false
edge_direct = false
allow_edges = false
default_route = false
```

將設定中的佔位符替換為實際 `NET_ID`。Core 2、3、4 對照第 1 節表格修改 `home_core_id` 和 `node_id`，其餘欄位可保持一致。`[uplink]` 僅用於滿足通用設定 schema，不決定 mesh 的實際撥號目標；不要新增 `[dns]` 或其他可選功能（本方案保持預設不接管宿主 DNS，若需專用私有後綴 split DNS 請另行按對應指引顯式啟用，而專用 mesh 本身不支援 DNS 轉發）。儲存後，務必以服務賬號預檢通用設定：

`sudo -u boreas boreas config-check /etc/boreas-mesh/node.toml`

確認檢查透過再繼續。專用 `runtime.toml` 由 `mesh-run` 解析，不在 `config-check` 檢查範圍內。

將以下四份 `runtime.toml` 分別儲存到**對應主機**的 `/etc/boreas-mesh/runtime.toml`。設定時必須確保本節點的 `listen` 與上一跳的 `next` 逐段對應，沿途所有節點上的路線 `path` 定義完全一致，且資料 socket 與控制 socket 不得複用埠。以下設定暫不含目錄段落，需按第 4 節所選方式追加到檔案末尾。

**Core 1 — Source**

```toml
mode = "source"
peers = [2, 3, 4]
tun = "btun0"
mtu = 1400

[[routes]]
path = [1, 2, 3, 4]
next = "192.0.2.2:18082"
tls_name = "core2.example.com"

[[routes]]
path = [1, 3, 4]
next = "192.0.2.3:18083"
tls_name = "core3.example.com"
```

**Core 2 — Relay（僅主路徑）**

```toml
mode = "relay"
peers = [1, 3, 4]

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.2:18082"
next = "192.0.2.3:18082"
tls_name = "core3.example.com"
```

**Core 3 — Relay（兩條路徑）**

```toml
mode = "relay"
peers = [1, 2, 4]

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.3:18082"
next = "192.0.2.4:18082"
tls_name = "core4.example.com"

[[routes]]
path = [1, 3, 4]
listen = "192.0.2.3:18083"
next = "192.0.2.4:18083"
tls_name = "core4.example.com"
```

**Core 4 — Destination**

```toml
mode = "destination"
peers = [1, 2, 3]
tun = "btun0"
mtu = 1400

[[routes]]
path = [1, 2, 3, 4]
listen = "192.0.2.4:18082"

[[routes]]
path = [1, 3, 4]
listen = "192.0.2.4:18083"
```

<a id="directory"></a>

## 4. 選擇一種目錄方式

根據你的目標二進位制能力與運維偏好，從下列三種方式中任選一種（格式不可混用）：

**A. 預先佈建成員 + 單一協調器（要求具備目錄發現與持久 CoreLSA 能力的構建）。** Core 3 在其 `runtime.toml` 末尾追加：

```toml
[directory_discovery]
coordinator = 3
listen = "192.0.2.3:18183"
```

Core 1、2、4 分別在各自 `runtime.toml` 末尾追加同一段協調器客戶端設定：

```toml
[directory_discovery]
coordinator = 3
next = "192.0.2.3:18183"
tls_name = "core3.example.com"
```

注意：協調器不發現任意未知成員。每個節點仍須預先設定其餘三個槽位的 `core-N.signed` 和一致的最終 `roots.cbor`。TLS 客戶端會校驗協調器的外層域名、證書鏈與簽名身份；協調器則依據內層 TLS 的精確 SPKI 匹配預先佈建成員，絕不從 TCP 來源、DNS、SessionHello 或 LSA 中學習成員或公開金鑰。協調器僅負責交換已驗證的原始簽名通告，不代簽、不授予資料邊，也不會自動選舉備用協調器。

**冷啟動與種子管理：** 僅在 Core 3 放置一份當前有效的 Core 1 通告（`material/core-1-lsa.signed`），以便 Core 2、3、4 在 Source 啟動前提前獲知 Core 1。其餘遠端 LSA 均透過目錄獲取，無需逐對複製。當部分通告尚未到位時，目錄交換可先行工作，但資料監聽與 TUN 附著會一直等待，直到拓撲圖中存在可用路徑。任何顯式置於磁碟的種子檔案都視為校驗輸入；續簽 LSA 後，應原子替換種子檔案，或在確認新頭已持久化後刪除不再需要的**種子檔案**。嚴禁將過期種子留在目錄中，也嚴禁刪除持久狀態檔案。

**B. 靜態控制鄰接（`[[directory]]`）。** 此格式不得與方式 A 混用。為控制面設定專用控制邊，按較低槽位撥較高槽位設定。例如，Core 1 撥 Core 2 的 `192.0.2.2:18182`：

```toml
# Core 1
[[directory]]
peer = 2
next = "192.0.2.2:18182"
tls_name = "core2.example.com"
```

```toml
# Core 2
[[directory]]
peer = 1
listen = "192.0.2.2:18182"
```

其餘控制邊遵循同樣規則，每條邊須在兩端成對設定並使用獨立埠（例如建立 `1→2→3→4` 控制鏈）。為每個目錄監聽端設定本機外層 TLS 服務端證書，為撥號端設定可信 CA 鏈。為保證下游先行就緒，可在啟動前預置當前有效的全部 LSA；啟用靜態同步後，學到的遠端頭無需再寫入磁碟寫入新的種子檔案。不要指望由尚未啟動的 Source 把第一份簽名 LSA 推向下游。

**C. 純手工種子（不寫任何目錄段）。** 初次部署時按 `peers` 為每個節點放齊所有對端的 `core-N-lsa.signed`，再按順序啟動。此方式無跨跳同步；執行期間仍可接收來自已認證直接資料鄰居的新通告。若使用具備目錄發現與持久 CoreLSA 能力的構建，重新啟動後可複用有效的持久頭；若使用不含該改動的構建，則不能依賴跨重新啟動持久化。

**同步校驗與排程行為：** 目錄同步會校驗直接通告、身份撤權及第三方簽名通告；每次同步分頁對應一份原始簽名 LSA，逐一驗證簽名、委派範圍、時間戳和防重放水位，透過認證的頁面會獨立提交。撥號方在上一次同步嘗試結束 5 秒後排程下一次嘗試，並與其他控制任務及資料輪次共享排程器——**這不構成 5 秒收斂保證**。當協調器暫時不可達時，已完整授權的資料圖在其有效期內仍可繼續工作；任何簽名、授權或時效校驗失敗都不會降級放行。目錄本身不分發身份憑據、資料授權、租約或衝突證據。

## 5. 管理員預先建立兩端 TUN，再啟動四個程序

Core 1 與 Core 4 各需一個交給 `boreas` 使用的持久、單佇列、無包資訊頭（`no_pi`）的 TUN 裝置。執行建立前先確認本機裝置名與路由無衝突，再逐臺設定，嚴禁使用 `replace` 覆蓋宿主原有路由。Core 2 和 Core 3 兩個 Relay 不建 TUN。

```sh
# 只在 Core 1
sudo ip tuntap add dev btun0 mode tun user boreas
sudo ip link set dev btun0 mtu 1400 up
sudo ip addr add 10.20.1.1/32 dev btun0
sudo ip route add 10.20.4.1/32 dev btun0 src 10.20.1.1
```

```sh
# 只在 Core 4
sudo ip tuntap add dev btun0 mode tun user boreas
sudo ip link set dev btun0 mtu 1400 up
sudo ip addr add 10.20.4.1/32 dev btun0
sudo ip route add 10.20.1.1/32 dev btun0 src 10.20.4.1
```

兩端點僅允許收發這兩個經認證的 `/32` VIP 流量；底層地址和宿主預設路由絕不能指向 TUN。`mesh-run` 只附著並校驗已存在的裝置，不負責建立或清理。主機重新啟動後，必須由管理員或本地網路管理器重新建立該專用 TUN 與對應授權 `/32` 路由。

確認四臺主機上 `boreas` 賬號均可透過可信路徑執行目標二進位制後，在每臺主機前臺執行以下命令（使用各自對應的設定檔案）。**啟動順序要求：** 先啟動 Core 3，再啟動 Core 4 和 Core 2；待三個下游節點均列印 `mesh ready node=…` 且透過 `ss -ltn` 確認對應資料埠處於監聽狀態後，最後啟動 Core 1。`mesh ready` 僅表示本機拓撲圖已有可用路徑且對應監聽或 TUN 已就緒，並不代表端到端電路已建通。切勿在下游未就緒時讓 Source 提前試撥：認證確認前出現的失敗不能作為切換依據。

```sh
sudo -u boreas boreas node mesh-run /etc/boreas-mesh/node.toml \
  /etc/boreas-mesh/material /etc/boreas-mesh/runtime.toml
```

若以守護程序方式託管，請捕獲 `stderr` 並使用 `SIGTERM` 停止程序。此執行入口**沒有** `control.sock`，不要使用普通 daemon 的 `ctl status` 來判斷 mesh 是否線上。

## 6. 驗收、切換和排錯

程序就緒後，按以下步驟驗證主路徑連通性、故障切換和撤權行為：

```sh
# Core 1
ip -4 route get 10.20.4.1 from 10.20.1.1
ping -c 4 -I 10.20.1.1 10.20.4.1
# Core 4
ip -4 route get 10.20.1.1 from 10.20.4.1
ping -c 4 -I 10.20.4.1 10.20.1.1
```

1. **核對主路徑電路與流量**：在 Source 和 Destination 日誌中核對相同的已確認 `circuit` ID 以及 `path=[1, 2, 3, 4]`。兩端日誌應出現 `tx`/`rx` 計數，Relay 僅報告密文轉發計數，不記錄明文資料內容。
2. **測試故障切換（僅限可銷燬測試環境）**：確認主路徑正在承載流量後，停止 Core 2 程序（不要停止協調器 Core 3）。等待兩端確認新路徑 `path=[1, 3, 4]`，新 `circuit` ID 在兩端應一致且不同於舊 ID；隨後發起新的 `ping` 測試連通性。執行期間僅在取得合格的失鏈證據、且備選路徑仍處於有效授權時，才會嘗試新的跳鏈與新的端到端 TLS 握手，絕不重放舊資料包或舊密文。電路確認前的 EOF/reset、認證或協議錯誤、憑據過期或撤權均不會觸發自動改走備路。故障切換不提供無損承諾，TCP 等上層連線需由應用或協議棧自行恢復。
3. 進一步的撤權測試由[倉庫驗收](#acceptance)完成。獨立身份撤權材料使用 `identity-revocation.signed` 入口；StatusSigner 的日常快照不替代 IdentityAuthority 撤權。已提交撤權不會因刪除郵箱檔案或重新啟動而消失。資料電路存續時也輪詢郵箱；撤權涉及路徑成員時，先持久化決定再關閉電路。被撤的是遠端時，仍可透過健康的目錄鄰接傳播原始簽名證據；若被撤的是本機代次，程序停止。

| 現象 | 檢查順序 |
| --- | --- |
| 目錄埠在聽但不出 `mesh ready` | 查三臺是否撥同一協調器、TCP/證書 SAN、預先佈建 `core-N.signed` 是否齊全，是否缺 Core 1 的引導種子或存在過期 LSA；確認資料邊兩端均有簽名宣告、清單沿途一致。 |
| `invalid directory discovery configuration` / `overlapping legacy links` | 目標二進位制是否支援協調器目錄發現；協調器只配 `listen`，其他節點只配 `next` 和 `tls_name`；不要混用兩種目錄段或佔用資料地址/埠。 |
| `mesh TUN attach` / VIP 不通 | 端點專用裝置是否持久、歸 `boreas`、名稱/MTU 匹配；比較兩端 `ip -4 route get` 與選中的源 VIP；用已確認路徑 ID 檢查是否同一電路。 |
| 已有資料突然停，日誌顯示狀態、授權或 LSA 失效 | 先核對 UTC、策略及狀態期限、撤權和所有拓撲通告。簽發更高序號不是忽略獨立撤權或同版分叉的辦法；修復原因後再按需協調重新啟動。 |
| `LsaConflict` / `LsaState` 或啟動拒絕 | 停止程序，保留受保護的 `core-lsa.state`、`core-lsa.state.lock` 及可能的 `core-lsa.state.staging`；查檔案系統、許可權、舊狀態與簽發方。不要刪檔案或換到空目錄來復原。 |

### 持久 CoreLSA 衝突證據（須支援持久 CoreLSA）

`mesh-run` 和 `mesh-probe` 使用 `state_dir/core-lsa.state`。該狀態僅供服務 UID 使用，繫結 `net_id`、NetworkRoot 指紋及本機槽位；儲存每槽位至多一份當前原始簽名通告（最多 16 個槽位）。首個同 `(core_generation, seq)`、簽名有效但待簽字節不同的分叉保留兩份原始信封並停止使用該授權。鎖協調寫入並標記初始化或寫衝突意圖；提交會同步私有 staging、原子安裝並同步父目錄。提交失敗、衝突標記未解決、中斷 staging、已初始化狀態缺失、路徑不安全、損壞或驗證到分叉都會拒絕啟動或停止執行授權。提高代次不能清空已持久化衝突。

恢復時舊種子不能降低已有水位；歷史信封的雙籤與委派按簽發時刻複核，允許承載資料的授權仍受當前策略、有效期和撤權約束。輪換前確認能保留歷史驗籤所需授權。先封存證據，再調查錯誤簽發、金鑰或儲存問題，必要時由管理員審閱並重新預先佈建信任；沒有自動解封。不要刪 `.lock`、`.staging` 或整個目錄“修好”服務。它不防受信 UID/root 替換整個狀態目錄或回滾儲存快照。

<a id="acceptance"></a>

## 7. 驗收入口及證據範圍

在與目標建置產物原始碼修訂一致的 [TLS 工作流](../../.github/workflows/rust-tls.yml)和受控 Linux runner 上，使用工作流固定的 OpenSSL、環境與 features。倉庫的兩個入口：

```sh
cargo test --locked -p boreas-tunnel --features openssl-inner-tls --test mesh_probe_live
cargo test --locked -p boreas-cli --features openssl-inner-tls --test mesh_run_netns --no-run
```

真實裝置測試是 ignored：只有顯式執行 Cargo 列印的 `mesh_run_netns` 測試二進位制才執行。用可銷燬 runner，須有 `/dev/net/tun`、`CAP_NET_ADMIN`、`CAP_SYS_ADMIN`、`ip`、`ping`、`unshare`、`mount` 和 `setpriv`；沿用與構建配套的 `OPENSSL_CONF` / `BOREAS_OPENSSL_BIN`：

```sh
sudo --preserve-env=OPENSSL_CONF,BOREAS_OPENSSL_BIN \
  /path/printed/mesh_run_netns-HASH --ignored --nocapture --test-threads=1
```

固定路徑用例啟動四個非 root 程序、兩個真實持久 TUN；只有協調器預置 Source LSA，透過共享目錄收斂，主備路徑分別傳真實包，核對新 ID 和密文計數。撤銷活躍遠端後應取消電路、報告無可用路徑但不退出；撤銷本機代次才要求 Source 退出碼 `2`。另外兩個用例不設定固定路徑，分別驗證單邊通告不能授權直達、失鏈後複用入口，以及執行中撤權後經雙邊簽名的直達路徑重新建環。活體 TLS 用例還覆蓋空閒電路撤權、跨跳傳播、未預先佈建成員拒絕和跨重新啟動分叉證據。這裡描述的是測試斷言；是否透過要讀目標提交的實際日誌。測試不經過真實 CDN，不驗證公用網路長穩、通用路由或生產就緒。
