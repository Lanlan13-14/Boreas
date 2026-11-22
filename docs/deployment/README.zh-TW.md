# Boreas 部署指南：從材料準備到雙機互通

[简体中文](README.zh-TW.md) · 繁體中文 · [English](README.en.md)

本指南協助你建立一條僅連接兩個 IPv4 VIP 的 Linux 通道。建議在兩台可隨時重建的主機上演練，並全程保留 SSH 與雲端主控台等旁路管理入口。驗收成功的標準不是「服務顯示執行中」，而是**兩端的通道路由正確、雙向 `ping` 成功，且收發封包計數持續增長**。

| 你手中的製品 | 應遵循的章節與路徑 |
| --- | --- |
| 可信的當前開發建置（Linux、`openssl-inner-tls`） | 依本頁順序完成 [準備 → 簽發 → 設定 → 安裝 → 互通](#workflow)。開發版 `daemon` 強制要求明確策略、網路根 pin 與持久水位，不可直接套用公開版的指令。 |
| 公開發布的 `v0.1.0-pre.3` x86-64 pq768 二進位檔 | 請直接跳至 [公開預發布版本雙機演練](#public-pre3)。請勿使用當前 `install.sh` 的服務包裝器或離線雙簽服務。 |
| 已獨立預先佈建軟體發布根與雙簽候選製品 | 共用下方的簽發與設定流程，安裝階段則改接 [離線簽章 systemd 服務](VERIFIED-SERVICE.md)，並與舊版 root 範本二選一。 |
| 需要連通多個 Core 節點 | 請改用 [四 Core 拓撲教學](linux-core-mesh-topology.zh-TW.md)；該路徑具備獨立的 CLI、清單格式、材料命名與 TUN 所有權規則。 |

<a id="workflow"></a>

## 1. 準備環境與位址

開始操作前，請先確認以下四項前置條件皆已滿足：

- **離線簽發機**：準備一台經過預先驗證且可信、支援 pq768 PKI 的 Boreas 環境；維持工作目錄私有，並確保系統時間準確。製品下載或傳輸應與託管私鑰分離，切勿在離線簽發機上連網拉取未知程式。
- **兩台 Linux 節點**：兩端必須採用同一來源修訂的製品並核對 CPU 架構。開發製品需與所使用的 `tools/deploy/` 來自相容修訂；可從 [建置工作流程](../../.github/workflows/rust-tls.yml) 對應的執行結果取得候選製品，切勿假設會有新的公開版本。若自行替換 OpenSSL 或 provider，原先的驗收結論將不再適用。
- **底層網路**：Core 需接受來自 Edge 的 TCP `8443` 連線（請同步檢查雲端安全群組與主機防火牆）；Edge 僅需能主動外撥即可，本範例無須開放 UDP。本指南採用直連 WSS，不經過 CDN 或反向代理。請選用未被佔用的連接埠與 TUN 名稱，避開主機現有路由、管理網路與業務網路。
- **系統工具**：兩端需具備完整的 `iproute2`、`ss`、`ping`；若使用安裝程式，還需具備 `readelf` 與 SHA-256 等工具。僅在選用對應服務路徑的主機上需要 systemd。預設部署不會修改主機全域 IPv6、DNS 或預設路由。

| 項目 | Core | Edge |
| --- | --- | --- |
| 底層位址 | 監聽 `0.0.0.0:8443`；範例可達位址 `203.0.113.10:8443` | 撥號至 Core 的真實可達位址，允許位於 NAT 後方 |
| 外層 TLS 名稱 | `wss.example.net`（憑證 DNS SAN） | 驗證 `wss.example.net`；HTTP Host 可附帶 `:8443` |
| `[node]` 槽位 | `home_core_id=1`、`vip_octet=1`、`node_id=1` | `home_core_id=1`、`vip_octet=2`、`node_id=2` |
| 通道參數 | `btun0`、MTU 1360、`10.20.1.1/32` | `btun0`、MTU 1360、`10.20.1.2/32` |

`203.0.113.10` 為文件保留位址，操作時必須替換為真實位址；使用裸 IP 撥號時，範例 DNS 名稱僅用於憑證驗證與 HTTP Host，無須設定公開 DNS 解析。永久 VIP 格式為 `10.20.<home_core_id>.<vip_octet>`，節點 ID 計算公式為 `((home_core_id - 1) << 8) | vip_octet`；撰寫設定檔時應以簽發材料為準，切勿自行挑選 VIP。

在兩台節點上先執行唯讀環境檢查：

```sh
uname -m
ls -l /dev/net/tun
ip -4 addr show
ip -4 route show
ip -4 route get 203.0.113.10
ss -ltn
```

最後兩項指令分別用於核實底層路由與監聽連接埠（在 Edge 上請將目標替換為 Core 的實際位址；Core 上也應確認自身的管理路由）。若系統缺少 `/dev/net/tun`，請先由管理員確認核心支援、裝置透傳與權限；支援模組載入的 Linux 可執行 `sudo modprobe tun`。請注意，容器擁有 UID 0 並不代表具備 TUN 或網路管理權限。使用 systemd 的主機可透過 `timedatectl status` 檢查時間同步狀態；離線簽發機也務必核對 UTC 時間。

<a id="offline-issuance"></a>

## 2. 離線簽發（僅在簽發機執行）

請在新建的私有工作目錄中操作。先執行 `boreas doctor` 確認實際建置能力，再進行簽發；基礎 CLI 封存檔無法取代已啟用 OpenSSL 後端的二進位檔。下方產生的 `NET_ID` 後續需寫入兩台節點的設定與安裝參數，可記錄該值，但私鑰絕對不得隨之傳輸。

```sh
umask 077
mkdir -m 0700 "$HOME/boreas-pki"
cd "$HOME/boreas-pki"
NET_ID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
printf 'NET_ID=%s\n' "$NET_ID"

boreas pki init-ca --ca-dir ./ca --net-id "$NET_ID" --validity-days 30
boreas pki issue-node --ca-dir ./ca --out-dir ./core --role core \
  --home-core 1 --vip-octet 1 --generation 1 --validity-hours 168 --outer-san wss.example.net
boreas pki issue-node --ca-dir ./ca --out-dir ./edge --role edge \
  --home-core 1 --vip-octet 2 --generation 1 --validity-hours 168

boreas pki sign-status --ca-dir ./ca --out ./status.signed --sequence 1 --ttl-seconds 86400
cp ./status.signed ./core/status.signed
cp ./status.signed ./edge/status.signed
cp ./core/local.signed ./edge/peer.signed
cp ./edge/local.signed ./core/peer.signed

boreas pki verify-bundle --material-dir ./core --require-peer
boreas pki verify-bundle --material-dir ./edge --require-peer
```

驗包結果應回報 `status: ok`；Core 的本機／對端 ID 應為 `1/2`，Edge 則應為 `2/1`。`issue-node` 內附的初始快照效期僅約一小時，另行簽發的範例快照效期為 24 小時。`peer.signed` 屬於**公開簽章身分**，並非對端的憑證私鑰。每台主機僅能接收屬於自己的節點包，`identity.key` 與 `outer.key` 不可互換。**整個 `ca/` 目錄必須留在離線保管區**，其中包含 NetworkRoot、IdentityAuthority、StatusSigner 與外層 TLS CA 私鑰。

<a id="network-policy"></a>

### 開發建置：額外簽發網路策略

**進行公開 `v0.1.0-pre.3` 演練時請跳過此小節**，其餘簽發步驟維持不變。針對開發建置，策略與節點必須使用相同的 `net_id`。請執行以下指令簽發當前 CLI 提供的 `10.20.0.0` 基址策略，接著將三個簽章輸入檔與兩個公鑰 pin 分開存放：

```sh
boreas pki sign-policy --ca-dir ./ca --out-dir ./policy-issued \
  --sequence 1 --ttl-seconds 604800
mkdir -m 0700 ./policy ./pins
install -m 0600 ./policy-issued/tbs.cbor ./policy/policy.tbs
install -m 0600 ./policy-issued/ed25519.sig ./policy/policy.ed25519.sig
install -m 0600 ./policy-issued/mldsa65.sig ./policy/policy.mldsa65.sig
install -m 0600 ./policy-issued/root-ed25519.der ./pins/root.ed25519.der
install -m 0600 ./policy-issued/root-mldsa65.der ./pins/root.mldsa65.der
```

掌管 NetworkRoot 的人員必須透過獨立可信的管道預先佈建這兩個公開 pin；絕對不可使用待驗證製品自身附帶的根憑證作為信任錨。以下預檢必須使用**已受信任**的 verifier CLI 與已核對的 pin 執行，此步驟僅驗證物件完整性，不會寫入水位狀態：

```sh
boreas pki verify-policy --net-id "$NET_ID" \
  --tbs-file ./policy/policy.tbs \
  --ed25519-signature-file ./policy/policy.ed25519.sig \
  --mldsa65-signature-file ./policy/policy.mldsa65.sig \
  --root-ed25519-der ./pins/root.ed25519.der \
  --root-mldsa65-der ./pins/root.mldsa65.der
```

將各自的節點材料包、策略三個檔案與已預先佈建的 pin 分發至目標主機的私有 staging 目錄；傳輸時請核對 SSH 主機金鑰或使用經核准的安全傳輸通道。切勿上傳 CA 目錄，也不可混入備份檔或暫存檔。請為兩份節點包各保留一份受保護的離線副本，並記錄初次簽發的序號與失效時間。

## 3. 設定兩個節點

以下為**完整的 Core TOML 設定範本**。請在每台主機建立各自的 `node.toml`（權限設為 `0600`），並將 `REPLACE_WITH_NET_ID` 替換為同一個實際數值。範本中的 `[paths]` 適用於下文 `v0.1.0-pre.3` 的手動路徑；開發版安裝程式在安裝時會重新定位這三項路徑，建議來源設定檔仍指向私有 staging 中真實存在的檔案與目錄。若採用離線雙簽 systemd 路徑，則須遵循其 [固定目錄配置](VERIFIED-SERVICE.md#首次安装管理员)，不經由舊版安裝程式重新定位。

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
identity_key = "/etc/boreas/material/identity.key"
roots = ["/etc/boreas/material/roots.cbor"]
state_dir = "/var/lib/boreas"

[uplink]
primary = "wss.example.net:8443"
paths = 4
probe_paths = 1

[limits]
ipv6 = false
advertise_routes = false
accept_routes = false
edge_direct = false
allow_edges = true
default_route = false
```

**Edge 設定可直接複製此檔案修改**：將 `role` 改為 `"edge"`，`vip_octet` 與 `node_id` 改為 `2`，`allow_edges` 改為 `false`；其餘欄位維持不變（若兩端實際檔案路徑不同，請各自填寫本機路徑）。`identity_generation` 必須與 `issue-node --generation` 相符。請勿將 `paths = 4` 誤解為會開啟四條使用中連線：該欄位代表 `[uplink]` 設定中的路徑上限，並非本範例實際建立的通道電路數量。

- `[node]` 對應已簽發的身分；單純修改 TOML 並不會改變節點身分。Core 的 `allow_edges` 僅允許該節點擔任接入端，無法取代 `peer.signed` 的點對點授權。
- `[paths]` 必須使用絕對路徑。私鑰僅授權給執行該服務的 UID 讀取，且狀態目錄必須具備持久性並允許該 UID 寫入。切勿讓兩台節點或兩個程序共用同一個執行狀態目錄。
- `[uplink]` 為必填區段。本指南透過 `--listen` / `BOREAS_LISTEN` 指定監聽位址，透過 `--connect` / `BOREAS_CONNECT` 明確撥號底層 IP；`--tls-name` / `BOREAS_TLS_NAME` 用於比對憑證 SAN，而 `--ws-host` / `BOREAS_WS_HOST` 則設定 WebSocket 請求的 Host 標頭。切勿將這三者都填入通道 VIP。

設定完成後，請使用已受信任的對應建置執行 `boreas config-check /实际路径/node.toml`。此指令通過僅代表靜態語法與基本欄位檢查成功；實際材料、策略、監聽埠、對端驗證與 TUN 建立仍須於執行階段驗證。

## 4. 安裝並啟動開發建置

請遵循 [一鍵安裝操作單](ONE_CLICK.zh-TW.md) 的步驟：在兩台主機準備相同結構的私有 staging 目錄，逐台比對可信 SHA-256 摘要，先執行 `--dry-run` 確認無誤，再使用 `--service systemd --accept-legacy-service` 進行安裝。分別寫入 Core 與 Edge 的 `boreas.env` 後，**先啟動 Core，待確認 TCP 監聽埠開啟後立刻啟動 Edge**。舊版範本採用 root 權限執行，僅適用於隔離環境評估；切勿與離線雙簽服務單元混裝。請注意，安裝成功且 `active` 符號連結已切換，並不代表本機程序已經開始執行或通道已經連通。若使用 `--service none`，則僅完成檔案安裝，不會啟動 daemon。

每台主機各自讀取自己的 `<prefix>/releases/<id>/config.toml` 與 `materials/`；兩端可使用相同的 release id，但絕對不可混用節點材料。一鍵部署的啟動腳本會讓兩端各自將本機組網 VIP 設定到 `btun0`，並僅新增一條指向已授權對端 IPv4 VIP 的 `/32` 路由（不會設定任何 `/24` 網段路由、路由匯出或封包轉發）。該腳本不會替換主機既有的位址或路由，並在結束時僅清理自己新增的項目。預設部署既不會修改系統預設路由，也不會更動 Core 或 Edge 的主機 DNS。一般上網流量與外層通道連線仍由主機原有的路由表處理；若組網位址與本機現有網段衝突，請先排除衝突再啟動。**採用此路徑時切勿預先建立 `btun0`**；反之，離線雙簽服務則要求管理員預先建立持久性 TUN 裝置與對端路由。

<a id="verify-and-maintain"></a>

## 5. 驗收與日常維護

驗收時應依序從網路底層檢查至應用層。Core 出現監聽埠不代表握手成功；`ss` 輸出中出現 TCP 連線也不代表已建立經過驗證的加密電路。

```sh
# Core
sudo ss -ltnp 'sport = :8443'
ip -4 addr show dev btun0
ip -4 route get 10.20.1.2 from 10.20.1.1

# Edge
ip -4 addr show dev btun0
ip -4 route get 10.20.1.1 from 10.20.1.2
# 替换为真实底层 IP；此路由绝不能指向 btun0
ip -4 route get 203.0.113.10
```

在舊版安裝程式的預設前綴下，請使用與執行 daemon 相同的 UID（此處為 root）查詢狀態。若採用離線雙簽服務，請改用 `sudo -u boreas` 並指定 `/var/lib/boreas/state/control.sock`；若是 `v0.1.0-pre.3`，則改為 `/var/lib/boreas/control.sock`。若當下找不到 socket 檔案，應先查閱服務日誌排除異常，切勿放寬檔案或目錄權限。檢視舊版範本的狀態主控台時，請明確將服務名稱設為 `boreas`。

```sh
sudo boreas ctl status --socket /opt/boreas/state/control.sock
sudo boreas console --json --socket /opt/boreas/state/control.sock \
  --service boreas

# Edge：发送前后各看一次状态
ping -c 4 -I 10.20.1.2 10.20.1.1
# Core：反向验证
ping -c 4 -I 10.20.1.1 10.20.1.2
```

預期結果：前往對端 `/32` 的路由確實選擇 `btun0`；狀態輸出顯示 `daemon_connected:true`、`security_mode:"e2e-required"`、`status_fresh:true`；雙向 `ping` 成功，且兩端的 `tx_packets` 與 `rx_packets` 持續增長。若需進一步驗證 TCP 傳輸效能，可在 Core 執行 `iperf3 -s -B 10.20.1.1`，並於 Edge 執行 `iperf3 -c 10.20.1.1 -B 10.20.1.2 -t 10`；建議於基礎連通故障排除後再進行壓力測試，且隔離環境的測試數據不代表公網 SLA。

### 選用：讓兩台節點使用私有網域名稱

請先確認上述雙向 `ping` 驗收已經通過，再依 [私有 DNS 部署說明](../engineering/dns-daemon-deployment.md) 簽發私有區域、在兩端安裝固定版本的組態檔，並直接向私有 DNS 位址發起查詢。私有 DNS 為選用功能：若僅由支援指定伺服器的專用應用程式直接查詢，無須修改主機的系統解析器，安裝程式亦不會自動佈建系統解析器規則。若需讓一般應用程式自動解析私有網域，應由管理員手動設定嚴格的依網域分流 DNS（Split DNS）：僅將私有網域後綴導向組網 DNS，其餘網域名稱仍維持由主機原有解析器處理；切勿替換全域 DNS，且私有後綴在通道斷線時亦不得回退至公網解析。若需啟用 TCP 查詢，兩端都必須明確設定 `[dns].tcp = true`。此選項僅啟用通道內的私有 DNS 服務，不會代為安裝作業系統解析規則，也不會將查詢轉發至公網。

### 續簽、重啟與停用

- **狀態快照**：於過期前在離線簽發機製作新版本，例如執行 `boreas pki sign-status --ca-dir ./ca --out ./status-2.signed --sequence 2 --ttl-seconds 86400`（僅在目前序號確定為 `1` 時才遞增為 `2`）。將同一份新快照分發至兩端主機，於實際 daemon 材料目錄內先複製為暫存檔，設定正確擁有者與 `0600` 權限後，再於同一檔案系統內進行原子性重新命名覆蓋 `status.signed`。daemon 會自動覆核新快照；若先前已因過期而停機，必須先更新材料再重新啟動服務。完成後再次檢查 `status_sequence`、`status_fresh` 與雙向流量是否正常。相同序號但內容不同、或低於目前序號的快照均無法作為續簽使用。
- **舊版開發安裝的發布目錄**：線上更新 `status.signed` 屬於執行期材料更新，不等於原始安裝套件的位元組未曾變動；切勿繼續使用相同的 release id 重新發布已更動過的輸入檔。新的安裝世代請一律使用新的 release id。若涉及策略或根憑證變更，應獨立評估效期、根指紋與水位影響，並依 [策略及狀態規則](POLICY-STATE.md) 規劃遷移，切勿直接覆蓋歷史檔案。軟體降版無法讓舊有、已過期或已撤銷的授權重新生效。
- **停用**：舊版 systemd 路徑請執行 `sudo systemctl stop boreas.service`，若不再需要開機自啟，再執行 `sudo systemctl disable boreas.service`；停用後請確認包裝腳本所新增的 `/32` 路由與 TUN 裝置已清理完畢。手動前景執行路徑請在**對應終端機**中停止程序，切勿使用全域 `pkill`。離線雙簽服務或 mesh 拓撲的持久性 TUN 裝置由管理員負責維護，停止服務不等於移除裝置。請保留狀態目錄與必要日誌以便後續稽核，切勿將清空水位當作重試手段。

<a id="public-pre3"></a>

## 6. 公開預發布版本雙機演練（僅限 `v0.1.0-pre.3`）

此為獨立的 **x86-64 Linux** 手動部署路徑。若目標主機已存在 Boreas 服務、TUN 裝置、相關路由或設定檔，請另行準備一台隔離主機進行演練，避免覆蓋既有環境。請注意，`.tar.gz` 基礎封存檔與下方的 pq768 二進位檔並非同一製品。

在**下載端**建立空白目錄並取得官方固定標籤的兩個檔案，請使用 `&&` 串接指令，確保任一下載或驗證失敗時立即中止該組操作：

```sh
BASE=https://github.com/Lanlan13-14/Boreas/releases/download/v0.1.0-pre.3
BIN=boreas-linux-x86_64-musl-pq768
curl -fLO "$BASE/$BIN" &&
  curl -fLO "$BASE/SHA256SUMS-PRE3" &&
  grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -
```

確認輸出顯示該二進位檔為 `OK` 且結束代碼為 `0` 後，請再透過獨立管道核對來源與 SHA-256 摘要。由於這兩個檔案來自同一來源，此步驟僅能驗證下載完整性，並非正式的雙簽軟體發布驗證；若無法建立信任鏈，切勿以 root 權限執行。確認兩台主機無命名衝突後，於兩節點安裝經過驗證的同一製品，離線簽發機則透過可信傳輸管道取得相同的簽發工具：

```sh
sudo install -m 0755 "$BIN" /usr/local/bin/boreas
boreas doctor
```

預期此版本的 `boreas doctor` 輸出應包含 `daemon: true` 與 `tls_backend: true`。接著依第 2 節步驟完成簽發並驗包，**並跳過網路策略小節**。透過安全通道將各自的節點包傳送至對應主機的 `/etc/boreas/material`，並依第 3 節範本撰寫 `/etc/boreas/node.toml`；此路徑下的 `[paths]` 維持範本預設配置即可。請建立由 root 擁有的 `/etc/boreas`、`/etc/boreas/material` 與 `/var/lib/boreas` 私有目錄（權限設為 `0700`），設定檔與私鑰權限皆設為 `0600`，確認檔案歸屬無誤後執行 `sudo boreas config-check /etc/boreas/node.toml`。

操作前請先備妥雙方終端機。於 Core 執行前景啟動指令，看到開始監聽後請務必在首次連線等待視窗（30 秒）內啟動 Edge；若超過等待視窗，請先檢視錯誤訊息並重新啟動 Core。

```sh
# Core，终端 1
sudo boreas daemon serve --config /etc/boreas/node.toml \
  --material-dir /etc/boreas/material --listen 0.0.0.0:8443 \
  --tun-name btun0 --mtu 1360
```

```sh
# Edge，终端 1：换成实际底层 IP，不要用 Core VIP
sudo boreas daemon connect --config /etc/boreas/node.toml \
  --material-dir /etc/boreas/material --connect 203.0.113.10:8443 \
  --tls-name wss.example.net --ws-host wss.example.net:8443 \
  --tun-name btun0 --mtu 1360
```

在各自的第二個終端機中使用 `ip link show dev btun0` 等待 daemon 建立 TUN 裝置，確認裝置出現後，僅在對應主機上執行各自的三行指令。若執行 `add` 時發生衝突，應立即停止並檢查原因，切勿改用 `replace` 強行覆蓋。

```sh
# Core，终端 2
sudo ip link set dev btun0 up
sudo ip addr add 10.20.1.1/32 dev btun0
sudo ip route add 10.20.1.2/32 dev btun0
```

```sh
# Edge，终端 2
sudo ip link set dev btun0 up
sudo ip addr add 10.20.1.2/32 dev btun0
sudo ip route add 10.20.1.1/32 dev btun0
```

依第 5 節步驟執行雙向驗證，查詢狀態指令請改用 `sudo boreas ctl status --socket /var/lib/boreas/control.sock`。演練結束需要停止時，請關閉兩端的前景程序並確認本次建立的 TUN、IP 位址與路由皆已消失。本節不將舊版手動指令寫入現行的服務範本；若有常駐需求，請依據目標開發建置選擇對應的服務部署路徑。

<a id="troubleshooting"></a>

## 7. 按層排查：先找到第一處異常

| 現象 | 先檢查 | 修復或下一步 |
| --- | --- | --- |
| `doctor` 沒有 TLS/daemon，或缺少引數 | 實際呼叫的是哪個二進位制；`uname -m`；公開 pre.3 與開發 CLI 是否混用 | 換成同架構、同修訂的可信 pq768 構建。不要補造 release 標籤、檔名或盲抄開發引數。 |
| 安裝器拒絕摘要、ELF、路徑或材料 | 摘要是否獨立核對；靜態 ELF/架構；輸入和父目錄屬主、符號連結/硬連結、許可權 | 在私有 staging 重新準備檔案，勿繞過校驗。相同 release id 下輸入變動用新 id。 |
| `config-check` 拒絕、wrapper 退出 `78` | TOML 是否 `0600`、`version = 2`、絕對路徑；`boreas.env` 是否正確；同名 TUN/VIP/對端 `/32` 是否已經存在 | 修正欄位、路徑或本機衝突；先看 `sudo journalctl -u boreas.service -n 100 --no-pager`，不要迴圈重啟。 |
| Core 沒監聽，或 TCP 超時 | `sudo ss -ltnp 'sport = :8443'`；Core 繫結地址；雲安全組和主機防火牆；Edge `ip -4 route get` 指向實際底層地址 | 修復監聽或底層路由；從控制檯恢復管理。不要把預設路由或公用網路底層地址指進 TUN。 |
| `outer handshake` / 外層證書錯誤 | `--tls-name`/SAN、證書鏈、有效期、Edge 的外層 CA；隨後檢查 `--ws-host` | 使用正確證書和信任鏈。SAN 不能用身份檔案或任意 HTTP Host 代替；不要關閉校驗。 |
| 內層認證或 PKI 失敗 | `local.signed` 與配置的槽位/代次、`peer.signed` 是否真為對端、roots 與證書是否屬同一網路 | 用離線可信 CLI 重跑 `pki verify-bundle --require-peer`，核對報告的本地/對端 ID。節點私密金鑰不能從另一端複製。 |
| 狀態過期、策略簽名/回滾錯誤 | 兩端 UTC 時間、簽發序號、有效期、策略檔名、獨立 pin 及實際 `state_dir` | 修復時鐘或準備新簽名輸入；保留持久防回退狀態。根指紋不匹配按稽核過的遷移流程處理。 |
| socket 不存在或許可權不符 | 程序是否已啟動、執行 UID、`state_dir` 和實際 socket 名 | 以同 UID 查正確路徑；不要 chmod 放開訪問。mesh-run 沒有此 socket。 |
| 已連線但 VIP 不通，或只通一邊 | 兩端 `ip -4 route get`、選定源 VIP、`btun0` 地址/MTU、宿主 ICMP 過濾，比較左右收發計數 | 只修授權對端 `/32`；源地址用 `ping -I <本端VIP>` 固定。底層可通不代表簽名電路承載的 VIP 對正確。 |

求助時給出建置產物來源和準確提交/標籤、架構、錯誤階段、脫敏後的 `ctl status` 和短日誌。不要分享私密金鑰、TLS 金鑰日誌、SSH 憑據或整套配置環境。倉庫另有[脫敏診斷採集器](../../tools/diagnostics/README.md)，它不讀取 daemon 配置、金鑰或日誌。

## 8. 無公用網路機器時如何驗證

倉庫的 [TLS 工作流](../../.github/workflows/rust-tls.yml) 用 `tools/release/netns_daemon_smoke.sh` 在隔離 Linux runner 中驗證開發構建的真實 TUN/資料面；這不是拿 pre.3 二進位制執行的指令碼。只在具備 `/dev/net/tun`、網路和掛載名稱空間許可權的可銷燬 runner 上，按工作流同一提交、二進位制和引數執行。舊安裝器、離線雙籤服務與多 Core 有各自測試入口，分別見對應文件。記錄準確的原始碼修訂版本 和實際透過的步驟，不能用普通 Rust 測試或被跳過的裝置步驟代替真實包 I/O。
