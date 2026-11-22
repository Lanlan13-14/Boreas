# Boreas 一鍵安裝：先預演，再啟動

[简体中文](ONE_CLICK.zh-TW.md) · 繁體中文 · [English](ONE_CLICK.en.md)

執行 `tools/deploy/install.sh` 可將**已經建置並由你核對來源**的靜態 Linux 二進位檔安裝至目標主機。該腳本還會檢查組態、預置材料並切換本機版本，完成這些步驟即算完成「安裝」；它不會編譯程式、簽發憑證、自動探索對端，也不會代你放行防火牆。若需測試雙機連通，請先完成[部署教學第 1–3 節](README.zh-TW.md#workflow)。

本流程採用的 `systemd`/`procd` 屬於明確啟用的舊版開發範本，服務將以 root 身分執行；若你需要經過驗證的發佈清單、非特權執行環境與就緒回退（readiness fallback）機制，請改用[離線雙簽 systemd 路徑](VERIFIED-SERVICE.md)，切勿混裝。本文件適用於**目前的相容開發建置**；公開版本 `v0.1.0-pre.3` 並未提供此處所需的 daemon 策略參數。

## 1. 在 Core、Edge 各準備一份輸入

開始安裝前，請在目標主機建立 `/root/boreas-stage`（擁有者為 root，權限 `0700`），並將目錄內所有檔案設為 root 所有、權限 `0600`；二進位輸入檔本身不需預先具備可執行權限。你也可以改用自訂的私有絕對路徑作為目錄。另外需備妥一份已審核的原始碼 checkout（內含 `tools/deploy/install.sh` 及其同目錄範本），後續所有指令皆從該 checkout 根目錄執行。

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

- **成品（Artifact）**：請從獨立可信管道取得 64 位元十六進位 SHA-256（或先驗證受信任的簽章清單），並核對原始碼修訂版本、架構與靜態連結；`sha256sum` 僅能計算本機檔案的雜湊摘要，無法證明檔案來源。安裝程式通過摘要與 ELF 檢查後，便會**執行**候選二進位檔的 `doctor`、`config-migrate`、`config-check` 與 `pki verify-bundle`。因此，真實性驗證必須在執行安裝程式之前完成，絕不可讓候選檔案替自己作證。
- **網路信任**：請依[簽發步驟](README.zh-TW.md#offline-issuance)準備材料，並使用可信的 CLI 執行 `pki verify-policy` 預先檢查；兩個網路根 pin 必須獨立預配，不可放入 `material/`。安裝腳本只會校驗路徑與權限，不會驗證策略雙簽；daemon 啟動時仍會依據 pin 驗簽並記錄水位（watermark），若驗證失敗則不會承載業務流量。
- **檔案與路徑**：材料目錄僅允許放置節點套件檔案與對端身分，嚴禁放入離線 CA 私鑰、未知檔案、符號連結、特殊檔案或子目錄；策略與 pin 必須為非空、單一硬連結的普通檔案，且其父目錄也必須可信。安裝目標 `/opt/boreas` 與預設 `/usr/local/bin` 不可為符號連結，亦不可允許群組或其他使用者寫入；若使用 `--bindir`，指定目錄必須預先存在。切勿將安裝前綴設於 `/tmp` 或重複使用系統目錄。完整規則請參閱[策略與狀態](POLICY-STATE.md)。
- **工具**：目標主機須備妥完整的 Linux `iproute2`、`readelf`、`sha256sum` 及通用 POSIX shell 工具；腳本不會自動安裝相依套件。若透過遠端連線操作，請先確認管理連線路徑不會經過即將建立的 TUN 介面。

## 2. 使用同一組參數預演與安裝

請先將下方兩個 `REPLACE_…` 預留位置替換為實際值。該函式僅供重複使用安裝指令；若切換終端機需重新定義。執行正式安裝前，請務必先加上 `--dry-run` 進行預演，以檢視預期落盤路徑與服務類型；若輸入檔為 root 所有，預演時也必須使用相同的 UID。

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

預演模式屬於唯讀操作：不會下載任何檔案、不會寫入目標路徑，也不會執行候選二進位檔或服務管理員。由於它僅檢查摘要、ELF 格式、路徑與檔案來源，預演通過並不代表組態或策略驗簽必然成功。`--url` 並非本教學採用的路線：腳本只接受直接的 HTTPS 二進位檔 URL，且要求加上 `--accept-weak-https`，依然無法驗證發佈簽章。

僅在預演結果與信任檢查皆確認無誤後，才可執行正式安裝。若只需安裝版本與執行檔入口而不需建立服務，請改用 `--service none`（預演時亦須使用相同模式）。若目標主機已在執行 `boreas.service`，請先規劃停機維護並檢查現有服務與路徑，切勿直接套用首次安裝流程；舊版範本無法替換離線雙簽服務。

```sh
install_boreas --service systemd --accept-legacy-service
sudo cat /opt/boreas/active
sudo /usr/local/bin/boreas doctor
```

安裝程式預設**不會啟動**服務。執行後，`active` 應輸出 `local-eval-1`，`doctor` 應顯示該二進位檔具備 daemon 與 TLS 支援。`/opt/boreas` 的權限為 `0700`，本範例中的 dispatcher 與執行狀態皆由 root 存取。安裝後的目錄配置如下：

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

`config-migrate` 會產生 `version = 2` 組態且不修改來源檔案；安裝程式則會核對 `net_id`，並將 `[paths]` 下的 `identity_key`、`roots` 與 `state_dir` 改寫為作用中版本對應的私鑰、roots 與共用狀態目錄。其餘組態內容仍需由你自行審核。安裝完成後，預設 `/usr/local/bin` 中的 `boreas` 與 `boreas-easy` 入口會指向 dispatcher。

## 3. 寫入本機角色與啟動參數

確認 `/etc/boreas` 未被其他服務佔用後，請建立擁有者為 root 的非符號連結目錄（權限 `0700`）與 `/etc/boreas/boreas.env`（普通檔案，權限精確設為 `0600`）。新檔案可使用以下兩條指令建立；**第二條指令會清空現有檔案內容，僅供首次建立時執行**。建立後請以管理員身分編輯該檔案，僅寫入符合本機角色的設定，切勿將兩段組態合併寫入。

```sh
sudo install -d -m 0700 -o root -g root /etc/boreas
sudo install -m 0600 -o root -g root /dev/null /etc/boreas/boreas.env
```

Core（監聽連接埠須由安全群組及防火牆放行）：

```ini
BOREAS_ROLE=core
BOREAS_VIP=10.20.1.1
BOREAS_PEER_VIP=10.20.1.2
BOREAS_LISTEN=0.0.0.0:8443
BOREAS_TUN_NAME=btun0
BOREAS_MTU=1360
```

Edge（請替換底層 IP 並核對憑證 SAN，不要填寫通道 VIP）：

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

VIP 必須使用簽章身分中屬於 RFC1918 網段的位址，不可包含 `/32`，且不允許前導零；底層監聽與撥號位址須為數字 IPv4 加上連接埠；TUN 介面名稱不得超過 15 個字元；wrapper 允許的 MTU 範圍為 `1280..1400`。請勿預先建立同名介面或對端 `/32` 路由，wrapper 會自行建立執行期資源，若發生衝突將拒絕啟動且不會覆蓋現有網路設定。服務停止時，wrapper 僅會嘗試撤銷自身新增的位址與路由，不會清空路由表，亦不會變更預設路由、防火牆或主機 DNS。

啟動順序上，請先在 Core 執行 `daemon-reload` 與 `start`，待確認 Core 已開始監聽 TCP 連接埠後，再於 Edge 執行相同的兩條指令。請務必等到[雙向驗收](README.zh-TW.md#verify-and-maintain)通過後，再考慮透過 `enable` 設定開機自動啟動。

```sh
sudo systemctl daemon-reload
sudo systemctl start boreas.service
sudo systemctl status boreas.service
sudo journalctl -u boreas.service -n 100 --no-pager
```

`Type=simple` 顯示為 `active` 並不代表交握、路由或流量已正常運作。請直接查詢實際 daemon 的執行狀態：

```sh
sudo /usr/local/bin/boreas ctl status --socket /opt/boreas/state/control.sock
sudo /usr/local/bin/boreas-easy --socket /opt/boreas/state/control.sock --service boreas
```

確認需啟用開機自動啟動時，請執行 `sudo systemctl enable boreas.service`。升級版本後，執行中的程序不會隨著 `active` 切換而自動替換；請先審核變更並依排程執行 `sudo systemctl restart boreas.service`，再重新完成雙向驗收。你亦可明確傳入 `--start` 來啟用並（重新）啟動服務，但該選項要求事先備妥合規的 `boreas.env` 且不會驗證資料面連通性，因此本手冊刻意採用分步驟檢查。

### 僅供評估的 procd 範本

若加上 `--service procd --accept-legacy-service`，舊版範本將會產生 `/etc/init.d/boreas`；環境檔案格式與前述相同。該範本採白名單機制讀取字面 `KEY=VALUE`，內容嚴禁加上引號、行尾註解、空白字元、變數展開或 CRLF 換行字元。目標主機必須具備完整的 `iproute2`、Linux TUN 及其他相依工具；提供此範本並不表示已驗證過 BusyBox `ip` 或實體 OpenWrt 裝置。請先在目標映像檔的不啟動模式下審閱路徑、工具與架構；若缺乏對應的驗證環境，請改走 Linux/systemd 路徑。

## 4. 安裝失敗、停止與回退

- **預演遭到拒絕**：優先檢視第一條錯誤訊息。檢查目標落盤路徑的各級父目錄權限、材料 allowlist、兩個 pin 是否置於材料目錄之外、三份策略檔是否夾帶多餘檔案，以及靜態 ELF 格式與架構是否相符。切勿放寬目錄權限或忽略摘要檢查失敗。
- **安裝失敗**：安裝鎖 `<prefix>/.install.lock` 用於將安裝作業序列化；若發現遺留的鎖定檔案，請先調查原因，切勿直接搶占。`active` 指標會在最後切換；若切換後安裝步驟明確失敗，安裝程式會嘗試恢復舊指標，但已發佈的檔案仍可能保留於磁碟中。`sync` 並不構成斷電安全性驗收。事後請務必核對 `active`、系統日誌與實際執行中的程序，不可將指標恢復誤判為舊服務已正常運行。
- **服務啟動失敗或反覆重啟**：請先執行 `sudo systemctl stop boreas.service` 並檢查日誌。退出碼 `78` 代表舊版 wrapper 因組態問題拒絕啟動，範本不會針對此退出碼執行重啟；一般錯誤則設有重啟次數上限。已安裝的服務不會因為執行期故障而自動回退版本。
- **升級與手動回退**：相同的 release id 僅接受位元組完全一致的輸入，任何修改皆須使用新的 id；歷史代際不會被覆寫。若需回退，請先停止服務，審核舊成品、舊策略及現有持久狀態是否仍相容且有效，再依[策略狀態與回退語意](POLICY-STATE.md#6-升级--start-与回滚)恢復指標、啟動服務並重新驗收。嚴禁透過刪除 `status.state` / `policy.state` 或降低授權水位（watermark）的方式來進行恢復。

### 如何區分測試證據

- `tools/deploy/test-install.sh` 為隔離的 shell 迴歸測試（使用模擬系統工具，不以 root 執行，也不會在已有 Boreas 服務的主機上運行）。該測試僅驗證檔案來源、路徑、權限、版本指標與 wrapper 約束，無法證明真實的封包傳輸能力。
- `tools/deploy/test-real-install.sh` 會在 [deploy 工作流程](../../.github/workflows/deploy.yml)的受控 runner 上以 `--service none` 驗證靜態安裝；該測試不會啟動服務或執行現場 TUN 驗收。如需真實資料面的驗證證據，請參閱 [TLS 工作流程](../../.github/workflows/rust-tls.yml)與[雙機驗收清單](README.zh-TW.md#verify-and-maintain)。
