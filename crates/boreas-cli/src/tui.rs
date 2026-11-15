//! Pure 9-row console menu and dangerous-confirmation checks.
//!
//! Master plan §10.4 / §10.4.1: a trilingual (zh-CN / zh-TW / en) first
//! screen, no Emoji, no ANSI, `NO_COLOR` honored by never emitting color,
//! and a 77-column x 18-line box only when the caller says the terminal is
//! wide enough. A narrow terminal gets a plain list and is never claimed to
//! be 77 columns. There is no stdin, no raw mode, no DSR probe and no
//! control socket here: [`render_menu`] only formats a [`MenuModel`] the
//! caller already built.
//!
//! [`confirm_dangerous`] compares a typed phrase and returns. It does not
//! change the security mode, revoke a node, uninstall anything, or talk to
//! a daemon. Recording that a phrase matched is not applying the action.

use std::fmt::{Display, Formatter};

use crate::i18n::{Lang, Msg, text};
use crate::render::{BOX_WIDTH, display_width};

/// Inner content width of the boxed screen: total minus the two border
/// columns and one padding space on each side. Same basis as
/// `render::render_status`.
const INNER_WIDTH: usize = BOX_WIDTH - 4;

/// Display columns reserved for a menu entry title. The §10.4.1 examples
/// pin the description at the same column in every language.
const TITLE_COLS: usize = 16;

/// Left status column (`NODE` … `MEM`) before the right-pinned field.
/// 36 inner columns puts `MODE` / `IN` / `AUTH` / `GUARD` at display
/// column 38, which is where the §10.4.1 examples place them.
const LEFT_FIELD_COLS: usize = 36;

/// Fixed row count of the boxed §10.4.1 screen (title, four status rows,
/// rule, nine entries, rule, hint, bottom border).
pub const MENU_LINES: usize = 18;

/// Errors from rendering one menu screen. A hostile field is rejected
/// outright (not substituted) so a control character cannot reach a terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MenuError {
    /// `selected` was outside `1..=9`.
    BadSelection,
    /// A free-text field contained a control character, ESC, a newline, or
    /// a CSI-style escape. Refused so it cannot inject into a log or a
    /// terminal (§10.4).
    Injection,
}

impl Display for MenuError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MenuError::BadSelection => write!(f, "menu selection must be 1..=9"),
            MenuError::Injection => {
                write!(
                    f,
                    "menu field rejected: control character or terminal escape"
                )
            }
        }
    }
}

impl std::error::Error for MenuError {}

/// Caller-supplied menu snapshot. Every string is untrusted display data.
///
/// `narrow` asks for the degraded list (§10.4: a too-narrow terminal must
/// not claim 77 columns). `no_color` is recorded for the caller; this
/// renderer never emits `0x1B` on either path, so `NO_COLOR` is not a
/// permission to add color.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuModel {
    pub version: String,
    pub platform: String,
    pub lang: Lang,
    pub node_name: String,
    pub role: String,
    pub mode_label: String,
    pub tun_label: String,
    pub inbound_label: String,
    pub mesh_label: String,
    pub auth_label: String,
    pub mem_label: String,
    pub guard_label: String,
    /// Highlighted entry, `1..=9`.
    pub selected: u8,
    /// Render the non-boxed list instead of the 77-column frame.
    pub narrow: bool,
    /// Caller observed a non-empty `NO_COLOR`. Does not change bytes today.
    pub no_color: bool,
}

impl MenuModel {
    /// Honest offline placeholder: no daemon was contacted, the displayed
    /// security mode is the production default `e2e-required` (§1.3) and
    /// entry 1 is selected. Counters are not invented.
    pub fn offline(version: &str, lang: Lang) -> MenuModel {
        MenuModel {
            version: version.to_string(),
            platform: String::new(),
            lang,
            node_name: String::new(),
            role: String::new(),
            mode_label: "e2e-required".to_string(),
            tun_label: "off".to_string(),
            inbound_label: "off".to_string(),
            mesh_label: "offline".to_string(),
            auth_label: "none".to_string(),
            mem_label: "n/a".to_string(),
            guard_label: "n/a".to_string(),
            selected: 1,
            narrow: false,
            no_color: false,
        }
    }

    /// Stable JSON for non-TTY / `--json`. `daemon` is always `false`: this
    /// slice has no control socket and must not invent a live mesh.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"command\":\"menu\",\"lang\":\"{}\",\"version\":\"{}\",",
                "\"platform\":\"{}\",\"node_name\":\"{}\",\"role\":\"{}\",",
                "\"mode\":\"{}\",\"tun\":\"{}\",\"inbound\":\"{}\",\"mesh\":\"{}\",",
                "\"auth\":\"{}\",\"mem\":\"{}\",\"guard\":\"{}\",",
                "\"selected\":{},\"narrow\":{},\"no_color\":{},",
                "\"daemon\":false,\"console_menu\":true}}"
            ),
            self.lang.code(),
            json_escape(&self.version),
            json_escape(&self.platform),
            json_escape(&self.node_name),
            json_escape(&self.role),
            json_escape(&self.mode_label),
            json_escape(&self.tun_label),
            json_escape(&self.inbound_label),
            json_escape(&self.mesh_label),
            json_escape(&self.auth_label),
            json_escape(&self.mem_label),
            json_escape(&self.guard_label),
            self.selected,
            self.narrow,
            self.no_color,
        )
    }
}

/// Render the §10.4.1 menu. Boxed output is exactly [`MENU_LINES`] lines of
/// exactly [`BOX_WIDTH`] display columns. Narrow output is one line per
/// entry plus a status line and contains no box-drawing.
///
/// Returns [`MenuError::Injection`] when `node_name` or any other free-text
/// field contains a C0/C1 control, ESC (`0x1B`), a newline, or a CSI
/// introducer. Does not read stdin and does not query a daemon.
pub fn render_menu(model: &MenuModel) -> Result<String, MenuError> {
    if !(1..=9).contains(&model.selected) {
        return Err(MenuError::BadSelection);
    }
    for field in free_text_fields(model) {
        if contains_injection(field) {
            return Err(MenuError::Injection);
        }
    }
    if model.narrow {
        Ok(render_narrow(model))
    } else {
        Ok(render_boxed(model))
    }
}

fn free_text_fields(model: &MenuModel) -> [&str; 11] {
    [
        model.version.as_str(),
        model.platform.as_str(),
        model.node_name.as_str(),
        model.role.as_str(),
        model.mode_label.as_str(),
        model.tun_label.as_str(),
        model.inbound_label.as_str(),
        model.mesh_label.as_str(),
        model.auth_label.as_str(),
        model.mem_label.as_str(),
        model.guard_label.as_str(),
    ]
}

/// Control characters (including ESC, newline and the 8-bit CSI `0x9B`).
/// `ESC` is itself a control, so a CSI sequence (`ESC [` …) is covered.
/// A literal `[` without a preceding control is ordinary text and is allowed.
fn contains_injection(value: &str) -> bool {
    value.chars().any(|c| c.is_control() || c == '\u{9B}')
}

fn render_boxed(model: &MenuModel) -> String {
    let mut lines = Vec::with_capacity(MENU_LINES);
    lines.push(title_line(model));
    let (row_tun_right, row_mesh_left, row_mesh_right) = status_keys(model.lang);
    lines.push(field_row(
        text(model.lang, Msg::NodeLabel),
        &node_value(model),
        text(model.lang, Msg::ModeLabel),
        &model.mode_label,
    ));
    lines.push(field_row(
        "TUN",
        &model.tun_label,
        row_tun_right,
        &model.inbound_label,
    ));
    lines.push(field_row(
        row_mesh_left,
        &model.mesh_label,
        row_mesh_right,
        &model.auth_label,
    ));
    lines.push(field_row(
        "MEM",
        &model.mem_label,
        "GUARD",
        &model.guard_label,
    ));
    lines.push(rule('├', '┤'));
    for index in 1..=9 {
        lines.push(entry_row(model, index));
    }
    lines.push(rule('├', '┤'));
    lines.push(row(&hint_line(model.lang)));
    lines.push(rule('└', '┘'));
    lines.join("\n")
}

fn title_line(model: &MenuModel) -> String {
    let left = format!("─ {} ", text(model.lang, Msg::ConsoleTitle));
    let platform = if model.platform.is_empty() {
        "offline".to_string()
    } else {
        model.platform.clone()
    };
    let right = format!(
        " v{} / {platform} / [L] {} ",
        model.version,
        text(model.lang, Msg::LangLabel)
    );
    let fill = BOX_WIDTH
        .saturating_sub(2)
        .saturating_sub(display_width(&left))
        .saturating_sub(display_width(&right));
    let line = format!("┌{left}{}{right}┐", "─".repeat(fill));
    // A hostile-but-legal (no controls) version/platform can still be wider
    // than the reserved title. Fit rather than emit a ragged frame.
    fit_line(&line)
}

/// §10.4.1 status keys differ by screen kind: a core shows IN/MESH/AUTH,
/// the Traditional example (an edge) shows AUTH/UPLINK/BACKUP. The language
/// selects which published skeleton this pure renderer matches.
fn status_keys(lang: Lang) -> (&'static str, &'static str, &'static str) {
    match lang {
        Lang::ZhTw => ("AUTH", "UPLINK", "BACKUP"),
        Lang::ZhCn | Lang::En => ("IN", "MESH", "AUTH"),
    }
}

fn node_value(model: &MenuModel) -> String {
    let name = if model.node_name.is_empty() {
        text(model.lang, Msg::UnknownNode).to_string()
    } else {
        model.node_name.clone()
    };
    if model.role.is_empty() {
        name
    } else {
        format!("{name} / {}", model.role)
    }
}

fn field_row(left_key: &str, left_value: &str, right_key: &str, right_value: &str) -> String {
    // Leading space matches the §10.4.1 examples (`│  NODE`). It lives
    // inside the 36-column left field so the right key stays at column 38.
    let left = format!(" {left_key:<7}{left_value}");
    let right = format!("{right_key:<8} {right_value}");
    let left_fit = fit_cols(&left, LEFT_FIELD_COLS);
    let gap = INNER_WIDTH.saturating_sub(LEFT_FIELD_COLS);
    let right_fit = fit_cols(&right, gap);
    row(&format!("{left_fit}{right_fit}"))
}

fn entry_row(model: &MenuModel, index: u8) -> String {
    let (title, detail) = entry_copy(model.lang, index);
    let marker = if model.selected == index { ">" } else { " " };
    let head = format!(" {marker} [{index}] ");
    let title_fit = fit_cols(title, TITLE_COLS);
    let used = display_width(&head) + TITLE_COLS + 1;
    let detail_fit = fit_cols(detail, INNER_WIDTH.saturating_sub(used));
    row(&format!("{head}{title_fit} {detail_fit}"))
}

fn hint_line(lang: Lang) -> String {
    // Leading space: the hint sits two cells inside the border, like the
    // status rows. `row` adds the other cell.
    match lang {
        Lang::ZhCn => {
            " [j/k] 移动  [1-9] 直达  [Enter] 执行  [L] 简/繁/EN  [r] 刷新  [q] 退出".to_string()
        }
        Lang::ZhTw => {
            " [j/k] 移動  [1-9] 直達  [Enter] 執行  [L] 簡/繁/EN  [r] 重整  [q] 離開".to_string()
        }
        Lang::En => {
            " [j/k] Move  [1-9] Jump  [Enter] Run   [L] zh/繁/EN  [r] Sync  [q] Quit".to_string()
        }
    }
}

/// Static 9-entry copy. Titles are padded to [`TITLE_COLS`] by the caller.
/// Latin tokens (`Enrollment`, `DirectGrant`, `e2e-required`, `supervisor`)
/// stay untranslated, matching §10.4.1.
fn entry_copy(lang: Lang, index: u8) -> (&'static str, &'static str) {
    match (lang, index) {
        (Lang::ZhCn, 1) => (
            "实时链路遥测",
            "内外层 KEX / 证书新鲜度 / RTT / 电路与窗口信用",
        ),
        (Lang::ZhCn, 2) => (
            "身份注册与直连",
            "Enrollment 状态 / CDN-DIR 监听 / DirectGrant",
        ),
        (Lang::ZhCn, 3) => (
            "核心互联与上行",
            "核心网格 DIR-CDN 自动择优 / 边缘主备上行切路",
        ),
        (Lang::ZhCn, 4) => (
            "目录租约与路由",
            "身份-挂靠-LSA 名录 / 子网路由裁决 / 权威 DNS",
        ),
        (Lang::ZhCn, 5) => (
            "压测与回源探针",
            "boreas bench 分层开销 / probe 回源与流控检测",
        ),
        (Lang::ZhCn, 6) => (
            "安全模式与吊销",
            "e2e-required 策略 / 状态快照与吊销 / RPF 审计",
        ),
        (Lang::ZhCn, 7) => ("可恢复热升级", "独立验双签清单 / 升级日志切换 / supervisor"),
        (Lang::ZhCn, 8) => (
            "服务与脱敏诊断",
            "启停守护进程 / 净化控制符日志 / 导出脱敏诊断包",
        ),
        (Lang::ZhCn, 9) => (
            "解绑或干净卸载",
            "撤销挂靠租约 / 清理本实例网卡、规则与版本目录",
        ),
        (Lang::ZhTw, 1) => (
            "即時鏈路遙測",
            "內外層 KEX / 憑證新鮮度 / RTT / 電路與視窗信用",
        ),
        (Lang::ZhTw, 2) => (
            "身分註冊與憑證",
            "檢視 NodeIdentity / 申請憑證續期 / DirectGrant",
        ),
        (Lang::ZhTw, 3) => (
            "核心互聯與上行",
            "主備上行切換 / 授權 DIR-CDN 擇優與路徑探測",
        ),
        (Lang::ZhTw, 4) => (
            "目錄租約與路由",
            "查詢名錄 / 通告與接受子網路由 / 內網權威 DNS",
        ),
        (Lang::ZhTw, 5) => (
            "壓測與回源探針",
            "boreas bench 分層開銷 / probe 回源與流控檢測",
        ),
        (Lang::ZhTw, 6) => (
            "安全模式與吊銷",
            "e2e-required 策略 / 狀態快照與吊銷 / 本機審計",
        ),
        (Lang::ZhTw, 7) => (
            "可恢復熱升級",
            "獨立驗雙簽章清單 / 升級日誌切換 / 外部守護回退",
        ),
        (Lang::ZhTw, 8) => (
            "服務與脫敏診斷",
            "啟停守護行程 / 淨化控制符日誌 / 匯出脫敏診斷包",
        ),
        (Lang::ZhTw, 9) => (
            "解綁或解除安裝",
            "撤銷掛靠租約 / 清理本實例網卡、規則與版本目錄",
        ),
        (Lang::En, 1) => (
            "Live Telemetry",
            "Outer/inner KEX, cert freshness, RTT, circuits",
        ),
        (Lang::En, 2) => (
            "Identity & DIR",
            "Enrollment status, CDN/DIR listener, DirectGrant",
        ),
        (Lang::En, 3) => (
            "Mesh & Uplinks",
            "Core/auth-edge DIR-CDN path select and uplinks",
        ),
        (Lang::En, 4) => (
            "Directory/Routes",
            "Identity, lease, LSA, subnet conflict, auth DNS",
        ),
        (Lang::En, 5) => (
            "Bench & Probe",
            "boreas bench layer cost or probe CDN flow-ctrl",
        ),
        (Lang::En, 6) => (
            "Mode & Revoke",
            "e2e-required policy, status snapshot, RPF audit",
        ),
        (Lang::En, 7) => (
            "Safe Upgrade",
            "Verify dual-sig manifest, journal & supervisor",
        ),
        (Lang::En, 8) => (
            "Service & Diag",
            "Manage daemon, sanitized logs, redacted bundle",
        ),
        (Lang::En, 9) => (
            "Leave/Uninstall",
            "Revoke lease or purge owned TUN, rules & files",
        ),
        _ => ("", ""),
    }
}

/// Narrow-terminal degradation: a status line plus the nine entries, no
/// box-drawing characters, no claim of 77 columns (§10.4).
fn render_narrow(model: &MenuModel) -> String {
    let mut lines = Vec::with_capacity(10);
    lines.push(format!(
        "{} {} {} {} sel={}",
        text(model.lang, Msg::ConsoleTitle),
        model.version,
        node_value(model),
        model.mode_label,
        model.selected
    ));
    for index in 1..=9 {
        let (title, detail) = entry_copy(model.lang, index);
        let marker = if model.selected == index { ">" } else { " " };
        lines.push(format!("{marker} [{index}] {title}  {detail}"));
    }
    lines.join("\n")
}

fn rule(left: char, right: char) -> String {
    format!("{left}{}{right}", "─".repeat(BOX_WIDTH - 2))
}

fn row(inner: &str) -> String {
    format!("│ {} │", fit_cols(inner, INNER_WIDTH))
}

/// Truncate to at most `max_cols` display columns without splitting a wide
/// character, then pad with spaces. Width class is [`display_width`].
fn fit_cols(value: &str, max_cols: usize) -> String {
    let mut out = String::new();
    let mut width = 0usize;
    for c in value.chars() {
        let w = display_width(c.encode_utf8(&mut [0; 4]));
        if width + w > max_cols {
            break;
        }
        out.push(c);
        width += w;
    }
    while width < max_cols {
        out.push(' ');
        width += 1;
    }
    out
}

/// Force one already-built frame line back to [`BOX_WIDTH`] columns.
/// A legal-but-huge version or platform would otherwise make the title
/// wider than the frame; truncating keeps every boxed line at 77.
fn fit_line(line: &str) -> String {
    fit_cols(line, BOX_WIDTH)
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// An action that would be dangerous if a daemon existed. Confirming it
/// here only checks the typed phrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DangerAction {
    /// Switch the security mode to hop-only (§1.3). Not performed.
    HopOnly,
    /// Revoke the node whose decimal id is `node_id`. Not performed.
    Revoke { node_id: u64 },
    /// Uninstall this instance. Not performed.
    Uninstall,
}

/// Why a typed confirmation was refused. Absence of [`ConfirmError`] means
/// the phrase matched and nothing else: the action was not applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmError {
    /// `typed` was not the exact required phrase.
    Mismatch,
    /// `typed` contained a newline, ESC, or another control character.
    Injection,
}

impl Display for ConfirmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfirmError::Mismatch => write!(f, "confirmation phrase did not match"),
            ConfirmError::Injection => {
                write!(f, "confirmation rejected: control character or newline")
            }
        }
    }
}

impl std::error::Error for ConfirmError {}

/// Compare `typed` with the exact phrase for `action`.
///
/// Accepts only the full phrase and nothing else: no surrounding whitespace,
/// no trailing newline, no case folding.
///
/// - [`DangerAction::HopOnly`] requires `HOP-ONLY`
/// - [`DangerAction::Revoke`] requires `REVOKE {node_id}` (decimal)
/// - [`DangerAction::Uninstall`] requires `UNINSTALL`
///
/// This function does **not** perform the action. It does not change mode,
/// revoke a certificate, delete files, or contact a daemon. `Ok(())` means
/// the phrase matched.
pub fn confirm_dangerous(action: &DangerAction, typed: &str) -> Result<(), ConfirmError> {
    if typed.chars().any(|c| c.is_control()) {
        return Err(ConfirmError::Injection);
    }
    let expected = match action {
        DangerAction::HopOnly => "HOP-ONLY".to_string(),
        DangerAction::Revoke { node_id } => format!("REVOKE {node_id}"),
        DangerAction::Uninstall => "UNINSTALL".to_string(),
    };
    if typed == expected {
        Ok(())
    } else {
        Err(ConfirmError::Mismatch)
    }
}

/// Box-drawing used by the wide screen. Narrow output must contain none.
#[cfg(test)]
const BOX_DRAWING: &[char] = &['┌', '┐', '└', '┘', '├', '┤', '─', '│'];

/// Emoji / pictograph ranges that must never appear (§10.4.1: 0 Emoji).
#[cfg(test)]
fn is_emoji(cp: u32) -> bool {
    matches!(
        cp,
        0x00A9 | 0x00AE
            | 0x203C | 0x2049 | 0x2122 | 0x2139
            | 0x2194..=0x21AA
            | 0x231A..=0x231B | 0x2328 | 0x23CF | 0x23E9..=0x23FA
            | 0x24C2 | 0x25AA..=0x25FE | 0x2600..=0x27BF
            | 0x2934..=0x2935 | 0x2B00..=0x2BFF | 0x3030 | 0x303D | 0x3297 | 0x3299
            | 0xFE0F
            | 0x1F000..=0x1FAFF
            | 0x200D
    )
}

/// §10.4.1 zh-CN oracle (core #3, e2e-req / pq768). Exact 18 lines.
#[cfg(test)]
const ZH_CN_ORACLE: &str = "\
┌─ BOREAS CONSOLE ──────────────────────── v1.11.0 / linux-arm64 / [L] 简中 ┐
│  NODE   hub-us-c / core #3          MODE     * e2e-req / pq768 / p1842    │
│  TUN    boreas0 / 10.20.3.1/16      IN       * :443 CDN / 195c / 16p      │
│  MESH   * 7/7 cores (5 DIR / 2 CDN) AUTH     * mldsa65 / snap 12m         │
│  MEM    RSS 68.4M / Slab 9.1/32M    GUARD    Drop 0 / Hs 2/32 / Ckt 42    │
├───────────────────────────────────────────────────────────────────────────┤
│  > [1] 实时链路遥测     内外层 KEX / 证书新鲜度 / RTT / 电路与窗口信用    │
│    [2] 身份注册与直连   Enrollment 状态 / CDN-DIR 监听 / DirectGrant      │
│    [3] 核心互联与上行   核心网格 DIR-CDN 自动择优 / 边缘主备上行切路      │
│    [4] 目录租约与路由   身份-挂靠-LSA 名录 / 子网路由裁决 / 权威 DNS      │
│    [5] 压测与回源探针   boreas bench 分层开销 / probe 回源与流控检测      │
│    [6] 安全模式与吊销   e2e-required 策略 / 状态快照与吊销 / RPF 审计     │
│    [7] 可恢复热升级     独立验双签清单 / 升级日志切换 / supervisor        │
│    [8] 服务与脱敏诊断   启停守护进程 / 净化控制符日志 / 导出脱敏诊断包    │
│    [9] 解绑或干净卸载   撤销挂靠租约 / 清理本实例网卡、规则与版本目录     │
├───────────────────────────────────────────────────────────────────────────┤
│  [j/k] 移动  [1-9] 直达  [Enter] 执行  [L] 简/繁/EN  [r] 刷新  [q] 退出   │
└───────────────────────────────────────────────────────────────────────────┘";

#[cfg(test)]
mod tests {
    use super::{
        BOX_DRAWING, BOX_WIDTH, DangerAction, MENU_LINES, MenuError, MenuModel, ZH_CN_ORACLE,
        confirm_dangerous, display_width, is_emoji, render_menu,
    };
    use crate::i18n::Lang;

    fn plan_zh() -> MenuModel {
        MenuModel {
            version: "1.11.0".to_string(),
            platform: "linux-arm64".to_string(),
            lang: Lang::ZhCn,
            node_name: "hub-us-c".to_string(),
            role: "core #3".to_string(),
            mode_label: "* e2e-req / pq768 / p1842".to_string(),
            tun_label: "boreas0 / 10.20.3.1/16".to_string(),
            inbound_label: "* :443 CDN / 195c / 16p".to_string(),
            mesh_label: "* 7/7 cores (5 DIR / 2 CDN)".to_string(),
            auth_label: "* mldsa65 / snap 12m".to_string(),
            mem_label: "RSS 68.4M / Slab 9.1/32M".to_string(),
            guard_label: "Drop 0 / Hs 2/32 / Ckt 42".to_string(),
            selected: 1,
            narrow: false,
            no_color: false,
        }
    }

    fn plan_tw() -> MenuModel {
        MenuModel {
            version: "1.11.0".to_string(),
            platform: "linux-amd64".to_string(),
            lang: Lang::ZhTw,
            node_name: "edge-la-02".to_string(),
            role: "edge".to_string(),
            mode_label: "* e2e-req / pq768 / p2091".to_string(),
            tun_label: "boreas0 / 10.20.3.27/16".to_string(),
            inbound_label: "* mldsa65 / snap 11m / g1".to_string(),
            mesh_label: "* hub-us-c CDN 31ms 4/4".to_string(),
            auth_label: "+ hub-us-d CDN 35ms 1/1".to_string(),
            mem_label: "RSS 28.6M / Slab 1.8/8M".to_string(),
            guard_label: "Drop 0 / Dir OFF / Ckt 6".to_string(),
            selected: 1,
            narrow: false,
            no_color: true,
        }
    }

    fn plan_en() -> MenuModel {
        MenuModel {
            version: "1.11.0".to_string(),
            platform: "linux-arm64".to_string(),
            lang: Lang::En,
            node_name: "hub-asia-a".to_string(),
            role: "core #1".to_string(),
            mode_label: "* e2e-req / pq768 / p1408".to_string(),
            tun_label: "boreas0 / 10.20.1.1/16".to_string(),
            inbound_label: "* :443 CDN / 195c / 16p".to_string(),
            mesh_label: "~ 6/7 cores (4 DIR / 2 CDN)".to_string(),
            auth_label: "* mldsa65 / snap 09m".to_string(),
            mem_label: "RSS 64.2M / Slab 9.2/32M".to_string(),
            guard_label: "Drop 0 / Hs 3/32 / Ckt 38".to_string(),
            selected: 1,
            narrow: false,
            no_color: false,
        }
    }

    fn assert_boxed(rendered: &str) {
        let lines: Vec<&str> = rendered.split('\n').collect();
        assert_eq!(lines.len(), MENU_LINES);
        for line in &lines {
            assert_eq!(display_width(line), BOX_WIDTH, "{line:?}");
            assert!(!line.as_bytes().contains(&0x1B));
            for c in line.chars() {
                assert!(!is_emoji(c as u32), "U+{:04X}", c as u32);
            }
        }
    }

    #[test]
    fn zh_cn_oracle_is_18_by_77_and_has_no_emoji() {
        let lines: Vec<&str> = ZH_CN_ORACLE.split('\n').collect();
        assert_eq!(lines.len(), 18);
        for line in &lines {
            assert_eq!(display_width(line), 77, "{line:?}");
            for c in line.chars() {
                assert!(!is_emoji(c as u32));
            }
        }
    }

    #[test]
    fn zh_cn_plan_skeleton_matches_the_oracle() {
        let rendered = render_menu(&plan_zh()).expect("plan model");
        assert_eq!(rendered, ZH_CN_ORACLE);
        assert_boxed(&rendered);
    }

    #[test]
    fn three_languages_are_18_lines_of_77_columns() {
        for model in [plan_zh(), plan_tw(), plan_en()] {
            let rendered = render_menu(&model).expect("render");
            assert_boxed(&rendered);
            assert!(rendered.contains("BOREAS CONSOLE"));
        }
        let zh = render_menu(&plan_zh()).unwrap();
        assert!(zh.contains("实时链路遥测"));
        assert!(zh.contains("[L] 简中"));
        let tw = render_menu(&plan_tw()).unwrap();
        assert!(tw.contains("即時鏈路遙測"));
        assert!(tw.contains("[L] 繁中"));
        let en = render_menu(&plan_en()).unwrap();
        assert!(en.contains("Live Telemetry"));
        assert!(en.contains("[L] EN"));
    }

    #[test]
    fn selected_entry_is_marked_and_others_are_not() {
        let mut model = plan_en();
        model.selected = 6;
        let rendered = render_menu(&model).unwrap();
        assert!(rendered.contains("> [6] Mode & Revoke"));
        assert!(rendered.contains("  [1] Live Telemetry"));
        assert!(!rendered.contains("> [1]"));
    }

    #[test]
    fn narrow_list_has_no_box_drawing_and_is_not_77_wide() {
        let mut model = plan_zh();
        model.narrow = true;
        let rendered = render_menu(&model).unwrap();
        for glyph in BOX_DRAWING {
            assert!(!rendered.contains(*glyph), "box glyph {glyph}");
        }
        let lines: Vec<&str> = rendered.split('\n').collect();
        assert_eq!(lines.len(), 10);
        assert!(lines.iter().any(|line| display_width(line) != BOX_WIDTH));
        assert!(rendered.contains("> [1] 实时链路遥测"));
        assert!(rendered.contains("[9] 解绑或干净卸载"));
        assert!(!rendered.as_bytes().contains(&0x1B));
    }

    #[test]
    fn no_color_and_default_emit_zero_escapes() {
        for mut model in [plan_zh(), plan_en(), plan_tw()] {
            model.no_color = false;
            let plain = render_menu(&model).unwrap();
            model.no_color = true;
            let muted = render_menu(&model).unwrap();
            assert!(!plain.as_bytes().contains(&0x1B));
            assert!(!muted.as_bytes().contains(&0x1B));
            assert_eq!(plain, muted);
        }
    }

    #[test]
    fn free_text_injection_is_rejected() {
        let samples = [
            "hub\nnext",
            "hub\r",
            "hub\u{1b}[31m",
            "hub\u{1b}",
            "hub\u{9b}31m",
            "hub\u{07}",
            "name\t",
        ];
        for sample in samples {
            let mut model = plan_zh();
            model.node_name = sample.to_string();
            assert_eq!(render_menu(&model), Err(MenuError::Injection), "{sample:?}");
            model.node_name = "hub-us-c".to_string();
            model.role = sample.to_string();
            assert_eq!(render_menu(&model), Err(MenuError::Injection));
            model.role = "core #3".to_string();
            model.version = sample.to_string();
            assert_eq!(render_menu(&model), Err(MenuError::Injection));
        }
    }

    #[test]
    fn ordinary_brackets_are_not_injection() {
        let mut model = plan_en();
        model.node_name = "hub[a]".to_string();
        let rendered = render_menu(&model).unwrap();
        assert!(rendered.contains("hub[a]"));
        assert_boxed(&rendered);
    }

    #[test]
    fn bad_selection_is_rejected() {
        let mut model = plan_en();
        model.selected = 0;
        assert_eq!(render_menu(&model), Err(MenuError::BadSelection));
        model.selected = 10;
        assert_eq!(render_menu(&model), Err(MenuError::BadSelection));
    }

    #[test]
    fn offline_model_is_honest_and_boxed() {
        let model = MenuModel::offline("0.1.0", Lang::En);
        let rendered = render_menu(&model).unwrap();
        assert_boxed(&rendered);
        assert!(rendered.contains("e2e-required"));
        assert!(rendered.contains("(unknown)"));
        assert!(rendered.contains("offline"));
        let json = model.to_json();
        assert!(json.contains("\"daemon\":false"));
        assert!(json.contains("\"console_menu\":true"));
        assert!(json.contains("\"mode\":\"e2e-required\""));
        assert!(json.contains("\"selected\":1"));
        assert!(!json.contains("\"daemon\":true"));
    }

    #[test]
    fn confirm_accepts_exact_phrases_only() {
        assert!(confirm_dangerous(&DangerAction::HopOnly, "HOP-ONLY").is_ok());
        assert!(confirm_dangerous(&DangerAction::Revoke { node_id: 42 }, "REVOKE 42").is_ok());
        assert!(confirm_dangerous(&DangerAction::Uninstall, "UNINSTALL").is_ok());
    }

    #[test]
    fn confirm_rejects_whitespace_case_newline_and_esc() {
        let rejects = [
            (DangerAction::HopOnly, "hop-only"),
            (DangerAction::HopOnly, "HOP-ONLY\n"),
            (DangerAction::HopOnly, " HOP-ONLY"),
            (DangerAction::HopOnly, "HOP-ONLY "),
            (DangerAction::HopOnly, ""),
            (DangerAction::HopOnly, "HOP-ONLY\u{1b}"),
            (DangerAction::Uninstall, "uninstall"),
            (DangerAction::Uninstall, "UNINSTALL\n"),
            (DangerAction::Revoke { node_id: 7 }, "REVOKE 7\n"),
            (DangerAction::Revoke { node_id: 7 }, "revoke 7"),
            (DangerAction::Revoke { node_id: 7 }, "REVOKE 8"),
            (DangerAction::Revoke { node_id: 7 }, "REVOKE  7"),
        ];
        for (action, typed) in rejects {
            assert!(
                confirm_dangerous(&action, typed).is_err(),
                "{action:?} / {typed:?}"
            );
        }
    }

    #[test]
    fn oversized_title_fields_stay_77_columns() {
        let mut model = plan_en();
        model.version = "9".repeat(80);
        model.platform = "linux-arm64-extra".to_string();
        let rendered = render_menu(&model).unwrap();
        assert_boxed(&rendered);
        assert!(!rendered.as_bytes().contains(&0x1B));
    }

    #[test]
    fn rendered_menu_copy_has_no_emoji() {
        for lang in [Lang::ZhCn, Lang::ZhTw, Lang::En] {
            let mut model = MenuModel::offline("0.1.0", lang);
            model.platform = "linux-arm64".to_string();
            let rendered = render_menu(&model).unwrap();
            for c in rendered.chars() {
                assert!(!is_emoji(c as u32), "{lang:?} U+{:04X}", c as u32);
            }
        }
    }
}
