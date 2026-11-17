//! Trilingual (zh-CN / zh-TW / en) static dictionary and language selection.
//!
//! Master plan §10.4 requires a native Rust CLI/TUI in Simplified Chinese,
//! Traditional Chinese and English, with no Emoji. All console copy used by
//! the status screen lives in the compile-time dictionary below, keyed by
//! the [`Msg`] enum (never by string) so a missing translation is a compile
//! error, not a runtime fallback.
//!
//! Language selection priority (highest first): explicit `--lang` argument,
//! then `BOREAS_LANG`, then `LC_ALL`, then `LANG`, then English. The pure
//! decision logic ([`select_lang`]) is separated from environment reading
//! ([`lang_from_env`]) so the priority chain is unit-testable without
//! mutating process environment.

/// Supported console languages (master plan §10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    ZhCn,
    ZhTw,
    En,
}

impl Lang {
    /// All supported languages, for exhaustive tests.
    #[cfg(test)]
    pub(crate) const ALL: [Lang; 3] = [Lang::ZhCn, Lang::ZhTw, Lang::En];

    /// BCP-47 style code used in JSON output and by `--lang`.
    pub fn code(self) -> &'static str {
        match self {
            Lang::ZhCn => "zh-CN",
            Lang::ZhTw => "zh-TW",
            Lang::En => "en",
        }
    }
}

/// Dictionary keys: every string the status screen and the line-mode console
/// can print. The console is line-oriented (no raw mode); see `crate::tui`.
#[allow(
    dead_code,
    reason = "dictionary is intentionally complete ahead of later console screens"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    ConsoleTitle,
    LangLabel,
    NodeLabel,
    ModeLabel,
    InboundLabel,
    OutboundLabel,
    On,
    Off,
    ConnectionsUnit,
    UpstreamsUnit,
    DaemonConnected,
    DaemonNotConnected,
    PlaintextWarning,
    E2eNote,
    OfflineNote,
    LiveNote,
    UsageLabel,
    UnknownNode,
    // --- line-mode console (boreas-easy) ---
    SrcLabel,
    SrcLive,
    SrcOffline,
    HeadingTelemetry,
    HeadingService,
    HeadingConfirm,
    HeadingNotice,
    HintService,
    HintConfirm,
    HintNotice,
    PromptLabel,
    NoticeUnknownCommand,
    NoticeNotImplemented,
    NoticeRefused,
    NoticeCancelled,
    SvcStatus,
    SvcStart,
    SvcStop,
    SvcConfig,
    SvcBack,
    ConfirmPrompt,
    CancelHint,
    /// Shown when the measured terminal width is below 77 columns, so the
    /// operator knows why the framed screen was replaced by a plain list.
    NarrowNotice,
}

impl Msg {
    /// Every key, for the dictionary-completeness test.
    #[cfg(test)]
    pub(crate) const ALL: [Msg; 41] = [
        Msg::ConsoleTitle,
        Msg::LangLabel,
        Msg::NodeLabel,
        Msg::ModeLabel,
        Msg::InboundLabel,
        Msg::OutboundLabel,
        Msg::On,
        Msg::Off,
        Msg::ConnectionsUnit,
        Msg::UpstreamsUnit,
        Msg::DaemonConnected,
        Msg::DaemonNotConnected,
        Msg::PlaintextWarning,
        Msg::E2eNote,
        Msg::OfflineNote,
        Msg::LiveNote,
        Msg::UsageLabel,
        Msg::UnknownNode,
        Msg::SrcLabel,
        Msg::SrcLive,
        Msg::SrcOffline,
        Msg::HeadingTelemetry,
        Msg::HeadingService,
        Msg::HeadingConfirm,
        Msg::HeadingNotice,
        Msg::HintService,
        Msg::HintConfirm,
        Msg::HintNotice,
        Msg::PromptLabel,
        Msg::NoticeUnknownCommand,
        Msg::NoticeNotImplemented,
        Msg::NoticeRefused,
        Msg::NoticeCancelled,
        Msg::SvcStatus,
        Msg::SvcStart,
        Msg::SvcStop,
        Msg::SvcConfig,
        Msg::SvcBack,
        Msg::ConfirmPrompt,
        Msg::CancelHint,
        Msg::NarrowNotice,
    ];
}

/// Compile-time static dictionary.
///
/// Field labels (`NODE`, `MODE`, `IN`, `OUT`) and the `ON`/`OFF` tokens stay
/// in Latin script in all three languages: the §10.4.1 examples of the
/// master plan do exactly that in the zh-CN and zh-TW screens (e.g.
/// `NODE hub-us-c`, `Dir OFF`). Security-mode tokens (`hop-only`,
/// `e2e-required`, §1.3) are likewise never translated; see
/// `render::SecurityMode::as_str`.
///
/// Only ASCII punctuation plus CJK unified ideographs are used, so every
/// character has a deterministic display width (no Ambiguous-width or Emoji
/// code points inside the box, per §10.4.1).
pub fn text(lang: Lang, msg: Msg) -> &'static str {
    match (lang, msg) {
        (_, Msg::ConsoleTitle) => "BOREAS CONSOLE",
        (Lang::ZhCn, Msg::LangLabel) => "简中",
        (Lang::ZhTw, Msg::LangLabel) => "繁中",
        (Lang::En, Msg::LangLabel) => "EN",
        (_, Msg::NodeLabel) => "NODE",
        (_, Msg::ModeLabel) => "MODE",
        (_, Msg::InboundLabel) => "IN",
        (_, Msg::OutboundLabel) => "OUT",
        (_, Msg::On) => "ON",
        (_, Msg::Off) => "OFF",
        (Lang::ZhCn, Msg::ConnectionsUnit) => "连接",
        (Lang::ZhTw, Msg::ConnectionsUnit) => "連接",
        (Lang::En, Msg::ConnectionsUnit) => "conn",
        (Lang::ZhCn, Msg::UpstreamsUnit) => "上游",
        (Lang::ZhTw, Msg::UpstreamsUnit) => "上游",
        (Lang::En, Msg::UpstreamsUnit) => "upstreams",
        // The literal English token is kept in all three languages so the
        // connection state is unambiguous in logs and screenshots; the
        // localised gloss follows it.
        (Lang::ZhCn, Msg::DaemonConnected) => "daemon: connected / 已连接.",
        (Lang::ZhTw, Msg::DaemonConnected) => "daemon: connected / 已連接.",
        (Lang::En, Msg::DaemonConnected) => "daemon: connected.",
        (Lang::ZhCn, Msg::DaemonNotConnected) => "daemon: not connected / 未连接.",
        (Lang::ZhTw, Msg::DaemonNotConnected) => "daemon: not connected / 未連接.",
        (Lang::En, Msg::DaemonNotConnected) => "daemon: not connected.",
        // Suffix after the mandatory `PLAINTEXT AT CORE` marker (§1.3).
        (Lang::ZhCn, Msg::PlaintextWarning) => "转发核心可见业务明文; 此模式非端到端加密",
        (Lang::ZhTw, Msg::PlaintextWarning) => "轉發核心可見業務明文; 此模式非端到端加密",
        (Lang::En, Msg::PlaintextWarning) => {
            "relay cores can read business plaintext; this is not E2E"
        }
        (Lang::ZhCn, Msg::E2eNote) => "转发核心仅见电路元数据与 E2E 密文",
        (Lang::ZhTw, Msg::E2eNote) => "轉發核心僅見電路元資料與 E2E 密文",
        (Lang::En, Msg::E2eNote) => "relay cores see circuit metadata and E2E ciphertext only",
        (Lang::ZhCn, Msg::OfflineNote) => "仅离线快照; 未尝试连接守护进程",
        (Lang::ZhTw, Msg::OfflineNote) => "僅離線快照; 未嘗試連接守護行程",
        (Lang::En, Msg::OfflineNote) => {
            "Offline snapshot only; no daemon connection was attempted."
        }
        (Lang::ZhCn, Msg::LiveNote) => "快照由调用方提供; 本屏仅负责渲染",
        (Lang::ZhTw, Msg::LiveNote) => "快照由呼叫方提供; 本屏僅負責渲染",
        (Lang::En, Msg::LiveNote) => "Snapshot supplied by caller; this screen only renders it.",
        (Lang::ZhCn, Msg::UsageLabel) => "用法",
        (Lang::ZhTw, Msg::UsageLabel) => "用法",
        (Lang::En, Msg::UsageLabel) => "Usage",
        (Lang::ZhCn, Msg::UnknownNode) => "(未知)",
        (Lang::ZhTw, Msg::UnknownNode) => "(未知)",
        (Lang::En, Msg::UnknownNode) => "(unknown)",
        // --- line-mode console. `live` / `offline` are machine state tokens and
        // are never translated, the same way `e2e-required` and `hop-only` are
        // kept verbatim (§1.3, §10.4). ---
        (_, Msg::SrcLabel) => "SRC",
        (_, Msg::SrcLive) => "live",
        (_, Msg::SrcOffline) => "offline",
        (Lang::ZhCn, Msg::HeadingTelemetry) => "实时链路遥测",
        (Lang::ZhTw, Msg::HeadingTelemetry) => "即時鏈路遙測",
        (Lang::En, Msg::HeadingTelemetry) => "Live Telemetry",
        (Lang::ZhCn, Msg::HeadingService) => "服务与脱敏诊断",
        (Lang::ZhTw, Msg::HeadingService) => "服務與脫敏診斷",
        (Lang::En, Msg::HeadingService) => "Service & Diag",
        (Lang::ZhCn, Msg::HeadingConfirm) => "危险操作确认",
        (Lang::ZhTw, Msg::HeadingConfirm) => "危險操作確認",
        (Lang::En, Msg::HeadingConfirm) => "Confirm action",
        (Lang::ZhCn, Msg::HeadingNotice) => "结果",
        (Lang::ZhTw, Msg::HeadingNotice) => "結果",
        (Lang::En, Msg::HeadingNotice) => "Result",
        (Lang::ZhCn, Msg::HintService) => " [1] 状态 [2] 启动 [3] 停止 [4] 配置 [5] 返回 [q] 退出",
        (Lang::ZhTw, Msg::HintService) => " [1] 狀態 [2] 啟動 [3] 停止 [4] 配置 [5] 返回 [q] 離開",
        (Lang::En, Msg::HintService) => {
            " [1] Status [2] Start [3] Stop [4] Config [5] Back [q] Quit"
        }
        (Lang::ZhCn, Msg::HintConfirm) => " 输入确认词后回车; 直接回车取消",
        (Lang::ZhTw, Msg::HintConfirm) => " 輸入確認詞後回車; 直接回車取消",
        (Lang::En, Msg::HintConfirm) => " Type the phrase above; bare Enter cancels",
        (Lang::ZhCn, Msg::HintNotice) => " [Enter] 返回主菜单 [q] 退出",
        (Lang::ZhTw, Msg::HintNotice) => " [Enter] 返回主選單 [q] 離開",
        (Lang::En, Msg::HintNotice) => " [Enter] Back to menu [q] Quit",
        (_, Msg::PromptLabel) => "> ",
        (Lang::ZhCn, Msg::NoticeUnknownCommand) => {
            "未知命令; 用 j/k 或 1-9 选择, Enter 执行, q 退出"
        }
        (Lang::ZhTw, Msg::NoticeUnknownCommand) => {
            "未知命令; 用 j/k 或 1-9 選擇, Enter 執行, q 離開"
        }
        (Lang::En, Msg::NoticeUnknownCommand) => {
            "Unknown command; use j/k or 1-9, Enter to run, q to quit"
        }
        (Lang::ZhCn, Msg::NoticeNotImplemented) => "未实现: 本版仅提供状态、配置检查与服务状态",
        (Lang::ZhTw, Msg::NoticeNotImplemented) => "未實現: 本版僅提供狀態、配置檢查與服務狀態",
        (Lang::En, Msg::NoticeNotImplemented) => {
            "Not implemented: this build offers status, config check and service state only"
        }
        (Lang::ZhCn, Msg::NoticeRefused) => "已拒绝: 本版不切换安全模式、不吊销、不卸载",
        (Lang::ZhTw, Msg::NoticeRefused) => "已拒絕: 本版不切換安全模式、不吊銷、不解除安裝",
        (Lang::En, Msg::NoticeRefused) => {
            "Refused: this build does not switch security mode, revoke, or uninstall"
        }
        (Lang::ZhCn, Msg::NoticeCancelled) => "已取消; 未执行任何动作",
        (Lang::ZhTw, Msg::NoticeCancelled) => "已取消; 未執行任何動作",
        (Lang::En, Msg::NoticeCancelled) => "Cancelled; nothing was executed",
        (Lang::ZhCn, Msg::SvcStatus) => "查询守护进程状态",
        (Lang::ZhTw, Msg::SvcStatus) => "查詢守護行程狀態",
        (Lang::En, Msg::SvcStatus) => "Query daemon status",
        (Lang::ZhCn, Msg::SvcStart) => "启动守护进程",
        (Lang::ZhTw, Msg::SvcStart) => "啟動守護行程",
        (Lang::En, Msg::SvcStart) => "Start daemon",
        (Lang::ZhCn, Msg::SvcStop) => "停止守护进程",
        (Lang::ZhTw, Msg::SvcStop) => "停止守護行程",
        (Lang::En, Msg::SvcStop) => "Stop daemon",
        (Lang::ZhCn, Msg::SvcConfig) => "检查配置文件",
        (Lang::ZhTw, Msg::SvcConfig) => "檢查配置檔案",
        (Lang::En, Msg::SvcConfig) => "Check config file",
        (Lang::ZhCn, Msg::SvcBack) => "返回主菜单",
        (Lang::ZhTw, Msg::SvcBack) => "返回主選單",
        (Lang::En, Msg::SvcBack) => "Back to menu",
        (Lang::ZhCn, Msg::ConfirmPrompt) => "请输入确认词: ",
        (Lang::ZhTw, Msg::ConfirmPrompt) => "請輸入確認詞: ",
        (Lang::En, Msg::ConfirmPrompt) => "Type this phrase: ",
        (Lang::ZhCn, Msg::CancelHint) => "直接回车取消",
        (Lang::ZhTw, Msg::CancelHint) => "直接回車取消",
        (Lang::En, Msg::CancelHint) => "Bare Enter cancels",
        // Degraded-width notice: the frame needs 77 columns (§10.4.1); below
        // that the console prints the narrow list instead and says why.
        (Lang::ZhCn, Msg::NarrowNotice) => "终端宽度不足 77 列; 已改用窄列表",
        (Lang::ZhTw, Msg::NarrowNotice) => "終端寬度不足 77 欄; 已改用窄清單",
        (Lang::En, Msg::NarrowNotice) => {
            "Terminal is narrower than 77 columns; using the narrow list"
        }
    }
}

/// Parse a language tag such as `zh-CN`, `zh_TW.UTF-8`, `zh-Hant-HK` or
/// `en_US.UTF-8`. Returns `None` for unsupported or empty tags (including
/// the POSIX `C` locale) so selection can fall through to the next source.
///
/// Traditional Chinese is selected for `zh-TW`, `zh-HK`, `zh-MO` and any
/// `zh-Hant*` tag; every other `zh*` tag (including bare `zh`, `zh-Hans`,
/// `zh-SG`) selects Simplified Chinese.
pub fn parse_lang(raw: &str) -> Option<Lang> {
    // Drop encoding (".UTF-8") and modifier ("@euro") suffixes, then
    // normalise case and separators.
    let base = raw.trim().split(['.', '@']).next().unwrap_or("");
    let tag = base.to_ascii_lowercase().replace('_', "-");
    if tag.is_empty() || tag == "c" || tag == "posix" {
        return None;
    }
    if tag.starts_with("zh-tw")
        || tag.starts_with("zh-hk")
        || tag.starts_with("zh-mo")
        || tag.starts_with("zh-hant")
    {
        return Some(Lang::ZhTw);
    }
    if tag == "zh" || tag.starts_with("zh-") {
        return Some(Lang::ZhCn);
    }
    if tag == "en" || tag.starts_with("en-") {
        return Some(Lang::En);
    }
    None
}

/// Pure language-selection logic: `--lang` > `BOREAS_LANG` > `LC_ALL` >
/// `LANG` > English. A source whose value does not parse falls through to
/// the next one.
pub fn select_lang(
    cli: Option<&str>,
    boreas_lang: Option<&str>,
    lc_all: Option<&str>,
    lang_env: Option<&str>,
) -> Lang {
    for candidate in [cli, boreas_lang, lc_all, lang_env] {
        if let Some(lang) = candidate.and_then(parse_lang) {
            return lang;
        }
    }
    Lang::En
}

/// Environment-reading wrapper around [`select_lang`]. This is the only
/// function in this module that touches the process environment.
pub fn lang_from_env(cli: Option<&str>) -> Lang {
    let boreas_lang = std::env::var("BOREAS_LANG").ok();
    let lc_all = std::env::var("LC_ALL").ok();
    let lang_env = std::env::var("LANG").ok();
    select_lang(
        cli,
        boreas_lang.as_deref(),
        lc_all.as_deref(),
        lang_env.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::{Lang, Msg, parse_lang, select_lang, text};

    #[test]
    fn parse_lang_accepts_common_tags() {
        assert_eq!(parse_lang("zh-CN"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh_cn"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh-CN.UTF-8"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh-Hans-CN"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh-SG"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh"), Some(Lang::ZhCn));
        assert_eq!(parse_lang("zh-TW"), Some(Lang::ZhTw));
        assert_eq!(parse_lang("zh_TW.UTF-8"), Some(Lang::ZhTw));
        assert_eq!(parse_lang("zh-HK"), Some(Lang::ZhTw));
        assert_eq!(parse_lang("zh-Hant-TW"), Some(Lang::ZhTw));
        assert_eq!(parse_lang("en"), Some(Lang::En));
        assert_eq!(parse_lang("en-US"), Some(Lang::En));
        assert_eq!(parse_lang("en_GB.UTF-8@euro"), Some(Lang::En));
        assert_eq!(parse_lang("EN"), Some(Lang::En));
    }

    #[test]
    fn parse_lang_rejects_unsupported_tags() {
        assert_eq!(parse_lang(""), None);
        assert_eq!(parse_lang("   "), None);
        assert_eq!(parse_lang("C"), None);
        assert_eq!(parse_lang("C.UTF-8"), None);
        assert_eq!(parse_lang("POSIX"), None);
        assert_eq!(parse_lang("fr-FR"), None);
        assert_eq!(parse_lang("ja-JP"), None);
        assert_eq!(parse_lang("zhongwen"), None);
    }

    #[test]
    fn select_lang_priority_chain() {
        // --lang wins over everything.
        assert_eq!(
            select_lang(Some("zh-TW"), Some("zh-CN"), Some("en"), Some("en")),
            Lang::ZhTw
        );
        // BOREAS_LANG wins over LC_ALL / LANG.
        assert_eq!(
            select_lang(None, Some("zh-CN"), Some("zh-TW"), Some("en")),
            Lang::ZhCn
        );
        // LC_ALL wins over LANG.
        assert_eq!(
            select_lang(None, None, Some("zh-TW"), Some("zh-CN")),
            Lang::ZhTw
        );
        // LANG is the last environment source.
        assert_eq!(
            select_lang(None, None, None, Some("zh_CN.UTF-8")),
            Lang::ZhCn
        );
        // Default is English.
        assert_eq!(select_lang(None, None, None, None), Lang::En);
    }

    #[test]
    fn select_lang_falls_through_unparseable_values() {
        assert_eq!(
            select_lang(Some("fr-FR"), Some("zh-TW"), None, None),
            Lang::ZhTw
        );
        assert_eq!(
            select_lang(None, Some(""), Some("C.UTF-8"), Some("zh-CN")),
            Lang::ZhCn
        );
        assert_eq!(
            select_lang(Some("xx"), Some("yy"), Some("zz"), Some("ww")),
            Lang::En
        );
    }

    #[test]
    fn dictionary_is_complete_for_every_language() {
        for lang in Lang::ALL {
            for msg in Msg::ALL {
                let value = text(lang, msg);
                assert!(!value.is_empty(), "empty text for {lang:?}/{msg:?}");
                assert!(
                    !value.chars().any(|c| c.is_control()),
                    "control character in {lang:?}/{msg:?}: {value:?}"
                );
            }
        }
    }

    #[test]
    fn lang_codes_match_dictionary_labels() {
        assert_eq!(Lang::ZhCn.code(), "zh-CN");
        assert_eq!(Lang::ZhTw.code(), "zh-TW");
        assert_eq!(Lang::En.code(), "en");
        // §10.4.1 title-line labels: [L] 简中 / 繁中 / EN.
        assert_eq!(text(Lang::ZhCn, Msg::LangLabel), "简中");
        assert_eq!(text(Lang::ZhTw, Msg::LangLabel), "繁中");
        assert_eq!(text(Lang::En, Msg::LangLabel), "EN");
    }
}
