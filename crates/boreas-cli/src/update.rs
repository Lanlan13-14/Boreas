//! Advisory release discovery only. No value here authorizes an artifact.

mod json;
mod offline;
mod transport;

pub(crate) fn offline(args: &[String]) -> (u8, String, String) {
    offline::run(args)
}

use std::cmp::Ordering;
use std::time::{Duration, Instant};

use crate::i18n::Lang;
use json::Value;
use transport::fetch;

const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_PAGE: &str = "https://github.com/Lanlan13-14/Boreas/releases";
const TOTAL: Duration = Duration::from_secs(5);
const STATIC_BUDGET: Duration = Duration::from_millis(1750);
const PAGE_SIZE: usize = 20;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Channel {
    #[default]
    Stable,
    Pre,
}

impl Channel {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "stable" => Some(Self::Stable),
            "pre" => Some(Self::Pre),
            _ => None,
        }
    }

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Pre => "pre",
        }
    }

    fn matches(self, version: &Version<'_>) -> bool {
        (self == Self::Pre) == version.pre.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Static,
    Api,
}

impl Source {
    fn url(self) -> &'static str {
        match self {
            Self::Static => {
                "https://raw.githubusercontent.com/Lanlan13-14/Boreas/refs/heads/release/release-manifest.json"
            }
            Self::Api => "https://api.github.com/repos/Lanlan13-14/Boreas/releases?per_page=20",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Static => "release-branch",
            Self::Api => "github-releases-list",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Issue {
    NoCurl,
    Timeout,
    Connect,
    Tls,
    TooLarge,
    Transport,
    Http(u16),
    Invalid,
}

impl Issue {
    fn message(self, lang: Lang) -> String {
        match self {
            Self::NoCurl => localized(lang, "trusted system curl unavailable", "可信系统 curl 不可用", "可信系統 curl 無法使用"),
            Self::Timeout => localized(lang, "time limit exceeded", "请求超时", "請求逾時"),
            Self::Connect => localized(lang, "DNS/connection failed (offline/restricted)", "DNS/连接失败（离线或受限）", "DNS/連線失敗（離線或受限）"),
            Self::Tls => localized(lang, "TLS handshake or verification failed", "TLS 握手或证书验证失败", "TLS 握手或憑證驗證失敗"),
            Self::TooLarge => localized(lang, "response exceeded byte limit", "响应超出字节上限", "回應超出位元組上限"),
            Self::Transport => localized(lang, "HTTPS transport failed", "HTTPS 传输失败", "HTTPS 傳輸失敗"),
            Self::Http(403) => localized(lang, "HTTP 403 (denied or rate limited)", "HTTP 403（拒绝或限流）", "HTTP 403（拒絕或限流）"),
            Self::Http(429) => localized(lang, "HTTP 429 (rate limited)", "HTTP 429（限流）", "HTTP 429（限流）"),
            Self::Http(status) => return format!("HTTP {status}"),
            Self::Invalid => localized(lang, "invalid discovery metadata", "发现元数据无效", "發現中繼資料無效"),
        }.into()
    }
}

#[derive(Debug)]
struct Version<'a> {
    core: [&'a str; 3],
    pre: Option<&'a str>,
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn number(value: &str) -> bool {
    digits(value) && (value.len() == 1 || !value.starts_with('0'))
}

fn numeric_cmp(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

impl<'a> Version<'a> {
    fn parse(raw: &'a str) -> Option<Self> {
        let identifiers = |value: &str, pre: bool| {
            value.split('.').all(|id| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && (!pre || !digits(id) || number(id))
            })
        };
        if raw.len() > 127 {
            return None;
        }
        let (plain, build) = raw.split_once('+').unwrap_or((raw, ""));
        if raw.contains('+') && !identifiers(build, false) {
            return None;
        }
        let (core, pre) = match plain.split_once('-') {
            Some((core, pre)) if identifiers(pre, true) => (core, Some(pre)),
            Some(_) => return None,
            None => (plain, None),
        };
        let mut parts = core.split('.');
        let core = [parts.next()?, parts.next()?, parts.next()?];
        (parts.next().is_none() && core.into_iter().all(number)).then_some(Self { core, pre })
    }

    fn tag(tag: &'a str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }

    fn precedence(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(&other.core) {
            let order = numeric_cmp(a, b);
            if order != Ordering::Equal {
                return order;
            }
        }
        match (self.pre, other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => {
                let mut left = a.split('.');
                let mut right = b.split('.');
                loop {
                    let order = match (left.next(), right.next()) {
                        (None, None) => return Ordering::Equal,
                        (Some(_), None) => return Ordering::Greater,
                        (None, Some(_)) => return Ordering::Less,
                        (Some(a), Some(b)) => match (digits(a), digits(b)) {
                            (true, true) => numeric_cmp(a, b),
                            (true, false) => Ordering::Less,
                            (false, true) => Ordering::Greater,
                            (false, false) => a.cmp(b),
                        },
                    };
                    if order != Ordering::Equal {
                        return order;
                    }
                }
            }
        }
    }
}

// A bare Cargo version does not prove the binary was built from that Git tag.
// Release packaging may explicitly provide the build tag (not runtime input).
fn build_tag() -> Option<&'static str> {
    let tag = option_env!("BOREAS_BUILD_TAG")?;
    let tagged = Version::tag(tag)?;
    let package = Version::parse(BUILD_VERSION)?;
    (tagged.core == package.core && (package.pre.is_none() || package.pre == tagged.pre))
        .then_some(tag)
}

pub(crate) fn local_build() -> String {
    let sha = option_env!("BOREAS_BUILD_SHA").or(option_env!("GITHUB_SHA"));
    let short = sha.filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    match (build_tag(), short) {
        (Some(tag), Some(sha)) => format!("{tag} ({})", &sha[..12]),
        (Some(tag), None) => tag.to_string(),
        (None, Some(sha)) => format!("{BUILD_VERSION} (dev, {})", &sha[..12]),
        (None, None) => format!("{BUILD_VERSION} (dev, commit unknown)"),
    }
}

fn static_tag(root: &Value, channel: Channel) -> Result<Option<String>, Issue> {
    if root.get("product")?.string() != Some("boreas") || root.get("schema")? != &Value::One {
        return Err(Issue::Invalid);
    }
    let get_tag = |key, channel: Channel| match root.get(key)? {
        Value::Null => Ok(None),
        Value::String(tag) if Version::tag(tag).is_some_and(|v| channel.matches(&v)) => {
            Ok(Some(tag.clone()))
        }
        _ => Err(Issue::Invalid),
    };
    let stable = get_tag("stable", Channel::Stable)?;
    let pre = get_tag("prerelease", Channel::Pre)?;
    Ok(match channel {
        Channel::Stable => stable,
        Channel::Pre => pre,
    })
}

fn api_tag(root: &Value, channel: Channel) -> Result<Option<String>, Issue> {
    let Value::Array(releases) = root else {
        return Err(Issue::Invalid);
    };
    if releases.len() > PAGE_SIZE {
        return Err(Issue::Invalid);
    }
    let mut best: Option<(&str, Version<'_>)> = None;
    for release in releases {
        let draft = release.get("draft")?.boolean().ok_or(Issue::Invalid)?;
        let pre = release.get("prerelease")?.boolean().ok_or(Issue::Invalid)?;
        let tag = release.get("tag_name")?.string().ok_or(Issue::Invalid)?;
        if draft || pre != (channel == Channel::Pre) {
            continue;
        }
        if let Some(version) = Version::tag(tag)
            && channel.matches(&version)
            && best.as_ref().is_none_or(|(_, v)| version.precedence(v).is_gt())
        {
            best = Some((tag, version));
        }
    }
    Ok(best.map(|(tag, _)| tag.to_string()))
}

fn discover(
    channel: Channel,
    start: Instant,
    mut get: impl FnMut(Source, Instant) -> Result<Vec<u8>, Issue>,
) -> Result<(Source, Option<String>), (Issue, Option<Issue>)> {
    let deadline = start + TOTAL;
    let static_result = get(Source::Static, start + STATIC_BUDGET)
        .and_then(|bytes| static_tag(&json::parse(&bytes)?, channel));
    let static_error = match static_result {
        Ok(tag) if Instant::now() < deadline => return Ok((Source::Static, tag)),
        Ok(_) => return Err((Issue::Timeout, None)),
        Err(Issue::NoCurl) => return Err((Issue::NoCurl, None)),
        Err(error) => error,
    };
    if Instant::now() >= deadline {
        return Err((static_error, Some(Issue::Timeout)));
    }
    let result = get(Source::Api, deadline).and_then(|bytes| api_tag(&json::parse(&bytes)?, channel));
    if Instant::now() >= deadline {
        return Err((static_error, Some(Issue::Timeout)));
    }
    result.map(|tag| (Source::Api, tag)).map_err(|error| (static_error, Some(error)))
}

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Newer,
    Same,
    Older,
    Uncompared,
}

fn compare(tag: &str, local: Option<&str>) -> Status {
    match local.and_then(Version::tag).zip(Version::tag(tag)) {
        Some((local, candidate)) => match candidate.precedence(&local) {
            Ordering::Greater => Status::Newer,
            Ordering::Equal => Status::Same,
            Ordering::Less => Status::Older,
        },
        None => Status::Uncompared,
    }
}

pub(crate) fn localized(lang: Lang, en: &'static str, cn: &'static str, tw: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::ZhCn => cn,
        Lang::ZhTw => tw,
    }
}

pub(crate) fn check(channel: Channel, lang: Lang) -> (bool, Vec<String>) {
    let unavailable = localized(lang, "Update check unavailable", "无法检查更新", "無法檢查更新");
    // Bound the terminal wait independently of process creation, DNS, pipe
    // I/O and metadata parsing. The transport separately terminates its child.
    let start = Instant::now();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .spawn(move || {
            let _ = sender.send(discover(channel, start, fetch));
        })
        .is_err()
    {
        return (false, vec![unavailable.into(), Issue::Transport.message(lang)]);
    }
    let result = match receiver.recv_timeout((start + TOTAL).saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(error) => {
            let reason = match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => Issue::Timeout,
                std::sync::mpsc::RecvTimeoutError::Disconnected => Issue::Transport,
            };
            return (false, vec![unavailable.into(), reason.message(lang)]);
        }
    };
    match result {
        Ok((source, tag)) => {
            let mut rows = match tag {
                Some(tag) => {
                    let label = match compare(&tag, build_tag()) {
                        Status::Newer => localized(lang, "Newer tag reported", "来源报告较新标签", "來源回報較新標籤"),
                        Status::Same => localized(lang, "Same precedence", "版本优先级相同", "版本優先級相同"),
                        Status::Older => localized(lang, "Only older tag reported", "仅报告较旧标签", "僅回報較舊標籤"),
                        Status::Uncompared => localized(lang, "Reported tag (dev build not compared)", "报告标签（开发构建未比较）", "回報標籤（開發組建未比較）"),
                    };
                    // Version::tag guarantees display-safe ASCII; use separate
                    // label and tag rows so a lengthy label cannot hide the tag.
                    vec![label.into(), tag]
                }
                None => vec![localized(lang, "No matching release in checked metadata.", "已检查的元数据中无匹配发布。", "已檢查的中繼資料中無相符發布。").into()],
            };
            rows.push(format!("{}: {}", localized(lang, "Source (release signature not verified)", "来源（未验证发布签名）", "來源（未驗證發布簽章）"), source.key()));
            rows.push(RELEASE_PAGE.into());
            (true, rows)
        }
        Err((primary, fallback)) => {
            let mut rows = vec![unavailable.into(), format!("release-branch: {}", primary.message(lang))];
            if let Some(fallback) = fallback {
                rows.push(format!("GitHub list: {}", fallback.message(lang)));
            }
            (false, rows)
        }
    }
}

pub(crate) fn blocked(lang: Lang) -> &'static str {
    localized(lang, "Auto-update blocked: no trusted feed; offline operator action only.", "自动更新已禁用：无可信更新源，仅支持管理员离线操作。", "自動更新已停用：無可信更新來源，僅支援管理員離線操作。")
}

pub(crate) fn run(args: &[String], lang: Lang) -> (u8, String, String) {
    let channel = match args {
        [] => Some(Channel::default()),
        [flag, value] if flag == "--channel" => Channel::parse(value),
        [flag] => flag.strip_prefix("--channel=").and_then(Channel::parse),
        _ => None,
    };
    let Some(channel) = channel else {
        return (2, String::new(), "usage: boreas update-check [--channel stable|pre]".into());
    };
    let (ok, rows) = check(channel, lang);
    let mut output = vec![format!("Boreas {} / {}", local_build(), channel.key())];
    output.extend(rows);
    output.push(blocked(lang).into());
    (u8::from(!ok), output.join("\n"), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC: &[u8] = br#"{"product":"boreas","schema":1,"stable":"v1.0.0","prerelease":"v1.1.0-pre.40"}"#;
    const LIST: &[u8] = br#"[
        {"draft":false,"prerelease":true,"tag_name":"v1.1.0-pre.9"},
        {"draft":false,"prerelease":false,"tag_name":"v1.10.0"},
        {"draft":false,"prerelease":false,"tag_name":"v1.9.0"},
        {"draft":true,"prerelease":false,"tag_name":"v9.0.0"},
        {"draft":false,"prerelease":false,"tag_name":"v8.0.0-pre.9"},
        {"draft":false,"prerelease":true,"tag_name":"v7.0.0"},
        {"draft":false,"prerelease":true,"tag_name":"v1.1.0-pre.40"},
        {"draft":false,"prerelease":false,"tag_name":"agent-v99.0.0"},
        {"draft":false,"prerelease":false,"tag_name":"v99.0.0\u001b[31m"}
    ]"#;

    #[test]
    fn semver_precedence_is_numeric_and_ignores_build_metadata() {
        for (older, newer) in [
            ("v0.1.20-pre.9", "v0.1.20-pre.40"),
            ("v0.1.20-pre.40", "v0.1.20"),
            ("v0.9.0", "v0.10.0"),
            ("v1.0.0-9", "v1.0.0-alpha"),
            ("v1.0.0-alpha", "v1.0.0-alpha.1"),
            ("v1.0.0-alpha.2", "v1.0.0-alpha.999999999999999999999999"),
        ] {
            assert_eq!(compare(newer, Some(older)), Status::Newer);
            assert_eq!(compare(older, Some(newer)), Status::Older);
        }
        assert_eq!(compare("v1.0.0+next", Some("v1.0.0")), Status::Same);
        assert_eq!(compare("v1.0.0", None), Status::Uncompared);
        for tag in ["1.0.0", "v01.0.0", "v1.0.0-pre.01", "v1.0.0+", "v1.0.0-pre..1", "v1.0.0/1"] {
            assert!(Version::tag(tag).is_none(), "accepted {tag}");
        }
    }

    #[test]
    fn channels_are_exclusive_and_drafts_foreign_tags_and_mismatches_are_ignored() {
        let data = json::parse(LIST).unwrap();
        assert_eq!(Channel::default(), Channel::Stable);
        assert_eq!(api_tag(&data, Channel::Stable).unwrap().as_deref(), Some("v1.10.0"));
        assert_eq!(api_tag(&data, Channel::Pre).unwrap().as_deref(), Some("v1.1.0-pre.40"));
        let pre_only = br#"[{"draft":false,"prerelease":true,"tag_name":"v1.0.0-pre.1"}]"#;
        assert_eq!(api_tag(&json::parse(pre_only).unwrap(), Channel::Stable), Ok(None));
    }

    #[test]
    fn discovery_falls_back_only_on_static_failure_and_shares_deadline() {
        let start = Instant::now();
        let mut calls = Vec::new();
        let result = discover(Channel::Stable, start, |source, deadline| {
            calls.push((source, deadline));
            Ok(STATIC.to_vec())
        });
        assert_eq!(result, Ok((Source::Static, Some("v1.0.0".into()))));
        assert_eq!(calls, [(Source::Static, start + STATIC_BUDGET)]);

        calls.clear();
        let result = discover(Channel::Pre, start, |source, deadline| {
            calls.push((source, deadline));
            match source {
                Source::Static => Ok(b"broken".to_vec()),
                Source::Api => Ok(LIST.to_vec()),
            }
        });
        assert_eq!(result, Ok((Source::Api, Some("v1.1.0-pre.40".into()))));
        assert_eq!(calls, [(Source::Static, start + STATIC_BUDGET), (Source::Api, start + TOTAL)]);
        let result = discover(Channel::Stable, Instant::now(), |source, _| {
            match source {
                Source::Static => Err(Issue::Http(404)),
                Source::Api => Err(Issue::Http(429)),
            }
        });
        assert_eq!(result, Err((Issue::Http(404), Some(Issue::Http(429)))));
    }

    #[test]
    fn discovery_rejects_duplicate_keys_invalid_schema_and_excessive_input() {
        assert_eq!(json::parse(br#"{"draft":false,"d\u0072aft":true}"#), Err(Issue::Invalid));
        assert_eq!(json::parse(br#"["\uD800"]"#), Err(Issue::Invalid));
        assert_eq!(json::parse(b"[] []"), Err(Issue::Invalid));
        assert_eq!(json::parse(format!("{}0{}", "[".repeat(50), "]".repeat(50)).as_bytes()), Err(Issue::Invalid));
        assert_eq!(json::parse(&vec![b' '; json::MAX_BYTES + 1]), Err(Issue::TooLarge));
        let wrong = br#"{"product":"zephyr","schema":1,"stable":null,"prerelease":null}"#;
        assert_eq!(static_tag(&json::parse(wrong).unwrap(), Channel::Stable), Err(Issue::Invalid));
        let wrong = br#"{"product":"boreas","schema":1,"stable":"v1.0.0-pre.1","prerelease":null}"#;
        assert_eq!(static_tag(&json::parse(wrong).unwrap(), Channel::Stable), Err(Issue::Invalid));
        let empty = br#"{"product":"boreas","schema":1,"stable":null,"prerelease":null}"#;
        assert_eq!(static_tag(&json::parse(empty).unwrap(), Channel::Stable), Ok(None));
    }

    #[test]
    fn cli_rejects_invalid_channels_without_network() {
        for args in [
            vec!["--channel".into()],
            vec!["--channel=nightly".into()],
            vec!["--channel".into(), "pre".into(), "--install".into()],
        ] {
            let (exit, out, error) = run(&args, Lang::En);
            assert_eq!(exit, 2);
            assert!(out.is_empty());
            assert!(error.contains("stable|pre"));
        }
    }
}
