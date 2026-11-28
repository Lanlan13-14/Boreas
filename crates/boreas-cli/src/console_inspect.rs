//! Read-only, allowlisted configuration summaries for console sections.
//!
//! These summaries are configuration only: they do not query credentials,
//! attest to runtime use, or expose endpoint/secret/path values. Parsing uses
//! the same bounded, ownership-checked and fail-closed loader as config-check.
use std::path::Path;

use crate::config::{Config, RuntimeCapabilities};
use crate::i18n::Lang;
use crate::update::localized;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Identity,
    Uplinks,
    RoutesDns,
    Security,
}

pub fn inspect(path: &Path, section: Section, lang: Lang) -> Vec<String> {
    match Config::read_file(path, RuntimeCapabilities::NO_RUNTIME) {
        Ok(config) => summarize(&config, section, lang),
        Err(error) => vec![
            localized(lang, "Configuration unavailable or rejected", "配置不可用或被拒绝", "設定無法取得或遭拒絕").into(),
            // ConfigError Display is deliberately secret-free, unlike arbitrary I/O errors.
            format!("{}: {}", localized(lang, "Reason", "原因", "原因"), error),
            localized(lang, "Runtime state unknown; no changes made", "运行状态未知；未作更改", "執行狀態未知；未作變更").into(),
        ],
    }
}

fn yes(value: bool) -> &'static str { if value { "yes" } else { "no" } }

fn summarize(config: &Config, section: Section, lang: Lang) -> Vec<String> {
    let mut rows = vec![localized(lang,
        "Validated local config only; not runtime state",
        "仅为已验证本地配置；并非运行状态",
        "僅為已驗證本機設定；並非執行狀態").to_string()];
    match section {
        Section::Identity => {
            rows.push(format!("role: {}", config.identity.role.as_str()));
            rows.push(format!("node ID: {} / home core: {}", config.identity.node_id, config.identity.home_core_id));
            rows.push(format!("identity generation: {}", config.identity.identity_generation));
            rows.push(localized(lang, "Credential validity and enrollment: unknown", "凭证有效性及注册状态：未知", "憑證有效性及註冊狀態：未知").into());
            rows.push(localized(lang, "DirectGrant and listener state: unknown", "DirectGrant 及监听状态：未知", "DirectGrant 及監聽狀態：未知").into());
        }
        Section::Uplinks => {
            rows.push(format!("primary configured: {}", yes(!config.uplinks.primary.is_empty())));
            rows.push(format!("backup configured: {}", yes(config.uplinks.backup.is_some())));
            rows.push(format!("paths: {} / probe paths: {}", config.uplinks.paths, config.uplinks.probe_paths));
            rows.push(localized(lang, "Active path, peers and probe results: unknown", "活动路径、对端及探测结果：未知", "活動路徑、對端及探測結果：未知").into());
            rows.push(localized(lang, "No path switch or probe was performed", "未执行切路或探测", "未執行切路或探測").into());
        }
        Section::RoutesDns => {
            rows.push(format!("advertise routes: {} / accept routes: {}", yes(config.limits.advertise_routes), yes(config.limits.accept_routes)));
            rows.push(format!("default route: {} / IPv6: {}", yes(config.limits.default_route), yes(config.limits.ipv6)));
            rows.push(format!("DNS section configured: {}", yes(config.dns.is_some())));
            rows.push(localized(lang, "Directory, leases, routes and DNS runtime: unknown", "目录、租约、路由及 DNS 运行状态：未知", "目錄、租約、路由及 DNS 執行狀態：未知").into());
            rows.push(localized(lang, "No routes or permissions were changed", "未更改路由或权限", "未變更路由或權限").into());
        }
        Section::Security => {
            rows.push(format!("configured policy: {}", config.security.mode.as_str()));
            rows.push(format!("configured suite: {}", config.security.suite.as_str()));
            if config.security.mode == crate::config::SecurityMode::HopOnly {
                rows.push("! HOP-ONLY: PLAINTEXT AT CORE".into());
            }
            rows.push(localized(lang, "Negotiated algorithms and E2E activation: unknown", "协商算法及端到端激活状态：未知", "協商演算法及端對端啟用狀態：未知").into());
            rows.push(localized(lang, "Revocation, snapshot freshness and audit: unknown", "吊销、快照新鲜度及审计：未知", "撤銷、快照新鮮度及稽核：未知").into());
            rows.push(localized(lang, "No policy change or revocation performed", "未更改策略或执行吊销", "未變更策略或執行撤銷").into());
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Config {
        let base = if cfg!(windows) { "C:/boreas-tests" } else { "/boreas-tests" };
        let source = format!(r#"version = 2
[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
[paths]
identity_key = "{base}/secret/identity.key"
roots = ["{base}/secret/roots.cbor"]
state_dir = "{base}/secret/state"
[uplink]
primary = "hub-us-c.example.net:443"
paths = 4
probe_paths = 1
"#);
        Config::parse_toml(&source, RuntimeCapabilities::NO_RUNTIME).unwrap()
    }

    #[test]
    fn sections_are_bounded_allowlists_and_do_not_claim_runtime() {
        let config = fixture();
        for lang in [Lang::En, Lang::ZhCn, Lang::ZhTw] {
            for section in [Section::Identity, Section::Uplinks, Section::RoutesDns, Section::Security] {
                let rows = summarize(&config, section, lang);
                assert!(rows.len() <= crate::tui::DETAIL_ROWS);
                let output = rows.join("\n");
                assert!(!output.contains("hub-us-c.example.net"));
                assert!(!output.contains("identity.key"));
                assert!(!output.contains("0123456789abcdef"));
                assert!(!output.contains('\u{1b}'));
                assert!(!output.contains("E2E active"));
            }
        }
    }

    #[test]
    fn configured_values_and_unknown_runtime_are_distinct() {
        let mut c = fixture();
        c.limits.accept_routes = true;
        c.security.mode = crate::config::SecurityMode::HopOnly;
        let security = summarize(&c, Section::Security, Lang::En).join("\n");
        assert!(security.contains("configured policy: hop-only"));
        assert!(security.contains("PLAINTEXT AT CORE"));
        assert!(security.contains("E2E activation: unknown"));
        let routes = summarize(&c, Section::RoutesDns, Lang::En).join("\n");
        assert!(routes.contains("accept routes: yes"));
        assert!(routes.contains("runtime: unknown"));
    }

    #[cfg(unix)]
    #[test]
    fn loader_refuses_symlinks_and_unsafe_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("boreas-inspect-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("config.toml");
        let link = dir.join("config-link.toml");
        std::fs::write(&file, "secret-should-not-be-displayed\u{1b}[31m").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&file, &link).unwrap();
        for path in [&link, &file] {
            if path == &file {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let output = inspect(path, Section::Security, Lang::En).join("\n");
            assert!(output.contains("rejected"));
            assert!(!output.contains("secret-should-not-be-displayed"));
            assert!(!output.contains('\u{1b}'));
            assert!(!output.contains("config-link.toml"));
        }
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn rejected_config_never_echoes_path_or_file_contents() {
        let path = std::env::temp_dir().join("boreas-nonexistent-private-path-inspection-test");
        let rows = inspect(&path, Section::Identity, Lang::En).join("\n");
        assert!(rows.contains("rejected"));
        assert!(rows.contains("unknown"));
        assert!(!rows.contains("private-path"));
    }
}
