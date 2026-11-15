//! Boreas single-binary entry point (master plan §1.1): the `boreas`
//! binary also serves as the `boreas-easy` console when invoked through
//! that symlink name (argv[0] detection, §10.5).
//!
//! This slice contains four honest pieces and nothing more:
//!
//! - a trilingual (`zh-CN` / `zh-TW` / `en`) one-shot rendering layer for the
//!   status screen (`status`, and `boreas-easy` with no arguments);
//! - a typed, fail-closed TOML configuration model with `config-check <path>`
//!   static policy validation and `config-migrate <path>` schema migration
//!   (stdout only; no file is rewritten);
//! - `doctor` / `self-check`, which keep reporting the missing daemon, TLS
//!   backend and networking.
//!
//! There is NO daemon, control socket, networking or TLS backend behind any of
//! this. `crates/boreas-tunnel` currently exposes only in-process session APIs
//! (`LinkClient` / `LinkServer`), no status snapshot and no `control.sock`, so
//! `status` keeps saying `daemon: not connected` and never fabricates a live
//! state. `menu` renders the §10.4.1 screen from an offline model only: no
//! raw mode, no DSR probe and no control socket (G-UI is not met).

mod config;
mod i18n;
mod render;
mod tui;

use std::env;
use std::io::IsTerminal;
use std::process::ExitCode;

use config::RuntimeCapabilities;
use i18n::{Lang, lang_from_env, parse_lang};
use render::{StatusSnapshot, render_status};
use tui::{DangerAction, MenuModel, confirm_dangerous, render_menu};

const IMPLEMENTATION_SCOPE: &str = "Phase 0 policy/config/console-rendering foundation only";

fn main() -> ExitCode {
    let mut argv = env::args();
    let argv0 = argv.next().unwrap_or_else(|| "boreas".to_string());
    let raw_args: Vec<String> = argv.collect();
    let (code, stdout, stderr) = dispatch(&argv0, &raw_args, env_lang_probe(), stdout_is_tty());
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    ExitCode::from(code)
}

/// Language probe against the real environment (thin wrapper over
/// [`i18n::lang_from_env`]; the selection logic itself is pure).
fn env_lang_probe() -> impl Fn(Option<&str>) -> Lang {
    lang_from_env
}

fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// True when argv[0]'s file name is `boreas-easy` (the console symlink of
/// §10.5). Directory components and a trailing `.exe` are ignored.
fn is_easy_entrypoint(argv0: &str) -> bool {
    let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
    base.strip_suffix(".exe").unwrap_or(base) == "boreas-easy"
}

/// Capability facts for this binary.
///
/// No runtime is integrated: `crates/boreas-tunnel` exposes only in-process
/// session APIs, there is no `control.sock`, and `boreas_dns::TcpDnsSupport`
/// reports `Unsupported`. When the tunnel crate publishes
/// `runtime_capabilities()`, this function must forward it verbatim instead of
/// hardcoding `NO_RUNTIME`; until then every capability-gated field is refused
/// rather than assumed.
fn runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities::NO_RUNTIME
}

/// Testable entry point: resolves the `boreas-easy` argv[0] alias, strips
/// the global `--lang` option, then hands off to [`run`].
///
/// When invoked as `boreas-easy` with no subcommand this is equivalent to
/// `status` (see the crate docs: the interactive raw-mode TUI is a future
/// slice, not implemented here).
fn dispatch(
    argv0: &str,
    raw_args: &[String],
    lang_probe: impl Fn(Option<&str>) -> Lang,
    stdout_tty: bool,
) -> (u8, String, String) {
    let (cli_lang, args) = match extract_lang_flag(raw_args) {
        Ok(pair) => pair,
        Err(msg) => return (2, String::new(), msg),
    };
    let lang = lang_probe(cli_lang.as_deref());
    if is_easy_entrypoint(argv0) && args.is_empty() {
        return run(&["status".to_string()], lang, stdout_tty);
    }
    run(&args, lang, stdout_tty)
}

/// Extract a global `--lang <tag>` / `--lang=<tag>` option (at most one).
/// Returns the raw tag plus the remaining arguments.
fn extract_lang_flag(raw_args: &[String]) -> Result<(Option<String>, Vec<String>), String> {
    let mut lang: Option<String> = None;
    let mut rest: Vec<String> = Vec::with_capacity(raw_args.len());
    let mut i = 0;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg == "--lang" {
            if lang.is_some() {
                return Err("error: --lang given more than once; run `boreas help`".to_string());
            }
            let Some(value) = raw_args.get(i + 1) else {
                return Err("error: --lang requires a value (zh-CN, zh-TW or en)".to_string());
            };
            lang = Some(value.clone());
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--lang=") {
            if lang.is_some() {
                return Err("error: --lang given more than once; run `boreas help`".to_string());
            }
            lang = Some(value.to_string());
            i += 1;
        } else {
            rest.push(arg.clone());
            i += 1;
        }
    }
    if let Some(tag) = &lang
        && parse_lang(tag).is_none()
    {
        return Err(format!(
            "error: unsupported language `{tag}`; expected zh-CN, zh-TW or en"
        ));
    }
    Ok((lang, rest))
}

fn run(args: &[String], lang: Lang, stdout_tty: bool) -> (u8, String, String) {
    match args.first().map(String::as_str) {
        None | Some("doctor") | Some("self-check") if args.len() <= 1 => {
            (0, doctor_json(), String::new())
        }
        None | Some("doctor") | Some("self-check") => (
            2,
            String::new(),
            "error: unexpected argument; run `boreas help`".into(),
        ),
        Some("status") => run_status(&args[1..], lang, stdout_tty),
        Some("menu") => run_menu(&args[1..], lang, stdout_tty),
        Some("confirm") => run_confirm(&args[1..]),
        Some("config-check") => run_config_check(&args[1..]),
        Some("config-migrate") => run_config_migrate(&args[1..]),
        Some("help") | Some("--help") | Some("-h") if args.len() == 1 => {
            (0, help_text(), String::new())
        }
        Some("help") | Some("--help") | Some("-h") => (
            2,
            String::new(),
            "error: unexpected argument; run `boreas help`".into(),
        ),
        Some(command) => (
            2,
            String::new(),
            format!("error: unknown or unavailable command `{command}`; no daemon was started"),
        ),
    }
}

/// `status [--json]`: render the offline status snapshot. There is no
/// daemon to ask yet, so the snapshot is [`StatusSnapshot::offline`] and
/// says so. Non-TTY output (or an explicit `--json`) is JSON (§10.4).
fn run_status(args: &[String], lang: Lang, stdout_tty: bool) -> (u8, String, String) {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => {
                return (
                    2,
                    String::new(),
                    format!("error: unexpected argument `{other}`; run `boreas help`"),
                );
            }
        }
    }
    let snapshot = StatusSnapshot::offline(env!("CARGO_PKG_VERSION"));
    if json || !stdout_tty {
        (0, snapshot.to_json(lang), String::new())
    } else {
        (0, render_status(&snapshot, lang), String::new())
    }
}

/// `menu [--json] [--narrow]`: render the §10.4.1 nine-entry screen from an
/// offline model. Non-TTY or `--json` prints JSON with `"daemon": false`.
/// `--narrow` prints the degraded list. A non-empty `NO_COLOR` is read only
/// here and only sets `no_color`; this command never emits color either way.
/// No control socket is opened and no live mesh is invented.
fn run_menu(args: &[String], lang: Lang, stdout_tty: bool) -> (u8, String, String) {
    let mut json = false;
    let mut narrow = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--narrow" => narrow = true,
            other => {
                return (
                    2,
                    String::new(),
                    format!("error: unexpected argument `{other}`; run `boreas help`"),
                );
            }
        }
    }
    let mut model = MenuModel::offline(env!("CARGO_PKG_VERSION"), lang);
    model.narrow = narrow;
    model.no_color = no_color_set();
    if json || !stdout_tty {
        return (0, model.to_json(), String::new());
    }
    match render_menu(&model) {
        Ok(screen) => (0, screen, String::new()),
        Err(error) => (2, String::new(), format!("error: {error}")),
    }
}

/// `NO_COLOR` is set when the variable exists and is non-empty. Read only by
/// [`run_menu`]; other commands ignore it.
fn no_color_set() -> bool {
    match std::env::var("NO_COLOR") {
        Ok(value) => !value.is_empty(),
        Err(_) => false,
    }
}

/// `confirm <hop-only|revoke:<id>|uninstall> <typed...>`: compare the joined
/// typed phrase and stop. Accept prints `applied: false` because no daemon
/// action exists. Reject exits 2. The mode is never changed.
fn run_confirm(args: &[String]) -> (u8, String, String) {
    let Some(action_arg) = args.first() else {
        return (
            2,
            String::new(),
            "error: confirm requires an action (hop-only, revoke:<id>, uninstall)".into(),
        );
    };
    let action = match parse_danger_action(action_arg) {
        Ok(action) => action,
        Err(message) => return (2, String::new(), message),
    };
    let typed = args[1..].join(" ");
    match confirm_dangerous(&action, &typed) {
        Ok(()) => (
            0,
            "{\"accepted\":true,\"applied\":false,\"reason\":\"confirmation recorded; no daemon action exists\"}".to_string(),
            String::new(),
        ),
        Err(_) => (
            2,
            "{\"accepted\":false,\"applied\":false}".to_string(),
            String::new(),
        ),
    }
}

fn parse_danger_action(raw: &str) -> Result<DangerAction, String> {
    if raw == "hop-only" {
        return Ok(DangerAction::HopOnly);
    }
    if raw == "uninstall" {
        return Ok(DangerAction::Uninstall);
    }
    if let Some(id) = raw.strip_prefix("revoke:") {
        if !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_digit())
            && let Ok(node_id) = id.parse::<u64>()
        {
            return Ok(DangerAction::Revoke { node_id });
        }
        return Err(format!(
            "error: revoke id must be a decimal integer; got `{id}`"
        ));
    }
    Err(format!(
        "error: unknown confirm action `{raw}`; expected hop-only, revoke:<id> or uninstall"
    ))
}

/// `config-check <path>`: parse and statically validate one TOML file, then
/// print redacted JSON. This never starts a daemon, opens a socket, reads key or
/// trust-anchor contents, resolves an endpoint or establishes TLS, so success
/// means "the document matches the declared schema and static policy" only.
/// Output is machine-readable JSON in every language, so `--lang` intentionally
/// does not change it; only human-facing console screens are localized (§10.4).
fn run_config_check(args: &[String]) -> (u8, String, String) {
    let [path] = args else {
        return (
            2,
            String::new(),
            "error: config-check requires exactly one config path".into(),
        );
    };
    match config::Config::read_file(std::path::Path::new(path), runtime_capabilities()) {
        Ok(config) => (0, config.redacted_json(), String::new()),
        Err(error) => (
            2,
            String::new(),
            format!("error: configuration rejected: {error}"),
        ),
    }
}

/// `config-migrate <path>`: read a legacy (`version = 1`) document and print its
/// canonical `version = 2` equivalent on stdout. The file on disk is never
/// modified, so migration is explicit: the operator reviews and installs it.
fn run_config_migrate(args: &[String]) -> (u8, String, String) {
    let [path] = args else {
        return (
            2,
            String::new(),
            "error: config-migrate requires exactly one config path".into(),
        );
    };
    match config::Config::read_file(std::path::Path::new(path), runtime_capabilities()) {
        Ok(config) => (0, config.to_v2_toml(), String::new()),
        Err(error) => (
            2,
            String::new(),
            format!("error: configuration rejected: {error}"),
        ),
    }
}

fn help_text() -> String {
    "boreas — Phase 0 policy/config/console foundation\n\n\
     USAGE:\n\
     \x20 boreas [doctor|self-check|status [--json]|menu [--json] [--narrow]|confirm <action> <typed...>|config-check <path>|config-migrate <path>|help]\n\
     \x20 boreas-easy   (one-shot status screen; interactive TUI not implemented)\n\n\
     OPTIONS:\n\
     \x20 --lang <zh-CN|zh-TW|en>   console language (else BOREAS_LANG/LC_ALL/LANG)\n\
     \x20 boreas status --json      JSON snapshot (also the default when not a TTY)\n\
     \x20 boreas menu [--narrow]    offline 9-entry screen (JSON when not a TTY)\n\
     \x20 boreas confirm hop-only|revoke:<id>|uninstall <phrase>\n\
     \x20                          records the phrase only; never applies it\n\n\
     config-check parses one TOML file (`version = 1` legacy or `version = 2`),\n\
     validates static policy and prints redacted JSON. config-migrate prints the\n\
     canonical version = 2 document for a legacy file and never rewrites it.\n\
     Neither starts a daemon, opens sockets, loads key or trust-anchor contents,\n\
     or establishes TLS.\n\n\
     No daemon, TLS backend, or networking is implemented."
        .to_string()
}

fn doctor_json() -> String {
    format!(
        "{{\"status\":\"foundation_only\",\"phase\":\"Phase 0\",\"scope\":\"{IMPLEMENTATION_SCOPE}\",\"daemon\":false,\"tls_backend\":false,\"networking\":false,\"control_socket\":false,\"config_check\":true,\"config_migrate\":true,\"status_screen\":true,\"console_menu\":true,\"runtime_capabilities\":\"not_integrated\",\"phase0_complete\":false}}"
    )
}

#[cfg(test)]
mod tests {
    use super::{Lang, dispatch, extract_lang_flag, is_easy_entrypoint, run};
    use crate::config::RuntimeCapabilities;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }

    /// Default probe: English regardless of input (tests stay hermetic).
    fn probe_en(_: Option<&str>) -> Lang {
        Lang::En
    }

    /// Absolute fixture root valid on the host family. TOML basic strings
    /// interpret backslashes, so Windows uses forward slashes (`C:/...`).
    #[cfg(windows)]
    const TEST_BASE: &str = "C:/boreas-tests";
    #[cfg(not(windows))]
    const TEST_BASE: &str = "/boreas-tests";

    fn config_source() -> String {
        format!(
            r#"
version = 2
[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
[paths]
identity_key = "{TEST_BASE}/secret/identity.key"
roots = ["{TEST_BASE}/secret/roots.cbor"]
state_dir = "{TEST_BASE}/secret/state"
[uplink]
primary = "hub-us-c.example.net:443"
paths = 4
probe_paths = 1
"#
        )
    }
}

    fn legacy_source() -> String {
        format!(
            r#"
version = 1
[network]
net_id = "0123456789abcdef0123456789abcdef"
[identity]
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
private_key = "{TEST_BASE}/secret/identity.key"
[paths]
roots = ["{TEST_BASE}/secret/roots.cbor"]
state_dir = "{TEST_BASE}/secret/state"
[transport]
uplinks = ["wss://hub-us-c.example.net"]
"#
        )
    }

    /// Write a fixture with `0600` on Unix; returns the path.
    fn write_fixture(name: &str, body: &str) -> std::path::PathBuf {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "boreas-{name}-{}-{unique}.toml",
            std::process::id()
        ));
        fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    // --- Pre-existing tests (behavior must stay compatible) ---

    #[test]
    fn doctor_command_reports_explicit_limitations() {
        let (code, stdout, stderr) = run(&args(&["doctor"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"daemon\":false"));
        assert!(stdout.contains("\"tls_backend\":false"));
        assert!(stdout.contains("\"control_socket\":false"));
        assert!(stdout.contains("\"runtime_capabilities\":\"not_integrated\""));
        assert!(stdout.contains("\"phase0_complete\":false"));
    }

    #[test]
    fn default_and_self_check_are_doctor() {
        assert_eq!(run(&[], Lang::En, false).0, 0);
        assert_eq!(run(&args(&["self-check"]), Lang::En, false).0, 0);
    }

    #[test]
    fn daemon_and_unknown_commands_fail_without_starting() {
        for command in ["daemon", "made-up"] {
            let (code, stdout, stderr) = run(&args(&[command]), Lang::En, false);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(stderr.contains("no daemon was started"));
        }
    }

    #[test]
    fn config_check_validates_v2_file_and_redacts_secrets() {
        let path = write_fixture("config-check", &config_source());
        let (code, stdout, stderr) = run(
            &args(&["config-check", path.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("\"valid\":true"));
        assert!(stdout.contains("\"schema_version\":2"));
        assert!(stdout.contains("\"migrated\":false"));
        assert!(stdout.contains("[REDACTED]"));
        assert!(!stdout.contains("identity.key"));
        assert!(!stdout.contains("hub-us-c.example.net"));
    }

    #[test]
    fn config_check_marks_legacy_documents_as_migrated() {
        let path = write_fixture("config-legacy", &legacy_source());
        let (code, stdout, stderr) = run(
            &args(&["config-check", path.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("\"schema\":\"legacy-v1\""));
        assert!(stdout.contains("\"migrated\":true"));
    }

    #[test]
    fn config_migrate_prints_v2_and_never_rewrites_the_file() {
        let path = write_fixture("config-migrate", &legacy_source());
        let before = std::fs::read_to_string(&path).unwrap();
        let (code, stdout, stderr) = run(
            &args(&["config-migrate", path.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let after = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("version = 2"));
        assert!(stdout.contains("[node]"));
        assert!(stdout.contains("primary = \"hub-us-c.example.net:443\""));
        assert_eq!(before, after, "config-migrate must not touch the file");
    }

    #[test]
    fn migrated_output_passes_config_check() {
        let legacy = write_fixture("config-roundtrip-src", &legacy_source());
        let (code, migrated, stderr) = run(
            &args(&["config-migrate", legacy.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let _ = std::fs::remove_file(&legacy);
        assert_eq!(code, 0, "{stderr}");
        let v2 = write_fixture("config-roundtrip-dst", &migrated);
        let (code, stdout, stderr) = run(
            &args(&["config-check", v2.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let _ = std::fs::remove_file(&v2);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("\"schema_version\":2"));
    }

    #[test]
    fn config_check_requires_path_and_never_starts_daemon() {
        let (code, stdout, stderr) = run(&args(&["config-check"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires exactly one config path"));

        let (code, stdout, stderr) = run(
            &args(&["config-check", "a.toml", "b.toml"]),
            Lang::En,
            false,
        );
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires exactly one config path"));
    }

    #[test]
    fn config_check_rejects_missing_and_unsafe_files() {
        let missing = std::env::temp_dir().join("boreas-config-check-missing-does-not-exist.toml");
        let _ = std::fs::remove_file(&missing);
        let (code, stdout, stderr) = run(
            &args(&["config-check", missing.to_str().unwrap()]),
            Lang::En,
            false,
        );
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("could not be read"));

        // §5.5 requires 0600; an explicitly world-readable copy must be refused.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use std::time::{SystemTime, UNIX_EPOCH};
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "boreas-config-check-perm-{}-{unique}.toml",
                std::process::id()
            ));
            std::fs::write(&path, config_source()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let (code, stdout, stderr) = run(
                &args(&["config-check", path.to_str().unwrap()]),
                Lang::En,
                false,
            );
            let _ = std::fs::remove_file(&path);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(stderr.contains("group- or world-accessible"));
        }
    }

    #[test]
    fn config_check_output_is_json_even_with_lang_flag() {
        let path = write_fixture("config-check-lang", &config_source());
        let (code, stdout, stderr) = dispatch(
            "boreas",
            &args(&["--lang", "zh-CN", "config-check", path.to_str().unwrap()]),
            probe_en,
            true,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.starts_with('{'), "{stdout}");
        assert!(stdout.contains("\"valid\":true"));
        assert!(stdout.contains("\"security_mode\":\"e2e-required\""));
    }

    #[test]
    fn config_check_refuses_capability_gated_fields_without_a_runtime() {
        // `[dns].tcp` is not schema-banned: the same document flips to accepted
        // purely by changing the capability value.
        let with_tcp = format!("{}[dns]\ntcp = true\n", config_source());
        let path = write_fixture("config-capability", &with_tcp);
        let (code, _, stderr) = run(
            &args(&["config-check", path.to_str().unwrap()]),
            Lang::En,
            false,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 2);
        assert!(
            stderr.contains("no integrated runtime reported that capability"),
            "{stderr}"
        );

        assert!(
            crate::config::Config::parse_toml(&with_tcp, RuntimeCapabilities::FULL)
                .expect("same document must validate once the capability exists")
                .dns
                .unwrap()
                .tcp
        );
    }

    #[test]
    fn help_lists_config_commands_and_never_claims_a_daemon() {
        let (code, stdout, _) = run(&args(&["help"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stdout.contains("config-check <path>"));
        assert!(stdout.contains("config-migrate <path>"));
        assert!(stdout.contains("No daemon, TLS backend, or networking is implemented."));
        let (code, _, stderr) = run(&args(&["help", "extra"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("unexpected argument"));
    }

    #[test]
    fn rejects_extra_arguments() {
        let (code, _, stderr) = run(&args(&["doctor", "unexpected"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("unexpected argument"));
    }

    // --- status subcommand ---

    #[test]
    fn status_non_tty_outputs_json_snapshot() {
        let (code, stdout, stderr) = run(&args(&["status"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"command\":\"status\""));
        assert!(stdout.contains("\"daemon\":\"not_connected\""));
        assert!(stdout.contains("\"security_mode\":\"e2e-required\""));
        // Never claim a live daemon or a PQ channel.
        assert!(!stdout.contains("\"daemon\":\"connected\""));
    }

    #[test]
    fn status_json_flag_forces_json_even_on_tty() {
        let (code, stdout, _) = run(&args(&["status", "--json"]), Lang::ZhTw, true);
        assert_eq!(code, 0);
        assert!(stdout.starts_with('{'));
        assert!(stdout.contains("\"lang\":\"zh-TW\""));
    }

    #[test]
    fn status_on_tty_renders_box_without_ansi() {
        // NO_COLOR (§10.4) is honored by construction: this slice never
        // emits ANSI escapes, with or without the variable set.
        for lang in [Lang::ZhCn, Lang::ZhTw, Lang::En] {
            let (code, stdout, stderr) = run(&args(&["status"]), lang, true);
            assert_eq!(code, 0);
            assert!(stderr.is_empty());
            assert!(stdout.contains("BOREAS CONSOLE"));
            assert!(stdout.contains("daemon: not connected"));
            assert!(!stdout.as_bytes().contains(&0x1B), "ANSI in {lang:?}");
        }
    }

    #[test]
    fn status_rejects_unexpected_arguments() {
        let (code, stdout, _) = run(&args(&["status", "now"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
    }

    // --- --lang handling ---

    #[test]
    fn lang_flag_is_extracted_before_the_command() {
        let (lang, rest) = extract_lang_flag(&args(&["--lang", "zh-TW", "status", "--json"]))
            .expect("valid flags");
        assert_eq!(lang.as_deref(), Some("zh-TW"));
        assert_eq!(rest, args(&["status", "--json"]));
    }

    #[test]
    fn lang_flag_supports_equals_form_after_command() {
        let (lang, rest) =
            extract_lang_flag(&args(&["status", "--lang=zh-CN", "--json"])).expect("valid flags");
        assert_eq!(lang.as_deref(), Some("zh-CN"));
        assert_eq!(rest, args(&["status", "--json"]));
    }

    #[test]
    fn lang_flag_errors_are_exit_2_without_stdout() {
        for bad in [
            args(&["--lang"]),
            args(&["--lang", "fr", "status"]),
            args(&["--lang", "en", "--lang", "zh-CN"]),
        ] {
            let (code, stdout, stderr) = dispatch("boreas", &bad, probe_en, false);
            assert_eq!(code, 2, "args: {bad:?}");
            assert!(stdout.is_empty());
            assert!(stderr.starts_with("error:"));
        }
    }

    // --- boreas-easy argv[0] alias ---

    #[test]
    fn easy_entrypoint_detection() {
        assert!(is_easy_entrypoint("boreas-easy"));
        assert!(is_easy_entrypoint("/usr/local/bin/boreas-easy"));
        assert!(is_easy_entrypoint("./boreas-easy"));
        assert!(is_easy_entrypoint("boreas-easy.exe"));
        assert!(!is_easy_entrypoint("boreas"));
        assert!(!is_easy_entrypoint("/usr/local/bin/boreas"));
        assert!(!is_easy_entrypoint("boreas-supervisor"));
    }

    #[test]
    fn easy_with_no_args_is_status() {
        let easy = dispatch("/usr/bin/boreas-easy", &[], probe_en, false);
        let status = run(&args(&["status"]), Lang::En, false);
        assert_eq!(easy, status);
        assert_eq!(easy.0, 0);
    }

    #[test]
    fn menu_non_tty_is_offline_json() {
        let (code, stdout, stderr) = run(&args(&["menu"]), Lang::ZhCn, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"command\":\"menu\""));
        assert!(stdout.contains("\"daemon\":false"));
        assert!(stdout.contains("\"lang\":\"zh-CN\""));
        assert!(stdout.contains("\"mode\":\"e2e-required\""));
        assert!(stdout.contains("\"selected\":1"));
        assert!(stdout.contains("\"console_menu\":true"));
        assert!(!stdout.contains("\"daemon\":true"));
    }

    #[test]
    fn menu_tty_is_boxed_and_narrow_is_not() {
        let (code, stdout, stderr) = run(&args(&["menu"]), Lang::En, true);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("BOREAS CONSOLE"));
        assert!(stdout.contains("e2e-required"));
        assert!(!stdout.as_bytes().contains(&0x1B));
        assert_eq!(stdout.split('\n').count(), 18);

        let (code, narrow, _) = run(&args(&["menu", "--narrow"]), Lang::En, true);
        assert_eq!(code, 0);
        assert!(!narrow.contains('┌'));
        assert!(narrow.contains("[1]"));
        assert_ne!(narrow.split('\n').count(), 18);
    }

    #[test]
    fn menu_json_flag_forces_json_on_tty() {
        let (code, stdout, _) = run(&args(&["menu", "--json", "--narrow"]), Lang::ZhTw, true);
        assert_eq!(code, 0);
        assert!(stdout.starts_with('{'));
        assert!(stdout.contains("\"narrow\":true"));
        assert!(stdout.contains("\"daemon\":false"));
        assert!(stdout.contains("\"lang\":\"zh-TW\""));
    }

    #[test]
    fn confirm_accepts_exact_phrase_without_applying() {
        let (code, stdout, stderr) = run(&args(&["confirm", "hop-only", "HOP-ONLY"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "{\"accepted\":true,\"applied\":false,\"reason\":\"confirmation recorded; no daemon action exists\"}"
        );
        let (code, stdout, _) = run(&args(&["confirm", "revoke:42", "REVOKE", "42"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stdout.contains("\"applied\":false"));
        let (code, stdout, _) = run(&args(&["confirm", "uninstall", "UNINSTALL"]), Lang::En, true);
        assert_eq!(code, 0);
        assert!(stdout.contains("\"accepted\":true"));
    }

    #[test]
    fn confirm_rejects_wrong_phrase_with_exit_2() {
        let (code, stdout, _) = run(&args(&["confirm", "hop-only", "hop-only"]), Lang::En, false);
        assert_eq!(code, 2);
        assert_eq!(stdout, "{\"accepted\":false,\"applied\":false}");
        let (code, stdout, _) = run(&args(&["confirm", "revoke:7", "REVOKE", "8"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stdout.contains("\"accepted\":false"));
        let (code, _, stderr) = run(&args(&["confirm"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("confirm requires"));
        let (code, _, stderr) = run(&args(&["confirm", "revoke:nope", "REVOKE nope"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("decimal"));
    }

    #[test]
    fn easy_still_accepts_explicit_commands() {
        let (code, stdout, _) = dispatch("boreas-easy", &args(&["doctor"]), probe_en, false);
        assert_eq!(code, 0);
        assert!(stdout.contains("\"daemon\":false"));
        let (code, _, _) = dispatch("boreas-easy", &args(&["bogus"]), probe_en, false);
        assert_eq!(code, 2);
    }
}
}
}
