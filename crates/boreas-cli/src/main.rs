//! Boreas single-binary entry point (master plan §1.1): the `boreas`
//! binary also serves as the `boreas-easy` console when invoked through
//! that symlink name (argv[0] detection, §10.5).
//!
//! This is the console's first slice: a pure rendering layer. There is NO
//! daemon, control socket, networking or TLS backend behind it yet
//! (`doctor`/`self-check` keep reporting that honestly). The full
//! interactive raw-mode TUI (master plan §10.4.1, 77x18 menu screen) is NOT
//! part of this slice; `boreas-easy` with no arguments currently renders
//! the same one-shot status screen as `boreas status`, and a future slice
//! will replace that with the raw-mode event loop fed by
//! `/run/boreas/control.sock`.

mod i18n;
mod render;

use std::env;
use std::io::IsTerminal;
use std::process::ExitCode;

use i18n::{Lang, lang_from_env, parse_lang};
use render::{StatusSnapshot, render_status};

const IMPLEMENTATION_SCOPE: &str = "Phase 0 policy/parser foundation only";

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
        Some("help") | Some("--help") | Some("-h") if args.len() == 1 => {
            (0, help_text(), String::new())
        }
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

fn help_text() -> String {
    "boreas — minimal Phase 0 policy/parser foundation\n\nUSAGE:\n  boreas [doctor|self-check|status|help]\n  boreas-easy   (status screen; interactive TUI not yet implemented)\n\nOPTIONS:\n  --lang <zh-CN|zh-TW|en>   console language (else BOREAS_LANG/LC_ALL/LANG)\n  boreas status --json      JSON snapshot (also the default when not a TTY)\n\nNo daemon, TLS backend, or networking is implemented."
        .to_string()
}

fn doctor_json() -> String {
    format!(
        "{{\"status\":\"foundation_only\",\"phase\":\"Phase 0\",\"scope\":\"{IMPLEMENTATION_SCOPE}\",\"daemon\":false,\"tls_backend\":false,\"networking\":false,\"phase0_complete\":false}}"
    )
}

#[cfg(test)]
mod tests {
    use super::{Lang, dispatch, extract_lang_flag, is_easy_entrypoint, run};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }

    /// Default probe: English regardless of input (tests stay hermetic).
    fn probe_en(_: Option<&str>) -> Lang {
        Lang::En
    }

    // --- Pre-existing tests (behavior must stay compatible) ---

    #[test]
    fn doctor_command_reports_explicit_limitations() {
        let (code, stdout, stderr) = run(&args(&["doctor"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"daemon\":false"));
        assert!(stdout.contains("\"tls_backend\":false"));
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
    fn rejects_extra_arguments() {
        let (code, _, stderr) = run(&args(&["doctor", "unexpected"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("unexpected argument"));
    }

    // --- New: status subcommand ---

    #[test]
    fn status_non_tty_outputs_json_snapshot() {
        let (code, stdout, stderr) = run(&args(&["status"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"command\":\"status\""));
        assert!(stdout.contains("\"daemon\":\"not_connected\""));
        assert!(stdout.contains("\"security_mode\":\"e2e-required\""));
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

    // --- New: --lang handling ---

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

    // --- New: boreas-easy argv[0] alias ---

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
    fn easy_still_accepts_explicit_commands() {
        let (code, stdout, _) = dispatch("boreas-easy", &args(&["doctor"]), probe_en, false);
        assert_eq!(code, 0);
        assert!(stdout.contains("\"daemon\":false"));
        let (code, _, _) = dispatch("boreas-easy", &args(&["bogus"]), probe_en, false);
        assert_eq!(code, 2);
    }
}
