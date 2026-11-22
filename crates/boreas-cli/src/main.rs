//! Boreas single-binary entry point (master plan §1.1): the `boreas`
//! binary also serves as the `boreas-easy` console when invoked through
//! that symlink name (argv[0] detection, §10.5).
//!
//! This slice contains the policy/config/console foundation plus an optional
//! hop-node process:
//!
//! - a trilingual (`zh-CN` / `zh-TW` / `en`) rendering layer for the status
//!   screen (`status`), the one-shot 9-entry screen (`menu`) and the
//!   line-mode console (`console`, also reached as `boreas-easy`);
//! - a typed, fail-closed TOML configuration model with `config-check <path>`
//!   static policy validation and `config-migrate <path>` schema migration
//!   (stdout only; no file is rewritten);
//! - `doctor` / `self-check`, which keep reporting the missing production
//!   daemon, TUN data plane and control socket;
//! - `node serve` / `node connect`, which refuse to start in the default
//!   binary because it has no TLS backend. The `openssl-inner-tls` feature
//!   links the reviewed OpenSSL pq768 hop path and runs one outer TLS 1.3
//!   plus one hop inner TLS session. That is not a production daemon, not
//!   E2E relay, and not a passed gate.
//!
//! `boreas-easy` / `boreas console` is a **line-oriented** console: it prints
//! the §10.4.1 box, prints a prompt, and reads one line per screen. There is no
//! raw mode and no key-level input, so an abnormal exit cannot leave a terminal
//! in a raw state (§10.4: `SIGKILL` cannot be made to run `Drop`). The box is
//! 77 columns wide, so it is only drawn when the *measured* terminal width
//! allows it: the width comes from `TIOCGWINSZ` / `GetConsoleScreenBufferInfo`,
//! never from a Device Status Report (`ESC [ 6 n`) probe, so nothing is left in
//! the operator's input queue. A narrower terminal gets the plain list instead
//! of a ragged frame. Non-TTY output stays JSON. Live status comes from the
//! authorized Unix control socket; when that fails the screen says `offline`
//! and shows the reason instead of inventing a mesh. Service start/stop run
//! `systemctl` or `/etc/init.d/boreas` with an argument vector (no shell) and
//! only after an exact typed phrase; security-mode changes, revocation and
//! uninstall are refused. **G-UI is still not passed.**

mod config;
mod daemon;
mod i18n;
mod network_policy_runtime;
mod node;
mod pki_cmd;
mod render;
mod tui;
mod update;

use std::env;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use config::{Config, NodeRole, RuntimeCapabilities};
use i18n::{Lang, Msg, lang_from_env, parse_lang, text};
use render::{
    BOX_WIDTH, DaemonState, StatusSnapshot, fits_boxed, render_status, render_status_narrow,
};
use tui::{
    ConfigWizardStep, ConsoleEffect, ConsoleState, ConsoleView, DETAIL_ROWS, DangerAction,
    MenuModel, confirm_dangerous, render_menu, sanitize_line,
};

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

/// Width of the terminal stdout is attached to, in columns, measured from the
/// platform console itself.
///
/// Unix uses `TIOCGWINSZ` and Windows uses `GetConsoleScreenBufferInfo`; both
/// report the size in kernel/driver state. No bytes are written to the terminal
/// and no reply is parsed, so this never emits a Device Status Report
/// (`ESC [ 6 n`) and cannot leave an unread reply in the operator's input
/// queue. When stdout is not a terminal (or the probe fails) the answer is
/// `None` and the caller keeps the fixed 77-column frame rather than guessing a
/// narrower one (§10.4: no terminal is ever told it has 77 columns when it does
/// not).
#[cfg(unix)]
fn terminal_columns() -> Option<usize> {
    use std::os::unix::io::AsRawFd;

    let fd = std::io::stdout().as_raw_fd();
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `TIOCGWINSZ` writes exactly one `struct winsize` through the
    // pointer and reads nothing else; `size` is a live, properly aligned local.
    let status = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
    if status != 0 {
        return None;
    }
    let columns = usize::from(size.ws_col);
    (columns > 0).then_some(columns)
}

/// Windows: the visible window rectangle, not the scrollback buffer, is the
/// width the operator can see. The two kernel32 imports are declared locally so
/// this crate keeps its existing dependency set.
#[cfg(windows)]
fn terminal_columns() -> Option<usize> {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(
        dead_code,
        reason = "layout mirror of COORD; kept only so the record size matches the SDK"
    )]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(
        dead_code,
        reason = "layout mirror of SMALL_RECT; only left/right (the visible width) are read"
    )]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }

    /// `CONSOLE_SCREEN_BUFFER_INFO`, in the order and layout of the SDK header.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(
        dead_code,
        reason = "layout mirror of CONSOLE_SCREEN_BUFFER_INFO; only the window rect is read"
    )]
    struct ScreenBufferInfo {
        size: Coord,
        cursor: Coord,
        attributes: u16,
        window: SmallRect,
        maximum_window: Coord,
    }

    /// `(DWORD)-11`, the documented value of `STD_OUTPUT_HANDLE`.
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleScreenBufferInfo(console: *mut c_void, info: *mut ScreenBufferInfo) -> i32;
    }

    // SAFETY: `GetStdHandle` takes a constant selector and returns a handle this
    // code only null-checks and hands back to the console API, which validates
    // it. `GetConsoleScreenBufferInfo` writes exactly one
    // `CONSOLE_SCREEN_BUFFER_INFO` into the out-pointer; the local `#[repr(C)]`
    // mirror above has the SDK layout and size, so the write stays in bounds.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return None;
        }
        let mut info = ScreenBufferInfo::default();
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            return None;
        }
        let width = i32::from(info.window.right) - i32::from(info.window.left) + 1;
        usize::try_from(width).ok().filter(|columns| *columns > 0)
    }
}

/// Neither Unix nor Windows: the width is unknown, so the caller keeps the
/// fixed frame. No probe is attempted.
#[cfg(not(any(unix, windows)))]
fn terminal_columns() -> Option<usize> {
    None
}

/// Measured columns, but only when stdout really is a terminal: a redirected
/// stream has no size and must stay on the JSON path.
fn measured_columns(stdout_tty: bool) -> Option<usize> {
    if stdout_tty { terminal_columns() } else { None }
}

/// True when argv[0]'s file name is `boreas-easy` (the console symlink of
/// §10.5). Directory components and a trailing `.exe` are ignored.
fn is_easy_entrypoint(argv0: &str) -> bool {
    let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
    base.strip_suffix(".exe").unwrap_or(base) == "boreas-easy"
}

/// Standalone config tools have no bound daemon profile. The Linux daemon
/// validates capabilities separately with its launch arguments; a generic
/// config check cannot attest to TUN, pinned DNS material or an E2E circuit.
fn runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities::NO_RUNTIME
}

/// Testable entry point: resolves the `boreas-easy` argv[0] alias, strips
/// the global `--lang` option, then hands off to [`run_with_columns`] with the
/// terminal width measured once (see [`terminal_columns`]).
///
/// `boreas-easy` with no subcommand enters the line-mode console, which is
/// interactive on a TTY and JSON otherwise (see [`run_console`]).
fn dispatch(
    argv0: &str,
    raw_args: &[String],
    lang_probe: impl Fn(Option<&str>) -> Lang,
    stdout_tty: bool,
) -> (u8, String, String) {
    dispatch_with_columns(
        argv0,
        raw_args,
        lang_probe,
        stdout_tty,
        measured_columns(stdout_tty),
    )
}

/// [`dispatch`] with the terminal width supplied by the caller, so the whole
/// entry path (including the `boreas-easy` alias) is testable without a real
/// terminal.
fn dispatch_with_columns(
    argv0: &str,
    raw_args: &[String],
    lang_probe: impl Fn(Option<&str>) -> Lang,
    stdout_tty: bool,
    columns: Option<usize>,
) -> (u8, String, String) {
    let (cli_lang, args) = match extract_lang_flag(raw_args) {
        Ok(pair) => pair,
        Err(msg) => return (2, String::new(), msg),
    };
    let lang = lang_probe(cli_lang.as_deref());
    if is_easy_entrypoint(argv0)
        && (args.is_empty()
            || matches!(
                args.first().map(String::as_str),
                Some("--socket" | "--config" | "--service" | "--json" | "--narrow")
            ))
    {
        let mut console_args = vec!["console".to_string()];
        console_args.extend(args);
        return run_with_columns(&console_args, lang, stdout_tty, columns);
    }
    run_with_columns(&args, lang, stdout_tty, columns)
}

/// Echo an operator-supplied argv value into a diagnostic without letting a
/// control character reach the terminal. `?` replaces every control, exactly
/// as [`sanitize_line`] does for screen fields (§10.4 terminal-injection
/// defense): a hostile argument must never be able to emit `ESC [ 31 m` into
/// stderr just because it was rejected.
fn sanitize_arg(value: &str) -> String {
    sanitize_line(value)
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
            "error: unsupported language `{}`; expected zh-CN, zh-TW or en",
            sanitize_arg(tag)
        ));
    }
    Ok((lang, rest))
}

#[cfg(test)]
fn run(args: &[String], lang: Lang, stdout_tty: bool) -> (u8, String, String) {
    run_with_columns(args, lang, stdout_tty, measured_columns(stdout_tty))
}

/// [`run`] with the measured terminal width supplied by the caller. Every
/// screen decision (77-column frame, narrow list, JSON) is made from these two
/// facts, which is what makes the degraded paths testable without a terminal.
fn run_with_columns(
    args: &[String],
    lang: Lang,
    stdout_tty: bool,
    columns: Option<usize>,
) -> (u8, String, String) {
    match args.first().map(String::as_str) {
        None | Some("doctor") | Some("self-check") if args.len() <= 1 => {
            (0, doctor_json(), String::new())
        }
        None | Some("doctor") | Some("self-check") => (
            2,
            String::new(),
            "error: unexpected argument; run `boreas help`".into(),
        ),
        Some("status") => run_status(&args[1..], lang, stdout_tty, columns),
        Some("menu") => run_menu(&args[1..], lang, stdout_tty, columns),
        Some("console") => run_console(&args[1..], lang, stdout_tty, columns),
        Some("update-check") => update::run(&args[1..], lang),
        Some("update") => update::offline(&args[1..]),
        Some("--version") if args.len() == 1 => {
            (0, format!("Boreas {}", update::local_build()), String::new())
        }
        Some("confirm") => run_confirm(&args[1..]),
        Some("config-check") => run_config_check(&args[1..]),
        Some("config-migrate") => run_config_migrate(&args[1..]),
        Some("config-save-candidate") => run_config_save_candidate(&args[1..]),
        Some("node") => node::run(&args[1..]),
        Some("pki") => match pki_cmd::run_pki_command(&args[1..]) {
            Ok(()) => (0, String::new(), String::new()),
            Err(err) => (
                2,
                String::new(),
                format!("error: {err}; no daemon was started"),
            ),
        },
        Some("daemon") => match daemon::run_daemon_command(&args[1..]) {
            Ok(()) => (0, String::new(), String::new()),
            Err(err) => (
                2,
                String::new(),
                format!("error: {err}; no daemon was started"),
            ),
        },
        Some("ctl") => match daemon::run_ctl_command(&args[1..]) {
            Ok(()) => (0, String::new(), String::new()),
            Err(err) => (
                2,
                String::new(),
                format!("error: {err}; no daemon was started"),
            ),
        },
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
            format!(
                "error: unknown or unavailable command `{}`; no daemon was started",
                sanitize_arg(command)
            ),
        ),
    }
}

/// `status [--json]`: render the offline status snapshot. There is no
/// daemon to ask yet, so the snapshot is [`StatusSnapshot::offline`] and
/// says so. Non-TTY output (or an explicit `--json`) is JSON (§10.4); a
/// terminal measured narrower than the 77-column frame gets the plain list.
fn run_status(
    args: &[String],
    lang: Lang,
    stdout_tty: bool,
    columns: Option<usize>,
) -> (u8, String, String) {
    let mut json = false;
    let mut socket_path: Option<std::path::PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json = true;
                i += 1;
            }
            "--socket" => {
                let Some(val) = args.get(i + 1) else {
                    return (
                        2,
                        String::new(),
                        "error: --socket requires a path; run `boreas help`".into(),
                    );
                };
                socket_path = Some(std::path::PathBuf::from(val));
                i += 2;
            }
            other => {
                return (
                    2,
                    String::new(),
                    format!(
                        "error: unexpected argument `{}`; run `boreas help`",
                        sanitize_arg(other)
                    ),
                );
            }
        }
    }
    let snapshot = match socket_path {
        Some(sock) => match daemon::query_control_socket(&sock) {
            Ok((live, _)) => live,
            Err(err) => {
                return (2, String::new(), format!("error: {err}"));
            }
        },
        None => StatusSnapshot::offline(env!("CARGO_PKG_VERSION")),
    };
    if json || !stdout_tty {
        (0, snapshot.to_json(lang), String::new())
    } else if fits_boxed(columns) {
        (0, render_status(&snapshot, lang), String::new())
    } else {
        let width = columns.unwrap_or(BOX_WIDTH).min(BOX_WIDTH);
        (
            0,
            render_status_narrow(&snapshot, lang, width),
            String::new(),
        )
    }
}

/// `menu [--json] [--narrow]`: render the §10.4.1 nine-entry screen from an
/// offline model. Non-TTY or `--json` prints JSON with `"daemon": false`.
/// `--narrow` prints the degraded list, and so does a terminal measured
/// narrower than the 77-column frame. A non-empty `NO_COLOR` is read only
/// here and only sets `no_color`; this command never emits color either way.
/// No control socket is opened and no live mesh is invented.
fn run_menu(
    args: &[String],
    lang: Lang,
    stdout_tty: bool,
    columns: Option<usize>,
) -> (u8, String, String) {
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
                    format!(
                        "error: unexpected argument `{}`; run `boreas help`",
                        sanitize_arg(other)
                    ),
                );
            }
        }
    }
    let mut model = MenuModel::offline(env!("CARGO_PKG_VERSION"), lang);
    model.narrow = narrow || !fits_boxed(columns);
    model.no_color = no_color_set();
    if json || !stdout_tty {
        return (0, model.to_json(), String::new());
    }
    match render_menu(&model) {
        Ok(screen) => (0, screen, String::new()),
        Err(error) => (2, String::new(), format!("error: {error}")),
    }
}

/// `NO_COLOR` is set when the variable exists and is non-empty. Read by the
/// screen builders (`menu` and `console`); it never enables color, it only
/// records that the caller does not want any.
fn no_color_set() -> bool {
    match std::env::var("NO_COLOR") {
        Ok(value) => !value.is_empty(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Line-mode console (`boreas-easy` / `boreas console`)
// ---------------------------------------------------------------------------

/// Authorized control socket from master plan §10.5. The daemon currently
/// binds `state_dir/control.sock`; `--socket` overrides this default.
const DEFAULT_CONTROL_SOCKET: &str = "/run/boreas/control.sock";

/// Configuration path from master plan §5.5.
const DEFAULT_CONFIG_PATH: &str = "/etc/boreas/config.toml";

/// Parsed `console` options.
struct ConsoleOptions {
    socket: PathBuf,
    config: PathBuf,
    service: Option<String>,
    narrow: bool,
    json: bool,
}

/// One value for a flag that requires it. Missing values are exit-2 errors,
/// never a silent default.
fn take_flag_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("error: {flag} requires a value; run `boreas help`"))
}

/// `console [--json] [--narrow] [--socket <PATH>] [--config <FILE>]
/// [--service <UNIT>]`: the line-mode management console.
///
/// On a TTY this reads one line per screen from stdin; otherwise (`--json` or
/// no TTY) it prints one JSON object and returns, so scripts and pipes never
/// hang waiting for input. The 77-column frame is only drawn when the measured
/// terminal width allows it (see [`terminal_columns`]); a narrower terminal
/// gets the plain list and a one-line notice.
fn run_console(
    args: &[String],
    lang: Lang,
    stdout_tty: bool,
    columns: Option<usize>,
) -> (u8, String, String) {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    run_console_with(args, lang, stdout_tty, columns, &mut reader, &mut writer)
}

/// [`run_console`] with the streams supplied by the caller. This is the same
/// production path (argument parsing, control-socket probe, width decision,
/// `drive_console`); tests hand it a byte reader and a buffer so the painted
/// screens can be asserted without a terminal.
fn run_console_with<R, W>(
    args: &[String],
    lang: Lang,
    stdout_tty: bool,
    columns: Option<usize>,
    reader: &mut R,
    writer: &mut W,
) -> (u8, String, String)
where
    R: BufRead,
    W: Write,
{
    let mut options = ConsoleOptions {
        socket: PathBuf::from(DEFAULT_CONTROL_SOCKET),
        config: PathBuf::from(DEFAULT_CONFIG_PATH),
        service: None,
        narrow: false,
        json: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                options.json = true;
                i += 1;
            }
            "--narrow" => {
                options.narrow = true;
                i += 1;
            }
            "--socket" | "--config" | "--service" => {
                let flag = args[i].clone();
                let value = match take_flag_value(args, i, &flag) {
                    Ok(value) => value,
                    Err(message) => return (2, String::new(), message),
                };
                match flag.as_str() {
                    "--socket" => options.socket = PathBuf::from(&value),
                    "--config" => options.config = PathBuf::from(&value),
                    _ => options.service = Some(value),
                }
                i += 2;
            }
            other => {
                return (
                    2,
                    String::new(),
                    format!(
                        "error: unexpected argument `{}`; run `boreas help`",
                        sanitize_arg(other)
                    ),
                );
            }
        }
    }

    let (live, snapshot, error) = probe_status(&options.socket);

    if options.json || !stdout_tty {
        let body = console_json(
            live,
            &snapshot,
            error.as_deref(),
            &options.socket,
            options.service.as_deref(),
            lang,
        );
        return (0, body, String::new());
    }

    // The measured width decides the layout; an explicit `--narrow` always
    // wins, and an unmeasured width keeps the frame. Only the width-forced
    // degradation is announced, so an explicit `--narrow` stays silent.
    let narrowed_by_width = !options.narrow && !fits_boxed(columns);

    let mut state = ConsoleState::new(lang, live);
    state.node_name = sanitize_line(&snapshot.node_name);
    state.narrow = options.narrow || narrowed_by_width;
    state.no_color = no_color_set();
    state.service_name = sanitize_line(&preview_unit(&options));

    if narrowed_by_width && writeln!(writer, "{}", text(lang, Msg::NarrowNotice)).is_err() {
        return (2, String::new(), "error: console write failed".into());
    }

    let mut io = ConsoleIo {
        socket: options.socket,
        config: options.config,
        service: options.service,
    };

    let outcome = drive_console(&mut state, reader, &mut *writer, |effect, effect_lang| {
        io.perform(effect, effect_lang)
    });
    // Leave the shell prompt on a fresh line; no terminal mode was changed.
    let _ = writeln!(writer);

    match outcome {
        Ok(()) => (0, String::new(), String::new()),
        Err(message) => (2, String::new(), format!("error: {message}")),
    }
}

/// Best-effort unit name for the confirmation screen. An explicit `--service`
/// wins; otherwise the name is derived from the config role. Nothing is
/// guessed: an unreadable config yields an empty name and the screen says so.
fn preview_unit(options: &ConsoleOptions) -> String {
    if let Some(name) = &options.service {
        return name.clone();
    }
    derive_unit(&options.config).unwrap_or_default()
}

fn derive_unit(config: &Path) -> Result<String, String> {
    let parsed = Config::read_file(config, RuntimeCapabilities::NO_RUNTIME).map_err(|error| {
        format!(
            "cannot read {} to derive the unit: {error}",
            config.display()
        )
    })?;
    Ok(match parsed.identity.role {
        NodeRole::Core => "boreas-core".to_string(),
        NodeRole::Edge => "boreas-edge".to_string(),
        NodeRole::EnrollmentService => String::new(),
    })
}

/// Query the control socket once. A failure is not downgraded to "no daemon":
/// the reason is returned so the screen can print it.
fn probe_status(socket: &Path) -> (bool, StatusSnapshot, Option<String>) {
    match daemon::query_control_socket(socket) {
        Ok((snapshot, _raw)) => (true, snapshot, None),
        Err(error) => (
            false,
            StatusSnapshot::offline(env!("CARGO_PKG_VERSION")),
            Some(error),
        ),
    }
}

/// Minimal JSON string escaping for console fields (this crate has no serde
/// dependency and deliberately has not added one).
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Non-TTY snapshot. `source` is the honest live/offline token; `error` carries
/// the query failure so a caller can tell "daemon absent" from "permission
/// denied" instead of guessing.
fn console_json(
    live: bool,
    snapshot: &StatusSnapshot,
    error: Option<&str>,
    socket: &Path,
    service: Option<&str>,
    lang: Lang,
) -> String {
    let daemon = match snapshot.daemon {
        DaemonState::Connected => "connected",
        DaemonState::NotConnected => "not_connected",
    };
    let error_field = match error {
        Some(value) => format!("\"{}\"", esc(value)),
        None => "null".to_string(),
    };
    let service_field = match service {
        Some(value) => format!("\"{}\"", esc(value)),
        None => "null".to_string(),
    };
    format!(
        concat!(
            "{{\"command\":\"console\",\"lang\":\"{}\",\"version\":\"{}\",",
            "\"source\":\"{}\",\"daemon\":\"{}\",\"node_name\":\"{}\",",
            "\"inbound_on\":{},\"inbound_connections\":{},\"outbound_upstreams\":{},",
            "\"security_mode\":\"{}\",\"socket\":\"{}\",\"service\":{},\"error\":{}}}"
        ),
        lang.code(),
        esc(&snapshot.version),
        if live { "live" } else { "offline" },
        daemon,
        esc(&sanitize_line(&snapshot.node_name)),
        snapshot.inbound_on,
        snapshot.inbound_connections,
        snapshot.outbound_upstreams,
        snapshot.security_mode.as_str(),
        esc(&socket.display().to_string()),
        service_field,
        error_field,
    )
}

/// Result of one driver-performed effect.
struct ConsoleOutcome {
    rows: Vec<String>,
    live: Option<bool>,
    node: Option<String>,
    endpoints: Option<(String, Option<String>)>,
}

impl ConsoleOutcome {
    fn rows(rows: Vec<String>) -> ConsoleOutcome {
        ConsoleOutcome {
            rows,
            live: None,
            node: None,
            endpoints: None,
        }
    }

    fn none() -> ConsoleOutcome {
        ConsoleOutcome {
            rows: Vec::new(),
            live: None,
            node: None,
            endpoints: None,
        }
    }
}

/// Performs the effects the pure reducer asked for.
struct ConsoleIo {
    socket: PathBuf,
    config: PathBuf,
    service: Option<String>,
}

impl ConsoleIo {
    fn perform(&mut self, effect: ConsoleEffect, lang: Lang) -> ConsoleOutcome {
        match effect {
            ConsoleEffect::RefreshStatus => {
                let (live, _snapshot, _error) = probe_status(&self.socket);
                ConsoleOutcome {
                    rows: Vec::new(),
                    live: Some(live),
                    node: None,
                    endpoints: None,
                }
            }
            ConsoleEffect::Telemetry => self.telemetry(lang),
            ConsoleEffect::ServiceStatus => self.service("status"),
            ConsoleEffect::ServiceStart => self.service("start"),
            ConsoleEffect::ServiceStop => self.service("stop"),
            ConsoleEffect::CheckConfig => self.config_check(),
            ConsoleEffect::CheckUpdate(channel) => {
                ConsoleOutcome::rows(update::check(channel, lang).1)
            }
            ConsoleEffect::ConfigWizard => self.config_wizard_start(lang),
            ConsoleEffect::ConfigWizardInput(values) => self.config_wizard_preview(values, lang),
            ConsoleEffect::ConfigWizardSave(values) => self.config_wizard_save(values, lang),
            ConsoleEffect::None | ConsoleEffect::Quit => ConsoleOutcome::none(),
        }
    }

    fn telemetry(&self, lang: Lang) -> ConsoleOutcome {
        let (live, snapshot, error) = probe_status(&self.socket);
        let name = if snapshot.node_name.is_empty() {
            text(lang, Msg::UnknownNode).to_string()
        } else {
            sanitize_line(&snapshot.node_name)
        };
        let mut rows = Vec::with_capacity(DETAIL_ROWS);
        rows.push(format!(
            "{}: {}",
            text(lang, Msg::SrcLabel),
            if live {
                text(lang, Msg::SrcLive)
            } else {
                text(lang, Msg::SrcOffline)
            }
        ));
        rows.push(format!("{}: {name}", text(lang, Msg::NodeLabel)));
        rows.push(format!(
            "{}: {} / {} {}",
            text(lang, Msg::InboundLabel),
            if snapshot.inbound_on {
                text(lang, Msg::On)
            } else {
                text(lang, Msg::Off)
            },
            snapshot.inbound_connections,
            text(lang, Msg::ConnectionsUnit)
        ));
        rows.push(format!(
            "{}: {} {}",
            text(lang, Msg::OutboundLabel),
            snapshot.outbound_upstreams,
            text(lang, Msg::UpstreamsUnit)
        ));
        rows.push(format!(
            "{}: {}",
            text(lang, Msg::ModeLabel),
            snapshot.security_mode.as_str()
        ));
        rows.push(
            text(
                lang,
                match snapshot.daemon {
                    DaemonState::Connected => Msg::DaemonConnected,
                    DaemonState::NotConnected => Msg::DaemonNotConnected,
                },
            )
            .to_string(),
        );
        if let Some(error) = error {
            rows.push(sanitize_line(&error));
        }
        rows.truncate(DETAIL_ROWS);
        ConsoleOutcome {
            rows,
            live: Some(live),
            node: Some(snapshot.node_name),
            endpoints: None,
        }
    }

    fn config_wizard_start(&self, lang: Lang) -> ConsoleOutcome {
        match Config::read_file(&self.config, RuntimeCapabilities::NO_RUNTIME) {
            Ok(parsed) => {
                let mut rows = match lang {
                    Lang::ZhCn => {
                        vec!["已读取并验证当前配置。仅修改 uplink.primary / backup。".into()]
                    }
                    Lang::ZhTw => {
                        vec!["已讀取並驗證目前設定。僅修改 uplink.primary / backup。".into()]
                    }
                    Lang::En => vec![
                        "Current config read and validated. Only uplink.primary/backup can change."
                            .into(),
                    ],
                };
                rows.push(format!(
                    "primary: {}",
                    sanitize_line(&parsed.uplinks.primary)
                ));
                rows.push(format!(
                    "backup: {}",
                    sanitize_line(parsed.uplinks.backup.as_deref().unwrap_or("(none)"))
                ));
                ConsoleOutcome {
                    rows,
                    endpoints: Some((parsed.uplinks.primary, parsed.uplinks.backup)),
                    live: None,
                    node: None,
                }
            }
            Err(error) => ConsoleOutcome::rows(vec![format!(
                "config rejected: {}",
                sanitize_line(&error.to_string())
            )]),
        }
    }

    fn config_wizard_preview(&self, values: String, _lang: Lang) -> ConsoleOutcome {
        let Some((primary, backup)) = values.split_once('\n') else {
            return ConsoleOutcome::rows(vec!["invalid candidate".into()]);
        };
        if primary.len() > 253
            || backup.len() > 253
            || primary.chars().any(char::is_control)
            || backup.chars().any(char::is_control)
        {
            return ConsoleOutcome::rows(vec!["endpoint input rejected".into()]);
        }
        let mut config = match Config::read_file(&self.config, RuntimeCapabilities::NO_RUNTIME) {
            Ok(config) => config,
            Err(error) => {
                return ConsoleOutcome::rows(vec![format!(
                    "config rejected: {}",
                    sanitize_line(&error.to_string())
                )]);
            }
        };
        config.uplinks.primary = primary.to_string();
        config.uplinks.backup = if backup.is_empty() {
            None
        } else {
            Some(backup.to_string())
        };
        if let Err(error) = config.validate(RuntimeCapabilities::NO_RUNTIME) {
            return ConsoleOutcome::rows(vec![format!(
                "candidate rejected: {}",
                sanitize_line(&error.to_string())
            )]);
        }
        let quote = |value: &str| toml::Value::String(value.to_string()).to_string();
        let footer = match _lang {
            Lang::ZhCn => "# 仅预览：未保存、应用或重载。",
            Lang::ZhTw => "# 僅預覽：未保存、套用或重新載入。",
            Lang::En => "# Preview only: not saved, applied, or reloaded.",
        };
        let fragment = format!(
            "[uplink]\nprimary = {}\n{}paths = {}\nprobe_paths = {}\n\n{}",
            quote(primary),
            if backup.is_empty() {
                String::new()
            } else {
                format!("backup = {}\n", quote(backup))
            },
            config.uplinks.paths,
            config.uplinks.probe_paths,
            footer
        );
        // Verify the emitted fragment is itself valid TOML, including hostile
        // quote/backslash endpoint characters. Keep paths and other config out.
        if let Err(error) = fragment.parse::<toml::Table>() {
            return ConsoleOutcome::rows(vec![format!(
                "candidate serialization failed: {}",
                sanitize_line(&error.to_string())
            )]);
        }
        ConsoleOutcome::rows(fragment.split('\n').map(str::to_string).collect::<Vec<_>>())
    }

    fn config_wizard_save(&self, values: String, _lang: Lang) -> ConsoleOutcome {
        let Some((primary, backup)) = values.split_once('\n') else {
            return ConsoleOutcome::rows(vec!["invalid candidate".into()]);
        };
        if primary.len() > 253
            || backup.len() > 253
            || primary.chars().any(char::is_control)
            || backup.chars().any(char::is_control)
        {
            return ConsoleOutcome::rows(vec!["endpoint input rejected".into()]);
        }
        let current = match Config::read_file(&self.config, RuntimeCapabilities::NO_RUNTIME) {
            Ok(config) => config,
            Err(error) => {
                return ConsoleOutcome::rows(vec![format!(
                    "config rejected: {}",
                    sanitize_line(&error.to_string())
                )]);
            }
        };
        let mut candidate = current;
        candidate.uplinks.primary = primary.to_string();
        candidate.uplinks.backup = if backup.is_empty() {
            None
        } else {
            Some(backup.to_string())
        };
        if let Err(error) = candidate.validate(RuntimeCapabilities::NO_RUNTIME) {
            return ConsoleOutcome::rows(vec![format!(
                "candidate rejected: {}",
                sanitize_line(&error.to_string())
            )]);
        }
        match candidate.save_endpoint_candidate(
            primary,
            if backup.is_empty() {
                None
            } else {
                Some(backup)
            },
        ) {
            Ok(name) => ConsoleOutcome::rows(vec![match _lang {
                Lang::ZhCn => format!("候选已保存为 {}；未应用或重载。", sanitize_line(&name)),
                Lang::ZhTw => format!("候選已保存為 {}；未套用或重新載入。", sanitize_line(&name)),
                Lang::En => format!(
                    "Candidate saved as {}; not applied or reloaded.",
                    sanitize_line(&name)
                ),
            }]),
            Err(error) => ConsoleOutcome::rows(vec![match _lang {
                Lang::ZhCn => format!("候选未保存：{}", sanitize_line(&error.to_string())),
                Lang::ZhTw => format!("候選未保存：{}", sanitize_line(&error.to_string())),
                Lang::En => format!("Candidate not saved: {}", sanitize_line(&error.to_string())),
            }]),
        }
    }

    /// Read-only static validation. Prints identifiers and policy switches but
    /// never key references, trust-anchor paths or state paths (§10.4).
    fn config_check(&self) -> ConsoleOutcome {
        let file = sanitize_line(&self.config.display().to_string());
        match Config::read_file(&self.config, RuntimeCapabilities::NO_RUNTIME) {
            Ok(parsed) => {
                let mut rows = vec![
                    format!("file: {file}"),
                    "config-check: valid".to_string(),
                    format!(
                        "schema: v{} ({})",
                        parsed.schema.as_u32(),
                        parsed.schema.label()
                    ),
                    format!(
                        "role: {} / node_id: {} / home_core: {} / vip_octet: {}",
                        parsed.identity.role.as_str(),
                        parsed.identity.node_id,
                        parsed.identity.home_core_id,
                        parsed.identity.vip_octet
                    ),
                    format!(
                        "mode: {} / suite: {}",
                        parsed.security.mode.as_str(),
                        parsed.security.suite.as_str()
                    ),
                    format!(
                        "uplink paths: {} / probe: {}",
                        parsed.uplinks.paths, parsed.uplinks.probe_paths
                    ),
                    "paths: [REDACTED] / state_dir: [REDACTED]".to_string(),
                ];
                rows.truncate(DETAIL_ROWS);
                ConsoleOutcome::rows(rows)
            }
            Err(error) => {
                let mut rows = vec![
                    format!("file: {file}"),
                    "config-check: rejected".to_string(),
                ];
                for line in error.to_string().lines().take(DETAIL_ROWS - 2) {
                    rows.push(sanitize_line(line));
                }
                ConsoleOutcome::rows(rows)
            }
        }
    }

    fn service(&self, verb: &str) -> ConsoleOutcome {
        let unit = match self.unit() {
            Ok(unit) => unit,
            Err(error) => return ConsoleOutcome::rows(vec![sanitize_line(&error)]),
        };
        if unit.is_empty() {
            return ConsoleOutcome::rows(vec![
                "no service unit: pass --service <UNIT> (boreas-core or boreas-edge)".to_string(),
            ]);
        }
        match service_invoke(&unit, verb) {
            Ok(rows) => ConsoleOutcome::rows(rows),
            Err(error) => ConsoleOutcome::rows(vec![sanitize_line(&error)]),
        }
    }

    /// Lazy: a missing config blocks only the service actions, never the
    /// status screen.
    fn unit(&self) -> Result<String, String> {
        match &self.service {
            Some(name) => Ok(name.clone()),
            None => derive_unit(&self.config),
        }
    }
}

/// True when an OpenWrt/procd init script owns the service and systemd is not
/// running. Checked by path so no shell is involved and no unit guess is made.
#[cfg(unix)]
fn manages_with_procd() -> bool {
    Path::new("/etc/init.d/boreas").is_file() && !Path::new("/run/systemd/system").is_dir()
}

/// Run one service verb with an argument vector. There is no `sh -c` anywhere:
/// the program and every argument are separate, and stdin is null so a
/// privilege prompt cannot block the console. `--no-ask-password` makes a
/// missing authorization fail instead of prompting.
#[cfg(unix)]
fn service_invoke(unit: &str, verb: &str) -> Result<Vec<String>, String> {
    use std::process::{Command, Stdio};

    let (program, arguments): (&str, Vec<&str>) = if manages_with_procd() {
        ("/etc/init.d/boreas", vec![verb])
    } else {
        let action = if verb == "status" { "is-active" } else { verb };
        (
            "systemctl",
            vec!["--no-pager", "--no-ask-password", action, unit],
        )
    };

    let output = Command::new(program)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;

    let mut rows: Vec<String> = Vec::with_capacity(DETAIL_ROWS);
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let cleaned = sanitize_line(line).trim().to_string();
        if !cleaned.is_empty() {
            rows.push(cleaned);
        }
        if rows.len() >= DETAIL_ROWS {
            break;
        }
    }
    if !output.status.success() {
        for line in String::from_utf8_lossy(&output.stderr).lines() {
            let cleaned = sanitize_line(line).trim().to_string();
            if !cleaned.is_empty() {
                rows.push(cleaned);
            }
            if rows.len() >= DETAIL_ROWS {
                break;
            }
        }
        // Keep one row for the exit code so a failure is never silently
        // truncated away by the bounded screen height.
        rows.truncate(DETAIL_ROWS - 1);
        rows.push(format!("exit: {}", output.status.code().unwrap_or(-1)));
    }
    if rows.is_empty() {
        rows.push("ok".to_string());
    }
    rows.truncate(DETAIL_ROWS);
    Ok(rows)
}

#[cfg(not(unix))]
fn service_invoke(_unit: &str, _verb: &str) -> Result<Vec<String>, String> {
    Err(
        "service control is implemented for Linux targets only (systemd or OpenWrt procd)"
            .to_string(),
    )
}

/// Drive the line-mode console: paint, read one line, reduce, perform.
///
/// Generic over the reader/writer and over an effect handler so the whole loop
/// is testable with a byte cursor and a fake performer — no terminal, no
/// socket, no child process.
fn drive_console<R, W, F>(
    state: &mut ConsoleState,
    reader: &mut R,
    out: &mut W,
    mut perform: F,
) -> Result<(), String>
where
    R: BufRead,
    W: Write,
    F: FnMut(ConsoleEffect, Lang) -> ConsoleOutcome,
{
    loop {
        let screen = state
            .screen(env!("CARGO_PKG_VERSION"))
            .map_err(|error| format!("console render failed: {error}"))?;
        writeln!(out, "{screen}").map_err(|_| "console write failed".to_string())?;
        write!(out, "{}", text(state.lang, Msg::PromptLabel))
            .map_err(|_| "console write failed".to_string())?;
        out.flush()
            .map_err(|_| "console flush failed".to_string())?;

        let mut line = String::new();
        let read = Read::by_ref(reader)
            .take(1026)
            .read_line(&mut line)
            .map_err(|_| "console read failed".to_string())?;
        if read > 1024 {
            writeln!(out, "{}", text(state.lang, Msg::NoticeUnknownCommand))
                .map_err(|_| "console write failed".to_string())?;
            return Ok(());
        }
        if read == 0 {
            // EOF is a clean exit, not an error: a closed pipe must not hang.
            return Ok(());
        }

        let step = state.apply(line.trim_end_matches(['\r', '\n']));
        if matches!(step, ConsoleEffect::Quit) {
            return Ok(());
        }
        if matches!(step, ConsoleEffect::None) {
            continue;
        }

        let is_refresh = matches!(step, ConsoleEffect::RefreshStatus);
        let is_update = matches!(step, ConsoleEffect::CheckUpdate(_));
        if is_update {
            writeln!(
                out,
                "{}",
                update::localized(
                    state.lang,
                    "Checking release metadata (up to 5 seconds)...",
                    "正在检查发布元数据（最长 5 秒）……",
                    "正在檢查發布中繼資料（最長 5 秒）……",
                )
            )
            .and_then(|()| out.flush())
            .map_err(|_| "console write failed".to_string())?;
        }
        let is_wizard_start = matches!(step, ConsoleEffect::ConfigWizard);
        let is_wizard_preview = matches!(step, ConsoleEffect::ConfigWizardInput(_));
        let is_wizard_save = matches!(step, ConsoleEffect::ConfigWizardSave(_));
        let outcome = perform(step, state.lang);
        if is_update {
            state.notice_rows = outcome.rows;
            continue;
        }
        if is_wizard_start {
            // Retain loaded endpoints for the reducer's next field transitions.
            if let Some((primary, backup)) = outcome.endpoints {
                state.config_primary = Some(primary);
                state.config_backup = Some(backup);
            }
            state.notice_rows = outcome.rows;
            continue;
        }
        if let Some(live) = outcome.live {
            state.live = live;
        }
        if let Some(node) = outcome.node {
            state.node_name = sanitize_line(&node);
        }
        if let Some((primary, backup)) = outcome.endpoints {
            state.config_primary = Some(primary);
            state.config_backup = Some(backup);
        }
        if is_refresh {
            continue;
        }
        if is_wizard_preview {
            // A boxed detail row is only 73 columns wide. Do not render a
            // TOML candidate through that truncating path: emit exact TOML
            // lines without terminal rendering. The outcome's first row marks
            // success; validation errors are plain notice text instead.
            let valid_candidate = outcome.rows.first().is_some_and(|row| row == "[uplink]");
            if valid_candidate {
                writeln!(
                    out,
                    "# BEGIN endpoint-only TOML preview (not saved/applied)"
                )
                .map_err(|_| "console write failed".to_string())?;
                for row in &outcome.rows {
                    writeln!(out, "{row}").map_err(|_| "console write failed".to_string())?;
                }
            }
            if valid_candidate {
                state.config_step = ConfigWizardStep::SaveOffer;
                state.notice_rows = match state.lang {
                    Lang::ZhCn => {
                        vec!["输入 s 选择保存候选；确认页面说明写入范围。未选择则取消。".into()]
                    }
                    Lang::ZhTw => {
                        vec!["輸入 s 選擇保存候選；確認頁面說明寫入範圍。未選擇則取消。".into()]
                    }
                    Lang::En => vec![
                        "Type s to choose saving; the confirmation page explains the write scope."
                            .into(),
                    ],
                };
            } else {
                state.config_primary = None;
                state.config_backup = None;
                state.config_step = ConfigWizardStep::Menu;
                state.notice_rows = outcome.rows;
            }
            state.view = ConsoleView::ConfigWizard;
            continue;
        }
        if is_wizard_save {
            state.config_primary = None;
            state.config_backup = None;
            state.config_step = ConfigWizardStep::Menu;
            state.notice_rows = outcome.rows;
            state.view = ConsoleView::Notice;
            continue;
        }
        state.notice_rows = outcome.rows;
        state.view = ConsoleView::Notice;
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
            "error: revoke id must be a decimal integer; got `{}`",
            sanitize_arg(id)
        ));
    }
    Err(format!(
        "error: unknown confirm action `{}`; expected hop-only, revoke:<id> or uninstall",
        sanitize_arg(raw)
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

fn run_config_save_candidate(args: &[String]) -> (u8, String, String) {
    let mut config_path = None;
    let mut primary = None;
    let mut backup = None;
    let mut confirm = None;
    let mut i = 0;
    while i < args.len() {
        let slot = match args[i].as_str() {
            "--config" => &mut config_path,
            "--primary" => &mut primary,
            "--backup" => &mut backup,
            "--confirm" => &mut confirm,
            _ => {
                return (
                    2,
                    String::new(),
                    "error: invalid config-save-candidate arguments".into(),
                );
            }
        };
        if slot.is_some() || i + 1 >= args.len() {
            return (
                2,
                String::new(),
                "error: duplicate or missing argument value".into(),
            );
        }
        *slot = Some(args[i + 1].clone());
        i += 2;
    }
    let (Some(path), Some(primary), Some(confirm)) = (config_path, primary, confirm) else {
        return (
            2,
            String::new(),
            "error: required --config, --primary, and --confirm SAVE".into(),
        );
    };
    if confirm != "SAVE" {
        return (
            2,
            String::new(),
            "error: confirmation must be exactly SAVE; nothing was saved".into(),
        );
    }
    let config = match Config::read_file(Path::new(&path), RuntimeCapabilities::NO_RUNTIME) {
        Ok(config) => config,
        Err(err) => {
            return (
                2,
                String::new(),
                format!("error: configuration rejected: {err}"),
            );
        }
    };
    match config.save_endpoint_candidate(&primary, backup.as_deref()) {
        Ok(name) => (
            0,
            format!("{{\"saved\":true,\"applied\":false,\"candidate\":\"{name}\"}}"),
            String::new(),
        ),
        Err(err) => (
            2,
            String::new(),
            format!("error: candidate not saved: {err}"),
        ),
    }
}

fn help_text() -> String {
    let mut text = "boreas — Phase 0 policy/config/console foundation\n\n\
     USAGE:\n\
     \x20 boreas [doctor|self-check|status [--json]|menu [--json] [--narrow]|console [--json] [--socket <p>] [--config <f>] [--service <u>]|confirm <action> <typed...>|config-check <path>|config-migrate <path>|config-save-candidate ...|node serve|node connect|help]\n\
     \x20 boreas-easy   (line-mode console: menu, service status/start/stop, updates)\n\
     \x20 boreas --version          local CLI build identity\n\
     \x20 boreas update-check [--channel stable|pre]  advisory discovery (default: stable)\n\
     \x20 boreas update-check --help  includes signed metadata discovery (Linux/OpenSSL)\n\
     \x20 boreas update --help     operator-only verified offline update (Linux/systemd)\n\n\
     OPTIONS:\n\
     \x20 --lang <zh-CN|zh-TW|en>   console language (else BOREAS_LANG/LC_ALL/LANG)\n\
     \x20 boreas status --json      JSON snapshot (also the default when not a TTY)\n\
     \x20 boreas menu [--narrow]    offline 9-entry screen (JSON when not a TTY)\n\
     \x20                          a terminal under 77 columns gets the plain list anyway\n\
     \x20 boreas console           line-mode console on a TTY; one JSON object otherwise\n\
     \x20   --socket <PATH>        control socket (default /run/boreas/control.sock)\n\
     \x20   --config <FILE>        config to validate (default /etc/boreas/config.toml)\n\
     \x20   --service <UNIT>       override the derived unit (boreas-core/-edge)\n\
     \x20                          start/stop require typing START / STOP exactly\n\
     \x20 boreas confirm hop-only|revoke:<id>|uninstall <phrase>\n\
     \x20                          records the phrase only; never applies it\n\
     \x20 boreas node serve <config> <listen> <material-dir>\n\
     \x20 boreas node connect <config> <host:port> <tls-name> <material-dir>\n\
     \x20                          hop process; TLS backend is feature-gated\n\
     \x20 boreas pki init-ca|issue-node|sign-status|verify-bundle ...\n\
     \x20                          offline ML-DSA-65 PKI management (openssl-inner-tls)\n\
     \x20 boreas daemon serve|connect --config <path> --material-dir <dir> ...\n\
     \x20                          real pq768 E2E + Linux TUN daemon (openssl-inner-tls)\n\
     \x20 boreas ctl status [--socket <path>] [--config <path>]\n\n\
     config-check parses one TOML file (`version = 1` legacy or `version = 2`),\n\
     validates static policy and prints redacted JSON. config-migrate prints the\n\
     canonical version = 2 document for a legacy file and never rewrites it.\n\
     Neither starts a daemon, opens sockets, loads key or trust-anchor contents,\n\
     or establishes TLS.\n\n\
     No production daemon, TUN data plane, or control socket is implemented.\n"
        .to_string();
    #[cfg(not(feature = "openssl-inner-tls"))]
    {
        text.push_str(
            "The default binary has no TLS backend; `node` exits without opening a socket.",
        );
    }
    #[cfg(feature = "openssl-inner-tls")]
    {
        text.push_str(
            "This openssl-inner-tls binary can run one hop via `node serve`/`node connect`. That is not a production daemon.",
        );
    }
    text.push_str("\n\n  Linux/OpenSSL, one-shot verified Core adjacency (control only):\n  ");
    text.push_str(node::MESH_PROBE_SYNTAX);
    text.push_str("\n\n  Linux/OpenSSL, dedicated signed Core source/relay/destination:\n  ");
    text.push_str(node::MESH_RUNTIME_SYNTAX);
    text
}

fn doctor_json() -> String {
    #[cfg(feature = "openssl-inner-tls")]
    {
        format!(
            "{{\"status\":\"pre_release_pq768_e2e\",\"phase\":\"Phase 0-5 partial (pre.1)\",\"scope\":\"{IMPLEMENTATION_SCOPE}\",\"daemon\":true,\"tls_backend\":true,\"networking\":true,\"control_socket\":true,\"config_check\":true,\"config_migrate\":true,\"status_screen\":true,\"console_menu\":true,\"runtime_capabilities\":\"openssl_pq768_e2e_point_to_point\",\"phase0_complete\":false}}"
        )
    }
    #[cfg(not(feature = "openssl-inner-tls"))]
    {
        format!(
            "{{\"status\":\"foundation_only\",\"phase\":\"Phase 0\",\"scope\":\"{IMPLEMENTATION_SCOPE}\",\"daemon\":false,\"tls_backend\":false,\"networking\":false,\"control_socket\":false,\"config_check\":true,\"config_migrate\":true,\"status_screen\":true,\"console_menu\":true,\"runtime_capabilities\":\"not_integrated\",\"phase0_complete\":false}}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigWizardStep, ConsoleEffect, ConsoleIo, ConsoleOutcome, ConsoleState, drive_console,
        run_console, run_console_with,
    };
    use super::{
        Lang, dispatch, dispatch_with_columns, extract_lang_flag, is_easy_entrypoint, run,
        run_with_columns,
    };
    use crate::config::RuntimeCapabilities;
    use crate::render::{BOX_WIDTH, display_width};

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
        assert!(stdout.contains("\"phase0_complete\":false"));
        #[cfg(not(feature = "openssl-inner-tls"))]
        {
            assert!(stdout.contains("\"daemon\":false"));
            assert!(stdout.contains("\"tls_backend\":false"));
            assert!(stdout.contains("\"control_socket\":false"));
            assert!(stdout.contains("\"runtime_capabilities\":\"not_integrated\""));
        }
        #[cfg(feature = "openssl-inner-tls")]
        {
            assert!(stdout.contains("\"daemon\":true"));
            assert!(stdout.contains("\"tls_backend\":true"));
            assert!(stdout.contains("\"control_socket\":true"));
        }
    }

    #[test]
    fn default_and_self_check_are_doctor() {
        assert_eq!(run(&[], Lang::En, false).0, 0);
        assert_eq!(run(&args(&["self-check"]), Lang::En, false).0, 0);
    }

    #[test]
    fn daemon_and_unknown_commands_fail_without_starting() {
        let (code, stdout, stderr) = run(&args(&["made-up"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no daemon was started"));

        #[cfg(not(feature = "openssl-inner-tls"))]
        {
            let (code, stdout, stderr) = run(&args(&["daemon"]), Lang::En, false);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(stderr.contains("no daemon was started"));
        }
        #[cfg(feature = "openssl-inner-tls")]
        {
            let (code, _, stderr) = run(&args(&["daemon", "bogus"]), Lang::En, false);
            assert_eq!(code, 2);
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
    fn config_candidate_confirmation_is_exact_and_never_prompts() {
        for confirm in ["save", "SAVE ", "SAVE\\n", "SAV"] {
            let result = super::run_config_save_candidate(&args(&[
                "--config",
                "/does/not/exist",
                "--primary",
                "hub.example:443",
                "--confirm",
                confirm,
            ]));
            assert_eq!(result.0, 2);
            assert!(result.2.contains("exactly SAVE"));
        }
        let missing = super::run_config_save_candidate(&args(&[
            "--config",
            "/does/not/exist",
            "--primary",
            "hub.example:443",
        ]));
        assert_eq!(missing.0, 2);
        assert!(missing.2.contains("required"));
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
        assert!(stdout.contains("config-save-candidate"));
        assert!(stdout.contains("node serve"));
        assert!(!stdout.contains("No daemon, TLS backend, or networking is implemented."));
        #[cfg(not(feature = "openssl-inner-tls"))]
        {
            assert!(stdout.contains("The default binary has no TLS backend"));
            let (code, _, stderr) = run(
                &args(&[
                    "node",
                    "serve",
                    "/boreas-tests/secret/config.toml",
                    "127.0.0.1:443",
                    "/boreas-tests/secret/material",
                ]),
                Lang::En,
                false,
            );
            assert_eq!(code, 2);
            assert!(stderr.contains("no TLS backend"));
            assert!(stderr.contains("no daemon was started"));
        }
        #[cfg(feature = "openssl-inner-tls")]
        {
            assert!(stdout.contains("This openssl-inner-tls binary can run one hop"));
        }
        let (code, _, stderr) = run(&args(&["node", "serve"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("node serve <config>"));
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
            // Explicit width: the assertion must not depend on the width of
            // whatever terminal happens to run the test.
            let (code, stdout, stderr) = run_with_columns(&args(&["status"]), lang, true, Some(80));
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
    fn easy_with_no_args_enters_the_console() {
        let easy = dispatch("/usr/bin/boreas-easy", &[], probe_en, false);
        let console = run(&args(&["console"]), Lang::En, false);
        assert_eq!(easy, console, "both must resolve to the console path");
        assert_eq!(easy.0, 0);
    }

    #[test]
    fn easy_console_options_do_not_require_an_explicit_subcommand() {
        let options = args(&[
            "--socket",
            "/nonexistent-boreas-console.sock",
            "--json",
            "--service",
            "boreas",
        ]);
        let easy = dispatch("boreas-easy", &options, probe_en, false);
        let mut explicit = args(&["console"]);
        explicit.extend(options);
        assert_eq!(easy, run(&explicit, Lang::En, false));
        assert_eq!(easy.0, 0);
        assert!(easy.1.contains("\"command\":\"console\""));
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
        let (code, stdout, stderr) = run_with_columns(&args(&["menu"]), Lang::En, true, Some(80));
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("BOREAS CONSOLE"));
        assert!(stdout.contains("e2e-required"));
        assert!(!stdout.as_bytes().contains(&0x1B));
        assert_eq!(stdout.split('\n').count(), 18);

        let (code, narrow, _) =
            run_with_columns(&args(&["menu", "--narrow"]), Lang::En, true, Some(80));
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

    /// The 77x18 frame is only produced when the measured width allows it.
    /// This drives the real `menu` entry point (`run_with_columns`) rather
    /// than the render model, so the width decision itself is under test.
    #[test]
    fn menu_frame_requires_a_measured_width_of_77_columns_in_three_languages() {
        for (lang, label, entry) in [
            (Lang::ZhCn, "[L] 简中", "实时链路遥测"),
            (Lang::ZhTw, "[L] 繁中", "即時鏈路遙測"),
            (Lang::En, "[L] EN", "Live Telemetry"),
        ] {
            let (code, stdout, stderr) = run_with_columns(&args(&["menu"]), lang, true, Some(80));
            assert_eq!(code, 0, "{stderr}");
            let lines: Vec<&str> = stdout.split('\n').collect();
            assert_eq!(lines.len(), 18, "{lang:?}: {stdout}");
            for line in &lines {
                assert_eq!(display_width(line), BOX_WIDTH, "{lang:?}: {line:?}");
                assert!(!line.as_bytes().contains(&0x1B), "{lang:?}");
            }
            assert!(stdout.contains(label), "{lang:?}: {stdout}");
            assert!(stdout.contains(entry), "{lang:?}: {stdout}");
        }

        // Exactly 77 columns is enough; one column less is not.
        let (_, at_boundary, _) = run_with_columns(&args(&["menu"]), Lang::En, true, Some(77));
        assert_eq!(at_boundary.split('\n').count(), 18);
        assert!(at_boundary.contains('┌'));

        for narrow_width in [76usize, 60, 40, 20] {
            let (code, stdout, stderr) =
                run_with_columns(&args(&["menu"]), Lang::En, true, Some(narrow_width));
            assert_eq!(code, 0, "{stderr}");
            assert!(!stdout.contains('┌'), "{narrow_width}: {stdout}");
            assert!(!stdout.contains('│'), "{narrow_width}: {stdout}");
            assert!(stdout.contains("[1] Live Telemetry"), "{narrow_width}");
            assert!(stdout.lines().count() < 18, "{narrow_width}");
            assert!(!stdout.as_bytes().contains(&0x1B));
        }
    }

    #[test]
    fn menu_json_reports_the_same_width_decision_as_the_screen() {
        let (code, wide, _) =
            run_with_columns(&args(&["menu", "--json"]), Lang::En, true, Some(80));
        assert_eq!(code, 0);
        assert!(wide.starts_with('{'));
        assert!(wide.contains("\"narrow\":false"), "{wide}");
        assert!(wide.contains("\"daemon\":false"));

        let (code, narrow, _) =
            run_with_columns(&args(&["menu", "--json"]), Lang::En, true, Some(40));
        assert_eq!(code, 0);
        assert!(narrow.contains("\"narrow\":true"), "{narrow}");
    }

    #[test]
    fn status_frame_requires_a_measured_width_of_77_columns() {
        let (code, wide, stderr) = run_with_columns(&args(&["status"]), Lang::En, true, Some(80));
        assert_eq!(code, 0, "{stderr}");
        assert!(wide.contains('┌'));
        assert!(wide.contains("daemon: not connected"));
        for line in wide.split('\n') {
            assert_eq!(display_width(line), BOX_WIDTH, "{line:?}");
        }

        for narrow_width in [76usize, 40] {
            let (code, narrow, stderr) =
                run_with_columns(&args(&["status"]), Lang::En, true, Some(narrow_width));
            assert_eq!(code, 0, "{stderr}");
            assert!(!narrow.contains('┌'), "{narrow_width}");
            assert!(narrow.contains("BOREAS CONSOLE"));
            assert!(narrow.contains("daemon: not connected"));
            for line in narrow.split('\n') {
                assert!(
                    display_width(line) <= narrow_width,
                    "{narrow_width}: {line:?}"
                );
            }
            assert!(!narrow.as_bytes().contains(&0x1B));
        }
    }

    #[test]
    fn confirm_accepts_exact_phrase_without_applying() {
        let (code, stdout, stderr) =
            run(&args(&["confirm", "hop-only", "HOP-ONLY"]), Lang::En, false);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "{\"accepted\":true,\"applied\":false,\"reason\":\"confirmation recorded; no daemon action exists\"}"
        );
        let (code, stdout, _) = run(
            &args(&["confirm", "revoke:42", "REVOKE", "42"]),
            Lang::En,
            false,
        );
        assert_eq!(code, 0);
        assert!(stdout.contains("\"applied\":false"));
        let (code, stdout, _) = run(
            &args(&["confirm", "uninstall", "UNINSTALL"]),
            Lang::En,
            true,
        );
        assert_eq!(code, 0);
        assert!(stdout.contains("\"accepted\":true"));
    }

    #[test]
    fn confirm_rejects_wrong_phrase_with_exit_2() {
        let (code, stdout, _) = run(&args(&["confirm", "hop-only", "hop-only"]), Lang::En, false);
        assert_eq!(code, 2);
        assert_eq!(stdout, "{\"accepted\":false,\"applied\":false}");
        let (code, stdout, _) = run(
            &args(&["confirm", "revoke:7", "REVOKE", "8"]),
            Lang::En,
            false,
        );
        assert_eq!(code, 2);
        assert!(stdout.contains("\"accepted\":false"));
        let (code, _, stderr) = run(&args(&["confirm"]), Lang::En, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("confirm requires"));
        let (code, _, stderr) = run(
            &args(&["confirm", "revoke:nope", "REVOKE nope"]),
            Lang::En,
            false,
        );
        assert_eq!(code, 2);
        assert!(stderr.contains("decimal"));
    }

    #[test]
    fn rejected_arguments_never_echo_control_characters() {
        // Rejecting a hostile argument must not paint it: the diagnostic that
        // names the argument is sanitized exactly like a screen field (§10.4).
        let hostile = "\u{1b}[31m";
        for argv in [
            args(&["status", hostile]),
            args(&["menu", hostile]),
            args(&["console", hostile]),
            args(&["confirm", hostile, "x"]),
            args(&["confirm", "revoke:", "REVOKE 1"]),
            args(&["confirm", "revoke:\u{1b}[31m", "REVOKE 1"]),
            args(&[hostile]),
        ] {
            let (code, stdout, stderr) = run(&argv, Lang::En, false);
            assert_eq!(code, 2, "{argv:?}");
            assert!(stderr.starts_with("error:"), "{argv:?}: {stderr:?}");
            assert!(
                !stderr.as_bytes().contains(&0x1B),
                "stderr echoed an escape for {argv:?}: {stderr:?}"
            );
            assert!(!stdout.as_bytes().contains(&0x1B), "{argv:?}");
        }

        // `--lang` is stripped before dispatch; its error path echoes the tag.
        let (code, stdout, stderr) = dispatch(
            "boreas",
            &args(&["--lang", "\u{1b}[31m", "status"]),
            probe_en,
            false,
        );
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(!stderr.as_bytes().contains(&0x1B), "{stderr:?}");
        assert!(stderr.contains("unsupported language"), "{stderr:?}");
    }

    #[test]
    fn easy_still_accepts_explicit_commands() {
        let (code, stdout, _) = dispatch("boreas-easy", &args(&["doctor"]), probe_en, false);
        assert_eq!(code, 0);
        assert!(stdout.contains("\"phase0_complete\":false"));
        let (code, _, _) = dispatch("boreas-easy", &args(&["bogus"]), probe_en, false);
        assert_eq!(code, 2);
    }

    // --- line-mode console ---

    /// Nanosecond component for unique temp-socket names.
    fn unique_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    }

    #[test]
    fn console_non_tty_is_json_and_does_not_read_any_stdin() {
        let (code, stdout, stderr) = run_console(&[], Lang::En, false, None);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.starts_with("{\"command\":\"console\""));
        assert!(!stdout.contains("PREVIEW"));
    }

    #[test]
    fn console_reports_offline_when_the_socket_is_absent() {
        let missing = std::env::temp_dir().join(format!(
            "boreas-console-absent-{}-{}.sock",
            std::process::id(),
            unique_suffix()
        ));
        let _ = std::fs::remove_file(&missing);
        let (code, stdout, stderr) = run_console(
            &args(&["--socket", missing.to_str().expect("utf8 temp path")]),
            Lang::En,
            false,
            None,
        );
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("\"command\":\"console\""));
        assert!(stdout.contains("\"source\":\"offline\""));
        assert!(stdout.contains("\"daemon\":\"not_connected\""));
        assert!(
            stdout.contains("\"error\":\""),
            "the query failure must be reported, not hidden: {stdout}"
        );
        // Never claim a live mesh.
        assert!(!stdout.contains("\"source\":\"live\""));
    }

    #[test]
    fn console_rejects_unknown_and_valueless_arguments() {
        let (code, stdout, stderr) = run_console(&args(&["--socket"]), Lang::En, false, None);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires a value"), "{stderr}");

        for flag in ["--config", "--service"] {
            let (code, _, stderr) = run_console(&args(&[flag]), Lang::En, false, None);
            assert_eq!(code, 2, "{flag}");
            assert!(stderr.contains("requires a value"), "{flag}");
        }

        let (code, stdout, stderr) = run_console(&args(&["--nope"]), Lang::En, false, None);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unexpected argument"), "{stderr}");
    }

    #[test]
    fn console_json_escapes_the_socket_path() {
        let weird = std::env::temp_dir().join("boreas-console-weird-\"q\".sock");
        let (code, stdout, _) = run_console(
            &args(&["--socket", weird.to_str().expect("utf8 temp path")]),
            Lang::En,
            false,
            None,
        );
        assert_eq!(code, 0);
        assert!(
            stdout.contains("\\\"q\\\""),
            "socket path must be JSON-escaped: {stdout}"
        );
    }

    /// Reader that fails the test if anything reads it: the JSON paths must
    /// never consume stdin, and `--json` on a TTY must never enter the loop.
    struct NeverRead;

    impl std::io::Read for NeverRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("stdin must not be read for JSON output");
        }
    }

    impl std::io::BufRead for NeverRead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            panic!("stdin must not be read for JSON output");
        }

        fn consume(&mut self, _amount: usize) {
            panic!("stdin must not be read for JSON output");
        }
    }

    /// Absent socket path under the temp dir: the console must report
    /// `offline` and still paint, instead of pretending a daemon answered.
    fn absent_socket_path(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "boreas-console-{tag}-{}-{}.sock",
            std::process::id(),
            unique_suffix()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Paint the console through the real entry point with a scripted reader.
    /// Returns `(exit code, stdout JSON half, painted screen bytes, stderr)`.
    fn run_scripted_console(
        argv: &[&str],
        lang: Lang,
        columns: Option<usize>,
        input: &[u8],
    ) -> (u8, String, String, String) {
        use std::io::BufReader;
        let mut reader = BufReader::new(input);
        let mut out = Vec::new();
        let (code, stdout, stderr) =
            run_console_with(&args(argv), lang, true, columns, &mut reader, &mut out);
        let painted = String::from_utf8(out).unwrap_or_else(|error| panic!("utf8: {error}"));
        (code, stdout, painted, stderr)
    }

    /// Painted screen bytes for a successful run.
    fn painted_screen(argv: &[&str], lang: Lang, columns: Option<usize>, input: &[u8]) -> String {
        let (code, stdout, painted, stderr) = run_scripted_console(argv, lang, columns, input);
        assert_eq!(code, 0, "{stderr}");
        assert!(
            stdout.is_empty(),
            "the TTY path paints instead of printing JSON"
        );
        painted
    }

    #[test]
    fn console_paints_the_77_by_18_frame_when_the_width_allows_it() {
        let socket = absent_socket_path("frame");
        let painted = painted_screen(
            &["--socket", socket.to_str().expect("utf8 temp path")],
            Lang::En,
            Some(80),
            b"q\n",
        );
        let screen: Vec<&str> = painted.lines().take(18).collect();
        assert_eq!(screen.len(), 18, "{painted}");
        for line in &screen {
            assert_eq!(display_width(line), BOX_WIDTH, "{line:?}");
        }
        assert!(painted.contains("BOREAS CONSOLE"));
        assert!(painted.contains("> [1] Live Telemetry"));
        assert!(
            !painted.as_bytes().contains(&0x1B),
            "no ANSI, so no DSR/CPR probe can be written"
        );
        assert!(
            !painted.contains("[6n"),
            "no Device Status Report is issued"
        );
        assert!(
            !painted.contains("narrow list"),
            "the frame needs no notice"
        );
    }

    #[test]
    fn console_announces_the_narrow_list_below_77_columns() {
        let painted = painted_screen(&[], Lang::ZhCn, Some(40), b"q\n");
        assert!(
            painted.starts_with("终端宽度不足 77 列"),
            "the degradation must say why: {painted}"
        );
        assert!(!painted.contains('┌'), "{painted}");
        assert!(!painted.contains('│'), "{painted}");
        assert!(painted.contains("[1] 实时链路遥测"), "{painted}");
        assert!(!painted.as_bytes().contains(&0x1B));

        // An explicit --narrow needs no notice: the operator asked for it.
        let explicit = painted_screen(&["--narrow"], Lang::ZhCn, Some(80), b"q\n");
        assert!(!explicit.contains("窄列表"), "{explicit}");
        assert!(!explicit.contains('┌'), "{explicit}");
    }

    #[test]
    fn console_keeps_the_frame_when_the_width_was_never_measured() {
        // No width and no terminal size: the fixed frame is kept instead of
        // silently replacing every screen with a list.
        let painted = painted_screen(&[], Lang::En, None, b"q\n");
        assert!(painted.contains('┌'), "{painted}");
        assert!(painted.contains("> [1] Live Telemetry"));
        assert!(
            painted
                .lines()
                .nth(17)
                .is_some_and(|line| line.ends_with('┘')),
            "the 18th line must be the bottom border: {painted}"
        );
    }

    #[test]
    fn console_cycles_through_three_languages_in_the_real_flow() {
        let painted = painted_screen(&[], Lang::ZhCn, Some(80), b"L\nL\nq\n");
        assert_eq!(painted.matches("BOREAS CONSOLE").count(), 3, "{painted}");
        assert!(painted.contains("[L] 简中"), "{painted}");
        assert!(painted.contains("[L] 繁中"), "{painted}");
        assert!(painted.contains("[L] EN"), "{painted}");
        assert!(painted.contains("实时链路遥测"));
        assert!(painted.contains("即時鏈路遙測"));
        assert!(painted.contains("Live Telemetry"));
        assert!(!painted.as_bytes().contains(&0x1B));
        for line in painted.lines().take(54) {
            if line.starts_with(['│', '┌', '├', '└']) {
                assert_eq!(display_width(line), BOX_WIDTH, "{line:?}");
            }
        }
    }

    #[test]
    fn console_json_paths_never_read_stdin_nor_paint() {
        let mut out = Vec::new();
        let (code, stdout, stderr) =
            run_console_with(&[], Lang::En, false, None, &mut NeverRead, &mut out);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.starts_with("{\"command\":\"console\""), "{stdout}");
        assert!(out.is_empty());

        // `--json` on a TTY takes the same path: JSON out, no screen, no read.
        let mut tty_out = Vec::new();
        let (code, stdout, stderr) = run_console_with(
            &args(&["--json"]),
            Lang::En,
            true,
            Some(80),
            &mut NeverRead,
            &mut tty_out,
        );
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.starts_with("{\"command\":\"console\""), "{stdout}");
        assert!(stdout.contains("\"lang\":\"en\""));
        assert!(tty_out.is_empty(), "JSON mode must not paint a screen");
    }

    #[test]
    fn easy_alias_routes_the_console_through_the_width_aware_path() {
        let easy =
            dispatch_with_columns("boreas-easy", &args(&["--json"]), probe_en, true, Some(80));
        assert_eq!(easy.0, 0);
        assert!(
            easy.1.starts_with("{\"command\":\"console\""),
            "{:?}",
            easy.1
        );
        // The alias must resolve to the same path as the explicit subcommand.
        assert_eq!(
            easy,
            run_with_columns(&args(&["console", "--json"]), Lang::En, true, Some(80))
        );
    }

    #[test]
    fn console_rejects_injected_wizard_input_without_echoing_it() {
        let path = write_fixture("wizard-inject", &config_source());
        let (code, stdout, painted, stderr) = run_scripted_console(
            &["--config", path.to_str().expect("utf8 fixture")],
            Lang::En,
            Some(80),
            b"8\n\n4\n1\nhost\x1b[31m.example:443\nq\n",
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.is_empty());
        assert!(painted.contains("Input rejected"), "{painted}");
        assert!(
            !painted.as_bytes().contains(&0x1B),
            "the escape must not be echoed: {painted:?}"
        );
        assert!(!painted.contains("31m"), "{painted}");
    }

    #[test]
    fn console_driver_runs_config_wizard_from_load_through_exact_preview() {
        use std::io::BufReader;
        let original = config_source();
        let path = write_fixture("wizard", &original);
        let mut io = ConsoleIo {
            socket: std::path::PathBuf::new(),
            config: path.clone(),
            service: None,
        };
        let mut state = ConsoleState::new(Lang::En, false);
        let mut reader = BufReader::new(
            &b"8\n\n4\n1\nnew-hub.example.net:443\nbackup.example.net:443\nPREVIEW\nq\n"[..],
        );
        let mut out = Vec::new();
        let result = drive_console(&mut state, &mut reader, &mut out, |effect, lang| {
            io.perform(effect, lang)
        });
        result.expect("driver");
        let output = String::from_utf8(out).expect("utf8");
        assert!(output.contains("[uplink]"));
        assert!(output.contains("primary = \"new-hub.example.net:443\""));
        assert!(output.contains("backup = \"backup.example.net:443\""));
        assert!(output.contains("paths = 4") && output.contains("probe_paths = 1"));
        assert!(output.contains("Preview validated"));
        assert!(output.contains("# BEGIN endpoint-only TOML preview"));
        assert!(output.contains("not saved/applied"));
        assert!(!output.contains("identity.key"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("config remains"),
            original
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(state.config_primary, None);
        assert_eq!(state.config_backup, None);
        assert_eq!(state.config_step, ConfigWizardStep::Menu);
    }

    #[test]
    fn console_driver_saves_only_after_valid_preview_and_exact_save() {
        use std::io::BufReader;
        let original = config_source();
        let path = write_fixture("wizard-save", &original);
        let mut state = ConsoleState::new(Lang::En, false);
        let mut reader = BufReader::new(
            &b"8\n\n4\n1\nnew-hub.example.net:443\nbackup.example.net:443\nPREVIEW\ns\nSAVE\nq\n"[..],
        );
        let mut output = Vec::new();
        let effects = std::cell::RefCell::new(Vec::new());
        drive_console(&mut state, &mut reader, &mut output, |effect, _lang| {
            let captured = effect.clone();
            effects.borrow_mut().push(effect);
            match captured {
                ConsoleEffect::ConfigWizard => ConsoleOutcome {
                    rows: vec![],
                    live: None,
                    node: None,
                    endpoints: Some(("old.example.net:443".into(), None)),
                },
                ConsoleEffect::ConfigWizardInput(_) => {
                    ConsoleOutcome::rows(vec!["[uplink]".into()])
                }
                ConsoleEffect::ConfigWizardSave(payload) => {
                    assert_eq!(payload, "new-hub.example.net:443\nbackup.example.net:443");
                    ConsoleOutcome::rows(vec!["candidate saved: mock.toml".into()])
                }
                _ => ConsoleOutcome::none(),
            }
        })
        .expect("driver");
        assert_eq!(
            effects
                .borrow()
                .iter()
                .filter(|effect| matches!(effect, ConsoleEffect::ConfigWizardSave(_)))
                .count(),
            1
        );
        assert!(
            effects
                .borrow()
                .iter()
                .any(|effect| matches!(effect, ConsoleEffect::ConfigWizardInput(_)))
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wizard_quote_long_endpoint_preview_is_valid_and_untruncated() {
        use std::io::BufReader;
        let path = write_fixture("wizard-escaped", &config_source());
        let endpoint = format!("{}\".example.net:443", "a".repeat(180));
        let input = format!("8\n\n4\n1\n{endpoint}\n\nPREVIEW\nq\n");
        let mut reader = BufReader::new(input.as_bytes());
        let mut output = Vec::new();
        let mut state = ConsoleState::new(Lang::En, false);
        let mut io = ConsoleIo {
            socket: std::path::PathBuf::new(),
            config: path.clone(),
            service: None,
        };
        drive_console(&mut state, &mut reader, &mut output, |effect, lang| {
            io.perform(effect, lang)
        })
        .expect("driver");
        let rendered = String::from_utf8(output).unwrap();
        let start = rendered.find("# BEGIN endpoint-only TOML preview").unwrap();
        let preview = &rendered[start..];
        let emitted = preview
            .lines()
            .skip(1)
            .take_while(|line| {
                !line.starts_with("# Preview only") && !line.starts_with("BOREAS CONSOLE")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let table: toml::Table = emitted.parse().expect("candidate fragment is valid TOML");
        assert_eq!(table["uplink"]["primary"].as_str(), Some(endpoint.as_str()));
        assert!(!rendered.contains("identity.key"));
        // TOML may choose a literal or escaped basic string; decoded bytes,
        // rather than one serializer spelling, define the preview contract.
        assert_eq!(table["uplink"].as_table().expect("uplink table").len(), 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wizard_preview_rejects_near_match_and_invalid_candidates() {
        use std::io::BufReader;
        let path = write_fixture("wizard-invalid", &config_source());
        for (phrase, endpoint, expected) in [
            (" preview", "valid.example.net:443", "Preview cancelled"),
            ("preview", "valid.example.net:443", "Preview cancelled"),
            ("PREVIEW", "not an endpoint", "candidate rejected"),
            ("PREVIEW", "\\\\bad.example.net:443", "candidate rejected"),
        ] {
            let input = format!("8\n\n4\n1\n{endpoint}\n\n{phrase}\nq\n");
            let mut reader = BufReader::new(input.as_bytes());
            let mut output = Vec::new();
            let mut state = ConsoleState::new(Lang::En, false);
            let mut io = ConsoleIo {
                socket: std::path::PathBuf::new(),
                config: path.clone(),
                service: None,
            };
            drive_console(&mut state, &mut reader, &mut output, |effect, lang| {
                io.perform(effect, lang)
            })
            .expect("driver");
            let rendered = String::from_utf8(output).unwrap();
            assert!(rendered.contains(expected), "{phrase:?}: {rendered}");
            if expected == "candidate rejected" {
                assert!(!rendered.contains("BEGIN endpoint-only TOML preview"));
            }
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn console_driver_paints_each_step_and_exits_on_q() {
        use std::io::BufReader;

        let mut state = ConsoleState::new(Lang::En, false);
        let mut reader = BufReader::new(&b"j\nq\n"[..]);
        let mut out: Vec<u8> = Vec::new();
        let result = drive_console(&mut state, &mut reader, &mut out, |effect, _lang| {
            assert_eq!(effect, ConsoleEffect::None, "navigation has no effect");
            ConsoleOutcome::none()
        });
        assert!(result.is_ok());

        let screen = String::from_utf8(out).expect("utf8");
        assert_eq!(screen.matches("BOREAS CONSOLE").count(), 2);
        assert!(screen.contains("> [2] Identity & DIR"));
        assert!(!screen.as_bytes().contains(&0x1B));
    }

    #[test]
    fn update_screen_checks_only_on_request_and_keeps_channel_results_separate() {
        use std::io::BufReader;
        use crate::update::Channel;

        let mut reader = BufReader::new(&b"7\n\nc\n2\nc\nb\nq\n"[..]);
        let mut state = ConsoleState::new(Lang::En, false);
        let mut effects = Vec::new();
        let mut out = Vec::new();
        drive_console(&mut state, &mut reader, &mut out, |effect, _lang| {
            let ConsoleEffect::CheckUpdate(channel) = effect else {
                panic!("unexpected effect: {effect:?}");
            };
            effects.push(channel);
            ConsoleOutcome::rows(vec![format!("fixture-{}", channel.key())])
        })
        .unwrap();
        assert_eq!(effects, [Channel::Stable, Channel::Pre]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Local build:"));
        assert!(out.contains("Auto-update blocked:"));
        assert_eq!(out.matches("fixture-stable").count(), 1);
        assert_eq!(out.matches("fixture-pre").count(), 1);
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn console_driver_bounds_overlong_input_and_exits() {
        use std::io::BufReader;
        let input = format!("{}\nq\n", "x".repeat(1100));
        let mut reader = BufReader::new(input.as_bytes());
        let mut output = Vec::new();
        let mut state = ConsoleState::new(Lang::En, false);
        drive_console(&mut state, &mut reader, &mut output, |_, _| {
            panic!("no effect expected")
        })
        .expect("bounded exit");
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Unknown command")
        );
    }

    #[test]
    fn console_driver_treats_eof_as_a_clean_exit() {
        use std::io::BufReader;

        let mut state = ConsoleState::new(Lang::En, false);
        let mut reader = BufReader::new(&b""[..]);
        let mut out: Vec<u8> = Vec::new();
        let result = drive_console(&mut state, &mut reader, &mut out, |_, _| {
            ConsoleOutcome::none()
        });
        assert!(result.is_ok(), "a closed pipe must not hang or fail");
    }

    #[test]
    fn console_driver_refuses_a_trailing_space_on_the_phrase() {
        use std::cell::RefCell;
        use std::io::BufReader;

        let performed = RefCell::new(Vec::new());
        let mut state = ConsoleState::new(Lang::En, false);
        state.service_name = "boreas-core".to_string();
        let mut reader = BufReader::new(&b"8\n\n2\nSTART \nq\n"[..]);
        let mut out: Vec<u8> = Vec::new();
        drive_console(&mut state, &mut reader, &mut out, |effect, _lang| {
            performed.borrow_mut().push(effect);
            ConsoleOutcome::rows(vec!["unexpected".to_string()])
        })
        .expect("driver");

        assert!(
            performed.borrow().is_empty(),
            "`START ` must not start the daemon: {:?}",
            performed.borrow()
        );
    }

    #[test]
    fn console_driver_starts_only_after_the_exact_phrase() {
        use std::cell::RefCell;
        use std::io::BufReader;

        let performed = RefCell::new(Vec::new());
        let mut state = ConsoleState::new(Lang::En, false);
        state.service_name = "boreas-core".to_string();
        let mut reader = BufReader::new(&b"8\n\n2\nSTART\nq\n"[..]);
        let mut out: Vec<u8> = Vec::new();
        drive_console(&mut state, &mut reader, &mut out, |effect, _lang| {
            performed.borrow_mut().push(effect);
            ConsoleOutcome::rows(vec!["active".to_string()])
        })
        .expect("driver");

        assert_eq!(*performed.borrow(), vec![ConsoleEffect::ServiceStart]);
        assert!(String::from_utf8(out).expect("utf8").contains("active"));
    }

    #[test]
    fn console_driver_never_runs_a_dangerous_entry() {
        use std::cell::RefCell;
        use std::io::BufReader;

        // Entry 6 (security mode / revoke) and entry 9 (uninstall) must both
        // stop at a refusal screen and never reach the effect handler.
        for entry in ["6", "9"] {
            let performed = RefCell::new(Vec::new());
            let mut state = ConsoleState::new(Lang::En, false);
            let input = format!("{entry}\n\nq\n");
            let mut reader = BufReader::new(input.as_bytes());
            let mut out: Vec<u8> = Vec::new();
            drive_console(&mut state, &mut reader, &mut out, |effect, _lang| {
                performed.borrow_mut().push(effect);
                ConsoleOutcome::none()
            })
            .expect("driver");

            assert!(
                performed.borrow().is_empty(),
                "entry {entry} must not perform anything: {:?}",
                performed.borrow()
            );
            let screen = String::from_utf8(out).expect("utf8");
            assert!(screen.contains("Refused"), "entry {entry}: {screen}");
        }
    }

    /// Live status is read from a real AF_UNIX socket in a temp directory. The
    /// fixture reads the complete `STATUS\n` request before answering, exactly
    /// like the daemon: responding and closing without that read races the
    /// client's write and surfaces as a spurious EPIPE ("control socket write
    /// failed"). Accept, read, write, and join are all bounded.
    #[cfg(unix)]
    #[test]
    fn console_reports_live_when_the_socket_answers() {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixListener;
        use std::sync::mpsc;
        use std::time::Duration;

        const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
        const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

        // macOS TMPDIR can already exceed sockaddr_un.sun_path once a test
        // name is appended. Keep this Unix-socket fixture short on every Unix.
        let dir = std::path::Path::new("/tmp").join(format!(
            "bc-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir(&dir).expect("unique temp dir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("private socket directory");
        }
        let socket_path = dir.join("control.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let mut poll_fd = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms = FIXTURE_TIMEOUT.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: `poll_fd` is one initialized `pollfd`; `poll` only writes
            // its `revents` field.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            assert_eq!(
                ready, 1,
                "the console did not connect within the fixture timeout"
            );
            assert_ne!(
                poll_fd.revents & libc::POLLIN,
                0,
                "fixture listener was not readable"
            );

            let (mut stream, _) = listener.accept().expect("accept");
            // BSD can inherit nonblocking mode from the listener. The
            // fixture needs a bounded blocking read of the complete request.
            stream.set_nonblocking(false).expect("blocking fixture stream");
            stream
                .set_read_timeout(Some(FIXTURE_TIMEOUT))
                .expect("fixture read timeout");
            stream
                .set_write_timeout(Some(FIXTURE_TIMEOUT))
                .expect("fixture write timeout");

            // Protocol order: read the whole request, then answer. This is the
            // daemon's contract and removes the close-before-read race.
            let mut request = String::new();
            BufReader::new((&mut stream).take(64))
                .read_line(&mut request)
                .expect("fixture reads STATUS");
            assert_eq!(request, "STATUS\n", "fixture read a partial request");

            let body = concat!(
                "{\"command\":\"ctl.status\",\"node\":\"core-1\",",
                "\"daemon_connected\":true,\"inbound_on\":true,",
                "\"inbound_connections\":1,\"outbound_upstreams\":0,",
                "\"security_mode\":\"e2e-required\"}\n"
            );
            stream.write_all(body.as_bytes()).expect("status answer");
            stream.flush().expect("status flush");
            done_tx.send(()).expect("fixture done signal");
        });

        let (code, stdout, stderr) = run_console(
            &args(&["--socket", socket_path.to_str().expect("utf8 socket")]),
            Lang::En,
            false,
            None,
        );

        let finished = match done_rx.recv_timeout(JOIN_TIMEOUT) {
            Ok(()) => {
                handle.join().expect("fixture thread");
                true
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                handle.join().expect("fixture thread");
                false
            }
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(finished, "fixture did not finish within {JOIN_TIMEOUT:?}");

        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("\"source\":\"live\""), "{stdout}");
        assert!(stdout.contains("\"daemon\":\"connected\""), "{stdout}");
        assert!(stdout.contains("\"node_name\":\"core-1\""), "{stdout}");
        assert!(stdout.contains("\"error\":null"), "{stdout}");
    }

    /// A hostile, very long node name from the control socket must reach the
    /// painted screen only through the sanitizing/truncating path: 18 lines of
    /// 77 columns, no ESC byte, and no extra line. This drives the real console
    /// entry point (`run_console_with`) against a real AF_UNIX fixture.
    #[cfg(unix)]
    #[test]
    fn console_paints_a_long_hostile_node_name_without_injection_or_ragged_lines() {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixListener;
        use std::sync::mpsc;
        use std::time::Duration;

        const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
        const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

        let dir = std::path::Path::new("/tmp").join(format!(
            "bcw-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir(&dir).expect("unique temp dir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("private socket directory");
        }
        let socket_path = dir.join("control.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let mut poll_fd = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms = FIXTURE_TIMEOUT.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: `poll_fd` is one initialized `pollfd`; `poll` only writes
            // its `revents` field.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            assert_eq!(
                ready, 1,
                "the console did not connect within the fixture timeout"
            );

            let (mut stream, _) = listener.accept().expect("accept");
            // BSD can inherit nonblocking mode from the listener. The
            // fixture needs a bounded blocking read of the complete request.
            stream.set_nonblocking(false).expect("blocking fixture stream");
            stream
                .set_read_timeout(Some(FIXTURE_TIMEOUT))
                .expect("fixture read timeout");
            stream
                .set_write_timeout(Some(FIXTURE_TIMEOUT))
                .expect("fixture write timeout");
            let mut request = String::new();
            BufReader::new((&mut stream).take(64))
                .read_line(&mut request)
                .expect("fixture reads STATUS");
            assert_eq!(request, "STATUS\n", "fixture read a partial request");

            let hostile = format!("{}\u{1b}[31m", "测".repeat(200));
            let body = format!(
                "{{\"command\":\"ctl.status\",\"node\":\"{hostile}\",\
                 \"daemon_connected\":true,\"inbound_on\":true,\
                 \"inbound_connections\":1,\"outbound_upstreams\":0,\
                 \"security_mode\":\"e2e-required\"}}\n"
            );
            stream.write_all(body.as_bytes()).expect("status answer");
            stream.flush().expect("status flush");
            done_tx.send(()).expect("fixture done signal");
        });

        let (code, stdout, painted, stderr) = run_scripted_console(
            &["--socket", socket_path.to_str().expect("utf8 socket")],
            Lang::En,
            Some(80),
            b"q\n",
        );

        let finished = match done_rx.recv_timeout(JOIN_TIMEOUT) {
            Ok(()) => {
                handle.join().expect("fixture thread");
                true
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                handle.join().expect("fixture thread");
                false
            }
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(finished, "fixture did not finish within {JOIN_TIMEOUT:?}");

        assert_eq!(code, 0, "{stderr}");
        assert!(
            stdout.is_empty(),
            "the TTY path paints instead of printing JSON"
        );
        let screen: Vec<&str> = painted.lines().take(18).collect();
        assert_eq!(screen.len(), 18, "no injected line: {painted}");
        for line in &screen {
            assert_eq!(display_width(line), BOX_WIDTH, "{line:?}");
        }
        assert!(
            !painted.as_bytes().contains(&0x1B),
            "a control character must not reach the terminal: {painted:?}"
        );
        assert!(painted.contains('测'), "the readable part still shows");
        assert!(
            !painted.contains(&"测".repeat(60)),
            "the name must be truncated to the cell, not painted in full"
        );
        assert!(painted.contains("live"), "the live source token is shown");
    }
}
