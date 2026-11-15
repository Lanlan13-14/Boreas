//! `boreas-supervisor` — the external upgrade-supervision process
//! (master plan §1.1, §10.3, §10.5).
//!
//! This binary is deliberately a *skeleton with real process semantics*, not
//! a release system. It never downloads, installs, or authenticates
//! anything: `prepare`/`activate` are intentionally absent so no operator
//! can stage an unverified artifact through this entry point. Manifest
//! verification (Ed25519 + ML-DSA dual signature, TUF-style roles, SBOM,
//! anti-rollback — master plan §10.1–§10.2, `G-SUPPLY`) is NOT implemented
//! anywhere in this crate and must land in an independent verification
//! layer before `prepare` is reachable in production.
//!
//! # Boot protocol
//!
//! Two launch modes compose into the §10.3 loop ("the external supervisor
//! rolls back the active pointer from an unconfirmed journal, then
//! restarts"; "re-running a broken path under systemd is not rollback"):
//!
//! 1. `recover` — call before launching any version. An unconfirmed
//!    (`Prepared`/`Activated`) journal rolls the active pointer back to the
//!    retained old version (or clears it on first install); a consistent
//!    `Confirmed` journal keeps the new version. Recovery is honest about
//!    being a store state transition only — it launches nothing.
//! 2. `supervise -- <argv...>` — the launch path. It performs recovery
//!    first ([`UpgradeStore::begin_activation`] starts in `recover()`), but
//!    never aborts mid-protocol:
//!    * no journal / consistent `Confirmed` → run `<argv...>` as the steady
//!      program and propagate its exit status (128+signal when killed);
//!    * `Prepared` → activate the candidate for one trial launch, run
//!      `<argv...>`; zero exit ⇒ `confirm()`, anything else (non-zero exit,
//!      death by signal, spawn/wait failure) ⇒ `recover()` rollback, with
//!      the old version directory retained in both cases;
//!    * `Activated` (a previous trial never confirmed, e.g. this supervisor
//!      or the candidate was `SIGKILL`ed before the outcome was recorded)
//!      → the `recover()` inside `begin_activation` has already restored
//!      the old pointer; run `<argv...>` as the *old* program and
//!      propagate its status. The candidate is not auto-retried by this
//!      invocation.
//!    * inconsistent `Confirmed` → refuse (non-zero, nothing launched).
//!
//!    The caller resolves `<argv...>` against the store: `supervise`
//!    replaces a leading `{version}` in `argv[0]` with the absolute
//!    active-version directory (fail-closed when no version is active), so
//!    the program actually started is always the one the pointer names —
//!    the candidate on a trial, the old program after a rollback — without
//!    the supervisor synthesising a binary name of its own.
//!
//! In production the pair is driven as `recover` once at service start,
//! then one `supervise` per OS-service restart; the first restart after an
//! upgrade runs the candidate once, a crash before `confirm()` leaves the
//! journal `Activated`, and the next `supervise` boots the rolled-back
//! version instead of retrying the candidate. Across further restarts the
//! journal sits at `Prepared` again, so a *fresh* `supervise` would trial
//! the candidate again — this minimal slice carries no cross-lifetime
//! "already failed" ledger. Breaking such a loop (trial budget, cooldown,
//! operator acknowledgement) is service policy that must be designed with
//! the §10.5 systemd/OS integration, **not** papered over here by silently
//! weakening `recover()`. Until that policy exists, wrap `supervise` with
//! bounded restart counts from the service manager and treat repeated
//! trial failures as an operator-visible condition.
//!
//! # Known gaps (explicit, not silently claimed)
//!
//! * **No signal forwarding.** If this process receives `SIGTERM`/etc. with
//!   a child running, the child is not signalled today; wiring that safely
//!   without a `libc` dependency is an open design item, listed as such in
//!   `docs/upgrade/README.md`.
//! * **No health gate beyond exit status.** A zero exit at *any* time is
//!   confirmed; "exit 0 because the administrator stopped it after a
//!   healthy run versus exit 0 immediately" cannot be distinguished
//!   without the §10.3/§10.5 health channel (`sd_notify` / control socket)
//!   that does not exist yet. The pointer is at least never confirmed on
//!   failure.
//! * **No store locking.** A second concurrent supervisor against the same
//!   store is not serialised (the library already requires single-writer
//!   access); lock policy is part of OS integration.
//! * **Durability** inherits the library audit: Linux directory `fsync`
//!   only, Windows/macOS fail closed, and the power-cut / fault-injection
//!   matrix behind `G-UPGRADE` remains unproven. Nothing in this slice
//!   claims `G-UPGRADE` (or `G-SUPPLY`) completion.
//!
//! Exit codes: `0` success/confirm/child exit 0; `1` any supervisor-side
//! error (usage, store open/recovery failure, spawn failure, rollback
//! after a failed trial — the exact cause is on stderr); `<n>` for steady
//! or rolled-back launches it is the child's own exit code, and `128+n`
//! when the child was killed by signal `n` (shell convention).

use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use boreas_supervisor::{Activation, Journal, Phase, Recovery, Result, UpgradeStore};

const EXIT_ERROR: u8 = 1;

/// Placeholder substituted (as a prefix) in `supervise`'s `argv[0]` with
/// the store's absolute active-version directory after recovery/activation.
const VERSION_PLACEHOLDER: &str = "{version}";

const USAGE: &str = "\
boreas-supervisor — external Boreas upgrade supervisor (minimal process slice)
USAGE:
    boreas-supervisor supervise --store <DIR> -- <argv...>
    boreas-supervisor recover --store <DIR> [--json]
    boreas-supervisor status --store <DIR> [--json]
    boreas-supervisor --help

subcommands:
    supervise   recover the store first, then run <argv...> as a child process
                (stdio inherited). A leading {version} in argv[0] is replaced
                with the resolved active-version directory; fail-closed when
                no version is active. A candidate activated for its trial
                launch is confirmed only on a zero exit and rolled back via
                recover() on any other outcome. Steady launches propagate the
                child's exit status (128+signal when killed).
    recover     run UpgradeStore::recover() without launching anything
    status      report the store's real journal/active-pointer state

This binary never downloads, installs, or authenticates a release.
prepare/activate are deliberately not exposed: staging artifacts requires
the independent manifest-verification layer (master plan Sec.10.1-10.2).";

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    match run_cli(&args) {
        CliOutcome::Done {
            code,
            stdout,
            stderr,
        } => {
            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            ExitCode::from(code)
        }
        CliOutcome::RunChild { plan, notes } => {
            for note in &notes {
                eprintln!("boreas-supervisor: {note}");
            }
            ExitCode::from(execute_supervise(plan))
        }
    }
}

/// Pure dispatch result. `RunChild` is separated from `Done` so unit tests
/// can assert which launch was planned (store state already advanced)
/// without spawning, then drive [`execute_supervise`] explicitly.
enum CliOutcome {
    Done {
        code: u8,
        stdout: String,
        stderr: String,
    },
    RunChild {
        plan: SupervisePlan,
        notes: Vec<String>,
    },
}

struct SupervisePlan {
    store_root: String,
    argv: Vec<OsString>,
    /// Version that must be confirmed on zero exit (trial launches only).
    trial_candidate: Option<String>,
}

/// What a launch decided before any process is spawned. Refusals return
/// from `cmd_supervise` directly and never reach this type; the variants
/// carry the version whose directory `{version}` resolves against.
enum Launch {
    Steady { active: Option<String> },
    Trial { candidate: String },
}

fn done(code: u8, stdout: String, stderr: String) -> CliOutcome {
    CliOutcome::Done {
        code,
        stdout,
        stderr,
    }
}

fn err_out(msg: &str) -> CliOutcome {
    done(
        EXIT_ERROR,
        String::new(),
        format!("boreas-supervisor: error: {msg}\n"),
    )
}

fn usage_err(msg: &str) -> CliOutcome {
    done(
        EXIT_ERROR,
        String::new(),
        format!("boreas-supervisor: error: {msg}\n\n{USAGE}\n"),
    )
}

fn run_cli(args: &[OsString]) -> CliOutcome {
    let Some(first) = args.first() else {
        return usage_err("missing subcommand");
    };
    let Some(cmd) = first.to_str() else {
        return usage_err("subcommand is not valid UTF-8");
    };
    match cmd {
        "--help" | "-h" | "help" => {
            if args.len() > 1 {
                usage_err("--help takes no further arguments")
            } else {
                done(0, format!("{USAGE}\n"), String::new())
            }
        }
        "supervise" => cmd_supervise(&args[1..]),
        "recover" => cmd_recover(&args[1..]),
        "status" => cmd_status(&args[1..]),
        other => usage_err(&format!("unknown subcommand: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Argument parsing (hand-rolled: the crate intentionally has no dependencies)
// ---------------------------------------------------------------------------

struct StoreArgs {
    store: String,
    json: bool,
}

fn parse_store_args(args: &[OsString], subcommand: &str) -> std::result::Result<StoreArgs, String> {
    let mut store: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i]
            .to_str()
            .ok_or_else(|| format!("{subcommand}: argument is not valid UTF-8"))?;
        match arg {
            "--store" => {
                if store.is_some() {
                    return Err(format!("{subcommand}: duplicate --store"));
                }
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| format!("{subcommand}: --store requires a value"))?;
                store = Some(
                    val.to_str()
                        .ok_or_else(|| format!("{subcommand}: --store value is not valid UTF-8"))?
                        .to_owned(),
                );
            }
            "--json" => {
                if json {
                    return Err(format!("{subcommand}: duplicate --json"));
                }
                json = true;
            }
            other => return Err(format!("{subcommand}: unexpected argument: {other}")),
        }
        i += 1;
    }
    Ok(StoreArgs {
        store: store.ok_or_else(|| format!("{subcommand}: missing required --store <DIR>"))?,
        json,
    })
}

struct SuperviseArgs {
    store: String,
    child_argv: Vec<OsString>,
}

fn parse_supervise_args(args: &[OsString]) -> std::result::Result<SuperviseArgs, String> {
    let mut store: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i]
            .to_str()
            .ok_or_else(|| "supervise: argument is not valid UTF-8".to_string())?;
        match arg {
            "--store" => {
                if store.is_some() {
                    return Err("supervise: duplicate --store".to_string());
                }
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "supervise: --store requires a value".to_string())?;
                store = Some(
                    val.to_str()
                        .ok_or_else(|| "supervise: --store value is not valid UTF-8".to_string())?
                        .to_owned(),
                );
            }
            "--" => {
                let store =
                    store.ok_or_else(|| "supervise: missing required --store <DIR>".to_string())?;
                let child_argv: Vec<OsString> = args[i + 1..].to_vec();
                if child_argv.is_empty() {
                    return Err(
                        "supervise: missing child argv after -- (nothing to run)".to_string()
                    );
                }
                return Ok(SuperviseArgs { store, child_argv });
            }
            other => {
                return Err(format!(
                    "supervise: unexpected argument: {other} (child argv must follow --)"
                ));
            }
        }
        i += 1;
    }
    Err("supervise: missing -- separator before child argv".to_string())
}

// ---------------------------------------------------------------------------
// Subcommands: recover / status (read the real store; nothing is fabricated)
// ---------------------------------------------------------------------------

fn open_store(path: &str) -> std::result::Result<UpgradeStore, CliOutcome> {
    UpgradeStore::open(path).map_err(|e| err_out(&format!("cannot open store {path}: {e}")))
}

fn cmd_recover(args: &[OsString]) -> CliOutcome {
    let parsed = match parse_store_args(args, "recover") {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let store = match open_store(&parsed.store) {
        Ok(s) => s,
        Err(o) => return o,
    };
    match recover_and_report(&store, parsed.json) {
        Ok(out) => done(0, out, String::new()),
        Err(e) => err_out(&format!("recover failed: {e}")),
    }
}

/// `UpgradeStore::open + recover`, formatted for operators. Shared by the
/// `recover` subcommand only; `supervise` uses `begin_activation`, which
/// performs its own recovery with trial semantics.
fn recover_and_report(store: &UpgradeStore, json: bool) -> Result<String> {
    let recovery = store.recover()?;
    if json {
        let (kind, active) = match &recovery {
            Recovery::NoTransaction => ("no_transaction", None),
            Recovery::Confirmed { active } => ("confirmed", active.as_deref()),
            Recovery::RolledBack { active } => ("rolled_back", active.as_deref()),
        };
        Ok(format!(
            "{{\"recovery\":{},\"active_version\":{}}}\n",
            json_str(kind),
            json_opt(active),
        ))
    } else {
        Ok(match &recovery {
            Recovery::NoTransaction => "recover: no upgrade transaction\n".to_string(),
            Recovery::Confirmed { active } => {
                format!(
                    "recover: confirmed upgrade intact, active={}\n",
                    active.as_deref().unwrap_or("(none)")
                )
            }
            Recovery::RolledBack { active } => {
                format!(
                    "recover: unconfirmed upgrade rolled back, active={}\n",
                    active.as_deref().unwrap_or("(none)")
                )
            }
        })
    }
}

fn cmd_status(args: &[OsString]) -> CliOutcome {
    let parsed = match parse_store_args(args, "status") {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let store = match open_store(&parsed.store) {
        Ok(s) => s,
        Err(o) => return o,
    };
    match status_report(&store, parsed.json) {
        Ok(out) => done(0, out, String::new()),
        Err(e) => err_out(&format!("status failed: {e}")),
    }
}

/// Render the store exactly as it is on disk: journal fields via
/// [`UpgradeStore::journal`], the raw pointer via
/// [`UpgradeStore::recorded_active_version`] (so a dangling pointer is
/// visible instead of hidden behind an error), and a `pointer_ok` verdict
/// from the strict [`UpgradeStore::active_version`] read.
fn status_report(store: &UpgradeStore, json: bool) -> Result<String> {
    let journal = store.journal()?;
    let recorded = store.recorded_active_version()?;
    let pointer_ok = store.active_version().is_ok();
    let stored = store.stored_version_count()?;
    if json {
        let journal_json = match &journal {
            None => "null".to_string(),
            Some(j) => format!(
                "{{\"old_version\":{},\"new_version\":{},\"phase\":{}}}",
                json_opt(j.old_version.as_deref()),
                json_str(&j.new_version),
                json_str(phase_name(&j.phase)),
            ),
        };
        Ok(format!(
            "{{\"journal\":{},\"active_version\":{},\"pointer_ok\":{},\"stored_versions\":{}}}\n",
            journal_json,
            json_opt(recorded.as_deref()),
            pointer_ok,
            stored,
        ))
    } else {
        let mut out = String::new();
        match &journal {
            None => out.push_str("journal: none\n"),
            Some(j) => {
                let _ = writeln!(
                    out,
                    "journal: phase={} old={} new={}",
                    phase_name(&j.phase),
                    j.old_version.as_deref().unwrap_or("(none)"),
                    j.new_version,
                );
            }
        }
        let _ = write!(
            out,
            "active: {}\npointer_ok: {}\nstored versions: {}\n",
            recorded.as_deref().unwrap_or("(none)"),
            pointer_ok,
            stored,
        );
        Ok(out)
    }
}

fn phase_name(phase: &Phase) -> &'static str {
    match phase {
        Phase::Prepared => "Prepared",
        Phase::Activated => "Activated",
        Phase::Confirmed => "Confirmed",
    }
}

// ---------------------------------------------------------------------------
// Subcommand: supervise (recover -> spawn -> wait -> confirm / roll back)
// ---------------------------------------------------------------------------

fn cmd_supervise(args: &[OsString]) -> CliOutcome {
    let parsed = match parse_supervise_args(args) {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let store = match open_store(&parsed.store) {
        Ok(s) => s,
        Err(o) => return o,
    };
    // Recovery happens before anything is launched (master plan Sec.10.3).
    // `begin_activation` starts from `recover()` and only permits the one
    // trial launch of a `Prepared` candidate afterwards.
    let mut notes: Vec<String> = Vec::new();
    let launch = match store.begin_activation() {
        Ok(Activation::Steady { active }) => {
            if let Some(v) = &active {
                notes.push(format!("supervising active version {v}"));
            }
            Launch::Steady { active }
        }
        Ok(Activation::TrialLaunch {
            candidate,
            previous,
        }) => {
            notes.push(format!(
                "trial launch of candidate {candidate} (previous: {}); \
                 confirmed only on a zero exit",
                previous.as_deref().unwrap_or("(none)")
            ));
            Launch::Trial { candidate }
        }
        Ok(Activation::RolledBack { active, candidate }) => {
            notes.push(format!(
                "candidate {candidate} was never confirmed; rolled back \
                 before launch, active={}",
                active.as_deref().unwrap_or("(none)")
            ));
            Launch::Steady { active }
        }
        Ok(Activation::Refused { active, candidate }) => {
            return err_out(&format!(
                "upgrade journal for candidate {candidate} is inconsistent \
                 with the active pointer; recovered to {} and refusing to \
                 launch — inspect the store with `status`",
                active.as_deref().unwrap_or("(none)"),
            ));
        }
        Err(e) => return err_out(&format!("pre-launch recovery failed: {e}")),
    };
    // `{version}` must resolve against the version the pointer names NOW
    // (the trial candidate, or the rolled-back/steady one) — never against
    // a version the caller merely hopes is active.
    let (trial_candidate, resolve_expected) = match &launch {
        Launch::Trial { candidate } => (Some(candidate.clone()), Some(candidate.clone())),
        Launch::Steady { active } => (None, active.clone()),
    };
    let argv = match resolve_child_argv(&store, &parsed.child_argv, resolve_expected.as_deref()) {
        Ok(argv) => argv,
        Err(e) => {
            // Fail-closed: a trial whose argv cannot even be resolved must
            // not linger in `Activated`. Restore the retained version now
            // instead of relying on a future boot to notice.
            if trial_candidate.is_some() && store.recover().is_err() {
                return err_out(&format!(
                    "{e}; rollback of the activated candidate ALSO failed — \
                     store may still point at the unconfirmed candidate"
                ));
            }
            return err_out(&e);
        }
    };
    CliOutcome::RunChild {
        plan: SupervisePlan {
            store_root: parsed.store,
            argv,
            trial_candidate,
        },
        notes,
    }
}

/// Resolve `{version}` (prefix of `argv[0]` only) against the version that
/// is active after recovery/activation. Fail-closed rules:
/// placeholder present but nothing active ⇒ error; placeholder in any
/// later argument ⇒ error (arguments are the operator's business, silently
/// rewriting them would be worse than refusing); store disagreement about
/// what is active ⇒ error.
fn resolve_child_argv(
    store: &UpgradeStore,
    child_argv: &[OsString],
    expected_active: Option<&str>,
) -> std::result::Result<Vec<OsString>, String> {
    for arg in &child_argv[1..] {
        if arg
            .to_str()
            .is_some_and(|s| s.contains(VERSION_PLACEHOLDER))
        {
            return Err(format!(
                "{VERSION_PLACEHOLDER} substitution is only supported in argv[0]"
            ));
        }
    }
    let Some(program) = child_argv.first() else {
        return Err("empty child argv".to_string());
    };
    let Some(rest) = program
        .to_str()
        .and_then(|s| s.strip_prefix(VERSION_PLACEHOLDER))
    else {
        return Ok(child_argv.to_vec());
    };
    let active = store
        .active_version()
        .map_err(|e| {
            format!("cannot resolve {VERSION_PLACEHOLDER}: active pointer unreadable: {e}")
        })?
        .ok_or_else(|| {
            format!("cannot resolve {VERSION_PLACEHOLDER}: no active version in store")
        })?;
    if Some(active.as_str()) != expected_active {
        return Err(format!(
            "cannot resolve {VERSION_PLACEHOLDER}: store activated {active} \
             but recovery reported {}",
            expected_active.unwrap_or("(none)")
        ));
    }
    let dir = store
        .version_dir(&active)
        .map_err(|e| format!("cannot resolve {VERSION_PLACEHOLDER}: {e}"))?;
    let mut argv = Vec::with_capacity(child_argv.len());
    argv.push(OsString::from(format!("{}{}", dir.to_string_lossy(), rest)));
    argv.extend(child_argv[1..].iter().cloned());
    Ok(argv)
}

/// Spawn the child with inherited stdio, wait for it, and close the
/// journal transaction according to how it died. Returns this process's
/// exit code. Never panics: every failure path keeps the store consistent
/// (trial candidates are rolled back, never left silently `Activated` —
/// and even if that rollback itself fails, the `Activated` journal makes
/// the *next* supervisor invocation roll back before launching).
///
/// Known gap: signals delivered to *this* process are not forwarded to the
/// child (see module docs). If this process is `SIGKILL`ed mid-trial, the
/// durable `Activated` journal is exactly what the next boot's
/// `recover()` uses to roll back — no `trap` is relied upon (§10.3).
fn execute_supervise(plan: SupervisePlan) -> u8 {
    let store = match UpgradeStore::open(&plan.store_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("boreas-supervisor: error: cannot re-open store: {e}");
            return EXIT_ERROR;
        }
    };
    let Some((program, rest)) = plan.argv.split_first() else {
        eprintln!("boreas-supervisor: error: empty child argv");
        return EXIT_ERROR;
    };
    match run_child_once(program, rest) {
        Ok(status) if status.success() => {
            if plan.trial_candidate.is_some() {
                match store.confirm() {
                    Ok(()) => {
                        eprintln!(
                            "boreas-supervisor: candidate confirmed after clean exit; \
                             previous version directory retained"
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!(
                            "boreas-supervisor: error: child exited 0 but confirm \
                             failed: {e}"
                        );
                        // Leave `Activated` untouched: the next supervisor
                        // invocation recovers before launching anything.
                        EXIT_ERROR
                    }
                }
            } else {
                0
            }
        }
        Ok(status) => {
            if plan.trial_candidate.is_some() {
                eprintln!(
                    "boreas-supervisor: trial child failed ({}); rolling back",
                    describe_status(status)
                );
                rollback_trial(&store)
            } else {
                exit_code_of(status)
            }
        }
        Err(e) => {
            eprintln!(
                "boreas-supervisor: error: cannot run {}: {e}",
                program.to_string_lossy()
            );
            if plan.trial_candidate.is_some() {
                rollback_trial(&store)
            } else {
                EXIT_ERROR
            }
        }
    }
}

fn rollback_trial(store: &UpgradeStore) -> u8 {
    match store.recover() {
        Ok(Recovery::RolledBack { active }) => {
            eprintln!(
                "boreas-supervisor: rolled back; active={} \
                 (previous version directory retained)",
                active.as_deref().unwrap_or("(none)")
            );
        }
        Ok(other) => {
            eprintln!(
                "boreas-supervisor: error: expected rollback, recovery \
                 reported {other:?} — inspect the store with `status`"
            );
        }
        Err(e) => {
            eprintln!(
                "boreas-supervisor: error: rollback after failed trial \
                 failed: {e} — journal remains Activated; the next \
                 supervisor invocation will recover before launching"
            );
        }
    }
    EXIT_ERROR
}

fn run_child_once(program: &OsString, args: &[OsString]) -> io::Result<ExitStatus> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    child.wait()
}

fn describe_status(status: ExitStatus) -> String {
    if let Some(code) = status.code() {
        format!("exit code {code}")
    } else if let Some(sig) = terminating_signal(status) {
        format!("killed by signal {sig}")
    } else {
        "terminated without an exit code".to_string()
    }
}

/// The child's own exit code, or `128 + signal` when it was killed
/// (clamped into `u8`), matching shell convention. A status that is
/// neither is an unspecified failure ⇒ `1`.
fn exit_code_of(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        u8::try_from(code).unwrap_or(EXIT_ERROR)
    } else if let Some(sig) = terminating_signal(status) {
        u8::try_from(128i32.saturating_add(sig)).unwrap_or(EXIT_ERROR)
    } else {
        EXIT_ERROR
    }
}

#[cfg(unix)]
fn terminating_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}
#[cfg(not(unix))]
fn terminating_signal(_status: ExitStatus) -> Option<i32> {
    None
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers. Version identifiers are already restricted to
// `[A-Za-z0-9._+-]` by the library, so escaping here is defence-in-depth
// for fixed strings (phase names), not a general JSON writer.
// ---------------------------------------------------------------------------

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn json_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_string(), json_str)
}

// Keep the journal type referenced so the status renderer stays coupled to
// the library's real shape if fields ever change.
#[allow(dead_code)]
fn _journal_shape(_: &Journal) {}

// ---------------------------------------------------------------------------
// Tests. Pure parsing/reporting runs everywhere; store/process behaviour is
// Linux-only because the library's durability contract is (Windows/macOS
// fail closed). Child processes are tiny test scripts in tempdirs — no
// network, no model, no installed Boreas binary involved.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn done_parts(outcome: CliOutcome) -> (u8, String, String) {
        match outcome {
            CliOutcome::Done {
                code,
                stdout,
                stderr,
            } => (code, stdout, stderr),
            CliOutcome::RunChild { .. } => panic!("expected a Done outcome"),
        }
    }

    #[test]
    fn help_prints_usage_and_exits_zero() {
        let (code, stdout, _) = done_parts(run_cli(&[os("--help")]));
        assert_eq!(code, 0);
        assert!(stdout.contains("supervise --store <DIR> -- <argv...>"));
        assert!(stdout.contains("never downloads, installs, or authenticates"));
    }

    #[test]
    fn unknown_subcommand_and_missing_subcommand_fail_closed() {
        let (code, _, err) = done_parts(run_cli(&[os("prepare")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("unknown subcommand: prepare"));
        let (code, _, err) = done_parts(run_cli(&[os("activate")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("unknown subcommand: activate"));
        let (code, _, err) = done_parts(run_cli(&[]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("missing subcommand"));
    }

    #[test]
    fn supervise_rejects_missing_child_argv_and_missing_separator() {
        let (code, _, err) = done_parts(run_cli(&[
            os("supervise"),
            os("--store"),
            os("/x"),
            os("--"),
        ]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("missing child argv"));
        let (code, _, err) = done_parts(run_cli(&[os("supervise"), os("--store"), os("/x")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("missing -- separator"));
        let (code, _, err) = done_parts(run_cli(&[os("supervise"), os("--"), os("/bin/true")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("missing required --store"));
        let (code, _, err) = done_parts(run_cli(&[
            os("supervise"),
            os("--store"),
            os("/x"),
            os("/bin/true"),
        ]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("child argv must follow --"));
    }

    #[test]
    fn store_commands_require_store_and_reject_unknown_flags() {
        let (code, _, err) = done_parts(run_cli(&[os("recover")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("missing required --store"));
        let (code, _, err) = done_parts(run_cli(&[os("status"), os("--wat")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("unexpected argument"));
        let (code, _, err) = done_parts(run_cli(&[os("status"), os("--store")]));
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("--store requires a value"));
    }

    #[test]
    fn json_helpers_escape_and_render_null() {
        assert_eq!(json_str("1.0.0"), "\"1.0.0\"");
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_opt(None), "null");
        assert_eq!(json_opt(Some("x")), "\"x\"");
    }

    #[test]
    fn exit_code_of_matches_real_child_statuses() {
        let ok = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .status()
            .unwrap();
        assert_eq!(exit_code_of(ok), 0);
        let three = Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .status()
            .unwrap();
        assert_eq!(exit_code_of(three), 3);
        assert_eq!(describe_status(three), "exit code 3");
        #[cfg(unix)]
        {
            let killed = Command::new("/bin/sh")
                .args(["-c", "exec kill -9 $$"])
                .status()
                .unwrap();
            assert_eq!(terminating_signal(killed), Some(9));
            assert_eq!(exit_code_of(killed), 137);
            assert_eq!(describe_status(killed), "killed by signal 9");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use boreas_supervisor::Candidate;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
        store_dir: PathBuf,
        src_dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "boreas-supervisor-cli-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                seq
            ));
            let store_dir = root.join("store");
            let src_dir = root.join("src");
            fs::create_dir_all(&store_dir).unwrap();
            fs::create_dir_all(&src_dir).unwrap();
            Self {
                root,
                store_dir,
                src_dir,
            }
        }

        fn store_str(&self) -> String {
            self.store_dir.to_string_lossy().into_owned()
        }

        fn store(&self) -> UpgradeStore {
            UpgradeStore::open(&self.store_dir).unwrap()
        }

        /// A fake "already independently verified" artifact directory whose
        /// program is a script doing `body`.
        fn artifact(&self, name: &str, body: &str) -> PathBuf {
            let dir = self.src_dir.join(name);
            fs::create_dir(&dir).unwrap();
            Self::write_prog(&dir.join("prog.sh"), body);
            dir
        }

        fn write_prog(path: &Path, body: &str) {
            fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        /// Install `version` as the pre-existing active version.
        fn seed_active(&self, version: &str, body: &str) -> PathBuf {
            let store = self.store();
            let dir = store.version_dir(version).unwrap();
            fs::create_dir(&dir).unwrap();
            Self::write_prog(&dir.join("prog.sh"), body);
            fs::write(
                self.store_dir.join("active.version"),
                format!("{version}\n"),
            )
            .unwrap();
            dir
        }

        fn prepare_and_activate(&self, version: &str, artifact_dir: &Path) {
            let store = self.store();
            store
                .prepare(
                    &Candidate {
                        version: version.to_owned(),
                    },
                    artifact_dir,
                )
                .unwrap();
            store.activate().unwrap();
        }

        fn marker(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Drive `supervise --store <dir> -- <argv...>` end to end: planning
    /// (recovery/activation + argv resolution) happens in `run_cli`, the
    /// real child runs in `execute_supervise`.
    fn supervise(f: &Fixture, child: &[&str]) -> (u8, Vec<String>) {
        let mut args = vec![os("supervise"), os("--store"), os(&f.store_str()), os("--")];
        args.extend(child.iter().map(|c| os(c)));
        match run_cli(&args) {
            CliOutcome::RunChild { plan, notes } => (execute_supervise(plan), notes),
            CliOutcome::Done {
                code,
                stdout,
                stderr,
            } => {
                panic!("supervise planning failed: code={code} stdout={stdout:?} stderr={stderr:?}")
            }
        }
    }

    fn store_cmd(f: &Fixture, cmd: &str, json: bool) -> (u8, String, String) {
        let mut args = vec![os(cmd), os("--store"), os(&f.store_str())];
        if json {
            args.push(os("--json"));
        }
        match run_cli(&args) {
            CliOutcome::Done {
                code,
                stdout,
                stderr,
            } => (code, stdout, stderr),
            CliOutcome::RunChild { .. } => panic!("{cmd} must not run a child"),
        }
    }

    // -- recover ----------------------------------------------------------

    #[test]
    fn recover_empty_store_reports_no_transaction() {
        let f = Fixture::new();
        let (code, out, _) = store_cmd(&f, "recover", false);
        assert_eq!(code, 0);
        assert!(out.contains("no upgrade transaction"));
        let (code, out, _) = store_cmd(&f, "recover", true);
        assert_eq!(code, 0);
        assert_eq!(
            out.trim(),
            r#"{"recovery":"no_transaction","active_version":null}"#
        );
        assert_eq!(f.store().active_version().unwrap(), None);
    }

    #[test]
    fn recover_with_current_pointer_and_no_journal_is_a_noop() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let (code, out, _) = store_cmd(&f, "recover", false);
        assert_eq!(code, 0);
        assert!(out.contains("no upgrade transaction"));
        assert_eq!(
            f.store().active_version().unwrap().as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn missing_store_fails_closed_for_every_subcommand() {
        let f = Fixture::new();
        let ghost = f.root.join("ghost").to_string_lossy().into_owned();
        for cmd in ["recover", "status"] {
            let args = vec![os(cmd), os("--store"), os(&ghost)];
            match run_cli(&args) {
                CliOutcome::Done { code, stderr, .. } => {
                    assert_eq!(code, EXIT_ERROR, "{cmd}");
                    assert!(stderr.contains("cannot open store"), "{cmd}: {stderr}");
                }
                CliOutcome::RunChild { .. } => panic!("{cmd} must not run a child"),
            }
        }
        let args = vec![
            os("supervise"),
            os("--store"),
            os(&ghost),
            os("--"),
            os("/bin/true"),
        ];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                assert!(stderr.contains("cannot open store"));
            }
            CliOutcome::RunChild { .. } => panic!("supervise must not run without a store"),
        }
    }

    #[test]
    fn corrupt_journal_fails_closed_and_status_reports_it() {
        let f = Fixture::new();
        let _ = f.store();
        fs::write(f.store_dir.join("upgrade.journal"), "garbage\n").unwrap();
        let (code, _, err) = store_cmd(&f, "recover", false);
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("recover failed"), "{err}");
        let (code, _, err) = store_cmd(&f, "status", false);
        assert_eq!(code, EXIT_ERROR);
        assert!(err.contains("status failed"), "{err}");
    }

    // -- status ------------------------------------------------------------

    #[test]
    fn status_reports_real_empty_store() {
        let f = Fixture::new();
        let (code, out, _) = store_cmd(&f, "status", false);
        assert_eq!(code, 0);
        assert!(out.contains("journal: none"), "{out}");
        assert!(out.contains("active: (none)"), "{out}");
        assert!(out.contains("stored versions: 0"), "{out}");
        let (code, out, _) = store_cmd(&f, "status", true);
        assert_eq!(code, 0);
        assert_eq!(
            out.trim(),
            r#"{"journal":null,"active_version":null,"pointer_ok":true,"stored_versions":0}"#
        );
    }

    #[test]
    fn status_reports_real_journal_and_retained_versions() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 0");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, out, _) = store_cmd(&f, "status", false);
        assert_eq!(code, 0);
        assert!(out.contains("phase=Prepared old=1.0.0 new=2.0.0"), "{out}");
        assert!(out.contains("active: 1.0.0"), "{out}");
        assert!(out.contains("pointer_ok: true"), "{out}");
        assert!(out.contains("stored versions: 2"), "{out}");
        let (code, out, _) = store_cmd(&f, "status", true);
        assert_eq!(code, 0);
        assert!(out.contains(r#""old_version":"1.0.0""#), "{out}");
        assert!(out.contains(r#""new_version":"2.0.0""#), "{out}");
        assert!(out.contains(r#""phase":"Prepared""#), "{out}");
    }

    #[test]
    fn status_shows_dangling_pointer_instead_of_erroring_away() {
        let f = Fixture::new();
        let _ = f.store();
        fs::write(f.store_dir.join("active.version"), "9.9.9\n").unwrap();
        let (code, out, _) = store_cmd(&f, "status", false);
        assert_eq!(code, 0);
        assert!(out.contains("active: 9.9.9"), "{out}");
        assert!(out.contains("pointer_ok: false"), "{out}");
        let (code, out, _) = store_cmd(&f, "status", true);
        assert_eq!(code, 0);
        assert!(out.contains(r#""active_version":"9.9.9""#), "{out}");
        assert!(out.contains(r#""pointer_ok":false"#), "{out}");
    }

    // -- supervise: trial outcomes ----------------------------------------

    #[test]
    fn trial_child_nonzero_exit_rolls_back_and_old_dir_survives() {
        let f = Fixture::new();
        let old_dir = f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 3");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, notes) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, EXIT_ERROR);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("trial launch of candidate 2.0.0"))
        );
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
        assert!(
            old_dir.join("prog.sh").is_file(),
            "old version dir must be retained"
        );
    }

    #[test]
    fn trial_child_killed_by_signal_rolls_back() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exec kill -9 $$");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, EXIT_ERROR);
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_ne!(store.journal().unwrap().unwrap().phase, Phase::Confirmed);
    }

    #[test]
    fn trial_child_zero_exit_confirms_and_keeps_old_dir() {
        let f = Fixture::new();
        let old_dir = f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 0");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 0);
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("2.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Confirmed);
        assert!(
            old_dir.join("prog.sh").is_file(),
            "old version dir must be retained"
        );
        // A later supervise is a steady launch of the confirmed version.
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 0);
        assert_eq!(store.active_version().unwrap().as_deref(), Some("2.0.0"));
    }

    #[test]
    fn already_activated_then_child_crashes_rolls_back_to_old_program() {
        // Semantically the "Activated + early crash" case: the boot that
        // starts from `Activated` has already been rolled back by recovery,
        // so {version} must resolve to the OLD program, and its crash must
        // propagate without touching the restored pointer.
        let f = Fixture::new();
        let marker = f.marker("old-ran");
        f.seed_active("1.0.0", &format!("touch {}; exit 3", marker.display()));
        let art = f.artifact("cand", "exit 0");
        f.prepare_and_activate("2.0.0", &art);
        let (code, notes) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(
            code, 3,
            "rolled-back launch propagates the child's exit code"
        );
        assert!(marker.is_file(), "old program must have run");
        assert!(notes.iter().any(|n| n.contains("never confirmed")));
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
    }

    // -- supervise: recovery-before-launch & steady propagation -----------

    #[test]
    fn unconfirmed_activation_is_rolled_back_before_anything_launches() {
        // prepare+activate, then a "crash" (no confirm). The next supervise
        // must recover first and start the old program, not the candidate.
        let f = Fixture::new();
        let old_marker = f.marker("old-ran");
        let cand_marker = f.marker("cand-ran");
        f.seed_active("1.0.0", &format!("touch {}; exit 0", old_marker.display()));
        let art = f.artifact("cand", &format!("touch {}; exit 0", cand_marker.display()));
        f.prepare_and_activate("2.0.0", &art);
        assert_eq!(
            f.store().journal().unwrap().unwrap().phase,
            Phase::Activated
        );
        let (code, notes) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 0);
        assert!(notes.iter().any(|n| n.contains("never confirmed")));
        assert!(old_marker.is_file(), "rolled-back old program must run");
        assert!(!cand_marker.exists(), "candidate must not be retried");
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
    }

    #[test]
    fn steady_child_exit_code_and_signal_propagate_without_touching_store() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 7");
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 7);
        assert_eq!(
            f.store().active_version().unwrap().as_deref(),
            Some("1.0.0")
        );
        assert_eq!(f.store().journal().unwrap(), None);

        let f2 = Fixture::new();
        f2.seed_active("1.0.0", "exec kill -9 $$");
        let (code, _) = supervise(&f2, &["{version}/prog.sh"]);
        assert_eq!(code, 137, "128+9 shell convention");
        assert_eq!(
            f2.store().active_version().unwrap().as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn repeated_steady_supervise_keeps_pointer_consistent() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        for _ in 0..3 {
            let (code, _) = supervise(&f, &["{version}/prog.sh"]);
            assert_eq!(code, 0);
            assert_eq!(
                f.store().active_version().unwrap().as_deref(),
                Some("1.0.0")
            );
        }
        // One failing steady run must not corrupt the pointer either.
        let prog = f.store().version_dir("1.0.0").unwrap().join("prog.sh");
        Fixture::write_prog(&prog, "exit 5");
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 5);
        assert_eq!(
            f.store().active_version().unwrap().as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn failed_trial_then_repeated_supervise_pointer_stays_consistent() {
        // After a failed trial the journal is `Prepared` again, so each
        // further supervise re-trials and re-rolls-back (documented; the
        // trial budget is outstanding service policy). The invariant under
        // test: the pointer ends at the retained old version after every
        // cycle and the candidate is never confirmed.
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 3");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        for _ in 0..3 {
            let (code, _) = supervise(&f, &["{version}/prog.sh"]);
            assert_eq!(code, EXIT_ERROR);
            let store = f.store();
            assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
            assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
        }
    }

    #[test]
    fn explicit_argv_runs_without_placeholder_and_may_carry_arguments() {
        // Operator-chosen argv (no {version}) still goes through recovery
        // and trial semantics: success here confirms the candidate.
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 0");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let script = f.src_dir.join("check.sh");
        Fixture::write_prog(&script, "test \"$1\" = expected-arg");
        let script = script.to_string_lossy().into_owned();
        let (code, _) = supervise(&f, &[&script, "expected-arg"]);
        assert_eq!(code, 0);
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("2.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Confirmed);
    }

    // -- supervise: fail-closed paths --------------------------------------

    #[test]
    fn missing_program_fails_closed_and_leaves_steady_store_untouched() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let ghost = f
            .root
            .join("no-such-program")
            .to_string_lossy()
            .into_owned();
        let (code, _) = supervise(&f, &[&ghost]);
        assert_eq!(code, EXIT_ERROR);
        assert_eq!(
            f.store().active_version().unwrap().as_deref(),
            Some("1.0.0")
        );
        assert_eq!(f.store().journal().unwrap(), None);
    }

    #[test]
    fn missing_program_during_trial_rolls_back_instead_of_lingering_activated() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 0");
        f.store()
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        // {version} resolves into the candidate dir, but the entry does
        // not exist there: spawn fails, trial must roll back immediately.
        let (code, _) = supervise(&f, &["{version}/missing-entry"]);
        assert_eq!(code, EXIT_ERROR);
        let store = f.store();
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
    }

    #[test]
    fn placeholder_without_any_active_version_fails_closed() {
        let f = Fixture::new();
        let args = vec![
            os("supervise"),
            os("--store"),
            os(&f.store_str()),
            os("--"),
            os("{version}/prog.sh"),
        ];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                assert!(stderr.contains("no active version"), "{stderr}");
            }
            CliOutcome::RunChild { .. } => panic!("must not launch without an active version"),
        }
    }

    #[test]
    fn placeholder_in_child_argument_is_rejected_not_substituted() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let args = vec![
            os("supervise"),
            os("--store"),
            os(&f.store_str()),
            os("--"),
            os("/bin/sh"),
            os("-c"),
            os("echo {version}"),
        ];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                assert!(stderr.contains("only supported in argv[0]"), "{stderr}");
            }
            CliOutcome::RunChild { .. } => panic!("must not substitute inside child arguments"),
        }
    }

    #[test]
    fn dangling_pointer_with_placeholder_fails_closed_before_launch() {
        let f = Fixture::new();
        let _ = f.store();
        fs::write(f.store_dir.join("active.version"), "9.9.9\n").unwrap();
        let args = vec![
            os("supervise"),
            os("--store"),
            os(&f.store_str()),
            os("--"),
            os("{version}/prog.sh"),
        ];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                // The strict active-pointer read inside pre-launch
                // recovery fails closed first (target dir missing).
                assert!(stderr.contains("pre-launch recovery failed"), "{stderr}");
            }
            CliOutcome::RunChild { .. } => panic!("must not launch a dangling pointer"),
        }
        // Nothing was launched or repaired implicitly: still dangling.
        assert_eq!(
            f.store().recorded_active_version().unwrap().as_deref(),
            Some("9.9.9")
        );
    }
}
