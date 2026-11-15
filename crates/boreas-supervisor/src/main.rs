//! `boreas-supervisor` — the external upgrade-supervision process
//! (master plan §1.1, §10.3, §10.5).
//!
//! This binary is the real supervision boundary, not a release system. It never
//! downloads, installs, or authenticates anything: `prepare`/`activate` are
//! intentionally absent so no operator can stage an unverified artifact through
//! this entry point. Manifest verification (Ed25519 + ML-DSA dual signature,
//! TUF-style roles, SBOM, anti-rollback — master plan §10.1–§10.2, `G-SUPPLY`)
//! lives in `manifest.rs` as strict structure/policy only; the signature
//! provider is not implemented, so `manifest::verify_release` fails closed and
//! `prepare` stays unreachable in production.
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
//!      `<argv...>`, and confirm only after an **authorized readiness answer**
//!      (see below); an early exit with any status, a readiness timeout, a
//!      rejected peer, a spawn/wait failure or a failed `confirm()`
//!      ⇒ `recover()` rollback, with the old version directory retained;
//!    * `Activated` (a previous trial never confirmed, e.g. this supervisor
//!      or the candidate was `SIGKILL`ed before the outcome was recorded)
//!      → the `recover()` inside `begin_activation` has already restored
//!      the old pointer; run `<argv...>` as the *old* program and
//!      propagate its status. The candidate is not auto-retried by this
//!      invocation, and the dead trial is recorded as a failed attempt.
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
//! upgrade runs the candidate once, and a crash before readiness leaves
//! the journal `Activated`, so the next `supervise` boots the rolled-back
//! version instead of retrying the candidate. A candidate that keeps failing
//! early is bounded by the durable trial budget
//! (`--max-trial-attempts`, default 3) rather than retried forever; after the
//! budget is spent the supervisor refuses to activate it and the operator must
//! inspect the store and run `reset-trial`.
//!
//! # Readiness: authorized handshake, not liveness
//!
//! A trial is confirmed only when the candidate proves it is *ready*, not when
//! it merely stayed alive. Before spawning, the supervisor binds a private
//! `AF_UNIX` socket (`<store>/ready.sock`, mode `0600`) and exports its path as
//! `BOREAS_READY_SOCKET`. The candidate must connect, satisfy peer-credential
//! checks (same uid always; on Linux the exact spawned pid) and answer a fresh
//! per-run random challenge with:
//!
//! * its state schema identifier,
//! * the number of ready workers,
//! * whether its TUN device is ready or absent.
//!
//! `--ready-timeout-ms` (default 30 000) bounds the answer, `--ready-min-workers`
//! (default 1) and `--ready-require-tun` (default `yes`) define acceptance.
//! Anything else — no connection, wrong peer, wrong echo, unacceptable state —
//! fails the trial and rolls back. A deadlocked-but-alive process can no longer
//! be confirmed.
//!
//! Deliberate limit: the challenge is **not yet bound to the candidate artifact
//! SHA-256**, because `verify_release` → `prepare` is not wired; that binding
//! belongs with the installer. There is also no Boreas daemon in this workspace
//! yet, so the protocol is exercised against the `__ready-stub` candidate in
//! integration tests. It is **not** claimed to be integrated in production.
//!
//! Every mutating subcommand (`supervise`, `recover`, `reset-trial`) holds the
//! store's exclusive OS file lock for its whole run, so two supervisors cannot
//! race the journal or the active pointer. The lock is released by the kernel
//! when the process dies, so a crash cannot leave a stale lock behind.
//!
//! Failed trials are durable. The attempt is written to `trial.state` *before*
//! the launch, so a supervisor that is killed mid-trial still consumes budget
//! on the next boot; `--max-trial-attempts` (default 3) bounds the restart loop
//! across process lifetimes. Only the operator-only `reset-trial` clears it.
//! The ledger can only ever *restrict* launches, so tampering with it causes a
//! denial of upgrades, never an unauthorised one.
//!
//! # Signals: forwarding and controlled stop
//!
//! `supervise` installs handlers for `SIGTERM`, `SIGINT` and `SIGHUP`. The
//! handler only stores the signal number in an atomic (async-signal-safe); the
//! wait loop forwards it to the child and gives it `--stop-grace-ms` (default
//! 10 000) before escalating to `SIGKILL`. A stop that arrives *before*
//! readiness fails the trial and rolls back, because an interrupted candidate
//! never proved itself.
//!
//! The group/console contract still applies underneath: a cgroup-wide stop
//! reaches the child directly, and if this supervisor is killed the durable
//! `Activated` journal plus the `in-flight` reservation make the next
//! `supervise` roll back and count the attempt (§10.3).
//!
//! What is *not* provided: per-signal exit mapping beyond `128+n`, a graceful
//! stop of an already-confirmed daemon beyond the forwarded signal, and any
//! Windows signal semantics (Windows has no POSIX disposition; its store path
//! stays fail-closed).
//!
//! # Still missing (explicit, not silently claimed)
//!
//! * **No artifact-SHA binding in the challenge**, and no real daemon to answer
//!   it: the protocol is real, the integration is not.
//! * **No release verification wiring.** Nothing here downloads, authenticates
//!   or stages a release; `prepare`/`activate` are deliberately absent from the
//!   CLI so no unverified artifact can be executed through it.
//! * **Durability** inherits the library audit: Linux directory `fsync`, macOS
//!   `F_FULLFSYNC` + directory `fsync`, Windows fail-closed, and the power-cut /
//!   fault-injection matrix behind `G-UPGRADE` remains unproven. Nothing in this
//!   slice claims `G-UPGRADE` or `G-SUPPLY` completion.
//!
//! Exit codes: `0` success/confirm/child exit 0; `1` any supervisor-side
//! error (usage, store open/lock/recovery failure, spawn failure, rejected
//! readiness, rollback after a failed trial — the exact cause is on stderr);
//! `<n>` for steady launches, confirmed launches that later exit, and
//! rolled-back launches it is the child's own exit code, and `128+n` when the
//! child was killed by signal `n` (shell convention).

use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
#[cfg(unix)]
use std::thread;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use boreas_supervisor::{
    Activation, Journal, Phase, Recovery, Result, StoreLock, TrialState, UpgradeStore,
};

/// POSIX signal forwarding + controlled stop (no-ops off Unix).
mod signals;

/// Authorized AF_UNIX readiness handshake. Unix-only: Windows has no `AF_UNIX`
/// in `std` and no peer-credential binding here, so a trial launch there fails
/// closed instead of confirming on liveness alone.
#[cfg(unix)]
mod readiness;

const EXIT_ERROR: u8 = 1;

/// Poll interval for child waits, readiness probes and stop deadlines.
#[cfg(unix)]
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A trial candidate must answer the readiness challenge within this window.
/// Overridable with `--ready-timeout-ms` (tests use short values).
const DEFAULT_READY_TIMEOUT_MS: u64 = 30_000;

/// How long a forwarded stop signal may take before `SIGKILL` is sent.
const DEFAULT_STOP_GRACE_MS: u64 = 10_000;

/// Minimum ready workers a candidate must report.
const DEFAULT_READY_MIN_WORKERS: u32 = 1;

/// Whether a ready TUN device is required (VPN deployments usually are).
const DEFAULT_READY_REQUIRE_TUN: bool = true;

/// Durable per-candidate trial budget. Overridable with
/// `--max-trial-attempts`; only the operator-only `reset-trial` clears it.
const DEFAULT_MAX_TRIAL_ATTEMPTS: u32 = 3;

/// Placeholder substituted (as a prefix) in `supervise`'s `argv[0]` with
/// the store's absolute active-version directory after recovery/activation.
const VERSION_PLACEHOLDER: &str = "{version}";

const USAGE: &str = "\
boreas-supervisor — external Boreas upgrade supervisor
USAGE:
    boreas-supervisor supervise --store <DIR> --ready-expected-schema <ID>
                                [--ready-timeout-ms <MS>]
                                [--ready-require-tun <yes|no>]
                                [--ready-min-workers <N>]
                                [--stop-grace-ms <MS>]
                                [--max-trial-attempts <N>] -- <argv...>
    boreas-supervisor recover --store <DIR> [--json]
    boreas-supervisor status --store <DIR> [--json]
    boreas-supervisor reset-trial --store <DIR> --confirm <VERSION>
    boreas-supervisor --help

subcommands:
    supervise   lock the store, recover it, then run <argv...> as a child
                process (stdio inherited). A leading {version} in argv[0] is
                replaced with the resolved active-version directory;
                fail-closed when no version is active.
                A prepared candidate gets one trial launch. It is confirmed
                only after an AUTHORIZED READINESS ANSWER: the supervisor
                binds <store>/ready.sock (mode 0600), exports it as
                BOREAS_READY_SOCKET, and the candidate must connect, prove it
                is the process we spawned (SO_PEERCRED / getpeereid: same uid,
                and on Linux the exact pid) and echo this run's fresh random
                challenge together with its state schema, ready worker count
                and TUN status. Liveness alone confirms nothing: a child that
                merely stays alive until --ready-timeout-ms (default 30000) is
                rolled back. --ready-require-tun (default yes) and
                --ready-min-workers (default 1) set the acceptance policy.
                The attempt is written to the store before the launch, so a
                killed supervisor still consumes budget; --max-trial-attempts
                (default 3) bounds the retry loop across restarts. Once
                confirmed, a later exit is an ordinary runtime stop and is
                propagated.
                Stops delivered to this process are forwarded to the child
                (SIGTERM/SIGINT/SIGHUP), with SIGKILL after --stop-grace-ms
                (default 10000).
    recover     run UpgradeStore::recover() under the store lock; launches
                nothing
    status      report the store's real journal/active-pointer/trial state
    reset-trial clear the durable failed-trial ledger. High-risk and
                operator-only: --confirm must repeat the exact candidate
                version recorded in trial.state, an audit line is appended to
                trial.audit, and only then is the budget reset. Name the OS
                account that ran it via the systemd journal / event log.

Every mutating subcommand takes an OS file lock on the store, so concurrent
supervisors cannot race the journal. The lock dies with the process and never
goes stale.

`__ready-stub` is a hidden test-support candidate (not an operator command); it
exists so integration tests exercise the real handshake with a real subprocess.

This binary never downloads, installs, or authenticates a release.
prepare/activate are deliberately not exposed: staging artifacts requires
the independent manifest-verification layer (master plan Sec.10.1-10.2).";

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    // Handlers are installed only for `supervise`, the one command that spawns a
    // child and must forward stops to it. Installing them for the test stub
    // would make the stub ignore SIGTERM and hang the forwarding test.
    if args.first().and_then(|arg| arg.to_str()) == Some("supervise")
        && let Err(e) = signals::install()
    {
        // Not fatal: the group-directed contract still applies.
        eprintln!("boreas-supervisor: warning: cannot install signal handlers: {e}");
    }
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
            ExitCode::from(execute_supervise(*plan))
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
        plan: Box<SupervisePlan>,
        notes: Vec<String>,
    },
}

struct SupervisePlan {
    store_root: String,
    argv: Vec<OsString>,
    /// Candidate whose trial launch is in flight (trial launches only).
    trial_candidate: Option<String>,
    /// Unix trial-readiness policy. Windows deliberately refuses trial launch
    /// because its readiness channel is not implemented there.
    #[cfg(unix)]
    ready_timeout: Duration,
    #[cfg(unix)]
    stop_grace: Duration,
    #[cfg(unix)]
    ready_require_tun: bool,
    #[cfg(unix)]
    ready_min_workers: u32,
    #[cfg(unix)]
    ready_expected_schema: String,
    /// Exclusive store lock, held from before recovery until the child exits.
    /// Dropping the plan releases it.
    store_lock: StoreLock,
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
        "reset-trial" => cmd_reset_trial(&args[1..]),
        // Test-support candidate side of the readiness handshake. Hidden (`__`)
        // because it is not an operator command: it exists so integration tests
        // drive the real protocol with a real subprocess instead of a mock.
        "__ready-stub" => cmd_ready_stub(&args[1..]),
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
    ready_timeout: Duration,
    stop_grace: Duration,
    ready_require_tun: bool,
    ready_min_workers: u32,
    ready_expected_schema: String,
    max_trial_attempts: u32,
    child_argv: Vec<OsString>,
}

fn parse_supervise_args(args: &[OsString]) -> std::result::Result<SuperviseArgs, String> {
    let mut store: Option<String> = None;
    let mut ready_timeout: Option<Duration> = None;
    let mut stop_grace: Option<Duration> = None;
    let mut ready_require_tun: Option<bool> = None;
    let mut ready_min_workers: Option<u32> = None;
    let mut ready_expected_schema: Option<String> = None;
    let mut max_trial_attempts: Option<u32> = None;
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
            "--ready-timeout-ms" => {
                if ready_timeout.is_some() {
                    return Err("supervise: duplicate --ready-timeout-ms".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| "supervise: --ready-timeout-ms requires a value".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --ready-timeout-ms value is not valid UTF-8".to_string()
                    })?;
                let ms: u64 = raw.parse().map_err(|_| {
                    "supervise: --ready-timeout-ms must be a whole number of milliseconds"
                        .to_string()
                })?;
                ready_timeout = Some(Duration::from_millis(ms));
            }
            "--stop-grace-ms" => {
                if stop_grace.is_some() {
                    return Err("supervise: duplicate --stop-grace-ms".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| "supervise: --stop-grace-ms requires a value".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --stop-grace-ms value is not valid UTF-8".to_string()
                    })?;
                let ms: u64 = raw.parse().map_err(|_| {
                    "supervise: --stop-grace-ms must be a whole number of milliseconds".to_string()
                })?;
                stop_grace = Some(Duration::from_millis(ms));
            }
            "--ready-require-tun" => {
                if ready_require_tun.is_some() {
                    return Err("supervise: duplicate --ready-require-tun".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| "supervise: --ready-require-tun requires a value".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --ready-require-tun value is not valid UTF-8".to_string()
                    })?;
                ready_require_tun = Some(match raw {
                    "yes" => true,
                    "no" => false,
                    _ => {
                        return Err(
                            "supervise: --ready-require-tun must be `yes` or `no`".to_string()
                        );
                    }
                });
            }
            "--ready-min-workers" => {
                if ready_min_workers.is_some() {
                    return Err("supervise: duplicate --ready-min-workers".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| "supervise: --ready-min-workers requires a value".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --ready-min-workers value is not valid UTF-8".to_string()
                    })?;
                let workers: u32 = raw.parse().map_err(|_| {
                    "supervise: --ready-min-workers must be a positive integer".to_string()
                })?;
                if workers == 0 {
                    return Err("supervise: --ready-min-workers must be at least 1".to_string());
                }
                ready_min_workers = Some(workers);
            }
            "--ready-expected-schema" => {
                if ready_expected_schema.is_some() {
                    return Err("supervise: duplicate --ready-expected-schema".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| {
                        "supervise: --ready-expected-schema requires a value".to_string()
                    })?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --ready-expected-schema value is not valid UTF-8".to_string()
                    })?;
                if raw.is_empty() || raw.len() > 64 {
                    return Err(
                        "supervise: --ready-expected-schema must be 1..=64 bytes".to_string()
                    );
                }
                if !raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
                    || raw.starts_with('.')
                {
                    return Err(
                        "supervise: --ready-expected-schema is not a valid identifier".to_string(),
                    );
                }
                ready_expected_schema = Some(raw.to_owned());
            }
            "--max-trial-attempts" => {
                if max_trial_attempts.is_some() {
                    return Err("supervise: duplicate --max-trial-attempts".to_string());
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| "supervise: --max-trial-attempts requires a value".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        "supervise: --max-trial-attempts value is not valid UTF-8".to_string()
                    })?;
                let attempts: u32 = raw.parse().map_err(|_| {
                    "supervise: --max-trial-attempts must be a positive integer".to_string()
                })?;
                if attempts == 0 {
                    return Err("supervise: --max-trial-attempts must be at least 1".to_string());
                }
                max_trial_attempts = Some(attempts);
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
                return Ok(SuperviseArgs {
                    store,
                    ready_timeout: ready_timeout
                        .unwrap_or_else(|| Duration::from_millis(DEFAULT_READY_TIMEOUT_MS)),
                    stop_grace: stop_grace
                        .unwrap_or_else(|| Duration::from_millis(DEFAULT_STOP_GRACE_MS)),
                    ready_require_tun: ready_require_tun.unwrap_or(DEFAULT_READY_REQUIRE_TUN),
                    ready_min_workers: ready_min_workers.unwrap_or(DEFAULT_READY_MIN_WORKERS),
                    // Required: the schema is bound to the target release, so a
                    // default would silently accept whatever a candidate says.
                    ready_expected_schema: ready_expected_schema.ok_or_else(|| {
                        "supervise: --ready-expected-schema <ID> is required \
                         (the state schema the target release expects)"
                            .to_string()
                    })?,
                    max_trial_attempts: max_trial_attempts.unwrap_or(DEFAULT_MAX_TRIAL_ATTEMPTS),
                    child_argv,
                });
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
    // Recovery rewrites the journal and pointer, so it must be serialised
    // against a running supervisor exactly like `supervise` is.
    let _lock = match store.lock_exclusive() {
        Ok(lock) => lock,
        Err(e) => return err_out(&format!("cannot recover store {}: {e}", parsed.store)),
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
    let trial = store.trial_state()?;
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
        let trial_json = match &trial {
            None => "null".to_string(),
            Some(t) => format!(
                "{{\"version\":{},\"attempts\":{},\"in_flight\":{}}}",
                json_str(&t.version),
                t.attempts,
                t.in_flight,
            ),
        };
        Ok(format!(
            "{{\"journal\":{},\"active_version\":{},\"pointer_ok\":{},\
             \"stored_versions\":{},\"trial\":{}}}\n",
            journal_json,
            json_opt(recorded.as_deref()),
            pointer_ok,
            stored,
            trial_json,
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
        match &trial {
            None => out.push_str("trial: none\n"),
            Some(t) => {
                let _ = writeln!(
                    out,
                    "trial: version={} attempts={} in_flight={}",
                    t.version, t.attempts, t.in_flight,
                );
            }
        }
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
// Subcommand: reset-trial (confirmed + audited operator acknowledgement)
// ---------------------------------------------------------------------------

struct ResetTrialArgs {
    store: String,
    confirm: String,
}

fn parse_reset_trial_args(args: &[OsString]) -> std::result::Result<ResetTrialArgs, String> {
    let mut store: Option<String> = None;
    let mut confirm: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i]
            .to_str()
            .ok_or_else(|| "reset-trial: argument is not valid UTF-8".to_string())?;
        match arg {
            "--store" | "--confirm" => {
                let slot = if arg == "--store" {
                    &mut store
                } else {
                    &mut confirm
                };
                if slot.is_some() {
                    return Err(format!("reset-trial: duplicate {arg}"));
                }
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("reset-trial: {arg} requires a value"))?
                    .to_str()
                    .ok_or_else(|| format!("reset-trial: {arg} value is not valid UTF-8"))?;
                *slot = Some(value.to_owned());
            }
            other => return Err(format!("reset-trial: unexpected argument: {other}")),
        }
        i += 1;
    }
    Ok(ResetTrialArgs {
        store: store.ok_or_else(|| "reset-trial: missing required --store <DIR>".to_string())?,
        // A high-risk action needs an explicit, non-guessable acknowledgement:
        // the operator must name the exact candidate recorded in `trial.state`.
        confirm: confirm.ok_or_else(|| {
            "reset-trial: --confirm <CANDIDATE_VERSION> is required (name the \
             recorded candidate after inspecting the store)"
                .to_string()
        })?,
    })
}

fn cmd_reset_trial(args: &[OsString]) -> CliOutcome {
    let parsed = match parse_reset_trial_args(args) {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let store = match open_store(&parsed.store) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let _lock = match store.lock_exclusive() {
        Ok(lock) => lock,
        Err(e) => return err_out(&format!("cannot reset trial in {}: {e}", parsed.store)),
    };
    match reset_trial_report(&store, &parsed.confirm) {
        Ok(out) => done(0, out, String::new()),
        Err(e) => err_out(&format!("reset-trial refused: {e}")),
    }
}

/// Clear the durable trial ledger after an exact confirmation, appending an
/// audit record first. Deliberately an explicit operator action: the supervisor
/// never clears a spent budget by itself, so a crash loop cannot silently
/// re-enable unlimited candidate trials.
fn reset_trial_report(store: &UpgradeStore, confirm: &str) -> std::result::Result<String, String> {
    let state = store.trial_state().map_err(|e| e.to_string())?;
    let Some(state) = state else {
        return Ok("reset-trial: no trial record to clear\n".to_string());
    };
    if state.version != confirm {
        return Err(format!(
            "confirmation does not match the recorded candidate {} \
             (re-run with --confirm {})",
            state.version, state.version
        ));
    }
    // Audit before clearing: if the audit write fails, the ledger is untouched.
    store
        .record_trial_reset(&state.version, state.attempts)
        .map_err(|e| e.to_string())?;
    store.clear_trial().map_err(|e| e.to_string())?;
    Ok(format!(
        "reset-trial: cleared {} attempt(s) for candidate {} after confirmation; \
         audit record appended to trial.audit; the next `supervise` may trial it again\n",
        state.attempts, state.version
    ))
}

// ---------------------------------------------------------------------------
// Subcommand: __ready-stub (test-support candidate side of the handshake)
// ---------------------------------------------------------------------------

/// Candidate side of the readiness handshake, for integration tests only.
///
/// It is a real protocol client — not a mock — so `tests/readiness.rs` can run
/// the supervisor and a `__ready-stub` child as two actual processes and
/// exercise AF_UNIX, peer credentials and the challenge/response end to end.
#[cfg(unix)]
fn cmd_ready_stub(args: &[OsString]) -> CliOutcome {
    let mut socket: Option<String> = None;
    let mut schema = String::from("state-v1");
    let mut workers: u32 = 1;
    let mut tun = readiness::TunStatus::Ready;
    let mut exit_after_ms: Option<u64> = None;
    let mut exit_code: u8 = 0;
    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            return usage_err("__ready-stub: argument is not valid UTF-8");
        };
        match flag {
            "--socket" | "--schema" | "--workers" | "--tun" | "--exit-after-ms" | "--exit-code" => {
                i += 1;
                let Some(raw) = args.get(i).and_then(|value| value.to_str()) else {
                    return usage_err(&format!("__ready-stub: {flag} requires a UTF-8 value"));
                };
                match flag {
                    "--socket" => socket = Some(raw.to_owned()),
                    "--schema" => schema = raw.to_owned(),
                    "--workers" => match raw.parse::<u32>() {
                        Ok(value) => workers = value,
                        Err(_) => return usage_err("__ready-stub: --workers must be an integer"),
                    },
                    "--tun" => {
                        tun = match raw {
                            "ready" => readiness::TunStatus::Ready,
                            "absent" => readiness::TunStatus::Absent,
                            _ => return usage_err("__ready-stub: --tun must be ready or absent"),
                        };
                    }
                    "--exit-after-ms" => match raw.parse::<u64>() {
                        Ok(value) => exit_after_ms = Some(value),
                        Err(_) => {
                            return usage_err("__ready-stub: --exit-after-ms must be a number");
                        }
                    },
                    "--exit-code" => match raw.parse::<u8>() {
                        Ok(value) => exit_code = value,
                        Err(_) => return usage_err("__ready-stub: --exit-code must be 0-255"),
                    },
                    _ => {}
                }
            }
            other => return usage_err(&format!("__ready-stub: unexpected argument: {other}")),
        }
        i += 1;
    }
    let socket = socket.or_else(|| {
        env::var_os(readiness::SOCKET_ENV).map(|value| value.to_string_lossy().into_owned())
    });
    let Some(socket) = socket else {
        return usage_err("__ready-stub: --socket or BOREAS_READY_SOCKET is required");
    };
    if let Err(e) = readiness::serve_once(std::path::Path::new(&socket), &schema, workers, tun) {
        return err_out(&format!("__ready-stub: readiness handshake failed: {e}"));
    }
    match exit_after_ms {
        Some(ms) => thread::sleep(Duration::from_millis(ms)),
        None => loop {
            // Stay alive until the supervisor stops us.
            thread::sleep(Duration::from_secs(3600));
        },
    }
    done(exit_code, String::new(), String::new())
}

#[cfg(not(unix))]
fn cmd_ready_stub(_args: &[OsString]) -> CliOutcome {
    err_out("__ready-stub: AF_UNIX readiness is not available on this platform")
}

// ---------------------------------------------------------------------------
// Subcommand: supervise (lock -> recover -> spawn -> readiness -> confirm)
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
    // Single writer: recovery, activation, the trial ledger and the child's
    // whole lifetime happen under one OS lock, so a second supervisor fails
    // fast instead of racing the journal.
    let store_lock = match store.lock_exclusive() {
        Ok(lock) => lock,
        Err(e) => return err_out(&format!("cannot supervise store {}: {e}", parsed.store)),
    };
    let mut notes: Vec<String> = Vec::new();

    // Durable reservation *before* `begin_activation` can move the active
    // pointer. If this process is killed anywhere after this point — including
    // between `activate()` and the spawn — the attempt is already recorded and
    // the next boot counts it. This is what closes the old
    // "killed after activate, before reserve" window.
    let reservation = match reserve_pending_trial(&store, parsed.max_trial_attempts) {
        Ok(reserved) => reserved,
        Err(e) => return err_out(&format!("cannot reserve a trial attempt: {e}")),
    };

    // Recovery happens before anything is launched (master plan Sec.10.3).
    // `begin_activation` starts from `recover()` and only permits the one
    // trial launch of a `Prepared` candidate afterwards.
    let launch = match store.begin_activation() {
        Ok(Activation::Steady { active }) => {
            // A reservation without a trial launch means the journal changed
            // under us (it should not: we hold the lock). Consume it as a
            // failed attempt rather than leaving it pending forever.
            settle_unused_reservation(&store, &reservation);
            if let Some(v) = &active {
                notes.push(format!("supervising active version {v}"));
            }
            Launch::Steady { active }
        }
        Ok(Activation::TrialLaunch {
            candidate,
            previous,
        }) => {
            match &reservation {
                Some(state) if state.version == candidate => notes.push(format!(
                    "trial launch {}/{} of candidate {candidate} (previous: {}); \
                     confirmed only after an authorized readiness answer within {} ms \
                     (require_tun={}, min_workers={})",
                    state.attempts,
                    parsed.max_trial_attempts,
                    previous.as_deref().unwrap_or("(none)"),
                    parsed.ready_timeout.as_millis(),
                    parsed.ready_require_tun,
                    parsed.ready_min_workers,
                )),
                _ => {
                    // Refuse rather than launch a trial whose attempt was never
                    // recorded: an unreserved launch would be unbounded.
                    let _ = store.mark_trial_failed();
                    if store.recover().is_err() {
                        return err_out(
                            "trial reservation and journal disagree; rollback of the \
                             activated candidate ALSO failed — store may still point at \
                             the unconfirmed candidate",
                        );
                    }
                    return err_out(
                        "trial reservation and journal disagree; refusing to launch an \
                         unreserved trial (inspect the store with `status`)",
                    );
                }
            }
            Launch::Trial { candidate }
        }
        Ok(Activation::RolledBack { active, candidate }) => {
            // A previous trial never confirmed (its supervisor died before the
            // outcome). That attempt is already reserved durably; flip it to
            // `failed` so the record is accurate even if this process dies now.
            if let Err(e) = store.mark_trial_failed() {
                notes.push(format!(
                    "warning: could not record the failed trial of {candidate}: {e}"
                ));
            }
            notes.push(format!(
                "candidate {candidate} was never confirmed; rolled back \
                 before launch, active={}",
                active.as_deref().unwrap_or("(none)")
            ));
            Launch::Steady { active }
        }
        Ok(Activation::Refused { active, candidate }) => {
            settle_unused_reservation(&store, &reservation);
            return err_out(&format!(
                "upgrade journal for candidate {candidate} is inconsistent \
                 with the active pointer; recovered to {} and refusing to \
                 launch — inspect the store with `status`",
                active.as_deref().unwrap_or("(none)"),
            ));
        }
        Err(e) => {
            // The reservation is already durable; record the failed outcome so
            // the ledger is accurate even though nothing was launched.
            settle_unused_reservation(&store, &reservation);
            return err_out(&format!("pre-launch recovery failed: {e}"));
        }
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
            if trial_candidate.is_some() {
                let _ = store.mark_trial_failed();
                if store.recover().is_err() {
                    return err_out(&format!(
                        "{e}; rollback of the activated candidate ALSO failed — \
                         store may still point at the unconfirmed candidate"
                    ));
                }
            }
            return err_out(&e);
        }
    };
    #[cfg(not(unix))]
    let _unused_unix_readiness_policy = (
        parsed.ready_timeout,
        parsed.stop_grace,
        parsed.ready_require_tun,
        parsed.ready_min_workers,
        parsed.ready_expected_schema.as_str(),
    );
    CliOutcome::RunChild {
        plan: Box::new(SupervisePlan {
            store_root: parsed.store,
            argv,
            trial_candidate,
            #[cfg(unix)]
            ready_timeout: parsed.ready_timeout,
            #[cfg(unix)]
            stop_grace: parsed.stop_grace,
            #[cfg(unix)]
            ready_require_tun: parsed.ready_require_tun,
            #[cfg(unix)]
            ready_min_workers: parsed.ready_min_workers,
            #[cfg(unix)]
            ready_expected_schema: parsed.ready_expected_schema,
            store_lock,
        }),
        notes,
    }
}

/// Reserve the next trial attempt **before** the active pointer can move.
///
/// Returns the reserved state when the journal is `Prepared` (this run will
/// trial that candidate), `None` otherwise. Reserving first is what removes the
/// old "killed between `activate()` and reservation" window: any kill after
/// this returns still consumes the attempt on the next boot. An exhausted
/// budget fails here, so the candidate is never briefly activated.
fn reserve_pending_trial(store: &UpgradeStore, max_attempts: u32) -> Result<Option<TrialState>> {
    let Some(journal) = store.journal()? else {
        return Ok(None);
    };
    if journal.phase != Phase::Prepared {
        return Ok(None);
    }
    store
        .reserve_trial(&journal.new_version, max_attempts)
        .map(Some)
}

/// A reservation that did not turn into a trial launch (journal changed under
/// the lock, or recovery failed) is consumed as a failed attempt rather than
/// left `in-flight` forever.
fn settle_unused_reservation(store: &UpgradeStore, reservation: &Option<TrialState>) {
    if reservation.is_some()
        && let Err(e) = store.mark_trial_failed()
    {
        eprintln!("boreas-supervisor: warning: could not settle an unused trial reservation: {e}");
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

/// Run the planned child and close the journal transaction according to its
/// real outcome. Returns this process's exit code.
///
/// Two quite different contracts apply:
///
/// * **steady launch** — the pointer is not ours to change; spawn, wait and
///   propagate the child's status.
/// * **trial launch** — the upgrade is committed only once the candidate has
///   proved it stays alive for the configured soak. Exiting 0 earlier is *not*
///   *not* readiness: it is recorded as a failed attempt and rolled back. Once the soak
///   deadline passes, `confirm()` is written while the child is still running,
///   so a later crash is an ordinary runtime stop instead of a silent upgrade
///   failure.
///
/// Never panics, and every failure path keeps the store consistent: trial
/// candidates are rolled back and their attempt is already durable, never left
/// silently `Activated` — and even if a rollback itself fails, the `Activated`
/// journal makes the *next* supervisor invocation roll back before launching.
fn execute_supervise(plan: SupervisePlan) -> u8 {
    // Hold the exclusive store lock for the entire child lifetime: it is
    // dropped only when this function returns.
    let _store_lock = plan.store_lock;
    let _store = match UpgradeStore::open(&plan.store_root) {
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
    if plan.trial_candidate.is_some() {
        #[cfg(unix)]
        {
            let trial = TrialPlan {
                socket: PathBuf::from(&plan.store_root).join("ready.sock"),
                ready_timeout: plan.ready_timeout,
                stop_grace: plan.stop_grace,
                policy: readiness::ReadinessPolicy {
                    expected_schema: plan.ready_expected_schema.clone(),
                    require_tun: plan.ready_require_tun,
                    min_workers: plan.ready_min_workers,
                },
            };
            return run_trial(&_store, program, rest, &trial);
        }
        #[cfg(not(unix))]
        {
            // No AF_UNIX readiness channel here: refusing is the only honest
            // option, because confirming on "process is alive" is exactly the
            // gate this round removes.
            eprintln!(
                "boreas-supervisor: error: readiness handshake is not implemented on this \
                 platform; refusing to confirm a trial on liveness alone"
            );
            return EXIT_ERROR;
        }
    }
    run_steady(program, rest)
}

/// Steady launch: the store already points at a confirmed version.
fn run_steady(program: &OsString, args: &[OsString]) -> u8 {
    match run_child_once(program, args) {
        Ok(status) => exit_code_of(status),
        Err(e) => {
            eprintln!(
                "boreas-supervisor: error: cannot run {}: {e}",
                program.to_string_lossy()
            );
            EXIT_ERROR
        }
    }
}

/// Everything one trial launch needs: the private socket, the readiness
/// deadline/policy and the stop grace.
#[cfg(unix)]
struct TrialPlan {
    socket: PathBuf,
    ready_timeout: Duration,
    stop_grace: Duration,
    policy: readiness::ReadinessPolicy,
}

/// Trial launch: readiness-gated, signal-forwarding, rollback on any failure.
///
/// The upgrade is committed **only** after the launched child connects to the
/// private socket, proves it is the process we spawned (peer credentials) and
/// answers this run's fresh challenge with an acceptable schema/worker/TUN
/// state. Being alive is not enough: the old liveness soak is gone.
#[cfg(unix)]
fn run_trial(store: &UpgradeStore, program: &OsString, args: &[OsString], plan: &TrialPlan) -> u8 {
    let listener = match readiness::bind(&plan.socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "boreas-supervisor: error: cannot bind readiness socket {}: {e}",
                plan.socket.display()
            );
            return fail_trial(store);
        }
    };
    let mut child = match spawn_child_with_env(program, args, &plan.socket) {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "boreas-supervisor: error: cannot run {}: {e}",
                program.to_string_lossy()
            );
            readiness::cleanup(&plan.socket);
            return fail_trial(store);
        }
    };
    let outcome = trial_loop(store, &mut child, &listener, plan);
    readiness::cleanup(&plan.socket);
    outcome
}

#[cfg(unix)]
fn trial_loop(
    store: &UpgradeStore,
    child: &mut Child,
    listener: &std::os::unix::net::UnixListener,
    plan: &TrialPlan,
) -> u8 {
    let deadline = Instant::now() + plan.ready_timeout;
    let mut confirmed = false;
    let mut pending_handshake = None;
    let mut stop: Option<(i32, Instant)> = None;
    loop {
        // 1. Controlled stop: forward the signal to the child. A stop that
        //    arrives before readiness means the trial never proved itself.
        if let Some(signal) = signals::take() {
            if let Some(err) = signals::forward(child.id(), signal) {
                eprintln!(
                    "boreas-supervisor: warning: cannot forward signal {signal} to the child: {err}"
                );
            }
            if confirmed {
                stop.get_or_insert((signal, Instant::now() + plan.stop_grace));
            } else {
                eprintln!("boreas-supervisor: stop signal {signal} before readiness; rolling back");
                let _ = child.kill();
                let _ = child.wait();
                return fail_trial(store);
            }
        }
        // 2. Child exit.
        match child.try_wait() {
            Ok(Some(status)) => {
                if confirmed {
                    // Already accepted: an ordinary runtime stop.
                    return exit_code_of(status);
                }
                eprintln!(
                    "boreas-supervisor: trial child exited before readiness ({}); rolling back",
                    describe_status(status)
                );
                return fail_trial(store);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("boreas-supervisor: error: cannot wait for the trial child: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return fail_trial(store);
            }
        }
        // 3. Stop grace expired: escalate.
        if let Some((signal, until)) = stop
            && Instant::now() >= until
        {
            eprintln!(
                "boreas-supervisor: child did not stop within {} ms; sending SIGKILL",
                plan.stop_grace.as_millis()
            );
            let _ = child.kill();
            let _ = child.wait();
            return if confirmed {
                signals::exit_code(signal)
            } else {
                fail_trial(store)
            };
        }
        // 4. Readiness handshake.
        if !confirmed {
            let now = Instant::now();
            if now >= deadline {
                eprintln!(
                    "boreas-supervisor: candidate did not become ready within {} ms; \
                     rolling back",
                    plan.ready_timeout.as_millis()
                );
                let _ = child.kill();
                let _ = child.wait();
                return fail_trial(store);
            }
            match readiness::probe_once(
                listener,
                child.id(),
                &plan.policy,
                &mut pending_handshake,
                deadline,
            ) {
                Ok(Some(report)) => {
                    eprintln!(
                        "boreas-supervisor: readiness accepted (schema={}, workers={}, tun={:?})",
                        report.schema, report.workers, report.tun
                    );
                    match store.confirm() {
                        Ok(()) => {
                            confirmed = true;
                            if let Err(e) = store.clear_trial() {
                                eprintln!(
                                    "boreas-supervisor: warning: upgrade confirmed, but the \
                                     trial ledger could not be cleared: {e}"
                                );
                            }
                            eprintln!(
                                "boreas-supervisor: upgrade confirmed after readiness; \
                                 previous version directory retained"
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "boreas-supervisor: error: readiness passed but confirm \
                                 failed: {e}; stopping the candidate and rolling back"
                            );
                            let _ = child.kill();
                            let _ = child.wait();
                            return fail_trial(store);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!(
                        "boreas-supervisor: readiness failed: {e}; stopping the candidate \
                         and rolling back"
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return fail_trial(store);
                }
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Record the consumed attempt durably (the reservation was written before the
/// launch) and restore the retained version.
#[cfg(unix)]
fn fail_trial(store: &UpgradeStore) -> u8 {
    if let Err(e) = store.mark_trial_failed() {
        eprintln!("boreas-supervisor: error: cannot record the failed trial attempt: {e}");
    }
    rollback_trial(store)
}

#[cfg(unix)]
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

/// Spawn one child with inherited stdio.
///
/// No new process group/console is created, deliberately: the child stays in
/// this process's group, so a group-directed stop (systemd's default
/// cgroup-wide kill, or Ctrl+C in the same terminal) reaches the child directly.
/// Stops that target only the supervisor are handled by forwarding (see
/// `signals`).
fn spawn_child(program: &OsString, args: &[OsString]) -> io::Result<Child> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

/// Spawn the trial candidate with the readiness socket exported in its
/// environment (`BOREAS_READY_SOCKET`).
#[cfg(unix)]
fn spawn_child_with_env(
    program: &OsString,
    args: &[OsString],
    socket: &std::path::Path,
) -> io::Result<Child> {
    Command::new(program)
        .args(args)
        .env(readiness::SOCKET_ENV, socket)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

fn run_child_once(program: &OsString, args: &[OsString]) -> io::Result<ExitStatus> {
    let mut child = spawn_child(program, args)?;
    child.wait()
}

#[cfg_attr(not(unix), allow(dead_code))]
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
// Tests. Pure parsing/reporting runs everywhere; store/process behaviour runs
// on the platforms with an integrated transaction backend (Linux, macOS).
// Windows keeps failing closed inside `UpgradeStore::open`, so its supervisor
// tests stay limited to the pure paths. Child processes are tiny scripts under
// a tempdir — no network, no model, no installed Boreas binary involved.
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
        assert!(stdout.contains("supervise --store <DIR>"));
        assert!(stdout.contains("-- <argv...>"));
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

    /// Start a real OS child process that terminates with `code` and does
    /// nothing else. The platform shell is only a launcher: the assertion is
    /// about a genuine `ExitStatus` returned by this operating system, never a
    /// synthesised value. `/bin/sh` is POSIX-guaranteed on Unix; `%COMSPEC%`
    /// (`cmd.exe`) is always present on Windows, so this test runs on every
    /// supported CI target instead of assuming a Unix shell exists.
    #[cfg(unix)]
    fn exit_with(code: i32) -> ExitStatus {
        let script = format!("exit {code}");
        Command::new("/bin/sh")
            .args(["-c", script.as_str()])
            .status()
            .expect("cannot launch a real /bin/sh child process")
    }

    #[cfg(windows)]
    fn exit_with(code: i32) -> ExitStatus {
        let script = format!("exit {code}");
        let shell = env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd.exe"));
        Command::new(shell)
            .args(["/C", script.as_str()])
            .status()
            .expect("cannot launch a real cmd.exe child process")
    }

    #[test]
    fn exit_code_of_matches_real_child_statuses() {
        let ok = exit_with(0);
        assert!(ok.success());
        assert_eq!(exit_code_of(ok), 0);

        let three = exit_with(3);
        assert!(!three.success());
        assert_eq!(exit_code_of(three), 3);
        assert_eq!(describe_status(three), "exit code 3");

        // A second non-trivial code proves the mapping is not a 0/1 special
        // case (cmd.exe relabels some failures as 1, so keep 42 off that path).
        assert_eq!(exit_code_of(exit_with(42)), 42);

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
        #[cfg(windows)]
        {
            // Windows has no POSIX signal disposition to report: a terminated
            // process carries an exit code, so `terminating_signal` must never
            // invent one and `describe_status` must stay on the code branch.
            assert_eq!(terminating_signal(three), None);
            assert_eq!(describe_status(three), "exit code 3");
        }
    }
}

/// End-to-end `supervise`/`recover`/`status` coverage. Gated to the platforms
/// whose transaction backend is integrated today (Linux, macOS): Windows still
/// fails closed in `UpgradeStore::open`, so only the pure parsing/reporting
/// tests run there.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod unix_tests {
    use super::*;
    use boreas_supervisor::{Candidate, UpgradeError};
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn short_test_dir() -> PathBuf {
        use std::io::Read;

        let base = Path::new("/tmp").canonicalize().expect("canonical /tmp");
        let uid = unsafe { libc::geteuid() };
        for _ in 0..32 {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let mut random = [0u8; 8];
            fs::File::open("/dev/urandom")
                .and_then(|mut source| source.read_exact(&mut random))
                .expect("read fixture randomness");
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = base.join(format!("bs-{}-{seq}-{suffix}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&root) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&root).expect("fixture metadata");
                    assert!(
                        metadata.file_type().is_dir(),
                        "fixture root must be a directory"
                    );
                    assert_eq!(
                        metadata.uid(),
                        uid,
                        "fixture root must be owned by this user"
                    );
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .expect("restrict fixture root permissions");
                    return root.canonicalize().expect("canonical fixture root");
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create short fixture root: {error}"),
            }
        }
        panic!("could not allocate unique short fixture root")
    }

    struct Fixture {
        root: PathBuf,
        store_dir: PathBuf,
        src_dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = short_test_dir();
            fs::create_dir(root.join("store")).unwrap();
            fs::create_dir(root.join("src")).unwrap();
            let store_dir = root.join("store");
            let src_dir = root.join("src");
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
        supervise_with(f, child, 250, DEFAULT_MAX_TRIAL_ATTEMPTS)
    }

    /// Same, with an explicit readiness timeout and trial budget.
    fn supervise_with(
        f: &Fixture,
        child: &[&str],
        ready_timeout_ms: u64,
        max_attempts: u32,
    ) -> (u8, Vec<String>) {
        let mut args = vec![
            os("supervise"),
            os("--store"),
            os(&f.store_str()),
            os("--ready-timeout-ms"),
            os(&ready_timeout_ms.to_string()),
            os("--ready-expected-schema"),
            os("state-v1"),
            os("--max-trial-attempts"),
            os(&max_attempts.to_string()),
            os("--"),
        ];
        args.extend(child.iter().map(|c| os(c)));
        match run_cli(&args) {
            CliOutcome::RunChild { plan, notes } => (execute_supervise(*plan), notes),
            CliOutcome::Done {
                code,
                stdout,
                stderr,
            } => {
                panic!("supervise planning failed: code={code} stdout={stdout:?} stderr={stderr:?}")
            }
        }
    }

    /// Planning-only variant: never spawns, so refusals can be asserted.
    fn supervise_plan(
        f: &Fixture,
        child: &[&str],
        ready_timeout_ms: u64,
        max: u32,
    ) -> (u8, String) {
        let mut args = vec![
            os("supervise"),
            os("--store"),
            os(&f.store_str()),
            os("--ready-timeout-ms"),
            os(&ready_timeout_ms.to_string()),
            os("--ready-expected-schema"),
            os("state-v1"),
            os("--max-trial-attempts"),
            os(&max.to_string()),
            os("--"),
        ];
        args.extend(child.iter().map(|c| os(c)));
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => (code, stderr),
            CliOutcome::RunChild { .. } => (0, "unexpected launch".to_string()),
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

    /// `reset-trial --store <dir> --confirm <version>` (the only accepted form).
    fn reset_trial(f: &Fixture, confirm: &str) -> (u8, String, String) {
        let args = vec![
            os("reset-trial"),
            os("--store"),
            os(&f.store_str()),
            os("--confirm"),
            os(confirm),
        ];
        match run_cli(&args) {
            CliOutcome::Done {
                code,
                stdout,
                stderr,
            } => (code, stdout, stderr),
            CliOutcome::RunChild { .. } => panic!("reset-trial must not run a child"),
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
            r#"{"journal":null,"active_version":null,"pointer_ok":true,"stored_versions":0,"trial":null}"#
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
                .any(|n| n.contains("trial launch 1/3 of candidate 2.0.0")),
            "{notes:?}"
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
    fn trial_zero_exit_without_readiness_is_not_confirmed() {
        // The hole this gate closes: a candidate that exits 0 immediately (bad
        // config, no-op build, operator stop) must never be confirmed just
        // because its status was 0. Readiness is the only confirmation path.
        let f = Fixture::new();
        let old_dir = f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 0");
        let store = f.store();
        store
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, _) = supervise_with(&f, &["{version}/prog.sh"], 5_000, 3);
        assert_eq!(code, EXIT_ERROR, "a clean exit is not readiness");
        assert_eq!(
            store.active_version().unwrap().as_deref(),
            Some("1.0.0"),
            "pointer must be rolled back"
        );
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
        assert!(old_dir.join("prog.sh").is_file(), "old dir retained");
        let trial = store.trial_state().unwrap().unwrap();
        assert_eq!(trial.version, "2.0.0");
        assert_eq!(trial.attempts, 1);
        assert!(
            !trial.in_flight,
            "outcome must be recorded, not left pending"
        );
    }

    #[test]
    fn candidate_that_stays_alive_without_answering_readiness_is_rolled_back() {
        // Alive is not ready: a child that never connects must time out and be
        // rolled back, even though it is perfectly healthy process-wise.
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exec sleep 30");
        let store = f.store();
        store
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let started = Instant::now();
        let (code, _) = supervise_with(&f, &["{version}/prog.sh"], 200, 3);
        assert_eq!(code, EXIT_ERROR, "liveness must not confirm");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the readiness timeout must bound the wait"
        );
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
        assert_eq!(store.trial_state().unwrap().unwrap().attempts, 1);
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
    fn failed_trial_is_bounded_by_the_durable_budget() {
        // After a failed trial the journal returns to `Prepared`, which is
        // indistinguishable from "never launched" by journal alone. The
        // durable trial ledger is what stops the restart loop: three attempts
        // are allowed, the fourth is refused without activating anything.
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let cand_marker = f.marker("cand-ran");
        let art = f.artifact(
            "cand",
            &format!("echo run >> {}; exit 3", cand_marker.display()),
        );
        let store = f.store();
        store
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        for attempt in 1..=3 {
            let (code, _) = supervise_with(&f, &["{version}/prog.sh"], 100, 3);
            assert_eq!(code, EXIT_ERROR, "attempt {attempt}");
            assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));
            assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
            assert_eq!(store.trial_state().unwrap().unwrap().attempts, attempt);
        }
        let runs_before = fs::read_to_string(&cand_marker).unwrap().lines().count();
        assert_eq!(runs_before, 3);

        // Fourth attempt: refused during planning, nothing is activated or
        // launched, and the operator is pointed at `reset-trial`.
        let (code, stderr) = supervise_plan(&f, &["{version}/prog.sh"], 100, 3);
        assert_eq!(code, EXIT_ERROR);
        assert!(stderr.contains("trial budget"), "{stderr}");
        assert!(stderr.contains("reset-trial"), "{stderr}");
        assert_eq!(
            fs::read_to_string(&cand_marker).unwrap().lines().count(),
            3,
            "a refused candidate must not run"
        );
        assert_eq!(store.journal().unwrap().unwrap().phase, Phase::Prepared);
        assert_eq!(store.active_version().unwrap().as_deref(), Some("1.0.0"));

        // Operator acknowledgement must name the exact recorded candidate; a
        // wrong confirmation leaves the ledger untouched.
        let (code, _, stderr) = reset_trial(&f, "9.9.9");
        assert_eq!(code, EXIT_ERROR);
        assert!(stderr.contains("does not match"), "{stderr}");
        assert_eq!(store.trial_state().unwrap().unwrap().attempts, 3);

        // Correct confirmation clears the budget and appends an audit record.
        let (code, out, _) = reset_trial(&f, "2.0.0");
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("cleared 3 attempt(s)"), "{out}");
        assert!(out.contains("trial.audit"), "{out}");
        assert_eq!(store.trial_state().unwrap(), None);
        let audit = fs::read_to_string(f.store_dir.join("trial.audit")).unwrap();
        assert!(
            audit.contains("reset-trial version=2.0.0 attempts=3"),
            "{audit}"
        );
        let (code, _) = supervise_with(&f, &["{version}/prog.sh"], 100, 3);
        assert_eq!(code, EXIT_ERROR);
        assert_eq!(store.trial_state().unwrap().unwrap().attempts, 1);
    }

    #[test]
    fn reset_trial_requires_an_explicit_confirmation() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 3");
        let store = f.store();
        store
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, EXIT_ERROR);
        assert_eq!(store.trial_state().unwrap().unwrap().attempts, 1);

        // No --confirm at all: usage error, nothing cleared.
        let args = vec![os("reset-trial"), os("--store"), os(&f.store_str())];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                assert!(stderr.contains("--confirm"), "{stderr}");
            }
            CliOutcome::RunChild { .. } => panic!("reset-trial must not run a child"),
        }
        // --json is not accepted for this command either.
        let args = vec![
            os("reset-trial"),
            os("--store"),
            os(&f.store_str()),
            os("--json"),
        ];
        match run_cli(&args) {
            CliOutcome::Done { code, stderr, .. } => {
                assert_eq!(code, EXIT_ERROR);
                assert!(stderr.contains("unexpected argument"), "{stderr}");
            }
            CliOutcome::RunChild { .. } => panic!("reset-trial must not run a child"),
        }
        assert_eq!(store.trial_state().unwrap().unwrap().attempts, 1);
    }

    // Confirm-path coverage (readiness accepted, argv passthrough, post-confirm
    // crash, signal forwarding) lives in `tests/readiness.rs`, because it needs
    // the real binary as the candidate side of the handshake. Shell scripts
    // cannot answer an AF_UNIX challenge, and a mock would not exercise the
    // protocol.

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

    // -- store lock & trial ledger reporting --------------------------------

    #[test]
    fn store_lock_is_exclusive_across_handles() {
        let f = Fixture::new();
        let store = f.store();
        let first = store.lock_exclusive().expect("first lock");
        // A second open of the same lock file is a second open file
        // description, so it conflicts exactly as another process would.
        match store.lock_exclusive() {
            Ok(_) => panic!("second lock must not be granted"),
            Err(e) => assert!(matches!(e, UpgradeError::Locked(_)), "{e}"),
        }
        drop(first);
        store
            .lock_exclusive()
            .expect("lock must be re-acquirable once dropped");
    }

    #[test]
    fn supervise_and_recover_refuse_while_the_store_is_locked() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let store = f.store();
        let held = store.lock_exclusive().expect("hold the store lock");

        let (code, stderr) = supervise_plan(&f, &["{version}/prog.sh"], 100, 3);
        assert_eq!(code, EXIT_ERROR);
        assert!(stderr.contains("locked"), "{stderr}");

        let (code, _, stderr) = store_cmd(&f, "recover", false);
        assert_eq!(code, EXIT_ERROR);
        assert!(stderr.contains("locked"), "{stderr}");

        // `status` is read-only and deliberately still available for
        // diagnosis while a supervisor holds the store.
        let (code, out, _) = store_cmd(&f, "status", false);
        assert_eq!(code, 0);
        assert!(out.contains("active: 1.0.0"), "{out}");

        drop(held);
        let (code, _) = supervise(&f, &["{version}/prog.sh"]);
        assert_eq!(code, 0);
    }

    #[test]
    fn status_reports_durable_trial_state() {
        let f = Fixture::new();
        f.seed_active("1.0.0", "exit 0");
        let art = f.artifact("cand", "exit 3");
        let store = f.store();
        store
            .prepare(
                &Candidate {
                    version: "2.0.0".into(),
                },
                &art,
            )
            .unwrap();
        let (code, _) = supervise_with(&f, &["{version}/prog.sh"], 100, 3);
        assert_eq!(code, EXIT_ERROR);

        let (code, out, _) = store_cmd(&f, "status", false);
        assert_eq!(code, 0);
        assert!(
            out.contains("trial: version=2.0.0 attempts=1 in_flight=false"),
            "{out}"
        );
        let (code, out, _) = store_cmd(&f, "status", true);
        assert_eq!(code, 0);
        assert!(
            out.contains(r#""trial":{"version":"2.0.0","attempts":1,"in_flight":false}"#),
            "{out}"
        );
    }
}
