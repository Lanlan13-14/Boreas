#![cfg(unix)]

//! End-to-end readiness and controlled-stop tests.
//!
//! These run the **real** `boreas-supervisor` binary supervising real
//! candidates (`__ready-stub` for the handshake tests and `/bin/sh` for the
//! crash/failure paths), so `AF_UNIX`, peer credentials, the fresh
//! challenge/response and signal forwarding are exercised as actual processes.
//! Nothing is mocked.
//!
//! They are integration tests rather than unit tests because the candidate side
//! needs a program that speaks the protocol; the library's own unit tests cover
//! the pure parsing/policy halves.

use boreas_supervisor::{Candidate, Phase, UpgradeStore};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_boreas-supervisor");

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn short_test_dir(prefix: &str) -> PathBuf {
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
        let root = base.join(format!("{prefix}-{}-{seq}-{suffix}", std::process::id()));
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
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("cannot create short fixture root: {error}"),
        }
    }
    panic!("could not allocate unique short fixture root")
}

struct Fixture {
    root: PathBuf,
    store: UpgradeStore,
}

impl Fixture {
    fn new() -> Self {
        let root = short_test_dir("br");
        fs::create_dir(root.join("store")).unwrap();
        fs::create_dir(root.join("artifact")).unwrap();
        let store = UpgradeStore::open(root.join("store")).unwrap();
        // Retained old version, so a failed trial has something to roll back to.
        fs::create_dir(store.version_dir("1.0.0").unwrap()).unwrap();
        fs::write(root.join("store").join("active.version"), "1.0.0\n").unwrap();
        Self { root, store }
    }

    fn store_path(&self) -> PathBuf {
        self.root.join("store")
    }

    fn prepare(&self, version: &str) {
        self.store
            .prepare(
                &Candidate {
                    version: version.to_owned(),
                },
                self.root.join("artifact"),
            )
            .unwrap();
    }

    fn supervise(&self) -> Command {
        self.supervise_with_schema("state-v1")
    }

    fn supervise_with_schema(&self, expected_schema: &str) -> Command {
        let mut cmd = self.supervise_with(5000, 3);
        cmd.arg("--ready-expected-schema")
            .arg(expected_schema)
            .arg("--");
        cmd
    }

    /// Same launch path with an explicit readiness timeout and trial budget.
    /// Callers append the `--` separator and the child argv afterwards.
    fn supervise_with(&self, ready_timeout_ms: u64, max_trial_attempts: u32) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("supervise")
            .arg("--store")
            .arg(self.store_path())
            .arg("--ready-timeout-ms")
            .arg(ready_timeout_ms.to_string())
            .arg("--max-trial-attempts")
            .arg(max_trial_attempts.to_string());
        cmd
    }

    fn supervise_with_timeout(&self, ready_timeout_ms: u64, max_trial_attempts: u32) -> Command {
        let mut cmd = self.supervise_with(ready_timeout_ms, max_trial_attempts);
        cmd.arg("--ready-expected-schema")
            .arg("state-v1")
            .arg("--");
        cmd
    }

    fn wait_for_confirmation(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(journal)) = self.store.journal()
                && journal.phase == Phase::Confirmed
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "candidate never produced a confirmed upgrade"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Wait until `path` exists, failing instead of hanging. Used to observe a
/// real candidate process rather than infer it from journal state.
fn wait_for_path(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} was not created before the deadline",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Kills a process group created by the test on drop. This is the cleanup path
/// for a failed assertion after the supervisor was SIGKILLed: without it the
/// supervisor's candidate would outlive the test.
struct ProcessGroupGuard(i32);

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        // SAFETY: `-self.0` is a negative pid, i.e. the process group the test
        // created with `process_group(0)`; the test process is not a member.
        let _ = unsafe { libc::kill(-self.0, libc::SIGKILL) };
    }
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn kill_term(child: &Child) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill(1) must be available");
    assert!(status.success(), "kill -TERM failed");
}

/// The candidate answers the challenge and the upgrade is committed while it is
/// still running; the retained old version stays on disk.
#[test]
fn readiness_answer_confirms_the_trial_and_retains_old_version() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    let output = f
        .supervise()
        .arg(BIN)
        .arg("__ready-stub")
        .arg("--workers")
        .arg("2")
        .arg("--tun")
        .arg("ready")
        .arg("--exit-after-ms")
        .arg("250")
        .output()
        .expect("spawn supervisor");

    let err = stderr(&output);
    assert!(
        output.status.success(),
        "supervisor failed: status={:?} stderr={err}",
        output.status
    );
    assert!(
        err.contains("readiness accepted"),
        "the answer must come from the readiness handshake, not liveness: {err}"
    );
    assert_eq!(f.store.active_version().unwrap().as_deref(), Some("2.0.0"));
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Confirmed);
    assert_eq!(f.store.trial_state().unwrap(), None);
    assert!(
        f.store.version_dir("1.0.0").unwrap().is_dir(),
        "old version directory must be retained"
    );
}

/// A protocol-valid answer with the wrong state schema must roll back rather than
/// silently accepting a schema the target release did not authorize.
#[test]
fn unexpected_schema_is_refused_and_rolled_back() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    let output = f
        .supervise_with_schema("state-v1")
        .arg(BIN)
        .arg("__ready-stub")
        .arg("--schema")
        .arg("state-v2")
        .arg("--exit-after-ms")
        .arg("2500")
        .output()
        .expect("spawn supervisor");

    assert_eq!(
        output.status.code(),
        Some(1),
        "schema refusal must exit non-zero: {}",
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(err.contains("schema"), "{err}");
    assert_eq!(
        f.store.active_version().unwrap().as_deref(),
        Some("1.0.0"),
        "pointer must be rolled back"
    );
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Prepared);
    assert_eq!(f.store.trial_state().unwrap().unwrap().attempts, 1);
}

/// A protocol-valid answer that fails the deployment policy (no TUN when one is
/// required) must roll back rather than confirm.
#[test]
fn tun_absent_is_refused_by_policy_and_rolled_back() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    let output = f
        .supervise()
        .arg(BIN)
        .arg("__ready-stub")
        .arg("--tun")
        .arg("absent")
        .arg("--exit-after-ms")
        .arg("2500")
        .output()
        .expect("spawn supervisor");

    assert_eq!(
        output.status.code(),
        Some(1),
        "policy refusal must exit non-zero: {}",
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("not ready") || err.contains("readiness failed"),
        "{err}"
    );
    assert_eq!(
        f.store.active_version().unwrap().as_deref(),
        Some("1.0.0"),
        "pointer must be rolled back"
    );
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Prepared);
    assert_eq!(
        f.store.trial_state().unwrap().unwrap().attempts,
        1,
        "the refused launch still consumes a durable attempt"
    );
}

/// A stop targeted at the supervisor alone reaches the child: the supervisor
/// forwards `SIGTERM`, the child dies, and the exit status is `128+15`.
#[test]
fn sigterm_is_forwarded_to_the_confirmed_child() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    let mut supervisor = f
        .supervise()
        .arg(BIN)
        .arg("__ready-stub")
        .arg("--exit-after-ms")
        .arg("60000")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");

    f.wait_for_confirmation(Duration::from_secs(10));
    kill_term(&supervisor);

    // Bounded wait: a hung supervisor must fail the test, not hang CI.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match supervisor.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = supervisor.kill();
                panic!("supervisor did not exit after the forwarded SIGTERM");
            }
        }
    };
    assert_eq!(
        status.code(),
        Some(143),
        "child was stopped by the forwarded SIGTERM (128+15)"
    );
    // The upgrade had already been committed before the stop.
    assert_eq!(f.store.active_version().unwrap().as_deref(), Some("2.0.0"));
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Confirmed);
}

/// SIGKILL the supervisor while the trial is activated but not yet confirmed.
///
/// This is the crash the journal exists for: the killed process must not be
/// able to report success, its durable reservation must keep the attempt
/// consumed, and the *next* real supervisor invocation must recover before
/// launching anything. A pass here is negative evidence about the killed run
/// (no `Confirmed`) plus positive evidence about recovery (old version is
/// active again), not proof that the whole daemon is durable.
///
/// The candidate is real and is observed via a "started" file. Because the
/// supervisor is SIGKILLed it cannot reap the candidate, so the test kills the
/// supervisor's process group (and a drop guard repeats that on failure); no
/// orphan may survive the test.
#[test]
fn sigkill_mid_trial_is_not_confirmed_and_next_boot_recovers_old_version() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    // The candidate reports that it started, then never answers readiness. It
    // is a real process, not a mock.
    let started = f.root.join("candidate-started");
    let script = f.root.join("hold.sh");
    fs::write(&script, "#!/bin/sh\n: > \"$1\"\nexec sleep 600\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

    let mut supervisor = f
        .supervise_with_timeout(60_000, 3)
        .arg("/bin/sh")
        .arg(&script)
        .arg(&started)
        // A separate process group lets the test kill the candidate after its
        // supervisor has been SIGKILLed and therefore cannot reap it.
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");
    let pgid = i32::try_from(supervisor.id()).expect("supervisor pid fits in i32");
    // Also cleans up if an assertion below panics.
    let _group = ProcessGroupGuard(pgid);

    wait_for_path(&started, Duration::from_secs(15));
    assert_eq!(
        f.store.active_version().unwrap().as_deref(),
        Some("2.0.0"),
        "the pointer must already name the candidate when the journal is Activated"
    );
    assert_eq!(
        f.store.journal().unwrap().unwrap().phase,
        Phase::Activated,
        "the candidate can only start after the Activated journal is written"
    );
    let trial = f.store.trial_state().unwrap().expect("durable reservation");
    assert_eq!(trial.attempts, 1);
    assert!(trial.in_flight, "the reservation must precede the launch");

    supervisor.kill().expect("SIGKILL the supervisor");
    let status = supervisor.wait().expect("reap the killed supervisor");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the test must kill the supervisor, not let it exit normally"
    );

    // The killed supervisor cannot reap the candidate. Kill the whole process
    // group so the real candidate cannot outlive the test; ESRCH is the only
    // acceptable failure because it proves there is no member left to kill.
    if unsafe { libc::kill(-pgid, libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ESRCH),
            "kill candidate process group: {error}"
        );
    }

    // The killed process left the transaction unconfirmed. Nothing may claim
    // the upgrade succeeded, and the attempt must still be visible on disk.
    assert_eq!(
        f.store.journal().unwrap().unwrap().phase,
        Phase::Activated,
        "SIGKILL must leave the unconfirmed journal for recovery"
    );
    assert_eq!(f.store.active_version().unwrap().as_deref(), Some("2.0.0"));
    let trial = f.store.trial_state().unwrap().expect("surviving reservation");
    assert_eq!(trial.attempts, 1);
    assert!(trial.in_flight);

    // The store lock died with the supervisor, so a second real invocation
    // must recover first: roll back, count the attempt as failed, and run the
    // old version instead of retrying the unconfirmed candidate.
    let output = f
        .supervise_with_timeout(5_000, 3)
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .output()
        .expect("spawn the recovery supervisor");
    let err = stderr(&output);
    assert!(
        output.status.success(),
        "recovery supervisor failed: status={:?} stderr={err}",
        output.status
    );
    assert!(
        err.contains("rolled back before launch"),
        "next boot must roll back before launching: {err}"
    );
    assert_eq!(
        f.store.active_version().unwrap().as_deref(),
        Some("1.0.0"),
        "recovery must restore the retained old version"
    );
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Prepared);
    let trial = f.store.trial_state().unwrap().expect("trial ledger");
    assert_eq!(trial.attempts, 1, "recovery must not invent or drop attempts");
    assert!(!trial.in_flight, "the recovered attempt is recorded as failed");
    assert!(
        f.store.version_dir("1.0.0").unwrap().is_dir(),
        "rollback must retain the old version directory"
    );
    println!(
        "BOREAS_SUPERVISOR_RECOVERY_EVIDENCE case=sigkill_mid_trial \
         journal=activated->prepared attempts=1 active=1.0.0 verdict=rolled_back"
    );
}

/// A candidate that exits before readiness is a failed trial, not a successful
/// upgrade: the journal rolls back, the durable attempt is consumed, and the
/// retained old version is still the active pointer.
#[test]
fn early_candidate_exit_before_readiness_rolls_back_and_consumes_attempt() {
    let f = Fixture::new();
    f.prepare("2.0.0");

    let output = f
        .supervise()
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 7")
        .output()
        .expect("spawn supervisor");

    let err = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an early crash must fail the supervisor: {err}"
    );
    assert!(
        err.contains("exited before readiness"),
        "the supervisor must diagnose the early exit: {err}"
    );
    assert_eq!(
        f.store.active_version().unwrap().as_deref(),
        Some("1.0.0"),
        "the early crash must not leave the candidate active"
    );
    assert_eq!(f.store.journal().unwrap().unwrap().phase, Phase::Prepared);
    let trial = f.store.trial_state().unwrap().expect("trial ledger");
    assert_eq!(trial.attempts, 1);
    assert!(!trial.in_flight);
    assert!(
        f.store.version_dir("1.0.0").unwrap().is_dir(),
        "the retained old version must survive the failed trial"
    );
    println!(
        "BOREAS_SUPERVISOR_RECOVERY_EVIDENCE case=early_exit_before_readiness \
         journal=prepared attempts=1 active=1.0.0 verdict=rolled_back"
    );
}
