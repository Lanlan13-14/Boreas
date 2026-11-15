#![cfg(unix)]

//! End-to-end readiness and controlled-stop tests.
//!
//! These run the **real** `boreas-supervisor` binary supervising the **real**
//! `__ready-stub` candidate (the same binary in its hidden test-support mode),
//! so `AF_UNIX`, peer credentials, the fresh challenge/response and signal
//! forwarding are exercised as actual processes. Nothing is mocked.
//!
//! They are integration tests rather than unit tests because the candidate side
//! needs a program that speaks the protocol; the library's own unit tests cover
//! the pure parsing/policy halves.

use boreas_supervisor::{Candidate, Phase, UpgradeStore};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
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
                assert!(metadata.file_type().is_dir(), "fixture root must be a directory");
                assert_eq!(metadata.uid(), uid, "fixture root must be owned by this user");
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
        let mut cmd = Command::new(BIN);
        cmd.arg("supervise")
            .arg("--store")
            .arg(self.store_path())
            .arg("--ready-timeout-ms")
            .arg("5000")
            .arg("--ready-expected-schema")
            .arg(expected_schema)
            .arg("--max-trial-attempts")
            .arg("3")
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
