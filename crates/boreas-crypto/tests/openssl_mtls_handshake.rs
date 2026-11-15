//! Real Rust<->Rust (and OpenSSL-CLI<->Rust) inner-TLS 1.3 mTLS integration
//! tests for the strict pq768 OpenSSL backend.
//!
//! What this proves, against the Boreas master plan (BOREAS-MASTER-PLAN
//! v1.11.0, section 4.2), with an ephemeral ML-DSA-65 PKI generated at test
//! runtime by the OpenSSL 3.6.1 CLI:
//!
//! * both Boreas endpoints (`OpenSslConnector` / `OpenSslAcceptor`) complete
//!   a real, mutually authenticated TLS 1.3 handshake over a byte stream
//!   (`UnixStream::pair`, run concurrently);
//! * each end reads the *verified* peer leaf certificate and it is
//!   byte-identical (DER) to the certificate the peer was issued;
//! * the negotiated parameters each end reports pass
//!   `Policy::validate_negotiated` for the production pq768 policy, with the
//!   negotiated AEAD always in {`TLS_AES_256_GCM_SHA384`,
//!   `TLS_CHACHA20_POLY1305_SHA256`}, `resumed == false` and
//!   `zero_rtt == false`;
//! * application plaintext (small ping/pong plus a 32 KiB blob) round-trips
//!   intact in both directions;
//! * the same strict handshake also runs in one process through the in-memory
//!   `WsByteStream` payload queue adapter and the non-blocking
//!   `HandshakeDriver`, with deterministic split/coalesced ciphertext chunks
//!   and explicit queue backpressure, then carries the same ping/pong and
//!   32 KiB plaintext payloads. This exercises the byte-queue boundary only;
//!   it is **not** an HTTP Upgrade, RFC 6455 framing, outer HTTPS, or WSS
//!   transport test;
//! * failure is closed: wrong trust anchor on either side, an expired
//!   client certificate, a missing client certificate, a classical-only
//!   key-exchange offer, a disallowed AEAD-only offer, a TLS 1.2-only
//!   client, a malformed/truncated ciphertext stream and a classical (RSA)
//!   client certificate are all rejected; pq1024 / wrong-key-type /
//!   mismatched local identities are rejected at construction time. Where
//!   only the server can detect the fault, TLS 1.3's 1-RTT shape means the
//!   client's local handshake legitimately completes first (`ClientView`
//!   below documents this per case); the rejecting side always fails
//!   promptly, and a connector-side handshake alone is not authorization.
//!
//! Honest limits (do not over-claim):
//!
//! * rust-openssl 0.10.82 exposes no safe negotiated-group getter
//!   (`SSL_get_negotiated_group`) and no peer-signature-scheme getter, so the
//!   Rust side does *not* directly read wire code points `0x11EC`
//!   (X25519MLKEM768) or `0x0905` (mldsa65). `HybridGroup::X25519MlKem768` /
//!   `IdentitySignature::MlDsa65` in the backend's negotiated report rest on
//!   the backend's constrained-context argument (only that group and that
//!   signature algorithm are configured, plus full verified-chain ML-DSA-65
//!   key/signature checks). The `s_client` interop test below cross-checks
//!   the group *name* and `Signature type: mldsa65` as printed by the
//!   OpenSSL CLI, which does read the negotiated values -- but that is the
//!   same OpenSSL codebase, not an independent implementation. True
//!   second-implementation interop (e.g. GnuTLS or Go, per
//!   `docs/research/phase0-tls-backend-interop-2026-11-15.md`) remains
//!   mainline Phase-0 G-CRYPTO work, as does direct FFI group/sigalg
//!   readout if the reviewer requires it.
//! * `resumed == false` is asserted from the backend's
//!   `SSL_session_reused` readout after each real handshake; the public API
//!   deliberately exposes no resumption surface, so an *attempted*
//!   resumption cannot be exercised from outside the backend.
//! * Rust<->Rust handshakes always exercise the first mutually preferred
//!   AEAD because the Boreas API fixes the suite list on both ends; the
//!   ChaCha20-Poly1305 suite is therefore proven against the Boreas
//!   acceptor by constraining `s_client` to that single suite (and both
//!   suites are covered by `tools/crypto-poc/run-openssl-mtls.sh`).
//! * `WsByteStream` is the ordered payload bridge only. It does not parse
//!   HTTP Upgrade, RFC 6455 frames, control frames, close handshakes,
//!   fragmentation flags, or compression; rejecting text/compressed frames
//!   and driving the real WebSocket state machine remain Phase 1 work. The
//!   in-memory pair test proves TLS can run over arbitrary binary chunking,
//!   not that a production WSS transport has been integrated.
//!
//! Test-material discipline: all keys/certificates are generated per test
//! into a unique `std::env::temp_dir()` subdirectory (mode 0700 on Unix)
//! and removed on drop. No private-key material is committed to the repo
//! and none is ever printed; subprocess output shown in assertions is
//! sanitized line-by-line. `OPENSSL_CONF` for every CLI subprocess is an
//! explicitly generated minimal config activating only OpenSSL's built-in
//! default provider, because `install_sw` does not install `ssl/openssl.cnf`
//! (mirrors `tools/crypto-poc/run-openssl-mtls.sh`). CI may additionally
//! export the same minimal config as `OPENSSL_CONF` for the whole test
//! process so the linked library also loads providers deterministically.
//!
//! Binary resolution: `BOREAS_OPENSSL_BIN` wins if set (and then any
//! capability failure is a hard test failure); otherwise
//! `/tmp/ossl/install/bin/openssl` and then `openssl` on `PATH` are probed
//! for X25519MLKEM768 + ML-DSA-65 support. If no capable CLI exists the
//! tests skip loudly on stderr instead of failing unrelated environments;
//! CI jobs that build OpenSSL 3.6.1 must set `BOREAS_OPENSSL_BIN` so a
//! missing binary cannot silently green.

#![cfg(all(unix, feature = "openssl-backend"))]

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boreas_crypto::backend::{
    BackendError, DriveState, EstablishedStream, OpenSslAcceptor, OpenSslConnector, PemIdentity,
};
use boreas_crypto::{
    Aead, HybridGroup, IdentitySignature, NegotiatedParameters, Policy, Suite, TlsVersion,
    WsByteStream,
};

/// Minimal provider config: built-in default provider only. Copied from the
/// reviewed CLI PoC (`tools/crypto-poc/run-openssl-mtls.sh`).
const MINIMAL_CNF: &str = "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\n\n[default_sect]\nactivate = 1\n";

const STREAM_TIMEOUT: Duration = Duration::from_secs(20);
const CLI_TIMEOUT: Duration = Duration::from_secs(45);

const PING: &[u8] = b"boreas-inner-tls-ping\x00\xff";
const PONG: &[u8] = b"boreas-inner-tls-pong\x01\xfe";
const CLI_PAYLOAD: &[u8] = b"BOREAS_CLI_TO_RUST_PLAINTEXT_OK\n";
const BLOB_LEN: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Ephemeral temp directory (removed on drop, including on test panic).
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "boreas-tls-test-{tag}-{}-{unique}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create ephemeral test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Private keys live here briefly; keep the directory owner-only.
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Path as a CLI argument. Test temp paths are constructed by us under
    /// `TMPDIR`; treat non-UTF8 temp roots as a hard harness error.
    fn arg(&self, name: &str) -> String {
        self.path(name)
            .to_str()
            .expect("ephemeral test paths must be UTF-8")
            .to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Small UTC helpers for the expired-certificate case (no external crates).
// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs() as i64
}

/// Days-since-epoch -> (year, month, day). Howard Hinnant's well-known
/// `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// OpenSSL `-not_before`/`-not_after` value (`CCYYMMDDHHMMSSZ`) at a
/// whole-day offset from now.
fn asn1_time_days_from_now(days: i64) -> String {
    let secs = now_unix() + days * 86_400;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

// ---------------------------------------------------------------------------
// OpenSSL CLI plumbing (child-scoped OPENSSL_CONF; sanitized diagnostics).
// ---------------------------------------------------------------------------

fn sanitize(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("psk") || lower.contains("secret") || lower.contains("private key") {
            out.push_str("<redacted-line>\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
        if out.len() > 4096 {
            out.push_str("<truncated>\n");
            break;
        }
    }
    out
}

fn run_cli(bin: &Path, cnf: &Path, args: &[String]) -> std::io::Result<Output> {
    Command::new(bin)
        .env("OPENSSL_CONF", cnf)
        .args(args)
        .output()
}

fn run_ok(bin: &Path, cnf: &Path, args: &[String], what: &str) -> Output {
    let out =
        run_cli(bin, cnf, args).unwrap_or_else(|e| panic!("failed to spawn openssl ({what}): {e}"));
    assert!(
        out.status.success(),
        "openssl {what} failed (status {:?}): {}",
        out.status.code(),
        sanitize(&out.stderr)
    );
    out
}

/// Does this binary know X25519MLKEM768 and ML-DSA-65?
fn capable(bin: &Path, cnf: &Path) -> bool {
    let groups = ["list".to_owned(), "-tls-groups".to_owned()];
    let sigalgs = ["list".to_owned(), "-signature-algorithms".to_owned()];
    let Ok(groups_out) = run_cli(bin, cnf, &groups) else {
        return false;
    };
    let Ok(sigalgs_out) = run_cli(bin, cnf, &sigalgs) else {
        return false;
    };
    groups_out.status.success()
        && sigalgs_out.status.success()
        && String::from_utf8_lossy(&groups_out.stdout).contains("X25519MLKEM768")
        && String::from_utf8_lossy(&sigalgs_out.stdout)
            .to_ascii_lowercase()
            .contains("ml-dsa-65")
}

/// Resolve the OpenSSL CLI. `None` means "skip loudly"; an explicitly set
/// but unusable `BOREAS_OPENSSL_BIN` is a hard failure by design.
fn resolve_openssl_bin(cnf: &Path) -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("BOREAS_OPENSSL_BIN") {
        let bin = PathBuf::from(explicit);
        assert!(
            capable(&bin, cnf),
            "BOREAS_OPENSSL_BIN={} is set but is not a runnable \
             X25519MLKEM768/ML-DSA-65-capable openssl; refusing to skip",
            bin.display()
        );
        return Some(bin);
    }
    for candidate in ["/tmp/ossl/install/bin/openssl", "openssl"] {
        let bin = PathBuf::from(candidate);
        if capable(&bin, cnf) {
            return Some(bin);
        }
    }
    None
}

/// CI jobs that build the pinned OpenSSL must set this so a missing or
/// incapable CLI cannot silently turn every TLS test into a skip.
fn tls_tests_required() -> bool {
    std::env::var("BOREAS_REQUIRE_TLS_TESTS").is_ok_and(|value| value == "1")
}

// ---------------------------------------------------------------------------
// Ephemeral ML-DSA-65 PKI (plus one rogue CA and one RSA leaf for negatives).
// ---------------------------------------------------------------------------

struct TestPki {
    dir: TempDir,
    bin: PathBuf,
}

impl TestPki {
    /// Returns `None` (test skips) when no capable openssl CLI exists.
    fn create(tag: &str) -> Option<Self> {
        let dir = TempDir::new(tag);
        std::fs::write(dir.path("openssl.cnf"), MINIMAL_CNF).expect("write minimal openssl.cnf");
        let cnf = dir.path("openssl.cnf");
        let Some(bin) = resolve_openssl_bin(&cnf) else {
            assert!(
                !tls_tests_required(),
                "BOREAS_REQUIRE_TLS_TESTS=1 but no openssl CLI with X25519MLKEM768 + \
                 ML-DSA-65 support was found; refusing to skip the TLS suite"
            );
            eprintln!(
                "SKIP ({tag}): no openssl CLI with X25519MLKEM768 + ML-DSA-65 support \
                 found (looked at $BOREAS_OPENSSL_BIN, /tmp/ossl/install/bin/openssl, \
                 PATH). Build OpenSSL 3.6.1 and set BOREAS_OPENSSL_BIN to run these tests."
            );
            return None;
        };
        let pki = Self { dir, bin };
        let version = pki.run(&["version".to_owned()], "version");
        eprintln!("openssl runtime ({tag}): {}", sanitize(&version.stdout).trim());

        pki.make_ca("root", "Boreas Test ML-DSA-65 Root");
        pki.make_ca("rogue", "Rogue ML-DSA-65 Root");
        pki.make_leaf(
            "server",
            "server.boreas.invalid",
            "1001",
            "serverAuth",
            (-1, 14),
        );
        pki.make_leaf(
            "client",
            "client.boreas.invalid",
            "1002",
            "clientAuth",
            (-1, 14),
        );
        // Validity window entirely in the past: deterministic expiry.
        pki.make_leaf(
            "expired-client",
            "expired.boreas.invalid",
            "1003",
            "clientAuth",
            (-3, -1),
        );
        pki.make_rsa_leaf();
        pki.assert_ml_dsa65_material();
        Some(pki)
    }

    fn cnf(&self) -> PathBuf {
        self.dir.path("openssl.cnf")
    }

    fn run(&self, args: &[String], what: &str) -> Output {
        run_ok(&self.bin, &self.cnf(), args, what)
    }

    fn make_ca(&self, name: &str, cn: &str) {
        self.run(
            &[
                "genpkey".into(),
                "-algorithm".into(),
                "ML-DSA-65".into(),
                "-out".into(),
                self.dir.arg(&format!("{name}.key")),
            ],
            &format!("genpkey {name} CA"),
        );
        self.run(
            &[
                "req".into(),
                "-new".into(),
                "-x509".into(),
                "-key".into(),
                self.dir.arg(&format!("{name}.key")),
                "-out".into(),
                self.dir.arg(&format!("{name}.pem")),
                "-not_before".into(),
                asn1_time_days_from_now(-1),
                "-not_after".into(),
                asn1_time_days_from_now(365),
                "-subj".into(),
                format!("/CN={cn}"),
                "-addext".into(),
                "basicConstraints=critical,CA:TRUE,pathlen:0".into(),
                "-addext".into(),
                "keyUsage=critical,keyCertSign,cRLSign".into(),
            ],
            &format!("req -x509 {name} CA"),
        );
    }

    fn make_leaf(&self, name: &str, cn: &str, serial: &str, eku: &str, validity_days: (i64, i64)) {
        self.run(
            &[
                "genpkey".into(),
                "-algorithm".into(),
                "ML-DSA-65".into(),
                "-out".into(),
                self.dir.arg(&format!("{name}.key")),
            ],
            &format!("genpkey {name}"),
        );
        self.run(
            &[
                "req".into(),
                "-new".into(),
                "-key".into(),
                self.dir.arg(&format!("{name}.key")),
                "-out".into(),
                self.dir.arg(&format!("{name}.csr")),
                "-subj".into(),
                format!("/CN={cn}"),
            ],
            &format!("req {name}"),
        );
        std::fs::write(
            self.dir.path(&format!("{name}.ext")),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectAltName=DNS:{cn}\n"
            ),
        )
        .expect("write leaf extensions");
        self.run(
            &[
                "x509".into(),
                "-req".into(),
                "-in".into(),
                self.dir.arg(&format!("{name}.csr")),
                "-CA".into(),
                self.dir.arg("root.pem"),
                "-CAkey".into(),
                self.dir.arg("root.key"),
                "-set_serial".into(),
                serial.into(),
                "-not_before".into(),
                asn1_time_days_from_now(validity_days.0),
                "-not_after".into(),
                asn1_time_days_from_now(validity_days.1),
                "-extfile".into(),
                self.dir.arg(&format!("{name}.ext")),
                "-out".into(),
                self.dir.arg(&format!("{name}.pem")),
            ],
            &format!("x509 -req {name}"),
        );
    }

    /// RSA-2048 client leaf signed by an RSA CA. Its key is classical, so a
    /// Boreas endpoint must refuse it locally (and as trust anchor here).
    fn make_rsa_leaf(&self) {
        self.run(
            &[
                "genpkey".into(),
                "-algorithm".into(),
                "RSA".into(),
                "-pkeyopt".into(),
                "rsa_keygen_bits:2048".into(),
                "-out".into(),
                self.dir.arg("rsa-ca.key"),
            ],
            "genpkey RSA CA",
        );
        self.run(
            &[
                "req".into(),
                "-new".into(),
                "-x509".into(),
                "-key".into(),
                self.dir.arg("rsa-ca.key"),
                "-out".into(),
                self.dir.arg("rsa-ca.pem"),
                "-days".into(),
                "365".into(),
                "-subj".into(),
                "/CN=RSA Test CA".into(),
                "-addext".into(),
                "basicConstraints=critical,CA:TRUE,pathlen:0".into(),
                "-addext".into(),
                "keyUsage=critical,keyCertSign,cRLSign".into(),
            ],
            "req -x509 RSA CA",
        );
        self.run(
            &[
                "genpkey".into(),
                "-algorithm".into(),
                "RSA".into(),
                "-pkeyopt".into(),
                "rsa_keygen_bits:2048".into(),
                "-out".into(),
                self.dir.arg("rsa-client.key"),
            ],
            "genpkey RSA client",
        );
        self.run(
            &[
                "req".into(),
                "-new".into(),
                "-key".into(),
                self.dir.arg("rsa-client.key"),
                "-out".into(),
                self.dir.arg("rsa-client.csr"),
                "-subj".into(),
                "/CN=rsa.boreas.invalid".into(),
            ],
            "req RSA client",
        );
        std::fs::write(
            self.dir.path("rsa-client.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:rsa.boreas.invalid\n",
        )
        .expect("write RSA leaf extensions");
        self.run(
            &[
                "x509".into(),
                "-req".into(),
                "-in".into(),
                self.dir.arg("rsa-client.csr"),
                "-CA".into(),
                self.dir.arg("rsa-ca.pem"),
                "-CAkey".into(),
                self.dir.arg("rsa-ca.key"),
                "-set_serial".into(),
                "2001".into(),
                "-days".into(),
                "14".into(),
                "-extfile".into(),
                self.dir.arg("rsa-client.ext"),
                "-out".into(),
                self.dir.arg("rsa-client.pem"),
            ],
            "x509 -req RSA client",
        );
    }

    /// Every ML-DSA artifact must really be ML-DSA-65 (certificate SPKI *and*
    /// signature algorithm), the leaves must verify against the good root,
    /// and that same verification must fail against the rogue root -- so the
    /// "wrong anchor" cases below cannot pass vacuously.
    fn assert_ml_dsa65_material(&self) {
        for name in ["root", "rogue", "server", "client", "expired-client"] {
            let out = self.run(
                &[
                    "x509".into(),
                    "-in".into(),
                    self.dir.arg(&format!("{name}.pem")),
                    "-noout".into(),
                    "-text".into(),
                ],
                &format!("x509 -text {name}"),
            );
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                text.matches("ML-DSA-65").count() >= 2,
                "{name}.pem must carry ML-DSA-65 as signature algorithm and SPKI"
            );
        }
        // `-no_check_time` isolates chain/issuer correctness here; the
        // expired leaf *must* fail on time in its own handshake test below.
        for name in ["server", "client", "expired-client"] {
            self.run(
                &[
                    "verify".into(),
                    "-no_check_time".into(),
                    "-CAfile".into(),
                    self.dir.arg("root.pem"),
                    self.dir.arg(&format!("{name}.pem")),
                ],
                &format!("verify {name} against good root (chain only)"),
            );
            let rogue = run_cli(
                &self.bin,
                &self.cnf(),
                &[
                    "verify".into(),
                    "-no_check_time".into(),
                    "-CAfile".into(),
                    self.dir.arg("rogue.pem"),
                    self.dir.arg(&format!("{name}.pem")),
                ],
            )
            .expect("spawn openssl verify (rogue)");
            assert!(
                !rogue.status.success(),
                "{name}.pem unexpectedly verifies against the rogue root; \
                 wrong-anchor tests would be vacuous"
            );
        }
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.path(name)).expect("read generated PEM")
    }

    fn identity(&self, cert: &str, key: &str, ca: &str) -> PemIdentity {
        PemIdentity {
            certificate_pem: self.read(cert),
            private_key_pem: self.read(key),
            trust_anchor_pem: self.read(ca),
        }
    }

    fn server_identity(&self) -> PemIdentity {
        self.identity("server.pem", "server.key", "root.pem")
    }

    fn client_identity(&self) -> PemIdentity {
        self.identity("client.pem", "client.key", "root.pem")
    }

    /// Cert/key come from the good root but the *trust anchor* is the rogue
    /// root: this end cannot verify its peer.
    fn server_identity_rogue_anchor(&self) -> PemIdentity {
        self.identity("server.pem", "server.key", "rogue.pem")
    }

    fn client_identity_rogue_anchor(&self) -> PemIdentity {
        self.identity("client.pem", "client.key", "rogue.pem")
    }

    fn expired_client_identity(&self) -> PemIdentity {
        self.identity("expired-client.pem", "expired-client.key", "root.pem")
    }

    fn rsa_client_identity(&self) -> PemIdentity {
        self.identity("rsa-client.pem", "rsa-client.key", "rsa-ca.pem")
    }

    /// DER bytes of a generated certificate, via `X509::from_pem`.
    fn cert_der(&self, name: &str) -> Vec<u8> {
        openssl::x509::X509::from_pem(&self.read(name))
            .expect("parse generated certificate PEM")
            .to_der()
            .expect("DER-encode generated certificate")
    }
}

// ---------------------------------------------------------------------------
// Concurrent Boreas handshake over a Unix socket pair.
// ---------------------------------------------------------------------------

/// Retries `EINTR` (`io::ErrorKind::Interrupted`) inside the byte transport.
///
/// On this Android/PRoot host, signals (apparently process-management
/// related) intermittently interrupt the blocking socket I/O *inside*
/// OpenSSL's handshake, which surfaces as `SSL_ERROR_SYSCALL` /
/// `tls_retry_write_records` on both ends with certificate verification
/// still `ok` (reproduced with a raw rust-openssl harness configured like
/// `backend.rs`, ~5/720 handshakes at 24-way parallelism; the same PKI
/// material then passes hundreds of serial handshakes). Retrying the
/// interrupted syscall is the textbook `SA_RESTART` equivalent and does not
/// alter any TLS bytes, so it cannot mask a real rejection: every negative
/// case below still fails promptly with a TLS-level error, which this
/// wrapper passes through untouched.
struct InterruptionShield<S>(S);

impl<S: Read> Read for InterruptionShield<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.read(buf) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

impl<S: Write> Write for InterruptionShield<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.0.write(buf) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            match self.0.flush() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

type SideResult<S> = Result<(EstablishedStream<S>, Duration), (BackendError, Duration)>;

fn into_side<S, F>(run: F) -> SideResult<S>
where
    F: FnOnce() -> Result<EstablishedStream<S>, BackendError>,
{
    let start = Instant::now();
    match run() {
        Ok(stream) => Ok((stream, start.elapsed())),
        Err(error) => Err((error, start.elapsed())),
    }
}

fn run_mtls(
    client: &PemIdentity,
    server: &PemIdentity,
) -> (
    SideResult<InterruptionShield<UnixStream>>,
    SideResult<InterruptionShield<UnixStream>>,
) {
    let policy = Policy::production_default();
    let connector = match OpenSslConnector::from_pem_identity(client, policy) {
        Ok(connector) => connector,
        Err(error) => {
            return (
                Err((error, Duration::ZERO)),
                Err((BackendError::Handshake, Duration::ZERO)),
            );
        }
    };
    let acceptor = match OpenSslAcceptor::from_pem_identity(server, policy) {
        Ok(acceptor) => acceptor,
        Err(error) => {
            // Keep the construction error on the side that produced it so
            // the negative-case assertions cannot misread it.
            return (
                Err((BackendError::Handshake, Duration::ZERO)),
                Err((error, Duration::ZERO)),
            );
        }
    };
    run_mtls_with(&connector, &acceptor)
}

fn run_mtls_with(
    connector: &OpenSslConnector,
    acceptor: &OpenSslAcceptor,
) -> (
    SideResult<InterruptionShield<UnixStream>>,
    SideResult<InterruptionShield<UnixStream>>,
) {
    let (client_end, server_end) = UnixStream::pair().expect("UnixStream::pair");
    for stream in [&client_end, &server_end] {
        stream
            .set_read_timeout(Some(STREAM_TIMEOUT))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(STREAM_TIMEOUT))
            .expect("set write timeout");
    }
    std::thread::scope(|scope| {
        let server = scope.spawn(|| into_side(|| acceptor.accept(InterruptionShield(server_end))));
        let client_result = into_side(|| connector.connect(InterruptionShield(client_end)));
        let server_result = server.join().expect("Acceptor thread panicked");
        (client_result, server_result)
    })
}

fn make_pair(client: &PemIdentity, server: &PemIdentity) -> (OpenSslConnector, OpenSslAcceptor) {
    let policy = Policy::production_default();
    let connector =
        OpenSslConnector::from_pem_identity(client, policy).expect("connector construction");
    let acceptor =
        OpenSslAcceptor::from_pem_identity(server, policy).expect("acceptor construction");
    (connector, acceptor)
}

/// The negotiated facts each end reports must satisfy the production policy
/// *again* when checked from the test (the backend checks internally too;
/// the point is that the public report itself carries compliant values).
fn assert_strict_negotiated(negotiated: NegotiatedParameters, end: &str) {
    Policy::production_default()
        .validate_negotiated(negotiated)
        .unwrap_or_else(|e| panic!("{end}: negotiated parameters violate production policy: {e}"));
    assert_eq!(negotiated.version, TlsVersion::Tls13, "{end}: TLS version");
    assert!(
        matches!(
            negotiated.aead,
            Aead::Aes256GcmSha384 | Aead::ChaCha20Poly1305Sha256
        ),
        "{end}: AEAD {:?} is outside the two suites the plan allows",
        negotiated.aead
    );
    assert!(
        !negotiated.resumed,
        "{end}: session resumption must stay off"
    );
    assert!(!negotiated.zero_rtt, "{end}: 0-RTT must stay off");
    // Constrained-context report (single configured group/sigalg + full
    // ML-DSA-65 chain checks), NOT a direct read of wire code points
    // 0x11EC/0x0905: rust-openssl 0.10.82 has no safe getters for those.
    assert_eq!(
        negotiated.group,
        HybridGroup::X25519MlKem768,
        "{end}: hybrid group"
    );
    assert_eq!(
        negotiated.peer_signature,
        IdentitySignature::MlDsa65,
        "{end}: peer signature"
    );
}

fn write_all(stream: &mut dyn Write, bytes: &[u8], what: &str) {
    stream
        .write_all(bytes)
        .unwrap_or_else(|e| panic!("write {what} ({} B): {e}", bytes.len()));
    stream.flush().expect("flush after write");
}

fn read_exact(stream: &mut dyn Read, len: usize, what: &str) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("read {what} ({len} B): {e}"));
    buf
}

/// Deterministic non-trivial plaintext (not a constant fill, so a stuck or
/// echoing buffer cannot pass).
fn blob() -> Vec<u8> {
    (0..BLOB_LEN)
        .map(|i| ((i * 31 + (i >> 8)) % 251) as u8)
        .collect()
}

// ---------------------------------------------------------------------------
// In-memory ordered payload-queue pump (no WebSocket framing).
// ---------------------------------------------------------------------------

/// Ciphertext chunk sizes used in order.  Deliberately includes sizes smaller
/// and larger than a TLS record and is not a divisor of any handshake flight,
/// so record boundaries are crossed in both directions.
const STREAM_CHUNKS: [usize; 16] = [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];

/// Move at most `chunk` ciphertext bytes from `from`'s outbound queue into
/// `to`'s inbound queue.  Returns whether any byte moved.  This models one
/// transport write being split/coalesced at the payload-queue boundary: the
/// receiver may accept only part of it, and the remainder stays queued by the
/// caller's transport.
fn pump_stream(from: &mut WsByteStream, to: &mut WsByteStream, chunk: usize) -> bool {
    let room = to.capacity().saturating_sub(to.inbound_len());
    if room == 0 {
        return false;
    }
    let mut buf = [0u8; 1024];
    let limit = chunk.min(buf.len()).min(room);
    let drained = from.drain_ciphertext(&mut buf[..limit]);
    if drained == 0 {
        return false;
    }
    let mut fed = 0;
    while fed < drained {
        match to.feed_ciphertext(&buf[fed..drained]) {
            Ok(0) => break,
            Ok(accepted) => fed += accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("inbound ciphertext queue rejected bytes: {error}"),
        }
    }
    // `room` was computed before draining; a shortfall would mean ciphertext
    // was silently dropped, which this harness must never permit.
    assert_eq!(fed, drained, "inbound queue accepted less than its checked room");
    true
}

fn stream_write_all(
    from: &mut EstablishedStream<WsByteStream>,
    to: &mut EstablishedStream<WsByteStream>,
    bytes: &[u8],
    chunk: usize,
) {
    let mut written = 0;
    while written < bytes.len() {
        // On WouldBlock, `written` intentionally does not advance: the next
        // call retries the exact same slice, which is required by SSL_write.
        match from.write_plaintext(&bytes[written..]) {
            Ok(0) => panic!("TLS write returned Ok(0) before all plaintext was written"),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("TLS write failed after {written} bytes: {error}"),
        }
        let _ = pump_stream(from.get_mut(), to.get_mut(), chunk);
    }
}

fn stream_read_exact(
    from: &mut EstablishedStream<WsByteStream>,
    to: &mut EstablishedStream<WsByteStream>,
    len: usize,
    chunk: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut read = 0;
    let mut idle = 0;
    while read < len {
        match from.read_plaintext(&mut out[read..]) {
            Ok(0) => panic!("unexpected TLS EOF after {read} of {len} plaintext bytes"),
            Ok(count) => {
                read += count;
                idle = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let _ = pump_stream(to.get_mut(), from.get_mut(), chunk);
                idle += 1;
                assert!(idle < 100_000, "TLS plaintext read stalled after {read} bytes");
            }
            Err(error) => panic!("TLS read failed after {read} bytes: {error}"),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Happy path: real mutual handshake, peer-certificate identity, strict
/// negotiated facts, plaintext ping/pong + 32 KiB blob in both directions,
/// and -- over three consecutive handshakes on the same endpoints -- a
/// single stable AEAD always inside the two allowed suites with no
/// resumption, ever.
#[test]
fn rust_to_rust_mutual_tls13_handshake_and_plaintext_roundtrip() {
    let Some(pki) = TestPki::create("happy-path") else {
        return;
    };
    let (connector, acceptor) = make_pair(&pki.client_identity(), &pki.server_identity());

    let server_der = pki.cert_der("server.pem");
    let client_der = pki.cert_der("client.pem");
    let mut seen_aeads: BTreeSet<&'static str> = BTreeSet::new();

    for round in 1..=3_i32 {
        let (client_result, server_result) = run_mtls_with(&connector, &acceptor);
        // Report both ends on failure: in a concurrent handshake the root
        // cause usually sits on the side that is *not* unwrapped first.
        let ((mut client, client_elapsed), (mut server, server_elapsed)) = match (
            client_result,
            server_result,
        ) {
            (Ok(client_ok), Ok(server_ok)) => (client_ok, server_ok),
            (client_result, server_result) => {
                let client_msg = match &client_result {
                    Ok((_, elapsed)) => format!("Ok in {elapsed:?}"),
                    Err((error, elapsed)) => format!("{error:?} after {elapsed:?}"),
                };
                let server_msg = match &server_result {
                    Ok((_, elapsed)) => format!("Ok in {elapsed:?}"),
                    Err((error, elapsed)) => format!("{error:?} after {elapsed:?}"),
                };
                panic!(
                    "round {round}: handshake failed (connector: {client_msg}; acceptor: {server_msg})"
                );
            }
        };

        // Mutual authentication: each end holds the peer's verified leaf,
        // byte-identical to what the CA issued for that role.
        assert_eq!(
            client
                .peer_certificate()
                .to_der()
                .expect("client-side peer DER"),
            server_der,
            "round {round}: connector must see the server leaf"
        );
        assert_eq!(
            server
                .peer_certificate()
                .to_der()
                .expect("server-side peer DER"),
            client_der,
            "round {round}: acceptor must see the client leaf"
        );
        assert_ne!(
            server_der, client_der,
            "test bug: server and client certificates are identical"
        );

        assert_strict_negotiated(client.negotiated(), "connector");
        assert_strict_negotiated(server.negotiated(), "acceptor");
        assert_eq!(
            client.negotiated().aead,
            server.negotiated().aead,
            "round {round}: both ends must report the same negotiated AEAD"
        );
        seen_aeads.insert(match client.negotiated().aead {
            Aead::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Aead::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            Aead::Other => unreachable!("policy gate already rejected Aead::Other"),
        });

        // Application plaintext, both directions, exact bytes.
        write_all(&mut client, PING, "ping");
        assert_eq!(read_exact(&mut server, PING.len(), "ping"), PING);
        write_all(&mut server, PONG, "pong");
        assert_eq!(read_exact(&mut client, PONG.len(), "pong"), PONG);
        let payload = blob();
        write_all(&mut client, &payload, "32 KiB blob c->s");
        assert_eq!(
            read_exact(&mut server, payload.len(), "32 KiB blob s-side"),
            payload
        );
        write_all(&mut server, &payload, "32 KiB blob s->c");
        assert_eq!(
            read_exact(&mut client, payload.len(), "32 KiB blob c-side"),
            payload
        );

        eprintln!(
            "round {round}: handshake ok (connector {client_elapsed:?}, acceptor {server_elapsed:?}), \
             aead={:?}, ping/pong + {BLOB_LEN} B blob round-trip ok",
            client.negotiated().aead
        );
    }

    // Same endpoint pair, three fresh full handshakes: deterministic for a
    // fixed suite-preference list. A flip would mean the reported AEAD is
    // not really the negotiated one.
    assert_eq!(
        seen_aeads.len(),
        1,
        "Rust<->Rust AEAD must be stable across identical handshakes, saw {seen_aeads:?}"
    );
}

/// In-process mTLS handshake over the bounded `WsByteStream` payload queues
/// using the non-blocking handshake/plaintext APIs, deterministic fragmentation
/// and coalescing, and queue backpressure.
///
/// This is deliberately not described as a WSS test: no HTTP Upgrade, RFC 6455
/// frame parser, outer HTTPS session, network WebSocket engine, or production
/// transport is involved. It proves the TLS engine can run over an ordered,
/// bounded binary queue, which is a prerequisite for Phase 1 WSS integration.
#[test]
fn payload_queue_carries_fragmented_mtls_without_websocket_framing() {
    let Some(pki) = TestPki::create("payload-queue") else {
        return;
    };
    let (connector, acceptor) = make_pair(&pki.client_identity(), &pki.server_identity());
    let mut client = connector
        .start_connect(WsByteStream::new())
        .expect("start queue-backed connector");
    let mut server = acceptor
        .start_accept(WsByteStream::new())
        .expect("start queue-backed acceptor");

    let mut client_done = false;
    let mut server_done = false;
    let mut tick = 0usize;
    for _ in 0..100_000 {
        if !client_done {
            client_done = client
                .drive_handshake()
                .expect("queue-backed connector handshake drive")
                == DriveState::Complete;
        }
        if !server_done {
            server_done = server
                .drive_handshake()
                .expect("queue-backed acceptor handshake drive")
                == DriveState::Complete;
        }
        if client_done && server_done {
            break;
        }
        let chunk = STREAM_CHUNKS[tick % STREAM_CHUNKS.len()];
        tick += 1;
        let client_to_server = pump_stream(client.transport_mut(), server.transport_mut(), chunk);
        let server_to_client = pump_stream(server.transport_mut(), client.transport_mut(), chunk);
        assert!(
            client_to_server || server_to_client,
            "queue handshake stalled (connector done={client_done}, acceptor done={server_done})"
        );
    }
    assert!(
        client_done && server_done,
        "queue handshake did not complete (connector done={client_done}, acceptor done={server_done})"
    );

    let mut client = client.finish().expect("finish queue-backed connector");
    let mut server = server.finish().expect("finish queue-backed acceptor");
    assert_eq!(
        client.peer_certificate().to_der().expect("peer DER"),
        pki.cert_der("server.pem"),
        "queue-backed connector must see the server leaf"
    );
    assert_eq!(
        server.peer_certificate().to_der().expect("peer DER"),
        pki.cert_der("client.pem"),
        "queue-backed acceptor must see the client leaf"
    );
    assert_strict_negotiated(client.negotiated(), "queue-backed connector");
    assert_strict_negotiated(server.negotiated(), "queue-backed acceptor");

    stream_write_all(&mut client, &mut server, PING, 7);
    assert_eq!(
        stream_read_exact(&mut server, &mut client, PING.len(), 5),
        PING
    );
    stream_write_all(&mut server, &mut client, PONG, 11);
    assert_eq!(
        stream_read_exact(&mut client, &mut server, PONG.len(), 3),
        PONG
    );

    let payload = blob();
    stream_write_all(&mut client, &mut server, &payload, 13);
    assert_eq!(
        stream_read_exact(&mut server, &mut client, payload.len(), 17),
        payload,
        "32 KiB queue payload client -> server must round-trip exactly"
    );
    stream_write_all(&mut server, &mut client, &payload, 19);
    assert_eq!(
        stream_read_exact(&mut client, &mut server, payload.len(), 23),
        payload,
        "32 KiB queue payload server -> client must round-trip exactly"
    );

    eprintln!(
        "byte-stream payload queue (no WS framing): handshake ok over {} deterministic chunk sizes, plaintext + {BLOB_LEN} B blob round-trip ok",
        STREAM_CHUNKS.len()
    );
}

/// `HandshakeDriver::finish` must reject an incomplete handshake, not merely
/// one with no peer certificate yet.
#[test]
fn finish_before_completed_handshake_is_rejected() {
    let Some(pki) = TestPki::create("early-finish") else {
        return;
    };

    // Stage 0: nothing was driven or exchanged.
    {
        let (connector, acceptor) = make_pair(&pki.client_identity(), &pki.server_identity());
        let client = connector
            .start_connect(WsByteStream::new())
            .expect("start connector");
        let server = acceptor
            .start_accept(WsByteStream::new())
            .expect("start acceptor");
        assert!(
            client.finish().is_err(),
            "connector must not establish before any handshake bytes"
        );
        assert!(
            server.finish().is_err(),
            "acceptor must not establish before any handshake bytes"
        );
    }

    // Stage 1: client completed its local 1-RTT handshake, server has only
    // received part of the client's final flight. The server may already hold
    // the client certificate, but the client Finished is incomplete, so
    // `SSL_is_init_finished` must keep `finish()` closed.
    {
        let (connector, acceptor) = make_pair(&pki.client_identity(), &pki.server_identity());
        let mut client = connector
            .start_connect(WsByteStream::new())
            .expect("start connector");
        let mut server = acceptor
            .start_accept(WsByteStream::new())
            .expect("start acceptor");

        assert_eq!(
            client.drive_handshake().expect("client ClientHello"),
            DriveState::Incomplete
        );
        while client.transport().outbound_len() > 0 {
            assert!(pump_stream(client.transport_mut(), server.transport_mut(), 31));
        }
        assert_eq!(
            server.drive_handshake().expect("server flight"),
            DriveState::Incomplete
        );
        while server.transport().outbound_len() > 0 {
            assert!(pump_stream(server.transport_mut(), client.transport_mut(), 37));
        }

        let mut client_done = false;
        for _ in 0..8 {
            if client
                .drive_handshake()
                .expect("client final flight")
                == DriveState::Complete
            {
                client_done = true;
                break;
            }
        }
        assert!(
            client_done,
            "client should complete after consuming the full server flight"
        );
        assert!(
            client.transport().outbound_len() > 0,
            "completed client must have produced its Certificate/Finished flight"
        );

        // Deliver roughly half of the client's final flight. At least one
        // record is necessarily missing, so the server cannot finish.
        let before = client.transport().outbound_len();
        let stop_at = before / 2;
        while client.transport().outbound_len() > stop_at {
            let chunk = (client.transport().outbound_len() - stop_at).min(23);
            assert!(pump_stream(client.transport_mut(), server.transport_mut(), chunk));
        }
        assert_eq!(
            server.drive_handshake().expect("partial client flight"),
            DriveState::Incomplete,
            "server must not complete on a truncated client final flight"
        );

        assert!(
            client.finish().is_ok(),
            "client-side 1-RTT completion is valid and must not be confused with server completion"
        );
        assert!(
            server.finish().is_err(),
            "server must not establish while the client Finished is incomplete"
        );
    }
}

/// Which ends a negative case may legitimately leave in `Ok`.
///
/// TLS 1.3 is 1-RTT: a *client*'s handshake completes locally after its own
/// `Finished` flight, before the server has verified the client
/// certificate. When only the server can detect the fault (server trusts
/// the wrong anchor, client certificate expired), standard OpenSSL
/// semantics -- on unmodified backend code -- let `connect()` return `Ok`;
/// the rejection is then observable only as the server side erroring and
/// the client's first application-data exchange failing. This harness runs
/// only the handshake, so for those cases it requires the *acceptor* to
/// fail promptly and merely permits the connector to be `Ok`. The Boreas
/// application layer must not treat a connector-side handshake alone as
/// authorization (the master plan already requires SessionHello /
/// SessionAccept on top); see the report note this test documents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientView {
    /// The client itself can detect the fault (it verifies the server
    /// chain), so both ends must error during the handshake.
    MustFail,
    /// Only the server can detect the fault; a completed 1-RTT client
    /// handshake is the protocol-correct outcome.
    MayComplete,
}

/// Shared shape of the wire-level negatives: both supplied identities must
/// at least *construct* (locally valid material); the acceptor (and, per
/// `client_view`, the connector) must fail promptly with the backend's
/// coarse handshake/verification errors -- never a hang, never a
/// policy-mismatch error leaking through as if a handshake had completed
/// with weak parameters.
fn assert_both_fail_promptly(
    case: &str,
    client: &PemIdentity,
    server: &PemIdentity,
    client_view: ClientView,
) {
    let (client_result, server_result) = run_mtls(client, server);
    for (end, result) in [("connector", &client_result), ("acceptor", &server_result)] {
        match result {
            Ok(_) => {
                if !(end == "connector" && client_view == ClientView::MayComplete) {
                    panic!("{case}: {end} unexpectedly completed the handshake");
                }
                eprintln!(
                    "{case}: connector completed its 1-RTT handshake before the server \
                     could reject it (expected; the acceptor side is the rejecting party)"
                );
            }
            Err((error, elapsed)) => {
                assert!(
                    matches!(
                        error,
                        BackendError::Handshake
                            | BackendError::PeerCertificateVerification
                            | BackendError::WrongPeerKeyType
                            | BackendError::WrongChainSignatureAlgorithm
                    ),
                    "{case}: {end} failed with unexpected error {error:?}"
                );
                assert!(
                    *elapsed < STREAM_TIMEOUT - Duration::from_secs(2),
                    "{case}: {end} failed after {elapsed:?}; expected a prompt TLS \
                     rejection, not a stream timeout"
                );
            }
        }
    }
}

/// The connector trusts only the rogue CA: it cannot verify the server
/// chain, and the handshake must die on both ends.
#[test]
fn wrong_trust_anchor_on_client_fails_closed() {
    let Some(pki) = TestPki::create("rogue-client-anchor") else {
        return;
    };
    assert_both_fail_promptly(
        "client trusts rogue CA",
        &pki.client_identity_rogue_anchor(),
        &pki.server_identity(),
        ClientView::MustFail,
    );
}

/// The acceptor trusts only the rogue CA: it cannot verify the client
/// chain, and the handshake must die on both ends. Together with the case
/// above this covers "wrong CA / wrong trust anchor" on either side.
#[test]
fn wrong_trust_anchor_on_server_fails_closed() {
    let Some(pki) = TestPki::create("rogue-server-anchor") else {
        return;
    };
    assert_both_fail_promptly(
        "server trusts rogue CA",
        &pki.client_identity(),
        &pki.server_identity_rogue_anchor(),
        ClientView::MayComplete,
    );
}

/// An expired client certificate (validity entirely in the past) must be
/// rejected even though its chain and algorithms are otherwise perfect.
#[test]
fn expired_client_certificate_fails_closed() {
    let Some(pki) = TestPki::create("expired-client") else {
        return;
    };
    assert_both_fail_promptly(
        "expired client certificate",
        &pki.expired_client_identity(),
        &pki.server_identity(),
        ClientView::MayComplete,
    );
}

/// Malformed and truncated ciphertext must fail the acceptor promptly instead
/// of hanging or surfacing a policy-mismatch error as if a handshake completed.
#[test]
fn malformed_and_truncated_ciphertext_fail_closed_promptly() {
    let Some(pki) = TestPki::create("malformed") else {
        return;
    };
    let acceptor = OpenSslAcceptor::from_pem_identity(
        &pki.server_identity(),
        Policy::production_default(),
    )
    .expect("acceptor construction");

    // Wrong record version/length followed by EOF.
    let (mut peer, transport) = UnixStream::pair().expect("UnixStream::pair");
    peer.write_all(b"\x16\x03\x03\x00\x05hello")
        .expect("write malformed record prefix");
    peer.shutdown(Shutdown::Write).expect("shutdown write half");
    let started = Instant::now();
    match acceptor.accept(InterruptionShield(transport)) {
        Ok(_) => panic!("acceptor completed a handshake on malformed ciphertext"),
        Err(error) => assert!(
            matches!(
                error,
                BackendError::Handshake
                    | BackendError::PeerCertificateVerification
                    | BackendError::WrongPeerKeyType
                    | BackendError::WrongChainSignatureAlgorithm
            ),
            "malformed stream failed with unexpected error {error:?}"
        ),
    }
    assert!(
        started.elapsed() < STREAM_TIMEOUT - Duration::from_secs(2),
        "malformed stream rejection took {:?}; expected a prompt failure",
        started.elapsed()
    );

    // Immediate EOF before any TLS record.
    let (peer, transport) = UnixStream::pair().expect("UnixStream::pair");
    drop(peer);
    let started = Instant::now();
    match acceptor.accept(InterruptionShield(transport)) {
        Ok(_) => panic!("acceptor completed a handshake on an empty transport"),
        Err(error) => assert!(
            matches!(
                error,
                BackendError::Handshake
                    | BackendError::PeerCertificateVerification
                    | BackendError::WrongPeerKeyType
                    | BackendError::WrongChainSignatureAlgorithm
            ),
            "empty stream failed with unexpected error {error:?}"
        ),
    }
    assert!(
        started.elapsed() < STREAM_TIMEOUT - Duration::from_secs(2),
        "empty stream rejection took {:?}; expected a prompt failure",
        started.elapsed()
    );
}

/// Construction-time fail-closed checks that need a real PKI: pq1024 in any
/// shape, a classical (RSA) local certificate, a mixed ML-DSA/RSA key pair,
/// and a cert/key mismatch between two genuine ML-DSA-65 identities.
#[test]
fn backend_rejects_pq1024_classical_and_mismatched_identities() {
    let Some(pki) = TestPki::create("construction") else {
        return;
    };
    let good = pki.client_identity();

    assert!(
        matches!(
            OpenSslConnector::from_pem_identity(
                &good,
                Policy {
                    suite: Suite::Pq1024,
                    allow_pq1024: false,
                }
            ),
            Err(BackendError::Pq1024NotEnabled)
        ),
        "pq1024 (not allowed) must be Pq1024NotEnabled"
    );
    assert!(
        matches!(
            OpenSslConnector::from_pem_identity(
                &good,
                Policy {
                    suite: Suite::Pq1024,
                    allow_pq1024: true,
                }
            ),
            Err(BackendError::Pq1024NotEnabled)
        ),
        "pq1024 (explicitly allowed by caller) must still be Pq1024NotEnabled"
    );
    assert!(
        matches!(
            OpenSslAcceptor::from_pem_identity(
                &pki.server_identity(),
                Policy {
                    suite: Suite::Pq768,
                    allow_pq1024: true,
                }
            ),
            Err(BackendError::UnsupportedSuite)
        ),
        "pq768 with allow_pq1024=true must be UnsupportedSuite"
    );

    let rsa = pki.rsa_client_identity();
    assert!(
        matches!(
            OpenSslConnector::from_pem_identity(&rsa, Policy::production_default()),
            Err(BackendError::WrongLocalCertificateKey)
        ),
        "RSA local certificate must be WrongLocalCertificateKey"
    );

    let mixed = PemIdentity {
        certificate_pem: good.certificate_pem.clone(),
        private_key_pem: rsa.private_key_pem.clone(),
        trust_anchor_pem: good.trust_anchor_pem.clone(),
    };
    assert!(
        matches!(
            OpenSslConnector::from_pem_identity(&mixed, Policy::production_default()),
            Err(BackendError::WrongLocalKeyType)
        ),
        "ML-DSA-65 certificate with RSA key must be WrongLocalKeyType"
    );

    let server = pki.server_identity();
    let mismatched = PemIdentity {
        certificate_pem: good.certificate_pem.clone(),
        private_key_pem: server.private_key_pem.clone(),
        trust_anchor_pem: good.trust_anchor_pem.clone(),
    };
    assert!(
        matches!(
            OpenSslConnector::from_pem_identity(&mismatched, Policy::production_default()),
            Err(BackendError::LocalIdentityMismatch)
        ),
        "valid ML-DSA-65 cert with the other leaf's key must fail the local SPKI match check"
    );
}

/// OpenSSL CLI `s_client` against the Boreas **acceptor** over loopback TCP.
/// This is the strongest wire-level cross-check available with one codebase:
/// the CLI (which *does* read negotiated values) must print the hybrid
/// group name and `Signature type: mldsa65`, and the acceptor must keep
/// all of its strict behaviour against a peer build with different knobs.
/// It is still OpenSSL on both sides -- not the master plan's independent
/// second-implementation gate.
#[test]
fn openssl_s_client_interop_with_boreas_acceptor() {
    let Some(pki) = TestPki::create("s-client") else {
        return;
    };
    let policy = Policy::production_default();
    let acceptor =
        OpenSslAcceptor::from_pem_identity(&pki.server_identity(), policy).expect("acceptor");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");
    let client_der = pki.cert_der("client.pem");
    let (bin, cnf, dir) = (pki.bin.clone(), pki.cnf(), &pki.dir);

    std::thread::scope(|scope| {
        // --- Positive 1: AES-256-GCM only, plaintext client -> Boreas. ---
        let server = scope.spawn(|| accept_cli_once(&listener, &acceptor, CLI_PAYLOAD));
        let out = run_s_client(
            &bin,
            &cnf,
            &s_client_args(
                dir,
                addr.port(),
                "TLS_AES_256_GCM_SHA384",
                "X25519MLKEM768",
                true,
            ),
            CLI_PAYLOAD,
        );
        let transcript = transcript_of(&out);
        assert!(
            out.status.success(),
            "s_client AES-256-GCM must succeed: {}",
            sanitize(&combined(&out))
        );
        assert_line(&transcript, "Ciphersuite: TLS_AES_256_GCM_SHA384");
        assert_hybrid_group_reported(&transcript);
        assert_line_ci(&transcript, "Signature type: mldsa65");
        let negotiated = server.join().expect("acceptor thread panicked");
        assert_eq!(negotiated.aead, Aead::Aes256GcmSha384);
        assert_eq!(
            negotiated.peer_der, client_der,
            "acceptor must see the s_client leaf"
        );

        // --- Positive 2: ChaCha20-Poly1305 only (second allowed AEAD). ---
        let server = scope.spawn(|| accept_cli_once(&listener, &acceptor, CLI_PAYLOAD));
        let out = run_s_client(
            &bin,
            &cnf,
            &s_client_args(
                dir,
                addr.port(),
                "TLS_CHACHA20_POLY1305_SHA256",
                "X25519MLKEM768",
                true,
            ),
            CLI_PAYLOAD,
        );
        let transcript = transcript_of(&out);
        assert!(
            out.status.success(),
            "s_client ChaCha20-Poly1305 must succeed: {}",
            sanitize(&combined(&out))
        );
        assert_line(&transcript, "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256");
        assert_hybrid_group_reported(&transcript);
        assert_line_ci(&transcript, "Signature type: mldsa65");
        let negotiated = server.join().expect("acceptor thread panicked");
        assert_eq!(negotiated.aead, Aead::ChaCha20Poly1305Sha256);
        assert_eq!(
            negotiated.peer_der, client_der,
            "acceptor must see the s_client leaf"
        );

        // --- Negatives: the Boreas acceptor must refuse each of these. ---
        expect_cli_rejection(
            scope,
            &listener,
            &acceptor,
            &bin,
            &cnf,
            "no client certificate",
            &s_client_args(
                dir,
                addr.port(),
                "TLS_AES_256_GCM_SHA384",
                "X25519MLKEM768",
                false,
            ),
            &[
                "certificate required",
                "peer did not return a certificate",
                "no peer certificate",
                "sslv3 alert",
                "tlsv1 alert",
                "handshake failure",
            ],
        );
        expect_cli_rejection(
            scope,
            &listener,
            &acceptor,
            &bin,
            &cnf,
            "classical-only key exchange (X25519)",
            &s_client_args(dir, addr.port(), "TLS_AES_256_GCM_SHA384", "X25519", true),
            &[
                "no suitable key share",
                "no shared group",
                "handshake failure",
                "sslv3 alert",
                "tlsv1 alert",
            ],
        );
        expect_cli_rejection(
            scope,
            &listener,
            &acceptor,
            &bin,
            &cnf,
            "disallowed AEAD only (TLS_AES_128_GCM_SHA256)",
            &s_client_args(
                dir,
                addr.port(),
                "TLS_AES_128_GCM_SHA256",
                "X25519MLKEM768",
                true,
            ),
            &[
                "no ciphers available",
                "no shared cipher",
                "handshake failure",
                "sslv3 alert",
                "tlsv1 alert",
            ],
        );
        expect_cli_rejection(
            scope,
            &listener,
            &acceptor,
            &bin,
            &cnf,
            "TLS 1.2-only client",
            &s_client_tls12_args(dir, addr.port()),
            &[
                "protocol version",
                "unsupported protocol",
                "no protocols available",
                "handshake failure",
                "sslv3 alert",
                "tlsv1 alert",
            ],
        );
    });
}

// ---------------------------------------------------------------------------
// s_client helpers.
// ---------------------------------------------------------------------------

struct AcceptedCli {
    aead: Aead,
    peer_der: Vec<u8>,
}

/// Accept one TCP connection through the Boreas acceptor, then require the
/// exact plaintext payload from the CLI peer.
fn accept_cli_once(
    listener: &TcpListener,
    acceptor: &OpenSslAcceptor,
    expect: &[u8],
) -> AcceptedCli {
    let (stream, _) = listener.accept().expect("accept s_client TCP connection");
    stream
        .set_read_timeout(Some(STREAM_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(STREAM_TIMEOUT))
        .expect("set write timeout");
    let (mut stream, elapsed) = into_side(|| acceptor.accept(InterruptionShield(stream)))
        .unwrap_or_else(|(e, _)| panic!("Boreas acceptor rejected a well-formed s_client: {e:?}"));
    let _ = elapsed;
    assert_strict_negotiated(stream.negotiated(), "acceptor (s_client peer)");
    assert_eq!(
        read_exact(&mut stream, expect.len(), "s_client plaintext"),
        expect,
        "application plaintext from s_client must arrive intact"
    );
    // `EstablishedStream` exposes no shutdown; `into_parts` is the public
    // path to the inner `SslStream`. Close gracefully so `s_client` exits 0
    // on a real close_notify instead of reporting "unexpected eof while
    // reading" for an abrupt drop. The shutdown result is not asserted:
    // `s_client` may send its own close_notify first (stdin EOF), which is
    // equally clean.
    let (mut raw, negotiated, peer_certificate) = stream.into_parts();
    let aead = negotiated.aead;
    let peer_der = peer_certificate.to_der().expect("peer certificate DER");
    // `Ok(Sent)` = our close_notify is out; `Ok(Received)` = the peer's is
    // in too. `Err(_)` here only means the TCP side already died, which the
    // transcript assertions judge on their own.
    let _ = raw.shutdown();
    AcceptedCli { aead, peer_der }
}

/// `s_client` arguments shared by the positive and negative cases: TLS 1.3
/// only, `-brief -state` (prints `Ciphersuite:`, `Negotiated TLS1.3 group:`
/// and `Signature type:`), no session tickets.
fn s_client_args(
    dir: &TempDir,
    port: u16,
    cipher: &str,
    group: &str,
    present_client_cert: bool,
) -> Vec<String> {
    let mut args = vec![
        "s_client".into(),
        "-connect".into(),
        format!("127.0.0.1:{port}"),
        "-servername".into(),
        "net.boreas.internal".into(),
        "-verify_return_error".into(),
        "-CAfile".into(),
        dir.arg("root.pem"),
        "-tls1_3".into(),
        "-groups".into(),
        group.into(),
        "-sigalgs".into(),
        "mldsa65".into(),
        "-ciphersuites".into(),
        cipher.into(),
        "-no_ticket".into(),
        "-ign_eof".into(),
        "-brief".into(),
        "-state".into(),
    ];
    if present_client_cert {
        args.push("-cert".into());
        args.push(dir.arg("client.pem"));
        args.push("-key".into());
        args.push(dir.arg("client.key"));
    }
    args
}

/// A structurally valid `s_client` invocation restricted to TLS 1.2.  The
/// acceptor must reject it on protocol version, so the "TLS 1.3 only" gate is
/// exercised at the wire level instead of being inferred from configuration.
fn s_client_tls12_args(dir: &TempDir, port: u16) -> Vec<String> {
    let mut args = s_client_args(
        dir,
        port,
        "TLS_AES_256_GCM_SHA384",
        "X25519MLKEM768",
        true,
    );
    let version = args
        .iter()
        .position(|arg| arg == "-tls1_3")
        .expect("s_client arguments carry -tls1_3");
    args[version] = "-tls1_2".into();
    let ciphersuites = args
        .iter()
        .position(|arg| arg == "-ciphersuites")
        .expect("s_client arguments carry -ciphersuites");
    args[ciphersuites] = "-cipher".into();
    args[ciphersuites + 1] = "DEFAULT".into();
    args
}

/// Run `s_client`, feed it stdin, and enforce an overall deadline by
/// polling. A timeout is a harness failure, never a TLS result.
fn run_s_client(bin: &Path, cnf: &Path, args: &[String], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(bin)
        .env("OPENSSL_CONF", cnf)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");
    if let Some(mut stdin) = child.stdin.take() {
        // Broken pipe is the expected shape of the negative cases.
        let _ = stdin.write_all(stdin_bytes);
    }
    let deadline = Instant::now() + CLI_TIMEOUT;
    loop {
        match child.try_wait().expect("poll s_client") {
            Some(_) => {
                return child.wait_with_output().expect("collect s_client output");
            }
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("openssl s_client did not finish within {CLI_TIMEOUT:?}");
            }
        }
    }
}

fn combined(out: &Output) -> Vec<u8> {
    let mut all = out.stdout.clone();
    all.push(b'\n');
    all.extend_from_slice(&out.stderr);
    all
}

fn transcript_of(out: &Output) -> String {
    sanitize(&combined(out))
}

fn assert_line(transcript: &str, needle: &str) {
    assert!(
        transcript.lines().any(|l| l.trim() == needle),
        "expected exact line {needle:?} in s_client transcript:\n{transcript}"
    );
}

fn assert_line_ci(transcript: &str, needle: &str) {
    let needle = needle.to_ascii_lowercase();
    assert!(
        transcript
            .lines()
            .any(|l| l.trim().to_ascii_lowercase() == needle),
        "expected line {needle:?} (case-insensitive) in s_client transcript:\n{transcript}"
    );
}

/// The negotiated-group line is the one place in this suite where the
/// *negotiated* (not merely configured) group is read from a handshake --
/// by the OpenSSL CLI, not by rust-openssl, which exposes no getter for
/// it. Wording `"Negotiated TLS1.3 group: <name>"` matches OpenSSL 3.5+;
/// require exactly one such line and that it names the hybrid group.
fn assert_hybrid_group_reported(transcript: &str) {
    let group_lines: Vec<&str> = transcript
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("negotiated") && l.contains("group"))
        .collect();
    assert_eq!(
        group_lines.len(),
        1,
        "expected exactly one negotiated-group line in s_client transcript:\n{transcript}"
    );
    assert!(
        group_lines[0].contains("X25519MLKEM768"),
        "negotiated group must be X25519MLKEM768, got: {}",
        group_lines[0]
    );
}

/// One negative CLI case: the Boreas acceptor must error, `s_client` must
/// exit non-zero for a TLS reason, and neither side may be a timeout or a
/// harness/CLI-usage error.
#[allow(clippy::too_many_arguments)]
fn expect_cli_rejection<'scope, 'env>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    listener: &'env TcpListener,
    acceptor: &'env OpenSslAcceptor,
    bin: &Path,
    cnf: &Path,
    case: &str,
    args: &[String],
    reason_markers_ci: &[&str],
) {
    let server = scope.spawn(|| -> SideResult<InterruptionShield<TcpStream>> {
        let (stream, _) = listener.accept().expect("accept s_client TCP connection");
        stream
            .set_read_timeout(Some(STREAM_TIMEOUT))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(STREAM_TIMEOUT))
            .expect("set write timeout");
        into_side(|| acceptor.accept(InterruptionShield(stream)))
    });
    let out = run_s_client(bin, cnf, args, CLI_PAYLOAD);
    let server_result = server.join().expect("acceptor thread panicked");

    match server_result {
        Ok(_) => panic!("{case}: Boreas acceptor unexpectedly completed the handshake"),
        Err((error, elapsed)) => {
            assert!(
                matches!(
                    error,
                    BackendError::Handshake
                        | BackendError::PeerCertificateVerification
                        | BackendError::WrongPeerKeyType
                        | BackendError::WrongChainSignatureAlgorithm
                ),
                "{case}: acceptor failed with unexpected error {error:?}"
            );
            assert!(
                elapsed < STREAM_TIMEOUT - Duration::from_secs(2),
                "{case}: acceptor failed after {elapsed:?}; expected a prompt TLS \
                 rejection, not a stream timeout"
            );
        }
    }

    let transcript = transcript_of(&out);
    let lower = transcript.to_ascii_lowercase();
    assert!(
        !out.status.success(),
        "{case}: s_client unexpectedly succeeded:\n{transcript}"
    );
    assert!(
        reason_markers_ci.iter().any(|m| lower.contains(m)),
        "{case}: no expected TLS rejection marker {reason_markers_ci:?} in s_client output:\n{transcript}"
    );
    for harness_error in [
        "unknown option",
        "unrecognized option",
        "no such file",
        "unable to load",
        "error setting certificate",
        "error setting private key",
    ] {
        assert!(
            !lower.contains(harness_error),
            "{case}: s_client output looks like a harness error ({harness_error:?}):\n{transcript}"
        );
    }
    eprintln!("PASS expected TLS rejection ({case})");
}
