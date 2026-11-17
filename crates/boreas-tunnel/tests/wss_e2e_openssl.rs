#![cfg(feature = "openssl-inner-tls")]

//! Real loopback TCP -> public-certificate outer TLS -> RFC6455 h1 -> pq768
//! hop mTLS -> SessionHello/Accept -> circuit -> pq768 E2E TLS -> encrypted
//! candidate confirmation -> business stream. Loopback-origin evidence only;
//! not CDN support or independent implementation interop.
use boreas_crypto::{
    Policy,
    backend::{OpenSslAcceptor, OpenSslConnector, PemIdentity},
};
use boreas_pki::NodeRole as PkiNodeRole;
use boreas_pki::management::{
    IdentityAuthority, IdentityTemplate, IssuerScope, ManagementTrust, VerifiedObject,
};
use boreas_pki::{VerifiedNetworkContext, verify_network_policy};
use boreas_proto::{
    SecurityMode,
    messages::PathRole,
    objects::{NodeRole as ObjectRole, ObjectBody},
};
use boreas_tunnel::{
    ClientTarget, LinkClient, LinkServer, OpenSslE2eBackend, OpenSslInnerAcceptor,
    OpenSslInnerConnector, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, PeerIdentity,
    PkiIdentityExtractor, VerifiedNodeIdentity,
    e2e::{accept_circuit, accept_e2e, open_e2e},
    resource::{Admission, Limits},
    session::SessionPolicy,
};
use openssl::{
    pkey::{KeyType, PKey},
    sha::sha256,
    x509::{X509, X509Req},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const IO_TIMEOUT: Duration = Duration::from_secs(12);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const APP_LEN: usize = 196_613;
const NET: [u8; 16] = [0x39; 16];

fn verified_default_policy() -> VerifiedNetworkContext {
    static POLICY: std::sync::OnceLock<VerifiedNetworkContext> = std::sync::OnceLock::new();
    *POLICY.get_or_init(|| {
        use boreas_proto::network_policy::NetworkPolicyCandidate;
        use boreas_proto::objects::MldsaParameterSet;
        use openssl::sign::Signer;
        let ed = PKey::private_key_from_raw_bytes(&[0x39; 32], openssl::pkey::Id::ED25519)
            .expect("policy Ed root");
        let pq = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[0x73; 32])
            .expect("policy ML-DSA root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            NET,
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        let candidate = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 1,
            expires: u64::MAX,
        };
        let raw = candidate.encode_tbs().unwrap();
        let message = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let mut signer = Signer::new_without_digest(&ed).unwrap();
        let ed_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        let mut signer = Signer::new_without_digest(&pq).unwrap();
        let pq_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        verify_network_policy(&raw, &ed_sig, &pq_sig, &pin, NET, 2)
            .unwrap()
            .require_default_runtime()
            .unwrap()
    })
}
const MINIMAL_CNF: &str = "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\n\n[default_sect]\nactivate = 1\n";
/// Never drain an unbounded CLI stderr stream: only this much of the private
/// capture file is ever read back.
const STDERR_CAP: u64 = 16 * 1024;
const STDERR_TEXT_LIMIT: usize = 4 * 1024;
const STDERR_LINE_LIMIT: usize = 320;
/// Appended when the byte budget forces truncation. Its length is reserved
/// before any partial line is emitted, so the retained text can never exceed
/// `STDERR_TEXT_LIMIT` -- including when the cut lands mid-line.
const STDERR_TRUNCATION: &str = "<truncated>\n";
/// Recognised OpenSSL CLI / provider diagnostics. Anything else is dropped
/// rather than echoed, so no key material, dump or invite text can leak.
const STDERR_MARKERS: [&str; 12] = [
    "error",
    "unable to",
    "unknown",
    "invalid",
    "failed",
    "failure",
    "not found",
    "no such file",
    "cannot",
    "problems encountered",
    "unsupported",
    "expected",
];

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "boreas-wss-e2e-{}-{}-{nonce}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create temporary PKI");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("restrict temporary PKI");
        }
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Replace the private fixture directory with a stable placeholder so
/// diagnostics never disclose where the ephemeral key material lived.
fn redact_dir(text: &str, dir: &str) -> String {
    text.split(dir).collect::<Vec<_>>().join("@DIR@")
}

/// Longest prefix of `text` that fits in `max_bytes`, always cut on a UTF-8
/// character boundary so truncation can never panic or emit a partial code
/// point.
fn truncate_utf8(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Longest prefix of `text` holding at most `max_chars` characters.
fn truncate_chars(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// Strip ANSI escape sequences and every remaining control character.
///
/// A synthetic CLI (or a fixed CLI echoing attacker-influenced data) must not
/// be able to inject terminal control bytes through a line that merely looks
/// like an error: only inert, printable text survives.
fn strip_terminal_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.next() {
                // CSI: ESC '[' ... final byte in 0x40..=0x7E.
                Some('[') => {
                    for next in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&next) {
                            break;
                        }
                    }
                }
                // OSC: ESC ']' ... BEL or ST (ESC '\').
                Some(']') => {
                    while let Some(next) = chars.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                // Two-byte escape: drop the whole sequence.
                Some(_) | None => {}
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    out
}

/// Keep at most `STDERR_TEXT_LIMIT` bytes of *recognised* CLI diagnostics from
/// the private stderr capture: PEM blocks, keying material, TLS dumps and
/// invite text are dropped entirely, terminal control bytes are stripped, the
/// fixture path is redacted, and every kept line is length-capped. The output
/// is inert text that is safe to print in a panic message, and it can never
/// exceed the byte budget because the truncation marker is reserved before a
/// partial line is appended.
fn sanitize_cli_stderr(bytes: &[u8], dir: &str) -> String {
    let mut kept = String::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("-----begin")
            || lower.contains("-----end")
            || lower.contains("private key")
            || lower.contains("pvk")
            || lower.contains("secret")
            || lower.contains("dump")
            || lower.contains("invite")
        {
            continue;
        }
        if !STDERR_MARKERS.iter().any(|marker| lower.contains(*marker)) {
            continue;
        }
        let text = strip_terminal_controls(&redact_dir(line, dir));
        let cleaned = truncate_chars(&text, STDERR_LINE_LIMIT).trim_end();
        if cleaned.is_empty() {
            continue;
        }
        let remaining = STDERR_TEXT_LIMIT.saturating_sub(kept.len());
        if remaining == 0 {
            break;
        }
        if cleaned.len() < remaining {
            kept.push_str(cleaned);
            kept.push('\n');
            continue;
        }
        // The line does not fit whole: emit the longest UTF-8-safe prefix that
        // leaves room for the marker, then stop. Total stays <= the limit.
        let budget = remaining.saturating_sub(STDERR_TRUNCATION.len());
        if budget == 0 {
            // Fewer bytes are left than the marker itself needs: shrink the
            // retained text (never mid code point) so the marker still fits.
            let cut = truncate_utf8(&kept, STDERR_TEXT_LIMIT - STDERR_TRUNCATION.len()).len();
            kept.truncate(cut);
            kept.push_str(STDERR_TRUNCATION);
            break;
        }
        kept.push_str(truncate_utf8(cleaned, budget));
        kept.push_str(STDERR_TRUNCATION);
        break;
    }
    if kept.is_empty() {
        "<no recognised CLI diagnostics>".to_owned()
    } else {
        kept
    }
}

fn openssl(t: &Temp, args: &[&str]) {
    static STDERR_SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = t.0.to_str().expect("temp path");
    let args: Vec<String> = args.iter().map(|a| a.replace("@DIR@", dir)).collect();
    let bin = std::env::var_os("BOREAS_OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    // A private regular file inside the already-owner-only fixture directory
    // (removed with it on drop) replaces a pipe: the CLI can never block on a
    // full pipe buffer, and no unbounded stream is forwarded to the test log.
    let stderr_path = t.path(&format!(
        ".openssl-stderr-{}.log",
        STDERR_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let stderr_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr_path)
        .expect("create private OpenSSL stderr capture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stderr_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict OpenSSL stderr capture");
    }
    // Fixture generation is test-only, but still bounded so a stuck provider cannot hang CI.
    let mut child = Command::new(bin)
        .env("OPENSSL_CONF", t.path("openssl.cnf"))
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("start OpenSSL fixture generator");
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match child.try_wait().expect("poll OpenSSL fixture process") {
            Some(status) => {
                if !status.success() {
                    let captured = std::fs::File::open(&stderr_path)
                        .ok()
                        .map(|file| {
                            let mut buf = Vec::new();
                            let mut reader = file.take(STDERR_CAP);
                            let _ = reader.read_to_end(&mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    panic!(
                        "OpenSSL fixture generation failed (status {:?}): {}\n{}",
                        status.code(),
                        redact_dir(&args.join(" "), dir),
                        sanitize_cli_stderr(&captured, dir)
                    );
                }
                break;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("OpenSSL fixture generation exceeded 45s deadline");
            }
            None => thread::sleep(Duration::from_millis(1)),
        }
    }
}
/// Key-generation recipe for one fixture identity.
///
/// `genpkey` takes the bare algorithm name plus option flags. `RSA:2048` is
/// not a valid OpenSSL 3 algorithm identifier and made the very first fixture
/// CLI invocation exit 1 before any TLS code ran; the modulus size belongs in
/// `-pkeyopt rsa_keygen_bits:2048`. Pure post-quantum algorithm names
/// (`ML-DSA-65`) stay as-is.
#[derive(Clone, Copy)]
enum KeyAlg {
    Rsa2048,
    MlDsa65,
}

fn genpkey(t: &Temp, out: &str, algorithm: KeyAlg) {
    let out = format!("@DIR@/{out}");
    match algorithm {
        KeyAlg::Rsa2048 => openssl(
            t,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                &out,
            ],
        ),
        KeyAlg::MlDsa65 => openssl(t, &["genpkey", "-algorithm", "ML-DSA-65", "-out", &out]),
    }
}

fn make_ca(t: &Temp, name: &str, algorithm: KeyAlg, subject: &str) {
    genpkey(t, &format!("{name}-ca.key"), algorithm);
    openssl(
        t,
        &[
            "req",
            "-new",
            "-x509",
            "-key",
            &format!("@DIR@/{name}-ca.key"),
            "-out",
            &format!("@DIR@/{name}-ca.pem"),
            "-days",
            "30",
            "-subj",
            subject,
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
}
struct LeafSpec<'a> {
    cn: &'a str,
    eku: &'a str,
    san: &'a str,
    serial: &'a str,
}
fn make_leaf(t: &Temp, ca: &str, stem: &str, algorithm: KeyAlg, spec: LeafSpec<'_>) {
    genpkey(t, &format!("{stem}.key"), algorithm);
    openssl(
        t,
        &[
            "req",
            "-new",
            "-key",
            &format!("@DIR@/{stem}.key"),
            "-out",
            &format!("@DIR@/{stem}.csr"),
            "-subj",
            &format!("/CN={}", spec.cn),
        ],
    );
    std::fs::write(t.path(&format!("{stem}.ext")), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={}\nsubjectAltName={}\n", spec.eku, spec.san)).expect("write leaf extensions");
    openssl(
        t,
        &[
            "x509",
            "-req",
            "-in",
            &format!("@DIR@/{stem}.csr"),
            "-CA",
            &format!("@DIR@/{ca}-ca.pem"),
            "-CAkey",
            &format!("@DIR@/{ca}-ca.key"),
            "-set_serial",
            spec.serial,
            "-days",
            "14",
            "-extfile",
            &format!("@DIR@/{stem}.ext"),
            "-out",
            &format!("@DIR@/{stem}.pem"),
        ],
    );
}
fn setup(t: &Temp) {
    std::fs::write(t.path("openssl.cnf"), MINIMAL_CNF).expect("write minimal provider config");
    make_ca(t, "outer", KeyAlg::Rsa2048, "/CN=Loopback WebPKI Test Root");
    make_leaf(
        t,
        "outer",
        "outer",
        KeyAlg::Rsa2048,
        LeafSpec {
            cn: "wss.boreas.test",
            eku: "serverAuth",
            san: "DNS:wss.boreas.test",
            serial: "101",
        },
    );
    make_ca(t, "id", KeyAlg::MlDsa65, "/CN=Boreas Test Identity Root");
    make_leaf(
        t,
        "id",
        "edge",
        KeyAlg::MlDsa65,
        LeafSpec {
            cn: "edge.boreas.test",
            eku: "clientAuth,serverAuth",
            san: "DNS:edge.boreas.test",
            serial: "201",
        },
    );
    make_leaf(
        t,
        "id",
        "core",
        KeyAlg::MlDsa65,
        LeafSpec {
            cn: "core.boreas.test",
            eku: "clientAuth,serverAuth",
            san: "DNS:core.boreas.test",
            serial: "202",
        },
    );
    make_leaf(
        t,
        "id",
        "unknown",
        KeyAlg::MlDsa65,
        LeafSpec {
            cn: "unknown.boreas.test",
            eku: "clientAuth,serverAuth",
            san: "DNS:unknown.boreas.test",
            serial: "203",
        },
    );
    make_ca(
        t,
        "rogue",
        KeyAlg::MlDsa65,
        "/CN=Untrusted Boreas Test Root",
    );
}
fn read(t: &Temp, name: &str) -> Vec<u8> {
    std::fs::read(t.path(name)).expect("read generated fixture")
}
fn pem(t: &Temp, leaf: &str, ca: &str) -> PemIdentity {
    PemIdentity {
        certificate_pem: read(t, &format!("{leaf}.pem")),
        private_key_pem: read(t, &format!("{leaf}.key")),
        trust_anchor_pem: read(t, &format!("{ca}-ca.pem")),
    }
}

fn verified_identity(
    t: &Temp,
    leaf: &str,
    node: u16,
    generation: u64,
    role: ObjectRole,
) -> VerifiedObject {
    let cert = X509::from_pem(&read(t, &format!("{leaf}.pem"))).expect("parse ML-DSA leaf");
    let mldsa = cert
        .public_key()
        .expect("leaf public key")
        .raw_public_key()
        .expect("leaf raw key");
    let csr = X509Req::from_pem(&read(t, &format!("{leaf}.csr")))
        .expect("parse signed CSR")
        .to_der()
        .expect("CSR DER");
    let node_ed = PKey::generate_ed25519().expect("ephemeral node Ed25519 key");
    let ed_public: [u8; 32] = node_ed
        .raw_public_key()
        .expect("node Ed25519 public key")
        .try_into()
        .expect("Ed25519 length");
    let issuer_ed = PKey::generate_ed25519().expect("ephemeral issuer Ed25519 key");
    let issuer_ml = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[node as u8; 32])
        .expect("ephemeral issuer ML-DSA key");
    let authority = IdentityAuthority::from_pkcs8_der(
        NET,
        b"loopback-test-ia".to_vec(),
        1,
        &issuer_ed.private_key_to_pkcs8().expect("issuer Ed PKCS8"),
        &issuer_ml
            .private_key_to_pkcs8()
            .expect("issuer ML-DSA PKCS8"),
    )
    .expect("IdentityAuthority");
    let scope = IssuerScope::for_identity(vec![PkiNodeRole::Edge, PkiNodeRole::Core], vec![1])
        .expect("bounded identity scope");
    let body = authority
        .node_identity_from_csr(
            IdentityTemplate {
                node_id: node,
                home_core_id: 1,
                vip_octet: node as u8,
                role: match role {
                    ObjectRole::Edge => PkiNodeRole::Edge,
                    ObjectRole::Core => PkiNodeRole::Core,
                    ObjectRole::EnrollmentService => PkiNodeRole::EnrollmentService,
                },
                identity_generation: generation,
                identity_pub_ed25519: ed_public,
                not_before_us: 1_000_000,
                expires_us: 9_000_000_000_000_000,
                scope: Vec::new(),
            },
            &csr,
        )
        .expect("construct NodeIdentity from signed CSR");
    assert_eq!(
        body.identity_pub_mldsa, mldsa,
        "certificate key is the key bound by management identity"
    );
    let signed = authority
        .sign_node_identity(body)
        .expect("dual-sign NodeIdentity");
    let mut trust = ManagementTrust::new(NET);
    trust
        .add_issuer(authority.issuer_record(scope).expect("issuer record"))
        .expect("provision test authority");
    trust
        .verify_and_authorize(&signed.encode().expect("encode signed object"), 2_000_000)
        .expect("ManagementTrust verifies signature, scope, sequence and time")
}
fn peer(object: &VerifiedObject) -> PeerIdentity {
    let value = VerifiedNodeIdentity::from_verified_object(object, &verified_default_policy())
        .expect("verified management identity");
    let ObjectBody::NodeIdentity(body) = &object.object().body else {
        unreachable!("verified helper returns NodeIdentity")
    };
    assert_eq!(value.vip(), body.vip);
    assert_eq!(
        value.node_id(),
        boreas_pki::node_id(
            body.home_core_id,
            body.vip[3],
            match body.role {
                ObjectRole::Core => PkiNodeRole::Core,
                ObjectRole::Edge => PkiNodeRole::Edge,
                ObjectRole::EnrollmentService => PkiNodeRole::EnrollmentService,
            },
        )
        .expect("verified node mapping")
    );
    assert_eq!(
        value.vip(),
        boreas_pki::expected_vip(
            body.home_core_id,
            value.vip()[3],
            match body.role {
                ObjectRole::Core => PkiNodeRole::Core,
                ObjectRole::Edge => PkiNodeRole::Edge,
                ObjectRole::EnrollmentService => PkiNodeRole::EnrollmentService,
            },
        )
        .expect("default overlay VIP")
    );
    value.peer_identity()
}
fn extractor(a: &VerifiedObject, b: &VerifiedObject) -> Arc<PkiIdentityExtractor> {
    Arc::new(
        PkiIdentityExtractor::new(vec![
            VerifiedNodeIdentity::from_verified_object(a, &verified_default_policy())
                .expect("verified A"),
            VerifiedNodeIdentity::from_verified_object(b, &verified_default_policy())
                .expect("verified B"),
        ])
        .expect("unique trusted SPKIs"),
    )
}

#[test]
fn signed_vip_lookup_requires_exact_verified_peer_and_certificate_owner() {
    let t = Temp::new();
    setup(&t);
    let edge_object = verified_identity(&t, "edge", 2, 4, ObjectRole::Edge);
    let core_object = verified_identity(&t, "core", 1, 9, ObjectRole::Core);
    let extractor = extractor(&edge_object, &core_object);
    let edge_peer = peer(&edge_object);
    let edge_certificate = X509::from_pem(&read(&t, "edge.pem"))
        .expect("parse verified Edge leaf")
        .to_der()
        .expect("encode Edge leaf DER");
    let ObjectBody::NodeIdentity(edge_body) = &edge_object.object().body else {
        unreachable!("verified helper returns NodeIdentity")
    };

    assert_eq!(
        extractor.signed_vip_for_verified_peer(edge_peer, &edge_certificate),
        Some(edge_body.vip),
        "signed VIP round-trips from the ManagementTrust-verified object"
    );

    let mut wrong_generation = edge_peer;
    wrong_generation.identity_generation += 1;
    assert_eq!(
        extractor.signed_vip_for_verified_peer(wrong_generation, &edge_certificate),
        None
    );
    let mut wrong_net = edge_peer;
    wrong_net.net_id[0] ^= 1;
    assert_eq!(
        extractor.signed_vip_for_verified_peer(wrong_net, &edge_certificate),
        None
    );
    let mut wrong_role = edge_peer;
    wrong_role.role = boreas_crypto::NodeRole::Core;
    assert_eq!(
        extractor.signed_vip_for_verified_peer(wrong_role, &edge_certificate),
        None
    );
    let core_certificate = X509::from_pem(&read(&t, "core.pem"))
        .expect("parse verified Core leaf")
        .to_der()
        .expect("encode Core leaf DER");
    assert_eq!(
        extractor.signed_vip_for_verified_peer(edge_peer, &core_certificate),
        None,
        "a different certificate SPKI cannot claim Edge's signed VIP"
    );

    // Distinct certificate keys claiming the same complete peer tuple are
    // ambiguous; even an otherwise valid cert must not select one VIP record.
    let duplicate_peer_object = verified_identity(&t, "unknown", 2, 4, ObjectRole::Edge);
    let ambiguous_extractor = PkiIdentityExtractor::new(vec![
        VerifiedNodeIdentity::from_verified_object(&edge_object, &verified_default_policy())
            .expect("verified Edge"),
        VerifiedNodeIdentity::from_verified_object(
            &duplicate_peer_object,
            &verified_default_policy(),
        )
        .expect("verified duplicate peer tuple"),
    ])
    .expect("different SPKIs are individually unique");
    assert_eq!(
        ambiguous_extractor.signed_vip_for_verified_peer(edge_peer, &edge_certificate),
        None,
        "duplicate verified peer tuple must be rejected as ambiguous"
    );
}

fn admission() -> Admission {
    Admission::new(Limits {
        handshakes_global: 4,
        authenticated_global: 4,
        authenticated_per_peer: 2,
        bytes_global: 8 * 1024 * 1024,
    })
}
fn policy(local: PeerIdentity, peer: PeerIdentity) -> SessionPolicy {
    SessionPolicy {
        local,
        expected_peer: peer,
        path_role: PathRole::Cdn,
        security_mode: SecurityMode::E2eRequired,
        suite: boreas_proto::messages::Suite::Pq768,
        mtu_cap: 1400,
        identity_registered: true,
        allow_pq1024: false,
        allow_hop_only: false,
        allowed_peer_roles: vec![peer.role],
    }
}
fn target(address: SocketAddr, name: &str) -> ClientTarget {
    ClientTarget {
        address,
        ws_host: format!("{name}:443"),
        tls_server_name: name.to_owned(),
        path: "/tunnel".into(),
    }
}

struct ServerSide {
    hop: Box<dyn boreas_tunnel::InnerTlsAcceptor>,
    e2e: OpenSslE2eBackend,
    outer: OpenSslOuterTlsAcceptor,
    local: PeerIdentity,
    peer: PeerIdentity,
}
struct ClientSide {
    hop: Box<dyn boreas_tunnel::InnerTlsConnector>,
    e2e: OpenSslE2eBackend,
    outer: OpenSslOuterTlsConnector,
    local: PeerIdentity,
    peer: PeerIdentity,
}
fn sides(t: &Temp) -> (ClientSide, ServerSide) {
    let obj_edge = verified_identity(t, "edge", 2, 4, ObjectRole::Edge);
    let obj_core = verified_identity(t, "core", 1, 9, ObjectRole::Core);
    let edge = peer(&obj_edge);
    let core = peer(&obj_core);
    let extractor = extractor(&obj_edge, &obj_core);
    let edge_pem = pem(t, "edge", "id");
    let core_pem = pem(t, "core", "id");
    let edge_connector = || {
        OpenSslConnector::from_pem_identity(&edge_pem, Policy::production_default())
            .expect("pq768 Edge connector")
    };
    let edge_acceptor = || {
        OpenSslAcceptor::from_pem_identity(&edge_pem, Policy::production_default())
            .expect("pq768 Edge acceptor")
    };
    let core_connector = || {
        OpenSslConnector::from_pem_identity(&core_pem, Policy::production_default())
            .expect("pq768 Core connector")
    };
    let core_acceptor = || {
        OpenSslAcceptor::from_pem_identity(&core_pem, Policy::production_default())
            .expect("pq768 Core acceptor")
    };
    let client = ClientSide {
        hop: Box::new(OpenSslInnerConnector::new(
            edge_connector(),
            extractor.clone(),
        )),
        e2e: OpenSslE2eBackend::new(
            Arc::new(edge_connector()),
            Arc::new(edge_acceptor()),
            extractor.clone(),
        ),
        outer: OpenSslOuterTlsConnector::with_root_certificates(&read(t, "outer-ca.pem"))
            .expect("private web-PKI root"),
        local: edge,
        peer: core,
    };
    let server = ServerSide {
        hop: Box::new(OpenSslInnerAcceptor::new(
            core_acceptor(),
            extractor.clone(),
        )),
        e2e: OpenSslE2eBackend::new(
            Arc::new(core_connector()),
            Arc::new(core_acceptor()),
            extractor,
        ),
        outer: OpenSslOuterTlsAcceptor::from_pem_files(t.path("outer.pem"), t.path("outer.key"))
            .expect("public origin cert"),
        local: core,
        peer: edge,
    };
    (client, server)
}
fn bounded_accept(listener: &TcpListener) -> Result<TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("listener nonblocking: {e}"))?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((tcp, _)) => {
                tcp.set_nonblocking(false)
                    .map_err(|e| format!("accepted socket blocking mode: {e}"))?;
                return Ok(tcp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("bounded accept deadline elapsed".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(format!("TCP accept: {e}")),
        }
    }
}
fn accept_session(
    listener: &TcpListener,
    side: ServerSide,
) -> Result<
    (
        boreas_tunnel::AcceptedSession,
        OpenSslE2eBackend,
        PeerIdentity,
    ),
    String,
> {
    let tcp = bounded_accept(listener)?;
    let ServerSide {
        hop,
        e2e,
        outer,
        local,
        peer,
    } = side;
    let accepted = LinkServer::new(hop)
        .accept_tls_stream(tcp, &outer, policy(local, peer), IO_TIMEOUT, &admission())
        .map_err(|e| e.to_string())?;
    Ok((accepted, e2e, peer))
}
fn payload() -> Vec<u8> {
    (0..APP_LEN)
        .map(|i| ((i * 73 + (i >> 3) * 19 + 11) % 251) as u8)
        .collect()
}

#[test]
fn real_loopback_wss_hop_e2e_confirmation_and_multiframe_business_payload() {
    let t = Temp::new();
    setup(&t);
    let (client_side, server_side) = sides(&t);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut accepted, backend, peer) =
            accept_session(&listener, server_side).map_err(|e| format!("hop: {e}"))?;
        let mut e2e =
            accept_e2e(&mut accepted.session, &backend, peer).map_err(|e| format!("E2E: {e}"))?;
        let mut data = vec![0u8; APP_LEN];
        e2e.read_exact(&mut data)
            .map_err(|e| format!("business stream: {e}"))?;
        Ok::<_, String>(data)
    });
    let link = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let session = link.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let mut hop = match session {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("client WSS/session failed: {e}; server={joined:?}");
        }
    };
    let e2e_result = open_e2e(&mut hop, &client_side.e2e, client_side.peer, 1);
    let mut e2e = match e2e_result {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("E2E TLS/confirmation failed: {e}; server={joined:?}");
        }
    };
    let expected = payload();
    let expected_hash = sha256(&expected);
    let write_result = e2e.write_all(&expected);
    drop(e2e);
    let server_result = server.join().expect("join server thread");
    write_result.expect("write business payload");
    let actual = server_result.expect("server path");
    assert_eq!(sha256(&actual), expected_hash);
    assert_eq!(actual, expected);
}

#[test]
fn outer_wrong_name_and_untrusted_ca_are_rejected() {
    let t = Temp::new();
    setup(&t);
    for (name, untrusted_ca) in [("wrong.boreas.test", false), ("wss.boreas.test", true)] {
        let (client_side, server_side) = sides(&t);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let outer = if untrusted_ca {
            OpenSslOuterTlsConnector::with_root_certificates(&read(&t, "rogue-ca.pem")).unwrap()
        } else {
            client_side.outer
        };
        let server = thread::spawn(move || accept_session(&listener, server_side).map(|_| ()));
        let client = LinkClient::new(Box::new(outer), client_side.hop);
        let client_result = client.connect(
            &target(address, name),
            policy(client_side.local, client_side.peer),
            IO_TIMEOUT,
        );
        let server_result = server.join().expect("join outer TLS server");
        assert!(
            client_result.is_err(),
            "outer certificate/name validation must fail"
        );
        assert!(
            server_result.is_err(),
            "outer verification failure must be observed by origin"
        );
    }
}

#[test]
fn inner_wrong_ca_is_rejected_without_hop_only_fallback() {
    let t = Temp::new();
    setup(&t);
    let (mut client_side, server_side) = sides(&t);
    let obj_edge = verified_identity(&t, "edge", 2, 4, ObjectRole::Edge);
    let obj_core = verified_identity(&t, "core", 1, 9, ObjectRole::Core);
    let rogue = PemIdentity {
        trust_anchor_pem: read(&t, "rogue-ca.pem"),
        ..pem(&t, "edge", "id")
    };
    client_side.hop = Box::new(OpenSslInnerConnector::new(
        OpenSslConnector::from_pem_identity(&rogue, Policy::production_default()).unwrap(),
        extractor(&obj_edge, &obj_core),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || accept_session(&listener, server_side).map(|_| ()));
    let client = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let client_result = client.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let server_result = server.join().expect("join inner TLS server");
    assert!(client_result.is_err());
    assert!(server_result.is_err());
}

#[test]
fn valid_ca_unknown_certificate_identity_is_rejected() {
    let t = Temp::new();
    setup(&t);
    let (mut client_side, server_side) = sides(&t);
    let obj_edge = verified_identity(&t, "edge", 2, 4, ObjectRole::Edge);
    let obj_core = verified_identity(&t, "core", 1, 9, ObjectRole::Core);
    let unknown = pem(&t, "unknown", "id");
    client_side.hop = Box::new(OpenSslInnerConnector::new(
        OpenSslConnector::from_pem_identity(&unknown, Policy::production_default()).unwrap(),
        extractor(&obj_edge, &obj_core),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || accept_session(&listener, server_side).map(|_| ()));
    let client = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let result = client.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let server_result = server.join().expect("join identity extractor rejection");
    assert!(result.is_err());
    assert!(
        server_result.is_err(),
        "valid CA chain without authorized identity SPKI must not produce a session"
    );
}

#[test]
fn hop_generation_mismatch_is_rejected_before_session_accept() {
    let t = Temp::new();
    setup(&t);
    let (client_side, server_side) = sides(&t);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || accept_session(&listener, server_side).map(|_| ()));
    let mut wrong_peer = client_side.peer;
    wrong_peer.identity_generation += 1;
    let client = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let client_result = client.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, wrong_peer),
        IO_TIMEOUT,
    );
    let server_result = server.join().expect("join session server");
    assert!(client_result.is_err());
    assert!(server_result.is_err());
}

#[test]
fn circuit_destination_mismatch_rejects_before_e2e_business() {
    let t = Temp::new();
    setup(&t);
    let (client_side, server_side) = sides(&t);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut accepted, _backend, _peer) = accept_session(&listener, server_side)?;
        accept_circuit(&mut accepted.session)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    let client = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let session = client.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let mut hop = match session {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("authorized hop failed: {e}; server={joined:?}");
        }
    };
    let mut wrong_destination = client_side.peer;
    wrong_destination.node_id = 3;
    let result = open_e2e(&mut hop, &client_side.e2e, wrong_destination, 1);
    let server_result = server.join().expect("join circuit destination validator");
    assert!(
        result.is_err(),
        "wrong destination NodeID cannot establish a circuit"
    );
    assert!(
        server_result.is_err(),
        "destination mismatch is rejected by the receiving endpoint"
    );
}

#[test]
fn e2e_generation_mismatch_never_yields_business_stream() {
    let t = Temp::new();
    setup(&t);
    let (client_side, server_side) = sides(&t);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut accepted, backend, peer) = accept_session(&listener, server_side)?;
        let mut wrong = peer;
        wrong.identity_generation += 1;
        let result = accept_e2e(&mut accepted.session, &backend, wrong);
        Ok::<bool, String>(result.is_err())
    });
    let client = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let session = client.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let mut hop = match session {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("hop connect failed: {e}; server={joined:?}");
        }
    };
    let result = open_e2e(&mut hop, &client_side.e2e, client_side.peer, 1);
    let server_result = server
        .join()
        .expect("join E2E server")
        .expect("hop establishment");
    assert!(
        result.is_err(),
        "generation mismatch cannot open business stream"
    );
    assert!(server_result);
}

// ---------------------------------------------------------------------------
// Sanitizer unit tests. The fixture-diagnostic path must be bounded, inert and
// leak-free on its own, independent of whether a real CLI ever fails -- and it
// must not trust an "error"-looking line blindly (a fixed or synthetic CLI
// could carry terminal control bytes or key material through it).
// ---------------------------------------------------------------------------

#[test]
fn sanitizer_keeps_only_recognised_cli_diagnostics() {
    let out = sanitize_cli_stderr(
        concat!(
            "Loading provider\n",
            "40AB1C:error:1E08010C:DECODER routines::unsupported\n",
            "random chatter\n",
            "unable to load certificate\n",
        )
        .as_bytes(),
        "/tmp/boreas-wss-e2e-unit",
    );
    assert!(out.contains("error:1E08010C:DECODER routines::unsupported"));
    assert!(out.contains("unable to load certificate"));
    assert!(!out.contains("Loading provider"));
    assert!(!out.contains("random chatter"));
}

#[test]
fn sanitizer_drops_pem_key_material_and_secret_lines() {
    let out = sanitize_cli_stderr(
        concat!(
            // A bare PEM block carries no recognised diagnostic marker.
            "-----BEGIN PRIVATE KEY-----\n",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n",
            "-----END PRIVATE KEY-----\n",
            // Even when the CLI prefixes it, key material is filtered.
            "error: -----BEGIN PRIVATE KEY-----\n",
            "error: secret=deadbeef\n",
            "error: the private key is not ready\n",
        )
        .as_bytes(),
        "/tmp/boreas-wss-e2e-unit",
    );
    assert_eq!(
        out, "<no recognised CLI diagnostics>",
        "PEM/key/secret lines must be dropped, got: {out}"
    );
}

#[test]
fn sanitizer_redacts_the_private_fixture_path() {
    let dir = "/tmp/boreas-wss-e2e-4242-0-7";
    let input = format!("error: could not open {dir}/outer.key\n");
    let out = sanitize_cli_stderr(input.as_bytes(), dir);
    assert!(out.contains("@DIR@/outer.key"), "got: {out}");
    assert!(!out.contains(dir), "private fixture path leaked: {out}");
}

#[test]
fn sanitizer_strips_escape_and_control_bytes() {
    let out = sanitize_cli_stderr(
        b"error: \x1b[31mboom\x1b[0m \x07bell\x00nul\n",
        "/tmp/boreas-wss-e2e-unit",
    );
    assert!(out.contains("boom"), "got: {out}");
    assert!(out.contains("bell"), "got: {out}");
    assert!(out.contains("nul"), "got: {out}");
    assert!(!out.contains('\u{1b}'), "ESC must not survive: {out:?}");
    assert_eq!(
        out.chars().filter(|c| c.is_control()).count(),
        1,
        "only the appended line terminator may be a control character: {out:?}"
    );
}

#[test]
fn sanitizer_caps_total_output_and_marks_truncation() {
    let input = format!("error: {}\n", "A".repeat(200)).repeat(100);
    let out = sanitize_cli_stderr(input.as_bytes(), "/tmp/boreas-wss-e2e-unit");
    assert!(
        out.len() <= STDERR_TEXT_LIMIT,
        "{} bytes exceed the {STDERR_TEXT_LIMIT}-byte budget",
        out.len()
    );
    assert!(
        out.ends_with(STDERR_TRUNCATION),
        "truncation must be marked, tail: {out:?}"
    );
}

#[test]
fn sanitizer_cap_is_utf8_safe_for_multibyte_lines() {
    let input = format!("error: {}\n", "€".repeat(300)).repeat(40);
    let out = sanitize_cli_stderr(input.as_bytes(), "/tmp/boreas-wss-e2e-unit");
    assert!(
        out.len() <= STDERR_TEXT_LIMIT,
        "{} bytes exceed the {STDERR_TEXT_LIMIT}-byte budget",
        out.len()
    );
    assert!(out.ends_with(STDERR_TRUNCATION), "tail: {out:?}");
    assert!(out.starts_with("error: €"), "head: {out:?}");
    assert!(
        !out.contains('\u{fffd}'),
        "truncation must not synthesise partial code points: {out:?}"
    );
}

#[test]
fn sanitizer_marks_truncation_even_when_only_a_sliver_remains() {
    // 455 lines of "error: B\n" fill 4095 of the 4096 bytes, so the deciding
    // line gets 1 remaining byte -- less than the marker itself needs.
    let input = "error: B\n".repeat(500);
    let out = sanitize_cli_stderr(input.as_bytes(), "/tmp/boreas-wss-e2e-unit");
    assert!(
        out.len() <= STDERR_TEXT_LIMIT,
        "{} bytes exceed the {STDERR_TEXT_LIMIT}-byte budget",
        out.len()
    );
    assert!(out.ends_with(STDERR_TRUNCATION), "tail: {out:?}");
}

#[test]
fn truncate_utf8_never_splits_a_code_point() {
    let text = "é€😀x";
    for max in 0..=text.len() + 2 {
        let cut = truncate_utf8(text, max);
        assert!(cut.len() <= max, "cut {cut:?} exceeds {max} bytes");
        assert!(
            text.starts_with(cut),
            "cut {cut:?} is not a prefix of {text:?}"
        );
        assert!(
            text.is_char_boundary(cut.len()),
            "cut {cut:?} ends mid code point"
        );
    }
}

/// One IPv4/UDP packet with a correct header checksum, for the packet path.
fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total).expect("bounded").to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..].copy_from_slice(payload);
    let mut sum = 0u32;
    for chunk in packet[..20].chunks(2) {
        sum += if chunk.len() == 2 {
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u32::from(chunk[0]) << 8
        };
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Real WSS + hop mTLS + E2E TLS circuit carrying VirtualTun packets through the
/// bounded L3 adapter, both directions.
///
/// This is the only test that exercises the token-gated public constructor
/// against a real circuit. It does not claim status freshness, revocation or
/// performance acceptance, and it is loopback-origin evidence only.
#[test]
fn real_loopback_e2e_circuit_carries_virtual_tun_packets() {
    use boreas_tun::PacketIo;

    let t = Temp::new();
    setup(&t);
    let (client_side, server_side) = sides(&t);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    // Edge node 2 holds 10.20.1.2; Core node 1 holds 10.20.1.1.
    let outbound = ipv4_packet([10, 20, 1, 2], [10, 20, 1, 1], b"e2e-packet-outbound");
    let inbound = ipv4_packet([10, 20, 1, 1], [10, 20, 1, 2], b"e2e-packet-inbound");
    let expected_inbound = inbound.clone();
    let outbound_len = outbound.len();
    let expected_outbound_hash = sha256(&outbound);
    // `policy` negotiates a 1400-byte hop MTU cap; stay at it.
    let mtu = 1400usize;

    let server = thread::spawn(move || {
        let (mut accepted, backend, peer) =
            accept_session(&listener, server_side).map_err(|e| format!("hop: {e}"))?;
        let e2e =
            accept_e2e(&mut accepted.session, &backend, peer).map_err(|e| format!("E2E: {e}"))?;
        let (device, host) =
            boreas_tun::VirtualTun::try_pair(4, 4, mtu).map_err(|e| format!("server tun: {e}"))?;
        let mut path = boreas_tunnel::packet_path::PacketPath::try_new_over_e2e(&device, e2e, mtu)
            .map_err(|e| format!("server path: {e}"))?;
        let received = path.step_inbound().map_err(|e| e.to_string())?;
        let delivered = host
            .read_packet()
            .map_err(|e| format!("server tun read: {e}"))?;
        device
            .inject(&expected_inbound)
            .map_err(|e| format!("server tun inject: {e}"))?;
        let sent = path.step_outbound().map_err(|e| e.to_string())?;
        path.close_gracefully();
        Ok::<_, String>((received, delivered, sent))
    });

    let link = LinkClient::new(Box::new(client_side.outer), client_side.hop);
    let session = link.connect(
        &target(address, "wss.boreas.test"),
        policy(client_side.local, client_side.peer),
        IO_TIMEOUT,
    );
    let mut hop = match session {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("client WSS/session failed: {e}; server={joined:?}");
        }
    };
    let e2e = match open_e2e(&mut hop, &client_side.e2e, client_side.peer, 1) {
        Ok(s) => s,
        Err(e) => {
            let joined = server.join();
            panic!("E2E TLS/confirmation failed: {e}; server={joined:?}");
        }
    };
    let (device, host) = boreas_tun::VirtualTun::try_pair(4, 4, mtu).expect("bounded client pair");
    let mut path = boreas_tunnel::packet_path::PacketPath::try_new_over_e2e(&device, e2e, mtu)
        .expect("client packet path");

    device
        .inject(&outbound)
        .expect("host emitted outbound packet");
    assert_eq!(
        path.step_outbound()
            .expect("outbound authorization and framing"),
        Some(outbound.len())
    );
    assert_eq!(
        path.step_inbound().expect("inbound authorization"),
        Some(inbound.len())
    );
    let delivered = host
        .read_packet()
        .expect("host readable")
        .expect("exactly one packet delivered");
    assert_eq!(delivered, inbound);
    assert_eq!(sha256(&delivered), sha256(&inbound));
    assert_eq!(
        path.step_inbound()
            .expect("TLS close_notify must be clean EOF"),
        None
    );

    let server_result = server
        .join()
        .expect("join server thread")
        .expect("server packet path");
    assert_eq!(server_result.0, Some(outbound_len));
    let server_delivered = server_result
        .1
        .expect("server delivered exactly one packet");
    assert_eq!(
        sha256(&server_delivered),
        expected_outbound_hash,
        "the packet crossed the real circuit unchanged"
    );
    assert_eq!(server_result.2, Some(inbound.len()));
}
