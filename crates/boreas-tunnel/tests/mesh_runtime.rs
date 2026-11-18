#![cfg(feature = "openssl-inner-tls")]

//! Four real nodes on loopback: one `IdentityAuthority`, an Edge/Core pair, a
//! Core/Core pair, a single Core relay hop, and a directory built from real
//! dual-signed management objects. These are library-level TLS tests: they
//! start no daemon process and wait for no daemon readiness.
//!
//! What this file demonstrates:
//!
//! * authenticated `edge -> core` and `core -> core` hop sessions whose peer
//!   identities come from `ManagementTrust`-verified `NodeIdentity` objects and
//!   from the certificate chain, never from a wire claim;
//! * one real single-relay hop `edge-a -> core-b -> edge-d`, driven over two
//!   real TLS sessions with `RelayCircuit` control and fragment frames. The
//!   relay budget is derived from [`MeshTopology`], but the topology remains a
//!   planning model and is not a route authorization;
//! * endpoint-to-endpoint E2E TLS over one authenticated hop session;
//! * a `DirectoryIngest` fed with real dual-signed `NodeIdentity`, `AttachmentLease`
//!   and `CoreLsa` objects, converged across two replicas over bounded pages, with
//!   an unverifiable object rejected and a same-version fork preserved as two
//!   original signed objects.
//!
//! What this file does NOT demonstrate, and must not be cited as:
//!
//! * physical four-Core hardware, cross-region links, CDN behaviour or netem loss;
//! * **any multi-hop relay or multi-hop E2E security claim**. `RelayHop::relay_once`
//!   is single-direction and does not carry the original opener across a second
//!   relay; the candidate binding/full-duplex design is documented, not
//!   implemented, in `docs/engineering/multihop-binding-next.md`. A bidirectional
//!   relay needs a stateful readiness/`WANT_READ` session API; a timeout-as-idle
//!   wrapper is not acceptable because TLS/WS may have consumed partial records.
//! * any gate. `G-CONVERGE`, `G-FAILOVER` and `G-E2E` remain open in
//!   `docs/engineering/gates.json`.

use boreas_crypto::{
    Policy,
    backend::{OpenSslAcceptor, OpenSslConnector, PemIdentity},
};
use boreas_pki::NodeRole as PkiNodeRole;
use boreas_pki::management::{
    IdentityAuthority, IdentityTemplate, IssuerRecord, IssuerScope, MANAGEMENT_SCHEMA_VERSION,
    ManagementTrust, VerifiedObject,
};
use boreas_pki::{Authority, VerifiedNetworkContext, verify_network_policy};
use boreas_proto::SecurityMode;
use boreas_proto::messages::{
    PathRole, SignedObject, SignerRole, SignerSignatures, Suite as MessageSuite,
};
use boreas_proto::network_policy::NetworkPolicyCandidate;
use boreas_proto::objects::{
    AttachmentLease, CoreLsa, Extension, ManagementObject, MldsaParameterSet, NodeRole as ObjectRole,
    ObjectBody, ObjectType, SubjectIdentity,
};
use boreas_tunnel::directory::{
    ApplyOutcome, DirectoryIngest, DirectoryKey, DirectoryObjectKind, IngestOutcome, KeyStatus,
    SignedObjectPage, page_snapshot, pki_verifier::PkiObjectVerifier,
};
use boreas_tunnel::e2e::{RelayHop, RelayProgress, accept_circuit, accept_e2e, open_circuit, open_e2e};
use boreas_tunnel::relay::{MeshTopology, NodeRef};
use boreas_tunnel::resource::{Admission, Limits};
use boreas_tunnel::session::SessionPolicy;
use boreas_tunnel::{
    AcceptedSession, ClientTarget, LinkClient, LinkServer, OpenSslE2eBackend, OpenSslInnerAcceptor,
    OpenSslInnerConnector, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, PeerIdentity,
    PkiIdentityExtractor, VerifiedNodeIdentity,
};
use openssl::{
    pkey::{Id, KeyType, PKey, Private},
    sha::sha256,
    sign::Signer,
    x509::{X509, X509Req},
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const IO_TIMEOUT: Duration = Duration::from_secs(12);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
/// Candidate network id used by every fixture object.
const NET: [u8; 16] = [0x39; 16];
/// Outer Web-PKI name presented by every loopback listener.
const HOST: &str = "wss.boreas.test";
/// Trusted UTC microseconds for every verification in this file.
const NOW_US: u64 = 2_000_000;
const EDGE_GENERATION: u64 = 4;
const CORE_B_GENERATION: u64 = 9;
const CORE_C_GENERATION: u64 = 5;
const EDGE_D_GENERATION: u64 = 7;
const MINIMAL_CNF: &str = "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\n\n[default_sect]\nactivate = 1\n";

// --- fixture PKI -------------------------------------------------------------

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "boreas-mesh-{}-{}-{nonce}",
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

fn read(t: &Temp, name: &str) -> Vec<u8> {
    std::fs::read(t.path(name)).expect("read fixture file")
}

/// Keep only inert diagnostic lines: never echo PEM material or a private key.
fn sanitize(bytes: &[u8], dir: &str) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut kept = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("PRIVATE KEY") || line.contains("BEGIN ") {
            continue;
        }
        let line = line.replace(dir, "@DIR@");
        if kept.len() + line.len() > 400 {
            break;
        }
        kept.push_str(&line);
        kept.push('\n');
    }
    kept
}

fn openssl(t: &Temp, args: &[&str]) {
    let dir = t.0.to_str().expect("temp path").to_owned();
    let args: Vec<String> = args.iter().map(|a| a.replace("@DIR@", &dir)).collect();
    let bin = std::env::var_os("BOREAS_OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    let output = Command::new(bin)
        .env("OPENSSL_CONF", t.path("openssl.cnf"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .expect("run OpenSSL fixture generator");
    assert!(
        output.status.success(),
        "OpenSSL fixture step `{}` failed ({}): {}",
        args.first().map_or("?", String::as_str),
        output.status,
        sanitize(&output.stderr, &dir)
    );
}

#[derive(Clone, Copy)]
enum KeyAlg {
    Rsa2048,
    MlDsa65,
}

/// `genpkey` takes the bare algorithm name; the RSA modulus size belongs in
/// `-pkeyopt rsa_keygen_bits`.
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
    std::fs::write(
        t.path(&format!("{stem}.ext")),
        format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={}\nsubjectAltName={}\n",
            spec.eku, spec.san
        ),
    )
    .expect("write leaf extensions");
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
    std::fs::write(t.path("openssl.cnf"), MINIMAL_CNF).expect("write provider config");
    make_ca(t, "outer", KeyAlg::Rsa2048, "/CN=Loopback WebPKI Test Root");
    make_leaf(
        t,
        "outer",
        "outer",
        KeyAlg::Rsa2048,
        LeafSpec {
            cn: HOST,
            eku: "serverAuth",
            san: &format!("DNS:{HOST}"),
            serial: "101",
        },
    );
    make_ca(t, "id", KeyAlg::MlDsa65, "/CN=Boreas Mesh Identity Root");
    let leaves = [
        ("edge-a", "202"),
        ("core-b", "203"),
        ("core-c", "204"),
        ("edge-d", "205"),
        // Signed by the same identity CA but never provisioned into any
        // extractor: the session must refuse it.
        ("rogue", "206"),
    ];
    for (stem, serial) in leaves {
        make_leaf(
            t,
            "id",
            stem,
            KeyAlg::MlDsa65,
            LeafSpec {
                cn: &format!("{stem}.boreas.test"),
                eku: "clientAuth,serverAuth",
                san: &format!("DNS:{stem}.boreas.test"),
                serial,
            },
        );
    }
}

/// The same four-node PKI is reused by every test in this file; generating it
/// once keeps the CI cost bounded. Nothing mutates it after `setup`.
fn pki() -> &'static Temp {
    static PKI: OnceLock<Temp> = OnceLock::new();
    PKI.get_or_init(|| {
        let t = Temp::new();
        setup(&t);
        t
    })
}

// --- signed network policy and node identities --------------------------------

fn verified_default_policy() -> VerifiedNetworkContext {
    static POLICY: OnceLock<VerifiedNetworkContext> = OnceLock::new();
    *POLICY.get_or_init(|| {
        let ed = PKey::private_key_from_raw_bytes(&[0x39; 32], Id::ED25519)
            .expect("policy Ed root");
        let pq = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[0x73; 32])
            .expect("policy ML-DSA root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            NET,
            ed.public_key_to_der().expect("policy Ed public"),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().expect("policy ML-DSA public"),
        )
        .expect("root pin");
        let candidate = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: pin.fingerprint().expect("fingerprint"),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 1,
            expires: u64::MAX,
        };
        let raw = candidate.encode_tbs().expect("policy TBS");
        let message = NetworkPolicyCandidate::signature_input(&raw).expect("policy input");
        let mut ed_signer = Signer::new_without_digest(&ed).expect("policy Ed signer");
        let ed_sig = ed_signer
            .sign_oneshot_to_vec(&message)
            .expect("policy Ed signature");
        let mut pq_signer = Signer::new_without_digest(&pq).expect("policy ML-DSA signer");
        let pq_sig = pq_signer
            .sign_oneshot_to_vec(&message)
            .expect("policy ML-DSA signature");
        verify_network_policy(&raw, &ed_sig, &pq_sig, &pin, NET, NOW_US)
            .expect("signed network policy")
            .require_default_runtime()
            .expect("default runtime policy")
    })
}

/// One node's real identity material. The Ed25519 and ML-DSA private keys are
/// the node's own management-signing keys, not a test shortcut: they are the
/// keys bound into the signed `NodeIdentity`.
struct IssuedNode {
    object: VerifiedObject,
    node_id: u16,
    ed: PKey<Private>,
    ml: PKey<Private>,
}

struct NodeSpec {
    leaf: &'static str,
    home_core: u8,
    vip_octet: u8,
    generation: u64,
    role: ObjectRole,
    ed_seed: u8,
}

fn pki_role(role: ObjectRole) -> PkiNodeRole {
    match role {
        ObjectRole::Edge => PkiNodeRole::Edge,
        ObjectRole::Core => PkiNodeRole::Core,
        ObjectRole::EnrollmentService => PkiNodeRole::EnrollmentService,
    }
}

fn identity_authority() -> IdentityAuthority {
    let ed = PKey::private_key_from_raw_bytes(&[0x51; 32], Id::ED25519).expect("issuer Ed");
    let ml = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[0x52; 32])
        .expect("issuer ML-DSA");
    IdentityAuthority::from_pkcs8_der(
        NET,
        b"mesh-test-identity-authority".to_vec(),
        1,
        &ed.private_key_to_pkcs8().expect("issuer Ed PKCS8"),
        &ml.private_key_to_pkcs8().expect("issuer ML-DSA PKCS8"),
    )
    .expect("IdentityAuthority")
}

fn issue_node(
    t: &Temp,
    authority: &IdentityAuthority,
    trust: &mut ManagementTrust,
    spec: NodeSpec,
) -> IssuedNode {
    let cert = X509::from_pem(&read(t, &format!("{}.pem", spec.leaf))).expect("parse leaf");
    let cert_key = cert
        .public_key()
        .expect("leaf public key")
        .raw_public_key()
        .expect("leaf raw key");
    let ml = PKey::private_key_from_pem(&read(t, &format!("{}.key", spec.leaf)))
        .expect("leaf private key");
    let csr = X509Req::from_pem(&read(t, &format!("{}.csr", spec.leaf)))
        .expect("parse signed CSR")
        .to_der()
        .expect("CSR DER");
    let ed = PKey::private_key_from_raw_bytes(&[spec.ed_seed; 32], Id::ED25519)
        .expect("node Ed25519 key");
    let ed_public: [u8; 32] = ed
        .raw_public_key()
        .expect("node Ed25519 public")
        .try_into()
        .expect("Ed25519 length");
    let node_id = boreas_pki::node_id(spec.home_core, spec.vip_octet, pki_role(spec.role))
        .expect("node id mapping");
    let body = authority
        .node_identity_from_csr(
            IdentityTemplate {
                node_id,
                home_core_id: spec.home_core,
                vip_octet: spec.vip_octet,
                role: pki_role(spec.role),
                identity_generation: spec.generation,
                identity_pub_ed25519: ed_public,
                not_before_us: 1_000_000,
                expires_us: 9_000_000_000_000_000,
                scope: Vec::new(),
            },
            &csr,
        )
        .expect("identity body from signed CSR");
    assert_eq!(
        body.identity_pub_mldsa, cert_key,
        "certificate key is the key bound by the management identity"
    );
    let signed = authority
        .sign_node_identity(body)
        .expect("dual-sign NodeIdentity");
    let object = trust
        .verify_and_authorize(&signed.encode().expect("encode identity"), NOW_US)
        .expect("ManagementTrust verifies signature, scope, sequence and time");
    IssuedNode {
        object,
        node_id,
        ed,
        ml,
    }
}

// --- dual-signed lease and LSA objects ---------------------------------------

/// A Core's own `CoreOperationalKey`: it may only sign that Core's LSA and that
/// Core's lease countersignatures (§2.2).
struct CoreOperationalKey {
    key_id: Vec<u8>,
    core_id: u8,
    ed: PKey<Private>,
    ml: PKey<Private>,
}

fn core_operational_key(core_id: u8, seed: u8) -> CoreOperationalKey {
    let ed = PKey::private_key_from_raw_bytes(&[seed; 32], Id::ED25519).expect("core Ed25519");
    let ml = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32])
        .expect("core ML-DSA");
    CoreOperationalKey {
        key_id: format!("core-{core_id}-operational").into_bytes(),
        core_id,
        ed,
        ml,
    }
}

impl CoreOperationalKey {
    fn issuer_record(&self) -> IssuerRecord {
        IssuerRecord {
            issuer_key_id: self.key_id.clone(),
            issuer_generation: 1,
            authority: Authority::CoreOperationalKey {
                core_id: self.core_id,
            },
            ed25519_public_key_der: self.ed.public_key_to_der().expect("core Ed public"),
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der: self.ml.public_key_to_der().expect("core ML-DSA public"),
            // A CoreOperationalKey has no identity/route scope; `may_issue_for_core`
            // bounds it to its own Core.
            scope: IssuerScope::default(),
        }
    }
}

fn signer(
    role: SignerRole,
    ed: &PKey<Private>,
    ml: &PKey<Private>,
    message: &[u8],
) -> SignerSignatures {
    let mut ed_signer = Signer::new_without_digest(ed).expect("Ed25519 signer");
    let ed25519: [u8; 64] = ed_signer
        .sign_oneshot_to_vec(message)
        .expect("Ed25519 signature")
        .try_into()
        .expect("Ed25519 length");
    let mut ml_signer = Signer::new_without_digest(ml).expect("ML-DSA signer");
    SignerSignatures {
        role,
        ed25519,
        mldsa_parameter_set: MldsaParameterSet::Mldsa65,
        mldsa: ml_signer
            .sign_oneshot_to_vec(message)
            .expect("ML-DSA signature"),
    }
}

struct LeaseSpec {
    identity_generation: u64,
    attach_generation: u64,
    target_core_id: u8,
    extension: u8,
}

/// Node primary signature + attached Core countersignature over the same TBS.
fn signed_lease(core: &CoreOperationalKey, node: &IssuedNode, spec: LeaseSpec) -> Vec<u8> {
    let object = ManagementObject {
        net_id: NET,
        issuer_key_id: core.key_id.clone(),
        issuer_generation: 1,
        subject_identity: SubjectIdentity::Node(node.node_id),
        seq: spec.attach_generation,
        issued_at: 1_000_000,
        expires: 9_000_000_000_000_000,
        extensions: vec![Extension {
            id: 7,
            critical: false,
            value: vec![spec.extension],
        }],
        body: ObjectBody::AttachmentLease(AttachmentLease {
            node_id: node.node_id,
            identity_generation: spec.identity_generation,
            attach_generation: spec.attach_generation,
            target_core_id: spec.target_core_id,
            not_before: 1_000_000,
            expires: 9_000_000_000_000_000,
        }),
    };
    let raw_tbs = boreas_proto::objects::encode_tbs(&object).expect("lease TBS");
    let message = boreas_proto::objects::signature_input(
        &raw_tbs,
        ObjectType::AttachmentLease,
        MANAGEMENT_SCHEMA_VERSION,
    )
    .expect("lease signature input");
    let signers = vec![
        signer(SignerRole::Primary, &node.ed, &node.ml, &message),
        signer(SignerRole::CoSign, &core.ed, &core.ml, &message),
    ];
    SignedObject {
        object_type: ObjectType::AttachmentLease,
        raw_tbs,
        signers,
    }
    .encode()
    .expect("signed lease")
}

/// Re-sign an existing lease TBS with the same node and Core keys. The TBS is
/// unchanged; only signature bytes may differ, so this must remain a duplicate
/// and never become an equivocation.
fn resign_lease(core: &CoreOperationalKey, node: &IssuedNode, signed: &SignedObject) -> Vec<u8> {
    let message = boreas_proto::objects::signature_input(
        &signed.raw_tbs,
        signed.object_type,
        MANAGEMENT_SCHEMA_VERSION,
    )
    .expect("lease signature input");
    SignedObject {
        object_type: signed.object_type,
        raw_tbs: signed.raw_tbs.clone(),
        signers: vec![
            signer(SignerRole::Primary, &node.ed, &node.ml, &message),
            signer(SignerRole::CoSign, &core.ed, &core.ml, &message),
        ],
    }
    .encode()
    .expect("resigned lease")
}

fn signed_lsa(core: &CoreOperationalKey, core_generation: u64, seq: u64) -> Vec<u8> {
    let object = ManagementObject {
        net_id: NET,
        issuer_key_id: core.key_id.clone(),
        issuer_generation: 1,
        subject_identity: SubjectIdentity::Core(core.core_id),
        seq,
        issued_at: 1_000_000,
        expires: 9_000_000_000_000_000,
        extensions: Vec::new(),
        body: ObjectBody::CoreLsa(CoreLsa {
            core_id: core.core_id,
            core_generation,
            seq,
            neighbors: Vec::new(),
        }),
    };
    let raw_tbs = boreas_proto::objects::encode_tbs(&object).expect("LSA TBS");
    let message = boreas_proto::objects::signature_input(
        &raw_tbs,
        ObjectType::CoreLsa,
        MANAGEMENT_SCHEMA_VERSION,
    )
    .expect("LSA signature input");
    SignedObject {
        object_type: ObjectType::CoreLsa,
        raw_tbs,
        signers: vec![signer(SignerRole::Primary, &core.ed, &core.ml, &message)],
    }
    .encode()
    .expect("signed LSA")
}

// --- four-node mesh -----------------------------------------------------------

struct LeafMaterial {
    cert: Vec<u8>,
    key: Vec<u8>,
    anchor: Vec<u8>,
}

impl LeafMaterial {
    fn pem(&self) -> PemIdentity {
        PemIdentity {
            certificate_pem: self.cert.clone(),
            private_key_pem: self.key.clone(),
            trust_anchor_pem: self.anchor.clone(),
        }
    }
}

/// Everything a thread needs. Only PEM bytes, public identities and the
/// certificate-to-identity extractor are shared; no private key of the trust
/// root crosses a thread here.
struct Mesh {
    dir: &'static Temp,
    outer_ca: Vec<u8>,
    extractor: Arc<PkiIdentityExtractor>,
    leaves: BTreeMap<&'static str, LeafMaterial>,
}

struct DirectoryState {
    authority_record: IssuerRecord,
    core_record: IssuerRecord,
    core: CoreOperationalKey,
    nodes: BTreeMap<&'static str, IssuedNode>,
}

impl DirectoryState {
    /// A fresh verifier: `ManagementTrust` keeps per-node replay slots, so each
    /// replica verifies with its own instance.
    fn verifier(&self) -> PkiObjectVerifier {
        let mut trust = ManagementTrust::new(NET);
        trust
            .add_issuer(self.authority_record.clone())
            .expect("provision identity authority");
        trust
            .add_issuer(self.core_record.clone())
            .expect("provision core operational key");
        PkiObjectVerifier::new(trust)
    }
}

const LEAVES: [&str; 5] = ["edge-a", "core-b", "core-c", "edge-d", "rogue"];

fn build() -> (
    Arc<Mesh>,
    BTreeMap<&'static str, PeerIdentity>,
    DirectoryState,
) {
    let t = pki();
    let authority = identity_authority();
    let scope = IssuerScope::for_identity(vec![PkiNodeRole::Edge, PkiNodeRole::Core], vec![1, 2, 3])
        .expect("bounded identity scope");
    let authority_record = authority.issuer_record(scope).expect("authority record");
    let core = core_operational_key(2, 0x61);
    let core_record = core.issuer_record();

    let mut trust = ManagementTrust::new(NET);
    trust
        .add_issuer(authority_record.clone())
        .expect("provision identity authority");
    trust
        .add_issuer(core_record.clone())
        .expect("provision core operational key");

    let specs = [
        NodeSpec {
            leaf: "edge-a",
            home_core: 1,
            vip_octet: 2,
            generation: EDGE_GENERATION,
            role: ObjectRole::Edge,
            ed_seed: 0x71,
        },
        NodeSpec {
            leaf: "core-b",
            home_core: 2,
            vip_octet: 1,
            generation: CORE_B_GENERATION,
            role: ObjectRole::Core,
            ed_seed: 0x72,
        },
        NodeSpec {
            leaf: "core-c",
            home_core: 3,
            vip_octet: 1,
            generation: CORE_C_GENERATION,
            role: ObjectRole::Core,
            ed_seed: 0x73,
        },
        NodeSpec {
            leaf: "edge-d",
            home_core: 3,
            vip_octet: 2,
            generation: EDGE_D_GENERATION,
            role: ObjectRole::Edge,
            ed_seed: 0x74,
        },
    ];
    let mut nodes = BTreeMap::new();
    let mut peers = BTreeMap::new();
    let mut trusted = Vec::new();
    for spec in specs {
        let issued = issue_node(t, &authority, &mut trust, spec);
        let verified = VerifiedNodeIdentity::from_verified_object(
            &issued.object,
            &verified_default_policy(),
        )
        .expect("policy-bound identity");
        peers.insert(spec.leaf, verified.peer_identity());
        trusted.push(verified);
        nodes.insert(spec.leaf, issued);
    }
    let extractor = Arc::new(PkiIdentityExtractor::new(trusted).expect("unique trusted SPKIs"));

    let anchor = read(t, "id-ca.pem");
    let leaves = LEAVES
        .iter()
        .map(|leaf| {
            (
                *leaf,
                LeafMaterial {
                    cert: read(t, &format!("{leaf}.pem")),
                    key: read(t, &format!("{leaf}.key")),
                    anchor: anchor.clone(),
                },
            )
        })
        .collect();
    let mesh = Mesh {
        dir: t,
        outer_ca: read(t, "outer-ca.pem"),
        extractor,
        leaves,
    };
    (
        Arc::new(mesh),
        peers,
        DirectoryState {
            authority_record,
            core_record,
            core,
            nodes,
        },
    )
}

impl Mesh {
    fn leaf(&self, name: &str) -> &LeafMaterial {
        self.leaves.get(name).expect("provisioned leaf")
    }

    fn outer_connector(&self) -> Result<OpenSslOuterTlsConnector, String> {
        OpenSslOuterTlsConnector::with_root_certificates(&self.outer_ca).map_err(|e| e.to_string())
    }

    fn outer_acceptor(&self) -> Result<OpenSslOuterTlsAcceptor, String> {
        OpenSslOuterTlsAcceptor::from_pem_files(self.dir.path("outer.pem"), self.dir.path("outer.key"))
            .map_err(|e| e.to_string())
    }

    fn inner_connector(&self, name: &str) -> Result<OpenSslInnerConnector, String> {
        let identity = self.leaf(name).pem();
        let connector = OpenSslConnector::from_pem_identity(&identity, Policy::production_default())
            .map_err(|e| e.to_string())?;
        Ok(OpenSslInnerConnector::new(connector, self.extractor.clone()))
    }

    fn inner_acceptor(&self, name: &str) -> Result<OpenSslInnerAcceptor, String> {
        let identity = self.leaf(name).pem();
        let acceptor = OpenSslAcceptor::from_pem_identity(&identity, Policy::production_default())
            .map_err(|e| e.to_string())?;
        Ok(OpenSslInnerAcceptor::new(acceptor, self.extractor.clone()))
    }

    fn e2e_backend(&self, name: &str) -> Result<OpenSslE2eBackend, String> {
        let identity = self.leaf(name).pem();
        let connector = OpenSslConnector::from_pem_identity(&identity, Policy::production_default())
            .map_err(|e| e.to_string())?;
        let acceptor = OpenSslAcceptor::from_pem_identity(&identity, Policy::production_default())
            .map_err(|e| e.to_string())?;
        Ok(OpenSslE2eBackend::new(
            Arc::new(connector),
            Arc::new(acceptor),
            self.extractor.clone(),
        ))
    }
}

// --- session helpers ----------------------------------------------------------

fn admission() -> Admission {
    Admission::new(Limits {
        handshakes_global: 16,
        authenticated_global: 16,
        authenticated_per_peer: 8,
        bytes_global: 8 * 1024 * 1024,
    })
}

fn policy(local: PeerIdentity, peer: PeerIdentity) -> SessionPolicy {
    SessionPolicy {
        local,
        expected_peer: peer,
        path_role: PathRole::Cdn,
        security_mode: SecurityMode::E2eRequired,
        suite: MessageSuite::Pq768,
        mtu_cap: 1400,
        identity_registered: true,
        allow_pq1024: false,
        allow_hop_only: false,
        allowed_peer_roles: vec![peer.role],
    }
}

fn target(address: SocketAddr) -> ClientTarget {
    ClientTarget {
        address,
        ws_host: format!("{HOST}:443"),
        tls_server_name: HOST.to_owned(),
        path: "/tunnel".into(),
    }
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

fn accept_one(
    listener: &TcpListener,
    mesh: &Mesh,
    leaf: &str,
    local: PeerIdentity,
    expected_peer: PeerIdentity,
) -> Result<AcceptedSession, String> {
    let tcp = bounded_accept(listener)?;
    let outer = mesh.outer_acceptor()?;
    let inner = mesh.inner_acceptor(leaf)?;
    let admission = admission();
    LinkServer::new(Box::new(inner))
        .accept_tls_stream(
            tcp,
            &outer,
            policy(local, expected_peer),
            IO_TIMEOUT,
            &admission,
        )
        .map_err(|e| format!("accept as {leaf}: {e}"))
}

fn connect(
    mesh: &Mesh,
    leaf: &str,
    local: PeerIdentity,
    address: SocketAddr,
    expected_peer: PeerIdentity,
) -> Result<boreas_tunnel::EstablishedSession, String> {
    let outer = mesh.outer_connector()?;
    let inner = mesh.inner_connector(leaf)?;
    LinkClient::new(Box::new(outer), Box::new(inner))
        .connect(&target(address), policy(local, expected_peer), IO_TIMEOUT)
        .map_err(|e| format!("connect as {leaf}: {e}"))
}

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 7 + (index >> 5) * 13 + 5) % 251) as u8)
        .collect()
}

/// What one relay actually did, from its own counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelayReport {
    forwarded: usize,
    active: usize,
}

/// Business bytes carried through the E2E TLS circuit in the direct-hop test.
const E2E_PAYLOAD: usize = 64 * 1024;

// --- tests --------------------------------------------------------------------

#[test]
fn authenticated_edge_core_and_core_core_sessions_bind_verified_identities() {
    let (mesh, peers, _state) = build();
    let a = peers["edge-a"];
    let b = peers["core-b"];
    let c = peers["core-c"];
    assert_eq!(a.node_id, 0x0002, "edge home Core 1, VIP octet 2");
    assert_eq!(b.node_id, 0x0101, "Core 2, VIP octet 1");
    assert_eq!(c.node_id, 0x0201, "Core 3, VIP octet 1");

    for (client, client_peer, server, server_peer) in [
        ("edge-a", a, "core-b", b),
        ("core-b", b, "core-c", c),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let server_thread = {
            let mesh = Arc::clone(&mesh);
            thread::spawn(move || {
                let accepted = accept_one(&listener, &mesh, server, server_peer, client_peer)?;
                let session = &accepted.session;
                Ok::<_, String>((
                    session.peer(),
                    session.local(),
                    session.security_suite(),
                    session.mtu_cap(),
                ))
            })
        };
        let session = connect(&mesh, client, client_peer, address, server_peer)
            .unwrap_or_else(|e| panic!("{client} -> {server}: {e}"));
        assert_eq!(session.peer(), server_peer);
        assert_eq!(session.local(), client_peer);
        assert_eq!(session.security_suite(), MessageSuite::Pq768);
        assert_eq!(session.mtu_cap(), 1400);
        let (peer, local, suite, mtu) = server_thread
            .join()
            .expect("join server thread")
            .expect("server session");
        assert_eq!(peer, client_peer, "{server} authenticated {client}");
        assert_eq!(local, server_peer);
        assert_eq!(suite, MessageSuite::Pq768);
        assert_eq!(mtu, 1400);
    }
}

#[test]
fn session_authorization_refuses_wrong_generation_and_unprovisioned_identity() {
    let (mesh, peers, _state) = build();
    let a = peers["edge-a"];
    let b = peers["core-b"];

    // The client expects one generation higher than the certificate proves. The
    // peer's TLS session is genuine, but the local expectation is not met, so no
    // session may be exposed to the client.
    let mut wrong_generation = b;
    wrong_generation.identity_generation += 1;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    let server_thread = {
        let mesh = Arc::clone(&mesh);
        thread::spawn(move || accept_one(&listener, &mesh, "core-b", b, a).map(|_| ()))
    };
    let refused = connect(&mesh, "edge-a", a, address, wrong_generation);
    assert!(
        refused.is_err(),
        "a mismatched identity generation must not authorize a session"
    );
    // The server side authenticated the real client; only the caller's own wrong
    // expectation was refused, so its outcome is not asserted here.
    let _ = server_thread.join();

    // Same CA, but this leaf was never provisioned into the extractor, so no
    // signed identity backs it.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    let server_thread = {
        let mesh = Arc::clone(&mesh);
        thread::spawn(move || accept_one(&listener, &mesh, "core-b", b, a).map(|_| ()))
    };
    let impostor = connect(&mesh, "rogue", a, address, b);
    assert!(
        impostor.is_err(),
        "an unprovisioned certificate must not become a node identity"
    );
    assert!(
        server_thread.join().expect("join server thread").is_err(),
        "the acceptor's extractor must reject the unprovisioned leaf"
    );
}

#[test]
fn single_hop_relay_forwards_circuit_frames_over_two_tls_sessions() {
    let (mesh, peers, _state) = build();
    let a = peers["edge-a"];
    let b = peers["core-b"];
    let d = peers["edge-d"];

    // One Core relay is two link hops: edge-a -> core-b -> edge-d. The planner
    // is a bounded model, not a route authorization; the two TLS sessions below
    // authenticate every hop independently.
    let now = Instant::now();
    let topology = MeshTopology::new(2, now).expect("core 2 view");
    let path = topology.path(2, 2).expect("single Core path");
    let hops = path.relay_hops().expect("relay hop budget");
    assert_eq!(path.cores(), &[2u8][..]);
    assert_eq!(hops, 2, "edge -> core-b -> edge is two hops");

    let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind core-b");
    let address_b = listener_b.local_addr().expect("core-b address");

    // core-b relays between edge-a (upstream) and edge-d (downstream). The
    // accept order is fixed: edge-a connects first, then edge-d.
    let relay = {
        let mesh = Arc::clone(&mesh);
        thread::spawn(move || -> Result<RelayReport, String> {
            let mut upstream = accept_one(&listener_b, &mesh, "core-b", b, a)?;
            let mut downstream = accept_one(&listener_b, &mesh, "core-b", b, d)?;
            let mut hop = RelayHop::new(admission(), 8, b).map_err(|e| e.to_string())?;
            let mut forwarded = 0usize;
            loop {
                match hop.relay_once(&mut upstream.session, &mut downstream.session, Instant::now()) {
                    Ok(RelayProgress::Continue) => forwarded += 1,
                    Ok(RelayProgress::CircuitClosed) => {
                        forwarded += 1;
                        break;
                    }
                    Err(error) => return Err(format!("relay core-b: {error}")),
                }
            }
            Ok(RelayReport {
                forwarded,
                active: hop.active_circuits(),
            })
        })
    };

    // Connect the upstream opener first, so core-b's two accepts have a fixed
    // order even though the downstream endpoint is a separate thread.
    let expected = payload(150_000);
    let mut session = connect(&mesh, "edge-a", a, address_b, b).expect("edge-a session to core-b");

    let endpoint_d = {
        let mesh = Arc::clone(&mesh);
        thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut session = connect(&mesh, "edge-d", d, address_b, b)?;
            let (mut circuit, info) = accept_circuit(&mut session).map_err(|e| e.to_string())?;
            assert_eq!(info.path_hops, hops, "the acceptor learns the declared path");
            let mut received = Vec::new();
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let read = circuit
                    .read_bytes(&mut buffer)
                    .map_err(|e| format!("edge-d read: {e}"))?;
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..read]);
            }
            Ok(received)
        })
    };

    let mut written = 0usize;
    {
        let (mut circuit, info) = open_circuit(
            &mut session,
            NodeRef {
                node_id: d.node_id,
                identity_generation: d.identity_generation,
            },
            hops,
        )
        .expect("open circuit through core-b");
        assert_eq!(info.path_hops, hops);
        while written < expected.len() {
            written += circuit
                .write_bytes(&expected[written..])
                .expect("write circuit fragment");
        }
        circuit.finish().expect("close circuit");
    }
    let received = endpoint_d.join().expect("join edge-d").expect("edge-d path");
    let report = relay.join().expect("join core-b").expect("core-b path");
    assert_eq!(sha256(&received), sha256(&expected));
    assert_eq!(received.len(), expected.len());
    assert_eq!(written, expected.len());
    // The open, every data fragment and the close crossed the single relay,
    // and it did not leak a circuit after the close.
    assert!(report.forwarded >= 5, "forwarded frames: {report:?}");
    assert_eq!(report.active, 0, "circuit still active after close");
}

#[test]
fn e2e_tls_runs_over_one_authenticated_hop_session() {
    let (mesh, peers, _state) = build();
    let a = peers["edge-a"];
    let b = peers["core-b"];
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("listener address");

    let server = {
        let mesh = Arc::clone(&mesh);
        thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut accepted = accept_one(&listener, &mesh, "core-b", b, a)?;
            let backend = mesh.e2e_backend("core-b")?;
            let mut e2e = accept_e2e(&mut accepted.session, &backend, a)
                .map_err(|e| format!("accept E2E: {e}"))?;
            let mut received = vec![0u8; E2E_PAYLOAD];
            e2e.read_exact(&mut received)
                .map_err(|e| format!("E2E business stream: {e}"))?;
            Ok(received)
        })
    };

    let expected = payload(E2E_PAYLOAD);
    let mut session = connect(&mesh, "edge-a", a, address, b).expect("edge-a session");
    let backend = mesh.e2e_backend("edge-a").expect("edge-a E2E backend");
    let mut e2e = open_e2e(&mut session, &backend, b, 1).expect("open E2E circuit");
    assert_eq!(e2e.info().peer, b);
    e2e.write_all(&expected).expect("write E2E business bytes");
    // `close_notify` gives the peer a clean end of stream, not a truncated record.
    e2e.close_gracefully();
    drop(e2e);
    let received = server.join().expect("join core-b").expect("core-b path");
    assert_eq!(sha256(&received), sha256(&expected));
    assert_eq!(received, expected);
}

#[test]
fn directory_converges_from_dual_signed_objects_over_bounded_pages() {
    let (_mesh, peers, state) = build();
    let node_a = &state.nodes["edge-a"];
    let subject = node_a.node_id;
    let lease_key = DirectoryKey {
        kind: DirectoryObjectKind::AttachmentLease,
        subject,
    };
    assert_eq!(
        boreas_tunnel::directory::home_core_id_for_node(subject),
        Some(1),
        "home Core comes only from the permanent NodeIdentity"
    );

    let lease = signed_lease(
        &state.core,
        node_a,
        LeaseSpec {
            identity_generation: EDGE_GENERATION,
            attach_generation: 1,
            target_core_id: 2,
            extension: 1,
        },
    );
    let lsa = signed_lsa(&state.core, 1, 1);
    let identity = node_a.object.raw_signed_object().to_vec();

    let mut source = DirectoryIngest::new(state.verifier());
    assert!(source.verify_and_apply(&identity, NOW_US).is_applied());
    assert!(source.verify_and_apply(&lsa, NOW_US).is_applied());
    assert!(source.verify_and_apply(&lease, NOW_US).is_applied());
    assert_eq!(
        source
            .directory()
            .get(lease_key)
            .expect("lease active")
            .target_core_id,
        Some(2)
    );

    // An unverifiable object is refused before convergence, whatever it claims.
    let mut forged = lease.clone();
    forged[0] ^= 0xFF;
    assert!(source.verify_and_apply(&forged, NOW_US).is_rejected());
    assert_eq!(
        source
            .directory()
            .get(lease_key)
            .expect("the real lease stays active")
            .payload,
        lease
    );

    // `content_hash` is SHA-256 of the exact TBS, never of the signature
    // envelope. Re-signing the same TBS with the same keys changes only
    // signature bytes; the directory must see a duplicate, not a fork.
    let signed = SignedObject::decode(&lease).expect("lease envelope");
    assert_eq!(
        source
            .directory()
            .get(lease_key)
            .expect("lease active")
            .content_hash,
        sha256(&signed.raw_tbs)
    );
    assert_ne!(sha256(&signed.raw_tbs), sha256(&lease));
    let resigned = resign_lease(&state.core, node_a, &signed);
    assert_eq!(
        SignedObject::decode(&resigned)
            .expect("resigned envelope")
            .raw_tbs,
        signed.raw_tbs
    );
    assert_eq!(
        source.verify_and_apply(&resigned, NOW_US),
        IngestOutcome::Verified(ApplyOutcome::Duplicate)
    );
    assert_eq!(source.stats().equivocated, 0);
    // A duplicate may canonicalize which exact envelope is retained for the
    // same TBS. Capture it so the later fork evidence check compares against
    // the replica's actual retained original, not an assumed one.
    let retained_after_resign = source
        .directory()
        .get(lease_key)
        .expect("lease active after re-sign")
        .payload
        .clone();

    // A second replica converges from the bounded pages, in reverse order, and
    // the periodic repeat changes nothing. Each page travels on the candidate
    // `DirectoryPage` control body and is re-verified object by object.
    let snapshot = source.snapshot();
    let pages: Vec<_> = page_snapshot(&snapshot).collect();
    assert!(!pages.is_empty());
    let mut replica = DirectoryIngest::new(state.verifier());
    for page in pages.iter().rev() {
        let body = page.encode_wire().expect("candidate page body");
        let wire_page = SignedObjectPage::decode_wire(&body).expect("decode page body");
        assert_eq!(&wire_page, page);
        let outcome = replica.ingest_page(&wire_page, NOW_US);
        // The trust layer may refuse an object whose prerequisite has not been
        // verified on this replica yet; that is a local ordering fact, not a
        // directory divergence, and the next pass closes it.
        assert_eq!(outcome.page_seq, page.page_seq);
        assert_eq!(outcome.over_limit, 0);
        assert_eq!(outcome.outcomes.len(), page.records.len());
    }
    for page in &pages {
        let body = page.encode_wire().expect("candidate page body");
        let wire_page = SignedObjectPage::decode_wire(&body).expect("decode page body");
        replica.ingest_page(&wire_page, NOW_US);
    }
    assert_eq!(replica.snapshot(), snapshot);
    assert_eq!(replica.stats().equivocated, 0);

    // Same writer, same version, different signed bytes: both originals are
    // preserved and the object is isolated (§3.3).
    let forked = signed_lease(
        &state.core,
        node_a,
        LeaseSpec {
            identity_generation: EDGE_GENERATION,
            attach_generation: 1,
            target_core_id: 2,
            extension: 2,
        },
    );
    assert_ne!(forked, lease);
    let fork_outcome = source.verify_and_apply(&forked, NOW_US);
    assert!(
        fork_outcome.is_equivocation(),
        "a same-version fork is isolated, not silently accepted: {fork_outcome:?}"
    );
    assert_eq!(
        source.directory().status(lease_key),
        KeyStatus::Poisoned,
        "the conflicting object is frozen out of the active view"
    );
    let evidence = source
        .evidence()
        .iter()
        .next()
        .expect("fork evidence retained");
    assert_eq!(evidence.key, lease_key);
    assert_eq!(
        evidence.retained.as_deref(),
        Some(retained_after_resign.as_slice())
    );
    assert_eq!(evidence.conflicting, forked);
    assert_eq!(source.evidence().dropped(), 0);
    // The peer identities are the ones the signed objects bind, not wire claims.
    assert_eq!(peers["edge-a"].node_id, subject);
    assert_eq!(peers["edge-a"].identity_generation, EDGE_GENERATION);
}
