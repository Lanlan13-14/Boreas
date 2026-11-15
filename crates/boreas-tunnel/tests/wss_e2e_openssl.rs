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
use boreas_proto::{SecurityMode, messages::PathRole, objects::NodeRole as ObjectRole};
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
const MINIMAL_CNF: &str = "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\nactivate = 1\n";

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

fn openssl(t: &Temp, args: &[&str]) {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.replace("@DIR@", t.0.to_str().expect("temp path")))
        .collect();
    let bin = std::env::var_os("BOREAS_OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    // Fixture generation is test-only, but still bounded so a stuck provider cannot hang CI.
    let mut child = Command::new(bin)
        .env("OPENSSL_CONF", t.path("openssl.cnf"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start OpenSSL fixture generator");
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match child.try_wait().expect("poll OpenSSL fixture process") {
            Some(status) => {
                assert!(
                    status.success(),
                    "OpenSSL fixture generation failed ({:?}); output suppressed",
                    status.code()
                );
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
fn make_ca(t: &Temp, name: &str, algorithm: &str, subject: &str) {
    openssl(
        t,
        &[
            "genpkey",
            "-algorithm",
            algorithm,
            "-out",
            &format!("@DIR@/{name}-ca.key"),
        ],
    );
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
fn make_leaf(t: &Temp, ca: &str, stem: &str, algorithm: &str, spec: LeafSpec<'_>) {
    openssl(
        t,
        &[
            "genpkey",
            "-algorithm",
            algorithm,
            "-out",
            &format!("@DIR@/{stem}.key"),
        ],
    );
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
    make_ca(t, "outer", "RSA:2048", "/CN=Loopback WebPKI Test Root");
    make_leaf(
        t,
        "outer",
        "outer",
        "RSA:2048",
        LeafSpec {
            cn: "wss.boreas.test",
            eku: "serverAuth",
            san: "DNS:wss.boreas.test",
            serial: "101",
        },
    );
    make_ca(t, "id", "ML-DSA-65", "/CN=Boreas Test Identity Root");
    make_leaf(
        t,
        "id",
        "edge",
        "ML-DSA-65",
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
        "ML-DSA-65",
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
        "ML-DSA-65",
        LeafSpec {
            cn: "unknown.boreas.test",
            eku: "clientAuth,serverAuth",
            san: "DNS:unknown.boreas.test",
            serial: "203",
        },
    );
    make_ca(t, "rogue", "ML-DSA-65", "/CN=Untrusted Boreas Test Root");
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
    let value =
        VerifiedNodeIdentity::from_verified_object(object).expect("verified management identity");
    PeerIdentity {
        net_id: value.net_id(),
        node_id: value.node_id(),
        identity_generation: value.identity_generation(),
        role: value.role(),
    }
}
fn extractor(a: &VerifiedObject, b: &VerifiedObject) -> Arc<PkiIdentityExtractor> {
    Arc::new(
        PkiIdentityExtractor::new(vec![
            VerifiedNodeIdentity::from_verified_object(a).expect("verified A"),
            VerifiedNodeIdentity::from_verified_object(b).expect("verified B"),
        ])
        .expect("unique trusted SPKIs"),
    )
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
