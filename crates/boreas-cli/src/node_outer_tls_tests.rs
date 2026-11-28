//! Explicit transport policy and outer TLS trust regression tests.
#![cfg(feature = "openssl-inner-tls")]

use std::{fs, net::{TcpListener, TcpStream}, path::Path, process::Command,
    sync::atomic::{AtomicU64, Ordering}, thread, time::Duration};
use boreas_tunnel::{OpenSslOuterTlsAcceptor, OuterTlsAcceptor, OuterTlsConnector};
use openssl::{asn1::Asn1Time, bn::{BigNum, MsbOption}, hash::MessageDigest,
    pkey::PKey, rsa::Rsa, x509::{X509, X509NameBuilder, extension::{BasicConstraints, SubjectAlternativeName}}};

struct NeverInner;
impl boreas_tunnel::InnerTlsConnector for NeverInner {
    fn connect(&self, _: Box<dyn boreas_tunnel::stream::Duplex>) -> Result<boreas_tunnel::EstablishedInner, boreas_tunnel::TunnelError> {
        panic!("unexpected inner handshake")
    }
}

#[test]
fn transport_mode_does_not_depend_on_ca_presence() {
    use super::OuterTransport;
    use boreas_tunnel::TransportMode;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!("boreas-mode-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&dir).unwrap();
    assert_eq!(OuterTransport::Wss.link_client(&dir, Box::new(NeverInner)).unwrap().mode(), TransportMode::Wss);
    assert_eq!(OuterTransport::Direct.link_client(&dir, Box::new(NeverInner)).unwrap().mode(), TransportMode::Direct);
    fs::write(dir.join("outer-ca.pem"), b"invalid").unwrap();
    assert!(OuterTransport::Wss.link_client(&dir, Box::new(NeverInner)).is_err());
    assert_eq!(OuterTransport::Direct.link_client(&dir, Box::new(NeverInner)).unwrap().mode(), TransportMode::Direct);
    fs::remove_dir_all(dir).unwrap();
}

fn make_certificate(dir: &Path) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "wss.boreas.test").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    cert.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns("wss.boreas.test")
        .build(&cert.x509v3_context(None, None)).unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    fs::write(dir.join("outer.pem"), cert.build().to_pem().unwrap()).unwrap();
    fs::write(dir.join("outer.key"), key.private_key_to_pem_pkcs8().unwrap()).unwrap();
}

fn handshake(dir: &Path, connector: &dyn OuterTlsConnector, name: &str) -> bool {
    let acceptor = OpenSslOuterTlsAcceptor::from_pem_files(dir.join("outer.pem"), dir.join("outer.key")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        acceptor.accept(socket).is_ok()
    });
    let socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let client_ok = connector.connect(socket, name).is_ok();
    let server_ok = server.join().unwrap();
    if client_ok { assert!(server_ok); }
    client_ok
}

// Run in an isolated process: OpenSSL consumes SSL_CERT_FILE/DIR globally.
#[test]
fn outer_tls_child() {
    let Some(dir) = std::env::var_os("BOREAS_TLS_TEST_DIR") else { return };
    let dir = Path::new(&dir);
    let default_root_installed = std::env::var_os("BOREAS_TLS_TEST_TRUSTED").is_some();
    let public = super::outer_connector(dir).unwrap();
    assert_eq!(handshake(dir, &public, "wss.boreas.test"), default_root_installed);
    assert!(!handshake(dir, &public, "wrong.boreas.test"));
    fs::copy(dir.join("outer.pem"), dir.join("outer-ca.pem")).unwrap();
    let private = super::outer_connector(dir).unwrap();
    assert!(handshake(dir, &private, "wss.boreas.test"));
    assert!(!handshake(dir, &private, "wrong.boreas.test"));
    assert_eq!(super::OuterTransport::Wss.link_client(dir, Box::new(NeverInner)).unwrap().mode(), boreas_tunnel::TransportMode::Wss);
    assert_eq!(super::OuterTransport::Direct.link_client(dir, Box::new(NeverInner)).unwrap().mode(), boreas_tunnel::TransportMode::Direct);
    fs::remove_file(dir.join("outer-ca.pem")).unwrap();
    fs::write(dir.join("outer-ca.pem"), b"not a PEM root").unwrap();
    assert!(super::outer_connector(dir).is_err());
    fs::remove_file(dir.join("outer-ca.pem")).unwrap();
    fs::write(dir.join(if default_root_installed { "trusted.ok" } else { "untrusted.ok" }), b"ok").unwrap();
}

#[test]
fn outer_tls_system_roots_private_roots_and_hostname() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!("boreas-trust-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&dir).unwrap();
    fs::create_dir(dir.join("empty-roots")).unwrap();
    make_certificate(&dir);
    fs::write(dir.join("empty.pem"), b"").unwrap();
    for trusted in [false, true] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "node::outer_tls_tests::outer_tls_child", "--nocapture"])
            .env("BOREAS_TLS_TEST_DIR", &dir)
            .env("SSL_CERT_DIR", dir.join("empty-roots"))
            .env("SSL_CERT_FILE", dir.join(if trusted { "outer.pem" } else { "empty.pem" }));
        if trusted { child.env("BOREAS_TLS_TEST_TRUSTED", "1"); }
        else { child.env_remove("BOREAS_TLS_TEST_TRUSTED"); }
        let status = child.status().unwrap();
        assert!(status.success(), "isolated outer TLS case failed: trusted={trusted}");
        assert!(dir.join(if trusted { "trusted.ok" } else { "untrusted.ok" }).is_file(), "isolated TLS test was not selected");
    }
    fs::remove_dir_all(dir).unwrap();
}
