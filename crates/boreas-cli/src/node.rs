//! One configured Boreas hop node (master plan §1.1 and §5.5).
//!
//! `node serve` is the Core listener. `node connect` is the Edge uplink.
//! Required configuration is taken from the existing fail-closed parser: a
//! missing value rejects startup and is not replaced by a default.
//!
//! The default binary reports that it has no TLS backend and exits without
//! opening a socket. The `openssl-inner-tls` feature links the reviewed
//! OpenSSL pq768 backend, verifies dual-signed NodeIdentity objects, and
//! runs exactly one outer TLS 1.3 session plus one hop inner TLS session.
//! That is not multi-core topology, not E2E relay, not a production daemon,
//! and not a passed gate.

#[cfg(feature = "openssl-inner-tls")]
use std::net::SocketAddr;
#[cfg(feature = "openssl-inner-tls")]
use std::path::Path;

#[cfg(feature = "openssl-inner-tls")]
use crate::config::NodeRole as ConfigRole;

#[path = "mesh_probe.rs"]
mod mesh_probe;
pub use mesh_probe::SYNTAX as MESH_PROBE_SYNTAX;

pub fn run(args: &[String]) -> (u8, String, String) {
    match args.first().map(String::as_str) {
        Some("mesh-probe") => mesh_probe::run(&args[1..]),
        Some("serve") if args.len() == 4 => serve(&args[1], &args[2], &args[3]),
        Some("connect") if args.len() == 5 => connect(&args[1], &args[2], &args[3], &args[4]),
        Some("serve") => (
            2,
            String::new(),
            "error: node serve <config> <listen> <material-dir>".into(),
        ),
        Some("connect") => (
            2,
            String::new(),
            "error: node connect <config> <host:port> <tls-name> <material-dir>".into(),
        ),
        Some(command) => (
            2,
            String::new(),
            format!("error: unknown node command `{command}`"),
        ),
        None => (
            2,
            String::new(),
            "error: node requires serve or connect".into(),
        ),
    }
}

#[cfg(not(feature = "openssl-inner-tls"))]
fn no_backend(command: &str) -> (u8, String, String) {
    (
        2,
        String::new(),
        format!(
            "error: node {command} requires the openssl-inner-tls build; this binary has no TLS backend and no daemon was started"
        ),
    )
}

#[cfg(not(feature = "openssl-inner-tls"))]
fn serve(_config_path: &str, _listen: &str, _material_dir: &str) -> (u8, String, String) {
    no_backend("serve")
}

#[cfg(not(feature = "openssl-inner-tls"))]
fn connect(
    _config_path: &str,
    _endpoint: &str,
    _tls_name: &str,
    _material_dir: &str,
) -> (u8, String, String) {
    no_backend("connect")
}

#[cfg(any(test, feature = "openssl-inner-tls"))]
fn valid_tls_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.contains(':')
        && !name.contains('/')
        && !name.contains(' ')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

#[cfg(feature = "openssl-inner-tls")]
const MAX_MATERIAL_FILE: usize = 16 * 1024;
#[cfg(feature = "openssl-inner-tls")]
const MAX_ISSUER_KEY_ID: usize = 64;
#[cfg(feature = "openssl-inner-tls")]
const MAX_PUBLIC_KEY_DER: usize = 4096;

#[cfg(feature = "openssl-inner-tls")]
struct Prepared {
    config: crate::config::Config,
    local_role: crate::config::NodeRole,
}

#[cfg(feature = "openssl-inner-tls")]
fn finish(result: Result<String, String>) -> (u8, String, String) {
    match result {
        Ok(report) => (0, report, String::new()),
        Err(message) => (2, String::new(), message),
    }
}

#[cfg(feature = "openssl-inner-tls")]
fn node_capabilities() -> crate::config::RuntimeCapabilities {
    crate::config::RuntimeCapabilities {
        dns_tcp: false,
        control_socket: false,
        e2e_relay: false,
    }
}

#[cfg(feature = "openssl-inner-tls")]
fn parse_socket(text: &str) -> Result<std::net::SocketAddr, String> {
    text.parse()
        .map_err(|_| format!("error: `{text}` is not an IP host:port address"))
}

#[cfg(feature = "openssl-inner-tls")]
fn prepare(config_path: &str, server: bool) -> Result<Prepared, String> {
    use crate::config::{CryptoSuite, NodeRole as ConfigRole, SecurityMode as ConfigMode};

    let config =
        crate::config::Config::read_file(std::path::Path::new(config_path), node_capabilities())
            .map_err(|error| format!("error: configuration rejected: {error}"))?;
    if config.security.suite != CryptoSuite::Pq768 {
        return Err("error: only suite pq768 is enabled; pq1024 has no accepted PoC".into());
    }
    if config.security.mode == ConfigMode::HopOnly {
        return Err(
            "error: hop-only requires interactive HOP-ONLY confirmation; refusing non-interactive start"
                .into(),
        );
    }
    let local_role = config.identity.role;
    if server && local_role != ConfigRole::Core {
        return Err("error: node serve requires role core".into());
    }
    if !server && local_role != ConfigRole::Edge {
        return Err("error: node connect requires role edge".into());
    }
    if local_role == ConfigRole::EnrollmentService {
        return Err("error: enrollment role cannot run the hop node".into());
    }
    Ok(Prepared { config, local_role })
}

#[cfg(feature = "openssl-inner-tls")]
fn serve(config_path: &str, listen: &str, material_dir: &str) -> (u8, String, String) {
    let prepared = match prepare(config_path, true) {
        Ok(value) => value,
        Err(message) => return (2, String::new(), message),
    };
    let address = match parse_socket(listen) {
        Ok(value) => value,
        Err(message) => return (2, String::new(), message),
    };
    finish(serve_backend(
        &prepared,
        address,
        std::path::Path::new(material_dir),
    ))
}

#[cfg(feature = "openssl-inner-tls")]
fn connect(
    config_path: &str,
    endpoint: &str,
    tls_name: &str,
    material_dir: &str,
) -> (u8, String, String) {
    if !valid_tls_name(tls_name) {
        return (
            2,
            String::new(),
            "error: TLS server name must be a bare DNS host".into(),
        );
    }
    let prepared = match prepare(config_path, false) {
        Ok(value) => value,
        Err(message) => return (2, String::new(), message),
    };
    let address = match parse_socket(endpoint) {
        Ok(value) => value,
        Err(message) => return (2, String::new(), message),
    };
    finish(connect_backend(
        &prepared,
        address,
        tls_name,
        std::path::Path::new(material_dir),
    ))
}

#[cfg(feature = "openssl-inner-tls")]
fn decode_net_id(text: &str) -> Result<[u8; 16], String> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("error: net_id must be 32 hexadecimal digits".into());
    }
    let mut out = [0u8; 16];
    for index in 0..16 {
        out[index] = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "error: net_id must be hexadecimal".to_string())?;
    }
    Ok(out)
}

#[cfg(feature = "openssl-inner-tls")]
fn read_bounded(dir: &Path, name: &str, max: usize) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    let bytes =
        std::fs::read(&path).map_err(|_| format!("error: cannot read `{}`", path.display()))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(format!(
            "error: `{}` must be between 1 and {max} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "openssl-inner-tls")]
fn unix_now_us() -> Result<u64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "error: system clock is before Unix epoch".to_string())?;
    u64::try_from(duration.as_micros())
        .map_err(|_| "error: system clock is out of range".to_string())
}

#[cfg(feature = "openssl-inner-tls")]
fn serve_backend(
    prepared: &Prepared,
    address: SocketAddr,
    material_dir: &Path,
) -> Result<String, String> {
    use std::sync::Arc;
    use std::time::Duration;

    use boreas_crypto::Policy;
    use boreas_crypto::backend::{OpenSslAcceptor, PemIdentity};
    use boreas_proto::SecurityMode;
    use boreas_proto::messages::{PathRole, Suite as MessageSuite};
    use boreas_tunnel::resource::{Admission, Limits};
    use boreas_tunnel::runtime::LinkServer;
    use boreas_tunnel::{
        OpenSslInnerAcceptor, OpenSslOuterTlsAcceptor, PkiIdentityExtractor, SessionPolicy,
    };

    let identities = load_verified_identities(prepared, material_dir)?;
    let identity = PemIdentity::from_pem_files(
        material_dir.join("identity.pem"),
        material_dir.join("identity.key"),
        material_dir.join("identity-ca.pem"),
    )
    .map_err(|error| format!("error: local identity PEM rejected: {error}"))?;
    let inner = OpenSslAcceptor::from_pem_identity(&identity, Policy::production_default())
        .map_err(|error| format!("error: inner TLS acceptor rejected: {error}"))?;
    let extractor = Arc::new(
        PkiIdentityExtractor::new(vec![identities.local.clone(), identities.peer.clone()])
            .map_err(|error| format!("error: peer extractor rejected: {error}"))?,
    );
    let server = LinkServer::new(Box::new(OpenSslInnerAcceptor::new(inner, extractor)));
    let outer = OpenSslOuterTlsAcceptor::from_pem_files(
        material_dir.join("outer.pem"),
        material_dir.join("outer.key"),
    )
    .map_err(|error| format!("error: outer TLS acceptor rejected: {error}"))?;
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| format!("error: cannot listen on {address}: {error}"))?;
    let admission = Admission::new(Limits {
        handshakes_global: 4,
        authenticated_global: 4,
        authenticated_per_peer: 1,
        bytes_global: 1024 * 1024,
    });
    let policy = SessionPolicy {
        local: identities.local_peer(),
        expected_peer: identities.peer_peer(),
        path_role: PathRole::Cdn,
        security_mode: SecurityMode::E2eRequired,
        suite: MessageSuite::Pq768,
        mtu_cap: 1400,
        identity_registered: true,
        allow_pq1024: false,
        allow_hop_only: false,
        allowed_peer_roles: vec![identities.peer.role()],
    };
    policy
        .validate()
        .map_err(|error| format!("error: session policy rejected: {error}"))?;
    let accepted = server
        .accept_tls(
            &listener,
            &outer,
            policy,
            Duration::from_secs(20),
            &admission,
        )
        .map_err(|error| format!("error: hop session failed: {error}"))?;
    Ok(report("serve", &accepted.session))
}

#[cfg(feature = "openssl-inner-tls")]
fn connect_backend(
    prepared: &Prepared,
    address: SocketAddr,
    tls_name: &str,
    material_dir: &Path,
) -> Result<String, String> {
    use std::sync::Arc;
    use std::time::Duration;

    use boreas_crypto::Policy;
    use boreas_crypto::backend::{OpenSslConnector, PemIdentity};
    use boreas_proto::SecurityMode;
    use boreas_proto::messages::{PathRole, Suite as MessageSuite};
    use boreas_tunnel::runtime::{ClientTarget, LinkClient};
    use boreas_tunnel::{
        OpenSslInnerConnector, OpenSslOuterTlsConnector, PkiIdentityExtractor, SessionPolicy,
    };

    let identities = load_verified_identities(prepared, material_dir)?;
    let identity = PemIdentity::from_pem_files(
        material_dir.join("identity.pem"),
        material_dir.join("identity.key"),
        material_dir.join("identity-ca.pem"),
    )
    .map_err(|error| format!("error: local identity PEM rejected: {error}"))?;
    let inner = OpenSslConnector::from_pem_identity(&identity, Policy::production_default())
        .map_err(|error| format!("error: inner TLS connector rejected: {error}"))?;
    let extractor = Arc::new(
        PkiIdentityExtractor::new(vec![identities.local.clone(), identities.peer.clone()])
            .map_err(|error| format!("error: peer extractor rejected: {error}"))?,
    );
    let outer_ca = read_bounded(material_dir, "outer-ca.pem", MAX_MATERIAL_FILE)?;
    let client = LinkClient::new(
        Box::new(
            OpenSslOuterTlsConnector::with_root_certificates(&outer_ca)
                .map_err(|error| format!("error: outer TLS connector rejected: {error}"))?,
        ),
        Box::new(OpenSslInnerConnector::new(inner, extractor)),
    );
    let target = ClientTarget {
        address,
        ws_host: format!("{tls_name}:{}", address.port()),
        tls_server_name: tls_name.to_string(),
        path: "/tunnel".to_string(),
    };
    let policy = SessionPolicy {
        local: identities.local_peer(),
        expected_peer: identities.peer_peer(),
        path_role: PathRole::Cdn,
        security_mode: SecurityMode::E2eRequired,
        suite: MessageSuite::Pq768,
        mtu_cap: 1400,
        identity_registered: true,
        allow_pq1024: false,
        allow_hop_only: false,
        allowed_peer_roles: vec![identities.peer.role()],
    };
    policy
        .validate()
        .map_err(|error| format!("error: session policy rejected: {error}"))?;
    let session = client
        .connect(&target, policy, Duration::from_secs(20))
        .map_err(|error| format!("error: hop session failed: {error}"))?;
    Ok(report("connect", &session))
}

#[cfg(feature = "openssl-inner-tls")]
struct VerifiedPair {
    local: boreas_tunnel::VerifiedNodeIdentity,
    peer: boreas_tunnel::VerifiedNodeIdentity,
}

#[cfg(feature = "openssl-inner-tls")]
impl VerifiedPair {
    fn local_peer(&self) -> boreas_tunnel::tls::PeerIdentity {
        self.local.peer_identity()
    }

    fn peer_peer(&self) -> boreas_tunnel::tls::PeerIdentity {
        self.peer.peer_identity()
    }
}

#[cfg(feature = "openssl-inner-tls")]
fn load_verified_identities(
    prepared: &Prepared,
    material_dir: &Path,
) -> Result<VerifiedPair, String> {
    use boreas_crypto::NodeRole;
    use boreas_pki::management::{IssuerRecord, IssuerScope, ManagementTrust};
    use boreas_pki::{Authority, NodeRole as PkiRole};
    use boreas_proto::objects::MldsaParameterSet;
    use boreas_tunnel::VerifiedNodeIdentity;

    let net_id = decode_net_id(&prepared.config.network.net_id)?;
    let issuer_key_id = read_bounded(material_dir, "issuer.key-id", MAX_ISSUER_KEY_ID)?;
    let generation_text = read_bounded(material_dir, "issuer.generation", 32)?;
    let generation_str = std::str::from_utf8(&generation_text)
        .map_err(|_| "error: issuer.generation must be ASCII digits".to_string())?
        .trim();
    let issuer_generation: u64 = generation_str
        .parse()
        .map_err(|_| "error: issuer.generation must be a positive integer".to_string())?;
    if issuer_generation == 0 {
        return Err("error: issuer.generation must be non-zero".into());
    }
    let ed25519_public_key_der =
        read_bounded(material_dir, "issuer.ed25519.der", MAX_PUBLIC_KEY_DER)?;
    let mldsa_public_key_der = read_bounded(material_dir, "issuer.mldsa.der", MAX_PUBLIC_KEY_DER)?;
    let scope = IssuerScope::for_identity(vec![PkiRole::Edge, PkiRole::Core], (1u8..=16).collect())
        .map_err(|error| format!("error: issuer scope rejected: {error}"))?;
    let mut trust = ManagementTrust::new(net_id);
    trust
        .add_issuer(IssuerRecord {
            issuer_key_id,
            issuer_generation,
            authority: Authority::IdentityAuthority,
            ed25519_public_key_der,
            mldsa_parameter_set: MldsaParameterSet::Mldsa65,
            mldsa_public_key_der,
            scope,
        })
        .map_err(|error| format!("error: issuer record rejected: {error}"))?;
    let now_us = unix_now_us()?;
    let local_object = trust
        .verify_and_authorize(
            &read_bounded(material_dir, "local.signed", MAX_MATERIAL_FILE)?,
            now_us,
        )
        .map_err(|error| format!("error: local NodeIdentity rejected: {error}"))?;
    let peer_object = trust
        .verify_and_authorize(
            &read_bounded(material_dir, "peer.signed", MAX_MATERIAL_FILE)?,
            now_us,
        )
        .map_err(|error| format!("error: peer NodeIdentity rejected: {error}"))?;
    let local = VerifiedNodeIdentity::from_verified_object_legacy_for_hop_only(&local_object)
        .map_err(|error| format!("error: local identity mapping rejected: {error}"))?;
    let peer = VerifiedNodeIdentity::from_verified_object_legacy_for_hop_only(&peer_object)
        .map_err(|error| format!("error: peer identity mapping rejected: {error}"))?;
    if local.net_id() != net_id
        || local.node_id() != prepared.config.identity.node_id
        || local.identity_generation() != prepared.config.identity.identity_generation
        || !role_matches(prepared.local_role, local.role())
    {
        return Err("error: local.signed does not match the configuration identity".into());
    }
    if peer.net_id() != net_id || peer.node_id() == local.node_id() {
        return Err("error: peer.signed is not a distinct node in this network".into());
    }
    if prepared.local_role == ConfigRole::Core && peer.role() != NodeRole::Edge {
        return Err("error: node serve accepts an edge peer".into());
    }
    if prepared.local_role == ConfigRole::Edge && peer.role() != NodeRole::Core {
        return Err("error: node connect dials a core peer".into());
    }
    Ok(VerifiedPair { local, peer })
}

#[cfg(feature = "openssl-inner-tls")]
fn role_matches(config: ConfigRole, crypto: boreas_crypto::NodeRole) -> bool {
    matches!(
        (config, crypto),
        (ConfigRole::Core, boreas_crypto::NodeRole::Core)
            | (ConfigRole::Edge, boreas_crypto::NodeRole::Edge)
    )
}

#[cfg(feature = "openssl-inner-tls")]
fn report(command: &str, session: &boreas_tunnel::EstablishedSession) -> String {
    let peer = session.peer();
    format!(
        "{{\"command\":\"node-{command}\",\"result\":\"one-hop-session\",\"production_daemon\":false,\"tls_backend\":true,\"networking\":true,\"e2e\":false,\"gate\":\"not-claimed\",\"peer_node_id\":{},\"mtu_cap\":{}}}",
        peer.node_id,
        session.mtu_cap()
    )
}

#[cfg(test)]
mod tests {
    use super::valid_tls_name;

    #[test]
    fn tls_name_rejects_ports_and_paths() {
        assert!(valid_tls_name("hub.boreas.test"));
        assert!(!valid_tls_name("hub.boreas.test:443"));
        assert!(!valid_tls_name("hub/boreas"));
        assert!(!valid_tls_name(""));
    }

    #[test]
    fn usage_errors_do_not_open_sockets() {
        let (code, stdout, stderr) = super::run(&[]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("node requires serve or connect"));
        let (code, _, stderr) = super::run(&["serve".into()]);
        assert_eq!(code, 2);
        assert!(stderr.contains("node serve <config>"));
        let (code, _, stderr) = super::run(&["connect".into()]);
        assert_eq!(code, 2);
        assert!(stderr.contains("node connect <config>"));
    }

    #[cfg(not(feature = "openssl-inner-tls"))]
    #[test]
    fn default_build_refuses_before_opening_a_socket() {
        let (code, stdout, stderr) = super::run(&[
            "connect".into(),
            "/boreas-tests/secret/config.toml".into(),
            "127.0.0.1:443".into(),
            "hub.boreas.test".into(),
            "/boreas-tests/secret/material".into(),
        ]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("no TLS backend"));
        assert!(stderr.contains("no daemon was started"));
    }
}
