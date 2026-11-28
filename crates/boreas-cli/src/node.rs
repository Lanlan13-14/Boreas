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
#[path = "mesh_runtime.rs"]
mod mesh_runtime;
pub use mesh_runtime::SYNTAX as MESH_RUNTIME_SYNTAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OuterTransport {
    Wss,
    Direct,
}

impl OuterTransport {
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn link_client(
        self,
        dir: &Path,
        inner: Box<dyn boreas_tunnel::InnerTlsConnector>,
    ) -> Result<boreas_tunnel::LinkClient, String> {
        match self {
            Self::Wss => Ok(boreas_tunnel::LinkClient::new(Box::new(outer_connector(dir)?), inner)),
            Self::Direct => Ok(boreas_tunnel::LinkClient::new_direct(inner)),
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "wss" => Ok(Self::Wss),
            "direct" => Ok(Self::Direct),
            _ => Err("--transport must be `wss` or `direct`".into()),
        }
    }
}

/// Inspect directory entries rather than following symlinks: a dangling CA or
/// certificate symlink is configured material, not permission to downgrade.
#[cfg(feature = "openssl-inner-tls")]
fn material_present(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot inspect `{}`: {e}", path.display())),
    }
}

#[cfg(feature = "openssl-inner-tls")]
pub(crate) fn outer_connector(dir: &Path) -> Result<boreas_tunnel::OpenSslOuterTlsConnector, String> {
    use boreas_tunnel::OpenSslOuterTlsConnector;
    let ca = dir.join("outer-ca.pem");
    if material_present(&ca)? {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options.open(&ca)
            .map_err(|_| format!("error: cannot read `{}`", ca.display()))?;
        let metadata = file.metadata().map_err(|_| format!("error: cannot stat `{}`", ca.display()))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_OUTER_CA_FILE as u64 {
            return Err("error: outer-ca.pem must be a non-empty regular file at most 1 MiB".into());
        }
        use std::io::Read;
        let mut pem = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_OUTER_CA_FILE as u64 + 1).read_to_end(&mut pem)
            .map_err(|_| "error: cannot read outer-ca.pem".to_string())?;
        if pem.is_empty() || pem.len() > MAX_OUTER_CA_FILE {
            return Err("error: outer-ca.pem exceeds size bounds".into());
        }
        OpenSslOuterTlsConnector::with_web_pki_and_roots(&pem)
            .map_err(|e| format!("outer-ca.pem rejected: {e}"))
    } else {
        OpenSslOuterTlsConnector::web_pki()
            .map_err(|e| format!("OpenSSL default trust paths unavailable: {e}"))
    }
}

#[cfg(feature = "openssl-inner-tls")]
pub(crate) fn outer_acceptor(
    dir: &Path,
    transport: OuterTransport,
) -> Result<Option<boreas_tunnel::OpenSslOuterTlsAcceptor>, String> {
    let cert = dir.join("outer.pem");
    let key = dir.join("outer.key");
    let present = (material_present(&cert)?, material_present(&key)?);
    if present.0 != present.1 {
        return Err("outer.pem and outer.key must both be installed; partial credentials are rejected".into());
    }
    match transport {
        OuterTransport::Direct => Ok(None),
        OuterTransport::Wss if !present.0 => Err("WSS requires both outer.pem and outer.key".into()),
        OuterTransport::Wss => boreas_tunnel::OpenSslOuterTlsAcceptor::from_pem_files(cert, key)
            .map(Some)
            .map_err(|e| format!("outer TLS acceptor rejected: {e}")),
    }
}

pub fn run(args: &[String]) -> (u8, String, String) {
    match args.first().map(String::as_str) {
        Some("mesh-probe") => mesh_probe::run(&args[1..]),
        Some("mesh-run") => mesh_runtime::run(&args[1..]),
        Some("serve") if args.len() == 4 || args.len() == 6 => {
            match node_transport(&args[4..]) {
                Ok(mode) => serve(&args[1], &args[2], &args[3], mode),
                Err(message) => (2, String::new(), message),
            }
        }
        Some("connect") if args.len() == 5 || args.len() == 7 => {
            match node_transport(&args[5..]) {
                Ok(mode) => connect(&args[1], &args[2], &args[3], &args[4], mode),
                Err(message) => (2, String::new(), message),
            }
        }
        Some("serve") => (
            2,
            String::new(),
            "error: node serve <config> <listen> <material-dir> [--transport wss|direct]".into(),
        ),
        Some("connect") => (
            2,
            String::new(),
            "error: node connect <config> <host:port> <tls-name> <material-dir> [--transport wss|direct]".into(),
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

fn node_transport(args: &[String]) -> Result<OuterTransport, String> {
    match args {
        [] => Ok(OuterTransport::Wss),
        [flag, value] if flag == "--transport" => OuterTransport::parse(value),
        _ => Err("error: expected --transport wss|direct".into()),
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
fn serve(_config_path: &str, _listen: &str, _material_dir: &str, _transport: OuterTransport) -> (u8, String, String) {
    no_backend("serve")
}

#[cfg(not(feature = "openssl-inner-tls"))]
fn connect(
    _config_path: &str,
    _endpoint: &str,
    _tls_name: &str,
    _material_dir: &str,
    _transport: OuterTransport,
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
const MAX_OUTER_CA_FILE: usize = 1024 * 1024;
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
fn serve(config_path: &str, listen: &str, material_dir: &str, transport: OuterTransport) -> (u8, String, String) {
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
        transport,
    ))
}

#[cfg(feature = "openssl-inner-tls")]
fn connect(
    config_path: &str,
    endpoint: &str,
    tls_name: &str,
    material_dir: &str,
    transport: OuterTransport,
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
        transport,
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
    use std::io::Read;
    let file = std::fs::File::open(&path)
        .map_err(|_| format!("error: cannot read `{}`", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| format!("error: cannot read `{}`", path.display()))?;
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
    transport: OuterTransport,
) -> Result<String, String> {
    use std::sync::Arc;
    use std::time::Duration;

    use boreas_crypto::Policy;
    use boreas_crypto::pq_wg::PqWgIdentity;
    use boreas_proto::SecurityMode;
    use boreas_proto::messages::{PathRole, Suite as MessageSuite};
    use boreas_tunnel::resource::{Admission, Limits};
    use boreas_tunnel::runtime::LinkServer;
    use boreas_tunnel::{PkiIdentityExtractor, PqWgInnerAcceptor, SessionPolicy};

    let identities = load_verified_identities(prepared, material_dir)?;
    let pq_identity = PqWgIdentity::from_private_key_file(material_dir.join("identity.key"))
        .map_err(|error| format!("error: local pq-wg identity rejected: {error}"))?;
    let extractor = Arc::new(
        PkiIdentityExtractor::new(vec![identities.local.clone(), identities.peer.clone()])
            .map_err(|error| format!("error: peer extractor rejected: {error}"))?,
    );
    let server = LinkServer::new(Box::new(
        PqWgInnerAcceptor::new(pq_identity, Policy::production_default(), extractor)
            .map_err(|error| format!("error: pq-wg acceptor rejected: {error}"))?,
    ));
    let outer = outer_acceptor(material_dir, transport)?;
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
        .accept_stream_until(
            listener.accept().map_err(|e| format!("error: accept failed: {e}"))?.0,
            outer.as_ref().map(|o| o as &dyn boreas_tunnel::OuterTlsAcceptor),
            policy,
            std::time::Instant::now() + Duration::from_secs(20),
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
    transport: OuterTransport,
) -> Result<String, String> {
    use std::sync::Arc;
    use std::time::Duration;

    use boreas_crypto::Policy;
    use boreas_crypto::pq_wg::PqWgIdentity;
    use boreas_proto::SecurityMode;
    use boreas_proto::messages::{PathRole, Suite as MessageSuite};
    use boreas_tunnel::runtime::ClientTarget;
    use boreas_tunnel::{PkiIdentityExtractor, PqWgInnerConnector, SessionPolicy};

    let identities = load_verified_identities(prepared, material_dir)?;
    let pq_identity = PqWgIdentity::from_private_key_file(material_dir.join("identity.key"))
        .map_err(|error| format!("error: local pq-wg identity rejected: {error}"))?;
    let extractor = Arc::new(
        PkiIdentityExtractor::new(vec![identities.local.clone(), identities.peer.clone()])
            .map_err(|error| format!("error: peer extractor rejected: {error}"))?,
    );
    let inner = PqWgInnerConnector::new(pq_identity, Policy::production_default(), extractor)
        .map_err(|error| format!("error: pq-wg connector rejected: {error}"))?;
    let client = transport.link_client(material_dir, Box::new(inner))?;
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

#[cfg(all(test, feature = "openssl-inner-tls"))]
#[path = "node_outer_tls_tests.rs"]
mod outer_tls_tests;

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

    #[test]
    fn transport_is_explicit_or_secure_by_default() {
        use super::{node_transport, OuterTransport};
        assert_eq!(node_transport(&[]).unwrap(), OuterTransport::Wss);
        assert_eq!(node_transport(&["--transport".into(), "direct".into()]).unwrap(), OuterTransport::Direct);
        assert_eq!(node_transport(&["--transport".into(), "wss".into()]).unwrap(), OuterTransport::Wss);
        assert!(node_transport(&["--transport".into(), "auto".into()]).is_err());
        assert!(node_transport(&["--transport".into()]).is_err());
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn server_rejects_missing_partial_and_invalid_outer_material() {
        use super::{outer_acceptor, outer_connector, OuterTransport};
        use std::{fs, sync::atomic::{AtomicU64, Ordering}};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("boreas-outer-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        assert!(outer_acceptor(&dir, OuterTransport::Wss).is_err());
        assert!(outer_acceptor(&dir, OuterTransport::Direct).unwrap().is_none());
        fs::write(dir.join("outer.pem"), b"invalid").unwrap();
        assert!(outer_acceptor(&dir, OuterTransport::Wss).is_err());
        assert!(outer_acceptor(&dir, OuterTransport::Direct).is_err());
        fs::write(dir.join("outer.key"), b"invalid").unwrap();
        assert!(outer_acceptor(&dir, OuterTransport::Wss).is_err());
        assert!(outer_acceptor(&dir, OuterTransport::Direct).unwrap().is_none());
        fs::remove_file(dir.join("outer.pem")).unwrap();
        assert!(outer_acceptor(&dir, OuterTransport::Wss).is_err());
        assert!(outer_acceptor(&dir, OuterTransport::Direct).is_err());
        fs::write(dir.join("outer-ca.pem"), b"invalid").unwrap();
        assert!(outer_connector(&dir).is_err());
        fs::remove_file(dir.join("outer-ca.pem")).unwrap();
        #[cfg(unix)] {
            std::os::unix::fs::symlink("missing-ca.pem", dir.join("outer-ca.pem")).unwrap();
            assert!(outer_connector(&dir).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn server_rejects_mismatched_certificate_and_key() {
        use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::{X509, X509NameBuilder}};
        use std::{fs, sync::atomic::{AtomicU64, Ordering}};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("boreas-outer-mismatch-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        let cert_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let other_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "wss.boreas.test").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let serial = openssl::bn::BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&cert_key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        cert.sign(&cert_key, MessageDigest::sha256()).unwrap();
        fs::write(dir.join("outer.pem"), cert.build().to_pem().unwrap()).unwrap();
        fs::write(dir.join("outer.key"), other_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert!(super::outer_acceptor(&dir, super::OuterTransport::Wss).is_err());
        fs::remove_dir_all(dir).unwrap();
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
