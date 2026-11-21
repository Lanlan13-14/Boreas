//! Explicit one-shot signed Core control exchange, separate from the TUN daemon.

pub const SYNTAX: &str = "boreas node mesh-probe <config> <material-dir> dial (<peer.signed> <IP:PORT> <tls-name>)+ | listen <peer.signed> <IP:PORT>";

pub fn run(args: &[String]) -> (u8, String, String) {
    #[cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]
    let result = linux::run(args);
    #[cfg(not(all(target_os = "linux", feature = "openssl-inner-tls")))]
    let result: Result<String, String> = {
        let _ = args;
        Err("mesh-probe requires Linux and the openssl-inner-tls build".into())
    };
    match result {
        Ok(output) => (0, output, String::new()),
        Err(error) => (2, String::new(), format!("error: {error}; {SYNTAX}")),
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]
pub(super) mod linux {
    use std::{
        fs::OpenOptions,
        io::{self, Read},
        net::{TcpListener, TcpStream},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
        thread,
        time::{Duration, Instant},
    };

    use boreas_crypto::{NodeRole, backend::PemIdentity};
    use boreas_pki::{
        management::MAX_SIGNED_OBJECT_BYTES,
        provisioning::{RootsBundle, parse_net_id_hex},
        status_store::StatusStore,
    };
    use boreas_tunnel::{
        ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector,
        mesh_probe::{Candidate, MeshProbe, management_trust, utc_now},
        resource::{Admission, Limits},
    };

    use crate::{
        config::{Config, CryptoSuite, NodeRole as ConfigRole, RuntimeCapabilities, SecurityMode},
        network_policy_runtime::{PolicyInputPaths, verify_and_record_default_policy},
    };

    fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
        read_material(path, max, None)
    }

    pub(in crate::node) fn read_material(
        path: &Path,
        max: usize,
        secret_owner: Option<u32>,
    ) -> Result<Vec<u8>, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "mesh material cannot be opened".to_string())?;
        let meta = file
            .metadata()
            .map_err(|_| "mesh material cannot be stat'ed".to_string())?;
        if !meta.is_file() || meta.len() == 0 || meta.len() > max as u64 {
            return Err("invalid mesh material file".into());
        }
        // SAFETY: geteuid is a pure getter for this process.
        let owner = unsafe { libc::geteuid() };
        let (owner, forbidden) = secret_owner.map_or((owner, 0o022), |uid| (uid, 0o077));
        if (meta.uid() != owner && meta.uid() != 0) || meta.mode() & forbidden != 0 {
            return Err("unsafe mesh material owner or permissions".into());
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "mesh material read failed".to_string())?;
        if bytes.is_empty() || bytes.len() > max {
            return Err("mesh material exceeds bounds".into());
        }
        Ok(bytes)
    }

    fn accept_one(listener: &TcpListener) -> io::Result<TcpStream> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match listener.accept() {
                Ok((tcp, _)) => {
                    tcp.set_nonblocking(false)?;
                    return Ok(tcp);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn run(args: &[String]) -> Result<String, String> {
        let [config, materials, mode, rest @ ..] = args else {
            return Err("missing mesh probe arguments".into());
        };
        let dial = match mode.as_str() {
            "dial" if matches!(rest.len(), 3 | 6 | 9) => true,
            "listen" if rest.len() == 2 => false,
            _ => return Err("invalid mesh probe arguments".into()),
        };
        let cfg = Config::read_file(Path::new(config), RuntimeCapabilities {
            dns_tcp: false,
            control_socket: false,
            e2e_relay: false,
        })
        .map_err(|e| format!("mesh config rejected: {e}"))?;
        if cfg.identity.role != ConfigRole::Core
            || cfg.security.suite != CryptoSuite::Pq768
            || cfg.security.mode != SecurityMode::E2eRequired
        {
            return Err("mesh probe requires Core, pq768 and e2e-required".into());
        }
        let mat = Path::new(materials);
        let state = &cfg.paths.state_dir;
        let net = parse_net_id_hex(&cfg.network.net_id)
            .map_err(|_| "invalid configured network".to_string())?;
        let root_path = cfg.paths.roots.first().ok_or("missing roots bundle")?;
        let roots = RootsBundle::decode(&read(root_path, 128 * 1024)?)
            .map_err(|_| "invalid roots bundle".to_string())?;
        let now = utc_now().map_err(|e| format!("mesh clock rejected: {e:?}"))?;
        let (root_fingerprint, _) = roots
            .verify_all(net, now)
            .map_err(|_| "root delegation verification failed".to_string())?;
        // SAFETY: geteuid takes no arguments and returns the current effective UID.
        let owner = unsafe { libc::geteuid() };
        let policy = verify_and_record_default_policy(
            PolicyInputPaths {
                tbs: &state.join("network-policy.tbs"),
                ed25519_signature: &state.join("network-policy.ed25519.sig"),
                mldsa65_signature: &state.join("network-policy.mldsa65.sig"),
                root_ed25519_der: &state.join("network-root.ed25519.der"),
                root_mldsa65_der: &state.join("network-root.mldsa65.der"),
            },
            &state.join("network-policy.state"),
            state,
            net,
            root_fingerprint,
            owner,
        )
        .map_err(|e| format!("mesh signed policy rejected: {e}"))?;
        if cfg.network.overlay_prefix.base() != policy.overlay_base() {
            return Err("configured overlay does not match signed policy".into());
        }
        let trust = management_trust(&roots, &policy, now)
            .map_err(|e| format!("mesh trust rejected: {e:?}"))?;
        let mut status = StatusStore::open(state.join("status.state"), net, owner, trust)
            .map_err(|e| format!("mesh durable status rejected: {e:?}"))?;
        let snapshot = read(&mat.join("status.signed"), MAX_SIGNED_OBJECT_BYTES)?;
        let now = utc_now().map_err(|e| format!("mesh clock rejected: {e:?}"))?;
        status
            .accept_signed_snapshot(&snapshot, now, Instant::now())
            .map_err(|e| format!("mesh signed status rejected: {e:?}"))?;
        let pem = PemIdentity {
            certificate_pem: read(&mat.join("identity.pem"), 64 * 1024)?,
            private_key_pem: read_material(&cfg.identity.private_key, 16 * 1024, Some(owner))?,
            trust_anchor_pem: read(&mat.join("identity-ca.pem"), 64 * 1024)?,
        };
        let local = read(&mat.join("local.signed"), MAX_SIGNED_OBJECT_BYTES)?;
        let lsa = read(&mat.join("local-lsa.signed"), MAX_SIGNED_OBJECT_BYTES)?;
        let mut probe = MeshProbe::new(policy, &roots, &mut status, &pem, &local, &lsa)
            .map_err(|e| format!("mesh local authority rejected: {e:?}"))?;
        let identity = probe.local();
        if identity.role != NodeRole::Core
            || identity.node_id != cfg.identity.node_id
            || identity.identity_generation != cfg.identity.identity_generation
        {
            return Err("configured Core does not match signed local identity".into());
        }
        let selected = if dial {
            let mut peers = Vec::new();
            let (groups, remainder) = rest.as_chunks::<3>();
            if !remainder.is_empty() {
                return Err("expected complete Core candidate triples".into());
            }
            for group in groups {
                let address = group[1]
                    .parse()
                    .map_err(|_| "invalid numeric Core endpoint")?;
                let name = &group[2];
                if name.is_empty()
                    || name.len() > 253
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                {
                    return Err("invalid Core TLS server name".into());
                }
                let target = ClientTarget {
                    address,
                    ws_host: name.clone(),
                    tls_server_name: name.clone(),
                    path: "/tunnel".into(),
                };
                peers.push((target, read(Path::new(&group[0]), MAX_SIGNED_OBJECT_BYTES)?));
            }
            let candidates: Vec<_> = peers
                .iter()
                .map(|(target, signed_identity)| Candidate {
                    target,
                    signed_identity,
                })
                .collect();
            probe.select(&candidates, &OpenSslOuterTlsConnector::web_pki)
        } else {
            let peer = read(Path::new(&rest[0]), MAX_SIGNED_OBJECT_BYTES)?;
            let address = rest[1]
                .parse::<std::net::SocketAddr>()
                .map_err(|_| "invalid Core listen endpoint")?;
            let outer = OpenSslOuterTlsAcceptor::from_pem_files(
                mat.join("outer.pem"),
                mat.join("outer.key"),
            )
            .map_err(|_| "invalid outer TLS credential")?;
            let listener = TcpListener::bind(address)
                .map_err(|e| format!("mesh bind failed: {}", e.kind()))?;
            let tcp =
                accept_one(&listener).map_err(|e| format!("mesh accept failed: {}", e.kind()))?;
            probe.respond(
                tcp,
                &peer,
                &outer,
                &Admission::new(Limits {
                    handshakes_global: 1,
                    authenticated_global: 1,
                    authenticated_per_peer: 1,
                    bytes_global: 1024 * 1024,
                }),
            )
        }
        .map_err(|e| format!("mesh adjacency failed: {e:?}"))?;
        Ok(format!(
            "authenticated_core={} attempts={} signed_lsa_bytes={} (control only)",
            selected.core_id,
            selected.attempts,
            selected.signed_lsa.len()
        ))
    }
}
