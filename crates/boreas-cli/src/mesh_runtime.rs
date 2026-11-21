//! Dedicated Linux Core runtime, independent of the generic Edge/Core daemon.

pub const SYNTAX: &str = "boreas node mesh-run <config> <material-dir> <runtime.toml>";

pub fn run(args: &[String]) -> (u8, String, String) {
    #[cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]
    let result = linux::run(args);
    #[cfg(not(all(target_os = "linux", feature = "openssl-inner-tls")))]
    let result: Result<(), String> = {
        let _ = args;
        Err("mesh-run requires Linux and the openssl-inner-tls build".into())
    };
    match result {
        Ok(()) => (0, String::new(), String::new()),
        Err(e) => (2, String::new(), format!("error: {e}; {SYNTAX}")),
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]
mod linux {
    use std::{
        collections::BTreeSet,
        fs,
        io::ErrorKind,
        net::{SocketAddr, TcpListener, TcpStream},
        os::unix::fs::MetadataExt,
        path::Path,
        thread,
        time::{Duration, Instant},
    };

    use boreas_crypto::backend::PemIdentity;
    use boreas_pki::{
        Authority, VerifiedNetworkContext,
        authority_revocation::AuthorityRevocationTrust,
        management::{MAX_SIGNED_OBJECT_BYTES, ManagementTrust},
        provisioning::{RootsBundle, parse_net_id_hex},
        status_store::{MAX_IDENTITY_REVOCATION_BYTES, StatusStore},
    };
    use boreas_tun::linux::{LinuxTunDevice, LinuxTunQueue};
    use boreas_tunnel::{
        ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector,
        mesh_probe::{Error, MeshProbe, utc_now},
        mesh_route::{DirectoryCore, RouteLocator},
        packet_path::{MAX_MTU, MIN_MTU},
        resource::{Admission, Limits},
    };
    use serde::Deserialize;

    use super::super::{mesh_probe::linux::read_material, valid_tls_name};
    use crate::{
        config::{Config, CryptoSuite, LimitsConfig, NodeRole, RuntimeCapabilities, SecurityMode},
        network_policy_runtime::{PolicyInputPaths, verify_and_record_default_policy},
    };

    const MAX_CORES: u8 = 16;
    const MAX_ROUTES: usize = 3;
    const POLL: Duration = Duration::from_millis(50);
    const RETRY: Duration = Duration::from_millis(500);
    const MAX_PEM: usize = 64 * 1024;

    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        Source,
        Relay,
        Destination,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Spec {
        mode: Mode,
        peers: Vec<u8>,
        tun: Option<String>,
        mtu: Option<usize>,
        routes: Vec<Route>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Route {
        path: Vec<u8>,
        listen: Option<SocketAddr>,
        next: Option<SocketAddr>,
        tls_name: Option<String>,
    }

    impl Spec {
        fn validate(&self, local: u8) -> Result<(), String> {
            let mut peers = BTreeSet::from([local]);
            if self.peers.len() >= usize::from(MAX_CORES)
                || self
                    .peers
                    .iter()
                    .any(|&id| !(1..=MAX_CORES).contains(&id) || !peers.insert(id))
                || !(1..=MAX_ROUTES).contains(&self.routes.len())
            {
                return Err("invalid mesh peer/route count or slot".into());
            }
            let endpoints = (
                !matches!(self.mode, Mode::Relay),
                !matches!(self.mode, Mode::Relay),
            );
            if (self.tun.is_some(), self.mtu.is_some()) != endpoints
                || self
                    .mtu
                    .is_some_and(|mtu| !(MIN_MTU..=MAX_MTU).contains(&mtu))
            {
                return Err("mesh endpoints require tun and mtu; relays forbid them".into());
            }
            let mut listens = BTreeSet::new();
            let mut targets = BTreeSet::new();
            let mut paths = BTreeSet::new();
            let mut first_hops = BTreeSet::new();
            let mut pair = None;
            for route in &self.routes {
                let path = &route.path;
                if !(3..=4).contains(&path.len())
                    || path
                        .iter()
                        .enumerate()
                        .any(|(i, id)| !peers.contains(id) || path[..i].contains(id))
                    || !paths.insert(path)
                {
                    return Err("invalid or duplicate mesh path".into());
                }
                let source = path[0];
                let destination = path[path.len() - 1];
                let expected = (source, destination);
                if source >= destination || pair.replace(expected).is_some_and(|p| p != expected) {
                    return Err("mesh routes must bind one ordered endpoint pair".into());
                }
                let (listen, next) = match self.mode {
                    Mode::Source if local == source && first_hops.insert(path[1]) => (false, true),
                    Mode::Relay if path[1..path.len() - 1].contains(&local) => (true, true),
                    Mode::Destination if local == destination => (true, false),
                    _ => {
                        return Err(
                            "mesh role does not match path position or first hop repeats".into(),
                        );
                    }
                };
                if route.listen.is_some() != listen
                    || route.next.is_some() != next
                    || route.tls_name.is_some() != next
                    || route
                        .listen
                        .is_some_and(|a| a.port() == 0 || !listens.insert(a))
                    || route.next.is_some_and(|a| {
                        a.port() == 0 || a.ip().is_unspecified() || !targets.insert(a)
                    })
                    || route
                        .tls_name
                        .as_deref()
                        .is_some_and(|name| !valid_tls_name(name))
                {
                    return Err("invalid or duplicate dedicated mesh listener/next target".into());
                }
            }
            Ok(())
        }
    }

    fn owner() -> u32 {
        // SAFETY: pure getter for the current effective UID.
        unsafe { libc::geteuid() }
    }

    fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
        read_material(path, max, None)
    }

    fn optional(path: &Path, max: usize) -> Result<Option<Vec<u8>>, String> {
        match fs::symlink_metadata(path) {
            Ok(_) => read(path, max).map(Some),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(_) => Err("mesh optional material cannot be stat'ed".into()),
        }
    }

    fn protected_dir(path: &Path) -> Result<(), String> {
        // Require protected ancestors, not just a safe leaf open. Otherwise a
        // writable parent could substitute another valid old signed snapshot or CA.
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err("mesh material/state directories must be absolute".into());
        }
        for dir in path.ancestors() {
            let meta = fs::symlink_metadata(dir).map_err(|_| "mesh directory unavailable")?;
            if !meta.is_dir()
                || (meta.uid() != 0 && meta.uid() != owner())
                || (meta.mode() & 0o022 != 0
                    && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0 && dir != path))
            {
                return Err("unsafe mesh directory owner or permissions".into());
            }
        }
        Ok(())
    }

    fn protected(path: &Path) -> Result<(), String> {
        protected_dir(path.parent().ok_or("mesh file has no parent")?)
    }

    fn target(route: &Route) -> Option<ClientTarget> {
        let name = route.tls_name.clone()?;
        Some(ClientTarget {
            address: route.next?,
            ws_host: name.clone(),
            tls_server_name: name,
            path: "/tunnel".into(),
        })
    }

    fn clock() -> Result<u64, String> {
        utc_now().map_err(|e| format!("mesh clock: {e:?}"))
    }

    fn policy_and_store(
        cfg: &Config,
    ) -> Result<(VerifiedNetworkContext, RootsBundle, StatusStore), String> {
        let net = parse_net_id_hex(&cfg.network.net_id).map_err(|_| "invalid mesh network")?;
        let [roots_path] = cfg.paths.roots.as_slice() else {
            return Err("mesh requires exactly one roots bundle".into());
        };
        protected(roots_path)?;
        let roots = RootsBundle::decode(&read(roots_path, 128 * 1024)?)
            .map_err(|_| "invalid mesh roots bundle")?;
        let now = clock()?;
        let (fingerprint, grants) = roots
            .verify_all(net, now)
            .map_err(|_| "invalid mesh root authorization")?;
        let state = &cfg.paths.state_dir;
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
            fingerprint,
            owner(),
        )
        .map_err(|e| format!("mesh signed policy: {e}"))?;
        if cfg.network.overlay_prefix.base() != policy.overlay_base() {
            return Err("configured overlay does not match signed policy".into());
        }
        let mut status_trust = ManagementTrust::new(net);
        let mut identity_trust = AuthorityRevocationTrust::new(net);
        let (mut has_status, mut has_identity) = (false, false);
        for grant in grants {
            let authority = grant.issuer_record().authority;
            status_trust
                .add_verified_issuer(&grant)
                .map_err(|_| "mesh status issuer rejected")?;
            has_status |= authority == Authority::StatusSigner;
            if authority == Authority::IdentityAuthority {
                identity_trust
                    .add_verified_issuer(grant)
                    .map_err(|_| "mesh revocation issuer rejected")?;
                has_identity = true;
            }
        }
        if !has_status || !has_identity {
            return Err("mesh requires status and independent identity authorities".into());
        }
        let status = StatusStore::open_with_identity_revocations(
            state.join("status.state"),
            net,
            owner(),
            status_trust,
            fingerprint,
            identity_trust,
        )
        .map_err(|e| format!("mesh durable status: {e:?}"))?;
        Ok((policy, roots, status))
    }

    fn accept(
        listeners: &[(usize, TcpListener)],
        cursor: &mut usize,
    ) -> Result<Option<(usize, TcpStream)>, String> {
        for _ in 0..listeners.len() {
            let (i, listener) = &listeners[*cursor];
            *cursor = (*cursor + 1) % listeners.len();
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|_| "mesh socket setup failed")?;
                    return Ok(Some((*i, stream)));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock
                            | ErrorKind::Interrupted
                            | ErrorKind::ConnectionAborted
                    ) => {}
                Err(e) => return Err(format!("mesh accept: {}", e.kind())),
            }
        }
        Ok(None)
    }

    fn open_tun(spec: &Spec) -> Result<Option<LinuxTunQueue>, String> {
        let (Some(name), Some(mtu)) = (&spec.tun, spec.mtu) else {
            return Ok(None);
        };
        let (_, tun) = LinuxTunDevice::open_provisioned(name, mtu)
            .map_err(|e| format!("mesh TUN attach: {e}"))?;
        Ok(Some(tun))
    }

    fn confirmed(role: &str, path: &[u8], id: [u8; 16]) {
        eprintln!(
            "mesh confirmed role={role} path={path:?} circuit={:032x}",
            u128::from_be_bytes(id)
        );
    }

    struct CoreFiles {
        identity: Vec<u8>,
        lsa: Option<Vec<u8>>,
    }

    struct Materials<'a> {
        dir: &'a Path,
        peers: &'a [u8],
    }

    impl Materials<'_> {
        fn lsa(&self) -> Result<Vec<u8>, String> {
            read(&self.dir.join("local-lsa.signed"), MAX_SIGNED_OBJECT_BYTES)
        }

        fn refresh(&self, probe: &mut MeshProbe<'_>) -> Result<Vec<CoreFiles>, String> {
            probe
                .refresh_runtime_authority(
                    &read(&self.dir.join("status.signed"), MAX_SIGNED_OBJECT_BYTES)?,
                    optional(
                        &self.dir.join("identity-revocation.signed"),
                        MAX_IDENTITY_REVOCATION_BYTES,
                    )?
                    .as_deref(),
                    &self.lsa()?,
                )
                .map_err(|e| format!("mesh runtime authority: {e:?}"))?;
            self.peers
                .iter()
                .map(|id| {
                    let identity = read(
                        &self.dir.join(format!("core-{id}.signed")),
                        MAX_SIGNED_OBJECT_BYTES,
                    )?;
                    let lsa = optional(
                        &self.dir.join(format!("core-{id}-lsa.signed")),
                        MAX_SIGNED_OBJECT_BYTES,
                    )?;
                    Ok(CoreFiles { identity, lsa })
                })
                .collect()
        }
    }

    pub(super) fn run(args: &[String]) -> Result<(), String> {
        let [config, dir, runtime] = args else {
            return Err("expected three mesh-run arguments".into());
        };
        let (config, dir, runtime) = (Path::new(config), Path::new(dir), Path::new(runtime));
        protected(config)?;
        protected(runtime)?;
        protected_dir(dir)?;
        let cfg = Config::read_file(config, RuntimeCapabilities::NO_RUNTIME)
            .map_err(|e| format!("mesh config: {e}"))?;
        if cfg.identity.role != NodeRole::Core
            || cfg.security.suite != CryptoSuite::Pq768
            || cfg.security.mode != SecurityMode::E2eRequired
            || cfg.dns.is_some()
            || cfg.limits != LimitsConfig::default()
        {
            return Err(
                "mesh-run requires Core/pq768/e2e-required with no DNS or optional limits".into(),
            );
        }
        protected_dir(&cfg.paths.state_dir)?;
        protected(&cfg.identity.private_key)?;
        let raw = read_material(runtime, 16 * 1024, Some(owner()))?;
        let spec: Spec =
            toml::from_str(std::str::from_utf8(&raw).map_err(|_| "mesh runtime must be UTF-8")?)
                .map_err(|_| "invalid mesh runtime TOML")?;
        spec.validate(cfg.identity.home_core_id)?;

        let materials = Materials {
            dir,
            peers: &spec.peers,
        };
        let (policy, roots, mut status) = policy_and_store(&cfg)?;
        let pem = PemIdentity {
            certificate_pem: read(&dir.join("identity.pem"), MAX_PEM)?,
            private_key_pem: read_material(&cfg.identity.private_key, 16 * 1024, Some(owner()))?,
            trust_anchor_pem: read(&dir.join("identity-ca.pem"), MAX_PEM)?,
        };
        let local = read(&dir.join("local.signed"), MAX_SIGNED_OBJECT_BYTES)?;
        let mut probe =
            MeshProbe::new(policy, &roots, &mut status, &pem, &local, &materials.lsa()?)
                .map_err(|e| format!("mesh local authority: {e:?}"))?;
        if probe.local().node_id != cfg.identity.node_id
            || probe.local().identity_generation != cfg.identity.identity_generation
        {
            return Err("local signed Core does not match configured identity".into());
        }
        let outer_roots = optional(&dir.join("outer-ca.pem"), MAX_PEM)?;
        let outer = || match &outer_roots {
            Some(pem) => OpenSslOuterTlsConnector::with_root_certificates(pem),
            None => OpenSslOuterTlsConnector::web_pki(),
        };
        if !matches!(spec.mode, Mode::Destination) {
            outer().map_err(|e| format!("mesh outer client credential: {e}"))?;
        }
        let mut acceptor = None;
        let mut listeners = Vec::new();
        let targets: Vec<_> = spec.routes.iter().map(target).collect();
        let locators: Vec<_> = spec
            .routes
            .iter()
            .zip(&targets)
            .filter_map(|(route, t)| {
                t.as_ref().map(|target| RouteLocator {
                    path: &route.path,
                    target,
                })
            })
            .collect();
        let admission = Admission::new(Limits {
            handshakes_global: 1,
            authenticated_global: 2,
            authenticated_per_peer: 1,
            bytes_global: 1024 * 1024,
        });
        let mut tun = None;
        let mut ready = false;
        let mut cursor = 0;
        let mut refresh_at = Instant::now();
        let mut last_loss = None;
        let mut preferred = None;
        let expected_ids: BTreeSet<_> = spec
            .peers
            .iter()
            .copied()
            .chain([cfg.identity.home_core_id])
            .collect();
        loop {
            let incoming = if listeners.is_empty() {
                None
            } else {
                accept(&listeners, &mut cursor)?
            };
            if ready && incoming.is_none() && !listeners.is_empty() && Instant::now() < refresh_at {
                thread::sleep(POLL);
                continue;
            }
            let peer_raw = materials.refresh(&mut probe)?;
            refresh_at = Instant::now() + RETRY;
            let signed: Vec<_> = peer_raw
                .iter()
                .map(|entry| DirectoryCore {
                    identity: &entry.identity,
                    seed_lsa: entry.lsa.as_deref(),
                })
                .collect();
            let graph = probe
                .verify_directory_graph(&local, &signed)
                .map_err(|e| format!("mesh signed graph: {e:?}"))?;
            if !graph.core_ids().eq(expected_ids.iter().copied()) {
                return Err("signed mesh graph slots differ from configured membership".into());
            }
            if !ready {
                // Require at least one authorized path before activating the real TUN or listeners.
                let mut usable = false;
                for route in &spec.routes {
                    match graph.authorize_path(&mut probe, &route.path) {
                        Ok(_) => usable = true,
                        Err(Error::NoRoute) => (),
                        Err(e) => return Err(format!("mesh route authorization: {e:?}")),
                    }
                }
                if !usable {
                    return Err("no authorized route at mesh startup".into());
                }
                tun = open_tun(&spec)?;
                if !matches!(spec.mode, Mode::Source) {
                    acceptor = Some(
                        OpenSslOuterTlsAcceptor::from_pem(
                            &read(&dir.join("outer.pem"), MAX_PEM)?,
                            &read_material(&dir.join("outer.key"), 16 * 1024, Some(owner()))?,
                        )
                        .map_err(|e| format!("mesh outer server credential: {e}"))?,
                    );
                    for (i, route) in spec.routes.iter().enumerate() {
                        let addr = route.listen.ok_or("mesh listener missing")?;
                        let listener = TcpListener::bind(addr)
                            .map_err(|e| format!("mesh bind {addr}: {}", e.kind()))?;
                        listener
                            .set_nonblocking(true)
                            .map_err(|_| "mesh listener setup failed")?;
                        listeners.push((i, listener));
                    }
                }
                ready = true;
                eprintln!("mesh ready node={}", probe.local().node_id);
            }
            match spec.mode {
                Mode::Source => {
                    let previous = preferred;
                    let result = graph.connect_tun(
                        &mut probe,
                        &locators,
                        &outer,
                        &admission,
                        (tun.as_ref().ok_or("mesh source TUN missing")?, previous),
                        |path, id| {
                            preferred = Some(path[1]);
                            confirmed("source", path, id);
                        },
                    );
                    match result {
                        Ok(e) => {
                            last_loss = None;
                            eprintln!(
                                "mesh epoch role=source circuit={:032x} tx={} rx={}",
                                u128::from_be_bytes(e.circuit_id),
                                e.tx,
                                e.rx
                            );
                        }
                        Err(Error::TopologyChanged) => {
                            eprintln!("mesh authenticated topology changed; rebuilding graph");
                            last_loss = None;
                            thread::sleep(RETRY);
                        }
                        Err(
                            e @ (Error::PathUnavailable(_)
                            | Error::ConfirmedPathLost(_)
                            | Error::NoRoute),
                        ) => {
                            if last_loss.as_ref() != Some(&e) {
                                eprintln!("mesh routes temporarily unavailable: {e:?}");
                            }
                            last_loss = Some(e);
                            thread::sleep(RETRY);
                        }
                        Err(e) => return Err(format!("mesh source stopped: {e:?}")),
                    }
                }
                Mode::Relay | Mode::Destination => {
                    let Some((i, socket)) = incoming else {
                        continue;
                    };
                    let path = &spec.routes[i].path;
                    let acceptor = acceptor
                        .as_ref()
                        .ok_or("mesh listener credential missing")?;
                    let result = match spec.mode {
                        Mode::Relay => graph
                            .relay(
                                &mut probe,
                                path,
                                socket,
                                targets[i].as_ref().ok_or("mesh relay target missing")?,
                                (acceptor, &outer),
                                &admission,
                            )
                            .map(|e| {
                                eprintln!(
                                    "mesh epoch role=relay circuit={:032x} ciphertext={:?}",
                                    u128::from_be_bytes(e.circuit_id),
                                    e.ciphertext_bytes
                                )
                            }),
                        Mode::Destination => graph
                            .respond_tun(
                                &mut probe,
                                path,
                                socket,
                                acceptor,
                                (
                                    &admission,
                                    tun.as_ref().ok_or("mesh destination TUN missing")?,
                                ),
                                |id| confirmed("destination", path, id),
                            )
                            .map(|e| {
                                eprintln!(
                                    "mesh epoch role=destination circuit={:032x} tx={} rx={}",
                                    u128::from_be_bytes(e.circuit_id),
                                    e.tx,
                                    e.rx
                                )
                            }),
                        Mode::Source => unreachable!(),
                    };
                    if let Err(e) = result {
                        // One unauthenticated connection must not kill the service.
                        // Replay poisoning and local authority errors are revisited
                        // by the next unconditional refresh before any admission.
                        eprintln!("mesh listener refused/closed circuit: {e:?}");
                        thread::sleep(POLL);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Spec;

        const SOURCE: &str = r#"
mode = "source"
peers = [2, 3, 4]
tun = "btun0"
mtu = 1400
[[routes]]
path = [1, 2, 4]
next = "192.0.2.2:18082"
tls_name = "core2.example.com"
[[routes]]
path = [1, 3, 4]
next = "192.0.2.3:18083"
tls_name = "core3.example.com"
"#;

        #[test]
        fn source_routes_bind_ordered_pair_with_distinct_first_hops() {
            let good: Spec = toml::from_str(SOURCE).unwrap();
            assert!(good.validate(1).is_ok());
            assert!(good.validate(2).is_err());
            for bad in [
                SOURCE.replace("[1, 3, 4]", "[1, 2, 3, 4]"),
                SOURCE.replace("[1, 3, 4]", "[1, 3, 2]"),
                SOURCE.replace("[1, 3, 4]", "[1, 3, 1, 4]"),
                SOURCE.replace("192.0.2.3:18083", "0.0.0.0:18083"),
                SOURCE.replace("1400", "1501"),
                SOURCE.replace("[2, 3, 4]", "[2, 2, 3, 4]"),
            ] {
                let parsed: Spec = toml::from_str(&bad).unwrap();
                assert!(parsed.validate(1).is_err());
            }
        }
    }
}
