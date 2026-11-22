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
        collections::{BTreeMap, BTreeSet},
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
        VerifiedNetworkContext,
        management::MAX_SIGNED_OBJECT_BYTES,
        provisioning::{RootsBundle, parse_net_id_hex},
        status_store::{MAX_IDENTITY_REVOCATION_BYTES, MAX_SCOPED_REVOCATION_BYTES, StatusStore},
    };
    use boreas_tun::linux::{LinuxTunDevice, LinuxTunQueue};
    use boreas_tunnel::{
        ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector,
        mesh_probe::{Candidate, Error, MeshProbe, mesh_trust, utc_now},
        mesh_route::{DirectoryCore, RouteLocator, RoutedPair},
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
    const DIRECTORY_POLL: Duration = Duration::from_secs(5);
    const MAX_PEM: usize = 64 * 1024;

    #[derive(Deserialize, PartialEq, Eq)]
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
        #[serde(default)]
        routes: Vec<Route>,
        routing: Option<Routing>,
        #[serde(default)]
        directory: Vec<DirectoryLink>,
        directory_discovery: Option<DirectoryDiscovery>,
    }

    // Strictly lower slot initiates, higher slot listens; prohibiting reverse
    // edges avoids circular waits in the single-owner runtime.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DirectoryLink {
        peer: u8,
        listen: Option<SocketAddr>,
        next: Option<SocketAddr>,
        tls_name: Option<String>,
    }

    // A provisioned coordinator is a locator/polling hub, never a new issuer.
    // Its one socket admits members by exact inner TLS SPKI, not by source IP.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DirectoryDiscovery {
        coordinator: u8,
        listen: Option<SocketAddr>,
        next: Option<SocketAddr>,
        tls_name: Option<String>,
    }

    const DISCOVERED: usize = usize::MAX; // sentinel; real indices are <16

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Route {
        path: Vec<u8>,
        listen: Option<SocketAddr>,
        next: Option<SocketAddr>,
        tls_name: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Routing {
        source: u8,
        destination: u8,
        listen: Option<SocketAddr>,
        #[serde(default)]
        incoming: Vec<u8>,
        #[serde(default)]
        outgoing: Vec<NeighborTarget>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NeighborTarget {
        peer: u8,
        next: SocketAddr,
        tls_name: String,
    }

    impl Routing {
        fn validate(
            &self,
            local: u8,
            mode: &Mode,
            peers: &BTreeSet<u8>,
            listens: &mut BTreeSet<SocketAddr>,
            targets: &mut BTreeSet<SocketAddr>,
        ) -> Result<(), String> {
            if self.source >= self.destination
                || !peers.contains(&self.source)
                || !peers.contains(&self.destination)
            {
                return Err("invalid routed mesh endpoint pair".into());
            }
            let expected = if local == self.source {
                Mode::Source
            } else if local == self.destination {
                Mode::Destination
            } else {
                Mode::Relay
            };
            let ingress = expected != Mode::Source;
            let egress = expected != Mode::Destination;
            if *mode != expected
                || self.listen.is_some() != ingress
                || self.incoming.is_empty() == ingress
                || self.outgoing.is_empty() == egress
                || self.incoming.len() >= usize::from(MAX_CORES)
                || self.outgoing.len() >= usize::from(MAX_CORES)
                || self
                    .listen
                    .is_some_and(|a| a.port() == 0 || !listens.insert(a))
            {
                return Err(
                    "routed mesh role, ingress or egress does not match endpoint pair".into(),
                );
            }
            let mut seen = BTreeSet::new();
            for &id in &self.incoming {
                if id == local || id == self.destination || !peers.contains(&id) || !seen.insert(id)
                {
                    return Err("invalid or duplicate routed mesh ingress peer".into());
                }
            }
            seen.clear();
            for hop in &self.outgoing {
                if hop.peer == local
                    || hop.peer == self.source
                    || !peers.contains(&hop.peer)
                    || !seen.insert(hop.peer)
                    || hop.next.port() == 0
                    || hop.next.ip().is_unspecified()
                    || !targets.insert(hop.next)
                    || !valid_tls_name(&hop.tls_name)
                {
                    return Err("invalid or duplicate routed mesh egress peer/locator".into());
                }
            }
            Ok(())
        }
    }

    impl Spec {
        fn directory_enabled(&self) -> bool {
            self.directory_discovery.is_some() || !self.directory.is_empty()
        }

        fn validate(&self, local: u8) -> Result<(), String> {
            let mut peers = BTreeSet::from([local]);
            if self.peers.len() >= usize::from(MAX_CORES)
                || self
                    .peers
                    .iter()
                    .any(|&id| !(1..=MAX_CORES).contains(&id) || !peers.insert(id))
                || self.routes.len() > MAX_ROUTES
                || self.routes.is_empty() != self.routing.is_some()
            {
                return Err("invalid mesh peer/route count or slot; configure exactly one of routes or routing".into());
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
            if let Some(routing) = &self.routing {
                routing.validate(local, &self.mode, &peers, &mut listens, &mut targets)?;
            }
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
            if let Some(d) = &self.directory_discovery {
                let outgoing = local != d.coordinator;
                if !self.directory.is_empty()
                    || !peers.contains(&d.coordinator)
                    || d.listen.is_some() == outgoing
                    || d.next.is_some() != outgoing
                    || d.tls_name.is_some() != outgoing
                    || d.listen.is_some_and(|a| {
                        a.port() == 0
                            || listens.iter().any(|b| {
                                a.port() == b.port()
                                    && (a.ip() == b.ip()
                                        || a.ip().is_unspecified()
                                        || b.ip().is_unspecified())
                            })
                    })
                    || d.next.is_some_and(|a| {
                        a.port() == 0 || a.ip().is_unspecified() || targets.contains(&a)
                    })
                    || d.tls_name.as_deref().is_some_and(|s| !valid_tls_name(s))
                {
                    return Err(
                        "invalid directory discovery configuration or overlapping legacy links"
                            .into(),
                    );
                }
            }
            let mut adjacent = BTreeSet::new();
            for d in &self.directory {
                let outgoing = local < d.peer;
                if d.peer == local
                    || !peers.contains(&d.peer)
                    || !adjacent.insert(d.peer)
                    || d.listen.is_some() == outgoing
                    || d.next.is_some() != outgoing
                    || d.tls_name.is_some() != outgoing
                    || d.listen.is_some_and(|a| {
                        a.port() == 0
                            || self
                                .routing
                                .as_ref()
                                .and_then(|r| r.listen)
                                .is_some_and(|b| {
                                    a.port() == b.port()
                                        && (a.ip() == b.ip()
                                            || a.ip().is_unspecified()
                                            || b.ip().is_unspecified())
                                })
                            || !listens.insert(a)
                    })
                    || d.next.is_some_and(|a| {
                        a.port() == 0 || a.ip().is_unspecified() || !targets.insert(a)
                    })
                    || d.tls_name.as_deref().is_some_and(|s| !valid_tls_name(s))
                {
                    return Err("invalid or duplicate dedicated directory link".into());
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
        Some(client_target(route.next?, route.tls_name.as_deref()?))
    }

    fn client_target(address: SocketAddr, name: &str) -> ClientTarget {
        ClientTarget {
            address,
            ws_host: name.into(),
            tls_server_name: name.into(),
            path: "/tunnel".into(),
        }
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
        let (fingerprint, _) = roots
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
        let (status_trust, identity_trust) = mesh_trust(&roots, &policy, now)
            .map_err(|e| format!("mesh authority trust: {e:?}"))?;
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

    fn bind_directory(addr: SocketAddr) -> Result<TcpListener, String> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| format!("mesh directory bind {addr}: {}", e.kind()))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "mesh directory listener setup failed")?;
        Ok(listener)
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
                    None,
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
        let mut probe = MeshProbe::new_durable(
            policy,
            &roots,
            &mut status,
            &pem,
            &local,
            &materials.lsa()?,
            (&cfg.paths.state_dir.join("core-lsa.state"), owner()),
        )
        .map_err(|e| format!("mesh local authority: {e:?}"))?;
        if probe.local().node_id != cfg.identity.node_id
            || probe.local().identity_generation != cfg.identity.identity_generation
        {
            return Err("local signed Core does not match configured identity".into());
        }
        let mailbox = dir.join("identity-revocation.signed");
        probe.set_identity_revocation_mailbox(move || {
            optional(&mailbox, MAX_IDENTITY_REVOCATION_BYTES).map_err(std::io::Error::other)
        });
        probe.set_scoped_revocation_mailboxes(move |name| {
            optional(&dir.join(name), MAX_SCOPED_REVOCATION_BYTES).map_err(std::io::Error::other)
        });
        let outer_roots = optional(&dir.join("outer-ca.pem"), MAX_PEM)?;
        let outer = || match &outer_roots {
            Some(pem) => OpenSslOuterTlsConnector::with_root_certificates(pem),
            None => OpenSslOuterTlsConnector::web_pki(),
        };
        let mut directory_listeners = Vec::new();
        let mut directory_targets = Vec::new();
        for d in &spec.directory {
            let i = spec
                .peers
                .iter()
                .position(|&id| id == d.peer)
                .ok_or("missing directory peer")?;
            if let Some(addr) = d.listen {
                directory_listeners.push((i, bind_directory(addr)?));
            } else {
                directory_targets.push((
                    i,
                    client_target(
                        d.next.ok_or("missing directory target")?,
                        d.tls_name.as_deref().ok_or("missing directory TLS name")?,
                    ),
                ));
            }
        }
        if let Some(d) = &spec.directory_discovery {
            if let Some(addr) = d.listen {
                directory_listeners.push((DISCOVERED, bind_directory(addr)?));
            } else {
                let i = spec
                    .peers
                    .iter()
                    .position(|&id| id == d.coordinator)
                    .ok_or("missing signed directory coordinator")?;
                directory_targets.push((
                    i,
                    client_target(
                        d.next.ok_or("missing coordinator target")?,
                        d.tls_name
                            .as_deref()
                            .ok_or("missing coordinator TLS name")?,
                    ),
                ));
            }
        }
        if !matches!(spec.mode, Mode::Destination) || !directory_targets.is_empty() {
            outer().map_err(|e| format!("mesh outer client credential: {e}"))?;
        }
        let acceptor = if !matches!(spec.mode, Mode::Source) || !directory_listeners.is_empty() {
            Some(
                OpenSslOuterTlsAcceptor::from_pem(
                    &read(&dir.join("outer.pem"), MAX_PEM)?,
                    &read_material(&dir.join("outer.key"), 16 * 1024, Some(owner()))?,
                )
                .map_err(|e| format!("mesh outer server credential: {e}"))?,
            )
        } else {
            None
        };
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
        let routed_targets = spec.routing.as_ref().map(|r| {
            r.outgoing
                .iter()
                .map(|hop| (hop.peer, client_target(hop.next, &hop.tls_name)))
                .collect::<BTreeMap<_, _>>()
        });
        let routed = spec
            .routing
            .as_ref()
            .zip(routed_targets.as_ref())
            .map(|(r, outgoing)| RoutedPair {
                endpoints: (r.source, r.destination),
                incoming: &r.incoming,
                outgoing,
            });
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
        let mut dir_cursor = 0;
        let mut prefer_directory_dial = false;
        let mut dir_poll = vec![Instant::now(); directory_targets.len()];
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
            let due = dir_poll
                .iter()
                .enumerate()
                .min_by_key(|&(_, t)| *t)
                .and_then(|(i, due)| (Instant::now() >= *due).then_some(i));
            let dir_incoming = if due.is_some() && prefer_directory_dial {
                None
            } else {
                accept(&directory_listeners, &mut dir_cursor)?
            };
            if ready
                && incoming.is_none()
                && !listeners.is_empty()
                && dir_incoming.is_none()
                && due.is_none()
                && Instant::now() < refresh_at
            {
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
            if spec.directory_enabled() {
                for (entry, &id) in signed.iter().zip(&spec.peers) {
                    if probe
                        .directory_member_id(entry.identity)
                        .map_err(|e| format!("mesh directory member: {e:?}"))?
                        != id
                    {
                        return Err(
                            "signed directory slot differs from configured membership".into()
                        );
                    }
                }
            }
            let previous_graph = match probe.verify_directory_graph(&local, &signed) {
                Ok(graph) => Ok(graph),
                Err(Error::DirectoryPending) => Err(Error::DirectoryPending),
                Err(e) => return Err(format!("mesh signed graph: {e:?}")),
            };
            let members: Vec<_> = signed.iter().map(|entry| entry.identity).collect();
            let mut synced = false;
            if let Some((i, socket)) = dir_incoming {
                prefer_directory_dial = true;
                let outer = acceptor
                    .as_ref()
                    .ok_or("directory listener credential missing")?;
                let result = if i == DISCOVERED {
                    probe
                        .accept_directory_member(socket, &members, outer, &admission)
                        .map(|_| ())
                } else {
                    probe.accept_directory(socket, members[i], &members, outer, &admission)
                };
                if let Err(e) = result {
                    if matches!(
                        e,
                        Error::LsaConflict | Error::LsaState | Error::RevocationState
                    ) {
                        return Err(format!("mesh directory authority stopped: {e:?}"));
                    }
                    eprintln!("mesh directory listener refused/closed exchange: {e:?}");
                }
                synced = true;
            } else if let Some(poll) = due {
                prefer_directory_dial = false;
                let (i, target) = &directory_targets[poll];
                let result = probe.sync_directory(
                    Candidate {
                        target,
                        signed_identity: members[*i],
                    },
                    &members,
                    &outer,
                    &admission,
                );
                dir_poll[poll] = Instant::now() + DIRECTORY_POLL;
                if let Err(e) = result {
                    if matches!(
                        e,
                        Error::LsaConflict | Error::LsaState | Error::RevocationState
                    ) {
                        return Err(format!("mesh directory authority stopped: {e:?}"));
                    }
                    eprintln!("mesh directory dial refused/closed exchange: {e:?}");
                }
                synced = true;
            }
            let graph = if synced {
                probe.verify_directory_graph(&local, &signed)
            } else {
                previous_graph
            };
            let graph = match graph {
                Ok(graph) => graph,
                Err(Error::DirectoryPending) if spec.directory_enabled() => {
                    thread::sleep(POLL);
                    continue;
                }
                Err(e) => return Err(format!("mesh signed graph: {e:?}")),
            };
            if !graph.core_ids().eq(expected_ids.iter().copied()) {
                return Err("signed mesh graph slots differ from configured membership".into());
            }
            if !ready {
                // Require at least one authorized path before activating the real TUN or listeners.
                let mut usable = false;
                if let Some(pair) = &routed {
                    match graph.authorize_routed_pair(&mut probe, pair) {
                        Ok(()) => usable = true,
                        Err(Error::NoRoute | Error::IdentityRevoked | Error::CoreRevoked) => (),
                        Err(e) => return Err(format!("mesh route authorization: {e:?}")),
                    }
                } else {
                    for route in &spec.routes {
                        match graph.authorize_path(&mut probe, &route.path) {
                            Ok(_) => usable = true,
                            Err(Error::NoRoute | Error::IdentityRevoked | Error::CoreRevoked) => (),
                            Err(e) => return Err(format!("mesh route authorization: {e:?}")),
                        }
                    }
                }
                if !usable {
                    if !spec.directory_enabled() {
                        return Err("no authorized route at mesh startup".into());
                    }
                    thread::sleep(POLL);
                    continue;
                }
                tun = open_tun(&spec)?;
                if !matches!(spec.mode, Mode::Source) {
                    let addresses = spec
                        .routes
                        .iter()
                        .map(|r| r.listen)
                        .chain(spec.routing.iter().map(|r| r.listen));
                    for (i, addr) in addresses.enumerate() {
                        let addr = addr.ok_or("mesh listener missing")?;
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
                    let endpoint = (tun.as_ref().ok_or("mesh source TUN missing")?, previous);
                    let on_confirmed = |path: &[u8], id| {
                        preferred = Some(path[1]);
                        confirmed("source", path, id);
                    };
                    let result = if let Some(pair) = &routed {
                        graph.connect_routed_tun(
                            &mut probe,
                            pair,
                            &outer,
                            &admission,
                            endpoint,
                            on_confirmed,
                        )
                    } else {
                        graph.connect_tun(
                            &mut probe,
                            &locators,
                            &outer,
                            &admission,
                            endpoint,
                            on_confirmed,
                        )
                    };
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
                        Err(e) if e.member_denial() => {
                            // This is an authority transition, not a transport
                            // retry. Rebuild and rank only still-authorized routes.
                            eprintln!("mesh source route closed: {e:?}");
                            preferred = None;
                            last_loss = None;
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
                    let acceptor = acceptor
                        .as_ref()
                        .ok_or("mesh listener credential missing")?;
                    let result = match spec.mode {
                        Mode::Relay => {
                            let outer = (acceptor, &outer as &dyn Fn() -> _);
                            if let Some(pair) = &routed {
                                graph.relay_routed(&mut probe, pair, socket, outer, &admission)
                            } else {
                                graph.relay(
                                    &mut probe,
                                    &spec.routes[i].path,
                                    socket,
                                    targets[i].as_ref().ok_or("mesh relay target missing")?,
                                    outer,
                                    &admission,
                                )
                            }
                            .map(|e| {
                                eprintln!(
                                    "mesh epoch role=relay circuit={:032x} ciphertext={:?}",
                                    u128::from_be_bytes(e.circuit_id),
                                    e.ciphertext_bytes
                                )
                            })
                        }
                        Mode::Destination => {
                            let endpoint = (
                                &admission,
                                tun.as_ref().ok_or("mesh destination TUN missing")?,
                            );
                            if let Some(pair) = &routed {
                                graph.respond_routed_tun(
                                    &mut probe,
                                    pair,
                                    socket,
                                    acceptor,
                                    endpoint,
                                    |path, id| confirmed("destination", path, id),
                                )
                            } else {
                                let path = &spec.routes[i].path;
                                graph.respond_tun(
                                    &mut probe,
                                    path,
                                    socket,
                                    acceptor,
                                    endpoint,
                                    |id| confirmed("destination", path, id),
                                )
                            }
                            .map(|e| {
                                eprintln!(
                                    "mesh epoch role=destination circuit={:032x} tx={} rx={}",
                                    u128::from_be_bytes(e.circuit_id),
                                    e.tx,
                                    e.rx
                                )
                            })
                        }
                        Mode::Source => unreachable!(),
                    };
                    if let Err(e) = result {
                        if matches!(
                            e,
                            Error::LsaConflict | Error::LsaState | Error::RevocationState
                        ) {
                            return Err(format!("mesh business authority stopped: {e:?}"));
                        }
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

        const ROUTED: &str = r#"
mode = "relay"
peers = [1, 2, 4]

[routing]
source = 1
destination = 4
incoming = [1, 2]
listen = "192.0.2.3:18082"

[[routing.outgoing]]
peer = 4
next = "192.0.2.4:18082"
tls_name = "core4.example.com"
"#;

        #[test]
        fn routed_mesh_config_binds_pair_and_local_ingress_egress() {
            let good: Spec = toml::from_str(ROUTED).unwrap();
            assert!(good.validate(3).is_ok());
            for bad in [
                ROUTED.replace("destination = 4", "destination = 1"),
                ROUTED.replace("destination = 4", "destination = 5"),
                ROUTED.replace("[1, 2]", "[1, 1]"),
                ROUTED.replace("[1, 2]", "[3]"),
                ROUTED.replace("[1, 2]", "[4]"),
                ROUTED.replace("[1, 2]", "[]"),
                ROUTED.replace("peer = 4", "peer = 1"),
                ROUTED.replace("peer = 4", "peer = 3"),
                ROUTED.replace("192.0.2.4:18082", "0.0.0.0:18082"),
                ROUTED.replace("core4.example.com", "https://core4.example.com"),
                format!("{ROUTED}\n[[routes]]\npath = [1, 3, 4]\n"),
                format!(
                    "{ROUTED}\n[directory_discovery]\ncoordinator = 3\nlisten = \"0.0.0.0:18082\"\n"
                ),
            ] {
                let parsed: Spec = toml::from_str(&bad).unwrap();
                assert!(parsed.validate(3).is_err(), "{bad}");
            }
        }

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
