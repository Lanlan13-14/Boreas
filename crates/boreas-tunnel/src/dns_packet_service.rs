//! Opt-in IPv4 private DNS for one authenticated Overlay binding. This owns
//! the real packet runtime, not a TUN, a host socket, or a daemon session.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use boreas_crypto::NodeRole;
use boreas_dns::{
    MAX_RESPONSE_BYTES,
    dispatch::{AuthoritySnapshot, ClientAuthorizer, QueryDispatcher},
    packet::{AuthenticatedPeerSource, PacketConfig},
    packet_runtime::{AuthenticatedSourceMap, PacketPollStats, PacketRuntime, PacketRuntimeConfig},
};
use boreas_pki::{
    VerifiedNetworkPolicy, dns_authority::VerifiedDnsAuthority,
    dns_service_policy::VerifiedDnsServicePolicy,
};
use boreas_proto::dns_service_policy::{Capability, DnsSubject};
use boreas_tun::inspect_packet;

use crate::{
    dns_runtime::{permanent_vip_in, verified_ipv4_resolver},
    e2e::E2eCircuit,
    packet_path::MAX_MTU,
    tls::PeerIdentity,
};

/// Default is disabled; setting this is not authorization to serve.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub enabled: bool,
    pub tcp: bool,
}

/// Explicit Core owner selection; credentials/addresses are never supplied by
/// the Edge. The worker gate must refer to this same circuit's liveness and
/// may be called concurrently; it must not update a single-owner UTC floor.
pub struct PublicForward {
    pub upstream: Arc<boreas_dns::secure_upstream::SecureUpstream>,
    pub excluded: Vec<String>,
    pub deadline: Instant,
    pub current: Arc<dyn Fn() -> bool + Send + Sync>,
}

pub use boreas_dns::secure_upstream::{MAX_CA_BYTES, SecureTransport, SecureUpstream};

/// Current policy and authority tokens selected by the circuit owner.
#[derive(Clone, Copy)]
pub struct Material<'a> {
    pub network: &'a VerifiedNetworkPolicy,
    pub service: &'a VerifiedDnsServicePolicy,
    pub authority: &'a VerifiedDnsAuthority,
}

#[derive(Clone, Copy)]
struct Binding<'a> {
    material: Material<'a>,
    core: PeerIdentity,
    edge: PeerIdentity,
    mtu: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BindingMismatch,
    NotAuthorized,
    NotFresh,
    InvalidMtuOrNetwork,
    InvalidAuthority,
    RuntimeUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

struct Liveness<F> {
    check: F,
    retired: AtomicBool,
}

impl<F: Fn() -> bool> Liveness<F> {
    fn is_current(&self) -> bool {
        if self.retired.load(Ordering::Acquire) {
            return false;
        }
        if !(self.check)() {
            self.retired.store(true, Ordering::Release);
            return false;
        }
        !self.retired.load(Ordering::Acquire)
    }
}

struct Client<F> {
    node_id: u16,
    source: AuthenticatedPeerSource,
    liveness: Arc<Liveness<F>>,
}

impl<F: Fn() -> bool + Send + Sync> ClientAuthorizer for Client<F> {
    fn authorized_node(&self, peer: AuthenticatedPeerSource) -> Option<u16> {
        (peer == self.source && self.liveness.is_current()).then_some(self.node_id)
    }
}

struct SingleSource(AuthenticatedPeerSource);

impl AuthenticatedSourceMap for SingleSource {
    fn authenticated_source(&self, observed: IpAddr) -> Option<AuthenticatedPeerSource> {
        (observed == self.0.address()).then_some(self.0)
    }
}

/// The exclusive owner must pass only packets from the bound Edge's verified
/// E2E circuit and return replies only on that same circuit. Do not use a shared
/// receive queue or queue popped replies past authorization on another worker.
/// Use one instance for the binding, not a new instance per query or transport.
/// This is not a multi-session/global admission controller.
pub struct DnsPacketService<F> {
    runtime: Option<PacketRuntime<QueryDispatcher<Client<F>>>>,
    source: SingleSource,
    dns_vip: Ipv4Addr,
    mtu: usize,
    started: Instant,
    expires_at: Instant,
    last_utc: u64,
    utc_until: u64,
    liveness: Arc<Liveness<F>>,
}

impl<F: Fn() -> bool + Send + Sync> DnsPacketService<F> {
    /// `is_current` is an additional, bounded, nonblocking denial gate owned by
    /// the transport. It must check the same live circuit and current selected
    /// identities, network, DNS service policy and signer/authority snapshot,
    /// including revocation, generations and anti-replay state. It must stay
    /// false after invalidation of this binding. If no such gate is available,
    /// leave this service disabled. Static signature verification is not a
    /// replacement for this gate. Capture the exact circuit ID and selected
    /// token versions in the gate, not a global "DNS enabled" predicate.
    ///
    /// Sample `started` immediately before sampling trusted `now_utc` (Unix
    /// microseconds). The mapped expiry is fixed; subsequent clock readings do
    /// not extend it. `now_utc` must also be sampled for each operation.
    pub fn try_new(
        config: Config,
        circuit: &E2eCircuit<'_>,
        material: Material<'_>,
        started: Instant,
        now_utc: u64,
        is_current: F,
    ) -> Result<Option<Self>, Error> {
        Self::try_new_for_path(
            config,
            circuit,
            usize::from(circuit.mtu_cap()),
            material,
            started,
            now_utc,
            None,
            is_current,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new_for_path(
        config: Config,
        circuit: &E2eCircuit<'_>,
        mtu: usize,
        material: Material<'_>,
        started: Instant,
        now_utc: u64,
        public: Option<PublicForward>,
        is_current: F,
    ) -> Result<Option<Self>, Error> {
        if config.enabled && mtu > usize::from(circuit.mtu_cap()) {
            return Err(Error::InvalidMtuOrNetwork);
        }
        Self::try_bind(
            config,
            Binding {
                material,
                core: circuit.local(),
                edge: circuit.info().peer,
                mtu,
            },
            started,
            now_utc,
            public,
            is_current,
        )
    }

    fn try_bind(
        config: Config,
        binding: Binding<'_>,
        started: Instant,
        now_utc: u64,
        public: Option<PublicForward>,
        is_current: F,
    ) -> Result<Option<Self>, Error> {
        if !config.enabled {
            return Ok(None);
        }
        let Binding {
            material:
                Material {
                    network,
                    service,
                    authority,
                },
            core,
            edge,
            mtu,
        } = binding;
        let context = network
            .require_default_runtime()
            .map_err(|_| Error::BindingMismatch)?;
        if core.policy() != Some(context)
            || edge.policy() != Some(context)
            || core.net_id != context.net_id()
            || edge.net_id != context.net_id()
            || core.role != NodeRole::Core
            || edge.role != NodeRole::Edge
            || core.identity_generation == 0
            || edge.identity_generation == 0
            || authority.net_id() != context.net_id()
            || authority.policy_digest() != context.policy_digest()
        {
            return Err(Error::BindingMismatch);
        }
        let base = context.overlay_base();
        if permanent_vip_in(base, core.node_id, core.role).is_none() {
            return Err(Error::BindingMismatch);
        }
        let edge_vip =
            permanent_vip_in(base, edge.node_id, edge.role).ok_or(Error::BindingMismatch)?;
        let (network_from, network_until) = context.validity();
        let (authority_from, authority_until) = authority.freshness();
        let (service_from, service_until) = service.validity();
        let utc_from = network_from.max(authority_from).max(service_from);
        let utc_until = network_until.min(authority_until).min(service_until);
        if now_utc < utc_from || now_utc >= utc_until || started > Instant::now() {
            return Err(Error::NotFresh);
        }
        // The existing authority still requires Replica. Forwarding adds a
        // distinct PublicForward check and grants no Advertise/Register rights.
        let core_subject = DnsSubject {
            node_id: core.node_id,
            identity_generation: core.identity_generation,
        };
        if !service.has_grant_at(
            network,
            core.net_id,
            core_subject,
            Capability::Replica,
            now_utc,
        ) || public.is_some() && !service.has_grant_at(
            network, core.net_id, core_subject, Capability::PublicForward, now_utc,
        ) || !is_current()
        {
            return Err(Error::NotAuthorized);
        }
        let expires_at = started
            .checked_add(Duration::from_micros(utc_until - now_utc))
            .filter(|expiry| Instant::now() < *expiry)
            .ok_or(Error::NotFresh)?;
        if mtu > MAX_MTU {
            return Err(Error::InvalidMtuOrNetwork);
        }
        let packet = PacketConfig::new_ipv4(Ipv4Addr::from(base), mtu)
            .map_err(|_| Error::InvalidMtuOrNetwork)?;
        let dns_vip = packet.dns_v4();
        let resolver = verified_ipv4_resolver(authority, edge_vip, MAX_RESPONSE_BYTES)
            .map_err(|_| Error::InvalidAuthority)?;
        let snapshot = AuthoritySnapshot::new(resolver, started, expires_at)
            .map_err(|_| Error::InvalidAuthority)?;
        let source = AuthenticatedPeerSource::from_authenticated_overlay_peer(IpAddr::V4(edge_vip))
            .map_err(|_| Error::BindingMismatch)?;
        let liveness = Arc::new(Liveness {
            check: is_current,
            retired: AtomicBool::new(false),
        });
        let client = Client {
            node_id: edge.node_id,
            source,
            liveness: Arc::clone(&liveness),
        };
        let mut dispatcher = QueryDispatcher::new(authority.zone(), Some(snapshot), None, client)
            .map_err(|_| Error::InvalidAuthority)?;
        if let Some(public) = public {
            dispatcher.enable_packet_forwarding(
                public.upstream, public.excluded, expires_at.min(public.deadline), public.current,
            ).map_err(|_| Error::RuntimeUnavailable)?;
        }
        let mut seed = [0; 8];
        if config.tcp {
            openssl::rand::rand_bytes(&mut seed).map_err(|_| Error::RuntimeUnavailable)?;
        }
        let runtime =
            PacketRuntime::new_private_dispatcher(
                dispatcher,
                packet,
                PacketRuntimeConfig {
                    tcp: boreas_dns::tcp::TcpDnsConfig {
                        idle_timeout: Duration::from_secs(10),
                        max_connection_age: Duration::from_secs(60),
                        ..Default::default()
                    },
                    random_seed: u64::from_ne_bytes(seed),
                    ..PacketRuntimeConfig::default()
                },
                config.tcp,
            )
            .map_err(|_| Error::RuntimeUnavailable)?;
        let mut instance = Self {
            runtime: Some(runtime),
            source: SingleSource(source),
            dns_vip,
            mtu,
            started,
            expires_at,
            last_utc: now_utc,
            utc_until,
            liveness,
        };
        if !instance.check_live(now_utc) {
            return Err(Error::NotAuthorized);
        }
        Ok(Some(instance))
    }

    /// After the first invalidation the service permanently drops all queues and
    /// TCP state. In particular, a UTC rollback cannot resume a stale runtime.
    pub(crate) fn check_live(&mut self, now_utc: u64) -> bool {
        if self.runtime.is_none() {
            return false;
        }
        if !self.liveness.is_current()
            || now_utc < self.last_utc
            || now_utc >= self.utc_until
            || Instant::now() >= self.expires_at
        {
            self.runtime = None;
            return false;
        }
        self.last_utc = now_utc;
        true
    }

    pub(crate) fn dns_vip(&self) -> Ipv4Addr {
        self.dns_vip
    }

    /// Queue a packet from this binding only. `false` means the packet was not
    /// accepted; it must not be retried against another DNS server by this seam.
    pub fn push_input(&mut self, packet: &[u8], now_utc: u64) -> bool {
        self.check_live(now_utc)
            && packet.len() <= self.mtu
            && inspect_packet(packet).is_ok_and(|meta| {
                meta.source == self.source.0.address()
                    && meta.destination == IpAddr::V4(self.dns_vip)
                    && meta.fragment.is_none()
                    && meta.header_len == 20
                    && matches!(meta.protocol, 6 | 17)
            })
            && self
                .runtime
                .as_mut()
                .is_some_and(|runtime| runtime.push_input(packet).is_ok())
    }

    /// Drive queued packets and TCP timers without opening an upstream socket.
    pub fn poll(&mut self, now_utc: u64) -> Option<PacketPollStats> {
        if !self.check_live(now_utc) {
            return None;
        }
        let millis = i64::try_from(self.started.elapsed().as_millis()).ok()?;
        let stats = self.runtime.as_mut()?.poll_private(millis, &self.source);
        self.check_live(now_utc).then_some(stats)
    }

    /// Recheck before handing one reply to the exclusive circuit owner, who
    /// must keep the binding current through actual transport delivery.
    pub fn pop_output(&mut self, now_utc: u64) -> Option<Vec<u8>> {
        if !self.check_live(now_utc) {
            return None;
        }
        let packet = self.runtime.as_ref()?.pop_output()?;
        let meta = inspect_packet(&packet).ok()?;
        (meta.source == IpAddr::V4(self.dns_vip)
            && meta.destination == self.source.0.address()
            && self.check_live(now_utc))
        .then_some(packet)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::dns_runtime::tests::{
        Fixture, dns_payload, dns_query, fixture_at, sign, udp_datagram,
    };
    use boreas_proto::dns_service_policy::{Capabilities, DnsServiceGrant, DnsServicePolicy};

    const UNIT: u64 = 1_000_000;
    const NOW: u64 = 1_500 * UNIT;
    const SERVICE_END: u64 = 1_800 * UNIT;
    const EDGE: [u8; 4] = [10, 20, 1, 2];
    const DNS: [u8; 4] = [10, 20, 0, 53];

    fn token(f: &Fixture, capability: Capability, generation: u64) -> VerifiedDnsServicePolicy {
        let raw = DnsServicePolicy {
            net_id: f.local.net_id,
            policy_digest: f.network.policy_digest(),
            sequence: 1,
            issued_at: 1_000 * UNIT,
            expires: SERVICE_END,
            grants: vec![DnsServiceGrant {
                subject: DnsSubject {
                    node_id: f.local.node_id,
                    identity_generation: generation,
                },
                capabilities: Capabilities::default().with(capability),
            }],
        }
        .encode_tbs()
        .unwrap();
        let (ed, pq) = sign(
            &f.root_ed,
            &f.root_pq,
            &DnsServicePolicy::signature_input(&raw).unwrap(),
        );
        VerifiedDnsServicePolicy::verify(&raw, &ed, &pq, &f.root, &f.network, NOW).unwrap()
    }

    fn binding<'a>(f: &'a Fixture, service: &'a VerifiedDnsServicePolicy) -> Binding<'a> {
        Binding {
            material: Material {
                network: &f.network,
                service,
                authority: &f.authority,
            },
            core: f.local,
            edge: PeerIdentity::policy_bound(
                f.local.net_id,
                2,
                3,
                NodeRole::Edge,
                f.local.policy().unwrap(),
            )
            .unwrap(),
            mtu: 1500,
        }
    }

    pub(crate) fn signed_packet_binding<F: Fn() -> bool + Send + Sync>(
        f: &Fixture,
        mtu: usize,
        is_current: F,
    ) -> (PeerIdentity, DnsPacketService<F>) {
        let policy = token(f, Capability::Replica, f.local.identity_generation);
        let bindings = Binding {
            mtu,
            ..binding(f, &policy)
        };
        let dns = DnsPacketService::try_bind(
            Config { enabled: true, tcp: false },
            bindings,
            Instant::now(),
            NOW,
            None,
            is_current,
        )
        .unwrap()
        .unwrap();
        (bindings.edge, dns)
    }

    fn packet(source: [u8; 4], name: &str, rrtype: u16) -> Vec<u8> {
        udp_datagram(source, DNS, 40_000, 53, &dns_query(name, rrtype), true)
    }

    #[test]
    fn service_requires_opt_in_and_exact_replica_grant() {
        let f = fixture_at(UNIT);
        let no_replica = token(&f, Capability::Advertise, 1);
        let wrong_generation = token(&f, Capability::Replica, 2);
        assert!(
            DnsPacketService::try_bind(
                Config::default(),
                binding(&f, &no_replica),
                Instant::now(),
                NOW,
                None,
                || panic!("disabled service checked liveness"),
            )
            .unwrap()
            .is_none()
        );
        for service in [&no_replica, &wrong_generation] {
            assert!(matches!(
                DnsPacketService::try_bind(
                    Config { enabled: true, tcp: false },
                    binding(&f, service),
                    Instant::now(),
                    NOW,
                    None,
                    || true,
                ),
                Err(Error::NotAuthorized)
            ));
        }
    }

    #[test]
    fn verified_private_udp_uses_bound_source_and_drops_queued_reply_on_invalidation() {
        let f = fixture_at(UNIT);
        let policy = token(&f, Capability::Replica, 1);
        let live = AtomicBool::new(true);
        let open = || {
            DnsPacketService::try_bind(
                Config { enabled: true, tcp: false },
                binding(&f, &policy),
                Instant::now(),
                NOW,
                None,
                || live.load(Ordering::SeqCst),
            )
            .unwrap()
            .unwrap()
        };
        let mut dns = open();
        let query = packet(EDGE, "host.b.example", 1);
        assert!(!dns.push_input(&packet([10, 20, 1, 3], "host.b.example", 1), NOW));
        for (name, kind, rcode, count) in [
            ("HOST.b.example", 1, 0, 1),
            ("host.b.example", 28, 0, 0),
            ("absent.b.example", 1, 3, 0),
        ] {
            assert!(dns.push_input(&packet(EDGE, name, kind), NOW));
            assert_eq!(dns.poll(NOW).unwrap().udp_answered, 1);
            let response = dns.pop_output(NOW).unwrap();
            let message = dns_payload(&response);
            assert_eq!(message[3] & 0x0f, rcode);
            assert_eq!(u16::from_be_bytes([message[6], message[7]]), count);
            if count == 1 {
                assert_eq!(&message[message.len() - 4..], &[10, 20, 1, 1]);
            }
        }
        assert!(dns.push_input(&packet(EDGE, "lookalike-b.example", 1), NOW));
        assert_eq!(dns.poll(NOW).unwrap().udp_answered, 0);
        assert!(dns.pop_output(NOW).is_none());
        assert!(dns.push_input(&query, NOW));
        assert_eq!(dns.poll(NOW).unwrap().output_queued, 1);
        assert!(dns.pop_output(SERVICE_END).is_none());
        assert!(!dns.push_input(&query, NOW));

        let mut dns = open();
        assert!(dns.push_input(&query, NOW));
        assert_eq!(dns.poll(NOW).unwrap().output_queued, 1);
        live.store(false, Ordering::SeqCst);
        assert!(dns.pop_output(NOW).is_none());
        live.store(true, Ordering::SeqCst);
        assert!(dns.poll(NOW).is_none());
    }
}
