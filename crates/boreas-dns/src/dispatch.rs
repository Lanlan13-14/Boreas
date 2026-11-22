//! Bounded split DNS for complete, prefix-free messages from trusted ingress.
//!
//! The configured private suffix is independent of authority availability. Only
//! the public branch can call the one optional explicit TCP upstream. This is
//! a blocking service component, not a listener or a packet/daemon integration.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::packet::AuthenticatedPeerSource;
use crate::upstream::{TcpUpstream, UpstreamError};
use crate::{
    AuthoritativeDns, DnsError, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES, OPT_HEADER_BYTES, is_in_zone,
    normalize_name, parse_query, truncate_parsed,
};

const MAX_AUTHORITY_ENTRIES: usize = 128;
const MAX_AUTHORITY_SOURCES: usize = 4096;
const WINDOW: Duration = Duration::from_secs(1);
const MAX_TRACKED_IDENTITIES: usize = 256;
const GLOBAL: Limits = Limits {
    in_flight: 64,
    queries: 1024,
    bytes: 4 * 1024 * 1024,
};
const PER_IDENTITY: Limits = Limits {
    in_flight: 8,
    queries: 64,
    bytes: 256 * 1024,
};

/// Live, per-network DNS client policy implemented by the trusted ingress owner.
///
/// Return the authenticated, currently DNS-authorized stable NodeID for this
/// binding (not a NodeID inferred from packet bytes). Reject revoked, stale,
/// foreign, or no-longer-bound sources. Both addresses of a dual-stack client
/// must map to the same ID; do not recycle an ID within the admitted scope.
/// Implementations must be bounded and nonblocking. The dispatcher is not an
/// authentication authority; the ingress owner must preserve the live binding
/// and verify packet-source integrity before calling it.
pub trait ClientAuthorizer: Send + Sync {
    fn authorized_node(&self, peer: AuthenticatedPeerSource) -> Option<u16>;
}

/// An authority snapshot and its effective half-open monotonic freshness window.
///
/// The caller must verify provenance and derive this interval from all applicable
/// policy, signer and snapshot validity limits, without extending it on clock
/// rollback. These fields are not a signature check or a revocation mechanism.
pub struct AuthoritySnapshot {
    resolver: AuthoritativeDns,
    valid_from: Instant,
    expires_at: Instant,
}

impl AuthoritySnapshot {
    pub fn new(
        resolver: AuthoritativeDns,
        valid_from: Instant,
        expires_at: Instant,
    ) -> Result<Self, DnsError> {
        let zone = &resolver.zone;
        if valid_from >= expires_at
            || resolver.sources.authorized.len() > MAX_AUTHORITY_SOURCES
            || zone.refused.len() > MAX_AUTHORITY_ENTRIES
            || zone
                .records
                .values()
                .flatten()
                .take(MAX_AUTHORITY_ENTRIES + 1)
                .count()
                > MAX_AUTHORITY_ENTRIES - zone.refused.len()
        {
            return Err(DnsError::InvalidConfiguration);
        }
        Ok(Self {
            resolver,
            valid_from,
            expires_at,
        })
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.valid_from <= now && now < self.expires_at
    }
}

/// Local failure to dispatch. None of these errors carries a DNS response.
/// Do not retry a failed dispatch via another resolver.
#[derive(Debug)]
pub enum DispatchError {
    Unauthorized,
    DeadlineExceeded,
    ResourceLimit,
    InvalidQuery(DnsError),
    AuthorityUnavailable,
    AuthorityNotFresh,
    AuthorityResponse(DnsError),
    PublicForwardingDisabled,
    PublicEdnsOptionsUnsupported,
    Upstream(UpstreamError),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("DNS client is not authorized"),
            Self::DeadlineExceeded => f.write_str("DNS dispatch deadline exceeded"),
            Self::ResourceLimit => f.write_str("DNS dispatch budget exhausted"),
            Self::InvalidQuery(reason) => write!(f, "invalid DNS query: {reason:?}"),
            Self::AuthorityUnavailable => f.write_str("private DNS authority unavailable"),
            Self::AuthorityNotFresh => f.write_str("private DNS authority is not fresh"),
            Self::AuthorityResponse(reason) => write!(f, "private DNS response failed: {reason:?}"),
            Self::PublicForwardingDisabled => f.write_str("public DNS forwarding is disabled"),
            Self::PublicEdnsOptionsUnsupported => {
                f.write_str("public EDNS options are unsupported")
            }
            Self::Upstream(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Upstream(error) => Some(error),
            _ => None,
        }
    }
}

/// One dispatcher for one trusted network policy. Share one instance across
/// the network's ingress callers so they share the same non-queueing budgets.
pub struct QueryDispatcher<A> {
    private_suffix: String,
    authority: Option<AuthoritySnapshot>,
    upstream: Option<TcpUpstream>,
    authorizer: A,
    budget: Mutex<Budget>,
    #[cfg(feature = "secure-upstream")]
    forwarder: Option<crate::forward::Forwarder>,
}

impl<A: ClientAuthorizer> QueryDispatcher<A> {
    /// Configure the complete private namespace for this single-zone service.
    /// The suffix and upstream must come from trusted configuration, not a DNS
    /// request or an unverified advertisement. If the private namespace is not
    /// known, do not construct a forwarding dispatcher. A root, invalid suffix,
    /// or authority for a different origin is rejected. Constructing a dispatcher
    /// opens no sockets. `None` for upstream disables forwarding, and `None` for
    /// authority does not unprotect names.
    pub fn new(
        private_suffix: &str,
        authority: Option<AuthoritySnapshot>,
        upstream: Option<TcpUpstream>,
        authorizer: A,
    ) -> Result<Self, DnsError> {
        let private_suffix = normalize_name(private_suffix)
            .filter(|name| !name.is_empty())
            .ok_or(DnsError::InvalidConfiguration)?;
        if authority
            .as_ref()
            .is_some_and(|snapshot| snapshot.resolver.zone.origin() != private_suffix.as_str())
        {
            return Err(DnsError::InvalidConfiguration);
        }
        Ok(Self {
            private_suffix,
            authority,
            upstream,
            authorizer,
            budget: Mutex::new(Budget::new(Instant::now())),
            #[cfg(feature = "secure-upstream")]
            forwarder: None,
        })
    }

    /// Dispatch one complete message using stream DNS response sizing. The caller
    /// owns framing, transport, and safe scheduling of the blocking public path;
    /// do not call it from an event loop or put an unbounded queue in front of it.
    /// `peer` is the binding for THIS query, obtained from authenticated ingress,
    /// never from a DNS field or an unverified packet address. `deadline` must be
    /// a monotonic request deadline; the configured TCP timeout may shorten it.
    pub fn dispatch(
        &self,
        peer: AuthenticatedPeerSource,
        query: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, DispatchError> {
        self.dispatch_inner(peer, query, deadline, None, true)
    }

    /// Nonblocking packet path: the private branch only, even if the instance
    /// has an upstream. `udp_ceiling` is the IP MTU less IP/UDP headers, or
    /// `None` for a complete TCP message. Both transports share one budget.
    pub(crate) fn dispatch_private_packet(
        &self,
        peer: AuthenticatedPeerSource,
        query: &[u8],
        udp_ceiling: Option<usize>,
    ) -> Result<Vec<u8>, DispatchError> {
        self.dispatch_inner(peer, query, Instant::now() + WINDOW, udp_ceiling, false)
    }

    /// The authenticated owner must verify its live signed `PublicForward`
    /// grant and supply an owned status/circuit gate before enabling this.
    /// This does not enable the unrelated plaintext library upstream.
    #[cfg(feature = "secure-upstream")]
    pub fn enable_packet_forwarding(
        &mut self,
        upstream: std::sync::Arc<crate::secure_upstream::SecureUpstream>,
        excluded: Vec<String>,
        lease_deadline: Instant,
        current: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<(), DnsError> {
        if self.authority.is_none() || self.forwarder.is_some() || excluded.len() > 32
            || excluded.iter().any(|suffix| {
                suffix.is_empty() || normalize_name(suffix).as_ref() != Some(suffix)
            })
        {
            return Err(DnsError::InvalidConfiguration);
        }
        self.forwarder = Some(crate::forward::Forwarder::new(upstream, excluded, lease_deadline, current)
            .map_err(|_| DnsError::InvalidConfiguration)?);
        Ok(())
    }

    pub(crate) fn dispatch_packet(
        &self,
        peer: AuthenticatedPeerSource,
        query: &[u8],
        udp: Option<usize>,
        _allow_pending: bool,
    ) -> Result<crate::forward_reply::Reply, DispatchError> {
        use crate::forward_reply::Reply;
        #[cfg(feature = "secure-upstream")]
        if let Some(forwarder) = &self.forwarder {
            let question = parse_query(query).map_err(DispatchError::InvalidQuery)?;
            if !is_in_zone(&question.name, &self.private_suffix) {
                if !self.permits_private_packet_peer(peer) {
                    return Err(DispatchError::Unauthorized);
                }
                let node = self.authorizer.authorized_node(peer).ok_or(DispatchError::Unauthorized)?;
                let _permit = self.admit(node, query.len() + MAX_RESPONSE_BYTES + 4)?;
                return Ok(if _allow_pending { forwarder.submit(query, question, udp) } else { Reply::Drop });
            }
        }
        self.dispatch_private_packet(peer, query, udp).map(Reply::Ready)
    }

    fn dispatch_inner(
        &self,
        peer: AuthenticatedPeerSource,
        query: &[u8],
        deadline: Instant,
        udp_ceiling: Option<usize>,
        allow_public: bool,
    ) -> Result<Vec<u8>, DispatchError> {
        use DispatchError::*;

        let node = self.authorizer.authorized_node(peer).ok_or(Unauthorized)?;
        check_deadline(deadline)?;
        if query.len() > MAX_QUERY_BYTES {
            return Err(InvalidQuery(DnsError::MessageTooLarge));
        }
        // Charge the request, a worst-case response, and both TCP prefixes.
        // Not refunded on failure, so malformed traffic also costs budget.
        let _permit = self.admit(node, query.len() + MAX_RESPONSE_BYTES + 4)?;
        let question = parse_query(query).map_err(InvalidQuery)?;
        check_deadline(deadline)?;

        let (response, selected_authority) = if is_in_zone(&question.name, &self.private_suffix) {
            let snapshot = self.authority.as_ref().ok_or(AuthorityUnavailable)?;
            if !snapshot.resolver.sources.permits(peer.address()) {
                return Err(Unauthorized);
            }
            if !snapshot.is_fresh(Instant::now()) {
                return Err(AuthorityNotFresh);
            }
            let resolver = &snapshot.resolver;
            let reply = resolver.respond_parsed(
                query,
                &question,
                udp_ceiling.is_some(),
                udp_ceiling.unwrap_or(MAX_RESPONSE_BYTES),
            );
            let reply = match (reply, udp_ceiling) {
                (Err(DnsError::TruncatedWouldExceed), Some(ceiling)) => truncate_parsed(
                    query,
                    &question,
                    resolver.udp_limit(&question, ceiling),
                    question.edns_size.is_some(),
                ),
                (reply, _) => reply,
            }
            .map_err(AuthorityResponse)?;
            (reply, Some(snapshot))
        } else {
            if !allow_public {
                return Err(PublicForwardingDisabled);
            }
            let upstream = self.upstream.as_ref().ok_or(PublicForwardingDisabled)?;
            // Uninterpreted client options are not public QNAMEs. Don't relay
            // their opaque payload (which might include private information).
            if question.edns_size.is_some() && query.len() != question.end + OPT_HEADER_BYTES {
                return Err(PublicEdnsOptionsUnsupported);
            }
            if self.authorizer.authorized_node(peer) != Some(node) {
                return Err(Unauthorized);
            }
            let reply = upstream
                .exchange_parsed_until(query, &question, deadline)
                .map_err(Upstream)?;
            (reply, None)
        };
        if self.authorizer.authorized_node(peer) != Some(node) {
            return Err(Unauthorized);
        }
        check_deadline(deadline)?;
        // In particular, the private snapshot may have expired during the
        // final client-policy check. Recheck the selected branch, never reroute.
        if selected_authority.is_some_and(|snapshot| !snapshot.is_fresh(Instant::now())) {
            return Err(AuthorityNotFresh);
        }
        Ok(response)
    }

    pub(crate) fn permits_private_packet_peer(&self, peer: AuthenticatedPeerSource) -> bool {
        self.authority.as_ref().is_some_and(|snapshot| {
            snapshot.resolver.sources.permits(peer.address())
                && self.authorizer.authorized_node(peer).is_some()
                && snapshot.is_fresh(Instant::now())
        })
    }

    fn admit(&self, node: u16, bytes: usize) -> Result<Permit<'_>, DispatchError> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| DispatchError::ResourceLimit)?;
        if !budget.admit(node, bytes, Instant::now()) {
            return Err(DispatchError::ResourceLimit);
        }
        Ok(Permit {
            node,
            budget: &self.budget,
        })
    }
}

fn check_deadline(deadline: Instant) -> Result<(), DispatchError> {
    if Instant::now() >= deadline {
        Err(DispatchError::DeadlineExceeded)
    } else {
        Ok(())
    }
}

struct Permit<'a> {
    node: u16,
    budget: &'a Mutex<Budget>,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        // Poisoned accounting already rejects all further admission.
        if let Ok(mut budget) = self.budget.lock() {
            budget.release(self.node);
        }
    }
}

struct Limits {
    in_flight: usize,
    queries: usize,
    bytes: usize,
}

#[derive(Default)]
struct Usage {
    in_flight: usize,
    queries: usize,
    bytes: usize,
}

impl Usage {
    fn allows(&self, limits: Limits, bytes: usize) -> bool {
        self.in_flight < limits.in_flight
            && self.queries < limits.queries
            && bytes <= limits.bytes - self.bytes
    }

    fn charge(&mut self, bytes: usize) {
        self.in_flight += 1;
        self.queries += 1;
        self.bytes += bytes;
    }

    fn reset_rates(&mut self) {
        self.queries = 0;
        self.bytes = 0;
    }
}

struct Budget {
    start: Instant,
    all: Usage,
    nodes: BTreeMap<u16, Usage>,
}

impl Budget {
    fn new(start: Instant) -> Self {
        Self {
            start,
            all: Usage::default(),
            nodes: BTreeMap::new(),
        }
    }

    fn admit(&mut self, node: u16, bytes: usize, now: Instant) -> bool {
        if now.duration_since(self.start) >= WINDOW {
            self.start = now;
            self.all.reset_rates();
            self.nodes.retain(|_, usage| {
                usage.reset_rates();
                usage.in_flight != 0
            });
        }
        if !self.all.allows(GLOBAL, bytes)
            || (self.nodes.len() == MAX_TRACKED_IDENTITIES && !self.nodes.contains_key(&node))
        {
            return false;
        }
        let usage = self.nodes.entry(node).or_default();
        if !usage.allows(PER_IDENTITY, bytes) {
            return false;
        }
        usage.charge(bytes);
        self.all.charge(bytes);
        true
    }

    fn release(&mut self, node: u16) {
        self.all.in_flight -= 1;
        self.nodes
            .get_mut(&node)
            .expect("an in-flight identity is retained across rate windows")
            .in_flight -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceAuthorization, Zone};

    struct TestClient(AuthenticatedPeerSource);

    impl ClientAuthorizer for TestClient {
        fn authorized_node(&self, peer: AuthenticatedPeerSource) -> Option<u16> {
            (peer == self.0).then_some(2)
        }
    }

    #[test]
    fn private_packet_transports_charge_the_same_budget() {
        let address = "10.20.1.2".parse().unwrap();
        let peer = AuthenticatedPeerSource::from_authenticated_overlay_peer(address).unwrap();
        let now = Instant::now();
        let resolver = AuthoritativeDns::new(
            Zone::new("corp.test").unwrap(),
            SourceAuthorization::new([address]),
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        let snapshot = AuthoritySnapshot::new(resolver, now, now + WINDOW).unwrap();
        let dispatcher =
            QueryDispatcher::new("corp.test", Some(snapshot), None, TestClient(peer)).unwrap();
        // Seed the window one small request below its byte ceiling. The same
        // full-response reservation applies to UDP and TCP, even on failure.
        let query = b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x04corp\x04test\0\0\x01\0\x01";
        let cost = query.len() + MAX_RESPONSE_BYTES + 4;
        {
            let mut budget = dispatcher.budget.lock().unwrap();
            // Keep this window from rolling over regardless of scheduler timing.
            budget.start = now + Duration::from_secs(60);
            let start = budget.start;
            assert!(budget.admit(2, PER_IDENTITY.bytes - cost, start));
            budget.release(2);
        }
        assert!(dispatcher.dispatch_private_packet(peer, query, Some(512)).is_ok());
        assert!(matches!(
            dispatcher.dispatch_private_packet(peer, query, None),
            Err(DispatchError::ResourceLimit)
        ));
    }

    #[test]
    fn private_udp_truncates_whole_rrset_under_client_and_link_limits() {
        let address = "10.20.1.2".parse().unwrap();
        let peer = AuthenticatedPeerSource::from_authenticated_overlay_peer(address).unwrap();
        let other = AuthenticatedPeerSource::from_authenticated_overlay_peer(
            "10.20.1.3".parse().unwrap(),
        )
        .unwrap();
        let mut zone = Zone::new("corp.test").unwrap();
        for octet in 1..=32 {
            let ip = std::net::Ipv4Addr::new(10, 20, 1, octet);
            zone.add_address("corp.test", ip.into()).unwrap();
        }
        let resolver = AuthoritativeDns::new(
            zone,
            SourceAuthorization::new([address]),
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        let now = Instant::now();
        let snapshot = AuthoritySnapshot::new(resolver, now, now + Duration::from_secs(60)).unwrap();
        let dispatcher =
            QueryDispatcher::new("corp.test", Some(snapshot), None, TestClient(peer)).unwrap();
        let query = b"\xab\xcd\x01\0\0\x01\0\0\0\0\0\0\x04corp\x04test\0\0\x01\0\x01";
        let truncated = dispatcher.dispatch_private_packet(peer, query, Some(1400)).unwrap();
        assert_eq!(&truncated[..12], b"\xab\xcd\x83\0\0\x01\0\0\0\0\0\0");
        assert_eq!(&truncated[12..], &query[12..]);

        let mut edns = query.to_vec();
        edns[11] = 1;
        edns.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]); // 1232
        let complete = dispatcher.dispatch_private_packet(peer, &edns, Some(1400)).unwrap();
        assert_eq!(&complete[2..12], b"\x85\0\0\x01\0\x20\0\0\0\x01");
        assert_eq!(complete.len(), query.len() + 32 * 16 + OPT_HEADER_BYTES);
        let link_limit = complete.len() - 1;
        let truncated = dispatcher.dispatch_private_packet(peer, &edns, Some(link_limit)).unwrap();
        assert_eq!(&truncated[..12], b"\xab\xcd\x83\0\0\x01\0\0\0\0\0\x01");
        assert_eq!(&truncated[12..query.len()], &query[12..]);
        assert_eq!(&truncated[query.len()..query.len() + 3], &[0, 0, 41]);
        assert_eq!(&truncated[query.len() + 3..query.len() + 5], &(link_limit as u16).to_be_bytes());
        assert_eq!(&truncated[query.len() + 5..], &[0; 6]);

        assert!(matches!(
            dispatcher.dispatch_private_packet(peer, &edns, Some(query.len())),
            Err(DispatchError::AuthorityResponse(DnsError::TruncatedWouldExceed))
        ));
        assert!(matches!(
            dispatcher.dispatch_private_packet(other, query, Some(1400)),
            Err(DispatchError::Unauthorized)
        ));
        let mut outside = *query;
        outside[13] = b'x';
        assert!(matches!(
            dispatcher.dispatch_private_packet(peer, &outside, Some(1400)),
            Err(DispatchError::PublicForwardingDisabled)
        ));
    }

    #[test]
    fn authority_freshness_is_half_open() {
        let from = Instant::now() + WINDOW;
        let until = from + WINDOW;
        let resolver = AuthoritativeDns::new(
            Zone::new("corp.test").unwrap(),
            SourceAuthorization::default(),
            512,
        )
        .unwrap();
        assert!(AuthoritySnapshot::new(resolver.clone(), from, from).is_err());
        let snapshot = AuthoritySnapshot::new(resolver, from, until).unwrap();
        assert!(!snapshot.is_fresh(from - Duration::from_nanos(1)));
        assert!(snapshot.is_fresh(from));
        assert!(snapshot.is_fresh(until - Duration::from_nanos(1)));
        assert!(!snapshot.is_fresh(until));
    }

    #[test]
    fn limits_hold_for_concurrent_work_even_across_rate_windows() {
        let now = Instant::now();
        let mut budget = Budget::new(now);
        for _ in 0..PER_IDENTITY.in_flight {
            assert!(budget.admit(0, 1, now));
        }
        assert!(!budget.admit(0, 1, now));
        for node in 1..=(GLOBAL.in_flight - PER_IDENTITY.in_flight) as u16 {
            assert!(budget.admit(node, 1, now));
        }
        assert!(!budget.admit(100, 1, now));
        assert!(!budget.admit(100, 1, now + WINDOW));
        budget.release(1);
        assert!(!budget.admit(0, 1, now + WINDOW));
        assert!(budget.admit(100, 1, now + WINDOW));
    }

    #[test]
    fn fixed_window_bounds_query_count_and_identity_table() {
        let now = Instant::now();
        let mut budget = Budget::new(now);
        for _ in 0..PER_IDENTITY.queries {
            assert!(budget.admit(0, 1, now));
            budget.release(0);
        }
        assert!(!budget.admit(0, 1, now));
        for node in 1..MAX_TRACKED_IDENTITIES as u16 {
            assert!(budget.admit(node, 1, now));
            budget.release(node);
        }
        assert!(!budget.admit(MAX_TRACKED_IDENTITIES as u16, 1, now));
        assert!(budget.admit(MAX_TRACKED_IDENTITIES as u16, 1, now + WINDOW));
        assert_eq!(budget.nodes.len(), 1);

        let mut global = Budget::new(now);
        for query in 0..GLOBAL.queries {
            let node = (query / PER_IDENTITY.queries) as u16;
            assert!(global.admit(node, 1, now));
            global.release(node);
        }
        assert!(!global.admit(100, 1, now));
        assert!(global.admit(100, 1, now + WINDOW));
    }

    #[test]
    fn byte_budgets_are_reserved_and_not_refunded_on_release() {
        let now = Instant::now();
        let mut budget = Budget::new(now);
        let request_cost = MAX_QUERY_BYTES + MAX_RESPONSE_BYTES + 4;
        for node in 0..(GLOBAL.bytes / PER_IDENTITY.bytes) as u16 {
            for _ in 0..PER_IDENTITY.bytes / request_cost {
                assert!(budget.admit(node, request_cost, now));
                budget.release(node);
            }
            assert!(!budget.admit(node, request_cost, now));
            let remaining = PER_IDENTITY.bytes % request_cost;
            assert!(budget.admit(node, remaining, now));
            budget.release(node);
        }
        assert!(!budget.admit(100, request_cost, now));
        assert!(budget.admit(100, request_cost, now + WINDOW));
    }
}
