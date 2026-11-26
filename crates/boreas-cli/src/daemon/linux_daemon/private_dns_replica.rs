//! One dedicated private DNS circuit at a time; at most two explicit Core
//! identities, one attempt each. No resolver, discovery, warm standby or replay.

use std::{net::SocketAddr, os::fd::AsRawFd, path::Path, sync::{Arc, Mutex}, time::{Duration, Instant}};

use boreas_pki::{VerifiedNetworkContext, management::ManagementTrust};
use boreas_tunnel::{dns_replica::{self, Side}, e2e::open_e2e_until};

use super::{
    AuthenticatedPeer, ClientTarget, HANDSHAKE_TIMEOUT, LinkClient, LiveCounters,
    OpenSslConnector, OpenSslE2eBackend, OpenSslInnerConnector, PATH_BACKUP, PATH_PRIMARY,
    PathStop, PeerIdentity, PinnedDns, PkiIdentityExtractor, PolicyWindow, SessionPolicy,
    StatusStore, TunEndpoint, VerifiedNodeIdentity, bound_path_io, direct_outer_connector,
    drive_business_path, duplicate_e2e_socket, lock_mutex, may_try_backup, now_utc_us,
    print_path_summary, revocation_slots, status_gate,
    check_identity_revocations,
};

const MAX_IDENTITY_BYTES: usize = 64 * 1024;

pub(super) struct Source {
    target: ClientTarget,
    pub(super) identity: VerifiedNodeIdentity,
    pub(super) valid_until: u64,
}

pub(super) struct Sources {
    primary: ClientTarget,
    pub(super) backup: Source,
}

impl Sources {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn load(
        primary: &str,
        backup: &str,
        identity: &Path,
        tls_name: &str,
        ws_host: Option<&str>,
        ws_path: &str,
        trust: &mut ManagementTrust,
        context: &VerifiedNetworkContext,
        primary_peer: PeerIdentity,
    ) -> Result<Self, String> {
        if !identity.is_absolute() {
            return Err("daemon: DNS backup identity requires an absolute file path".into());
        }
        let primary = target(primary, tls_name, ws_host, ws_path)?;
        let backup = target(backup, tls_name, ws_host, ws_path)?;
        if primary.address == backup.address {
            return Err("daemon: private DNS replicas require distinct endpoints".into());
        }
        let raw = crate::network_policy_runtime::read_bounded_regular(
            identity, MAX_IDENTITY_BYTES, "private DNS backup identity",
        ).map_err(|e| format!("daemon: {e}"))?;
        let signed = trust.verify_and_authorize(&raw, now_utc_us()?)
            .map_err(|e| format!("daemon: DNS backup signed identity rejected: {e}"))?;
        let identity = VerifiedNodeIdentity::from_verified_object(&signed, context)
            .map_err(|e| format!("daemon: DNS backup node identity rejected: {e}"))?;
        if identity.role() != boreas_crypto::NodeRole::Core
            || identity.node_id() == primary_peer.node_id
        {
            return Err("daemon: private DNS backup must be a distinct Core node".into());
        }
        let valid_until = signed.valid_until().min(identity.expires());
        Ok(Self { primary, backup: Source { target: backup, identity, valid_until } })
    }
}

fn target(
    spec: &str, tls_name: &str, ws_host: Option<&str>, path: &str,
) -> Result<ClientTarget, String> {
    let address = numeric_endpoint(spec)?;
    if tls_name.is_empty() {
        return Err("daemon: private DNS replica TLS name must not be empty".into());
    }
    Ok(ClientTarget {
        address,
        ws_host: ws_host.unwrap_or(spec).to_string(),
        tls_server_name: tls_name.to_string(),
        path: path.to_string(),
    })
}

pub(super) fn numeric_endpoint(spec: &str) -> Result<SocketAddr, String> {
    let address = spec.parse::<SocketAddr>()
        .map_err(|_| "daemon: private DNS replica endpoints require literal IPv4:port")?;
    if !matches!(address, SocketAddr::V4(v4) if !v4.ip().is_unspecified()
        && !v4.ip().is_multicast() && !v4.ip().is_broadcast() && v4.port() != 0)
    {
        return Err("daemon: private DNS replica endpoints require unicast IPv4 and nonzero port".into());
    }
    Ok(address)
}

#[derive(Clone, Copy)]
pub(super) struct Epoch {
    pub(super) ordinal: u64,
    pub(super) active_path: u8,
    pub(super) sequence: u64,
    pub(super) promotions: u64,
}

pub(super) struct Run<'a> {
    pub(super) sources: &'a Sources,
    pub(super) mat_dir: &'a Path,
    pub(super) status_path: &'a Path,
    pub(super) policy_window: PolicyWindow,
    pub(super) store: Arc<Mutex<StatusStore>>,
    pub(super) extractor: Arc<PkiIdentityExtractor>,
    pub(super) connector: OpenSslConnector,
    pub(super) backend: OpenSslE2eBackend,
    pub(super) policy: SessionPolicy,
    pub(super) tun: &'a TunEndpoint,
    pub(super) mtu: usize,
    pub(super) max_packets: Option<u64>,
    pub(super) max_seconds: Option<u64>,
    pub(super) counters: &'a Arc<LiveCounters>,
    pub(super) dns: &'a PinnedDns,
}

struct Gate<'a> {
    policy_window: PolicyWindow,
    store: &'a Mutex<StatusStore>,
    status_path: &'a Path,
    dns: &'a PinnedDns,
    peers: [PeerIdentity; 2],
    slots: [[AuthenticatedPeer; 2]; 2],
    sequence: u64,
}

impl Gate<'_> {
    // Check both provisioned generations: an authorization failure of the old
    // source must not be mistaken for permission to select another source.
    fn check(&self) -> Result<Instant, String> {
        self.policy_window.check()?;
        let mut store = lock_mutex(self.store);
        let (sequence, deadline, _) = status_gate(
            &mut store, self.status_path, now_utc_us()?, Instant::now(),
        )?;
        if sequence != self.sequence {
            return Err("daemon: private DNS replica selection status sequence changed".into());
        }
        check_identity_revocations(&mut store, self.status_path, self.slots[0])?;
        super::check_committed_identity_revocations(&store, self.slots[1])?;
        for peer in self.peers {
            self.dns.check_source(peer)?;
        }
        Ok(deadline.min(self.policy_window.deadline()).min(self.dns.deadline()))
    }
}

pub(super) fn run(run: Run<'_>) -> Result<(), String> {
    let primary = run.policy.expected_peer;
    let backup = run.sources.backup.identity.peer_identity();
    let gate = Gate {
        policy_window: run.policy_window,
        store: &run.store,
        status_path: run.status_path,
        dns: run.dns,
        peers: [primary, backup],
        slots: [revocation_slots(run.policy.local, primary)?, revocation_slots(run.policy.local, backup)?],
        sequence: run.counters.status_sequence.load(super::Ordering::Acquire),
    };
    let client = LinkClient::new(
        Box::new(direct_outer_connector(run.mat_dir)?),
        Box::new(OpenSslInnerConnector::new(run.connector, run.extractor.clone())),
    );
    let mut ordinal = 0;
    let mut packets_before = 0u64;
    let deadline = run.max_seconds.map(|seconds| {
        Instant::now().checked_add(Duration::from_secs(seconds))
            .ok_or("daemon: private DNS selection deadline overflow")
    }).transpose()?;
    for (index, (target, peer)) in [
        (&run.sources.primary, primary), (&run.sources.backup.target, backup),
    ].into_iter().enumerate() {
        let valid_until = gate.check()?;
        let connect_until = (Instant::now() + HANDSHAKE_TIMEOUT)
            .min(deadline.unwrap_or(valid_until))
            .min(valid_until);
        let remaining = connect_until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("daemon: private DNS replica selection deadline exhausted".into());
        }
        // This classifier sees only the raw TCP dial's result. In particular,
        // no TLS/WSS/E2E error (including a handshake timeout) can reach it.
        let tcp = match std::net::TcpStream::connect_timeout(&target.address, remaining) {
            Ok(tcp) => tcp,
            Err(error) if index == 0 && may_try_backup(&error) => {
                eprintln!("daemon: private DNS primary TCP unavailable before authentication; selecting configured backup");
                continue;
            }
            Err(error) => return Err(format!("daemon: private DNS replica TCP connect failed: {error}")),
        };
        let socket = tcp.try_clone().map_err(|e| format!("daemon: DNS replica socket clone failed: {e}"))?;
        let fd = socket.as_raw_fd();
        gate.check()?;
        let mut policy = run.policy.clone();
        policy.expected_peer = peer;
        let mut hop = client.connect_preconnected_until(tcp, target, policy, connect_until)
            .map_err(|e| format!("daemon: private DNS replica WSS/hop rejected: {e}"))?;
        let valid_until = gate.check()?;
        let handshake_until = (Instant::now() + HANDSHAKE_TIMEOUT)
            .min(deadline.unwrap_or(valid_until))
            .min(valid_until);
        let mut e2e = open_e2e_until(&mut hop, &run.backend, peer, 1, &socket, handshake_until)
            .map_err(|e| format!("daemon: private DNS replica E2E rejected: {e}"))?;
        gate.check()?;
        dns_replica::confirm(&mut e2e, &socket, handshake_until, Side::Edge, run.dns.pin(), run.dns.tcp)
            .map_err(|e| format!("daemon: private DNS replica confirmation rejected: {e}"))?;
        gate.check()?;
        bound_path_io(fd)?;
        ordinal += 1;
        let epoch = Epoch {
            ordinal,
            active_path: if index == 0 { PATH_PRIMARY } else { PATH_BACKUP },
            sequence: gate.sequence,
            promotions: ordinal - 1,
        };
        let report = drive_business_path(
            "connect", fd, run.tun, e2e, run.mtu, run.status_path, run.policy_window,
            Arc::clone(&run.store), run.max_packets, packets_before, deadline, None,
            None, run.counters, Some(run.dns), Some(epoch),
        );
        run.counters.connected.store(false, super::Ordering::SeqCst);
        run.counters.outbound_upstreams.store(0, super::Ordering::SeqCst);
        drop(hop);
        drop(socket);
        let report = report?;
        match &report.stop {
            PathStop::Budget(reason) => {
                print_path_summary("connect", run.tun, &report, reason, epoch.promotions, ordinal);
                return Ok(());
            }
            // The dedicated profile requires E2E TLS close_notify. A bare or
            // reset socket could mean remote pin withdrawal or revocation, so
            // never promote an ambiguous post-authentication failure.
            PathStop::PeerClosed if index == 0 => {
                packets_before = packets_before
                    .saturating_add(report.stats.outbound_packets)
                    .saturating_add(report.stats.inbound_packets);
                eprintln!("daemon: private DNS primary closed authenticated circuit; selecting configured backup");
            }
            PathStop::PeerClosed => {
                print_path_summary("connect", run.tun, &report, "peer_closed_cleanly", epoch.promotions, ordinal);
                return Ok(());
            }
            PathStop::Failed { reason, .. } => {
                return Err(format!("daemon: private DNS selected circuit failed (no failover): {reason}"));
            }
        }
    }
    Err("daemon: private DNS replica selection exhausted".into())
}

pub(super) fn accept_confirmation(
    e2e: &mut boreas_tunnel::e2e::E2eCircuit<'_>, fd: i32, dns: &PinnedDns, deadline: Instant,
) -> Result<(), String> {
    dns.check_source(e2e.local())?;
    let socket = duplicate_e2e_socket(fd)
        .map_err(|e| format!("daemon: private DNS replica confirmation socket: {e}"))?;
    dns_replica::confirm(e2e, &socket, deadline.min(dns.deadline()), Side::Core, dns.pin(), dns.tcp)
        .map_err(|e| format!("daemon: private DNS replica confirmation rejected: {e}"))?;
    dns.check_source(e2e.local())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_targets_are_numeric_unicast_and_keep_explicit_tls_name() {
        for invalid in ["dns.example:443", "0.0.0.0:443", "224.0.0.1:443", "192.0.2.1:0", "[::1]:443"] {
            assert!(target(invalid, "tls.example", None, "/tunnel").is_err());
        }
        let target = target("192.0.2.1:443", "tls.example", None, "/tunnel").unwrap();
        assert_eq!(target.ws_host, "192.0.2.1:443");
        assert_eq!(target.tls_server_name, "tls.example");
    }
}
