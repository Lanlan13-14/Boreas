//! Direct Edge/Core cohort with fixed ordinal and resource limits. Only the coordinator owns the TUN.

use super::*;
use boreas_tunnel::{
    circuit::{CircuitId, HARD_PAIR_CAP},
    circuit_pool::{CircuitPool, MAX_TRACKED_FLOWS, PoolError},
    csprng::random_array,
    e2e::{E2eL3Profile, accept_e2e_with_l3_profile_until, open_e2e_with_l3_profile_until},
};
use std::{
    io::ErrorKind,
    net::Shutdown,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};

const QUEUE_PACKETS: usize = 64;
const TICK: Duration = Duration::from_millis(1);
const STARTUP_LIMIT: Duration = Duration::from_secs(45);
const COHORT_MAGIC: &[u8; 5] = b"BCOH\x01";
const COHORT_LEN: usize = 26;
const REPLACEMENT_RETRY: Duration = Duration::from_secs(1);
const REPLACEMENT_MAGIC: &[u8; 5] = b"BREP\x01";
const REPLACEMENT_LEN: usize = COHORT_LEN + 8 + 16;

#[derive(Debug)]
enum Failure {
    Transport(String),
    Terminal(String),
}

impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self::Terminal(reason)
    }
}

fn transport_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    )
}

fn tunnel_failure(phase: &str, error: TunnelError) -> Failure {
    use boreas_tunnel::ws::WsError;
    let reason = format!("{phase}: {error}");
    match error {
        TunnelError::Timeout
        | TunnelError::Closed
        | TunnelError::Ws(WsError::Timeout | WsError::Closed) => Failure::Transport(reason),
        TunnelError::Io(kind) | TunnelError::Ws(WsError::Io(kind)) if transport_kind(kind) => {
            Failure::Transport(reason)
        }
        // Opaque TLS handshake errors might be authorization failures. Never retry
        // a rejection for which the backend cannot prove transport provenance.
        _ => Failure::Terminal(reason),
    }
}

fn business_failure(phase: &str, error: PacketPathError) -> Failure {
    let reason = format!("{phase} circuit failed: {error:?}");
    if matches!(error, PacketPathError::CircuitIo(kind) if transport_kind(kind)) {
        Failure::Transport(reason)
    } else {
        Failure::Terminal(reason)
    }
}

#[derive(Default)]
pub(super) struct LaneCounters {
    tx: AtomicU64,
    rx: AtomicU64,
    state: AtomicU64, // high bits: generation; low bit: ready
}

pub(super) fn status_lanes(counters: &LiveCounters) -> String {
    use std::fmt::Write as _;
    let mut json = String::from("[");
    let count = counters.multi_active_count.load(Ordering::Acquire);
    for (index, lane) in counters
        .multi_active_lanes
        .iter()
        .take(usize::from(count))
        .enumerate()
    {
        if index != 0 {
            json.push(',');
        }
        let state = lane.state.load(Ordering::Acquire);
        let _ = write!(
            json,
            "{{\"lane\":{},\"generation\":{},\"ready\":{},\"tx_packets\":{},\"rx_packets\":{}}}",
            index + 1,
            state >> 1,
            state & 1 != 0,
            lane.tx.load(Ordering::Relaxed),
            lane.rx.load(Ordering::Relaxed),
        );
    }
    json.push(']');
    json
}

pub(super) enum Endpoint {
    Edge(LinkClient, ClientTarget),
    Core(TcpListener, LinkServer, OpenSslOuterTlsAcceptor),
}

pub(super) struct Run<'a> {
    pub(super) profile: E2eL3Profile,
    pub(super) policy: SessionPolicy,
    pub(super) backend: OpenSslE2eBackend,
    pub(super) tun: &'a TunEndpoint,
    pub(super) mtu: usize,
    pub(super) status_path: &'a Path,
    pub(super) policy_window: PolicyWindow,
    pub(super) store: Arc<Mutex<StatusStore>>,
    pub(super) max_seconds: Option<u64>,
    pub(super) counters: &'a Arc<LiveCounters>,
}

#[derive(Default)]
struct Cohort {
    stopped: AtomicBool,
    running: AtomicBool,
    draining: AtomicBool,
    peer_closed: AtomicU8,
    reason: OnceLock<String>,
    freshness: Mutex<Option<(Instant, u64)>>,
    attempts: Mutex<Vec<Arc<Attempt>>>,
    versions: Mutex<[Option<Version>; HARD_PAIR_CAP]>,
}

#[derive(Default)]
struct Attempt {
    socket: Mutex<Option<TcpStream>>,
    ready: AtomicBool,
    lost: AtomicBool,
    progress: Mutex<Option<Instant>>,
}

impl Attempt {
    fn interrupt(&self) {
        if let Some(tcp) = lock_mutex(&self.socket).as_ref() {
            let _ = tcp.shutdown(Shutdown::Both);
        }
    }

    fn lose(&self) {
        self.lost.store(true, Ordering::Release);
        self.interrupt();
    }

    fn expire_if_stalled(&self) {
        // Serialize expiry with start/end of an operation: an observed stale
        // deadline cannot accidentally cancel a later healthy operation.
        let mut progress = lock_mutex(&self.progress);
        if progress.is_some_and(|expires| Instant::now() >= expires) {
            self.lose();
            *progress = None;
        }
    }

    fn step<T>(&self, action: impl FnOnce() -> T) -> T {
        *lock_mutex(&self.progress) = Some(Instant::now() + PATH_IO_TIMEOUT);
        let result = action();
        *lock_mutex(&self.progress) = None;
        result
    }
}

impl Cohort {
    fn register(&self, attempt: &Attempt, tcp: &TcpStream) -> Result<TcpStream, Failure> {
        let shutdown = tcp
            .try_clone()
            .map_err(|e| format!("duplicate lane socket: {e}"))?;
        let operation = tcp
            .try_clone()
            .map_err(|e| format!("duplicate lane socket: {e}"))?;
        let mut socket = lock_mutex(&attempt.socket);
        self.check()?;
        if attempt.lost.load(Ordering::Acquire) {
            return Err(Failure::Transport("lane attempt was interrupted".into()));
        }
        *socket = Some(shutdown);
        Ok(operation)
    }

    fn forget(&self, attempt: &Arc<Attempt>) {
        lock_mutex(&self.attempts).retain(|other| !Arc::ptr_eq(other, attempt));
    }

    fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
        for attempt in lock_mutex(&self.attempts).iter() {
            attempt.interrupt();
        }
    }

    fn fail(&self, reason: String) {
        let _ = self.reason.set(reason);
        self.cancel();
    }

    fn forward(&self, policy: PolicyWindow) -> Result<(), String> {
        self.check()?;
        policy.check()?;
        let lease = *lock_mutex(&self.freshness);
        if lease.is_some_and(|(mono, utc)| {
            Instant::now() < mono && now_utc_us().is_ok_and(|now| now < utc)
        }) {
            Ok(())
        } else {
            Err(
                "daemon multi-active: StatusSnapshot cutoff reached before a verified refresh"
                    .into(),
            )
        }
    }

    fn check(&self) -> Result<(), String> {
        match self.reason.get() {
            Some(reason) => Err(reason.clone()),
            None if self.stopped.load(Ordering::Acquire) => Err("cohort cancelled".into()),
            None => Ok(()),
        }
    }
}

struct CancelOnDrop<'a>(&'a Cohort);

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct WorkerGuard<'a>(&'a Cohort);

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0
                .fail("daemon multi-active: lane worker panicked".into());
        }
    }
}

#[derive(Clone, Copy)]
struct Membership {
    nonce: Option<[u8; 16]>,
    ordinal: u8,
    count: u8,
    mtu: u16,
}

impl Membership {
    fn record(self, kind: u8, nonce: [u8; 16]) -> [u8; COHORT_LEN] {
        let mut wire = [0; COHORT_LEN];
        wire[..5].copy_from_slice(COHORT_MAGIC);
        wire[5] = kind;
        wire[6] = self.ordinal;
        wire[7] = self.count;
        wire[8..10].copy_from_slice(&self.mtu.to_be_bytes());
        wire[10..].copy_from_slice(&nonce);
        wire
    }

    fn validate(self, kind: u8, received: [u8; COHORT_LEN]) -> Result<[u8; 16], String> {
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&received[10..]);
        if nonce == [0; 16]
            || self.nonce.is_some_and(|expected| expected != nonce)
            || received != self.record(kind, nonce)
        {
            return Err("encrypted cohort nonce, lane ordinal, count or MTU mismatch".into());
        }
        Ok(nonce)
    }

    // A post-BE2E exchange *inside* each confirmed pq768 TLS circuit. It binds
    // the exact runtime MTU and ordinal to one fresh cohort, not merely to the
    // expected identity/count; no unauthenticated socket arrival assigns a lane.
    fn confirm(self, circuit: &mut E2eCircuit<'_>, edge: bool) -> Result<[u8; 16], String> {
        if edge {
            let nonce = self.nonce.ok_or("missing Edge cohort nonce")?;
            circuit
                .write_all(&self.record(0, nonce))
                .map_err(|e| e.to_string())?;
            circuit.flush().map_err(|e| e.to_string())?;
        }
        let mut received = [0; COHORT_LEN];
        circuit
            .read_exact(&mut received)
            .map_err(|e| e.to_string())?;
        let nonce = self.validate(u8::from(edge), received)?;
        if !edge {
            circuit
                .write_all(&self.record(1, nonce))
                .map_err(|e| e.to_string())?;
            circuit.flush().map_err(|e| e.to_string())?;
        }
        Ok(nonce)
    }

    fn confirm_full_cohort(
        self,
        circuit: &mut E2eCircuit<'_>,
        edge: bool,
        nonce: [u8; 16],
    ) -> Result<(), String> {
        let write = |circuit: &mut E2eCircuit<'_>, kind| -> Result<(), String> {
            circuit
                .write_all(&self.record(kind, nonce))
                .map_err(|e| e.to_string())?;
            circuit.flush().map_err(|e| e.to_string())
        };
        let read = |circuit: &mut E2eCircuit<'_>, kind| -> Result<(), String> {
            let mut wire = [0; COHORT_LEN];
            circuit.read_exact(&mut wire).map_err(|e| e.to_string())?;
            if wire != self.record(kind, nonce) {
                return Err("encrypted full-cohort confirmation mismatch".into());
            }
            Ok(())
        };
        if edge {
            write(circuit, 2)?;
            read(circuit, 3)
        } else {
            read(circuit, 2)?;
            write(circuit, 3)
        }
    }
}

#[derive(Clone, Copy)]
struct Version {
    // The authenticated initial circuit identifies this slot for the entire
    // cohort, including across unsuccessful/partially observed replacements.
    anchor: CircuitId,
    last_id: CircuitId,
    generation: u64,
    vacant: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Replacement {
    ordinal: u8,
    generation: u64,
    anchor: CircuitId,
}

impl Replacement {
    fn record(self, nonce: [u8; 16], count: u8, mtu: u16, kind: u8) -> [u8; REPLACEMENT_LEN] {
        let mut wire = [0; REPLACEMENT_LEN];
        wire[..COHORT_LEN].copy_from_slice(
            &Membership {
                nonce: Some(nonce),
                ordinal: self.ordinal,
                count,
                mtu,
            }
            .record(kind, nonce),
        );
        wire[..5].copy_from_slice(REPLACEMENT_MAGIC);
        wire[COHORT_LEN..COHORT_LEN + 8].copy_from_slice(&self.generation.to_be_bytes());
        wire[COHORT_LEN + 8..].copy_from_slice(&self.anchor.0);
        wire
    }

    fn parse(
        wire: [u8; REPLACEMENT_LEN],
        nonce: [u8; 16],
        count: u8,
        mtu: u16,
    ) -> Result<Self, Failure> {
        let offer = Self {
            ordinal: wire[6],
            generation: u64::from_be_bytes(
                wire[COHORT_LEN..COHORT_LEN + 8]
                    .try_into()
                    .expect("fixed generation"),
            ),
            anchor: CircuitId(wire[COHORT_LEN + 8..].try_into().expect("fixed circuit ID")),
        };
        if offer.ordinal >= count
            || !(2..=u64::MAX >> 1).contains(&offer.generation)
            || wire != offer.record(nonce, count, mtu, 0)
        {
            return Err(Failure::Terminal(
                "encrypted replacement membership mismatch".into(),
            ));
        }
        Ok(offer)
    }
}

#[derive(Clone, Copy)]
enum Opening {
    Initial(Membership),
    Replace {
        nonce: [u8; 16],
        count: u8,
        mtu: u16,
        offer: Option<Replacement>,
    },
}

impl Opening {
    fn confirm(
        self,
        circuit: &mut E2eCircuit<'_>,
        ctx: &WorkerContext<'_>,
        until: Instant,
    ) -> Result<([u8; 16], u8, u64), Failure> {
        let edge = ctx.endpoint.is_edge();
        match self {
            Self::Initial(membership) => {
                let nonce = membership.confirm(circuit, edge)?;
                ctx.gate(until)?;
                if membership.ordinal + 1 == membership.count {
                    membership.confirm_full_cohort(circuit, edge, nonce)?;
                }
                Ok((nonce, membership.ordinal, 1))
            }
            Self::Replace {
                nonce,
                count,
                mtu,
                offer,
            } => {
                let read =
                    |circuit: &mut E2eCircuit<'_>| -> Result<[u8; REPLACEMENT_LEN], Failure> {
                        let mut received = [0; REPLACEMENT_LEN];
                        let mut filled = 0;
                        while filled < received.len() {
                            match circuit.read(&mut received[filled..]) {
                                Ok(0) => return Err(Failure::Terminal(
                                    "authenticated close before complete replacement membership"
                                        .into(),
                                )),
                                Ok(read) => filled += read,
                                Err(e) if e.kind() == ErrorKind::Interrupted => {
                                    remaining(ctx.cohort, until)?;
                                }
                                Err(e) => {
                                    return Err(tunnel_failure(
                                        "read replacement membership",
                                        e.into(),
                                    ));
                                }
                            }
                        }
                        Ok(received)
                    };
                let write = |circuit: &mut E2eCircuit<'_>, offer: Replacement, kind| {
                    circuit
                        .write_all(&offer.record(nonce, count, mtu, kind))
                        .and_then(|()| circuit.flush())
                        .map_err(|e| tunnel_failure("write replacement membership", e.into()))
                };
                let offer = if let Some(offer) = offer {
                    write(circuit, offer, 0)?;
                    if read(circuit)? != offer.record(nonce, count, mtu, 1) {
                        return Err(Failure::Terminal(
                            "encrypted replacement acknowledgement mismatch".into(),
                        ));
                    }
                    offer
                } else {
                    let offer = Replacement::parse(read(circuit)?, nonce, count, mtu)?;
                    loop {
                        remaining(ctx.cohort, until)?;
                        let version = lock_mutex(&ctx.cohort.versions)[usize::from(offer.ordinal)]
                            .ok_or_else(|| {
                                Failure::Terminal("replacement has no initial cohort slot".into())
                            })?;
                        if offer.anchor != version.anchor || offer.generation <= version.generation
                        {
                            return Err(Failure::Terminal(
                                "replacement does not name a fresh generation of this slot".into(),
                            ));
                        }
                        if version.vacant {
                            break;
                        }
                        // A correctly authenticated request may beat our loss detection.
                        // It cannot itself invalidate a healthy lane or use its credit.
                        thread::sleep(TICK);
                    }
                    ctx.gate(until)?;
                    write(circuit, offer, 1)?;
                    offer
                };
                Ok((nonce, offer.ordinal, offer.generation))
            }
        }
    }
}

struct Ready {
    id: CircuitId,
    identity: BusinessIdentity,
    nonce: [u8; 16],
    ordinal: u8,
    generation: u64,
}

/// PacketPath still owns framing, E2E I/O and authenticated L3 authorization.
/// These are channels, not TUN handles. The coordinator performs the additional
/// TCP flow/affinity decision and is the only consumer/producer of host packets.
struct LaneIo {
    to_wire: Receiver<Vec<u8>>,
    from_wire: SyncSender<Vec<u8>>,
    cohort: Arc<Cohort>,
    attempt: Arc<Attempt>,
}

impl PacketIo for LaneIo {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
        if self.cohort.stopped.load(Ordering::Acquire) {
            return Err(TunError::QueueClosed);
        }
        if self.attempt.lost.load(Ordering::Acquire)
            || self.cohort.draining.load(Ordering::Acquire)
            || self.cohort.peer_closed.load(Ordering::Acquire) != 0
        {
            return Ok(None);
        }
        match self.to_wire.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(TunError::QueueClosed),
        }
    }

    fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        if self.cohort.stopped.load(Ordering::Acquire) {
            return Err(TunError::QueueClosed);
        }
        if self.attempt.lost.load(Ordering::Acquire)
            || self.cohort.draining.load(Ordering::Acquire)
            || self.cohort.peer_closed.load(Ordering::Acquire) != 0
        {
            return Ok(());
        }
        match self.from_wire.try_send(packet.to_vec()) {
            // Drop on saturation, without sending on a different lane. TCP
            // retransmits on the original lane, even if the lost packet was SYN.
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => Err(TunError::QueueClosed),
        }
    }
}

struct DispatchLane {
    to_wire: SyncSender<Vec<u8>>,
    from_wire: Receiver<Vec<u8>>,
}

fn lane_channels(cohort: &Arc<Cohort>, attempt: &Arc<Attempt>) -> (DispatchLane, LaneIo) {
    let (to_wire, lane_input) = mpsc::sync_channel(QUEUE_PACKETS);
    let (lane_output, from_wire) = mpsc::sync_channel(QUEUE_PACKETS);
    (DispatchLane { to_wire, from_wire }, LaneIo {
        to_wire: lane_input,
        from_wire: lane_output,
        cohort: Arc::clone(cohort),
        attempt: Arc::clone(attempt),
    })
}

enum Hop {
    Edge(EstablishedSession),
    Core(boreas_tunnel::runtime::AcceptedSession),
}

impl Endpoint {
    fn is_edge(&self) -> bool {
        matches!(self, Self::Edge(..))
    }

    fn connect_socket(
        &self,
        ctx: &WorkerContext<'_>,
        until: Instant,
    ) -> Result<TcpStream, Failure> {
        match self {
            Self::Edge(client, target) => {
                let remaining = remaining(ctx.cohort, until)?;
                client
                    .connect_tcp(target, remaining.min(HANDSHAKE_TIMEOUT))
                    .map_err(|e| tunnel_failure("TCP dial", e.into()))
            }
            Self::Core(listener, ..) => loop {
                let remaining = remaining(ctx.cohort, until)?;
                match listener.accept() {
                    Ok((tcp, _)) => return Ok(tcp),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        ctx.run.policy_window.check()?;
                        thread::sleep(remaining.min(IDLE_POLL_TIMEOUT));
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(tunnel_failure("TCP accept", e.into())),
                }
            },
        }
    }
}

fn remaining(cohort: &Cohort, until: Instant) -> Result<Duration, Failure> {
    cohort.check()?;
    until
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| Failure::Transport("authenticated opening deadline elapsed".into()))
}

struct WorkerContext<'a> {
    endpoint: &'a Endpoint,
    admission: &'a Admission,
    run: &'a LanePolicy<'a>,
    cohort: &'a Cohort,
    slots: [AuthenticatedPeer; 2],
}

impl WorkerContext<'_> {
    fn gate(&self, until: Instant) -> Result<(), Failure> {
        self.run.policy_window.check()?;
        lock_revocation_gate(self.run.store, self.run.status_path, self.slots)?;
        remaining(self.cohort, until)?;
        Ok(())
    }
}

fn run_lane(
    ctx: &WorkerContext<'_>,
    attempt: &Attempt,
    opening: Opening,
    until: Instant,
    io: &LaneIo,
    ready: SyncSender<Ready>,
) -> Result<(), Failure> {
    let run = ctx.run;
    let cohort = ctx.cohort;
    ctx.gate(until)?;
    let tcp = ctx.endpoint.connect_socket(ctx, until)?;
    let interrupt = cohort.register(attempt, &tcp)?;
    ctx.gate(until)?;
    let hop_until = (Instant::now() + HANDSHAKE_TIMEOUT).min(until);
    let mut hop = match ctx.endpoint {
        Endpoint::Edge(client, target) => client
            .connect_preconnected_until(tcp, target, run.policy.clone(), hop_until)
            .map(Hop::Edge),
        Endpoint::Core(_, server, outer) => server
            .accept_tls_stream_until(tcp, outer, run.policy.clone(), hop_until, ctx.admission)
            .map(Hop::Core),
    }
    .map_err(|e| tunnel_failure("WSS + pq768 hop session rejected", e))?;
    let session = match &mut hop {
        Hop::Edge(session) => session,
        Hop::Core(accepted) => &mut accepted.session,
    };
    ctx.gate(until)?;
    let e2e_until = (Instant::now() + HANDSHAKE_TIMEOUT).min(until);
    let edge = ctx.endpoint.is_edge();
    let mut circuit = if edge {
        open_e2e_with_l3_profile_until(
            session,
            run.backend,
            run.policy.expected_peer,
            1,
            run.profile,
            &interrupt,
            e2e_until,
        )
    } else {
        accept_e2e_with_l3_profile_until(
            session,
            run.backend,
            run.policy.expected_peer,
            run.profile,
            &interrupt,
            e2e_until,
        )
    }
    .map_err(|e| tunnel_failure("pq768 E2E circuit rejected", e))?;
    // Before any possibly-blocking circuit teardown on setup errors, interrupt
    // the socket. PacketPath owns the circuit after successful binding.
    let setup = (|| {
        if circuit.l3_profile() != run.profile
            || circuit.info().path_hops != 1
            || circuit.local() != run.policy.local
            || circuit.info().peer != run.policy.expected_peer
            || run.mtu > usize::from(circuit.mtu_cap())
        {
            return Err(Failure::Terminal(
                "confirmed circuit is not the exact direct policy/identity/MTU binding".into(),
            ));
        }
        bound_path_io(interrupt.as_raw_fd())?;
        let member = opening.confirm(&mut circuit, ctx, until)?;
        ctx.gate(until)?;
        Ok(member)
    })();
    let (nonce, ordinal, generation) = match setup {
        Ok(member) => member,
        Err(reason) => {
            attempt.interrupt();
            return Err(reason);
        }
    };
    let mut path = PacketPath::try_new_over_e2e(io, circuit, run.mtu)
        .map_err(|e| format!("authenticated PacketPath bind rejected: {e:?}"))?;
    let result = (|| {
        ready
            .send(Ready {
                id: CircuitId(path.circuit_id()),
                identity: business_identity(&path),
                nonce,
                ordinal,
                generation,
            })
            .map_err(|_| Failure::Terminal("cohort ended before lane admission".into()))?;
        while !attempt.ready.load(Ordering::Acquire) || !cohort.running.load(Ordering::Acquire) {
            if attempt.lost.load(Ordering::Acquire) {
                return Err(Failure::Transport("lane attempt was interrupted".into()));
            }
            remaining(cohort, until)?;
            thread::sleep(TICK);
        }
        let counters = &run.counters.multi_active_lanes[usize::from(ordinal)];
        let fd = interrupt.as_raw_fd();
        loop {
            if cohort.stopped.load(Ordering::Acquire) || attempt.lost.load(Ordering::Acquire) {
                return Ok(());
            }
            if cohort.draining.load(Ordering::Acquire) {
                path.close_gracefully();
                return Ok(());
            }
            let peer_closing = cohort.peer_closed.load(Ordering::Acquire) != 0;
            cohort.forward(run.policy_window)?;
            let outbound = if peer_closing {
                None
            } else {
                attempt
                    .step(|| path.step_outbound())
                    .map_err(|e| business_failure("outbound", e))?
            };
            if let Some(bytes) = outbound {
                counters.tx.fetch_add(1, Ordering::Relaxed);
                run.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                run.counters
                    .tx_bytes
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }
            let wait = if outbound.is_some() || path.has_buffered_input() {
                Duration::ZERO
            } else {
                TICK
            };
            if (poll_io(fd, None, PathPoll::Read, wait)?.socket_readable
                || path.has_buffered_input())
                && !cohort.stopped.load(Ordering::Acquire)
                && !cohort.draining.load(Ordering::Acquire)
            {
                cohort.forward(run.policy_window)?;
                if attempt
                    .step(|| path.step_inbound())
                    .map_err(|e| business_failure("inbound", e))?
                    .is_none()
                {
                    if !attempt.lost.load(Ordering::Acquire) {
                        cohort.peer_closed.fetch_add(1, Ordering::AcqRel);
                    }
                    return Ok(());
                }
            }
        }
    })();
    // Do not let the circuit's best-effort Drop write hold up failure publication.
    match &result {
        Err(Failure::Transport(_)) => attempt.lose(),
        Err(Failure::Terminal(reason)) if !cohort.stopped.load(Ordering::Acquire) => {
            cohort.fail(format!(
                "daemon multi-active: lane {}: {reason}",
                ordinal + 1
            ));
        }
        _ => {}
    }
    result
}

struct Task<'scope> {
    attempt: Arc<Attempt>,
    channels: DispatchLane,
    ready: Receiver<Ready>,
    worker: thread::ScopedJoinHandle<'scope, Result<(), Failure>>,
    until: Instant,
}

impl<'scope> Task<'scope> {
    fn spawn<'env>(
        scope: &'scope thread::Scope<'scope, 'env>,
        ctx: &'scope WorkerContext<'env>,
        cohort: &Arc<Cohort>,
        opening: Opening,
        until: Instant,
    ) -> Result<Self, String> {
        let attempt = Arc::new(Attempt::default());
        {
            let mut attempts = lock_mutex(&cohort.attempts);
            cohort.check()?;
            if attempts.len() >= usize::from(ctx.run.profile.active_lanes()) {
                return Err("daemon multi-active: socket quota exhausted".into());
            }
            attempts.push(Arc::clone(&attempt));
        }
        let (channels, io) = lane_channels(cohort, &attempt);
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let control = Arc::clone(&attempt);
        let worker = thread::Builder::new()
            .name("boreas-lane".into())
            .spawn_scoped(scope, move || {
                let _guard = WorkerGuard(ctx.cohort);
                let result = run_lane(ctx, &control, opening, until, &io, ready_tx);
                if let Err(Failure::Terminal(reason)) = &result
                    && !ctx.cohort.stopped.load(Ordering::Acquire)
                {
                    // Keep opaque TLS failures terminal even near a timeout.
                    // The transport's own deadline guards report typed timeouts.
                    ctx.cohort.fail(format!("daemon multi-active: {reason}"));
                }
                if result.is_err() {
                    control.interrupt();
                }
                drop(lock_mutex(&control.socket).take());
                result
            });
        match worker {
            Ok(worker) => Ok(Self {
                attempt,
                channels,
                ready,
                worker,
                until,
            }),
            Err(e) => {
                cohort.forget(&attempt);
                Err(format!("daemon multi-active: cannot spawn lane: {e}"))
            }
        }
    }

    fn join(self, cohort: &Cohort) -> Result<Result<(), Failure>, String> {
        let result = self
            .worker
            .join()
            .map_err(|_| "daemon multi-active: lane panicked".to_string());
        cohort.forget(&self.attempt);
        result
    }
}

struct Active<'scope> {
    task: Task<'scope>,
    id: CircuitId,
    retired: bool,
}

fn pool_error(error: PoolError) -> String {
    format!("daemon multi-active: pool rejected lane/flow operation: {error:?}")
}

struct Dispatch<'a, 'scope> {
    run: &'a Run<'a>,
    cohort: &'a Arc<Cohort>,
    pool: CircuitPool,
    lanes: Vec<Option<Active<'scope>>>,
    pending: Option<Task<'scope>>,
    retry_at: Instant,
    generation: u64,
    nonce: [u8; 16],
    mtu: u16,
    identity: BusinessIdentity,
    edge: bool,
}

impl<'scope> Dispatch<'_, 'scope> {
    fn publish(&self) {
        let count = self
            .lanes
            .iter()
            .flatten()
            .filter(|lane| !lane.retired)
            .count() as u64;
        Live::connections(self.run.counters, self.edge).store(count, Ordering::SeqCst);
        self.run
            .counters
            .connected
            .store(count != 0, Ordering::SeqCst);
    }

    fn maintain<'env>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        ctx: &'scope WorkerContext<'env>,
        deadline: Option<Instant>,
    ) -> Result<(), String> {
        let cohort = self.cohort;
        let mut changed = false;
        for (index, slot) in self.lanes.iter_mut().enumerate() {
            let Some(lane) = slot else {
                continue;
            };
            let attempt = &lane.task.attempt;
            if !lane.retired {
                attempt.expire_if_stalled();
            }
            // A worker can time out while racing the final admission bit.
            // It never leaves a published ready lane with no worker.
            let lost = attempt.lost.load(Ordering::Acquire);
            if !lane.retired && (lost || lane.task.worker.is_finished()) {
                if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                    continue;
                }
                cohort.check()?;
                if !lost {
                    attempt.lose();
                }
                self.pool.invalidate_lane(lane.id).map_err(pool_error)?;
                lane.retired = true;
                self.run.counters.multi_active_lanes[index]
                    .state
                    .fetch_and(!1, Ordering::Release);
                changed = true;
                self.retry_at = Instant::now() + REPLACEMENT_RETRY;
            }
            if lane.retired && lane.task.worker.is_finished() {
                let lane = slot.take().expect("retired lane still occupies slot");
                let result = lane.task.join(cohort)?;
                cohort.check()?;
                if let Err(Failure::Terminal(reason)) = result {
                    return Err(reason);
                }
                self.pool.release_lane(lane.id).map_err(pool_error)?;
                lock_mutex(&cohort.versions)[index]
                    .as_mut()
                    .expect("admitted version")
                    .vacant = true;
            }
        }
        if changed {
            self.publish();
        }
        if cohort.peer_closed.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        // The coordinator never blocks on dial, TLS, or an unfinished worker.
        if let Some(task) = &self.pending {
            if task.worker.is_finished() {
                let result = self.pending.take().expect("pending task").join(cohort)?;
                cohort.check()?;
                match result {
                    Err(Failure::Transport(reason)) => {
                        eprintln!("daemon multi-active: replacement transport: {reason}")
                    }
                    Err(Failure::Terminal(reason)) => return Err(reason),
                    Ok(()) => {
                        return Err(
                            "daemon multi-active: replacement ended before admission".into()
                        );
                    }
                }
                self.retry_at = Instant::now() + REPLACEMENT_RETRY;
            } else if Instant::now() >= task.until {
                // The worker checks the same absolute deadline even while not
                // registered (bounded connect or nonblocking listener polling).
                task.attempt.lose();
            } else if let Ok(ready) = task.ready.try_recv() {
                cohort.forward(self.run.policy_window)?;
                let index = usize::from(ready.ordinal);
                let version =
                    lock_mutex(&cohort.versions)[index].ok_or("missing admitted lane version")?;
                if ready.nonce != self.nonce
                    || ready.identity != self.identity
                    || !version.vacant
                    || ready.generation <= version.generation
                    || ready.id == version.anchor
                    || ready.id == version.last_id
                {
                    return Err(
                        "daemon multi-active: replacement is not fresh in the authenticated cohort"
                            .into(),
                    );
                }
                self.pool.reserve_lane(ready.id).map_err(pool_error)?;
                self.pool.mark_ready(ready.id).map_err(pool_error)?;
                let task = self.pending.take().expect("ready task");
                task.attempt.ready.store(true, Ordering::Release);
                self.lanes[index] = Some(Active {
                    task,
                    id: ready.id,
                    retired: false,
                });
                lock_mutex(&cohort.versions)[index] = Some(Version {
                    generation: ready.generation,
                    last_id: ready.id,
                    vacant: false,
                    ..version
                });
                self.run.counters.multi_active_lanes[index]
                    .state
                    .store(ready.generation << 1 | 1, Ordering::Release);
                self.publish();
            }
        }
        if self.pending.is_none()
            && Instant::now() >= self.retry_at
            && let Some(ordinal) = self.lanes.iter().position(Option::is_none)
        {
            let offer = if self.edge {
                self.generation = self
                    .generation
                    .checked_add(1)
                    .filter(|generation| *generation <= u64::MAX >> 1)
                    .ok_or("daemon multi-active: exhausted replacement generations")?;
                let version =
                    lock_mutex(&cohort.versions)[ordinal].ok_or("missing admitted lane version")?;
                Some(Replacement {
                    ordinal: ordinal as u8,
                    generation: self.generation,
                    anchor: version.anchor,
                })
            } else {
                None
            };
            let until = (Instant::now() + STARTUP_LIMIT).min(self.run.policy_window.deadline());
            let until = deadline.map_or(until, |stop| until.min(stop));
            let opening = Opening::Replace {
                nonce: self.nonce,
                count: self.lanes.len() as u8,
                mtu: self.mtu,
                offer,
            };
            self.pending = Some(Task::spawn(scope, ctx, cohort, opening, until)?);
        }
        Ok(())
    }

    fn forward<'env>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        ctx: &'scope WorkerContext<'env>,
        deadline: Option<Instant>,
    ) -> Result<&'static str, String> {
        let run = self.run;
        let cohort = self.cohort;
        let tun_fd = run
            .tun
            .raw_fd()
            .ok_or("multi-active requires real Linux TUN")?;
        let io = run.tun.packet_io();
        let mut scratch = vec![0; run.mtu + 1];
        let mut peer_close = None;
        loop {
            cohort.forward(run.policy_window)?;
            let closed = usize::from(cohort.peer_closed.load(Ordering::Acquire));
            if closed != 0 {
                let (expected, until) = *peer_close.get_or_insert_with(|| {
                    (
                        self.lanes
                            .iter()
                            .flatten()
                            .filter(|lane| !lane.retired)
                            .count(),
                        Instant::now() + Duration::from_secs(1),
                    )
                });
                // A clean close is a cohort shutdown, not a replacement trigger.
                // Never hide a second lane's unexpected loss behind close_notify.
                if self
                    .lanes
                    .iter()
                    .flatten()
                    .any(|lane| !lane.retired && lane.task.attempt.lost.load(Ordering::Acquire))
                {
                    return Err("daemon multi-active: transport loss during cohort close".into());
                }
                if closed == expected {
                    return Ok("peer_closed_cleanly");
                }
                if Instant::now() >= until {
                    return Err("daemon multi-active: lane close left an incomplete cohort".into());
                }
                thread::sleep(TICK);
                continue;
            }
            if deadline.is_some_and(|until| Instant::now() >= until) {
                return Ok("max_seconds_reached");
            }
            self.maintain(scope, ctx, deadline)?;
            let mut progressed = false;
            for (index, lane) in self
                .lanes
                .iter()
                .enumerate()
                .filter_map(|(index, lane)| lane.as_ref().map(|lane| (index, lane)))
            {
                let usable = || {
                    !lane.retired
                        && !lane.task.attempt.lost.load(Ordering::Acquire)
                        && cohort.peer_closed.load(Ordering::Acquire) == 0
                };
                if !usable() {
                    continue;
                }
                if let Ok(packet) = lane.task.channels.from_wire.try_recv() {
                    progressed = true;
                    if !usable() {
                        continue;
                    }
                    match self.pool.accept_inbound(lane.id, &packet) {
                        Ok(_) => {}
                        Err(
                            PoolError::FlowLimit | PoolError::UnknownFlow | PoolError::FlowFailed,
                        ) => continue,
                        Err(e) => return Err(pool_error(e)),
                    }
                    cohort.forward(run.policy_window)?;
                    if !usable() {
                        continue;
                    }
                    match io.write_packet(&packet) {
                        Ok(()) => {
                            run.counters.multi_active_lanes[index]
                                .rx
                                .fetch_add(1, Ordering::Relaxed);
                            run.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                            run.counters
                                .rx_bytes
                                .fetch_add(packet.len() as u64, Ordering::Relaxed);
                        }
                        Err(TunError::QueueFull) => {}
                        Err(e) => {
                            return Err(format!("daemon multi-active: TUN write failed: {e:?}"));
                        }
                    }
                }
            }
            let wait = if progressed { Duration::ZERO } else { TICK };
            if poll_io(tun_fd, Some(tun_fd), PathPoll::Read, wait)?.tun_readable
                && let Some(packet) = io
                    .read_packet_with_scratch(&mut scratch)
                    .map_err(|e| format!("daemon multi-active: TUN read failed: {e:?}"))?
            {
                cohort.forward(run.policy_window)?;
                if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                    continue;
                }
                let packet = packet.as_ref();
                let (_, id) = match self.pool.route_outbound(packet) {
                    Ok(binding) => binding,
                    Err(
                        PoolError::PacketDenied(_)
                        | PoolError::NotTcp
                        | PoolError::Fragmented
                        | PoolError::InvalidTcpHeader
                        | PoolError::UnknownFlow
                        | PoolError::FlowLimit
                        | PoolError::FlowFailed
                        | PoolError::NoReadyLane,
                    ) => continue,
                    Err(e) => return Err(pool_error(e)),
                };
                let lane = self
                    .lanes
                    .iter()
                    .flatten()
                    .find(|lane| lane.id == id)
                    .ok_or("daemon multi-active: pool selected an unowned lane")?;
                if !lane.retired && !lane.task.attempt.lost.load(Ordering::Acquire) {
                    // Backpressure drops on the pinned lane; never spill into a sibling.
                    let _ = lane.task.channels.to_wire.try_send(packet.to_vec());
                }
            }
        }
    }
}

struct LanePolicy<'a> {
    profile: E2eL3Profile,
    policy: &'a SessionPolicy,
    backend: &'a OpenSslE2eBackend,
    mtu: usize,
    status_path: &'a Path,
    policy_window: PolicyWindow,
    store: &'a Mutex<StatusStore>,
    counters: &'a LiveCounters,
}

struct Live<'a> {
    counters: &'a LiveCounters,
    edge: bool,
}

impl Live<'_> {
    fn connections(counters: &LiveCounters, edge: bool) -> &AtomicU64 {
        if edge {
            &counters.outbound_upstreams
        } else {
            &counters.inbound_connections
        }
    }
}

impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.counters.connected.store(false, Ordering::SeqCst);
        for lane in &self.counters.multi_active_lanes {
            lane.state.fetch_and(!1, Ordering::Release);
        }
        Self::connections(self.counters, self.edge).store(0, Ordering::SeqCst);
    }
}

fn admit(
    run: &Run<'_>,
    cohort: &Cohort,
    all: Vec<Ready>,
    until: Instant,
    edge: bool,
    slots: [AuthenticatedPeer; 2],
) -> Result<(CircuitPool, Vec<CircuitId>, BusinessIdentity), String> {
    let first = all.first().ok_or("daemon multi-active: empty cohort")?;
    let identity = first.identity;
    let nonce = first.nonce;
    let mut pool = CircuitPool::new(
        identity.local_vip,
        identity.peer_vip,
        run.mtu,
        all.len(),
        MAX_TRACKED_FLOWS,
    )
    .map_err(|e| format!("daemon multi-active: invalid pool: {e:?}"))?;
    let mut ids = Vec::with_capacity(all.len());
    for ready in all {
        if ready.identity != identity || ready.nonce != nonce {
            return Err("daemon multi-active: inconsistent authenticated cohort identity".into());
        }
        pool.reserve_lane(ready.id)
            .map_err(|e| format!("daemon multi-active: lane reservation refused: {e:?}"))?;
        pool.mark_ready(ready.id)
            .map_err(|e| format!("daemon multi-active: lane admission refused: {e:?}"))?;
        ids.push(ready.id);
    }
    if edge {
        report_trial_ready(run.tun)?;
    }
    run.policy_window.check()?;
    {
        let mut store = lock_mutex(&run.store);
        let (_, deadline, utc) =
            status_gate(&mut store, run.status_path, now_utc_us()?, Instant::now())?;
        check_identity_revocations(&mut store, run.status_path, slots)?;
        *lock_mutex(&cohort.freshness) = Some((deadline, utc));
    }
    remaining(cohort, until).map_err(failure_reason)?;
    cohort.forward(run.policy_window)?;
    Ok((pool, ids, identity))
}

fn failure_reason(failure: Failure) -> String {
    match failure {
        Failure::Transport(reason) | Failure::Terminal(reason) => reason,
    }
}

pub(super) fn run(endpoint: Endpoint, run: Run<'_>) -> Result<(), String> {
    let edge = endpoint.is_edge();
    let count = run.profile.active_lanes();
    if !(2..=HARD_PAIR_CAP).contains(&usize::from(count)) {
        return Err("daemon multi-active: invalid confirmed lane count".into());
    }
    let slots = revocation_slots(run.policy.local, run.policy.expected_peer)?;
    run.policy_window.check()?;
    lock_revocation_gate(&run.store, run.status_path, slots)?;
    if !edge {
        // Core readiness still means that a verified TUN and listener exist;
        // connected status will not be published until all lanes are bound.
        report_trial_ready(run.tun)?;
    }
    let mtu = u16::try_from(run.mtu).map_err(|_| "daemon multi-active: invalid MTU")?;
    let max_duration = run.max_seconds.map(Duration::from_secs);
    // Validate user time arithmetic before any sockets or workers are started.
    if max_duration.is_some_and(|duration| Instant::now().checked_add(duration).is_none()) {
        return Err("daemon multi-active: invalid --max-seconds".into());
    }
    let mut nonce = if edge {
        Some(random_array::<16>().map_err(|_| "daemon multi-active: cohort entropy unavailable")?)
    } else {
        None
    };
    if nonce == Some([0; 16]) {
        return Err("daemon multi-active: invalid all-zero cohort nonce".into());
    }
    let admission = Admission::new(Limits {
        handshakes_global: 1,
        authenticated_global: usize::from(count),
        authenticated_per_peer: usize::from(count),
        bytes_global: 16 * 1024 * 1024,
    });
    let cohort = Arc::new(Cohort::default());
    let lane_policy = LanePolicy {
        profile: run.profile,
        policy: &run.policy,
        backend: &run.backend,
        mtu: run.mtu,
        status_path: run.status_path,
        policy_window: run.policy_window,
        store: &run.store,
        counters: run.counters,
    };
    let clock = Instant::now();
    let until = (clock + STARTUP_LIMIT).min(run.policy_window.deadline());
    let context = WorkerContext {
        endpoint: &endpoint,
        admission: &admission,
        run: &lane_policy,
        cohort: &cohort,
        slots,
    };
    let cancel = Arc::clone(&cohort);
    let refresh = Arc::clone(&cohort);
    let watchdog = StatusWatchdog::start_with_interrupt(
        Arc::clone(&run.store),
        run.status_path.to_path_buf(),
        run.policy_window,
        move || cancel.cancel(),
        move |mono, utc| *lock_mutex(&refresh.freshness) = Some((mono, utc)),
        Arc::clone(run.counters),
        STATUS_RECHECK_INTERVAL,
        Some(slots),
    );
    let result = thread::scope(|scope| {
        let _cancel_before_join = CancelOnDrop(&cohort);
        let mut tasks = Vec::with_capacity(usize::from(count));
        let mut readiness = Vec::with_capacity(usize::from(count));
        for ordinal in 0..count {
            let opening = Opening::Initial(Membership {
                nonce,
                ordinal,
                count,
                mtu,
            });
            let task = Task::spawn(scope, &context, &cohort, opening, until)?;
            let ready = loop {
                let remaining = remaining(&cohort, until).map_err(failure_reason)?;
                match task.ready.recv_timeout(TICK.min(remaining)) {
                    Ok(ready) => break ready,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let result = task.join(&cohort)?;
                        cohort.check()?;
                        return Err(result.err().map_or_else(
                            || "initial lane exited before admission".into(),
                            failure_reason,
                        ));
                    }
                }
            };
            nonce = Some(ready.nonce);
            tasks.push(task);
            readiness.push(ready);
        }
        let (pool, ids, identity) = admit(&run, &cohort, readiness, until, edge, slots)?;
        let deadline = max_duration
            .map(|duration| {
                Instant::now()
                    .checked_add(duration)
                    .ok_or("daemon multi-active: invalid --max-seconds")
            })
            .transpose()?;
        let lanes = tasks
            .into_iter()
            .zip(ids)
            .enumerate()
            .map(|(index, (task, id))| {
                lock_mutex(&cohort.versions)[index] = Some(Version {
                    anchor: id,
                    last_id: id,
                    generation: 1,
                    vacant: false,
                });
                run.counters.multi_active_lanes[index]
                    .state
                    .store(3, Ordering::Release);
                task.attempt.ready.store(true, Ordering::Release);
                Some(Active {
                    task,
                    id,
                    retired: false,
                })
            })
            .collect();
        let live = Live {
            counters: run.counters,
            edge,
        };
        let mut dispatch = Dispatch {
            run: &run,
            cohort: &cohort,
            pool,
            lanes,
            pending: None,
            retry_at: Instant::now(),
            generation: 1,
            nonce: nonce.expect("admitted cohort has a nonce"),
            mtu,
            identity,
            edge,
        };
        run.counters.path_epoch.store(1, Ordering::SeqCst);
        run.counters
            .multi_active_count
            .store(count, Ordering::Release);
        dispatch.publish();
        cohort.running.store(true, Ordering::Release);
        let result = dispatch.forward(scope, &context, deadline);
        dispatch.pool.revoke();
        drop(live);
        let reason = match result {
            Ok(reason) => reason,
            Err(reason) => {
                cohort.fail(reason.clone());
                return Err(reason);
            }
        };
        cohort.draining.store(true, Ordering::Release);
        if let Some(task) = &dispatch.pending {
            task.attempt.lose();
        }
        let close_until = Instant::now() + Duration::from_secs(1);
        while dispatch
            .lanes
            .iter()
            .flatten()
            .any(|lane| !lane.task.worker.is_finished())
        {
            cohort.check()?;
            if Instant::now() >= close_until {
                return Err("daemon multi-active: lane workers exceeded shutdown grace".into());
            }
            thread::sleep(TICK);
        }
        cohort.check()?;
        Ok((identity, reason))
    });
    // All scoped workers are joined and their admission credits are released.
    // Join the watchdog before considering a concurrent revocation successful.
    let fault = watchdog.fault_handle();
    drop(watchdog);
    if let Some(reason) = fault.get() {
        return Err(reason.clone());
    }
    if let Some(reason) = cohort.reason.get() {
        return Err(reason.clone());
    }
    let (identity, reason) = result?;
    let mode = if edge { "connect" } else { "serve" };
    let report = PathReport {
        stop: PathStop::Budget(reason),
        identity,
        stats: PacketStats {
            outbound_packets: run.counters.tx_packets.load(Ordering::Relaxed),
            outbound_bytes: run.counters.tx_bytes.load(Ordering::Relaxed),
            inbound_packets: run.counters.rx_packets.load(Ordering::Relaxed),
            inbound_bytes: run.counters.rx_bytes.load(Ordering::Relaxed),
            ..PacketStats::default()
        },
        local_vip: identity.local_vip,
        peer_vip: identity.peer_vip,
    };
    print_path_summary(mode, run.tun, &report, reason, 0, 1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_requires_exact_direction_ordinal_count_mtu_and_nonce() {
        let expected = Membership {
            nonce: Some([0x37; 16]),
            ordinal: 2,
            count: 4,
            mtu: 1360,
        };
        let valid = expected.record(0, [0x37; 16]);
        assert_eq!(expected.validate(0, valid), Ok([0x37; 16]));
        for offset in 0..valid.len() {
            let mut wrong = valid;
            wrong[offset] ^= 1;
            assert!(expected.validate(0, wrong).is_err(), "byte {offset}");
        }
        // Only the first Core lane can learn a nonce. It cannot learn zero.
        let first = Membership {
            nonce: None,
            ordinal: 0,
            ..expected
        };
        assert!(first.validate(0, first.record(0, [0; 16])).is_err());
        assert_eq!(first.validate(0, first.record(0, [3; 16])), Ok([3; 16]));
    }

    #[test]
    fn saturation_keeps_the_lane_bound_and_cancellation_stops_queue_access() {
        let cohort = Arc::new(Cohort::default());
        let attempt = Arc::new(Attempt::default());
        let (dispatcher, lane) = lane_channels(&cohort, &attempt);
        for sequence in 0..QUEUE_PACKETS {
            lane.write_packet(&[sequence as u8]).unwrap();
            dispatcher.to_wire.try_send(vec![sequence as u8]).unwrap();
        }
        // Inbound is lossy on saturation; all queued packets remain FIFO.
        lane.write_packet(&[255]).unwrap();
        assert_eq!(
            dispatcher.to_wire.try_send(vec![255]),
            Err(TrySendError::Full(vec![255]))
        );
        for sequence in 0..QUEUE_PACKETS {
            assert_eq!(dispatcher.from_wire.try_recv().unwrap(), vec![
                sequence as u8
            ]);
            assert_eq!(lane.read_packet().unwrap(), Some(vec![sequence as u8]));
        }
        assert_eq!(dispatcher.from_wire.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(lane.read_packet(), Ok(None));
        attempt.lose();
        dispatcher.to_wire.try_send(vec![1]).unwrap();
        assert_eq!(lane.read_packet(), Ok(None));
        assert_eq!(lane.write_packet(&[1]), Ok(()));
        assert_eq!(dispatcher.from_wire.try_recv(), Err(TryRecvError::Empty));
        cohort.cancel();
        assert_eq!(lane.read_packet(), Err(TunError::QueueClosed));
        assert_eq!(lane.write_packet(&[1]), Err(TunError::QueueClosed));
    }

    #[test]
    fn replacement_membership_binds_slot_and_rejects_corrupted_wire() {
        let nonce = [0x37; 16];
        let offer = Replacement {
            ordinal: 2,
            generation: 7,
            anchor: CircuitId([0x52; 16]),
        };
        let wire = offer.record(nonce, 4, 1360, 0);
        assert_eq!(Replacement::parse(wire, nonce, 4, 1360).unwrap(), offer);
        for offset in [0, 5, 7, 8, 10] {
            let mut wrong = wire;
            wrong[offset] ^= 1;
            assert!(Replacement::parse(wrong, nonce, 4, 1360).is_err());
        }
        assert!(Replacement::parse(offer.record(nonce, 4, 1360, 1), nonce, 4, 1360).is_err());
    }

    #[test]
    fn only_typed_transport_errors_permit_replacement() {
        assert!(matches!(
            business_failure(
                "test",
                PacketPathError::CircuitIo(ErrorKind::ConnectionReset)
            ),
            Failure::Transport(_)
        ));
        for err in [
            PacketPathError::CircuitIo(ErrorKind::InvalidData),
            PacketPathError::CircuitProtocol,
            PacketPathError::TruncatedFrame,
            PacketPathError::IdentityMismatch,
            PacketPathError::HostQueueClosed,
        ] {
            assert!(matches!(
                business_failure("test", err),
                Failure::Terminal(_)
            ));
        }
        assert!(matches!(
            tunnel_failure("test", TunnelError::InnerTls("e2e handshake")),
            Failure::Terminal(_)
        ));
    }

    #[test]
    fn local_interrupt_does_not_cancel_sibling_socket() {
        let cohort = Cohort::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut peers = Vec::new();
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let tcp = TcpStream::connect(addr).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let attempt = Arc::new(Attempt::default());
            cohort.register(&attempt, &tcp).unwrap();
            lock_mutex(&cohort.attempts).push(Arc::clone(&attempt));
            peers.push(peer);
            attempts.push(attempt);
        }
        attempts[0].lose();
        assert_eq!(peers[0].read(&mut [0]).unwrap(), 0);
        assert_eq!(cohort.check(), Ok(()));
        lock_mutex(&attempts[1].socket)
            .as_ref()
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut value = [0];
        peers[1].read_exact(&mut value).unwrap();
        assert_eq!(value, *b"x");
        cohort.fail("terminal lane fault".into());
        assert_eq!(cohort.check(), Err("terminal lane fault".into()));
        assert_eq!(peers[1].read(&mut [0]).unwrap(), 0);
    }
}
