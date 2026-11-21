//! Direct fixed-size Edge/Core cohort. No worker owns or touches the TUN.

use super::*;
use boreas_tunnel::{
    circuit::{CircuitId, HARD_PAIR_CAP},
    circuit_pool::{CircuitPool, MAX_TRACKED_FLOWS, PoolError},
    csprng::random_array,
    e2e::{E2eL3Profile, accept_e2e_with_l3_profile_until, open_e2e_with_l3_profile_until},
};
use std::{
    net::Shutdown,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};

const QUEUE_PACKETS: usize = 64;
const TICK: Duration = Duration::from_millis(1);
const STARTUP_LIMIT: Duration = Duration::from_secs(45);
const COHORT_MAGIC: &[u8; 5] = b"BCOH\x01";
const COHORT_LEN: usize = 26;

#[derive(Default)]
pub(super) struct LaneCounters {
    tx: AtomicU64,
    rx: AtomicU64,
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
        let _ = write!(
            json,
            "{{\"lane\":{},\"tx_packets\":{},\"rx_packets\":{}}}",
            index + 1,
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
    finished: AtomicU8,
    reason: OnceLock<String>,
    freshness: Mutex<Option<(Instant, u64)>>,
    sockets: Mutex<Vec<TcpStream>>,
}

impl Cohort {
    fn register(&self, tcp: &TcpStream) -> Result<TcpStream, String> {
        let shutdown = tcp
            .try_clone()
            .map_err(|e| format!("duplicate lane socket: {e}"))?;
        let operation = tcp
            .try_clone()
            .map_err(|e| format!("duplicate lane socket: {e}"))?;
        let mut sockets = lock_mutex(&self.sockets);
        if self.stopped.load(Ordering::Acquire) || sockets.len() >= HARD_PAIR_CAP {
            return Err("cohort cancelled or socket quota exhausted".into());
        }
        sockets.push(shutdown);
        Ok(operation)
    }

    fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
        // Registration and shutdown share this lock, including when cancellation
        // races with a just-connected socket. Never shut down a borrowed raw fd.
        for tcp in lock_mutex(&self.sockets).iter() {
            let _ = tcp.shutdown(Shutdown::Both);
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

struct Ready {
    id: CircuitId,
    identity: BusinessIdentity,
    nonce: [u8; 16],
}

/// PacketPath still owns framing, E2E I/O and authenticated L3 authorization.
/// These are channels, not TUN handles. The coordinator performs the additional
/// TCP flow/affinity decision and is the only consumer/producer of host packets.
struct LaneIo {
    to_wire: Receiver<Vec<u8>>,
    from_wire: SyncSender<Vec<u8>>,
    cohort: Arc<Cohort>,
}

impl PacketIo for LaneIo {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
        if self.cohort.stopped.load(Ordering::Acquire) {
            return Err(TunError::QueueClosed);
        }
        if self.cohort.draining.load(Ordering::Acquire)
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
        if self.cohort.draining.load(Ordering::Acquire)
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
    progress_deadline: Arc<AtomicU64>,
}

fn lane_channels(cohort: &Arc<Cohort>) -> (DispatchLane, LaneIo) {
    let (to_wire, lane_input) = mpsc::sync_channel(QUEUE_PACKETS);
    let (lane_output, from_wire) = mpsc::sync_channel(QUEUE_PACKETS);
    (
        DispatchLane {
            to_wire,
            from_wire,
            progress_deadline: Arc::new(AtomicU64::new(0)),
        },
        LaneIo {
            to_wire: lane_input,
            from_wire: lane_output,
            cohort: Arc::clone(cohort),
        },
    )
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
        run: &Run<'_>,
        cohort: &Cohort,
        until: Instant,
    ) -> Result<TcpStream, String> {
        match self {
            Self::Edge(client, target) => {
                let remaining = remaining_startup(cohort, until)?;
                client
                    .connect_tcp(target, remaining.min(HANDSHAKE_TIMEOUT))
                    .map_err(|e| format!("daemon multi-active: TCP dial failed: {e}"))
            }
            Self::Core(listener, ..) => loop {
                let remaining = remaining_startup(cohort, until)?;
                match listener.accept() {
                    Ok((tcp, _)) => return Ok(tcp),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        run.policy_window.check()?;
                        thread::sleep(remaining.min(IDLE_POLL_TIMEOUT));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(format!("daemon multi-active: accept failed: {e}")),
                }
            },
        }
    }
}

fn remaining_startup(cohort: &Cohort, until: Instant) -> Result<Duration, String> {
    cohort.check()?;
    until
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            "daemon multi-active: incomplete authenticated cohort at startup deadline".into()
        })
}

struct WorkerContext<'a> {
    endpoint: &'a Endpoint,
    admission: &'a Admission,
    run: &'a LanePolicy<'a>,
    cohort: &'a Cohort,
    until: Instant,
    slots: [AuthenticatedPeer; 2],
    clock: Instant,
}

fn elapsed_ms(clock: Instant) -> u64 {
    u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bounded_step<T>(clock: Instant, liveness: &AtomicU64, action: impl FnOnce() -> T) -> T {
    // SO_RCVTIMEO only bounds one syscall. A trickle across many TLS/WS/frame
    // reads must not hold a business operation (or its teardown) indefinitely.
    let timeout = u64::try_from(PATH_IO_TIMEOUT.as_millis()).expect("fixed timeout fits u64");
    liveness.store(elapsed_ms(clock).saturating_add(timeout), Ordering::Release);
    let result = action();
    liveness.store(0, Ordering::Release);
    result
}

#[allow(clippy::too_many_arguments)]
fn run_lane(
    ctx: &WorkerContext<'_>,
    tcp: TcpStream,
    interrupt: &TcpStream,
    membership: Membership,
    io: &LaneIo,
    ready: SyncSender<Ready>,
    liveness: &AtomicU64,
) -> Result<(), String> {
    let run = ctx.run;
    let cohort = ctx.cohort;
    let gate = || {
        remaining_startup(cohort, ctx.until)?;
        run.policy_window.check()?;
        lock_revocation_gate(run.store, run.status_path, ctx.slots)
    };
    gate()?;
    let hop_until = (Instant::now() + HANDSHAKE_TIMEOUT).min(ctx.until);
    let mut hop = match ctx.endpoint {
        Endpoint::Edge(client, target) => client
            .connect_preconnected_until(tcp, target, run.policy.clone(), hop_until)
            .map(Hop::Edge),
        Endpoint::Core(_, server, outer) => server
            .accept_tls_stream_until(tcp, outer, run.policy.clone(), hop_until, ctx.admission)
            .map(Hop::Core),
    }
    .map_err(|e| format!("WSS + pq768 hop session rejected: {e}"))?;
    let session = match &mut hop {
        Hop::Edge(session) => session,
        Hop::Core(accepted) => &mut accepted.session,
    };
    gate()?;
    let e2e_until = (Instant::now() + HANDSHAKE_TIMEOUT).min(ctx.until);
    let edge = ctx.endpoint.is_edge();
    let mut circuit = if edge {
        open_e2e_with_l3_profile_until(
            session,
            run.backend,
            run.policy.expected_peer,
            1,
            run.profile,
            interrupt,
            e2e_until,
        )
    } else {
        accept_e2e_with_l3_profile_until(
            session,
            run.backend,
            run.policy.expected_peer,
            run.profile,
            interrupt,
            e2e_until,
        )
    }
    .map_err(|e| format!("pq768 E2E circuit rejected: {e}"))?;
    // Before any possibly-blocking circuit teardown on setup errors, interrupt
    // the socket. PacketPath owns the circuit after successful binding.
    let setup = (|| {
        if circuit.l3_profile() != run.profile
            || circuit.info().path_hops != 1
            || circuit.local() != run.policy.local
            || circuit.info().peer != run.policy.expected_peer
            || run.mtu > usize::from(circuit.mtu_cap())
        {
            return Err(
                "confirmed circuit is not the exact direct policy/identity/MTU binding".into(),
            );
        }
        bound_path_io(interrupt.as_raw_fd())?;
        let nonce = membership.confirm(&mut circuit, edge)?;
        gate()?;
        if membership.ordinal + 1 == membership.count {
            // Ordered admission guarantees all earlier lanes are locally
            // bound. The final lane confirms that fact from both peers.
            membership.confirm_full_cohort(&mut circuit, edge, nonce)?;
            gate()?;
        }
        Ok(nonce)
    })();
    let nonce = match setup {
        Ok(nonce) => nonce,
        Err(reason) => {
            let _ = interrupt.shutdown(Shutdown::Both);
            return Err(reason);
        }
    };
    let mut path = PacketPath::try_new_over_e2e(io, circuit, run.mtu)
        .map_err(|e| format!("authenticated PacketPath bind rejected: {e:?}"))?;
    // Avoid running CircuitStream's best-effort Drop write before the
    // coordinator has been notified of errors from the worker loop.
    let result: Result<(), String> = (|| {
        ready
            .send(Ready {
                id: CircuitId(path.circuit_id()),
                identity: business_identity(&path),
                nonce,
            })
            .map_err(|_| "cohort ended before lane admission")?;
        while !cohort.running.load(Ordering::Acquire) {
            cohort.check()?;
            thread::sleep(TICK);
        }

        let counters = &run.counters.multi_active_lanes[usize::from(membership.ordinal)];
        let fd = interrupt.as_raw_fd();
        loop {
            if cohort.stopped.load(Ordering::Acquire) {
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
                bounded_step(ctx.clock, liveness, || path.step_outbound())
                    .map_err(|e| format!("outbound circuit failed: {e:?}"))?
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
            if (poll_io(fd, None, wait)?.0 || path.has_buffered_input())
                && !cohort.stopped.load(Ordering::Acquire)
                && !cohort.draining.load(Ordering::Acquire)
            {
                cohort.forward(run.policy_window)?;
                match bounded_step(ctx.clock, liveness, || path.step_inbound())
                    .map_err(|e| format!("inbound circuit failed: {e:?}"))?
                {
                    Some(_) => {}
                    None => {
                        cohort.peer_closed.fetch_add(1, Ordering::AcqRel);
                        return Ok(());
                    }
                }
            }
        }
    })();
    if let Err(reason) = &result
        && !cohort.stopped.load(Ordering::Acquire)
    {
        cohort.fail(format!(
            "daemon multi-active: lane {}: {reason}",
            membership.ordinal + 1
        ));
    }
    result
}

fn check_progress(cohort: &Cohort, lanes: &[DispatchLane], clock: Instant) -> Result<(), String> {
    cohort.check()?;
    let now = elapsed_ms(clock);
    for (index, lane) in lanes.iter().enumerate() {
        let expires = lane.progress_deadline.load(Ordering::Acquire);
        if expires != 0 && now >= expires {
            return Err(format!(
                "daemon multi-active: lane {} exceeded business I/O deadline",
                index + 1
            ));
        }
    }
    Ok(())
}

fn dispatch(
    run: &Run<'_>,
    cohort: &Cohort,
    pool: &mut CircuitPool,
    lanes: &[DispatchLane],
    ids: &[CircuitId],
    clock: Instant,
    deadline: Option<Instant>,
) -> Result<&'static str, String> {
    let tun_fd = run
        .tun
        .raw_fd()
        .ok_or("multi-active requires real Linux TUN")?;
    let io = run.tun.packet_io();
    // Linux additionally reads one byte to detect oversize packets.
    let mut scratch = vec![0; run.mtu + 1];
    let mut peer_close_deadline = None;
    'dispatch: loop {
        check_progress(cohort, lanes, clock)?;
        cohort.forward(run.policy_window)?;
        let closed = usize::from(cohort.peer_closed.load(Ordering::Acquire));
        if closed == lanes.len() {
            return Ok("peer_closed_cleanly");
        }
        if closed != 0 {
            // The first close_notify quiesces all lanes. Only *all* confirmed
            // TLS EOFs count as clean; never hide another lane's transport or
            // protocol failure behind the first clean notification.
            let until =
                *peer_close_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(1));
            if Instant::now() >= until {
                return Err("daemon multi-active: lane close left an incomplete cohort".into());
            }
            thread::sleep(TICK);
            continue;
        }
        if deadline.is_some_and(|until| Instant::now() >= until) {
            return Ok("max_seconds_reached");
        }
        // One bounded visit to each lane, then one TUN read. No busy inbound
        // lane can repeatedly win against another lane or the host queue.
        let mut progressed = false;
        for (index, lane) in lanes.iter().enumerate() {
            if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                continue 'dispatch;
            }
            cohort.check()?;
            match lane.from_wire.try_recv() {
                Ok(packet) => {
                    progressed = true;
                    match pool.accept_inbound(ids[index], &packet) {
                        Ok(_) => {}
                        // A bounded table may become full asymmetrically. No
                        // flow is evicted, and an unknown non-SYN is never bound.
                        Err(PoolError::FlowLimit | PoolError::UnknownFlow) => continue,
                        Err(e) => {
                            return Err(format!(
                                "daemon multi-active: refused inbound lane/flow: {e:?}"
                            ));
                        }
                    }
                    cohort.forward(run.policy_window)?;
                    if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                        continue 'dispatch;
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
                        Err(TunError::QueueFull) => {} // TCP retries on its pinned lane.
                        Err(e) => {
                            return Err(format!("daemon multi-active: TUN write failed: {e:?}"));
                        }
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                        continue 'dispatch;
                    }
                    cohort.check()?;
                    return Err("daemon multi-active: inbound lane worker disconnected".into());
                }
            }
        }
        // The existing poll helper checks the second fd for terminal TUN
        // events. The first fd is the same nonblocking TUN; ignore its result.
        let wait = if progressed { Duration::ZERO } else { TICK };
        if poll_io(tun_fd, Some(tun_fd), wait)?.1
            && let Some(packet) = io
                .read_packet_with_scratch(&mut scratch)
                .map_err(|e| format!("daemon multi-active: TUN read failed: {e:?}"))?
        {
            let packet = packet.as_ref();
            let (_, id) = match pool.route_outbound(packet) {
                Ok(binding) => binding,
                Err(
                    PoolError::PacketDenied(_)
                    | PoolError::NotTcp
                    | PoolError::Fragmented
                    | PoolError::InvalidTcpHeader
                    | PoolError::UnknownFlow
                    | PoolError::FlowLimit,
                ) => continue,
                Err(e) => {
                    return Err(format!(
                        "daemon multi-active: outbound lane unavailable: {e:?}"
                    ));
                }
            };
            let index = ids
                .iter()
                .position(|lane| *lane == id)
                .ok_or("daemon multi-active: pool selected an unowned lane")?;
            cohort.forward(run.policy_window)?;
            if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                continue 'dispatch;
            }
            match lanes[index].to_wire.try_send(packet.to_vec()) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    if cohort.peer_closed.load(Ordering::Acquire) != 0 {
                        continue 'dispatch;
                    }
                    cohort.check()?;
                    return Err("daemon multi-active: outbound lane worker disconnected".into());
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

impl<'a> Live<'a> {
    fn publish(counters: &'a LiveCounters, edge: bool, count: u8) -> Self {
        counters.multi_active_count.store(count, Ordering::Release);
        Self::connections(counters, edge).store(u64::from(count), Ordering::SeqCst);
        counters.path_epoch.store(1, Ordering::SeqCst);
        counters.connected.store(true, Ordering::SeqCst);
        Self { counters, edge }
    }

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
    remaining_startup(cohort, until)?;
    cohort.forward(run.policy_window)?;
    Ok((pool, ids, identity))
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
        until,
        slots,
        clock,
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
        let mut dispatchers = Vec::with_capacity(usize::from(count));
        let mut readiness = Vec::with_capacity(usize::from(count));
        for ordinal in 0..count {
            // Bounded serial admission (one in-progress handshake). Before
            // business, only the fixed count of sockets can be accepted/dialed.
            let tcp = endpoint.connect_socket(&run, &cohort, until)?;
            let interrupt = cohort.register(&tcp)?;
            let (dispatcher, io) = lane_channels(&cohort);
            let liveness = Arc::clone(&dispatcher.progress_deadline);
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let membership = Membership {
                nonce,
                ordinal,
                count,
                mtu,
            };
            let ctx = &context;
            thread::Builder::new()
                .name(format!("boreas-lane-{}", ordinal + 1))
                .spawn_scoped(scope, move || {
                    let _guard = WorkerGuard(ctx.cohort);
                    let result =
                        run_lane(ctx, tcp, &interrupt, membership, &io, ready_tx, &liveness);
                    if let Err(reason) = result
                        && !ctx.cohort.stopped.load(Ordering::Acquire)
                    {
                        ctx.cohort.fail(format!(
                            "daemon multi-active: lane {}: {reason}",
                            ordinal + 1
                        ));
                    }
                    ctx.cohort.finished.fetch_add(1, Ordering::Release);
                })
                .map_err(|e| format!("daemon multi-active: cannot spawn lane: {e}"))?;
            // Never wait unboundedly on a partial encrypted membership record.
            // All earlier sockets remain registered while this lane is pending.
            let ready = loop {
                let remaining = remaining_startup(&cohort, until)?;
                match ready_rx.recv_timeout(TICK.min(remaining)) {
                    Ok(ready) => break ready,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        cohort.check()?;
                        return Err(
                            "daemon multi-active: lane worker disconnected before admission".into(),
                        );
                    }
                }
            };
            nonce = Some(ready.nonce);
            dispatchers.push(dispatcher);
            readiness.push(ready);
        }
        let (mut pool, ids, identity) = admit(&run, &cohort, readiness, until, edge, slots)?;
        let deadline = max_duration
            .map(|duration| {
                Instant::now()
                    .checked_add(duration)
                    .ok_or("daemon multi-active: invalid --max-seconds")
            })
            .transpose()?;
        let live = Live::publish(run.counters, edge, count);
        cohort.running.store(true, Ordering::Release);
        let result = dispatch(
            &run,
            &cohort,
            &mut pool,
            &dispatchers,
            &ids,
            clock,
            deadline,
        );
        pool.revoke();
        drop(live);
        let reason = match result {
            Ok(reason) => reason,
            Err(reason) => {
                cohort.fail(reason.clone());
                return Err(reason);
            }
        };
        cohort.draining.store(true, Ordering::Release);
        let close_until = Instant::now() + Duration::from_secs(1);
        while cohort.finished.load(Ordering::Acquire) != count && Instant::now() < close_until {
            cohort.check()?;
            thread::sleep(TICK);
        }
        cohort.check()?;
        if cohort.finished.load(Ordering::Acquire) != count {
            return Err("daemon multi-active: lane workers exceeded shutdown grace".into());
        }
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
        let (dispatcher, lane) = lane_channels(&cohort);
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
        cohort.cancel();
        assert_eq!(lane.read_packet(), Err(TunError::QueueClosed));
        assert_eq!(lane.write_packet(&[1]), Err(TunError::QueueClosed));
    }

    #[test]
    fn joint_cancellation_interrupts_all_owned_sockets_and_rejects_late_registration() {
        let cohort = Cohort::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut peers = Vec::new();
        let mut interrupts = Vec::new();
        for _ in 0..HARD_PAIR_CAP {
            let tcp = TcpStream::connect(addr).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            interrupts.push(cohort.register(&tcp).unwrap());
            peers.push(peer);
        }
        let late = TcpStream::connect(addr).unwrap();
        assert!(cohort.register(&late).is_err());
        cohort.fail("lane fault".into());
        assert_eq!(cohort.check(), Err("lane fault".into()));
        for peer in &mut peers {
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
        assert!(cohort.register(&late).is_err());
        drop(interrupts);
    }
}
