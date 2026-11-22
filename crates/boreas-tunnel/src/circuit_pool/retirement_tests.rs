use super::tests::{ip_checksum, packet};
use super::*;

const L: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 1);
const R: Ipv4Addr = Ipv4Addr::new(10, 20, 16, 251);
const A: CircuitId = CircuitId([1; 16]);
const B: CircuitId = CircuitId([2; 16]);
const F: u8 = 1;
const S: u8 = 2;
const X: u8 = 4;
const K: u8 = 16;

fn seg(rev: bool, port: u16, flags: u8, seq: u32, ack: u32, data: usize) -> Vec<u8> {
    let mut p = packet(rev, port, flags).to_vec();
    p.resize(40 + data, 0x5a);
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[24..28].copy_from_slice(&seq.to_be_bytes());
    p[28..32].copy_from_slice(&ack.to_be_bytes());
    let csum = tcp_checksum(&p[12..20], &p[20..]);
    p[36..38].copy_from_slice(&csum.to_be_bytes());
    ip_checksum(&mut p);
    p
}

fn pool(local: Ipv4Addr, remote: Ipv4Addr, limit: usize) -> CircuitPool {
    let mut p = CircuitPool::new(local, remote, 1500, 2, limit).unwrap();
    for id in [A, B] {
        p.reserve_lane(id).unwrap();
        p.mark_ready(id).unwrap();
    }
    p
}

fn one(p: &mut CircuitPool, lane: CircuitId, rev: bool, s: &[u8], now: Instant) -> FlowKey {
    if rev {
        p.accept_at(lane, s, now).unwrap()
    } else {
        let (key, actual) = p.route_at(s, now).unwrap();
        assert_eq!(actual, lane);
        key
    }
}

fn establish(p: &mut CircuitPool, lane: CircuitId, port: u16, now: Instant) -> FlowKey {
    let key = one(p, lane, false, &seg(false, port, S, 10, 0, 0), now);
    one(p, lane, true, &seg(true, port, S | K, 20, 11, 0), now);
    one(p, lane, false, &seg(false, port, K, 11, 21, 0), now);
    key
}

fn close(p: &mut CircuitPool, lane: CircuitId, port: u16, now: Instant) {
    one(p, lane, false, &seg(false, port, F | K, 11, 21, 0), now);
    one(p, lane, true, &seg(true, port, F | K, 21, 12, 0), now);
    one(p, lane, false, &seg(false, port, K, 12, 22, 0), now);
}

#[test]
fn two_endpoints_wrap_data_half_close_and_retry_without_rebinding() {
    let mut a = pool(L, R, 1);
    let mut b = pool(R, L, 1);
    let t = Instant::now();
    let old = seg(false, 80, S, u32::MAX - 1, 0, 0);
    let fin = seg(false, 80, F | K, u32::MAX, 101, 3);
    let last_fin = seg(true, 80, F | K, 108, 3, 0);
    let last_ack = seg(false, 80, K, 3, 109, 0);
    let (key, _) = a.route_at(&old, t).unwrap();
    let mut relay = |rev, s: &[u8]| {
        let (origin, destination) = if rev {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        assert_eq!(origin.route_at(s, t), Ok((key, A)));
        assert_eq!(destination.accept_at(A, s, t), Ok(key));
    };
    relay(false, &old);
    relay(true, &seg(true, 80, S | K, 100, u32::MAX, 0));
    relay(false, &seg(false, 80, K, u32::MAX, 101, 0));
    relay(false, &fin);
    relay(true, &seg(true, 80, K, 101, 3, 7));
    relay(false, &seg(false, 80, K, 3, 108, 0));
    relay(true, &last_fin);
    // The local ACK is observed, but dropped before it reaches the remote
    // dispatcher; the remote FIN retransmission and final ACK must still work.
    assert_eq!(a.route_at(&last_ack, t), Ok((key, A)));
    assert_eq!(a.flow_count(), 0);
    assert_eq!(b.binding(key), Some(FlowBinding::Pinned(A)));
    assert_eq!(b.route_at(&last_fin, t), Ok((key, A)));
    assert_eq!(a.accept_at(A, &last_fin, t), Ok(key));
    assert_eq!(a.route_at(&last_ack, t), Ok((key, A)));
    assert_eq!(b.accept_at(A, &last_ack, t), Ok(key));
    assert_eq!(b.flow_count(), 0);
    let fresh = seg(false, 80, S, 5000, 0, 0);
    for old_or_new in [&old, &fresh] {
        assert_eq!(a.route_at(old_or_new, t), Err(PoolError::UnknownFlow));
        for lane in [A, B] {
            assert_eq!(
                b.accept_at(lane, old_or_new, t),
                Err(PoolError::UnknownFlow)
            );
        }
    }
    assert_eq!(b.accept_at(B, &last_ack, t), Err(PoolError::UnknownFlow));
    assert_eq!(a.retire_flow(key), None);
    let reuse = t + CLOSE_GUARD;
    assert_eq!(
        b.accept_at(A, &last_ack, reuse),
        Err(PoolError::UnknownFlow)
    );
    assert_eq!(a.route_at(&fresh, reuse), Ok((key, B)));
    assert_eq!(b.accept_at(B, &fresh, reuse), Ok(key));
    assert_eq!(b.accept_at(A, &old, reuse), Err(PoolError::WrongLane));
    assert_eq!(b.binding(key), Some(FlowBinding::Pinned(B)));
}

#[test]
fn wrong_lane_corrupt_fin_invalid_ack_and_reset_do_not_retire() {
    let t = Instant::now();
    let mut p = pool(L, R, 2);
    let key = establish(&mut p, A, 80, t);
    let failed = establish(&mut p, B, 81, t);
    p.begin_drain(A).unwrap();
    let remote_fin = seg(true, 80, F | K, 21, 12, 0);
    let mut corrupt = remote_fin.clone();
    corrupt[36] ^= 1;
    assert_eq!(p.accept_at(B, &remote_fin, t), Err(PoolError::WrongLane));
    one(&mut p, A, false, &seg(false, 80, F | K, 11, 21, 0), t);
    one(&mut p, A, true, &corrupt, t);
    one(&mut p, A, false, &seg(false, 80, K, 12, 22, 0), t);
    one(&mut p, A, true, &seg(true, 80, X | K, 21, 12, 0), t);
    assert_eq!(p.binding(key), Some(FlowBinding::Pinned(A)));
    one(&mut p, A, true, &remote_fin, t);
    for bad in [
        seg(false, 80, K, 999, 22, 0), // unobserved sender position
        seg(false, 80, K, 12, 23, 0),  // ACK beyond the FIN
        seg(false, 80, K, 12, 21, 0),  // ACK before the FIN
    ] {
        one(&mut p, A, false, &bad, t);
        assert_eq!(p.binding(key), Some(FlowBinding::Pinned(A)));
    }
    assert_eq!(p.invalidate_lane(B), Ok(1));
    assert_eq!(p.binding(failed), Some(FlowBinding::Failed));
    one(&mut p, A, false, &seg(false, 80, K, 12, 22, 0), t);
    assert_eq!(p.pinned_count(A), 0);
    assert_eq!(p.invalidate_lane(A), Ok(0));
    assert_eq!(p.accept_at(A, &remote_fin, t), Err(PoolError::UnknownFlow));
    let later = t + CLOSE_GUARD;
    assert_eq!(
        p.route_at(&seg(false, 81, S, 100, 0, 0), later),
        Err(PoolError::FlowFailed)
    );
    assert_eq!(p.flow_count(), 1);
}

#[test]
fn bounded_guard_pressure_never_evicts_and_recovers_on_expiry() {
    let t = Instant::now();
    let mut p = pool(L, R, 1);
    establish(&mut p, A, 80, t);
    close(&mut p, A, 80, t);
    assert_eq!(p.flow_count(), 0);
    establish(&mut p, B, 81, t);
    close(&mut p, B, 81, t);
    assert_eq!(p.flow_count(), 1);
    assert_eq!(p.flows.len(), 2);
    assert_eq!(p.guards.len(), 2);
    let new_tuple = seg(false, 82, S, 30, 0, 0);
    assert_eq!(p.route_at(&new_tuple, t), Err(PoolError::FlowLimit));
    for port in [80, 81] {
        let retry = seg(false, port, S, 10, 0, 0);
        assert_eq!(
            p.route_at(&retry, t + CLOSE_GUARD - Duration::from_nanos(1)),
            Err(PoolError::UnknownFlow)
        );
    }
    assert_eq!(p.route_at(&new_tuple, t + CLOSE_GUARD).unwrap().1, A);
    assert!(p.guards.is_empty());
    assert_eq!(p.flows.len(), 1);
    assert_eq!(p.revoke(), 1);
}

#[test]
fn incomplete_handshake_and_one_sided_close_have_no_idle_expiry() {
    let t = Instant::now();
    let mut p = pool(L, R, 2);
    let half = establish(&mut p, A, 80, t);
    one(&mut p, A, false, &seg(false, 80, F | K, 11, 21, 0), t);
    one(&mut p, A, true, &seg(true, 80, K, 21, 12, 0), t);
    let incomplete = one(&mut p, B, false, &seg(false, 81, S, 10, 0, 0), t);
    one(&mut p, B, true, &seg(true, 81, S | K, 20, 10, 0), t); // bad handshake ACK
    close(&mut p, B, 81, t);
    let later = t + Duration::from_secs(3600);
    assert_eq!(
        p.route_at(&seg(false, 82, S, 30, 0, 0), later),
        Err(PoolError::FlowLimit)
    );
    assert_eq!(p.binding(half), Some(FlowBinding::Pinned(A)));
    assert_eq!(p.binding(incomplete), Some(FlowBinding::Pinned(B)));
}
