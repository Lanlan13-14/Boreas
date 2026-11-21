use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use boreas_dns::dispatch::{AuthoritySnapshot, ClientAuthorizer, DispatchError, QueryDispatcher};
use boreas_dns::packet::AuthenticatedPeerSource;
use boreas_dns::upstream::{TcpUpstream, UpstreamError};
use boreas_dns::{AuthoritativeDns, DnsError, MAX_QUERY_BYTES, SourceAuthorization, Zone};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 20, 1, 2));
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 20, 1, 3));
const WAIT: Duration = Duration::from_secs(5);
const TTL: Duration = Duration::from_secs(60);

struct Policy(Arc<AtomicBool>);

impl ClientAuthorizer for Policy {
    fn authorized_node(&self, peer: AuthenticatedPeerSource) -> Option<u16> {
        (self.0.load(Ordering::SeqCst) && peer.address() == CLIENT).then_some(23)
    }
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut bytes = vec![0x76, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn resolver(suffix: &str, allow: IpAddr, cap: usize) -> AuthoritativeDns {
    let mut zone = Zone::new(suffix).unwrap();
    zone.add_address(
        &format!("host.{suffix}"),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 91)),
    )
    .unwrap();
    zone.refuse_name(&format!("denied.{suffix}")).unwrap();
    AuthoritativeDns::new(zone, SourceAuthorization::new([allow]), cap).unwrap()
}

fn fresh(allow: IpAddr, cap: usize) -> AuthoritySnapshot {
    let now = Instant::now();
    AuthoritySnapshot::new(resolver("corp.test", allow, cap), now, now + TTL).unwrap()
}

fn service(
    authority: Option<AuthoritySnapshot>,
    listener: Option<&TcpListener>,
    enabled: Arc<AtomicBool>,
) -> QueryDispatcher<Policy> {
    let upstream = listener.map(|listener| {
        TcpUpstream::new(listener.local_addr().unwrap(), WAIT, 512).unwrap()
    });
    QueryDispatcher::new("CoRP.TEsT.", authority, upstream, Policy(enabled)).unwrap()
}

fn ask(
    dns: &QueryDispatcher<Policy>,
    source: IpAddr,
    bytes: &[u8],
) -> Result<Vec<u8>, DispatchError> {
    dns.dispatch(
        AuthenticatedPeerSource::from_authenticated_overlay_peer(source).unwrap(),
        bytes,
        Instant::now() + WAIT,
    )
}

fn listener() -> TcpListener {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_no_connect(listener: &TcpListener) {
    // Work is synchronous; even a closed connection remains observable in the
    // accept queue if the dispatcher tried to connect. No sleep is necessary.
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[test]
fn private_success_nodata_nxdomain_and_refused_never_open_upstream() {
    let listener = listener();
    let dns = service(
        Some(fresh(CLIENT, 512)),
        Some(&listener),
        Arc::new(AtomicBool::new(true)),
    );
    for (name, qtype, flags, answers) in [
        ("HOST.Corp.TeST", 1, 0x8500, 1),
        ("CORP.test", 1, 0x8500, 0),
        ("host.corp.test", 28, 0x8500, 0),
        ("missing.corp.test", 1, 0x8503, 0),
        ("denied.corp.test", 1, 0x8105, 0),
    ] {
        let request = query(name, qtype);
        let response = ask(&dns, CLIENT, &request).unwrap();
        assert_eq!(word(&response, 0), word(&request, 0));
        assert_eq!(word(&response, 2), flags);
        assert_eq!(word(&response, 6), answers);
        assert_eq!(&response[12..request.len()], &request[12..]);
        if answers == 1 {
            assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 91]);
        }
    }
    assert_no_connect(&listener);
}

#[test]
fn unavailable_expired_not_yet_valid_and_failed_authority_never_forward() {
    let listener = listener();
    let now = Instant::now();
    let enabled = Arc::new(AtomicBool::new(true));
    let request = query("host.corp.test", 1);
    let missing = service(None, Some(&listener), enabled.clone());
    assert!(matches!(
        ask(&missing, CLIENT, &request),
        Err(DispatchError::AuthorityUnavailable)
    ));
    for (from, until) in [
        (now - Duration::from_millis(1), now),
        (now + TTL, now + TTL + TTL),
    ] {
        let snapshot = AuthoritySnapshot::new(resolver("corp.test", CLIENT, 512), from, until)
            .unwrap();
        let stale = service(Some(snapshot), Some(&listener), enabled.clone());
        for request in [&request, &query("missing.CORP.TEST", 1)] {
            assert!(matches!(
                ask(&stale, CLIENT, request),
                Err(DispatchError::AuthorityNotFresh)
            ));
        }
    }
    let small = service(Some(fresh(CLIENT, 12)), Some(&listener), enabled);
    assert!(matches!(
        ask(&small, CLIENT, &request),
        Err(DispatchError::AuthorityResponse(DnsError::TruncatedWouldExceed))
    ));
    assert_no_connect(&listener);
}

#[test]
fn authorization_is_required_before_parsing_or_dialing_and_rechecked_per_request() {
    let listener = listener();
    let enabled = Arc::new(AtomicBool::new(true));
    let dns = service(Some(fresh(CLIENT, 512)), Some(&listener), enabled.clone());
    let private = query("host.corp.test", 1);
    let public = query("host.example", 1);
    for request in [&private[..], &public[..], &[][..]] {
        assert!(matches!(ask(&dns, OTHER, request), Err(DispatchError::Unauthorized)));
    }
    assert!(ask(&dns, CLIENT, &private).is_ok());
    enabled.store(false, Ordering::SeqCst);
    for request in [&private, &public] {
        assert!(matches!(ask(&dns, CLIENT, request), Err(DispatchError::Unauthorized)));
    }
    enabled.store(true, Ordering::SeqCst);
    let denied = service(Some(fresh(OTHER, 512)), Some(&listener), enabled);
    assert!(matches!(ask(&denied, CLIENT, &private), Err(DispatchError::Unauthorized)));
    assert_no_connect(&listener);
}

#[test]
fn malformed_and_expired_requests_cannot_reach_upstream() {
    let listener = listener();
    let dns = service(None, Some(&listener), Arc::new(AtomicBool::new(true)));
    assert!(matches!(
        ask(&dns, CLIENT, &vec![0; MAX_QUERY_BYTES + 1]),
        Err(DispatchError::InvalidQuery(DnsError::MessageTooLarge))
    ));
    for mut bad in [query("corp.test", 1), query("notcorp.test", 1)] {
        bad[5] = 2;
        assert!(matches!(ask(&dns, CLIENT, &bad), Err(DispatchError::InvalidQuery(_))));
        bad[5] = 1;
        bad[3] = 3;
        assert!(matches!(
            ask(&dns, CLIENT, &bad),
            Err(DispatchError::InvalidQuery(DnsError::InvalidHeader))
        ));
        bad[3] = 0;
        bad[12] = 0xc0;
        assert!(matches!(ask(&dns, CLIENT, &bad), Err(DispatchError::InvalidQuery(_))));
    }
    // A literal dot inside a wire label is not the label separator used by
    // canonical presentation form. This parser rejects rather than guessing.
    let mut ambiguous = query("corp.test", 1);
    ambiguous[12] = 9;
    ambiguous[17] = b'.';
    assert!(matches!(
        ask(&dns, CLIENT, &ambiguous),
        Err(DispatchError::InvalidQuery(DnsError::InvalidName))
    ));
    let mut opaque = query("public.test", 1);
    opaque[11] = 1;
    opaque.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 13]);
    opaque.extend_from_slice(&[0xfd, 0xe8, 0, 9]);
    opaque.extend_from_slice(b"corp.test");
    assert!(matches!(
        ask(&dns, CLIENT, &opaque),
        Err(DispatchError::PublicEdnsOptionsUnsupported)
    ));
    assert!(matches!(
        dns.dispatch(
            AuthenticatedPeerSource::from_authenticated_overlay_peer(CLIENT).unwrap(),
            &query("public.test", 1),
            Instant::now(),
        ),
        Err(DispatchError::DeadlineExceeded)
    ));
    assert_no_connect(&listener);
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let until = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                return stream;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("test TCP upstream accept failed: {error}"),
        }
    }
}

fn read_query(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0; 2];
    stream.read_exact(&mut length).unwrap();
    let mut bytes = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn reply(bytes: &[u8], flags: u16, stream: &mut TcpStream) -> Vec<u8> {
    let mut response = bytes.to_vec();
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    stream.write_all(&(response.len() as u16).to_be_bytes()).unwrap();
    stream.write_all(&response).unwrap();
    response
}

#[test]
fn public_label_lookalikes_forward_once_per_request_including_negative_replies() {
    let listener = listener();
    // Test both fresh and absent authority over the same immutable suffix.
    let enabled = Arc::new(AtomicBool::new(true));
    let fresh = service(Some(fresh(CLIENT, 512)), Some(&listener), enabled.clone());
    let missing = service(None, Some(&listener), enabled);
    let a = query("NotCoRP.TeST", 1);
    let b = query("host.corp.test.public", 1);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            [&a, &a, &b].map(|expected| {
                let mut socket = accept_bounded(&listener);
                let request = read_query(&mut socket);
                assert_eq!(&request, expected);
                reply(&request, 0x8183, &mut socket)
            })
        });
        let got = [
            ask(&fresh, CLIENT, &a).unwrap(),
            ask(&fresh, CLIENT, &a).unwrap(),
            ask(&missing, CLIENT, &b).unwrap(),
        ];
        assert_eq!(got, worker.join().unwrap());
    });
    assert_no_connect(&listener);
}

#[test]
fn public_forwarding_is_opt_in_and_upstream_failure_never_retries() {
    let listener = listener();
    let enabled = Arc::new(AtomicBool::new(true));
    let off = service(Some(fresh(CLIENT, 512)), None, enabled.clone());
    let request = query("public.test", 1);
    assert!(matches!(
        ask(&off, CLIENT, &request),
        Err(DispatchError::PublicForwardingDisabled)
    ));
    let on = service(Some(fresh(CLIENT, 512)), Some(&listener), enabled);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut socket = accept_bounded(&listener);
            assert_eq!(read_query(&mut socket), request);
            // Complete frame prefix over the configured cap; no body needed.
            socket.write_all(&513u16.to_be_bytes()).unwrap();
        });
        assert!(matches!(
            ask(&on, CLIENT, &request),
            Err(DispatchError::Upstream(UpstreamError::InvalidResponse(
                DnsError::MessageTooLarge
            )))
        ));
        worker.join().unwrap();
    });
    assert_no_connect(&listener);
}

#[test]
fn client_revoked_during_public_exchange_cannot_receive_reply() {
    let listener = listener();
    let enabled = Arc::new(AtomicBool::new(true));
    let dns = service(None, Some(&listener), enabled.clone());
    let request = query("public.test", 1);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut socket = accept_bounded(&listener);
            let received = read_query(&mut socket);
            assert_eq!(received, request);
            enabled.store(false, Ordering::SeqCst);
            reply(&received, 0x8180, &mut socket);
        });
        assert!(matches!(ask(&dns, CLIENT, &request), Err(DispatchError::Unauthorized)));
        worker.join().unwrap();
    });
    assert_no_connect(&listener);
}

#[test]
fn configuration_rejects_root_and_wrong_authority_origin() {
    let enabled = Arc::new(AtomicBool::new(true));
    for bad in [".", "", "corp..test", "other.test"] {
        assert!(matches!(
            QueryDispatcher::new(bad, Some(fresh(CLIENT, 512)), None, Policy(enabled.clone())),
            Err(DnsError::InvalidConfiguration)
        ));
    }
}

#[test]
fn public_tcp_preserves_answer_ttl_and_empty_opt() {
    let listener = listener();
    let dns = service(None, Some(&listener), Arc::new(AtomicBool::new(true)));
    let mut request = query("public.test", 1);
    request[11] = 1;
    let opt_start = request.len();
    request.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut socket = accept_bounded(&listener);
            assert_eq!(read_query(&mut socket), request);
            let mut answer = request[..opt_start].to_vec();
            answer[7] = 1;
            answer.extend_from_slice(&[
                0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 3, 231, 0, 4, 192, 0, 2, 80,
            ]);
            answer.extend_from_slice(&request[opt_start..]);
            reply(&answer, 0x8180, &mut socket)
        });
        let response = ask(&dns, CLIENT, &request).unwrap();
        assert_eq!(response, worker.join().unwrap());
        assert_eq!(&response[opt_start + 6..opt_start + 10], &999u32.to_be_bytes());
    });
    assert_no_connect(&listener);
}
