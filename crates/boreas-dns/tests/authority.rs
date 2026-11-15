//! Table-driven checks of the existing authoritative responder.
//!
//! These tests do not bind port 53, spawn threads, or prove a LAN source
//! address. They are not G-DNS acceptance.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use boreas_dns::{AuthoritativeDns, DnsError, SourceAuthorization, Zone};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

fn wire(labels: &[&[u8]]) -> Vec<u8> {
    let mut name = Vec::new();
    for label in labels {
        name.push(label.len() as u8);
        name.extend_from_slice(label);
    }
    name.push(0);
    name
}

fn query(name: &[u8], qtype: u16, rd: bool) -> Vec<u8> {
    let mut msg = vec![
        0xab,
        0xcd,
        if rd { 0x01 } else { 0x00 },
        0x00,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    msg.extend_from_slice(name);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

fn service(max: usize) -> AuthoritativeDns {
    let mut zone = Zone::new("corp.example").unwrap();
    zone.add_address(
        "host.corp.example",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
    )
    .unwrap();
    zone.add_address(
        "dual.corp.example",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
    )
    .unwrap();
    zone.add_address("dual.corp.example", "2001:db8::11".parse().unwrap())
        .unwrap();
    zone.refuse_name("blocked.corp.example").unwrap();
    AuthoritativeDns::new(zone, SourceAuthorization::new([CLIENT]), max).unwrap()
}

fn flags(msg: &[u8]) -> u16 {
    u16::from_be_bytes([msg[2], msg[3]])
}

fn counts(msg: &[u8]) -> (u16, u16, u16, u16) {
    (
        u16::from_be_bytes([msg[4], msg[5]]),
        u16::from_be_bytes([msg[6], msg[7]]),
        u16::from_be_bytes([msg[8], msg[9]]),
        u16::from_be_bytes([msg[10], msg[11]]),
    )
}

struct Case {
    name: &'static [&'static [u8]],
    qtype: u16,
    rcode: u16,
    answers: u16,
    aa: bool,
}

#[test]
fn table_covers_hit_nodata_nxdomain_and_refused() {
    let dns = service(512);
    let cases = [
        Case {
            name: &[b"host", b"corp", b"example"],
            qtype: 1,
            rcode: 0,
            answers: 1,
            aa: true,
        },
        Case {
            name: &[b"dual", b"corp", b"example"],
            qtype: 28,
            rcode: 0,
            answers: 1,
            aa: true,
        },
        Case {
            name: &[b"host", b"corp", b"example"],
            qtype: 28,
            rcode: 0,
            answers: 0,
            aa: true,
        },
        Case {
            name: &[b"missing", b"corp", b"example"],
            qtype: 1,
            rcode: 3,
            answers: 0,
            aa: true,
        },
        Case {
            name: &[b"blocked", b"corp", b"example"],
            qtype: 1,
            rcode: 5,
            answers: 0,
            aa: false,
        },
        Case {
            name: &[b"example", b"net"],
            qtype: 1,
            rcode: 5,
            answers: 0,
            aa: false,
        },
    ];
    for case in cases {
        let response = dns
            .respond_udp(CLIENT, &query(&wire(case.name), case.qtype, true))
            .unwrap()
            .unwrap();
        let bits = flags(&response);
        assert_eq!(bits & 0x000f, case.rcode, "{:?}", case.name);
        assert_eq!(counts(&response).1, case.answers, "{:?}", case.name);
        assert_eq!(bits & 0x0400 != 0, case.aa, "{:?}", case.name);
        assert_eq!(bits & 0x8000, 0x8000);
        assert_eq!(bits & 0x0080, 0, "RA must stay clear");
        assert_eq!(bits & 0x0200, 0, "ordinary answers must not set TC");
        assert_eq!(counts(&response).2, 0);
        assert!(response.len() <= 512);
    }
}

#[test]
fn aaaa_only_name_is_nodata_for_a_not_nxdomain() {
    let mut zone = Zone::new("corp.example").unwrap();
    zone.add_address(
        "v6.corp.example",
        IpAddr::V6("2001:db8::6".parse::<Ipv6Addr>().unwrap()),
    )
    .unwrap();
    let dns = AuthoritativeDns::new(zone, SourceAuthorization::new([CLIENT]), 512).unwrap();
    let response = dns
        .respond_udp(
            CLIENT,
            &query(&wire(&[b"v6", b"corp", b"example"]), 1, false),
        )
        .unwrap()
        .unwrap();
    assert_eq!(flags(&response) & 0x000f, 0);
    assert_eq!(counts(&response).1, 0);
    assert_ne!(flags(&response) & 0x0400, 0);
}

#[test]
fn recursion_desired_is_echoed_and_does_not_set_ra() {
    let dns = service(512);
    let response = dns
        .respond_udp(
            CLIENT,
            &query(&wire(&[b"host", b"corp", b"example"]), 1, true),
        )
        .unwrap()
        .unwrap();
    assert_eq!(flags(&response) & 0x0100, 0x0100);
    assert_eq!(flags(&response) & 0x0080, 0);
    let last = response.len();
    assert_eq!(&response[last - 4..], &[192, 0, 2, 10]);
}

#[test]
fn qclass_other_than_in_is_formerr_not_a_refused_message() {
    let dns = service(512);
    let mut msg = query(&wire(&[b"host", b"corp", b"example"]), 1, false);
    let n = msg.len();
    msg[n - 2] = 0;
    msg[n - 1] = 3; // CH
    assert_eq!(
        dns.respond_udp(CLIENT, &msg),
        Err(DnsError::InvalidQuestion)
    );
    assert_eq!(
        dns.respond_tcp(CLIENT, &msg),
        Err(DnsError::InvalidQuestion)
    );
}

#[test]
fn more_than_one_question_is_rejected() {
    let dns = service(512);
    let mut msg = query(&wire(&[b"host", b"corp", b"example"]), 1, false);
    msg[4] = 0;
    msg[5] = 2;
    assert_eq!(dns.respond_udp(CLIENT, &msg), Err(DnsError::InvalidHeader));
}

#[test]
fn oversize_answer_errors_and_udp_truncate_keeps_an_empty_answer() {
    let dns = service(32);
    let msg = query(&wire(&[b"host", b"corp", b"example"]), 1, true);
    assert_eq!(
        dns.respond_udp(CLIENT, &msg),
        Err(DnsError::TruncatedWouldExceed)
    );
    assert_eq!(
        dns.respond_tcp(CLIENT, &msg),
        Err(DnsError::TruncatedWouldExceed)
    );
    assert_eq!(
        dns.udp_truncate(&msg, 12),
        Err(DnsError::TruncatedWouldExceed)
    );
    let tc = dns.udp_truncate(&msg, 512).unwrap();
    assert!(tc.len() <= 512);
    assert_eq!(flags(&tc) & 0x8200, 0x8200);
    assert_eq!(flags(&tc) & 0x0080, 0);
    assert_eq!(flags(&tc) & 0x0100, 0x0100);
    assert_eq!(counts(&tc), (1, 0, 0, 0));
    assert!(tc.windows(2).all(|w| w != [0xc0, 0x0c]));
}

#[test]
fn tcp_cap_4096_still_refuses_a_message_that_cannot_fit() {
    let dns = service(4096);
    let mut msg = query(&wire(&[b"host", b"corp", b"example"]), 1, false);
    msg[11] = 1;
    msg.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
    let response = dns.respond_tcp(CLIENT, &msg).unwrap().unwrap();
    assert!(response.len() <= 4096);
    assert_eq!(counts(&response).1, 1);
    assert_eq!(flags(&response) & 0x0200, 0);
}

#[test]
fn names_labels_and_compression_loops_stay_rejected() {
    let dns = service(512);
    assert!(Zone::new(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(Zone::new(&format!("{}.example", "ab.".repeat(130))).is_err());
    let long = wire(&[b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    assert_eq!(
        dns.respond_udp(CLIENT, &query(&long, 1, false)),
        Err(DnsError::InvalidName)
    );
    // Pointer to itself: a compression loop, rejected rather than followed.
    assert_eq!(
        dns.respond_udp(CLIENT, &query(&[0xc0, 0x0c], 1, false)),
        Err(DnsError::InvalidName)
    );
    // Pointer back into the pointer: also a loop, still InvalidName.
    assert_eq!(
        dns.respond_udp(CLIENT, &query(&[0xc0, 0x0c, 0xc0, 0x0c], 1, false)),
        Err(DnsError::InvalidName)
    );
}

/// Two independent length-prefixed queries, plus one frame past the cap.
/// This exercises the DNS TCP length prefix only. It does not drive smoltcp
/// and is not a production TCP stack proof.
#[test]
fn pure_framer_answers_two_queries_and_rejects_an_oversize_frame() {
    let dns = service(512);
    let one = query(&wire(&[b"host", b"corp", b"example"]), 1, false);
    let two = query(&wire(&[b"missing", b"corp", b"example"]), 28, true);
    let mut framed = Vec::new();
    framed.extend_from_slice(&(one.len() as u16).to_be_bytes());
    framed.extend_from_slice(&one);
    framed.extend_from_slice(&(two.len() as u16).to_be_bytes());
    framed.extend_from_slice(&two);

    let mut offset = 0;
    let mut rcodes = Vec::new();
    for _ in 0..2 {
        let len = u16::from_be_bytes([framed[offset], framed[offset + 1]]) as usize;
        offset += 2;
        let response = dns
            .respond_tcp(CLIENT, &framed[offset..offset + len])
            .unwrap()
            .unwrap();
        rcodes.push(flags(&response) & 0x000f);
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(response[3] & 0x80, 0);
        offset += len;
    }
    assert_eq!(offset, framed.len());
    assert_eq!(rcodes, vec![0, 3]);

    let huge = vec![0u8; 4097];
    let mut bad = (huge.len() as u16).to_be_bytes().to_vec();
    bad.extend_from_slice(&huge);
    let declared = u16::from_be_bytes([bad[0], bad[1]]) as usize;
    assert!(declared > 4096 || bad.len() - 2 > 4096);
    assert_eq!(
        dns.respond_tcp(CLIENT, &bad[2..]),
        Err(DnsError::MessageTooLarge)
    );
}
