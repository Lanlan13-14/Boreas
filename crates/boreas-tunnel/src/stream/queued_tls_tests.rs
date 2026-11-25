use super::*;
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder},
};
use std::{
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

struct WireGate {
    tcp: TcpStream,
    limit: Arc<Mutex<usize>>,
}
impl Read for WireGate {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.tcp.read(out)
    }
}
impl Write for WireGate {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut left = self.limit.lock().unwrap();
        if *left == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = self.tcp.write(&bytes[..bytes.len().min(*left)])?;
        *left -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}
impl Duplex for WireGate {
    fn has_buffered_input(&self) -> bool {
        false
    }
    fn is_raw_socket(&self) -> bool {
        true
    }
    fn enable_progress(&mut self) -> io::Result<bool> {
        self.tcp.set_nonblocking(true)?;
        Ok(true)
    }
}
fn context() -> SslContext {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "queue-test").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_certificate(&cert.build()).unwrap();
    ctx.set_private_key(&key).unwrap();
    // This private unit fixture exercises byte scheduling, not authorization;
    // authenticated pq768 coverage remains in the WSS integration suite.
    ctx.set_verify(SslVerifyMode::NONE);
    ctx.set_num_tickets(0).unwrap();
    ctx.build()
}
fn pair() -> (QueuedTls<WireGate>, QueuedTls<WireGate>) {
    let ctx = context();
    let server_ctx = ctx.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let gate = WireGate {
            tcp,
            limit: Arc::new(Mutex::new(usize::MAX)),
        };
        QueuedTls::new(
            Ssl::new(&server_ctx)
                .unwrap()
                .accept(QueueIo::new(gate))
                .unwrap(),
        )
    });
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let gate = WireGate {
        tcp,
        limit: Arc::new(Mutex::new(usize::MAX)),
    };
    let client = QueuedTls::new(Ssl::new(&ctx).unwrap().connect(QueueIo::new(gate)).unwrap());
    (client, server.join().unwrap())
}
fn pump(a: &mut QueuedTls<WireGate>, b: &mut QueuedTls<WireGate>) {
    a.progress_io().unwrap();
    b.progress_io().unwrap();
}

#[test]
fn tls_mid_ciphertext_allows_reverse_before_tail_both_roles_and_full_record_control() {
    for reverse_roles in [false, true] {
        for split in [1, 5, 47, usize::MAX] {
            let (a, b) = pair();
            let (mut sender, mut receiver) = if reverse_roles { (b, a) } else { (a, b) };
            sender.enable_progress().unwrap();
            receiver.enable_progress().unwrap();
            *sender.transport_mut().limit.lock().unwrap() = split;
            let payload = vec![0x63; 2048];
            assert_eq!(sender.write(&payload).unwrap(), payload.len());
            let mut out = vec![0; 4096];
            let until = Instant::now() + Duration::from_secs(5);
            let incomplete = split != usize::MAX;
            pump(&mut sender, &mut receiver);
            if incomplete {
                assert_eq!(
                    receiver.read(&mut out).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let deadline = receiver.plain.as_ref().unwrap().read_deadline;
                assert!(deadline.is_some());
                assert_eq!(receiver.write(b"independent reverse").unwrap(), 19);
                loop {
                    pump(&mut receiver, &mut sender);
                    match sender.read(&mut out) {
                        Ok(n) => {
                            assert_eq!(&out[..n], b"independent reverse");
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until)
                        }
                        other => panic!("reverse failed: {other:?}"),
                    }
                }
                // The reverse was decrypted while the original record tail is
                // still physically withheld at the sender's raw socket boundary.
                assert_eq!(*sender.transport_mut().limit.lock().unwrap(), 0);
                assert_eq!(receiver.plain.as_ref().unwrap().read_deadline, deadline);
                *sender.transport_mut().limit.lock().unwrap() = usize::MAX;
            }
            loop {
                pump(&mut sender, &mut receiver);
                match receiver.read(&mut out) {
                    Ok(n) => {
                        assert_eq!(&out[..n], payload);
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < until)
                    }
                    other => panic!("tail failed: {other:?}"),
                }
            }
            assert!(receiver.plain.as_ref().unwrap().read_deadline.is_none());
            assert_eq!(
                receiver.read(&mut out).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}

#[test]
fn tls_partial_read_deadline_poison_and_idle_has_no_deadline() {
    let (mut sender, mut receiver) = pair();
    sender.enable_progress().unwrap();
    receiver.enable_progress().unwrap();
    let mut out = [0; 128];
    assert_eq!(
        receiver.read(&mut out).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(receiver.plain.as_ref().unwrap().read_deadline.is_none());
    *sender.transport_mut().limit.lock().unwrap() = 1;
    sender.write_all(b"retained").unwrap();
    pump(&mut sender, &mut receiver);
    assert_eq!(
        receiver.read(&mut out).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(receiver.plain.as_ref().unwrap().read_deadline.is_some());
    receiver.plain.as_mut().unwrap().read_deadline = Some(Instant::now());
    assert_eq!(
        receiver.progress_io().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(receiver.failed);
    assert!(receiver.write(b"forbidden").is_err());
}

#[test]
fn websocket_frame_spanning_complete_tls_records_yields_for_reverse_both_roles() {
    use crate::ws::{WsLimits, WsRole, WsStream};
    for receiver_server in [false, true] {
        let (a, b) = pair();
        let (mut sender, mut receiver) = if receiver_server { (a, b) } else { (b, a) };
        sender.enable_progress().unwrap();
        receiver.enable_progress().unwrap();
        let payload = b"cross-record-frame";
        let mut encoded = vec![
            0x82,
            payload.len() as u8 | if receiver_server { 0x80 } else { 0 },
        ];
        let mask = [1u8, 2, 3, 4];
        if receiver_server {
            encoded.extend_from_slice(&mask);
        }
        encoded.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ if receiver_server { mask[i % 4] } else { 0 }),
        );
        let split = encoded.len() - 3;
        sender.write_all(&encoded[..split]).unwrap();
        let mut ws = WsStream::new(
            receiver,
            if receiver_server {
                WsRole::Server
            } else {
                WsRole::Client
            },
            WsLimits::default(),
        );
        ws.enable_progress().unwrap();
        let mut out = [0; 128];
        let until = Instant::now() + Duration::from_secs(5);
        for _ in 0..8 {
            sender.progress_io().unwrap();
            ws.progress_io().unwrap();
        }
        assert_eq!(
            ws.read(&mut out).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        ws.write_all(b"reverse-ws").unwrap();
        let mut reverse = Vec::new();
        let reverse_len = 2 + if receiver_server { 0 } else { 4 } + 10;
        while reverse.len() < reverse_len {
            ws.progress_io().unwrap();
            sender.progress_io().unwrap();
            match sender.read(&mut out) {
                Ok(n) => reverse.extend_from_slice(&out[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => assert!(Instant::now() < until),
                other => panic!("reverse WS failed: {other:?}"),
            }
        }
        assert_eq!(reverse.len(), reverse_len);
        assert_eq!(reverse[0], 0x82);
        let masked = reverse[1] & 0x80 != 0;
        assert_eq!(masked, !receiver_server);
        assert_eq!(reverse[1] & 0x7f, 10);
        let start = if masked { 6 } else { 2 };
        let decoded: Vec<u8> = reverse[start..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ if masked { reverse[2 + i % 4] } else { 0 })
            .collect();
        assert_eq!(decoded, b"reverse-ws");
        // Tail is not produced until the independent reverse frame is exact.
        sender.write_all(&encoded[split..]).unwrap();
        loop {
            sender.progress_io().unwrap();
            ws.progress_io().unwrap();
            match ws.read(&mut out) {
                Ok(n) => {
                    assert_eq!(&out[..n], b"cross-record-frame");
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => assert!(Instant::now() < until),
                other => panic!("WS completion failed: {other:?}"),
            }
        }
    }
}
