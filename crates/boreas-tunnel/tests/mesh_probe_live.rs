#![cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]

//! Real loopback outer TLS/WSS + strict pq768 hop mTLS + signed adjacency.
//! Runs in the existing rust-tls Actions integration test suite.

use std::{
    fs,
    net::TcpListener,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use boreas_crypto::backend::PemIdentity;
use boreas_pki::{
    NetworkRootPin, NodeRole, VerifiedNetworkContext,
    management::MANAGEMENT_SCHEMA_VERSION,
    provisioning::{
        CaInitParams, NodeIssueParams, RootsBundle, SignedRootAuthorization, init_ca_dir,
        issue_node_dir, sign_network_policy_dir, sign_status_file,
    },
    root_authorization::{MAX_CHAIN_DEPTH, Purpose, RootAuthorizationCandidate, Scope},
    status_store::StatusStore,
    verify_network_policy,
};
use boreas_proto::{
    messages::{PathRole, SignedObject, SignerRole, SignerSignatures},
    objects::{
        self, CoreLsa, ManagementObject, MldsaParameterSet, Neighbor, ObjectBody, ObjectType,
        SubjectIdentity,
    },
};
use boreas_tunnel::{
    ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    mesh_probe::{Candidate, Error, MeshProbe, Selected, management_trust, utc_now},
    resource::{Admission, Limits},
};
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};

const NET: [u8; 16] = [70; 16];
const NAME: &str = "adhoc.boreas.test";

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Node {
    path: PathBuf,
    pem: PemIdentity,
    identity: Vec<u8>,
    lsa: Vec<u8>,
}

struct Fixture {
    _temp: Temp,
    nodes: Vec<Node>,
    roots: RootsBundle,
    policy: VerifiedNetworkContext,
    status: Vec<u8>,
    outer_ca: Vec<u8>,
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).expect("fixture file")
}

fn sign(key: &PKey<Private>, msg: &[u8]) -> Vec<u8> {
    Signer::new_without_digest(key)
        .unwrap()
        .sign_oneshot_to_vec(msg)
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let now = utc_now().unwrap();
        let temp = Temp(
            std::env::temp_dir().join(format!("boreas-live-probe-{}-{now}", std::process::id())),
        );
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&temp.0).unwrap();
        let ca = temp.0.join("ca");
        init_ca_dir(&ca, &CaInitParams {
            net_id: NET,
            issuer_generation: 1,
            now_us: now,
            validity_days: 1,
        })
        .unwrap();
        let policy_dir = temp.0.join("policy");
        sign_network_policy_dir(&ca, &policy_dir, 1, now, 600).unwrap();
        let mut roots = RootsBundle::decode(&read(&ca, "roots.cbor")).unwrap();
        let pin = NetworkRootPin::provisioned(
            NET,
            roots.root_ed25519_pub_der.clone(),
            MldsaParameterSet::Mldsa65,
            roots.root_mldsa65_pub_der.clone(),
        )
        .unwrap();
        let policy = verify_network_policy(
            &read(&policy_dir, "tbs.cbor"),
            &read(&policy_dir, "ed25519.sig"),
            &read(&policy_dir, "mldsa65.sig"),
            &pin,
            NET,
            now,
        )
        .unwrap()
        .require_default_runtime()
        .unwrap();
        let snapshot_path = temp.0.join("status.signed");
        sign_status_file(&ca, &snapshot_path, 1, now, 120).unwrap();
        let root_ed = PKey::private_key_from_der(&read(&ca, "root.ed25519.key")).unwrap();
        let root_ml = PKey::private_key_from_der(&read(&ca, "root.mldsa65.key")).unwrap();
        let mut nodes = Vec::new();
        for id in 1u8..=4 {
            let path = temp.0.join(format!("core-{id}"));
            issue_node_dir(&ca, &path, &NodeIssueParams {
                role: NodeRole::Core,
                home_core_id: id,
                vip_octet: 1,
                identity_generation: 1,
                now_us: now,
                validity_hours: 1,
                outer_san_dns: Some(NAME.into()),
            })
            .unwrap();
            let issuer = format!("test-core-{id}").into_bytes();
            let ed = PKey::generate_ed25519().unwrap();
            let ml = PKey::private_key_from_seed(
                None,
                openssl::pkey::KeyType::ML_DSA_65,
                None,
                &[id; 32],
            )
            .unwrap();
            let authorization = RootAuthorizationCandidate {
                net_id: NET,
                issuer_key_id: issuer.clone(),
                issuer_generation: 1,
                purpose: Purpose::CoreOperational,
                ed25519_public_key_der: ed.public_key_to_der().unwrap(),
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa_public_key_der: ml.public_key_to_der().unwrap(),
                scope: Scope::CoreOperational { core_id: id },
                not_before: now,
                expires: now + 300_000_000,
                chain_depth: MAX_CHAIN_DEPTH,
                may_delegate: false,
            };
            let raw_candidate = authorization.encode_candidate().unwrap();
            let mut msg = b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0".to_vec();
            msg.extend_from_slice(&raw_candidate);
            roots.authorizations.push(SignedRootAuthorization {
                raw_candidate,
                ed25519_signature: sign(&root_ed, &msg),
                mldsa_signature: sign(&root_ml, &msg),
            });
            let lsa = ManagementObject {
                net_id: NET,
                issuer_key_id: issuer,
                issuer_generation: 1,
                subject_identity: SubjectIdentity::Core(id),
                seq: 1,
                issued_at: now,
                expires: now + 120_000_000,
                extensions: Vec::new(),
                body: ObjectBody::CoreLsa(CoreLsa {
                    core_id: id,
                    core_generation: 1,
                    seq: 1,
                    neighbors: (1..=4)
                        .filter(|other| *other != id)
                        .map(|other| Neighbor {
                            peer_core_id: other,
                            rtt_p50_ms: u16::from(other),
                            loss_ppm: 0,
                            path_type: PathRole::Cdn as u8,
                        })
                        .collect(),
                }),
            };
            let raw_tbs = objects::encode_tbs(&lsa).unwrap();
            let message =
                objects::signature_input(&raw_tbs, ObjectType::CoreLsa, MANAGEMENT_SCHEMA_VERSION)
                    .unwrap();
            let lsa = SignedObject {
                object_type: ObjectType::CoreLsa,
                raw_tbs,
                signers: vec![SignerSignatures {
                    role: SignerRole::Primary,
                    ed25519: sign(&ed, &message).try_into().unwrap(),
                    mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                    mldsa: sign(&ml, &message),
                }],
            }
            .encode()
            .unwrap();
            let pem = PemIdentity::from_pem_files(
                path.join("identity.pem"),
                path.join("identity.key"),
                path.join("identity-ca.pem"),
            )
            .unwrap();
            let identity = read(&path, "local.signed");
            nodes.push(Node {
                path,
                pem,
                identity,
                lsa,
            });
        }
        Self {
            _temp: temp,
            roots,
            policy,
            nodes,
            status: fs::read(snapshot_path).unwrap(),
            outer_ca: read(&ca, "outer-ca.pem"),
        }
    }

    fn node(&self, id: usize) -> &Node {
        &self.nodes[id - 1]
    }

    fn status(&self, id: usize) -> StatusStore {
        let path = &self.node(id).path;
        let now = utc_now().unwrap();
        let trust = management_trust(&self.roots, &self.policy, now).unwrap();
        let mut store = StatusStore::open(
            path.join("status.state"),
            NET,
            fs::metadata(path).unwrap().uid(),
            trust,
        )
        .unwrap();
        store
            .accept_signed_snapshot(&self.status, now, Instant::now())
            .unwrap();
        store
    }

    fn probe<'a>(&'a self, id: usize, status: &'a mut StatusStore) -> MeshProbe<'a> {
        let n = self.node(id);
        MeshProbe::new(
            self.policy,
            &self.roots,
            status,
            &n.pem,
            &n.identity,
            &n.lsa,
        )
        .unwrap()
    }

    fn respond(&self, listener: TcpListener, id: usize) -> Result<Selected, Error> {
        let n = self.node(id);
        let outer = OpenSslOuterTlsAcceptor::from_pem_files(
            n.path.join("outer.pem"),
            n.path.join("outer.key"),
        )
        .unwrap();
        let mut status = self.status(id);
        let mut probe = self.probe(id, &mut status);
        let admission = Admission::new(Limits {
            handshakes_global: 1,
            authenticated_global: 1,
            authenticated_per_peer: 1,
            bytes_global: 1024 * 1024,
        });
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("loopback accept: {e}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        probe.respond(socket, &self.node(1).identity, &outer, &admission)
    }
}

fn listener() -> (TcpListener, ClientTarget) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = ClientTarget {
        address: listener.local_addr().unwrap(),
        ws_host: NAME.into(),
        tls_server_name: NAME.into(),
        path: "/tunnel".into(),
    };
    (listener, target)
}

#[test]
fn strict_pq768_signed_adjacency_only_falls_back_before_authentication() {
    let f = Fixture::new();
    let mut status = f.status(1);
    let mut probe = f.probe(1, &mut status);
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let (refusing, unavailable) = listener();
    // Allocate the second address before closing the first listener, so these
    // two candidates cannot alias even if the OS quickly recycles ports.
    let (server, preferred_backup) = listener();
    drop(refusing);
    thread::scope(|scope| {
        let responder = scope.spawn(|| f.respond(server, 3));
        let result = probe
            .select(
                &[
                    Candidate {
                        target: &preferred_backup,
                        signed_identity: &f.node(3).identity,
                    },
                    Candidate {
                        target: &unavailable,
                        signed_identity: &f.node(2).identity,
                    },
                ],
                &outer,
            )
            .unwrap();
        assert_eq!(result.core_id, 3);
        assert_eq!(result.attempts, 2);
        assert_eq!(result.signed_lsa, f.node(3).lsa);
        let reply = responder.join().unwrap().unwrap();
        assert_eq!(reply.core_id, 1);
        assert_eq!(reply.signed_lsa, f.node(1).lsa);
    });

    // A certificate for Core 3 is valid under the same certificate CA and the
    // correct outer SAN, but is not the signed SPKI expected for Core 2.
    let (wrong, wrong_locator) = listener();
    let (unused, unused_locator) = listener();
    unused.set_nonblocking(true).unwrap();
    thread::scope(|scope| {
        let responder = scope.spawn(|| f.respond(wrong, 3));
        let result = probe.select(
            &[
                Candidate {
                    target: &wrong_locator,
                    signed_identity: &f.node(2).identity,
                },
                Candidate {
                    target: &unused_locator,
                    signed_identity: &f.node(3).identity,
                },
            ],
            &outer,
        );
        assert_eq!(
            result,
            Err(Error::Transport(TunnelError::InnerTls(
                "peer identity mapping"
            )))
        );
        assert!(responder.join().unwrap().is_err());
        assert!(matches!(unused.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    });
}

fn accept_socket(listener: TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                return socket;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(e) => panic!("loopback accept: {e}"),
        }
    }
}

fn fixed_exchange(f: &Fixture, ids: &[usize], cut_path: bool) -> Result<[u8; 16], Error> {
    use boreas_tunnel::mesh_relay::{forward_fixed, with_fixed_endpoint};
    use std::io::{Read, Write};
    let envelopes: Vec<&[u8]> = ids
        .iter()
        .map(|id| f.node(*id).identity.as_slice())
        .collect();
    let mut sockets: Vec<_> = (1..ids.len()).map(|_| listener()).collect();
    let destinations: Vec<_> = sockets.iter().map(|(_, target)| target.clone()).collect();
    let marker = if cut_path { 0x55 } else { ids.len() as u8 };
    let payload = (0..100_000u32)
        .map(|i| ((i.wrapping_mul(43) >> 7) as u8) ^ marker)
        .collect::<Vec<_>>();
    let response = *b"authenticated endpoint response";
    let outer_client = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let envelopes = &envelopes;
    let destinations = &destinations;
    let payload = &payload;
    let outer_client = &outer_client;
    thread::scope(|scope| {
        let mut relays = Vec::new();
        let mut endpoints = Vec::new();
        for (index, (socket, _)) in sockets.drain(..).enumerate() {
            let pos = index + 1;
            let id = ids[pos];
            let path = &f.node(id).path;
            let setup = move || -> Result<_, Error> {
                let mut status = f.status(id);
                let mut probe = f.probe(id, &mut status);
                let route = probe.authorize_fixed_route(envelopes)?;
                let outer = OpenSslOuterTlsAcceptor::from_pem_files(
                    path.join("outer.pem"),
                    path.join("outer.key"),
                )?;
                let accepted = accept_socket(socket);
                let fault = accepted.try_clone().map_err(TunnelError::from)?;
                let admission = Admission::new(Limits {
                    handshakes_global: 1,
                    authenticated_global: 2,
                    authenticated_per_peer: 1,
                    bytes_global: 1024 * 1024,
                });
                let left =
                    probe.accept(accepted, &f.node(ids[pos - 1]).identity, &outer, &admission)?;
                if pos + 1 == ids.len() {
                    let mut seen = None;
                    let result = with_fixed_endpoint(&mut probe, &route, left, |c| {
                        seen = Some(c.circuit_id());
                        let mut received = vec![0; payload.len()];
                        c.read_exact(&mut received)?;
                        assert_eq!(received, *payload);
                        if cut_path {
                            fault.shutdown(std::net::Shutdown::Both)?;
                        } else {
                            c.write_all(&response)?;
                        }
                        Ok(c.circuit_id())
                    });
                    if cut_path {
                        assert!(result.is_err());
                        return Ok((seen.expect("confirmed before fault"), None));
                    }
                    Ok((result?, None))
                } else {
                    let right = probe.dial(
                        &[Candidate {
                            target: &destinations[pos],
                            signed_identity: &f.node(ids[pos + 1]).identity,
                        }],
                        outer_client,
                        &admission,
                    )?;
                    assert_eq!(admission.snapshot().unwrap().authenticated, 2);
                    let forwarded = forward_fixed(&mut probe, &route, left, right, &admission);
                    let credits = admission.snapshot().unwrap();
                    assert_eq!(
                        (credits.handshakes, credits.authenticated, credits.bytes),
                        (0, 0, 0)
                    );
                    let forwarded = forwarded?;
                    Ok((forwarded.circuit_id, Some(forwarded.ciphertext_bytes)))
                }
            };
            if pos + 1 == ids.len() {
                endpoints.push(scope.spawn(setup));
            } else {
                relays.push(scope.spawn(setup));
            }
        }
        let mut status = f.status(ids[0]);
        let mut probe = f.probe(ids[0], &mut status);
        let route = probe.authorize_fixed_route(envelopes)?;
        let hop = probe.dial(
            &[Candidate {
                target: &destinations[0],
                signed_identity: &f.node(ids[1]).identity,
            }],
            outer_client,
            &Admission::new(Limits {
                handshakes_global: 1,
                authenticated_global: 1,
                authenticated_per_peer: 1,
                bytes_global: 1024 * 1024,
            }),
        )?;
        let mut lost_id = None;
        let result = with_fixed_endpoint(&mut probe, &route, hop, |c| {
            lost_id = Some(c.circuit_id());
            c.write_all(payload)?;
            let mut reply = [0; 31];
            c.read_exact(&mut reply)?;
            assert_eq!(reply, response);
            Ok(c.circuit_id())
        });
        let received = endpoints.pop().unwrap().join().unwrap()?;
        if cut_path {
            assert!(
                result.is_err(),
                "the endpoint must not accept a partial exchange"
            );
            assert_eq!(lost_id, Some(received.0));
            for relay in relays {
                assert!(relay.join().unwrap().is_err());
            }
            return Ok(received.0);
        }
        let id = result?;
        assert_eq!(id, received.0);
        for relay in relays {
            let (seen, bytes) = relay.join().unwrap()?;
            assert_eq!(id, seen);
            let bytes = bytes.unwrap();
            assert!(bytes[0] > payload.len() as u64 && bytes[1] > response.len() as u64);
        }
        Ok(id)
    })
}

#[test]
fn signed_fixed_route_transfers_bidirectional_e2e_and_rebuilds_after_path_loss() {
    let f = Fixture::new();
    // The first route transfers through two distinct relays, then loses its
    // last link after confirmed application bytes but before the reply.
    let lost = fixed_exchange(&f, &[1, 2, 3, 4], true).unwrap();
    // Explicitly reauthorize a shorter alternate path. The endpoints and
    // their generations are unchanged: links, circuit and TLS are all new.
    let replacement = fixed_exchange(&f, &[1, 3, 4], false).unwrap();
    assert_ne!(lost, replacement);
    let through_two = fixed_exchange(&f, &[1, 2, 3, 4], false).unwrap();
    assert_ne!(through_two, replacement);
}
