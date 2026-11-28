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
    status_store::{AuthenticatedPeer, IDENTITY_REVOCATION_MAGIC, StatusStore},
    verify_network_policy,
};
use boreas_proto::{
    authority_revocation::{AuthorityRevocation, RevocationClass, RevocationScope},
    messages::{PathRole, SignedObject, SignerRole, SignerSignatures},
    objects::{
        self, CoreLsa, ManagementObject, MldsaParameterSet, Neighbor, ObjectBody, ObjectType,
        SubjectIdentity,
    },
};
use boreas_tunnel::{
    ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    mesh_probe::{Candidate, Error, MeshProbe, Selected, mesh_trust, utc_now},
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
    lsa_ed: PKey<Private>,
    lsa_ml: PKey<Private>,
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
        use std::{
            os::unix::fs::DirBuilderExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "boreas-live-probe-{}-{now}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let temp = Temp(path);
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
                outer_ca_issued: false,
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
                            rtt_p50_ms: match (id.min(other), id.max(other)) {
                                (1, 3) => 20,
                                (2, 4) => 30,
                                _ => u16::from(other),
                            },
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
                lsa_ed: ed,
                lsa_ml: ml,
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
        self.named_status(id, "status.state")
    }

    fn named_status(&self, id: usize, name: &str) -> StatusStore {
        let path = &self.node(id).path;
        let now = utc_now().unwrap();
        let (trust, identity_trust) = mesh_trust(&self.roots, &self.policy, now).unwrap();
        let mut store = StatusStore::open_with_identity_revocations(
            path.join(name),
            NET,
            fs::metadata(path).unwrap().uid(),
            trust,
            self.policy.root_key_fingerprint(),
            identity_trust,
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

fn graph_inputs(f: &Fixture, local: usize) -> Vec<boreas_tunnel::mesh_route::SignedCore<'_>> {
    (1..=4)
        .filter(|id| *id != local)
        .map(|id| boreas_tunnel::mesh_route::SignedCore {
            identity: &f.node(id).identity,
            lsa: &f.node(id).lsa,
        })
        .collect()
}

fn route_admission() -> Admission {
    Admission::new(Limits {
        handshakes_global: 1,
        authenticated_global: 2,
        authenticated_per_peer: 1,
        bytes_global: 1024 * 1024,
    })
}

fn outer_for(f: &Fixture, id: usize) -> OpenSslOuterTlsAcceptor {
    let path = &f.node(id).path;
    OpenSslOuterTlsAcceptor::from_pem_files(path.join("outer.pem"), path.join("outer.key")).unwrap()
}

#[test]
fn verified_graph_automatically_rebuilds_confirmed_circuit_after_link_cut() {
    use boreas_tunnel::mesh_route::RouteLocator;
    use std::{
        io::{Read, Write},
        net::Shutdown,
        sync::mpsc,
    };

    let f = &Fixture::new();
    const PRIMARY: &[u8] = &[1, 2, 3, 4];
    const BACKUP: &[u8] = &[1, 3, 4];
    let (p2, p2_target) = listener();
    let (p3, p3_target) = listener();
    let (p4, p4_target) = listener();
    let (b3, b3_target) = listener();
    let (b4, b4_target) = listener();
    let outer = &|| OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let payload: Vec<u8> = (0..70_000u32)
        .map(|n| (n.wrapping_mul(43) >> 7) as u8)
        .collect();
    let payload = &payload;
    let (ids_tx, ids_rx) = mpsc::channel();
    thread::scope(|scope| {
        let spawn_relay =
            |listener, id, path: &'static [u8], target: ClientTarget, state: &'static str| {
                scope.spawn(move || {
                    let mut status = f.named_status(id, state);
                    let mut probe = f.probe(id, &mut status);
                    let graph =
                        probe.verify_route_graph(&f.node(id).identity, &graph_inputs(f, id))?;
                    graph.relay(
                        &mut probe,
                        path,
                        accept_socket(listener),
                        &target,
                        (&outer_for(f, id), outer),
                        &route_admission(),
                    )
                })
            };
        let primary2 = spawn_relay(p2, 2, PRIMARY, p3_target, "primary.state");
        let primary3 = spawn_relay(p3, 3, PRIMARY, p4_target, "primary.state");
        let backup3 = spawn_relay(b3, 3, BACKUP, b4_target, "backup.state");
        let spawn_destination = |listener,
                                 path: &'static [u8],
                                 state: &'static str,
                                 cut: bool,
                                 tx: mpsc::Sender<[u8; 16]>| {
            scope.spawn(move || -> Result<_, Error> {
                let mut status = f.named_status(4, state);
                let mut probe = f.probe(4, &mut status);
                let graph = probe.verify_route_graph(&f.node(4).identity, &graph_inputs(f, 4))?;
                let accepted = accept_socket(listener);
                let fault = accepted.try_clone().map_err(TunnelError::from)?;
                graph.respond(
                    &mut probe,
                    path,
                    accepted,
                    &outer_for(f, 4),
                    &route_admission(),
                    |c| {
                        let mut observed = vec![0; payload.len()];
                        c.read_exact(&mut observed)?;
                        if cut {
                            assert_eq!(&observed, payload);
                        } else {
                            assert!(observed.iter().zip(payload).all(|(a, b)| *a == !*b));
                        }
                        tx.send(c.circuit_id()).unwrap();
                        if cut {
                            fault.shutdown(Shutdown::Both)?;
                            return Err(TunnelError::Closed);
                        }
                        c.write_all(b"second circuit")?;
                        Ok(c.circuit_id())
                    },
                )
            })
        };
        let primary4 = spawn_destination(p4, PRIMARY, "primary.state", true, ids_tx.clone());
        let backup4 = spawn_destination(b4, BACKUP, "backup.state", false, ids_tx);

        let mut status = f.status(1);
        let mut probe = f.probe(1, &mut status);
        let graph = probe
            .verify_route_graph(&f.node(1).identity, &graph_inputs(f, 1))
            .unwrap();
        let admission = route_admission();
        let mut seen = Vec::new();
        let result = graph
            .connect(
                &mut probe,
                &[
                    RouteLocator {
                        path: BACKUP,
                        target: &b3_target,
                    },
                    RouteLocator {
                        path: PRIMARY,
                        target: &p2_target,
                    },
                ],
                outer,
                &admission,
                |path, c| {
                    seen.push((path.to_vec(), c.circuit_id()));
                    if path == PRIMARY {
                        c.write_all(payload)?;
                    } else {
                        // Explicitly different, independent operation. The transport
                        // must not replay the first path's already consumed bytes.
                        c.write_all(&payload.iter().map(|b| !*b).collect::<Vec<_>>())?;
                    }
                    let mut reply = [0; 14];
                    c.read_exact(&mut reply)?;
                    assert_eq!(&reply, b"second circuit");
                    Ok(c.circuit_id())
                },
            )
            .unwrap();
        assert_eq!(seen.iter().map(|p| p.0.as_slice()).collect::<Vec<_>>(), [
            PRIMARY, BACKUP
        ]);
        assert_ne!(seen[0].1, result);
        assert_eq!(ids_rx.try_recv().unwrap(), seen[0].1);
        assert_eq!(ids_rx.try_recv().unwrap(), result);
        assert!(primary2.join().unwrap().is_err());
        assert!(primary3.join().unwrap().is_err());
        assert_eq!(
            primary4.join().unwrap(),
            Err(Error::Transport(TunnelError::Closed))
        );
        assert_eq!(backup4.join().unwrap().unwrap(), result);
        let forwarded = backup3.join().unwrap().unwrap();
        assert_eq!(forwarded.circuit_id, result);
        assert!(forwarded.ciphertext_bytes[0] > payload.len() as u64);
        assert!(forwarded.ciphertext_bytes[1] > 14);
        let snap = admission.snapshot().unwrap();
        assert_eq!((snap.handshakes, snap.authenticated, snap.bytes), (0, 0, 0));
    });
}

fn change_lsa(node: &Node, edit: impl FnOnce(&mut ManagementObject)) -> Vec<u8> {
    let mut envelope = SignedObject::decode(&node.lsa).unwrap();
    let mut object = objects::decode_tbs(&envelope.raw_tbs).unwrap();
    edit(&mut object);
    envelope.raw_tbs = objects::encode_tbs(&object).unwrap();
    let msg = objects::signature_input(
        &envelope.raw_tbs,
        ObjectType::CoreLsa,
        MANAGEMENT_SCHEMA_VERSION,
    )
    .unwrap();
    envelope.signers[0].ed25519 = sign(&node.lsa_ed, &msg).try_into().unwrap();
    envelope.signers[0].mldsa = sign(&node.lsa_ml, &msg);
    envelope.encode().unwrap()
}

#[test]
fn graph_rejects_forgery_and_does_not_use_withdrawn_or_superseded_edges() {
    let f = Fixture::new();
    let mut status = f.status(1);
    let mut probe = f.probe(1, &mut status);
    let initial = probe
        .verify_route_graph(&f.node(1).identity, &graph_inputs(&f, 1))
        .unwrap();
    initial.authorize_path(&mut probe, &[1, 2, 4]).unwrap();
    let mut inputs = graph_inputs(&f, 1);
    let mut forged = SignedObject::decode(&f.node(2).lsa).unwrap();
    forged.signers[0].ed25519[0] ^= 1;
    let forged = forged.encode().unwrap();
    inputs[0].lsa = &forged;
    assert!(matches!(
        probe.verify_route_graph(&f.node(1).identity, &inputs),
        Err(Error::Lsa)
    ));

    let withdrawn = change_lsa(f.node(2), |obj| {
        obj.seq = 2;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = 2;
        lsa.neighbors.retain(|n| n.peer_core_id != 4);
    });
    inputs[0].lsa = &withdrawn;
    let graph = probe
        .verify_route_graph(&f.node(1).identity, &inputs)
        .unwrap();
    assert!(matches!(
        initial.authorize_path(&mut probe, &[1, 2, 4]),
        Err(Error::Lsa)
    ));
    assert!(matches!(
        graph.authorize_path(&mut probe, &[1, 2, 4]),
        Err(Error::NoRoute)
    ));
    graph.authorize_path(&mut probe, &[1, 3, 4]).unwrap();
    assert!(matches!(
        probe.verify_route_graph(&f.node(1).identity, &graph_inputs(&f, 1)),
        Err(Error::Lsa)
    ));

    let fork = change_lsa(f.node(2), |obj| {
        obj.seq = 2;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = 2;
        lsa.neighbors[0].rtt_p50_ms += 1;
    });
    inputs[0].lsa = &fork;
    assert!(matches!(
        probe.verify_route_graph(&f.node(1).identity, &inputs),
        Err(Error::Lsa)
    ));
    assert!(matches!(
        graph.authorize_path(&mut probe, &[1, 2, 3, 4]),
        Err(Error::Lsa)
    ));
}

#[test]
fn authenticated_hop_refreshes_directory_without_using_the_old_graph() {
    use boreas_tunnel::mesh_route::{DirectoryCore, RouteLocator};

    let f = Fixture::new();
    let mut status = f.status(1);
    let mut probe = f.probe(1, &mut status);
    let original = graph_inputs(&f, 1);
    let mut seeds: Vec<_> = original
        .iter()
        .map(|raw| DirectoryCore {
            identity: raw.identity,
            seed_lsa: Some(raw.lsa),
        })
        .collect();
    let local = &f.node(1).identity;
    let old = probe.verify_directory_graph(local, &seeds).unwrap();
    let update = change_lsa(f.node(2), |obj| {
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        // Same sequence in a higher generation is a new version, not a fork.
        lsa.core_generation = 2;
        lsa.neighbors.retain(|n| n.peer_core_id != 4);
    });
    let (server, target) = listener();
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let primary = [1, 2, 4];
    thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let mut status = f.status(2);
            let mut probe = f.probe(2, &mut status);
            probe
                .refresh_runtime_authority(&f.status, None, &update)
                .unwrap();
            probe.respond(
                accept_socket(server),
                local,
                &outer_for(&f, 2),
                &route_admission(),
            )
        });
        assert_eq!(
            old.connect(
                &mut probe,
                &[RouteLocator {
                    path: &primary,
                    target: &target
                }],
                &outer,
                &route_admission(),
                |_, _| -> Result<(), TunnelError> {
                    panic!("a superseded graph must not enter business I/O")
                }
            ),
            Err(Error::TopologyChanged)
        );
        peer.join().unwrap().unwrap();
    });
    assert!(matches!(
        old.authorize_path(&mut probe, &primary),
        Err(Error::Lsa)
    ));
    for seed in [Some(f.node(2).lsa.as_slice()), None] {
        seeds[0].seed_lsa = seed;
        let graph = probe.verify_directory_graph(local, &seeds).unwrap();
        assert!(matches!(
            graph.authorize_path(&mut probe, &primary),
            Err(Error::NoRoute)
        ));
        graph.authorize_path(&mut probe, &[1, 3, 4]).unwrap();
    }
    // A wrongly filed, valid third-party LSA must not mutate its own slot.
    let foreign = change_lsa(f.node(3), |obj| {
        obj.seq = 2;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = 2;
    });
    seeds[0].seed_lsa = Some(&foreign);
    assert!(matches!(
        probe.verify_directory_graph(local, &seeds),
        Err(Error::Lsa)
    ));
    seeds[0].seed_lsa = None;
    assert!(probe.verify_directory_graph(local, &seeds).is_ok());
}

#[test]
fn verified_graph_does_not_fallback_after_wrong_first_hop_spki() {
    use boreas_tunnel::mesh_route::RouteLocator;

    let f = &Fixture::new();
    let (wrong, wrong_target) = listener();
    let (unused, unused_target) = listener();
    unused.set_nonblocking(true).unwrap();
    let mut status = f.status(1);
    let mut probe = f.probe(1, &mut status);
    let graph = probe
        .verify_route_graph(&f.node(1).identity, &graph_inputs(f, 1))
        .unwrap();
    thread::scope(|scope| {
        let responder = scope.spawn(|| f.respond(wrong, 3));
        let result: Result<(), _> = graph.connect(
            &mut probe,
            &[
                RouteLocator {
                    path: &[1, 3, 4],
                    target: &unused_target,
                },
                RouteLocator {
                    path: &[1, 2, 3, 4],
                    target: &wrong_target,
                },
            ],
            &|| OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca),
            &route_admission(),
            |_, _| panic!("unauthorized peer must not reach the application"),
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

fn identity_evidence(f: &Fixture, subject: AuthenticatedPeer, authority: bool) -> Vec<u8> {
    let ca = f._temp.0.join("ca");
    let (name, issuer): (&str, &[u8]) = if authority {
        ("ia", b"identity-authority-v1")
    } else {
        ("status", b"status-signer-v1")
    };
    let now = utc_now().unwrap();
    let tbs = AuthorityRevocation {
        net_id: subject.net_id(),
        class: RevocationClass::Identity,
        subject_node_id: subject.node_id(),
        identity_generation: subject.identity_generation(),
        issuer_key_id: issuer.to_vec(),
        issuer_generation: 1,
        scope: RevocationScope::default(),
        seq: 1,
        issued_at: now,
        next_update: now + 60_000_000,
    }
    .encode_tbs()
    .unwrap();
    let input = AuthorityRevocation::signature_input(&tbs).unwrap();
    let mut evidence = IDENTITY_REVOCATION_MAGIC.to_vec();
    for algorithm in ["ed25519", "mldsa65"] {
        let key =
            PKey::private_key_from_der(&read(&ca, &format!("{name}.{algorithm}.key"))).unwrap();
        evidence.extend_from_slice(&sign(&key, &input));
    }
    evidence.extend_from_slice(&tbs);
    evidence
}

#[test]
fn original_identity_revocation_is_relayed_between_distinct_cores_and_invalidates_fixed_route() {
    use boreas_tunnel::mesh_relay::with_fixed_endpoint;

    let f = Fixture::new();
    // The subject isn't either participant in either 1→2 or 2→3 exchange.
    let subject = AuthenticatedPeer::new(NET, 0x0301, 1).unwrap();
    let successor = AuthenticatedPeer::new(NET, 0x0301, 2).unwrap();
    let evidence = identity_evidence(&f, subject, true);
    let wrong_authority = identity_evidence(&f, subject, false);
    let mut sender = f.status(1);
    assert!(
        sender
            .accept_identity_revocation(&wrong_authority, utc_now().unwrap())
            .is_err()
    );
    assert!(!sender.identity_revoked(&subject).unwrap());
    sender
        .accept_identity_revocation(&evidence, utc_now().unwrap())
        .unwrap();
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let (listener12, target12) = listener();
    thread::scope(|scope| {
        let acceptor = scope.spawn(|| f.respond(listener12, 2));
        f.probe(1, &mut sender)
            .select(
                &[Candidate {
                    target: &target12,
                    signed_identity: &f.node(2).identity,
                }],
                &outer,
            )
            .unwrap();
        acceptor.join().unwrap().unwrap();
    });

    // Reopen Core 2's independent store before forwarding what it received.
    let mut sender2 = f.status(2);
    assert!(sender2.identity_revoked(&subject).unwrap());
    assert!(!sender2.identity_revoked(&successor).unwrap());
    assert_eq!(
        sender2
            .relayable_identity_revocations(utc_now().unwrap())
            .unwrap(),
        vec![evidence.as_slice()]
    );
    let mut receiver = f.status(3);
    assert!(!receiver.identity_revoked(&subject).unwrap());
    let status_cutoff = receiver
        .current_fresh(utc_now().unwrap(), Instant::now())
        .unwrap()
        .deadline();
    let (listener32, target32) = listener();
    let mut probe = f.probe(3, &mut receiver);
    let route_members = [3, 2, 4].map(|id| f.node(id).identity.as_slice());
    let preauthorized = probe.authorize_fixed_route(&route_members).unwrap();
    let admission = Admission::new(Limits {
        handshakes_global: 1,
        authenticated_global: 1,
        authenticated_per_peer: 1,
        bytes_global: 1024 * 1024,
    });
    thread::scope(|scope| {
        let f = &f;
        let acceptor = scope.spawn(move || {
            let mut probe2 = f.probe(2, &mut sender2);
            let n = f.node(2);
            let outer = OpenSslOuterTlsAcceptor::from_pem_files(
                n.path.join("outer.pem"),
                n.path.join("outer.key"),
            )
            .unwrap();
            probe2.respond(
                accept_socket(listener32),
                &f.node(3).identity,
                &outer,
                &Admission::new(Limits {
                    handshakes_global: 1,
                    authenticated_global: 1,
                    authenticated_per_peer: 1,
                    bytes_global: 1024 * 1024,
                }),
            )
        });
        let hop = probe
            .dial(
                &[Candidate {
                    target: &target32,
                    signed_identity: &f.node(2).identity,
                }],
                &outer,
                &admission,
            )
            .unwrap();
        assert_eq!(admission.snapshot().unwrap().authenticated, 1);
        assert!(matches!(
            probe.authorize_fixed_route(&route_members),
            Err(Error::IdentityRevoked)
        ));
        assert_eq!(
            with_fixed_endpoint::<()>(&mut probe, &preauthorized, hop, |_| {
                panic!("revoked route admitted to business")
            }),
            Err(Error::IdentityRevoked)
        );
        let credits = admission.snapshot().unwrap();
        assert_eq!(
            (credits.handshakes, credits.authenticated, credits.bytes),
            (0, 0, 0)
        );
        let unaffected_route = [1, 2, 3].map(|id| f.node(id).identity.as_slice());
        assert!(probe.authorize_fixed_route(&unaffected_route).is_ok());
        acceptor.join().unwrap().unwrap();
    });
    drop(probe);
    assert_eq!(receiver.sequence(), Some(1));
    assert!(
        receiver
            .current_fresh(utc_now().unwrap(), Instant::now())
            .unwrap()
            .deadline()
            <= status_cutoff
    );
    drop(receiver);
    let mut receiver = f.status(3);
    assert!(receiver.identity_revoked(&subject).unwrap());
    assert!(!receiver.identity_revoked(&successor).unwrap());
    assert_eq!(
        receiver
            .relayable_identity_revocations(utc_now().unwrap())
            .unwrap(),
        vec![evidence.as_slice()]
    );
}

#[test]
fn live_relay_denial_interrupts_idle_e2e_and_releases_both_hops() {
    use boreas_tunnel::mesh_route::RouteLocator;
    use std::{io::Read, sync::mpsc};

    let f = &Fixture::new();
    let (relay_listener, relay_target) = listener();
    let (destination_listener, destination_target) = listener();
    let outer = &|| OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let path = &[1, 2, 4];
    let mailbox = f.node(2).path.join("identity-revocation.signed");
    let subject = AuthenticatedPeer::new(NET, 0x0301, 1).unwrap();
    let evidence = identity_evidence(f, subject, true);
    // The owner under test is Core 2. A revoked participant need not cooperate
    // in closing the sockets: Core 1 and Core 4 both block on a real TLS read.
    let relay_credits = route_admission();
    let (src_ready, src_confirmed) = mpsc::channel();
    let (dst_ready, dst_confirmed) = mpsc::channel();
    thread::scope(|scope| {
        let relay = scope.spawn(|| {
            let mut store = f.status(2);
            let mut probe = f.probe(2, &mut store);
            probe.set_identity_revocation_mailbox(|| match fs::read(&mailbox) {
                Ok(raw) => Ok(Some(raw)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            });
            let graph = probe.verify_route_graph(&f.node(2).identity, &graph_inputs(f, 2))?;
            graph.relay(
                &mut probe,
                path,
                accept_socket(relay_listener),
                &destination_target,
                (&outer_for(f, 2), outer),
                &relay_credits,
            )
        });
        let destination = scope.spawn(|| {
            let mut store = f.status(4);
            let mut probe = f.probe(4, &mut store);
            let graph = probe.verify_route_graph(&f.node(4).identity, &graph_inputs(f, 4))?;
            graph.respond(
                &mut probe,
                path,
                accept_socket(destination_listener),
                &outer_for(f, 4),
                &route_admission(),
                |c| {
                    dst_ready.send(c.circuit_id()).unwrap();
                    c.read_exact(&mut [0; 1]).map_err(TunnelError::from)
                },
            )
        });
        let source = scope.spawn(|| {
            let mut store = f.status(1);
            let mut probe = f.probe(1, &mut store);
            let graph = probe.verify_route_graph(&f.node(1).identity, &graph_inputs(f, 1))?;
            graph.connect(
                &mut probe,
                &[RouteLocator {
                    path,
                    target: &relay_target,
                }],
                outer,
                &route_admission(),
                |_, c| {
                    src_ready.send(c.circuit_id()).unwrap();
                    c.read_exact(&mut [0; 1]).map_err(TunnelError::from)
                },
            )
        });
        let wait = Duration::from_secs(5);
        let id = src_confirmed.recv_timeout(wait).unwrap();
        assert_eq!(id, dst_confirmed.recv_timeout(wait).unwrap());
        assert_eq!(relay_credits.snapshot().unwrap().authenticated, 2);
        let published = Instant::now();
        let stage = mailbox.with_extension("staging");
        fs::write(&stage, &evidence).unwrap();
        fs::rename(stage, &mailbox).unwrap();
        assert!(matches!(relay.join().unwrap(), Err(Error::IdentityRevoked)));
        assert!(source.join().unwrap().is_err());
        assert!(destination.join().unwrap().is_err());
        assert!(published.elapsed() < Duration::from_secs(2));
    });
    let snap = relay_credits.snapshot().unwrap();
    assert_eq!((snap.handshakes, snap.authenticated, snap.bytes), (0, 0, 0));
    fs::remove_file(&mailbox).unwrap();
    let reopened = f.status(2);
    assert!(reopened.identity_revoked(&subject).unwrap());
    assert!(
        !reopened
            .identity_revoked(&AuthenticatedPeer::new(NET, 0x0301, 2).unwrap())
            .unwrap()
    );
}

#[test]
fn live_directory_propagates_remote_denial_after_graph_isolation() {
    use boreas_tunnel::mesh_route::DirectoryCore;

    let f = &Fixture::new();
    let subject = AuthenticatedPeer::new(NET, 0x0301, 1).unwrap();
    let evidence = identity_evidence(f, subject, true);
    let wrong_authority = identity_evidence(f, subject, false);
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let members = |id| {
        [1, 2, 3, 4]
            .into_iter()
            .filter(|&other| other != id)
            .map(|other| f.node(other).identity.as_slice())
            .collect::<Vec<_>>()
    };
    let mut a_status = f.status(1);
    let mut b_status = f.status(2);
    let mut c_status = f.status(3);
    assert!(!a_status.identity_revoked(&subject).unwrap());
    assert!(!b_status.identity_revoked(&subject).unwrap());
    assert!(!c_status.identity_revoked(&subject).unwrap());
    let mut a = f.probe(1, &mut a_status);
    let mut b = f.probe(2, &mut b_status);
    let mut c = f.probe(3, &mut c_status);
    let graph = |probe: &mut MeshProbe<'_>, id| {
        let others = [1, 2, 3, 4]
            .into_iter()
            .filter(|&other| other != id)
            .map(|other| DirectoryCore {
                identity: &f.node(other).identity,
                seed_lsa: Some(&f.node(other).lsa),
            })
            .collect::<Vec<_>>();
        probe
            .verify_directory_graph(&f.node(id).identity, &others)
            .unwrap()
    };
    let a_before = graph(&mut a, 1);
    assert!(a_before.authorize_path(&mut a, &[1, 4, 3]).is_ok());
    graph(&mut b, 2);
    graph(&mut c, 3);
    assert_eq!(
        a.refresh_runtime_authority(&f.status, Some(&wrong_authority), &f.node(1).lsa),
        Err(Error::Status)
    );
    assert!(a_before.authorize_path(&mut a, &[1, 4, 3]).is_ok());
    a.refresh_runtime_authority(&f.status, Some(&evidence), &f.node(1).lsa)
        .unwrap();
    let a_after = graph(&mut a, 1);
    assert!(a_after.core_ids().eq(1..=4));
    assert_eq!(a_after.signed_lsa(4), None);
    assert!(matches!(
        a_before.authorize_path(&mut a, &[1, 4, 3]),
        Err(Error::IdentityRevoked)
    ));
    assert!(matches!(
        a_after.authorize_path(&mut a, &[1, 4, 3]),
        Err(Error::IdentityRevoked)
    ));
    assert!(a_after.authorize_path(&mut a, &[1, 2, 3]).is_ok());

    let sync = |from: &mut MeshProbe<'_>, to: &mut MeshProbe<'_>, src, dst| {
        let (socket, target) = listener();
        let (dial_credits, listen_credits) = (route_admission(), route_admission());
        thread::scope(|scope| {
            let received = scope.spawn(|| {
                to.accept_directory_member(
                    accept_socket(socket),
                    &members(dst),
                    &outer_for(f, dst),
                    &listen_credits,
                )
            });
            assert_eq!(
                from.sync_directory(
                    Candidate {
                        target: &target,
                        signed_identity: &f.node(dst).identity,
                    },
                    &members(src),
                    &outer,
                    &dial_credits
                ),
                Ok(())
            );
            assert_eq!(received.join().unwrap(), Ok(src as u8));
        });
        for credits in [&dial_credits, &listen_credits] {
            let snap = credits.snapshot().unwrap();
            assert_eq!((snap.handshakes, snap.authenticated, snap.bytes), (0, 0, 0));
        }
    };
    sync(&mut a, &mut b, 1, 2);
    assert_eq!(graph(&mut b, 2).signed_lsa(4), None);
    // The intermediate Core has already isolated the subject, yet it must
    // keep its control profiles running so the exact signed evidence moves on.
    sync(&mut b, &mut c, 2, 3);
    assert_eq!(graph(&mut c, 3).signed_lsa(4), None);
    drop(c);
    drop(c_status);
    let mut reopened = f.status(3);
    assert_eq!(
        reopened
            .relayable_identity_revocations(utc_now().unwrap())
            .unwrap(),
        vec![evidence.as_slice()]
    );
}

#[test]
fn directory_converges_over_two_authenticated_hops_and_gates_business() {
    use boreas_tunnel::mesh_route::DirectoryCore;

    let f = &Fixture::new();
    let mut a_status = f.status(1);
    let mut b_status = f.status(2);
    let mut c_status = f.status(3);
    let mut a = f.probe(1, &mut a_status);
    let mut b = f.probe(2, &mut b_status);
    let mut c = f.probe(3, &mut c_status);
    // Real A--B--C only. No direct A--C locator or remote LSA seed.
    let chain = |id: usize, neighbors: &[u8]| {
        change_lsa(f.node(id), |obj| {
            obj.seq += 1;
            let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
                unreachable!()
            };
            lsa.seq = obj.seq;
            lsa.neighbors
                .retain(|n| neighbors.contains(&n.peer_core_id));
        })
    };
    let a_lsa = chain(1, &[2]);
    let b_lsa = chain(2, &[1, 3]);
    let c_lsa = chain(3, &[2]);
    for (probe, raw) in [(&mut a, &a_lsa), (&mut b, &b_lsa), (&mut c, &c_lsa)] {
        probe
            .refresh_runtime_authority(&f.status, None, raw)
            .unwrap();
    }
    let identities = [1, 2, 3].map(|id| f.node(id).identity.as_slice());
    let a_members = [identities[1], identities[2]];
    let b_members = [identities[0], identities[2]];
    let c_members = [identities[0], identities[1]];
    let [a_inputs, b_inputs, c_inputs] = [a_members, b_members, c_members].map(|members| {
        members.map(|identity| DirectoryCore {
            identity,
            seed_lsa: None,
        })
    });
    for (probe, local, members) in [
        (&mut a, identities[0], &a_inputs),
        (&mut b, identities[1], &b_inputs),
        (&mut c, identities[2], &c_inputs),
    ] {
        assert!(matches!(
            probe.verify_directory_graph(local, members),
            Err(Error::DirectoryPending)
        ));
    }

    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let exchange = |from: &mut MeshProbe<'_>,
                    to: &mut MeshProbe<'_>,
                    first: usize,
                    second: usize,
                    from_members: &[&[u8]],
                    to_members: &[&[u8]]| {
        let (listener, target) = listener();
        let from_admission = route_admission();
        let to_admission = route_admission();
        thread::scope(|scope| {
            let acceptor = scope.spawn(|| {
                to.accept_directory(
                    accept_socket(listener),
                    identities[first - 1],
                    to_members,
                    &outer_for(f, second),
                    &to_admission,
                )
            });
            let result = from.sync_directory(
                Candidate {
                    target: &target,
                    signed_identity: identities[second - 1],
                },
                from_members,
                &outer,
                &from_admission,
            );
            assert_eq!(result, Ok(()));
            assert_eq!(acceptor.join().unwrap(), Ok(()));
        });
        for admission in [&from_admission, &to_admission] {
            let snap = admission.snapshot().unwrap();
            assert_eq!((snap.handshakes, snap.authenticated, snap.bytes), (0, 0, 0));
        }
    };
    exchange(&mut a, &mut b, 1, 2, &a_members, &b_members);
    assert!(matches!(
        a.verify_directory_graph(identities[0], &a_inputs),
        Err(Error::DirectoryPending)
    ));
    exchange(&mut b, &mut c, 2, 3, &b_members, &c_members);
    exchange(&mut a, &mut b, 1, 2, &a_members, &b_members);
    let a_old = a.verify_directory_graph(identities[0], &a_inputs).unwrap();
    assert_eq!(a_old.signed_lsa(3), Some(c_lsa.as_slice()));
    for (probe, local, members) in [
        (&mut a, identities[0], &a_inputs),
        (&mut b, identities[1], &b_inputs),
        (&mut c, identities[2], &c_inputs),
    ] {
        let graph = probe.verify_directory_graph(local, members).unwrap();
        assert!(graph.core_ids().eq(1..=3));
        for (id, raw) in [(1, &a_lsa), (2, &b_lsa), (3, &c_lsa)] {
            assert_eq!(graph.signed_lsa(id), Some(raw.as_slice()));
        }
        graph.authorize_path(probe, &[1, 2, 3]).unwrap();
    }

    // Use the learned directory, never fixed-route or operator-seeded input,
    // to authorize a real nested TLS business circuit on separate sockets.
    let b_graph = b.verify_directory_graph(identities[1], &b_inputs).unwrap();
    let c_graph = c.verify_directory_graph(identities[2], &c_inputs).unwrap();
    let (b_listener, b_target) = listener();
    let (c_listener, c_target) = listener();
    let path = &[1, 2, 3];
    thread::scope(|scope| {
        use boreas_tunnel::mesh_route::RouteLocator;
        use std::io::{Read, Write};
        let b = &mut b;
        let c = &mut c;
        let outer = &outer;
        let relay = scope.spawn(move || {
            b_graph.relay(
                b,
                path,
                accept_socket(b_listener),
                &c_target,
                (&outer_for(f, 2), outer),
                &route_admission(),
            )
        });
        let receiver = scope.spawn(move || {
            c_graph.respond(
                c,
                path,
                accept_socket(c_listener),
                &outer_for(f, 3),
                &route_admission(),
                |circuit| {
                    let mut req = [0; 4];
                    circuit.read_exact(&mut req)?;
                    assert_eq!(&req, b"ping");
                    circuit.write_all(b"pong")?;
                    Ok(circuit.circuit_id())
                },
            )
        });
        let id = a_old
            .connect(
                &mut a,
                &[RouteLocator {
                    path,
                    target: &b_target,
                }],
                outer,
                &route_admission(),
                |_, circuit| {
                    circuit.write_all(b"ping")?;
                    let mut reply = [0; 4];
                    circuit.read_exact(&mut reply)?;
                    assert_eq!(&reply, b"pong");
                    Ok(circuit.circuit_id())
                },
            )
            .unwrap();
        assert_eq!(receiver.join().unwrap().unwrap(), id);
        assert_eq!(relay.join().unwrap().unwrap().circuit_id, id);
    });

    // C withdraws its only advertised business edge. The separate,
    // preprovisioned control adjacency still carries that signed withdrawal.
    let withdrawn = change_lsa(f.node(3), |obj| {
        obj.seq = 3;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = obj.seq;
        lsa.neighbors.clear();
    });
    c.refresh_runtime_authority(&f.status, None, &withdrawn)
        .unwrap();
    exchange(&mut b, &mut c, 2, 3, &b_members, &c_members);
    exchange(&mut a, &mut b, 1, 2, &a_members, &b_members);
    assert!(matches!(
        a_old.authorize_path(&mut a, &[1, 2, 3]),
        Err(Error::Lsa)
    ));
    let latest = a.verify_directory_graph(identities[0], &a_inputs).unwrap();
    assert_eq!(latest.signed_lsa(3), Some(withdrawn.as_slice()));
    assert!(matches!(
        latest.authorize_path(&mut a, &[1, 2, 3]),
        Err(Error::NoRoute)
    ));

    // A different healthy B replica knows only C's earlier, valid head. When
    // this is replayed over a new authenticated hop, A independently retains
    // the newer original envelope and the old business path remains barred.
    let mut replay_status = f.named_status(2, "replay.state");
    let mut replay_b = f.probe(2, &mut replay_status);
    replay_b
        .refresh_runtime_authority(&f.status, None, &b_lsa)
        .unwrap();
    let seeds = [
        DirectoryCore {
            identity: identities[0],
            seed_lsa: Some(&a_lsa),
        },
        DirectoryCore {
            identity: identities[2],
            seed_lsa: Some(&c_lsa),
        },
    ];
    replay_b
        .verify_directory_graph(identities[1], &seeds)
        .unwrap();
    exchange(&mut replay_b, &mut a, 2, 1, &b_members, &a_members);
    let latest = a.verify_directory_graph(identities[0], &a_inputs).unwrap();
    assert_eq!(latest.signed_lsa(3), Some(withdrawn.as_slice()));
    assert!(matches!(
        latest.authorize_path(&mut a, &[1, 2, 3]),
        Err(Error::NoRoute)
    ));

    // Disjoint replicas may each have accepted a different, valid C-signed
    // version 3. The receiving Core freezes C instead of taking first arrival.
    let fork = change_lsa(f.node(3), |obj| {
        obj.seq = 3;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = obj.seq;
    });
    let mut fork_status = f.named_status(2, "fork.state");
    let mut fork_b = f.probe(2, &mut fork_status);
    fork_b
        .refresh_runtime_authority(&f.status, None, &b_lsa)
        .unwrap();
    fork_b
        .verify_directory_graph(identities[1], &[
            DirectoryCore {
                identity: identities[0],
                seed_lsa: Some(&a_lsa),
            },
            DirectoryCore {
                identity: identities[2],
                seed_lsa: Some(&fork),
            },
        ])
        .unwrap();
    let (socket, target) = listener();
    thread::scope(|scope| {
        let acceptor = scope.spawn(|| {
            a.accept_directory(
                accept_socket(socket),
                identities[1],
                &a_members,
                &outer_for(f, 1),
                &route_admission(),
            )
        });
        let _ = fork_b.sync_directory(
            Candidate {
                target: &target,
                signed_identity: identities[0],
            },
            &b_members,
            &outer,
            &route_admission(),
        );
        assert_eq!(acceptor.join().unwrap(), Err(Error::Lsa));
    });
    assert!(matches!(
        a.verify_directory_graph(identities[0], &a_inputs),
        Err(Error::Lsa)
    ));
    assert!(matches!(
        latest.authorize_path(&mut a, &[1, 2, 3]),
        Err(Error::Lsa)
    ));
}

#[test]
fn shared_directory_listener_discovers_provisioned_spkis_and_rejects_unlisted_core() {
    use boreas_tunnel::mesh_route::DirectoryCore;

    let f = &Fixture::new();
    let mut statuses = [f.status(1), f.status(2), f.status(3), f.status(4)];
    let [a_status, b_status, c_status, stranger_status] = &mut statuses;
    let mut a = f.probe(1, a_status);
    let mut b = f.probe(2, b_status);
    let mut c = f.probe(3, c_status);
    let mut stranger = f.probe(4, stranger_status);
    let [a_raw, b_raw, c_raw] = [1, 2, 3].map(|id| f.node(id).identity.as_slice());
    let a_members = [b_raw, c_raw];
    let b_members = [a_raw, c_raw];
    let c_members = [a_raw, b_raw];
    let (listen, target) = listener();
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    let acceptor = outer_for(f, 2);
    let admission = route_admission();
    let stranger_members = [b_raw];
    for client_id in [4, 3, 1, 3] {
        let (client, provisioned, expected) = match client_id {
            1 => (&mut a, &a_members[..], Some(1)),
            3 => (&mut c, &c_members[..], Some(3)),
            4 => (&mut stranger, &stranger_members[..], None),
            _ => unreachable!("unexpected directory fixture client"),
        };
        let socket = listen.try_clone().unwrap();
        thread::scope(|scope| {
            let incoming = scope.spawn(|| {
                b.accept_directory_member(accept_socket(socket), &b_members, &acceptor, &admission)
            });
            let outgoing = client.sync_directory(
                Candidate {
                    target: &target,
                    signed_identity: b_raw,
                },
                provisioned,
                &outer,
                &route_admission(),
            );
            let result = incoming.join().unwrap();
            match expected {
                Some(id) => {
                    assert_eq!(result, Ok(id));
                    assert_eq!(outgoing, Ok(()));
                }
                None => {
                    assert!(result.is_err());
                    assert!(outgoing.is_err());
                }
            }
        });
        let snap = admission.snapshot().unwrap();
        assert_eq!((snap.handshakes, snap.authenticated, snap.bytes), (0, 0, 0));
    }
    // Only B has a listener. A and C learned each other's exact signed LSA
    // despite never having a control locator or socket for each other.
    for (probe, local, peers, learned) in [
        (&mut a, a_raw, a_members, 3u8),
        (&mut c, c_raw, c_members, 1u8),
    ] {
        let inputs = peers.map(|identity| DirectoryCore {
            identity,
            seed_lsa: None,
        });
        let graph = probe.verify_directory_graph(local, &inputs).unwrap();
        assert_eq!(
            graph.signed_lsa(learned),
            Some(f.node(usize::from(learned)).lsa.as_slice())
        );
        graph.authorize_path(probe, &[1, 2, 3]).unwrap();
    }
}

#[test]
fn authenticated_forwarded_core_lsa_fork_preserves_both_envelopes_and_blocks_restart() {
    use boreas_tunnel::mesh_route::DirectoryCore;
    use std::os::unix::fs::{PermissionsExt, symlink};

    let f = &Fixture::new();
    let [a, b, c] = [1, 2, 3].map(|id| f.node(id));
    let path = a.path.join("core-lsa.state");
    let owner = fs::metadata(&a.path).unwrap().uid();
    fn reopen<'a>(
        f: &'a Fixture,
        status: &'a mut StatusStore,
        path: &Path,
        owner: u32,
    ) -> Result<MeshProbe<'a>, Error> {
        let a = f.node(1);
        MeshProbe::new_durable(
            f.policy,
            &f.roots,
            status,
            &a.pem,
            &a.identity,
            &a.lsa,
            (path, owner),
        )
    }
    fn seeds<'a>(b: &'a Node, c: &'a Node, lsa: Option<&'a [u8]>) -> [DirectoryCore<'a>; 2] {
        [
            DirectoryCore {
                identity: &b.identity,
                seed_lsa: Some(&b.lsa),
            },
            DirectoryCore {
                identity: &c.identity,
                seed_lsa: lsa,
            },
        ]
    }
    let newest = change_lsa(c, |obj| {
        obj.seq += 1;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = obj.seq;
    });
    let fork = change_lsa(c, |obj| {
        obj.seq += 1;
        let ObjectBody::CoreLsa(lsa) = &mut obj.body else {
            unreachable!()
        };
        lsa.seq = obj.seq;
        lsa.neighbors.clear();
    });
    let mut a_status = f.status(1);
    let healthy = {
        let mut probe = reopen(f, &mut a_status, &path, owner).unwrap();
        probe
            .verify_directory_graph(&a.identity, &seeds(b, c, Some(&newest)))
            .unwrap();
        let initial = fs::read(&path).unwrap();
        for signature in [false, true] {
            let mut corrupt = SignedObject::decode(&fork).unwrap();
            if signature {
                corrupt.signers[0].mldsa[0] ^= 1;
            } else {
                corrupt.signers[0].ed25519[0] ^= 1;
            }
            let corrupt = corrupt.encode().unwrap();
            assert!(matches!(
                probe.verify_directory_graph(&a.identity, &seeds(b, c, Some(&corrupt))),
                Err(Error::Lsa)
            ));
            assert_eq!(fs::read(&path).unwrap(), initial);
        }
        initial
    };
    drop(a_status);
    let mut a_status = f.status(1);
    let mut probe = reopen(f, &mut a_status, &path, owner).unwrap();
    for seed in [None, Some(c.lsa.as_slice())] {
        let graph = probe
            .verify_directory_graph(&a.identity, &seeds(b, c, seed))
            .unwrap();
        assert_eq!(graph.signed_lsa(3), Some(newest.as_slice()));
    }
    let mut b_status = f.status(2);
    let mut sender = f.probe(2, &mut b_status);
    assert!(matches!(
        sender.verify_directory_graph(&b.identity, &[
            DirectoryCore {
                identity: &a.identity,
                seed_lsa: None
            },
            DirectoryCore {
                identity: &c.identity,
                seed_lsa: Some(&fork)
            },
        ]),
        Err(Error::DirectoryPending)
    )); // B accepted C, but A is still pending.
    let a_members = [b.identity.as_slice(), c.identity.as_slice()];
    let b_members = [a.identity.as_slice(), c.identity.as_slice()];
    let (listen, target) = listener();
    let outer = || OpenSslOuterTlsConnector::with_root_certificates(&f.outer_ca);
    thread::scope(|scope| {
        let receiver = scope.spawn(|| {
            probe.accept_directory_member(
                accept_socket(listen),
                &a_members,
                &outer_for(f, 1),
                &route_admission(),
            )
        });
        let _ = sender.sync_directory(
            Candidate {
                target: &target,
                signed_identity: &a.identity,
            },
            &b_members,
            &outer,
            &route_admission(),
        );
        assert_eq!(receiver.join().unwrap(), Err(Error::LsaConflict));
    });
    drop(probe);
    drop(a_status);
    let mut a_status = f.status(1);
    let image = fs::read(&path).unwrap();
    for original in [&newest, &fork] {
        assert!(
            image
                .windows(original.len())
                .any(|candidate| candidate == original.as_slice())
        );
    }
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaConflict)
    ));
    // A checksum is not a trust input. Even with a recomputed checksum,
    // corrupting either stored signature must be classified as bad state,
    // not as authenticated evidence.
    for side in [&newest, &fork] {
        let at = image
            .windows(side.len())
            .position(|raw| raw == side.as_slice())
            .unwrap();
        let mut altered = image.clone();
        altered[at + 6] ^= 1; // first Ed25519 signature byte, after envelope + primary role
        let digest_at = altered.len() - 32;
        let digest = openssl::sha::sha256(&altered[..digest_at]);
        altered[digest_at..].copy_from_slice(&digest);
        fs::write(&path, altered).unwrap();
        assert!(matches!(
            reopen(f, &mut a_status, &path, owner),
            Err(Error::LsaState)
        ));
    }
    // Simulate crash after the durable conflict intent, before the evidence
    // image was installed: a valid older image must not resume admission.
    fs::write(&path, healthy).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    fs::write(&path, &image).unwrap();
    let displaced = path.with_extension("backup");
    fs::rename(&path, &displaced).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    symlink(&displaced, &path).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    fs::remove_file(&path).unwrap();
    fs::hard_link(&displaced, &path).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    fs::remove_file(&path).unwrap();
    fs::rename(&displaced, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let staging = a.path.join("core-lsa.state.staging");
    fs::write(&staging, b"interrupted").unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
    fs::remove_file(staging).unwrap();
    fs::write(&path, &image[..image.len() - 1]).unwrap();
    assert!(matches!(
        reopen(f, &mut a_status, &path, owner),
        Err(Error::LsaState)
    ));
}
