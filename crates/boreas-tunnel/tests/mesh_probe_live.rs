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
