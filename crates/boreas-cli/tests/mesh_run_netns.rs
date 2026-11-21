#![cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]

//! Opt-in privileged test: four actual processes, two real persistent TUNs.

use boreas_pki::{
    NodeRole,
    management::MANAGEMENT_SCHEMA_VERSION,
    provisioning::{
        CaInitParams, NodeIssueParams, RootsBundle, SignedRootAuthorization, init_ca_dir,
        issue_node_dir, sign_network_policy_dir, sign_status_file,
    },
    root_authorization::{MAX_CHAIN_DEPTH, Purpose, RootAuthorizationCandidate, Scope},
};
use boreas_proto::{
    messages::{PathRole, SignedObject, SignerRole, SignerSignatures},
    objects::{
        self, CoreLsa, ManagementObject, MldsaParameterSet, Neighbor, ObjectBody, ObjectType,
        SubjectIdentity,
    },
};
use boreas_tunnel::mesh_probe::utc_now;
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
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
    identity: Vec<u8>,
    lsa: Vec<u8>,
}

struct Fixture {
    _temp: Temp,
    nodes: Vec<Node>,
    roots: RootsBundle,
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
            let identity = read(&path, "local.signed");
            nodes.push(Node {
                path,
                identity,
                lsa,
            });
        }
        Self {
            _temp: temp,
            roots,
            nodes,
            status: fs::read(snapshot_path).unwrap(),
            outer_ca: read(&ca, "outer-ca.pem"),
        }
    }

    fn node(&self, id: usize) -> &Node {
        &self.nodes[id - 1]
    }
}

const UID: &str = "65534";
const SERVICE_IP: [&str; 4] = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"];

fn checked(c: &mut Command) {
    let result = c.output().unwrap_or_else(|e| panic!("{c:?}: {e}"));
    assert!(
        result.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

struct Network {
    names: [String; 4],
    bridge: String,
}
impl Network {
    fn setup() -> Self {
        let p = std::process::id();
        let network = Self {
            names: std::array::from_fn(|i| format!("bmesh-{p}-{i}")),
            bridge: format!("bm{p}"),
        };
        checked(Command::new("ip").args(["link", "add", &network.bridge, "type", "bridge"]));
        checked(Command::new("ip").args(["link", "set", &network.bridge, "up"]));
        for (i, namespace) in network.names.iter().enumerate() {
            checked(Command::new("ip").args(["netns", "add", namespace]));
            let host = format!("bv{p}{i}");
            checked(Command::new("ip").args([
                "link", "add", &host, "type", "veth", "peer", "name", "underlay", "netns",
                namespace,
            ]));
            checked(Command::new("ip").args(["link", "set", &host, "master", &network.bridge]));
            checked(Command::new("ip").args(["link", "set", &host, "up"]));
            for args in [
                vec!["link", "set", "lo", "up"],
                vec!["link", "set", "underlay", "up"],
                vec![
                    "addr",
                    "add",
                    &format!("{}/24", SERVICE_IP[i]),
                    "dev",
                    "underlay",
                ],
            ] {
                checked(Command::new("ip").args(["-n", namespace]).args(args));
            }
        }
        for (i, local, remote) in [(0, "10.20.1.1", "10.20.4.1"), (3, "10.20.4.1", "10.20.1.1")] {
            let ns = &network.names[i];
            checked(Command::new("ip").args([
                "netns", "exec", ns, "ip", "tuntap", "add", "dev", "bmesh0", "mode", "tun", "user",
                UID,
            ]));
            checked(
                Command::new("ip").args(["-n", ns, "link", "set", "bmesh0", "mtu", "1400", "up"]),
            );
            checked(Command::new("ip").args([
                "-n",
                ns,
                "addr",
                "add",
                &format!("{local}/32"),
                "dev",
                "bmesh0",
            ]));
            checked(Command::new("ip").args([
                "-n",
                ns,
                "route",
                "add",
                &format!("{remote}/32"),
                "dev",
                "bmesh0",
                "src",
                local,
            ]));
        }
        network
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        for ns in &self.names {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
        let _ = Command::new("ip")
            .args(["link", "del", &self.bridge])
            .output();
    }
}

fn route(path: &str, listen: Option<(usize, u16)>, next: Option<(usize, u16)>) -> String {
    let mut out = format!("[[routes]]\npath = [{path}]\n");
    if let Some((i, port)) = listen {
        out += &format!("listen = \"{}:{port}\"\n", SERVICE_IP[i]);
    }
    if let Some((i, port)) = next {
        out += &format!(
            "next = \"{}:{port}\"\ntls_name = \"{NAME}\"\n",
            SERVICE_IP[i]
        );
    }
    out
}

fn private(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn install(f: &Fixture) -> [PathBuf; 4] {
    let base = &f._temp.0;
    // Allow traversal to each node, without exposing the offline signing keys.
    fs::set_permissions(base, fs::Permissions::from_mode(0o711)).unwrap();
    let binary = base.join("boreas-netns");
    fs::copy(env!("CARGO_BIN_EXE_boreas"), &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let root_bytes = f.roots.encode().unwrap();
    std::array::from_fn(|i| {
        let node = f.node(i + 1);
        let dir = &node.path;
        let state = dir.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        for (source, destination) in [
            ("tbs.cbor", "network-policy.tbs"),
            ("ed25519.sig", "network-policy.ed25519.sig"),
            ("mldsa65.sig", "network-policy.mldsa65.sig"),
        ] {
            private(&state.join(destination), read(&base.join("policy"), source));
        }
        private(
            &state.join("network-root.ed25519.der"),
            &f.roots.root_ed25519_pub_der,
        );
        private(
            &state.join("network-root.mldsa65.der"),
            &f.roots.root_mldsa65_pub_der,
        );
        private(&dir.join("roots.cbor"), &root_bytes);
        private(&dir.join("status.signed"), &f.status);
        private(&dir.join("outer-ca.pem"), &f.outer_ca);
        private(&dir.join("local-lsa.signed"), &node.lsa);
        let mut peers = Vec::new();
        for j in 1..=4 {
            if j != i + 1 {
                peers.push(j);
                private(&dir.join(format!("core-{j}.signed")), &f.node(j).identity);
                private(&dir.join(format!("core-{j}-lsa.signed")), &f.node(j).lsa);
            }
        }
        let role = ["source", "relay", "relay", "destination"][i];
        let mut runtime = format!("mode = \"{role}\"\npeers = {peers:?}\n");
        if i == 0 || i == 3 {
            runtime += "tun = \"bmesh0\"\nmtu = 1400\n";
        }
        const MAIN: &str = "1, 2, 3, 4";
        const BACKUP: &str = "1, 3, 4";
        runtime += &match i {
            0 => route(BACKUP, None, Some((2, 18083))) + &route(MAIN, None, Some((1, 18082))),
            1 => route(MAIN, Some((1, 18082)), Some((2, 18082))),
            2 => {
                route(MAIN, Some((2, 18082)), Some((3, 18082)))
                    + &route(BACKUP, Some((2, 18083)), Some((3, 18083)))
            }
            3 => route(MAIN, Some((3, 18082)), None) + &route(BACKUP, Some((3, 18083)), None),
            _ => unreachable!(),
        };
        private(&dir.join("runtime.toml"), runtime);
        let config = format!(
            r#"version = 2
[node]
net_id = "46464646464646464646464646464646"
role = "core"
home_core_id = {core}
vip_octet = 1
node_id = {node_id}
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "{dir}/identity.key"
roots = ["{dir}/roots.cbor"]
state_dir = "{dir}/state"
[uplink]
primary = "127.0.0.1:443"
paths = 1
probe_paths = 1
"#,
            dir = dir.display(),
            core = i + 1,
            node_id = i * 256 + 1
        );
        private(&dir.join("node.toml"), config);
        checked(Command::new("chown").args(["-R", "65534:65534"]).arg(dir));
        dir.clone()
    })
}

struct Process {
    child: Child,
    log: PathBuf,
}
impl Process {
    fn spawn(f: &Fixture, n: &Network, i: usize, dir: &Path) -> Self {
        let log = f._temp.0.join(format!("process-{i}.log"));
        let child = Command::new("ip")
            .args(["netns", "exec", &n.names[i], "unshare", "--mount", "--propagation", "private", "sh", "-ec",
                "umount -l /sys; mount -t sysfs sysfs /sys; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \"$@\"",
                "mesh-netns"])
            .arg(f._temp.0.join("boreas-netns"))
            .args(["node", "mesh-run"])
            .arg(dir.join("node.toml"))
            .arg(dir)
            .arg(dir.join("runtime.toml"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn().unwrap();
        Self { child, log }
    }

    fn text(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }

    fn wait_for(&mut self, match_log: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let text = self.text();
            if let Some(line) = text.lines().find(|line| line.contains(match_log)) {
                return line.to_owned();
            }
            assert!(
                self.child.try_wait().unwrap().is_none() && Instant::now() < deadline,
                "waiting for {match_log}:\n{text}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

fn circuit(line: &str) -> &str {
    line.split_once("circuit=")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap()
}

fn ping(n: &Network, i: usize, destination: &str) {
    checked(Command::new("ip").args([
        "netns",
        "exec",
        &n.names[i],
        "ping",
        "-n",
        "-c",
        "1",
        "-w",
        "3",
        "-I",
        "bmesh0",
        destination,
    ]));
}

#[test]
#[ignore = "requires root, CAP_NET_ADMIN/CAP_SYS_ADMIN, real TUN, and iproute2/ping/setpriv"]
fn mesh_run_real_tun_switches_to_fresh_backup_after_confirmed_relay_loss() {
    let n = Network::setup();
    let f = Fixture::new();
    let dirs = install(&f);
    let mut destination = Process::spawn(&f, &n, 3, &dirs[3]);
    destination.wait_for("mesh ready");
    let mut second = Process::spawn(&f, &n, 2, &dirs[2]);
    second.wait_for("mesh ready");
    let mut first = Process::spawn(&f, &n, 1, &dirs[1]);
    first.wait_for("mesh ready");
    let mut source = Process::spawn(&f, &n, 0, &dirs[0]);
    let primary = source.wait_for("role=source path=[1, 2, 3, 4]");
    assert_eq!(
        circuit(&primary),
        circuit(&destination.wait_for("role=destination path=[1, 2, 3, 4]"))
    );
    ping(&n, 0, "10.20.4.1");
    first.stop();
    let backup = source.wait_for("role=source path=[1, 3, 4]");
    assert_ne!(circuit(&primary), circuit(&backup));
    assert_eq!(
        circuit(&backup),
        circuit(&destination.wait_for("role=destination path=[1, 3, 4]"))
    );
    ping(&n, 3, "10.20.1.1");
    let source_epoch = source.wait_for(&format!("role=source circuit={}", circuit(&backup)));
    assert!(source_epoch.contains("tx=1 rx=1"), "{source_epoch}");
    let relay_epoch = second.wait_for(&format!("role=relay circuit={}", circuit(&backup)));
    assert!(relay_epoch.contains("ciphertext=["), "{relay_epoch}");

    // Publish an independently signed denial for the still-active backup relay.
    // The next local authority boundary must stop source admission, not select
    // another path past the revocation or treat it as ordinary socket failure.
    use boreas_pki::status_store::IDENTITY_REVOCATION_MAGIC;
    use boreas_proto::authority_revocation::{
        AuthorityRevocation, RevocationClass, RevocationScope,
    };
    let now = utc_now().unwrap();
    let tbs = AuthorityRevocation {
        net_id: NET,
        class: RevocationClass::Identity,
        subject_node_id: 513,
        identity_generation: 1,
        issuer_key_id: b"identity-authority-v1".to_vec(),
        issuer_generation: 1,
        scope: RevocationScope::default(),
        seq: 1,
        issued_at: now,
        next_update: now + 15_000_000,
    }
    .encode_tbs()
    .unwrap();
    let msg = AuthorityRevocation::signature_input(&tbs).unwrap();
    let ca = f._temp.0.join("ca");
    let mut raw = IDENTITY_REVOCATION_MAGIC.to_vec();
    for name in ["ia.ed25519.key", "ia.mldsa65.key"] {
        raw.extend(sign(
            &PKey::private_key_from_der(&read(&ca, name)).unwrap(),
            &msg,
        ));
    }
    raw.extend(tbs);
    let stage = dirs[0].join("revocation.tmp");
    fs::write(&stage, raw).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)).unwrap();
    fs::rename(stage, dirs[0].join("identity-revocation.signed")).unwrap();
    source.wait_for("mesh signed graph: Status");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = source.child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
}
