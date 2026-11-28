#![cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]

//! Opt-in privileged test: four actual processes, two real persistent TUNs.

use boreas_pki::{
    NodeRole,
    provisioning::{
        CaInitParams, NodeIssueParams, RootsBundle,
        core_mesh::{LsaParams, authorize_core, init_core_request, sign_lsa},
        init_ca_dir, issue_node_dir, sign_network_policy_dir, sign_status_file,
    },
};
use boreas_proto::authority_revocation::RevocationClass;
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

#[derive(Clone, Copy)]
enum Topology {
    Legacy,
    OneSidedDirect,
    SignedDirectBackup,
}

impl Fixture {
    fn new() -> Self {
        Self::with_topology(Topology::Legacy)
    }

    fn with_topology(topology: Topology) -> Self {
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
        let mut roots_path = ca.join("roots.cbor");
        let snapshot_path = temp.0.join("status.signed");
        sign_status_file(&ca, &snapshot_path, 1, now, 120).unwrap();
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
            let keys = temp.0.join(format!("operational-{id}"));
            init_core_request(&keys, NET, id, 1, now, 1).unwrap();
            let new_roots = temp.0.join(format!("roots-{id}.cbor"));
            authorize_core(
                &ca,
                &roots_path,
                &keys.join("core.request"),
                &new_roots,
                id,
                now,
            )
            .unwrap();
            roots_path = new_roots;
            let neighbors: Vec<_> = (1..=4)
                .filter(|other| {
                    *other != id
                        && !(matches!(topology, Topology::OneSidedDirect) && id == 4 && *other == 1)
                })
                .map(|other| {
                    let rtt = match (id.min(other), id.max(other)) {
                        (1, 4) => match topology {
                            Topology::OneSidedDirect => 1,
                            Topology::SignedDirectBackup => 12,
                            Topology::Legacy => u16::from(other),
                        },
                        (1, 3) => 20,
                        (2, 4) => 30,
                        _ => u16::from(other),
                    };
                    (other, rtt, 0)
                })
                .collect();
            let lsa_path = path.join("fixture-lsa.signed");
            sign_lsa(&keys, &roots_path, &lsa_path, &LsaParams {
                now,
                core_generation: 1,
                sequence: 1,
                ttl_seconds: 120,
                neighbors: &neighbors,
            })
            .unwrap();
            let lsa = fs::read(lsa_path).unwrap();
            let identity = read(&path, "local.signed");
            nodes.push(Node {
                path,
                identity,
                lsa,
            });
        }
        let roots = RootsBundle::decode(&fs::read(roots_path).unwrap()).unwrap();
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
    created_namespaces: Vec<String>,
    created_hosts: Vec<String>,
    bridge_created: bool,
}
impl Network {
    fn setup() -> Self {
        static NEXT_NETWORK: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let p = std::process::id();
        let serial = NEXT_NETWORK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut network = Self {
            names: std::array::from_fn(|i| format!("bmesh-{p}-{serial}-{i}")),
            bridge: format!("bm{p:x}{serial:x}"),
            created_namespaces: Vec::new(),
            created_hosts: Vec::new(),
            bridge_created: false,
        };
        checked(Command::new("ip").args(["link", "add", &network.bridge, "type", "bridge"]));
        network.bridge_created = true;
        checked(Command::new("ip").args(["link", "set", &network.bridge, "up"]));
        for (i, namespace) in network.names.iter().enumerate() {
            checked(Command::new("ip").args(["netns", "add", namespace]));
            network.created_namespaces.push(namespace.clone());
            let host = format!("bv{p:x}{serial:x}{i:x}");
            checked(Command::new("ip").args([
                "link", "add", &host, "type", "veth", "peer", "name", "underlay", "netns",
                namespace,
            ]));
            network.created_hosts.push(host.clone());
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
        for host in self.created_hosts.iter().rev() {
            let _ = Command::new("ip").args(["link", "del", host]).output();
        }
        for ns in self.created_namespaces.iter().rev() {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
        if self.bridge_created {
            let _ = Command::new("ip")
                .args(["link", "del", &self.bridge])
                .output();
        }
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

fn install(f: &Fixture, routed: bool) -> [PathBuf; 4] {
    let base = &f._temp.0;
    // Allow traversal to each node, without exposing the offline signing keys.
    fs::set_permissions(base, fs::Permissions::from_mode(0o711)).unwrap();
    let binary = base.join("boreas-netns");
    // The CI acceptance runner restores the daemon built with this test.
    // Ordinary Cargo invocations still use Cargo's own binary path.
    let source = std::env::var_os("BOREAS_MESH_TEST_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_boreas")));
    fs::copy(source, &binary).unwrap();
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
                if routed {
                    private(&dir.join(format!("core-{j}-lsa.signed")), &f.node(j).lsa);
                }
                // The legacy case instead learns almost all heads through discovery.
            }
        }
        let role = ["source", "relay", "relay", "destination"][i];
        let mut runtime = format!("mode = \"{role}\"\npeers = {peers:?}\n");
        if i == 0 || i == 3 {
            runtime += "tun = \"bmesh0\"\nmtu = 1400\n";
        }
        if routed {
            runtime += "[routing]\nsource = 1\ndestination = 4\n";
            let incoming: &[usize] = match i {
                0 => &[],
                1 => &[1],
                2 => &[1, 2],
                3 => &[1, 2, 3],
                _ => unreachable!(),
            };
            let outgoing: &[usize] = match i {
                0 => &[2, 3, 4],
                1 => &[3, 4],
                2 => &[4],
                3 => &[],
                _ => unreachable!(),
            };
            if !incoming.is_empty() {
                runtime += &format!(
                    "incoming = {incoming:?}\nlisten = \"{}:18082\"\n",
                    SERVICE_IP[i]
                );
            }
            for &peer in outgoing {
                runtime += &format!(
                    "[[routing.outgoing]]\npeer = {peer}\nnext = \"{}:18082\"\ntls_name = \"{NAME}\"\n",
                    SERVICE_IP[peer - 1]
                );
            }
        } else {
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
            runtime += "[directory_discovery]\ncoordinator = 3\n";
            if i == 2 {
                runtime += &format!("listen = \"{}:18183\"\n", SERVICE_IP[2]);
            } else {
                runtime += &format!(
                    "next = \"{}:18183\"\ntls_name = \"{NAME}\"\n",
                    SERVICE_IP[2]
                );
            }
        }
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
        self.wait_for_line(match_log, |_| true)
    }

    fn wait_for_new_path(&mut self, match_log: &str, previous_circuit: &str) -> String {
        self.wait_for_line(match_log, |line| circuit(line) != previous_circuit)
    }

    fn wait_for_line(&mut self, match_log: &str, accept: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let text = self.text();
            if let Some(line) = text
                .lines()
                .find(|line| line.contains(match_log) && accept(line))
            {
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

fn publish_denial(f: &Fixture, dir: &Path, subject_node_id: u16) {
    publish_authority_denial(f, dir, subject_node_id, RevocationClass::Identity);
}

fn publish_authority_denial(f: &Fixture, dir: &Path, subject_node_id: u16, class: RevocationClass) {
    use boreas_pki::status_store::{IDENTITY_REVOCATION_MAGIC, SCOPED_REVOCATION_MAGIC};
    use boreas_proto::authority_revocation::{AuthorityRevocation, RevocationScope};
    let (issuer_key_id, header, keys, name) = match class {
        RevocationClass::Identity => (b"identity-authority-v1".to_vec(), IDENTITY_REVOCATION_MAGIC,
            ["ia.ed25519.key", "ia.mldsa65.key"], "identity-revocation.signed"),
        RevocationClass::Core => (f.roots.network_root_pin().unwrap().fingerprint().unwrap().to_vec(),
            SCOPED_REVOCATION_MAGIC, ["root.ed25519.key", "root.mldsa65.key"], "core-revocation.signed"),
        _ => unreachable!(),
    };
    let now = utc_now().unwrap();
    let tbs = AuthorityRevocation {
        net_id: NET,
        class,
        subject_node_id,
        identity_generation: 1,
        issuer_key_id,
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
    let mut raw = header.to_vec();
    for name in keys {
        raw.extend(sign(
            &PKey::private_key_from_der(&read(&ca, name)).unwrap(),
            &msg,
        ));
    }
    raw.extend(tbs);
    let stage = dir.join("revocation.tmp");
    fs::write(&stage, raw).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)).unwrap();
    fs::rename(stage, dir.join(name)).unwrap();
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
    let dirs = install(&f, false);
    // Run discovery on real processes and on one dedicated socket. The hub
    // cannot finish its graph until it sees Core 1, whose business process
    // must start last: EOF before route confirmation is deliberately not
    // retryable. Seed Core 1 only at the hub to break that startup dependency.
    let bootstrap = dirs[2].join("core-1-lsa.signed");
    fs::write(&bootstrap, &f.node(1).lsa).unwrap();
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o644)).unwrap();
    let mut second = Process::spawn(&f, &n, 2, &dirs[2]);
    let mut destination = Process::spawn(&f, &n, 3, &dirs[3]);
    let mut first = Process::spawn(&f, &n, 1, &dirs[1]);
    for process in [&mut second, &mut destination, &mut first] {
        process.wait_for("mesh ready");
    }
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

    // Wait for a new, idle backup circuit before publishing. A remote denial
    // closes that circuit, not the node or its dedicated directory service.
    let next = source.wait_for_new_path("role=source path=[1, 3, 4]", circuit(&backup));
    assert_ne!(circuit(&backup), circuit(&next));
    publish_denial(&f, &dirs[0], 513);
    source.wait_for("mesh source route closed: IdentityRevoked");
    source.wait_for("mesh routes temporarily unavailable: NoRoute");
    assert!(source.child.try_wait().unwrap().is_none());

    // In contrast, the source's own denied generation cannot serve business
    // or directory traffic. Require the process to fail closed.
    publish_denial(&f, &dirs[0], 1);
    source.wait_for("mesh runtime authority: IdentityRevoked");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = source.child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            break;
        }
        assert!(Instant::now() < deadline, "{}", source.text());
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires root, CAP_NET_ADMIN/CAP_SYS_ADMIN, real TUN, and iproute2/ping/setpriv"]
fn mesh_routed_tun_derives_paths_and_reuses_ingress_after_relay_loss() {
    let n = Network::setup();
    let f = Fixture::with_topology(Topology::OneSidedDirect);
    let dirs = install(&f, true);
    let mut destination = Process::spawn(&f, &n, 3, &dirs[3]);
    let mut shared_relay = Process::spawn(&f, &n, 2, &dirs[2]);
    let mut first_relay = Process::spawn(&f, &n, 1, &dirs[1]);
    for process in [&mut destination, &mut shared_relay, &mut first_relay] {
        process.wait_for("mesh ready");
    }
    // A cheap one-sided direct advertisement is not an edge. Also verify
    // complete rank selection (1-2-3-4 is cheaper than 1-2-4).
    let mut source = Process::spawn(&f, &n, 0, &dirs[0]);
    let primary = source.wait_for("role=source path=[1, 2, 3, 4]");
    assert_eq!(
        circuit(&primary),
        circuit(&destination.wait_for("role=destination path=[1, 2, 3, 4]"))
    );
    ping(&n, 0, "10.20.4.1");
    first_relay.stop();
    // Core 3 uses the *same port* here, but the authenticated predecessor
    // changes from 2 to 1. Core 4 reuses its listener on both paths as well.
    let backup = source.wait_for("role=source path=[1, 3, 4]");
    assert_ne!(circuit(&primary), circuit(&backup));
    assert_eq!(
        circuit(&backup),
        circuit(&destination.wait_for("role=destination path=[1, 3, 4]"))
    );
    ping(&n, 3, "10.20.1.1");
    let observed = shared_relay.wait_for(&format!("role=relay circuit={}", circuit(&backup)));
    assert!(observed.contains("ciphertext=["), "{observed}");
}

#[test]
#[ignore = "requires root, CAP_NET_ADMIN/CAP_SYS_ADMIN, real TUN, and iproute2/ping/setpriv"]
fn mesh_routed_tun_live_revocation_excludes_relay_and_preserves_healthy_path() {
    let n = Network::setup();
    let f = Fixture::with_topology(Topology::SignedDirectBackup);
    let dirs = install(&f, true);
    let mut destination = Process::spawn(&f, &n, 3, &dirs[3]);
    let mut shared_relay = Process::spawn(&f, &n, 2, &dirs[2]);
    let mut first_relay = Process::spawn(&f, &n, 1, &dirs[1]);
    for process in [&mut destination, &mut shared_relay, &mut first_relay] {
        process.wait_for("mesh ready");
    }
    let mut source = Process::spawn(&f, &n, 0, &dirs[0]);
    let primary = source.wait_for("role=source path=[1, 2, 3, 4]");
    assert_eq!(
        circuit(&primary),
        circuit(&destination.wait_for("role=destination path=[1, 2, 3, 4]"))
    );
    publish_denial(&f, &dirs[0], 257);
    source.wait_for("mesh source route closed: IdentityRevoked");
    assert!(first_relay.child.try_wait().unwrap().is_none());
    // Unlike the one-sided direct fixture, this reciprocal edge is usable;
    // it outranks the surviving transit alternative after Core 2 is denied.
    let backup = source.wait_for("role=source path=[1, 4]");
    assert_ne!(circuit(&primary), circuit(&backup));
    assert_eq!(
        circuit(&backup),
        circuit(&destination.wait_for("role=destination path=[1, 4]"))
    );
    ping(&n, 0, "10.20.4.1");
}

#[test]
#[ignore = "requires root, CAP_NET_ADMIN/CAP_SYS_ADMIN, real TUN, and iproute2/ping/setpriv"]
fn mesh_root_core_revocation_withdraws_owned_path_but_keeps_admin_routes() {
    let n = Network::setup();
    let f = Fixture::with_topology(Topology::SignedDirectBackup);
    let dirs = install(&f, true);
    let mut destination = Process::spawn(&f, &n, 3, &dirs[3]);
    let mut shared_relay = Process::spawn(&f, &n, 2, &dirs[2]);
    let mut first_relay = Process::spawn(&f, &n, 1, &dirs[1]);
    for process in [&mut destination, &mut shared_relay, &mut first_relay] {
        process.wait_for("mesh ready");
    }
    let mut source = Process::spawn(&f, &n, 0, &dirs[0]);
    let primary = source.wait_for("role=source path=[1, 2, 3, 4]");
    assert_eq!(
        circuit(&primary),
        circuit(&destination.wait_for("role=destination path=[1, 2, 3, 4]")),
    );
    let admin_route = || {
        let output = Command::new("ip")
            .args(["-n", &n.names[0], "route", "show", "exact", "10.20.4.1/32"])
            .output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("dev bmesh0"));
        output.stdout
    };
    let before = admin_route();
    publish_authority_denial(&f, &dirs[0], 257, RevocationClass::Core);
    source.wait_for("mesh source route closed: CoreRevoked");
    let backup = source.wait_for("role=source path=[1, 4]");
    assert_ne!(circuit(&primary), circuit(&backup));
    assert_eq!(circuit(&backup), circuit(&destination.wait_for("role=destination path=[1, 4]")));
    assert_eq!(admin_route(), before);
    // Mailbox deletion and process restart do not resurrect the denied route.
    source.stop();
    fs::remove_file(dirs[0].join("core-revocation.signed")).unwrap();
    let mut source = Process::spawn(&f, &n, 0, &dirs[0]);
    let reopened = source.wait_for("role=source path=[1, 4]");
    assert_ne!(circuit(&backup), circuit(&reopened));
    destination.wait_for(&format!("role=destination circuit={}", circuit(&reopened)));
    assert!(!source.text().contains("role=source path=[1, 2, 3, 4]"));
    assert_eq!(admin_route(), before);
    ping(&n, 0, "10.20.4.1");
}

#[test]
fn provisioned_operational_signer_is_limited_to_its_authorized_core() {
    let fixture = Fixture::new();
    let base = &fixture._temp.0;
    let roots = base.join("roots-4.cbor");
    let keys = base.join("operational-1");
    let now = utc_now().unwrap();
    let wrong = base.join("bad-roots.cbor");
    assert!(
        authorize_core(
            &base.join("ca"),
            &base.join("roots-2.cbor"),
            &keys.join("core.request"),
            &wrong,
            4,
            now,
        )
        .is_err()
    );
    assert!(!wrong.exists());
    let out = base.join("bad-lsa.signed");
    assert!(
        sign_lsa(&keys, &roots, &out, &LsaParams {
            now,
            core_generation: 1,
            sequence: 2,
            ttl_seconds: 60,
            neighbors: &[(1, 10, 0)],
        })
        .is_err()
    );
    assert!(!out.exists());
}
