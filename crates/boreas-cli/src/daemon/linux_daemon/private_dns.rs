//! Static, locally pinned private DNS deployment (Linux daemon only).

use std::{
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use boreas_pki::{
    NetworkRootPin, VerifiedNetworkPolicy,
    dns_authority::{DnsSignerPin, VerifiedDnsAuthority},
    dns_service_policy::VerifiedDnsServicePolicy,
};
use boreas_proto::dns_service_policy::{Capability, DnsSubject};
use boreas_tunnel::{
    dns_packet_service::{MAX_CA_BYTES, Material, PublicForward, SecureTransport, SecureUpstream},
    tls::PeerIdentity,
};
use serde::Deserialize;

use crate::network_policy_runtime::read_bounded_regular;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    Doh,
    TlsTcp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFile {
    transport: Transport,
    endpoint: SocketAddr,
    tls_name: String,
    ca_file: PathBuf,
    path: Option<String>,
    #[serde(default)]
    exclude_suffixes: Vec<String>,
}

/// Trusted launch input. Not a peer-advertised URL, credentials, or resolver.
pub(super) struct PublicUpstream {
    upstream: Arc<SecureUpstream>,
    excluded: Vec<String>,
}

impl PublicUpstream {
    pub(super) fn load(file: &Path) -> Result<Self, String> {
        if !file.is_absolute() {
            return Err("daemon: public DNS upstream file requires an absolute path".into());
        }
        let bytes = read_bounded_regular(file, 8192, "public DNS upstream config")
            .map_err(|e| format!("daemon: {e}"))?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "daemon: public DNS config is not UTF-8")?;
        let settings: UpstreamFile = toml::from_str(text)
            .map_err(|_| "daemon: invalid public DNS upstream config")?;
        let transport = match (settings.transport, settings.path) {
            (Transport::Doh, Some(path)) => SecureTransport::Https { path },
            (Transport::TlsTcp, None) => SecureTransport::TlsTcp,
            _ => return Err("daemon: specify path for DoH only".into()),
        };
        if settings.exclude_suffixes.len() > 32 || settings.exclude_suffixes.iter().any(|s| {
            s.is_empty() || s.len() > 253 || !s.split('.').all(|label| {
                !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')
                })
            })
        }) {
            return Err("daemon: invalid public DNS exclusion suffix list".into());
        }
        if !settings.ca_file.is_absolute() {
            return Err("daemon: public DNS CA file requires an absolute path".into());
        }
        let ca = read_bounded_regular(&settings.ca_file, MAX_CA_BYTES, "public DNS upstream CA")
            .map_err(|e| format!("daemon: {e}"))?;
        let upstream = SecureUpstream::new(settings.endpoint, settings.tls_name, &ca, transport)
            .map_err(|e| format!("daemon: {e}"))?;
        Ok(Self { upstream: Arc::new(upstream), excluded: settings.exclude_suffixes })
    }

    pub(super) fn bind(
        &self,
        lease: &Arc<Lease>,
        status_current: impl Fn() -> bool + Send + Sync + 'static,
    ) -> PublicForward {
        let lease = Arc::clone(lease);
        let deadline = lease.deadline;
        // Only the upstream worker samples this UTC floor. Sampling the
        // packet loop's floor here would mistake thread scheduling for rollback.
        let floor = AtomicU64::new(lease.last_utc.load(Ordering::Relaxed));
        let current = Arc::new(move || {
            if lease.retired.load(Ordering::Acquire) {
                return false;
            }
            if !status_current()
                || Instant::now() >= deadline
                || !super::now_utc_us().is_ok_and(|now| {
                    now < lease.until_utc && now >= floor.fetch_max(now, Ordering::Relaxed)
                })
            {
                lease.retired.store(true, Ordering::Release);
                return false;
            }
            !lease.retired.load(Ordering::Acquire)
        });
        PublicForward { upstream: Arc::clone(&self.upstream), excluded: self.excluded.clone(), deadline, current }
    }
}

const PIN_POLL: Duration = Duration::from_millis(100);

pub(super) struct PinnedDns {
    pin_file: PathBuf,
    pin: Vec<u8>,
    network: VerifiedNetworkPolicy,
    service: VerifiedDnsServicePolicy,
    authority: VerifiedDnsAuthority,
    pub(super) vip: Ipv4Addr,
    pub(super) tcp: bool,
    pub(super) public: bool,
    pub(super) upstream: Option<PublicUpstream>,
    until_utc: u64,
    deadline: Instant,
    loaded_utc: u64,
}

fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    read_bounded_regular(path, max, "private DNS input")
        .map_err(|e| format!("daemon: private DNS {}: {e}", path.display()))
}

struct Object {
    tbs: Vec<u8>,
    ed: Vec<u8>,
    pq: Vec<u8>,
}

impl Object {
    fn load(dir: &Path, name: &str, max_tbs: usize) -> Result<Self, String> {
        Ok(Self {
            tbs: read(&dir.join(format!("{name}.tbs")), max_tbs)?,
            ed: read(&dir.join(format!("{name}.ed25519.sig")), 64)?,
            pq: read(&dir.join(format!("{name}.mldsa65.sig")), 3309)?,
        })
    }
}

impl PinnedDns {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn load(
        dir: &Path,
        pin_file: PathBuf,
        network: VerifiedNetworkPolicy,
        root: &NetworkRootPin,
        core: PeerIdentity,
        zone: &str,
        tcp: bool,
        public: bool,
        upstream: Option<PublicUpstream>,
        identities_until: u64,
    ) -> Result<Self, String> {
        use boreas_proto::{dns_authority, dns_service_policy};

        if !dir.is_absolute() || !pin_file.is_absolute() {
            return Err("daemon: private DNS inputs require absolute paths".into());
        }
        // An independent operator-selected exact version pin, not a digest
        // learned from the submitted set. No first-use or sequence fallback.
        let dir = dir
            .canonicalize()
            .map_err(|e| format!("daemon: DNS artifact directory: {e}"))?;
        let parent = pin_file
            .parent()
            .ok_or("daemon: missing DNS pin parent")?
            .canonicalize()
            .map_err(|e| format!("daemon: DNS pin directory: {e}"))?;
        if parent.starts_with(&dir) {
            return Err("daemon: private DNS pin must be outside the artifact directory".into());
        }
        let pin_file = parent.join(
            pin_file
                .file_name()
                .ok_or("daemon: missing DNS pin filename")?,
        );
        let pin = read(&pin_file, 96)?;
        let s = Object::load(&dir, "service", dns_service_policy::MAX_TBS_LEN)?;
        let g = Object::load(&dir, "signer", dns_authority::MAX_TBS_LEN)?;
        let a = Object::load(&dir, "authority", dns_authority::MAX_TBS_LEN)?;
        let selected = [&s, &g, &a].map(|o| openssl::sha::sha256(&o.tbs)).concat();
        if selected != pin {
            return Err("daemon: private DNS version pin mismatch".into());
        }
        let context = network
            .require_default_runtime()
            .map_err(|e| format!("daemon: DNS network context: {e}"))?;
        let started = Instant::now();
        let now = super::now_utc_us()?;
        let service = VerifiedDnsServicePolicy::verify(&s.tbs, &s.ed, &s.pq, root, &network, now)
            .map_err(|e| format!("daemon: DNS service policy rejected: {e}"))?;
        let grant = DnsSignerPin::verify_grant(&g.tbs, &g.ed, &g.pq, root, &context, now)
            .map_err(|e| format!("daemon: DNS signer grant rejected: {e}"))?;
        let authority = VerifiedDnsAuthority::verify(&a.tbs, &a.ed, &a.pq, &grant, &context, now)
            .map_err(|e| format!("daemon: DNS authority rejected: {e}"))?;
        if authority.zone() != zone {
            return Err("daemon: configured quarantine suffix differs from signed DNS zone".into());
        }
        if !service.has_grant_at(
            &network,
            core.net_id,
            DnsSubject {
                node_id: core.node_id,
                identity_generation: core.identity_generation,
            },
            Capability::Replica,
            now,
        ) {
            return Err("daemon: this Core generation lacks a current DNS Replica grant".into());
        }
        if public && !service.has_grant_at(
            &network,
            core.net_id,
            DnsSubject { node_id: core.node_id, identity_generation: core.identity_generation },
            Capability::PublicForward,
            now,
        ) {
            return Err("daemon: this Core generation lacks a current DNS PublicForward grant".into());
        }
        let until_utc = authority
            .freshness()
            .1
            .min(service.validity().1)
            .min(identities_until);
        let deadline = until_utc
            .checked_sub(now)
            .and_then(|remaining| started.checked_add(Duration::from_micros(remaining)))
            .filter(|&end| Instant::now() < end)
            .ok_or("daemon: invalid or already expired DNS deadline")?;
        let [a, b, _, _] = context.overlay_base();
        Ok(Self {
            pin_file,
            pin,
            network,
            service,
            authority,
            vip: Ipv4Addr::new(a, b, 0, 53),
            tcp,
            public,
            upstream,
            until_utc,
            deadline,
            loaded_utc: now,
        })
    }

    pub(super) fn material(&self) -> Material<'_> {
        Material {
            network: &self.network,
            service: &self.service,
            authority: &self.authority,
        }
    }

    pub(super) fn bind(&self, status_until: u64, deadline: Instant, utc_floor: u64) -> Arc<Lease> {
        Arc::new(Lease {
            until_utc: self.until_utc.min(status_until),
            deadline: self.deadline.min(deadline),
            last_utc: AtomicU64::new(self.loaded_utc.max(utc_floor)),
            retired: AtomicBool::new(false),
        })
    }
}

/// Each lease has one packet-loop owner. The watchdog observes UTC separately
/// to avoid a false rollback when concurrently sampled clocks are reordered.
pub(super) struct Lease {
    until_utc: u64,
    deadline: Instant,
    last_utc: AtomicU64,
    retired: AtomicBool,
}

impl Lease {
    pub(super) fn current(&self) -> bool {
        if self.retired.load(Ordering::Acquire) {
            return false;
        }
        let now = super::now_utc_us().ok();
        if now.is_none_or(|now| {
            now >= self.until_utc || now < self.last_utc.fetch_max(now, Ordering::Relaxed)
        }) || Instant::now() >= self.deadline
        {
            self.retired.store(true, Ordering::Release);
            return false;
        }
        !self.retired.load(Ordering::Acquire)
    }
}

/// Interrupt an already-blocked transport call, without waiting for status
/// signature verification/persistence or modifying the shared status watchdog.
/// The original session and this owned duplicate refer to the same socket.
pub(super) struct Interrupt {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Interrupt {
    pub(super) fn start(
        dns: &PinnedDns,
        lease: Arc<Lease>,
        fd: OwnedFd,
        status_current: impl Fn() -> bool + Send + 'static,
    ) -> Result<Self, String> {
        let path = dns.pin_file.clone();
        let pin = dns.pin.clone();
        if read(&path, 96)? != pin || !lease.current() {
            return Err("daemon: private DNS lease or version pin lost before business".into());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("boreas-dns-lease".into())
            .spawn(move || {
                let mut last_utc = lease.last_utc.load(Ordering::Relaxed);
                while !stopped.load(Ordering::Acquire) {
                    let now = super::now_utc_us().ok();
                    if let Some(now) = now.filter(|&now| now >= last_utc && now < lease.until_utc)
                        && !lease.retired.load(Ordering::Acquire)
                        && status_current()
                        && Instant::now() < lease.deadline
                        && read(&path, 96).is_ok_and(|current| current == pin)
                    {
                        last_utc = now;
                        thread::park_timeout(
                            PIN_POLL.min(lease.deadline.saturating_duration_since(Instant::now())),
                        );
                        continue;
                    }
                    lease.retired.store(true, Ordering::Release);
                    // SAFETY: fd is still an owned duplicate of the bound socket.
                    unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
                    return;
                }
            })
            .map_err(|e| format!("daemon: cannot start private DNS lease interrupt: {e}"))?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Interrupt {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}
