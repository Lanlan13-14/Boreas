//! One scoped owner watches the operator mailbox during a dedicated circuit.
//! Only the status ledger is shared: TLS, E2E and admission ownership stay on
//! the operation thread. A watcher can only shut down owned socket clones.

use std::{
    net::Shutdown,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use super::*;
use boreas_proto::authority_revocation::{
    MAX_IDENTITY_REVOCATION_BYTES, MAX_SCOPED_REVOCATION_BYTES, RevocationClass,
    SCOPED_REVOCATION_MAILBOXES,
};
use std::io;

const POLL: Duration = Duration::from_millis(100);

type Reader<'a> = dyn Fn() -> io::Result<Option<Vec<u8>>> + Send + Sync + 'a;
type ScopedReader<'a> = dyn Fn(&str) -> io::Result<Option<Vec<u8>>> + Send + Sync + 'a;
const SCOPED_COUNT: usize = SCOPED_REVOCATION_MAILBOXES.len();

#[derive(Default)]
pub(super) struct Mailbox<'a> {
    reader: Option<Box<Reader<'a>>>,
    scoped_reader: Option<Box<ScopedReader<'a>>>,
    // Cache only exact carrier bytes verified by the ledger, never a mere
    // path/mtime/inode match. Deletion is not an undo and clears the cache.
    last: Mutex<Last>,
    fault: AtomicBool,
}

#[derive(Default)]
struct Last {
    identity: Option<Vec<u8>>,
    scoped: [Option<Vec<u8>>; SCOPED_COUNT],
}

impl<'a> MeshProbe<'a> {
    /// Register a bounded local mailbox reader before running operations. It
    /// supplies bytes, not authority: every changed carrier goes through the
    /// same root-bound durable verifier as other submissions. The reader must
    /// return promptly and must not acquire mesh state or perform network I/O.
    pub fn set_identity_revocation_mailbox(
        &mut self,
        read: impl Fn() -> std::io::Result<Option<Vec<u8>>> + Send + Sync + 'a,
    ) {
        self.live_identity.reader = Some(Box::new(read));
    }

    /// Register local Core, Route and Direct mailbox delivery. Filename and
    /// carrier framing do not confer authority; the ledger verifies both.
    pub fn set_scoped_revocation_mailboxes(
        &mut self,
        read: impl Fn(&str) -> io::Result<Option<Vec<u8>>> + Send + Sync + 'a,
    ) {
        self.live_identity.scoped_reader = Some(Box::new(read));
    }

    pub(crate) fn poll_identity_mailbox(&self) -> Result<(), Error> {
        self.live_identity.poll(&self.status)
    }

    /// Poll even if neither peer is sending, or a TLS/frame read/write is
    /// blocked. Report the local cause instead of an induced EOF/reset, so
    /// the source must not misclassify its own cancellation as path loss.
    pub(crate) fn with_live_identity<T>(
        &self,
        members: &[Core],
        remote_lsa_expiry: u64,
        sockets: &[&TcpStream],
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.poll_identity_mailbox()?;
        self.check_route_utc(members, remote_lsa_expiry)?;
        let mailbox = &self.live_identity;
        if mailbox.reader.is_none() && mailbox.scoped_reader.is_none() {
            return operation();
        }
        let sockets = sockets
            .iter()
            .map(|socket| socket.try_clone())
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| Error::RevocationState)?;
        let stop = Stop::default();
        thread::scope(|scope| {
            let stop = &stop;
            let worker = thread::Builder::new()
                .name("boreas-mesh-revocation".into())
                .spawn_scoped(scope, move || {
                    while !stop.wait() {
                        let outcome = mailbox
                            .poll(&self.status)
                            .and_then(|()| self.check_route_utc(members, remote_lsa_expiry));
                        if let Err(error) = outcome {
                            for socket in &sockets {
                                let _ = socket.shutdown(Shutdown::Both);
                            }
                            return Err(error);
                        }
                    }
                    Ok(())
                })
                .map_err(|_| Error::RevocationState)?;
            let armed = SignalOnDrop(stop);
            let result = operation();
            drop(armed);
            worker.join().map_err(|_| Error::RevocationState)??;
            // Resolve a publication at the completion boundary (including
            // transport errors) before the caller may retry a fresh path.
            self.poll_identity_mailbox()?;
            self.check_route_utc(members, remote_lsa_expiry)?;
            result
        })
    }
}

impl Mailbox<'_> {
    pub(super) fn check_fault(&self) -> Result<(), Error> {
        if self.fault.load(Ordering::Acquire) {
            Err(Error::RevocationState)
        } else {
            Ok(())
        }
    }

    fn poll(&self, status: &Mutex<&mut StatusStore>) -> Result<(), Error> {
        self.check_fault()?;
        let result = (|| {
            let mut last = self.last.lock().map_err(|_| Error::RevocationState)?;
            self.check_fault()?;
            if let Some(read) = &self.reader {
                update(status, &mut last.identity, read(), RevocationClass::Identity)?;
            }
            if let Some(read) = &self.scoped_reader {
                for ((class, name), cache) in SCOPED_REVOCATION_MAILBOXES.iter().zip(&mut last.scoped) {
                    update(status, cache, read(name), *class)?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.fault.store(true, Ordering::Release);
        }
        result
    }
}

fn update(
    status: &Mutex<&mut StatusStore>,
    last: &mut Option<Vec<u8>>,
    raw: io::Result<Option<Vec<u8>>>,
    class: RevocationClass,
) -> Result<(), Error> {
    let raw = raw.map_err(|_| Error::RevocationState)?;
    if raw == *last {
        return Ok(());
    }
    if let Some(bytes) = raw.as_deref() {
        let identity = class == RevocationClass::Identity;
        let max = if identity { MAX_IDENTITY_REVOCATION_BYTES } else { MAX_SCOPED_REVOCATION_BYTES };
        if bytes.len() > max {
            return Err(Error::RevocationState);
        }
        let mut store = status.lock().map_err(|_| Error::RevocationState)?;
        let now = utc_now()?;
        let result = if identity { store.accept_identity_revocation(bytes, now) }
            else { store.accept_scoped_revocation(class, bytes, now) };
        match result {
            // The floor already contains a verified denial for this exact scope.
            Ok(()) | Err(boreas_pki::status_store::Error::RevocationStale) => (),
            Err(_) => return Err(Error::RevocationState),
        }
    }
    *last = raw;
    Ok(())
}

#[derive(Default)]
struct Stop {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl Stop {
    fn wait(&self) -> bool {
        let stopped = self.stopped.lock().unwrap_or_else(|p| p.into_inner());
        let (stopped, _) = self
            .wake
            .wait_timeout_while(stopped, POLL, |stopped| !*stopped)
            .unwrap_or_else(|p| p.into_inner());
        *stopped
    }
}

struct SignalOnDrop<'a>(&'a Stop);

impl Drop for SignalOnDrop<'_> {
    fn drop(&mut self) {
        let mut stopped = self.0.stopped.lock().unwrap_or_else(|p| p.into_inner());
        *stopped = true;
        self.0.wake.notify_one();
    }
}
