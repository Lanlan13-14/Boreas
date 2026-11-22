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

const POLL: Duration = Duration::from_millis(100);

type Reader<'a> = dyn Fn() -> std::io::Result<Option<Vec<u8>>> + Send + Sync + 'a;

#[derive(Default)]
pub(super) struct Mailbox<'a> {
    reader: Option<Box<Reader<'a>>>,
    // Cache only exact carrier bytes verified by the ledger, never a mere
    // path/mtime/inode match. Deletion is not an undo and clears the cache.
    last: Mutex<Option<Vec<u8>>>,
    fault: AtomicBool,
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
        if mailbox.reader.is_none() {
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
                .name("boreas-mesh-identity".into())
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
        let Some(read) = &self.reader else {
            return Ok(());
        };
        let result = (|| {
            let mut last = self.last.lock().map_err(|_| Error::RevocationState)?;
            let raw = read().map_err(|_| Error::RevocationState)?;
            if raw != *last {
                if let Some(bytes) = raw.as_deref() {
                    if bytes.len() > boreas_pki::status_store::MAX_IDENTITY_REVOCATION_BYTES {
                        return Err(Error::RevocationState);
                    }
                    match status
                        .lock()
                        .map_err(|_| Error::RevocationState)?
                        .accept_identity_revocation(bytes, utc_now()?)
                    {
                        // A newer denial for this exact scope may have arrived
                        // over a hop since the operator populated the mailbox.
                        Ok(()) | Err(boreas_pki::status_store::Error::RevocationStale) => (),
                        Err(_) => return Err(Error::RevocationState),
                    }
                }
                *last = raw;
            }
            Ok(())
        })();
        if result.is_err() {
            self.fault.store(true, Ordering::Release);
        }
        result
    }
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
