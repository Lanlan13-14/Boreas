//! Bounded worker used only by the explicitly authorized packet dispatcher.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

use crate::{
    MAX_RESPONSE_BYTES, Question, is_in_zone, truncate_parsed,
    forward_reply::{PendingReply, Reply},
    secure_upstream::{EXCHANGE_TIMEOUT, SecureUpstream},
};

const QUEUED: usize = 4;
// Count both the active exchange and queued work, even if the originating
// packet/stream is canceled. Separate from the common DNS rate budget.
pub(crate) const MAX_PENDING: usize = QUEUED + 1;

struct Job {
    query: Vec<u8>,
    question: Question,
    udp_ceiling: Option<usize>,
    deadline: Instant,
    result: SyncSender<Vec<u8>>,
    canceled: Arc<AtomicBool>,
}

pub(crate) struct Forwarder {
    queue: Option<SyncSender<Job>>,
    worker: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    lease_deadline: Instant,
    excluded: Vec<String>,
}

impl Forwarder {
    pub(crate) fn new(
        upstream: Arc<SecureUpstream>,
        excluded: Vec<String>,
        lease_deadline: Instant,
        current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUED);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let live = Arc::clone(&current);
        let worker = thread::Builder::new().name("boreas-public-dns".into()).spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let Ok(job) = rx.recv() else { break };
                let gate = || {
                    !stopped.load(Ordering::Acquire)
                        && !job.canceled.load(Ordering::Acquire)
                        && live()
                };
                if !gate() || Instant::now() >= job.deadline {
                    continue;
                }
                let response = upstream.exchange(&job.query, &job.question, job.deadline, &gate);
                if !gate() {
                    continue;
                }
                let response = match response {
                    Ok(reply) => fit_udp(&job.query, &job.question, job.udp_ceiling, reply),
                    Err(_) => servfail(&job.query, &job.question, job.udp_ceiling),
                };
                if let Some(response) = response {
                    let _ = job.result.try_send(response);
                }
            }
        })?;
        Ok(Self { queue: Some(tx), worker: Some(worker), stop, lease_deadline, excluded })
    }

    pub(crate) fn submit(&self, query: &[u8], question: Question, udp: Option<usize>) -> Reply {
        // One signed authority suffix was already routed locally. Other
        // private namespaces are excluded here, before job creation or I/O.
        const SPECIAL: &[&str] = &[
            "local", "localhost", "internal", "home.arpa", "in-addr.arpa", "ip6.arpa",
            "invalid", "test", "example", "onion", "alt",
        ];
        if !question.name.contains('.')
            || SPECIAL.iter().any(|suffix| is_in_zone(&question.name, suffix))
            || self.excluded.iter().any(|suffix| is_in_zone(&question.name, suffix))
            || Instant::now() >= self.lease_deadline
            || !crate::upstream::forwardable(&question, query)
        {
            return Reply::Drop;
        }
        let (send, result) = mpsc::sync_channel(1);
        let canceled = Arc::new(AtomicBool::new(false));
        let job = Job {
            query: query.to_vec(),
            question,
            udp_ceiling: udp,
            deadline: self.lease_deadline.min(Instant::now() + EXCHANGE_TIMEOUT),
            result: send,
            canceled: Arc::clone(&canceled),
        };
        if let Some(queue) = &self.queue
            && queue.try_send(job).is_ok()
        {
            Reply::Pending(PendingReply { result, canceled })
        } else {
            Reply::Drop
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.queue.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn limit(q: &Question, ceiling: usize) -> usize {
    ceiling.min(q.edns_size.unwrap_or(512).clamp(512, MAX_RESPONSE_BYTES))
}

fn fit_udp(query: &[u8], q: &Question, udp: Option<usize>, response: Vec<u8>) -> Option<Vec<u8>> {
    if let Some(ceiling) = udp
        && response.len() > limit(q, ceiling)
    {
        return truncate_parsed(query, q, limit(q, ceiling), q.edns_size.is_some()).ok();
    }
    Some(response)
}

fn servfail(query: &[u8], q: &Question, udp: Option<usize>) -> Option<Vec<u8>> {
    let mut reply = truncate_parsed(query, q, udp.map_or(MAX_RESPONSE_BYTES, |n| limit(q, n)), false).ok()?;
    reply[2] &= !2; // TC clear: an explicit failure, not a request to retry.
    reply[3] = 2;
    Some(reply)
}
