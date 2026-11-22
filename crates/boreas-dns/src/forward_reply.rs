#[cfg(feature = "secure-upstream")]
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, TryRecvError},
    },
    task::Poll,
};

pub(crate) enum Reply {
    Ready(Vec<u8>),
    #[cfg(feature = "secure-upstream")]
    Pending(PendingReply),
    Drop,
}

#[cfg(feature = "secure-upstream")]
#[derive(Debug)]
pub(crate) struct PendingReply {
    pub(crate) result: Receiver<Vec<u8>>,
    pub(crate) canceled: Arc<AtomicBool>,
}

#[cfg(feature = "secure-upstream")]
impl PendingReply {
    pub(crate) fn poll(&self) -> Poll<Option<Vec<u8>>> {
        match self.result.try_recv() {
            Ok(response) => Poll::Ready(Some(response)),
            Err(TryRecvError::Disconnected) => Poll::Ready(None),
            Err(TryRecvError::Empty) => Poll::Pending,
        }
    }
}

#[cfg(feature = "secure-upstream")]
impl Drop for PendingReply {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
    }
}
