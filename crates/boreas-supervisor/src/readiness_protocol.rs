//! Shared wire-format constants for the binary readiness server and library client.

pub(crate) const CHALLENGE_MAGIC: &str = "BOREAS-READY-1";
pub(crate) const RESPONSE_MAGIC: &str = "BOREAS-READY-OK";
pub(crate) const MAX_LINE_BYTES: usize = 512;
pub(crate) const MAX_SCHEMA_BYTES: usize = 64;
pub(crate) const MAX_WORKERS: u32 = 4096;
