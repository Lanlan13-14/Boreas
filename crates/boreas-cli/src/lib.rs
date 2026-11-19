//! Library surface used by the `boreas` binary's integration tests.
//!
//! The binary remains the daemon. This crate only exposes the revocation gate so
//! `tests/revoke_runtime.rs` can drive it without spawning a TUN device. It is
//! empty unless `openssl-inner-tls` is enabled on Linux.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
#![forbid(unsafe_code)]

pub mod daemon_revoke;
