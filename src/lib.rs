//! REALITY protocol primitives.
//!
//! This crate intentionally keeps authentication separate from the TLS record
//! engine. The next layer consumes a parsed TLS 1.3 ClientHello and, only when
//! this module authenticates it, continues with the REALITY server handshake.

pub mod reality;
pub mod tls_client_hello;
pub mod vless;
