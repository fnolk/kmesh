#![forbid(unsafe_code)]

pub mod config;
pub mod identity;
pub mod protocol;

// Owned by the server, transport, and client implementation workstreams.
pub mod client;
pub mod server;
pub mod transport;
