#![forbid(unsafe_code)]

pub mod config;
pub mod identity;
shadow_rs::shadow!(build);

pub mod protocol;
mod target_id;
pub mod version;

// Owned by the server, transport, and client implementation workstreams.
pub mod client;
pub mod server;
pub mod transport;
