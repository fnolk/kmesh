//! IPv4 QAD discovery, authenticated UDP punching, and QUIC socket handoff.

mod discovery;
mod packet;
mod punch;

use std::net::{SocketAddrV4, UdpSocket as StdUdpSocket};

use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::{TransportError, iroh::HandoffOptions, qad::QadObservation};

pub use discovery::discover_ipv4_mappings;
pub use punch::PreparedPunch;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QadPlan {
    PrivateAndOfficial {
        server_url: reqwest::Url,
        udp_port: u16,
    },
    OfficialDefault,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PunchRole {
    Target,
    Client,
}

impl PunchRole {
    fn wire(self) -> u8 {
        match self {
            Self::Target => 0,
            Self::Client => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchIdentity {
    pub session_id: Uuid,
    pub target_id: EndpointId,
    pub client_id: EndpointId,
}

#[derive(Debug)]
pub struct DiscoveredUdpSocket {
    pub socket: StdUdpSocket,
    pub local_socket: SocketAddrV4,
    pub observations: Vec<QadObservation>,
    pub qad_plan: QadPlan,
}

impl DiscoveredUdpSocket {
    pub fn handoff_options(&self) -> HandoffOptions {
        HandoffOptions {
            bind_addr: self.local_socket,
            self_observed_addr: self.observations[0].observed_addr,
        }
    }
}

#[derive(Debug)]
pub enum MappingDiscovery {
    Ready(DiscoveredUdpSocket),
    Unavailable { reason: String },
}

#[derive(Debug, Error)]
pub enum PunchError {
    #[error("direct UDP path unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Fatal(#[from] TransportError),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchCounters {
    pub tx_datagrams: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchSelection {
    pub index: u16,
    pub local_socket: SocketAddrV4,
    pub peer_observed_addr: SocketAddrV4,
    pub counters: PunchCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalBindState {
    pub index: u16,
    pub bind_addr: SocketAddrV4,
}
