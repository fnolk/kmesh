use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub profile: String,
    pub server_url: String,
    pub data_dir: PathBuf,
    pub tls: TlsConfig,
    pub ssh: SshConfig,
    pub stun: StunConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "default".to_owned(),
            server_url: "https://localhost:443".to_owned(),
            data_dir: default_data_dir(),
            tls: TlsConfig::default(),
            ssh: SshConfig::default(),
            stun: StunConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub ca_certificates: Vec<PathBuf>,
    pub server_name: Option<String>,
    pub proxy: Option<HttpProxyConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SshConfig {
    pub address: SocketAddr,
    pub connect_timeout_secs: u64,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            address: SocketAddr::from(([127, 0, 0, 1], 22)),
            connect_timeout_secs: 10,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StunConfig {
    pub servers: Vec<String>,
    pub udp_bind_address: SocketAddr,
    pub probe_timeout_millis: u64,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            udp_bind_address: SocketAddr::from(([0, 0, 0, 0], 0)),
            probe_timeout_millis: 2_000,
        }
    }
}

fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .expect("resolve the operating system's per-user data directory")
        .join("kmesh")
}
