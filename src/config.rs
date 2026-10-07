use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub auth: AuthConfig,
    pub server_addr: String,
    pub server_port: u16,
    pub data_dir: PathBuf,
    pub tls: TlsConfig,
    pub ssh: SshConfig,
    pub server: ServerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "default".to_owned(),
            auth: AuthConfig::default(),
            server_addr: "localhost".to_owned(),
            server_port: 9443,
            data_dir: default_data_dir(),
            tls: TlsConfig::default(),
            ssh: SshConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginMethod {
    Token,
    PublicKey,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub method: Option<LoginMethod>,
    pub username: Option<String>,
    pub key: Option<PathBuf>,
    pub token: Option<String>,
}

impl Config {
    pub fn default_config_path() -> PathBuf {
        dirs::home_dir()
            .expect("resolve the user's home directory")
            .join(".kmesh")
            .join("config.toml")
    }

    pub fn server_origin(&self) -> anyhow::Result<String> {
        server_origin(&self.server_addr, self.server_port)
    }
}

pub fn server_origin(server_addr: &str, server_port: u16) -> anyhow::Result<String> {
    ensure!(server_port != 0, "server port must be between 1 and 65535");
    ensure!(
        !server_addr.is_empty()
            && server_addr == server_addr.trim()
            && !server_addr.contains("://")
            && !server_addr
                .chars()
                .any(|character| matches!(character, '/' | '?' | '#' | '@')),
        "server address must be an IP address or hostname without a scheme or path"
    );

    let unbracketed = server_addr
        .strip_prefix('[')
        .and_then(|addr| addr.strip_suffix(']'))
        .unwrap_or(server_addr);
    let host = match unbracketed.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => address.to_string(),
        Ok(std::net::IpAddr::V6(address)) => format!("[{address}]"),
        Err(_) => {
            ensure!(
                !server_addr.contains(':')
                    && !server_addr.contains('[')
                    && !server_addr.contains(']'),
                "server address must be an IP address or hostname without a scheme or path"
            );
            server_addr.to_owned()
        }
    };
    canonical_origin(&format!("https://{host}:{server_port}"))
}

pub fn canonical_origin(server_url: &str) -> anyhow::Result<String> {
    let url = Url::parse(server_url).context("parse server URL")?;
    ensure!(
        url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
        "server URL must be an origin without a path, query, or fragment"
    );
    ensure!(url.scheme() == "https", "server URL must use HTTPS");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "server URL cannot include credentials"
    );
    Ok(url.origin().ascii_serialization())
}

pub(crate) fn resolve_path(path: &Path, base_dir: &Path) -> PathBuf {
    let path_text = path.to_string_lossy();
    if path_text == "~" {
        return dirs::home_dir().expect("resolve the user's home directory");
    }
    if let Some(home_relative) = path_text.strip_prefix("~/") {
        return dirs::home_dir()
            .expect("resolve the user's home directory")
            .join(home_relative);
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_certificates: Vec<PathBuf>,
    pub server_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind_addr: std::net::IpAddr,
    pub udp_port: u16,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub disable_private_relay: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            udp_port: 3478,
            tls_cert: None,
            tls_key: None,
            disable_private_relay: false,
        }
    }
}

fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .expect("resolve the user's home directory")
        .join(".cache")
        .join("kmesh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_the_requested_user_paths_and_ports() {
        let config = Config::default();
        let home = dirs::home_dir().expect("home directory");
        assert_eq!(
            Config::default_config_path(),
            home.join(".kmesh/config.toml")
        );
        assert_eq!(config.data_dir, home.join(".cache/kmesh"));
        assert_eq!(config.server_addr, "localhost");
        assert_eq!(config.server_port, 9443);
        assert_eq!(config.server.udp_port, 3478);
        assert!(config.auth.method.is_none());
        assert!(config.auth.username.is_none());
        assert!(config.auth.key.is_none());
        assert!(config.auth.token.is_none());
    }

    #[test]
    fn auth_method_serializes_as_the_cli_value() {
        assert_eq!(
            toml::from_str::<AuthConfig>("method = \"public-key\"")
                .unwrap()
                .method,
            Some(LoginMethod::PublicKey)
        );
        assert_eq!(
            toml::from_str::<AuthConfig>("method = \"token\"")
                .unwrap()
                .method,
            Some(LoginMethod::Token)
        );
    }

    #[test]
    fn server_origin_joins_https_and_accepts_ipv4_ipv6_and_hostnames() {
        assert_eq!(
            server_origin("example.test", 9443).unwrap(),
            "https://example.test:9443"
        );
        assert_eq!(
            server_origin("192.0.2.10", 9443).unwrap(),
            "https://192.0.2.10:9443"
        );
        assert_eq!(
            server_origin("2001:db8::1", 9443).unwrap(),
            "https://[2001:db8::1]:9443"
        );
        assert!(server_origin("https://example.test", 9443).is_err());
        assert!(server_origin("example.test/path", 9443).is_err());
        assert!(server_origin("example.test", 0).is_err());
    }

    #[test]
    fn config_paths_resolve_relative_to_config_or_home() {
        let config_dir = Path::new("/etc/kmesh");
        assert_eq!(
            resolve_path(Path::new("certs/ca.pem"), config_dir),
            config_dir.join("certs/ca.pem")
        );
        assert_eq!(
            resolve_path(Path::new("~/.cache/kmesh"), config_dir),
            dirs::home_dir().unwrap().join(".cache/kmesh")
        );
    }
}
