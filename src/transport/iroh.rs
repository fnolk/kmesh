use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, RelayConfig, RelayMap, RelayMode, SecretKey, TransportAddr,
    Watcher as _,
    endpoint::{
        Connection, NetReportConfig, PortmapperConfig, RecvStream, SendStream, VarInt, presets,
    },
};
use iroh_relay::{RelayQuicConfig, tls::CaTlsConfig};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    config::{HttpProxyConfig, TlsConfig},
    protocol::{RouteMode, SelectedPath},
    transport::{TransportError, http::validate_proxy_url},
};

pub const IROH_SSH_ALPN: &[u8] = b"kmesh/ssh/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffOptions {
    pub bind_addr: std::net::SocketAddrV4,
    pub self_observed_addr: std::net::SocketAddrV4,
}

#[derive(Clone, Debug)]
pub struct IrohEndpointOptions {
    pub relay_choice: RelayChoice,
    pub tls: TlsConfig,
    pub handoff: Option<HandoffOptions>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayChoice {
    DirectOnly,
    Private { url: reqwest::Url, quic_port: u16 },
}

pub async fn create_endpoint(
    secret_key: SecretKey,
    accept: bool,
    options: IrohEndpointOptions,
) -> Result<Endpoint, TransportError> {
    let relay_mode = match &options.relay_choice {
        RelayChoice::DirectOnly => RelayMode::Disabled,
        RelayChoice::Private { url, quic_port } => {
            if *quic_port == 0 {
                return Err(TransportError::Configuration(
                    "private relay QUIC port must be nonzero".to_owned(),
                ));
            }
            let relay_url = validate_relay_url(url.clone())?;
            let relay_map = RelayMap::from_iter([RelayConfig::new(
                relay_url,
                Some(RelayQuicConfig::new(*quic_port)),
            )]);
            RelayMode::Custom(relay_map)
        }
    };
    let alpns = if accept {
        vec![IROH_SSH_ALPN.to_vec()]
    } else {
        Vec::new()
    };

    let mut net_report_config = NetReportConfig::minimal();
    if matches!(&options.relay_choice, RelayChoice::Private { .. }) {
        // Relay-only endpoints have no IP transport for QAD, so HTTPS latency selects their home relay.
        net_report_config.https_probes = true;
    }

    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(alpns)
        .relay_mode(relay_mode)
        .net_report_config(net_report_config)
        .ca_tls_config(build_ca_tls_config(&options.tls)?);

    match (&options.relay_choice, options.handoff) {
        (RelayChoice::DirectOnly, Some(handoff)) => {
            builder = builder
                .portmapper_config(PortmapperConfig::Disabled)
                .clear_ip_transports()
                .bind_addr(SocketAddr::V4(handoff.bind_addr))
                .map_err(|error| TransportError::Configuration(error.to_string()))?;
        }
        (RelayChoice::DirectOnly, None) => {}
        (RelayChoice::Private { .. }, None) => {
            builder = builder
                .portmapper_config(PortmapperConfig::Disabled)
                .clear_ip_transports();
        }
        (RelayChoice::Private { .. }, Some(_)) => {
            return Err(TransportError::Configuration(
                "private relay-only endpoint cannot use a direct UDP handoff".to_owned(),
            ));
        }
    }

    if let Some(proxy) = &options.tls.proxy {
        builder = builder.proxy_url(build_proxy_url(proxy)?);
    }

    let endpoint = builder
        .bind()
        .await
        .map_err(|error| TransportError::Iroh(error.to_string()))?;

    if let Some(handoff) = options.handoff {
        let self_observed_addr = SocketAddr::V4(handoff.self_observed_addr);
        endpoint.add_external_addr(self_observed_addr).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut address = endpoint.watch_addr();
        loop {
            if address
                .get()
                .ip_addrs()
                .any(|candidate| *candidate == self_observed_addr)
            {
                break;
            }
            tokio::select! {
                updated = address.updated() => {
                    if updated.is_err() {
                        return Err(TransportError::EndpointClosed);
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(TransportError::Timeout("publishing the peer-observed UDP address"));
                }
            }
        }
    }

    Ok(endpoint)
}

pub async fn connect_peer(
    endpoint: &Endpoint,
    address: EndpointAddr,
    relay_choice: &RelayChoice,
) -> Result<Connection, TransportError> {
    validate_endpoint_addr(&address, relay_choice)?;
    endpoint
        .connect(address, IROH_SSH_ALPN)
        .await
        .map_err(TransportError::IrohConnect)
}

pub async fn wait_for_selected_path(
    connection: &Connection,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<SelectedPath, TransportError> {
    let mut snapshots = connection.paths_stream();
    loop {
        let snapshot = tokio::time::timeout_at(deadline, snapshots.next())
            .await
            .map_err(|_| TransportError::Timeout("waiting for route-selected Iroh path"))?
            .ok_or(TransportError::EndpointClosed)?;
        let Some(path) = snapshot.iter().find(|path| path.is_selected()) else {
            continue;
        };
        return match (route_mode, path.remote_addr()) {
            (
                RouteMode::PrivateDirect | RouteMode::PublicDirect,
                TransportAddr::Ip(remote_address),
            ) => Ok(SelectedPath::Direct {
                remote_address: *remote_address,
            }),
            (RouteMode::PrivateRelay, TransportAddr::Relay(url)) => {
                Ok(SelectedPath::PrivateRelay {
                    url: url.to_string(),
                })
            }
            (mode, remote_address) => Err(TransportError::ProtocolViolation(format!(
                "route {mode:?} selected an incompatible Iroh path {remote_address}"
            ))),
        };
    }
}

pub fn allowed_relay_urls(
    relay_choice: &RelayChoice,
) -> Result<BTreeSet<iroh::RelayUrl>, TransportError> {
    match relay_choice {
        RelayChoice::Private { url, .. } => Ok(BTreeSet::from([validate_relay_url(url.clone())?])),
        RelayChoice::DirectOnly => Ok(BTreeSet::new()),
    }
}

pub fn validate_endpoint_addr(
    address: &EndpointAddr,
    relay_choice: &RelayChoice,
) -> Result<(), TransportError> {
    let allowed = allowed_relay_urls(relay_choice)?;
    if address.relay_urls().any(|url| !allowed.contains(url)) {
        return Err(TransportError::ProtocolViolation(
            "peer address includes a relay outside the selected relay mode".to_owned(),
        ));
    }
    Ok(())
}

pub async fn accept_peer(endpoint: &Endpoint) -> Result<Connection, TransportError> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or(TransportError::EndpointClosed)?;
    incoming.await.map_err(TransportError::IrohConnecting)
}

pub fn snapshot_iroh_paths(connection: &Connection) -> Vec<IrohPathStats> {
    connection
        .paths()
        .iter()
        .filter_map(|path| {
            let kind = if path.is_ip() {
                IrohPathKind::Direct
            } else if path.is_relay() {
                IrohPathKind::Relay
            } else {
                return None;
            };
            let stats = path.stats();
            Some(IrohPathStats {
                kind,
                remote_address: path.remote_addr().to_string(),
                selected: path.is_selected(),
                udp_tx_bytes: stats.udp_tx.bytes,
                udp_rx_bytes: stats.udp_rx.bytes,
            })
        })
        .collect()
}

pub async fn wait_endpoint_ready(
    endpoint: &Endpoint,
    relay_choice: &RelayChoice,
    deadline: tokio::time::Instant,
) -> Result<(), TransportError> {
    let RelayChoice::Private { .. } = relay_choice else {
        return Ok(());
    };

    let mut status = endpoint.home_relay_status();
    loop {
        let relays = status.get();
        if relays.iter().any(|relay| relay.is_connected()) {
            return Ok(());
        }
        if let Some(reason) = relays.iter().find_map(|relay| relay.auth_denied_reason()) {
            return Err(TransportError::Authentication(reason.to_owned()));
        }
        if let Some(error) = relays
            .iter()
            .filter_map(|relay| relay.last_error())
            .find(|error| crate::transport::is_auth_failure_source(*error))
        {
            return Err(TransportError::Authentication(error.to_string()));
        }
        tokio::select! {
            update = status.updated() => {
                if update.is_err() {
                    return Err(TransportError::EndpointClosed);
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(TransportError::Timeout("Iroh relay registration"));
            }
        }
    }
}

pub struct IrohByteStream {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    send_finished: bool,
}

impl IrohByteStream {
    pub async fn open_bi(connection: Connection) -> Result<Self, TransportError> {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(TransportError::IrohConnection)?;
        Ok(Self {
            connection,
            send,
            recv,
            send_finished: false,
        })
    }

    pub async fn accept_bi(connection: Connection) -> Result<Self, TransportError> {
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(TransportError::IrohConnection)?;
        Ok(Self {
            connection,
            send,
            recv,
            send_finished: false,
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn selected_path(&self) -> Option<IrohSelectedPath> {
        let paths = self.connection.paths();
        let path = paths.iter().find(|path| path.is_selected())?;
        let kind = if path.is_ip() {
            IrohPathKind::Direct
        } else if path.is_relay() {
            IrohPathKind::Relay
        } else {
            return None;
        };
        let stats = path.stats();
        Some(IrohSelectedPath {
            kind,
            remote_address: path.remote_addr().to_string(),
            udp_tx_bytes: stats.udp_tx.bytes,
            udp_rx_bytes: stats.udp_rx.bytes,
        })
    }

    pub fn path_stats(&self) -> Vec<IrohPathStats> {
        snapshot_iroh_paths(&self.connection)
    }

    /// Sends FIN and waits until the peer acknowledges every byte written to this stream.
    ///
    /// Call this after normal bidirectional SSH EOF and before closing the connection. Use
    /// [`Self::reset`] when cancellation interrupts the copy.
    pub async fn finish_send_and_wait(&mut self) -> io::Result<()> {
        if !self.send_finished {
            self.send.shutdown().await?;
            self.send_finished = true;
        }
        match self.send.stopped().await {
            Ok(None) => Ok(()),
            Ok(Some(code)) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("peer stopped the SSH stream with code {code}"),
            )),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    /// Resets both halves of this stream after SSH cancellation.
    pub fn reset(&mut self) -> io::Result<()> {
        let send = self.send.reset(VarInt::from_u32(0));
        let recv = self.recv.stop(VarInt::from_u32(0));
        send.map_err(io::Error::other)?;
        recv.map_err(io::Error::other)
    }
}

impl AsyncRead for IrohByteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for IrohByteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buffer)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.send_finished {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.send_finished = true;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrohPathKind {
    Direct,
    Relay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrohSelectedPath {
    pub kind: IrohPathKind,
    pub remote_address: String,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrohPathStats {
    pub kind: IrohPathKind,
    pub remote_address: String,
    pub selected: bool,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
}

pub(super) fn validate_relay_url(url: reqwest::Url) -> Result<iroh::RelayUrl, TransportError> {
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(TransportError::Configuration(
            "relay URL must be an HTTP(S) origin without credentials, path, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(url.into())
}

pub(super) fn build_ca_tls_config(tls: &TlsConfig) -> Result<CaTlsConfig, TransportError> {
    let mut certificates = Vec::new();
    for path in &tls.ca_certificates {
        let file = File::open(path).map_err(|error| {
            TransportError::Configuration(format!(
                "open CA certificate file {}: {error}",
                path.display()
            ))
        })?;
        certificates.extend(
            rustls_pemfile::certs(&mut BufReader::new(file))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    TransportError::Configuration(format!(
                        "parse CA certificate file {}: {error}",
                        path.display()
                    ))
                })?,
        );
    }

    if tls.ca_certificates.is_empty() {
        Ok(CaTlsConfig::default())
    } else if certificates.is_empty() {
        Err(TransportError::Configuration(
            "configured CA certificate files contain no certificates".to_owned(),
        ))
    } else {
        Ok(CaTlsConfig::default().with_extra_roots(certificates))
    }
}

fn build_proxy_url(proxy: &HttpProxyConfig) -> Result<reqwest::Url, TransportError> {
    let mut url = validate_proxy_url(&proxy.url)?;
    match (&proxy.username, &proxy.password) {
        (Some(username), Some(password)) => {
            url.set_username(username).map_err(|_| {
                TransportError::Configuration("invalid HTTP proxy username".to_owned())
            })?;
            url.set_password(Some(password)).map_err(|_| {
                TransportError::Configuration("invalid HTTP proxy password".to_owned())
            })?;
        }
        (None, None) => {}
        _ => {
            return Err(TransportError::Configuration(
                "HTTP proxy username and password must be configured together".to_owned(),
            ));
        }
    }
    Ok(url)
}
