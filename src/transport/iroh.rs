use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader},
    pin::Pin,
    task::{Context, Poll},
};

use iroh::{
    Endpoint, EndpointAddr, RelayConfig, RelayMap, RelayMode, SecretKey,
    endpoint::{
        Connection, NetReportConfig, PortmapperConfig, RecvStream, SendStream, VarInt, presets,
    },
};
use iroh_relay::{RelayQuicConfig, tls::CaTlsConfig};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    config::{HttpProxyConfig, TlsConfig},
    transport::{TransportError, http::validate_proxy_url},
};

pub const IROH_SSH_ALPN: &[u8] = b"kmesh/ssh/1";

#[derive(Clone, Debug)]
pub struct IrohEndpointOptions {
    pub relay_choice: RelayChoice,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayChoice {
    Private { url: reqwest::Url, qad_port: u16 },
    PublicDefault,
}

pub async fn create_endpoint(
    secret_key: SecretKey,
    accept: bool,
    options: IrohEndpointOptions,
) -> Result<Endpoint, TransportError> {
    let relay_mode = match &options.relay_choice {
        RelayChoice::Private { url, qad_port } => {
            if *qad_port == 0 {
                return Err(TransportError::Configuration(
                    "QAD port must be nonzero".to_owned(),
                ));
            }
            let relay_url = validate_relay_url(url.clone())?;
            let relay_map = RelayMap::from_iter([RelayConfig::new(
                relay_url,
                Some(RelayQuicConfig::new(*qad_port)),
            )]);
            RelayMode::Custom(relay_map)
        }
        RelayChoice::PublicDefault => RelayMode::Default,
    };
    let alpns = if accept {
        vec![IROH_SSH_ALPN.to_vec()]
    } else {
        Vec::new()
    };

    let mut net_report = NetReportConfig::default();
    net_report.captive_portal_check = false;

    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(alpns)
        .relay_mode(relay_mode)
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(net_report)
        .ca_tls_config(build_ca_tls_config(&options.tls)?);

    if let Some(proxy) = &options.tls.proxy {
        builder = builder.proxy_url(build_proxy_url(proxy)?);
    }

    builder
        .bind()
        .await
        .map_err(|error| TransportError::Iroh(error.to_string()))
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

pub fn allowed_relay_urls(
    relay_choice: &RelayChoice,
) -> Result<BTreeSet<iroh::RelayUrl>, TransportError> {
    match relay_choice {
        RelayChoice::Private { url, .. } => Ok(BTreeSet::from([validate_relay_url(url.clone())?])),
        RelayChoice::PublicDefault => Ok(RelayMode::Default.relay_map().urls::<BTreeSet<_>>()),
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
    incoming
        .await
        .map_err(|error| TransportError::Iroh(error.to_string()))
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
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
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
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
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
        Some(IrohSelectedPath {
            kind,
            remote_address: path.remote_addr().to_string(),
        })
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
}

fn validate_relay_url(url: reqwest::Url) -> Result<iroh::RelayUrl, TransportError> {
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

fn build_ca_tls_config(tls: &TlsConfig) -> Result<CaTlsConfig, TransportError> {
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
