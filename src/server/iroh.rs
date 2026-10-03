use std::{
    convert::Infallible, error::Error as StdError, fmt, future::Future, io::BufReader,
    net::SocketAddr, path::Path, pin::Pin, sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, service::Service};
use hyper_util::rt::TokioIo;
use iroh::EndpointId;
use iroh_relay::{
    KeyCache,
    server::{
        Access, AccessControl, ClientRequest, DynAccessControl, Metrics,
        QuicConfig as IrohQuicConfig, Server as IrohRelayServer, ServerConfig as IrohServerConfig,
        http_server::{BytesBody, Handlers, HyperError, RelayService, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use super::ServerState;

type BoxError = Box<dyn StdError + Send + Sync>;
type ResponseBody = UnsyncBoxBody<Bytes, BoxError>;

pub struct IrohServer {
    https_addr: SocketAddr,
    qad_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    https_task: Option<JoinHandle<Result<()>>>,
    qad_server: IrohRelayServer,
    relay_service: Option<RelayService>,
}

impl IrohServer {
    pub fn https_addr(&self) -> SocketAddr {
        self.https_addr
    }

    pub fn qad_addr(&self) -> SocketAddr {
        self.qad_addr
    }

    pub async fn run_until_shutdown(mut self) -> Result<()> {
        let outcome = tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("wait for shutdown signal").map(|()| ())
            }
            result = self.https_task.as_mut().expect("HTTPS task exists") => {
                self.https_task.take();
                match result {
                    Ok(Ok(())) => Err(anyhow!("kmesh HTTPS listener stopped unexpectedly")),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(anyhow!(error).context("join kmesh HTTPS listener")),
                }
            }
            result = self.qad_server.join() => {
                match result {
                    Ok(Ok(())) => Err(anyhow!("Iroh QAD listener stopped unexpectedly")),
                    Ok(Err(error)) => Err(anyhow!(error).context("Iroh QAD listener failed")),
                    Err(error) => Err(anyhow!(error).context("join Iroh QAD listener")),
                }
            }
        };
        if let Some(relay_service) = self.relay_service.as_ref() {
            relay_service.shutdown().await;
        }
        self.qad_server
            .shutdown()
            .await
            .map_err(|error| anyhow!(error))
            .context("shut down Iroh QAD listener")?;
        self.shutdown.send_replace(true);
        if let Some(https_task) = self.https_task {
            https_task.await.context("join kmesh HTTPS listener")??;
        }
        outcome
    }

    pub async fn shutdown(self) -> Result<()> {
        let Self {
            shutdown,
            https_task,
            qad_server,
            relay_service,
            ..
        } = self;
        if let Some(relay_service) = relay_service {
            relay_service.shutdown().await;
        }
        qad_server
            .shutdown()
            .await
            .map_err(|error| anyhow!(error))
            .context("shut down Iroh QAD listener")?;
        shutdown.send_replace(true);
        https_task
            .context("kmesh HTTPS task already joined")?
            .await
            .context("join kmesh HTTPS listener")??;
        Ok(())
    }
}

pub async fn listen_and_serve(
    router: Router,
    relay_access: Option<Arc<dyn DynAccessControl>>,
    https_bind: SocketAddr,
    qad_bind: SocketAddr,
    tls_cert: impl AsRef<Path>,
    tls_key: impl AsRef<Path>,
) -> Result<IrohServer> {
    let server_tls = load_server_tls(tls_cert, tls_key)?;
    let listener = TcpListener::bind(https_bind)
        .await
        .with_context(|| format!("bind kmesh HTTPS listener at {https_bind}"))?;
    let https_addr = listener
        .local_addr()
        .context("read kmesh HTTPS listener address")?;

    let relay_service = relay_access.map(|relay_access| {
        RelayService::new(
            relay_handlers(),
            hyper::HeaderMap::new(),
            None,
            KeyCache::new(1024),
            relay_access,
            Arc::new(Metrics::default()),
        )
    });
    let relay_service_with_notify = relay_service.as_ref().map(|relay_service| {
        RelayServiceWithNotify::new(relay_service.clone(), Arc::new(Notify::new()))
    });

    let mut qad_config = IrohServerConfig::default();
    let mut quic_config = IrohQuicConfig::new(qad_bind);
    quic_config.server_config = Some((*server_tls).clone());
    qad_config.quic = Some(quic_config);
    let qad_server = IrohRelayServer::spawn(qad_config)
        .await
        .with_context(|| format!("bind Iroh QAD listener at {qad_bind}"))?;
    let qad_addr = qad_server
        .quic_addr()
        .context("Iroh QAD listener did not report its bound address")?;

    let tls_acceptor = TlsAcceptor::from(server_tls);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let https_task = tokio::spawn(serve_https(
        listener,
        tls_acceptor,
        router,
        relay_service_with_notify,
        shutdown_rx,
    ));

    Ok(IrohServer {
        https_addr,
        qad_addr,
        shutdown,
        https_task: Some(https_task),
        qad_server,
        relay_service,
    })
}

impl AccessControl for ServerState {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let endpoint_id: EndpointId = request.endpoint_id();
        match self
            .inner
            .db
            .endpoint_can_use_relay(&endpoint_id.to_string())
            .await
        {
            Ok(true) => Access::Allow,
            Ok(false) => Access::Deny {
                reason: Some("EndpointId is not registered for kmesh".to_owned()),
            },
            Err(error) => {
                tracing::error!(endpoint = %endpoint_id, error = %error, "Iroh relay authorization lookup failed");
                Access::Deny {
                    reason: Some("EndpointId authorization failed".to_owned()),
                }
            }
        }
    }
}

impl fmt::Debug for ServerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerState")
            .field("issuer", &self.inner.issuer)
            .finish_non_exhaustive()
    }
}

async fn serve_https(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    router: Router,
    relay: Option<RelayServiceWithNotify>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    if error.is_panic() {
                        return Err(error).context("HTTPS connection task panicked");
                    }
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept HTTPS connection")?;
                let tls_acceptor = tls_acceptor.clone();
                let service = CombinedService { router: router.clone(), relay: relay.clone(), peer };
                connections.spawn(async move {
                    if let Err(error) = serve_connection(stream, tls_acceptor, service).await {
                        tracing::debug!(peer = %peer, error = %error, "HTTPS connection ended");
                    }
                });
            }
        }
    }
    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result
            && error.is_panic()
        {
            return Err(error).context("HTTPS connection task panicked during shutdown");
        }
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    service: CombinedService,
) -> Result<()> {
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls_acceptor.accept(stream),
    )
    .await
    .context("HTTPS handshake timed out")?
    .context("complete HTTPS handshake")?;
    let io = TokioIo::new(MaybeTlsStream::Tls(tls_stream));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Some(std::time::Duration::from_secs(10)))
        .max_headers(64)
        .max_buf_size(32 * 1024);
    builder
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .context("serve HTTPS/relay HTTP connection")
}

#[derive(Clone)]
struct CombinedService {
    router: Router,
    relay: Option<RelayServiceWithNotify>,
    peer: SocketAddr,
}

impl Service<Request<Incoming>> for CombinedService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let peer = self.peer;
        let is_iroh_path = request.method() == Method::GET
            && matches!(
                request.uri().path(),
                "/relay"
                    | "/"
                    | "/index.html"
                    | "/ping"
                    | "/robots.txt"
                    | "/healthz"
                    | "/generate_204"
            );
        if is_iroh_path && self.relay.is_some() {
            let relay = self.relay.clone().expect("checked above");
            Box::pin(async move {
                let response = relay.call(request).await?;
                Ok(response.map(box_relay_body))
            })
        } else {
            let router = self.router.clone();
            Box::pin(async move {
                let mut request = request;
                request
                    .extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                let response = router
                    .oneshot(request)
                    .await
                    .map_err(|never| match never {})?;
                Ok(response.map(box_axum_body))
            })
        }
    }
}

fn box_relay_body(body: BytesBody) -> ResponseBody {
    body.map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn box_axum_body(body: axum::body::Body) -> ResponseBody {
    body.map_err(|error| Box::new(error) as BoxError)
        .boxed_unsync()
}

fn relay_handlers() -> Handlers {
    let mut handlers = Handlers::default();
    handlers.insert(
        (Method::GET, "/"),
        Box::new(|_, response| {
            let body: BytesBody = Box::new(Full::from(Bytes::from_static(
                b"<!doctype html><title>Iroh Relay</title><h1>Iroh Relay</h1>",
            )));
            response
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(body)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers.insert(
        (Method::GET, "/index.html"),
        Box::new(|_, response| {
            let body: BytesBody = Box::new(Full::from(Bytes::from_static(
                b"<!doctype html><title>Iroh Relay</title><h1>Iroh Relay</h1>",
            )));
            response
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(body)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers.insert(
        (Method::GET, "/ping"),
        Box::new(|_, response| {
            response
                .status(StatusCode::OK)
                .header("Access-Control-Allow-Origin", "*")
                .body(Box::new(Full::new(Bytes::new())) as BytesBody)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers.insert(
        (Method::GET, "/robots.txt"),
        Box::new(|_, response| {
            let body: BytesBody = Box::new(Full::from(Bytes::from_static(
                b"User-agent: *\nDisallow: /\n",
            )));
            response
                .status(StatusCode::OK)
                .body(body)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers.insert(
        (Method::GET, "/healthz"),
        Box::new(|_, response| {
            response
                .status(StatusCode::OK)
                .body(Box::new(Full::from(Bytes::from_static(b"ok"))) as BytesBody)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers.insert(
        (Method::GET, "/generate_204"),
        Box::new(|request, mut response| {
            let challenge = request
                .headers()
                .get("X-Iroh-Challenge")
                .and_then(|value| value.to_str().ok())
                .filter(|value| {
                    !value.is_empty()
                        && value.len() < 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                        })
                });
            if let Some(challenge) = challenge {
                response = response.header("X-Iroh-Response", format!("response {challenge}"));
            }
            response
                .status(StatusCode::NO_CONTENT)
                .body(Box::new(Full::new(Bytes::new())) as BytesBody)
                .map_err(|error| Box::new(error) as HyperError)
        }),
    );
    handlers
}

fn load_server_tls(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>> {
    let cert_file = std::fs::File::open(cert_path.as_ref())
        .with_context(|| format!("open TLS certificate {}", cert_path.as_ref().display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse HTTPS certificate chain")?;
    if certs.is_empty() {
        bail!("HTTPS certificate chain is empty");
    }
    let key_file = std::fs::File::open(key_path.as_ref())
        .with_context(|| format!("open TLS private key {}", key_path.as_ref().display()))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("parse HTTPS private key")?
        .context("HTTPS private key is empty")?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build HTTPS and Iroh QAD TLS configuration")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
