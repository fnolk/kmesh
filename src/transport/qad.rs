//! QUIC Address Discovery using an owned IPv4 UDP socket.

use std::{
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV4, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient};
use noq::{Endpoint, PathId};
use serde::{Deserialize, Serialize};
use tokio::{
    task::JoinSet,
    time::{Instant as TokioInstant, timeout_at},
};

/// One authenticated QAD reflector.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QadReflector {
    /// IPv4 reflector address and UDP port.
    pub addr: SocketAddrV4,
    /// TLS server name expected by the supplied client configuration.
    pub server_name: String,
}

/// One successful QAD observation made over the caller-owned UDP socket.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QadObservation {
    /// Authenticated reflector contacted for this observation.
    pub reflector: QadReflector,
    /// Local IPv4 tuple shared by all reflectors in this invocation.
    pub local_socket: SocketAddrV4,
    /// Public IPv4 tuple reported by the reflector over the authenticated QUIC connection.
    pub observed_addr: SocketAddrV4,
    /// Whether the reflector's TLS handshake completed and was verified.
    pub handshake_confirmed: bool,
    /// QUIC path UDP datagrams sent on the observation connection.
    pub udp_tx_datagrams: u64,
    /// QUIC path UDP datagrams received on the observation connection.
    pub udp_rx_datagrams: u64,
    /// QUIC path UDP bytes sent on the observation connection.
    pub udp_tx_bytes: u64,
    /// QUIC path UDP bytes received on the observation connection.
    pub udp_rx_bytes: u64,
}

type TaskOwner = Arc<Mutex<(bool, JoinSet<()>)>>;

/// Noq runtime which tracks the endpoint driver and connection drivers in the caller's scope.
///
/// The weak owner avoids a cycle between the task set, Noq's driver futures, and this runtime.
#[derive(Debug)]
struct TrackedTokioRuntime {
    owner: Weak<Mutex<(bool, JoinSet<()>)>>,
    delegate: noq::TokioRuntime,
}

impl noq::Runtime for TrackedTokioRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        self.delegate.new_timer(deadline)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let mut state = owner.lock().expect("QAD runtime task owner poisoned");
        if state.0 {
            return;
        }
        state.1.spawn(future);
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Box<dyn noq::AsyncUdpSocket>> {
        self.delegate.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        self.delegate.now()
    }
}

async fn join_noq_tasks(owner: &TaskOwner) -> Result<()> {
    let mut state = owner.lock().expect("QAD runtime task owner poisoned");
    state.0 = true;
    let mut tasks = std::mem::take(&mut state.1);
    drop(state);

    while let Some(result) = tasks.join_next().await {
        result.context("join QAD Noq runtime task")?;
    }
    Ok(())
}

/// Discover the external IPv4 mapping of `socket` through each QAD reflector.
///
/// A duplicated handle is passed to Noq; the owned original is returned after all Noq drivers and
/// connections have stopped. Dropping this future aborts its tracked tasks when the task owner is
/// dropped. The socket is set to nonblocking mode for Tokio I/O and is returned in that mode.
pub async fn observe_ipv4_mappings(
    socket: UdpSocket,
    tls: rustls::ClientConfig,
    targets: &[QadReflector],
    deadline: TokioInstant,
) -> Result<(UdpSocket, Vec<QadObservation>)> {
    super::ensure_rustls_provider();
    ensure!(
        !targets.is_empty(),
        "at least one QAD reflector is required"
    );
    let local_socket = socket
        .local_addr()
        .context("read owned UDP socket address")?;
    let SocketAddr::V4(local_socket) = local_socket else {
        bail!("QAD mapping discovery requires an IPv4 UDP socket");
    };
    socket
        .set_nonblocking(true)
        .context("set owned UDP socket nonblocking for Tokio")?;

    let owner: TaskOwner = Arc::new(Mutex::new((false, JoinSet::new())));
    let runtime: Arc<dyn noq::Runtime> = Arc::new(TrackedTokioRuntime {
        owner: Arc::downgrade(&owner),
        delegate: noq::TokioRuntime,
    });
    let quic_socket = socket
        .try_clone()
        .context("clone owned UDP socket for Noq")?;
    let endpoint = Endpoint::new(
        noq::EndpointConfig::default(),
        None,
        quic_socket,
        runtime.clone(),
    )
    .context("create QAD Noq endpoint on the owned UDP socket")?;
    let client = QuicClient::new(endpoint.clone(), tls);
    let mut observations = Vec::with_capacity(targets.len());

    for reflector in targets {
        let connection = timeout_at(
            deadline,
            client.create_conn(reflector.addr.into(), &reflector.server_name),
        )
        .await
        .with_context(|| format!("QAD QUIC connect to {}", reflector.addr))?
        .with_context(|| format!("QAD QUIC connect to {}", reflector.addr))?;
        timeout_at(deadline, connection.handshake_confirmed())
            .await
            .with_context(|| format!("QAD TLS handshake to {}", reflector.addr))?
            .with_context(|| format!("QAD TLS handshake to {}", reflector.addr))?;

        let observed = timeout_at(deadline, connection.observed_external_addr().next())
            .await
            .with_context(|| format!("QAD observed-address report from {}", reflector.addr))?
            .context("QAD observed-address stream ended")?;
        let observed = SocketAddr::new(observed.ip().to_canonical(), observed.port());
        let SocketAddr::V4(observed_addr) = observed else {
            bail!(
                "QAD reflector {} reported a non-IPv4 address",
                reflector.addr
            );
        };

        let path = connection
            .path(PathId::ZERO)
            .context("QAD initial path is unavailable")?;
        let remote = path.remote_address().context("read QAD remote address")?;
        ensure!(
            remote == SocketAddr::V4(reflector.addr),
            "QAD path remote address {remote} differs from requested reflector {}",
            reflector.addr
        );
        let stats = path.stats();
        ensure!(
            stats.udp_tx.datagrams > 0
                && stats.udp_rx.datagrams > 0
                && stats.udp_tx.bytes > 0
                && stats.udp_rx.bytes > 0,
            "QAD path to {} has no bidirectional UDP statistics",
            reflector.addr
        );
        observations.push(QadObservation {
            reflector: reflector.clone(),
            local_socket,
            observed_addr,
            handshake_confirmed: true,
            udp_tx_datagrams: stats.udp_tx.datagrams,
            udp_rx_datagrams: stats.udp_rx.datagrams,
            udp_tx_bytes: stats.udp_tx.bytes,
            udp_rx_bytes: stats.udp_rx.bytes,
        });
        connection.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
    }

    drop(client);
    endpoint.close(0u16.into(), b"QAD observation complete");
    timeout_at(deadline, endpoint.wait_idle())
        .await
        .context("wait for QAD Noq connections to drain")?;
    drop(endpoint);
    drop(runtime);
    timeout_at(deadline, join_noq_tasks(&owner))
        .await
        .context("wait for QAD Noq drivers to stop")??;

    Ok((socket, observations))
}

#[cfg(test)]
mod tests {
    use super::{TaskOwner, TrackedTokioRuntime, join_noq_tasks};
    use noq::Runtime as _;
    use std::sync::{Arc, Mutex};
    use tokio::{sync::oneshot, task::JoinSet};

    #[tokio::test]
    async fn dropping_task_owner_aborts_noq_tasks() {
        let owner: TaskOwner = Arc::new(Mutex::new((false, JoinSet::new())));
        let runtime = TrackedTokioRuntime {
            owner: Arc::downgrade(&owner),
            delegate: noq::TokioRuntime,
        };
        let (sender, receiver) = oneshot::channel::<()>();
        runtime.spawn(Box::pin(async move {
            let _sender = sender;
            std::future::pending::<()>().await;
        }));

        drop(runtime);
        drop(owner);

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), receiver).await;
        assert!(matches!(result, Ok(Err(_))));
    }

    #[tokio::test]
    async fn joining_task_owner_waits_for_noq_tasks() {
        let owner: TaskOwner = Arc::new(Mutex::new((false, JoinSet::new())));
        let runtime = TrackedTokioRuntime {
            owner: Arc::downgrade(&owner),
            delegate: noq::TokioRuntime,
        };
        let (sender, receiver) = oneshot::channel::<()>();
        runtime.spawn(Box::pin(async move {
            let _ = sender.send(());
        }));

        drop(runtime);
        join_noq_tasks(&owner).await.unwrap();

        assert!(receiver.await.is_ok());
        assert!(owner.lock().unwrap().0);
    }
}
