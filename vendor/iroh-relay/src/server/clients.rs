//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::SystemTime,
};

use dashmap::DashMap;
use iroh_base::EndpointId;
use n0_future::IterExt;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::{
    ConnectionId, OnDisconnectGuard,
    client::{Client, Config, ForwardPacketError},
};
use crate::{
    protos::{
        relay::{Datagrams, Status},
        streams::BytesStreamSink,
    },
    server::{client::SendError, metrics::Metrics},
};

/// Traffic counters and connection identity for a relay client.
#[derive(Debug, Clone)]
pub struct RelayConnectionStats {
    /// Endpoint authenticated by the relay handshake.
    pub endpoint_id: EndpointId,
    /// Process-unique identity of this transport connection.
    pub connection_id: ConnectionId,
    /// Time this connection was registered with the relay.
    pub connected_at: SystemTime,
    /// Whether this connection currently receives packets addressed to its endpoint.
    pub active: bool,
    /// Payload bytes successfully decoded from this client and accepted by the relay.
    ///
    /// This includes ingress packets later dropped because their destination is unavailable or
    /// its send queue is full. Protocol control frames are excluded.
    pub bytes_received: u64,
    /// Payload bytes successfully written by the relay to this client. Protocol control frames
    /// are excluded.
    pub bytes_sent: u64,
}

/// Point-in-time view of relay connections and process-lifetime payload traffic.
#[derive(Debug, Clone)]
pub struct RelayTrafficSnapshot {
    /// Time at which this snapshot was sampled.
    pub sampled_at: SystemTime,
    /// All currently registered relay transports, including inactive duplicate endpoint
    /// connections.
    pub connections: Vec<RelayConnectionStats>,
    /// Payload bytes decoded from clients since this relay process started.
    pub bytes_received: u64,
    /// Payload bytes successfully written to clients since this relay process started.
    pub bytes_sent: u64,
}

#[derive(Debug, Default)]
pub(super) struct TrafficCounters {
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
}

impl TrafficCounters {
    pub(super) fn snapshot(&self) -> (u64, u64) {
        (
            self.bytes_received.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
        )
    }
}

/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
#[derive(Debug, Clone, Default)]
pub struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    /// Process-lifetime payload totals, retained after connections unregister.
    traffic: TrafficCounters,
    /// Serializes reservation, registration, and disconnect so in-flight handshakes cannot miss
    /// an administrative disconnect between authorization and client registration.
    registration_gate: Mutex<()>,
    pending: DashMap<ConnectionId, PendingRegistration>,
    shutting_down: AtomicBool,
}

#[derive(Debug)]
struct PendingRegistration {
    endpoint_id: EndpointId,
    cancellation: CancellationToken,
}

#[derive(Debug)]
pub(super) struct RegistrationLease {
    clients: Clients,
    endpoint_id: EndpointId,
    connection_id: ConnectionId,
    cancellation: CancellationToken,
}

impl Drop for RegistrationLease {
    fn drop(&mut self) {
        self.clients
            .0
            .pending
            .remove_if(&self.connection_id, |_, pending| {
                pending.endpoint_id == self.endpoint_id
            });
    }
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    /// Returns current relay transports and process-lifetime payload traffic totals.
    ///
    /// Received bytes count decoded datagram payloads, including payloads whose forwarding later
    /// fails. Sent bytes count datagram payloads after the relay successfully writes them to the
    /// destination connection. Protocol control frames do not contribute to either counter.
    pub fn traffic_snapshot(&self) -> RelayTrafficSnapshot {
        let mut connections = Vec::new();
        for entry in self.0.clients.iter() {
            let state = entry.value();
            connections.push(state.active.stats(true));
            connections.extend(state.inactive.iter().map(|client| client.stats(false)));
        }
        let (bytes_received, bytes_sent) = self.0.traffic.snapshot();
        RelayTrafficSnapshot {
            sampled_at: SystemTime::now(),
            connections,
            bytes_received,
            bytes_sent,
        }
    }

    pub(super) fn record_received(&self, connection: &TrafficCounters, bytes: u64) {
        connection
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
        self.0
            .traffic
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub(super) fn record_sent(&self, connection: &TrafficCounters, bytes: u64) {
        connection.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.0
            .traffic
            .bytes_sent
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Shuts down all connected clients.
    ///
    /// This method cancels all active and pending client connections managed by this registry.
    /// It waits for registered actors to unregister before returning; queued outbound frames are
    /// dropped with their connections.
    pub async fn shutdown(&self) {
        {
            let _gate = self
                .0
                .registration_gate
                .lock()
                .expect("relay endpoint registration gate is not poisoned");
            self.0.shutting_down.store(true, Ordering::Release);
            let pending_ids = self
                .0
                .pending
                .iter()
                .map(|entry| *entry.key())
                .collect::<Vec<_>>();
            for connection_id in pending_ids {
                if let Some((_, pending)) = self.0.pending.remove(&connection_id) {
                    pending.cancellation.cancel();
                }
            }
        }
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        n0_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    pub(super) fn reserve_registration(
        &self,
        endpoint_id: EndpointId,
        connection_id: ConnectionId,
    ) -> RegistrationLease {
        let _gate = self
            .0
            .registration_gate
            .lock()
            .expect("relay endpoint registration gate is not poisoned");
        let cancellation = CancellationToken::new();
        if self.0.shutting_down.load(Ordering::Acquire) {
            cancellation.cancel();
        } else {
            self.0.pending.insert(
                connection_id,
                PendingRegistration {
                    endpoint_id,
                    cancellation: cancellation.clone(),
                },
            );
        }
        RegistrationLease {
            clients: self.clone(),
            endpoint_id,
            connection_id,
            cancellation,
        }
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    ///
    /// Once the client disconnects, the [`OnDisconnectGuard`] set in `config` will be dropped,
    /// allowing callers to be notified of the disconnect.
    pub fn register<S>(&self, client_config: Config<S>, metrics: Arc<Metrics>) -> bool
    where
        S: BytesStreamSink + Send + 'static,
    {
        let lease = self.reserve_registration(
            client_config.guard.endpoint_id,
            client_config.guard.connection_id,
        );
        self.register_reserved(client_config, metrics, lease)
    }

    pub(super) fn register_reserved<S>(
        &self,
        client_config: Config<S>,
        metrics: Arc<Metrics>,
        lease: RegistrationLease,
    ) -> bool
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.guard.endpoint_id;
        let connection_id = client_config.guard.connection_id;
        debug_assert!(Arc::ptr_eq(&self.0, &lease.clients.0));
        debug_assert_eq!(endpoint_id, lease.endpoint_id);
        debug_assert_eq!(connection_id, lease.connection_id);
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let gate = self
            .0
            .registration_gate
            .lock()
            .expect("relay endpoint registration gate is not poisoned");
        self.0.pending.remove(&connection_id);
        if lease.cancellation.is_cancelled() || self.0.shutting_down.load(Ordering::Acquire) {
            metrics.accepts.inc();
            metrics.disconnects.inc();
            drop(gate);
            drop(client_config);
            debug!(
                remote_endpoint = %endpoint_id.fmt_short(),
                "rejecting a relay transport cancelled during authorization"
            );
            return false;
        }

        let client = Client::new(
            client_config,
            self,
            metrics.clone(),
            lease.cancellation.clone(),
        );
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health(Status::SameEndpointIdConnected)
                    .ok();
                state.inactive.push(old_client);
                metrics.clients_inactive_added.inc();
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
        }
        drop(gate);
        true
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, guard: OnDisconnectGuard, metrics: &Metrics) {
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            %connection_id, "unregistering client"
        );

        let mut notify_peers = None;

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    metrics.clients_inactive_removed.inc();
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Inform the old client that it is healthy again.
                    state.active.try_send_health(Status::Healthy).ok();
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: collect sent_to set for peer-gone notifications.
                    notify_peers = self.0.sent_to.remove(&endpoint_id).map(|(_, peers)| peers);
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                metrics.clients_inactive_removed.inc();
                // Active client is unmodified: keep entry in map.
                false
            }
        });

        // Inform peers that this endpoint is gone.
        // Done outside the remove_if_mut closure to avoid DashMap deadlocks.
        if let Some(peers) = notify_peers {
            for peer_id in peers {
                if let Some(peer) = self.0.clients.get(&peer_id) {
                    match peer.active.try_send_peer_gone(endpoint_id) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "client too busy to receive peer gone notification, dropping"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "can no longer write to client, dropping peer gone notification"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Disconnects connections registered for `endpoint_id`.
    ///
    /// With `Some(connection_id)`, disconnects only that connection (active or
    /// an inactive duplicate) and cancels its pending authorization handshake. With `None`,
    /// disconnects every current and pending connection for the endpoint. Returns `true` if a
    /// matching connection was found, or `false` otherwise.
    ///
    /// Shutdown happens asynchronously: cancellation interrupts the actor's current stream I/O,
    /// drops queued frames, and then unregisters the transport.
    pub fn disconnect(&self, endpoint_id: EndpointId, connection_id: Option<ConnectionId>) -> bool {
        let _gate = self
            .0
            .registration_gate
            .lock()
            .expect("relay endpoint registration gate is not poisoned");
        let pending_ids = self
            .0
            .pending
            .iter()
            .filter(|entry| {
                entry.value().endpoint_id == endpoint_id
                    && connection_id.is_none_or(|id| id == *entry.key())
            })
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for id in &pending_ids {
            if let Some((_, pending)) = self.0.pending.remove(id) {
                pending.cancellation.cancel();
            }
        }
        let mut found = !pending_ids.is_empty();
        let Some(state) = self.0.clients.get(&endpoint_id) else {
            return found;
        };
        let mut clients = state.inactive.iter().chain([&state.active]);
        if let Some(id) = connection_id {
            if let Some(client) = clients.find(|c| c.connection_id() == id) {
                client.start_shutdown();
                found = true;
            }
        } else {
            for client in clients {
                client.start_shutdown();
                found = true;
            }
        }
        found
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        metrics: &Metrics,
    ) -> Result<(), ForwardPacketError> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
            return Ok(());
        };
        match client.active.try_send_packet(src, data) {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<ConnectionId> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt};
    use n0_future::{Sink, SinkExt, Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use tokio::sync::{Notify, oneshot};

    use super::*;
    use crate::{
        KeyCache,
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{
            common::FrameType,
            relay::{ClientToRelayMsg, RelayToClientMsg},
            streams::{StreamError, WsBytesFramed},
        },
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    struct BlockingFlushSink {
        flush_started: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for BlockingFlushSink {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl Stream for BlockingFlushSink {
        type Item = std::result::Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<Bytes> for BlockingFlushSink {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.get_mut().flush_started.notify_one();
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    n0_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => n0_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn disconnect_cancels_a_pending_stream_flush_and_unregisters() {
        let endpoint_id = SecretKey::generate().public();
        let flush_started = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = BlockingFlushSink {
            flush_started: flush_started.clone(),
            dropped: dropped.clone(),
        };
        let config = Config::new(
            OnDisconnectGuard::empty(endpoint_id),
            crate::server::streams::RelayedStream::new(stream, KeyCache::new(16)),
            ProtocolVersion::default(),
        );
        let clients = Clients::default();
        clients.register(config, Arc::new(Metrics::default()));

        {
            let client = clients
                .0
                .clients
                .get(&endpoint_id)
                .expect("registered blocking-flush client");
            client
                .active
                .try_send_health(Status::Healthy)
                .expect("queue a relay control frame");
        }
        tokio::time::timeout(Duration::from_secs(1), flush_started.notified())
            .await
            .expect("actor did not enter the blocked flush");

        assert!(clients.disconnect(endpoint_id, None));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !clients.0.clients.contains_key(&endpoint_id) && dropped.load(Ordering::Acquire)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("cancelled actor did not unregister and drop its stream");
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // send packet
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.active.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone());
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone());
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        // send packet and verify it is send to a2
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));

        // a1 is marked active again and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::Healthy));

        // a1 should receive packets
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_peer_gone_notification() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // Register both clients
        let (builder_a, _a_rw) = test_client_builder(a_key);
        let (builder_b, mut b_rw) = test_client_builder(b_key);
        clients.register(builder_a, metrics.clone());
        clients.register(builder_b, metrics.clone());

        // A sends a packet to B (records sent_to[A] = {B})
        let data = b"hello b!";
        clients.send_packet(b_key, Datagrams::from(&data[..]), a_key, &metrics)?;

        // B receives the packet
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: data.to_vec().into(),
            }
        );

        // Disconnect A
        {
            let client = clients.0.clients.get(&a_key).unwrap();
            client.active.start_shutdown();
        }

        // Wait for A to unregister
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout waiting for A to unregister")?;

        // B should receive EndpointGone(a_key): notifying B that A is gone
        let frame = recv_frame(FrameType::EndpointGone, &mut b_rw).await?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(a_key));

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn disconnect_cancels_a_handshake_before_client_registration() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(23u64);
        let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let (builder, mut client_rw) = test_client_builder(endpoint_id);
        let connection_id = builder.guard.connection_id();
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let registration = clients.reserve_registration(endpoint_id, connection_id);
        let (authorized_tx, authorized_rx) = oneshot::channel();
        let (continue_tx, continue_rx) = oneshot::channel();
        let register_clients = clients.clone();

        // Model AccessControl allowing this endpoint while the relay handshake is paused before
        // it finishes writing the confirmation frame and registers the Client actor.
        let registration_task = tokio::spawn(async move {
            authorized_tx
                .send(())
                .expect("notify authorization reached");
            continue_rx.await.expect("resume the pending handshake");
            register_clients.register_reserved(builder, metrics, registration)
        });
        authorized_rx
            .await
            .std_context("wait for allowed handshake")?;

        assert!(clients.disconnect(endpoint_id, Some(connection_id)));
        continue_tx.send(()).expect("resume handshake registration");
        assert!(!registration_task.await.std_context("join registration")?);
        assert!(clients.traffic_snapshot().connections.is_empty());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match client_rw.next().await {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                }
            }
        })
        .await
        .std_context("wait for rejected relay transport to close")?;

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn traffic_snapshot_counts_payloads_and_retains_totals_after_disconnect() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(17u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();
        let idle_key = SecretKey::from_bytes(&rng.random()).public();
        let (a_builder, mut a_rw) = test_client_builder(a_key);
        let (b_builder, mut b_rw) = test_client_builder(b_key);
        let (idle_builder, _idle_rw) = test_client_builder(idle_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(a_builder, metrics.clone());
        clients.register(b_builder, metrics.clone());
        clients.register(idle_builder, metrics);

        let initial = clients.traffic_snapshot();
        assert_eq!(initial.bytes_received, 0);
        assert_eq!(initial.bytes_sent, 0);
        assert_eq!(initial.connections.len(), 3);
        assert!(
            initial
                .connections
                .iter()
                .all(|connection| connection.bytes_received == 0 && connection.bytes_sent == 0)
        );

        a_rw.send(ClientToRelayMsg::Ping(*b"pingpong")).await?;
        assert_eq!(
            recv_frame(FrameType::Pong, &mut a_rw).await?,
            RelayToClientMsg::Pong(*b"pingpong")
        );
        let after_control = clients.traffic_snapshot();
        assert_eq!(after_control.bytes_received, 0);
        assert_eq!(after_control.bytes_sent, 0);

        let a_to_b = b"from a";
        a_rw.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_key,
            datagrams: Datagrams::from(&a_to_b[..]),
        })
        .await?;
        assert_eq!(
            recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: a_to_b.to_vec().into(),
            }
        );

        let b_to_a = b"from b";
        b_rw.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: a_key,
            datagrams: Datagrams::from(&b_to_a[..]),
        })
        .await?;
        assert_eq!(
            recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: b_to_a.to_vec().into(),
            }
        );

        let a_to_missing = b"undeliverable";
        let missing_key = SecretKey::from_bytes(&rng.random()).public();
        a_rw.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: missing_key,
            datagrams: Datagrams::from(&a_to_missing[..]),
        })
        .await?;
        a_rw.send(ClientToRelayMsg::Ping(*b"barrier!")).await?;
        assert_eq!(
            recv_frame(FrameType::Pong, &mut a_rw).await?,
            RelayToClientMsg::Pong(*b"barrier!")
        );

        let snapshot = clients.traffic_snapshot();
        assert_eq!(
            snapshot.bytes_received,
            (a_to_b.len() + b_to_a.len() + a_to_missing.len()) as u64
        );
        assert_eq!(snapshot.bytes_sent, (a_to_b.len() + b_to_a.len()) as u64);
        let stats = |endpoint_id| {
            snapshot
                .connections
                .iter()
                .find(|connection| connection.endpoint_id == endpoint_id)
                .unwrap()
        };
        assert_eq!(
            stats(a_key).bytes_received,
            (a_to_b.len() + a_to_missing.len()) as u64
        );
        assert_eq!(stats(a_key).bytes_sent, b_to_a.len() as u64);
        assert_eq!(stats(b_key).bytes_received, b_to_a.len() as u64);
        assert_eq!(stats(b_key).bytes_sent, a_to_b.len() as u64);
        assert_eq!(stats(idle_key).bytes_received, 0);
        assert_eq!(stats(idle_key).bytes_sent, 0);

        let b_connection_id = stats(b_key).connection_id;
        assert!(clients.disconnect(b_key, Some(b_connection_id)));
        tokio::time::timeout(Duration::from_secs(1), async {
            while clients
                .traffic_snapshot()
                .connections
                .iter()
                .any(|connection| connection.connection_id == b_connection_id)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .std_context("wait for relay disconnect")?;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match b_rw.next().await {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                }
            }
        })
        .await
        .std_context("wait for relay transport close")?;

        let after_disconnect = clients.traffic_snapshot();
        assert_eq!(after_disconnect.bytes_received, snapshot.bytes_received);
        assert_eq!(after_disconnect.bytes_sent, snapshot.bytes_sent);
        assert!(after_disconnect.connections.iter().all(|connection| {
            connection.endpoint_id != b_key && connection.connection_id != b_connection_id
        }));

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn disconnect_connection_id_only_closes_that_transport_after_replacement() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(19u64);
        let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let (first_builder, mut first_rw) = test_client_builder(endpoint_id);
        let (second_builder, mut second_rw) = test_client_builder(endpoint_id);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        clients.register(first_builder, metrics.clone());
        let first_id = clients.active_connection_id(endpoint_id).unwrap();
        clients.register(second_builder, metrics);
        let second_id = clients.active_connection_id(endpoint_id).unwrap();
        assert_ne!(first_id, second_id);

        assert!(clients.disconnect(endpoint_id, Some(first_id)));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let connections = clients.traffic_snapshot().connections;
                if connections.len() == 1 && connections[0].connection_id == second_id {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .std_context("wait for selected connection disconnect")?;

        second_rw.send(ClientToRelayMsg::Ping(*b"liveping")).await?;
        assert_eq!(
            recv_frame(FrameType::Pong, &mut second_rw).await?,
            RelayToClientMsg::Pong(*b"liveping")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match first_rw.next().await {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                }
            }
        })
        .await
        .std_context("wait for selected transport close")?;

        assert_eq!(
            clients
                .traffic_snapshot()
                .connections
                .first()
                .unwrap()
                .connection_id,
            second_id
        );
        clients.shutdown().await;
        Ok(())
    }
}
