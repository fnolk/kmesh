use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use iroh::endpoint::PathEvent;
use tokio::io::AsyncWriteExt;

use crate::transport::{IrohByteStream, IrohPathKind, IrohPathStats, snapshot_iroh_paths};

fn path_status_message(
    selected: Option<&(IrohPathKind, String)>,
    reported_initial: bool,
) -> String {
    match selected {
        Some((kind, remote_address)) => {
            let label = match kind {
                IrohPathKind::Direct => "direct P2P",
                IrohPathKind::Relay => "Iroh relay",
            };
            let status = if reported_initial {
                "Connection path changed"
            } else {
                "Connection path"
            };
            format!(
                "{status}: {label} ({})",
                super::super::output::cell(remote_address)
            )
        }
        None if reported_initial => {
            "No network path is selected. Iroh is selecting a new path.".to_owned()
        }
        None => "Connection established. Iroh is selecting a network path.".to_owned(),
    }
}

pub(super) async fn copy_stdio(stream: &mut IrohByteStream) -> Result<(u64, u64)> {
    let path_connection = stream.connection().clone();
    let path_task = tokio::spawn(async move {
        let mut path_snapshots = path_connection.paths_stream();
        let mut path_events = path_connection.path_events();
        let mut previous = HashMap::<String, IrohPathStats>::new();
        let mut previous_selected = None;
        let mut reported_initial = false;
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                biased;
                snapshot = path_snapshots.next() => {
                    let Some(snapshot) = snapshot else { break; };
                    let selected = snapshot
                        .iter()
                        .find(|path| path.is_selected())
                        .and_then(|path| {
                            let kind = if path.is_ip() {
                                IrohPathKind::Direct
                            } else if path.is_relay() {
                                IrohPathKind::Relay
                            } else {
                                return None;
                            };
                            Some((kind, path.remote_addr().to_string()))
                        });
                    if !reported_initial || selected != previous_selected {
                        eprintln!("{}", path_status_message(selected.as_ref(), reported_initial));
                        previous_selected = selected;
                        reported_initial = true;
                    }
                }
                _ = ticker.tick(), if tracing::enabled!(tracing::Level::TRACE) => {
                    for current in snapshot_iroh_paths(&path_connection) {
                        if let Some(before) = previous.get(&current.remote_address) {
                            tracing::trace!(
                                "QUIC path UDP interval ({}) kind={:?} selected={} TX delta={} RX delta={}",
                                current.remote_address,
                                current.kind,
                                current.selected,
                                current.udp_tx_bytes.saturating_sub(before.udp_tx_bytes),
                                current.udp_rx_bytes.saturating_sub(before.udp_rx_bytes),
                            );
                        } else {
                            tracing::trace!(
                                "QUIC path UDP baseline ({}) kind={:?} selected={} TX={} RX={}",
                                current.remote_address,
                                current.kind,
                                current.selected,
                                current.udp_tx_bytes,
                                current.udp_rx_bytes,
                            );
                        }
                        previous.insert(current.remote_address.clone(), current);
                    }
                }
                event = path_events.next() => {
                    let Some(event) = event else { break; };
                    match event {
                        PathEvent::Opened { id, remote_addr, .. } => {
                            if let Some(path) = path_connection.paths().iter().find(|path| path.id() == id) {
                                let kind = if path.is_relay() { IrohPathKind::Relay } else { IrohPathKind::Direct };
                                let stats = path.stats();
                                previous.insert(remote_addr.to_string(), IrohPathStats {
                                    kind,
                                    remote_address: remote_addr.to_string(),
                                    selected: path.is_selected(),
                                    udp_tx_bytes: stats.udp_tx.bytes,
                                    udp_rx_bytes: stats.udp_rx.bytes,
                                });
                                tracing::trace!(remote_address = %remote_addr, udp_tx_bytes = stats.udp_tx.bytes, udp_rx_bytes = stats.udp_rx.bytes, "QUIC path opened");
                            }
                        }
                        PathEvent::Selected { id, remote_addr, .. } => {
                            if let Some(path) = path_connection.paths().iter().find(|path| path.id() == id) {
                                let kind = if path.is_relay() { IrohPathKind::Relay } else { IrohPathKind::Direct };
                                let stats = path.stats();
                                previous.insert(remote_addr.to_string(), IrohPathStats {
                                    kind,
                                    remote_address: remote_addr.to_string(),
                                    selected: true,
                                    udp_tx_bytes: stats.udp_tx.bytes,
                                    udp_rx_bytes: stats.udp_rx.bytes,
                                });
                            }
                        }
                        PathEvent::Closed { remote_addr, last_stats, .. } => {
                            if let Some(before) = previous.remove(&remote_addr.to_string()) {
                                tracing::trace!(
                                    "QUIC path closed ({remote_addr}) UDP final TX={} RX={} delta TX={} RX={}",
                                    last_stats.udp_tx.bytes,
                                    last_stats.udp_rx.bytes,
                                    last_stats.udp_tx.bytes.saturating_sub(before.udp_tx_bytes),
                                    last_stats.udp_rx.bytes.saturating_sub(before.udp_rx_bytes),
                                );
                            } else {
                                tracing::trace!(remote_address = %remote_addr, udp_tx_bytes = last_stats.udp_tx.bytes, udp_rx_bytes = last_stats.udp_rx.bytes, "QUIC path closed");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    let copy_result = async {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let paths_before = stream.path_stats();
        let transferred = {
            let (mut reader, mut writer) = tokio::io::split(&mut *stream);
            let upload = async {
                let bytes = tokio::io::copy(&mut stdin, &mut writer).await?;
                writer.shutdown().await?;
                Ok::<_, std::io::Error>(bytes)
            };
            let download = async {
                let bytes = tokio::io::copy(&mut reader, &mut stdout).await?;
                stdout.flush().await?;
                Ok::<_, std::io::Error>(bytes)
            };
            let (upload, download) =
                tokio::try_join!(upload, download).context("copy bidirectional SSH stdio")?;
            (upload, download)
        };
        let paths_after = stream.path_stats();
        let selected_path = stream.selected_path();
        tracing::debug!(
            paths_before = ?paths_before,
            paths_after = ?paths_after,
            ssh_upload_bytes = transferred.0,
            ssh_download_bytes = transferred.1,
            selected_path = ?selected_path,
            "SSH QUIC path snapshots"
        );
        for after in &paths_after {
            if let Some(before) = paths_before.iter().find(|before| {
                before.kind == after.kind && before.remote_address == after.remote_address
            }) {
                tracing::debug!(
                    "QUIC path UDP delta ({}) kind={:?} selected_before={} selected_after={} TX={} RX={}",
                    after.remote_address,
                    after.kind,
                    before.selected,
                    after.selected,
                    after.udp_tx_bytes.saturating_sub(before.udp_tx_bytes),
                    after.udp_rx_bytes.saturating_sub(before.udp_rx_bytes),
                );
            } else {
                tracing::debug!(
                    "QUIC path UDP snapshot ({}) kind={:?} selected_after={} baseline_missing=true TX={} RX={}",
                    after.remote_address,
                    after.kind,
                    after.selected,
                    after.udp_tx_bytes,
                    after.udp_rx_bytes,
                );
            }
        }
        stream
            .finish_send_and_wait()
            .await
            .context("wait for target to acknowledge final SSH bytes")?;
        stream
            .connection()
            .close(iroh::endpoint::VarInt::from_u32(0), b"ssh session complete");
        Ok::<_, anyhow::Error>((transferred.0, transferred.1))
    }
    .await;
    path_task.abort();
    let _ = path_task.await;
    copy_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_status_uses_english_for_each_connection_state() {
        let direct = (IrohPathKind::Direct, "192.0.2.1:5000".to_owned());
        let relay = (IrohPathKind::Relay, "https://relay.example".to_owned());
        assert_eq!(
            path_status_message(Some(&direct), false),
            "Connection path: direct P2P (192.0.2.1:5000)"
        );
        assert_eq!(
            path_status_message(Some(&relay), true),
            "Connection path changed: Iroh relay (https://relay.example)"
        );
        assert_eq!(
            path_status_message(None, false),
            "Connection established. Iroh is selecting a network path."
        );
        assert_eq!(
            path_status_message(None, true),
            "No network path is selected. Iroh is selecting a new path."
        );
    }

    #[test]
    fn path_status_escapes_terminal_controls_in_addresses() {
        let relay = (IrohPathKind::Relay, "relay\n\x1b[31m".to_owned());
        assert_eq!(
            path_status_message(Some(&relay), false),
            "Connection path: Iroh relay (relay\\n\\u{1b}[31m)"
        );
    }
}
