use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use futures_util::StreamExt;
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient};
use noq::{Endpoint, PathId};
use rustls::RootCertStore;
use serde_json::{Value, json};
use tokio::time::timeout;
use uuid::Uuid;

const SERVER_ADDR: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    Ipv4Addr::new(192, 0, 2, 11),
    3478,
));
const SERVER_NAME: &str = "192.0.2.11";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut ca_file = None;
    let mut local_ip = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ca-file" => ca_file = args.next().map(PathBuf::from),
            "--local-ip" => {
                local_ip = Some(
                    args.next()
                        .context("--local-ip requires an IPv4 address")?
                        .parse::<Ipv4Addr>()
                        .context("parse --local-ip")?,
                )
            }
            _ => bail!(
                "usage: cargo run --example udp_qad_check -- --ca-file <PEM> --local-ip <IPv4>"
            ),
        }
    }
    let ca_file = ca_file.context("--ca-file is required")?;
    let local_ip = IpAddr::V4(local_ip.context("--local-ip is required")?);
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("install rustls ring provider"))?;
    }
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(File::open(&ca_file).context("open CA file")?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "CA file contains no certificates");
    for cert in certs {
        roots.add(cert).context("add CA certificate")?;
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let endpoint =
        Endpoint::client(SocketAddr::new(local_ip, 0)).context("bind one QAD UDP socket")?;
    let local_socket = endpoint.local_addr().context("read local QAD UDP socket")?;
    let client = QuicClient::new(endpoint.clone(), tls);
    let mut rounds = Vec::with_capacity(3);

    for round in 1..=3 {
        let started = Instant::now();
        let mut record = json!({
            "round": round,
            "probe_id": Uuid::new_v4(),
            "requested_remote": SERVER_ADDR,
            "tls_server_name": SERVER_NAME,
            "local_socket": local_socket,
            "success": false
        });
        match timeout(
            CONNECT_TIMEOUT,
            client.create_conn(SERVER_ADDR, SERVER_NAME),
        )
        .await
        {
            Err(_) => {
                record["phase"] = json!("connect");
                record["error"] = json!("QUIC QAD handshake timed out after 5 seconds");
            }
            Ok(Err(error)) => {
                record["phase"] = json!("connect");
                record["error"] = json!(error.to_string());
            }
            Ok(Ok(connection)) => {
                let handshake_ms = started.elapsed().as_millis();
                let handshake_confirmed = connection.handshake_data().is_some();
                let observed_started = Instant::now();
                let observed =
                    timeout(OBSERVE_TIMEOUT, connection.observed_external_addr().next()).await;
                let observed_addr = match observed {
                    Err(_) => {
                        record["phase"] = json!("observed_external_addr");
                        record["error"] = json!("QAD observed address timed out after 5 seconds");
                        None
                    }
                    Ok(None) => {
                        record["phase"] = json!("observed_external_addr");
                        record["error"] = json!("QAD observed-address stream ended");
                        None
                    }
                    Ok(Some(address)) => Some(address),
                };
                record["connection_stable_id"] = json!(connection.stable_id());
                record["handshake_confirmed"] = json!(handshake_confirmed);
                record["tls_verified"] = json!(handshake_confirmed);
                record["handshake_latency_ms"] = json!(handshake_ms);
                record["observed_latency_ms"] = json!(observed_started.elapsed().as_millis());
                if let Some(address) = observed_addr {
                    record["observed_external_addr"] = json!(address);
                }
                let remote_matches = if let Some(path) = connection.path(PathId::ZERO) {
                    match path.remote_address() {
                        Ok(remote) => {
                            record["remote_socket"] = json!(remote);
                            record["remote_matches_requested"] = json!(remote == SERVER_ADDR);
                            remote == SERVER_ADDR
                        }
                        Err(error) => {
                            record["error"] = json!(error.to_string());
                            false
                        }
                    }
                } else {
                    record["error"] = json!("QAD initial path unavailable");
                    false
                };
                if let Some(path) = connection.path(PathId::ZERO) {
                    let stats = path.stats();
                    let positive = stats.udp_tx.datagrams > 0
                        && stats.udp_tx.bytes > 0
                        && stats.udp_rx.datagrams > 0
                        && stats.udp_rx.bytes > 0;
                    record["udp_tx_datagrams"] = json!(stats.udp_tx.datagrams);
                    record["udp_tx_bytes"] = json!(stats.udp_tx.bytes);
                    record["udp_rx_datagrams"] = json!(stats.udp_rx.datagrams);
                    record["udp_rx_bytes"] = json!(stats.udp_rx.bytes);
                    record["rtt_ms"] =
                        json!(connection.rtt(PathId::ZERO).map(|rtt| rtt.as_millis()));
                    record["udp_counters_positive"] = json!(positive);
                    if !positive {
                        record["error"] =
                            json!("QAD path UDP counters were not positive in both directions");
                    }
                } else {
                    record["error"] = json!("QAD initial path statistics unavailable");
                }
                if !handshake_confirmed {
                    record["error"] = json!("QUIC TLS handshake data unavailable");
                }
                if !remote_matches {
                    record["error"] = json!("QUIC remote address differed from fixed B endpoint");
                }
                if observed_addr.is_some()
                    && handshake_confirmed
                    && remote_matches
                    && record.get("udp_counters_positive") == Some(&Value::Bool(true))
                {
                    record["success"] = json!(true);
                }
                record["round_latency_ms"] = json!(started.elapsed().as_millis());
                connection.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
            }
        }
        if endpoint
            .local_addr()
            .context("read reused QAD UDP socket")?
            != local_socket
        {
            record["success"] = json!(false);
            record["error"] = json!("QAD endpoint local UDP socket changed between rounds");
        }
        rounds.push(record);
    }

    let endpoint_idle = timeout(Duration::from_secs(3), endpoint.wait_idle())
        .await
        .is_ok();
    let success_count = rounds
        .iter()
        .filter(|round| round["success"] == true)
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "protocol": "Iroh QAD over QUIC/UDP",
            "server": SERVER_ADDR,
            "tls_server_name": SERVER_NAME,
            "local_socket": local_socket,
            "endpoint_idle_wait_completed": endpoint_idle,
            "success_count": success_count,
            "rounds": rounds
        }))?
    );
    if success_count != 3 || !endpoint_idle {
        bail!("one or more bounded QAD rounds failed");
    }
    Ok(())
}
