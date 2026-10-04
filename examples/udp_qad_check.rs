use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use futures_util::StreamExt;
use iroh::{RelayMode, endpoint::PathId};
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient};
use iroh_relay::tls::CaTlsConfig;
use noq::Endpoint;
use rustls::RootCertStore;
use serde_json::{Value, json};
use tokio::{
    net::lookup_host,
    time::{Instant as TokioInstant, timeout, timeout_at},
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use kmesh::{
    config::TlsConfig,
    transport::{
        MappingDiscovery, QadPlan, QadReflector, discover_ipv4_mappings, observe_ipv4_mappings,
    },
};

const SERVER_ADDR: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    Ipv4Addr::new(192, 0, 2, 11),
    3478,
));
const SERVER_NAME: &str = "192.0.2.11";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);
const OFFICIAL_PAIR_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const OFFICIAL_PAIR_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
const OFFICIAL_SINGLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    PrivateB,
    Official,
}

struct Args {
    mode: Mode,
    ca_file: Option<PathBuf>,
    local_ip: Option<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("warn,kmesh::transport::qad=debug"))
        .with_writer(std::io::stderr)
        .try_init();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("install rustls ring provider"))?;
    }
    let args = parse_args()?;
    match args.mode {
        Mode::PrivateB => run_private_b(args).await,
        Mode::Official => run_official().await,
    }
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::PrivateB;
    let mut mode_seen = false;
    let mut ca_file = None;
    let mut local_ip = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                let value = args
                    .next()
                    .context("--mode requires official or private-b")?;
                mode = match value.as_str() {
                    "official" => Mode::Official,
                    "private-b" => Mode::PrivateB,
                    _ => bail!("--mode must be official or private-b"),
                };
                mode_seen = true;
            }
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
                "usage: udp_qad_check [--mode private-b --ca-file <PEM> --local-ip <IPv4>] | [--mode official]"
            ),
        }
    }
    if mode == Mode::PrivateB {
        ensure!(
            ca_file.is_some() && local_ip.is_some(),
            "private-b mode requires --ca-file and --local-ip"
        );
    } else {
        ensure!(
            mode_seen && ca_file.is_none() && local_ip.is_none(),
            "official mode requires --mode official and uses only the default trusted root store"
        );
    }
    Ok(Args {
        mode,
        ca_file,
        local_ip,
    })
}

async fn run_private_b(args: Args) -> Result<()> {
    let ca_file = args.ca_file.context("--ca-file is required")?;
    let local_ip = IpAddr::V4(args.local_ip.context("--local-ip is required")?);
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
            "round_id": Uuid::new_v4(),
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
                let handshake_started = Instant::now();
                let handshake_confirmed =
                    match timeout(CONNECT_TIMEOUT, connection.handshake_confirmed()).await {
                        Ok(Ok(())) => true,
                        Ok(Err(error)) => {
                            record["error"] = json!(error.to_string());
                            false
                        }
                        Err(_) => {
                            record["error"] =
                                json!("QUIC handshake confirmation timed out after 5 seconds");
                            false
                        }
                    };
                let handshake_ms = handshake_started.elapsed().as_millis();
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
                    Ok(Some(address)) => {
                        Some(SocketAddr::new(address.ip().to_canonical(), address.port()))
                    }
                };
                record["connection_stable_id_local"] = json!(connection.stable_id());
                record["handshake_confirmed"] = json!(handshake_confirmed);
                record["tls_verified"] = json!(handshake_confirmed);
                record["handshake_confirmation_latency_ms"] = json!(handshake_ms);
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

async fn run_official() -> Result<()> {
    let relay_configs = RelayMode::Default.relay_map().relays::<Vec<_>>();
    ensure!(
        relay_configs.len() >= 2,
        "Iroh default relay map exposes fewer than two reflectors"
    );
    let official = relay_configs
        .into_iter()
        .take(2)
        .map(|relay| {
            let server_name = relay
                .url
                .host_str()
                .context("official relay config has no hostname")?
                .to_owned();
            let port = relay
                .quic
                .as_ref()
                .context("official relay config has no QAD QUIC settings")?
                .port;
            Ok::<_, anyhow::Error>((server_name, port))
        })
        .collect::<Result<Vec<_>>>()?;

    let pair_started = Instant::now();
    let pair_deadline = TokioInstant::now() + OFFICIAL_PAIR_ATTEMPT_TIMEOUT;
    let pair_result = discover_ipv4_mappings(
        &QadPlan::OfficialDefault,
        &TlsConfig::default(),
        pair_deadline,
    )
    .await;
    let pair_elapsed_ms = pair_started.elapsed().as_millis();
    let pair_result = match pair_result {
        Ok(MappingDiscovery::Ready(discovered)) => {
            let local_socket = discovered.local_socket;
            let observations = discovered.observations;
            drop(discovered.socket);
            let result = json!({
                "status": "ready",
                "local_socket": local_socket,
                "observations": observations,
            });
            result
        }
        Ok(MappingDiscovery::Unavailable { reason }) => json!({
            "status": "unavailable",
            "reason": reason,
        }),
        Err(error) => json!({
            "status": "error",
            "reason": format!("{error:#}"),
        }),
    };

    let mut single_reflector_results = Vec::with_capacity(official.len());
    for (index, (server_name, port)) in official.iter().enumerate() {
        let started = Instant::now();
        let deadline = TokioInstant::now() + OFFICIAL_SINGLE_TIMEOUT;
        let mut phase = "dns_ipv4";
        let mut resolved_addr = None;
        let result = async {
            let addresses = timeout_at(deadline, lookup_host((server_name.as_str(), *port)))
                .await
                .context("official reflector DNS lookup exceeded the 5-second budget")??;
            let address = addresses
                .filter_map(|address| match address {
                    SocketAddr::V4(address) => Some(address),
                    SocketAddr::V6(_) => None,
                })
                .next()
                .with_context(|| format!("official reflector {server_name} has no IPv4 address"))?;
            resolved_addr = Some(address);
            phase = "qad_handshake_observation";

            let socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .context("bind single-reflector IPv4 QAD socket")?;
            let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls = CaTlsConfig::default()
                .client_config(crypto_provider)
                .context("build TLS config with the official WebPKI trust roots")?;
            let reflector = QadReflector {
                addr: address,
                server_name: server_name.clone(),
            };
            let (socket, observations) =
                observe_ipv4_mappings(socket, tls, &[reflector], deadline, deadline)
                    .await
                    .with_context(|| format!("single official reflector QAD at {address}"))?;
            let local_socket = socket.local_addr().context("read retained QAD socket")?;
            drop(socket);
            ensure!(
                observations.len() == 1,
                "single-reflector QAD returned {} observations",
                observations.len()
            );
            Ok::<_, anyhow::Error>((local_socket, observations.into_iter().next().unwrap()))
        }
        .await;
        let elapsed_ms = started.elapsed().as_millis();
        let record = match result {
            Ok((local_socket, observation)) => json!({
                "order": index + 1,
                "configured_server_name": server_name,
                "configured_port": port,
                "resolved_ipv4": resolved_addr,
                "phase": "complete",
                "status": "ready",
                "elapsed_ms": elapsed_ms,
                "local_socket": local_socket,
                "observation": observation,
            }),
            Err(error) => json!({
                "order": index + 1,
                "configured_server_name": server_name,
                "configured_port": port,
                "resolved_ipv4": resolved_addr,
                "phase": phase,
                "status": "unavailable_or_error",
                "elapsed_ms": elapsed_ms,
                "reason": format!("{error:#}"),
            }),
        };
        single_reflector_results.push(record);
    }

    let output = json!({
        "protocol": "Iroh QAD over QUIC/UDP",
        "mode": "official_default",
        "tls_verification": "CaTlsConfig::default with embedded WebPKI trust roots; B CA is not loaded",
        "production_qad_plan": {
            "reflectors": official.iter().enumerate().map(|(index, (server_name, port))| json!({
                "order": index + 1,
                "configured_server_name": server_name,
                "quic_port": port,
            })).collect::<Vec<_>>(),
            "qad_probe_budget_ms": OFFICIAL_PAIR_PROBE_TIMEOUT.as_millis(),
            "attempt_cleanup_deadline_ms": OFFICIAL_PAIR_ATTEMPT_TIMEOUT.as_millis(),
            "elapsed_ms": pair_elapsed_ms,
            "result": pair_result,
        },
        "single_reflector_checks": single_reflector_results,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
