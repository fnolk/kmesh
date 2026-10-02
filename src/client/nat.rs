use std::{collections::HashMap, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use tokio::{net::lookup_host, time::timeout};

use crate::{
    config::StunConfig,
    protocol::{LocalCandidate, NatObservation, StunMapping},
    transport::{LocalCandidate as TransportLocalCandidate, StunMappingObservation, UdpAttempt},
};

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const STUN_TIMEOUT: Duration = Duration::from_millis(750);

pub async fn diagnose(config: &StunConfig, servers: &[String]) -> Result<()> {
    ensure!(
        servers.len() == 3 && servers[0] == servers[2],
        "provide three --stun endpoints in A-B-A order"
    );

    let mut config = config.clone();
    config.servers.clear();
    let ipv4 = config.udp_bind_address.is_ipv4();
    let mut attempt = UdpAttempt::bind(config).await?;
    let local_candidates = attempt.gather().await?;
    let destinations = resolve_destinations(servers, ipv4).await?;
    ensure!(
        destinations[0] != destinations[1],
        "A and B must resolve to different UDP destinations"
    );

    println!("本次 NAT 诊断使用一个 UDP socket，按 A-B-A 顺序探测：");
    println!("本机候选：{}", format_candidates(&local_candidates));

    let mut mappings = Vec::with_capacity(destinations.len());
    let mut complete = true;
    for (index, destination) in destinations.iter().enumerate() {
        let observation = timeout(
            STUN_TIMEOUT,
            attempt.observe_stun_mappings(std::slice::from_ref(destination)),
        )
        .await;
        match observation {
            Err(_) => {
                println!(
                    "STUN[{}] destination={} timeout_ms={}",
                    index + 1,
                    destination,
                    STUN_TIMEOUT.as_millis()
                );
                mappings.push(None);
                complete = false;
            }
            Ok(Err(error)) => {
                println!(
                    "STUN[{}] destination={} failed={}",
                    index + 1,
                    destination,
                    error
                );
                mappings.push(None);
                complete = false;
            }
            Ok(Ok(mut observations)) => {
                let observation = observations.pop().context("STUN observation missing")?;
                match observation.outcome {
                    Ok(mapped) => {
                        println!(
                            "STUN[{}] socket={} destination={} mapped={} rtt_ms={}",
                            index + 1,
                            observation.local_socket,
                            observation.destination,
                            mapped,
                            observation.rtt.as_millis()
                        );
                        mappings.push(Some(mapped));
                    }
                    Err(error) => {
                        println!(
                            "STUN[{}] socket={} destination={} failed={} rtt_ms={}",
                            index + 1,
                            observation.local_socket,
                            observation.destination,
                            error,
                            observation.rtt.as_millis()
                        );
                        mappings.push(None);
                        complete = false;
                    }
                }
            }
        }
    }

    match (mappings[0], mappings[2]) {
        (Some(first), Some(last)) => println!(
            "A1/A2 mapping {}",
            if first == last { "matched" } else { "differed" }
        ),
        _ => println!("A1/A2 mapping comparison incomplete"),
    }
    if complete {
        Ok(())
    } else {
        bail!("one or more bounded STUN observations failed")
    }
}

pub(super) async fn resolve_stun_destinations(
    config: &StunConfig,
    server_url: &str,
) -> Result<Vec<SocketAddr>> {
    let servers = if config.servers.is_empty() {
        vec![default_stun_endpoint(server_url)?]
    } else {
        config.servers.clone()
    };
    resolve_destinations(&servers, config.udp_bind_address.is_ipv4()).await
}

pub(super) fn to_nat_observation(
    local_candidates: Vec<TransportLocalCandidate>,
    mappings: Vec<StunMappingObservation>,
) -> NatObservation {
    for mapping in &mappings {
        tracing::debug!(
            socket = %mapping.local_socket,
            destination = %mapping.destination,
            outcome = ?mapping.outcome,
            rtt_ms = mapping.rtt.as_millis(),
            "same-socket STUN mapping observation"
        );
    }
    NatObservation {
        local_candidates: local_candidates
            .into_iter()
            .map(|candidate| LocalCandidate {
                address: candidate.address,
                prefix_len: candidate.prefix_len,
            })
            .collect(),
        stun_mappings: mappings
            .into_iter()
            .map(|mapping| StunMapping {
                server: mapping.destination,
                mapped: mapping.outcome.ok(),
            })
            .collect(),
    }
}

async fn resolve_destinations(servers: &[String], ipv4: bool) -> Result<Vec<SocketAddr>> {
    let mut resolved = HashMap::<&str, SocketAddr>::new();
    let mut destinations = Vec::with_capacity(servers.len());
    for server in servers {
        if let Some(destination) = resolved.get(server.as_str()) {
            destinations.push(*destination);
            continue;
        }
        let destination = timeout(DNS_TIMEOUT, lookup_host(server))
            .await
            .with_context(|| format!("resolve STUN server {server} timed out"))??
            .find(|address| address.is_ipv4() == ipv4)
            .with_context(|| format!("STUN server {server} has no matching IP family"))?;
        resolved.insert(server, destination);
        destinations.push(destination);
    }
    Ok(destinations)
}

fn default_stun_endpoint(server_url: &str) -> Result<String> {
    let url = reqwest::Url::parse(server_url).context("parse server URL for STUN endpoint")?;
    let host = url.host_str().context("server URL has no host")?;
    if host.starts_with('[') || !host.contains(':') {
        Ok(format!("{host}:3478"))
    } else {
        Ok(format!("[{host}]:3478"))
    }
}

fn format_candidates(candidates: &[SocketAddr]) -> String {
    candidates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
