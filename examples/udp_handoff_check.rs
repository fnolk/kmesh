use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{
    Endpoint, EndpointAddr, RelayConfig, RelayMap, RelayMode, SecretKey, Watcher as _,
    endpoint::{NetReportConfig, PortmapperConfig, presets},
};
use iroh_relay::{RelayQuicConfig, tls::CaTlsConfig};
use kmesh::transport::tls::private_ca_tls_config;
use serde::Serialize;
use serde_json::json;
use tokio::time::{Instant, timeout_at};

const B_RELAY_URL: &str = "https://192.0.2.11:9443";
const B_QAD_PORT: u16 = 3478;
const ALPN: &[u8] = b"kmesh/udp-handoff-check/1";
const ROUND_TIMEOUT: Duration = Duration::from_secs(20);

struct Args {
    local_ip: Ipv4Addr,
    endpoint_secret_key_file: PathBuf,
}

#[derive(Serialize)]
struct EndpointSnapshot {
    endpoint_id: String,
    local_socket: SocketAddr,
    endpoint_addr: EndpointAddr,
    actual_home_relay_url: String,
    b_relay_connected: bool,
    connected_relays: Vec<String>,
    udp_v4: bool,
    global_v4: SocketAddrV4,
    mapping_varies_by_dest_ipv4: Option<bool>,
    relay_latency: serde_json::Value,
}

fn parse_args() -> Result<Args> {
    let mut local_ip = None;
    let mut endpoint_secret_key_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--local-ip" => {
                local_ip = Some(
                    args.next()
                        .context("--local-ip requires an IPv4 address")?
                        .parse::<Ipv4Addr>()
                        .context("parse --local-ip")?,
                )
            }
            "--endpoint-secret-key-file" => {
                endpoint_secret_key_file = args.next().map(PathBuf::from)
            }
            _ => bail!(
                "usage: udp_handoff_check --local-ip <IPv4> --endpoint-secret-key-file <FILE>"
            ),
        }
    }
    Ok(Args {
        local_ip: local_ip.context("--local-ip is required")?,
        endpoint_secret_key_file: endpoint_secret_key_file
            .context("--endpoint-secret-key-file is required")?,
    })
}

async fn bind_endpoint(
    secret_key: SecretKey,
    ca_tls: CaTlsConfig,
    local_ip: Ipv4Addr,
    local_port: u16,
    deadline: Instant,
) -> Result<Endpoint> {
    let relay_url = B_RELAY_URL.parse().context("parse fixed B relay URL")?;
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(
            relay_url,
            Some(RelayQuicConfig::new(B_QAD_PORT)),
        )])))
        .ca_tls_config(ca_tls)
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .clear_ip_transports()
        .bind_addr(SocketAddr::V4(SocketAddrV4::new(local_ip, local_port)))
        .context("configure IPv4 Iroh endpoint")?;
    timeout_at(deadline, builder.bind())
        .await
        .context("bind Iroh endpoint before deadline")?
        .context("bind Iroh endpoint")
}

async fn observe_endpoint(
    endpoint: &Endpoint,
    local_ip: Ipv4Addr,
    deadline: Instant,
) -> Result<EndpointSnapshot> {
    let private_relay_url = B_RELAY_URL
        .parse::<iroh::RelayUrl>()
        .context("parse fixed B relay URL")?;
    let mut relay_status = endpoint.home_relay_status();
    let connected_relays = loop {
        let statuses = relay_status.get();
        if let Some(relay) = statuses
            .iter()
            .find(|relay| relay.url() == &private_relay_url && relay.is_connected())
        {
            let _ = relay;
            break statuses
                .iter()
                .filter(|relay| relay.is_connected())
                .map(|relay| relay.url().to_string())
                .collect::<Vec<_>>();
        }
        if let Some(reason) = statuses
            .iter()
            .find(|relay| relay.url() == &private_relay_url)
            .and_then(|relay| relay.auth_denied_reason())
        {
            bail!("B relay denied the endpoint identity: {reason}");
        }
        match timeout_at(deadline, relay_status.updated()).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => bail!("B relay status watcher disconnected"),
            Err(_) => bail!("B relay did not connect before the endpoint deadline"),
        }
    };

    let actual_home_relay_url = endpoint
        .addr()
        .relay_urls()
        .next()
        .map(ToString::to_string)
        .context("Iroh endpoint has no home relay URL")?;
    ensure!(
        actual_home_relay_url == private_relay_url.to_string(),
        "endpoint home relay changed from fixed B URL: {actual_home_relay_url}"
    );

    let local_socket = endpoint
        .bound_sockets()
        .into_iter()
        .find(|address| address.is_ipv4() && address.ip() == IpAddr::V4(local_ip))
        .context("Iroh endpoint has no bound socket on requested IPv4")?;
    let mut report_watcher = endpoint.net_report();
    let report = timeout_at(deadline, report_watcher.initialized())
        .await
        .context("wait for initialized Iroh QAD net report")?;
    ensure!(report.udp_v4, "Iroh net report did not verify IPv4 UDP");
    let global_v4 = report
        .global_v4
        .context("Iroh net report has no global IPv4 mapping")?;
    let global_candidate = SocketAddr::V4(global_v4);
    let mut address_watcher = endpoint.watch_addr();
    loop {
        if address_watcher
            .get()
            .ip_addrs()
            .any(|candidate| candidate == &global_candidate)
        {
            break;
        }
        timeout_at(deadline, address_watcher.updated())
            .await
            .context("wait for QAD global IPv4 candidate in EndpointAddr")?
            .map_err(|_| anyhow!("Iroh EndpointAddr watcher disconnected"))?;
    }
    let endpoint_addr = address_watcher.get();
    let relay_latency =
        serde_json::to_value(report.relay_latency).context("serialize relay latency report")?;

    Ok(EndpointSnapshot {
        endpoint_id: endpoint.id().to_string(),
        local_socket,
        endpoint_addr,
        actual_home_relay_url,
        b_relay_connected: true,
        connected_relays,
        udp_v4: report.udp_v4,
        global_v4,
        mapping_varies_by_dest_ipv4: report.mapping_varies_by_dest_ipv4,
        relay_latency,
    })
}

async fn run() -> Result<()> {
    let args = parse_args()?;
    let deadline = Instant::now() + ROUND_TIMEOUT;
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("install rustls ring provider"))?;
    }

    let encoded = std::fs::read_to_string(&args.endpoint_secret_key_file)
        .context("read enrolled Endpoint secret key")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("decode enrolled Endpoint secret key")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Endpoint secret key must contain 32 bytes"))?;
    let secret_key = SecretKey::from_bytes(&bytes);

    let ca_tls = private_ca_tls_config()?;

    let old_endpoint = bind_endpoint(
        secret_key.clone(),
        ca_tls.clone(),
        args.local_ip,
        0,
        deadline,
    )
    .await
    .context("old Iroh socket bind phase")?;
    let old = observe_endpoint(&old_endpoint, args.local_ip, deadline)
        .await
        .context("old Iroh B/QAD observation phase")?;
    println!(
        "{}",
        serde_json::to_string(&json!({"event":"old_iroh_endpoint","snapshot":old}))?
    );

    timeout_at(deadline, old_endpoint.close())
        .await
        .context("close old Iroh endpoint before tuple handoff")?;
    drop(old_endpoint);
    println!(
        "{}",
        serde_json::to_string(
            &json!({"event":"old_iroh_endpoint_closed_and_dropped","endpoint_id":old.endpoint_id,"local_socket":old.local_socket})
        )?
    );

    let raw_socket = UdpSocket::bind(old.local_socket)
        .context("bind raw UDP socket to the old Iroh local tuple")?;
    let raw_local_socket = raw_socket.local_addr().context("read raw UDP tuple")?;
    ensure!(
        raw_local_socket == old.local_socket,
        "raw UDP socket bound a different tuple: {raw_local_socket}"
    );
    drop(raw_socket);
    println!(
        "{}",
        serde_json::to_string(
            &json!({"event":"raw_udp_bind_and_close","local_socket":raw_local_socket,"packets_sent":0})
        )?
    );

    let new_endpoint = bind_endpoint(
        secret_key,
        ca_tls,
        args.local_ip,
        old.local_socket.port(),
        deadline,
    )
    .await
    .context("new Iroh same-tuple bind phase")?;
    let new = observe_endpoint(&new_endpoint, args.local_ip, deadline)
        .await
        .context("new Iroh B/QAD observation phase")?;
    timeout_at(deadline, new_endpoint.close())
        .await
        .context("close new Iroh endpoint")?;
    drop(new_endpoint);

    let same_endpoint_id = old.endpoint_id == new.endpoint_id;
    let same_local_socket = old.local_socket == new.local_socket;
    let same_global_mapping = old.global_v4 == new.global_v4;
    let pass = old.udp_v4
        && new.udp_v4
        && old.b_relay_connected
        && new.b_relay_connected
        && same_endpoint_id
        && same_local_socket
        && same_global_mapping;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "experiment":"sequential Iroh socket close, raw bind/close, and same-tuple Iroh rebind",
            "same_udp_socket_object_reused":false,
            "old":old,
            "new":new,
            "comparison":{
                "same_endpoint_id":same_endpoint_id,
                "same_local_socket":same_local_socket,
                "local_tuple_reused":same_local_socket,
                "same_global_v4_mapping":same_global_mapping,
                "mapping_preserved":pass
            },
            "pass":pass
        }))?
    );
    if !pass {
        bail!("same-tuple Iroh mapping was not preserved");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                json!({"event":"failure","error":format!("{error:#}")})
            );
            ExitCode::FAILURE
        }
    }
}
