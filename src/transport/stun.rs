use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rtc_stun::fingerprint::FINGERPRINT;
use rtc_stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, TransactionId};
use rtc_stun::xoraddr::XorMappedAddress;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use crate::config::StunConfig;
use crate::transport::TransportError;

const STUN_BUFFER_SIZE: usize = 4096;
const STUN_INITIAL_RTO: Duration = Duration::from_millis(500);
const STUN_MAX_RETRANSMISSIONS: usize = 3;

pub async fn resolve_servers(config: &StunConfig) -> Result<Vec<SocketAddr>, TransportError> {
    let mut servers = Vec::new();
    for server in &config.servers {
        let authority = parse_stun_authority(server)?;
        let resolved = tokio::net::lookup_host(&authority).await.map_err(|error| {
            TransportError::Stun(format!("resolve STUN endpoint {authority}: {error}"))
        })?;
        servers.extend(resolved);
    }
    servers.sort_unstable();
    servers.dedup();
    Ok(servers)
}

pub async fn gather_mapping(
    socket: &UdpSocket,
    server: SocketAddr,
) -> Result<SocketAddr, TransportError> {
    let transaction_id = TransactionId::new();
    let mut request = Message::new();
    request
        .build(&[
            Box::new(transaction_id),
            Box::new(BINDING_REQUEST),
            Box::new(FINGERPRINT),
        ])
        .map_err(|error| TransportError::Stun(format!("build Binding Request: {error}")))?;

    let mut buffer = [0; STUN_BUFFER_SIZE];
    for retransmission in 0..=STUN_MAX_RETRANSMISSIONS {
        socket
            .send_to(&request.raw, server)
            .await
            .map_err(TransportError::Network)?;
        let rto = STUN_INITIAL_RTO * (1_u32 << retransmission);
        let deadline = Instant::now() + rto;
        loop {
            let (length, source) = match timeout_at(deadline, socket.recv_from(&mut buffer)).await {
                Ok(Ok(received)) => received,
                Ok(Err(error)) => return Err(TransportError::Network(error)),
                Err(_) => break,
            };
            if source != server || !rtc_stun::message::is_stun_message(&buffer[..length]) {
                continue;
            }
            let mut response = Message::new();
            response
                .unmarshal_binary(&buffer[..length])
                .map_err(|error| TransportError::Stun(format!("decode STUN response: {error}")))?;
            if response.transaction_id != transaction_id {
                continue;
            }
            if response.typ != BINDING_SUCCESS {
                return Err(TransportError::Stun(format!(
                    "STUN server returned {}",
                    response.typ
                )));
            }
            if response.contains(rtc_stun::attributes::ATTR_FINGERPRINT) {
                rtc_stun::fingerprint::FingerprintAttr
                    .check(&response)
                    .map_err(|error| {
                        TransportError::Stun(format!("check STUN fingerprint: {error}"))
                    })?;
            }
            let mut mapped = [XorMappedAddress::default()];
            response.parse(&mut mapped).map_err(|error| {
                TransportError::Stun(format!("read XOR-MAPPED-ADDRESS: {error}"))
            })?;
            return Ok(SocketAddr::new(mapped[0].ip, mapped[0].port));
        }
    }
    Err(TransportError::Timeout("STUN Binding transaction"))
}

pub async fn serve_stun(
    bind_addr: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TransportError> {
    if *shutdown.borrow_and_update() {
        return Ok(());
    }
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(TransportError::Network)?;
    let mut buffer = [0; STUN_BUFFER_SIZE];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow_and_update() => return Ok(()),
                    Ok(()) => {}
                    Err(_) => return Ok(()),
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = received.map_err(TransportError::Network)?;
                let Some(response) = binding_response(&buffer[..length], source) else {
                    continue;
                };
                socket.send_to(&response, source).await.map_err(TransportError::Network)?;
            }
        }
    }
}

fn binding_response(packet: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if !rtc_stun::message::is_stun_message(packet) {
        return None;
    }
    let mut request = Message::new();
    if request.unmarshal_binary(packet).is_err() || request.typ != BINDING_REQUEST {
        return None;
    }
    if request.contains(rtc_stun::attributes::ATTR_FINGERPRINT)
        && rtc_stun::fingerprint::FingerprintAttr
            .check(&request)
            .is_err()
    {
        return None;
    }
    let mut response = Message::new();
    response
        .build(&[
            Box::new(request.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: source.ip(),
                port: source.port(),
            }),
            Box::new(FINGERPRINT),
        ])
        .ok()?;
    Some(response.raw)
}

fn parse_stun_authority(server: &str) -> Result<String, TransportError> {
    let authority = server
        .strip_prefix("stun://")
        .or_else(|| server.strip_prefix("stun:"))
        .unwrap_or(server);
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(TransportError::Configuration(
            "STUN server address is empty".to_owned(),
        ));
    }
    Ok(authority.to_owned())
}

pub fn same_address_family(local: SocketAddr, address: IpAddr) -> bool {
    local.is_ipv4() == address.is_ipv4()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc_stun::message::BINDING_REQUEST;

    #[test]
    fn stun_authority_accepts_supported_forms() {
        assert_eq!(
            parse_stun_authority("stun:localhost:3478").unwrap(),
            "localhost:3478"
        );
        assert_eq!(
            parse_stun_authority("stun://localhost:3478?transport=udp").unwrap(),
            "localhost:3478"
        );
        assert_eq!(
            parse_stun_authority("127.0.0.1:3478").unwrap(),
            "127.0.0.1:3478"
        );
    }

    #[test]
    fn binding_response_echoes_transaction_and_source_mapping() {
        let transaction_id = TransactionId::new();
        let mut request = Message::new();
        request
            .build(&[
                Box::new(transaction_id),
                Box::new(BINDING_REQUEST),
                Box::new(FINGERPRINT),
            ])
            .unwrap();

        let source: SocketAddr = "203.0.113.7:45123".parse().unwrap();
        let packet = binding_response(&request.raw, source).unwrap();
        let mut response = Message::new();
        response.unmarshal_binary(&packet).unwrap();
        assert_eq!(response.typ, BINDING_SUCCESS);
        assert_eq!(response.transaction_id, transaction_id);
        rtc_stun::fingerprint::FingerprintAttr
            .check(&response)
            .unwrap();
        let mut mapped = [XorMappedAddress::default()];
        response.parse(&mut mapped).unwrap();
        assert_eq!(SocketAddr::new(mapped[0].ip, mapped[0].port), source);
    }
}
