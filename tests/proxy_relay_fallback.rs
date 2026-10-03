use std::io;

use kmesh::transport::{RelayChoice, TransportError, allowed_relay_urls, validate_endpoint_addr};

#[test]
fn only_classified_network_failures_advance_the_route_attempt() {
    let eligible = [
        TransportError::Timeout("relay connection"),
        TransportError::Network(io::Error::from(io::ErrorKind::ConnectionRefused)),
        TransportError::Network(io::Error::from(io::ErrorKind::TimedOut)),
    ];
    for error in eligible {
        assert!(error.is_network_failure(), "{error} must be retryable");
        assert!(!error.is_auth_failure(), "{error} must not be auth failure");
    }

    let terminal = [
        TransportError::Authentication("denied".to_owned()),
        TransportError::ProtocolViolation("invalid peer address".to_owned()),
        TransportError::Tls("untrusted certificate".to_owned()),
        TransportError::Configuration("invalid relay URL".to_owned()),
        TransportError::EndpointClosed,
        TransportError::WebSocket("proxy returned 407".to_owned()),
    ];
    for error in terminal {
        assert!(!error.is_network_failure(), "{error} must fail closed");
    }
}

#[test]
fn direct_route_has_no_relay_addresses_and_private_route_allows_only_its_server() {
    let private_url: reqwest::Url = "https://private-relay.invalid".parse().unwrap();
    let private_relay = iroh::RelayUrl::from(private_url.clone());
    let direct_urls = allowed_relay_urls(&RelayChoice::DirectOnly).unwrap();
    assert!(direct_urls.is_empty());

    let peer_addr = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
        .with_relay_url(private_relay.clone());
    assert!(validate_endpoint_addr(&peer_addr, &RelayChoice::DirectOnly).is_err());

    let private_choice = RelayChoice::Private {
        url: private_url,
        quic_port: 3478,
    };
    assert_eq!(
        allowed_relay_urls(&private_choice).unwrap(),
        [private_relay].into_iter().collect()
    );
}
