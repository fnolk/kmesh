use std::io;

use kmesh::transport::{RelayChoice, TransportError, allowed_relay_urls};

#[test]
fn only_classified_network_failures_are_eligible_for_private_retry() {
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
fn private_relay_address_is_rejected_in_public_default_mode() {
    let private_url: reqwest::Url = "https://private-relay.invalid".parse().unwrap();
    let private_relay = iroh::RelayUrl::from(private_url.clone());
    let public_urls = allowed_relay_urls(&RelayChoice::PublicDefault).unwrap();

    assert!(!public_urls.contains(&private_relay));
}
