use std::{io, sync::Arc};

use iroh_relay::tls::{CaTlsConfig, ServerCertVerifierBuilder};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
};

use super::TransportError;

pub(crate) const TLS_SERVER_NAME: &str = "kmesh.internal";

const CA_CERTIFICATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ca-cert.pem"));
const SERVER_CERTIFICATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/server-cert.pem"));
const SERVER_PRIVATE_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/server-key.pem"));
const CLIENT_CERTIFICATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/client-cert.pem"));
const CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/client-key.pem"));

#[derive(Debug)]
struct FixedServerNameVerifier {
    verifier: Arc<WebPkiServerVerifier>,
    server_name: ServerName<'static>,
}

impl ServerCertVerifier for FixedServerNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &self.server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

pub(crate) fn root_certificates() -> Result<Vec<CertificateDer<'static>>, TransportError> {
    parse_certificates(CA_CERTIFICATE, "embedded CA certificate")
}

pub(crate) fn root_cert_store() -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    for certificate in root_certificates()? {
        roots.add(certificate).map_err(|error| {
            TransportError::Configuration(format!("load embedded CA certificate: {error}"))
        })?;
    }
    Ok(roots)
}

pub(crate) fn server_identity()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    Ok((
        parse_certificates(SERVER_CERTIFICATE, "embedded server certificate")?,
        parse_private_key(SERVER_PRIVATE_KEY, "embedded server private key")?,
    ))
}

pub(crate) fn client_identity()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    Ok((
        parse_certificates(CLIENT_CERTIFICATE, "embedded client certificate")?,
        parse_private_key(CLIENT_PRIVATE_KEY, "embedded client private key")?,
    ))
}

pub(crate) fn server_config() -> Result<Arc<ServerConfig>, TransportError> {
    ensure_crypto_provider();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store()?))
        .build()
        .map_err(|error| {
            TransportError::Configuration(format!(
                "build embedded client certificate verifier: {error}"
            ))
        })?;
    let (certificate_chain, private_key) = server_identity()?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| {
            TransportError::Configuration(format!("build embedded HTTPS server identity: {error}"))
        })?;
    Ok(Arc::new(config))
}

/// Build a client TLS config with the embedded kmesh identity and fixed service name.
pub fn private_client_config() -> Result<ClientConfig, TransportError> {
    ensure_crypto_provider();
    let verifier = fixed_server_verifier(root_cert_store()?)?;
    let (certificate_chain, private_key) = client_identity()?;
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(|error| {
            TransportError::Configuration(format!("build embedded client TLS identity: {error}"))
        })?;
    config.enable_sni = false;
    Ok(config)
}

/// Build a client TLS config for public WebPKI QAD reflectors.
pub fn public_client_config() -> ClientConfig {
    ensure_crypto_provider();
    ClientConfig::builder()
        .with_root_certificates(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth()
}

/// Build the Iroh TLS settings for the embedded private relay identity.
pub fn private_ca_tls_config() -> Result<CaTlsConfig, TransportError> {
    ensure_crypto_provider();
    let roots = root_certificates()?;
    let expected_server_name =
        ServerName::try_from(TLS_SERVER_NAME.to_owned()).map_err(|error| {
            TransportError::Configuration(format!("invalid fixed kmesh TLS server name: {error}"))
        })?;
    let verifier_builder: ServerCertVerifierBuilder = Arc::new(move |provider| {
        let mut root_store = RootCertStore::empty();
        for certificate in roots.clone() {
            root_store.add(certificate).map_err(io::Error::other)?;
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider)
            .build()
            .map_err(io::Error::other)?;
        Ok(Arc::new(FixedServerNameVerifier {
            verifier,
            server_name: expected_server_name.clone(),
        }) as Arc<dyn ServerCertVerifier>)
    });
    let resolver = private_client_config()?.client_auth_cert_resolver.clone();
    Ok(CaTlsConfig::custom_server_cert_verifier(verifier_builder)
        .with_client_cert_resolver(resolver)
        .with_sni(false))
}

pub(crate) fn fixed_server_verifier(
    roots: RootCertStore,
) -> Result<Arc<dyn ServerCertVerifier>, TransportError> {
    ensure_crypto_provider();
    let provider = CryptoProvider::get_default()
        .expect("ring provider installed before building TLS verifier")
        .clone();
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|error| {
            TransportError::Configuration(format!("build server certificate verifier: {error}"))
        })?;
    let server_name = ServerName::try_from(TLS_SERVER_NAME.to_owned()).map_err(|error| {
        TransportError::Configuration(format!("invalid fixed kmesh TLS server name: {error}"))
    })?;
    Ok(Arc::new(FixedServerNameVerifier {
        verifier,
        server_name,
    }))
}

fn parse_certificates(
    pem: &[u8],
    label: &str,
) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    rustls_pemfile::certs(&mut io::BufReader::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransportError::Configuration(format!("parse {label}: {error}")))
}

fn parse_private_key(pem: &[u8], label: &str) -> Result<PrivateKeyDer<'static>, TransportError> {
    rustls_pemfile::private_key(&mut io::BufReader::new(pem))
        .map_err(|error| TransportError::Configuration(format!("parse {label}: {error}")))?
        .ok_or_else(|| {
            TransportError::Configuration(format!("{label} PEM contains no private key"))
        })
}

fn ensure_crypto_provider() {
    crate::transport::ensure_rustls_provider();
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    async fn server_handshake(
        client_config: ClientConfig,
    ) -> (
        Result<(), String>,
        JoinHandle<Result<Option<String>, String>>,
    ) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind TLS test listener");
        let address = listener.local_addr().expect("read TLS test address");
        let acceptor = TlsAcceptor::from(server_config().expect("build production server config"));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS test connection");
            acceptor
                .accept(stream)
                .await
                .map(|stream| stream.get_ref().1.server_name().map(str::to_owned))
                .map_err(|error| error.to_string())
        });
        let server_name =
            ServerName::try_from(TLS_SERVER_NAME.to_owned()).expect("fixed server name is valid");
        let client = TlsConnector::from(Arc::new(client_config))
            .connect(
                server_name,
                tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connect TLS test socket"),
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string());
        (client, server)
    }

    #[tokio::test]
    async fn production_server_requires_the_embedded_client_identity() {
        let (client, server) = server_handshake(
            private_client_config().expect("build embedded private client config"),
        )
        .await;
        client.expect("embedded mTLS client handshake succeeds");
        assert_eq!(
            server
                .await
                .expect("join server handshake")
                .expect("server accepts the embedded client"),
            None,
            "private mTLS omits the network host from TLS SNI"
        );

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(
                fixed_server_verifier(root_cert_store().expect("load embedded CA"))
                    .expect("build fixed-name verifier"),
            )
            .with_no_client_auth();
        let (client, server) = server_handshake(client_config).await;
        drop(client);
        assert!(server.await.expect("join server handshake").is_err());

        let untrusted_client =
            rcgen::generate_simple_self_signed(vec!["untrusted-client".to_owned()])
                .expect("generate a client certificate from an unrelated CA");
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(
                fixed_server_verifier(root_cert_store().expect("load embedded CA"))
                    .expect("build fixed-name verifier"),
            )
            .with_client_auth_cert(
                parse_certificates(
                    untrusted_client.cert.pem().as_bytes(),
                    "untrusted client certificate",
                )
                .expect("parse untrusted client certificate"),
                parse_private_key(
                    untrusted_client.signing_key.serialize_pem().as_bytes(),
                    "untrusted client key",
                )
                .expect("parse untrusted client key"),
            )
            .expect("build untrusted client config");
        let (client, server) = server_handshake(client_config).await;
        drop(client);
        assert!(server.await.expect("join server handshake").is_err());
    }

    #[test]
    fn private_server_verifier_rejects_wrong_ca_and_fixed_server_name() {
        ensure_crypto_provider();
        let (certificates, _) = server_identity().expect("load embedded server identity");
        let certificate = certificates.first().expect("embedded server certificate");
        let time = UnixTime::now();
        let name = ServerName::try_from(TLS_SERVER_NAME.to_owned()).expect("fixed server name");
        let verifier = fixed_server_verifier(root_cert_store().expect("load embedded CA"))
            .expect("build private verifier");
        verifier
            .verify_server_cert(certificate, &certificates[1..], &name, &[], time)
            .expect("embedded server certificate chains to embedded CA and matches fixed name");

        let unrelated_ca = rcgen::generate_simple_self_signed(vec!["unrelated-ca".to_owned()])
            .expect("generate unrelated test CA");
        let mut wrong_roots = RootCertStore::empty();
        for certificate in
            parse_certificates(unrelated_ca.cert.pem().as_bytes(), "unrelated test CA")
                .expect("parse unrelated test CA")
        {
            wrong_roots.add(certificate).expect("add unrelated test CA");
        }
        let wrong_ca = WebPkiServerVerifier::builder(Arc::new(wrong_roots))
            .build()
            .expect("build empty root verifier");
        assert!(
            wrong_ca
                .verify_server_cert(certificate, &certificates[1..], &name, &[], time)
                .is_err()
        );

        let wrong_name = ServerName::try_from("wrong.kmesh.internal".to_owned())
            .expect("wrong test name is valid");
        let verifier = WebPkiServerVerifier::builder(Arc::new(root_cert_store().unwrap()))
            .build()
            .expect("build WebPKI verifier");
        let wrong_name_verifier = FixedServerNameVerifier {
            verifier,
            server_name: wrong_name,
        };
        assert!(
            wrong_name_verifier
                .verify_server_cert(certificate, &certificates[1..], &name, &[], time)
                .is_err()
        );
    }

    #[test]
    fn private_tls_configs_omit_sni_and_public_qad_keeps_webpki_sni() {
        let private = private_client_config().expect("build embedded private client config");
        assert!(!private.enable_sni);
        assert!(private.client_auth_cert_resolver.has_certs());

        let private_relay = private_ca_tls_config()
            .expect("build embedded private relay TLS config")
            .client_config(Arc::new(rustls::crypto::ring::default_provider()))
            .expect("build embedded private relay client config");
        assert!(!private_relay.enable_sni);
        assert!(private_relay.client_auth_cert_resolver.has_certs());

        assert!(public_client_config().enable_sni);
    }
}
