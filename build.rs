use std::{env, fs, io::BufReader, path::PathBuf, sync::Arc};

#[cfg(unix)]
use std::path::Path;

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{PrivateKeyDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
};

const SERVER_NAME: &str = "kmesh.internal";

struct PemInput {
    env_name: &'static str,
    output_name: &'static str,
}

const PEM_INPUTS: [PemInput; 5] = [
    PemInput {
        env_name: "KMESH_CA_CERT_PATH",
        output_name: "ca-cert.pem",
    },
    PemInput {
        env_name: "KMESH_SERVER_CERT_PATH",
        output_name: "server-cert.pem",
    },
    PemInput {
        env_name: "KMESH_SERVER_KEY_PATH",
        output_name: "server-key.pem",
    },
    PemInput {
        env_name: "KMESH_CLIENT_CERT_PATH",
        output_name: "client-cert.pem",
    },
    PemInput {
        env_name: "KMESH_CLIENT_KEY_PATH",
        output_name: "client-key.pem",
    },
];

fn main() {
    shadow_rs::ShadowBuilder::builder()
        .build_pattern(shadow_rs::BuildPattern::RealTime)
        .build()
        .expect("generate kmesh build metadata");

    let inputs = PEM_INPUTS
        .iter()
        .map(|input| {
            println!("cargo:rerun-if-env-changed={}", input.env_name);
            let path = env::var_os(input.env_name)
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    panic!(
                        "required build environment variable {} is not set",
                        input.env_name
                    )
                });
            let contents = fs::read(&path)
                .unwrap_or_else(|_| panic!("read {} at {}", input.env_name, path.display()));
            (input, path, contents)
        })
        .collect::<Vec<_>>();

    validate_material(&inputs);

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    for (input, path, contents) in inputs {
        println!("cargo:rerun-if-changed={}", path.display());
        let output = out_dir.join(input.output_name);
        fs::write(&output, contents)
            .unwrap_or_else(|_| panic!("write embedded TLS material {}", input.output_name));
        #[cfg(unix)]
        set_private_file(&output);
    }
}

fn validate_material(inputs: &[(&PemInput, PathBuf, Vec<u8>)]) {
    let ca = certificates(&inputs[0].2, "CA certificate");
    assert_eq!(
        ca.len(),
        1,
        "CA certificate PEM must contain exactly one certificate"
    );
    let server_chain = certificates(&inputs[1].2, "server certificate chain");
    let server_key = private_key(&inputs[2].2, "server private key");
    let client_chain = certificates(&inputs[3].2, "client certificate chain");
    let client_key = private_key(&inputs[4].2, "client private key");

    let mut roots = RootCertStore::empty();
    roots
        .add(ca[0].clone())
        .expect("CA certificate must be a valid trust anchor");
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install build-time rustls crypto provider");
    }

    let server_verifier = WebPkiServerVerifier::builder(Arc::new(roots.clone()))
        .build()
        .expect("build embedded CA server verifier");
    let server_name = ServerName::try_from(SERVER_NAME.to_owned())
        .expect("fixed kmesh TLS identity must be a valid DNS name");
    server_verifier
        .verify_server_cert(
            &server_chain[0],
            &server_chain[1..],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .expect("server certificate must chain to the embedded CA, be currently valid, have serverAuth EKU, and include SAN kmesh.internal");

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
        .build()
        .expect("build embedded CA client verifier");
    client_verifier
        .verify_client_cert(&client_chain[0], &client_chain[1..], UnixTime::now())
        .expect("client certificate must chain to the embedded CA, be currently valid, and have clientAuth EKU");

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_chain, server_key)
        .expect("server certificate and private key must match");
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, client_key)
        .expect("client certificate and private key must match");
}

fn certificates(contents: &[u8], label: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(contents))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| panic!("{label} PEM is invalid"));
    assert!(
        !certificates.is_empty(),
        "{label} PEM contains no certificates"
    );
    certificates
}

fn private_key(contents: &[u8], label: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(contents))
        .unwrap_or_else(|_| panic!("{label} PEM is invalid"))
        .unwrap_or_else(|| panic!("{label} PEM contains no private key"))
}

#[cfg(unix)]
fn set_private_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|_| panic!("restrict permissions for embedded TLS material"));
}
