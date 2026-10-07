# Upstream source

This directory vendors `iroh-relay` 1.3.0 from the crates.io package whose original `Cargo.lock` checksum was `ee116a8233f84980574bb8d11e4517503080cd2c3605bafca04ee9c35d708bd9`. The package metadata records upstream commit `0072d7d84b233f9e7185eb676f049beaf557ac03` in `.cargo_vcs_info.json`.

The only Rust source file changed locally is `src/tls.rs`. `CaTlsConfig` now carries an optional `ResolvesClientCert`, exposes `with_client_cert_resolver`, and uses that resolver when it builds a client config. This lets Iroh private relay connections present kmesh's embedded client certificate. It also carries an SNI setting, defaults it to enabled, and exposes `with_sni` so private kmesh relay connections can omit the network hostname while public relay connections retain normal SNI. The `Clone` and `Debug` implementations account for the resolver trait object and SNI setting. All other Rust source files match the upstream package.

`LICENSE-MIT` and `LICENSE-APACHE` are copied from the upstream repository root at the recorded commit. `LICENSE-BSD3` is included in the crates.io package.
