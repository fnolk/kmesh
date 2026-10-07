# Upstream source

This directory vendors `iroh-relay` 1.3.0 from the crates.io package whose original `Cargo.lock` checksum was `ee116a8233f84980574bb8d11e4517503080cd2c3605bafca04ee9c35d708bd9`. The package metadata records upstream commit `0072d7d84b233f9e7185eb676f049beaf557ac03` in `.cargo_vcs_info.json`.

Local Rust changes include `src/tls.rs`, where `CaTlsConfig` carries an optional `ResolvesClientCert`, exposes `with_client_cert_resolver`, and uses that resolver when it builds a client config. This lets Iroh private relay connections present kmesh's embedded client certificate. The `Clone` and `Debug` implementations account for the resolver trait object.

`CaTlsConfig` also carries an SNI setting, defaults it to enabled, and exposes `with_sni` so private kmesh relay connections can omit the network hostname while public relay connections retain normal SNI.

The server API also exposes numeric conversion for `ConnectionId`, per-connection relay payload traffic snapshots, process-lifetime ingress and egress totals, and exact-connection disconnection through `Clients`. Ingress counts decoded datagram payloads even when forwarding later fails; egress counts payloads after a successful write. Protocol control frames are excluded. Relay-service authorization reserves a temporary registration lease before its async access check; `Clients::disconnect` cancels both registered transports and matching in-flight handshakes, preventing a late registration after an administrator closes a session. Actor cancellation preempts pending stream reads, writes, and flushes, drops queued outbound frames, and unregisters the transport without a final flush.

`LICENSE-MIT` and `LICENSE-APACHE` are copied from the upstream repository root at the recorded commit. `LICENSE-BSD3` is included in the crates.io package.
