# Local Iroh transport validation

The current local suite runs without public relay access or long-duration sessions:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The tests exercise private HTTPS/Iroh relay and QAD listeners, QAD address observation, relay-mode allowlists, public-default control negotiation with no private relay, network-only retry policy with a fresh client identity, ticket-bound activation, and SSH-stream half-close. The self-hosted data-path test uses a local TCP echo fixture; it does not launch OpenSSH `sshd`.

This replaces the retired STUN/Quinn/WSS-data harness. The current tests do not contact a public relay, run against `target-1`, exercise a live deployment, or perform long-idle and large-file tests.
