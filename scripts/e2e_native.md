# Local Iroh transport validation

The local suite runs without public relay access or long-duration sessions:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The tests exercise private HTTPS/Iroh relay and QAD listeners, QAD address observation, relay-mode allowlists, public-default control negotiation with no private relay, network-only retry policy with a fresh client identity, ticket-bound activation, SSH-stream half-close, interrupted ticket reads, and setup cancellation. The self-hosted data-path test uses a local TCP echo fixture; it does not launch OpenSSH `sshd`.

The current suite includes 33 tests. It does not contact a public relay, run against `target-1`, or perform long-idle and large-file tests. For live SSH checks, use [`verify_live.md`](verify_live.md) and the current Iroh harness/report linked there.
