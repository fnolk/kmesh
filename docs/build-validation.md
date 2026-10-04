# Build and route acceptance

The CI workflow runs formatting, Clippy, all-target tests, and a release build for each supported target. A successful CI run verifies those checks for its exact source revision; live P2P and SSH route selection need separate evidence from the deployed server, target agent, and client.

## Reproducible release builds

`scripts/build-release.sh` builds the four release targets: Linux x86_64 and aarch64 with musl, plus macOS Intel and Apple Silicon. It requires `cargo-zigbuild`, Zig, and the Rust targets. Set an explicit target directory before running it:

```sh
export CARGO_TARGET_DIR=/path/to/cargo-target
export CARGO_ZIGBUILD_ZIG_PATH=/path/to/zig
export PATH=/path/to/cargo-zigbuild-directory:$PATH
scripts/build-release.sh
```

The output files are:

```text
$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh
$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh
$CARGO_TARGET_DIR/x86_64-apple-darwin/release/kmesh
$CARGO_TARGET_DIR/aarch64-apple-darwin/release/kmesh
```

Record the source revision and SHA-256 of each file before deployment. Check Linux binaries are static ELF executables with no interpreter or dynamic dependencies:

```sh
file "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh"
readelf -l "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh" | rg INTERP
readelf -d "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh" | rg NEEDED
file "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh"
readelf -l "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh" | rg INTERP
readelf -d "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh" | rg NEEDED
```

The `readelf` commands should print no matching lines. `file` or `lipo -info` should show the requested architecture for each macOS binary. CI also checks each target's dependency graph for OpenSSL and `native-tls` packages.

## Local and CI checks

Run the same source checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

`--all-targets` includes library and binary tests, integration tests, and examples. Current tests cover protocol and identity boundaries, same-socket QAD discovery, signed UDP handoff, direct-only and private-relay endpoint policy, SSH-shaped QUIC streams, HTTPS CONNECT proxying, and failure classification. These tests do not establish that two deployed NATs select a direct path.

## Live acceptance gates

Use one short, recorded run per required route and attach the same session ID's client, server, and target-agent logs. Preserve the candidate source revision, binary hashes, server configuration, selected Iroh path, SSH exit status, and whether bytes moved over the reported path.

| Route | Required evidence |
|---|---|
| `PrivateDirect` | The client and agent report the same session; Iroh selects `Direct`; OpenSSH completes a command over that connection. QAD observations alone do not count as direct-path proof. |
| `PublicDirect` | The direct-only endpoints select `Direct`; the SSH stream uses that direct path. Official relay services may provide QAD, and this route never carries SSH data through a public relay. |
| `PrivateRelay` | Iroh selects the configured private relay URL; OpenSSH completes a command. The endpoint reports no IP transport candidates for this route. |
| Route fallback | A bounded direct attempt fails, a fresh authorized route attempt is recorded, and the next route completes SSH on its own allowed path. Ticket, identity, TLS/CA, proxy-authentication, configuration, and RBAC errors terminate the route plan. |

After the path gates pass, verify OpenSSH host-key checking, a nonzero remote exit code, SCP/SFTP content hashes, local forwarding, ControlMaster reuse, and the RBAC boundary: an activated SSH session continues while a new connection after revocation is denied. These checks use the deployed OpenSSH client and target `sshd`; an Iroh nonce exchange is not an SSH acceptance test.

## Current evidence status

The route-aware fallback run on candidate `be3ca70` exposed a message-order race: the server can send `ContinueNative(Standard)` while client QAD discovery is still in progress. The client fix is committed as `a27a1b1` on its isolated branch; the target-agent fix and rerun are pending integration. Treat the three-route fallback, current P2P selection, target-1 SSH path, and four-target release artifacts as unaccepted until the final candidate has been rebuilt and the live report records those results.

The historical reports under `scripts/verify_iroh_live_report.md` and `scripts/verify_live_report.md` document earlier route implementations. The existing `verify_iroh_live.py` and `verify_iroh_ssh.py` harnesses also use earlier `private`/`public-default` controls; update them before using them as acceptance tools for the current three-route plan. Do not infer current acceptance from those reports or from a CI pass. One-hour idle sessions and 1 GiB transfers are not part of the short-run acceptance gate.
