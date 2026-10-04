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

## Final candidate evidence — `eb359f7`

The accepted source revision is `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`. The final build manifest is [`manifest.txt`](/Users/example/.cache/kmesh-release-validation/eb359f7/artifacts/manifest.txt).

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --release --all-targets -- -D warnings` | Passed |
| `cargo test --locked --release --all-targets -- --test-threads=1` | 71 passed, 0 failed, 2 ignored |
| Explicit route-acceptance tests | 2 passed in 60.83s |
| Four release targets | Built successfully; artifact hashes below |

The candidate includes the QAD probe/Noq cleanup deadline correction and agent control-mailbox lifecycle correction. The mailbox regression passed. The release manifest reports a clean source tree and no active Cargo process at build completion.

| Release target | Artifact SHA-256 | Format / check |
|---|---|---|
| `x86_64-unknown-linux-musl` | `7f0e52310289670764b42dbe4cd62795b6aa7f9a7c91b926b4450cc17e1553e9` | Static-pie ELF; `PT_INTERP` and `DT_NEEDED` absent |
| `aarch64-unknown-linux-musl` | `e2b4cd12e579b198b91887f3e964b4d2ae06326a5896c95082ef1c531b40cb56` | Static ELF; `PT_INTERP` and `DT_NEEDED` absent |
| `x86_64-apple-darwin` | `b8c4a9f624e4a03efe33e5922dab30ee0d0e88229aa3b5326b4c36b17d0c59bf` | Mach-O x86_64 |
| `aarch64-apple-darwin` | `770681ecf3b2c4f428db9be9dafabb1e647aab34bbedb1101250bfdceb623aeb` | Mach-O arm64 |

The separately built native macOS arm64 host CLI used by local route acceptance has SHA-256 `1e3a2c1b810d1aaf9338c0a3aba79402fd4075277275b5d183642e89c6ca2766`; it is distinct from the canonical arm64 release artifact above. The Linux artifacts passed static ELF checks. The manifest records the dependency graph and confirms `openssl`, `openssl-sys`, `native-tls`, and `hyper-tls` are absent.

## Live `target-1` SSH results

The deployed client used the arm64 release binary (`770681ec…623aeb`); target agent and server used the x86_64 Linux musl binary (`7f0e5231…1553e9`). The detailed per-run reports are in [`verify_iroh_live_report.md`](../scripts/verify_iroh_live_report.md).

| Route | Result | Selected peer IPv4 and SSH-path UDP byte deltas |
|---|---|---|
| `PrivateDirect` | 3/3 SSH commands passed; `server-1`, marker, exit 23; direct gate passed before command | `192.0.2.19:2111` — TX/RX `10477/10588`; `:2157` — `11617/10727`; `:2158` — `8692/10234` |
| `PublicDirect` | 3/3 SSH commands passed; `server-1`, marker, exit 23; direct gate passed before command | `192.0.2.19:4170` — `13212/11772`; `:4171` — `10589/12016`; `:4172` — `10475/11660` |

The private-mode short OpenSSH suite passed with report status `passed`, 52 passing steps and four expected-observation steps. It covered a 1 MiB SCP/SFTP round-trip (matching SHA-256 `943d64207a10f875aac2b4129149d37594bb170381b1e2e37b192bbec07600cb`), local forwarding, strict rejection of a wrong host key, ControlMaster reuse, a five-second idle stream, two concurrent channels, cancellation while the master stayed alive, and RBAC/session boundaries for grant revocation, target disable, and logout. The target and client login were restored; `cleanup_errors` was empty. The report is `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/ssh-suite-eb359f7/ssh-private-20261004T034407Z-5af0d8a3/report.json`.

An in-flight direct SSH command also survived a private server-control restart: report `run-20261004T034551Z` records the target online after restart, `server-1`, marker, exit 23, selected path `192.0.2.19:2164`, and SSH-path TX/RX deltas `12945/11957`.

A final bounded PrivateDirect `ControlMaster` sample kept the direct path `192.0.2.19:2123` selected while two independent random 4 MiB SCP transfers ran concurrently (both exit 0; local and remote SHA-256 matched) and four interactive echo probes returned in 58.943, 468.781, 517.340, and 50.795 ms. All probes began with two active transfers; the first three ended with two active, and the final probe ended with zero active. The transfer phase took 1.462 seconds. Twenty-four RSS samples from the proxy process (PID 90414) ranged from 21,568 to 22,976 KiB, with a 22,960 KiB median. The sample used a 25-second data-phase cap and completed cleanup: temporary files, master, and proxy are gone; A and B are active; the target is online and enabled; grants and database integrity are intact; active and pending sessions are zero; B still listens on UDP 3478 and TCP 9443. This is one short sample, not an SLO or a long-term capacity estimate. Full details: [`performance report`](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/perf-eb359f7-20261004/report.json>).

## Relay fallback and QAD evidence

The two explicit route-acceptance tests passed with the kmesh CLI. They exercise two real direct timeouts followed by a private-relay Iroh path and an SSH-shaped TCP fixture, plus a denied private-relay attempt with all sessions closed and no active rows. The success fixture records relay path TX/RX growth (`146/113`), a 22-byte SSH request, and 52 bytes on the proxy stdout. These tests exercise the actual CLI/control/transport route but use a local SSH stub; they are not a forced private-relay connection to `target-1`.

The separate QAD diagnostic build at source `431c91e` records two authenticated official UDP 7842 reflector observations on the same retained socket, both reporting `192.0.2.12:12008`. Reflector probing took 1338 ms; stopping and joining Noq drivers took 2430 ms; total discovery and cleanup took 3813 ms. The prior diagnostic returned Unavailable because its two-second deadline also covered driver cleanup. This confirms the QAD lifecycle correction without claiming a peer connection or SSH result.

Earlier 4e field evidence remains historical: it passed `PrivateDirect` 3/3 and completed a real private-relay fallback, while its `PublicDirect` route timed out and its first short-suite harness failed during process cleanup. The kmesh candidate corrects the QAD cleanup and agent mailbox lifecycles; its own public-direct field route now passes 3/3. kmesh's live suite and direct runs above are the current acceptance evidence.

This is short-run validation only. One-hour idle and 1 GiB transfer tests were cancelled and are not claimed.
