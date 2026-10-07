# kmesh

kmesh gives OpenSSH an on-demand `ProxyCommand` to a target agent. Each SSH transport uses one Iroh QUIC bidirectional stream. The route plan tries direct UDP paths first; when they fail, it uses only the kmesh server's configured private relay. OpenSSH continues to handle host-key verification, SSH account authentication, shell sessions, SFTP, SCP, and port forwarding.

The client starts `kmesh proxy` on demand through `ProxyCommand`; it does not need a resident kmesh agent. One `kmesh agent` stays running on each target machine and forwards authenticated streams to its locally configured `sshd`. The kmesh server handles user and device authentication, current RBAC, connection coordination, and the self-hosted relay.

Each new SSH transport follows a bounded route plan. With a private relay configured, kmesh tries `PrivateDirect`, then `PublicDirect`, then `PrivateRelay`. Both direct modes use QAD only to discover candidates and disable Iroh relay data paths; `PublicDirect` never sends SSH bytes through a public relay. `PrivateRelay` allows only the relay at the kmesh server's HTTPS origin and disables IP transports. Without a private relay URL, only `PublicDirect` is available. Network and timeout failures can advance to the next fresh, separately authorized attempt; certificate, identity, permission, and configuration failures stop the plan. The proxy prints the selected path and route failures to stderr; stdout carries only SSH bytes.

## Build and install

Rust 1.94 or newer and OpenSSH are required. The public server needs a TLS certificate and private key supplied by the deployment. Each target agent creates and persists a stable Iroh endpoint identity during enrollment. Build the binary with:

```sh
cargo build --locked --release
mkdir -p ~/.local/bin
install -m 0755 target/release/kmesh ~/.local/bin/kmesh
```

Add `~/.local/bin` to `PATH` for an ordinary user install. Service deployments may place the binary in a system-owned path for their service units.

The CI workflow is configured to build Linux x86_64/aarch64 musl and macOS Intel/Apple Silicon binaries and upload each target's artifact. It also runs native formatting, Clippy, and test checks. kmesh uses Rust TLS libraries; its Linux dependency graph includes `openssl-probe` for certificate discovery and contains no OpenSSL TLS or `native-tls` package.

## Start the public server

Choose a stable HTTPS origin. The examples use `https://kmesh.example.com:9443`; use the same canonical origin for `--issuer` and client `server_url`, and issue a TLS certificate for its host.

```sh
kmesh server init \
  --data-dir /var/lib/kmesh \
  --admin admin \
  --issuer https://kmesh.example.com:9443
```

The command prompts for the initial admin password. Start the service with a certificate whose SAN covers the public server name:

```sh
kmesh server run \
  --data-dir /var/lib/kmesh \
  --issuer https://kmesh.example.com:9443 \
  --bind 0.0.0.0:9443 \
  --tls-cert /etc/kmesh/tls.crt \
  --tls-key /etc/kmesh/tls.key \
  --qad-bind 0.0.0.0:3478
```

For automation, `--password-stdin` reads a password from piped stdin without echoing it or placing it in process arguments. The same option is available for password login and admin user creation/password reset; user creation and reset read two matching lines.

The deployment used for the current acceptance work listens on TCP 9443 for HTTPS control and the self-hosted Iroh relay, and UDP 3478 for QAD. Direct peer paths also need outbound UDP between client and target. When UDP direct paths fail, the last route uses the private relay over the same HTTPS origin; HTTPS control remains required in every route. Official relay services provide QAD for `PublicDirect` and never carry its SSH stream. In public-direct-only mode, pass `--disable-private-relay`; the server then omits its private relay URL from `GET /v1/transport`.

The current schema expects a fresh kmesh database. It does not migrate databases from the earlier STUN/Quinn/WSS-data implementation. Keep the old data directory as a backup and initialize the Iroh version with a separate, empty `--data-dir`.

## Configure a target and access

On an administrator workstation, log in and create the target, user, role, and grant. The target ID is stable; its name becomes the OpenSSH alias.

```sh
kmesh --server-url https://kmesh.example.com:9443 login --method password --username admin
kmesh --server-url https://kmesh.example.com:9443 admin targets create build-machine
kmesh --server-url https://kmesh.example.com:9443 admin users create alice
kmesh --server-url https://kmesh.example.com:9443 admin roles create engineers
kmesh --server-url https://kmesh.example.com:9443 admin users roles <alice-user-id> <engineers-role-id>
kmesh --server-url https://kmesh.example.com:9443 admin grants add <engineers-role-id> <target-id>
```

Commands that create or reset a password read it through a hidden prompt. Start the interactive shell with the same server origin:

```sh
kmesh --server-url https://kmesh.example.com:9443 admin
```

Inside the shell, `help` and Tab completion are available. One-shot admin commands accept `--json` for machine-readable output. The examples pass `--server-url` on each client command; setting `server_url` in the default config file removes that option from future commands.

For public-key kmesh login, register the user's SSH public key and use `ssh-keygen` for the SSHSIG challenge:

```sh
kmesh --server-url https://kmesh.example.com:9443 admin keys add <alice-user-id> ~/.ssh/id_ed25519.pub --label laptop
kmesh --server-url https://kmesh.example.com:9443 login \
  --method public-key --username alice --key ~/.ssh/id_ed25519
```

The challenge signature binds the server-provided payload and uses the `kmesh-login` namespace. kmesh sends the public key and signature; the private key stays with OpenSSH or ssh-agent.

On the target machine, enroll its persistent device identity and start the agent:

```sh
kmesh --server-url https://kmesh.example.com:9443 agent enroll \
  --target-id <target-id> --enrollment-code <one-time-code>
kmesh --server-url https://kmesh.example.com:9443 agent run --target-id <target-id>
```

The enrolled device key signs each session's freshly generated target data-plane identity; active SSH sessions use independent Iroh endpoints. The agent uses `ssh.address` from its config, which defaults to `127.0.0.1:22`. A typical Linux config is `~/.local/share/kmesh/config.toml`; macOS stores it under `~/Library/Application Support/kmesh/config.toml`:

```toml
server_url = "https://kmesh.example.com:9443"
profile = "default"

[ssh]
address = "127.0.0.1:22"
connect_timeout_secs = 10
```

The client and agent config only need the kmesh control URL plus their local SSH/TLS settings. There are no client-side STUN server or UDP bind overrides. The proxy and agent discover the private relay URL and QAD port from the server's authenticated `/v1/transport` response. `PrivateDirect` observes B's QAD at UDP 3478 and an official reflector; `PublicDirect` observes official Iroh QAD reflectors only.

## Connect with OpenSSH

On the client, log in and write an OpenSSH host block:

```sh
kmesh --server-url https://kmesh.example.com:9443 login --method password --username alice
kmesh --server-url https://kmesh.example.com:9443 ssh-config build-machine >> ~/.ssh/config
ssh build-machine
```

The generated block sets `ProxyCommand`, a stable `HostKeyAlias`, and OpenSSH `ControlMaster` reuse. The first SSH connection establishes its path; subsequent SSH/SCP/SFTP commands can reuse the OpenSSH control connection. Each underlying transport has one session ID and fresh client/target data EndpointIds. The server checks current RBAC when opening the session and again during activation, after both peers report the selected route and the target reports Iroh readiness. Once activated, the stream runs to completion after permission changes or control-plane disconnection; kmesh does not retry or switch routes mid-SSH. Standard SSH host-key checks remain active. Add the target's verified SSH host key to the client's `known_hosts` before connecting.

The kmesh client state is separated by server origin, profile, and normalized username. Token and agent identity files use mode `0600`, their directories use mode `0700`, and refresh tokens rotate under a cross-process file lock. A refresh with an uncertain network result clears the local login and asks the user to sign in again.

## Private CA certificates

If the server uses a private TLS certificate authority, add its certificate to the client config:

```toml
server_url = "https://kmesh.example.com:9443"

[tls]
ca_certificates = ["/etc/ssl/certs/company-root.pem"]
```

The configured certificate authority verifies the HTTPS control connection and private Iroh relay. `PrivateRelay` needs outbound HTTPS to the server origin; `PrivateDirect` and `PublicDirect` still depend on UDP being allowed between peers. OpenSSH verifies the target SSH host key independently of TLS and Iroh endpoint identity.

## Service files

Example systemd units for a server and one target agent are in [`deploy/systemd`](deploy/systemd). A per-user macOS LaunchAgent template is in [`deploy/launchd`](deploy/launchd). Review paths, user IDs, origins, and certificate locations before enabling them.

For systemd, create the service account and protect its state/config files before enabling the units. Ensure `kmesh` can read the server TLS key and the agent config; keep each directory at `0700` and each secret file at `0600`.

```sh
sudo useradd --system --home-dir /var/lib/kmesh --shell /usr/sbin/nologin kmesh
sudo install -d -o kmesh -g kmesh -m 0700 /var/lib/kmesh /etc/kmesh
sudo install -o root -g kmesh -m 0640 tls.key /etc/kmesh/tls.key
sudo install -o root -g kmesh -m 0644 tls.crt /etc/kmesh/tls.crt
sudo systemctl enable --now kmesh-server.service
```

After enrolling a target into `/var/lib/kmesh`, set its UUID and start the instance:

```sh
TARGET_ID=00000000-0000-0000-0000-000000000000
sudo systemctl enable --now "kmesh-agent@${TARGET_ID}.service"
```

## Verification status

The final candidate is source `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`. Formatting and all-target Clippy passed; native all-target tests report 71 passed, 0 failed, and 2 ignored. The two explicit route-acceptance tests passed, and release binaries were built for Linux x86_64/aarch64 musl and macOS x86_64/arm64. The [final build and route evidence](docs/build-validation.md) records the source, checks, and artifact SHA-256 values.

On `target-1`, `PrivateDirect` and `PublicDirect` each passed three fresh SSH commands. Every command selected a direct IPv4 path before SSH, returned `server-1`, and exited with status 23. The full short OpenSSH suite passed SCP/SFTP 1 MiB integrity, forwarding, strict host-key rejection, ControlMaster reuse, idle and concurrent streams, and the RBAC/session boundaries. A separate in-flight SSH command also completed while the private server control connection restarted. See the [current live acceptance report](scripts/verify_iroh_live_report.md).

The kmesh CLI also passed two controlled relay-route tests using a local SSH stub: direct-timeout fallback to the private relay, and private-relay denial with session cleanup. These controlled tests are distinct from a forced private-relay connection to the live `target-1` SSH service. One-hour idle and 1 GiB transfer tests were cancelled and are not part of the acceptance result. The final bounded PrivateDirect sample kept direct path `192.0.2.19:2123` selected while transferring two independent 4 MiB files concurrently in 1.462 seconds, with four interactive echo latencies of 58.943–517.340 ms and 24 proxy RSS samples of 21,568–22,976 KiB. This single run is not an SLO or capacity estimate; see the [sample report](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/perf-eb359f7-20261004/report.json>).
