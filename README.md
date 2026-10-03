# kmesh

kmesh gives OpenSSH an on-demand `ProxyCommand` to a target agent. Each SSH transport uses one Iroh QUIC bidirectional stream: Iroh establishes a direct peer path when possible and relays the same stream when the network requires it. OpenSSH continues to handle host-key verification, SSH account authentication, shell sessions, SFTP, SCP, and port forwarding.

The client starts `kmesh proxy` on demand through `ProxyCommand`; it does not need a resident kmesh agent. One `kmesh agent` stays running on each target machine and forwards authenticated streams to its locally configured `sshd`. The kmesh server handles user and device authentication, current RBAC, connection coordination, and the self-hosted relay.

When configured, kmesh first uses the relay embedded at the same HTTPS origin as the control service. A network-only failure can start a fresh, separately authorized session through Iroh's default public relay set. The relay modes carry data only: login, authorization, ticket issuance, and activation continue to require the kmesh server. Certificate, identity, permission, and configuration failures stop the attempt without changing relay mode. The proxy reports the selected Iroh path to stderr; stdout carries only SSH bytes.

## Build and install

Rust 1.94 or newer and OpenSSH are required. The public server needs a TLS certificate and private key supplied by the deployment. Each target agent creates and persists a stable Iroh endpoint identity during enrollment. Build the binary with:

```sh
cargo build --locked --release
install -m 0755 target/release/kmesh /usr/local/bin/kmesh
```

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

The default deployment listens on TCP 9443 for HTTPS control and the self-hosted Iroh relay, and UDP 3478 for Iroh QAD. Direct peer paths also require outbound UDP between the client and target. If the self-hosted path cannot be reached for network reasons, the client and target may use Iroh's default public relay set; their HTTPS control connection to the kmesh server remains required. In public-relay-only mode, pass `--disable-private-relay`; this omits the server's private relay URL from `GET /v1/transport`.

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

On the target machine, enroll its persistent Iroh identity and start the agent:

```sh
kmesh --server-url https://kmesh.example.com:9443 agent enroll \
  --target-id <target-id> --enrollment-code <one-time-code>
kmesh --server-url https://kmesh.example.com:9443 agent run --target-id <target-id>
```

The agent uses `ssh.address` from its config, which defaults to `127.0.0.1:22`. A typical Linux config is `~/.local/share/kmesh/config.toml`; macOS stores it under `~/Library/Application Support/kmesh/config.toml`:

```toml
server_url = "https://kmesh.example.com:9443"
profile = "default"

[ssh]
address = "127.0.0.1:22"
connect_timeout_secs = 10
```

The client and agent config only need the kmesh control URL plus their local SSH/TLS settings. There are no STUN server or UDP bind overrides. The proxy and agent discover the private relay URL and actual QAD port from the server's authenticated `/v1/transport` response.

## Connect with OpenSSH

On the client, log in and write an OpenSSH host block:

```sh
kmesh --server-url https://kmesh.example.com:9443 login --method password --username alice
kmesh --server-url https://kmesh.example.com:9443 ssh-config build-machine >> ~/.ssh/config
ssh build-machine
```

The generated block sets `ProxyCommand`, a stable `HostKeyAlias`, and OpenSSH `ControlMaster` reuse. The first SSH connection establishes its path; subsequent SSH/SCP/SFTP commands can reuse the OpenSSH control connection. RBAC is checked for a new transport and again before activation. An already activated SSH stream runs to completion after permission changes or control-plane disconnection; a new stream still requires online authorization. Standard SSH host-key checks remain active. Add the target's verified SSH host key to the client's `known_hosts` before connecting.

The kmesh client state is separated by server origin, profile, and normalized username. Token and agent identity files use mode `0600`, their directories use mode `0700`, and refresh tokens rotate under a cross-process file lock. A refresh with an uncertain network result clears the local login and asks the user to sign in again.

## Enterprise proxies and private CAs

HTTPS control and Iroh relay connections use the same proxy and CA settings. Add proxy and enterprise CA values to the client config:

```toml
server_url = "https://kmesh.example.com:9443"

[tls]
ca_certificates = ["/etc/ssl/certs/company-root.pem"]

[tls.proxy]
url = "https://proxy.corp.example:8443"
username = "kmesh-client"
password = "read-from-a-protected-config-file"
```

The proxy supports HTTP or HTTPS CONNECT and Basic authentication. Keep config files containing proxy passwords readable only by the user. OpenSSH verifies the target SSH host key independently of TLS and Iroh endpoint identity.

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

Run the local checks with `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo test --locked --all-targets`. The self-hosted integration test starts local HTTPS and QAD listeners, verifies an observed UDP address, completes ticket authorization and activation, and transfers SSH-shaped bytes over a TCP fixture. Agent tests also cover ticket stream interruption and cancellation before activation. These local tests do not contact a public relay or run against a live target.

[`scripts/verify_iroh_live.py`](scripts/verify_iroh_live.py) provides separate read-only preflight, staging, deployment, and SSH verification commands. [`scripts/verify_live.md`](scripts/verify_live.md) describes the short live checks, and [`scripts/verify_iroh_live_report.md`](scripts/verify_iroh_live_report.md) records the current public server and `target-1` results. The retired [`scripts/verify_live_report.md`](scripts/verify_live_report.md) covers the earlier STUN/Quinn/WSS implementation only. Long-duration sessions and large-file transfers are outside the current verification scope.
