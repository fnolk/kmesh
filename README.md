# kmesh

kmesh connects OpenSSH to a target machine through a direct QUIC path when the network allows it, then uses the server's WSS relay when direct UDP cannot be established. OpenSSH continues to handle host-key verification, SSH user authentication, shell sessions, SFTP, SCP, and port forwarding.

The client starts `kmesh proxy` on demand through `ProxyCommand`. A `kmesh agent` stays running on each target machine and forwards one authenticated stream to its locally configured `sshd`. The public server handles user/agent authentication, live RBAC checks, connection coordination, and relaying.

## Build and install

Rust 1.94 or newer and OpenSSH are required. The public server needs a TLS certificate and private key supplied by the deployment. Each agent creates and persists its own QUIC certificate during enrollment. Build the binary with:

```sh
cargo build --locked --release
install -m 0755 target/release/kmesh /usr/local/bin/kmesh
```

The release CI builds Linux x86_64/aarch64 musl and macOS Intel/Apple Silicon targets. kmesh uses Rust TLS libraries and does not enable OpenSSL features.

## Start the public server

Choose a stable HTTPS origin. Use the same canonical origin as the issuer and client `server_url`; kmesh normalizes a trailing slash and the standard HTTPS port.

```sh
kmesh server init \
  --data-dir /var/lib/kmesh \
  --admin admin \
  --issuer https://kmesh.example.com
```

The command prompts for the initial admin password. Start the service with a certificate whose SAN covers the public server name:

```sh
kmesh server run \
  --data-dir /var/lib/kmesh \
  --issuer https://kmesh.example.com \
  --bind 0.0.0.0:443 \
  --tls-cert /etc/kmesh/tls.crt \
  --tls-key /etc/kmesh/tls.key \
  --stun-bind 0.0.0.0:3478
```

For automation, `--password-stdin` reads a password from piped stdin without echoing it or placing it in process arguments. The same option is available for password login and admin user creation/password reset; user creation and reset read two matching lines.

The deployment needs TCP 443 and UDP 3478 reachable. If a network blocks UDP, client and agent carry SSH data over the server's WSS endpoint on 443.

## Configure a target and access

On an administrator workstation, log in and create the target, user, role, and grant. The target ID is stable; its name becomes the OpenSSH alias.

```sh
kmesh --server-url https://kmesh.example.com login --method password --username admin
kmesh --server-url https://kmesh.example.com admin targets create build-machine
kmesh --server-url https://kmesh.example.com admin users create alice
kmesh --server-url https://kmesh.example.com admin roles create engineers
kmesh --server-url https://kmesh.example.com admin users roles <alice-user-id> <engineers-role-id>
kmesh --server-url https://kmesh.example.com admin grants add <engineers-role-id> <target-id>
```

Commands that create or reset a password read it through a hidden prompt. Start the interactive shell with the same server origin:

```sh
kmesh --server-url https://kmesh.example.com admin
```

Inside the shell, `help` and Tab completion are available. One-shot admin commands accept `--json` for machine-readable output. The examples pass `--server-url` on each client command; setting `server_url` in the default config file removes that option from future commands.

For public-key kmesh login, register the user's SSH public key and use `ssh-keygen` for the SSHSIG challenge:

```sh
kmesh --server-url https://kmesh.example.com admin keys add <alice-user-id> ~/.ssh/id_ed25519.pub --label laptop
kmesh --server-url https://kmesh.example.com login \
  --method public-key --username alice --key ~/.ssh/id_ed25519
```

The challenge signature binds the server-provided payload and uses the `kmesh-login` namespace. kmesh sends the public key and signature; the private key stays with OpenSSH or ssh-agent.

On the target machine, enroll the persistent QUIC certificate and start the agent:

```sh
kmesh --server-url https://kmesh.example.com agent enroll \
  --target-id <target-id> --enrollment-code <one-time-code>
kmesh --server-url https://kmesh.example.com agent run --target-id <target-id>
```

The agent uses `ssh.address` from its config, which defaults to `127.0.0.1:22`. A typical Linux config is `~/.local/share/kmesh/config.toml`; macOS stores it under `~/Library/Application Support/kmesh/config.toml`:

```toml
server_url = "https://kmesh.example.com"
profile = "default"

[ssh]
address = "127.0.0.1:22"
connect_timeout_secs = 10

[stun]
servers = []
udp_bind_address = "0.0.0.0:0"
probe_timeout_millis = 2000
```

With no STUN override, kmesh uses the configured server host on UDP port 3478.

## Connect with OpenSSH

On the client, log in and write an OpenSSH host block:

```sh
kmesh --server-url https://kmesh.example.com login --method password --username alice
kmesh --server-url https://kmesh.example.com ssh-config build-machine >> ~/.ssh/config
ssh build-machine
```

The generated block sets `ProxyCommand`, a stable `HostKeyAlias`, and OpenSSH `ControlMaster` reuse. The first SSH connection establishes its path; subsequent SSH/SCP/SFTP commands can reuse the OpenSSH control connection. RBAC is checked when a new underlying transport is created; channels opened over an existing ControlMaster transport share that connection's established authorization. Standard SSH host-key checks remain active. Add the target's verified SSH host key to the client's `known_hosts` before connecting.

The kmesh client state is separated by server origin, profile, and normalized username. Token and agent identity files use mode `0600`, their directories use mode `0700`, and refresh tokens rotate under a cross-process file lock. A refresh with an uncertain network result clears the local login and asks the user to sign in again.

## Enterprise proxies and private CAs

REST and WSS use the same proxy and CA settings. Add proxy and enterprise CA values to the client config:

```toml
server_url = "https://kmesh.example.com"

[tls]
ca_certificates = ["/etc/ssl/certs/company-root.pem"]

[tls.proxy]
url = "https://proxy.corp.example:8443"
username = "kmesh-client"
password = "read-from-a-protected-config-file"
```

The proxy supports HTTP or HTTPS CONNECT and Basic authentication. Keep config files containing proxy passwords readable only by the user. OpenSSH itself still verifies the target SSH host key independently of TLS and QUIC certificates.

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

The Unix integration script [`scripts/e2e.sh`](scripts/e2e.sh) exercises direct QUIC, relay fallback, verified SSH host keys, remote exit codes, SCP/SFTP, ControlMaster reuse, RBAC revocation, concurrent token refresh, and SSHD disconnect propagation against a temporary `sshd` and local kmesh server. It requires `sshd`, OpenSSH tools, `openssl`, `curl`, Python 3, and Rust. Long idle-session and 1 GiB throughput runs require separate duration and capacity testing.
