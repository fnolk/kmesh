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

Set `server_addr` to the public IP address or hostname covered by the TLS certificate. kmesh builds the HTTPS origin internally from `server_addr` and `server_port`; configuration and command-line arguments take the address without `https://` or a path. The default ports are TCP 9443 for HTTPS and UDP 3478 for QAD.

Copy [`config.example.toml`](config.example.toml) to `~/.kmesh/config.toml` and edit it for this host. When that file exists, kmesh uses it for defaults. Explicit command-line options override TOML values, and built-in values apply when neither supplies a setting. Paths in TOML may start with `~/`; other relative paths resolve from the config file's directory. The default data directory is `~/.cache/kmesh`.

```sh
kmesh server init --admin admin
```

The first initialization prints the initial administrator API token once. Store it in `KMESH_TOKEN` or in the local `[auth] token` setting. Start the service with a certificate whose SAN covers the public server name:

```sh
kmesh server run
```

For a server deployment, set `data_dir` to its persistent state location and set `server.tls_cert` and `server.tls_key` in the config. `server.bind_addr` controls both listener IPs. `server_port` controls HTTPS and `server.udp_port` controls QAD; the server publishes the actual QAD UDP port through `/v1/transport` for clients and agents. The UDP setting applies on the server. Clients and agents use the port advertised by the server.

The deployment used for the current acceptance work listens on TCP 9443 for HTTPS control and the self-hosted Iroh relay, and UDP 3478 for QAD. Direct peer paths also need outbound UDP between client and target. When UDP direct paths fail, the last route uses the private relay over the same HTTPS origin; HTTPS control remains required in every route. Official relay services provide QAD for `PublicDirect` and never carry its SSH stream. In public-direct-only mode, set `server.disable_private_relay = true` or pass `--disable-private-relay`; the server then omits its private relay URL from `GET /v1/transport`.

Schema v4 stores API-token credentials and requires a fresh data directory. It does not migrate schema v3 or earlier databases, including the previous STUN/Quinn/WSS-data implementation. Keep existing data as a backup and initialize v4 with a separate, empty `data_dir`.

## Configure a target and access

On an administrator workstation, log in and create the target, user, role, and grant. The target ID is stable; its name becomes the OpenSSH alias.

```sh
kmesh login --method token
kmesh admin targets create build-machine
kmesh admin users create alice
kmesh admin tokens create <alice-user-id> --label laptop
kmesh admin roles create engineers
kmesh admin users roles <alice-user-id> <engineers-role-id>
kmesh admin grants add <engineers-role-id> <target-id>
```

API tokens created by `server init` and `admin tokens create` are shown once. With `KMESH_TOKEN` set, run `kmesh login --method token`; when `[auth].method = "token"` is in the config, you can run `kmesh login`. A command-line `--token` takes priority over `KMESH_TOKEN`, which takes priority over `[auth].token`. The login exchanges the long-lived API token for the normal locally stored session tokens. Start the interactive shell with the same server origin:

```toml
[auth]
method = "token"
token = "kmesh_your_api_token"
```

```sh
kmesh admin
```

List a user's issued tokens when auditing them, and revoke a token when it should stop authenticating:

```sh
kmesh admin tokens list <user-id>
kmesh admin tokens revoke <token-id>
```

Inside the shell, `help` and Tab completion are available. One-shot admin commands accept `--json` for machine-readable output. Use `--server-addr` and `--server-port` to override the configured server for one command.

For public-key kmesh login, register the user's SSH public key and use `ssh-keygen` for the SSHSIG challenge:

```sh
kmesh admin keys add <alice-user-id> ~/.ssh/id_ed25519.pub --label laptop
kmesh login \
  --method public-key --username alice --key ~/.ssh/id_ed25519
```

The challenge signature binds the server-provided payload and uses the `kmesh-login` namespace. kmesh sends the public key and signature; the private key stays with OpenSSH or ssh-agent.

Set `[auth] method = "public-key"`, `username`, and `key` in `~/.kmesh/config.toml` to omit those options from future logins:

```toml
[auth]
method = "public-key"
username = "alice"
key = "~/.ssh/id_ed25519"
```

Login settings from CLI options override TOML. A login requires an explicit method so kmesh never guesses between token and public-key authentication.

On the target machine, enroll its persistent device identity and start the agent:

```sh
kmesh agent enroll \
  --target-id <target-id> --enrollment-code <one-time-code>
kmesh agent run --target-id <target-id>
```

The enrolled device key signs each session's freshly generated target data-plane identity; active SSH sessions use independent Iroh endpoints. The agent reads `ssh.address` from `~/.kmesh/config.toml`, which defaults to `127.0.0.1:22`.

`profile` selects a separate local credential namespace. For example, `kmesh --profile work login ...` saves tokens separately from the `default` profile, so the same server and username can have independent sign-ins. Saved credentials are scoped by server, profile, and normalized username; the profile does not affect routing or server-side access permissions.

The client and agent config contains the server address plus local SSH/TLS settings. There are no client-side STUN server or UDP bind overrides. The proxy and agent discover the private relay URL and QAD port from the server's authenticated `/v1/transport` response. `PrivateDirect` observes B's QAD at the configured server UDP port and an official reflector; `PublicDirect` observes official Iroh QAD reflectors only.

## Connect with OpenSSH

On the client, log in and write an OpenSSH host block:

```sh
kmesh login --method token
kmesh ssh-config build-machine >> ~/.ssh/config
ssh build-machine
```

The generated block sets `ProxyCommand`, a stable `HostKeyAlias`, and OpenSSH `ControlMaster` reuse. The first SSH connection establishes its path; subsequent SSH/SCP/SFTP commands can reuse the OpenSSH control connection. Each underlying transport has one session ID and fresh client/target data EndpointIds. The server checks current RBAC when opening the session and again during activation, after both peers report the selected route and the target reports Iroh readiness. Once activated, the stream runs to completion after permission changes or control-plane disconnection; kmesh does not retry or switch routes mid-SSH. Standard SSH host-key checks remain active. Add the target's verified SSH host key to the client's `known_hosts` before connecting.

The kmesh client state is separated by server origin, profile, and normalized username. Token and agent identity files use mode `0600`, their directories use mode `0700`, and refresh tokens rotate under a cross-process file lock. A refresh with an uncertain network result clears the local login and asks the user to sign in again.

## Private CA certificates

If the server uses a private TLS certificate authority, add its certificate to the client config:

```toml
server_addr = "kmesh.example.com"
server_port = 9443

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
sudo install -o root -g kmesh -m 0640 config.example.toml /etc/kmesh/config.toml
sudo install -o root -g kmesh -m 0640 tls.key /etc/kmesh/tls.key
sudo install -o root -g kmesh -m 0644 tls.crt /etc/kmesh/tls.crt
```

Edit `/etc/kmesh/config.toml` for the deployment: set `server_addr`, `data_dir = "/var/lib/kmesh"`, `server.tls_cert = "/etc/kmesh/tls.crt"`, and `server.tls_key = "/etc/kmesh/tls.key"`. Initialize and start the server with this same config:

```sh
sudo -u kmesh /usr/local/bin/kmesh --config /etc/kmesh/config.toml server init --admin admin
sudo systemctl enable --now kmesh-server.service
```

For a target agent, provide `/etc/kmesh/agent.toml` with the server address and `data_dir = "/var/lib/kmesh"` before starting its unit. The LaunchAgent uses the default `~/.kmesh/config.toml`.

After enrolling a target into `/var/lib/kmesh`, set its UUID and start the instance:

```sh
TARGET_ID=00000000-0000-0000-0000-000000000000
sudo systemctl enable --now "kmesh-agent@${TARGET_ID}.service"
```

## Verification status

The final candidate is source `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`. Formatting and all-target Clippy passed; native all-target tests report 71 passed, 0 failed, and 2 ignored. The two explicit route-acceptance tests passed, and release binaries were built for Linux x86_64/aarch64 musl and macOS x86_64/arm64. The [final build and route evidence](docs/build-validation.md) records the source, checks, and artifact SHA-256 values.

On `target-1`, `PrivateDirect` and `PublicDirect` each passed three fresh SSH commands. Every command selected a direct IPv4 path before SSH, returned `server-1`, and exited with status 23. The full short OpenSSH suite passed SCP/SFTP 1 MiB integrity, forwarding, strict host-key rejection, ControlMaster reuse, idle and concurrent streams, and the RBAC/session boundaries. A separate in-flight SSH command also completed while the private server control connection restarted. See the [current live acceptance report](scripts/verify_iroh_live_report.md).

The kmesh CLI also passed two controlled relay-route tests using a local SSH stub: direct-timeout fallback to the private relay, and private-relay denial with session cleanup. These controlled tests are distinct from a forced private-relay connection to the live `target-1` SSH service. One-hour idle and 1 GiB transfer tests were cancelled and are not part of the acceptance result. The final bounded PrivateDirect sample kept direct path `192.0.2.19:2123` selected while transferring two independent 4 MiB files concurrently in 1.462 seconds, with four interactive echo latencies of 58.943–517.340 ms and 24 proxy RSS samples of 21,568–22,976 KiB. This single run is not an SLO or capacity estimate; see the [sample report](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/perf-eb359f7-20261004/report.json>).
