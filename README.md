# kmesh

kmesh gives OpenSSH an on-demand `ProxyCommand` to a target agent. Each SSH transport uses one Iroh QUIC bidirectional stream. The route plan tries direct UDP paths first; when they fail, it uses only the kmesh server's configured private relay. OpenSSH continues to handle host-key verification, SSH account authentication, shell sessions, SFTP, SCP, and port forwarding.

The client starts `kmesh proxy` on demand through `ProxyCommand`; it does not need a resident kmesh agent. One `kmesh agent` stays running on each target machine and forwards authenticated streams to its locally configured `sshd`. The kmesh server handles user and device authentication, current RBAC, connection coordination, and the self-hosted relay.

Each new SSH transport follows a bounded route plan. With a private relay configured, kmesh tries `PrivateDirect`, then `PublicDirect`, then `PrivateRelay`. Both direct modes use QAD only to discover candidates and disable Iroh relay data paths; `PublicDirect` never sends SSH bytes through a public relay. `PrivateRelay` allows only the relay at the kmesh server's HTTPS origin and disables IP transports. Without a private relay URL, only `PublicDirect` is available. Network and timeout failures can advance to the next fresh, separately authorized attempt; certificate, identity, permission, and configuration failures stop the plan. The proxy prints the selected path and route failures to stderr; stdout carries only SSH bytes.

## Build and install

Rust 1.94 or newer, OpenSSL, and OpenSSH are required. Each build embeds the kmesh mTLS trust certificate plus server and client identities; prepare those materials as described in [Build-time mTLS certificates](#build-time-mtls-certificates). Each target agent creates and persists a stable Iroh endpoint identity during enrollment. Build the binary with:

```sh
cargo build --locked --release
mkdir -p ~/.local/bin
install -m 0755 target/release/kmesh ~/.local/bin/kmesh
```

Add `~/.local/bin` to `PATH` for an ordinary user install. Service deployments may place the binary in a system-owned path for their service units.

The CI workflow builds Linux x86_64/aarch64 musl, macOS Apple Silicon, and Windows x86_64 binaries, and runs formatting, Clippy, and test checks. Pull request checks, including fork pull requests, generate temporary test identities. Trusted release builds embed the configured mTLS identities in each binary. Publishing a GitHub release tagged `v<version>` builds and attaches one archive per platform; the tag must match the version in `Cargo.toml`. kmesh uses Rust TLS libraries; its Linux dependency graph includes `openssl-probe` for certificate discovery and contains no OpenSSL TLS or `native-tls` package.

`kmesh --version` prints the package version, build branch, commit ID, build time, and Rust toolchain metadata. The server checks this version on every `/v1` API request and both client and agent control connections. Stable releases interoperate within the same major version; `0.x` releases also require the same minor version. Prerelease builds require matching major, minor, patch, and prerelease identifiers.

## Start the public server

Set `server_addr` to the public IP address or hostname clients use to reach the server. Private mTLS handshakes omit SNI, so this address is used for network resolution and the HTTP `Host` value only. The server certificate still identifies the kmesh service as `DNS:kmesh.internal`; clients validate that identity against the embedded CA independently of the configured address. kmesh builds the HTTPS origin internally from `server_addr` and `server_port`; configuration and command-line arguments take the address without `https://` or a path. The default ports are TCP 9443 for HTTPS and UDP 3478 for QAD.

Copy [`config.example.toml`](config.example.toml) to `~/.kmesh/config.toml` and edit it for this host. When that file exists, kmesh uses it for defaults. Explicit command-line options override TOML values, and built-in values apply when neither supplies a setting. Paths in TOML may start with `~/`; other relative paths resolve from the config file's directory. The default data directory is `~/.cache/kmesh`.

```sh
kmesh server init --admin admin
```

The first initialization prints the initial administrator API JWT once. Set
`[auth].method = "token"` and store the value in `KMESH_TOKEN` or `[auth].token`.
Start the service; its mTLS server identity is embedded in the binary:

```sh
kmesh server run
```

For a server deployment, set `data_dir` to its persistent state location. `server.bind_addr` controls both listener IPs. `server_port` controls HTTPS and `server.udp_port` controls QAD; the server publishes the actual QAD UDP port through `/v1/transport` for clients and agents. The UDP setting applies on the server. Clients and agents use the port advertised by the server.

The deployment used for the current acceptance work listens on TCP 9443 for HTTPS control and the self-hosted Iroh relay, and UDP 3478 for QAD. Direct peer paths also need outbound UDP between client and target. When UDP direct paths fail, the last route uses the private relay over the same HTTPS origin; HTTPS control remains required in every route. Official relay services provide QAD for `PublicDirect` and never carry its SSH stream. In public-direct-only mode, set `server.disable_private_relay = true` or pass `--disable-private-relay`; the server then omits its private relay URL from `GET /v1/transport`.

Version 0.4.1 uses the 0.4 API and schema version 6. It separates platform roles from access groups. Upgrades from 0.3.x or earlier require a separate, empty `data_dir`; earlier schemas are not migrated. Existing 0.4.0 databases remain compatible. Version 0.3 clients cannot use a 0.4 server. Upgrade the server, clients, and agents together when moving from 0.3.x.

## Compact admin interface

Use the overview to inspect users, platform roles, access groups, targets, and credential counts
in one command. Use a detail view to inspect each access path, API token metadata,
and SSH public key fingerprints for the related users:

```sh
kmesh admin overview        # Short form: kmesh a ls
kmesh a u s alice           # users show alice
kmesh a r ls                 # roles list
kmesh a g s engineers       # groups show engineers
kmesh a t s build-machine   # targets show build-machine
kmesh a ls -j               # Joined JSON view
```

The overview separates user and target state from target availability. An enabled
but offline target can remain authorized. The access path is user → access group →
`ssh_connect` grant → target. The `admin` platform role gives no SSH access.
Detail views show the selected access paths and their disabled-user or
disabled-target blockers. Relationship columns show each object's full assignments.
Tokens and keys belong to users; they are not target-specific credentials.

`TOKENS A/T` means active/total API tokens, with expired and revoked tokens
excluded from the active count. An active token cannot authenticate a disabled
user. Key counts include currently registered keys. Lists show complete IDs and
SHA256 key fingerprints. They do not print token values or public key blobs.
Token creation and enrollment commands still show the new credential once.
Admin commands with `--json` return the 0.4 API response shape. The
`keys list` response includes public key text; joined JSON views contain
fingerprints only.

Joined views use sequential reads of the existing API. They are not atomic
snapshots. The view reports its collection time and fails if a required read or a
relationship check fails. Run it again after concurrent administrative changes. Retained grants to targets
missing from the target list appear as unavailable references with a warning;
they never count as authorized access.
The overview needs three resource-list requests, one per user for access groups,
one per access group for grants, and two per relevant user for token and key metadata. Use the
original resource-list commands when only a small list is needed.

Common short forms:

```sh
kmesh a u c alice                       # users create
kmesh a g c engineers                   # groups create
kmesh a u roles alice admin             # Set alice's platform role
kmesh a u groups alice engineers        # Set access groups for alice
kmesh a gr a engineers build-machine    # grants add; add one permission
kmesh a tk c alice -l laptop -e 604800   # tokens create; lifetime in seconds
kmesh a k a alice ~/.ssh/id_ed25519.pub -l laptop
kmesh a t en build-machine              # targets issue-enrollment
kmesh a rx ls                           # relay list
```

Resource aliases are `u` (users), `r` (roles), `g` (groups), `gr` (grants), `t` (targets), `tk` (tokens),
`k`/`pk` (keys), and `rx` (relay). Actions include `ls`/`l` (list),
`s` (show), `c`/`new` (create), `a` (add), `rm` (remove/delete/revoke), `on`/`off`
(enable/disable), `mv` (rename), and `en` (issue-enrollment), where applicable.
Aliases are explicit; arbitrary command prefixes are not accepted. Use the
canonical commands in this release. `users roles` sets one platform role: `member` or
`admin`. `users groups` replaces all access groups. Use an empty group ID list to
remove every access group. Confirm this change at the prompt, or pass `--yes` in scripts.
`grants add` adds the named permission.

Global short options work before or after subcommands: `-c` config, `-d` data
directory, `-p` profile, `-s` server address, and `-P` server port. Admin accepts
`-j` JSON, token/key creation accepts `-l` label, token creation accepts `-e`
lifetime, and grant changes accept `-x` permission. Use `--help` on each command
for its arguments. The interactive shell supports the same resource and action
aliases and Tab completion. `kmesh admin` opens the shell; `kmesh admin -j` prints
the overview as JSON and exits.

Human-readable tables use spaces, clear headings, row counts, complete IDs, and
explicit empty results. Terminal control characters in table values are escaped.
Use `--json` for scripts. Runtime messages and help use English with the
[CLI language and display guide](docs/cli-style.md). The guide sets the ASD-STE100
Issue 9 vocabulary, sentence length, and project term rules. User data, exact
identifiers, and dependency diagnostics retain their original meanings.

## Change access groups safely

Use incremental commands to retain the user's other groups:

```sh
kmesh admin users add-groups alice engineers support
kmesh admin users remove-groups alice support
kmesh admin users groups alice engineers --dry-run
kmesh admin users groups alice --yes
```

`users groups` (also `users set-groups`) replaces all assignments. `add-groups`
adds only the specified groups. `remove-groups` removes only the specified groups.
Both incremental commands require at least one group ID. Repeated IDs have no
additional effect. All specified groups must exist.

Each command shows the groups before and after the change. It also shows target
access that the user gains or loses. Disabled users and disabled or removed targets
have no effective target access. An offline target can still be authorized. Access
through a retained group is not reported as lost.

Use `--dry-run` to inspect a change without writing assignments or audit records.
The server applies group changes in one transaction. Before a write, it checks
that the preview still matches the current assignments and effective access changes.
If the preview changed, the command stops. Run it again to obtain a new preview.

When a change removes all existing groups, the terminal asks you to type `yes`.
Any other response cancels the change. Scripts and JSON commands require `--yes`
for this operation. `--yes` does not bypass the preview check. Existing SSH
connections, including connections reused by OpenSSH, can continue after a change.

All group commands accept `--json`. The existing replacement command retains its
`result: "user_access_groups"` and `data` fields. It adds `change` and `applied`.
Incremental commands and previews use `result: "group_change"`. Human-readable
previews go to stderr before a write. JSON results go only to stdout.

## Check credentials, access, and connections

```sh
kmesh status
kmesh status --json
kmesh access explain alice build-machine
kmesh doctor build-machine
kmesh doctor build-machine --json
```

`status` checks the HTTPS service, version compatibility, available route settings,
and the configured credentials. It shows the server, profile, client version,
user, and platform role. It never prints tokens or private keys. A public-key
session is created or refreshed when a command needs it.

`access explain <user-id> <target-id>` requires the admin platform role. It shows
access groups, granting groups, permission blockers, and agent availability.
Authorization is evaluated from one database snapshot. Online state is read
separately. Missing grants, disabled accounts, and disabled or removed targets are
reported separately. Platform admin status does not grant SSH access. This command
returns success when it produces an explanation, including an access denial.

`doctor <target-id>` works for administrators and ordinary users. It checks the
server, version, credentials, target access, agent availability, network path,
and SSH service. Ordinary users receive no details about targets they cannot access.
Checks after a failure are marked `not_checked`. Failed checks include a next
action and return a nonzero exit status. `status` uses the same failure convention.
With `--json`, the report remains one JSON object on stdout. Errors go to stderr.

The connection check opens a temporary authorized session through the normal
route plan. It can take up to the normal 60-second setup budget, plus 12 seconds
for the SSH identification and connection cleanup. It reads a bounded SSH
identification, then closes the stream and session. This produces connection
activity and can appear in server or SSH logs. It does not authenticate to the
SSH account or execute a command. A successful check does not verify the SSH host key or account
credentials. Use OpenSSH to verify those separately. A failed SSH identification
check requires inspection of the agent's local SSH address, service, and logs.

These commands require a server that supports the new group-change and
access-explanation operations. Upgrade the server before using these operations.
Existing API operations and database schemas are unchanged.

## Configure a target and access

On an administrator workstation, configure credentials and create the target, user, access group, and grant. New users have the `member` platform role and no access groups. The fixed platform roles are `member` and `admin`. Access group IDs are the trimmed names with ASCII letters lowercased. Target names at creation and rename use a 1–64 character ASCII slug (`A–Z`, `a–z`, `0–9`, `.`, `_`, `-`; the first character is alphanumeric). On creation, the lowercase name becomes the fixed target ID while its casing remains the display name. Rename changes the name and OpenSSH alias while preserving the ID. Admin commands refer to users, access groups, and targets by ID. Platform roles use the fixed values `member` and `admin`.

Target creation and enrollment issue commands show a complete enrollment command. The command includes `--server-port` only when the server uses a port other than `9443`.

`ssh-config` scopes `HostKeyAlias` by the canonical server origin and target ID. Agent state uses the selected data directory and target ID. Use a separate data directory for each server when target IDs are equal.

To use API token authentication, set `[auth].method = "token"` in
`~/.kmesh/config.toml`. Set `KMESH_TOKEN` or store the token in `[auth].token`.
The environment variable takes priority.

```toml
[auth]
method = "token"
token = "<signed API JWT>"
```

```sh
kmesh admin targets create build-machine
kmesh admin users create alice
kmesh admin tokens create alice --label laptop
kmesh admin tokens create alice --label automation --expires-in 604800
kmesh admin roles list
kmesh admin groups create engineers
kmesh admin users groups alice engineers
kmesh admin grants add engineers build-machine
```

Give Alice platform admin access when she must change server users, groups,
targets, credentials, or relay traffic:

```sh
kmesh admin users roles alice admin
```

API JWTs created by `server init` and `admin tokens create` are shown once. They act as Bearer credentials directly. Omitting `--expires-in` creates a long-lived JWT; `--expires-in <seconds>` sets its lifetime. Each command sends the configured token directly to the server. Replace an expired token in its source. Token authentication does not use refresh tokens. Public-key authentication uses a separate access and refresh session.

Start the interactive shell with the same server origin:

```sh
kmesh admin
```

List a user's issued tokens when auditing them, and revoke a token when it should stop authenticating:

```sh
kmesh admin tokens list <user-id>
kmesh admin tokens revoke <token-id>
```

Inside the shell, `help` and Tab completion are available. One-shot admin commands accept `--json` for machine-readable output. Use `--server-addr` and `--server-port` to override the configured server for one command.

For public-key authentication, register the user's SSH public key and configure the SSH private key for the SSHSIG challenge:

```sh
kmesh admin keys add <alice-user-id> ~/.ssh/id_ed25519.pub --label laptop
```

The challenge signature binds the server-provided payload and uses the `kmesh-login` namespace. kmesh sends the public key and signature; the private key stays with OpenSSH or ssh-agent.

Set `[auth] method = "public-key"`, `username`, and `key` in `~/.kmesh/config.toml`. Commands then authenticate with this SSH key when required:

```toml
[auth]
method = "public-key"
username = "alice"
key = "~/.ssh/id_ed25519"
```

For an encrypted key held by `ssh-agent`, set `key` to its `.pub` file. Keep the
private key loaded in the agent when kmesh needs to sign a challenge.

On the target machine, enroll the target agent and start it:

```sh
kmesh --server-addr mesh.example.com agent enroll \
  --target-id <target-id> --enrollment-code <enrollment-code>
kmesh agent run --target-id <target-id>
```

The agent stores its server address, credentials, device identity, and SSH settings under `<data-dir>/agents/<target-id>`. On Linux, root uses `/var/lib/kmesh`. Other Linux users use `$XDG_STATE_HOME/kmesh`, or `~/.local/state/kmesh` when `XDG_STATE_HOME` is empty. On macOS, the default is `~/Library/Application Support/kmesh`. On Windows, the default is `%LOCALAPPDATA%/kmesh`.

The default local SSH address is `127.0.0.1:22`, and the default time limit is 10 seconds. Use `--ssh-address` and `--ssh-connect-timeout-secs` during enrollment to change these values. The `agent run` command reads its run settings from the agent state in this data directory. If you set `--data-dir` during enrollment, use the same value with `agent run`. The enrollment result prints the full run command.

`profile` selects a separate local public-key session cache. For example, `kmesh --profile work targets list` keeps its cached session separate from the `default` profile. The cache is scoped by server, profile, username, and SSH public-key fingerprint. The profile does not affect routing or server-side access permissions.

Client config contains the server address. Enrollment stores the target's local SSH address and time limit in agent state. Remove the old `[ssh]` section from existing `config.toml` files. Set the target's SSH values during agent enrollment. There are no client-side STUN server or UDP bind overrides. The proxy and agent discover the private relay URL and QAD port from the server's authenticated `/v1/transport` response. `PrivateDirect` observes B's QAD at the configured server UDP port and an official reflector; `PublicDirect` observes official Iroh QAD reflectors only.

## Connect with OpenSSH

On the client, configure credentials and write an OpenSSH host block:

```sh
kmesh ssh-config build-machine >> ~/.ssh/config
ssh build-machine
```

The generated block sets `ProxyCommand`, a stable `HostKeyAlias`, and OpenSSH `ControlMaster` reuse. The first SSH connection establishes its path; subsequent SSH/SCP/SFTP commands can reuse the OpenSSH control connection. Each underlying transport has one session ID and fresh client/target data EndpointIds. The server checks current RBAC when opening the session and again during activation, after both peers report the selected route and the target reports Iroh readiness. Once activated, the stream runs to completion after permission changes or control-plane disconnection; kmesh does not retry or switch routes mid-SSH. Standard SSH host-key checks remain active. Add the target's verified SSH host key to the client's `known_hosts` before connecting.

The generated `ProxyCommand` receives the selected config path and server options. It inherits `KMESH_TOKEN` from the `ssh` process. Set the same token source or public-key settings in that config file.

The public-key session cache is separated by server, profile, username, and configured key fingerprint. Cached sessions and agent state files use mode `0600`; their directories use mode `0700`. Public-key session refresh tokens rotate under a cross-process file lock. If refresh has an uncertain result, kmesh clears the cache and reports the error. Run the command again to authenticate with the configured SSH key. Enroll each existing agent again to create state in the new directory layout.

## Build-time mTLS certificates

Every build needs a CA certificate, a server certificate and key, and a client certificate and key. The CA certificate is the public trust anchor each side uses to verify its peer's certificate; its separate private key signs certificates and stays outside the build inputs. The server certificate must identify `DNS:kmesh.internal`; `server_addr` remains a separately configurable network address and private mTLS handshakes omit SNI. The server validates the peer's client certificate against the embedded CA and `clientAuth` usage. Clients and agents validate the peer's server certificate against the embedded CA, `serverAuth` usage, and fixed `DNS:kmesh.internal` service identity. Public QAD connections continue to use normal WebPKI validation and hostname SNI.

Open-source users can create a local CA and both identities with the included OpenSSL script. It writes a private output directory with mode `0700`, protects PEM files with mode `0600`, and issues server/client certificates with the required EKUs and validity through `2099-12-31 23:59:59 UTC`:

```sh
cert_dir="$HOME/.local/share/kmesh/build-certs"
scripts/generate-mtls-certs.sh "$cert_dir"

export KMESH_CA_CERT_PATH="$cert_dir/ca-cert.pem"
export KMESH_SERVER_CERT_PATH="$cert_dir/server-cert.pem"
export KMESH_SERVER_KEY_PATH="$cert_dir/server-key.pem"
export KMESH_CLIENT_CERT_PATH="$cert_dir/client-cert.pem"
export KMESH_CLIENT_KEY_PATH="$cert_dir/client-key.pem"

cargo build --locked --release
```

The CA private key is saved as `ca-key.pem` for certificate issuance and is never passed to Cargo. The five environment variables point to PEM files used by the build; missing or invalid material makes the build fail. The resulting binary contains the CA certificate and both private identities, so distribute it only to trusted server, client, and agent hosts. User login, tokens, and server-side access control continue to authenticate kmesh users.

To rotate these identities, create a fresh certificate set, export its five paths, rebuild the release binaries, and deploy the rebuilt binary to the server, clients, and agents as one coordinated update. Restart kmesh processes after deployment so they use the new embedded material. OpenSSH verifies target SSH host keys independently of mTLS and Iroh endpoint identity.

## Service files

Example systemd units for a server and one target agent are in [`deploy/systemd`](deploy/systemd). A per-user macOS LaunchAgent template is in [`deploy/launchd`](deploy/launchd). Review paths, user IDs, and origins before enabling them.

For systemd, create the service account and protect its state and configuration files before enabling the units. Keep each private directory at `0700` and each secret file at `0600`.

```sh
sudo useradd --system --home-dir /var/lib/kmesh --shell /usr/sbin/nologin kmesh
sudo install -d -o kmesh -g kmesh -m 0700 /var/lib/kmesh
```

For a server, create its config directory and copy the example file:

```sh
sudo install -d -o root -g kmesh -m 0750 /etc/kmesh
sudo install -o root -g kmesh -m 0640 config.example.toml /etc/kmesh/config.toml
```

Edit `/etc/kmesh/config.toml` for the deployment and set `server_addr` and `data_dir = "/var/lib/kmesh"`. Initialize and start the server with this same config:

```sh
sudo -u kmesh /usr/local/bin/kmesh --config /etc/kmesh/config.toml server init --admin admin
sudo systemctl enable --now kmesh-server.service
```

For a target agent, enroll as the service user. The command stores its credentials under `/var/lib/kmesh/agents/<target-id>`:

```sh
TARGET_ID=build-machine
sudo -u kmesh /usr/local/bin/kmesh \
  --data-dir /var/lib/kmesh --server-addr mesh.example.com \
  agent enroll --target-id "$TARGET_ID" --enrollment-code '<enrollment-code>'
sudo systemctl enable --now "kmesh-agent@${TARGET_ID}.service"
```

The service reads agent state from `/var/lib/kmesh`. A user without root access can enroll in the default per-user state directory and run the agent as that user. On macOS, enroll with `--data-dir "$HOME/Library/Application Support/kmesh"`. Use the same path in the LaunchAgent file. Enroll each existing agent again after this change to create state in the new directory layout.

## Inspect private relay traffic

Administrators can inspect the server's live Iroh relay transports and close a private-relay SSH session:

```sh
kmesh admin relay list
kmesh admin --json relay list
kmesh admin relay close <session-id>
```

The list takes two relay snapshots about one second apart and reports the measured duration, process-lifetime ingress and egress totals, and byte-per-second rates. Each row represents one actual relay endpoint transport. `relay_connection_count` counts endpoint transports; `ssh_session_count` counts unique mapped SSH sessions, which normally have one client and one target endpoint row. A live endpoint without a current private-relay runtime appears as `unknown` with its EndpointId.

Traffic values count Iroh relay datagram payloads: they include the QUIC packet bytes carried inside each relay datagram, and exclude relay control frames, WebSocket/TLS framing, and network-layer headers. These values describe bytes the relay handled and differ from NIC byte counters. Server totals remain cumulative after a connection closes; a newly observed endpoint starts its rate window from zero. Direct UDP SSH streams do not pass through the relay, so their SSH bytes do not contribute to relay payload totals.

`kmesh admin relay close <session-id>` accepts a PrivateRelay session. The server commits the session as closed, cancels registered and in-flight relay connections for its per-session endpoints, then sends `Close` to the client and target control channels. Closed endpoint identities fail the relay authorization check, which prevents an in-flight handshake from registering after the administrative close. Direct sessions return a conflict. If the server runs with `--disable-private-relay`, the list reports `enabled: false` and an empty connection set.

## Verification status

### Historical live acceptance

The following live acceptance results belong to source `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`. They document that earlier deployment and do not verify the current source.

The final candidate is source `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`. Formatting and all-target Clippy passed; native all-target tests report 71 passed, 0 failed, and 2 ignored. The two explicit route-acceptance tests passed, and release binaries were built for Linux x86_64/aarch64 musl and macOS x86_64/arm64. The [final build and route evidence](docs/build-validation.md) records the source, checks, and artifact SHA-256 values.

On `target-1`, `PrivateDirect` and `PublicDirect` each passed three fresh SSH commands. Every command selected a direct IPv4 path before SSH, returned `server-1`, and exited with status 23. The full short OpenSSH suite passed SCP/SFTP 1 MiB integrity, forwarding, strict host-key rejection, ControlMaster reuse, idle and concurrent streams, and the RBAC/session boundaries. A separate in-flight SSH command also completed while the private server control connection restarted. See the [historical live acceptance report](scripts/verify_iroh_live_report.md).

The kmesh CLI also passed two controlled relay-route tests using a local SSH stub: direct-timeout fallback to the private relay, and private-relay denial with session cleanup. These controlled tests are distinct from a forced private-relay connection to the live `target-1` SSH service. One-hour idle and 1 GiB transfer tests were cancelled and are not part of the acceptance result. The final bounded PrivateDirect sample kept direct path `192.0.2.19:2123` selected while transferring two independent 4 MiB files concurrently in 1.462 seconds, with four interactive echo latencies of 58.943–517.340 ms and 24 proxy RSS samples of 21,568–22,976 KiB. This single run is not an SLO or capacity estimate; see the [sample report](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/perf-eb359f7-20261004/report.json>).

### Historical 0.3.0 local verification

Local formatting and all-target Clippy with warnings denied pass. `cargo test --locked --all-targets` passes 104 tests with 2 existing QAD route-acceptance tests ignored. The vendored `iroh-relay` library suite passes all 64 tests, including pending-handshake cancellation and a permanently blocked flush cancellation check. Root tests include the real self-hosted relay natural EOF test and the admin relay list/close test; this is local verification, not a live deployment acceptance run.


### Current 0.4.1 local verification

Formatting and all-target Clippy with warnings denied pass. The all-target test
suite passes 152 tests, with 2 existing QAD route-acceptance tests ignored.
Tests cover atomic group changes, stale previews, audit rollback, diagnostic
permission boundaries, and real server/agent checks against SSH and non-SSH stubs.
This is local verification, not live deployment acceptance. See the
[0.4.1 release notes](docs/releases/0.4.1.md) for changes and upgrade requirements.
