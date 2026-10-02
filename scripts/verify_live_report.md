# Public server and `target-1` integration report

Recorded 2026-10-02 against the deployment at `https://192.0.2.11` and the target SSH alias `target-1` (`root@target.example.com:5750`). The current state is ready for a retry after the public network path is restored.

## Local client preparation

The Apple Silicon release CLI is `/Users/example/GitHub/kmesh/target/aarch64-apple-darwin/release/kmesh`; it reports version `0.1.0`, SHA-256 `79d1e6d3046664e2fb0282d1f409be5680ace83cd3a5d37299d41fd704c3076b`. The independent config is `/Users/example/.cache/kmesh-live/client/config.toml` (0600), with data directory `/Users/example/.cache/kmesh-live/client/data` (0700) and profile `target-1-live`. It trusts the deployment CA and uses the public server IP as TLS server name. The default kmesh profile and SSH config were not changed.

The deployment CA verifies the leaf certificate, whose SAN includes `IP Address:192.0.2.11`. The target host-key list at `/Users/example/.cache/kmesh-live/target/ssh-host-keys.pub` matches an authenticated `ssh target-1` connection. The observed Ed25519 fingerprint is `SHA256:i5+21MyghGWodXDWG/nqZ5+FwS8I4v7aG1VgQPfJuHg`. That authenticated SSH reported hostname `server-1`, CentOS 7 x86_64 (`Linux 3.10.0-1160.el7`), and UID 0. No private key was read or uploaded.

## Network evidence and current blocker

The native `kmesh login` CLI was invoked with the administrator password read from its 0600 file through stdin. It exited 1 before creating a user, target, role, or enrollment token. Its sensitive output was withheld. Independent connection checks provide the transport evidence:

- Mac to `192.0.2.11:443/TCP`: four-second connect timeout; `nc` also returned `Operation timed out`.
- Mac through its configured HTTP proxy: CONNECT returned HTTP 200, then the TLS ClientHello received no response before timeout.
- Mac to `192.0.2.11:3478/UDP`: an RFC 5389 Binding Request received no response within four seconds.
- `target-1` to `https://192.0.2.11/health`: CA-verified curl timed out connecting to port 443 after four seconds.
- The server operator reports `kmesh-verification-server.service` listening on `0.0.0.0:443/TCP` and `0.0.0.0:3478/UDP`, local TLS health 200 with the CA, and host firewall input policy allowing traffic. Cloud security-group or upstream ACL state remains unverified.

Both client and target networks fail before HTTP/TLS or STUN responses. An upstream ACL is the likely cause given the reported server listener and host firewall state; the cloud ACL has not been inspected. No firewall or cloud security-group changes were made. The target agent has not been enrolled or started because the client could not create an enrollment token.

## Retry procedure

The real-CLI provisioning and verification steps are captured in [`verify_live.md`](verify_live.md). Once both endpoints can reach the public server, run:

```sh
python3 scripts/verify_live.py --mode provision
```

It creates target `target-1`, user `verification-ssh`, role `target-1-access`, and the SSH-connect grant using the admin CLI. It stores the one-time token in `/Users/example/.cache/kmesh-live/client/enrollment.json` (0600) and the random SSH password in `/Users/example/.cache/kmesh-live/client/verification-ssh-password` (0600). The target-agent operator can read only the enrollment file path to enroll. After the agent reports online, run:

```sh
python3 scripts/verify_live.py --mode verify --agent-timeout 900
```

Verification covers direct/relay path reporting, authenticated SSH hostname/kernel and exit status, 16 MiB SFTP/SCP hash checks, forced relay, revoking permission for new connections while an established session finishes, and restoring the grant. The report is written to `/Users/example/.cache/kmesh-live/client/report.json` (0600) without passwords or tokens.
