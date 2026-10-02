# Live server and target verification

`verify_live.py` uses the native release CLI and a separate cache profile. It does not read or change the user's default kmesh state or SSH config. The script provisions `target-1`, `verification-ssh`, and `target-1-access` through the admin CLI, writes the one-time enrollment token to a 0600 JSON file, waits for the target agent, then verifies authenticated OpenSSH, the remote hostname and kernel, remote exit status, SFTP/SCP SHA-256, direct STUN reachability, forced WSS relay, and RBAC revocation while an established SSH session finishes. It restores the grant before exiting.

The current local paths are:

- Native Apple Silicon CLI: `/Users/example/GitHub/kmesh/target/aarch64-apple-darwin/release/kmesh`
- Isolated client config: `/Users/example/.cache/kmesh-live/client/config.toml`
- Isolated client data/profile: `/Users/example/.cache/kmesh-live/client/data`, profile `target-1-live`
- Admin password input: `/Users/example/.cache/kmesh-live/server/admin-password`
- Server CA: `/Users/example/.cache/kmesh-live/server/ca.pem`
- Target SSH public host keys: `/Users/example/.cache/kmesh-live/target/ssh-host-keys.pub`

Provision the target through the real kmesh admin CLI. Then give the target-agent operator only the enrollment file path so it can read the token locally. After the operator reports the agent online, run the verification mode:

```sh
python3 scripts/verify_live.py --mode provision
python3 scripts/verify_live.py --mode verify --agent-timeout 900
```

The provision command prints the target UUID and enrollment-file path; it never prints the token or generated SSH password. The verification report stores only connection details, paths, exit codes, and hashes in the 0600 file `/Users/example/.cache/kmesh-live/client/report.json`. It keeps the access grant enabled after the tests. Temporary payloads and remote `/tmp/kmesh-live-*.bin` files are removed after checks.

## Current deployment attempt

Recorded 2026-10-02. The `target-1` SSH alias resolves to `root@target.example.com:5750`; authenticated OpenSSH succeeded and reported `server-1`, CentOS 7 x86_64 (`Linux 3.10.0-1160.el7`), UID 0. The target's SSH host-key file was checked against that authenticated connection: the Ed25519 fingerprint was `SHA256:i5+21MyghGWodXDWG/nqZ5+FwS8I4v7aG1VgQPfJuHg`.

The native Apple Silicon release binary reported `kmesh 0.1.0`, SHA-256 `79d1e6d3046664e2fb0282d1f409be5680ace83cd3a5d37299d41fd704c3076b`. The generated server leaf certificate has IP SAN `192.0.2.11`; the local CA verifies it. An isolated client config and mode-0700 data directory are ready. Provisioning and enrollment have not run because the public API is unreachable from both client and target networks.

Observed reachability evidence:

- From the Mac, direct TCP connect to `192.0.2.11:443` timed out after four seconds. `nc` returned `Operation timed out`.
- The configured HTTP proxy accepted `CONNECT 192.0.2.11:443` with HTTP 200, then received no TLS handshake response before timeout.
- An RFC 5389 STUN Binding Request to `192.0.2.11:3478/UDP` received no response within four seconds.
- From `target-1`, a CA-verified HTTPS health check to `https://192.0.2.11/health` timed out connecting to port 443 after four seconds.
- The server operator reports `kmesh-verification-server.service` bound to `0.0.0.0:443/TCP` and `0.0.0.0:3478/UDP`, local TLS health 200 with the CA, and host firewall policy allowing input. The cloud security-group/upstream ACL state remains unverified.

The evidence places the current blocker before TLS and STUN protocol handling. The host listener and operating-system firewall reports support an upstream network ACL as a likely cause; the cloud ACL itself has not been inspected. No firewall or cloud ACL changes were made. Re-run provisioning and verification after the public endpoints become reachable.
