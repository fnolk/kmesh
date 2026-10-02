# Live server and target verification

`verify_live.py` uses the native release CLI and a separate cache profile. It does not read or change the user's default kmesh state or SSH config. The script provisions `target-1`, `verification-ssh`, and `target-1-access` through the admin CLI, writes the one-time enrollment token to a 0600 JSON file, waits briefly for the target agent, then verifies authenticated OpenSSH, the remote hostname and kernel, remote exit status, STUN reachability, the actual direct/relay path, and 1 MiB SFTP/SCP SHA-256 transfers. The live run stays short and leaves the SSH-connect grant enabled.

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
python3 scripts/verify_live.py --mode verify --agent-timeout 120
```

The provision command prints the target UUID and enrollment-file path; it never prints the token or generated kmesh login password. The verification report stores only connection details, paths, exit codes, and hashes in the 0600 file `/Users/example/.cache/kmesh-live/client/report.json`. It keeps the access grant enabled after the tests. Temporary payloads and remote `/tmp/kmesh-live-*.bin` files are removed after checks.

## Current deployment attempt

Recorded 2026-10-02. The `target-1` SSH alias resolves to `root@target.example.com:5750`; authenticated OpenSSH succeeded and reported `server-1`, CentOS 7 x86_64 (`Linux 3.10.0-1160.el7`), UID 0. The target's SSH host-key file was checked against that authenticated connection: Ed25519 fingerprint `SHA256:i5+21MyghGWodXDWG/nqZ5+FwS8I4v7aG1VgQPfJuHg`.

The native Apple Silicon release binary is `kmesh 0.1.0`, SHA-256 `79d1e6d3046664e2fb0282d1f409be5680ace83cd3a5d37299d41fd704c3076b`. The independent client config points to `https://192.0.2.11:9443`, trusts the deployment CA, and uses data directory `/Users/example/.cache/kmesh-live/client/data` with profile `target-1-live`.

Provisioning succeeded through the native admin CLI using administrator `verification-admin`: target `target-1` has UUID `00000000-0000-4000-8000-000000000001`; user `verification-ssh`, role `target-1-access`, and its SSH-connect grant were created. The enrollment JSON is `/Users/example/.cache/kmesh-live/client/enrollment.json` (0600); the kmesh login password for `verification-ssh` is `/Users/example/.cache/kmesh-live/client/verification-ssh-password` (0600). The enrollment token was passed to the target operator by file path only.

The 9443 TLS endpoint is reachable from the Mac and target, and the deployment CA verified the leaf certificate with IP SAN `192.0.2.11`. The operator reports `kmesh-verification-server-9443.service` active on `0.0.0.0:9443/TCP` and `0.0.0.0:3478/UDP`; a native STUN Binding request succeeded in 11.46 ms. Target enrollment and agent control are online. The live report records an SSH path of `relay`; a separate SSH diagnostic reported `UDP hole-punch probe timed out`. Direct P2P/QUIC was not observed, and the available evidence does not establish a NAT type.
