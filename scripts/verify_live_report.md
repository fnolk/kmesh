# Public server and `target-1` integration report

Recorded 2026-10-02 against `https://192.0.2.11:9443` and target alias `target-1` (`root@target.example.com:5750`). The native CLI provisioned the target and user, the target agent enrolled, and the short live SSH/SFTP/SCP checks completed.

## Local client and credentials

The Apple Silicon release CLI is `kmesh 0.1.0`, SHA-256 `79d1e6d3046664e2fb0282d1f409be5680ace83cd3a5d37299d41fd704c3076b`. The independent config is `/Users/example/.cache/kmesh-live/client/config.toml` (0600), data directory `/Users/example/.cache/kmesh-live/client/data` (0700), profile `target-1-live`. It trusts the deployment CA and uses the IP SAN `192.0.2.11`. The default kmesh profile and SSH config were not changed.

The target host-key list matched an authenticated `ssh target-1` connection. Its Ed25519 fingerprint is `SHA256:i5+21MyghGWodXDWG/nqZ5+FwS8I4v7aG1VgQPfJuHg`. That SSH reported `server-1`, CentOS 7 x86_64 (`Linux 3.10.0-1160.el7`), UID 0. No private key was read or uploaded.

The real CLI used administrator `verification-admin` and created target `target-1` with UUID `00000000-0000-4000-8000-000000000001`, user `verification-ssh`, role `target-1-access`, and an SSH-connect grant. A first login using username `admin` returned 401; the corrected username succeeded. The enrollment token is stored in `/Users/example/.cache/kmesh-live/client/enrollment.json` (0600) and was given to the target operator by file path only. The kmesh login password for `verification-ssh` is stored in `/Users/example/.cache/kmesh-live/client/verification-ssh-password` (0600).

## Live result

The server unit `kmesh-verification-server-9443.service` is active on `0.0.0.0:9443/TCP`; STUN listens on `0.0.0.0:3478/UDP`. The CA-verified health endpoint returned HTTP 200. A native STUN Binding request returned a valid response. The target agent enrolled and its transient service became active.

The short SSH command returned hostname `server-1` and kernel `Linux 3.10.0-1160.el7.x86_64 x86_64`. The remote exit-code check returned 23 as expected. The actual transport path was `relay`; a separate SSH diagnostic reported `UDP hole-punch probe timed out`. This run did not observe direct P2P/QUIC, and the available evidence does not establish a NAT type. A 1 MiB SFTP round-trip and SCP upload returned matching SHA-256 values:

`23dfb4d79fe26db203a23d8cd479ab39ef1d3e40727848b1f39b8a8ac12d1977`

The sanitized result is `/Users/example/.cache/kmesh-live/client/report.json` (0600). This live run stayed within the requested short SSH and 1 MiB file-transfer scope; it did not run a long session, large transfer, or live RBAC revocation test.
