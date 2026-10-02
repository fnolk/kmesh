# Native SSH end-to-end harness

`e2e_native.py` exercises the real CLI, TLS/WSS server, target agent, and a per-run OpenSSH daemon. It needs a non-root POSIX account, Python 3, OpenSSL, OpenSSH client tools, and a local `sshd`. On macOS it uses `/opt/homebrew/sbin/sshd` when present.

Build the CLI, then run the complete one-hour test:

```sh
CARGO_TARGET_DIR=/path/to/shared/target cargo build --bin kmesh
python3 scripts/e2e_native.py --binary /path/to/shared/target/debug/kmesh --idle-seconds 3600
```

The harness allocates random TCP and UDP ports and creates all CA, server, SSH, agent, user, and database state under a short `/tmp/km-*` directory. Its custom `sshd` runs on loopback under the current user with `UsePAM no`; `StrictModes no` is explicit because macOS's `/private/tmp` ancestor is world-writable. It does not read or change the user's SSH configuration, host keys, firewall, or Docker state. It removes its temporary directory and owned processes on success or failure. Sanitized command and daemon logs plus `results.json` remain under the ignored `target/e2e-logs/` directory.

The run covers TLS chain validation, password and SSHSIG login, RBAC and target enrollment, SSH host-key rejection, OpenSSH ControlMaster, eight concurrent ProxyCommand refreshes, SFTP and SCP hashes, a real 1 GiB SCP transfer, a no-response UDP STUN endpoint that forces WSS relay, relay half-close, and revoking permission while an already-open SSH remains alive. The one-hour idle session starts before the remaining data-plane tests; the script checks the process once a minute and confirms its final command completes.

## Verification record

Recorded 2026-10-02 on macOS ARM using OpenSSH 10.2p1. The active test run used TLS port 58773, STUN UDP port 61483, SSH port 58774, and target `00000000-0000-4000-8000-000000000003`. Password login, registered SSH public-key login, SSHSIG login, eight concurrent refreshes, wrong host-key rejection, ControlMaster reuse, SFTP round-trip, the 1 GiB SCP hash, forced WSS relay, relay half-close, new-connection denial after RBAC revoke, and continued operation of the pre-revoke P2P/QUIC session passed.

The 1 GiB payload SHA-256 was `525787f3a84e3e99b42f96376a4798a30ca062ef5a7c56c009cc97e762ce6e8f`. The pre-revoke P2P/QUIC SSH started at 15:17:47 and completed at 16:17:47 after exactly 3,600 seconds; all once-a-minute liveness checks passed, and the final remote command returned `IDLE_OK`. RBAC revocation denied a new tunnel while preserving this existing SSH connection.

The running proxy's executable path was recorded before a later build replaced the shared target binary: SHA-256 `e0c5451f185f7c4e390f396b911df2b9ce3e999100b76734075e604e901acc6e`. During the idle run, `lsof` showed proxy PID 63749 still mapped to its original executable inode `122861097` (57,251,048 bytes). The shared path was later replaced by inode `122916188` (57,290,120 bytes), SHA-256 `728cfe60454a8b668498e65c46542f62bcff38299435c944a9d6463b7481f1a5`; the idle session kept running its original image.

After completion, the harness stopped its server, agent, sshd, and SSH processes, and removed `/tmp/km-cg1yctta`, including the local 1 GiB payload. The 1 GiB remote copy was removed after its hash check. Sanitized daemon/CLI logs and `results.json` were copied to `/Users/example/GitHub/kmesh/target/e2e-logs/native-20261002-151744-63626/` with a `0700` directory and `0600` files; the 2 MiB relay echo output and all temporary keys, tokens, and databases were excluded.
