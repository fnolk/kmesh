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

The 1 GiB payload SHA-256 was `525787f3a84e3e99b42f96376a4798a30ca062ef5a7c56c009cc97e762ce6e8f`. The run log is `target/e2e-logs/native-20261002-151744-63626/`. At the time this record was prepared, the idle connection had passed 2,412 of 3,600 seconds of once-a-minute liveness checks; the final completion record is added after the full hour elapses.

The running proxy had loaded the binary image whose SHA-256 was captured as `e0c5451f185f7c4e390f396b911df2b9ce3e999100b76734075e604e901acc6e`. A later build replaced the shared target path while the SSH process remained active; `lsof` confirmed the process retained its original executable inode.
