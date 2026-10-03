# Iroh live SSH verification report

Test date: 2026-10-03. The checks used `https://192.0.2.11:9443` and the existing OpenSSH management connection to `target-1`. No long-duration test was run.

## Artifacts and service state

The deployment refresh used code revision `548523fc39dffdef84ec9edbd574ac8d944bf38b`:

| Artifact | SHA-256 |
|---|---|
| macOS ARM64 client | `8006a171094a97407feca3143eaf38db47f037b394e7ea987a95d07bb080c56b` |
| Linux x86_64 musl server/agent | `3b4ae4f4a4c29fec9a62ef29f66b3db8e40d007ffcbd5a25ad589df084d3bb87` |

Both binaries were installed only in `/opt/kmesh-iroh-verification`. The Linux artifact SHA-256 was verified on the server and target before the two new services were stopped and atomically refreshed. The schema 3 SQLite database, user/role/target records, target UUID, and persistent agent identity were reused. The original verification binary, database, TLS files, and units remain intact for rollback.

The target is `target-1-iroh-e423a4a7`, UUID `00000000-0000-4000-8000-000000000006`. Test user `kmesh-verify-e423a4a7` has role UUID `00000000-0000-4000-8000-000000000005`. Its agent config points to `127.0.0.1:22`, verified from the existing target configuration. At the end of the checks, the new private server and its target agent were active; the old verification units remained stopped.

## Login and SSH checks

Password login succeeded. SSHSIG public-key login also succeeded using a temporary Ed25519 key and a dedicated temporary `SSH_AUTH_SOCK`. The test key fingerprint was `SHA256:4qgLlCt0LDdNygvtSbXFf1Gwva6wThM5u3WsdkGV1eI`; its key ID is `00000000-0000-4000-8000-000000000004`. The private key was removed and the dedicated agent stopped. The saved login file had mode `0600`; its profile directories had mode `0700`.

OpenSSH read the target's Ed25519 host key through the authenticated management connection and used strict host-key checking. SSH returned hostname `server-1` and exit code 23. A separately generated wrong host key was rejected.

The private-mode extended checks used the 423 release. SCP upload and SFTP download of a 1 MiB file had matching SHA-256 `300177b25e71361eef91e5e2c03727df794f35e3cfcb93003e1e81fa06b4a152`. A local forward returned `SSH-2.0-OpenSSH_7.4`. ControlMaster served repeated commands, SCP/SFTP, and the forward through one kmesh proxy. During RBAC revocation the existing master continued to run a command, while a new transport was denied. The grant was restored, the temporary remote file was removed, and cleanup reported no errors.

After the 548 control-session fix, the public-mode extended run passed the same file, forward, host-key, ControlMaster, and RBAC checks. Its 1 MiB round-trip SHA-256 was `9f92d9eaffc148f513cdfa46c1a652ec945af2c81aabf2041c5d4f8964269911`. Two fresh SSH connections under the same saved kmesh login session also succeeded; both reports contain the same one-way auth-session fingerprint `fb1e811dd5b058151c2754bea7eb83252730163700fff4e683e278c9a199734d`.

## Iroh candidates and selected paths

Both 548 probes kept SSH active for 8 seconds and recorded the selected path plus endpoint diagnostics. The PublicDefault probe reported:

- Target candidate addresses: `10.0.0.1:36451`, `10.0.0.4:36451`, `10.0.0.5:36451`, and public QAD address `192.0.2.19:4150`.
- Client QAD report: `udp_v4=true`, `global_v4=192.0.2.12:11351`, `mapping_varies_by_dest_ipv4=Some(false)`.
- Selected path: `relay:https://aps1-1.relay.n0.iroh.link./`; no direct-path selection event appeared during the 8-second session.

The private-mode probe reported:

- Target candidate addresses: `10.0.0.1:59997`, `10.0.0.4:59997`, `10.0.0.5:59997`, and public QAD address `192.0.2.19:4182`.
- Client QAD report: `udp_v4=true`, `global_v4=192.0.2.12:11462`; mapping variation was unknown because this mode reported through one relay.
- Selected path: `relay:https://192.0.2.11:9443/`; no direct-path selection event appeared during the 8-second session.

These observations confirm that this run exchanged public target candidates and the client obtained a QAD IPv4 mapping. They show the paths selected for these SSH streams; they do not establish direct P2P success or the cause of relay selection. The target-side NetReport value was not captured separately.

## Evidence files

The preflight, stage, 423 baseline, login, and 548 refresh reports are under `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/`. The 548 public extended report is `runs/run-20261003-iroh-upgrade-548523f/public-extended/ssh-public-default-20261003T033346Z-9cb0e000/report.json`. The 548 public and private debug reports are `runs/run-20261003-public548-debugprobe-2/report.json` and `runs/run-20261003-private548-debugprobe/report.json`. Their original stderr files are mode `0600` beside each report. Reports contain no password, refresh token, enrollment token, or private-key contents.
