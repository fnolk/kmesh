# Historical Iroh SSH verification report — earlier route implementation

> **Scope:** This report preserves the 2026-10-03 evidence gathered from several earlier source and binary revisions listed below. Those revisions used the former private/public-default route model; in particular, the public-default runs could carry SSH data over an official Iroh relay. Current `PrivateDirect` and `PublicDirect` endpoints disable relay data paths, and only `PrivateRelay` carries SSH through the self-hosted relay. None of the path outcomes below verifies the current three-route design.

> **Current acceptance status (2026-10-04):** The route-aware fallback run on candidate `be3ca70` exposed a control-message race when `ContinueNative(Standard)` arrives during client QAD discovery. Client-side correction `a27a1b1` is committed on its isolated branch; the target-agent correction and rerun are pending integration. Current direct SSH over `target-1`, the fallback path, and four-platform release artifacts remain unaccepted until a final candidate report records the exact source revision, hashes, and selected path for each connection.

Test date: 2026-10-03. The checks used `https://192.0.2.11:9443` and the existing OpenSSH management connection to `target-1`. No long-duration test was run.

## Artifacts and service state

The deployment refresh used code revision `548523fc39dffdef84ec9edbd574ac8d944bf38b`:

| Artifact | SHA-256 |
|---|---|
| macOS ARM64 client | `8006a171094a97407feca3143eaf38db47f037b394e7ea987a95d07bb080c56b` |
| Linux x86_64 musl server/agent | `3b4ae4f4a4c29fec9a62ef29f66b3db8e40d007ffcbd5a25ad589df084d3bb87` |

The Linux x86_64 musl artifact was installed on the server and target under `/opt/kmesh-iroh-verification`; its SHA-256 was verified on both hosts before the new services were stopped and atomically refreshed. The macOS ARM64 client ran locally from `/Users/example/GitHub/kmesh/target/aarch64-apple-darwin/release/kmesh`. The schema 3 SQLite database, user/role/target records, target UUID, and persistent agent identity were reused. The original verification binary, database, TLS files, and units remain intact for rollback.

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
- Client QAD report: `udp_v4=true`, `global_v4=192.0.2.12:11462`, `mapping_varies_by_dest_ipv4=None`. This private-mode report used one configured relay; no conclusion about mapping variation beyond that report is recorded.
- Selected path: `relay:https://192.0.2.11:9443/`; no direct-path selection event appeared during the 8-second session.

These observations confirm that this run exchanged public target candidates and the client obtained a QAD IPv4 mapping. They show the paths selected for these SSH streams; they do not establish direct P2P success or the cause of relay selection. The target-side NetReport value was not captured separately.

## Latest direct SSH result

The reverse-dial PublicDefault SSH run recorded fresh A and C NetReports. Across three reflectors, A reported the same `192.0.2.19:4152` with `mapping_varies_by_dest_ipv4=Some(false)`; C reported the same `192.0.2.12:12632` with `Some(false)`. The endpoints exchanged their public and local candidates, and C logged 23 off-path probes per A candidate. OpenSSH still selected `relay:https://euc1-1.relay.n0.iroh.link./`; this run did not achieve P2P.

The portmapper-enabled Private SSH check used Linux agent SHA-256 `45b6c9dd8b6a1c92b6385860978925c84e535b92625382fd2b31aecf897040b8` and macOS ARM64 client SHA-256 `bac2df1e0afbe128f961d0d480dfb8108c536ccc9b24dd961cbffb85ac6800bb`. SSH returned `server-1`, the completion marker, and expected exit code 23 after no Direct path was selected within 10.06 seconds. Its path remained `relay:https://192.0.2.11:9443/`, so `ssh_status=passed` and `p2p_status=failed`. The private-relay QAD observations were `192.0.2.19:4187` on A and `192.0.2.12:12484` on C; each used one reflector, so both `mapping_varies_by_dest_ipv4` values were `None`. These QAD addresses are not portmapper mappings.

Portmapper logs record mapping attempts and UPnP failure, with no successful mapping event or external mapped address. With `portmapper=trace,igd_next=debug`, C logged SSDP broadcasts to `239.255.255.250:1900` followed by `UPnP mapping failed`. A’s earlier portmapper-enabled Private SSH run, with `portmapper=debug`, recorded two mapping attempts for `10.0.0.4:34870` followed by the same failure. Separate Doctor three-protocol probes completed with exit 0 on both C and A and reported `UPnP=false`, `PCP=false`, and `NAT-PMP=false`. C logged PCP `IO error during PCP`, NAT-PMP `Connection refused`, and UPnP `No response within timeout`; A logged PCP `IO error during PCP`, NAT-PMP `read timeout`, and UPnP `No response within timeout`. The Doctor evidence is under `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/taskcache/runs/gateway-probe-20261003/`. These results report the detected protocol state for those probe runs; they do not establish the location of peer UDP loss.

In the latest gated SSH run, C logged 19 Noq probes of 35 bytes to A’s public candidate `192.0.2.19:4188`; `iroh::socket::transports` recorded 19 `sent transmit` events to that address and no send errors or pending drops. Before the run, `ss -4` confirmed the single kmesh IPv4 UDP listener at `*:39278` (PID 5675); a separate IPv6 listener uses port 32865. A’s 15-second physical `ens1f0` capture filtered on UDP port 39278 saw 34 packets, all A→C: 17 from `10.0.0.4:39278` to `192.0.2.12:13254` and 17 to `10.0.0.6:56674`, each destination receiving 16 UDP payloads of 35 bytes and one of 1200 bytes. It saw no C→A packet to the listener and dropped none in the kernel. SSH still used the relay and P2P remains unmet. The sender logs show C’s UDP send call returned success; the physical-interface capture shows no reverse packet at A, leaving its loss location unknown.

Read-only host inspection found iptables INPUT/FORWARD policies `ACCEPT`, no matching DROP rule, and firewalld not running. CNI forwarding rules target `virbr0`; the CNI admin chain is empty. The `net.bridge.bridge-nf-call-iptables` sysctl path was absent. A routes C through `br0`; its bridge members are `ens1f0` and `tap0`. C-side `en0` capture remains unavailable because `/dev/bpf0` is root-only mode `0600`; it is still needed to correlate C’s interface traffic with the A-side capture.

After the run, the private server and new agent were active, the public server was inactive, the agent environment was empty, and server B retained its 763 binary. The latest report is `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-private-ens1f0-gated/report.json`; its client stderr and `target-1-ens1f0-39278.txt` capture are mode `0600` beside it. Capture SHA-256: `5779f7c0c3ae8ecb4c3f078714743aff27a33f1e18841a24029e554eb08de82c`. The prior portmapper and br0 evidence is under `runs/run-20261003-private-socket-send/`.

## Direct-first same-connection SSH attempt

The target agent binary was built from worker commit `0f5949d8676708b83677bf74d271f76569dd74b9`; its tree `150ae6d08301ffd5f212cf9e6203f76ec15faa5f` matches primary commit `d96a103220aa077818933a803977a4552629cba6`. Linux x86_64 musl artifact SHA-256 is `f1324d606f10b4c4d6459d7b9313e782f8a786e1d43101ab76162fe99bf59c92`; the prior target binary `45b6c9dd8b6a1c92b6385860978925c84e535b92625382fd2b31aecf897040b8` remains as a SHA-named backup. The macOS ARM64 client remained `bac2df1e0afbe128f961d0d480dfb8108c536ccc9b24dd961cbffb85ac6800bb`; server B remained on binary SHA `32dbb6d670ab7b425b04d8229d36c8191bfd46237be78e0bd5706297f8439c9a`. The existing schema 3 data, target UUID, credentials, and device identity were reused.

Two bounded SSH samples used the existing OpenSSH `ProxyCommand`. The client waited up to 8 seconds for a selected Direct path before sending `hostname`, a completion marker, and expected exit 23. The agent waited up to 2 seconds for a selected IP path on that same QUIC connection before opening its bidirectional stream and writing the ticket.

| Relay mode | SSH result | Client path result | Agent path before ticket | P2P result |
|---|---|---|---|---|
| Private | `server-1`, marker observed, exit 23 | 8.057-second wait; selected path remained `relay:https://192.0.2.11:9443/` | `direct_selected=false`; only the selected private relay appeared in the path snapshot | Failed; no Direct path selected |
| PublicDefault | `server-1`, marker observed, exit 23 | 8.086-second wait; selected path remained `relay:https://aps1-1.relay.n0.iroh.link./` | `direct_selected=false`; only the selected public relay appeared in the path snapshot | Failed; no Direct path selected |

The agent snapshots show only relay paths before ticket setup and before SSH byte forwarding. When `copy_bidirectional` later returned `connection lost`, the private relay counters changed from TX/RX `10904/8504` to `15980/12736` (delta `+5076/+4232`); the PublicDefault relay counters changed from `10894/8453` to `15948/12733` (delta `+5054/+4280`). These are aggregate QUIC path counters, not SSH-only byte counts. The client-side end-of-stream SSH byte summary was absent in both reports, so no SSH-only counter is claimed. Both SSH commands succeeded over their observed relay path; both P2P checks failed. The experiments do not establish why direct paths were not selected, or that the 2-second observation window ends SDK path discovery.

Raw evidence is mode `0600` at these exact paths:

- Private C stderr: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-private/path-probe-private.stderr`
- Private A snapshots: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-private/agent-path-probe-private-late.log`
- Private report JSON: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-private/report.json`
- Public C stderr: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-public/path-probe-public-default.stderr`
- Public A snapshots: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-public/agent-path-probe-public.log`
- Public report JSON: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-public/report.json`
- Private restore report: `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261003-direct-wait-d96a103-restore/report.json`

After the PublicDefault comparison, Private mode was restored. Server B's private unit and target A's agent are active, the public server unit is inactive, server B still has binary SHA `32dbb6d670ab7b425b04d8229d36c8191bfd46237be78e0bd5706297f8439c9a`, target A runs binary SHA `f1324d606f10b4c4d6459d7b9313e782f8a786e1d43101ab76162fe99bf59c92`, the old target binary remains backed up under SHA `45b6c9dd8b6a1c92b6385860978925c84e535b92625382fd2b31aecf897040b8`, and the target is online. The temporary agent `RUST_LOG` override was removed; the active agent reports an empty environment. No third SSH sample was run.

## Evidence files

The preflight, stage, 423 baseline, login, and 548 refresh reports are under `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/`. The 548 public extended report is `runs/run-20261003-iroh-upgrade-548523f/public-extended/ssh-public-default-20261003T033346Z-9cb0e000/report.json`. The 548 public and private debug reports are `runs/run-20261003-public548-debugprobe-2/report.json` and `runs/run-20261003-private548-debugprobe/report.json`. Their original stderr files are mode `0600` beside each report. Reports contain no password, refresh token, enrollment token, or private-key contents.
