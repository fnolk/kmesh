# kmesh SSH acceptance report — source `eb359f7`

Source revision: `eb359f76d09ab1d58c3d6ec7cd8f9d42aefcc12e`.

- Client (`aarch64-apple-darwin`) SHA-256: `770681ecf3b2c4f428db9be9dafabb1e647aab34bbedb1101250bfdceb623aeb`.
- Server and target agent (`x86_64-unknown-linux-musl`) SHA-256: `7f0e52310289670764b42dbe4cd62795b6aa7f9a7c91b926b4450cc17e1553e9`.
- Full source/build/test checks and all four release artifact hashes: [build-validation.md](../docs/build-validation.md) and `/Users/example/.cache/kmesh-release-validation/eb359f7/artifacts/manifest.txt`.

## P2P SSH routes

Both reports show each command was gated on an Iroh `Direct` path before SSH bytes were sent. Each command returned `server-1`, observed its marker, and exited with code 23. The selected IPv4 peer and same-path SSH UDP byte deltas were:

| Route | Attempt | Peer | TX/RX bytes |
|---|---:|---|---:|
| `PrivateDirect` | 1 | `192.0.2.19:2111` | `10477/10588` |
| `PrivateDirect` | 2 | `192.0.2.19:2157` | `11617/10727` |
| `PrivateDirect` | 3 | `192.0.2.19:2158` | `8692/10234` |
| `PublicDirect` | 1 | `192.0.2.19:4170` | `13212/11772` |
| `PublicDirect` | 2 | `192.0.2.19:4171` | `10589/12016` |
| `PublicDirect` | 3 | `192.0.2.19:4172` | `10475/11660` |

Reports: [`PrivateDirect run`](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261004T033933Z/report.json>) and [`PublicDirect run`](</Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261004T034050Z/report.json>).

## Short OpenSSH suite

The private-mode suite report is `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/ssh-suite-eb359f7/ssh-private-20261004T034407Z-5af0d8a3/report.json`. It completed with `status=passed`, 52 passing steps, four expected-observation steps, and no cleanup errors. Coverage included:

- 1 MiB SCP upload/SFTP download with matching SHA-256 `943d64207a10f875aac2b4129149d37594bb170381b1e2e37b192bbec07600cb`.
- A local SSH banner through forwarding; strict rejection of a wrong host key.
- ControlMaster reuse, a five-second idle stream, two concurrent channels, and a cancelled channel while the master remained alive.
- Existing activated sessions continued through grant revocation, target disable, and logout; new transports were denied, then access was restored by fresh login.

The generated suite uses a real OpenSSH client and `target-1` target. Long-duration sessions and 1 GiB transfer tests were cancelled and are not claimed.

## Control restart while SSH is active

Report `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/run-20261004T034551Z/report.json` records a private server control restart while an eight-second SSH command was in flight. The command returned `server-1`, its marker, and exit 23 on direct path `192.0.2.19:2164`, with same-path TX/RX byte deltas `12945/11957`; the target was online after restart. Session ID: `00000000-0000-4000-8000-000000000002`.

## Bounded transfer, interaction, and memory sample

The report `/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003/runs/perf-eb359f7-20261004/report.json` records one `PrivateDirect` ControlMaster sample on `192.0.2.19:2123`: two independent random 4 MiB SCP transfers completed concurrently with exit code 0 and matching local/remote SHA-256; the same direct path `192.0.2.19:2123` stayed selected, and transfer time was 1.462 seconds. Four interactive echoes returned in 58.943, 468.781, 517.340, and 50.795 ms. Each probe started with two active transfers; the first three ended with two active, and the final probe ended with zero active. The 24 RSS samples cover proxy PID 90414 only: min/median/max 21,568/22,960/22,976 KiB. The data phase had a 25-second cap. Temporary files, ControlMaster, and proxy were cleaned up; A/B were active, the target online and enabled, database integrity and grants were intact, active and pending session counts were zero, and B retained UDP 3478/TCP 9443. This is a single bounded sample; it establishes no SLO or long-term capacity estimate.

## Private-relay fallback scope

The kmesh CLI passed two controlled route-acceptance tests. The successful test timed out two direct attempts, then selected the local private relay and moved SSH-stub bytes over that Iroh path. The failure test denied the private relay and verified closed sessions with no active rows. The success fixture recorded relay path TX/RX deltas `146/113`, a 22-byte SSH request, and 52 proxy stdout bytes. These are current-code CLI/control/transport tests with a local SSH stub; they are not a live forced private-relay SSH connection to `target-1`.

A real private-relay fallback was observed under the earlier source `4e629ad`: after `PrivateDirect` and `PublicDirect` timeouts, `target-1` completed SSH through `https://192.0.2.11:9443/`. This is historical evidence for 4e only, not a claim that kmesh was forced through the relay in the live short suite.

## QAD cleanup correction

The earlier public-direct run on source 4e returned only a LAN candidate and timed out waiting for the target Iroh connection. Its report did not contain paired QAD observations or target-side discovery logs. A later standalone diagnostic isolated a deadline issue: the old two-second deadline also covered Noq driver shutdown and returned Unavailable while waiting for connections to drain. With a separate cleanup budget, the diagnostic obtained two authenticated official UDP 7842 observations on the same retained socket, both reporting `192.0.2.12:12008`; probing took 1338 ms, cleanup 2430 ms, and total time 3813 ms. Its evidence is `/Users/example/.cache/kmesh-build/public-qad-evidence-4e629ad/public-qad-after-cleanup.json` and the artifact is separate from the production CLI. kmesh includes the QAD deadline fix and passes live `PublicDirect` 3/3 above.

The prior 4e short-suite harness report ended in a client-process cleanup failure; the script-only harness correction is separate from Rust and binary revisions. Current kmesh's complete suite report above passes.
