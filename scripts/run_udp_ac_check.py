#!/usr/bin/env python3
"""Run one coordinated Iroh UDP AC diagnostic round."""

import argparse
import asyncio
import copy
import ipaddress
import json
import os
import re
import shlex
import signal
import uuid
from datetime import datetime, timezone
from pathlib import Path

HOST = "target-1"
CLIENT_IP = "10.0.0.6"
TARGET_IP = "10.0.0.4"
PRIVATE_RELAY_URL = "https://192.0.2.11:9443/"
B_QAD_PORT = 3478
OFFICIAL_RELAY_URL = "https://aps1-1.relay.n0.iroh.link./"
OFFICIAL_QAD_PORT = 7842
CLIENT_CA = "/Users/example/.cache/kmesh-live/server/ca.pem"
TARGET_CA = "/opt/kmesh-iroh-verification/ca.pem"
TIMEOUT = 60
LOG_FILTER = "warn,iroh::socket=trace"
PID_MARKER = re.compile(rb"KMESH_AC_REMOTE_PID=([0-9]+)")
CAPTURE_PID_MARKER = re.compile(rb"KMESH_AC_CAPTURE_PID=([0-9]+)")
CAPTURE_CHILD_PID_MARKER = re.compile(rb"KMESH_AC_CAPTURE_CHILD_PID=([0-9]+)")
CAPTURE_EXE_MARKER = re.compile(rb"KMESH_AC_CAPTURE_EXE=(/[^\r\n]+)")
CAPTURE_CHILD_EXE_MARKER = re.compile(rb"KMESH_AC_CAPTURE_CHILD_EXE=(/[^\r\n]+)")
ANSI_ESCAPE = re.compile(rb"\x1b\[[0-9;]*m")
QAD_REPORT = re.compile(
    rb'QadProbeReport\s*\{\s*relay:\s*RelayUrl\("([^"]+)"\),.*?\baddr:\s*(\[[^\]]+\]:\d+|[^,\s}]+)'
)


def create_private_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def parse_event(line):
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and isinstance(value.get("event"), str) else None


def parse_socket_address(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a socket address string")
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or value[end + 1:end + 2] != ":":
            raise ValueError(f"{field} has invalid IPv6 socket syntax")
        host, port_text = value[1:end], value[end + 2:]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            raise ValueError(f"{field} has invalid socket syntax")
    address = ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"{field} has invalid port")
    return address, port


async def collect(reader, path, role, events, queue=None, remote_pid=None, qad_reports=None, qad_report_event=None):
    with path.open("ab") as output:
        while line := await reader.readline():
            output.write(line)
            output.flush()
            if remote_pid is not None:
                match = PID_MARKER.search(line)
                if match:
                    remote_pid["pid"] = int(match.group(1))
            if qad_reports is not None:
                match = QAD_REPORT.search(ANSI_ESCAPE.sub(b"", line))
                if match:
                    qad_reports[role].append({
                        "relay_url": match.group(1).decode(),
                        "socket_addr": match.group(2).decode(),
                        "raw_line": ANSI_ESCAPE.sub(b"", line).decode(errors="replace").rstrip(),
                    })
                    qad_report_event.set()
            if queue is not None:
                event = parse_event(line)
                if event is not None:
                    events.append(event)
                    queue.put_nowait((role, event))
    if queue is not None:
        queue.put_nowait((role, None))


async def stop_group(proc):
    if proc is None or proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), 2)
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await asyncio.wait_for(proc.wait(), 2)


async def send_json(proc, value):
    if proc is None or proc.returncode is not None or proc.stdin is None:
        return
    proc.stdin.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
    await proc.stdin.drain()


async def next_event(queue, deadline):
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("60-second runner deadline elapsed")
    try:
        role, event = await asyncio.wait_for(queue.get(), remaining)
    except asyncio.TimeoutError as error:
        raise TimeoutError("60-second runner deadline elapsed") from error
    if event is None:
        raise RuntimeError(f"{role} helper stdout closed before the phase completed")
    if event.get("event") in {"failure", "direct_timeout", "direct_wait_error"}:
        raise RuntimeError(f"{role} helper reported {event}")
    return role, event


def ssh_base():
    return ["ssh", "-oBatchMode=yes", "-oConnectTimeout=8", "-oConnectionAttempts=1", "-T"]


async def cleanup_target(pid_file, target_bin, reported_pid, raw_out, raw_err):
    expected = "" if reported_pid is None else str(reported_pid)
    script = f"""pid_file={shlex.quote(pid_file)}
expected_bin={shlex.quote(target_bin)}
expected_pid={shlex.quote(expected)}
pid=$(cat \"$pid_file\" 2>/dev/null) || exit 2
case \"$pid\" in ''|*[!0-9]*) exit 3;; esac
[ -z \"$expected_pid\" ] || [ \"$pid\" = \"$expected_pid\" ] || exit 4
proc=/proc/$pid
same_exe() {{ [ -e \"$proc\" ] && [ \"$(readlink \"$proc/exe\" 2>/dev/null || true)\" = \"$expected_bin\" ]; }}
if same_exe; then
  kill -TERM \"$pid\" 2>/dev/null || true
  i=0
  while [ \"$i\" -lt 20 ] && same_exe; do sleep 0.1; i=$((i + 1)); done
  if same_exe; then kill -KILL \"$pid\" 2>/dev/null || true; fi
  i=0
  while [ \"$i\" -lt 20 ] && same_exe; do sleep 0.1; i=$((i + 1)); done
  same_exe && exit 5
fi
printf 'KMESH_AC_REMOTE_PID=%s\\n' \"$pid\"
printf 'KMESH_AC_CLEANUP=verified\\n'
rm -f -- \"$pid_file\"
"""
    proc = await asyncio.create_subprocess_exec(
        *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(script),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 12)
    except asyncio.TimeoutError:
        await stop_group(proc)
        out, err = b"", b"remote cleanup timed out"
    raw_out.write_bytes(out)
    raw_err.write_bytes(err)
    raw_out.chmod(0o600)
    raw_err.chmod(0o600)
    cleaned_pid = None
    marker = PID_MARKER.search(out)
    if marker:
        cleaned_pid = int(marker.group(1))
    return {
        "exit_code": proc.returncode,
        "reported_pid": reported_pid,
        "cleaned_pid": cleaned_pid,
        "verified": proc.returncode == 0 and b"KMESH_AC_CLEANUP=verified" in out,
        "stdout": out.decode(errors="replace"),
        "stderr": err.decode(errors="replace"),
    }


async def cleanup_target_capture(supervisor_pid, child_pid, raw_out, raw_err):
    expected_supervisor = "" if supervisor_pid is None else str(supervisor_pid)
    expected_child = "" if child_pid is None else str(child_pid)
    script = f"""supervisor={shlex.quote(expected_supervisor)}
child={shlex.quote(expected_child)}
same_timeout() {{
  [ -n "$supervisor" ] && [ -e "/proc/$supervisor/exe" ] &&
    [ "$(readlink "/proc/$supervisor/exe" 2>/dev/null || true)" = /usr/bin/timeout ]
}}
same_tcpdump() {{
  [ -n "$child" ] && [ -e "/proc/$child/exe" ] &&
    [ "$(readlink "/proc/$child/exe" 2>/dev/null || true)" = /usr/sbin/tcpdump ]
}}
if [ -z "$child" ] && same_timeout; then
  children=$(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null || true)
  set -- $children
  if [ "$#" -eq 1 ] && [ "$(readlink "/proc/$1/exe" 2>/dev/null || true)" = /usr/sbin/tcpdump ]; then
    child=$1
    printf 'KMESH_AC_CAPTURE_CHILD_PID=%s\\n' "$child"
    printf 'KMESH_AC_CAPTURE_CHILD_EXE=%s\\n' /usr/sbin/tcpdump
  fi
fi
if same_tcpdump; then kill -INT "$child" 2>/dev/null || true; fi
if same_timeout; then kill -INT "$supervisor" 2>/dev/null || true; fi
i=0
while [ "$i" -lt 30 ] && {{ same_timeout || same_tcpdump; }}; do sleep 0.1; i=$((i + 1)); done
if same_tcpdump; then kill -KILL "$child" 2>/dev/null || true; fi
if same_timeout; then kill -KILL "$supervisor" 2>/dev/null || true; fi
i=0
while [ "$i" -lt 20 ] && {{ same_timeout || same_tcpdump; }}; do sleep 0.1; i=$((i + 1)); done
if same_timeout || same_tcpdump; then exit 5; fi
printf 'KMESH_AC_CAPTURE_CLEANUP=verified\\n'
"""
    proc = await asyncio.create_subprocess_exec(
        *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(script),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 10)
    except asyncio.TimeoutError:
        await stop_group(proc)
        out, err = b"", b"remote capture cleanup timed out"
    raw_out.write_bytes(out)
    raw_err.write_bytes(err)
    raw_out.chmod(0o600)
    raw_err.chmod(0o600)
    return {
        "exit_code": proc.returncode,
        "supervisor_pid": supervisor_pid,
        "child_pid": child_pid,
        "verified": (supervisor_pid is not None and child_pid is not None
                     and proc.returncode == 0 and b"KMESH_AC_CAPTURE_CLEANUP=verified" in out),
        "stdout": out.decode(errors="replace"),
        "stderr": err.decode(errors="replace"),
    }


async def run(args):
    started = asyncio.get_running_loop().time()
    deadline = started + TIMEOUT
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    out_dir.chmod(0o700)
    os.umask(0o077)
    logs = {name: out_dir / name for name in (
        "client.stdout.jsonl", "client.stderr.log", "target.stdout.jsonl",
        "target.stderr.log", "remote-cleanup.stdout.log", "remote-cleanup.stderr.log",
        "target-capture.packets.log", "target-capture.stderr.log",
        "target-capture-inspect.stdout.log", "target-capture-inspect.stderr.log",
        "target-capture-cleanup.stdout.log", "target-capture-cleanup.stderr.log",
    )}
    for path in logs.values():
        create_private_file(path)

    client_bin = Path(args.client_bin).expanduser().resolve()
    if not client_bin.is_file() or not os.access(client_bin, os.X_OK):
        raise ValueError("--client-bin must name an executable local file")
    if not args.target_bin.startswith("/"):
        raise ValueError("--target-bin must be an absolute path on target-1")
    client_secret_file = None
    if args.relay_mode == "private":
        if not args.client_secret_file or not args.target_secret_file:
            raise ValueError("private mode requires both endpoint secret-file paths")
        client_secret_file = Path(args.client_secret_file).expanduser().resolve()
        if not client_secret_file.is_file():
            raise ValueError("--client-secret-file must name an existing local file")
        if client_secret_file.stat().st_mode & 0o077:
            raise ValueError("--client-secret-file must be private to its owner")
        if not args.target_secret_file.startswith("/"):
            raise ValueError("--target-secret-file must be an absolute path on target-1")
    elif args.client_secret_file or args.target_secret_file:
        raise ValueError("public mode uses fresh helper identities and accepts no secret-file paths")
    if args.capture_target and args.relay_mode != "private":
        raise ValueError("--capture-target is available for private mode only")
    if args.mapping_candidates and args.relay_mode != "private":
        raise ValueError("--mapping-candidates is available for private mode only")
    if args.predict_target_next_port and (args.relay_mode != "private" or not args.mapping_candidates):
        raise ValueError("--predict-target-next-port requires private --mapping-candidates mode")
    if args.peer_ip_only and (args.relay_mode != "private" or not args.mapping_candidates):
        raise ValueError("--peer-ip-only requires private --mapping-candidates mode")

    run_id = uuid.uuid4().hex
    pid_file = f"/tmp/kmesh-udp-ac-{run_id}.pid"
    target_args = [
        args.target_bin, "--role", "target", "--relay-mode", args.relay_mode,
        "--ca-file", TARGET_CA,
    ]
    if args.relay_mode == "private":
        target_args.extend([
            "--local-ip", TARGET_IP,
            "--endpoint-secret-key-file", args.target_secret_file,
        ])
        if args.mapping_candidates:
            target_args.append("--mapping-candidates")
        if args.peer_ip_only:
            target_args.append("--peer-ip-only")
    remote_command = f"""umask 077
pid=$$
printf '%s\\n' \"$pid\" > {shlex.quote(pid_file)}
printf 'KMESH_AC_REMOTE_PID=%s\\n' \"$pid\" >&2
export RUST_LOG={shlex.quote(LOG_FILTER)}
exec {' '.join(shlex.quote(arg) for arg in target_args)}
"""
    queue, events = asyncio.Queue(), {"client": [], "target": []}
    qad_reports, qad_report_event = {"client": [], "target": []}, asyncio.Event()
    mapping_candidates = {
        "enabled": args.mapping_candidates,
        "ready_original": {},
        "observations": {},
        "watch_addr_published_ip_candidates": {},
        "all_successful_qad_reports": {},
        "control_to_client": None,
        "control_to_target": None,
        "local_candidates_published": {},
        "peer_ip_only": args.peer_ip_only,
        "peer_bootstrap": {
            "candidates_by_receiver": {},
            "expected_dial_endpoint_addr_by_receiver": {},
            "actual_dial_endpoint_by_receiver": {},
        },
        "prediction": {
            "enabled": args.predict_target_next_port,
            "input_source": "only this target process's successful QadProbeReport records, matched to its ready.relay_map URLs",
            "rule": "for each live target reflector-observed SocketAddr, use the same public IP and observed UDP port plus one",
            "history_basis": "three earlier independent endpoint runs showed a per-reflector +1 port trend; historical addresses do not populate this run's candidates",
            "assumption": "A's peer-destination mapping may follow that +1 trend; the prediction remains unverified until a selected path uses it",
            "target_predicted_candidates": [],
        },
    }
    remote_pid, procs, readers = {"pid": None}, {}, []
    capture_proc, capture_readers = None, []
    capture_info = {
        "enabled": args.capture_target,
        "interface": "ens1f0" if args.capture_target else None,
        "filter": None,
        "target_local_socket": None,
        "target_local_ip": None,
        "bound_port": None,
        "started_utc": None,
        "peer_metadata_gate_utc": None,
        "stopped_utc": None,
        "ssh_pid": None,
        "supervisor_pid": None,
        "supervisor_executable": None,
        "child_pid": None,
        "child_executable": None,
        "exit_code": None,
        "cleanup": None,
        "packet_lines": None,
        "tx_packets": None,
        "tx_udp_payload_bytes": None,
        "rx_packets": None,
        "rx_udp_payload_bytes": None,
        "udp_payload_length_1200_packet_count": None,
        "udp_payload_length_count_note": "Raw tcpdump UDP payload length evidence only; a 1200-byte payload is not identified as a QUIC Initial packet.",
        "statistics": {},
        "stdout": str(logs["target-capture.packets.log"]),
        "stderr": str(logs["target-capture.stderr.log"]),
    }
    ready, direct, failure = {}, {}, None
    dial_endpoints = {}
    gate_sent = False

    try:
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("runner deadline elapsed before start")
        client_args = [
            str(client_bin), "--role", "client", "--relay-mode", args.relay_mode,
            "--ca-file", CLIENT_CA,
        ]
        if args.relay_mode == "private":
            client_args.extend([
                "--local-ip", CLIENT_IP,
                "--endpoint-secret-key-file", str(client_secret_file),
            ])
            if args.mapping_candidates:
                client_args.append("--mapping-candidates")
            if args.peer_ip_only:
                client_args.append("--peer-ip-only")
        client = await asyncio.create_subprocess_exec(
            *client_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, env={**os.environ, "RUST_LOG": LOG_FILTER},
        )
        procs["client"] = client
        target = await asyncio.create_subprocess_exec(
            *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(remote_command),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        procs["target"] = target
        readers = [
            asyncio.create_task(collect(client.stdout, logs["client.stdout.jsonl"], "client", events["client"], queue)),
            asyncio.create_task(collect(
                client.stderr, logs["client.stderr.log"], "client", events["client"],
                qad_reports=qad_reports if args.mapping_candidates else None,
                qad_report_event=qad_report_event if args.mapping_candidates else None,
            )),
            asyncio.create_task(collect(target.stdout, logs["target.stdout.jsonl"], "target", events["target"], queue)),
            asyncio.create_task(collect(
                target.stderr, logs["target.stderr.log"], "target", events["target"],
                remote_pid=remote_pid,
                qad_reports=qad_reports if args.mapping_candidates else None,
                qad_report_event=qad_report_event if args.mapping_candidates else None,
            )),
        ]

        while len(ready) < 2:
            role, event = await next_event(queue, deadline)
            if event["event"] == "ready":
                ready[role] = event

        if args.mapping_candidates:
            mapping_candidates["ready_original"] = copy.deepcopy(ready)
            qad_deadline = min(deadline, asyncio.get_running_loop().time() + 5)
            reports_by_role = {}
            while True:
                reports_by_role.clear()
                for role in ("client", "target"):
                    event = ready[role]
                    if event.get("role") != role or event.get("relay_mode") != "private":
                        raise ValueError(f"{role} ready event has a mismatched role or relay mode")
                    relay_map = event.get("relay_map")
                    if not isinstance(relay_map, list) or len(relay_map) != 2:
                        raise ValueError(f"{role} ready.relay_map must contain the two configured QAD reflectors")
                    urls = [entry.get("url") for entry in relay_map if isinstance(entry, dict)]
                    if len(urls) != 2 or any(not isinstance(url, str) for url in urls) or len(set(urls)) != 2:
                        raise ValueError(f"{role} ready.relay_map must contain two distinct URL entries")
                    if not any(entry["url"] == PRIVATE_RELAY_URL and entry.get("qad_udp_port") == B_QAD_PORT for entry in relay_map):
                        raise ValueError(f"{role} ready.relay_map must retain B relay TCP 9443 and QAD UDP {B_QAD_PORT}")
                    if any(type(entry.get("qad_udp_port")) is not int or not 1 <= entry["qad_udp_port"] <= 65535 for entry in relay_map):
                        raise ValueError(f"{role} ready.relay_map contains an invalid QAD UDP port")
                    configured_qad = {entry["url"]: entry["qad_udp_port"] for entry in relay_map}
                    if configured_qad != {
                        PRIVATE_RELAY_URL: B_QAD_PORT,
                        OFFICIAL_RELAY_URL: OFFICIAL_QAD_PORT,
                    }:
                        raise ValueError(f"{role} ready.relay_map differs from the fixed B and official QAD reflectors")
                    matching = {
                        url: [report for report in qad_reports[role] if report["relay_url"] == url]
                        for url in urls
                    }
                    if all(matching[url] for url in urls):
                        reports_by_role[role] = (relay_map, matching)
                if len(reports_by_role) == 2:
                    break
                remaining = qad_deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("each live endpoint must emit one successful QadProbeReport per configured reflector")
                qad_report_event.clear()
                try:
                    await asyncio.wait_for(qad_report_event.wait(), remaining)
                except asyncio.TimeoutError as error:
                    raise TimeoutError("each live endpoint must emit one successful QadProbeReport per configured reflector") from error

            for role in ("client", "target"):
                event = ready[role]
                local_ip, _ = parse_socket_address(event.get("local_socket"), f"{role} ready.local_socket")
                expected_local_ip = ipaddress.ip_address(CLIENT_IP if role == "client" else TARGET_IP)
                if local_ip.version != 4 or local_ip != expected_local_ip:
                    raise ValueError(f"{role} live Endpoint bound socket does not match its configured IPv4 interface")
                global_ip, _ = parse_socket_address(event.get("global_v4"), f"{role} ready.global_v4")
                if global_ip.version != 4:
                    raise ValueError(f"{role} ready.global_v4 must be IPv4")
                endpoint_addr = event.get("endpoint_addr")
                if not isinstance(endpoint_addr, dict) or endpoint_addr.get("id") != event.get("endpoint_id"):
                    raise ValueError(f"{role} ready EndpointAddr identity must match the active Endpoint")
                existing_addrs = endpoint_addr.get("addrs")
                if not isinstance(existing_addrs, list):
                    raise ValueError(f"{role} ready EndpointAddr.addrs must be a list")
                if not any(addr == {"Ip": event["global_v4"]} for addr in existing_addrs):
                    raise ValueError(f"{role} original ready EndpointAddr must retain its QAD global_v4 candidate")
                relay_map, matching = reports_by_role[role]
                observed = []
                for relay in relay_map:
                    report = matching[relay["url"]][0]
                    report_ip, report_port = parse_socket_address(
                        report["socket_addr"], f"{role} QadProbeReport addr from {relay['url']}"
                    )
                    if report_ip.version != 4 or report_ip != global_ip:
                        raise ValueError(f"{role} QAD reflector reports a public IPv4 that differs from ready.global_v4")
                    observed.append({
                        "relay_url": relay["url"],
                        "qad_udp_port": relay.get("qad_udp_port"),
                        "socket_addr": f"{report_ip}:{report_port}",
                        "raw_report": report,
                    })
                unique_candidates = list(dict.fromkeys(item["socket_addr"] for item in observed))
                mapping_candidates["observations"][role] = {
                    "endpoint_id": event["endpoint_id"],
                    "bound_socket": event["local_socket"],
                    "global_v4": event["global_v4"],
                    "relay_map": relay_map,
                    "successful_qad_reports": observed,
                    "observed_unique_candidates": unique_candidates,
                    "predicted_extra_candidates": [],
                }

            client_self_candidates = mapping_candidates["observations"]["client"]["observed_unique_candidates"]
            target_self_candidates = mapping_candidates["observations"]["target"]["observed_unique_candidates"]
            target_prediction = []
            if args.predict_target_next_port:
                for candidate in target_self_candidates:
                    predicted_ip, observed_port = parse_socket_address(candidate, "target measured reflector candidate")
                    if observed_port == 65535:
                        raise ValueError("target +1 port prediction would overflow the UDP port range")
                    predicted_address = f"{predicted_ip}:{observed_port + 1}"
                    if predicted_address not in target_prediction:
                        target_prediction.append(predicted_address)
                if len(target_prediction) > 2:
                    raise ValueError("target next-port prediction exceeded the two-reflector candidate bound")
                mapping_candidates["observations"]["target"]["predicted_extra_candidates"] = target_prediction
                mapping_candidates["prediction"]["target_predicted_candidates"] = target_prediction
            control_to_client = copy.deepcopy(ready["target"])
            control_to_client["receiver_self_observed_candidates"] = client_self_candidates
            control_to_client["receiver_self_predicted_candidates"] = []
            control_to_target = copy.deepcopy(ready["client"])
            control_to_target["receiver_self_observed_candidates"] = target_self_candidates
            control_to_target["receiver_self_predicted_candidates"] = target_prediction
            if args.peer_ip_only:
                peer_candidates_by_receiver = {
                    "client": list(dict.fromkeys(target_self_candidates + target_prediction)),
                    "target": list(dict.fromkeys(client_self_candidates)),
                }
                sender_role_by_receiver = {"client": "target", "target": "client"}
                peer_ready_by_receiver = {"client": control_to_client, "target": control_to_target}
                for receiver_role, peer_candidates in peer_candidates_by_receiver.items():
                    sender_role = sender_role_by_receiver[receiver_role]
                    if not peer_candidates:
                        raise ValueError(f"{receiver_role} peer bootstrap candidates are empty")
                    peer_event = ready[sender_role]
                    peer_addr = peer_event["endpoint_addr"]
                    peer_global = parse_socket_address(
                        peer_event.get("global_v4"), f"{sender_role} ready.global_v4"
                    )
                    peer_candidate_tuples = [
                        parse_socket_address(candidate, f"{receiver_role} peer bootstrap candidate")
                        for candidate in peer_candidates
                    ]
                    if (len(peer_candidates) > 4
                            or any(candidate_ip.version != 4 or candidate_ip != peer_global[0]
                                   for candidate_ip, _ in peer_candidate_tuples)):
                        raise ValueError(f"{receiver_role} peer bootstrap candidates must be at most four IPv4 addresses for the peer's live public IP")
                    if peer_global not in peer_candidate_tuples:
                        raise ValueError(f"{receiver_role} peer bootstrap candidates omit the peer's live B QAD address")
                    original_ip_addrs = []
                    for address in peer_addr.get("addrs", []):
                        if isinstance(address, dict) and isinstance(address.get("Ip"), str):
                            original_ip, original_port = parse_socket_address(
                                address["Ip"], f"{sender_role} ready EndpointAddr IPv4 candidate"
                            )
                            if original_ip.version == 4:
                                original_ip_addrs.append(f"{original_ip}:{original_port}")
                    expected_dial_ips = list(dict.fromkeys(original_ip_addrs + peer_candidates))
                    expected_dial_addr = {
                        "id": peer_addr["id"],
                        "addrs": [{"Ip": address} for address in expected_dial_ips],
                    }
                    peer_ready_by_receiver[receiver_role]["peer_bootstrap_candidates"] = peer_candidates
                    mapping_candidates["peer_bootstrap"]["candidates_by_receiver"][receiver_role] = {
                        "sender_role": sender_role,
                        "receiver_role": receiver_role,
                        "peer_bootstrap_candidates": peer_candidates,
                        "peer_endpoint_addr_original": copy.deepcopy(peer_addr),
                        "expected_dial_endpoint_addr": expected_dial_addr,
                    }
                    mapping_candidates["peer_bootstrap"]["expected_dial_endpoint_addr_by_receiver"][receiver_role] = expected_dial_addr
            mapping_candidates["control_to_client"] = {
                "sender_role": "target",
                "sender_endpoint_id": ready["target"]["endpoint_id"],
                "receiver_role": "client",
                "receiver_endpoint_id": ready["client"]["endpoint_id"],
                "receiver_self_observed_candidates": client_self_candidates,
                "peer_ready": control_to_client,
            }
            mapping_candidates["control_to_target"] = {
                "sender_role": "client",
                "sender_endpoint_id": ready["client"]["endpoint_id"],
                "receiver_role": "target",
                "receiver_endpoint_id": ready["target"]["endpoint_id"],
                "receiver_self_observed_candidates": target_self_candidates,
                "peer_ready": control_to_target,
            }

        if args.capture_target:
            capture_info["target_local_socket"] = ready["target"]["local_socket"]
            socket_host, separator, socket_port = ready["target"]["local_socket"].rpartition(":")
            if not separator or ipaddress.ip_address(socket_host).version != 4:
                raise ValueError("target ready.local_socket must be an IPv4 socket address")
            target_port = int(socket_port)
            if not 1 <= target_port <= 65535:
                raise ValueError("target ready.local_socket port is outside the UDP port range")
            target_ip = str(ipaddress.IPv4Address(socket_host))
            capture_filter = f"ip and udp and port {target_port}"
            capture_info["target_local_ip"] = target_ip
            capture_info["bound_port"] = target_port
            capture_info["filter"] = capture_filter
            capture_command = (
                "printf 'KMESH_AC_CAPTURE_PID=%s\\n' \"$$\" >&2; "
                "exec /usr/bin/timeout -s INT -k 2s 35s /usr/sbin/tcpdump "
                f"-i ens1f0 -nn -tttt -l {shlex.quote(capture_filter)}"
            )
            capture_proc = await asyncio.create_subprocess_exec(
                *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(capture_command),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True,
            )
            capture_info["ssh_pid"] = capture_proc.pid
            capture_readers.append(asyncio.create_task(
                collect(capture_proc.stdout, logs["target-capture.packets.log"], "capture", [])
            ))
            supervisor_match, listening = None, False
            startup_deadline = min(deadline, asyncio.get_running_loop().time() + 10)
            with logs["target-capture.stderr.log"].open("ab") as output:
                while not listening:
                    remaining = startup_deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise TimeoutError("A tcpdump did not report listening on ens1f0")
                    try:
                        line = await asyncio.wait_for(capture_proc.stderr.readline(), remaining)
                    except asyncio.TimeoutError as error:
                        raise TimeoutError("A tcpdump did not report listening on ens1f0") from error
                    if not line:
                        raise RuntimeError("A capture SSH stream closed before tcpdump became ready")
                    output.write(line)
                    output.flush()
                    supervisor_match = supervisor_match or CAPTURE_PID_MARKER.search(line)
                    listening = b"listening on ens1f0" in line
            if supervisor_match is None:
                raise RuntimeError("capture supervisor PID marker was missing")
            capture_info["supervisor_pid"] = int(supervisor_match.group(1))
            capture_info["started_utc"] = datetime.now(timezone.utc).isoformat()

            inspect_script = f"""supervisor={capture_info['supervisor_pid']}
[ "$(readlink "/proc/$supervisor/exe" 2>/dev/null || true)" = /usr/bin/timeout ] || exit 2
children=$(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null) || exit 3
set -- $children
[ "$#" -eq 1 ] || exit 4
child=$1
child_exe=$(readlink "/proc/$child/exe" 2>/dev/null || true)
[ "$child_exe" = /usr/sbin/tcpdump ] || exit 5
printf 'KMESH_AC_CAPTURE_CHILD_PID=%s\\n' "$child"
printf 'KMESH_AC_CAPTURE_EXE=%s\\n' "$(readlink "/proc/$supervisor/exe")"
printf 'KMESH_AC_CAPTURE_CHILD_EXE=%s\\n' "$child_exe"
"""
            inspect_proc = await asyncio.create_subprocess_exec(
                *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(inspect_script),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True,
            )
            try:
                inspect_out, inspect_err = await asyncio.wait_for(inspect_proc.communicate(), 8)
            except asyncio.TimeoutError:
                await stop_group(inspect_proc)
                inspect_out, inspect_err = b"", b"capture process inspection timed out"
            logs["target-capture-inspect.stdout.log"].write_bytes(inspect_out)
            logs["target-capture-inspect.stderr.log"].write_bytes(inspect_err)
            child_match = CAPTURE_CHILD_PID_MARKER.search(inspect_out)
            supervisor_exe_match = CAPTURE_EXE_MARKER.search(inspect_out)
            child_exe_match = CAPTURE_CHILD_EXE_MARKER.search(inspect_out)
            if (inspect_proc.returncode != 0 or child_match is None or supervisor_exe_match is None
                    or child_exe_match is None):
                raise RuntimeError("could not verify the tcpdump timeout supervisor and child")
            capture_info["child_pid"] = int(child_match.group(1))
            capture_info["supervisor_executable"] = supervisor_exe_match.group(1).decode()
            capture_info["child_executable"] = child_exe_match.group(1).decode()
            capture_readers.append(asyncio.create_task(
                collect(capture_proc.stderr, logs["target-capture.stderr.log"], "capture", [])
            ))

        if args.capture_target:
            capture_info["peer_metadata_gate_utc"] = datetime.now(timezone.utc).isoformat()
        if args.mapping_candidates:
            control_to_client = mapping_candidates["control_to_client"]["peer_ready"]
            control_to_target = mapping_candidates["control_to_target"]["peer_ready"]
        else:
            control_to_client = ready["target"]
            control_to_target = ready["client"]
        await send_json(client, control_to_client)
        await send_json(target, control_to_target)

        if args.mapping_candidates:
            local_candidates_published = {}
            peer_received_roles = set()
            while (len(local_candidates_published) < 2
                   or (args.peer_ip_only and len(peer_received_roles) < 2)):
                role, event = await next_event(queue, deadline)
                if event["event"] == "direct_selected":
                    direct[role] = event
                    continue
                if args.peer_ip_only and event["event"] == "peer_received":
                    sender_role = {"client": "target", "target": "client"}[role]
                    event_bootstrap = event.get("peer_bootstrap_candidates")
                    source_addr = ready[sender_role]["endpoint_addr"]
                    original_peer_addr = event.get("original_peer_endpoint_addr")
                    dial_addr = event.get("dial_endpoint_addr")
                    dial_endpoints[role] = {
                        "sender_role": sender_role,
                        "receiver_role": role,
                        "peer_ip_only": event.get("peer_ip_only"),
                        "peer_bootstrap_candidates": event_bootstrap,
                        "original_peer_endpoint_addr": original_peer_addr,
                        "dial_endpoint_addr": dial_addr,
                        "validated": False,
                    }
                    mapping_candidates["peer_bootstrap"]["actual_dial_endpoint_by_receiver"] = copy.deepcopy(dial_endpoints)
                    if event.get("peer_ip_only") is not True:
                        raise ValueError(f"{role} helper did not report peer-ip-only dial setup")
                    expected_bootstrap = mapping_candidates["peer_bootstrap"]["candidates_by_receiver"][role]["peer_bootstrap_candidates"]
                    if (not isinstance(event_bootstrap, list)
                            or len(event_bootstrap) != len(expected_bootstrap)
                            or set(event_bootstrap) != set(expected_bootstrap)):
                        raise ValueError(f"{role} helper dial candidates differ from the peer's live QAD and prediction inputs")
                    expected_dial_addr = mapping_candidates["peer_bootstrap"]["expected_dial_endpoint_addr_by_receiver"][role]
                    if original_peer_addr != source_addr:
                        raise ValueError(f"{role} helper received a different peer EndpointAddr than the controller sent")
                    if not isinstance(dial_addr, dict) or dial_addr.get("id") != source_addr.get("id"):
                        raise ValueError(f"{role} helper reported a mismatched dial EndpointAddr identity")
                    dial_addrs = dial_addr.get("addrs")
                    if not isinstance(dial_addrs, list):
                        raise ValueError(f"{role} helper dial EndpointAddr has no address list")
                    dial_ips = [
                        address["Ip"] for address in dial_addrs
                        if isinstance(address, dict) and len(address) == 1 and isinstance(address.get("Ip"), str)
                    ]
                    expected_dial_ips = [address["Ip"] for address in expected_dial_addr["addrs"]]
                    if (len(dial_ips) != len(dial_addrs) or set(dial_ips) != set(expected_dial_ips)
                            or len(dial_ips) != len(expected_dial_ips)):
                        raise ValueError(f"{role} actual dial EndpointAddr differs from peer LAN plus live bootstrap candidates or contains a relay")
                    dial_endpoints[role]["validated"] = True
                    mapping_candidates["peer_bootstrap"]["actual_dial_endpoint_by_receiver"] = copy.deepcopy(dial_endpoints)
                    peer_received_roles.add(role)
                    continue
                if event["event"] != "local_candidates_published":
                    continue
                observation = mapping_candidates["observations"][role]
                if event.get("role") != role or event.get("endpoint_id") != observation["endpoint_id"]:
                    raise ValueError(f"{role} local_candidates_published identity mismatch")
                if event.get("bound_socket") != observation["bound_socket"]:
                    raise ValueError(f"{role} local_candidates_published bound socket mismatch")
                if event.get("actual_home_relay_url") != ready[role].get("relay_url") or event.get("b_relay_connected") is not True:
                    raise ValueError(f"{role} local candidate publication did not retain the connected private B relay")
                expected_observed = observation["observed_unique_candidates"]
                expected_predicted = observation["predicted_extra_candidates"]
                expected_published = list(dict.fromkeys(expected_observed + expected_predicted))
                event_observed = event.get("receiver_self_observed_candidates")
                if (not isinstance(event_observed, list) or len(event_observed) != len(expected_observed)
                        or any(not isinstance(address, str) for address in event_observed)
                        or set(event_observed) != set(expected_observed)):
                    raise ValueError(f"{role} published measured candidates differ from this process's QAD observations")
                event_predicted = event.get("receiver_self_predicted_port_candidates")
                if (not isinstance(event_predicted, list) or len(event_predicted) != len(expected_predicted)
                        or any(not isinstance(address, str) for address in event_predicted)
                        or set(event_predicted) != set(expected_predicted)):
                    raise ValueError(f"{role} published predicted candidates differ from the controller's bounded rule")
                event_published = event.get("published_candidates")
                if (not isinstance(event_published, list) or len(event_published) != len(expected_published)
                        or any(not isinstance(address, str) for address in event_published)
                        or set(event_published) != set(expected_published)):
                    raise ValueError(f"{role} published candidate union differs from measured and predicted inputs")
                endpoint_addr_before = event.get("endpoint_addr_before")
                endpoint_addr_after = event.get("endpoint_addr_after")
                if (not isinstance(endpoint_addr_before, dict) or not isinstance(endpoint_addr_after, dict)
                        or endpoint_addr_before.get("id") != observation["endpoint_id"]
                        or endpoint_addr_after.get("id") != observation["endpoint_id"]):
                    raise ValueError(f"{role} published EndpointAddr identity mismatch")
                relay_before = [addr for addr in endpoint_addr_before.get("addrs", []) if isinstance(addr, dict) and "Relay" in addr]
                relay_after = [addr for addr in endpoint_addr_after.get("addrs", []) if isinstance(addr, dict) and "Relay" in addr]
                if (relay_after != relay_before
                        or {"Relay": event["actual_home_relay_url"]} not in relay_after):
                    raise ValueError(f"{role} local candidate publication changed EndpointAddr relay URLs")
                if not all({"Ip": address} in endpoint_addr_after.get("addrs", []) for address in expected_published):
                    raise ValueError(f"{role} watch_addr confirmation lacks one or more observed QAD candidates")
                local_candidates_published[role] = event
                mapping_candidates["watch_addr_published_ip_candidates"][role] = [
                    addr["Ip"] for addr in endpoint_addr_after.get("addrs", [])
                    if isinstance(addr, dict) and isinstance(addr.get("Ip"), str)
                ]
            mapping_candidates["local_candidates_published"] = local_candidates_published

        while len(direct) < 2:
            role, event = await next_event(queue, deadline)
            if event["event"] == "direct_selected":
                direct[role] = event
        await send_json(client, {"event": "go"})
        await send_json(target, {"event": "go"})
        gate_sent = True

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("runner deadline elapsed before nonce exchange completed")
        await asyncio.wait_for(asyncio.gather(client.wait(), target.wait()), remaining)
        await asyncio.wait_for(asyncio.gather(*readers), 3)
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
        if not gate_sent:
            await asyncio.gather(
                send_json(procs.get("client"), {"event": "abort"}),
                send_json(procs.get("target"), {"event": "abort"}),
                return_exceptions=True,
            )
    finally:
        await asyncio.gather(*(stop_group(proc) for proc in procs.values()), return_exceptions=True)
        if readers:
            try:
                await asyncio.wait_for(asyncio.gather(*readers, return_exceptions=True), 2)
            except asyncio.TimeoutError:
                for task in readers:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*readers, return_exceptions=True)

        if capture_proc is not None:
            if capture_proc.returncode is None:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining > 0:
                    try:
                        await asyncio.wait_for(capture_proc.wait(), remaining)
                    except asyncio.TimeoutError:
                        pass
            capture_info["exit_code"] = capture_proc.returncode
            capture_info["cleanup"] = await cleanup_target_capture(
                capture_info["supervisor_pid"], capture_info["child_pid"],
                logs["target-capture-cleanup.stdout.log"],
                logs["target-capture-cleanup.stderr.log"],
            )
            cleanup_out = logs["target-capture-cleanup.stdout.log"].read_bytes()
            if capture_info["child_pid"] is None:
                child_match = CAPTURE_CHILD_PID_MARKER.search(cleanup_out)
                if child_match:
                    capture_info["cleanup"]["discovered_child_pid"] = int(child_match.group(1))
            if capture_proc.returncode is None:
                await stop_group(capture_proc)
                capture_info["exit_code"] = capture_proc.returncode
            capture_info["stopped_utc"] = datetime.now(timezone.utc).isoformat()
            if capture_readers:
                try:
                    await asyncio.wait_for(asyncio.gather(*capture_readers), 3)
                except asyncio.TimeoutError:
                    for task in capture_readers:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*capture_readers, return_exceptions=True)
            packet_lines = logs["target-capture.packets.log"].read_bytes().splitlines()
            ip_packet_lines = [line for line in packet_lines if b" IP " in line or line.startswith(b"IP ")]
            capture_info["packet_lines"] = len(ip_packet_lines)
            local_endpoint = f"{capture_info['target_local_ip']}.{capture_info['bound_port']}".encode()
            tx_packets = tx_bytes = rx_packets = rx_bytes = udp_payload_length_1200_count = 0
            for line in ip_packet_lines:
                payload = re.search(rb"length (\d+)", line)
                byte_count = int(payload.group(1)) if payload else 0
                if byte_count == 1200:
                    udp_payload_length_1200_count += 1
                if re.search(rb"(?:^|\s)" + re.escape(local_endpoint) + rb"\s+>", line):
                    tx_packets += 1
                    tx_bytes += byte_count
                elif re.search(rb">\s+" + re.escape(local_endpoint) + rb":", line):
                    rx_packets += 1
                    rx_bytes += byte_count
            capture_info["tx_packets"] = tx_packets
            capture_info["tx_udp_payload_bytes"] = tx_bytes
            capture_info["rx_packets"] = rx_packets
            capture_info["rx_udp_payload_bytes"] = rx_bytes
            capture_info["udp_payload_length_1200_packet_count"] = udp_payload_length_1200_count
            capture_stderr_text = logs["target-capture.stderr.log"].read_text(errors="replace")
            for key, pattern in (
                ("captured", r"(\d+) packets captured"),
                ("received_by_filter", r"(\d+) packets received by filter"),
                ("dropped_by_kernel", r"(\d+) packets dropped by kernel"),
                ("dropped_by_interface", r"(\d+) packets? dropped by (?:the )?interface"),
            ):
                match = re.search(pattern, capture_stderr_text)
                if match:
                    capture_info["statistics"][key] = int(match.group(1))
            if capture_info["started_utc"] is None and failure is None:
                failure = "RuntimeError: target tcpdump readiness gate was not reached"
            if (capture_info["started_utc"] is not None
                    and (capture_info["exit_code"] != 124 or not capture_info["cleanup"]["verified"])
                    and failure is None):
                failure = "RuntimeError: target tcpdump did not complete its bounded verified capture"

    if args.mapping_candidates:
        mapping_candidates["all_successful_qad_reports"] = copy.deepcopy(qad_reports)

    cleanup = await cleanup_target(
        pid_file, args.target_bin, remote_pid["pid"],
        logs["remote-cleanup.stdout.log"], logs["remote-cleanup.stderr.log"],
    )
    nonce_events = {
        role: next((event for event in events[role] if event.get("event") == "nonce_result"), None)
        for role in ("client", "target")
    }
    complete = {
        role: next((event for event in events[role] if event.get("event") == "complete"), None)
        for role in ("client", "target")
    }
    prediction_result = None
    if args.predict_target_next_port:
        target_observation = mapping_candidates["observations"].get("target", {})
        predicted_candidates = target_observation.get("predicted_extra_candidates", [])
        measured_candidates = target_observation.get("observed_unique_candidates", [])
        client_nonce = nonce_events["client"] or {}
        selected_sample = client_nonce.get("selected_direct_before")
        if not isinstance(selected_sample, dict):
            selected_sample = (direct.get("client") or {}).get("selected_path")
        selected_remote = selected_sample.get("remote_addr") if isinstance(selected_sample, dict) else None
        selected_ipv4 = bool(
            isinstance(selected_sample, dict)
            and selected_sample.get("selected") is True
            and selected_sample.get("is_ip") is True
            and selected_sample.get("is_ipv4") is True
        )
        selected_socket_addr = None
        if selected_ipv4:
            selected_ip, selected_port = parse_socket_address(selected_remote[3:], "selected IPv4 path remote_addr")
            selected_socket_addr = f"{selected_ip}:{selected_port}"
        path_id = selected_sample.get("path_id") if isinstance(selected_sample, dict) else None
        selected_delta = next((
            delta for delta in client_nonce.get("direct_path_udp_deltas", [])
            if delta.get("path_id") == path_id
        ), None)
        same_path_bytes = bool(
            selected_delta
            and selected_delta.get("tx_bytes_delta", 0) > 0
            and selected_delta.get("rx_bytes_delta", 0) > 0
            and client_nonce.get("direct_bytes_grew_both_directions") is True
        )
        nonce_pass = (
            all(event is not None and event.get("nonce_echoes_match") is True and event.get("pass") is True
                for event in nonce_events.values())
            and all(event is not None and event.get("pass") is True for event in complete.values())
        )
        predicted_hit = selected_ipv4 and selected_socket_addr in predicted_candidates
        measured_hit = selected_ipv4 and selected_socket_addr in measured_candidates
        prediction_confirmed = predicted_hit and same_path_bytes and nonce_pass
        if prediction_confirmed:
            outcome = "predicted_candidate_direct_data_confirmed"
        elif same_path_bytes and nonce_pass and measured_hit:
            outcome = "measured_reflector_candidate_direct_data_confirmed"
        elif same_path_bytes and nonce_pass:
            outcome = "other_candidate_direct_data_confirmed"
        elif selected_ipv4:
            outcome = "direct_path_selected_without_complete_payload_proof"
        else:
            outcome = "no_direct_result"
        prediction_result = {
            "outcome": outcome,
            "predicted_candidates": predicted_candidates,
            "measured_reflector_candidates": measured_candidates,
            "selected_remote_addr": selected_remote,
            "selected_socket_addr": selected_socket_addr,
            "selected_ipv4_path": selected_ipv4,
            "selected_remote_is_predicted": bool(predicted_hit),
            "selected_remote_is_reflector_measured": bool(measured_hit),
            "same_path_tx_and_rx_bytes_grew": same_path_bytes,
            "nonce_pass_both_roles": bool(nonce_pass),
            "prediction_confirmed": bool(prediction_confirmed),
        }
    success = (
        failure is None
        and set(procs) == {"client", "target"}
        and all(proc.returncode == 0 for proc in procs.values())
        and all(event is not None and event.get("pass") is True for event in nonce_events.values())
        and all(event is not None and event.get("pass") is True for event in complete.values())
        and all(
            role in direct
            and isinstance(direct[role].get("selected_path"), dict)
            and direct[role]["selected_path"].get("selected") is True
            and direct[role]["selected_path"].get("is_ip") is True
            and direct[role]["selected_path"].get("is_ipv4") is True
            for role in ("client", "target")
        )
        and cleanup["verified"]
        and (not args.mapping_candidates or (
            len(mapping_candidates["observations"]) == 2
            and all(len(observation["successful_qad_reports"]) == 2
                    for observation in mapping_candidates["observations"].values())
            and len(mapping_candidates["local_candidates_published"]) == 2
            and (not args.peer_ip_only or len(mapping_candidates["peer_bootstrap"]["actual_dial_endpoint_by_receiver"]) == 2)
        ))
        and (not args.capture_target or (
            capture_info["started_utc"] is not None
            and capture_info["exit_code"] == 124
            and capture_info["cleanup"]["verified"]
        ))
    )
    summary = {
        "status": "passed" if success else "failed",
        "failure": failure,
        "relay_mode": args.relay_mode,
        "peer_ip_only": args.peer_ip_only,
        "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
        "local_client_pid": procs["client"].pid if "client" in procs else None,
        "target_ssh_pid": procs["target"].pid if "target" in procs else None,
        "target_helper_pid": remote_pid["pid"] or cleanup["cleaned_pid"],
        "target_executable": args.target_bin,
        "ready": ready,
        "direct_selected": direct,
        "dial_endpoints": dial_endpoints,
        "prediction_result": prediction_result,
        "nonce_result": nonce_events,
        "complete": complete,
        "exit_codes": {role: proc.returncode for role, proc in procs.items()},
        "remote_cleanup": cleanup,
        "mapping_candidates": mapping_candidates,
        "target_capture": capture_info,
        "events": events,
        "raw_logs": {name: str(path) for name, path in logs.items()},
        "evidence_directory": str(out_dir),
    }
    summary_path = out_dir / "summary.json"
    create_private_file(summary_path)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-bin", required=True, help="local macOS udp_ac_check executable")
    parser.add_argument("--target-bin", required=True, help="absolute udp_ac_check path already staged on target-1")
    parser.add_argument("--relay-mode", required=True, choices=("private", "public"))
    parser.add_argument("--client-secret-file", help="private local enrolled key file (private mode only)")
    parser.add_argument("--target-secret-file", help="absolute enrolled key file on target-1 (private mode only)")
    parser.add_argument("--out-dir", required=True, help="new private evidence directory")
    parser.add_argument("--capture-target", action="store_true", help="capture the target UDP endpoint on target-1 ens1f0")
    parser.add_argument("--mapping-candidates", action="store_true", help="exchange each endpoint's two live QAD-observed IP:port candidates")
    parser.add_argument("--predict-target-next-port", action="store_true", help="add at most two target candidates predicted from this run's QAD ports")
    parser.add_argument("--peer-ip-only", action="store_true", help="use peer IP candidates only, with same-run measured bootstrap candidates (private mapping-candidates mode only)")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
