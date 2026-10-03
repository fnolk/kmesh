#!/usr/bin/env python3
"""Run one same-tuple QAD, raw-UDP, and Iroh direct-path validation round."""

import argparse
import asyncio
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
TARGET_IP = "10.0.0.4"
CLIENT_IP = "10.0.0.6"
PRIVATE_RELAY_URL = "https://192.0.2.11:9443/"
B_QAD_ADDR = "192.0.2.11:3478"
OFFICIAL_QAD_PORT = 7842
TARGET_CA = "/opt/kmesh-iroh-verification/ca.pem"
CLIENT_CA = "/Users/example/.cache/kmesh-live/server/ca.pem"
TARGET_SOCKET_COUNT = 257
TIMEOUT_SECONDS = 75
CAPTURE_SECONDS = 55
REMOTE_PID_MARKER = re.compile(rb"KMESH_BIRTHDAY_REMOTE_PID=([0-9]+)")
CAPTURE_PID_MARKER = re.compile(rb"KMESH_BIRTHDAY_CAPTURE_PID=([0-9]+)")
CAPTURE_CHILD_PID_MARKER = re.compile(rb"KMESH_BIRTHDAY_CAPTURE_CHILD_PID=([0-9]+)")
CAPTURE_TIMEOUT_EXE_MARKER = re.compile(rb"KMESH_BIRTHDAY_CAPTURE_TIMEOUT_EXE=(/[^\r\n]+)")
CAPTURE_TCPDUMP_EXE_MARKER = re.compile(rb"KMESH_BIRTHDAY_CAPTURE_TCPDUMP_EXE=(/[^\r\n]+)")


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
        raise ValueError(f"{field} has an invalid UDP port")
    return address, port


def validate_qad_ready(role, ready, expected_local_ip):
    if ready.get("role") != role:
        raise ValueError(f"{role} ready role mismatch")
    if ready.get("configured_relay_url") != PRIVATE_RELAY_URL:
        raise ValueError(f"{role} endpoint must stay on the fixed private B relay")
    endpoint_id = ready.get("endpoint_id")
    if not isinstance(endpoint_id, str) or not endpoint_id:
        raise ValueError(f"{role} endpoint ID is missing")
    local_ip, _ = parse_socket_address(ready.get("local_socket"), f"{role} ready.local_socket")
    if local_ip.version != 4 or str(local_ip) != expected_local_ip:
        raise ValueError(f"{role} ready socket is not on its configured IPv4 interface")

    observations = ready.get("observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise ValueError(f"{role} must report both completed QAD reflector observations")
    reflectors, public_ips, normalized = set(), set(), []
    for observation in observations:
        reflector = observation.get("reflector")
        if not isinstance(reflector, dict):
            raise ValueError(f"{role} QAD observation has no reflector descriptor")
        reflector_addr = reflector.get("addr")
        reflector_ip, reflector_port = parse_socket_address(reflector_addr, f"{role} reflector.addr")
        server_name = reflector.get("server_name")
        if not isinstance(server_name, str) or not server_name:
            raise ValueError(f"{role} QAD observation has no TLS server name")
        reflector_key = (str(reflector_ip), reflector_port)
        if reflector_key in reflectors:
            raise ValueError(f"{role} QAD observations repeat a reflector")
        reflectors.add(reflector_key)
        if reflector_port not in (3478, OFFICIAL_QAD_PORT):
            raise ValueError(f"{role} QAD observation uses an unexpected UDP port")
        if reflector_port == 3478 and str(reflector_ip) != "192.0.2.11":
            raise ValueError("private QAD reflector must remain B UDP 3478")
        if (reflector_port == OFFICIAL_QAD_PORT
                and not server_name.endswith(("relay.n0.iroh.link.", "relay.n0.iroh.link"))):
            raise ValueError(f"{role} UDP 7842 QAD source is not an Iroh public relay")
        if observation.get("handshake_confirmed") is not True:
            raise ValueError(f"{role} QAD handshake is not confirmed")
        if observation.get("local_socket") != ready["local_socket"]:
            raise ValueError(f"{role} QAD observation used a different local socket")
        observed_addr = observation.get("observed_addr")
        observed_ip, observed_port = parse_socket_address(observed_addr, f"{role} QAD observed_addr")
        if observed_ip.version != 4:
            raise ValueError(f"{role} QAD observation must be IPv4")
        public_ips.add(str(observed_ip))
        counters = {}
        for direction in ("tx", "rx"):
            for metric in ("datagrams", "bytes"):
                name = f"udp_{direction}_{metric}"
                value = observation.get(name)
                if type(value) is not int or value < 0:
                    raise ValueError(f"{role} QAD observation has an invalid {name} counter")
                counters[name] = value
        if not all(counters.values()):
            raise ValueError(f"{role} QAD evidence lacks bidirectional UDP counters")
        normalized.append({
            "reflector": {"addr": reflector_addr, "server_name": server_name},
            "local_socket": ready["local_socket"],
            "observed_addr": f"{observed_ip}:{observed_port}",
            "handshake_confirmed": True,
            **counters,
        })
    if {port for _, port in reflectors} != {3478, OFFICIAL_QAD_PORT}:
        raise ValueError(f"{role} needs B UDP 3478 and official UDP 7842 QAD observations")
    return {
        "endpoint_id": endpoint_id,
        "local_socket": ready["local_socket"],
        "observations": normalized,
        "observed_public_ips": sorted(public_ips),
    }


def selected_a_socket(raw_ready, raw_selected):
    sockets = raw_ready.get("sockets")
    if not isinstance(sockets, list) or len(sockets) != TARGET_SOCKET_COUNT:
        raise ValueError("A raw_ready must expose all 257 UDP sockets")
    index = raw_selected.get("index")
    if type(index) is not int or not 0 <= index < TARGET_SOCKET_COUNT:
        raise ValueError("raw_selected A index is outside its socket vector")
    matches = [item for item in sockets if item.get("index") == index]
    if len(matches) != 1:
        raise ValueError("raw_selected A index does not identify exactly one socket")
    local_socket = raw_selected.get("local_socket")
    if local_socket != matches[0].get("local_socket"):
        raise ValueError("raw_selected A tuple differs from the indexed raw_ready socket")
    ip, _ = parse_socket_address(local_socket, "A raw_selected.local_socket")
    if ip.version != 4 or str(ip) != TARGET_IP:
        raise ValueError("selected A socket is not on target-1's configured IPv4 interface")
    return matches[0]


def derive_handoff_messages(target_raw, client_raw, selected_target_index):
    if target_raw.get("index") != selected_target_index or client_raw.get("index") != selected_target_index:
        raise ValueError("both raw_selected events must identify the same A socket index")
    target_peer_observed = target_raw.get("peer_observed_addr")
    client_peer_observed = client_raw.get("peer_observed_addr")
    for field, value in (("target peer_observed_addr", target_peer_observed),
                         ("client peer_observed_addr", client_peer_observed)):
        address, _ = parse_socket_address(value, field)
        if address.version != 4:
            raise ValueError(f"{field} must be IPv4")
    return {
        "target": {
            "event": "hand_off",
            "self_observed_addr": client_peer_observed,
            "peer_observed_addr": target_peer_observed,
        },
        "client": {
            "event": "hand_off",
            "self_observed_addr": target_peer_observed,
            "peer_observed_addr": client_peer_observed,
        },
    }


def validate_nonce_protocol(nonce_results, direct_selected, native_ready, complete):
    expected_roles = {"target", "client"}
    if (set(nonce_results) != expected_roles or set(direct_selected) != expected_roles
            or set(native_ready) != expected_roles or set(complete) != expected_roles):
        raise ValueError("nonce validation needs both authenticated endpoint roles")
    evidence = {}
    for role in ("target", "client"):
        result = nonce_results[role]
        rounds = result.get("nonce_rounds")
        if not isinstance(rounds, list) or len(rounds) != 6:
            raise ValueError(f"{role} did not report six nonce-direction results")
        keys = [(item.get("round"), item.get("direction")) for item in rounds]
        expected_keys = {
            (round_number, direction)
            for round_number in (1, 2, 3)
            for direction in ("target_to_client", "client_to_target")
        }
        if len(set(keys)) != 6 or set(keys) != expected_keys:
            raise ValueError(f"{role} nonce results do not cover each round in both directions")
        if any(not isinstance(item.get("nonce_sha256"), str) for item in rounds):
            raise ValueError(f"{role} nonce hash evidence is incomplete")
        sent_echoes = [item for item in rounds if item.get("echo_matches") is True]
        returned_echoes = [item for item in rounds if item.get("echo_sent") is True]
        if len(sent_echoes) != 3 or len(returned_echoes) != 3:
            raise ValueError(f"{role} must verify its three sent nonces and echo the three peer nonces")
        if any(item.get(key) is not True for item in rounds for key in (
            "fin_complete", "peer_eof", "send_stopped_ok"
        )):
            raise ValueError(f"{role} nonce stream FIN/EOF completion is incomplete")
        if (result.get("nonce_echoes_match") is not True
                or result.get("peer_nonces_echoed") is not True
                or result.get("fin_complete") is not True
                or result.get("peer_eof") is not True
                or result.get("send_stopped_ok") is not True
                or result.get("direct_path_udp_bytes_grew_both_directions") is not True
                or result.get("pass") is not True):
            raise ValueError(f"{role} failed nonce, direct-path byte-growth, or FIN verification")
        selected_path = direct_selected[role]["selected_path"]
        selected_path_id = selected_path["path_id"]
        deltas = result.get("path_deltas")
        selected_delta = next((
            delta for delta in deltas if delta.get("path_id") == selected_path_id
        ), None) if isinstance(deltas, list) else None
        if (selected_delta is None or selected_delta.get("tx_bytes_delta", 0) <= 0
                or selected_delta.get("rx_bytes_delta", 0) <= 0):
            raise ValueError(f"{role} selected IPv4 path has no bidirectional UDP byte growth")
        completion = complete[role]
        if completion.get("endpoint_id") != native_ready[role]["endpoint_id"]:
            raise ValueError(f"{role} completion endpoint identity mismatch")
        if (completion.get("same_tuple_reused") is not True
                or completion.get("nonce_echoes_match") is not True
                or completion.get("peer_nonces_echoed") is not True
                or completion.get("fin_complete") is not True
                or completion.get("peer_eof") is not True
                or completion.get("send_stopped_ok") is not True
                or completion.get("pass") is not True):
            raise ValueError(f"{role} did not confirm same-tuple direct nonce/FIN completion")
        evidence[role] = {
            "sent_nonce_echoes_verified": len(sent_echoes),
            "peer_nonce_echoes_sent": len(returned_echoes),
            "selected_path_id": selected_path_id,
            "selected_path_tx_bytes_delta": selected_delta["tx_bytes_delta"],
            "selected_path_rx_bytes_delta": selected_delta["rx_bytes_delta"],
            "same_tuple_reused": True,
            "fin_complete": True,
        }

    target_rounds = {
        (item["round"], item["direction"]): item
        for item in nonce_results["target"]["nonce_rounds"]
    }
    client_rounds = {
        (item["round"], item["direction"]): item
        for item in nonce_results["client"]["nonce_rounds"]
    }
    for key in target_rounds:
        target_round = target_rounds[key]
        client_round = client_rounds[key]
        target_matches = target_round.get("echo_matches") is True
        client_matches = client_round.get("echo_matches") is True
        target_echoed = target_round.get("echo_sent") is True
        client_echoed = client_round.get("echo_sent") is True
        if (target_round.get("nonce_sha256") != client_round.get("nonce_sha256")
                or target_matches == client_matches
                or target_echoed == client_echoed
                or target_matches != client_echoed
                or target_echoed != client_matches):
            raise ValueError(f"target/client nonce hashes or echo directions differ for {key}")
    evidence["cross_endpoint_nonce_hashes_match"] = True
    return evidence


def ssh_base():
    return ["ssh", "-oBatchMode=yes", "-oConnectTimeout=8", "-oConnectionAttempts=1", "-T"]


async def collect_stdout(reader, path, role, events, queue):
    with path.open("ab") as output:
        while line := await reader.readline():
            output.write(line)
            output.flush()
            event = parse_event(line)
            if event is not None:
                events[role].append(event)
                queue.put_nowait((role, event))
    queue.put_nowait((role, None))


async def collect_raw(reader, path):
    with path.open("ab") as output:
        while data := await reader.read(65536):
            output.write(data)
            output.flush()


async def collect_target_stderr(reader, path, remote_pid):
    with path.open("ab") as output:
        while line := await reader.readline():
            output.write(line)
            output.flush()
            marker = REMOTE_PID_MARKER.search(line)
            if marker:
                remote_pid["pid"] = int(marker.group(1))


async def collect_capture_stderr(reader, path, capture, ready_event):
    with path.open("ab") as output:
        while line := await reader.readline():
            output.write(line)
            output.flush()
            marker = CAPTURE_PID_MARKER.search(line)
            if marker:
                capture["supervisor_pid"] = int(marker.group(1))
            if b"listening on ens1f0" in line:
                ready_event.set()


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


async def next_event(queue, deadline, finished_roles):
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("75-second runner deadline elapsed")
        try:
            role, event = await asyncio.wait_for(queue.get(), remaining)
        except asyncio.TimeoutError as error:
            raise TimeoutError("75-second runner deadline elapsed") from error
        if event is None:
            if role in finished_roles:
                continue
            raise RuntimeError(f"{role} helper stdout closed before a validated complete event")
        if event.get("event") == "failure":
            raise RuntimeError(f"{role} helper failed: {event.get('error', event)}")
        return role, event


async def cleanup_remote_helper(pid_file, target_bin, reported_pid, stdout_path, stderr_path):
    expected_pid = "" if reported_pid is None else str(reported_pid)
    script = f"""pid_file={shlex.quote(pid_file)}
expected_bin={shlex.quote(target_bin)}
expected_pid={shlex.quote(expected_pid)}
if [ ! -f "$pid_file" ]; then
  printf 'KMESH_BIRTHDAY_CLEANUP=no-target\\n'
  exit 0
fi
pid=$(cat "$pid_file") || exit 2
case "$pid" in ''|*[!0-9]*) exit 3;; esac
[ -z "$expected_pid" ] || [ "$pid" = "$expected_pid" ] || exit 4
proc=/proc/$pid
same_exe() {{ [ -e "$proc/exe" ] && [ "$(readlink "$proc/exe" 2>/dev/null || true)" = "$expected_bin" ]; }}
if same_exe; then
  kill -TERM "$pid" 2>/dev/null || true
  i=0
  while [ "$i" -lt 10 ] && same_exe; do sleep 0.1; i=$((i + 1)); done
  if same_exe; then kill -KILL "$pid" 2>/dev/null || true; fi
  i=0
  while [ "$i" -lt 10 ] && same_exe; do sleep 0.1; i=$((i + 1)); done
  same_exe && exit 5
fi
printf 'KMESH_BIRTHDAY_CLEANUP=verified\\n'
rm -f -- "$pid_file"
"""
    proc = await asyncio.create_subprocess_exec(
        *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(script),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 4)
    except asyncio.TimeoutError:
        await stop_group(proc)
        out, err = b"", b"remote helper cleanup timed out"
    stdout_path.write_bytes(out)
    stderr_path.write_bytes(err)
    stdout_path.chmod(0o600)
    stderr_path.chmod(0o600)
    no_target = b"KMESH_BIRTHDAY_CLEANUP=no-target" in out
    return {
        "exit_code": proc.returncode,
        "reported_pid": reported_pid,
        "verified": proc.returncode == 0 and (
            b"KMESH_BIRTHDAY_CLEANUP=verified" in out or no_target
        ),
        "no_target_started": no_target,
        "stdout": out.decode(errors="replace"),
        "stderr": err.decode(errors="replace"),
    }


async def cleanup_remote_capture(supervisor_pid, child_pid, stdout_path, stderr_path):
    supervisor = "" if supervisor_pid is None else str(supervisor_pid)
    child = "" if child_pid is None else str(child_pid)
    script = f"""supervisor={shlex.quote(supervisor)}
child={shlex.quote(child)}
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
    printf 'KMESH_BIRTHDAY_CAPTURE_CHILD_PID=%s\\n' "$child"
  fi
fi
if same_tcpdump; then kill -INT "$child" 2>/dev/null || true; fi
if same_timeout; then kill -INT "$supervisor" 2>/dev/null || true; fi
i=0
while [ "$i" -lt 10 ] && {{ same_timeout || same_tcpdump; }}; do sleep 0.1; i=$((i + 1)); done
if same_tcpdump; then kill -KILL "$child" 2>/dev/null || true; fi
if same_timeout; then kill -KILL "$supervisor" 2>/dev/null || true; fi
i=0
while [ "$i" -lt 10 ] && {{ same_timeout || same_tcpdump; }}; do sleep 0.1; i=$((i + 1)); done
if same_timeout || same_tcpdump; then exit 5; fi
printf 'KMESH_BIRTHDAY_CAPTURE_CLEANUP=verified\\n'
"""
    proc = await asyncio.create_subprocess_exec(
        *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(script),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 4)
    except asyncio.TimeoutError:
        await stop_group(proc)
        out, err = b"", b"remote capture cleanup timed out"
    stdout_path.write_bytes(out)
    stderr_path.write_bytes(err)
    stdout_path.chmod(0o600)
    stderr_path.chmod(0o600)
    marker = CAPTURE_CHILD_PID_MARKER.search(out)
    return {
        "exit_code": proc.returncode,
        "supervisor_pid": supervisor_pid,
        "child_pid": child_pid or (int(marker.group(1)) if marker else None),
        "verified": (
            supervisor_pid is not None and proc.returncode == 0
            and b"KMESH_BIRTHDAY_CAPTURE_CLEANUP=verified" in out
        ),
        "stdout": out.decode(errors="replace"),
        "stderr": err.decode(errors="replace"),
    }


async def start_target_capture(client_ready, logs, deadline):
    public_ips = sorted({
        parse_socket_address(obs["observed_addr"], "client QAD observed_addr")[0].compressed
        for obs in client_ready["observations"]
    })
    client_local_ip = parse_socket_address(
        client_ready["local_socket"], "client ready.local_socket"
    )[0].compressed
    hosts = list(dict.fromkeys(public_ips + [client_local_ip]))
    capture_filter = "udp and (" + " or ".join(f"host {host}" for host in hosts) + ")"
    capture_command = (
        "printf 'KMESH_BIRTHDAY_CAPTURE_PID=%s\\n' \"$$\" >&2; "
        f"exec /usr/bin/timeout -s INT -k 2s {CAPTURE_SECONDS}s "
        f"/usr/sbin/tcpdump -i ens1f0 -nn -tttt -l {shlex.quote(capture_filter)}"
    )
    proc = await asyncio.create_subprocess_exec(
        *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(capture_command),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    state = {
        "ssh_pid": proc.pid,
        "supervisor_pid": None,
        "child_pid": None,
        "supervisor_executable": None,
        "child_executable": None,
        "interface": "ens1f0",
        "filter": capture_filter,
        "c_public_ips": public_ips,
        "c_local_ip": client_local_ip,
        "started_utc": None,
        "stopped_utc": None,
        "exit_code": None,
        "packet_lines": None,
        "udp_payload_length_1200_count": None,
        "statistics": {},
        "stdout": str(logs["target-capture.packets.log"]),
        "stderr": str(logs["target-capture.stderr.log"]),
        "cleanup": None,
        "_proc": proc,
    }
    listening = asyncio.Event()
    state["_readers"] = [
        asyncio.create_task(collect_raw(proc.stdout, logs["target-capture.packets.log"])),
        asyncio.create_task(collect_capture_stderr(
            proc.stderr, logs["target-capture.stderr.log"], state, listening
        )),
    ]
    remaining = min(deadline, asyncio.get_running_loop().time() + 10) - asyncio.get_running_loop().time()
    try:
        await asyncio.wait_for(listening.wait(), remaining)
        if state["supervisor_pid"] is None:
            raise RuntimeError("A capture timeout-supervisor PID marker is missing")
        state["started_utc"] = datetime.now(timezone.utc).isoformat()
        inspect_script = f"""supervisor={state['supervisor_pid']}
[ "$(readlink "/proc/$supervisor/exe" 2>/dev/null || true)" = /usr/bin/timeout ] || exit 2
children=$(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null) || exit 3
set -- $children
[ "$#" -eq 1 ] || exit 4
child=$1
child_exe=$(readlink "/proc/$child/exe" 2>/dev/null || true)
[ "$child_exe" = /usr/sbin/tcpdump ] || exit 5
printf 'KMESH_BIRTHDAY_CAPTURE_CHILD_PID=%s\\n' "$child"
printf 'KMESH_BIRTHDAY_CAPTURE_TIMEOUT_EXE=%s\\n' "$(readlink "/proc/$supervisor/exe")"
printf 'KMESH_BIRTHDAY_CAPTURE_TCPDUMP_EXE=%s\\n' "$child_exe"
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
            inspect_out, inspect_err = b"", b"capture inspection timed out"
        logs["target-capture-inspect.stdout.log"].write_bytes(inspect_out)
        logs["target-capture-inspect.stderr.log"].write_bytes(inspect_err)
        for path in (logs["target-capture-inspect.stdout.log"], logs["target-capture-inspect.stderr.log"]):
            path.chmod(0o600)
        child_match = CAPTURE_CHILD_PID_MARKER.search(inspect_out)
        timeout_match = CAPTURE_TIMEOUT_EXE_MARKER.search(inspect_out)
        tcpdump_match = CAPTURE_TCPDUMP_EXE_MARKER.search(inspect_out)
        if (inspect_proc.returncode != 0 or child_match is None
                or timeout_match is None or tcpdump_match is None):
            raise RuntimeError("could not verify A timeout and tcpdump process executables")
        state["child_pid"] = int(child_match.group(1))
        state["supervisor_executable"] = timeout_match.group(1).decode()
        state["child_executable"] = tcpdump_match.group(1).decode()
        return state
    except Exception:
        state["cleanup"] = await cleanup_remote_capture(
            state["supervisor_pid"], state["child_pid"],
            logs["target-capture-cleanup.stdout.log"],
            logs["target-capture-cleanup.stderr.log"],
        )
        await stop_group(proc)
        try:
            await asyncio.wait_for(asyncio.gather(*state["_readers"], return_exceptions=True), 2)
        except asyncio.TimeoutError:
            for task in state["_readers"]:
                if not task.done():
                    task.cancel()
        raise


async def finish_target_capture(state, logs):
    if state is None:
        return None
    proc = state["_proc"]
    state["cleanup"] = await cleanup_remote_capture(
        state["supervisor_pid"], state["child_pid"],
        logs["target-capture-cleanup.stdout.log"],
        logs["target-capture-cleanup.stderr.log"],
    )
    if proc.returncode is None:
        try:
            await asyncio.wait_for(proc.wait(), 2)
        except asyncio.TimeoutError:
            await stop_group(proc)
    state["exit_code"] = proc.returncode
    state["stopped_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        await asyncio.wait_for(asyncio.gather(*state["_readers"]), 3)
    except asyncio.TimeoutError:
        for task in state["_readers"]:
            if not task.done():
                task.cancel()
        await asyncio.gather(*state["_readers"], return_exceptions=True)
    packet_lines = logs["target-capture.packets.log"].read_bytes().splitlines()
    udp_lines = [line for line in packet_lines if b"UDP," in line]
    state["packet_lines"] = len(udp_lines)
    state["udp_payload_length_1200_count"] = sum(
        bool(re.search(rb"UDP, length 1200(?:\s|$)", line)) for line in udp_lines
    )
    packets_by_tuple = {}
    for line in udp_lines:
        match = re.search(rb"\bIP\s+(\S+)\s+>\s+(\S+): UDP, length (\d+)", line)
        if match is None:
            continue
        source = match.group(1).decode(errors="replace")
        destination = match.group(2).decode(errors="replace")
        payload_len = match.group(3).decode()
        key = f"{source} -> {destination}"
        packet = packets_by_tuple.setdefault(key, {
            "source": source,
            "destination": destination,
            "packet_count": 0,
            "udp_payload_length_counts": {},
        })
        packet["packet_count"] += 1
        packet["udp_payload_length_counts"][payload_len] = (
            packet["udp_payload_length_counts"].get(payload_len, 0) + 1
        )
    state["udp_packets_by_tuple"] = list(packets_by_tuple.values())
    stderr = logs["target-capture.stderr.log"].read_text(errors="replace")
    for key, pattern in (
        ("captured", r"(\d+) packets captured"),
        ("received_by_filter", r"(\d+) packets received by filter"),
        ("dropped_by_kernel", r"(\d+) packets dropped by kernel"),
        ("dropped_by_interface", r"(\d+) packets? dropped by (?:the )?interface"),
    ):
        match = re.search(pattern, stderr)
        if match:
            state["statistics"][key] = int(match.group(1))
    state.pop("_proc", None)
    state.pop("_readers", None)
    return state


async def run(args):
    started = asyncio.get_running_loop().time()
    deadline = started + TIMEOUT_SECONDS
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    out_dir.chmod(0o700)
    os.umask(0o077)
    names = (
        "client.stdout.jsonl", "client.stderr.log", "target.stdout.jsonl", "target.stderr.log",
        "target-capture.packets.log", "target-capture.stderr.log",
        "target-capture-inspect.stdout.log", "target-capture-inspect.stderr.log",
        "target-capture-cleanup.stdout.log", "target-capture-cleanup.stderr.log",
        "remote-cleanup.stdout.log", "remote-cleanup.stderr.log",
    )
    logs = {name: out_dir / name for name in names}
    for path in logs.values():
        create_private_file(path)

    client_bin = Path(args.client_bin).expanduser().resolve()
    client_secret = Path(args.client_secret_file).expanduser().resolve()
    if not client_bin.is_file() or not os.access(client_bin, os.X_OK):
        raise ValueError("--client-bin must name an executable local helper")
    if not client_secret.is_file() or client_secret.stat().st_mode & 0o077:
        raise ValueError("--client-secret-file must name an existing private endpoint key file")
    if not args.target_bin.startswith("/"):
        raise ValueError("--target-bin must be an absolute helper path on target-1")
    if not args.target_secret_file.startswith("/"):
        raise ValueError("--target-secret-file must be an absolute endpoint key path on target-1")

    run_id = uuid.uuid4().hex
    sid = str(uuid.uuid4())
    pid_file = f"/tmp/kmesh-udp-birthday-{run_id}.pid"
    target_args = [
        args.target_bin, "--role", "target", "--ca-file", TARGET_CA,
        "--local-ip", TARGET_IP, "--endpoint-secret-key-file", args.target_secret_file,
    ]
    remote_command = f"""umask 077
pid=$$
printf '%s\\n' "$pid" > {shlex.quote(pid_file)}
printf 'KMESH_BIRTHDAY_REMOTE_PID=%s\\n' "$pid" >&2
exec {' '.join(shlex.quote(arg) for arg in target_args)}
"""

    queue, events = asyncio.Queue(), {"client": [], "target": []}
    procs, readers = {}, []
    remote_pid = {"pid": None}
    capture_state = None
    ready, raw_ready, raw_selected = {}, {}, {}
    native_ready, direct_selected, nonce_results, complete = {}, {}, {}, {}
    finished_roles = set()
    handoff_messages, connect_messages = {}, {}
    failure, last_phase, gate_data_open = None, "startup", False
    target_metadata = client_metadata = None
    selected_socket = None
    nonce_validation = None
    success = False
    cleanup = None
    capture_finish = None

    try:
        client_args = [
            str(client_bin), "--role", "client", "--ca-file", CLIENT_CA,
            "--local-ip", CLIENT_IP, "--endpoint-secret-key-file", str(client_secret),
        ]
        client = await asyncio.create_subprocess_exec(
            *client_args,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        procs["client"] = client
        target = await asyncio.create_subprocess_exec(
            *ssh_base(), HOST, "/bin/sh -c " + shlex.quote(remote_command),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        procs["target"] = target
        readers = [
            asyncio.create_task(collect_stdout(
                client.stdout, logs["client.stdout.jsonl"], "client", events, queue
            )),
            asyncio.create_task(collect_raw(client.stderr, logs["client.stderr.log"])),
            asyncio.create_task(collect_stdout(
                target.stdout, logs["target.stdout.jsonl"], "target", events, queue
            )),
            asyncio.create_task(collect_target_stderr(
                target.stderr, logs["target.stderr.log"], remote_pid
            )),
        ]

        last_phase = "ready"
        while len(ready) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] != "ready":
                continue
            if role in ready or event.get("role") != role:
                raise ValueError(f"{role} ready event has an invalid role or is repeated")
            ready[role] = event
        if ready["target"].get("endpoint_id") == ready["client"].get("endpoint_id"):
            raise ValueError("A and C endpoint IDs must be distinct")
        target_metadata = validate_qad_ready("target", ready["target"], TARGET_IP)
        client_metadata = validate_qad_ready("client", ready["client"], CLIENT_IP)

        paired = {
            "target": {
                "event": "paired",
                "sid": sid,
                "target_id": target_metadata["endpoint_id"],
                "client_id": client_metadata["endpoint_id"],
                "peer_local_socket": client_metadata["local_socket"],
                "peer_observations": client_metadata["observations"],
            },
            "client": {
                "event": "paired",
                "sid": sid,
                "target_id": target_metadata["endpoint_id"],
                "client_id": client_metadata["endpoint_id"],
                "peer_local_socket": target_metadata["local_socket"],
                "peer_observations": target_metadata["observations"],
            },
        }
        await send_json(target, paired["target"])
        await send_json(client, paired["client"])

        last_phase = "raw_ready"
        while len(raw_ready) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] != "raw_ready":
                continue
            sockets = event.get("sockets")
            expected_count = TARGET_SOCKET_COUNT if role == "target" else 1
            if event.get("role") != role or role in raw_ready:
                raise ValueError(f"{role} raw_ready event has an invalid role or is repeated")
            if not isinstance(sockets, list) or len(sockets) != expected_count:
                raise ValueError(f"{role} raw_ready must list exactly {expected_count} sockets")
            indices = [item.get("index") for item in sockets]
            if any(type(index) is not int for index in indices) or len(set(indices)) != len(indices):
                raise ValueError(f"{role} raw_ready indices must be unique integers")
            if role == "target" and set(indices) != set(range(TARGET_SOCKET_COUNT)):
                raise ValueError("A raw_ready indices must cover 0 through 256")
            if role == "client" and indices != [0]:
                raise ValueError("C raw_ready must expose only its single socket at index 0")
            socket_by_index = {}
            for item in sockets:
                local_socket = item.get("local_socket")
                ip, _ = parse_socket_address(local_socket, f"{role} raw_ready.local_socket")
                expected_ip = TARGET_IP if role == "target" else CLIENT_IP
                if ip.version != 4 or str(ip) != expected_ip:
                    raise ValueError(f"{role} raw_ready socket is not on its configured local interface")
                socket_by_index[item["index"]] = local_socket
            if len(set(socket_by_index.values())) != expected_count:
                raise ValueError(f"{role} raw_ready contains duplicate UDP socket tuples")
            raw_ready[role] = {**event, "socket_by_index": socket_by_index}
        if raw_ready["client"]["socket_by_index"][0] != client_metadata["local_socket"]:
            raise ValueError("C raw socket tuple changed from its original QAD socket")

        capture_state = await start_target_capture(ready["client"], logs, deadline)
        last_phase = "start_probe"
        await send_json(target, {"event": "start_probe"})
        if deadline - asyncio.get_running_loop().time() <= 1:
            raise TimeoutError("runner deadline elapsed before C raw probes could start")
        await asyncio.sleep(1)
        await send_json(client, {"event": "start_probe"})

        last_phase = "raw_selected"
        while len(raw_selected) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] != "raw_selected":
                continue
            if event.get("role") != role or role in raw_selected:
                raise ValueError(f"{role} raw_selected event has an invalid role or is repeated")
            raw_selected[role] = event
        a_selected_index = raw_selected["target"].get("index")
        selected_socket = selected_a_socket(raw_ready["target"], raw_selected["target"])
        if raw_selected["client"].get("index") != a_selected_index:
            raise ValueError("C raw_selected did not identify the A-selected socket index")
        if raw_selected["client"].get("local_socket") != client_metadata["local_socket"]:
            raise ValueError("C raw-selected tuple differs from its original QAD socket")
        handoff_messages = derive_handoff_messages(
            raw_selected["target"], raw_selected["client"], a_selected_index
        )
        await send_json(target, handoff_messages["target"])
        await send_json(client, handoff_messages["client"])

        last_phase = "native_ready"
        while len(native_ready) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] != "native_ready":
                continue
            if event.get("role") != role or role in native_ready:
                raise ValueError(f"{role} native_ready event has an invalid role or is repeated")
            expected_id = target_metadata["endpoint_id"] if role == "target" else client_metadata["endpoint_id"]
            selected_local_socket = raw_selected[role]["local_socket"]
            if event.get("endpoint_id") != expected_id:
                raise ValueError(f"{role} native endpoint ID changed during same-tuple handoff")
            if event.get("local_socket") != selected_local_socket:
                raise ValueError(f"{role} native endpoint did not retain its raw-selected tuple")
            if event.get("home_relay_url") != PRIVATE_RELAY_URL:
                raise ValueError(f"{role} native endpoint left the fixed private B relay")
            endpoint_addr = event.get("endpoint_addr")
            if not isinstance(endpoint_addr, dict) or endpoint_addr.get("id") != expected_id:
                raise ValueError(f"{role} native EndpointAddr identity mismatch")
            native_ready[role] = event

        connect_messages = {
            "target": {
                "event": "connect",
                "peer_endpoint_id": native_ready["client"]["endpoint_id"],
                "peer_endpoint_addr": native_ready["client"]["endpoint_addr"],
            },
            "client": {
                "event": "connect",
                "peer_endpoint_id": native_ready["target"]["endpoint_id"],
                "peer_endpoint_addr": native_ready["target"]["endpoint_addr"],
            },
        }
        last_phase = "connect"
        await send_json(target, connect_messages["target"])
        await send_json(client, connect_messages["client"])

        last_phase = "direct_selected"
        while len(direct_selected) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] != "direct_selected":
                continue
            if event.get("role") != role or role in direct_selected:
                raise ValueError(f"{role} direct_selected event has an invalid role or is repeated")
            path = event.get("selected_path")
            if (not isinstance(path, dict) or path.get("selected") is not True
                    or path.get("is_ip") is not True or path.get("is_ipv4") is not True):
                raise ValueError(f"{role} did not select a direct IPv4 QUIC path")
            direct_selected[role] = event
        last_phase = "go_data"
        await send_json(target, {"event": "go_data"})
        await send_json(client, {"event": "go_data"})

        last_phase = "nonce_and_fin"
        while len(nonce_results) < 2 or len(complete) < 2:
            role, event = await next_event(queue, deadline, finished_roles)
            if event["event"] == "nonce_result":
                if event.get("role") != role or role in nonce_results:
                    raise ValueError(f"{role} nonce_result event has an invalid role or is repeated")
                nonce_results[role] = event
            elif event["event"] == "complete":
                if event.get("role") != role or role in complete:
                    raise ValueError(f"{role} complete event has an invalid role or is repeated")
                if role not in nonce_results:
                    raise ValueError(f"{role} complete arrived before its nonce_result")
                if (event.get("endpoint_id") != native_ready[role]["endpoint_id"]
                        or event.get("same_tuple_reused") is not True
                        or event.get("nonce_echoes_match") is not True
                        or event.get("peer_nonces_echoed") is not True
                        or event.get("fin_complete") is not True
                        or event.get("peer_eof") is not True
                        or event.get("send_stopped_ok") is not True
                        or event.get("pass") is not True):
                    raise ValueError(f"{role} complete event failed the same-tuple nonce/FIN contract")
                complete[role] = event
                finished_roles.add(role)

        nonce_validation = validate_nonce_protocol(
            nonce_results, direct_selected, native_ready, complete
        )

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("runner deadline elapsed before helper cleanup")
        await asyncio.wait_for(asyncio.gather(client.wait(), target.wait()), remaining)
        await asyncio.wait_for(asyncio.gather(*readers), 3)
        if any(proc.returncode != 0 for proc in procs.values()):
            raise RuntimeError("one or more helper processes exited unsuccessfully")
        success = True
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
        await asyncio.gather(
            send_json(procs.get("target"), {"event": "abort"}),
            send_json(procs.get("client"), {"event": "abort"}),
            return_exceptions=True,
        )
    finally:
        helper_cleanup = asyncio.create_task(cleanup_remote_helper(
            pid_file, args.target_bin, remote_pid["pid"],
            logs["remote-cleanup.stdout.log"], logs["remote-cleanup.stderr.log"],
        ))
        if capture_state is not None:
            capture_finish = asyncio.create_task(finish_target_capture(capture_state, logs))
        await asyncio.gather(*(stop_group(proc) for proc in procs.values()), return_exceptions=True)
        if readers:
            try:
                await asyncio.wait_for(asyncio.gather(*readers, return_exceptions=True), 3)
            except asyncio.TimeoutError:
                for task in readers:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*readers, return_exceptions=True)
        try:
            cleanup = await helper_cleanup
        except Exception as error:
            cleanup = {"verified": False, "error": f"{type(error).__name__}: {error}"}
        if capture_finish is not None:
            try:
                capture_state = await capture_finish
            except Exception as error:
                capture_state["cleanup"] = {
                    "verified": False,
                    "error": f"{type(error).__name__}: {error}",
                }
    if failure is None and not cleanup["verified"]:
        failure = "RuntimeError: exact-PID remote helper cleanup did not verify"
        success = False
    if capture_state is not None and not capture_state.get("cleanup", {}).get("verified", False):
        if failure is None:
            failure = "RuntimeError: exact-PID A capture cleanup did not verify"
        success = False
    success = bool(
        success and failure is None and cleanup["verified"]
        and capture_state is not None
        and capture_state.get("started_utc") is not None
        and capture_state.get("cleanup", {}).get("verified") is True
        and set(ready) == {"target", "client"}
        and set(raw_ready) == {"target", "client"}
        and set(raw_selected) == {"target", "client"}
        and set(native_ready) == {"target", "client"}
        and set(direct_selected) == {"target", "client"}
        and set(nonce_results) == {"target", "client"}
        and set(complete) == {"target", "client"}
    )
    capture_info = None if capture_state is None else {
        key: value for key, value in capture_state.items()
        if not key.startswith("_")
    }
    summary = {
        "status": "passed" if success else "failed",
        "failure": failure,
        "last_phase": last_phase,
        "sid": sid,
        "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
        "fixed_b_relay_url": PRIVATE_RELAY_URL,
        "fixed_b_qad_addr": B_QAD_ADDR,
        "official_qad_udp_port": OFFICIAL_QAD_PORT,
        "client_executable": str(client_bin),
        "target_executable": args.target_bin,
        "client_helper_pid": procs["client"].pid if "client" in procs else None,
        "target_ssh_pid": procs["target"].pid if "target" in procs else None,
        "target_helper_pid": remote_pid["pid"],
        "ready": ready,
        "qad_validation": {"target": target_metadata, "client": client_metadata},
        "raw_ready": raw_ready,
        "raw_selected": raw_selected,
        "selected_target_socket_index": raw_selected.get("target", {}).get("index"),
        "selected_target_socket": selected_socket,
        "hand_off": handoff_messages,
        "native_ready": native_ready,
        "connect_gates": connect_messages,
        "direct_selected": direct_selected,
        "nonce_result": nonce_results,
        "nonce_validation": nonce_validation,
        "complete": complete,
        "helper_exit_codes": {role: proc.returncode for role, proc in procs.items()},
        "remote_cleanup": cleanup,
        "target_capture": capture_info,
        "events": events,
        "evidence_directory": str(out_dir),
        "raw_logs": {name: str(path) for name, path in logs.items()},
        "udp_payload_length_note": (
            "tcpdump UDP payload length is raw size evidence only; "
            "1200 bytes is not classified as a QUIC Initial packet."
        ),
    }
    summary_path = out_dir / "summary.json"
    create_private_file(summary_path)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-bin", required=True, help="local birthday helper executable")
    parser.add_argument("--target-bin", required=True, help="absolute birthday helper path on target-1")
    parser.add_argument("--client-secret-file", required=True, help="existing private C endpoint key file")
    parser.add_argument("--target-secret-file", required=True, help="existing private A endpoint key file on target-1")
    parser.add_argument("--out-dir", required=True, help="new private evidence directory")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
