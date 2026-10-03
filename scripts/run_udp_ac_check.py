#!/usr/bin/env python3
"""Run one coordinated Iroh UDP AC diagnostic round."""

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
CLIENT_IP = "10.0.0.6"
TARGET_IP = "10.0.0.4"
CLIENT_CA = "/Users/example/.cache/kmesh-live/server/ca.pem"
TARGET_CA = "/opt/kmesh-iroh-verification/ca.pem"
TIMEOUT = 60
LOG_FILTER = "warn,iroh::socket=trace"
PID_MARKER = re.compile(rb"KMESH_AC_REMOTE_PID=([0-9]+)")
CAPTURE_PID_MARKER = re.compile(rb"KMESH_AC_CAPTURE_PID=([0-9]+)")
CAPTURE_CHILD_PID_MARKER = re.compile(rb"KMESH_AC_CAPTURE_CHILD_PID=([0-9]+)")
CAPTURE_EXE_MARKER = re.compile(rb"KMESH_AC_CAPTURE_EXE=(/[^\r\n]+)")
CAPTURE_CHILD_EXE_MARKER = re.compile(rb"KMESH_AC_CAPTURE_CHILD_EXE=(/[^\r\n]+)")


def create_private_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def parse_event(line):
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and isinstance(value.get("event"), str) else None


async def collect(reader, path, role, events, queue=None, remote_pid=None):
    with path.open("ab") as output:
        while line := await reader.readline():
            output.write(line)
            output.flush()
            if remote_pid is not None:
                match = PID_MARKER.search(line)
                if match:
                    remote_pid["pid"] = int(match.group(1))
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
    remote_command = f"""umask 077
pid=$$
printf '%s\\n' \"$pid\" > {shlex.quote(pid_file)}
printf 'KMESH_AC_REMOTE_PID=%s\\n' \"$pid\" >&2
export RUST_LOG={shlex.quote(LOG_FILTER)}
exec {' '.join(shlex.quote(arg) for arg in target_args)}
"""
    queue, events = asyncio.Queue(), {"client": [], "target": []}
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
        "statistics": {},
        "stdout": str(logs["target-capture.packets.log"]),
        "stderr": str(logs["target-capture.stderr.log"]),
    }
    ready, direct, failure = {}, {}, None
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
            asyncio.create_task(collect(client.stderr, logs["client.stderr.log"], "client", events["client"])),
            asyncio.create_task(collect(target.stdout, logs["target.stdout.jsonl"], "target", events["target"], queue)),
            asyncio.create_task(collect(target.stderr, logs["target.stderr.log"], "target", events["target"], remote_pid=remote_pid)),
        ]

        while len(ready) < 2:
            role, event = await next_event(queue, deadline)
            if event["event"] == "ready":
                ready[role] = event

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
        await send_json(client, ready["target"])
        await send_json(target, ready["client"])

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
            tx_packets = tx_bytes = rx_packets = rx_bytes = 0
            for line in ip_packet_lines:
                payload = re.search(rb"length (\d+)", line)
                byte_count = int(payload.group(1)) if payload else 0
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
    success = (
        failure is None
        and set(procs) == {"client", "target"}
        and all(proc.returncode == 0 for proc in procs.values())
        and all(event is not None and event.get("pass") is True for event in nonce_events.values())
        and all(event is not None and event.get("pass") is True for event in complete.values())
        and cleanup["verified"]
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
        "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
        "local_client_pid": procs["client"].pid if "client" in procs else None,
        "target_ssh_pid": procs["target"].pid if "target" in procs else None,
        "target_helper_pid": remote_pid["pid"] or cleanup["cleaned_pid"],
        "target_executable": args.target_bin,
        "ready": ready,
        "direct_selected": direct,
        "nonce_result": nonce_events,
        "complete": complete,
        "exit_codes": {role: proc.returncode for role, proc in procs.items()},
        "remote_cleanup": cleanup,
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
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
