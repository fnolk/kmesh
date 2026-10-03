#!/usr/bin/env python3
"""Run one coordinated Iroh UDP AC diagnostic round."""

import argparse
import asyncio
import json
import os
import re
import shlex
import signal
import uuid
from pathlib import Path

HOST = "target-1"
CLIENT_IP = "10.0.0.6"
TARGET_IP = "10.0.0.4"
CLIENT_CA = "/Users/example/.cache/kmesh-live/server/ca.pem"
TARGET_CA = "/opt/kmesh-iroh-verification/ca.pem"
TIMEOUT = 60
PID_MARKER = re.compile(rb"KMESH_AC_REMOTE_PID=([0-9]+)")


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
    )}
    for path in logs.values():
        create_private_file(path)

    client_bin = Path(args.client_bin).expanduser().resolve()
    if not client_bin.is_file() or not os.access(client_bin, os.X_OK):
        raise ValueError("--client-bin must name an executable local file")
    if not args.target_bin.startswith("/"):
        raise ValueError("--target-bin must be an absolute path on target-1")

    run_id = uuid.uuid4().hex
    pid_file = f"/tmp/kmesh-udp-ac-{run_id}.pid"
    remote_command = f"""umask 077
pid=$$
printf '%s\\n' \"$pid\" > {shlex.quote(pid_file)}
printf 'KMESH_AC_REMOTE_PID=%s\\n' \"$pid\" >&2
exec {shlex.quote(args.target_bin)} --role target --local-ip {TARGET_IP} --ca-file {TARGET_CA}
"""
    queue, events = asyncio.Queue(), {"client": [], "target": []}
    remote_pid, procs, readers = {"pid": None}, {}, []
    ready, direct, failure = {}, {}, None
    gate_sent = False

    try:
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("runner deadline elapsed before start")
        client = await asyncio.create_subprocess_exec(
            str(client_bin), "--role", "client", "--local-ip", CLIENT_IP,
            "--ca-file", CLIENT_CA, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
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
    )
    summary = {
        "status": "passed" if success else "failed",
        "failure": failure,
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
    parser.add_argument("--out-dir", required=True, help="new private evidence directory")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
