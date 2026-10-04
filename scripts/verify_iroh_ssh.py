#!/usr/bin/env python3
"""Run bounded OpenSSH, file-transfer, forwarding, mux, host-key, and RBAC checks."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import select
import secrets
import signal
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

COMMAND_TIMEOUT = 15
SSH_CONNECT_TIMEOUT_SECONDS = 65
SSH_NEW_CONNECTION_TIMEOUT_SECONDS = SSH_CONNECT_TIMEOUT_SECONDS + COMMAND_TIMEOUT
PATH_EVENT = re.compile(r"连接路径(切换)?：(P2P 直连|Iroh 中继) \(([^)]+)\)")


class VerificationError(RuntimeError):
    pass


class Verification:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.started = dt.datetime.now(dt.timezone.utc)
        args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(args.evidence_dir, 0o700)
        run_id = f"ssh-{args.mode}-{self.started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        self.run_dir = args.evidence_dir / run_id
        self.run_dir.mkdir(mode=0o700)
        self.report_path = self.run_dir / "report.json"
        self.proxy_dir = self.run_dir / "bin"
        self.proxy_dir.mkdir(mode=0o700)
        self.proxy_calls = self.run_dir / "proxy-calls.log"
        self.proxy_pids = self.run_dir / "proxy-pids.log"
        self.path_log = self.run_dir / "path-events.log"
        self.master_log = self.run_dir / "control-master.log"
        self.socket_dir = tempfile.TemporaryDirectory(prefix="kmesh-mux-", dir="/tmp")
        self.master_socket = Path(self.socket_dir.name) / "c"
        self.proxy_calls.touch(mode=0o600)
        self.proxy_pids.touch(mode=0o600)
        self.path_log.touch(mode=0o600)
        self.report: dict[str, Any] = {
            "run_id": run_id,
            "started_utc": self.started.isoformat(),
            "mode": args.mode,
            "alias": args.alias,
            "role_id": str(args.role_id),
            "target_id": str(args.target_id),
            "client_binary": str(args.client_binary),
            "steps": [],
        }
        deployment_file = args.admin_config.parent / "deployment.json"
        if deployment_file.is_file() and stat.S_IMODE(deployment_file.stat().st_mode) == 0o600:
            deployment = json.loads(deployment_file.read_text())
            self.report["source_revision"] = deployment.get("artifact_revision")
            self.report["client_binary_sha256"] = hashlib.sha256(args.client_binary.read_bytes()).hexdigest()
            self.report["server_agent_binary_sha256"] = deployment.get("server_agent_binary_sha256")
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.proxy_dir) + os.pathsep + self.env.get("PATH", "")
        self.env["KMESH_REAL_BINARY"] = str(args.client_binary)
        self.env["KMESH_PROXY_COUNT_FILE"] = str(self.proxy_calls)
        self.env["KMESH_PROXY_PID_FILE"] = str(self.proxy_pids)
        self.env["KMESH_PATH_LOG_FILE"] = str(self.path_log)
        self.proxy_command: list[str] = []
        self.master: subprocess.Popen[bytes] | None = None
        self.master_log_handle: Any = None
        self.remote_file: str | None = None
        self.forward: str | None = None
        self.revocation_attempted = False
        self.target_disable_attempted = False
        self.logout_restore: tuple[str, bytes] | None = None
        self.cleanup_errors: list[str] = []
        self.host_key_alias = ""
        self.known_hosts = Path()
        self.proxy_rss_peak_kb = 0
        self.proxy_rss_samples = 0

    def write_report(self) -> None:
        self.report["updated_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        temp_path = self.report_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(self.report, indent=2, ensure_ascii=False) + "\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, self.report_path)
        os.chmod(self.report_path, 0o600)

    def record(
        self,
        label: str,
        status: str,
        *,
        exit_code: int | None = None,
        elapsed_ms: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        step: dict[str, Any] = {"label": label, "status": status, "exit_code": exit_code}
        if elapsed_ms is not None:
            step["elapsed_ms"] = elapsed_ms
        if details:
            step.update(details)
        self.report["steps"].append(step)
        self.write_report()

    def run(
        self,
        label: str,
        argv: list[str],
        *,
        timeout: float = COMMAND_TIMEOUT,
        accepted: tuple[int, ...] | None = (0,),
        env: dict[str, str] | None = None,
        input_data: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        started = time.monotonic()
        merged_env = self.env.copy()
        if env:
            merged_env.update(env)
        try:
            result = subprocess.run(
                argv,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=merged_env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            self.record(label, "timeout", elapsed_ms=round((time.monotonic() - started) * 1000))
            raise VerificationError(f"{label} exceeded {timeout:g} seconds") from error
        status = (
            "observed"
            if accepted is None
            else "passed"
            if result.returncode in accepted
            else "failed"
        )
        self.record(label, status, exit_code=result.returncode, elapsed_ms=round((time.monotonic() - started) * 1000))
        if status == "failed":
            raise VerificationError(f"{label} exited with status {result.returncode}")
        return result

    def proxy_count(self) -> int:
        return len(self.proxy_calls.read_text().splitlines())

    def record_proxy_count(self, expected: int, label: str) -> None:
        observed = self.proxy_count()
        status = "passed" if observed == expected else "failed"
        self.record(label, status, details={"expected_proxy_invocations": expected, "observed_proxy_invocations": observed})
        if status == "failed":
            raise VerificationError(f"{label}: expected {expected} kmesh proxy starts, observed {observed}")

    def sample_proxy_rss(self) -> None:
        for raw_pid in self.proxy_pids.read_text().splitlines():
            if not raw_pid.isdigit():
                continue
            sample = subprocess.run(
                ["ps", "-o", "rss=", "-p", raw_pid],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
                text=True,
            )
            value = sample.stdout.strip()
            if sample.returncode == 0 and value.isdigit():
                self.proxy_rss_peak_kb = max(self.proxy_rss_peak_kb, int(value))
                self.proxy_rss_samples += 1

    def wait_ssh_processes(
        self,
        label: str,
        processes: list[subprocess.Popen[bytes]],
        timeout: float,
    ) -> list[tuple[int, bytes, bytes]]:
        deadline = time.monotonic() + timeout
        while any(process.poll() is None for process in processes):
            self.sample_proxy_rss()
            if time.monotonic() >= deadline:
                for process in processes:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                for process in processes:
                    process.communicate()
                self.record(label, "timeout")
                raise VerificationError(f"{label} exceeded {timeout:g} seconds")
            time.sleep(0.1)
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=2)
            results.append((process.returncode, stdout, stderr))
        self.sample_proxy_rss()
        return results

    def verify_short_stream_interactions(self) -> None:
        self.sample_proxy_rss()
        idle = subprocess.Popen(
            self.ssh_base(multiplex=True) + ["sh -c 'sleep 5; printf kmesh-idle-complete'"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            start_new_session=True,
        )
        idle_result = self.wait_ssh_processes("five-second-idle-stream", [idle], 10)[0]
        if idle_result[0] != 0 or b"kmesh-idle-complete" not in idle_result[1]:
            raise VerificationError("five-second active SSH stream did not finish after idle")
        self.record("five-second-idle-stream", "passed", exit_code=idle_result[0])

        commands = [
            ("left", "sh -c 'sleep 2; printf kmesh-concurrent-left'"),
            ("right", "sh -c 'sleep 2; printf kmesh-concurrent-right'"),
        ]
        processes = [
            subprocess.Popen(
                self.ssh_base(multiplex=True) + [command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
                start_new_session=True,
            )
            for _, command in commands
        ]
        concurrent_results = self.wait_ssh_processes("concurrent-short-ssh-channels", processes, 10)
        for (name, _command), (returncode, stdout, _stderr) in zip(commands, concurrent_results):
            if returncode != 0 or f"kmesh-concurrent-{name}".encode() not in stdout:
                raise VerificationError(f"concurrent SSH channel {name} did not finish successfully")
        self.record(
            "concurrent-short-ssh-channels",
            "passed",
            details={"channels": len(commands)},
        )

        cancelled = subprocess.Popen(
            self.ssh_base(multiplex=True)
            + [
                "printf '%s\\n' kmesh-cancel-started; sleep 5; "
                "printf '%s\\n' kmesh-cancelled-command-complete"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            start_new_session=True,
        )
        if not select.select([cancelled.stdout], [], [], 5)[0]:
            try:
                os.killpg(cancelled.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cancelled.communicate(timeout=2)
            raise VerificationError("cancel-test SSH channel never reached its active remote command")
        started_marker = cancelled.stdout.readline().strip()
        if started_marker != b"kmesh-cancel-started":
            try:
                os.killpg(cancelled.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cancelled.communicate(timeout=2)
            raise VerificationError("cancel-test SSH channel did not report its active marker")
        time.sleep(1)
        try:
            os.killpg(cancelled.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            cancel_stdout, _cancel_stderr = cancelled.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(cancelled.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cancel_stdout, _cancel_stderr = cancelled.communicate(timeout=2)
            raise VerificationError("cancelled SSH command process group did not exit")
        if cancelled.returncode == 0 and b"kmesh-cancelled-command-complete" in cancel_stdout:
            raise VerificationError("cancelled SSH command unexpectedly completed")
        after_cancel = self.run(
            "control-master-survives-channel-cancel",
            self.ssh_base(multiplex=True) + ["hostname"],
            timeout=5,
        )
        if not after_cancel.stdout.strip():
            raise VerificationError("ControlMaster stopped responding after channel cancellation")
        self.record_proxy_count(3, "short-interactions-reuse-one-control-master")
        self.report["short_stream_interactions"] = {
            "idle_seconds": 5,
            "concurrent_channels": len(commands),
            "cancelled_channel_process_exit": cancelled.returncode,
            "control_master_alive_after_cancel": True,
            "proxy_rss_peak_kb": self.proxy_rss_peak_kb or None,
            "proxy_rss_samples": self.proxy_rss_samples,
        }
        self.write_report()

    def ssh_base(self, *, multiplex: bool) -> list[str]:
        args = [
            "ssh",
            "-F",
            str(self.args.ssh_config),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
            "-o",
            "ConnectionAttempts=1",
        ]
        if multiplex:
            args.extend(["-S", str(self.master_socket)])
        else:
            args.extend(["-S", "none", "-o", "ControlMaster=no", "-o", "ControlPath=none"])
        args.append(self.args.alias)
        return args

    def prepare_proxy_shim(self) -> None:
        shim = self.proxy_dir / "kmesh"
        shim.write_text(
            "#!/bin/sh\n"
            "printf 'start\\n' >> \"$KMESH_PROXY_COUNT_FILE\"\n"
            "printf '[proxy-start]\\n' >> \"$KMESH_PATH_LOG_FILE\"\n"
            "printf '%s\\n' \"$$\" >> \"$KMESH_PROXY_PID_FILE\"\n"
            "exec \"$KMESH_REAL_BINARY\" \"$@\" 2>>\"$KMESH_PATH_LOG_FILE\"\n"
        )
        os.chmod(shim, 0o700)
        config = self.run(
            "read-effective-ssh-config",
            ["ssh", "-G", "-F", str(self.args.ssh_config), self.args.alias],
            timeout=5,
        ).stdout.decode("utf-8", "replace")
        fields = dict(line.split(" ", 1) for line in config.splitlines() if " " in line)
        proxy = shlex.split(fields.get("proxycommand", ""))
        if not proxy or proxy[0] != "kmesh":
            raise VerificationError("SSH config ProxyCommand must resolve through the kmesh CLI name")
        self.proxy_command = proxy
        self.host_key_alias = fields.get("hostkeyalias", "")
        expected_alias = f"kmesh/{self.args.target_id}"
        if self.host_key_alias != expected_alias:
            raise VerificationError("SSH HostKeyAlias does not match the supplied target UUID")
        known_hosts_candidates = shlex.split(fields.get("userknownhostsfile", ""))
        self.known_hosts = next(
            (Path(value).expanduser() for value in known_hosts_candidates if Path(value).expanduser().is_file()),
            Path(),
        )
        if not self.known_hosts.is_file():
            raise VerificationError("SSH config has no readable UserKnownHostsFile for strict host-key checks")
        if len(os.fsencode(self.master_socket)) >= 100:
            raise VerificationError("evidence path is too long for an OpenSSH control socket")
        self.report["ssh_config"] = str(self.args.ssh_config)
        self.report["known_hosts_alias"] = self.host_key_alias
        self.write_report()

    def start_master(self) -> None:
        if self.master_socket.exists():
            raise VerificationError("isolated ControlMaster socket already exists")
        self.master_log_handle = self.master_log.open("ab")
        argv = [
            "ssh",
            "-F",
            str(self.args.ssh_config),
            "-S",
            str(self.master_socket),
            "-o",
            "ControlPersist=no",
            "-M",
            "-N",
            self.args.alias,
        ]
        self.master = subprocess.Popen(
            argv,
            stdout=self.master_log_handle,
            stderr=self.master_log_handle,
            env=self.env,
            start_new_session=True,
        )
        deadline = time.monotonic() + SSH_NEW_CONNECTION_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.master.poll() is not None:
                raise VerificationError("ControlMaster exited before becoming ready")
            check = subprocess.run(
                [
                    "ssh",
                    "-F",
                    str(self.args.ssh_config),
                    "-S",
                    str(self.master_socket),
                    "-O",
                    "check",
                    self.args.alias,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env,
                timeout=2,
                check=False,
            )
            if check.returncode == 0:
                self.record("start-control-master", "passed", details={"proxy_invocations": self.proxy_count()})
                return
            time.sleep(0.1)
        raise VerificationError("ControlMaster did not become ready within 15 seconds")

    def close_master(self) -> None:
        if self.master is not None and self.master.poll() is None:
            result = subprocess.run(
                [
                    "ssh",
                    "-F",
                    str(self.args.ssh_config),
                    "-S",
                    str(self.master_socket),
                    "-O",
                    "exit",
                    self.args.alias,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env,
                timeout=5,
                check=False,
            )
            self.record("close-control-master", "passed" if result.returncode == 0 else "observed", exit_code=result.returncode)
            try:
                self.master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.master.terminate()
                self.master.wait(timeout=3)
        if self.master_log_handle is not None:
            self.master_log_handle.close()
            self.master_log_handle = None
        self.master = None

    def read_path_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        attempt = 0
        for line in self.path_log.read_text(errors="replace").splitlines():
            if line == "[proxy-start]":
                attempt += 1
                continue
            match = PATH_EVENT.search(line)
            if match:
                label = match.group(2)
                events.append(
                    {
                        "sequence": len(events) + 1,
                        "proxy_attempt": attempt,
                        "kind": "direct" if label == "P2P 直连" else "relay",
                        "label": label,
                        "remote_address": match.group(3),
                        "event": "path-change" if match.group(1) else "selected",
                    }
                )
        return events

    def save_path_events(self) -> list[dict[str, Any]]:
        events = self.read_path_events()
        self.report["path_events"] = events
        self.report["observed_direct"] = any(event["kind"] == "direct" for event in events)
        self.report["final_path_event"] = events[-1] if events else None
        self.write_report()
        return events

    def admin(self, label: str, *subcommand: str) -> dict[str, Any]:
        result = self.run(
            label,
            [
                str(self.args.client_binary),
                "--config",
                str(self.args.admin_config),
                "--profile",
                "admin",
                "admin",
                *subcommand,
                "--json",
            ],
        )
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise VerificationError(f"{label} returned invalid JSON") from error
        return response

    def grant_exists(self) -> bool:
        response = self.admin("list-role-grants", "grants", "list", str(self.args.role_id))
        if response.get("result") != "grants" or not isinstance(response.get("data"), list):
            raise VerificationError("admin grants list returned an unexpected response")
        return any(
            item.get("role_id") == str(self.args.role_id)
            and item.get("target_id") == str(self.args.target_id)
            and item.get("permission") == "ssh_connect"
            for item in response["data"]
        )

    def verify_basic_ssh(self) -> None:
        result = self.run(
            "hostname-and-exit-23",
            self.ssh_base(multiplex=False) + ["hostname; exit 23"],
            timeout=SSH_NEW_CONNECTION_TIMEOUT_SECONDS,
            accepted=(23,),
        )
        hostname = result.stdout.decode("utf-8", "replace").strip()
        if not hostname:
            raise VerificationError("hostname command returned no output")
        self.report["hostname"] = hostname
        self.report["exit_23"] = result.returncode
        self.write_report()
        self.record_proxy_count(1, "first-proxy-start-count")

    def verify_path_probe(self) -> None:
        attempt = self.proxy_count() + 1
        result = self.run(
            "eight-second-path-observation",
            self.ssh_base(multiplex=False)
            + ["hostname; sleep 8; echo kmesh-path-probe-complete"],
            timeout=SSH_NEW_CONNECTION_TIMEOUT_SECONDS,
        )
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        if not lines or not any(line.strip() == "kmesh-path-probe-complete" for line in lines):
            raise VerificationError("8-second path probe did not return hostname and completion marker")
        events = self.save_path_events()
        probe_events = [event for event in events if event["proxy_attempt"] == attempt]
        self.report["path_probe"] = {
            "duration_seconds": 8,
            "hostname": lines[0].strip(),
            "completion_marker": True,
            "path_events": probe_events,
            "observed_direct": any(event["kind"] == "direct" for event in probe_events),
            "final_path_event": probe_events[-1] if probe_events else None,
        }
        self.write_report()
        self.record_proxy_count(2, "two-fresh-proxy-start-count")

    def verify_control_master(self) -> None:
        self.start_master()
        hostname = self.run("control-master-hostname", self.ssh_base(multiplex=True) + ["hostname"])
        if not hostname.stdout.strip():
            raise VerificationError("ControlMaster hostname returned no output")
        exit_23 = self.run(
            "control-master-exit-23",
            self.ssh_base(multiplex=True) + ["sh -c 'exit 23'"],
            accepted=(23,),
        )
        self.report["control_master"] = {
            "hostname": hostname.stdout.decode("utf-8", "replace").strip(),
            "second_command_exit": exit_23.returncode,
        }
        self.write_report()
        self.record_proxy_count(3, "control-master-reuses-one-proxy")

    def verify_file_transfer(self) -> None:
        source = self.run_dir / "scp-sftp-source.bin"
        downloaded = self.run_dir / "scp-sftp-roundtrip.bin"
        data = secrets.token_bytes(1024 * 1024)
        source.write_bytes(data)
        os.chmod(source, 0o600)
        expected_hash = hashlib.sha256(data).hexdigest()
        self.remote_file = f"/tmp/kmesh-ssh-verify-{uuid.uuid4().hex}.bin"
        scp = [
            "scp",
            "-F",
            str(self.args.ssh_config),
            "-o",
            f"ControlPath={self.master_socket}",
            "-o",
            "ControlMaster=auto",
            str(source),
            f"{self.args.alias}:{self.remote_file}",
        ]
        self.run("scp-upload-1mib", scp)
        batch = self.run_dir / "sftp-get.batch"
        batch.write_text(f'get "{self.remote_file}" "{downloaded}"\n')
        os.chmod(batch, 0o600)
        self.run(
            "sftp-download-1mib",
            [
                "sftp",
                "-F",
                str(self.args.ssh_config),
                "-o",
                f"ControlPath={self.master_socket}",
                "-o",
                "ControlMaster=auto",
                "-b",
                str(batch),
                self.args.alias,
            ],
        )
        observed_hash = hashlib.sha256(downloaded.read_bytes()).hexdigest()
        self.report["file_roundtrip"] = {
            "bytes": len(data),
            "sha256": expected_hash,
            "roundtrip_sha256": observed_hash,
            "match": expected_hash == observed_hash,
            "upload": "scp",
            "download": "sftp",
        }
        self.write_report()
        if observed_hash != expected_hash:
            raise VerificationError("1 MiB SCP/SFTP round-trip SHA-256 mismatch")
        self.record_proxy_count(3, "file-transfers-reuse-control-master")

    def verify_forward(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.forward = f"127.0.0.1:{port}:127.0.0.1:22"
        self.run(
            "request-local-ssh-banner-forward",
            [
                "ssh",
                "-F",
                str(self.args.ssh_config),
                "-S",
                str(self.master_socket),
                "-O",
                "forward",
                "-L",
                self.forward,
                self.args.alias,
            ],
        )
        with socket.create_connection(("127.0.0.1", port), timeout=3) as forwarded:
            forwarded.settimeout(3)
            banner = forwarded.recv(512).decode("ascii", "replace").strip()
        if not banner.startswith(("SSH-2.0-", "SSH-1.99-")):
            raise VerificationError("local -L forward did not return an SSH banner")
        self.report["local_forward"] = {
            "destination": "127.0.0.1:22",
            "banner": banner,
        }
        self.write_report()
        self.cancel_forward()
        self.record_proxy_count(3, "local-forward-reuses-control-master")

    def cancel_forward(self) -> None:
        if self.forward is None or self.master is None or self.master.poll() is not None:
            return
        result = subprocess.run(
            [
                "ssh",
                "-F",
                str(self.args.ssh_config),
                "-S",
                str(self.master_socket),
                "-O",
                "cancel",
                "-L",
                self.forward,
                self.args.alias,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.env,
            timeout=5,
            check=False,
        )
        self.record("cancel-local-forward", "passed" if result.returncode == 0 else "observed", exit_code=result.returncode)
        if result.returncode != 0:
            raise VerificationError("could not cancel the temporary local SSH forward")
        self.forward = None

    def wrong_known_hosts(self) -> Path:
        host_keys = self.run(
            "read-configured-public-host-key",
            ["ssh-keygen", "-F", self.host_key_alias, "-f", str(self.known_hosts)],
            accepted=(0,),
            timeout=5,
        ).stdout.decode("utf-8", "replace")
        known_key: tuple[str, str] | None = None
        for line in host_keys.splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            index = 1 if fields and fields[0].startswith("@") else 0
            if len(fields) >= index + 3:
                known_key = (fields[index + 1], fields[index + 2])
                break
        if known_key is None:
            raise VerificationError("could not read the configured public host-key entry")
        algorithm, _key_blob = known_key
        key_types = {
            "ssh-ed25519": ["-t", "ed25519"],
            "ssh-rsa": ["-t", "rsa", "-b", "2048"],
            "ecdsa-sha2-nistp256": ["-t", "ecdsa", "-b", "256"],
            "ecdsa-sha2-nistp384": ["-t", "ecdsa", "-b", "384"],
            "ecdsa-sha2-nistp521": ["-t", "ecdsa", "-b", "521"],
        }
        if algorithm not in key_types:
            raise VerificationError(f"unsupported host-key type for a mismatch check: {algorithm}")
        private_path = self.run_dir / "wrong-host-key"
        self.run(
            "generate-local-wrong-host-key",
            ["ssh-keygen", "-q", *key_types[algorithm], "-N", "", "-f", str(private_path)],
            timeout=10,
        )
        public_fields = Path(f"{private_path}.pub").read_text().split()
        wrong_known_hosts = self.run_dir / "wrong_known_hosts"
        wrong_known_hosts.write_text(f"{self.host_key_alias} {public_fields[0]} {public_fields[1]} local-test-only\n")
        os.chmod(wrong_known_hosts, 0o600)
        self.report["wrong_key"] = {"host_key_algorithm": algorithm, "private_key_stays_local": True}
        self.write_report()
        return wrong_known_hosts

    def verify_host_key_rejection(self) -> None:
        wrong_hosts = self.wrong_known_hosts()
        command = self.ssh_base(multiplex=False)
        alias_index = command.index(self.args.alias)
        command[alias_index:alias_index] = [
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={wrong_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"HostKeyAlias={self.host_key_alias}",
        ]
        command.append("true")
        result = self.run(
            "strict-host-key-rejects-wrong-key",
            command,
            timeout=SSH_NEW_CONNECTION_TIMEOUT_SECONDS,
            accepted=None,
        )
        text = (result.stderr + result.stdout).decode("utf-8", "replace").lower()
        if result.returncode == 0 or not any(
            phrase in text
            for phrase in (
                "host key verification failed",
                "remote host identification has changed",
                "offending ",
            )
        ):
            raise VerificationError("wrong host key was not rejected by strict SSH host-key checking")
        self.record("assert-strict-host-key-rejection", "passed", details={"rejected": True})
        self.report["wrong_key"]["rejected"] = True
        self.write_report()
        private_key = self.run_dir / "wrong-host-key"
        private_key.unlink(missing_ok=True)
        Path(f"{private_key}.pub").unlink(missing_ok=True)
        self.record_proxy_count(4, "wrong-host-key-used-fresh-proxy")

    def verify_revoke_boundary(self) -> None:
        if not self.grant_exists():
            raise VerificationError("the supplied role has no ssh_connect grant for the target")
        self.revocation_attempted = True
        self.admin("revoke-target-grant", "grants", "remove", str(self.args.role_id), str(self.args.target_id))
        if self.grant_exists():
            raise VerificationError("admin revoke command returned but the target grant remains")
        existing = self.run("active-control-master-survives-revoke", self.ssh_base(multiplex=True) + ["hostname"])
        active_hostname = existing.stdout.decode("utf-8", "replace").strip()
        if not active_hostname:
            raise VerificationError("active ControlMaster returned no hostname after revoke")
        self.report["active_after_revoke_hostname"] = active_hostname
        self.write_report()
        denied_command = self.ssh_base(multiplex=False) + ["true"]
        denied = self.run("new-connection-after-revoke", denied_command, accepted=None)
        path_text = self.path_log.read_text(errors="replace")
        latest_attempt = path_text.rsplit("[proxy-start]", 1)[-1].lower()
        denied_text = (denied.stderr + denied.stdout).decode("utf-8", "replace").lower() + latest_attempt
        if denied.returncode == 0 or not any(
            phrase in denied_text for phrase in ("forbidden", "operation is not permitted", "authorization")
        ):
            raise VerificationError("a new SSH connection did not show the expected authorization denial")
        self.report["new_connection_after_revoke"] = {
            "denied": True,
            "reason": "kmesh authorization",
        }
        self.write_report()
        self.record("assert-new-connection-authorization-denied", "passed", details={"denied": True})
        self.record_proxy_count(5, "revoked-new-connection-used-fresh-proxy")

    def restore_grant(self) -> None:
        if not self.revocation_attempted:
            return
        if not self.grant_exists():
            self.admin("restore-target-grant", "grants", "add", str(self.args.role_id), str(self.args.target_id))
        if not self.grant_exists():
            raise VerificationError("could not restore the original ssh_connect grant")
        self.record("restore-original-target-grant", "passed")

    def target_enabled(self) -> bool:
        response = self.admin("list-verification-targets", "targets", "list")
        if response.get("result") != "targets" or not isinstance(response.get("data"), list):
            raise VerificationError("admin targets list returned an unexpected response")
        target = next(
            (item for item in response["data"] if item.get("target_id") == str(self.args.target_id)),
            None,
        )
        if target is None or not isinstance(target.get("enabled"), bool):
            raise VerificationError("verification target state is missing from targets list")
        return target["enabled"]

    def restore_target(self) -> None:
        if not self.target_disable_attempted:
            return
        if not self.target_enabled():
            self.admin(
                "restore-verification-target",
                "targets",
                "enable",
                str(self.args.target_id),
            )
        if not self.target_enabled():
            raise VerificationError("could not restore the target's enabled state")
        self.target_disable_attempted = False
        self.record("restore-verification-target", "passed")

    def verify_target_disable_boundary(self) -> None:
        if not self.grant_exists() or not self.target_enabled():
            raise VerificationError("target disable check requires its original enabled ssh_connect grant")
        self.target_disable_attempted = True
        try:
            self.admin(
                "disable-verification-target",
                "targets",
                "disable",
                str(self.args.target_id),
            )
            if self.target_enabled():
                raise VerificationError("admin disable command left the target enabled")
            active = self.run(
                "active-control-master-survives-target-disable",
                self.ssh_base(multiplex=True) + ["hostname"],
                timeout=5,
            )
            if not active.stdout.strip():
                raise VerificationError("active ControlMaster stopped responding after target disable")
            denied = self.run(
                "new-transport-after-target-disable",
                self.ssh_base(multiplex=False) + ["true"],
                accepted=None,
            )
            denial = (denied.stderr + denied.stdout).decode("utf-8", "replace").lower()
            attempt_log = self.path_log.read_text(errors="replace").rsplit("[proxy-start]", 1)[-1].lower()
            if denied.returncode == 0 or not any(
                phrase in denial + attempt_log
                for phrase in ("not enrolled", "target is offline", "not found", "disabled")
            ):
                raise VerificationError("new transport did not report the disabled target")
            self.report["target_disable_boundary"] = {
                "active_control_master_continued": True,
                "new_transport_denied": True,
                "reason": "target disabled",
            }
            self.write_report()
            self.record("assert-target-disable-boundary", "passed")
        finally:
            self.restore_target()

    def verification_user_password(self) -> tuple[str, bytes]:
        deployment_file = self.args.admin_config.parent / "deployment.json"
        if not deployment_file.is_file() or stat.S_IMODE(deployment_file.stat().st_mode) != 0o600:
            raise VerificationError("protected verification deployment state is missing")
        deployment = json.loads(deployment_file.read_text())
        username = deployment.get("username")
        password_file = deployment.get("user_password_file")
        if not isinstance(username, str) or not username or not isinstance(password_file, str) or not password_file:
            raise VerificationError("verification user credentials are unavailable")
        password_path = Path(password_file)
        if not password_path.is_file():
            raise VerificationError("verification user password file is missing")
        if stat.S_IMODE(password_path.stat().st_mode) != 0o600:
            raise VerificationError("verification password file is not owner-only")
        return username, password_path.read_bytes()

    def verification_user_cli(self, *command: str) -> list[str]:
        if (
            len(self.proxy_command) < 3
            or self.proxy_command[-2] != "proxy"
            or self.proxy_command[-1] != str(self.args.target_id)
        ):
            raise VerificationError("ProxyCommand does not match the verification target")
        return [
            str(self.args.client_binary),
            *self.proxy_command[1:-2],
            *command,
        ]

    def restore_verification_login(self) -> None:
        if self.logout_restore is None:
            return
        username, password = self.logout_restore
        self.run(
            "restore-verification-user-login",
            self.verification_user_cli(
                "login",
                "--method",
                "password",
                "--username",
                username,
                "--password-stdin",
            ),
            input_data=password,
            timeout=30,
        )
        self.logout_restore = None

    def verify_logout_boundary(self) -> None:
        username, password = self.verification_user_password()
        self.logout_restore = (username, password)
        self.run(
            "verification-user-logout",
            self.verification_user_cli("logout"),
            timeout=30,
        )
        try:
            active = self.run(
                "active-control-master-survives-login-logout",
                self.ssh_base(multiplex=True) + ["hostname"],
                timeout=5,
            )
            if not active.stdout.strip():
                raise VerificationError("active ControlMaster stopped responding after user logout")
            denied = self.run(
                "new-transport-after-login-logout",
                self.ssh_base(multiplex=False) + ["true"],
                accepted=None,
            )
            denial = (denied.stderr + denied.stdout).decode("utf-8", "replace").lower()
            if denied.returncode == 0 or not any(
                phrase in denial for phrase in ("read active kmesh login", "please run kmesh login")
            ):
                raise VerificationError("new transport did not require login after logout")
            self.report["logout_boundary"] = {
                "active_control_master_continued": True,
                "new_transport_denied": True,
                "reason": "local login removed after server logout",
            }
            self.write_report()
            self.record("assert-logout-boundary", "passed")
        finally:
            self.restore_verification_login()
        restored = self.run(
            "verify-login-restored-after-logout-test",
            self.ssh_base(multiplex=False) + ["hostname"],
            timeout=SSH_NEW_CONNECTION_TIMEOUT_SECONDS,
        )
        if not restored.stdout.strip():
            raise VerificationError("verification user login was not restored after logout test")
        self.record("verify-login-restored-after-logout-test", "passed")

    def cleanup(self) -> None:
        try:
            self.restore_verification_login()
        except Exception as error:
            self.cleanup_errors.append(f"verification login restoration failed: {error}")
        try:
            self.restore_target()
        except Exception as error:
            self.cleanup_errors.append(f"target enablement restoration failed: {error}")
            self.record("restore-verification-target", "failed")
        try:
            self.restore_grant()
        except Exception as error:
            self.cleanup_errors.append(f"grant restoration failed: {error}")
            self.record("restore-original-target-grant", "failed")
        if self.remote_file and self.master is not None and self.master.poll() is None:
            try:
                self.run(
                    "remove-temporary-remote-transfer-file",
                    self.ssh_base(multiplex=True) + [f"rm -f -- {shlex.quote(self.remote_file)}"],
                    timeout=5,
                )
            except Exception as error:
                self.cleanup_errors.append(f"remote test-file cleanup failed: {error}")
        try:
            self.cancel_forward()
        except Exception as error:
            self.cleanup_errors.append(f"port-forward cleanup failed: {error}")
        try:
            self.close_master()
        except Exception as error:
            self.cleanup_errors.append(f"ControlMaster cleanup failed: {error}")
        self.socket_dir.cleanup()
        self.save_path_events()
        self.report["cleanup_errors"] = self.cleanup_errors
        self.write_report()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行短时 kmesh Iroh SSH 验收。")
    parser.add_argument("--client-binary", required=True, type=Path)
    parser.add_argument("--ssh-config", required=True, type=Path)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--admin-config", required=True, type=Path)
    parser.add_argument("--role-id", required=True, type=uuid.UUID)
    parser.add_argument("--target-id", required=True, type=uuid.UUID)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("private", "public-direct"), required=True)
    args = parser.parse_args()
    args.client_binary = args.client_binary.resolve()
    args.ssh_config = args.ssh_config.resolve()
    args.admin_config = args.admin_config.resolve()
    args.evidence_dir = args.evidence_dir.resolve()
    if args.alias.startswith("-") or not args.alias:
        parser.error("--alias must name an OpenSSH Host alias")
    for label, path in (
        ("client binary", args.client_binary),
        ("SSH config", args.ssh_config),
        ("admin config", args.admin_config),
    ):
        if not path.is_file():
            parser.error(f"{label} does not exist")
    if not os.access(args.client_binary, os.X_OK):
        parser.error("client binary is not executable")
    deployment_file = args.admin_config.parent / "deployment.json"
    if not deployment_file.is_file() or stat.S_IMODE(deployment_file.stat().st_mode) != 0o600:
        parser.error("verification deployment state must exist with mode 0600 beside --admin-config")
    try:
        deployment = json.loads(deployment_file.read_text())
    except json.JSONDecodeError:
        parser.error("verification deployment state is invalid")
    if not deployment.get("artifact_revision") or not deployment.get("server_agent_binary_sha256"):
        parser.error("deployment state must identify the active source and server/agent artifact SHA-256")
    if shutil.which("ssh") is None or shutil.which("ssh-keygen") is None:
        parser.error("OpenSSH ssh and ssh-keygen are required")
    return args


def main() -> int:
    verifier = Verification(parse_args())
    failure: str | None = None
    try:
        verifier.prepare_proxy_shim()
        if not verifier.grant_exists():
            raise VerificationError("the supplied role has no ssh_connect grant for the target")
        verifier.verify_basic_ssh()
        verifier.verify_path_probe()
        verifier.verify_control_master()
        verifier.verify_short_stream_interactions()
        verifier.verify_file_transfer()
        verifier.verify_forward()
        verifier.verify_host_key_rejection()
        verifier.verify_revoke_boundary()
        verifier.verify_target_disable_boundary()
        verifier.verify_logout_boundary()
    except (OSError, subprocess.SubprocessError, VerificationError, json.JSONDecodeError) as error:
        failure = str(error)
        verifier.report["failure"] = failure
        verifier.write_report()
    finally:
        verifier.cleanup()
    if verifier.cleanup_errors and failure is None:
        failure = "; ".join(verifier.cleanup_errors)
    verifier.report["status"] = "failed" if failure else "passed"
    if failure:
        verifier.report["failure"] = failure
    verifier.write_report()
    result = {
        "status": verifier.report["status"],
        "report": str(verifier.report_path),
        "observed_direct": verifier.report.get("observed_direct", False),
        "final_path_event": verifier.report.get("final_path_event"),
    }
    print(json.dumps(result, ensure_ascii=False))
    if failure:
        print(f"SSH验收失败：{failure}", file=sys.stderr)
        return 1
    print(f"SSH验收通过，证据保存在 {verifier.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
