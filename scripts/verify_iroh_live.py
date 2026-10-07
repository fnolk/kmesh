#!/usr/bin/env python3
"""Short, repeatable live SSH verification for the Iroh implementation.

Only the Python standard library is required. Stage writes to a new, isolated
remote directory. Deploy is the only command that stops the old services.
"""

from __future__ import annotations

import base64
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import select
import signal
import shlex
import ssl
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any


SERVER_ADDR_DEFAULT = "192.0.2.11"
SERVER_PORT_DEFAULT = 9443
SERVER_DEFAULT = "root@192.0.2.11"
TARGET_DEFAULT = "target-1"
REMOTE_ROOT = "/opt/kmesh-iroh-verification"
OLD_SERVER_UNIT = "kmesh-verification-server-9443.service"
OLD_AGENT_UNIT = "kmesh-verification-agent.service"
SERVER_PRIVATE_UNIT = "kmesh-iroh-verification-server-private.service"
SERVER_PUBLIC_UNIT = "kmesh-iroh-verification-server-public.service"
AGENT_UNIT = "kmesh-iroh-verification-agent@.service"
SSH_CONNECT_TIMEOUT_SECONDS = 65
SSH_COMMAND_TIMEOUT_SECONDS = 15
SSH_NEW_CONNECTION_TIMEOUT_SECONDS = SSH_CONNECT_TIMEOUT_SECONDS + SSH_COMMAND_TIMEOUT_SECONDS
INITIAL_ADMIN_TOKEN_PREFIX = "初始管理员 API token（仅显示一次）："
CA_DEFAULT = Path("/Users/example/.cache/kmesh-live/server/ca.pem")
STATE_DEFAULT = Path("/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003")
PATH_EVENT_RE = re.compile(
    r"连接路径(?P<change>切换)?：(?P<label>P2P 直连|Iroh 中继) \((?P<address>[^)]+)\)"
)
NO_SELECTED_PATH_RE = re.compile(
    r"(?:连接已建立；Iroh 正在选择网络路径|当前没有已选网络路径；Iroh 正在重新选择)。"
)
LOG_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b"
)
QUIC_PATH_SAMPLE_RE = re.compile(
    r"QUIC path UDP (?P<sample>baseline|interval) \((?P<address>[^)]+)\) "
    r"kind=(?P<kind>Direct|Relay) selected=(?P<selected>true|false) "
    r"TX(?: delta)?=(?P<tx>\d+) RX(?: delta)?=(?P<rx>\d+)"
)
ROUTE_FAILURE_RE = re.compile(
    r"SSH route (?P<route_mode>PrivateDirect|PublicDirect|PrivateRelay) failed after "
    r"(?P<elapsed_ms>\d+) ms: (?P<message>.*)"
)
REMOTE_RUNNER = (
    "import json,subprocess,sys; "
    "secret=sys.stdin.buffer.read(); "
    "raw_args=sys.argv[1:]; capture_stdout='__KMESH_CAPTURE_STDOUT__' in raw_args; "
    "secret_stdin='__KMESH_SECRET_STDIN__' in raw_args; "
    "args=[secret.decode() if x=='__KMESH_SECRET_STDIN__' else x for x in raw_args "
    "if x!='__KMESH_CAPTURE_STDOUT__']; "
    "p=subprocess.run(args,input=(b'' if secret_stdin else secret),"
    "stdout=subprocess.PIPE,stderr=subprocess.PIPE); "
    "err=p.stderr.decode('utf-8','replace'); "
    "err=err.replace(secret.decode('utf-8','replace'),'<redacted>') if secret else err; "
    "out={'exit_code':p.returncode,'stdout_bytes':len(p.stdout),'stderr':err[-4096:]}; "
    "out['stdout']=p.stdout.decode('utf-8','replace') if capture_stdout else None; "
    "print(json.dumps(out,ensure_ascii=False)); sys.exit(p.returncode)"
)
REMOTE_WRITE = (
    "import os,pathlib,sys\n"
    "p=pathlib.Path(sys.argv[1]); mode=int(sys.argv[2],8)\n"
    "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)\n"
    "with os.fdopen(fd,'wb') as f: f.write(sys.stdin.buffer.read())\n"
    "os.chmod(p,mode)\n"
)


class VerificationError(RuntimeError):
    pass


class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.started = dt.datetime.now(dt.timezone.utc)
        run_id = args.run_id or self.started.strftime("run-%Y%m%dT%H%M%SZ")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id) or run_id in {".", ".."}:
            raise VerificationError("run ID must contain only letters, digits, dot, underscore, or hyphen")
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(args.state_dir, 0o700)
        self.run_dir = args.state_dir / "runs" / run_id
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        self.report_path = self.run_dir / "report.json"
        previous = json.loads(self.report_path.read_text()) if self.report_path.is_file() else None
        self.events: list[dict[str, Any]] = previous.get("events", []) if previous else []
        self.secrets: list[str] = []
        self.report: dict[str, Any] = previous or {
            "run_id": run_id,
            "started_utc": self.started.isoformat(),
            "server_url": args.issuer,
            "server_ssh": args.server_ssh,
            "target_ssh": args.target_ssh,
            "events": self.events,
        }
        if previous is None and args.client_binary.is_file():
            self.report["client_artifact"] = {
                "source_revision": args.artifact_revision,
                "path": str(args.client_binary),
                "sha256": hashlib.sha256(args.client_binary.read_bytes()).hexdigest(),
            }

    def protect_secret(self, value: str) -> None:
        if value:
            self.secrets.append(value)

    def redact(self, data: bytes | str) -> str:
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        for secret in self.secrets:
            text = text.replace(secret, "<redacted>")
        text = re.sub(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            "<redacted-private-key>",
            text,
            flags=re.DOTALL,
        )
        text = re.sub(
            r"(?i)(password|api[_ -]?token|enrollment[_ -]?token|access[_ -]?token|refresh[_ -]?token|secret)"
            r"(\s*[:=]\s*)[^\s,;]+",
            r"\1\2<redacted>",
            text,
        )
        return text[-4096:]

    def record(
        self,
        phase: str,
        label: str,
        *,
        status: str,
        exit_code: int | None = None,
        stdout_bytes: int = 0,
        stderr: bytes | str = b"",
        details: dict[str, Any] | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "phase": phase,
            "label": label,
            "status": status,
            "exit_code": exit_code,
            "stdout_bytes": stdout_bytes,
            "stderr": self.redact(stderr),
        }
        if details:
            event.update(details)
        self.events.append(event)
        self.write_report()

    def write_report(self) -> None:
        self.report["updated_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        tmp = self.report_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.report, indent=2, ensure_ascii=False) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.report_path)
        os.chmod(self.report_path, 0o600)

    def local(
        self,
        phase: str,
        label: str,
        argv: list[str],
        *,
        input_data: bytes | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30,
        accepted: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        merged_env = os.environ.copy()
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
            self.record(
                phase,
                label,
                status="timeout",
                stderr=error.stderr or b"",
                details={"timeout_seconds": timeout},
            )
            raise VerificationError(f"{phase}/{label} timed out after {timeout:g}s") from error
        status = "passed" if result.returncode in accepted else "failed"
        self.record(
            phase,
            label,
            status=status,
            exit_code=result.returncode,
            stdout_bytes=len(result.stdout),
            stderr=result.stderr,
        )
        if status == "failed":
            raise VerificationError(
                f"{phase}/{label} exited {result.returncode}: {self.redact(result.stderr).strip()}"
            )
        return result

    def remote(
        self,
        phase: str,
        label: str,
        host: str,
        argv: list[str],
        *,
        stdin: bytes | None = None,
        capture_initial_admin_token: bool = False,
        timeout: float = 30,
        accepted: tuple[int, ...] = (0,),
    ) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any] | None]:
        remote_argv = ["python3", "-c", REMOTE_RUNNER, *argv]
        if capture_initial_admin_token:
            remote_argv.append("__KMESH_CAPTURE_STDOUT__")
        remote_command = shlex.join(remote_argv)
        ssh_argv = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            host,
            remote_command,
        ]
        result = subprocess.run(
            ssh_argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        remote_report = None
        if result.stdout:
            try:
                remote_report = json.loads(result.stdout)
            except json.JSONDecodeError:
                remote_report = None
        exit_code = result.returncode
        stderr = result.stderr
        if remote_report:
            exit_code = int(remote_report.get("exit_code", exit_code))
            stderr = str(remote_report.get("stderr", "")).encode()
            if capture_initial_admin_token:
                output = str(remote_report.get("stdout") or "")
                token = next(
                    (
                        line[len(INITIAL_ADMIN_TOKEN_PREFIX) :].strip()
                        for line in output.splitlines()
                        if line.startswith(INITIAL_ADMIN_TOKEN_PREFIX)
                        and line[len(INITIAL_ADMIN_TOKEN_PREFIX) :].strip()
                    ),
                    None,
                )
                if token is None:
                    raise VerificationError("server initialization did not return its initial admin API token")
                self.protect_secret(token)
                remote_report["captured_token"] = token
                remote_report.pop("stdout", None)
        status = "passed" if exit_code in accepted else "failed"
        self.record(
            phase,
            label,
            status=status,
            exit_code=exit_code,
            stdout_bytes=(
                int(remote_report.get("stdout_bytes", 0))
                if remote_report
                else len(result.stdout)
            ),
            stderr=stderr,
            details={"host": host},
        )
        if status == "failed":
            raise VerificationError(
                f"{phase}/{label} on {host} exited {exit_code}: {self.redact(stderr).strip()}"
            )
        if capture_initial_admin_token and remote_report is None:
            raise VerificationError("server initialization output was unavailable for token capture")
        return result, remote_report

    def ssh_raw(
        self,
        phase: str,
        label: str,
        host: str,
        remote_command: str,
        *,
        stdin: bytes | None = None,
        timeout: float = 30,
        accepted: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [
                "ssh",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                host,
                remote_command,
            ],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        status = "passed" if result.returncode in accepted else "failed"
        self.record(
            phase,
            label,
            status=status,
            exit_code=result.returncode,
            stdout_bytes=len(result.stdout),
            stderr=result.stderr,
            details={"host": host},
        )
        if status == "failed":
            raise VerificationError(
                f"{phase}/{label} on {host} exited {result.returncode}: "
                f"{self.redact(result.stderr).strip()}"
            )
        return result

    def kmesh_args(self, profile: str, *subcommand: str) -> list[str]:
        return [
            str(self.args.client_binary),
            "--config",
            str(self.client_config),
            "--profile",
            profile,
            *subcommand,
        ]

    @property
    def client_state(self) -> Path:
        return self.args.state_dir / "client"

    @property
    def client_config(self) -> Path:
        return self.args.state_dir / "config.toml"

    @property
    def state_file(self) -> Path:
        return self.args.state_dir / "deployment.json"

    def save_state(self, value: dict[str, Any]) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_file)
        os.chmod(self.state_file, 0o600)

    def load_state(self) -> dict[str, Any]:
        if not self.state_file.is_file():
            raise VerificationError(f"deployment state is missing: {self.state_file}")
        return json.loads(self.state_file.read_text())


def server_units() -> dict[str, str]:
    base = f"{REMOTE_ROOT}/bin/kmesh --config {REMOTE_ROOT}/server-data/config.toml server run"
    template = """[Unit]
Description=kmesh Iroh verification server ({mode})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=2
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
"""
    return {
        SERVER_PRIVATE_UNIT: template.format(exec_start=base, mode="private relay"),
        SERVER_PUBLIC_UNIT: template.format(
            exec_start=base + " --disable-private-relay", mode="public-direct"
        ),
    }


def agent_unit() -> str:
    return f"""[Unit]
Description=kmesh Iroh verification agent for target %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={REMOTE_ROOT}/bin/kmesh --config {REMOTE_ROOT}/agent-data/config.toml agent run --target-id %i
Restart=always
RestartSec=2
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="按隔离的 stage/deploy/verify 阶段验证 kmesh Iroh SSH。"
    )
    parser.add_argument("--server-ssh", default=SERVER_DEFAULT)
    parser.add_argument("--target-ssh", default=TARGET_DEFAULT)
    parser.add_argument("--server-addr", default=SERVER_ADDR_DEFAULT, help="Server IP address or hostname")
    parser.add_argument("--server-port", type=int, default=SERVER_PORT_DEFAULT, help="Server HTTPS port")
    parser.add_argument("--state-dir", type=Path, default=STATE_DEFAULT)
    repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--client-binary", type=Path, default=repo / "target/aarch64-apple-darwin/release/kmesh")
    parser.add_argument(
        "--linux-binary",
        type=Path,
        default=repo / "target/x86_64-unknown-linux-musl/release/kmesh",
    )
    parser.add_argument("--artifact-revision", default=None)
    parser.add_argument("--ca-file", type=Path, default=CA_DEFAULT)
    parser.add_argument("--run-id", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print planned boundaries without contacting hosts")
    subparsers.add_parser("preflight", help="read-only host, service, binary, and port checks")
    subparsers.add_parser("stage", help="write isolated files and initialize the new database")
    subparsers.add_parser("stage-binary", help="copy a new Linux artifact into inactive temp paths and verify SHA-256")
    subparsers.add_parser("refresh-binary", help="atomically update only the staged verification server and agent")
    subparsers.add_parser("deploy", help="transition from old services to the staged new services")
    verify_parser = subparsers.add_parser("verify", help="run API-token login or reuse its saved session, then test SSH")
    verify_parser.add_argument("--reuse-login", action="store_true")
    subparsers.add_parser("key-login", help="verify SSHSIG login with an isolated temporary ssh-agent")
    probe = subparsers.add_parser("path-probe", help="run fresh direct-gated SSH path samples")
    probe.add_argument("--seconds", type=int, default=SSH_CONNECT_TIMEOUT_SECONDS)
    probe.add_argument("--repetitions", type=int, default=3)
    probe.add_argument("--ssh-config", type=Path, default=None)
    probe.add_argument(
        "--restart-server-after-direct",
        action="store_true",
        help="restart only the new private server after this SSH stream selects Direct",
    )
    mode = subparsers.add_parser("mode", help="switch only the new deployment between relay modes")
    mode.add_argument("value", choices=("private", "public-direct"))
    subparsers.add_parser("rollback", help="stop new units and restore the preserved old services")
    return parser


def print_plan(args: argparse.Namespace) -> None:
    plan = {
        "stage": [
            "read-only preflight; fail if /opt/kmesh-iroh-verification already exists",
            "copy the Linux musl binary, reuse the existing TLS files, write two new server units and one agent template",
            "initialize a fresh SQLite data directory and capture the one-time admin API token into a 0600 local file",
            "leave both old units, binaries, and data running and untouched",
        ],
        "stage-binary": [
            "upload a replacement Linux binary to a temporary path on the new server and target",
            "verify both SHA-256 values while the running new services remain active",
        ],
        "refresh-binary": [
            "stop only the current new target agent and the active new server mode",
            "atomically install the verified binary on both new hosts and restart in the same mode",
            "reuse the schema 4 database, target UUID, and persistent agent identity",
        ],
        "deploy": [
            "stop the old target agent, then the old public server to release TCP 9443 and UDP 3478",
            "start the new private server with its isolated database",
            "create a new user, role, target, and grant; enroll the target through a 0600 token file piped to remote Python stdin",
            "start one new target agent and wait for the new target to report online",
        ],
        "verify": [
            "API-token login in an isolated kmesh profile, then real OpenSSH hostname and expected exit code 23",
            "record the Iroh-selected path and remote address; the relay-mode label alone is not direct-path evidence",
            "key-login verifies SSHSIG with a separate temporary SSH_AUTH_SOCK; verify_iroh_ssh.py runs the extended SSH checks",
            "write only sanitized results to a 0600 evidence report; preserve raw secrets in protected files or environment variables",
        ],
        "mode": [
            "stop only the new target agent and active new server unit",
            "start the other new server mode over the same database, then restart its agent",
            "close harness ControlMasters before switching and wait for target online",
        ],
        "path-probe": [
            "run a bounded SSH command with RUST_LOG enabled for Iroh NetReport and target candidate diagnostics",
            "save the complete stderr at mode 0600 and report parsed QAD/global_v4 and selected path events",
        ],
        "key-login": [
            "register a temporary Ed25519 public key and perform a real SSHSIG login using its own ssh-agent socket",
            "save the login profile under a separate name and verify 0600 credential/0700 directory permissions",
            "delete the temporary private key and stop only the dedicated ssh-agent",
        ],
        "rollback": [
            "stop the new agent and whichever new server mode is active",
            "restart the original agent and server units using their original files and data",
            "preserve the new deployment directory and evidence for diagnosis",
        ],
    }
    print(json.dumps(plan, indent=2, ensure_ascii=False))


def ensure_client_inputs(harness: Harness) -> None:
    args = harness.args
    if not args.client_binary.is_file():
        raise VerificationError("--client-binary must name the native kmesh executable")
    if not os.access(args.client_binary, os.X_OK):
        raise VerificationError("client binary is not executable")
    if not args.ca_file.is_file():
        raise VerificationError("--ca-file does not exist")


def preflight(harness: Harness) -> None:
    ensure_client_inputs(harness)
    args = harness.args
    client_hash = hashlib.sha256(args.client_binary.read_bytes()).hexdigest()
    version = harness.local(
        "preflight",
        "client-version",
        [str(args.client_binary), "--version"],
    )
    harness.report["client"] = {
        "binary": str(args.client_binary),
        "sha256": client_hash,
        "version": harness.redact(version.stdout).strip(),
    }
    if args.artifact_revision:
        harness.report["client"]["artifact_revision"] = args.artifact_revision
    ssh_version = harness.local("preflight", "openssh-version", ["ssh", "-V"], accepted=(0, 1))
    harness.report["openssh_version"] = harness.redact(ssh_version.stderr or ssh_version.stdout).strip()
    remote_check = r'''set +e
printf 'host='; hostname -f
printf 'platform='; uname -sm
printf 'old_server='; systemctl is-active kmesh-verification-server-9443.service 2>/dev/null
printf 'old_agent='; systemctl is-active kmesh-verification-agent.service 2>/dev/null
printf 'new_root_exists='; if test -e /opt/kmesh-iroh-verification; then echo yes; else echo no; fi
printf 'listeners='; (ss -H -lntup 2>/dev/null | awk '$5 ~ /:(9443|3478|22)$/ {printf "%s ",$0}')
'''
    for label, host in (("server", args.server_ssh), ("target", args.target_ssh)):
        result = harness.ssh_raw(
            "preflight",
            f"{label}-read-only-inventory",
            host,
            "sh -s",
            stdin=remote_check.encode(),
            timeout=20,
        )
        harness.report.setdefault("hosts", {})[label] = harness.redact(result.stdout)
        harness.write_report()
    if not args.linux_binary or not args.linux_binary.is_file():
        harness.record(
            "preflight",
            "linux-binary",
            status="pending",
            details={"reason": "Linux musl release artifact has not been supplied"},
        )
    else:
        harness.report["linux_binary"] = {
            "path": str(args.linux_binary),
            "sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
            "bytes": args.linux_binary.stat().st_size,
        }
        harness.write_report()
    with socket.socket() as local_sshd:
        local_sshd.settimeout(1.0)
        try:
            local_sshd.connect(("127.0.0.1", 22))
            banner = local_sshd.recv(256).decode("ascii", "replace").strip()
            harness.record("preflight", "local-sshd-banner", status="passed", details={"banner": banner})
        except OSError as error:
            harness.record(
                "preflight",
                "local-sshd-banner",
                status="unavailable",
                stderr=str(error),
            )


def stage(harness: Harness) -> None:
    args = harness.args
    ensure_client_inputs(harness)
    if args.linux_binary is None or not args.linux_binary.is_file():
        raise VerificationError("stage requires --linux-binary for the Linux x86_64 musl release")
    for host, label in ((args.server_ssh, "server"), (args.target_ssh, "target")):
        result = harness.ssh_raw(
            "stage",
            f"{label}-new-root-absent",
            host,
            f"test ! -e {shlex.quote(REMOTE_ROOT)}",
            timeout=15,
        )
        del result
    for host, label in ((args.server_ssh, "server"), (args.target_ssh, "target")):
        harness.ssh_raw(
            "stage",
            f"{label}-create-new-directories",
            host,
            f"mkdir -m 0700 {REMOTE_ROOT} && install -d -m 0700 "
            + " ".join(
                shlex.quote(path)
                for path in (
                    (f"{REMOTE_ROOT}/bin", f"{REMOTE_ROOT}/server-data", f"{REMOTE_ROOT}/tls")
                    if label == "server"
                    else (f"{REMOTE_ROOT}/bin", f"{REMOTE_ROOT}/agent-data")
                )
            ),
            timeout=15,
        )
        harness.local(
            "stage",
            f"{label}-copy-linux-binary",
            ["scp", "-q", str(args.linux_binary), f"{host}:{REMOTE_ROOT}/bin/kmesh.stage"],
            timeout=90,
        )
        harness.ssh_raw(
            "stage",
            f"{label}-install-linux-binary",
            host,
            f"install -m 0755 {REMOTE_ROOT}/bin/kmesh.stage {REMOTE_ROOT}/bin/kmesh "
            f"&& rm {REMOTE_ROOT}/bin/kmesh.stage",
        )

    old_tls = "/opt/kmesh-verification/tls"
    harness.ssh_raw(
        "stage",
        "server-copy-existing-tls",
        args.server_ssh,
        f"install -m 0644 {old_tls}/server-cert.pem {REMOTE_ROOT}/tls/server-cert.pem "
        f"&& install -m 0600 {old_tls}/server-key.pem {REMOTE_ROOT}/tls/server-key.pem",
    )
    harness.ssh_raw(
        "stage",
        "target-copy-existing-ca",
        args.target_ssh,
        f"install -m 0644 /opt/kmesh-verification/ca.pem {REMOTE_ROOT}/ca.pem",
    )
    server_config = (
        f"server_addr = {json.dumps(args.server_addr)}\n"
        f"server_port = {args.server_port}\n"
        f"data_dir = {json.dumps(REMOTE_ROOT + '/server-data')}\n"
        "profile = \"verification-server\"\n\n"
        "[server]\n"
        "bind_addr = \"0.0.0.0\"\n"
        "udp_port = 3478\n"
        f"tls_cert = {json.dumps(REMOTE_ROOT + '/tls/server-cert.pem')}\n"
        f"tls_key = {json.dumps(REMOTE_ROOT + '/tls/server-key.pem')}\n"
        "disable_private_relay = false\n"
    )
    harness.remote(
        "stage",
        "write-server-config",
        args.server_ssh,
        ["python3", "-c", REMOTE_WRITE, f"{REMOTE_ROOT}/server-data/config.toml", "0640"],
        stdin=server_config.encode(),
    )
    for unit, contents in server_units().items():
        harness.remote(
            "stage",
            f"write-{unit}",
            args.server_ssh,
            ["python3", "-c", REMOTE_WRITE, f"/etc/systemd/system/{unit}", "0644"],
            stdin=contents.encode(),
        )
    harness.remote(
        "stage",
        "write-agent-unit",
        args.target_ssh,
        ["python3", "-c", REMOTE_WRITE, f"/etc/systemd/system/{AGENT_UNIT}", "0644"],
        stdin=agent_unit().encode(),
    )
    agent_config = (
        f"server_addr = {json.dumps(args.server_addr)}\n"
        f"server_port = {args.server_port}\n"
        f"data_dir = {json.dumps(REMOTE_ROOT + '/agent-data')}\n"
        "profile = \"verification\"\n\n"
        "[tls]\n"
        f"ca_certificates = [{json.dumps(REMOTE_ROOT + '/ca.pem')}]\n\n"
        "[ssh]\n"
        "address = \"127.0.0.1:22\"\n"
        "connect_timeout_secs = 10\n"
    )
    harness.remote(
        "stage",
        "write-agent-config",
        args.target_ssh,
        ["python3", "-c", REMOTE_WRITE, f"{REMOTE_ROOT}/agent-data/config.toml", "0600"],
        stdin=agent_config.encode(),
    )
    harness.ssh_raw("stage", "server-systemd-reload", args.server_ssh, "systemctl daemon-reload")
    harness.ssh_raw("stage", "target-systemd-reload", args.target_ssh, "systemctl daemon-reload")

    init_command = [
        f"{REMOTE_ROOT}/bin/kmesh",
        "--config",
        f"{REMOTE_ROOT}/server-data/config.toml",
        "server",
        "init",
        "--admin",
        "verification-admin",
    ]
    _, init_report = harness.remote(
        "stage",
        "initialize-new-server-database",
        args.server_ssh,
        init_command,
        stdin=b"",
        capture_initial_admin_token=True,
        timeout=30,
    )
    if init_report is None:
        raise VerificationError("initial administrator API token was not returned")
    initial_admin_token = init_report["captured_token"]
    write_private_file(
        args.state_dir / "credentials" / "initial-admin-api-token",
        initial_admin_token.encode("utf-8") + b"\n",
    )
    harness.report["staged_linux_binary"] = {
        "sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
        "bytes": args.linux_binary.stat().st_size,
    }
    harness.report["staged_units"] = [SERVER_PRIVATE_UNIT, SERVER_PUBLIC_UNIT, AGENT_UNIT]
    harness.report["artifact_revision"] = args.artifact_revision
    harness.write_report()


def remote_binary_hash(harness: Harness, phase: str, label: str, host: str, path: str) -> str:
    result = harness.ssh_raw(phase, label, host, f"sha256sum {shlex.quote(path)}")
    fields = result.stdout.decode("ascii", "strict").split()
    if len(fields) < 2 or fields[1] != path:
        raise VerificationError(f"{label} returned an unexpected sha256sum response")
    return fields[0]


def stage_binary(harness: Harness) -> None:
    state = harness.load_state()
    if state["server_mode"] not in {"private", "public-direct"}:
        raise VerificationError("deployment has an unknown server mode")
    if not harness.args.linux_binary.is_file():
        raise VerificationError("stage-binary requires --linux-binary")
    expected = hashlib.sha256(harness.args.linux_binary.read_bytes()).hexdigest()
    staged_path = f"{REMOTE_ROOT}/bin/kmesh.next"
    for host, label in ((harness.args.server_ssh, "server"), (harness.args.target_ssh, "target")):
        exists = harness.ssh_raw(
            "stage-binary",
            f"{label}-check-next-binary",
            host,
            f"test -e {shlex.quote(staged_path)}",
            accepted=(0, 1),
        )
        if exists.returncode == 0:
            observed = remote_binary_hash(
                harness, "stage-binary", f"{label}-existing-next-sha256", host, staged_path
            )
            if observed != expected:
                raise VerificationError(f"{label} already has a different staged kmesh.next")
        else:
            harness.local(
                "stage-binary",
                f"{label}-copy-linux-binary",
                ["scp", "-q", str(harness.args.linux_binary), f"{host}:{staged_path}"],
                timeout=90,
            )
            observed = remote_binary_hash(
                harness, "stage-binary", f"{label}-verify-next-sha256", host, staged_path
            )
            if observed != expected:
                raise VerificationError(f"{label} staged binary SHA-256 mismatch")
    harness.report["staged_upgrade"] = {
        "artifact_revision": harness.args.artifact_revision,
        "path_on_both_hosts": staged_path,
        "sha256": expected,
        "bytes": harness.args.linux_binary.stat().st_size,
        "services_stopped": False,
    }
    harness.write_report()


def upgrade_binary(harness: Harness) -> None:
    state = harness.load_state()
    expected = hashlib.sha256(harness.args.linux_binary.read_bytes()).hexdigest()
    staged_path = f"{REMOTE_ROOT}/bin/kmesh.next"
    current_path = f"{REMOTE_ROOT}/bin/kmesh"
    hosts = ((harness.args.server_ssh, "server"), (harness.args.target_ssh, "target"))
    backups: dict[str, dict[str, str]] = {}
    swaps: dict[str, str] = {}
    for host, label in hosts:
        observed = remote_binary_hash(
            harness, "refresh-binary", f"{label}-verify-staged-sha256", host, staged_path
        )
        if observed != expected:
            raise VerificationError(f"{label} staged binary SHA-256 does not match requested artifact")

        current_sha = remote_binary_hash(
            harness, "refresh-binary", f"{label}-verify-current-sha256", host, current_path
        )
        backup_path = f"{REMOTE_ROOT}/bin/kmesh.{current_sha}.backup"
        backup_exists = harness.ssh_raw(
            "refresh-binary",
            f"{label}-check-current-backup",
            host,
            f"test -e {shlex.quote(backup_path)}",
            accepted=(0, 1),
        )
        if backup_exists.returncode == 0:
            backup_sha = remote_binary_hash(
                harness, "refresh-binary", f"{label}-verify-existing-backup", host, backup_path
            )
            if backup_sha != current_sha:
                raise VerificationError(f"{label} SHA-named backup has unexpected contents")
        else:
            harness.ssh_raw(
                "refresh-binary",
                f"{label}-preserve-current-binary",
                host,
                f"cp -p {shlex.quote(current_path)} {shlex.quote(backup_path)}",
            )
            backup_sha = remote_binary_hash(
                harness, "refresh-binary", f"{label}-verify-preserved-backup", host, backup_path
            )
            if backup_sha != current_sha:
                raise VerificationError(f"{label} current binary backup SHA-256 mismatch")
        backups[label] = {"path": backup_path, "sha256": current_sha}

        swap_path = f"{REMOTE_ROOT}/bin/kmesh.{expected}.swap"
        swap_exists = harness.ssh_raw(
            "refresh-binary",
            f"{label}-check-staged-swap",
            host,
            f"test -e {shlex.quote(swap_path)}",
            accepted=(0, 1),
        )
        if swap_exists.returncode == 0:
            swap_sha = remote_binary_hash(
                harness, "refresh-binary", f"{label}-verify-existing-swap", host, swap_path
            )
            if swap_sha != expected:
                raise VerificationError(f"{label} SHA-named swap has unexpected contents")
        else:
            harness.ssh_raw(
                "refresh-binary",
                f"{label}-prepare-atomic-swap",
                host,
                f"install -m 0755 {shlex.quote(staged_path)} {shlex.quote(swap_path)}",
            )
            swap_sha = remote_binary_hash(
                harness, "refresh-binary", f"{label}-verify-prepared-swap", host, swap_path
            )
            if swap_sha != expected:
                raise VerificationError(f"{label} prepared swap SHA-256 mismatch")
        swaps[label] = swap_path

    close_run_masters(harness)
    target_unit = f"kmesh-iroh-verification-agent@{state['target_id']}.service"
    server_unit = (
        SERVER_PUBLIC_UNIT if state["server_mode"] == "public-direct" else SERVER_PRIVATE_UNIT
    )
    harness.ssh_raw(
        "refresh-binary", "stop-new-target-agent", harness.args.target_ssh, f"systemctl stop {target_unit}"
    )
    harness.ssh_raw(
        "refresh-binary", "stop-current-new-server", harness.args.server_ssh, f"systemctl stop {server_unit}"
    )
    for host, label in hosts:
        command = (
            f"mv -f {shlex.quote(swaps[label])} {shlex.quote(current_path)} && "
            f"rm -f {shlex.quote(staged_path)}"
        )
        harness.ssh_raw("refresh-binary", f"{label}-atomic-install", host, command)
    harness.ssh_raw("refresh-binary", "start-new-server-current-mode", harness.args.server_ssh, f"systemctl start {server_unit}")
    wait_health(harness, "refresh-binary")
    harness.ssh_raw("refresh-binary", "start-new-target-agent", harness.args.target_ssh, f"systemctl start {target_unit}")

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = kmesh_admin_json(
            harness, "admin", "targets", "list", label="wait-target-online-after-binary-upgrade", phase="refresh-binary"
        )
        targets = expect_data(response, "targets", "wait-target-online-after-binary-upgrade")
        if any(item["target_id"] == state["target_id"] and item["online"] for item in targets):
            break
        time.sleep(1)
    else:
        raise VerificationError("the existing target identity did not reconnect after the binary upgrade")

    harness.report["binary_upgrade"] = {
        "artifact_revision": harness.args.artifact_revision,
        "sha256": expected,
        "server_and_agent_sha256_verified": True,
        "server_mode_preserved": state["server_mode"],
        "schema_and_target_identity_reused": True,
        "preserved_current_binaries": backups,
        "legacy_deployment_touched": False,
    }
    state["artifact_revision"] = harness.args.artifact_revision
    state["server_agent_binary_sha256"] = expected
    harness.save_state(state)
    harness.write_report()


def read_secret_file(path: Path) -> bytes:
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise VerificationError(f"secret file permissions must be 0600 or stricter: {path}")
    value = path.read_bytes().rstrip(b"\r\n")
    if not value:
        raise VerificationError(f"secret file is empty: {path}")
    return value


def write_private_file(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(value)
    os.chmod(path, 0o600)


def client_config(harness: Harness) -> None:
    args = harness.args
    text = (
        f"server_addr = {json.dumps(args.server_addr)}\n"
        f"server_port = {args.server_port}\n"
        f"profile = \"verification\"\n"
        f"data_dir = {json.dumps(str(harness.client_state))}\n\n"
        "[tls]\n"
        f"ca_certificates = [{json.dumps(str(args.ca_file))}]\n"
    )
    harness.args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if harness.client_config.exists():
        if harness.client_config.read_text() != text:
            raise VerificationError(f"refusing to replace unexpected client config {harness.client_config}")
        return
    write_private_file(harness.client_config, text.encode())


def kmesh_admin_json(
    harness: Harness,
    profile: str,
    *command: str,
    input_data: bytes | None = None,
    label: str,
    phase: str = "deploy",
) -> dict[str, Any]:
    result = harness.local(
        phase,
        label,
        harness.kmesh_args(profile, "admin", "--json", *command),
        input_data=input_data,
        timeout=30,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"{label} returned invalid JSON") from error
    return payload


def verify_public_key_login(harness: Harness) -> None:
    state = harness.load_state()
    suffix = harness.report["run_id"].replace("-", "")[-8:]
    profile = f"ssh-public-key-{suffix}"
    key_base = harness.run_dir / "kmesh-login-ed25519"
    private_key = key_base
    public_key = Path(str(key_base) + ".pub")
    if private_key.exists() != public_key.exists():
        raise VerificationError("temporary login key pair is incomplete")
    if not private_key.exists():
        harness.local(
            "auth",
            "generate-temporary-ed25519-login-key",
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kmesh-live-sshsig", "-f", str(private_key)],
            timeout=10,
        )
        private_key.chmod(0o600)
    fingerprint_result = harness.local(
        "auth", "fingerprint-temporary-login-public-key", ["ssh-keygen", "-lf", str(public_key)]
    )
    fingerprint = fingerprint_result.stdout.decode("utf-8", "replace").split()[1]
    public_key_parts = public_key.read_text().split()
    existing_keys = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "keys",
            "list",
            state["user_id"],
            label="list-public-login-keys",
            phase="auth",
        ),
        "keys",
        "list-public-login-keys",
    )
    registered_key = next(
        (
            item
            for item in existing_keys
            if item["public_key"].split()[:2] == public_key_parts[:2]
        ),
        None,
    )
    if registered_key is None:
        registered = expect_data(
            kmesh_admin_json(
                harness,
                "admin",
                "keys",
                "add",
                state["user_id"],
                str(public_key),
                "--label",
                f"live-{suffix}",
                label="register-public-login-key",
                phase="auth",
            ),
            "keys",
            "register-public-login-key",
        )
        registered_key = next(
            item for item in registered if item["public_key"].split()[:2] == public_key_parts[:2]
        )

    socket_dir = Path(tempfile.mkdtemp(prefix="km-agent-"))
    socket_path = socket_dir / "a"
    agent_started = harness.local(
        "auth",
        "start-dedicated-ssh-agent",
        ["ssh-agent", "-a", str(socket_path), "-s"],
        timeout=10,
    )
    agent_text = agent_started.stdout.decode("utf-8", "replace")
    socket_match = re.search(r"SSH_AUTH_SOCK=([^;]+);", agent_text)
    pid_match = re.search(r"SSH_AGENT_PID=(\d+);", agent_text)
    if not socket_match or not pid_match:
        raise VerificationError("ssh-agent did not report its dedicated socket and process ID")
    agent_env = {
        "SSH_AUTH_SOCK": socket_match.group(1),
        "SSH_AGENT_PID": pid_match.group(1),
    }
    try:
        harness.local("auth", "load-temporary-key-into-dedicated-agent", ["ssh-add", str(private_key)], env=agent_env)
        harness.local(
            "auth",
            "verification-user-sshsig-login",
            harness.kmesh_args(
                profile,
                "login",
                "--method",
                "public-key",
                "--username",
                state["username"],
                "--key",
                str(public_key),
            ),
            env=agent_env,
            timeout=30,
        )
        credential = None
        for path in (harness.client_state / "profiles").rglob("*.json"):
            saved = json.loads(path.read_text())
            if saved.get("profile") == profile and saved.get("username") == state["username"]:
                credential = path
                break
        if credential is None or stat.S_IMODE(credential.stat().st_mode) != 0o600:
            raise VerificationError("SSHSIG login profile credentials were not saved with mode 0600")
        parent = credential.parent
        while parent != harness.client_state.parent:
            if stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise VerificationError("SSHSIG login profile directory is accessible by group or others")
            parent = parent.parent
        harness.report["sshsig_login"] = {
            "status": "passed",
            "profile": profile,
            "key_fingerprint": fingerprint,
            "key_id": registered_key["key_id"],
            "agent_socket": "dedicated temporary socket",
            "credential_mode": "0600",
            "credential_directory_mode": "0700",
        }
        harness.write_report()
    finally:
        harness.local("auth", "stop-dedicated-ssh-agent", ["ssh-agent", "-k"], env=agent_env, timeout=10)
        private_key.unlink(missing_ok=True)
        socket_dir.rmdir()


def expect_data(response: dict[str, Any], result_name: str, label: str) -> Any:
    if response.get("result") != result_name or "data" not in response:
        raise VerificationError(f"{label} returned an unexpected response type")
    return response["data"]


def wait_health(harness: Harness, phase: str) -> None:
    context = ssl.create_default_context(cafile=str(harness.args.ca_file))
    deadline = time.monotonic() + 20
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                harness.args.issuer + "/health", context=context, timeout=3
            ) as response:
                if response.status == 200:
                    harness.record(phase, "https-health", status="passed", exit_code=0)
                    return
                last_error = f"HTTP {response.status}"
        except (OSError, ssl.SSLError) as error:
            last_error = str(error)
        time.sleep(1)
    harness.record(phase, "https-health", status="failed", stderr=last_error)
    raise VerificationError(f"{phase}/https-health did not pass: {harness.redact(last_error)}")


def admin_login(harness: Harness) -> None:
    admin_token = read_secret_file(
        harness.args.state_dir / "credentials" / "initial-admin-api-token"
    ).decode("utf-8")
    harness.protect_secret(admin_token)
    result = harness.local(
        "deploy",
        "administrator-api-token-login",
        harness.kmesh_args(
            "admin",
            "login",
            "--method",
            "token",
        ),
        env={"KMESH_TOKEN": admin_token},
        timeout=30,
    )
    if result.returncode != 0:
        raise VerificationError("administrator login failed")


def deploy(harness: Harness) -> None:
    args = harness.args
    if harness.state_file.exists():
        raise VerificationError(f"deployment state already exists: {harness.state_file}")
    if not (args.state_dir / "config.toml").is_file():
        client_config(harness)

    harness.ssh_raw("deploy", "stop-old-target-agent", args.target_ssh, f"systemctl stop {OLD_AGENT_UNIT}")
    harness.ssh_raw("deploy", "stop-old-server", args.server_ssh, f"systemctl stop {OLD_SERVER_UNIT}")
    harness.ssh_raw(
        "deploy", "start-new-private-server", args.server_ssh, f"systemctl start {SERVER_PRIVATE_UNIT}"
    )
    wait_health(harness, "deploy")
    admin_login(harness)

    suffix = harness.report["run_id"].replace("-", "")[-8:]
    target_name = f"target-1-iroh-{suffix}"
    username = f"kmesh-verify-{suffix}"
    role_name = f"target-1-access-{suffix}"
    target_data = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "targets",
            "create",
            target_name,
            label="create-target",
        ),
        "target_created",
        "create-target",
    )
    target = target_data["target"]
    target_id = target["target_id"]
    enrollment_code = target_data["enrollment_token"]
    harness.protect_secret(enrollment_code)

    user = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "users",
            "create",
            username,
            label="create-user",
        ),
        "user",
        "create-user",
    )
    user_id = user["user_id"]
    issued_token = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "tokens",
            "create",
            user_id,
            "--label",
            "verification-user",
            label="create-user-api-token",
        ),
        "api_token_issued",
        "create-user-api-token",
    )
    user_token = issued_token["token"]
    harness.protect_secret(user_token)
    user_token_file = args.state_dir / "credentials" / "verification-user-api-token"
    write_private_file(user_token_file, user_token.encode("utf-8") + b"\n")
    role = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "roles",
            "create",
            role_name,
            label="create-role",
        ),
        "role",
        "create-role",
    )
    role_id = role["role_id"]
    kmesh_admin_json(
        harness,
        "admin",
        "users",
        "roles",
        user_id,
        role_id,
        label="bind-user-role",
    )
    kmesh_admin_json(
        harness,
        "admin",
        "grants",
        "add",
        role_id,
        target_id,
        label="grant-ssh-connect",
    )
    state = {
        "target_id": target_id,
        "target_name": target_name,
        "user_id": user_id,
        "username": username,
        "user_token_file": str(user_token_file),
        "role_id": role_id,
        "role_name": role_name,
        "server_mode": "private",
        "artifact_revision": args.artifact_revision,
        "server_agent_binary_sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    harness.save_state(state)

    enroll_args = [
        f"{REMOTE_ROOT}/bin/kmesh",
        "--config",
        f"{REMOTE_ROOT}/agent-data/config.toml",
        "agent",
        "enroll",
        "--target-id",
        target_id,
        "--enrollment-code",
        "__KMESH_SECRET_STDIN__",
    ]
    try:
        harness.remote(
            "deploy",
            "enroll-target-identity",
            args.target_ssh,
            enroll_args,
            stdin=enrollment_code.encode(),
            timeout=30,
        )
    finally:
        del enrollment_code
    harness.ssh_raw(
        "deploy",
        "start-new-target-agent",
        args.target_ssh,
        f"systemctl start kmesh-iroh-verification-agent@{target_id}.service",
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = kmesh_admin_json(
            harness,
            "admin",
            "targets",
            "list",
            label="wait-target-online",
        )
        targets = expect_data(response, "targets", "wait-target-online")
        if any(item["target_id"] == target_id and item["online"] for item in targets):
            break
        time.sleep(1)
    else:
        raise VerificationError("new verification target did not become online")
    harness.report["deployment"] = {
        "target_id": target_id,
        "target_name": target_name,
        "user_id": user_id,
        "username": username,
        "role_id": role_id,
        "server_mode": "private",
    }
    harness.write_report()


def fetch_target_host_key(harness: Harness, state: dict[str, Any]) -> tuple[str, str]:
    result = harness.ssh_raw(
        "verify",
        "read-target-sshd-ed25519-public-key-over-management-ssh",
        harness.args.target_ssh,
        "cat /etc/ssh/ssh_host_ed25519_key.pub",
    )
    parts = result.stdout.decode("ascii", "strict").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise VerificationError("target returned no Ed25519 sshd host public key")
    base64.b64decode(parts[1], validate=True)
    host_alias = f"kmesh/{state['target_id']}"
    return host_alias, f"{host_alias} {parts[0]} {parts[1]}\n"


def write_ssh_config(
    harness: Harness,
    state: dict[str, Any],
    profile: str,
    known_hosts: Path,
    config_path: Path,
) -> str:
    result = harness.local(
        "verify",
        f"render-openssh-config-{profile}",
        harness.kmesh_args(profile, "ssh-config", state["target_id"]),
        timeout=30,
    )
    rendered = result.stdout.decode("utf-8")
    alias_match = re.search(r"(?m)^Host\s+(\S+)\s*$", rendered)
    if not alias_match:
        raise VerificationError("kmesh ssh-config output has no Host alias")
    alias = alias_match.group(1)
    mux_path = harness.run_dir / f"control-{profile}-%C"
    rendered, count = re.subn(
        r"(?m)^(\s*ControlPath\s+).*$",
        lambda match: match.group(1) + str(mux_path),
        rendered,
        count=1,
    )
    if count != 1:
        raise VerificationError("generated SSH config has no ControlPath")
    extra = (
        "Host *\n"
        "  User root\n"
        "  BatchMode yes\n"
        "  StrictHostKeyChecking yes\n"
        f"  UserKnownHostsFile {known_hosts}\n"
        f"  ConnectTimeout {SSH_CONNECT_TIMEOUT_SECONDS}\n"
        "  ServerAliveInterval 20\n"
        "  ServerAliveCountMax 2\n"
    )
    write_private_file(config_path, (rendered + extra).encode())
    return alias


def selected_paths(stderr: bytes) -> list[dict[str, str]]:
    text = stderr.decode("utf-8", "replace")
    return [
        {
            "sequence": index,
            "event": "change" if match.group("change") else "initial",
            "kind": "direct" if match.group("label") == "P2P 直连" else "relay",
            "remote_address": match.group("address"),
        }
        for index, match in enumerate(PATH_EVENT_RE.finditer(text), start=1)
    ]


def route_attempt_failures(stderr: bytes, harness: Harness) -> list[dict[str, Any]]:
    failures = []
    for line in stderr.decode("utf-8", "replace").splitlines():
        match = ROUTE_FAILURE_RE.search(line)
        if match:
            failures.append(
                {
                    "route_mode": match.group("route_mode"),
                    "elapsed_ms": int(match.group("elapsed_ms")),
                    "error": harness.redact(match.group("message")),
                }
            )
    return failures


def path_state_observations(stderr: bytes) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(stderr.splitlines(), start=1):
        text = raw_line.decode("utf-8", "replace")
        timestamp_match = LOG_TIMESTAMP_RE.match(text)
        timestamp = timestamp_match.group("timestamp") if timestamp_match else None
        for path_event in selected_paths(raw_line):
            observations.append(
                {
                    "source": "path_event",
                    "line_number": line_number,
                    "timestamp": timestamp,
                    "selected": True,
                    **path_event,
                }
            )
        if NO_SELECTED_PATH_RE.search(text):
            observations.append(
                {
                    "source": "no_selected_path",
                    "line_number": line_number,
                    "timestamp": timestamp,
                    "selected": False,
                    "kind": None,
                    "remote_address": None,
                }
            )
        match = QUIC_PATH_SAMPLE_RE.search(text)
        if match:
            observations.append(
                {
                    "source": "udp_path_snapshot",
                    "line_number": line_number,
                    "timestamp": timestamp,
                    "sample": match.group("sample"),
                    "kind": "direct" if match.group("kind") == "Direct" else "relay",
                    "selected": match.group("selected") == "true",
                    "remote_address": match.group("address"),
                    "udp_tx_bytes": int(match.group("tx")),
                    "udp_rx_bytes": int(match.group("rx")),
                }
            )
    return observations


def update_selected_path_state(
    selected_path_state: dict[str, Any] | None, observation: dict[str, Any]
) -> dict[str, Any] | None:
    if observation["selected"]:
        return observation
    if observation["source"] == "no_selected_path":
        return None
    if (
        observation["source"] == "udp_path_snapshot"
        and selected_path_state is not None
        and observation["remote_address"] == selected_path_state["remote_address"]
    ):
        return None
    return selected_path_state


def auth_session_fingerprint(harness: Harness, profile: str, username: str) -> str:
    for path in (harness.client_state / "profiles").rglob("*.json"):
        saved = json.loads(path.read_text())
        if saved.get("profile") != profile or saved.get("username") != username:
            continue
        token = saved["tokens"]["access_token"]
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        session_id = claims["sid"]
        return hashlib.sha256(session_id.encode()).hexdigest()
    raise VerificationError("saved login session was not found")


def endpoint_diagnostics(stderr: bytes) -> dict[str, Any]:
    lines = stderr.decode("utf-8", "replace").splitlines()
    candidates = []
    net_reports = []
    qnt_attempts = []
    udp_path_events = []
    noq_negotiated = []
    reach_out_events = []
    nat_probe_tx: dict[str, dict[str, int]] = {}
    path_response_tx: dict[str, dict[str, int]] = {}
    udp_transport_events = []
    received_paths: dict[str, int] = {}
    validated_paths = []
    for line in lines:
        candidate_match = re.search(r"(?P<role>target|client)_ip_addrs=\[([^\]]*)\]", line)
        if candidate_match:
            candidates.append(
                {
                    "role": candidate_match.group("role"),
                    "ip_addrs": [item.strip() for item in candidate_match.group(2).split(",") if item.strip()],
                    "source_line": line,
                }
            )
        if "net_report generated" in line:
            global_match = re.search(r"global_v4:\s*(Some\([^)]*\)|None)", line)
            udp_match = re.search(r"udp_v4:\s*(true|false)", line)
            global_value = global_match.group(1) if global_match else None
            if global_value and global_value.startswith("Some("):
                global_value = global_value[5:-1]
            net_reports.append(
                {
                    "udp_v4": udp_match.group(1) == "true" if udp_match else None,
                    "global_v4": global_value,
                    "source_line": line,
                }
            )
        if "iroh::_events::qnt::init" in line:
            qnt_attempts.append({"source_line": line})
        if "n0's nat traversal negotiated" in line:
            noq_negotiated.append(line)
        if "got frame REACH_OUT" in line:
            reach_out_events.append(line)
        for message, counts in (
            ("sending off-path NAT probe", nat_probe_tx),
            ("sending off-path PATH_RESPONSE", path_response_tx),
        ):
            if message in line:
                match = re.search(
                    r"dst=\((?P<ip>[^,]+), (?P<port>\d+)\) len=(?P<length>\d+)",
                    line,
                )
                if match:
                    ip = match.group("ip").removeprefix("::ffff:")
                    key = f"{ip}:{match.group('port')}"
                    entry = counts.setdefault(key, {"datagrams": 0, "payload_bytes": 0})
                    entry["datagrams"] += 1
                    entry["payload_bytes"] += int(match.group("length"))
        received = re.search(
            r"got (?:Initial|Handshake|Data) packet \(\d+ bytes\) from \(local: .*?, remote: ([^)]+)\)",
            line,
        )
        if received:
            remote_path = received.group(1)
            received_paths[remote_path] = received_paths.get(remote_path, 0) + 1
        if "new path validated" in line:
            validated_paths.append(line)
        if "iroh::socket::transports" in line:
            if "transport pending, dropped transmit" in line:
                send_result = "pending_drop"
            elif "dropped transmit" in line:
                send_result = "send_error"
            elif "sent transmit" in line:
                send_result = "sent"
            else:
                send_result = None
            if send_result is not None:
                udp_transport_events.append({"result": send_result, "source_line": line})
        if any(
            marker in line
            for marker in (
                "UDP baseline",
                "UDP final",
                "UDP delta",
                "UDP snapshot",
                "UDP interval",
                "SSH 流量统计：",
            )
        ):
            udp_path_events.append({"source_line": line})
    target_candidates = [
        address
        for event in candidates
        if event["role"] == "target"
        for address in event["ip_addrs"]
    ]
    peer_candidate_addresses = sorted(set(target_candidates) | set(nat_probe_tx))
    udp_transport_by_candidate = {}
    for event in udp_transport_events:
        matches = [
            address
            for address in peer_candidate_addresses
            if re.search(
                rf"(?<![0-9.]){re.escape(address)}(?![0-9])",
                event["source_line"],
            )
        ]
        event["candidate_destinations"] = matches
        for address in matches:
            counts = udp_transport_by_candidate.setdefault(
                address, {"sent": 0, "send_error": 0, "pending_drop": 0}
            )
            counts[event["result"]] += 1
    return {
        "candidate_events": candidates,
        "client_net_report_events": net_reports,
        "qnt_attempt_events": qnt_attempts,
        "noq_nat_traversal": {
            "negotiated_events": noq_negotiated,
            "reach_out_events": reach_out_events,
            "off_path_nat_probe_tx": nat_probe_tx,
            "off_path_path_response_tx": path_response_tx,
            "received_quic_packet_paths": received_paths,
            "validated_path_events": validated_paths,
        },
        "udp_transport_events": udp_transport_events,
        "udp_transport_by_candidate": udp_transport_by_candidate,
        "udp_path_events": udp_path_events,
    }


def verify(harness: Harness, *, reuse_login: bool = False) -> None:
    state = harness.load_state()
    config_path = harness.client_config
    if not config_path.is_file():
        client_config(harness)
    if reuse_login:
        harness.record("verify", "reuse-saved-api-token-login-session", status="passed")
    else:
        user_token = read_secret_file(Path(state["user_token_file"])).decode("utf-8")
        harness.protect_secret(user_token)
        harness.local(
            "verify",
            "verification-user-api-token-login",
            harness.kmesh_args(
                "ssh-token",
                "login",
                "--method",
                "token",
            ),
            env={"KMESH_TOKEN": user_token},
            timeout=30,
        )
    session_fingerprint = auth_session_fingerprint(harness, "ssh-token", state["username"])
    host_alias, known_host = fetch_target_host_key(harness, state)
    mode_suffix = "private" if state["server_mode"] == "private" else "public-direct"
    known_hosts = harness.run_dir / f"known_hosts-{mode_suffix}"
    write_private_file(known_hosts, known_host.encode())
    config_suffix = "" if mode_suffix == "private" else "-public-direct"
    ssh_config = harness.run_dir / f"ssh-token{config_suffix}.conf"
    alias = write_ssh_config(harness, state, "ssh-token", known_hosts, ssh_config)
    env = {
        "PATH": str(harness.args.client_binary.parent) + os.pathsep + os.environ.get("PATH", ""),
    }
    command = [
        "ssh",
        "-F",
        str(ssh_config),
        "-vv",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        alias,
        "hostname; exit 23",
    ]
    result = harness.local(
        "verify",
        "ssh-hostname-exit-23",
        command,
        env=env,
        timeout=SSH_NEW_CONNECTION_TIMEOUT_SECONDS,
        accepted=(23,),
    )
    hostname = result.stdout.decode("utf-8", "replace").strip()
    if not hostname:
        raise VerificationError("SSH returned exit 23 without a hostname")
    path_events = selected_paths(result.stderr)
    route_failures = route_attempt_failures(result.stderr, harness)
    if "deployment" in harness.report:
        harness.report["deployment"]["server_mode"] = state["server_mode"]
    harness.report["ssh_basic"] = {
        "mode": state["server_mode"],
        "source_revision": harness.args.artifact_revision,
        "client_binary_sha256": harness.report.get("client_artifact", {}).get("sha256"),
        "server_agent_binary_sha256": state.get("server_agent_binary_sha256"),
        "login_profile": "ssh-token",
        "reused_login_session": reuse_login,
        "auth_session_sha256": session_fingerprint,
        "target_id": state["target_id"],
        "hostname": hostname,
        "expected_exit_code": 23,
        "observed_exit_code": result.returncode,
        "host_key_source": "Ed25519 public key read over authenticated management SSH",
        "known_hosts_alias": host_alias,
        "path_events_in_stderr_order": path_events,
        "route_attempt_failures": route_failures,
        "initial_path": path_events[0] if path_events else None,
        "selected_path": path_events[-1] if path_events else None,
        "selected_path_observed": bool(path_events),
        "observed_direct_path": any(event["kind"] == "direct" for event in path_events),
    }
    harness.write_report()


def close_run_masters(harness: Harness) -> None:
    for config in harness.args.state_dir.glob("runs/*/ssh-*.conf"):
        text = config.read_text()
        match = re.search(r"(?m)^Host\s+(\S+)\s*$", text)
        if not match:
            continue
        subprocess.run(
            ["ssh", "-F", str(config), "-O", "exit", match.group(1)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )


def set_mode(harness: Harness, mode: str) -> None:
    state = harness.load_state()
    if state["server_mode"] == mode:
        harness.record("mode", "already-in-requested-mode", status="passed", details={"mode": mode})
        return
    close_run_masters(harness)
    target_unit = f"kmesh-iroh-verification-agent@{state['target_id']}.service"
    old_server_unit = SERVER_PUBLIC_UNIT if state["server_mode"] == "public-direct" else SERVER_PRIVATE_UNIT
    new_server_unit = SERVER_PUBLIC_UNIT if mode == "public-direct" else SERVER_PRIVATE_UNIT
    harness.ssh_raw("mode", "stop-new-target-agent", harness.args.target_ssh, f"systemctl stop {target_unit}")
    harness.ssh_raw("mode", "stop-current-new-server", harness.args.server_ssh, f"systemctl stop {old_server_unit}")
    harness.ssh_raw("mode", "start-requested-new-server", harness.args.server_ssh, f"systemctl start {new_server_unit}")
    wait_health(harness, "mode")
    harness.ssh_raw("mode", "restart-new-target-agent", harness.args.target_ssh, f"systemctl start {target_unit}")
    state["server_mode"] = mode
    harness.save_state(state)
    if "deployment" in harness.report:
        harness.report["deployment"]["server_mode"] = mode
        harness.write_report()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = kmesh_admin_json(harness, "admin", "targets", "list", label="wait-target-online")
        targets = expect_data(response, "targets", "wait-target-online")
        if any(item["target_id"] == state["target_id"] and item["online"] for item in targets):
            break
        time.sleep(1)
    else:
        raise VerificationError(f"target did not reconnect after switching to {mode}")


def _path_probe_sample(
    harness: Harness,
    seconds: int,
    ssh_config: Path | None,
    sample_index: int,
    restart_server_after_direct: bool,
) -> dict[str, Any]:
    if not 1 <= seconds <= SSH_CONNECT_TIMEOUT_SECONDS:
        raise VerificationError(
            f"path probe duration must be between 1 and {SSH_CONNECT_TIMEOUT_SECONDS} seconds"
        )
    state = harness.load_state()
    harness.report.setdefault(
        "deployment",
        {
            "target_id": state["target_id"],
            "target_name": state["target_name"],
            "server_mode": state["server_mode"],
        },
    )
    if "deployment" in harness.report:
        harness.report["deployment"]["server_mode"] = state["server_mode"]
    if restart_server_after_direct and state["server_mode"] != "private":
        raise VerificationError("control-disconnect probe requires the new private server mode")
    mode_suffix = "private" if state["server_mode"] == "private" else "public-direct"
    config_suffix = "" if mode_suffix == "private" else "-public-direct"
    ssh_config = ssh_config or harness.run_dir / f"ssh-token{config_suffix}.conf"
    if not ssh_config.is_file():
        candidates = sorted(
            harness.args.state_dir.glob(f"runs/*/ssh-token{config_suffix}.conf"),
            key=lambda path: path.stat().st_mtime,
        )
        if candidates:
            ssh_config = candidates[-1]
    if not ssh_config.is_file():
        raise VerificationError(f"SSH config for {mode_suffix} mode is missing")
    ssh_config = ssh_config.resolve()
    text = ssh_config.read_text()
    match = re.search(r"(?m)^Host\s+(\S+)\s*$", text)
    if not match:
        raise VerificationError("SSH config has no Host alias")
    alias = match.group(1)
    env = {
        "PATH": str(harness.args.client_binary.parent) + os.pathsep + os.environ.get("PATH", ""),
        "RUST_LOG": "iroh::net_report=debug,iroh::_events::qnt::init=debug,iroh::socket=debug,iroh::socket::transports=trace,iroh::socket::remote_map::remote_state=trace,portmapper=trace,igd_next=debug,noq_proto::connection=trace,noq_proto::connection::paths=trace,kmesh::client::proxy=trace",
    }
    process = subprocess.Popen(
        [
            "ssh",
            "-F",
            str(ssh_config),
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            alias,
            "sh -s",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **env},
        bufsize=0,
        start_new_session=True,
    )
    stdout_chunks = []
    stderr_chunks = []
    stderr_events = []
    pending_stderr = bytearray()
    selected_path_state = None
    process_started_at = time.monotonic()
    direct_wait_deadline = time.monotonic() + seconds
    command_sent_at = None
    script_sent_after_direct = False
    path_state_at_command = None
    direct_gate_remote_address = None
    process_deadline = None
    process_timed_out = False
    control_disconnect = None
    open_streams = {process.stdout, process.stderr}
    script = (
        b"hostname\nprintf '%s\\n' kmesh-path-probe-started\nsleep 8\nprintf '%s\\n' "
        b"kmesh-path-probe-complete\nexit 23\n"
        if restart_server_after_direct
        else b"hostname\nprintf '%s\\n' kmesh-path-probe-started\nsleep 1\nprintf '%s\\n' "
        b"kmesh-path-probe-complete\nexit 23\n"
    )
    while open_streams or process.poll() is None:
        now = time.monotonic()
        if command_sent_at is None and process.poll() is None and (
            (selected_path_state is not None and selected_path_state["kind"] == "direct")
            or now >= direct_wait_deadline
        ):
            script_sent_after_direct = (
                selected_path_state is not None and selected_path_state["kind"] == "direct"
            )
            path_state_at_command = (
                {
                    key: selected_path_state.get(key)
                    for key in ("source", "timestamp", "sample", "kind", "selected", "remote_address")
                }
                if selected_path_state
                else None
            )
            direct_gate_remote_address = (
                selected_path_state["remote_address"] if script_sent_after_direct else None
            )
            command_sent_at = now
            process_deadline = now + 25
            try:
                process.stdin.write(script)
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
        if command_sent_at is not None and process.poll() is None and now >= process_deadline:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process_timed_out = True
        readable, _, _ = select.select(list(open_streams), [], [], 0.1) if open_streams else ([], [], [])
        for stream in readable:
            chunk = os.read(stream.fileno(), 4096)
            if not chunk:
                open_streams.remove(stream)
                if stream is process.stderr and pending_stderr:
                    line = bytes(pending_stderr)
                    stderr_events.append((time.monotonic(), line))
                    for event in path_state_observations(line):
                        selected_path_state = update_selected_path_state(
                            selected_path_state, event
                        )
                    pending_stderr.clear()
                continue
            if stream is process.stdout:
                stdout_chunks.append(chunk)
                continue
            stderr_chunks.append(chunk)
            pending_stderr.extend(chunk)
            while b"\n" in pending_stderr:
                line, _, remaining = pending_stderr.partition(b"\n")
                line += b"\n"
                pending_stderr[:] = remaining
                stderr_events.append((time.monotonic(), line))
                for event in path_state_observations(line):
                    selected_path_state = update_selected_path_state(
                        selected_path_state, event
                    )
        if (
            restart_server_after_direct
            and script_sent_after_direct
            and control_disconnect is None
            and b"kmesh-path-probe-started" in b"".join(stdout_chunks)
        ):
            try:
                harness.ssh_raw(
                    "path-probe",
                    f"restart-private-control-server-during-direct-session-{sample_index}",
                    harness.args.server_ssh,
                    f"systemctl restart {SERVER_PRIVATE_UNIT}",
                    timeout=20,
                )
                wait_health(harness, "path-probe")
                target_id = state["target_id"]
                target_online_deadline = time.monotonic() + 20
                target_online = False
                while time.monotonic() < target_online_deadline:
                    try:
                        response = kmesh_admin_json(
                            harness,
                            "admin",
                            "targets",
                            "list",
                            label=f"wait-agent-online-after-control-restart-{sample_index}",
                            phase="path-probe",
                        )
                        targets = expect_data(
                            response,
                            "targets",
                            f"wait-agent-online-after-control-restart-{sample_index}",
                        )
                        if any(item["target_id"] == target_id and item["online"] for item in targets):
                            target_online = True
                            break
                    except (OSError, subprocess.SubprocessError, VerificationError, json.JSONDecodeError):
                        pass
                    time.sleep(0.5)
                control_disconnect = {
                    "performed": True,
                    "server_unit": SERVER_PRIVATE_UNIT,
                    "target_online_after_restart": target_online,
                    "active_direct_ssh_command_was_in_flight": True,
                }
            except (OSError, subprocess.SubprocessError, VerificationError, json.JSONDecodeError) as error:
                recovery_error = None
                try:
                    harness.ssh_raw(
                        "path-probe",
                        f"ensure-private-control-server-active-{sample_index}",
                        harness.args.server_ssh,
                        f"systemctl start {SERVER_PRIVATE_UNIT}",
                        timeout=20,
                    )
                    wait_health(harness, "path-probe")
                except (OSError, subprocess.SubprocessError, VerificationError, json.JSONDecodeError) as recovery:
                    recovery_error = harness.redact(str(recovery))
                control_disconnect = {
                    "performed": False,
                    "server_unit": SERVER_PRIVATE_UNIT,
                    "target_online_after_restart": False,
                    "error": harness.redact(str(error)),
                    "server_recovery_error": recovery_error,
                }
    if process.stdin and not process.stdin.closed:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
    returncode = process.wait()
    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)
    stdout_lines = stdout.decode("utf-8", "replace").splitlines()
    marker_observed = "kmesh-path-probe-complete" in stdout_lines
    hostname = next(
        (
            line
            for line in stdout_lines
            if line and line not in {"kmesh-path-probe-started", "kmesh-path-probe-complete"}
        ),
        "",
    )
    ssh_status = "passed" if returncode == 23 and hostname and marker_observed else "failed"
    harness.record(
        "path-probe",
        f"ssh-path-probe-{mode_suffix}-{sample_index}",
        status=ssh_status,
        exit_code=returncode,
        stdout_bytes=len(stdout),
        stderr=stderr,
        details={
            "direct_selected_before_script": script_sent_after_direct,
            "direct_wait_timeout_seconds": seconds,
            "direct_wait_elapsed_seconds": round(
                (command_sent_at or time.monotonic()) - process_started_at, 3
            ),
            "process_timed_out": process_timed_out,
        },
    )
    stderr_path = harness.run_dir / f"path-probe-{mode_suffix}-{sample_index}.stderr"
    stderr_path.write_bytes(stderr)
    os.chmod(stderr_path, 0o600)
    path_events = selected_paths(stderr)
    route_failures = route_attempt_failures(stderr, harness)
    path_state_events = path_state_observations(stderr)
    selected_path_events = [event for event in path_state_events if event["selected"]]
    final_selected_path = None
    for event in path_state_events:
        final_selected_path = update_selected_path_state(final_selected_path, event)
    diagnostics = endpoint_diagnostics(stderr)
    ssh_transfer_bytes = None
    in_flight_deltas = {}
    for event_time, raw_line in stderr_events:
        line = raw_line.decode("utf-8", "replace")
        if "SSH 流量统计：" in line:
            transfer_match = re.search(
                r"SSH 流量统计：本地→目标=(\d+) bytes；目标→本地=(\d+) bytes", line
            )
            if transfer_match:
                ssh_transfer_bytes = {
                    "local_to_target": int(transfer_match.group(1)),
                    "target_to_local": int(transfer_match.group(2)),
                }
        if command_sent_at is None or event_time < command_sent_at:
            continue
        interval_match = QUIC_PATH_SAMPLE_RE.search(line)
        if (
            interval_match
            and interval_match.group("sample") == "interval"
            and interval_match.group("kind") == "Direct"
            and interval_match.group("selected") == "true"
            and interval_match.group("address") == direct_gate_remote_address
        ):
            remote_address = interval_match.group("address")
            delta = in_flight_deltas.setdefault(remote_address, {"udp_tx_bytes": 0, "udp_rx_bytes": 0})
            delta["udp_tx_bytes"] += int(interval_match.group("tx"))
            delta["udp_rx_bytes"] += int(interval_match.group("rx"))
    direct_selected_path_deltas = [{"remote_address": address, **delta} for address, delta in in_flight_deltas.items()]
    path_delta_source = "in_flight_interval" if in_flight_deltas else None
    final_path_is_direct = bool(
        final_selected_path
        and final_selected_path["kind"] == "direct"
        and final_selected_path["remote_address"] == direct_gate_remote_address
    )
    p2p_status = (
        "passed"
        if ssh_status == "passed" and script_sent_after_direct and final_path_is_direct
        and any(
            item["udp_tx_bytes"] > 0 and item["udp_rx_bytes"] > 0
            for item in direct_selected_path_deltas
        )
        else "failed"
    )
    sample = {
        "status": p2p_status,
        "ssh_status": ssh_status,
        "p2p_status": p2p_status,
        "source_revision": harness.args.artifact_revision,
        "client_binary_sha256": harness.report.get("client_artifact", {}).get("sha256"),
        "server_agent_binary_sha256": state.get("server_agent_binary_sha256"),
        "duration_seconds": round(time.monotonic() - process_started_at, 3),
        "direct_wait_timeout_seconds": seconds,
        "direct_wait_elapsed_seconds": round(
            (command_sent_at or time.monotonic()) - process_started_at, 3
        ),
        "hostname": hostname,
        "marker_observed": marker_observed,
        "ssh_command_exit_code": returncode,
        "direct_selected_before_script": script_sent_after_direct,
        "direct_gate_remote_address": direct_gate_remote_address,
        "direct_gate_observation": path_state_at_command,
        "direct_gate_observation_source": (
            path_state_at_command.get("source") if path_state_at_command else None
        ),
        "process_timed_out": process_timed_out,
        "control_disconnect": control_disconnect
        if control_disconnect is not None
        else (
            {"performed": False, "reason": "direct path was not selected before SSH command"}
            if restart_server_after_direct
            else None
        ),
        "ssh_transfer_bytes": ssh_transfer_bytes,
        "ssh_transfer_summary_observed": ssh_transfer_bytes is not None,
        "direct_path_delta_source": path_delta_source if direct_selected_path_deltas else None,
        "direct_selected_path_ssh_udp_deltas": direct_selected_path_deltas,
        "direct_selected_path_udp_delta_observed": bool(direct_selected_path_deltas),
        "path_events_in_stderr_order": path_events,
        "route_attempt_failures": route_failures,
        "path_state_observations_in_stderr_order": path_state_events,
        "initial_path": selected_path_events[0] if selected_path_events else None,
        "selected_path": final_selected_path,
        "observed_direct_path": any(
            item["kind"] == "direct" for item in selected_path_events
        ),
        "stderr_file": str(stderr_path),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_bytes": len(stderr),
        "ssh_config": str(ssh_config),
        "debug_filter": env["RUST_LOG"],
        **diagnostics,
    }
    harness.report.setdefault(f"path_probe_{mode_suffix}_samples", []).append(sample)
    harness.write_report()
    return sample


def path_probe(
    harness: Harness,
    seconds: int,
    ssh_config: Path | None,
    repetitions: int,
    restart_server_after_direct: bool,
) -> None:
    if not 1 <= repetitions <= 3:
        raise VerificationError("path probe repetitions must be between one and three")
    if restart_server_after_direct and repetitions != 1:
        raise VerificationError("control-disconnect probe requires exactly one path sample")
    samples = [
        _path_probe_sample(
            harness,
            seconds,
            ssh_config,
            sample_index,
            restart_server_after_direct,
        )
        for sample_index in range(1, repetitions + 1)
    ]
    mode_suffix = "private" if harness.load_state()["server_mode"] == "private" else "public-direct"
    ssh_status = "passed" if all(sample["ssh_status"] == "passed" for sample in samples) else "failed"
    p2p_status = "passed" if all(sample["p2p_status"] == "passed" for sample in samples) else "failed"
    control_disconnect_status = None
    if restart_server_after_direct:
        control_disconnect_status = (
            "passed"
            if ssh_status == "passed"
            and samples[0]["p2p_status"] == "passed"
            and samples[0]["control_disconnect"]
            and samples[0]["control_disconnect"].get("performed")
            and samples[0]["control_disconnect"].get("target_online_after_restart")
            and samples[0]["control_disconnect"].get("active_direct_ssh_command_was_in_flight")
            else "failed"
        )
    harness.report[f"path_probe_{mode_suffix}"] = {
        "status": p2p_status,
        "ssh_status": ssh_status,
        "p2p_status": p2p_status,
        "control_disconnect_status": control_disconnect_status,
        "repetitions": len(samples),
        "samples": samples,
    }
    harness.write_report()


def rollback(harness: Harness) -> None:
    close_run_masters(harness)
    state = json.loads(harness.state_file.read_text()) if harness.state_file.is_file() else None
    if state:
        target_unit = f"kmesh-iroh-verification-agent@{state['target_id']}.service"
        harness.ssh_raw(
            "rollback", "stop-new-target-agent", harness.args.target_ssh, f"systemctl stop {target_unit}"
        )
    for unit in (SERVER_PRIVATE_UNIT, SERVER_PUBLIC_UNIT):
        harness.ssh_raw("rollback", f"stop-{unit}", harness.args.server_ssh, f"systemctl stop {unit}")
    harness.ssh_raw("rollback", "restore-old-server", harness.args.server_ssh, f"systemctl start {OLD_SERVER_UNIT}")
    harness.ssh_raw("rollback", "restore-old-target-agent", harness.args.target_ssh, f"systemctl start {OLD_AGENT_UNIT}")
    harness.report["rollback"] = {
        "status": "restored-old-units",
        "new_data_preserved": True,
        "server_mode_at_rollback": state["server_mode"] if state else None,
        "new_agent_target_known": bool(state),
    }
    harness.write_report()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.server_port <= 65535:
        parser.error("--server-port must be between 1 and 65535")
    if not args.server_addr or args.server_addr != args.server_addr.strip() or any(
        character in args.server_addr for character in "/?#@"
    ):
        parser.error("--server-addr must be an IP address or hostname without a scheme or path")
    try:
        address = ipaddress.ip_address(args.server_addr)
    except ValueError:
        if ":" in args.server_addr or "[" in args.server_addr or "]" in args.server_addr:
            parser.error("--server-addr must be an IP address or hostname without a scheme or path")
        host = args.server_addr
    else:
        host = f"[{address}]" if isinstance(address, ipaddress.IPv6Address) else str(address)
    args.issuer = f"https://{host}:{args.server_port}"
    if args.command == "plan":
        print_plan(args)
        return 0
    if args.command in {
        "stage",
        "stage-binary",
        "refresh-binary",
        "deploy",
        "verify",
        "key-login",
        "path-probe",
    } and not args.artifact_revision:
        parser.error("--artifact-revision is required for artifact staging and SSH evidence")
    harness = Harness(args)
    try:
        if args.command == "preflight":
            preflight(harness)
        elif args.command == "stage":
            stage(harness)
        elif args.command == "stage-binary":
            stage_binary(harness)
        elif args.command == "refresh-binary":
            upgrade_binary(harness)
        elif args.command == "deploy":
            deploy(harness)
        elif args.command == "verify":
            verify(harness, reuse_login=args.reuse_login)
        elif args.command == "key-login":
            verify_public_key_login(harness)
        elif args.command == "path-probe":
            path_probe(
                harness,
                args.seconds,
                args.ssh_config,
                args.repetitions,
                args.restart_server_after_direct,
            )
        elif args.command == "mode":
            set_mode(harness, args.value)
        elif args.command == "rollback":
            rollback(harness)
        else:
            raise VerificationError(f"unknown phase {args.command}")
    except (OSError, subprocess.SubprocessError, VerificationError, json.JSONDecodeError) as error:
        harness.report["failure"] = harness.redact(str(error))
        harness.write_report()
        print(
            json.dumps(
                {
                    "status": "failed",
                    "phase": args.command,
                    "report": str(harness.report_path),
                    "reason": harness.redact(str(error)),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1
    phase_status = "prepared" if args.command == "stage" else "passed"
    if args.command == "path-probe":
        state = harness.load_state()
        mode_suffix = "private" if state["server_mode"] == "private" else "public-direct"
        probe = harness.report[f"path_probe_{mode_suffix}"]
        harness.report["ssh_status"] = probe["ssh_status"]
        harness.report["p2p_status"] = probe["p2p_status"]
        phase_status = probe["p2p_status"]
        if probe.get("control_disconnect_status") == "failed":
            phase_status = "failed"
    harness.report["last_phase_status"] = phase_status
    harness.report["status"] = phase_status
    harness.write_report()
    result_fields = {"status": phase_status, "report_status": harness.report["status"]}
    if harness.report.get("p2p_status"):
        result_fields["ssh_status"] = harness.report["ssh_status"]
        result_fields["p2p_status"] = harness.report["p2p_status"]
        state = harness.load_state()
        mode_suffix = "private" if state["server_mode"] == "private" else "public-direct"
        probe = harness.report.get(f"path_probe_{mode_suffix}", {})
        if probe.get("control_disconnect_status"):
            result_fields["control_disconnect_status"] = probe["control_disconnect_status"]
    result_fields.update(
        {"phase": args.command, "report": str(harness.report_path), "events": len(harness.events)}
    )
    print(
        json.dumps(
            result_fields,
            ensure_ascii=False,
        )
    )
    return 1 if args.command == "path-probe" and phase_status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
