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
import json
import os
import re
import secrets
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


ISSUER_DEFAULT = "https://192.0.2.11:9443"
SERVER_DEFAULT = "root@192.0.2.11"
TARGET_DEFAULT = "target-1"
REMOTE_ROOT = "/opt/kmesh-iroh-verification"
OLD_SERVER_UNIT = "kmesh-verification-server-9443.service"
OLD_AGENT_UNIT = "kmesh-verification-agent.service"
SERVER_PRIVATE_UNIT = "kmesh-iroh-verification-server-private.service"
SERVER_PUBLIC_UNIT = "kmesh-iroh-verification-server-public.service"
AGENT_UNIT = "kmesh-iroh-verification-agent@.service"
ADMIN_PASSWORD_DEFAULT = Path("/Users/example/.cache/kmesh-live/server/admin-password")
CA_DEFAULT = Path("/Users/example/.cache/kmesh-live/server/ca.pem")
STATE_DEFAULT = Path("/Users/example/.cache/kmesh-live/client/iroh-integrated-20261003")
REMOTE_RUNNER = (
    "import json,subprocess,sys; "
    "secret=sys.stdin.buffer.read(); "
    "args=[secret.decode() if x=='__KMESH_SECRET_STDIN__' else x for x in sys.argv[1:]]; "
    "p=subprocess.run(args,input=(b'' if '__KMESH_SECRET_STDIN__' in sys.argv[1:] else secret),"
    "stdout=subprocess.PIPE,stderr=subprocess.PIPE); "
    "err=p.stderr.decode('utf-8','replace'); "
    "err=err.replace(secret.decode('utf-8','replace'),'<redacted>') if secret else err; "
    "print(json.dumps({'exit_code':p.returncode,'stdout_bytes':len(p.stdout),"
    "'stderr':err[-4096:]},ensure_ascii=False)); sys.exit(p.returncode)"
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
            r"(?i)(password|enrollment[_ -]?token|access[_ -]?token|refresh[_ -]?token|secret)"
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
        timeout: float = 30,
        accepted: tuple[int, ...] = (0,),
    ) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any] | None]:
        remote_argv = ["python3", "-c", REMOTE_RUNNER, *argv]
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
            "--data-dir",
            str(self.client_state),
            "--profile",
            profile,
            "--server-url",
            self.args.issuer,
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


def server_units(issuer: str) -> dict[str, str]:
    base = (
        f"{REMOTE_ROOT}/bin/kmesh --data-dir {REMOTE_ROOT}/server-data "
        f"server run --issuer {issuer} --bind 0.0.0.0:9443 "
        f"--tls-cert {REMOTE_ROOT}/tls/server-cert.pem "
        f"--tls-key {REMOTE_ROOT}/tls/server-key.pem --qad-bind 0.0.0.0:3478"
    )
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
            exec_start=base + " --disable-private-relay", mode="public default relay"
        ),
    }


def agent_unit(issuer: str) -> str:
    return f"""[Unit]
Description=kmesh Iroh verification agent for target %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={REMOTE_ROOT}/bin/kmesh --data-dir {REMOTE_ROOT}/agent-data --server-url {issuer} agent run --target-id %i
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
    parser.add_argument("--issuer", default=ISSUER_DEFAULT)
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
    parser.add_argument("--admin-password-file", type=Path, default=ADMIN_PASSWORD_DEFAULT)
    parser.add_argument("--run-id", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print planned boundaries without contacting hosts")
    subparsers.add_parser("preflight", help="read-only host, service, binary, and port checks")
    subparsers.add_parser("stage", help="write isolated files and initialize the new database")
    subparsers.add_parser("stage-binary", help="copy a new Linux artifact into inactive temp paths and verify SHA-256")
    subparsers.add_parser("refresh-binary", help="atomically update only the staged verification server and agent")
    subparsers.add_parser("deploy", help="transition from old services to the staged new services")
    verify_parser = subparsers.add_parser("verify", help="run password login or reuse its saved session, then test SSH")
    verify_parser.add_argument("--reuse-login", action="store_true")
    subparsers.add_parser("key-login", help="verify SSHSIG login with an isolated temporary ssh-agent")
    probe = subparsers.add_parser("path-probe", help="keep one SSH command active briefly and record Iroh path changes")
    probe.add_argument("--seconds", type=int, default=8)
    probe.add_argument("--ssh-config", type=Path, default=None)
    mode = subparsers.add_parser("mode", help="switch only the new deployment between relay modes")
    mode.add_argument("value", choices=("private", "public-default"))
    subparsers.add_parser("rollback", help="stop new units and restore the preserved old services")
    return parser


def print_plan(args: argparse.Namespace) -> None:
    plan = {
        "stage": [
            "read-only preflight; fail if /opt/kmesh-iroh-verification already exists",
            "copy the Linux musl binary, reuse the existing TLS files, write two new server units and one agent template",
            "initialize a fresh SQLite data directory using the admin password through stdin",
            "leave both old units, binaries, and data running and untouched",
        ],
        "stage-binary": [
            "upload a replacement Linux binary to a temporary path on the new server and target",
            "verify both SHA-256 values while the running new services remain active",
        ],
        "refresh-binary": [
            "stop only the current new target agent and the active new server mode",
            "atomically install the verified binary on both new hosts and restart in the same mode",
            "reuse the schema 3 database, target UUID, and persistent agent identity",
        ],
        "deploy": [
            "stop the old target agent, then the old public server to release TCP 9443 and UDP 3478",
            "start the new private server with its isolated database",
            "create a new user, role, target, and grant; enroll the target through a 0600 token file piped to remote Python stdin",
            "start one new target agent and wait for the new target to report online",
        ],
        "verify": [
            "password login in an isolated kmesh profile, then real OpenSSH hostname and expected exit code 23",
            "record the Iroh-selected path and remote address; the relay-mode label alone is not direct-path evidence",
            "key-login verifies SSHSIG with a separate temporary SSH_AUTH_SOCK; verify_iroh_ssh.py runs the extended SSH checks",
            "write only sanitized results to a 0600 evidence report; preserve raw secrets in protected files/stdin",
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
    if not args.admin_password_file.is_file():
        raise VerificationError("--admin-password-file does not exist")


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
    for unit, contents in server_units(args.issuer).items():
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
        stdin=agent_unit(args.issuer).encode(),
    )
    agent_config = (
        f"server_url = {json.dumps(args.issuer)}\n"
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

    admin_password = read_secret_file(args.admin_password_file)
    harness.protect_secret(admin_password.decode("utf-8", "replace"))
    init_command = [
        f"{REMOTE_ROOT}/bin/kmesh",
        "--data-dir",
        f"{REMOTE_ROOT}/server-data",
        "server",
        "init",
        "--admin",
        "verification-admin",
        "--issuer",
        args.issuer,
        "--password-stdin",
    ]
    harness.remote(
        "stage",
        "initialize-new-server-database",
        args.server_ssh,
        init_command,
        stdin=admin_password + b"\n",
        timeout=30,
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
    if state["server_mode"] not in {"private", "public-default"}:
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
    for host, label in hosts:
        observed = remote_binary_hash(
            harness, "refresh-binary", f"{label}-verify-staged-sha256", host, staged_path
        )
        if observed != expected:
            raise VerificationError(f"{label} staged binary SHA-256 does not match requested artifact")

    close_run_masters(harness)
    target_unit = f"kmesh-iroh-verification-agent@{state['target_id']}.service"
    server_unit = (
        SERVER_PUBLIC_UNIT if state["server_mode"] == "public-default" else SERVER_PRIVATE_UNIT
    )
    harness.ssh_raw(
        "refresh-binary", "stop-new-target-agent", harness.args.target_ssh, f"systemctl stop {target_unit}"
    )
    harness.ssh_raw(
        "refresh-binary", "stop-current-new-server", harness.args.server_ssh, f"systemctl stop {server_unit}"
    )
    for host, label in hosts:
        swap = f"{REMOTE_ROOT}/bin/kmesh.swap"
        previous = f"{REMOTE_ROOT}/bin/kmesh.previous"
        command = (
            f"test ! -e {previous} && cp -p {current_path} {previous} && "
            f"install -m 0755 {staged_path} {swap} && mv -f {swap} {current_path} && "
            f"rm {staged_path}"
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
        "legacy_deployment_touched": False,
    }
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
        f"server_url = {json.dumps(args.issuer)}\n"
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


def admin_login(harness: Harness) -> bytes:
    password = read_secret_file(harness.args.admin_password_file)
    harness.protect_secret(password.decode("utf-8", "replace"))
    result = harness.local(
        "deploy",
        "administrator-password-login",
        harness.kmesh_args(
            "admin",
            "login",
            "--method",
            "password",
            "--username",
            "verification-admin",
            "--password-stdin",
        ),
        input_data=password + b"\n",
        timeout=30,
    )
    if result.returncode != 0:
        raise VerificationError("administrator login failed")
    return password


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

    password = secrets.token_urlsafe(32)
    password_path = args.state_dir / "verification-user-password"
    write_private_file(password_path, password.encode() + b"\n")
    harness.protect_secret(password)
    user = expect_data(
        kmesh_admin_json(
            harness,
            "admin",
            "users",
            "create",
            username,
            "--password-stdin",
            input_data=(password + "\n" + password + "\n").encode(),
            label="create-user",
        ),
        "user",
        "create-user",
    )
    user_id = user["user_id"]
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
        "user_password_file": str(password_path),
        "role_id": role_id,
        "role_name": role_name,
        "server_mode": "private",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    harness.save_state(state)

    enroll_args = [
        f"{REMOTE_ROOT}/bin/kmesh",
        "--server-url",
        args.issuer,
        "--data-dir",
        f"{REMOTE_ROOT}/agent-data",
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
        "  ConnectTimeout 15\n"
        "  ServerAliveInterval 20\n"
        "  ServerAliveCountMax 2\n"
    )
    write_private_file(config_path, (rendered + extra).encode())
    return alias


def selected_paths(stderr: bytes) -> list[dict[str, str]]:
    text = stderr.decode("utf-8", "replace")
    pattern = re.compile(
        r"连接路径(?P<change>切换)?：(?P<label>P2P 直连|Iroh 中继) \((?P<address>[^)]+)\)"
    )
    return [
        {
            "sequence": index,
            "event": "change" if match.group("change") else "initial",
            "kind": "direct" if match.group("label") == "P2P 直连" else "relay",
            "remote_address": match.group("address"),
        }
        for index, match in enumerate(pattern.finditer(text), start=1)
    ]


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
    for line in lines:
        candidate_match = re.search(r"target_ip_addrs=\[([^\]]*)\]", line)
        if candidate_match:
            candidates.append(
                {
                    "ip_addrs": [item.strip() for item in candidate_match.group(1).split(",") if item.strip()],
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
    return {"target_candidate_events": candidates, "client_net_report_events": net_reports}


def verify(harness: Harness, *, reuse_login: bool = False) -> None:
    state = harness.load_state()
    config_path = harness.client_config
    if not config_path.is_file():
        client_config(harness)
    if reuse_login:
        harness.record("verify", "reuse-saved-password-login-session", status="passed")
    else:
        password = read_secret_file(Path(state["user_password_file"]))
        harness.protect_secret(password.decode("utf-8", "replace"))
        harness.local(
            "verify",
            "verification-user-password-login",
            harness.kmesh_args(
                "ssh-password",
                "login",
                "--method",
                "password",
                "--username",
                state["username"],
                "--password-stdin",
            ),
            input_data=password + b"\n",
            timeout=30,
        )
    session_fingerprint = auth_session_fingerprint(harness, "ssh-password", state["username"])
    host_alias, known_host = fetch_target_host_key(harness, state)
    mode_suffix = "private" if state["server_mode"] == "private" else "public-default"
    known_hosts = harness.run_dir / f"known_hosts-{mode_suffix}"
    write_private_file(known_hosts, known_host.encode())
    config_suffix = "" if mode_suffix == "private" else "-public-default"
    ssh_config = harness.run_dir / f"ssh-password{config_suffix}.conf"
    alias = write_ssh_config(harness, state, "ssh-password", known_hosts, ssh_config)
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
        timeout=30,
        accepted=(23,),
    )
    hostname = result.stdout.decode("utf-8", "replace").strip()
    if not hostname:
        raise VerificationError("SSH returned exit 23 without a hostname")
    path_events = selected_paths(result.stderr)
    if "deployment" in harness.report:
        harness.report["deployment"]["server_mode"] = state["server_mode"]
    harness.report["ssh_basic"] = {
        "mode": state["server_mode"],
        "login_profile": "ssh-password",
        "reused_login_session": reuse_login,
        "auth_session_sha256": session_fingerprint,
        "target_id": state["target_id"],
        "hostname": hostname,
        "expected_exit_code": 23,
        "observed_exit_code": result.returncode,
        "host_key_source": "Ed25519 public key read over authenticated management SSH",
        "known_hosts_alias": host_alias,
        "path_events_in_stderr_order": path_events,
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
    old_server_unit = SERVER_PUBLIC_UNIT if state["server_mode"] == "public-default" else SERVER_PRIVATE_UNIT
    new_server_unit = SERVER_PUBLIC_UNIT if mode == "public-default" else SERVER_PRIVATE_UNIT
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


def path_probe(harness: Harness, seconds: int, ssh_config: Path | None) -> None:
    if not 1 <= seconds <= 30:
        raise VerificationError("path probe duration must be between 1 and 30 seconds")
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
    mode_suffix = "private" if state["server_mode"] == "private" else "public-default"
    config_suffix = "" if mode_suffix == "private" else "-public-default"
    ssh_config = ssh_config or harness.run_dir / f"ssh-password{config_suffix}.conf"
    if not ssh_config.is_file():
        candidates = sorted(
            harness.args.state_dir.glob(f"runs/*/ssh-password{config_suffix}.conf"),
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
        "RUST_LOG": "iroh::net_report=debug,kmesh::client::proxy=debug",
    }
    result = harness.local(
        "path-probe",
        f"ssh-path-probe-{mode_suffix}",
        [
            "ssh",
            "-F",
            str(ssh_config),
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            alias,
            f"hostname; sleep {seconds}; echo kmesh-path-probe-complete",
        ],
        env=env,
        timeout=seconds + 25,
    )
    stderr_path = harness.run_dir / f"path-probe-{mode_suffix}.stderr"
    stderr_path.write_bytes(result.stderr)
    os.chmod(stderr_path, 0o600)
    path_events = selected_paths(result.stderr)
    stdout_lines = result.stdout.decode("utf-8", "replace").splitlines()
    marker_observed = "kmesh-path-probe-complete" in stdout_lines
    if not marker_observed:
        raise VerificationError("path probe command did not return its completion marker")
    diagnostics = endpoint_diagnostics(result.stderr)
    harness.report[f"path_probe_{mode_suffix}"] = {
        "status": "passed",
        "duration_seconds": seconds,
        "hostname": stdout_lines[0] if stdout_lines else "",
        "marker_observed": marker_observed,
        "path_events_in_stderr_order": path_events,
        "initial_path": path_events[0] if path_events else None,
        "selected_path": path_events[-1] if path_events else None,
        "observed_direct_path": any(item["kind"] == "direct" for item in path_events),
        "stderr_file": str(stderr_path),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "ssh_config": str(ssh_config),
        "debug_filter": env["RUST_LOG"],
        **diagnostics,
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
    if args.command == "plan":
        print_plan(args)
        return 0
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
            path_probe(harness, args.seconds, args.ssh_config)
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
    harness.report["status"] = "prepared" if args.command == "stage" else "passed"
    harness.write_report()
    print(
        json.dumps(
            {
                "status": harness.report["status"],
                "phase": args.command,
                "report": str(harness.report_path),
                "events": len(harness.events),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
