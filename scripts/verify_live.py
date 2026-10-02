#!/usr/bin/env python3
"""Provision and verify a live kmesh SSH target without touching user SSH state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid


SERVER_URL = "https://192.0.2.11"
ORIGIN_HOST = "192.0.2.11"
TARGET_NAME = "target-1"
USER_NAME = "verification-ssh"
ROLE_NAME = "target-1-access"
SSH_ALIAS = "target-1-kmesh"
SSH_HOST = "target.example.com"
SSH_PORT = "5750"
SSH_USER = "root"
SSH_HOST_KEYS = pathlib.Path("/Users/example/.cache/kmesh-live/target/ssh-host-keys.pub")


def private_file(path: pathlib.Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(contents)
        file.flush()
        os.fsync(file.fileno())


def replace_private_file(path: pathlib.Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(contents)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def read_secret(path: pathlib.Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError(f"secret file must be a regular 0600 file: {path}")
    return path.read_bytes().rstrip(b"\r\n")


def cli_args(binary: pathlib.Path, config: pathlib.Path, data_dir: pathlib.Path, profile: str) -> list[str]:
    return [str(binary), "--config", str(config), "--data-dir", str(data_dir), "--profile", profile]


def command(
    name: str,
    argv: list[str | pathlib.Path],
    *,
    input_data: bytes | None = None,
    timeout: int = 60,
    check: bool = True,
    hide_output: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [str(arg) for arg in argv],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
        check=False,
    )
    if check and result.returncode:
        if hide_output:
            detail = "sensitive command failed; its output was withheld"
        else:
            detail = result.stderr.decode(errors="replace")[-2000:]
        raise RuntimeError(f"{name} exited {result.returncode}: {detail}")
    return result


def parse_admin(result: subprocess.CompletedProcess[bytes], action: str) -> dict[str, object]:
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"admin {action} did not return valid JSON") from error
    if not isinstance(payload, dict) or payload.get("result") is None:
        raise RuntimeError(f"admin {action} returned an unexpected response")
    return payload


class LiveVerification:
    def __init__(self, binary: pathlib.Path, cache: pathlib.Path, config: pathlib.Path):
        self.binary = binary.resolve()
        self.cache = cache
        self.client = cache / "client"
        self.data = self.client / "data"
        self.config = config
        self.admin_profile = "target-1-admin"
        self.user_profile = "target-1-live"
        self.admin_password_file = cache / "server" / "admin-password"
        self.user_password_file = self.client / "verification-ssh-password"
        self.enrollment_file = self.client / "enrollment.json"
        self.report_file = self.client / "report.json"
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.binary.parent}{os.pathsep}{self.env.get('PATH', '')}"
        self.results: dict[str, object] = {
            "server_url": SERVER_URL,
            "target_name": TARGET_NAME,
            "username": USER_NAME,
            "profile": self.user_profile,
            "config": str(self.config),
            "data_dir": str(self.data),
            "checks": {},
        }

    def ensure_local_state(self) -> None:
        for path in (self.cache, self.client, self.data, self.client / "control"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise RuntimeError(f"kmesh release binary is unavailable: {self.binary}")
        if not self.config.is_file():
            raise RuntimeError(f"live config is unavailable: {self.config}")
        if not (self.cache / "server" / "ca.pem").is_file():
            raise RuntimeError("live server CA is unavailable")
        read_secret(self.admin_password_file)

    def admin(self, *args: str, input_data: bytes | None = None, hide_output: bool = False) -> subprocess.CompletedProcess[bytes]:
        return command(
            "admin CLI",
            [*cli_args(self.binary, self.config, self.data, self.admin_profile), "admin", *args],
            input_data=input_data,
            hide_output=hide_output,
            timeout=120,
            env=self.env,
        )

    def provision(self) -> None:
        self.ensure_local_state()
        admin_password = read_secret(self.admin_password_file) + b"\n"
        command(
            "admin password login",
            [*cli_args(self.binary, self.config, self.data, self.admin_profile), "login", "--method", "password", "--username", "admin", "--password-stdin"],
            input_data=admin_password,
            hide_output=True,
            env=self.env,
        )

        if self.enrollment_file.exists() or self.user_password_file.exists():
            raise RuntimeError("live verification state already exists; use the existing profile and enrollment")
        target_result = self.admin("--json", "targets", "create", TARGET_NAME, hide_output=True)
        target_data = parse_admin(target_result, "target creation")["data"]
        if not isinstance(target_data, dict):
            raise RuntimeError("target creation returned an unexpected data object")
        target = target_data["target"]
        if not isinstance(target, dict):
            raise RuntimeError("target creation returned no target object")
        target_id = str(target["target_id"])
        private_file(
            self.enrollment_file,
            json.dumps(
                {"target_id": target_id, "enrollment_token": target_data["enrollment_token"]},
                separators=(",", ":"),
            ).encode(),
        )
        self.results["target_id"] = target_id
        self.results["enrollment_file"] = str(self.enrollment_file)

        user_password = secrets.token_urlsafe(30)
        private_file(self.user_password_file, (user_password + "\n").encode())
        user_result = self.admin(
            "--json", "users", "create", USER_NAME, "--password-stdin",
            input_data=(user_password + "\n" + user_password + "\n").encode(),
            hide_output=True,
        )
        user_data = parse_admin(user_result, "user creation")["data"]
        if not isinstance(user_data, dict):
            raise RuntimeError("user creation returned an unexpected data object")
        user_id = str(user_data["user_id"])

        role_result = self.admin("--json", "roles", "create", ROLE_NAME, hide_output=True)
        role_data = parse_admin(role_result, "role creation")["data"]
        if not isinstance(role_data, dict):
            raise RuntimeError("role creation returned an unexpected data object")
        role_id = str(role_data["role_id"])
        self.admin("grants", "add", role_id, target_id, "--permission", "ssh-connect")
        self.admin("users", "roles", user_id, role_id)
        self.results.update({"user_id": user_id, "role_id": role_id})
        self.save_report()
        print(f"live target 已创建：{target_id}")
        print(f"enrollment 文件已安全写入：{self.enrollment_file}")
        print(f"用户凭据文件已安全写入：{self.user_password_file}")

    def enrollment(self) -> dict[str, str]:
        info = self.enrollment_file.stat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("enrollment JSON must be a regular 0600 file")
        payload = json.loads(self.enrollment_file.read_text())
        return {"target_id": str(payload["target_id"]), "enrollment_token": str(payload["enrollment_token"])}

    def wait_agent_online(self, target_id: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.admin("--json", "targets", "list", hide_output=True)
            targets = parse_admin(result, "target list")["data"]
            if isinstance(targets, list) and any(
                item.get("target_id") == target_id and item.get("online") is True
                for item in targets if isinstance(item, dict)
            ):
                return
            time.sleep(2)
        raise RuntimeError(f"target agent did not become online within {timeout} seconds")

    def ensure_known_hosts(self, target_id: str) -> pathlib.Path:
        if not SSH_HOST_KEYS.is_file():
            raise RuntimeError(f"authenticated target SSH host keys are unavailable: {SSH_HOST_KEYS}")
        command("validate target host keys", ["ssh-keygen", "-lf", SSH_HOST_KEYS], env=self.env)
        entries = []
        for line in SSH_HOST_KEYS.read_text().splitlines():
            fields = line.split()
            if len(fields) < 2:
                raise RuntimeError("target host key file contains a malformed line")
            entries.append(f"kmesh/{target_id} {fields[0]} {fields[1]}")
        path = self.client / "known_hosts"
        replace_private_file(path, ("\n".join(entries) + "\n").encode())
        return path

    def write_ssh_config(self, profile: str, target_id: str, known_hosts: pathlib.Path, suffix: str) -> pathlib.Path:
        rendered = command(
            "render SSH config",
            [*cli_args(self.binary, self.config, self.data, profile), "ssh-config", TARGET_NAME],
            env=self.env,
        ).stdout.decode()
        rendered = rendered.replace(f"Host {TARGET_NAME}\n", f"Host {SSH_ALIAS}\n", 1)
        path = self.client / f"ssh_config.{suffix}"
        extra = (
            f"\nHost {SSH_ALIAS}\n"
            f"    HostName {SSH_HOST}\n    Port {SSH_PORT}\n    User {SSH_USER}\n"
            f"    UserKnownHostsFile {known_hosts}\n    StrictHostKeyChecking yes\n"
            "    IdentitiesOnly no\n    BatchMode yes\n    ConnectTimeout 20\n"
            f"    ControlPath {self.client / 'control' / '%C'}\n"
        )
        replace_private_file(path, (rendered + extra).encode())
        return path

    def ssh(self, config: pathlib.Path, remote_args: list[str], *, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[bytes]:
        return command(
            "OpenSSH over kmesh",
            ["ssh", "-F", config, "-o", "ControlMaster=no", "-o", f"ControlPath={self.client / 'control' / '%C'}", SSH_ALIAS, *remote_args],
            check=check,
            timeout=timeout,
            env=self.env,
        )

    @staticmethod
    def connection_path(stderr: bytes) -> str:
        text = stderr.decode(errors="replace")
        for path in ("P2P / QUIC", "relay"):
            if f"连接路径：{path}" in text:
                return path
        return "unreported"

    @staticmethod
    def file_sha256(path: pathlib.Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def stun_probe(self, timeout: float = 4.0) -> bool:
        transaction = secrets.token_bytes(12)
        request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + transaction
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.sendto(request, (ORIGIN_HOST, 3478))
            response, peer = sock.recvfrom(4096)
            return (
                len(response) >= 20 and response[:2] == b"\x01\x01"
                and response[4:8] == b"\x21\x12\xa4\x42"
                and response[8:20] == transaction and peer == (ORIGIN_HOST, 3478)
            )
        except TimeoutError:
            return False
        finally:
            sock.close()

    def verify_ssh_and_files(self, target_id: str, profile: str, known_hosts: pathlib.Path, suffix: str) -> dict[str, object]:
        config = self.write_ssh_config(profile, target_id, known_hosts, suffix)
        connected = self.ssh(config, ["hostname; uname -srm"])
        path = self.connection_path(connected.stderr)
        details = connected.stdout.decode(errors="replace").strip().splitlines()
        if len(details) < 2 or path == "unreported":
            raise RuntimeError("SSH did not return hostname, kernel, and a recognized kmesh path")
        exit_result = self.ssh(config, ["exit 23"], check=False)
        if exit_result.returncode != 23:
            raise RuntimeError(f"remote SSH exit code was {exit_result.returncode}, expected 23")

        work = pathlib.Path(tempfile.mkdtemp(prefix="live-", dir=self.data))
        os.chmod(work, 0o700)
        sftp_remote = f"/tmp/kmesh-live-{uuid.uuid4().hex}.bin"
        scp_remote = f"/tmp/kmesh-live-{uuid.uuid4().hex}.bin"
        try:
            source = work / "payload.bin"
            download = work / "download.bin"
            with source.open("wb") as file:
                remaining = 16 * 1024 * 1024
                while remaining:
                    chunk = os.urandom(min(1024 * 1024, remaining))
                    file.write(chunk)
                    remaining -= len(chunk)
            source_hash = self.file_sha256(source)
            ssh_options = ["-o", "ControlMaster=no", "-o", f"ControlPath={self.client / 'control' / '%C'}"]
            sftp_batch = f"put {source} {sftp_remote}\nget {sftp_remote} {download}\n"
            sftp = command(
                "SFTP round-trip",
                ["sftp", "-F", config, *ssh_options, "-b", "-", SSH_ALIAS],
                input_data=sftp_batch.encode(),
                timeout=300,
                env=self.env,
            )
            if self.file_sha256(download) != source_hash:
                raise RuntimeError("SFTP downloaded payload hash differs")

            command("SCP upload", ["scp", "-F", config, *ssh_options, source, f"{SSH_ALIAS}:{scp_remote}"], timeout=300, env=self.env)
            remote_hash = self.ssh(config, [f"sha256sum {shlex.quote(scp_remote)}"])
            actual_hash = remote_hash.stdout.decode().split()[0]
            if actual_hash != source_hash:
                raise RuntimeError("SCP remote SHA-256 differs")
        finally:
            for remote_path in (sftp_remote, scp_remote):
                self.ssh(config, [f"rm -f {shlex.quote(remote_path)}"], check=False, timeout=20)
            shutil.rmtree(work, ignore_errors=True)

        return {
            "hostname": details[0],
            "uname": details[1],
            "exit_code_test": exit_result.returncode,
            "path": path,
            "sftp_sha256": source_hash,
            "scp_sha256": actual_hash,
            "sftp_exit_code": sftp.returncode,
        }

    def verify_relay(self, target_id: str, known_hosts: pathlib.Path) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        config_text = self.config.read_text()
        config_text = config_text.replace(
            "servers = []", f'servers = ["127.0.0.1:{port}"]', 1
        )
        relay_config = self.client / "relay.toml"
        replace_private_file(relay_config, config_text.encode())
        password = read_secret(self.user_password_file) + b"\n"
        command(
            "relay profile login",
            [*cli_args(self.binary, relay_config, self.data, "target-1-relay"), "login", "--method", "password", "--username", USER_NAME, "--password-stdin"],
            input_data=password,
            hide_output=True,
            env=self.env,
        )
        config = self.write_ssh_config("target-1-relay", target_id, known_hosts, "relay")
        try:
            result = self.ssh(config, ["hostname"])
            path = self.connection_path(result.stderr)
            if path != "relay":
                raise RuntimeError(f"blackholed STUN did not force relay; actual path: {path}")
            return path
        finally:
            sock.close()

    def verify_rbac_retention(self, target_id: str, role_id: str, config: pathlib.Path) -> None:
        active_command = ["ssh", "-F", config, "-o", "ControlMaster=no", "-o", f"ControlPath={self.client / 'control' / '%C'}", SSH_ALIAS, "printf 'SESSION_STARTED\\n'; sleep 20; printf ACTIVE_SSH_OK"]
        active = subprocess.Popen(active_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        revoked = False
        try:
            assert active.stderr is not None
            assert active.stdout is not None
            import selectors

            selector = selectors.DefaultSelector()
            selector.register(active.stderr, selectors.EVENT_READ)
            selector.register(active.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 30
            observed_path = None
            session_started = False
            while time.monotonic() < deadline and active.poll() is None and (observed_path is None or not session_started):
                for key, _ in selector.select(timeout=1):
                    line = key.fileobj.readline()
                    if key.fileobj is active.stderr:
                        path = self.connection_path(line)
                        if path != "unreported":
                            observed_path = path
                    elif b"SESSION_STARTED" in line:
                        session_started = True
            selector.close()
            if observed_path is None or not session_started:
                raise RuntimeError("SSH did not establish its kmesh path and remote command before RBAC revoke")

            self.admin("grants", "remove", role_id, target_id, "--permission", "ssh-connect")
            revoked = True
            denied = self.ssh(config, ["true"], check=False)
            if denied.returncode == 0:
                raise RuntimeError("new SSH was accepted after RBAC revoke")
            stdout, stderr = active.communicate(timeout=35)
            if active.returncode != 0 or b"ACTIVE_SSH_OK" not in stdout:
                raise RuntimeError(f"pre-revoke SSH failed while grant was revoked: {stderr.decode(errors='replace')[-1000:]}")
            self.results["rbac_existing_session_path"] = observed_path
            self.results["rbac_new_connection_after_revoke"] = "denied"
        finally:
            if active.poll() is None:
                active.terminate()
                try:
                    active.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    active.kill()
                    active.wait(timeout=5)
            if revoked:
                self.admin("grants", "add", role_id, target_id, "--permission", "ssh-connect")

    def verify(self, agent_timeout: int) -> None:
        self.ensure_local_state()
        enrollment = self.enrollment()
        target_id = enrollment["target_id"]
        self.results["target_id"] = target_id
        try:
            self.wait_agent_online(target_id, agent_timeout)
            self.results["agent_online"] = True
            self.results["stun_binding_response"] = self.stun_probe()

            password = read_secret(self.user_password_file) + b"\n"
            command(
                "verification user login",
                [*cli_args(self.binary, self.config, self.data, self.user_profile), "login", "--method", "password", "--username", USER_NAME, "--password-stdin"],
                input_data=password,
                hide_output=True,
                env=self.env,
            )
            known_hosts = self.ensure_known_hosts(target_id)
            direct_report = self.verify_ssh_and_files(target_id, self.user_profile, known_hosts, "direct")
            self.results["ssh"] = direct_report
            self.results["relay_path"] = self.verify_relay(target_id, known_hosts)

            role_result = self.admin("--json", "roles", "list", hide_output=True)
            roles = parse_admin(role_result, "role list")["data"]
            role = next((item for item in roles if item.get("name") == ROLE_NAME), None)
            if role is None:
                raise RuntimeError("live SSH role disappeared")
            direct_config = self.client / "ssh_config.direct"
            self.verify_rbac_retention(target_id, str(role["role_id"]), direct_config)
            restored = self.ssh(direct_config, ["hostname"])
            self.results["ssh_after_restore"] = {
                "hostname": restored.stdout.decode(errors="replace").strip().splitlines()[0],
                "path": self.connection_path(restored.stderr),
            }
        finally:
            self.results["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            self.save_report()
        print("live SSH/SCP/SFTP/RBAC 验证完成")
        print(f"脱敏报告：{self.report_file}")

    def save_report(self) -> None:
        data = json.dumps(self.results, ensure_ascii=False, indent=2).encode() + b"\n"
        temporary = self.report_file.with_name(f".{self.report_file.name}.{os.getpid()}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, self.report_file)
        os.chmod(self.report_file, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "/Users/example/GitHub/kmesh/target"))
    parser.add_argument("--binary", type=pathlib.Path, default=default_target / "aarch64-apple-darwin" / "release" / "kmesh")
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path("/Users/example/.cache/kmesh-live"))
    parser.add_argument("--config", type=pathlib.Path, default=pathlib.Path("/Users/example/.cache/kmesh-live/client/config.toml"))
    parser.add_argument("--mode", choices=("provision", "verify"), required=True)
    parser.add_argument("--agent-timeout", type=int, default=900)
    args = parser.parse_args()
    verifier = LiveVerification(args.binary, args.cache, args.config)
    try:
        if args.mode == "provision":
            verifier.provision()
        else:
            verifier.verify(args.agent_timeout)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        verifier.results["error"] = str(error)
        verifier.results["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        verifier.save_report()
        print(f"live verification 未完成：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
