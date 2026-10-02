#!/usr/bin/env python3
"""Run kmesh against a real local sshd using isolated credentials and configs."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pathlib
import pwd
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOG_ROOT = ROOT / "target" / "e2e-logs"
SSH_KEYGEN = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
SSH = shutil.which("ssh") or "/usr/bin/ssh"
SCP = shutil.which("scp") or "/usr/bin/scp"
SFTP = shutil.which("sftp") or "/usr/bin/sftp"
SSHD = "/opt/homebrew/sbin/sshd" if pathlib.Path("/opt/homebrew/sbin/sshd").is_file() else (shutil.which("sshd") or "/usr/sbin/sshd")


class Harness:
    def __init__(self, binary: pathlib.Path, idle_seconds: int):
        self.binary = binary.resolve()
        self.idle_seconds = idle_seconds
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.logs = LOG_ROOT / f"native-{stamp}-{os.getpid()}"
        self.logs.mkdir(parents=True, exist_ok=False)
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="km-", dir="/tmp"))
        self.processes: list[subprocess.Popen[bytes]] = []
        self.services: list[subprocess.Popen[bytes]] = []
        self.events: list[dict[str, object]] = []
        self.direct_path_observed = False
        self.master_info: tuple[pathlib.Path, pathlib.Path] | None = None
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.binary.parent}{os.pathsep}{self.env.get('PATH', '')}"
        self.env["RUST_LOG"] = "kmesh::client::agent=debug"

    def record(self, name: str, detail: str = "") -> None:
        event = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "step": name, "detail": detail}
        self.events.append(event)
        (self.logs / "results.json").write_text(json.dumps(self.events, indent=2) + "\n")
        print(f"{name}" + (f"：{detail}" if detail else ""), flush=True)

    def run(
        self,
        name: str,
        argv: list[str | pathlib.Path],
        *,
        input_bytes: bytes | None = None,
        timeout: int = 120,
        check: bool = True,
        sensitive: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        args = [str(item) for item in argv]
        result = subprocess.run(
            args,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env or self.env,
            check=False,
        )
        if not sensitive:
            (self.logs / f"{name}.stdout").write_bytes(result.stdout)
            (self.logs / f"{name}.stderr").write_bytes(result.stderr)
        if check and result.returncode:
            detail = "sensitive command failed" if sensitive else result.stderr.decode(errors="replace")[-3000:]
            raise RuntimeError(f"{name} exited {result.returncode}: {detail}")
        return result

    def start(self, name: str, argv: list[str | pathlib.Path], *, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
        log = open(self.logs / f"{name}.log", "ab", buffering=0)
        process = subprocess.Popen(
            [str(item) for item in argv],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env or self.env,
            start_new_session=True,
        )
        self.processes.append(process)
        self.services.append(process)
        return process

    def stop(self, process: subprocess.Popen[bytes], timeout: int = 10) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    @staticmethod
    def port(socktype: int) -> int:
        with socket.socket(socket.AF_INET, socktype) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def cli(self, config: pathlib.Path, data: pathlib.Path, profile: str = "default") -> list[str]:
        return [str(self.binary), "--config", str(config), "--data-dir", str(data), "--profile", profile]

    def make_config(self, path: pathlib.Path, data: pathlib.Path, tls_port: int, stun_port: int, ssh_port: int) -> None:
        quote = json.dumps
        config = (
            f"profile = \"default\"\nserver_url = {quote(f'https://127.0.0.1:{tls_port}')}\n"
            f"data_dir = {quote(str(data))}\n\n"
            "[tls]\n"
            f"ca_certificates = [{quote(str(self.temp / 'tls' / 'ca.crt'))}]\n"
            'server_name = "127.0.0.1"\n\n'
            "[ssh]\n"
            f"address = {quote(f'127.0.0.1:{ssh_port}')}\nconnect_timeout_secs = 10\n\n"
            "[stun]\n"
            f"servers = [{quote(f'127.0.0.1:{stun_port}')} ]\n"
            'udp_bind_address = "0.0.0.0:0"\nprobe_timeout_millis = 2000\n'
        )
        path.write_text(config)
        path.chmod(0o600)

    def wait_tcp(self, port: int, process: subprocess.Popen[bytes], label: str) -> None:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{label} exited early; inspect {self.logs / (label + '.log')}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"{label} did not listen on 127.0.0.1:{port}")

    def wait_https(self, url: str, ca: pathlib.Path, process: subprocess.Popen[bytes]) -> None:
        context = ssl.create_default_context(cafile=str(ca))
        parsed = urllib.parse.urlsplit(url)
        deadline = time.monotonic() + 25
        last_error = "no response"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"server exited early; inspect {self.logs / 'server.log'}")
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=1)
            try:
                connection.request("GET", parsed.path)
                response = connection.getresponse()
                if response.status == 200 and response.read() == b"ok":
                    return
                last_error = f"HTTP status {response.status}"
            except Exception as error:
                last_error = repr(error)
            finally:
                connection.close()
            if time.monotonic() < deadline:
                time.sleep(0.15)
        raise RuntimeError(f"HTTPS health check failed for {url}: {last_error}")

    def generate_tls(self, directory: pathlib.Path) -> None:
        directory.mkdir(mode=0o700)
        ca_key = directory / "ca.key"
        ca_cert = directory / "ca.crt"
        server_key = directory / "server.key"
        csr = directory / "server.csr"
        ext = directory / "server.ext"
        ext.write_text(
            "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
            "extendedKeyUsage=serverAuth\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
        )
        self.run("tls-ca", ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "2", "-nodes", "-subj", "/CN=kmesh-e2e-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-keyout", ca_key, "-out", ca_cert])
        self.run("tls-server-key", ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", server_key, "-out", csr])
        self.run("tls-server-cert", ["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-days", "2", "-sha256", "-extfile", ext, "-out", directory / "server.crt"])
        ca_key.unlink()
        csr.unlink()
        ext.unlink()
        server_key.chmod(0o600)

    def generate_key(self, name: str, key_type: str = "ed25519") -> pathlib.Path:
        path = self.temp / "keys" / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.run(f"keygen-{name}", [SSH_KEYGEN, "-q", "-t", key_type, "-N", "", "-C", f"kmesh E2E {name}", "-f", path])
        path.chmod(0o600)
        return path

    def ssh_options(self, control_path: pathlib.Path, known_hosts: pathlib.Path, identity: pathlib.Path) -> list[str]:
        return [
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "IdentitiesOnly=yes",
            "-o", f"IdentityFile={identity}",
            "-o", "ControlMaster=no",
            "-o", f"ControlPath={control_path}",
            "-o", "ControlPersist=no",
            "-o", "ConnectTimeout=30",
            "-o", "BatchMode=yes",
        ]

    def ssh(self, name: str, config: pathlib.Path, options: list[str], remote: str, *, input_bytes: bytes | None = None, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        destination_and_command = shlex.split(remote)
        if not destination_and_command:
            raise ValueError("SSH destination is empty")
        return self.run(name, [SSH, "-F", config, *options, *destination_and_command], input_bytes=input_bytes, timeout=timeout, check=check)

    def ssh_config(self, config: pathlib.Path, data: pathlib.Path, profile: str, target: str, out: pathlib.Path) -> None:
        result = self.run(f"ssh-config-{profile}", [*self.cli(config, data, profile), "ssh-config", target])
        out.write_bytes(result.stdout)
        user = pwd.getpwuid(os.getuid()).pw_name
        with out.open("a") as file:
            file.write(
                f"Host e2e\n    HostName 127.0.0.1\n    User {user}\n"
                f"    IdentityFile {self.temp / 'keys' / 'user'}\n    IdentitiesOnly yes\n"
                f"    PreferredAuthentications publickey\n    PasswordAuthentication no\n"
            )
        out.chmod(0o600)

    def remote_hash(self, name: str, config: pathlib.Path, options: list[str], remote_path: str) -> str:
        utility = "shasum -a 256" if shutil.which("shasum") else "sha256sum"
        result = self.ssh(name, config, options, f"e2e {utility} {remote_path}")
        return result.stdout.decode().split()[0]

    def run_all(self) -> None:
        self.record("prepare isolated temporary TLS, users, agent, and sshd state")
        tls_dir = self.temp / "tls"
        self.generate_tls(tls_dir)
        server_dir = self.temp / "server-data"
        client_dir = self.temp / "client-data"
        admin_dir = self.temp / "admin-data"
        agent_dir = self.temp / "agent-data"
        for directory in (server_dir, client_dir, admin_dir, agent_dir):
            directory.mkdir(mode=0o700)

        tls_port = self.port(socket.SOCK_STREAM)
        stun_port = self.port(socket.SOCK_DGRAM)
        ssh_port = self.port(socket.SOCK_STREAM)
        issuer = f"https://127.0.0.1:{tls_port}"
        base_config = self.temp / "client.toml"
        self.make_config(base_config, client_dir, tls_port, stun_port, ssh_port)
        admin_config = self.temp / "admin.toml"
        self.make_config(admin_config, admin_dir, tls_port, stun_port, ssh_port)
        agent_config = self.temp / "agent.toml"
        self.make_config(agent_config, agent_dir, tls_port, stun_port, ssh_port)

        ca_cert = tls_dir / "ca.crt"
        server_cert = tls_dir / "server.crt"
        server_key = tls_dir / "server.key"
        admin_password = "KmeshE2E-Admin-2026!"
        user_password = "KmeshE2E-User-2026!"
        self.run("server-init", [self.binary, "--data-dir", server_dir, "server", "init", "--admin", "admin", "--password-stdin", "--issuer", issuer], input_bytes=(admin_password + "\n").encode())
        server = self.start("server", [self.binary, "--data-dir", server_dir, "server", "run", "--issuer", issuer, "--bind", f"127.0.0.1:{tls_port}", "--tls-cert", server_cert, "--tls-key", server_key, "--stun-bind", f"127.0.0.1:{stun_port}"])
        self.wait_https(f"{issuer}/health", ca_cert, server)
        self.record("server HTTPS/WSS TLS chain and STUN listeners are live", f"TLS {tls_port}, STUN UDP {stun_port}")

        ssh_user_key = self.generate_key("user")
        host_key = self.generate_key("sshd-host")
        wrong_host_key = self.generate_key("wrong-host")
        (self.temp / "ssh").mkdir(mode=0o700)
        ssh_home = self.temp / "sshd"
        ssh_home.mkdir(mode=0o700)
        authorized = ssh_home / "authorized_keys"
        authorized.write_bytes((ssh_user_key.with_suffix(".pub")).read_bytes())
        authorized.chmod(0o600)
        sshd_config = ssh_home / "sshd_config"
        ssh_user = pwd.getpwuid(os.getuid()).pw_name
        sshd_config.write_text(
            f"Port {ssh_port}\nListenAddress 127.0.0.1\nPidFile {ssh_home / 'sshd.pid'}\n"
            f"HostKey {host_key}\nAuthorizedKeysFile {authorized}\n"
            "StrictModes no\nUsePAM no\nPasswordAuthentication no\nPubkeyAuthentication yes\n"
            "PermitRootLogin no\nAllowUsers " + ssh_user + "\n"
            "AllowTcpForwarding no\nX11Forwarding no\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n"
        )
        sshd_config.chmod(0o600)
        self.run("sshd-config-check", [SSHD, "-t", "-f", sshd_config])
        sshd = self.start("sshd", [SSHD, "-D", "-e", "-f", sshd_config])
        self.wait_tcp(ssh_port, sshd, "sshd")
        self.record("isolated non-root OpenSSH server is live", f"sshd {ssh_port}, user {ssh_user}")

        admin_cli = self.cli(admin_config, admin_dir)
        self.run("admin-login", [*admin_cli, "login", "--method", "password", "--username", "admin", "--password-stdin"], input_bytes=(admin_password + "\n").encode())
        created_user = self.run("admin-create-user", [*admin_cli, "admin", "--json", "users", "create", "alice", "--password-stdin"], input_bytes=(user_password + "\n" + user_password + "\n").encode(), sensitive=True)
        created_user_json = json.loads(created_user.stdout)
        user_id = created_user_json["data"]["user_id"]
        created_role = self.run("admin-create-role", [*admin_cli, "admin", "--json", "roles", "create", "ssh-users"], sensitive=True)
        role_id = json.loads(created_role.stdout)["data"]["role_id"]
        created_target = self.run("admin-create-target", [*admin_cli, "admin", "--json", "targets", "create", "e2e"], sensitive=True)
        target_response = json.loads(created_target.stdout)["data"]
        target_id = target_response["target"]["target_id"]
        enrollment = target_response["enrollment_token"]
        self.run("admin-grant", [*admin_cli, "admin", "grants", "add", role_id, target_id, "--permission", "ssh-connect"])
        self.run("admin-assign-role", [*admin_cli, "admin", "users", "roles", user_id, role_id])
        self.run("admin-add-ssh-key", [*admin_cli, "admin", "keys", "add", user_id, str(ssh_user_key.with_suffix(".pub")), "--label", "e2e-key"])
        self.run("agent-enroll", [*self.cli(agent_config, agent_dir), "agent", "enroll", "--target-id", target_id, "--enrollment-code", enrollment], sensitive=True)
        enrollment = ""
        agent = self.start("agent", [*self.cli(agent_config, agent_dir), "agent", "run", "--target-id", target_id])
        deadline = time.monotonic() + 25
        online = False
        while time.monotonic() < deadline:
            result = self.run("targets-online", [*admin_cli, "admin", "--json", "targets", "list"], check=False, sensitive=True)
            if result.returncode == 0:
                target_views = json.loads(result.stdout)["data"]
                online = any(item["target_id"] == target_id and item["online"] for item in target_views)
                if online:
                    break
            if agent.poll() is not None:
                raise RuntimeError(f"agent exited; inspect {self.logs / 'agent.log'}")
            time.sleep(0.2)
        if not online:
            raise RuntimeError("agent did not become online")
        self.record("admin RBAC, SSH key registration, one-time enrollment, and online agent passed", f"target {target_id}")

        self.run("alice-password-login", [*self.cli(base_config, client_dir), "login", "--method", "password", "--username", "alice", "--password-stdin"], input_bytes=(user_password + "\n").encode())
        ssh_config = self.temp / "ssh_config"
        self.ssh_config(base_config, client_dir, "default", "e2e", ssh_config)
        known_hosts = self.temp / "known_hosts"
        host_public = host_key.with_suffix(".pub").read_text().split()
        known_hosts.write_text(f"kmesh/{target_id} {host_public[0]} {host_public[1]}\n")
        known_hosts.chmod(0o600)
        control_path = self.temp / "ssh" / "control-%C"
        options = self.ssh_options(control_path, known_hosts, ssh_user_key)
        result = self.ssh("ssh-direct-smoke", ssh_config, options, "e2e printf KMESH_DIRECT_OK")
        path_text = result.stderr.decode(errors="replace")
        if b"KMESH_DIRECT_OK" not in result.stdout or not any(path in path_text for path in ("连接路径：P2P / QUIC", "连接路径：relay")):
            raise RuntimeError("SSH smoke did not report a working transport path")
        self.direct_path_observed = "连接路径：P2P / QUIC" in path_text
        self.record("password login and SSH public-key authentication passed", "P2P/QUIC" if self.direct_path_observed else "WSS relay fallback")

        idle = subprocess.Popen(
            [SSH, "-F", str(ssh_config), *options, "-T", "e2e", "sleep 3600; printf IDLE_OK"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            start_new_session=True,
        )
        self.processes.append(idle)
        idle_started = time.monotonic()
        self.record("one-hour active SSH idle session started before remaining QA", "P2P/QUIC" if self.direct_path_observed else "WSS relay fallback")

        self.run("alice-public-key-login", [*self.cli(base_config, client_dir), "login", "--method", "public-key", "--username", "alice", "--key", ssh_user_key], sensitive=True)
        self.record("SSHSIG public-key login passed with a registered comment and ssh-keygen-derived canonical key")

        profile_files = list((client_dir / "profiles").glob("*/*/*.json"))
        login_file = next(path for path in profile_files if json.loads(path.read_text()).get("username") == "alice")
        login = json.loads(login_file.read_text())
        old_refresh = login["tokens"]["refresh_token"]
        login["tokens"]["access_expires_at"] = 0
        login_file.write_text(json.dumps(login))
        login_file.chmod(0o600)
        concurrent = []
        for index in range(8):
            concurrent.append(subprocess.Popen(
                [SSH, "-F", str(ssh_config), *options, "e2e", f"printf REFRESH_{index}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
            ))
        for index, process in enumerate(concurrent):
            stdout, stderr = process.communicate(timeout=180)
            if process.returncode != 0 or f"REFRESH_{index}".encode() not in stdout:
                raise RuntimeError(f"parallel refresh SSH {index} failed: {stderr.decode(errors='replace')[-1000:]}")
        refreshed = json.loads(login_file.read_text())
        if refreshed["tokens"]["refresh_token"] == old_refresh:
            raise RuntimeError("parallel refresh did not rotate the saved refresh token")
        self.record("eight parallel ProxyCommand processes serialized refresh and all completed SSH")

        wrong_hosts = self.temp / "wrong_known_hosts"
        wrong_public = wrong_host_key.with_suffix(".pub").read_text().split()
        wrong_hosts.write_text(f"kmesh/{target_id} {wrong_public[0]} {wrong_public[1]}\n")
        wrong_hosts.chmod(0o600)
        bad = self.ssh("ssh-wrong-hostkey", ssh_config, self.ssh_options(self.temp / "ssh" / "bad-%C", wrong_hosts, ssh_user_key), "e2e true", check=False)
        if bad.returncode == 0:
            raise RuntimeError("SSH accepted a deliberately incorrect pinned host key")
        self.record("strict SSH host-key pinning rejected a deliberately incorrect key")

        master_path = self.temp / "ssh" / "master-%C"
        master_options = [
            "-o", f"UserKnownHostsFile={known_hosts}", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "IdentitiesOnly=yes", "-o", f"IdentityFile={ssh_user_key}",
            "-o", "ControlMaster=yes", "-o", f"ControlPath={master_path}", "-o", "ControlPersist=5m", "-o", "BatchMode=yes",
        ]
        master_start = self.run("ssh-controlmaster-start", [SSH, "-F", ssh_config, *master_options, "-MNf", "e2e"], timeout=60)
        self.master_info = (ssh_config, master_path)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            checked = self.run("ssh-controlmaster-check", [SSH, "-F", ssh_config, "-o", f"ControlPath={master_path}", "-O", "check", "e2e"], check=False)
            if checked.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"OpenSSH ControlMaster did not become ready after parent exit {master_start.returncode}")
        reused = self.ssh("ssh-controlmaster-reuse", ssh_config, self.ssh_options(master_path, known_hosts, ssh_user_key), "e2e printf CONTROLMASTER_OK")
        if b"CONTROLMASTER_OK" not in reused.stdout:
            raise RuntimeError("SSH ControlMaster did not carry a command")
        self.run("ssh-controlmaster-exit", [SSH, "-F", ssh_config, "-o", f"ControlPath={master_path}", "-O", "exit", "e2e"], check=False)
        self.master_info = None
        self.record("OpenSSH ControlMaster reuse passed")

        small = self.temp / "sftp-source.bin"
        small_bytes = bytes(range(256)) * 4096
        small.write_bytes(small_bytes)
        remote_small = f"/tmp/kmesh-e2e-{uuid.uuid4().hex}.bin"
        batch = f"put {small} {remote_small}\nget {remote_small} {self.temp / 'sftp-copy.bin'}\nrm {remote_small}\n"
        self.run("sftp-roundtrip", [SFTP, "-F", ssh_config, *options, "-b", "-", "e2e"], input_bytes=batch.encode(), timeout=180)
        if (self.temp / "sftp-copy.bin").read_bytes() != small_bytes:
            raise RuntimeError("SFTP round-trip payload differed")
        remote_scp = f"/tmp/kmesh-e2e-{uuid.uuid4().hex}.bin"
        self.run("scp-small-upload", [SCP, "-F", ssh_config, *options, small, f"e2e:{remote_scp}"], timeout=180)
        local_hash = hashlib.sha256(small_bytes).hexdigest()
        remote_hash = self.remote_hash("scp-small-remote-hash", ssh_config, options, remote_scp)
        if remote_hash != local_hash:
            raise RuntimeError("SCP payload SHA-256 did not match")
        self.run("scp-small-remove", [*self.ssh_base(ssh_config, options), "e2e", f"rm -f {remote_scp}"])
        self.record("SFTP round-trip and SCP upload SHA-256 passed")

        large = self.temp / "one-gib.bin"
        self.run("create-one-gib", ["dd", "if=/dev/urandom", f"of={large}", "bs=1m", "count=1024"], timeout=300)
        large_hash = self.hash_file(large)
        remote_large = f"/tmp/kmesh-e2e-{uuid.uuid4().hex}-1g.bin"
        self.run("scp-one-gib-upload", [SCP, "-F", ssh_config, *options, "-o", "Compression=no", large, f"e2e:{remote_large}"], timeout=1800)
        actual_large_hash = self.remote_hash("scp-one-gib-remote-hash", ssh_config, options, remote_large)
        if actual_large_hash != large_hash:
            raise RuntimeError(f"1 GiB SCP hash mismatch: {large_hash} != {actual_large_hash}")
        self.run("scp-one-gib-remove", [*self.ssh_base(ssh_config, options), "e2e", f"rm -f {remote_large}"])
        large.unlink()
        self.record("actual 1 GiB SCP upload integrity passed", f"sha256 {large_hash}")

        relay_stun = self.port(socket.SOCK_DGRAM)
        blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole.bind(("127.0.0.1", relay_stun))
        relay_config = self.temp / "relay.toml"
        relay_dir = client_dir
        self.make_config(relay_config, relay_dir, tls_port, relay_stun, ssh_port)
        self.run("relay-profile-login", [*self.cli(relay_config, relay_dir, "relay"), "login", "--method", "password", "--username", "alice", "--password-stdin"], input_bytes=(user_password + "\n").encode())
        relay_ssh_config = self.temp / "relay_ssh_config"
        self.ssh_config(relay_config, relay_dir, "relay", "e2e", relay_ssh_config)
        relay_options = self.ssh_options(self.temp / "ssh" / "relay-%C", known_hosts, ssh_user_key)
        relayed = self.ssh("ssh-relay-smoke", relay_ssh_config, relay_options, "e2e printf KMESH_RELAY_OK")
        if b"KMESH_RELAY_OK" not in relayed.stdout or "连接路径：relay" not in relayed.stderr.decode(errors="replace"):
            raise RuntimeError("blackholed STUN client did not use the actual WSS relay path")
        half_close_bytes = bytes(range(251)) * 8192
        half_close = self.ssh("ssh-relay-half-close", relay_ssh_config, relay_options, "e2e cat", input_bytes=half_close_bytes, timeout=180)
        if half_close.stdout != half_close_bytes:
            raise RuntimeError("relay half-close echo payload differed")
        relay_remote = f"/tmp/kmesh-e2e-{uuid.uuid4().hex}-relay.bin"
        self.run("scp-relay-upload", [SCP, "-F", relay_ssh_config, *relay_options, small, f"e2e:{relay_remote}"], timeout=180)
        if self.remote_hash("scp-relay-hash", relay_ssh_config, relay_options, relay_remote) != local_hash:
            raise RuntimeError("relay SCP integrity check failed")
        self.run("scp-relay-remove", [*self.ssh_base(relay_ssh_config, relay_options), "e2e", f"rm -f {relay_remote}"])
        blackhole.close()
        self.record("blackholed UDP forced actual WSS relay; SSH, SFTP-compatible byte flow, SCP hash, and half-close passed")

        self.run("admin-revoke-target", [*admin_cli, "admin", "grants", "remove", role_id, target_id, "--permission", "ssh-connect"])
        denied = self.ssh("ssh-after-rbac-revoke", ssh_config, options, "e2e true", check=False)
        if denied.returncode == 0:
            raise RuntimeError("new SSH opened after dynamic RBAC revoke")
        if idle.poll() is not None:
            raise RuntimeError(f"existing idle SSH ended after revoke with status {idle.returncode}")
        self.record("RBAC revoke denied a new SSH open while the already active SSH stayed alive")

        idle_deadline = idle_started + self.idle_seconds
        while time.monotonic() < idle_deadline:
            remaining = int(idle_deadline - time.monotonic())
            if idle.poll() is not None:
                stdout, stderr = idle.communicate()
                raise RuntimeError(f"hour-idle SSH ended early status={idle.returncode}: {stderr.decode(errors='replace')[-1000:]} {stdout[-500:]!r}")
            time.sleep(min(60, max(1, remaining)))
            elapsed = int(time.monotonic() - idle_started)
            self.record("existing authorized SSH remains alive during idle window", f"{elapsed}/{self.idle_seconds} seconds")
        stdout, stderr = idle.communicate(timeout=30)
        if idle.returncode != 0 or b"IDLE_OK" not in stdout:
            raise RuntimeError(f"idle SSH did not complete: status={idle.returncode}, stderr={stderr.decode(errors='replace')[-1000:]}")
        self.record("one-hour SSH idle session completed after its original RBAC grant was revoked")

        self.stop(agent)
        self.stop(sshd)
        self.stop(server)
        self.record("all native SSH E2E assertions passed", f"direct_quic={self.direct_path_observed}; logs {self.logs}")

    @staticmethod
    def ssh_base(config: pathlib.Path, options: list[str]) -> list[str]:
        return [SSH, "-F", str(config), *options]

    @staticmethod
    def hash_file(path: pathlib.Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file:
            while chunk := file.read(8 * 1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def cleanup(self) -> None:
        if self.master_info is not None:
            config, path = self.master_info
            subprocess.run([SSH, "-F", str(config), "-o", f"ControlPath={path}", "-O", "exit", "e2e"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5)
        for process in reversed(self.processes):
            self.stop(process, timeout=5)
        shutil.rmtree(self.temp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default=ROOT / "target" / "debug" / "kmesh")
    parser.add_argument("--idle-seconds", type=int, default=3600)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0:
        parser.error("this native harness requires a non-root POSIX account and a local OpenSSH daemon")
    if not args.binary.is_file():
        parser.error(f"kmesh binary does not exist: {args.binary}; build it with cargo build --bin kmesh")
    harness = Harness(args.binary, args.idle_seconds)
    try:
        harness.run_all()
        return 0
    except BaseException as error:
        harness.record("E2E failed", str(error))
        raise
    finally:
        harness.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
