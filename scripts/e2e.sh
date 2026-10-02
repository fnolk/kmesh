#!/usr/bin/env bash
set -euo pipefail
umask 077
export RUST_LOG=kmesh=debug

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT_DIR/target"}
BUILD_BIN=${KMESH_BINARY:-"$TARGET_DIR/release/kmesh"}
TMP_DIR=$(mktemp -d "/tmp/km.XXXXXX")
BIN="$TMP_DIR/bin/kmesh"
SSHD_BIN=$(command -v sshd)
SERVER_PID=
SSHD_PID=
AGENT_PID=

cleanup() {
  local status=$?
  for pid in "$AGENT_PID" "$SERVER_PID" "$SSHD_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ $status -ne 0 ]]; then
    printf '端到端验证失败，临时日志目录：%s\n' "$TMP_DIR" >&2
    for log in "$TMP_DIR/server.log" "$TMP_DIR/sshd.log" "$TMP_DIR/agent.log" "$TMP_DIR/direct.err" "$TMP_DIR/scp.err" "$TMP_DIR/relay.err" "$TMP_DIR/disconnect.err"; do
      if [[ -f "$log" ]]; then
        printf '\n--- %s ---\n' "$(basename "$log")" >&2
        tail -n 80 "$log" >&2
      fi
    done
  fi
  if [[ "${KEEP_E2E_TMP:-0}" != 1 || $status -eq 0 ]]; then
    rm -rf "$TMP_DIR"
  else
    printf '调试数据已保留在 %s\n' "$TMP_DIR" >&2
  fi
  return "$status"
}
trap cleanup EXIT INT TERM

for tool in cargo ssh sshd ssh-keygen ssh-keyscan scp sftp openssl curl python3; do
  command -v "$tool" >/dev/null || { printf '缺少测试依赖：%s\n' "$tool" >&2; exit 2; }
done

run_timeout() {
  local seconds=$1
  shift
  python3 -c 'import subprocess,sys
try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]))
    raise SystemExit(result.returncode)
except subprocess.TimeoutExpired:
    print("command timed out", file=sys.stderr)
    raise SystemExit(124)' "$seconds" "$@"
}

if [[ -z "${KMESH_BINARY:-}" ]]; then
  cargo build --locked --release --bin kmesh --manifest-path "$ROOT_DIR/Cargo.toml"
fi
[[ -x "$BUILD_BIN" ]]
mkdir -p "$TMP_DIR/bin"
cp "$BUILD_BIN" "$BIN"
chmod 700 "$BIN"
PATH="$TMP_DIR/bin:$(dirname "$BIN"):$PATH"
export PATH

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

free_udp_port() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

SERVER_PORT=$(free_port)
SSHD_PORT=$(free_port)
STUN_PORT=$(free_udp_port)
SERVER_URL="https://localhost:$SERVER_PORT"
SERVER_DATA="$TMP_DIR/server-data"
CLIENT_DATA="$TMP_DIR/client-data"
AGENT_DATA="$TMP_DIR/agent-data"
ADMIN_PASSWORD='kmesh-e2e-initial-admin-secret'
USER_PASSWORD='kmesh-e2e-user-secret'
REMOTE_USER=$(id -un)

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TMP_DIR/ca.key" -out "$TMP_DIR/ca.crt" \
  -subj '/CN=kmesh-e2e-root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$TMP_DIR/server.key" \
  -out "$TMP_DIR/server.csr" -subj '/CN=localhost' >/dev/null 2>&1
cat >"$TMP_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$TMP_DIR/server.csr" -CA "$TMP_DIR/ca.crt" \
  -CAkey "$TMP_DIR/ca.key" -CAcreateserial -out "$TMP_DIR/server.crt" \
  -days 1 -sha256 -extfile "$TMP_DIR/server.ext" >/dev/null 2>&1
chmod 600 "$TMP_DIR/server.key"

"$BIN" server init --data-dir "$SERVER_DATA" --admin admin \
  --issuer "$SERVER_URL" --password-stdin <<<"$ADMIN_PASSWORD"
"$BIN" server run --data-dir "$SERVER_DATA" --issuer "$SERVER_URL" \
  --bind "127.0.0.1:$SERVER_PORT" --tls-cert "$TMP_DIR/server.crt" \
  --tls-key "$TMP_DIR/server.key" --stun-bind "0.0.0.0:$STUN_PORT" \
  >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --cacert "$TMP_DIR/ca.crt" \
    "$SERVER_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail --cacert "$TMP_DIR/ca.crt" \
  "$SERVER_URL/health" >/dev/null
printf 'HTTPS server 已就绪。\n'

ssh-keygen -q -t ed25519 -N '' -f "$TMP_DIR/user-key"
ssh-keygen -q -t ed25519 -N '' -f "$TMP_DIR/sshd-host-key"
install -d -m 700 "$TMP_DIR/ssh-home/.ssh"
install -m 600 "$TMP_DIR/user-key.pub" "$TMP_DIR/ssh-home/.ssh/authorized_keys"
cat >"$TMP_DIR/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $TMP_DIR/sshd-host-key
PidFile $TMP_DIR/sshd.pid
AuthorizedKeysFile $TMP_DIR/ssh-home/.ssh/authorized_keys
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
UsePAM no
AllowUsers $REMOTE_USER
Subsystem sftp internal-sftp
EOF
chmod 600 "$TMP_DIR/sshd_config"
"$SSHD_BIN" -t -f "$TMP_DIR/sshd_config"
"$SSHD_BIN" -D -e -f "$TMP_DIR/sshd_config" >"$TMP_DIR/sshd.log" 2>&1 &
SSHD_PID=$!
for _ in $(seq 1 20); do
  if ssh-keyscan -p "$SSHD_PORT" 127.0.0.1 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cat >"$TMP_DIR/agent.toml" <<EOF
server_url = "$SERVER_URL"
profile = "agent"
data_dir = "$AGENT_DATA"

[tls]
ca_certificates = ["$TMP_DIR/ca.crt"]

[ssh]
address = "127.0.0.1:$SSHD_PORT"
connect_timeout_secs = 10

[stun]
servers = ["127.0.0.1:$STUN_PORT"]
udp_bind_address = "0.0.0.0:0"
probe_timeout_millis = 2000
EOF

cat >"$TMP_DIR/client-direct.toml" <<EOF
server_url = "$SERVER_URL"
profile = "direct"
data_dir = "$CLIENT_DATA"

[tls]
ca_certificates = ["$TMP_DIR/ca.crt"]

[stun]
servers = ["127.0.0.1:$STUN_PORT"]
udp_bind_address = "0.0.0.0:0"
probe_timeout_millis = 2000
EOF

cat >"$TMP_DIR/client-relay.toml" <<EOF
server_url = "$SERVER_URL"
profile = "relay"
data_dir = "$CLIENT_DATA"

[tls]
ca_certificates = ["$TMP_DIR/ca.crt"]

[stun]
servers = ["127.0.0.1:1"]
udp_bind_address = "0.0.0.0:0"
probe_timeout_millis = 2000
EOF

ADMIN=("$BIN" --config "$TMP_DIR/client-direct.toml" --server-url "$SERVER_URL" --profile admin)
printf '%s\n' "$ADMIN_PASSWORD" | "${ADMIN[@]}" login --method password --username admin --password-stdin

target_json=$("${ADMIN[@]}" admin --json targets create e2e-target)
TARGET_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["target"]["target_id"])' <<<"$target_json")
ENROLLMENT_CODE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["enrollment_token"])' <<<"$target_json")

user_json=$(printf '%s\n%s\n' "$USER_PASSWORD" "$USER_PASSWORD" | \
  "${ADMIN[@]}" admin --json users create e2e-user --password-stdin)
USER_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["user_id"])' <<<"$user_json")
role_json=$("${ADMIN[@]}" admin --json roles create e2e-ssh-users)
ROLE_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["role_id"])' <<<"$role_json")
"${ADMIN[@]}" admin users roles "$USER_ID" "$ROLE_ID" >/dev/null
"${ADMIN[@]}" admin grants add "$ROLE_ID" "$TARGET_ID" >/dev/null
"${ADMIN[@]}" admin keys add "$USER_ID" "$TMP_DIR/user-key.pub" --label e2e >/dev/null

"$BIN" --config "$TMP_DIR/agent.toml" agent enroll \
  --target-id "$TARGET_ID" --enrollment-code "$ENROLLMENT_CODE"
"$BIN" --config "$TMP_DIR/agent.toml" agent run --target-id "$TARGET_ID" \
  >"$TMP_DIR/agent.log" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 30); do
  targets_json=$("${ADMIN[@]}" admin --json targets list 2>/dev/null || true)
  if python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; raise SystemExit(0 if any(t["target_id"] == sys.argv[1] and t["online"] for t in d) else 1)' "$TARGET_ID" <<<"$targets_json" 2>/dev/null; then
    break
  fi
  sleep 1
done
python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; raise SystemExit(0 if any(t["target_id"] == sys.argv[1] and t["online"] for t in d) else 1)' \
  "$TARGET_ID" <<<"$targets_json"
printf 'target agent 已上线。\n'

printf '%s\n' "$USER_PASSWORD" | "$BIN" --config "$TMP_DIR/client-direct.toml" \
  --profile direct login --method password --username e2e-user --password-stdin
"$BIN" --config "$TMP_DIR/client-direct.toml" --profile direct login \
  --method public-key --username e2e-user --key "$TMP_DIR/user-key"

"$BIN" --config "$TMP_DIR/client-direct.toml" --profile direct ssh-config "$TARGET_ID" \
  >"$TMP_DIR/direct.ssh_config"

HOST_KEY=$(awk '{print $1 " " $2}' "$TMP_DIR/sshd-host-key.pub")
printf 'kmesh/%s %s\n' "$TARGET_ID" "$HOST_KEY" >"$TMP_DIR/known_hosts"
chmod 600 "$TMP_DIR/known_hosts"

SSH_COMMON=(
  -o "UserKnownHostsFile=$TMP_DIR/known_hosts"
  -o GlobalKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=yes
  -o "IdentityFile=$TMP_DIR/user-key"
  -o IdentitiesOnly=yes
  -o "ControlPath=$TMP_DIR/direct-control-%C"
)
run_timeout 30 ssh -vvv -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'printf direct-ok' >"$TMP_DIR/direct.out" 2>"$TMP_DIR/direct.err"
grep -q 'direct-ok' "$TMP_DIR/direct.out"
grep -q 'P2P / QUIC' "$TMP_DIR/direct.err"
printf '直连 SSH host-key 验证通过。\n'

if run_timeout 30 ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'exit 23' >/dev/null 2>&1; then
  printf '远程非零退出码被吞掉。\n' >&2
  exit 1
else
  ssh_status=$?
fi
[[ "$ssh_status" -eq 23 ]] || {
  printf 'SSH 返回退出码 %s，预期 23。\n' "$ssh_status" >&2
  exit 1
}
printf '远程 SSH 退出码传递通过。\n'

printf 'scp-payload\n' >"$TMP_DIR/file-to-scp"
run_timeout 30 scp -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "$TMP_DIR/file-to-scp" "${REMOTE_USER}@e2e-target:/tmp/kmesh-e2e-scp-file" \
  >/dev/null 2>"$TMP_DIR/scp.err"
run_timeout 30 ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'cat /tmp/kmesh-e2e-scp-file' | grep -q '^scp-payload$'
printf 'SCP 文件传输通过。\n'

printf 'sftp-payload\n' >"$TMP_DIR/file-to-copy"
printf 'put %s /tmp/kmesh-e2e-file\n' "$TMP_DIR/file-to-copy" | \
  run_timeout 30 sftp -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
    "${REMOTE_USER}@e2e-target" >/dev/null 2>"$TMP_DIR/sftp.err"
run_timeout 30 ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'cat /tmp/kmesh-e2e-file' | grep -q '^sftp-payload$'
printf 'SFTP 文件传输通过。\n'
ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'true' >/dev/null
ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  -O check "${REMOTE_USER}@e2e-target" >/dev/null 2>&1

printf '%s\n' "$USER_PASSWORD" | "$BIN" --config "$TMP_DIR/client-relay.toml" \
  --profile relay login --method password --username e2e-user --password-stdin
"$BIN" --config "$TMP_DIR/client-relay.toml" --profile relay ssh-config "$TARGET_ID" \
  >"$TMP_DIR/relay.ssh_config"
run_timeout 30 ssh -F "$TMP_DIR/relay.ssh_config" \
  -o "UserKnownHostsFile=$TMP_DIR/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
  -o "IdentityFile=$TMP_DIR/user-key" -o IdentitiesOnly=yes \
  -o "ControlPath=$TMP_DIR/relay-control-%C" \
  "${REMOTE_USER}@e2e-target" 'printf relay-ok' \
  >"$TMP_DIR/relay.out" 2>"$TMP_DIR/relay.err"
grep -q 'relay-ok' "$TMP_DIR/relay.out"
python3 - "$SERVER_DATA/server.sqlite3" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    paths = {row[0] for row in db.execute("SELECT selected_path FROM tunnel_sessions") if row[0]}
assert {"quic", "relay"} <= paths, f"expected direct and relay audit paths, got {paths}"
PY
printf 'WSS relay SSH host-key 验证通过。\n'

python3 - "$CLIENT_DATA" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
matches = []
for path in root.glob("profiles/*/*/*.json"):
    state = json.loads(path.read_text())
    if state["username"] == "e2e-user" and state["profile"] == "direct":
        matches.append((path, state))
assert len(matches) == 1, f"expected one direct profile, found {len(matches)}"
path, state = matches[0]
state["tokens"]["access_expires_at"] = 0
path.write_text(json.dumps(state))
PY

refresh_pids=()
for index in $(seq 1 8); do
  "$BIN" --config "$TMP_DIR/client-direct.toml" --profile direct targets list \
    >"$TMP_DIR/refresh-$index.out" 2>"$TMP_DIR/refresh-$index.err" &
  refresh_pids+=("$!")
done
for pid in "${refresh_pids[@]}"; do wait "$pid"; done
printf '并发凭据刷新通过。\n'

"${ADMIN[@]}" admin grants remove "$ROLE_ID" "$TARGET_ID" >/dev/null
run_timeout 30 ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  "${REMOTE_USER}@e2e-target" 'printf existing-master-ok' \
  >"$TMP_DIR/existing-master.out" 2>"$TMP_DIR/existing-master.err"
grep -q 'existing-master-ok' "$TMP_DIR/existing-master.out"
printf '已有 ControlMaster 在撤权后继续工作。\n'
if run_timeout 15 ssh -F "$TMP_DIR/direct.ssh_config" \
  -o "UserKnownHostsFile=$TMP_DIR/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
  -o "IdentityFile=$TMP_DIR/user-key" -o IdentitiesOnly=yes \
  -o ControlMaster=no -o ControlPath=none \
  "${REMOTE_USER}@e2e-target" true >/dev/null 2>&1; then
  printf '撤销授权后新 transport 仍然成功。\n' >&2
  exit 1
fi

"${ADMIN[@]}" admin grants add "$ROLE_ID" "$TARGET_ID" >/dev/null
mkfifo "$TMP_DIR/ssh.stdin"
exec 9<>"$TMP_DIR/ssh.stdin"
remote_pid_file="$TMP_DIR/ssh-session.pid"
ssh -F "$TMP_DIR/direct.ssh_config" \
  -o "UserKnownHostsFile=$TMP_DIR/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
  -o "IdentityFile=$TMP_DIR/user-key" -o IdentitiesOnly=yes \
  -o ControlMaster=no -o ControlPath=none \
  "${REMOTE_USER}@e2e-target" "printf '%s' \$\$ > $remote_pid_file; exec sleep 300" \
  <"$TMP_DIR/ssh.stdin" >"$TMP_DIR/disconnect.out" 2>"$TMP_DIR/disconnect.err" &
disconnect_ssh_pid=$!
for _ in $(seq 1 15); do
  if [[ -f "$remote_pid_file" ]]; then
    break
  fi
  sleep 1
done
[[ -f "$remote_pid_file" ]] || { printf '测试SSH会话未建立。\n' >&2; exit 1; }
remote_shell_pid=$(/bin/cat "$remote_pid_file")
sshd_session_pid=$(/bin/ps -o ppid= -p "$remote_shell_pid" | tr -d ' ')
[[ -n "$sshd_session_pid" && "$sshd_session_pid" != "$SSHD_PID" ]] || {
  printf '无法定位活动SSHD会话进程。\n' >&2
  exit 1
}
kill "$sshd_session_pid"
kill "$remote_shell_pid" 2>/dev/null || true
disconnect_state=
for _ in $(seq 1 10); do
  disconnect_state=$(/bin/ps -o stat= -p "$disconnect_ssh_pid" 2>/dev/null | tr -d ' ' || true)
  if [[ -z "$disconnect_state" || "$disconnect_state" == Z* ]]; then
    break
  fi
  sleep 1
done
if [[ -n "$disconnect_state" && "$disconnect_state" != Z* ]]; then
  kill "$disconnect_ssh_pid" 2>/dev/null || true
  exec 9>&-
  wait "$disconnect_ssh_pid" 2>/dev/null || true
  printf 'SSH 代理在目标断线后仍未退出。\n' >&2
  exit 1
fi
wait "$disconnect_ssh_pid" 2>/dev/null || true
exec 9>&-
printf '目标 QUIC 断线已传给 OpenSSH，代理及时退出。\n'

ssh -F "$TMP_DIR/direct.ssh_config" "${SSH_COMMON[@]}" \
  -O exit "${REMOTE_USER}@e2e-target" >/dev/null 2>&1 || true
ssh -F "$TMP_DIR/relay.ssh_config" \
  -o "ControlPath=$TMP_DIR/relay-control-%C" -O exit \
  "${REMOTE_USER}@e2e-target" >/dev/null 2>&1 || true
printf '端到端验证通过：直连、relay、SSH host-key/退出码、SCP/SFTP、ControlMaster、RBAC、并发 refresh 与断线传播。\n'
