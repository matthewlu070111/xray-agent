#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/xray-agent"
VENV_DIR="${APP_DIR}/venv"
AGENT_PY="${APP_DIR}/agent.py"
ENV_FILE="/etc/default/xray-agent"
SERVICE_FILE="/etc/systemd/system/xray-agent.service"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[-] 请用 root 执行：sudo bash $0"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_install_if_missing() {
  # args: pkg...
  local missing=()
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if (( ${#missing[@]} > 0 )); then
    echo "[*] 安装依赖: ${missing[*]}"
    apt-get update -y
    apt-get install -y "${missing[@]}"
  fi
}

prompt() {
  # prompt "提示" "默认值" -> echo value
  local msg="$1"
  local def="$2"
  local val=""
  if [[ -n "$def" ]]; then
    read -r -p "${msg} [默认: ${def}] : " val
    echo "${val:-$def}"
  else
    read -r -p "${msg} : " val
    echo "$val"
  fi
}

gen_token() {
  if have_cmd openssl; then
    openssl rand -hex 16
  else
    # fallback：尽量保证可用（仍建议装 openssl）
    python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
  fi
}

validate_url() {
  local u="$1"
  if [[ "$u" != http://* && "$u" != https://* ]]; then
    echo "[-] PANEL_BASE 必须以 http:// 或 https:// 开头"
    exit 1
  fi
}

guess_xray_bin() {
  if have_cmd xray; then
    command -v xray
  else
    echo "/usr/local/bin/xray"
  fi
}

guess_xray_config() {
  local xbin="$1"
  local d
  d="$(dirname "$xbin")"
  if [[ -f "${d}/config.json" ]]; then
    echo "${d}/config.json"
  elif [[ -f "/etc/xray/config.json" ]]; then
    echo "/etc/xray/config.json"
  elif [[ -f "/usr/local/etc/xray/config.json" ]]; then
    echo "/usr/local/etc/xray/config.json"
  else
    echo "/etc/xray/config.json"
  fi
}

write_agent_py() {
  cat > "$AGENT_PY" <<'PYCODE'
import json, time, hashlib, subprocess, requests, os, re

# ====== 环境变量配置 ======
PANEL_BASE = os.environ.get("PANEL_BASE", "").rstrip("/")
NODE_NAME  = os.environ.get("NODE_NAME", "")
NODE_TOKEN = os.environ.get("NODE_TOKEN", "")
XRAY_CONFIG = os.environ.get("XRAY_CONFIG", "/usr/local/etc/xray/config.json")
XRAY_SERVICE = os.environ.get("XRAY_SERVICE", "xray")
XRAY_API = os.environ.get("XRAY_API", "127.0.0.1:10086")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "30"))
INBOUND_TAG = os.environ.get("INBOUND_TAG", "vless-in")
# =============================

HEADERS = {"X-Node": NODE_NAME, "X-Token": NODE_TOKEN}

def sh(cmd):
  subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sh_out(cmd):
  return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")

def fetch_desired_users():
  r = requests.get(PANEL_BASE + "/agent/users", headers=HEADERS, timeout=10)
  r.raise_for_status()
  return r.json()

def heartbeat():
  r = requests.post(PANEL_BASE + "/agent/heartbeat", headers=HEADERS, timeout=10)
  r.raise_for_status()

def stat_one(name: str) -> int:
  try:
    out = sh_out(["xray","api","stats","--server",XRAY_API,"-name",name]).strip()

    # 直接就是数字
    if out.isdigit():
      return int(out)

    # 抓最后一个数字
    m = re.findall(r"\d+", out)
    return int(m[-1]) if m else 0
  except Exception:
    return 0

def report_usage(desired_users):
  items = []
  for u in desired_users:
    email = u["email"]
    up = stat_one(f"user>>>{email}>>>traffic>>>uplink")
    down = stat_one(f"user>>>{email}>>>traffic>>>downlink")
    items.append({"email": email, "uplink": up, "downlink": down})

  payload = {"items": items, "ts": int(time.time())}
  r = requests.post(PANEL_BASE + "/agent/report", headers=HEADERS, json=payload, timeout=10)
  r.raise_for_status()

def load_config():
  with open(XRAY_CONFIG, "r", encoding="utf-8") as f:
    return json.load(f)

def save_config(cfg):
  tmp = XRAY_CONFIG + ".tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
  os.replace(tmp, XRAY_CONFIG)

def hash_clients(clients):
  b = json.dumps(clients, ensure_ascii=False, sort_keys=True).encode("utf-8")
  return hashlib.sha256(b).hexdigest()

def build_clients(desired_users):
  enabled = [u for u in desired_users if u.get("enabled")]
  clients = []
  for u in enabled:
    clients.append({
      "id": u["uuid"],
      "email": u["email"],
      "flow": u.get("flow") or "xtls-rprx-vision"
    })
  return clients

def apply_users_to_config(cfg, desired_users) -> bool:
  clients = build_clients(desired_users)

  inbounds = cfg.get("inbounds", [])
  target = None
  for ib in inbounds:
    if ib.get("tag") == INBOUND_TAG:
      target = ib
      break
  if not target:
    raise RuntimeError(f"cannot find inbound tag={INBOUND_TAG} in {XRAY_CONFIG}")

  settings = target.setdefault("settings", {})
  old_clients = settings.get("clients", [])
  if hash_clients(old_clients) == hash_clients(clients):
    return False

  settings["clients"] = clients
  return True

def restart_xray():
  sh(["systemctl", "restart", XRAY_SERVICE])

def fetch_actions(limit=50):
  r = requests.get(PANEL_BASE + f"/agent/actions?limit={limit}", headers=HEADERS, timeout=10)
  r.raise_for_status()
  return r.json()

def action_done(action_id: int, status: str, message: str = ""):
  r = requests.post(PANEL_BASE + "/agent/actions/done", headers=HEADERS,
                    json={"id": action_id, "status": status, "message": message},
                    timeout=10)
  r.raise_for_status()

def process_actions():
  actions = fetch_actions()
  need_sync = False

  for a in actions:
    try:
      # 这三类都标记需要立即 sync（更快收敛）
      if a["action"] in ("sync", "enable", "disable"):
        need_sync = True
      action_done(a["id"], "done", "")
    except Exception as e:
      try:
        action_done(a["id"], "failed", str(e))
      except Exception:
        pass

  return need_sync

def do_sync_once():
  heartbeat()
  desired = fetch_desired_users()
  cfg = load_config()
  changed = apply_users_to_config(cfg, desired)
  if changed:
    save_config(cfg)
    restart_xray()
  report_usage(desired)

def main():
  while True:
    try:
      need_sync = process_actions()
      if need_sync:
        do_sync_once()
      else:
        # 常规轮询
        do_sync_once()
    except Exception as e:
        print("agent loop error:", e, flush=True)
    time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
  main()
PYCODE
  chmod 755 "$AGENT_PY"
}

write_systemd() {
  cat > "$SERVICE_FILE" <<'SVC'
[Unit]
Description=Xray Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/xray-agent
WorkingDirectory=/opt/xray-agent
ExecStart=/opt/xray-agent/venv/bin/python3 /opt/xray-agent/agent.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC
}

main() {
  need_root

  echo "[1/8] 校验并安装依赖（python3/venv/pip/openssl/curl/ca-certificates）..."
  apt_install_if_missing python3 python3-venv ca-certificates curl openssl

  echo "[2/8] 交互输入配置..."
  local default_xray_bin default_xray_config
  default_xray_bin="$(guess_xray_bin)"
  XRAY_BIN="$(prompt "XRAY 可执行文件路径（which xray）" "$default_xray_bin")"

  if [[ ! -x "$XRAY_BIN" ]]; then
    echo "[-] XRAY_BIN 不可执行：$XRAY_BIN"
    echo "    先确认 xray 已安装，并给出正确路径（例如 /usr/local/bin/xray）"
    exit 1
  fi

  default_xray_config="$(guess_xray_config "$XRAY_BIN")"
  XRAY_CONFIG="$(prompt "Xray 配置文件路径（会被 agent 写入 clients）" "$default_xray_config")"

  if [[ ! -f "$XRAY_CONFIG" ]]; then
    echo "[-] XRAY_CONFIG 不存在：$XRAY_CONFIG"
    echo "    你可以先创建/复制好配置文件再运行脚本。"
    exit 1
  fi

  XRAY_SERVICE="$(prompt "Xray systemd 服务名（用于重启）" "xray")"

  INBOUND_TAG="$(prompt "Xray inbound tag（config 中 vless inbound 的 tag）" "vless-in")"

  XRAY_API_PORT="$(prompt "Xray API 端口（你 xray dokodemo-door listen 的端口）" "10086")"
  if ! [[ "$XRAY_API_PORT" =~ ^[0-9]+$ ]]; then
    echo "[-] 端口必须是数字"
    exit 1
  fi
  XRAY_API="127.0.0.1:${XRAY_API_PORT}"

  PANEL_BASE="$(prompt "B机面板域名（agent 访问的 base url）" "https://ap.techninja.top")"
  validate_url "$PANEL_BASE"

  NODE_NAME="$(prompt "本节点 node_name（必须和面板 nodes.name 一致）" "node-1")"

  token_in="$(prompt "本节点 node_token（回车自动生成）" "")"
  if [[ -z "$token_in" ]]; then
    NODE_TOKEN="$(gen_token)"
    echo "[*] 已生成 NODE_TOKEN：$NODE_TOKEN"
    echo "    记得在 B 机面板创建/更新节点 token 与此一致"
  else
    NODE_TOKEN="$token_in"
  fi

  SYNC_INTERVAL="$(prompt "同步间隔 SYNC_INTERVAL（秒）" "30")"
  if ! [[ "$SYNC_INTERVAL" =~ ^[0-9]+$ ]]; then
    echo "[-] SYNC_INTERVAL 必须是数字"
    exit 1
  fi

  echo "[3/8] 创建目录并初始化 venv..."
  mkdir -p "$APP_DIR"
  python3 -m venv "$VENV_DIR"

  echo "[4/8] 安装 Python 依赖 requests..."
  "$VENV_DIR/bin/pip" install --upgrade pip wheel >/dev/null
  "$VENV_DIR/bin/pip" install requests >/dev/null

  echo "[5/8] 写入 agent.py..."
  write_agent_py

  echo "[6/8] 写入环境变量文件 ${ENV_FILE} ..."
  cat > "$ENV_FILE" <<EOF
PANEL_BASE=${PANEL_BASE}
NODE_NAME=${NODE_NAME}
NODE_TOKEN=${NODE_TOKEN}
XRAY_CONFIG=${XRAY_CONFIG}
XRAY_SERVICE=${XRAY_SERVICE}
XRAY_API=${XRAY_API}
INBOUND_TAG=${INBOUND_TAG}
SYNC_INTERVAL=${SYNC_INTERVAL}
EOF
  chmod 600 "$ENV_FILE"

  echo "[7/8] 写入 systemd service 并启动..."
  write_systemd
  systemctl daemon-reload
  systemctl enable --now xray-agent

  echo "[8/8] 安装完成 ✅"
  echo "  - 配置文件：$ENV_FILE（以后改域名/端口/interval 就改这里）"
  echo "  - 查看日志：journalctl -u xray-agent -f"
  echo "  - 重启服务：systemctl restart xray-agent"
}

main
