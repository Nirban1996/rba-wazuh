#!/usr/bin/env bash
set -euo pipefail

echo "[+] RBA setup starting..."

if [ ! -d "$HOME/rba" ]; then
  echo "[-] ~/rba not found. Copy your working ~/rba folder here first."
  exit 1
fi

cd "$HOME/rba"

echo "[+] Installing OS packages..."
sudo apt update -y
sudo apt install -y python3 python3-venv python3-pip curl

echo "[+] Creating virtualenv (if missing)..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

echo "[+] Installing Python deps..."
source .venv/bin/activate
python -m pip install -U pip
pip install python-dotenv opensearch-py pandas plotly streamlit streamlit-autorefresh

echo "[+] Creating .env (only if missing)..."
if [ ! -f ".env" ]; then
  cat > .env <<'ENV'
# --- OpenSearch / Wazuh indexer ---
OS_HOST=192.168.227.128
OS_PORT=9200
OS_USER=admin
OS_PASS=admin
OS_SSL=true
OS_VERIFY_CERTS=false

# --- RBA knobs ---
RBA_TIME_WINDOW_HOURS=24
RBA_HALF_LIFE_MINUTES=240
RBA_QUERY_SIZE=2000

RBA_BASELINE_WINDOW_HOURS=1
RBA_K_SIGMA=3
RBA_DELTA_MIN=1
RBA_ALERT_COOLDOWN_MINUTES=60
RBA_TOP_CONTRIBUTORS=5
RBA_MAX_ALERTS_PER_RUN=20
RBA_MIN_SIGMA=0.1
ENV
  echo "[!] Created ~/rba/.env with defaults (edit if needed)."
else
  echo "[+] .env already exists (keeping it)."
fi

chmod 600 .env || true

echo "[+] Sanity compile check..."
python -m py_compile rba_compute_snapshot_and_alert_once.py
python -m py_compile rba_dashboard.py
echo "[+] Python compile OK."

echo "[+] Creating runner script..."
cat > run_rba.sh <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/rba"
source "$HOME/rba/.venv/bin/activate"
python "$HOME/rba/rba_compute_snapshot_and_alert_once.py"
RUN
chmod +x run_rba.sh

USER_NAME="$(whoami)"
HOME_DIR="$HOME"

echo "[+] Installing systemd service + timer..."
sudo tee /etc/systemd/system/rba-engine.service > /dev/null <<SERVICE
[Unit]
Description=RBA engine (compute state + snapshots + alerts)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${USER_NAME}
WorkingDirectory=${HOME_DIR}/rba
EnvironmentFile=${HOME_DIR}/rba/.env
ExecStart=${HOME_DIR}/rba/run_rba.sh
SERVICE

sudo tee /etc/systemd/system/rba-engine.timer > /dev/null <<TIMER
[Unit]
Description=Run RBA engine every minute

[Timer]
OnBootSec=30
OnUnitActiveSec=60
Unit=rba-engine.service
AccuracySec=5

[Install]
WantedBy=timers.target
TIMER

sudo systemctl daemon-reload
sudo systemctl enable --now rba-engine.timer

echo "[+] Timer status:"
sudo systemctl status rba-engine.timer --no-pager || true

echo
echo "[+] DONE."
echo "Next:"
echo "  1) Edit .env if needed: nano ~/rba/.env"
echo "  2) Test engine once:   source ~/rba/.venv/bin/activate && python ~/rba/rba_compute_snapshot_and_alert_once.py"
echo "  3) Run dashboard:      source ~/rba/.venv/bin/activate && streamlit run ~/rba/rba_dashboard.py --server.address 0.0.0.0 --server.port 8501"
echo "  4) Logs:               sudo journalctl -u rba-engine.service -n 60 --no-pager"
