#!/usr/bin/env bash
set -euo pipefail

cd /home/ubuntu-25/rba
source /home/ubuntu-25/rba/.venv/bin/activate

INTERVAL_SECONDS=300   # 5 minutes

while true; do
  echo "[$(date -Is)] RBA run starting..."
  python -u /home/ubuntu-25/rba/rba_compute_snapshot_and_alert_once.py || echo "[$(date -Is)] RBA run failed (will retry)"
  echo "[$(date -Is)] RBA run finished. Sleeping ${INTERVAL_SECONDS}s..."
  sleep "${INTERVAL_SECONDS}"
done
