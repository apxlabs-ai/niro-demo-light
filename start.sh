#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -r requirements.txt
python seed.py

# Sidecar: poll /health and print a single readiness line once the server is
# up. Bounded to 30s; dies silently on timeout. Lets agents grep stdout for
# "→ helpdesk ready" instead of guessing sleep durations.
(
  for _ in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
      echo "→ helpdesk ready on http://127.0.0.1:8000"
      exit 0
    fi
    sleep 0.5
  done
) &

exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
