#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -r requirements.txt
export HELPDESK_SECRET="${HELPDESK_SECRET:-dev-helpdesk-secret-0000000000000000}"
python seed.py

# Background uvicorn, fully decoupled from the parent shell so the
# server survives if the caller's shell session terminates. nohup
# ignores SIGHUP; disown detaches from the parent's job table; the
# redirect keeps stdout/stderr off the parent shell. stop.sh cleans
# up by port (lsof :8000), so no PID file needed.
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload \
  > /tmp/helpdesk.log 2>&1 &
disown $! 2>/dev/null || true

# Wait until /health responds, then exit clean. Deterministic signal
# for agents and humans alike — no need to guess sleep durations.
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo "→ helpdesk ready on http://127.0.0.1:8000 (logs: /tmp/helpdesk.log)"
    exit 0
  fi
  sleep 0.5
done

echo "helpdesk failed to start within 30s; see /tmp/helpdesk.log" >&2
exit 1
