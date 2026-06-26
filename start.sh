#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${HELPDESK_SECRET:-}" ] || [ "${HELPDESK_SECRET:-}" = "dev-secret-do-not-use-in-prod" ]; then
  echo "HELPDESK_SECRET must be set to a non-placeholder JWT signing secret." >&2
  echo "Example: export HELPDESK_SECRET=\"$(openssl rand -hex 32)\"" >&2
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -r requirements.txt
python seed.py
bash niro/gen-credentials.sh

# Background uvicorn, fully decoupled from the parent shell so the
# server survives if the caller's shell session terminates. nohup
# ignores SIGHUP; disown detaches from the parent's job table; the
# redirect keeps stdout/stderr off the parent shell. stop.sh cleans
# up by port, so no PID file needed.

# Port 8000 — plain HTTP (Bearer token auth)
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload \
  > /tmp/helpdesk.log 2>&1 &
disown $! 2>/dev/null || true

# Port 8443 — HTTPS + mTLS (client cert auth, CERT_REQUIRED=2)
CERTS="$(dirname "$0")/niro/certs"
nohup uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile  "$CERTS/server.key" \
  --ssl-certfile "$CERTS/server.crt" \
  --ssl-ca-certs "$CERTS/ca.crt" \
  --ssl-cert-reqs 2 \
  > /tmp/helpdesk-tls.log 2>&1 &
disown $! 2>/dev/null || true

# Wait until both ports respond, then exit clean.
for _ in $(seq 1 60); do
  http_ok=false; tls_ok=false
  curl -sf  http://127.0.0.1:8000/health  >/dev/null 2>&1 && http_ok=true
  curl -sf --cacert "$CERTS/ca.crt" \
       --cert "$CERTS/client-agent.crt" \
       --key  "$CERTS/client-agent.key" \
       https://127.0.0.1:8443/health >/dev/null 2>&1 && tls_ok=true
  if $http_ok && $tls_ok; then
    echo "→ helpdesk ready on http://127.0.0.1:8000  (logs: /tmp/helpdesk.log)"
    echo "→ helpdesk ready on https://127.0.0.1:8443 (logs: /tmp/helpdesk-tls.log, mTLS)"
    exit 0
  fi
  sleep 0.5
done

echo "helpdesk failed to start within 30s" >&2
echo "  HTTP  logs: /tmp/helpdesk.log" >&2
echo "  HTTPS logs: /tmp/helpdesk-tls.log" >&2
exit 1
