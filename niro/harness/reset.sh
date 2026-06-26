#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${NIRO_PROJECT_ROOT:-$(cd "$CONFIG_DIR/.." && pwd)}"
RUN_DIR="$CONFIG_DIR/harness/run"
SECRET_FILE="$RUN_DIR/helpdesk_secret"
PYTHON="$PROJECT_ROOT/.venv/bin/python"

mkdir -p "$RUN_DIR"
if [ -z "${HELPDESK_SECRET:-}" ] || [ "${HELPDESK_SECRET:-}" = "dev-secret-do-not-use-in-prod" ]; then
  if [ ! -s "$SECRET_FILE" ]; then
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex 32 > "$SECRET_FILE"
    else
      python3 -c 'import secrets; print(secrets.token_hex(32))' > "$SECRET_FILE"
    fi
    chmod 600 "$SECRET_FILE"
  fi
  export HELPDESK_SECRET="$(cat "$SECRET_FILE")"
fi

python3 - "$HELPDESK_SECRET" <<'PY'
import sys
secret = sys.argv[1]
if secret == "dev-secret-do-not-use-in-prod" or len(secret.encode("utf-8")) < 32:
    raise SystemExit("HELPDESK_SECRET must be non-placeholder and at least 32 bytes")
PY

export NIRO_PROJECT_ROOT="$PROJECT_ROOT"
export NIRO_CONFIG_DIR="$CONFIG_DIR"
export PYTHONPATH="$PROJECT_ROOT:$CONFIG_DIR/harness/pythonpath${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

if [ -x "$PYTHON" ]; then
  "$PYTHON" "$CONFIG_DIR/harness/serve.py" stop
else
  python3 "$CONFIG_DIR/harness/serve.py" stop
fi
if lsof -ti tcp:8000 >/dev/null 2>&1; then
  lsof -ti tcp:8000 | xargs kill
fi

cd "$PROJECT_ROOT"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -r requirements.txt

rm -f "$RUN_DIR"/helpdesk.db "$RUN_DIR"/helpdesk.db-journal "$RUN_DIR"/helpdesk.db-wal "$RUN_DIR"/helpdesk.db-shm
cd "$RUN_DIR"
"$PYTHON" "$PROJECT_ROOT/seed.py"
"$CONFIG_DIR/gen-credentials.sh"
"$PYTHON" "$CONFIG_DIR/gen-fixtures.py"
"$PYTHON" "$CONFIG_DIR/harness/serve.py" start
"$PYTHON" "$CONFIG_DIR/harness/healthcheck.py"
