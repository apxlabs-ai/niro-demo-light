#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${NIRO_PROJECT_ROOT:-$(cd "$CONFIG_DIR/.." && pwd)}"
PYTHON="$PROJECT_ROOT/.venv/bin/python"

export NIRO_PROJECT_ROOT="$PROJECT_ROOT"
export NIRO_CONFIG_DIR="$CONFIG_DIR"

if [ -x "$PYTHON" ]; then
  "$PYTHON" "$CONFIG_DIR/harness/serve.py" stop
else
  python3 "$CONFIG_DIR/harness/serve.py" stop
fi

for port in 8000 8443; do
  if lsof -ti tcp:"$port" >/dev/null 2>&1; then
    pids="$(lsof -ti tcp:"$port")"
    echo "$pids" | xargs kill
    echo "stopped pid(s) on port $port: $(echo "$pids" | tr '\n' ' ')"
  else
    echo "nothing listening on port $port"
  fi
done
