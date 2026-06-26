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

if lsof -ti tcp:8000 >/dev/null 2>&1; then
  pids="$(lsof -ti tcp:8000)"
  echo "$pids" | xargs kill
  echo "stopped pid(s) on port 8000: $(echo "$pids" | tr '\n' ' ')"
else
  echo "nothing listening on port 8000"
fi
