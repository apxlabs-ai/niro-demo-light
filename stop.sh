#!/usr/bin/env bash
# Stop whatever is listening on port 8000 (the helpdesk server started
# by run.sh). Safe to run when nothing is listening — exits silently.
set -euo pipefail

PORT="${PORT:-8000}"

pids="$(lsof -ti tcp:"$PORT" 2>/dev/null || true)"
if [ -z "$pids" ]; then
  echo "nothing listening on port $PORT"
  exit 0
fi

echo "$pids" | xargs kill
echo "stopped pid(s) on port $PORT: $(echo "$pids" | tr '\n' ' ')"
