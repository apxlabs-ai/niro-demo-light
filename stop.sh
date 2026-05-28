#!/usr/bin/env bash
# Stop the helpdesk servers started by start.sh (ports 8000 and 8443).
# Safe to run when nothing is listening — exits silently.
set -euo pipefail

_stop_port() {
  local port="$1"
  local pids
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  if [ -z "$pids" ]; then
    echo "nothing listening on port $port"
  else
    echo "$pids" | xargs kill
    echo "stopped pid(s) on port $port: $(echo "$pids" | tr '\n' ' ')"
  fi
}

_stop_port 8000
_stop_port 8443
