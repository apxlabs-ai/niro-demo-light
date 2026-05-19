#!/usr/bin/env bash
# Apply the helpdesk feature patch to the working tree as uncommitted
# changes — as if the coding agent had just edited the files. From here, ask
# the agent to create a branch, commit, push, and open a PR; the agent's
# `gh pr create` is the trigger that fires the niro hook.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$SCRIPT_DIR/patches/customer-can-reopen.patch"

cd "$(git rev-parse --show-toplevel)"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "working tree has tracked changes; commit or stash first" >&2
  exit 1
fi

git apply "$PATCH"

echo "→ helpdesk changes applied to the working tree (uncommitted)."
echo "→ next: ask your coding agent to branch, commit, push, and open a PR."
