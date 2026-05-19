#!/usr/bin/env bash
# Close every open PR on the fixture repo and delete its branch.
# Resets the repo to clean main for the next demo run.
set -euo pipefail

REPO_SLUG="apxlabs-ai/niro-demo-light"

prs="$(gh pr list --repo "$REPO_SLUG" --state open --json number --jq '.[].number')"

if [[ -z "$prs" ]]; then
  echo "no open PRs to close"
  exit 0
fi

while IFS= read -r n; do
  echo "→ closing PR #$n + deleting branch"
  gh pr close "$n" --repo "$REPO_SLUG" --delete-branch
done <<< "$prs"
