#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$SCRIPT_DIR/patches/saved-searches.patch"

BASE_BRANCH="${BASE_BRANCH:-main}"
NEW_BRANCH="${NEW_BRANCH:-feature/saved-searches-$(date +%Y%m%d-%H%M%S)}"
PRE_COMMIT_MSG="${PRE_COMMIT_MSG:-save local changes before switching branches}"
PATCH_COMMIT_MSG="${1:-apply helpdesk saved searches patch}"

cd "$(git rev-parse --show-toplevel)"

# Commit current local changes, including untracked files
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  git add -A
  git commit -m "$PRE_COMMIT_MSG"
  echo "→ existing local changes committed."
fi

# Move to main and update it
git switch "$BASE_BRANCH"
git pull --ff-only origin "$BASE_BRANCH"

# Create a fresh branch
git switch -c "$NEW_BRANCH"

# Apply patch and commit it
git apply "$PATCH"
git add -A
git commit -m "$PATCH_COMMIT_MSG"

echo "→ switched to $BASE_BRANCH, created $NEW_BRANCH, applied patch, and committed."
echo "→ current branch: $(git branch --show-current)"
echo "→ next: codex can start with a clean working tree."