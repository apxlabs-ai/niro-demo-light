#!/usr/bin/env bash
# niro-nudge.sh: turn-end nudge delivery for the copilot integration.
#
# Why this script exists:
#   Copilot CLI discards a postToolUse hook's stdout (verified
#   against v1.0.48 and against the engine's source — the
#   postToolUse output normalizer is `a => {}`). So nudging the
#   LLM from inside niro-on-push.sh via additionalContext does
#   nothing. The only Copilot hook whose output reaches the LLM
#   is agentStop, where `{"decision":"block","reason":"X"}`
#   forces another agent turn with X as the next user prompt.
#
# Two-step wiring:
#   1. niro-on-push.sh runs at postToolUse, detects `git push` /
#      `gh pr create`, resolves the open PR, and writes a marker
#      file in $TMPDIR named:
#        niro-pending-pentest.<sessionId>.<pr_number>
#      (The marker is a zero-byte file — the filename IS the
#      signal; PR number lives in the trailing path segment.)
#   2. niro-nudge.sh runs at agentStop, globs all markers for
#      the current session, deletes them, and emits one
#      decision:block whose reason names the pending PRs.
#
# Session scoping: markers carry the sessionId so concurrent
# copilot sessions in the same repo never see each other's
# markers, and a stale marker from a crashed prior session has
# the wrong sessionId — it stays on disk (harmless) until the
# OS reaps $TMPDIR.

set -u

input="$(cat)"

# sessionId is required: without it, we can't scope the glob. If
# stdin isn't valid JSON (or jq is absent), no-op.
sessionId=""
if command -v jq >/dev/null 2>&1; then
  sessionId="$(echo "$input" | jq -r '.sessionId // ""' 2>/dev/null || echo "")"
fi
if [ -z "$sessionId" ] || [ "$sessionId" = "null" ]; then
  echo '{}'
  exit 0
fi

# $TMPDIR on macOS ends in "/"; on Linux it's typically unset and
# we fall back to /tmp/ with an explicit slash. The braced
# default keeps the path well-formed in both cases.
TMP="${TMPDIR:-/tmp/}"
prefix="${TMP}niro-pending-pentest.${sessionId}."

shopt -s nullglob
markers=( "$prefix"* )
shopt -u nullglob

if [ "${#markers[@]}" -eq 0 ]; then
  # No pending pentests for this session — let the turn end
  # normally.
  echo '{}'
  exit 0
fi

# Extract PR numbers (trailing path segment after the final dot)
# and de-duplicate. `touch` is idempotent so duplicates would be
# rare, but two pushes to the same branch creating the marker
# twice would still produce two filenames with the same PR# —
# defensive sort -u keeps the reason text tidy.
prs=()
for f in "${markers[@]}"; do
  prs+=( "${f##*.}" )
done
# Dedupe + sort. Avoid `mapfile` because macOS ships bash 3.2 as
# /bin/bash; the unquoted array-from-substitution form is bash-3
# compatible. Safe to leave unquoted: PR numbers are digit-only
# (we extract them from filenames we own), no whitespace risk.
# shellcheck disable=SC2207
prs=( $(printf '%s\n' "${prs[@]}" | sort -un) )

# Consume markers BEFORE emitting the reason: if the agent acts
# on the nudge in the next turn, agentStop fires again — and we
# must NOT renudge for the same PR again, else infinite loop.
rm -f "${markers[@]}"

if [ "${#prs[@]}" -eq 1 ]; then
  reason="A push just landed on PR #${prs[0]}. To update the security review, call mcp__niro__start_pentest with mode=pr and pr_number=${prs[0]}."
else
  list=""
  for p in "${prs[@]}"; do
    if [ -z "$list" ]; then
      list="#${p}"
    else
      list="${list}, #${p}"
    fi
  done
  reason="Pushes landed on PRs ${list}. To update the security reviews, call mcp__niro__start_pentest once per PR (mode=pr, pr_number=N)."
fi

# Emit decision:block with the reason. jq handles JSON escaping
# for the reason text; if jq is unavailable, a minimal manual
# escape keeps the output well-formed for the common cases
# (no embedded quotes/backslashes in PR numbers).
if command -v jq >/dev/null 2>&1; then
  jq -n --arg reason "$reason" '{decision:"block",reason:$reason}'
else
  esc="${reason//\\/\\\\}"
  esc="${esc//\"/\\\"}"
  printf '{"decision":"block","reason":"%s"}\n' "$esc"
fi
