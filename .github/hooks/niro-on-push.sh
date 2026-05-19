#!/usr/bin/env bash
# niro-on-push.sh: PostToolUse hook fired after either `git push` OR
# `gh pr create`. Nudges the coding agent to run a security review
# when the current branch has an open PR. The hook itself stays
# minimal — what to do, how to invoke niro, what URL/scope to pass —
# all lives in niro/README.md so this script never needs updating
# when niro evolves.
#
# Two triggers because the typical agent workflow is push-then-create:
#   git push          (creates branch on remote, no PR yet)
#   gh pr create      (creates the PR)
# Firing only on git push misses the moment the PR exists. Firing on
# both means the hook catches initial PR creation AND subsequent
# pushes to an already-PR'd branch.
#
# Silent no-op when:
#   - the command isn't actually a git push or gh pr create (kernel
#     `if` matcher fires on too-complex-to-parse Bash commands as a
#     safety fallback; this script applies the final string check)
#   - gh is not installed (graceful — niro is bonus, not blocker)
#   - the current branch has no open PR (push fired before
#     `gh pr create`; the next trigger will catch it)
#
# Installed by `niro init` at one or both of:
#   .claude/hooks/niro-on-push.sh    (Claude Code)
#   .github/hooks/niro-on-push.sh    (Copilot CLI)
# Disable by removing the matching hook entry from its agent's
# config file (.claude/settings.json or .github/hooks/niro.json) or
# deleting the script copy at that path.

set -euo pipefail

# The hook config tells us which agent is calling us via --agent.
# The hook config — not the install path — is the source of truth
# because (a) the same script file can legitimately live under
# multiple paths (symlinked / shared / per-agent copy), and
# (b) the config carries the intent at write time so a future
# reader doesn't have to reverse-engineer "what's `.github/hooks/`?".
#
# Hook config snippets:
#   .claude/settings.json   "command": ".claude/hooks/niro-on-push.sh --agent claude"
#   .github/hooks/niro.json "bash":    ".github/hooks/niro-on-push.sh --agent copilot"
#
# Adding agent N+1: one new --agent value in their hook config + one
# matching case in the response section near the bottom.
case "${1:-}" in
  --agent)
    NIRO_HOOK_AGENT="${2:-}"
    ;;
  *)
    echo "niro-on-push: expected --agent <name> (got: ${*:-no args})" >&2
    exit 0
    ;;
esac
case "$NIRO_HOOK_AGENT" in
  claude|copilot) ;;
  *)
    echo "niro-on-push: unknown agent: ${NIRO_HOOK_AGENT:-empty}" >&2
    exit 0
    ;;
esac

# Hook receives the tool call's JSON envelope on stdin. The shape
# differs per coding agent:
#   - Claude Code:   .tool_input.command
#   - Copilot CLI:   .toolArgs.command (and .toolArgs is sometimes a
#                    JSON-encoded string the agent stringified, not
#                    an object — try both)
# Niro init drops this same script into BOTH agents' hook
# directories (.claude/hooks/ for Claude, .github/hooks/ for
# Copilot), so the script must self-detect the payload shape.
#
# For Claude: the kernel-side matchers (`Bash(git push *)` and
# `Bash(gh pr create *)`) do subcommand extraction + env-var
# stripping AND fire unconditionally on "too complex to parse"
# commands as a safety fallback. The case below filters those false
# positives by requiring one of the two trigger phrases to appear
# in the rendered command.
#
# For Copilot: there's no command-pattern matcher; the hook config
# fires on every `bash` tool call and this script does ALL the
# filtering itself.
input="$(cat)"

# start_pentest short-circuit:
#
# If this postToolUse is for the niro start_pentest tool, the agent
# has already taken action on this PR — kicking off (or trying to
# kick off) a pentest. Re-prompting via niro-nudge.sh at agentStop
# adds zero new information: the agent already saw start_pentest's
# success/failure result and can decide what to do next on its own.
#
# So we clear the marker for that <sessionId>.<pr_number>. At
# agentStop, the nudge script globs nothing for this PR and stays
# silent. The other marker semantics (write-on-push, delete-on-nudge)
# stay unchanged — this is purely an additional "agent already
# engaged, suppress one redundant nudge" path.
#
# We match on suffix "*start_pentest" rather than the exact
# namespaced name "niro-start_pentest", so the same logic survives
# any future SDK wire-format change (bare vs prefixed).
# Empirically (Copilot CLI 1.0.49) toolName arrives as
# "niro-start_pentest"; the suffix match catches both that and any
# future bare form.
#
# Runs unconditionally (not gated on agent): claude never writes
# markers, so rm -f silently no-ops there. Cheaper than another
# conditional branch and survives a future world where claude grows
# the same marker pattern.
if command -v jq >/dev/null 2>&1; then
  toolName="$(echo "$input" | jq -r '.toolName // .tool_name // ""' 2>/dev/null || echo "")"
  case "$toolName" in
    *start_pentest)
      # toolArgs can arrive as an object OR a stringified JSON blob
      # (same dual-shape quirk the bash-command branch below handles
      # via fromjson?). Mirror that pattern here so both shapes work.
      # tool_input is checked too so this stays correct if a future
      # claude install adopts the marker pattern (its envelope uses
      # snake_case tool_input + tool_name).
      sp_session="$(echo "$input" | jq -r '.sessionId // .session_id // ""' 2>/dev/null || echo "")"
      sp_pr="$(echo "$input" | jq -r '
        .toolArgs.pr_number
        // (.toolArgs | (fromjson? // {}) | .pr_number)
        // .tool_input.pr_number
        // ""
      ' 2>/dev/null || echo "")"
      if [ -n "$sp_session" ] && [ "$sp_session" != "null" ] \
         && [ -n "$sp_pr" ] && [ "$sp_pr" != "null" ]; then
        rm -f "${TMPDIR:-/tmp/}niro-pending-pentest.${sp_session}.${sp_pr}"
      fi
      exit 0
      ;;
  esac
fi

if command -v jq >/dev/null 2>&1; then
  # Try Claude's shape, fall back to Copilot's. The `// ""` chain
  # also handles Copilot's stringified toolArgs case via the
  # `fromjson?` pass: if toolArgs is a JSON-encoded string, decode
  # it and pull .command from inside; otherwise treat it as an
  # already-parsed object.
  cmd="$(echo "$input" | jq -r '
    .tool_input.command
    // .toolArgs.command
    // (.toolArgs | (fromjson? // {}) | .command)
    // ""
  ' 2>/dev/null || echo "")"
  case "$cmd" in
    *"git push"*) ;;       # confirmed push, proceed
    *"gh pr create"*) ;;   # confirmed PR creation, proceed
    *) exit 0 ;;           # fired by safety fallback or unrelated command
  esac
fi

if ! command -v gh >/dev/null 2>&1; then
  exit 0
fi

# Resolve the OPEN PR for the current branch. `gh pr view` is tempting
# here but it doesn't filter by state — when a branch name is reused
# across runs, it can resolve to a previously merged/closed PR. The
# `gh pr list --head BRANCH --state open` form is explicit and only
# returns the live PR.
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
if [ -z "$branch" ] || [ "$branch" = "HEAD" ]; then
  exit 0
fi

pr_number="$(gh pr list --head "$branch" --state open --json number -q '.[0].number' 2>/dev/null || true)"
if [ -z "$pr_number" ] || [ "$pr_number" = "null" ]; then
  exit 0
fi

# Per-agent nudge delivery.
#
#   - claude: stdout reaches the LLM. Emit the nested
#     {hookSpecificOutput.additionalContext} shape that Claude
#     Code's hook processor reads.
#
#   - copilot: stdout is discarded by Copilot for postToolUse
#     (verified against v1.0.48 — the engine's output normalizer
#     for that event is `a => {}`). So we record the pending PR
#     as a zero-byte marker file in $TMPDIR and let niro-nudge.sh
#     deliver the actual prompt at agentStop, where Copilot does
#     honour `decision:block`+`reason`. The PR number lives in
#     the filename so the nudge script reads it without parsing
#     contents; the sessionId scopes the marker to this session
#     so concurrent copilots in the same repo don't clobber each
#     other.
case "$NIRO_HOOK_AGENT" in
  claude)
    msg="You just pushed code on a branch with open PR #${pr_number}. The PR comment only updates after niro pentests the new push. Call start_pentest with mode=pr and pr_number=${pr_number}."
    cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"${msg}"}}
EOF
    ;;
  copilot)
    sessionId=""
    if command -v jq >/dev/null 2>&1; then
      sessionId="$(echo "$input" | jq -r '.sessionId // ""' 2>/dev/null || echo "")"
    fi
    if [ -z "$sessionId" ] || [ "$sessionId" = "null" ]; then
      exit 0
    fi
    : > "${TMPDIR:-/tmp/}niro-pending-pentest.${sessionId}.${pr_number}"
    ;;
esac
