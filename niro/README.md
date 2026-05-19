# Niro in this project

Niro is an AI-powered pentest agent. It runs test cases against your
authorized targets — each one a specific attack — and returns the coverage
map: which passed, which failed (the bugs, with runnable PoCs), which were
blocked waiting on your input.

You don't invoke Niro directly. Your coding agent calls Niro (over MCP) when
you ask for security testing — typically at push or PR time. Niro returns
the run; your agent drafts fixes for failed cases (with regression tests),
re-runs to confirm closure, and surfaces any blocked items as a punch-list.
You review the diff and the punch-list, provide what's needed, merge.

The MCP tools Niro exposes — their descriptions, arguments, and outputs —
are visible in your coding agent's tool list and are the authoritative
reference for what each one does.

## Layout

- `niro.yaml` — project config (runtime, resource caps, log level).
- `scope.yaml` — what Niro is authorized to test (self-documenting; in-file comments cover format and the per-environment-config rule).
- `credentials.yaml.example` — format reference + instructions for how to produce your local `credentials.yaml`. Do not edit or delete. Niro does NOT scaffold `credentials.yaml` for you; you produce it yourself (manually or via a script) and it must never be committed.

## Setup

One-time per project:

- Define what's in scope: edit `scope.yaml` (in-file comments explain
  the format and the per-environment-config rule).
- Create `niro/credentials.yaml` if your targets require auth — see
  `credentials.yaml.example` for the format and for sample shell
  recipes to populate it from your secrets backend (1Password,
  Doppler, Vault, plain heredoc, etc.). The file is gitignored by
  default; keep it that way.
- Tune resource caps if needed: edit `niro.yaml`.


