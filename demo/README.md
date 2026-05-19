# niro-demo-light

Self-contained pentest demo: a clean FastAPI helpdesk baseline plus a
vulnerability fixture you replay as a PR. niro runs against the PR and
surfaces findings.

## Layout

- `main` — clean helpdesk-api baseline. Customer/agent roles, ticket CRUD,
  comments, JWT auth, RBAC enforced everywhere.
- `demo/` — replay tooling (this directory).
  - `fixtures/customer-reopen-and-search.patch` — a portable `git
    format-patch` of the vulnerability-introducing PR.
  - `run.sh` — apply the patch to the working tree (uncommitted).
  - `cleanup.sh` — close any open PRs on the repo and delete their branches.

`demo/` exists on every branch (including the demo PR branch), so it does
not appear in the PR diff. niro pentests only the helpdesk source changes.

## Run a demo

```bash
gh repo clone apxlabs-ai/niro-demo-light /tmp/demo
cd /tmp/demo
./demo/run.sh         # patches the working tree
# ask your coding agent to branch, commit, push, and open the PR
./demo/cleanup.sh     # closes PR, repo back to clean main
```

## Fixture: customer-reopen-and-search

Plays a plausible feature PR: "let customers reopen their own resolved
tickets and add fuzzy ticket search." Three changes land together:

1. **New `POST /tickets/{id}/reopen`** — customer reopens their own
   resolved/closed ticket. Correctly scoped.
2. **Loosened `PATCH /tickets/{id}` guard** — the agent-only role check was
   replaced with a customer-ownership check, "to support the new reopen
   flow." Looks reasonable on review.
3. **New `GET /tickets/search?q=...`** — fuzzy LIKE-match on ticket subject
   and description, scoped to the caller for customers. The handler builds
   the SQL with an f-string against the `q` parameter.

### Expected findings

- **CRITICAL — SQL Injection** on `GET /tickets/search`. The `q` parameter
  is concatenated into a raw SQL `LIKE` clause via Python f-string. A
  UNION-based payload exfiltrates the `users` table including bcrypt
  `password_hash` values. Repro (as any logged-in user):
  ```
  GET /tickets/search?q=x') UNION SELECT id,1,1,email,password_hash,'open','normal',created_at,created_at FROM users--
  ```
- **HIGH — Broken Function Level Authorization** on `PATCH /tickets/{id}`.
  Removing the agent-only guard means a customer can now mutate `status`,
  `priority`, and `assignee_id` on any ticket they own. They can mark
  their own ticket `resolved` (hiding live issues from queues), bump
  `priority=urgent` (queue-jumping), or reassign to a specific agent. The
  dedicated `/reopen` endpoint exists, but PATCH was left wide open. Repro
  (as the ticket's customer):
  ```
  PATCH /tickets/1   {"status":"resolved","priority":"urgent","assignee_id":1}
  ```

## Adding another fixture

1. Branch from `main`, write the vulnerable feature, commit.
2. `git format-patch -1 HEAD -o demo/fixtures/`.
3. Rename to something descriptive; delete the temp branch; return to `main`.
4. Document expected findings in this README; either parameterize `run.sh`
   to take a patch path or duplicate it per fixture.
