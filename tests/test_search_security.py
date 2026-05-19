"""Regression tests for the three findings from pentest niro_pt_44b9d13c.

Each test is written to FAIL on the unfixed code and PASS after the fix.

TC-15D3BB73 (CRITICAL) — cache key does not include caller identity
TC-E00808C4 (CRITICAL) — scheduled-report worker runs search without scope
TC-A1F5D141 (HIGH)    — schedule accepts arbitrary recipient email
"""
import pytest

import app.search as search_module
from tests.conftest import _seed_users, auth, login


# ---------------------------------------------------------------------------
# TC-15D3BB73 — cross-tenant cache leak
# ---------------------------------------------------------------------------

def test_cache_does_not_leak_across_customers(client, db_session):
    """Customer B must not receive Customer A's tickets via a cache hit.

    Attack path:
      1. Customer A creates a ticket then runs a saved search that seeds
         the in-process cache under the sha256 of the filter JSON.
      2. Customer B runs an identical filter.
      3. On unfixed code the cache returns A's result set to B.
    """
    # Guarantee a clean cache before each assertion.
    search_module.invalidate_cache()

    a, b, _ = _seed_users(db_session)
    tok_a = login(client, a.email, "pass-a")
    tok_b = login(client, b.email, "pass-b")

    # Create all tickets FIRST so no subsequent mutation clears the cache
    # mid-test. A must seed the cache with no mutations between seeding and B's read.
    client.post("/tickets", json={"subject": "A-secret", "description": "A only", "priority": "high"}, headers=auth(tok_a))
    client.post("/tickets", json={"subject": "B-own", "description": "B only", "priority": "low"}, headers=auth(tok_b))

    # Clear the cache after all mutations so A's next run is a real DB hit
    # that populates the cache cleanly.
    search_module.invalidate_cache()

    r = client.post("/searches", json={"name": "A-search", "filter": {"status": "open"}}, headers=auth(tok_a))
    assert r.status_code == 201
    sid_a = r.json()["id"]
    client.get(f"/searches/{sid_a}/run", headers=auth(tok_a))  # seeds cache, no mutations after this

    r = client.post("/searches", json={"name": "B-search", "filter": {"status": "open"}}, headers=auth(tok_b))
    assert r.status_code == 201
    sid_b = r.json()["id"]
    resp = client.get(f"/searches/{sid_b}/run", headers=auth(tok_b))
    assert resp.status_code == 200

    tickets = resp.json()["tickets"]
    customer_ids_returned = {t["customer_id"] for t in tickets}

    assert a.id not in customer_ids_returned, (
        f"TC-15D3BB73: Customer B's search result contains Customer A's "
        f"tickets (customer_id={a.id}). Cache leak confirmed."
    )
    assert b.id in customer_ids_returned, (
        "TC-15D3BB73: Customer B's own ticket was not returned."
    )


# ---------------------------------------------------------------------------
# TC-E00808C4 — scheduled-report worker runs without scope (cross-tenant)
# ---------------------------------------------------------------------------

def test_scheduled_report_initial_run_scoped_to_owner(client, db_session):
    """The initial run fired by POST /searches/{id}/schedule must only
    include the owning customer's tickets, not all tenants'.

    On unfixed code run_scheduled_report calls execute_search without
    scope=owner, returning rows across all tenants. The cross-tenant
    exfiltration is visible in initial_run.result_count and
    result_ticket_ids_json.
    """
    search_module.invalidate_cache()

    a, b, _ = _seed_users(db_session)
    tok_a = login(client, a.email, "pass-a")
    tok_b = login(client, b.email, "pass-b")

    # Each customer creates one ticket.
    client.post("/tickets", json={"subject": "A-secret", "description": "A only", "priority": "high"}, headers=auth(tok_a))
    client.post("/tickets", json={"subject": "B-ticket", "description": "B only", "priority": "low"}, headers=auth(tok_b))

    # Customer A creates a saved search with an empty filter (matches all)
    # and immediately schedules a report.
    r = client.post("/searches", json={"name": "A-all", "filter": {}}, headers=auth(tok_a))
    assert r.status_code == 201
    sid = r.json()["id"]

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": a.email},
        headers=auth(tok_a),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    # The initial_run must not have captured B's ticket.
    run_ids = body["initial_run"]["result_ticket_ids_json"]
    import json
    captured_ids = json.loads(run_ids)

    # Fetch ticket ids owned by B so we can assert they're absent.
    b_ticket_resp = client.get("/tickets", headers=auth(tok_b))
    b_ticket_ids = {t["id"] for t in b_ticket_resp.json()}

    leaked = set(captured_ids) & b_ticket_ids
    assert not leaked, (
        f"TC-E00808C4: Scheduled report initial run captured ticket(s) "
        f"{leaked} belonging to Customer B (id={b.id}). Unscoped search confirmed."
    )


# ---------------------------------------------------------------------------
# TC-A1F5D141 — schedule accepts arbitrary recipient email
# ---------------------------------------------------------------------------

def test_schedule_rejects_email_not_owned_by_user(client, db_session):
    """POST /searches/{id}/schedule must reject an email that does not
    belong to the authenticated user.

    On unfixed code any EmailStr is accepted verbatim. An attacker with
    a valid session token can exfiltrate their own (correctly scoped)
    ticket data to any address.
    """
    a, _, _ = _seed_users(db_session)
    tok_a = login(client, a.email, "pass-a")

    r = client.post("/searches", json={"name": "my-search", "filter": {}}, headers=auth(tok_a))
    assert r.status_code == 201
    sid = r.json()["id"]

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=auth(tok_a),
    )
    assert resp.status_code == 422, (
        f"TC-A1F5D141: Expected 422 when scheduling to an email the caller "
        f"does not own, got {resp.status_code}. Arbitrary recipient confirmed."
    )


def test_schedule_accepts_owners_own_email(client, db_session):
    """Positive case: scheduling to the authenticated user's own email must succeed."""
    a, _, _ = _seed_users(db_session)
    tok_a = login(client, a.email, "pass-a")

    r = client.post("/searches", json={"name": "legit-search", "filter": {}}, headers=auth(tok_a))
    assert r.status_code == 201
    sid = r.json()["id"]

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": a.email},
        headers=auth(tok_a),
    )
    assert resp.status_code == 201, resp.text
