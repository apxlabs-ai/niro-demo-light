"""Regression tests for niro pentest niro_pt_33a5b712.

Each test is written to FAIL on the unfixed code (demonstrating the live bug)
and PASS after the fix is applied.

TC-68D26C62 (CRITICAL) — cache scope leak: customer B gets A's cached results
TC-84960666 (CRITICAL) — schedule scope bypass: run_scheduled_report omits scope
TC-6DEF4652 (MEDIUM)   — email recipient not validated against caller's account
"""
import json


# ---------------------------------------------------------------------------
# TC-68D26C62: result cache keyed only on filter, not on requesting user
# ---------------------------------------------------------------------------

def test_cache_does_not_leak_between_customers(client, user_a, user_b, tok_a, tok_b):
    """Customer B running the same filter as A must not receive A's tickets.

    Bug: _cache_key() in app/search.py hashes only the filter JSON. When B
    calls execute_search with the same filter after A's cache entry is stored,
    execute_search returns A's rows before applying B's scope restriction.
    """
    # A creates a ticket (also flushes cache via invalidate_cache())
    r = client.post(
        "/tickets",
        json={"subject": "A-secret", "description": "A only", "priority": "high"},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert r.status_code == 201
    a_ticket_id = r.json()["id"]

    # B creates a ticket (flushes cache again)
    r = client.post(
        "/tickets",
        json={"subject": "B-secret", "description": "B only", "priority": "low"},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 201
    b_ticket_id = r.json()["id"]

    # A creates a search and runs it — cache miss, stores A's scoped rows
    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert r.status_code == 201
    sid_a = r.json()["id"]

    r = client.get(f"/searches/{sid_a}/run", headers={"Authorization": f"Bearer {tok_a}"})
    assert r.status_code == 200
    assert any(t["id"] == a_ticket_id for t in r.json()["tickets"])

    # B creates the identical filter search and runs it — must NOT cache-hit A's entry
    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 201
    sid_b = r.json()["id"]

    r = client.get(f"/searches/{sid_b}/run", headers={"Authorization": f"Bearer {tok_b}"})
    assert r.status_code == 200
    b_results = r.json()

    returned_ids = {t["id"] for t in b_results["tickets"]}
    assert b_ticket_id in returned_ids, "B's own ticket missing from results"
    assert a_ticket_id not in returned_ids, (
        f"Cache leak (TC-68D26C62): B received A's ticket {a_ticket_id}. "
        f"All IDs returned: {returned_ids}"
    )
    assert all(t["customer_id"] == user_b.id for t in b_results["tickets"]), (
        "B's search results contain tickets belonging to another customer"
    )


# ---------------------------------------------------------------------------
# TC-84960666: run_scheduled_report calls execute_search without scope
# ---------------------------------------------------------------------------

def test_schedule_initial_run_scoped_to_owner(client, user_a, user_b, tok_a, tok_b):
    """The initial_run from scheduling must only contain the scheduling user's tickets.

    Bug: app/jobs.py:run_scheduled_report calls
      execute_search(saved.filter_json, db, use_cache=False)
    without passing scope=owner, so scope defaults to None → global cross-tenant
    view. A's ticket IDs appear in initial_run.result_ticket_ids_json returned to B.
    """
    # A creates a ticket that B must never see
    r = client.post(
        "/tickets",
        json={"subject": "A-confidential", "description": "A only", "priority": "urgent"},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert r.status_code == 201
    a_ticket_id = r.json()["id"]

    # B creates a saved search with empty filter
    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 201
    sid = r.json()["id"]

    # B schedules the search — triggers synchronous run_scheduled_report
    r = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": user_b.email},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 201
    body = r.json()

    result_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])
    assert a_ticket_id not in result_ids, (
        f"Scope bypass (TC-84960666): B's scheduled report initial run "
        f"contains A's ticket {a_ticket_id}. All IDs: {result_ids}"
    )


# ---------------------------------------------------------------------------
# TC-6DEF4652: scheduled report email not validated against caller's account
# ---------------------------------------------------------------------------

def test_schedule_rejects_mismatched_email(client, user_b, tok_b):
    """Scheduling a report to an email other than the caller's account must fail with 422.

    Bug: schedule_report in app/routes/searches.py stores req.email verbatim.
    Pydantic's EmailStr only validates format, not ownership. An attacker can
    exfiltrate ticket data to any address they choose.
    """
    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 201
    sid = r.json()["id"]

    r = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": "victim@attacker-controlled.com"},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert r.status_code == 422, (
        f"Expected 422 for mismatched recipient email but got {r.status_code}. "
        f"A customer was able to send scheduled reports to an arbitrary address "
        f"(TC-6DEF4652)."
    )
