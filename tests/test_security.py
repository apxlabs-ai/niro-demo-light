"""Regression tests for the five security findings from pentest niro_pt_cabd011d.

Each test is named after its finding ID and MUST FAIL on unfixed code.
"""
import json

import pytest

from tests.conftest import auth, make_search, make_ticket


# ---------------------------------------------------------------------------
# TC-7DF98F8C — CRITICAL: cache key missing user scope
# ---------------------------------------------------------------------------

def test_TC_7DF98F8C_cache_does_not_leak_across_tenants(
    client, db_session, customer_a, customer_b, token_a, token_b
):
    """Customer B must not receive Customer A's tickets via a cached search result."""
    make_ticket(db_session, customer_a, subject="SECRET-A")
    make_ticket(db_session, customer_b, subject="SECRET-B")

    search_a = make_search(client, token_a, name="all-a")
    search_b = make_search(client, token_b, name="all-b")

    # Prime the cache with Customer A's scoped result
    r = client.get(f"/searches/{search_a['id']}/run", headers=auth(token_a))
    assert r.status_code == 200
    ids_a = {t["id"] for t in r.json()["tickets"]}
    assert all(t["customer_id"] == customer_a.id for t in r.json()["tickets"])

    # Customer B runs an identical filter — must get only their own tickets
    r = client.get(f"/searches/{search_b['id']}/run", headers=auth(token_b))
    assert r.status_code == 200
    for ticket in r.json()["tickets"]:
        assert ticket["customer_id"] == customer_b.id, (
            f"Cache poisoning: Customer B received ticket {ticket['id']} "
            f"belonging to customer_id={ticket['customer_id']}"
        )
    # No overlap with A's tickets
    ids_b = {t["id"] for t in r.json()["tickets"]}
    assert ids_a.isdisjoint(ids_b), (
        f"Cross-tenant ticket IDs leaked: {ids_a & ids_b}"
    )


# ---------------------------------------------------------------------------
# TC-418AE8CB — CRITICAL: run_scheduled_report missing scope=owner
# ---------------------------------------------------------------------------

def test_TC_418AE8CB_scheduled_report_scoped_to_owner(
    client, db_session, customer_a, customer_b, token_b
):
    """Scheduled report initial_run must only contain the scheduling customer's tickets."""
    make_ticket(db_session, customer_a, subject="A-confidential")
    make_ticket(db_session, customer_b, subject="B-ticket")

    search = make_search(client, token_b, name="probe")
    r = client.post(
        f"/searches/{search['id']}/schedule",
        json={"frequency": "daily", "email": customer_b.email},
        headers=auth(token_b),
    )
    assert r.status_code == 201, r.text
    body = r.json()

    persisted_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])
    result_count = body["initial_run"]["result_count"]

    # The persisted count + ID list must only reflect Customer B's tickets
    assert result_count == 1, (
        f"Expected 1 ticket (Customer B's), got {result_count} — "
        "cross-tenant tickets leaked into scheduled report run"
    )
    assert len(persisted_ids) == 1, (
        f"result_ticket_ids_json contains {len(persisted_ids)} IDs, expected 1"
    )
    for ticket in body["initial_results"]:
        assert ticket["customer_id"] == customer_b.id, (
            f"Cross-tenant ticket in scheduled report: {ticket}"
        )


# ---------------------------------------------------------------------------
# TC-C1EC55B7 — HIGH: run history exposes cross-tenant ticket IDs
# ---------------------------------------------------------------------------

def test_TC_C1EC55B7_run_history_does_not_expose_cross_tenant_ids(
    client, db_session, customer_a, customer_b, token_b
):
    """result_ticket_ids_json in run history must not contain other tenants' IDs."""
    t_a = make_ticket(db_session, customer_a, subject="A-private")
    t_b = make_ticket(db_session, customer_b, subject="B-own")

    search = make_search(client, token_b, name="leak-probe")
    r = client.post(
        f"/searches/{search['id']}/schedule",
        json={"frequency": "daily", "email": customer_b.email},
        headers=auth(token_b),
    )
    assert r.status_code == 201
    schedule_id = r.json()["schedule"]["id"]

    r = client.get(f"/searches/schedules/{schedule_id}/runs", headers=auth(token_b))
    assert r.status_code == 200
    runs = r.json()
    assert len(runs) >= 1
    for run in runs:
        ids = json.loads(run["result_ticket_ids_json"])
        assert t_a.id not in ids, (
            f"Customer A's ticket id={t_a.id} appears in Customer B's run history"
        )
        if t_b.id not in ids and run["result_count"] > 0:
            pytest.fail(f"Customer B's own ticket id={t_b.id} missing from run history")


# ---------------------------------------------------------------------------
# TC-C90B9439 — MEDIUM: agent can mutate/delete customer's saved search
# ---------------------------------------------------------------------------

def test_TC_C90B9439_agent_cannot_patch_customer_search(
    client, db_session, customer_a, token_a, token_agent
):
    """Agent must receive 403 when PATCHing a customer-owned saved search."""
    search = make_search(client, token_a, name="my-search")

    r = client.patch(
        f"/searches/{search['id']}",
        json={"name": "AGENT-TAMPERED"},
        headers=auth(token_agent),
    )
    assert r.status_code == 403, (
        f"Expected 403 but got {r.status_code}: agent silently mutated customer search"
    )


def test_TC_C90B9439_agent_cannot_delete_customer_search(
    client, db_session, customer_a, token_a, token_agent
):
    """Agent must receive 403 when DELETing a customer-owned saved search."""
    search = make_search(client, token_a, name="do-not-delete")

    r = client.delete(f"/searches/{search['id']}", headers=auth(token_agent))
    assert r.status_code == 403, (
        f"Expected 403 but got {r.status_code}: agent silently deleted customer search"
    )

    # Confirm the search still exists for the owner
    r = client.get(f"/searches/{search['id']}", headers=auth(token_a))
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# TC-29859CF0 — MEDIUM: agent can delete a customer's scheduled report
# ---------------------------------------------------------------------------

def test_TC_29859CF0_agent_cannot_delete_customer_schedule(
    client, db_session, customer_a, token_a, token_agent
):
    """Agent must receive 403 when DELETing a customer-owned scheduled report."""
    make_ticket(db_session, customer_a, subject="A-ticket")
    search = make_search(client, token_a, name="my-search")
    r = client.post(
        f"/searches/{search['id']}/schedule",
        json={"frequency": "daily", "email": customer_a.email},
        headers=auth(token_a),
    )
    assert r.status_code == 201
    schedule_id = r.json()["schedule"]["id"]

    r = client.delete(f"/searches/schedules/{schedule_id}", headers=auth(token_agent))
    assert r.status_code == 403, (
        f"Expected 403 but got {r.status_code}: agent silently deleted customer schedule"
    )

    # Confirm schedule still exists for the owner
    r = client.get(f"/searches/{search['id']}/schedule", headers=auth(token_a))
    assert r.status_code == 200
    assert any(s["id"] == schedule_id for s in r.json())


# ---------------------------------------------------------------------------
# TC-77822689 — MEDIUM: arbitrary email accepted for scheduled reports
# ---------------------------------------------------------------------------

def test_TC_77822689_schedule_email_must_match_owner(
    client, db_session, customer_b, token_b
):
    """Scheduling a report to a non-owner email address must be rejected."""
    make_ticket(db_session, customer_b, subject="B-ticket")
    search = make_search(client, token_b, name="exfil-probe")

    r = client.post(
        f"/searches/{search['id']}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=auth(token_b),
    )
    assert r.status_code == 403, (
        f"Expected 403 but got {r.status_code}: arbitrary email accepted for scheduled report"
    )
