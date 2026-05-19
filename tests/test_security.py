"""Regression tests for the three security findings from pentest niro_pt_f8771c47.

TC-1F25AC15 (CRITICAL) — cache key missing scope: customers share cached results
TC-2074AC7B (CRITICAL) — run_scheduled_report missing scope: cross-tenant leak in email body
TC-7A23B42A (HIGH)     — schedule email not validated against owner's address
"""
import pytest

from app.models import Status, Priority, Ticket
from app.search import invalidate_cache
from tests.conftest import login


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_ticket(client, token, subject, status="open"):
    r = client.post(
        "/tickets",
        json={"subject": subject, "description": "d", "status": status, "priority": "normal"},
        headers={"Authorization": token},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _create_search(client, token, name="s", filter=None):
    r = client.post(
        "/searches",
        json={"name": name, "filter": filter or {"status": "open"}},
        headers={"Authorization": token},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# TC-1F25AC15: cache key must be scoped per user
# ---------------------------------------------------------------------------

def test_cached_results_not_shared_between_customers(client, seed_users):
    """Customer B must never receive Customer A's cached search results."""
    customer_a, customer_b, _ = seed_users
    tok_a = login(client, customer_a.email)
    tok_b = login(client, customer_b.email)

    invalidate_cache()

    # A creates a ticket and runs a search — this seeds the cache.
    _create_ticket(client, tok_a, "A-only-ticket")
    search_a = _create_search(client, tok_a, name="a-open")
    r = client.get(f"/searches/{search_a}/run", headers={"Authorization": tok_a})
    assert r.status_code == 200
    a_ids = {t["id"] for t in r.json()["tickets"]}
    assert len(a_ids) > 0, "A should see their own ticket"

    # B creates a search with the identical filter and runs it.
    search_b = _create_search(client, tok_b, name="b-open")
    r = client.get(f"/searches/{search_b}/run", headers={"Authorization": tok_b})
    assert r.status_code == 200
    b_tickets = r.json()["tickets"]

    # None of A's tickets must appear in B's results.
    b_ids = {t["id"] for t in b_tickets}
    assert not (a_ids & b_ids), (
        f"Cross-tenant cache leak: B received A's ticket IDs {a_ids & b_ids}"
    )
    # Every ticket B sees must belong to B.
    for t in b_tickets:
        assert t["customer_id"] == customer_b.id, (
            f"B received ticket owned by customer_id={t['customer_id']}"
        )


# ---------------------------------------------------------------------------
# TC-2074AC7B: run_scheduled_report must apply scope=owner
# ---------------------------------------------------------------------------

def test_scheduled_report_only_includes_owner_tickets(client, seed_users):
    """The initial_run result_count from POST /searches/{id}/schedule must
    equal only the owner's ticket count, not the global count."""
    customer_a, customer_b, _ = seed_users
    tok_a = login(client, customer_a.email)
    tok_b = login(client, customer_b.email)

    invalidate_cache()

    # Ensure both customers have tickets.
    _create_ticket(client, tok_a, "A-sched-1")
    _create_ticket(client, tok_b, "B-sched-1")
    _create_ticket(client, tok_b, "B-sched-2")

    search_id = _create_search(client, tok_a, name="a-sched", filter={"status": "open"})

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": customer_a.email},
        headers={"Authorization": tok_a},
    )
    assert r.status_code == 201, r.text
    body = r.json()

    initial_run = body["initial_run"]
    assert initial_run["success"] is True

    # The run's persisted ticket IDs must contain no tickets owned by B.
    import json as _json
    persisted_ids = set(_json.loads(initial_run["result_ticket_ids_json"]))
    # Collect B's ticket IDs from their search results.
    sb = _create_search(client, tok_b, name="b-all", filter={"status": "open"})
    r_b = client.get(f"/searches/{sb}/run", headers={"Authorization": tok_b})
    b_ids = {t["id"] for t in r_b.json()["tickets"]}

    leaked = persisted_ids & b_ids
    assert not leaked, (
        f"Scheduled report for customer A included Customer B's ticket IDs: {leaked}"
    )


# ---------------------------------------------------------------------------
# TC-7A23B42A: schedule email must match the authenticated user's email
# ---------------------------------------------------------------------------

def test_schedule_rejects_arbitrary_recipient_email(client, seed_users):
    """POST /searches/{id}/schedule with email != owner's email must be rejected."""
    customer_a, _, _ = seed_users
    tok_a = login(client, customer_a.email)

    search_id = _create_search(client, tok_a, name="a-exfil")

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "hourly", "email": "attacker@evil.com"},
        headers={"Authorization": tok_a},
    )
    assert r.status_code in (403, 422), (
        f"Expected 403/422 for arbitrary recipient, got {r.status_code}: {r.text}"
    )
