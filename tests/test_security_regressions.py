"""Regression tests for security findings from pentest niro_pt_aef56d3d.

Each test is named after the finding it covers and asserts the SECURE
behaviour. Before fixes these tests FAIL; after fixes they PASS.
"""
import json

import pytest
from app.models import Role, Ticket, Priority, Status
from app.search import _cache, invalidate_cache
from tests.conftest import auth_header, make_user


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_ticket(db, customer, subject, priority=Priority.high, status=Status.open):
    t = Ticket(
        customer_id=customer.id,
        subject=subject,
        description="",
        priority=priority,
        status=status,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def create_search(client, user, filter_dict, name="test search"):
    r = client.post(
        "/searches",
        json={"name": name, "filter": filter_dict},
        headers=auth_header(user),
    )
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# TC-ACE5BAE6 (CRITICAL) — cache key must include caller scope
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_customers(client, db):
    """Customer B must never receive Customer A's tickets via a shared cache entry.

    The bug: _cache_key() hashes only filter_json, not scope. When Customer A
    runs a search it populates the cache; Customer B's identical filter then
    gets a cache hit and sees A's rows.
    """
    invalidate_cache()

    cust_a = make_user(db, "a@example.com", "pw", Role.customer)
    cust_b = make_user(db, "b@example.com", "pw", Role.customer)

    make_ticket(db, cust_a, "SECRET_A_TICKET")
    make_ticket(db, cust_b, "ORDINARY_B_TICKET")

    search_a = create_search(client, cust_a, {"status": "open"}, "A open")
    search_b = create_search(client, cust_b, {"status": "open"}, "B open")

    # A runs first — populates the cache.
    r_a = client.get(f"/searches/{search_a['id']}/run", headers=auth_header(cust_a))
    assert r_a.status_code == 200
    subjects_a = {t["subject"] for t in r_a.json()["tickets"]}
    assert "SECRET_A_TICKET" in subjects_a
    assert "ORDINARY_B_TICKET" not in subjects_a

    # B runs second — must NOT get A's cached rows.
    r_b = client.get(f"/searches/{search_b['id']}/run", headers=auth_header(cust_b))
    assert r_b.status_code == 200
    subjects_b = {t["subject"] for t in r_b.json()["tickets"]}
    assert "ORDINARY_B_TICKET" in subjects_b, "Customer B should see their own ticket"
    assert "SECRET_A_TICKET" not in subjects_b, (
        "Customer B must NOT see Customer A's ticket — cache leak detected"
    )


# ---------------------------------------------------------------------------
# TC-E6C66B5A (HIGH) — ReportRun audit row must not contain cross-tenant IDs
# ---------------------------------------------------------------------------


def test_report_run_contains_only_owner_tickets(client, db):
    """ReportRun.result_ticket_ids_json must only include the scheduling
    customer's own ticket IDs, never IDs from other tenants.

    The bug: run_scheduled_report calls execute_search without scope=owner,
    so the unscoped query hits every tenant and records cross-tenant IDs in
    the ReportRun row — readable by the customer via GET /schedules/{id}/runs.
    """
    invalidate_cache()

    cust_a = make_user(db, "a@example.com", "pw", Role.customer)
    cust_b = make_user(db, "b@example.com", "pw", Role.customer)

    ticket_a = make_ticket(db, cust_a, "A_PRIVATE", priority=Priority.high)
    ticket_b = make_ticket(db, cust_b, "B_TICKET", priority=Priority.high)

    search_b = create_search(client, cust_b, {"priority": "high"}, "B high")

    r = client.post(
        f"/searches/{search_b['id']}/schedule",
        json={"frequency": "daily", "email": cust_b.email},
        headers=auth_header(cust_b),
    )
    assert r.status_code == 201, r.text
    payload = r.json()
    sched_id = payload["schedule"]["id"]

    # Check the initial_run embedded in the response.
    initial_run = payload["initial_run"]
    ids_in_run = json.loads(initial_run["result_ticket_ids_json"])
    assert ticket_a.id not in ids_in_run, (
        f"Customer A's ticket {ticket_a.id} must not appear in Customer B's report run; "
        f"got ids: {ids_in_run}"
    )
    assert ticket_b.id in ids_in_run, "Customer B's own ticket must be in the run"

    # Also check via the runs history endpoint.
    r2 = client.get(
        f"/searches/schedules/{sched_id}/runs",
        headers=auth_header(cust_b),
    )
    assert r2.status_code == 200
    runs = r2.json()
    assert runs, "Expected at least one run in history"
    ids_in_history = json.loads(runs[0]["result_ticket_ids_json"])
    assert ticket_a.id not in ids_in_history, (
        f"Cross-tenant ticket {ticket_a.id} exposed in run history"
    )


# ---------------------------------------------------------------------------
# TC-A943EE82 (HIGH) — scheduled report must not send to unverified addresses
# ---------------------------------------------------------------------------


def test_schedule_rejects_email_not_owned_by_user(client, db):
    """POST /searches/{id}/schedule must reject email addresses that don't
    belong to the authenticated user.

    The bug: the route accepts any EmailStr without checking it matches the
    caller's account email, allowing a customer to direct reports (and their
    cross-tenant content) to an arbitrary attacker-controlled address.
    """
    cust_b = make_user(db, "b@example.com", "pw", Role.customer)
    make_ticket(db, cust_b, "B_TICKET")

    search_b = create_search(client, cust_b, {"status": "open"}, "B open")

    r = client.post(
        f"/searches/{search_b['id']}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.example"},
        headers=auth_header(cust_b),
    )
    assert r.status_code == 422, (
        f"Expected 422 when scheduling to an unowned address, got {r.status_code}: {r.text}"
    )


def test_schedule_accepts_users_own_email(client, db):
    """POST /searches/{id}/schedule must succeed when the email matches the
    authenticated user's own account address."""
    cust_b = make_user(db, "b@example.com", "pw", Role.customer)
    make_ticket(db, cust_b, "B_TICKET")

    search_b = create_search(client, cust_b, {"status": "open"}, "B open")

    r = client.post(
        f"/searches/{search_b['id']}/schedule",
        json={"frequency": "daily", "email": cust_b.email},
        headers=auth_header(cust_b),
    )
    assert r.status_code == 201, (
        f"Expected 201 when scheduling to own email, got {r.status_code}: {r.text}"
    )
