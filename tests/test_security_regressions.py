"""Regression tests for security findings from pentest niro_pt_2d86d52b.

Each test is written to FAIL on the unfixed code and PASS after fixes are
applied. Tests are named after their finding ID so they can be linked back
to the pentest report.

Findings covered:
  TC-84BC4584  CRITICAL  Cache key omits scope — cross-tenant data leak on cache hit
  TC-55ACC8F8  CRITICAL  Worker runs execute_search() without scope= — all-tenant results
  TC-1A85E0E6  HIGH      ReportRun.result_ticket_ids_json stored/returned unscoped
  TC-FFEB010C  HIGH      Schedule email not pinned to authenticated user's email
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
# Import all models so Base.metadata knows about every table before create_all
from app.models import (  # noqa: F401
    Role, SavedSearch, ScheduledReport, ReportRun, Ticket, User,
)
from app import search as search_module


# ---------------------------------------------------------------------------
# In-memory DB + client fixtures
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_and_client():
    """Yields (db_session, test_client) sharing the same in-memory SQLite DB.

    StaticPool forces all connections to reuse a single in-memory connection,
    so tables created by Base.metadata.create_all are visible to route handlers
    that open their own sessions via the get_db override.
    """
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    search_module.invalidate_cache()

    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    session = Session()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield session, c
    session.close()
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_user(db, email, role=Role.customer):
    u = User(email=email, password_hash=hash_password("pw"), full_name="Test User", role=role)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def make_ticket(db, customer_id, subject="ticket", status="open"):
    t = Ticket(
        customer_id=customer_id,
        subject=subject,
        description="desc",
        status=status,
        priority="normal",
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def auth_header(user):
    return {"Authorization": f"Bearer {issue_token(user)}"}


# ---------------------------------------------------------------------------
# TC-84BC4584  Cross-tenant cache hit
# ---------------------------------------------------------------------------

def test_TC_84BC4584_cache_does_not_leak_across_tenants(db_and_client):
    db_session, client = db_and_client
    """Customer B must not receive Customer A's tickets on a cache hit.

    Bug: _cache_key() hashes only filter_json, ignoring scope. The first
    caller's scoped results are stored and returned verbatim to any subsequent
    caller with the same filter — regardless of tenant.
    """
    customer_a = make_user(db_session, "a@test.com")
    customer_b = make_user(db_session, "b@test.com")

    ticket_a = make_ticket(db_session, customer_a.id, "A-secret")
    _ticket_b = make_ticket(db_session, customer_b.id, "B-secret")

    # Each customer creates a saved search with the same filter
    resp_a = client.post(
        "/searches",
        json={"name": "A-search", "filter": {"status": "open"}},
        headers=auth_header(customer_a),
    )
    assert resp_a.status_code == 201
    search_a_id = resp_a.json()["id"]

    resp_b = client.post(
        "/searches",
        json={"name": "B-search", "filter": {"status": "open"}},
        headers=auth_header(customer_b),
    )
    assert resp_b.status_code == 201
    search_b_id = resp_b.json()["id"]

    # Customer A runs their search — populates cache
    run_a = client.get(f"/searches/{search_a_id}/run", headers=auth_header(customer_a))
    assert run_a.status_code == 200
    a_ids = {t["id"] for t in run_a.json()["tickets"]}
    assert ticket_a.id in a_ids

    # Customer B runs their search — must NOT get A's tickets from cache
    run_b = client.get(f"/searches/{search_b_id}/run", headers=auth_header(customer_b))
    assert run_b.status_code == 200
    b_ticket_ids = {t["id"] for t in run_b.json()["tickets"]}
    assert ticket_a.id not in b_ticket_ids, (
        "TC-84BC4584: Customer B received Customer A's ticket via shared cache"
    )
    # All returned tickets must belong to B
    for t in run_b.json()["tickets"]:
        assert t["customer_id"] == customer_b.id, (
            f"TC-84BC4584: ticket {t['id']} (customer_id={t['customer_id']}) "
            f"returned to customer_b (id={customer_b.id})"
        )


# ---------------------------------------------------------------------------
# TC-55ACC8F8  Worker unscoped execute_search
# ---------------------------------------------------------------------------

def test_TC_55ACC8F8_scheduled_report_scoped_to_owner(db_and_client):
    db_session, client = db_and_client
    """The initial run fired by POST /searches/{id}/schedule must only
    contain tickets belonging to the scheduling customer.

    Bug: run_scheduled_report() calls execute_search() without scope=owner,
    returning tickets from all tenants.
    """
    customer_a = make_user(db_session, "a@test.com")
    customer_b = make_user(db_session, "b@test.com")

    ticket_a = make_ticket(db_session, customer_a.id, "A-secret")
    ticket_b = make_ticket(db_session, customer_b.id, "B-secret")

    # Customer A creates a saved search
    resp = client.post(
        "/searches",
        json={"name": "A-all", "filter": {"status": "open"}},
        headers=auth_header(customer_a),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    # Customer A schedules it (email field is required in unfixed code)
    sched_resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "a@test.com"},
        headers=auth_header(customer_a),
    )
    assert sched_resp.status_code == 201
    body = sched_resp.json()

    initial_ids = {t["id"] for t in body["initial_results"]}
    assert ticket_b.id not in initial_ids, (
        f"TC-55ACC8F8: Customer B's ticket {ticket_b.id} appeared in "
        "Customer A's scheduled report initial run"
    )
    assert ticket_a.id in initial_ids

    # Also check the persisted ReportRun ticket IDs
    stored_ids = set(json.loads(body["initial_run"]["result_ticket_ids_json"]))
    assert ticket_b.id not in stored_ids, (
        f"TC-55ACC8F8: Customer B's ticket {ticket_b.id} stored in "
        "Customer A's ReportRun.result_ticket_ids_json"
    )


# ---------------------------------------------------------------------------
# TC-1A85E0E6  Audit trail leaks cross-tenant IDs
# ---------------------------------------------------------------------------

def test_TC_1A85E0E6_run_history_does_not_expose_cross_tenant_ids(db_and_client):
    db_session, client = db_and_client
    """GET /searches/schedules/{id}/runs must not return ticket IDs the
    requesting customer is not allowed to see.

    Bug: result_ticket_ids_json is populated by an unscoped worker call and
    returned verbatim without re-filtering against the viewer's scope.
    """
    customer_a = make_user(db_session, "a@test.com")
    customer_b = make_user(db_session, "b@test.com")

    _ticket_a = make_ticket(db_session, customer_a.id, "A-secret")
    ticket_b = make_ticket(db_session, customer_b.id, "B-secret")

    # Customer A creates search + schedule (initial run fires immediately)
    search_resp = client.post(
        "/searches",
        json={"name": "A-all", "filter": {"status": "open"}},
        headers=auth_header(customer_a),
    )
    assert search_resp.status_code == 201
    search_id = search_resp.json()["id"]

    sched_resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "a@test.com"},
        headers=auth_header(customer_a),
    )
    assert sched_resp.status_code == 201
    schedule_id = sched_resp.json()["schedule"]["id"]

    # Fetch run history as Customer A
    runs_resp = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=auth_header(customer_a),
    )
    assert runs_resp.status_code == 200
    for run in runs_resp.json():
        stored_ids = set(json.loads(run["result_ticket_ids_json"]))
        assert ticket_b.id not in stored_ids, (
            f"TC-1A85E0E6: Customer B's ticket {ticket_b.id} leaked via "
            "ReportRun.result_ticket_ids_json in Customer A's run history"
        )


# ---------------------------------------------------------------------------
# TC-FFEB010C  Schedule email not pinned to user's own address
# ---------------------------------------------------------------------------

def test_TC_FFEB010C_schedule_email_pinned_to_user_email(db_and_client):
    db_session, client = db_and_client
    """POST /searches/{id}/schedule must deliver to the authenticated user's
    own email address and must not accept a caller-supplied arbitrary address.

    Bug: ScheduleReportCreate contains an `email` field that is accepted
    verbatim without checking that it matches the authenticated user.
    """
    customer_a = make_user(db_session, "a@test.com")

    search_resp = client.post(
        "/searches",
        json={"name": "A-all", "filter": {"status": "open"}},
        headers=auth_header(customer_a),
    )
    assert search_resp.status_code == 201
    search_id = search_resp.json()["id"]

    # Attempt to schedule with a different (attacker-controlled) email
    sched_resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.example"},
        headers=auth_header(customer_a),
    )

    if sched_resp.status_code == 201:
        # If the endpoint accepted the request, the stored email must be the
        # user's own address — not the attacker-supplied one.
        stored_email = sched_resp.json()["schedule"]["email"]
        assert stored_email == customer_a.email, (
            f"TC-FFEB010C: schedule accepted attacker email "
            f"'{stored_email}' instead of user's own '{customer_a.email}'"
        )
    # If the endpoint returned 4xx that's also acceptable (rejected the payload)
