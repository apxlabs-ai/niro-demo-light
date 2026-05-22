"""Regression tests for three security findings from pentest niro_pt_b87bdb9b.

Each test is designed to FAIL on the unfixed code and PASS after the fix.
Run before patching to confirm they detect the bug, then after patching to
confirm the fix is correct.

TC-67F387E3 (CRITICAL): scheduled-report worker runs unscoped search —
    cross-tenant tickets land in every customer's email report.

TC-85235A97 (HIGH): ReportRun.result_ticket_ids_json persists + returns
    cross-tenant ticket IDs via GET /searches/schedules/{id}/runs.

TC-0D10C000 (HIGH): in-process search result cache keyed on filter only —
    Customer B's cached rows served to Customer A with an identical filter.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import invalidate_cache


# ---------------------------------------------------------------------------
# Test database + client fixtures
# ---------------------------------------------------------------------------

_TEST_DB_URL = "sqlite://"  # in-memory, never touches helpdesk.db


@pytest.fixture()
def db_session():
    engine = create_engine(
        _TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture()
def client(db_session):
    """TestClient wired to the in-memory session; cache flushed before each test."""
    invalidate_cache()
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _make_user(db, email: str, role: Role) -> User:
    password = "pw-" + email
    u = User(
        email=email,
        password_hash=hash_password(password),
        full_name=email.split("@")[0],
        role=role,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _make_ticket(db, customer: User, subject: str) -> Ticket:
    t = Ticket(
        customer_id=customer.id,
        subject=subject,
        description="desc",
        status="open",
        priority="normal",
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _bearer(user: User) -> str:
    return f"Bearer {issue_token(user)}"


# ---------------------------------------------------------------------------
# TC-67F387E3 — scheduled report must not include other customers' tickets
# ---------------------------------------------------------------------------


def test_scheduled_report_scoped_to_owner(client, db_session):
    """POST /searches/{id}/schedule: initial_run must contain only the
    schedule-owner's tickets, not tickets from other tenants."""
    cust_a = _make_user(db_session, "a@test.com", Role.customer)
    cust_b = _make_user(db_session, "b@test.com", Role.customer)

    ticket_a = _make_ticket(db_session, cust_a, "A-secret")
    _ticket_b = _make_ticket(db_session, cust_b, "B-ticket")

    invalidate_cache()

    # Customer B creates a broad saved search (no filters — matches everything
    # in the unscoped path).
    r = client.post(
        "/searches",
        json={"name": "all-open", "filter": {}, "pinned": False},
        headers={"Authorization": _bearer(cust_b)},
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Customer B schedules a report.
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "b@test.com"},
        headers={"Authorization": _bearer(cust_b)},
    )
    assert r.status_code == 201
    body = r.json()

    # The initial run's result_count must equal only B's ticket count (1).
    run = body["initial_run"]
    assert run["result_count"] == 1, (
        f"TC-67F387E3: initial_run.result_count={run['result_count']}; "
        f"expected 1 (only B's ticket). Cross-tenant leak detected."
    )

    # The persisted result_ticket_ids_json must not contain A's ticket id.
    import json
    ids = json.loads(run["result_ticket_ids_json"])
    assert ticket_a.id not in ids, (
        f"TC-67F387E3: result_ticket_ids_json={ids} contains A's ticket "
        f"id={ticket_a.id}. Cross-tenant IDs must not be stored."
    )


# ---------------------------------------------------------------------------
# TC-85235A97 — run history must not expose cross-tenant ticket IDs
# ---------------------------------------------------------------------------


def test_run_history_ticket_ids_scoped(client, db_session):
    """GET /searches/schedules/{id}/runs: result_ticket_ids_json must
    contain only IDs the schedule owner is entitled to see."""
    cust_a = _make_user(db_session, "aa@test.com", Role.customer)
    cust_b = _make_user(db_session, "bb@test.com", Role.customer)

    ticket_a = _make_ticket(db_session, cust_a, "AA-secret")
    ticket_b = _make_ticket(db_session, cust_b, "BB-ticket")

    invalidate_cache()

    r = client.post(
        "/searches",
        json={"name": "search", "filter": {}, "pinned": False},
        headers={"Authorization": _bearer(cust_b)},
    )
    search_id = r.json()["id"]

    client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "bb@test.com"},
        headers={"Authorization": _bearer(cust_b)},
    )

    r = client.get(
        f"/searches/schedules/1/runs",
        headers={"Authorization": _bearer(cust_b)},
    )
    assert r.status_code == 200
    runs = r.json()
    assert runs, "Expected at least one run row"

    import json
    for run in runs:
        ids = json.loads(run["result_ticket_ids_json"])
        assert ticket_a.id not in ids, (
            f"TC-85235A97: run history exposes A's ticket id={ticket_a.id} "
            f"to Customer B. result_ticket_ids_json={ids}"
        )
        assert ticket_b.id in ids or not ids, (
            f"TC-85235A97: B's own ticket {ticket_b.id} missing from {ids}"
        )


# ---------------------------------------------------------------------------
# TC-0D10C000 — cache must be keyed per tenant, not just per filter
# ---------------------------------------------------------------------------


def test_search_cache_not_shared_across_tenants(client, db_session):
    """GET /searches/{id}/run: if two customers run the same filter within
    the cache TTL, each must see only their own tickets."""
    cust_a = _make_user(db_session, "ca@test.com", Role.customer)
    cust_b = _make_user(db_session, "cb@test.com", Role.customer)

    ticket_a = _make_ticket(db_session, cust_a, "CacheTest-A-secret")
    ticket_b = _make_ticket(db_session, cust_b, "CacheTest-B-secret")

    invalidate_cache()

    # Both customers create an identical filter (empty → all open).
    r = client.post(
        "/searches",
        json={"name": "s", "filter": {}, "pinned": False},
        headers={"Authorization": _bearer(cust_a)},
    )
    search_a = r.json()["id"]

    r = client.post(
        "/searches",
        json={"name": "s", "filter": {}, "pinned": False},
        headers={"Authorization": _bearer(cust_b)},
    )
    search_b = r.json()["id"]

    # Customer B runs first — populates cache slot for this filter.
    r = client.get(
        f"/searches/{search_b}/run",
        headers={"Authorization": _bearer(cust_b)},
    )
    assert r.status_code == 200
    b_ids = {t["id"] for t in r.json()["tickets"]}
    assert ticket_b.id in b_ids, "Sanity: B should see their own ticket"

    # Customer A runs immediately after — must get A's tickets, NOT B's cached rows.
    r = client.get(
        f"/searches/{search_a}/run",
        headers={"Authorization": _bearer(cust_a)},
    )
    assert r.status_code == 200
    a_result = r.json()
    a_ids = {t["id"] for t in a_result["tickets"]}

    assert ticket_b.id not in a_ids, (
        f"TC-0D10C000: Customer A's search returned Customer B's ticket "
        f"id={ticket_b.id}. Cache is not scoped per tenant."
    )
    assert ticket_a.id in a_ids, (
        f"TC-0D10C000: Customer A's own ticket id={ticket_a.id} missing. "
        f"Got: {a_ids}"
    )
