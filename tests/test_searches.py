"""Regression tests for saved-search security findings.

TC-C0AD1774: In-process result cache does not include scope identity in the
  cache key. Two customers running the same filter within the TTL window get
  the same cached rows — the second customer receives the first customer's
  tickets. Each test here MUST FAIL on unfixed code and PASS after the fix.

TC-341F98BD: run_scheduled_report() calls execute_search without passing
  scope=owner, so the scheduled report worker returns tickets across all
  tenants. MUST FAIL on unfixed code and PASS after the fix.

Test strategy: FastAPI TestClient with in-memory SQLite DB injected via
dependency_override. Both customers are created in the same DB. The
searches_router is registered on the test app via the normal include path.
Cache is flushed between tests via invalidate_cache() so tests are isolated.
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
from app.models import ReportRun, Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import invalidate_cache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def two_customers(db):
    """Seed two customers, each with one ticket, and return bearer tokens."""
    alex = User(
        email="alex@test.example",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@test.example",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)

    ticket_alex = Ticket(
        customer_id=alex.id,
        subject="ALEX CONFIDENTIAL",
        description="only alex should see this",
        status="open",
        priority="low",
    )
    ticket_blair = Ticket(
        customer_id=blair.id,
        subject="BLAIR CONFIDENTIAL",
        description="only blair should see this",
        status="open",
        priority="low",
    )
    db.add_all([ticket_alex, ticket_blair])
    db.commit()
    db.refresh(ticket_alex)
    db.refresh(ticket_blair)

    token_alex = issue_token(alex)
    token_blair = issue_token(blair)

    return alex, blair, ticket_alex, ticket_blair, token_alex, token_blair


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# TC-C0AD1774: cache key must include scope so two tenants with the same
# filter each get their own rows, not each other's.
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_tenants(client, two_customers):
    """TC-C0AD1774: running an identical filter as two different customers
    must return each customer's own tickets only.

    FAILS on unfixed code because _cache_key() hashes only the filter JSON,
    not the caller's identity. Customer A populates the cache; Customer B
    hits the same cache entry and receives A's rows.
    """
    alex, blair, ticket_alex, ticket_blair, token_alex, token_blair = two_customers
    invalidate_cache()  # ensure clean state

    # Both customers create saved searches with the same filter.
    resp = client.post(
        "/searches",
        json={"name": "alex open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_alex}"},
    )
    assert resp.status_code == 201
    search_alex_id = resp.json()["id"]

    resp = client.post(
        "/searches",
        json={"name": "blair open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_blair}"},
    )
    assert resp.status_code == 201
    search_blair_id = resp.json()["id"]

    # Alex runs first — cache MISS; result stored keyed by filter hash only
    # (in unfixed code, scope is NOT part of the key).
    resp_alex = client.get(
        f"/searches/{search_alex_id}/run",
        headers={"Authorization": f"Bearer {token_alex}"},
    )
    assert resp_alex.status_code == 200
    alex_ids = {t["id"] for t in resp_alex.json()["tickets"]}
    assert ticket_alex.id in alex_ids, "alex must see her own ticket"
    assert ticket_blair.id not in alex_ids, "alex must NOT see blair's ticket"

    # Blair runs next — should be a fresh query scoped to Blair's data.
    # On unfixed code this is a cache HIT and returns Alex's rows instead.
    resp_blair = client.get(
        f"/searches/{search_blair_id}/run",
        headers={"Authorization": f"Bearer {token_blair}"},
    )
    assert resp_blair.status_code == 200
    blair_ids = {t["id"] for t in resp_blair.json()["tickets"]}
    assert ticket_blair.id in blair_ids, "blair must see her own ticket"
    assert ticket_alex.id not in blair_ids, (
        "TC-C0AD1774: blair received alex's ticket — cache key must include scope"
    )


# ---------------------------------------------------------------------------
# TC-341F98BD: scheduled report must be scoped to the search owner's tickets.
# ---------------------------------------------------------------------------


def test_scheduled_report_is_scoped_to_owner(client, two_customers):
    """TC-341F98BD: POST /searches/{id}/schedule initial run must only contain
    the search owner's tickets, not tickets from other tenants.

    FAILS on unfixed code because run_scheduled_report() calls execute_search
    without passing scope=owner, so the query has no per-tenant WHERE clause
    and returns every ticket in the DB.
    """
    alex, blair, ticket_alex, ticket_blair, token_alex, _ = two_customers
    invalidate_cache()

    # Alex creates a saved search with an empty filter (would match all if unscoped).
    resp = client.post(
        "/searches",
        json={"name": "all tickets", "filter": {}},
        headers={"Authorization": f"Bearer {token_alex}"},
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    # Alex schedules a report — this fires an initial run via run_scheduled_report.
    resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alex@test.example"},
        headers={"Authorization": f"Bearer {token_alex}"},
    )
    assert resp.status_code == 201
    body = resp.json()

    # The persisted ReportRun must only count/list Alex's tickets.
    run = body["initial_run"]
    result_ids = set(__import__("json").loads(run["result_ticket_ids_json"]))
    assert ticket_alex.id in result_ids, "alex's own ticket must appear in the run"
    assert ticket_blair.id not in result_ids, (
        "TC-341F98BD: blair's ticket leaked into alex's scheduled report — "
        "run_scheduled_report must pass scope=owner to execute_search"
    )
    assert run["result_count"] == 1, (
        f"TC-341F98BD: expected 1 ticket (alex's only), got {run['result_count']}"
    )
