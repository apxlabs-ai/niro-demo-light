"""Regression tests for four security findings from pentest niro_pt_1200781d.

Each test is named after its TC-ID and must FAIL against the unfixed code,
then PASS after the fix is applied. Do not reorder: tests share no state.
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.auth import hash_password
from app.models import Role, User

# --------------------------------------------------------------------------
# Shared in-memory DB + client fixture
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    # StaticPool ensures every session reuses the same in-memory connection,
    # so Base.metadata.create_all sees the same DB that queries hit.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed two customers + one agent into the test DB
    db = TestingSession()
    alex = User(
        email="alex@example.com",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("alex-pass"),
    )
    blair = User(
        email="blair@example.com",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("blair-pass"),
    )
    agent = User(
        email="agent@example.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("agent-pass"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    db.close()

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def _login(client, email, password):
    r = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# TC-E0E8BCAF — CRITICAL: cache key does not include caller scope
#
# Blair runs a saved search with the same filter that Alex already ran.
# Without the fix the cache returns Alex's tickets to Blair.
# --------------------------------------------------------------------------


def test_TC_E0E8BCAF_cache_scope_isolation(client):
    alex_tok = _login(client, "alex@example.com", "alex-pass")
    blair_tok = _login(client, "blair@example.com", "blair-pass")

    # Each customer creates a ticket
    r = client.post(
        "/tickets",
        json={"subject": "ALEX-PRIVATE", "description": "alex data", "priority": "high"},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    alex_ticket_id = r.json()["id"]

    r = client.post(
        "/tickets",
        json={"subject": "BLAIR-PRIVATE", "description": "blair data", "priority": "high"},
        headers=_auth(blair_tok),
    )
    assert r.status_code == 201
    blair_ticket_id = r.json()["id"]

    # Both create identical saved searches (empty filter → same cache key without fix)
    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    alex_search_id = r.json()["id"]

    r = client.post(
        "/searches",
        json={"name": "all", "filter": {}},
        headers=_auth(blair_tok),
    )
    assert r.status_code == 201
    blair_search_id = r.json()["id"]

    # Alex runs first — seeds the cache
    r = client.get(f"/searches/{alex_search_id}/run", headers=_auth(alex_tok))
    assert r.status_code == 200
    alex_ids = {t["id"] for t in r.json()["tickets"]}
    assert alex_ticket_id in alex_ids
    assert blair_ticket_id not in alex_ids, "Alex should not see Blair's ticket"

    # Blair runs — must NOT get Alex's data from the cache
    r = client.get(f"/searches/{blair_search_id}/run", headers=_auth(blair_tok))
    assert r.status_code == 200
    blair_ids = {t["id"] for t in r.json()["tickets"]}
    assert blair_ticket_id in blair_ids, "Blair should see her own ticket"
    assert alex_ticket_id not in blair_ids, "Blair must not receive Alex's ticket from cache"


# --------------------------------------------------------------------------
# TC-F5D8E1C5 — CRITICAL: scheduled report worker runs without tenant scope
#
# When Alex schedules a report, run_scheduled_report must only include
# Alex's tickets. result_ticket_ids_json on the initial ReportRun must
# not contain Blair's ticket ID.
# --------------------------------------------------------------------------


def test_TC_F5D8E1C5_scheduled_report_tenant_scope(client):
    alex_tok = _login(client, "alex@example.com", "alex-pass")
    blair_tok = _login(client, "blair@example.com", "blair-pass")

    # Ensure Blair has at least one ticket distinct from Alex's
    r = client.post(
        "/tickets",
        json={"subject": "BLAIR-SCHEDULED", "description": "blair sched", "priority": "low"},
        headers=_auth(blair_tok),
    )
    assert r.status_code == 201
    blair_ticket_id = r.json()["id"]

    # Alex creates and runs a schedule
    r = client.post(
        "/searches",
        json={"name": "sched-test", "filter": {}},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alex@example.com"},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    run_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])

    assert blair_ticket_id not in run_ids, (
        f"Blair's ticket {blair_ticket_id} must not appear in Alex's scheduled report "
        f"result_ticket_ids_json: {run_ids}"
    )


# --------------------------------------------------------------------------
# TC-00CC9832 — HIGH: cross-tenant ticket IDs in run history
#
# The run history endpoint must not leak other customers' ticket IDs
# in result_ticket_ids_json.
# --------------------------------------------------------------------------


def test_TC_00CC9832_run_history_no_cross_tenant_ids(client):
    alex_tok = _login(client, "alex@example.com", "alex-pass")
    blair_tok = _login(client, "blair@example.com", "blair-pass")

    # Blair creates a fresh ticket so we have a known ID to check
    r = client.post(
        "/tickets",
        json={"subject": "BLAIR-HISTORY", "description": "blair hist", "priority": "low"},
        headers=_auth(blair_tok),
    )
    assert r.status_code == 201
    blair_ticket_id = r.json()["id"]

    # Alex schedules a report
    r = client.post(
        "/searches",
        json={"name": "history-test", "filter": {}},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alex@example.com"},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    schedule_id = r.json()["schedule"]["id"]

    # Fetch run history
    r = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(alex_tok),
    )
    assert r.status_code == 200
    runs = r.json()
    assert len(runs) >= 1

    for run in runs:
        stored_ids = json.loads(run["result_ticket_ids_json"])
        assert blair_ticket_id not in stored_ids, (
            f"Blair's ticket {blair_ticket_id} leaked into Alex's run history: {stored_ids}"
        )


# --------------------------------------------------------------------------
# TC-AA078251 — MEDIUM: arbitrary email accepted for scheduled reports
#
# The schedule endpoint must reject an email that does not belong to the
# authenticated user. Expecting 422 (or 400).
# --------------------------------------------------------------------------


def test_TC_AA078251_schedule_email_must_match_user(client):
    alex_tok = _login(client, "alex@example.com", "alex-pass")

    r = client.post(
        "/searches",
        json={"name": "email-test", "filter": {}},
        headers=_auth(alex_tok),
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(alex_tok),
    )
    assert r.status_code in (400, 422), (
        f"Expected 400/422 when scheduling to an address not owned by the user, "
        f"got {r.status_code}: {r.text}"
    )
