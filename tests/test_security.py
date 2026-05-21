"""Regression tests for the three security findings from the niro pentest.

TC-C86E1D31 (CRITICAL): scheduled-report worker runs unscoped, exfiltrating
    cross-tenant tickets via email and the initial_run audit row.
TC-26426659 (CRITICAL): search result cache is keyed by filter only, not by
    caller identity, so one customer's cached results leak to another.
TC-96004620 (HIGH): result_ticket_ids_json in ReportRunOut exposes cross-tenant
    ticket IDs returned by the unscoped worker.

Each test is written to FAIL on the unfixed code and PASS after the fix.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.main import app
from app.auth import hash_password
from app.models import Role, User, Ticket, Priority, Status
from app.db import get_db

# --- In-memory DB fixture -------------------------------------------

SQLALCHEMY_TEST_URL = "sqlite://"


@pytest.fixture()
def client():
    engine = create_engine(
        SQLALCHEMY_TEST_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, raise_server_exceptions=True) as c:
        db = TestingSession()
        # Two customers with separate tickets
        alex = User(
            email="alex@test.com",
            full_name="Alex",
            role=Role.customer,
            password_hash=hash_password("pass1234"),
        )
        blair = User(
            email="blair@test.com",
            full_name="Blair",
            role=Role.customer,
            password_hash=hash_password("pass1234"),
        )
        db.add_all([alex, blair])
        db.flush()
        db.add(Ticket(
            customer_id=alex.id,
            subject="Alex PRIVATE secret",
            description="alex only",
            status=Status.open,
            priority=Priority.high,
        ))
        db.add(Ticket(
            customer_id=blair.id,
            subject="Blair PRIVATE secret",
            description="blair only",
            status=Status.open,
            priority=Priority.high,
        ))
        db.commit()
        db.close()
        yield c

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def _token(client, email, password="pass1234"):
    r = client.post("/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- TC-C86E1D31: unscoped worker exfiltrates cross-tenant tickets ------

def test_scheduled_report_initial_run_scoped_to_owner(client):
    """POST /searches/{id}/schedule must return an initial_run whose
    result_count matches only the scheduling user's own tickets, not
    tickets from other tenants."""
    alex_tok = _token(client, "alex@test.com")

    # Create saved search that would match both tenants' tickets
    r = client.post("/searches", json={"name": "all PRIVATE", "filter": {"subject_contains": "PRIVATE"}}, headers=_auth(alex_tok))
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Schedule it — the initial run fires synchronously
    r = client.post(f"/searches/{search_id}/schedule", json={"frequency": "daily", "email": "alex@test.com"}, headers=_auth(alex_tok))
    assert r.status_code == 201, r.text
    body = r.json()

    # initial_run.result_count must be 1 (Alex's ticket only), not 2
    assert body["initial_run"]["result_count"] == 1, (
        f"Worker ran unscoped: result_count={body['initial_run']['result_count']} "
        f"(cross-tenant exfiltration — TC-C86E1D31)"
    )


# --- TC-96004620: result_ticket_ids_json must not expose other tenants' IDs --

def test_run_history_ticket_ids_scoped_to_owner(client):
    """GET /searches/schedules/{id}/runs must not return ticket IDs that
    belong to other tenants in result_ticket_ids_json."""
    import json as _json

    alex_tok = _token(client, "alex@test.com")

    r = client.post("/searches", json={"name": "PRIVATE", "filter": {"subject_contains": "PRIVATE"}}, headers=_auth(alex_tok))
    search_id = r.json()["id"]

    r = client.post(f"/searches/{search_id}/schedule", json={"frequency": "daily", "email": "alex@test.com"}, headers=_auth(alex_tok))
    assert r.status_code == 201
    schedule_id = r.json()["schedule"]["id"]

    r = client.get(f"/searches/schedules/{schedule_id}/runs", headers=_auth(alex_tok))
    assert r.status_code == 200
    runs = r.json()

    assert len(runs) >= 1
    # result_ticket_ids_json must either be absent from the schema or
    # contain only Alex's ticket IDs — Blair's ticket id must not appear.
    for run in runs:
        if "result_ticket_ids_json" in run:
            ids = _json.loads(run["result_ticket_ids_json"])
            # Get Blair's ticket id by running as Blair and seeing what she owns
            blair_tok = _token(client, "blair@test.com")
            br = client.post("/searches", json={"name": "b", "filter": {}}, headers=_auth(blair_tok))
            blair_search = br.json()["id"]
            br2 = client.get(f"/searches/{blair_search}/run", headers=_auth(blair_tok))
            blair_ids = {t["id"] for t in br2.json()["tickets"]}
            leaked = blair_ids & set(ids)
            assert not leaked, (
                f"result_ticket_ids_json contains Blair's ticket IDs {leaked} — TC-96004620"
            )


# --- TC-26426659: cache key must include caller identity ----------------

def test_cache_does_not_leak_across_tenants(client):
    """When two customers use the same filter, the second must receive
    her own tickets, not the first customer's cached result set."""
    from app.search import invalidate_cache
    invalidate_cache()  # start clean

    alex_tok = _token(client, "alex@test.com")
    blair_tok = _token(client, "blair@test.com")

    # Alex creates and runs a saved search with an empty filter
    r = client.post("/searches", json={"name": "all", "filter": {}}, headers=_auth(alex_tok))
    alex_search = r.json()["id"]
    r = client.get(f"/searches/{alex_search}/run", headers=_auth(alex_tok))
    assert r.status_code == 200
    alex_tickets = {t["id"] for t in r.json()["tickets"]}

    # Blair creates and runs a saved search with the identical filter (cache should NOT serve Alex's rows)
    r = client.post("/searches", json={"name": "all", "filter": {}}, headers=_auth(blair_tok))
    blair_search = r.json()["id"]
    r = client.get(f"/searches/{blair_search}/run", headers=_auth(blair_tok))
    assert r.status_code == 200
    blair_tickets = {t["id"] for t in r.json()["tickets"]}

    # Their ticket sets must be disjoint
    assert alex_tickets.isdisjoint(blair_tickets), (
        f"Cache leaked across tenants: Alex got {alex_tickets}, Blair got {blair_tickets}, "
        f"overlap={alex_tickets & blair_tickets} — TC-26426659"
    )

    # Bidirectional: Blair's results must not appear in Alex's next run
    r = client.get(f"/searches/{alex_search}/run", headers=_auth(alex_tok))
    alex_tickets2 = {t["id"] for t in r.json()["tickets"]}
    assert alex_tickets2.isdisjoint(blair_tickets), (
        f"Cache leaked Blair's data into Alex's run: {alex_tickets2 & blair_tickets} — TC-26426659"
    )
