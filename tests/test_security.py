"""Regression tests for the four findings from pentest niro_pt_ef8fd969.

Each test is named after its finding ID and MUST FAIL before the fixes
are applied (proving the test can detect the bug). After the fixes,
each test must pass.
"""
import json

import pytest

from app.models import Role
from app.search import _cache, execute_search, serialize_filter
from app.models import SavedSearch

from .conftest import _auth, _login, _make_ticket, _make_user


# ---------------------------------------------------------------------------
# TC-DA81F835 (CRITICAL): scheduled report worker ignores tenant scope
# ---------------------------------------------------------------------------

def test_TC_DA81F835_scheduled_report_worker_respects_tenant_scope(client, db_session):
    """run_scheduled_report must not include other tenants' tickets in the
    emailed result set (result_ticket_ids_json / result_count)."""
    alex = _make_user(db_session, "alex@example.com", Role.customer)
    blair = _make_user(db_session, "blair@example.com", Role.customer)
    t_alex = _make_ticket(db_session, alex, "ALEX-SECRET")
    _make_ticket(db_session, blair, "BLAIR-SECRET")

    tok = _login(client, "alex@example.com")

    # Create a saved search (open tickets — would match both tenants if unscoped)
    r = client.post(
        "/searches",
        json={"name": "all open", "filter": {"status": "open"}, "pinned": False},
        headers=_auth(tok),
    )
    assert r.status_code == 201, r.text
    search_id = r.json()["id"]

    # Schedule: this fires run_scheduled_report immediately
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alex@example.com"},
        headers=_auth(tok),
    )
    assert r.status_code == 201, r.text
    body = r.json()

    initial_run = body["initial_run"]
    ids = json.loads(initial_run["result_ticket_ids_json"])

    # The worker must only include Alex's ticket, not Blair's
    assert initial_run["result_count"] == 1, (
        f"Worker returned {initial_run['result_count']} tickets; expected 1 (only Alex's). "
        f"result_ticket_ids_json={initial_run['result_ticket_ids_json']}"
    )
    assert t_alex.id in ids, "Alex's own ticket must appear in the run"
    assert all(i == t_alex.id for i in ids), (
        f"Run contains ticket IDs not owned by Alex: {ids}"
    )


# ---------------------------------------------------------------------------
# TC-57038A7B (CRITICAL): result cache not keyed by user/scope
# ---------------------------------------------------------------------------

def test_TC_57038A7B_cache_not_shared_across_tenants(client, db_session):
    """A cache hit populated by an agent (full view) must not be served
    to a customer who is only allowed to see their own tickets."""
    agent = _make_user(db_session, "agent@example.com", Role.agent)
    alex = _make_user(db_session, "alex@example.com", Role.customer)
    blair = _make_user(db_session, "blair@example.com", Role.customer)
    _make_ticket(db_session, alex, "ALEX-SECRET")
    _make_ticket(db_session, blair, "BLAIR-SECRET")

    agent_tok = _login(client, "agent@example.com")
    alex_tok = _login(client, "alex@example.com")

    # Each user creates a saved search with the same filter
    for tok in (agent_tok, alex_tok):
        r = client.post(
            "/searches",
            json={"name": "open", "filter": {"status": "open"}, "pinned": False},
            headers=_auth(tok),
        )
        assert r.status_code == 201, r.text

    # Agent runs first — populates cache with all-tenant result
    searches = client.get("/searches", headers=_auth(agent_tok)).json()
    agent_search_id = next(s["id"] for s in searches if s["owner_id"] == agent.id)
    r = client.get(f"/searches/{agent_search_id}/run", headers=_auth(agent_tok))
    assert r.status_code == 200
    assert r.json()["count"] == 2  # agent sees both

    # Alex runs her search — must NOT get Blair's ticket from cache
    searches = client.get("/searches", headers=_auth(alex_tok)).json()
    alex_search_id = next(s["id"] for s in searches if s["owner_id"] == alex.id)
    r = client.get(f"/searches/{alex_search_id}/run", headers=_auth(alex_tok))
    assert r.status_code == 200
    data = r.json()
    subjects = [t["subject"] for t in data["tickets"]]
    assert "BLAIR-SECRET" not in subjects, (
        f"Cache leaked Blair's ticket to Alex: {subjects}"
    )
    assert data["count"] == 1, (
        f"Alex received {data['count']} tickets; expected 1. subjects={subjects}"
    )


# ---------------------------------------------------------------------------
# TC-FFDE6F80 (HIGH): schedule can be directed to arbitrary email
# ---------------------------------------------------------------------------

def test_TC_FFDE6F80_schedule_email_must_match_authenticated_user(client, db_session):
    """POST /searches/{id}/schedule must reject an email address that does
    not belong to the authenticated user."""
    alex = _make_user(db_session, "alex@example.com", Role.customer)
    _make_ticket(db_session, alex, "ALEX-SECRET")
    tok = _login(client, "alex@example.com")

    r = client.post(
        "/searches",
        json={"name": "s", "filter": {}, "pinned": False},
        headers=_auth(tok),
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Attempt to direct the report to an attacker-controlled address
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(tok),
    )
    assert r.status_code == 422, (
        f"Expected 422 when email != user email; got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# TC-8D727213 (MEDIUM): run history exposes other tenants' ticket IDs
# ---------------------------------------------------------------------------

def test_TC_8D727213_run_history_ticket_ids_scoped_to_owner(client, db_session):
    """ReportRun.result_ticket_ids_json must not contain ticket IDs that
    belong to a different tenant than the schedule owner."""
    alex = _make_user(db_session, "alex@example.com", Role.customer)
    blair = _make_user(db_session, "blair@example.com", Role.customer)
    t_alex = _make_ticket(db_session, alex, "ALEX-SECRET")
    t_blair = _make_ticket(db_session, blair, "BLAIR-SECRET")

    tok = _login(client, "alex@example.com")

    r = client.post(
        "/searches",
        json={"name": "open", "filter": {"status": "open"}, "pinned": False},
        headers=_auth(tok),
    )
    search_id = r.json()["id"]

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alex@example.com"},
        headers=_auth(tok),
    )
    assert r.status_code == 201
    schedule_id = r.json()["schedule"]["id"]

    # Inspect run history
    r = client.get(f"/searches/schedules/{schedule_id}/runs", headers=_auth(tok))
    assert r.status_code == 200
    runs = r.json()
    assert len(runs) >= 1

    for run in runs:
        ids = json.loads(run["result_ticket_ids_json"])
        assert t_blair.id not in ids, (
            f"Run history exposes Blair's ticket ID {t_blair.id} to Alex: ids={ids}"
        )
