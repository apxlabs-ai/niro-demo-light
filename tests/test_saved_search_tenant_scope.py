"""Regression tests: saved-search executor must enforce tenant scope on
every path, including the two non-request paths that previously leaked
across tenants.

Invariants under test (each paired with a green legitimate case so a red
is provably the invariant, not a broken environment):

  1. GET /searches/{id}/run must never serve one tenant another tenant's
     tickets out of the shared in-process result cache — even when an
     agent (all-tenant view) previously ran the SAME filter and populated
     the cache. Root cause: app/search.py _cache_key() keyed on filter
     JSON only, ignoring the caller's scope.

  2. A scheduled report's email body must contain only the owner's
     tickets. Root cause: app/jobs.py run_scheduled_report() called
     execute_search() WITHOUT scope=owner, returning every tenant's rows.

  3. The persisted run history (GET /searches/schedules/{id}/runs ->
     result_ticket_ids_json) must contain only the owner's ticket IDs.
     Same root cause as (2).

These exercise the project's real routes / worker via FastAPI TestClient
+ an isolated in-memory SQLite DB, following tests/test_mtls.py. The
in-process cache in app/search.py is module-global, so it is reset around
every test here.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import search as search_module
from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.jobs import run_scheduled_report
from app.main import app
from app.models import (
    ReportFrequency,
    Role,
    SavedSearch,
    ScheduledReport,
    Status,
    Ticket,
    User,
)
from app.search import serialize_filter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    # StaticPool keeps a single shared connection so the in-memory DB is
    # visible across the TestClient's worker thread + lifespan, not a
    # fresh empty DB per pool checkout.
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


@pytest.fixture(autouse=True)
def _reset_cache():
    """The result cache in app/search.py is module-global; isolate tests."""
    search_module.invalidate_cache()
    yield
    search_module.invalidate_cache()


@pytest.fixture()
def tenants(db):
    """Two customers in different tenants plus an agent, each with one
    open ticket. Returns (cust_a, cust_b, agent, t_a, t_b, t_agent)."""
    cust_a = User(
        email="alex@customer.test",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    cust_b = User(
        email="blair@customer.test",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.test",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([cust_a, cust_b, agent])
    db.commit()
    for u in (cust_a, cust_b, agent):
        db.refresh(u)

    t_a = Ticket(
        customer_id=cust_a.id,
        subject="ALEX-PRIVATE-SUBJECT",
        description="alex private body",
        status=Status.open,
        priority="low",
    )
    t_b = Ticket(
        customer_id=cust_b.id,
        subject="BLAIR-PRIVATE-SUBJECT",
        description="blair PRIVATE SECRET body",
        status=Status.open,
        priority="low",
    )
    t_agent = Ticket(
        customer_id=agent.id,
        subject="AGENT-TENANT-SUBJECT",
        description="agent tenant body",
        status=Status.open,
        priority="low",
    )
    db.add_all([t_a, t_b, t_agent])
    db.commit()
    for t in (t_a, t_b, t_agent):
        db.refresh(t)
    return cust_a, cust_b, agent, t_a, t_b, t_agent


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": "Bearer " + issue_token(user)}


def _make_saved_search(db, owner: User, filter_dict: dict) -> SavedSearch:
    saved = SavedSearch(
        owner_id=owner.id,
        name=f"search-for-{owner.id}",
        filter_json=serialize_filter(filter_dict),
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


# ---------------------------------------------------------------------------
# 1. Cross-tenant cache-poisoning via GET /searches/{id}/run  (TC-F985AEDC)
# ---------------------------------------------------------------------------

def test_run_search_cache_is_not_shared_across_tenants(db, client, tenants):
    cust_a, cust_b, agent, t_a, t_b, t_agent = tenants
    filt = {"status": "open"}
    a_search = _make_saved_search(db, cust_a, filt)
    agent_search = _make_saved_search(db, agent, filt)

    # --- Positive control: fresh cache, customer A runs first. Scoping
    #     works -> A sees only their own ticket. Proves the environment is
    #     healthy so the exploit's red is meaningful.
    search_module.invalidate_cache()
    resp = client.get(f"/searches/{a_search.id}/run", headers=_auth(cust_a))
    assert resp.status_code == 200
    control_ids = {t["id"] for t in resp.json()["tickets"]}
    assert t_a.id in control_ids, "customer A must see their own ticket"
    assert t_b.id not in control_ids, "control: A must not see B's ticket"
    assert t_agent.id not in control_ids, "control: A must not see agent-tenant ticket"

    # --- Exploit: agent (all-tenant view) runs the SAME filter first and
    #     populates the shared cache, then customer A runs their search.
    #     On the vulnerable code the cache key ignores scope, so A is
    #     served the agent's cross-tenant set.
    search_module.invalidate_cache()
    agent_resp = client.get(f"/searches/{agent_search.id}/run", headers=_auth(agent))
    assert agent_resp.status_code == 200
    agent_ids = {t["id"] for t in agent_resp.json()["tickets"]}
    assert {t_a.id, t_b.id, t_agent.id} <= agent_ids, (
        "sanity: agent (all-tenant) view should include every tenant's ticket"
    )

    victim_resp = client.get(f"/searches/{a_search.id}/run", headers=_auth(cust_a))
    assert victim_resp.status_code == 200
    victim_ids = {t["id"] for t in victim_resp.json()["tickets"]}
    assert t_a.id in victim_ids, "customer A must still see their own ticket"
    assert t_b.id not in victim_ids, (
        "cross-tenant leak: customer A received customer B's ticket from the "
        "agent-poisoned shared result cache"
    )
    assert t_agent.id not in victim_ids, (
        "cross-tenant leak: customer A received the agent-tenant ticket from "
        "the shared result cache"
    )


# ---------------------------------------------------------------------------
# 2. Scheduled-report email leaks cross-tenant tickets  (TC-DFD6E012)
# ---------------------------------------------------------------------------

def test_scheduled_report_email_contains_only_owner_tickets(db, tenants, monkeypatch, tmp_path):
    cust_a, cust_b, agent, t_a, t_b, t_agent = tenants
    mail_log = tmp_path / "mail.log"
    monkeypatch.setenv("HELPDESK_MAIL_LOG", str(mail_log))

    # Owner = customer B, empty filter (would match every ticket if unscoped).
    saved = _make_saved_search(db, cust_b, {})
    sched = ScheduledReport(
        saved_search_id=saved.id,
        frequency=ReportFrequency.daily,
        email="blair@customer.test",
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)
    assert run.success is True

    # The legitimate content (owner's own ticket) must be present...
    body = json.loads(mail_log.read_text().strip().splitlines()[-1])["body"]
    assert t_b.subject in body, "owner's own ticket must appear in the report"
    # ...and no other tenant's content may leak into the email.
    assert t_a.subject not in body, "email leaked another customer's ticket"
    assert t_agent.subject not in body, "email leaked the agent-tenant ticket"
    assert run.result_count == 1, (
        f"report must count only the owner's tickets, got {run.result_count}"
    )


# ---------------------------------------------------------------------------
# 3. Run-history endpoint leaks cross-tenant ticket IDs  (TC-03E2B19C)
# ---------------------------------------------------------------------------

def test_schedule_run_history_only_exposes_owner_ticket_ids(db, client, tenants, monkeypatch, tmp_path):
    cust_a, cust_b, agent, t_a, t_b, t_agent = tenants
    monkeypatch.setenv("HELPDESK_MAIL_LOG", str(tmp_path / "mail.log"))

    # Owner = customer A, empty filter. Creating the schedule fires an
    # initial run that persists a ReportRun row.
    saved = _make_saved_search(db, cust_a, {})
    resp = client.post(
        f"/searches/{saved.id}/schedule",
        headers=_auth(cust_a),
        json={"frequency": "daily", "email": "alex@customer.example.com"},
    )
    assert resp.status_code == 201
    sched_id = resp.json()["schedule"]["id"]

    runs = client.get(
        f"/searches/schedules/{sched_id}/runs", headers=_auth(cust_a)
    )
    assert runs.status_code == 200
    history = runs.json()
    assert history, "expected at least the initial run in the history"
    ids = set(json.loads(history[0]["result_ticket_ids_json"]))

    assert t_a.id in ids, "owner's own ticket id must appear in run history"
    assert t_b.id not in ids, (
        "run history leaked another customer's ticket id"
    )
    assert t_agent.id not in ids, (
        "run history leaked the agent-tenant ticket id"
    )
