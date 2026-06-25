"""Regression tests for saved-search / scheduled-report tenant isolation.

These guard the CRITICAL finding TC-CB0F4816: a customer scheduling an
email report from a saved search must receive ONLY their own tickets —
never another tenant's. The scheduled-report worker runs server-side and
must scope the search to the saved search's owner, exactly as the
synchronous GET /searches/{id}/run path already does.

`test_schedule_report_does_not_leak_other_tenants_tickets` FAILS on the
unfixed code (the worker calls execute_search with no scope → global
cross-tenant view) and PASSES once app/jobs.py passes scope=owner.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import current_user, hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Priority, Role, Status, Ticket, User


@pytest.fixture()
def db():
    # StaticPool: one shared connection so the in-memory DB is visible
    # across threads — FastAPI sync routes run in a worker thread, and a
    # per-thread pool would hand them an empty database.
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
def two_tenants(db):
    """Customer A with 2 tickets, Customer B with 2 'B-secret' tickets."""
    alex = User(
        email="alex@customer.example.com",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.example.com",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)

    a_tickets = [
        Ticket(customer_id=alex.id, subject="A-ticket-1", description="a1",
               status=Status.open, priority=Priority.low),
        Ticket(customer_id=alex.id, subject="A-ticket-2", description="a2",
               status=Status.open, priority=Priority.low),
    ]
    b_tickets = [
        Ticket(customer_id=blair.id, subject="B-secret-1", description="b1",
               status=Status.open, priority=Priority.high),
        Ticket(customer_id=blair.id, subject="B-secret-2", description="b2",
               status=Status.open, priority=Priority.high),
    ]
    db.add_all(a_tickets + b_tickets)
    db.commit()
    for t in a_tickets + b_tickets:
        db.refresh(t)
    return alex, blair, a_tickets, b_tickets


@pytest.fixture()
def client_as_alex(db, two_tenants):
    """TestClient authenticated as Customer A via dependency override."""
    alex, *_ = two_tenants
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[current_user] = lambda: alex
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    # Entering the TestClient builds the middleware stack on the shared
    # app object. Reset it so a later fixture (e.g. test_mtls) can still
    # add_middleware without "Cannot add middleware after start" errors.
    app.middleware_stack = None


def test_run_search_is_scoped_to_owner(client_as_alex, two_tenants):
    """Baseline (already correct): GET /run only returns the caller's tickets."""
    alex, blair, a_tickets, b_tickets = two_tenants
    resp = client_as_alex.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False}
    )
    assert resp.status_code == 201
    sid = resp.json()["id"]

    run = client_as_alex.get(f"/searches/{sid}/run")
    assert run.status_code == 200
    assert run.json()["count"] == len(a_tickets)
    returned_ids = {t["id"] for t in run.json()["tickets"]}
    assert {t.id for t in b_tickets}.isdisjoint(returned_ids)


def test_schedule_report_does_not_leak_other_tenants_tickets(
    client_as_alex, two_tenants, tmp_path, monkeypatch
):
    """REGRESSION (TC-CB0F4816): scheduling a report must not include or
    email another tenant's tickets.

    On the unfixed code the worker runs the filter with scope=None, so
    initial_run.result_count is the global count (4) and Customer B's
    ticket IDs / subjects land in the run record and the mock email.
    """
    alex, blair, a_tickets, b_tickets = two_tenants
    mail_log = tmp_path / "mail.log"
    monkeypatch.setenv("HELPDESK_MAIL_LOG", str(mail_log))

    resp = client_as_alex.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False}
    )
    sid = resp.json()["id"]

    sched = client_as_alex.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.example.com"},
    )
    assert sched.status_code == 201
    body = sched.json()

    b_ids = {t.id for t in b_tickets}

    # The persisted/emailed run must be scoped to Customer A only.
    assert body["initial_run"]["result_count"] == len(a_tickets), (
        "scheduled run leaked cross-tenant rows: "
        f"got {body['initial_run']['result_count']}, expected {len(a_tickets)}"
    )
    run_ids = set(json.loads(body["initial_run"]["result_ticket_ids_json"]))
    assert b_ids.isdisjoint(run_ids), (
        f"Customer B ticket IDs leaked into the run record: {b_ids & run_ids}"
    )

    # The mock email body must not carry Customer B's ticket subjects.
    sent = mail_log.read_text() if mail_log.exists() else ""
    assert "B-secret" not in sent, "Customer B subjects leaked into the emailed report"
