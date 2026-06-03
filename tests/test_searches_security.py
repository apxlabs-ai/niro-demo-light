import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.jobs import run_scheduled_report
from app.main import app
from app.models import ReportFrequency, Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import serialize_filter


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
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def customers(db):
    alex = User(
        email="alex-search@example.com",
        full_name="Alex Search",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair-search@example.com",
        full_name="Blair Search",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)

    alex_ticket = Ticket(
        customer_id=alex.id,
        subject="cache-marker-owned-by-alex",
        description="alex-only search result",
        status="open",
        priority="normal",
    )
    blair_ticket = Ticket(
        customer_id=blair.id,
        subject="blair-private-ticket",
        description="blair-only search result",
        status="open",
        priority="normal",
    )
    db.add_all([alex_ticket, blair_ticket])
    db.commit()
    db.refresh(alex_ticket)
    db.refresh(blair_ticket)
    return alex, blair, alex_ticket, blair_ticket


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def test_saved_search_cache_is_scoped_per_customer(client, customers):
    alex, blair, alex_ticket, _ = customers
    body = {
        "name": "same-filter",
        "filter": {"subject_contains": "cache-marker-owned-by-alex"},
        "pinned": False,
    }

    alex_search = client.post("/searches", json=body, headers=_auth(alex)).json()
    alex_result = client.get(
        f"/searches/{alex_search['id']}/run", headers=_auth(alex)
    )
    assert alex_result.status_code == 200
    assert [t["id"] for t in alex_result.json()["tickets"]] == [alex_ticket.id]

    blair_search = client.post("/searches", json=body, headers=_auth(blair)).json()
    blair_result = client.get(
        f"/searches/{blair_search['id']}/run", headers=_auth(blair)
    )

    assert blair_result.status_code == 200
    assert blair_result.json()["count"] == 0
    assert blair_result.json()["tickets"] == []


def test_scheduled_report_runs_with_saved_search_owner_scope(db, customers, monkeypatch):
    alex, _, alex_ticket, blair_ticket = customers
    monkeypatch.setenv("HELPDESK_MAIL_LOG", "/tmp/helpdesk-test-mail.log")
    saved = SavedSearch(
        owner_id=alex.id,
        name="alex empty filter",
        filter_json=serialize_filter({}),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    schedule = ScheduledReport(
        saved_search_id=saved.id,
        frequency=ReportFrequency.daily,
        email="alex@example.com",
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    run = run_scheduled_report(schedule.id, db)
    result_ids = json.loads(run.result_ticket_ids_json)

    assert run.success is True
    assert run.result_count == 1
    assert result_ids == [alex_ticket.id]
    assert blair_ticket.id not in result_ids
