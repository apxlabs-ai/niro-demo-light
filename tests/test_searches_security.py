import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.jobs import run_scheduled_report
from app.models import ReportFrequency, Role, SavedSearch, ScheduledReport, User


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
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
def users(db):
    customer = User(
        email="customer@example.com",
        full_name="Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@example.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([customer, agent])
    db.commit()
    db.refresh(customer)
    db.refresh(agent)
    return customer, agent


@pytest.fixture()
def saved_search(db, users):
    customer, _ = users
    saved = SavedSearch(
        owner_id=customer.id,
        name="private search",
        filter_json='{"status": "open"}',
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


@pytest.fixture()
def agent_saved_search(db, users):
    _, agent = users
    saved = SavedSearch(
        owner_id=agent.id,
        name="agent search",
        filter_json='{"status": "open"}',
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def test_agent_cannot_patch_customer_saved_search(client, db, users, saved_search):
    _, agent = users

    resp = client.patch(
        f"/searches/{saved_search.id}",
        json={"name": "agent edited"},
        headers=_auth(agent),
    )

    assert resp.status_code == 403
    db.refresh(saved_search)
    assert saved_search.name == "private search"


def test_agent_cannot_delete_customer_saved_search(client, db, users, saved_search):
    _, agent = users

    resp = client.delete(f"/searches/{saved_search.id}", headers=_auth(agent))

    assert resp.status_code == 403
    assert db.get(SavedSearch, saved_search.id) is not None


def test_agent_cannot_schedule_customer_saved_search(client, db, users, saved_search):
    _, agent = users

    resp = client.post(
        f"/searches/{saved_search.id}/schedule",
        json={"frequency": "daily", "email": "agent@example.com"},
        headers=_auth(agent),
    )

    assert resp.status_code == 403


def test_agent_cannot_schedule_report_to_external_email(
    client, users, agent_saved_search
):
    _, agent = users

    resp = client.post(
        f"/searches/{agent_saved_search.id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.example"},
        headers=_auth(agent),
    )

    assert resp.status_code == 403


def test_worker_blocks_agent_report_to_external_email(
    db, users, agent_saved_search, tmp_path, monkeypatch
):
    mail_log = tmp_path / "mail.log"
    monkeypatch.setenv("HELPDESK_MAIL_LOG", str(mail_log))
    sched = ScheduledReport(
        saved_search_id=agent_saved_search.id,
        frequency=ReportFrequency.daily,
        email="attacker@evil.example",
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)

    assert run.success is False
    assert run.error == "recipient not approved"
    assert not mail_log.exists()
