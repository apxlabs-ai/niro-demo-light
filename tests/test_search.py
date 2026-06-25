import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base
from app.jobs import run_scheduled_report
from app.models import ReportFrequency, Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import execute_search, invalidate_cache, serialize_filter


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)
    invalidate_cache()


@pytest.fixture()
def customers_with_tickets(db):
    alex = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.example.com",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)

    alex_ticket = Ticket(
        customer_id=alex.id,
        subject="Alex private ticket",
        description="owned by alex",
    )
    blair_ticket = Ticket(
        customer_id=blair.id,
        subject="Blair private ticket",
        description="owned by blair",
    )
    db.add_all([alex_ticket, blair_ticket])
    db.commit()
    db.refresh(alex_ticket)
    db.refresh(blair_ticket)

    return alex, blair, alex_ticket, blair_ticket


def test_search_cache_is_scoped_per_customer(db, customers_with_tickets):
    alex, blair, alex_ticket, blair_ticket = customers_with_tickets
    filter_json = serialize_filter({})

    alex_rows = execute_search(filter_json, db, scope=alex)
    blair_rows = execute_search(filter_json, db, scope=blair)

    assert [row["id"] for row in alex_rows] == [alex_ticket.id]
    assert [row["id"] for row in blair_rows] == [blair_ticket.id]


def test_scheduled_report_uses_saved_search_owner_scope(db, customers_with_tickets):
    alex, _, alex_ticket, _ = customers_with_tickets
    saved = SavedSearch(
        owner_id=alex.id,
        name="Alex tickets",
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

    assert run.success is True
    assert run.result_count == 1
    assert json.loads(run.result_ticket_ids_json) == [alex_ticket.id]
