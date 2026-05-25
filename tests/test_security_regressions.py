"""Regression tests for two critical IDOR/data-leak bugs.

TC-B1C0F6E6: cache key omits scope → customer B sees customer A's
             tickets when they share the same filter string.

TC-E6C9E2B3: run_scheduled_report omits scope → background worker
             emails cross-tenant ticket data to the schedule owner.

Each test is written to FAIL on the unfixed code and PASS after the fix.
"""
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base
from app.jobs import run_scheduled_report
from app.models import (
    ReportFrequency,
    Role,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
)
from app.search import execute_search, invalidate_cache


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


@pytest.fixture()
def two_customers(db):
    customer_a = User(
        email="a@test.test",
        full_name="Customer A",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    customer_b = User(
        email="b@test.test",
        full_name="Customer B",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([customer_a, customer_b])
    db.commit()
    db.refresh(customer_a)
    db.refresh(customer_b)

    ticket_a = Ticket(
        customer_id=customer_a.id,
        subject="A-secret-ticket",
        description="owned by A",
        status="open",
        priority="low",
    )
    ticket_b = Ticket(
        customer_id=customer_b.id,
        subject="B-secret-ticket",
        description="owned by B",
        status="open",
        priority="low",
    )
    db.add_all([ticket_a, ticket_b])
    db.commit()
    db.refresh(ticket_a)
    db.refresh(ticket_b)

    return customer_a, customer_b, ticket_a, ticket_b


# ---------------------------------------------------------------------------
# TC-B1C0F6E6 — cache key must incorporate scope
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_customers(db, two_customers):
    """Customer B must not see customer A's tickets when they share the same
    filter and customer A has already seeded the cache."""
    customer_a, customer_b, ticket_a, ticket_b = two_customers

    invalidate_cache()
    filter_json = json.dumps({"status": "open"})

    # Customer A runs first → seeds cache
    rows_a = execute_search(filter_json, db, scope=customer_a, use_cache=True)
    a_ids = {r["id"] for r in rows_a}
    assert ticket_a.id in a_ids, "sanity: A must see their own ticket"
    assert ticket_b.id not in a_ids, "sanity: A must NOT see B's ticket"

    # Customer B runs with identical filter → must NOT get customer A's data
    rows_b = execute_search(filter_json, db, scope=customer_b, use_cache=True)
    b_ids = {r["id"] for r in rows_b}

    assert ticket_b.id in b_ids, "B must see their own ticket"
    assert ticket_a.id not in b_ids, "TC-B1C0F6E6: B must NOT see A's ticket"


# ---------------------------------------------------------------------------
# TC-E6C9E2B3 — run_scheduled_report must scope results to the owner
# ---------------------------------------------------------------------------


def test_scheduled_report_scoped_to_owner(db, two_customers):
    """The background worker must not include tickets belonging to other
    customers in the ReportRun result_ticket_ids_json or result_count."""
    customer_a, customer_b, ticket_a, ticket_b = two_customers

    saved = SavedSearch(
        owner_id=customer_a.id,
        name="A's search",
        filter_json="{}",
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)

    sched = ScheduledReport(
        saved_search_id=saved.id,
        frequency=ReportFrequency.daily,
        email="attacker@evil.example.com",
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)

    ticket_ids = set(json.loads(run.result_ticket_ids_json))
    assert run.success is True
    assert ticket_a.id in ticket_ids, "A's own ticket must appear in the run"
    assert ticket_b.id not in ticket_ids, (
        "TC-E6C9E2B3: B's ticket must NOT appear in a report owned by A"
    )
    assert run.result_count == 1, (
        f"TC-E6C9E2B3: result_count should be 1 (A's ticket only), got {run.result_count}"
    )
