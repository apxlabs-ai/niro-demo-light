"""Regression tests for the saved-search + scheduled-report feature.

Each test here pins one cross-tenant invariant that niro's PR-mode
pentest (pentest niro_pt_7a9e54ff, PR #109) cracked. Every test is
written to FAIL on the unfixed code in the exact way the finding
describes, and to PASS once the corresponding fix lands:

  TC-960EBF27 (CRITICAL): app/search.py result cache is keyed on the
      filter JSON only — not the caller's scope — so a customer running
      a saved search inherits another customer's freshly-cached rows.
      -> test_run_search_cache_does_not_leak_across_customers

  TC-F010AE50 (CRITICAL): app/jobs.py run_scheduled_report calls
      execute_search() with no scope, so a scheduled report (and the
      email it sends) contains every tenant's tickets, not just the
      owner's.
      -> test_scheduled_report_is_scoped_to_owner

  TC-AFFC9252 (MEDIUM): POST /searches/{id}/schedule accepts an
      arbitrary `email`, letting a customer wire recurring delivery of
      ticket data to an address that isn't their own.
      -> test_schedule_rejects_foreign_recipient_email

The mTLS BOLA finding (TC-B1FB1397) already has a regression test in
tests/test_mtls.py::test_mtls_ticket_by_id_cross_user_returns_403.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import current_user, hash_password
from app.db import Base, get_db
from app.jobs import run_scheduled_report
from app.main import app
from app.models import (
    Priority,
    ReportFrequency,
    Role,
    SavedSearch,
    ScheduledReport,
    Status,
    Ticket,
    User,
)
from app.search import invalidate_cache, serialize_filter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_cache():
    """The result cache is a module global — flush it around every test
    so cache state can't bleed between cases."""
    invalidate_cache()
    yield
    invalidate_cache()


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
def demo(db):
    """Two customers; Alex owns 2 open tickets, Blair owns 1 open ticket."""
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

    tickets = [
        Ticket(
            customer_id=alex.id,
            subject="alex-secret-1",
            description="alex private 1",
            status=Status.open,
            priority=Priority.low,
        ),
        Ticket(
            customer_id=alex.id,
            subject="alex-secret-2",
            description="alex private 2",
            status=Status.open,
            priority=Priority.low,
        ),
        Ticket(
            customer_id=blair.id,
            subject="blair-secret-1",
            description="blair private 1",
            status=Status.open,
            priority=Priority.low,
        ),
    ]
    db.add_all(tickets)
    db.commit()
    for t in tickets:
        db.refresh(t)

    return alex, blair


def _saved_search(db, owner, filter_dict, name="s"):
    saved = SavedSearch(
        owner_id=owner.id,
        name=name,
        filter_json=serialize_filter(filter_dict),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


@pytest.fixture()
def client_as(db):
    """Factory: returns a TestClient whose current_user resolves to the
    given user. Lets a single test switch identities (Alex primes, Blair
    reads) against the same in-memory DB."""
    app.dependency_overrides[get_db] = lambda: db

    def _make(user):
        app.dependency_overrides[current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=True)

    yield _make
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# TC-960EBF27 — result cache leaks across customers
# ---------------------------------------------------------------------------


def test_run_search_cache_does_not_leak_across_customers(db, demo, client_as):
    """Alex runs a saved search (priming the cache for filter
    {status: open}); Blair then runs her own search with the identical
    filter. Blair must see only her own ticket — never Alex's cached
    rows.

    On the unfixed code the cache key ignores scope, so Blair's request
    hits Alex's cache entry and this assertion fails with Alex's rows.
    """
    alex, blair = demo
    alex_search = _saved_search(db, alex, {"status": "open"}, name="alex_open")
    blair_search = _saved_search(db, blair, {"status": "open"}, name="blair_open")

    # Alex primes the cache.
    r_alex = client_as(alex).get(f"/searches/{alex_search.id}/run")
    assert r_alex.status_code == 200
    assert r_alex.json()["count"] == 2  # Alex owns 2 open tickets

    # Blair runs the same filter — must get only her own ticket.
    r_blair = client_as(blair).get(f"/searches/{blair_search.id}/run")
    assert r_blair.status_code == 200
    returned = r_blair.json()["tickets"]
    owners = {t["customer_id"] for t in returned}
    assert owners == {blair.id}, (
        f"cross-tenant cache leak: Blair received tickets owned by {owners}, "
        f"expected only {{{blair.id}}}"
    )
    assert r_blair.json()["count"] == 1


# ---------------------------------------------------------------------------
# TC-F010AE50 — scheduled report not scoped to its owner
# ---------------------------------------------------------------------------


def test_scheduled_report_is_scoped_to_owner(db, demo):
    """A scheduled report owned by Blair must only ever materialize
    Blair's tickets. The worker entrypoint run_scheduled_report() is
    the trusted backend path that both records the audit row and feeds
    the outbound email body, so its result set must be owner-scoped.

    On the unfixed code run_scheduled_report calls execute_search()
    with no scope, so the run materializes all three tickets across both
    tenants and this assertion fails.
    """
    alex, blair = demo
    saved = _saved_search(db, blair, {"status": "open"}, name="blair_sched")
    sched = ScheduledReport(
        saved_search_id=saved.id,
        frequency=ReportFrequency.daily,
        email=blair.email,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)

    assert run.success is True
    assert run.result_count == 1, (
        f"scheduled report leaked cross-tenant rows: result_count="
        f"{run.result_count}, expected 1 (Blair's open tickets only)"
    )
    import json

    leaked_ids = set(json.loads(run.result_ticket_ids_json))
    blair_ids = {
        t.id
        for t in db.query(Ticket).filter(Ticket.customer_id == blair.id).all()
    }
    assert leaked_ids <= blair_ids, (
        f"scheduled report included ticket ids outside the owner: "
        f"{leaked_ids - blair_ids}"
    )


# ---------------------------------------------------------------------------
# TC-AFFC9252 — schedule accepts an attacker-chosen recipient
# ---------------------------------------------------------------------------


def test_schedule_rejects_foreign_recipient_email(db, demo, client_as, monkeypatch, tmp_path):
    """A customer must not be able to schedule ticket-content emails to
    an address that isn't their own. Blair scheduling delivery to
    attacker@evil.com must be rejected (403/422).

    On the unfixed code the email field is unconstrained, so the POST
    returns 201 and a persistent exfil schedule is created — this
    assertion fails.
    """
    # Keep any mock-email side effect off the shared /tmp log.
    monkeypatch.setenv("HELPDESK_MAIL_LOG", str(tmp_path / "mail.log"))

    _alex, blair = demo
    saved = _saved_search(db, blair, {"status": "open"}, name="blair_exfil")

    resp = client_as(blair).post(
        f"/searches/{saved.id}/schedule",
        json={"frequency": "hourly", "email": "attacker@evil.com"},
    )
    assert resp.status_code in (403, 422), (
        f"foreign recipient accepted: POST /schedule returned "
        f"{resp.status_code} for email attacker@evil.com (Blair is "
        f"{blair.email})"
    )

    # And nothing should have been persisted.
    remaining = db.query(ScheduledReport).count()
    assert remaining == 0, "a rejected schedule must not be persisted"
