import json
import os
import subprocess
import sys

os.environ.setdefault(
    "HELPDESK_SECRET", "test-secret-for-helpdesk-suite-00000000"
)

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.jobs import run_scheduled_report
from app.models import (
    Base,
    ReportFrequency,
    Role,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
)
from app.routes.searches import (
    delete_search,
    disable_schedule,
    get_search,
    list_searches,
    list_schedules,
    list_runs,
    schedule_report,
    update_search,
)
from app.schemas import SavedSearchUpdate, ScheduleReportCreate
from app.search import execute_search, invalidate_cache, serialize_filter


def test_auth_requires_explicit_jwt_secret():
    env = os.environ.copy()
    env.pop("HELPDESK_SECRET", None)

    result = subprocess.run(
        [sys.executable, "-c", "import app.auth"],
        cwd=os.getcwd(),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "HELPDESK_SECRET" in result.stderr


@pytest.fixture
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        invalidate_cache()


def add_customer(db, email):
    user = User(
        email=email,
        password_hash="unused",
        full_name=email,
        role=Role.customer,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def add_agent(db, email="agent@example.com"):
    user = User(
        email=email,
        password_hash="unused",
        full_name=email,
        role=Role.agent,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def add_ticket(db, customer, subject):
    ticket = Ticket(
        customer_id=customer.id,
        subject=subject,
        description=f"private description for {subject}",
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


def add_saved_search(db, owner, name="owner search"):
    saved = SavedSearch(
        owner_id=owner.id,
        name=name,
        filter_json=serialize_filter({}),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


def test_saved_search_cache_is_partitioned_by_customer_scope(db):
    customer_a = add_customer(db, "a@example.com")
    customer_b = add_customer(db, "b@example.com")
    ticket_a = add_ticket(db, customer_a, "cache marker A")
    ticket_b = add_ticket(db, customer_b, "cache marker B")

    filter_json = serialize_filter({})

    a_results = execute_search(filter_json, db, scope=customer_a)
    b_results = execute_search(filter_json, db, scope=customer_b)

    assert {row["id"] for row in a_results} == {ticket_a.id}
    assert {row["id"] for row in b_results} == {ticket_b.id}


def test_scheduled_report_uses_saved_search_owner_scope(db):
    customer_a = add_customer(db, "a@example.com")
    customer_b = add_customer(db, "b@example.com")
    marker = "schedleak-regression"
    ticket_a = add_ticket(db, customer_a, f"{marker} A")
    ticket_b = add_ticket(db, customer_b, f"{marker} B")
    saved = SavedSearch(
        owner_id=customer_a.id,
        name="A schedule",
        filter_json=serialize_filter({"subject_contains": marker}),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    schedule = ScheduledReport(
        saved_search_id=saved.id,
        frequency=ReportFrequency.daily,
        email="a@example.com",
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    run = run_scheduled_report(schedule.id, db)
    result_ids = set(json.loads(run.result_ticket_ids_json))

    assert run.result_count == 1
    assert result_ids == {ticket_a.id}
    assert ticket_b.id not in result_ids


def test_agent_cannot_update_customer_saved_search(db):
    customer = add_customer(db, "a@example.com")
    agent = add_agent(db)
    saved = add_saved_search(db, customer)

    with pytest.raises(HTTPException) as exc:
        update_search(saved.id, SavedSearchUpdate(name="agent overwrite"), agent, db)

    assert exc.value.status_code == 403


def test_agent_cannot_delete_customer_saved_search(db):
    customer = add_customer(db, "a@example.com")
    agent = add_agent(db)
    saved = add_saved_search(db, customer)

    with pytest.raises(HTTPException) as exc:
        delete_search(saved.id, agent, db)

    assert exc.value.status_code == 403
    assert db.get(SavedSearch, saved.id) is not None


def test_agent_cannot_schedule_customer_saved_search(db):
    customer = add_customer(db, "a@example.com")
    agent = add_agent(db)
    saved = add_saved_search(db, customer)

    with pytest.raises(HTTPException) as exc:
        schedule_report(
            saved.id,
            ScheduleReportCreate(email="agent-exfil@example.com"),
            agent,
            db,
        )

    assert exc.value.status_code == 403


def test_disabling_schedule_preserves_report_run_history(db):
    customer = add_customer(db, "a@example.com")
    add_ticket(db, customer, "audit retention marker")
    saved = SavedSearch(
        owner_id=customer.id,
        name="audit search",
        filter_json=serialize_filter({"subject_contains": "audit retention marker"}),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    response = schedule_report(
        saved.id,
        ScheduleReportCreate(email="owner@example.com"),
        customer,
        db,
    )

    schedule_id = response.schedule.id

    assert list_runs(schedule_id, customer, db)
    delete_search(saved.id, customer, db)
    assert list_runs(schedule_id, customer, db)

    disable_schedule(schedule_id, customer, db)
    schedule = db.get(ScheduledReport, schedule_id)

    assert schedule is not None
    assert schedule.enabled is False
    assert list_runs(schedule_id, customer, db)


def test_agent_cannot_read_customer_schedule_recipients(db):
    customer = add_customer(db, "a@example.com")
    agent = add_agent(db)
    saved = add_saved_search(db, customer)
    schedule_report(
        saved.id,
        ScheduleReportCreate(email="private-recipient@example.com"),
        customer,
        db,
    )

    with pytest.raises(HTTPException) as exc:
        list_schedules(saved.id, agent, db)

    assert exc.value.status_code == 403


def test_agent_cannot_schedule_agent_owned_all_ticket_search(db):
    agent = add_agent(db)
    saved = add_saved_search(db, agent, "agent all tickets")

    with pytest.raises(HTTPException) as exc:
        schedule_report(
            saved.id,
            ScheduleReportCreate(email="outside-recipient@example.net"),
            agent,
            db,
        )

    assert exc.value.status_code == 403


def test_agent_cannot_read_customer_saved_search_metadata(db):
    customer = add_customer(db, "a@example.com")
    agent = add_agent(db)
    saved = SavedSearch(
        owner_id=customer.id,
        name="private legal escalation",
        filter_json=serialize_filter(
            {"subject_contains": "confidential acquisition complaint"}
        ),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)

    with pytest.raises(HTTPException) as exc:
        get_search(saved.id, agent, db)

    assert exc.value.status_code == 403
    assert saved.id not in {row.id for row in list_searches(agent, db)}


def test_deleting_saved_search_preserves_schedule_run_history(db):
    customer = add_customer(db, "a@example.com")
    add_ticket(db, customer, "delete search audit marker")
    saved = SavedSearch(
        owner_id=customer.id,
        name="audit search",
        filter_json=serialize_filter(
            {"subject_contains": "delete search audit marker"}
        ),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    response = schedule_report(
        saved.id,
        ScheduleReportCreate(email="owner@example.com"),
        customer,
        db,
    )
    schedule_id = response.schedule.id

    assert list_runs(schedule_id, customer, db)


def test_deleting_saved_search_preserves_run_criteria_snapshot(db):
    customer = add_customer(db, "a@example.com")
    marker = "criteria snapshot marker"
    add_ticket(db, customer, marker)
    saved = SavedSearch(
        owner_id=customer.id,
        name="criteria snapshot search",
        filter_json=serialize_filter({"subject_contains": marker}),
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    response = schedule_report(
        saved.id,
        ScheduleReportCreate(email="owner@example.com"),
        customer,
        db,
    )
    schedule_id = response.schedule.id

    delete_search(saved.id, customer, db)
    runs = list_runs(schedule_id, customer, db)

    assert runs[0].search_name_snapshot == "criteria snapshot search"
    assert runs[0].filter_json_snapshot == serialize_filter(
        {"subject_contains": marker}
    )
