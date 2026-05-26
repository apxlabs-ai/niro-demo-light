"""
Regression tests for the four security findings from pentest niro_pt_e7aa9059.

Each test is named after its finding ID and MUST FAIL on the unfixed code.
Run them before applying fixes to confirm they catch the bug, then again
after to confirm the fix is correct.
"""
import json

import pytest

from app.jobs import run_scheduled_report
from app.models import SavedSearch, ScheduledReport
from app.search import _cache, execute_search

from .conftest import auth, login


# ---------------------------------------------------------------------------
# TC-B951DC0F — CRITICAL: cross-tenant cache poisoning in execute_search
#
# The cache key is sha256(filter_json) only.  Blair's scoped results are
# stored under that key; Alex's subsequent request gets a cache hit and
# receives Blair's rows instead of his own.
# ---------------------------------------------------------------------------


def test_TC_B951DC0F_cache_key_includes_scope(client, db, customer_alex, customer_blair):
    """Alex must never receive Blair's tickets from a cache hit."""
    alex_tok = login(client, customer_alex.email, "alex-pw")
    blair_tok = login(client, customer_blair.email, "blair-pw")

    # Each customer creates a private ticket.
    client.post(
        "/tickets",
        json={"subject": "Alex private", "description": "x", "status": "open", "priority": "high"},
        headers=auth(alex_tok),
    )
    client.post(
        "/tickets",
        json={"subject": "Blair private", "description": "x", "status": "open", "priority": "high"},
        headers=auth(blair_tok),
    )

    # Both customers create a saved search with the identical empty filter.
    r = client.post("/searches", json={"name": "all", "filter": {}}, headers=auth(blair_tok))
    assert r.status_code == 201
    blair_search_id = r.json()["id"]

    r = client.post("/searches", json={"name": "all", "filter": {}}, headers=auth(alex_tok))
    assert r.status_code == 201
    alex_search_id = r.json()["id"]

    # Blair runs first — populates the cache.
    r = client.get(f"/searches/{blair_search_id}/run", headers=auth(blair_tok))
    assert r.status_code == 200
    blair_subjects = {t["subject"] for t in r.json()["tickets"]}
    assert "Blair private" in blair_subjects
    assert "Alex private" not in blair_subjects

    # Alex runs the same filter — must NOT get Blair's rows from the cache.
    r = client.get(f"/searches/{alex_search_id}/run", headers=auth(alex_tok))
    assert r.status_code == 200
    alex_subjects = {t["subject"] for t in r.json()["tickets"]}
    assert "Alex private" in alex_subjects, "Alex should see his own ticket"
    assert "Blair private" not in alex_subjects, "Alex must not see Blair's ticket (cache poisoning)"


# ---------------------------------------------------------------------------
# TC-F86E7456 — CRITICAL: scheduled-report worker runs unscoped search,
#               exfiltrating all tenants' tickets into the emailed report.
#
# run_scheduled_report calls execute_search(...) without scope=owner,
# so result_ticket_ids_json on the ReportRun row contains every tenant's IDs.
# ---------------------------------------------------------------------------


def test_TC_F86E7456_worker_scopes_results_to_owner(db, customer_alex, customer_blair):
    """Worker must only include the search owner's tickets in the run."""
    from app.models import Ticket, Priority, Status

    # Give each customer a ticket.
    alex_ticket = Ticket(
        customer_id=customer_alex.id,
        subject="Alex worker ticket",
        description="x",
        status=Status.open,
        priority=Priority.high,
    )
    blair_ticket = Ticket(
        customer_id=customer_blair.id,
        subject="Blair worker ticket",
        description="x",
        status=Status.open,
        priority=Priority.high,
    )
    db.add_all([alex_ticket, blair_ticket])
    db.commit()

    # Alex creates a saved search with a broad filter.
    saved = SavedSearch(
        owner_id=customer_alex.id,
        name="all tickets",
        filter_json="{}",
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)

    sched = ScheduledReport(
        saved_search_id=saved.id,
        email=customer_alex.email,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)
    assert run.success, f"Run failed: {run.error}"

    reported_ids = set(json.loads(run.result_ticket_ids_json))
    assert alex_ticket.id in reported_ids, "Worker must include Alex's ticket"
    assert blair_ticket.id not in reported_ids, (
        "Worker must not include Blair's ticket in Alex's report (cross-tenant leak)"
    )


# ---------------------------------------------------------------------------
# TC-D8D9D239 — MEDIUM: schedule endpoint accepts arbitrary third-party email
#
# Any authenticated user can wire a recurring report to an address they
# don't own, turning the app into a spam relay / data-exfil channel.
# ---------------------------------------------------------------------------


def test_TC_D8D9D239_schedule_rejects_third_party_email(client, db, customer_alex, customer_blair):
    """Scheduling a report to an address that isn't the caller's own must be rejected."""
    alex_tok = login(client, customer_alex.email, "alex-pw")

    r = client.post("/searches", json={"name": "s", "filter": {}}, headers=auth(alex_tok))
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Alex tries to send reports to Blair's address (a third party).
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": customer_blair.email},
        headers=auth(alex_tok),
    )
    assert r.status_code == 403, (
        f"Expected 403 when scheduling to a third-party email, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# TC-5B305A1C — MEDIUM: agents can silently PATCH a customer's saved search
#
# _load_search_for_owner grants full write access to agents.  The comment
# says "agents may read any search (for analytics)" but the helper is also
# used by PATCH/DELETE/schedule, letting agents modify customer data.
# ---------------------------------------------------------------------------


def test_TC_5B305A1C_agent_cannot_modify_customer_search(client, db, agent_user, customer_alex):
    """An agent must not be able to PATCH (or DELETE) a customer's saved search."""
    alex_tok = login(client, customer_alex.email, "alex-pw")
    agent_tok = login(client, agent_user.email, "agent-pw")

    # Alex creates a saved search.
    r = client.post(
        "/searches",
        json={"name": "Alex search", "filter": {"status": "open"}},
        headers=auth(alex_tok),
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Agent tries to rename Alex's search.
    r = client.patch(
        f"/searches/{search_id}",
        json={"name": "AGENT-TAMPERED"},
        headers=auth(agent_tok),
    )
    assert r.status_code == 403, (
        f"Expected 403 when agent PATCHes a customer search, got {r.status_code}: {r.text}"
    )

    # Confirm the search is unchanged from Alex's perspective.
    r = client.get(f"/searches/{search_id}", headers=auth(alex_tok))
    assert r.json()["name"] == "Alex search", "Search name must not have been modified by the agent"
