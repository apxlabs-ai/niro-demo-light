"""Regression tests for the 5 niro security findings on PR #36.

Protocol: run on UNFIXED code first — every test must FAIL. Then apply
the fixes and re-run — every test must PASS. A test written after the
fix only proves consistency; it can never prove the bug existed.
"""
import json

import pytest

from app.jobs import run_scheduled_report
from app.models import ReportFrequency, ReportRun, ScheduledReport
from app.search import execute_search, invalidate_cache, serialize_filter


# ---------------------------------------------------------------------------
# TC-57CB5C2A (CRITICAL) — worker stores cross-tenant ticket IDs
# Root cause: execute_search called without scope= in jobs.py
# ---------------------------------------------------------------------------

def test_worker_scopes_results_to_owner(db_session, customer_a, customer_b, ticket_a, ticket_b):
    """run_scheduled_report must only store ticket IDs the search owner can
    see, not all tickets across every tenant."""
    from app.models import SavedSearch
    saved = SavedSearch(owner_id=customer_a.id, name="all",
                        filter_json=serialize_filter({}), pinned=False)
    db_session.add(saved)
    db_session.commit()
    db_session.refresh(saved)

    sched = ScheduledReport(saved_search_id=saved.id,
                            frequency=ReportFrequency.daily,
                            email=customer_a.email)
    db_session.add(sched)
    db_session.commit()

    run = run_scheduled_report(sched.id, db_session)

    stored_ids = json.loads(run.result_ticket_ids_json)
    assert ticket_a.id in stored_ids, "owner's ticket must be in the stored result"
    assert ticket_b.id not in stored_ids, "other customer's ticket must NOT be stored"


# ---------------------------------------------------------------------------
# TC-7CD284AE (HIGH) — GET /searches/schedules/{id}/runs leaks foreign IDs
# list_runs returns result_ticket_ids_json verbatim with no ownership filter
# ---------------------------------------------------------------------------

def test_list_runs_filters_ids_for_customer(
    client, db_session, customer_a, customer_b,
    ticket_a, ticket_b, token_a, saved_search_a,
):
    """The run-history endpoint must redact ticket IDs belonging to other
    customers before returning records to a customer caller."""
    sched = ScheduledReport(saved_search_id=saved_search_a.id,
                            frequency=ReportFrequency.daily,
                            email=customer_a.email)
    db_session.add(sched)
    db_session.commit()
    db_session.refresh(sched)

    # Inject a run record that already contains cross-tenant ticket IDs
    # (simulating the poisoned rows the unfixed worker would produce).
    poisoned = [ticket_a.id, ticket_b.id]
    run = ReportRun(scheduled_report_id=sched.id, success=True,
                    result_count=len(poisoned),
                    result_ticket_ids_json=json.dumps(poisoned))
    db_session.add(run)
    db_session.commit()

    resp = client.get(f"/searches/schedules/{sched.id}/runs",
                      headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1
    returned_ids = json.loads(runs[0]["result_ticket_ids_json"])
    assert ticket_b.id not in returned_ids, "foreign customer's ticket ID must be redacted"
    assert ticket_a.id in returned_ids, "caller's own ticket ID must be preserved"


# ---------------------------------------------------------------------------
# TC-ADA06A47 (CRITICAL) — search result cache ignores caller identity
# Cache keyed only on filter JSON; two different customers share the same entry
# ---------------------------------------------------------------------------

def test_search_cache_is_scoped_per_user(
    db_session, customer_a, customer_b, ticket_a, ticket_b
):
    """execute_search with use_cache=True must not serve Customer A's cached
    results to Customer B when they run the same logical filter."""
    invalidate_cache()  # clear any state from prior tests

    results_a = execute_search(serialize_filter({}), db_session,
                               scope=customer_a, use_cache=True)
    results_b = execute_search(serialize_filter({}), db_session,
                               scope=customer_b, use_cache=True)

    ids_a = {r["id"] for r in results_a}
    ids_b = {r["id"] for r in results_b}

    assert ticket_a.id in ids_a, "Customer A must see their own ticket"
    assert ticket_b.id in ids_b, "Customer B must see their own ticket"
    assert ticket_b.id not in ids_a, "Customer A must NOT see Customer B's ticket"
    assert ticket_a.id not in ids_b, "Customer B must NOT see Customer A's ticket"


# ---------------------------------------------------------------------------
# TC-2D1F0332 (HIGH) — schedule email not validated against the caller
# Any caller can route report emails to an arbitrary inbox
# ---------------------------------------------------------------------------

def test_schedule_email_must_match_caller(
    client, ticket_a, token_a, saved_search_a
):
    """POST /searches/{id}/schedule must reject an email address that does
    not belong to the authenticated caller."""
    resp = client.post(
        f"/searches/{saved_search_a.id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp.status_code == 422, (
        f"expected 422 for mismatched email, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TC-E2FFE661 (MEDIUM) — agents can mutate any customer's saved search
# _load_search_for_owner skips the ownership check for agents on write paths
# ---------------------------------------------------------------------------

def test_agent_cannot_patch_customer_search(
    client, ticket_a, token_agent, saved_search_a
):
    """PATCH /searches/{id} must return 403 when the caller is an agent who
    does not own the saved search."""
    resp = client.patch(
        f"/searches/{saved_search_a.id}",
        json={"name": "hijacked by agent"},
        headers={"Authorization": f"Bearer {token_agent}"},
    )
    assert resp.status_code == 403, (
        f"expected 403 for agent PATCH on customer search, got {resp.status_code}: {resp.text}"
    )


def test_agent_cannot_delete_customer_search(
    client, ticket_a, token_agent, saved_search_a
):
    """DELETE /searches/{id} must return 403 when the caller is an agent who
    does not own the saved search."""
    resp = client.delete(
        f"/searches/{saved_search_a.id}",
        headers={"Authorization": f"Bearer {token_agent}"},
    )
    assert resp.status_code == 403, (
        f"expected 403 for agent DELETE on customer search, got {resp.status_code}: {resp.text}"
    )
