"""Regression tests for three security findings from the niro pentest.

TC-7AB427A5 (CRITICAL): Cache scope leak — a customer's search results
    must never be returned from cache to a different customer.

TC-9F85CD0E (CRITICAL): Scheduled reports cross-tenant leak — the background
    job must scope results to the owning customer, not all tenants.

TC-13428639 (MEDIUM): Unverified email recipient — a scheduled report must
    only be sent to the authenticated user's own email address.

Each test is written to FAIL on the unfixed code and PASS after the fix.
"""
import json

import pytest

import app.search as search_module
from app.jobs import run_scheduled_report
from app.models import SavedSearch, ScheduledReport
from app.search import execute_search, invalidate_cache, serialize_filter


# ---------------------------------------------------------------------------
# TC-7AB427A5 — Cache does not include caller scope in its key
# ---------------------------------------------------------------------------


class TestCacheScopeLeak:
    """The search result cache must be keyed on (filter, scope) so that
    customer A's results are never served from cache to customer B."""

    def test_customer_a_results_not_served_from_cache_to_customer_b(
        self, db_session, users, tickets
    ):
        """
        1. Customer A runs a filter — result is cached.
        2. Customer B runs the SAME filter — must NOT see Customer A's ticket.

        On unfixed code: the cache key ignores scope, so B gets A's cached
        result set (containing A's ticket).
        """
        customer_a = users["customer_a"]
        customer_b = users["customer_b"]

        filter_json = serialize_filter({})  # empty filter — matches everything for scope

        # Prime the cache as customer A
        results_a = execute_search(filter_json, db_session, scope=customer_a)
        ticket_ids_a = {r["id"] for r in results_a}
        assert tickets["a"].id in ticket_ids_a, "sanity: A must see their own ticket"

        # Now run as customer B — the cache should NOT return A's ticket
        results_b = execute_search(filter_json, db_session, scope=customer_b)
        ticket_ids_b = {r["id"] for r in results_b}

        assert tickets["b"].id in ticket_ids_b, "B must see their own ticket"
        assert tickets["a"].id not in ticket_ids_b, (
            "SECURITY: customer B must not receive customer A's ticket from cache"
        )

    def test_agent_result_not_served_from_cache_to_customer(
        self, db_session, users, tickets
    ):
        """An agent runs a search (sees all tickets); a customer running the
        same filter afterward must still be scoped to their own tickets."""
        agent = users["agent"]
        customer_b = users["customer_b"]

        filter_json = serialize_filter({})

        # Agent primes cache — sees both tickets
        results_agent = execute_search(filter_json, db_session, scope=agent)
        assert len(results_agent) == 2, "agent should see both tickets"

        # Customer B hits same filter — must only see their own ticket
        results_b = execute_search(filter_json, db_session, scope=customer_b)
        ticket_ids_b = {r["id"] for r in results_b}

        assert tickets["a"].id not in ticket_ids_b, (
            "SECURITY: customer must not see other customer's ticket via agent-primed cache"
        )
        assert tickets["b"].id in ticket_ids_b


# ---------------------------------------------------------------------------
# TC-9F85CD0E — Scheduled report worker fetches cross-tenant tickets
# ---------------------------------------------------------------------------


class TestScheduledReportScopeEnforcement:
    """run_scheduled_report must restrict query results to the owning
    customer's tickets, not return rows across all tenants."""

    def test_scheduled_report_only_includes_owner_tickets(
        self, db_session, users, tickets
    ):
        """
        Customer A owns a saved search + schedule.
        The report run result_ticket_ids must NOT contain Customer B's ticket.

        On unfixed code: execute_search is called without scope=owner, so the
        query has no customer_id predicate and both tickets appear in the run.
        """
        customer_a = users["customer_a"]

        saved = SavedSearch(
            owner_id=customer_a.id,
            name="A's search",
            filter_json=serialize_filter({}),
        )
        db_session.add(saved)
        db_session.commit()
        db_session.refresh(saved)

        sched = ScheduledReport(
            saved_search_id=saved.id,
            frequency="daily",
            email=customer_a.email,
        )
        db_session.add(sched)
        db_session.commit()
        db_session.refresh(sched)

        run = run_scheduled_report(sched.id, db_session)

        assert run.success, f"run should succeed, got error: {run.error}"

        result_ids = set(json.loads(run.result_ticket_ids_json))

        assert tickets["a"].id in result_ids, (
            "customer A's ticket must appear in their report"
        )
        assert tickets["b"].id not in result_ids, (
            "SECURITY: customer B's ticket must not appear in customer A's report"
        )


# ---------------------------------------------------------------------------
# TC-13428639 — Arbitrary email recipient accepted on schedule creation
# ---------------------------------------------------------------------------


class TestScheduleEmailRestriction:
    """POST /searches/{id}/schedule must reject email addresses that do not
    belong to the authenticated user."""

    def test_schedule_to_own_email_is_accepted(self, client, tokens, users, tickets):
        """Creating a schedule addressed to the caller's own email must succeed."""
        auth = tokens["customer_a"]
        customer_a = users["customer_a"]

        r = client.post(
            "/searches",
            json={"name": "my search", "filter": {}},
            headers={"Authorization": auth},
        )
        assert r.status_code == 201
        search_id = r.json()["id"]

        r = client.post(
            f"/searches/{search_id}/schedule",
            json={"frequency": "daily", "email": customer_a.email},
            headers={"Authorization": auth},
        )
        assert r.status_code == 201

    def test_schedule_to_foreign_email_is_rejected(self, client, tokens, users, tickets):
        """Creating a schedule addressed to someone else's email must be
        rejected with 403 (or 422).

        On unfixed code: the API stores and uses any email without checking
        that it belongs to the caller.
        """
        auth = tokens["customer_a"]
        customer_b = users["customer_b"]

        r = client.post(
            "/searches",
            json={"name": "my search", "filter": {}},
            headers={"Authorization": auth},
        )
        assert r.status_code == 201
        search_id = r.json()["id"]

        r = client.post(
            f"/searches/{search_id}/schedule",
            json={"frequency": "daily", "email": customer_b.email},
            headers={"Authorization": auth},
        )
        assert r.status_code in (403, 422), (
            f"SECURITY: scheduling to another user's email must be rejected, "
            f"got {r.status_code}: {r.text}"
        )
