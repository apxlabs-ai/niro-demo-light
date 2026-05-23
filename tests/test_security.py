"""
Security regression tests for the saved-search / scheduled-report surface.

Each test maps to a niro finding from pentest niro_pt_366a8897. Tests are
written to assert the SECURE behaviour — they must FAIL on the unpatched
code and PASS after the fix is applied.

Findings covered:
  TC-E3E45718  CRITICAL  Cache key does not include scope
  TC-27689201  HIGH      schedule response leaks cross-tenant ticket IDs
  TC-FB7EB9E3  MEDIUM    run-history leaks cross-tenant ticket IDs
  TC-29253600  HIGH      arbitrary attacker-controlled schedule email
  TC-5A118AF0  HIGH      customer_id filter targets victim tenant

TC-DF842DC1 (BLOCKED) is the same root cause as TC-27689201 / TC-5A118AF0
(unscoped execute_search in the worker) — both of those tests cover it.
"""
from tests.conftest import (
    _auth,
    _create_search,
    _create_ticket,
    _signup_and_login,
)


# ---------------------------------------------------------------------------
# TC-E3E45718 — cache key must include scope
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_tenants(client):
    """Customer B must not receive Customer A's tickets via a cache hit.

    Root cause: _cache_key() in search.py uses only the filter JSON, so
    the first call (Customer A, scope=A) stores A's rows under key K.
    The second call (Customer B, scope=B, same filter) hits key K and
    returns A's rows without touching the DB.

    Fix: include the user id + role in the cache key, OR never cache
    user-scoped results.
    """
    token_a, _uid_a = _signup_and_login(client, "alice@example.com")
    token_b, _uid_b = _signup_and_login(client, "bob@example.com")

    ticket_a_id = _create_ticket(client, token_a, "Secret-A")

    # A creates and runs a saved search — primes the cache for filter "{}".
    search_a = _create_search(client, token_a, {})
    r = client.get(f"/searches/{search_a}/run", headers=_auth(token_a))
    assert r.status_code == 200
    a_ticket_ids = {t["id"] for t in r.json()["tickets"]}
    assert ticket_a_id in a_ticket_ids

    # B creates a saved search with the SAME empty filter — cache hit risk.
    search_b = _create_search(client, token_b, {})
    r = client.get(f"/searches/{search_b}/run", headers=_auth(token_b))
    assert r.status_code == 200
    b_ticket_ids = {t["id"] for t in r.json()["tickets"]}

    # B must not see A's ticket.
    assert ticket_a_id not in b_ticket_ids, (
        f"Cache poisoning: Customer B received Customer A's ticket "
        f"(id={ticket_a_id}) via a shared cache entry."
    )


# ---------------------------------------------------------------------------
# TC-27689201 — schedule response must not expose cross-tenant ticket IDs
# ---------------------------------------------------------------------------


def test_schedule_initial_run_only_contains_owner_ticket_ids(client):
    """POST /searches/{id}/schedule response must scope the initial run.

    Root cause: schedule_report calls run_scheduled_report(sched.id, db),
    which calls execute_search(..., db, use_cache=False) with no scope
    argument. The unscoped query returns all tenants' tickets; their IDs
    are stored in ReportRun.result_ticket_ids_json and returned inline.

    Fix: pass scope=owner to execute_search inside run_scheduled_report.
    """
    import json

    token_a, _uid_a = _signup_and_login(client, "alice2@example.com")
    token_b, uid_b = _signup_and_login(client, "bob2@example.com")

    ticket_a_id = _create_ticket(client, token_a, "A-private-ticket")
    _create_ticket(client, token_b, "B-own-ticket")

    # B schedules a search with an empty filter.
    search_b = _create_search(client, token_b, {})
    r = client.post(
        f"/searches/{search_b}/schedule",
        json={"frequency": "daily", "email": "bob2@example.com"},
        headers=_auth(token_b),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    run_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])

    assert ticket_a_id not in run_ids, (
        f"Cross-tenant leak: Customer A's ticket (id={ticket_a_id}) appeared "
        f"in Customer B's schedule response (result_ticket_ids_json={run_ids})."
    )


# ---------------------------------------------------------------------------
# TC-FB7EB9E3 — run-history must not expose cross-tenant ticket IDs
# ---------------------------------------------------------------------------


def test_run_history_does_not_expose_cross_tenant_ids(client):
    """GET /searches/schedules/{id}/runs must scope result_ticket_ids_json.

    Same root cause as TC-27689201: run_scheduled_report stores the
    unscoped result in the ReportRun row. The /runs endpoint then returns
    those rows (including the cross-tenant IDs) to the customer.

    Fix: scoping execute_search in run_scheduled_report fixes both this
    finding and TC-27689201 at the same time — they share the root cause.
    """
    import json

    token_a, _uid_a = _signup_and_login(client, "alice3@example.com")
    token_b, uid_b = _signup_and_login(client, "bob3@example.com")

    ticket_a_id = _create_ticket(client, token_a, "A-secret-3")
    _create_ticket(client, token_b, "B-own-3")

    search_b = _create_search(client, token_b, {})
    r = client.post(
        f"/searches/{search_b}/schedule",
        json={"frequency": "daily", "email": "bob3@example.com"},
        headers=_auth(token_b),
    )
    assert r.status_code == 201, r.text
    schedule_id = r.json()["schedule"]["id"]

    # Read the run history back via the API.
    r = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(token_b),
    )
    assert r.status_code == 200, r.text
    runs = r.json()
    assert runs, "Expected at least one run in history"
    ids_in_history = json.loads(runs[0]["result_ticket_ids_json"])

    assert ticket_a_id not in ids_in_history, (
        f"Cross-tenant leak in run history: Customer A's ticket "
        f"(id={ticket_a_id}) is visible in Customer B's run history "
        f"(result_ticket_ids_json={ids_in_history})."
    )


# ---------------------------------------------------------------------------
# TC-29253600 — schedule email must be the authenticated user's own address
# ---------------------------------------------------------------------------


def test_schedule_email_must_match_authenticated_user(client):
    """POST /searches/{id}/schedule must reject arbitrary recipient emails.

    Root cause: ScheduleReportCreate.email is taken verbatim from the
    request body with no ownership check. Any valid EmailStr is accepted,
    enabling a user to direct their (or other tenants') ticket data to
    an attacker-controlled mailbox.

    Fix: either enforce req.email == user.email in the route handler,
    or drop the email field and always derive it from user.email.
    """
    token_a, _uid_a = _signup_and_login(client, "alice4@example.com")
    search_a = _create_search(client, token_a, {})

    r = client.post(
        f"/searches/{search_a}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(token_a),
    )
    assert r.status_code == 422, (
        f"Expected 422 when scheduling to an external email address, "
        f"got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# TC-5A118AF0 — customer_id filter must not expose another tenant's tickets
# ---------------------------------------------------------------------------


def test_customer_id_filter_cannot_target_other_tenant(client):
    """A customer must not use a customer_id filter to exfiltrate a victim's tickets.

    Root cause: SearchFilter accepts customer_id with no ownership check.
    When a saved search with customer_id=<victim> is scheduled, the
    unscoped worker query applies ONLY the victim's customer_id predicate,
    returning exclusively the victim's rows.

    Fix: either reject customer_id values that don't match the requesting
    customer's own id in create_search / update_search, or scope
    execute_search in run_scheduled_report (the fix for TC-27689201) —
    the scoped query will AND customer_id=owner with customer_id=victim,
    yielding zero rows.
    """
    import json

    token_a, uid_a = _signup_and_login(client, "alice5@example.com")
    token_b, uid_b = _signup_and_login(client, "bob5@example.com")

    ticket_a_id = _create_ticket(client, token_a, "A-victim-ticket")

    # B creates a search that explicitly targets A's customer_id.
    r = client.post(
        "/searches",
        json={"name": "victim-search", "filter": {"customer_id": uid_a}},
        headers=_auth(token_b),
    )
    # Either the creation is rejected (403/422) or it succeeds but the
    # scheduled run must not return A's tickets.
    if r.status_code in (403, 422):
        return  # creation rejected — fix applied at the schema layer

    assert r.status_code == 201, r.text
    search_id = r.json()["id"]

    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "bob5@example.com"},
        headers=_auth(token_b),
    )
    assert r.status_code == 201, r.text
    run_ids = json.loads(r.json()["initial_run"]["result_ticket_ids_json"])

    assert ticket_a_id not in run_ids, (
        f"Targeted cross-tenant exfil: Customer B's schedule on a filter "
        f"{{customer_id={uid_a}}} returned Customer A's ticket "
        f"(id={ticket_a_id}) in result_ticket_ids_json={run_ids}."
    )
