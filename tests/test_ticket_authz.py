"""
Regression tests for TC-63C0557B / TC-91888D97 (BOLA on /reopen) and
TC-8E60A923 (customer writing agent-only fields via PATCH).

Each test is written to FAIL on the unfixed code and PASS after the fix.
"""
import pytest
from tests.conftest import _login


# ── TC-63C0557B / TC-91888D97 ─────────────────────────────────────────────────
# reopen_ticket has no ownership check; customer B can reopen customer A's ticket

def test_reopen_other_customers_ticket_is_forbidden(client):
    """Customer B must not reopen a closed ticket belonging to customer A."""
    tok_b = _login(client, "b@test.com")
    resp = client.post(
        f"/tickets/{client._ticket_id}/reopen",
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert resp.status_code == 403, (
        f"Expected 403 but got {resp.status_code}: {resp.text}"
    )


def test_reopen_own_ticket_is_allowed(client):
    """Customer A can reopen their own closed ticket."""
    tok_a = _login(client, "a@test.com")
    resp = client.post(
        f"/tickets/{client._ticket_id}/reopen",
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"


def test_agent_can_reopen_any_ticket(client):
    """Agents may reopen any ticket regardless of ownership."""
    tok_agent = _login(client, "agent@test.com")
    resp = client.post(
        f"/tickets/{client._ticket_id}/reopen",
        headers={"Authorization": f"Bearer {tok_agent}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"


# ── TC-8E60A923 ────────────────────────────────────────────────────────────────
# update_ticket lets customers set agent-only fields: status, priority, assignee_id

def test_customer_cannot_set_status(client):
    """Customer must not be able to change ticket status."""
    tok_a = _login(client, "a@test.com")
    resp = client.patch(
        f"/tickets/{client._ticket_id}",
        json={"status": "resolved"},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    # Either the field is silently ignored (ticket status unchanged) or 403/422.
    # The ticket starts as 'closed'; it must not become 'resolved'.
    if resp.status_code == 200:
        assert resp.json()["status"] != "resolved", (
            "Customer was able to change ticket status — agent-only field exposed"
        )


def test_customer_cannot_set_priority(client):
    """Customer must not be able to escalate ticket priority."""
    tok_a = _login(client, "a@test.com")
    resp = client.patch(
        f"/tickets/{client._ticket_id}",
        json={"priority": "urgent"},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    if resp.status_code == 200:
        assert resp.json()["priority"] != "urgent", (
            "Customer was able to change ticket priority — agent-only field exposed"
        )


def test_customer_cannot_set_assignee(client):
    """Customer must not be able to reassign a ticket to an arbitrary user."""
    tok_a = _login(client, "a@test.com")
    resp = client.patch(
        f"/tickets/{client._ticket_id}",
        json={"assignee_id": 1},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    if resp.status_code == 200:
        assert resp.json()["assignee_id"] != 1, (
            "Customer was able to set assignee_id — agent-only field exposed"
        )


def test_agent_can_set_workflow_fields(client):
    """Agents retain full PATCH access."""
    tok_agent = _login(client, "agent@test.com")
    resp = client.patch(
        f"/tickets/{client._ticket_id}",
        json={"status": "open", "priority": "high"},
        headers={"Authorization": f"Bearer {tok_agent}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "open"
    assert data["priority"] == "high"
