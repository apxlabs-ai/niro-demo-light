"""Saved-search query execution + result cache.

Hot path: a customer hits GET /searches/{id}/run repeatedly while
building out a workflow. For common filters (e.g., {status: open})
the underlying SQL is expensive enough at scale that we memoize per-
filter results in-process. The cache is opportunistic — entries
expire on TTL and are invalidated on ticket mutations.

This module is shared between two callers:

  - The synchronous API path (`run_search` endpoint), which executes a
    saved search on demand for an authenticated user.
  - The background job worker (`app/jobs.py`), which runs scheduled
    reports off-cycle and emails the results.

The executor accepts an optional `scope` argument so the caller can
restrict results to a specific user's tickets. Callers in user-facing
contexts MUST pass `scope=<the_user>`; admin/analytics callers omit
`scope` to get the global view across all tenants. See `execute_search`
for the contract.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Priority, Role, Status, Ticket, User

_logger = logging.getLogger(__name__)

# In-process result cache. Module-global because the FastAPI process
# is single-process in dev (uvicorn --reload) and the cache is sized
# to live data — not a long-running production cache. The TTL is short
# enough that staleness on mutations is bounded; the mutation hooks in
# routes/tickets.py also call invalidate_cache() to flush entries when
# tickets change.
_CACHE_TTL_SECONDS = 60
_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


# --- Filter validation ------------------------------------------------
#
# The SearchFilter Pydantic schema enforces shape at the API edge, but
# the executor also accepts raw dicts (used by the worker, which
# deserializes filter_json straight from the DB without re-routing
# through Pydantic). normalize_filter() is the single place that asserts
# the filter dict is well-formed before it touches the query builder.

_ALLOWED_KEYS = {
    "status",
    "priority",
    "assignee_id",
    "customer_id",
    "subject_contains",
    "created_after",
    "created_before",
}


class FilterError(ValueError):
    """Raised on a malformed filter. The routes layer catches this and
    returns a 422; the worker catches it and records a failed run."""


def normalize_filter(filter_dict: dict[str, Any]) -> dict[str, Any]:
    """Validate + canonicalize a filter dict.

    Drops keys whose value is None (the Pydantic schema serializes
    unset fields as None; we don't want them affecting the cache key).
    Validates enum values raise FilterError on bad input so a bad
    saved search doesn't crash a worker tick with a 500.
    """
    if not isinstance(filter_dict, dict):
        raise FilterError(f"filter must be a dict, got {type(filter_dict).__name__}")
    out: dict[str, Any] = {}
    for k, v in filter_dict.items():
        if v is None:
            continue
        if k not in _ALLOWED_KEYS:
            raise FilterError(f"unknown filter key: {k!r}")
        if k == "status":
            try:
                Status(v)
            except ValueError as e:
                raise FilterError(f"bad status: {v!r}") from e
        elif k == "priority":
            try:
                Priority(v)
            except ValueError as e:
                raise FilterError(f"bad priority: {v!r}") from e
        out[k] = v
    return out


def serialize_filter(filter_dict: dict[str, Any]) -> str:
    """Stable JSON serialization for storage + cache keying. Sorted
    keys so logically-identical filters produce byte-identical JSON."""
    return json.dumps(normalize_filter(filter_dict), sort_keys=True, default=str)


# --- Query builder ----------------------------------------------------


def _build_query(filter_dict: dict[str, Any], scope: User | None):
    """Build a SELECT for the given filter, optionally scoped to a user.

    Scope semantics:
      scope=None         → no user-level filter applied; returns rows
                           across all tenants. Used by analytics and by
                           admin dashboards that pre-authenticate the
                           caller upstream.
      scope=<customer>   → restrict to tickets where customer_id matches
                           the user's id.
      scope=<agent>      → no user-level filter applied (agents see all).
    """
    q = select(Ticket).order_by(Ticket.created_at.desc())
    if scope is not None and scope.role == Role.customer:
        q = q.where(Ticket.customer_id == scope.id)
    if "status" in filter_dict:
        q = q.where(Ticket.status == Status(filter_dict["status"]))
    if "priority" in filter_dict:
        q = q.where(Ticket.priority == Priority(filter_dict["priority"]))
    if "assignee_id" in filter_dict:
        q = q.where(Ticket.assignee_id == filter_dict["assignee_id"])
    if "customer_id" in filter_dict:
        q = q.where(Ticket.customer_id == filter_dict["customer_id"])
    if "subject_contains" in filter_dict:
        q = q.where(Ticket.subject.ilike(f"%{filter_dict['subject_contains']}%"))
    if "created_after" in filter_dict:
        q = q.where(Ticket.created_at >= filter_dict["created_after"])
    if "created_before" in filter_dict:
        q = q.where(Ticket.created_at <= filter_dict["created_before"])
    return q


def _ticket_to_dict(t: Ticket) -> dict[str, Any]:
    return {
        "id": t.id,
        "customer_id": t.customer_id,
        "assignee_id": t.assignee_id,
        "subject": t.subject,
        "description": t.description,
        "status": t.status.value if hasattr(t.status, "value") else t.status,
        "priority": t.priority.value if hasattr(t.priority, "value") else t.priority,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


# --- Result cache + executor -----------------------------------------


def _scope_cache_fragment(scope: User | None) -> str:
    """Scope-aware cache fragment.

    Customer searches must never share cache entries with other
    customers or with agent/global searches, even when the filter JSON
    is byte-identical.
    """
    if scope is None:
        return "global"
    if scope.role == Role.customer:
        return f"customer:{scope.id}"
    return f"role:{scope.role.value}"


def _cache_key(filter_json: str, scope: User | None) -> str:
    """Stable cache key derived from the filter JSON + caller scope.

    The filter JSON is already canonicalized by `serialize_filter`
    (sorted keys, normalized values), so two logically-identical
    filters produce the same key — and therefore hit the same cache
    entry within the same visibility scope. That's the win: a popular
    saved search ({status: open}) only pays the SQL cost once per TTL
    window across the whole process, without cross-tenant bleed.
    """
    material = f"{_scope_cache_fragment(scope)}::{filter_json}"
    return hashlib.sha256(material.encode()).hexdigest()


def execute_search(
    filter_json: str,
    db: Session,
    *,
    scope: User | None = None,
    use_cache: bool = True,
) -> list[dict[str, Any]]:
    """Run the saved filter and return matching tickets as dicts.

    scope=None returns the global view (used by analytics + admin
    paths that pre-authenticate upstream of this function).
    scope=<user> restricts results to that user's tickets when the
    user is a customer; agents always see everything.

    use_cache=False skips the in-process cache — useful for the
    scheduled-report worker, which needs a fresh result set every tick
    and shouldn't waste a cache slot on per-schedule one-off queries.
    """
    filter_dict = normalize_filter(json.loads(filter_json) if filter_json else {})
    canon_json = json.dumps(filter_dict, sort_keys=True, default=str)

    if use_cache:
        key = _cache_key(canon_json, scope)
        now = time.time()
        hit = _cache.get(key)
        if hit is not None:
            cached_at, rows = hit
            if now - cached_at < _CACHE_TTL_SECONDS:
                return rows

    rows = [_ticket_to_dict(t) for t in db.scalars(_build_query(filter_dict, scope)).all()]

    if use_cache:
        _cache[_cache_key(canon_json, scope)] = (time.time(), rows)
    return rows


def invalidate_cache() -> None:
    """Drop all cached results. Called by routes/tickets.py whenever a
    ticket is created, updated, or deleted — the simplest correct
    invalidation policy. Fine-grained per-key eviction would require
    knowing which filters could match a mutated row, which isn't worth
    the complexity at this scale."""
    _cache.clear()


def cache_size() -> int:
    """Operator visibility into cache occupancy. Exposed via the
    `popular searches` analytics endpoint for agents to spot-check
    cache health."""
    return len(_cache)
