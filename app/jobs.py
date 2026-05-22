"""Background worker for scheduled email reports.

Runs in-process via an asyncio task started by FastAPI's lifespan
hook. Every `_TICK_SECONDS`, the worker:

  1. Scans ScheduledReport rows for any whose `next_run_at` has passed
     and whose `enabled` flag is True.
  2. For each due row, runs the saved-search filter and persists a
     ReportRun record + sends a mock email.
  3. Updates `next_run_at` to now + frequency delta.

Per-tick errors are caught + logged + recorded on the ReportRun row so
a single bad schedule doesn't poison the worker. The schema permits
re-enabling a disabled schedule, so operators can investigate a
failure and resume without touching the DB by hand.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .email import render_report_body, render_report_subject, send_email
from .models import ReportFrequency, ReportRun, SavedSearch, ScheduledReport, User
from .search import FilterError, execute_search

_logger = logging.getLogger(__name__)

# Tick once per minute. The frequency enum quantizes schedules into
# hourly/daily/weekly buckets, so sub-minute precision wouldn't move
# the needle for any real user-visible schedule.
_TICK_SECONDS = 60

_FREQUENCY_DELTAS = {
    ReportFrequency.hourly: timedelta(hours=1),
    ReportFrequency.daily: timedelta(days=1),
    ReportFrequency.weekly: timedelta(weeks=1),
}


def _next_run_after(frequency: ReportFrequency, fired_at: datetime) -> datetime:
    """Compute the next firing time given the cadence + the moment the
    current run started. Tied to the run's start time (not its end) so
    a long-running report doesn't drift its schedule."""
    return fired_at + _FREQUENCY_DELTAS[frequency]


import json as _json


def run_scheduled_report(report_id: int, db: Session) -> ReportRun:
    """Execute one scheduled report and return the persisted ReportRun.

    Order of operations:
      1. Load the schedule, its saved search, and the owning user.
      2. Run the search filter via the shared executor.
      3. Render + send the email.
      4. Persist a ReportRun + advance next_run_at + last_run_at.

    Any exception during steps 2–3 is caught and recorded on the
    ReportRun row (success=False, error=<message>). The next_run_at
    advance still happens so a permanently-broken schedule retries on
    its normal cadence rather than firing on every worker tick.
    """
    started = datetime.utcnow()
    report = db.get(ScheduledReport, report_id)
    if report is None:
        # Race: schedule was deleted between dequeue and load. No-op.
        return ReportRun(
            scheduled_report_id=report_id,
            ran_at=started,
            success=False,
            error="schedule not found",
        )
    saved = db.get(SavedSearch, report.saved_search_id)
    if saved is None:
        run = ReportRun(
            scheduled_report_id=report.id,
            ran_at=started,
            success=False,
            error="saved search not found",
        )
        db.add(run)
        report.next_run_at = _next_run_after(report.frequency, started)
        report.last_run_at = started
        db.commit()
        db.refresh(run)
        return run

    owner = db.get(User, saved.owner_id)
    if owner is None:
        run = ReportRun(
            scheduled_report_id=report.id,
            ran_at=started,
            success=False,
            error="owner user not found",
        )
        db.add(run)
        report.next_run_at = _next_run_after(report.frequency, started)
        report.last_run_at = started
        db.commit()
        db.refresh(run)
        return run

    try:
        # Scope to the saved-search owner so a customer's scheduled report
        # only contains their own tickets. use_cache=False ensures each
        # background tick gets a fresh result rather than a stale cache hit.
        results = execute_search(saved.filter_json, db, scope=owner, use_cache=False)
    except FilterError as e:
        run = ReportRun(
            scheduled_report_id=report.id,
            ran_at=started,
            success=False,
            error=f"filter invalid: {e}",
        )
        db.add(run)
        report.next_run_at = _next_run_after(report.frequency, started)
        report.last_run_at = started
        db.commit()
        db.refresh(run)
        return run
    except Exception as e:  # noqa: BLE001 — broad catch is intentional here
        _logger.exception("filter execution failed for report %s", report.id)
        run = ReportRun(
            scheduled_report_id=report.id,
            ran_at=started,
            success=False,
            error=f"execute_search raised: {type(e).__name__}",
        )
        db.add(run)
        report.next_run_at = _next_run_after(report.frequency, started)
        report.last_run_at = started
        db.commit()
        db.refresh(run)
        return run

    subject = render_report_subject(saved.name, len(results))
    body = render_report_body(saved.name, report.frequency.value, results)
    try:
        send_email(to=report.email, subject=subject, body=body)
    except Exception as e:  # noqa: BLE001
        _logger.exception("email send failed for report %s", report.id)
        run = ReportRun(
            scheduled_report_id=report.id,
            ran_at=started,
            success=False,
            error=f"email send raised: {type(e).__name__}",
            result_count=len(results),
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
            result_ticket_ids_json=_json.dumps([t["id"] for t in results][:200]),
        )
        db.add(run)
        report.next_run_at = _next_run_after(report.frequency, started)
        report.last_run_at = started
        db.commit()
        db.refresh(run)
        return run

    run = ReportRun(
        scheduled_report_id=report.id,
        ran_at=started,
        success=True,
        result_count=len(results),
        duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        result_ticket_ids_json=_json.dumps([t["id"] for t in results][:200]),
    )
    db.add(run)
    report.next_run_at = _next_run_after(report.frequency, started)
    report.last_run_at = started
    db.commit()
    db.refresh(run)
    return run


def _due_report_ids(db: Session, now: datetime) -> list[int]:
    """All enabled schedules whose next_run_at is at or before `now`."""
    rows = db.scalars(
        select(ScheduledReport.id).where(
            ScheduledReport.enabled.is_(True),
            ScheduledReport.next_run_at <= now,
        )
    ).all()
    return list(rows)


async def worker_loop() -> None:
    """Drive `run_scheduled_report` for every due schedule, once per
    tick. Sleeps first so app startup isn't blocked by a flood of
    backed-up schedules.

    The DB session is opened per tick (not per report) so a single
    flaky report can't poison the session for its siblings on the same
    tick. Errors that escape `run_scheduled_report` are caught here as
    a last-resort guardrail so a malformed schedule can't kill the
    worker task."""
    _logger.info("scheduled-report worker started; tick=%ss", _TICK_SECONDS)
    while True:
        try:
            await asyncio.sleep(_TICK_SECONDS)
        except asyncio.CancelledError:
            _logger.info("scheduled-report worker cancelled")
            raise
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            due = _due_report_ids(db, now)
            for report_id in due:
                try:
                    run_scheduled_report(report_id, db)
                except Exception:  # noqa: BLE001
                    _logger.exception("worker tick failed for report %s", report_id)
        finally:
            db.close()


def start_worker() -> asyncio.Task:
    """Start the background worker on the current event loop. Called
    from the FastAPI lifespan hook in app/main.py."""
    return asyncio.get_event_loop().create_task(worker_loop())
