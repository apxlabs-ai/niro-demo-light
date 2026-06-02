"""Saved-search + scheduled-report endpoints.

Surface:

  POST   /searches                          create a saved search
  GET    /searches                          list the caller's saved searches
  GET    /searches/{id}                     read one saved search
  PATCH  /searches/{id}                     rename / re-filter / pin
  DELETE /searches/{id}                     delete (cascades to schedules + runs)
  GET    /searches/{id}/run                 execute and return matches
  POST   /searches/{id}/schedule            wire up a recurring email report
  GET    /searches/{id}/schedule            list this search's schedules
  DELETE /searches/schedules/{schedule_id}  disable a schedule
  GET    /searches/schedules/{schedule_id}/runs  inspect a schedule's run history
  GET    /searches/_stats                   operator/agent: cache stats + popular searches
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import current_user, require_agent
from ..db import get_db
from ..jobs import run_scheduled_report
from ..models import Role, SavedSearch, ScheduledReport, User
from ..schemas import (
    ReportRunOut,
    SavedSearchCreate,
    SavedSearchOut,
    SavedSearchUpdate,
    ScheduleCreateResponse,
    ScheduledReportOut,
    ScheduleReportCreate,
    SearchResultsOut,
    TicketOut,
)
from ..search import (
    FilterError,
    cache_size,
    execute_search,
    serialize_filter,
)

router = APIRouter(prefix="/searches", tags=["searches"])


# --- Helpers ----------------------------------------------------------


def _load_search_for_read(
    search_id: int, user: User, db: Session
) -> SavedSearch:
    """Load a saved search, returning 404 / 403 with the same semantics
    as the rest of the API. Agents may read any search for analytics;
    customers may only read their own."""
    saved = db.get(SavedSearch, search_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="saved search not found")
    if user.role != Role.agent and saved.owner_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return saved


def _load_search_for_owner(search_id: int, user: User, db: Session) -> SavedSearch:
    """Load a saved search for owner-only mutations."""
    saved = db.get(SavedSearch, search_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="saved search not found")
    if saved.owner_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return saved


def _load_schedule_for_owner(
    schedule_id: int, user: User, db: Session
) -> ScheduledReport:
    """Same idea, for ScheduledReport rows. The owner is identified
    indirectly: ScheduledReport.saved_search_id → SavedSearch.owner_id."""
    sched = db.get(ScheduledReport, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    saved = db.get(SavedSearch, sched.saved_search_id)
    if saved is None:
        # Orphan schedule — shouldn't happen given the cascade rule,
        # but treat as not-found for the caller.
        raise HTTPException(status_code=404, detail="schedule not found")
    if user.role != Role.agent and saved.owner_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return sched


def _load_schedule_for_mutation(
    schedule_id: int, user: User, db: Session
) -> ScheduledReport:
    sched = db.get(ScheduledReport, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    saved = db.get(SavedSearch, sched.saved_search_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    if saved.owner_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return sched


# --- CRUD on saved searches ------------------------------------------


@router.post("", response_model=SavedSearchOut, status_code=201)
def create_search(
    req: SavedSearchCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    saved = SavedSearch(
        owner_id=user.id,
        name=req.name,
        filter_json=serialize_filter(req.filter.model_dump(mode="json")),
        pinned=req.pinned,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


@router.get("", response_model=list[SavedSearchOut])
def list_searches(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = select(SavedSearch).order_by(
        SavedSearch.pinned.desc(), SavedSearch.created_at.desc()
    )
    if user.role == Role.customer:
        q = q.where(SavedSearch.owner_id == user.id)
    return list(db.scalars(q).all())


# --- Agent-only analytics --------------------------------------------


@router.get("/_stats")
def search_stats(
    agent: User = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """Operator view: search-count totals + cache occupancy + the top
    pinned filters across all customers. Agent role required because
    this aggregates across tenants for capacity planning."""
    total = db.scalar(select(func.count()).select_from(SavedSearch))
    pinned = db.scalar(
        select(func.count())
        .select_from(SavedSearch)
        .where(SavedSearch.pinned.is_(True))
    )
    return {
        "total_saved_searches": int(total or 0),
        "pinned_saved_searches": int(pinned or 0),
        "result_cache_size": cache_size(),
    }


@router.get("/{search_id}", response_model=SavedSearchOut)
def get_search(
    search_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return _load_search_for_read(search_id, user, db)


@router.patch("/{search_id}", response_model=SavedSearchOut)
def update_search(
    search_id: int,
    req: SavedSearchUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    saved = _load_search_for_owner(search_id, user, db)
    if req.name is not None:
        saved.name = req.name
    if req.filter is not None:
        saved.filter_json = serialize_filter(req.filter.model_dump(mode="json"))
    if req.pinned is not None:
        saved.pinned = req.pinned
    db.commit()
    db.refresh(saved)
    return saved


@router.delete("/{search_id}", status_code=204)
def delete_search(
    search_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    saved = _load_search_for_owner(search_id, user, db)
    db.delete(saved)
    db.commit()


# --- Run a search on demand ------------------------------------------


@router.get("/{search_id}/run", response_model=SearchResultsOut)
def run_search(
    search_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Execute the saved search against the current ticket table and
    return matching rows. The caller's scope is passed to the executor
    so a customer only sees their own tickets even if the saved search
    has no explicit customer_id filter."""
    saved = _load_search_for_read(search_id, user, db)
    try:
        rows = execute_search(saved.filter_json, db, scope=user)
    except FilterError as e:
        raise HTTPException(status_code=422, detail=f"saved search filter invalid: {e}")
    return SearchResultsOut(count=len(rows), tickets=rows)


# --- Schedules + run history ----------------------------------------


@router.post(
    "/{search_id}/schedule",
    response_model=ScheduleCreateResponse,
    status_code=201,
)
def schedule_report(
    search_id: int,
    req: ScheduleReportCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Wire a saved search to a recurring email report. We fire an
    initial run immediately so the caller sees what the first emailed
    report would look like — this also surfaces filter errors at create
    time rather than at the next worker tick."""
    saved = _load_search_for_owner(search_id, user, db)

    sched = ScheduledReport(
        saved_search_id=saved.id,
        frequency=req.frequency,
        email=req.email,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    # Fire once now via the same code path the background tick uses.
    # The worker function persists a ReportRun row + sends the email +
    # advances next_run_at, so the schedule is fully primed when we
    # return.
    initial_run = run_scheduled_report(sched.id, db)
    db.refresh(sched)

    # The user wants the initial run's results inline in the response
    # for UX confirmation — re-run the (cached) filter through the
    # executor so the response carries TicketOut rows rather than the
    # truncated id list stored on the ReportRun audit row.
    try:
        rows = execute_search(saved.filter_json, db, scope=user)
    except FilterError:
        rows = []
    return ScheduleCreateResponse(
        schedule=sched,
        initial_run=initial_run,
        initial_results=rows,
    )


@router.get("/{search_id}/schedule", response_model=list[ScheduledReportOut])
def list_schedules(
    search_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    saved = _load_search_for_owner(search_id, user, db)
    rows = db.scalars(
        select(ScheduledReport).where(ScheduledReport.saved_search_id == saved.id)
    ).all()
    return list(rows)


@router.delete("/schedules/{schedule_id}", status_code=204)
def disable_schedule(
    schedule_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Disable + delete a schedule. We hard-delete here (the ReportRun
    history is preserved via SET NULL'ed FK on the runs table)."""
    sched = _load_schedule_for_mutation(schedule_id, user, db)
    db.delete(sched)
    db.commit()


@router.get(
    "/schedules/{schedule_id}/runs", response_model=list[ReportRunOut]
)
def list_runs(
    schedule_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Read the run history for a schedule. Useful for spotting silent
    failures (success=False rows with error messages) without waiting
    for an out-of-band alert."""
    sched = _load_schedule_for_mutation(schedule_id, user, db)
    from ..models import ReportRun

    rows = (
        db.scalars(
            select(ReportRun)
            .where(ReportRun.scheduled_report_id == sched.id)
            .order_by(ReportRun.ran_at.desc())
        )
        .all()
    )
    return list(rows)
