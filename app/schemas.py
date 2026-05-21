from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .models import Priority, ReportFrequency, Role, Status


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: Role


class TicketCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    priority: Priority = Priority.normal


class TicketUpdate(BaseModel):
    status: Status | None = None
    priority: Priority | None = None
    assignee_id: int | None = None


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    customer_id: int
    assignee_id: int | None
    subject: str
    description: str
    status: Status
    priority: Priority
    created_at: datetime
    updated_at: datetime


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class CommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ticket_id: int
    author_id: int
    body: str
    created_at: datetime


# --- Saved search & scheduled-report payloads -------------------------
#
# The filter payload is a small flat dict — keys correspond to columns
# on the tickets table the search executor understands. See
# app/search.py for the supported keys and their semantics.


class SearchFilter(BaseModel):
    """A ticket filter as it appears on the wire.

    Every field is optional. An empty filter matches all tickets the
    caller is allowed to see. Validation happens at construction time so
    bad enum values surface as 422 from the API layer rather than as a
    SQLAlchemy error deep in the executor."""

    status: Status | None = None
    priority: Priority | None = None
    assignee_id: int | None = Field(default=None, ge=0)
    customer_id: int | None = Field(default=None, ge=0)
    subject_contains: str | None = Field(default=None, max_length=200)
    created_after: datetime | None = None
    created_before: datetime | None = None


class SavedSearchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    filter: SearchFilter
    pinned: bool = False


class SavedSearchUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    filter: SearchFilter | None = None
    pinned: bool | None = None


class SavedSearchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    name: str
    filter_json: str
    pinned: bool
    created_at: datetime
    updated_at: datetime


class SearchResultsOut(BaseModel):
    count: int
    tickets: list[TicketOut]


class ScheduleReportCreate(BaseModel):
    frequency: ReportFrequency = ReportFrequency.daily
    email: EmailStr


class ScheduledReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    saved_search_id: int
    frequency: ReportFrequency
    email: EmailStr
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime


class ReportRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scheduled_report_id: int
    ran_at: datetime
    result_count: int
    duration_ms: int
    success: bool
    error: str | None


class ScheduleCreateResponse(BaseModel):
    """Returned from POST /searches/{id}/schedule. Includes the new
    schedule record plus the initial run's results so the caller can
    immediately see what the first emailed report would contain. The
    initial run also persists as a ReportRun row, same as any
    background-tick run."""

    schedule: ScheduledReportOut
    initial_run: ReportRunOut
    initial_results: list[TicketOut]
