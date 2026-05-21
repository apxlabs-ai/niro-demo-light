import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Role(str, enum.Enum):
    customer = "customer"
    agent = "agent"


class ReportFrequency(str, enum.Enum):
    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"


class Status(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    waiting_customer = "waiting_customer"
    resolved = "resolved"
    closed = "closed"


class Priority(str, enum.Enum):
    low = "low"
    normal = "normal"
    high = "high"
    urgent = "urgent"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    full_name: Mapped[str] = mapped_column(String)
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.customer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    subject: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    status: Mapped[Status] = mapped_column(SAEnum(Status), default=Status.open)
    priority: Mapped[Priority] = mapped_column(
        SAEnum(Priority), default=Priority.normal
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    customer = relationship("User", foreign_keys=[customer_id])
    assignee = relationship("User", foreign_keys=[assignee_id])
    comments = relationship(
        "Comment", back_populates="ticket", cascade="all, delete-orphan"
    )


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    ticket = relationship("Ticket", back_populates="comments")
    author = relationship("User")


class SavedSearch(Base):
    """A named, persisted ticket-filter combo. Customers save searches they
    re-use (e.g., 'my open urgent items'), agents save dashboards across
    customers ('all waiting_customer over 24h'). Filter shape is
    documented in app/search.py — kept as JSON in the DB so adding a new
    filter axis is a Pydantic schema change, not a migration."""

    __tablename__ = "saved_searches"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    filter_json: Mapped[str] = mapped_column(Text)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    owner = relationship("User", foreign_keys=[owner_id])
    schedules = relationship(
        "ScheduledReport", back_populates="saved_search", cascade="all, delete-orphan"
    )


class ScheduledReport(Base):
    """A saved search wired up to fire periodically and email the result
    set to a recipient. Frequency is an enum (hourly/daily/weekly) for
    UX simplicity; the worker computes `next_run_at` from the previous
    fire + the frequency delta."""

    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    saved_search_id: Mapped[int] = mapped_column(
        ForeignKey("saved_searches.id"), index=True
    )
    frequency: Mapped[ReportFrequency] = mapped_column(
        SAEnum(ReportFrequency), default=ReportFrequency.daily
    )
    email: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    saved_search = relationship("SavedSearch", back_populates="schedules")
    runs = relationship("ReportRun", back_populates="schedule", cascade="save-update, merge")


class ReportRun(Base):
    """A single execution of a scheduled report. Persisted for audit
    (`who got what data when`) and so operators can re-inspect failed
    runs without waiting for the next tick."""

    __tablename__ = "report_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scheduled_report_id: Mapped[int | None] = mapped_column(
        ForeignKey("scheduled_reports.id"), nullable=True, index=True
    )
    ran_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    # Truncated ticket-id list — useful for operators inspecting a run
    # without re-running the filter. Capped at 200 IDs to keep rows light.
    result_ticket_ids_json: Mapped[str] = mapped_column(Text, default="[]")

    schedule = relationship("ScheduledReport", back_populates="runs")
