from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, require_agent
from ..db import get_db
from ..models import Comment, Role, Ticket, User
from ..schemas import (
    CommentCreate,
    CommentOut,
    TicketCreate,
    TicketOut,
    TicketUpdate,
)

router = APIRouter(prefix="/tickets", tags=["tickets"])

# Largest signed 64-bit integer the SQLite/SQLAlchemy layer can bind. A
# path id beyond this overflows the driver and surfaces as an unhandled
# 500; bounding the path parameter turns it into a clean 422 instead.
MAX_TICKET_ID = 9223372036854775807

TicketIdPath = Annotated[int, Path(ge=1, le=MAX_TICKET_ID)]


def _load_ticket_for_read(
    ticket_id: int, user: User, db: Session
) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    if user.role != Role.agent and ticket.customer_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return ticket


@router.post("", response_model=TicketOut, status_code=201)
def create_ticket(
    req: TicketCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ticket = Ticket(
        customer_id=user.id,
        subject=req.subject,
        description=req.description,
        priority=req.priority,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


@router.get("", response_model=list[TicketOut])
def list_tickets(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = select(Ticket).order_by(Ticket.created_at.desc())
    if user.role == Role.customer:
        q = q.where(Ticket.customer_id == user.id)
    return list(db.scalars(q).all())


@router.get("/{ticket_id}", response_model=TicketOut)
def get_ticket(
    ticket_id: TicketIdPath,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return _load_ticket_for_read(ticket_id, user, db)


@router.patch("/{ticket_id}", response_model=TicketOut)
def update_ticket(
    ticket_id: int,
    req: TicketUpdate,
    agent: User = Depends(require_agent),
    db: Session = Depends(get_db),
):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    data = req.model_dump(exclude_unset=True)
    # assignee_id is a foreign key to users.id; SQLite does not enforce it,
    # so reject an assignee that does not correspond to an existing user
    # rather than persisting an orphaned reference. A null assignee (unassign)
    # remains valid.
    assignee_id = data.get("assignee_id")
    if assignee_id is not None and db.get(User, assignee_id) is None:
        raise HTTPException(status_code=422, detail="assignee_id does not refer to an existing user")
    for field, value in data.items():
        setattr(ticket, field, value)
    db.commit()
    db.refresh(ticket)
    return ticket


@router.post("/{ticket_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(
    ticket_id: int,
    req: CommentCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ticket = _load_ticket_for_read(ticket_id, user, db)
    comment = Comment(ticket_id=ticket.id, author_id=user.id, body=req.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@router.get("/{ticket_id}/comments", response_model=list[CommentOut])
def list_comments(
    ticket_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ticket = _load_ticket_for_read(ticket_id, user, db)
    return list(
        db.scalars(
            select(Comment)
            .where(Comment.ticket_id == ticket.id)
            .order_by(Comment.created_at.asc())
        ).all()
    )
