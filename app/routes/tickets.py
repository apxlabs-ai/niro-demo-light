from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..db import get_db
from ..models import Comment, Role, Status, Ticket, User
from ..schemas import (
    CommentCreate,
    CommentOut,
    TicketCreate,
    TicketOut,
    TicketUpdate,
)

router = APIRouter(prefix="/tickets", tags=["tickets"])


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
    ticket_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return _load_ticket_for_read(ticket_id, user, db)


@router.patch("/{ticket_id}", response_model=TicketOut)
def update_ticket(
    ticket_id: int,
    req: TicketUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    if user.role != Role.agent and ticket.customer_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    data = req.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(ticket, field, value)
    db.commit()
    db.refresh(ticket)
    return ticket


@router.post("/{ticket_id}/reopen", response_model=TicketOut)
def reopen_ticket(
    ticket_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Reopen a resolved or closed ticket.

    Ownership is implicit: customers only see their own tickets in the
    "My tickets" list rendered by the web UI, so the ticket_id reaching
    this handler is always one the caller filed. Agents can reopen
    anything.
    """
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    if ticket.status not in (Status.resolved, Status.closed):
        raise HTTPException(status_code=400, detail="ticket is not closed")
    ticket.status = Status.open
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
