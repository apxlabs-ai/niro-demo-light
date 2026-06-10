"""mTLS-authenticated routes.

All endpoints on this router require a valid client certificate verified
at the TLS layer (port 8443, ssl-cert-reqs=CERT_REQUIRED). The
current_user_mtls dependency resolves the cert CN to a User; no Bearer
token is needed or accepted here.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user_mtls
from ..db import get_db
from ..models import Ticket, User
from ..schemas import TicketOut, UserOut

router = APIRouter(prefix="/mtls", tags=["mtls"])


@router.get("/me", response_model=UserOut)
def mtls_me(user: User = Depends(current_user_mtls)):
    """Return the identity of the cert-authenticated caller."""
    return user


@router.get("/tickets", response_model=list[TicketOut])
def mtls_list_tickets(
    user: User = Depends(current_user_mtls),
    db: Session = Depends(get_db),
):
    """Return all tickets owned by the cert-authenticated caller."""
    return list(
        db.scalars(
            select(Ticket)
            .where(Ticket.customer_id == user.id)
            .order_by(Ticket.created_at.desc())
        ).all()
    )


@router.get("/tickets/{ticket_id}", response_model=TicketOut)
def mtls_get_ticket(
    ticket_id: int,
    user: User = Depends(current_user_mtls),
    db: Session = Depends(get_db),
):
    """Return a single ticket by ID for a cert-authenticated caller.

    Note: verifies the caller holds a valid client certificate.
    """
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    if ticket.customer_id != user.id:
        raise HTTPException(status_code=403, detail="forbidden")
    return ticket
