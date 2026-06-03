import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import Base, engine
from .jobs import start_worker
from .routes.auth import me_router, router as auth_router
from .routes.mtls import router as mtls_router
from .routes.searches import router as searches_router
from .routes.signing import router as signing_router
from .routes.tickets import router as tickets_router

logging.basicConfig(level=logging.INFO)

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Spin up the scheduled-report worker on startup, cancel it on
    shutdown. The worker drives ScheduledReport rows on its own
    cadence; the rest of the API is unaffected by its presence."""
    worker_task = start_worker()
    try:
        yield
    finally:
        worker_task.cancel()


app = FastAPI(title="Helpdesk API", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(me_router)
app.include_router(tickets_router)
app.include_router(mtls_router)
app.include_router(searches_router)
app.include_router(signing_router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
