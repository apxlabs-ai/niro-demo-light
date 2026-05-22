import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import inspect, text

from .db import Base, engine
from .jobs import start_worker
from .routes.auth import me_router, router as auth_router
from .routes.searches import router as searches_router
from .routes.tickets import router as tickets_router

logging.basicConfig(level=logging.INFO)

def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        columns = {c["name"] for c in inspect(conn).get_columns("saved_searches")}
        if "deleted" not in columns:
            conn.execute(
                text(
                    "ALTER TABLE saved_searches "
                    "ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT 0"
                )
            )
        run_columns = {c["name"] for c in inspect(conn).get_columns("report_runs")}
        if "search_name_snapshot" not in run_columns:
            conn.execute(
                text(
                    "ALTER TABLE report_runs "
                    "ADD COLUMN search_name_snapshot VARCHAR NOT NULL DEFAULT ''"
                )
            )
        if "filter_json_snapshot" not in run_columns:
            conn.execute(
                text(
                    "ALTER TABLE report_runs "
                    "ADD COLUMN filter_json_snapshot TEXT NOT NULL DEFAULT '{}'"
                )
            )


ensure_schema()


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
app.include_router(searches_router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
