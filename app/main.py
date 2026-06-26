import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .db import Base, engine
from .jobs import start_worker
from .routes.auth import me_router, router as auth_router
from .routes.mtls import router as mtls_router
from .routes.searches import router as searches_router
from .routes.tickets import router as tickets_router

logging.basicConfig(level=logging.INFO)

Base.metadata.create_all(bind=engine)

# Field-name fragments whose submitted value must never be reflected back in a
# validation-error response (case-insensitive substring match on the loc path).
_SENSITIVE_LOC_FRAGMENTS = ("password", "passwd", "secret", "token", "pwd")
_REDACTED = "[redacted]"


def _is_sensitive_loc(loc) -> bool:
    for part in loc or ():
        if isinstance(part, str) and any(
            frag in part.lower() for frag in _SENSITIVE_LOC_FRAGMENTS
        ):
            return True
    return False


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


@app.exception_handler(RequestValidationError)
async def redact_validation_errors(request: Request, exc: RequestValidationError):
    """Custom 422 handler that mirrors FastAPI's default response shape but
    redacts the echoed ``input`` for sensitive fields (e.g. ``password``).

    FastAPI/Pydantic's default RequestValidationError handler serializes the
    raw submitted value into ``detail[*].input``. For sensitive fields that
    reflects the secret verbatim into the response body — and from there into
    proxy logs, APM agents, and error monitors that capture 4xx bodies. Here we
    strip that value for sensitive locs while leaving every other field (and the
    overall structure/status) untouched, so ordinary validation errors stay
    actionable for clients.
    """
    sanitized = []
    for err in exc.errors():
        err = dict(err)
        if _is_sensitive_loc(err.get("loc")):
            if "input" in err:
                err["input"] = _REDACTED
            # ``ctx`` can carry the offending value for some error types; drop
            # it for sensitive fields as defense-in-depth.
            err.pop("ctx", None)
        sanitized.append(err)
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder({"detail": sanitized}),
    )


app.include_router(auth_router)
app.include_router(me_router)
app.include_router(tickets_router)
app.include_router(mtls_router)
app.include_router(searches_router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
