from fastapi import FastAPI

from .db import Base, engine
from .routes.auth import me_router, router as auth_router
from .routes.tickets import router as tickets_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Helpdesk API", version="0.1.0")
app.include_router(auth_router)
app.include_router(me_router)
app.include_router(tickets_router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
