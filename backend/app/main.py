import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .admin import router as admin_router
from .api.routes import router
from .auth import router as auth_router
from .config import get_settings
from .db import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db(settings)
    logger.info("database ready at %s", settings.database_url)
    yield


app = FastAPI(
    title="Sentinel Scan",
    description=(
        "Scan IoCs with clamd and enrich verdicts against VirusTotal, AlienVault OTX and abuse.ch."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def private_responses(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(router)


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}
