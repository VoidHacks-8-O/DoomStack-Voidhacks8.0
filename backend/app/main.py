"""ANVITRACE — FastAPI Application Entry Point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.database.duckdb import close, connect
from app.routers.dataset import router as dataset_router
from app.routers.investigations import account_router, investigation_router
from app.utils.logging import logger


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info("Starting up ANVITRACE backend platform...")
    connect()
    logger.info("DuckDB connected and canonical schema applied.")
    yield
    logger.info("Shutting down ANVITRACE backend platform...")
    close()
    logger.info("DuckDB connection closed safely.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Offline cyber-forensics platform for financial transaction analysis and money-mule investigation.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for local forensic UI / inspection tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
@app.get("/api/health", tags=["system"])
async def health_check():
    """System health check endpoint."""
    return {
        "status": "ok",
        "project": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": "DuckDB (Embedded)",
        "offline": True,
    }



# Register functional routers
app.include_router(dataset_router, prefix="/api")
app.include_router(account_router, prefix="/api")
app.include_router(investigation_router, prefix="/api")
