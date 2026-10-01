"""ANVITRACE — FastAPI Application Entry Point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config.settings import settings


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    # TODO: Initialize DuckDB connection on startup
    yield
    # TODO: Close DuckDB connection on shutdown


app = FastAPI(
    title=settings.APP_NAME,
    description="Offline cyber-forensics platform for financial transaction analysis and money-mule investigation.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
async def health_check():
    """Basic health check endpoint."""
    return {"status": "ok", "project": settings.APP_NAME}
