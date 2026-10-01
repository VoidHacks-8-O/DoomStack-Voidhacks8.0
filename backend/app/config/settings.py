"""Application settings — loaded from environment / .env file."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve project root (backend/)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Central configuration for ANVITRACE."""

    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "ANVITRACE"
    APP_ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # --- Server ---
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # --- Database ---
    DUCKDB_PATH: str = "data/anvitrace.duckdb"

    # --- Data Directories ---
    DATA_RAW_DIR: str = "data/raw"
    DATA_PROCESSED_DIR: str = "data/processed"
    DATA_INDEXES_DIR: str = "data/indexes"
    DATA_EVIDENCE_DIR: str = "data/evidence"
    DATA_EXPORTS_DIR: str = "data/exports"

    @property
    def project_root(self) -> Path:
        return _PROJECT_ROOT

    @property
    def duckdb_abs_path(self) -> Path:
        return _PROJECT_ROOT / self.DUCKDB_PATH


settings = Settings()
