"""DuckDB connection management.

Provides a thin abstraction for obtaining and closing a DuckDB connection.
The actual connection lifecycle is managed by the FastAPI lifespan in main.py.
"""

from pathlib import Path

import duckdb

from app.config.settings import settings

# Module-level connection reference (initialised during app startup).
_connection: duckdb.DuckDBPyConnection | None = None


def get_connection() -> duckdb.DuckDBPyConnection:
    """Return the active DuckDB connection.

    Raises:
        RuntimeError: If the connection has not been initialised yet.
    """
    if _connection is None:
        raise RuntimeError("DuckDB connection has not been initialised. Call connect() first.")
    return _connection


def connect(db_path: Path | str | None = None) -> duckdb.DuckDBPyConnection:
    """Open (or create) a DuckDB database and store the connection.

    Args:
        db_path: Path to the DuckDB file.  Defaults to the value in settings.

    Returns:
        The opened DuckDB connection.
    """
    global _connection  # noqa: PLW0603
    path = Path(db_path) if db_path else settings.duckdb_abs_path
    path.parent.mkdir(parents=True, exist_ok=True)
    _connection = duckdb.connect(str(path))
    return _connection


def close() -> None:
    """Close the active DuckDB connection if one exists."""
    global _connection  # noqa: PLW0603
    if _connection is not None:
        _connection.close()
        _connection = None
