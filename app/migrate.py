from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import text

from app.db import ENGINE


def run_migrations() -> None:
    """
    Runs schema.sql then all files in ./migrations/*.sql in lexical order.
    Idempotency must be inside the SQL (IF NOT EXISTS etc.)
    """
    root = Path(__file__).resolve().parent
    schema_path = root / "schema.sql"
    migrations_dir = root / "migrations"

    if not schema_path.exists():
        raise RuntimeError(f"schema.sql not found at: {schema_path}")

    schema_sql = schema_path.read_text(encoding="utf-8")

    migration_files = []
    if migrations_dir.exists() and migrations_dir.is_dir():
        migration_files = sorted(migrations_dir.glob("*.sql"))

    with ENGINE.begin() as conn:
        # 1) Base schema
        conn.execute(text(schema_sql))

        # 2) Additive migrations
        for f in migration_files:
            sql = f.read_text(encoding="utf-8").strip()
            if not sql:
                continue
            conn.execute(text(sql))

    logging.getLogger(__name__).info(
        "migrations_ok",
        extra={"schema": str(schema_path), "count": len(migration_files)},
    )
