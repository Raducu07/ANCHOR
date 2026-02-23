# app/migrate.py
import os
from pathlib import Path

from sqlalchemy import text
from app.db import ENGINE


def _read_sql(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _exec_sql(sql: str) -> None:
    with ENGINE.begin() as conn:
        conn.execute(text(sql))


def run_migrations() -> None:
    base = Path(__file__).parent
    schema_path = base / "schema.sql"
    security_path = base / "security.sql"

    # Always run schema
    _exec_sql(_read_sql(schema_path))

    # Only run security when explicitly enabled
    if os.getenv("RUN_SECURITY_MIGRATIONS", "0").strip() != "1":
        return

    if not security_path.exists():
        return

    strict = os.getenv("STRICT_SECURITY_MIGRATIONS", "0").strip() == "1"
    try:
        _exec_sql(_read_sql(security_path))
    except Exception:
        if strict:
            raise
