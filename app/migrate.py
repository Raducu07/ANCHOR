# app/migrate.py
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Tuple

from sqlalchemy import text

from app.db import ENGINE


MIGRATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

SELECT_APPLIED_SQL = """
SELECT filename, checksum
FROM schema_migrations
ORDER BY filename ASC;
"""

INSERT_APPLIED_SQL = """
INSERT INTO schema_migrations (filename, checksum)
VALUES (:filename, :checksum)
ON CONFLICT (filename) DO NOTHING;
"""


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _list_migration_files(migrations_dir: Path) -> List[Path]:
    if not migrations_dir.exists() or not migrations_dir.is_dir():
        return []
    # Only .sql files, sorted by name (your YYYYMMDD_XX naming works perfectly)
    return sorted([p for p in migrations_dir.glob("*.sql") if p.is_file()])


def run_migrations() -> None:
    """
    Safe, idempotent migration runner:
      1) Apply schema.sql baseline (idempotent).
      2) Apply new migrations from ./migrations/*.sql in sorted order.
      3) Track applied migrations + checksum in schema_migrations.
    """

    base_dir = Path(__file__).parent
    schema_path = base_dir / "schema.sql"
    migrations_dir = base_dir.parent / "migrations"

    with ENGINE.begin() as conn:
        # Ensure tracking table exists
        conn.execute(text(MIGRATIONS_TABLE_SQL))

        # Load applied migrations
        applied_rows: List[Tuple[str, str]] = [
            (str(r[0]), str(r[1])) for r in conn.execute(text(SELECT_APPLIED_SQL)).fetchall()
        ]
        applied = {fn: chk for fn, chk in applied_rows}

        # 1) Baseline schema (idempotent, safe to run repeatedly)
        if schema_path.exists():
            schema_sql = _read_text_file(schema_path).strip()
            if schema_sql:
                conn.execute(text(schema_sql))

        # 2) Apply migrations (only those not already applied)
        for path in _list_migration_files(migrations_dir):
            filename = path.name
            sql = _read_text_file(path).strip()
            if not sql:
                # Empty file: still record it to avoid re-checking every deploy
                conn.execute(text(INSERT_APPLIED_SQL), {"filename": filename, "checksum": _sha256("")})
                continue

            checksum = _sha256(sql)

            if filename in applied:
                # If the file changed after being applied, fail fast (protects prod consistency)
                if applied[filename] != checksum:
                    raise RuntimeError(
                        f"Migration checksum mismatch for {filename}. "
                        f"Applied={applied[filename]} Current={checksum}. "
                        f"Do not edit applied migrations; create a new one."
                    )
                # Already applied, skip
                continue

            # Apply migration file
            conn.execute(text(sql))

            # Record it
            conn.execute(text(INSERT_APPLIED_SQL), {"filename": filename, "checksum": checksum})
