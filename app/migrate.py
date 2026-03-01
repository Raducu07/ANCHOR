# app/migrate.py
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("anchor.migrate")


def _migrations_dir() -> Path:
    here = Path(__file__).resolve()
    return (here.parent.parent / "migrations").resolve()


def _list_sql_files(mdir: Path) -> List[Path]:
    if not mdir.exists() or not mdir.is_dir():
        return []
    return sorted([p for p in mdir.iterdir() if p.is_file() and p.suffix.lower() == ".sql"])


def _ensure_schema_migrations(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS public.schema_migrations (
                filename text PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now()
            );
            """
        )
    )


def _is_applied(db: Session, filename: str) -> bool:
    row = db.execute(
        text("SELECT 1 FROM public.schema_migrations WHERE filename = :f"),
        {"f": filename},
    ).fetchone()
    return row is not None


def _mark_applied(db: Session, filename: str) -> None:
    db.execute(
        text(
            """
            INSERT INTO public.schema_migrations (filename)
            VALUES (:f)
            ON CONFLICT (filename) DO NOTHING;
            """
        ),
        {"f": filename},
    )


def _strip_sql_comments(sql: str) -> str:
    # Remove full-line comments starting with --
    out_lines = []
    for line in sql.splitlines():
        s = line.strip()
        if s.startswith("--") or s == "":
            out_lines.append(line)
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def _split_statements(sql: str) -> List[str]:
    """
    Very simple SQL splitter: splits on semicolons.
    Assumes migrations are plain DDL/DML without dollar-quoted functions containing semicolons.
    (Keep migrations simple; put functions in separate migrations if needed.)
    """
    sql = _strip_sql_comments(sql).strip()
    parts = [p.strip() for p in sql.split(";")]
    return [p for p in parts if p]


def _exec_script(db: Session, sql: str) -> int:
    stmts = _split_statements(sql)
    for stmt in stmts:
        db.execute(text(stmt))
    return len(stmts)


def run_migrations(db: Session) -> dict:
    """
    Apply SQL migrations from /migrations in lexical order.

    - Logs scan/apply/applied.
    - Uses schema_migrations to avoid reapplying.
    - Executes scripts statement-by-statement.
    - FAIL-FAST on any error.
    """
    mdir = _migrations_dir()
    files = _list_sql_files(mdir)

    db_name = db.execute(text("SELECT current_database()")).scalar()
    db_user = db.execute(text("SELECT current_user")).scalar()

    _ensure_schema_migrations(db)
    db.commit()

    applied: List[str] = []
    skipped: List[str] = []

    logger.info(
        json.dumps(
            {
                "event": "migration.scan",
                "migrations_dir": str(mdir),
                "file_count": len(files),
                "db_name": db_name,
                "db_user": db_user,
            }
        )
    )

    for path in files:
        fname = path.name
        if _is_applied(db, fname):
            skipped.append(fname)
            continue

        sql = path.read_text(encoding="utf-8").strip()
        if not sql:
            logger.info(json.dumps({"event": "migration.empty", "file": fname}))
            _mark_applied(db, fname)
            db.commit()
            applied.append(fname)
            continue

        logger.info(json.dumps({"event": "migration.apply", "file": fname}))

        try:
            stmt_count = _exec_script(db, sql)
            _mark_applied(db, fname)
            db.commit()
            applied.append(fname)
            logger.info(json.dumps({"event": "migration.applied", "file": fname, "statements": stmt_count}))
        except Exception as e:
            db.rollback()
            logger.error(
                json.dumps(
                    {
                        "event": "migration.failed",
                        "file": fname,
                        "error_type": type(e).__name__,
                        "error": str(e)[:500],
                    }
                )
            )
            raise

    return {
        "status": "ok",
        "db_name": db_name,
        "db_user": db_user,
        "migrations_dir": str(mdir),
        "applied": applied,
        "skipped": skipped,
        "file_count": len(files),
    }
