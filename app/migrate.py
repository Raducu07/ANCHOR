# app/migrate.py
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("anchor.migrate")


def _migrations_dir() -> Path:
    # project_root/migrations
    # app/ is sibling of migrations/
    here = Path(__file__).resolve()
    return (here.parent.parent / "migrations").resolve()


def _list_sql_files(mdir: Path) -> List[Path]:
    if not mdir.exists() or not mdir.is_dir():
        return []
    files = sorted([p for p in mdir.iterdir() if p.is_file() and p.suffix.lower() == ".sql"])
    return files


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


def run_migrations(db: Session) -> dict:
    """
    Apply SQL migrations from /migrations in lexical order.

    - Logs each apply.
    - Uses schema_migrations to avoid reapplying.
    - FAIL-FAST: any migration error raises (so deploy cannot silently succeed).
    """
    mdir = _migrations_dir()
    files = _list_sql_files(mdir)

    # Lightweight diagnostics to prove what DB we are on
    db_name = db.execute(text("SELECT current_database()")).scalar()
    db_user = db.execute(text("SELECT current_user")).scalar()

    # Make sure the tracking table exists
    _ensure_schema_migrations(db)
    db.commit()

    applied = []
    skipped = []

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
            # empty migration file: mark applied to avoid looping forever
            logger.info(json.dumps({"event": "migration.empty", "file": fname}))
            _mark_applied(db, fname)
            db.commit()
            applied.append(fname)
            continue

        logger.info(json.dumps({"event": "migration.apply", "file": fname}))

        try:
            # Run inside a transaction; if any statement fails, rollback and raise.
            db.execute(text(sql))
            _mark_applied(db, fname)
            db.commit()
            applied.append(fname)
            logger.info(json.dumps({"event": "migration.applied", "file": fname}))
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
