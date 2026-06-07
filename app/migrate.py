# app/migrate.py
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("anchor.migrate")


# 2A-D.1 Patch 6 — Checksum verification env toggle.
_CHECKSUM_VERIFY_ENV = "ANCHOR_MIGRATION_VERIFY_CHECKSUMS"
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


def _migrations_dir() -> Path:
    here = Path(__file__).resolve()
    return (here.parent.parent / "migrations").resolve()


def _list_sql_files(mdir: Path) -> List[Path]:
    # 2A-D.1 Patch 6: intentionally non-recursive. Only top-level
    # `.sql` files in `migrations/` are scanned. Subdirectories are
    # ignored on purpose — historically a stray `migrations/migrations/`
    # nested file went undetected for months because it duplicated real
    # migrations and was never executed. The non-recursive `iterdir`
    # plus `is_file()` filter encodes that intent in code.
    if not mdir.exists() or not mdir.is_dir():
        return []
    return sorted([p for p in mdir.iterdir() if p.is_file() and p.suffix.lower() == ".sql"])


def _ensure_schema_migrations(db: Session) -> None:
    """
    Ensure a migrations table exists in new installs.

    NOTE: production may already have a richer schema (e.g., checksum NOT NULL).
    We won't try to alter an existing table here.
    """
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


def _has_checksum_column(db: Session) -> bool:
    row = db.execute(
        text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'schema_migrations'
              AND column_name = 'checksum'
            """
        )
    ).fetchone()
    return row is not None


def _is_applied(db: Session, filename: str) -> bool:
    row = db.execute(
        text("SELECT 1 FROM public.schema_migrations WHERE filename = :f"),
        {"f": filename},
    ).fetchone()
    return row is not None


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _checksum_sql(sql_text: str) -> str:
    """Canonical checksum of the on-disk migration source. Uses the same
    SHA-256 over the same stripped UTF-8 text the runner already uses
    when marking applied — see _mark_applied / run_migrations apply
    loop. Kept as a thin alias so the verification path and the apply
    path are guaranteed to compute checksums the same way."""
    return _sha256_hex(sql_text)


def verify_checksums_enabled() -> bool:
    """Return True iff the migration runner should verify SHA-256
    checksums of already-applied migrations on startup.

    Resolution rules (mirror the Patch 1 / 4B prod-config patterns):
      * APP_ENV=prod + env unset/blank → True (verify by default).
      * APP_ENV=prod + env in TRUTHY → True.
      * APP_ENV=prod + env in FALSY → False (operator override; allowed
        but logged at the call site).
      * APP_ENV=prod + unknown value → RuntimeError (fail-closed).
      * Non-prod + env unset/blank → False (no verification in dev/test
        so a developer rapidly iterating locally is not blocked).
      * Non-prod + env in TRUTHY → True.
      * Non-prod + env in FALSY → False.
      * Non-prod + unknown value → False (defensive fallback, no raise).
    """
    from app.anchor_logging import get_app_env

    raw = (os.getenv(_CHECKSUM_VERIFY_ENV) or "").strip().lower()
    is_prod = get_app_env() == "prod"

    if not raw:
        return is_prod

    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False

    # Unknown value — fail-closed in prod, defensive default in non-prod.
    if is_prod:
        raise RuntimeError(
            f"{_CHECKSUM_VERIFY_ENV}={raw!r} is not a recognised boolean. "
            f"Use one of: {sorted(_TRUTHY)} or {sorted(_FALSY)}."
        )
    return False


def _verify_existing_checksum(
    db: Session, *, filename: str, expected_checksum: str
) -> str:
    """For a migration that has already been applied (a row exists in
    schema_migrations), check the on-disk file SHA-256 against the
    stored checksum.

    Returns one of:
      * "no_column"   — schema_migrations has no `checksum` column yet
                        (e.g. migration 10016 has not run). Caller
                        should continue startup without verification.
      * "no_row"      — filename not present in schema_migrations.
                        Caller should treat as "not applied" and let the
                        normal apply path proceed.
      * "match"       — stored checksum equals expected.
      * "backfilled"  — stored checksum was NULL (pre-Patch-6 row);
                        backfilled with the expected value. Logged.

    Raises:
      RuntimeError    — checksum mismatch. Does NOT overwrite the stored
                        value. Refusing startup preserves forensic state.
    """
    if not _has_checksum_column(db):
        return "no_column"

    row = db.execute(
        text(
            "SELECT checksum FROM public.schema_migrations WHERE filename = :f"
        ),
        {"f": filename},
    ).mappings().first()

    if not row:
        return "no_row"

    stored = row.get("checksum")

    if stored is None:
        # Pre-Patch-6 row — backfill once, log, continue.
        db.execute(
            text(
                """
                UPDATE public.schema_migrations
                SET checksum = :c
                WHERE filename = :f
                  AND checksum IS NULL
                """
            ),
            {"f": filename, "c": expected_checksum},
        )
        logger.info(
            json.dumps(
                {
                    "event": "migration.checksum.backfilled",
                    "file": filename,
                    "checksum_sha256": expected_checksum,
                }
            )
        )
        return "backfilled"

    if str(stored) == expected_checksum:
        return "match"

    logger.error(
        json.dumps(
            {
                "event": "migration.checksum.mismatch",
                "file": filename,
                "stored_sha256": str(stored),
                "expected_sha256": expected_checksum,
            }
        )
    )
    raise RuntimeError(
        f"Migration {filename!r} checksum mismatch — the on-disk file has "
        "been edited after it was applied. Doctrine: existing migrations "
        "are never retroactively edited. Refusing to start. Restore the "
        "file to its applied state OR add a new migration."
    )


def _mark_applied(db: Session, filename: str, sql_text: str, checksum_col: bool) -> None:
    if checksum_col:
        checksum = _sha256_hex(sql_text)
        db.execute(
            text(
                """
                INSERT INTO public.schema_migrations (filename, checksum)
                VALUES (:f, :c)
                ON CONFLICT (filename) DO NOTHING;
                """
            ),
            {"f": filename, "c": checksum},
        )
    else:
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
    out_lines: List[str] = []
    for line in sql.splitlines():
        s = line.strip()
        if s.startswith("--"):
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _split_statements(sql: str) -> List[str]:
    """
    Splits on semicolons for simple SQL files.

    Option A requirement:
    - If the file contains a dollar-quoted block (e.g. DO $$ ... $$; or CREATE FUNCTION ... $$ ... $$;),
      treat the whole file as a single statement so we do NOT split on internal semicolons.
    """
    sql = _strip_sql_comments(sql).strip()
    if not sql:
        return []

    # Dollar-quoted blocks can contain semicolons; do not split them.
    if "$$" in sql:
        return [sql]

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

    - Logs scan/apply/applied/failed.
    - Uses schema_migrations to avoid reapplying.
    - Executes scripts statement-by-statement (except $$ blocks = single statement).
    - Compatible with existing schema_migrations tables that require checksum.
    - FAIL-FAST on any error.
    """
    mdir = _migrations_dir()
    files = _list_sql_files(mdir)

    db_name = db.execute(text("SELECT current_database()")).scalar()
    db_user = db.execute(text("SELECT current_user")).scalar()

    _ensure_schema_migrations(db)
    db.commit()

    checksum_col = _has_checksum_column(db)
    verify_enabled = verify_checksums_enabled()

    applied: List[str] = []
    skipped: List[str] = []
    verified: List[str] = []
    backfilled: List[str] = []

    logger.info(
        json.dumps(
            {
                "event": "migration.scan",
                "migrations_dir": str(mdir),
                "file_count": len(files),
                "db_name": db_name,
                "db_user": db_user,
                "checksum_column": checksum_col,
                "verify_checksums": verify_enabled,
            }
        )
    )

    for path in files:
        fname = path.name
        if _is_applied(db, fname):
            # 2A-D.1 Patch 6: before skipping an already-applied
            # migration, verify the on-disk file matches the checksum
            # recorded when it was first applied. A mismatch raises
            # RuntimeError and refuses startup. Disabled when the
            # toggle resolves to False (default in non-prod) so a
            # developer iterating on a migration locally is not
            # blocked. Also gracefully no-ops if the checksum column
            # has not been added yet (i.e. on the boot that applies
            # migration 10016 itself).
            if verify_enabled:
                file_sql = path.read_text(encoding="utf-8").strip()
                expected = _checksum_sql(file_sql)
                result = _verify_existing_checksum(
                    db, filename=fname, expected_checksum=expected
                )
                if result == "match":
                    verified.append(fname)
                elif result == "backfilled":
                    backfilled.append(fname)
                    db.commit()
                # "no_column" / "no_row" → silent fall-through; "no_row"
                # is impossible here because _is_applied returned True.
            skipped.append(fname)
            continue

        sql_text = path.read_text(encoding="utf-8").strip()
        if not sql_text:
            logger.info(json.dumps({"event": "migration.empty", "file": fname}))
            _mark_applied(db, fname, "", checksum_col)
            db.commit()
            applied.append(fname)
            continue

        logger.info(json.dumps({"event": "migration.apply", "file": fname}))

        try:
            stmt_count = _exec_script(db, sql_text)
            _mark_applied(db, fname, sql_text, checksum_col)
            db.commit()
            applied.append(fname)
            logger.info(
                json.dumps(
                    {"event": "migration.applied", "file": fname, "statements": stmt_count}
                )
            )
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
        "checksum_column": checksum_col,
        "verify_checksums": verify_enabled,
        "applied": applied,
        "skipped": skipped,
        "verified": verified,
        "backfilled": backfilled,
        "file_count": len(files),
    }
