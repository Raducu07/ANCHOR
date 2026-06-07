"""
2A-D.1 Patch 6 — migration checksum verification tests.

Covers:
  * `_checksum_sql` — deterministic SHA-256.
  * `verify_checksums_enabled()` env toggle resolution (prod default on,
    non-prod default off, explicit truthy/falsy, unknown values).
  * `_verify_existing_checksum(...)` behaviour against a stubbed
    SQLAlchemy session: match / backfill / mismatch / no-column / no-row.
  * `_list_sql_files` is non-recursive and there are no stray nested
    `.sql` files under `migrations/`.
  * Migration 10016 exists, adds the column, and is idempotent.

No live DB. The stub session records SQL it is given and returns canned
rows from `mappings().first()` so the checksum-verification path can be
exercised end-to-end.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"
CHECKSUM_MIGRATION = MIGRATIONS_DIR / "10016_schema_migrations_checksum.sql"

from app.migrate import (  # noqa: E402
    _checksum_sql,
    _list_sql_files,
    _sha256_hex,
    _verify_existing_checksum,
    verify_checksums_enabled,
)


# ---------------------------------------------------------------------
# Stub session
# ---------------------------------------------------------------------


class _Mapping:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row


class _ScalarResult:
    def __init__(self, value: Any):
        self._value = value

    def scalar(self) -> Any:
        return self._value


class _MappingsCarrier:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def mappings(self) -> _Mapping:
        return _Mapping(self._row)

    def fetchone(self) -> Optional[Dict[str, Any]]:
        return self._row


class _StubSession:
    """Programmable stub for the small subset of SQLAlchemy session API
    the migration runner uses.

    Configure:
      * `has_checksum_column` — tied to the canned response for the
        information_schema lookup in `_has_checksum_column`.
      * `existing_checksum_row` — what
        `SELECT checksum FROM schema_migrations WHERE filename=:f`
        returns. `None` means "no row found".
      * `existing_checksum_value` — the value inside that row's
        `checksum` field (use `None` to simulate a NULL backfill case;
        only consulted when `existing_checksum_row=True`).

    All `execute(...)` calls are recorded in `self.calls` for assertion.
    """

    def __init__(
        self,
        *,
        has_checksum_column: bool = True,
        existing_checksum_row: bool = True,
        existing_checksum_value: Optional[str] = "PLACEHOLDER",
    ) -> None:
        self.has_checksum_column = has_checksum_column
        self.existing_checksum_row = existing_checksum_row
        self.existing_checksum_value = existing_checksum_value
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.committed = False

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(statement, "text", statement))
        self.calls.append((sql, dict(params or {})))

        upper = sql.upper()

        # _has_checksum_column lookup
        if "INFORMATION_SCHEMA.COLUMNS" in upper:
            return _MappingsCarrier(
                {"col": 1} if self.has_checksum_column else None
            )

        # SELECT checksum FROM public.schema_migrations
        if "SELECT CHECKSUM FROM PUBLIC.SCHEMA_MIGRATIONS" in upper:
            if not self.existing_checksum_row:
                return _MappingsCarrier(None)
            return _MappingsCarrier({"checksum": self.existing_checksum_value})

        # UPDATE backfill
        if "UPDATE PUBLIC.SCHEMA_MIGRATIONS" in upper:
            return _MappingsCarrier(None)

        return _MappingsCarrier(None)

    def commit(self) -> None:
        self.committed = True


# ---------------------------------------------------------------------
# 1. _checksum_sql is deterministic and matches the existing hasher
# ---------------------------------------------------------------------


def test_checksum_sql_is_deterministic() -> None:
    sql = "ALTER TABLE foo ENABLE ROW LEVEL SECURITY;"
    assert _checksum_sql(sql) == _checksum_sql(sql)


def test_checksum_sql_matches_existing_sha256_helper() -> None:
    """Apply path uses `_sha256_hex(sql_text)` to write the checksum;
    verification must use the same function so the two paths agree."""
    sql = "DO $$ BEGIN PERFORM 1; END $$;"
    assert _checksum_sql(sql) == _sha256_hex(sql)


def test_checksum_sql_differs_on_edit() -> None:
    a = "SELECT 1;"
    b = "SELECT 2;"
    assert _checksum_sql(a) != _checksum_sql(b)


# ---------------------------------------------------------------------
# 2. verify_checksums_enabled() env-toggle resolution
# ---------------------------------------------------------------------


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_MIGRATION_VERIFY_CHECKSUMS", raising=False)


def test_verify_default_disabled_in_nonprod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    _clear_env(monkeypatch)
    assert verify_checksums_enabled() is False


def test_verify_default_enabled_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    _clear_env(monkeypatch)
    assert verify_checksums_enabled() is True


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "  On  "])
def test_verify_truthy_value_enables_in_nonprod(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ANCHOR_MIGRATION_VERIFY_CHECKSUMS", value)
    assert verify_checksums_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE", "  No  "])
def test_verify_falsy_value_disables_in_prod(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_MIGRATION_VERIFY_CHECKSUMS", value)
    # Operator override is allowed.
    assert verify_checksums_enabled() is False


def test_verify_unknown_value_fail_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_MIGRATION_VERIFY_CHECKSUMS", "yolo")
    with pytest.raises(RuntimeError, match="not a recognised boolean"):
        verify_checksums_enabled()


def test_verify_unknown_value_defensive_in_nonprod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ANCHOR_MIGRATION_VERIFY_CHECKSUMS", "yolo")
    # Non-prod must not raise; defensive fallback is False.
    assert verify_checksums_enabled() is False


# ---------------------------------------------------------------------
# 3. _verify_existing_checksum behaviour
# ---------------------------------------------------------------------


def test_verify_no_column_returns_no_column_sentinel() -> None:
    session = _StubSession(has_checksum_column=False)
    result = _verify_existing_checksum(
        session, filename="10001.sql", expected_checksum="deadbeef"
    )
    assert result == "no_column"
    # Only the column probe should have run; no SELECT checksum issued.
    assert all(
        "SELECT checksum FROM public.schema_migrations" not in sql
        for sql, _ in session.calls
    )


def test_verify_no_row_returns_no_row_sentinel() -> None:
    session = _StubSession(
        has_checksum_column=True, existing_checksum_row=False
    )
    result = _verify_existing_checksum(
        session, filename="10001.sql", expected_checksum="deadbeef"
    )
    assert result == "no_row"


def test_verify_match_returns_match() -> None:
    session = _StubSession(
        has_checksum_column=True,
        existing_checksum_row=True,
        existing_checksum_value="deadbeef",
    )
    result = _verify_existing_checksum(
        session, filename="10001.sql", expected_checksum="deadbeef"
    )
    assert result == "match"
    # No UPDATE issued on a match.
    assert all(
        "UPDATE public.schema_migrations" not in sql for sql, _ in session.calls
    )


def test_verify_null_checksum_backfills_with_update() -> None:
    session = _StubSession(
        has_checksum_column=True,
        existing_checksum_row=True,
        existing_checksum_value=None,
    )
    result = _verify_existing_checksum(
        session, filename="10001.sql", expected_checksum="deadbeef"
    )
    assert result == "backfilled"

    updates = [
        (sql, params)
        for sql, params in session.calls
        if "UPDATE public.schema_migrations" in sql
    ]
    assert len(updates) == 1
    update_sql, update_params = updates[0]
    assert "SET checksum = :c" in update_sql
    assert "checksum IS NULL" in update_sql
    assert update_params["f"] == "10001.sql"
    assert update_params["c"] == "deadbeef"


def test_verify_mismatch_raises_and_does_not_overwrite() -> None:
    session = _StubSession(
        has_checksum_column=True,
        existing_checksum_row=True,
        existing_checksum_value="cafefade",  # stored
    )
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        _verify_existing_checksum(
            session, filename="10001.sql", expected_checksum="deadbeef"
        )
    # No UPDATE issued on mismatch — forensic state preserved.
    assert all(
        "UPDATE public.schema_migrations" not in sql for sql, _ in session.calls
    )


# ---------------------------------------------------------------------
# 4. _list_sql_files is non-recursive
# ---------------------------------------------------------------------


def test_list_sql_files_returns_only_top_level_sql(tmp_path: Path) -> None:
    top = tmp_path / "migrations"
    top.mkdir()
    (top / "10000_a.sql").write_text("-- top a")
    (top / "10001_b.sql").write_text("-- top b")
    nested = top / "nested"
    nested.mkdir()
    (nested / "9999_stray.sql").write_text("-- stray")

    found = _list_sql_files(top)
    found_names = {p.name for p in found}
    assert found_names == {"10000_a.sql", "10001_b.sql"}
    assert "9999_stray.sql" not in found_names


def test_no_nested_sql_files_under_migrations_directory() -> None:
    """Regression guard: a `.sql` file under a subdirectory of
    `migrations/` would silently be ignored by the runner. Patch 6
    removed the historical nested `migrations/migrations/` directory;
    ensure no equivalent regression is reintroduced."""
    nested_sql = [
        p
        for p in MIGRATIONS_DIR.rglob("*.sql")
        if p.parent != MIGRATIONS_DIR
    ]
    assert nested_sql == [], (
        f"Found nested .sql files (runner is non-recursive): {nested_sql}"
    )


# ---------------------------------------------------------------------
# 5. Migration 10016 file inspection
# ---------------------------------------------------------------------


def test_migration_10016_exists() -> None:
    assert CHECKSUM_MIGRATION.is_file(), (
        f"Expected migration file at {CHECKSUM_MIGRATION!s}"
    )


def test_migration_10016_adds_checksum_column_idempotently() -> None:
    sql = CHECKSUM_MIGRATION.read_text(encoding="utf-8")
    # Must use IF NOT EXISTS so re-application on a DB that already has
    # the column (operator-applied schemas) is safe.
    pattern = re.compile(
        r"ALTER\s+TABLE\s+public\.schema_migrations\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+checksum\s+text",
        re.IGNORECASE,
    )
    assert pattern.search(sql), (
        "Expected ALTER TABLE public.schema_migrations ADD COLUMN IF NOT EXISTS checksum text"
    )


def test_migration_10016_is_wrapped_in_a_transaction() -> None:
    sql = CHECKSUM_MIGRATION.read_text(encoding="utf-8")
    assert re.search(r"^\s*BEGIN\s*;", sql, re.IGNORECASE | re.MULTILINE)
    assert re.search(r"^\s*COMMIT\s*;", sql, re.IGNORECASE | re.MULTILINE)


def test_migration_10016_does_not_set_not_null_or_default() -> None:
    """Older applied rows pre-date this migration and must be allowed
    to carry NULL until the runner backfills them on next boot."""
    sql = CHECKSUM_MIGRATION.read_text(encoding="utf-8").upper()
    # Defensive — the migration must NOT mention NOT NULL on the
    # checksum column or set a DEFAULT that would clobber backfill.
    # (We allow the strings to appear in comments, but not in DDL.
    # Stripping comments is overkill; a substring veto is sufficient
    # given the migration body's small size.)
    code_lines = [
        line for line in sql.splitlines() if not line.strip().startswith("--")
    ]
    code = "\n".join(code_lines)
    assert "CHECKSUM TEXT NOT NULL" not in code
    assert "ALTER COLUMN CHECKSUM SET NOT NULL" not in code
    assert "ALTER COLUMN CHECKSUM SET DEFAULT" not in code
