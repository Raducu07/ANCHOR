"""TD-BE — SQL-level regression for portal_submit.SQL_INSERT_OVERRIDE_AUDIT.

Background:
  M6.10.1 production fix removed a partial-index `ON CONFLICT` from
  insert_policy_audit_event. The same bug shape existed in
  `portal_submit.SQL_INSERT_OVERRIDE_AUDIT`:

      ON CONFLICT (clinic_id, action, idempotency_key) DO NOTHING

  The matching unique index in app/schema.sql is partial:

      CREATE UNIQUE INDEX admin_audit_events_idem_uq
        ON admin_audit_events (clinic_id, action, idempotency_key)
        WHERE idempotency_key IS NOT NULL;

  Postgres requires the partial-index predicate to be repeated in the
  ON CONFLICT target for inference, otherwise it raises
  `InvalidColumnReference: there is no unique or exclusion constraint
  matching the ON CONFLICT specification` at runtime. FakeDB-based
  tests cannot catch this because they don't parse SQL, so we assert
  on the raw SQL string constant here.
"""
from __future__ import annotations


def _sql_text() -> str:
    from app.portal_submit import SQL_INSERT_OVERRIDE_AUDIT
    return str(SQL_INSERT_OVERRIDE_AUDIT.text)


def test_override_audit_sql_inserts_into_admin_audit_events() -> None:
    sql = _sql_text()
    assert "INSERT INTO admin_audit_events" in sql


def test_override_audit_sql_has_no_unsafe_partial_index_on_conflict() -> None:
    """If ON CONFLICT is ever re-introduced against the partial
    admin_audit_events_idem_uq index, it MUST include the WHERE
    predicate; otherwise prod 500s. Currently the statement is
    append-only — no ON CONFLICT at all."""
    sql = _sql_text()
    if "ON CONFLICT" in sql.upper():
        assert "idempotency_key IS NOT NULL" in sql, (
            "ON CONFLICT against admin_audit_events_idem_uq must repeat "
            "the partial-index WHERE predicate (idempotency_key IS NOT NULL)."
        )
    else:
        # Append-only path: explicitly assert the broken target is gone.
        assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in sql


def test_override_audit_sql_preserves_forensic_columns() -> None:
    """Removing ON CONFLICT must not drop useful audit metadata columns."""
    sql = _sql_text()
    for col in (
        "clinic_id",
        "admin_user_id",
        "action",
        "target_id",
        "ip_hash",
        "meta",
        "idempotency_key",
    ):
        assert col in sql, f"missing audit column: {col}"
    # Still returns the event_id so the route can verify the insert.
    assert "RETURNING event_id" in sql


def test_override_audit_sql_does_not_reference_raw_content_fields() -> None:
    """Audit insert must remain metadata-only. No prompt/output/draft/
    transcript columns should appear in the SQL."""
    sql = _sql_text().lower()
    for marker in ("prompt", "draft", "output_text", "input_text", "transcript", "raw_content"):
        assert marker not in sql, f"forbidden raw-content marker in audit SQL: {marker}"

