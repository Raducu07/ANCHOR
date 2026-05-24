# app/assistant_policy.py
#
# M6.7 — Clinic-scoped Assistant policy / settings.
#
# Doctrine recap:
#   * Operational toggles are tunable per clinic (validation profile, limits,
#     whether generation / client_communication is enabled, display copy).
#   * Hard safety guarantees are NOT tunable. `require_human_review` and
#     `allow_receipts_after_review` are pinned to True at both the app and
#     DB layers; any attempt to set them False is rejected.
#   * The validator is never disabled. `validation_profile='off'` is not a
#     legal value.
#
# Versioning:
#   * Each update inserts a new (clinic_id, policy_version) row.
#   * Only one row per clinic may have is_active=true (partial unique idx).
#   * The previous active row is flipped is_active=false, superseded_at=now()
#     by the app inside the same transaction as the new INSERT.
from __future__ import annotations

import json
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.assistant_usage_limits import daily_run_limit as env_daily_run_limit
from app.assistant_usage_limits import monthly_run_limit as env_monthly_run_limit


VALIDATION_PROFILE_STANDARD = "standard"
VALIDATION_PROFILE_CONSERVATIVE = "conservative"
ALLOWED_VALIDATION_PROFILES = {
    VALIDATION_PROFILE_STANDARD,
    VALIDATION_PROFILE_CONSERVATIVE,
}

DEFAULT_POLICY_LABEL = "Default Assistant Policy"


# Fields the PATCH endpoint accepts. Any other key in the request body is
# rejected with 400 (assistant_policy_field_not_allowed).
ALLOWED_PATCH_FIELDS = {
    "client_communication_enabled",
    "generation_enabled",
    "validation_profile",
    "daily_run_limit_per_clinic",
    "monthly_run_limit_per_clinic",
    "policy_label",
    "policy_notes",
}

# Hard-doctrine fields — explicitly forbidden in PATCH bodies even though
# the request model technically allows extras, to give a clear error code.
FORBIDDEN_PATCH_FIELDS = {
    "require_human_review",
    "allow_receipts_after_review",
}


@dataclass(frozen=True)
class AssistantPolicy:
    """Effective Assistant policy. Returned by `get_effective_policy()`.

    When no DB row exists, this is the safe default derived from env-level
    PR 2D defaults; in that case `id`, `created_at`, etc. are None and
    `policy_version` is 0 (the "default-before-any-update" sentinel).
    """

    id: Optional[_uuid.UUID]
    clinic_id: Optional[_uuid.UUID]
    policy_version: int
    is_active: bool
    is_default: bool

    client_communication_enabled: bool
    generation_enabled: bool
    validation_profile: str

    daily_run_limit_per_clinic: int
    monthly_run_limit_per_clinic: int

    require_human_review: bool
    allow_receipts_after_review: bool

    policy_label: str
    policy_notes: Optional[str]

    created_by_user_id: Optional[_uuid.UUID]
    created_at: Optional[datetime]
    activated_at: Optional[datetime]


def _row_to_policy(row: Dict[str, Any]) -> AssistantPolicy:
    return AssistantPolicy(
        id=row["id"],
        clinic_id=row["clinic_id"],
        policy_version=int(row["policy_version"]),
        is_active=bool(row["is_active"]),
        is_default=False,
        client_communication_enabled=bool(row["client_communication_enabled"]),
        generation_enabled=bool(row["generation_enabled"]),
        validation_profile=str(row["validation_profile"]),
        daily_run_limit_per_clinic=int(row["daily_run_limit_per_clinic"]),
        monthly_run_limit_per_clinic=int(row["monthly_run_limit_per_clinic"]),
        require_human_review=bool(row["require_human_review"]),
        allow_receipts_after_review=bool(row["allow_receipts_after_review"]),
        policy_label=str(row["policy_label"]),
        policy_notes=row.get("policy_notes"),
        created_by_user_id=row.get("created_by_user_id"),
        created_at=row.get("created_at"),
        activated_at=row.get("activated_at"),
    )


def _default_policy(clinic_id: Optional[str] = None) -> AssistantPolicy:
    """Safe default. Used when a clinic has no assistant_policy_settings
    row yet (and we deliberately do NOT lazily insert one on read)."""
    return AssistantPolicy(
        id=None,
        clinic_id=_uuid.UUID(clinic_id) if clinic_id else None,
        policy_version=0,
        is_active=False,
        is_default=True,
        client_communication_enabled=True,
        generation_enabled=True,
        validation_profile=VALIDATION_PROFILE_STANDARD,
        daily_run_limit_per_clinic=env_daily_run_limit(),
        monthly_run_limit_per_clinic=env_monthly_run_limit(),
        require_human_review=True,
        allow_receipts_after_review=True,
        policy_label=DEFAULT_POLICY_LABEL,
        policy_notes=None,
        created_by_user_id=None,
        created_at=None,
        activated_at=None,
    )


_SELECT_COLUMNS = """
    id,
    clinic_id,
    policy_version,
    is_active,
    client_communication_enabled,
    generation_enabled,
    validation_profile,
    daily_run_limit_per_clinic,
    monthly_run_limit_per_clinic,
    require_human_review,
    allow_receipts_after_review,
    policy_label,
    policy_notes,
    created_by_user_id,
    created_at,
    activated_at,
    superseded_at
"""


def get_active_policy_row(db: Session, *, clinic_id: str) -> Optional[Dict[str, Any]]:
    """Return raw row dict for the clinic's active policy, or None."""
    row = (
        db.execute(
            text(
                f"""
                SELECT {_SELECT_COLUMNS}
                FROM assistant_policy_settings
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                  AND is_active = true
                LIMIT 1
                """
            ),
            {"clinic_id": clinic_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def get_effective_policy(db: Session, *, clinic_id: str) -> AssistantPolicy:
    """Return the active policy if present, else the safe default. Never
    raises and never silently mutates the DB."""
    row = get_active_policy_row(db, clinic_id=clinic_id)
    if row is None:
        return _default_policy(clinic_id=clinic_id)
    return _row_to_policy(row)


def get_policy_history_rows(
    db: Session, *, clinic_id: str, limit: int
) -> List[Dict[str, Any]]:
    rows = (
        db.execute(
            text(
                f"""
                SELECT {_SELECT_COLUMNS}
                FROM assistant_policy_settings
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                ORDER BY policy_version DESC
                LIMIT :limit
                """
            ),
            {"clinic_id": clinic_id, "limit": int(limit)},
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


def _max_policy_version(db: Session, *, clinic_id: str) -> int:
    row = (
        db.execute(
            text(
                """
                SELECT COALESCE(MAX(policy_version), 0) AS v
                FROM assistant_policy_settings
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                """
            ),
            {"clinic_id": clinic_id},
        )
        .mappings()
        .first()
    )
    return int((row or {}).get("v") or 0)


def deactivate_active_policies(db: Session, *, clinic_id: str) -> None:
    db.execute(
        text(
            """
            UPDATE assistant_policy_settings
            SET is_active = false,
                superseded_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND is_active = true
            """
        ),
        {"clinic_id": clinic_id},
    )


def insert_new_policy_version(
    db: Session,
    *,
    clinic_id: str,
    created_by_user_id: str,
    policy_version: int,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """Insert a new policy row, return the persisted row dict."""
    row = (
        db.execute(
            text(
                f"""
                INSERT INTO assistant_policy_settings (
                    clinic_id,
                    policy_version,
                    is_active,
                    client_communication_enabled,
                    generation_enabled,
                    validation_profile,
                    daily_run_limit_per_clinic,
                    monthly_run_limit_per_clinic,
                    require_human_review,
                    allow_receipts_after_review,
                    policy_label,
                    policy_notes,
                    created_by_user_id,
                    activated_at
                )
                VALUES (
                    CAST(:clinic_id AS uuid),
                    :policy_version,
                    true,
                    :client_communication_enabled,
                    :generation_enabled,
                    :validation_profile,
                    :daily_run_limit_per_clinic,
                    :monthly_run_limit_per_clinic,
                    true,
                    true,
                    :policy_label,
                    :policy_notes,
                    CAST(:created_by_user_id AS uuid),
                    now()
                )
                RETURNING {_SELECT_COLUMNS}
                """
            ),
            {
                "clinic_id": clinic_id,
                "policy_version": int(policy_version),
                "client_communication_enabled": bool(settings["client_communication_enabled"]),
                "generation_enabled": bool(settings["generation_enabled"]),
                "validation_profile": str(settings["validation_profile"]),
                "daily_run_limit_per_clinic": int(settings["daily_run_limit_per_clinic"]),
                "monthly_run_limit_per_clinic": int(settings["monthly_run_limit_per_clinic"]),
                "policy_label": str(settings["policy_label"]),
                "policy_notes": settings.get("policy_notes"),
                "created_by_user_id": created_by_user_id,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise RuntimeError("assistant_policy_settings insert returned no row")
    return dict(row)


def insert_policy_audit_event(
    db: Session,
    *,
    clinic_id: str,
    admin_user_id: str,
    previous_policy_version: int,
    new_policy_version: int,
    changed_fields: List[str],
    ip_hash: Optional[str] = None,
) -> None:
    """Metadata-only entry in the existing admin_audit_events table.

    Mirrors the shape used by portal_submit.override_submission, with
    DB-enforced idempotency: re-applying the same (clinic, action,
    new_policy_version) is a no-op."""
    idempotency_key = (
        f"assistant_policy_updated:{clinic_id}:{new_policy_version}"
    )
    meta = {
        "previous_policy_version": int(previous_policy_version),
        "new_policy_version": int(new_policy_version),
        "changed_fields": sorted(set(changed_fields)),
    }
    db.execute(
        text(
            """
            INSERT INTO admin_audit_events (
                clinic_id,
                admin_user_id,
                action,
                target_id,
                ip_hash,
                meta,
                idempotency_key
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:admin_user_id AS uuid),
                :action,
                NULL,
                :ip_hash,
                CAST(:meta AS jsonb),
                :idempotency_key
            )
            ON CONFLICT (clinic_id, action, idempotency_key)
            DO NOTHING
            """
        ),
        {
            "clinic_id": clinic_id,
            "admin_user_id": admin_user_id,
            "action": "assistant_policy_updated",
            "ip_hash": ip_hash,
            "meta": json.dumps(meta),
            "idempotency_key": idempotency_key,
        },
    )
