# app/assistant_intelligence.py
#
# M6.8 — Assistant analytics, derived from existing metadata-only
# assistant_runs evidence. Doctrine recap:
#   * Reads NEVER touch raw content (none exists on the table).
#   * Reads only count, group, and rate-shape existing metadata fields.
#   * Output is governance evidence, not clinical judgement.
#   * Clinic tenancy + RLS apply at the DB session layer; queries also
#     include explicit clinic_id predicates for clarity / index use.
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.assistant_policy import (
    VALIDATION_PROFILE_STANDARD,
    get_active_policy_row,
)
from app.assistant_usage_limits import (
    daily_run_limit as env_daily_run_limit,
    get_assistant_run_counts,
    monthly_run_limit as env_monthly_run_limit,
)


GOVERNANCE_NOTE = (
    "Assistant intelligence uses metadata only. No raw prompt, input, "
    "draft, transcript, or clinical content is analysed or stored."
)


def _safe_div(n: float, d: float) -> float:
    if not d:
        return 0.0
    return float(n) / float(d)


def _round(value: float, places: int = 4) -> float:
    return round(float(value), places)


def _window_bounds(*, now: Optional[datetime] = None, days: int = 30) -> Dict[str, Any]:
    end_at = now or datetime.now(timezone.utc)
    start_at = end_at - timedelta(days=int(days))
    return {
        "days": int(days),
        "start_at": start_at,
        "end_at": end_at,
    }


# ---------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------

_SUMMARY_COUNTS_SQL = """
SELECT
    COUNT(*) AS total_runs,

    COUNT(*) FILTER (WHERE run_status = 'generation_succeeded')
        AS draft_generated,
    COUNT(*) FILTER (WHERE run_status = 'generation_refused')
        AS refused_before_model_call,
    COUNT(*) FILTER (WHERE run_status = 'output_blocked')
        AS output_blocked,
    COUNT(*) FILTER (WHERE run_status = 'generation_failed')
        AS generation_failed,

    COUNT(*) FILTER (
        WHERE refusal_reason_codes ? 'generation_disabled_by_policy'
    ) AS generation_disabled_by_policy,

    COUNT(*) FILTER (WHERE pii_detected = true) AS pii_detected,

    COUNT(*) FILTER (WHERE review_status IS NOT NULL AND review_status <> 'not_reviewed')
        AS reviewed,
    COUNT(*) FILTER (WHERE review_status = 'reviewed_approved') AS approved,
    COUNT(*) FILTER (WHERE review_status = 'reviewed_needs_edit') AS needs_edit,
    COUNT(*) FILTER (WHERE review_status = 'reviewed_rejected') AS rejected,

    COUNT(*) FILTER (WHERE receipt_id IS NOT NULL) AS receipt_linked,

    COUNT(*) FILTER (WHERE assistant_policy_id IS NULL) AS default_policy_runs,
    COUNT(*) FILTER (WHERE assistant_policy_id IS NOT NULL) AS policy_versioned_runs
FROM assistant_runs
WHERE clinic_id = CAST(:clinic_id AS uuid)
  AND created_at >= :start_at
  AND created_at <  :end_at
"""


_TOP_REFUSAL_REASONS_SQL = """
SELECT code, COUNT(*) AS c
FROM (
    SELECT jsonb_array_elements_text(refusal_reason_codes) AS code
    FROM assistant_runs
    WHERE clinic_id = CAST(:clinic_id AS uuid)
      AND created_at >= :start_at
      AND created_at <  :end_at
) AS codes
GROUP BY code
ORDER BY c DESC, code ASC
LIMIT :limit
"""


_TOP_SAFETY_FLAGS_SQL = """
SELECT code, COUNT(*) AS c
FROM (
    SELECT jsonb_array_elements_text(safety_flags) AS code
    FROM assistant_runs
    WHERE clinic_id = CAST(:clinic_id AS uuid)
      AND created_at >= :start_at
      AND created_at <  :end_at
) AS codes
GROUP BY code
ORDER BY c DESC, code ASC
LIMIT :limit
"""


_BY_VALIDATION_PROFILE_SQL = """
SELECT
    COALESCE(assistant_validation_profile, :default_profile) AS validation_profile,
    COUNT(*) AS c
FROM assistant_runs
WHERE clinic_id = CAST(:clinic_id AS uuid)
  AND created_at >= :start_at
  AND created_at <  :end_at
GROUP BY validation_profile
ORDER BY c DESC, validation_profile ASC
"""


def _fetch_summary_counts(
    db: Session,
    *,
    clinic_id: str,
    start_at: datetime,
    end_at: datetime,
) -> Dict[str, int]:
    row = (
        db.execute(
            text(_SUMMARY_COUNTS_SQL),
            {"clinic_id": clinic_id, "start_at": start_at, "end_at": end_at},
        )
        .mappings()
        .first()
    )
    if not row:
        # Defensive empty-state shape.
        return {
            "total_runs": 0,
            "draft_generated": 0,
            "refused_before_model_call": 0,
            "output_blocked": 0,
            "generation_failed": 0,
            "generation_disabled_by_policy": 0,
            "pii_detected": 0,
            "reviewed": 0,
            "approved": 0,
            "needs_edit": 0,
            "rejected": 0,
            "receipt_linked": 0,
            "default_policy_runs": 0,
            "policy_versioned_runs": 0,
        }
    return {k: int(row.get(k) or 0) for k in (
        "total_runs",
        "draft_generated",
        "refused_before_model_call",
        "output_blocked",
        "generation_failed",
        "generation_disabled_by_policy",
        "pii_detected",
        "reviewed",
        "approved",
        "needs_edit",
        "rejected",
        "receipt_linked",
        "default_policy_runs",
        "policy_versioned_runs",
    )}


def _fetch_code_counts(
    db: Session,
    *,
    sql: str,
    clinic_id: str,
    start_at: datetime,
    end_at: datetime,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    rows = (
        db.execute(
            text(sql),
            {
                "clinic_id": clinic_id,
                "start_at": start_at,
                "end_at": end_at,
                "limit": int(limit),
            },
        )
        .mappings()
        .all()
    )
    return [{"code": str(r["code"]), "count": int(r["c"])} for r in rows]


def _fetch_by_validation_profile(
    db: Session,
    *,
    clinic_id: str,
    start_at: datetime,
    end_at: datetime,
) -> List[Dict[str, Any]]:
    rows = (
        db.execute(
            text(_BY_VALIDATION_PROFILE_SQL),
            {
                "clinic_id": clinic_id,
                "start_at": start_at,
                "end_at": end_at,
                "default_profile": VALIDATION_PROFILE_STANDARD,
            },
        )
        .mappings()
        .all()
    )
    return [
        {"validation_profile": str(r["validation_profile"]), "count": int(r["c"])}
        for r in rows
    ]


# ---------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------

def build_assistant_intelligence_summary(
    db: Session,
    *,
    clinic_id: str,
    days: int = 30,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Aggregate metadata-only Assistant signals for `clinic_id` over the
    last `days` days. Never touches raw content."""
    bounds = _window_bounds(now=now, days=days)
    start_at: datetime = bounds["start_at"]
    end_at: datetime = bounds["end_at"]

    counts = _fetch_summary_counts(
        db, clinic_id=clinic_id, start_at=start_at, end_at=end_at
    )

    top_refusal = _fetch_code_counts(
        db,
        sql=_TOP_REFUSAL_REASONS_SQL,
        clinic_id=clinic_id,
        start_at=start_at,
        end_at=end_at,
        limit=10,
    )
    top_safety = _fetch_code_counts(
        db,
        sql=_TOP_SAFETY_FLAGS_SQL,
        clinic_id=clinic_id,
        start_at=start_at,
        end_at=end_at,
        limit=10,
    )

    by_profile = _fetch_by_validation_profile(
        db, clinic_id=clinic_id, start_at=start_at, end_at=end_at
    )

    # by_status / by_review_status derived from counts so the wire shape
    # always lists the canonical statuses (zeroed when empty).
    by_status = [
        {"status": "draft_generated", "count": counts["draft_generated"]},
        {"status": "refused_before_model_call", "count": counts["refused_before_model_call"]},
        {"status": "output_blocked", "count": counts["output_blocked"]},
        {"status": "generation_failed", "count": counts["generation_failed"]},
    ]
    by_review_status = [
        {"status": "approved", "count": counts["approved"]},
        {"status": "needs_edit", "count": counts["needs_edit"]},
        {"status": "rejected", "count": counts["rejected"]},
        {
            "status": "not_reviewed",
            "count": max(
                0, counts["total_runs"] - counts["reviewed"]
            ),
        },
    ]

    total = counts["total_runs"]
    rates = {
        "draft_generated_rate": _round(_safe_div(counts["draft_generated"], total)),
        # Refusal rate aggregates "the model was not allowed to produce a
        # returned draft for this run" — input refusals + output blocks.
        "refusal_rate": _round(
            _safe_div(
                counts["refused_before_model_call"] + counts["output_blocked"],
                total,
            )
        ),
        "output_blocked_rate": _round(_safe_div(counts["output_blocked"], total)),
        "pii_detected_rate": _round(_safe_div(counts["pii_detected"], total)),
        "review_completion_rate": _round(_safe_div(counts["reviewed"], total)),
        "receipt_completion_rate": _round(_safe_div(counts["receipt_linked"], total)),
        "approval_rate_among_reviewed": _round(
            _safe_div(counts["approved"], counts["reviewed"])
        ),
    }

    funnel = {
        "submitted": total,
        "generated_or_refused_or_blocked": (
            counts["draft_generated"]
            + counts["refused_before_model_call"]
            + counts["output_blocked"]
        ),
        "reviewed": counts["reviewed"],
        "receipt_created": counts["receipt_linked"],
    }

    # Usage limits: prefer active policy, fall back to env defaults.
    policy_row = get_active_policy_row(db, clinic_id=clinic_id)
    if policy_row is not None:
        daily_limit = int(policy_row["daily_run_limit_per_clinic"])
        monthly_limit = int(policy_row["monthly_run_limit_per_clinic"])
        usage_source = "assistant_policy"
    else:
        daily_limit = env_daily_run_limit()
        monthly_limit = env_monthly_run_limit()
        usage_source = "default"

    runs_today, runs_this_month = get_assistant_run_counts(
        db, clinic_id=clinic_id, now=end_at
    )

    usage_limits = {
        "daily_limit_per_clinic": daily_limit,
        "monthly_limit_per_clinic": monthly_limit,
        "runs_today": int(runs_today),
        "runs_this_month": int(runs_this_month),
        "daily_utilization_rate": _round(_safe_div(runs_today, daily_limit)),
        "monthly_utilization_rate": _round(_safe_div(runs_this_month, monthly_limit)),
        "source": usage_source,
    }

    return {
        "window": {
            "days": int(days),
            "start_at": start_at.isoformat(),
            "end_at": end_at.isoformat(),
        },
        "summary": counts,
        "rates": rates,
        "funnel": funnel,
        "top_refusal_reasons": top_refusal,
        "top_safety_flags": top_safety,
        "by_status": by_status,
        "by_review_status": by_review_status,
        "by_validation_profile": by_profile,
        "usage_limits": usage_limits,
        "governance_note": GOVERNANCE_NOTE,
    }
