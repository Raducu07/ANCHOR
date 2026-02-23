# app/governance_config.py
#
# Ready for deploy (copy/paste).
#
# Updates applied (from our discussion):
# - Ensures policy writes are durable by supporting optional commit (commit=True) and safe rollback.
# - Adds small validation/normalization helpers (prevents weird JSON shapes).
# - Keeps tiny in-process cache (TTL) but makes it thread-safe with a lock.
# - Provides a "get_policy_by_id" helper for clean endpoint responses if you want it later.
#
# NOTE: If you already commit in your endpoint, leave commit=False (default).
#       If you want this module to be "safe by default", call create_new_policy(..., commit=True).

import json
import time
import uuid
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy import text


@dataclass
class GovernancePolicy:
    id: uuid.UUID
    policy_version: str
    neutrality_version: str
    min_score_allow: int
    hard_block_rules: List[str]
    soft_rules: List[str]
    max_findings: int
    updated_at: str


# ---------------------------
# Tiny in-process cache (TTL)
# ---------------------------

_CACHE_LOCK = threading.Lock()
_CACHE: Dict[str, Any] = {"ts": 0, "policy": None}
CACHE_TTL_SECONDS = 10


def _as_list(value: Any, default: List[str]) -> List[str]:
    """
    Normalize JSON-ish values to a list[str].
    Accepts list, JSON string, JSONB, etc. Falls back to default.
    """
    try:
        if value is None:
            return list(default)
        if isinstance(value, list):
            return [str(x) for x in value]
        if isinstance(value, str):
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        # SQLAlchemy may return tuples in some weird cases; treat as list-like
        if isinstance(value, tuple):
            return [str(x) for x in value]
        return list(default)
    except Exception:
        return list(default)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _row_to_policy(row) -> GovernancePolicy:
    # row is a SQLAlchemy row (tuple-like)
    updated = row[7]
    updated_iso = updated.isoformat() if updated is not None and hasattr(updated, "isoformat") else ""
    return GovernancePolicy(
        id=uuid.UUID(str(row[0])),
        policy_version=str(row[1]),
        neutrality_version=str(row[2]),
        min_score_allow=_as_int(row[3], 75),
        hard_block_rules=_as_list(row[4], ["jailbreak", "therapy", "promise"]),
        soft_rules=_as_list(row[5], ["direct_advice", "coercion"]),
        max_findings=_as_int(row[6], 10),
        updated_at=updated_iso,
    )


def _default_policy() -> GovernancePolicy:
    # Defensive defaults (should rarely be used because schema seeds governance_config)
    return GovernancePolicy(
        id=uuid.uuid4(),
        policy_version="gov-v1.0",
        neutrality_version="n-v1.1",
        min_score_allow=75,
        hard_block_rules=["jailbreak", "therapy", "promise"],
        soft_rules=["direct_advice", "coercion"],
        max_findings=10,
        updated_at="",
    )


def get_current_policy(db, *, use_cache: bool = True) -> GovernancePolicy:
    """
    Returns the most recently updated policy row.
    Safe defaults if DB row has unexpected shapes.
    """
    now = int(time.time())

    if use_cache:
        with _CACHE_LOCK:
            cached = _CACHE.get("policy")
            ts = int(_CACHE.get("ts") or 0)
            if cached is not None and (now - ts) <= CACHE_TTL_SECONDS:
                return cached

    row = db.execute(
        text(
            """
            SELECT
              id,
              policy_version,
              neutrality_version,
              min_score_allow,
              hard_block_rules,
              soft_rules,
              max_findings,
              updated_at
            FROM governance_config
            ORDER BY updated_at DESC
            LIMIT 1
            """
        )
    ).fetchone()

    if not row:
        pol = _default_policy()
        with _CACHE_LOCK:
            _CACHE["ts"] = now
            _CACHE["policy"] = pol
        return pol

    pol = _row_to_policy(row)
    with _CACHE_LOCK:
        _CACHE["ts"] = now
        _CACHE["policy"] = pol
    return pol


def list_policy_history(db, limit: int = 50) -> List[GovernancePolicy]:
    limit = max(1, min(200, int(limit)))
    rows = db.execute(
        text(
            """
            SELECT
              id,
              policy_version,
              neutrality_version,
              min_score_allow,
              hard_block_rules,
              soft_rules,
              max_findings,
              updated_at
            FROM governance_config
            ORDER BY updated_at DESC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).fetchall()

    out: List[GovernancePolicy] = []
    for r in rows:
        out.append(_row_to_policy(r))
    return out


def get_policy_by_id(db, policy_id: uuid.UUID) -> Optional[GovernancePolicy]:
    """
    Convenience helper if you ever want to fetch the policy you just inserted by its id.
    Returns None if not found.
    """
    row = db.execute(
        text(
            """
            SELECT
              id,
              policy_version,
              neutrality_version,
              min_score_allow,
              hard_block_rules,
              soft_rules,
              max_findings,
              updated_at
            FROM governance_config
            WHERE id = :id
            LIMIT 1
            """
        ),
        {"id": str(policy_id)},
    ).fetchone()

    if not row:
        return None
    return _row_to_policy(row)


def bust_policy_cache() -> None:
    """
    Explicit cache bust (useful after admin updates).
    """
    with _CACHE_LOCK:
        _CACHE["ts"] = 0
        _CACHE["policy"] = None


def create_new_policy(
    db,
    *,
    policy_version: str,
    neutrality_version: str,
    min_score_allow: int,
    hard_block_rules: List[str],
    soft_rules: List[str],
    max_findings: int,
    commit: bool = False,
) -> GovernancePolicy:
    """
    Inserts a new policy row (append-only).
    The active policy is always the most recent by updated_at.

    Transaction semantics:
      - If commit=False (default): caller must db.commit()
      - If commit=True: this function commits and rolls back on error.

    Returns:
      - The (new) current policy (read back with use_cache=False).
    """
    pid = uuid.uuid4()

    # Normalize inputs
    policy_version = (policy_version or "").strip() or "gov-v1.0"
    neutrality_version = (neutrality_version or "").strip() or "n-v1.1"
    min_score_allow = int(min_score_allow)
    max_findings = int(max_findings)

    hbr = [str(x).strip() for x in (hard_block_rules or []) if str(x).strip()]
    sft = [str(x).strip() for x in (soft_rules or []) if str(x).strip()]

    try:
        db.execute(
            text(
                """
                INSERT INTO governance_config (
                  id,
                  policy_version,
                  neutrality_version,
                  min_score_allow,
                  hard_block_rules,
                  soft_rules,
                  max_findings,
                  updated_at
                )
                VALUES (
                  :id,
                  :policy_version,
                  :neutrality_version,
                  :min_score_allow,
                  CAST(:hard_block_rules AS jsonb),
                  CAST(:soft_rules AS jsonb),
                  :max_findings,
                  NOW()
                )
                """
            ),
            {
                "id": str(pid),
                "policy_version": policy_version,
                "neutrality_version": neutrality_version,
                "min_score_allow": min_score_allow,
                "hard_block_rules": json.dumps(hbr),
                "soft_rules": json.dumps(sft),
                "max_findings": max_findings,
            },
        )

        if commit:
            db.commit()

        bust_policy_cache()

        # Return current (read-your-writes works inside same tx; after commit also fine)
        return get_current_policy(db, use_cache=False)

    except Exception:
        if commit:
            try:
                db.rollback()
            except Exception:
                pass
        # Ensure cache isn't stuck in a bad state
        bust_policy_cache()
        raise
