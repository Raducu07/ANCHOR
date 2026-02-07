# app/governance_config.py
import json
import time
import uuid
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

_CACHE: Dict[str, Any] = {"ts": 0, "policy": None}
CACHE_TTL_SECONDS = 10


def _as_list(value: Any, default: List[str]) -> List[str]:
    try:
        if value is None:
            return default
        if isinstance(value, list):
            return [str(x) for x in value]
        # sometimes JSONB can come as string
        if isinstance(value, str):
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        return default
    except Exception:
        return default


def get_current_policy(db, *, use_cache: bool = True) -> GovernancePolicy:
    """
    Returns the most recently updated policy row.
    Safe defaults if DB row has unexpected shapes.
    """
    now = int(time.time())
    if use_cache and _CACHE["policy"] is not None and (now - int(_CACHE["ts"])) <= CACHE_TTL_SECONDS:
        return _CACHE["policy"]

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
        # Should never happen due to schema seed, but keep it safe.
        pol = GovernancePolicy(
            id=uuid.uuid4(),
            policy_version="gov-v1.0",
            neutrality_version="n-v1.1",
            min_score_allow=75,
            hard_block_rules=["jailbreak", "therapy", "promise"],
            soft_rules=["direct_advice", "coercion"],
            max_findings=10,
            updated_at="",
        )
        _CACHE["ts"] = now
        _CACHE["policy"] = pol
        return pol

    pol = GovernancePolicy(
        id=uuid.UUID(str(row[0])),
        policy_version=str(row[1]),
        neutrality_version=str(row[2]),
        min_score_allow=int(row[3]),
        hard_block_rules=_as_list(row[4], ["jailbreak", "therapy", "promise"]),
        soft_rules=_as_list(row[5], ["direct_advice", "coercion"]),
        max_findings=int(row[6]),
        updated_at=row[7].isoformat() if row[7] else "",
    )

    _CACHE["ts"] = now
    _CACHE["policy"] = pol
    return pol


def list_policy_history(db, limit: int = 50) -> List[GovernancePolicy]:
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
        {"limit": int(limit)},
    ).fetchall()

    out: List[GovernancePolicy] = []
    for r in rows:
        out.append(
            GovernancePolicy(
                id=uuid.UUID(str(r[0])),
                policy_version=str(r[1]),
                neutrality_version=str(r[2]),
                min_score_allow=int(r[3]),
                hard_block_rules=_as_list(r[4], ["jailbreak", "therapy", "promise"]),
                soft_rules=_as_list(r[5], ["direct_advice", "coercion"]),
                max_findings=int(r[6]),
                updated_at=r[7].isoformat() if r[7] else "",
            )
        )
    return out


def create_new_policy(
    db,
    *,
    policy_version: str,
    neutrality_version: str,
    min_score_allow: int,
    hard_block_rules: List[str],
    soft_rules: List[str],
    max_findings: int,
) -> GovernancePolicy:
    """
    Inserts a new policy row (versioned by policy_version), becomes active by updated_at ordering.
    """
    pid = uuid.uuid4()

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
            "min_score_allow": int(min_score_allow),
            "hard_block_rules": json.dumps(hard_block_rules),
            "soft_rules": json.dumps(soft_rules),
            "max_findings": int(max_findings),
        },
    )

    # Bust cache
    _CACHE["ts"] = 0
    _CACHE["policy"] = None

    # Return current
    return get_current_policy(db, use_cache=False)
