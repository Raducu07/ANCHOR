# app/main.py
import uuid
import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations

from app.governance_config import (
    get_current_policy,
    list_policy_history,
    create_new_policy,
)

from app.memory_shaping import (
    propose_memory_offer,
    compute_offer_debug,
    fetch_recent_user_texts,
)

# ✅ ONE scorer module (V1.1)
from app.neutrality_v11 import score_neutrality

# ✅ Governance layer (A2/A3)
from app.governance import govern_output

from app.schemas import (
    CreateSessionResponse,
    SendMessageRequest,
    SendMessageResponse,
    MemoryItem,
    CreateMemoryRequest,
    MemoryOfferResponse,
    NeutralityScoreRequest,
    NeutralityScoreResponse,
)

app = FastAPI(title="ANCHOR API")


# ---------------------------
# A4 — Policy update schema (request)
# ---------------------------

class GovernancePolicyUpdateRequest(BaseModel):
    policy_version: str = Field(..., min_length=3, max_length=64)
    neutrality_version: str = Field(default="n-v1.1", min_length=3, max_length=64)
    min_score_allow: int = Field(default=75, ge=0, le=100)
    hard_block_rules: List[str] = Field(default_factory=lambda: ["jailbreak", "therapy", "promise"])
    soft_rules: List[str] = Field(default_factory=lambda: ["direct_advice", "coercion"])
    max_findings: int = Field(default=10, ge=1, le=50)


# ---------------------------
# Helpers
# ---------------------------

def _ensure_user_exists(db, user_id: uuid.UUID) -> None:
    row = db.execute(
        text("SELECT id FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")


def _ensure_session_exists(db, session_id: uuid.UUID) -> None:
    row = db.execute(
        text("SELECT id FROM sessions WHERE id = :sid"),
        {"sid": str(session_id)},
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")


def _validate_memory_statement(statement: str) -> None:
    s = (statement or "").strip()

    # Keep memory short + single-line (presence, not essays)
    if not s or "\n" in s or len(s) > 280:
        raise HTTPException(status_code=400, detail="Invalid memory statement")

    # Minimal neutrality guardrails (v1)
    banned = [
        "you should",
        "try to",
        "it might help",
        "i recommend",
        "diagnos",
        "therapy",
        "therapist",
        "you need to",
        "this will help",
        "you will feel",
    ]
    low = s.lower()
    if any(b in low for b in banned):
        raise HTTPException(
            status_code=400,
            detail="Memory statement violates neutrality rules",
        )


def _norm_stmt(s: str) -> str:
    return " ".join((s or "").strip().split())


def _score_neutrality_safe(text_value: str, debug: bool) -> Dict[str, Any]:
    """
    Compatible with both:
      - score_neutrality(text)
      - score_neutrality(text, debug=True)
    """
    try:
        return score_neutrality(text_value, debug=debug)  # type: ignore[arg-type]
    except TypeError:
        base = score_neutrality(text_value)  # type: ignore[misc]
        if debug and isinstance(base, dict):
            base["debug"] = {
                "note": "scorer does not support debug=True; returned base scoring only"
            }
        return base


# ---------------------------
# Governance schema detection + insert (A3/A4)
# ---------------------------

# Cache column set (avoid per-request information_schema hits)
_GOV_EVENTS_COLSET: Optional[set[str]] = None


def _get_governance_events_colset(db) -> set[str]:
    global _GOV_EVENTS_COLSET
    if _GOV_EVENTS_COLSET is not None:
        return _GOV_EVENTS_COLSET

    rows = db.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'governance_events'
            """
        )
    ).fetchall()
    _GOV_EVENTS_COLSET = {str(r[0]) for r in rows}
    return _GOV_EVENTS_COLSET


def _gov_has_a4_cols(db) -> bool:
    cols = _get_governance_events_colset(db)
    return {"policy_version", "neutrality_version", "decision_trace"}.issubset(cols)


def _days_to_interval(days: int) -> int:
    """
    Clamp day window to [1, 365]. Default 30.
    """
    if days is None:
        return 30
    try:
        d = int(days)
    except Exception:
        d = 30
    return max(1, min(365, d))


def _time_window_where(days: int) -> str:
    """
    Standard time window predicate for governance_events.
    Uses a parameter :days.
    """
    _ = _days_to_interval(days)  # validate/clamp upstream; keep here for readability
    return "created_at >= (NOW() - (:days || ' days')::interval)"


def _insert_governance_event(
    db,
    *,
    user_id: Optional[uuid.UUID],
    session_id: Optional[uuid.UUID],
    mode: str,
    audit: Dict[str, Any],
) -> None:
    """
    A3/A4 — writes one audit row into governance_events.

    Compatible with:
    - A3 schema: findings JSONB, audit JSONB
    - A4 upgrades: policy_version, neutrality_version, decision_trace

    Safe by design: never raises upward.
    """
    try:
        if not user_id:
            return

        a = audit or {}

        decision = a.get("decision")
        if not isinstance(decision, dict):
            decision = {}

        findings = a.get("findings")
        if not isinstance(findings, list):
            findings = []

        notes = a.get("notes")
        if not isinstance(notes, dict):
            notes = {}

        allowed = bool(decision.get("allowed", True))
        replaced = bool(decision.get("replaced", False))
        score = int(decision.get("score", 0) or 0)
        grade = str(decision.get("grade", "unknown") or "unknown")
        reason = str(decision.get("reason", "") or "")

        # Triggered rule ids
        triggered_rule_ids: List[str] = []
        for f in findings:
            if isinstance(f, dict):
                rid = f.get("rule_id")
                if isinstance(rid, str):
                    rid = rid.strip()
                    if rid:
                        triggered_rule_ids.append(rid)
        triggered_rule_ids = sorted(set(triggered_rule_ids))[:25]

        decision_trace = {
            "min_score_allow": notes.get("min_score_allow"),
            "hard_block_rules": notes.get("hard_block_rules"),
            "soft_rules": notes.get("soft_rules"),
            "triggered_rule_ids": triggered_rule_ids,
            "score": score,
            "grade": grade,
            "replaced": replaced,
            "reason": reason,
        }

        # Prefer pulling active policy versions from governance_config
        policy_version = "gov-v1.0"
        neutrality_version = "n-v1.1"
        try:
            pol = get_current_policy(db)
            if isinstance(pol, dict):
                pv = pol.get("policy_version")
                nv = pol.get("neutrality_version")
                if isinstance(pv, str) and pv.strip():
                    policy_version = pv.strip()
                if isinstance(nv, str) and nv.strip():
                    neutrality_version = nv.strip()
        except Exception:
            pass

        has_a4 = _gov_has_a4_cols(db)

        if has_a4:
            db.execute(
                text(
                    """
                    INSERT INTO governance_events (
                      id, user_id, session_id, mode,
                      allowed, replaced, score, grade, reason,
                      findings, audit,
                      policy_version, neutrality_version, decision_trace
                    )
                    VALUES (
                      :id, :user_id, :session_id, :mode,
                      :allowed, :replaced, :score, :grade, :reason,
                      CAST(:findings AS jsonb),
                      CAST(:audit AS jsonb),
                      :policy_version, :neutrality_version,
                      CAST(:decision_trace AS jsonb)
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(user_id),
                    "session_id": str(session_id) if session_id else None,
                    "mode": mode,
                    "allowed": allowed,
                    "replaced": replaced,
                    "score": score,
                    "grade": grade,
                    "reason": reason,
                    "findings": json.dumps(findings),
                    "audit": json.dumps(a),
                    "policy_version": policy_version,
                    "neutrality_version": neutrality_version,
                    "decision_trace": json.dumps(decision_trace),
                },
            )
        else:
            # A3-only schema
            db.execute(
                text(
                    """
                    INSERT INTO governance_events (
                      id, user_id, session_id, mode,
                      allowed, replaced, score, grade, reason,
                      findings, audit
                    )
                    VALUES (
                      :id, :user_id, :session_id, :mode,
                      :allowed, :replaced, :score, :grade, :reason,
                      CAST(:findings AS jsonb),
                      CAST(:audit AS jsonb)
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(user_id),
                    "session_id": str(session_id) if session_id else None,
                    "mode": mode,
                    "allowed": allowed,
                    "replaced": replaced,
                    "score": score,
                    "grade": grade,
                    "reason": reason,
                    "findings": json.dumps(findings),
                    "audit": json.dumps(a),
                },
            )

    except Exception:
        # Never break runtime due to audit persistence failure
        pass


# ---------------------------
# Startup
# ---------------------------

@app.on_event("startup")
def on_startup():
    run_migrations()


# ---------------------------
# Health / Root
# ---------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db-check")
def db_check():
    db_ping()
    return {"db": "ok"}


@app.get("/db-memories-check")
def db_memories_check():
    with SessionLocal() as db:
        try:
            db.execute(text("SELECT 1 FROM memories LIMIT 1"))
            return {"memories_table": "ok"}
        except Exception as e:
            return {"memories_table": "error", "detail": str(e)}


@app.get("/")
def root():
    return {"name": "ANCHOR API", "status": "live"}


# ---------------------------
# Neutrality scoring (V1.1)
# ---------------------------

@app.post("/v1/neutrality/score", response_model=NeutralityScoreResponse)
def neutrality_score(req: NeutralityScoreRequest):
    try:
        debug_flag = bool(getattr(req, "debug", False))
        return _score_neutrality_safe(req.text, debug_flag)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"neutrality_error: {type(e).__name__}: {e}",
        )


# ---------------------------
# A4 — Governance policy endpoints (4.1–4.4)
# ---------------------------

@app.get("/v1/governance/policy/current")
def governance_policy_current():
    with SessionLocal() as db:
        try:
            return {"policy": get_current_policy(db)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.get("/v1/governance/policy/history")
def governance_policy_history(limit: int = 50):
    limit = max(1, min(200, int(limit)))
    with SessionLocal() as db:
        try:
            return {"history": list_policy_history(db, limit=limit)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.post("/v1/governance/policy")
def governance_policy_create(payload: GovernancePolicyUpdateRequest):
    with SessionLocal() as db:
        try:
            created = create_new_policy(
                db,
                policy_version=payload.policy_version,
                neutrality_version=payload.neutrality_version,
                min_score_allow=int(payload.min_score_allow),
                hard_block_rules=list(payload.hard_block_rules or []),
                soft_rules=list(payload.soft_rules or []),
                max_findings=int(payload.max_findings),
            )
            return {"created": created}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.get("/v1/governance/policy/schema")
def governance_policy_schema():
    """
    Lightweight visibility endpoint for config table existence + newest row timestamp.
    """
    with SessionLocal() as db:
        try:
            row = db.execute(
                text(
                    """
                    SELECT updated_at
                    FROM governance_config
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """
                )
            ).fetchone()
            return {
                "governance_config_table": "ok",
                "latest_updated_at": row[0].isoformat() if row and row[0] else None,
            }
        except Exception as e:
            return {"governance_config_table": "error", "detail": str(e)}


# ---------------------------
# Sessions
# ---------------------------

@app.post("/v1/sessions", response_model=CreateSessionResponse)
def create_session():
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()

    with SessionLocal() as db:
        db.execute(text("INSERT INTO users (id) VALUES (:id)"), {"id": str(user_id)})
        db.execute(
            text(
                "INSERT INTO sessions (id, user_id, mode, question_used) "
                "VALUES (:sid, :uid, 'witness', false)"
            ),
            {"sid": str(session_id), "uid": str(user_id)},
        )
        db.commit()

    return CreateSessionResponse(user_id=user_id, session_id=session_id, mode="witness")


@app.post("/v1/users/{user_id}/sessions", response_model=CreateSessionResponse)
def create_session_for_user(user_id: uuid.UUID):
    session_id = uuid.uuid4()

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        db.execute(
            text(
                "INSERT INTO sessions (id, user_id, mode, question_used) "
                "VALUES (:sid, :uid, 'witness', false)"
            ),
            {"sid": str(session_id), "uid": str(user_id)},
        )
        db.commit()

    return CreateSessionResponse(user_id=user_id, session_id=session_id, mode="witness")


# ---------------------------
# Messages (with governance)
# ---------------------------

@app.post("/v1/sessions/{session_id}/messages", response_model=SendMessageResponse)
def send_message(session_id: uuid.UUID, payload: SendMessageRequest):
    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)

        uid_row = db.execute(
            text("SELECT user_id FROM sessions WHERE id = :sid"),
            {"sid": str(session_id)},
        ).fetchone()
        user_id = uuid.UUID(str(uid_row[0])) if uid_row and uid_row[0] else None

        # store user message
        db.execute(
            text(
                "INSERT INTO messages (id, session_id, role, content) "
                "VALUES (:id, :sid, 'user', :content)"
            ),
            {
                "id": str(uuid.uuid4()),
                "sid": str(session_id),
                "content": payload.content,
            },
        )

        # draft witness reply
        draft_reply = (
            "I’m here with you. I’m going to reflect back what I heard, briefly.\n\n"
            f"**What you said:** {payload.content}\n\n"
            "One question: what feels most important in this right now?"
        )

        # A2 governance gate
        final_reply, _decision, audit = govern_output(
            user_text=payload.content,
            assistant_text=draft_reply,
            user_id=user_id,
            session_id=session_id,
            mode="witness",
            debug=False,
        )

        # store governed assistant message ONCE ✅
        db.execute(
            text(
                "INSERT INTO messages (id, session_id, role, content) "
                "VALUES (:id, :sid, 'assistant', :content)"
            ),
            {
                "id": str(uuid.uuid4()),
                "sid": str(session_id),
                "content": final_reply,
            },
        )

        # A3/A4 persist audit event (same transaction)
        _insert_governance_event(
            db,
            user_id=user_id,
            session_id=session_id,
            mode="witness",
            audit=audit if isinstance(audit, dict) else {},
        )

        db.commit()

    return SendMessageResponse(session_id=session_id, role="assistant", content=final_reply)


@app.get("/v1/sessions/{session_id}/messages")
def list_messages(session_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)

        rows = db.execute(
            text(
                """
                SELECT role, content, created_at
                FROM messages
                WHERE session_id = :sid
                ORDER BY
                    created_at ASC,
                    CASE role
                        WHEN 'user' THEN 0
                        WHEN 'assistant' THEN 1
                        ELSE 2
                    END ASC,
                    id ASC
                """
            ),
            {"sid": str(session_id)},
        ).fetchall()

    return [
        {
            "role": r[0],
            "content": r[1],
            "created_at": r[2].isoformat() if r[2] else None,
        }
        for r in rows
    ]


# ---------------------------
# A3/A4 — Governance audit endpoints (A5: default last 30 days)
# ---------------------------

@app.get("/v1/users/{user_id}/governance-events")
def list_governance_events_for_user(user_id: uuid.UUID, limit: int = 50, days: int = 30):
    limit = max(1, min(500, int(limit)))
    d = _days_to_interval(days)

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        has_a4 = _gov_has_a4_cols(db)

        where_sql = f"user_id = :uid AND {_time_window_where(d)}"
        params = {"uid": str(user_id), "limit": limit, "days": d}

        if has_a4:
            rows = db.execute(
                text(
                    f"""
                    SELECT
                      id, user_id, session_id, mode,
                      allowed, replaced, score, grade, reason,
                      findings, audit,
                      policy_version, neutrality_version, decision_trace,
                      created_at
                    FROM governance_events
                    WHERE {where_sql}
                    ORDER BY created_at DESC
                    LIMIT :limit
                    """
                ),
                params,
            ).fetchall()

            return {
                "user_id": str(user_id),
                "window_days": d,
                "has_a4_cols": True,
                "events": [
                    {
                        "id": str(r[0]),
                        "user_id": str(r[1]) if r[1] else None,
                        "session_id": str(r[2]) if r[2] else None,
                        "mode": r[3],
                        "allowed": bool(r[4]),
                        "replaced": bool(r[5]),
                        "score": int(r[6]),
                        "grade": r[7],
                        "reason": r[8],
                        "findings": r[9] or [],
                        "audit": r[10] or {},
                        "policy_version": r[11],
                        "neutrality_version": r[12],
                        "decision_trace": r[13] or {},
                        "created_at": r[14].isoformat() if r[14] else None,
                    }
                    for r in rows
                ],
            }

        # A3-only
        rows = db.execute(
            text(
                f"""
                SELECT
                  id, user_id, session_id, mode,
                  allowed, replaced, score, grade, reason,
                  findings, audit,
                  created_at
                FROM governance_events
                WHERE {where_sql}
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).fetchall()

        return {
            "user_id": str(user_id),
            "window_days": d,
            "has_a4_cols": False,
            "events": [
                {
                    "id": str(r[0]),
                    "user_id": str(r[1]) if r[1] else None,
                    "session_id": str(r[2]) if r[2] else None,
                    "mode": r[3],
                    "allowed": bool(r[4]),
                    "replaced": bool(r[5]),
                    "score": int(r[6]),
                    "grade": r[7],
                    "reason": r[8],
                    "findings": r[9] or [],
                    "audit": r[10] or {},
                    "created_at": r[11].isoformat() if r[11] else None,
                }
                for r in rows
            ],
        }


@app.get("/v1/sessions/{session_id}/governance-events")
def list_governance_events_for_session(session_id: uuid.UUID, limit: int = 50, days: int = 30):
    limit = max(1, min(500, int(limit)))
    d = _days_to_interval(days)

    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)
        has_a4 = _gov_has_a4_cols(db)

        where_sql = f"session_id = :sid AND {_time_window_where(d)}"
        params = {"sid": str(session_id), "limit": limit, "days": d}

        if has_a4:
            rows = db.execute(
                text(
                    f"""
                    SELECT
                      id, user_id, session_id, mode,
                      allowed, replaced, score, grade, reason,
                      findings, audit,
                      policy_version, neutrality_version, decision_trace,
                      created_at
                    FROM governance_events
                    WHERE {where_sql}
                    ORDER BY created_at DESC
                    LIMIT :limit
                    """
                ),
                params,
            ).fetchall()

            return {
                "session_id": str(session_id),
                "window_days": d,
                "has_a4_cols": True,
                "events": [
                    {
                        "id": str(r[0]),
                        "user_id": str(r[1]) if r[1] else None,
                        "session_id": str(r[2]) if r[2] else None,
                        "mode": r[3],
                        "allowed": bool(r[4]),
                        "replaced": bool(r[5]),
                        "score": int(r[6]),
                        "grade": r[7],
                        "reason": r[8],
                        "findings": r[9] or [],
                        "audit": r[10] or {},
                        "policy_version": r[11],
                        "neutrality_version": r[12],
                        "decision_trace": r[13] or {},
                        "created_at": r[14].isoformat() if r[14] else None,
                    }
                    for r in rows
                ],
            }

        # A3-only
        rows = db.execute(
            text(
                f"""
                SELECT
                  id, user_id, session_id, mode,
                  allowed, replaced, score, grade, reason,
                  findings, audit,
                  created_at
                FROM governance_events
                WHERE {where_sql}
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).fetchall()

        return {
            "session_id": str(session_id),
            "window_days": d,
            "has_a4_cols": False,
            "events": [
                {
                    "id": str(r[0]),
                    "user_id": str(r[1]) if r[1] else None,
                    "session_id": str(r[2]) if r[2] else None,
                    "mode": r[3],
                    "allowed": bool(r[4]),
                    "replaced": bool(r[5]),
                    "score": int(r[6]),
                    "grade": r[7],
                    "reason": r[8],
                    "findings": r[9] or [],
                    "audit": r[10] or {},
                    "created_at": r[11].isoformat() if r[11] else None,
                }
                for r in rows
            ],
        }


# ---------------------------
# A5 — Governance analytics layer (default last 30 days)
# ---------------------------

@app.get("/v1/governance/health")
def governance_health():
    """
    Minimal governance health check:
    - table readable
    - last event timestamp
    - A4 columns present/absent
    """
    with SessionLocal() as db:
        try:
            cols = _get_governance_events_colset(db)
            has_a4 = _gov_has_a4_cols(db)
            last_row = db.execute(
                text("SELECT created_at FROM governance_events ORDER BY created_at DESC LIMIT 1")
            ).fetchone()
            last_ts = last_row[0].isoformat() if last_row and last_row[0] else None

            return {
                "status": "ok",
                "governance_events_table": "ok",
                "has_a4_cols": bool(has_a4),
                "columns": sorted(list(cols))[:200],
                "last_event_created_at": last_ts,
            }
        except Exception as e:
            return {
                "status": "error",
                "governance_events_table": "error",
                "detail": str(e),
            }


def _fetch_rule_counts_last_window(db, where_sql: str, params: Dict[str, Any], has_a4: bool) -> List[Dict[str, Any]]:
    """
    Top triggered rules in last window.
    A4: decision_trace.triggered_rule_ids
    A3: findings[*].rule_id
    """
    if has_a4:
        q = f"""
        WITH base AS (
          SELECT decision_trace
          FROM governance_events
          WHERE {where_sql}
        ),
        rules AS (
          SELECT jsonb_array_elements_text(COALESCE(decision_trace->'triggered_rule_ids', '[]'::jsonb)) AS rid
          FROM base
        )
        SELECT rid, COUNT(*) AS n
        FROM rules
        WHERE rid IS NOT NULL AND rid <> ''
        GROUP BY rid
        ORDER BY n DESC, rid ASC
        LIMIT 10
        """
        rows = db.execute(text(q), params).fetchall()
        return [{"rule_id": r[0], "count": int(r[1])} for r in rows]

    q = f"""
    WITH base AS (
      SELECT findings
      FROM governance_events
      WHERE {where_sql}
    ),
    rules AS (
      SELECT (elem->>'rule_id') AS rid
      FROM base, LATERAL jsonb_array_elements(COALESCE(findings, '[]'::jsonb)) AS elem
    )
    SELECT rid, COUNT(*) AS n
    FROM rules
    WHERE rid IS NOT NULL AND rid <> ''
    GROUP BY rid
    ORDER BY n DESC, rid ASC
    LIMIT 10
    """
    rows = db.execute(text(q), params).fetchall()
    return [{"rule_id": r[0], "count": int(r[1])} for r in rows]


def _fetch_grade_breakdown_last_window(db, where_sql: str, params: Dict[str, Any]) -> Dict[str, int]:
    q = f"""
    SELECT grade, COUNT(*)::int
    FROM governance_events
    WHERE {where_sql}
    GROUP BY grade
    ORDER BY grade ASC
    """
    rows = db.execute(text(q), params).fetchall()
    out: Dict[str, int] = {}
    for g, n in rows:
        out[str(g)] = int(n)
    return out


def _fetch_core_metrics_last_window(db, where_sql: str, params: Dict[str, Any]) -> Dict[str, Any]:
    q = f"""
    SELECT
      COUNT(*)::int AS events_total,
      COALESCE(AVG(CASE WHEN allowed THEN 1 ELSE 0 END), 0)::float AS allowed_rate,
      COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate,
      COALESCE(AVG(score), 0)::float AS avg_score
    FROM governance_events
    WHERE {where_sql}
    """
    row = db.execute(text(q), params).fetchone()
    if not row:
        return {"events_total": 0, "allowed_rate": 0.0, "replaced_rate": 0.0, "avg_score": 0.0}
    return {
        "events_total": int(row[0]),
        "allowed_rate": float(row[1]),
        "replaced_rate": float(row[2]),
        "avg_score": float(row[3]),
    }


@app.get("/v1/governance/metrics")
def governance_metrics(days: int = 30):
    """
    Fleet metrics across all users/sessions (default last 30 days).
    """
    d = _days_to_interval(days)

    with SessionLocal() as db:
        has_a4 = _gov_has_a4_cols(db)
        where_sql = _time_window_where(d)
        params = {"days": d}

        core = _fetch_core_metrics_last_window(db, where_sql, params)
        grades = _fetch_grade_breakdown_last_window(db, where_sql, params)
        top_rules = _fetch_rule_counts_last_window(db, where_sql, params, has_a4)

        return {
            "window_days": d,
            "core": core,
            "grade_breakdown": grades,
            "top_triggered_rules": top_rules,
            "has_a4_cols": bool(has_a4),
        }


@app.get("/v1/governance/metrics/by-policy")
def governance_metrics_by_policy(days: int = 30, limit: int = 50):
    """
    Group metrics by policy_version + neutrality_version (A4),
    or single bucket (A3).
    """
    d = _days_to_interval(days)
    limit = max(1, min(200, int(limit)))

    with SessionLocal() as db:
        has_a4 = _gov_has_a4_cols(db)

        if has_a4:
            rows = db.execute(
                text(
                    """
                    SELECT
                      policy_version,
                      neutrality_version,
                      COUNT(*)::int AS events_total,
                      COALESCE(AVG(CASE WHEN allowed THEN 1 ELSE 0 END), 0)::float AS allowed_rate,
                      COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate,
                      COALESCE(AVG(score), 0)::float AS avg_score
                    FROM governance_events
                    WHERE created_at >= (NOW() - (:days || ' days')::interval)
                    GROUP BY policy_version, neutrality_version
                    ORDER BY events_total DESC, policy_version ASC, neutrality_version ASC
                    LIMIT :limit
                    """
                ),
                {"days": d, "limit": limit},
            ).fetchall()

            return {
                "window_days": d,
                "has_a4_cols": True,
                "rows": [
                    {
                        "policy_version": r[0],
                        "neutrality_version": r[1],
                        "events_total": int(r[2]),
                        "allowed_rate": float(r[3]),
                        "replaced_rate": float(r[4]),
                        "avg_score": float(r[5]),
                    }
                    for r in rows
                ],
            }

        row = db.execute(
            text(
                """
                SELECT
                  COUNT(*)::int AS events_total,
                  COALESCE(AVG(CASE WHEN allowed THEN 1 ELSE 0 END), 0)::float AS allowed_rate,
                  COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate,
                  COALESCE(AVG(score), 0)::float AS avg_score
                FROM governance_events
                WHERE created_at >= (NOW() - (:days || ' days')::interval)
                """
            ),
            {"days": d},
        ).fetchone()

        return {
            "window_days": d,
            "has_a4_cols": False,
            "rows": [
                {
                    "policy_version": "gov-v1.0",
                    "neutrality_version": "n-v1.1",
                    "events_total": int(row[0] if row else 0),
                    "allowed_rate": float(row[1] if row else 0.0),
                    "replaced_rate": float(row[2] if row else 0.0),
                    "avg_score": float(row[3] if row else 0.0),
                }
            ],
        }


@app.get("/v1/users/{user_id}/governance/metrics")
def governance_metrics_for_user(user_id: uuid.UUID, days: int = 30):
    """
    User-scoped governance metrics (default last 30 days).
    """
    d = _days_to_interval(days)

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        has_a4 = _gov_has_a4_cols(db)

        where_sql = f"user_id = :uid AND {_time_window_where(d)}"
        params = {"uid": str(user_id), "days": d}

        core = _fetch_core_metrics_last_window(db, where_sql, params)
        grades = _fetch_grade_breakdown_last_window(db, where_sql, params)
        top_rules = _fetch_rule_counts_last_window(db, where_sql, params, has_a4)

        trend = db.execute(
            text(
                """
                WITH w AS (
                  SELECT
                    CASE
                      WHEN created_at >= (NOW() - '7 days'::interval) THEN 'last_7'
                      WHEN created_at >= (NOW() - '14 days'::interval) AND created_at < (NOW() - '7 days'::interval) THEN 'prev_7'
                      ELSE NULL
                    END AS bucket,
                    replaced
                  FROM governance_events
                  WHERE user_id = :uid
                    AND created_at >= (NOW() - '14 days'::interval)
                )
                SELECT
                  bucket,
                  COUNT(*)::int AS n,
                  COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate
                FROM w
                WHERE bucket IS NOT NULL
                GROUP BY bucket
                """
            ),
            {"uid": str(user_id)},
        ).fetchall()

        trend_map = {str(r[0]): {"events_total": int(r[1]), "replaced_rate": float(r[2])} for r in trend}

        return {
            "user_id": str(user_id),
            "window_days": d,
            "core": core,
            "grade_breakdown": grades,
            "top_triggered_rules": top_rules,
            "trend_7d": {
                "last_7": trend_map.get("last_7", {"events_total": 0, "replaced_rate": 0.0}),
                "prev_7": trend_map.get("prev_7", {"events_total": 0, "replaced_rate": 0.0}),
            },
            "has_a4_cols": bool(has_a4),
        }


@app.get("/v1/sessions/{session_id}/governance/metrics")
def governance_metrics_for_session(session_id: uuid.UUID, days: int = 30):
    """
    Session-scoped governance metrics (default last 30 days).
    """
    d = _days_to_interval(days)

    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)
        has_a4 = _gov_has_a4_cols(db)

        where_sql = f"session_id = :sid AND {_time_window_where(d)}"
        params = {"sid": str(session_id), "days": d}

        core = _fetch_core_metrics_last_window(db, where_sql, params)
        grades = _fetch_grade_breakdown_last_window(db, where_sql, params)
        top_rules = _fetch_rule_counts_last_window(db, where_sql, params, has_a4)

        return {
            "session_id": str(session_id),
            "window_days": d,
            "core": core,
            "grade_breakdown": grades,
            "top_triggered_rules": top_rules,
            "has_a4_cols": bool(has_a4),
        }


# ---------------------------
# Evidence + Memory debugging
# ---------------------------

@app.get("/v1/users/{user_id}/evidence-check")
def evidence_check(user_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        sessions_count = db.execute(
            text("SELECT COUNT(*) FROM sessions WHERE user_id = :uid"),
            {"uid": str(user_id)},
        ).fetchone()[0]

        user_msgs = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM messages m
                JOIN sessions s ON s.id = m.session_id
                WHERE s.user_id = :uid AND m.role = 'user'
                """
            ),
            {"uid": str(user_id)},
        ).fetchone()[0]

        last_sessions = db.execute(
            text(
                """
                SELECT id, created_at
                FROM sessions
                WHERE user_id = :uid
                ORDER BY created_at DESC
                LIMIT 5
                """
            ),
            {"uid": str(user_id)},
        ).fetchall()

    return {
        "user_id": str(user_id),
        "sessions_count": int(sessions_count),
        "user_message_count": int(user_msgs),
        "last_sessions": [{"id": str(r[0]), "created_at": r[1].isoformat()} for r in last_sessions],
    }


@app.get("/v1/users/{user_id}/memory-debug")
def memory_debug(user_id: uuid.UUID, limit: int = 80):
    limit = max(1, min(500, int(limit)))

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        items = fetch_recent_user_texts(db, user_id, limit=limit)

        signals = {
            "overwhelm_load": [
                "overwhelmed", "too much", "can't keep up", "cannot keep up",
                "exhausted", "burnt out", "drained", "no time", "stressed", "pressure"
            ],
            "responsibility_conflict": [
                "i have to", "i must", "obligation", "obligations", "responsible",
                "expectations", "expects", "everyone", "depend on me", "duty"
            ],
            "control_uncertainty": [
                "i don't know", "uncertain", "confused", "not sure", "what if",
                "worried", "anxious"
            ],
        }

        counts = {k: 0 for k in signals}
        evidence = {k: set() for k in signals}

        for sid, txt in items:
            low = (txt or "").strip().lower()
            if not low:
                continue
            for k, needles in signals.items():
                if any(n in low for n in needles):
                    counts[k] += 1
                    evidence[k].add(str(sid))

        best_key = max(counts, key=lambda k: counts[k]) if counts else None
        best_count = counts[best_key] if best_key else 0

        return {
            "user_id": str(user_id),
            "scanned_user_messages": len(items),
            "counts": counts,
            "best_key": best_key,
            "best_count": best_count,
            "evidence_session_ids": list(evidence[best_key])[:5] if best_key else [],
            "sample_last_5_texts": [t for (_, t) in items[-5:]],
        }


@app.get("/v1/users/{user_id}/memory-offer-debug")
def memory_offer_debug(user_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        return compute_offer_debug(db, user_id)


# ---------------------------
# Memories
# ---------------------------

@app.get("/v1/users/{user_id}/memories", response_model=List[MemoryItem])
def list_memories(user_id: uuid.UUID, active: bool = True, kind: Optional[str] = None):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        if kind:
            rows = db.execute(
                text(
                    "SELECT id, kind, statement, confidence, active, evidence_session_ids, created_at "
                    "FROM memories "
                    "WHERE user_id = :uid AND active = :active AND kind = :kind "
                    "ORDER BY created_at DESC"
                ),
                {"uid": str(user_id), "active": active, "kind": kind},
            ).fetchall()
        else:
            rows = db.execute(
                text(
                    "SELECT id, kind, statement, confidence, active, evidence_session_ids, created_at "
                    "FROM memories "
                    "WHERE user_id = :uid AND active = :active "
                    "ORDER BY created_at DESC"
                ),
                {"uid": str(user_id), "active": active},
            ).fetchall()

    result: List[MemoryItem] = []
    for r in rows:
        evidence = r[5] or []
        evidence_uuids: List[uuid.UUID] = []
        for x in evidence:
            try:
                evidence_uuids.append(uuid.UUID(str(x)))
            except Exception:
                pass

        result.append(
            MemoryItem(
                id=uuid.UUID(str(r[0])),
                kind=r[1],
                statement=r[2],
                confidence=r[3],
                active=bool(r[4]),
                evidence_session_ids=evidence_uuids,
                created_at=r[6].isoformat() if r[6] else "",
            )
        )
    return result


@app.post("/v1/users/{user_id}/memory-offer", response_model=MemoryOfferResponse)
def memory_offer(user_id: uuid.UUID):
    DEFAULT_KIND = "negative_space"
    DEFAULT_STATEMENT = "No stable pattern is evident yet from recent entries."
    DEFAULT_STATEMENT_DUP = "No new stable pattern stands out beyond what is already saved."

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        offer = propose_memory_offer(db, user_id)

        if not offer:
            dup_default = db.execute(
                text(
                    """
                    SELECT 1
                    FROM memories
                    WHERE user_id = :uid
                      AND active = true
                      AND kind = :kind
                      AND statement = :statement
                    LIMIT 1
                    """
                ),
                {"uid": str(user_id), "kind": DEFAULT_KIND, "statement": DEFAULT_STATEMENT},
            ).fetchone()

            if dup_default:
                return MemoryOfferResponse(
                    offer=CreateMemoryRequest(
                        kind=DEFAULT_KIND,
                        statement=DEFAULT_STATEMENT_DUP,
                        confidence="tentative",
                        evidence_session_ids=[],
                    )
                )

            return MemoryOfferResponse(
                offer=CreateMemoryRequest(
                    kind=DEFAULT_KIND,
                    statement=DEFAULT_STATEMENT,
                    confidence="tentative",
                    evidence_session_ids=[],
                )
            )

        offer_kind = offer["kind"]
        offer_stmt = _norm_stmt(offer["statement"])
        _validate_memory_statement(offer_stmt)

        dup = db.execute(
            text(
                """
                SELECT 1
                FROM memories
                WHERE user_id = :uid
                  AND active = true
                  AND kind = :kind
                  AND statement = :statement
                LIMIT 1
                """
            ),
            {"uid": str(user_id), "kind": offer_kind, "statement": offer_stmt},
        ).fetchone()

        if dup:
            return MemoryOfferResponse(
                offer=CreateMemoryRequest(
                    kind=DEFAULT_KIND,
                    statement=DEFAULT_STATEMENT_DUP,
                    confidence="tentative",
                    evidence_session_ids=[],
                )
            )

        return MemoryOfferResponse(
            offer=CreateMemoryRequest(
                kind=offer_kind,
                statement=offer_stmt,
                confidence=offer["confidence"],
                evidence_session_ids=offer["evidence_session_ids"],
            )
        )


@app.post("/v1/users/{user_id}/memories", response_model=MemoryItem)
def create_memory(user_id: uuid.UUID, payload: CreateMemoryRequest):
    stmt = _norm_stmt(payload.statement)
    _validate_memory_statement(stmt)

    if payload.kind == "negative_space":
        raise HTTPException(
            status_code=400,
            detail="negative_space is an offer fallback and cannot be saved as a memory",
        )

    kind_allowed = {
        "recurring_tension",
        "unexpressed_axis",
        "values_vs_emphasis",
        "decision_posture",
        "negative_space",
    }
    if payload.kind not in kind_allowed:
        raise HTTPException(status_code=400, detail="Invalid memory kind")

    conf_allowed = {"tentative", "emerging", "consistent"}
    if payload.confidence not in conf_allowed:
        raise HTTPException(status_code=400, detail="Invalid confidence")

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        count_row = db.execute(
            text("SELECT COUNT(*) FROM memories WHERE user_id = :uid AND active = true"),
            {"uid": str(user_id)},
        ).fetchone()

        if count_row and int(count_row[0]) >= 5:
            raise HTTPException(status_code=400, detail="Max active memories reached (5)")

        mem_id = uuid.uuid4()
        evidence_json = [str(x) for x in (payload.evidence_session_ids or [])]
        evidence_str = json.dumps(evidence_json)

        row = db.execute(
            text(
                """
                INSERT INTO memories (
                    id, user_id, kind, statement,
                    evidence_session_ids, confidence, active
                )
                VALUES (
                    :id, :uid, :kind, :statement,
                    CAST(:evidence AS jsonb),
                    :confidence, true
                )
                RETURNING
                    id, kind, statement, confidence, active,
                    evidence_session_ids, created_at
                """
            ),
            {
                "id": str(mem_id),
                "uid": str(user_id),
                "kind": payload.kind,
                "statement": stmt,
                "evidence": evidence_str,
                "confidence": payload.confidence,
            },
        ).fetchone()

        db.commit()

    evidence_uuids: List[uuid.UUID] = []
    for x in (row[5] or []):
        try:
            evidence_uuids.append(uuid.UUID(str(x)))
        except Exception:
            pass

    return MemoryItem(
        id=uuid.UUID(str(row[0])),
        kind=row[1],
        statement=row[2],
        confidence=row[3],
        active=bool(row[4]),
        evidence_session_ids=evidence_uuids,
        created_at=row[6].isoformat() if row[6] else "",
    )


@app.post("/v1/users/{user_id}/memories/{memory_id}/archive")
def archive_memory(user_id: uuid.UUID, memory_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        row = db.execute(
            text(
                """
                UPDATE memories
                SET active = false, updated_at = NOW()
                WHERE id = :mid AND user_id = :uid
                RETURNING id
                """
            ),
            {"mid": str(memory_id), "uid": str(user_id)},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Memory not found")

        db.commit()

    return {"archived": True}
