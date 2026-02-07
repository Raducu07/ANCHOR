# app/main.py
import uuid
import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations

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
    - A4 upgrades (optional): policy_version, neutrality_version, decision_trace

    Safe by design: never raises upward.
    """
    try:
        if not user_id:
            return

        # Your governance.py emits:
        # audit = { "decision": {...}, "findings": [...], "notes": {...}, ... }
        decision = audit.get("decision") or {}
        findings = audit.get("findings") or []
        notes = audit.get("notes") or {}

        allowed = bool(decision.get("allowed", True))
        replaced = bool(decision.get("replaced", False))
        score = int(decision.get("score", 0) or 0)
        grade = str(decision.get("grade", "unknown") or "unknown")
        reason = str(decision.get("reason", "") or "")

        # Compact deterministic decision trace (A4)
        triggered_rule_ids = []
        try:
            for f in findings:
                rid = (f.get("rule_id") or "").strip()
                if rid:
                    triggered_rule_ids.append(rid)
        except Exception:
            triggered_rule_ids = []

        decision_trace = {
            "min_score_allow": notes.get("min_score_allow"),
            "hard_block_rules": notes.get("hard_block_rules"),
            "soft_rules": notes.get("soft_rules"),
            "triggered_rule_ids": triggered_rule_ids[:25],
            "score": score,
            "grade": grade,
            "replaced": replaced,
            "reason": reason,
        }

        # Versions (A4). Keep stable strings now; later you can read from governance_config.
        policy_version = "gov-v1.0"
        neutrality_version = "n-v1.1"

        # Detect whether A4 columns exist (so we don't crash on older DBs)
        cols = db.execute(
            text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'governance_events'
                """
            )
        ).fetchall()
        colset = {str(r[0]) for r in cols}

        has_a4 = {"policy_version", "neutrality_version", "decision_trace"}.issubset(colset)

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
                    "audit": json.dumps(audit),
                    "policy_version": policy_version,
                    "neutrality_version": neutrality_version,
                    "decision_trace": json.dumps(decision_trace),
                },
            )
        else:
            # A3-only schema (your latest posted schema.sql)
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
                    "audit": json.dumps(audit),
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

        # fetch user_id for this session (for governance + audit)
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
        final_reply, decision, audit = govern_output(
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

        # A3 persist audit event (same transaction)
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
# A3 — Governance audit endpoints
# ---------------------------

@app.get("/v1/users/{user_id}/governance-events")
def list_governance_events_for_user(user_id: uuid.UUID, limit: int = 50):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        rows = db.execute(
            text(
                """
                SELECT
                  id, user_id, session_id, mode,
                  allowed, replaced, score, grade, reason,
                  findings, decision, notes,
                  created_at
                FROM governance_events
                WHERE user_id = :uid
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"uid": str(user_id), "limit": int(limit)},
        ).fetchall()

    return [
        {
            "id": str(r[0]),
            "user_id": str(r[1]),
            "session_id": str(r[2]) if r[2] else None,
            "mode": r[3],
            "allowed": bool(r[4]),
            "replaced": bool(r[5]),
            "score": int(r[6]),
            "grade": r[7],
            "reason": r[8],
            "findings": r[9] or [],
            "decision": r[10] or {},
            "notes": r[11] or {},
            "created_at": r[12].isoformat() if r[12] else None,
        }
        for r in rows
    ]


@app.get("/v1/sessions/{session_id}/governance-events")
def list_governance_events_for_session(session_id: uuid.UUID, limit: int = 50):
    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)

        rows = db.execute(
            text(
                """
                SELECT
                  id, user_id, session_id, mode,
                  allowed, replaced, score, grade, reason,
                  findings, decision, notes,
                  created_at
                FROM governance_events
                WHERE session_id = :sid
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"sid": str(session_id), "limit": int(limit)},
        ).fetchall()

    return [
        {
            "id": str(r[0]),
            "user_id": str(r[1]),
            "session_id": str(r[2]) if r[2] else None,
            "mode": r[3],
            "allowed": bool(r[4]),
            "replaced": bool(r[5]),
            "score": int(r[6]),
            "grade": r[7],
            "reason": r[8],
            "findings": r[9] or [],
            "decision": r[10] or {},
            "notes": r[11] or {},
            "created_at": r[12].isoformat() if r[12] else None,
        }
        for r in rows
    ]


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
