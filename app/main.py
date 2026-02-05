import uuid
import json

from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations
from app.memory_shaping import propose_memory_offer
from app.schemas import (
    CreateSessionResponse,
    SendMessageRequest,
    SendMessageResponse,
    MemoryItem,
    CreateMemoryRequest,
    MemoryOfferResponse,
)

app = FastAPI(title="ANCHOR API")


def _ensure_user_exists(db, user_id: uuid.UUID):
    row = db.execute(
        text("SELECT id FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")


def _validate_memory_statement(statement: str):
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
    # normalize whitespace to avoid invisible mismatches
    return " ".join((s or "").strip().split())


@app.on_event("startup")
def on_startup():
    run_migrations()


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


@app.post("/v1/sessions", response_model=CreateSessionResponse)
def create_session():
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()

    with SessionLocal() as db:
        db.execute(
            text("INSERT INTO users (id) VALUES (:id)"),
            {"id": str(user_id)},
        )
        db.execute(
            text(
                "INSERT INTO sessions (id, user_id, mode, question_used) "
                "VALUES (:sid, :uid, 'witness', false)"
            ),
            {"sid": str(session_id), "uid": str(user_id)},
        )
        db.commit()

    return CreateSessionResponse(
        user_id=user_id,
        session_id=session_id,
        mode="witness",
    )


from app.schemas import CreateSessionForUserResponse  # add to imports at top

@app.post("/v1/users/{user_id}/sessions", response_model=CreateSessionForUserResponse)
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

    return CreateSessionForUserResponse(
        user_id=user_id,
        session_id=session_id,
        mode="witness",
    )


@app.post("/v1/sessions/{session_id}/messages", response_model=SendMessageResponse)
def send_message(session_id: uuid.UUID, payload: SendMessageRequest):
    with SessionLocal() as db:
        row = db.execute(
            text("SELECT id FROM sessions WHERE id = :sid"),
            {"sid": str(session_id)},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Session not found")

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

        # v1 witness reply (presence, not advice)
        reply = (
            "I’m here with you. I’m going to reflect back what I heard, briefly.\n\n"
            f"**What you said:** {payload.content}\n\n"
            "One question: what feels most important in this right now?"
        )

        # store assistant message
        db.execute(
            text(
                "INSERT INTO messages (id, session_id, role, content) "
                "VALUES (:id, :sid, 'assistant', :content)"
            ),
            {
                "id": str(uuid.uuid4()),
                "sid": str(session_id),
                "content": reply,
            },
        )

        db.commit()

    return SendMessageResponse(
        session_id=session_id,
        role="assistant",
        content=reply,
    )


@app.get("/v1/sessions/{session_id}/messages")
def list_messages(session_id: uuid.UUID):
    with SessionLocal() as db:
        row = db.execute(
            text("SELECT id FROM sessions WHERE id = :sid"),
            {"sid": str(session_id)},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Session not found")

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

    result = []
    for r in rows:
        result.append(
            {
                "role": r[0],
                "content": r[1],
                "created_at": r[2].isoformat() if r[2] else None,
            }
        )
    return result


@app.get("/v1/users/{user_id}/memories", response_model=list[MemoryItem])
def list_memories(user_id: uuid.UUID, active: bool = True, kind: str | None = None):
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

    result = []
    for r in rows:
        evidence = r[5] or []
        evidence_uuids = []
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

        # If no strong pattern, return safe default — but avoid repeating it if already saved
        if not offer:
            # Check if the default is already saved as an active memory
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
                {
                    "uid": str(user_id),
                    "kind": DEFAULT_KIND,
                    "statement": DEFAULT_STATEMENT,
                },
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

        # Normal computed-offer flow
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
            {
                "uid": str(user_id),
                "kind": offer_kind,
                "statement": offer_stmt,
            },
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

        # Scarcity rule: max 5 active memories
        count_row = db.execute(
            text(
                "SELECT COUNT(*) FROM memories "
                "WHERE user_id = :uid AND active = true"
            ),
            {"uid": str(user_id)},
        ).fetchone()

        if count_row and int(count_row[0]) >= 5:
            raise HTTPException(
                status_code=400,
                detail="Max active memories reached (5)",
            )

        mem_id = uuid.uuid4()

        evidence_json = [str(x) for x in (payload.evidence_session_ids or [])]
        evidence_str = json.dumps(evidence_json)

        row = db.execute(
            text(
                """
                INSERT INTO memories (
                    id,
                    user_id,
                    kind,
                    statement,
                    evidence_session_ids,
                    confidence,
                    active
                )
                VALUES (
                    :id,
                    :uid,
                    :kind,
                    :statement,
                    CAST(:evidence AS jsonb),
                    :confidence,
                    true
                )
                RETURNING
                    id,
                    kind,
                    statement,
                    confidence,
                    active,
                    evidence_session_ids,
                    created_at
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

    evidence_uuids = []
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
