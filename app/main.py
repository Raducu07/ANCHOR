import uuid
from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations
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
        raise HTTPException(status_code=400, detail="Memory statement violates neutrality rules")

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


# ✅ NEW (Step 2): root endpoint so base URL isn't Not Found
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


@app.post(
    "/v1/sessions/{session_id}/messages",
    response_model=SendMessageResponse,
)
def send_message(session_id: uuid.UUID, payload: SendMessageRequest):
    with SessionLocal() as db:
        row = db.execute(
            text("SELECT id FROM sessions WHERE id = :sid"),
            {"sid": str(session_id)},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Session not found")

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

        reply = (
            "I’m here with you. I’m going to reflect back what I heard, briefly.\n\n"
            f"**What you said:** {payload.content}\n\n"
            "One question: what feels most important in this right now?"
        )

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


# ✅ NEW (Step 1): list messages for a session (history)
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
