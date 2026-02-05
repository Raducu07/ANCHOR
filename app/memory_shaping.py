import uuid
from sqlalchemy import text

# Rule-based, no LLM. Produces at most ONE memory offer.

MAX_LOOKBACK_MESSAGES = 80  # safe default


def fetch_recent_user_texts(db, user_id: uuid.UUID, limit: int = MAX_LOOKBACK_MESSAGES):
    """
    Returns a list of tuples: (session_id, content)
    Only user role messages.
    """
    rows = db.execute(
        text(
            """
            SELECT m.session_id, m.content
            FROM messages m
            JOIN sessions s ON s.id = m.session_id
            WHERE s.user_id = :uid
              AND m.role = 'user'
            ORDER BY m.created_at DESC, m.id DESC
            LIMIT :limit
            """
        ),
        {"uid": str(user_id), "limit": int(limit)},
    ).fetchall()

    # reverse to chronological-ish for nicer scanning (optional)
    rows = list(reversed(rows))
    return [(uuid.UUID(str(r[0])), r[1] or "") for r in rows]
