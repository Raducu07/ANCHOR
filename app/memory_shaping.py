import re
import uuid
from sqlalchemy import text

# Memory kinds allowed by your API
KIND_RECURRING_TENSION = "recurring_tension"


def propose_memory_offer(db, user_id: uuid.UUID):
    """
    Rule-based memory shaping V1.
    - Reads recent USER messages for this user across recent sessions.
    - Detects "load > time" / overwhelm / obligation expansion pattern.
    - Returns ONE offer dict or None.
    """

    # 1) Pull recent user messages (last 60 user messages is plenty for v1)
    rows = db.execute(
        text(
            """
            SELECT
                m.content,
                s.id AS session_id,
                m.created_at
            FROM messages m
            JOIN sessions s ON s.id = m.session_id
            WHERE s.user_id = :uid
              AND m.role = 'user'
            ORDER BY m.created_at DESC
            LIMIT 60
            """
        ),
        {"uid": str(user_id)},
    ).fetchall()

    if not rows:
        return None

    # 2) Define simple lexical signals (neutral, non-clinical)
    # We want to detect: time scarcity + load growth + overwhelmed/pressure/obligations
    patterns = [
        r"\boverwhelm(ed|ing)?\b",
        r"\btoo much\b",
        r"\b(can'?t|cannot)\s+cope\b",
        r"\bno time\b",
        r"\bnot enough time\b",
        r"\btime\b.*\b(run|running)\s+out\b",
        r"\bbehind\b",
        r"\bpressure\b",
        r"\bobligations?\b",
        r"\bload\b",
        r"\bworkload\b",
        r"\btoo many\b",
        r"\bkeeps?\s+(growing|increasing|expanding)\b",
        r"\bmore and more\b",
        r"\bexceed(s|ing)?\b.*\btime\b",
        r"\btime\b.*\bexceed(s|ing)?\b",
        r"\bsqueez(e|ing)\s+out\b",
        r"\bcrowd(s|ing)\s+out\b",
    ]
    rx = re.compile("|".join(patterns), re.IGNORECASE)

    # 3) Score messages + collect evidence sessions
    hit_sessions = []
    hits = 0

    for content, session_id, _created_at in rows:
        if not content:
            continue
        if rx.search(content):
            hits += 1
            hit_sessions.append(str(session_id))

    # Need at least 2 hits across at least 2 different sessions
    unique_sessions = list(dict.fromkeys(hit_sessions))  # preserve order, unique
    if hits < 2 or len(unique_sessions) < 2:
        return None

    evidence = unique_sessions[:3]  # keep small

    # 4) Return a single neutral statement (no advice, no promises, no therapy)
    statement = "Across multiple moments, you describe your load exceeding your available time."

    return {
        "kind": KIND_RECURRING_TENSION,
        "statement": statement,
        "confidence": "emerging" if hits < 4 else "consistent",
        "evidence_session_ids": [uuid.UUID(x) for x in evidence],
    }
