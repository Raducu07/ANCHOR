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

    # Reverse to chronological-ish for nicer scanning (optional)
    rows = list(reversed(rows))
    return [(uuid.UUID(str(r[0])), (r[1] or "")) for r in rows]


def _contains_any(text_lower: str, needles: list[str]) -> bool:
    # Simple substring matching (v1). Deterministic and fast.
    return any(n in text_lower for n in needles)


def _is_duplicate_active_memory(db, user_id: uuid.UUID, kind: str, statement: str) -> bool:
    row = db.execute(
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
        {"uid": str(user_id), "kind": kind, "statement": statement},
    ).fetchone()
    return bool(row)


def propose_memory_offer(db, user_id: uuid.UUID):
    """
    Returns a dict shaped like CreateMemoryRequest, plus evidence_session_ids.
    Or returns None if no strong pattern.
    """

    items = fetch_recent_user_texts(db, user_id, limit=MAX_LOOKBACK_MESSAGES)
    if not items:
        return None

    # Lexical signals (v1).
    # Keep these simple & neutral. Expand later, but keep determinism.
    signals = {
        "overwhelm_load": [
            "overwhelmed",
            "too much",
            "can't keep up",
            "cannot keep up",
            "exhausted",
            "burnt out",
            "burned out",
            "drained",
            "no time",
            "not enough time",
            "stressed",
            "pressure",
            "workload",
            "load",
            "time is fixed",
            "responsibilities expand",
        ],
        "responsibility_conflict": [
            "i have to",
            "i must",
            "obligation",
            "obligations",
            "responsible",
            "expectations",
            "everyone",
            "depend on me",
            "duty",
            "i keep saying yes",
        ],
        "control_uncertainty": [
            "i don't know",
            "i do not know",
            "uncertain",
            "confused",
            "not sure",
            "what if",
            "worried",
            "anxious",
        ],
    }

    # We want evidence from DIFFERENT sessions, not just repeated lines in one session.
    counts = {k: 0 for k in signals}
    evidence_sessions = {k: set() for k in signals}

    for session_id, txt in items:
        low = (txt or "").strip().lower()
        if not low:
            continue

        for k, needles in signals.items():
            if _contains_any(low, needles):
                counts[k] += 1
                evidence_sessions[k].add(session_id)

    # Pick the best supported pattern
    best_key = max(counts, key=lambda k: counts[k])
    best_count = counts[best_key]
    best_sessions = evidence_sessions[best_key]

    # Thresholds (tune later):
    # Require at least 2 hits AND at least 2 distinct sessions
    if best_count < 2 or len(best_sessions) < 2:
        return None

    # Map signal -> memory offer (neutral, non-advice)
    if best_key == "overwhelm_load":
        kind = "recurring_tension"
        statement = "Across multiple moments, you describe your load exceeding your available time."
    elif best_key == "responsibility_conflict":
        kind = "values_vs_emphasis"
        statement = "You repeatedly describe prioritising obligations even when it conflicts with personal bandwidth."
    else:  # control_uncertainty
        kind = "decision_posture"
        statement = "You repeatedly describe uncertainty and a desire for firmer footing before acting."

    # Confidence from frequency
    if best_count >= 4:
        confidence = "consistent"
    elif best_count >= 3:
        confidence = "emerging"
    else:
        confidence = "tentative"

    # ✅ Deterministic evidence ordering: preserve the order sessions first appeared
    # We scan items chronologically; collect first-seen session IDs.
    ordered_unique = []
    seen = set()
    for session_id, txt in items:
        if session_id in best_sessions and session_id not in seen:
            ordered_unique.append(session_id)
            seen.add(session_id)

    evidence_session_ids = ordered_unique[:5]

    # ✅ Dedupe: if already saved as an active memory, do NOT re-offer it
    if _is_duplicate_active_memory(db, user_id, kind, statement):
        return None

    return {
        "kind": kind,
        "statement": statement,
        "confidence": confidence,
        "evidence_session_ids": evidence_session_ids,
    }

