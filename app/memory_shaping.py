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
    
def _contains_any(text_lower: str, needles: list[str]) -> bool:
    return any(n in text_lower for n in needles)


def propose_memory_offer(db, user_id: uuid.UUID):
    """
    Returns a dict shaped like CreateMemoryRequest, plus evidence_session_ids.
    Or returns None if no strong pattern.
    """

    items = fetch_recent_user_texts(db, user_id, limit=MAX_LOOKBACK_MESSAGES)
    if not items:
        return None

    # Simple lexical signals (v1). We'll expand later.
    signals = {
        "overwhelm_load": [
            "overwhelmed", "too much", "can't keep up", "exhausted", "burnt out",
            "drained", "no time", "stressed", "pressure"
        ],
        "responsibility_conflict": [
            "i have to", "i must", "obligation", "responsible", "expectations",
            "everyone", "depend on me", "duty"
        ],
        "control_uncertainty": [
            "i don't know", "uncertain", "confused", "not sure", "what if",
            "worried", "anxious"
        ],
    }

    counts = {k: 0 for k in signals}
    evidence = {k: set() for k in signals}

    for session_id, txt in items:
        low = (txt or "").strip().lower()
        if not low:
            continue

        for k, needles in signals.items():
            if _contains_any(low, needles):
                counts[k] += 1
                evidence[k].add(session_id)

    # Decision: pick the best supported pattern
    best_key = max(counts, key=lambda k: counts[k])
    best_count = counts[best_key]

    # thresholds (tune later)
    if best_count < 2:
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
    confidence = "tentative"
    if best_count >= 4:
        confidence = "consistent"
    elif best_count >= 3:
        confidence = "emerging"

    evidence_session_ids = list(evidence[best_key])[:5]

    return {
        "kind": kind,
        "statement": statement,
        "confidence": confidence,
        "evidence_session_ids": evidence_session_ids,
    }
