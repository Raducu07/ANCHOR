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

    # reverse to chronological-ish for nicer scanning
    rows = list(reversed(rows))
    return [(uuid.UUID(str(r[0])), (r[1] or "")) for r in rows]


def _contains_any(text_lower: str, needles: list[str]) -> bool:
    return any(n in text_lower for n in needles)


def compute_offer_debug(db, user_id: uuid.UUID, limit: int = MAX_LOOKBACK_MESSAGES):
    """
    Returns a dict with:
    - offer (or None)
    - debug: counts, evidence, best_key, best_count, sampled texts
    """
    items = fetch_recent_user_texts(db, user_id, limit=limit)

    debug = {
        "user_id": str(user_id),
        "scanned_user_messages": len(items),
        "counts": {"overwhelm_load": 0, "responsibility_conflict": 0, "control_uncertainty": 0},
        "best_key": None,
        "best_count": 0,
        "evidence_session_ids": [],
        "sample_last_5_texts": [t for (_, t) in items[-5:]],
    }

    if not items:
        return {"offer": None, "debug": debug}

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

    evidence = {k: set() for k in signals}

    for session_id, txt in items:
        low = (txt or "").strip().lower()
        if not low:
            continue

        for k, needles in signals.items():
            if _contains_any(low, needles):
                debug["counts"][k] += 1
                evidence[k].add(session_id)

    best_key = max(debug["counts"], key=lambda k: debug["counts"][k])
    best_count = debug["counts"][best_key]

    debug["best_key"] = best_key
    debug["best_count"] = best_count
    debug["evidence_session_ids"] = [str(x) for x in list(evidence[best_key])[:5]]

    # Threshold
    if best_count < 2:
        return {"offer": None, "debug": debug}

    # Map signal -> offer (neutral, non-advice)
    if best_key == "overwhelm_load":
        kind = "recurring_tension"
        statement = "Across multiple moments, you describe your load exceeding your available time."
    elif best_key == "responsibility_conflict":
        kind = "values_vs_emphasis"
        statement = "You repeatedly describe prioritising obligations even when it conflicts with personal bandwidth."
    else:
        kind = "decision_posture"
        statement = "You repeatedly describe uncertainty and a desire for firmer footing before acting."

    # Confidence from frequency
    confidence = "tentative"
    if best_count >= 4:
        confidence = "consistent"
    elif best_count >= 3:
        confidence = "emerging"

    offer = {
        "kind": kind,
        "statement": statement,
        "confidence": confidence,
        "evidence_session_ids": [uuid.UUID(x) for x in debug["evidence_session_ids"]],
    }

    return {"offer": offer, "debug": debug}


def propose_memory_offer(db, user_id: uuid.UUID):
    """
    Returns a dict shaped like CreateMemoryRequest, plus evidence_session_ids.
    Or returns None if no strong pattern.
    """
    out = compute_offer_debug(db, user_id, limit=MAX_LOOKBACK_MESSAGES)
    return out["offer"]
