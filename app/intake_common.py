from __future__ import annotations

import re
from typing import Optional, Tuple

DEMO_REQUEST_STATUSES = ("new", "contacted", "booked", "qualified", "closed")
START_REQUEST_STATUSES = ("new", "contacted", "onboarding", "qualified", "closed")

MAX_CHAT_QUESTION_LENGTH = 500
MAX_TEXTAREA_LENGTH = 4000

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d[\d\s().-]{6,}\d)(?!\w)"
)


def normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    out = value.strip()
    return out or None


def clamp_text(value: str, *, max_length: int) -> str:
    value = (value or "").strip()
    if len(value) <= max_length:
        return value
    return value[:max_length].rstrip()


def redact_contact_details(value: str) -> Tuple[Optional[str], bool, bool]:
    source = (value or "").strip()
    if not source:
        return None, False, False

    contains_email = bool(_EMAIL_RE.search(source))
    contains_phone = bool(_PHONE_RE.search(source))

    redacted = _EMAIL_RE.sub("[redacted-email]", source)
    redacted = _PHONE_RE.sub("[redacted-phone]", redacted)

    if redacted == source:
        return None, contains_email, contains_phone

    return clamp_text(redacted, max_length=MAX_CHAT_QUESTION_LENGTH), contains_email, contains_phone


def has_honeypot_value(*values: Optional[str]) -> bool:
    return any(bool((value or "").strip()) for value in values)
