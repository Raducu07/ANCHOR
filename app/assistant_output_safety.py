# app/assistant_output_safety.py
#
# M6.6 — Post-output safety validation for Assistant drafts.
#
# The validator scans the transient draft AFTER the model returns it and
# BEFORE the route hands it back to the caller. If unsafe clinical content
# is detected, the route blocks the draft (run_status = output_blocked)
# without returning or persisting the raw text.
#
# Doctrine:
#   * The raw draft is never logged here.
#   * The validator returns ONLY safety/refusal codes — never the
#     matched substring, never the draft excerpt.
#   * Failure-closed: if any rule fires, the draft is blocked.
#   * The mandatory review line is itself a required ANCHOR governance
#     marker; a draft missing it is treated as unsafe.
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple


OUTPUT_BLOCKED_MESSAGE = (
    "ANCHOR blocked this draft because it may contain clinical judgement "
    "or unsafe clinical content. Please revise the clinician-confirmed "
    "facts and try again."
)


# Controlled vocabulary. Names align with AssistantSafetyCode style in
# app/assistant_models.py and the input-side codes in portal_assistant.py.
SAFETY_CODE_DIAGNOSIS_LANGUAGE = "output_diagnosis_language"
SAFETY_CODE_TREATMENT_RECOMMENDATION = "output_treatment_recommendation"
SAFETY_CODE_PRESCRIBING_OR_DOSE = "output_prescribing_or_dose"
SAFETY_CODE_TRIAGE_OR_DISCHARGE_DECISION = "output_triage_or_discharge_decision"
SAFETY_CODE_PROGNOSIS_OR_CLINICAL_JUDGEMENT = "output_prognosis_or_clinical_judgement"
SAFETY_CODE_MISSING_REVIEW_WARNING = "output_missing_review_warning"
SAFETY_CODE_IDENTIFIER_RISK = "output_contains_identifier_risk"
SAFETY_CODE_UNCLASSIFIED_SAFETY_RISK = "output_unclassified_safety_risk"


REQUIRED_REVIEW_PHRASES: Tuple[str, ...] = (
    "REVIEW REQUIRED",
    "ANCHOR does not replace professional judgement",
)


# Pattern tables. Each entry is (code, [patterns]). All patterns are
# compiled once at import time and matched case-insensitively against a
# whitespace-collapsed lowercase view of the draft for the prose checks;
# identifier checks operate on the raw draft.

_DOSE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bgive\s+\d+(?:\.\d+)?\s*(?:mg|ml|mls|g|mcg|microgram[s]?|tablet[s]?|drop[s]?)\b", re.IGNORECASE),
    re.compile(r"\b\d+(?:\.\d+)?\s*mg\s*/\s*kg\b", re.IGNORECASE),
    re.compile(r"\b\d+(?:\.\d+)?\s*ml\s*/\s*kg\b", re.IGNORECASE),
    re.compile(r"\bdos(?:e|age|ing)\b", re.IGNORECASE),
    re.compile(r"\badminister\b", re.IGNORECASE),
    re.compile(r"\bprescrib(?:e|ing|ed|es|ption)\b", re.IGNORECASE),
    re.compile(r"\btake\s+\d+(?:\.\d+)?\s*(?:tablet|capsule|mg|ml|drop)", re.IGNORECASE),
    re.compile(r"\b(?:once|twice|three\s+times|four\s+times)\s+(?:a\s+)?(?:daily|day)\b", re.IGNORECASE),
    re.compile(r"\bevery\s+\d+\s*(?:hours?|hrs?|h)\b", re.IGNORECASE),
    re.compile(r"\b(?:bid|tid|qid|sid)\b", re.IGNORECASE),
    # Route abbreviations as standalone tokens, e.g. "po", "iv", "im", "sc".
    re.compile(r"(?:^|[^a-zA-Z])(?:po|iv|im|sc)\b(?=\s|$|[.,;:!?])", re.IGNORECASE),
]

_DIAGNOSIS_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bdiagnosed\s+with\b", re.IGNORECASE),
    re.compile(r"\bdiagnosis\s+is\b", re.IGNORECASE),
    re.compile(r"\bwe\s+think\s+this\s+is\b", re.IGNORECASE),
    re.compile(r"\blikely\s+has\s+\w+", re.IGNORECASE),
    re.compile(r"\bdifferential\s+diagnos(?:is|es)\b", re.IGNORECASE),
    re.compile(r"\bruled\s+out\b", re.IGNORECASE),
    re.compile(r"\bconfirmed\s+(?:case\s+of\s+)?[a-z]+itis\b", re.IGNORECASE),
]

_TREATMENT_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bwe\s+recommend\s+(?:treatment|starting|that\s+you\s+start)", re.IGNORECASE),
    re.compile(r"\btreatment\s+plan\b", re.IGNORECASE),
    re.compile(r"\bstart(?:ing)?\s+(?:treatment|antibiotic[s]?|nsaid[s]?|medication)", re.IGNORECASE),
    re.compile(r"\b(?:needs|requires)\s+surgery\b", re.IGNORECASE),
    re.compile(r"\bshould\s+be\s+treated\s+with\b", re.IGNORECASE),
    re.compile(r"\bantibiotic[s]?\s+(?:are|will\s+be)\s+(?:needed|required|prescribed|started)", re.IGNORECASE),
    re.compile(r"\bpain\s+relief\s+(?:should\s+be|will\s+be|is)\b", re.IGNORECASE),
]

# Triage/discharge — intentionally narrow. The validator MUST NOT block
# ordinary "ready for collection" / "ready to go home" phrasing that
# typically comes straight from clinician-confirmed facts.
_TRIAGE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bsafe\s+to\s+discharge\s+because\b", re.IGNORECASE),
    re.compile(r"\bno\s+need\s+to\s+see\s+a\s+vet\b", re.IGNORECASE),
    re.compile(r"\bdoes(?:\s+not|n['’]t)\s+need\s+urgent\s+care\b", re.IGNORECASE),
    re.compile(r"\bcan\s+wait\s+until\s+tomorrow\b", re.IGNORECASE),
    re.compile(r"\bemergency\s+(?:is\s+)?not\s+required\b", re.IGNORECASE),
    re.compile(r"\bgo\s+home\s+without\s+further\s+checks\b", re.IGNORECASE),
    re.compile(r"\bclinically\s+stable\s+for\s+discharge\b", re.IGNORECASE),
]

_PROGNOSIS_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bprognosis\s+is\b", re.IGNORECASE),
    re.compile(r"\b(?:excellent|good|fair|poor|guarded)\s+prognosis\b", re.IGNORECASE),
    re.compile(r"\bwill\s+make\s+a\s+full\s+recovery\b", re.IGNORECASE),
    re.compile(r"\bno\s+complications\s+(?:are\s+)?expected\b", re.IGNORECASE),
    re.compile(r"\brisk\s+is\s+low\b", re.IGNORECASE),
    re.compile(r"\bthis\s+is\s+not\s+serious\b", re.IGNORECASE),
]

# Identifier risk — operate on raw draft (case-insensitive). Same shapes
# the input-side PII detector uses, so behaviour is consistent.
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b\+?\d[\d\s().-]{7,}\d\b")
_UK_POSTCODE_RE = re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b", re.IGNORECASE)


_PROSE_RULES: List[Tuple[str, List[Pattern[str]]]] = [
    (SAFETY_CODE_PRESCRIBING_OR_DOSE, _DOSE_PATTERNS),
    (SAFETY_CODE_DIAGNOSIS_LANGUAGE, _DIAGNOSIS_PATTERNS),
    (SAFETY_CODE_TREATMENT_RECOMMENDATION, _TREATMENT_PATTERNS),
    (SAFETY_CODE_TRIAGE_OR_DISCHARGE_DECISION, _TRIAGE_PATTERNS),
    (SAFETY_CODE_PROGNOSIS_OR_CLINICAL_JUDGEMENT, _PROGNOSIS_PATTERNS),
]


@dataclass(frozen=True)
class AssistantOutputSafetyResult:
    """Validator output. Contains only governance codes — never any
    excerpt of the draft."""

    allowed: bool
    safety_flags: List[str] = field(default_factory=list)
    refusal_reason_codes: List[str] = field(default_factory=list)


def _ordered_unique(values: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _check_required_review_phrases(draft: str) -> bool:
    """Both required phrases must appear in the draft, case-insensitive.
    Order is not required."""
    if not draft:
        return False
    haystack = draft.lower()
    return all(phrase.lower() in haystack for phrase in REQUIRED_REVIEW_PHRASES)


def _scan_prose_rules(draft: str) -> List[str]:
    """Return ordered, de-duplicated list of safety codes that fire on
    `draft`. Uses a whitespace-collapsed view to dampen line-break
    sensitivity of multi-word patterns."""
    if not draft:
        return []
    # Collapse any run of whitespace to a single space so multi-word
    # patterns survive line wrapping.
    collapsed = re.sub(r"\s+", " ", draft)

    codes: List[str] = []
    for code, patterns in _PROSE_RULES:
        for pat in patterns:
            if pat.search(collapsed):
                codes.append(code)
                break
    return _ordered_unique(codes)


def _scan_identifier_risk(draft: str) -> bool:
    """Return True if the draft contains an email, phone, or UK postcode.

    Placeholder tokens of the form `[CONFIRM: …]` never contain '@' or
    long digit runs or postcode-shaped tokens, so they don't trigger
    this check by construction."""
    if not draft:
        return False
    if _EMAIL_RE.search(draft):
        return True
    if _PHONE_RE.search(draft):
        return True
    if _UK_POSTCODE_RE.search(draft):
        return True
    return False


# M6.7 — Conservative profile adds a small handful of stricter rules on
# top of the standard pattern table. The validator is NEVER disabled —
# 'off' is not a legal profile value and is rejected upstream.
_CONSERVATIVE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bmonitor\s+(?:at\s+)?home\b", re.IGNORECASE),
    re.compile(r"\bkeep\s+an\s+eye\s+on\b", re.IGNORECASE),
    re.compile(r"\bwait\s+and\s+see\b", re.IGNORECASE),
]


def validate_client_communication_output(
    draft: str,
    profile: str = "standard",
) -> AssistantOutputSafetyResult:
    """Run all post-output checks. Returns an allow/block decision plus
    the codes that fired. NEVER stores or returns any excerpt of `draft`.

    `profile` may be 'standard' or 'conservative'. Unknown values fall
    back to 'standard' (failure-closed: extra checks would not run, but
    no rule is silently dropped)."""
    codes: List[str] = []

    # Rule 1 — required review warning. A missing warning is itself a
    # block because ANCHOR's governance contract requires every draft to
    # carry it verbatim.
    if not _check_required_review_phrases(draft):
        codes.append(SAFETY_CODE_MISSING_REVIEW_WARNING)

    # Rules 2–6 — prose patterns (dose / diagnosis / treatment /
    # triage / prognosis).
    codes.extend(_scan_prose_rules(draft))

    # Rule 7 — identifier risk.
    if _scan_identifier_risk(draft):
        codes.append(SAFETY_CODE_IDENTIFIER_RISK)

    # M6.7 — Conservative profile: extra triage-adjacent patterns. The
    # match still routes to the existing triage code so frontends and
    # audit do not have to learn a new vocabulary.
    if profile == "conservative" and draft:
        collapsed = re.sub(r"\s+", " ", draft)
        for pat in _CONSERVATIVE_PATTERNS:
            if pat.search(collapsed):
                codes.append(SAFETY_CODE_TRIAGE_OR_DISCHARGE_DECISION)
                break

    codes = _ordered_unique(codes)
    allowed = len(codes) == 0
    return AssistantOutputSafetyResult(
        allowed=allowed,
        safety_flags=codes,
        refusal_reason_codes=codes,
    )
