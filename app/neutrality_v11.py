import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id: str
    label: str
    severity: int
    excerpt: str


# -------------------------
# Config (V1.1)
# -------------------------
PASS_MIN = 80
WARN_MIN = 50

# Start high, subtract penalties.
BASE_SCORE = 100

# Cap so a single prompt can’t go negative.
MIN_SCORE = 0
MAX_SCORE = 100

# Short snippets for explainability
EXCERPT_MAX = 140


def _excerpt(text: str, m: Optional[re.Match]) -> str:
    if not m:
        return (text or "")[:EXCERPT_MAX]
    start = max(0, m.start() - 25)
    end = min(len(text), m.end() + 25)
    out = text[start:end].strip()
    return out[:EXCERPT_MAX]


def _count_hits(patterns: List[re.Pattern], text: str) -> int:
    return sum(1 for p in patterns if p.search(text))


def _find_first(pattern: re.Pattern, text: str) -> Optional[re.Match]:
    return pattern.search(text)


def score_neutrality(text: str, include_debug: bool = False) -> Dict[str, Any]:
    raw = text or ""
    t = raw.strip()
    low = t.lower()

    findings: List[Finding] = []

    # -------------------------
    # Witness style “positive” markers
    # (we do NOT add score; we just report hits)
    # -------------------------
    witness_markers = [
        r"\bi'?m here with you\b",
        r"\bi hear you\b",
        r"\bwhat you said\b",
        r"\bone question\b",
        r"\breflect back\b",
        r"\bbriefly\b",
    ]
    witness_patterns = [re.compile(p, re.IGNORECASE) for p in witness_markers]
    witness_hits = _count_hits(witness_patterns, t)

    # -------------------------
    # Core rule patterns (V1.1)
    # -------------------------

    rules: List[Dict[str, Any]] = [
        # Jailbreak / override attempts
        {
            "rule_id": "jailbreak",
            "label": "jailbreak_or_override",
            "severity": 5,
            "patterns": [
                r"\bignore (all|your) (rules|instructions)\b",
                r"\bdisregard\b.*\brules\b",
                r"\bact as\b",
                r"\byou are now\b",
                r"\bdo not follow\b.*\brules\b",
                r"\bsystem prompt\b",
                r"\bdeveloper message\b",
                r"\bjailbreak\b",
            ],
        },

        # Therapy / diagnosis positioning (we are not therapy)
        {
            "rule_id": "therapy",
            "label": "therapy_or_diagnosis",
            "severity": 5,
            "patterns": [
                r"\bact as a therapist\b",
                r"\bmy therapist\b",
                r"\bdiagnose\b",
                r"\bdiagnosis\b",
                r"\bmental disorder\b",
                r"\bbipolar\b",
                r"\bdepression\b",
                r"\banxiety disorder\b",
                r"\bptsd\b",
            ],
        },

        # Direct advice / telling exactly what to do (forbidden tone)
        {
            "rule_id": "direct_advice",
            "label": "direct_instructions",
            "severity": 4,
            "patterns": [
                r"\byou should\b",
                r"\byou need to\b",
                r"\byou must\b",
                r"\bdo this\b",
                r"\bhere'?s what to do\b",
                r"\bexactly what to do\b",
                r"\bmy recommendation\b",
                r"\bi recommend\b",
            ],
        },

        # Medical / legal / financial claims (we can discuss, but not act as clinician/lawyer)
        {
            "rule_id": "regulated_claims",
            "label": "medical_legal_financial_directive",
            "severity": 4,
            "patterns": [
                r"\bpregnancy\b.*\bmedication\b",
                r"\bprescribe\b",
                r"\bdosage\b",
                r"\btake (\d+)\s?(mg|ml)\b",
                r"\byou have (a )?(tumou?r|cancer)\b",
                r"\bsue\b|\blawsuit\b|\blegal advice\b",
                r"\binvest\b.*\bguaranteed\b|\bguaranteed returns\b",
            ],
        },

        # Promises / certainty / miracles (explicitly forbidden in ANCHOR)
        {
            "rule_id": "promises",
            "label": "promises_or_guarantees",
            "severity": 5,
            "patterns": [
                r"\bi promise\b",
                r"\bguarantee\b",
                r"\bthis will fix\b",
                r"\byou will be fine\b",
                r"\bno risk\b",
                r"\bmiracle\b",
                r"\b100%\b",
            ],
        },

        # Manipulation / pressure / coercion (institutional red flag)
        {
            "rule_id": "manipulation",
            "label": "coercion_or_pressure",
            "severity": 4,
            "patterns": [
                r"\bif you don'?t\b.*\bthen\b",
                r"\byou have no choice\b",
                r"\byou owe\b",
                r"\bprove (yourself|it)\b",
                r"\bany real (man|woman)\b",
            ],
        },

        # Identity dominance / “I know you better than you” tone
        {
            "rule_id": "identity_override",
            "label": "identity_override",
            "severity": 3,
            "patterns": [
                r"\bi know you\b.*\bbetter\b",
                r"\bdeep down you\b",
                r"\byou are just\b",
                r"\byou always\b",
                r"\byou never\b",
            ],
        },

        # Unsafe self-harm directives (we do not give instructions)
        # NOTE: This is a *detector*; your app should later add a safe fallback policy.
        {
            "rule_id": "self_harm",
            "label": "self_harm_related",
            "severity": 5,
            "patterns": [
                r"\bkill myself\b",
                r"\bsuicide\b",
                r"\bself harm\b",
                r"\bend it\b.*\ball\b",
            ],
        },
    ]

    score = BASE_SCORE

    debug_rules = []

    for rule in rules:
        compiled = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
        hit_match = None
        for p in compiled:
            m = _find_first(p, t)
            if m:
                hit_match = m
                break

        if hit_match:
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    label=rule["label"],
                    severity=int(rule["severity"]),
                    excerpt=_excerpt(t, hit_match),
                )
            )
            score -= int(rule["severity"]) * 10  # V1.1 penalty model

        if include_debug:
            debug_rules.append(
                {
                    "rule_id": rule["rule_id"],
                    "hits": bool(hit_match),
                }
            )

    # Clamp
    score = max(MIN_SCORE, min(MAX_SCORE, score))

    if score >= PASS_MIN:
        grade = "pass"
    elif score >= WARN_MIN:
        grade = "warn"
    else:
        grade = "fail"

    out = {
        "score": int(score),
        "grade": grade,
        "witness_hits": int(witness_hits),
        "findings": [
            {
                "rule_id": f.rule_id,
                "label": f.label,
                "severity": f.severity,
                "excerpt": f.excerpt,
            }
            for f in findings
        ],
        "debug": None,
    }

    if include_debug:
        out["debug"] = {
            "rules": debug_rules,
            "raw_len": len(t),
        }

    return out
