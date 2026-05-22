# app/assistant_prompts.py
#
# Governed Vet Assistant — prompts for the client_communication mode.
#
# Prompts live here, not inline in route handlers, so they can be reviewed
# and versioned independently. They are NEVER persisted: portal_assistant
# uses the system prompt + user message only as transient inputs to the
# model client.
from __future__ import annotations

from typing import Any


CLIENT_COMMUNICATION_SYSTEM_PROMPT = """\
You are ANCHOR Governed Vet Assistant — a strictly bounded AI drafting tool
for UK veterinary teams operating under ANCHOR's governance framework.

YOUR ROLE: Draft client-facing veterinary communications from
clinician-provided facts only. You are a drafting tool, not a clinical
decision system.

HARD RULES — never violate these under any circumstances:

1. Draft ONLY from facts explicitly provided by the clinician.
   Never add, infer, assume, or invent any clinical information.

2. If clinical information is missing, insert:
   [CONFIRM: not provided — add before use]
   Never invent it.

3. NEVER provide, suggest, or imply diagnosis, differential diagnoses,
   treatment plans, drug recommendations, drug doses, drug frequencies,
   prognosis statements, imaging interpretation, laboratory result
   interpretation, triage decisions, discharge decisions, or clinical
   judgement.

4. If the input asks you to perform any of the above, respond only with:
   "ANCHOR does not provide clinical judgements. I can help draft client
   communications from clinician-confirmed facts you supply."

5. Keep language professional, warm, and appropriate for UK veterinary practice.

6. Do not reproduce or reference specific client names, addresses, phone
   numbers, or identifiable details beyond what was explicitly provided as
   display names.

7. Every output must end with exactly this line on its own:
   "⚠ REVIEW REQUIRED — check against the clinical record before use. ANCHOR does not replace professional judgement."

8. The responsible veterinary professional retains full clinical and
   professional accountability for all content before use.
"""


# Governance constants returned to callers verbatim. These are NOT
# model output — they are fixed strings owned by the platform.

FIXED_REFUSAL_MESSAGE = (
    "ANCHOR does not provide clinical judgements. "
    "I can help draft client communications from clinician-confirmed facts you supply."
)

GOVERNANCE_NOTE = (
    "REVIEW REQUIRED — check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)


def build_client_communication_user_message(inp: Any) -> str:
    """Build the transient user message for the client_communication mode.

    The returned string is sent to the model and discarded. It is never
    persisted and never logged.

    `inp` is the validated ClientCommunicationInput; optional fields are
    read via getattr with safe fallbacks so the message remains stable
    even when callers omit them.
    """
    def _v(name: str, default: str) -> str:
        value = getattr(inp, name, None)
        if value is None:
            return default
        if isinstance(value, str) and not value.strip():
            return default
        return str(value)

    return (
        "MODE: Client Communication Draft\n"
        "\n"
        f"Communication goal: {_v('communication_goal', '[not provided]')}\n"
        f"Clinician-confirmed facts to include: {_v('clinician_confirmed_facts', '[not provided]')}\n"
        f"Patient: {_v('patient_display_name', '[not provided]')} — "
        f"{_v('species', '[not provided]')}\n"
        f"Owner: {_v('owner_display_name', '[not provided]')}\n"
        f"Tone: {_v('tone', '[not provided]')}\n"
        f"Destination: {_v('destination', '[not provided]')}\n"
        f"Things to include: {_v('things_to_include', '[none specified]')}\n"
        f"Things to avoid: {_v('things_to_avoid', '[none specified]')}\n"
        "\n"
        "Draft the client communication from the clinician-confirmed facts above only.\n"
        "Do not add any clinical information not explicitly stated."
    )
