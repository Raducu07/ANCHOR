# app/assistant_contracts.py
"""
Mode contracts for the Governed Vet Assistant (PR 1).

These contracts are structured data, not free-form documentation. The shape
returned from `build_contract_discovery_payload()` is the wire contract for
GET /v1/assistant/contracts.

PR 1 doctrine:
- client_communication is the only ACTIVE mode.
- The other five modes are contract_defined_only.
- Storage policy is metadata_only_by_default.
- human_review_required is true for every mode.
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.assistant_models import AssistantMode

CONTRACT_VERSION: str = "assistant_contract_v1"
STORAGE_POLICY: str = "metadata_only_by_default"
HUMAN_REVIEW_REQUIRED: bool = True

STATUS_ACTIVE: str = "active"
STATUS_CONTRACT_ONLY: str = "contract_defined_only"


# ============================================================
# Mode contracts (declarative)
# ============================================================
#
# Every entry has:
#   - mode             (AssistantMode value)
#   - version          (per-mode contract version)
#   - status           (active | contract_defined_only)
#   - purpose          (one-line purpose statement)
#   - required_fields  (input fields the mode requires)
#   - optional_fields  (input fields the mode may accept)
#   - allowed_outputs  (output types within scope, when defined)
#   - prohibited_outputs (output types that are always blocked)
#   - hard_boundary    (one-line clinical/safety boundary)
#   - human_review_required (always True in PR 1)
#   - content_storage  (always "not_stored_by_default" in PR 1)
#
# Prohibited outputs intentionally use plain natural-language tokens so that
# the front-end and audit pipelines can render them without translation.

_CLINICAL_PROHIBITED: List[str] = [
    "diagnosis",
    "treatment recommendation",
    "prescribing",
    "dose calculation",
    "imaging interpretation",
    "lab interpretation",
    "triage/discharge decision",
]


MODE_CONTRACTS: Dict[AssistantMode, Dict[str, Any]] = {
    AssistantMode.client_communication: {
        "mode": AssistantMode.client_communication.value,
        "version": "client_communication_v1",
        "status": STATUS_ACTIVE,
        "purpose": "Draft client-facing communication from clinician-provided facts only.",
        "required_fields": [
            "communication_goal",
            "clinician_confirmed_facts",
        ],
        "optional_fields": [
            "patient_display_name",
            "species",
            "owner_display_name",
            "tone",
            "things_to_include",
            "things_to_avoid",
            "destination",
            "reviewer_role",
        ],
        "allowed_outputs": [
            "client update",
            "appointment follow-up",
            "post-consult summary",
            "non-urgent advice already confirmed by clinician",
            "complaint response draft",
            "administrative client message",
        ],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": (
            "No diagnosis, treatment recommendation, drug selection, dose calculation, "
            "prognosis unless explicitly provided, triage decision, or emergency advice "
            "beyond directing client to contact a veterinary professional."
        ),
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
    AssistantMode.discharge_instructions: {
        "mode": AssistantMode.discharge_instructions.value,
        "version": "discharge_instructions_v1",
        "status": STATUS_CONTRACT_ONLY,
        "purpose": "Draft discharge instructions from clinician-confirmed facts.",
        "required_fields": [
            "procedure_or_condition",
            "clinician_confirmed_plan",
            "clinician_confirmed_medications_or_empty",
            "follow_up_instructions_or_empty",
        ],
        "optional_fields": [],
        "allowed_outputs": [],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": (
            "Must not invent medications, doses, diagnosis, prognosis, warning signs, "
            "or follow-up instructions. If medications missing, use "
            "[CONFIRM: medication details not provided] placeholder."
        ),
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
    AssistantMode.referral_summary: {
        "mode": AssistantMode.referral_summary.value,
        "version": "referral_summary_v1",
        "status": STATUS_CONTRACT_ONLY,
        "purpose": "Structure a referral/admin summary from provided history and findings.",
        "required_fields": [
            "reason_for_referral",
            "history",
            "clinician_confirmed_findings",
            "requested_action",
        ],
        "optional_fields": [],
        "allowed_outputs": [],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": "No differential diagnoses or interpretation unless explicitly provided.",
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
    AssistantMode.internal_handover: {
        "mode": AssistantMode.internal_handover.value,
        "version": "internal_handover_v1",
        "status": STATUS_CONTRACT_ONLY,
        "purpose": "Create internal handover from source facts.",
        "required_fields": [
            "patient_status",
            "active_plan",
            "outstanding_tasks",
        ],
        "optional_fields": [],
        "allowed_outputs": [],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": "No new treatment plan, no escalation decision, no dose/rate changes.",
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
    AssistantMode.dictation_to_note: {
        "mode": AssistantMode.dictation_to_note.value,
        "version": "dictation_to_note_v1",
        "status": STATUS_CONTRACT_ONLY,
        "purpose": "Turn dictated facts into structured note format.",
        "required_fields": [
            "dictated_text",
            "desired_format",
        ],
        "optional_fields": [],
        "allowed_outputs": [],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": "No new assessment, diagnosis, or plan beyond dictated/confirmed content.",
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
    AssistantMode.external_ai_review: {
        "mode": AssistantMode.external_ai_review.value,
        "version": "external_ai_review_v1",
        "status": STATUS_CONTRACT_ONLY,
        "purpose": "Review governance risks in external AI output.",
        "required_fields": [
            "source_tool",
            "external_output_text",
            "intended_destination",
            "human_review_status",
        ],
        "optional_fields": [],
        "allowed_outputs": [],
        "prohibited_outputs": list(_CLINICAL_PROHIBITED),
        "hard_boundary": "Does not clinically validate the external output.",
        "human_review_required": True,
        "content_storage": "not_stored_by_default",
    },
}


def active_modes() -> List[str]:
    return [
        m.value
        for m, c in MODE_CONTRACTS.items()
        if c["status"] == STATUS_ACTIVE
    ]


def build_contract_discovery_payload() -> Dict[str, Any]:
    """
    Returns the wire payload for GET /v1/assistant/contracts.

    All six modes are present. Only client_communication is active. Other
    modes carry the contract_defined_only status.
    """
    return {
        "contract_version": CONTRACT_VERSION,
        "storage_policy": STORAGE_POLICY,
        "human_review_required": HUMAN_REVIEW_REQUIRED,
        "active_modes": active_modes(),
        "modes": [MODE_CONTRACTS[m] for m in AssistantMode],
    }
