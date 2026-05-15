# app/assistant_models.py
"""
Pydantic models and enums for the Governed Vet Assistant (PR 1).

Notes:
- Raw input is transient. It is never persisted. Only its hash and field keys
  are stored on assistant_runs.
- This PR defines all six modes; only client_communication is "active". The
  others are contract-defined only.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ============================================================
# Enums
# ============================================================


class AssistantMode(str, Enum):
    client_communication = "client_communication"          # ACTIVE in this PR
    discharge_instructions = "discharge_instructions"      # contract-defined only
    referral_summary = "referral_summary"                  # contract-defined only
    internal_handover = "internal_handover"                # contract-defined only
    dictation_to_note = "dictation_to_note"                # contract-defined only
    external_ai_review = "external_ai_review"              # contract-defined only


class AssistantReviewStatus(str, Enum):
    not_reviewed = "not_reviewed"
    review_confirmed = "review_confirmed"
    discarded = "discarded"


class AssistantSafetyCode(str, Enum):
    diagnosis_request = "diagnosis_request"
    treatment_recommendation_request = "treatment_recommendation_request"
    prescribing_request = "prescribing_request"
    dose_calculation_request = "dose_calculation_request"
    imaging_interpretation_request = "imaging_interpretation_request"
    lab_interpretation_request = "lab_interpretation_request"
    triage_or_discharge_decision_request = "triage_or_discharge_decision_request"
    unsupported_prognosis = "unsupported_prognosis"
    missing_clinician_confirmed_facts = "missing_clinician_confirmed_facts"
    pii_detected = "pii_detected"
    external_ai_no_human_review = "external_ai_no_human_review"


# ============================================================
# Pydantic models
# ============================================================


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AssistantRunCreate(_StrictModel):
    """
    Request envelope for an assistant run.

    `input` is transient. It is hashed and its top-level field keys are recorded;
    its raw values are never stored on assistant_runs.
    """

    mode: AssistantMode
    contract_version: str = Field(default="assistant_contract_v1", max_length=64)
    input: Dict[str, Any]
    user_role: Optional[str] = Field(default=None, max_length=64)
    workflow_origin: str = Field(default="anchor_assistant", max_length=64)


class ClientCommunicationInput(_StrictModel):
    """
    Input shape for AssistantMode.client_communication.

    The fields below define the contract for the active mode. No clinical
    decision-making fields are accepted here.
    """

    communication_goal: str = Field(..., min_length=2, max_length=500)
    clinician_confirmed_facts: str = Field(..., min_length=2, max_length=4000)

    patient_display_name: Optional[str] = Field(default=None, max_length=200)
    species: Optional[str] = Field(default=None, max_length=100)
    owner_display_name: Optional[str] = Field(default=None, max_length=200)

    tone: Literal[
        "warm_professional",
        "concise",
        "empathetic",
        "formal",
        "reassuring",
    ] = "warm_professional"

    destination: Literal[
        "email",
        "sms",
        "printed_discharge",
        "internal_review",
        "other",
    ] = "email"

    things_to_include: Optional[str] = Field(default=None, max_length=2000)
    things_to_avoid: Optional[str] = Field(default=None, max_length=2000)

    reviewer_role: Optional[
        Literal[
            "veterinary_surgeon",
            "registered_veterinary_nurse",
            "practice_manager",
            "reception_admin",
            "other",
        ]
    ] = None
