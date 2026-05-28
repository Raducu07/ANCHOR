# app/learn_models.py
"""
Pydantic models for Phase 2A-1 — CPD-Recordable AI Literacy.

Doctrine notes:
- Metadata only. No raw learning content is modelled or persisted here.
  `LearningModule.content_reference` is a path/URL; module content lives in
  markdown shipped with the deploy (docs/learn/modules/<slug>.md).
- `role_applicability` is AUDIENCE METADATA (e.g. vet, nurse, reception). It is
  NOT an access-control role and has no relationship to clinic_users.role.
- CPD export payloads are immutable metadata snapshots only — no clinical
  content, no quiz answers, no free-text learner submissions.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------
# Module catalogue
# ---------------------------------------------------------------------
class LearningModule(BaseModel):
    module_id: UUID
    module_slug: str
    version: str
    title: str
    summary: str
    learning_objectives: List[str]
    role_applicability: List[str]
    cpd_minutes: int
    category: str
    rcvs_principle_mappings: List[str]
    eu_ai_act_article_mappings: List[str]
    content_reference: str
    is_active: bool


# ---------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------
class LearningCompletion(BaseModel):
    completion_id: UUID
    user_id: UUID
    module_id: UUID
    module_version: str
    completed_at: datetime
    acknowledgement_provided: bool
    cpd_minutes_credited: int
    is_voided: bool
    void_reason: Optional[str] = None
    voided_at: Optional[datetime] = None
    voided_by_user_id: Optional[UUID] = None


class LearningCompletionCreate(_StrictModel):
    module_id: UUID
    acknowledgement_provided: bool = False


class LearningCompletionVoid(_StrictModel):
    void_reason: str = Field(..., min_length=3, max_length=500)


# ---------------------------------------------------------------------
# CPD record (derived) + export
# ---------------------------------------------------------------------
class CPDRecord(BaseModel):
    user_id: UUID
    total_modules_completed: int
    total_cpd_minutes: int
    first_completion_at: Optional[datetime]
    most_recent_completion_at: Optional[datetime]
    completions: List[LearningCompletion]


class CPDExportPayloadSummary(BaseModel):
    total_modules_completed: int
    total_cpd_minutes: int
    first_completion_at: Optional[str] = None
    most_recent_completion_at: Optional[str] = None


class CPDExportPayloadCompletion(BaseModel):
    module_id: str
    module_version: str
    completed_at: str
    cpd_minutes_credited: int
    acknowledgement_provided: bool


class CPDExportPayload(BaseModel):
    """Immutable metadata snapshot serialised into cpd_exports.export_payload."""

    export_version: str
    clinic_id: str
    user_id: str
    generated_by_user_id: str
    generated_at: str
    cpd_summary: CPDExportPayloadSummary
    completions: List[CPDExportPayloadCompletion]


class CPDExport(BaseModel):
    export_id: UUID
    user_id: UUID
    generated_by_user_id: UUID
    export_version: str
    export_hash: str
    generated_at: datetime
    # export_payload is intentionally NOT exposed here; it is served separately
    # via GET /v1/learn/cpd/exports/{export_id}/payload.


# ---------------------------------------------------------------------
# Trust Pack learning delta (aggregate metadata only)
# ---------------------------------------------------------------------
class TrustPackLearningDelta(BaseModel):
    total_staff_with_completions: int
    total_cpd_minutes_delivered: int
    completion_rate_by_role: Dict[str, float]
    bias_detection_completions: int
    module_catalogue_count: int
    last_completion_at: Optional[datetime]
    # Honest disclosure of what completion_rate_by_role is keyed on. The repo's
    # access-control role enum is admin/staff only; clinical roles (vet, nurse,
    # ...) exist only as module audience metadata, never as user data.
    role_basis: str = "access_control_role"
