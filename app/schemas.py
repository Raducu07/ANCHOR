# app/schemas.py

import uuid
from typing import Any, List, Optional, Literal

from pydantic import BaseModel, Field


# ---------------------------
# Sessions / Messages
# ---------------------------

class CreateSessionResponse(BaseModel):
    user_id: uuid.UUID
    session_id: uuid.UUID
    mode: str


class CreateSessionForUserResponse(BaseModel):
    user_id: uuid.UUID
    session_id: uuid.UUID
    mode: str = "witness"


class SendMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=8000)


class SendMessageResponse(BaseModel):
    session_id: uuid.UUID
    role: Literal["assistant"]
    content: str


# ---------------------------
# Memory shaping
# ---------------------------

class MemoryItem(BaseModel):
    id: uuid.UUID
    kind: str
    statement: str
    confidence: str
    active: bool
    evidence_session_ids: List[uuid.UUID] = Field(default_factory=list)
    created_at: str


class CreateMemoryRequest(BaseModel):
    kind: str
    statement: str
    confidence: str = "tentative"
    evidence_session_ids: List[uuid.UUID] = Field(default_factory=list)


class MemoryOfferResponse(BaseModel):
    offer: Optional[CreateMemoryRequest] = None


# ---------------------------
# Neutrality scoring
# ---------------------------

class NeutralityScoreRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000)
    debug: bool = False  # keep your swagger behavior consistent


class NeutralityFinding(BaseModel):
    rule_id: str
    label: str
    severity: int
    excerpt: str


class NeutralityScoreResponse(BaseModel):
    score: int
    grade: str
    witness_hits: int = 0
    findings: List[NeutralityFinding] = Field(default_factory=list)
    debug: Optional[Any] = None

# ---------------------------
# Value artifacts — Session Export (M4.5)
# ---------------------------

class ExportMessage(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    created_at: str


class ExportMemory(BaseModel):
    id: uuid.UUID
    kind: str
    statement: str
    confidence: str
    active: bool
    evidence_session_ids: List[uuid.UUID] = Field(default_factory=list)
    created_at: str


class ExportGovernanceEvent(BaseModel):
    id: uuid.UUID
    created_at: str
    mode: str
    allowed: Optional[bool] = None
    replaced: Optional[bool] = None
    score: Optional[int] = None
    grade: Optional[str] = None
    reason: Optional[str] = None
    policy_version: Optional[str] = None
    neutrality_version: Optional[str] = None
    triggered_rule_ids: List[str] = Field(default_factory=list)


class SessionExportResponse(BaseModel):
    export_version: str = "export-v1"
    now_utc: str
    user_id: uuid.UUID
    session_id: uuid.UUID
    session_mode: str
    session_created_at: Optional[str] = None

    messages: List[ExportMessage] = Field(default_factory=list)
    memories_active: List[ExportMemory] = Field(default_factory=list)

    governance_events: List[ExportGovernanceEvent] = Field(default_factory=list)

    # lightweight computed summary (cheap + useful)
    summary: dict = Field(default_factory=dict)
