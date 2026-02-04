import uuid
from typing import List, Optional, Literal

from pydantic import BaseModel, Field

class CreateSessionResponse(BaseModel):
    user_id: uuid.UUID
    session_id: uuid.UUID
    mode: str

class SendMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=8000)

class SendMessageResponse(BaseModel):
    session_id: uuid.UUID
    role: Literal["assistant"]
    content: str
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
