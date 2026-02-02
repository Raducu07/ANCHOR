from pydantic import BaseModel, Field
from typing import Literal
import uuid

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
