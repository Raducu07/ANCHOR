from __future__ import annotations

from typing import Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.intake_common import MAX_CHAT_QUESTION_LENGTH, MAX_TEXTAREA_LENGTH, clamp_text, normalize_optional_text


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DemoRequestCreate(_StrictModel):
    full_name: str = Field(..., min_length=2, max_length=200)
    work_email: EmailStr
    clinic_name: str = Field(..., min_length=2, max_length=200)
    role: str = Field(..., min_length=2, max_length=100)
    current_ai_use: str = Field(..., min_length=2, max_length=200)
    primary_interest: str = Field(..., min_length=2, max_length=200)
    biggest_concern: str = Field(..., min_length=2, max_length=500)
    clinic_size: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=50)
    message: Optional[str] = Field(default=None, max_length=MAX_TEXTAREA_LENGTH)
    consent: bool
    source_page: Optional[str] = Field(default=None, max_length=200)
    utm_source: Optional[str] = Field(default=None, max_length=200)
    utm_medium: Optional[str] = Field(default=None, max_length=200)
    utm_campaign: Optional[str] = Field(default=None, max_length=200)
    website: Optional[str] = Field(default=None, max_length=200)
    company_website: Optional[str] = Field(
        default=None,
        max_length=200,
        validation_alias=AliasChoices("company_website", "honeypot"),
    )

    @field_validator("clinic_size", "phone", "message", "source_page", "utm_source", "utm_medium", "utm_campaign")
    @classmethod
    def _normalize_optional(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def _require_consent(self) -> "DemoRequestCreate":
        if not self.consent:
            raise ValueError("consent must be true")
        return self


class StartRequestCreate(_StrictModel):
    clinic_name: str = Field(..., min_length=2, max_length=200)
    full_name: str = Field(..., min_length=2, max_length=200)
    work_email: EmailStr
    role: str = Field(..., min_length=2, max_length=100)
    preferred_plan: str = Field(..., min_length=2, max_length=100)
    clinic_size: str = Field(..., min_length=1, max_length=100)
    current_ai_use: str = Field(..., min_length=2, max_length=200)
    rollout_timing: str = Field(..., min_length=2, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=50)
    site_count: Optional[int] = Field(default=None, ge=0, le=10000)
    message: Optional[str] = Field(default=None, max_length=MAX_TEXTAREA_LENGTH)
    consent: bool
    source_page: Optional[str] = Field(default=None, max_length=200)
    utm_source: Optional[str] = Field(default=None, max_length=200)
    utm_medium: Optional[str] = Field(default=None, max_length=200)
    utm_campaign: Optional[str] = Field(default=None, max_length=200)
    website: Optional[str] = Field(default=None, max_length=200)
    company_website: Optional[str] = Field(
        default=None,
        max_length=200,
        validation_alias=AliasChoices("company_website", "honeypot"),
    )

    @field_validator("phone", "message", "source_page", "utm_source", "utm_medium", "utm_campaign")
    @classmethod
    def _normalize_optional(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def _require_consent(self) -> "StartRequestCreate":
        if not self.consent:
            raise ValueError("consent must be true")
        return self


class PublicSiteChatEventCreate(_StrictModel):
    session_id: Optional[str] = Field(default=None, max_length=128)
    question_text: str = Field(..., min_length=1, max_length=MAX_TEXTAREA_LENGTH)
    question_category: Optional[str] = Field(default=None, max_length=100)
    matched_topic: Optional[str] = Field(default=None, max_length=100)
    answer_confidence: Optional[str] = Field(default=None, max_length=32)
    suggested_cta: Optional[str] = Field(default=None, max_length=64)
    source_page: Optional[str] = Field(default=None, max_length=200)
    utm_source: Optional[str] = Field(default=None, max_length=200)
    utm_medium: Optional[str] = Field(default=None, max_length=200)
    utm_campaign: Optional[str] = Field(default=None, max_length=200)

    @field_validator(
        "session_id",
        "question_category",
        "matched_topic",
        "answer_confidence",
        "suggested_cta",
        "source_page",
        "utm_source",
        "utm_medium",
        "utm_campaign",
    )
    @classmethod
    def _normalize_optional(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value)

    @field_validator("question_text")
    @classmethod
    def _normalize_question_text(cls, value: str) -> str:
        return clamp_text(value, max_length=MAX_CHAT_QUESTION_LENGTH)


class IntakeCreateResponse(_StrictModel):
    status: str = "ok"
    request_id: str
    created_at: str
    notification_status: str


class ChatLogResponse(_StrictModel):
    status: str = "ok"
    event_id: str
    created_at: str


class UpdateIntakeRequest(_StrictModel):
    status: Optional[str] = Field(default=None, min_length=2, max_length=32)
    notes: Optional[str] = Field(default=None, max_length=MAX_TEXTAREA_LENGTH)

    @field_validator("notes")
    @classmethod
    def _normalize_notes(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def _require_change(self) -> "UpdateIntakeRequest":
        if self.status is None and "notes" not in self.model_fields_set:
            raise ValueError("status or notes is required")
        return self
