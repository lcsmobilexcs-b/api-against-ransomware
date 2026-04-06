"""Data contracts: SecuritySnares alerts, normalized events, idempotency keys."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ProcessingStatus(str, Enum):
    """Final outcome for a processed alert."""

    ROTATION_TRIGGERED = "rotation_triggered"
    ROTATION_FAILED = "rotation_failed"
    EMAIL_SENT_UNMATCHED = "email_sent_unmatched"
    EMAIL_SENT_AMBIGUOUS = "email_sent_ambiguous"
    SKIPPED_NOT_RANSOMWARE = "skipped_not_ransomware"
    SKIPPED_INVALID = "skipped_invalid"
    DUPLICATE = "duplicate"


class SecuritySnaresAlert(BaseModel):
    """Subset of SecuritySnares API alert response (see docs)."""

    entity_id: str = Field(..., alias="entity_id")
    hostname: str | None = None
    executing_username: str | None = None
    executing_user_sid: str | None = None
    alert_time: datetime | None = None
    ai_analysis: str | None = None
    process_name: str | None = None
    process_file_path: str | None = None
    process_sha256: str | None = None
    action_taken: str | None = None
    organization_id: str | None = None
    agent_id: str | None = None
    ip_address: str | None = None
    dismissed: bool | None = None  # not in raw API; may be set by client

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @field_validator("alert_time", mode="before")
    @classmethod
    def parse_alert_time(cls, v: Any) -> datetime | None:
        if v is None or v == "":
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return None


class ParsedAiAnalysis(BaseModel):
    """Parsed JSON from ai_analysis field when present."""

    summary: str | None = None
    severity: int | None = None


class NormalizedAlert(BaseModel):
    """Canonical alert for processing (idempotency key = entity_id)."""

    entity_id: str
    hostname: str
    executing_username_raw: str
    hostname_normalized: str
    account_name: str
    domain_hint: str | None
    alert_time: datetime | None
    process_name: str | None
    process_sha256: str | None
    ai_summary: str | None
    ai_severity: int | None
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def idempotency_key(self) -> str:
        """Canonical key for deduplication (SecuritySnares alert entity_id)."""
        return self.entity_id


def parse_executing_username(executing_username: str) -> tuple[str, str | None]:
    """
    Split DOMAIN\\user or user@domain into (account_name, domain_hint).

    Returns (account_name, domain_hint or None).
    """
    s = (executing_username or "").strip()
    if not s:
        return "", None

    if "\\" in s:
        parts = s.split("\\", 1)
        domain = parts[0].strip() or None
        user = parts[1].strip() if len(parts) > 1 else ""
        return user, domain

    if "@" in s:
        user, _, rest = s.partition("@")
        return user.strip(), rest.strip() or None

    return s, None


def parse_ai_analysis_field(ai_analysis: str | None) -> ParsedAiAnalysis:
    if not ai_analysis:
        return ParsedAiAnalysis()
    try:
        data = json.loads(ai_analysis)
        if isinstance(data, dict):
            return ParsedAiAnalysis(
                summary=data.get("summary"),
                severity=data.get("severity"),
            )
    except (json.JSONDecodeError, TypeError):
        pass
    return ParsedAiAnalysis()


def normalize_hostname(hostname: str) -> str:
    return (hostname or "").strip().upper()
