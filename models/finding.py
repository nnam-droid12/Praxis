"""finding.py — Finding: a single piece of evidence produced by one specialist agent."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """One piece of evidence an agent surfaces for a Case.

    `confidence` and `severity` start at their lowest values and are set by
    the Foundation-Sec scoring model (Feature 3).
    """

    id: str = Field(default_factory=lambda: f"finding-{uuid.uuid4().hex[:12]}")
    agent: str
    title: str
    description: str
    severity: Severity = Severity.LOW
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    spl_query: str
    events: list[dict] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
