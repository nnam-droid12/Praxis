"""case.py — Case: an investigation opened in response to triggered Praxis alerts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from .finding import Finding


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class Case(BaseModel):
    """An investigation that fans out to the specialist agents and collects their Findings."""

    id: str = Field(default_factory=lambda: f"case-{uuid.uuid4().hex[:12]}")
    trigger_alerts: list[str] = Field(default_factory=list)
    status: CaseStatus = CaseStatus.OPEN
    findings: list[Finding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.updated_at = datetime.now(timezone.utc)
