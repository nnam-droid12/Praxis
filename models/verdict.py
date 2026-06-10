"""verdict.py — Verdict: the Correlation Lead's synthesis of a Case."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class VerdictLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    ACTIVE_INTRUSION = "active_intrusion"


class KillChainStep(BaseModel):
    """One stage of the reconstructed attack timeline."""

    stage: str
    timestamp: datetime
    description: str
    finding_ids: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    """The Correlation Lead's final synthesis of all Findings in a Case."""

    case_id: str
    level: VerdictLevel
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    kill_chain: list[KillChainStep] = Field(default_factory=list)
    contributing_findings: list[str] = Field(default_factory=list)
    dissenting_view: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
