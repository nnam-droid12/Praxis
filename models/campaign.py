"""campaign.py — Campaign / CampaignVerdict: cross-user correlation results.

A `Campaign` is one indicator of compromise (rogue AP, shared exfil
destination, shared persistence artifact) that touches 2+ user accounts. A
`CampaignVerdict` runs the standard 5-agent investigation for each affected
user and rolls the results into one combined verdict.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .verdict import KillChainStep, Verdict, VerdictLevel


class Campaign(BaseModel):
    """One indicator of compromise shared by 2+ user accounts."""

    id: str = Field(default_factory=lambda: f"campaign-{uuid.uuid4().hex[:12]}")
    indicator_type: str
    indicator_label: str
    indicator_value: str
    users: list[str] = Field(default_factory=list)
    details: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CampaignVerdict(BaseModel):
    """Combined verdict across all users affected by one Campaign."""

    campaign: Campaign
    level: VerdictLevel
    summary: str
    user_verdicts: dict[str, Verdict] = Field(default_factory=dict)
    combined_kill_chain: list[KillChainStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
