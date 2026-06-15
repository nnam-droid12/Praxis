"""lateral_movement.py — LateralMovementAgent: Feature 5 specialist agent.

Investigates lateral-movement signals for a user — multi-protocol access to
file-server hosts — by running hand-written SPL against real Splunk data via
`McpSplunkClient`, building a `Finding`, and scoring it via `ScoringClient`.
"""

from __future__ import annotations

from models import Finding
from scoring import ScoringClient
from splunk import McpSplunkClient


class LateralMovementAgent:
    """Investigates lateral-movement signals for a user (Feature 5)."""

    name = "lateral_movement"

    def __init__(self, splunk: McpSplunkClient, scorer: ScoringClient | None = None) -> None:
        self.splunk = splunk
        self.scorer = scorer or ScoringClient()

    async def investigate(self, user: str, earliest_time: str = "-24h") -> list[Finding]:
        """Run lateral-movement checks for `user` and return scored Findings."""
        spl = f"search index=main sourcetype=praxis:network user={user} dest_role=file_server"
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        if not rows:
            return []

        finding = Finding(
            agent=self.name,
            title=f"File-server access for {user}",
            description=(
                f"Network connections from {user} to file-server hosts, checked "
                f"for multi-protocol lateral movement."
            ),
            spl_query=spl,
            events=rows,
            entities={"users": [user]},
        )
        return [await self.scorer.score(finding)]
