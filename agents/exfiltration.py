"""exfiltration.py — ExfiltrationAgent: Feature 5 specialist agent.

Investigates exfiltration signals for a user — DNS tunneling and large
egress to low-reputation destinations — by running hand-written SPL against
real Splunk data via `McpSplunkClient`, building a `Finding`, and scoring it
via `ScoringClient`.
"""

from __future__ import annotations

from models import Finding
from scoring import ScoringClient
from splunk import McpSplunkClient


class ExfiltrationAgent:
    """Investigates exfiltration signals for a user (Feature 5)."""

    name = "exfiltration"

    def __init__(self, splunk: McpSplunkClient, scorer: ScoringClient | None = None) -> None:
        self.splunk = splunk
        self.scorer = scorer or ScoringClient()

    async def investigate(self, user: str, earliest_time: str = "-24h") -> list[Finding]:
        """Run exfiltration checks for `user` and return scored Findings."""
        spl = f"search index=main sourcetype=praxis:egress user={user}"
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        if not rows:
            return []

        finding = Finding(
            agent=self.name,
            title=f"Egress activity for {user}",
            description=(
                f"Outbound network activity from {user}'s host, checked for DNS "
                f"tunneling and large transfers to low-reputation destinations."
            ),
            spl_query=spl,
            events=rows,
            entities={"users": [user]},
        )
        return [await self.scorer.score(finding)]
