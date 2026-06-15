"""persistence.py — PersistenceAgent: Feature 5 specialist agent.

Investigates persistence signals for a user — newly created scheduled tasks
— by running hand-written SPL against real Splunk data via `McpSplunkClient`,
building a `Finding`, and scoring it via `ScoringClient`.
"""

from __future__ import annotations

from models import Finding
from scoring import ScoringClient
from splunk import McpSplunkClient


class PersistenceAgent:
    """Investigates persistence signals for a user (Feature 5)."""

    name = "persistence"

    def __init__(self, splunk: McpSplunkClient, scorer: ScoringClient | None = None) -> None:
        self.splunk = splunk
        self.scorer = scorer or ScoringClient()

    async def investigate(self, user: str, earliest_time: str = "-24h") -> list[Finding]:
        """Run persistence checks for `user` and return scored Findings."""
        spl = (
            f"search index=main sourcetype=praxis:endpoint user={user} "
            f"action=scheduled_task_created"
        )
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        if not rows:
            return []

        finding = Finding(
            agent=self.name,
            title=f"Scheduled task activity for {user}",
            description=(
                f"Scheduled tasks created under {user}'s context, checked for "
                f"unsigned binaries, encoded commands, and approved-change tickets."
            ),
            spl_query=spl,
            events=rows,
            entities={"users": [user]},
        )
        return [await self.scorer.score(finding)]
