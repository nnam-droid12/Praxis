"""devils_advocate.py — DevilsAdvocateAgent: Feature 5 specialist agent.

Actively looks for evidence that an alert is a false alarm, by re-running the
Identity Analyst's login query and the Persistence agent's scheduled-task
query for a user. `ScoringClient` already down-weights findings when
mitigating evidence is present (`travel_record` on a high-velocity login,
`change_ticket` on a signed scheduled task) — if no such evidence is found,
the resulting Finding stays at its escalated severity, reinforcing rather
than dismissing the other agents' findings.
"""

from __future__ import annotations

from models import Finding
from scoring import ScoringClient
from splunk import McpSplunkClient


class DevilsAdvocateAgent:
    """Looks for exculpatory evidence for a user's flagged activity (Feature 5)."""

    name = "devils_advocate"

    def __init__(self, splunk: McpSplunkClient, scorer: ScoringClient | None = None) -> None:
        self.splunk = splunk
        self.scorer = scorer or ScoringClient()

    async def investigate(self, user: str, earliest_time: str = "-24h") -> list[Finding]:
        """Re-check `user`'s logins and scheduled tasks for mitigating context."""
        findings: list[Finding] = []

        login_spl = (
            f"search index=main sourcetype=praxis:auth user={user} "
            f"action=login status=success"
        )
        login_rows = await self.splunk.run_query(login_spl, earliest_time=earliest_time)
        if login_rows:
            findings.append(
                await self.scorer.score(
                    Finding(
                        agent=self.name,
                        title=f"Travel-record check for {user}",
                        description=(
                            f"Re-checking {user}'s high-velocity logins for an "
                            f"on-file travel record before treating them as suspicious."
                        ),
                        spl_query=login_spl,
                        events=login_rows,
                        entities={"users": [user]},
                    )
                )
            )

        task_spl = (
            f"search index=main sourcetype=praxis:endpoint user={user} "
            f"action=scheduled_task_created"
        )
        task_rows = await self.splunk.run_query(task_spl, earliest_time=earliest_time)
        if task_rows:
            findings.append(
                await self.scorer.score(
                    Finding(
                        agent=self.name,
                        title=f"Change-ticket check for {user}",
                        description=(
                            f"Re-checking {user}'s new scheduled tasks for an "
                            f"approved change ticket before treating them as persistence."
                        ),
                        spl_query=task_spl,
                        events=task_rows,
                        entities={"users": [user]},
                    )
                )
            )

        return findings
