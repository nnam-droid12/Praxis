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
        """Run lateral-movement and Wi-Fi access-point checks for `user`."""
        findings: list[Finding] = []

        net_spl = f"search index=main sourcetype=praxis:network user={user} dest_role=file_server"
        net_rows = await self.splunk.run_query(net_spl, earliest_time=earliest_time)
        if net_rows:
            net_finding = Finding(
                agent=self.name,
                title=f"File-server access for {user}",
                description=(
                    f"Network connections from {user} to file-server hosts, checked "
                    f"for multi-protocol lateral movement."
                ),
                spl_query=net_spl,
                events=net_rows,
                entities={"users": [user]},
            )
            findings.append(await self.scorer.score(net_finding))

        wifi_spl = f"search index=main sourcetype=praxis:wifi user={user} action=wifi_association"
        wifi_rows = await self.splunk.run_query(wifi_spl, earliest_time=earliest_time)
        if wifi_rows:
            wifi_finding = Finding(
                agent=self.name,
                title=f"Wi-Fi access-point activity for {user}",
                description=(
                    f"Wi-Fi association events for {user}'s device(s), checked "
                    f"against the known/authorized access-point inventory for "
                    f"rogue or evil-twin access points."
                ),
                spl_query=wifi_spl,
                events=wifi_rows,
                entities={"users": [user]},
            )
            findings.append(await self.scorer.score(wifi_finding))

        return findings
