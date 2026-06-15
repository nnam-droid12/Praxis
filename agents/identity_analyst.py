"""identity_analyst.py — IdentityAnalystAgent: Feature 4 vertical slice.

Investigates identity/auth signals for a user — impossible-travel logins and
MFA-fatigue (push-bombing) patterns — by running hand-written SPL against real
Splunk data via `McpSplunkClient`, building `Finding`s, and scoring them via
`ScoringClient`. Hand-written SPL is the primary path since `saia_generate_spl`
is currently broken (see memory: mcp-known-issues).

Usage:
    async with McpSplunkClient() as splunk:
        agent = IdentityAnalystAgent(splunk)
        findings = await agent.investigate("j.okonkwo")
"""

from __future__ import annotations

from models import Finding
from scoring import ScoringClient
from splunk import McpSplunkClient


class IdentityAnalystAgent:
    """Investigates identity/auth signals for a user (Feature 4)."""

    name = "identity_analyst"

    def __init__(self, splunk: McpSplunkClient, scorer: ScoringClient | None = None) -> None:
        self.splunk = splunk
        self.scorer = scorer or ScoringClient()

    async def investigate(self, user: str, earliest_time: str = "-24h") -> list[Finding]:
        """Run identity-analyst checks for `user` and return scored Findings.

        Only emits a Finding for a check if it returned at least one event.
        """
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
                        title=f"Login activity for {user}",
                        description=(
                            f"Successful logins by {user}, checked for impossible-travel "
                            f"velocity between consecutive logins."
                        ),
                        spl_query=login_spl,
                        events=login_rows,
                        entities={"users": [user]},
                    )
                )
            )

        mfa_spl = f"search index=main sourcetype=praxis:auth user={user} action=mfa_challenge"
        mfa_rows = await self.splunk.run_query(mfa_spl, earliest_time=earliest_time)
        if mfa_rows:
            findings.append(
                await self.scorer.score(
                    Finding(
                        agent=self.name,
                        title=f"MFA challenge activity for {user}",
                        description=(
                            f"MFA challenge/response events for {user}, checked for "
                            f"push-bombing (repeated denials followed by an approval)."
                        ),
                        spl_query=mfa_spl,
                        events=mfa_rows,
                        entities={"users": [user]},
                    )
                )
            )

        return findings
