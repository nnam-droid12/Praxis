"""campaign.py — Campaign Hunter orchestration: cross-user correlation.

`hunt_campaigns` runs `CampaignHunterAgent.hunt()` to find indicators of
compromise shared by 2+ accounts, then runs the standard 5-agent
investigation (`run_case`) for each affected user and rolls the results into
one `CampaignVerdict` per campaign.
"""

from __future__ import annotations

from agents import CampaignHunterAgent
from models import Campaign, CampaignVerdict, KillChainStep, Verdict, VerdictLevel
from splunk import McpSplunkClient

from .graph import run_case

_LEVEL_ORDER = {
    VerdictLevel.BENIGN: 0,
    VerdictLevel.SUSPICIOUS: 1,
    VerdictLevel.ACTIVE_INTRUSION: 2,
}


async def hunt_campaigns(splunk: McpSplunkClient, earliest_time: str = "-7d") -> list[CampaignVerdict]:
    """Find cross-user campaigns and investigate every affected user."""
    campaigns = await CampaignHunterAgent(splunk).hunt(earliest_time)

    verdicts: list[CampaignVerdict] = []
    for campaign in campaigns:
        user_verdicts: dict[str, Verdict] = {}
        for user in campaign.users:
            _, verdict = await run_case(splunk, user, earliest_time)
            user_verdicts[user] = verdict

        verdicts.append(_build_campaign_verdict(campaign, user_verdicts))

    return verdicts


def _build_campaign_verdict(campaign: Campaign, user_verdicts: dict[str, Verdict]) -> CampaignVerdict:
    level = max(
        (v.level for v in user_verdicts.values()),
        key=lambda lvl: _LEVEL_ORDER[lvl],
        default=VerdictLevel.BENIGN,
    )

    combined_kill_chain: list[KillChainStep] = []
    for user, verdict in user_verdicts.items():
        for step in verdict.kill_chain:
            combined_kill_chain.append(step.model_copy(update={"user": user}))
    combined_kill_chain.sort(key=lambda s: s.timestamp)

    return CampaignVerdict(
        campaign=campaign,
        level=level,
        summary=_summary(campaign, user_verdicts),
        user_verdicts=user_verdicts,
        combined_kill_chain=combined_kill_chain,
    )


def _summary(campaign: Campaign, user_verdicts: dict[str, Verdict]) -> str:
    users_desc = ", ".join(
        f"{user} ({verdict.level.value})" for user, verdict in user_verdicts.items()
    )
    return (
        f"{len(campaign.users)} accounts connected to the same "
        f"{campaign.indicator_label.lower()} ({campaign.indicator_value}): {users_desc}."
    )
