"""campaign_hunter.py — CampaignHunterAgent: cross-user correlation.

Runs cross-user (no `user=` filter) SPL `stats`/`dc()` queries to find
indicators of compromise shared by 2+ accounts — a rogue Wi-Fi access point,
a shared low-reputation exfiltration destination, or a shared unsigned
persistence artifact — and returns each match as a `Campaign`.
"""

from __future__ import annotations

from typing import Any

from models import Campaign
from splunk import McpSplunkClient


class CampaignHunterAgent:
    """Hunts for indicators of compromise shared across 2+ user accounts."""

    name = "campaign_hunter"

    def __init__(self, splunk: McpSplunkClient) -> None:
        self.splunk = splunk

    async def hunt(self, earliest_time: str = "-7d") -> list[Campaign]:
        campaigns: list[Campaign] = []
        campaigns += await self._rogue_access_points(earliest_time)
        campaigns += await self._shared_exfil_destinations(earliest_time)
        campaigns += await self._shared_persistence_artifacts(earliest_time)
        return campaigns

    async def _rogue_access_points(self, earliest_time: str) -> list[Campaign]:
        spl = (
            "search index=main sourcetype=praxis:wifi action=wifi_association known_bssid=false "
            "| stats values(user) as users dc(user) as user_count "
            "values(ssid) as ssid values(ap_vendor) as ap_vendor values(security) as security by bssid "
            "| where user_count > 1"
        )
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        return [
            Campaign(
                indicator_type="rogue_access_point",
                indicator_label="Rogue/evil-twin Wi-Fi access point",
                indicator_value=row.get("bssid", ""),
                users=_as_list(row.get("users")),
                details={
                    "ssid": _first(row.get("ssid")),
                    "ap_vendor": _first(row.get("ap_vendor")),
                    "security": _first(row.get("security")),
                },
            )
            for row in rows
        ]

    async def _shared_exfil_destinations(self, earliest_time: str) -> list[Campaign]:
        spl = (
            "search index=main sourcetype=praxis:egress dest_reputation=low "
            "| stats values(user) as users dc(user) as user_count by dest_domain "
            "| where user_count > 1"
        )
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        return [
            Campaign(
                indicator_type="shared_exfil_destination",
                indicator_label="Shared low-reputation exfiltration destination",
                indicator_value=row.get("dest_domain", ""),
                users=_as_list(row.get("users")),
            )
            for row in rows
        ]

    async def _shared_persistence_artifacts(self, earliest_time: str) -> list[Campaign]:
        spl = (
            "search index=main sourcetype=praxis:endpoint action=scheduled_task_created signed=false "
            "| stats values(user) as users dc(user) as user_count by task_name "
            "| where user_count > 1"
        )
        rows = await self.splunk.run_query(spl, earliest_time=earliest_time)
        return [
            Campaign(
                indicator_type="shared_persistence_artifact",
                indicator_label="Shared unsigned persistence artifact",
                indicator_value=row.get("task_name", ""),
                users=_as_list(row.get("users")),
            )
            for row in rows
        ]


def _as_list(value: Any) -> list[str]:
    """Normalize a Splunk `values()` multivalue field to a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _first(value: Any) -> str:
    items = _as_list(value)
    return items[0] if items else ""
