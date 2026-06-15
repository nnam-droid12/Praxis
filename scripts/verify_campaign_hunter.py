"""verify_campaign_hunter.py — Live check for Campaign Hunter (cross-user correlation).

`CampaignHunterAgent` runs cross-user SPL `stats`/`dc(user)` queries to find
indicators of compromise shared by 2+ accounts. The planted dataset has both
j.okonkwo and e.osei associate to the same rogue/evil-twin BSSID
(DE:AD:BE:EF:00:01) — Campaign Hunter should cluster them into one
`rogue_access_point` campaign, then `hunt_campaigns` runs the full 5-agent
investigation for each user and rolls the results into one `CampaignVerdict`.

Checks:
  1. CampaignHunterAgent.hunt() finds exactly one rogue_access_point campaign
     whose users include both j.okonkwo and e.osei.
  2. hunt_campaigns() -> j.okonkwo=active_intrusion, e.osei=suspicious,
     campaign-level level=active_intrusion (max of the two), and the combined
     kill chain contains steps tagged with both usernames.

Run:
    python scripts/verify_campaign_hunter.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from agents import CampaignHunterAgent  # noqa: E402
from models import VerdictLevel  # noqa: E402
from orchestrator import hunt_campaigns  # noqa: E402
from splunk import McpSplunkClient  # noqa: E402

load_dotenv()

GREEN = "\033[32m"
RED = "\033[31m"
YEL = "\033[33m"
RST = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RST} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RST} {msg}")


def info(msg: str) -> None:
    print(f"  {YEL}[..]{RST} {msg}")


async def main() -> None:
    failures = 0

    async with McpSplunkClient() as splunk:
        print("[1] CampaignHunterAgent.hunt() — cross-user rogue AP")
        campaigns = await CampaignHunterAgent(splunk).hunt(earliest_time="-7d")
        rogue = [c for c in campaigns if c.indicator_type == "rogue_access_point"]
        if len(rogue) != 1:
            fail(f"Expected exactly 1 rogue_access_point campaign, got {len(rogue)}")
            failures += 1
        else:
            campaign = rogue[0]
            ok(f"{campaign.indicator_label} bssid={campaign.indicator_value} "
               f"users={campaign.users} details={campaign.details}")
            if not {"j.okonkwo", "e.osei"}.issubset(set(campaign.users)):
                fail("Expected both j.okonkwo and e.osei in the rogue AP campaign's users")
                failures += 1

        print("\n[2] hunt_campaigns() — combined verdict")
        verdicts = await hunt_campaigns(splunk, earliest_time="-7d")
        rogue_verdicts = [v for v in verdicts if v.campaign.indicator_type == "rogue_access_point"]
        if len(rogue_verdicts) != 1:
            fail(f"Expected exactly 1 rogue_access_point CampaignVerdict, got {len(rogue_verdicts)}")
            failures += 1
        else:
            verdict = rogue_verdicts[0]
            ok(f"campaign level={verdict.level.value}")
            info(f"summary: {verdict.summary}")

            okonkwo = verdict.user_verdicts.get("j.okonkwo")
            osei = verdict.user_verdicts.get("e.osei")

            if okonkwo is None:
                fail("No verdict for j.okonkwo")
                failures += 1
            else:
                ok(f"j.okonkwo -> {okonkwo.level.value} (confidence={okonkwo.confidence})")
                if okonkwo.level != VerdictLevel.ACTIVE_INTRUSION:
                    fail("Expected j.okonkwo -> active_intrusion")
                    failures += 1

            if osei is None:
                fail("No verdict for e.osei")
                failures += 1
            else:
                ok(f"e.osei -> {osei.level.value} (confidence={osei.confidence})")
                if osei.level != VerdictLevel.SUSPICIOUS:
                    fail("Expected e.osei -> suspicious")
                    failures += 1

            if verdict.level != VerdictLevel.ACTIVE_INTRUSION:
                fail("Expected campaign-level verdict -> active_intrusion (max of the two)")
                failures += 1

            chain_users = {step.user for step in verdict.combined_kill_chain}
            ok(f"combined_kill_chain: {len(verdict.combined_kill_chain)} steps, users={chain_users}")
            if not {"j.okonkwo", "e.osei"}.issubset(chain_users):
                fail("Expected combined_kill_chain to include steps for both users")
                failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Campaign Hunter (cross-user correlation) verified live.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
