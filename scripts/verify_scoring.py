"""verify_scoring.py — Feature 3 live check for the rule-based ScoringClient.

Pulls real events from index=main for each of the 5 `Praxis - *` alert
scenarios plus the 2 Devil's-Advocate false-alarm scenarios, builds a
Finding from each, runs ScoringClient.score(), and checks that the
resulting severity matches the expected outcome for that scenario.

Run:
    python scripts/verify_scoring.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from models import Finding, Severity  # noqa: E402
from scoring import ScoringClient  # noqa: E402
from splunk import McpSplunkClient  # noqa: E402

load_dotenv()

GREEN = "\033[32m"
RED = "\033[31m"
YEL = "\033[33m"
RST = "\033[0m"

SCENARIOS = [
    {
        "title": "Impossible travel login (real)",
        "agent": "identity_analyst",
        "spl": "search index=main sourcetype=praxis:auth user=j.okonkwo action=login | head 5",
        "expect": {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
    },
    {
        "title": "Impossible travel — traveling exec (false alarm)",
        "agent": "devils_advocate",
        "spl": "search index=main sourcetype=praxis:auth user=m.okafor | head 5",
        "expect": {Severity.LOW},
    },
    {
        "title": "MFA fatigue pattern",
        "agent": "identity_analyst",
        "spl": "search index=main sourcetype=praxis:auth user=j.okonkwo action=mfa_challenge | head 10",
        "expect": {Severity.HIGH, Severity.CRITICAL},
    },
    {
        "title": "Lateral movement to file server",
        "agent": "lateral_movement",
        "spl": "search index=main sourcetype=praxis:network user=j.okonkwo dest_role=file_server | head 5",
        "expect": {Severity.HIGH, Severity.CRITICAL},
    },
    {
        "title": "New scheduled task (unsigned + encoded command)",
        "agent": "persistence",
        "spl": "search index=main sourcetype=praxis:endpoint user=j.okonkwo | head 5",
        "expect": {Severity.HIGH, Severity.CRITICAL},
    },
    {
        "title": "New scheduled task — approved change (false alarm)",
        "agent": "devils_advocate",
        "spl": "search index=main sourcetype=praxis:endpoint user=it.admin | head 5",
        "expect": {Severity.LOW},
    },
    {
        "title": "DNS tunneling + large egress",
        "agent": "exfiltration",
        "spl": "search index=main sourcetype=praxis:egress user=j.okonkwo | head 20",
        "expect": {Severity.HIGH, Severity.CRITICAL},
    },
]


def ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RST} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RST} {msg}")


def info(msg: str) -> None:
    print(f"  {YEL}[..]{RST} {msg}")


async def main() -> None:
    scorer = ScoringClient()
    failures = 0

    async with McpSplunkClient() as splunk:
        for i, scenario in enumerate(SCENARIOS, start=1):
            print(f"[{i}] {scenario['title']}")
            rows = await splunk.run_query(scenario["spl"], earliest_time="-7d")
            if not rows:
                fail(f"No rows returned for: {scenario['spl']}")
                failures += 1
                continue

            finding = Finding(
                agent=scenario["agent"],
                title=scenario["title"],
                description=f"Live verification scenario: {scenario['title']}",
                spl_query=scenario["spl"],
                events=rows,
                entities={"users": [rows[0].get("user", "")]},
            )
            scored = await scorer.score(finding)

            ok(
                f"severity={scored.severity.value} confidence={scored.confidence} "
                f"scoring_method={scored.scoring_method}"
            )
            info(f"rationale: {scored.rationale}")

            if scored.severity not in scenario["expect"]:
                fail(
                    f"severity {scored.severity.value!r} not in expected "
                    f"{sorted(s.value for s in scenario['expect'])}"
                )
                failures += 1
            if scored.scoring_method != "rule_based":
                fail(f"scoring_method={scored.scoring_method!r}, expected 'rule_based'")
                failures += 1
            print()

    if failures:
        print(f"{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"{GREEN}Feature 3 live check complete — all scenarios scored as expected.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
