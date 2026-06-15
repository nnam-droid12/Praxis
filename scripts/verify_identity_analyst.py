"""verify_identity_analyst.py — Feature 4 live check for IdentityAnalystAgent.

Runs the Identity Analyst's vertical slice (real Splunk query -> Finding ->
ScoringClient) for:
  1. j.okonkwo  — planted impossible-travel + MFA-fatigue campaign, expects
                  at least one elevated-severity Finding.
  2. m.okafor   — traveling-exec false alarm (geo_velocity_kmh>1000 but has a
                  travel_record on file), expects LOW severity only.

Run:
    python scripts/verify_identity_analyst.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from agents import IdentityAnalystAgent  # noqa: E402
from models import Severity  # noqa: E402
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
        agent = IdentityAnalystAgent(splunk)

        print("[1] j.okonkwo — planted impossible-travel + MFA-fatigue campaign")
        findings = await agent.investigate("j.okonkwo", earliest_time="-7d")
        if not findings:
            fail("No findings returned for j.okonkwo")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")
            if not any(f.severity != Severity.LOW for f in findings):
                fail("Expected at least one elevated-severity finding for j.okonkwo")
                failures += 1

        print("\n[2] m.okafor — traveling exec (false alarm)")
        findings = await agent.investigate("m.okafor", earliest_time="-7d")
        if not findings:
            fail("No findings returned for m.okafor")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")
            if any(f.severity != Severity.LOW for f in findings):
                fail("Expected only LOW severity findings for m.okafor (false alarm)")
                failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Feature 4 live check complete — IdentityAnalystAgent verified.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
