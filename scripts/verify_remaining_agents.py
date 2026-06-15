"""verify_remaining_agents.py — Feature 5 live check for the remaining
specialist agents (LateralMovement, Persistence, Exfiltration, DevilsAdvocate).

Runs each agent's vertical slice (real Splunk query -> Finding ->
ScoringClient) for:
  1. j.okonkwo  — planted multi-stage campaign: lateral movement to FS01,
                  unsigned scheduled task, DNS tunneling/large egress. Each
                  specialist agent expects elevated severity. DevilsAdvocate
                  finds no mitigating travel_record/change_ticket for
                  j.okonkwo, so its findings stay elevated too.
  2. m.okafor   — DevilsAdvocate's travel-record check should find the
                  on-file travel_record and report LOW severity.
  3. it.admin   — DevilsAdvocate's change-ticket check should find the
                  approved change_ticket and report LOW severity.

Run:
    python scripts/verify_remaining_agents.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from agents import (  # noqa: E402
    DevilsAdvocateAgent,
    ExfiltrationAgent,
    LateralMovementAgent,
    PersistenceAgent,
)
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
        print("[1] Lateral Movement — j.okonkwo (planted FS01 access)")
        findings = await LateralMovementAgent(splunk).investigate("j.okonkwo", earliest_time="-7d")
        if not findings:
            fail("No findings returned for j.okonkwo")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")
            if not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
                fail("Expected HIGH/CRITICAL severity for j.okonkwo's lateral movement")
                failures += 1

        print("\n[2] Persistence — j.okonkwo (planted unsigned scheduled task)")
        findings = await PersistenceAgent(splunk).investigate("j.okonkwo", earliest_time="-7d")
        if not findings:
            fail("No findings returned for j.okonkwo")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")
            if not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
                fail("Expected HIGH/CRITICAL severity for j.okonkwo's scheduled task")
                failures += 1

        print("\n[3] Exfiltration — j.okonkwo (planted DNS tunneling/large egress)")
        findings = await ExfiltrationAgent(splunk).investigate("j.okonkwo", earliest_time="-7d")
        if not findings:
            fail("No findings returned for j.okonkwo")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")
            if not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
                fail("Expected HIGH/CRITICAL severity for j.okonkwo's egress activity")
                failures += 1

        print("\n[4] Devil's Advocate — j.okonkwo (no mitigating evidence expected)")
        findings = await DevilsAdvocateAgent(splunk).investigate("j.okonkwo", earliest_time="-7d")
        if not findings:
            fail("No findings returned for j.okonkwo")
            failures += 1
        else:
            for f in findings:
                ok(f"{f.title} -> severity={f.severity.value} confidence={f.confidence}")
                info(f"rationale: {f.rationale}")

        print("\n[5] Devil's Advocate — m.okafor (expects on-file travel_record -> LOW)")
        findings = await DevilsAdvocateAgent(splunk).investigate("m.okafor", earliest_time="-7d")
        if not findings:
            fail("No findings returned for m.okafor")
            failures += 1
        else:
            travel_finding = next((f for f in findings if "Travel-record" in f.title), None)
            if travel_finding is None:
                fail("No travel-record finding returned for m.okafor")
                failures += 1
            else:
                ok(f"{travel_finding.title} -> severity={travel_finding.severity.value} "
                   f"confidence={travel_finding.confidence}")
                info(f"rationale: {travel_finding.rationale}")
                if travel_finding.severity != Severity.LOW:
                    fail("Expected LOW severity for m.okafor's travel-record check")
                    failures += 1

        print("\n[6] Devil's Advocate — it.admin (expects approved change_ticket -> LOW)")
        findings = await DevilsAdvocateAgent(splunk).investigate("it.admin", earliest_time="-7d")
        if not findings:
            fail("No findings returned for it.admin")
            failures += 1
        else:
            ticket_finding = next((f for f in findings if "Change-ticket" in f.title), None)
            if ticket_finding is None:
                fail("No change-ticket finding returned for it.admin")
                failures += 1
            else:
                ok(f"{ticket_finding.title} -> severity={ticket_finding.severity.value} "
                   f"confidence={ticket_finding.confidence}")
                info(f"rationale: {ticket_finding.rationale}")
                if ticket_finding.severity != Severity.LOW:
                    fail("Expected LOW severity for it.admin's change-ticket check")
                    failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Feature 5 live check complete — remaining agents verified.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
