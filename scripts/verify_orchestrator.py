"""verify_orchestrator.py — Feature 6 live check for the LangGraph
Orchestrator + CorrelationLead.

Runs the full fan-out/fan-in pipeline for:
  1. j.okonkwo — planted multi-stage campaign, expects ACTIVE_INTRUSION with
                 a kill chain spanning multiple agents and no dissent.
  2. m.okafor  — traveling-exec false alarm, expects BENIGN with a
                 dissenting view citing the on-file travel record.
  3. it.admin  — approved-change false alarm, expects BENIGN with a
                 dissenting view citing the change ticket.

Run:
    python scripts/verify_orchestrator.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from models import VerdictLevel  # noqa: E402
from orchestrator import run_case  # noqa: E402
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
        print("[1] j.okonkwo — planted multi-stage campaign")
        case, verdict = await run_case(splunk, "j.okonkwo", earliest_time="-7d")
        ok(f"{len(case.findings)} findings -> level={verdict.level.value} confidence={verdict.confidence}")
        info(f"summary: {verdict.summary}")
        for step in verdict.kill_chain:
            info(f"  [{step.timestamp}] {step.stage}: {step.description}")
        if verdict.level != VerdictLevel.ACTIVE_INTRUSION:
            fail(f"Expected ACTIVE_INTRUSION, got {verdict.level.value}")
            failures += 1
        if verdict.dissenting_view is not None:
            fail(f"Expected no dissenting view, got: {verdict.dissenting_view}")
            failures += 1
        if len(verdict.kill_chain) < 3:
            fail(f"Expected a kill chain with >= 3 steps, got {len(verdict.kill_chain)}")
            failures += 1

        print("\n[2] m.okafor — traveling-exec false alarm")
        case, verdict = await run_case(splunk, "m.okafor", earliest_time="-7d")
        ok(f"{len(case.findings)} findings -> level={verdict.level.value} confidence={verdict.confidence}")
        info(f"summary: {verdict.summary}")
        if verdict.level != VerdictLevel.BENIGN:
            fail(f"Expected BENIGN, got {verdict.level.value}")
            failures += 1
        if not verdict.dissenting_view or "travel_record" not in verdict.dissenting_view:
            fail(f"Expected a travel_record dissenting view, got: {verdict.dissenting_view}")
            failures += 1

        print("\n[3] it.admin — approved-change false alarm")
        case, verdict = await run_case(splunk, "it.admin", earliest_time="-7d")
        ok(f"{len(case.findings)} findings -> level={verdict.level.value} confidence={verdict.confidence}")
        info(f"summary: {verdict.summary}")
        if verdict.level != VerdictLevel.BENIGN:
            fail(f"Expected BENIGN, got {verdict.level.value}")
            failures += 1
        if not verdict.dissenting_view or "change" not in verdict.dissenting_view.lower():
            fail(f"Expected a change-ticket dissenting view, got: {verdict.dissenting_view}")
            failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Feature 6 live check complete — Orchestrator + CorrelationLead verified.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
