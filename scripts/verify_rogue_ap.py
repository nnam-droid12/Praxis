"""verify_rogue_ap.py — Live check for rogue Wi-Fi access-point detection.

LateralMovementAgent now runs a second SPL query against
`sourcetype=praxis:wifi` and the ScoringClient flags any `wifi_association`
event with `known_bssid=false` as a possible rogue/evil-twin access point
(signal: rogue_access_point, +4 points -> HIGH severity).

Checks:
  1. j.okonkwo — planted rogue AP (unrecognized BSSID broadcasting
                 CorpWiFi-Secure) -> HIGH/CRITICAL severity.
  2. m.okafor  — associated to a known/authorized AP -> LOW severity,
                 no risk signals.
  3. it.admin  — associated to a known/authorized AP -> LOW severity,
                 no risk signals.

Run:
    python scripts/verify_rogue_ap.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from agents import LateralMovementAgent  # noqa: E402
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
        print("[1] Lateral Movement — j.okonkwo (planted rogue AP)")
        findings = await LateralMovementAgent(splunk).investigate("j.okonkwo", earliest_time="-7d")
        wifi_finding = next((f for f in findings if "Wi-Fi" in f.title), None)
        if wifi_finding is None:
            fail("No Wi-Fi finding returned for j.okonkwo")
            failures += 1
        else:
            ok(f"{wifi_finding.title} -> severity={wifi_finding.severity.value} "
               f"confidence={wifi_finding.confidence}")
            info(f"rationale: {wifi_finding.rationale}")
            if wifi_finding.severity not in (Severity.HIGH, Severity.CRITICAL):
                fail("Expected HIGH/CRITICAL severity for j.okonkwo's rogue AP")
                failures += 1
            if "rogue" not in wifi_finding.rationale.lower():
                fail("Expected rogue/evil-twin rationale for j.okonkwo")
                failures += 1

        print("\n[2] Lateral Movement — m.okafor (known/authorized AP)")
        findings = await LateralMovementAgent(splunk).investigate("m.okafor", earliest_time="-7d")
        wifi_finding = next((f for f in findings if "Wi-Fi" in f.title), None)
        if wifi_finding is None:
            fail("No Wi-Fi finding returned for m.okafor")
            failures += 1
        else:
            ok(f"{wifi_finding.title} -> severity={wifi_finding.severity.value} "
               f"confidence={wifi_finding.confidence}")
            info(f"rationale: {wifi_finding.rationale}")
            if wifi_finding.severity != Severity.LOW:
                fail("Expected LOW severity for m.okafor's known AP")
                failures += 1

        print("\n[3] Lateral Movement — it.admin (known/authorized AP)")
        findings = await LateralMovementAgent(splunk).investigate("it.admin", earliest_time="-7d")
        wifi_finding = next((f for f in findings if "Wi-Fi" in f.title), None)
        if wifi_finding is None:
            fail("No Wi-Fi finding returned for it.admin")
            failures += 1
        else:
            ok(f"{wifi_finding.title} -> severity={wifi_finding.severity.value} "
               f"confidence={wifi_finding.confidence}")
            info(f"rationale: {wifi_finding.rationale}")
            if wifi_finding.severity != Severity.LOW:
                fail("Expected LOW severity for it.admin's known AP")
                failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Rogue Wi-Fi access-point detection verified live.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
