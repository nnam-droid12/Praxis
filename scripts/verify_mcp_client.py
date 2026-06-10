"""verify_mcp_client.py — Feature 2 live check for McpSplunkClient + models.

Confirms, against the real Splunk instance:
  1. McpSplunkClient.run_query returns rows from index=main.
  2. A Finding can be built from a real event row.
  3. A Case can hold that Finding.
  4. McpSplunkClient.get_praxis_alerts() finds the 5 `Praxis - *` alerts.
  5. McpSplunkClient.run_saved_search executes one of those alerts.

Run:
    python scripts/verify_mcp_client.py
"""

import asyncio
import sys

from dotenv import load_dotenv

sys.path.insert(0, ".")

from models import Case, Finding  # noqa: E402
from splunk import McpSplunkClient  # noqa: E402

load_dotenv()

GREEN = "\033[32m"
RED = "\033[31m"
RST = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RST} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RST} {msg}")


async def main() -> None:
    async with McpSplunkClient() as splunk:
        print("[1] run_query against index=main")
        rows = await splunk.run_query(
            "search index=main sourcetype=praxis:auth | head 3",
            earliest_time="-24h",
        )
        if not rows:
            fail("No rows returned from index=main sourcetype=praxis:auth")
            sys.exit(1)
        ok(f"Got {len(rows)} row(s); first _raw: {rows[0].get('_raw', '')[:80]}")

        print("\n[2] Build a Finding from a real event")
        finding = Finding(
            agent="identity_analyst",
            title="Sample MFA event",
            description="Built from a live praxis:auth row for Feature 2 verification.",
            spl_query="search index=main sourcetype=praxis:auth | head 3",
            events=rows,
            entities={"hosts": [rows[0].get("host", "")]},
        )
        ok(f"Finding.id={finding.id} severity={finding.severity} events={len(finding.events)}")

        print("\n[3] Wrap the Finding in a Case")
        case = Case(trigger_alerts=["Praxis - MFA Fatigue Pattern"])
        case.add_finding(finding)
        ok(f"Case.id={case.id} status={case.status} findings={len(case.findings)}")

        print("\n[4] get_praxis_alerts()")
        alerts = await splunk.get_praxis_alerts()
        names = {a["name"] for a in alerts}
        expected = {
            "Praxis - Impossible Travel Login",
            "Praxis - MFA Fatigue Pattern",
            "Praxis - Lateral Movement Multi-Protocol to File Server",
            "Praxis - New Scheduled Task Created",
            "Praxis - DNS Tunneling or Large Egress to Low-Reputation Destination",
        }
        missing = expected - names
        if missing:
            fail(f"Missing alerts: {missing}")
        else:
            ok(f"Found all {len(expected)} Praxis alerts")

        print("\n[5] run_saved_search('Praxis - MFA Fatigue Pattern')")
        try:
            results = await splunk.run_saved_search(
                "Praxis - MFA Fatigue Pattern",
                earliest_time="-24h",
                latest_time="now",
            )
            ok(f"Saved search executed, {len(results)} row(s) returned")
        except Exception as exc:  # noqa: BLE001
            fail(f"run_saved_search failed: {exc}")

    print(f"\n{GREEN}Feature 2 live check complete.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
