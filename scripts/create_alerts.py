"""create_alerts.py — create the 5 `Praxis - *` saved-search alerts via the
Splunk REST API (https://localhost:8089), since the MCP Server cannot create
saved searches.

Reads SPLUNK_HOST / SPLUNK_PORT / SPLUNK_USERNAME / SPLUNK_PASSWORD from .env
and uses HTTP Basic Auth against /servicesNS/{user}/search/saved/searches.

Run:
    python scripts/create_alerts.py
"""

import os
import sys
from urllib.parse import quote

import httpx
from dotenv import load_dotenv

load_dotenv()

HOST = os.environ.get("SPLUNK_HOST", "localhost")
PORT = os.environ.get("SPLUNK_PORT", "8089")
USER = os.environ.get("SPLUNK_USERNAME", "")
PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
BASE_URL = f"https://{HOST}:{PORT}"

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


# Each search is individually LOW severity. The planted campaign trips
# all 5; the Praxis multi-agent investigation correlates them into one
# CRITICAL verdict.
ALERTS = [
    {
        "name": "Praxis - Impossible Travel Login",
        "search": "search index=main sourcetype=praxis:auth action=login status=success geo_velocity_kmh>1000",
    },
    {
        "name": "Praxis - MFA Fatigue Pattern",
        "search": (
            "search index=main sourcetype=praxis:auth action=mfa_challenge status=denied "
            "| bucket _time span=5m | stats count by user, _time | where count>=4"
        ),
    },
    {
        "name": "Praxis - Lateral Movement Multi-Protocol to File Server",
        "search": (
            "search index=main sourcetype=praxis:network dest_role=file_server (protocol=SMB OR protocol=RDP) "
            "| bucket _time span=10m | stats dc(protocol) as protocol_count values(protocol) as protocols "
            "by user, src_host, dest_host, _time | where protocol_count>=2"
        ),
    },
    {
        "name": "Praxis - New Scheduled Task Created",
        "search": "search index=main sourcetype=praxis:endpoint action=scheduled_task_created",
    },
    {
        "name": "Praxis - DNS Tunneling or Large Egress to Low-Reputation Destination",
        "search": (
            "search index=main sourcetype=praxis:egress dest_reputation=low "
            "(protocol=DNS OR bytes_out>10000000)"
        ),
    },
]

# Common fields applied to every alert (mirrors data/savedsearches.conf).
COMMON = {
    "dispatch.earliest_time": "-60m",
    "dispatch.latest_time": "now",
    "cron_schedule": "*/5 * * * *",
    "is_scheduled": "1",
    "alert_type": "number of events",
    "alert_comparator": "greater than",
    "alert_threshold": "0",
    "alert.severity": "2",
    "alert.track": "1",
}


def main() -> None:
    if not USER or not PASSWORD:
        fail("SPLUNK_USERNAME / SPLUNK_PASSWORD not set in .env")
        sys.exit(1)

    create_url = f"{BASE_URL}/servicesNS/{USER}/search/saved/searches"

    with httpx.Client(verify=False, auth=(USER, PASSWORD), timeout=60) as client:
        print("=== Creating Praxis saved-search alerts ===")
        for alert in ALERTS:
            payload = {**COMMON, "name": alert["name"], "search": alert["search"]}
            resp = client.post(create_url, data=payload, params={"output_mode": "json"})
            if resp.status_code in (200, 201):
                ok(f"Created: {alert['name']}")
            elif resp.status_code == 409:
                info(f"Already exists, updating: {alert['name']}")
                update_payload = {k: v for k, v in payload.items() if k != "name"}
                upd_url = f"{create_url}/{quote(alert['name'], safe='')}"
                upd_resp = client.post(upd_url, data=update_payload, params={"output_mode": "json"})
                if upd_resp.status_code in (200, 201):
                    ok(f"Updated: {alert['name']}")
                else:
                    fail(f"Update failed ({upd_resp.status_code}): {alert['name']}")
                    info(upd_resp.text[:500])
            else:
                fail(f"Failed ({resp.status_code}): {alert['name']}")
                info(resp.text[:500])

        print("\n=== Verifying ===")
        list_url = f"{BASE_URL}/servicesNS/-/search/saved/searches"
        resp = client.get(
            list_url,
            params={"output_mode": "json", "search": "Praxis", "count": 0},
        )
        resp.raise_for_status()
        entries = resp.json().get("entry", [])
        found = {e["name"] for e in entries}
        for alert in ALERTS:
            if alert["name"] in found:
                content = next(e["content"] for e in entries if e["name"] == alert["name"])
                ok(
                    f"{alert['name']}  "
                    f"(scheduled={content.get('is_scheduled')}, "
                    f"cron={content.get('cron_schedule')}, "
                    f"track={content.get('alert.track')})"
                )
            else:
                fail(f"NOT FOUND: {alert['name']}")


if __name__ == "__main__":
    main()
