"""run_alert_investigation.py — Feature 9 custom alert action runner.

Invoked by splunk_app/praxis_alert_action/bin/praxis_investigate.py, which
forwards splunkd's alert-action JSON payload (payload_format = json) via
stdin: {"results_file": "...", "configuration": {"param.*": ...}, ...}.

For each distinct user found in the triggering search's results_file, runs
a full Praxis investigation (orchestrator.run_case, real Splunk via
McpSplunkClient) and writes the Correlation Lead's verdict back to Splunk
via HEC as sourcetype=praxis:verdict.

Prints a JSON summary to stdout; exits non-zero on failure (Splunk's
contract for alert action scripts).
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from models import Case, Verdict  # noqa: E402
from orchestrator import run_case  # noqa: E402
from splunk import McpSplunkClient  # noqa: E402

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "").rstrip("/")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")


def _extract_users(payload: dict[str, Any]) -> list[str]:
    """Return distinct values of `param.user_field` from `results_file`."""
    user_field = payload.get("configuration", {}).get("param.user_field", "user")
    results_file = payload.get("results_file")
    if not results_file or not os.path.exists(results_file):
        return []

    users: list[str] = []
    with gzip.open(results_file, "rt", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            user = row.get(user_field)
            if user and user not in users:
                users.append(user)
    return users


def _verdict_event(user: str, case: Case, verdict: Verdict) -> dict[str, Any]:
    return {
        "case_id": case.id,
        "user": user,
        "level": verdict.level.value,
        "confidence": verdict.confidence,
        "summary": verdict.summary,
        "dissenting_view": verdict.dissenting_view,
        "kill_chain": [step.model_dump(mode="json") for step in verdict.kill_chain],
        "findings": [
            {"agent": f.agent, "severity": f.severity.value, "title": f.title}
            for f in case.findings
        ],
    }


def _send_to_hec(event: dict[str, Any]) -> None:
    if not HEC_URL or not HEC_TOKEN:
        print(f"  [skip] SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN not set; not writing verdict for {event['user']}", file=sys.stderr)
        return

    body = {
        "event": event,
        "sourcetype": "praxis:verdict",
        "source": "praxis_alert_action",
        "time": datetime.now(timezone.utc).timestamp(),
    }
    headers = {"Authorization": f"Splunk {HEC_TOKEN}", "Content-Type": "application/json"}
    with httpx.Client(verify=False, timeout=30) as client:
        resp = client.post(f"{HEC_URL}/services/collector/event", headers=headers, json=body)
        resp.raise_for_status()


async def _investigate(users: list[str], earliest_time: str) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    async with McpSplunkClient() as splunk:
        for user in users:
            case, verdict = await run_case(splunk, user, earliest_time)
            event = _verdict_event(user, case, verdict)
            _send_to_hec(event)
            summaries.append({"user": user, "case_id": case.id, "level": verdict.level.value, "confidence": verdict.confidence})
    return summaries


def main() -> int:
    payload = json.load(sys.stdin)
    earliest_time = payload.get("configuration", {}).get("param.earliest_time", "-24h")
    users = _extract_users(payload)

    if not users:
        print(json.dumps({"status": "no_users", "search_name": payload.get("search_name")}))
        return 0

    summaries = asyncio.run(_investigate(users, earliest_time))
    print(json.dumps({"status": "ok", "search_name": payload.get("search_name"), "investigations": summaries}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
