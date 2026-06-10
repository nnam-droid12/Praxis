"""
ingest_hec.py - Send the Praxis synthetic dataset to Splunk via HEC.

Reads data/events/hec_events.jsonl (produced by data/gen_scenario.py) and
POSTs each event to the HTTP Event Collector /services/collector endpoint.

Run:
    python scripts/ingest_hec.py

Requires in .env:
    SPLUNK_HEC_URL=https://localhost:8088
    SPLUNK_HEC_TOKEN=<HEC token>
"""

import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

HEC_URL   = os.environ.get("SPLUNK_HEC_URL", "").rstrip("/")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")

EVENTS_FILE = Path(__file__).parent.parent / "data" / "events" / "hec_events.jsonl"


def main() -> None:
    if not HEC_URL or not HEC_TOKEN:
        print("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set in .env")
        sys.exit(1)

    if not EVENTS_FILE.exists():
        print(f"{EVENTS_FILE} not found - run: python data/gen_scenario.py")
        sys.exit(1)

    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json",
    }

    with EVENTS_FILE.open(encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]

    print(f"Sending {len(lines)} events to {HEC_URL}/services/collector ...")

    # HEC accepts multiple JSON objects concatenated in one POST body.
    batch_size = 50
    sent = 0
    with httpx.Client(verify=False, timeout=30) as client:
        for i in range(0, len(lines), batch_size):
            batch = lines[i:i + batch_size]
            body = "".join(batch)
            resp = client.post(f"{HEC_URL}/services/collector/event", headers=headers, content=body)
            if resp.status_code != 200:
                print(f"  Batch {i // batch_size + 1}: HTTP {resp.status_code} - {resp.text}")
                sys.exit(1)
            result = resp.json()
            if result.get("code") != 0:
                print(f"  Batch {i // batch_size + 1}: {result}")
                sys.exit(1)
            sent += len(batch)
            print(f"  Sent {sent}/{len(lines)}")

    print("\nDone. All events accepted by HEC.")
    print("Note: HEC indexing is asynchronous - wait ~10-30s before verifying counts in Splunk.")


if __name__ == "__main__":
    main()
