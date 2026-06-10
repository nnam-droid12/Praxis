"""
verify_ingest.py - Confirm the Praxis synthetic dataset landed in Splunk.

Runs the verification SPL from data/README.md via the live MCP Server and
prints results.

Run:
    python scripts/verify_ingest.py
"""

import asyncio
import json
import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv()

MCP_URL   = os.environ.get("SPLUNK_MCP_URL", "").rstrip("/")
MCP_TOKEN = os.environ.get("SPLUNK_TOKEN", "")


async def run_query(client: httpx.AsyncClient, spl: str, earliest: str = "-2h") -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "splunk_run_query",
            "arguments": {"query": spl, "earliest_time": earliest, "latest_time": "now"},
        },
    }
    headers = {
        "Authorization": f"Bearer {MCP_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    resp = await client.post(MCP_URL, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        result_json = {}
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                body = line[5:].strip()
                if body and body != "[DONE]":
                    result_json = json.loads(body)
        return result_json
    return resp.json()


async def main() -> None:
    async with httpx.AsyncClient(verify=False) as client:
        print("=== Event counts by sourcetype ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by sourcetype",
            earliest="-24h",
        )
        text = result.get("result", result)["content"][0]["text"]
        print(text)

        print("\n=== Planted campaign (j.okonkwo) ===")
        result = await run_query(
            client,
            "search index=main user=j.okonkwo "
            "| sort _time "
            "| table _time sourcetype user host src_host dest_host action protocol dest_domain geo_velocity_kmh",
            earliest="-2h",
        )
        text = result.get("result", result)["content"][0]["text"]
        print(text)

        print("\n=== False alarms ===")
        result = await run_query(
            client,
            "search index=main (user=m.okafor OR (user=it.admin host=FS02)) "
            "| table _time sourcetype user geo_velocity_kmh travel_record signed change_ticket",
            earliest="-24h",
        )
        text = result.get("result", result)["content"][0]["text"]
        print(text)


if __name__ == "__main__":
    asyncio.run(main())
