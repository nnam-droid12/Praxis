"""Verify only the most recent ingestion batch (host-fixed), excluding older test batches."""

import asyncio
import json
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

MCP_URL   = os.environ.get("SPLUNK_MCP_URL", "").rstrip("/")
MCP_TOKEN = os.environ.get("SPLUNK_TOKEN", "")

# Tight window: covers the newest campaign (~01:06-01:28) but excludes the
# older test batch (~00:27-00:49).
EARLIEST = "-50m"


async def run_query(client: httpx.AsyncClient, spl: str) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "splunk_run_query",
            "arguments": {"query": spl, "earliest_time": EARLIEST, "latest_time": "now"},
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
        print(f"=== Counts by sourcetype (earliest={EARLIEST}) ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by sourcetype",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== host field values (should now show WKSTN-OKONKWO / FS01 / benign hosts, not localhost:8088) ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by host",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== j.okonkwo campaign (should be 26 events) ===")
        result = await run_query(
            client,
            "search index=main user=j.okonkwo "
            "| sort _time "
            "| table _time sourcetype host src_host dest_host action protocol dest_domain geo_velocity_kmh",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Lateral movement correlation: auth host == network src_host? ===")
        result = await run_query(
            client,
            "search index=main host=WKSTN-OKONKWO | stats count by sourcetype, host, src_host, dest_host",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Persistence/exfil correlation: host=FS01 ===")
        result = await run_query(
            client,
            "search index=main host=FS01 | stats count by sourcetype, host, src_host, dest_host",
        )
        print(result.get("result", result)["content"][0]["text"])


if __name__ == "__main__":
    asyncio.run(main())
