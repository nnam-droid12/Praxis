"""Delete the previously-ingested Praxis synthetic events (host-field bug fix redo)."""

import asyncio
import json
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

MCP_URL   = os.environ.get("SPLUNK_MCP_URL", "").rstrip("/")
MCP_TOKEN = os.environ.get("SPLUNK_TOKEN", "")


async def run_query(client: httpx.AsyncClient, spl: str, earliest: str = "-24h") -> dict:
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
    resp = await client.post(MCP_URL, json=payload, headers=headers, timeout=120)
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
        print("=== Deleting praxis:* synthetic events from index=main ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) | delete",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Recheck counts (should be 0 / empty) ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by sourcetype",
        )
        print(result.get("result", result)["content"][0]["text"])


if __name__ == "__main__":
    asyncio.run(main())
