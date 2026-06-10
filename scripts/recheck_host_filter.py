"""Recheck whether host= filter searches have caught up with stats-by-host (tsidx lag check)."""

import asyncio
import json
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

MCP_URL   = os.environ.get("SPLUNK_MCP_URL", "").rstrip("/")
MCP_TOKEN = os.environ.get("SPLUNK_TOKEN", "")


async def run_query(client: httpx.AsyncClient, spl: str, earliest="-50m") -> dict:
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
        print("=== search host=WKSTN-OKONKWO | stats count by sourcetype ===")
        result = await run_query(client, "search index=main host=WKSTN-OKONKWO | stats count by sourcetype")
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== search host=FS01 | stats count by sourcetype ===")
        result = await run_query(client, "search index=main host=FS01 | stats count by sourcetype")
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== search index=main host=FS01 (no sourcetype filter) | stats count ===")
        result = await run_query(client, "search index=main host=FS01 | stats count")
        print(result.get("result", result)["content"][0]["text"])


if __name__ == "__main__":
    asyncio.run(main())
