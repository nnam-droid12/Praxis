"""Quick diagnostic: recheck counts and check for host-field collision."""

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
        print("=== Recheck counts ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by sourcetype",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Distinct host values across praxis sourcetypes ===")
        result = await run_query(
            client,
            "search index=main sourcetype IN (praxis:auth, praxis:network, praxis:endpoint, praxis:egress) "
            "| stats count by host, sourcetype",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Does host=WKSTN-OKONKWO match anything? ===")
        result = await run_query(
            client,
            "search index=main host=WKSTN-OKONKWO | stats count",
        )
        print(result.get("result", result)["content"][0]["text"])

        print("\n=== Raw event sample for praxis:auth (first impossible-travel login) ===")
        result = await run_query(
            client,
            "search index=main sourcetype=praxis:auth user=j.okonkwo action=login | head 1 | table _raw, host",
        )
        print(result.get("result", result)["content"][0]["text"])


if __name__ == "__main__":
    asyncio.run(main())
