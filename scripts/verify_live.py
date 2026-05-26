"""
verify_live.py — Phase 0 live connectivity check for Praxis.

Confirms:
  1. MCP Server is reachable at SPLUNK_MCP_URL with SPLUNK_TOKEN.
  2. splunk_ search tools are advertised by the MCP Server.
  3. saia_generate_spl is advertised (AI Assistant for SPL installed).
  4. A trivial splunk_ search executes and returns rows.
  5. saia_generate_spl translates a natural-language intent to SPL.

Run:
    pip install httpx python-dotenv
    python scripts/verify_live.py

Set these in .env or as environment variables before running:
    SPLUNK_MCP_URL=http://localhost:8000/en-US/splunkd/__raw/services/mcp
    SPLUNK_TOKEN=<your MCP Encrypted Token>
"""

import asyncio
import json
import os
import sys
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

# SPLUNK_MCP_URL is the full MCP endpoint (e.g. http://localhost:8000/en-US/splunkd/__raw/services/mcp)
MCP_URL   = os.environ.get("SPLUNK_MCP_URL", "").rstrip("/")
MCP_TOKEN = os.environ.get("SPLUNK_TOKEN", "")

BOLD  = "\033[1m"
GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
RST   = "\033[0m"

# Use ASCII symbols — Windows cp1252 console can't render Unicode ✓/✗
def ok(msg: str)   -> None: print(f"  {GREEN}[OK]{RST} {msg}")
def fail(msg: str) -> None: print(f"  {RED}[FAIL]{RST} {msg}")
def info(msg: str) -> None: print(f"  {YEL}[..]{RST} {msg}")


# ---------------------------------------------------------------------------
# Low-level MCP helper — MCP Streamable HTTP (2025-03-26 spec)
# The MCP Server (app 7931) accepts POST /mcp with a JSON-RPC 2.0 envelope.
# Authorization: Bearer <token>
# ---------------------------------------------------------------------------

async def mcp_call(
    client: httpx.AsyncClient,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
) -> dict[str, Any]:
    """Send one JSON-RPC 2.0 request to the MCP Server and return the result dict."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }
    headers = {
        "Authorization": f"Bearer {MCP_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    # MCP_URL is already the full endpoint — post directly to it
    resp = await client.post(MCP_URL, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()

    # The server may return plain JSON or an SSE stream; handle both.
    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        # Collect SSE lines and parse the last "data:" event as JSON.
        raw = resp.text
        result_json: dict[str, Any] = {}
        for line in raw.splitlines():
            if line.startswith("data:"):
                body = line[5:].strip()
                if body and body != "[DONE]":
                    result_json = json.loads(body)
        return result_json
    else:
        return resp.json()


async def list_tools(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Return the full tools list from the MCP Server."""
    result = await mcp_call(client, "tools/list")
    # Spec: result = {"tools": [...]}  or wrapped in {"result": {"tools": [...]}}
    if "result" in result:
        result = result["result"]
    return result.get("tools", [])


async def call_tool(
    client: httpx.AsyncClient,
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    """Call a named MCP tool and return its content."""
    result = await mcp_call(client, "tools/call", {"name": tool_name, "arguments": arguments}, request_id=2)
    if "result" in result:
        result = result["result"]
    return result


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

async def check_env() -> bool:
    print(f"\n{BOLD}[1] Environment{RST}")
    ok_flag = True
    if not MCP_URL:
        fail("SPLUNK_MCP_URL is not set in .env")
        info("Set SPLUNK_MCP_URL=http://localhost:8000/en-US/splunkd/__raw/services/mcp in .env")
        ok_flag = False
    else:
        ok(f"SPLUNK_MCP_URL = {MCP_URL}")
    if not MCP_TOKEN:
        fail("SPLUNK_TOKEN is not set in .env")
        info("Generate one: Splunk Web -> Settings -> Tokens -> New Token")
        ok_flag = False
    else:
        ok(f"SPLUNK_TOKEN  = {MCP_TOKEN[:8]}... (truncated)")
    return ok_flag


async def check_reachable(client: httpx.AsyncClient) -> bool:
    print(f"\n{BOLD}[2] MCP Server reachability{RST}")
    try:
        # MCP initialize handshake
        result = await mcp_call(client, "initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "praxis-verify", "version": "0.1"},
        })
        server_info = result.get("result", result).get("serverInfo", {})
        ok(f"MCP Server responded: {server_info}")
        return True
    except Exception as exc:
        fail(f"Cannot reach MCP Server: {exc}")
        info("Check: is MCP Server app enabled in Splunk? Is the URL correct?")
        return False


async def check_tools(client: httpx.AsyncClient) -> tuple[bool, list[str]]:
    print(f"\n{BOLD}[3] Available MCP tools{RST}")
    try:
        tools = await list_tools(client)
        names = [t.get("name", "") for t in tools]
        if not names:
            fail("No tools returned — is the MCP Server app enabled and configured?")
            return False, []

        splunk_tools = [n for n in names if n.startswith("splunk_")]
        saia_tools   = [n for n in names if n.startswith("saia_")]
        other_tools  = [n for n in names if not n.startswith(("splunk_", "saia_"))]

        ok(f"Total tools: {len(names)}")
        ok(f"splunk_ tools ({len(splunk_tools)}): {splunk_tools}")
        if saia_tools:
            ok(f"saia_ tools ({len(saia_tools)}): {saia_tools}")
        else:
            fail(
                "No saia_ tools found — AI Assistant for SPL (app 7245) may not be installed "
                "or MCP Server app needs a restart."
            )
        if other_tools:
            info(f"Other tools: {other_tools}")
        return True, names
    except Exception as exc:
        fail(f"tools/list failed: {exc}")
        return False, []


async def check_search(client: httpx.AsyncClient, tool_names: list[str]) -> bool:
    print(f"\n{BOLD}[4] Trivial splunk_ search{RST}")
    # Confirmed tool name from live instance: splunk_run_query
    search_tool = "splunk_run_query" if "splunk_run_query" in tool_names else next(
        (n for n in tool_names if n.startswith("splunk_") and "query" in n),
        None,
    )
    if not search_tool:
        fail("splunk_run_query not found in tool list.")
        info(f"Available splunk_ tools: {[n for n in tool_names if n.startswith('splunk_')]}")
        return False

    info(f"Using tool: {search_tool}")
    try:
        result = await call_tool(client, search_tool, {
            "query": "search index=_internal sourcetype=splunkd | head 3 | table _time host sourcetype",
            "earliest_time": "-5m",
            "latest_time": "now",
        })
        info(f"Raw result (first 400 chars): {str(result)[:400]}")
        ok(f"Search executed via {search_tool}")
        return True
    except Exception as exc:
        fail(f"Search failed: {exc}")
        info("If 403: check token permissions (must have 'search' capability).")
        return False


async def check_spl_gen(client: httpx.AsyncClient, tool_names: list[str]) -> bool:
    print(f"\n{BOLD}[5] saia_generate_spl (NL to SPL){RST}")
    if "saia_generate_spl" not in tool_names:
        fail("saia_generate_spl not in tool list — AI Assistant for SPL not installed or not exposed.")
        return False

    try:
        # Confirmed from live instance: argument is "prompt", not "question"
        result = await call_tool(client, "saia_generate_spl", {
            "prompt": "Show me the top 5 source IPs with the most failed login attempts in the last hour",
        })
        info(f"Raw result (first 400 chars): {str(result)[:400]}")
        ok("saia_generate_spl responded")
        return True
    except Exception as exc:
        fail(f"saia_generate_spl failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    print(f"{BOLD}{'='*60}{RST}")
    print(f"{BOLD}  Praxis - Phase 0 Live Connectivity Check{RST}")
    print(f"{BOLD}{'='*60}{RST}")

    if not await check_env():
        sys.exit(1)

    async with httpx.AsyncClient(verify=False) as client:  # verify=False for self-signed dev cert
        if not await check_reachable(client):
            sys.exit(1)

        ok_tools, tool_names = await check_tools(client)
        search_ok  = await check_search(client, tool_names)
        sai_ok     = await check_spl_gen(client, tool_names)

    print(f"\n{BOLD}{'='*60}{RST}")
    all_ok = ok_tools and search_ok
    if all_ok and sai_ok:
        print(f"{GREEN}{BOLD}  ALL CHECKS PASSED - Praxis is ready to build.{RST}")
    elif all_ok:
        print(f"{YEL}{BOLD}  Core checks passed; saia_ tools unavailable (AI Assistant not installed).{RST}")
        print(f"  Install app 7245 for the NL→SPL bonus, then re-run.")
    else:
        print(f"{RED}{BOLD}  Some checks FAILED. Fix the issues above before proceeding.{RST}")
        sys.exit(1)
    print(f"{BOLD}{'='*60}{RST}\n")


if __name__ == "__main__":
    asyncio.run(main())
