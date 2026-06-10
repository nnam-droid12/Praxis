"""mcp_client.py — McpSplunkClient: the ONLY Splunk interface for Praxis agents.

Wraps the Splunk MCP Server (app 7931) JSON-RPC 2.0 / Streamable HTTP API
(SPLUNK_MCP_URL, Bearer SPLUNK_TOKEN). Every agent talks to Splunk exclusively
through this client.

Usage:
    async with McpSplunkClient() as splunk:
        rows = await splunk.run_query("search index=main sourcetype=praxis:auth | head 5")
        alerts = await splunk.get_praxis_alerts()
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx


class McpToolError(RuntimeError):
    """Raised when an MCP tool call returns isError=true."""


class McpSplunkClient:
    def __init__(self, mcp_url: str | None = None, token: str | None = None) -> None:
        self.mcp_url = (mcp_url or os.environ["SPLUNK_MCP_URL"]).rstrip("/")
        self.token = token or os.environ["SPLUNK_TOKEN"]
        self._client: httpx.AsyncClient | None = None
        self._request_id = 0

    async def __aenter__(self) -> "McpSplunkClient":
        self._client = httpx.AsyncClient(verify=False, timeout=120)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- low level ---------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("McpSplunkClient must be used as 'async with McpSplunkClient() as ...'")
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params or {}}
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        resp = await self._client.post(self.mcp_url, json=payload, headers=headers)
        resp.raise_for_status()

        if "text/event-stream" in resp.headers.get("content-type", ""):
            result: dict[str, Any] = {}
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    body = line[5:].strip()
                    if body and body != "[DONE]":
                        result = json.loads(body)
            return result
        return resp.json()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call an MCP tool and return its parsed content.

        Prefers `structuredContent`; otherwise parses the first text content
        block as JSON, falling back to the raw string.
        """
        response = await self._rpc("tools/call", {"name": name, "arguments": arguments})
        result = response.get("result", response)

        if result.get("isError"):
            message = result["content"][0]["text"] if result.get("content") else str(result)
            raise McpToolError(f"{name}: {message}")

        if "structuredContent" in result:
            return result["structuredContent"]

        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            text = content[0]["text"]
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text

        return result

    # -- high level -----------------------------------------------------------

    async def run_query(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        row_limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Run an SPL search via `splunk_run_query` and return result rows."""
        result = await self.call_tool(
            "splunk_run_query",
            {
                "query": query,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": row_limit,
            },
        )
        return result.get("results", []) if isinstance(result, dict) else []

    async def run_saved_search(
        self,
        saved_search_name: str,
        args: str = "",
        earliest_time: str | None = None,
        latest_time: str | None = None,
        row_limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Run a saved search by name (e.g. one of the `Praxis - *` alerts)."""
        arguments: dict[str, Any] = {
            "saved_search_name": saved_search_name,
            "args": args,
            "row_limit": row_limit,
        }
        if earliest_time is not None:
            arguments["earliest_time"] = earliest_time
        if latest_time is not None:
            arguments["latest_time"] = latest_time

        result = await self.call_tool("splunk_run_saved_search", arguments)
        return result.get("results", []) if isinstance(result, dict) else []

    async def get_knowledge_objects(self, object_type: str, row_limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve Splunk knowledge objects (e.g. type='alerts', 'saved_searches')."""
        result = await self.call_tool("splunk_get_knowledge_objects", {"type": object_type, "row_limit": row_limit})
        return result.get("results", []) if isinstance(result, dict) else []

    async def get_praxis_alerts(self, row_limit: int = 100) -> list[dict[str, Any]]:
        """Return the `Praxis - *` alert definitions."""
        alerts = await self.get_knowledge_objects("alerts", row_limit=row_limit)
        return [a for a in alerts if a.get("name", "").startswith("Praxis - ")]

    async def generate_spl(
        self,
        prompt: str,
        *,
        chat_history: str = " ",
        additional_context: str = "",
        spl_only: bool = True,
    ) -> str:
        """Translate a natural-language intent into SPL via AI Assistant for SPL."""
        result = await self.call_tool(
            "saia_generate_spl",
            {
                "prompt": prompt,
                "chat_history": chat_history,
                "additional_context": additional_context,
                "spl_only": spl_only,
            },
        )
        if isinstance(result, dict):
            return result.get("spl") or result.get("text") or json.dumps(result)
        return str(result)

    async def get_info(self) -> dict[str, Any]:
        """Return `splunk_get_info` (version, server name, etc.)."""
        result = await self.call_tool("splunk_get_info", {})
        return result if isinstance(result, dict) else {}
