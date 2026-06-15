"""main.py — Feature 7 FastAPI SSE backend.

`GET /investigate/{user}` streams each specialist agent's Findings as
Server-Sent Events as soon as they complete, followed by a final `verdict`
event from the CorrelationLead.

Run:
    uvicorn api.main:app --reload
"""

from __future__ import annotations

import json
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from orchestrator import run_case  # noqa: F401  (re-exported for convenience)
from orchestrator.graph import stream_case
from splunk import McpSplunkClient

app = FastAPI(title="Praxis Investigation API")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/investigate/{user}")
async def investigate(user: str, earliest_time: str = "-24h") -> StreamingResponse:
    """Stream a live multi-agent investigation for `user` as SSE."""
    return StreamingResponse(_event_stream(user, earliest_time), media_type="text/event-stream")


async def _event_stream(user: str, earliest_time: str) -> AsyncIterator[str]:
    async with McpSplunkClient() as splunk:
        async for node_name, output in stream_case(splunk, user, earliest_time):
            event, data = _serialize(node_name, output)
            yield f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _serialize(node_name: str, output: dict) -> tuple[str, dict]:
    if node_name == "correlation_lead":
        return "verdict", {
            "case": output["case"].model_dump(mode="json"),
            "verdict": output["verdict"].model_dump(mode="json"),
        }
    findings = output.get("findings", [])
    return "finding", {
        "agent": node_name,
        "findings": [f.model_dump(mode="json") for f in findings],
    }
