"""verify_api.py — Feature 7 live check for the FastAPI SSE backend.

Drives api.main:app in-process via httpx.ASGITransport (no separate server
process), streaming GET /investigate/{user} and parsing the SSE `event:`/
`data:` lines. Confirms:
  1. /health returns 200.
  2. j.okonkwo — 5 `finding` events (one per agent) plus a final `verdict`
     event with level=active_intrusion and a non-empty kill chain.
  3. m.okafor — final verdict event with level=benign and a dissenting_view.

Run:
    python scripts/verify_api.py
"""

import asyncio
import json
import sys

import httpx
from dotenv import load_dotenv

sys.path.insert(0, ".")

from api.main import app  # noqa: E402

load_dotenv()

GREEN = "\033[32m"
RED = "\033[31m"
YEL = "\033[33m"
RST = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RST} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RST} {msg}")


def info(msg: str) -> None:
    print(f"  {YEL}[..]{RST} {msg}")


async def stream_events(client: httpx.AsyncClient, user: str, earliest_time: str) -> list[tuple[str, dict]]:
    events: list[tuple[str, dict]] = []
    async with client.stream(
        "GET", f"/investigate/{user}", params={"earliest_time": earliest_time}, timeout=120
    ) as response:
        event_name = None
        async for line in response.aiter_lines():
            if line.startswith("event:"):
                event_name = line.removeprefix("event:").strip()
            elif line.startswith("data:"):
                data = json.loads(line.removeprefix("data:").strip())
                events.append((event_name, data))
    return events


async def main() -> None:
    failures = 0
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        print("[1] GET /health")
        resp = await client.get("/health")
        if resp.status_code == 200 and resp.json().get("status") == "ok":
            ok(f"health -> {resp.json()}")
        else:
            fail(f"health check failed: {resp.status_code} {resp.text}")
            failures += 1

        print("\n[2] GET /investigate/j.okonkwo (-7d)")
        events = await stream_events(client, "j.okonkwo", "-7d")
        finding_events = [e for e in events if e[0] == "finding"]
        verdict_events = [e for e in events if e[0] == "verdict"]
        agents_seen = {e[1]["agent"] for e in finding_events}
        ok(f"{len(finding_events)} finding event(s) from agents: {sorted(agents_seen)}")
        expected_agents = {
            "identity_analyst",
            "lateral_movement",
            "exfiltration",
            "persistence",
            "devils_advocate",
        }
        if agents_seen != expected_agents:
            fail(f"expected finding events from {expected_agents}, got {agents_seen}")
            failures += 1
        if not verdict_events:
            fail("no verdict event received")
            failures += 1
        else:
            verdict = verdict_events[0][1]["verdict"]
            ok(f"verdict -> level={verdict['level']} confidence={verdict['confidence']}")
            info(f"kill_chain steps: {len(verdict['kill_chain'])}")
            if verdict["level"] != "active_intrusion":
                fail(f"expected level=active_intrusion, got {verdict['level']}")
                failures += 1
            if not verdict["kill_chain"]:
                fail("expected a non-empty kill chain")
                failures += 1

        print("\n[3] GET /investigate/m.okafor (-7d)")
        events = await stream_events(client, "m.okafor", "-7d")
        verdict_events = [e for e in events if e[0] == "verdict"]
        if not verdict_events:
            fail("no verdict event received")
            failures += 1
        else:
            verdict = verdict_events[0][1]["verdict"]
            ok(f"verdict -> level={verdict['level']} confidence={verdict['confidence']}")
            info(f"dissenting_view: {verdict['dissenting_view']}")
            if verdict["level"] != "benign":
                fail(f"expected level=benign, got {verdict['level']}")
                failures += 1
            if not verdict["dissenting_view"]:
                fail("expected a non-empty dissenting_view")
                failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Feature 7 live check complete — FastAPI SSE backend verified.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
