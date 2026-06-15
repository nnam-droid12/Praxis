"""verify_alert_action.py — Feature 9 live check for the Praxis custom alert action.

Builds a real gzip-CSV `results_file` from a live Splunk query (no mocks),
constructs a realistic alert-action JSON payload (payload_format = json, as
splunkd would send to a custom alert action's stdin), and pipes it into:

  1. scripts/run_alert_investigation.py directly, for j.okonkwo
     (expects level=active_intrusion)
  2. splunk_app/praxis_alert_action/bin/praxis_investigate.py — the
     two-stage launcher — for m.okafor (expects level=benign with a
     dissenting view)

Then confirms both resulting `sourcetype=praxis:verdict` events landed in
Splunk via the real McpSplunkClient.

Run:
    python scripts/verify_alert_action.py
"""

import asyncio
import csv
import gzip
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, ".")

from splunk import McpSplunkClient  # noqa: E402

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
EARLIEST_TIME = "-7d"

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


async def _build_results_file(splunk: McpSplunkClient, user: str) -> Path:
    """Run a real Splunk query for `user` and write its first row to a gzip CSV."""
    rows = await splunk.run_query(f"search index=main user={user} | head 1", earliest_time=EARLIEST_TIME)
    if not rows:
        raise RuntimeError(f"No events found for {user} in index=main")

    fieldnames = list(rows[0].keys())
    fd, path = tempfile.mkstemp(suffix=".csv.gz")
    os.close(fd)
    with gzip.open(path, "wt", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return Path(path)


def _payload(results_file: Path, search_name: str) -> dict:
    return {
        "sid": f"scheduler__praxis__verify_{search_name.replace(' ', '_')}",
        "search_name": search_name,
        "server_host": "DESKTOP-V4R983R",
        "server_uri": "https://localhost:8089",
        "results_file": str(results_file),
        "results_link": "https://localhost:8000/en-US/app/search/search",
        "configuration": {
            "param.user_field": "user",
            "param.earliest_time": EARLIEST_TIME,
        },
    }


def _run(cmd: list[str], payload: dict, env: dict | None = None) -> dict:
    result = subprocess.run(
        cmd,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env,
    )
    if result.stderr.strip():
        info(f"stderr: {result.stderr.strip()}")
    if result.returncode != 0:
        raise RuntimeError(f"{cmd[-1]} exited {result.returncode}\nstdout: {result.stdout}")
    return json.loads(result.stdout)


async def main() -> None:
    failures = 0

    async with McpSplunkClient() as splunk:
        print("[1] Building real results_file (gzip CSV) for j.okonkwo and m.okafor ...")
        okonkwo_file = await _build_results_file(splunk, "j.okonkwo")
        okafor_file = await _build_results_file(splunk, "m.okafor")
        ok(f"j.okonkwo -> {okonkwo_file}")
        ok(f"m.okafor  -> {okafor_file}")

    try:
        print("\n[2] scripts/run_alert_investigation.py directly — j.okonkwo")
        payload = _payload(okonkwo_file, "Praxis - Verify j.okonkwo")
        output = _run([sys.executable, "scripts/run_alert_investigation.py"], payload)
        info(f"output: {output}")
        if output.get("status") != "ok" or not output.get("investigations"):
            fail(f"Unexpected runner output: {output}")
            failures += 1
        else:
            inv = output["investigations"][0]
            if inv["level"] != "active_intrusion":
                fail(f"Expected active_intrusion, got {inv['level']}")
                failures += 1
            else:
                ok(f"j.okonkwo -> {inv['level']} (confidence={inv['confidence']}, case_id={inv['case_id']})")

        print("\n[3] bin/praxis_investigate.py (two-stage launcher) — m.okafor")
        payload = _payload(okafor_file, "Praxis - Verify m.okafor")
        env = {**os.environ, "PRAXIS_HOME": str(ROOT), "PRAXIS_PYTHON": sys.executable}
        output = _run(
            [sys.executable, "splunk_app/praxis_alert_action/bin/praxis_investigate.py"],
            payload,
            env=env,
        )
        info(f"output: {output}")
        if output.get("status") != "ok" or not output.get("investigations"):
            fail(f"Unexpected runner output: {output}")
            failures += 1
        else:
            inv = output["investigations"][0]
            if inv["level"] != "benign":
                fail(f"Expected benign, got {inv['level']}")
                failures += 1
            else:
                ok(f"m.okafor -> {inv['level']} (confidence={inv['confidence']}, case_id={inv['case_id']})")
    finally:
        okonkwo_file.unlink(missing_ok=True)
        okafor_file.unlink(missing_ok=True)

    print("\n[4] Confirming sourcetype=praxis:verdict events landed in Splunk ...")
    info("waiting 25s for HEC indexing ...")
    await asyncio.sleep(25)

    async with McpSplunkClient() as splunk:
        rows = await splunk.run_query(
            'search index=main sourcetype="praxis:verdict"',
            earliest_time="-10m",
        )
        events = [json.loads(row["_raw"]) for row in rows]
        by_user = {e.get("user"): e for e in events}

        for user, expected_level in [("j.okonkwo", "active_intrusion"), ("m.okafor", "benign")]:
            row = by_user.get(user)
            if not row:
                fail(f"No praxis:verdict event found for {user}")
                failures += 1
                continue
            ok(f"{user} -> praxis:verdict found (level={row.get('level')}, case_id={row.get('case_id')})")
            if row.get("level") != expected_level:
                fail(f"Expected level={expected_level}, got {row.get('level')}")
                failures += 1
            if user == "m.okafor" and not row.get("dissenting_view"):
                fail("Expected a dissenting_view on m.okafor's verdict")
                failures += 1

    if failures:
        print(f"\n{RED}{failures} check(s) failed.{RST}")
        sys.exit(1)
    print(f"\n{GREEN}Feature 9 live check complete — Praxis alert action verified end-to-end.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
