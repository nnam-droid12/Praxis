#!/usr/bin/env python3
"""praxis_investigate.py — Feature 9 custom alert action entry point.

Splunk invokes this script with the alert's JSON payload on stdin (per
`payload_format = json` in ../default/alert_actions.conf). This launcher is
stdlib-only (it runs under Splunk's bundled Python) and simply forwards that
payload to the Praxis project's own interpreter, which runs the real
investigation (orchestrator + agents + McpSplunkClient) and writes the
verdict back to Splunk via HEC. See scripts/run_alert_investigation.py.

Configure via environment variables (set on the Splunk service, or in
local/alert_actions.conf as `param.*` and read by Splunk into the env):
  PRAXIS_HOME    - path to the Praxis project root (default: see below)
  PRAXIS_PYTHON  - path to the Python interpreter with Praxis's deps
                    installed (default: `python` on PATH)
"""

import os
import subprocess
import sys

DEFAULT_PRAXIS_HOME = r"C:\Users\hp\Desktop\praxis"


def main() -> int:
    payload = sys.stdin.read()

    praxis_home = os.environ.get("PRAXIS_HOME", DEFAULT_PRAXIS_HOME)
    praxis_python = os.environ.get("PRAXIS_PYTHON", "python")
    runner = os.path.join(praxis_home, "scripts", "run_alert_investigation.py")

    if not os.path.exists(runner):
        sys.stderr.write(f"praxis_investigate: runner not found at {runner}\n")
        sys.stderr.write("Set PRAXIS_HOME to the Praxis project root.\n")
        return 2

    result = subprocess.run(
        [praxis_python, runner],
        input=payload,
        capture_output=True,
        text=True,
        cwd=praxis_home,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
