"""client.py — ScoringClient: rule-based Finding severity/confidence scoring (Feature 3).

Deterministic, field-threshold scoring over a Finding's raw Splunk events.
No external LLM dependency (no AITK, no Anthropic API) — every signal below
maps to a concrete field emitted by the synthetic dataset
(data/gen_scenario.py) and the 5 `Praxis - *` saved searches:

  - impossible_travel / geo_velocity_explained  (Impossible Travel Login)
  - mfa_fatigue                                 (MFA Fatigue Pattern)
  - multi_protocol_lateral_movement             (Lateral Movement to File Server)
  - unsigned_scheduled_task / encoded_command   (New Scheduled Task Created)
  - approved_change                             (false-alarm: signed task + change ticket)
  - dns_tunneling / low_reputation_destination / large_egress (DNS Tunneling / Large Egress)

Usage:
    scorer = ScoringClient()
    scored_finding = await scorer.score(finding)
"""

from __future__ import annotations

from dataclasses import dataclass

from models import Finding, Severity


@dataclass
class _Signal:
    name: str
    points: int
    detail: str


class ScoringClient:
    """Scores Findings via deterministic field-threshold rules."""

    async def score(self, finding: Finding) -> Finding:
        """Return a copy of `finding` with severity/confidence/rationale set."""
        signals = _evaluate(finding.events)
        total = sum(s.points for s in signals)

        return finding.model_copy(
            update={
                "severity": _severity_for(total),
                "confidence": _confidence_for(total),
                "rationale": _rationale(signals),
                "scoring_method": "rule_based",
            }
        )


def _severity_for(total: int) -> Severity:
    if total >= 7:
        return Severity.CRITICAL
    if total >= 4:
        return Severity.HIGH
    if total >= 1:
        return Severity.MEDIUM
    return Severity.LOW


def _confidence_for(total: int) -> float:
    return round(max(0.1, min(0.95, 0.2 + 0.1 * total)), 2)


def _rationale(signals: list[_Signal]) -> str:
    if not signals:
        return "No risk signals matched in the sampled events."
    seen: list[str] = []
    for signal in signals:
        if signal.detail not in seen:
            seen.append(signal.detail)
    return "; ".join(seen)


def _to_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _evaluate(events: list[dict]) -> list[_Signal]:
    signals: list[_Signal] = []

    # -- Impossible travel -------------------------------------------------
    for event in events:
        velocity = _to_float(event.get("geo_velocity_kmh"))
        if velocity is not None and velocity > 1000:
            if event.get("travel_record"):
                signals.append(
                    _Signal(
                        "geo_velocity_explained",
                        -2,
                        f"geo_velocity_kmh={velocity:.0f} (>1000) but explained by "
                        f"travel_record={event['travel_record']}",
                    )
                )
            else:
                signals.append(
                    _Signal(
                        "impossible_travel",
                        3,
                        f"geo_velocity_kmh={velocity:.0f} exceeds 1000 km/h with no "
                        f"travel_record on file",
                    )
                )
            break

    # -- MFA fatigue ---------------------------------------------------------
    mfa_denials = sum(
        1 for e in events if e.get("action") == "mfa_challenge" and e.get("status") == "denied"
    )
    mfa_approved = any(
        e.get("action") == "mfa_challenge" and e.get("status") == "approved" for e in events
    )
    if mfa_denials >= 3:
        if mfa_approved:
            signals.append(
                _Signal(
                    "mfa_fatigue",
                    4,
                    f"{mfa_denials} consecutive MFA push denials followed by an "
                    f"approval (MFA fatigue / push-bombing)",
                )
            )
        else:
            signals.append(
                _Signal("mfa_denials", 2, f"{mfa_denials} consecutive MFA push denials")
            )

    # -- Multi-protocol lateral movement to a file server --------------------
    protocols = {
        e["protocol"] for e in events if e.get("dest_role") == "file_server" and e.get("protocol")
    }
    if len(protocols) >= 2:
        signals.append(
            _Signal(
                "multi_protocol_lateral_movement",
                3,
                f"{len(protocols)} distinct protocols ({', '.join(sorted(protocols))}) "
                f"used to reach a file server",
            )
        )

    # -- Scheduled task persistence ------------------------------------------
    for event in events:
        if event.get("action") != "scheduled_task_created":
            continue
        signed = str(event.get("signed", "")).lower()
        if signed == "false":
            signals.append(
                _Signal(
                    "unsigned_scheduled_task",
                    3,
                    f"scheduled task {event.get('task_name')!r} created by an unsigned binary",
                )
            )
        elif signed == "true" and event.get("change_ticket"):
            signals.append(
                _Signal(
                    "approved_change",
                    -3,
                    f"scheduled task {event.get('task_name')!r} is tied to approved "
                    f"change {event['change_ticket']}",
                )
            )

        task_command = str(event.get("task_command", ""))
        if "-enc" in task_command.lower():
            signals.append(
                _Signal(
                    "encoded_command",
                    2,
                    "task_command contains an encoded/obfuscated PowerShell payload",
                )
            )

    # -- DNS tunneling ---------------------------------------------------------
    dns_tunnel_queries = sum(
        1
        for e in events
        if e.get("protocol") == "DNS"
        and e.get("query_type") == "TXT"
        and (entropy := _to_float(e.get("subdomain_entropy"))) is not None
        and entropy > 3.5
    )
    if dns_tunnel_queries >= 5:
        signals.append(
            _Signal(
                "dns_tunneling",
                3,
                f"{dns_tunnel_queries} high-entropy TXT queries to the same domain "
                f"(DNS tunneling pattern)",
            )
        )

    # -- Low-reputation destination / large egress ----------------------------
    if any(e.get("dest_reputation") == "low" for e in events):
        signals.append(_Signal("low_reputation_destination", 2, "destination has low reputation"))

    max_bytes_out = max(
        (v for e in events if (v := _to_float(e.get("bytes_out"))) is not None), default=None
    )
    if max_bytes_out is not None and max_bytes_out > 1_000_000:
        signals.append(
            _Signal("large_egress", 2, f"bytes_out={max_bytes_out:.0f} exceeds the 1MB threshold")
        )

    return signals
