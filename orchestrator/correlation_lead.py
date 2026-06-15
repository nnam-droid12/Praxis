"""correlation_lead.py — CorrelationLead: Feature 6 fan-in synthesis.

Deterministically synthesizes a Case's Findings into a Verdict: counts how
many distinct specialist agents independently flagged elevated-severity
activity, reconstructs a kill-chain timeline ordered by event time, and
surfaces any Devil's Advocate mitigating evidence as a dissenting view.

No external LLM dependency — see memory: hackathon_deadline.
"""

from __future__ import annotations

from datetime import datetime, timezone

from models import Case, Finding, KillChainStep, Severity, Verdict, VerdictLevel
from scoring import NO_SIGNALS_RATIONALE

_ELEVATED = (Severity.HIGH, Severity.CRITICAL)


class CorrelationLead:
    """Synthesizes a Case's Findings into a Verdict (Feature 6)."""

    def synthesize(self, case: Case) -> Verdict:
        findings = case.findings
        elevated_agents = {f.agent for f in findings if f.severity in _ELEVATED}
        medium_agents = {f.agent for f in findings if f.severity == Severity.MEDIUM}
        dissent = [
            f
            for f in findings
            if f.agent == "devils_advocate"
            and f.severity == Severity.LOW
            and f.rationale != NO_SIGNALS_RATIONALE
        ]

        level = _level_for(elevated_agents, medium_agents)
        kill_chain = _kill_chain(findings)

        return Verdict(
            case_id=case.id,
            level=level,
            confidence=_confidence_for(level, findings),
            summary=_summary(level, findings, elevated_agents, dissent),
            kill_chain=kill_chain,
            contributing_findings=[step.finding_ids[0] for step in kill_chain],
            dissenting_view=dissent[0].rationale if dissent else None,
        )


def _level_for(elevated_agents: set[str], medium_agents: set[str]) -> VerdictLevel:
    if len(elevated_agents) >= 3:
        return VerdictLevel.ACTIVE_INTRUSION
    if elevated_agents or medium_agents:
        return VerdictLevel.SUSPICIOUS
    return VerdictLevel.BENIGN


def _confidence_for(level: VerdictLevel, findings: list[Finding]) -> float:
    if level == VerdictLevel.BENIGN:
        if not findings:
            return 0.5
        avg = sum(f.confidence for f in findings) / len(findings)
        return round(max(0.1, min(0.95, 1 - avg)), 2)

    qualifying = [f.confidence for f in findings if f.severity != Severity.LOW]
    if not qualifying:
        return 0.5
    return round(sum(qualifying) / len(qualifying), 2)


def _summary(
    level: VerdictLevel,
    findings: list[Finding],
    elevated_agents: set[str],
    dissent: list[Finding],
) -> str:
    if level == VerdictLevel.ACTIVE_INTRUSION:
        stages = ", ".join(sorted(elevated_agents))
        return (
            f"{len(elevated_agents)} of 5 specialist agents independently flagged "
            f"elevated-severity activity ({stages}) with no mitigating evidence "
            f"found by Devil's Advocate — consistent with an active, multi-stage "
            f"intrusion."
        )
    if level == VerdictLevel.SUSPICIOUS:
        stages = ", ".join(sorted(elevated_agents)) if elevated_agents else "medium-severity findings only"
        return (
            f"Elevated activity detected ({stages}), but not enough corroborating "
            f"agents to call this an active intrusion."
        )
    if dissent:
        return (
            f"All findings are low severity; Devil's Advocate found mitigating "
            f"evidence: {dissent[0].rationale}"
        )
    if not findings:
        return "No findings returned by any agent."
    return "All findings are low severity with no notable signals."


def _kill_chain(findings: list[Finding]) -> list[KillChainStep]:
    steps: list[KillChainStep] = []
    for f in findings:
        if f.severity == Severity.LOW:
            continue
        steps.append(
            KillChainStep(
                stage=f.agent,
                timestamp=_earliest_event_time(f.events) or f.created_at,
                description=f"{f.title}: {f.rationale}",
                finding_ids=[f.id],
            )
        )
    steps.sort(key=lambda s: s.timestamp)
    return steps


def _earliest_event_time(events: list[dict]) -> datetime | None:
    """Parse the leading `YYYY-MM-DD HH:MM:SS.fff` of Splunk's `_time` field.

    Splunk returns `_time` as e.g. "2026-06-14 06:54:44.878 W. Central Africa
    Standard Time" — not ISO8601. Only relative ordering across events from
    this same Splunk instance is needed, so the timezone suffix is ignored.
    """
    times: list[datetime] = []
    for event in events:
        raw = event.get("_time")
        if not isinstance(raw, str):
            continue
        try:
            times.append(
                datetime.strptime(raw[:23], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
            )
        except ValueError:
            continue
    return min(times) if times else None
