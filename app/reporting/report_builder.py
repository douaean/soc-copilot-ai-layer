"""
Reporting layer — structured agent output -> analyst-readable report.

Responsibility (and ONLY responsibility):
    Take the final InvestigationState (MITRE mapping, recommendations,
    severity) and render it into a human-readable report.

What does NOT belong here:
    - No LLM calls that change the underlying conclusions (this is
      formatting, not reasoning — if you need the LLM to reason more,
      that belongs in app/agents, not here)

Milestone: M10 (this is a Milestone 0/1 skeleton).
"""

from typing import Any


def build_analyst_report(investigation_result: dict[str, Any]) -> str:
    """Render an analyst-facing report from the investigation result."""
    alert = investigation_result.get("alert", {})
    correlation = investigation_result.get("correlation") or {}
    threat_intel = investigation_result.get("threat_intel") or {}
    severity_score = alert.get("rule", {}).get("level")
    status = investigation_result.get("status", "unknown")
    final_score = investigation_result.get("final_score")

    report_lines = [
        "# Analyst Investigation Report",
        "",
        "## Alert Summary",
        f"Timestamp: {alert.get('timestamp', 'Unknown')}",
        f"Agent: {alert.get('agent', {}).get('name', 'Unknown')} ({alert.get('agent', {}).get('ip', 'Unknown')})",
        f"Rule: {alert.get('rule', {}).get('description', 'Unknown')} ({alert.get('rule', {}).get('id', 'Unknown')})",
        f"Severity level: {severity_score if severity_score is not None else 'Unknown'}",
        "",
        "## Correlation & Decision",
        f"False positive: {correlation.get('false_positive', False)}",
        f"Correlation score: {correlation.get('correlation_score', 'Unknown')}",
        f"Investigation status: {status}",
        "",
        "## Threat Intelligence Summary",
        f"Source: {threat_intel.get('source', 'N/A')}",
        f"Summary: {threat_intel.get('summary', 'No intelligence summary.')}",
        f"Confidence: {threat_intel.get('confidence', 'N/A')}",
        "",
        "## Final Score",
        f"Investigation score: {final_score if final_score is not None else 'Unknown'}",
        "",
        "## Recommended Next Steps",
    ]

    if status == "auto_closed":
        report_lines.extend(
            [
                "- This alert was classified as a false positive.",
                "- The system auto-closed it to reduce analyst noise.",
                "- Review the threshold rules if this result is unexpected.",
            ]
        )
    else:
        report_lines.extend(
            [
                "- Continue the investigation with network telemetry and host logs.",
                "- Use the Tavily intelligence summary to validate the observed behavior.",
                "- Escalate to incident response if related activity is confirmed.",
            ]
        )

    if threat_intel.get("details"):
        report_lines.append("")
        report_lines.append("## Threat Intelligence Details")
        for detail in threat_intel["details"]:
            report_lines.append(f"- {detail}")

    return "\n".join(report_lines)
