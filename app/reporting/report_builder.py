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
    """
    Renders the final investigation result as a human-readable report
    (markdown or plain text, TBD in M10).
    """
    raise NotImplementedError("Implement in Milestone 10.")
