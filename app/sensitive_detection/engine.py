"""
Correlation of the individual detectors into a single verdict.

The previous implementation wrote every run to
``output/sensitive_detection.json`` with the matched secrets included, in a
directory tracked by git. That file is gone: the same information, minus the
secret values, is already carried by the LangGraph checkpoint, so duplicating
it bought nothing and leaked everything.

Risk grading now lives in ``adapters.risk_level_for`` so the orchestration
layer and this correlator cannot drift apart.
"""

from __future__ import annotations

from typing import Any

from app.agents.state import RiskLevel

from .adapters import Finding, risk_level_for, to_state_entities


class SensitiveDataCorrelator:
    """Combines PII and secret findings into one summarized verdict."""

    def correlate(
        self,
        alert: dict[str, Any],
        presidio_results: list[Finding],
        trufflehog_results: list[Finding],
    ) -> dict[str, Any]:
        """
        Return a redacted summary of both detector runs.

        The returned payload is safe to log or persist: it carries counts,
        entity types and the risk grade, never the matched values. Callers
        needing the full state model should use
        ``adapters.build_detection_result`` instead.
        """
        entities, errors = to_state_entities(presidio_results, trufflehog_results)
        return {
            "alert_id": alert.get("id") or alert.get("alert_id"),
            "summary": {
                "pii_count": sum(1 for e in entities if e.detector == "presidio"),
                "secret_count": sum(1 for e in entities if e.detector == "trufflehog"),
                "entity_types": sorted({e.entity_type for e in entities}),
                "risk_level": str(self.calculate_risk(presidio_results, trufflehog_results)),
            },
            "errors": errors,
        }

    def calculate_risk(
        self,
        presidio_results: list[Finding],
        trufflehog_results: list[Finding],
    ) -> RiskLevel:
        """Grade the combined findings. Delegates to the shared policy."""
        entities, _ = to_state_entities(presidio_results, trufflehog_results)
        return risk_level_for(entities)
