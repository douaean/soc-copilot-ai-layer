"""
Threat-intelligence node.

Runs on the non-sensitive branch only. Retrieves grounding material, then
investigates. Both collaborators receive the sanitized LLM context, never
the state — and ``AlertState.set_ti_result`` refuses the write outright if
the alert turns out to be sensitive, so a routing mistake cannot send an
alert's contents to an external service.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.agents.state import (
    AlertState,
    LLMContext,
    NodeName,
    RAGContext,
    StateUpdate,
    ThreatIntelResult,
)

from ._common import node_patch

__all__ = ["Retriever", "ThreatIntelProvider", "make_threat_intel_node"]


class Retriever(Protocol):
    """Retrieves grounding documents from the internal knowledge base."""

    def retrieve(self, query: str) -> RAGContext:
        """Return the retrieval context for ``query``."""
        ...


class ThreatIntelProvider(Protocol):
    """Investigates an alert using external and internal intelligence."""

    def investigate(self, context: LLMContext) -> ThreatIntelResult:
        """Return the investigation result for an LLM-safe context."""
        ...


def make_threat_intel_node(
    provider: ThreatIntelProvider,
    retriever: Retriever,
) -> Callable[[AlertState], StateUpdate]:
    """Build the threat-intel node bound to a provider and a retriever."""

    def threat_intel_node(state: AlertState) -> StateUpdate:
        """
        Ground the alert, then investigate it.

        Retrieval runs first so the investigation context already carries
        the documents. Either collaborator failing raises: an alert
        investigated with no grounding, or with no intelligence, is not the
        same alert investigated successfully, and recording it as one would
        hide the outage from whoever reads the report.
        """
        rag_patch = state.set_rag_context(retriever.retrieve(_retrieval_query(state)))
        working = state.with_update(rag_patch)
        result = provider.investigate(
            working.get_llm_context(consumer=NodeName.THREAT_INTEL)
        )
        return node_patch(
            state, NodeName.THREAT_INTEL, rag_patch, working.set_ti_result(result)
        )

    return threat_intel_node


def _retrieval_query(state: AlertState) -> str:
    """Build the retrieval query from safe fields only."""
    metadata = state.get_alert_metadata()
    parts = [
        str(metadata.get("rule_id") or ""),
        str(metadata.get("severity_label") or ""),
        state.get_sanitized_prompt(),
    ]
    return " ".join(part for part in parts if part).strip()
