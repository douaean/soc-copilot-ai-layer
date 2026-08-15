"""
Analyst node.

The convergence point of both branches. Produces the triage verdict from
the sanitized context and hands it to ``AlertState.set_analysis``, which
applies the escalation policy the agent cannot override.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.agents.state import AlertState, AnalystResult, LLMContext, NodeName, StateUpdate

from ._common import node_patch

__all__ = ["AnalystEngine", "make_analyst_node"]


class AnalystEngine(Protocol):
    """Produces a triage verdict from an LLM-safe context."""

    def analyze(self, context: LLMContext) -> AnalystResult:
        """Return the analyst verdict for the given sanitized context."""
        ...


def make_analyst_node(engine: AnalystEngine) -> Callable[[AlertState], StateUpdate]:
    """Build the analyst node bound to a concrete reasoning engine."""

    def analyst_node(state: AlertState) -> StateUpdate:
        """
        Produce the verdict and apply the escalation policy.

        ``sensitive`` and ``rule`` are passed explicitly because a mutator
        patch is not readable back off the state within a node; passing
        the live fields is what keeps the policy from reading stale
        values.

        A failing engine raises. Inventing a verdict here would produce an
        ``AnalystResult`` that reads like an analysis but is not one, and
        it would be checkpointed as if it were. The last good checkpoint is
        kept and the application decides whether to retry or escalate.
        """
        result = engine.analyze(state.get_llm_context(consumer=NodeName.ANALYST))
        return node_patch(
            state,
            NodeName.ANALYST,
            state.set_analysis(result, sensitive=state.sensitive, rule=state.rule),
        )

    return analyst_node
