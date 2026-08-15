"""
Rule-generator node.

Runs on the sensitive branch when no existing rule covers the exposure.
Drafts a Wazuh rule from the sanitized context only — this node calls an
LLM, so it reads the state exclusively through ``get_llm_context``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.agents.state import (
    AlertState,
    LLMContext,
    NodeName,
    RuleEngineeringResult,
    StateUpdate,
)

from ._common import node_patch

__all__ = ["RuleDrafter", "make_rule_generator_node"]


class RuleDrafter(Protocol):
    """Drafts a Wazuh rule from an LLM-safe context."""

    def draft(self, context: LLMContext) -> tuple[str, str]:
        """Return ``(rule_xml, reason)`` for the given sanitized context."""
        ...


def make_rule_generator_node(
    drafter: RuleDrafter,
) -> Callable[[AlertState], StateUpdate]:
    """Build the rule-generator node bound to a concrete drafter."""

    def rule_generator_node(state: AlertState) -> StateUpdate:
        """
        Draft a rule for the uncovered exposure and attach it to the state.

        The draft always carries ``requires_rule_review``, enforced by
        ``RuleEngineeringResult``, so no generated rule is deployable
        without a human. A failing drafter raises rather than leaving a
        silently un-drafted rule behind.
        """
        context = state.get_llm_context(consumer=NodeName.RULE_GENERATOR)
        rule_xml, reason = drafter.draft(context)

        previous = state.get_rule_result() or RuleEngineeringResult()
        result = RuleEngineeringResult(
            rule_exists=previous.rule_exists,
            matched_rule_id=previous.matched_rule_id,
            generated_rule=rule_xml,
            generation_reason=reason,
        )
        return node_patch(
            state, NodeName.RULE_GENERATOR, state.set_rule_result(result)
        )

    return rule_generator_node
