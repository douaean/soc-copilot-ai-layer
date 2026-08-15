"""
Rule-checker node.

Runs on the sensitive branch. Asks whether Wazuh already has rules covering
the detected categories. Deterministic — no LLM is involved.

"Covered" means only that existing rules already detect these categories. It
is not a safety verdict; the analyst still assesses the alert either way.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.agents.state import (
    AlertState,
    DetectedEntity,
    NodeName,
    RuleEngineeringResult,
    StateUpdate,
)

from ._common import node_patch

__all__ = ["RuleRepository", "make_rule_checker_node"]


class RuleRepository(Protocol):
    """Looks up existing Wazuh rule coverage for detected categories."""

    def find_matching_rules(
        self,
        entities: list[DetectedEntity],
        alert_metadata: dict[str, str | int | None],
    ) -> dict[str, str]:
        """
        Return a mapping of ``entity_type`` to the id of a rule covering it.

        Uncovered categories must be omitted from the mapping rather than
        mapped to an empty value, so the caller can tell them apart.
        """
        ...


def make_rule_checker_node(
    repository: RuleRepository,
) -> Callable[[AlertState], StateUpdate]:
    """Build the rule-checker node bound to a concrete rule repository."""

    def rule_checker_node(state: AlertState) -> StateUpdate:
        """
        Record which detected categories existing Wazuh rules already cover.

        The alert counts as covered only when *every* detected category has
        a rule. One covered category among several does not make the alert
        covered — the uncovered ones still need a rule drafted, which is
        what routes to the generator.
        """
        detected = {entity.entity_type for entity in state.get_sensitive_entities()}
        covered = repository.find_matching_rules(
            state.get_sensitive_entities(), state.get_alert_metadata()
        )
        uncovered = sorted(detected - set(covered))

        if detected and not uncovered:
            result = RuleEngineeringResult(
                rule_exists=True,
                matched_rule_id=", ".join(sorted(set(covered.values()))),
            )
        else:
            result = RuleEngineeringResult(
                rule_exists=False,
                generation_reason=(
                    f"No existing rule covers: {', '.join(uncovered)}"
                    if uncovered
                    else "No sensitive category was recorded to check coverage for"
                ),
            )

        return node_patch(state, NodeName.RULE_CHECKER, state.set_rule_result(result))

    return rule_checker_node
