"""
Dashboard node.

The terminal node. It finalizes the run rather than rendering anything: the
dashboard payload is a read, served by the API layer through
``AlertState.get_dashboard_payload`` against the final checkpoint.
"""

from __future__ import annotations

from collections.abc import Callable

from app.agents.state import AlertState, NodeName, StateUpdate

from ._common import node_patch

__all__ = ["make_dashboard_node"]


def make_dashboard_node() -> Callable[[AlertState], StateUpdate]:
    """Build the dashboard node. It has no external collaborator."""

    def dashboard_node(state: AlertState) -> StateUpdate:
        """
        Shrink the checkpoint and close the run.

        Document bodies are dropped — they dominate checkpoint size and
        are reproducible from the retrieval query — while citations,
        scores and sources are kept so the rendered report stays
        verifiable.

        ``finish_execution`` is applied after the node bookkeeping rather
        than alongside it: both write ``execution``, and closing the run
        must be the last word so ``current_node`` ends cleared and this
        node still appears in ``completed_nodes``.
        """
        patch = node_patch(state, NodeName.DASHBOARD, state.clear_runtime_data())
        return patch | state.with_update(patch).finish_execution()

    return dashboard_node
