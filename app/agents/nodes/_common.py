"""
Shared plumbing for node implementations.

The only non-obvious problem a node has is that ``set_current_node``,
``add_error`` and ``add_completed_node`` all patch the same ``execution``
key. Returning them as separate entries in one dict would silently drop all
but the last. :func:`node_patch` folds them in order and emits a single
coherent patch instead.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.state import AlertState, NodeName, StateUpdate

__all__ = ["node_patch"]


def node_patch(
    state: AlertState,
    node: NodeName,
    *updates: StateUpdate,
    errors: Sequence[str] = (),
) -> StateUpdate:
    """
    Fold a node's updates into one patch, with its execution bookkeeping.

    Applies ``set_current_node`` first and ``add_completed_node`` last, so
    a checkpoint taken mid-node shows the node as running and one taken
    after shows it complete. ``errors`` are recorded through
    ``add_error``, which keeps the run alive — a node that must abort
    should raise instead.

    Only the keys actually touched are returned, so a node never
    overwrites a field it had no business writing.
    """
    working = state.with_update(state.set_current_node(node))
    touched = {"execution"}

    for update in updates:
        working = working.with_update(update)
        touched |= set(update)

    for message in errors:
        working = working.with_update(working.add_error(node, message))

    working = working.with_update(working.add_completed_node(node))
    return {key: getattr(working, key) for key in touched}
