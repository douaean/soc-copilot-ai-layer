"""
Sensitive-data detection node.

The first node to run and the only one that reads the original prompt. It
scans, sanitizes, and records the verdict that routes the rest of the graph.
Detector output formats are not known here — the scanner returns state
models already, courtesy of ``app.sensitive_detection.adapters``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.agents.state import AlertState, NodeName, SensitiveDetectionResult, StateUpdate

from ._common import node_patch

__all__ = ["SensitiveScanner", "make_sensitive_detection_node"]


class SensitiveScanner(Protocol):
    """
    Scans a prompt for PII and secrets.

    Implementations own the detector-specific formats and must not return
    matched values. See ``app.sensitive_detection.adapters`` for the
    Presidio/TruffleHog implementation of this contract.
    """

    def scan(self, text: str) -> tuple[SensitiveDetectionResult, str, list[str]]:
        """
        Return ``(result, sanitized_prompt, errors)`` for ``text``.

        ``errors`` carries problems the detectors *reported* while still
        producing a usable result. A scan that could not run at all must
        raise instead, and must not put matched values in the message.
        """
        ...


def make_sensitive_detection_node(
    scanner: SensitiveScanner,
) -> Callable[[AlertState], StateUpdate]:
    """Build the detection node bound to a concrete scanner."""

    def sensitive_detection_node(state: AlertState) -> StateUpdate:
        """
        Scan the prompt, store its sanitized form, and record the verdict.

        A failing scanner raises, which stops the run before any LLM node
        can be reached — the prompt is never classified, so it is never
        released. Guessing a verdict here would be the one mistake this
        node exists to prevent.
        """
        read = state.get_original_prompt(requester=str(NodeName.SENSITIVE_DETECTION))
        working = state.with_update(read.update)

        result, sanitized, errors = scanner.scan(read.value)

        prompt_patch = working.set_sanitized_prompt(sanitized)
        detection_patch = working.set_sensitive_detection(
            result, prompt=prompt_patch["prompt"]
        )
        return node_patch(
            working,
            NodeName.SENSITIVE_DETECTION,
            prompt_patch,
            detection_patch,
            errors=errors,
        )

    return sensitive_detection_node
