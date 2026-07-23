"""
RAG layer — bridges retrieval and reasoning.

Responsibility (and ONLY responsibility):
    Take a validated alert + retrieved documents, construct a grounded
    prompt (context injection), and hand it to the agent layer. Nothing
    here decides WHAT to do with the LLM's answer — that's the agents'
    job.

What does NOT belong here:
    - No direct ChromaDB queries (that's app/retrieval — this module
      consumes retrieval results, it doesn't fetch them)
    - No MITRE classification logic (that's app/agents)
    - No report formatting (that's app/reporting)

Why RAG here at all (see docs/ARCHITECTURE.md §3.4):
    Turns "recall the correct answer from model memory" (unreliable for
    a small local model) into "read this retrieved, ground-truth
    document and apply it" (reading comprehension) — this is also what
    gives us NFR2 auditability: every conclusion can point back to the
    specific retrieved document that supports it.

Milestone: M6 (this is a Milestone 0/1 skeleton).
"""

from typing import Any


def build_grounded_prompt(alert_text: str, retrieved_docs: list[dict[str, Any]]) -> str:
    """
    Combines the alert and retrieved context into a single grounded
    prompt for the LLM.

    TODO (M6): finalize prompt template, decide how many docs to include,
    decide truncation strategy for long full_log fields.
    """
    raise NotImplementedError("Implement in Milestone 6.")
