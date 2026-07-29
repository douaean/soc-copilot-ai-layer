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
    """Build a concise grounded prompt for the investigation workflow."""
    context_snippets = []
    for index, doc in enumerate(retrieved_docs[:3], start=1):
        content = doc.get("content") or doc.get("text") or str(doc)
        context_snippets.append(f"[{index}] {doc.get('title', 'Document')} - {content}")

    context_section = "\n\n".join(context_snippets) or "No relevant context was retrieved."

    return (
        "You are a security analysis assistant. Use the alert details and any "
        "retrieved context to decide whether the alert should be auto-closed as a "
        "false positive or escalated for threat intelligence review.\n\n"
        "Alert:\n"
        f"{alert_text}\n\n"
        "Retrieved context:\n"
        f"{context_section}\n\n"
        "Provide structured feedback for correlation and an investigation score."
    )
