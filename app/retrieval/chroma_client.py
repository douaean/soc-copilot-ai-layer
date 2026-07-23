"""
Retrieval layer — ChromaDB client and query interface.

Responsibility (and ONLY responsibility):
    Given a query (e.g. embedded alert text), return the most semantically
    similar documents from the knowledge base (MITRE ATT&CK descriptions,
    past incidents, detection rule docs).

What does NOT belong here:
    - No prompt construction (that's app/rag)
    - No LLM calls
    - No knowledge of FastAPI routes

Why ChromaDB (see docs/ARCHITECTURE.md §3.3):
    Semantic (embedding + cosine similarity) search over keyword search,
    zero-infra local deployment (NFR5 — data confidentiality), native
    LangChain integration.

Milestone: M5 (this is a Milestone 0/1 skeleton).
"""

from typing import Any


class ChromaRetriever:
    """
    Thin wrapper around a Chroma collection for semantic retrieval.

    NOTE: this is a skeleton. Implementation (collection setup, embedding
    function wiring, top-k config, metadata filtering) happens in M5.
    """

    def __init__(self, collection_name: str, persist_directory: str) -> None:
        self.collection_name = collection_name
        self.persist_directory = persist_directory

    def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """
        Returns the top_k most semantically similar documents to `text`.
        """
        raise NotImplementedError("Implement in Milestone 5.")
