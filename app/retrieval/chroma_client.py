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

    NOTE: this is a skeleton. We provide a keyword-based fallback so the
    retrieval layer can be demonstrated without an installed vector DB.
    """

    def __init__(self, collection_name: str, persist_directory: str) -> None:
        self.collection_name = collection_name
        self.persist_directory = persist_directory
        self._sample_documents = [
            {
                "id": "T1110",
                "title": "Credential Access",
                "content": "Brute force and password guessing attacks against remote services are mapped to MITRE ATT&CK technique T1110.",
            },
            {
                "id": "T1021",
                "title": "Remote Services",
                "content": "Lateral movement techniques involving remote services such as SSH and RDP are captured under T1021.",
            },
            {
                "id": "T1046",
                "title": "Network Service Discovery",
                "content": "Scanning and reconnaissance of network services is part of the ATT&CK technique T1046.",
            },
        ]

    def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Return a simple set of relevant documents for the given query text."""
        if not text:
            return self._sample_documents[:top_k]

        query_text = text.lower()
        matched = []
        for document in self._sample_documents:
            score = 0
            if "ssh" in query_text and "remote services" in document["content"].lower():
                score += 3
            if "brute force" in query_text or "failed password" in query_text:
                score += 5 if "credential access" in document["content"].lower() else 0
            if "scan" in query_text or "recon" in query_text:
                score += 4 if "network service discovery" in document["content"].lower() else 0
            if score > 0:
                matched.append((score, document))

        matched.sort(key=lambda item: item[0], reverse=True)
        return [doc for _, doc in matched][:top_k]
