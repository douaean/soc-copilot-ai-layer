# AI-Native SOC Copilot — AI Layer

AI reasoning layer sitting between the Wazuh REST API and the analyst
dashboard. Ingests security alerts, retrieves relevant cybersecurity
knowledge (RAG), reasons over them via a multi-agent system (LangGraph),
maps them to MITRE ATT&CK, and produces analyst-facing investigation
reports.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design
rationale, requirements, and roadmap before touching any code.

## Stack

- **FastAPI** — API layer / orchestrator (async, Pydantic validation)
- **LangGraph** — multi-agent orchestration (conditional/cyclical workflow)
- **LangChain** — RAG plumbing
- **ChromaDB** — local vector store (MITRE ATT&CK corpus, past incidents)
- **Ollama** — local LLM inference (data confidentiality)

## Project layout

```
app/
  ingestion/     # Pulls alerts from Wazuh REST API (polling). No business logic.
  validation/    # Pydantic models — the contract for "what is a valid alert".
  retrieval/     # ChromaDB client + query logic. Knows nothing about LLMs.
  rag/           # Prompt construction, grounding. Bridges retrieval + agents.
  agents/        # LangGraph graph definition + individual agent nodes.
  reporting/     # Turns structured agent output into analyst-readable reports.
  api/           # FastAPI routes. Thin — delegates to the modules above.
  core/          # Config, settings, shared utilities, dependency injection wiring.
  dashboard/     # Dashboard-facing endpoints/serializers.
tests/           # Mirrors app/ structure.
knowledge_base/  # Source documents to be embedded into ChromaDB (MITRE ATT&CK, etc.)
docs/            # Architecture decisions, roadmap, diagrams.
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
uvicorn app.api.main:app --reload
```

## Status

Milestone 0-1 complete: problem framing, requirements, and core architecture
decisions (FastAPI, LangGraph, ChromaDB, Ollama, polling ingestion) are
finalized and documented in `docs/ARCHITECTURE.md`. Implementation begins
at Milestone 2 (Ingestion Layer).
