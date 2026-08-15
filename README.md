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

## Testing

```bash
.venv/bin/python3 -m pytest -q
```

## API

- `POST /alerts/ingest` — ingest one or more alerts from Wazuh or the built-in mock dataset and run the investigation workflow.
- `GET /alerts/sample` — return a sample set of structured mock alerts for demonstration.
- `POST /investigation` — submit a single validated Wazuh alert payload for investigation and report generation.

Example mock ingestion:

```bash
curl -X POST "http://127.0.0.1:8000/alerts/ingest?mock=true"
```

Example direct investigation of a single alert:

```bash
curl -X POST "http://127.0.0.1:8000/investigation" \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-07-28T17:00:00Z","rule":{"level":8,"description":"Possible brute force SSH login attempt","id":"1002"},"agent":{"id":"agent-01","name":"host-01.example.local","ip":"10.0.0.5"},"full_log":"Failed password for invalid user root from 10.0.0.10 port 22 ssh2"}'
```

The current implementation is structured so the orchestrator, LangGraph workflow, retrieval, and reporting layers are separated. A LangGraph-compatible fallback workflow is available so the API can be exercised while the full agent implementation and Chroma retrieval path are completed.

## Demo workflow

1. Request mock alerts from `GET /alerts/sample` or ingest them with `POST /alerts/ingest?mock=true`.
2. The service validates every alert and uses correlation logic to identify likely false positives.
3. If an alert is not auto-closed, the system performs a Tavily threat intelligence search and assigns a final investigation score.
4. The response includes a structured investigation result and an analyst-facing report.

## Status

Prototype ready for demonstration: the API can ingest mock or Wazuh alerts, validate them, correlate them, auto-close likely false positives, search for threat intelligence context against Tavily, and generate an analyst-facing report. The architecture remains modular so the next milestones can replace the fallback components with a production LangGraph/ChromaDB/LLM implementation.
