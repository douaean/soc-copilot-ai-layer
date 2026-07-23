# AI-Native SOC Copilot — AI Layer Architecture

**Status:** Milestone 0-1 complete (Problem framing, Requirements, Core architecture decisions)
**Last updated:** 2026-07-23

---

## 1. Problem Statement

Wazuh Manager produces raw JSON alerts via its REST API. Raw alerts are not
actionable for a SOC analyst under load — they need context (has this
happened before? how severe is it? what's the standard response?), not a log
line.

The AI layer's job: close the gap between raw telemetry and analyst judgment.

```
Wazuh Endpoint → Wazuh Agent → Wazuh Manager → Wazuh REST API
                                                        │
                                                        ▼
                                              ┌───────────────────┐
                                              │     AI Layer      │  ← this repo
                                              │ (this document)   │
                                              └───────────────────┘
                                                        │
                                                        ▼
                                                    Dashboard
```

---

## 2. Requirements

### Functional
| ID | Requirement |
|----|---|
| FR1 | Ingest Wazuh alerts (polling, for now — see §4) |
| FR2 | Validate & normalize alert structure before any processing |
| FR3 | Retrieve relevant cybersecurity knowledge related to the alert (RAG) |
| FR4 | Map alert to MITRE ATT&CK tactics/techniques |
| FR5 | Produce investigation recommendations |
| FR6 | Produce a human-readable analyst report |
| FR7 | Expose results via dashboard, not raw API output |

### Non-Functional (these justify most architecture decisions below)
| ID | Requirement | Drives |
|----|---|---|
| NFR1 | Latency bound (~<5s target for triage-level alerts) | FastAPI async, LangGraph conditional routing |
| NFR2 | Auditability — every AI conclusion must be traceable to a source | RAG over raw LLM recall |
| NFR3 | Availability under alert bursts (brute-force = 100s of alerts/sec) | FastAPI async I/O |
| NFR4 | No hallucinated security guidance | RAG grounding, LangGraph severity-based reasoning depth |
| NFR5 | Data confidentiality — alert data must not leave the network uncontrolled | Ollama (local inference), ChromaDB (local vector DB) |
| NFR6 | Extensibility (1 → 1000 endpoints) | Clean separation of ingestion/validation/retrieval/agents |

---

## 3. Core Architecture Decisions

### 3.1 FastAPI (entry point / orchestrator)

**Why:** Native async (ASGI) means the system can wait on Chroma queries,
Ollama generation, and the Wazuh API *concurrently* instead of blocking one
request at a time — required for NFR3 (burst tolerance). Built-in Pydantic
validation lets us reject malformed alerts at the boundary, before they ever
reach the RAG/agent pipeline — required for NFR2.

**Tradeoff accepted:** No built-in ORM/admin (unlike Django) — we'll add
SQLAlchemy only if/when we need relational storage (Milestone 13+, not now).

**Known failure mode to avoid:** any blocking (synchronous) call inside an
`async def` route freezes the entire event loop for *all* concurrent
requests, not just one. Use `httpx` (async) for outbound HTTP calls, never
`requests`.

### 3.2 LangGraph (multi-agent orchestration)

**Why:** Real investigation workflow isn't a straight line — a low-severity
alert should take a cheap fast path; a high-severity alert may need deeper
retrieval, re-querying, or looping before a report is written. LangGraph
models this as a graph with conditional/cyclical edges, which a single
prompt or a fixed sequential chain cannot do.

**Why this resolves the NFR1 vs NFR4 tension:** severity-based branching
means most alerts stay fast (NFR1), while the minority of serious alerts
are allowed to take the slower, more thorough path (NFR4) — the tradeoff is
conditional, not universal.

**Tradeoff accepted:** More LLM calls = more latency and cost *on the
alerts that take the long path*, and more inter-agent surface area to debug
(a bug can live in how Agent A's output is interpreted by Agent B, not just
inside one node).

### 3.3 ChromaDB (vector store for retrieval)

**Why:** Keyword/text search matches strings, not meaning — a Wazuh log
line like "authentication failures for root" and a MITRE doc describing
"brute force" may share zero literal words despite describing the same
technique. Embeddings + cosine similarity match on semantic closeness
instead. Chroma specifically: zero-infra local deployment (satisfies
NFR5 — no data leaves the network), first-class LangChain integration,
appropriate for current scale.

**Tradeoff accepted / revisit later:** Chroma is not built for
massive-scale, multi-node, high-availability deployment. If the project
grows toward hundreds/thousands of endpoints (see Milestone 13), we'd
evaluate pgvector or a managed vector DB with stronger operational
guarantees — not a today decision.

### 3.4 Ollama (local LLM inference)

**Why:** NFR5 — sending alert data (internal IPs, hostnames, usernames,
raw log lines) to a hosted LLM API creates a "recon-by-proxy" risk: a
third party (or anyone who later breaches/subpoenas them) gains a partial
map of our security posture. Local inference keeps this data inside our
network boundary. Also avoids potential compliance violations in regulated
environments.

**Tradeoff accepted:** Local models (7B–13B class) have a lower reasoning
ceiling than hosted frontier models, particularly on nuanced MITRE
classification. This is *why RAG matters more here* — RAG turns "recall the
correct technique from memory" (hard, failure-prone for small models) into
"read this retrieved, ground-truth technique description and apply it"
(reading comprehension, which small models handle far more reliably).

### 3.5 Ingestion: Polling vs Webhook — Polling chosen for now

Polling: our side repeatedly asks Wazuh's REST API for new alerts on an
interval. Webhook: Wazuh would push alerts to us the instant they occur.

**Why polling for this phase:** no dependency on configuring Wazuh's
output/webhook side, no publicly exposed endpoint to secure under time
pressure. The ingestion method is treated as an implementation detail
behind an interface — the rest of the pipeline (validation → RAG → agents)
does not know or care whether an alert arrived via polling or webhook. This
means we can swap to webhook later (Milestone 2 revisit) without touching
downstream code.

---

## 4. Data Flow (current milestone scope)

```
Wazuh REST API
      │
      ▼  (poll every N seconds)
┌──────────────────┐
│ Ingestion module  │  app/ingestion
└──────────────────┘
      │  raw JSON
      ▼
┌──────────────────┐
│ Validation module │  app/validation  (Pydantic models)
└──────────────────┘
      │  normalized AlertModel
      ▼
┌──────────────────┐
│ Retrieval module   │  app/retrieval  (ChromaDB query)
└──────────────────┘
      │  relevant docs
      ▼
┌──────────────────┐
│ RAG module         │  app/rag  (prompt construction + grounding)
└──────────────────┘
      │
      ▼
┌──────────────────┐
│ Agents (LangGraph) │  app/agents  (MITRE mapping, recommendations)
└──────────────────┘
      │
      ▼
┌──────────────────┐
│ Reporting module   │  app/reporting  (analyst-facing report)
└──────────────────┘
      │
      ▼
   Dashboard / API response
```

---

## 5. Roadmap (milestones ahead)

- M2 — Ingestion Layer (polling implementation, Wazuh API client)
- M3 — Validation & Normalization (Pydantic models for alerts)
- M4 — Knowledge Base & Embeddings (MITRE corpus, chunking strategy)
- M5 — ChromaDB & Retrieval (collection design, query interface)
- M6 — RAG Pipeline (prompt construction, grounding)
- M7 — LLM Layer via Ollama (model selection, prompting)
- M8 — Multi-Agent Design with LangGraph (agent roles, graph definition)
- M9 — MITRE ATT&CK Mapping Logic
- M10 — Report Generation
- M11 — Dashboard & API Contracts
- M12 — Security Hardening (auth, secrets, prompt injection, RAG poisoning)
- M13 — Scalability (Kafka/Redis/Postgres — only if/when justified)
- M14 — Testing Strategy & CI

Each milestone will define: objectives, expected output, dependencies,
difficulty, known failure points, testing strategy, and Definition of Done
before implementation begins.
